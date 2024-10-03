use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;
use reqwest;
use serde_json;

lazy_static! {
    static ref DNS_PROVIDER_BASE_URL: String = "https://1.1.1.1/dns-query".to_string();
}

#[derive(Debug)]
pub struct MyDNSResolver {
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl MyDNSResolver {

    #[allow(unused)]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .build()
            .unwrap();
        let cache: HashMap<String, String> = serde_json::from_str(&load_cache_file().unwrap()).unwrap();
        let cache = Arc::new(Mutex::new(cache));
        Self {
            client,
            cache,
        }
    }

    #[allow(unused)]
    pub fn query_spf_record(&self, fqdn: &str) -> Result<Option<String>> {
        let records = self.query_simple(fqdn, "TXT")?;
        let spf_records: Vec<String> = records.into_iter().filter(|s| s.starts_with("v=spf1 ")).collect();
        if spf_records.len() == 0 {
            return Ok(None);
        }
        if spf_records.len() > 1 {
            println!("detect invalid SPF setting (multiple SPF records): {:?}", spf_records);
            return Ok(Some("*INVALID_SPF_SETTING*".to_string())); // go to "PERMERROR" (see "section 4.5" in RFC7208)
        }
        let spf_record = spf_records[0].clone();
        println!("spf_record: {}", spf_record);
        Ok(Some(spf_record))
    }

    #[allow(unused)]
    pub fn query_mx_record(&self, fqdn: &str) -> Result<Vec<String>> { // Vec may be empty
        let records = self.query_simple(fqdn, "MX")?;
        lazy_static! {
            static ref REGEX_MX_RECORD: Regex = Regex::new(r"^ *\d+ +(\S+) *$").unwrap();
        }
        let mut hosts = Vec::new();
        for record in records {
            match REGEX_MX_RECORD.captures(&record) {
                Some(caps) => hosts.push(caps[1].to_string()),
                None => return Err(anyhow!("invalid MX record: {}", record)),
            }
        }
        Ok(hosts)
    }

    #[allow(unused)]
    pub fn query_simple(&self, fqdn: &str, query_type: &str) -> Result<Vec<String>> { // Vec may be empty
        let query_result =
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    self.lookup(fqdn.to_string(), query_type.to_string()).await
                });
        let records = query_result?; // may be empty
        for s in &records {
            println!("dns_{}_record: {} {}", query_type, fqdn, s);
        }
        Ok(records)
    }

    #[allow(unused)]
    pub async fn lookup(&self, fqdn: String, query_type: String) -> Result<Vec<String>> {
        // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
        // https://developers.google.com/speed/public-dns/docs/doh/json?hl=ja
        let random_value: usize = 27; // rand::random();
        let headers = [
            ("Accept", "application/dns-json"),
        ];
        let query_type_number = if let Some(v) = get_query_type_number_from_string(&query_type) {
            v
        } else {
            return Err(anyhow!("invalid query type: {}", query_type));
        };
        let options = [
            ("name", fqdn.as_str()),
            ("type", &query_type_number.to_string()),
            ("cd", "false"),
            // ("ct", "application/dns-json"),
            ("do", "true"),
            ("edns_client_subnet", "0.0.0.0/0"),
            ("random_padding", &"x".repeat(random_value % 64 + 1)),
        ];
        let query_string = options.into_iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join("&");
        let url = format!("{}?{}", *DNS_PROVIDER_BASE_URL, query_string);
        let cache_data = {
            let mut guard = self.cache.lock().unwrap();
            if let Some(v) = guard.get(&url) {
                Some(v.clone())
            } else {
                None
            }
        };
        let response_text = if let Some(s) = cache_data {
            s
        } else {
            let s = self.issue_request_and_get_response(&url, &headers).await?;
            {
                let mut guard = self.cache.lock().unwrap();
                guard.insert(url.clone(), s.clone());
            }
            s
        };
        // println!("response_text: \"{}\"", response_text);
        let json: serde_json::Value = serde_json::from_str(&response_text)?;
        let results = if let serde_json::Value::Array(v) = &json["Answer"] {
            // resolve canonical name (automatically redirected by DoH server)
            if v.len() == 0 {
                Vec::new()
            } else {
                let mut table = HashMap::<String, Vec<String>>::new();
                for x in v {
                    let name = x["name"].as_str().unwrap().to_string(); // strip double-quotation
                    let data = strip_string_quotation(&x["data"].to_string());
                    if table.contains_key(&name) {
                        table.get_mut(&name).unwrap().push(data);
                    } else {
                        table.insert(name, vec![data]);
                    }
                }
                // println!("DEBUG: fqdn={:?} table={:?}", fqdn, table);
                let mut key = if !table.contains_key(&fqdn) && fqdn.ends_with(".") { fqdn[..(fqdn.len() - 1)].to_string() } else { fqdn.clone() };
                assert!(table.contains_key(&key));
                let v = loop {
                    let v = table.remove(&key).unwrap();
                    assert_ne!(v.len(), 0);
                    if v.len() > 1 {
                        break v;
                    }
                    let maybe_new_key = v[0].clone();
                    if table.contains_key(&maybe_new_key) {
                        key = maybe_new_key;
                        continue;
                    }
                    if maybe_new_key.ends_with(".") {
                        let maybe_new_key = maybe_new_key[..(maybe_new_key.len() - 1)].to_string(); // drop trailing dot
                        if table.contains_key(&maybe_new_key) {
                            key = maybe_new_key;
                            continue;
                        }
                    }
                    break v;
                };
                assert!(table.is_empty());
                v
            }
        } else {
            Vec::new() // empty
        };
        Ok(results)
    }

    #[allow(unused)]
    pub fn save_cache(&self) -> Result<()> {
        let guard = self.cache.lock().unwrap();
        save_cache_file(&serde_json::to_string(&*guard).unwrap())?;
        Ok(())
    }

    async fn issue_request_and_get_response(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
        let url = reqwest::Url::parse(url)?;
        let mut request = self.client.get(url.clone()).version(reqwest::Version::HTTP_2);
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        // println!("MyDNSResolver: issue request for: {}", url.to_string()[0..50].to_owned());
        let response = request.send().await?;
        // println!("MyDNSResolver: Response.version(): {:?} for {}", response.version(), url.to_string()[0..50].to_owned());
        let text = response.text().await?;
        Ok(text)
    }
}

fn get_query_type_number_from_string(s: &str) -> Option<u16> {
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    match s {
        "A"         => Some(1),
        "CNAME"     => Some(5),
        "PTR"       => Some(12),
        "MX"        => Some(15),
        "TXT"       => Some(16),
        "AAAA"      => Some(28),
        "SPF"       => Some(99),
        _           => None,
    }
}

lazy_static! {
    static ref REGEX_QUOTED_BY_DOUBLE_QUOTE: Regex = Regex::new(r#"^["](.*)["]$"#).unwrap();
    static ref REGEX_QUOTED_BY_ESCAPED_DOUBLE_QUOTE: Regex = Regex::new(r#"^(.*?)[\\]["]([^"]+?)[\\]["](.*)$"#).unwrap();
}

fn strip_string_quotation(original: &str) -> String {
    let mut result = original.to_string();
    loop {
        let prev_len = result.len();
        if let Some(caps) = REGEX_QUOTED_BY_DOUBLE_QUOTE.captures(&result) {
            result = caps[1].to_string();
        }
        if let Some(caps) = REGEX_QUOTED_BY_ESCAPED_DOUBLE_QUOTE.captures(&result) {
            result = format!("{}{}{}", caps[1].to_string(), caps[2].to_string(), caps[3].to_string());
        }
        if result.len() == prev_len {
            break;
        }
    }
    result
}

lazy_static! {
    static ref CACHE_FILENAME: String = "./dns_cache.json".to_string();
}

fn load_cache_file() -> Result<String> {
    let f = File::open(&*CACHE_FILENAME)?;
    let mut reader = BufReader::new(f);
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    Ok(buf)
}

fn save_cache_file(s: &str) -> Result<()> {
    let f = File::create(&*CACHE_FILENAME)?;
    let mut writer = BufWriter::new(f);
    writer.write_all(s.as_bytes())?;
    writer.flush()?;
    Ok(())
}
