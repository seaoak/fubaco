use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use rand;
use regex::Regex;
use reqwest;
use serde_json;

lazy_static! {
    static ref DNS_PROVIDER_BASE_URL: String = "https://1.1.1.1/dns-query".to_string();
}

#[derive(Debug)]
pub struct MyDNSResolver {
    client: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl MyDNSResolver {

    #[allow(unused)]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .build()
            .unwrap();
        let cache: HashMap<String, Vec<String>> = serde_json::from_str(&load_cache_file().unwrap()).unwrap();
        let cache = Arc::new(Mutex::new(cache));
        Self {
            client,
            cache,
        }
    }

    #[allow(unused)]
    pub async fn lookup(&self, fqdn: String, query_type: String) -> Result<Vec<String>> {
        // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
        // https://developers.google.com/speed/public-dns/docs/doh/json?hl=ja
        {
            let key = format!("{}&{}", fqdn, query_type);
            let mut guard = self.cache.lock().unwrap();
            if let Some(v) = guard.get(&key) {
                return Ok(v.clone());
            }
        }
        let random_value: usize = rand::random();
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
        let response_text = self.issue_request_and_get_response(&url, &headers).await?;
        // println!("response_text: \"{}\"", response_text);
        let json: serde_json::Value = serde_json::from_str(&response_text)?;
        let answers = if let serde_json::Value::Array(v) = &json["Answer"] {
            v.clone()
        } else {
            Vec::new() // empty
        };
        let results: Vec<String> = answers.into_iter().map(|v| strip_string_quotation(&v["data"].to_string())).collect();
        {
            let key = format!("{}&{}", fqdn, query_type);
            let mut guard = self.cache.lock().unwrap();
            guard.insert(key, results.clone()); // drop old value if exists
        }
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
