use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use rand;
use reqwest;
use serde_json;

lazy_static! {
    static ref DNS_PROVIDER_BASE_URL: String = "https://1.1.1.1/dns-query".to_string();
}

#[derive(Debug)]
pub struct MyDNSResolver {
    client: reqwest::Client,
}

impl MyDNSResolver {

    #[allow(unused)]
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .build()
            .unwrap();
        Self {
            client,
        }
    }

    #[allow(unused)]
    pub async fn lookup(&self, fqdn: String, query_type: String) -> Result<Vec<String>> {
        // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
        // https://developers.google.com/speed/public-dns/docs/doh/json?hl=ja
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
        println!("response_text: \"{}\"", response_text);
        let json: serde_json::Value = serde_json::from_str(&response_text)?;
        let answers = if let serde_json::Value::Array(v) = &json["Answer"] {
            v.clone()
        } else {
            Vec::new() // empty
        };
        let results: Vec<String> = answers.into_iter().map(|v| v["data"].to_string()).collect();
        Ok(results)
    }

    async fn issue_request_and_get_response(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
        let url = reqwest::Url::parse(url)?;
        let mut request = self.client.get(url.clone()).version(reqwest::Version::HTTP_2);
        for (k, v) in headers {
            request = request.header(*k, *v);
        }
        println!("MyDNSResolver: issue request for: {}", url.to_string()[0..50].to_owned());
        let response = request.send().await?;
        println!("MyDNSResolver: Response.version(): {:?} for {}", response.version(), url.to_string()[0..50].to_owned());
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
