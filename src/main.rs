use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use kana::wide2ascii;
use lazy_static::lazy_static;
use mail_parser::{Message, MessageParser};
use regex::Regex;
use rustls;
use rustls_native_certs;
use scraper;
use serde::{Deserialize, Serialize};
use tokio;
use unicode_normalization::UnicodeNormalization;
use webpki_roots;

mod my_crypto;
mod my_disconnect;
mod my_dkim_verifier;
mod my_dns_resolver;
mod my_dmarc_verifier;
mod my_message_parser;
mod my_spf_verifier;
mod my_text_line_stream;
mod pop3_upstream;

use my_crypto::*;
use my_dkim_verifier::DKIMResult;
use my_dns_resolver::MyDNSResolver;
use my_message_parser::MyMessageParser;
use my_spf_verifier::{SPFResult, SPFStatus};
use my_text_line_stream::MyTextLineStream;
use pop3_upstream::*;

//====================================================================
#[allow(unreachable_code)]
fn main() {
    println!("Hello, world!");

    if false {
        match test_my_crypto() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    if false {
        match test_my_dns_resolver() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    if false {
        match test_rustls_my_client() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    if false {
        match test_rustls_simple_client() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    if true {
        match test_spam_checker_with_local_files() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    if true {
        match test_pop3_bridge() {
            Ok(()) => (),
            Err(e) => panic!("{:?}", e),
        };
        std::process::exit(0);
    }

    match test_pop3_upstream() {
        Ok(()) => (),
        Err(e) => panic!("{:?}", e),
    };
}

fn normalize_string<P: AsRef<str>>(s: P) -> String {
    // normalize string (Unicode NFKC, uppercase, no-whitespace, no-bullet)
    let s: &str = s.as_ref();
    let mut unicode_normalized_str = String::new();
    unicode_normalized_str.extend(s.nfkc());
    wide2ascii(&unicode_normalized_str).to_uppercase().replace(&[' ', '　', '・'], "")
}

fn make_fubaco_padding_header(nbytes: usize) -> String { // generate just-nbyte-sized "X-Fubaco-Padding" header
    let line_length_limit = 80;
    let headding = "X-Fubaco-Padding: ".to_string();
    assert!(nbytes >= headding.len() + "x\r\n".len()); // at least one "x" is necessary
    let mut buf = format!("{}{}\r\n", headding, "x".repeat(nbytes - headding.len() - "\r\n".len())); // if line length is no limit

    // split buf into multi-line
    let mut pos = line_length_limit - "\r\n".len();
    while pos <= buf.len() - "\r\n x\r\n".len() {
        buf.replace_range(pos..(pos + "\r\n ".len()), "\r\n ");
        pos += line_length_limit;
    }
    if pos < buf.len() { // odd position
        pos = buf.len() - "\r\n x\r\n".len(); // roll back
        buf.replace_range(pos..(pos + "\r\n ".len()), "\r\n ");
    }
    assert!(buf.ends_with("x\r\n")); // at least one "x" is contained in last line
    buf
}

fn load_tsv_file<P: AsRef<Path>>(path: P) -> Result<Vec<Vec<String>>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.starts_with("#") {
            continue; // skip comment
        }
        let fields = line.split("\t").filter(|s| s.len() > 0).map(|s| s.to_string()).collect::<Vec<String>>();
        if fields.len() == 0 {
            continue; // skip empty line
        }
        lines.push(fields);
    }
    Ok(lines)
}

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE_GENERAL: Regex = Regex::new(r"^([A-Z]+)(?: +(\S+)(?: +(\S+))?)? *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_USER: Regex = Regex::new(r"^USER +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND: Regex = Regex::new(r"^ *(\S+) +(\S+) *$").unwrap(); // "\r\n" is stripped
    static ref REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS: Regex = Regex::new(r"\b([1-9][0-9]*) octets\b").unwrap();
    static ref DATABASE_FILENAME: String = "./db.json".to_string();
    static ref FUBACO_HEADER_TOTAL_SIZE: usize = 512; // (78+2)*6+(30+2)
}

lazy_static! {
    static ref MY_DNS_RESOLVER: Arc<MyDNSResolver> = Arc::new(MyDNSResolver::new());
}

fn test_my_crypto() -> Result<()> {
    {
        let input_text = "";
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha1, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha1: {}", input_text, base64_string);
        assert_eq!(base64_string, "2jmj7l5rSw0yVb/vlWAYkK/YBwk="); // see "section 3.4.4" in RFC6376
    }
    {
        let input_text = "\r\n"; // CRLF
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha1, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha1: {}", input_text, base64_string);
        assert_eq!(base64_string, "uoq1oCgLlTqpdDX/iUbLy7J1Wic="); // see "section 3.4.3" in RFC6376
    }
    {
        let input_text = "";
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha256, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha256: {}", input_text, base64_string);
        assert_eq!(base64_string, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="); // see "section 3.4.4" in RFC6376
    }
    {
        let input_text = "\r\n"; // CRLF
        let sha1_vec = my_calc_hash(MyHashAlgo::Sha256, input_text.as_bytes());
        let base64_string = BASE64_STANDARD.encode(sha1_vec);
        println!("input: \"{}\" => base64 of sha256: {}", input_text, base64_string);
        assert_eq!(base64_string, "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="); // see "section 3.4.3" in RFC6376
    }
    Ok(())
}

fn test_my_dns_resolver() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            println!("Hello world in tokio");
            let queries = [
                ("seaoak.jp", "A"),
                ("seaoak.jp", "AAAA"),
                ("seaoak.jp", "TXT"),
                ("_dmarc.seaoak.jp", "TXT"),
            ];
            let mut infos = Vec::new();
            for (fqdn, query_type) in queries {
                let resolver = MY_DNS_RESOLVER.clone();
                let handle = tokio::spawn(async move {
                    resolver.lookup(fqdn.to_string(), query_type.to_string()).await
                });
                infos.push((fqdn, query_type, handle));
            }
            for info in infos {
                let (fqdn, query_type, handle) = info;
                let results = handle.await??;
                for result in results {
                    println!("Result: {} {} \"{}\"", fqdn, query_type, result);
                }
            }
            Ok::<(), anyhow::Error>(())
        })?;
    Ok(())
}

fn test_rustls_my_client() -> Result<()> {
    let upstream_hostname = "seaoak.jp".to_string();
    let upstream_port = 443;

    let tls_root_store =
        rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    let tls_config =
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(tls_root_store)
                .with_no_client_auth(),
        );
    let upstream_host = upstream_hostname.clone().try_into().unwrap();
    let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
    let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname, upstream_port))?;
    let mut upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);

    println!("issue HTTP request");
    upstream_tls_stream.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: seaoak.jp\r\n",
            // "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n",
        ).as_bytes(),
    )?;
    let ciphersuite = upstream_tls_stream.conn.negotiated_cipher_suite().unwrap();
    eprintln!("Current ciphersuite: {:?}", ciphersuite.suite());
    let mut plaintext = Vec::new();
    let mut local_buf = [0u8; 1024];
    loop {
        let nbytes = match upstream_tls_stream.read(&mut local_buf) {
            Ok(0) => return Err(anyhow!("steam is closed unexpectedly")),
            Ok(len) => len,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                eprintln!("retry read()");
                // upstream_tls_connection.process_new_packets()?;
                continue;
            },
            Err(e) => return Err(anyhow!(e)),
        };
        plaintext.extend(&local_buf[0..nbytes]);
        if MyTextLineStream::<TcpStream>::ends_with_u8(&plaintext, b"</html>\n") { // allow empty line
            eprintln!("detect last LF");
            break;
        }
    }
    eprintln!("------------------------------");
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn test_rustls_simple_client() -> Result<()> {
    let upstream_hostname = "seaoak.jp".to_string();
    let upstream_port = 443;

    let tls_root_store =
        rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    let tls_config =
        Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(tls_root_store)
                .with_no_client_auth()
        );
    let upstream_host = upstream_hostname.clone().try_into().unwrap();
    let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
    let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname, upstream_port))?;
    let mut upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);

    println!("issue HTTP request");
    upstream_tls_stream.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: seaoak.jp\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n",
        ).as_bytes(),
    )?;
    let ciphersuite = upstream_tls_stream.conn.negotiated_cipher_suite().unwrap();
    eprintln!("Current ciphersuite: {:?}", ciphersuite.suite());
    let mut plaintext = Vec::new();
    upstream_tls_stream.read_to_end(&mut plaintext)?;
    std::io::stdout().write_all(&plaintext)?;
    Ok(())
}

fn spam_checker_suspicious_envelop_from(message: &Message) -> Option<String> {
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string(); // may be empty string
    let envelop_from = envelop_from.replace(&['<', '>'], "").to_lowercase().trim().to_string();
    println!("Evelop.from: \"{}\"", envelop_from);
    if envelop_from.len() == 0 {
        Some("suspicious-envelop-from".to_string())
    } else {
        None
    }
}

fn spam_checker_blacklist_tld(message: &Message) -> Option<String> {
    let blacklist_tld_list = vec![".cn", ".ru", ".hu", ".br", ".su", ".nz", ".in", ".cz", ".be", ".cl"];
    let header_from = message.from().unwrap().first().map(|addr| addr.address.clone().unwrap_or_default().to_string()).unwrap_or_default().to_lowercase();
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string().replace(&['<', '>'], "").to_lowercase(); // may be empty string
    println!("Evelop.from: \"{}\"", envelop_from);
    let mut is_spam = false;
    for tld in &blacklist_tld_list {
        if header_from.ends_with(tld) {
            println!("blacklist-tld in from header address: \"{}\"", header_from);
            is_spam = true;
        }
    }
    for tld in &blacklist_tld_list {
        if envelop_from.ends_with(tld) {
            println!("blacklist-tld in envelop from address: \"{}\"", envelop_from);
            is_spam = true;
        }
    }
    if is_spam {
        Some("blacklist-tld".to_string())
    } else {
        None
    }
}

fn spam_checker_suspicious_from(message: &Message) -> Option<String> {
    let name = normalize_string(message.from().unwrap().first().unwrap().name.clone().unwrap_or_default());
    println!("From.name: \"{}\"", name);
    let address = normalize_string(message.from().unwrap().first().unwrap().address.clone().unwrap_or_default());
    println!("From.address: \"{}\"", address);
    let subject = normalize_string(message.subject().unwrap_or_default());
    println!("Subject: \"{}\"", subject);
    let destination = normalize_string(message.to().unwrap().first().map(|addr| addr.address.clone().unwrap()).unwrap_or_default()); // may be empty string
    println!("To.address: \"{}\"", destination);
    let (expected_from_address_regex, prohibited_words): (Regex, Vec<String>) = (|| {
        lazy_static! {
            static ref REGEX_ALWAYS_MATCH: Regex = Regex::new(r".").unwrap();
            static ref REGEX_DOT_AT_THE_FIRST: Regex = Regex::new(r"^[.]").unwrap();
        }
        let filename = "list_suspicious_from.tsv";
        let mut lines = match load_tsv_file(filename) {
            Ok(v) => v,
            Err(e) => {
                println!("can not load \"{}\": {}", filename, e);
                return (REGEX_ALWAYS_MATCH.clone(), Vec::new());
            },
        };
        assert!(lines.iter().all(|fields| fields.len() > 0));
        for fields in &mut lines {
            fields[0] = normalize_string(&fields[0]);
        }
        let (v1, v2): (Vec<Vec<String>>, Vec<Vec<String>>) = lines.into_iter().partition(|fields| fields.len() == 1);
        let prohibited_words = v1.into_iter().map(|fields| fields[0].clone()).collect::<Vec<String>>();
        let matched_lines = v2.into_iter().filter(|fields| name.contains(&fields[0]) || subject.contains(&fields[0])).collect::<Vec<Vec<String>>>();
        if matched_lines.len() == 0 {
            return (REGEX_ALWAYS_MATCH.clone(), prohibited_words);
        }
        let mut domains = Vec::new();
        for fields in matched_lines.into_iter() { // merge all matched lines
            assert!(fields.len() > 1);
            domains.extend(fields.into_iter().skip(1).map(|s| REGEX_DOT_AT_THE_FIRST.replace(&s, "").to_string())); // remove redundant dot
        }
        assert_ne!(domains.len(), 0);
        let joined_string = domains.into_iter().map(|s| s.replace(".", "[.]")).collect::<Vec<String>>().join("|");
        let pattern_string = format!("(?i)[.@]({})$", joined_string); // case-insensitive
        let regex = match Regex::new(&pattern_string) {
            Ok(v) => v,
            Err(_e) => {
                println!("REGEX for suspicious-from is invalid: {}", pattern_string);
                return (REGEX_ALWAYS_MATCH.clone(), prohibited_words);
            },
        };
        (regex, prohibited_words)
    })();

    if !expected_from_address_regex.is_match(&address) {
        return Some("suspicious-from".to_string());
    }
    if prohibited_words.iter().any(|s| name.contains(s)) {
        return Some("prohibited-word-in-from".to_string());
    }
    if prohibited_words.iter().any(|s| subject.contains(s)) {
        return Some("prohibited-word-in-subject".to_string());
    }
    if address == destination { // header.from is camoflaged with destination address
        return Some("suspicious-from".to_string());
    }
    None
}

fn spam_checker_suspicious_hyperlink(message: &Message) -> Option<String> {
    let html;
    match message.body_html(0) {
        Some(v) => html = v,
        None => return None,
    }
    let dom = scraper::Html::parse_document(&html);
    let selector = scraper::Selector::parse(r"a[href]").unwrap();
    for elem in dom.select(&selector) {
        let url = elem.value().attr("href").unwrap();
        lazy_static! {
            static ref REGEX_URL_WITH_NORMAL_HOST: Regex = Regex::new(r"^https?[:][/][/]([-_a-z0-9.]+)([/]\S*)?$").unwrap();
        }
        let host_in_href;
        if let Some(caps) = REGEX_URL_WITH_NORMAL_HOST.captures(url) {
            host_in_href = caps[1].to_string();
        } else {
            // for example, "with port number", "with percent-encoded", "with BASIC authentication info"
            println!("suspicious-href: \"{}\"", url);
            return Some("suspicious-href".to_string()); // camouflaged hostname
        }
        let text = elem.inner_html();
        if let Some(caps) = REGEX_URL_WITH_NORMAL_HOST.captures(&text) {
            let host_in_text = caps[1].to_string();
            if host_in_href != host_in_text {
                println!("camouflage-hyperlink: \"{}\" vs \"{}\"", host_in_href, host_in_text);
                return Some("camouflaged-hyperlink".to_string());
            }
        }
    }
    None
}

fn spam_checker_hidden_text_in_html(message: &Message) -> Option<String> {
    let html;
    match message.body_html(0) {
        Some(v) => html = v,
        None => return None,
    }
    lazy_static! {
        static ref REGEX_CSS_FOR_HIDDEN_TEXT: Regex = Regex::new(r"(?i)\bfont-size:\s*0").unwrap(); // case insensitive
    }
    if REGEX_CSS_FOR_HIDDEN_TEXT.is_match(&html) {
        return Some("hidden-text-in-html".to_string());
    }
    None
}

fn spam_checker_fully_html_encoded_text(message: &Message) -> Option<String> {
    // https://ja.wikipedia.org/wiki/文字参照
    // https://ja.wikipedia.org/wiki/Quoted-printable
    let text;
    match message.body_text(0) {
        Some(v) => text = v,
        None => return None,
    }
    lazy_static! {
        static ref REGEX_NUMERIC_CARACTER_REFERENCE: Regex = Regex::new(r"^([&][#](\d+|x[0-9a-fA-F]+)[;])+[=]?\r?\n").unwrap();
    }
    if REGEX_NUMERIC_CARACTER_REFERENCE.is_match(&text) {
        return Some("fully-html-encoding-text".to_string());
    }
    None
}

fn spam_checker_suspicious_delivery_report(message: &Message) -> Option<String> {
    let from_address = message.from().unwrap().first().unwrap().address.clone().unwrap_or_default().to_ascii_lowercase();
    if !from_address.starts_with("postmaster@") {
        return None;
    }
    for part in message.parts.iter() {
        let mut is_target_part = false;
        for header in part.headers.iter() {
            match header.name {
                mail_parser::HeaderName::ContentType => {
                    match header.value() {
                        mail_parser::HeaderValue::ContentType(ctype) => {
                            if ctype.ctype() == "message" && ctype.subtype() == Some("delivery-status") {
                                is_target_part = true;
                                break;
                            }
                        },
                        _ => (), // skip
                    }
                },
                _ => (), // skip
            }
        }
        if !is_target_part {
            continue;
        }
        let text = part.text_contents().unwrap();

        lazy_static! {
            static ref REGEX_REPORT_DOMAIN: Regex = Regex::new(r"^Reporting-MTA: [^;]+;\s*(\S+)\s*$").unwrap();
            static ref REGEX_DESTINATION_DOMAIN: Regex = Regex::new(r"^Final-Recipient: [^;]+;\s*([-_.+=0-9a-zA-Z]+@([-_.0-9a-zA-Z]+))\s*$").unwrap();
        }

        let mut report_domain = None;
        let mut destination_domain = None;
        for line in text.lines() {
            if let Some(caps) = REGEX_REPORT_DOMAIN.captures(line) {
                report_domain = Some(caps[1].to_string().to_ascii_lowercase());
            }
            if let Some(caps) = REGEX_DESTINATION_DOMAIN.captures(line) {
                destination_domain = Some(caps[2].to_string().to_ascii_lowercase());
            }
        }
        match (&report_domain, &destination_domain) {
            (Some(domain1), Some(domain2)) => {
                println!("delivery_report: report_domain={} destination_domain={}", domain1, domain2);
                if domain1 != domain2 {
                    // report_domain may be an "open relay" mail server
                    return Some("suspicious-delivery-report".to_string());
                }
            },
            _ => {
                println!("delivery report syntax error");
                return Some("invalid-delivery-report-format".to_string());
            }
        }
    }
    None
}

fn make_fubaco_headers(message_u8: &[u8]) -> Result<String> {
    let message;
    if let Some(v) = MessageParser::default().parse(message_u8) {
        message = v;
    } else {
        return Err(anyhow!("can not parse the message"));
    }

    let mut spam_judgement: Vec<String> = [
        spam_checker_suspicious_envelop_from,
        spam_checker_blacklist_tld,
        spam_checker_suspicious_from,
        spam_checker_suspicious_hyperlink,
        spam_checker_hidden_text_in_html,
        spam_checker_fully_html_encoded_text,
        spam_checker_suspicious_delivery_report,
    ].iter().filter_map(|f| f(&message)).collect();
    if spam_judgement.len() == 0 {
        spam_judgement.push("none".to_string());
    }

    let table_of_authentication_results_header = message.get_authentication_results();

    let mut spf_result = my_spf_verifier::spf_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        if let Some(mx_spf_status) = table.get("spf") {
            let mx_spf_status = mx_spf_status.parse::<SPFStatus>().unwrap(); // TODO: unknonw string may have to be an error, not panic
            if &mx_spf_status != spf_result.as_status() {
                println!("WARNING: my SPF checker says different result to \"Authentication-Results\" header: my={} vs header={}", spf_result.as_status(), mx_spf_status);
            }
            let mx_spf_domain = table.get("spf-target-domain").map(|s| s.to_string());
            if mx_spf_domain.is_some() && &mx_spf_domain != spf_result.as_domain() {
                let my_domain = spf_result.as_domain().clone().unwrap_or_default();
                let mx_domain = mx_spf_domain.clone().unwrap();
                println!("WARNING: my SPF checker says different target domain to \"Authentication-Results\" header: my={} vs header={}", my_domain, mx_domain);
            }
            if mx_spf_status != SPFStatus::NONE {
                let domain = mx_spf_domain.or_else(|| spf_result.as_domain().clone());
                spf_result = SPFResult::new(mx_spf_status, domain); // overwrite
            }
        }
    }
    let dkim_result = my_dkim_verifier::dkim_verify(&message, &MY_DNS_RESOLVER);
    let mut dkim_status = dkim_result.to_string();
    let mut dkim_target = match &dkim_result {
        DKIMResult::PASS(addr) => Some(addr.to_string()),
        _ => None,
    };
    if let Some(table) = &table_of_authentication_results_header {
        if let Some(mx_dkim_status) = table.get("dkim").or_else(|| table.get("dkim-adsp")) {
            if mx_dkim_status != &dkim_status {
                println!("WARNING: my DKIM checker says different result to \"Authentication-Results\" header: my={} vs header={}", dkim_status, mx_dkim_status);
            }
            if mx_dkim_status != "none" {
                dkim_status = mx_dkim_status.to_string(); // overwrite
            }
            if let Some(mx_dkim_target) = table.get("dkim-target-domain") {
                if let Some(my_dkim_target) = &dkim_target {
                    if mx_dkim_target != my_dkim_target {
                        println!("WARNING: my DKIM checker says different target domain to \"Authentication-Results\" header: my={} vs header={}", my_dkim_target, mx_dkim_target);
                    }
                }
                if mx_dkim_status == "pass" {
                    dkim_target = Some(mx_dkim_target.to_string()); // overwrite
                }
            }
        }
    }
    let dmarc_result = my_dmarc_verifier::dmarc_verify(&message, spf_result.as_domain(), &dkim_target, &MY_DNS_RESOLVER);
    let mut dmarc_status = dmarc_result.to_string();
    if let Some(table) = &table_of_authentication_results_header {
        if let Some(mx_dmarc_status) = table.get("dmarc") {
            if mx_dmarc_status != &dmarc_status {
                println!("WARNING: my DMARC checker says different result to \"Authentication-Results\" header: my={} vs header={}", dmarc_status, mx_dmarc_status);
            }
            if mx_dmarc_status != "none" {
                dmarc_status = mx_dmarc_status.to_string(); // overwrite
            }
        }
    }

    let auth_results = vec![
        format!("spf={}", spf_result.as_status()),
        format!("dkim={}", dkim_status),
        format!("dmarc={}", dmarc_status),
    ];

    let mut fubaco_headers = Vec::new();
    fubaco_headers.push(format!("X-Fubaco-Spam-Judgement: {}\r\n", spam_judgement.join(" ")));
    fubaco_headers.push(format!("X-Fubaco-Authentication: {}\r\n", auth_results.join(" ")));
    let nbytes = fubaco_headers.iter().fold(0, |acc, s| acc + s.len());
    fubaco_headers.push(make_fubaco_padding_header(*FUBACO_HEADER_TOTAL_SIZE - nbytes));
    Ok(fubaco_headers.join(""))
}

#[allow(unused)]
fn test_spam_checker_with_local_files() -> Result<()> {
    let path_to_dir = std::path::Path::new("./mail-sample");
    for entry in path_to_dir.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let filename = entry.file_name().to_string_lossy().to_string();
        if !filename.starts_with("mail-sample.") || !filename.ends_with(".eml") {
            continue;
        }
        println!("------------------------------------------------------------------------------");
        println!("FILE: {}", filename);
        let f = File::open(entry.path())?;
        let mut reader = BufReader::new(f);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let fubaco_headers = make_fubaco_headers(&buf)?;
        print!("{}", fubaco_headers);
    }
    MY_DNS_RESOLVER.save_cache()?;
    Ok(())
}

#[allow(unused)]
fn test_pop3_bridge() -> Result<()> {
    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    struct Username(String);

    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct Hostname(String);

    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
    struct UniqueID(String);

    #[derive(Clone, Debug, Serialize, Deserialize)]
    struct MessageInfo {
        username: Username,
        unique_id: UniqueID,
        fubaco_headers: String,
        is_deleted: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
    struct MessageNumber(u32);

    let username_to_hostname: HashMap<Username, Hostname> = vec![
        "FUBACO_Nq2DYd4cFHGZ_U",
        "FUBACO_Km2TTTAEMErD_H",
        "FUBACO_NC7s2kMrxDnU_U",
        "FUBACO_Fzkd5hfaTv6D_H",
        "FUBACO_SiwDkj2vtpqH_U",
        "FUBACO_MFhg2T3pxVRW_H",
        "FUBACO_GYDTwK7YTcbU_U",
        "FUBACO_QW5DV9Wko6oC_H",
    ].into_iter().map(|s| env::var(s).unwrap()).collect::<Vec<String>>().chunks(2).map(|v| (Username(v[0].clone()), Hostname(v[1].clone()))).collect();

    fn load_db_file() -> Result<String> {
        let f = File::open(&*DATABASE_FILENAME)?;
        let mut reader = BufReader::new(f);
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn save_db_file(s: &str) -> Result<()> {
        let f = File::create(&*DATABASE_FILENAME)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(s.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    // https://serde.rs/derive.html
    let mut database: HashMap<Username, HashMap<UniqueID, MessageInfo>> = serde_json::from_str(&load_db_file()?).unwrap(); // permanent table (save and load a DB file)
    let lack_keys: Vec<Username> = username_to_hostname.keys().filter(|u| !database.contains_key(u)).map(|u| u.clone()).collect();
    lack_keys.into_iter().for_each(|u| {
        database.insert(u, HashMap::new());
    });

    // https://doc.rust-lang.org/std/net/struct.TcpListener.html
    let downstream_port = 5940;
    let downstream_addr = format!("{}:{}", "127.0.0.1", downstream_port);
    let listener = TcpListener::bind(downstream_addr)?;
    loop {
        match listener.accept() {
            Ok((downstream_tcp_stream, remote_addr)) => {
                // https://doc.rust-lang.org/std/net/enum.SocketAddr.html#method.ip
                assert_eq!(remote_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

                let mut downstream_stream = MyTextLineStream::connect(downstream_tcp_stream);

                // send dummy greeting message to client (upstream is not opened yet)
                println!("send dummy greeting message to downstream");
                downstream_stream.write_all_and_flush(b"+OK Greeting\r\n")?;

                // wait for "USER" command to identify mail account
                let username;
                let upstream_hostname;
                let upstream_port = 995;
                {
                    let mut command_line = Vec::<u8>::new();
                    downstream_stream.read_some_lines(&mut command_line)?;
                    let command_str = String::from_utf8_lossy(&command_line);
                    match REGEX_POP3_COMMAND_LINE_FOR_USER.captures(&command_str) {
                        Some(caps) => username = Username(caps.get(1).unwrap().as_str().to_string()),
                        None => return Err(anyhow!("The first POP3 command should be \"USER\", but: {}", command_str.trim())),
                    }
                    match username_to_hostname.get(&username) {
                        Some(h) => upstream_hostname = h.clone(),
                        None => return Err(anyhow!("FATAL: unknown username: {:?}", username)),
                    }
                }
                println!("username: {}", username.0);
                println!("upstream_addr: {}:{}", upstream_hostname.0, upstream_port);

                println!("open upstream connection");
                let tls_root_store = if false {
                    // use "rustls-native-certs" crate
                    let mut roots = rustls::RootCertStore::empty();
                    for cert in rustls_native_certs::load_native_certs()? {
                        roots.add(cert).unwrap();
                    }
                    roots
                } else {
                    // use "webpki-roots" crate
                    rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS
                            .iter()
                            .cloned(),
                    )
                };
                let tls_config =
                    Arc::new(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(tls_root_store)
                            .with_no_client_auth(),
                    );
                let mut upstream_host = upstream_hostname.0.clone().try_into().unwrap();
                let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
                let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname.0, upstream_port))?;
                let mut upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);
                let mut upstream_stream = MyTextLineStream::connect(upstream_tls_stream);

                // wait for POP3 greeting message from server
                {
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("greeting message is received: {}", status_line.trim());
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: invalid greeting message is received: {}", status_line.trim()));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // issue delayed "USER" command
                {
                    println!("issue USER command");
                    let mut command_line = format!("USER {}\r\n", username.0).into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for USER command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("relay the response: {}", status_line.trim());
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for USER command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // relay "PASS" command
                {
                    let mut command_line = Vec::<u8>::new();
                    downstream_stream.read_some_lines(&mut command_line)?;
                    let command_str = String::from_utf8_lossy(&command_line);
                    println!("relay POP3 command: {}", command_str.trim());
                    if !command_str.starts_with("PASS ") {
                        return Err(anyhow!("2nd command should be \"PASS\" command, but: {}", command_str.trim()));
                    }
                    upstream_stream.write_all_and_flush(&command_line)?;
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("relay the response: {}", status_line.trim());
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for PASS command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // issue internal "UIDL" command (to get unique-id for all mails)
                let message_number_to_unique_id;
                {
                    println!("issue internal UIDL command");
                    let mut command_line = format!("UIDL\r\n").into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for UIDL command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("the response for UIDL command is received: {}", status_line.trim());
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for UIDL command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                    println!("parse response body of UIDL command");
                    let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
                    let body_text = String::from_utf8_lossy(body_u8);
                    let mut table: HashMap<MessageNumber, UniqueID> = HashMap::new();
                    for line in body_text.split_terminator("\r\n") {
                        if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                            let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                            let unique_id = UniqueID(caps.get(2).unwrap().as_str().into());
                            let is_already_exists = table.insert(message_number, unique_id).is_some();
                            assert!(!is_already_exists);
                        } else {
                            return Err(anyhow!("invalid response: {}", line));
                        }
                    }
                    message_number_to_unique_id = table;
                    println!("Done");
                }

                // issue internal "LIST" command (to get message size for all mails)
                let message_number_to_nbytes;
                {
                    println!("issue internal LIST command");
                    let mut command_line = format!("LIST\r\n").into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for LIST command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("the response for UIDL command is received: {}", status_line.trim());
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for LIST command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                    println!("parse response body of LIST command");
                    let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
                    let body_text = String::from_utf8_lossy(body_u8);
                    let mut table: HashMap<MessageNumber, usize> = HashMap::new();
                    for line in body_text.split_terminator("\r\n") {
                        if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                            let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                            let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                            let is_already_exists = table.insert(message_number, nbytes).is_some();
                            assert!(!is_already_exists);
                        } else {
                            return Err(anyhow!("invalid response: {}", line));
                        }
                    }
                    message_number_to_nbytes = table;
                    println!("Done");
                }

                let mut unique_id_to_message_info = database.get_mut(&username).unwrap(); // borrow mutable ref
                if (unique_id_to_message_info.len() == 0) { // at the first time only, all existed massages are treated as old messages which have no fubaco header
                    for (message_number, unique_id) in message_number_to_unique_id.iter() {
                        let nbytes = message_number_to_nbytes[message_number];
                        let info =
                            MessageInfo {
                                username: username.clone(),
                                unique_id: unique_id.clone(),
                                fubaco_headers: "".to_string(),
                                is_deleted: false,
                            };
                        let ret = unique_id_to_message_info.insert(unique_id.clone(), info);
                        assert!(ret.is_none());
                    }
                }
                println!("{} messages exist in database", unique_id_to_message_info.len());

                let total_nbytes_of_maildrop = message_number_to_nbytes.values().fold(0, |acc, nbytes| acc + nbytes);
                println!("total_nbytes_of_maildrop = {}", total_nbytes_of_maildrop);
                let total_nbytes_of_modified_maildrop = message_number_to_unique_id
                    .iter()
                    .map(|(message_number, unique_id)| {
                        if let Some(info) = unique_id_to_message_info.get(unique_id) {
                            message_number_to_nbytes[message_number] + info.fubaco_headers.len()
                        } else {
                            message_number_to_nbytes[message_number] + *FUBACO_HEADER_TOTAL_SIZE
                        }
                    })
                    .fold(0, |acc, nbytes| acc + nbytes);
                println!("total_nbytes_of_modified_maildrop = {}", total_nbytes_of_modified_maildrop);

                // relay POP3 commands/responses
                loop {
                    let command_name;
                    let command_arg1;
                    let command_arg2;
                    let is_multi_line_response_expected;
                    { // relay a POP3 command
                        let mut command_line = Vec::<u8>::new();
                        downstream_stream.read_some_lines(&mut command_line)?;
                        let command_str = String::from_utf8_lossy(&command_line);
                        println!("relay POP3 command: {}", command_str.trim());
                        upstream_stream.write_all_and_flush(&command_line)?;
                        println!("Done");

                        if let Some(caps) = REGEX_POP3_COMMAND_LINE_GENERAL.captures(&command_str) {
                            command_name = caps[1].to_string();
                            command_arg1 = caps.get(2).map(|v| v.as_str().to_owned());
                            command_arg2 = caps.get(3).map(|v| v.as_str().to_owned());
                        } else {
                            return Err(anyhow!("invalid command line: {}", command_str.trim()));
                        }

                        is_multi_line_response_expected = match command_name.as_str() {
                            "STAT"                           => false,
                            "LIST" if command_arg1.is_none() => true,
                            "LIST" if command_arg1.is_some() => false,
                            "RETR"                           => true,
                            "DELE"                           => false,
                            "NOOP"                           => false,
                            "RSET"                           => false,
                            "QUIT"                           => false,
                            "TOP"                            => true,
                            "UIDL" if command_arg1.is_none() => true,
                            "UIDL" if command_arg1.is_some() => false,
                            "USER"                           => false,
                            "PASS"                           => false,
                            _ => return Err(anyhow!("unknown command: {}", command_str.trim())),
                        };
                    }

                    let mut response_lines = Vec::<u8>::new();
                    let mut is_first_response = true;
                    let mut status_line = "".to_string(); // dummy initialization (must be set to a string before use)
                    loop { // receive lines until the end of a response
                        upstream_stream.read_some_lines(&mut response_lines)?;
                        if (is_first_response) {
                            status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                        }
                        if is_first_response && status_line.starts_with("-ERR") {
                            println!("ERR response is received: {}", status_line.trim());
                            break;
                        }
                        assert!(!is_first_response || status_line.starts_with("+OK"));
                        if !is_multi_line_response_expected {
                            println!("single-line response is received: {}", status_line.trim());
                            break;
                        }
                        if MyTextLineStream::<TcpStream>::ends_with_u8(&response_lines, b"\r\n.\r\n") {
                            println!("multl-line response ({} byte body) is received: {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line.trim());
                            break;
                        }
                        is_first_response = false;
                    }
                    if status_line.starts_with("+OK") {
                        // modify response
                        if command_name == "LIST" && command_arg1.is_some() {
                            println!("modify single-line response for LIST command");
                            let arg_message_number = MessageNumber(u32::from_str_radix(&command_arg1.clone().unwrap(), 10).unwrap());
                            let unique_id;
                            if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
                                unique_id = v;
                            } else {
                                return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
                            }
                            let message_number;
                            let nbytes;
                            if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                                message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().as_str(), 10).unwrap());
                                nbytes = usize::from_str_radix(caps.get(2).unwrap().as_str(), 10).unwrap();
                            } else {
                                return Err(anyhow!("invalid response: {}", status_line.trim()));
                            }
                            assert_eq!(message_number, arg_message_number);
                            assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                            let new_nbytes;
                            if let Some(info) = unique_id_to_message_info.get(unique_id) {
                                new_nbytes = nbytes + info.fubaco_headers.len();
                            } else {
                                new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
                            }
                            response_lines.clear();
                            response_lines.extend(format!("+OK {} {}\r\n", message_number.0, new_nbytes).into_bytes());
                            println!("Done");
                        }
                        if command_name == "LIST" && command_arg1.is_none() {
                            println!("modify multi-line response for LIST command");
                            let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
                            let body_text = String::from_utf8_lossy(body_u8);
                            let mut buf = Vec::<u8>::with_capacity(body_u8.len());
                            let mut total_nbytes = 0;
                            for line in body_text.split_terminator("\r\n") {
                                if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                                    let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                                    let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                                    assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                                    let unique_id = &message_number_to_unique_id[&message_number];
                                    let new_nbytes;
                                    if let Some(info) = unique_id_to_message_info.get(unique_id) {
                                        new_nbytes = nbytes + info.fubaco_headers.len();
                                    } else {
                                        new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
                                    }
                                    total_nbytes += new_nbytes;
                                    buf.extend(format!("{} {}\r\n", message_number.0, new_nbytes).into_bytes());
                                } else {
                                    return Err(anyhow!("invalid response: {}", line));
                                }
                            }
                            assert_eq!(total_nbytes, total_nbytes_of_modified_maildrop);

                            let new_status_line;
                            if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                                let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                                assert_eq!(nbytes, total_nbytes_of_maildrop);
                                assert!(nbytes <= total_nbytes);
                                assert_eq!(0, (total_nbytes - nbytes) % *FUBACO_HEADER_TOTAL_SIZE);
                                new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, format!("{} octets", total_nbytes)).to_string();
                            } else {
                                new_status_line = status_line.clone();
                            }

                            response_lines.clear();
                            response_lines.extend(new_status_line.into_bytes());
                            response_lines.extend(buf);
                            response_lines.extend(".\r\n".as_bytes());
                            println!("Done");
                        }
                        if command_name == "RETR" || command_name == "TOP" {
                            println!("modify response body for RETR/TOP command");
                            let arg_message_number = MessageNumber(u32::from_str_radix(&command_arg1.clone().unwrap(), 10).unwrap());
                            let unique_id;
                            if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
                                unique_id = v;
                            } else {
                                return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
                            }
                            let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];

                            let fubaco_headers;
                            if let Some(info) = unique_id_to_message_info.get(unique_id) {
                                if command_name == "RETR" {
                                    assert_eq!(body_u8.len(), message_number_to_nbytes[&arg_message_number]);
                                }
                                fubaco_headers = info.fubaco_headers.clone();
                            } else {
                                // TODO: SPAM checker
                                fubaco_headers = make_fubaco_headers(body_u8)?;
                                println!("add fubaco headers:\n----------\n{}----------", fubaco_headers);
                                unique_id_to_message_info.insert(
                                    unique_id.clone(),
                                    MessageInfo {
                                        username: username.clone(),
                                        unique_id: unique_id.clone(),
                                        fubaco_headers: fubaco_headers.clone(),
                                        is_deleted: false,
                                    },
                                );
                            };

                            let mut buf = Vec::<u8>::new();
                            buf.extend(fubaco_headers.as_bytes());
                            buf.extend(body_u8.iter());

                            let new_status_line;
                            if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                                let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                                assert_eq!(nbytes, body_u8.len());
                                let new_nbytes = nbytes + fubaco_headers.len();
                                new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, format!("{} octets", new_nbytes)).to_string();
                            } else {
                                new_status_line = status_line.clone();
                            }

                            response_lines.clear();
                            response_lines.extend(new_status_line.into_bytes());
                            response_lines.extend(buf);
                            response_lines.extend(".\r\n".as_bytes());
                            println!("Done");
                        }
                        if command_name == "STAT" {
                            println!("modify single-line response for STAT command");
                            let num_of_messages;
                            let nbytes;
                            if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                                num_of_messages = usize::from_str_radix(&caps[1], 10).unwrap();
                                nbytes = usize::from_str_radix(&caps[2], 10).unwrap();
                            } else {
                                return Err(anyhow!("invalid response: {}", status_line.trim()));
                            }
                            assert_eq!(num_of_messages, message_number_to_nbytes.len());
                            assert_eq!(nbytes, total_nbytes_of_maildrop);
                            response_lines.clear();
                            response_lines.extend(format!("+OK {} {}\r\n", num_of_messages, total_nbytes_of_modified_maildrop).into_bytes());
                            println!("Done");
                        }
                    }
                    println!("relay the response: {}", status_line.trim());
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if command_name == "QUIT" {
                        println!("close POP3 stream");
                        upstream_stream.disconnect()?;
                        downstream_stream.disconnect()?;
                        println!("POP3 streams are closed"); // both streams were automatically closed by QUIT command
                        break;
                    }
                }

                // https://serde.rs/derive.html
                save_db_file(&serde_json::to_string(&database).unwrap())?;
            },
            Err(e) => return Err(anyhow!(e)),
        }
    }
}

#[allow(unused)]
fn test_pop3_upstream() -> Result<()> {
    let username = env::var("FUBACO_Nq2DYd4cFHGZ_U").unwrap();
    let password = env::var("FUBACO_AhCE3FNtfdJV_P").unwrap();
    let hostname = env::var("FUBACO_Km2TTTAEMErD_H").unwrap();
    let port = 995;

    println!("open upstream connection");
    let mut pop3_upstream = POP3Upstream::connect(&hostname, port)?;

    println!("wait for greeting response");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_GREETING, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue USER command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_USER, Some(username))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue PASS command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_PASS, Some(password))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue STAT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_STAT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue LIST command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_LIST_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_size_list: Vec<usize> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap()).map(|s| s.parse::<usize>().unwrap()).collect();
    println!("DEBUG: mail_size_list = {:?}\n", mail_size_list);

    println!("issue UIDL command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_UIDL_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_uid_list: Vec<String> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap().to_string()).collect();
    println!("DEBUG: mail_uid_list = {:?}\n", mail_uid_list);

    assert_eq!(mail_size_list.len(), mail_uid_list.len());
    let mail_list: Vec<(usize, String)> = mail_size_list.into_iter().zip(mail_uid_list.into_iter()).collect();
    println!("DEBUG: mail_list = {:?}\n", mail_list);

    println!("issue QUIT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_QUIT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("closing connection...");
    pop3_upstream.disconnect()?;
    println!("connection is successfully closed");

    Ok(())
}
