use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use kana::wide2ascii;
use lazy_static::lazy_static;
use mail_parser::{Message, MessageParser};
use my_dmarc_verifier::{DMARCResult, DMARCStatus};
use regex::Regex;
use rustls;
use scraper;
use tokio;
use unicode_normalization::UnicodeNormalization;
use webpki_roots;

mod my_crypto;
mod my_disconnect;
mod my_dkim_verifier;
mod my_dns_resolver;
mod my_dmarc_verifier;
mod my_message_parser;
mod my_pop3_bridge;
mod my_spf_verifier;
mod my_text_line_stream;
mod pop3_upstream;

use my_crypto::*;
use my_dkim_verifier::{DKIMResult, DKIMStatus};
use my_dns_resolver::MyDNSResolver;
use my_message_parser::MyMessageParser;
use my_spf_verifier::{SPFResult, SPFStatus};
use my_text_line_stream::MyTextLineStream;
use pop3_upstream::*;

//====================================================================
#[allow(unreachable_code)]
fn main() {
    println!("Hello, world!");

    assert_eq!(intersect_vec(&vec![1, 2, 3, 4, 5], &vec![2, 4, 6, 8]), vec![&2, &4]);

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

    if false {
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

fn intersect_vec<'a, 'b, S>(a: &'a [S], b: &'b [S]) -> Vec<&'a S>
    where S: PartialEq + Sized
{
    a.iter().filter(|aa| b.contains(aa)).collect()
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
    while pos <= buf.len() - "\r\n\tx\r\n".len() {
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
        pos += line_length_limit;
    }
    if pos < buf.len() { // odd position
        pos = buf.len() - "\r\n\tx\r\n".len(); // roll back
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
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
    static ref BLACKLIST_TLD_LIST: Vec<String> = vec![".cn", ".ru", ".hu", ".br", ".su", ".nz", ".in", ".cz", ".be", ".cl"].into_iter().map(|s| s.to_string()).collect();
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
    let header_from = message.from().map(|x| x.first().map(|addr| addr.address.clone().unwrap_or_default().to_string()).unwrap_or_default().to_lowercase()).unwrap_or_default();
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string().replace(&['<', '>'], "").to_lowercase(); // may be empty string
    println!("Evelop.from: \"{}\"", envelop_from);
    let mut is_spam = false;
    for tld in BLACKLIST_TLD_LIST.iter() {
        if header_from.ends_with(tld) {
            println!("blacklist-tld in from header address: \"{}\"", header_from);
            is_spam = true;
        }
    }
    for tld in BLACKLIST_TLD_LIST.iter() {
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
    let name = normalize_string(message.from().map(|x| x.first().unwrap().name.clone().unwrap_or_default()).unwrap_or_default());
    println!("From.name: \"{}\"", name);
    let address = normalize_string(message.from().map(|x| x.first().unwrap().address.clone().unwrap_or_default()).unwrap_or_default());
    println!("From.address: \"{}\"", address);
    let subject = normalize_string(message.subject().unwrap_or_default());
    println!("Subject: \"{}\"", subject);
    let destination = normalize_string(message.to().map(|x| x.first().map(|addr| addr.address.clone().unwrap()).unwrap_or_default()).unwrap_or_default()); // may be empty string
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
    let mut table = HashSet::<&'static str>::new();
    for elem in dom.select(&selector) {
        let url = elem.value().attr("href").unwrap().trim();
        lazy_static! {
            static ref REGEX_URL_WITH_NORMAL_HOST: Regex = Regex::new(r"^https?[:][/][/]([-_a-z0-9.]+)([/]\S*)?$").unwrap();
        }
        let host_in_href;
        if let Some(caps) = REGEX_URL_WITH_NORMAL_HOST.captures(url) {
            host_in_href = caps[1].to_string();
        } else {
            // for example, "with port number", "with percent-encoded", "with BASIC authentication info"
            println!("suspicious-href: \"{}\"", url);
            table.insert("suspicious-href"); // camouflaged hostname
            continue;
        }
        for tld in BLACKLIST_TLD_LIST.iter() {
            if host_in_href.ends_with(tld) {
                println!("blacklist-tld-in-href: \"{}\"", host_in_href);
                table.insert("blacklist-tld-in-href");
            }
        }
        let text = elem.inner_html();
        let text = text.trim();
        if let Some(caps) = REGEX_URL_WITH_NORMAL_HOST.captures(text) {
            let host_in_text = caps[1].to_string();
            if host_in_href != host_in_text {
                println!("camouflage-hyperlink: \"{}\" vs \"{}\"", host_in_href, host_in_text);
                table.insert("camouflaged-hyperlink");
            }
        }
    }
    if !table.is_empty() {
        let mut list = table.into_iter().map(|s| s.to_string()).collect::<Vec<String>>();
        list.sort();
        let text = list.join(" ");
        return Some(text);
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
    let from_address = message.from().map(|x| x.first().unwrap().address.clone().unwrap_or_default().to_ascii_lowercase()).unwrap_or_default();
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
            let my_spf_domain_list = spf_result.as_domains().clone();
            let mx_spf_domain_list = table.get("spf-target-domains").map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_spf_domain_list.len() > 0 && mx_spf_domain_list.len() > 0 && intersect_vec(&my_spf_domain_list, &mx_spf_domain_list).len() == 0 {
                println!("WARNING: my SPF checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_spf_domain_list, mx_spf_domain_list);
            }
            if mx_spf_status != SPFStatus::NONE {
                spf_result = SPFResult::new(mx_spf_status, mx_spf_domain_list); // overwrite
            }
        }
    }
    let mut dkim_result = my_dkim_verifier::dkim_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        let mx_label = ["dkim", "dkim-adsp"].into_iter().filter(|s| table.contains_key(*s)).take(1).next();
        if let Some(mx_label) = mx_label {
            let mx_dkim_status = table.get(mx_label).unwrap();
            let mx_dkim_status = mx_dkim_status.parse::<DKIMStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
            if &mx_dkim_status != dkim_result.as_status() {
                println!("WARNING: my DKIM checker says different result to \"Authentication-Results\" header: my={} vs header={}", dkim_result.as_status(), mx_dkim_status);
            }
            let my_dkim_domain_list = dkim_result.as_domains().clone();
            let mx_dkim_domain_list = table.get(&format!("{}-target-domains", mx_label)).map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_dkim_domain_list.len() > 0 && mx_dkim_domain_list.len() > 0 && intersect_vec(&my_dkim_domain_list, &mx_dkim_domain_list).len() == 0 {
                println!("WARNING: my DKIM checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_dkim_domain_list, mx_dkim_domain_list);
            }
            if mx_dkim_status != DKIMStatus::NONE {
                dkim_result = DKIMResult::new(mx_dkim_status, mx_dkim_domain_list); // overwrite
            }
        }
    }
    let mut dmarc_result;
    {
        let spf_domain_list: Vec<String> = if spf_result.as_status() == &SPFStatus::PASS {
            spf_result.as_domains().clone()
        } else {
            Vec::new()
        };
        let dkim_domain_list: Vec<String> = if dkim_result.as_status() == &DKIMStatus::PASS {
            dkim_result.as_domains().clone()
        } else {
            Vec::new()
        };
        dmarc_result = my_dmarc_verifier::dmarc_verify(&message, &spf_domain_list, &dkim_domain_list, &MY_DNS_RESOLVER);
        if let Some(table) = &table_of_authentication_results_header {
            if let Some(mx_dmarc_status) = table.get("dmarc") {
                let mx_dmarc_status = mx_dmarc_status.parse::<DMARCStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
                if &mx_dmarc_status != dmarc_result.as_status() {
                    println!("WARNING: my DMARC checker says different result to \"Authentication-Results\" header: my={} vs header={}", dmarc_result.as_status(), mx_dmarc_status);
                }
                if mx_dmarc_status != DMARCStatus::NONE {
                    dmarc_result = DMARCResult::new(mx_dmarc_status, dmarc_result.as_policy().clone()); // overwrite
                }
            }
        }
    }

    let auth_results = vec![
        format!("spf={}", spf_result.as_status()),
        format!("dkim={}", dkim_result.as_status()),
        format!("dmarc={}", dmarc_result.as_status()),
    ];

    let mut fubaco_headers = Vec::new();
    fubaco_headers.push(format!("X-Fubaco-Spam-Judgement: {}\r\n", spam_judgement.join(" ")));
    fubaco_headers.push(format!("X-Fubaco-Authentication: {}\r\n", auth_results.join(" ")));
    let nbytes = fubaco_headers.iter().fold(0, |acc, s| acc + s.len());
    fubaco_headers.push(make_fubaco_padding_header(*FUBACO_HEADER_TOTAL_SIZE - nbytes));
    Ok(fubaco_headers.join(""))
}

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

fn test_pop3_bridge() -> Result<()> {
    my_pop3_bridge::run_pop3_bridge(&MY_DNS_RESOLVER)
}

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
