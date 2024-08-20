use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
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

mod my_disconnect;
mod my_dns_resolver;
mod my_text_line_stream;
mod pop3_upstream;

use my_dns_resolver::MyDNSResolver;
use my_text_line_stream::MyTextLineStream;
use pop3_upstream::*;

//====================================================================
#[allow(unreachable_code)]
fn main() {
    println!("Hello, world!");

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

fn normalize_string<S: Into<String>>(s: S) -> String {
    // normalize string (Unicode NFKC, uppercase, no-whitespace, no-bullet)
    let mut unicode_normalized_str = String::new();
    unicode_normalized_str.extend(s.into().nfkc());
    wide2ascii(&unicode_normalized_str).to_uppercase().replace(" ", "").replace("　", "").replace("・", "")
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

lazy_static! {
    static ref REGEX_MAIL_ADDRESS: Regex = Regex::new(r"^([-._+=a-z0-9]+)[@]([0-9a-z]([-_0-9a-z]*[0-9a-z])?([.][0-9a-z]([-_0-9a-z]*[0-9a-z])?)+)$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_GENERAL: Regex = Regex::new(r"^([A-Z]+)(?: +(\S+)(?: +(\S+))?)? *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_USER: Regex = Regex::new(r"^USER +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND: Regex = Regex::new(r"^ *(\S+) +(\S+) *$").unwrap(); // "\r\n" is stripped
    static ref REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS: Regex = Regex::new(r"\b([1-9][0-9]*) octets\b").unwrap();
    static ref DATABASE_FILENAME: String = "./db.json".to_string();
    static ref FUBACO_HEADER_TOTAL_SIZE: usize = 512; // (78+2)*6+(30+2)
}

fn test_my_dns_resolver() -> Result<()> {
    let resolver = Arc::new(MyDNSResolver::new());
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
                let resolver = resolver.clone();
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

fn dns_query_spf(fqdn: &str) -> Result<Option<String>> {
    let query_result =
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = MyDNSResolver::new();
                resolver.lookup(fqdn.to_string(), "TXT".to_string()).await
            });
    let spf_records: Vec<String> = query_result?.into_iter().filter(|s| s.starts_with("v=spf1 ")).collect();
    if spf_records.len() == 0 {
        return Ok(None);
    }
    {
        let mut remark = "";
        for s in &spf_records {
            println!("spf_record: {}{}", s, remark);
            remark = " *IGNORED*";
        }
    }
    let spf_record = spf_records[0].clone(); // ignore multiple records (invalid DNS setting)
    Ok(Some(spf_record))
}

fn dns_query_simple(fqdn: &str, query_type: &str) -> Result<Vec<String>> { // Vec may be empty
    let query_result =
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = MyDNSResolver::new();
                resolver.lookup(fqdn.to_string(), query_type.to_string()).await
            });
    let records = query_result?; // may be empty
    for s in &records {
        println!("dns_{}_record: {} {}", query_type, fqdn, s);
    }
    Ok(records)
}

fn dns_query_mx(fqdn: &str) -> Result<Vec<String>> { // Vec may be empty
    let query_result =
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let resolver = MyDNSResolver::new();
                resolver.lookup(fqdn.to_string(), "MX".to_string()).await
            });
    let records = query_result?;
    for s in &records {
        println!("dns_MX_record: {} {}", fqdn, s);
    }
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SPFResult {
    NONE,
    PASS,
    FAIL,
    SOFTFAIL,
    PERMERROR,
    TEMPERROR,
}

impl std::fmt::Display for SPFResult {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::NONE      => "spf-none",
            Self::PASS      => "spf-pass",
            Self::FAIL      => "spf-fail",
            Self::SOFTFAIL  => "spf-softfail",
            Self::PERMERROR => "spf-permerror",
            Self::TEMPERROR => "spf-temperror",
        };
        write!(dest, "{}", s)
    }
}

fn spf_check_recursively(domain: &str, source_ip: &IpAddr, envelop_from: &str) -> SPFResult {
    let spf_record;
    match dns_query_spf(domain) {
        Ok(Some(s)) => spf_record = s,
        Ok(None) => return SPFResult::NONE,
        Err(_e) => return SPFResult::TEMPERROR,
    }

    lazy_static! {
        static ref REGEX_SPF_REDIRECT_DOMAIN: Regex = Regex::new(r"^redirect=([_a-z0-9]([-_a-z0-9]*[a-z0-9])?([.][a-z0-9]([-_a-z0-9]*[a-z0-9])?)*)$").unwrap();
        static ref REGEX_SPF_INCLUDE_DOMAIN: Regex = Regex::new(r"^include:([_a-z0-9]([-_a-z0-9]*[a-z0-9])?([.][a-z0-9]([-_a-z0-9]*[a-z0-9])?)*)$").unwrap();
    }
    let mut fields: Vec<String> = spf_record.split(" ").filter(|s| s.len() > 0).map(|s| s.to_string()).collect();
    fields.reverse();
    assert_eq!(fields.pop(), Some("v=spf1".to_string()));
    while let Some(field) = fields.pop() {
        if field == "~all" {
            return SPFResult::SOFTFAIL;
        }
        if field == "-all" {
            return SPFResult::FAIL;
        }
        if field == "+a" || field == "a" {
            let query_type;
            let prefix;
            match source_ip {
                IpAddr::V4(_target) => {
                    query_type = "A";
                    prefix = "+ip4:";
                },
                IpAddr::V6(_target) => {
                    query_type = "AAAA";
                    prefix = "+ip6:";
                }
            }
            match dns_query_simple(domain, query_type) {
                Ok(records) => {
                    for record in records {
                        fields.push(format!("{}{}", prefix, record));
                    }
                    continue;
                },
                Err(_e) => return SPFResult::TEMPERROR,
            }
        }
        if field == "+mx" || field == "mx" {
            let hosts = match dns_query_mx(domain) {
                Ok(v) => v,
                Err(_e) => return SPFResult::TEMPERROR,
            };
            let query_type;
            let prefix;
            match source_ip {
                IpAddr::V4(_target) => {
                    query_type = "A";
                    prefix = "+ip4:";
                },
                IpAddr::V6(_target) => {
                    query_type = "AAAA";
                    prefix = "+ip6:";
                }
            }
            for host in hosts {
                match dns_query_simple(&host, query_type) {
                    Ok(records) => {
                        for record in records {
                            fields.push(format!("{}{}", prefix, record));
                        }
                    },
                    Err(_e) => return SPFResult::TEMPERROR,
                }
            }
            continue;
        }
        if field == "+exists" || field == "exists" {
            let hosts = match dns_query_simple(domain, "A") {
                Ok(v) => v,
                Err(_e) => return SPFResult::TEMPERROR,
            };
            if hosts.len() > 0 {
                return SPFResult::PASS;
            }
        }
        if field == "+ptr" || field == "ptr" {
            let name;
            let query_type;
            let prefix;
            match source_ip {
                IpAddr::V4(addr) => {
                    let [u0, u1, u2, u3] = addr.octets();
                    name = format!("{}.{}.{}.{}.in-addr.arpa.", u3, u2, u1, u0);
                    query_type = "A";
                    prefix = "+ip4:";
                },
                IpAddr::V6(addr) => {
                    let s = format!("{:032x}", addr.to_bits());
                    let list: Vec<String> = s.chars().rev().map(|c| String::from(c)).collect();
                    name = format!("{}.ip6.arpa.", list.join("."));
                    query_type = "AAAA";
                    prefix = "+ip6:";
                }
            }
            let mut hosts = Vec::new();
            match dns_query_simple(&name, "PTR") {
                Ok(v) => hosts.extend(v.into_iter()),
                Err(_e) => return SPFResult::TEMPERROR,
            }
            if hosts.len() != 1 {
                println!("can not get PTR record of: {} {}", name, hosts.len());
                return SPFResult::PERMERROR; // invalid DNS info
            }
            let host = hosts.pop().unwrap();
            let postfix = if host.ends_with(".") { "." } else { "" };
            let target = format!("{}{}", domain, postfix);
            if host.ends_with(&target) {
                let mut list = Vec::new();
                match dns_query_simple(&host, query_type) {
                    Ok(v) => list.extend(v.into_iter()),
                    Err(_e) => return SPFResult::TEMPERROR,
                }
                for ip in list {
                    fields.push(format!("{}{}", prefix, ip));
                }
                continue;
            }
        }

        trait MyIpAddr where Self: Eq + FromStr {
            const BITS: u32;
            const UNSPECIFIED: Self;
            fn to_bits(self) -> u128;
        }
        impl MyIpAddr for Ipv4Addr {
            const BITS: u32 = Ipv4Addr::BITS;
            const UNSPECIFIED: Self = Ipv4Addr::UNSPECIFIED;
            fn to_bits(self) -> u128 {
                Ipv4Addr::to_bits(self) as u128
            }
        }
        impl MyIpAddr for Ipv6Addr {
            const BITS: u32 = Ipv6Addr::BITS;
            const UNSPECIFIED: Self = Ipv6Addr::UNSPECIFIED;
            fn to_bits(self) -> u128 {
                Ipv6Addr::to_bits(self)
            }
        }
        fn process_ip_field<I: MyIpAddr>(prefix: &str, regex: &Regex, source_ip: &IpAddr, field: &str) -> Option<SPFResult> {
            let addr;
            let bitmask_len;
            if let Some(caps) = regex.captures(field) {
                let arg1 = caps[1].to_string();
                addr = arg1.parse::<I>().unwrap_or(I::UNSPECIFIED);
                let arg3 = caps.get(3).map_or(I::BITS.to_string(), |s| s.as_str().to_string());
                bitmask_len = u32::from_str_radix(&arg3, 10).unwrap_or(0);
            } else {
                println!("{} syntax error: \"{}\"", prefix, field);
                return Some(SPFResult::PERMERROR); // syntax error (abort immediately)
            }

            if addr == I::UNSPECIFIED {
                println!("{} address parse error: \"{}\"", prefix, field);
                return Some(SPFResult::PERMERROR);
            }
            if bitmask_len == 0 || bitmask_len > I::BITS {
                println!("{} netmask parse error: \"{}\"", prefix, field);
                return Some(SPFResult::PERMERROR);
            }
            let bits;
            let bit_expression;
            match source_ip {
                IpAddr::V4(target) => {
                    bits = Ipv4Addr::BITS;
                    bit_expression = target.to_bits() as u128;
                },
                IpAddr::V6(target) => {
                    bits = Ipv6Addr::BITS;
                    bit_expression = target.to_bits();
                },
            }
            if bits != I::BITS {
                return None;
            }
            let bitmask = (!0u128) << (I::BITS - bitmask_len);
            let left = bit_expression;
            let right = addr.to_bits() as u128; // may be cast
            if left & bitmask == right & bitmask {
                return Some(SPFResult::PASS);
            }
            None
        }

        if field.starts_with("+ip4:") || field.starts_with("ip4:") {
            lazy_static! {
                static ref REGEX_SPF_IPV4: Regex = Regex::new(r"^[+]?ip4:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)([/]([1-9][0-9]*))?$").unwrap();
            }
            if let Some(result) = process_ip_field::<Ipv4Addr>("ip4", &REGEX_SPF_IPV4, source_ip, &field) {
                return result;
            }
        }
        if field.starts_with("+ip6:") || field.starts_with("ip6:") {
            lazy_static! {
                static ref REGEX_SPF_IPV6: Regex = Regex::new(r"^[+]?ip6:([:0-9a-f]+)([/]([1-9][0-9]*))?$").unwrap();
            }
            if let Some(result) = process_ip_field::<Ipv6Addr>("ip6", &REGEX_SPF_IPV6, source_ip, &field) {
                return result;
            }
        }
        if let Some(caps) = REGEX_SPF_REDIRECT_DOMAIN.captures(&field) {
            let domain = caps[1].to_string();
            let nested_spf;
            match dns_query_spf(&domain) {
                Ok(Some(s)) => nested_spf = s,
                Ok(None) => return SPFResult::PERMERROR, // invalid field (abort immediately)
                Err(_e) => return SPFResult::TEMPERROR, // internal error
            }
            let mut nested_fields: Vec<String> = nested_spf.split(" ").filter(|s| s.len() > 0).map(|s| s.to_string()).collect();
            nested_fields.reverse();
            fields.extend(nested_fields.into_iter());
            continue;
        }
        if let Some(caps) = REGEX_SPF_INCLUDE_DOMAIN.captures(&field) {
            let domain = caps[1].to_string();
            let result = spf_check_recursively(&domain, source_ip, envelop_from);
            match result {
                r @ SPFResult::PASS      => return r,
                r @ SPFResult::PERMERROR => return r,
                r @ SPFResult::TEMPERROR => return r,
                SPFResult::NONE      => (), // ignored
                SPFResult::FAIL      => (), // ignored
                SPFResult::SOFTFAIL  => (), // ignored
            }
        }
    }
    SPFResult::NONE
}

fn spam_checker_spf(message: &Message) -> Option<String> {
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string(); // may be empty string
    let envelop_from = envelop_from.replace("<", "").replace(">", "").to_lowercase().trim().to_string();
    println!("Evelop.from: \"{}\"", envelop_from);
    if envelop_from.len() == 0 {
        return None;
    }
    let mut source_ip = None;
    {
        for value in message.header_values("Received") {
            if let mail_parser::HeaderValue::Received(received) = value {
                if let Some(mail_parser::Host::Name(s)) = received.by() {
                    if s == "niftygreeting" || s.ends_with(".nifty.com") || s.ends_with(".mailbox.org") || s.ends_with(".gandi.net") || s.ends_with(".mxrouting.net") || s.ends_with(".google.com") {
                        println!("DEBUG: received.from(): \"{:?}\"", received.from());
                        if let Some(mail_parser::Host::Name(ss)) = received.from() {
                            lazy_static! {
                                static ref REGEX_NIFTY_MAILSERVER: Regex = Regex::new(r"^concspmx-\d+$").unwrap();
                            }
                            if s.ends_with(".nifty.com") && REGEX_NIFTY_MAILSERVER.is_match(ss) {
                                println!("skip \"Receivec\" header (internal relay in nifty)");
                                continue; // skip (internal relay in nifty)
                            }
                        }
                        match received.from_ip() {
                            Some(IpAddr::V4(addr)) => {
                                source_ip = Some(IpAddr::V4(addr));
                                break;
                            }
                            Some(IpAddr::V6(addr)) => {
                                source_ip = Some(IpAddr::V6(addr));
                                break;
                            }
                            _ => {
                                // empty
                            }
                        }
                    }
                }
            }
        }
    };
    if source_ip.is_none() {
        return None;
    }
    let source_ip = source_ip.unwrap();
    println!("source_ip: {}", source_ip);

    let domain;
    if let Some(caps) = REGEX_MAIL_ADDRESS.captures(&envelop_from) {
        domain = caps[2].to_string();
    } else {
        return Some("invalid-envelop-from".to_string());
    }

    return Some(spf_check_recursively(&domain, &source_ip, &envelop_from).to_string());
}

fn spam_checker_suspicious_envelop_from(message: &Message) -> Option<String> {
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string(); // may be empty string
    let envelop_from = envelop_from.replace("<", "").replace(">", "").to_lowercase().trim().to_string();
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
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string().replace("<", "").replace(">", "").to_lowercase(); // may be empty string
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
    let expected_from_address_pattern = (|| {
        if name.contains("AMAZON") || subject.contains("AMAZON") {
            return r"[.@]amazon(\.co\.jp|\.com)$";
        }
        if name.contains("JCB") {
            return r"[.@]jcb\.co\.jp$";
        }
        if name.contains("三井住友銀行") || name.contains("三井住友カード") || name.contains("SMBC") || name.contains("VPASS") || name.contains("SUMITOMOMITSUI") || subject.contains("三井住友") {
            return r"[.@](vpass\.ne\.jp|smbc\.co\.jp)$";
        }
        if name.contains("ヤマト運輸") {
            return r"[.@]kuronekoyamato\.co\.jp$";
        }
        if name.contains("VIEWCARD") || name.contains("ビューカード") || name.contains("VIEW'SNET") || subject.contains("VIEW'SNET") {
            return r"[.@]viewsnet\.jp$";
        }
        if name.contains("東京電力") || name.contains("TEPCO") || subject.contains("東京電力") {
            return r"[.@](tepco\.co\.jp|hikkoshi-line\.jp)$";
        }
        if name.contains("三菱UFJ") || name.contains("MUFG") {
            return r"[.@]mufg\.jp$";
        }
        if name.contains("えきねっと") {
            return r"[.@]eki-net\.com$";
        }
        if name.contains("DOCOMO") || name.contains("ドコモ") || subject.contains("DOCOMO") || subject.contains("ドコモ") {
            return r"[.@](docomo\.ne\.jp|mydocomo\.com)$";
        }
        if name.contains("PAYPAL") {
            return r"[.@]paypal\.com$";
        }
        if name.contains("APPLE") {
            return r"[.@]apple\.com$";
        }
        r"." // always match
    })();
    let suspicious_words_in_name = [
        "イオンペイ", "イオンカード", "イオン銀行", "イオンフィナンシャルサービス", "AEON",
        "AMERICANEXPRESS", "アメリカンエキスプレス",
        "セゾンカード",
        "永久不滅",
        "ETC利用照会サービス", "マイレージサービス",
        "エポスカード", "エポスNET",
        "マスターカード",
        "JCON", "J-COM",
        "楽天カード",
        "VIAGRA", "CIALIS",
    ];
    let suspicious_words_in_subject = [
        "VIAGRA", "CIALIS",
    ];

    let is_spam = (|| {
        if !Regex::new(&format!("(?i){}", expected_from_address_pattern)).unwrap().is_match(&address) {
            return true;
        }
        if suspicious_words_in_name.iter().any(|s| name.contains(s)) {
            return true;
        }
        if suspicious_words_in_subject.iter().any(|s| subject.contains(s)) {
            return true;
        }
        if address == destination { // header.from is camoflaged with destination address
            return true;
        }
        false
    })();
    if is_spam {
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

fn make_fubaco_headers(message_u8: &[u8]) -> Result<String> {
    let message;
    if let Some(v) = MessageParser::default().parse(message_u8) {
        message = v;
    } else {
        return Err(anyhow!("can not parse the message"));
    }
    let mut spam_judgement: Vec<String> = [
        spam_checker_spf,
        spam_checker_suspicious_envelop_from,
        spam_checker_blacklist_tld,
        spam_checker_suspicious_from,
        spam_checker_suspicious_hyperlink,
        spam_checker_hidden_text_in_html,
        spam_checker_fully_html_encoded_text,
    ].iter().filter_map(|f| f(&message)).collect();
    if spam_judgement.len() == 0 {
        spam_judgement.push("none".to_string());
    }

    let mut fubaco_headers = Vec::new();
    fubaco_headers.push(format!("X-Fubaco-Spam-Judgement: {}\r\n", spam_judgement.join(" ")));
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
