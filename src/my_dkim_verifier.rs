use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::SystemTime;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use lazy_static::lazy_static;
use mail_parser::Message;
use regex::Regex;

use crate::my_crypto::*;
use crate::my_dns_resolver::MyDNSResolver;
use crate::my_message_parser::MyMessageParser;

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DKIMResult {
    NONE,
    PASS,
    FAIL,
    PERMERROR,
    TEMPERROR,
}

impl std::fmt::Display for DKIMResult {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::NONE      => "dkim-none",
            Self::PASS      => "dkim-pass",
            Self::FAIL      => "dkim-fail",
            Self::PERMERROR => "dkim-permerror",
            Self::TEMPERROR => "dkim-temperror",
        };
        write!(dest, "{}", s)
    }
}

//====================================================================
fn get_dkim_signature_header(message: &Message) -> Option<String> {
    let header_value = match message.header("DKIM-Signature") {
        Some(mail_parser::HeaderValue::Text(s)) => s, // there is no CRLF at the end
        _ => return None,
    };
    println!("DKIM-Signature: {}", header_value);
    Some(header_value.to_string())
}

fn parse_dkim_signature(header_value: &str) -> Result<HashMap<String, String>> {
    lazy_static! {
        static ref REGEX_LINE_BREAK: Regex = Regex::new(r"\r\n[ \t]+").unwrap();
        static ref REGEX_SEQUENCE_OF_WHITESPACE: Regex = Regex::new(r"[ \t]+").unwrap();
        static ref REGEX_CRLF_AT_THE_END: Regex = Regex::new(r"\r\n$").unwrap();
    }
    let mut table = HashMap::<String, String>::new();
    let s = REGEX_LINE_BREAK.replace_all(header_value, "");
    let s = REGEX_SEQUENCE_OF_WHITESPACE.replace_all(&s, "");
    let s = REGEX_CRLF_AT_THE_END.replace(&s, ""); // remove CRLF (may be not exists)
    assert!(!s.contains("\r"));
    assert!(!s.contains("\n"));
    let fields = s.split(";").filter(|s| s.len() > 0);
    for field in fields {
        if let Some((tag, value)) = field.split_once("=") {
            table.insert(tag.to_owned(), value.to_owned());
        } else {
            return Err(anyhow!("DKIM_Signature header value syntax error: \"{}\"", field));
        }
    }
    let mandatory_field_names = [
        "v",
        "a",
        "b",
        "bh",
        "d",
        "h",
        "s",
    ];
    let lack_of_mandatory_field_names = mandatory_field_names.into_iter().filter(|s| !table.contains_key(*s)).collect::<Vec<&str>>();
    if lack_of_mandatory_field_names.len() > 0 {
        return Err(anyhow!("DKIM: lack of mandatory fields: {:?}", lack_of_mandatory_field_names));
    }
    let complement_list = [
        ("c", "simple/simple".to_string()),
        ("i", format!("@{}", table.get("d").unwrap())),
        ("l", u32::MAX.to_string()), // "unlimited"
        ("q", "dns/txt".to_string()),
        ("t", 0.to_string()), // "UNIX EPOCH"
        ("x", "1000000000000".to_string()), // "unlimited" (=10^12)
        ("z", "dummy".to_string()), // dummy
    ];
    for (tag, value) in complement_list {
        if !table.contains_key(tag) {
            table.insert(tag.to_string(), value);
        }
    }
    Ok(table)
}

fn dkim_canonicalization_for_body(mode: &str, body_u8: &[u8]) -> Result<String> {
    let is_simple = match mode {
        "simple/simple" | "relaxed/simple" | "simple" | "relaxed" => true,
        "simple/relaxed" | "relaxed/relaxed" => false,
        _ => return Err(anyhow!("DKIM_Signature canonicalization mode is invalid: {}", mode)),
    };
    let body_text = String::from_utf8_lossy(body_u8);
    {
        lazy_static! {
            static ref REGEX_ALONE_LF: Regex = Regex::new(r"\r[^\n]").unwrap();
            static ref REGEX_ALONE_CR: Regex = Regex::new(r"[^\r]\n").unwrap();
        }
        if REGEX_ALONE_LF.is_match(&body_text) {
            println!("WARNING: alone LF is detected");
        }
        if REGEX_ALONE_CR.is_match(&body_text) {
            println!("WARNING: alone CR is detected");
        }
    }
    let mut text = if is_simple {
        body_text.to_string()
    } else {
        lazy_static! {
            static ref REGEX_WHITESPACE_AT_THE_END_OF_LINE: Regex = Regex::new(r"[ \t]+\r\n").unwrap();
            static ref REGEX_SEQUENCE_OF_WHITESPACE: Regex = Regex::new(r"[ \t]+").unwrap();
        }
        let text = REGEX_WHITESPACE_AT_THE_END_OF_LINE.replace_all(&body_text, "\r\n");
        let text = REGEX_SEQUENCE_OF_WHITESPACE.replace_all(&text, " ");
        text.to_string()
    };
    if text.len() > 0 && !text.ends_with("\r\n") {
        text.push_str("\r\n");
    }

    // remove empty lines at the end of body
    while text.ends_with("\r\n\r\n") {
        text.truncate(text.len() - "\r\n".len());
    }
    if text.as_str() == "\r\n" {
        text.truncate(0);
    }
    if is_simple && text.len() == 0 {
        return Ok("\r\n".to_string()); // see "sectionn 3.4.3" in RFC6376
    }
    Ok(text)
}

fn dkim_canonicalization_for_headers(mode: &str, headers: &[String]) -> Result<String> {
    let is_simple = match mode {
        "simple/simple" | "simple/relaxed" | "simple" => true,
        "relaxed/simple" | "relaxed/relaxed" | "relaxed" => false,
        _ => return Err(anyhow!("DKIM_Signature canonicalization mode is invalid: {}", mode)),
    };
    let mut lines = Vec::new();
    for header in headers {
        let (tag, text) = header.split_once(":").unwrap();
        if is_simple {
            lines.push(header.to_owned());
        } else {
            // see "section 3.4.2" in RFC6376
            let tag = tag.to_ascii_lowercase();
            let tag = tag.trim();
            lazy_static! {
                static ref REGEX_CONTINUATION_LINE_PATTERN: Regex = Regex::new(r"\r\n([ \t])").unwrap();
                static ref REGEX_SEQUENCE_OF_WHITESPACE: Regex = Regex::new(r"[ \t]+").unwrap();
                static ref REGEX_WHITESPACE_AT_THE_END_OF_VALUE: Regex = Regex::new(r"[ \t]*\r\n$").unwrap();
                static ref REGEX_WHITESPACE_AT_THE_HEAD_OF_VALUE: Regex = Regex::new(r"^[ \t]+").unwrap();
            }
            let text = REGEX_CONTINUATION_LINE_PATTERN.replace_all(&text, "$1");
            assert!(!text[..(text.len() - "\r\n".len())].contains("\r\n"));
            let text = REGEX_SEQUENCE_OF_WHITESPACE.replace_all(&text, " ");
            let text = REGEX_WHITESPACE_AT_THE_END_OF_VALUE.replace_all(&text, ""); // remove CRLF at the end of value
            let text = REGEX_WHITESPACE_AT_THE_HEAD_OF_VALUE.replace(&text, "");
            lines.push(format!("{}:{}\r\n", tag, text));
        }
    }
    let text = lines.join("");
    Ok(text)
}

//====================================================================
pub fn dkim_verify(message: &Message, resolver: &MyDNSResolver) -> DKIMResult {
    let dkim_signature_header_value = match get_dkim_signature_header(message) {
        Some(s) => s,
        None => return DKIMResult::NONE,
    };
    let dkim_signature_fields = match parse_dkim_signature(&dkim_signature_header_value) {
        Ok(v) => v,
        Err(e) => {
            println!("DKIM_Signature header value parse error: {}", e);
            return DKIMResult::PERMERROR;
        }
    };

    // check "a" tag of "DKIM-Signature" header
    let (dkim_signature_pubkey_algo, dkim_signature_hash_algo) = match dkim_signature_fields["a"].split_once("-") {
        Some((x, y)) => (x.to_owned(), y.to_owned()),
        None => {
            println!("DKIM-Signature has invalid \"a\" field: \"{}\"", dkim_signature_fields["a"]);
            return DKIMResult::PERMERROR;
        }
    };
    let dkim_signature_pubkey_algo = match MyAsymmetricAlgo::try_from(dkim_signature_pubkey_algo.as_str()) {
        Ok(v) => v,
        Err(e) => {
            println!("DKIM-Signature signature algorithm is invalid: {}", e);
            return DKIMResult::PERMERROR;
        },
    };
    let dkim_signature_hash_algo = match MyHashAlgo::try_from(dkim_signature_hash_algo.as_str()) {
        Ok(v) => v,
        Err(e) => {
            println!("DKIM-Signature hash algorithm is invalid: {}", e);
            return DKIMResult::PERMERROR;
        },
    };
    match (dkim_signature_pubkey_algo, dkim_signature_hash_algo) {
        (MyAsymmetricAlgo::Rsa, MyHashAlgo::Sha1) |
        (MyAsymmetricAlgo::Rsa, MyHashAlgo::Sha256) |
        (MyAsymmetricAlgo::Ed25519, MyHashAlgo::Sha256) => (), // OK
        _ => {
            println!("DKIM-Signature algorithm is invalid combination: {}", dkim_signature_fields["a"]);
            return DKIMResult::PERMERROR;
        },
    }

    // check "i" tag of "DKIM-Signature" header against "d" tag
    {
        let (_localpart, domain) = dkim_signature_fields["i"].split_once("@").unwrap_or(("", ""));
        if domain == dkim_signature_fields["d"] {
            // OK (same domain)
        } else if domain.ends_with(&format!(".{}", dkim_signature_fields["d"])) {
            // OK (subdomain)
        } else {
            println!("DKIM_Signature header \"i\" is invalid: \"{}\" vs \"{}\"", dkim_signature_fields["i"], dkim_signature_fields["d"]);
            return DKIMResult::PERMERROR;
        }
    }

    let timestamp_at_gateway;
    {
        let now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_secs();
        if let Some(received) = message.get_received_header_of_gateway() {
            if let Some(datetime) = received.date() {
                let seconds = datetime.to_timestamp();
                assert!(seconds >= 0);
                timestamp_at_gateway = seconds as u64;
            } else {
                println!("WARNING: \"Received\" header has no timestamp: {:?}", received);
                timestamp_at_gateway = now;
            }
        } else {
            timestamp_at_gateway = now;
        }
    }

    // check signature timestamp
    {
        let timestamp = match u64::from_str_radix(&dkim_signature_fields["t"], 10) {
            Ok(v) => v,
            Err(_e) => {
                println!("DKIM_Signature field \"t\" has invalid value: \"{}\"", &dkim_signature_fields["t"]);
                return DKIMResult::PERMERROR;
            }
        };
        if timestamp_at_gateway < timestamp {
            println!("DKIM_Signature is in the future");
            return DKIMResult::FAIL;
        }
    }

    // check expiration date
    {
        let limit = match u64::from_str_radix(&dkim_signature_fields["x"], 10) {
            Ok(v) => v,
            Err(_e) => {
                println!("DKIM_Signature field \"x\" has invalid value: \"{}\"", &dkim_signature_fields["x"]);
                return DKIMResult::PERMERROR;
            }
        };
        if timestamp_at_gateway > limit {
            println!("DKIM_Signature is expired");
            return DKIMResult::FAIL;
        }
    }

    // body canonicalization and limitation (limitation is effective after canonicalization)
    let pos_of_top_of_body = message.raw_message().windows(4).enumerate()
        .skip_while(|(_, arr)| !(arr[0] == b'\r' && arr[1] == b'\n' && arr[2] == b'\r' && arr[3] == b'\n'))
        .map(|(i, _)| i + 4)
        .next()
        .unwrap_or(message.raw_message().len());
    let body_u8_limited = {
        let body_u8_raw = if pos_of_top_of_body >= message.raw_message().len() {
            b""
        } else {
            &message.raw_message()[pos_of_top_of_body..]
        };
        let mut body_u8_canonicalized = match dkim_canonicalization_for_body(&dkim_signature_fields["c"], body_u8_raw) {
            Ok(s) => s,
            Err(e) => {
                println!("DKIM canonicalizatino error: {}", e);
                return DKIMResult::PERMERROR;
            },
        };
        let limit = match usize::from_str_radix(&dkim_signature_fields["l"], 10) {
            Ok(v) => v,
            Err(_e) => {
                println!("DKIM_Signature field \"l\" has invalid value: \"{}\"", dkim_signature_fields["l"]);
                return DKIMResult::PERMERROR;
            },
        };
        body_u8_canonicalized.truncate(limit);
        body_u8_canonicalized.into_bytes()
    };

    // header select
    let mut selected_headers = Vec::<String>::new();
    let dkim_signature_header_raw;
    {
        let mut header_table = HashMap::<String, Vec<String>>::new();
        {
            // parse all headers
            fn update_table(table: &mut HashMap<String, Vec<String>>, buf: &[String]) {
                assert_ne!(buf.len(), 0); // >= 2
                assert_ne!(buf.len(), 1); // >= 2
                let tag = &buf[0];
                let mut text = buf[1..].join("\r\n");
                text.push_str("\r\n");
                if let Some(v) = table.get_mut(tag) {
                    v.push(text);
                } else {
                    let v = vec![text];
                    table.insert(tag.clone(), v);
                }
            }

            let header_u8 = &message.raw_message()[..(pos_of_top_of_body - b"\r\n".len())];
            let header_text = String::from_utf8_lossy(header_u8);
            let lines = header_text.split("\r\n").filter(|s| s.len() > 0); // CRLF is removed
            let mut buf = Vec::<String>::new();
            for line in lines {
                if line.starts_with(" ") || line.starts_with("\t") {
                    assert_ne!(buf.len(), 0); // >= 2
                    assert_ne!(buf.len(), 1); // >= 2
                    buf.push(line.to_owned());
                } else {
                    if buf.len() > 0 {
                        update_table(&mut header_table, &buf);
                        buf.clear();
                    }
                    if let Some((tag, _value)) = line.split_once(":") {
                        buf.push(tag.trim().to_ascii_lowercase()); // case-insensitive
                        buf.push(line.to_owned());
                    } else {
                        println!("DIKM all headers parse error: {}", line);
                        return DKIMResult::PERMERROR;
                    }
                }
            }
            if buf.len() > 0 {
                update_table(&mut header_table, &buf);
                buf.clear();
            }
        }
        dkim_signature_header_raw = header_table.get(&"DKIM-Signature".to_ascii_lowercase()).unwrap()[0].clone(); // must exist
        lazy_static! {
            static ref REGEX_SEQUENCE_OF_WHITESPACE: Regex = Regex::new(r"[ \t]+").unwrap();
        }
        let stripped_selectors = REGEX_SEQUENCE_OF_WHITESPACE.replace_all(&dkim_signature_fields["h"], "");
        let tags = stripped_selectors.split(":").map(str::to_ascii_lowercase); // case-insensitive
        for tag in tags {
            if header_table.contains_key(&tag) {
                if let Some(header_text) = header_table.get_mut(&tag).unwrap().pop() { // "Last-In-First-Out" order (see "section 5.4.2" in RFC6376)
                    selected_headers.push(header_text);
                } else {
                    // ignore nonexistent header fields (see "section 3.5" in RFC6376)
                }
            } else {
                // ignore nonexistent header fields (see "section 3.5" in RFC6376)
            }
        }
    }
    let selected_headers = selected_headers; // frozen

    // check hash value of body
    {
        let body_hash_value = my_calc_hash(dkim_signature_hash_algo, &body_u8_limited);
        let base64_value = BASE64_STANDARD.encode(&body_hash_value);
        let bh_value = &dkim_signature_fields["bh"];
        if base64_value == *bh_value {
            println!("DKIM-Signature Body Hash is OK");
        } else {
            println!("DKIM-Signature Body Hash is not matched: {} vs {}", base64_value, bh_value);
            if bh_value.starts_with("CPi+57OhV6n9mvBpGp+jzS4TnhyGa+oGe2/1BpLR") { // mail-sample.AMAZON_3.eml
                let f = File::create("debug_out.txt").unwrap();
                let mut writer = BufWriter::new(f);
                writer.write_all(&body_u8_limited).unwrap();
                writer.flush().unwrap();
            }
            if bh_value.starts_with("YXvW1zu96ay1cElgm0eiqEcP8KSqSfWh1nCeAl4") { // mail-sample.dkim-ok_4.eml
                let f = File::create("debug_out_2.txt").unwrap();
                let mut writer = BufWriter::new(f);
                writer.write_all(&body_u8_limited).unwrap();
                writer.flush().unwrap();
            }
            return DKIMResult::FAIL;
        }
    }

    // calculate header hash value (see "section 3.7" in RFC6376)
    let header_hash_value;
    {
        let mut headers = selected_headers.to_vec();
        lazy_static! {
            static ref REGEX_B_FIELD: Regex = Regex::new(r"\bb=([^;]|\r\n)+").unwrap(); // include whitespace and CRLF
        }
        let mut dkim_signature_header_modified = REGEX_B_FIELD.replace(&dkim_signature_header_raw, "b=").to_string();
        if !dkim_signature_header_modified.ends_with("\r\n") {
            dkim_signature_header_modified.push_str("\r\n");
        }
        headers.push(dkim_signature_header_modified);
        let mut header_canonicalized = match dkim_canonicalization_for_headers(&dkim_signature_fields["c"], &headers) {
            Ok(s) => s,
            Err(e) => {
                println!("DKIM canonicalization for headers is failed: {}", e);
                return DKIMResult::PERMERROR;
            },
        };
        assert!(header_canonicalized.ends_with("\r\n"));
        header_canonicalized.truncate(header_canonicalized.len() - "\r\n".len()); // remove CRLF at the end of DKIM-Signature header
        println!("----------\n{}\n----------", header_canonicalized);
        let header_u8 = header_canonicalized.as_bytes();
        header_hash_value = my_calc_hash(dkim_signature_hash_algo, header_u8);
        println!("DEBUG: header_hash: {}", BASE64_STANDARD.encode(&header_hash_value));
    }

    // refer DNS record
    let mut dkim_dns_fields = HashMap::<String, String>::new();
    {
        let query_key = format!("{}._domainkey.{}", dkim_signature_fields["s"], dkim_signature_fields["d"]); // see "section 3.6.2.1" in RFC6376
        let query_responses = match resolver.query_simple(&query_key, "TXT") {
            Ok(v) => v,
            Err(e) => {
                println!("DNS query falied: {}", e);
                return DKIMResult::TEMPERROR;
            },
        };
        let text_raw = match query_responses.into_iter().next() { // use first record even if there are multiple records (see section "3.6.2.2" in RFC6376)
            Some(s) => s,
            None => {
                println!("DKIM record is not found in DNS: {}", query_key);
                return DKIMResult::PERMERROR;
            },
        };
        let fields = text_raw.split(";").filter(|s| s.len() > 0).map(str::trim);
        for field in fields {
            let (tag, value) = field.split_once("=").unwrap_or(("", ""));
            let tag = tag.trim();
            let value = value.trim();
            if tag == "" {
                println!("DKIM record in DNS is syntax error: {}", text_raw);
                return DKIMResult::PERMERROR;
            }
            assert!(dkim_dns_fields.get(tag).is_none());
            dkim_dns_fields.insert(tag.to_owned(), value.to_owned());
        }
    }
    let dkim_dns_fields = dkim_dns_fields; // frozen
    {
        // validation (see "section 3.6.1" in RFC6376)
        if let Some(v) = dkim_dns_fields.get("v") {
            if v == "DKIM1" {
                // OK
            } else {
                println!("DKIM record in DNS has invalid \"v\" field: \"{}\"", v);
                return DKIMResult::PERMERROR;
            }
        } else {
            // OK (not specified)
        }
        if let Some(v) = dkim_dns_fields.get("h") {
            if v.split(":").any(|s| s == dkim_signature_hash_algo.to_string()) {
                // OK
            } else {
                println!("DKIM record in DNS specifies other hash algorithm: {} vs {}", v, dkim_signature_hash_algo);
                return DKIMResult::PERMERROR;
            }
        } else {
            // OK (not specified)
        }
        if let Some(v) = dkim_dns_fields.get("k") {
            if *v == dkim_signature_pubkey_algo.to_string() {
                // OK
            } else {
                println!("DKIM record in DNS has different pubkey algorithm: {} vs {}", v, dkim_signature_pubkey_algo);
                return DKIMResult::PERMERROR;
            }
        } else {
            // OK (not specified)
        }
        if let Some(v) = dkim_dns_fields.get("p") {
            if v.len() > 0 {
                // OK
            }  else {
                println!("DKIM record in DNS has empty \"p\" field (means \"revoked\")"); // see "section 3.6.1" in RFC6376
                return DKIMResult::PERMERROR;
            }
        } else {
            println!("DKIM record in DNS has no \"p\" field");
            return DKIMResult::PERMERROR;
        }
        if let Some(v) = dkim_dns_fields.get("s") {
            if v.split(":").any(|s| s == "email" || s == "*") {
                // OK
            } else {
                println!("DKIM record in DNS has invalid \"s\" field: \"{}\"", v);
                return DKIMResult::PERMERROR;
            }
        } else {
            // OK (not specified)
        }
        if let Some(v) = dkim_dns_fields.get("t") {
            if v.split(":").any(|s| s == "y") {
                // ignore (always enforce to verify signature)
            }
            if v.split(":").any(|s| s == "s") {
                let (_localpart, domain) = dkim_signature_fields["i"].split_once("@").unwrap_or(("", ""));
                if domain == dkim_signature_fields["d"] {
                    // OK
                } else {
                    println!("DKIM record in DNS specifies not to allow subdomain as DKIM-Signature \"i\" field: {} vs {}", domain, dkim_signature_fields["d"]);
                    return DKIMResult::PERMERROR;
                }
            } else {
                // OK (not specified)
            }
        }

        // NOTE: ignore "g" field (because it is obsoleted) (see "section C.1" in RFC6376)
    }

    // verify signature
    {
        let pubkey_u8 = match BASE64_STANDARD.decode(&dkim_dns_fields["p"]) {
            Ok(v) => v,
            Err(e) => {
                println!("DKIM record in DNS has invalid \"p\" field (can not decode as Base64): \"{}\" for \"{}\"", e, dkim_dns_fields["p"]);
                return DKIMResult::PERMERROR;
            },
        };
        let expected_pubkey_bit_length = match 8 * pubkey_u8.len() {
            256..512 => 256,
            512..1024 => 512,
            1024..2048 => 1024,
            2048..4096 => 2048,
            4096..5000 => 4096,
            _ => {
                println!("unexpected pubkey length: {}", pubkey_u8.len());
                return DKIMResult::PERMERROR;
            },
        };
        let signature_u8 = match BASE64_STANDARD.decode(&dkim_signature_fields["b"]) {
            Ok(v) => v,
            Err(e) => {
                println!("DKIM-Signature has invalid \"b\" field (can not decode as Base64): \"{}\" for \"{}\"", e, dkim_signature_fields["b"]);
                return DKIMResult::PERMERROR;
            },
        };
        if signature_u8.len() != expected_pubkey_bit_length / 8 {
            println!("DEBUG: invalid signature length: {}", signature_u8.len());
            return DKIMResult::PERMERROR;
        }
        match my_verify_sign(dkim_signature_pubkey_algo, pubkey_u8.as_slice(), dkim_signature_hash_algo, header_hash_value.as_slice(), signature_u8.as_slice()) {
            Ok(true) => {
                println!("DKIM signature is OK");
            },
            Ok(false) => {
                println!("DKIM signature is NG");
                return DKIMResult::FAIL;
            },
            Err(e) => {
                println!("DKIM signature verification is failed: {}", e);
                return DKIMResult::PERMERROR;
            },
        };
    }

    DKIMResult::PASS
}
