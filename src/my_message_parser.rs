use std::collections::HashMap;

use lazy_static::lazy_static;
use mail_parser::Message;
use regex::Regex;

pub trait MyMessageParser<'a> {
    fn get_envelop_from(&'a self) -> Option<String>;
    fn get_received_header_of_gateway(&'a self) -> Option<Box<mail_parser::Received<'a>>>;
    fn get_authentication_results(&'a self) -> Option<HashMap<String, String>>;
}

impl<'a> MyMessageParser<'a> for Message<'a> {
    fn get_envelop_from(&'a self) -> Option<String> {
        let first_header = self.header_values("Return-Path").next();
        if first_header.is_none() {
            return None;
        }
        let address = match first_header.unwrap() {
            mail_parser::HeaderValue::Text(text) => text,
            mail_parser::HeaderValue::Empty => "",
            _ => unreachable!(), // unexpected type for "Return-Path" header
        };
        let envelop_from = address.replace(&['<', '>'], "").to_lowercase().trim().to_string();
        println!("Evelop.from: \"{}\"", envelop_from);
        if envelop_from.len() == 0 {
            None
        } else {
            Some(envelop_from)
        }
    }

    fn get_received_header_of_gateway(&'a self) -> Option<Box<mail_parser::Received<'a>>> {
        for header_value in self.header_values("Received") {
            if let mail_parser::HeaderValue::Received(received) = header_value {
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
                        if received.from_ip().is_none() {
                            continue;
                        }
                        return Some(received.clone());
                    }
                }
            }
        }
        None
    }

    fn get_authentication_results(&'a self) -> Option<HashMap<String, String>> {
        let header_value = match self.header("Authentication-Results") {
            Some(mail_parser::HeaderValue::Text(s)) => s,
            _ => return None,
        };
        println!("Authenticatino-Results: {}", header_value);
        lazy_static! {
            static ref REGEX_CONTINUATION_LINE_PATTERN: Regex = Regex::new(r"\r\n([ \t])").unwrap();
        }
        let header_value = REGEX_CONTINUATION_LINE_PATTERN.replace_all(&header_value, " ");
        let mut table = HashMap::<String, String>::new();
        let records = header_value.split(";").map(str::trim);
        for record in records {
            // refer to RFC5451
            // https://datatracker.ietf.org/doc/html/rfc5451
            if table.get("mx").is_none() {
                // first record is MX (mail server)
                table.insert("mx".to_string(), record.to_string());
                continue;
            }
            if record == "none" {
                continue;
            }
            let (pair, rest) = if let Some((pair, rest)) = record.split_once(' ') { // "rest" may be empty string
                (pair, rest.trim())
            } else {
                (record, "")
            };
            let (label, status) = if let Some((label, status)) = pair.split_once('=') {
                (label, status)
            } else {
                println!("WARNING: syntax error at \"Authentication-Results\" header: \"{}\"", pair);
                continue;
            };
            let target = match label {
                "spf" => {
                    lazy_static! {
                        static ref REGEX_SMTP_MAILFROM: Regex = Regex::new(r"(^|\s)smtp\.mailfrom=(\S+)(\s|$)").unwrap();
                        static ref REGEX_SMTP_HELO: Regex = Regex::new(r"(^|\s)smtp\.helo=(\S+)(\s|$)").unwrap();
                        static ref REGEX_DOMAIN_OF: Regex = Regex::new(r"(^|\s)domain of (\S+) ").unwrap();
                    }
                    if let Some(caps) = REGEX_SMTP_MAILFROM.captures(rest) {
                        Some(caps[2].to_string())
                    } else if let Some(caps) = REGEX_SMTP_HELO.captures(rest) {
                        Some(caps[2].to_string())
                    } else if let Some(caps) = REGEX_DOMAIN_OF.captures(rest) {
                        Some(caps[2].to_string())
                    } else {
                        None
                    }
                },
                "dkim" => {
                    lazy_static! {
                        static ref REGEX_HEADER_I: Regex = Regex::new(r"(^|\s)header\.i=(\S+)(\s|$)").unwrap();
                        static ref REGEX_HEADER_D: Regex = Regex::new(r"(^|\s)header\.d=(\S+)(\s|$)").unwrap();
                    }
                    if let Some(caps) = REGEX_HEADER_I.captures(rest) {
                        Some(caps[2].to_string())
                    } else if let Some(caps) = REGEX_HEADER_D.captures(rest) {
                        Some(caps[2].to_string())
                    } else {
                        None
                    }
                },
                "dmarc" | "dkim-adsp" => {
                    lazy_static! {
                        static ref REGEX_HEADER_FROM: Regex = Regex::new(r"(^|\s)header\.from=(\S+)(\s|$)").unwrap();
                    }
                    if let Some(caps) = REGEX_HEADER_FROM.captures(rest) {
                        Some(caps[2].to_string())
                    } else {
                        None
                    }
                },
                "sender-id" => {
                    lazy_static! {
                        static ref REGEX_HEADER_FROM: Regex = Regex::new(r"(^|\s)header\.From=(\S+)(\s|$)").unwrap();
                    }
                    if let Some(caps) = REGEX_HEADER_FROM.captures(rest) {
                        Some(caps[2].to_string())
                    } else {
                        None
                    }
                },
                _ => { // unknown label
                    println!("WARNING: detect unknown label at \"Authentication-Results\" header: \"{}\"", label);
                    None
                },
            };
            let domain = if let Some(mail_address) = target {
                assert_ne!(mail_address.len(), 0);
                if let Some((_localpart, domain)) = mail_address.split_once('@') {
                    Some(domain.to_string())
                } else {
                    Some(mail_address)
                }
            } else {
                None
            };
            assert!(!table.contains_key(label));
            table.insert(label.to_string(), status.to_string());
            if let Some(s) = domain {
                table.insert(format!("{}-target-domain", label), s);
            }
        }
        Some(table)
    }
}
