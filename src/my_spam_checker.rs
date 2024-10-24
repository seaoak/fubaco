use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use mail_parser::Message;
use kana::wide2ascii;
use lazy_static::lazy_static;
use lingua;
use regex::Regex;
use scraper;
use unicode_normalization::UnicodeNormalization;

lazy_static! {
    static ref BLACKLIST_TLD_LIST: Vec<String> = vec![".cn", ".ru", ".hu", ".br", ".su", ".nz", ".in", ".cz", ".be", ".cl"].into_iter().map(|s| s.to_string()).collect();
    static ref SUSPICIOUS_LIST_FILENAME: String = "./list_suspicious_from.tsv".to_string();
}

fn normalize_string<P: AsRef<str>>(s: P) -> String {
    // normalize string (Unicode NFKC, uppercase, no-whitespace, no-bullet)
    let s: &str = s.as_ref();
    let mut unicode_normalized_str = String::new();
    unicode_normalized_str.extend(s.nfkc());
    wide2ascii(&unicode_normalized_str).to_uppercase().replace(&[' ', '　', '・'], "")
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

fn get_trusted_domains() -> Result<Vec<String>> {
    let lines = load_tsv_file(&*SUSPICIOUS_LIST_FILENAME)?;
    let mut list = lines.into_iter().filter(|l| l.len() > 1).flat_map(|l| l[1..].to_owned().into_iter()).collect::<Vec<String>>();
    for s in list.iter_mut() {
        // remove redundant dot at the start of string
        if s.starts_with(".") {
            s.remove(0);
        }
    }
    Ok(list)
}

pub fn spam_checker_suspicious_envelop_from(message: &Message) -> Option<String> {
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string(); // may be empty string
    let envelop_from = envelop_from.replace(&['<', '>'], "").to_lowercase().trim().to_string();
    println!("Evelop.from: \"{}\"", envelop_from);
    if envelop_from.len() == 0 {
        Some("suspicious-envelop-from".to_string())
    } else {
        None
    }
}

pub fn spam_checker_blacklist_tld(message: &Message) -> Option<String> {
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

pub fn spam_checker_suspicious_from(message: &Message) -> Option<String> {
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
        }
        let mut lines = match load_tsv_file(&*SUSPICIOUS_LIST_FILENAME) {
            Ok(v) => v,
            Err(e) => {
                println!("can not load \"{}\": {}", &*SUSPICIOUS_LIST_FILENAME, e);
                return (REGEX_ALWAYS_MATCH.clone(), Vec::new());
            },
        };
        assert!(lines.iter().all(|fields| fields.len() > 0));
        for fields in &mut lines {
            fields[0] = normalize_string(&fields[0]);
            for s in fields[1..].iter_mut() {
                // remove redundant dot at the start of string
                if s.starts_with(".") {
                    s.remove(0);
                }
            }
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
            domains.extend(fields.into_iter().skip(1));
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
    lazy_static! {
        static ref LANGUAGES_FOR_DETECTOR: Vec<lingua::Language> = vec![lingua::Language::English, lingua::Language::Japanese];
        static ref DETECTOR: lingua::LanguageDetector = lingua::LanguageDetectorBuilder::from_languages(&LANGUAGES_FOR_DETECTOR).build();
        static ref EXCEPTION_CHARS: Vec<char> = vec!['ー']; // these characters are "is_alphabetic()=true", but do not recognize a Japanese character
    }
    let is_suspicious_alphabet = |c: &char| {
        if !c.is_alphabetic() {
            return false;
        }
        if EXCEPTION_CHARS.contains(c) {
            return false;
        }
        // see https://crates.io/crates/lingua
        let confidence_values = DETECTOR.compute_language_confidence_values(*c).into_iter().collect::<HashMap<lingua::Language, f64>>();
        let is_english = confidence_values[&lingua::Language::English] > 0.9;
        let is_japanese = confidence_values[&lingua::Language::Japanese] > 0.9;
        let is_ok = (is_english && c.is_ascii_alphabetic()) || is_japanese;
        if !is_ok {
            println!("suspicious-alphabet: {} ({:?})", *c, confidence_values);
        }
        !is_ok
    };
    if name.chars().any(|c| is_suspicious_alphabet(&c)) {
        return Some("suspicious-alphabet-in-from".to_string());
    }
    if subject.chars().any(|c| is_suspicious_alphabet(&c)) {
        return Some("suspicious-alphabet-in-subject".to_string());
    }
    None
}

pub fn spam_checker_suspicious_hyperlink(message: &Message) -> Option<String> {
    let trusted_domains = get_trusted_domains().unwrap_or_else(|err| {
        println!("WARNING: can not get list of trusted domains: {:?}", err);
        Vec::new()
    });
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
            static ref REGEX_URL_WITH_MAILTO: Regex = Regex::new(r"^mailto[:][-_.+=0-9a-z]+[@][-_.0-9a-z]+$").unwrap();
            static ref REGEX_URL_WITH_NORMAL_HOST: Regex = Regex::new(r"^https?[:][/][/]([-_a-z0-9.]+)([/]\S*)?$").unwrap();
        }
        if url.starts_with('#') {
            continue; // skip "in-page" hyperlink
        }
        if url.starts_with("mailto:") {
            if !REGEX_URL_WITH_MAILTO.is_match(url) {
                println!("suspicious-mailto: \"{}\"", url);
                table.insert("suspicious-mailto");
            }
            continue;
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
        if trusted_domains.iter().any(|d| d == &host_in_href || host_in_href.ends_with(&format!(".{}", d))) {
            continue; // skip later checks (treat as "OK")
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

#[allow(unreachable_code, unused)]
pub fn spam_checker_hidden_text_in_html(message: &Message) -> Option<String> {
    return None; // temporally disable because some sender (Amazon, iCloud) use hidden text in HTML
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

pub fn spam_checker_fully_html_encoded_text(message: &Message) -> Option<String> {
    // https://ja.wikipedia.org/wiki/文字参照
    // https://ja.wikipedia.org/wiki/Quoted-printable
    let text;
    match message.body_text(0) {
        Some(v) => text = v,
        None => return None,
    }
    lazy_static! {
        static ref REGEX_NUMERIC_CHARACTER_REFERENCE: Regex = Regex::new(r"([&][#](\d+|x[0-9a-fA-F]+)[;]){8}").unwrap();
    }
    if REGEX_NUMERIC_CHARACTER_REFERENCE.is_match(&text) {
        return Some("fully-html-encoding-text".to_string());
    }
    None
}

pub fn spam_checker_suspicious_delivery_report(message: &Message) -> Option<String> {
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
