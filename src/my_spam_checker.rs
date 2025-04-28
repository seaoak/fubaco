use std::collections::HashSet;

use mail_parser::Message;
use lazy_static::lazy_static;
use regex::Regex;
use scraper;

use crate::my_fqdn;
use crate::my_str::*;

pub fn spam_checker_envelop_from(table: &mut HashSet<String>, message: &Message) {
    let envelop_from = message.return_path().clone().as_text().unwrap_or_default().to_string();
    let envelop_from = envelop_from.trim().trim_start_matches('<').trim_end_matches('>').trim(); // may be empty string
    println!("Envelop.from: \"{}\"", envelop_from);
    if let Some(fqdn) = my_fqdn::extract_fqdn_in_mail_address_with_validation(&envelop_from) {
        if my_fqdn::is_blacklist_tld(&fqdn) {
            println!("blacklist-tld in envelop from address: \"{}\"", envelop_from);
            table.insert("blacklist-tld-in-envelop-from".into());
        }
    } else {
        table.insert("invalid-envelop-from".into());
    }
}

fn get_list_of_header_from(message: &Message) -> Vec<(Option<String>, Option<String>)> {
    let address = match message.from() {
        Some(a) => a,
        _ => return Vec::new(),
    };
    let list = match address {
        mail_parser::Address::List(v) => v.to_vec(),
        mail_parser::Address::Group(groups) => {
            groups.into_iter().flat_map(|g| g.addresses.iter()).map(|addr| addr.to_owned()).collect()
        },
    };
    list.into_iter().map(|addr| {
        let name = addr.name().map(|s| s.trim().to_owned());
        let address = addr.address().map(|s| s.trim().to_owned());
        (name, address)
    }).collect()
}

pub fn spam_checker_header_from(table: &mut HashSet<String>, message: &Message) {
    let list_header_from = get_list_of_header_from(message);
    if list_header_from.len() > 1024 {
        table.insert("too-many-header-from".into());
    } else {
        list_header_from.into_iter().for_each(|(_name, address)| {
            if address.is_none() {
                table.insert("malformed-header-from".into());
                return;
            }
            let address = address.unwrap();
            if let Some(fqdn) = my_fqdn::extract_fqdn_in_mail_address_with_validation(&address) {
                if my_fqdn::is_blacklist_tld(&fqdn) {
                    println!("blacklist-tld in from header address: \"{}\"", address);
                    table.insert("blacklist-tld-in-header-from".into());
                }
            } else {
                table.insert("invalid-header-from".into());
            }
        });
    }
}

pub fn spam_checker_suspicious_from(table: &mut HashSet<String>, message: &Message) {
    // TODO: support multiple header from
    let name_raw = message.from().map(|x| x.first().unwrap().name.clone().unwrap_or_default()).unwrap_or_default();
    println!("From.name_raw: \"{}\"", name_raw);
    let name = normalize_string(&name_raw);
    println!("From.name: \"{}\"", name);
    let address = normalize_string(message.from().map(|x| x.first().unwrap().address.clone().unwrap_or_default()).unwrap_or_default());
    println!("From.address: \"{}\"", address);
    let subject_raw = message.subject().unwrap_or_default();
    println!("Subject_raw: \"{}\"", subject_raw);
    let subject = normalize_string(subject_raw);
    println!("Subject: \"{}\"", subject);
    let destination = normalize_string(message.to().map(|x| x.first().map(|addr| addr.address.clone().unwrap()).unwrap_or_default()).unwrap_or_default()); // may be empty string
    println!("To.address: \"{}\"", destination);

    if my_fqdn::is_trusted_domain(&address) {
        println!("skip trusted domain: {}", address);
        return;
    }
    if let Some(false) = my_fqdn::is_valid_domain_by_guessing_from_text(&address, &name) {
        table.insert("suspicious-from".into());
    }
    if let Some(false) = my_fqdn::is_valid_domain_by_guessing_from_text(&address, &subject) {
        table.insert("suspicious-from".into());
    }
    if my_fqdn::is_prohibited_word_included(&name) {
        table.insert("prohibited-word-in-from".into());
    }
    if my_fqdn::is_prohibited_word_included(&subject) {
        table.insert("prohibited-word-in-subject".into());
    }
    if address == destination { // header.from is camoflaged with destination address
        table.insert("suspicious-from".into());
    }

    if is_non_english_alphabet_included(&name_raw) {
        table.insert("suspicious-alphabet-in-from".into());
    }
    if is_non_english_alphabet_included(&subject_raw) {
        table.insert("suspicious-alphabet-in-subject".into());
    }

    if is_unicode_control_codepoint_included(&name_raw) {
        table.insert("suspicious-control-codepoint-in-from".into());
    }
    if is_unicode_control_codepoint_included(&subject_raw) {
        table.insert("suspicious-control-codepoint-in-subject".into());
    }
}

fn check_hyperlink(table: &mut HashSet<String>, url: &str, text: Option<String>) {
    lazy_static! {
        static ref REGEX_URL_WITH_MAILTO: Regex = Regex::new(r"^mailto[:][-_.+=0-9a-z]+[@][-_.0-9a-z]+$").unwrap();
        static ref REGEX_URL_WITH_TEL: Regex = Regex::new(r"^tel[:][-0-9]+$").unwrap();
    }
    let url = url.trim();
    if url.len() == 0 {
        return; // skip dummy hyperlink (usually used for JavaScript)
    }
    if url.starts_with('#') {
        return; // skip "in-page" hyperlink
    }
    if url.to_ascii_lowercase().starts_with("mailto:") {
        if !REGEX_URL_WITH_MAILTO.is_match(url) {
            println!("suspicious-mailto: \"{}\"", url);
            table.insert("suspicious-mailto".into());
        }
        return;
    }
    if url.to_ascii_lowercase().starts_with("tel:") {
        if !REGEX_URL_WITH_TEL.is_match(url) {
            println!("suspicious-tel: \"{}\"", url);
            table.insert("suspicious-tel".into());
        }
        return;
    }
    let host_in_href;
    if let Some(host) = my_fqdn::extract_fqdn_in_url_with_validation(url) {
        host_in_href = host;
    } else {
        println!("suspicious-href: \"{}\"", url);
        table.insert("suspicious-href".into());
        return;
    }
    if my_fqdn::is_trusted_domain(&host_in_href) {
        return; // skip later checks (treat as "OK")
    }
    if my_fqdn::is_blacklist_tld(&host_in_href) {
        println!("blacklist-tld-in-href: \"{}\"", host_in_href);
        table.insert("blacklist-tld-in-href".into());
    }
    if let Some(text) = text {
        let text = text.trim();
        if let Some(host_in_text) = my_fqdn::extract_fqdn_in_url_with_validation(&text) {
            if host_in_href != host_in_text {
                println!("camouflage-hyperlink: \"{}\" vs \"{}\"", host_in_href, host_in_text);
                table.insert("camouflaged-hyperlink".into());
            }
        }
    }
}

pub fn spam_checker_suspicious_hyperlink(table: &mut HashSet<String>, message: &Message) {
    let html;
    match message.body_html(0) {
        Some(v) => html = v,
        None => return,
    }
    let dom = scraper::Html::parse_document(&html);
    let selector = scraper::Selector::parse(r"a[href]").unwrap();
    for elem in dom.select(&selector) {
        let url = elem.value().attr("href").unwrap().trim();
        let text = elem.inner_html();
        let text = text.trim().to_owned();
        check_hyperlink(table, url, Some(text));
    }
}

pub fn spam_checker_suspicious_link_in_plain_text(table: &mut HashSet<String>, message: &Message) {
    let body_text;
    match message.body_text(0) {
        Some(v) => body_text = v,
        None => return,
    }
    lazy_static! {
        static ref REGEX_LIKE_URL: Regex = Regex::new(r"(?i)(^|\s)(https?[:][/][/]\S+)(\s|$)").unwrap();
    }
    for line in body_text.lines() {
        if line.len() > 1024 {
            continue; // skip too long line (avoid DoS)
        }
        if let Some(caps) = REGEX_LIKE_URL.captures(line) {
            let url = caps[2].as_ref();
            check_hyperlink(table, url, None);
        }
    }
}

#[allow(unreachable_code, unused)]
pub fn spam_checker_hidden_text_in_html(table: &mut HashSet<String>, message: &Message) {
    return; // temporally disable because some sender (Amazon, iCloud) use hidden text in HTML
    let html;
    match message.body_html(0) {
        Some(v) => html = v,
        None => return,
    }
    lazy_static! {
        static ref REGEX_CSS_FOR_HIDDEN_TEXT: Regex = Regex::new(r"(?i)\bfont-size:\s*0").unwrap(); // case insensitive
    }
    if REGEX_CSS_FOR_HIDDEN_TEXT.is_match(&html) {
        table.insert("hidden-text-in-html".into());
    }
}

pub fn spam_checker_fully_html_encoded_text(table: &mut HashSet<String>, message: &Message) {
    // https://ja.wikipedia.org/wiki/文字参照
    // https://ja.wikipedia.org/wiki/Quoted-printable
    let text;
    match message.body_text(0) {
        Some(v) => text = v,
        None => return,
    }
    lazy_static! {
        static ref REGEX_NUMERIC_CHARACTER_REFERENCE: Regex = Regex::new(r"([&][#](\d+|x[0-9a-fA-F]+)[;]){8}").unwrap();
    }
    if REGEX_NUMERIC_CHARACTER_REFERENCE.is_match(&text) {
        table.insert("fully-html-encoding-text".into());
    }
}

pub fn spam_checker_suspicious_delivery_report(table: &mut HashSet<String>, message: &Message) {
    let from_address = message.from().map(|x| x.first().unwrap().address.clone().unwrap_or_default().to_ascii_lowercase()).unwrap_or_default();
    if !from_address.starts_with("postmaster@") {
        return;
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
                    table.insert("suspicious-delivery-report".into());
                }
            },
            _ => {
                println!("delivery report syntax error");
                table.insert("invalid-delivery-report-format".into());
            }
        }
    }
}
