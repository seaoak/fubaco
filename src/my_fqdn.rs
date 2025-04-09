use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;

use crate::my_str::normalize_string;

lazy_static! {
    static ref SUSPICIOUS_LIST_FILENAME: String = "./list_suspicious_from.tsv".to_string();
}

//================================================================================
// use my "list_suspicious_from.tsv"

fn load_tsv_file<P: AsRef<Path>>(path: P) -> Result<Vec<Vec<String>>> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    let mut lines = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.len() == 0 {
            continue; // skip empty line
        }
        if line.starts_with("#") {
            continue; // skip comment
        }
        let fields = line.split("\t").map(|s| s.trim()).filter(|s| s.len() > 0).map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(fields.len() > 0);
        lines.push(fields);
    }
    Ok(lines)
}

fn normalize_domain_string(text: &str) -> String {
    text.trim_start_matches(['.', '@']).trim_end_matches('.').to_ascii_lowercase()
}

fn get_blacklist_tld() -> Result<Vec<String>> {
    let lines = load_tsv_file(&*SUSPICIOUS_LIST_FILENAME).unwrap_or_default();
    let it = lines.iter().filter(|l| l[0] == "@");
    let it = it.filter(|l| l.len() > 1);
    let it = it.flat_map(|l| l[1..].iter());
    let it = it.map(|s| normalize_domain_string(s));
    let it = it.map(|s| format!(".{}", s));
    let list = it.collect::<Vec<_>>();
    Ok(list)
}

fn get_trusted_domains() -> Result<Vec<String>> {
    let lines = load_tsv_file(&*SUSPICIOUS_LIST_FILENAME)?;
    let it = lines.iter().filter(|l| l[0] == "!");
    let it = it.filter(|l| l.len() > 1);
    let it = it.flat_map(|l| l[1..].iter());
    let it = it.map(|s| normalize_domain_string(s));
    let list = it.collect::<Vec<_>>();
    assert!(list.iter().all(|s| !s.starts_with('.'))); // redundant dot at the start of string is not allowed
    assert!(list.iter().all(|s| !s.contains('@'))); // localpart is not allowed
    Ok(list)
}

fn get_prohibited_words() -> Result<Vec<String>> {
    let lines = load_tsv_file(&*SUSPICIOUS_LIST_FILENAME)?;
    let it = lines.iter().filter(|l| l.len() == 1);
    let it = it.flatten().map(|word| normalize_string(word));
    let list = it.collect::<Vec<_>>();
    Ok(list)
}

fn get_table_of_valid_domains() -> Result<HashMap<String, Vec<String>>> {
    let lines = load_tsv_file(&*SUSPICIOUS_LIST_FILENAME)?;
    let it = lines.iter().filter(|l| l[0] != "@" && l[0] != "!" && l.len() > 1);
    let it = it.map(|l| {
        let keyword = normalize_string(&l[0]);
        let domains = l[1..].iter().map(|s| normalize_domain_string(s)).collect();
        (keyword, domains)
    });
    let table = it.collect::<HashMap<_, _>>();
    Ok(table)
}

//================================================================================
// use "Public Suffix List"
// https://publicsuffix.org/
//
// use crate "publicsuffix"
// https://crates.io/crates/publicsuffix


//================================================================================
pub fn is_blacklist_tld(fqdn: &str) -> bool {
    let fqdn = fqdn.trim().to_ascii_lowercase();
    let blacklist = get_blacklist_tld().unwrap_or_default();
    for tld in blacklist.iter() {
        if fqdn.ends_with(tld) {
            return true;
        }
    }
    false
}

pub fn is_trusted_domain(fqdn: &str) -> bool {
    let fqdn = fqdn.trim().to_ascii_lowercase();
    let trusted_domains = get_trusted_domains().unwrap_or_default();
    let trusted_pattern = trusted_domains.join("|").replace(".", "[.]");
    let trusted_regex = Regex::new(&format!("(?i)[.@]({})$", trusted_pattern)).unwrap();
    trusted_regex.is_match(&fqdn)
}

pub fn is_prohibited_word_included(text: &str) -> bool {
    let list = get_prohibited_words().unwrap_or_default();
    list.iter().any(|word| text.contains(word))
}

pub fn is_valid_domain_by_guessing_from_text(fqdn: &str, text: &str) -> Option<bool> {
    let fqdn = fqdn.trim().to_ascii_lowercase();
    let table = get_table_of_valid_domains().unwrap_or_default();
    let it = table.into_iter().filter(|(keyword, _domains)| text.contains(keyword));
    let it = it.flat_map(|(_keyword, domains)| domains.into_iter());
    let it = it.map(|s| s.trim_start_matches(['.', '@']).to_owned());
    let joined_string = it.map(|s| s.replace(".", "[.]")).collect::<Vec<_>>().join("|");
    if joined_string.len() == 0 {
        return None; // no keyword is detected
    }
    let pattern_string = format!("(?i)[.@]({})$", joined_string); // case-insensitive
    let regex = match Regex::new(&pattern_string) {
        Ok(v) => v,
        Err(_e) => {
            println!("ERROR: REGEX for suspicious-from is invalid: {}", pattern_string);
            return None;
        },
    };
    Some(regex.is_match(&fqdn))
}
