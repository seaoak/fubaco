use std::collections::HashMap;
use std::str::FromStr;

use anyhow::anyhow;
use lazy_static::lazy_static;
use mail_parser::Message;
use regex::Regex;

use crate::my_dns_resolver::MyDNSResolver;
use crate::my_message_parser::MyMessageParser;

//====================================================================
#[allow(unused)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum IdentifierAlignmentStatus {
    Strict,
    Relaxed,
    None,
}

impl IdentifierAlignmentStatus {

    // refer to "section 3.1" in RFC7489
    #[allow(unused)]
    pub fn check_alignment(target: &str, header_from: &str) -> Self {
        let target_domain = if let Some((_localpart, domain)) = target.split_once('@') {
            domain
        } else {
            target
        };
        let header_domain = if let Some((_localpart, domain)) = header_from.split_once('@') {
            domain
        } else {
            header_from
        };
        let target_domain = target_domain.to_ascii_lowercase(); // just in case
        let header_domain = header_domain.to_ascii_lowercase(); // just in case
        assert!(!target_domain.starts_with("."));
        assert!(!header_domain.starts_with("."));
        if target_domain == header_domain {
            return Self::Strict;
        }
        if target_domain.ends_with(&format!(".{}", header_domain)) {
            // NOTE: skip using Public Suffix List(PSL)
            return Self::Relaxed;
        }
        Self::None
    }
}

//====================================================================
#[allow(unused)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DMARCPolicy {
    NONE,
    QUARANTINE,
    REJECT,
    ENFORCED, // Fubaco original (when no DNS record is existed)
}

impl std::str::FromStr for DMARCPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none"         => Ok(Self::NONE),
            "quarantine"   => Ok(Self::QUARANTINE),
            "reject"       => Ok(Self::REJECT),
            _              => Err(anyhow!("invalid string for DMARCPolicy")),
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DMARCStatus {
    NONE,
    PASS,
    FAIL,
    TEMPERROR,
    PERMERROR,
}

impl std::fmt::Display for DMARCStatus {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::NONE       => "none",
            Self::PASS       => "pass",
            Self::FAIL       => "fail",
            Self::TEMPERROR  => "temperror",
            Self::PERMERROR  => "permerror",
        };
        write!(dest, "{}", s)
    }
}

impl std::str::FromStr for DMARCStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none"         => Ok(Self::NONE),
            "pass"         => Ok(Self::PASS),
            "fail"         => Ok(Self::FAIL),
            "temperror"    => Ok(Self::TEMPERROR),
            "permerror"    => Ok(Self::PERMERROR),
            _              => Err(anyhow!("invalid string for DMARCStatus")),
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DMARCResult {
    status: DMARCStatus,
    policy: Option<DMARCPolicy>,
}

impl DMARCResult {
    pub fn new(status: DMARCStatus, policy: Option<DMARCPolicy>) -> Self {
        Self {
            status,
            policy,
        }
    }

    pub fn as_status(&self) -> &DMARCStatus {
        &self.status
    }

    pub fn as_policy(&self) -> &Option<DMARCPolicy> {
        &self.policy
    }
}

//====================================================================
#[allow(unused)]
pub fn dmarc_verify(message: &Message, spf_target: &Option<String>, dkim_target: &Option<String>, resolver: &MyDNSResolver) -> DMARCResult {
    let target_domain = if let Some(s) = message.get_domain_of_header_from() {
        s
    } else {
        return DMARCResult::new(DMARCStatus::PERMERROR, None);
    };

    // DNS lookup for DMARC record
    let dns_fields = {
        let dns_record = match resolver.query_simple(&format!("_dmarc.{}", target_domain), "TXT") {
            Ok(v) => {
                assert_ne!(v.len(), 0); // at least one entry must be existed if DNS lookup succeed
                if v.len() > 1 {
                    println!("multiple DMARC records are found by DNS lookup ({}): {:?}", target_domain, v);
                    return DMARCResult::new(DMARCStatus::PERMERROR, None);
                }
                v[0].clone()
            },
            Err(e) => {
                println!("no DMARC record is found by DNS lookup ({}): {:?}", target_domain, e);
                return DMARCResult::new(DMARCStatus::TEMPERROR, None);
            }
        };
        let mut table = HashMap::<String, String>::new();
        for field in dns_record.split(';').map(|s| s.trim()) {
            if let Some((left, right)) = field.split_once('=') {
                if table.contains_key(left) {
                    println!("invalid DMARC record: key \"{}\" is existed multple times", left);
                    return DMARCResult::new(DMARCStatus::PERMERROR, None);
                }
                if table.is_empty() {
                    if left != "v" {
                        println!("invalid DMARC record: the first tag must be \"v\", but: {}", left);
                        return DMARCResult::new(DMARCStatus::PERMERROR, None);
                    }
                }
                table.insert(left.to_string(), right.to_string());
            }
        }

        // validate and complement DMARC record (see "Section 6.3" in RFC7489)
        {
            fn validate<F>(table: &mut HashMap<String, String>, label: &str, default_value: Option<&str>, is_valid: F) -> Option<DMARCResult>
                where F: Fn(&str) -> bool
            {
                if let Some(s) = table.get(label) {
                    if is_valid(s.as_str()) {
                        // OK
                    } else {
                        println!("detect invalid \"{}\" field in DMARC record: \"{}\"", label, s);
                        return Some(DMARCResult::new(DMARCStatus::PERMERROR, None));
                    }
                } else {
                    if let Some(s) = default_value { // may be empty string (for OPTIONAL field with string argument)
                        if s.len() > 0 {
                            table.insert(label.to_string(), s.to_string());
                        }
                    } else {
                        println!("detet lack of required field \"{}\" in DMARC record", label);
                        return Some(DMARCResult::new(DMARCStatus::PERMERROR, None));
                    }
                }
                None
            }

            lazy_static! {
                static ref REGEX_INTEGER_FROM_0_to_100: Regex = Regex::new(r"^([0-9]|[1-9][0-9]|100)$").unwrap();
                static ref REGEX_INTEGER_GREATER_THAN_0: Regex = Regex::new(r"^([1-9][0-9]*)$").unwrap();
                static ref REGEX_MAIL_ADDRESS_LIST: Regex = Regex::new(r"^mailto[:]([-_.+=0-9a-zA-Z]+[@][-_.0-9a-zA-Z]+)([,]mailto[:]([-_.+=0-9a-zA-Z]+[@][-_.0-9a-zA-Z]+))*$").unwrap();
            }

            if let Some(r) = validate(&mut table, "adkim", Some("r"), |s| s == "r" || s == "s") {
                return r;
            }
            if let Some(r) = validate(&mut table, "aspf", Some("r"), |s| s == "r" || s == "s") {
                return r;
            }
            if let Some(r) = validate(&mut table, "fo", Some("0"), |s| s == "0" || s == "1" || s == "d" || s == "s") {
                return r;
            }
            if let Some(r) = validate(&mut table, "p", None, |s| s == "none" || s == "quarantine" || s == "reject") {
                return r;
            }
            if let Some(r) = validate(&mut table, "pct", Some("100"), |s| REGEX_INTEGER_FROM_0_to_100.is_match(s)) {
                return r;
            }
            if let Some(r) = validate(&mut table, "rf", Some("afrf"), |s| true) {
                return r;
            }
            if let Some(r) = validate(&mut table, "ri", Some("86400"), |s| REGEX_INTEGER_GREATER_THAN_0.is_match(s)) {
                return r;
            }
            if let Some(r) = validate(&mut table, "rua", Some(""), |s| REGEX_MAIL_ADDRESS_LIST.is_match(s)) {
                return r;
            }
            if let Some(r) = validate(&mut table, "ruf", Some(""), |s| REGEX_MAIL_ADDRESS_LIST.is_match(s)) {
                return r;
            }
            if let Some(r) = validate(&mut table, "sp", Some(""), |s| s == "none" || s == "quarantine" || s == "reject") {
                return r;
            }
            if let Some(r) = validate(&mut table, "v", None, |s| s == "DMARC1") {
                return r;
            }
        }

        table
    };
    let policy = DMARCPolicy::from_str(dns_fields.get("p").unwrap()).unwrap();

    // check alignment
    {
        fn is_aligned(mode: Option<&String>, prev_target: &Option<String>, target_domain: &str) -> bool {
            let mode = mode.unwrap().as_str(); // must be complemented already
            let target = if let Some(addr) = prev_target {
                addr.as_str()
            } else {
                return false;
            };
            let alignment_status = IdentifierAlignmentStatus::check_alignment(target, target_domain);
            match (mode, alignment_status) {
                ("s", IdentifierAlignmentStatus::Strict)   => true,
                ("s", IdentifierAlignmentStatus::Relaxed)  => false,
                ("s", IdentifierAlignmentStatus::None)     => false,
                ("r", IdentifierAlignmentStatus::Strict)   => true,
                ("r", IdentifierAlignmentStatus::Relaxed)  => true,
                ("r", IdentifierAlignmentStatus::None)     => false,
                _                                          => unreachable!("BUG"),
            }
        }

        let mut is_alignment_ok = false;
        if is_aligned(dns_fields.get("aspf"), spf_target, &target_domain) {
            is_alignment_ok = true; // overwrite
        }
        if is_aligned(dns_fields.get("adkim"), dkim_target, &target_domain) {
            is_alignment_ok = true; // overwrite
        }

        if !is_alignment_ok {
            return DMARCResult::new(DMARCStatus::FAIL, Some(policy));
        }
    };








    DMARCResult::new(DMARCStatus::NONE, None)
}
