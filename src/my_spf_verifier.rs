use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use anyhow::anyhow;
use lazy_static::lazy_static;
use mail_parser::Message;
use regex::Regex;

use crate::my_dns_resolver::MyDNSResolver;
use crate::my_logger::prelude::*;
use crate::my_message_parser::MyMessageParser;

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SPFStatus {
    NONE,
    NEUTRAL,
    PASS,
    FAIL,
    SOFTFAIL,
    HARDFAIL,
    PERMERROR,
    TEMPERROR,
}

impl std::fmt::Display for SPFStatus {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::NONE      => "none",
            Self::NEUTRAL   => "neutral",
            Self::PASS      => "pass",
            Self::FAIL      => "fail",
            Self::SOFTFAIL  => "softfail",
            Self::HARDFAIL  => "hardfail",
            Self::PERMERROR => "permerror",
            Self::TEMPERROR => "temperror",
        };
        write!(dest, "{}", s)
    }
}

impl std::str::FromStr for SPFStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none"         => Ok(Self::NONE),
            "neutral"      => Ok(Self::NEUTRAL),
            "pass"         => Ok(Self::PASS),
            "fail"         => Ok(Self::FAIL),
            "softfail"     => Ok(Self::SOFTFAIL),
            "hardfail"     => Ok(Self::HARDFAIL),
            "permerror"    => Ok(Self::PERMERROR),
            "temperror"    => Ok(Self::TEMPERROR),
            _              => Err(anyhow!("invalid string for SPFStatus")),
        }
    }
}

//====================================================================
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SPFResult {
    status: SPFStatus,
    domains: Vec<String>, // domain part of "smtp.mailfrom" or "smtp.helo"
}

impl SPFResult {
    pub fn new(status: SPFStatus, domains: Vec<String>) -> Self {
        Self {
            status,
            domains,
        }
    }

    pub fn as_status(&self) -> &SPFStatus {
        &self.status
    }

    pub fn as_domains(&self) -> &Vec<String> {
        &self.domains
    }
}

//====================================================================
fn spf_check_recursively(domain: &str, source_ip: &IpAddr, envelop_from: &str, resolver: &MyDNSResolver) -> SPFResult {
    let target_domain = if let Some((_localpart, domain)) = envelop_from.split_once('@') {
        domain
    } else {
        envelop_from
    };
    let target_domain = target_domain.to_string();

    let spf_record;
    match resolver.query_spf_record(domain) {
        Ok(Some(s)) => spf_record = s,
        Ok(None) => return SPFResult::new(SPFStatus::NONE, vec![target_domain]),
        Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
    }

    lazy_static! {
        static ref REGEX_SPF_REDIRECT_DOMAIN: Regex = Regex::new(r"^redirect=([_a-z0-9]([-_a-z0-9]*[a-z0-9])?([.][a-z0-9]([-_a-z0-9]*[a-z0-9])?)*)$").unwrap();
        static ref REGEX_SPF_INCLUDE_DOMAIN: Regex = Regex::new(r"^include:([_a-z0-9]([-_a-z0-9]*[a-z0-9])?([.][a-z0-9]([-_a-z0-9]*[a-z0-9])?)*)$").unwrap();
    }
    let mut fields: Vec<String> = spf_record.split_ascii_whitespace().map(ToString::to_string).collect();
    fields.reverse();
    let first_field = fields.pop().unwrap();
    if first_field != "v=spf1" {
        return SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]); // invalid SPF record (abort immediately)
    }
    while let Some(field) = fields.pop() {
        if field == "~all" {
            return SPFResult::new(SPFStatus::SOFTFAIL, vec![target_domain]);
        }
        if field == "-all" {
            return SPFResult::new(SPFStatus::FAIL, vec![target_domain]);
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
            match resolver.query_simple(domain, query_type) {
                Ok(records) => {
                    for record in records {
                        fields.push(format!("{}{}", prefix, record));
                    }
                    continue;
                },
                Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
            }
        }
        if field == "+mx" || field == "mx" {
            let hosts = match resolver.query_mx_record(domain) {
                Ok(v) => v,
                Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
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
                match resolver.query_simple(&host, query_type) {
                    Ok(records) => {
                        for record in records {
                            fields.push(format!("{}{}", prefix, record));
                        }
                    },
                    Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
                }
            }
            continue;
        }
        if field == "+exists" || field == "exists" {
            let hosts = match resolver.query_simple(domain, "A") {
                Ok(v) => v,
                Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
            };
            if hosts.len() > 0 {
                return SPFResult::new(SPFStatus::PASS, vec![target_domain]);
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
            match resolver.query_simple(&name, "PTR") {
                Ok(v) => hosts.extend(v.into_iter()),
                Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
            }
            if hosts.len() != 1 {
                debug!("can not get PTR record of: {} {}", name, hosts.len());
                return SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]); // invalid DNS info
            }
            let host = hosts.pop().unwrap();
            let postfix = if host.ends_with(".") { "." } else { "" };
            let target = format!("{}{}", domain, postfix);
            if host.ends_with(&target) {
                let mut list = Vec::new();
                match resolver.query_simple(&host, query_type) {
                    Ok(v) => list.extend(v.into_iter()),
                    Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]),
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
        fn process_ip_field<I: MyIpAddr>(prefix: &str, regex: &Regex, source_ip: &IpAddr, field: &str, target_domain: String) -> Option<SPFResult> {
            let addr;
            let bitmask_len;
            if let Some(caps) = regex.captures(field) {
                let arg1 = caps[1].to_string();
                addr = arg1.parse::<I>().unwrap_or(I::UNSPECIFIED);
                let arg3 = caps.get(3).map_or(I::BITS.to_string(), |s| s.as_str().to_string());
                bitmask_len = u32::from_str_radix(&arg3, 10).unwrap_or(0);
            } else {
                debug!("{} syntax error: \"{}\"", prefix, field);
                return Some(SPFResult::new(SPFStatus::PERMERROR, vec![target_domain])); // syntax error (abort immediately)
            }

            if addr == I::UNSPECIFIED {
                debug!("{} address parse error: \"{}\"", prefix, field);
                return Some(SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]));
            }
            if bitmask_len == 0 || bitmask_len > I::BITS {
                debug!("{} netmask parse error: \"{}\"", prefix, field);
                return Some(SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]));
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
                return Some(SPFResult::new(SPFStatus::PASS, vec![target_domain]));
            }
            None
        }

        if field.starts_with("+ip4:") || field.starts_with("ip4:") {
            lazy_static! {
                static ref REGEX_SPF_IPV4: Regex = Regex::new(r"^[+]?ip4:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)([/]([1-9][0-9]*))?$").unwrap();
            }
            if let Some(result) = process_ip_field::<Ipv4Addr>("ip4", &REGEX_SPF_IPV4, source_ip, &field, target_domain.clone()) {
                return result;
            }
        }
        if field.starts_with("+ip6:") || field.starts_with("ip6:") {
            lazy_static! {
                static ref REGEX_SPF_IPV6: Regex = Regex::new(r"^[+]?ip6:([:0-9a-f]+)([/]([1-9][0-9]*))?$").unwrap();
            }
            if let Some(result) = process_ip_field::<Ipv6Addr>("ip6", &REGEX_SPF_IPV6, source_ip, &field, target_domain.clone()) {
                return result;
            }
        }
        if let Some(caps) = REGEX_SPF_REDIRECT_DOMAIN.captures(&field) {
            let domain = caps[1].to_string();
            let nested_spf;
            match resolver.query_spf_record(&domain) {
                Ok(Some(s)) => nested_spf = s,
                Ok(None) => return SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]), // invalid field (abort immediately)
                Err(_e) => return SPFResult::new(SPFStatus::TEMPERROR, vec![target_domain]), // internal error
            }
            let mut nested_fields: Vec<String> = nested_spf.split_ascii_whitespace().map(ToString::to_string).collect();
            nested_fields.reverse();
            let first_field = nested_fields.pop().unwrap();
            if first_field != "v=spf1" {
                return SPFResult::new(SPFStatus::PERMERROR, vec![target_domain]); // invalid SPF record (abort immediately)
            }
            fields.extend(nested_fields.into_iter());
            continue;
        }
        if let Some(caps) = REGEX_SPF_INCLUDE_DOMAIN.captures(&field) {
            let domain = caps[1].to_string();
            let result = spf_check_recursively(&domain, source_ip, envelop_from, resolver);
            match &result.status {
                &SPFStatus::PASS      => return result,
                &SPFStatus::PERMERROR => return result,
                &SPFStatus::TEMPERROR => return result,
                &SPFStatus::NONE      => (), // ignored
                &SPFStatus::NEUTRAL   => (), // ignored
                &SPFStatus::FAIL      => (), // ignored
                &SPFStatus::SOFTFAIL  => (), // ignored
                &SPFStatus::HARDFAIL  => (), // ignored
            }
        }

        // ignore (skip) unknown field
    }
    SPFResult::new(SPFStatus::NONE, vec![target_domain])
}

//====================================================================
pub fn spf_verify(message: &Message, resolver: &MyDNSResolver) -> SPFResult {
    let envelop_from = if let Some(addr) = message.get_envelop_from() {
        addr
    } else {
        return SPFResult::new(SPFStatus::NONE, Vec::new());
    };

    let domain = if let Some((_localpart, domain)) = envelop_from.split_once('@') {
        domain.to_string()
    } else {
        envelop_from.clone()
    };

    let source_ip = if let Some(addr) = message.get_source_ip() {
        addr
    } else {
        return SPFResult::new(SPFStatus::NONE, vec![domain]);
    };
    trace!("source_ip: {}", source_ip);

    spf_check_recursively(&domain, &source_ip, &envelop_from, resolver)
}
