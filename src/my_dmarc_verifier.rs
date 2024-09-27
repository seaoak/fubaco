use mail_parser::Message;

use crate::my_dns_resolver::MyDNSResolver;

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
}

#[allow(unused)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DMARCResult {
    NONE,
    PASS,
    FAIL(DMARCPolicy),
}

impl std::fmt::Display for DMARCResult {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            Self::NONE       => "none",
            Self::PASS       => "pass",
            Self::FAIL(_)    => "fail",
        };
        write!(dest, "{}", s)
    }
}

//====================================================================
#[allow(unused)]
pub fn dmarc_verify(message: &Message, spf_target: &Option<String>, dkim_target: &Option<String>, resolver: &MyDNSResolver) -> DMARCResult {
    DMARCResult::NONE
}
