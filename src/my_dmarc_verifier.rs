use anyhow::anyhow;
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
    ENFORCED, // Fubaco original (when no DNS record is existed)
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
    policy: DMARCPolicy,
}

impl DMARCResult {
    pub fn new(status: DMARCStatus, policy: DMARCPolicy) -> Self {
        Self {
            status,
            policy,
        }
    }

    pub fn as_status(&self) -> &DMARCStatus {
        &self.status
    }

    pub fn as_policy(&self) -> &DMARCPolicy {
        &self.policy
    }
}

//====================================================================
#[allow(unused)]
pub fn dmarc_verify(message: &Message, spf_target: &Option<String>, dkim_target: &Option<String>, resolver: &MyDNSResolver) -> DMARCResult {
    DMARCResult::new(DMARCStatus::NONE, DMARCPolicy::NONE)
}
