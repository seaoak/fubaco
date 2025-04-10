use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use mail_parser::MessageParser;
use std::collections::HashSet;
use std::sync::Arc;

use crate::my_dkim_verifier::{self, DKIMResult, DKIMStatus};
use crate::my_dmarc_verifier::{self, DMARCResult, DMARCStatus};
use crate::my_dns_resolver::MyDNSResolver;
use crate::my_message_parser::MyMessageParser;
use crate::my_spam_checker;
use crate::my_spf_verifier::{self, SPFResult, SPFStatus};
use crate::my_str;

lazy_static! {
    pub static ref FUBACO_HEADER_TOTAL_SIZE: usize = 512; // (78+2)*6+(30+2)
}

lazy_static! {
    static ref MY_DNS_RESOLVER: Arc<MyDNSResolver> = Arc::new(MyDNSResolver::new());
}

fn intersect_vec<'a, 'b, S>(a: &'a [S], b: &'b [S]) -> Vec<&'a S>
    where S: PartialEq + Sized
{
    a.iter().filter(|aa| b.contains(aa)).collect()
}

fn make_fubaco_padding_header(nbytes: usize) -> String { // generate just-nbyte-sized "X-Fubaco-Padding" header
    let line_length_limit = 80;
    let headding = "X-Fubaco-Padding: ".to_string();
    assert!(nbytes >= headding.len() + "x\r\n".len()); // at least one "x" is necessary
    let mut buf = format!("{}{}\r\n", headding, "x".repeat(nbytes - headding.len() - "\r\n".len())); // if line length is no limit

    // split buf into multi-line
    let mut pos = line_length_limit - "\r\n".len();
    while pos <= buf.len() - "\r\n\tx\r\n".len() {
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
        pos += line_length_limit;
    }
    if pos < buf.len() { // odd position
        pos = buf.len() - "\r\n\tx\r\n".len(); // roll back
        buf.replace_range(pos..(pos + "\r\n\t".len()), "\r\n\t");
    }
    assert!(buf.ends_with("x\r\n")); // at least one "x" is contained in last line
    buf
}

pub fn make_fubaco_headers(message_u8: &[u8]) -> Result<String> {
    let fixed_message_u8 = my_str::fix_incorrect_quoted_printable_text(message_u8);
    if fixed_message_u8.len() != message_u8.len() {
        println!("fixed_message_u8: {} bytes ({:+})", fixed_message_u8.len(), fixed_message_u8.len() as isize - message_u8.len() as isize);
    }
    let message;
    if let Some(v) = MessageParser::default().parse(&fixed_message_u8) {
        message = v;
    } else {
        return Err(anyhow!("can not parse the message"));
    }

    let spam_judgement = {
        let mut table = HashSet::<&'static str>::new();
        [
            my_spam_checker::spam_checker_suspicious_envelop_from,
            my_spam_checker::spam_checker_blacklist_tld,
            my_spam_checker::spam_checker_suspicious_from,
            my_spam_checker::spam_checker_suspicious_hyperlink,
            my_spam_checker::spam_checker_suspicious_link_in_plain_text,
            my_spam_checker::spam_checker_hidden_text_in_html,
            my_spam_checker::spam_checker_fully_html_encoded_text,
            my_spam_checker::spam_checker_suspicious_delivery_report,
        ].into_iter().for_each(|f| f(&mut table, &message));
        if table.is_empty() {
            table.insert("none");
        }
        let mut list = table.into_iter().collect::<Vec<&'static str>>();
        list.sort();
        list
    };

    let table_of_authentication_results_header = message.get_authentication_results();

    let mut spf_result = my_spf_verifier::spf_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        if let Some(mx_spf_status) = table.get("spf") {
            let mx_spf_status = mx_spf_status.parse::<SPFStatus>().unwrap(); // TODO: unknonw string may have to be an error, not panic
            if &mx_spf_status != spf_result.as_status() {
                println!("WARNING: my SPF checker says different result to \"Authentication-Results\" header: my={} vs header={}", spf_result.as_status(), mx_spf_status);
            }
            let my_spf_domain_list = spf_result.as_domains().clone();
            let mx_spf_domain_list = table.get("spf-target-domains").map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_spf_domain_list.len() > 0 && mx_spf_domain_list.len() > 0 && intersect_vec(&my_spf_domain_list, &mx_spf_domain_list).len() == 0 {
                println!("WARNING: my SPF checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_spf_domain_list, mx_spf_domain_list);
            }
            if mx_spf_status != SPFStatus::NONE {
                spf_result = SPFResult::new(mx_spf_status, mx_spf_domain_list); // overwrite
            }
        }
    }
    let mut dkim_result = my_dkim_verifier::dkim_verify(&message, &MY_DNS_RESOLVER);
    if let Some(table) = &table_of_authentication_results_header {
        let mx_label = ["dkim", "dkim-adsp"].into_iter().filter(|s| table.contains_key(*s)).take(1).next();
        if let Some(mx_label) = mx_label {
            let mx_dkim_status = table.get(mx_label).unwrap();
            let mx_dkim_status = mx_dkim_status.parse::<DKIMStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
            if &mx_dkim_status != dkim_result.as_status() {
                println!("WARNING: my DKIM checker says different result to \"Authentication-Results\" header: my={} vs header={}", dkim_result.as_status(), mx_dkim_status);
            }
            let my_dkim_domain_list = dkim_result.as_domains().clone();
            let mx_dkim_domain_list = table.get(&format!("{}-target-domains", mx_label)).map(|s| s.split(',').map(str::to_string).collect::<Vec<String>>()).unwrap_or_default();
            if my_dkim_domain_list.len() > 0 && mx_dkim_domain_list.len() > 0 && intersect_vec(&my_dkim_domain_list, &mx_dkim_domain_list).len() == 0 {
                println!("WARNING: my DKIM checker says different target domain to \"Authentication-Results\" header: my={:?} vs header={:?}", my_dkim_domain_list, mx_dkim_domain_list);
            }
            if mx_dkim_status != DKIMStatus::NONE {
                dkim_result = DKIMResult::new(mx_dkim_status, mx_dkim_domain_list); // overwrite
            }
        }
    }
    let mut dmarc_result;
    {
        let spf_domain_list: Vec<String> = if spf_result.as_status() == &SPFStatus::PASS {
            spf_result.as_domains().clone()
        } else {
            Vec::new()
        };
        let dkim_domain_list: Vec<String> = if dkim_result.as_status() == &DKIMStatus::PASS {
            dkim_result.as_domains().clone()
        } else {
            Vec::new()
        };
        dmarc_result = my_dmarc_verifier::dmarc_verify(&message, &spf_domain_list, &dkim_domain_list, &MY_DNS_RESOLVER);
        if let Some(table) = &table_of_authentication_results_header {
            if let Some(mx_dmarc_status) = table.get("dmarc") {
                let mx_dmarc_status = mx_dmarc_status.parse::<DMARCStatus>().unwrap(); // TODO: unknown string may have to be an error, not panic
                if &mx_dmarc_status != dmarc_result.as_status() {
                    println!("WARNING: my DMARC checker says different result to \"Authentication-Results\" header: my={} vs header={}", dmarc_result.as_status(), mx_dmarc_status);
                }
                if mx_dmarc_status != DMARCStatus::NONE {
                    dmarc_result = DMARCResult::new(mx_dmarc_status, dmarc_result.as_policy().clone()); // overwrite
                }
            }
        }
    }

    let auth_results = vec![
        format!("spf={}", spf_result.as_status()),
        format!("dkim={}", dkim_result.as_status()),
        format!("dmarc={}", dmarc_result.as_status()),
    ];

    let mut fubaco_headers = Vec::new();
    fubaco_headers.push(format!("X-Fubaco-Spam-Judgement: {}\r\n", spam_judgement.join(" ")));
    fubaco_headers.push(format!("X-Fubaco-Authentication: {}\r\n", auth_results.join(" ")));
    let nbytes = fubaco_headers.iter().fold(0, |acc, s| acc + s.len());
    fubaco_headers.push(make_fubaco_padding_header(*FUBACO_HEADER_TOTAL_SIZE - nbytes));
    Ok(fubaco_headers.join(""))
}
