use lazy_static::lazy_static;
use mail_parser::Message;
use regex::Regex;

pub trait MyMessageParser<'a> {
    fn get_received_header_of_gateway(&'a self) -> Option<Box<mail_parser::Received<'a>>>;
}

impl<'a> MyMessageParser<'a> for Message<'a> {
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
}
