use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{anyhow, Result};
use mail_parser::Message;
use lazy_static::lazy_static;
use scraper;
use serde::Serialize;
use serde_json;

use crate::my_logger::prelude::*;
use crate::my_timestamp::MyTimestamp;

lazy_static! {
    static ref DB_FILENAME: String = "./fubaco_yondatweet.json".to_string();
}

//================================================================================
#[derive(Debug, Serialize)]
struct MyItem {
    url: String,
    raw_html: String,
    time_added: String,
    localtime_added: String,
    status_id: String,
    user_name: String,
    user_id: String,
    body_text: String,
    localtime_posted: String,
    tags: Vec<String>,
}

impl MyItem {
    pub fn from_message(message: &Message, tags: &Vec<String>) -> Result<Self> {
        let date_header = message.date().ok_or_else(|| anyhow!("no \"Date:\" header"))?;
        let timestamp_of_mail = MyTimestamp::from(date_header.to_timestamp());
        let time_added = timestamp_of_mail.to_int().to_string();
        let localtime_added = timestamp_of_mail.to_str();

        let raw_html = message.body_html(0).ok_or_else(|| anyhow!("no body HTML"))?.to_string();
        let dom = scraper::Html::parse_document(&raw_html);

        let raw_url = {
            let selector = scraper::Selector::parse(r"a[href]").unwrap();
            let elem = dom.select(&selector).nth(0).ok_or_else(|| anyhow!("no href"))?;
            let href = elem.value().attr("href").unwrap().trim();
            if !href.starts_with(r"https://x.com/") {
                return Err(anyhow!("invalid URL (invalid prefix): {}", href));
            }
            href
        };
        let url = raw_url.split_once("?").ok_or_else(|| anyhow!("invalid URL (no query): {}", raw_url))?.0.to_string();
        let parts_of_url: Vec<_> = url.split("/").collect();
        if parts_of_url.len() != 6 || parts_of_url[4] != "status" {
            return Err(anyhow!("invalid URL (invalid form): {}", url));
        }
        let user_id = parts_of_url[3].to_string();
        let status_id = parts_of_url[5].to_string();

        let user_name = {
            let pattern = format!(r###"a[href*="{}?"]:not(:has(img))"###, parts_of_url[0..4].join("/"));
            let selector = scraper::Selector::parse(&pattern).unwrap();
            let elem = dom.select(&selector).nth(0).ok_or_else(|| anyhow!("no href for user_name"))?;
            elem.inner_html()
        };

        let body_text = {
            let selector = scraper::Selector::parse(r"td:not(:has(table)").unwrap();
            let elem = (|| {
                for elem in dom.select(&selector) {
                    if let Some(style) = elem.attr("style") {
                        for key_and_value in style.split(";").map(|s| s.trim()) {
                            if key_and_value == "text-decoration: none" {
                                return Ok(elem);
                            }
                        }
                    }
                }
                Err(anyhow!("no body text"))
            })()?;
            let lines = elem.children().map(|node| {
                match node.value() {
                    scraper::Node::Text(t) => Ok(t.to_string()),
                    scraper::Node::Element(e) => {
                        match e.name().to_ascii_lowercase().as_str() {
                            "br" => Ok("\n".to_string()),
                            "a" => {
                                // same as `e.innerText`
                                let list = scraper::ElementRef::wrap(node).unwrap().text().collect::<Vec<_>>();
                                Ok(list.join(""))
                            },
                            _ => Err(anyhow!("unexpected element: {:?}", e)),
                        }
                    },
                    _ => Err(anyhow!("invalid Node: {:?}", node)),
                }
            }).collect::<Result<Vec<_>>>()?;
            lines.join("")
        };

        let localtime_posted = {
            let selector = scraper::Selector::parse(r"td>a:only-child:not(:has(img))").unwrap();
            let elem = dom.select(&selector).nth(1).ok_or_else(|| anyhow!("no element for localtime_posted"))?;
            elem.inner_html()
        };

        let tags = tags.clone();
        Ok(Self {
            url,
            raw_html,
            time_added,
            localtime_added,
            status_id,
            user_name,
            user_id,
            body_text,
            localtime_posted,
            tags,
        })
    }

    pub fn save_to_json_file(&self) -> Result<()> {
        debug!("plugin_yondatweet: write to JSON file: {}", *DB_FILENAME);
        let mut f = OpenOptions::new().append(true).create(true).open(&*DB_FILENAME)?;
        let mut text = serde_json::to_string_pretty(self)?;
        text.push_str(",\n");
        f.write_all(text.as_bytes())?;
        f.flush()?;
        Ok(())
    }
}

//================================================================================
pub fn plugin_yondatweet(table_of_spam_check_result: &mut HashSet<String>, message: &Message) {
    let header_to = message.to().and_then(|to| to.first()).and_then(|addr| addr.address());
    if header_to.is_none() {
        debug!("WARNING: plugin_yondatweet: there is no \"to\" header");
        return;
    }
    let header_to = header_to.unwrap();

    lazy_static! {
        static ref TABLE_OF_MAIL_ADDRESS_TO_TAGS: HashMap<String, Vec<String>> = {
            let mut table = HashMap::new();
            if let Ok(mail_address) = env::var("FUBACO_PLUGIN_YONDATWEET_ADDRESS_FF14") {
                table.insert(mail_address, vec!["FUBACO".into(), "TWEET".into(), "FF14".into()]);
            }
            if let Ok(mail_address) = env::var("FUBACO_PLUGIN_YONDATWEET_ADDRESS_OTHERS") {
                table.insert(mail_address, vec!["FUBACO".into(), "TWEET".into(), "OTHERS".into()]);
            }
            assert_ne!(table.len(), 0);
            table
        };
    }

    if let Some(tags) = TABLE_OF_MAIL_ADDRESS_TO_TAGS.get(header_to) {
        debug!("plugin_yondatweet: detect target mail address: {header_to}");
        if !table_of_spam_check_result.is_empty() {
            info!("plugin_yondatweet: clear results of SPAM CHECKER");
            table_of_spam_check_result.clear();
        }
        let item = MyItem::from_message(message, tags);
        let result = item.and_then(|item| item.save_to_json_file());
        if let Err(e) = result {
            error!("ERROR: plugin_yondatweet: {:?}", e);
            return;
        }
    }
}
