use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{anyhow, Result};
use mail_parser::Message;
use lazy_static::lazy_static;
use serde::Serialize;
use serde_json;

use crate::my_logger::prelude::*;
use crate::my_timestamp::MyTimestamp;

lazy_static! {
    static ref DB_FILENAME: String = "./fubaco_yondakiji.json".to_string();
}

//================================================================================
#[derive(Debug, Serialize)]
struct MyItem {
    given_url: String,
    given_title: String,
    time_added: String,
    localtime_added: String,
    tags: Vec<String>,
}

impl MyItem {
    pub fn from_message(message: &Message, tags: &Vec<String>) -> Result<Self> {
        let title = match message.subject() {
            Some(s) => s,
            None => return Err(anyhow!("no subject")),
        };

        let body_text =  match message.body_text(0) {
            Some(v) => v,
            None => return Err(anyhow!("no body text")),
        };
        let line = body_text.lines().map(|s| s.trim()).filter(|s| s.len() > 0).nth(0);
        if line.is_none() {
            return Err(anyhow!("empty body"));
        }
        let url = line.unwrap();
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(anyhow!("detect invalid character: {}", url));
        }
        if !url.starts_with("https://") {
            return Err(anyhow!("not a URL: {}", url));
        }

        let timestamp = MyTimestamp::now();
        let given_url = url.into();
        let given_title = title.into();
        let time_added = timestamp.to_int().to_string();
        let localtime_added = timestamp.to_str();
        let tags = tags.clone();
        Ok(Self {
            given_url,
            given_title,
            time_added,
            localtime_added,
            tags,
        })
    }

    pub fn save_to_json_file(&self) -> Result<()> {
        debug!("plugin_yondakiji: write to JSON file: {}", *DB_FILENAME);
        let mut f = OpenOptions::new().append(true).create(true).open(&*DB_FILENAME)?;
        let mut text = serde_json::to_string_pretty(self)?;
        text.push_str(",\n");
        f.write_all(text.as_bytes())?;
        f.flush()?;
        Ok(())
    }
}

//================================================================================
pub fn plugin_yondakiji(table_of_spam_check_result: &mut HashSet<String>, message: &Message) {
    let header_to = message.to().and_then(|to| to.first()).and_then(|addr| addr.address());
    if header_to.is_none() {
        debug!("WARNING: plugin_yondakiji: there is no \"to\" header");
        return;
    }
    let header_to = header_to.unwrap();

    lazy_static! {
        static ref TABLE_OF_MAIL_ADDRESS_TO_TAGS: HashMap<String, Vec<String>> = {
            let mut table = HashMap::new();
            if let Ok(mail_address) = env::var("FUBACO_PLUGIN_YONDAKIJI_ADDRESS_FF14") {
                table.insert(mail_address, vec!["FUBACO".into(), "FF14".into()]);
            }
            if let Ok(mail_address) = env::var("FUBACO_PLUGIN_YONDAKIJI_ADDRESS_OTHERS") {
                table.insert(mail_address, vec!["FUBACO".into(), "OTHERS".into()]);
            }
            assert_ne!(table.len(), 0);
            table
        };
    }

    if let Some(tags) = TABLE_OF_MAIL_ADDRESS_TO_TAGS.get(header_to) {
        debug!("plugin_yondakiji: detect target mail address: {header_to}");
        if !table_of_spam_check_result.is_empty() {
            info!("plugin_yondakiji: clear results of SPAM CHECKER");
            table_of_spam_check_result.clear();
        }
        let item = MyItem::from_message(message, tags);
        let result = item.and_then(|item| item.save_to_json_file());
        if let Err(e) = result {
            error!("ERROR: plugin_yondakiji: {:?}", e);
            return;
        }
    }
}
