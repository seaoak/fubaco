use std::collections::HashMap;
use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;

use crate::{FUBACO_HEADER_TOTAL_SIZE, MessageInfo, UniqueID};
use crate::my_disconnect::MyDisconnect;
use crate::my_text_line_stream::MyTextLineStream;

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE_GENERAL: Regex = Regex::new(r"^([A-Z]+)(?: +(\S+)(?: +(\S+))?)? *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND: Regex = Regex::new(r"^ *(\S+) +(\S+) *$").unwrap(); // "\r\n" is stripped
    static ref REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS: Regex = Regex::new(r"\b([1-9][0-9]*) octets\b").unwrap();
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MessageNumber(u32);

pub fn process_pop3_transaction<S, T>(upstream_stream: &mut MyTextLineStream<S>, downstream_stream: &mut MyTextLineStream<T>, database: &mut HashMap<UniqueID, MessageInfo>) -> Result<()>
    where S: Read + Write + MyDisconnect,
          T: Read + Write + MyDisconnect,
{
    let unique_id_to_message_info = database;

    // issue internal "UIDL" command (to get unique-id for all mails)
    let message_number_to_unique_id;
    {
        println!("issue internal UIDL command");
        let command_line = format!("UIDL\r\n").into_bytes();
        upstream_stream.write_all_and_flush(&command_line)?;
        println!("wait the response for UIDL command");
        let mut response_lines = Vec::<u8>::new();
        upstream_stream.read_some_lines(&mut response_lines)?;
        let status_line = MyTextLineStream::<S>::take_first_line(&response_lines)?;
        println!("the response for UIDL command is received: {}", status_line.trim());
        if status_line.starts_with("-ERR") {
            return Err(anyhow!("FATAL: ERR response is received for UIDL command"));
        }
        assert!(status_line.starts_with("+OK"));
        println!("parse response body of UIDL command");
        let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
        let body_text = String::from_utf8_lossy(body_u8);
        let mut table: HashMap<MessageNumber, UniqueID> = HashMap::new();
        for line in body_text.split_terminator("\r\n") {
            if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                let unique_id = UniqueID(caps.get(2).unwrap().as_str().into());
                let is_already_existed = table.insert(message_number, unique_id).is_some();
                assert!(!is_already_existed);
            } else {
                return Err(anyhow!("invalid response: {}", line));
            }
        }
        message_number_to_unique_id = table;
        println!("Done");
    }

    // issue internal "LIST" command (to get message size for all mails)
    let message_number_to_nbytes;
    {
        println!("issue internal LIST command");
        let command_line = format!("LIST\r\n").into_bytes();
        upstream_stream.write_all_and_flush(&command_line)?;
        println!("wait the response for LIST command");
        let mut response_lines = Vec::<u8>::new();
        upstream_stream.read_some_lines(&mut response_lines)?;
        let status_line = MyTextLineStream::<S>::take_first_line(&response_lines)?;
        println!("the response for UIDL command is received: {}", status_line.trim());
        if status_line.starts_with("-ERR") {
            return Err(anyhow!("FATAL: ERR response is received for LIST command"));
        }
        assert!(status_line.starts_with("+OK"));
        println!("parse response body of LIST command");
        let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
        let body_text = String::from_utf8_lossy(body_u8);
        let mut table: HashMap<MessageNumber, usize> = HashMap::new();
        for line in body_text.split_terminator("\r\n") {
            if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                let is_already_existed = table.insert(message_number, nbytes).is_some();
                assert!(!is_already_existed);
            } else {
                return Err(anyhow!("invalid response: {}", line));
            }
        }
        message_number_to_nbytes = table;
        println!("Done");
    }

    if unique_id_to_message_info.len() == 0 { // at the first time only, all existed massages are treated as old messages which have no fubaco header
        for (_message_number, unique_id) in message_number_to_unique_id.iter() {
            let info =
                MessageInfo {
                    unique_id: unique_id.clone(),
                    fubaco_headers: "".to_string(),
                    is_deleted: false,
                };
            let ret = unique_id_to_message_info.insert(unique_id.clone(), info);
            assert!(ret.is_none());
        }
    }
    println!("{} messages exist in database", unique_id_to_message_info.len());

    let total_nbytes_of_maildrop = message_number_to_nbytes.values().fold(0, |acc, nbytes| acc + nbytes);
    println!("total_nbytes_of_maildrop = {}", total_nbytes_of_maildrop);
    let total_nbytes_of_modified_maildrop = message_number_to_unique_id
        .iter()
        .map(|(message_number, unique_id)| {
            if let Some(info) = unique_id_to_message_info.get(unique_id) {
                message_number_to_nbytes[message_number] + info.fubaco_headers.len()
            } else {
                message_number_to_nbytes[message_number] + *FUBACO_HEADER_TOTAL_SIZE
            }
        })
        .fold(0, |acc, nbytes| acc + nbytes);
    println!("total_nbytes_of_modified_maildrop = {}", total_nbytes_of_modified_maildrop);

    // relay POP3 commands/responses
    loop {
        let command_name;
        let command_arg1;
        let is_multi_line_response_expected;
        { // relay a POP3 command
            let mut command_line = Vec::<u8>::new();
            downstream_stream.read_some_lines(&mut command_line)?;
            let command_str = String::from_utf8_lossy(&command_line);
            println!("relay POP3 command: {}", command_str.trim());
            upstream_stream.write_all_and_flush(&command_line)?;
            println!("Done");

            if let Some(caps) = REGEX_POP3_COMMAND_LINE_GENERAL.captures(&command_str) {
                command_name = caps[1].to_string();
                command_arg1 = caps.get(2).map(|v| v.as_str().to_owned());
            } else {
                return Err(anyhow!("invalid command line: {}", command_str.trim()));
            }

            is_multi_line_response_expected = match command_name.as_str() {
                "STAT"                           => false,
                "LIST" if command_arg1.is_none() => true,
                "LIST" if command_arg1.is_some() => false,
                "RETR"                           => true,
                "DELE"                           => false,
                "NOOP"                           => false,
                "RSET"                           => false,
                "QUIT"                           => false,
                "TOP"                            => true,
                "UIDL" if command_arg1.is_none() => true,
                "UIDL" if command_arg1.is_some() => false,
                "USER"                           => false,
                "PASS"                           => false,
                _ => return Err(anyhow!("unknown command: {}", command_str.trim())),
            };
        }

        let mut response_lines = Vec::<u8>::new();
        let mut is_first_response = true;
        let mut status_line = "".to_string(); // dummy initialization (must be set to a string before use)
        loop { // receive lines until the end of a response
            upstream_stream.read_some_lines(&mut response_lines)?;
            if is_first_response {
                status_line = MyTextLineStream::<S>::take_first_line(&response_lines)?;
            }
            if is_first_response && status_line.starts_with("-ERR") {
                println!("ERR response is received: {}", status_line.trim());
                break;
            }
            assert!(!is_first_response || status_line.starts_with("+OK"));
            if !is_multi_line_response_expected {
                println!("single-line response is received: {}", status_line.trim());
                break;
            }
            if MyTextLineStream::<S>::ends_with_u8(&response_lines, b"\r\n.\r\n") {
                println!("multl-line response ({} byte body) is received: {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line.trim());
                break;
            }
            is_first_response = false;
        }
        if status_line.starts_with("+OK") {
            // modify response
            if command_name == "LIST" && command_arg1.is_some() {
                println!("modify single-line response for LIST command");
                let arg_message_number = MessageNumber(u32::from_str_radix(&command_arg1.clone().unwrap(), 10).unwrap());
                let unique_id;
                if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
                    unique_id = v;
                } else {
                    return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
                }
                let message_number;
                let nbytes;
                if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                    message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().as_str(), 10).unwrap());
                    nbytes = usize::from_str_radix(caps.get(2).unwrap().as_str(), 10).unwrap();
                } else {
                    return Err(anyhow!("invalid response: {}", status_line.trim()));
                }
                assert_eq!(message_number, arg_message_number);
                assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                let new_nbytes;
                if let Some(info) = unique_id_to_message_info.get(unique_id) {
                    new_nbytes = nbytes + info.fubaco_headers.len();
                } else {
                    new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
                }
                response_lines.clear();
                response_lines.extend(format!("+OK {} {}\r\n", message_number.0, new_nbytes).into_bytes());
                println!("Done");
            }
            if command_name == "LIST" && command_arg1.is_none() {
                println!("modify multi-line response for LIST command");
                let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
                let body_text = String::from_utf8_lossy(body_u8);
                let mut buf = Vec::<u8>::with_capacity(body_u8.len());
                let mut total_nbytes = 0;
                for line in body_text.split_terminator("\r\n") {
                    if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                        let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                        let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                        assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                        let unique_id = &message_number_to_unique_id[&message_number];
                        let new_nbytes;
                        if let Some(info) = unique_id_to_message_info.get(unique_id) {
                            new_nbytes = nbytes + info.fubaco_headers.len();
                        } else {
                            new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
                        }
                        total_nbytes += new_nbytes;
                        buf.extend(format!("{} {}\r\n", message_number.0, new_nbytes).into_bytes());
                    } else {
                        return Err(anyhow!("invalid response: {}", line));
                    }
                }
                assert_eq!(total_nbytes, total_nbytes_of_modified_maildrop);

                let new_status_line;
                if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                    let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                    assert_eq!(nbytes, total_nbytes_of_maildrop);
                    assert!(nbytes <= total_nbytes);
                    assert_eq!(0, (total_nbytes - nbytes) % *FUBACO_HEADER_TOTAL_SIZE);
                    new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, format!("{} octets", total_nbytes)).to_string();
                } else {
                    new_status_line = status_line.clone();
                }

                response_lines.clear();
                response_lines.extend(new_status_line.into_bytes());
                response_lines.extend(buf);
                response_lines.extend(".\r\n".as_bytes());
                println!("Done");
            }
            if command_name == "RETR" || command_name == "TOP" {
                println!("modify response body for RETR/TOP command");
                let arg_message_number = MessageNumber(u32::from_str_radix(&command_arg1.clone().unwrap(), 10).unwrap());
                let unique_id;
                if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
                    unique_id = v;
                } else {
                    return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
                }
                let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];

                let fubaco_headers;
                if let Some(info) = unique_id_to_message_info.get(unique_id) {
                    if command_name == "RETR" {
                        assert_eq!(body_u8.len(), message_number_to_nbytes[&arg_message_number]);
                    }
                    fubaco_headers = info.fubaco_headers.clone();
                } else {
                    // TODO: SPAM checker
                    fubaco_headers = crate::make_fubaco_headers(body_u8)?;
                    println!("add fubaco headers:\n----------\n{}----------", fubaco_headers);
                    unique_id_to_message_info.insert(
                        unique_id.clone(),
                        MessageInfo {
                            unique_id: unique_id.clone(),
                            fubaco_headers: fubaco_headers.clone(),
                            is_deleted: false,
                        },
                    );
                };

                let mut buf = Vec::<u8>::new();
                buf.extend(fubaco_headers.as_bytes());
                buf.extend(body_u8.iter());

                let new_status_line;
                if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                    let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                    assert_eq!(nbytes, body_u8.len());
                    let new_nbytes = nbytes + fubaco_headers.len();
                    new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, format!("{} octets", new_nbytes)).to_string();
                } else {
                    new_status_line = status_line.clone();
                }

                response_lines.clear();
                response_lines.extend(new_status_line.into_bytes());
                response_lines.extend(buf);
                response_lines.extend(".\r\n".as_bytes());
                println!("Done");
            }
            if command_name == "STAT" {
                println!("modify single-line response for STAT command");
                let num_of_messages;
                let nbytes;
                if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                    num_of_messages = usize::from_str_radix(&caps[1], 10).unwrap();
                    nbytes = usize::from_str_radix(&caps[2], 10).unwrap();
                } else {
                    return Err(anyhow!("invalid response: {}", status_line.trim()));
                }
                assert_eq!(num_of_messages, message_number_to_nbytes.len());
                assert_eq!(nbytes, total_nbytes_of_maildrop);
                response_lines.clear();
                response_lines.extend(format!("+OK {} {}\r\n", num_of_messages, total_nbytes_of_modified_maildrop).into_bytes());
                println!("Done");
            }
        }
        println!("relay the response: {}", status_line.trim());
        downstream_stream.write_all_and_flush(&response_lines)?;
        println!("Done");
        if command_name == "QUIT" {
            println!("close POP3 stream");
            upstream_stream.disconnect()?;
            downstream_stream.disconnect()?;
            println!("POP3 streams are closed"); // both streams were automatically closed by QUIT command
            break;
        }
    }

    Ok(())
}