use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use native_tls::TlsConnector;
use regex::Regex;
use serde::{Serialize, Deserialize};

mod my_disconnect;
mod my_text_line_stream;
mod pop3_upstream;

use my_text_line_stream::MyTextLineStream;
use pop3_upstream::*;

//====================================================================
fn main() {
    println!("Hello, world!");

    match test_pop3_bridge() {
        Ok(()) => (),
        Err(e) => panic!("{:?}", e),
    };

    match test_pop3_upstream() {
        Ok(()) => (),
        Err(e) => panic!("{:?}", e),
    };
}

fn make_fubaco_padding_header(nbytes: usize) -> String { // generate just-nbyte-sized "X-Fubaco-Padding" header
    let line_length_limit = 80;
    let headding = "X-Fubaco-Padding: ".to_string();
    assert!(nbytes >= headding.len() + "x\r\n".len()); // at least one "x" is necessary
    let mut buf = format!("{}{}\r\n", headding, "x".repeat(nbytes - headding.len() - "\r\n".len())); // if line length is no limit

    // split buf into multi-line
    let mut pos = line_length_limit - "\r\n".len();
    while pos <= buf.len() - "\r\n x\r\n".len() {
        buf.replace_range(pos..(pos + "\r\n ".len()), "\r\n ");
        pos += line_length_limit;
    }
    assert!(buf.ends_with("x\r\n")); // at least one "x" is contained in last line
    buf
}

lazy_static!{
    static ref REGEX_POP3_COMMAND_LINE_FOR_MULTI_LINE_RESPONSE: Regex = Regex::new(r"^(LIST|UIDL|RETR +\S+|TOP +\S+ +\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_LIST_SINGLE: Regex = Regex::new(r"^LIST +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_LIST_ALL: Regex = Regex::new(r"^LIST *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_RETR: Regex = Regex::new(r"^RETR *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_TOP: Regex = Regex::new(r"^TOP +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_STAT: Regex = Regex::new(r"^STAT *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_QUIT: Regex = Regex::new(r"^QUIT *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_USER: Regex = Regex::new(r"^USER +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND: Regex = Regex::new(r"^ *(\S+) +(\S+) *$").unwrap(); // "\r\n" is stripped
    static ref REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS: Regex = Regex::new(r"\b([1-9][0-9]*) octets\b").unwrap();
    static ref DATABASE_FILENAME: String = "./db.json".to_string();
    static ref FUBACO_HEADER_TOTAL_SIZE: usize = 512; // (78+2)*6+(30+2)
}

#[allow(unused)]
fn test_pop3_bridge() -> Result<()> {

    #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash,Serialize,Deserialize)]
    struct Username(String);

    #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
    struct Hostname(String);

    #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash,Serialize,Deserialize)]
    struct UniqueID(String);

    #[derive(Clone,Debug,Serialize,Deserialize)]
    struct MailInfo {
        username: Username,
        unique_id: UniqueID,
        original_size: usize,
        modified_size: usize,
        inserted_headers: String,
        is_deleted: bool,
    }

    #[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
    struct MessageNumber(u32);

    let username_to_hostname: HashMap<Username, Hostname> = vec![
        "FUBACO_Nq2DYd4cFHGZ_U",
        "FUBACO_Km2TTTAEMErD_H",

        "FUBACO_NC7s2kMrxDnU_U",
        "FUBACO_Fzkd5hfaTv6D_H",

        "FUBACO_SiwDkj2vtpqH_U",
        "FUBACO_MFhg2T3pxVRW_H",

        "FUBACO_GYDTwK7YTcbU_U",
        "FUBACO_QW5DV9Wko6oC_H",

    ].into_iter().map(|s| env::var(s).unwrap()).collect::<Vec<String>>().chunks(2).map(|v| (Username(v[0].clone()), Hostname(v[1].clone()))).collect();

    fn load_db_file() -> Result<String> {
        let f = File::open(&*DATABASE_FILENAME)?;
        let mut reader = BufReader::new(f);
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn save_db_file(s: &str) -> Result<()> {
        let f = File::open(&*DATABASE_FILENAME)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(s.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    // https://serde.rs/derive.html
    let mut database: HashMap<Username, HashMap<UniqueID, MailInfo>> = serde_json::from_str(&load_db_file()?).unwrap(); // permanent table (save and load a DB file)
    let lack_keys: Vec<Username> = username_to_hostname.keys().filter(|u| !database.contains_key(u)).map(|u| u.clone()).collect();
    lack_keys.into_iter().for_each(|u| {
        database.insert(u, HashMap::new());
    });

    // https://doc.rust-lang.org/std/net/struct.TcpListener.html
    let downstream_port = 5940;
    let downstream_addr = format!("{}:{}", "127.0.0.1", downstream_port);
    let listener = TcpListener::bind(downstream_addr)?;
    loop {
        match listener.accept() {
            Ok((downstream_tcp_stream, remote_addr)) => {

                // https://doc.rust-lang.org/std/net/enum.SocketAddr.html#method.ip
                assert_eq!(remote_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

                let mut downstream_stream = MyTextLineStream::connect(downstream_tcp_stream);

                // send dummy greeting message to client (upstream is not opened yet)
                println!("send dummy greeting message to downstream");
                downstream_stream.write_all_and_flush(b"+OK Greeting\r\n")?;

                // wait for "USER" command to identify mail account
                let username;
                let upstream_hostname;
                let upstream_port = 995;
                {
                    let mut command_line = Vec::<u8>::new();
                    downstream_stream.read_some_lines(&mut command_line)?;
                    let command_str = String::from_utf8_lossy(&command_line);
                    match REGEX_POP3_COMMAND_LINE_FOR_USER.captures(&command_str) {
                        Some(caps) => username = Username(caps.get(1).unwrap().as_str().to_string()),
                        None => return Err(anyhow!("The first POP3 command should be \"USER\", but: {}", command_str)),
                    }
                    match username_to_hostname.get(&username) {
                        Some(h) => upstream_hostname = h.clone(),
                        None => return Err(anyhow!("FATAL: unknown username: {:?}", username)),
                    }
                }
                println!("username: {}", username.0);
                println!("upstream_addr: {}:{}", upstream_hostname.0, upstream_port);

                println!("open upstream connection");
                let upstream_connector = TlsConnector::new()?;
                let upstream_tcp_stream = TcpStream::connect(format!("{}:{}", upstream_hostname.0, upstream_port))?;
                let upstream_tls_stream = upstream_connector.connect(&upstream_hostname.0, upstream_tcp_stream)?;
                let mut upstream_stream = MyTextLineStream::connect(upstream_tls_stream);

                // wait for POP3 greeting message from server
                {
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("greeting message is received: {}", status_line);
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: invalid greeting message is received: {}", status_line));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // issue delayed "USER" command
                {
                    println!("issue USER command");
                    let mut command_line = format!("USER {}\r\n", username.0).into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for USER command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("relay the response: {}", status_line);
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for USER command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // relay "PASS" command
                {
                    let mut command_line = Vec::<u8>::new();
                    downstream_stream.read_some_lines(&mut command_line)?;
                    let command_str = String::from_utf8_lossy(&command_line);
                    println!("relay POP3 command: {}", command_str);
                    if !command_str.starts_with("PASS ") {
                        return Err(anyhow!("2nd command should be \"PASS\" command, but: {}", command_str));
                    }
                    upstream_stream.write_all_and_flush(&command_line)?;
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("relay the response: {}", status_line);
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for PASS command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // issue internal "UIDL" command (to get unique-id for all mails)
                let message_number_to_unique_id;
                {
                    println!("issue internal UIDL command");
                    let mut command_line = format!("UIDL\r\n").into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for UIDL command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("the response for UIDL command is received: {}", status_line);
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for UIDL command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                    println!("parse response body of UIDL command");
                    let body_u8 = &response_lines[status_line.len() .. (response_lines.len() - b".\r\n".len())];
                    let body_text = String::from_utf8_lossy(body_u8);
                    let mut table: HashMap<MessageNumber, UniqueID> = HashMap::new();
                    for line in body_text.split_terminator("\r\n") {
                        if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                            let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                            let unique_id = UniqueID(caps.get(2).unwrap().as_str().into());
                            let is_already_exists = table.insert(message_number, unique_id).is_some();
                            assert!(!is_already_exists);
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
                    let mut command_line = format!("LIST\r\n").into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    println!("wait the response for LIST command");
                    let mut response_lines = Vec::<u8>::new();
                    upstream_stream.read_some_lines(&mut response_lines)?;
                    let status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                    println!("the response for UIDL command is received: {}", status_line);
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for LIST command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                    println!("parse response body of LIST command");
                    let body_u8 = &response_lines[status_line.len() .. (response_lines.len() - b".\r\n".len())];
                    let body_text = String::from_utf8_lossy(body_u8);
                    let mut table: HashMap<MessageNumber, usize> = HashMap::new();
                    for line in body_text.split_terminator("\r\n") {
                        if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                            let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                            let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                            let is_already_exists = table.insert(message_number, nbytes).is_some();
                            assert!(!is_already_exists);
                        } else {
                            return Err(anyhow!("invalid response: {}", line));
                        }
                    }
                    message_number_to_nbytes = table;
                    println!("Done");
                }

                let mut unique_id_to_mail_info = database.get(&username).unwrap(); // borrow mutable ref
                let is_new_mail: HashMap<MessageNumber, bool> = message_number_to_unique_id.iter().map(|(message_number, unique_id)| (message_number.clone(), !unique_id_to_mail_info.contains_key(unique_id))).collect();
                let total_nbytes_of_maildrop = message_number_to_nbytes.values().fold(0, |acc, nbytes| acc + nbytes);
                let total_nbytes_of_modified_maildrop = message_number_to_unique_id.iter().map(|(message_number, unique_id)| {
                    if is_new_mail[message_number] {
                        message_number_to_nbytes[message_number] + *FUBACO_HEADER_TOTAL_SIZE
                    } else {
                        unique_id_to_mail_info[unique_id].modified_size
                    }
                }).fold(0, |acc, nbytes| acc + nbytes);

                // relay POP3 commands/responses
                loop {
                    let is_multi_line_response_expected;
                    let is_list_single_command;
                    let is_list_all_command;
                    let is_retr_command;
                    let is_top_command;
                    let is_stat_command;
                    let is_last_command;
                    { // relay a POP3 command
                        let mut command_line = Vec::<u8>::new();
                        downstream_stream.read_some_lines(&mut command_line)?;
                        let command_str = String::from_utf8_lossy(&command_line);
                        println!("relay POP3 command: {}", command_str);
                        upstream_stream.write_all_and_flush(&command_line)?;
                        println!("Done");
                        is_multi_line_response_expected = REGEX_POP3_COMMAND_LINE_FOR_MULTI_LINE_RESPONSE.is_match(&command_str);
                        is_list_single_command = REGEX_POP3_COMMAND_LINE_FOR_LIST_SINGLE.is_match(&command_str);
                        is_list_all_command = REGEX_POP3_COMMAND_LINE_FOR_LIST_ALL.is_match(&command_str);
                        is_retr_command = REGEX_POP3_COMMAND_LINE_FOR_RETR.is_match(&command_str);
                        is_top_command = REGEX_POP3_COMMAND_LINE_FOR_TOP.is_match(&command_str);
                        is_stat_command = REGEX_POP3_COMMAND_LINE_FOR_STAT.is_match(&command_str);
                        is_last_command = REGEX_POP3_COMMAND_LINE_FOR_QUIT.is_match(&command_str);
                    }

                    let mut response_lines = Vec::<u8>::new();
                    let mut is_first_response = true;
                    let mut status_line = "".to_string(); // dummy initialization (must be set to a string before use)
                    loop { // receive lines until the end of a response
                        upstream_stream.read_some_lines(&mut response_lines)?;
                        if (is_first_response) {
                            status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                        }
                        if is_first_response && status_line.starts_with("-ERR") {
                            println!("ERR response is received: {}", status_line);
                            break;
                        }
                        assert!(is_first_response && status_line.starts_with("+OK"));
                        if !is_multi_line_response_expected {
                            println!("single-line response is received: {}", status_line);
                            break;
                        }
                        if MyTextLineStream::<TcpStream>::ends_with_u8(&response_lines, b"\r\n.\r\n") {
                            println!("multl-line response ({} byte body) is received: {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line);
                            break;
                        }
                        is_first_response = false;
                    }
                    if status_line.starts_with("+OK") {
                        if is_list_single_command {
                            println!("modify single-line response for LIST command");
                            let message_number;
                            let nbytes;
                            if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                                message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().as_str(), 10).unwrap());
                                nbytes = usize::from_str_radix(caps.get(2).unwrap().as_str(), 10).unwrap();
                            } else {
                                return Err(anyhow!("invalid response: {}", status_line));
                            }
                            assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                            let new_nbytes = nbytes + if is_new_mail[&message_number] { *FUBACO_HEADER_TOTAL_SIZE } else { 0 };
                            response_lines.clear();
                            response_lines.extend(format!("+OK {} {}\r\n", message_number.0, new_nbytes).into_bytes());
                            println!("Done");
                        }
                        if is_list_all_command {
                            println!("modify multi-line response for LIST command");
                            let body_u8 = &response_lines[status_line.len() .. (response_lines.len() - b".\r\n".len())];
                            let body_text = String::from_utf8_lossy(body_u8);
                            let mut buf = Vec::<u8>::with_capacity(body_u8.len());
                            let mut total_nbytes = 0;
                            for line in body_text.split_terminator("\r\n") {
                                if let Some(caps) = REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND.captures(line) {
                                    let message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().into(), 10).unwrap());
                                    let nbytes = usize::from_str_radix(caps.get(2).unwrap().into(), 10).unwrap();
                                    assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                                    let new_nbytes = nbytes + if is_new_mail[&message_number] { *FUBACO_HEADER_TOTAL_SIZE } else { 0 };
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
                        if is_retr_command || is_top_command {
                            println!("modify response body for RETR/TOP command");
                            let body_u8 = &response_lines[status_line.len() .. (response_lines.len() - b".\r\n".len())];
                            let fubaco_headers = make_fubaco_padding_header(*FUBACO_HEADER_TOTAL_SIZE);

                            let mut buf = Vec::<u8>::with_capacity(body_u8.len() + *FUBACO_HEADER_TOTAL_SIZE);
                            buf.extend(fubaco_headers.into_bytes());
                            buf.extend(body_u8);

                            let new_status_line;
                            if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                                let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                                let new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
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
                        if is_stat_command {
                            println!("modify single-line response for STAT command");
                            let num_of_mails;
                            let nbytes;
                            if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                                num_of_mails = usize::from_str_radix(&caps[1], 10).unwrap();
                                nbytes = usize::from_str_radix(&caps[2], 10).unwrap();
                            } else {
                                return Err(anyhow!("invalid response: {}", status_line));
                            }
                            assert_eq!(num_of_mails, message_number_to_nbytes.len());
                            assert_eq!(nbytes, total_nbytes_of_maildrop);
                            response_lines.clear();
                            response_lines.extend(format!("+OK {} {}\r\n", num_of_mails, total_nbytes_of_modified_maildrop).into_bytes());
                            println!("Done");
                        }
                    }
                    println!("relay the response: {}", status_line);
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    println!("Done");
                    if is_last_command {
                        println!("close POP3 stream");
                        upstream_stream.disconnect()?;
                        downstream_stream.disconnect()?;
                        break;
                    }
                }

                // https://serde.rs/derive.html
                save_db_file(&serde_json::to_string(&database).unwrap())?;
            },
            Err(e) => return Err(anyhow!(e)),
        }
    }
}

#[allow(unused)]
fn test_pop3_upstream() -> Result<()> {
    let username = env::var("FUBACO_Nq2DYd4cFHGZ_U").unwrap();
    let password = env::var("FUBACO_AhCE3FNtfdJV_P").unwrap();
    let hostname = env::var("FUBACO_Km2TTTAEMErD_H").unwrap();
    let port = 995;

    println!("open upstream connection");
    let connector = TlsConnector::new()?;
    let tcp_stream = TcpStream::connect((hostname.to_string(), port))?;
    let tls_stream = connector.connect(&hostname, tcp_stream)?;

    let mut pop3_upstream = POP3Upstream::connect(tls_stream)?;

    println!("wait for greeting response");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_GREETING, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue USER command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_USER, Some(username))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue PASS command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_PASS, Some(password))?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue STAT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_STAT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("issue LIST command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_LIST_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_size_list: Vec<usize> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap()).map(|s| s.parse::<usize>().unwrap()).collect();
    println!("DEBUG: mail_size_list = {:?}\n", mail_size_list);

    println!("issue UIDL command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_UIDL_ALL, None)?;
    let (_, body) = match response {
        POP3Response::OkSingleLine(status) => panic!("BUG: unexpected single-line response: {}", status),
        POP3Response::OkMultiLine(status, body) => {
            println!("detect OK response: {}{}", status, String::from_utf8_lossy(&body));
            (status, body)
        },
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    };
    let mail_uid_list: Vec<String> = String::from_utf8_lossy(&body).lines().map(|line| line.split_whitespace().nth(1).unwrap().to_string()).collect();
    println!("DEBUG: mail_uid_list = {:?}\n", mail_uid_list);

    assert_eq!(mail_size_list.len(), mail_uid_list.len());
    let mail_list: Vec<(usize, String)> = mail_size_list.into_iter().zip(mail_uid_list.into_iter()).collect();
    println!("DEBUG: mail_list = {:?}\n", mail_list);

    println!("issue QUIT command");
    let response = pop3_upstream.exec_command(&POP3_COMMAND_QUIT, None)?;
    match response {
        POP3Response::OkSingleLine(status) => println!("detect OK response: {}", status),
        POP3Response::OkMultiLine(status, body) => panic!("BUG: unexpected multi-line response: {}{}", status, String::from_utf8_lossy(&body)),
        POP3Response::Err(status) => panic!("FATAL: detect -ERR response: {}", status),
    }

    println!("closing connection...");
    pop3_upstream.disconnect()?;
    println!("connection is successfully closed");

    Ok(())
}
