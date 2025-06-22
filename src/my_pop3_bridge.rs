use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::my_disconnect::MyDisconnect;
use crate::my_dns_resolver::MyDNSResolver;
use crate::my_fubaco_header::{self, FUBACO_HEADER_TOTAL_SIZE};
use crate::my_logger::prelude::*;
use crate::my_text_line_stream::MyTextLineStream;

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE_GENERAL: Regex = Regex::new(r"^([A-Z]+)(?: +(\S+)(?: +(\S+))?)? *\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_USER: Regex = Regex::new(r"^USER +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *\r\n$").unwrap();
    static ref REGEX_POP3_RESPONSE_BODY_FOR_LISTING_COMMAND: Regex = Regex::new(r"^ *(\S+) +(\S+) *$").unwrap(); // "\r\n" is stripped
    static ref REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS: Regex = Regex::new(r"\b([1-9][0-9]*) octets\b").unwrap();
    static ref DATABASE_FILENAME: String = "./db.json".to_string();
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct Username(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Hostname(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
struct UniqueID(String);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct MessageNumber(u32);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageInfo {
    unique_id: UniqueID,
    fubaco_headers: String,
    is_deleted: bool,
}

fn read_one_response_completely<S>(upstream_stream: &mut MyTextLineStream<S>, is_multi_line_response_expected: bool) -> Result<(String, Vec<u8>)>
    where S: Read + Write + MyDisconnect
{
    let mut response_lines = Vec::<u8>::new();
    let mut is_first_response = true;
    let mut status_line = "".to_string(); // dummy initialization (must be set to a string before use)
    loop { // receive lines until the end of a response
        upstream_stream.read_some_lines(&mut response_lines)?;
        if is_first_response {
            status_line = MyTextLineStream::<S>::take_first_line(&response_lines)?;
        }
        if status_line.starts_with("-ERR") {
            info!("ERR response is received: {}", status_line.trim());
            break;
        }
        assert!(status_line.starts_with("+OK"));
        if !is_multi_line_response_expected {
            info!("single-line response is received: {}", status_line.trim());
            break;
        }
        if MyTextLineStream::<S>::ends_with_u8(&response_lines, b"\r\n.\r\n") {
            info!("multl-line response ({} byte body) is received: {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line.trim());
            break;
        }
        is_first_response = false;
    }

    Ok((status_line, response_lines))
}

fn parse_multi_line_response<S>(response_lines: &[u8]) -> Result<Vec<(MessageNumber, String)>>
    where S: Read + Write + MyDisconnect
{
    let status_line = MyTextLineStream::<S>::take_first_line(response_lines)?;
    assert!(status_line.starts_with("+OK"));
    assert!(MyTextLineStream::<S>::ends_with_u8(response_lines, b"\r\n.\r\n"));

    let body_u8 = &response_lines[status_line.len()..(response_lines.len() - b".\r\n".len())];
    let body_text = String::from_utf8_lossy(body_u8);
    trace!("{}", body_text);

    let mut table = HashSet::new();
    let mut list = Vec::new();
    for line in body_text.split_terminator("\r\n") {
        let line = line.trim();
        let (index, value) = if let Some(t) = line.split_once(' ') {
            t
        } else {
            return Err(anyhow!("invalid entry in multi-line response (one whitespace should be contained): \"{}\"", line));
        };
        let message_number = if let Ok(n) = u32::from_str_radix(index, 10) {
            MessageNumber(n)
        } else {
            return Err(anyhow!("invalid entry in multi-line response (first element should be integer): \"{}\"", line));
        };
        if table.contains(&message_number) {
            return Err(anyhow!("ivalid entry in multi-line response (a message number occurs multiple times: \"{}\"", line));
        }
        table.insert(message_number.clone());
        let value = value.trim();
        list.push((message_number, value.to_string()));
    }
    Ok(list)
}

fn parse_response_for_uidl_command<S>(response_lines: &[u8]) -> Result<Vec<(MessageNumber, UniqueID)>>
    where S: Read + Write + MyDisconnect
{
    let list = parse_multi_line_response::<S>(response_lines)?;
    let list = list.into_iter().map(|(n, s)| (n, UniqueID(s))).collect();
    Ok(list)
}

fn parse_response_for_list_command<S>(response_lines: &[u8]) -> Result<Vec<(MessageNumber, usize)>>
    where S: Read + Write + MyDisconnect
{
    fn convert_an_entry(tupple: (MessageNumber, String)) -> Option<(MessageNumber, usize)> {
        let (n, s) = tupple;
        if let Ok(i) = usize::from_str_radix(&s, 10) {
            Some((n, i))
        } else {
            None
        }
    }

    let list = parse_multi_line_response::<S>(response_lines)?;
    let num_of_entries = list.len();
    let list: Vec<(MessageNumber, usize)> = list.into_iter().filter_map(|t| convert_an_entry(t)).collect();
    if list.len() != num_of_entries {
        return Err(anyhow!("invalid entry in multi-line response for LIST command: some entries have non-integer value"));
    }
    Ok(list)
}

fn process_pop3_transaction<S, T>(
    upstream_stream: &mut MyTextLineStream<S>,
    downstream_stream: &mut MyTextLineStream<T>,
    database: &mut HashMap<UniqueID, MessageInfo>,
    resolver: &MyDNSResolver,
) -> Result<()>
    where S: Read + Write + MyDisconnect,
          T: Read + Write + MyDisconnect,
{
    let unique_id_to_message_info = database;

    // issue internal "UIDL" command (to get unique-id for all mails)
    let message_number_to_unique_id;
    {
        info!("issue internal UIDL command");
        let command_line = format!("UIDL\r\n").into_bytes();
        upstream_stream.write_all_and_flush(&command_line)?;
        info!("wait the response for UIDL command");
        let (status_line, response_lines) = read_one_response_completely(upstream_stream, true)?;
        info!("the response for UIDL command is received: {}", status_line.trim());
        if status_line.starts_with("-ERR") {
            return Err(anyhow!("FATAL: ERR response is received for UIDL command"));
        }
        assert!(status_line.starts_with("+OK"));
        info!("parse response body of UIDL command");
        let list = parse_response_for_uidl_command::<S>(&response_lines)?;
        message_number_to_unique_id = list.into_iter().collect::<HashMap<MessageNumber, UniqueID>>();
        info!("Done");
    }

    // issue internal "LIST" command (to get message size for all mails)
    let message_number_to_nbytes;
    {
        info!("issue internal LIST command");
        let command_line = format!("LIST\r\n").into_bytes();
        upstream_stream.write_all_and_flush(&command_line)?;
        info!("wait the response for LIST command");
        let (status_line, response_lines) = read_one_response_completely(upstream_stream, true)?;
        info!("the response for UIDL command is received: {}", status_line.trim());
        if status_line.starts_with("-ERR") {
            return Err(anyhow!("FATAL: ERR response is received for LIST command"));
        }
        assert!(status_line.starts_with("+OK"));
        info!("parse response body of LIST command");
        let list = parse_response_for_list_command::<S>(&response_lines)?;
        message_number_to_nbytes = list.into_iter().collect::<HashMap<MessageNumber, usize>>();
        info!("Done");
    }
    assert_eq!(message_number_to_nbytes.len(), message_number_to_unique_id.len());

    if unique_id_to_message_info.len() == 0 { // at the first time only, all existed massages are treated as old messages which have no fubaco header
        for unique_id in message_number_to_unique_id.values() {
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
    info!("{} messages exist in database", unique_id_to_message_info.len());

    let total_nbytes_of_original_maildrop = message_number_to_nbytes.values().fold(0, |acc, nbytes| acc + nbytes);
    info!("total_nbytes_of_original_maildrop = {}", total_nbytes_of_original_maildrop);
    let total_nbytes_of_modified_maildrop = message_number_to_unique_id
        .iter()
        .map(|(message_number, unique_id)| {
            if !message_number_to_nbytes.contains_key(message_number) {
                unreachable!("BUG: invalid MessageNumber: {:?}", message_number);
            }
            if let Some(info) = unique_id_to_message_info.get(unique_id) {
                message_number_to_nbytes[message_number] + info.fubaco_headers.len()
            } else {
                message_number_to_nbytes[message_number] + *FUBACO_HEADER_TOTAL_SIZE
            }
        })
        .fold(0, |acc, nbytes| acc + nbytes);
    info!("total_nbytes_of_modified_maildrop = {}", total_nbytes_of_modified_maildrop);

    // relay POP3 commands/responses
    loop {
        let command_name;
        let command_arg1;
        let is_multi_line_response_expected;
        { // relay a POP3 command
            let mut command_line = Vec::<u8>::new();
            downstream_stream.read_some_lines(&mut command_line)?;
            let command_str = String::from_utf8_lossy(&command_line);
            info!("relay POP3 command: {}", command_str.trim());
            upstream_stream.write_all_and_flush(&command_line)?;
            info!("Done");

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

        let (status_line, mut response_lines) = read_one_response_completely(upstream_stream, is_multi_line_response_expected)?;
        if status_line.starts_with("+OK") {
            // modify response
            if command_name == "LIST" && command_arg1.is_some() {
                info!("modify single-line response for LIST command");
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
                info!("Done");
            }
            if command_name == "LIST" && command_arg1.is_none() {
                info!("modify multi-line response for LIST command");
                let original_list = parse_response_for_list_command::<S>(&response_lines)?;
                let modified_list = original_list.into_iter().map(|(message_number, nbytes)| {
                    assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
                    let unique_id = &message_number_to_unique_id[&message_number];
                    let new_nbytes;
                    if let Some(info) = unique_id_to_message_info.get(unique_id) {
                        new_nbytes = nbytes + info.fubaco_headers.len();
                    } else {
                        new_nbytes = nbytes + *FUBACO_HEADER_TOTAL_SIZE;
                    }
                    (message_number, new_nbytes)
                });
                let modified_body_u8 = modified_list.flat_map(|(message_number, nbytes)| {
                    format!("{} {}\r\n", message_number.0, nbytes).into_bytes()
                });

                let new_status_line;
                if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&status_line) {
                    let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
                    assert_eq!(nbytes, total_nbytes_of_original_maildrop);
                    assert!(nbytes <= total_nbytes_of_modified_maildrop);
                    assert_eq!(0, (total_nbytes_of_modified_maildrop - nbytes) % *FUBACO_HEADER_TOTAL_SIZE);
                    let new_field = format!("{} octets", total_nbytes_of_modified_maildrop);
                    new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, new_field).to_string();
                } else {
                    new_status_line = status_line.clone();
                }

                response_lines.clear();
                response_lines.extend(new_status_line.into_bytes());
                response_lines.extend(modified_body_u8);
                response_lines.extend(".\r\n".as_bytes());
                info!("Done");
            }
            if command_name == "RETR" || command_name == "TOP" {
                info!("modify response body for RETR/TOP command");
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
                        if body_u8.len() != message_number_to_nbytes[&arg_message_number] {
                            warn!("WARNING: message size is different from the response of LIST comand: {} vs {}", body_u8.len(), message_number_to_nbytes[&arg_message_number]);
                        }
                    }
                    fubaco_headers = info.fubaco_headers.clone();
                } else {
                    // TODO: SPAM checker
                    fubaco_headers = my_fubaco_header::make_fubaco_headers(body_u8, resolver)?;
                    info!("add fubaco headers:\n----------\n{}----------", fubaco_headers);
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
                    if nbytes != body_u8.len() {
                        print!("WARNING: message size is different from the \"{} octets\" in staus line: {}", nbytes, body_u8.len());
                    }
                    let new_nbytes = nbytes + fubaco_headers.len();
                    new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&status_line, format!("{} octets", new_nbytes)).to_string();
                } else {
                    new_status_line = status_line.clone();
                }

                response_lines.clear();
                response_lines.extend(new_status_line.into_bytes());
                response_lines.extend(buf);
                response_lines.extend(".\r\n".as_bytes());
                info!("Done");
            }
            if command_name == "STAT" {
                info!("modify single-line response for STAT command");
                let num_of_messages;
                let nbytes;
                if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&status_line) {
                    num_of_messages = usize::from_str_radix(&caps[1], 10).unwrap();
                    nbytes = usize::from_str_radix(&caps[2], 10).unwrap();
                } else {
                    return Err(anyhow!("invalid response: {}", status_line.trim()));
                }
                assert_eq!(num_of_messages, message_number_to_nbytes.len());
                assert_eq!(nbytes, total_nbytes_of_original_maildrop);
                response_lines.clear();
                response_lines.extend(format!("+OK {} {}\r\n", num_of_messages, total_nbytes_of_modified_maildrop).into_bytes());
                info!("Done");
            }
        }
        info!("relay the response: {}", status_line.trim());
        downstream_stream.write_all_and_flush(&response_lines)?;
        info!("Done");
        if command_name == "QUIT" {
            info!("close POP3 stream");
            upstream_stream.disconnect()?;
            downstream_stream.disconnect()?;
            info!("POP3 streams are closed"); // both streams were automatically closed by QUIT command
            break;
        }
    }

    Ok(())
}

pub fn run_pop3_bridge(resolver: &MyDNSResolver) -> Result<()> {
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
        if !Path::new(&*DATABASE_FILENAME).try_exists()? {
            return Ok("{}".to_string());
        }
        let f = File::open(&*DATABASE_FILENAME)?;
        let mut reader = BufReader::new(f);
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        Ok(buf)
    }

    fn save_db_file(s: &str) -> Result<()> {
        let f = File::create(&*DATABASE_FILENAME)?;
        let mut writer = BufWriter::new(f);
        writer.write_all(s.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    // https://serde.rs/derive.html
    let mut database: HashMap<Username, HashMap<UniqueID, MessageInfo>> = serde_json::from_str(&load_db_file()?).unwrap(); // permanent table (save and load a DB file)
    let lack_keys: Vec<Username> = username_to_hostname.keys().filter(|u| !database.contains_key(u)).map(|u| u.clone()).collect();
    lack_keys.into_iter().for_each(|u| {
        database.insert(u, HashMap::new());
    });

    // https://doc.rust-lang.org/std/net/struct.TcpListener.html
    let downstream_port = 5940;
    let downstream_addr = format!("{}:{}", "127.0.0.1", downstream_port);
    let listener = TcpListener::bind(downstream_addr)?;
    loop {
        info!("wait for new connection on port {}...", downstream_port);
        match listener.accept() {
            Ok((downstream_tcp_stream, remote_addr)) => {
                // https://doc.rust-lang.org/std/net/enum.SocketAddr.html#method.ip
                assert_eq!(remote_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

                let mut downstream_stream = MyTextLineStream::connect(downstream_tcp_stream);

                // clear DNS cache at the start of a POP3 transaction
                resolver.clear_cache();

                // send dummy greeting message to client (upstream is not opened yet)
                info!("send dummy greeting message to downstream");
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
                        None => return Err(anyhow!("The first POP3 command should be \"USER\", but: {}", command_str.trim())),
                    }
                    match username_to_hostname.get(&username) {
                        Some(h) => upstream_hostname = h.clone(),
                        None => return Err(anyhow!("FATAL: unknown username: {:?}", username)),
                    }
                }
                info!("username: {}", username.0);
                info!("upstream_addr: {}:{}", upstream_hostname.0, upstream_port);

                info!("open upstream connection");
                let tls_root_store = if false {
                    // use "rustls-native-certs" crate
                    let mut roots = rustls::RootCertStore::empty();
                    for cert in rustls_native_certs::load_native_certs()? {
                        roots.add(cert).unwrap();
                    }
                    roots
                } else {
                    // use "webpki-roots" crate
                    rustls::RootCertStore::from_iter(
                        webpki_roots::TLS_SERVER_ROOTS
                            .iter()
                            .cloned(),
                    )
                };
                let tls_config =
                    Arc::new(
                        rustls::ClientConfig::builder()
                            .with_root_certificates(tls_root_store)
                            .with_no_client_auth(),
                    );
                let upstream_host = upstream_hostname.0.clone().try_into().unwrap();
                let mut upstream_tls_connection = rustls::ClientConnection::new(tls_config, upstream_host)?;
                let mut upstream_tcp_socket = TcpStream::connect(format!("{}:{}", upstream_hostname.0, upstream_port))?;
                let upstream_tls_stream = rustls::Stream::new(&mut upstream_tls_connection, &mut upstream_tcp_socket);
                let mut upstream_stream = MyTextLineStream::connect(upstream_tls_stream);

                // wait for POP3 greeting message from server
                {
                    let (status_line, response_lines) = read_one_response_completely(&mut upstream_stream, false)?;
                    assert_eq!(status_line.len(), response_lines.len());
                    info!("greeting message is received: {}", status_line.trim());
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: invalid greeting message is received: {}", status_line.trim()));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                // issue delayed "USER" command
                {
                    info!("issue USER command");
                    let command_line = format!("USER {}\r\n", username.0).into_bytes();
                    upstream_stream.write_all_and_flush(&command_line)?;
                    info!("wait the response for USER command");
                    let (status_line, response_lines) = read_one_response_completely(&mut upstream_stream, false)?;
                    assert_eq!(status_line.len(), response_lines.len());
                    info!("relay the response: {}", status_line.trim());
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    info!("Done");
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
                    info!("relay POP3 command: {}", command_str.trim());
                    if !command_str.starts_with("PASS ") {
                        return Err(anyhow!("2nd command should be \"PASS\" command, but: {}", command_str.trim()));
                    }
                    upstream_stream.write_all_and_flush(&command_line)?;
                    let (status_line, response_lines) = read_one_response_completely(&mut upstream_stream, false)?;
                    assert_eq!(status_line.len(), response_lines.len());
                    info!("relay the response: {}", status_line.trim());
                    downstream_stream.write_all_and_flush(&response_lines)?;
                    info!("Done");
                    if status_line.starts_with("-ERR") {
                        return Err(anyhow!("FATAL: ERR response is received for PASS command"));
                    }
                    assert!(status_line.starts_with("+OK"));
                }

                process_pop3_transaction(&mut upstream_stream, &mut downstream_stream, database.get_mut(&username).unwrap(), resolver)?;

                // https://serde.rs/derive.html
                save_db_file(&serde_json::to_string(&database).unwrap())?;
            },
            Err(e) => return Err(anyhow!(e)),
        }
    }
}
