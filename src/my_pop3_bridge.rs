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
use crate::my_pop3_command::{MyPop3Command, MyPop3CommandName, MyPop3Response};
use crate::my_pop3_downstream::MyPop3Downstream;
use crate::my_pop3_upstream::MyPop3Upstream;

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE_GENERAL: Regex = Regex::new(r"^([A-Z]+)(?: +(\S+)(?: +(\S+))?)? *(\r\n)?$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_USER: Regex = Regex::new(r"^USER +(\S+) *(\r\n)?$").unwrap();
    static ref REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND: Regex = Regex::new(r"^\+OK +(\S+) +(\S+) *(\r\n)?$").unwrap();
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

//====================================================================
fn parse_multi_line_response<T, F>(contents_u8: &[u8], converter: F) -> Result<Vec<(MessageNumber, T)>>
    where F: Fn(&str) -> Option<T>,
{
    let contents_text = String::from_utf8_lossy(contents_u8);
    debug!("{}", contents_text);

    let mut table = HashSet::new();
    let mut list = Vec::new();
    for line in contents_text.split_terminator("\r\n") {
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
        let value = converter(value.trim_ascii());
        if value.is_none() {
            return Err(anyhow!("invalid value in multi-line response: \"{}\"", line));
        }
        list.push((message_number, value.unwrap()));
    }
    Ok(list)
}

fn parse_response_for_uidl_command(contents_u8: &[u8]) -> Result<Vec<(MessageNumber, UniqueID)>> {
    parse_multi_line_response(contents_u8, |s| Some(UniqueID(s.to_string())))
}

fn parse_response_for_list_command(contents_u8: &[u8]) -> Result<Vec<(MessageNumber, usize)>> {
    parse_multi_line_response(contents_u8, |s| usize::from_str_radix(s, 10).ok())
}

//====================================================================
fn issue_pop3_command_with_multi_line_response<S, T, F>(
    upstream_stream: &mut MyPop3Upstream<S>,
    command: &MyPop3Command,
    parser: F,
) -> Result<T>
    where S: Read + Write + MyDisconnect,
          F: FnOnce(&[u8]) -> Result<T>,
{
    assert!(command.is_multi_line_response_expected());
    let response = upstream_stream.issue_command(&command)?;
    if response.is_err() {
        return Err(anyhow!("FATAL: ERR response is received for {} command", command.name()));
    }
    info!("parse response contents of {} command", command.name());
    parser(response.as_contents_u8().unwrap())
}

//====================================================================
fn calculate_modified_nbytes_of_message(
    original_nbytes: usize,
    info: Option<&MessageInfo>
) -> usize {
    let nbytes_of_fubaco_header = match info {
        Some(info) => info.fubaco_headers.len(),
        None => *FUBACO_HEADER_TOTAL_SIZE,
    };
    original_nbytes + nbytes_of_fubaco_header
}

fn calculate_total_nbytes_of_original_maildrop(message_number_to_nbytes: &HashMap<MessageNumber, usize>) -> usize {
    message_number_to_nbytes.values().sum()
}

fn calculate_total_nbytes_of_modified_maildrop(
    message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
) -> usize {
    message_number_to_nbytes
        .iter()
        .map(|(message_number, original_nbytes)| {
            let unique_id = &message_number_to_unique_id[message_number];
            let info = unique_id_to_message_info.get(unique_id);
            calculate_modified_nbytes_of_message(*original_nbytes, info)
        })
        .sum()
}

//====================================================================
fn filter_for_response_of_dummy(
    response: &MyPop3Response,
    command: &MyPop3Command,
    _unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
    _message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    _message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    if response.is_ok() {
        assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    }
    Ok((None, None))
}

fn filter_for_response_of_list_single(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::LIST);
    assert!(!command.is_multi_line_response_expected());

    info!("modify single-line response for LIST command");
    let arg_str = command.as_nth_arg(0).unwrap();
    let arg_message_number = MessageNumber(u32::from_str_radix(&arg_str, 10).map_err(|_| anyhow!("argument of LIST command shoud be integer: {}", arg_str))?);
    let unique_id;
    if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
        unique_id = v;
    } else {
        return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
    }
    let message_number;
    let nbytes;
    if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&response.status_line()) {
        message_number = MessageNumber(u32::from_str_radix(caps.get(1).unwrap().as_str(), 10).unwrap());
        nbytes = usize::from_str_radix(caps.get(2).unwrap().as_str(), 10).unwrap();
    } else {
        return Err(anyhow!("invalid response: {}", response.status_line()));
    }
    assert_eq!(message_number, arg_message_number);
    assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
    let new_nbytes = calculate_modified_nbytes_of_message(nbytes, unique_id_to_message_info.get(unique_id));
    let bin = format!("+OK {} {}\r\n", message_number.0, new_nbytes).into_bytes();
    let modified_response = Some(MyPop3Response::try_from(bin.as_ref()).unwrap());
    info!("Done");

    Ok((modified_response, None))
}

fn filter_for_response_of_list_all(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::LIST);
    assert!(command.is_multi_line_response_expected());

    info!("modify multi-line response for LIST command");
    let original_list = parse_response_for_list_command(response.as_contents_u8().unwrap())?;
    let modified_list = original_list.into_iter().map(|(message_number, nbytes)| {
        assert_eq!(nbytes, message_number_to_nbytes[&message_number]);
        let unique_id = &message_number_to_unique_id[&message_number];
        let new_nbytes = calculate_modified_nbytes_of_message(nbytes, unique_id_to_message_info.get(unique_id));
        (message_number, new_nbytes)
    });
    let modified_contents_u8 = modified_list.flat_map(|(message_number, nbytes)| {
        format!("{} {}\r\n", message_number.0, nbytes).into_bytes()
    });

    let new_status_line;
    if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&response.status_line()) {
        let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
        assert_eq!(nbytes, calculate_total_nbytes_of_original_maildrop(&message_number_to_nbytes));
        let total_nbytes_of_modified_maildrop = calculate_total_nbytes_of_modified_maildrop(&message_number_to_nbytes, &message_number_to_unique_id, &unique_id_to_message_info);
        info!("total_nbytes_of_modified_maildrop = {}", total_nbytes_of_modified_maildrop);
        let new_field = format!("{} octets", total_nbytes_of_modified_maildrop);
        new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&response.status_line(), new_field).to_string();
    } else {
        new_status_line = response.status_line();
    }

    let bin = [].into_iter()
        .chain(new_status_line.trim_end_matches("\r\n").bytes())
        .chain("\r\n".bytes())
        .chain(modified_contents_u8)
        .chain(".\r\n".bytes())
        .collect::<Vec<_>>();
    let modified_response = Some(MyPop3Response::try_from(bin.as_ref()).unwrap());
    info!("Done");

    Ok((modified_response, None))
}

fn filter_for_response_of_retr(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::RETR);
    assert!(command.is_multi_line_response_expected());

    info!("modify response contents for RETR/TOP command");
    let arg_str = command.as_nth_arg(0).unwrap();
    let arg_message_number = MessageNumber(u32::from_str_radix(&arg_str, 10).map_err(|_| anyhow!("argument of RETR/TOP command shoud be integer: {}", arg_str))?);
    let unique_id;
    if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
        unique_id = v;
    } else {
        return Err(anyhow!("unknown message number is specified: {}", arg_message_number.0));
    }
    assert!(response.is_multi_line_response());
    let contents_u8 = response.as_contents_u8().unwrap();

    let fubaco_headers;
    let new_info;
    if let Some(info) = unique_id_to_message_info.get(unique_id) {
        if command.name() == MyPop3CommandName::RETR {
            if contents_u8.len() != message_number_to_nbytes[&arg_message_number] {
                warn!("WARNING: message size is different from the response of LIST comand: {} vs {}", contents_u8.len(), message_number_to_nbytes[&arg_message_number]);
            }
        }
        fubaco_headers = info.fubaco_headers.clone();
        new_info = None;
    } else {
        // TODO: SPAM checker
        fubaco_headers = my_fubaco_header::make_fubaco_headers(contents_u8, resolver)?;
        info!("add fubaco headers:\n----------\n{}----------", fubaco_headers);
        new_info = Some(MessageInfo {
            unique_id: unique_id.clone(),
            fubaco_headers: fubaco_headers.clone(),
            is_deleted: false,
        });
    };

    let new_status_line;
    if let Some(caps) = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.captures(&response.status_line()) {
        let nbytes = usize::from_str_radix(&caps[1], 10).unwrap();
        if nbytes != contents_u8.len() {
            print!("WARNING: message size is different from the \"{} octets\" in staus line: {}", nbytes, contents_u8.len());
        }
        let new_nbytes = nbytes + fubaco_headers.len();
        new_status_line = REGEX_POP3_RESPONSE_STATUS_LINE_OCTETS.replace(&response.status_line(), format!("{} octets", new_nbytes)).to_string();
    } else {
        new_status_line = response.status_line();
    }

    let bin = [].into_iter()
        .chain(new_status_line.trim_end_matches("\r\n").bytes())
        .chain("\r\n".bytes())
        .chain(fubaco_headers.bytes())
        .chain(contents_u8.to_owned())
        .chain(".\r\n".bytes())
        .collect::<Vec<_>>();
    let modified_response = Some(MyPop3Response::try_from(bin.as_ref()).unwrap());
    info!("Done");

    Ok((modified_response, new_info))
}

fn filter_for_response_of_stat(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MessageNumber, UniqueID>,
    message_number_to_nbytes: &HashMap<MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::STAT);
    assert!(!command.is_multi_line_response_expected());

    info!("modify single-line response for STAT command");
    let num_of_messages;
    let nbytes;
    if let Some(caps) = REGEX_POP3_RESPONSE_FOR_LISTING_SINGLE_COMMAND.captures(&response.status_line()) {
        num_of_messages = usize::from_str_radix(&caps[1], 10).unwrap();
        nbytes = usize::from_str_radix(&caps[2], 10).unwrap();
    } else {
        return Err(anyhow!("invalid response: {}", response.status_line()));
    }
    assert_eq!(num_of_messages, message_number_to_nbytes.len());
    assert_eq!(nbytes, calculate_total_nbytes_of_original_maildrop(&message_number_to_nbytes));
    let total_nbytes_of_modified_maildrop = calculate_total_nbytes_of_modified_maildrop(&message_number_to_nbytes, &message_number_to_unique_id, &unique_id_to_message_info);
    info!("total_nbytes_of_modified_maildrop = {}", total_nbytes_of_modified_maildrop);
    let bin = format!("+OK {} {}\r\n", num_of_messages, total_nbytes_of_modified_maildrop).into_bytes();
    let modified_response = Some(MyPop3Response::try_from(bin.as_ref()).unwrap());
    info!("Done");

    Ok((modified_response, None))
}

//====================================================================
fn process_pop3_transaction<S, T>(
    upstream_stream: &mut MyPop3Upstream<S>,
    downstream_stream: &mut MyPop3Downstream<T>,
    database: &mut HashMap<UniqueID, MessageInfo>,
    resolver: &MyDNSResolver,
) -> Result<()>
    where S: Read + Write + MyDisconnect,
          T: Read + Write + MyDisconnect,
{
    let unique_id_to_message_info = database;

    // issue internal "UIDL" command (to get unique-id for all mails)
    let message_number_to_unique_id: HashMap<MessageNumber, UniqueID> = {
        info!("issue internal UIDL command");
        let command = MyPop3Command::new(MyPop3CommandName::UIDL, &[]);
        let list = issue_pop3_command_with_multi_line_response(upstream_stream, &command, parse_response_for_uidl_command)?;
        list.into_iter().collect()
    };

    // issue internal "LIST" command (to get message size for all mails)
    let message_number_to_nbytes: HashMap<MessageNumber, usize> = {
        info!("issue internal LIST command");
        let command = MyPop3Command::new(MyPop3CommandName::LIST, &[]);
        let list = issue_pop3_command_with_multi_line_response(upstream_stream, &command, parse_response_for_list_command)?;
        list.into_iter().collect()
    };
    assert_eq!(message_number_to_nbytes.len(), message_number_to_unique_id.len());
    info!("total_nbytes_of_original_maildrop = {}", calculate_total_nbytes_of_original_maildrop(&message_number_to_nbytes));

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

    // relay POP3 commands/responses
    loop {
        let (command, responder) = downstream_stream.wait_for_command()?;
        let response = upstream_stream.issue_command(&command)?;
        if response.is_ok() {
            assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
        }

        let filter = match (response.is_ok(), command.name(), response.is_multi_line_response()) {
            (false, _, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::APOP, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::DELE, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::LIST, false) => filter_for_response_of_list_single,
            (true, MyPop3CommandName::LIST, true) => filter_for_response_of_list_all,
            (true, MyPop3CommandName::NOOP, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::PASS, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::QUIT, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::RETR, _) => filter_for_response_of_retr,
            (true, MyPop3CommandName::RSET, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::STAT, _) => filter_for_response_of_stat,
            (true, MyPop3CommandName::TOP, _) => filter_for_response_of_retr,
            (true, MyPop3CommandName::UIDL, _) => filter_for_response_of_dummy,
            (true, MyPop3CommandName::USER, _) => filter_for_response_of_dummy,
        };
        let (modified_response, new_info) = filter(&response, &command, unique_id_to_message_info, &message_number_to_unique_id, &message_number_to_nbytes, resolver)?;
        if let Some(info) = new_info {
            let ret = unique_id_to_message_info.insert(info.unique_id.clone(), info);
            assert!(ret.is_none());
        }

        let final_response = modified_response.unwrap_or(response);
        info!("relay the response: {}", final_response.status_line());
        responder.send_response(&final_response)?;
        info!("Done");
        if command.name() == MyPop3CommandName::QUIT {
            info!("close POP3 stream");
            upstream_stream.disconnect()?;
            downstream_stream.disconnect()?;
            info!("POP3 streams are closed"); // both streams were automatically closed by QUIT command
            break;
        }
    }

    Ok(())
}

//====================================================================
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

                let mut downstream_stream = MyPop3Downstream::connect(downstream_tcp_stream)?; // include sending dummy greeting message

                // clear DNS cache at the start of a POP3 transaction
                resolver.clear_cache();

                // wait for "USER" command to identify mail account
                let (username, responder_for_username) = {
                    let (command, responder) = downstream_stream.wait_for_command()?;
                    if command.name() != MyPop3CommandName::USER {
                        return Err(anyhow!("The first POP3 command should be \"USER\": {:?}", command));
                    }
                    (Username(command.as_nth_arg(0).unwrap()), responder)
                };
                let upstream_hostname = username_to_hostname.get(&username).ok_or_else(|| anyhow!("unknown username: {:?}", username))?;
                let upstream_port = 995;

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

                let mut upstream_stream = MyPop3Upstream::connect(upstream_tls_stream)?; // include waiting for greeting message from server

                // issue delayed "USER" command
                {
                    info!("issue USER command");
                    let command = MyPop3Command::new(MyPop3CommandName::USER, &[&username.0]);
                    let response = upstream_stream.issue_command(&command)?;
                    info!("relay the response: {}", response.status_line());
                    responder_for_username.send_response(&response)?;
                    info!("Done");
                    if response.is_err() {
                        return Err(anyhow!("FATAL: ERR response is received for USER command"));
                    }
                }

                // relay "PASS" command
                {
                    let (command, responder) = downstream_stream.wait_for_command()?;
                    if command.name() != MyPop3CommandName::PASS {
                        return Err(anyhow!("The second POP3 command should be \"PASS\": {:?}", command));
                    }
                    let response = upstream_stream.issue_command(&command)?;
                    info!("relay the response: {}", response.status_line());
                    responder.send_response(&response)?;
                    info!("Done");
                    if response.is_err() {
                        return Err(anyhow!("FATAL: ERR response is received for PASS command"));
                    }
                }

                process_pop3_transaction(&mut upstream_stream, &mut downstream_stream, database.get_mut(&username).unwrap(), resolver)?;

                // https://serde.rs/derive.html
                save_db_file(&serde_json::to_string(&database).unwrap())?;
            },
            Err(e) => return Err(anyhow!(e)),
        }
    }
}
