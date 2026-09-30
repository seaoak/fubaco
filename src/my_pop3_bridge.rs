use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use crate::my_disconnect::MyDisconnect;
use crate::my_dns_resolver::MyDNSResolver;
use crate::my_fubaco_header::{self, FUBACO_HEADER_TOTAL_SIZE};
use crate::my_logger::prelude::*;
use crate::my_pop3_command::{MyIteratorIsUnique, MyPop3Command, MyPop3CommandName, MyPop3MessageNumber, MyPop3Octets, MyPop3Response, MyPop3ScanListingItem, MyPop3UniqueID, MyPop3Username};
use crate::my_pop3_downstream::MyPop3Downstream;
use crate::my_pop3_upstream::MyPop3Upstream;

lazy_static! {
    static ref DATABASE_FILENAME: String = "./db.json".to_string();
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct Hostname(String);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MessageInfo {
    unique_id: MyPop3UniqueID,
    fubaco_headers: String,
    is_deleted: bool,
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

fn calculate_total_nbytes_of_original_maildrop(message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>) -> usize {
    message_number_to_nbytes.values().sum()
}

fn calculate_total_nbytes_of_modified_maildrop(
    message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
    message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
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
    _unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
    _message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    _message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
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
    unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::LIST);
    assert!(!command.is_multi_line_response_expected());

    info!("modify single-line response for LIST command");
    let arg_message_number = command.as_message_number().unwrap();
    let unique_id;
    if let Some(v) = message_number_to_unique_id.get(&arg_message_number) {
        unique_id = v;
    } else {
        return Err(anyhow!("unknown message number is specified: {}", &arg_message_number));
    }

    let original_item = response.parse_as_for_list_single(&command)?;
    assert_eq!(original_item.as_message_number(), arg_message_number);
    assert_eq!(original_item.as_nbytes().as_usize(), message_number_to_nbytes[original_item.as_message_number()]);

    let new_nbytes = calculate_modified_nbytes_of_message(original_item.as_nbytes().as_usize(), unique_id_to_message_info.get(unique_id));
    let new_nbytes = MyPop3Octets::from(new_nbytes);
    assert!(new_nbytes.as_usize() > 0);
    assert!(new_nbytes.as_usize() >= original_item.as_nbytes().as_usize());
    let new_item = original_item.rebuild_with_nbytes(original_item.as_message_number(), &new_nbytes);
    let modified_response = response.rebuild_as_for_list_single(&new_item, &command);
    assert_eq!(original_item, modified_response.parse_as_for_list_single(&command).unwrap());
    info!("Done");

    Ok((Some(modified_response), None))
}

fn filter_for_response_of_list_all(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::LIST);
    assert!(command.is_multi_line_response_expected());

    info!("modify multi-line response for LIST command");
    let original_list: Vec<MyPop3ScanListingItem> = response.as_contents().unwrap().to_items()?;
    assert!(original_list.iter().map(|info| info.as_message_number()).is_unique(), "{:?}", (&original_list, &response));
    let modified_list = original_list.into_iter().map(|info| {
        assert_eq!(info.as_nbytes().as_usize(), message_number_to_nbytes[info.as_message_number()]);
        let unique_id = &message_number_to_unique_id[info.as_message_number()];
        let new_nbytes = calculate_modified_nbytes_of_message(info.as_nbytes().as_usize(), unique_id_to_message_info.get(unique_id));
        info.rebuild_with_nbytes(info.as_message_number(), &new_nbytes.into())
    }).collect::<Vec<_>>();
    let modified_response = response.rebuild_as_for_list_all(&modified_list, &command);
    info!("Done");

    Ok((Some(modified_response), None))
}

fn filter_for_response_of_retr(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
    resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::RETR); // TODO: support TOP command if possible
    assert!(command.is_multi_line_response_expected());

    info!("modify response contents for RETR command");
    let message_number = command.as_message_number().unwrap();
    let unique_id = message_number_to_unique_id.get(&message_number).ok_or_else(|| anyhow!("unexpected message number: {}", &message_number))?;
    let nbytes = message_number_to_nbytes.get(&message_number).ok_or_else(|| anyhow!("unexpected message number: {}", &message_number))?;
    let contents_u8 = response.as_contents().unwrap().as_contents_u8();
    if contents_u8.len() != *nbytes {
        // NOTE: this validation is effective only for RETR command (not for TOP command)
        warn!("WARNING: message size is different from the response of LIST comand: {} vs {}", contents_u8.len(), nbytes);
    }

    let fubaco_headers;
    let new_info;
    if let Some(info) = unique_id_to_message_info.get(&unique_id) {
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

    let new_contents_u8 = [fubaco_headers.as_bytes(), contents_u8].concat();
    let modified_response = response.rebuild_as_for_retr(&new_contents_u8, &command);
    info!("Done");

    Ok((Some(modified_response), new_info))
}

fn filter_for_response_of_stat(
    response: &MyPop3Response,
    command: &MyPop3Command,
    unique_id_to_message_info: &HashMap<MyPop3UniqueID, MessageInfo>,
    message_number_to_unique_id: &HashMap<MyPop3MessageNumber, MyPop3UniqueID>,
    message_number_to_nbytes: &HashMap<MyPop3MessageNumber, usize>,
    _resolver: &MyDNSResolver,
) -> Result<(Option<MyPop3Response>, Option<MessageInfo>)> {
    assert!(response.is_ok());
    assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
    assert_eq!(command.name(), MyPop3CommandName::STAT);
    assert!(!command.is_multi_line_response_expected());

    info!("modify single-line response for STAT command");
    let (num_of_messages, nbytes) = response.parse_as_for_stat(&command)?;
    assert_eq!(num_of_messages.as_usize(), message_number_to_nbytes.len());
    assert_eq!(nbytes.as_usize(), calculate_total_nbytes_of_original_maildrop(&message_number_to_nbytes));
    let new_nbytes = calculate_total_nbytes_of_modified_maildrop(&message_number_to_nbytes, &message_number_to_unique_id, &unique_id_to_message_info);
    info!("total_nbytes_of_modified_maildrop = {}", new_nbytes);
    let new_nbytes = new_nbytes.into();
    let modified_status_line = response.as_status_line().rebuild_as_for_stat(&num_of_messages, &new_nbytes);
    let modified_response = response.rebuild(&modified_status_line, None);
    info!("Done");

    Ok((Some(modified_response), None))
}

//====================================================================
fn process_pop3_transaction<S, T>(
    upstream_stream: &mut MyPop3Upstream<S>,
    downstream_stream: &mut MyPop3Downstream<T>,
    database: &mut HashMap<MyPop3UniqueID, MessageInfo>,
    resolver: &MyDNSResolver,
) -> Result<()>
    where S: Read + Write + MyDisconnect,
          T: Read + Write + MyDisconnect,
{
    let unique_id_to_message_info = database;

    // issue internal "UIDL" command (to get unique-id for all mails)
    let message_number_to_unique_id: HashMap<MyPop3MessageNumber, MyPop3UniqueID> = {
        info!("issue internal UIDL command");
        let command = MyPop3Command::UIDL_ALL;
        let response = upstream_stream.issue_command(&command)?;
        let list = response.parse_as_for_uidl_all(&command)?;
        list.into_iter().map(|item| item.to_tuple()).collect()
    };

    // issue internal "LIST" command (to get message size for all mails)
    let message_number_to_nbytes: HashMap<MyPop3MessageNumber, usize> = {
        info!("issue internal LIST command");
        let command = MyPop3Command::LIST_ALL;
        let response = upstream_stream.issue_command(&command)?;
        let (_, _, list) = response.parse_as_for_list_all(&command)?;
        list.into_iter().map(|item| (item.as_message_number().clone(), item.as_nbytes().as_usize())).collect()
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
        info!("relay the response: {}", final_response.as_status_line());
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
    let username_to_hostname: HashMap<MyPop3Username, Hostname> = vec![
        "FUBACO_Nq2DYd4cFHGZ_U",
        "FUBACO_Km2TTTAEMErD_H",
        "FUBACO_NC7s2kMrxDnU_U",
        "FUBACO_Fzkd5hfaTv6D_H",
        "FUBACO_SiwDkj2vtpqH_U",
        "FUBACO_MFhg2T3pxVRW_H",
        "FUBACO_GYDTwK7YTcbU_U",
        "FUBACO_QW5DV9Wko6oC_H",
    ].into_iter().map(|s| env::var(s).unwrap()).collect::<Vec<String>>().chunks(2).map(|v| (MyPop3Username::from_str(&v[0]).unwrap(), Hostname(v[1].clone()))).collect();

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
    let mut database: HashMap<MyPop3Username, HashMap<MyPop3UniqueID, MessageInfo>> = serde_json::from_str(&load_db_file()?).unwrap(); // permanent table (save and load a DB file)
    let lack_keys: Vec<MyPop3Username> = username_to_hostname.keys().filter(|u| !database.contains_key(u)).map(|u| u.clone()).collect();
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
                    match command {
                        MyPop3Command::USER(x) => (x, responder),
                        _ => return Err(anyhow!("The first POP3 command should be \"USER\": {:?}", command)),
                    }
                };
                let upstream_hostname = username_to_hostname.get(&username).ok_or_else(|| anyhow!("unknown username: {:?}", username))?;
                let upstream_port = 995;

                info!("username: {}", username);
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
                    let command = MyPop3Command::USER(username.clone());
                    let response = upstream_stream.issue_command(&command)?;
                    info!("relay the response: {}", response.as_status_line());
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
                    info!("relay the response: {}", response.as_status_line());
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
