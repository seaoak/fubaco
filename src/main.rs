use std::env;
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use native_tls::TlsConnector;
use regex::Regex;

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

lazy_static!{
    static ref REGEX_POP3_COMMAND_LINE_FOR_MULTI_LINE_RESPONSE: Regex = Regex::new(r"^(LIST|UIDL|RETR +\S+|TOP +\S+( +\S+)?)\s*\r\n$").unwrap();
    static ref REGEX_POP3_COMMAND_LINE_FOR_QUIT: Regex = Regex::new(r"^QUIT\s*\r\n$").unwrap();
}

#[allow(unused)]
fn test_pop3_bridge() -> Result<()> {
    let upstream_hostname = env::var("FUBACO_Km2TTTAEMErD_H").unwrap();
    let upstream_port = 995;

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

                println!("open upstream connection");
                let upstream_connector = TlsConnector::new()?;
                let upstream_tcp_stream = TcpStream::connect((upstream_hostname.to_string(), upstream_port))?;
                let upstream_tls_stream = upstream_connector.connect(&upstream_hostname, upstream_tcp_stream)?;
                let mut upstream_stream = MyTextLineStream::connect(upstream_tls_stream);

                // wait for POP3 greeting message from server
                {
                    let mut response = Vec::<u8>::new();
                    if let Err(e) = upstream_stream.read_some_lines(&mut response) {
                        if let Err(e2) = downstream_stream.disconnect() {
                            return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                        }
                        return Err(e);
                    }
                    println!("relay greeting message");
                    if let Err(e) = downstream_stream.write_all_and_flush(&response) {
                        if let Err(e2) = upstream_stream.disconnect() {
                            return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                        }
                        return Err(e);
                    }
                    println!("Done");
                }

                // relay POP3 commands/responses
                loop {
                    let is_multi_line_response_expected;
                    let is_last_command;
                    { // relay a POP3 command
                        let mut command_line = Vec::<u8>::new();
                        if let Err(e) = downstream_stream.read_some_lines(&mut command_line) {
                            if let Err(e2) = upstream_stream.disconnect() {
                                return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                            }
                            return Err(e);
                        }
                        let command_str = String::from_utf8_lossy(&command_line);
                        println!("relay POP3 command: {}", command_str);
                        if let Err(e) = upstream_stream.write_all_and_flush(&command_line) {
                            if let Err(e2) = downstream_stream.disconnect() {
                                return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                            }
                            return Err(e);
                        }
                        println!("Done");
                        is_multi_line_response_expected = REGEX_POP3_COMMAND_LINE_FOR_MULTI_LINE_RESPONSE.is_match(&command_str);
                        is_last_command = REGEX_POP3_COMMAND_LINE_FOR_QUIT.is_match(&command_str);
                    }

                    let mut response_lines = Vec::<u8>::new();
                    let mut is_first_response = true;
                    let mut status_line = "".to_string(); // dummy initialization (must be set to a string before use)
                    loop { // receive lines until the end of a response
                        if let Err(e) = upstream_stream.read_some_lines(&mut response_lines) {
                            if let Err(e2) = downstream_stream.disconnect() {
                                return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                            }
                            return Err(e);
                        }
                        if (is_first_response) {
                            status_line = MyTextLineStream::<TcpStream>::take_first_line(&response_lines)?;
                        }
                        if !is_multi_line_response_expected {
                            println!("relay single-line response: {}", status_line);
                            break;
                        }
                        if is_first_response && status_line.starts_with("-ERR") {
                            println!("relay ERR response: {}", status_line);
                            break;
                        }
                        if MyTextLineStream::<TcpStream>::ends_with_u8(&response_lines, b"\r\n.\r\n") {
                            println!("relay multl-line response ({} byte body): {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line);
                            break;
                        }
                        is_first_response = false;
                    }
                    if let Err(e) = downstream_stream.write_all_and_flush(&response_lines) {
                        if let Err(e2) = upstream_stream.disconnect() {
                            return Err(anyhow!("DOUBLE FAILURE!\nError1: {:?}\nError2: {:?}", e, e2));
                        }
                        return Err(e);
                    }
                    println!("Done");
                    if is_last_command {
                        println!("close POP3 stream");
                        upstream_stream.disconnect()?;
                        downstream_stream.disconnect()?;
                        break;
                    }
                }
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
