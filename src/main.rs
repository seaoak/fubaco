use std::env;
use std::io::{Read, Write, ErrorKind};
use std::net::{ToSocketAddrs, TcpStream};

use anyhow::{anyhow, Result};
use native_tls::{TlsConnector, TlsStream};
use regex::Regex;

#[macro_use]
extern crate lazy_static;

const ALMOST_MAX_LINE_LENGTH: usize = 1024;
const ASCII_CODE_CR: u8 = b'\r'; // 0x0d "Carriage Return"
const ASCII_CODE_LF: u8 = b'\n'; // 0x0a "Line Feed"

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE: Regex = Regex::new(r"^[A-Z]+( \S+)?\r\n$").unwrap(); // "message-number" is decimal and greater than 0 (RFC1939)
}

//====================================================================
fn main() {
    println!("Hello, world!");

    match test_pop3() {
        Ok(()) => (),
        Err(e) => panic!("{}", e),
    };
}

fn test_pop3() -> Result<()> {
    let username = env::var("FUBACO_Nq2DYd4cFHGZ_U").unwrap();
    let password = env::var("FUBACO_AhCE3FNtfdJV_P").unwrap();
    let hostname = env::var("FUBACO_Km2TTTAEMErD_H").unwrap();
    let port = 995;

    println!("open connection");
	let mut pop3_stream = POP3Stream::connect((hostname.to_string(), port), &hostname)?;

    println!("wait for greeting response");
    let mut buf = Vec::<u8>::new();
    pop3_stream.read_single_line_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") { // greeting message
        println!("detect OK response as greeting message: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect negative greeting message: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) as greeting message: {}", &response);
    }

    println!("issue USER command");
    let mut buf = Vec::<u8>::new();
    pop3_stream.write_command(&format!("USER {}\r\n", &username))?;
    pop3_stream.read_single_line_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") {
        println!("detect OK response for USER command: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect ERR response for USER command: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) for USER command: {}", &response);
    }

    println!("issue PASS command");
    let mut buf = Vec::<u8>::new();
    pop3_stream.write_command(&format!("PASS {}\r\n", &password))?;
    pop3_stream.read_single_line_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") {
        println!("detect OK response for PASS command: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect ERR response for PASS command: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) for PASS command: {}", &response);
    }

    println!("issue STAT command");
    let mut buf = Vec::<u8>::new();
    pop3_stream.write_command(&format!("STAT\r\n"))?;
    pop3_stream.read_single_line_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") {
        println!("detect OK response for STAT command: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect ERR response for STAT command: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) for STAT command: {}", &response);
    }

    println!("issue LIST command");
    let mut buf = Vec::<u8>::new();
    pop3_stream.write_command(&format!("LIST\r\n"))?;
    pop3_stream.read_multi_lines_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") {
        println!("detect OK response for LIST command: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect ERR response for LIST command: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) for LIST command: {}", &response);
    }

    println!("issue QUIT command");
    let mut buf = Vec::<u8>::new();
    pop3_stream.write_command("QUIT\r\n")?;
    pop3_stream.read_single_line_response(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    if starts_with_u8(&buf, b"+OK ") || starts_with_u8(&buf, b"+OK\r\n") {
        println!("detect OK response for QUIT command: {}", &response);
    } else if starts_with_u8(&buf, b"-ERR ") || starts_with_u8(&buf, b"-ERR\r\n") {
        return Err(anyhow!("detect ERR response for QUIT command: {}", &response));
    } else {
        panic!("detect invalid response (neither +OK nor -ERR) for QUIT command: {}", &response);
    }

    println!("closing connection...");
    pop3_stream.shutdown()?;
    println!("connection is successfully closed");

    Ok(())
}

//====================================================================
#[derive(Debug)]
struct POP3Stream<S: Read + Write> {
    stream: S,
    is_in_transaction: bool, // a TRANSACTION is from authentication to QUIT command
}

impl POP3Stream<TlsStream<TcpStream>> {

    fn connect<A:ToSocketAddrs>(addr: A, server_fqdn: &str) -> Result<POP3Stream<TlsStream<TcpStream>>> {
        let connector = TlsConnector::new()?;
        let tcp_stream = TcpStream::connect(addr)?;
        let tls_stream = connector.connect(server_fqdn, tcp_stream)?;
        Ok(POP3Stream {
            stream: tls_stream,
            is_in_transaction: false,
        })
    }

    fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown()?;
        Ok(())
    }
}

impl<S: Read + Write> POP3Stream<S> {
    fn read_single_line_response(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        assert_eq!(buf.len(), 0);
        self.read_some_lines(buf)?;
        assert!(!buf[0..buf.len() - 2].contains(&ASCII_CODE_CR));
        assert!(!buf[0..buf.len() - 2].contains(&ASCII_CODE_LF));
        Ok(())
    }

    fn read_multi_lines_response(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        assert_eq!(buf.len(), 0);
        let mut is_ok_response = false;
        loop {
            self.read_some_lines(buf)?;
            if !is_ok_response {
                is_ok_response = starts_with_u8(buf, b"+OK ") || starts_with_u8(buf, b"+OK\r\n");
                if !is_ok_response {
                    return Ok(());
                }
            }
            if ends_with_u8(buf, b"\r\n.\r\n") {
                break;
            }
        }
    Ok(())
    }

    fn read_some_lines(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        // NOTE: buf might contain some elements already
        // NOTE: this function may read multple lines at once
        let mut local_buf = [0u8; ALMOST_MAX_LINE_LENGTH];
        loop {
            let nbytes = match self.stream.read(&mut local_buf) {
                Ok(0) => return Err(anyhow!("TLS connection is closed unexpectedly")),
                Ok(len) => len,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow!(e)),
            };
            buf.extend(&local_buf[0..nbytes]);
            if ends_with_u8(buf, b"\r\n") { // allow empty line
                break;
            }
        }
        Ok(())
    }

    fn write_command(&mut self, text: &str) -> Result<()> {
        assert!(REGEX_POP3_COMMAND_LINE.is_match(text));
        self.stream.write_all(text.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }
}

//====================================================================
fn starts_with_u8(target: &[u8], pattern: &[u8]) -> bool {
    if target.len() < pattern.len() {
        return false;
    }
    for i in 0..pattern.len() {
        if target[i] != pattern[i] {
            return false;
        }
    }
    true
}

fn ends_with_u8(target: &[u8], pattern: &[u8]) -> bool {
    if target.len() < pattern.len() {
        return false;
    }
    for i in 1..=pattern.len() {
        if target[target.len() - i] != pattern[pattern.len() - i] {
            return false;
        }
    }
    true
}
