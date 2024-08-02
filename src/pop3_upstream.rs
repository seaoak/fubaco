use std::io::{Read, Write, ErrorKind};
use std::net::{ToSocketAddrs, TcpStream};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use native_tls::{TlsConnector, TlsStream};
use regex::Regex;

const ALMOST_MAX_LINE_LENGTH: usize = 1024;
const ASCII_CODE_CR: u8 = b'\r'; // 0x0d "Carriage Return"
const ASCII_CODE_LF: u8 = b'\n'; // 0x0a "Line Feed"

lazy_static! {
    static ref REGEX_POP3_COMMAND_LINE: Regex = Regex::new(r"^[A-Z]+( \S+)?\r\n$").unwrap(); // "message-number" is decimal and greater than 0 (RFC1939)
    static ref REGEX_POP3_OK_RESPONSE: Regex = Regex::new(r"^\+OK( \S[^\r\n]*)?\r\n$").unwrap();
    static ref REGEX_POP3_ERR_RESPONSE: Regex = Regex::new(r"^-ERR( \S[^\r\n]*)?\r\n$").unwrap();
}

//====================================================================
#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(non_camel_case_types)]
enum POP3State {
    GREETING,
    AUTHORIZATION_0,
    AUTHORIZATION_1,
    TRANSACTION,
    UPDATE,
}

impl std::fmt::Display for POP3State {
    fn fmt(&self, dest: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(dest, "{:?}", self)
    }
}

//====================================================================
#[derive(Debug)]
pub struct POP3Command {
    command_text: String,
    arg_regex: Option<Regex>,
    has_multi_line_response: bool,
    expected_state: POP3State,
    next_state: POP3State,
}

lazy_static! {
    pub static ref POP3_COMMAND_GREETING: POP3Command = POP3Command {
        command_text: "".to_string(), // this is not a command (only response for connecting)
        arg_regex: None,
        has_multi_line_response: false,
        expected_state: POP3State::GREETING,
        next_state: POP3State::AUTHORIZATION_0,
    };
    pub static ref POP3_COMMAND_QUIT: POP3Command = POP3Command {
        command_text: "QUIT".to_string(),
        arg_regex: None,
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::UPDATE,
    };
    pub static ref POP3_COMMAND_STAT: POP3Command = POP3Command {
        command_text: "STAT".to_string(),
        arg_regex: None,
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
    pub static ref POP3_COMMAND_LIST_ALL: POP3Command = POP3Command {
        command_text: "LIST".to_string(),
        arg_regex: None,
        has_multi_line_response: true,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
	pub static ref POP3_COMMAND_LIST_ONE: POP3Command = POP3Command {
        command_text: "LIST".to_string(),
        arg_regex: Some(Regex::new(r"^[1-9][0-9]*$").unwrap()), // "message-number" is decimal and greater than 0 (RFC1939)
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
	pub static ref POP3_COMMAND_RETR: POP3Command = POP3Command {
        command_text: "RETR".to_string(),
        arg_regex: Some(Regex::new(r"^[1-9][0-9]*$").unwrap()), // "message-number" is decimal and greater than 0 (RFC1939)
        has_multi_line_response: true,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
	pub static ref POP3_COMMAND_DELE: POP3Command = POP3Command {
        command_text: "DELE".to_string(),
        arg_regex: Some(Regex::new(r"^[1-9][0-9]*$").unwrap()), // "message-number" is decimal and greater than 0 (RFC1939)
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
    pub static ref POP3_COMMAND_NOOP: POP3Command = POP3Command {
        command_text: "NOOP".to_string(),
        arg_regex: None,
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
    pub static ref POP3_COMMAND_RSET: POP3Command = POP3Command {
        command_text: "RSET".to_string(),
        arg_regex: None,
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
    pub static ref POP3_COMMAND_TOP: POP3Command = POP3Command {
        command_text: "TOP".to_string(),
        arg_regex: Some(Regex::new(r"^[1-9][0-9]* [1-9][0-9]*$").unwrap()), // "message-number" is decimal and greater than 0 (RFC1939)
        has_multi_line_response: true,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
    pub static ref POP3_COMMAND_UIDL_ALL: POP3Command = POP3Command {
        command_text: "UIDL".to_string(),
        arg_regex: None,
        has_multi_line_response: true,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
	pub static ref POP3_COMMAND_UIDL_ONE: POP3Command = POP3Command {
        command_text: "UIDL".to_string(),
        arg_regex: Some(Regex::new(r"^[1-9][0-9]*$").unwrap()), // "message-number" is decimal and greater than 0 (RFC1939)
        has_multi_line_response: false,
        expected_state: POP3State::TRANSACTION,
        next_state: POP3State::TRANSACTION,
    };
	pub static ref POP3_COMMAND_USER: POP3Command = POP3Command {
        command_text: "USER".to_string(),
        arg_regex: Some(Regex::new(r"^\S+$").unwrap()),
        has_multi_line_response: false,
        expected_state: POP3State::AUTHORIZATION_0,
        next_state: POP3State::AUTHORIZATION_1,
    };
	pub static ref POP3_COMMAND_PASS: POP3Command = POP3Command {
        command_text: "PASS".to_string(),
        arg_regex: Some(Regex::new(r"^\S+$").unwrap()),
        has_multi_line_response: false,
        expected_state: POP3State::AUTHORIZATION_1,
        next_state: POP3State::TRANSACTION,
    };
}

//====================================================================
#[derive(Debug)]
pub enum POP3Response { // String includes CRLF at the end
    OkSingleLine(String),
    OkMultiLine(String, Vec<u8>), // "status" and "body" (not include the last line ".\r\n")
    Err(String),
}

//====================================================================
#[derive(Debug)]
pub struct POP3Upstream<S: Read + Write> {
    stream: S,
    state: POP3State,
}

impl POP3Upstream<TlsStream<TcpStream>> {

    pub fn connect<A:ToSocketAddrs>(addr: A, server_fqdn: &str) -> Result<POP3Upstream<TlsStream<TcpStream>>> {
        let connector = TlsConnector::new()?;
        let tcp_stream = TcpStream::connect(addr)?;
        let tls_stream = connector.connect(server_fqdn, tcp_stream)?;
        Ok(POP3Upstream {
            stream: tls_stream,
            state: POP3State::GREETING,
        })
    }

    pub fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown()?;
        Ok(())
    }
}

impl<S: Read + Write> POP3Upstream<S> {

    pub fn exec_command(&mut self, command: &POP3Command, args: Option<String>) -> Result<POP3Response> {
        if let Some(regex) = &command.arg_regex {
            if let Some(args_text) = &args {
                assert!(regex.is_match(args_text));
            } else {
                assert!(false);
            }
        } else {
            assert!(args.is_none());
        }

        if command.expected_state != self.state {
            return Err(anyhow!("FATAL: can not exec {} command in {} state", command.command_text, self.state));
        }

        if command.command_text.len() == 0 { // Greeting
            assert!(command.arg_regex.is_none());
            assert!(args.is_none());
            // do nothing
        } else if let Some(args_text) = &args {
            self.write_command(&format!("{} {}\r\n", command.command_text, args_text))?;
        } else {
            self.write_command(&format!("{}\r\n", command.command_text))?;
        }

        let mut buf = Vec::<u8>::new();
        if command.has_multi_line_response {
            self.read_multi_line_response(&mut buf)?;
        } else {
            self.read_single_line_response(&mut buf)?;
        }
        let first_line = take_first_line(&buf)?;
        if REGEX_POP3_ERR_RESPONSE.is_match(&first_line) {
            if buf.len() > first_line.len() {
                return Err(anyhow!("detect invalid -ERR response (not single line): {}", String::from_utf8_lossy(&buf)));
            }
            return Ok(POP3Response::Err(first_line));
        } else if REGEX_POP3_OK_RESPONSE.is_match(&first_line) {
            self.state = command.next_state;
            if command.has_multi_line_response {
                assert!(ends_with_u8(&buf, b"\r\n.\r\n"));
                let body_length = buf.len() - first_line.len() - b".\r\n".len(); // may be zero
                let body = Vec::from_iter(buf.into_iter().skip(first_line.len()).take(body_length));
                return Ok(POP3Response::OkMultiLine(first_line, body));
            } else {
                if buf.len() > first_line.len() {
                    return Err(anyhow!("detect invalid +OK response (not single line): {}", String::from_utf8_lossy(&buf)));
                }
                return Ok(POP3Response::OkSingleLine(first_line));
            }
        } else {
            return Err(anyhow!("detect invalid response (neither +OK nor -ERR): {}", String::from_utf8_lossy(&buf)));
        }
    }

    //-----------------------------------------------------------------------------
    fn read_single_line_response(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        assert_eq!(buf.len(), 0);
        self.read_some_lines(buf)?;
        assert!(!buf[0..buf.len() - 2].contains(&ASCII_CODE_CR));
        assert!(!buf[0..buf.len() - 2].contains(&ASCII_CODE_LF));
        Ok(())
    }

    fn read_multi_line_response(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        assert_eq!(buf.len(), 0);
        let mut is_ok_response = false;
        loop {
            self.read_some_lines(buf)?;
            if !is_ok_response {
                is_ok_response = starts_with_u8(buf, b"+OK ") || starts_with_u8(buf, b"+OK\r\n");
                if !is_ok_response {
                    if starts_with_u8(buf, b"-ERR ") || starts_with_u8(buf, b"-ERR\r\n") {
                        return Ok(());
                    }
                    return Err(anyhow!("detect invalid response (neither +OK nor -ERR): {}", String::from_utf8_lossy(buf)));
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

fn take_first_line(target: &[u8]) -> Result<String> { // return value includes CRLF
    let pos_of_first_crlf = target.iter().position(|c| *c == ASCII_CODE_CR);
    if let Some(pos) = pos_of_first_crlf {
        if target.len() < pos + 2 || target[pos + 1] != ASCII_CODE_LF {
            return Err(anyhow!("detect CR character without following LF character: {}", String::from_utf8_lossy(target)));
        }
        let mut buf = Vec::<u8>::with_capacity(pos + 2);
        buf.extend(target[0..pos + 2].iter());
        let first_line = String::from_utf8_lossy(&buf).to_string();
        return Ok(first_line);
    }
    Err(anyhow!("detect lack of CRLF: {}", String::from_utf8_lossy(target)))
}
