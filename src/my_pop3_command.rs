use std::str::FromStr;

use anyhow::{anyhow, Result};
use strum::{Display, EnumString};

use crate::my_text_line_stream::take_first_line;

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, EnumString)]
pub enum MyPop3CommandName {
    // https://datatracker.ietf.org/doc/html/rfc1939
    APOP,
    DELE,
    LIST,
    NOOP,
    PASS,
    QUIT,
    RETR,
    RSET,
    STAT,
    TOP,
    UIDL,
    USER,
}

impl MyPop3CommandName {
    pub fn range_of_number_of_arguments(&self) -> std::ops::RangeInclusive<usize> {
        match self {
            // https://datatracker.ietf.org/doc/html/rfc1939
            Self::APOP => 2..=2,
            Self::DELE => 1..=1,
            Self::LIST => 0..=1, // argument is optional
            Self::NOOP => 0..=0,
            Self::PASS => 1..=1,
            Self::QUIT => 0..=0,
            Self::RETR => 1..=1,
            Self::RSET => 0..=0,
            Self::STAT => 0..=0,
            Self::TOP  => 2..=2,
            Self::UIDL => 0..=1, // argument is optional
            Self::USER => 1..=1,
        }
    }

    pub fn is_well_formed_arguments(&self, args: &[String]) -> bool {
        fn validator_for_any(ss: &str) -> bool {
            ss.chars().all(|c| c.is_ascii() && !c.is_ascii_whitespace() && !c.is_ascii_control())
        }

        fn validator_for_digest(ss: &str) -> bool {
            // "MD5 digest string" in RFC1939
            ss.chars().all(|c| c.is_ascii_hexdigit())
        }

        fn validator_for_message_number(ss: &str) -> bool {
            // an integer of base-10 (i.e. decimal), starting with `1`
            // NOTE: to avoid DoS, assume `u32`.
            match u32::from_str_radix(ss, 10) {
                Err(_) => false,
                Ok(0) => false,
                Ok(_) => true,
            }
        }

        fn validator_for_non_negative_integer(ss: &str) -> bool {
            // "a non-negative number of lines" in RFC1939
            // NOTE: to avoid DoS, assume `u32`.
            u32::from_str_radix(ss, 10).is_ok()
        }

        let validators: &[_] = match self {
            Self::APOP => &[validator_for_any, validator_for_digest],
            Self::DELE => &[validator_for_message_number],
            Self::LIST => &[validator_for_message_number],
            Self::NOOP => &[],
            Self::PASS => &[validator_for_any],
            Self::QUIT => &[],
            Self::RETR => &[validator_for_message_number],
            Self::RSET => &[],
            Self::STAT => &[],
            Self::TOP  => &[validator_for_message_number, validator_for_non_negative_integer],
            Self::UIDL => &[validator_for_message_number],
            Self::USER => &[validator_for_any],
        };
        assert_eq!(&validators.len(), self.range_of_number_of_arguments().end());

        assert!(args.iter().all(|arg| !arg.is_empty()));
        assert!(self.range_of_number_of_arguments().contains(&args.len()));
        validators.into_iter().zip(args).all(|(pred, ss)| pred(ss))
    }
}

//====================================================================
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MyPop3Command {
    name: MyPop3CommandName,
    args: Vec<String>,
}

impl std::str::FromStr for MyPop3Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = if s.ends_with("\r\n") {
            &s[0..(s.len() - 2)]
        } else {
            s
        };
        if s.is_empty() {
            return Err(anyhow!("invalid command line: should not be empty"));
        }
        if !s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            return Err(anyhow!("invalid codepoint in POP3 command line: {:?}", s));
        }
        let mut it = s.trim_ascii().split_ascii_whitespace();
        let s0 = it.next().ok_or_else(|| anyhow!("empty argument: {:?}", s))?;
        let name = MyPop3CommandName::from_str(s0).or_else(|_| Err(anyhow!("invalid command name: {:?}", s)))?;
        let args = it.map(String::from).collect::<Vec<_>>();
        if !name.range_of_number_of_arguments().contains(&args.len()) {
            return Err(anyhow!("too few/many arguments: {:?} / {:?} / {:?}", s, name, args));
        }
        if !name.is_well_formed_arguments(args.as_ref()) {
            return Err(anyhow!("{} command is not well-formed: {:?} / {:?}", name, args, s));
        }
        Ok(Self { name, args })
    }
}

impl TryFrom<&[u8]> for MyPop3Command {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let raw_u8 = value;
        match String::from_utf8(Vec::from(raw_u8)) {
            Ok(ss) => Self::from_str(&ss), // delegate
            Err(_) => Err(anyhow!("invalid byte sequence (not UTF-8) in command line: {:?}", raw_u8)),
        }
    }
}

impl MyPop3Command {
    pub fn new(name: MyPop3CommandName, args: &[&str]) -> Self {
        let it0 = [name.to_string()].into_iter();
        let it1 = args.into_iter().map(|s| s.to_string());
        let fields = it0.chain(it1).collect::<Vec<_>>();
        let command_line = format!("{}\r\n", fields.join(" "));
        Self::from_str(&command_line).unwrap() // delegate for validation
    }

    pub fn name(&self) -> MyPop3CommandName {
        self.name
    }

    pub fn is_multi_line_response_expected(&self) -> bool {
        match (self.name, self.args.len()) {
            (MyPop3CommandName::STAT, 0) => false,
            (MyPop3CommandName::LIST, 0) => true,
            (MyPop3CommandName::LIST, 1) => false,
            (MyPop3CommandName::APOP, 2) => false,
            (MyPop3CommandName::DELE, 1) => false,
            (MyPop3CommandName::NOOP, 0) => false,
            (MyPop3CommandName::PASS, 1) => false,
            (MyPop3CommandName::QUIT, 0) => false,
            (MyPop3CommandName::RETR, 1) => true,
            (MyPop3CommandName::RSET, 0) => false,
            (MyPop3CommandName::TOP,  2) => true,
            (MyPop3CommandName::UIDL, 0) => true,
            (MyPop3CommandName::UIDL, 1) => false,
            (MyPop3CommandName::USER, 1) => false,

            (MyPop3CommandName::STAT, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::LIST, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::APOP, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::DELE, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::NOOP, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::PASS, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::QUIT, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::RETR, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::RSET, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::TOP,  _) => unreachable!("{:?}", self),
            (MyPop3CommandName::UIDL, _) => unreachable!("{:?}", self),
            (MyPop3CommandName::USER, _) => unreachable!("{:?}", self),
        }
    }

    pub fn as_nth_arg(&self, index: usize) -> Option<String> {
        assert!(self.name.range_of_number_of_arguments().contains(&(1+index)));
        self.args.get(index).map(String::to_owned)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bin = self.name.to_string().into_bytes();
        for ss in &self.args {
            bin.push(b' ');
            bin.extend_from_slice(ss.as_bytes());
        }
        bin.extend_from_slice(b"\r\n");
        bin
    }
}

//====================================================================
#[derive(Debug, PartialEq, Eq)]
pub enum MyPop3Response {
    OkSingleLine {
        status_line: String, // not include CRLF at the end
    },
    OkMultiLine {
        status_line: String, // not include CRLF at the end
        body_u8: Vec<u8>, // not include ".\r\n" at the end, but include CRLF of last line
    },
    Err {
        status_line: String, // not include CRLF at the end
    },
}

impl TryFrom<&[u8]> for MyPop3Response {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let raw_u8 = Vec::from(value);
        if raw_u8.is_empty() {
            return Err(anyhow!("invalid POP3 response: should not be empty"));
        }
        if !raw_u8.ends_with(b"\r\n") {
            return Err(anyhow!("invalid POP3 response: should be ended with CRLF: {:?}", raw_u8));
        }
        let status_line = take_first_line(&raw_u8)?.strip_suffix("\r\n").unwrap().to_owned(); // remove CRLF at the end
        if status_line.is_empty() {
            return Err(anyhow!("invalid POP3 response line: should not be empty"));
        }
        if !status_line.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            return Err(anyhow!("invalid codepoint in POP3 response line: {:?}", status_line));
        }
        let is_ok = Self::is_likely_to_be_ok(&status_line);
        let is_err = Self::is_likely_to_be_err(&status_line);
        if !(is_ok || is_err) {
            return Err(anyhow!("invalid POP3 response (neither OK nor ERR): {:?}", raw_u8));
        }
        let is_multi_line_response = status_line.len() + "\r\n".len() < raw_u8.len();
        match (is_ok, is_multi_line_response) {
            (false, false) => Ok(Self::Err { status_line }),
            (false, true) => Err(anyhow!("invalid POP3 response (ERR response should be single-line response): {:?}", raw_u8)),
            (true, false) => Ok(Self::OkSingleLine { status_line }),
            (true, true) => {
                let body_u8 = extract_body_u8(&raw_u8, &status_line)?;
                Ok(Self::OkMultiLine { status_line, body_u8 })
            },
        }
    }
}

impl MyPop3Response {
    // static utility function (to encapsulate the pattern "+OK")
    pub fn is_likely_to_be_ok(ss: &str) -> bool {
        assert!(!ss.is_empty());
        let status_line = ss.split_terminator("\r\n").nth(0).unwrap();
        status_line == "+OK" || status_line.starts_with("+OK ")
    }

    // static utility function (to encapsulate the pattern "-ERR")
    pub fn is_likely_to_be_err(ss: &str) -> bool {
        assert!(!ss.is_empty());
        let status_line = ss.split_terminator("\r\n").nth(0).unwrap();
        status_line == "-ERR" || status_line.starts_with("-ERR ")
    }

    pub fn is_ok(&self) -> bool {
        match self {
            Self::OkSingleLine { .. } => true,
            Self::OkMultiLine { .. } => true,
            Self::Err { .. } => false,
        }
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    pub fn is_multi_line_response(&self) -> bool {
        match self {
            Self::OkSingleLine { .. } => false,
            Self::OkMultiLine { .. } => true,
            Self::Err { .. } => false,
        }
    }

    pub fn status_line(&self) -> String {
        let ss = match self {
            Self::OkSingleLine { status_line, .. } => status_line,
            Self::OkMultiLine { status_line, .. } => status_line,
            Self::Err { status_line, .. } => status_line,
        };
        assert!(!ss.ends_with("\r\n")); // not include CRLF at the end
        ss.clone()
    }

    pub fn as_body_u8(&self) -> Option<&[u8]> {
        match self {
            Self::OkSingleLine { .. } => None,
            Self::OkMultiLine { body_u8, .. } => Some(body_u8),
            Self::Err { .. } => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bin = self.status_line().into_bytes();
        assert!(!bin.ends_with(b"\r\n"));
        bin.extend_from_slice(b"\r\n");
        if let Some(body_u8) = self.as_body_u8() {
            assert!(body_u8.is_empty() || body_u8.ends_with(b"\r\n"));
            bin.extend_from_slice(body_u8);
            bin.extend_from_slice(b".\r\n");
        }
        bin
    }
}

fn extract_body_u8(raw_u8: &[u8], status_line: &str) -> Result<Vec<u8>> {
    let status_line = status_line.trim_end_matches("\r\n"); // remove CRLF if exists

    assert!(status_line.len() + "\r\n".len() < raw_u8.len());
    assert!(raw_u8.starts_with(format!("{}\r\n", status_line).as_bytes()));

    let expected_tail = b"\r\n.\r\n";
    let bin = &raw_u8[status_line.len()..];
    let actual_tail = &bin[bin.len().saturating_sub(expected_tail.len())..];
    if actual_tail != expected_tail {
        return Err(anyhow!("invalid POP3 response (multi-line response should be ends with {:?}), but {:?}", expected_tail, actual_tail));
    }
    let body_u8 = Vec::from(&raw_u8[(status_line.len() + "\r\n".len())..(raw_u8.len() - b".\r\n".len())]); // may be emtpty
    Ok(body_u8)
}

#[test]
fn test_001_extract_body_u8() {
    assert_eq!(b"", extract_body_u8(b"+OK\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"", extract_body_u8(b"+OK\r\n.\r\n", "+OK\r\n").unwrap().as_array().unwrap());
    assert_eq!(b"\r\n", extract_body_u8(b"+OK\r\n\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a\r\n", extract_body_u8(b"+OK\r\na\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a b c\r\n", extract_body_u8(b"+OK\r\na b c\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a b c\r\n\r\nd e f\r\n\r\n", extract_body_u8(b"+OK\r\na b c\r\n\r\nd e f\r\n\r\n.\r\n", "+OK").unwrap().as_array().unwrap());

    assert!(extract_body_u8(b"+OK\r\n\r\n", "+OK").is_err());
}

#[test]
#[allow(non_snake_case)]
fn test_001_MyPop3Response_try_from() {
    let status_line = "+OK".to_string();
    let raw_u8 = format!("{}\r\n", status_line);
    assert_eq!(MyPop3Response::OkSingleLine { status_line }, MyPop3Response::try_from(raw_u8.as_bytes()).unwrap());

    let status_line = "+OK ".to_string();
    let raw_u8 = format!("{}\r\n", status_line);
    assert_eq!(MyPop3Response::OkSingleLine { status_line }, MyPop3Response::try_from(raw_u8.as_bytes()).unwrap());

    let status_line = "+OK 123".to_string();
    let raw_u8 = format!("{}\r\n", status_line);
    assert_eq!(MyPop3Response::OkSingleLine { status_line }, MyPop3Response::try_from(raw_u8.as_bytes()).unwrap());

    let status_line = "-ERR".to_string();
    let raw_u8 = format!("{}\r\n", status_line);
    assert_eq!(MyPop3Response::Err { status_line }, MyPop3Response::try_from(raw_u8.as_bytes()).unwrap());

    let status_line = "-ERR foo bar".to_string();
    let raw_u8 = format!("{}\r\n", status_line);
    assert_eq!(MyPop3Response::Err { status_line }, MyPop3Response::try_from(raw_u8.as_bytes()).unwrap());

    // multi-line response with empty body
    let status_line = "+OK".to_string();
    let body_u8 = "".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&body_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, body_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // multi-line response with a body of one line
    let status_line = "+OK".to_string();
    let body_u8 = "foo bar\r\n".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&body_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, body_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // multi-line response with a body of three lines
    let status_line = "+OK".to_string();
    let body_u8 = "foo bar\r\n\r\nbuz\r\n".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&body_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, body_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // ERR response can not have a body
    let status_line = "-ERR".to_string();
    let raw_u8 = format!("{}\r\n.\r\n", status_line);
    assert!(MyPop3Response::try_from(raw_u8.as_bytes()).is_err());
}
