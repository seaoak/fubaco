use std::ops::RangeInclusive;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::my_text_line_stream::take_first_line;

//====================================================================
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MyPop3Username(String); // for USER command

impl std::str::FromStr for MyPop3Username {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii() && !c.is_ascii_whitespace() && !c.is_ascii_control()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for MyPop3Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3Password(String); // for PASS command

impl std::str::FromStr for MyPop3Password {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii() && !c.is_ascii_whitespace() && !c.is_ascii_control()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for MyPop3Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3Digest(String); // MD5 digest string for APOP command

impl std::str::FromStr for MyPop3Digest {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if !s.chars().all(|c| c.is_ascii() && !c.is_ascii_whitespace() && !c.is_ascii_control()) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for MyPop3Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MyPop3UniqueID(String); // for UIDL command

impl std::str::FromStr for MyPop3UniqueID {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // RFC1939 says "consisting of one to 70 characters in the range 0x21 to 0x7E"
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        if s.len() > 70 {
            return Err(anyhow!("too long unique-id: {:?}", s));
        }
        if !s.chars().map(u32::from).all(|c| 0x21 <= c && c <= 0x7e) {
            return Err(anyhow!("invalid codepoint: {:?}", s));
        }
        Ok(Self(s.to_owned()))
    }
}

impl AsRef<str> for MyPop3UniqueID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MyPop3UniqueID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3MessageNumber(u32); // for LIST command and others

impl std::str::FromStr for MyPop3MessageNumber {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // an integer of base-10 (i.e. decimal), starting with `1`
        // NOTE: to avoid DoS, assume `u32`.
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match u32::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(0) => Err(anyhow!("zero is not allowed (starting with one): {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl AsRef<u32> for MyPop3MessageNumber {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl std::fmt::Display for MyPop3MessageNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MyPop3NumberOfLines(u32); // for TOP command

impl std::str::FromStr for MyPop3NumberOfLines {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // "a non-negative number of lines" in RFC1939
        // NOTE: to avoid DoS, assume `u32`.
        if s.is_empty() {
            return Err(anyhow!("argument is empty"));
        }
        match u32::from_str_radix(s, 10) {
            Err(_) => Err(anyhow!("not unsigned integer: {:?}", s)),
            Ok(x) => Ok(Self(x)),
        }
    }
}

impl AsRef<u32> for MyPop3NumberOfLines {
    fn as_ref(&self) -> &u32 {
        &self.0
    }
}

impl std::fmt::Display for MyPop3NumberOfLines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq, Display, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum MyPop3CommandName {
    // https://datatracker.ietf.org/doc/html/rfc1939
    // RFC1939 says:
    //   - "case-insensitive keyword"
    //   - "consist of printable ASCII characters"
    // NOTE: the order of definition below is alphabetical simply.
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
    fn range_of_number_of_arguments(&self) -> RangeInclusive<usize> {
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
}

#[test]
#[allow(non_snake_case)]
fn test_001_MyPop3CommandName_from_str() {
    assert_eq!(MyPop3CommandName::LIST, "LIST".parse().unwrap());
    assert_eq!(MyPop3CommandName::LIST, "list".parse().unwrap()); // case-insensitive
    assert_eq!(MyPop3CommandName::LIST, "LiSt".parse().unwrap()); // case-insensitive
    assert!(MyPop3CommandName::from_str(" LIST").is_err()); // an extra space at the start
    assert!(MyPop3CommandName::from_str("LIS T").is_err()); // an extra space in the middle
    assert!(MyPop3CommandName::from_str("LIST ").is_err()); // an extra space at the end
}

//====================================================================
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum MyPop3Command {
    APOP(MyPop3Username, MyPop3Digest),
    DELE(MyPop3MessageNumber),
    LIST_ALL,
    LIST_SINGLE(MyPop3MessageNumber),
    NOOP,
    PASS(MyPop3Password),
    QUIT,
    RETR(MyPop3MessageNumber),
    RSET,
    STAT,
    TOP(MyPop3MessageNumber, MyPop3NumberOfLines),
    UIDL_ALL,
    UIDL_SINGLE(MyPop3MessageNumber),
    USER(MyPop3Username),
}

impl std::str::FromStr for MyPop3Command {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (keyword, args) = validate_and_parse_command_line(s)?;
        let name = MyPop3CommandName::from_str(&keyword).or_else(|e| Err(anyhow!("{:?}\n   where {:?}", e, (&keyword, &args, &s))))?;
        Self::compose(name, &args)
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
    pub fn name(&self) -> MyPop3CommandName {
        let (name, _) = self.decompose();
        name
    }

    pub fn is_multi_line_response_expected(&self) -> bool {
        match &self {
            Self::APOP(_, _)     => false,
            Self::DELE(_)        => false,
            Self::LIST_ALL       => true,
            Self::LIST_SINGLE(_) => false,
            Self::NOOP           => false,
            Self::PASS(_)        => false,
            Self::QUIT           => false,
            Self::RETR(_)        => true,
            Self::RSET           => false,
            Self::STAT           => false,
            Self::TOP(_, _)      => true,
            Self::UIDL_ALL       => true,
            Self::UIDL_SINGLE(_) => false,
            Self::USER(_)        => false,
        }
    }

    pub fn as_message_number(&self) -> Option<&MyPop3MessageNumber> {
        match &self {
            Self::APOP(_, _)     => None,
            Self::DELE(x)        => Some(x),
            Self::LIST_ALL       => None,
            Self::LIST_SINGLE(x) => Some(x),
            Self::NOOP           => None,
            Self::PASS(_)        => None,
            Self::QUIT           => None,
            Self::RETR(x)        => Some(x),
            Self::RSET           => None,
            Self::STAT           => None,
            Self::TOP(x, _)      => Some(x),
            Self::UIDL_ALL       => None,
            Self::UIDL_SINGLE(x) => Some(x),
            Self::USER(_)        => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let (name, args) = self.decompose();
        let mut bin = name.to_string().into_bytes();
        for ss in &args {
            bin.push(b' ');
            bin.extend_from_slice(ss.as_bytes());
        }
        bin.extend_from_slice(b"\r\n");
        bin
    }

    fn compose<T: AsRef<str>, U: AsRef<[T]>>(name: MyPop3CommandName, args: U) -> Result<Self> {
        let args = args.as_ref().iter().map(|s| s.as_ref().to_owned()).collect::<Vec<_>>();
        if !name.range_of_number_of_arguments().contains(&args.len()) {
            return Err(anyhow!("too few/many arguments: {:?}", (name, args)));
        }
        {   // validation
            let dummy_command_line = [name.to_string()].into_iter().chain(args.clone().into_iter()).collect::<Vec<_>>().join(" ");
            let (dummy_keyword, dummy_args) = validate_and_parse_command_line(&dummy_command_line).or_else(|e| Err(anyhow!("{:?}\n   where {:?}", e, (&name, &args))))?;
            assert_eq!(dummy_keyword.to_ascii_uppercase(), name.to_string());
            assert_eq!(dummy_args, args);
        }
        let typed_command = match (name, args.len()) {
            (MyPop3CommandName::APOP, 2) => Self::APOP(args[0].parse()?, args[1].parse()?),
            (MyPop3CommandName::DELE, 1) => Self::DELE(args[0].parse()?),
            (MyPop3CommandName::LIST, 0) => Self::LIST_ALL,
            (MyPop3CommandName::LIST, 1) => Self::LIST_SINGLE(args[0].parse()?),
            (MyPop3CommandName::NOOP, 0) => Self::NOOP,
            (MyPop3CommandName::PASS, 1) => Self::PASS(args[0].parse()?),
            (MyPop3CommandName::QUIT, 0) => Self::QUIT,
            (MyPop3CommandName::RETR, 1) => Self::RETR(args[0].parse()?),
            (MyPop3CommandName::RSET, 0) => Self::RSET,
            (MyPop3CommandName::STAT, 0) => Self::STAT,
            (MyPop3CommandName::TOP,  2) => Self::TOP(args[0].parse()?, args[1].parse()?),
            (MyPop3CommandName::UIDL, 0) => Self::UIDL_ALL,
            (MyPop3CommandName::UIDL, 1) => Self::UIDL_SINGLE(args[0].parse()?),
            (MyPop3CommandName::USER, 1) => Self::USER(args[0].parse()?),

            (MyPop3CommandName::APOP, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::DELE, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::LIST, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::NOOP, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::PASS, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::QUIT, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::RETR, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::RSET, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::STAT, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::TOP,  _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::UIDL, _) => unreachable!("{:?}", (name, args)),
            (MyPop3CommandName::USER, _) => unreachable!("{:?}", (name, args)),
        };

        if true { // for debug
            let (name2, args2) = typed_command.decompose();
            assert_eq!(name2, name);
            assert_eq!(args2.len(), args.len());
            for i in 0..args2.len() {
                assert_eq!(args2[i], args[i]);
            }
        }

        Ok(typed_command)
    }

    fn decompose(&self) -> (MyPop3CommandName, Vec<String>) {
        let (name, args): (MyPop3CommandName, &[&dyn std::fmt::Display]) = match &self {
            Self::APOP(x, y) => (MyPop3CommandName::APOP, &[x, y]),
            Self::DELE(x) => (MyPop3CommandName::DELE, &[x]),
            Self::LIST_ALL => (MyPop3CommandName::LIST, &[]),
            Self::LIST_SINGLE(x) => (MyPop3CommandName::LIST, &[x]),
            Self::NOOP => (MyPop3CommandName::NOOP, &[]),
            Self::PASS(x) => (MyPop3CommandName::PASS, &[x]),
            Self::QUIT => (MyPop3CommandName::QUIT, &[]),
            Self::RETR(x) => (MyPop3CommandName::RETR, &[x]),
            Self::RSET => (MyPop3CommandName::RSET, &[]),
            Self::STAT => (MyPop3CommandName::STAT, &[]),
            Self::TOP(x, y) => (MyPop3CommandName::TOP, &[x, y]),
            Self::UIDL_ALL => (MyPop3CommandName::UIDL, &[]),
            Self::UIDL_SINGLE(x) => (MyPop3CommandName::UIDL, &[x]),
            Self::USER(x) => (MyPop3CommandName::USER, &[x]),
        };
        let args: Vec<_> = args.into_iter().map(|s| s.to_string()).collect();
        (name, args)
    }
}

fn validate_and_parse_command_line(s: &str) -> Result<(String, Vec<String>)> {
    // RFC1939 says:
    //   - Commands in the POP3 consist of a case-insensitive keyword, possibly followed by one or more arguments.
    //   - All commands are terminated by a CRLF pair.
    //   - Keywords and arguments consist of printable ASCII characters.
    //   - Keywords and arguments are each separated by a single SPACE character.
    //   - Keywords are three or four characters long.
    //   - Each argument may be up to 40 characters long.
    let s = s.strip_suffix("\r\n").unwrap_or(s); // for convenience, allow a string without CRLF
    if s.is_empty() {
        return Err(anyhow!("command line is empty"));
    }
    let separator = ' '; // single SPACE character
    let mut it = s.split(separator).map(|s| s.to_string());
    let keyword = it.next().ok_or_else(|| anyhow!("no keyword: {:?}", s))?;
    let args = it.collect::<Vec<_>>();

    let validator = |ss: &str, range_of_length: &RangeInclusive<usize>| {
        if ss.is_empty() {
            return Err(anyhow!("empty field (continuous SPACE characters is not allowed): {:?}", (ss, &keyword, &args, s)));
        }
        if !range_of_length.contains(&ss.len()) {
            return Err(anyhow!("invalid length of a field: {:?}", (ss.len(), &ss, &keyword, &args, s)));
        }
        let is_ascii_printable_character = |c: char| c.is_ascii() && !c.is_ascii_control() && !c.is_ascii_whitespace();
        if !ss.chars().all(is_ascii_printable_character) {
            return Err(anyhow!("invalid character in a field: {:?}", (ss, &keyword, &args, ss)));
        }
        Ok(())
    };
    let range_of_length_of_keyword: RangeInclusive<usize> = 3..=4;
    let range_of_length_of_argument: RangeInclusive<usize> = 1..=40;

    let _ = validator(&keyword, &range_of_length_of_keyword)?;
    for arg in &args {
        let _ = validator(&arg, &range_of_length_of_argument)?;
    }

    Ok((keyword, args))
}

#[test]
fn test_001_validate_and_parse_command_line() {
    fn should_be_eq(input_text: &str, expected: &[&str]) {
        let (keyword, args) = validate_and_parse_command_line(input_text).unwrap();
        let left = [vec![keyword], args].concat();
        let right = expected.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(left, right, "{:?}", (&input_text, &expected));
    }
    fn should_be_err(input_text: &str) {
        assert!(validate_and_parse_command_line(input_text).is_err(), "{:?}", (&input_text));
    }

    should_be_eq("ABC", &["ABC"]);
    should_be_eq("ABC\r\n", &["ABC"]);
    should_be_eq("aBc", &["aBc"]);
    should_be_eq("abcd", &["abcd"]);
    should_be_eq("aBc9", &["aBc9"]);
    should_be_eq("ABC 123", &["ABC", "123"]);
    should_be_eq("ABC 123 4 !@_+", &["ABC", "123", "4", "!@_+"]);
    should_be_eq("ABC 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15", &["ABC", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15"]);
    should_be_eq("ABC 1111222233334444555566667777888899990000", &["ABC", "1111222233334444555566667777888899990000"]);
    should_be_eq("ABC 1111222233334444555566667777888899990000\r\n", &["ABC", "1111222233334444555566667777888899990000"]);

    should_be_err("");
    should_be_err("\r\n");
    should_be_err("\r\n\r\n");
    should_be_err("\r\n ");
    should_be_err("\r\na");

    should_be_err(" ");
    should_be_err(" \r\n");
    should_be_err(" \r\n\r\n");
    should_be_err(" \r\n ");
    should_be_err(" \r\na");

    should_be_err(" ABC");
    should_be_err(" ABC\r\n");
    should_be_err(" ABC\r\n ");
    should_be_err("AB C");
    should_be_err("AB C\r\n");
    should_be_err("AB C\r\n ");
    should_be_err("ABC ");
    should_be_err("ABC \r\n");
    should_be_err("ABC\r\n ");

    should_be_err(" ABC 123\r\n");
    should_be_err("ABC  123\r\n");
    should_be_err("ABC 123 \r\n");
    should_be_err("ABC 123\r\n ");

    should_be_err(" ABC 123 4 5\r\n"); // an extra SPACE at the start
    should_be_err("ABC 123  4 5\r\n"); // muliple SPACEs
    should_be_err("ABC 123 4  5\r\n"); // multiple SPACEs
    should_be_err("ABC 123 4 5 \r\n"); // an extra SPACE at the end
    should_be_err("ABC 123 4 5\r\n "); // an extra SPACE at next of CRLF

    should_be_err("\tABC"); // TAB is not allowed
    should_be_err("A\tBC"); // TAB is not allowed
    should_be_err("AB\ttC"); // TAB is not allowed
    should_be_err("ABC\t"); // TAB is not allowed
    should_be_err("ABC\t\r\n"); // TAB is not allowed
    should_be_err("ABC\r\n\t"); // TAB is not allowed

    should_be_err("ABC "); // an extra SPACE at the end
    should_be_err("ABC \r\n"); // an extra SPACE at the end
    should_be_err("ABC\r\n "); // an extra SPACE at next of CRLF
    should_be_err("ABC  "); // multiple extra SPACEs at the end
    should_be_err("ABC  \r\n"); // multiple extra SPACEs at the end

    should_be_err("A\r\n");
    should_be_err("AB\r\n");
    should_be_err("ABCDE\r\n");
    should_be_err("1111222233334444555566667777888899990000\r\n");

    should_be_err("ABC 1111222233334444555566667777888899990000+");
    should_be_err("ABC 1111222233334444555566667777888899990000 1111222233334444555566667777888899990000+ 1111222233334444555566667777888899990000");
}

//====================================================================
#[derive(Debug, PartialEq, Eq)]
pub enum MyPop3Response {
    OkSingleLine {
        status_line: String, // not include CRLF at the end
    },
    OkMultiLine {
        status_line: String, // not include CRLF at the end
        contents_u8: Vec<u8>, // not include ".\r\n" at the end, but include CRLF of last line
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
        if status_line.len() + "\r\n".len() > 512 {
            // RFC1939 says `Responses may be up to 512 characters long, including the terminating CRLF`
            return Err(anyhow!("invalid POP3 response line: too long: {:?}", status_line));
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
                let contents_u8 = extract_contents_u8(&raw_u8, &status_line)?;
                Ok(Self::OkMultiLine { status_line, contents_u8 })
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

    pub fn as_contents_u8(&self) -> Option<&[u8]> {
        match self {
            Self::OkSingleLine { .. } => None,
            Self::OkMultiLine { contents_u8, .. } => Some(contents_u8),
            Self::Err { .. } => None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bin = self.status_line().into_bytes();
        assert!(!bin.ends_with(b"\r\n"));
        bin.extend_from_slice(b"\r\n");
        if let Some(contents_u8) = self.as_contents_u8() {
            assert!(contents_u8.is_empty() || contents_u8.ends_with(b"\r\n"));
            bin.extend_from_slice(contents_u8);
            bin.extend_from_slice(b".\r\n");
        }
        bin
    }
}

fn extract_contents_u8(raw_u8: &[u8], status_line: &str) -> Result<Vec<u8>> {
    let status_line = status_line.trim_end_matches("\r\n"); // remove CRLF if exists

    assert!(status_line.len() + "\r\n".len() < raw_u8.len());
    assert!(raw_u8.starts_with(format!("{}\r\n", status_line).as_bytes()));

    let expected_tail = b"\r\n.\r\n";
    let bin = &raw_u8[status_line.len()..];
    let actual_tail = &bin[bin.len().saturating_sub(expected_tail.len())..];
    if actual_tail != expected_tail {
        return Err(anyhow!("invalid POP3 response (multi-line response should be ends with {:?}), but {:?}", expected_tail, actual_tail));
    }
    let contents_u8 = Vec::from(&raw_u8[(status_line.len() + "\r\n".len())..(raw_u8.len() - b".\r\n".len())]); // may be emtpty
    Ok(contents_u8)
}

#[test]
fn test_001_extract_contents_u8() {
    assert_eq!(b"", extract_contents_u8(b"+OK\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"", extract_contents_u8(b"+OK\r\n.\r\n", "+OK\r\n").unwrap().as_array().unwrap());
    assert_eq!(b"\r\n", extract_contents_u8(b"+OK\r\n\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a\r\n", extract_contents_u8(b"+OK\r\na\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a b c\r\n", extract_contents_u8(b"+OK\r\na b c\r\n.\r\n", "+OK").unwrap().as_array().unwrap());
    assert_eq!(b"a b c\r\n\r\nd e f\r\n\r\n", extract_contents_u8(b"+OK\r\na b c\r\n\r\nd e f\r\n\r\n.\r\n", "+OK").unwrap().as_array().unwrap());

    assert!(extract_contents_u8(b"+OK\r\n\r\n", "+OK").is_err());
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

    // multi-line response with empty contents
    let status_line = "+OK".to_string();
    let contents_u8 = "".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&contents_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, contents_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // multi-line response with contents of one line
    let status_line = "+OK".to_string();
    let contents_u8 = "foo bar\r\n".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&contents_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, contents_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // multi-line response with contents of three lines
    let status_line = "+OK".to_string();
    let contents_u8 = "foo bar\r\n\r\nbuz\r\n".to_owned().into_bytes();
    let raw_u8 = format!("{}\r\n{}.\r\n", status_line, String::from_utf8_lossy(&contents_u8)).into_bytes();
    assert_eq!(MyPop3Response::OkMultiLine { status_line, contents_u8 }, MyPop3Response::try_from(raw_u8.as_ref()).unwrap());

    // ERR response can not have contents
    let status_line = "-ERR".to_string();
    let raw_u8 = format!("{}\r\n.\r\n", status_line);
    assert!(MyPop3Response::try_from(raw_u8.as_bytes()).is_err());
}
