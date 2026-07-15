use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;

//====================================================================
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
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

impl std::str::FromStr for MyPop3CommandName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NOTE: `to_ascii_uppercase()` seems too much.
        match s {
            "APOP" => Ok(Self::APOP),
            "DELE" => Ok(Self::DELE),
            "LIST" => Ok(Self::LIST),
            "NOOP" => Ok(Self::NOOP),
            "PASS" => Ok(Self::PASS),
            "QUIT" => Ok(Self::QUIT),
            "RETR" => Ok(Self::RETR),
            "RSET" => Ok(Self::RSET),
            "STAT" => Ok(Self::STAT),
            "TOP"  => Ok(Self::TOP),
            "UIDL" => Ok(Self::UIDL),
            "USER" => Ok(Self::USER),
            _      => Err(anyhow!("invalid argument: {:?}", s)),
        }
    }
}

impl fmt::Display for MyPop3CommandName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ss = match self {
            Self::APOP => "APOP",
            Self::DELE => "DELE",
            Self::LIST => "LIST",
            Self::NOOP => "NOOP",
            Self::PASS => "PASS",
            Self::QUIT => "QUIT",
            Self::RETR => "RETR",
            Self::RSET => "RSET",
            Self::STAT => "STAT",
            Self::TOP  => "TOP",
            Self::UIDL => "UIDL",
            Self::USER => "USER",
        };
        write!(f, "{ss}")
    }
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
        Ok(Self { name, args })
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
            (MyPop3CommandName::DELE, 0) => false,
            (MyPop3CommandName::NOOP, 0) => false,
            (MyPop3CommandName::PASS, 1) => false,
            (MyPop3CommandName::QUIT, 0) => false,
            (MyPop3CommandName::RETR, 1) => true,
            (MyPop3CommandName::RSET, 0) => false,
            (MyPop3CommandName::TOP,  2) => true,
            (MyPop3CommandName::UIDL, 0) => true,
            (MyPop3CommandName::UIDL, 1) => false,
            (MyPop3CommandName::USER, 1) => false,
            _ => unreachable!("{:?}", self),
        }
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
