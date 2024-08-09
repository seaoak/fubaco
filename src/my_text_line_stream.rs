use std::io::{Read, Write, ErrorKind};

use anyhow::{anyhow, Result};

use crate::my_disconnect::MyDisconnect;

const ALMOST_MAX_LINE_LENGTH: usize = 1024;
const ASCII_CODE_CR: u8 = b'\r'; // 0x0d "Carriage Return"
const ASCII_CODE_LF: u8 = b'\n'; // 0x0a "Line Feed"

//====================================================================
#[derive(Debug)]
pub struct MyTextLineStream<S: Read + Write + MyDisconnect> {
    raw_stream: S,
}

impl<S: Read + Write + MyDisconnect> MyTextLineStream<S> {
    pub fn connect(stream: S) -> Self {
        Self {
            raw_stream: stream,
        }
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.raw_stream.disconnect()?;
        Ok(())
    }

    pub fn write_all_and_flush(&mut self, lines: &[u8]) -> Result<()> {
        assert!(Self::ends_with_u8(lines, b"\r\n"));
        self.raw_stream.write_all(lines)?;
        self.raw_stream.flush()?;
        Ok(())
    }

    pub fn read_some_lines(&mut self, buf: &mut Vec<u8>) -> Result<()> {
        // NOTE: buf might contain some elements already
        // NOTE: this function may read multple lines at once
        let mut local_buf = [0u8; ALMOST_MAX_LINE_LENGTH];
        loop {
            let nbytes = match self.raw_stream.read(&mut local_buf) {
                Ok(0) => return Err(anyhow!("steam is closed unexpectedly")),
                Ok(len) => len,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(anyhow!(e)),
            };
            buf.extend(&local_buf[0..nbytes]);
            if Self::ends_with_u8(buf, b"\r\n") { // allow empty line
                break;
            }
        }
        Ok(())
    }

    // static methods (utilities)
    #[allow(unused)]
    pub fn starts_with_u8(target: &[u8], pattern: &[u8]) -> bool {
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
    
    #[allow(unused)]
    pub fn ends_with_u8(target: &[u8], pattern: &[u8]) -> bool {
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

    #[allow(unused)]
    pub fn take_first_line(target: &[u8]) -> Result<String> { // return value includes CRLF
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

    #[allow(unused)]
    pub fn find_u8(target: &[u8], pattern: &[u8]) -> Option<usize> {
        assert!(pattern.len() > 0);
        if target.len() < pattern.len() {
            return None;
        }
        let mut pos = 0;
        while pos + pattern.len() <= target.len() {
            let mut is_matching = true;
            for i in 0..pattern.len() {
                if target[pos + i] != pattern[i] {
                    is_matching = false;
                    break;
                }
            }
            if is_matching {
                return Some(pos);
            }
            pos += 1;
        }
        None
    }
}
