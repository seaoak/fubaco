use std::io::{Read, Write, ErrorKind};

use anyhow::{anyhow, Result};

use crate::my_disconnect::MyDisconnect;

const ALMOST_MAX_LINE_LENGTH: usize = 1024;

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
        assert!(ends_with_u8(lines, b"\r\n"));
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
            if ends_with_u8(buf, b"\r\n") { // allow empty line
                break;
            }
        }
        Ok(())
    }
}

//====================================================================
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
