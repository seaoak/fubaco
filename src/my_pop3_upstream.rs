use std::io::{Read, Write};

use anyhow::{anyhow, Result};

use crate::my_disconnect::MyDisconnect;
use crate::my_logger::prelude::*;
use crate::my_pop3_command::{MyPop3Command, MyPop3Response};
use crate::my_text_line_stream::{self, MyTextLineStream};

//====================================================================
#[derive(Debug)]
pub struct MyPop3Upstream<T: Read + Write + MyDisconnect> {
    stream: MyTextLineStream<T>,
}

impl<T: Read + Write + MyDisconnect> MyPop3Upstream<T> {
    pub fn connect(stream: T) -> Result<Self> {
        let mut stream = MyTextLineStream::connect(stream);

        // wait for POP3 greeting message from server
        {
            let response = read_one_response_completely(&mut stream, false)?;
            info!("greeting message is received: {}", response.status_line());
            if response.is_err() {
                return Err(anyhow!("greeting message should be OK: {}", response.status_line()));
            }
        }

        Ok(Self {
            stream,
        })
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.stream.disconnect()
    }

    pub fn issue_command(&mut self, command: &MyPop3Command) -> Result<MyPop3Response> {
        info!("issue POP3 command: {:?}", command);
        self.stream.write_all_and_flush(&command.to_bytes())?;
        info!("wait the response for {} command", command.name());
        read_one_response_completely(&mut self.stream, command.is_multi_line_response_expected())
    }
}

//====================================================================
fn read_one_response_completely<T: Read + Write + MyDisconnect>(upstream_stream: &mut MyTextLineStream<T>, is_multi_line_response_expected: bool) -> Result<MyPop3Response> {
    let mut response_lines = Vec::<u8>::new();
    upstream_stream.read_some_lines(&mut response_lines)?;
    assert_ne!(response_lines.len(), 0);

    let status_line = my_text_line_stream::take_first_line(&response_lines)?;
    let is_ok = MyPop3Response::is_likely_to_be_ok(&status_line);
    let is_err = MyPop3Response::is_likely_to_be_err(&status_line);

    if is_ok && is_multi_line_response_expected {
        while !response_lines.ends_with(b"\r\n.\r\n") {
            upstream_stream.read_some_lines(&mut response_lines)?;
        }
    }

    if is_ok {
        if is_multi_line_response_expected {
            info!("multi-line response ({} byte contents) is received: {}", response_lines.len() - status_line.len() - b".\r\n".len(), status_line.trim_end_matches("\r\n"));
        } else {
            info!("single-line response is received: {}", status_line.trim_end_matches("\r\n"));
        }
    }
    if is_err {
        info!("ERR response is received: {}", status_line.trim_end_matches("\r\n"));
    }

    MyPop3Response::try_from(response_lines.as_ref())
}
