use std::io::{Read, Write};

use anyhow::Result;

use crate::my_disconnect::MyDisconnect;
use crate::my_logger::prelude::*;
use crate::my_pop3_command::{MyPop3Command, MyPop3Response};
use crate::my_text_line_stream::MyTextLineStream;

//====================================================================
#[derive(Debug)]
pub struct MyPop3Downstream<T: Read + Write + MyDisconnect> {
    stream: MyTextLineStream<T>,
    pending_command: Option<MyPop3Command>,
}

impl<T: Read + Write + MyDisconnect> MyPop3Downstream<T> {
    pub fn connect(stream: T) -> Result<Self> {
        let mut stream = MyTextLineStream::connect(stream);

        // send dummy greeting message to client (upstream is not opened yet)
        info!("send dummy greeting message to downstream");
        let greeting_response = MyPop3Response::try_from(b"+OK Greeting\r\n".as_ref()).unwrap();
        stream.write_all_and_flush(&greeting_response.to_bytes())?;

        Ok(Self {
            stream,
            pending_command: None,
        })
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.stream.disconnect()
    }

    pub fn wait_for_command<'a>(&'a mut self) -> Result<(MyPop3Command, MyPop3Responder<'a, T>)> {
        assert!(self.pending_command.is_none());
        let mut command_line = Vec::<u8>::new();
        self.stream.read_some_lines(&mut command_line)?;
        let command = MyPop3Command::try_from(command_line.as_ref())?;
        self.pending_command = Some(command.clone());
        Ok((command, MyPop3Responder::new(self)))
    }

    // not public (available by MyPop3Responder only)
    fn send_response(&mut self, response: &MyPop3Response) -> Result<()> {
        assert!(self.pending_command.is_some());
        let command = self.pending_command.take().unwrap();
        if response.is_ok() {
            assert_eq!(response.is_multi_line_response(), command.is_multi_line_response_expected());
        }
        self.stream.write_all_and_flush(&response.to_bytes())
    }
}

//====================================================================
#[derive(Debug)]
pub struct MyPop3Responder<'a, T: Read + Write + MyDisconnect> {
    stream: &'a mut MyPop3Downstream<T>, // hold mutable reference to acquire the lock of the stream
}

impl<'a, T: Read + Write + MyDisconnect> MyPop3Responder<'a, T> {
    fn new(stream: &'a mut MyPop3Downstream<T>) -> Self {
        Self {
            stream,
        }
    }

    // consume self to release the lock of the stream
    pub fn send_response(self, response: &MyPop3Response) -> Result<()> {
        self.stream.send_response(response)
    }
}
