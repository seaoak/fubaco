use std::net;

use anyhow::Result;
use native_tls;
use rustls;

pub trait MyDisconnect {
    fn disconnect(&mut self) -> Result<()>;
}

//====================================================================
impl<'a> MyDisconnect for rustls::Stream<'a, rustls::ClientConnection, net::TcpStream> {
    fn disconnect(&mut self) -> Result<()> {
        // self.shutdown()?;
        Ok(())
    }
}

impl MyDisconnect for native_tls::TlsStream<net::TcpStream> {
    fn disconnect(&mut self) -> Result<()> {
        self.shutdown()?;
        Ok(())
    }
}

impl MyDisconnect for net::TcpStream {
    fn disconnect(&mut self) -> Result<()> {
        self.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}
