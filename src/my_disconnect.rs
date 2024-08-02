use std::net::TcpStream;

use anyhow::Result;
use native_tls::TlsStream;

pub trait MyDisconnect {
    fn disconnect(&mut self) -> Result<()>;
}

//====================================================================
impl MyDisconnect for TlsStream<TcpStream> {
    fn disconnect(&mut self) -> Result<()> {
        self.shutdown()?;
        Ok(())
    }
}

impl MyDisconnect for TcpStream {
    fn disconnect(&mut self) -> Result<()> {
        self.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
}
