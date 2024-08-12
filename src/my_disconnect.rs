use std::net;

use anyhow::Result;
use native_tls;

pub trait MyDisconnect {
    fn disconnect(&mut self) -> Result<()>;
}

//====================================================================
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
