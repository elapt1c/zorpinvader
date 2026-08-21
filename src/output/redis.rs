//! Redis output format.
//!
//! Stores scan results in a Redis server using RESP protocol commands
//! (`SADD`). Port sets are stored as Redis sets keyed by IP address.
//!
//! Ported from C `out-redis.c`.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::{
    name_from_ip_proto,
    BannerEvent, OutputContext, OutputFormat, StatusEvent,
};

/// Redis output plugin.
pub struct RedisOutput {
    /// The underlying TCP connection to the Redis server.
    /// Set during `open()` and reused for all subsequent commands.
    stream: Option<TcpStream>,
    /// Number of outstanding (unacknowledged) commands.
    outstanding: u64,
    /// Authentication password, if any.
    password: Option<String>,
    /// Target host:port (set by the caller before open).
    target_addr: Option<String>,
}

impl RedisOutput {
    pub fn new() -> Self {
        Self {
            stream: None,
            outstanding: 0,
            password: None,
            target_addr: None,
        }
    }

    /// Configure the Redis target address and optional password.
    /// Must be called before `open()`.
    pub fn configure(&mut self, addr: String, password: Option<String>) {
        self.target_addr = Some(addr);
        self.password = password;
    }

    /// Send a RESP command and increment the outstanding counter.
    fn send_command(&mut self, cmd: &str) -> io::Result<()> {
        if let Some(ref mut stream) = self.stream {
            stream.write_all(cmd.as_bytes())?;
            self.outstanding += 1;
        }
        Ok(())
    }

    /// Read a single line from the Redis stream.
    fn recv_line(stream: &mut TcpStream) -> io::Result<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read_exact(&mut byte) {
                Ok(()) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(String::from_utf8_lossy(&line).to_string())
    }

    /// Drain any pending responses from Redis without blocking.
    fn drain_responses(&mut self) {
        if let Some(ref mut stream) = self.stream {
            stream
                .set_nonblocking(true)
                .ok();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
            stream
                .set_nonblocking(false)
                .ok();
            self.outstanding = 0;
        }
    }
}

impl OutputFormat for RedisOutput {
    fn file_extension(&self) -> &str {
        "redis"
    }

    fn open(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        let addr = match &self.target_addr {
            Some(a) => a.clone(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "redis target address not configured",
                ));
            }
        };

        let mut stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // Authenticate if password is set.
        if let Some(ref pw) = self.password {
            let auth_cmd = format!(
                "*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n",
                pw.len(),
                pw
            );
            stream.write_all(auth_cmd.as_bytes())?;
            let response = Self::recv_line(&mut stream)?;
            if !response.starts_with("+OK") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("redis AUTH failed: {}", response.trim()),
                ));
            }
        }

        // PING to verify connection.
        stream.write_all(b"PING\r\n")?;
        let response = Self::recv_line(&mut stream)?;
        if !response.starts_with("+PONG") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("redis PING failed: {}", response.trim()),
            ));
        }

        self.stream = Some(stream);
        Ok(())
    }

    fn close(&mut self, _writer: &mut dyn Write, _ctx: &OutputContext) -> io::Result<()> {
        if let Some(ref mut stream) = self.stream {
            let _ = stream.write_all(b"QUIT\r\n");
        }
        self.stream = None;
        Ok(())
    }

    fn report_status(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        event: &StatusEvent,
    ) -> io::Result<()> {
        let ip_str = event.ip.to_string();
        let port_str = format!("{}/{}", event.port, name_from_ip_proto(event.ip_proto));

        // SADD "host" <ip>
        let cmd1 = format!(
            "*3\r\n$4\r\nSADD\r\n$4\r\nhost\r\n${}\r\n{}\r\n",
            ip_str.len(),
            ip_str,
        );
        self.send_command(&cmd1)?;

        // SADD <ip> <port/proto>
        let cmd2 = format!(
            "*3\r\n$4\r\nSADD\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
            ip_str.len(),
            ip_str,
            port_str.len(),
            port_str,
        );
        self.send_command(&cmd2)?;

        // SADD <ip>:<port/proto> <timestamp:status:reason:ttl>
        let key = format!("{}:{}", ip_str, port_str);
        let value = format!(
            "{}:{}:{}:{}",
            event.timestamp, event.status as u32, event.reason, event.ttl,
        );
        let cmd3 = format!(
            "*3\r\n$4\r\nSADD\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
            key.len(),
            key,
            value.len(),
            value,
        );
        self.send_command(&cmd3)?;

        // Drain responses to avoid buildup.
        self.drain_responses();

        Ok(())
    }

    fn report_banner(
        &mut self,
        _writer: &mut dyn Write,
        _ctx: &OutputContext,
        _event: &BannerEvent,
    ) -> io::Result<()> {
        // Banner storage in Redis is not implemented in the C version either.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redis_output_creation() {
        let out = RedisOutput::new();
        assert!(out.stream.is_none());
        assert_eq!(out.outstanding, 0);
        assert!(out.password.is_none());
    }

    #[test]
    fn test_redis_file_extension() {
        let out = RedisOutput::new();
        assert_eq!(
            <RedisOutput as OutputFormat>::file_extension(&out),
            "redis"
        );
    }

    #[test]
    fn test_redis_configure() {
        let mut out = RedisOutput::new();
        out.configure("127.0.0.1:6379".to_string(), Some("secret".to_string()));
        assert_eq!(out.target_addr, Some("127.0.0.1:6379".to_string()));
        assert_eq!(out.password, Some("secret".to_string()));
    }
}
