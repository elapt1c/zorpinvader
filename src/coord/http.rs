//! A minimal HTTP/1.1 server, sized for the control API.
//!
//! Deliberately small: one request per connection, `Content-Length` bodies (with
//! `Expect: 100-continue` support, because that is what curl sends for bodies
//! over a kilobyte), JSON in and out, and `Connection: close`. No chunked
//! encoding, no keep-alive, no TLS — TLS belongs to whatever terminates the
//! public endpoint (`cloudflared`, Caddy, nginx).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Largest request body accepted. A block's hit list is the biggest thing a
/// client sends: a pathological /16 block answering on every port is ~450k hits,
/// which is well under this.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// Largest header block accepted.
const MAX_HEADER_LINES: usize = 128;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(|s| s.as_str())
    }

    /// Parse the body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("invalid JSON body: {}", e))
    }

    /// Bearer token from the `Authorization` header.
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|s| s.trim())
    }
}

/// Read one request from the stream.
pub fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);

    let mut line = String::new();
    if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
        return Err("empty request".to_string());
    }
    let mut parts = line.trim_end().split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err(format!("malformed request line: {}", line.trim_end()));
    }
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    for _ in 0..MAX_HEADER_LINES {
        let mut header = String::new();
        if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length: usize = headers
        .get("content-length")
        .map(|v| v.trim().parse::<usize>())
        .transpose()
        .map_err(|_| "invalid Content-Length".to_string())?
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(format!("body too large ({} bytes)", content_length));
    }

    if headers
        .get("expect")
        .map(|v| v.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false)
    {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("short body: {}", e))?;
    }

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

/// Write a complete response and close the connection.
pub fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        status,
        reason(status),
        content_type,
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

pub fn respond_json(stream: &mut TcpStream, status: u16, body: &str) {
    respond(stream, status, "application/json", body.as_bytes());
}

pub fn respond_text(stream: &mut TcpStream, status: u16, body: &str) {
    respond(stream, status, "text/plain; charset=utf-8", body.as_bytes());
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Constant-time-ish token comparison: compare lengths first, then accumulate
/// differences so the comparison time does not depend on where a mismatch is.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Random hex token, used when `--server-token` is not supplied.
pub fn random_token() -> String {
    let mut bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_matches("abc123", "abc123"));
        assert!(!token_matches("abc123", "abc124"));
        assert!(!token_matches("abc123", "abc12"));
        assert!(!token_matches("", ""));
    }

    #[test]
    fn random_tokens_are_hex_and_unique() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 48);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
