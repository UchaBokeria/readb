use crate::{policy::Res, wire::line};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}
pub fn request(r: &mut impl Read, max: usize) -> Res<Request> {
    let first = line(r, 4096).map_err(|_| "invalid_http_line")?;
    let first = String::from_utf8(first).map_err(|_| "invalid_http_line")?;
    let parts: Vec<_> = first.trim_end_matches('\r').split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err("invalid_http_line".into());
    }
    let mut headers = HashMap::new();
    let mut total = first.len();
    loop {
        let raw = line(r, 4096).map_err(|_| "invalid_http_header")?;
        total += raw.len() + 1;
        if total > 8192 {
            return Err("headers_too_large".into());
        }
        if raw == b"\r" {
            break;
        }
        let raw = String::from_utf8(raw).map_err(|_| "invalid_http_header")?;
        let (k, v) = raw
            .trim_end_matches('\r')
            .split_once(':')
            .ok_or("invalid_http_header")?;
        let key = k.to_ascii_lowercase();
        if k.is_empty() || k.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-') {
            return Err("invalid_http_header".into());
        }
        if headers.insert(key, v.trim().to_string()).is_some() {
            return Err("duplicate_http_header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("transfer_encoding_forbidden".into());
    }
    let size = headers
        .get("content-length")
        .map(String::as_str)
        .or_else(|| if parts[0] == "GET" { Some("0") } else { None })
        .ok_or("content_length_required")?;
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid_content_length".into());
    }
    let size: usize = size.parse().map_err(|_| "invalid_content_length")?;
    if size > max {
        return Err("body_too_large".into());
    }
    let mut body = vec![0; size];
    r.read_exact(&mut body).map_err(|_| "incomplete_body")?;
    Ok(Request {
        method: parts[0].into(),
        path: parts[1].into(),
        headers,
        body,
    })
}
pub fn answer(w: &mut impl Write, status: u16, v: &serde_json::Value) -> Res<()> {
    let body = serde_json::to_vec(v).unwrap();
    write!(w,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).and_then(|_|w.write_all(&body)).map_err(|_|"response_closed".into())
}
/// Private existing loopback Hermes bridge only; never follows redirects.
pub fn bridge(route: &str, data: Option<&serde_json::Value>) -> Res<serde_json::Value> {
    if route != "/health" && route != "/send" {
        return Err("invalid_bridge_route".into());
    }
    let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|_| "bridge_unavailable")?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "bridge_timeout_setup")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "bridge_timeout_setup")?;
    let body = data
        .map(|d| serde_json::to_vec(d).unwrap())
        .unwrap_or_default();
    let method = if data.is_some() { "POST" } else { "GET" };
    write!(stream,"{method} {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).and_then(|_|stream.write_all(&body)).map_err(|_|"bridge_write_failed")?;
    let first = line(&mut stream, 4096).map_err(|_| "bridge_header_failed")?;
    let text = String::from_utf8_lossy(&first);
    if !text.starts_with("HTTP/1.1 200 ") && !text.starts_with("HTTP/1.0 200 ") {
        return Err("bridge_rejected".into());
    }
    let mut size = None;
    let mut total = 0;
    loop {
        let h = line(&mut stream, 4096).map_err(|_| "bridge_header_failed")?;
        total += h.len();
        if total > 8192 {
            return Err("bridge_headers_too_large".into());
        }
        if h == b"\r" {
            break;
        }
        let h = String::from_utf8_lossy(&h);
        if let Some((k, v)) = h.trim().split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding") {
                return Err("bridge_transfer_encoding_unsupported".into());
            }
            if k.eq_ignore_ascii_case("content-length") {
                if size.is_some() {
                    return Err("bridge_duplicate_length".into());
                }
                size = Some(
                    v.trim()
                        .parse::<usize>()
                        .map_err(|_| "bridge_invalid_length")?,
                );
            }
        }
    }
    let size = size.ok_or("bridge_content_length_required")?;
    if size > 8192 {
        return Err("bridge_response_too_large".into());
    }
    let mut body = vec![0; size];
    stream
        .read_exact(&mut body)
        .map_err(|_| "bridge_body_failed")?;
    serde_json::from_slice(&body).map_err(|_| "bridge_invalid_json".into())
}
