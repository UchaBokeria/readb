use readb::http::*;
#[test]
fn strict_http() {
    let raw =
        b"POST /v1/quest/port HTTP/1.1\r\nContent-Length: 2\r\nAuthorization: Bearer x\r\n\r\n{}";
    assert_eq!(request(&mut raw.as_slice(), 128).unwrap().body, b"{}");
    for h in [
        "Content-Length: 2\r\nContent-Length: 2",
        "Transfer-Encoding: chunked\r\nContent-Length: 2",
        "Content-Length: 999",
        "Content-Length: -1",
    ] {
        let text = format!("POST /v1/quest/port HTTP/1.1\r\n{h}\r\n\r\n{{}}");
        assert!(request(&mut text.as_bytes(), 128).is_err());
    }
}
#[test]
fn duplicate_auth_denied() {
    let raw =
        b"POST / HTTP/1.1\r\nAuthorization: a\r\nAuthorization: b\r\nContent-Length: 0\r\n\r\n";
    assert!(request(&mut raw.as_slice(), 128).is_err());
}
