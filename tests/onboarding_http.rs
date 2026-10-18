use readb::{
    onboarding::{admin_issue, public_request},
    registry::Registry,
    schema::ServerConfig,
};
use std::{collections::HashMap, fs};
fn registry() -> Registry {
    let p = std::env::temp_dir().join(format!("readb-onboard-http-{}", readb::policy::random()));
    Registry::new(
        ServerConfig {
            schema: 1,
            adb: "/must-not-execute".into(),
            devices: vec![],
            listeners: vec![],
        },
        p,
    )
    .unwrap()
}
#[test]
fn admin_issue_requires_real_broker_and_never_creates_invite_or_secret_on_missing_capability() {
    let r = registry();
    let before = fs::read_dir(&r.root).unwrap().count();
    let body = serde_json::json!({"name":"Pixel","kind":"phone","endpoint":"vpn.example.org:51820","client_session":"public-browser-session","setup_url":"https://readb.uchabokeria.space"});
    let response = admin_issue(&r, &serde_json::to_vec(&body).unwrap());
    assert_eq!(response.status, 503);
    assert_eq!(response.value["blocker"], "report_firewall_setup_required");
    assert!(response.value.get("setup_code").is_none());
    assert!(!r.root.join("onboarding").exists());
    assert_eq!(fs::read_dir(&r.root).unwrap().count(), before);
    fs::remove_dir_all(r.root).unwrap();
}
#[test]
fn public_routes_reject_malformed_cross_origin_and_unknown_without_ledger_writes() {
    let r = registry();
    for (method, path, body, origin) in [
        ("GET", "/onboard/v1/claim", "{}", false),
        ("POST", "/onboard/v1/claim", "{", false),
        ("POST", "/onboard/v1/claim", "{}", false),
        ("POST", "/onboard/v1/resume?client_auth=secret", "{}", false),
        ("POST", "/onboard/v1/resume", "{}", true),
    ] {
        let mut headers = HashMap::from([("content-type".into(), "application/json".into())]);
        if origin {
            headers.insert("origin".into(), "https://attacker.invalid".into());
        }
        let request = readb::http::Request {
            method: method.into(),
            path: path.into(),
            headers,
            body: body.as_bytes().to_vec(),
        };
        let response = public_request(&r, &request, "127.0.0.1");
        assert!([400, 403, 404].contains(&response.status));
        assert!(!response.value.to_string().contains("secret"));
        assert!(!r.root.join("onboarding").exists());
    }
    fs::remove_dir_all(r.root).unwrap();
}

#[test]
fn live_loopback_router_keeps_admin_auth_and_public_session_auth_separate() {
    use std::{
        io::{Read, Write},
        net::TcpStream,
        sync::Arc,
        time::Duration,
    };
    let registry = Arc::new(registry());
    let view = readb::web::configure(registry.clone(), true, 0).unwrap();
    let url = view["url"].as_str().unwrap();
    let addr = url.trim_start_matches("http://").trim_end_matches('/');
    let key = fs::read_to_string(registry.root.join("dashboard-key")).unwrap();
    let post = |path: &str, body: &str, authorized: bool| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let auth = if authorized {
            format!("Authorization: Bearer {}\r\n", key)
        } else {
            String::new()
        };
        write!(s,"POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        let mut result = String::new();
        s.read_to_string(&mut result).unwrap();
        assert!(!result.contains(&key));
        let (headers, body) = result.split_once("\r\n\r\n").unwrap();
        let status = headers
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()
            .unwrap();
        (
            status,
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
        )
    };
    let body=serde_json::json!({"name":"Pixel","kind":"phone","endpoint":"vpn.example.org:51820","client_session":"actual-browser-session"}).to_string();
    let (status, result) = post("/api/onboard/invite", &body, false);
    assert_eq!(status, 403);
    assert_eq!(result["error"], "dashboard_key_or_origin_rejected");
    let (status, result) = post("/api/onboard/invite", &body, true);
    assert_eq!(status, 503);
    assert_eq!(result["blocker"], "report_firewall_setup_required");
    assert!(!registry.root.join("onboarding").exists());
    let body = serde_json::json!({"request_sha256":"a".repeat(64),"client_auth":"b".repeat(64)})
        .to_string();
    let (status, result) = post("/onboard/v1/resume", &body, false);
    assert_eq!(status, 403);
    assert_eq!(result["code"], "invalid_setup");
    assert!(result.get("error").is_none());
    readb::web::configure(registry.clone(), false, 0).unwrap();
    fs::remove_dir_all(&registry.root).unwrap();
}
