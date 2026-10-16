use readb::web::*;
use std::collections::HashMap;
#[test]
fn dashboard_is_off_by_default_and_never_shows_key() {
    let s = Dashboard::default();
    assert_eq!(s.public_view()["enabled"], false);
    assert!(s.public_view().get("key").is_none());
}
#[test]
fn dashboard_rejects_wrong_key_host_and_origin() {
    let mut h = HashMap::from([
        ("host".into(), "127.0.0.1:9870".into()),
        ("authorization".into(), "Bearer fixture-only-key".into()),
    ]);
    assert!(authorized(&h, "fixture-only-key", 9870));
    h.insert("origin".into(), "https://evil.example".into());
    assert!(!authorized(&h, "fixture-only-key", 9870));
    h.remove("origin");
    h.insert("host".into(), "evil.example:9870".into());
    assert!(!authorized(&h, "fixture-only-key", 9870));
    h.insert("host".into(), "127.0.0.1:9870".into());
    assert!(!authorized(&h, "wrong-key", 9870));
}

#[test]
fn real_http_auth_controller_viewer_policy_and_shutdown() {
    use readb::{
        backend::now,
        policy::{Owner, Receipt, random},
        registry::Registry,
        schema::ServerConfig,
    };
    use serde_json::{Value, json};
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        os::unix::fs::PermissionsExt,
        sync::Arc,
        time::Duration,
    };
    let root = std::env::temp_dir().join(format!("readb-http-{}", &random()[..12]));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = root.join("adb");
    fs::write(&adb, "#!/bin/sh\ncase \"$*\" in *ro.serialno*) echo fixture;; *) printf 'fixture output';; esac\n").unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let c = ServerConfig::parse(&serde_json::to_vec(&json!({"schema":1,"adb":adb,"devices":[{"id":"phone","name":"Fixture phone","kind":"phone","peer":"192.0.2.3","adb_port":5037,"token":"x".repeat(64),"identity":<sha2::Sha256 as sha2::Digest>::digest(b"fixture").iter().map(|b| format!("{b:02x}")).collect::<String>()}]})).unwrap()).unwrap();
    let r = Arc::new(Registry::new(c, root.join("state")).unwrap());
    let b = r.device("phone").unwrap();
    {
        let mut s = b.state.lock().unwrap();
        s.receipt = Receipt {
            received_at: now(),
            port: 40000,
            battery: 70,
            connected: true,
            identity_verified: true,
            transport_cleanup_failed: false,
        };
        s.target = Some(40000);
    }
    let view = configure(r.clone(), true, 0).unwrap();
    let url = view["url"].as_str().unwrap();
    let addr = url.strip_prefix("http://").unwrap().trim_end_matches('/');
    let key = fs::read_to_string(r.root.join("dashboard-key")).unwrap();
    let request = |method: &str, path: &str, auth: &str, origin: Option<&str>, body: Value| {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = if method == "POST" {
            body.to_string()
        } else {
            String::new()
        };
        let origin = origin
            .map(|o| format!("Origin: {o}\r\n"))
            .unwrap_or_default();
        write!(s,"{method} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {auth}\r\n{origin}Content-Length: {}\r\n\r\n{body}",body.len()).unwrap();
        let mut bytes = Vec::new();
        s.read_to_end(&mut bytes).unwrap();
        let raw = String::from_utf8(bytes).unwrap();
        let (header, body) = raw.split_once("\r\n\r\n").unwrap();
        (header.to_string(), body.to_string())
    };
    let (h, _) = request("GET", "/api/status", "wrong", None, Value::Null);
    assert!(h.starts_with("HTTP/1.1 403"));
    let (h, _) = request(
        "GET",
        "/api/status",
        &key,
        Some("https://evil.example"),
        Value::Null,
    );
    assert!(h.starts_with("HTTP/1.1 403"));
    let (h, body) = request("GET", "/api/config", &key, None, Value::Null);
    assert!(h.starts_with("HTTP/1.1 200"));
    assert!(!body.contains(&"x".repeat(64)));
    assert!(!body.contains(&"a".repeat(64)));
    let ticket = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "other-host".into(),
                session: "fixture".into(),
                job: "UI review".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    let (h, body) = request(
        "POST",
        "/api/action",
        &key,
        None,
        json!({"device":"phone","action":"wake"}),
    );
    assert!(!h.starts_with("HTTP/1.1 200"));
    assert!(
        body.contains("device_busy") && body.contains("UI review") && body.contains("other-host")
    );
    let (h, body) = request(
        "POST",
        "/api/action",
        &key,
        None,
        json!({"device":"phone","action":"model"}),
    );
    assert!(h.starts_with("HTTP/1.1 200"), "{h}: {body}");
    assert!(body.contains("fixture output"));
    assert!(b.status()["viewers"].as_array().unwrap().is_empty());
    b.release(&ticket).unwrap();
    let (h, body) = request(
        "POST",
        "/api/policy",
        &key,
        None,
        json!({"device":"phone","enabled":false,"prevent_lock":false}),
    );
    assert!(h.starts_with("HTTP/1.1 200"), "{body}");
    assert_eq!(b.status()["keepalive_policy"]["enabled"], false);
    assert!(b.status()["job"].is_null());
    configure(r.clone(), false, 0).unwrap();
    assert_eq!(r.web.lock().unwrap().public_view()["enabled"], false);
}

#[test]
fn immediate_disable_enable_reuses_fixed_port() {
    use readb::{registry::Registry, schema::ServerConfig};
    use std::sync::Arc;
    let root =
        std::env::temp_dir().join(format!("readb-toggle-{}", &readb::policy::random()[..12]));
    let c = ServerConfig::parse(br#"{"schema":1,"adb":"/no-adb","devices":[]}"#).unwrap();
    let r = Arc::new(Registry::new(c, root).unwrap());
    let v = configure(r.clone(), true, 0).unwrap();
    let port = v["url"]
        .as_str()
        .unwrap()
        .trim_end_matches('/')
        .rsplit(':')
        .next()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    for _ in 0..8 {
        configure(r.clone(), false, 0).unwrap();
        configure(r.clone(), true, port).unwrap();
    }
    configure(r, false, 0).unwrap();
}
