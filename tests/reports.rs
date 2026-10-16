use readb::{policy::random, registry::Registry, schema::ServerConfig};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
#[test]
fn v2_http_binds_source_and_token_and_never_dispatches_for_no_port() {
    let root = std::env::temp_dir().join(format!("readb-reports-{}", &random()[..12]));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = root.join("adb");
    fs::write(
        &adb,
        "#!/bin/sh\necho forbidden > \"$HOME/adb-was-called\"\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let reserve = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserve.local_addr().unwrap();
    drop(reserve);
    let c=ServerConfig::parse(&serde_json::to_vec(&json!({"schema":1,"adb":adb,"devices":[{"id":"phone","name":"Phone fixture","kind":"phone","peer":"127.0.0.1","adb_port":5090,"token":"x".repeat(64)},{"id":"other","name":"Other fixture","kind":"phone","peer":"127.0.0.2","adb_port":5091,"token":"y".repeat(64)}],"listeners":[{"bind":address.to_string(),"path":"/v2/phone","device":"phone","format":"v2"},{"bind":address.to_string(),"path":"/v2/other","device":"other","format":"v2"}]})).unwrap()).unwrap();
    let r = Arc::new(Registry::new(c, root.join("state")).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let rr = r.clone();
    let st = stop.clone();
    let h = thread::spawn(move || readb::daemon::serve(rr, st));
    for _ in 0..100 {
        if TcpStream::connect(address).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let post = |path: &str, key: &str, body: Value| {
        let mut s = TcpStream::connect(address).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let body = body.to_string();
        write!(s,"POST {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{body}",body.len()).unwrap();
        let mut data = String::new();
        s.read_to_string(&mut data).unwrap();
        let (header, body) = data.split_once("\r\n\r\n").unwrap();
        (
            header.to_string(),
            serde_json::from_str::<Value>(body).unwrap(),
        )
    };
    let v = json!({"schema":2,"epoch":"fixture-boot","sequence":1,"port":null,"battery":12,"observed":{"credential_storage_unlocked":true,"screen_lock":"unknown","vpn_active":true,"notifications":"granted","discovery":"denied","secure_settings":"denied"}});
    assert!(
        post("/v2/phone", "wrong", v.clone())
            .0
            .starts_with("HTTP/1.1 403")
    );
    assert!(
        post("/v2/other", &"y".repeat(64), v.clone())
            .0
            .starts_with("HTTP/1.1 403")
    );
    assert_eq!(
        r.device("phone")
            .unwrap()
            .state
            .lock()
            .unwrap()
            .receipt
            .received_at,
        0.
    );
    let (head, body) = post("/v2/phone", &"x".repeat(64), v.clone());
    assert!(head.starts_with("HTTP/1.1 200"));
    assert_eq!(body["connected"], false);
    assert!(!root.join("state/devices/phone/adb-was-called").exists());
    r.device("phone")
        .unwrap()
        .state
        .lock()
        .unwrap()
        .last_attempt = None;
    let (head, body) = post("/v2/phone", &"x".repeat(64), v.clone());
    assert!(head.starts_with("HTTP/1.1 409"));
    assert_eq!(body["error"], "stale_report_sequence");
    let mut bad = v;
    bad["schema"] = json!(99);
    assert!(
        post("/v2/phone", &"x".repeat(64), bad)
            .0
            .starts_with("HTTP/1.1 400")
    );
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap().unwrap();
}
