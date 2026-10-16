use readb::{control::*, policy::*};
#[test]
fn request_schema_bounded() {
    assert!(Request::parse(br#"{"action":"status"}"#).is_ok());
    assert!(Request::parse(br#"{"action":"exec","args":[],"extra":true}"#).is_err());
}
#[test]
fn remote_job_argv_validation() {
    assert!(
        Request::parse(br#"{"action":"exec","args":["shell","getprop"],"timeout":999999}"#)
            .is_err()
    );
}
#[test]
fn binary_control_stream_roundtrip() {
    use readb::{backend::*, wire::*};
    use std::{
        fs,
        io::Write,
        os::unix::{fs::PermissionsExt, net::UnixStream},
        sync::Arc,
        thread,
    };
    let dir = std::env::temp_dir().join(format!("quest-stream-{}", random()));
    fs::create_dir(&dir).unwrap();
    let adb = dir.join("adb");
    fs::write(&adb,"#!/bin/sh\ncase \"$*\" in\n*ro.serialno*) echo fixture;;\n*) printf '\\000\\377hi';;\nesac\n").unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    use sha2::{Digest, Sha256};
    let backend = Arc::new(
        Backend::new(Config {
            peer: "192.0.2.5".parse().unwrap(),
            adb_port: 5038,
            kind: readb::schema::Kind::Quest,
            keepalive: Default::default(),
            dir,
            adb,
            token: "x".repeat(64),
            identity: Sha256::digest(b"fixture")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            recipient: "1@s.whatsapp.net".into(),
        })
        .unwrap(),
    );
    {
        let mut s = backend.state.lock().unwrap();
        s.target = Some(40000);
        s.receipt = Receipt {
            received_at: now(),
            port: 40000,
            battery: 73,
            connected: true,
            identity_verified: true,
            transport_cleanup_failed: false,
        };
    }
    let token = backend
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "one".into(),
                job: "binary".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    let b = backend.clone();
    thread::spawn(move || handle(server, b));
    let req =
        serde_json::json!({"action":"exec","ticket":token,"args":["exec-out","screencap","-p"]});
    writeln!(client, "{req}").unwrap();
    frame(&mut client, 4, b"").unwrap();
    let mut out = Vec::new();
    loop {
        let (tag, data) = read_frame(&mut client).unwrap();
        if tag == 1 {
            out.extend_from_slice(&data)
        }
        if tag == 3 {
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&data).unwrap()["code"],
                0
            );
            break;
        }
    }
    assert_eq!(out, b"\0\xffhi");
    backend.release(&token).unwrap();
}
