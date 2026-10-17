use readb::{registry::*, schema::*};
use serde_json::json;
fn config() -> ServerConfig {
    ServerConfig::parse(&serde_json::to_vec(&json!({"schema":1,"adb":"/no-adb","devices":[{"id":"phone","name":"Phone","kind":"phone","peer":"192.0.2.3","adb_port":5037,"token":"x".repeat(64),"identity":"a".repeat(64)},{"id":"quest","name":"Quest","kind":"quest","peer":"192.0.2.5","adb_port":5038,"token":"z".repeat(64),"identity":"b".repeat(64)}]})).unwrap()).unwrap()
}
#[test]
fn device_scopes_are_independent_and_public_status_is_redacted() {
    let dir = std::env::temp_dir().join(format!("readb-registry-{}", readb::policy::random()));
    let r = Registry::new(config(), dir).unwrap();
    assert_eq!(r.status()["devices"].as_array().unwrap().len(), 2);
    assert!(r.device("missing").is_err());
    assert!(r.device("../quest").is_err());
    assert!(!r.status().to_string().contains(&"x".repeat(64)));
    let owner = |name: &str| readb::policy::Owner {
        agent: "test".into(),
        origin: "host".into(),
        session: "session".into(),
        job: name.into(),
        allow_sleep: false,
    };
    let a = r
        .device("quest")
        .unwrap()
        .claim(owner("quest-job"), 90)
        .unwrap();
    let b = r
        .device("phone")
        .unwrap()
        .claim(owner("phone-job"), 90)
        .unwrap();
    assert!(
        r.device("quest")
            .unwrap()
            .claim(owner("conflict"), 90)
            .is_err()
    );
    r.device("phone").unwrap().release(&b).unwrap();
    assert!(r.device("quest").unwrap().status()["job"].is_object());
    r.device("quest").unwrap().release(&a).unwrap();
}
#[test]
fn missing_config_parent_add_is_retryable_without_retained_directory() {
    let root = std::env::temp_dir().join(format!("readb-config-retry-{}", readb::policy::random()));
    let cfg = root.join("missing/server.json");
    let r = Registry::new_at(config(), root.join("state"), cfg.clone()).unwrap();
    let d:Device=serde_json::from_value(json!({"id":"new-phone","name":"New phone","kind":"phone","peer":"192.0.2.9","adb_port":5099,"token":"c".repeat(64)})).unwrap();
    assert!(r.add(d.clone(), None).is_err());
    assert!(!root.join("state/devices/new-phone").exists());
    std::fs::create_dir(cfg.parent().unwrap()).unwrap();
    r.add(d, None).unwrap();
    assert!(r.device("new-phone").is_ok());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn external_valid_config_edit_is_never_overwritten_by_add() {
    let root =
        std::env::temp_dir().join(format!("readb-registry-drift-{}", readb::policy::random()));
    let r = Registry::new(config(), root.clone()).unwrap();
    let d:Device=serde_json::from_value(json!({"id":"first","name":"First","kind":"phone","peer":"192.0.2.9","adb_port":5099,"token":"c".repeat(64)})).unwrap();
    r.add(d.clone(), None).unwrap();
    let mut edited = r.config();
    edited.devices[0].name = "Owner external edit".into();
    let bytes = serde_json::to_vec(&edited).unwrap();
    std::fs::write(&r.config_path, &bytes).unwrap();
    let mut second = d;
    second.id = "second".into();
    second.peer = "192.0.2.10".parse().unwrap();
    second.adb_port = 5100;
    assert!(
        r.add(second, None)
            .unwrap_err()
            .contains("catalog_external_change")
    );
    assert_eq!(std::fs::read(&r.config_path).unwrap(), bytes);
    assert!(!root.join("devices/second").exists());
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn legacy_formats_are_strict_and_device_bound() {
    assert_eq!(
        parse_report(br#"{"port":40000}"#, ReportFormat::LegacyPixel)
            .unwrap()
            .battery,
        -1
    );
    assert!(parse_report(br#"{"port":40000,"battery":50}"#, ReportFormat::LegacyPixel).is_err());
    assert!(parse_report(br#"{"port":40000,"battery":50}"#, ReportFormat::LegacyQuest).is_ok());
    assert!(
        parse_report(
            br#"{"schema":99,"port":40000,"battery":50}"#,
            ReportFormat::V1
        )
        .is_err()
    );
    assert!(
        parse_report(
            br#"{"schema":1,"port":40000,"battery":50}"#,
            ReportFormat::V1
        )
        .is_ok()
    );
}

#[test]
fn dynamic_add_remove_preserves_other_device_jobs_and_private_state() {
    let root =
        std::env::temp_dir().join(format!("readb-registry-edit-{}", readb::policy::random()));
    let r = Registry::new(config(), root.clone()).unwrap();
    let b = r.device("quest").unwrap();
    let owner = readb::policy::Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "fixture".into(),
        job: "working".into(),
        allow_sleep: false,
    };
    let ticket = b.claim(owner.clone(), 90).unwrap();
    let d: Device=serde_json::from_value(json!({"id":"new-phone","name":"Another phone","kind":"phone","peer":"192.0.2.4","adb_port":5039,"token":"y".repeat(64),"identity":"c".repeat(64)})).unwrap();
    r.add(d.clone(), None).unwrap();
    assert!(r.add(d, None).unwrap_err().contains("duplicate"));
    assert!(r.device("new-phone").is_ok());
    let persisted = ServerConfig::parse(&std::fs::read(root.join("server.json")).unwrap()).unwrap();
    assert_eq!(persisted.devices.len(), 3);
    let n = r.device("new-phone").unwrap();
    std::fs::write(n.config.dir.join("private-marker"), b"fixture").unwrap();
    let t = n.claim(owner, 90).unwrap();
    assert!(r.remove("new-phone", "wrong").is_err());
    r.remove("new-phone", &t).unwrap();
    assert!(r.device("new-phone").is_err());
    assert!(n.config.dir.join("private-marker").exists());
    assert!(
        n.claim(
            readb::policy::Owner {
                agent: "test".into(),
                origin: "host".into(),
                session: "s".into(),
                job: "old reference".into(),
                allow_sleep: false
            },
            90
        )
        .is_err()
    );
    assert!(b.status()["job"].is_object());
    b.release(&ticket).unwrap();
}

#[test]
fn large_status_reply_uses_multiple_frames_without_false_success() {
    use std::{io::Write, os::unix::net::UnixStream, sync::Arc, thread};
    let root = std::env::temp_dir().join(format!("readb-large-{}", readb::policy::random()));
    let r = Arc::new(Registry::new(config(), root).unwrap());
    for (_, b) in r.all() {
        for i in 0..16 {
            b.watch(
                readb::policy::Owner {
                    agent: "a".repeat(160),
                    origin: "o".repeat(160),
                    session: format!("{}{:02}", "s".repeat(158), i),
                    job: "j".repeat(160),
                    allow_sleep: false,
                },
                90,
            )
            .unwrap();
        }
    }
    // Pad history past the 64KiB single-frame limit through valid events.
    let b = r.device("quest").unwrap();
    for _ in 0..1000 {
        readb::events::append(
            &b.config.dir,
            &readb::events::Event::new("operation", "fixture", "getprop", "view", "finished"),
        )
        .unwrap();
    }
    let (mut client, server) = UnixStream::pair().unwrap();
    thread::spawn(move || readb::daemon::control_client(server, r));
    client
        .write_all(b"{\"action\":\"history\",\"args\":[\"1000\"]}\n")
        .unwrap();
    let mut data = Vec::new();
    loop {
        let (tag, bytes) = readb::wire::read_frame(&mut client).unwrap();
        if tag == 3 {
            break;
        }
        assert_eq!(tag, 1);
        data.extend(bytes);
    }
    let result: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert_eq!(result["events"].as_array().unwrap().len(), 1000);
}

#[test]
fn shutdown_rejects_late_registry_changes_and_dashboard_enable() {
    let root =
        std::env::temp_dir().join(format!("readb-shutdown-{}", &readb::policy::random()[..12]));
    let r = std::sync::Arc::new(Registry::new(config(), root).unwrap());
    r.shutdown().unwrap();
    let d:Device=serde_json::from_value(json!({"id":"late","name":"Late","kind":"phone","peer":"192.0.2.8","adb_port":5040,"token":"x".repeat(64)})).unwrap();
    assert!(r.add(d, None).unwrap_err().contains("shutdown"));
    assert!(readb::web::configure(r, true, 0).is_err());
}
