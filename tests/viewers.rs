use readb::{backend::*, policy::*};
use std::fs;
fn owner(job: &str) -> Owner {
    Owner {
        agent: "test".into(),
        origin: "fixture".into(),
        session: "one".into(),
        job: job.into(),
        allow_sleep: false,
    }
}
#[test]
fn viewers_share_with_one_controller_and_cannot_mutate() {
    let dir = std::env::temp_dir().join(format!("readb-viewers-{}", random()));
    fs::create_dir(&dir).unwrap();
    let b = Backend::new(Config {
        peer: "192.0.2.5".parse().unwrap(),
        adb_port: 5038,
        kind: readb::schema::Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb: "/no-adb".into(),
        token: "x".repeat(64),
        identity: "a".repeat(64),
        recipient: "1@s.whatsapp.net".into(),
    })
    .unwrap();
    let a = b.watch(owner("view-a"), 90).unwrap();
    let c = b.claim(owner("control"), 90).unwrap();
    let z = b.watch(owner("view-b"), 90).unwrap();
    assert!(b.claim(owner("second-controller"), 90).is_err());
    assert!(
        b.prepare(
            &a,
            vec![
                "shell".into(),
                "input".into(),
                "keyevent".into(),
                "3".into()
            ]
        )
        .err()
        .unwrap()
        .contains("observer")
    );
    b.heartbeat(&a).unwrap();
    b.release(&a).unwrap();
    b.release(&c).unwrap();
    b.release(&z).unwrap();
    assert_eq!(b.status()["viewers"].as_array().unwrap().len(), 0);
}
#[test]
fn screenshots_are_observers_but_device_file_writes_are_not() {
    assert!(is_pure(
        &["exec-out", "screencap", "-p"].map(str::to_string)
    ));
    assert!(!is_pure(
        &["shell", "screencap", "/sdcard/private.png"].map(str::to_string)
    ));
}
#[test]
fn only_controller_changes_persistent_keepalive_policy() {
    let dir = std::env::temp_dir().join(format!("readb-policy-{}", random()));
    fs::create_dir(&dir).unwrap();
    let config = Config {
        peer: "192.0.2.5".parse().unwrap(),
        adb_port: 5038,
        kind: readb::schema::Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb: "/no-adb".into(),
        token: "x".repeat(64),
        identity: "a".repeat(64),
        recipient: String::new(),
    };
    let b = Backend::new(config.clone()).unwrap();
    let v = b.watch(owner("viewer"), 90).unwrap();
    assert!(b.set_keepalive(&v, false, false).is_err());
    let c = b.claim(owner("settings"), 90).unwrap();
    b.set_keepalive(&c, false, false).unwrap();
    assert_eq!(b.status()["keepalive_policy"]["enabled"], false);
    assert_eq!(
        Backend::new(config).unwrap().status()["keepalive_policy"]["enabled"],
        false
    );
}
#[test]
fn viewer_renewal_stops_after_receipt_is_rejected() {
    let dir = std::env::temp_dir().join(format!("readb-rejected-{}", random()));
    fs::create_dir(&dir).unwrap();
    let b = Backend::new(Config {
        peer: "192.0.2.5".parse().unwrap(),
        adb_port: 5038,
        kind: readb::schema::Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb: "/no-adb".into(),
        token: "x".repeat(64),
        identity: "a".repeat(64),
        recipient: String::new(),
    })
    .unwrap();
    let t = b.watch(owner("rejected"), 90).unwrap();
    assert!(!b.running(&t, 0));
}
#[test]
fn server_file_writes_are_not_shared_observer_operations() {
    assert!(!is_pure(
        &["pull", "/sdcard/file", "/server/config"].map(str::to_string)
    ));
}
