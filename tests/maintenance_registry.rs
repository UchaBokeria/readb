use readb::{
    policy::{Owner, random},
    registry::Registry,
    schema::ServerConfig,
};
use std::{
    fs,
    sync::{Arc, Barrier},
    thread,
};
fn owner() -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "fixture".into(),
        session: "maintenance".into(),
        job: "fixture job".into(),
        allow_sleep: true,
    }
}
fn registry() -> Registry {
    let root = std::env::temp_dir().join(format!("readb-maint-reg-{}", random()));
    let c=ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":"/not-executed","devices":[{"id":"phone","name":"Fixture","kind":"phone","peer":"10.88.0.100","adb_port":5058,"token":"x".repeat(64)}]})).unwrap()).unwrap();
    Registry::new(c, root).unwrap()
}
#[test]
fn maintenance_requires_no_leases_and_blocks_cached_backends_until_exact_resume() {
    let r = registry();
    let b = r.device("phone").unwrap();
    let config = r.config_fingerprint().unwrap();
    let tag = "a".repeat(64);
    let ticket = b.claim(owner(), 90).unwrap();
    assert!(r.prepare_maintenance(&tag, &config).is_err());
    b.release(&ticket).unwrap();
    let view = b.watch(owner(), 90).unwrap();
    assert!(r.prepare_maintenance(&tag, &config).is_err());
    b.release(&view).unwrap();
    r.prepare_maintenance(&tag, &config).unwrap();
    r.prepare_maintenance(&tag, &config).unwrap();
    assert!(b.claim(owner(), 90).unwrap_err().contains("maintenance"));
    assert!(b.watch(owner(), 90).is_err());
    assert!(b.keepalive().is_err());
    assert!(r.status()["maintenance"].is_object());
    assert!(r.resume_maintenance(&"c".repeat(64), &config).is_err());
    r.resume_maintenance(&tag, &config).unwrap();
    assert!(r.status()["maintenance"].is_null());
    let t = b.claim(owner(), 90).unwrap();
    b.release(&t).unwrap();
    fs::remove_dir_all(&r.root).unwrap();
}
#[test]
fn marker_refresh_covers_startup_and_constructor_before_runtime_lock_race() {
    let r = registry();
    let b = r.device("phone").unwrap();
    let config = r.config_fingerprint().unwrap();
    let tag = "a".repeat(64);
    readb::maintenance::Store::open(&r.root)
        .unwrap()
        .publish(&readb::maintenance::Marker::new(&tag, &config).unwrap())
        .unwrap();
    r.refresh_maintenance().unwrap();
    assert!(b.claim(owner(), 90).is_err());
    let fresh = Registry::new_at(r.config(), r.root.clone(), r.config_path.clone()).unwrap();
    assert!(fresh.status()["maintenance"].is_object());
    assert!(fresh.device("phone").unwrap().claim(owner(), 90).is_err());
    fresh.resume_maintenance(&tag, &config).unwrap();
    fs::remove_dir_all(&r.root).unwrap();
}
#[test]
fn claim_race_never_grants_both_maintenance_and_a_job() {
    for _ in 0..24 {
        let r = Arc::new(registry());
        let b = r.device("phone").unwrap();
        let config = r.config_fingerprint().unwrap();
        let tag = "a".repeat(64);
        let start = Arc::new(Barrier::new(2));
        let ready = start.clone();
        let backend = b.clone();
        let h = thread::spawn(move || {
            ready.wait();
            backend.claim(owner(), 90)
        });
        start.wait();
        let prepared = r.prepare_maintenance(&tag, &config);
        let claimed = h.join().unwrap();
        assert!(!(prepared.is_ok() && claimed.is_ok()));
        if prepared.is_ok() {
            assert!(claimed.is_err());
            r.resume_maintenance(&tag, &config).unwrap();
        } else {
            let t = claimed.unwrap();
            assert!(!r.root.join("upgrade-maintenance.json").exists());
            b.release(&t).unwrap();
        }
        fs::remove_dir_all(&r.root).unwrap();
    }
}
#[test]
fn resume_never_resurrects_shutdown_or_overwrites_config_drift() {
    let r = registry();
    let config = r.config_fingerprint().unwrap();
    let tag = "a".repeat(64);
    r.prepare_maintenance(&tag, &config).unwrap();
    r.shutdown().unwrap();
    assert!(r.resume_maintenance(&tag, &config).is_err());
    assert!(r.root.join("upgrade-maintenance.json").exists());
    fs::remove_dir_all(&r.root).unwrap();
    let r = registry();
    let config = r.config_fingerprint().unwrap();
    r.prepare_maintenance(&tag, &config).unwrap();
    fs::write(&r.config_path, b"changed externally").unwrap();
    assert!(r.resume_maintenance(&tag, &config).is_err());
    assert!(r.device("phone").unwrap().claim(owner(), 90).is_err());
    assert_eq!(fs::read(&r.config_path).unwrap(), b"changed externally");
    fs::remove_dir_all(&r.root).unwrap();
}
#[test]
fn runtime_refresh_cannot_force_an_active_job_into_maintenance() {
    let r = registry();
    let b = r.device("phone").unwrap();
    let config = r.config_fingerprint().unwrap();
    let tag = "a".repeat(64);
    let ticket = b.claim(owner(), 90).unwrap();
    readb::maintenance::Store::open(&r.root)
        .unwrap()
        .publish(&readb::maintenance::Marker::new(&tag, &config).unwrap())
        .unwrap();
    let refreshed = r.refresh_maintenance();
    b.release(&ticket).unwrap();
    fs::remove_dir_all(&r.root).unwrap();
    assert!(
        refreshed.is_err(),
        "startup refresh must not close active runtime admission"
    );
}

fn rpc(r: Arc<Registry>, request: serde_json::Value) -> (i32, serde_json::Value) {
    use std::{io::Write, os::unix::net::UnixStream};
    let (mut client, server) = UnixStream::pair().unwrap();
    let h = thread::spawn(move || readb::daemon::control_client(server, r));
    writeln!(client, "{request}").unwrap();
    let (_, bytes) = readb::wire::read_frame(&mut client).unwrap();
    let value = serde_json::from_slice(&bytes).unwrap();
    let (_, bytes) = readb::wire::read_frame(&mut client).unwrap();
    let end: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    h.join().unwrap();
    (end["code"].as_i64().unwrap() as i32, value)
}
#[test]
fn maintenance_rpc_requires_exact_server_scope_and_keeps_diagnosis_available() {
    use serde_json::json;
    let r = Arc::new(registry());
    let config = r.config_fingerprint().unwrap();
    let tag = "a".repeat(64);
    let (_, status) = rpc(r.clone(), json!({"action":"status"}));
    assert_eq!(status["config_fingerprint"], config);
    for request in [
        json!({"action":"maintenance-prepare","args":[tag,config],"device":"phone"}),
        json!({"action":"maintenance-prepare","args":[tag]}),
        json!({"action":"maintenance-prepare","args":[tag,"b".repeat(64)]}),
    ] {
        assert_ne!(rpc(r.clone(), request).0, 0);
        assert!(r.status()["maintenance"].is_null());
    }
    assert_eq!(
        rpc(
            r.clone(),
            json!({"action":"maintenance-prepare","args":[tag,config]})
        )
        .0,
        0
    );
    assert!(rpc(r.clone(), json!({"action":"status"})).1["maintenance"].is_object());
    assert_ne!(
        rpc(
            r.clone(),
            json!({"action":"maintenance-resume","args":["c".repeat(64),config]})
        )
        .0,
        0
    );
    assert_eq!(
        rpc(
            r.clone(),
            json!({"action":"maintenance-resume","args":[tag,config]})
        )
        .0,
        0
    );
    assert!(r.status()["maintenance"].is_null());
    fs::remove_dir_all(&r.root).unwrap();
}
