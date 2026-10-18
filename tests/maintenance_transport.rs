// Separate process: fork/exec fixtures can briefly inherit other tests' flock FDs.
use readb::{policy::random, registry::Registry, schema::ServerConfig};
use std::{fs, thread};
#[test]
fn prepare_excludes_keeper_after_it_drops_the_state_lock() {
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::PermissionsExt,
        time::{Duration, Instant},
    };
    let outer = std::env::temp_dir().join(format!("readb-maint-transport-{}", random()));
    fs::create_dir(&outer).unwrap();
    fs::set_permissions(&outer, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = outer.join("adb");
    let entered = outer.join("entered");
    let release = outer.join("release");
    fs::write(&adb,format!("#!/bin/sh\n: > '{}'\nwhile [ ! -e '{}' ]; do /usr/bin/sleep .01; done\nprintf fixture\n",entered.display(),release.display())).unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let pin = Sha256::digest(b"fixture")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let c=ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":adb,"devices":[{"id":"phone","name":"Fixture","kind":"phone","peer":"10.88.0.100","adb_port":5058,"token":"x".repeat(64),"identity":pin}]})).unwrap()).unwrap();
    let r = Registry::new(c, outer.join("server")).unwrap();
    let b = r.device("phone").unwrap();
    b.state.lock().unwrap().receipt = readb::policy::Receipt {
        received_at: readb::backend::now(),
        port: 40000,
        battery: 60,
        connected: true,
        identity_verified: true,
        transport_cleanup_failed: false,
    };
    let backend = b.clone();
    let h = thread::spawn(move || backend.keepalive());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !entered.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let did_enter = entered.exists();
    let config = r.config_fingerprint().unwrap();
    let prepared = r.prepare_maintenance(&"a".repeat(64), &config);
    fs::write(&release, b"release").unwrap();
    let result = h.join().unwrap();
    assert!(did_enter, "fake keeper never reached transport");
    assert!(result.is_ok());
    assert!(prepared.unwrap_err().contains("transport_busy"));
    assert!(!r.root.join("upgrade-maintenance.json").exists());
    fs::remove_dir_all(outer).unwrap();
}
