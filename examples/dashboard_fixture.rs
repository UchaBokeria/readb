//! Local UI fixture. No real ADB, VPN, device or private configuration is used.
use readb::{
    backend::now,
    events::{self, Event},
    policy::{Owner, Receipt, random},
    registry::Registry,
    schema::ServerConfig,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
fn main() {
    let root = std::env::temp_dir().join(format!("readb-dashboard-fixture-{}", &random()[..12]));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = root.join("fixture-adb");
    fs::write(&adb,r#"#!/bin/sh
case "$*" in
*ro.serialno*) echo readb-fixture;;
*dumpsys*power*) printf 'mWakefulness=Awake\nmIsPowered=false\nmStayOn=true\n';;
*dumpsys*battery*) printf 'level: 88\ntemperature: 290\n';;
*getprop*model*) echo 'Fixture Android';;
*screencap*) printf 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' | base64 -d;;
*) echo 'Fixture command finished. No real device was used.';;
esac
"#).unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let pin = Sha256::digest(b"readb-fixture")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let config=ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":adb,"devices":[{"id":"lab-phone","name":"Lab phone (fixture)","kind":"phone","peer":"192.0.2.3","adb_port":5037,"token":"x".repeat(64),"identity":pin},{"id":"studio-quest","name":"Studio Quest (fixture)","kind":"quest","peer":"192.0.2.5","adb_port":5038,"token":"z".repeat(64),"identity":pin}]})).unwrap()).unwrap();
    let registry = Arc::new(Registry::new(config, root.join("state")).unwrap());
    fs::write(registry.root.join("dashboard-key"), "f".repeat(64)).unwrap();
    fs::set_permissions(
        registry.root.join("dashboard-key"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for (id, b) in registry.all() {
        let mut s = b.state.lock().unwrap();
        s.target = Some(40000);
        s.receipt = Receipt {
            received_at: now(),
            port: 40000,
            battery: if id == "lab-phone" { 88 } else { 62 },
            connected: true,
            identity_verified: true,
            transport_cleanup_failed: false,
        };
        drop(s);
        let _ = b.keepalive();
        for name in ["screencap", "getprop"] {
            events::append(
                &b.config.dir,
                &Event::new("complete", &random(), name, "view", "fixture-finished"),
            )
            .unwrap();
        }
    }
    let phone = registry.device("lab-phone").unwrap();
    phone
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "laptop fixture".into(),
                session: "ui-fixture".into(),
                job: "Layout checks (fixture)".into(),
                allow_sleep: false,
            },
            3600,
        )
        .unwrap();
    phone
        .watch(
            Owner {
                agent: "claude".into(),
                origin: "server fixture".into(),
                session: "ui-fixture".into(),
                job: "Watching logs (fixture)".into(),
                allow_sleep: false,
            },
            3600,
        )
        .unwrap();
    let status = readb::web::configure(registry.clone(), true, 0).unwrap();
    println!("Fixture only: {}", status["url"].as_str().unwrap());
    println!("Private fixture state: {}", registry.root.display());
    let rr = registry.clone();
    thread::spawn(move || {
        loop {
            for (_, b) in rr.all() {
                b.state.lock().unwrap().receipt.received_at = now();
                let _ = b.keepalive();
            }
            thread::sleep(Duration::from_secs(20));
        }
    });
    let stop = Arc::new(AtomicBool::new(false));
    let _ = &Ordering::SeqCst;
    readb::daemon::serve(registry, stop).unwrap();
}
