use readb::{
    backend::now,
    policy::{Receipt, random},
    registry::Registry,
    schema::ServerConfig,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
#[test]
fn real_cli_daemon_protocol_claim_views_binary_and_release() {
    let root = std::env::temp_dir().join(format!("readb-cli-e2e-{}", random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = root.join("adb");
    fs::write(&adb,"#!/bin/sh\ncase \"$*\" in\n*keygen*) printf 'fixture private key' > \"$6\";;\n*pair*) read code; test \"$code\" = \"123456\" || exit 1; echo paired;;\n*disconnect*) echo disconnected;;\n*connect*) echo connected to 192.0.2.8:40000;;\n*devices) printf 'List of devices attached\\n';;\n*ro.serialno*) echo fixture;;\n*) printf '\\000\\377hi';;\nesac\n").unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
    let pin = Sha256::digest(b"fixture")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let config=ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":adb,"devices":[{"id":"quest","name":"Fixture","kind":"quest","peer":"192.0.2.5","adb_port":5038,"token":"x".repeat(64),"identity":pin}]})).unwrap()).unwrap();
    let registry = Arc::new(Registry::new(config, root.join("server")).unwrap());
    {
        let b = registry.device("quest").unwrap();
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
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let r = registry.clone();
    let h = thread::spawn(move || readb::daemon::serve(r, flag));
    for _ in 0..100 {
        if root.join("server/control.sock").exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let call = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_readb"))
            .args([
                "--local",
                "--state-dir",
                root.join("server").to_str().unwrap(),
            ])
            .args(args)
            .env("READB_CONFIG_DIR", root.join("client"))
            .output()
            .unwrap()
    };
    let claim = |mode: &str, name: &str| {
        let o = call(&[
            "--device",
            "quest",
            "job",
            "claim",
            "--agent",
            "test",
            "--origin",
            "host",
            "--session",
            "e2e",
            "--job",
            name,
            "--mode",
            mode,
        ]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        serde_json::from_slice::<serde_json::Value>(&o.stdout).unwrap()
    };
    let c = claim("control", "controller");
    {
        use std::io::Write;
        use std::process::Stdio;
        let mut pair = Command::new(env!("CARGO_BIN_EXE_readb"))
            .args([
                "--local",
                "--state-dir",
                root.join("server").to_str().unwrap(),
                "--device",
                "quest",
                "--ticket",
                c["ticket_path"].as_str().unwrap(),
                "device",
                "pair",
                "--port",
                "40001",
            ])
            .env("READB_CONFIG_DIR", root.join("client"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        pair.stdin.take().unwrap().write_all(b"123456\n").unwrap();
        let result = pair.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("paired"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("123456"));
    }
    let a = claim("view", "viewer-one");
    let z = claim("view", "viewer-two");
    let loser = call(&[
        "--device",
        "quest",
        "job",
        "claim",
        "--agent",
        "test",
        "--origin",
        "other",
        "--session",
        "e2e",
        "--job",
        "loser",
    ]);
    assert_eq!(loser.status.code(), Some(73));
    assert!(String::from_utf8_lossy(&loser.stderr).contains("controller"));
    let pic = call(&[
        "--device",
        "quest",
        "--ticket",
        a["ticket_path"].as_str().unwrap(),
        "exec",
        "--",
        "exec-out",
        "screencap",
        "-p",
    ]);
    assert!(
        pic.status.success(),
        "{}",
        String::from_utf8_lossy(&pic.stderr)
    );
    assert_eq!(pic.stdout, b"\0\xffhi");
    let forbidden = call(&[
        "--device",
        "quest",
        "--ticket",
        a["ticket_path"].as_str().unwrap(),
        "exec",
        "--",
        "shell",
        "input",
        "keyevent",
        "3",
    ]);
    assert_eq!(forbidden.status.code(), Some(73));
    assert!(String::from_utf8_lossy(&forbidden.stderr).contains("observer"));
    for v in [a, z, c] {
        let o = call(&[
            "--device",
            "quest",
            "--ticket",
            v["ticket_path"].as_str().unwrap(),
            "job",
            "release",
        ]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let history = call(&["history", "--limit", "5"]);
    assert!(history.status.success());
    let history: serde_json::Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(!history["events"].as_array().unwrap().is_empty());
    assert!(history["events"].as_array().unwrap().len() <= 5);
    assert!(
        !serde_json::to_string(&history)
            .unwrap()
            .contains("ticket_path")
    );
    let logs = call(&["--device", "quest", "logs", "--tail", "3"]);
    assert!(
        logs.status.success(),
        "{}",
        String::from_utf8_lossy(&logs.stderr)
    );
    for line in String::from_utf8(logs.stdout).unwrap().lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["device"], "quest");
    }
    let future = call(&["logs", "--since", "9999999999"]);
    assert!(future.status.success());
    assert!(future.stdout.is_empty());
    assert!(!call(&["history", "--limit", "0"]).status.success());
    let import = root.join("new-device.json");
    fs::write(&import,serde_json::to_vec(&serde_json::json!({"device":{"id":"other","name":"Other","kind":"phone","peer":"192.0.2.8","adb_port":5040,"token":"y".repeat(64),"identity":""},"listener":null})).unwrap()).unwrap();
    fs::set_permissions(&import, fs::Permissions::from_mode(0o600)).unwrap();
    let added = call(&["device", "add", "--file", import.to_str().unwrap()]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(!String::from_utf8_lossy(&added.stdout).contains(&"y".repeat(64)));
    let ids = call(&["device", "ls", "-q"]);
    assert_eq!(String::from_utf8(ids.stdout).unwrap(), "quest\nother\n");
    let t = call(&[
        "--device",
        "other",
        "job",
        "claim",
        "--agent",
        "test",
        "--origin",
        "host",
        "--session",
        "s",
        "--job",
        "remove",
    ]);
    assert!(t.status.success());
    let t: serde_json::Value = serde_json::from_slice(&t.stdout).unwrap();
    let ticket = t["ticket_path"].as_str().unwrap();
    let probe = call(&[
        "--device", "other", "--ticket", ticket, "device", "connect", "--port", "40000",
    ]);
    assert!(
        probe.status.success(),
        "{}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let probe: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
    let fingerprint = probe["fingerprint"].as_str().unwrap();
    assert!(
        !call(&[
            "--device",
            "other",
            "--ticket",
            ticket,
            "device",
            "trust",
            "--fingerprint",
            fingerprint
        ])
        .status
        .success()
    );
    let trusted = call(&[
        "--device",
        "other",
        "--ticket",
        ticket,
        "device",
        "trust",
        "--fingerprint",
        fingerprint,
        "--yes",
    ]);
    assert!(
        trusted.status.success(),
        "{}",
        String::from_utf8_lossy(&trusted.stderr)
    );
    assert!(
        registry
            .device("other")
            .unwrap()
            .report(readb::policy::Report {
                port: 40000,
                battery: 70
            })
            .unwrap()
    );
    let disconnected = call(&[
        "--device",
        "other",
        "--ticket",
        ticket,
        "device",
        "disconnect",
    ]);
    assert!(disconnected.status.success());
    let disconnected: serde_json::Value = serde_json::from_slice(&disconnected.stdout).unwrap();
    assert_eq!(disconnected["paused"], true);

    assert!(
        !call(&["--device", "other", "device", "rm", "--yes"])
            .status
            .success()
    );
    assert!(
        call(&[
            "--device",
            "other",
            "--ticket",
            t["ticket_path"].as_str().unwrap(),
            "device",
            "rm",
            "--yes"
        ])
        .status
        .success()
    );
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap().unwrap();
}
