use readb::{
    backend::atomic,
    client::{Context, Contexts},
    policy::random,
};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::Command,
    thread,
    time::{Duration, Instant},
};
#[test]
fn network_changes_use_selected_coordinator_and_private_controller_ticket() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for local in [true, false] {
        let root = std::env::temp_dir().join(format!("readb-netcli-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let ticket = root.join("ticket.json");
        atomic(&ticket, &serde_json::json!({"token":"t".repeat(64)})).unwrap();
        let context = Contexts {
            current: Some("fixture".into()),
            contexts: std::collections::BTreeMap::from([(
                "fixture".into(),
                Context {
                    ssh: None,
                    binary: "unused".into(),
                    state: root.clone(),
                },
            )]),
        };
        atomic(&root.join("contexts.json"), &context).unwrap();
        let listener = UnixListener::bind(root.join("control.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let h = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let r = readb::control::Request::parse(
                            &readb::wire::line(&mut s, 4096).unwrap(),
                        )
                        .unwrap();
                        assert_eq!(r.action, "network-enroll");
                        assert_eq!(r.device, "quest");
                        assert_eq!(r.ticket, "t".repeat(64));
                        assert_eq!(
                            r.args,
                            vec![format!("{}AAA=", "D".repeat(40)), "10.88.0.100".into()]
                        );
                        readb::wire::frame(&mut s, 1, b"{\"outcome\":\"applied\"}").unwrap();
                        readb::wire::frame(&mut s, 3, b"{\"code\":0}").unwrap();
                        s.flush().unwrap();
                        return;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "CLI did not use selected coordinator"
                        );
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_readb"));
        cmd.env("READB_CONFIG_DIR", &root);
        if local {
            cmd.args(["--local", "--state-dir"]).arg(&root);
        } else {
            cmd.args(["--context", "fixture"]);
        }
        let o = cmd
            .arg("--ticket")
            .arg(&ticket)
            .args([
                "network",
                "enroll",
                "--id",
                "quest",
                "--key",
                &format!("{}AAA=", "D".repeat(40)),
                "--address",
                "10.88.0.100",
            ])
            .output()
            .unwrap();
        h.join().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(!String::from_utf8_lossy(&o.stdout).contains(&"t".repeat(64)));
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn root_maintenance_never_falls_through_to_client_context() {
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["--context", "not-a-server", "network", "reconcile"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("network_requires_explicit_--local"));
}
#[test]
fn mismatched_device_is_rejected_before_transport() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args([
            "--local",
            "--state-dir",
            "/nonexistent-readb-fixture",
            "--device",
            "phone",
            "network",
            "rm",
            "quest",
        ])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("network_device_mismatch"));
}
