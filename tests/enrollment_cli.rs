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
fn args() -> Vec<&'static str> {
    vec![
        "--device",
        "pixel-new",
        "device",
        "enroll",
        "--name",
        "Pixel",
        "--kind",
        "phone",
        "--endpoint",
        "vpn.example.org:51820",
        "--report-port",
        "19193",
    ]
}
#[test]
fn apply_and_authority_are_rejected_before_context_or_ticket_reads() {
    for extra in [vec![], vec!["--dry-run", "--ticket", "/must-not-read"]] {
        let o = Command::new(env!("CARGO_BIN_EXE_readb"))
            .env("READB_CONFIG_DIR", "/must-not-read")
            .args(args())
            .args(&extra)
            .output()
            .unwrap();
        assert!(!o.status.success());
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(
            e.contains(if extra.is_empty() {
                "enrollment_dry_run_required"
            } else {
                "enrollment_preview_ticket_forbidden"
            }),
            "{e}"
        );
    }
}
#[test]
fn preview_uses_selected_coordinator_without_a_controller_ticket() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for local in [true, false] {
        let root = std::env::temp_dir().join(format!("readb-enrollcli-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        atomic(
            &root.join("contexts.json"),
            &Contexts {
                current: Some("fixture".into()),
                contexts: std::collections::BTreeMap::from([(
                    "fixture".into(),
                    Context {
                        ssh: None,
                        binary: "unused".into(),
                        state: root.clone(),
                    },
                )]),
            },
        )
        .unwrap();
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
                        assert_eq!(r.action, "device-enroll-preview");
                        assert_eq!(r.device, "pixel-new");
                        assert!(r.ticket.is_empty() && r.owner.is_none() && !r.observe);
                        assert_eq!(r.args.len(), 1);
                        let request: readb::enrollment_profile::Request =
                            serde_json::from_str(&r.args[0]).unwrap();
                        request.validate().unwrap();
                        assert_eq!(request.name, "Pixel");
                        assert_eq!(request.report_port, 19193);
                        readb::wire::frame(&mut s,1,b"{\"dry_run\":true,\"can_apply\":false,\"profile_deliverable\":false,\"blockers\":[\"report_firewall_setup_required\"]}").unwrap();
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
        let o = cmd.args(args()).arg("--dry-run").output().unwrap();
        h.join().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["can_apply"], false);
        fs::remove_dir_all(root).unwrap();
    }
}
