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
        "setup-code",
        "--name",
        "Pixel",
        "--kind",
        "phone",
        "--endpoint",
        "vpn.example.org:51820",
        "--agent",
        "codex",
        "--origin",
        "pc",
        "--session",
        "actual-session",
        "--job",
        "Enroll Pixel",
    ]
}
#[test]
fn setup_code_does_not_read_an_existing_device_ticket() {
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(args())
        .args(["--ticket", "/must-not-read"])
        .env("READB_CONFIG_DIR", "/must-not-read")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("setup_code_ticket_forbidden"));
}
#[test]
fn setup_code_uses_coordinator_actual_owner_and_preserves_blocked_status() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = std::env::temp_dir().join(format!("readb-onboard-cli-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let h = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match listener.accept() {
                Ok((mut s, _)) => {
                    let req =
                        readb::control::Request::parse(&readb::wire::line(&mut s, 4096).unwrap())
                            .unwrap();
                    assert_eq!(req.action, "device-setup-code");
                    assert_eq!(req.device, "pixel-new");
                    assert!(req.ticket.is_empty());
                    assert_eq!(req.owner.as_ref().unwrap().session, "actual-session");
                    assert_eq!(req.owner.as_ref().unwrap().job, "Enroll Pixel");
                    let body: serde_json::Value = serde_json::from_str(&req.args[0]).unwrap();
                    assert_eq!(body["client_session"], "actual-session");
                    assert!(body["report_port"].is_null());
                    readb::wire::frame(&mut s,2,b"{\"schema\":1,\"code\":\"setup_blocked\",\"blocker\":\"report_firewall_setup_required\"}").unwrap();
                    readb::wire::frame(&mut s, 3, b"{\"code\":78}").unwrap();
                    s.flush().unwrap();
                    return;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline);
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["--local", "--state-dir"])
        .arg(&root)
        .args(args())
        .output()
        .unwrap();
    h.join().unwrap();
    assert_eq!(o.status.code(), Some(78));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(combined.contains("report_firewall_setup_required"));
    fs::remove_dir_all(root).unwrap();
}
