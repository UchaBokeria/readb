use readb::{backend::*, control::handle, policy::*, wire::*};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
fn setup() -> (Arc<Backend>, String) {
    let dir = std::env::temp_dir().join(format!("quest-lifecycle-{}", random()));
    fs::create_dir(&dir).unwrap();
    static FIXTURE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let adb = FIXTURE
        .get_or_init(|| {
            let d = std::env::temp_dir().join(format!("quest-lifecycle-program-{}", random()));
            fs::create_dir(&d).unwrap();
            let adb = d.join("adb");
            fs::write(
                &adb,
                r##"#!/bin/sh
case "$*" in
*ro.serialno*) echo fixture;;
*) echo $$ > "${ADB_VENDOR_KEYS%/*}/started.tmp"; mv "${ADB_VENDOR_KEYS%/*}/started.tmp" "${ADB_VENDOR_KEYS%/*}/started"; exec sleep 30;;
esac
"##,
            )
            .unwrap();
            fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
            adb
        })
        .clone();
    let b = Arc::new(
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
                .map(|v| format!("{v:02x}"))
                .collect(),
            recipient: "1@s.whatsapp.net".into(),
        })
        .unwrap(),
    );
    {
        let mut s = b.state.lock().unwrap();
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
    let t = b.claim(owner("first"), 90).unwrap();
    (b, t)
}
fn owner(job: &str) -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "fixture".into(),
        job: job.into(),
        allow_sleep: false,
    }
}
fn start(b: Arc<Backend>, t: &str, timeout: u64) -> (UnixStream, thread::JoinHandle<()>) {
    let (mut c, s) = UnixStream::pair().unwrap();
    let h = thread::spawn(move || handle(s, b));
    writeln!(c,"{}",serde_json::json!({"action":"exec","ticket":t,"timeout":timeout,"args":["shell","input","keyevent","3"]})).unwrap();
    frame(&mut c, 4, b"").unwrap();
    (c, h)
}
fn started(b: &Backend) -> i32 {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Ok(p) = fs::read_to_string(b.config.dir.join(".android/started")) {
            return p.trim().parse().unwrap();
        }
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(10));
    }
}
fn finished(b: &Backend) {
    let until = Instant::now() + Duration::from_secs(4);
    while b.status()["operation_running"] == true {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn disconnect_after_stdin_eof_cancels_child_and_fences_remote_uncertainty() {
    let (b, t) = setup();
    let (c, h) = start(b.clone(), &t, 20);
    let pid = started(&b);
    drop(c);
    finished(&b);
    h.join().unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert!(b.status()["cleanup_unknown"].is_string());
    assert!(b.claim(owner("second"), 90).is_err());
    assert!(Backend::new(b.config.clone()).unwrap().status()["cleanup_unknown"].is_string());
}
#[test]
fn timeout_and_explicit_cancel_do_not_release_unknown_device_work() {
    for cancel in [false, true] {
        let (b, t) = setup();
        let (mut c, h) = start(b.clone(), &t, 1);
        let pid = started(&b);
        if cancel {
            b.cancel(&t).unwrap();
        }
        loop {
            let (tag, data) = read_frame(&mut c).unwrap();
            if tag == 3 {
                let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
                assert_ne!(v["code"], 0);
                break;
            }
        }
        h.join().unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert!(b.status()["cleanup_unknown"].is_string());
        assert!(b.release(&t).is_err());
    }
}
#[test]
fn rotation_during_active_command_fences_old_generation() {
    let (b, t) = setup();
    let (mut c, h) = start(b.clone(), &t, 20);
    started(&b);
    assert!(
        !b.report(Report {
            port: 40001,
            battery: 73
        })
        .unwrap()
    );
    loop {
        if read_frame(&mut c).unwrap().0 == 3 {
            break;
        }
    }
    h.join().unwrap();
    assert_eq!(b.status()["connected"], false);
    assert!(b.status()["cleanup_unknown"].is_string());
    assert!(b.claim(owner("second"), 90).is_err());
}
#[test]
fn shutdown_cancels_existing_process_and_rejects_late_requests() {
    let (b, t) = setup();
    let (mut c, h) = start(b.clone(), &t, 20);
    started(&b);
    b.begin_shutdown().unwrap();
    assert!(
        b.claim(owner("queued"), 90)
            .unwrap_err()
            .contains("shutdown")
    );
    loop {
        if read_frame(&mut c).unwrap().0 == 3 {
            break;
        }
    }
    h.join().unwrap();
    assert_eq!(b.status()["stopping"], true);
    assert_eq!(b.status()["operation_running"], false);
}
#[test]
fn disconnected_stdin_backpressure_does_not_keep_silent_job_alive() {
    let (b, t) = setup();
    let (mut c, s) = UnixStream::pair().unwrap();
    let bb = b.clone();
    let h = thread::spawn(move || handle(s, bb));
    writeln!(c,"{}",serde_json::json!({"action":"exec","ticket":t,"timeout":20,"args":["shell","input","keyevent","3"]})).unwrap();
    started(&b);
    c.set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    for _ in 0..100 {
        if frame(&mut c, 0, &[0; 65536]).is_err() {
            break;
        }
    }
    drop(c);
    finished(&b);
    h.join().unwrap();
    assert!(b.status()["cleanup_unknown"].is_string());
}
#[test]
fn two_real_observer_commands_run_while_controller_owns_device() {
    let (b, control) = setup();
    let a = b.watch(owner("read-a"), 90).unwrap();
    let z = b.watch(owner("read-z"), 90).unwrap();
    let mut handles = Vec::new();
    for t in [&a, &z] {
        let (mut c, s) = UnixStream::pair().unwrap();
        let bb = b.clone();
        let h = thread::spawn(move || handle(s, bb));
        writeln!(c,"{}",serde_json::json!({"action":"exec","ticket":t,"timeout":10,"args":["exec-out","screencap","-p"]})).unwrap();
        frame(&mut c, 4, b"").unwrap();
        handles.push((c, h));
    }
    let until = Instant::now() + Duration::from_secs(3);
    while b.status()["viewers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["active"] == true)
        .count()
        != 2
    {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(b.claim(owner("second-controller"), 90).is_err());
    let _reserved = b
        .prepare(
            &control,
            ["shell", "input", "keyevent", "3"]
                .map(str::to_string)
                .to_vec(),
        )
        .unwrap();
    b.complete_for(&control, false);
    b.release(&control).unwrap();
    b.cancel(&a).unwrap();
    b.cancel(&z).unwrap();
    for (mut c, h) in handles {
        loop {
            if read_frame(&mut c).unwrap().0 == 3 {
                break;
            }
        }
        h.join().unwrap();
    }
    assert!(
        b.status()["viewers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["active"] == false)
    );
}
