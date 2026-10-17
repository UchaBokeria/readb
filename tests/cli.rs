use std::process::Command;
#[test]
fn help_and_completion_do_not_need_server_or_private_config() {
    for args in [
        vec!["--help"],
        vec!["device", "--help"],
        vec!["job", "--help"],
        vec!["context", "--help"],
        vec!["action", "--help"],
        vec!["service", "--help"],
        vec!["setup", "--help"],
        vec!["setup", "plan", "--help"],
        vec!["completion", "fish"],
    ] {
        let o = Command::new(env!("CARGO_BIN_EXE_readb"))
            .args(&args)
            .env("HOME", "/nonexistent")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{:?}: {}",
            args,
            String::from_utf8_lossy(&o.stderr)
        );
    }
}
#[test]
fn setup_requires_explicit_server_local_scope() {
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["setup", "plan", "--endpoint", "vpn.example.org:51820"])
        .env("HOME", "/nonexistent")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("setup_requires_explicit_--local_on_server")
    );
}
#[test]
fn direct_device_transport_has_no_client_fallback() {
    let o = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["--context", "missing", "device", "ls"])
        .env("HOME", "/nonexistent")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(!o.stderr.is_empty());
}

#[test]
fn cancelled_pair_prompt_restores_echo_and_flushes_unsubmitted_code() {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let mut slave = unsafe { File::from_raw_fd(slave) };
    let mut child = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args([
            "--local", "--device", "fixture", "device", "pair", "--port", "40001",
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    let mut observed = String::new();
    while !observed.contains("Pairing code:") {
        assert!(Instant::now() < until);
        let mut p = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut p, 1, 100) } > 0 {
            let mut buf = [0; 512];
            let n = master.read(&mut buf).unwrap();
            observed.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }
    master.write_all(b"123456").unwrap();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            assert_eq!(s.code(), Some(78));
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(slave.as_raw_fd(), term.as_mut_ptr()) },
        0
    );
    assert_ne!(unsafe { term.assume_init() }.c_lflag & libc::ECHO, 0);
    master.write_all(b"\n").unwrap();
    let mut buf = [0u8; 16];
    let n = slave.read(&mut buf).unwrap();
    assert_eq!(
        &buf[..n],
        b"\n",
        "unsubmitted pairing code leaked to the next terminal reader"
    );
}
