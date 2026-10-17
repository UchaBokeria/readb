use readb::adb_server::ManagedServer;
use std::{fs, net::TcpListener, os::unix::fs::PermissionsExt};
#[test]
fn manages_only_own_foreground_server_and_refuses_existing_listener() {
    let dir = std::env::temp_dir().join(format!("readb-adb-server-{}", readb::policy::random()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let fake = dir.join("adb");
    fs::write(&fake,"#!/usr/bin/env python3\nimport sys,socket,time,os\nif 'server' in sys.argv and 'nodaemon' in sys.argv:\n p=int(sys.argv[sys.argv.index('-L')+1].split(':')[1]);s=socket.socket(fileno=p);os.write(int(sys.argv[sys.argv.index('--reply-fd')+1]),bytes([79,75,10]));time.sleep(60)\nelif 'devices' in sys.argv: print('List of devices attached')\nelse: sys.exit(8)\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let occupied = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    assert!(ManagedServer::start(&fake, &dir, occupied.local_addr().unwrap().port()).is_err());
    // Allocate only after the occupied fixture: otherwise the OS may reuse the
    // just-released ephemeral port for that fixture itself.
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = ManagedServer::start(&fake, &dir, port).unwrap();
    assert!(server.running().unwrap());
    assert!(TcpListener::bind(("127.0.0.1", port)).is_err());
    unsafe {
        libc::kill(server.pid() as i32, libc::SIGKILL);
    }
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while server.running().unwrap() {
        assert!(std::time::Instant::now() < until);
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        TcpListener::bind(("127.0.0.1", port)).is_err(),
        "Dead child must not free the reservation for an unrelated server"
    );
    server.stop().unwrap();
    assert!(!server.running().unwrap());
    assert!(TcpListener::bind(("127.0.0.1", port)).is_ok());
    assert!(occupied.local_addr().is_ok());
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn an_exiting_launcher_never_counts_as_a_running_server() {
    let dir = std::env::temp_dir().join(format!("readb-adb-exit-{}", readb::policy::random()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ManagedServer::start(std::path::Path::new("/bin/true"), &dir, 55199).is_err());
    fs::remove_dir_all(dir).unwrap();
}
