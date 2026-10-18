use readb::{adb_server::ManagedServer, enrollment_ports::Ports};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
};
fn free() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[test]
fn reservations_hold_exact_ports_and_refuse_unowned_or_wildcard_bindings() {
    let adb = free();
    let report: SocketAddr = format!("127.0.0.1:{}", free()).parse().unwrap();
    let mut ports = Ports::reserve(adb, report, None).unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, adb)).is_err());
    assert!(TcpListener::bind(report).is_err());
    assert!(Ports::reserve(adb, report, None).is_err());
    let report_fd = ports.take_report().unwrap();
    assert_eq!(report_fd.local_addr().unwrap(), report);
    assert!(ports.take_report().is_err());
    let adb_fd = ports.take_adb().unwrap();
    assert_eq!(adb_fd.local_addr().unwrap().port(), adb);
    assert!(ports.take_adb().is_err());
    drop(ports);
    assert!(TcpListener::bind(report).is_err());
    drop(report_fd);
    drop(adb_fd);
    assert!(Ports::reserve(free(), "0.0.0.0:19199".parse().unwrap(), None).is_err());
}
#[test]
fn sharing_requires_the_exact_owned_listener_and_clones_keep_it_reserved() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let exact = listener.local_addr().unwrap();
    let ports = Ports::reserve(free(), exact, Some(&listener)).unwrap();
    drop(listener);
    assert!(TcpListener::bind(exact).is_err());
    drop(ports);
    assert!(TcpListener::bind(exact).is_ok());
    let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(Ports::reserve(free(), exact, Some(&other)).is_err());
}
#[test]
fn reserved_adb_descriptor_moves_to_owned_server_without_rebinding() {
    let dir = std::env::temp_dir().join(format!("readb-enroll-adb-{}", readb::policy::random()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let fake = dir.join("adb");
    fs::write(&fake,"#!/usr/bin/env python3\nimport sys,socket,time,os\nif 'server' in sys.argv:\n s=socket.socket(fileno=3);os.write(4,b'OK\\n');time.sleep(60)\nelse: print('List of devices attached')\n").unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = free();
    let report = format!("127.0.0.1:{}", free()).parse().unwrap();
    let mut ports = Ports::reserve(adb, report, None).unwrap();
    let mut server =
        ManagedServer::start_reserved(&fake, &dir, adb, ports.take_adb().unwrap()).unwrap();
    assert!(server.running().unwrap());
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, adb)).is_err());
    drop(ports);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, adb)).is_err());
    server.stop().unwrap();
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, adb)).is_ok());
    let wrong = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(ManagedServer::start_reserved(&fake, &dir, adb, wrong).is_err());
    fs::remove_dir_all(dir).unwrap();
}
