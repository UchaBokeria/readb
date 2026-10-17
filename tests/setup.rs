use readb::setup::{Facts, NetworkMode, Options, build_plan};
use std::net::Ipv4Addr;

fn options() -> Options {
    Options {
        endpoint: "vpn.example.org:51820".into(),
        interface: "readb0".into(),
        address: Ipv4Addr::new(10, 88, 0, 1),
        prefix: 24,
        listen_port: 51820,
        mode: NetworkMode::Create,
    }
}
fn facts() -> Facts {
    Facts {
        os: "linux".into(),
        arch: "x86_64".into(),
        libc: "gnu".into(),
        init: "systemd".into(),
        adb: Some("/usr/bin/adb".into()),
        wg: true,
        wg_quick: true,
        ip: true,
        privilege: true,
        free_bytes: Some(2 * 1024 * 1024 * 1024),
        storage_writable: true,
        interface_exists: false,
        interface_wireguard: Some(true),
        interface_address_matches: Some(true),
        interface_listen_port: Some(51820),
        route_overlap: Some(false),
        port_in_use: Some(false),
    }
}
#[test]
fn clean_plan_is_stable_private_free_and_has_honest_scope() {
    let a = build_plan(options(), facts()).unwrap();
    let b = build_plan(options(), facts()).unwrap();
    assert!(a.ready);
    assert_eq!(a.plan_sha256, b.plan_sha256);
    assert!(!a.applied);
    let text = serde_json::to_string(&a).unwrap();
    assert!(!text.contains("private_key"));
    assert_eq!(*a.phases.last().unwrap(), "acceptance");
}
#[test]
fn missing_facts_and_network_conflicts_are_blockers() {
    let mut f = facts();
    f.adb = None;
    f.free_bytes = None;
    f.route_overlap = None;
    f.port_in_use = Some(true);
    f.privilege = false;
    let p = build_plan(options(), f).unwrap();
    assert!(!p.ready);
    for code in [
        "adb_missing",
        "disk_unknown",
        "routes_unknown",
        "udp_port_in_use",
        "privilege_missing",
    ] {
        assert!(p.blockers.iter().any(|b| b.code == code), "{code}");
    }
}
#[test]
fn existing_interface_requires_explicit_reuse_and_is_not_reprovisioned() {
    let mut f = facts();
    f.interface_exists = true;
    f.port_in_use = Some(true);
    f.route_overlap = Some(true);
    assert!(!build_plan(options(), f.clone()).unwrap().ready);
    let mut o = options();
    o.mode = NetworkMode::Reuse;
    let p = build_plan(o, f).unwrap();
    assert!(p.ready);
    assert_eq!(p.network_action, "inspect_existing_only");
    let mut missing = options();
    missing.mode = NetworkMode::Reuse;
    assert!(!build_plan(missing, facts()).unwrap().ready);
}
#[test]
fn invalid_inputs_fail_before_any_probe_or_mutation() {
    for endpoint in [
        "",
        "host",
        "-host:1",
        "host:0",
        "host:65536",
        "host:22\n",
        "host:22/path",
    ] {
        let mut o = options();
        o.endpoint = endpoint.into();
        assert!(build_plan(o, facts()).is_err(), "{endpoint:?}");
    }
    for interface in ["../mobile", "mobile;rm", "", "0123456789012345"] {
        let mut o = options();
        o.interface = interface.into();
        assert!(build_plan(o, facts()).is_err());
    }
    for address in [
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(10, 88, 0, 0),
        Ipv4Addr::new(10, 88, 0, 255),
    ] {
        let mut o = options();
        o.address = address;
        assert!(build_plan(o, facts()).is_err());
    }
}
#[test]
fn unsupported_platform_and_changed_plan_are_distinct() {
    let a = build_plan(options(), facts()).unwrap();
    let mut o = options();
    o.listen_port = 51821;
    assert_ne!(a.plan_sha256, build_plan(o, facts()).unwrap().plan_sha256);
    let mut f = facts();
    f.os = "other".into();
    f.arch = "unknown".into();
    f.init = "unknown".into();
    let p = build_plan(options(), f).unwrap();
    for code in [
        "linux_required",
        "architecture_unsupported",
        "init_unsupported",
    ] {
        assert!(p.blockers.iter().any(|b| b.code == code));
    }
}
#[test]
fn changing_observations_do_not_change_desired_plan_identity() {
    let a = build_plan(options(), facts()).unwrap();
    let mut f = facts();
    f.free_bytes = Some(1024 * 1024 * 1024);
    f.port_in_use = Some(true);
    let b = build_plan(options(), f).unwrap();
    assert_eq!(a.plan_sha256, b.plan_sha256);
    assert!(!b.ready);
}
#[test]
fn subnet_must_be_entirely_private() {
    for (address, prefix) in [
        (Ipv4Addr::new(172, 16, 0, 1), 8),
        (Ipv4Addr::new(192, 168, 1, 1), 8),
    ] {
        let mut o = options();
        o.address = address;
        o.prefix = prefix;
        assert!(build_plan(o, facts()).is_err());
    }
}
#[test]
fn reuse_requires_actual_wireguard_network_and_listener_evidence() {
    let mut o = options();
    o.mode = NetworkMode::Reuse;
    for (kind, address, port) in [
        (Some(false), Some(true), Some(51820)),
        (None, Some(true), Some(51820)),
        (Some(true), Some(false), Some(51820)),
        (Some(true), Some(true), Some(12345)),
        (Some(true), Some(true), None),
    ] {
        let mut f = facts();
        f.interface_exists = true;
        f.interface_wireguard = kind;
        f.interface_address_matches = address;
        f.interface_listen_port = port;
        assert!(!build_plan(o.clone(), f).unwrap().ready);
    }
}
#[test]
fn existing_regular_file_is_not_a_usable_home() {
    let path = std::env::temp_dir().join(format!("readb-home-file-{}", readb::policy::random()));
    std::fs::write(&path, b"fixture").unwrap();
    let p = readb::setup::inspect(options(), &path).unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!p.ready);
    assert!(p.blockers.iter().any(|b| b.code == "storage_not_writable"));
}
