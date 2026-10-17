use readb::{
    network::{Policy, Snapshot},
    setup::{NetworkMode, Options},
    setup_apply::{Owner, bind},
};
use std::{collections::BTreeMap, path::PathBuf};
fn owner() -> Owner {
    Owner {
        name: "tester".into(),
        uid: 1000,
        gid: 1000,
        home: PathBuf::from("/home/tester"),
    }
}
fn options() -> Options {
    Options {
        endpoint: "vpn.example.org:51820".into(),
        interface: "mobile".into(),
        address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        listen_port: 51820,
        mode: NetworkMode::Reuse,
    }
}
fn policy() -> Policy {
    Policy {
        schema: 1,
        uid: 1000,
        interface: "mobile".into(),
        server_key: format!("{}AAA=", "E".repeat(40)),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.100".parse().unwrap(),
        last: "10.88.0.110".parse().unwrap(),
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        server_key: policy().server_key,
        addresses: vec!["10.88.0.1/24".into()],
        peers: BTreeMap::from([(
            format!("{}AAA=", "F".repeat(40)),
            vec!["10.88.0.5/32".into(), "fd00::5/128".into()],
        )]),
    }
}
#[test]
fn owner_home_binary_range_and_endpoint_are_bound() {
    let a = bind(options(), owner(), policy(), snapshot(), b"binary").unwrap();
    assert_eq!(
        a.plan_sha256,
        bind(options(), owner(), policy(), snapshot(), b"binary")
            .unwrap()
            .plan_sha256
    );
    let mut o = owner();
    o.home = "/home/other".into();
    assert_ne!(
        a.plan_sha256,
        bind(options(), o, policy(), snapshot(), b"binary")
            .unwrap()
            .plan_sha256
    );
    assert_ne!(
        a.plan_sha256,
        bind(options(), owner(), policy(), snapshot(), b"new-binary")
            .unwrap()
            .plan_sha256
    );
    let mut p = policy();
    p.last = "10.88.0.111".parse().unwrap();
    assert_ne!(
        a.plan_sha256,
        bind(options(), owner(), p, snapshot(), b"binary")
            .unwrap()
            .plan_sha256
    );
    let mut opt = options();
    opt.endpoint = "other.example.org:51820".into();
    assert_ne!(
        a.plan_sha256,
        bind(opt, owner(), policy(), snapshot(), b"binary")
            .unwrap()
            .plan_sha256
    );
    let text = serde_json::to_string(&a).unwrap();
    assert!(text.contains("devices_accepted\":false"));
    assert!(!text.contains("private_key"));
}
#[test]
fn refuses_root_unsafe_owner_or_mismatched_policy() {
    for uid in [0, u32::MAX] {
        let mut o = owner();
        o.uid = uid;
        assert!(bind(options(), o, policy(), snapshot(), b"b").is_err());
    }
    let mut o = owner();
    o.gid = 0;
    assert!(bind(options(), o, policy(), snapshot(), b"b").is_err());
    for home in ["/", "relative", "/home/../root", "/home/bad\n"] {
        let mut o = owner();
        o.home = home.into();
        assert!(bind(options(), o, policy(), snapshot(), b"b").is_err());
    }
    let mut p = policy();
    p.uid = 1001;
    assert!(bind(options(), owner(), p, snapshot(), b"b").is_err());
    let mut p = policy();
    p.interface = "other".into();
    assert!(bind(options(), owner(), p, snapshot(), b"b").is_err());
    let mut opt = options();
    opt.mode = NetworkMode::Create;
    assert!(bind(opt, owner(), policy(), snapshot(), b"b").is_err());
}
#[test]
fn rejects_existing_peer_range_overlap_including_supernets_and_host_bits() {
    for route in [
        "10.88.0.100/32",
        "10.88.0.109/30",
        "10.88.0.5/24",
        "0.0.0.0/0",
    ] {
        let mut s = snapshot();
        s.peers.values_mut().next().unwrap().push(route.into());
        assert!(
            bind(options(), owner(), policy(), s, b"b").is_err(),
            "{route}"
        );
    }
    for route in ["garbage", "10.88.0.5/33", "fd00::5/129"] {
        let mut s = snapshot();
        s.peers.values_mut().next().unwrap().push(route.into());
        assert!(
            bind(options(), owner(), policy(), s, b"b").is_err(),
            "{route}"
        );
    }
}
#[test]
fn rejects_unpinned_server_and_retains_peer_snapshot_hash() {
    let mut s = snapshot();
    s.server_key = format!("{}AAA=", "G".repeat(40));
    assert!(bind(options(), owner(), policy(), s, b"b").is_err());
    let mut s = snapshot();
    s.addresses.clear();
    assert!(bind(options(), owner(), policy(), s, b"b").is_err());
    let mut s = snapshot();
    s.addresses.push("10.89.0.1/24".into());
    assert!(bind(options(), owner(), policy(), s, b"b").is_err());
    let a = bind(options(), owner(), policy(), snapshot(), b"b").unwrap();
    let mut s = snapshot();
    s.peers.clear();
    let b = bind(options(), owner(), policy(), s, b"b").unwrap();
    assert_ne!(a.baseline_sha256, b.baseline_sha256);
    // Observations are separate from immutable installation intent.
    assert_eq!(a.plan_sha256, b.plan_sha256);
}
#[test]
fn passwd_resolution_rejects_root_unknown_and_injection() {
    for name in [
        "root",
        "",
        "-other",
        "other\n",
        "does-not-exist-readb-123456",
    ] {
        assert!(Owner::resolve(name).is_err(), "{name:?}");
    }
}

#[test]
fn home_admission_pins_ancestry_and_rejects_symlinks_and_writable_homes() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return;
    } // root-only namespace/image acceptance is a separate gate.
    let base = std::env::current_dir()
        .unwrap()
        .join("build")
        .join(format!("owner-{}", readb::policy::random()));
    fs::create_dir_all(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let mut o = Owner {
        name: "fixture".into(),
        uid,
        gid: unsafe { libc::getegid() },
        home: base.clone(),
    };
    o.check_home().unwrap();
    assert!(o.can_write_home().unwrap());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(!o.can_write_home().unwrap());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.join("alias");
    symlink(&base, &link).unwrap();
    o.home = link;
    assert!(o.check_home().is_err());
    o.home = base.clone();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o720)).unwrap();
    assert!(o.check_home().is_err());
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    o.uid += 1;
    assert!(o.check_home().is_err());
    fs::remove_dir_all(base).unwrap();
}

#[test]
fn cli_requires_explicit_local_and_complete_owner_range() {
    use std::process::Command;
    let bin = env!("CARGO_BIN_EXE_readb");
    let common = ["setup", "plan", "--endpoint", "vpn.example.org:51820"];
    let bad = Command::new(bin)
        .args(common)
        .args(["--user", "tester"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    let remote = Command::new(bin).args(common).output().unwrap();
    assert!(!remote.status.success());
    assert!(String::from_utf8_lossy(&remote.stderr).contains("--local_on_server"));
    let root = Command::new(bin)
        .arg("--local")
        .args(common)
        .args([
            "--reuse-interface",
            "--user",
            "root",
            "--range-first",
            "10.88.0.100",
            "--range-last",
            "10.88.0.110",
        ])
        .output()
        .unwrap();
    assert!(!root.status.success());
    assert!(String::from_utf8_lossy(&root.stderr).contains("setup_nonroot_owner"));
}

#[test]
fn root_files_cli_has_explicit_recovery_and_rejects_client_routing() {
    use std::process::Command;
    let bin = env!("CARGO_BIN_EXE_readb");
    let help = Command::new(bin)
        .args(["setup", "files", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--recover"));
    let denied = Command::new(bin)
        .args(["setup", "files", "--endpoint", "vpn.example.org:51820"])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("--local_on_server"));
}
