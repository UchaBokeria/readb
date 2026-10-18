//! Opt-in real Linux proof. Run only in an isolated network namespace with root fixtures.
use readb::{
    network::{Kernel, Manager, Policy, Request},
    network_recovery::Recovery,
    network_runtime::LinuxKernel,
    route_events::RouteEvents,
};
use std::{os::unix::fs::MetadataExt, path::Path, process::Command};
fn key(c: char) -> String {
    format!("{}AAA=", c.to_string().repeat(40))
}
fn command(program: &str, args: &[&str]) {
    let mut c = Command::new(program);
    c.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    let r = readb::runner::capture_cmd(c, std::time::Duration::from_secs(5), 16384).unwrap();
    assert!(r.ok, "isolated command failed, exit{}", r.code);
}
fn create(private: &str) {
    command(
        "/usr/bin/ip",
        &["link", "add", "readbtest0", "type", "wireguard"],
    );
    command(
        "/usr/bin/wg",
        &["set", "readbtest0", "private-key", private],
    );
    command(
        "/usr/bin/ip",
        &["address", "add", "10.88.0.1/24", "dev", "readbtest0"],
    );
    command("/usr/bin/ip", &["link", "set", "readbtest0", "up"]);
    command(
        "/usr/bin/wg",
        &[
            "set",
            "readbtest0",
            "peer",
            &key('B'),
            "allowed-ips",
            "10.88.0.3/32",
        ],
    );
}
#[test]
fn real_namespace_link_recreation_heals_only_managed_peers() {
    if std::env::var("READB_TEST_NETNS").as_deref() != Ok("1") {
        return;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "isolated proof requires root"
    );
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "refuse host namespace"
    );
    let fixture = std::env::var("READB_NETNS_FIXTURE").unwrap();
    let fixture = Path::new(&fixture);
    assert_eq!(fixture.parent(), Some(Path::new("/run")));
    assert!(
        fixture
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("readb-net-proof-")
    );
    let meta = std::fs::symlink_metadata(fixture).unwrap();
    assert!(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0);
    let private = fixture.join("server.key");
    let other = fixture.join("other.key");
    for path in [&private, &other] {
        let m = std::fs::symlink_metadata(path).unwrap();
        assert!(m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o077 == 0);
    }
    let private = private.to_str().unwrap();
    let other = other.to_str().unwrap();
    let policy = Policy {
        schema: 1,
        uid: 1000,
        interface: "readbtest0".into(),
        server_key: std::env::var("READB_NETNS_PUBLIC_KEY").unwrap(),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.10".parse().unwrap(),
        last: "10.88.0.20".parse().unwrap(),
    };
    let state = fixture.join("state");
    std::fs::create_dir(&state).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut events = RouteEvents::new().unwrap();
    create(private);
    assert!(
        events.drain().unwrap(),
        "actual link/address events observed"
    );
    let mut manager = Manager::open(&state, policy.clone()).unwrap();
    let mut kernel = LinuxKernel::new().unwrap();
    manager
        .apply(
            0,
            Request::Enroll {
                id: "managed".into(),
                key: key('C'),
                address: "10.88.0.10".parse().unwrap(),
            },
            &mut kernel,
        )
        .unwrap();
    let baseline = kernel.snapshot(&policy).unwrap();
    let mut recovery = Recovery::new(0);
    recovery
        .tick(0, false, &mut manager, &mut kernel)
        .unwrap()
        .unwrap();
    command("/usr/bin/ip", &["link", "delete", "readbtest0"]);
    assert!(events.drain().unwrap());
    assert!(
        recovery
            .tick(2000, true, &mut manager, &mut kernel)
            .unwrap()
            .is_err()
    );
    assert!(!manager.fenced());
    create(private);
    assert!(events.drain().unwrap());
    recovery
        .tick(4000, true, &mut manager, &mut kernel)
        .unwrap()
        .unwrap();
    assert_eq!(baseline, kernel.snapshot(&policy).unwrap());
    // Administrative down is observed, never reversed by the helper.
    command("/usr/bin/ip", &["link", "set", "readbtest0", "down"]);
    assert!(events.drain().unwrap());
    assert!(kernel.snapshot(&policy).is_err());
    assert!(
        recovery
            .tick(6000, true, &mut manager, &mut kernel)
            .unwrap()
            .is_err()
    );
    command("/usr/bin/ip", &["link", "set", "readbtest0", "up"]);
    recovery
        .tick(8000, true, &mut manager, &mut kernel)
        .unwrap()
        .unwrap();
    assert_eq!(baseline, kernel.snapshot(&policy).unwrap());
    // WireGuard key/peer changes need not emit rtnetlink: periodic fallback checks them.
    command("/usr/bin/wg", &["set", "readbtest0", "private-key", other]);
    command(
        "/usr/bin/wg",
        &["set", "readbtest0", "peer", &key('C'), "remove"],
    );
    let changed = kernel.snapshot(&policy).unwrap();
    assert_ne!(baseline.server_key, changed.server_key);
    assert!(
        recovery
            .tick(38000, false, &mut manager, &mut kernel)
            .unwrap()
            .is_err()
    );
    assert_eq!(changed, kernel.snapshot(&policy).unwrap());
    command(
        "/usr/bin/wg",
        &["set", "readbtest0", "private-key", private],
    );
    recovery
        .tick(43000, false, &mut manager, &mut kernel)
        .unwrap()
        .unwrap();
    assert_eq!(baseline, kernel.snapshot(&policy).unwrap());
    assert!(!manager.fenced());
    drop(manager);
    println!(
        "isolated link events/recreation/down/key-pin/periodic fallback passed; live interfaces untouched"
    );
}
