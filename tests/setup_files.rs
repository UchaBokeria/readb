use readb::{
    network::{Policy, Snapshot},
    setup::{NetworkMode, Options},
    setup_apply::{Owner, bind},
    setup_files::{apply, recover},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
fn image() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-files-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn plan(binary: &[u8]) -> readb::setup_apply::ApplyPlan {
    let p = Policy {
        schema: 1,
        uid: 1000,
        interface: "readb0".into(),
        server_key: format!("{}AAA=", "E".repeat(40)),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.100".parse().unwrap(),
        last: "10.88.0.150".parse().unwrap(),
    };
    let o = Options {
        endpoint: "vpn.example.org:51820".into(),
        interface: p.interface.clone(),
        address: p.server_address,
        prefix: 24,
        listen_port: 51820,
        mode: NetworkMode::Reuse,
    };
    let owner = Owner {
        name: "fixture".into(),
        uid: 1000,
        gid: 1000,
        home: "/home/fixture".into(),
    };
    let s = Snapshot {
        server_key: p.server_key.clone(),
        addresses: vec!["10.88.0.1/24".into()],
        peers: BTreeMap::new(),
    };
    bind(o, owner, p, s, binary).unwrap()
}
#[test]
fn files_are_journaled_repeatable_and_never_claim_services_or_devices() {
    let root = image();
    let p = plan(b"binary");
    let r = apply(&root, &p, b"binary").unwrap();
    assert!(r["files_installed"].as_bool().unwrap());
    for k in [
        "helper_active",
        "coordinator_active",
        "devices_accepted",
        "network_verified",
    ] {
        assert_eq!(r[k], false);
    }
    apply(&root, &p, b"binary").unwrap();
    assert!(root.join("etc/readb/network-policy.json").is_file());
    assert!(
        root.join("etc/systemd/system/readb-network.service")
            .is_file()
    );
    let other = plan(b"changed");
    assert!(apply(&root, &other, b"changed").is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_inputs_and_installed_edits_remain_blocked_on_retry() {
    let root = image();
    let mut p = plan(b"binary");
    p.owner.home = "/home/other".into();
    assert!(apply(&root, &p, b"binary").is_err());
    assert!(!root.join("etc").exists());
    let p = plan(b"binary");
    apply(&root, &p, b"binary").unwrap();
    let file = root.join("etc/systemd/system/readb-network.service");
    fs::write(&file, b"external").unwrap();
    assert!(apply(&root, &p, b"binary").is_err());
    assert!(recover(&root, &p, b"binary").is_err());
    assert_eq!(fs::read(file).unwrap(), b"external");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn explicit_recovery_checks_original_plan_and_each_owned_artifact() {
    use readb::setup_journal::{Journal, Phase};
    let root = image();
    let p = plan(b"binary");
    let jdir = root.join("var/lib/readb-setup");
    fs::create_dir_all(&jdir).unwrap();
    fs::set_permissions(&jdir, fs::Permissions::from_mode(0o700)).unwrap();
    {
        let mut j = Journal::open(&jdir, &p.plan_sha256).unwrap();
        for phase in [Phase::Preflight, Phase::Dependencies] {
            j.begin(phase).unwrap();
            j.complete(phase).unwrap();
        }
        j.begin(Phase::Network).unwrap();
    }
    assert!(apply(&root, &p, b"binary").is_err());
    assert!(recover(&root, &plan(b"changed"), b"changed").is_err());
    let r = recover(&root, &p, b"binary").unwrap();
    assert_eq!(r["files_installed"], true);
    apply(&root, &p, b"binary").unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_does_not_consume_an_unrelated_binary_install_intent() {
    use readb::network_install::{Installer, Plan};
    let root = image();
    let p = plan(b"binary");
    apply(&root, &p, b"binary").unwrap();
    {
        let mut i = Installer::open(&root).unwrap();
        i.prepare(
            Plan::new(&p.policy, b"other-upgrade").unwrap(),
            b"other-upgrade",
        )
        .unwrap();
    }
    let pending = root.join("var/lib/readb-network/install-pending.json");
    let before = fs::read(&pending).unwrap();
    assert!(recover(&root, &p, b"binary").is_err());
    assert_eq!(fs::read(pending).unwrap(), before);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn read_only_phase_interruption_can_be_reconciled_before_files() {
    use readb::setup_journal::{Journal, Phase};
    let root = image();
    let p = plan(b"binary");
    let dir = root.join("var/lib/readb-setup");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    {
        let mut j = Journal::open(&dir, &p.plan_sha256).unwrap();
        j.begin(Phase::Preflight).unwrap();
    }
    assert_eq!(
        recover(&root, &p, b"binary").unwrap()["files_installed"],
        true
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_without_any_recorded_phase_does_not_install_files() {
    let root = image();
    let p = plan(b"binary");
    assert!(recover(&root, &p, b"binary").is_err());
    assert!(!root.join("etc").exists());
    fs::remove_dir_all(root).unwrap();
}
