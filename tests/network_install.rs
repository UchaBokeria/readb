use readb::network::Policy;
use readb::network_install::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn image() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-net-install-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn policy() -> Policy {
    Policy {
        schema: 1,
        uid: 1000,
        interface: "mobile".into(),
        server_key: format!("{}AAA=", "E".repeat(40)),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.10".parse().unwrap(),
        last: "10.88.0.20".parse().unwrap(),
    }
}
#[test]
fn plan_keeps_privileged_binary_outside_user_paths_and_never_starts_service() {
    let p = Plan::new(&policy(), b"binary").unwrap();
    assert!(
        p.binary_path()
            .starts_with("/usr/local/lib/readb-network/releases/")
    );
    let unit = p.unit();
    assert!(unit.contains("User=root"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN"));
    assert!(unit.contains("After=network-online.target wg-quick@mobile.service"));
    assert!(!unit.contains("/home/"));
    assert!(!unit.contains("enable --now"));
}
#[test]
fn fresh_repeat_upgrade_and_external_edit_are_safe() {
    let root = image();
    let p = Plan::new(&policy(), b"binary").unwrap();
    let mut i = Installer::open(&root).unwrap();
    i.install(p.clone(), b"binary").unwrap();
    i.install(p.clone(), b"binary").unwrap();
    let p2 = Plan::new(&policy(), b"new binary").unwrap();
    i.install(p2, b"new binary").unwrap();
    let unit = root.join("etc/systemd/system/readb-network.service");
    fs::write(&unit, b"owner external edit").unwrap();
    assert!(i.install(p, b"binary").is_err());
    assert_eq!(fs::read(unit).unwrap(), b"owner external edit");
    drop(i);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn unknown_units_symlinks_parallel_installs_and_wrong_binary_are_denied() {
    let root = image();
    let p = Plan::new(&policy(), b"binary").unwrap();
    let mut i = Installer::open(&root).unwrap();
    assert!(Installer::open(&root).is_err());
    assert!(i.install(p.clone(), b"wrong binary").is_err());
    let unit = root.join("etc/systemd/system/readb-network.service");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::write(&unit, b"existing unknown unit").unwrap();
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(i.install(p.clone(), b"binary").is_err());
    assert_eq!(fs::read(&unit).unwrap(), b"existing unknown unit");
    fs::remove_file(&unit).unwrap();
    symlink(root.join("outside"), &unit).unwrap();
    assert!(i.install(p, b"binary").is_err());
    assert!(!root.join("outside").exists());
    drop(i);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn interrupted_install_recovers_from_known_files_and_preserves_external_changes() {
    let root = image();
    let p = Plan::new(&policy(), b"binary").unwrap();
    {
        let mut i = Installer::open(&root).unwrap();
        i.prepare(p.clone(), b"binary").unwrap();
        assert!(i.fenced());
        assert!(i.install(p.clone(), b"binary").is_err());
    }
    let mut i = Installer::open(&root).unwrap();
    assert!(i.fenced());
    i.recover().unwrap();
    assert!(!i.fenced());
    i.install(p.clone(), b"binary").unwrap();
    let p2 = Plan::new(&policy(), b"new binary").unwrap();
    i.prepare(p2, b"new binary").unwrap();
    let unit = root.join("etc/systemd/system/readb-network.service");
    fs::write(&unit, b"external edit").unwrap();
    assert!(i.recover().is_err());
    assert!(i.fenced());
    assert_eq!(fs::read(&unit).unwrap(), b"external edit");
    drop(i);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_can_commit_verified_files_after_an_interrupted_receipt_write() {
    let root = image();
    let p = Plan::new(&policy(), b"binary").unwrap();
    {
        let mut i = Installer::open(&root).unwrap();
        i.prepare(p.clone(), b"binary").unwrap();
    }
    let binary = root.join(p.binary_path().trim_start_matches('/'));
    fs::create_dir_all(binary.parent().unwrap()).unwrap();
    fs::write(&binary, b"binary").unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let unit = root.join("etc/systemd/system/readb-network.service");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::write(&unit, p.unit()).unwrap();
    fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).unwrap();
    let mut i = Installer::open(&root).unwrap();
    i.recover().unwrap();
    assert!(!i.fenced());
    i.install(p, b"binary").unwrap();
    drop(i);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_binary_permissions_and_symlinked_parents_are_preserved() {
    let root = image();
    let p = Plan::new(&policy(), b"binary").unwrap();
    let mut i = Installer::open(&root).unwrap();
    i.install(p.clone(), b"binary").unwrap();
    let binary = root.join(p.binary_path().trim_start_matches('/'));
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(i.install(p, b"binary").is_err());
    assert!(!i.fenced());
    drop(i);
    fs::remove_dir_all(root).unwrap();
    let root = image();
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, root.join("usr")).unwrap();
    let mut i = Installer::open(&root).unwrap();
    assert!(
        i.install(Plan::new(&policy(), b"binary").unwrap(), b"binary")
            .is_err()
    );
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
    drop(i);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn an_unresolved_install_intent_blocks_helper_startup_even_if_malformed() {
    let root = image();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    assert!(ensure_complete(&state).is_ok());
    fs::write(state.join("install-pending.json"), b"bad json").unwrap();
    assert!(ensure_complete(&state).is_err());
    fs::remove_file(state.join("install-pending.json")).unwrap();
    symlink(root.join("absent"), state.join("install-pending.json")).unwrap();
    assert!(ensure_complete(&state).is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn install_intent_is_checked_after_acquiring_the_same_state_lock_as_startup() {
    let root = image();
    let state = root.join("var/lib/readb-network");
    let mut i = Installer::open(&root).unwrap();
    assert!(ensure_complete(&state).is_ok());
    i.prepare(Plan::new(&policy(), b"binary").unwrap(), b"binary")
        .unwrap();
    drop(i);
    assert!(
        readb::network::Manager::open(&state, policy()).is_err(),
        "startup must recheck pending intent under its state lock"
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_previous_release_denies_upgrade_and_rollback() {
    for during_pending in [false, true] {
        let root = image();
        let p = Plan::new(&policy(), b"binary").unwrap();
        let old = root.join(p.binary_path().trim_start_matches('/'));
        let mut i = Installer::open(&root).unwrap();
        i.install(p, b"binary").unwrap();
        let next = Plan::new(&policy(), b"new binary").unwrap();
        if during_pending {
            i.prepare(next.clone(), b"new binary").unwrap();
        }
        fs::remove_file(&old).unwrap();
        if during_pending {
            assert!(i.recover().is_err());
            assert!(i.fenced());
        } else {
            assert!(i.install(next, b"new binary").is_err());
            assert!(!i.fenced());
        }
        drop(i);
        fs::remove_dir_all(root).unwrap();
    }
}
