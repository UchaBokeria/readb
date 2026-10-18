use readb::setup_upgrade_systemd::{admit_empty, admit_frozen};
use serde_json::json;
#[test]
fn empty_bootstrap_refuses_devices_listeners_or_unknown_runtime() {
    let config = readb::schema::ServerConfig::parse(
        &serde_json::to_vec(&json!({"schema":1,"adb":"/not-executed","devices":[],"listeners":[]}))
            .unwrap(),
    )
    .unwrap();
    let good = json!({"schema":1,"pid":123,"devices":[],"listener_errors":{},"catalog_cleanup_unknown":false});
    assert_eq!(admit_empty(&good, &config).unwrap().len(), 64);
    for key in [
        "devices",
        "listener_errors",
        "catalog_cleanup_unknown",
        "pid",
    ] {
        let mut bad = good.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(admit_empty(&bad, &config).is_err());
    }
    let mut bad = good.clone();
    bad["devices"] = json!([{"id":"active"}]);
    assert!(admit_empty(&bad, &config).is_err());
    let mut bad = good.clone();
    bad["listener_errors"] = json!({"report":"bind failed"});
    assert!(admit_empty(&bad, &config).is_err());
}
#[test]
fn freezer_requires_manager_and_kernel_and_exact_sole_process() {
    assert!(admit_frozen("frozen", "populated 1\nfrozen 1\n", "123\n", 123).is_ok());
    for (manager, events, procs, pid) in [
        ("freezing", "frozen 1\n", "123\n", 123),
        ("frozen", "frozen 0\n", "123\n", 123),
        ("frozen", "frozen 1\nfrozen 0\n", "123\n", 123),
        ("frozen", "frozen 1\n", "123\n456\n", 123),
        ("frozen", "frozen 1\n", "456\n", 123),
        ("frozen", "frozen 1\n", "0\n", 0),
    ] {
        assert!(admit_frozen(manager, events, procs, pid).is_err());
    }
}
#[test]
fn offline_empty_inspection_never_creates_a_missing_catalog_binding() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root =
        std::env::temp_dir().join(format!("readb-upgrade-empty-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let file = root.join("server.json");
    fs::write(
        &file,
        serde_json::to_vec(&json!({"schema":1,"adb":"/not-executed","devices":[],"listeners":[]}))
            .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(readb::setup_upgrade_systemd::inspect_empty(&state, &file).is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 2);
    readb::catalog::Store::new(&state, &file)
        .preflight()
        .unwrap();
    assert!(readb::setup_upgrade_systemd::inspect_empty(&state, &file).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn quiet_marker_requires_existing_binding_and_real_runtime_lock() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let root =
        std::env::temp_dir().join(format!("readb-rollback-lock-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let file = root.join("server.json");
    fs::write(
        &file,
        serde_json::to_vec(&json!({"schema":1,"adb":"/not-executed","devices":[],"listeners":[]}))
            .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let pin = "b".repeat(64);
    let tag = "a".repeat(64);
    assert!(readb::setup_upgrade_systemd::quiet_marker(&state, &file, &tag, &pin, false).is_err());
    assert!(!state.join("upgrade-maintenance.json").exists());
    readb::catalog::Store::new(&state, &file)
        .preflight()
        .unwrap();
    let pin =
        readb::setup_upgrade_systemd::inspect_empty(&state, &file).unwrap()["config_fingerprint"]
            .as_str()
            .unwrap()
            .to_owned();
    let runtime = readb::catalog::runtime_lock(&state, &file).unwrap();
    assert!(readb::setup_upgrade_systemd::quiet_marker(&state, &file, &tag, &pin, false).is_err());
    assert!(!state.join("upgrade-maintenance.json").exists());
    drop(runtime);
    readb::setup_upgrade_systemd::quiet_marker(&state, &file, &tag, &pin, false).unwrap();
    assert!(
        readb::setup_upgrade_systemd::quiet_marker(&state, &file, &"c".repeat(64), &pin, true)
            .is_err()
    );
    readb::setup_upgrade_systemd::quiet_marker(&state, &file, &tag, &pin, true).unwrap();
    readb::setup_upgrade_systemd::quiet_marker(&state, &file, &tag, &pin, true).unwrap();
    assert!(!state.join("upgrade-maintenance.json").exists());
    fs::remove_dir_all(root).unwrap();
}
