use readb::catalog::{Store, recover, runtime_lock};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn fixture() -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("readb-catalog-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let cfg = root.join("server.json");
    (root, cfg)
}
#[test]
fn publication_is_durable_and_leaves_no_pending_journal() {
    let (root, cfg) = fixture();
    let s = Store::new(&root, &cfg);
    s.publish(&serde_json::json!({"schema":1}), None).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&cfg).unwrap()).unwrap()["schema"],
        1
    );
    assert!(!s.fenced());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn interrupted_before_and_after_publish_recover_only_expected_bytes() {
    for committed in [false, true] {
        let (root, cfg) = fixture();
        let s = Store::new(&root, &cfg);
        s.publish(&serde_json::json!({"version":1}), None).unwrap();
        let prepared = s.prepare(&serde_json::json!({"version":2}), None).unwrap();
        if committed {
            fs::write(&cfg, prepared).unwrap();
        }
        assert!(s.fenced());
        assert!(s.publish(&serde_json::json!({"version":3}), None).is_err());
        let proof = recover(&root, &cfg).unwrap();
        assert_eq!(proof["committed"], committed);
        assert!(!s.fenced());
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn recovery_never_overwrites_an_external_edit_or_runs_with_live_daemon() {
    let (root, cfg) = fixture();
    let s = Store::new(&root, &cfg);
    s.publish(&serde_json::json!({"version":1}), None).unwrap();
    s.prepare(&serde_json::json!({"version":2}), None).unwrap();
    let lease = runtime_lock(&root, &cfg).unwrap();
    assert!(recover(&root, &cfg).is_err());
    drop(lease);
    fs::write(&cfg, b"external edit").unwrap();
    assert!(recover(&root, &cfg).is_err());
    assert_eq!(fs::read(&cfg).unwrap(), b"external edit");
    assert!(s.fenced());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn ordinary_publication_rejects_external_edits_and_stale_writers() {
    let (root, cfg) = fixture();
    let s = Store::new(&root, &cfg);
    s.publish(&serde_json::json!({"version":1}), None).unwrap();
    let stale = Store::new(&root, &cfg);
    s.publish(&serde_json::json!({"version":2}), None).unwrap();
    assert!(
        stale
            .publish(&serde_json::json!({"version":3}), None)
            .is_err()
    );
    fs::write(&cfg, b"{\"version\":4}").unwrap();
    assert!(s.publish(&serde_json::json!({"version":5}), None).is_err());
    assert_eq!(fs::read(&cfg).unwrap(), b"{\"version\":4}");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn a_config_cannot_be_managed_or_recovered_through_another_state_root() {
    let (root, cfg) = fixture();
    let (other, _) = fixture();
    let s = Store::new(&root, &cfg);
    s.publish(&serde_json::json!({"version":1}), None).unwrap();
    assert!(
        Store::new(&other, &cfg)
            .publish(&serde_json::json!({"version":2}), None)
            .is_err()
    );
    assert!(runtime_lock(&other, &cfg).is_err());
    s.prepare(&serde_json::json!({"version":2}), None).unwrap();
    assert!(recover(&other, &cfg).is_err());
    assert!(s.fenced());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(other).unwrap();
}
#[test]
fn stage_creation_already_has_durable_intent_if_process_stops() {
    let (root, cfg) = fixture();
    let s = Store::new(&root, &cfg);
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), String> =
            s.transaction(&serde_json::json!({"version":1}), Some("new-phone"), || {
                let d = root.join("devices/new-phone/.android");
                fs::create_dir_all(&d).unwrap();
                for p in [root.join("devices"), root.join("devices/new-phone"), d] {
                    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
                }
                assert!(s.fenced());
                panic!("simulated process interruption after Backend.new");
            });
    }));
    assert!(interrupted.is_err());
    assert!(s.fenced());
    recover(&root, &cfg).unwrap();
    assert!(!root.join("devices/new-phone").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_removes_only_known_empty_uncommitted_stage_and_preserves_keys() {
    for keep_key in [false, true] {
        let (root, cfg) = fixture();
        let s = Store::new(&root, &cfg);
        let device = root.join("devices/new-phone");
        let android = device.join(".android");
        fs::create_dir_all(&android).unwrap();
        for p in [root.join("devices"), device.clone(), android.clone()] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        if keep_key {
            fs::write(android.join("adbkey"), b"retained key").unwrap();
        }
        s.prepare(&serde_json::json!({"version":1}), Some("new-phone"))
            .unwrap();
        recover(&root, &cfg).unwrap();
        assert_eq!(android.join("adbkey").exists(), keep_key);
        assert_eq!(device.exists(), keep_key);
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn journal_symlink_and_wrong_target_fail_closed() {
    let (root, cfg) = fixture();
    let s = Store::new(&root, &cfg);
    s.prepare(&serde_json::json!({"version":1}), None).unwrap();
    assert!(recover(&root, &root.join("other.json")).is_err());
    fs::remove_file(root.join("catalog-pending.json")).unwrap();
    symlink(&cfg, root.join("catalog-pending.json")).unwrap();
    assert!(s.preflight().is_err());
    assert!(recover(&root, &cfg).is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn unexpected_stage_symlink_keeps_recovery_fenced() {
    let (root, cfg) = fixture();
    let (outside, _) = fixture();
    let device = root.join("devices/new-phone");
    fs::create_dir_all(&device).unwrap();
    fs::set_permissions(root.join("devices"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&device, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(outside.join("retained-key"), b"fixture key").unwrap();
    symlink(&outside, device.join(".android")).unwrap();
    let s = Store::new(&root, &cfg);
    s.prepare(&serde_json::json!({"version":1}), Some("new-phone"))
        .unwrap();
    assert!(recover(&root, &cfg).is_err());
    assert!(s.fenced());
    assert_eq!(
        fs::read(outside.join("retained-key")).unwrap(),
        b"fixture key"
    );
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}
