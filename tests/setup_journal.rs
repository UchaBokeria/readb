use readb::setup_journal::{Journal, Phase};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-setup-test-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
#[test]
fn resume_preserves_completed_phases_and_detects_interruption() {
    let p = dir();
    let hash = "a".repeat(64);
    {
        let mut j = Journal::open(&p, &hash).unwrap();
        j.begin(Phase::Preflight).unwrap();
        j.complete(Phase::Preflight).unwrap();
        j.begin(Phase::Dependencies).unwrap();
    }
    let mut j = Journal::open(&p, &hash).unwrap();
    assert!(j.completed(Phase::Preflight));
    assert!(
        j.complete(Phase::Dependencies)
            .unwrap_err()
            .contains("setup_cleanup_unknown")
    );
    assert!(
        j.begin(Phase::Dependencies)
            .unwrap_err()
            .contains("setup_cleanup_unknown")
    );
    assert!(j.begin(Phase::Network).is_err());
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn changed_plan_parallel_writer_and_out_of_order_completion_are_rejected() {
    let p = dir();
    let hash = "a".repeat(64);
    {
        let mut j = Journal::open(&p, &hash).unwrap();
        assert!(Journal::open(&p, &hash).is_err());
        assert!(j.begin(Phase::Network).is_err());
        assert!(j.complete(Phase::Preflight).is_err());
        j.begin(Phase::Preflight).unwrap();
        j.complete(Phase::Preflight).unwrap();
    }
    assert!(Journal::open(&p, &"b".repeat(64)).is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn symlinks_untrusted_modes_and_invalid_state_fail_closed() {
    let p = dir();
    let other = dir();
    symlink(other.join("secret"), p.join("journal.json")).unwrap();
    assert!(Journal::open(&p, &"a".repeat(64)).is_err());
    assert!(!other.join("secret").exists());
    fs::remove_file(p.join("journal.json")).unwrap();
    fs::write(p.join("journal.json"), b"{}").unwrap();
    assert!(Journal::open(&p, &"a".repeat(64)).is_err());
    fs::remove_file(p.join("journal.json")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Journal::open(&p, &"a".repeat(64)).is_err());
    fs::remove_dir_all(p).unwrap();
    fs::remove_dir_all(other).unwrap();
}

#[test]
fn original_provider_evidence_is_pinned_across_recovery() {
    let p = dir();
    let plan = "a".repeat(64);
    let original = "b".repeat(64);
    let changed = "c".repeat(64);
    {
        let mut j = Journal::open(&p, &plan).unwrap();
        j.bind_provider(&original).unwrap();
        j.bind_provider(&original).unwrap();
        j.begin(Phase::Preflight).unwrap();
    }
    let mut j = Journal::open(&p, &plan).unwrap();
    assert!(
        j.bind_provider(&changed)
            .unwrap_err()
            .contains("provider_changed")
    );
    j.bind_provider(&original).unwrap();
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
