use readb::user_install::{Desired, Transaction};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
fn fixture() -> PathBuf {
    let root = std::env::temp_dir().join(format!("readb-user-tx-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn desired(root: &std::path::Path) -> Vec<Desired> {
    vec![
        Desired::file(root.join("a"), b"new-a".to_vec(), 0o600),
        Desired::link(root.join("b"), root.join("a")),
    ]
}
#[test]
fn interrupted_publication_requires_explicit_exact_recovery() {
    let root = fixture();
    let items = desired(&root);
    let journal = root.join("journal");
    {
        let mut tx = Transaction::open(&journal, "scope-a", &items, false).unwrap();
        tx.publish(0, &items[0]).unwrap();
        assert!(
            Transaction::open(&journal, "scope-a", &items, true).is_err(),
            "one installer only"
        );
    }
    assert!(Transaction::open(&journal, "scope-a", &items, false).is_err());
    assert!(Transaction::open(&journal, "scope-b", &items, true).is_err());
    let mut altered = desired(&root);
    altered[0] = Desired::file(root.join("a"), b"other".to_vec(), 0o600);
    assert!(Transaction::open(&journal, "scope-a", &altered, true).is_err());
    {
        let mut tx = Transaction::open(&journal, "scope-a", &items, true).unwrap();
        tx.publish(0, &items[0]).unwrap();
        tx.publish(1, &items[1]).unwrap();
        tx.finish().unwrap();
    }
    assert_eq!(fs::read(root.join("a")).unwrap(), b"new-a");
    assert_eq!(fs::read_link(root.join("b")).unwrap(), root.join("a"));
    assert!(!journal.join("pending.json").exists());
    assert!(journal.join("receipt.json").is_file());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn edited_partial_artifact_fences_before_other_destinations_change() {
    let root = fixture();
    let items = desired(&root);
    let journal = root.join("journal");
    {
        let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
        tx.publish(0, &items[0]).unwrap();
    }
    fs::write(root.join("a"), b"owner edit").unwrap();
    assert!(Transaction::open(&journal, "scope", &items, true).is_err());
    assert!(!root.join("b").exists());
    assert!(journal.join("pending.json").exists());
    assert_eq!(fs::read(root.join("a")).unwrap(), b"owner edit");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn symlink_parent_and_hardlinked_destinations_are_never_adopted() {
    use std::os::unix::fs::symlink;
    let root = fixture();
    let outside = fixture();
    symlink(&outside, root.join("alias")).unwrap();
    let items = vec![Desired::file(root.join("alias/file"), b"x".to_vec(), 0o600)];
    assert!(Transaction::open(&root.join("journal"), "scope", &items, false).is_err());
    assert!(!outside.join("file").exists());
    fs::write(root.join("a"), b"owner").unwrap();
    fs::set_permissions(root.join("a"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(root.join("a"), root.join("alias-copy")).unwrap();
    assert!(Transaction::open(&root.join("journal"), "scope", &desired(&root), false).is_err());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(outside).unwrap();
}
#[test]
fn unknown_receipt_is_preserved_and_recorded_after_state_recovers() {
    let root = fixture();
    let items = desired(&root);
    let journal = root.join("journal");
    fs::create_dir(&journal).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(journal.join("receipt.json"), b"owner file").unwrap();
    fs::set_permissions(
        journal.join("receipt.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(Transaction::open(&journal, "scope", &items, false).is_err());
    assert!(!root.join("a").exists());
    assert_eq!(
        fs::read(journal.join("receipt.json")).unwrap(),
        b"owner file"
    );
    fs::remove_file(journal.join("receipt.json")).unwrap();
    {
        let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
        for (n, item) in items.iter().enumerate() {
            tx.publish(n, item).unwrap();
        }
        // Simulate the crash window after receipt fsync but before intent clear.
        fs::copy(journal.join("pending.json"), journal.join("receipt.json")).unwrap();
    }
    let tx = Transaction::open(&journal, "scope", &items, true).unwrap();
    tx.finish().unwrap();
    assert!(!journal.join("pending.json").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn preserved_config_and_immutable_release_refuse_changed_bytes() {
    let root = fixture();
    let file = root.join("config");
    fs::write(&file, b"owner change").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    for desired in [
        Desired::file(file.clone(), b"old config".to_vec(), 0o600).preserve(),
        Desired::file(file.clone(), b"release".to_vec(), 0o600).immutable(),
    ] {
        assert!(Transaction::open(&root.join("journal"), "scope", &[desired], false).is_err());
        assert!(!root.join("journal/pending.json").exists());
        assert_eq!(fs::read(&file).unwrap(), b"owner change");
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn changed_pending_or_receipt_stays_fenced_during_publication() {
    let root = fixture();
    let items = desired(&root);
    let journal = root.join("journal");
    {
        let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
        fs::write(journal.join("pending.json"), b"owner edit").unwrap();
        assert!(tx.publish(0, &items[0]).is_err());
        assert!(!root.join("a").exists());
    }
    fs::remove_file(journal.join("pending.json")).unwrap();
    {
        let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
        for (n, item) in items.iter().enumerate() {
            tx.publish(n, item).unwrap();
        }
        fs::write(journal.join("receipt.json"), b"owner receipt").unwrap();
        fs::set_permissions(
            journal.join("receipt.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(tx.finish().is_err());
        assert!(journal.join("pending.json").exists());
        assert_eq!(
            fs::read(journal.join("receipt.json")).unwrap(),
            b"owner receipt"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn replacement_valid_receipt_is_not_adopted_during_recovery() {
    let root = fixture();
    let items = desired(&root);
    let journal = root.join("journal");
    {
        let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
        tx.publish(0, &items[0]).unwrap();
    }
    let other = fixture();
    let theirs = desired(&other);
    let other_journal = other.join("journal");
    {
        let mut tx = Transaction::open(&other_journal, "other-scope", &theirs, false).unwrap();
        for (n, item) in theirs.iter().enumerate() {
            tx.publish(n, item).unwrap();
        }
        tx.finish().unwrap();
    }
    fs::copy(
        other_journal.join("receipt.json"),
        journal.join("receipt.json"),
    )
    .unwrap();
    let receipt = fs::read(journal.join("receipt.json")).unwrap();
    assert!(Transaction::open(&journal, "scope", &items, true).is_err());
    assert!(journal.join("pending.json").exists());
    assert_eq!(fs::read(journal.join("receipt.json")).unwrap(), receipt);
    assert!(!root.join("b").exists());
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(other).unwrap();
}
#[test]
fn completion_upgrade_requires_prior_receipt_and_preserves_owner_edits() {
    let root = fixture();
    let file = root.join("completion");
    let journal = root.join("journal");
    fs::write(&file, b"custom completion").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let next = vec![Desired::file(file.clone(), b"generated v2".to_vec(), 0o600).owned()];
    assert!(Transaction::open(&journal, "next", &next, false).is_err());
    assert!(!journal.join("pending.json").exists());
    fs::remove_file(&file).unwrap();
    let initial = vec![Desired::file(file.clone(), b"generated v1".to_vec(), 0o600).owned()];
    {
        let mut tx = Transaction::open(&journal, "first", &initial, false).unwrap();
        tx.publish(0, &initial[0]).unwrap();
        tx.finish().unwrap();
    }
    {
        let mut tx = Transaction::open(&journal, "next", &next, false).unwrap();
        tx.publish(0, &next[0]).unwrap();
        tx.finish().unwrap();
    }
    fs::write(&file, b"owner edited completion").unwrap();
    let third = vec![Desired::file(file.clone(), b"generated v3".to_vec(), 0o600).owned()];
    assert!(Transaction::open(&journal, "third", &third, false).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"owner edited completion");
    fs::remove_dir_all(root).unwrap();
}
