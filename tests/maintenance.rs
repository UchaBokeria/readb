use readb::{
    maintenance::{Marker, Store},
    policy::random,
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-maint-{}", random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn marker() -> Marker {
    Marker::new(&"a".repeat(64), &"b".repeat(64)).unwrap()
}
#[test]
fn exact_marker_is_durable_and_repeatable_but_not_transferable() {
    let p = dir();
    let m = marker();
    {
        let mut store = Store::open(&p).unwrap();
        assert!(store.load(&"b".repeat(64)).unwrap().is_none());
        store.publish(&m).unwrap();
        store.publish(&m).unwrap();
        assert!(Store::open(&p).is_err());
        assert!(
            store
                .publish(&Marker::new(&"c".repeat(64), &"b".repeat(64)).unwrap())
                .is_err()
        );
    }
    let mut store = Store::open(&p).unwrap();
    assert!(store.load(&"b".repeat(64)).unwrap() == Some(m.clone()));
    assert!(store.load(&"d".repeat(64)).is_err());
    store.remove(&m).unwrap();
    assert!(store.load(&"b".repeat(64)).unwrap().is_none());
    assert!(store.remove(&m).is_err());
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn unknown_or_changed_marker_is_preserved() {
    let p = dir();
    let mut store = Store::open(&p).unwrap();
    store.publish(&marker()).unwrap();
    let path = p.join("upgrade-maintenance.json");
    let original = fs::read(&path).unwrap();
    let other = Marker::new(&"c".repeat(64), &"b".repeat(64)).unwrap();
    assert!(store.remove(&other).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    fs::write(&path, b"{partial").unwrap();
    assert!(store.load(&"b".repeat(64)).is_err());
    assert!(store.publish(&marker()).is_err());
    assert!(store.remove(&marker()).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"{partial");
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn marker_paths_modes_links_and_size_are_fail_closed() {
    for case in 0..5 {
        let p = dir();
        let target = p.join("upgrade-maintenance.json");
        let original = p.join("foreign");
        fs::write(&original, b"preserve").unwrap();
        match case {
            0 => symlink(&original, &target).unwrap(),
            1 => {
                fs::write(&target, b"{}").unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
            }
            2 => {
                fs::hard_link(&original, &target).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            }
            3 => {
                fs::write(&target, vec![b'x'; 4097]).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => {
                fs::create_dir(&target).unwrap();
                fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let mut store = Store::open(&p).unwrap();
        assert!(store.load(&"b".repeat(64)).is_err());
        assert!(store.publish(&marker()).is_err());
        assert!(store.remove(&marker()).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"preserve");
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }
}
#[test]
fn invalid_hashes_and_unsafe_state_never_publish() {
    assert!(Marker::new("bad", &"a".repeat(64)).is_err());
    assert!(Marker::new(&"A".repeat(64), &"b".repeat(64)).is_err());
    let p = dir();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(&p).is_err());
    assert!(!p.join("upgrade-maintenance.json").exists());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn unsafe_lock_and_state_aliases_are_rejected_without_touching_foreign_data() {
    for case in 0..4 {
        let p = dir();
        let foreign = p.join("foreign");
        fs::write(&foreign, b"preserve").unwrap();
        let lock = p.join("upgrade-maintenance.lock");
        match case {
            0 => symlink(&foreign, &lock).unwrap(),
            1 => {
                fs::hard_link(&foreign, &lock).unwrap();
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
            }
            2 => {
                fs::write(&lock, b"preserve").unwrap();
                fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
            }
            _ => {
                fs::create_dir(&lock).unwrap();
            }
        }
        assert!(Store::open(&p).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
        assert!(!p.join("upgrade-maintenance.json").exists());
        let alias = p.with_extension("alias");
        symlink(&p, &alias).unwrap();
        assert!(Store::open(&alias).is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(p).unwrap();
    }
}
#[test]
fn failed_publication_or_removal_never_claims_success() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let p = dir();
    let mut store = Store::open(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(store.publish(&marker()).is_err());
    assert!(!p.join("upgrade-maintenance.json").exists());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    store.publish(&marker()).unwrap();
    let bytes = fs::read(p.join("upgrade-maintenance.json")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(store.remove(&marker()).is_err());
    assert_eq!(fs::read(p.join("upgrade-maintenance.json")).unwrap(), bytes);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    store.remove(&marker()).unwrap();
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn startup_inspection_is_read_only_and_does_not_compete_for_writer_lock() {
    let p = dir();
    assert!(
        readb::maintenance::inspect(&p, &"b".repeat(64))
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read_dir(&p).unwrap().count(), 0);
    let mut store = Store::open(&p).unwrap();
    assert!(
        readb::maintenance::inspect(&p, &"b".repeat(64))
            .unwrap()
            .is_none()
    );
    store.publish(&marker()).unwrap();
    assert!(readb::maintenance::inspect(&p, &"b".repeat(64)).unwrap() == Some(marker()));
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
