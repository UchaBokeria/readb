use readb::{
    enrollment_journal::{Phase, Store, inspect},
    enrollment_profile::{Facts, Material, Request, plan},
    network::{Policy, Snapshot},
    policy::{Owner, random},
    schema::{Kind, ServerConfig},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};
fn key(c: char) -> String {
    format!("{}AAA=", c.to_string().repeat(40))
}
fn facts() -> Facts {
    Facts {
        policy: Policy {
            schema: 1,
            uid: 1000,
            interface: "mobile".into(),
            server_key: key('E'),
            server_address: "10.99.0.2".parse().unwrap(),
            prefix: 24,
            first: "10.99.0.100".parse().unwrap(),
            last: "10.99.0.150".parse().unwrap(),
        },
        managed: BTreeMap::new(),
        snapshot: Snapshot {
            server_key: key('E'),
            addresses: vec!["10.99.0.2/24".into()],
            peers: BTreeMap::from([
                (key('B'), vec!["10.99.0.3/32".into()]),
                (key('D'), vec!["10.99.0.100/31".into()]),
            ]),
        },
    }
}
fn config() -> ServerConfig {
    ServerConfig {
        schema: 1,
        adb: "/not-executed".into(),
        devices: vec![],
        listeners: vec![],
    }
}
fn request() -> Request {
    Request {
        id: "pixel-readb".into(),
        name: "Pixel".into(),
        kind: Kind::Phone,
        endpoint: "vpn.example.org:51820".into(),
        report_port: 19193,
    }
}

fn dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-enroll-{}", random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn material() -> Material {
    Material::generate(
        plan(&facts(), &config(), &request(), &[], &BTreeSet::new()).unwrap(),
        "/usr/bin/wg".as_ref(),
    )
    .unwrap()
}
fn owner() -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "actual-session".into(),
        job: "enroll Pixel".into(),
        allow_sleep: false,
    }
}
#[test]
fn dropped_client_preserves_exact_material_and_only_one_global_pending() {
    let p = dir();
    let m = material();
    let bytes = m.profile_bytes().unwrap();
    let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let r = s.begin(m, &owner()).unwrap();
    let transaction = r.transaction().to_string();
    assert_eq!(r.phase(), Phase::Prepared);
    assert!(Store::open(&p, "/usr/bin/wg".as_ref()).is_err());
    drop(s);
    let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let r = s.recover("pixel-readb", &owner()).unwrap();
    assert_eq!(r.transaction(), transaction);
    assert!(
        r.material("/usr/bin/wg".as_ref())
            .unwrap()
            .profile_bytes()
            .unwrap()
            == bytes
    );
    let mut other = owner();
    other.session = "different".into();
    assert!(s.recover("pixel-readb", &other).is_err());
    assert!(s.begin(material(), &owner()).is_err());
    drop(s);
    assert_eq!(inspect(&p).unwrap().len(), 1);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn catalog_phase_advances_only_its_exact_recorded_mutation() {
    let p = dir();
    let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let r = s.begin(material(), &owner()).unwrap();
    let tx = r.transaction().to_string();
    let next = s
        .prepare_catalog("pixel-readb", &tx, &owner(), &config())
        .unwrap();
    let before = s.recover("pixel-readb", &owner()).unwrap();
    assert_eq!(before.phase(), Phase::CatalogIntent);
    assert!(
        s.confirm_catalog("pixel-readb", &tx, &owner(), &config())
            .is_err()
    );
    let mut wrong = next.clone();
    wrong.adb = "/another/path".into();
    assert!(
        s.confirm_catalog("pixel-readb", &tx, &owner(), &wrong)
            .is_err()
    );
    s.confirm_catalog("pixel-readb", &tx, &owner(), &next)
        .unwrap();
    let after = s.recover("pixel-readb", &owner()).unwrap();
    assert_eq!(after.phase(), Phase::CatalogAdded);
    assert!(
        s.prepare_catalog("pixel-readb", &tx, &owner(), &next)
            .is_err()
    );
    drop(s);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn journal_rejects_unknown_external_replacement_and_keeps_it() {
    let p = dir();
    let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    s.begin(material(), &owner()).unwrap();
    let journal = p.join("enrollment/journal.json");
    fs::write(&journal, b"{external").unwrap();
    assert!(s.recover("pixel-readb", &owner()).is_err());
    assert!(s.begin(material(), &owner()).is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"{external");
    drop(s);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn symlinks_permissions_and_corruption_fail_closed() {
    for case in 0..3 {
        let p = dir();
        let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
        s.begin(material(), &owner()).unwrap();
        drop(s);
        let path = p.join("enrollment/journal.json");
        let saved = fs::read(&path).unwrap();
        match case {
            0 => {
                let foreign = p.join("foreign");
                fs::write(&foreign, &saved).unwrap();
                fs::remove_file(&path).unwrap();
                symlink(&foreign, &path).unwrap();
            }
            1 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => {
                fs::write(&path, b"{}").unwrap();
            }
        }
        assert!(inspect(&p).is_err());
        assert!(Store::open(&p, "/usr/bin/wg".as_ref()).is_err());
        fs::remove_dir_all(p).unwrap();
    }
}
#[test]
fn pending_device_startup_and_cached_backends_refuse_every_ordinary_entry() {
    let p = dir();
    let mut s = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let r = s.begin(material(), &owner()).unwrap();
    let tx = r.transaction().to_string();
    let mut next = s
        .prepare_catalog("pixel-readb", &tx, &owner(), &config())
        .unwrap();
    s.confirm_catalog("pixel-readb", &tx, &owner(), &next)
        .unwrap();
    let mut other = next.devices[0].clone();
    other.id = "existing".into();
    other.peer = "10.99.0.3".parse().unwrap();
    other.adb_port = 5037;
    next.devices.push(other);
    drop(s);
    let registry = readb::registry::Registry::new(next, p.clone()).unwrap();
    let pending = registry.device("pixel-readb").unwrap();
    assert!(
        pending
            .claim(owner(), 90)
            .unwrap_err()
            .contains("enrollment_pending")
    );
    assert!(
        pending
            .watch(owner(), 90)
            .unwrap_err()
            .contains("enrollment_pending")
    );
    assert!(
        pending
            .report(readb::policy::Report {
                port: 40000,
                battery: 80
            })
            .unwrap_err()
            .contains("enrollment_pending")
    );
    assert!(
        pending
            .prepare("not-a-ticket", vec!["devices".into()])
            .err()
            .unwrap()
            .contains("enrollment_pending")
    );
    assert!(
        pending
            .set_keepalive("not-a-ticket", true, true)
            .unwrap_err()
            .contains("enrollment_pending")
    );
    assert!(
        pending
            .begin_network("not-a-ticket", "network-enroll")
            .unwrap_err()
            .contains("enrollment_pending")
    );
    assert!(pending.keepalive().is_err());
    assert!(pending.status()["enrollment_pending"] == true);
    let existing = registry.device("existing").unwrap();
    let ticket = existing.claim(owner(), 90).unwrap();
    existing.release(&ticket).unwrap();
    // Loss of journal must never reopen a cached device or fresh daemon.
    fs::remove_file(p.join("enrollment/journal.json")).unwrap();
    assert!(pending.claim(owner(), 90).is_err());
    assert!(registry.refresh_enrollments().is_err());
    assert!(readb::registry::Registry::new(registry.config(), p.clone()).is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn internal_claim_retains_barrier_and_recovers_only_original_owner_without_stealing() {
    let p = dir();
    let mut store = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let first = store.begin(material(), &owner()).unwrap();
    let next = store
        .prepare_catalog("pixel-readb", first.transaction(), &owner(), &config())
        .unwrap();
    store
        .confirm_catalog("pixel-readb", first.transaction(), &owner(), &next)
        .unwrap();
    let registry = readb::registry::Registry::new(next, p.clone()).unwrap();
    let healthy = || Ok(serde_json::json!({"fenced":false,"scoped_controller":true}));
    assert!(
        registry
            .claim_enrollment(&mut store, "pixel-readb", &owner(), || Ok(
                serde_json::json!({"fenced":true,"scoped_controller":true})
            ))
            .is_err()
    );
    let ticket = registry
        .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
        .unwrap();
    assert_eq!(
        registry
            .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
            .unwrap(),
        ticket
    );
    let pending = registry.device("pixel-readb").unwrap();
    assert!(pending.claim(owner(), 90).is_err());
    assert!(pending.prepare(&ticket, vec!["devices".into()]).is_err());
    let mut wrong = owner();
    wrong.session = "wrong-session".into();
    assert!(
        registry
            .claim_enrollment(&mut store, "pixel-readb", &wrong, healthy)
            .is_err()
    );
    // No automatic cancellation of unrelated busy work, even if catalog owner matches.
    {
        let mut state = pending.state.lock().unwrap();
        state
            .gate
            .release(&ticket, readb::backend::lease_now())
            .unwrap();
        state
            .gate
            .claim(wrong, readb::backend::lease_now(), 90)
            .unwrap();
    }
    assert!(
        registry
            .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
            .unwrap_err()
            .contains("busy")
    );
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn expired_idle_ticket_can_rebind_but_persisted_unknown_work_and_other_state_cannot() {
    let p = dir();
    let mut store = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let first = store.begin(material(), &owner()).unwrap();
    let next = store
        .prepare_catalog("pixel-readb", first.transaction(), &owner(), &config())
        .unwrap();
    store
        .confirm_catalog("pixel-readb", first.transaction(), &owner(), &next)
        .unwrap();
    let registry = readb::registry::Registry::new(next.clone(), p.clone()).unwrap();
    let healthy = || Ok(serde_json::json!({"fenced":false,"scoped_controller":true}));
    let before = registry
        .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
        .unwrap();
    let pending = registry.device("pixel-readb").unwrap();
    pending
        .state
        .lock()
        .unwrap()
        .gate
        .lease
        .as_mut()
        .unwrap()
        .expires = readb::backend::lease_now() - 1.;
    let after = registry
        .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
        .unwrap();
    assert_ne!(before, after);
    assert!(pending.prepare(&after, vec!["devices".into()]).is_err());
    let other = dir();
    let mut foreign = Store::open(&other, "/usr/bin/wg".as_ref()).unwrap();
    assert!(
        registry
            .claim_enrollment(&mut foreign, "pixel-readb", &owner(), healthy)
            .unwrap_err()
            .contains("other_state")
    );
    drop(foreign);
    fs::remove_dir_all(other).unwrap();
    // A new daemon cannot treat a leftover durable operation as an expired idle job.
    fs::write(pending.config.dir.join("active-operation.json"), b"{}").unwrap();
    fs::set_permissions(
        pending.config.dir.join("active-operation.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    drop(registry);
    drop(pending);
    let restarted = readb::registry::Registry::new(next, p.clone()).unwrap();
    assert!(
        restarted
            .claim_enrollment(&mut store, "pixel-readb", &owner(), healthy)
            .unwrap_err()
            .contains("cleanup_unknown")
    );
    drop(store);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn ordinary_catalog_add_cannot_race_an_inflight_enrollment_allocator() {
    let p = dir();
    let registry = readb::registry::Registry::new(config(), p.clone()).unwrap();
    let allocation = Store::open(&p, "/usr/bin/wg".as_ref()).unwrap();
    let import = material().server_import().unwrap();
    let result = registry.add(import.device.clone(), import.listener.clone());
    assert!(result.err().is_some_and(|e| e.contains("enrollment_busy")));
    assert!(registry.config().devices.is_empty());
    drop(allocation);
    registry.add(import.device, import.listener).unwrap();
    fs::remove_dir_all(p).unwrap();
}
