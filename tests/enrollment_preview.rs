use readb::{
    enrollment_preview::{Probe, handle},
    enrollment_profile::{Facts, Request},
    network::{Policy, Snapshot},
    registry::Registry,
    schema::{Kind, ServerConfig},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
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
        snapshot: Snapshot {
            server_key: key('E'),
            addresses: vec!["10.99.0.2/24".into()],
            peers: BTreeMap::new(),
        },
        managed: BTreeMap::new(),
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
fn rpc() -> readb::control::Request {
    let mut r = readb::client::request("device-enroll-preview", Some("pixel-readb"));
    r.args = vec![serde_json::to_string(&request()).unwrap()];
    r
}
fn registry() -> Registry {
    let p = std::env::temp_dir().join(format!("readb-preview-{}", readb::policy::random()));
    Registry::new(
        ServerConfig {
            schema: 1,
            adb: "/must-not-execute".into(),
            devices: vec![],
            listeners: vec![],
        },
        p,
    )
    .unwrap()
}
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, p: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(p).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                visit(root, &e.path(), out)
            } else {
                out.insert(
                    e.path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    fs::read(e.path()).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
struct Fake {
    facts_calls: usize,
    port_calls: usize,
    change: bool,
    occupy: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            facts_calls: 0,
            port_calls: 0,
            change: false,
            occupy: false,
        }
    }
}
impl Probe for Fake {
    fn facts(&mut self) -> readb::policy::Res<Facts> {
        self.facts_calls += 1;
        let mut f = facts();
        if self.change && self.facts_calls > 1 {
            f.snapshot
                .peers
                .insert(key('C'), vec!["10.99.0.149/32".into()]);
        }
        Ok(f)
    }
    fn listening_ports(&mut self) -> readb::policy::Res<BTreeSet<u16>> {
        self.port_calls += 1;
        Ok(if self.occupy && self.port_calls > 1 {
            BTreeSet::from([5040])
        } else {
            BTreeSet::new()
        })
    }
}
#[test]
fn preview_returns_only_advisory_candidate_and_missing_firewall_gate_without_side_effects() {
    let r = registry();
    let before = tree(&r.root);
    let mut p = Fake::new();
    let v = handle(&r, &rpc(), &mut p).unwrap();
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["can_apply"], false);
    assert_eq!(v["profile_deliverable"], false);
    assert_eq!(v["candidate"]["peer"], "10.99.0.100");
    assert_eq!(v["candidate"]["adb_port"], 5040);
    assert!(
        v["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "report_firewall_setup_required")
    );
    assert_eq!(v["firewall"]["available"], false);
    assert_eq!(p.facts_calls, 2);
    assert_eq!(p.port_calls, 2);
    assert_eq!(tree(&r.root), before);
    assert!(!r.root.join("enrollment").exists());
    let text = v.to_string();
    for forbidden in ["private_key", "token", "ticket"] {
        assert!(!text.contains(forbidden));
    }
    fs::remove_dir_all(r.root).unwrap();
}
#[test]
fn malformed_or_authority_bearing_preview_never_contacts_helper() {
    let r = registry();
    for case in 0..5 {
        let mut req = rpc();
        match case {
            0 => req.ticket = "not-a-ticket".into(),
            1 => {
                req.owner = Some(readb::policy::Owner {
                    agent: "a".into(),
                    origin: "b".into(),
                    session: "c".into(),
                    job: "d".into(),
                    allow_sleep: false,
                })
            }
            2 => req.device = "another".into(),
            3 => req.args = vec!["{\"private_key\":\"must-not-echo\"}".into()],
            _ => req.args.clear(),
        };
        let mut p = Fake::new();
        assert!(handle(&r, &req, &mut p).is_err());
        assert_eq!(p.facts_calls, 0);
        assert_eq!(p.port_calls, 0);
    }
    fs::remove_dir_all(r.root).unwrap();
}
#[test]
fn root_or_port_changes_invalidate_the_candidate_instead_of_replanning_in_a_loop() {
    for ports in [false, true] {
        let r = registry();
        let before = tree(&r.root);
        let mut p = Fake::new();
        p.change = !ports;
        p.occupy = ports;
        let v = handle(&r, &rpc(), &mut p).unwrap();
        assert!(v["candidate"].is_null());
        assert!(
            v["blockers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "enrollment_snapshot_changed")
        );
        assert!(p.facts_calls <= 2 && p.port_calls <= 2);
        assert_eq!(tree(&r.root), before);
        fs::remove_dir_all(r.root).unwrap();
    }
}
#[test]
fn maintenance_and_unknown_journal_block_before_public_helper_reads() {
    for corrupt in [false, true] {
        let r = registry();
        if corrupt {
            fs::create_dir(r.root.join("enrollment")).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(r.root.join("enrollment"), fs::Permissions::from_mode(0o700))
                .unwrap();
            fs::write(r.root.join("enrollment/journal.json"), b"{unknown").unwrap();
            fs::set_permissions(
                r.root.join("enrollment/journal.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        } else {
            r.prepare_maintenance(&"a".repeat(64), &r.config_fingerprint().unwrap())
                .unwrap();
        }
        let before = tree(&r.root);
        let mut p = Fake::new();
        let v = handle(&r, &rpc(), &mut p).unwrap();
        assert!(v["candidate"].is_null());
        assert!(!v["blockers"].as_array().unwrap().is_empty());
        assert_eq!(p.facts_calls, 0);
        assert_eq!(p.port_calls, 0);
        assert_eq!(tree(&r.root), before);
        fs::remove_dir_all(r.root).unwrap();
    }
}

#[test]
fn actual_daemon_rpc_rejects_authority_bearing_preview_without_helper_or_writes() {
    use std::{io::Write, os::unix::net::UnixStream, sync::Arc, thread};
    let registry = Arc::new(registry());
    let before = tree(&registry.root);
    let (mut client, server) = UnixStream::pair().unwrap();
    let r = registry.clone();
    let h = thread::spawn(move || readb::daemon::control_client(server, r));
    let mut req = rpc();
    req.ticket = "not-authority-for-preview".into();
    writeln!(client, "{}", serde_json::to_string(&req).unwrap()).unwrap();
    let (tag, data) = readb::wire::read_frame(&mut client).unwrap();
    assert_eq!(tag, 2);
    let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
    assert!(v["error"].as_str().unwrap().contains("without_authority"));
    let (tag, data) = readb::wire::read_frame(&mut client).unwrap();
    assert_eq!(tag, 3);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&data).unwrap()["code"],
        78
    );
    h.join().unwrap();
    assert_eq!(tree(&registry.root), before);
    fs::remove_dir_all(&registry.root).unwrap();
}
