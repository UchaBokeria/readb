use readb::{
    network::{Peer, Policy},
    report_firewall::*,
    schema::*,
};
use std::collections::BTreeMap;
fn key(c: char) -> String {
    format!("{}AAA=", c.to_string().repeat(40))
}
fn bound() -> (Policy, BTreeMap<String, Peer>, ServerConfig) {
    let p = Policy {
        schema: 1,
        uid: 1000,
        interface: "mobile".into(),
        server_key: key('E'),
        server_address: "10.99.0.2".parse().unwrap(),
        prefix: 24,
        first: "10.99.0.100".parse().unwrap(),
        last: "10.99.0.150".parse().unwrap(),
    };
    let peer = Peer {
        key: key('B'),
        address: "10.99.0.100".parse().unwrap(),
    };
    let c = ServerConfig {
        schema: 1,
        adb: "/not-executed".into(),
        devices: vec![Device {
            id: "phone".into(),
            name: "Phone".into(),
            kind: Kind::Phone,
            peer: peer.address,
            adb_port: 5040,
            token: "x".repeat(64),
            identity: String::new(),
            keepalive: Keepalive::default(),
            recipient: None,
        }],
        listeners: vec![Listener {
            bind: "10.99.0.2:19193".parse().unwrap(),
            path: "/v2/phone".into(),
            device: "phone".into(),
            format: ReportFormat::V2,
        }],
    };
    (p, BTreeMap::from([("phone".into(), peer)]), c)
}
fn rule() -> ReportRule {
    let (p, m, c) = bound();
    ReportRule::from_bound(&p, &m, &c, "phone").unwrap()
}
fn host() -> HostFacts {
    HostFacts {
        schema: 1,
        adapter: "ufw-0.36.2-iptables-1.8.10-nft".into(),
        active: true,
        topology: "ufw-v4-input-linear-v1".into(),
        tools: vec![
            ToolFact {
                canonical: "/usr/sbin/ufw".into(),
                uid: 0,
                mode: 0o755,
                regular: true,
                links: 1,
                ancestors_root_protected: true,
                sha256: "a".repeat(64),
            },
            ToolFact {
                canonical: "/usr/sbin/xtables-nft-multi".into(),
                uid: 0,
                mode: 0o755,
                regular: true,
                links: 1,
                ancestors_root_protected: true,
                sha256: "b".repeat(64),
            },
        ],
    }
}
fn snapshot() -> Snapshot {
    Snapshot {
        host: host(),
        kernel: View {
            rules: vec![],
            insert_at: 0,
        },
        persistent: View {
            rules: vec![],
            insert_at: 0,
        },
        other_state: "c".repeat(64),
    }
}
fn entry(r: &ReportRule, verdict: Verdict) -> Entry {
    Entry {
        selector: r.selector(),
        verdict,
        comment: None,
    }
}
#[test]
fn bound_tuple_is_exact_and_never_adopts_unmanaged_or_wildcard_inputs() {
    let r = rule();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["source"], "10.99.0.100");
    assert_eq!(v["destination"], "10.99.0.2");
    assert_eq!(v["port"], 19193);
    assert!(!serde_json::to_string(&r).unwrap().contains(&"x".repeat(64)));
    let (p, m, mut c) = bound();
    c.listeners[0].bind = "0.0.0.0:19193".parse().unwrap();
    assert!(ReportRule::from_bound(&p, &m, &c, "phone").is_err());
    let (p, mut m, c) = bound();
    m.get_mut("phone").unwrap().address = "10.99.0.101".parse().unwrap();
    assert!(ReportRule::from_bound(&p, &m, &c, "phone").is_err());
    let (p, m, mut c) = bound();
    c.listeners[0].format = ReportFormat::V1;
    assert!(ReportRule::from_bound(&p, &m, &c, "phone").is_err());
    let (p, m, mut c) = bound();
    c.listeners[0].bind = "10.99.0.2:5040".parse().unwrap();
    assert!(ReportRule::from_bound(&p, &m, &c, "phone").is_err());
}
#[test]
fn exact_ensure_recovery_and_owned_revoke_preserve_all_other_state() {
    let r = rule();
    let before = snapshot();
    let i = Intent::ensure(r.clone(), before.clone()).unwrap();
    assert!(matches!(i.observe(&before).unwrap(), Observation::Before));
    let after = i.expected_after();
    let Observation::After(receipt) = i.observe(&after).unwrap() else {
        panic!()
    };
    receipt.check_current(&rule(), &after).unwrap();
    let revoke = Intent::revoke(rule(), &receipt, after.clone()).unwrap();
    assert!(matches!(
        revoke.observe(&after).unwrap(),
        Observation::Before
    ));
    let removed = revoke.expected_after();
    assert_eq!(removed, before);
    assert!(matches!(
        revoke.observe(&removed).unwrap(),
        Observation::After(_)
    ));
    assert!(
        Intent::ensure(r, after)
            .unwrap_err()
            .contains("foreign_or_existing")
    );
}
#[test]
fn races_foreign_rules_and_shadowing_fail_closed() {
    let r = rule();
    let i = Intent::ensure(r.clone(), snapshot()).unwrap();
    let mut race = i.expected_after();
    race.other_state = "d".repeat(64);
    assert!(i.observe(&race).unwrap_err().contains("drift"));
    for verdict in [
        Verdict::Drop,
        Verdict::Reject,
        Verdict::Accept,
        Verdict::Unknown,
    ] {
        let mut s = snapshot();
        s.kernel.rules.push(entry(&r, verdict));
        s.kernel.insert_at = 1;
        s.persistent = s.kernel.clone();
        assert!(Intent::ensure(r.clone(), s).is_err());
    }
    let mut s = snapshot();
    let mut e = entry(&r, Verdict::Drop);
    e.selector.source = "10.99.0.101/32".parse().unwrap();
    s.kernel.rules.push(e);
    s.kernel.insert_at = 1;
    s.persistent = s.kernel.clone();
    assert!(Intent::ensure(r.clone(), s).is_ok());
    let mut s = i.expected_after();
    s.kernel.rules[0].comment = Some("someone-else".into());
    assert!(i.observe(&s).is_err());
    let mut s = i.expected_after();
    s.kernel.rules.push(s.kernel.rules[0].clone());
    assert!(i.observe(&s).is_err());
}
#[test]
fn receipt_survives_disjoint_other_device_rules_but_not_own_shadowing() {
    let i = Intent::ensure(rule(), snapshot()).unwrap();
    let mut s = i.expected_after();
    let Observation::After(r) = i.observe(&s).unwrap() else {
        panic!()
    };
    let mut other = entry(&rule(), Verdict::Accept);
    other.selector.source = "10.99.0.101/32".parse().unwrap();
    s.kernel.rules.insert(0, other.clone());
    s.kernel.insert_at += 1;
    s.persistent = s.kernel.clone();
    s.other_state = "d".repeat(64);
    r.check_current(&rule(), &s).unwrap();
    s.kernel.rules.insert(0, entry(&rule(), Verdict::Drop));
    s.kernel.insert_at += 1;
    s.persistent = s.kernel.clone();
    assert!(r.check_current(&rule(), &s).is_err());
}
#[test]
fn unsupported_host_and_unprotected_tool_facts_are_not_capabilities() {
    for which in 0..12 {
        let mut s = snapshot();
        match which {
            0 => s.host.active = false,
            1 => s.host.adapter = "firewalld".into(),
            2 => s.host.topology = "unknown-nft-hook".into(),
            3 => s.host.tools[0].uid = 1000,
            4 => s.host.tools[0].mode = 0o777,
            5 => s.host.tools[0].ancestors_root_protected = false,
            6 => s.host.tools[1].canonical = "/tmp/iptables".into(),
            7 => s.host.tools[0].regular = false,
            8 => s.host.tools[0].links = 2,
            9 => s.host.tools[0].sha256 = "not-a-digest".into(),
            10 => s.host.tools[0].mode = 0o4755,
            _ => s.host.tools[1].canonical = "/usr/sbin/ufw".into(),
        };
        assert!(Intent::ensure(rule(), s).is_err());
    }
    assert_eq!(prerequisite().code(), "report_firewall_setup_required");
    assert!(!prerequisite().available());
}
#[test]
fn malformed_normalized_predicates_and_unknown_fields_are_rejected() {
    assert!("10.99.0.100/24".parse::<Cidr>().is_err());
    assert!("0.0.0.0/33".parse::<Cidr>().is_err());
    let mut s = snapshot();
    let mut e = entry(&rule(), Verdict::Continue);
    e.selector.port = Some((200, 100));
    s.kernel.rules.push(e);
    assert!(Intent::ensure(rule(), s).is_err());
    let mut s = serde_json::to_value(snapshot()).unwrap();
    s["untrusted"] = true.into();
    assert!(serde_json::from_value::<Snapshot>(s).is_err());
}

#[test]
fn broad_prior_drop_unknown_predicate_and_boundary_corruption_refuse() {
    let r = rule();
    for unknown in [false, true] {
        let mut s = snapshot();
        let mut e = entry(
            &r,
            if unknown {
                Verdict::Continue
            } else {
                Verdict::Drop
            },
        );
        e.selector.interface = None;
        e.selector.source = "10.99.0.0/24".parse().unwrap();
        e.selector.destination = "0.0.0.0/0".parse().unwrap();
        e.selector.port = None;
        e.selector.protocol = Protocol::Any;
        e.selector.unknown = unknown;
        s.kernel.rules.push(e);
        s.kernel.insert_at = 1;
        s.persistent = s.kernel.clone();
        assert!(Intent::ensure(r.clone(), s).is_err());
    }
    let i = Intent::ensure(r, snapshot()).unwrap();
    let s = i.expected_after();
    let Observation::After(receipt) = i.observe(&s).unwrap() else {
        panic!()
    };
    let mut invalid = s.clone();
    invalid.kernel.insert_at = 0;
    invalid.persistent = invalid.kernel.clone();
    assert!(Intent::revoke(rule(), &receipt, invalid).is_err());
    let mut changed = s;
    changed.host.tools[0].sha256 = "e".repeat(64);
    assert!(
        receipt
            .check_current(&rule(), &changed)
            .unwrap_err()
            .contains("host_changed")
    );
}

#[test]
fn saved_receipt_cannot_outlive_root_policy_or_registered_peer_identity() {
    let i = Intent::ensure(rule(), snapshot()).unwrap();
    let s = i.expected_after();
    let Observation::After(receipt) = i.observe(&s).unwrap() else {
        panic!()
    };
    let (mut p, m, c) = bound();
    p.server_key = key('C');
    let changed = ReportRule::from_bound(&p, &m, &c, "phone").unwrap();
    assert!(receipt.check_current(&changed, &s).is_err());
    assert!(Intent::revoke(changed, &receipt, s.clone()).is_err());
    let (p, mut m, c) = bound();
    m.get_mut("phone").unwrap().key = key('D');
    let changed = ReportRule::from_bound(&p, &m, &c, "phone").unwrap();
    assert!(receipt.check_current(&changed, &s).is_err());
}
