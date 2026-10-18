use readb::setup_upgrade::{Action, Actions, Journal, Observation};
struct Fake {
    ready: [bool; 9],
    calls: usize,
    lose: Option<Action>,
    binding: Vec<u8>,
}
impl Actions for Fake {
    fn confirm(&mut self, _: Action, _: &Journal) -> Result<(), String> {
        Ok(())
    }
    fn admit(&mut self, _: &Journal) -> Result<(), String> {
        Ok(())
    }
    fn inspect(&mut self, a: Action) -> Result<Observation, String> {
        let done = self.ready[a.index()];
        Ok(Observation {
            fingerprint: format!("{:064x}", a.index() * 2 + usize::from(done)),
            ready: done,
            retry_safe: !done,
        })
    }
    fn apply(&mut self, a: Action, j: &mut Journal, _: bool) -> Result<(), String> {
        if a == Action::Binding {
            j.publish_binding(&self.binding)?;
        }
        self.ready[a.index()] = true;
        self.calls += 1;
        if self.lose == Some(a) {
            self.lose = None;
            Err("lost ack".into())
        } else {
            Ok(())
        }
    }
}
use readb::{policy::random, setup_journal::inspect_completed};
use std::{fs, os::unix::fs::PermissionsExt};
fn fixture() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("readb-upgrade-{}", random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    let state = serde_json::json!({"schema":1,"plan_sha256":"a".repeat(64),"provider_sha256":"b".repeat(64),"completed":["preflight","dependencies","network","coordinator","persistence"],"running":null,"activation":{"completed":readb::setup_activation::ACTIONS.iter().map(|a|serde_json::json!({"action":a,"before":"c".repeat(64),"after":"d".repeat(64)})).collect::<Vec<_>>(),"pending":null}});
    fs::write(p.join("journal.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    fs::set_permissions(p.join("journal.json"), fs::Permissions::from_mode(0o600)).unwrap();
    p
}
#[test]
fn completed_proof_is_read_only_and_holds_setup_lock() {
    let p = fixture();
    let original = fs::read(p.join("journal.json")).unwrap();
    let proof = inspect_completed(&p, &"a".repeat(64), &"b".repeat(64)).unwrap();
    assert_eq!(proof.bytes(), original);
    assert_eq!(proof.sha256().len(), 64);
    assert!(inspect_completed(&p, &"a".repeat(64), &"b".repeat(64)).is_err());
    assert_eq!(fs::read(p.join("journal.json")).unwrap(), original);
    assert_eq!(fs::read_dir(&p).unwrap().count(), 1);
    drop(proof);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn proof_refuses_changed_binding_incomplete_activation_and_unsafe_files() {
    let p = fixture();
    let original = fs::read(p.join("journal.json")).unwrap();
    assert!(inspect_completed(&p, &"c".repeat(64), &"b".repeat(64)).is_err());
    assert!(inspect_completed(&p, &"a".repeat(64), &"c".repeat(64)).is_err());
    for field in ["running", "activation", "completed"] {
        let mut v: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match field {
            "running" => v[field] = serde_json::json!("enrollment"),
            "activation" => v[field] = serde_json::json!({"completed":[],"pending":null}),
            _ => v[field] = serde_json::json!(["preflight"]),
        }
        fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(inspect_completed(&p, &"a".repeat(64), &"b".repeat(64)).is_err());
    }
    fs::write(p.join("journal.json"), &original).unwrap();
    fs::hard_link(p.join("journal.json"), p.join("alias")).unwrap();
    assert!(inspect_completed(&p, &"a".repeat(64), &"b".repeat(64)).is_err());
    fs::remove_dir_all(p).unwrap();
}
fn plans() -> (readb::setup_apply::ApplyPlan, readb::setup_apply::ApplyPlan) {
    use readb::{
        network::{Policy, Snapshot},
        setup::{NetworkMode, Options},
        setup_apply::{Owner, bind},
    };
    let o = Options {
        endpoint: "vpn.example.org:51820".into(),
        interface: "mobile".into(),
        address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        listen_port: 51820,
        mode: NetworkMode::Reuse,
    };
    let u = Owner {
        name: "tester".into(),
        uid: 1000,
        gid: 1000,
        home: "/home/tester".into(),
    };
    let p = Policy {
        schema: 1,
        uid: 1000,
        interface: "mobile".into(),
        server_key: format!("{}AAA=", "E".repeat(40)),
        server_address: o.address,
        prefix: 24,
        first: "10.88.0.100".parse().unwrap(),
        last: "10.88.0.110".parse().unwrap(),
    };
    let snap = Snapshot {
        server_key: p.server_key.clone(),
        addresses: vec!["10.88.0.1/24".into()],
        peers: Default::default(),
    };
    (
        bind(o.clone(), u.clone(), p.clone(), snap.clone(), b"old").unwrap(),
        bind(o, u, p, snap, b"new").unwrap(),
    )
}
#[test]
fn upgrade_plan_changes_only_software_and_never_adopts_changed_network() {
    use readb::setup_upgrade::Plan;
    let (old, mut new) = plans();
    let upgrade = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    assert_eq!(upgrade.old_image().len(), 64);
    assert_ne!(upgrade.old_image(), upgrade.new_image());
    assert!(Plan::new(&old, &old, b"old", b"old", &"b".repeat(64)).is_err());
    new.baseline_sha256 = "c".repeat(64);
    assert!(Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).is_err());
}
#[test]
fn pending_upgrade_blocks_setup_and_lost_action_reply_requires_verified_recovery() {
    use readb::setup_upgrade::{self, Journal, Plan};
    let p = fixture();
    let (old, new) = plans();
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
    v["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    let original = proof.bytes().to_vec();
    let mut next = v.clone();
    next["plan_sha256"] = serde_json::json!(new.plan_sha256);
    let binding = serde_json::to_vec(&next).unwrap();
    let mut j = Journal::begin(proof, plan.clone()).unwrap();
    let mut f = Fake {
        ready: [false; 9],
        calls: 0,
        lose: Some(Action::Maintenance),
        binding: binding.clone(),
    };
    assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
    assert_eq!(f.calls, 1);
    drop(j);
    assert_eq!(
        readb::setup_upgrade::recorded_plan(&p)
            .unwrap()
            .unwrap()
            .identity(),
        plan.identity()
    );
    assert!(readb::setup_journal::Journal::open(&p, &old.plan_sha256).is_err());
    let mut j = Journal::open(&p, &plan).unwrap();
    assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
    setup_upgrade::run(&mut j, &mut f, true).unwrap();
    assert_eq!(f.calls, 9);
    assert!(j.complete());
    assert_eq!(j.original_setup(), original);
    assert_eq!(fs::read(p.join("journal.json")).unwrap(), binding);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn stale_original_proof_cannot_publish_an_upgrade_intent() {
    use readb::setup_upgrade::{Journal, Plan};
    let p = fixture();
    let (old, new) = plans();
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
    v["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    fs::write(p.join("journal.json"), b"external edit").unwrap();
    assert!(Journal::begin(proof, plan).is_err());
    assert!(!p.join("upgrade.json").exists());
    assert_eq!(fs::read(p.join("journal.json")).unwrap(), b"external edit");
    fs::remove_dir_all(p).unwrap();
}

fn finished_upgrade() -> (
    std::path::PathBuf,
    readb::setup_apply::ApplyPlan,
    readb::setup_apply::ApplyPlan,
) {
    use readb::setup_upgrade::{self, Plan};
    let p = fixture();
    let (old, new) = plans();
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
    v["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    let mut j = Journal::begin(proof, plan).unwrap();
    v["plan_sha256"] = serde_json::json!(new.plan_sha256);
    let binding = serde_json::to_vec(&v).unwrap();
    let mut f = Fake {
        ready: [false; 9],
        calls: 0,
        lose: None,
        binding,
    };
    setup_upgrade::run(&mut j, &mut f, false).unwrap();
    drop(j);
    (p, old, new)
}
#[test]
fn completed_upgrade_rejects_reverted_binding_but_allows_legitimate_next_setup_phase() {
    let (p, old, new) = finished_upgrade();
    let binding = fs::read(p.join("journal.json")).unwrap();
    let mut j = readb::setup_journal::Journal::open(&p, &new.plan_sha256).unwrap();
    j.begin(readb::setup_journal::Phase::Enrollment).unwrap();
    drop(j);
    assert!(readb::setup_journal::Journal::open(&p, &new.plan_sha256).is_ok());
    let mut reverted: serde_json::Value = serde_json::from_slice(&binding).unwrap();
    reverted["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(
        p.join("journal.json"),
        serde_json::to_vec(&reverted).unwrap(),
    )
    .unwrap();
    assert!(readb::setup_journal::Journal::open(&p, &old.plan_sha256).is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn next_upgrade_retains_completed_upgrade_evidence_before_new_intent() {
    use readb::{network::Snapshot, setup_apply::bind, setup_upgrade::Plan};
    let (p, _, old) = finished_upgrade();
    let snap = Snapshot {
        server_key: old.policy.server_key.clone(),
        addresses: vec!["10.88.0.1/24".into()],
        peers: Default::default(),
    };
    let new = bind(
        old.options.clone(),
        old.owner.clone(),
        old.policy.clone(),
        snap,
        b"third",
    )
    .unwrap();
    let before = fs::read(p.join("upgrade.json")).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    let plan = Plan::new(&old, &new, b"new", b"third", &"b".repeat(64)).unwrap();
    let j = Journal::begin(proof, plan).unwrap();
    assert!(!j.complete());
    let histories = fs::read_dir(&p)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("upgrade-history-")
        })
        .collect::<Vec<_>>();
    assert_eq!(histories.len(), 1);
    assert_eq!(fs::read(&histories[0]).unwrap(), before);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn changed_pending_upgrade_is_rejected_before_retry_effect() {
    use readb::setup_upgrade::{self, Plan};
    let p = fixture();
    let (old, new) = plans();
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
    v["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    let mut j = Journal::begin(proof, plan.clone()).unwrap();
    v["plan_sha256"] = serde_json::json!(new.plan_sha256);
    let mut f = Fake {
        ready: [false; 9],
        calls: 0,
        lose: Some(Action::Maintenance),
        binding: serde_json::to_vec(&v).unwrap(),
    };
    assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
    drop(j);
    f.ready[0] = false;
    struct Tamper {
        f: Fake,
        path: std::path::PathBuf,
    }
    impl Actions for Tamper {
        fn confirm(&mut self, _: Action, _: &Journal) -> Result<(), String> {
            Ok(())
        }
        fn admit(&mut self, _: &Journal) -> Result<(), String> {
            fs::write(&self.path, b"external pending edit").unwrap();
            Ok(())
        }
        fn inspect(&mut self, a: Action) -> Result<Observation, String> {
            self.f.inspect(a)
        }
        fn apply(&mut self, a: Action, j: &mut Journal, r: bool) -> Result<(), String> {
            self.f.apply(a, j, r)
        }
    }
    let mut j = Journal::open(&p, &plan).unwrap();
    let mut f = Tamper {
        f,
        path: p.join("upgrade.json"),
    };
    assert!(setup_upgrade::run(&mut j, &mut f, true).is_err());
    assert_eq!(
        f.f.calls, 1,
        "external edit must be detected before a retry effect"
    );
    assert_eq!(
        fs::read(p.join("upgrade.json")).unwrap(),
        b"external pending edit"
    );
    drop(j);
    fs::remove_dir_all(p).unwrap();
}

#[test]
fn restart_after_each_lost_action_ack_never_replays_completed_effects() {
    use readb::setup_upgrade::{self, ACTIONS, Plan};
    for action in ACTIONS {
        let p = fixture();
        let (old, new) = plans();
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
        v["plan_sha256"] = serde_json::json!(old.plan_sha256);
        fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
        let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
        let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
        let mut j = Journal::begin(proof, plan.clone()).unwrap();
        v["plan_sha256"] = serde_json::json!(new.plan_sha256);
        let mut f = Fake {
            ready: [false; 9],
            calls: 0,
            lose: Some(action),
            binding: serde_json::to_vec(&v).unwrap(),
        };
        assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
        assert_eq!(f.calls, action.index() + 1);
        assert_eq!(j.pending(), Some(action));
        drop(j);
        let mut j = Journal::open(&p, &plan).unwrap();
        assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
        setup_upgrade::run(&mut j, &mut f, true).unwrap();
        assert_eq!(
            f.calls, 9,
            "lost ack for {action:?} must not replay its effect"
        );
        assert!(j.complete());
        drop(j);
        fs::remove_dir_all(p).unwrap();
    }
}
#[test]
fn visible_ready_effect_requires_durable_adapter_confirmation() {
    use readb::setup_upgrade::{self, Plan};
    struct Unsynced(Fake);
    impl Actions for Unsynced {
        fn admit(&mut self, j: &Journal) -> Result<(), String> {
            self.0.admit(j)
        }
        fn inspect(&mut self, a: Action) -> Result<Observation, String> {
            self.0.inspect(a)
        }
        fn apply(&mut self, a: Action, j: &mut Journal, r: bool) -> Result<(), String> {
            self.0.apply(a, j, r)
        }
        fn confirm(&mut self, _: Action, _: &Journal) -> Result<(), String> {
            Err("directory sync unconfirmed".into())
        }
    }
    let p = fixture();
    let (old, new) = plans();
    let mut v: serde_json::Value =
        serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
    v["plan_sha256"] = serde_json::json!(old.plan_sha256);
    fs::write(p.join("journal.json"), serde_json::to_vec(&v).unwrap()).unwrap();
    let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
    let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
    let mut j = Journal::begin(proof, plan).unwrap();
    let mut ready = [false; 9];
    ready[0] = true;
    let mut f = Unsynced(Fake {
        ready,
        calls: 0,
        lose: None,
        binding: vec![],
    });
    assert!(setup_upgrade::run(&mut j, &mut f, false).is_err());
    assert_eq!(j.completed_count(), 0);
    assert_eq!(j.pending(), Some(Action::Maintenance));
    assert_eq!(f.0.calls, 0);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}

struct Undo {
    ready: [bool; 9],
    calls: Vec<readb::setup_upgrade::RollbackAction>,
    lose: Option<readb::setup_upgrade::RollbackAction>,
}
impl readb::setup_upgrade::RollbackActions for Undo {
    fn admit(&mut self, _: &Journal) -> Result<(), String> {
        Ok(())
    }
    fn inspect(&mut self, a: readb::setup_upgrade::RollbackAction) -> Result<Observation, String> {
        let done = self.ready[a.index()];
        Ok(Observation {
            fingerprint: format!("{:064x}", a.index() * 2 + usize::from(done)),
            ready: done,
            retry_safe: !done,
        })
    }
    fn apply(
        &mut self,
        a: readb::setup_upgrade::RollbackAction,
        j: &mut Journal,
        _: bool,
    ) -> Result<(), String> {
        if a == readb::setup_upgrade::RollbackAction::Binding {
            j.publish_original_binding()?;
        }
        self.calls.push(a);
        self.ready[a.index()] = true;
        if self.lose == Some(a) {
            self.lose = None;
            Err("lost rollback ack".into())
        } else {
            Ok(())
        }
    }
    fn confirm(
        &mut self,
        _: readb::setup_upgrade::RollbackAction,
        _: &Journal,
    ) -> Result<(), String> {
        Ok(())
    }
}
#[test]
fn rollback_preserves_forward_evidence_and_recovers_each_lost_reply_without_stop_replay() {
    use readb::setup_upgrade::{self, Plan, ROLLBACK_ACTIONS};
    for lost in ROLLBACK_ACTIONS {
        let p = fixture();
        let (old, new) = plans();
        let mut v: serde_json::Value =
            serde_json::from_slice(&fs::read(p.join("journal.json")).unwrap()).unwrap();
        v["plan_sha256"] = serde_json::json!(old.plan_sha256);
        let original = serde_json::to_vec(&v).unwrap();
        fs::write(p.join("journal.json"), &original).unwrap();
        let plan = Plan::new(&old, &new, b"old", b"new", &"b".repeat(64)).unwrap();
        let mut j = Journal::begin(
            inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap(),
            plan.clone(),
        )
        .unwrap();
        v["plan_sha256"] = serde_json::json!(new.plan_sha256);
        let mut f = Fake {
            ready: [false; 9],
            calls: 0,
            lose: None,
            binding: serde_json::to_vec(&v).unwrap(),
        };
        setup_upgrade::run(&mut j, &mut f, false).unwrap();
        let before: serde_json::Value =
            serde_json::from_slice(&fs::read(p.join("upgrade.json")).unwrap()).unwrap();
        j.begin_rollback(&"8".repeat(64)).unwrap();
        let mut undo = Undo {
            ready: [false; 9],
            calls: vec![],
            lose: Some(lost),
        };
        assert!(setup_upgrade::run_rollback(&mut j, &mut undo, false).is_err());
        drop(j);
        assert!(readb::setup_journal::Journal::open(&p, &old.plan_sha256).is_err());
        let mut j = Journal::open(&p, &plan).unwrap();
        assert!(setup_upgrade::run_rollback(&mut j, &mut undo, false).is_err());
        assert!(j.begin_rollback(&"9".repeat(64)).is_err());
        j.begin_rollback(&"8".repeat(64)).unwrap();
        setup_upgrade::run_rollback(&mut j, &mut undo, true).unwrap();
        assert!(j.rollback_complete());
        assert!(!j.complete());
        assert_eq!(undo.calls, ROLLBACK_ACTIONS);
        setup_upgrade::run_rollback(&mut j, &mut undo, false).unwrap();
        assert_eq!(undo.calls, ROLLBACK_ACTIONS);
        assert!(setup_upgrade::run(&mut j, &mut f, true).is_err());
        let after: serde_json::Value =
            serde_json::from_slice(&fs::read(p.join("upgrade.json")).unwrap()).unwrap();
        for k in ["plan", "original", "binding", "completed", "pending"] {
            assert_eq!(before[k], after[k]);
        }
        assert_eq!(fs::read(p.join("journal.json")).unwrap(), original);
        drop(j);
        let legacy = readb::setup_journal::Journal::open(&p, &old.plan_sha256).unwrap();
        drop(legacy);
        let proof = inspect_completed(&p, &old.plan_sha256, &"b".repeat(64)).unwrap();
        let j = Journal::begin(proof, plan).unwrap();
        assert_eq!(j.completed_count(), 0);
        drop(j);
        assert_eq!(fs::read_dir(&p).unwrap().count(), 3);
        fs::remove_dir_all(p).unwrap();
    }
}
