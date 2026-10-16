use readb::policy::*;
#[test]
fn strict_report() {
    assert!(Report::parse(br#"{"port":40000,"battery":73}"#).is_ok());
    for b in [
        br#"{"port":true,"battery":73}"#.as_slice(),
        br#"{"port":22,"battery":73}"#,
        br#"{"port":40000,"battery":101}"#,
        br#"{"port":40000,"battery":73,"extra":1}"#,
        br#"{"port":40000,"port":40001,"battery":73}"#,
    ] {
        assert!(Report::parse(b).is_err());
    }
}
fn owner(job: &str) -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "session1".into(),
        job: job.into(),
        allow_sleep: false,
    }
}
#[test]
fn job_conflicts_and_bad_ticket() {
    let mut g = Gate::new();
    let t = g.claim(owner("X"), 0., 90).unwrap();
    let busy = g.claim(owner("Y"), 1., 90).unwrap_err();
    assert!(busy.contains("X"));
    assert!(busy.starts_with("device_busy:"));
    assert!(busy.contains("expires in 89s"));
    assert!(g.authorize("wrong", 1.).is_err());
    assert!(g.authorize(&t, 1.).is_ok());
}
#[test]
fn expires_and_fences_unknown_work() {
    let mut g = Gate::new();
    let t = g.claim(owner("X"), 0., 90).unwrap();
    g.begin(&t, 1., false).unwrap();
    g.cancel("timeout");
    assert!(
        g.claim(owner("Y"), 100., 90)
            .unwrap_err()
            .contains("cleanup_unknown")
    );
    assert!(g.authorize(&t, 101.).is_err());
}
#[test]
fn pure_work_cancel_can_release() {
    let mut g = Gate::new();
    let t = g.claim(owner("X"), 0., 90).unwrap();
    g.begin(&t, 1., true).unwrap();
    g.cancel("timeout");
    g.finish();
    assert!(g.claim(owner("Y"), 100., 90).is_ok());
}
#[test]
fn expired_ticket_cannot_rearm() {
    let mut g = Gate::new();
    let t = g.claim(owner("X"), 0., 10).unwrap();
    assert!(g.authorize(&t, 11.).is_err());
    assert!(g.claim(owner("Y"), 12., 10).is_ok());
    assert!(g.authorize(&t, 12.).is_err());
}
#[test]
fn control_char_metadata_and_ttl_rejected() {
    let mut g = Gate::new();
    let mut o = owner("X");
    o.job = "bad\njob".into();
    assert!(g.claim(o, 0., 90).is_err());
    assert!(g.claim(owner("X"), 0., 0).is_err());
}
#[test]
fn receipt_gate() {
    let r = Receipt {
        received_at: 100.,
        port: 40000,
        battery: 73,
        connected: true,
        identity_verified: true,
        transport_cleanup_failed: false,
    };
    assert!(r.fresh(101.));
    assert!(!r.fresh(99.));
    assert!(!r.fresh(281.));
}
#[test]
fn notification_hysteresis() {
    let mut n = Notice::default();
    assert!(!n.eligible(21, 0.));
    assert!(n.eligible(20, 0.));
    n.success(1., "test".into(), 20);
    assert!(!n.eligible(4, 300.));
    n.rearm(29);
    assert!(!n.eligible(4, 300.));
    n.rearm(30);
    assert!(n.eligible(4, 300.));
}
#[test]
fn active_cancel_cannot_reassign_before_local_exit() {
    let mut g = Gate::new();
    let t = g.claim(owner("X"), 0., 90).unwrap();
    g.begin(&t, 1., true).unwrap();
    g.cancel("client_lost");
    assert!(g.claim(owner("Y"), 2., 90).is_err());
    g.finish();
    assert!(g.claim(owner("Y"), 3., 90).is_ok());
}
#[test]
fn reconciliation_requires_fresh_explicit_checks_and_no_active_work() {
    let mut g = Gate::new();
    g.cleanup_unknown = Some("unknown".into());
    let mut e = Evidence {
        checked_at: 100.,
        local_work_quiescent: true,
        remote_work_quiescent: true,
        summary: "Verified both local and device-side operation completion".into(),
        checked_by: "codex/session1".into(),
    };
    assert!(g.reconcile(&e, 200.).is_err());
    g.active = true;
    assert!(g.reconcile(&e, 101.).is_err());
    g.active = false;
    e.remote_work_quiescent = false;
    assert!(g.reconcile(&e, 101.).is_err());
    e.remote_work_quiescent = true;
    assert!(g.reconcile(&e, 101.).is_ok());
    assert!(g.cleanup_unknown.is_none());
}
