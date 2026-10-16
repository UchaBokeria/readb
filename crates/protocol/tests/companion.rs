use readb_protocol::{Companion, Grant, Observed, ScreenLock};
fn observed() -> Observed {
    Observed {
        credential_storage_unlocked: true,
        screen_lock: ScreenLock::Unknown,
        vpn_active: true,
        notifications: Grant::Granted,
        discovery: Grant::Denied,
        secure_settings: Grant::Denied,
    }
}
#[test]
fn startup_has_no_cached_port_and_late_completion_cannot_finish_another_request() {
    let mut c = Companion::new("reporter-one".into(), 100).unwrap();
    let first = c.poll(100, 50, observed()).unwrap().unwrap();
    assert_eq!(first.port, None);
    assert_eq!(first.sequence, 1);
    assert!(c.poll(101, 50, observed()).unwrap().is_none());
    c.port_changed(102, Some(40000)).unwrap();
    assert!(c.complete(99, 103, true).is_err());
    c.complete(first.sequence, 103, true).unwrap();
    assert_eq!(c.next_due(), 5100);
    let next = c.poll(5100, 49, observed()).unwrap().unwrap();
    assert_eq!(next.port, Some(40000));
    assert_eq!(next.sequence, 2);
    assert!(c.complete(first.sequence, 5200, true).is_err());
    assert!(c.poll(99999, 49, observed()).unwrap().is_none());
    c.complete(next.sequence, 5200, false).unwrap();
    assert_eq!(c.next_due(), 10200);
}
#[test]
fn invalid_samples_do_not_consume_sequence_or_schedule() {
    assert!(Companion::new("invalid epoch".into(), 0).is_err());
    let mut c = Companion::new("reporter-one".into(), 0).unwrap();
    assert!(c.poll(0, 101, observed()).is_err());
    assert!(c.port_changed(0, Some(20)).is_err());
    assert_eq!(c.poll(0, 80, observed()).unwrap().unwrap().sequence, 1);
}
