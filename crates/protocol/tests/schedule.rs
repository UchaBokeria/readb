use readb_protocol::*;
#[test]
fn startup_periodic_events_throttle_and_recovery() {
    let mut s = Schedule::new(100);
    assert!(s.due(100));
    assert_eq!(s.port(), None);
    s.attempt(100);
    s.complete(110, true);
    assert_eq!(s.next_due(), 20110);
    s.port_changed(111, Some(40000)).unwrap();
    assert_eq!(s.next_due(), 5100);
    assert!(!s.due(5099));
    assert!(s.due(5100));
    s.attempt(5100);
    s.complete(5200, false);
    assert_eq!(s.next_due(), 10200);
    s.attempt(10200);
    s.complete(10300, false);
    assert_eq!(s.next_due(), 20300);
    s.network_changed(11000);
    assert_eq!(s.next_due(), 15200);
    s.attempt(15200);
    s.complete(15300, true);
    assert_eq!(s.next_due(), 35300);
    s.port_changed(16000, None).unwrap();
    assert_eq!(s.port(), None);
    assert_eq!(s.next_due(), 20200);
    assert!(s.port_changed(17000, Some(22)).is_err());
}
#[test]
fn no_spinning_on_clock_rewind_or_large_failure_count() {
    let mut s = Schedule::new(1000);
    s.attempt(1000);
    for i in 0..100 {
        let now = 2000 + i * 60000;
        s.complete(now, false);
        assert!(s.next_due() > now && s.next_due() <= now + 60000);
        s.attempt(s.next_due());
    }
    assert!(!s.due(0));
    let mut edge = Schedule::new(u64::MAX - 1);
    edge.attempt(u64::MAX - 1);
    edge.complete(u64::MAX - 1, false);
    assert_eq!(edge.next_due(), u64::MAX);
}
#[test]
fn port_event_during_request_is_not_overwritten_by_late_success() {
    let mut s = Schedule::new(0);
    assert!(s.attempt(0));
    assert!(!s.attempt(0));
    s.port_changed(100, Some(40000)).unwrap();
    s.complete(8000, true);
    assert!(s.due(8000));
    assert!(s.attempt(8000));
    s.complete(8100, true);
    assert_eq!(s.next_due(), 28100);
}
