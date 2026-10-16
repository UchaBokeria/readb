use readb_protocol::*;
fn packet() -> Vec<u8> {
    br#"{"schema":2,"epoch":"fixture-boot","sequence":1,"port":null,"battery":73,"observed":{"credential_storage_unlocked":false,"screen_lock":"unknown","vpn_active":true,"notifications":"granted","discovery":"granted","secure_settings":"denied"}}"#.to_vec()
}
#[test]
fn boot_without_port_is_valid_but_not_a_connection_claim() {
    let r = Report::parse(&packet()).unwrap();
    assert_eq!(r.port, None);
    assert_eq!(r.observed.screen_lock, ScreenLock::Unknown);
    assert!(!r.observed.credential_storage_unlocked);
    assert!(Report::parse(&serde_json::to_vec(&r).unwrap()).is_ok());
}
#[test]
fn strict_version_shapes_and_bounds() {
    for (a, b) in [
        ("\"schema\":2", "\"schema\":3"),
        ("\"port\":null", "\"port\":22"),
        ("\"port\":null", "\"port\":true"),
        ("\"sequence\":1", "\"sequence\":0"),
        ("\"battery\":73", "\"battery\":101"),
        ("\"epoch\":\"fixture-boot\"", "\"epoch\":\"../bad\""),
        ("\"screen_lock\":\"unknown\"", "\"screen_lock\":\"maybe\""),
        ("\"schema\":2", "\"schema\":2,\"extra\":true"),
    ] {
        let s = String::from_utf8(packet()).unwrap().replace(a, b);
        assert!(Report::parse(s.as_bytes()).is_err(), "{a} => {b}");
    }
    assert!(Report::parse(&vec![b' '; 4097]).is_err());
}
#[test]
fn report_cursor_rejects_replay_and_recent_retired_epochs() {
    let mut c = Cursor::default();
    let mut r = Report::parse(&packet()).unwrap();
    assert_eq!(c.accept(&r).unwrap(), EpochChange::First);
    assert!(c.accept(&r).is_err());
    r.sequence = 2;
    assert_eq!(c.accept(&r).unwrap(), EpochChange::Same);
    r.epoch = "next-boot".into();
    r.sequence = 1;
    assert_eq!(c.accept(&r).unwrap(), EpochChange::Changed);
    r.epoch = "fixture-boot".into();
    r.sequence = 3;
    assert!(c.accept(&r).is_err());
    let mut restored: Cursor = serde_json::from_slice(&serde_json::to_vec(&c).unwrap()).unwrap();
    r.epoch = "next-boot".into();
    r.sequence = 1;
    assert!(restored.accept(&r).is_err());
}
