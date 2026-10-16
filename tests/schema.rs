use readb::schema::*;
#[test]
fn schema_rejects_bad_ids_duplicate_peers_and_unsupported_versions() {
    let base = r#"{"schema":1,"adb":"/usr/bin/adb","devices":[{"id":"phone","name":"Phone","kind":"phone","peer":"192.0.2.3","adb_port":5037,"token":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","identity":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}"#;
    let c = ServerConfig::parse(base.as_bytes()).unwrap();
    assert!(c.public_view().to_string().find("xxxxxxxx").is_none());
    assert!(c.public_view().to_string().find(&"a".repeat(64)).is_none());
    assert!(c.devices[0].keepalive.enabled);
    assert!(c.devices[0].keepalive.prevent_lock);
    assert!(
        ServerConfig::parse(
            base.replace("\"phone\",\"name\"", "\"../phone\",\"name\"")
                .as_bytes()
        )
        .is_err()
    );
    assert!(ServerConfig::parse(base.replace("\"schema\":1", "\"schema\":99").as_bytes()).is_err());
    let mut v: serde_json::Value = serde_json::from_str(base).unwrap();
    let d = v["devices"][0].clone();
    v["devices"].as_array_mut().unwrap().push(d);
    assert!(ServerConfig::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn device_identity_and_ports_are_not_guessed() {
    assert!(!valid_id(""));
    assert!(!valid_id("--all"));
    assert!(!valid_id("host/name"));
    assert!(valid_id("quest-2"));
    let bad = r#"{"schema":1,"adb":"adb","devices":[]}"#;
    assert!(ServerConfig::parse(bad.as_bytes()).is_err());
}
#[test]
fn fresh_server_can_start_empty_before_first_enrollment() {
    assert!(ServerConfig::parse(br#"{"schema":1,"adb":"/usr/bin/adb","devices":[]}"#).is_ok());
}
