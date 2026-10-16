use readb_protocol::Profile;
use serde_json::{Value, json};
fn fixture() -> Value {
    json!({"schema":1,"device_id":"quest-demo","server_peer":"10.99.0.2","server_port":19192,"device_address":"10.99.0.5","token":"a".repeat(64),"private_key":"A".repeat(43)+"=","server_public_key":"B".repeat(43)+"=","endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true})
}
#[test]
fn profile_is_bounded_strict_and_only_routes_to_its_server() {
    let profile: Profile = serde_json::from_value(fixture()).unwrap();
    profile.validate().unwrap();
    assert_eq!(profile.report_path(), "/v2/quest-demo");
    for (field, value) in [
        ("server_peer", json!("127.0.0.1")),
        ("server_peer", json!("8.8.8.8")),
        ("device_address", json!("10.99.0.2")),
        ("device_id", json!("../evil")),
        ("device_id", json!("-quest")),
        ("endpoint", json!("host\nPrivateKey=secret:22")),
        ("token", json!("short")),
        ("server_port", json!(80)),
        ("schema", json!(2)),
    ] {
        let mut v = fixture();
        v[field] = value;
        let p: Profile = serde_json::from_value(v).unwrap();
        assert!(p.validate().is_err(), "{field}");
    }
    let mut v = fixture();
    v["allowed_ips"] = json!(["0.0.0.0/0"]);
    assert!(serde_json::from_value::<Profile>(v).is_err());
}
