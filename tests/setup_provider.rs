use readb::{
    network::{Policy, Snapshot},
    setup_provider::{Saved, verify},
};
use std::collections::BTreeMap;
fn key(c: char) -> String {
    format!("{}AAA=", c.to_string().repeat(40))
}
fn policy() -> Policy {
    Policy {
        schema: 1,
        uid: 1000,
        interface: "readb0".into(),
        server_key: key('E'),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.100".parse().unwrap(),
        last: "10.88.0.110".parse().unwrap(),
    }
}
fn config() -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.88.0.1/24\nListenPort = 51820\nSaveConfig = false\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.88.0.5/32\nPersistentKeepalive = 25\n",
        key('C'),
        key('D')
    )
}
fn live() -> Snapshot {
    Snapshot {
        server_key: key('E'),
        addresses: vec!["10.88.0.1/24".into()],
        peers: BTreeMap::from([(key('D'), vec!["10.88.0.5/32".into()])]),
    }
}
#[test]
fn persistence_requires_exact_identity_routes_and_durable_enablement() {
    let saved = Saved::parse(config().as_bytes()).unwrap();
    let receipt = verify(&saved, &policy(), &live(), &key('E'), 51820, true).unwrap();
    let text = serde_json::to_string(&receipt).unwrap();
    assert!(!text.contains(&key('C')));
    assert!(text.contains("wg_quick"));
    assert!(verify(&saved, &policy(), &live(), &key('F'), 51820, true).is_err());
    assert!(verify(&saved, &policy(), &live(), &key('E'), 51821, true).is_err());
    assert!(verify(&saved, &policy(), &live(), &key('E'), 51820, false).is_err());
    let mut changed = live();
    changed
        .peers
        .get_mut(&key('D'))
        .unwrap()
        .push("10.88.0.6/32".into());
    assert!(verify(&saved, &policy(), &changed, &key('E'), 51820, true).is_err());
}
#[test]
fn unknown_hooks_overrides_duplicates_and_unsafe_routes_fail_closed() {
    for extra in [
        "PostUp = echo bad",
        "PreDown = echo bad",
        "SaveConfig = true",
        "Address = 10.88.0.2/24",
        "Table = 123",
        "Unknown = ignored",
    ] {
        let conf = config().replace("[Peer]", &format!("{extra}\n[Peer]"));
        assert!(Saved::parse(conf.as_bytes()).is_err(), "{extra}");
    }
    for bad in [
        config().replace("10.88.0.5/32", "0.0.0.0/0"),
        config().replace("10.88.0.1/24", "10.88.0.1/24, fd00::1/64"),
        config() + "[Other]\nFoo=bar\n",
        config() + &format!("[Peer]\nPublicKey={}\nAllowedIPs=10.88.0.8/32\n", key('D')),
    ] {
        assert!(Saved::parse(bad.as_bytes()).is_err());
    }
}

#[test]
fn boot_unit_admission_refuses_transient_enablement_and_hidden_commands() {
    use readb::setup_provider::verify_unit;
    let facts = "LoadState=loaded\nUnitFileState=enabled\nDropInPaths=\nExecStart={ path=/usr/bin/wg-quick ; argv[]=/usr/bin/wg-quick up readb0 ; ignore_errors=no ; }\nExecStartPre=\nExecStartPost=\nEnvironmentFiles=\nUser=\nRootDirectory=\nRootImage=\nFragmentPath=/usr/lib/systemd/system/wg-quick@.service\n";
    verify_unit(facts, "readb0", "/usr/bin/wg-quick").unwrap();
    for bad in [
        facts.replace("State=enabled", "State=enabled-runtime"),
        facts.replace("DropInPaths=", "DropInPaths=/etc/override.conf"),
        facts.replace("ExecStartPre=", "ExecStartPre=/bin/sh"),
        facts.replace(" up readb0", " up other"),
    ] {
        assert!(verify_unit(&bad, "readb0", "/usr/bin/wg-quick").is_err());
    }
}
#[test]
fn missing_systemctl_arrays_need_typed_empty_bus_evidence() {
    use readb::setup_provider::empty_property;
    assert!(empty_property(&serde_json::json!({"type":"a(sb)","data":[]}), "a(sb)").is_ok());
    for bad in [
        serde_json::json!({"type":"s","data":[]}),
        serde_json::json!({"type":"a(sb)","data":[["/bad",false]]}),
        serde_json::json!({"type":"a(sb)"}),
    ] {
        assert!(empty_property(&bad, "a(sb)").is_err());
    }
}
