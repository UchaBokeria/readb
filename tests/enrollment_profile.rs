use readb::{
    enrollment_profile::{Facts, Material, Request, plan},
    network::{Policy, Snapshot},
    schema::{Kind, ServerConfig},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
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
        managed: BTreeMap::new(),
        snapshot: Snapshot {
            server_key: key('E'),
            addresses: vec!["10.99.0.2/24".into()],
            peers: BTreeMap::from([
                (key('B'), vec!["10.99.0.3/32".into()]),
                (key('D'), vec!["10.99.0.100/31".into()]),
            ]),
        },
    }
}
fn config() -> ServerConfig {
    ServerConfig {
        schema: 1,
        adb: "/not-executed".into(),
        devices: vec![],
        listeners: vec![],
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
#[test]
fn readonly_plan_skips_actual_routes_catalog_and_reserved_addresses_and_ports() {
    let first = plan(
        &facts(),
        &config(),
        &request(),
        &[],
        &BTreeSet::from([5037, 5038, 5040]),
    )
    .unwrap();
    assert_eq!(first.peer, "10.99.0.102".parse::<Ipv4Addr>().unwrap());
    assert_eq!(first.adb_port, 5041);
    assert_eq!(first.report_bind.to_string(), "10.99.0.2:19193");
    assert_eq!(first.report_path, "/v2/pixel-readb");
    let mut second = request();
    second.id = "quest-readb".into();
    let next = plan(
        &facts(),
        &config(),
        &second,
        &[first.reservation()],
        &BTreeSet::from([5040]),
    )
    .unwrap();
    assert_eq!(next.peer, "10.99.0.103".parse::<Ipv4Addr>().unwrap());
    assert_eq!(next.adb_port, 5042);
    let public = serde_json::to_string(&first).unwrap();
    assert!(!public.contains("private_key") && !public.contains("token"));
}
#[test]
fn facts_drift_and_exhaustion_fail_before_generating_keys_or_files() {
    let mut f = facts();
    f.snapshot.server_key = key('C');
    assert!(plan(&f, &config(), &request(), &[], &BTreeSet::new()).is_err());
    let mut f = facts();
    f.snapshot.peers.insert(key('C'), vec!["0.0.0.0/0".into()]);
    assert!(
        plan(&f, &config(), &request(), &[], &BTreeSet::new())
            .unwrap_err()
            .contains("address_range_exhausted")
    );
    let mut f = facts();
    f.snapshot
        .peers
        .insert(key('C'), vec!["invalid/route".into()]);
    assert!(plan(&f, &config(), &request(), &[], &BTreeSet::new()).is_err());
}
#[test]
fn duplicate_ids_unsafe_endpoint_and_unknown_occupied_report_port_refuse() {
    for endpoint in [
        "vpn.example.org:0",
        "vpn.example.org:51820;sh",
        "https://vpn.example.org:51820",
        "vpn.example.org\n:51820",
    ] {
        let mut r = request();
        r.endpoint = endpoint.into();
        assert!(plan(&facts(), &config(), &r, &[], &BTreeSet::new()).is_err());
    }
    let first = plan(&facts(), &config(), &request(), &[], &BTreeSet::new()).unwrap();
    assert!(
        plan(
            &facts(),
            &config(),
            &request(),
            &[first.reservation()],
            &BTreeSet::new()
        )
        .is_err()
    );
    assert!(
        plan(
            &facts(),
            &config(),
            &request(),
            &[],
            &BTreeSet::from([19193])
        )
        .unwrap_err()
        .contains("report_port_busy")
    );
}
#[test]
fn material_uses_real_bounded_wireguard_keygen_and_matches_private_companion_and_server_import() {
    let p = plan(&facts(), &config(), &request(), &[], &BTreeSet::new()).unwrap();
    let material = Material::generate(p, "/usr/bin/wg".as_ref()).unwrap();
    let private = material.profile_bytes().unwrap();
    let profile: readb_protocol::Profile = serde_json::from_slice(&private).unwrap();
    profile.validate().unwrap();
    let import = material.server_import().unwrap();
    assert!(import.device.token == profile.token);
    assert_eq!(import.device.peer, profile.device_address);
    assert!(import.device.identity.is_empty());
    assert_eq!(import.listener.unwrap().path, profile.report_path());
    let saved = material.private_bytes().unwrap();
    let restored = Material::from_private(&saved, "/usr/bin/wg".as_ref()).unwrap();
    assert!(private == restored.profile_bytes().unwrap());
    let public = material.public_view();
    let text = serde_json::to_string(&public).unwrap();
    assert!(!text.contains(&profile.token) && !text.contains(&profile.private_key));
}
#[test]
fn missing_untrusted_keygen_and_corrupt_private_material_are_credential_free_errors() {
    let p = plan(&facts(), &config(), &request(), &[], &BTreeSet::new()).unwrap();
    assert!(Material::generate(p.clone(), "/does-not-exist/wg".as_ref()).is_err());
    assert!(
        Material::from_private(
            br#"{"schema":1,"token":"must-not-appear-in-error"}"#,
            "/usr/bin/wg".as_ref()
        )
        .err()
        .unwrap()
        .find("must-not-appear")
        .is_none()
    );
    let m = Material::generate(p, "/usr/bin/wg".as_ref()).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&m.private_bytes().unwrap()).unwrap();
    v["token"] = serde_json::json!("bad");
    assert!(
        Material::from_private(&serde_json::to_vec(&v).unwrap(), "/usr/bin/wg".as_ref()).is_err()
    );
}
#[test]
fn private_recovery_rejects_individually_valid_but_mismatched_wireguard_keys() {
    let m = Material::generate(
        plan(&facts(), &config(), &request(), &[], &BTreeSet::new()).unwrap(),
        "/usr/bin/wg".as_ref(),
    )
    .unwrap();
    let mut saved: serde_json::Value = serde_json::from_slice(&m.private_bytes().unwrap()).unwrap();
    saved["public_key"] = serde_json::json!(key('C'));
    assert!(
        Material::from_private(&serde_json::to_vec(&saved).unwrap(), "/usr/bin/wg".as_ref())
            .is_err()
    );
}
