use readb_android_core::Bridge;
use serde_json::{Value, json};
fn call(b: &mut Bridge, v: Value) -> Value {
    serde_json::from_str(&b.call(&v.to_string())).unwrap()
}
#[test]
fn handles_are_bounded_never_reused_and_late_callbacks_are_rejected() {
    let mut b = Bridge::default();
    let a = call(
        &mut b,
        json!({"op":"create","epoch":"reporter-one","now":0}),
    );
    let h = a["handle"].as_u64().unwrap();
    assert_eq!(call(&mut b, json!({"op":"close","handle":h}))["ok"], true);
    assert_eq!(
        call(&mut b, json!({"op":"network","handle":h,"now":1}))["error"],
        "unknown_reporter"
    );
    let z = call(
        &mut b,
        json!({"op":"create","epoch":"reporter-two","now":0}),
    );
    assert_ne!(z["handle"], h);
    for i in 0..7 {
        assert_eq!(
            call(
                &mut b,
                json!({"op":"create","epoch":format!("reporter-{i}"),"now":0})
            )["ok"],
            true
        );
    }
    assert_eq!(
        call(
            &mut b,
            json!({"op":"create","epoch":"reporter-full","now":0})
        )["error"],
        "reporter_limit"
    );
}
#[test]
fn dispatch_is_strict_and_reports_no_port_before_discovery() {
    let mut b = Bridge::default();
    assert_eq!(
        call(
            &mut b,
            json!({"op":"create","epoch":"reporter-one","now":0,"secret":"do not echo"})
        )["error"],
        "invalid_request"
    );
    assert!(!b.call(&"x".repeat(8193)).contains("xxxxx"));
    assert_eq!(
        call(
            &mut b,
            json!({"op":"create","epoch":"reporter-one","now":0})
        )["handle"],
        1
    );
    let o = json!({"credential_storage_unlocked":false,"screen_lock":"unknown","vpn_active":true,"notifications":"denied","discovery":"denied","secure_settings":"denied"});
    let r = call(
        &mut b,
        json!({"op":"poll","handle":1,"now":0,"battery":-1,"observed":o}),
    );
    assert_eq!(r["report"]["sequence"], 1);
    assert_eq!(r["report"]["port"], Value::Null);
    assert_eq!(
        call(
            &mut b,
            json!({"op":"complete","handle":1,"sequence":3,"now":1,"success":true})
        )["error"],
        "stale_report_completion"
    );
    assert_eq!(
        call(
            &mut b,
            json!({"op":"complete","handle":1,"sequence":1,"now":1,"success":true})
        )["next_due"],
        20001
    );
}

#[test]
fn enrollment_validation_returns_no_private_material() {
    let mut b = Bridge::default();
    let profile = json!({"schema":1,"device_id":"quest-demo","server_peer":"10.99.0.2","server_port":19192,"device_address":"10.99.0.5","token":"a".repeat(64),"private_key":"A".repeat(43)+"=","server_public_key":"B".repeat(43)+"=","endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true});
    let r = call(&mut b, json!({"op":"validate_profile","profile":profile}));
    assert_eq!(r["ok"], true);
    assert_eq!(r["report_path"], "/v2/quest-demo");
    assert!(!r.to_string().contains(&"a".repeat(64)));
    assert!(r.get("profile").is_none());
}
