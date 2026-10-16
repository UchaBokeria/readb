use readb::{backend::Config, notifier::*, policy::*};
use serde_json::json;
use std::{cell::Cell, fs};
fn setup() -> Config {
    let dir = std::env::temp_dir().join(format!("quest-notice-{}", random()));
    fs::create_dir(&dir).unwrap();
    Config {
        peer: "192.0.2.5".parse().unwrap(),
        adb_port: 5038,
        kind: readb::schema::Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb: "/not-used".into(),
        identity: "x".repeat(64),
        token: "x".repeat(64),
        recipient: "1@s.whatsapp.net".into(),
    }
}
fn report() -> Receipt {
    Receipt {
        received_at: 100.,
        port: 40000,
        battery: 4,
        connected: true,
        identity_verified: true,
        transport_cleanup_failed: false,
    }
}
#[test]
fn confirmed_send_dedup_survives_restart() {
    let c = setup();
    let n = Notifier::new(&c).unwrap();
    let sends = Cell::new(0);
    let bridge = |route: &str, _: Option<&serde_json::Value>| {
        if route == "/health" {
            Ok(json!({"status":"connected"}))
        } else {
            sends.set(sends.get() + 1);
            Ok(json!({"success":true,"messageId":"fixture"}))
        }
    };
    n.process_with(&report(), 101., || Ok("1:2@s.whatsapp.net".into()), bridge)
        .unwrap();
    let n = Notifier::new(&c).unwrap();
    n.process_with(
        &report(),
        102.,
        || panic!("dedup failed"),
        |_, _| panic!("dedup failed"),
    )
    .unwrap();
    assert_eq!(sends.get(), 1);
}
#[test]
fn changed_self_never_sends_and_retry_persists() {
    let c = setup();
    let n = Notifier::new(&c).unwrap();
    assert!(
        n.process_with(
            &report(),
            101.,
            || Ok("2@s.whatsapp.net".into()),
            |route, _| {
                assert_eq!(route, "/health");
                Ok(json!({"status":"connected"}))
            }
        )
        .is_err()
    );
    let n = Notifier::new(&c).unwrap();
    n.process_with(
        &report(),
        102.,
        || panic!("retry not delayed"),
        |_, _| panic!("retry not delayed"),
    )
    .unwrap();
}
#[test]
fn stale_or_unverified_cannot_notify() {
    let c = setup();
    let n = Notifier::new(&c).unwrap();
    n.process_with(&report(), 400., || panic!(), |_, _| panic!())
        .unwrap();
    let mut r = report();
    r.connected = false;
    n.process_with(&r, 101., || panic!(), |_, _| panic!())
        .unwrap();
}
#[test]
fn enrolled_authenticated_boot_battery_can_notify_without_adb_but_untrusted_cannot() {
    let c = setup();
    let n = Notifier::new(&c).unwrap();
    let sample = BatterySample {
        received_at: 100.,
        battery: 4,
        authenticated: true,
        enrolled: true,
    };
    let sends = Cell::new(0);
    n.process_battery_with(
        &sample,
        101.,
        || Ok("1@s.whatsapp.net".into()),
        |route, _| {
            if route == "/health" {
                Ok(json!({"status":"connected"}))
            } else {
                sends.set(sends.get() + 1);
                Ok(json!({"success":true,"messageId":"fixture"}))
            }
        },
    )
    .unwrap();
    assert_eq!(sends.get(), 1);
    for (authenticated, enrolled) in [(false, true), (true, false)] {
        let n = Notifier::new(&setup()).unwrap();
        n.process_battery_with(
            &BatterySample {
                received_at: 100.,
                battery: 4,
                authenticated,
                enrolled,
            },
            101.,
            || panic!("untrusted sample"),
            |_, _| panic!("untrusted sample"),
        )
        .unwrap();
    }
}
