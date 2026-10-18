use readb::enrollment_delivery::{Context, Prepared};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn run(command: &mut Command) {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "host codec fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn java_recipient_rust_envelope_authenticated_receipts_and_exact_recovery() {
    let root = std::env::temp_dir().join(format!("readb-delivery-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    run(Command::new("javac").args([
        "--release",
        "11",
        "-d",
        root.to_str().unwrap(),
        "android/src/dev/readb/handover/EnrollmentDelivery.java",
        "android/tests/host/EnrollmentDeliveryTest.java",
    ]));
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "EnrollmentDeliveryTest",
        "init",
        root.to_str().unwrap(),
    ]));
    let request = fs::read(root.join("request")).unwrap();
    let context = Context::new(&"a".repeat(64), "pixel-readb", &"b".repeat(64)).unwrap();
    let profile = serde_json::to_vec(&serde_json::json!({"schema":1,"device_id":"pixel-readb","server_peer":"10.99.0.2","server_port":19193,"device_address":"10.99.0.102","token":"1".repeat(64),"private_key":format!("{}AAA=","B".repeat(40)),"server_public_key":format!("{}AAA=","E".repeat(40)),"endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true})).unwrap();
    let prepared = Prepared::seal(&context, &request, &profile).unwrap();
    assert!(
        Prepared::seal(
            &context,
            &fs::read(root.join("weak-request")).unwrap(),
            &profile
        )
        .is_err()
    );
    let saved = prepared.private_bytes().unwrap();
    let restored = Prepared::restore(&saved).unwrap();
    assert_eq!(restored.envelope(), prepared.envelope());
    assert!(restored.private_bytes().unwrap() == saved);
    assert!(Prepared::restore(&[saved.as_slice(), b"trailing"].concat()).is_err());
    fs::write(root.join("context"), context.bytes()).unwrap();
    fs::write(root.join("envelope"), prepared.envelope()).unwrap();
    // Synthetic fixture data only. No real profile or device key is used.
    fs::write(root.join("expected-profile"), &profile).unwrap();
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "EnrollmentDeliveryTest",
        "open",
        root.to_str().unwrap(),
    ]));
    let ack = fs::read(root.join("ack")).unwrap();
    restored.verify_ack(&ack).unwrap();
    let final_receipt = restored.final_receipt(&ack).unwrap();
    assert!(restored.verify_ack(&final_receipt).is_err());
    let mut bad = ack.clone();
    bad[131] ^= 1;
    assert!(restored.verify_ack(&bad).is_err());
    assert!(restored.final_receipt(&bad).is_err());
    assert!(restored.verify_ack(&ack[..131]).is_err());
    assert!(
        restored
            .verify_ack(&[ack.as_slice(), b"x"].concat())
            .is_err()
    );
    let another_context = Context::new(&"a".repeat(64), "pixel-readb", &"c".repeat(64)).unwrap();
    let another = Prepared::seal(&another_context, &request, &profile).unwrap();
    assert!(another.verify_ack(&ack).is_err());
    let resealed = Prepared::seal(&context, &request, &profile).unwrap();
    assert_ne!(
        resealed.envelope(),
        prepared.envelope(),
        "retry must restore, never silently reseal"
    );
    assert!(resealed.verify_ack(&ack).is_err());
    fs::write(root.join("final"), &final_receipt).unwrap();
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "EnrollmentDeliveryTest",
        "final",
        root.to_str().unwrap(),
    ]));
    let other = Context::new(&"a".repeat(64), "other-device", &"b".repeat(64)).unwrap();
    let other_delivery = Prepared::seal(&other, &request, &profile).err();
    assert!(
        other_delivery.is_some(),
        "profile device must match bound context"
    );
    assert!(Prepared::seal(&context, &[request.as_slice(), b"x"].concat(), &profile).is_err());
    let mut weak = request.clone();
    weak[0] ^= 1;
    assert!(Prepared::seal(&context, &weak, &profile).is_err());
    let mut changed = saved.clone();
    changed[saved.len() - 1] ^= 1;
    assert!(Prepared::restore(&changed).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn context_is_canonical_bounded_and_errors_do_not_echo_private_input() {
    for server in [
        "secret-must-not-appear".to_string(),
        "A".repeat(64),
        "a".repeat(63),
    ] {
        let error = Context::new(&server, "pixel", &"b".repeat(64))
            .err()
            .unwrap();
        assert!(!error.contains(&server));
    }
    assert!(Context::new(&"a".repeat(64), "../pixel", &"b".repeat(64)).is_err());
    assert!(
        Prepared::restore(b"private-must-not-appear")
            .err()
            .unwrap()
            .contains("delivery")
    );
}
