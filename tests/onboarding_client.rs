use readb::enrollment_delivery::{Context, Prepared};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
fn run(c: &mut Command) {
    let r = c.output().unwrap();
    if !r.stdout.is_empty() {
        println!("{}", String::from_utf8_lossy(&r.stdout));
    }
    assert!(
        r.status.success(),
        "host onboarding fixture failed: {}\n{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    );
}
#[test]
#[ignore = "run scripts/test-android-onboarding-client.sh for pinned host JSON sources"]
fn native_client_real_tls_protocol_order_and_recovery() {
    let json =
        std::env::var("READB_HOST_JSON_SOURCES").expect("explicit pinned source fixture required");
    let root = std::env::temp_dir().join(format!("readb-client-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut javac = Command::new("javac");
    javac.args(["--release", "11", "-d", root.to_str().unwrap()]);
    for p in [
        "android/src/dev/readb/handover/EnrollmentDelivery.java",
        "android/src/dev/readb/handover/EnrollmentJournal.java",
        "android/src/dev/readb/companion/OnboardingHttp.java",
        "android/src/dev/readb/companion/OnboardingClient.java",
        "android/tests/onboarding-host/android/content/Context.java",
        "android/tests/onboarding-host/dev/readb/companion/EnrollmentStore.java",
        "android/tests/onboarding-host/dev/readb/companion/OnboardingClientTest.java",
        "android/tests/host/EnrollmentDeliveryTest.java",
    ] {
        javac.arg(p);
    }
    for p in [
        "JSONObject",
        "JSONArray",
        "JSONTokener",
        "JSONStringer",
        "JSONException",
        "JSON",
    ] {
        javac.arg(Path::new(&json).join(format!("org/json/{p}.java")));
    }
    run(&mut javac);
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "EnrollmentDeliveryTest",
        "init",
        root.to_str().unwrap(),
    ]));
    let request = fs::read(root.join("request")).unwrap();
    let context = Context::new(&"a".repeat(64), "pixel-readb", &"b".repeat(64)).unwrap();
    let profile=serde_json::to_vec(&serde_json::json!({"schema":1,"device_id":"pixel-readb","server_peer":"10.99.0.2","server_port":19193,"device_address":"10.99.0.102","token":"1".repeat(64),"private_key":format!("{}AAA=","B".repeat(40)),"server_public_key":format!("{}AAA=","E".repeat(40)),"endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true})).unwrap();
    let prepared = Prepared::seal(&context, &request, &profile).unwrap();
    for (name, bytes) in [
        ("context", context.bytes().to_vec()),
        ("envelope", prepared.envelope().to_vec()),
        ("expected-profile", profile),
    ] {
        fs::write(root.join(name), bytes).unwrap();
    }
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "EnrollmentDeliveryTest",
        "open",
        root.to_str().unwrap(),
    ]));
    let ack = fs::read(root.join("ack")).unwrap();
    fs::write(root.join("final"), prepared.final_receipt(&ack).unwrap()).unwrap();
    run(Command::new("keytool").args([
        "-genkeypair",
        "-alias",
        "local-test",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "1",
        "-dname",
        "CN=localhost",
        "-ext",
        "SAN=dns:localhost",
        "-storetype",
        "PKCS12",
        "-keystore",
        root.join("local.p12").to_str().unwrap(),
        "-storepass",
        "test-only",
        "-keypass",
        "test-only",
        "-noprompt",
    ]));
    run(Command::new("java").args([
        "-cp",
        root.to_str().unwrap(),
        "dev.readb.companion.OnboardingClientTest",
        root.to_str().unwrap(),
    ]));
    fs::remove_dir_all(root).unwrap();
}
