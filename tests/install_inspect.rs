use std::{fs, os::unix::fs::PermissionsExt, process::Command};
#[test]
fn user_install_inspection_is_read_only_exact_and_never_prints_file_contents() {
    let home = std::env::temp_dir().join(format!("readb-inspect-user-{}", readb::policy::random()));
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let call = |inspect: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_readb"));
        c.args(["install", "--client", "--prefix"])
            .arg(home.join("prefix"))
            .env("HOME", &home);
        if inspect {
            c.arg("--inspect");
        }
        c.output().unwrap()
    };
    let out = call(true);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let absent: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(absent["state"], "absent");
    assert!(!home.join(".local").exists());
    assert!(call(false).status.success());
    let out = call(true);
    assert!(out.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["state"],
        "ready"
    );
    let binary = fs::read_link(home.join(".local/bin/readb")).unwrap();
    fs::write(&binary, b"private wrong binary").unwrap();
    let out = call(true);
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("private wrong binary"));
    assert_eq!(fs::read(binary).unwrap(), b"private wrong binary");
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn pending_server_inspection_binds_recovery_without_replaying_or_exposing_journal() {
    if !std::path::Path::new("/run/systemd/system").is_dir() {
        return;
    }
    let home =
        std::env::temp_dir().join(format!("readb-inspect-pending-{}", readb::policy::random()));
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = home.join("Android/platform-tools/adb");
    fs::create_dir_all(adb.parent().unwrap()).unwrap();
    fs::write(adb, b"not executed").unwrap();
    let bin = home.join("bin");
    fs::create_dir(&bin).unwrap();
    let ctl = bin.join("systemctl");
    fs::write(&ctl, b"#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&ctl, fs::Permissions::from_mode(0o700)).unwrap();
    let call = |inspect: bool, prefix: &std::path::Path| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_readb"));
        c.args(["install", "--server", "--prefix"])
            .arg(prefix)
            .env("HOME", &home)
            .env("PATH", &bin);
        if inspect {
            c.arg("--inspect");
        }
        c.output().unwrap()
    };
    assert!(!call(false, &home.join("prefix")).status.success());
    let path = home.join(".local/share/readb-installer/pending.json");
    let before = fs::read(&path).unwrap();
    let result = call(true, &home.join("prefix"));
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["state"], "pending");
    assert_eq!(value["pending_bound"], true);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(!call(true, &home.join("wrong-prefix")).status.success());
    assert_eq!(fs::read(path).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn exact_receipt_backed_previous_release_is_upgradeable_but_edited_release_is_not() {
    use readb::user_install::{Desired, Transaction};
    use sha2::{Digest, Sha256};
    let home =
        std::env::temp_dir().join(format!("readb-inspect-upgrade-{}", readb::policy::random()));
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let prefix = home.join("prefix");
    let output = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["install", "--client", "--dry-run", "--prefix"])
        .arg(&prefix)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(output.status.success());
    let mut p: serde_json::Value =
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["plan"].clone();
    let bytes = b"old managed release";
    let hex = |bytes: &[u8]| {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let digest = hex(bytes);
    let old = prefix.join(format!(".install/0.1.0-{}/readb", &digest[..16]));
    p["unit"] = serde_json::json!(
        p["unit"]
            .as_str()
            .unwrap()
            .replace(p["binary"].as_str().unwrap(), old.to_str().unwrap())
    );
    p["binary"] = serde_json::json!(old);
    // Value map ordering differs from InstallPlan. Build its original field order.
    let binding = {
        let ordered = format!(
            "[{},{{\"binary\":{},\"link\":{},\"config\":{},\"state\":{},\"unit_path\":{},\"unit\":{},\"server\":{}}}]",
            serde_json::to_string(&home).unwrap(),
            p["binary"],
            p["link"],
            p["config"],
            p["state"],
            p["unit_path"],
            p["unit"],
            p["server"]
        );
        hex(ordered.as_bytes())
    };
    let artifacts = [
        Desired::file(old.clone(), bytes.to_vec(), 0o700),
        Desired::link(home.join(".local/bin/readb"), old.clone()),
    ];
    let mut tx = Transaction::open(
        &home.join(".local/share/readb-installer"),
        &binding,
        &artifacts,
        false,
    )
    .unwrap();
    for (n, a) in artifacts.iter().enumerate() {
        tx.publish(n, a).unwrap();
    }
    tx.finish().unwrap();
    let call = || {
        Command::new(env!("CARGO_BIN_EXE_readb"))
            .args(["install", "--client", "--inspect", "--prefix"])
            .arg(&prefix)
            .env("HOME", &home)
            .output()
            .unwrap()
    };
    let out = call();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["state"],
        "upgrade"
    );
    fs::write(old, b"unknown edit").unwrap();
    assert!(!call().status.success());
    fs::remove_dir_all(home).unwrap();
}
