use std::process::Command;
#[test]
fn setup_help_explains_install_directory_and_requires_selected_user() {
    let help = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["setup", "plan", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--install-dir"));
    let invalid = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args([
            "--local",
            "setup",
            "plan",
            "--endpoint",
            "vpn.example.org:51820",
            "--install-dir",
            "/home/tester/readb",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("--user"));
}
#[test]
fn provider_check_is_a_named_read_only_setup_command() {
    let out = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["setup", "provider", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("--reuse-interface"));
}
#[test]
fn activation_is_explicit_and_user_enable_does_not_imply_start() {
    let apply = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["setup", "apply", "--help"])
        .output()
        .unwrap();
    assert!(apply.status.success());
    assert!(String::from_utf8_lossy(&apply.stdout).contains("--recover"));
    let help = Command::new(env!("CARGO_BIN_EXE_readb"))
        .args(["service", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("enable"));
}
