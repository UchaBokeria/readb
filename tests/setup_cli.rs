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
