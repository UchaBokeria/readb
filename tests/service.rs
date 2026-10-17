use readb::service::*;
use std::path::Path;
#[test]
fn install_plan_is_user_scoped_and_owns_only_readb() {
    let p = plan(
        Path::new("/home/example"),
        Path::new("/home/example/opt/cloud/remote-adb"),
        true,
    )
    .unwrap();
    assert!(!p.unit.contains("readb.service"));
    assert!(p.unit.contains("--local"));
    assert!(p.unit.contains("KillMode=control-group"));
    assert!(!p.unit.contains("pkill"));
    assert!(!p.unit.contains("5037"));
    assert_eq!(p.state, "/home/example/.local/share/readb");
    assert!(p.binary.contains("remote-adb/.install/"));
    assert!(plan(Path::new("/home/example"), Path::new("relative"), true).is_err());
}

#[test]
fn client_install_is_repeatable_and_never_overwrites_an_unmanaged_command() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let root =
        std::env::temp_dir().join(format!("readb-install-{}", &readb::policy::random()[..12]));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let call = |home: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_readb"))
            .args(["install", "--client", "--prefix"])
            .arg(home.join("prefix"))
            .env("HOME", home)
            .output()
            .unwrap()
    };
    for _ in 0..2 {
        let o = call(&root);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let target = fs::read_link(root.join(".local/bin/readb")).unwrap();
    assert!(target.to_string_lossy().contains("0.2.0-"));
    assert!(root.join(".config/fish/completions/readb.fish").exists());
    assert!(!root.join(".config/readb/server.json").exists());
    assert!(!root.join(".config/systemd/user/readb.service").exists());
    fs::remove_file(root.join(".local/bin/readb")).unwrap();
    fs::write(root.join(".local/bin/readb"), b"owner command").unwrap();
    assert!(!call(&root).status.success());
    assert_eq!(
        fs::read(root.join(".local/bin/readb")).unwrap(),
        b"owner command"
    );
}

#[test]
fn installer_reads_executing_inode_after_its_path_is_removed() {
    use std::{fs, process::Command};
    if std::env::var_os("READB_SOURCE_FIXTURE").is_some() {
        let exe = std::env::current_exe().unwrap();
        assert!(exe.starts_with(std::env::temp_dir()));
        assert!(
            exe.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("readb-source-fixture-")
        );
        fs::remove_file(exe).unwrap();
        let p = plan(
            Path::new("/home/fixture"),
            Path::new("/home/fixture/readb"),
            false,
        );
        assert!(
            p.is_ok(),
            "executing inode must remain readable: {}",
            p.err().unwrap_or_default()
        );
        return;
    }
    let path =
        std::env::temp_dir().join(format!("readb-source-fixture-{}", readb::policy::random()));
    fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    let result = Command::new(&path)
        .args([
            "--exact",
            "installer_reads_executing_inode_after_its_path_is_removed",
            "--nocapture",
        ])
        .env("READB_SOURCE_FIXTURE", "1")
        .output()
        .unwrap();
    let _ = fs::remove_file(path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}
