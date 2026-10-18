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
    // Another test thread can briefly fork while this fixture is copied,
    // inheriting its write descriptor until exec. Retry only Linux ETXTBSY;
    // never retry the test itself or hide an execution/test failure.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let result = loop {
        let output = Command::new(&path)
            .args([
                "--exact",
                "installer_reads_executing_inode_after_its_path_is_removed",
                "--nocapture",
            ])
            .env("READB_SOURCE_FIXTURE", "1")
            .output();
        match output {
            Err(e)
                if e.raw_os_error() == Some(libc::ETXTBSY) && std::time::Instant::now() < until =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            output => break output.unwrap(),
        }
    };
    let _ = fs::remove_file(path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
fn a_description_is_not_permission_to_replace_an_unrelated_or_symlinked_unit() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    for dangling in [false, true] {
        let root =
            std::env::temp_dir().join(format!("readb-unit-admission-{}", readb::policy::random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let adb = root.join("Android/platform-tools/adb");
        fs::create_dir_all(adb.parent().unwrap()).unwrap();
        fs::write(&adb, b"not executed by install").unwrap();
        let unit = root.join(".config/systemd/user/readb.service");
        fs::create_dir_all(unit.parent().unwrap()).unwrap();
        let unknown=b"[Unit]\nDescription=readb remote Android coordinator\n[Service]\nExecStart=/bin/false\n";
        if dangling {
            symlink(root.join("missing-unit"), &unit).unwrap();
        } else {
            fs::write(&unit, unknown).unwrap();
            fs::set_permissions(&unit, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let result = Command::new(env!("CARGO_BIN_EXE_readb"))
            .args(["install", "--server", "--prefix"])
            .arg(root.join("prefix"))
            .env("HOME", &root)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("unmanaged_readb_unit_preserved"));
        assert!(
            !root.join("prefix/.install").exists(),
            "reject unknown unit before any package writes"
        );
        if dangling {
            assert!(fs::symlink_metadata(unit).unwrap().file_type().is_symlink());
        } else {
            assert_eq!(fs::read(unit).unwrap(), unknown);
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn unsafe_existing_server_config_is_rejected_before_install_writes() {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    for variant in ["hardlink", "oversize", "dangling"] {
        let root = std::env::temp_dir().join(format!(
            "readb-config-admission-{}",
            readb::policy::random()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let config = root.join(".config/readb/server.json");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let bytes = br#"{"schema":1,"adb":"/usr/bin/adb","devices":[],"listeners":[]}"#;
        if variant == "dangling" {
            symlink(root.join("missing-config"), &config).unwrap();
        } else {
            fs::write(&config, bytes).unwrap();
            fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
            if variant == "hardlink" {
                fs::hard_link(&config, root.join("owner-copy")).unwrap();
            } else {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&config)
                    .unwrap()
                    .set_len(1024 * 1024 + 1)
                    .unwrap();
            }
        }
        let out = Command::new(env!("CARGO_BIN_EXE_readb"))
            .args(["install", "--server", "--prefix"])
            .arg(root.join("prefix"))
            .env("HOME", &root)
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("existing_config_must_be_private_owned_regular_file"),
            "{}: {}",
            variant,
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!root.join("prefix/.install").exists());
        if variant == "hardlink" {
            assert_eq!(fs::read(&config).unwrap(), bytes);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn pending_user_install_never_restarts_implicitly_or_discards_unknown_evidence() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    let root =
        std::env::temp_dir().join(format!("readb-install-pending-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let journal = root.join(".local/share/readb-installer");
    fs::create_dir_all(&journal).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(journal.join("pending.json"), b"unknown pending evidence").unwrap();
    fs::set_permissions(
        journal.join("pending.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    for recovery in [false, true] {
        let mut call = Command::new(env!("CARGO_BIN_EXE_readb"));
        call.args(["install", "--client", "--prefix"])
            .arg(root.join("prefix"))
            .env("HOME", &root);
        if recovery {
            call.arg("--recover");
        }
        let r = call.output().unwrap();
        assert!(!r.status.success());
        let expected = if recovery {
            "install_invalid_journal_preserved"
        } else {
            "install_cleanup_unknown"
        };
        assert!(
            String::from_utf8_lossy(&r.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert!(!root.join("prefix/.install").exists());
        assert_eq!(
            fs::read(journal.join("pending.json")).unwrap(),
            b"unknown pending evidence"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn interrupted_server_reload_recovers_exact_files_without_starting_a_service() {
    use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
    if !Path::new("/run/systemd/system").is_dir() {
        return;
    }
    let root =
        std::env::temp_dir().join(format!("readb-server-recovery-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let adb = root.join("Android/platform-tools/adb");
    fs::create_dir_all(adb.parent().unwrap()).unwrap();
    fs::write(adb, b"not executed").unwrap();
    let bin = root.join("fake-bin");
    fs::create_dir(&bin).unwrap();
    let manager = bin.join("systemctl");
    fs::write(&manager,b"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$READB_TEST_MANAGER_LOG\"\n[ -f \"$READB_TEST_MANAGER_OK\" ]\n").unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o700)).unwrap();
    let call = |recover: bool| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_readb"));
        c.args(["install", "--server", "--prefix"])
            .arg(root.join("prefix"));
        if recover {
            c.arg("--recover");
        }
        c.env("HOME", &root)
            .env("PATH", &bin)
            .env("READB_TEST_MANAGER_LOG", root.join("manager.log"))
            .env("READB_TEST_MANAGER_OK", root.join("manager-ok"));
        c.output().unwrap()
    };
    let failed = call(false);
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("install_reload_unconfirmed"),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    let journal = root.join(".local/share/readb-installer");
    assert!(journal.join("pending.json").exists());
    assert!(!root.join(".local/bin/readb").exists());
    let config = fs::read(root.join(".config/readb/server.json")).unwrap();
    let unit = fs::read(root.join(".config/systemd/user/readb.service")).unwrap();
    fs::write(root.join("manager-ok"), b"ok").unwrap();
    let ordinary = call(false);
    assert!(!ordinary.status.success());
    assert!(String::from_utf8_lossy(&ordinary.stderr).contains("install_cleanup_unknown"));
    let recovered = call(true);
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    assert!(!journal.join("pending.json").exists());
    assert!(journal.join("receipt.json").is_file());
    assert!(root.join(".local/bin/readb").is_symlink());
    assert_eq!(
        config,
        fs::read(root.join(".config/readb/server.json")).unwrap()
    );
    assert_eq!(
        unit,
        fs::read(root.join(".config/systemd/user/readb.service")).unwrap()
    );
    assert_eq!(
        fs::read_to_string(root.join("manager.log")).unwrap(),
        "--user daemon-reload\n--user daemon-reload\n"
    );
    fs::remove_dir_all(root).unwrap();
}
