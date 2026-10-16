use crate::{backend::atomic, policy::Res, registry::private_dir};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};
#[derive(Serialize)]
pub struct InstallPlan {
    pub binary: String,
    pub link: String,
    pub config: String,
    pub state: String,
    pub unit_path: String,
    pub unit: String,
    pub server: bool,
}
fn safe_path(p: &Path) -> bool {
    p.is_absolute()
        && !p
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|c| *c < 32 || b"%\"\\".contains(c))
}
pub fn plan(home: &Path, prefix: &Path, server: bool) -> Res<InstallPlan> {
    if !safe_path(home) || !safe_path(prefix) {
        return Err("absolute_safe_install_paths_required".into());
    }
    use sha2::Digest;
    let current = std::env::current_exe().map_err(|_| "current_binary_unavailable")?;
    let digest = sha2::Sha256::digest(fs::read(current).map_err(|_| "current_binary_unreadable")?);
    let digest = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let binary = prefix.join(format!(
        ".install/{}-{}/readb",
        env!("CARGO_PKG_VERSION"),
        &digest[..16]
    ));
    let config = home.join(".config/readb/server.json");
    let state = home.join(".local/share/readb");
    let unit_path = home.join(".config/systemd/user/readb.service");
    let unit = format!(
        "[Unit]\nDescription=readb remote Android coordinator\nAfter=network-online.target\n\n[Service]\nExecStart=\"{}\" --local --state-dir \"{}\" daemon --config \"{}\"\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=45\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\nProtectSystem=strict\nReadWritePaths=\"{}\"\nMemoryMax=256M\nTasksMax=512\n\n[Install]\nWantedBy=default.target\n",
        binary.display(),
        state.display(),
        config.display(),
        home.display()
    );
    Ok(InstallPlan {
        binary: binary.to_string_lossy().into(),
        link: home.join(".local/bin/readb").to_string_lossy().into(),
        config: config.to_string_lossy().into(),
        state: state.to_string_lossy().into(),
        unit_path: unit_path.to_string_lossy().into(),
        unit,
        server,
    })
}
fn find_adb(home: &Path) -> Option<PathBuf> {
    let candidates = [
        home.join("Android/platform-tools/adb"),
        home.join("Android/Sdk/platform-tools/adb"),
        PathBuf::from("/usr/bin/adb"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}
fn atomic_bytes(path: &Path, bytes: &[u8], mode: u32) -> Res<()> {
    let temp = path.with_extension(format!("new-{}", crate::policy::random()));
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)
            .map_err(|_| "install_file_create_failed")?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "install_file_write_failed")?;
        fs::rename(&temp, path).map_err(|_| "install_file_replace_failed")?;
        fs::File::open(path.parent().ok_or("invalid_install_path")?)
            .and_then(|f| f.sync_all())
            .map_err(|_| "install_directory_sync_failed")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
pub fn install(p: &InstallPlan, home: &Path, dry_run: bool) -> Res<Value> {
    if dry_run {
        return Ok(
            json!({"dry_run":true,"plan":p,"privileges":"user only; network provisioning is a separate explicit step"}),
        );
    }
    let binary = Path::new(&p.binary);
    let parent = binary.parent().ok_or("invalid_install_path")?;
    let link = Path::new(&p.link);
    let current = std::env::current_exe().map_err(|_| "current_binary_unavailable")?;
    let bytes = fs::read(&current).map_err(|_| "current_binary_unreadable")?;
    // Complete preflight before switching any live command or service definition.
    if let Ok(meta) = fs::symlink_metadata(link) {
        if !meta.file_type().is_symlink() {
            return Err("readb_path_exists_and_is_not_managed_symlink".into());
        }
        let target = fs::read_link(link).map_err(|_| "existing_link_unreadable")?;
        if !target.starts_with(parent.parent().ok_or("invalid_install_path")?)
            || target.file_name() != Some(std::ffi::OsStr::new("readb"))
        {
            return Err("readb_symlink_is_not_managed_here: existing command preserved".into());
        }
    }
    let config = Path::new(&p.config);
    let initial = if p.server {
        if let Ok(m) = fs::symlink_metadata(config) {
            use std::os::unix::fs::MetadataExt;
            if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
                return Err("existing_config_must_be_private_owned_regular_file".into());
            }
            crate::schema::ServerConfig::parse(
                &fs::read(config).map_err(|_| "existing_config_unavailable")?,
            )?;
            None
        } else {
            Some(
                json!({"schema":1,"adb":find_adb(home).ok_or("adb_missing: install Android platform-tools, then rerun; existing configuration was not changed")?,"devices":[],"listeners":[]}),
            )
        }
    } else {
        None
    };
    let unit = Path::new(&p.unit_path);
    let old_unit = if p.server && unit.exists() {
        let old = fs::read(unit).map_err(|_| "unit_unreadable")?;
        if !String::from_utf8_lossy(&old).contains("Description=readb remote Android coordinator") {
            return Err("unmanaged_readb_unit_preserved".into());
        }
        Some(old)
    } else {
        None
    };
    private_dir(parent)?;
    if let Ok(m) = fs::symlink_metadata(binary) {
        if !m.is_file() || fs::read(binary).map_err(|_| "release_unreadable")? != bytes {
            return Err("immutable_release_mismatch".into());
        }
    } else {
        atomic_bytes(binary, &bytes, 0o700)?;
    }
    let completion = install_completions(binary, home)?;
    if p.server {
        private_dir(Path::new(&p.state))?;
        private_dir(&home.join(".config/readb"))?;
        if let Some(initial) = initial {
            atomic(config, &initial)?;
        }
        if Path::new("/run/systemd/system").is_dir() {
            fs::create_dir_all(unit.parent().unwrap()).map_err(|_| "unit_directory_unavailable")?;
            if let Some(old) = &old_unit
                && old != p.unit.as_bytes()
            {
                let backups = Path::new(&p.state).join("backups");
                private_dir(&backups)?;
                atomic_bytes(
                    &backups.join(format!("unit-{}.service", crate::policy::random())),
                    old,
                    0o600,
                )?;
            }
            atomic_bytes(unit, p.unit.as_bytes(), 0o600)?;
            if let Err(e) = systemctl(&["daemon-reload"]) {
                if let Some(old) = old_unit {
                    atomic_bytes(unit, &old, 0o600)?;
                } else {
                    fs::remove_file(unit).map_err(|_| "install_unit_rollback_failed")?;
                }
                let _ = systemctl(&["daemon-reload"]);
                return Err(format!(
                    "install_not_activated: {e}; prior command and unit preserved"
                ));
            }
        }
    }
    fs::create_dir_all(link.parent().unwrap()).map_err(|_| "bin_directory_unavailable")?;
    let temp = link.with_extension(format!("new-{}", crate::policy::random()));
    symlink(binary, &temp).map_err(|_| "binary_link_failed")?;
    if fs::rename(&temp, link).is_err() {
        let _ = fs::remove_file(temp);
        return Err("binary_link_replace_failed".into());
    }
    Ok(
        json!({"installed":true,"binary":p.binary,"link":p.link,"server":p.server,"state":p.state,"completions":completion,"next":if p.server{"readb --local service start"}else{"readb context add NAME --ssh HOST --state SERVER_STATE"},"network_provisioned":false,"note":"Existing devices and VPN configuration were not changed."}),
    )
}

pub fn systemctl(args: &[&str]) -> Res<Value> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(
            |_| "service_manager_unavailable: use readb --local daemon --config FILE in foreground",
        )?;
    let text = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!("service_manager_failed: {}", err.trim()));
    }
    Ok(json!({"ok":true,"output":text.trim()}))
}
pub fn manage(action: &str) -> Res<Value> {
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("no_systemd: run foreground daemon or use your init supervisor; no PID guessing or broad kill performed".into());
    }
    match action {
        "start" => systemctl(&["enable", "--now", "readb.service"]),
        "stop" => systemctl(&["stop", "readb.service"]),
        "restart" => systemctl(&["restart", "readb.service"]),
        "status" => {
            let o = Command::new("systemctl")
                .args([
                    "--user",
                    "show",
                    "readb.service",
                    "-p",
                    "ActiveState",
                    "-p",
                    "SubState",
                    "-p",
                    "MainPID",
                    "-p",
                    "MemoryCurrent",
                    "-p",
                    "CPUUsageNSec",
                ])
                .output()
                .map_err(|_| "service_status_unavailable")?;
            Ok(json!({"ok":o.status.success(),"status":String::from_utf8_lossy(&o.stdout)}))
        }
        "uninstall" => {
            systemctl(&["disable", "--now", "readb.service"])?;
            let p = PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?)
                .join(".config/systemd/user/readb.service");
            if p.exists() {
                fs::remove_file(p).map_err(|_| "unit_remove_failed")?;
            }
            systemctl(&["daemon-reload"])?;
            Ok(json!({"service_removed":true,"private_state_preserved":true}))
        }
        _ => Err("unsupported_service_action".into()),
    }
}
fn install_completions(binary: &Path, home: &Path) -> Res<Vec<String>> {
    let mut installed = Vec::new();
    for (shell, path) in [
        (
            "bash",
            home.join(".local/share/bash-completion/completions/readb"),
        ),
        ("zsh", home.join(".local/share/zsh/site-functions/_readb")),
        ("fish", home.join(".config/fish/completions/readb.fish")),
    ] {
        let output = Command::new(binary)
            .args(["completion", shell])
            .output()
            .map_err(|_| "completion_generate_failed")?;
        if !output.status.success() {
            return Err("completion_generate_failed".into());
        }
        fs::create_dir_all(path.parent().unwrap())
            .map_err(|_| "completion_directory_unavailable")?;
        atomic_bytes(&path, &output.stdout, 0o600)?;
        installed.push(shell.into());
    }
    Ok(installed)
}
