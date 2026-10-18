use crate::{
    policy::Res,
    registry::private_dir,
    user_install::{Desired, Transaction},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::MetadataExt,
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
// The filename can be replaced by a concurrent build/upgrade. Linux keeps the
// running inode available; hash and install those same executing bytes.
fn executing_bytes() -> Res<Vec<u8>> {
    fs::read("/proc/self/exe").map_err(|_| "current_binary_unreadable".into())
}
fn safe_path(p: &Path) -> bool {
    p.is_absolute()
        && !p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
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
    let digest = sha2::Sha256::digest(executing_bytes()?);
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
fn verified_release(path: &Path) -> Res<bool> {
    use sha2::Digest;
    let m = fs::symlink_metadata(path).map_err(|_| "previous_release_metadata_unavailable")?;
    if !m.is_file()
        || m.len() > 64 * 1024 * 1024
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o700
    {
        return Ok(false);
    }
    let Some(name) = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
    else {
        return Ok(false);
    };
    let Some((_, short)) = name.rsplit_once('-') else {
        return Ok(false);
    };
    if short.len() != 16 || !short.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let hash = sha2::Sha256::digest(fs::read(path).map_err(|_| "previous_release_unreadable")?)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(hash.starts_with(short))
}
fn find_adb(home: &Path) -> Option<PathBuf> {
    let candidates = [
        home.join("Android/platform-tools/adb"),
        home.join("Android/Sdk/platform-tools/adb"),
        PathBuf::from("/usr/bin/adb"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}
pub fn install(p: &InstallPlan, home: &Path, dry_run: bool) -> Res<Value> {
    install_recover(p, home, dry_run, false)
}
pub fn install_recover(p: &InstallPlan, home: &Path, dry_run: bool, recover: bool) -> Res<Value> {
    if dry_run {
        return Ok(
            json!({"dry_run":true,"plan":p,"privileges":"user only; network provisioning is a separate explicit step"}),
        );
    }
    if unsafe { libc::geteuid() } == 0 {
        return Err(
            "user_installer_requires_nonroot_identity: use setup as root to select a user".into(),
        );
    }
    let binary = Path::new(&p.binary);
    let parent = binary.parent().ok_or("invalid_install_path")?;
    let link = Path::new(&p.link);
    let bytes = executing_bytes()?;
    // Complete preflight before switching any live command or service definition.
    let previous_target = match fs::symlink_metadata(link) {
        Ok(meta) => {
            if !meta.file_type().is_symlink() || meta.uid() != unsafe { libc::geteuid() } {
                return Err("readb_path_exists_and_is_not_managed_symlink".into());
            }
            let target = fs::read_link(link).map_err(|_| "existing_link_unreadable")?;
            let namespace = parent.parent().ok_or("invalid_install_path")?;
            if !safe_path(&target)
                || target
                    .strip_prefix(namespace)
                    .ok()
                    .is_none_or(|p| p.components().count() != 2)
                || target.file_name() != Some(std::ffi::OsStr::new("readb"))
            {
                return Err("readb_symlink_is_not_managed_here: existing command preserved".into());
            }
            Some(target)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("existing_link_metadata_unavailable".into()),
    };
    let config = Path::new(&p.config);
    let initial = if p.server {
        match fs::symlink_metadata(config) {
            Ok(m) => {
                if !m.is_file()
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.mode() & 0o077 != 0
                    || m.nlink() != 1
                    || m.len() > 1024 * 1024
                {
                    return Err("existing_config_must_be_private_owned_regular_file".into());
                }
                crate::schema::ServerConfig::parse(
                    &fs::read(config).map_err(|_| "existing_config_unavailable")?,
                )?;
                None
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(
                json!({"schema":1,"adb":find_adb(home).ok_or("adb_missing: install Android platform-tools, then rerun; existing configuration was not changed")?,"devices":[],"listeners":[]}),
            ),
            Err(_) => return Err("existing_config_metadata_unavailable".into()),
        }
    } else {
        None
    };
    let unit = Path::new(&p.unit_path);
    let _old_unit = if p.server {
        match fs::symlink_metadata(unit) {
            Ok(meta) => {
                if !meta.is_file()
                    || meta.len() > 16384
                    || meta.uid() != unsafe { libc::geteuid() }
                    || meta.mode() & 0o077 != 0
                    || meta.nlink() != 1
                {
                    return Err("unmanaged_readb_unit_preserved".into());
                }
                let old = fs::read(unit).map_err(|_| "unit_unreadable")?;
                if old != p.unit.as_bytes() {
                    let Some(target) = &previous_target else {
                        return Err("unmanaged_readb_unit_preserved".into());
                    };
                    let previous_unit = p.unit.replace(&p.binary, &target.to_string_lossy());
                    if old != previous_unit.as_bytes() || !verified_release(target)? {
                        return Err("unmanaged_readb_unit_preserved".into());
                    }
                }
                Some(old)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("unit_metadata_unavailable".into()),
        }
    } else {
        None
    };
    // Render every desired artifact before any package path changes. Hashes in
    // the private journal bind exact bytes, never copy plaintext secrets into it.
    let mut artifacts = vec![Desired::file(binary.into(), bytes, 0o700).immutable()];
    let completion = completion_artifacts(home)?;
    artifacts.extend(completion);
    if p.server {
        let config_bytes = if let Some(initial) = initial {
            serde_json::to_vec(&initial).map_err(|_| "install_config_encoding_failed")?
        } else {
            fs::read(config).map_err(|_| "existing_config_unavailable")?
        };
        let config_exists = fs::symlink_metadata(config).is_ok();
        let mode = if config_exists {
            fs::symlink_metadata(config)
                .map_err(|_| "existing_config_metadata_unavailable")?
                .mode()
                & 0o777
        } else {
            0o600
        };
        let desired = Desired::file(config.into(), config_bytes, mode);
        artifacts.push(if config_exists {
            desired.preserve()
        } else {
            desired
        });
        if Path::new("/run/systemd/system").is_dir() {
            artifacts.push(Desired::file(
                unit.into(),
                p.unit.as_bytes().to_vec(),
                0o600,
            ));
        }
    }
    artifacts.push(Desired::link(link.into(), binary.into()));
    use sha2::Digest;
    let binding = sha2::Sha256::digest(
        serde_json::to_vec(&(home, p)).map_err(|_| "install_plan_encoding_failed")?,
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let mut tx = Transaction::open(
        &home.join(".local/share/readb-installer"),
        &binding,
        &artifacts,
        recover,
    )?;
    if p.server {
        private_dir(Path::new(&p.state))?;
    }
    // Publish the command link last. A failed reload leaves exact before/after
    // evidence and a visible recovery fence, not an implicitly successful install.
    let last = artifacts.len() - 1;
    for (n, artifact) in artifacts[..last].iter().enumerate() {
        tx.publish(n, artifact)?;
    }
    if p.server && Path::new("/run/systemd/system").is_dir() {
        systemctl(&["daemon-reload"]).map_err(|_|"install_reload_unconfirmed: pending files kept; fix user bus then rerun exact install with --recover")?;
    }
    tx.publish(last, &artifacts[last])?;
    tx.finish()?;
    Ok(
        json!({"installed":true,"binary":p.binary,"link":p.link,"server":p.server,"state":p.state,"completions":["bash","zsh","fish"],"next":if p.server{"readb --local service start"}else{"readb context add NAME --ssh HOST --state SERVER_STATE"},"network_provisioned":false,"services_started":false,"note":"Existing devices and VPN configuration were not changed."}),
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
fn completion_artifacts(home: &Path) -> Res<Vec<Desired>> {
    let mut result = Vec::new();
    for (shell, path) in [
        (
            "bash",
            home.join(".local/share/bash-completion/completions/readb"),
        ),
        ("zsh", home.join(".local/share/zsh/site-functions/_readb")),
        ("fish", home.join(".config/fish/completions/readb.fish")),
    ] {
        let mut command = Command::new("/proc/self/exe");
        command.args(["completion", shell]);
        let output =
            crate::runner::capture_cmd(command, std::time::Duration::from_secs(15), 1024 * 1024)?;
        if !output.ok {
            return Err("completion_generate_failed".into());
        }
        result.push(Desired::file(path, output.out, 0o600).owned());
    }
    Ok(result)
}
