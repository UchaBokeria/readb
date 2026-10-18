//! Existing-interface systemd activation. No VPN restart, peer enrollment or ADB.
use crate::{
    policy::Res,
    setup_activation::{self, Action, Actions, Observation},
    setup_apply::ApplyPlan,
    setup_journal::{Journal, Phase},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn fields(text: &str) -> Res<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or("setup_unit_reply_invalid")?;
        // systemctl prints the typed (0, "/") no-job value as an empty
        // present Job property. A missing property is still rejected below.
        let value = if k == "Job" && v.is_empty() { "0" } else { v };
        if result.insert(k.into(), value.into()).is_some() {
            return Err("setup_unit_duplicate_property".into());
        }
    }
    Ok(result)
}
pub fn admit_unit(text: &str, fragment: &str) -> Res<BTreeMap<String, String>> {
    let m = fields(text)?;
    for (k, v) in [
        ("LoadState", "loaded"),
        ("FragmentPath", fragment),
        ("DropInPaths", ""),
        ("NeedDaemonReload", "no"),
        ("Job", "0"),
    ] {
        if m.get(k).map(String::as_str) != Some(v) {
            return Err(format!("setup_unit_not_admitted: {k}"));
        }
    }
    Ok(m)
}
pub fn enable_before(text: &str) -> Res<bool> {
    let m = fields(text)?;
    if m.get("DropInPaths").map(String::as_str) != Some("")
        || m.get("Job").map(String::as_str) != Some("0")
    {
        return Ok(false);
    }
    Ok(matches!(
        m.get("UnitFileState").map(String::as_str),
        Some("disabled" | "enabled")
    ) || (m.get("LoadState").map(String::as_str) == Some("not-found")
        && m.get("UnitFileState").map(String::as_str) == Some("")
        && m.get("MainPID").map(String::as_str) == Some("0")
        && m.get("ActiveState").map(String::as_str) == Some("inactive")))
}
pub fn admit_user_manager(text: &str, uid: u32) -> Res<BTreeMap<String, String>> {
    let m = fields(text)?;
    let fragment = m
        .get("FragmentPath")
        .ok_or("setup_user_manager_fragment_missing")?;
    if !matches!(
        fragment.as_str(),
        "/usr/lib/systemd/system/user@.service" | "/lib/systemd/system/user@.service"
    ) || m.get("User").map(String::as_str) != Some(uid.to_string().as_str())
    {
        return Err("setup_user_manager_identity_or_template_changed".into());
    }
    let drops = m
        .get("DropInPaths")
        .ok_or("setup_user_manager_dropins_unknown")?;
    let mut seen = std::collections::BTreeSet::new();
    for file in drops.split_whitespace() {
        if !matches!(
            file,
            "/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf"
                | "/usr/lib/systemd/system/user@.service.d/timeout.conf"
        ) || !seen.insert(file)
        {
            return Err("setup_user_manager_override_not_admitted".into());
        }
    }
    admit_unit(
        &text.replace(&format!("DropInPaths={drops}"), "DropInPaths="),
        fragment,
    )?;
    Ok(m)
}
fn ctl(args: &[&str]) -> Res<String> {
    let bin = crate::network_runtime::program(&["/usr/bin/systemctl", "/bin/systemctl"])?;
    let mut c = std::process::Command::new(bin);
    c.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .args(args);
    let r = crate::runner::capture_cmd(c, Duration::from_secs(30), 65536)
        .map_err(|_| "setup_service_manager_completion_unconfirmed")?;
    if !r.ok {
        return Err("setup_service_manager_failed: pending activation preserved".into());
    }
    String::from_utf8(r.out).map_err(|_| "setup_service_manager_reply_invalid".into())
}
fn show(name: &str) -> Res<String> {
    ctl(&[
        "show",
        "--all",
        name,
        "-p",
        "LoadState",
        "-p",
        "FragmentPath",
        "-p",
        "DropInPaths",
        "-p",
        "NeedDaemonReload",
        "-p",
        "Job",
        "-p",
        "ActiveState",
        "-p",
        "SubState",
        "-p",
        "MainPID",
        "-p",
        "UnitFileState",
        "-p",
        "ControlGroup",
        "-p",
        "User",
    ])
}
fn quiet(m: &BTreeMap<String, String>, name: &str) -> bool {
    if m.get("ActiveState").map(String::as_str) != Some("inactive")
        || m.get("MainPID").map(String::as_str) != Some("0")
        || m.get("Job").map(String::as_str) != Some("0")
    {
        return false;
    }
    let Some(group) = m.get("ControlGroup") else {
        return false;
    };
    if group.is_empty() {
        return true;
    }
    let p = Path::new(group);
    if !p.is_absolute()
        || p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || !group.ends_with(&format!("/{name}"))
    {
        return false;
    }
    match fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(group.trim_start_matches('/'))
            .join("cgroup.procs"),
    ) {
        Ok(s) => s.trim().is_empty(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}
pub fn admit_user_file_recovery(text: &str, fragment: &str) -> Res<()> {
    let m = fields(text)?;
    let known = (m.get("LoadState").map(String::as_str) == Some("loaded")
        && m.get("FragmentPath").map(String::as_str) == Some(fragment))
        || (m.get("LoadState").map(String::as_str) == Some("not-found")
            && m.get("FragmentPath").map(String::as_str) == Some(""));
    if !known || m.get("DropInPaths").map(String::as_str) != Some("") || !quiet(&m, "readb.service")
    {
        return Err("setup_user_upgrade_requires_quiescent_service".into());
    }
    Ok(())
}
fn start_tick(pid: u32) -> Res<String> {
    let s =
        fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| "setup_process_unavailable")?;
    s.rsplit_once(") ")
        .and_then(|(_, s)| s.split_whitespace().nth(19))
        .map(str::to_string)
        .ok_or("setup_process_stat_invalid".into())
}
fn process(pid: u32, uid: u32, binary: &Path, args: Option<&[String]>) -> Res<()> {
    if pid == 0 {
        return Err("setup_process_missing".into());
    }
    let before = start_tick(pid)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| "setup_process_unavailable")?;
    let ids = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .ok_or("setup_process_identity_unavailable")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "setup_process_identity_invalid")?;
    if ids != vec![uid; 4]
        || fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|_| "setup_process_image_unavailable")?
            != binary
    {
        return Err("setup_process_identity_or_image_mismatch".into());
    }
    if let Some(args) = args {
        if hash(
            &fs::read(format!("/proc/{pid}/exe")).map_err(|_| "setup_process_image_unavailable")?,
        ) != hash(&fs::read("/proc/self/exe").map_err(|_| "setup_image_unavailable")?)
        {
            return Err("setup_process_image_hash_mismatch".into());
        }
        let bytes = fs::read(format!("/proc/{pid}/cmdline"))
            .map_err(|_| "setup_process_arguments_unavailable")?;
        let actual = bytes
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| std::str::from_utf8(b).map(str::to_string))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "setup_process_arguments_invalid")?;
        if actual != args {
            return Err("setup_process_arguments_mismatch".into());
        }
    }
    if start_tick(pid)? != before {
        return Err("setup_process_changed_during_inspection".into());
    }
    Ok(())
}
fn pid(m: &BTreeMap<String, String>) -> Res<u32> {
    m.get("MainPID")
        .and_then(|s| s.parse().ok())
        .ok_or("setup_unit_pid_unavailable".into())
}
fn running(m: &BTreeMap<String, String>) -> bool {
    m.get("ActiveState").map(String::as_str) == Some("active")
        && m.get("SubState").map(String::as_str) == Some("running")
}
struct Systemd<'a> {
    plan: &'a ApplyPlan,
    user: crate::service::InstallPlan,
}
impl Systemd<'_> {
    fn core(&self) -> Res<()> {
        crate::network_install::inspect_setup_files(
            Path::new("/"),
            &self.plan.policy,
            &self.plan.root_install,
        )
    }
    fn selected(&self, args: &[&str]) -> Res<Value> {
        crate::setup_user::value_for(
            &self.plan.owner,
            &args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
    }
    fn user_files(&self) -> Res<Value> {
        self.selected(&[
            "install",
            "--server",
            "--prefix",
            self.plan.install_dir.to_str().ok_or("setup_path_invalid")?,
            "--inspect",
        ])
    }
    fn user_unit(&self) -> Res<String> {
        let v = self.selected(&["--local", "service", "status"])?;
        v["status"]
            .as_str()
            .map(str::to_string)
            .ok_or("setup_user_unit_reply_invalid".into())
    }
    fn linger(&self) -> Res<bool> {
        let bin = crate::network_runtime::program(&["/usr/bin/loginctl", "/bin/loginctl"])?;
        let mut c = std::process::Command::new(bin);
        c.env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .args([
                "show-user",
                &self.plan.owner.uid.to_string(),
                "--property=Linger",
                "--value",
            ]);
        let r = crate::runner::capture_cmd(c, Duration::from_secs(10), 1024)?;
        if !r.ok {
            return Err("setup_user_linger_unavailable".into());
        }
        match r.out.as_slice() {
            b"yes\n" => Ok(true),
            b"no\n" => Ok(false),
            _ => Err("setup_user_linger_reply_invalid".into()),
        }
    }
    fn observe(&self, a: Action, ready: bool, retry_safe: bool, detail: &str) -> Observation {
        Observation {
            fingerprint: hash(
                format!("{}:{a:?}:{ready}:{detail}", self.plan.plan_sha256).as_bytes(),
            ),
            ready,
            retry_safe,
            subordinate_pending: false,
        }
    }
    fn wait(&mut self, a: Action) -> Res<()> {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            if self.inspect(a).is_ok_and(|s| s.ready) {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(
                    "setup_activation_readiness_unconfirmed: pending action retained".into(),
                );
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }
}
impl Actions for Systemd<'_> {
    fn inspect(&mut self, a: Action) -> Res<Observation> {
        self.core()?;
        match a {
            Action::HelperEnabled => {
                let text = show("readb-network.service")?;
                let m = fields(&text)?;
                let enabled = m.get("UnitFileState").map(String::as_str) == Some("enabled");
                let admitted =
                    admit_unit(&text, "/etc/systemd/system/readb-network.service").is_ok();
                // Reload+enable are idempotent metadata effects, never process/network
                // operations. The before fingerprint deliberately binds boot state and
                // immutable owned files; cache refresh alone is safe on explicit recovery.
                let safe = enable_before(&text)?;
                Ok(self.observe(
                    a,
                    enabled && admitted,
                    safe,
                    if enabled { "enabled" } else { "disabled" },
                ))
            }
            Action::HelperRunning => {
                let m = admit_unit(
                    &show("readb-network.service")?,
                    "/etc/systemd/system/readb-network.service",
                )?;
                let ready = if running(&m) {
                    let binary = self.plan.root_install.binary_path();
                    let args = vec![
                        binary.clone(),
                        "--local".into(),
                        "network".into(),
                        "helper".into(),
                        "--policy".into(),
                        "/etc/readb/network-policy.json".into(),
                        "--state".into(),
                        "/var/lib/readb-network".into(),
                    ];
                    process(pid(&m)?, 0, Path::new(&binary), Some(&args))?;
                    let health =
                        crate::network_runtime::call(crate::network_runtime::Call::Status)?;
                    health["interface_verified"] == true
                        && health["fenced"] == false
                        && health["interface"] == self.plan.policy.interface
                } else {
                    false
                };
                Ok(self.observe(a, ready, quiet(&m, "readb-network.service"), "owned-helper"))
            }
            Action::Linger => {
                let ready = self.linger()?;
                Ok(self.observe(a, ready, !ready, "selected-user"))
            }
            Action::UserManager => {
                let name = format!("user@{}.service", self.plan.owner.uid);
                let text = show(&name)?;
                let m = admit_user_manager(&text, self.plan.owner.uid)?;
                let mut template =
                    crate::setup_provider::protected_file(Path::new(&m["FragmentPath"]), false)?;
                for file in m["DropInPaths"].split_whitespace() {
                    template.extend_from_slice(file.as_bytes());
                    template.extend_from_slice(&crate::setup_provider::protected_file(
                        Path::new(file),
                        false,
                    )?);
                }
                let ready = if running(&m) {
                    let runtime = PathBuf::from(format!("/run/user/{}", self.plan.owner.uid));
                    use std::os::unix::fs::{FileTypeExt, MetadataExt};
                    let metadata =
                        fs::symlink_metadata(&runtime).map_err(|_| "setup_user_runtime_missing")?;
                    let socket = fs::symlink_metadata(runtime.join("bus"))
                        .map_err(|_| "setup_user_bus_missing")?;
                    if !metadata.is_dir()
                        || metadata.uid() != self.plan.owner.uid
                        || metadata.mode() & 0o077 != 0
                        || !socket.file_type().is_socket()
                        || socket.uid() != self.plan.owner.uid
                    {
                        return Err("setup_user_runtime_or_bus_unsafe".into());
                    }
                    let bin = crate::network_runtime::program(&[
                        "/usr/lib/systemd/systemd",
                        "/lib/systemd/systemd",
                    ])?;
                    process(pid(&m)?, self.plan.owner.uid, &bin, None)?;
                    true
                } else {
                    false
                };
                Ok(self.observe(a, ready, quiet(&m, &name), &hash(&template)))
            }
            Action::UserFiles => {
                let value = self.user_files()?;
                let state = value["state"]
                    .as_str()
                    .ok_or("setup_user_file_state_invalid")?;
                let mark = value["fingerprint"]
                    .as_str()
                    .ok_or("setup_user_file_fingerprint_missing")?;
                if matches!(state, "upgrade" | "pending") {
                    let text = self.user_unit()?;
                    admit_user_file_recovery(&text, &self.user.unit_path)?;
                }
                Ok(Observation {
                    fingerprint: mark.into(),
                    ready: state == "ready",
                    retry_safe: state == "absent" || state == "upgrade",
                    subordinate_pending: state == "pending" && value["pending_bound"] == true,
                })
            }
            Action::UserEnabled | Action::UserRunning => {
                if self.user_files()?["state"] != "ready" {
                    return Err("setup_user_files_not_ready".into());
                }
                let m = admit_unit(&self.user_unit()?, &self.user.unit_path)?;
                if a == Action::UserEnabled {
                    let enabled = m.get("UnitFileState").map(String::as_str) == Some("enabled");
                    let safe = m.get("UnitFileState").map(String::as_str) == Some("disabled");
                    return Ok(self.observe(a, enabled, safe, "owned-user-unit"));
                }
                let ready = if running(&m) {
                    let args = vec![
                        self.user.binary.clone(),
                        "--local".into(),
                        "--state-dir".into(),
                        self.user.state.clone(),
                        "daemon".into(),
                        "--config".into(),
                        self.user.config.clone(),
                    ];
                    let actual = pid(&m)?;
                    process(
                        actual,
                        self.plan.owner.uid,
                        Path::new(&self.user.binary),
                        Some(&args),
                    )?;
                    let health = self.selected(&[
                        "--local",
                        "--state-dir",
                        &self.user.state,
                        "--json",
                        "doctor",
                    ])?;
                    health["pid"] == actual && health["catalog_cleanup_unknown"] == false
                } else {
                    false
                };
                Ok(self.observe(a, ready, quiet(&m, "readb.service"), "owned-coordinator"))
            }
        }
    }
    fn apply(&mut self, a: Action, recover: bool) -> Res<()> {
        self.core()?;
        match a {
            Action::HelperEnabled => {
                ctl(&["daemon-reload"])?;
                ctl(&["enable", "readb-network.service"])?;
            }
            Action::HelperRunning => {
                ctl(&["start", "readb-network.service"])?;
                self.wait(a)?;
            }
            Action::Linger => {
                let bin = crate::network_runtime::program(&["/usr/bin/loginctl", "/bin/loginctl"])?;
                let mut c = std::process::Command::new(bin);
                c.env_clear()
                    .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                    .env("LANG", "C")
                    .args(["enable-linger", &self.plan.owner.name]);
                let r = crate::runner::capture_cmd(c, Duration::from_secs(30), 4096)?;
                if !r.ok {
                    return Err("setup_linger_enable_unconfirmed".into());
                }
            }
            Action::UserManager => {
                ctl(&["start", &format!("user@{}.service", self.plan.owner.uid)])?;
                self.wait(a)?;
            }
            Action::UserFiles => {
                let pending = recover && self.user_files()?["state"] == "pending";
                crate::setup_user::install_for_recover(
                    &self.plan.owner,
                    &self.plan.install_dir,
                    pending,
                )?;
            }
            Action::UserEnabled => {
                self.selected(&["--local", "service", "enable"])?;
            }
            Action::UserRunning => {
                self.selected(&["--local", "service", "start"])?;
                self.wait(a)?;
            }
        }
        Ok(())
    }
}
pub fn apply(plan: &ApplyPlan, binary: &[u8], recover: bool) -> Res<Value> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("setup_apply_requires_root".into());
    }
    plan.validate(binary)?;
    let current = crate::setup_apply::Owner::resolve(&plan.owner.name)?;
    if serde_json::to_vec(&current).map_err(|_| "setup_owner_invalid")?
        != serde_json::to_vec(&plan.owner).map_err(|_| "setup_owner_invalid")?
        || !current.can_write_home()?
    {
        return Err("setup_owner_changed_or_home_unavailable".into());
    }
    let user = crate::service::plan(&plan.owner.home, &plan.install_dir, true)?;
    let mut adapter = Systemd { plan, user };
    // Admit user-owned parent paths and the existing receipt before changing
    // root files/units. A writable home alone does not prove a safe destination.
    let initial_user_files = adapter.user_files()?;
    if initial_user_files["state"] == "pending" && !recover {
        return Err("setup_user_files_pending: explicit recovery required".into());
    }
    let provider = crate::setup_provider::inspect(&plan.policy, plan.options.listen_port)?;
    let provider_pin = hash(
        &serde_json::to_vec(&(&provider, &plan.baseline_sha256))
            .map_err(|_| "setup_provider_encoding_failed")?,
    );
    let path = crate::network_install::setup_journal_directory(Path::new("/"))?;
    Journal::open(&path, &plan.plan_sha256)?.bind_provider(&provider_pin)?;
    if crate::network_install::inspect_setup_files(Path::new("/"), &plan.policy, &plan.root_install)
        .is_err()
    {
        if recover {
            crate::setup_files::recover(Path::new("/"), plan, binary)?;
        } else {
            crate::setup_files::apply(Path::new("/"), plan, binary)?;
        }
    } else {
        crate::setup_files::reconcile_installed(Path::new("/"), plan, binary, recover)?;
    }
    let mut journal = Journal::open(&path, &plan.plan_sha256)?;
    setup_activation::activate(&mut journal, &mut adapter, recover)?;
    if !journal.completed(Phase::Persistence) {
        journal.admit_persistence(recover)?;
        let fresh = crate::setup_provider::inspect(&plan.policy, plan.options.listen_port)?;
        let fresh_pin = hash(
            &serde_json::to_vec(&(&fresh, &plan.baseline_sha256))
                .map_err(|_| "setup_provider_encoding_failed")?,
        );
        journal.bind_provider(&fresh_pin)?;
        journal.complete(Phase::Persistence)?;
    }
    Ok(
        json!({"files_installed":true,"helper_active":true,"coordinator_active":true,"network_verified":true,"provider":provider,"devices_accepted":false,"plan_sha256":plan.plan_sha256,"next":"Enroll devices and verify each migration before retiring existing services. Web stays off by default."}),
    )
}
