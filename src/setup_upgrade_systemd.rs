//! Exact empty-staging systemd upgrade. No device migration or VPN replacement.
use crate::{policy::Res, schema::ServerConfig};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
fn hash(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn empty(config: &ServerConfig) -> Res<String> {
    config.validate()?;
    if !config.devices.is_empty() || !config.listeners.is_empty() {
        return Err("upgrade_empty_staging_only: use a reviewed managed-device adapter".into());
    }
    Ok(hash(
        &serde_json::to_vec(config).map_err(|_| "upgrade_config_encoding_failed")?,
    ))
}
pub fn admit_empty(status: &Value, config: &ServerConfig) -> Res<String> {
    if status["schema"] != 1
        || status["pid"]
            .as_u64()
            .is_none_or(|p| p == 0 || p > u32::MAX as u64)
        || status["catalog_cleanup_unknown"] != false
        || status["devices"].as_array().is_none_or(|a| !a.is_empty())
        || status["listener_errors"]
            .as_object()
            .is_none_or(|m| !m.is_empty())
    {
        return Err("upgrade_empty_runtime_not_admitted".into());
    }
    empty(config)
}
pub fn admit_frozen(manager: &str, events: &str, processes: &str, pid: u32) -> Res<()> {
    let fields = events
        .lines()
        .map(|l| {
            l.split_once(' ')
                .ok_or_else(|| "upgrade_cgroup_events_invalid".to_string())
        })
        .collect::<Res<Vec<_>>>()?;
    let frozen = fields
        .iter()
        .filter(|(k, _)| *k == "frozen")
        .collect::<Vec<_>>();
    if pid == 0
        || manager != "frozen"
        || frozen.len() != 1
        || frozen[0].1 != "1"
        || processes.split_whitespace().collect::<Vec<_>>() != [pid.to_string()]
    {
        return Err("upgrade_exact_frozen_cgroup_required".into());
    }
    Ok(())
}
fn load_empty(state: &Path, file: &Path) -> Res<(ServerConfig, String)> {
    let raw = crate::user_install::read_owned(file, 1024 * 1024)?
        .ok_or("upgrade_existing_config_required")?;
    let config = ServerConfig::parse(&raw)?;
    let pin = empty(&config)?;
    crate::catalog::Store::for_loaded_config(state, file, &config)?.preflight_existing()?;
    Ok((config, pin))
}
pub fn inspect_empty(state: &Path, file: &Path) -> Res<Value> {
    let (config, pin) = load_empty(state, file)?;
    let marker = crate::maintenance::inspect(state, &pin)?;
    Ok(
        json!({"empty":true,"config_fingerprint":pin,"config":config,"maintenance":marker,"existing_binding":true}),
    )
}
fn exact_process(pid: u32, uid: u32, binary: &Path, digest: &str, args: &[String]) -> Res<String> {
    let tick = crate::setup_systemd::start_tick(pid)?;
    crate::setup_systemd::process(pid, uid, binary, None)?;
    if hash(&fs::read(format!("/proc/{pid}/exe")).map_err(|_| "upgrade_process_image_missing")?)
        != digest
    {
        return Err("upgrade_process_image_changed".into());
    }
    let command =
        fs::read(format!("/proc/{pid}/cmdline")).map_err(|_| "upgrade_process_args_missing")?;
    let observed = command
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| std::str::from_utf8(b).map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "upgrade_process_args_invalid")?;
    if observed != args || crate::setup_systemd::start_tick(pid)? != tick {
        return Err("upgrade_process_arguments_or_generation_changed".into());
    }
    Ok(hash(
        &serde_json::to_vec(&(pid, tick, uid, binary, digest, args))
            .map_err(|_| "upgrade_process_encoding_failed")?,
    ))
}
fn cgroup(group: &str) -> Res<PathBuf> {
    let p = Path::new(group);
    if !p.is_absolute()
        || !group.ends_with("/readb.service")
        || p.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err("upgrade_owned_cgroup_required".into());
    }
    Ok(Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
}
fn user_args(binary: &str, state: &Path, file: &Path) -> Res<Vec<String>> {
    Ok(vec![
        binary.into(),
        "--local".into(),
        "--state-dir".into(),
        state.to_str().ok_or("upgrade_path_utf8_required")?.into(),
        "daemon".into(),
        "--config".into(),
        file.to_str().ok_or("upgrade_path_utf8_required")?.into(),
    ])
}
pub struct Bootstrap<'a> {
    pub upgrade: &'a str,
    pub config: &'a str,
    pub pid: u32,
    pub tick: &'a str,
    pub binary: &'a Path,
    pub image: &'a str,
    pub group: &'a str,
}
fn frozen_process(state: &Path, file: &Path, b: &Bootstrap<'_>) -> Res<String> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return Err("upgrade_bootstrap_requires_selected_user".into());
    }
    let status = crate::service::manage("status")?;
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?);
    let m = crate::setup_systemd::admit_unit(
        status["status"]
            .as_str()
            .ok_or("upgrade_unit_reply_invalid")?,
        home.join(".config/systemd/user/readb.service")
            .to_str()
            .ok_or("upgrade_path_utf8_required")?,
    )?;
    if crate::setup_systemd::pid(&m)? != b.pid
        || m.get("ControlGroup").map(String::as_str) != Some(b.group)
        || !b
            .group
            .starts_with(&format!("/user.slice/user-{uid}.slice/"))
        || crate::setup_systemd::start_tick(b.pid)? != b.tick
    {
        return Err("upgrade_frozen_process_generation_changed".into());
    }
    let dir = cgroup(b.group)?;
    admit_frozen(
        m.get("FreezerState").ok_or("upgrade_freezer_unsupported")?,
        &fs::read_to_string(dir.join("cgroup.events")).map_err(|_| "upgrade_cgroup_unavailable")?,
        &fs::read_to_string(dir.join("cgroup.procs")).map_err(|_| "upgrade_cgroup_unavailable")?,
        b.pid,
    )?;
    let args = user_args(
        b.binary.to_str().ok_or("upgrade_path_utf8_required")?,
        state,
        file,
    )?;
    exact_process(b.pid, uid, b.binary, b.image, &args)
}
/// Offline publisher for the root adapter only. An existing catalog binding and
/// exact sole frozen owned process are required; no runtime lock is bypassed for
/// a running/unfrozen coordinator and no missing catalog ownership is adopted.
pub fn bootstrap_empty(state: &Path, file: &Path, b: &Bootstrap<'_>) -> Res<Value> {
    let marker = crate::maintenance::Marker::new(b.upgrade, b.config)?;
    let (_, pin) = load_empty(state, file)?;
    if pin != b.config {
        return Err("upgrade_config_changed".into());
    }
    let before = frozen_process(state, file, b)?;
    crate::maintenance::Store::open(state)?.publish(&marker)?;
    let (_, fresh) = load_empty(state, file)?;
    if fresh != pin || frozen_process(state, file, b)? != before {
        return Err("upgrade_bootstrap_changed: maintenance retained".into());
    }
    Ok(json!({"ready_to_stop":true,"maintenance":marker,"process_fingerprint":before}))
}
use crate::{
    setup_apply::ApplyPlan,
    setup_upgrade::{self, Action, Actions, Journal, Observation},
};
struct Adapter<'a> {
    old: ApplyPlan,
    new: ApplyPlan,
    old_user: crate::service::InstallPlan,
    new_user: crate::service::InstallPlan,
    old_image: String,
    new_image: String,
    binary: &'a [u8],
    provider: String,
    tag: String,
    config: String,
    original: Vec<u8>,
    journal_path: PathBuf,
    phase: usize,
    pending: Option<Action>,
    release_intent: bool,
}
impl Adapter<'_> {
    fn selected(&self, args: &[&str]) -> Res<Value> {
        crate::setup_user::value_for(
            &self.new.owner,
            &args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        )
    }
    fn local(&self, args: &[&str]) -> Res<Value> {
        let mut a = vec!["--local", "--state-dir", &self.new_user.state, "--json"];
        a.extend_from_slice(args);
        self.selected(&a)
    }
    fn user_text(&self) -> Res<String> {
        self.local(&["service", "status"])?["status"]
            .as_str()
            .map(str::to_owned)
            .ok_or("upgrade_user_unit_reply_invalid".into())
    }
    fn user_unit(&self) -> Res<BTreeMap<String, String>> {
        crate::setup_systemd::admit_unit(&self.user_text()?, &self.new_user.unit_path)
    }
    fn helper_unit(&self, allow_reload: bool) -> Res<BTreeMap<String, String>> {
        let mut text = crate::setup_systemd::show("readb-network.service")?;
        if allow_reload {
            text = text.replace("NeedDaemonReload=yes", "NeedDaemonReload=no");
        }
        crate::setup_systemd::admit_unit(&text, "/etc/systemd/system/readb-network.service")
    }
    fn user_process(&self, new: bool, m: &BTreeMap<String, String>) -> Res<String> {
        if !crate::setup_systemd::running(m) {
            return Err("upgrade_owned_user_not_running".into());
        }
        let u = if new { &self.new_user } else { &self.old_user };
        exact_process(
            crate::setup_systemd::pid(m)?,
            self.new.owner.uid,
            Path::new(&u.binary),
            if new {
                &self.new_image
            } else {
                &self.old_image
            },
            &user_args(&u.binary, Path::new(&u.state), Path::new(&u.config))?,
        )
    }
    fn helper_process(&self, new: bool, m: &BTreeMap<String, String>) -> Res<String> {
        if !crate::setup_systemd::running(m) {
            return Err("upgrade_owned_helper_not_running".into());
        }
        let p = if new {
            &self.new.root_install
        } else {
            &self.old.root_install
        };
        let binary = p.binary_path();
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
        exact_process(
            crate::setup_systemd::pid(m)?,
            0,
            Path::new(&binary),
            if new {
                &self.new_image
            } else {
                &self.old_image
            },
            &args,
        )
    }
    fn healthy_helper(&self, new: bool) -> Res<()> {
        self.helper_process(new, &self.helper_unit(false)?)?;
        let v = crate::network_runtime::call(crate::network_runtime::Call::Status)?;
        if v["fenced"] != false
            || v["interface_verified"] != true
            || v["interface"] != self.new.policy.interface
        {
            return Err("upgrade_helper_health_unconfirmed".into());
        }
        Ok(())
    }
    fn provider(&self) -> Res<()> {
        let receipt = match crate::setup_provider::inspect_managed_baseline(
            &self.new.policy,
            self.new.options.listen_port,
        ) {
            Ok((r, b)) => {
                if hash(&serde_json::to_vec(&b).map_err(|_| "upgrade_baseline_invalid")?)
                    != self.new.baseline_sha256
                {
                    return Err("upgrade_external_baseline_changed".into());
                }
                r
            }
            Err(_) => {
                crate::setup_provider::inspect(&self.new.policy, self.new.options.listen_port)?
            }
        };
        if hash(
            &serde_json::to_vec(&(&receipt, &self.new.baseline_sha256))
                .map_err(|_| "upgrade_provider_invalid")?,
        ) != self.provider
        {
            return Err("upgrade_original_provider_changed".into());
        }
        Ok(())
    }
    fn files(&self) -> Res<Value> {
        self.selected(&[
            "install",
            "--server",
            "--prefix",
            self.new
                .install_dir
                .to_str()
                .ok_or("upgrade_path_utf8_required")?,
            "--inspect",
        ])
    }
    fn config(&self) -> Res<Value> {
        let v = self.local(&[
            "maintenance",
            "inspect-empty",
            "--file",
            &self.new_user.config,
        ])?;
        if v["config_fingerprint"] != self.config
            || v["existing_binding"] != true
            || v["empty"] != true
        {
            return Err("upgrade_original_empty_config_changed".into());
        }
        Ok(v)
    }
    fn doctor(&self) -> Res<Value> {
        self.local(&["doctor"])
    }
    fn expected_marker(&self) -> Res<Value> {
        serde_json::to_value(crate::maintenance::Marker::new(&self.tag, &self.config)?)
            .map_err(|_| "upgrade_marker_invalid".into())
    }
    fn barrier(&self, m: &BTreeMap<String, String>) -> Res<bool> {
        if self.config()?["maintenance"] != self.expected_marker()? {
            return Ok(false);
        }
        if m.get("FreezerState").map(String::as_str) == Some("frozen") {
            let dir = cgroup(m.get("ControlGroup").ok_or("upgrade_cgroup_missing")?)?;
            admit_frozen(
                "frozen",
                &fs::read_to_string(dir.join("cgroup.events"))
                    .map_err(|_| "upgrade_cgroup_unavailable")?,
                &fs::read_to_string(dir.join("cgroup.procs"))
                    .map_err(|_| "upgrade_cgroup_unavailable")?,
                crate::setup_systemd::pid(m)?,
            )?;
            Ok(true)
        } else {
            Ok(self.doctor()?["maintenance"] == self.expected_marker()?)
        }
    }
    fn user_quiet(&self) -> Res<()> {
        if !crate::setup_systemd::quiet(&self.user_unit()?, "readb.service") {
            return Err("upgrade_user_requires_quiet_owned_unit".into());
        }
        Ok(())
    }
    fn helper_quiet(&self) -> Res<()> {
        if !crate::setup_systemd::quiet(&self.helper_unit(true)?, "readb-network.service") {
            return Err("upgrade_helper_requires_quiet_owned_unit".into());
        }
        Ok(())
    }
    fn root_files(&self, new: bool) -> Res<()> {
        let plan = if new {
            &self.new.root_install
        } else {
            &self.old.root_install
        };
        crate::network_install::inspect_setup_files(Path::new("/"), &self.new.policy, plan)
    }
    fn bootstrap(&self, m: &BTreeMap<String, String>) -> Res<()> {
        let pid = crate::setup_systemd::pid(m)?;
        let tick = crate::setup_systemd::start_tick(pid)?;
        let group = m.get("ControlGroup").ok_or("upgrade_cgroup_missing")?;
        self.local(&[
            "maintenance",
            "bootstrap-empty",
            "--file",
            &self.new_user.config,
            "--upgrade",
            &self.tag,
            "--config",
            &self.config,
            "--pid",
            &pid.to_string(),
            "--tick",
            &tick,
            "--binary",
            &self.old_user.binary,
            "--image",
            &self.old_image,
            "--group",
            group,
        ])?;
        Ok(())
    }
    fn new_ready(&self) -> Res<()> {
        self.root_files(true)?;
        if self.files()?["state"] != "ready" {
            return Err("upgrade_new_user_files_not_ready".into());
        }
        self.healthy_helper(true)?;
        let m = self.user_unit()?;
        self.user_process(true, &m)?;
        let status = self.doctor()?;
        if status["pid"] != crate::setup_systemd::pid(&m)?
            || status["catalog_cleanup_unknown"] != false
        {
            return Err("upgrade_new_coordinator_not_ready".into());
        }
        self.provider()
    }
    fn released(&self) -> Res<bool> {
        let status = self.doctor()?;
        if !status.get("maintenance").is_some_and(Value::is_null) {
            return Ok(false);
        }
        let config = status["config_fingerprint"]
            .as_str()
            .ok_or("upgrade_live_config_unknown")?;
        // On an already released daemon, a legitimate catalog edit may change
        // config. Never clear a marker or require its newly active jobs idle.
        let v = self.local(&["maintenance", "inspect-marker", "--config", config])?;
        Ok(v["maintenance"].is_null())
    }
    fn observation(&self, a: Action, ready: bool, safe: bool, detail: &str) -> Observation {
        Observation {
            fingerprint: hash(format!("{}:{a:?}:{detail}", self.tag).as_bytes()),
            ready,
            retry_safe: safe,
        }
    }
    fn wait(&mut self, a: Action) -> Res<()> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(25);
        loop {
            if self.inspect(a).is_ok_and(|o| o.ready) {
                return Ok(());
            }
            if std::time::Instant::now() >= until {
                return Err(
                    "upgrade_service_readiness_unconfirmed: exact pending phase retained".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }
}
impl Actions for Adapter<'_> {
    fn admit(&mut self, j: &Journal) -> Res<()> {
        self.phase = j.completed_count();
        self.pending = j.pending();
        self.release_intent = self.phase == 9 || j.pending() == Some(Action::Resume);
        if self.phase >= 8 && self.release_intent && self.released().unwrap_or(false) {
            return self.new_ready();
        }
        self.config()?;
        self.provider()?;
        if self.phase < 3 {
            self.root_files(false)?;
        } else if self.phase > 3 {
            self.root_files(true)?;
        }
        let state = self.files()?;
        if self.phase < 4 && state["state"] != "upgrade" {
            return Err("upgrade_original_user_files_not_admitted".into());
        }
        if self.phase > 4 && state["state"] != "ready" {
            return Err("upgrade_new_user_files_not_admitted".into());
        }
        if self.phase == 0 {
            let m = self.user_unit()?;
            self.user_process(false, &m)?;
            self.healthy_helper(false)?;
        } else if self.phase == 1 {
            let m = self.user_unit()?;
            if !crate::setup_systemd::quiet(&m, "readb.service") {
                self.user_process(false, &m)?;
                if !self.barrier(&m)? {
                    return Err("upgrade_user_barrier_not_confirmed".into());
                }
            }
            self.healthy_helper(false)?;
        } else if self.phase <= 5 {
            self.user_quiet()?;
        }
        if self.phase == 2 {
            let m = self.helper_unit(false)?;
            if !crate::setup_systemd::quiet(&m, "readb-network.service") {
                self.healthy_helper(false)?;
            }
        } else if (3..=4).contains(&self.phase) {
            self.helper_quiet()?;
        } else if self.phase == 5 {
            let m = self.helper_unit(true)?;
            if !crate::setup_systemd::quiet(&m, "readb-network.service") {
                self.healthy_helper(true)?;
            }
        } else if self.phase >= 6 {
            self.healthy_helper(true)?;
        }
        if self.phase == 6 {
            let m = self.user_unit()?;
            if !crate::setup_systemd::quiet(&m, "readb.service") {
                self.user_process(true, &m)?;
                if !self.barrier(&m)? {
                    return Err("upgrade_new_user_barrier_missing".into());
                }
            }
        } else if self.phase >= 7 {
            self.new_ready()?;
            if !self.barrier(&self.user_unit()?)? {
                return Err("upgrade_new_user_barrier_missing".into());
            }
        }
        Ok(())
    }
    fn inspect(&mut self, a: Action) -> Res<Observation> {
        match a {
            Action::Maintenance => {
                let m = self.user_unit()?;
                let process = self.user_process(false, &m)?;
                let ready = self.barrier(&m)?;
                if !ready && m.get("FreezerState").map(String::as_str) != Some("frozen") {
                    let (_, config) = load_empty_as_selected(self)?;
                    admit_empty(&self.doctor()?, &config)?;
                    if self.local(&["config", "show"])? != config.public_view() {
                        return Err("upgrade_runtime_config_changed".into());
                    }
                }
                Ok(self.observation(a, ready, true, &format!("{}:{process}", self.config)))
            }
            Action::StopUser => {
                let m = self.user_unit()?;
                let quiet = crate::setup_systemd::quiet(&m, "readb.service");
                let detail = if quiet {
                    "quiet".into()
                } else {
                    let process = self.user_process(false, &m)?;
                    if !self.barrier(&m)? {
                        return Err("upgrade_user_barrier_missing".into());
                    }
                    process
                };
                Ok(self.observation(a, quiet, true, &detail))
            }
            Action::StopHelper => {
                let m = self.helper_unit(false)?;
                let quiet = crate::setup_systemd::quiet(&m, "readb-network.service");
                let detail = if quiet {
                    "quiet".into()
                } else {
                    self.helper_process(false, &m)?
                };
                Ok(self.observation(a, quiet, true, &detail))
            }
            Action::RootFiles => {
                use crate::network_install::UpgradeFiles;
                let state = crate::network_install::inspect_upgrade_state(
                    Path::new("/"),
                    &self.new.policy,
                    &self.old.root_install,
                    &self.new.root_install,
                )?;
                let ready = state == UpgradeFiles::New;
                let safe = state != UpgradeFiles::Pending || self.pending == Some(a);
                Ok(self.observation(
                    a,
                    ready,
                    safe,
                    if ready { "new-files" } else { "old-files" },
                ))
            }
            Action::UserFiles => {
                let state = self.files()?;
                let ready = state["state"] == "ready";
                let safe = state["state"] == "upgrade"
                    || (self.pending == Some(a)
                        && state["state"] == "pending"
                        && state["pending_bound"] == true);
                Ok(self.observation(
                    a,
                    ready,
                    safe,
                    if ready { "new-files" } else { "old-files" },
                ))
            }
            Action::StartHelper => {
                let m = self.helper_unit(true)?;
                let quiet = crate::setup_systemd::quiet(&m, "readb-network.service");
                if !quiet {
                    self.healthy_helper(true)?;
                }
                Ok(self.observation(
                    a,
                    !quiet,
                    quiet,
                    if quiet { "quiet" } else { "new-running" },
                ))
            }
            Action::StartUser => {
                let m = self.user_unit()?;
                let quiet = crate::setup_systemd::quiet(&m, "readb.service");
                if !quiet {
                    self.user_process(true, &m)?;
                    if !self.barrier(&m)? {
                        return Err("upgrade_new_user_barrier_missing".into());
                    }
                }
                Ok(self.observation(
                    a,
                    !quiet,
                    quiet,
                    if quiet { "quiet" } else { "new-running" },
                ))
            }
            Action::Binding => {
                let expected = crate::setup_systemd::verified_upgrade_binding(
                    &self.new,
                    &self.original,
                    &self.old.plan_sha256,
                    &self.provider,
                )?;
                let current = crate::setup_journal::snapshot(&self.journal_path)?;
                let ready = current == expected;
                Ok(self.observation(
                    a,
                    ready,
                    !ready,
                    if ready { "new-binding" } else { "old-binding" },
                ))
            }
            Action::Resume => {
                let ready = self.released()?;
                if ready && !self.release_intent {
                    return Err("upgrade_release_without_durable_intent".into());
                }
                Ok(self.observation(
                    a,
                    ready,
                    !ready,
                    if ready {
                        "released"
                    } else {
                        "owned-maintenance"
                    },
                ))
            }
        }
    }
    fn apply(&mut self, a: Action, j: &mut Journal, recover: bool) -> Res<()> {
        match a {
            Action::Maintenance => {
                let m = self.user_unit()?;
                let before = self.user_process(false, &m)?;
                if m.get("FreezerState").map(String::as_str) == Some("frozen") {
                    self.bootstrap(&m)?;
                } else if self.doctor()?.get("maintenance").is_some() {
                    self.local(&[
                        "maintenance",
                        "prepare",
                        "--upgrade",
                        &self.tag,
                        "--config",
                        &self.config,
                    ])?;
                } else {
                    self.local(&["service", "freeze"])?;
                    let result = (|| -> Res<()> {
                        let frozen = self.user_unit()?;
                        if self.user_process(false, &frozen)? != before {
                            return Err("upgrade_frozen_generation_changed".into());
                        }
                        self.config()?;
                        self.bootstrap(&frozen)
                    })();
                    if let Err(error) = result {
                        // If no marker was published, restore only this same frozen
                        // admitted process. Never thaw a different/unknown generation.
                        if let Ok(frozen) = self.user_unit()
                            && self.user_process(false, &frozen).is_ok_and(|p| p == before)
                            && self
                                .local(&["maintenance", "inspect-marker", "--config", &self.config])
                                .is_ok_and(|v| v["maintenance"].is_null())
                        {
                            let _ = self.local(&["service", "thaw"]);
                        }
                        return Err(error);
                    }
                }
            }
            Action::StopUser => {
                self.local(&["service", "stop"])?;
                self.wait(a)?;
            }
            Action::StopHelper => {
                crate::setup_systemd::ctl(&["stop", "readb-network.service"])?;
                self.wait(a)?;
            }
            Action::RootFiles => {
                let mut i = crate::network_install::Installer::open(Path::new("/"))?;
                if i.fenced() {
                    if !recover {
                        return Err("upgrade_root_files_require_exact_recovery".into());
                    }
                    i.recover_setup_pending(&self.new.policy, &self.new.root_install)?;
                }
                i.install(self.new.root_install.clone(), self.binary)?;
                i.verify_setup_files(&self.new.policy, &self.new.root_install)?;
            }
            Action::UserFiles => {
                let pending = self.files()?["state"] == "pending";
                if pending && !recover {
                    return Err("upgrade_user_files_require_exact_recovery".into());
                }
                crate::setup_user::install_for_recover(
                    &self.new.owner,
                    &self.new.install_dir,
                    pending,
                )?;
            }
            Action::StartHelper => {
                crate::setup_systemd::ctl(&["daemon-reload"])?;
                crate::setup_systemd::ctl(&["start", "readb-network.service"])?;
                self.wait(a)?;
            }
            Action::StartUser => {
                self.local(&["service", "start"])?;
                self.wait(a)?;
            }
            Action::Binding => {
                let bytes = crate::setup_systemd::verified_upgrade_binding(
                    &self.new,
                    &self.original,
                    &self.old.plan_sha256,
                    &self.provider,
                )?;
                j.publish_binding(&bytes)?;
            }
            Action::Resume => {
                if j.pending() != Some(a) || j.completed_count() != a.index() {
                    return Err("upgrade_final_release_intent_required".into());
                }
                self.release_intent = true;
                self.new_ready()?;
                let status = self.doctor()?;
                if status["maintenance"] != self.expected_marker()? {
                    return Err("upgrade_resume_owner_unknown".into());
                }
                let disk =
                    self.local(&["maintenance", "inspect-marker", "--config", &self.config])?;
                if disk["maintenance"].is_null() {
                    self.local(&[
                        "maintenance",
                        "resume",
                        "--upgrade",
                        &self.tag,
                        "--config",
                        &self.config,
                        "--recover",
                    ])?;
                } else {
                    self.local(&[
                        "maintenance",
                        "resume",
                        "--upgrade",
                        &self.tag,
                        "--config",
                        &self.config,
                    ])?;
                }
            }
        }
        Ok(())
    }
    fn confirm(&mut self, a: Action, j: &Journal) -> Res<()> {
        match a {
            Action::Maintenance => {
                let m = self.user_unit()?;
                if m.get("FreezerState").map(String::as_str) == Some("frozen") {
                    self.bootstrap(&m)?;
                } else {
                    self.local(&[
                        "maintenance",
                        "prepare",
                        "--upgrade",
                        &self.tag,
                        "--config",
                        &self.config,
                    ])?;
                }
            }
            Action::RootFiles => {
                let i = crate::network_install::Installer::open(Path::new("/"))?;
                i.verify_setup_files(&self.new.policy, &self.new.root_install)?;
            }
            Action::UserFiles => {
                self.user_quiet()?;
                crate::setup_user::install_for_recover(
                    &self.new.owner,
                    &self.new.install_dir,
                    false,
                )?;
            }
            Action::Resume => {
                if j.pending() != Some(a) {
                    return Err("upgrade_final_release_intent_required".into());
                }
                self.new_ready()?;
                self.local(&[
                    "maintenance",
                    "confirm-released",
                    "--upgrade",
                    &self.tag,
                    "--config",
                    &self.config,
                ])?;
                if !self.released()? {
                    return Err("upgrade_release_unconfirmed".into());
                }
            }
            _ => (),
        }
        Ok(())
    }
}
fn load_empty_as_selected(a: &Adapter<'_>) -> Res<(String, ServerConfig)> {
    let v = a.config()?;
    let config = ServerConfig::parse(
        &serde_json::to_vec(&v["config"]).map_err(|_| "upgrade_config_invalid")?,
    )?;
    Ok((a.config.clone(), config))
}
impl Adapter<'_> {
    fn initial_admission(&self) -> Res<()> {
        self.root_files(false)?;
        self.config()?;
        if self.files()?["state"] != "upgrade" {
            return Err("upgrade_original_user_contract_unknown".into());
        }
        let m = self.user_unit()?;
        self.user_process(false, &m)?;
        if m.get("FreezerState").map(String::as_str) == Some("frozen") {
            return Err("upgrade_unrecorded_frozen_service: preserve state and inspect".into());
        }
        self.healthy_helper(false)?;
        let helper = crate::network_runtime::call(crate::network_runtime::Call::Status)?;
        if helper["devices"].as_object().is_none_or(|m| !m.is_empty()) {
            return Err("upgrade_empty_helper_registry_required".into());
        }
        let (_, config) = load_empty_as_selected(self)?;
        let status = self.doctor()?;
        admit_empty(&status, &config)?;
        if status["pid"] != crate::setup_systemd::pid(&m)?
            || self.local(&["config", "show"])? != config.public_view()
        {
            return Err("upgrade_original_runtime_identity_changed".into());
        }
        if !self.config()?["maintenance"].is_null() {
            return Err("upgrade_existing_unrelated_maintenance_preserved".into());
        }
        let manager = crate::setup_systemd::admit_user_manager(
            &crate::setup_systemd::show(&format!("user@{}.service", self.new.owner.uid))?,
            self.new.owner.uid,
        )?;
        if !crate::setup_systemd::running(&manager) {
            return Err("upgrade_user_manager_not_running".into());
        }
        self.provider()
    }
    fn thaw_interrupted_unpublished(&self, j: &Journal) -> Res<()> {
        if j.pending() != Some(Action::Maintenance) {
            return Ok(());
        }
        let m = self.user_unit()?;
        if m.get("FreezerState").map(String::as_str) != Some("frozen") {
            return Ok(());
        }
        let process = self.user_process(false, &m)?;
        let before = self.observation(
            Action::Maintenance,
            false,
            true,
            &format!("{}:{process}", self.config),
        );
        if j.pending_before() != Some(before.fingerprint.as_str()) {
            return Err("upgrade_frozen_generation_unknown: no thaw attempted".into());
        }
        let disk = self.local(&["maintenance", "inspect-marker", "--config", &self.config])?;
        if disk["maintenance"].is_null() && self.config().is_err() {
            self.local(&["service", "thaw"])?;
            return Err("upgrade_empty_catalog_changed: exact original unit thawed; pending evidence retained".into());
        }
        Ok(())
    }
}
/// Software-only existing-interface upgrade. Only the exact empty-staging
/// contract is supported initially. Every mutation is behind root journal intent.
pub fn apply(
    options: crate::setup::Options,
    owner: crate::setup_apply::Owner,
    policy: crate::network::Policy,
    install_dir: PathBuf,
    binary: &[u8],
    recover: bool,
    inspect: bool,
) -> Res<Value> {
    use crate::network::Kernel;
    if unsafe { libc::geteuid() } != 0 {
        return Err("upgrade_requires_root_on_server".into());
    }
    let current = crate::setup_apply::Owner::resolve(&owner.name)?;
    if serde_json::to_vec(&current).map_err(|_| "upgrade_owner_invalid")?
        != serde_json::to_vec(&owner).map_err(|_| "upgrade_owner_invalid")?
        || !owner.can_write_home()?
    {
        return Err("upgrade_owner_changed".into());
    }
    let path = PathBuf::from("/var/lib/readb-setup");
    let recorded = setup_upgrade::recorded_status(&path)?;
    let candidate = hash(binary);
    let rollback = setup_upgrade::recorded_rollback(&path)?;
    if rollback == Some(false) {
        return Err("upgrade_rollback_pending: use exact setup rollback --recover".into());
    }
    let same = rollback != Some(true)
        && recorded
            .as_ref()
            .is_some_and(|(p, _, _)| p.new_image() == candidate);
    if same && recorded.as_ref().is_some_and(|(_, p, _)| p.is_some()) && !recover {
        return Err("upgrade_cleanup_unknown: rerun exact setup upgrade with --recover".into());
    }
    let old_bytes = if same {
        crate::network_install::inspect_release(
            Path::new("/"),
            recorded.as_ref().unwrap().0.old_image(),
        )?
    } else {
        crate::network_install::inspect_installed(Path::new("/"))?
            .binary()
            .to_vec()
    };
    let (receipt, baseline) =
        match crate::setup_provider::inspect_managed_baseline(&policy, options.listen_port) {
            Ok(v) => v,
            Err(_) => {
                // Strict saved/live matching excludes no peers. Only the empty
                // bootstrap uses this fallback; root admission proves service state.
                let r = crate::setup_provider::inspect(&policy, options.listen_port)?;
                let mut kernel = crate::network_runtime::LinuxKernel::new()?;
                (r, kernel.snapshot(&policy)?)
            }
        };
    let old = crate::setup_apply::bind_with_install_dir(
        options.clone(),
        owner.clone(),
        policy.clone(),
        baseline.clone(),
        &old_bytes,
        install_dir.clone(),
    )?;
    let new = crate::setup_apply::bind_with_install_dir(
        options,
        owner.clone(),
        policy,
        baseline,
        binary,
        install_dir,
    )?;
    let provider = hash(
        &serde_json::to_vec(&(&receipt, &new.baseline_sha256))
            .map_err(|_| "upgrade_provider_encoding_failed")?,
    );
    let new_user = crate::service::plan_for_binary(&owner.home, &new.install_dir, true, binary)?;
    let old_user =
        crate::service::plan_for_binary(&owner.home, &new.install_dir, true, &old_bytes)?;
    let config = if same {
        recorded
            .as_ref()
            .unwrap()
            .0
            .empty_config()
            .ok_or("upgrade_empty_config_binding_missing")?
            .to_owned()
    } else {
        let args = vec![
            "--local".into(),
            "--state-dir".into(),
            new_user.state.clone(),
            "--json".into(),
            "maintenance".into(),
            "inspect-empty".into(),
            "--file".into(),
            new_user.config.clone(),
        ];
        crate::setup_user::value_for(&owner, &args)?["config_fingerprint"]
            .as_str()
            .ok_or("upgrade_empty_config_unknown")?
            .to_owned()
    };
    let plan = setup_upgrade::Plan::new(&old, &new, &old_bytes, binary, &provider)?
        .for_empty_config(&config)?;
    if same && recorded.as_ref().unwrap().0.identity() != plan.identity() {
        return Err("upgrade_recovery_contract_changed: preserve original operation".into());
    }
    let mut adapter = Adapter {
        old_image: hash(&old_bytes),
        new_image: candidate,
        old,
        new,
        old_user,
        new_user,
        binary,
        provider: provider.clone(),
        tag: plan.identity(),
        config,
        original: vec![],
        journal_path: path.clone(),
        phase: 0,
        pending: None,
        release_intent: false,
    };
    if inspect {
        if same {
            if recorded.as_ref().unwrap().2 != setup_upgrade::ACTIONS.len() {
                return Err(
                    "upgrade_recorded_operation_incomplete: inspect phase and use exact --recover"
                        .into(),
                );
            }
            let proof = crate::setup_journal::inspect_completed(
                &path,
                &adapter.new.plan_sha256,
                &provider,
            )?;
            adapter.new_ready()?;
            return Ok(
                json!({"read_only":true,"already_current":true,"original_setup_sha256":proof.sha256(),"root_image":adapter.new_image}),
            );
        }
        let proof =
            crate::setup_journal::inspect_completed(&path, &adapter.old.plan_sha256, &provider)?;
        adapter.initial_admission()?;
        return Ok(
            json!({"read_only":true,"admitted":true,"original_setup_sha256":proof.sha256(),"old_plan_sha256":adapter.old.plan_sha256,"new_plan_sha256":adapter.new.plan_sha256,"upgrade_sha256":plan.identity(),"devices_migrated":false}),
        );
    }
    let mut journal = if same {
        Journal::open(&path, &plan)?
    } else {
        let proof =
            crate::setup_journal::inspect_completed(&path, &adapter.old.plan_sha256, &provider)?;
        adapter.initial_admission()?;
        Journal::begin(proof, plan)?
    };
    adapter.original = journal.original_setup().to_vec();
    adapter.thaw_interrupted_unpublished(&journal)?;
    setup_upgrade::run(&mut journal, &mut adapter, recover)?;
    Ok(
        json!({"upgraded":true,"plan_sha256":adapter.new.plan_sha256,"root_image":adapter.new_image,"coordinator_active":true,"network_verified":true,"devices_migrated":false,"legacy_services_retained":true,"note":"Empty staging software only. Device handover and acceptance remain separate."}),
    )
}
/// Directory durability only. Does not reopen cached admission or delete a file.
pub fn confirm_released(state: &Path, upgrade: &str, config: &str) -> Res<Value> {
    crate::maintenance::Store::open(state)?
        .confirm_removed(&crate::maintenance::Marker::new(upgrade, config)?)?;
    Ok(json!({"absence_durable":true,"runtime_admission_changed":false}))
}

/// Inspect a selected-user target from its private hash-named release. Root
/// provides the expected image digest; caller-controlled bytes grant no authority.
pub fn inspect_install(home: &Path, prefix: &Path, image: &Path, expected: &str) -> Res<Value> {
    let bytes = crate::user_install::read_owned(image, 64 * 1024 * 1024)?
        .ok_or("rollback_target_image_missing")?;
    if hash(&bytes) != expected {
        return Err("rollback_target_image_changed".into());
    }
    let plan = crate::service::plan_for_binary(home, prefix, true, &bytes)?;
    if Path::new(&plan.binary) != image {
        return Err("rollback_target_image_path_changed".into());
    }
    crate::service::inspect_for_binary(&plan, home, &bytes)
}
/// Runtime lock + existing empty binding, not a systemd PID observation, protect
/// offline marker changes against an independently launched coordinator.
pub fn quiet_marker(
    state: &Path,
    file: &Path,
    upgrade: &str,
    config: &str,
    release: bool,
) -> Res<Value> {
    let _runtime = crate::catalog::existing_runtime_lock(state, file)?;
    let (_, pin) = load_empty(state, file)?;
    if pin != config {
        return Err("rollback_empty_config_changed".into());
    }
    let marker = crate::maintenance::Marker::new(upgrade, config)?;
    let mut store = crate::maintenance::Store::open(state)?;
    if release {
        match store.load(config)? {
            Some(m) if m == marker => store.remove(&marker)?,
            None => store.confirm_removed(&marker)?,
            _ => return Err("rollback_marker_owner_changed".into()),
        }
    } else {
        store.publish(&marker)?;
    }
    let (_, fresh) = load_empty(state, file)?;
    if fresh != pin {
        return Err("rollback_config_changed: marker evidence retained".into());
    }
    Ok(json!({"quiet":true,"released":release}))
}

use crate::setup_upgrade::{RollbackAction as UndoAction, RollbackActions};
struct Rollback<'a> {
    a: Adapter<'a>,
    old_bytes: &'a [u8],
    phase: usize,
    pending: Option<UndoAction>,
    forward_root: bool,
    forward_user: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Files {
    Old,
    New,
    ForwardPending,
    RollbackPending,
}
impl Rollback<'_> {
    fn files(&self, new: bool) -> Res<Value> {
        let p = if new {
            &self.a.new_user
        } else {
            &self.a.old_user
        };
        self.a.local(&[
            "maintenance",
            "inspect-install",
            "--prefix",
            self.a
                .new
                .install_dir
                .to_str()
                .ok_or("rollback_path_invalid")?,
            "--image",
            &p.binary,
            "--sha",
            if new {
                &self.a.new_image
            } else {
                &self.a.old_image
            },
        ])
    }
    fn root_state(&self) -> Res<Files> {
        if self.a.root_files(false).is_ok() {
            return Ok(Files::Old);
        }
        if self.a.root_files(true).is_ok() {
            return Ok(Files::New);
        }
        self.a.helper_quiet()?;
        if self.forward_root
            && crate::network_install::inspect_upgrade_state(
                Path::new("/"),
                &self.a.old.policy,
                &self.a.old.root_install,
                &self.a.new.root_install,
            ) == Ok(crate::network_install::UpgradeFiles::Pending)
        {
            return Ok(Files::ForwardPending);
        }
        if self.pending == Some(UndoAction::RootFiles)
            && crate::network_install::inspect_upgrade_state(
                Path::new("/"),
                &self.a.old.policy,
                &self.a.new.root_install,
                &self.a.old.root_install,
            ) == Ok(crate::network_install::UpgradeFiles::Pending)
        {
            return Ok(Files::RollbackPending);
        }
        Err("rollback_root_files_unknown: preserve unrelated intent or edit".into())
    }
    fn user_state(&self) -> Res<Files> {
        if self.files(false).is_ok_and(|s| s["state"] == "ready") {
            return Ok(Files::Old);
        }
        if self.files(true).is_ok_and(|s| s["state"] == "ready") {
            return Ok(Files::New);
        }
        if self.forward_user && self.files(true).is_ok_and(|s| s["state"] == "pending") {
            return Ok(Files::ForwardPending);
        }
        if self.pending == Some(UndoAction::UserFiles)
            && self.files(false).is_ok_and(|s| s["state"] == "pending")
        {
            return Ok(Files::RollbackPending);
        }
        Err("rollback_user_files_unknown: preserve unrelated intent or edit".into())
    }
    fn user_identity(&self, m: &BTreeMap<String, String>) -> Res<(bool, String)> {
        match self.a.user_process(false, m) {
            Ok(p) => Ok((false, p)),
            Err(_) => self.a.user_process(true, m).map(|p| (true, p)),
        }
    }
    fn helper_identity(&self) -> Res<bool> {
        let m = self.a.helper_unit(true)?;
        if crate::setup_systemd::quiet(&m, "readb-network.service") {
            return Ok(false);
        }
        match self.a.helper_process(false, &m) {
            Ok(_) => self.a.healthy_helper(false)?,
            Err(_) => self.a.healthy_helper(true)?,
        }
        Ok(true)
    }
    fn provider(&self) -> Res<()> {
        let receipt = match crate::setup_provider::inspect_managed_baseline(
            &self.a.old.policy,
            self.a.old.options.listen_port,
        )
        .or_else(|_| {
            crate::setup_provider::inspect_legacy_baseline(
                &self.a.old.policy,
                self.a.old.options.listen_port,
            )
        }) {
            Ok((r, b)) => {
                if hash(&serde_json::to_vec(&b).map_err(|_| "rollback_baseline_invalid")?)
                    != self.a.old.baseline_sha256
                {
                    return Err("rollback_external_baseline_changed".into());
                }
                r
            }
            Err(_) => {
                crate::setup_provider::inspect(&self.a.old.policy, self.a.old.options.listen_port)?
            }
        };
        if hash(
            &serde_json::to_vec(&(&receipt, &self.a.old.baseline_sha256))
                .map_err(|_| "rollback_provider_invalid")?,
        ) != self.a.provider
        {
            return Err("rollback_original_provider_changed".into());
        }
        Ok(())
    }
    fn marker(&self) -> Res<Value> {
        Ok(self
            .a
            .local(&["maintenance", "inspect-marker", "--config", &self.a.config])?["maintenance"]
            .clone())
    }
    fn quiet_marker(&self, release: bool) -> Res<()> {
        self.a.user_quiet()?;
        let mut args = vec![
            "maintenance",
            "quiet-marker",
            "--file",
            &self.a.old_user.config,
            "--upgrade",
            &self.a.tag,
            "--config",
            &self.a.config,
        ];
        if release {
            args.push("--release");
        }
        self.a.local(&args)?;
        Ok(())
    }
    fn old_ready(&self) -> Res<()> {
        if self.root_state() != Ok(Files::Old) || self.user_state() != Ok(Files::Old) {
            return Err("rollback_original_files_not_ready".into());
        }
        self.a.healthy_helper(false)?;
        let m = self.a.user_unit()?;
        self.a.user_process(false, &m)?;
        let status = self.a.doctor()?;
        if status["pid"] != crate::setup_systemd::pid(&m)?
            || status["catalog_cleanup_unknown"] != false
            || status.get("maintenance").is_some_and(|m| !m.is_null())
        {
            return Err("rollback_original_coordinator_not_ready".into());
        }
        if !self.marker()?.is_null() {
            return Err("rollback_original_coordinator_marker_present".into());
        }
        self.provider()
    }
    fn obs(&self, a: UndoAction, ready: bool, detail: &str) -> Observation {
        Observation {
            fingerprint: hash(format!("{}:rollback:{a:?}:{detail}", self.a.tag).as_bytes()),
            ready,
            retry_safe: true,
        }
    }
    fn maintenance(&mut self) -> Res<()> {
        let m = self.a.user_unit()?;
        if crate::setup_systemd::quiet(&m, "readb.service") {
            return self.quiet_marker(false);
        }
        let (new, before) = self.user_identity(&m)?;
        if new {
            self.a.local(&[
                "maintenance",
                "prepare",
                "--upgrade",
                &self.a.tag,
                "--config",
                &self.a.config,
            ])?;
        } else if m.get("FreezerState").map(String::as_str) == Some("frozen") {
            self.a.bootstrap(&m)?;
        } else {
            self.a.local(&["service", "freeze"])?;
            let result = (|| -> Res<()> {
                let frozen = self.a.user_unit()?;
                if self.a.user_process(false, &frozen)? != before {
                    return Err("rollback_frozen_generation_changed".into());
                }
                self.a.config()?;
                self.a.bootstrap(&frozen)
            })();
            if let Err(error) = result {
                if let Ok(frozen) = self.a.user_unit()
                    && self
                        .a
                        .user_process(false, &frozen)
                        .is_ok_and(|p| p == before)
                    && self.marker().is_ok_and(|m| m.is_null())
                {
                    self.a.local(&["service", "thaw"]).map_err(|e| {
                        format!("rollback_thaw_unconfirmed: {e}; original error: {error}")
                    })?;
                }
                return Err(error);
            }
        }
        Ok(())
    }
    fn thaw_unpublished(&self, j: &Journal) -> Res<()> {
        if j.rollback_pending() != Some(UndoAction::Maintenance) {
            return Ok(());
        }
        let m = self.a.user_unit()?;
        if m.get("FreezerState").map(String::as_str) != Some("frozen") {
            return Ok(());
        }
        let p = self.a.user_process(false, &m)?;
        if j.rollback_before()
            != Some(
                self.obs(UndoAction::Maintenance, false, &p)
                    .fingerprint
                    .as_str(),
            )
        {
            return Err("rollback_frozen_generation_unknown: no thaw attempted".into());
        }
        if self.marker()?.is_null() && self.a.config().is_err() {
            self.a.local(&["service", "thaw"])?;
            return Err(
                "rollback_empty_catalog_changed: exact original unit thawed; pending retained"
                    .into(),
            );
        }
        Ok(())
    }
    fn wait(&mut self, a: UndoAction) -> Res<()> {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(25);
        loop {
            if self.inspect(a).is_ok_and(|v| v.ready) {
                return Ok(());
            }
            if std::time::Instant::now() >= until {
                return Err(
                    "rollback_service_readiness_unconfirmed: pending phase retained".into(),
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
        }
    }
}
impl RollbackActions for Rollback<'_> {
    fn admit(&mut self, j: &Journal) -> Res<()> {
        self.phase = j.rollback_count().ok_or("rollback_not_admitted")?;
        self.pending = j.rollback_pending();
        // This is the sole reopening boundary. Never stop or force idle a
        // released original process after the final start acknowledgement is lost.
        if (self.phase >= 8 || (self.phase == 7 && self.pending == Some(UndoAction::Release)))
            && self.old_ready().is_ok()
        {
            return Ok(());
        }
        self.a.config()?;
        self.provider()?;
        let root = self.root_state()?;
        let user = self.user_state()?;
        if self.phase > 3 && root != Files::Old {
            return Err("rollback_restored_root_files_changed".into());
        }
        if self.phase > 4 && user != Files::Old {
            return Err("rollback_restored_user_files_changed".into());
        }
        let m = self.a.user_unit()?;
        let quiet = crate::setup_systemd::quiet(&m, "readb.service");
        if self.phase < 2 {
            if !quiet {
                self.user_identity(&m)?;
                if self.phase == 1 && !self.a.barrier(&m)? {
                    return Err("rollback_barrier_not_confirmed".into());
                }
            }
        } else if self.phase < 8 {
            self.a.user_quiet()?;
        }
        if (3..5).contains(&self.phase) {
            self.a.helper_quiet()?;
        } else if self.phase >= 6 {
            self.a.healthy_helper(false)?;
        } else {
            self.helper_identity()?;
        }
        if self.phase > 0
            && self.phase < 8
            && self.marker()? != self.a.expected_marker()?
            && !(self.phase == 7
                && self.pending == Some(UndoAction::Release)
                && self.marker()?.is_null())
        {
            return Err("rollback_exact_marker_required".into());
        }
        if self.phase == 8 {
            self.a.user_quiet()?;
            if !self.marker()?.is_null() {
                return Err("rollback_release_not_confirmed".into());
            }
        }
        Ok(())
    }
    fn inspect(&mut self, a: UndoAction) -> Res<Observation> {
        match a {
            UndoAction::Maintenance => {
                let m = self.a.user_unit()?;
                if crate::setup_systemd::quiet(&m, "readb.service") {
                    return Ok(self.obs(a, self.marker()? == self.a.expected_marker()?, "quiet"));
                }
                let (_, p) = self.user_identity(&m)?;
                let ready = self.a.barrier(&m)?;
                if !ready {
                    let disk = self.marker()?;
                    if !disk.is_null() {
                        return Err("rollback_other_maintenance_preserved".into());
                    }
                    if m.get("FreezerState").map(String::as_str) != Some("frozen") {
                        let (_, config) = load_empty_as_selected(&self.a)?;
                        admit_empty(&self.a.doctor()?, &config)?;
                    }
                }
                Ok(self.obs(a, ready, &p))
            }
            UndoAction::StopUser => {
                let m = self.a.user_unit()?;
                let quiet = crate::setup_systemd::quiet(&m, "readb.service");
                let detail = if quiet {
                    "quiet".into()
                } else {
                    let (_, p) = self.user_identity(&m)?;
                    if !self.a.barrier(&m)? {
                        return Err("rollback_user_barrier_missing".into());
                    }
                    p
                };
                Ok(self.obs(a, quiet, &detail))
            }
            UndoAction::StopHelper => {
                let m = self.a.helper_unit(true)?;
                let quiet = crate::setup_systemd::quiet(&m, "readb-network.service");
                let detail = if quiet {
                    "quiet".into()
                } else {
                    self.a
                        .helper_process(false, &m)
                        .or_else(|_| self.a.helper_process(true, &m))?
                };
                Ok(self.obs(a, quiet, &detail))
            }
            UndoAction::RootFiles => {
                Ok(self.obs(a, self.root_state()? == Files::Old, "exact-file-transition"))
            }
            UndoAction::UserFiles => {
                Ok(self.obs(a, self.user_state()? == Files::Old, "exact-file-transition"))
            }
            UndoAction::StartHelper => {
                let m = self.a.helper_unit(true)?;
                let ready = crate::setup_systemd::running(&m);
                if ready {
                    self.a.healthy_helper(false)?;
                } else if !crate::setup_systemd::quiet(&m, "readb-network.service") {
                    return Err("rollback_helper_transition_unknown".into());
                }
                Ok(self.obs(a, ready, "original-helper"))
            }
            UndoAction::Binding => {
                let current = crate::setup_journal::snapshot(&self.a.journal_path)?;
                Ok(self.obs(a, current == self.a.original, "original-binding"))
            }
            UndoAction::Release => {
                // A saved release intent can outlive a subsequent start by the
                // boot manager. Acknowledge the exact released old process; do
                // not stop its later jobs or require its catalog still empty.
                if self.phase == 7 && self.pending == Some(a) && self.old_ready().is_ok() {
                    return Ok(self.obs(a, true, "owned-marker-release"));
                }
                self.a.user_quiet()?;
                let m = self.marker()?;
                if !m.is_null() && m != self.a.expected_marker()? {
                    return Err("rollback_marker_owner_changed".into());
                }
                Ok(self.obs(a, m.is_null(), "owned-marker-release"))
            }
            UndoAction::StartUser => {
                let m = self.a.user_unit()?;
                let ready = crate::setup_systemd::running(&m);
                if ready {
                    self.old_ready()?;
                } else {
                    self.a.user_quiet()?;
                }
                Ok(self.obs(a, ready, "original-coordinator"))
            }
        }
    }
    fn apply(&mut self, a: UndoAction, j: &mut Journal, recover: bool) -> Res<()> {
        match a {
            UndoAction::Maintenance => self.maintenance()?,
            UndoAction::StopUser => {
                self.a.local(&["service", "stop"])?;
                self.wait(a)?;
            }
            UndoAction::StopHelper => {
                crate::setup_systemd::ctl(&["stop", "readb-network.service"])?;
                self.wait(a)?;
            }
            UndoAction::RootFiles => {
                let state = self.root_state()?;
                let mut i = crate::network_install::Installer::open(Path::new("/"))?;
                if matches!(state, Files::ForwardPending | Files::RollbackPending) {
                    if state == Files::RollbackPending && !recover {
                        return Err("rollback_root_files_require_recovery".into());
                    }
                    let p = if state == Files::ForwardPending {
                        &self.a.new.root_install
                    } else {
                        &self.a.old.root_install
                    };
                    i.recover_setup_pending(&self.a.old.policy, p)?;
                }
                i.install(self.a.old.root_install.clone(), self.old_bytes)?;
                i.verify_setup_files(&self.a.old.policy, &self.a.old.root_install)?;
            }
            UndoAction::UserFiles => {
                let state = self.user_state()?;
                if state == Files::ForwardPending {
                    crate::setup_user::install_image(
                        &self.a.old.owner,
                        &self.a.old.install_dir,
                        true,
                        self.a.binary,
                    )?;
                }
                if state == Files::RollbackPending && !recover {
                    return Err("rollback_user_files_require_recovery".into());
                }
                crate::setup_user::install_image(
                    &self.a.old.owner,
                    &self.a.old.install_dir,
                    state == Files::RollbackPending,
                    self.old_bytes,
                )?;
            }
            UndoAction::StartHelper => {
                crate::setup_systemd::ctl(&["daemon-reload"])?;
                crate::setup_systemd::ctl(&["start", "readb-network.service"])?;
                self.wait(a)?;
            }
            UndoAction::Binding => j.publish_original_binding()?,
            UndoAction::Release => {
                self.pending = Some(a);
                self.quiet_marker(true)?;
            }
            UndoAction::StartUser => {
                if j.rollback_pending() != Some(a) || j.rollback_count() != Some(a.index()) {
                    return Err("rollback_final_start_intent_required".into());
                }
                self.a.local(&["service", "start"])?;
                self.wait(a)?;
            }
        }
        Ok(())
    }
    fn confirm(&mut self, a: UndoAction, _j: &Journal) -> Res<()> {
        match a {
            UndoAction::Maintenance => self.maintenance()?,
            UndoAction::RootFiles => crate::network_install::Installer::open(Path::new("/"))?
                .verify_setup_files(&self.a.old.policy, &self.a.old.root_install)?,
            UndoAction::UserFiles => {
                self.a.user_quiet()?;
                crate::setup_user::install_image(
                    &self.a.old.owner,
                    &self.a.old.install_dir,
                    false,
                    self.old_bytes,
                )?;
            }
            UndoAction::Binding => { /* Root journal publishes and fsyncs the exact original bytes. */
            }
            UndoAction::Release => {
                if self.phase == 7 && self.pending == Some(a) && self.old_ready().is_ok() {
                    self.a.local(&[
                        "maintenance",
                        "confirm-released",
                        "--upgrade",
                        &self.a.tag,
                        "--config",
                        &self.a.config,
                    ])?;
                } else {
                    self.quiet_marker(true)?;
                }
            }
            UndoAction::StartUser => {
                self.old_ready()?;
                self.a.local(&[
                    "maintenance",
                    "confirm-released",
                    "--upgrade",
                    &self.a.tag,
                    "--config",
                    &self.a.config,
                ])?;
            }
            _ => (),
        }
        Ok(())
    }
}
/// Rollback only the exact retained empty upgrade. New code orchestrates while
/// both target installers execute their sealed, independently pinned images.
pub struct RollbackOptions<'a> {
    pub recover: bool,
    pub inspect: bool,
    pub upgrade_image: Option<&'a Path>,
}
pub fn rollback(
    options: crate::setup::Options,
    owner: crate::setup_apply::Owner,
    policy: crate::network::Policy,
    install_dir: PathBuf,
    binary: &[u8],
    flags: RollbackOptions<'_>,
) -> Res<Value> {
    let RollbackOptions {
        recover,
        inspect,
        upgrade_image,
    } = flags;
    use crate::network::Kernel;
    if unsafe { libc::geteuid() } != 0 {
        return Err("rollback_requires_root_on_server".into());
    }
    let current = crate::setup_apply::Owner::resolve(&owner.name)?;
    if serde_json::to_vec(&current).map_err(|_| "rollback_owner_invalid")?
        != serde_json::to_vec(&owner).map_err(|_| "rollback_owner_invalid")?
        || !owner.can_write_home()?
    {
        return Err("rollback_owner_changed".into());
    }
    let path = PathBuf::from("/var/lib/readb-setup");
    let (recorded, forward_pending, _) =
        setup_upgrade::recorded_status(&path)?.ok_or("rollback_no_recorded_upgrade")?;
    let old_bytes = crate::network_install::inspect_release(Path::new("/"), recorded.old_image())?;
    let provided = upgrade_image
        .map(|p| crate::network_install::inspect_candidate(Path::new("/"), p, recorded.new_image()))
        .transpose()?;
    let new_bytes=match crate::network_install::inspect_release(Path::new("/"),recorded.new_image()) {
        Ok(bytes)=>bytes,
        Err(e) if e=="network_install_release_missing"=>provided.ok_or("rollback_candidate_not_retained: supply --upgrade-image with protected recorded candidate bytes")?,
        Err(e)=>return Err(e),
    };
    let (receipt, baseline) = match crate::setup_provider::inspect_managed_baseline(
        &policy,
        options.listen_port,
    )
    .or_else(|_| crate::setup_provider::inspect_legacy_baseline(&policy, options.listen_port))
    {
        Ok(v) => v,
        Err(_) => {
            let r = crate::setup_provider::inspect(&policy, options.listen_port)?;
            let mut k = crate::network_runtime::LinuxKernel::new()?;
            (r, k.snapshot(&policy)?)
        }
    };
    let old = crate::setup_apply::bind_with_install_dir(
        options.clone(),
        owner.clone(),
        policy.clone(),
        baseline.clone(),
        &old_bytes,
        install_dir.clone(),
    )?;
    let new = crate::setup_apply::bind_with_install_dir(
        options,
        owner.clone(),
        policy,
        baseline,
        &new_bytes,
        install_dir,
    )?;
    let provider = hash(
        &serde_json::to_vec(&(&receipt, &new.baseline_sha256))
            .map_err(|_| "rollback_provider_invalid")?,
    );
    let config = recorded
        .empty_config()
        .ok_or("rollback_empty_config_binding_required")?
        .to_owned();
    let plan = setup_upgrade::Plan::new(&old, &new, &old_bytes, &new_bytes, &provider)?
        .for_empty_config(&config)?;
    if plan.identity() != recorded.identity() {
        return Err("rollback_original_contract_changed".into());
    }
    let old_user =
        crate::service::plan_for_binary(&owner.home, &old.install_dir, true, &old_bytes)?;
    let new_user =
        crate::service::plan_for_binary(&owner.home, &new.install_dir, true, &new_bytes)?;
    let a = Adapter {
        old,
        new,
        old_user,
        new_user,
        old_image: hash(&old_bytes),
        new_image: hash(&new_bytes),
        binary: &new_bytes,
        provider,
        tag: plan.identity(),
        config,
        original: vec![],
        journal_path: path.clone(),
        phase: 0,
        pending: None,
        release_intent: false,
    };
    let mut undo = Rollback {
        a,
        old_bytes: &old_bytes,
        phase: 0,
        pending: None,
        forward_root: forward_pending == Some(Action::RootFiles),
        forward_user: forward_pending == Some(Action::UserFiles),
    };
    if inspect {
        let setup_upgrade::RecordInspection {
            original,
            count,
            pending,
            complete,
        } = setup_upgrade::inspect_record(&path, &plan)?;
        undo.a.original = original;
        undo.phase = count.unwrap_or(0);
        undo.pending = pending;
        if complete {
            undo.old_ready()?;
        } else {
            undo.a.config()?;
            undo.root_state()?;
            undo.user_state()?;
            undo.helper_identity()?;
            let m = undo.a.user_unit()?;
            if !crate::setup_systemd::quiet(&m, "readb.service") {
                undo.user_identity(&m)?;
            }
            undo.provider()?;
        }
        return Ok(
            json!({"read_only":true,"rollback_admitted":true,"original_image":recorded.old_image(),"upgrade_sha256":plan.identity()}),
        );
    }
    let mut journal = Journal::open(&path, &plan)?;
    undo.a.original = journal.original_setup().to_vec();
    // Admission before first intent; a prior pending operation still needs an
    // explicit matching recovery and never gets silently replaced.
    if journal.rollback_count().is_none() {
        undo.a.config()?;
        undo.root_state()?;
        undo.user_state()?;
        undo.helper_identity()?;
    }
    journal.begin_rollback(&hash(binary))?;
    undo.thaw_unpublished(&journal)?;
    setup_upgrade::run_rollback(&mut journal, &mut undo, recover)?;
    Ok(
        json!({"rolled_back":true,"original_image":recorded.old_image(),"upgrade_sha256":plan.identity(),"legacy_services_retained":true,"devices_migrated":false}),
    )
}
