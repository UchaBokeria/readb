use crate::{policy::*, runner::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub fn lease_now() -> f64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64()
}
pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
pub fn atomic(path: &Path, value: &impl serde::Serialize) -> Res<()> {
    let tmp = path.with_extension(format!("tmp-{}", random()));
    let bytes = serde_json::to_vec(value).map_err(|_| "state_serialize_failed")?;
    let r = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| "state_create_failed")?;
        f.write_all(&bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "state_write_failed")?;
        fs::rename(&tmp, path).map_err(|_| "state_rename_failed")?;
        fs::File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|_| "state_directory_sync_failed")?;
        Ok(())
    })();
    if r.is_err() {
        let _ = fs::remove_file(tmp);
    }
    r
}
#[derive(Clone)]
pub struct Config {
    pub peer: std::net::Ipv4Addr,
    pub adb_port: u16,
    pub kind: crate::schema::Kind,
    pub keepalive: crate::schema::Keepalive,
    pub dir: PathBuf,
    pub adb: PathBuf,
    pub token: String,
    pub identity: String,
    pub recipient: String,
}
pub struct Operation {
    pub pairing: bool,
    pub network: bool,
    pub id: String,
    pub command: String,
    pub observer: bool,
}
pub struct Viewer {
    pub owner: Owner,
    pub expires: f64,
    pub ttl: u64,
    pub active: bool,
}
pub struct State {
    pub report_cursor: readb_protocol::Cursor,
    pub companion: Option<(f64, readb_protocol::Report)>,
    pub viewers: std::collections::HashMap<String, Viewer>,
    pub operations: std::collections::HashMap<String, Operation>,
    pub keepalive: crate::schema::Keepalive,

    pub paused: bool,
    pub stopping: bool,
    pub maintenance: bool,
    pub(crate) enrollment: Option<String>,
    pub gate: Gate,
    pub receipt: Receipt,
    pub target: Option<u16>,
    pub generation: u64,
    pub last_attempt: Option<f64>,
}
pub struct Backend {
    pub config: Config,
    pub state: Mutex<State>,
    transport: Mutex<()>,
    identity: Mutex<String>,
    managed_server: std::sync::atomic::AtomicBool,
    server_closed: std::sync::atomic::AtomicBool,
    enrollment_closed: std::sync::atomic::AtomicBool,
    server: Mutex<Option<crate::adb_server::ManagedServer>>,
}
pub struct Prepared {
    pub pairing: bool,
    pub command: Command,
    pub generation: u64,
    pub pure: bool,
}
impl Backend {
    pub fn new(config: Config) -> Res<Self> {
        Self::prepare_key_home(&config)?;
        let mut gate = Gate::new();
        for p in ["cleanup-unknown.json", "active-operation.json"] {
            if config.dir.join(p).exists() {
                gate.cleanup_unknown =
                    Some("restart requires reconciliation of previous device work".into());
            }
        }
        if fs::read_dir(&config.dir)
            .map_err(|_| "private_state_unavailable")?
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().starts_with("active-view-"))
        {
            gate.cleanup_unknown =
                Some("restart requires reconciliation of previous viewer work".into());
        }
        let policy_file = config.dir.join("policy.json");
        let keepalive = if policy_file.exists() {
            let b = fs::read(policy_file).map_err(|_| "keepalive_policy_unavailable")?;
            if b.len() > 4096 {
                return Err("invalid_keepalive_policy".into());
            }
            serde_json::from_slice(&b).map_err(|_| "invalid_keepalive_policy")?
        } else {
            config.keepalive.clone()
        };
        let cursor_path = config.dir.join("report-cursor.json");
        let report_cursor = if cursor_path.exists() {
            readb_protocol::Cursor::parse(
                &fs::read(cursor_path).map_err(|_| "report_cursor_unavailable")?,
            )?
        } else {
            Default::default()
        };
        let paused = if config.dir.join("connection.json").exists() {
            let b = fs::read(config.dir.join("connection.json"))
                .map_err(|_| "connection_policy_unavailable")?;
            if b.len() > 128 {
                return Err("invalid_connection_policy".into());
            }
            serde_json::from_slice::<bool>(&b).map_err(|_| "invalid_connection_policy")?
        } else {
            false
        };
        let enrollment = crate::enrollment_journal::barrier(&config.dir)?;
        let enrollment_closed = enrollment.is_some();
        Ok(Self {
            identity: Mutex::new(config.identity.clone()),
            config,
            state: Mutex::new(State {
                report_cursor,
                companion: None,
                viewers: Default::default(),
                operations: Default::default(),
                keepalive,
                paused,
                stopping: false,
                maintenance: false,
                enrollment,
                gate,
                receipt: Receipt::default(),
                target: None,
                generation: 0,
                last_attempt: None,
            }),
            transport: Mutex::new(()),
            managed_server: std::sync::atomic::AtomicBool::new(false),
            server_closed: std::sync::atomic::AtomicBool::new(false),
            enrollment_closed: std::sync::atomic::AtomicBool::new(enrollment_closed),
            server: Mutex::new(None),
        })
    }
    fn lifecycle_admission(s: &mut State, ticket: &str) -> Res<()> {
        Self::check_running(s)?;
        s.gate.authorize(ticket, lease_now())?;
        if s.gate.cleanup_unknown.is_some() || s.gate.active || s.viewers.values().any(|v| v.active)
        {
            return Err("device_operation_busy_or_cleanup_unknown".into());
        }
        Ok(())
    }
    pub fn probe_identity(&self, ticket: &str, port: u16) -> Res<Value> {
        if port < 1024 {
            return Err("invalid_connect_port".into());
        }
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::lifecycle_admission(&mut s, ticket)?;
        if !self.identity.lock().unwrap().is_empty() {
            return Err(
                "identity_already_configured: changed identities need separate recovery".into(),
            );
        }
        let target = format!("{}:{port}", self.config.peer);
        let result = (|| -> Res<String> {
            let connection = self.adb(&["connect", &target])?;
            let text = String::from_utf8_lossy(&connection.out);
            if !connection.ok
                || !(text.contains(&format!("connected to {target}"))
                    || text.contains(&format!("already connected to {target}")))
            {
                return Err("secure_adb_connect_failed: finish pairing first".into());
            }
            let serial = self.adb(&["-s", &target, "shell", "getprop", "ro.serialno"])?;
            if !serial.ok {
                return Err("device_identity_read_failed".into());
            }
            let serial = String::from_utf8(serial.out).map_err(|_| "invalid_device_identity")?;
            let serial = serial.trim();
            if serial.is_empty() || serial.len() > 256 || serial.chars().any(char::is_control) {
                return Err("invalid_device_identity".into());
            }
            Ok(Sha256::digest(serial.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect())
        })();
        self.disconnect(&target)?;
        let pin = result?;
        atomic(
            &self.config.dir.join("identity-review.json"),
            &json!({"fingerprint":pin,"checked_at":now(),"job_proof":Sha256::digest(ticket.as_bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>()}),
        )?;
        Ok(
            json!({"fingerprint":pin,"trusted":false,"next":"Verify this device, then readb device trust --fingerprint SHA256 --yes with the same controller ticket. No normal device command is enabled."}),
        )
    }
    pub fn trust_identity(
        &self,
        ticket: &str,
        pin: &str,
        persist: impl FnOnce() -> Res<()>,
    ) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::lifecycle_admission(&mut s, ticket)?;
        let mut identity = self.identity.lock().unwrap();
        if !identity.is_empty() {
            return Err("identity_already_configured".into());
        }
        if pin.len() != 64
            || !pin
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid_identity_fingerprint".into());
        }
        let bytes = fs::read(self.config.dir.join("identity-review.json"))
            .map_err(|_| "review_identity_first: run device connect --port PORT")?;
        if bytes.len() > 1024 {
            return Err("invalid_identity_review".into());
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_identity_review")?;
        if !v["checked_at"]
            .as_f64()
            .is_some_and(|t| (0.0..=120.).contains(&(now() - t)))
            || !v["fingerprint"].as_str().is_some_and(|p| equal(p, pin))
            || !v["job_proof"].as_str().is_some_and(|proof| {
                equal(
                    proof,
                    &Sha256::digest(ticket.as_bytes())
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                )
            })
        {
            return Err("identity_review_mismatch_or_expired".into());
        }
        persist()?;
        *identity = pin.into();
        let _ = fs::remove_file(self.config.dir.join("identity-review.json"));
        Ok(())
    }
    pub fn connect_device(&self, ticket: &str, port: Option<u16>) -> Res<Value> {
        let selected = {
            let _transport = self.transport.lock().unwrap();
            let mut s = self.state.lock().unwrap();
            Self::lifecycle_admission(&mut s, ticket)?;
            self.ensure_owned_server(true)?;
            port.or_else(|| {
                ((0.0..=180.).contains(&(now() - s.receipt.received_at))).then_some(s.receipt.port)
            })
            .filter(|p| *p >= 1024)
            .ok_or("connect_port_unavailable: wait for companion report or pass --port")?
        };
        if self.identity.lock().unwrap().is_empty() {
            return self.probe_identity(ticket, selected);
        }
        let battery = self.state.lock().unwrap().receipt.battery;
        let connected = self.refresh_pinned(
            ticket,
            Report {
                port: selected,
                battery,
            },
        )?;
        if !connected {
            return Err("secure_adb_connect_or_identity_failed: inspect server, VPN, pairing and pinned identity; no device command started".into());
        }
        Ok(self.status())
    }
    pub fn disconnect_device(&self, ticket: &str) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::lifecycle_admission(&mut s, ticket)?;
        atomic(&self.config.dir.join("connection.json"), &true)?;
        s.paused = true;
        let target = s.target.take();
        s.receipt.connected = false;
        s.receipt.identity_verified = false;
        s.generation += 1;
        if let Some(port) = target {
            self.disconnect(&format!("{}:{port}", self.config.peer))?;
        }
        Ok(())
    }
    pub fn retire(&self, ticket: &str, persist: impl FnOnce() -> Res<()>) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        s.gate.authorize(ticket, lease_now())?;
        if s.gate.cleanup_unknown.is_some()
            || s.gate.active
            || s.viewers
                .values()
                .any(|v| v.active || v.expires > lease_now())
        {
            return Err(
                "device_in_use: release viewers and finish operations before removal".into(),
            );
        }
        persist()?;
        s.stopping = true;
        s.gate.cancel("device_removed");
        Ok(())
    }
    pub fn begin_shutdown(&self) -> Res<()> {
        self.server_closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut s = self.state.lock().unwrap();
        s.stopping = true;
        for v in s.viewers.values_mut() {
            v.expires = 0.;
        }
        s.gate.cancel("coordinator_shutdown");
        self.persist_fence(&s)
    }
    fn check_running(s: &State) -> Res<()> {
        if s.stopping {
            return Err("coordinator_shutdown".into());
        }
        if s.enrollment.is_some() {
            return Err(
                "enrollment_pending: recover original enrollment before device work".into(),
            );
        }
        if s.maintenance {
            return Err("coordinator_maintenance: upgrade pending".into());
        }
        Ok(())
    }
    fn network_active(s: &State) -> bool {
        s.operations.values().any(|op| op.network)
    }
    pub fn battery_sample(&self) -> crate::notifier::BatterySample {
        let s = self.state.lock().unwrap();
        if let Some((received, r)) = &s.companion {
            crate::notifier::BatterySample {
                received_at: *received,
                battery: r.battery,
                authenticated: true,
                enrolled: !self.identity.lock().unwrap().is_empty(),
            }
        } else if s.report_cursor.is_initialized() {
            crate::notifier::BatterySample {
                received_at: 0.,
                battery: -1,
                authenticated: false,
                enrolled: !self.identity.lock().unwrap().is_empty(),
            }
        } else {
            crate::notifier::BatterySample::from_receipt(&s.receipt, now())
        }
    }
    pub fn status(&self) -> Value {
        let mut s = self.state.lock().unwrap();
        s.gate.expire(lease_now());
        s.viewers.retain(|_, v| v.active || v.expires > lease_now());
        let server_state = if self
            .managed_server
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            match self.server.try_lock() {
                Ok(mut slot) => match slot.as_mut() {
                    None => "not_started",
                    Some(server) => match server.running() {
                        Ok(true) => "running",
                        Ok(false) => "exited",
                        Err(_) => "unknown",
                    },
                },
                Err(_) => "starting_or_stopping",
            }
        } else {
            "unmanaged_library"
        };
        let connected = s.enrollment.is_none()
            && s.receipt.fresh(now())
            && matches!(server_state, "running" | "unmanaged_library");
        let mut value = json!({"identity_configured":!self.identity.lock().unwrap().is_empty(),"enrollment_pending":s.enrollment.is_some(),"paused":s.paused,"stopping":s.stopping,"connected":connected,"identity_verified":connected,"adb_server_state":server_state,"report_age_seconds":if s.receipt.received_at>0.{Some(now()-s.receipt.received_at)}else{None},"battery":s.receipt.battery,"adb_server_port":self.config.adb_port,"viewers":s.viewers.values().map(|v|json!({"owner":v.owner,"active":v.active,"remaining_seconds":(v.expires-lease_now()).max(0.)})).collect::<Vec<_>>(),"keepalive_policy":s.keepalive,"job":s.gate.lease,"lease_age_seconds":s.gate.lease.as_ref().map(|l|(lease_now()-l.started).max(0.)),"lease_remaining_seconds":s.gate.lease.as_ref().map(|l|(l.expires-lease_now()).max(0.)),"operation_running":s.gate.active,"cleanup_unknown":s.gate.cleanup_unknown,"generation":s.generation,"last_job":s.gate.last_owner,"cancel_reason":s.gate.cancel_reason});
        if let Some((received, report)) = &s.companion {
            value["companion"] = json!({"reported":true,"age_seconds":now()-received,"observed":report.observed,"tls_port_available":report.port.is_some()});
        }
        if let Ok(bytes) = fs::read(self.config.dir.join("keepalive.json"))
            && bytes.len() <= 4096
            && let Ok(m) = serde_json::from_slice::<Value>(&bytes)
        {
            let age = m["last_check_epoch"].as_f64().map(|t| now() - t);
            value["maintenance_fresh"] = json!(
                m["identity_verified"] == true && age.is_some_and(|a| (0. ..=60.).contains(&a))
            );
            value["maintenance"] = m;
        }
        value
    }
    pub(crate) fn verify_enrollment(&self, expected: Option<&str>) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let disk = crate::enrollment_journal::barrier(&self.config.dir)?;
        let mut state = self.state.lock().unwrap();
        if state.enrollment.is_some() || disk.is_some() || expected.is_some() {
            self.enrollment_closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            // Cached admission never reopens merely because a record disappears.
            if state.enrollment.is_none() {
                state.enrollment = disk.clone().or_else(|| expected.map(str::to_owned));
            }
            if state.enrollment.as_deref() != expected || disk.as_deref() != expected {
                return Err("enrollment_barrier_changed: preserve pending device state".into());
            }
        }
        Ok(())
    }
    pub(crate) fn claim_enrollment(
        &self,
        record: &crate::enrollment_journal::Record,
    ) -> Res<String> {
        let _transport = self.transport.lock().unwrap();
        if crate::enrollment_journal::barrier(&self.config.dir)?.as_deref()
            != Some(record.transaction())
        {
            return Err("enrollment_barrier_changed".into());
        }
        let mut state = self.state.lock().unwrap();
        if state.stopping
            || state.maintenance
            || state.enrollment.as_deref() != Some(record.transaction())
            || !matches!(
                record.phase(),
                crate::enrollment_journal::Phase::CatalogAdded
                    | crate::enrollment_journal::Phase::ControllerHeld
            )
        {
            return Err("enrollment_internal_claim_not_admitted".into());
        }
        state.gate.expire(lease_now());
        if state.gate.cleanup_unknown.is_some() {
            return Err("enrollment_cleanup_unknown: inspect device work before recovery".into());
        }
        if state.gate.active || !state.operations.is_empty() || !state.viewers.is_empty() {
            return Err("enrollment_device_busy: existing work was not cancelled".into());
        }
        if let Some(lease) = &state.gate.lease {
            if serde_json::to_value(&lease.owner).map_err(|_| "enrollment_owner_invalid")?
                != serde_json::to_value(record.owner()).map_err(|_| "enrollment_owner_invalid")?
            {
                return Err(format!(
                    "enrollment_device_busy: {} on {} is running {:?}; no job was cancelled",
                    lease.owner.agent, lease.owner.origin, lease.owner.job
                ));
            }
            let token = lease.token.clone();
            state.gate.heartbeat(&token, lease_now())?;
            return Ok(token);
        }
        state.gate.claim(record.owner().clone(), lease_now(), 90)
    }
    pub fn claim(&self, o: Owner, ttl: u64) -> Res<String> {
        let _maintenance = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        s.gate.claim(o, lease_now(), ttl)
    }
    pub fn watch(&self, o: Owner, ttl: u64) -> Res<String> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if s.gate.cleanup_unknown.is_some() {
            return Err("cleanup_unknown".into());
        }
        s.viewers.retain(|_, v| v.active || v.expires > lease_now());
        if s.viewers.len() >= 16 {
            return Err("observer_limit_reached".into());
        }
        let mut validate = Gate::new();
        let t = validate.claim(o.clone(), lease_now(), ttl)?;
        s.viewers.insert(
            t.clone(),
            Viewer {
                owner: o,
                expires: lease_now() + ttl as f64,
                ttl,
                active: false,
            },
        );
        Ok(t)
    }
    fn viewer_journal(&self, t: &str) -> PathBuf {
        self.config.dir.join(format!(
            "active-view-{}.json",
            Sha256::digest(t.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    }
    pub fn heartbeat(&self, t: &str) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if let Some(v) = s.viewers.get_mut(t) {
            if v.expires <= lease_now() {
                return Err("expired_observer_ticket".into());
            }
            v.expires = lease_now() + v.ttl as f64;
            return Ok(());
        }
        s.gate.heartbeat(t, lease_now())
    }
    pub fn release(&self, t: &str) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        if let Some(v) = s.viewers.get(t) {
            if v.active {
                return Err("job_operation_busy".into());
            }
            s.viewers.remove(t);
            return Ok(());
        }
        s.gate.release(t, lease_now())
    }
    pub fn cancel(&self, t: &str) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if let Some(v) = s.viewers.get_mut(t) {
            v.expires = 0.;
            if !v.active {
                s.viewers.remove(t);
            }
            return Ok(());
        }
        s.gate.authorize(t, lease_now())?;
        s.gate.cancel("owner_cancelled");
        self.persist_fence(&s)
    }
    pub fn reconcile(&self, e: &Evidence) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        let mut check = Gate::new();
        check.active = s.gate.active || s.viewers.values().any(|v| v.active);
        check.cleanup_unknown = s.gate.cleanup_unknown.clone();
        check.reconcile(e, now())?;
        atomic(&self.config.dir.join("reconciliation.json"), e)?;
        for file in ["cleanup-unknown.json", "active-operation.json"] {
            match fs::remove_file(self.config.dir.join(file)) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("reconciliation_journal_cleanup_failed".into()),
            }
        }
        for e in fs::read_dir(&self.config.dir).map_err(|_| "state_read_failed")? {
            let p = e.map_err(|_| "state_read_failed")?.path();
            if p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("active-view-"))
            {
                fs::remove_file(p).map_err(|_| "reconciliation_journal_cleanup_failed")?;
            }
        }
        fs::File::open(&self.config.dir)
            .and_then(|f| f.sync_all())
            .map_err(|_| "reconciliation_sync_failed")?;
        s.gate.cleanup_unknown = None;
        Ok(())
    }
    fn persist_fence(&self, s: &State) -> Res<()> {
        if let Some(reason) = &s.gate.cleanup_unknown {
            atomic(
                &self.config.dir.join("cleanup-unknown.json"),
                &json!({"reason":reason,"at":now()}),
            )?;
        }
        Ok(())
    }
    fn adb(&self, args: &[&str]) -> Res<Captured> {
        self.ensure_owned_server(false)?;
        let c = self.command(args.iter().map(|s| s.to_string()).collect());
        capture_cmd(c, Duration::from_secs(3), 16384)
            .inspect_err(|e| eprintln!("Device transport probe failed: {e}"))
    }
    pub fn enable_owned_server(&self) {
        self.managed_server
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn ensure_owned_server(&self, restart: bool) -> Res<()> {
        if self
            .enrollment_closed
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("enrollment_pending: owned ADB server not started".into());
        }
        if self.server_closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("owned_adb_server_closed".into());
        }
        if !self
            .managed_server
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let mut slot = self.server.lock().unwrap();
        if self.server_closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("owned_adb_server_closed".into());
        }
        if let Some(server) = slot.as_mut() {
            if server.running()? {
                return Ok(());
            }
            if !restart {
                return Err(
                    "owned_adb_server_exited: use controller device connect after checking jobs"
                        .into(),
                );
            }
            server.stop()?;
            *slot = None;
        }
        *slot = Some(crate::adb_server::ManagedServer::start(
            &self.config.adb,
            &self.config.dir,
            self.config.adb_port,
        )?);
        Ok(())
    }
    pub fn stop_owned_server(&self) -> Res<()> {
        self.server_closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut slot = self.server.lock().unwrap();
        if let Some(server) = slot.as_mut() {
            server.stop()?;
        }
        *slot = None;
        Ok(())
    }
    fn prepare_key_home(config: &Config) -> Res<()> {
        use std::os::unix::fs::MetadataExt;
        let home = config.dir.join(".android");
        crate::registry::private_dir(&home)?;
        let imported = config.dir.join("adbkey");
        let primary = home.join("adbkey");
        for path in [&imported, &primary] {
            if let Ok(m) = fs::symlink_metadata(path)
                && (!m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0)
            {
                return Err("adb_key_must_be_private_owned_regular_file".into());
            }
        }
        if imported.exists() {
            if primary.exists() {
                if fs::read(&imported).map_err(|_| "adb_key_unreadable")?
                    != fs::read(&primary).map_err(|_| "adb_key_unreadable")?
                {
                    return Err("adb_key_conflict: retained keys differ; no key replaced".into());
                }
            } else {
                use std::io::Write;
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(primary)
                    .map_err(|_| "adb_key_import_failed")?;
                f.write_all(&fs::read(imported).map_err(|_| "adb_key_unreadable")?)
                    .and_then(|_| f.sync_all())
                    .map_err(|_| "adb_key_import_failed")?;
                fs::File::open(&home)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "adb_key_directory_sync_failed")?;
            }
        }
        Ok(())
    }
    fn ensure_pairing_key(&self) -> Res<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let key = self.config.dir.join(".android/adbkey");
        if let Ok(m) = fs::symlink_metadata(&key) {
            if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
                return Err("adb_key_must_be_private_owned_regular_file".into());
            }
            return Ok(());
        }
        let temp = self.config.dir.join(format!("adbkey-new-{}", random()));
        let result = (|| -> Res<()> {
            let out = capture_cmd(
                self.command(vec!["keygen".into(), temp.to_string_lossy().into()]),
                std::time::Duration::from_secs(5),
                16384,
            )?;
            if !out.ok {
                return Err("adb_key_generation_failed".into());
            }
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
                .map_err(|_| "adb_key_permissions_failed")?;
            fs::File::open(&temp)
                .and_then(|f| f.sync_all())
                .map_err(|_| "adb_key_sync_failed")?;
            fs::rename(&temp, &key).map_err(|_| "adb_key_commit_failed")?;
            let public = PathBuf::from(format!("{}.pub", temp.display()));
            if public.exists() {
                fs::File::open(&public)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "adb_public_key_sync_failed")?;
                fs::rename(public, self.config.dir.join(".android/adbkey.pub"))
                    .map_err(|_| "adb_public_key_commit_failed")?;
            }
            for dir in [&self.config.dir, self.config.dir.join(".android").as_path()] {
                fs::File::open(dir)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "adb_key_directory_sync_failed")?;
            }
            Ok(())
        })();
        let _ = fs::remove_file(&temp);
        let _ = fs::remove_file(format!("{}.pub", temp.display()));
        result
    }
    fn command(&self, args: Vec<String>) -> Command {
        let mut c =
            crate::adb_server::client(&self.config.adb, &self.config.dir, self.config.adb_port);
        c.args(args);
        c
    }
    fn pinned(&self, p: u16) -> bool {
        let target = format!("{}:{p}", self.config.peer);
        self.adb(&["-s", &target, "shell", "getprop", "ro.serialno"])
            .is_ok_and(|r| {
                r.ok && equal(
                    &Sha256::digest(String::from_utf8_lossy(&r.out).trim().as_bytes())
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    &self.identity.lock().unwrap(),
                )
            })
    }
    fn disconnect(&self, target: &str) -> Res<()> {
        let r = self.adb(&["disconnect", target])?;
        if r.ok {
            return Ok(());
        }
        let list = self.adb(&["devices"])?;
        if !list.ok
            || !String::from_utf8_lossy(&list.out).starts_with("List of devices attached")
            || String::from_utf8_lossy(&list.out)
                .lines()
                .skip(1)
                .any(|l| l.split_whitespace().next() == Some(target))
        {
            return Err("transport_cleanup_failed".into());
        }
        Ok(())
    }
    fn report_admission(s: &State) -> Res<()> {
        Self::check_running(s)?;
        if Self::network_active(s) {
            return Err("network_change_in_progress: retry the report after completion".into());
        }
        if s.operations.values().any(|op| op.pairing) {
            return Err("pairing_in_progress".into());
        }
        if s.last_attempt.is_some_and(|last| lease_now() - last < 5.) {
            return Err("rate_limited".into());
        }
        Ok(())
    }
    fn report_unavailable(&self, s: &mut State, reason: &str) -> Res<()> {
        s.receipt.connected = false;
        s.receipt.identity_verified = false;
        if s.target.is_some() || s.gate.active || s.viewers.values().any(|v| v.active) {
            s.generation += 1;
            s.target = None;
            for v in s.viewers.values_mut() {
                v.expires = 0.;
            }
            s.gate.cancel(reason);
            if let Err(e) = self.persist_fence(s) {
                s.gate.cleanup_unknown = Some("report_state_persistence_failed".into());
                return Err(e);
            }
        }
        Ok(())
    }
    pub fn report_v2(&self, r: readb_protocol::Report) -> Res<bool> {
        r.validate()?;
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::report_admission(&s)?;
        let mut next = s.report_cursor.clone();
        let change = next.accept(&r)?;
        if let Err(e) = atomic(&self.config.dir.join("report-cursor.json"), &next) {
            s.gate.cleanup_unknown = Some("report_cursor_persistence_failed".into());
            let _ = self.report_unavailable(&mut s, "report_cursor_persistence_failed");
            return Err(e);
        }
        s.report_cursor = next;
        s.last_attempt = Some(lease_now());
        if change == readb_protocol::EpochChange::Changed
            || (change == readb_protocol::EpochChange::First && s.receipt.received_at > 0.)
        {
            self.report_unavailable(&mut s, "reporter_epoch_changed")?;
        }
        s.companion = Some((now(), r.clone()));
        if let Some(port) = r.port {
            return self.report_inner(
                &mut s,
                Report {
                    port,
                    battery: r.battery,
                },
            );
        }
        self.report_unavailable(&mut s, "tls_port_unavailable")?;
        s.receipt = Receipt {
            received_at: now(),
            port: 0,
            battery: r.battery,
            ..Receipt::default()
        };
        atomic(&self.config.dir.join("last-report.json"), &s.receipt)?;
        Ok(false)
    }
    pub fn report(&self, r: Report) -> Res<bool> {
        self.refresh_report(r, None)
    }
    fn refresh_pinned(&self, ticket: &str, r: Report) -> Res<bool> {
        self.refresh_report(r, Some(ticket))
    }
    fn refresh_report(&self, r: Report, ticket: Option<&str>) -> Res<bool> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if ticket.is_none() && s.report_cursor.is_initialized() {
            return Err("report_protocol_downgrade".into());
        }
        if let Some(ticket) = ticket {
            Self::lifecycle_admission(&mut s, ticket)?;
        }
        Self::report_admission(&s)?;
        if ticket.is_some() {
            atomic(&self.config.dir.join("connection.json"), &false)?;
            s.paused = false;
        }
        s.last_attempt = Some(lease_now());
        self.report_inner(&mut s, r)
    }
    fn report_inner(&self, s: &mut State, r: Report) -> Res<bool> {
        let time = now();
        if s.paused {
            s.receipt = Receipt {
                received_at: time,
                port: r.port,
                battery: r.battery,
                ..Receipt::default()
            };
            atomic(&self.config.dir.join("last-report.json"), &s.receipt)?;
            return Ok(false);
        }
        let target = format!("{}:{}", self.config.peer, r.port);
        let same = s.target == Some(r.port);
        let active = s.gate.active || s.viewers.values().any(|v| v.active);
        if active && !same {
            for v in s.viewers.values_mut() {
                v.expires = 0.;
            }
            s.gate.cancel("transport_changed");
            self.persist_fence(s)?;
            s.receipt = Receipt {
                received_at: time,
                port: r.port,
                battery: r.battery,
                ..Receipt::default()
            };
            atomic(&self.config.dir.join("last-report.json"), &s.receipt)?;
            return Ok(false);
        }
        let mut cleanup_failed = false;
        let connected = if same && active {
            let good = self.pinned(r.port);
            if !good {
                for v in s.viewers.values_mut() {
                    v.expires = 0.;
                }
                s.gate.cancel("identity_or_transport_unavailable");
                self.persist_fence(s)?;
            }
            good
        } else {
            if s.target.is_some() && !same {
                s.gate.cancel("transport_changed");
                self.persist_fence(s)?;
            }
            let result = (|| -> Res<bool> {
                let list = self.adb(&["devices"])?;
                let text = String::from_utf8_lossy(&list.out);
                if !list.ok || !text.starts_with("List of devices attached") {
                    return Err("transport_inventory_failed".into());
                }
                let stale: Vec<_> = text
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_whitespace().next())
                    .filter(|v| v.starts_with(&format!("{}:", self.config.peer)) && *v != target)
                    .collect();
                if stale.len() > 2 {
                    return Err("transport_inventory_requires_review".into());
                }
                for old in stale {
                    self.disconnect(old)?;
                }
                let result = self.adb(&["connect", &target])?;
                let text = String::from_utf8_lossy(&result.out);
                let good = result.ok
                    && (text.contains(&format!("connected to {target}"))
                        || text.contains(&format!("already connected to {target}")))
                    && self.pinned(r.port);
                if !good {
                    self.disconnect(&target)?;
                }
                Ok(good)
            })();
            match result {
                Ok(v) => v,
                Err(_) => {
                    cleanup_failed = true;
                    false
                }
            }
        };
        if connected && !same {
            s.generation += 1;
            s.target = Some(r.port);
        }
        if !connected {
            s.target = None;
        }
        s.receipt = Receipt {
            received_at: time,
            port: r.port,
            battery: r.battery,
            connected,
            identity_verified: connected,
            transport_cleanup_failed: cleanup_failed,
        };
        atomic(&self.config.dir.join("last-report.json"), &s.receipt)?;
        Ok(connected)
    }
    pub(crate) fn maintenance_transport(&self) -> Res<std::sync::MutexGuard<'_, ()>> {
        self.transport
            .try_lock()
            .map_err(|_| "maintenance_transport_busy".into())
    }
    pub(crate) fn maintenance_quiet(&self, s: &mut State) -> Res<()> {
        if s.stopping {
            return Err("coordinator_shutdown".into());
        }
        s.gate.expire(lease_now());
        s.viewers.retain(|_, v| v.active || v.expires > lease_now());
        if s.gate.cleanup_unknown.is_some() {
            self.persist_fence(s)?;
            return Err("maintenance_cleanup_unknown: reconcile device work first".into());
        }
        if s.gate.lease.is_some()
            || !s.viewers.is_empty()
            || s.gate.active
            || !s.operations.is_empty()
        {
            return Err("maintenance_jobs_busy: release controllers and viewers first".into());
        }
        Ok(())
    }
    pub(crate) fn preflight_network(&self, ticket: &str) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if let Err(error) = s.gate.authorize(ticket, lease_now()) {
            self.persist_fence(&s)?;
            return Err(error);
        }
        if s.gate.active || s.viewers.values().any(|v| v.active) {
            return Err("network_operation_busy: wait for active operations".into());
        }
        Ok(())
    }
    /// Network setup must work before ADB is paired or reachable. This grants
    /// no kernel authority; the coordinator still needs a bound root proof.
    pub fn begin_network(&self, t: &str, label: &str) -> Res<String> {
        if !matches!(label, "network-enroll" | "network-rm") {
            return Err("invalid_network_operation".into());
        }
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        s.gate.authorize(t, lease_now())?;
        if s.viewers.values().any(|v| v.active) {
            return Err("network_viewer_operation_busy: wait for active viewers".into());
        }
        s.gate.begin(t, lease_now(), false)?;
        let id = random();
        let record = json!({"generation":s.generation,"job":s.gate.lease,
            "pure":false,"started":true,"kind":"network","operation":id});
        if let Err(e) = atomic(&self.config.dir.join("active-operation.json"), &record) {
            s.gate.cancel("network_intent_persistence_failed");
            let _ = self.persist_fence(&s);
            s.gate.finish();
            return Err(e);
        }
        s.operations.insert(
            t.into(),
            Operation {
                pairing: false,
                network: true,
                id: id.clone(),
                command: label.into(),
                observer: false,
            },
        );
        if let Err(e) = crate::events::append(
            &self.config.dir,
            &crate::events::Event::new("start", &id, label, "control", "network-pending"),
        ) {
            s.gate.cancel("network_history_persistence_failed");
            let _ = self.persist_fence(&s);
            s.gate.finish();
            s.operations.remove(t);
            return Err(e);
        }
        Ok(id)
    }
    pub fn authorize_network(&self, t: &str, operation: &str) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if !s.gate.active
            || !s
                .operations
                .get(t)
                .is_some_and(|op| op.network && op.id == operation)
        {
            return Err("network_operation_not_active".into());
        }
        if let Err(e) = s.gate.authorize(t, lease_now()) {
            self.persist_fence(&s)?;
            return Err(e);
        }
        Ok(())
    }
    pub fn prepare(&self, t: &str, args: Vec<String>) -> Res<Prepared> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if Self::network_active(&s) {
            return Err("network_change_in_progress: wait before issuing ADB commands".into());
        }
        let observer = s.viewers.contains_key(t);
        if s.gate.cleanup_unknown.is_some() {
            return Err("cleanup_unknown".into());
        }
        if observer {
            let v = &s.viewers[t];
            if v.expires <= lease_now() {
                return Err("expired_observer_ticket".into());
            }
        } else {
            s.gate.authorize(t, lease_now())?;
        }
        let pairing = args.first().is_some_and(|a| a == "pair");
        if pairing {
            if observer
                || !(2..=3).contains(&args.len())
                || !args[1].parse::<u16>().is_ok_and(|p| p >= 1024)
            {
                return Err("pair_requires_controller_and_port_only".into());
            }
            if args
                .get(2)
                .is_some_and(|ip| ip.parse::<std::net::Ipv4Addr>().ok() != Some(self.config.peer))
            {
                return Err("pair_ip_must_match_configured_peer: use the enrolled VPN IP".into());
            }
            self.ensure_pairing_key()?;
        }
        let allowed = [
            "pair",
            "shell",
            "exec-out",
            "pull",
            "push",
            "install",
            "install-multiple",
            "uninstall",
            "logcat",
            "get-state",
            "bugreport",
            "reboot",
        ];
        if args.is_empty()
            || !allowed.contains(&args[0].as_str())
            || args.iter().any(|a| a.contains('\0'))
        {
            return Err(
                "unsupported_command: shared transport selection/lifecycle is coordinator-owned"
                    .into(),
            );
        }
        if observer && !is_pure(&args) {
            return Err("observer_cannot_change_device".into());
        }
        if !pairing && (!s.receipt.fresh(now()) || s.target != Some(s.receipt.port)) {
            return Err("Device unavailable: no fresh verified secure ADB report".into());
        }
        if !pairing && !self.pinned(s.receipt.port) {
            s.receipt.connected = false;
            return Err(
                "Device identity/connection check failed; no requested command issued".into(),
            );
        }
        if !pairing {
            validate_remote(&args)?;
        }
        // Pairing changes TLS authorization, but starts no device-side command.
        // A failed/expired code is safe to retry after local child cleanup. Keep
        // controller admission above; this flag only governs cancellation fences.
        let pure = pairing || is_pure(&args);
        if observer {
            let v = s.viewers.get_mut(t).unwrap();
            if v.active {
                return Err("job_operation_busy".into());
            }
            v.active = true;
            v.expires = lease_now() + v.ttl as f64;
        } else {
            s.gate.begin(t, lease_now(), true)?;
        }
        let generation = s.generation;
        let target = format!("{}:{}", self.config.peer, s.receipt.port);
        if let Err(e) = atomic(
            &if observer {
                self.viewer_journal(t)
            } else {
                self.config.dir.join("active-operation.json")
            },
            &json!({"generation":generation,"job":if observer{json!(&s.viewers[t].owner)}else{json!(&s.gate.lease)},"pure":pure,"started":false}),
        ) {
            if observer {
                s.viewers.get_mut(t).unwrap().active = false;
            } else {
                s.gate.finish();
            }
            return Err(e);
        }
        s.operations.insert(
            t.into(),
            Operation {
                pairing,
                network: false,
                id: random(),
                command: if args[0] == "shell" || args[0] == "exec-out" {
                    args.get(1).cloned().unwrap_or_default()
                } else {
                    args[0].clone()
                },
                observer,
            },
        );
        let mut argv = if pairing {
            vec!["pair".into(), format!("{}:{}", self.config.peer, args[1])]
        } else {
            vec!["-s".into(), target]
        };
        if pairing {
            // Code arrives over the private stdin stream, never argv or history.
        } else if args[0] == "shell" || args[0] == "exec-out" {
            argv.push(args[0].clone());
            argv.push(
                args[1..]
                    .iter()
                    .map(|a| format!("'{}'", a.replace('\'', "'\"'\"'")))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        } else {
            argv.extend(args);
        }
        Ok(Prepared {
            pairing,
            command: self.command(argv),
            generation,
            pure,
        })
    }
    pub fn spawn(&self, t: &str, p: &mut Prepared) -> Res<Child> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        if Self::network_active(&s) {
            return Err("network_change_in_progress: no ADB command started".into());
        }
        let observer = s.viewers.contains_key(t);
        if s.gate.cleanup_unknown.is_some() {
            return Err("cleanup_unknown".into());
        }
        let admitted = if observer {
            let v = &s.viewers[t];
            v.active && v.expires > lease_now()
        } else {
            s.gate.authorize(t, lease_now())?;
            s.gate.active
        };
        if !admitted
            || s.generation != p.generation
            || (!p.pairing && (!s.receipt.fresh(now()) || s.target != Some(s.receipt.port)))
        {
            return Err("dispatch_fenced".into());
        }
        self.ensure_owned_server(false)?;
        atomic(
            &if observer {
                self.viewer_journal(t)
            } else {
                self.config.dir.join("active-operation.json")
            },
            &json!({"generation":p.generation,"job":if observer{json!(&s.viewers[t].owner)}else{json!(&s.gate.lease)},"pure":p.pure,"started":true}),
        )?;
        if !observer {
            s.gate.active_pure = p.pure;
        }
        let op = s.operations.get(t).ok_or("operation_metadata_missing")?;
        crate::events::append(
            &self.config.dir,
            &crate::events::Event::new(
                "dispatch",
                &op.id,
                &op.command,
                if observer { "view" } else { "control" },
                "started",
            ),
        )?;
        p.command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|_| "command_spawn_failed".into())
    }
    pub fn running(&self, t: &str, generation: u64) -> bool {
        let mut s = self.state.lock().unwrap();
        let pairing = s.operations.get(t).is_some_and(|op| op.pairing);
        if s.stopping
            || s.maintenance
            || s.enrollment.is_some()
            || Self::network_active(&s)
            || (!pairing && !s.receipt.fresh(now()))
            || s.gate.cleanup_unknown.is_some()
            || s.generation != generation
        {
            return false;
        }
        if let Some(v) = s.viewers.get_mut(t) {
            if v.expires <= lease_now() {
                return false;
            }
            v.expires = lease_now() + v.ttl as f64;
            return true;
        }
        s.gate.heartbeat(t, lease_now()).is_ok()
    }
    pub fn complete(&self, cancelled: bool) {
        let token = self
            .state
            .lock()
            .unwrap()
            .operations
            .iter()
            .find(|(_, o)| !o.observer)
            .map(|(t, _)| t.clone())
            .unwrap_or_default();
        self.complete_for(&token, cancelled)
    }
    pub fn complete_for(&self, t: &str, cancelled: bool) {
        self.complete_result(
            t,
            cancelled,
            if cancelled {
                "cancelled-or-failed"
            } else {
                "finished"
            },
        )
    }
    pub fn complete_result(&self, t: &str, cancelled: bool, outcome: &str) {
        let mut s = self.state.lock().unwrap();
        self.complete_result_locked(&mut s, t, cancelled, outcome)
    }
    pub fn finish_network(
        &self,
        t: &str,
        operation: &str,
        cancelled: bool,
        outcome: &str,
    ) -> Res<()> {
        let mut s = self.state.lock().unwrap();
        if !s
            .operations
            .get(t)
            .is_some_and(|op| op.network && op.id == operation)
        {
            return Err("network_operation_not_active".into());
        }
        self.complete_result_locked(&mut s, t, cancelled, outcome);
        if s.gate.cleanup_unknown.is_some() {
            return Err(
                "network_completion_fenced: inspect device and root state before retry".into(),
            );
        }
        Ok(())
    }
    fn complete_result_locked(&self, s: &mut State, t: &str, cancelled: bool, outcome: &str) {
        if let Some(op) = s.operations.remove(t)
            && crate::events::append(
                &self.config.dir,
                &crate::events::Event::new(
                    "complete",
                    &op.id,
                    &op.command,
                    if op.observer { "view" } else { "control" },
                    outcome,
                ),
            )
            .is_err()
        {
            s.gate.cleanup_unknown = Some("history_write_failed".into());
        }
        if s.viewers.contains_key(t) {
            if let Some(v) = s.viewers.get_mut(t) {
                v.active = false;
            }
            if self.persist_fence(s).is_err() {
                s.gate.cleanup_unknown = Some("state_persistence_failed".into());
            }
            if s.gate.cleanup_unknown.is_none() && fs::remove_file(self.viewer_journal(t)).is_err()
            {
                s.gate.cleanup_unknown = Some("viewer_journal_cleanup_failed".into());
            }
            if s.viewers.get(t).is_some_and(|v| v.expires <= lease_now()) {
                s.viewers.remove(t);
            }
            return;
        }
        if cancelled {
            s.gate.cancel("command_cancelled_or_timed_out");
        }
        if self.persist_fence(s).is_err() {
            s.gate.cleanup_unknown = Some("state_persistence_failed".into());
        }
        s.gate.finish();
        if s.gate.cleanup_unknown.is_none()
            && fs::remove_file(self.config.dir.join("active-operation.json")).is_err()
        {
            s.gate.cleanup_unknown = Some("active_journal_cleanup_failed".into());
        }
    }
    pub fn set_keepalive(&self, t: &str, enabled: bool, prevent_lock: bool) -> Res<()> {
        let _transport = self.transport.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        Self::check_running(&s)?;
        s.gate.authorize(t, lease_now())?;
        if s.gate.active {
            return Err("job_operation_busy".into());
        }
        let policy = crate::schema::Keepalive {
            enabled,
            prevent_lock,
        };
        atomic(&self.config.dir.join("policy.json"), &policy)?;
        s.keepalive = policy;
        Ok(())
    }
    pub fn keepalive(&self) -> Res<Value> {
        let _transport = match self.transport.try_lock() {
            Ok(v) => v,
            Err(_) => return Err("transport_maintenance_busy".into()),
        };
        let s = self.state.lock().unwrap();
        if s.stopping
            || s.maintenance
            || s.enrollment.is_some()
            || Self::network_active(&s)
            || !s.keepalive.enabled
            || !s.receipt.fresh(now())
            || s.gate.cleanup_unknown.is_some()
            || s.gate.lease.as_ref().is_some_and(|l| l.owner.allow_sleep)
        {
            return Err("keepalive_not_permitted_by_state_or_job".into());
        }
        let port = s.receipt.port;
        let prevent_lock = s.keepalive.prevent_lock;
        drop(s);
        if !self.pinned(port) {
            return Err("identity_unverified".into());
        }
        let target = format!("{}:{port}", self.config.peer);
        let mut commands = vec![vec!["shell", "svc", "power", "stayon", "true"]];
        if prevent_lock && matches!(self.config.kind, crate::schema::Kind::Quest) {
            commands.push(vec![
                "shell",
                "am",
                "broadcast",
                "-a",
                "com.oculus.vrpowermanager.prox_close",
            ]);
        }
        for cmd in commands {
            let mut a = vec!["-s", &target];
            a.extend(cmd);
            if !self.adb(&a)?.ok {
                return Err("keepalive_command_failed".into());
            }
        }
        let power = self.adb(&["-s", &target, "shell", "dumpsys", "power"])?;
        let p = String::from_utf8_lossy(&power.out);
        let value = json!({"active":true,"connected":power.ok,"identity_verified":true,"awake":p.contains("mWakefulness=Awake"),"powered":p.contains("mIsPowered=true"),"stay_on":p.contains("mStayOn=true"),"prevent_lock_requested":prevent_lock,"unlocked":"unknown","secure_unlock_supported":false,"last_check_epoch":now()});
        atomic(&self.config.dir.join("keepalive.json"), &value)?;
        Ok(value)
    }
}
pub fn is_pure(a: &[String]) -> bool {
    if a.iter().any(|v| {
        v.chars()
            .any(|c| !(c.is_ascii_alphanumeric() || "._:/=-*".contains(c)))
    }) {
        return false;
    }
    matches!(a,[one,two,three] if one=="shell"&&two=="cat"&&["/proc/meminfo","/proc/loadavg","/proc/uptime"].contains(&three.as_str()))
        || matches!(a,[one,two,three] if one=="shell"&&two=="df"&&three=="-h")
        || matches!(a,[one,two,three] if one=="shell"&&two=="ps"&&three=="-A")
        || matches!(a,[one,two,three,four] if one=="shell"&&two=="pm"&&three=="list"&&four=="packages")
        || matches!(a,[one,two,three,four] if one=="shell"&&two=="pm"&&three=="path"&&crate::actions::package(four))
        || matches!(a,[one] if one=="get-state")
        || (a.first().is_some_and(|v| v == "logcat")
            && a.iter().skip(1).all(|v| {
                [
                    "-d",
                    "-v",
                    "brief",
                    "long",
                    "threadtime",
                    "time",
                    "raw",
                    "-b",
                    "main",
                    "system",
                    "crash",
                    "events",
                    "all",
                ]
                .contains(&v.as_str())
            }))
        || matches!(a,[one,two,three] if one=="exec-out"&&two=="screencap"&&three=="-p")
        || matches!(a,[one,two,..] if (one=="shell"||one=="exec-out")&&two=="getprop")
        || matches!(a,[one,two,three] if one=="shell"&&two=="dumpsys"&&["power","input","battery","user","thermalservice","connectivity","wifi","display"].contains(&three.as_str()))
}

fn validate_remote(a: &[String]) -> Res<()> {
    if a[0] != "shell" && a[0] != "exec-out" {
        return Ok(());
    }
    let program = a.get(1).ok_or("structured_remote_command_required")?;
    if matches!(a,[one,two,three,text] if (one=="shell"||one=="exec-out")&&two=="input"&&three=="text"&&!text.chars().any(char::is_control))
    {
        return Ok(());
    }
    let known = [
        "getprop",
        "dumpsys",
        "input",
        "wm",
        "pm",
        "cmd",
        "settings",
        "uiautomator",
        "screencap",
        "cat",
        "ls",
        "stat",
        "mkdir",
        "rmdir",
        "rm",
        "mv",
        "cp",
        "chmod",
        "chown",
        "touch",
        "date",
        "id",
        "pidof",
        "ps",
        "kill",
        "am",
        "svc",
        "df",
        "du",
        "readlink",
        "test",
        "true",
        "false",
        "logcat",
        "tee",
        "monkey",
    ];
    if !known.contains(&program.as_str())
        || a.iter().skip(1).any(|v| {
            ["sh", "bash", "python", "python3", "nohup", "setsid"].contains(&v.as_str())
                || v.chars().any(|c| ";&|`<>$".contains(c))
        })
    {
        return Err("untracked_remote_work_forbidden: use structured synchronous command arguments; shell/eval/background jobs need an audited runner, not raw ADB bypass".into());
    }
    if a.iter().any(|v| v == "--async")
        || (program == "am"
            && a.get(2).is_some_and(|v| v == "instrument")
            && !a.iter().any(|v| v == "-w"))
    {
        return Err(
            "untracked_remote_work_forbidden: instrumentation must wait for completion".into(),
        );
    }
    Ok(())
}
