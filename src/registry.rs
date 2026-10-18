use crate::{
    backend::{Backend, Config},
    policy::{Report, Res},
    schema::*,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
pub struct Registry {
    pub root: PathBuf,
    pub network: Arc<crate::network_controller::NetworkController>,
    pub web: Mutex<crate::web::Dashboard>,
    pub config_path: PathBuf,
    pub revision: std::sync::atomic::AtomicU64,
    pub closing: std::sync::atomic::AtomicBool,
    shutdown_requested: std::sync::atomic::AtomicBool,
    maintenance: Mutex<Option<crate::maintenance::Marker>>,
    pub listener_errors: Mutex<BTreeMap<String, String>>,
    catalog: Mutex<Catalog>,
    managed_servers: std::sync::atomic::AtomicBool,
    catalog_store: crate::catalog::Store,
}
fn fingerprint(config: &ServerConfig) -> Res<String> {
    use sha2::Digest;
    let bytes = serde_json::to_vec(config).map_err(|_| "maintenance_config_encoding_failed")?;
    Ok(sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
struct Catalog {
    config: ServerConfig,
    devices: BTreeMap<String, Arc<Backend>>,
    notifiers: BTreeMap<String, Arc<crate::notifier::Notifier>>,
}
pub fn private_dir(p: &Path) -> Res<()> {
    if let Ok(m) = fs::symlink_metadata(p) {
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err("private_directory_ownership_or_permissions_invalid".into());
        }
    } else {
        fs::create_dir_all(p).map_err(|_| "private_directory_create_failed")?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))
            .map_err(|_| "private_directory_permissions_failed")?;
    }
    Ok(())
}
impl Registry {
    pub fn new(config: ServerConfig, root: PathBuf) -> Res<Self> {
        let path = root.join("server.json");
        Self::new_at(config, root, path)
    }
    pub fn new_at(config: ServerConfig, root: PathBuf, config_path: PathBuf) -> Res<Self> {
        config.validate()?;
        private_dir(&root)?;
        let base = root.join("devices");
        private_dir(&base)?;
        let enrollments = crate::enrollment_journal::inspect(&root)?;
        let mut devices = BTreeMap::new();
        let mut notifiers = BTreeMap::new();
        for d in &config.devices {
            let dir = base.join(&d.id);
            private_dir(&dir)?;
            if let Some(record) = enrollments.get(&d.id) {
                crate::enrollment_journal::publish_barrier(&dir, record.transaction())?;
            }
            let b = Backend::new(Config {
                dir,
                adb: config.adb.clone(),
                token: d.token.clone(),
                identity: d.identity.clone(),
                recipient: d.recipient.clone().unwrap_or_default(),
                peer: d.peer,
                adb_port: d.adb_port,
                kind: d.kind,
                keepalive: d.keepalive.clone(),
            })?;
            if !b.config.recipient.is_empty() {
                notifiers.insert(
                    d.id.clone(),
                    Arc::new(crate::notifier::Notifier::named(&b.config, &d.name)?),
                );
            }
            devices.insert(d.id.clone(), Arc::new(b));
        }
        let registry = Self {
            catalog_store: crate::catalog::Store::for_loaded_config(&root, &config_path, &config)?,
            root,
            network: Arc::new(crate::network_controller::NetworkController::new()),
            config_path,
            revision: std::sync::atomic::AtomicU64::new(1),
            closing: std::sync::atomic::AtomicBool::new(false),
            shutdown_requested: std::sync::atomic::AtomicBool::new(false),
            maintenance: Mutex::new(None),
            listener_errors: Mutex::new(BTreeMap::new()),
            managed_servers: std::sync::atomic::AtomicBool::new(false),
            web: Mutex::new(Default::default()),
            catalog: Mutex::new(Catalog {
                config,
                devices,
                notifiers,
            }),
        };
        registry.refresh_enrollments()?;
        registry.refresh_maintenance()?;
        Ok(registry)
    }
    pub fn refresh_enrollments(&self) -> Res<()> {
        let records = crate::enrollment_journal::inspect(&self.root)?;
        let catalog = self.catalog.lock().unwrap();
        for (id, backend) in &catalog.devices {
            backend.verify_enrollment(records.get(id).map(|r| r.transaction()))?;
        }
        Ok(())
    }
    /// Server-side enrollment recovery only. Root metadata must come through the
    /// existing authenticated helper client; a pending ticket grants no ADB work.
    pub fn claim_enrollment(
        &self,
        store: &mut crate::enrollment_journal::Store,
        id: &str,
        owner: &crate::policy::Owner,
        root_status: impl FnOnce() -> Res<Value>,
    ) -> Res<String> {
        store.bound_to(&self.root)?;
        let record = store.recover(id, owner)?;
        let status = root_status()?;
        if status["fenced"] != false || status["scoped_controller"] != true {
            return Err("enrollment_root_not_ready: inspect root fence or upgrade helper".into());
        }
        let catalog = self.catalog.lock().unwrap();
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        self.catalog_store.preflight()?;
        if fingerprint(&catalog.config)? != record.expected_config() {
            return Err("enrollment_catalog_changed: inspect original pending transaction".into());
        }
        let backend = catalog
            .devices
            .get(id)
            .ok_or("enrollment_device_not_published")?;
        let ticket = backend.claim_enrollment(&record)?;
        // A publication failure keeps the live lease; recovery reuses that exact
        // same-owner idle lease or waits for safe expiry. Never cancel or steal.
        store.bind_ticket(id, record.transaction(), owner, record.ticket(), &ticket)?;
        Ok(ticket)
    }
    pub fn config_fingerprint(&self) -> Res<String> {
        fingerprint(&self.catalog.lock().unwrap().config)
    }
    pub fn prepare_maintenance(&self, upgrade: &str, config: &str) -> Res<Value> {
        let expected = crate::maintenance::Marker::new(upgrade, config)?;
        let catalog = self.catalog.lock().unwrap();
        if self
            .shutdown_requested
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("coordinator_shutdown".into());
        }
        self.catalog_store.preflight()?;
        if fingerprint(&catalog.config)? != config {
            return Err("maintenance_config_changed".into());
        }
        let backends = catalog.devices.values().collect::<Vec<_>>();
        let _transports = backends
            .iter()
            .map(|b| b.maintenance_transport())
            .collect::<Res<Vec<_>>>()?;
        let mut states = backends
            .iter()
            .map(|b| {
                b.state
                    .try_lock()
                    .map_err(|_| "maintenance_state_busy".into())
            })
            .collect::<Res<Vec<_>>>()?;
        for (backend, state) in backends.iter().zip(states.iter_mut()) {
            backend.maintenance_quiet(state)?;
        }
        let mut store = crate::maintenance::Store::open(&self.root)?;
        if self
            .maintenance
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|m| m != &expected)
        {
            return Err("maintenance_owned_by_other_upgrade".into());
        }
        // Close cached admission even if publication has an ambiguous I/O error.
        // Catalog+all transports+all states prevent a claim/report/keeper race.
        self.closing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        for state in &mut states {
            state.maintenance = true;
        }
        *self.maintenance.lock().unwrap() = Some(expected.clone());
        store.publish(&expected)?;
        Ok(json!({"maintenance":expected,"ready_to_stop":true}))
    }
    /// Called again after acquiring the daemon runtime lock: a constructor read
    /// alone can race an admitted offline publisher before serve obtains it.
    pub fn refresh_maintenance(&self) -> Res<()> {
        let catalog = self.catalog.lock().unwrap();
        if self
            .shutdown_requested
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("coordinator_shutdown".into());
        }
        let config = fingerprint(&catalog.config)?;
        let marker = crate::maintenance::inspect(&self.root, &config)?;
        if marker.is_none() && self.maintenance.lock().unwrap().is_some() {
            return Err("maintenance_marker_disappeared".into());
        }
        if let Some(marker) = marker {
            self.catalog_store.preflight()?;
            let backends = catalog.devices.values().collect::<Vec<_>>();
            let _transports = backends
                .iter()
                .map(|b| b.maintenance_transport())
                .collect::<Res<Vec<_>>>()?;
            let mut states = backends
                .iter()
                .map(|b| {
                    b.state
                        .try_lock()
                        .map_err(|_| "maintenance_state_busy".into())
                })
                .collect::<Res<Vec<_>>>()?;
            if states.iter().any(|s| {
                s.stopping
                    || s.gate.lease.is_some()
                    || !s.viewers.is_empty()
                    || s.gate.active
                    || !s.operations.is_empty()
            }) {
                return Err("maintenance_runtime_refresh_requires_idle".into());
            }
            self.closing
                .store(true, std::sync::atomic::Ordering::SeqCst);
            for state in &mut states {
                state.maintenance = true;
            }
            *self.maintenance.lock().unwrap() = Some(marker);
        }
        Ok(())
    }
    pub fn resume_maintenance(&self, upgrade: &str, config: &str) -> Res<Value> {
        self.resume_maintenance_inner(upgrade, config, false)
    }
    /// Reconcile a lost removal acknowledgement on this still-closed process.
    /// Absence alone never authorizes reopening a different/fresh daemon.
    pub fn recover_maintenance_resume(&self, upgrade: &str, config: &str) -> Res<Value> {
        self.resume_maintenance_inner(upgrade, config, true)
    }
    fn resume_maintenance_inner(&self, upgrade: &str, config: &str, recover: bool) -> Res<Value> {
        let expected = crate::maintenance::Marker::new(upgrade, config)?;
        let catalog = self.catalog.lock().unwrap();
        if self
            .shutdown_requested
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("coordinator_shutdown".into());
        }
        self.catalog_store.preflight()?;
        if fingerprint(&catalog.config)? != config {
            return Err("maintenance_config_changed".into());
        }
        if self.maintenance.lock().unwrap().as_ref() != Some(&expected) {
            return Err("maintenance_owner_mismatch".into());
        }
        let backends = catalog.devices.values().collect::<Vec<_>>();
        let _transports = backends
            .iter()
            .map(|b| b.maintenance_transport())
            .collect::<Res<Vec<_>>>()?;
        let mut states = backends
            .iter()
            .map(|b| {
                b.state
                    .try_lock()
                    .map_err(|_| "maintenance_state_busy".into())
            })
            .collect::<Res<Vec<_>>>()?;
        for (backend, state) in backends.iter().zip(states.iter_mut()) {
            backend.maintenance_quiet(state)?;
        }
        let mut store = crate::maintenance::Store::open(&self.root)?;
        if recover {
            store.confirm_removed(&expected)?;
        } else {
            store.remove(&expected)?;
        }
        *self.maintenance.lock().unwrap() = None;
        for state in &mut states {
            state.maintenance = false;
        }
        self.closing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"maintenance":null,"resumed":true}))
    }
    pub fn config(&self) -> ServerConfig {
        self.catalog.lock().unwrap().config.clone()
    }
    pub fn enable_owned_servers(&self) {
        let c = self.catalog.lock().unwrap();
        self.managed_servers
            .store(true, std::sync::atomic::Ordering::SeqCst);
        for b in c.devices.values() {
            b.enable_owned_server();
        }
    }
    pub fn stop_owned_servers(&self) -> Res<()> {
        let mut error = None;
        for (_, b) in self.all() {
            if let Err(e) = b.stop_owned_server() {
                error = Some(e);
            }
        }
        error.map_or(Ok(()), Err)
    }
    pub fn notify(&self, id: &str) {
        let (n, b) = {
            let c = self.catalog.lock().unwrap();
            (c.notifiers.get(id).cloned(), c.devices.get(id).cloned())
        };
        if let (Some(n), Some(b)) = (n, b) {
            let sample = b.battery_sample();
            let _ = n.process_battery(&sample);
        }
    }
    pub fn device(&self, id: &str) -> Res<Arc<Backend>> {
        if !valid_id(id) {
            return Err("invalid_device_id".into());
        }
        self.catalog
            .lock()
            .unwrap()
            .devices
            .get(id)
            .cloned()
            .ok_or_else(|| format!("unknown_device: {id}; run readb device ls"))
    }
    pub fn all(&self) -> Vec<(String, Arc<Backend>)> {
        self.catalog
            .lock()
            .unwrap()
            .devices
            .iter()
            .map(|(id, b)| (id.clone(), b.clone()))
            .collect()
    }
    /// Resolve the device and start its controller operation under the catalog
    /// lock. An independently supplied Backend cannot be relabeled as a peer.
    pub(crate) fn begin_network_operation(
        &self,
        ticket: &str,
        id: &str,
        request: &crate::network::Request,
    ) -> Res<(Arc<Backend>, String)> {
        self.network_operation(ticket, id, request, true)
    }
    pub(crate) fn preflight_network(
        &self,
        ticket: &str,
        id: &str,
        request: &crate::network::Request,
    ) -> Res<()> {
        self.network_operation(ticket, id, request, false)
            .map(|_| ())
    }
    fn network_operation(
        &self,
        ticket: &str,
        id: &str,
        request: &crate::network::Request,
        start: bool,
    ) -> Res<(Arc<Backend>, String)> {
        if !valid_id(id) {
            return Err("invalid_network_device".into());
        }
        let c = self.catalog.lock().unwrap();
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        self.catalog_store.preflight()?;
        let backend = c.devices.get(id).cloned().ok_or("unknown_device")?;
        let device = c
            .config
            .devices
            .iter()
            .find(|d| d.id == id)
            .ok_or("registry_device_scope_inconsistent")?;
        if backend.config.peer != device.peer {
            return Err("registry_device_scope_inconsistent".into());
        }
        let label = match request {
            crate::network::Request::Enroll {
                id: requested,
                key,
                address,
            } if requested == id && *address == device.peer && crate::network::valid_key(key) => {
                "network-enroll"
            }
            crate::network::Request::Remove { id: requested } if requested == id => "network-rm",
            _ => return Err("network_request_scope_mismatch".into()),
        };
        let operation = if start {
            backend.begin_network(ticket, label)?
        } else {
            backend.preflight_network(ticket)?;
            String::new()
        };
        Ok((backend, operation))
    }
    pub fn status(&self) -> Value {
        let c = self.catalog.lock().unwrap();
        json!({"schema":1,"pid":std::process::id(),"config_fingerprint":fingerprint(&c.config).ok(),"maintenance":*self.maintenance.lock().unwrap(),"catalog_cleanup_unknown":self.catalog_store.fenced(),"listener_errors":*self.listener_errors.lock().unwrap(),"devices":c.config.devices.iter().map(|d|{let mut v=c.devices[&d.id].status();v["id"]=json!(d.id);v["name"]=json!(d.name);v["kind"]=json!(d.kind);v}).collect::<Vec<_>>()})
    }
    pub fn add(&self, d: Device, listener: Option<Listener>) -> Res<Value> {
        let _allocation = crate::enrollment_journal::catalog_guard(&self.root)?;
        if crate::enrollment_journal::inspect(&self.root)?.contains_key(&d.id) {
            return Err("enrollment_pending: use original typed enrollment transaction".into());
        }
        let mut c = self.catalog.lock().unwrap();
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        let mut next = c.config.clone();
        next.devices.push(d.clone());
        if let Some(l) = listener {
            next.listeners.push(l);
        }
        next.validate()?;
        self.catalog_store.preflight()?;
        let dir = self.root.join("devices").join(&d.id);
        if dir.exists() {
            return Err(
                "device_id_has_retained_state: choose another id; keys were preserved".into(),
            );
        }
        let (b, n) = self.catalog_store.transaction(&next, Some(&d.id), || {
            private_dir(&dir)?;
            let b = Arc::new(Backend::new(Config {
                dir,
                adb: next.adb.clone(),
                token: d.token.clone(),
                identity: d.identity.clone(),
                recipient: d.recipient.clone().unwrap_or_default(),
                peer: d.peer,
                adb_port: d.adb_port,
                kind: d.kind,
                keepalive: d.keepalive.clone(),
            })?);
            let n = if b.config.recipient.is_empty() {
                None
            } else {
                Some(Arc::new(crate::notifier::Notifier::named(
                    &b.config, &d.name,
                )?))
            };
            if self
                .managed_servers
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                b.enable_owned_server();
            }
            Ok((b, n))
        })?;
        c.config = next;
        c.devices.insert(d.id.clone(), b);
        if let Some(n) = n {
            c.notifiers.insert(d.id.clone(), n);
        }
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"added":d.id,"private_state_preserved":true}))
    }
    pub fn trust(&self, id: &str, ticket: &str, pin: &str) -> Res<Value> {
        let mut c = self.catalog.lock().unwrap();
        self.catalog_store.preflight()?;
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        let b = c.devices.get(id).cloned().ok_or("unknown_device")?;
        let mut next = c.config.clone();
        let d = next
            .devices
            .iter_mut()
            .find(|d| d.id == id)
            .ok_or("unknown_device")?;
        if !d.identity.is_empty() {
            return Err("identity_already_configured".into());
        }
        d.identity = pin.into();
        next.validate()?;
        b.trust_identity(ticket, pin, || self.catalog_store.publish(&next, None))?;
        c.config = next;
        Ok(
            json!({"device":id,"identity_configured":true,"note":"Normal commands require the next fresh pinned report. Reconnect if paused."}),
        )
    }
    pub fn remove(&self, id: &str, ticket: &str) -> Res<Value> {
        let mut c = self.catalog.lock().unwrap();
        self.catalog_store.preflight()?;
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        let b = c.devices.get(id).cloned().ok_or("unknown_device")?;
        let mut next = c.config.clone();
        next.devices.retain(|d| d.id != id);
        next.listeners.retain(|l| l.device != id);
        b.retire(ticket, || self.catalog_store.publish(&next, None))?;
        c.config = next;
        c.devices.remove(id);
        c.notifiers.remove(id);
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        b.stop_owned_server()?;
        Ok(json!({"removed":id,"private_state_preserved":true,"state_path":b.config.dir}))
    }
    pub fn shutdown(&self) -> Res<()> {
        {
            let _c = self.catalog.lock().unwrap();
            self.shutdown_requested
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.closing
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(stop) = &self.web.lock().unwrap().stop {
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let mut error = None;
        for (_, b) in self.all() {
            if let Err(e) = b.begin_shutdown() {
                error = Some(e)
            }
        }
        error.map_or(Ok(()), Err)
    }
    pub fn active(&self) -> bool {
        self.all().iter().any(|(_, b)| {
            let s = b.state.lock().unwrap();
            s.gate.active || s.viewers.values().any(|v| v.active)
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pixel {
    port: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1 {
    schema: u32,
    port: u16,
    battery: i16,
}
pub fn parse_report(raw: &[u8], format: ReportFormat) -> Res<Report> {
    if raw.len() > 128 {
        return Err("report_too_large".into());
    }
    let r = match format {
        ReportFormat::V2 => return Err("v2_requires_envelope_parser".into()),
        ReportFormat::LegacyQuest => return Report::parse(raw),
        ReportFormat::LegacyPixel => {
            let p: Pixel =
                serde_json::from_slice(raw).map_err(|_| "invalid_legacy_phone_report")?;
            Report {
                port: p.port,
                battery: -1,
            }
        }
        ReportFormat::V1 => {
            let p: V1 = serde_json::from_slice(raw).map_err(|_| "invalid_report")?;
            if p.schema != 1 {
                return Err("unsupported_report_version".into());
            }
            Report {
                port: p.port,
                battery: p.battery,
            }
        }
    };
    if r.port < 1024 || !(-1..=100).contains(&r.battery) {
        return Err("invalid_report".into());
    }
    Ok(r)
}
