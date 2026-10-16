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
    pub web: Mutex<crate::web::Dashboard>,
    pub config_path: PathBuf,
    pub revision: std::sync::atomic::AtomicU64,
    pub closing: std::sync::atomic::AtomicBool,
    pub listener_errors: Mutex<BTreeMap<String, String>>,
    catalog: Mutex<Catalog>,
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
        let mut devices = BTreeMap::new();
        let mut notifiers = BTreeMap::new();
        for d in &config.devices {
            let dir = base.join(&d.id);
            private_dir(&dir)?;
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
        Ok(Self {
            root,
            config_path,
            revision: std::sync::atomic::AtomicU64::new(1),
            closing: std::sync::atomic::AtomicBool::new(false),
            listener_errors: Mutex::new(BTreeMap::new()),
            web: Mutex::new(Default::default()),
            catalog: Mutex::new(Catalog {
                config,
                devices,
                notifiers,
            }),
        })
    }
    pub fn config(&self) -> ServerConfig {
        self.catalog.lock().unwrap().config.clone()
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
    pub fn status(&self) -> Value {
        let c = self.catalog.lock().unwrap();
        json!({"schema":1,"pid":std::process::id(),"listener_errors":*self.listener_errors.lock().unwrap(),"devices":c.config.devices.iter().map(|d|{let mut v=c.devices[&d.id].status();v["id"]=json!(d.id);v["name"]=json!(d.name);v["kind"]=json!(d.kind);v}).collect::<Vec<_>>()})
    }
    pub fn add(&self, d: Device, listener: Option<Listener>) -> Res<Value> {
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
        let dir = self.root.join("devices").join(&d.id);
        if dir.exists() {
            return Err(
                "device_id_has_retained_state: choose another id; keys were preserved".into(),
            );
        }
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
        if let Err(e) = crate::backend::atomic(&self.config_path, &next) {
            // Only an uncommitted new empty directory is removed. Never touch retained state.
            let _ = fs::remove_dir(&b.config.dir);
            return Err(e);
        }
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
        b.trust_identity(ticket, pin, || {
            crate::backend::atomic(&self.config_path, &next)
        })?;
        c.config = next;
        Ok(
            json!({"device":id,"identity_configured":true,"note":"Normal commands require the next fresh pinned report. Reconnect if paused."}),
        )
    }
    pub fn remove(&self, id: &str, ticket: &str) -> Res<Value> {
        let mut c = self.catalog.lock().unwrap();
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("coordinator_shutdown".into());
        }
        let b = c.devices.get(id).cloned().ok_or("unknown_device")?;
        let mut next = c.config.clone();
        next.devices.retain(|d| d.id != id);
        next.listeners.retain(|l| l.device != id);
        b.retire(ticket, || crate::backend::atomic(&self.config_path, &next))?;
        c.config = next;
        c.devices.remove(id);
        c.notifiers.remove(id);
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({"removed":id,"private_state_preserved":true,"state_path":b.config.dir}))
    }
    pub fn shutdown(&self) -> Res<()> {
        {
            let _c = self.catalog.lock().unwrap();
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
