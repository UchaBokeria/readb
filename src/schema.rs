use crate::policy::Res;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
pub const SCHEMA: u32 = 1;
pub fn valid_id(s: &str) -> bool {
    readb_protocol::valid_device_id(s)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Phone,
    Quest,
    Android,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Keepalive {
    pub enabled: bool,
    pub prevent_lock: bool,
}
impl Default for Keepalive {
    fn default() -> Self {
        Self {
            enabled: true,
            prevent_lock: true,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub peer: Ipv4Addr,
    pub adb_port: u16,
    pub token: String,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub keepalive: Keepalive,
    #[serde(default)]
    pub recipient: Option<String>,
}
#[derive(Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ReportFormat {
    #[default]
    V1,
    V2,
    LegacyQuest,
    LegacyPixel,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub bind: SocketAddr,
    pub path: String,
    pub device: String,
    #[serde(default)]
    pub format: ReportFormat,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub schema: u32,
    pub adb: PathBuf,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub listeners: Vec<Listener>,
}
impl ServerConfig {
    pub fn parse(b: &[u8]) -> Res<Self> {
        if b.len() > 1024 * 1024 {
            return Err("configuration_too_large".into());
        }
        let c: Self = serde_json::from_slice(b).map_err(|_| "invalid_configuration")?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Res<()> {
        if self.schema != SCHEMA {
            return Err("unsupported_configuration_version".into());
        }
        if !self.adb.is_absolute() || self.devices.len() > 128 {
            return Err("absolute_adb_path_and_devices_required".into());
        }
        let (mut ids, mut peers, mut ports) = (HashSet::new(), HashSet::new(), HashSet::new());
        for d in &self.devices {
            if !valid_id(&d.id)
                || d.name.is_empty()
                || d.name.len() > 100
                || d.name.chars().any(char::is_control)
                || d.peer.is_unspecified()
                || d.peer.is_multicast()
                || d.adb_port < 1024
                || d.token.len() < 40
                || d.token.len() > 256
                || d.token.chars().any(char::is_control)
                || (!d.identity.is_empty()
                    && (d.identity.len() != 64
                        || !d
                            .identity
                            .bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))))
                || !ids.insert(&d.id)
                || !peers.insert(d.peer)
                || !ports.insert(d.adb_port)
            {
                return Err("invalid_or_duplicate_device_configuration".into());
            }
            if d.recipient.as_ref().is_some_and(|r| {
                !r.strip_suffix("@s.whatsapp.net")
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
            }) {
                return Err("invalid_notification_recipient".into());
            }
        }
        let mut routes = HashSet::new();
        for l in &self.listeners {
            if !ids.contains(&l.device)
                || !l.path.starts_with('/')
                || l.path.len() > 128
                || l.path.chars().any(|c| c.is_whitespace() || c.is_control())
                || l.bind.ip().is_unspecified()
                || !routes.insert((l.bind, l.path.as_str()))
            {
                return Err("invalid_report_listener".into());
            }
        }
        Ok(())
    }
    pub fn public_view(&self) -> Value {
        json!({"schema":self.schema,"adb":self.adb,"devices":self.devices.iter().map(|d|json!({"id":d.id,"name":d.name,"kind":d.kind,"peer":d.peer,"adb_port":d.adb_port,"keepalive":d.keepalive,"identity_configured":!d.identity.is_empty()})).collect::<Vec<_>>(),"listeners":self.listeners.iter().map(|l|json!({"bind":l.bind,"path":l.path,"device":l.device,"format":l.format})).collect::<Vec<_>>()})
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceImport {
    pub device: Device,
    pub listener: Option<Listener>,
}
