use crate::{
    backend::{Config, atomic, now},
    http::bridge,
    policy::{Notice, Receipt, Res, equal},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf, sync::Mutex};
pub struct Notifier {
    state: Mutex<Notice>,
    path: PathBuf,
    recipient: String,
    label: String,
}
impl Notifier {
    pub fn new(c: &Config) -> Res<Self> {
        Self::named(c, "Android device")
    }
    pub fn named(c: &Config, label: &str) -> Res<Self> {
        let path = c.dir.join("notification.json");
        let state = if path.exists() {
            serde_json::from_slice(&fs::read(&path).map_err(|_| "notification_state_unavailable")?)
                .map_err(|_| "invalid_notification_state")?
        } else {
            Notice::default()
        };
        Ok(Self {
            state: Mutex::new(state),
            path,
            recipient: c.recipient.clone(),
            label: label.into(),
        })
    }
    pub fn process(&self, r: &Receipt) -> Res<()> {
        self.process_with(
            r,
            now(),
            || {
                let file = PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?)
                    .join(".hermes/whatsapp/session/creds.json");
                let v: Value = serde_json::from_slice(
                    &fs::read(file).map_err(|_| "self_identity_unavailable")?,
                )
                .map_err(|_| "self_identity_invalid")?;
                v["me"]["id"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or("self_identity_missing".into())
            },
            bridge,
        )
    }
    pub fn process_with(
        &self,
        r: &Receipt,
        time: f64,
        identity: impl Fn() -> Res<String>,
        bridge: impl Fn(&str, Option<&Value>) -> Res<Value>,
    ) -> Res<()> {
        if !r.fresh(time) || r.battery < 0 {
            return Ok(());
        }
        let mut s = self.state.lock().unwrap();
        s.rearm(r.battery);
        if !s.eligible(r.battery, time) {
            return atomic(&self.path, &*s);
        }
        s.reserve(time);
        atomic(&self.path, &*s)?;
        if bridge("/health", None)?["status"] != "connected" {
            return Err("bridge_disconnected".into());
        }
        let raw = identity()?;
        let (left, right) = raw.split_once('@').ok_or("self_identity_invalid")?;
        let canonical = format!("{}@{}", left.split(':').next().unwrap(), right);
        if !equal(&canonical, &self.recipient) {
            return Err("self_chat_identity_changed".into());
        }
        let result = bridge(
            "/send",
            Some(
                &json!({"chatId":self.recipient,"message":format!("{} battery is low ({}%). Please connect power.",self.label,r.battery)}),
            ),
        )?;
        if result["success"] != true {
            return Err("message_not_confirmed".into());
        }
        let id = result["messageId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("message_receipt_missing")?;
        s.success(time, id.to_string(), r.battery);
        atomic(&self.path, &*s)
    }
}
