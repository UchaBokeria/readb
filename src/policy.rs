use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read};
use subtle::ConstantTimeEq;
pub type Res<T> = Result<T, String>;
pub fn equal(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
pub fn random() -> String {
    let mut b = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .expect("OS entropy unavailable");
    b.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub port: u16,
    pub battery: i16,
}
impl Report {
    pub fn parse(b: &[u8]) -> Res<Self> {
        if b.len() > 128 {
            return Err("report_too_large".into());
        }
        let r: Self = serde_json::from_slice(b).map_err(|_| "invalid_report")?;
        if r.port < 1024 || r.battery < -1 || r.battery > 100 {
            return Err("invalid_report".into());
        }
        Ok(r)
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Receipt {
    pub received_at: f64,
    pub port: u16,
    pub battery: i16,
    pub connected: bool,
    pub identity_verified: bool,
    pub transport_cleanup_failed: bool,
}
impl Receipt {
    pub fn fresh(&self, now: f64) -> bool {
        self.connected
            && self.identity_verified
            && !self.transport_cleanup_failed
            && self.port >= 1024
            && now >= self.received_at
            && now - self.received_at <= 180.
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub agent: String,
    pub origin: String,
    pub session: String,
    pub job: String,
    #[serde(default)]
    pub allow_sleep: bool,
}
impl Owner {
    fn valid(&self) -> bool {
        [&self.agent, &self.origin, &self.session, &self.job]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control))
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Lease {
    pub owner: Owner,
    pub started: f64,
    pub expires: f64,
    pub ttl: u64,
    #[serde(skip)]
    pub token: String,
}
#[derive(Debug, Default)]
pub struct Gate {
    pub last_owner: Option<Owner>,
    pub lease: Option<Lease>,
    pub active: bool,
    pub active_pure: bool,
    pub cancel_reason: Option<String>,
    pub cleanup_unknown: Option<String>,
}
impl Gate {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn expire(&mut self, now: f64) {
        if self.lease.as_ref().is_some_and(|l| now >= l.expires) {
            self.cancel("lease_expired");
        }
    }
    pub fn claim(&mut self, owner: Owner, now: f64, ttl: u64) -> Res<String> {
        self.expire(now);
        if let Some(s) = &self.cleanup_unknown {
            return Err(format!("cleanup_unknown: {s}"));
        }
        if self.active {
            return Err(format!(
                "cleanup_pending: {} on {} is still running {:?}; your job {:?} did not start",
                self.lease
                    .as_ref()
                    .map(|l| &l.owner.agent)
                    .unwrap_or(&"previous agent".into()),
                self.lease
                    .as_ref()
                    .map(|l| &l.owner.origin)
                    .unwrap_or(&"previous host".into()),
                self.lease
                    .as_ref()
                    .map(|l| &l.owner.job)
                    .or(self.last_owner.as_ref().map(|o| &o.job)),
                owner.job
            ));
        }
        if let Some(l) = &self.lease {
            return Err(format!(
                "device_busy: {} on {} is running {:?}; your job {:?} did not start; expires in {:.0}s",
                l.owner.agent,
                l.owner.origin,
                l.owner.job,
                owner.job,
                (l.expires - now).max(0.).ceil()
            ));
        }
        if !owner.valid() || !(10..=3600).contains(&ttl) {
            return Err("invalid_owner_or_ttl".into());
        }
        let token = random();
        self.lease = Some(Lease {
            owner,
            started: now,
            expires: now + ttl as f64,
            ttl,
            token: token.clone(),
        });
        self.cancel_reason = None;
        Ok(token)
    }
    pub fn authorize(&mut self, token: &str, now: f64) -> Res<()> {
        self.expire(now);
        if self.cleanup_unknown.is_some() {
            return Err("cleanup_unknown".into());
        }
        match &self.lease {
            Some(l) if equal(token, &l.token) => Ok(()),
            _ => Err("invalid_or_expired_job_ticket: claim an exclusive Quest job first".into()),
        }
    }
    pub fn heartbeat(&mut self, token: &str, now: f64) -> Res<()> {
        self.authorize(token, now)?;
        let l = self.lease.as_mut().unwrap();
        l.expires = now + l.ttl as f64;
        Ok(())
    }
    pub fn begin(&mut self, token: &str, now: f64, pure: bool) -> Res<()> {
        self.heartbeat(token, now)?;
        if self.active {
            return Err("job_operation_busy: previous command is still running".into());
        }
        self.active = true;
        self.active_pure = pure;
        Ok(())
    }
    pub fn finish(&mut self) {
        self.active = false;
        self.active_pure = false;
    }
    pub fn release(&mut self, token: &str, now: f64) -> Res<()> {
        self.authorize(token, now)?;
        if self.active {
            return Err("job_operation_busy".into());
        }
        self.lease = None;
        Ok(())
    }
    pub fn cancel(&mut self, why: &str) {
        if self.active && !self.active_pure {
            self.cleanup_unknown = Some(format!(
                "{why}; remote completion for the previous job must be reconciled"
            ));
        }
        self.last_owner = self
            .lease
            .as_ref()
            .map(|l| l.owner.clone())
            .or(self.last_owner.take());
        self.lease = None;
        self.cancel_reason = Some(why.into());
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub checked_at: f64,
    pub local_work_quiescent: bool,
    pub remote_work_quiescent: bool,
    pub summary: String,
    pub checked_by: String,
}
impl Gate {
    pub fn reconcile(&mut self, e: &Evidence, wall: f64) -> Res<()> {
        if self.active
            || self.cleanup_unknown.is_none()
            || !e.local_work_quiescent
            || !e.remote_work_quiescent
            || !e.checked_at.is_finite()
            || wall < e.checked_at
            || wall - e.checked_at > 60.
            || e.summary.len() < 20
            || e.summary.len() > 1000
            || e.checked_by.is_empty()
            || e.checked_by.len() > 160
            || e.summary
                .chars()
                .chain(e.checked_by.chars())
                .any(char::is_control)
        {
            return Err("reconciliation_requires_explicit_fresh_verified_quiescence".into());
        }
        self.cleanup_unknown = None;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Notice {
    pub alerted: bool,
    pub next_attempt: f64,
    pub failures: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery: Option<i16>,
}
impl Default for Notice {
    fn default() -> Self {
        Self {
            alerted: false,
            next_attempt: 0.,
            failures: 0,
            delivered_at: None,
            message_id: None,
            battery: None,
        }
    }
}
impl Notice {
    pub fn eligible(&self, battery: i16, now: f64) -> bool {
        (0..=20).contains(&battery) && !self.alerted && now >= self.next_attempt
    }
    pub fn rearm(&mut self, battery: i16) {
        if battery >= 30 {
            self.alerted = false;
            self.failures = 0;
            self.next_attempt = 0.;
        }
    }
    pub fn reserve(&mut self, now: f64) {
        self.failures = self.failures.saturating_add(1);
        self.next_attempt = now
            + (300u64.saturating_mul(1u64 << self.failures.saturating_sub(1).min(4))).min(3600)
                as f64;
    }
    pub fn success(&mut self, now: f64, id: String, battery: i16) {
        self.alerted = true;
        self.delivered_at = Some(now);
        self.message_id = Some(id);
        self.battery = Some(battery);
        self.failures = 0;
        self.next_attempt = 0.;
    }
}
