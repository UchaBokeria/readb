//! Platform-neutral companion messages and a single-worker report schedule.
//! Times are monotonic milliseconds on the companion, never wall-clock timestamps.
use serde::{Deserialize, Serialize};
pub type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Grant {
    Unknown,
    Granted,
    Denied,
    NotRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScreenLock {
    Unknown,
    Locked,
    Unlocked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observed {
    /// CE storage availability is NOT proof that a Quest VR lockscreen is open.
    pub credential_storage_unlocked: bool,
    pub screen_lock: ScreenLock,
    pub vpn_active: bool,
    pub notifications: Grant,
    pub discovery: Grant,
    pub secure_settings: Grant,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: u32,
    /// Random reporter-lifetime epoch. A new reporter cannot reuse a cached port.
    pub epoch: String,
    pub sequence: u64,
    pub port: Option<u16>,
    pub battery: i16,
    pub observed: Observed,
}
fn valid_epoch(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
impl Report {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err("report_too_large".into());
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_report_v2")?;
        r.validate()?;
        Ok(r)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != 2 {
            return Err("unsupported_report_version".into());
        }
        if !valid_epoch(&self.epoch)
            || self.sequence == 0
            || self.port.is_some_and(|p| p < 1024)
            || !(-1..=100).contains(&self.battery)
        {
            return Err("invalid_report_v2".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    epoch: String,
    sequence: u64,
    retired: Vec<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum EpochChange {
    First,
    Same,
    Changed,
}
impl Cursor {
    pub fn is_initialized(&self) -> bool {
        !self.epoch.is_empty()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 8192 {
            return Err("report_cursor_too_large".into());
        }
        let c: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_report_cursor")?;
        c.validate()?;
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        if self.retired.len() > 64
            || self.retired.iter().any(|s| !valid_epoch(s))
            || (self.epoch.is_empty() && (self.sequence != 0 || !self.retired.is_empty()))
            || (!self.epoch.is_empty() && (!valid_epoch(&self.epoch) || self.sequence == 0))
        {
            return Err("invalid_report_cursor".into());
        }
        Ok(())
    }
    /// Recent-epoch ordering protection, not a replacement for authenticated WireGuard.
    /// A caller persists the returned cursor before applying any report state.
    pub fn accept(&mut self, r: &Report) -> Result<EpochChange> {
        self.validate()?;
        r.validate()?;
        let change = if self.epoch.is_empty() {
            EpochChange::First
        } else if self.epoch == r.epoch {
            if r.sequence <= self.sequence {
                return Err("stale_report_sequence".into());
            }
            EpochChange::Same
        } else {
            if self.retired.contains(&r.epoch) {
                return Err("retired_report_epoch".into());
            }
            self.retired.push(self.epoch.clone());
            if self.retired.len() > 64 {
                self.retired.remove(0);
            }
            EpochChange::Changed
        };
        self.epoch = r.epoch.clone();
        self.sequence = r.sequence;
        Ok(change)
    }
}
#[derive(Clone, Debug)]
pub struct Schedule {
    port: Option<u16>,
    last_attempt: Option<u64>,
    due: u64,
    failures: u32,
    revision: u64,
    attempted_revision: u64,
    inflight: bool,
}
impl Schedule {
    pub fn new(now: u64) -> Self {
        Self {
            port: None,
            last_attempt: None,
            due: now,
            failures: 0,
            revision: 0,
            attempted_revision: 0,
            inflight: false,
        }
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    pub fn next_due(&self) -> u64 {
        self.due
    }
    pub fn due(&self, now: u64) -> bool {
        !self.inflight && now >= self.due
    }
    pub fn attempt(&mut self, now: u64) -> bool {
        if !self.due(now) {
            return false;
        }
        self.last_attempt = Some(now);
        self.attempted_revision = self.revision;
        self.inflight = true;
        self.due = now.saturating_add(5000);
        true
    }
    pub fn complete(&mut self, now: u64, success: bool) {
        if !self.inflight {
            return;
        }
        self.inflight = false;
        let delay = if success {
            self.failures = 0;
            20000
        } else {
            self.failures = self.failures.saturating_add(1);
            (5000u64.saturating_mul(1 << self.failures.saturating_sub(1).min(4))).min(60000)
        };
        self.due = now.saturating_add(delay);
        if self.revision != self.attempted_revision {
            self.expedite(now);
        }
    }
    fn expedite(&mut self, now: u64) {
        self.revision = self.revision.saturating_add(1);
        self.due = self.due.min(
            now.max(
                self.last_attempt
                    .map(|t| t.saturating_add(5000))
                    .unwrap_or(now),
            ),
        );
    }
    pub fn network_changed(&mut self, now: u64) {
        self.expedite(now);
    }
    pub fn port_changed(&mut self, now: u64, port: Option<u16>) -> Result<()> {
        if port.is_some_and(|p| p < 1024) {
            return Err("invalid_tls_port".into());
        }
        if self.port != port {
            self.port = port;
            self.expedite(now);
        }
        Ok(())
    }
}

/// A reporter lifetime. Callers generate a fresh random epoch on each service start.
/// Network I/O happens outside this state; completion must name its exact sequence.
pub struct Companion {
    epoch: String,
    sequence: u64,
    inflight: Option<u64>,
    schedule: Schedule,
}
impl Companion {
    pub fn new(epoch: String, now: u64) -> Result<Self> {
        if !valid_epoch(&epoch) {
            return Err("invalid_report_epoch".into());
        }
        Ok(Self {
            epoch,
            sequence: 0,
            inflight: None,
            schedule: Schedule::new(now),
        })
    }
    pub fn next_due(&self) -> u64 {
        self.schedule.next_due()
    }
    pub fn port_changed(&mut self, now: u64, port: Option<u16>) -> Result<()> {
        self.schedule.port_changed(now, port)
    }
    pub fn network_changed(&mut self, now: u64) {
        self.schedule.network_changed(now);
    }
    pub fn poll(&mut self, now: u64, battery: i16, observed: Observed) -> Result<Option<Report>> {
        if !self.schedule.due(now) {
            return Ok(None);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or("report_sequence_exhausted")?;
        let report = Report {
            schema: 2,
            epoch: self.epoch.clone(),
            sequence,
            port: self.schedule.port(),
            battery,
            observed,
        };
        report.validate()?;
        if !self.schedule.attempt(now) {
            return Ok(None);
        }
        self.sequence = sequence;
        self.inflight = Some(sequence);
        Ok(Some(report))
    }
    pub fn complete(&mut self, sequence: u64, now: u64, success: bool) -> Result<()> {
        if self.inflight != Some(sequence) {
            return Err("stale_report_completion".into());
        }
        self.inflight = None;
        self.schedule.complete(now, success);
        Ok(())
    }
}

/// Private enrollment material. Never format or return this value in diagnostics.
/// Android additionally validates WireGuard keys with the official parser.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: u32,
    pub device_id: String,
    pub server_peer: std::net::Ipv4Addr,
    pub server_port: u16,
    pub device_address: std::net::Ipv4Addr,
    pub token: String,
    pub private_key: String,
    pub server_public_key: String,
    pub endpoint: String,
    pub keep_awake: bool,
    pub prevent_lock: bool,
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        let key = |s: &str| {
            s.len() == 44
                && s.ends_with('=')
                && s[..43]
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        };
        let endpoint = self.endpoint.rsplit_once(':').is_some_and(|(host, port)| {
            (1..=253).contains(&host.len())
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
                && port.parse::<u16>().is_ok_and(|p| p > 0)
        });
        if self.schema != 1
            || !valid_device_id(&self.device_id)
            || !self.server_peer.is_private()
            || !self.device_address.is_private()
            || self.server_peer == self.device_address
            || self.server_port < 1024
            || self.token.len() != 64
            || !self.token.bytes().all(|c| c.is_ascii_hexdigit())
            || !key(&self.private_key)
            || !key(&self.server_public_key)
            || !endpoint
        {
            return Err("invalid_enrollment_profile".into());
        }
        Ok(())
    }
    pub fn report_path(&self) -> String {
        format!("/v2/{}", self.device_id)
    }
}

/// Same identifier contract on server and companion.
pub fn valid_device_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
