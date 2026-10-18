//! Pure admission for a future narrow report-firewall broker. No I/O or commands.
//! Normalized snapshots must come from an authenticated, root-owned parser, never
//! from the enrollment caller. These values are not runtime capability proofs.
use crate::{
    network::{self, Peer, Policy},
    policy::Res,
    schema::{self, ReportFormat, ServerConfig},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr};
fn hash(value: &impl Serialize) -> String {
    Sha256::digest(serde_json::to_vec(value).expect("serializable fixed schema"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Serialize)]
pub struct Prerequisite {
    schema: u8,
    adapter: &'static str,
    available: bool,
    code: &'static str,
}
impl Prerequisite {
    pub fn available(&self) -> bool {
        self.available
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
}
pub fn prerequisite() -> Prerequisite {
    Prerequisite {
        schema: 1,
        adapter: "ufw-v1",
        available: false,
        code: "report_firewall_setup_required",
    }
}
/// Deliberately serialize-only: wire input cannot mint an authorized rule.
/// ```compile_fail
/// let _: readb::report_firewall::ReportRule = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReportRule {
    schema: u8,
    device: String,
    interface: String,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
    policy_sha256: String,
    peer_sha256: String,
}
impl ReportRule {
    pub fn from_bound(
        policy: &Policy,
        managed: &BTreeMap<String, Peer>,
        config: &ServerConfig,
        id: &str,
    ) -> Res<Self> {
        policy.validate()?;
        config.validate()?;
        let peer = managed
            .get(id)
            .ok_or("report_firewall_managed_peer_required")?;
        let device = config
            .devices
            .iter()
            .find(|d| d.id == id)
            .ok_or("report_firewall_device_required")?;
        let mut listeners = config.listeners.iter().filter(|l| l.device == id);
        let listener = listeners
            .next()
            .ok_or("report_firewall_v2_listener_required")?;
        if !schema::valid_id(id)
            || !network::valid_key(&peer.key)
            || peer.key == policy.server_key
            || peer.address < policy.first
            || peer.address > policy.last
            || peer.address != device.peer
            || managed
                .iter()
                .any(|(other, p)| other != id && (p.address == peer.address || p.key == peer.key))
            || listeners.next().is_some()
            || !matches!(listener.format, ReportFormat::V2)
            || listener.bind.ip() != policy.server_address
            || listener.bind.port() < 1024
            || config
                .devices
                .iter()
                .any(|d| d.adb_port == listener.bind.port())
            || config
                .listeners
                .iter()
                .any(|l| l.device != id && l.bind == listener.bind)
            || listener.path != format!("/v2/{id}")
        {
            return Err("report_firewall_exact_bound_tuple_required".into());
        }
        Ok(Self {
            schema: 1,
            device: id.into(),
            interface: policy.interface.clone(),
            source: peer.address,
            destination: policy.server_address,
            port: listener.bind.port(),
            policy_sha256: hash(policy),
            peer_sha256: hash(peer),
        })
    }
    pub fn selector(&self) -> Selector {
        Selector {
            interface: Some(self.interface.clone()),
            source: Cidr(self.source, 32),
            destination: Cidr(self.destination, 32),
            protocol: Protocol::Tcp,
            port: Some((self.port, self.port)),
            unknown: false,
        }
    }
    pub fn ownership_comment(&self) -> String {
        format!("readb-report:{}", hash(self))
    }
    fn entry(&self) -> Entry {
        Entry {
            selector: self.selector(),
            verdict: Verdict::Accept,
            comment: Some(self.ownership_comment()),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cidr(Ipv4Addr, u8);
impl From<Cidr> for String {
    fn from(c: Cidr) -> Self {
        format!("{}/{}", c.0, c.1)
    }
}
impl TryFrom<String> for Cidr {
    type Error = String;
    fn try_from(s: String) -> Res<Self> {
        s.parse()
    }
}
impl FromStr for Cidr {
    type Err = String;
    fn from_str(s: &str) -> Res<Self> {
        let (ip, prefix) = s.split_once('/').ok_or("report_firewall_invalid_cidr")?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| "report_firewall_invalid_cidr")?;
        let prefix: u8 = prefix.parse().map_err(|_| "report_firewall_invalid_cidr")?;
        if prefix > 32 {
            return Err("report_firewall_invalid_cidr".into());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        if u32::from(ip) & mask != u32::from(ip) || s != format!("{ip}/{prefix}") {
            return Err("report_firewall_noncanonical_cidr".into());
        }
        Ok(Self(ip, prefix))
    }
}
impl Cidr {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.1 == 0 {
            0
        } else {
            u32::MAX << (32 - self.1)
        };
        u32::from(ip) & mask == u32::from(self.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Other,
    Any,
}
/// A conservative IPv4 NEW-flow predicate. Unknown conditions may never be
/// converted into a disjoint predicate by the parser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub interface: Option<String>,
    pub source: Cidr,
    pub destination: Cidr,
    pub protocol: Protocol,
    pub port: Option<(u16, u16)>,
    pub unknown: bool,
}
impl Selector {
    fn validate(&self) -> Res<()> {
        if self.interface.as_ref().is_some_and(|s| {
            s.is_empty()
                || s.len() > 15
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }) || self.port.is_some_and(|(a, b)| a > b)
        {
            return Err("report_firewall_invalid_selector".into());
        }
        Ok(())
    }
    fn matches(&self, r: &ReportRule) -> bool {
        self.interface.as_ref().is_none_or(|i| i == &r.interface)
            && self.source.contains(r.source)
            && self.destination.contains(r.destination)
            && matches!(self.protocol, Protocol::Tcp | Protocol::Any)
            && self.port.is_none_or(|(a, b)| a <= r.port && r.port <= b)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    Continue,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub selector: Selector,
    pub verdict: Verdict,
    pub comment: Option<String>,
}
/// Ordered, flattened INPUT path through the supported UFW user insertion point.
/// `insert_at` is before the terminal return/default policy, not after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub rules: Vec<Entry>,
    pub insert_at: usize,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFact {
    pub canonical: String,
    pub uid: u32,
    pub mode: u32,
    pub regular: bool,
    pub links: u64,
    pub ancestors_root_protected: bool,
    pub sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFacts {
    pub schema: u8,
    pub adapter: String,
    pub active: bool,
    pub topology: String,
    pub tools: Vec<ToolFact>,
}
impl HostFacts {
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || !self.active
            || self.adapter != "ufw-0.36.2-iptables-1.8.10-nft"
            || self.topology != "ufw-v4-input-linear-v1"
        {
            return Err("report_firewall_unsupported_host".into());
        }
        if self.tools.len() != 2 {
            return Err("report_firewall_root_owned_tools_required".into());
        }
        for path in ["/usr/sbin/ufw", "/usr/sbin/xtables-nft-multi"] {
            let t = self
                .tools
                .iter()
                .find(|t| t.canonical == path)
                .ok_or("report_firewall_root_owned_tools_required")?;
            if t.uid != 0
                || t.mode & 0o022 != 0
                || t.mode & 0o7000 != 0
                || t.mode & 0o111 == 0
                || !t.regular
                || t.links != 1
                || !t.ancestors_root_protected
                || !valid_hash(&t.sha256)
            {
                return Err("report_firewall_root_owned_tools_required".into());
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub host: HostFacts,
    pub kernel: View,
    pub persistent: View,
    pub other_state: String,
}
impl Snapshot {
    fn validate(&self) -> Res<()> {
        self.host.validate()?;
        if !valid_hash(&self.other_state) {
            return Err("report_firewall_invalid_snapshot".into());
        }
        for view in [&self.kernel, &self.persistent] {
            if view.rules.len() > 8192 || view.insert_at > view.rules.len() {
                return Err("report_firewall_invalid_snapshot".into());
            }
            for e in &view.rules {
                e.selector.validate()?;
                if e.comment
                    .as_ref()
                    .is_some_and(|s| s.len() > 256 || s.chars().any(char::is_control))
                {
                    return Err("report_firewall_invalid_comment".into());
                }
            }
        }
        Ok(())
    }
}
fn inspect(view: &View, rule: &ReportRule, owned: bool) -> Res<Option<usize>> {
    let expected = rule.entry();
    let tag = rule.ownership_comment();
    let mut found = None;
    for (index, e) in view.rules.iter().enumerate() {
        if e.comment.as_deref() == Some(&tag)
            && (!owned || e != &expected || found.replace(index).is_some())
        {
            return Err("report_firewall_foreign_or_existing_rule".into());
        }
    }
    if owned && found.is_none() {
        return Err("report_firewall_owned_rule_missing".into());
    }
    let limit = found.unwrap_or(view.insert_at);
    if found.is_some_and(|i| i >= view.insert_at) {
        return Err("report_firewall_rule_outside_owned_insertion_path".into());
    }
    for e in &view.rules[..limit] {
        if e.selector.matches(rule) {
            if e.selector.unknown || e.verdict == Verdict::Unknown {
                return Err("report_firewall_unknown_path".into());
            }
            match e.verdict {
                Verdict::Continue => {}
                Verdict::Accept => return Err("report_firewall_foreign_or_existing_rule".into()),
                _ => return Err("report_firewall_shadowed_rule".into()),
            }
        }
    }
    // A foreign exact rule after the insertion point must not be silently adopted.
    if view.rules.iter().enumerate().any(|(i, e)| {
        Some(i) != found && e.selector == expected.selector && e.verdict == Verdict::Accept
    }) {
        return Err("report_firewall_foreign_or_existing_rule".into());
    }
    Ok(found)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Ensure,
    Revoke,
}
/// In-memory observation only. Persistence, fsync and peer credentials belong to
/// the future broker journal; serializing this receipt proves none of those.
#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    schema: u8,
    rule: ReportRule,
    action: Action,
    before_sha256: String,
    after_sha256: String,
    host_sha256: String,
}
impl Receipt {
    pub fn check_current(&self, bound: &ReportRule, s: &Snapshot) -> Res<()> {
        s.validate()?;
        if bound != &self.rule {
            return Err("report_firewall_bound_rule_changed".into());
        }
        if self.host_sha256 != hash(&s.host) {
            return Err("report_firewall_host_changed".into());
        }
        if self.action != Action::Ensure {
            return Err("report_firewall_grant_receipt_required".into());
        }
        inspect(&s.kernel, &self.rule, true)?;
        inspect(&s.persistent, &self.rule, true)?;
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Intent {
    rule: ReportRule,
    action: Action,
    before: Snapshot,
    after: Snapshot,
}
#[derive(Debug)]
pub enum Observation {
    Before,
    After(Receipt),
}
impl Intent {
    pub fn ensure(rule: ReportRule, before: Snapshot) -> Res<Self> {
        Self::new(rule, Action::Ensure, before)
    }
    pub fn revoke(bound: ReportRule, receipt: &Receipt, before: Snapshot) -> Res<Self> {
        receipt.check_current(&bound, &before)?;
        Self::new(receipt.rule.clone(), Action::Revoke, before)
    }
    fn new(rule: ReportRule, action: Action, before: Snapshot) -> Res<Self> {
        before.validate()?;
        let mut after = before.clone();
        for v in [&mut after.kernel, &mut after.persistent] {
            let index = inspect(v, &rule, action == Action::Revoke)?;
            match action {
                Action::Ensure => {
                    v.rules.insert(v.insert_at, rule.entry());
                    v.insert_at += 1;
                }
                Action::Revoke => {
                    v.rules
                        .remove(index.ok_or("report_firewall_owned_rule_missing")?);
                    v.insert_at -= 1;
                }
            }
        }
        Ok(Self {
            rule,
            action,
            before,
            after,
        })
    }
    /// Expected normalized diff, never a shell command or permission to apply.
    pub fn expected_after(&self) -> Snapshot {
        self.after.clone()
    }
    /// Lost acknowledgement: only exact before/after is recognized. A caller may
    /// retry after Before only under the future broker's durable intent+lock.
    pub fn observe(&self, observed: &Snapshot) -> Res<Observation> {
        observed.validate()?;
        if observed == &self.before {
            Ok(Observation::Before)
        } else if observed == &self.after {
            Ok(Observation::After(Receipt {
                schema: 1,
                rule: self.rule.clone(),
                action: self.action,
                before_sha256: hash(&self.before),
                after_sha256: hash(&self.after),
                host_sha256: hash(&self.after.host),
            }))
        } else {
            Err("report_firewall_snapshot_drift".into())
        }
    }
}
