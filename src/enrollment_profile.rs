//! Private material generation and read-only allocation. No catalog, peer, file or device writes.
use crate::{
    network::{self, Policy, Snapshot},
    policy::{Res, random},
    schema::*,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub policy: Policy,
    pub snapshot: Snapshot,
    pub managed: BTreeMap<String, network::Peer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub endpoint: String,
    pub report_port: u16,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub id: String,
    pub peer: Ipv4Addr,
    pub adb_port: u16,
    pub report_bind: SocketAddr,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    schema: u8,
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub endpoint: String,
    pub peer: Ipv4Addr,
    pub adb_port: u16,
    pub report_bind: SocketAddr,
    pub report_path: String,
    pub server_peer: Ipv4Addr,
    pub server_public_key: String,
    pub policy_fingerprint: String,
    pub snapshot_fingerprint: String,
    pub config_fingerprint: String,
}
impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentPlan")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .field("adb_port", &self.adb_port)
            .finish_non_exhaustive()
    }
}
fn fingerprint(value: &impl Serialize) -> Res<String> {
    Ok(
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "enrollment_encoding_failed")?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn endpoint(value: &str) -> bool {
    value.rsplit_once(':').is_some_and(|(host, port)| {
        (1..=253).contains(&host.len())
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && port.parse::<u16>().is_ok_and(|p| p > 0)
    })
}
fn interval(route: &str) -> Res<Option<(u64, u64)>> {
    let (address, prefix) = route
        .split_once('/')
        .ok_or("enrollment_invalid_public_route")?;
    let ip = address
        .parse::<IpAddr>()
        .map_err(|_| "enrollment_invalid_public_route")?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "enrollment_invalid_public_route")?;
    match ip {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let low = u32::from(ip) & mask;
            Ok(Some((low as u64, (low | !mask) as u64)))
        }
        IpAddr::V6(_) if prefix <= 128 => Ok(None),
        _ => Err("enrollment_invalid_public_route".into()),
    }
}
impl Facts {
    pub fn validate(&self) -> Res<()> {
        self.policy.validate()?;
        if self.snapshot.server_key != self.policy.server_key
            || self.snapshot.addresses
                != vec![format!(
                    "{}/{}",
                    self.policy.server_address, self.policy.prefix
                )]
            || self.snapshot.peers.len() > 4096
        {
            return Err("enrollment_public_policy_or_snapshot_changed".into());
        }
        let mut total = 0usize;
        for (key, routes) in &self.snapshot.peers {
            total += routes.len();
            if !network::valid_key(key) || routes.len() > 256 || total > 4096 {
                return Err("enrollment_public_snapshot_too_large_or_invalid".into());
            }
            for route in routes {
                interval(route)?;
            }
        }
        let mut managed_keys = BTreeSet::new();
        let mut managed_addresses = BTreeSet::new();
        for (id, peer) in &self.managed {
            if !valid_id(id)
                || !network::valid_key(&peer.key)
                || peer.key == self.policy.server_key
                || peer.address < self.policy.first
                || peer.address > self.policy.last
                || !managed_keys.insert(&peer.key)
                || !managed_addresses.insert(peer.address)
                || self.snapshot.peers.get(&peer.key) != Some(&vec![format!("{}/32", peer.address)])
            {
                return Err("enrollment_managed_snapshot_inconsistent".into());
            }
        }
        Ok(())
    }
}
impl Plan {
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || !valid_id(&self.id)
            || self.name.is_empty()
            || self.name.len() > 100
            || self.name.chars().any(char::is_control)
            || !endpoint(&self.endpoint)
            || !self.peer.is_private()
            || !self.server_peer.is_private()
            || self.peer == self.server_peer
            || !network::valid_key(&self.server_public_key)
            || self.adb_port < 1024
            || self.report_bind.ip() != IpAddr::V4(self.server_peer)
            || self.report_bind.port() < 1024
            || self.adb_port == self.report_bind.port()
            || self.report_path != format!("/v2/{}", self.id)
            || ![
                &self.policy_fingerprint,
                &self.snapshot_fingerprint,
                &self.config_fingerprint,
            ]
            .iter()
            .all(|s| valid_hash(s))
        {
            return Err("enrollment_plan_invalid".into());
        }
        Ok(())
    }
    pub fn reservation(&self) -> Reservation {
        Reservation {
            id: self.id.clone(),
            peer: self.peer,
            adb_port: self.adb_port,
            report_bind: self.report_bind,
        }
    }
}
/// A dry-run is pure. Physical sockets must be reserved and facts rechecked on apply.
pub fn plan(
    facts: &Facts,
    config: &ServerConfig,
    request: &Request,
    reserved: &[Reservation],
    occupied: &BTreeSet<u16>,
) -> Res<Plan> {
    facts.validate()?;
    config.validate()?;
    if !valid_id(&request.id)
        || request.name.is_empty()
        || request.name.len() > 100
        || request.name.chars().any(char::is_control)
        || !endpoint(&request.endpoint)
        || request.report_port < 1024
    {
        return Err("enrollment_request_invalid".into());
    }
    if config.devices.iter().any(|d| d.id == request.id)
        || facts.managed.contains_key(&request.id)
        || reserved.iter().any(|r| r.id == request.id)
    {
        return Err("enrollment_device_id_in_use".into());
    }
    if reserved.len() > 128 {
        return Err("enrollment_reservation_limit".into());
    }
    let bind = SocketAddr::new(IpAddr::V4(facts.policy.server_address), request.report_port);
    let shared = config
        .listeners
        .iter()
        .any(|l| l.bind == bind && matches!(l.format, ReportFormat::V2))
        || reserved.iter().any(|r| r.report_bind == bind);
    if config
        .listeners
        .iter()
        .any(|l| l.bind == bind && !matches!(l.format, ReportFormat::V2))
        || (occupied.contains(&request.report_port) && !shared)
        || config
            .devices
            .iter()
            .any(|d| d.adb_port == request.report_port)
        || reserved.iter().any(|r| r.adb_port == request.report_port)
    {
        return Err("enrollment_report_port_busy".into());
    }
    let mut used = Vec::new();
    for routes in facts.snapshot.peers.values() {
        for route in routes {
            if let Some(i) = interval(route)? {
                used.push(i);
            }
        }
    }
    for peer in config
        .devices
        .iter()
        .map(|d| d.peer)
        .chain(reserved.iter().map(|r| r.peer))
    {
        let p = u32::from(peer) as u64;
        used.push((p, p));
    }
    used.sort_unstable();
    let mut candidate = u32::from(facts.policy.first) as u64;
    for (low, high) in used {
        if candidate >= low && candidate <= high {
            candidate = high + 1;
        }
    }
    if candidate > u32::from(facts.policy.last) as u64 {
        return Err("enrollment_address_range_exhausted".into());
    }
    let mut ports = occupied.clone();
    ports.extend(config.devices.iter().map(|d| d.adb_port));
    ports.extend(config.listeners.iter().map(|l| l.bind.port()));
    ports.extend(reserved.iter().map(|r| r.adb_port));
    ports.extend(reserved.iter().map(|r| r.report_bind.port()));
    ports.insert(request.report_port);
    let adb_port = (5040..=u16::MAX)
        .find(|p| !ports.contains(p))
        .ok_or("enrollment_adb_port_range_exhausted")?;
    let plan = Plan {
        schema: 1,
        id: request.id.clone(),
        name: request.name.clone(),
        kind: request.kind,
        endpoint: request.endpoint.clone(),
        peer: Ipv4Addr::from(candidate as u32),
        adb_port,
        report_bind: bind,
        report_path: format!("/v2/{}", request.id),
        server_peer: facts.policy.server_address,
        server_public_key: facts.policy.server_key.clone(),
        policy_fingerprint: fingerprint(&facts.policy)?,
        snapshot_fingerprint: fingerprint(&facts.snapshot)?,
        config_fingerprint: fingerprint(config)?,
    };
    plan.validate()?;
    Ok(plan)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMaterial {
    schema: u8,
    plan: Plan,
    private_key: String,
    public_key: String,
    token: String,
}
/// Bytes are only exposed through explicitly private APIs, never generic diagnostics.
/// ```compile_fail
/// fn cannot_serialize(m: &readb::enrollment_profile::Material) {
///     let _ = serde_json::to_string(m);
/// }
/// ```
/// ```compile_fail
/// fn cannot_debug(m: &readb::enrollment_profile::Material) {
///     let _ = format!("{m:?}");
/// }
/// ```
pub struct Material {
    stored: StoredMaterial,
}
fn keygen_tool(path: &Path) -> Res<std::path::PathBuf> {
    if !path.is_absolute() {
        return Err("enrollment_keygen_tool_must_be_absolute".into());
    }
    let canonical = fs::canonicalize(path).map_err(|_| "enrollment_keygen_tool_unavailable")?;
    for ancestor in canonical.ancestors() {
        let m = fs::metadata(ancestor).map_err(|_| "enrollment_keygen_tool_unavailable")?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("enrollment_keygen_tool_untrusted".into());
        }
    }
    if !fs::metadata(&canonical)
        .map_err(|_| "enrollment_keygen_tool_unavailable")?
        .is_file()
    {
        return Err("enrollment_keygen_tool_untrusted".into());
    }
    Ok(canonical)
}
fn key_output(mut output: crate::runner::Captured) -> Res<String> {
    if !output.ok {
        output.out.fill(0);
        output.err.fill(0);
        return Err("enrollment_keygen_failed".into());
    }
    let result = std::str::from_utf8(&output.out)
        .ok()
        .and_then(|s| s.strip_suffix('\n'))
        .filter(|s| network::valid_key(s))
        .map(str::to_owned);
    output.out.fill(0);
    output.err.fill(0);
    result.ok_or_else(|| "enrollment_keygen_invalid_output".into())
}
fn derive_public(private_key: &str, wg: &Path) -> Res<String> {
    let tool = keygen_tool(wg)?;
    let mut input = private_key.as_bytes().to_vec();
    input.push(b'\n');
    let mut command = Command::new(&tool);
    command.arg("pubkey");
    let generated = crate::runner::capture_cmd_input(command, &input, Duration::from_secs(5), 256);
    input.fill(0);
    key_output(generated.map_err(|_| "enrollment_keygen_failed")?)
}
impl Material {
    pub fn generate(plan: Plan, wg: &Path) -> Res<Self> {
        plan.validate()?;
        let tool = keygen_tool(wg)?;
        let mut command = Command::new(&tool);
        command.arg("genkey");
        let private_key = key_output(
            crate::runner::capture_cmd(command, Duration::from_secs(5), 256)
                .map_err(|_| "enrollment_keygen_failed")?,
        )?;
        let public_key = derive_public(&private_key, &tool)?;
        let material = Self {
            stored: StoredMaterial {
                schema: 1,
                plan,
                private_key,
                public_key,
                token: random(),
            },
        };
        material.validate()?;
        Ok(material)
    }
    fn validate(&self) -> Res<()> {
        self.stored.plan.validate()?;
        if self.stored.schema != 1
            || !network::valid_key(&self.stored.private_key)
            || !network::valid_key(&self.stored.public_key)
            || self.stored.public_key == self.stored.plan.server_public_key
            || !valid_hash(&self.stored.token)
        {
            return Err("enrollment_private_material_invalid".into());
        }
        let _: readb_protocol::Profile = serde_json::from_slice(&self.profile_bytes_unchecked()?)
            .map_err(|_| "enrollment_profile_invalid")?;
        Ok(())
    }
    fn profile_bytes_unchecked(&self) -> Res<Vec<u8>> {
        let profile = json!({"schema":1,"device_id":self.stored.plan.id,"server_peer":self.stored.plan.server_peer,"server_port":self.stored.plan.report_bind.port(),"device_address":self.stored.plan.peer,"token":self.stored.token,"private_key":self.stored.private_key,"server_public_key":self.stored.plan.server_public_key,"endpoint":self.stored.plan.endpoint,"keep_awake":true,"prevent_lock":true});
        let bytes =
            serde_json::to_vec(&profile).map_err(|_| "enrollment_profile_encoding_failed")?;
        let decoded: readb_protocol::Profile =
            serde_json::from_slice(&bytes).map_err(|_| "enrollment_profile_invalid")?;
        decoded.validate()?;
        Ok(bytes)
    }
    pub fn profile_bytes(&self) -> Res<Vec<u8>> {
        self.validate()?;
        self.profile_bytes_unchecked()
    }
    pub fn private_bytes(&self) -> Res<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(&self.stored).map_err(|_| "enrollment_private_encoding_failed".into())
    }
    pub fn from_private(bytes: &[u8], wg: &Path) -> Res<Self> {
        let material = Self::shape_from_private(bytes)?;
        let derived = derive_public(&material.stored.private_key, wg)?;
        if derived != material.stored.public_key {
            return Err("enrollment_keypair_mismatch".into());
        }
        Ok(material)
    }
    // Admission-only parsing. Never export or apply material from this unchecked
    // representation; delivery/catalog effects require from_private with the
    // administrator's trusted tool, not an executable supplied in private data.
    pub(crate) fn shape_from_private(bytes: &[u8]) -> Res<Self> {
        if bytes.len() > 8192 {
            return Err("enrollment_private_material_too_large".into());
        }
        let stored: StoredMaterial =
            serde_json::from_slice(bytes).map_err(|_| "enrollment_private_material_invalid")?;
        let material = Self { stored };
        material.validate()?;
        Ok(material)
    }
    pub fn public_key(&self) -> &str {
        &self.stored.public_key
    }
    pub fn plan(&self) -> &Plan {
        &self.stored.plan
    }
    pub fn public_view(&self) -> Value {
        json!({"device":self.stored.plan.id,"peer":self.stored.plan.peer,"adb_port":self.stored.plan.adb_port,"report_bind":self.stored.plan.report_bind,"identity_configured":false,"profile_deliverable":false})
    }
    pub fn server_import(&self) -> Res<DeviceImport> {
        self.validate()?;
        let import = DeviceImport {
            device: Device {
                id: self.stored.plan.id.clone(),
                name: self.stored.plan.name.clone(),
                kind: self.stored.plan.kind,
                peer: self.stored.plan.peer,
                adb_port: self.stored.plan.adb_port,
                token: self.stored.token.clone(),
                identity: String::new(),
                keepalive: Keepalive::default(),
                recipient: None,
            },
            listener: Some(Listener {
                bind: self.stored.plan.report_bind,
                path: self.stored.plan.report_path.clone(),
                device: self.stored.plan.id.clone(),
                format: ReportFormat::V2,
            }),
        };
        let config = ServerConfig {
            schema: 1,
            adb: "/not-executed".into(),
            devices: vec![import.device.clone()],
            listeners: vec![import.listener.clone().unwrap()],
        };
        config.validate()?;
        Ok(import)
    }
}
