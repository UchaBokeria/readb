//! Narrow managed-peer authority. No interface/private-key/endpoint replacement.
//! Kernel effects remain fenced until their complete before/after snapshot is known.
use crate::policy::Res;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: u8,
    pub uid: u32,
    pub interface: String,
    pub server_key: String,
    pub server_address: Ipv4Addr,
    pub prefix: u8,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
}
pub(crate) fn valid_key(s: &str) -> bool {
    // WireGuard keys are canonical base64 of exactly32 bytes. Reject zero keys.
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        && b"AEIMQUYcgkosw048".contains(&s.as_bytes()[42])
        && s[..43].bytes().any(|c| c != b'A')
}
impl Policy {
    pub fn validate(&self) -> Res<()> {
        let a = u32::from(self.server_address);
        let first = u32::from(self.first);
        let last = u32::from(self.last);
        if self.schema != 1
            || self.uid == u32::MAX
            || self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            || !valid_key(&self.server_key)
            || !(8..=30).contains(&self.prefix)
        {
            return Err("network_policy_invalid".into());
        }
        let mask = u32::MAX << (32 - self.prefix);
        let low = a & mask;
        let high = low | !mask;
        let private = [(0x0a000000u32, 8u8), (0xac100000, 12), (0xc0a80000, 16)]
            .iter()
            .any(|(net, p)| {
                let m = u32::MAX << (32 - p);
                low & m == *net && high & m == *net
            });
        if !private
            || first > last
            || first <= low
            || last >= high
            || (first..=last).contains(&a)
            || a == low
            || a == high
        {
            return Err("network_policy_range_invalid".into());
        }
        Ok(())
    }
    fn admit(&self, uid: u32) -> Res<()> {
        if uid != 0 && uid != self.uid {
            Err("network_caller_denied".into())
        } else {
            Ok(())
        }
    }
    fn hash(&self) -> Res<String> {
        Ok(
            Sha256::digest(serde_json::to_vec(self).map_err(|_| "network_policy_encoding_failed")?)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub server_key: String,
    pub addresses: Vec<String>,
    pub peers: BTreeMap<String, Vec<String>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub key: String,
    pub address: Ipv4Addr,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Enroll {
        id: String,
        key: String,
        address: Ipv4Addr,
    },
    Remove {
        id: String,
    },
    Restore {
        id: String,
    },
}
pub trait Kernel {
    fn snapshot(&mut self, policy: &Policy) -> Res<Snapshot>;
    fn set(&mut self, policy: &Policy, key: &str, address: Option<Ipv4Addr>) -> Res<()>;
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    request: Request,
    before: Snapshot,
    after: Snapshot,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u8,
    policy_sha256: String,
    devices: BTreeMap<String, Peer>,
    pending: Option<Pending>,
}
type ChangePlan = (BTreeMap<String, Peer>, Snapshot, String, Option<Ipv4Addr>);
pub struct Manager {
    dir: File,
    policy: Policy,
    state: State,
    poisoned: bool,
}
fn private_directory(path: &Path) -> Res<File> {
    if !path.is_absolute() {
        return Err("network_absolute_state_required".into());
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "network_state_unavailable")?;
    let mut count = 0;
    for part in path.components() {
        let n = match part {
            Component::RootDir => continue,
            Component::Normal(n) => n,
            _ => return Err("network_state_path_invalid".into()),
        };
        let n = std::ffi::CString::new(n.as_bytes()).map_err(|_| "network_state_path_invalid")?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("network_state_unavailable_or_symlink".into());
        }
        dir = unsafe { File::from_raw_fd(fd) };
        count += 1;
    }
    let m = dir
        .metadata()
        .map_err(|_| "network_state_metadata_failed")?;
    if count == 0 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("network_private_owned_state_required".into());
    }
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("network_helper_busy".into());
    }
    Ok(dir)
}
fn read_state(dir: &File, name: &std::ffi::CStr) -> Res<Option<State>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err("network_state_read_failed".into())
        };
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata().map_err(|_| "network_state_metadata_failed")?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > 262144
    {
        return Err("network_private_regular_state_required".into());
    }
    let mut b = vec![];
    f.take(262145)
        .read_to_end(&mut b)
        .map_err(|_| "network_state_read_failed")?;
    Ok(Some(
        serde_json::from_slice(&b).map_err(|_| "network_state_invalid")?,
    ))
}
impl Manager {
    pub fn open(path: &Path, policy: Policy) -> Res<Self> {
        policy.validate()?;
        let hash = policy.hash()?;
        let dir = private_directory(path)?;
        crate::network_install::ensure_complete_fd(&dir)?;
        let disk = read_state(&dir, c"network.json")?.unwrap_or(State {
            schema: 1,
            policy_sha256: hash.clone(),
            devices: BTreeMap::new(),
            pending: None,
        });
        let marker = read_state(&dir, c"network-pending.json")?;
        let state = marker.clone().unwrap_or_else(|| disk.clone());
        if disk.schema != 1 || disk.policy_sha256 != hash {
            return Err("network_state_policy_mismatch".into());
        }
        if marker.is_none() && state.pending.is_some() {
            return Err("network_missing_durable_intent".into());
        }
        if state.schema != 1 || state.policy_sha256 != hash || state.devices.len() > 128 {
            return Err("network_state_policy_mismatch".into());
        }
        let mut m = Self {
            dir,
            policy,
            state,
            poisoned: false,
        };
        // Validate persisted authority before any kernel call, including interrupted intents.
        for (id, peer) in &m.state.devices {
            m.validate_peer(id, peer)?;
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        for peer in m.state.devices.values() {
            if !keys.insert(&peer.key) || !addresses.insert(peer.address) {
                return Err("network_duplicate_managed_peer".into());
            }
        }
        if let Some(p) = &m.state.pending {
            let (_, after, _, _) = m.plan(&p.request, &p.before)?;
            let devices = m.plan(&p.request, &p.before)?.0;
            if disk.devices != m.state.devices && disk.devices != devices {
                return Err("network_state_external_edit".into());
            }
            if after != p.after {
                return Err("network_pending_invalid".into());
            }
        }
        if marker.is_some() && m.state.pending.is_none() {
            return Err("network_intent_invalid".into());
        }
        if marker.is_none() {
            m.save()?;
        }
        Ok(m)
    }
    fn validate_peer(&self, id: &str, peer: &Peer) -> Res<()> {
        let a = u32::from(peer.address);
        if !readb_protocol::valid_device_id(id)
            || !valid_key(&peer.key)
            || peer.key == self.policy.server_key
            || a < u32::from(self.policy.first)
            || a > u32::from(self.policy.last)
        {
            return Err("network_peer_outside_scope".into());
        }
        Ok(())
    }
    fn snapshot_valid(&self, s: &Snapshot) -> Res<()> {
        self.snapshot_check(s, false)
    }
    fn snapshot_check(&self, s: &Snapshot, allow_missing: bool) -> Res<()> {
        if s.server_key != self.policy.server_key
            || s.addresses
                != vec![format!(
                    "{}/{}",
                    self.policy.server_address, self.policy.prefix
                )]
        {
            return Err("network_interface_identity_changed".into());
        }
        if s.peers.len() > 4096 {
            return Err("network_snapshot_too_large".into());
        }
        for (key, routes) in &s.peers {
            if !valid_key(key) || routes.len() > 256 {
                return Err("network_snapshot_invalid".into());
            }
            for route in routes {
                let (a, p) = route.split_once('/').ok_or("network_route_invalid")?;
                let a = a
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| "network_route_invalid")?;
                let p = p.parse::<u8>().map_err(|_| "network_route_invalid")?;
                if p > if a.is_ipv4() { 32 } else { 128 } {
                    return Err("network_route_invalid".into());
                }
            }
        }
        for peer in self.state.devices.values() {
            if allow_missing && !s.peers.contains_key(&peer.key) {
                continue;
            }
            if s.peers.get(&peer.key) != Some(&vec![format!("{}/32", peer.address)]) {
                return Err("network_managed_peer_changed: preserve external edits".into());
            }
        }
        Ok(())
    }
    fn route_available(before: &Snapshot, address: Ipv4Addr) -> Res<()> {
        for routes in before.peers.values() {
            for route in routes {
                let (a, p) = route.split_once('/').ok_or("network_route_invalid")?;
                if let Ok(a) = a.parse::<Ipv4Addr>() {
                    let p = p.parse::<u8>().map_err(|_| "network_route_invalid")?;
                    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                    if u32::from(a) & mask == u32::from(address) & mask {
                        return Err("network_address_overlap".into());
                    }
                }
            }
        }
        Ok(())
    }
    fn plan(&self, r: &Request, before: &Snapshot) -> Res<ChangePlan> {
        self.snapshot_check(before, matches!(r, Request::Restore { .. }))?;
        let mut devices = self.state.devices.clone();
        let mut after = before.clone();
        match r {
            Request::Enroll { id, key, address } => {
                let peer = Peer {
                    key: key.clone(),
                    address: *address,
                };
                self.validate_peer(id, &peer)?;
                if devices.contains_key(id) || before.peers.contains_key(key) {
                    return Err("network_peer_already_exists: no automatic adoption".into());
                }
                Self::route_available(before, *address)?;
                devices.insert(id.clone(), peer);
                if devices.len() > 128 {
                    return Err("network_device_limit".into());
                }
                after
                    .peers
                    .insert(key.clone(), vec![format!("{address}/32")]);
                Ok((devices, after, key.clone(), Some(*address)))
            }
            Request::Restore { id } => {
                let peer = devices.get(id).ok_or("network_peer_not_managed")?;
                if before.peers.contains_key(&peer.key) {
                    return Err("network_peer_already_present".into());
                }
                Self::route_available(before, peer.address)?;
                after
                    .peers
                    .insert(peer.key.clone(), vec![format!("{}/32", peer.address)]);
                let key = peer.key.clone();
                let address = peer.address;
                Ok((devices, after, key, Some(address)))
            }
            Request::Remove { id } => {
                let peer = devices.remove(id).ok_or("network_peer_not_managed")?;
                after.peers.remove(&peer.key);
                Ok((devices, after, peer.key, None))
            }
        }
    }
    fn save(&mut self) -> Res<()> {
        self.save_named(c"network.json", &self.state.clone())
    }
    fn save_named(&mut self, target: &std::ffi::CStr, state: &State) -> Res<()> {
        self.poisoned = true;
        let bytes = serde_json::to_vec(state).map_err(|_| "network_state_encode_failed")?;
        if bytes.len() > 262144 {
            return Err("network_state_too_large".into());
        }
        let name =
            std::ffi::CString::new(format!("network-{}.tmp", crate::policy::random())).unwrap();
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("network_state_create_failed".into());
        }
        let result = (|| {
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(|_| "network_state_sync_failed")?;
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err("network_state_replace_failed".into());
            }
            self.dir
                .sync_all()
                .map_err(|_| "network_state_directory_sync_failed")?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        } else {
            self.poisoned = false;
        }
        result
    }
    fn finish(&mut self, old: &State) -> Res<()> {
        self.save()?;
        let removed =
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), c"network-pending.json".as_ptr(), 0) }
                == 0;
        if !removed || self.dir.sync_all().is_err() {
            let _ = self.save_named(c"network-pending.json", old);
            self.poisoned = true;
            return Err("network_intent_cleanup_unknown".into());
        }
        Ok(())
    }
    pub(crate) fn coordinator_uid(&self) -> u32 {
        self.policy.uid
    }
    pub(crate) fn authorize(&self, uid: u32) -> Res<()> {
        self.policy.admit(uid)
    }
    pub fn status(&self, uid: u32, k: &mut impl Kernel) -> Res<serde_json::Value> {
        self.policy.admit(uid)?;
        let snapshot = k.snapshot(&self.policy)?;
        Ok(
            serde_json::json!({"fenced":self.fenced(),"interface":self.policy.interface,"interface_verified":self.snapshot_valid(&snapshot).is_ok(),"devices":self.state.devices}),
        )
    }
    pub fn devices(&self) -> &BTreeMap<String, Peer> {
        &self.state.devices
    }
    pub fn fenced(&self) -> bool {
        self.poisoned || self.state.pending.is_some()
    }
    pub fn apply(&mut self, uid: u32, r: Request, k: &mut impl Kernel) -> Res<()> {
        self.policy.admit(uid)?;
        if matches!(r, Request::Restore { .. }) && uid != 0 {
            return Err("network_restore_requires_root".into());
        }
        if self.fenced() {
            return Err("network_cleanup_unknown: reconcile before another write".into());
        }
        let before = k.snapshot(&self.policy)?;
        let (devices, after, key, address) = self.plan(&r, &before)?;
        self.state.pending = Some(Pending {
            request: r,
            before: before.clone(),
            after: after.clone(),
        });
        self.save_named(c"network-pending.json", &self.state.clone())?;
        self.save()?;
        // Read again after durable intent; external edits never get silently overwritten.
        if k.snapshot(&self.policy)? != before {
            return Err("network_changed_before_apply".into());
        }
        k.set(&self.policy, &key, address)?;
        if k.snapshot(&self.policy)? != after {
            return Err("network_apply_verification_failed".into());
        }
        let old = self.state.clone();
        self.state.devices = devices;
        self.state.pending = None;
        if let Err(e) = self.finish(&old) {
            self.state = old;
            return Err(e);
        }
        Ok(())
    }
    pub fn restore(&mut self, uid: u32, k: &mut impl Kernel) -> Res<()> {
        self.restore_up_to(uid, k, usize::MAX).map(|_| ())
    }
    pub fn restore_up_to(&mut self, uid: u32, k: &mut impl Kernel, limit: usize) -> Res<usize> {
        if limit == 0 {
            return Err("network_restore_batch_required".into());
        }
        if uid != 0 {
            return Err("network_restore_requires_root".into());
        }
        if self.fenced() {
            return Err("network_cleanup_unknown: reconcile before restore".into());
        }
        let snapshot = k.snapshot(&self.policy)?;
        self.snapshot_check(&snapshot, true)?;
        let missing: Vec<String> = self
            .state
            .devices
            .iter()
            .filter(|(_, p)| !snapshot.peers.contains_key(&p.key))
            .map(|(id, _)| id.clone())
            .collect();
        let remaining = missing.len().saturating_sub(limit);
        for id in missing.into_iter().take(limit) {
            self.apply(0, Request::Restore { id }, k)?;
        }
        Ok(remaining)
    }
    pub fn reconcile(&mut self, uid: u32, k: &mut impl Kernel) -> Res<()> {
        self.policy.admit(uid)?;
        if self.poisoned {
            return Err("network_restart_required_after_storage_error".into());
        }
        let p = self
            .state
            .pending
            .clone()
            .ok_or("network_no_pending_operation")?;
        let observed = k.snapshot(&self.policy)?;
        let old = self.state.clone();
        if observed == p.after {
            self.state.devices = self.plan(&p.request, &p.before)?.0;
        } else if observed != p.before {
            return Err(
                "network_external_change: review pending snapshots; no automatic rollback".into(),
            );
        }
        self.state.pending = None;
        if let Err(e) = self.finish(&old) {
            self.state = old;
            return Err(e);
        }
        Ok(())
    }
}
