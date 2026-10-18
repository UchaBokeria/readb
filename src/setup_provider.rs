//! Read-only admission of a deliberately small wg-quick persistence profile.
//! Never serialize/debug the saved private key or run configuration hooks.
use crate::{
    network::{Policy, Snapshot, valid_key},
    policy::Res,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub struct Saved {
    private_key: String,
    address: String,
    port: u16,
    peers: BTreeMap<String, Vec<String>>,
    digest: String,
}
#[derive(Serialize)]
pub struct Receipt {
    pub provider: &'static str,
    pub interface: String,
    pub config_sha256: String,
    pub boot_enabled: bool,
    pub saved_peers: usize,
    pub unit_sha256: Option<String>,
}
fn routes(value: &str) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        let (ip, prefix) = part.split_once('/').ok_or("provider_route_unsupported")?;
        let ip = ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "provider_route_unsupported")?;
        if prefix != "32" || !ip.is_private() {
            return Err("provider_private_ipv4_host_routes_required".into());
        }
        out.push(format!("{ip}/32"));
    }
    out.sort();
    out.dedup();
    if out.is_empty() {
        return Err("provider_route_required".into());
    }
    Ok(out)
}
impl Saved {
    pub fn parse(bytes: &[u8]) -> Res<Self> {
        if bytes.len() > 128 * 1024 {
            return Err("provider_config_too_large".into());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| "provider_config_invalid")?;
        if text.bytes().any(|c| c < 32 && !b"\n\r\t".contains(&c)) {
            return Err("provider_config_invalid".into());
        }
        let mut section = 0;
        let mut interface = BTreeMap::new();
        let mut peer = BTreeMap::new();
        let mut peers = BTreeMap::new();
        fn finish(
            p: &mut BTreeMap<String, String>,
            peers: &mut BTreeMap<String, Vec<String>>,
        ) -> Res<()> {
            if p.is_empty() {
                return Err("provider_incomplete_peer".into());
            }
            let key = p.remove("PublicKey").ok_or("provider_peer_key_required")?;
            if !valid_key(&key) {
                return Err("provider_peer_key_invalid".into());
            }
            let ips = routes(
                &p.remove("AllowedIPs")
                    .ok_or("provider_peer_routes_required")?,
            )?;
            if peers.insert(key, ips).is_some() {
                return Err("provider_duplicate_peer".into());
            }
            p.clear();
            Ok(())
        }
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap().trim();
            if line.is_empty() {
                continue;
            }
            if line == "[Interface]" {
                if section != 0 {
                    return Err("provider_duplicate_interface".into());
                }
                section = 1;
                continue;
            }
            if line == "[Peer]" {
                if section == 0 {
                    return Err("provider_interface_required".into());
                }
                if section == 2 {
                    finish(&mut peer, &mut peers)?;
                }
                section = 2;
                continue;
            }
            let (name, value) = line.split_once('=').ok_or("provider_config_unsupported")?;
            let name = name.trim();
            let value = value.trim();
            if value.is_empty() {
                return Err("provider_config_empty_value".into());
            }
            let target = match section {
                1 => &mut interface,
                2 => &mut peer,
                _ => return Err("provider_interface_required".into()),
            };
            let allowed = if section == 1 {
                [
                    "PrivateKey",
                    "Address",
                    "ListenPort",
                    "SaveConfig",
                    "MTU",
                    "Table",
                ]
                .as_slice()
            } else {
                ["PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"].as_slice()
            };
            if !allowed.contains(&name)
                || target.insert(name.to_string(), value.to_string()).is_some()
            {
                return Err("provider_config_unsupported_or_duplicate".into());
            }
            match name {
                "SaveConfig" if value != "false" => {
                    return Err("provider_save_config_must_be_false".into());
                }
                "Table" if value != "auto" => return Err("provider_table_unsupported".into()),
                "MTU"
                    if value
                        .parse::<u32>()
                        .ok()
                        .is_none_or(|n| !(576..=65535).contains(&n)) =>
                {
                    return Err("provider_mtu_invalid".into());
                }
                "PersistentKeepalive" if value.parse::<u16>().is_err() => {
                    return Err("provider_keepalive_invalid".into());
                }
                "Endpoint"
                    if value.chars().any(char::is_whitespace)
                        || value.rsplit_once(':').is_none_or(|(h, p)| {
                            h.is_empty() || p.parse::<u16>().ok().is_none_or(|n| n == 0)
                        }) =>
                {
                    return Err("provider_endpoint_invalid".into());
                }
                _ => {}
            }
        }
        if section == 2 {
            finish(&mut peer, &mut peers)?;
        }
        let private_key = interface
            .remove("PrivateKey")
            .ok_or("provider_private_key_required")?;
        if !valid_key(&private_key) {
            return Err("provider_private_key_invalid".into());
        }
        let address = interface
            .remove("Address")
            .ok_or("provider_address_required")?;
        let (ip, prefix) = address
            .split_once('/')
            .ok_or("provider_single_ipv4_address_required")?;
        let ip = ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "provider_single_ipv4_address_required")?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| "provider_single_ipv4_address_required")?;
        if !ip.is_private() || !(8..=30).contains(&prefix) {
            return Err("provider_single_ipv4_address_required".into());
        }
        let port = interface
            .remove("ListenPort")
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p > 0)
            .ok_or("provider_listener_required")?;
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Self {
            private_key,
            address: format!("{ip}/{prefix}"),
            port,
            peers,
            digest,
        })
    }
    pub(crate) fn public_key(&self) -> Res<String> {
        let wg = crate::network_runtime::program(&["/usr/bin/wg", "/usr/sbin/wg"])?;
        let mut cmd = std::process::Command::new(wg);
        cmd.arg("pubkey").env_clear().env("LANG", "C");
        let result = crate::runner::capture_cmd_input(
            cmd,
            format!("{}\n", self.private_key).as_bytes(),
            std::time::Duration::from_secs(3),
            128,
        )?;
        if !result.ok {
            return Err("provider_public_key_derivation_failed".into());
        }
        let key = String::from_utf8(result.out).map_err(|_| "provider_public_key_invalid")?;
        let key = key.trim();
        if !valid_key(key) {
            return Err("provider_public_key_invalid".into());
        }
        Ok(key.into())
    }
}
pub fn verify(
    saved: &Saved,
    policy: &Policy,
    live: &Snapshot,
    derived_key: &str,
    listen_port: u16,
    enabled: bool,
) -> Res<Receipt> {
    policy.validate()?;
    if !enabled {
        return Err("provider_boot_not_enabled".into());
    }
    if derived_key != policy.server_key
        || live.server_key != policy.server_key
        || saved.address != format!("{}/{}", policy.server_address, policy.prefix)
        || live.addresses != vec![saved.address.clone()]
        || saved.port != listen_port
    {
        return Err("provider_saved_live_identity_mismatch".into());
    }
    let mut actual = live.peers.clone();
    for routes in actual.values_mut() {
        routes.sort();
        routes.dedup();
    }
    if actual != saved.peers {
        return Err("provider_unpersisted_or_changed_peers".into());
    }
    let mut occupied = BTreeSet::new();
    let mask = u32::MAX << (32 - policy.prefix);
    let network = u32::from(policy.server_address) & mask;
    for routes in actual.values() {
        for r in routes {
            let (ip, _) = r.split_once('/').ok_or("provider_route_unsupported")?;
            let ip = ip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| "provider_route_unsupported")?;
            if u32::from(ip) & mask != network
                || ip == policy.server_address
                || !occupied.insert(ip)
            {
                return Err("provider_peer_scope_or_overlap".into());
            }
        }
    }
    Ok(Receipt {
        provider: "wg_quick",
        interface: policy.interface.clone(),
        config_sha256: saved.digest.clone(),
        boot_enabled: true,
        saved_peers: saved.peers.len(),
        unit_sha256: None,
    })
}

pub fn verify_unit(facts: &str, interface: &str, program: &str) -> Res<String> {
    let mut values = BTreeMap::new();
    for line in facts.lines() {
        let (k, v) = line.split_once('=').ok_or("provider_unit_invalid")?;
        if values.insert(k, v).is_some() {
            return Err("provider_unit_duplicate_property".into());
        }
    }
    if values.get("LoadState") != Some(&"loaded") || values.get("UnitFileState") != Some(&"enabled")
    {
        return Err("provider_durable_boot_unit_required".into());
    }
    for field in [
        "DropInPaths",
        "ExecStartPre",
        "ExecStartPost",
        "EnvironmentFiles",
        "RootDirectory",
        "RootImage",
    ] {
        if values.get(field) != Some(&"") {
            return Err("provider_unit_overrides_or_hooks_unsupported".into());
        }
    }
    if !matches!(values.get("User"), Some(&"" | &"root")) {
        return Err("provider_root_unit_required".into());
    }
    let start = values
        .get("ExecStart")
        .ok_or("provider_exec_start_required")?;
    let expected = format!("{program} up {interface}");
    let argv = start
        .split_once("argv[]=")
        .and_then(|(_, s)| s.split_once(';'))
        .map(|(a, _)| a.trim());
    let path = start
        .split_once("path=")
        .and_then(|(_, s)| s.split_once(';'))
        .map(|(a, _)| a.trim());
    if argv != Some(expected.as_str())
        || path != Some(program)
        || start.matches("argv[]=").count() != 1
        || start.matches("path=").count() != 1
    {
        return Err("provider_exec_start_mismatch".into());
    }
    let fragment = values
        .get("FragmentPath")
        .ok_or("provider_fragment_required")?;
    let p = std::path::Path::new(fragment);
    if !p.is_absolute() || p.file_name().is_none_or(|s| s != "wg-quick@.service") {
        return Err("provider_vendor_unit_required".into());
    }
    Ok((*fragment).into())
}
pub(crate) fn protected_file(path: &std::path::Path, private: bool) -> Res<Vec<u8>> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
        path::Component,
    };
    if !path.is_absolute() {
        return Err("provider_absolute_root_path_required".into());
    }
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "provider_root_unavailable")?;
    let parts = path
        .components()
        .filter(|c| *c != Component::RootDir)
        .collect::<Vec<_>>();
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err("provider_path_unsafe".into());
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "provider_path_unsafe")?;
        let last = i + 1 == parts.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err("provider_file_unavailable_or_unsafe".into());
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let m = dir.metadata().map_err(|_| "provider_file_unavailable")?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("provider_root_owned_path_required".into());
        }
        if last {
            if !m.is_file()
                || m.nlink() != 1
                || m.len() > 128 * 1024
                || (private && m.mode() & 0o777 != 0o600)
            {
                return Err("provider_file_permissions_or_size_invalid".into());
            }
            let mut bytes = Vec::new();
            dir.take(128 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "provider_file_read_failed")?;
            if bytes.len() > 128 * 1024 {
                return Err("provider_config_too_large".into());
            }
            return Ok(bytes);
        }
    }
    Err("provider_file_required".into())
}
pub fn empty_property(value: &serde_json::Value, signature: &str) -> Res<()> {
    if value["type"] != signature || value["data"].as_array().is_none_or(|a| !a.is_empty()) {
        return Err("provider_unit_array_not_verified_empty".into());
    }
    Ok(())
}
fn bus(args: &[&str]) -> Res<serde_json::Value> {
    let bin = crate::network_runtime::program(&["/usr/bin/busctl", "/bin/busctl"])?;
    let mut cmd = std::process::Command::new(bin);
    cmd.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .arg("--json=short")
        .args(args);
    let r = crate::runner::capture_cmd(cmd, std::time::Duration::from_secs(5), 16384)?;
    if !r.ok {
        return Err("provider_unit_bus_observation_failed".into());
    }
    serde_json::from_slice(&r.out).map_err(|_| "provider_unit_bus_reply_invalid".into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedEvidence {
    schema: u8,
    policy_sha256: String,
    external_baseline: Snapshot,
    devices: BTreeMap<String, crate::network::Peer>,
}
// Pure validation, not authentication. Only inspect_managed obtains this value
// from the credential-checked root helper; never accept caller-supplied evidence.
fn managed_baseline(
    policy: &Policy,
    live: &Snapshot,
    evidence: &serde_json::Value,
) -> Res<Snapshot> {
    policy.validate()?;
    let e: ManagedEvidence = serde_json::from_value(evidence.clone())
        .map_err(|_| "provider_managed_evidence_invalid")?;
    let digest: String =
        Sha256::digest(serde_json::to_vec(policy).map_err(|_| "provider_policy_encoding_failed")?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
    if e.schema != 1 || e.policy_sha256 != digest || e.devices.len() > 4096 {
        return Err("provider_managed_policy_mismatch".into());
    }
    let mut reconstructed = e.external_baseline.clone();
    let mut addresses = BTreeSet::new();
    for (id, peer) in e.devices {
        if !readb_protocol::valid_device_id(&id)
            || !valid_key(&peer.key)
            || peer.key == policy.server_key
            || peer.address < policy.first
            || peer.address > policy.last
            || !addresses.insert(peer.address)
            || reconstructed.peers.contains_key(&peer.key)
        {
            return Err("provider_managed_peer_invalid_or_overlap".into());
        }
        reconstructed
            .peers
            .insert(peer.key, vec![format!("{}/32", peer.address)]);
    }
    let mut current = live.clone();
    for snapshot in [&mut current, &mut reconstructed] {
        for routes in snapshot.peers.values_mut() {
            routes.sort();
            routes.dedup();
        }
    }
    if current != reconstructed {
        return Err("provider_managed_live_snapshot_changed".into());
    }
    Ok(e.external_baseline)
}
/// Read-only managed-provider inspection. Authenticate root helper evidence,
/// bind its policy and complete current snapshot, then compare only the exact
/// external baseline to saved VPN state. Recheck helper evidence before return.
/// This does not compare the original setup receipt or authorize an upgrade.
pub fn inspect_managed(policy: &Policy, listen_port: u16) -> Res<Receipt> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("provider_inspection_requires_root".into());
    }
    let evidence = crate::network_runtime::call(crate::network_runtime::Call::ProviderBaseline)?;
    let receipt = inspect_inner(policy, listen_port, Some(&evidence))?;
    if crate::network_runtime::call(crate::network_runtime::Call::ProviderBaseline)? != evidence {
        return Err("provider_managed_evidence_changed_during_inspection".into());
    }
    Ok(receipt)
}
pub fn inspect(policy: &Policy, listen_port: u16) -> Res<Receipt> {
    inspect_inner(policy, listen_port, None)
}
fn inspect_inner(
    policy: &Policy,
    listen_port: u16,
    evidence: Option<&serde_json::Value>,
) -> Res<Receipt> {
    use crate::network::Kernel;
    if unsafe { libc::geteuid() } != 0 {
        return Err("provider_inspection_requires_root".into());
    }
    policy.validate()?;
    let path = std::path::PathBuf::from(format!("/etc/wireguard/{}.conf", policy.interface));
    let bytes = protected_file(&path, true)?;
    let saved = Saved::parse(&bytes)?;
    let key = saved.public_key()?;
    let wg_quick = crate::network_runtime::program(&["/usr/bin/wg-quick", "/usr/sbin/wg-quick"])?;
    let ctl = crate::network_runtime::program(&["/usr/bin/systemctl", "/bin/systemctl"])?;
    let name = format!("wg-quick@{}.service", policy.interface);
    let mut cmd = std::process::Command::new(ctl);
    cmd.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .args(["show", "--all", &name]);
    for p in [
        "LoadState",
        "UnitFileState",
        "DropInPaths",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "EnvironmentFiles",
        "User",
        "RootDirectory",
        "RootImage",
        "FragmentPath",
    ] {
        cmd.arg(format!("--property={p}"));
    }
    let result = crate::runner::capture_cmd(cmd, std::time::Duration::from_secs(5), 16384)?;
    if !result.ok {
        return Err("provider_unit_observation_failed".into());
    }
    let mut facts = String::from_utf8(result.out).map_err(|_| "provider_unit_invalid")?;
    // systemctl's human printer omits empty execution/environment arrays, even
    // with --all. A missing property is not evidence of emptiness. Query the
    // typed system bus and fail closed on unavailable/unsupported properties.
    let object = bus(&[
        "call",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "GetUnit",
        "s",
        &name,
    ])?;
    if object["type"] != "o" {
        return Err("provider_unit_object_invalid".into());
    }
    let unit_object = object["data"]
        .as_array()
        .filter(|a| a.len() == 1)
        .and_then(|a| a[0].as_str())
        .filter(|p| p.starts_with("/org/freedesktop/systemd1/unit/"))
        .ok_or("provider_unit_object_invalid")?;
    for (field, signature) in [
        ("ExecStartPre", "a(sasbttttuii)"),
        ("ExecStartPost", "a(sasbttttuii)"),
        ("EnvironmentFiles", "a(sb)"),
    ] {
        let value = bus(&[
            "get-property",
            "org.freedesktop.systemd1",
            unit_object,
            "org.freedesktop.systemd1.Service",
            field,
        ])?;
        empty_property(&value, signature)?;
        if !facts.lines().any(|l| l.starts_with(&format!("{field}="))) {
            facts.push_str(&format!("{field}=\n"));
        }
    }
    let fragment = verify_unit(
        &facts,
        &policy.interface,
        wg_quick.to_str().ok_or("provider_program_path_invalid")?,
    )?;
    let unit_bytes = protected_file(std::path::Path::new(&fragment), false)?;
    let wg = crate::network_runtime::program(&["/usr/bin/wg", "/usr/sbin/wg"])?;
    let mut probe = std::process::Command::new(wg);
    probe
        .env_clear()
        .env("LANG", "C")
        .args(["show", &policy.interface, "listen-port"]);
    let result = crate::runner::capture_cmd(probe, std::time::Duration::from_secs(3), 128)?;
    if !result.ok
        || std::str::from_utf8(&result.out)
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            != Some(listen_port)
    {
        return Err("provider_live_listener_mismatch".into());
    }
    let mut kernel = crate::network_runtime::LinuxKernel::new()?;
    let live = kernel.snapshot(policy)?;
    let live = match evidence {
        Some(evidence) => managed_baseline(policy, &live, evidence)?,
        None => live,
    };
    let mut receipt = verify(&saved, policy, &live, &key, listen_port, true)?;
    receipt.unit_sha256 = Some(
        Sha256::digest(&unit_bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    );
    if protected_file(std::path::Path::new(&fragment), false)? != unit_bytes {
        return Err("provider_unit_changed_during_inspection".into());
    }
    if protected_file(&path, true)? != bytes {
        return Err("provider_config_changed_during_inspection".into());
    }
    Ok(receipt)
}

/// Authenticated external snapshot for software-only upgrade plan reconstruction.
/// Retains the original recorded baseline while real managed peers exist.
pub(crate) fn inspect_managed_baseline(
    policy: &Policy,
    listen_port: u16,
) -> Res<(Receipt, Snapshot)> {
    use crate::network::Kernel;
    if unsafe { libc::geteuid() } != 0 {
        return Err("provider_inspection_requires_root".into());
    }
    let evidence = crate::network_runtime::call(crate::network_runtime::Call::ProviderBaseline)?;
    let mut kernel = crate::network_runtime::LinuxKernel::new()?;
    let baseline = managed_baseline(policy, &kernel.snapshot(policy)?, &evidence)?;
    let receipt = inspect_inner(policy, listen_port, Some(&evidence))?;
    if crate::network_runtime::call(crate::network_runtime::Call::ProviderBaseline)? != evidence {
        return Err("provider_managed_evidence_changed_during_inspection".into());
    }
    Ok((receipt, baseline))
}

#[cfg(test)]
mod managed_tests {
    use super::*;
    fn key(c: char) -> String {
        format!("{}AAA=", c.to_string().repeat(40))
    }
    fn fixture() -> (Policy, Snapshot, serde_json::Value) {
        let policy = Policy {
            schema: 1,
            uid: 1000,
            interface: "readb0".into(),
            server_key: key('E'),
            server_address: "10.88.0.1".parse().unwrap(),
            prefix: 24,
            first: "10.88.0.100".parse().unwrap(),
            last: "10.88.0.110".parse().unwrap(),
        };
        let baseline = Snapshot {
            server_key: key('E'),
            addresses: vec!["10.88.0.1/24".into()],
            peers: BTreeMap::from([(key('D'), vec!["10.88.0.5/32".into()])]),
        };
        let mut live = baseline.clone();
        live.peers.insert(key('C'), vec!["10.88.0.100/32".into()]);
        let digest: String = Sha256::digest(serde_json::to_vec(&policy).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let evidence = serde_json::json!({"schema":1,"policy_sha256":digest,"external_baseline":baseline,"devices":{"phone":{"key":key('C'),"address":"10.88.0.100"}}});
        (policy, live, evidence)
    }
    #[test]
    fn managed_evidence_requires_exact_policy_and_complete_current_snapshot() {
        let (p, live, evidence) = fixture();
        let baseline = managed_baseline(&p, &live, &evidence).unwrap();
        assert_eq!(baseline.peers.len(), 1);
        assert!(baseline.peers.contains_key(&key('D')));
        let saved = Saved::parse(format!("[Interface]\nPrivateKey={}\nAddress=10.88.0.1/24\nListenPort=51820\n[Peer]\nPublicKey={}\nAllowedIPs=10.88.0.5/32\n",key('B'),key('D')).as_bytes()).unwrap();
        assert!(verify(&saved, &p, &baseline, &key('E'), 51820, true).is_ok());
        assert!(verify(&saved, &p, &live, &key('E'), 51820, true).is_err());
        let mut unknown_live = live.clone();
        unknown_live
            .peers
            .insert(key('F'), vec!["10.88.0.101/32".into()]);
        let mut unknown_evidence = evidence.clone();
        unknown_evidence["external_baseline"]["peers"][key('F')] =
            serde_json::json!(["10.88.0.101/32"]);
        let external = managed_baseline(&p, &unknown_live, &unknown_evidence).unwrap();
        assert!(external.peers.contains_key(&key('F')));
        assert!(verify(&saved, &p, &external, &key('E'), 51820, true).is_err());

        let mut bad = evidence.clone();
        bad["policy_sha256"] = serde_json::json!("f".repeat(64));
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence.clone();
        bad["devices"] = serde_json::json!({});
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence.clone();
        bad["external_baseline"]["peers"][key('D')] = serde_json::json!(["10.88.0.6/32"]);
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut changed = live.clone();
        changed.peers.remove(&key('C'));
        assert!(managed_baseline(&p, &changed, &evidence).is_err());
        changed = live.clone();
        changed
            .peers
            .insert(key('F'), vec!["10.88.0.101/32".into()]);
        assert!(managed_baseline(&p, &changed, &evidence).is_err());
        let mut bad = evidence.clone();
        bad["devices"]["phone"]["address"] = serde_json::json!("10.88.0.102");
        assert!(managed_baseline(&p, &live, &bad).is_err());
    }
    #[test]
    fn managed_evidence_rejects_alias_overlap_unknown_shape_and_wrong_scope() {
        let (p, live, evidence) = fixture();
        let mut bad = evidence.clone();
        bad["devices"]["alias"] = bad["devices"]["phone"].clone();
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence.clone();
        bad["external_baseline"]["peers"][key('C')] = serde_json::json!(["10.88.0.100/32"]);
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence.clone();
        bad["ignored"] = serde_json::json!(true);
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence.clone();
        bad["devices"]["phone"]["address"] = serde_json::json!("10.88.0.99");
        assert!(managed_baseline(&p, &live, &bad).is_err());
        let mut bad = evidence;
        bad["schema"] = serde_json::json!(2);
        assert!(managed_baseline(&p, &live, &bad).is_err());
    }
}
