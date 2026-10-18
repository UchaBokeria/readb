//! Linux-only root boundary. Public keys/AllowedIPs only; never request `wg dump`.
use crate::{
    network::{Kernel, Manager, Policy, Request, Snapshot, valid_key},
    policy::Res,
    runner,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Call {
    Status,
    ProviderBaseline,
    EnrollmentFacts,
    Restore,
    Reconcile,
    Apply { request: Request },
    Scoped { nonce: String, request: Request },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rpc {
    pub schema: u8,
    pub request: Call,
}
fn peer_uid(s: &UnixStream) -> Res<u32> {
    let mut c = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            c.as_mut_ptr().cast(),
            &mut n,
        )
    } != 0
        || n as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err("network_peer_credentials_unavailable".into());
    }
    Ok(unsafe { c.assume_init() }.uid)
}
pub fn handle(s: &mut UnixStream, m: &mut Manager, k: &mut impl Kernel) -> Res<()> {
    handle_recovery(s, m, k, None)
}
fn handle_recovery(
    s: &mut UnixStream,
    m: &mut Manager,
    k: &mut impl Kernel,
    health: Option<Value>,
) -> Res<()> {
    let authority = crate::network_authority::FixedAuthority {
        uid: m.coordinator_uid(),
    };
    handle_recovery_authority(s, m, k, health, &authority)
}
pub fn handle_authority(
    s: &mut UnixStream,
    m: &mut Manager,
    k: &mut impl Kernel,
    authority: &impl crate::network_authority::Authority,
) -> Res<()> {
    handle_recovery_authority(s, m, k, None, authority)
}
fn handle_recovery_authority(
    s: &mut UnixStream,
    m: &mut Manager,
    k: &mut impl Kernel,
    health: Option<Value>,
    authority: &impl crate::network_authority::Authority,
) -> Res<()> {
    s.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "network_socket_timeout_failed")?;
    s.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "network_socket_timeout_failed")?;
    let result = (|| -> Res<Value> {
        let uid = peer_uid(s)?;
        let admission = m.authorize(uid);
        // Consume the bounded request before returning a denial. Closing a Unix
        // stream with unread request bytes can reset it and discard the reason.
        let request =
            crate::wire::line(s, 4096).map_err(|_| "network_request_missing_or_too_large");
        admission?;
        let b = request?;
        let rpc: Rpc = serde_json::from_slice(&b).map_err(|_| "network_invalid_request")?;
        if rpc.schema != 1 {
            return Err("network_unsupported_schema".into());
        }
        match rpc.request {
            Call::Status => {
                let mut result = match m.status(uid, k) {
                    Ok(value) => value,
                    Err(error) if health.is_some() => {
                        json!({"fenced":m.fenced(),"interface_verified":false,"error":error})
                    }
                    Err(error) => return Err(error),
                };
                result["scoped_controller"] = json!(true);
                if let Some(health) = health {
                    result["recovery"] = health;
                }
                Ok(result)
            }
            Call::EnrollmentFacts => serde_json::to_value(m.enrollment_facts(uid, k)?)
                .map_err(|_| "network_public_facts_encoding_failed".into()),
            Call::ProviderBaseline => {
                let baseline = m.provider_baseline(uid, k)?;
                Ok(
                    json!({"schema":1,"policy_sha256":m.policy_fingerprint()?,"external_baseline":baseline,"devices":m.devices()}),
                )
            }
            Call::Restore => {
                m.restore(uid, k)?;
                Ok(json!({"restored":true}))
            }
            Call::Reconcile => {
                if uid != 0 {
                    return Err(
                        "network_controller_proxy_required: direct user mutations are disabled"
                            .into(),
                    );
                }
                m.reconcile(uid, k)?;
                Ok(json!({"reconciled":true}))
            }
            Call::Scoped { nonce, request } => {
                // Restore/reconcile are explicit host maintenance, never scoped user requests.
                if matches!(request, Request::Restore { .. }) {
                    return Ok(
                        json!({"outcome":"refused","error":"network_restore_requires_root_maintenance"}),
                    );
                }
                let digest = crate::network_controller::request_digest(&request)?;
                if authority.check(&nonce, &digest).is_err() {
                    return Ok(
                        json!({"outcome":"refused","error":"network_controller_proof_refused"}),
                    );
                }
                match m.apply(uid, request, k) {
                    Ok(()) => Ok(json!({"outcome":"applied"})),
                    Err(error) => Ok(
                        json!({"outcome":if m.fenced(){"uncertain"}else{"refused"},"error":error}),
                    ),
                }
            }
            Call::Apply { request } => {
                if uid != 0 {
                    return Err(
                        "network_controller_proxy_required: direct user mutations are disabled"
                            .into(),
                    );
                }
                m.apply(uid, request, k)?;
                Ok(json!({"applied":true}))
            }
        }
    })();
    let response = match result {
        Ok(v) => json!({"ok":true,"result":v}),
        Err(e) => json!({"ok":false,"error":e}),
    };
    let b = serde_json::to_vec(&response).map_err(|_| "network_reply_encoding_failed")?;
    s.write_all(&b)
        .and_then(|_| s.write_all(b"\n"))
        .map_err(|_| "network_reply_write_failed")?;
    Ok(())
}
pub(crate) fn program(paths: &[&str]) -> Res<PathBuf> {
    for path in paths {
        let p = Path::new(path);
        let Ok(p) = p.canonicalize() else { continue };
        let mut a = Some(p.as_path());
        let mut safe = true;
        while let Some(part) = a {
            let Ok(m) = fs::symlink_metadata(part) else {
                safe = false;
                break;
            };
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                safe = false;
                break;
            }
            a = part.parent();
        }
        if safe && fs::metadata(&p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0) {
            return Ok(p);
        }
    }
    Err("network_trusted_system_tool_missing".into())
}
pub struct LinuxKernel {
    wg: PathBuf,
    ip: PathBuf,
}
impl LinuxKernel {
    pub fn new() -> Res<Self> {
        Ok(Self {
            wg: program(&["/usr/bin/wg", "/usr/sbin/wg"])?,
            ip: program(&["/usr/bin/ip", "/usr/sbin/ip", "/sbin/ip"])?,
        })
    }
    pub fn public_key(&self, interface: &str) -> Res<String> {
        if interface.is_empty()
            || interface.len() > 15
            || !interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err("network_interface_name_invalid".into());
        }
        let raw = Self::command(&self.wg, &["show", interface, "public-key"])?;
        let key = std::str::from_utf8(&raw)
            .map_err(|_| "network_invalid_snapshot")?
            .trim();
        if !valid_key(key) {
            return Err("network_interface_key_invalid".into());
        }
        Ok(key.into())
    }
    fn command(p: &Path, args: &[&str]) -> Res<Vec<u8>> {
        let mut c = Command::new(p);
        c.args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C");
        let r = runner::capture_cmd(c, Duration::from_secs(5), 1024 * 1024)?;
        if !r.ok {
            return Err("network_system_command_failed".into());
        }
        Ok(r.out)
    }
}
fn snapshot_addresses(addresses: &[Value]) -> Res<Vec<String>> {
    if addresses.len() != 1 {
        return Err("network_interface_missing_or_ambiguous".into());
    }
    if !addresses[0]["flags"]
        .as_array()
        .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"))
    {
        return Err("network_interface_down".into());
    }
    let mut ips = Vec::new();
    for a in addresses[0]["addr_info"]
        .as_array()
        .ok_or("network_invalid_snapshot")?
    {
        let addr = a["local"]
            .as_str()
            .ok_or("network_invalid_snapshot")?
            .parse::<Ipv4Addr>()
            .map_err(|_| "network_invalid_snapshot")?;
        let prefix = a["prefixlen"]
            .as_u64()
            .filter(|n| *n <= 32)
            .ok_or("network_invalid_snapshot")?;
        ips.push(format!("{addr}/{prefix}"));
    }
    ips.sort();
    Ok(ips)
}
impl Kernel for LinuxKernel {
    fn snapshot(&mut self, p: &Policy) -> Res<Snapshot> {
        p.validate()?;
        let key = Self::command(&self.wg, &["show", &p.interface, "public-key"])?;
        let key = std::str::from_utf8(&key)
            .map_err(|_| "network_invalid_snapshot")?
            .trim()
            .to_string();
        let addresses = Self::command(
            &self.ip,
            &["-j", "-4", "address", "show", "dev", &p.interface],
        )?;
        let addresses: Vec<Value> =
            serde_json::from_slice(&addresses).map_err(|_| "network_invalid_snapshot")?;
        let ips = snapshot_addresses(&addresses)?;
        let raw = Self::command(&self.wg, &["show", &p.interface, "allowed-ips"])?;
        let raw = std::str::from_utf8(&raw).map_err(|_| "network_invalid_snapshot")?;
        let mut peers = BTreeMap::new();
        for line in raw.lines() {
            let mut cols = line.split_whitespace();
            let public = cols.next().ok_or("network_invalid_snapshot")?;
            if !valid_key(public) {
                return Err("network_invalid_snapshot".into());
            }
            let mut routes: Vec<String> = cols
                .flat_map(|s| s.split(','))
                .filter(|s| *s != "(none)" && !s.is_empty())
                .map(str::to_string)
                .collect();
            routes.sort();
            if peers.insert(public.into(), routes).is_some() {
                return Err("network_duplicate_snapshot_peer".into());
            }
        }
        Ok(Snapshot {
            server_key: key,
            addresses: ips,
            peers,
        })
    }
    fn set(&mut self, p: &Policy, key: &str, address: Option<Ipv4Addr>) -> Res<()> {
        p.validate()?;
        if !valid_key(key) {
            return Err("network_invalid_peer_key".into());
        }
        if let Some(a) = address {
            let cidr = format!("{a}/32");
            Self::command(
                &self.wg,
                &["set", &p.interface, "peer", key, "allowed-ips", &cidr],
            )?;
        } else {
            Self::command(&self.wg, &["set", &p.interface, "peer", key, "remove"])?;
        }
        Ok(())
    }
}
fn protected_root_directory(path: &Path) -> Res<()> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("network_root_path_invalid".into());
    }
    let mut part = Some(path);
    while let Some(p) = part {
        let m = fs::symlink_metadata(p).map_err(|_| "network_root_directory_unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("network_root_directory_unsafe".into());
        }
        part = p.parent();
    }
    Ok(())
}
pub(crate) fn root_policy(path: &Path) -> Res<Policy> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("network_helper_requires_root: coordinator stays unprivileged".into());
    }
    let parent = path.parent().ok_or("network_policy_path_invalid")?;
    // Pin and validate every component; root policy has no user-writable parent.
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("network_policy_path_invalid".into());
    }
    let mut d = Some(parent);
    while let Some(p) = d {
        let m = fs::symlink_metadata(p).map_err(|_| "network_policy_parent_unavailable")?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("network_policy_parent_unsafe".into());
        }
        d = p.parent();
    }
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "network_policy_unavailable")?;
    let m = f.metadata().map_err(|_| "network_policy_unavailable")?;
    if !m.is_file() || m.uid() != 0 || m.nlink() != 1 || m.mode() & 0o077 != 0 || m.len() > 4096 {
        return Err("network_private_root_policy_required".into());
    }
    let mut b = vec![];
    f.take(4097)
        .read_to_end(&mut b)
        .map_err(|_| "network_policy_read_failed")?;
    let p: Policy = serde_json::from_slice(&b).map_err(|_| "network_invalid_policy")?;
    p.validate()?;
    Ok(p)
}
const SOCKET: &str = "/run/readb-network/control.sock";
pub fn serve(policy_path: &Path, state: &Path) -> Res<()> {
    let p = root_policy(policy_path)?;
    protected_root_directory(state)?;
    crate::network_install::ensure_complete(state)?;
    let runtime = Path::new("/run/readb-network");
    match fs::create_dir(runtime) {
        Ok(()) => fs::set_permissions(runtime, fs::Permissions::from_mode(0o711))
            .map_err(|_| "network_runtime_permissions_failed")?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err("network_runtime_unavailable".into()),
    }
    let m = fs::symlink_metadata(runtime).map_err(|_| "network_runtime_unavailable")?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("network_runtime_unsafe".into());
    }
    let lock = File::open(runtime).map_err(|_| "network_runtime_unavailable")?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("network_helper_busy".into());
    }
    if let Ok(m) = fs::symlink_metadata(SOCKET) {
        if !m.file_type().is_socket()
            || ![0, p.uid].contains(&m.uid())
            || UnixStream::connect(SOCKET).is_ok()
        {
            return Err("network_socket_already_owned_or_invalid".into());
        }
        fs::remove_file(SOCKET).map_err(|_| "network_stale_socket_cleanup_failed")?;
    }
    let socket = UnixListener::bind(SOCKET).map_err(|_| "network_socket_bind_failed")?;
    let name = std::ffi::CString::new(SOCKET).unwrap();
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))
        .map_err(|_| "network_socket_permissions_failed")?;
    if unsafe { libc::chown(name.as_ptr(), p.uid, u32::MAX) } != 0 {
        return Err("network_socket_owner_failed".into());
    }
    crate::network_authority::prepare_directory(p.uid)?;
    let mut manager = Manager::open(state, p)?;
    let mut kernel = LinuxKernel::new()?;
    socket
        .set_nonblocking(true)
        .map_err(|_| "network_nonblocking_listener_failed")?;
    let origin = std::time::Instant::now();
    let now = || origin.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let mut recovery = crate::network_recovery::Recovery::new(now());
    let mut events = crate::route_events::RouteEvents::new().ok();
    if events.is_none() {
        eprintln!("readb network: link notifications unavailable; periodic checks remain active");
    }
    let mut event = false;
    let mut last_error = None;
    loop {
        if let Some(result) = recovery.tick(now(), event, &mut manager, &mut kernel) {
            recovery.completed_at(now());
            let error = result.err();
            if error != last_error {
                if let Some(reason) = &error {
                    eprintln!("readb network recovery: {reason}");
                }
                last_error = error;
            }
        }
        let (control, changed) =
            crate::route_events::wait(socket.as_raw_fd(), events.as_ref(), Duration::from_secs(1))?;
        event = false;
        if changed && let Some(watcher) = events.as_mut() {
            match watcher.drain() {
                Ok(value) => event = value,
                Err(_) => {
                    events = None;
                    eprintln!(
                        "readb network: link notifications lost; periodic checks remain active"
                    );
                }
            }
        }
        if control {
            match socket.accept() {
                Ok((mut stream, _)) => {
                    let mut health = recovery.status(now());
                    health["link_events"] = json!(events.is_some());
                    let _ = handle_recovery(&mut stream, &mut manager, &mut kernel, Some(health));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(_) => return Err("network_socket_accept_failed".into()),
            }
        }
    }
}
pub fn call(request: Call) -> Res<Value> {
    let mut s = crate::network_authority::connect_control()
        .map_err(|_| "network_helper_unavailable: inspect the narrow server helper")?;
    if crate::network_authority::peer_uid(&s)? != 0 {
        return Err("network_helper_wrong_peer: root service required".into());
    }
    s.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|_| "network_timeout_failed")?;
    s.set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|_| "network_timeout_failed")?;
    let b = serde_json::to_vec(&Rpc { schema: 1, request })
        .map_err(|_| "network_request_encoding_failed")?;
    s.write_all(&b)
        .and_then(|_| s.write_all(b"\n"))
        .map_err(|_| "network_request_write_failed")?;
    let b = crate::wire::line(&mut s, 65536).map_err(|_| "network_reply_missing_or_too_large")?;
    let v: Value = serde_json::from_slice(&b).map_err(|_| "network_invalid_reply")?;
    if v["ok"] != true {
        return Err(v["error"]
            .as_str()
            .unwrap_or("network_request_failed")
            .into());
    }
    Ok(v["result"].clone())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_state_rejects_writable_ancestors_even_when_leaf_would_be_private() {
        assert!(protected_root_directory(Path::new("/run")).is_ok());
        assert!(protected_root_directory(Path::new("/tmp")).is_err());
        assert!(protected_root_directory(Path::new("relative")).is_err());
        assert!(protected_root_directory(Path::new("/run/../tmp")).is_err());
    }
}

#[cfg(test)]
mod trusted_probe_tests {
    #[test]
    fn root_probe_refuses_user_executables_and_accepts_trusted_system_binary() {
        use std::os::unix::fs::PermissionsExt;
        let path =
            std::env::temp_dir().join(format!("readb-untrusted-probe-{}", crate::policy::random()));
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(super::program(&[path.to_str().unwrap()]).is_err());
        std::fs::remove_file(path).unwrap();
        assert!(super::program(&["/usr/bin/true", "/bin/true"]).is_ok());
    }
}
#[cfg(test)]
mod link_state_tests {
    use super::*;
    #[test]
    fn pinned_address_does_not_make_a_stopped_interface_ready() {
        let up = serde_json::json!([{"flags":["UP","LOWER_UP"],"addr_info":[{"local":"10.88.0.1","prefixlen":24}]}]);
        assert_eq!(
            snapshot_addresses(up.as_array().unwrap()).unwrap(),
            vec!["10.88.0.1/24"]
        );
        let down =
            serde_json::json!([{"flags":[],"addr_info":[{"local":"10.88.0.1","prefixlen":24}]}]);
        assert!(snapshot_addresses(down.as_array().unwrap()).is_err());
    }
}
#[cfg(test)]
mod recovery_status_tests {
    use super::*;
    struct Missing;
    impl Kernel for Missing {
        fn snapshot(&mut self, _: &Policy) -> Res<Snapshot> {
            Err("network_interface_missing".into())
        }
        fn set(&mut self, _: &Policy, _: &str, _: Option<Ipv4Addr>) -> Res<()> {
            panic!("status must never write")
        }
    }
    #[test]
    fn unavailable_interface_status_still_explains_recovery_without_writing() {
        let root =
            std::env::temp_dir().join(format!("readb-recovery-status-{}", crate::policy::random()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = Policy {
            schema: 1,
            uid: unsafe { libc::geteuid() },
            interface: "readb0".into(),
            server_key: format!("{}AAA=", "E".repeat(40)),
            server_address: "10.88.0.1".parse().unwrap(),
            prefix: 24,
            first: "10.88.0.10".parse().unwrap(),
            last: "10.88.0.20".parse().unwrap(),
        };
        let mut manager = Manager::open(&root, p).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(
                &serde_json::to_vec(&Rpc {
                    schema: 1,
                    request: Call::Status,
                })
                .unwrap(),
            )
            .unwrap();
        client.write_all(b"\n").unwrap();
        handle_recovery(
            &mut server,
            &mut manager,
            &mut Missing,
            Some(json!({"last_error":"network_interface_missing","next_check_in_ms":5000})),
        )
        .unwrap();
        let reply = crate::wire::line(&mut client, 4096).unwrap();
        let reply: Value = serde_json::from_slice(&reply).unwrap();
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["result"]["interface_verified"], false);
        assert_eq!(reply["result"]["recovery"]["next_check_in_ms"], 5000);
        assert!(!manager.fenced());
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod controller_admission_tests {
    use super::*;
    struct NoKernel(usize);
    impl Kernel for NoKernel {
        fn snapshot(&mut self, _: &Policy) -> Res<Snapshot> {
            self.0 += 1;
            Err("kernel_must_not_be_reached".into())
        }
        fn set(&mut self, _: &Policy, _: &str, _: Option<std::net::Ipv4Addr>) -> Res<()> {
            panic!("no write")
        }
    }
    #[test]
    fn direct_user_mutation_needs_coordinator_controller_proxy() {
        let uid = unsafe { libc::geteuid() };
        if uid == 0 {
            return;
        }
        let root =
            std::env::temp_dir().join(format!("readb-rpc-admission-{}", crate::policy::random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            schema: 1,
            uid,
            interface: "readb0".into(),
            server_key: format!("{}AAA=", "E".repeat(40)),
            server_address: "10.88.0.1".parse().unwrap(),
            prefix: 24,
            first: "10.88.0.100".parse().unwrap(),
            last: "10.88.0.110".parse().unwrap(),
        };
        let mut m = Manager::open(&root, policy).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(
                &serde_json::to_vec(&Rpc {
                    schema: 1,
                    request: Call::Apply {
                        request: Request::Enroll {
                            id: "phone".into(),
                            key: format!("{}AAA=", "D".repeat(40)),
                            address: "10.88.0.100".parse().unwrap(),
                        },
                    },
                })
                .unwrap(),
            )
            .unwrap();
        client.write_all(b"\n").unwrap();
        let mut k = NoKernel(0);
        handle(&mut server, &mut m, &mut k).unwrap();
        let value: Value =
            serde_json::from_slice(&crate::wire::line(&mut client, 4096).unwrap()).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(
            value["error"],
            "network_controller_proxy_required: direct user mutations are disabled"
        );
        assert_eq!(k.0, 0);
    }
}
