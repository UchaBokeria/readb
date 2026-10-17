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
    Reconcile,
    Apply { request: Request },
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
            Call::Status => m.status(uid, k),
            Call::Reconcile => {
                m.reconcile(uid, k)?;
                Ok(json!({"reconciled":true}))
            }
            Call::Apply { request } => {
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
fn program(paths: &[&str]) -> Res<PathBuf> {
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
        if addresses.len() != 1 {
            return Err("network_interface_missing_or_ambiguous".into());
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
fn root_policy(path: &Path) -> Res<Policy> {
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
    if unsafe { libc::chown(name.as_ptr(), p.uid, u32::MAX) } != 0 {
        return Err("network_socket_owner_failed".into());
    }
    fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o600))
        .map_err(|_| "network_socket_permissions_failed")?;
    let mut manager = Manager::open(state, p)?;
    let mut kernel = LinuxKernel::new()?;
    for stream in socket.incoming() {
        let mut s = stream.map_err(|_| "network_socket_accept_failed")?;
        let _ = handle(&mut s, &mut manager, &mut kernel);
    }
    Ok(())
}
pub fn call(request: Call) -> Res<Value> {
    let mut s = UnixStream::connect(SOCKET)
        .map_err(|_| "network_helper_unavailable: install the narrow server helper first")?;
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
