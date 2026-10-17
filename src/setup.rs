//! Read-only provisioning plan. Applying network changes is deliberately separate.
use crate::{policy::Res, runner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, net::Ipv4Addr, path::Path, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Create,
    Reuse,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub endpoint: String,
    pub interface: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub listen_port: u16,
    pub mode: NetworkMode,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub os: String,
    pub arch: String,
    pub libc: String,
    pub init: String,
    pub adb: Option<String>,
    pub wg: bool,
    pub wg_quick: bool,
    pub ip: bool,
    pub privilege: bool,
    pub free_bytes: Option<u64>,
    pub storage_writable: bool,
    pub interface_exists: bool,
    pub interface_wireguard: Option<bool>,
    pub interface_address_matches: Option<bool>,
    pub interface_listen_port: Option<u16>,
    pub route_overlap: Option<bool>,
    pub port_in_use: Option<bool>,
}
#[derive(Serialize)]
pub struct Blocker {
    pub code: &'static str,
    pub next: &'static str,
}
#[derive(Serialize)]
pub struct SetupPlan {
    pub schema: u8,
    pub plan_sha256: String,
    pub ready: bool,
    pub applied: bool,
    pub options: Options,
    pub facts: Facts,
    pub network_action: &'static str,
    pub phases: Vec<&'static str>,
    pub blockers: Vec<Blocker>,
}
impl Options {
    pub fn validate(&self) -> Res<()> {
        let (host, port) = self
            .endpoint
            .rsplit_once(':')
            .ok_or("endpoint_requires_host_port")?;
        if host.is_empty()
            || host.starts_with('-')
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || port.parse::<u16>().ok().is_none_or(|p| p == 0)
        {
            return Err("invalid_endpoint_host_port".into());
        }
        if self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("invalid_interface_name".into());
        }
        if !(8..=30).contains(&self.prefix) || self.listen_port == 0 || !self.address.is_private() {
            return Err("private_ipv4_host_prefix_8_to_30_required".into());
        }
        let mask = u32::MAX << (32 - self.prefix);
        let network = u32::from(self.address) & mask;
        let broadcast = network | !mask;
        if !Ipv4Addr::from(network).is_private() || !Ipv4Addr::from(broadcast).is_private() {
            return Err("entire_subnet_must_be_private".into());
        }
        let host = u32::from(self.address) & !mask;
        if host == 0 || host == !mask {
            return Err("network_or_broadcast_address".into());
        }
        Ok(())
    }
}
pub fn build_plan(options: Options, facts: Facts) -> Res<SetupPlan> {
    options.validate()?;
    // Bind intent, not changing free space, sockets or dependency availability.
    // Apply must always inspect current facts again, even for a matching journal.
    let digest =
        Sha256::digest(serde_json::to_vec(&(1u8, &options)).map_err(|_| "plan_encoding_failed")?);
    let mut p = SetupPlan {
        schema: 1,
        plan_sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
        ready: false,
        applied: false,
        network_action: match options.mode {
            NetworkMode::Create => "create_dedicated",
            NetworkMode::Reuse => "inspect_existing_only",
        },
        options,
        facts,
        phases: vec![
            "preflight",
            "dependencies",
            "network",
            "coordinator",
            "persistence",
            "enrollment",
            "acceptance",
        ],
        blockers: Vec::new(),
    };
    macro_rules! block {
        ($condition:expr,$code:literal,$next:literal) => {
            if $condition {
                p.blockers.push(Blocker {
                    code: $code,
                    next: $next,
                });
            }
        };
    }
    block!(
        p.facts.os != "linux",
        "linux_required",
        "Run setup on the Linux server."
    );
    block!(
        !matches!(p.facts.arch.as_str(), "x86_64" | "aarch64"),
        "architecture_unsupported",
        "Build and verify readb for this architecture first."
    );
    block!(
        !matches!(p.facts.libc.as_str(), "gnu" | "musl"),
        "libc_unknown",
        "Verify the native binary toolchain first."
    );
    block!(
        !matches!(p.facts.init.as_str(), "systemd" | "openrc"),
        "init_unsupported",
        "Use documented foreground mode until a persistence adapter exists."
    );
    block!(
        p.facts.adb.is_none(),
        "adb_missing",
        "Install platform-tools; an SDK download requires separate explicit license consent."
    );
    block!(
        !p.facts.wg || !p.facts.wg_quick,
        "wireguard_tools_missing",
        "Install wireguard-tools using your distribution package manager."
    );
    block!(
        !p.facts.ip,
        "iproute_missing",
        "Install iproute2 using your distribution package manager."
    );
    block!(
        !p.facts.privilege,
        "privilege_missing",
        "Provision the narrow root network helper; keep the coordinator unprivileged."
    );
    block!(
        p.facts.free_bytes.is_none(),
        "disk_unknown",
        "Check writable server storage capacity."
    );
    block!(
        !p.facts.storage_writable,
        "storage_not_writable",
        "Use an existing writable home directory on a writable filesystem."
    );
    block!(
        p.facts.free_bytes.is_some_and(|b| b < 512 * 1024 * 1024),
        "disk_low",
        "Free at least 512 MiB before installing."
    );
    match p.options.mode {
        NetworkMode::Create => {
            block!(
                p.facts.interface_exists,
                "interface_exists",
                "Choose another interface or explicitly inspect with --reuse-interface."
            );
            block!(
                p.facts.route_overlap == Some(true),
                "route_overlap",
                "Choose a private subnet with no existing route overlap."
            );
            block!(
                p.facts.route_overlap.is_none(),
                "routes_unknown",
                "Restore read-only ip route inspection before provisioning."
            );
            block!(
                p.facts.port_in_use == Some(true),
                "udp_port_in_use",
                "Choose a free WireGuard UDP port."
            );
            block!(
                p.facts.port_in_use.is_none(),
                "ports_unknown",
                "Restore read-only UDP socket inspection before provisioning."
            );
        }
        NetworkMode::Reuse => {
            block!(
                !p.facts.interface_exists,
                "reuse_interface_missing",
                "Choose an existing interface; readb will not create or replace it in reuse mode."
            );
            block!(
                p.facts.interface_wireguard != Some(true),
                "reuse_wireguard_unverified",
                "Verify this is an existing WireGuard interface; ordinary network links cannot be reused."
            );
            block!(
                p.facts.interface_address_matches != Some(true),
                "reuse_address_mismatch_or_unknown",
                "Pass the existing server address and prefix; do not replace them."
            );
            block!(
                p.facts.interface_listen_port != Some(p.options.listen_port),
                "reuse_listen_port_mismatch_or_unknown",
                "Inspect the WireGuard listener with authorized privileges and pass its existing port."
            );
        }
    }
    p.ready = p.blockers.is_empty();
    Ok(p)
}
fn executable(name: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .filter(|p| p.is_absolute())
        .map(|p| p.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
        .map(|p| p.to_string_lossy().into_owned())
}
fn command(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    // A root preflight must never run an executable from an owner's writable
    // HOME/PATH. Unprivileged probes can still inspect a user-installed SDK.
    let program = if unsafe { libc::geteuid() } == 0 {
        crate::network_runtime::program(&[program]).ok()?
    } else {
        std::path::PathBuf::from(program)
    };
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C");
    let c = runner::capture_cmd(command, Duration::from_secs(3), 1024 * 1024).ok()?;
    c.ok.then_some(c.out)
}
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let mut p = path;
    while !p.exists() {
        p = p.parent()?;
    }
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), out.as_mut_ptr()) } != 0 {
        return None;
    }
    let out = unsafe { out.assume_init() };
    Some(out.f_bavail.saturating_mul(out.f_frsize))
}
fn storage_writable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() || !fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        return false;
    }
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut out = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), out.as_mut_ptr()) } != 0 {
        return false;
    }
    let out = unsafe { out.assume_init() };
    out.f_flag & libc::ST_RDONLY == 0
        && unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                c.as_ptr(),
                libc::W_OK | libc::X_OK,
                libc::AT_EACCESS,
            )
        } == 0
}
fn udp_used(port: u16) -> Option<bool> {
    let mut found = false;
    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        let raw = fs::read_to_string(path).ok()?;
        for row in raw.lines().skip(1) {
            let endpoint = row.split_whitespace().nth(1)?;
            let (_, hex) = endpoint.rsplit_once(':')?;
            found |= u16::from_str_radix(hex, 16).ok()? == port;
        }
    }
    Some(found)
}
fn overlaps(options: &Options, ip: &str) -> Option<bool> {
    let raw = command(ip, &["-j", "-4", "route", "show", "table", "all"])?;
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&raw).ok()?;
    let wanted = u32::from(options.address);
    let wanted_mask = u32::MAX << (32 - options.prefix);
    for row in rows {
        let dst = row.get("dst")?.as_str()?;
        if dst == "default" {
            continue;
        }
        let (addr, prefix) = dst.split_once('/').unwrap_or((dst, "32"));
        let addr = u32::from(addr.parse::<Ipv4Addr>().ok()?);
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let common = mask & wanted_mask;
        if addr & common == wanted & common {
            return Some(true);
        }
    }
    Some(false)
}
pub fn inspect(options: Options, home: &Path) -> Res<SetupPlan> {
    options.validate()?;
    let ip = executable("ip");
    let wg = executable("wg");
    let (kind, address, port) = if matches!(options.mode, NetworkMode::Reuse) {
        let link = ip
            .as_deref()
            .and_then(|ip| command(ip, &["-j", "-d", "link", "show", "dev", &options.interface]))
            .and_then(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
            .and_then(|r| {
                r.first()
                    .and_then(|r| r.pointer("/linkinfo/info_kind"))
                    .and_then(|v| v.as_str())
                    .map(|s| s == "wireguard")
            });
        let address = ip
            .as_deref()
            .and_then(|ip| {
                command(
                    ip,
                    &["-j", "-4", "address", "show", "dev", &options.interface],
                )
            })
            .and_then(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
            .and_then(|r| {
                r.first()
                    .and_then(|r| r.get("addr_info"))
                    .and_then(|v| v.as_array())
                    .map(|r| {
                        r.iter().any(|a| {
                            a["local"].as_str().and_then(|s| s.parse::<Ipv4Addr>().ok())
                                == Some(options.address)
                                && a["prefixlen"].as_u64() == Some(u64::from(options.prefix))
                        })
                    })
            });
        let port = wg
            .as_deref()
            .and_then(|wg| command(wg, &["show", &options.interface, "listen-port"]))
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.trim().parse::<u16>().ok());
        (link, address, port)
    } else {
        (None, None, None)
    };
    let adb = [
        home.join("Android/platform-tools/adb"),
        home.join("Android/Sdk/platform-tools/adb"),
    ]
    .into_iter()
    .filter_map(|p| p.to_str().map(str::to_owned))
    .chain(executable("adb"))
    .find(|p| {
        command(p, &["version"]).is_some_and(|v| v.starts_with(b"Android Debug Bridge version"))
    });
    let facts = Facts {
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        libc: if cfg!(target_env = "gnu") {
            "gnu"
        } else if cfg!(target_env = "musl") {
            "musl"
        } else {
            "unknown"
        }
        .into(),
        init: if Path::new("/run/systemd/system").exists() {
            "systemd"
        } else if Path::new("/run/openrc").exists() {
            "openrc"
        } else {
            "unknown"
        }
        .into(),
        adb,
        wg: wg.is_some(),
        wg_quick: executable("wg-quick").is_some(),
        ip: ip.is_some(),
        privilege: unsafe { libc::geteuid() } == 0,
        free_bytes: free_bytes(home),
        storage_writable: storage_writable(home),
        interface_exists: Path::new("/sys/class/net")
            .join(&options.interface)
            .exists(),
        interface_wireguard: kind,
        interface_address_matches: address,
        interface_listen_port: port,
        route_overlap: ip.as_deref().and_then(|ip| overlaps(&options, ip)),
        port_in_use: udp_used(options.listen_port),
    };
    build_plan(options, facts)
}
