//! Read-only installation intent. Root effects require a separate journaled phase.
use crate::{
    network::{Policy, Snapshot, valid_key},
    policy::Res,
    setup::{NetworkMode, Options},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    net::{Ipv4Addr, Ipv6Addr},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, PathBuf},
};
#[derive(Clone, Serialize)]
pub struct Owner {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}
impl Owner {
    fn validate(&self) -> Res<()> {
        if self.uid == 0
            || self.uid == u32::MAX
            || self.gid == 0
            || self.gid == u32::MAX
            || self.name.is_empty()
            || self.name.len() > 256
            || self.name.starts_with('-')
            || !self
                .name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || !self.home.is_absolute()
            || self.home.parent().is_none()
            || self
                .home
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            || self
                .home
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|c| *c < 32 || b"%\"\\".contains(c))
        {
            return Err("setup_nonroot_owner_and_safe_home_required".into());
        }
        Ok(())
    }
    /// Resolve passwd, never SUDO_USER/HOME supplied by a caller. This does not
    /// grant permission to run a user binary as root or prove user-bus availability.
    pub fn resolve(name: &str) -> Res<Self> {
        let input = Self {
            name: name.into(),
            uid: 1,
            gid: 1,
            home: "/placeholder".into(),
        };
        input.validate()?;
        let name_c = CString::new(name).map_err(|_| "setup_user_invalid")?;
        let mut size = 4096;
        loop {
            let mut buf = vec![0u8; size];
            let mut pw = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result = std::ptr::null_mut();
            let rc = unsafe {
                libc::getpwnam_r(
                    name_c.as_ptr(),
                    pw.as_mut_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == libc::ERANGE && size < 1024 * 1024 {
                size *= 2;
                continue;
            }
            if rc != 0 || result.is_null() {
                return Err("setup_user_not_found".into());
            }
            let pw = unsafe { pw.assume_init() };
            if pw.pw_dir.is_null() || pw.pw_name.is_null() {
                return Err("setup_passwd_invalid".into());
            }
            let home = unsafe { CStr::from_ptr(pw.pw_dir) }.to_bytes();
            let resolved = unsafe { CStr::from_ptr(pw.pw_name) }
                .to_str()
                .map_err(|_| "setup_passwd_invalid")?;
            if resolved != name {
                return Err("setup_passwd_name_mismatch".into());
            }
            let owner = Self {
                name: name.into(),
                uid: pw.pw_uid,
                gid: pw.pw_gid,
                home: std::ffi::OsStr::from_bytes(home).into(),
            };
            owner.validate()?;
            owner.check_home()?;
            return Ok(owner);
        }
    }
    /// Probe using the selected UID/GID, with no inherited root groups. A
    /// primary-group-only denial is a blocker, never evidence of readiness.
    pub fn can_write_home(&self) -> Res<bool> {
        use std::os::unix::process::CommandExt;
        self.check_home()?;
        let root = unsafe { libc::geteuid() } == 0;
        if !root && unsafe { libc::geteuid() } != self.uid {
            return Err("setup_owner_probe_requires_root_or_selected_user".into());
        }
        let test = crate::network_runtime::program(&["/usr/bin/test", "/bin/test"])?;
        for flag in ["-w", "-x"] {
            let mut command = std::process::Command::new(&test);
            command
                .arg(flag)
                .arg(&self.home)
                .current_dir("/")
                .env_clear()
                .env("LANG", "C");
            if root {
                let uid = self.uid;
                let gid = self.gid;
                unsafe {
                    command.pre_exec(move || {
                        if libc::setgroups(0, std::ptr::null()) != 0
                            || libc::setgid(gid) != 0
                            || libc::setuid(uid) != 0
                            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            let result =
                crate::runner::capture_cmd(command, std::time::Duration::from_secs(3), 1024)?;
            if !result.ok {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Pin each path component; reject symlinks and writable/unrelated ancestry.
    /// Recheck immediately before privilege drop; a plan is not a retained handle.
    pub fn check_home(&self) -> Res<()> {
        self.validate()?;
        let mut dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|_| "setup_home_unavailable")?;
        for part in self.home.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            let name = CString::new(name.as_bytes()).map_err(|_| "setup_home_invalid")?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("setup_home_missing_or_symlink".into());
            }
            dir = unsafe { File::from_raw_fd(fd) };
            let m = dir.metadata().map_err(|_| "setup_home_metadata_failed")?;
            if ![0, self.uid].contains(&m.uid()) || m.mode() & 0o022 != 0 {
                return Err("setup_home_unsafe_ancestry".into());
            }
        }
        if dir
            .metadata()
            .map_err(|_| "setup_home_metadata_failed")?
            .uid()
            != self.uid
        {
            return Err("setup_home_owner_mismatch".into());
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub struct ApplyPlan {
    pub schema: u8,
    pub plan_sha256: String,
    pub baseline_sha256: String,
    pub owner: Owner,
    pub options: Options,
    pub policy: Policy,
    pub root_install: crate::network_install::Plan,
    pub files_installed: bool,
    pub helper_active: bool,
    pub coordinator_active: bool,
    pub network_verified: bool,
    pub devices_accepted: bool,
}
fn hash<T: Serialize>(value: &T) -> Res<String> {
    Ok(
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "setup_apply_encoding_failed")?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
pub fn bind(
    options: Options,
    owner: Owner,
    policy: Policy,
    mut baseline: Snapshot,
    binary: &[u8],
) -> Res<ApplyPlan> {
    options.validate()?;
    owner.validate()?;
    policy.validate()?;
    if !matches!(options.mode, NetworkMode::Reuse) {
        return Err("setup_apply_reuse_only: new interface creation is a separate phase".into());
    }
    if owner.uid != policy.uid
        || options.interface != policy.interface
        || options.address != policy.server_address
        || options.prefix != policy.prefix
    {
        return Err("setup_apply_policy_mismatch".into());
    }
    if baseline.server_key != policy.server_key
        || baseline.addresses != vec![format!("{}/{}", policy.server_address, policy.prefix)]
    {
        return Err("setup_apply_interface_pin_mismatch".into());
    }
    for (key, routes) in &mut baseline.peers {
        if !valid_key(key) || key == &baseline.server_key {
            return Err("setup_apply_peer_key_invalid".into());
        }
        for route in routes.iter() {
            let (address, prefix) = route
                .split_once('/')
                .ok_or("setup_apply_peer_route_invalid")?;
            let prefix = prefix
                .parse::<u8>()
                .map_err(|_| "setup_apply_peer_route_invalid")?;
            if let Ok(address) = address.parse::<Ipv4Addr>() {
                if prefix > 32 {
                    return Err("setup_apply_peer_route_invalid".into());
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let low = u32::from(address) & mask;
                let high = low | !mask;
                if low <= u32::from(policy.last) && high >= u32::from(policy.first) {
                    return Err(
                        "setup_apply_enrollment_range_in_use: choose a dedicated unused range"
                            .into(),
                    );
                }
            } else if address.parse::<Ipv6Addr>().is_err() || prefix > 128 {
                return Err("setup_apply_peer_route_invalid".into());
            }
        }
        routes.sort();
        routes.dedup();
    }
    baseline.addresses.sort();
    baseline.addresses.dedup();
    let root_install = crate::network_install::Plan::new(&policy, binary)?;
    let plan_sha256 = hash(&(1u8, &options, &owner, &policy, &root_install))?;
    Ok(ApplyPlan {
        schema: 1,
        plan_sha256,
        baseline_sha256: hash(&baseline)?,
        owner,
        options,
        policy,
        root_install,
        files_installed: false,
        helper_active: false,
        coordinator_active: false,
        network_verified: false,
        devices_accepted: false,
    })
}
