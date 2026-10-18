//! Root helper files only. No service start, VPN effects or unknown-file takeover.
use crate::{network::Policy, policy::Res};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path},
};
const UNIT: &str = "etc/systemd/system/readb-network.service";
const STATE: &str = "var/lib/readb-network";
const RECEIPT: &str = "install.json";
const INTENT: &str = "install-pending.json";
const POLICY_FILE: &str = "etc/readb/network-policy.json";
const POLICY_INTENT: &str = "policy-pending.json";
const POLICY_RECEIPT: &str = "policy-install.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyIntent {
    schema: u8,
    policy: Policy,
    before: Option<Vec<u8>>,
    before_receipt: Option<Vec<u8>>,
}

fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid_hash(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    schema: u8,
    policy: Policy,
    binary_sha: String,
}
impl Plan {
    pub fn new(policy: &Policy, binary: &[u8]) -> Res<Self> {
        policy.validate()?;
        if binary.is_empty() || binary.len() > 64 * 1024 * 1024 {
            return Err("network_install_binary_size_invalid".into());
        }
        Ok(Self {
            schema: 1,
            policy: policy.clone(),
            binary_sha: hash(binary),
        })
    }
    fn validate(&self) -> Res<()> {
        self.policy.validate()?;
        if self.schema != 1 || !valid_hash(&self.binary_sha) {
            return Err("network_install_plan_invalid".into());
        }
        Ok(())
    }
    pub fn binary_path(&self) -> String {
        format!(
            "/usr/local/lib/readb-network/releases/{}/readb",
            self.binary_sha
        )
    }
    pub fn unit(&self) -> String {
        format!(
            "[Unit]\nDescription=readb narrow network helper\nWants=network-online.target\nAfter=network-online.target wg-quick@{}.service\n\n[Service]\nUser=root\nExecStart={} --local network helper --policy /etc/readb/network-policy.json --state /var/lib/readb-network\nRestart=on-failure\nRestartSec=5\nKillMode=control-group\nTimeoutStopSec=15\nUMask=0077\nRuntimeDirectory=readb-network\nRuntimeDirectoryMode=0711\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nReadWritePaths=/var/lib/readb-network /run/readb-network\nRestrictAddressFamilies=AF_UNIX AF_NETLINK\nMemoryMax=64M\nTasksMax=32\n\n[Install]\nWantedBy=multi-user.target\n",
            self.policy.interface,
            self.binary_path()
        )
    }
    fn receipt(&self) -> Res<Receipt> {
        Ok(Receipt {
            schema: 1,
            binary_sha: self.binary_sha.clone(),
            unit_sha: hash(self.unit().as_bytes()),
            policy_sha: hash(
                &serde_json::to_vec(&self.policy).map_err(|_| "network_install_encoding_failed")?,
            ),
        })
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u8,
    binary_sha: String,
    unit_sha: String,
    policy_sha: String,
}
impl Receipt {
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || [&self.binary_sha, &self.unit_sha, &self.policy_sha]
                .iter()
                .any(|s| !valid_hash(s))
        {
            Err("network_install_receipt_invalid".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: u8,
    plan: Plan,
    before: Option<Receipt>,
    before_unit: Option<Vec<u8>>,
}
struct Root {
    dir: File,
}
fn c(s: &std::ffi::OsStr) -> Res<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(|_| "network_install_path_invalid".into())
}
impl Root {
    fn open(path: &Path) -> Res<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|x| matches!(x, Component::CurDir | Component::ParentDir))
        {
            return Err("network_install_absolute_root_required".into());
        }
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "network_install_root_unavailable")?;
        check_dir(&dir)?;
        Ok(Self { dir })
    }
    fn directory(&self, path: &Path, create: bool) -> Res<Option<File>> {
        let mut dir = self
            .dir
            .try_clone()
            .map_err(|_| "network_install_directory_unavailable")?;
        for part in path.components() {
            let Component::Normal(name) = part else {
                return Err("network_install_relative_path_required".into());
            };
            let name = c(name)?;
            let mut fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                if !create {
                    return Ok(None);
                }
                if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err("network_install_mkdir_failed".into());
                }
                dir.sync_all()
                    .map_err(|_| "network_install_directory_sync_failed")?;
                fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            if fd < 0 {
                return Err("network_install_directory_unsafe".into());
            }
            dir = unsafe { File::from_raw_fd(fd) };
            check_dir(&dir)?;
        }
        Ok(Some(dir))
    }
    fn read(&self, path: &Path) -> Res<Option<Vec<u8>>> {
        let Some(dir) =
            self.directory(path.parent().ok_or("network_install_path_invalid")?, false)?
        else {
            return Ok(None);
        };
        read_at(
            &dir,
            path.file_name().ok_or("network_install_path_invalid")?,
        )
    }
    fn mode(&self, path: &Path) -> Res<Option<u32>> {
        let Some(dir) =
            self.directory(path.parent().ok_or("network_install_path_invalid")?, false)?
        else {
            return Ok(None);
        };
        let name = c(path.file_name().ok_or("network_install_path_invalid")?)?;
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
                Err("network_install_file_unavailable".into())
            };
        }
        let f = unsafe { File::from_raw_fd(fd) };
        Ok(Some(
            f.metadata()
                .map_err(|_| "network_install_file_metadata_failed")?
                .mode()
                & 0o7777,
        ))
    }
    fn sync(&self, path: &Path) -> Res<()> {
        let mut dir = self
            .dir
            .try_clone()
            .map_err(|_| "network_install_sync_failed")?;
        dir.sync_all().map_err(|_| "network_install_sync_failed")?;
        for part in path
            .parent()
            .ok_or("network_install_path_invalid")?
            .components()
        {
            let Component::Normal(name) = part else {
                return Err("network_install_relative_path_required".into());
            };
            let name = c(name)?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("network_install_sync_path_unavailable".into());
            }
            dir = unsafe { File::from_raw_fd(fd) };
            check_dir(&dir)?;
            dir.sync_all().map_err(|_| "network_install_sync_failed")?;
        }
        let name = c(path.file_name().ok_or("network_install_path_invalid")?)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("network_install_sync_file_unavailable".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(|_| "network_install_sync_failed")?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1 {
            return Err("network_install_sync_file_unsafe".into());
        }
        file.sync_all()
            .and_then(|_| dir.sync_all())
            .map_err(|_| "network_install_sync_failed".into())
    }
    fn write(&self, path: &Path, bytes: &[u8], mode: u32) -> Res<()> {
        let dir = self
            .directory(path.parent().ok_or("network_install_path_invalid")?, true)?
            .unwrap();
        write_at(
            &dir,
            path.file_name().ok_or("network_install_path_invalid")?,
            bytes,
            mode,
        )
    }
    fn remove(&self, path: &Path) -> Res<()> {
        let Some(dir) =
            self.directory(path.parent().ok_or("network_install_path_invalid")?, false)?
        else {
            return Ok(());
        };
        remove_at(
            &dir,
            path.file_name().ok_or("network_install_path_invalid")?,
        )
    }
}
fn check_dir(dir: &File) -> Res<()> {
    let m = dir
        .metadata()
        .map_err(|_| "network_install_directory_metadata_failed")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
        Err("network_install_owned_directory_required".into())
    } else {
        Ok(())
    }
}
fn read_at(dir: &File, name: &std::ffi::OsStr) -> Res<Option<Vec<u8>>> {
    let name = c(name)?;
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
            Err("network_install_file_unavailable_or_symlink".into())
        };
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f
        .metadata()
        .map_err(|_| "network_install_file_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > 64 * 1024 * 1024
    {
        return Err("network_install_private_owned_regular_file_required".into());
    }
    let mut b = vec![];
    f.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "network_install_file_read_failed")?;
    if b.len() > 64 * 1024 * 1024 {
        return Err("network_install_file_too_large".into());
    }
    Ok(Some(b))
}
fn write_at(dir: &File, target: &std::ffi::OsStr, bytes: &[u8], mode: u32) -> Res<()> {
    write_at_mode(dir, target, bytes, mode, false)
}
fn write_at_mode(
    dir: &File,
    target: &std::ffi::OsStr,
    bytes: &[u8],
    mode: u32,
    no_replace: bool,
) -> Res<()> {
    let target = c(target)?;
    let name = std::ffi::CString::new(format!("install-{}.tmp", crate::policy::random())).unwrap();
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err("network_install_file_create_failed".into());
    }
    let result = (|| {
        let mut f = unsafe { File::from_raw_fd(fd) };
        f.set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(|_| "network_install_file_permissions_failed")?;
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "network_install_file_sync_failed")?;
        if unsafe {
            // Atomic no-replace must work without a musl CRT wrapper. A
            // missing kernel operation remains a fenced failure, never replace.
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                name.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
                if no_replace {
                    libc::RENAME_NOREPLACE
                } else {
                    0
                },
            )
        } != 0
        {
            return Err("network_install_file_replace_failed".into());
        }
        dir.sync_all()
            .map_err(|_| "network_install_directory_sync_failed")?;
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
        }
    }
    result
}
fn remove_at(dir: &File, name: &std::ffi::OsStr) -> Res<()> {
    let name = c(name)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
    {
        return Err("network_install_remove_failed".into());
    }
    dir.sync_all()
        .map_err(|_| "network_install_directory_sync_failed".into())
}
pub struct Installer {
    root: Root,
    state: File,
    pending: Option<Intent>,
    pending_policy: Option<PolicyIntent>,
    poisoned: bool,
}
impl Installer {
    pub fn open(image_root: &Path) -> Res<Self> {
        let root = Root::open(image_root)?;
        let state = root.directory(Path::new(STATE), true)?.unwrap();
        let m = state
            .metadata()
            .map_err(|_| "network_install_state_unavailable")?;
        if m.mode() & 0o077 != 0 {
            return Err("network_install_private_state_required".into());
        }
        if unsafe { libc::flock(state.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("network_install_busy: stop the helper before installation".into());
        }
        let pending = read_at(&state, INTENT.as_ref())?
            .map(|b| {
                serde_json::from_slice::<Intent>(&b)
                    .map_err(|_| "network_install_intent_invalid".to_string())
            })
            .transpose()?;
        if let Some(p) = &pending {
            p.plan.validate()?;
            if p.schema != 1 || p.before_unit.as_ref().is_some_and(|b| b.len() > 16384) {
                return Err("network_install_intent_invalid".into());
            }
            if let Some(before) = &p.before {
                before.validate()?;
                if p.before_unit
                    .as_ref()
                    .is_none_or(|b| hash(b) != before.unit_sha)
                {
                    return Err("network_install_intent_before_mismatch".into());
                }
            } else if p.before_unit.is_some() {
                return Err("network_install_unmanaged_before_unit".into());
            }
        }
        let pending_policy = read_at(&state, POLICY_INTENT.as_ref())?
            .map(|b| {
                serde_json::from_slice::<PolicyIntent>(&b)
                    .map_err(|_| "network_policy_intent_invalid")
            })
            .transpose()?;
        if let Some(p) = &pending_policy {
            p.policy.validate()?;
            let canonical =
                serde_json::to_vec(&p.policy).map_err(|_| "network_policy_encoding_failed")?;
            let receipt = serde_json::to_vec(&hash(&canonical))
                .map_err(|_| "network_policy_encoding_failed")?;
            if p.schema != 1
                || p.policy.uid == 0
                || p.before.as_ref().is_some_and(|b| b != &canonical)
                || p.before_receipt.as_ref().is_some_and(|b| b != &receipt)
            {
                return Err("network_policy_intent_invalid".into());
            }
        }
        Ok(Self {
            root,
            state,
            pending,
            pending_policy,
            poisoned: false,
        })
    }
    fn receipt(&self) -> Res<Option<Receipt>> {
        let r = read_at(&self.state, RECEIPT.as_ref())?
            .map(|b| {
                serde_json::from_slice::<Receipt>(&b)
                    .map_err(|_| "network_install_receipt_invalid".to_string())
            })
            .transpose()?;
        if let Some(r) = &r {
            r.validate()?
        }
        Ok(r)
    }
    fn record(&self, name: &str, value: &impl Serialize) -> Res<()> {
        let b = serde_json::to_vec(value).map_err(|_| "network_install_encoding_failed")?;
        write_at(&self.state, name.as_ref(), &b, 0o600)
    }
    pub fn fenced(&self) -> bool {
        self.poisoned || self.pending.is_some() || self.pending_policy.is_some()
    }
    pub fn prepare_policy(&mut self, policy: &Policy) -> Res<()> {
        if self.fenced() {
            return Err("network_policy_cleanup_unknown: recover before installing".into());
        }
        policy.validate()?;
        if policy.uid == 0 {
            return Err("network_policy_nonroot_coordinator_required".into());
        }
        let canonical = serde_json::to_vec(policy).map_err(|_| "network_policy_encoding_failed")?;
        let before = self.root.read(Path::new(POLICY_FILE))?;
        if before.as_ref().is_some_and(|b| b != &canonical)
            || (before.is_some() && self.root.mode(Path::new(POLICY_FILE))? != Some(0o600))
        {
            return Err("network_policy_existing_config_preserved".into());
        }
        let before_receipt = read_at(&self.state, POLICY_RECEIPT.as_ref())?;
        if let Some(receipt) = &before_receipt {
            // The receipt is a canonical policy SHA, never an instruction to adopt
            // another file. An absent previously owned file also needs review.
            let expected = serde_json::to_vec(&hash(&canonical))
                .map_err(|_| "network_policy_encoding_failed")?;
            if receipt != &expected || before.is_none() {
                return Err("network_policy_owned_file_changed".into());
            }
        }
        self.root.directory(Path::new("etc/readb"), true)?;
        let intent = PolicyIntent {
            schema: 1,
            policy: policy.clone(),
            before,
            before_receipt,
        };
        self.poisoned = true;
        self.record(POLICY_INTENT, &intent)?;
        self.pending_policy = Some(intent);
        self.poisoned = false;
        Ok(())
    }
    pub fn install_policy(&mut self, policy: &Policy) -> Res<()> {
        self.prepare_policy(policy)?;
        let intent = self.pending_policy.as_ref().unwrap().clone();
        let canonical =
            serde_json::to_vec(&intent.policy).map_err(|_| "network_policy_encoding_failed")?;
        if intent.before.is_none() {
            let dir = self
                .root
                .directory(Path::new("etc/readb"), false)?
                .ok_or("network_policy_parent_missing")?;
            write_at_mode(
                &dir,
                "network-policy.json".as_ref(),
                &canonical,
                0o600,
                true,
            )?;
        }
        self.finish_policy(&intent, true)
    }
    fn finish_policy(&mut self, intent: &PolicyIntent, installed: bool) -> Res<()> {
        let canonical =
            serde_json::to_vec(&intent.policy).map_err(|_| "network_policy_encoding_failed")?;
        let actual = self.root.read(Path::new(POLICY_FILE))?;
        let expected =
            serde_json::to_vec(&hash(&canonical)).map_err(|_| "network_policy_encoding_failed")?;
        let receipt = read_at(&self.state, POLICY_RECEIPT.as_ref())?;
        if receipt != intent.before_receipt && (!installed || receipt.as_ref() != Some(&expected)) {
            return Err("network_policy_external_receipt_preserved".into());
        }

        if installed {
            if actual.as_ref() != Some(&canonical)
                || self.root.mode(Path::new(POLICY_FILE))? != Some(0o600)
            {
                return Err("network_policy_verification_failed".into());
            }
            self.root.sync(Path::new(POLICY_FILE))?;
            self.record(POLICY_RECEIPT, &hash(&canonical))?;
        } else {
            if actual.is_some() || intent.before.is_some() {
                return Err("network_policy_rollback_mismatch".into());
            }
            let dir = self
                .root
                .directory(Path::new("etc/readb"), false)?
                .ok_or("network_policy_parent_missing")?;
            dir.sync_all()
                .map_err(|_| "network_policy_directory_sync_failed")?;
        }
        if let Err(e) = remove_at(&self.state, POLICY_INTENT.as_ref()) {
            let _ = self.record(POLICY_INTENT, intent);
            self.poisoned = true;
            return Err(e);
        }
        self.pending_policy = None;
        Ok(())
    }
    pub fn recover_policy(&mut self) -> Res<()> {
        if self.poisoned {
            return Err("network_policy_restart_required_after_storage_error".into());
        }
        let intent = self
            .pending_policy
            .clone()
            .ok_or("network_policy_no_pending_operation")?;
        if self.pending.is_some() {
            return Err("network_policy_competing_install_intent".into());
        }
        let canonical =
            serde_json::to_vec(&intent.policy).map_err(|_| "network_policy_encoding_failed")?;
        let actual = self.root.read(Path::new(POLICY_FILE))?;
        match actual {
            Some(ref bytes) if bytes == &canonical => self.finish_policy(&intent, true),
            None if intent.before.is_none() => self.finish_policy(&intent, false),
            _ => Err("network_policy_external_edit_preserved".into()),
        }
    }
    pub fn recover_setup_pending(&mut self, policy: &Policy, plan: &Plan) -> Res<()> {
        let expected = serde_json::to_vec(plan).map_err(|_| "setup_recovery_encoding_failed")?;
        let policy_bytes =
            serde_json::to_vec(policy).map_err(|_| "setup_recovery_encoding_failed")?;
        if let Some(p) = &self.pending
            && serde_json::to_vec(&p.plan).map_err(|_| "setup_recovery_encoding_failed")?
                != expected
        {
            return Err("setup_recovery_unrelated_binary_intent_preserved".into());
        }
        if let Some(p) = &self.pending_policy
            && serde_json::to_vec(&p.policy).map_err(|_| "setup_recovery_encoding_failed")?
                != policy_bytes
        {
            return Err("setup_recovery_unrelated_policy_intent_preserved".into());
        }
        // Verify both scopes before consuming either durable intent.
        if self.pending_policy.is_some() {
            self.recover_policy()?;
        }
        if self.pending.is_some() {
            self.recover()?;
        }
        Ok(())
    }
    pub fn verify_setup_files(&self, policy: &Policy, plan: &Plan) -> Res<()> {
        if self.fenced() {
            return Err("network_setup_files_cleanup_unknown".into());
        }
        verify_file_contents(&self.root, &self.state, policy, plan)?;
        self.root.sync(Path::new(POLICY_FILE))?;
        self.root.sync(Path::new(UNIT))?;
        self.root.sync(Path::new(&plan.binary_path()[1..]))?;
        self.root.sync(Path::new(&format!("{STATE}/{RECEIPT}")))?;
        self.root
            .sync(Path::new(&format!("{STATE}/{POLICY_RECEIPT}")))?;
        Ok(())
    }
    fn verify_release(&self, r: &Receipt) -> Res<()> {
        verify_release_contents(&self.root, r)
    }
    pub fn prepare(&mut self, plan: Plan, binary: &[u8]) -> Res<()> {
        if self.fenced() {
            return Err("network_install_cleanup_unknown: recover before installing".into());
        }
        plan.validate()?;
        if hash(binary) != plan.binary_sha {
            return Err("network_install_binary_hash_mismatch".into());
        }
        let before = self.receipt()?;
        let unit = self.root.read(Path::new(UNIT))?;
        if let Some(r) = &before {
            self.verify_release(r)?;
            if unit.as_ref().is_none_or(|b| hash(b) != r.unit_sha) {
                return Err("network_install_owned_unit_changed".into());
            }
            if r.policy_sha != plan.receipt()?.policy_sha {
                return Err("network_install_policy_changed: review separately".into());
            }
        } else if unit.is_some() {
            return Err("network_install_unknown_unit_preserved".into());
        }
        let target = plan.binary_path();
        if let Some(bytes) = self.root.read(Path::new(&target[1..]))?
            && (hash(&bytes) != plan.binary_sha
                || self.root.mode(Path::new(&target[1..]))? != Some(0o700))
        {
            return Err("network_install_immutable_release_mismatch".into());
        }
        let intent = Intent {
            schema: 1,
            plan,
            before,
            before_unit: unit,
        };
        self.poisoned = true;
        self.record(INTENT, &intent)?;
        self.pending = Some(intent);
        self.poisoned = false;
        Ok(())
    }
    pub fn install(&mut self, plan: Plan, binary: &[u8]) -> Res<()> {
        self.install_with_sync(plan, binary, |installer, plan| {
            let path = plan.binary_path();
            installer.root.sync(Path::new(&path[1..]))?;
            installer.root.sync(Path::new(UNIT))
        })
    }
    fn install_with_sync(
        &mut self,
        plan: Plan,
        binary: &[u8],
        sync: impl FnOnce(&Self, &Plan) -> Res<()>,
    ) -> Res<()> {
        self.prepare(plan, binary)?;
        let p = self.pending.as_ref().unwrap().clone();
        // Intent is durable before either public file changes. Source bytes are pinned
        // in memory and hashed; no privileged executable is left in a user-owned path.
        let target = p.plan.binary_path();
        let target = Path::new(&target[1..]);
        if self.root.read(target)?.is_none() {
            self.root.write(target, binary, 0o700)?
        }
        if self.root.read(Path::new(UNIT))? != p.before_unit {
            return Err("network_install_unit_changed_before_apply".into());
        }
        self.root
            .write(Path::new(UNIT), p.plan.unit().as_bytes(), 0o600)?;
        sync(self, &p.plan)?;
        self.verify_after(&p)?;
        self.record(RECEIPT, &p.plan.receipt()?)?;
        self.clear(&p)
    }
    fn verify_after(&self, p: &Intent) -> Res<()> {
        let path = p.plan.binary_path();
        let receipt = p.plan.receipt()?;
        if self.root.mode(Path::new(&path[1..]))? != Some(0o700)
            || self
                .root
                .read(Path::new(&path[1..]))?
                .as_ref()
                .is_none_or(|b| hash(b) != p.plan.binary_sha)
            || self
                .root
                .read(Path::new(UNIT))?
                .as_ref()
                .is_none_or(|b| hash(b) != receipt.unit_sha)
        {
            return Err("network_install_verification_failed".into());
        }
        Ok(())
    }
    fn clear(&mut self, p: &Intent) -> Res<()> {
        if let Err(e) = remove_at(&self.state, INTENT.as_ref()) {
            let _ = self.record(INTENT, p);
            self.poisoned = true;
            return Err(e);
        }
        self.pending = None;
        Ok(())
    }
    pub fn recover(&mut self) -> Res<()> {
        self.recover_with_sync(|installer, plan| {
            let path = plan.binary_path();
            installer.root.sync(Path::new(&path[1..]))?;
            installer.root.sync(Path::new(UNIT))
        })
    }
    fn recover_with_sync(&mut self, sync: impl FnOnce(&Self, &Plan) -> Res<()>) -> Res<()> {
        if self.poisoned {
            return Err("network_install_restart_required_after_storage_error".into());
        }
        let p = self
            .pending
            .clone()
            .ok_or("network_install_no_pending_operation")?;
        if let Some(before) = &p.before {
            self.verify_release(before)?;
        }
        let actual = self.receipt()?;
        let after = p.plan.receipt()?;
        if actual != p.before && actual.as_ref() != Some(&after) {
            return Err("network_install_external_receipt_change".into());
        }
        let unit = self.root.read(Path::new(UNIT))?;
        let desired = p.plan.unit().into_bytes();
        if unit != p.before_unit && unit.as_ref() != Some(&desired) {
            return Err("network_install_external_unit_change".into());
        }
        let path = p.plan.binary_path();
        let binary = self.root.read(Path::new(&path[1..]))?;
        if binary
            .as_ref()
            .is_some_and(|b| hash(b) != p.plan.binary_sha)
            || (binary.is_some() && self.root.mode(Path::new(&path[1..]))? != Some(0o700))
        {
            return Err("network_install_external_binary_change".into());
        }
        if unit.as_ref() == Some(&desired) && binary.is_some() {
            sync(self, &p.plan)?;
            self.verify_after(&p)?;
            self.record(RECEIPT, &after)?;
        } else {
            // Incomplete installation rolls back only its unit/receipt. Verified immutable
            // release files are retained; no private profile or unknown file is removed.
            if let Some(bytes) = &p.before_unit {
                self.root.write(Path::new(UNIT), bytes, 0o600)?
            } else if unit.is_some() {
                self.root.remove(Path::new(UNIT))?
            }
            if let Some(r) = &p.before {
                let path = format!(
                    "usr/local/lib/readb-network/releases/{}/readb",
                    r.binary_sha
                );
                self.root.sync(Path::new(&path))?;
                self.root.sync(Path::new(UNIT))?;
                self.verify_release(r)?;
                self.record(RECEIPT, r)?
            } else {
                remove_at(&self.state, RECEIPT.as_ref())?
            }
        }
        self.clear(&p)
    }
}
pub fn ensure_complete(state: &Path) -> Res<()> {
    match std::fs::symlink_metadata(state.join(INTENT)){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Ok(()),_=>Err("network_install_cleanup_unknown: stop helper and run network install-recover locally as root".into())}
}
fn require_root() -> Res<()> {
    if unsafe { libc::geteuid() } != 0 {
        Err("network_install_requires_root: coordinator stays unprivileged".into())
    } else {
        Ok(())
    }
}
pub fn install_on_server(dry_run: bool) -> Res<serde_json::Value> {
    require_root()?;
    let policy = crate::network_runtime::root_policy(Path::new("/etc/readb/network-policy.json"))?;
    let mut bytes = vec![];
    File::open("/proc/self/exe")
        .map_err(|_| "network_executing_binary_unavailable")?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "network_executing_binary_unavailable")?;
    let plan = Plan::new(&policy, &bytes)?;
    if dry_run {
        return Ok(
            serde_json::json!({"applied":false,"proposed_only":true,"filesystem_admission":false,"binary":plan.binary_path(),"unit":"/etc/systemd/system/readb-network.service","state":"/var/lib/readb-network","service_started":false,"unit_text":plan.unit()}),
        );
    }
    let mut installer = Installer::open(Path::new("/"))?;
    installer.install(plan.clone(), &bytes)?;
    Ok(
        serde_json::json!({"installed_files":true,"binary":plan.binary_path(),"service_started":false,"network_changed":false,"next":"Verify the unit, then activate it in the separately authorized setup phase."}),
    )
}
pub fn recover_on_server() -> Res<serde_json::Value> {
    require_root()?;
    let mut i = Installer::open(Path::new("/"))?;
    i.recover()?;
    Ok(serde_json::json!({"recovered":true,"service_started":false,"network_changed":false}))
}

pub(crate) fn ensure_complete_fd(dir: &File) -> Res<()> {
    for marker in [INTENT, POLICY_INTENT] {
        let name = std::ffi::CString::new(marker).unwrap();
        let mut meta = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                meta.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(
                "network_install_cleanup_unknown: recover the installation before starting helper"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Protected setup journal directory. Uses the same no-symlink ancestry checks
/// as root installation; test image roots are explicit and never CLI inputs.
pub fn setup_journal_directory(image_root: &Path) -> Res<std::path::PathBuf> {
    let root = Root::open(image_root)?;
    let dir = root
        .directory(Path::new("var/lib/readb-setup"), true)?
        .ok_or("setup_journal_missing")?;
    let m = dir
        .metadata()
        .map_err(|_| "setup_journal_metadata_failed")?;
    if m.mode() & 0o077 != 0 {
        return Err("setup_private_journal_required".into());
    }
    Ok(image_root.join("var/lib/readb-setup"))
}

/// Observe exact installed files without taking Manager's exclusive state lock.
/// This grants no write authority and does not prove a running helper or network.
pub fn inspect_setup_files(image_root: &Path, policy: &Policy, plan: &Plan) -> Res<()> {
    let root = Root::open(image_root)?;
    let state = root
        .directory(Path::new(STATE), false)?
        .ok_or("network_install_state_unavailable")?;
    if state
        .metadata()
        .map_err(|_| "network_install_state_unavailable")?
        .mode()
        & 0o077
        != 0
    {
        return Err("network_install_private_state_required".into());
    }
    verify_file_contents(&root, &state, policy, plan)
}
/// An exact installed image, not authority to stop or replace its running service.
/// Discovery is read-only and does not contend with the live helper state lock.
pub struct Installed {
    policy: Policy,
    plan: Plan,
    binary: Vec<u8>,
}
impl Installed {
    pub fn image_sha256(&self) -> &str {
        &self.plan.binary_sha
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn plan(&self) -> &Plan {
        &self.plan
    }
    pub fn binary(&self) -> &[u8] {
        &self.binary
    }
}
/// Read an already installed root-owned immutable release by its exact digest.
/// This does not adopt a receipt or prove a running process.
pub fn inspect_release(image_root: &Path, digest: &str) -> Res<Vec<u8>> {
    if !valid_hash(digest) {
        return Err("network_install_image_digest_invalid".into());
    }
    let root = Root::open(image_root)?;
    let path = format!("usr/local/lib/readb-network/releases/{digest}/readb");
    let bytes = root
        .read(Path::new(&path))?
        .ok_or("network_install_release_missing")?;
    if bytes.is_empty() || hash(&bytes) != digest || root.mode(Path::new(&path))? != Some(0o700) {
        return Err("network_install_previous_release_changed".into());
    }
    Ok(bytes)
}
pub fn inspect_installed(image_root: &Path) -> Res<Installed> {
    let root = Root::open(image_root)?;
    let state = root
        .directory(Path::new(STATE), false)?
        .ok_or("network_install_state_unavailable")?;
    if state
        .metadata()
        .map_err(|_| "network_install_state_unavailable")?
        .mode()
        & 0o077
        != 0
    {
        return Err("network_install_private_state_required".into());
    }
    no_file_intent(&state)?;
    let policy_bytes = root
        .read(Path::new(POLICY_FILE))?
        .ok_or("network_policy_missing")?;
    let policy: Policy =
        serde_json::from_slice(&policy_bytes).map_err(|_| "network_policy_invalid")?;
    policy.validate()?;
    let receipt_bytes =
        read_at(&state, RECEIPT.as_ref())?.ok_or("network_install_receipt_missing")?;
    let receipt: Receipt =
        serde_json::from_slice(&receipt_bytes).map_err(|_| "network_install_receipt_invalid")?;
    receipt.validate()?;
    let plan = Plan {
        schema: 1,
        policy: policy.clone(),
        binary_sha: receipt.binary_sha,
    };
    // Reconstruct the supported unit contract. Unknown historical templates
    // require an explicit adapter; never infer ownership from a unit description.
    verify_file_contents(&root, &state, &policy, &plan)?;
    let binary = root
        .read(Path::new(&plan.binary_path()[1..]))?
        .ok_or("network_install_previous_release_changed")?;
    if Plan::new(&policy, &binary)?.binary_path() != plan.binary_path()
        || read_at(&state, RECEIPT.as_ref())?.as_ref() != Some(&receipt_bytes)
        || root.read(Path::new(POLICY_FILE))?.as_ref() != Some(&policy_bytes)
    {
        return Err("network_install_changed_during_inspection".into());
    }
    verify_file_contents(&root, &state, &policy, &plan)?;
    Ok(Installed {
        policy,
        plan,
        binary,
    })
}
fn no_file_intent(state: &File) -> Res<()> {
    for name in [INTENT, POLICY_INTENT] {
        if read_at(state, name.as_ref())?.is_some() {
            return Err("network_setup_files_cleanup_unknown".into());
        }
    }
    Ok(())
}
fn verify_release_contents(root: &Root, r: &Receipt) -> Res<()> {
    r.validate()?;
    let path = format!(
        "usr/local/lib/readb-network/releases/{}/readb",
        r.binary_sha
    );
    if root
        .read(Path::new(&path))?
        .as_ref()
        .is_none_or(|b| hash(b) != r.binary_sha)
        || root.mode(Path::new(&path))? != Some(0o700)
    {
        return Err("network_install_previous_release_changed".into());
    }
    Ok(())
}
fn verify_file_contents(root: &Root, state: &File, policy: &Policy, plan: &Plan) -> Res<()> {
    plan.validate()?;
    policy.validate()?;
    no_file_intent(state)?;
    let bytes = serde_json::to_vec(policy).map_err(|_| "network_policy_encoding_failed")?;
    let expected = plan.receipt()?;
    let receipt: Option<Receipt> = read_at(state, RECEIPT.as_ref())?
        .map(|b| serde_json::from_slice(&b).map_err(|_| "network_install_receipt_invalid"))
        .transpose()?;
    if bytes != serde_json::to_vec(&plan.policy).map_err(|_| "network_policy_encoding_failed")?
        || root.read(Path::new(POLICY_FILE))?.as_ref() != Some(&bytes)
        || root.mode(Path::new(POLICY_FILE))? != Some(0o600)
        || receipt.as_ref() != Some(&expected)
        || root.read(Path::new(UNIT))?.as_deref() != Some(plan.unit().as_bytes())
        || root.mode(Path::new(UNIT))? != Some(0o600)
        || read_at(state, POLICY_RECEIPT.as_ref())?.as_ref()
            != Some(
                &serde_json::to_vec(&hash(&bytes)).map_err(|_| "network_policy_encoding_failed")?,
            )
    {
        return Err("network_setup_files_verification_failed".into());
    }
    verify_release_contents(root, &expected)?;
    no_file_intent(state)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UpgradeFiles {
    Old,
    Pending,
    New,
}
/// Call only after the admitted helper is quiet. A matching pending intent
/// permits exact recovery; it never grants arbitrary mark-complete authority.
pub fn inspect_upgrade_state(
    image_root: &Path,
    policy: &Policy,
    old: &Plan,
    new: &Plan,
) -> Res<UpgradeFiles> {
    old.validate()?;
    new.validate()?;
    if serde_json::to_vec(&old.policy).map_err(|_| "upgrade_policy_invalid")?
        != serde_json::to_vec(policy).map_err(|_| "upgrade_policy_invalid")?
        || serde_json::to_vec(&new.policy).map_err(|_| "upgrade_policy_invalid")?
            != serde_json::to_vec(policy).map_err(|_| "upgrade_policy_invalid")?
    {
        return Err("upgrade_policy_changed".into());
    }
    let i = Installer::open(image_root)?;
    if i.pending_policy.is_some() {
        return Err("upgrade_unrelated_policy_intent_preserved".into());
    }
    if let Some(p) = &i.pending {
        let before = old.receipt()?;
        let after = new.receipt()?;
        if serde_json::to_vec(&p.plan).map_err(|_| "upgrade_plan_invalid")?
            != serde_json::to_vec(new).map_err(|_| "upgrade_plan_invalid")?
            || p.before.as_ref() != Some(&before)
            || p.before_unit.as_deref() != Some(old.unit().as_bytes())
        {
            return Err("upgrade_unrelated_install_intent_preserved".into());
        }
        i.verify_release(&before)?;
        let current = i.receipt()?;
        let unit = i.root.read(Path::new(UNIT))?;
        if (current.as_ref() != Some(&before) && current.as_ref() != Some(&after))
            || (unit.as_deref() != Some(old.unit().as_bytes())
                && unit.as_deref() != Some(new.unit().as_bytes()))
            || i.root.read(Path::new(POLICY_FILE))?.as_ref()
                != Some(&serde_json::to_vec(policy).map_err(|_| "upgrade_policy_invalid")?)
            || i.root.mode(Path::new(POLICY_FILE))? != Some(0o600)
            || i.root.mode(Path::new(UNIT))? != Some(0o600)
        {
            return Err("upgrade_pending_files_changed".into());
        }
        let path = new.binary_path();
        let path = Path::new(&path[1..]);
        if let Some(bytes) = i.root.read(path)?
            && (hash(&bytes) != new.binary_sha || i.root.mode(path)? != Some(0o700))
        {
            return Err("upgrade_pending_image_changed".into());
        }
        return Ok(UpgradeFiles::Pending);
    }
    if verify_file_contents(&i.root, &i.state, policy, new).is_ok() {
        return Ok(UpgradeFiles::New);
    }
    verify_file_contents(&i.root, &i.state, policy, old)?;
    Ok(UpgradeFiles::Old)
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    #[test]
    fn recovery_keeps_intent_when_accepted_file_sync_fails() {
        let root =
            std::env::temp_dir().join(format!("readb-install-sync-{}", crate::policy::random()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            schema: 1,
            uid: 1000,
            interface: "readb0".into(),
            server_key: format!("{}AAA=", "E".repeat(40)),
            server_address: "10.88.0.1".parse().unwrap(),
            prefix: 24,
            first: "10.88.0.10".parse().unwrap(),
            last: "10.88.0.20".parse().unwrap(),
        };
        let plan = Plan::new(&policy, b"binary").unwrap();
        let mut i = Installer::open(&root).unwrap();
        i.prepare(plan.clone(), b"binary").unwrap();
        i.root
            .write(Path::new(&plan.binary_path()[1..]), b"binary", 0o700)
            .unwrap();
        i.root
            .write(Path::new(UNIT), plan.unit().as_bytes(), 0o600)
            .unwrap();
        assert!(
            i.recover_with_sync(|_, _| Err("injected sync failure".into()))
                .is_err()
        );
        assert!(i.fenced());
        assert!(i.receipt().unwrap().is_none());
        drop(i);
        let mut i = Installer::open(&root).unwrap();
        assert!(i.fenced());
        i.recover().unwrap();
        assert!(!i.fenced());
        // Even an already present verified release needs a durability barrier
        // when accepted by a retry; byte equality alone is insufficient.
        assert!(
            i.install_with_sync(plan, b"binary", |_, _| Err(
                "injected reused-release sync failure".into()
            ))
            .is_err()
        );
        assert!(i.fenced());
        drop(i);
        let mut i = Installer::open(&root).unwrap();
        assert!(i.fenced());
        i.recover().unwrap();
        drop(i);
        std::fs::remove_dir_all(root).unwrap();
    }
}
