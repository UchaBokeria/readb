//! Private write-ahead enrollment state. No device, network or catalog effects.
use crate::{
    enrollment_profile::{Material, Reservation},
    policy::{Owner, Res, random},
    schema::ServerConfig,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};
const LIMIT: usize = 2 * 1024 * 1024;
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn fingerprint(config: &ServerConfig) -> Res<String> {
    config.validate()?;
    Ok(hash(
        &serde_json::to_vec(config).map_err(|_| "enrollment_config_encoding_failed")?,
    ))
}
fn hash_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn owner_valid(o: &Owner) -> bool {
    [&o.agent, &o.origin, &o.session, &o.job]
        .iter()
        .all(|s| !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control))
}
fn same_owner(a: &Owner, b: &Owner) -> bool {
    a.agent == b.agent
        && a.origin == b.origin
        && a.session == b.session
        && a.job == b.job
        && a.allow_sleep == b.allow_sleep
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Prepared,
    CatalogIntent,
    CatalogAdded,
    ControllerHeld,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    schema: u8,
    transaction: String,
    owner: Owner,
    phase: Phase,
    material: Vec<u8>,
    material_hash: String,
    expected_config: String,
    catalog_after: Option<String>,
    #[serde(default)]
    ticket: Option<String>,
}
impl StoredRecord {
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || !hash_valid(&self.transaction)
            || !owner_valid(&self.owner)
            || self.material.len() > 8192
            || hash(&self.material) != self.material_hash
            || !hash_valid(&self.expected_config)
        {
            return Err("enrollment_journal_record_invalid".into());
        }
        let m = Material::shape_from_private(&self.material)?;
        if matches!(self.phase, Phase::Prepared | Phase::CatalogIntent)
            && self.expected_config != m.plan().config_fingerprint
        {
            return Err("enrollment_initial_catalog_mismatch".into());
        }
        if self.phase == Phase::Prepared {
            if self.catalog_after.is_some() || self.expected_config != m.plan().config_fingerprint {
                return Err("enrollment_journal_phase_invalid".into());
            }
        } else if !self.catalog_after.as_ref().is_some_and(|s| hash_valid(s)) {
            return Err("enrollment_catalog_intent_missing".into());
        }
        if matches!(self.phase, Phase::CatalogAdded | Phase::ControllerHeld)
            && self.catalog_after.as_ref() != Some(&self.expected_config)
        {
            return Err("enrollment_catalog_phase_invalid".into());
        }
        if (self.phase == Phase::ControllerHeld) != self.ticket.is_some()
            || self.ticket.as_ref().is_some_and(|t| !hash_valid(t))
        {
            return Err("enrollment_ticket_phase_invalid".into());
        }
        Ok(())
    }
    fn material(&self) -> Res<Material> {
        self.validate()?;
        Material::shape_from_private(&self.material)
    }
    fn authorize(&self, transaction: &str, owner: &Owner) -> Res<()> {
        self.validate()?;
        if self.transaction != transaction || !same_owner(&self.owner, owner) {
            return Err("enrollment_owned_by_other_job: use original owner and transaction".into());
        }
        Ok(())
    }
}
/// Opaque private record: public diagnostics cannot serialize its credentials.
/// ```compile_fail
/// fn leak(r: readb::enrollment_journal::Record) { let _ = serde_json::to_string(&r); }
/// ```
#[derive(Clone)]
pub struct Record {
    stored: StoredRecord,
}
impl Record {
    pub fn transaction(&self) -> &str {
        &self.stored.transaction
    }
    pub fn phase(&self) -> Phase {
        self.stored.phase
    }
    pub fn material(&self, wg: &Path) -> Res<Material> {
        self.stored.validate()?;
        Material::from_private(&self.stored.material, wg)
    }
    pub fn reservation(&self) -> Res<Reservation> {
        Ok(self.stored.material()?.plan().reservation())
    }
    pub(crate) fn owner(&self) -> &Owner {
        &self.stored.owner
    }
    pub(crate) fn ticket(&self) -> Option<&str> {
        self.stored.ticket.as_deref()
    }
    pub fn expected_config(&self) -> &str {
        &self.stored.expected_config
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u8,
    records: BTreeMap<String, StoredRecord>,
}
impl Journal {
    fn validate(&self) -> Res<()> {
        if self.schema != 1 || self.records.len() > 128 {
            return Err("enrollment_journal_invalid".into());
        }
        for (id, r) in &self.records {
            r.validate()?;
            if r.material()?.plan().id != *id {
                return Err("enrollment_journal_id_mismatch".into());
            }
        }
        Ok(())
    }
}
fn private_file(f: &File) -> Res<()> {
    let m = f.metadata().map_err(|_| "enrollment_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o7077 != 0
    {
        return Err("enrollment_private_regular_file_required".into());
    }
    Ok(())
}
fn directory(root: &Path, create: bool) -> Res<Option<File>> {
    if !root.is_absolute()
        || root
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("enrollment_absolute_state_path_required".into());
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| "enrollment_root_unavailable")?;
    let m = root.metadata().map_err(|_| "enrollment_root_unavailable")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7077 != 0 {
        return Err("enrollment_private_root_required".into());
    }
    if create
        && unsafe { libc::mkdirat(root.as_raw_fd(), c"enrollment".as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err("enrollment_directory_create_failed".into());
    }
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            c"enrollment".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if !create && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("enrollment_directory_unavailable".into());
    }
    let dir = unsafe { File::from_raw_fd(fd) };
    let m = dir
        .metadata()
        .map_err(|_| "enrollment_directory_unavailable")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7077 != 0 {
        return Err("enrollment_private_directory_required".into());
    }
    if create {
        root.sync_all()
            .map_err(|_| "enrollment_directory_sync_failed")?;
    }
    Ok(Some(dir))
}
fn read(dir: &File) -> Res<Option<Vec<u8>>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"journal.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("enrollment_journal_unavailable".into());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    private_file(&f)?;
    if f.metadata()
        .map_err(|_| "enrollment_metadata_failed")?
        .len()
        > LIMIT as u64
    {
        return Err("enrollment_journal_too_large".into());
    }
    let mut b = Vec::new();
    f.take((LIMIT + 1) as u64)
        .read_to_end(&mut b)
        .map_err(|_| "enrollment_journal_read_failed")?;
    if b.len() > LIMIT {
        return Err("enrollment_journal_too_large".into());
    }
    Ok(Some(b))
}
fn decode(bytes: Option<&[u8]>) -> Res<Journal> {
    let j = match bytes {
        None => Journal {
            schema: 1,
            records: BTreeMap::new(),
        },
        Some(b) => serde_json::from_slice(b).map_err(|_| "enrollment_journal_invalid")?,
    };
    j.validate()?;
    Ok(j)
}
/// Read-only startup admission. Unknown/corrupt state must refuse startup.
pub fn inspect(root: &Path) -> Res<BTreeMap<String, Record>> {
    let Some(dir) = directory(root, false)? else {
        return Ok(BTreeMap::new());
    };
    let b = read(&dir)?;
    let j = decode(b.as_deref())?;
    dir.sync_all()
        .map_err(|_| "enrollment_journal_durability_unconfirmed")?;
    Ok(j.records
        .into_iter()
        .map(|(id, stored)| (id, Record { stored }))
        .collect())
}
/// Global enrollment allocator lock; never used as a device controller lease.
// LOCK_UN precedes descriptor close. CLOEXEC alone leaves an open-file-
// description inherited by a concurrent fork alive until that child execs.
struct AllocationLock(File);
impl Drop for AllocationLock {
    fn drop(&mut self) {
        if unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) } != 0 {
            eprintln!("readb: enrollment_allocator_unlock_unconfirmed");
        }
    }
}
pub struct Store {
    dir: File,
    _lock: AllocationLock,
    observed: Option<String>,
    poisoned: bool,
    wg: Option<std::path::PathBuf>,
    root: std::path::PathBuf,
}
pub(crate) struct AllocationGuard {
    _store: Store,
}
/// Ordinary catalog add shares the allocator lock, including its journal check.
/// It has no key-generation capability and may not act as an enrollment writer.
pub(crate) fn catalog_guard(root: &Path) -> Res<AllocationGuard> {
    let store = Store::open_inner(root, None)?;
    store.check_admission()?;
    Ok(AllocationGuard { _store: store })
}
/// Allocation lock precedes catalog/transports/runtime/maintenance locks. Keep
/// this guard through upgrade marker publication and postchecks, even when the
/// catalog is empty. Recovery/release observations do not call this gate.
pub(crate) fn maintenance_guard(root: &Path) -> Res<AllocationGuard> {
    let store = Store::open_inner(root, None)?;
    if !store.load()?.records.is_empty() {
        return Err(
            "enrollment_pending: finish or inspect pending enrollment before upgrade".into(),
        );
    }
    Ok(AllocationGuard { _store: store })
}
impl Store {
    pub fn open(root: &Path, wg: &Path) -> Res<Self> {
        let store = Self::open_inner(root, Some(wg.to_path_buf()))?;
        store.check_admission()?;
        Ok(store)
    }
    fn open_inner(root: &Path, wg: Option<std::path::PathBuf>) -> Res<Self> {
        let dir = directory(root, true)?.ok_or("enrollment_directory_unavailable")?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c"lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("enrollment_lock_unavailable".into());
        }
        let lock = unsafe { File::from_raw_fd(fd) };
        private_file(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("enrollment_busy: another enrollment is allocating resources".into());
        }
        let lock = AllocationLock(lock);
        let b = read(&dir)?;
        decode(b.as_deref())?;
        dir.sync_all()
            .map_err(|_| "enrollment_journal_durability_unconfirmed")?;
        let observed = b.as_deref().map(hash);
        Ok(Self {
            dir,
            _lock: lock,
            observed,
            poisoned: false,
            wg,
            root: root.to_path_buf(),
        })
    }
    pub(crate) fn check_admission(&self) -> Res<()> {
        self.bound_to(&self.root)?;
        if crate::maintenance::inspect_active(&self.root)?.is_some() {
            return Err(
                "coordinator_maintenance: enrollment paused until exact upgrade completion".into(),
            );
        }
        Ok(())
    }
    fn load(&self) -> Res<Journal> {
        if self.poisoned {
            return Err(
                "enrollment_publication_unconfirmed: reopen and inspect pending state".into(),
            );
        }
        let b = read(&self.dir)?;
        if b.as_deref().map(hash) != self.observed {
            return Err("enrollment_journal_changed: preserve state and inspect".into());
        }
        decode(b.as_deref())
    }
    fn publish(&mut self, j: &Journal) -> Res<()> {
        self.publish_sync(j, File::sync_all)
    }
    fn publish_sync(
        &mut self,
        j: &Journal,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Res<()> {
        self.check_admission()?;
        j.validate()?;
        self.load()?;
        let b = serde_json::to_vec(j).map_err(|_| "enrollment_encoding_failed")?;
        if b.len() > LIMIT {
            return Err("enrollment_journal_too_large".into());
        }
        let name = std::ffi::CString::new(format!("pending-{}.tmp", random())).unwrap();
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("enrollment_temp_create_failed".into());
        }
        let mut f = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> Res<()> {
            f.write_all(&b)
                .and_then(|_| f.sync_all())
                .map_err(|_| "enrollment_write_failed")?;
            self.load()?;
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    c"journal.json".as_ptr(),
                )
            } != 0
            {
                return Err("enrollment_publish_failed".into());
            }
            self.poisoned = true;
            sync(&self.dir).map_err(|_| "enrollment_publication_unconfirmed")?;
            let actual = read(&self.dir)?;
            if actual.as_deref() != Some(b.as_slice()) {
                return Err("enrollment_publication_changed".into());
            }
            self.observed = Some(hash(&b));
            self.poisoned = false;
            Ok(())
        })();
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        result
    }
    pub(crate) fn bound_to(&self, root: &Path) -> Res<()> {
        let other = directory(root, false)?.ok_or("enrollment_state_binding_missing")?;
        let a = self
            .dir
            .metadata()
            .map_err(|_| "enrollment_metadata_failed")?;
        let b = other.metadata().map_err(|_| "enrollment_metadata_failed")?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Err("enrollment_owned_by_other_state".into());
        }
        Ok(())
    }
    pub(crate) fn bind_ticket(
        &mut self,
        id: &str,
        transaction: &str,
        owner: &Owner,
        previous: Option<&str>,
        ticket: &str,
    ) -> Res<()> {
        self.check_admission()?;
        if !hash_valid(ticket) {
            return Err("enrollment_ticket_invalid".into());
        }
        let mut journal = self.load()?;
        let record = journal.records.get_mut(id).ok_or("enrollment_not_found")?;
        record.authorize(transaction, owner)?;
        if !matches!(record.phase, Phase::CatalogAdded | Phase::ControllerHeld)
            || record.ticket.as_deref() != previous
        {
            return Err("enrollment_ticket_transition_changed".into());
        }
        record.ticket = Some(ticket.to_string());
        record.phase = Phase::ControllerHeld;
        self.publish(&journal)
    }
    pub fn begin(&mut self, m: Material, owner: &Owner) -> Res<Record> {
        self.check_admission()?;
        if !owner_valid(owner) {
            return Err("enrollment_owner_invalid".into());
        }
        let mut j = self.load()?;
        if !j.records.is_empty() {
            return Err(
                "enrollment_pending: recover original transaction before allocating another device"
                    .into(),
            );
        }
        let b = m.private_bytes()?;
        let r = StoredRecord {
            schema: 1,
            transaction: random(),
            owner: owner.clone(),
            phase: Phase::Prepared,
            material_hash: hash(&b),
            material: b,
            expected_config: m.plan().config_fingerprint.clone(),
            catalog_after: None,
            ticket: None,
        };
        r.validate()?;
        j.records.insert(m.plan().id.clone(), r.clone());
        self.publish(&j)?;
        Ok(Record { stored: r })
    }
    pub fn recover(&self, id: &str, owner: &Owner) -> Res<Record> {
        let j = self.load()?;
        let r = j.records.get(id).ok_or("enrollment_not_found")?;
        if !same_owner(&r.owner, owner) {
            return Err("enrollment_owned_by_other_job: use original owner and session".into());
        }
        Ok(Record { stored: r.clone() })
    }
    pub fn prepare_catalog(
        &mut self,
        id: &str,
        transaction: &str,
        owner: &Owner,
        current: &ServerConfig,
    ) -> Res<ServerConfig> {
        self.check_admission()?;
        let mut j = self.load()?;
        let r = j.records.get_mut(id).ok_or("enrollment_not_found")?;
        r.authorize(transaction, owner)?;
        if r.phase != Phase::Prepared {
            return Err("enrollment_catalog_already_prepared: recover recorded transition".into());
        }
        if fingerprint(current)? != r.expected_config {
            return Err("enrollment_catalog_changed: restore expected catalog or inspect pending enrollment".into());
        }
        let import = Material::from_private(
            &r.material,
            self.wg
                .as_deref()
                .ok_or("enrollment_keygen_tool_not_configured")?,
        )?
        .server_import()?;
        let mut next = current.clone();
        next.devices.push(import.device);
        if let Some(l) = import.listener {
            next.listeners.push(l);
        }
        next.validate()?;
        r.catalog_after = Some(fingerprint(&next)?);
        r.phase = Phase::CatalogIntent;
        self.publish(&j)?;
        Ok(next)
    }
    pub fn confirm_catalog(
        &mut self,
        id: &str,
        transaction: &str,
        owner: &Owner,
        current: &ServerConfig,
    ) -> Res<()> {
        self.check_admission()?;
        let mut j = self.load()?;
        let r = j.records.get_mut(id).ok_or("enrollment_not_found")?;
        r.authorize(transaction, owner)?;
        let actual = fingerprint(current)?;
        if r.phase != Phase::CatalogIntent || r.catalog_after.as_ref() != Some(&actual) {
            return Err(
                "enrollment_catalog_transition_unconfirmed: inspect exact recorded catalog".into(),
            );
        }
        r.expected_config = actual;
        r.phase = Phase::CatalogAdded;
        self.publish(&j)
    }
}

fn device_dir(path: &Path, publishing: bool) -> Res<File> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "enrollment_device_directory_unavailable")?;
    let m = dir.metadata().map_err(|_| "enrollment_metadata_failed")?;
    let forbidden = if publishing { 0o7077 } else { 0o7022 };
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & forbidden != 0 {
        return Err("enrollment_owned_nonwritable_device_directory_required".into());
    }
    Ok(dir)
}
fn read_barrier(dir: &File) -> Res<Option<String>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"enrollment-pending.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("enrollment_barrier_unavailable".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private_file(&file)?;
    if file
        .metadata()
        .map_err(|_| "enrollment_metadata_failed")?
        .len()
        > 256
    {
        return Err("enrollment_barrier_invalid".into());
    }
    let mut bytes = Vec::new();
    file.take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| "enrollment_barrier_unavailable")?;
    let transaction: String =
        serde_json::from_slice(&bytes).map_err(|_| "enrollment_barrier_invalid")?;
    if !hash_valid(&transaction) {
        return Err("enrollment_barrier_invalid".into());
    }
    Ok(Some(transaction))
}
pub(crate) fn barrier(path: &Path) -> Res<Option<String>> {
    let dir = device_dir(path, false)?;
    let result = read_barrier(&dir)?;
    dir.sync_all()
        .map_err(|_| "enrollment_barrier_durability_unconfirmed")?;
    Ok(result)
}
pub(crate) fn publish_barrier(path: &Path, transaction: &str) -> Res<()> {
    if !hash_valid(transaction) {
        return Err("enrollment_transaction_invalid".into());
    }
    let dir = device_dir(path, true)?;
    if let Some(current) = read_barrier(&dir)? {
        if current != transaction {
            return Err("enrollment_barrier_owned_by_other_transaction".into());
        }
        return dir
            .sync_all()
            .map_err(|_| "enrollment_barrier_durability_unconfirmed".into());
    }
    let name = std::ffi::CString::new(format!("enrollment-pending-{}.tmp", random())).unwrap();
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("enrollment_barrier_create_failed".into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Res<()> {
        let bytes = serde_json::to_vec(transaction).map_err(|_| "enrollment_encoding_failed")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "enrollment_barrier_sync_failed")?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                name.as_ptr(),
                dir.as_raw_fd(),
                c"enrollment-pending.json".as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("enrollment_barrier_publication_refused".into());
        }
        dir.sync_all()
            .map_err(|_| "enrollment_barrier_durability_unconfirmed")?;
        Ok(())
    })();
    unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn parent_drop_unlocks_even_if_a_fork_equivalent_fd_remains_open() {
        let root = std::env::temp_dir().join(format!("readb-enrollment-lock-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(&root, "/usr/bin/wg".as_ref()).unwrap();
        let inherited = store._lock.0.try_clone().unwrap();
        drop(store);
        let next = Store::open(&root, "/usr/bin/wg".as_ref()).unwrap();
        drop(next);
        drop(inherited);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn barrier_reads_preserve_old_readonly_directories_but_never_accept_writable_or_linked_state() {
        let root = std::env::temp_dir().join(format!("readb-enrollment-mode-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(barrier(&root).unwrap().is_none());
        let transaction = random();
        assert!(publish_barrier(&root, &transaction).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(barrier(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        publish_barrier(&root, &transaction).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(barrier(&root).unwrap(), Some(transaction));
        let marker = root.join("enrollment-pending.json");
        let foreign = root.join("foreign");
        fs::rename(&marker, &foreign).unwrap();
        std::os::unix::fs::symlink(&foreign, &marker).unwrap();
        assert!(barrier(&root).is_err());
        assert!(foreign.is_file());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn renamed_journal_with_failed_directory_sync_stays_pending_until_reopened() {
        let root = std::env::temp_dir().join(format!("readb-enrollment-sync-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(&root, "/usr/bin/wg".as_ref()).unwrap();
        let journal = Journal {
            schema: 1,
            records: BTreeMap::new(),
        };
        let result = store.publish_sync(&journal, |_| {
            Err(std::io::Error::from_raw_os_error(libc::EIO))
        });
        assert!(
            result
                .unwrap_err()
                .contains("enrollment_publication_unconfirmed")
        );
        assert!(root.join("enrollment/journal.json").is_file());
        assert!(
            store
                .load()
                .err()
                .unwrap()
                .contains("enrollment_publication_unconfirmed")
        );
        assert!(store.publish(&journal).is_err());
        drop(store);
        let recovered = Store::open(&root, "/usr/bin/wg".as_ref()).unwrap();
        assert!(recovered.load().unwrap().records.is_empty());
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }
}
