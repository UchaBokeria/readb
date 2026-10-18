//! Private invitation/recipient binding ledger. No peer, profile or device effects.
//! Callers must verify actual setup capability before issuing an invitation, then
//! release this lock before using the sole enrollment/controller effect paths.
use crate::{
    enrollment_profile::Request,
    policy::{Owner, Res, equal, random},
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
    path::{Component, Path, PathBuf},
};
const LIMIT: usize = 2 * 1024 * 1024;
pub fn request_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
fn normalize_code(s: &str) -> Option<String> {
    if !matches!(s.len(), 16 | 19) {
        return None;
    }
    let code = s.bytes().filter(|b| *b != b'-').collect::<Vec<_>>();
    (code.len() == 16 && code.iter().all(u8::is_ascii_hexdigit) && matches!(s.len(), 16 | 19))
        .then(|| String::from_utf8(code).unwrap().to_ascii_lowercase())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    request: Vec<u8>,
    request_sha256: String,
    auth_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    metadata: Request,
    owner: Owner,
    server: String,
    transaction: String,
    code_sha256: String,
    issued: u64,
    expires: u64,
    bound: Option<Bound>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    start: u64,
    count: u32,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u8,
    records: BTreeMap<String, Record>,
    attempts: BTreeMap<String, Window>,
}
impl Ledger {
    fn empty() -> Self {
        Self {
            schema: 1,
            ..Default::default()
        }
    }
    fn validate(&self) -> Res<()> {
        if self.schema != 1 || self.records.len() > 128 || self.attempts.len() > 257 {
            return Err("onboarding_ledger_invalid".into());
        }
        let mut recipients = std::collections::BTreeSet::new();
        let mut codes = std::collections::BTreeSet::new();
        let mut transactions = std::collections::BTreeSet::new();
        for (id, r) in &self.records {
            r.metadata.validate()?;
            if id != &r.metadata.id
                || !owner_valid(&r.owner)
                || !hash_valid(&r.server)
                || !hash_valid(&r.transaction)
                || !hash_valid(&r.code_sha256)
                || !codes.insert(&r.code_sha256)
                || !transactions.insert(&r.transaction)
                || r.expires
                    != r.issued
                        .checked_add(600)
                        .ok_or("onboarding_ledger_invalid")?
            {
                return Err("onboarding_ledger_invalid".into());
            }
            if let Some(b) = &r.bound {
                crate::enrollment_delivery::validate_request(&b.request)?;
                if !hash_valid(&b.auth_sha256)
                    || request_hash(&b.request) != b.request_sha256
                    || !recipients.insert(&b.request_sha256)
                {
                    return Err("onboarding_ledger_invalid".into());
                }
            }
        }
        if self
            .attempts
            .iter()
            .any(|(peer, w)| peer != "global" && !hash_valid(peer) || w.count > 100)
        {
            return Err("onboarding_ledger_invalid".into());
        }
        Ok(())
    }
}
/// Reveal only in the authenticated admin response. No Debug/Serialize.
pub struct Invitation {
    code: String,
    transaction: String,
    expires: u64,
}
impl Invitation {
    pub fn code(&self) -> &str {
        &self.code
    }
    pub fn transaction(&self) -> &str {
        &self.transaction
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
}
/// Public setup identity, without setup code or recovery credential/hash.
#[derive(Clone)]
pub struct Session {
    record: Record,
}
impl Session {
    pub fn id(&self) -> &str {
        &self.record.metadata.id
    }
    pub fn transaction(&self) -> &str {
        &self.record.transaction
    }
    pub fn metadata(&self) -> &Request {
        &self.record.metadata
    }
    pub fn owner(&self) -> &Owner {
        &self.record.owner
    }
    pub fn server_binding(&self) -> &str {
        &self.record.server
    }
    pub fn recipient(&self) -> &[u8] {
        &self.record.bound.as_ref().expect("bound session").request
    }
    pub fn request_sha256(&self) -> &str {
        &self
            .record
            .bound
            .as_ref()
            .expect("bound session")
            .request_sha256
    }
}
fn private(file: &File) -> Res<()> {
    let m = file.metadata().map_err(|_| "onboarding_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7077 != 0
        || m.nlink() != 1
    {
        return Err("onboarding_private_file_required".into());
    }
    Ok(())
}
fn dir(root: &Path, create: bool) -> Res<File> {
    if !root.is_absolute()
        || root
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("onboarding_absolute_state_required".into());
    }
    let base = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| "onboarding_state_unavailable")?;
    let m = base.metadata().map_err(|_| "onboarding_metadata_failed")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7077 != 0 {
        return Err("onboarding_private_state_required".into());
    }
    if create
        && unsafe { libc::mkdirat(base.as_raw_fd(), c"onboarding".as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err("onboarding_directory_create_failed".into());
    }
    let fd = unsafe {
        libc::openat(
            base.as_raw_fd(),
            c"onboarding".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("onboarding_directory_unavailable".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let m = file.metadata().map_err(|_| "onboarding_metadata_failed")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7077 != 0 {
        return Err("onboarding_private_directory_required".into());
    }
    if create {
        base.sync_all()
            .map_err(|_| "onboarding_directory_sync_failed")?;
    }
    Ok(file)
}
fn read(dir: &File) -> Res<Option<Vec<u8>>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"sessions.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("onboarding_ledger_unavailable".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    private(&file)?;
    let mut b = Vec::new();
    file.take(LIMIT as u64 + 1)
        .read_to_end(&mut b)
        .map_err(|_| "onboarding_ledger_read_failed")?;
    if b.len() > LIMIT {
        return Err("onboarding_ledger_too_large".into());
    }
    Ok(Some(b))
}
fn decode(bytes: Option<&[u8]>) -> Res<Ledger> {
    let ledger = match bytes {
        Some(b) => serde_json::from_slice(b).map_err(|_| "onboarding_ledger_invalid")?,
        None => Ledger::empty(),
    };
    ledger.validate()?;
    Ok(ledger)
}
struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}
pub struct Store {
    root: PathBuf,
    dir: File,
    lock: Lock,
    observed: Option<String>,
    poisoned: bool,
}
impl Store {
    pub fn open(root: &Path) -> Res<Self> {
        let dir = dir(root, true)?;
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
            return Err("onboarding_lock_unavailable".into());
        }
        let lock = unsafe { File::from_raw_fd(fd) };
        private(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("onboarding_busy".into());
        }
        let lock = Lock(lock);
        let bytes = read(&dir)?;
        decode(bytes.as_deref())?;
        dir.sync_all()
            .map_err(|_| "onboarding_durability_unconfirmed")?;
        Ok(Self {
            root: root.into(),
            dir,
            lock,
            observed: bytes.as_deref().map(request_hash),
            poisoned: false,
        })
    }
    fn load(&self) -> Res<Ledger> {
        if self.poisoned {
            return Err("onboarding_publication_unconfirmed: reopen exact state".into());
        }
        let other = dir(&self.root, false)?;
        let a = self
            .dir
            .metadata()
            .map_err(|_| "onboarding_metadata_failed")?;
        let b = other.metadata().map_err(|_| "onboarding_metadata_failed")?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err("onboarding_state_changed".into());
        }
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c"lock".as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("onboarding_lock_changed".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private(&file)?;
        let a = self
            .lock
            .0
            .metadata()
            .map_err(|_| "onboarding_metadata_failed")?;
        let b = file.metadata().map_err(|_| "onboarding_metadata_failed")?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err("onboarding_lock_changed".into());
        }
        let bytes = read(&self.dir)?;
        if bytes.as_deref().map(request_hash) != self.observed {
            return Err("onboarding_ledger_changed".into());
        }
        decode(bytes.as_deref())
    }
    fn publish(&mut self, ledger: &Ledger) -> Res<()> {
        self.publish_sync(ledger, File::sync_all)
    }
    fn publish_sync(
        &mut self,
        ledger: &Ledger,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Res<()> {
        ledger.validate()?;
        self.load()?;
        let bytes = serde_json::to_vec(ledger).map_err(|_| "onboarding_encoding_failed")?;
        if bytes.len() > LIMIT {
            return Err("onboarding_ledger_too_large".into());
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
            return Err("onboarding_temp_create_failed".into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> Res<()> {
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "onboarding_write_failed")?;
            self.load()?;
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    c"sessions.json".as_ptr(),
                )
            } != 0
            {
                return Err("onboarding_publish_failed".into());
            }
            self.poisoned = true;
            sync(&self.dir).map_err(|_| "onboarding_publication_unconfirmed")?;
            if read(&self.dir)?.as_deref() != Some(bytes.as_slice()) {
                return Err("onboarding_publication_changed".into());
            }
            self.observed = Some(request_hash(&bytes));
            self.poisoned = false;
            Ok(())
        })();
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        result
    }
    pub fn issue(
        &mut self,
        metadata: &Request,
        owner: &Owner,
        server: &str,
        now: u64,
    ) -> Res<Invitation> {
        metadata.validate()?;
        if !owner_valid(owner) || !hash_valid(server) {
            return Err("onboarding_issue_scope_invalid".into());
        }
        let mut ledger = self.load()?;
        ledger
            .records
            .retain(|_, r| r.bound.is_some() || r.expires >= now);
        if ledger.records.contains_key(&metadata.id) {
            return Err(
                "setup_invitation_exists: revoke an unused invite or resume its original setup"
                    .into(),
            );
        }
        if ledger.records.len() >= 128 {
            return Err("onboarding_session_limit".into());
        }
        let code = random()[..16].to_owned();
        let code_sha256 = request_hash(code.as_bytes());
        if ledger
            .records
            .values()
            .any(|r| r.code_sha256 == code_sha256)
        {
            return Err("onboarding_code_collision_retry".into());
        }
        let transaction = random();
        let expires = now.checked_add(600).ok_or("onboarding_clock_invalid")?;
        ledger.records.insert(
            metadata.id.clone(),
            Record {
                metadata: metadata.clone(),
                owner: owner.clone(),
                server: server.into(),
                transaction: transaction.clone(),
                code_sha256,
                issued: now,
                expires,
                bound: None,
            },
        );
        self.publish(&ledger)?;
        Ok(Invitation {
            code: code
                .as_bytes()
                .chunks(4)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("-"),
            transaction,
            expires,
        })
    }
    fn limited(ledger: &Ledger, peer: &str, now: u64) -> bool {
        let key = request_hash(peer.as_bytes());
        [(key.as_str(), 5), ("global", 100)]
            .iter()
            .any(|(key, max)| {
                ledger
                    .attempts
                    .get(*key)
                    .is_some_and(|w| (now < w.start || now - w.start < 60) && w.count >= *max)
            })
    }
    fn failed(&mut self, mut ledger: Ledger, peer: &str, now: u64) -> Res<Session> {
        ledger
            .attempts
            .retain(|_, w| now < w.start || now - w.start < 60);
        let key = request_hash(peer.as_bytes());
        if Self::limited(&ledger, peer, now) {
            return Err("setup_rate_limited: retry_after_ms=60000".into());
        }
        if !ledger.attempts.contains_key(&key) && ledger.attempts.len() >= 257 {
            return Err("setup_rate_limited: retry_after_ms=60000".into());
        }
        for key in [key, "global".into()] {
            let w = ledger.attempts.entry(key).or_insert(Window {
                start: now,
                count: 0,
            });
            w.count = w.count.saturating_add(1);
        }
        self.publish(&ledger)?;
        Err("invalid_setup".into())
    }
    /// Admin cancel only an unused invitation. A bound/pending setup stays intact.
    pub fn revoke_unused(&mut self, id: &str, owner: &Owner) -> Res<()> {
        let mut ledger = self.load()?;
        let record = ledger
            .records
            .get(id)
            .ok_or("onboarding_invitation_not_found")?;
        if !owner_valid(owner)
            || owner.agent != record.owner.agent
            || owner.origin != record.owner.origin
            || owner.session != record.owner.session
            || owner.job != record.owner.job
            || owner.allow_sleep != record.owner.allow_sleep
        {
            return Err("onboarding_original_owner_required".into());
        }
        if record.bound.is_some() {
            return Err("onboarding_pending_retained: resume the original setup".into());
        }
        ledger.records.remove(id);
        self.publish(&ledger)
    }
    pub fn claim(
        &mut self,
        code: &str,
        recipient: &[u8],
        auth: &str,
        peer: &str,
        now: u64,
    ) -> Res<Session> {
        let mut ledger = self.load()?;
        if !hash_valid(auth) || crate::enrollment_delivery::validate_request(recipient).is_err() {
            return self.failed(ledger, peer, now);
        }
        let Some(code) = normalize_code(code) else {
            return self.failed(ledger, peer, now);
        };
        let codehash = request_hash(code.as_bytes());
        let request_sha256 = request_hash(recipient);
        let authhash = request_hash(auth.as_bytes());
        let Some(id) = ledger
            .records
            .iter()
            .find(|(_, r)| equal(&r.code_sha256, &codehash))
            .map(|(id, _)| id.clone())
        else {
            return self.failed(ledger, peer, now);
        };
        let record = ledger.records.get(&id).unwrap();
        if let Some(b) = &record.bound {
            if equal(&b.request_sha256, &request_sha256)
                && equal(&b.auth_sha256, &authhash)
                && b.request == recipient
            {
                return Ok(Session {
                    record: record.clone(),
                });
            }
            return self.failed(ledger, peer, now);
        }
        if Self::limited(&ledger, peer, now) {
            return Err("setup_rate_limited: retry_after_ms=60000".into());
        }
        if now < record.issued
            || now > record.expires
            || ledger
                .records
                .values()
                .filter_map(|r| r.bound.as_ref())
                .any(|b| b.request_sha256 == request_sha256)
        {
            return self.failed(ledger, peer, now);
        }
        let record = ledger.records.get_mut(&id).unwrap();
        record.bound = Some(Bound {
            request: recipient.into(),
            request_sha256,
            auth_sha256: authhash,
        });
        let session = Session {
            record: record.clone(),
        };
        self.publish(&ledger)?;
        Ok(session)
    }
    pub fn resume(
        &mut self,
        request_sha256: &str,
        auth: &str,
        peer: &str,
        now: u64,
    ) -> Res<Session> {
        let ledger = self.load()?;
        if hash_valid(request_sha256) && hash_valid(auth) {
            let authhash = request_hash(auth.as_bytes());
            if let Some(record) = ledger.records.values().find(|r| {
                r.bound.as_ref().is_some_and(|b| {
                    equal(&b.request_sha256, request_sha256) && equal(&b.auth_sha256, &authhash)
                })
            }) {
                return Ok(Session {
                    record: record.clone(),
                });
            }
        }
        self.failed(ledger, peer, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn lost_directory_sync_receipt_poisoned_handle_reopens_exact_committed_ledger() {
        let root = std::env::temp_dir().join(format!("readb-onboard-sync-{}", random()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(&root).unwrap();
        let mut ledger = store.load().unwrap();
        ledger.attempts.insert(
            "global".into(),
            Window {
                start: 1000,
                count: 1,
            },
        );
        assert!(
            store
                .publish_sync(&ledger, |_| Err(std::io::Error::from_raw_os_error(
                    libc::EIO
                )))
                .is_err()
        );
        assert!(
            store
                .load()
                .err()
                .unwrap()
                .contains("publication_unconfirmed")
        );
        drop(store);
        let store = Store::open(&root).unwrap();
        assert_eq!(store.load().unwrap().attempts["global"].count, 1);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn moved_state_or_lock_and_external_edits_are_preserved_instead_of_overwritten() {
        for action in ["lock", "state", "ledger"] {
            let root = std::env::temp_dir().join(format!("readb-onboard-inode-{}", random()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let store = Store::open(&root).unwrap();
            match action {
                "lock" => {
                    std::fs::rename(
                        root.join("onboarding/lock"),
                        root.join("onboarding/old-lock"),
                    )
                    .unwrap();
                    std::fs::write(root.join("onboarding/lock"), b"").unwrap();
                    std::fs::set_permissions(
                        root.join("onboarding/lock"),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
                "state" => {
                    std::fs::rename(root.join("onboarding"), root.join("old-onboarding")).unwrap();
                    std::fs::create_dir(root.join("onboarding")).unwrap();
                    std::fs::set_permissions(
                        root.join("onboarding"),
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
                _ => {
                    std::fs::write(root.join("onboarding/sessions.json"), b"foreign").unwrap();
                    std::fs::set_permissions(
                        root.join("onboarding/sessions.json"),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .unwrap();
                }
            }
            assert!(store.load().is_err());
            if action == "ledger" {
                assert_eq!(
                    std::fs::read(root.join("onboarding/sessions.json")).unwrap(),
                    b"foreign"
                )
            };
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
