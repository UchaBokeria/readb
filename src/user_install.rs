//! Private user-file write-ahead transaction. No service start or device operations.
//! The caller admits ownership of existing artifacts and binds its exact plan.
use crate::policy::Res;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Component, Path, PathBuf},
};
const MAX: u64 = 64 * 1024 * 1024;
pub struct Desired {
    path: PathBuf,
    data: Data,
    preserved: bool,
    immutable: bool,
    owned: bool,
}
enum Data {
    File(Vec<u8>, u32),
    Link(PathBuf),
}
impl Desired {
    pub fn file(path: PathBuf, bytes: Vec<u8>, mode: u32) -> Self {
        Self {
            path,
            data: Data::File(bytes, mode),
            preserved: false,
            immutable: false,
            owned: false,
        }
    }
    pub fn link(path: PathBuf, target: PathBuf) -> Self {
        Self {
            path,
            data: Data::Link(target),
            preserved: false,
            immutable: false,
            owned: false,
        }
    }
    pub fn preserve(mut self) -> Self {
        self.preserved = true;
        self
    }
    pub fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }
    pub fn owned(mut self) -> Self {
        self.owned = true;
        self
    }
    fn mark(&self) -> Res<Mark> {
        match &self.data {
            Data::File(bytes, mode)
                if bytes.len() as u64 <= MAX
                    && (*mode == 0o600 || *mode == 0o700 || *mode == 0o400) =>
            {
                Ok(Mark {
                    kind: "file".into(),
                    digest: hash(bytes),
                    mode: *mode,
                })
            }
            Data::Link(target) if valid_path(target) => Ok(Mark {
                kind: "link".into(),
                digest: hash(target.as_os_str().as_encoded_bytes()),
                mode: 0,
            }),
            _ => Err("install_artifact_invalid".into()),
        }
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Mark {
    kind: String,
    digest: String,
    mode: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    path: PathBuf,
    before: Option<Mark>,
    after: Mark,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: u8,
    binding: String,
    receipt_before: Option<String>,
    items: Vec<Item>,
}
pub struct Transaction {
    root: PathBuf,
    _lock: File,
    intent: Intent,
    receipt_before: Option<String>,
    pending_sha: String,
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && !path.as_os_str().as_encoded_bytes().iter().any(|b| *b < 32)
}
/// Inspect every existing ancestor; creation is separate and only private.
fn ancestors(path: &Path, create: bool) -> Res<()> {
    if !valid_path(path) {
        return Err("install_absolute_plain_path_required".into());
    }
    let mut current = PathBuf::from("/");
    for part in path.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        current.push(name);
        let m = match fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    continue;
                }
                let mut b = fs::DirBuilder::new();
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
                b.create(&current)
                    .map_err(|_| "install_directory_create_failed")?;
                sync(current.parent().ok_or("install_parent_missing")?)?;
                fs::symlink_metadata(&current).map_err(|_| "install_directory_metadata_failed")?
            }
            Err(_) => return Err("install_directory_metadata_failed".into()),
        };
        // A root-owned sticky /tmp may contain a private test/user home. No
        // group-writable or foreign-owned path may redirect installed artifacts.
        let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
        if !m.is_dir()
            || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
            || (m.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err("install_unsafe_parent_preserved".into());
        }
    }
    Ok(())
}
fn sync(path: &Path) -> Res<()> {
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(|_| "install_directory_sync_unknown".into())
}
fn read(path: &Path, limit: u64) -> Res<Option<Vec<u8>>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("install_private_file_unavailable".into()),
    };
    let m = f.metadata().map_err(|_| "install_file_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o077 != 0
        || m.len() > limit
    {
        return Err("install_bounded_private_owned_file_required".into());
    }
    let mut bytes = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "install_file_read_failed")?;
    if bytes.len() as u64 > limit {
        return Err("install_file_too_large".into());
    }
    Ok(Some(bytes))
}
fn observe(path: &Path) -> Res<Option<Mark>> {
    ancestors(path.parent().ok_or("install_parent_missing")?, false)?;
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("install_artifact_metadata_failed".into()),
    };
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7000 != 0 {
        return Err("install_foreign_artifact_preserved".into());
    }
    if m.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|_| "install_link_unreadable")?;
        if !valid_path(&target) {
            return Err("install_link_target_invalid".into());
        }
        return Ok(Some(Mark {
            kind: "link".into(),
            digest: hash(target.as_os_str().as_encoded_bytes()),
            mode: 0,
        }));
    }
    let bytes = read(path, MAX)?.ok_or("install_artifact_disappeared")?;
    Ok(Some(Mark {
        kind: "file".into(),
        digest: hash(&bytes),
        mode: m.mode() & 0o777,
    }))
}
fn publish_name(from: &Path, to: &Path, create_only: bool) -> Res<()> {
    if !create_only {
        return fs::rename(from, to).map_err(|_| "install_publish_failed".into());
    }
    use std::os::unix::ffi::OsStrExt;
    let from =
        std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(|_| "install_path_invalid")?;
    let to =
        std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(|_| "install_path_invalid")?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err("install_create_conflict: pending intent preserved".into());
    }
    Ok(())
}
fn bytes(path: &Path, data: &[u8], mode: u32, create_only: bool) -> Res<()> {
    let temp = path.with_extension(format!("stage-{}", crate::policy::random()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "install_stage_create_failed")?;
        f.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| "install_stage_permissions_failed")?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|_| "install_stage_sync_failed")?;
        publish_name(&temp, path, create_only)?;
        sync(path.parent().ok_or("install_parent_missing")?)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
fn decode(raw: &[u8]) -> Res<Intent> {
    let i: Intent = serde_json::from_slice(raw).map_err(|_| "install_invalid_journal_preserved")?;
    let valid_mark = |m: &Mark| {
        (m.kind == "file" && m.mode & !0o700 == 0 || m.kind == "link" && m.mode == 0)
            && m.digest.len() == 64
            && m.digest.bytes().all(|b| b.is_ascii_hexdigit())
    };
    let mut seen = std::collections::BTreeSet::new();
    if i.schema != 1
        || i.binding.is_empty()
        || i.binding.len() > 128
        || i.binding.chars().any(char::is_control)
        || i.receipt_before
            .as_ref()
            .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        || i.items.is_empty()
        || i.items.len() > 16
        || !i.items.iter().all(|a| {
            valid_path(&a.path)
                && seen.insert(&a.path)
                && valid_mark(&a.after)
                && a.before.as_ref().is_none_or(valid_mark)
        })
    {
        return Err("install_invalid_journal_preserved".into());
    }
    Ok(i)
}
fn persist_observed(path: &Path, mark: &Mark) -> Res<()> {
    if observe(path)? != Some(mark.clone()) {
        return Err("install_incomplete: pending intent preserved".into());
    }
    if mark.kind == "file" {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .and_then(|f| f.sync_all())
            .map_err(|_| "install_artifact_sync_unknown")?;
    }
    for parent in path.ancestors().skip(1) {
        sync(parent)?;
    }
    if observe(path)? != Some(mark.clone()) {
        return Err("install_artifact_changed_during_sync".into());
    }
    Ok(())
}
fn clear_pending(root: &Path, intent: &[u8], flush: impl FnOnce(&Path) -> Res<()>) -> Res<()> {
    fs::remove_file(root.join("pending.json")).map_err(|_| "install_pending_clear_failed")?;
    if flush(root).is_err() {
        // Keep a visible fence even when the final unlink sync was uncertain.
        // Restoration itself can fail on broken storage; never report success.
        let restored = bytes(&root.join("pending.json"), intent, 0o600, true).is_ok();
        return Err(if restored {"install_cleanup_unknown: pending intent restored"} else {"install_cleanup_unknown: storage failure prevented fence restoration; inspect receipt before any retry"}.into());
    }
    Ok(())
}
impl Transaction {
    pub fn open(root: &Path, binding: &str, desired: &[Desired], recover: bool) -> Res<Self> {
        if binding.is_empty()
            || binding.len() > 128
            || binding.chars().any(char::is_control)
            || desired.is_empty()
            || desired.len() > 16
        {
            return Err("install_intent_invalid".into());
        }
        // Preflight destinations before even making the journal directory.
        let mut expected = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for item in desired {
            if !valid_path(&item.path) || !seen.insert(&item.path) {
                return Err("install_destination_invalid".into());
            }
            expected.push((item.path.clone(), item.mark()?));
            ancestors(item.path.parent().ok_or("install_parent_missing")?, false)?;
        }
        ancestors(root, true)?;
        let lock = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
            .map_err(|_| "install_journal_unavailable")?;
        let m = lock
            .metadata()
            .map_err(|_| "install_journal_metadata_failed")?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("install_private_journal_required".into());
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("install_busy: another installer owns this home".into());
        }
        // An unrelated receipt is never an invitation to overwrite it.
        let receipt_raw = read(&root.join("receipt.json"), 65536)?;
        let receipt_intent = receipt_raw.as_deref().map(decode).transpose()?;
        let receipt_before = receipt_raw.as_deref().map(hash);
        let pending = root.join("pending.json");
        let intent = if let Some(raw) = read(&pending, 65536)? {
            if !recover {
                return Err("install_cleanup_unknown: rerun the exact command with --recover after reviewing pending files".into());
            }
            let intent = decode(&raw)?;
            let after_receipt =
                hash(&serde_json::to_vec(&intent).map_err(|_| "install_intent_encoding_failed")?);
            if receipt_before != intent.receipt_before && receipt_before != Some(after_receipt) {
                return Err("install_recovery_receipt_changed: pending intent preserved".into());
            }
            if intent.schema != 1
                || intent.binding != binding
                || intent.items.len() != expected.len()
                || !intent
                    .items
                    .iter()
                    .zip(&expected)
                    .all(|(a, (p, m))| &a.path == p && &a.after == m)
            {
                return Err("install_recovery_plan_changed".into());
            }
            for item in &intent.items {
                let current = observe(&item.path)?;
                if current != item.before && current != Some(item.after.clone()) {
                    return Err(
                        "install_recovery_artifact_changed: pending intent preserved".into(),
                    );
                }
            }
            intent
        } else {
            if recover {
                return Err("install_no_pending_operation".into());
            }
            let mut items = Vec::new();
            for (n, (path, after)) in expected.into_iter().enumerate() {
                let before = observe(&path)?;
                if desired[n].owned
                    && before.is_some()
                    && before != Some(after.clone())
                    && !receipt_intent.as_ref().is_some_and(|i| {
                        i.items
                            .iter()
                            .any(|old| old.path == path && Some(old.after.clone()) == before)
                    })
                {
                    return Err("install_unmanaged_completion_preserved".into());
                }
                if (desired[n].preserved && before != Some(after.clone()))
                    || (desired[n].immutable && before.is_some() && before != Some(after.clone()))
                {
                    return Err("install_preserved_artifact_changed".into());
                }
                items.push(Item {
                    path,
                    before,
                    after,
                });
            }
            let intent = Intent {
                schema: 1,
                binding: binding.into(),
                receipt_before: receipt_before.clone(),
                items,
            };
            bytes(
                &pending,
                &serde_json::to_vec(&intent).map_err(|_| "install_intent_encoding_failed")?,
                0o600,
                true,
            )?;
            intent
        };
        let pending_sha =
            hash(&serde_json::to_vec(&intent).map_err(|_| "install_intent_encoding_failed")?);
        if read(&pending, 65536)?.as_deref().map(hash) != Some(pending_sha.clone()) {
            return Err("install_pending_changed: preserve journal and artifacts".into());
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
            intent,
            receipt_before,
            pending_sha,
        })
    }
    fn guard(&self) -> Res<()> {
        if read(&self.root.join("pending.json"), 65536)?
            .as_deref()
            .map(hash)
            != Some(self.pending_sha.clone())
        {
            return Err("install_pending_changed: preserve journal and artifacts".into());
        }
        Ok(())
    }
    pub fn publish(&mut self, index: usize, desired: &Desired) -> Res<()> {
        self.guard()?;
        let item = self.intent.items.get(index).ok_or("install_step_invalid")?;
        if item.path != desired.path || item.after != desired.mark()? {
            return Err("install_step_changed".into());
        }
        let current = observe(&item.path)?;
        if current == Some(item.after.clone()) {
            return Ok(());
        }
        if current != item.before {
            return Err("install_artifact_changed: pending intent preserved".into());
        }
        ancestors(item.path.parent().ok_or("install_parent_missing")?, true)?;
        match &desired.data {
            Data::File(data, mode) => bytes(&item.path, data, *mode, current.is_none())?,
            Data::Link(target) => {
                let temp = item
                    .path
                    .with_extension(format!("stage-{}", crate::policy::random()));
                symlink(target, &temp).map_err(|_| "install_link_stage_failed")?;
                if publish_name(&temp, &item.path, current.is_none()).is_err() {
                    let _ = fs::remove_file(temp);
                    return Err("install_link_publish_failed".into());
                }
                sync(item.path.parent().unwrap())?;
            }
        }
        if observe(&item.path)? != Some(item.after.clone()) {
            return Err("install_after_state_unconfirmed".into());
        }
        Ok(())
    }
    pub fn finish(self) -> Res<()> {
        self.finish_with_flush(persist_observed)
    }
    fn finish_with_flush(self, mut flush: impl FnMut(&Path, &Mark) -> Res<()>) -> Res<()> {
        self.guard()?;
        if read(&self.root.join("receipt.json"), 65536)?
            .as_deref()
            .map(hash)
            != self.receipt_before
        {
            return Err("install_receipt_changed: pending intent preserved".into());
        }
        for item in &self.intent.items {
            flush(&item.path, &item.after)?;
        }
        // Durable receipt precedes removal; a crash between is recoverable by
        // the same after-state checks, never by blindly dropping a pending file.
        bytes(
            &self.root.join("receipt.json"),
            &serde_json::to_vec(&self.intent).map_err(|_| "install_receipt_encoding_failed")?,
            0o600,
            self.receipt_before.is_none(),
        )?;
        clear_pending(
            &self.root,
            &serde_json::to_vec(&self.intent).map_err(|_| "install_intent_encoding_failed")?,
            sync,
        )
    }
}
/// Read only the current install proof. Config/completions may legitimately
/// change later; the caller selects the immutable executable/unit/link core.
pub fn inspect(root: &Path, binding: &str, expected: &[Desired]) -> Res<serde_json::Value> {
    ancestors(root, false)?;
    let lock = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
    {
        Ok(f) => Some(f),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("install_inspection_directory_unsafe".into()),
    };
    if let Some(f) = &lock {
        let m = f
            .metadata()
            .map_err(|_| "install_inspection_directory_unavailable")?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("install_inspection_private_directory_required".into());
        }
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err("install_busy".into());
        }
    }
    if let Some(raw) = read(&root.join("pending.json"), 1024 * 1024)? {
        let intent = decode(&raw)?;
        if intent.binding != binding {
            return Err("install_inspection_pending_scope_mismatch".into());
        }
        return Ok(
            serde_json::json!({"state":"pending","pending_bound":true,"fingerprint":hash(&raw)}),
        );
    }
    let mut present = 0;
    for item in expected {
        if let Some(mark) = observe(&item.path)? {
            present += 1;
            if mark != item.mark()? {
                return Err("install_inspection_owned_artifact_changed".into());
            }
        }
    }
    let state = if present == 0 {
        "absent"
    } else if present == expected.len() {
        let raw = read(&root.join("receipt.json"), 1024 * 1024)?
            .ok_or("install_inspection_receipt_required")?;
        let receipt = decode(&raw)?;
        if receipt.binding != binding {
            return Err("install_inspection_receipt_scope_mismatch".into());
        }
        for item in expected {
            let wanted = item.mark()?;
            if !receipt
                .items
                .iter()
                .any(|r| r.path == item.path && r.after == wanted)
            {
                return Err("install_inspection_receipt_artifact_mismatch".into());
            }
        }
        "ready"
    } else {
        return Err("install_inspection_partial_without_journal".into());
    };
    Ok(
        serde_json::json!({"state":state,"pending_bound":false,"fingerprint":hash(format!("{binding}:{state}").as_bytes())}),
    )
}
pub(crate) fn read_owned(path: &Path, limit: u64) -> Res<Option<Vec<u8>>> {
    ancestors(path.parent().ok_or("install_parent_missing")?, false)?;
    read(path, limit)
}

#[cfg(test)]
mod failure_tests {
    use super::*;
    fn root() -> PathBuf {
        let p = std::env::temp_dir().join(format!("readb-tx-fault-{}", crate::policy::random()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }
    #[test]
    fn accepted_after_state_must_flush_before_receipt_or_clear() {
        let root = root();
        let items = vec![Desired::file(root.join("file"), b"content".to_vec(), 0o600)];
        let journal = root.join("journal");
        {
            let mut tx = Transaction::open(&journal, "scope", &items, false).unwrap();
            tx.publish(0, &items[0]).unwrap();
        }
        let tx = Transaction::open(&journal, "scope", &items, true).unwrap();
        let mut calls = 0;
        assert!(
            tx.finish_with_flush(|_, _| {
                calls += 1;
                Err("injected_sync_failure".into())
            })
            .is_err()
        );
        assert_eq!(calls, 1);
        assert!(journal.join("pending.json").exists());
        assert!(!journal.join("receipt.json").exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_final_unlink_sync_restores_visible_fence() {
        let root = root();
        bytes(&root.join("pending.json"), b"exact intent", 0o600, true).unwrap();
        assert!(
            clear_pending(&root, b"exact intent", |_| Err(
                "injected_sync_failure".into()
            ))
            .is_err()
        );
        assert_eq!(
            read(&root.join("pending.json"), 100).unwrap().unwrap(),
            b"exact intent"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
