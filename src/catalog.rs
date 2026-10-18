//! Write-ahead catalog publication. Uncertain writes require offline recovery.
use crate::{backend::atomic, policy::Res};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    schema: u8,
    config: PathBuf,
    before: Option<String>,
    after: String,
    added: Option<String>,
}
pub struct Store {
    root: PathBuf,
    config: PathBuf,
    poisoned: std::sync::atomic::AtomicBool,
    baseline: std::sync::Mutex<Res<Option<String>>>,
    target: std::sync::Mutex<Option<PathBuf>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    schema: u8,
    state: PathBuf,
}
fn target_path(config: &Path) -> Res<PathBuf> {
    let parent = fs::canonicalize(config.parent().ok_or("catalog_parent_required")?)
        .map_err(|_| "catalog_parent_unavailable")?;
    Ok(parent.join(config.file_name().ok_or("catalog_filename_required")?))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read(path: &Path, limit: u64) -> Res<Option<Vec<u8>>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("catalog_private_file_unavailable".into()),
    };
    let m = f.metadata().map_err(|_| "catalog_metadata_failed")?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > limit
    {
        return Err("catalog_requires_bounded_private_owned_file".into());
    }
    let mut bytes = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "catalog_read_failed")?;
    if bytes.len() as u64 > limit {
        return Err("catalog_file_too_large".into());
    }
    Ok(Some(bytes))
}
fn directory(path: &Path) -> Res<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "catalog_directory_unavailable".into())
}
fn lock(root: &Path, name: &str) -> Res<File> {
    let dir = directory(root)?;
    let m = dir.metadata().map_err(|_| "catalog_lock_metadata_failed")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("catalog_private_root_required".into());
    }
    let name = std::ffi::CString::new(name).map_err(|_| "catalog_lock_name_invalid")?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("catalog_lock_unavailable".into());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata().map_err(|_| "catalog_lock_metadata_failed")?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("catalog_private_lock_required".into());
    }
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("catalog_busy: stop the coordinator before offline recovery".into());
    }
    Ok(f)
}
fn create_binding(
    name: &Path,
    bytes: &[u8],
    write: impl FnOnce(&mut File, &[u8]) -> Res<()>,
) -> Res<()> {
    use std::os::unix::ffi::OsStrExt;
    let temp = name.with_extension(format!("tmp-{}", crate::policy::random()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|_| "catalog_binding_stage_failed")?;
        write(&mut f, bytes)?;
        f.sync_all()
            .map_err(|_| "catalog_binding_stage_sync_failed")?;
        let from = std::ffi::CString::new(temp.as_os_str().as_bytes())
            .map_err(|_| "catalog_binding_path_invalid")?;
        let to = std::ffi::CString::new(name.as_os_str().as_bytes())
            .map_err(|_| "catalog_binding_path_invalid")?;
        if unsafe {
            // Use the kernel operation directly: older bundled musl has no
            // renameat2 wrapper. Never fall back to replacing an existing binding.
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
            return Err(
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
                    "catalog_binding_exists"
                } else {
                    "catalog_binding_atomic_publish_failed"
                }
                .into(),
            );
        }
        directory(name.parent().ok_or("catalog_parent_required")?)?
            .sync_all()
            .map_err(|_| "catalog_binding_setup_unknown")?;
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}
pub fn runtime_lock(root: &Path, config: &Path) -> Res<File> {
    Store::new(root, config).bind_mode(true)?;
    lock(root, "catalog-runtime.lock")
}
impl Store {
    pub fn new(root: &Path, config: &Path) -> Self {
        Self {
            root: root.into(),
            config: config.into(),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            baseline: std::sync::Mutex::new(
                read(config, 1024 * 1024).map(|v| v.as_deref().map(hash)),
            ),
            target: std::sync::Mutex::new(target_path(config).ok()),
        }
    }
    pub fn for_loaded_config(
        root: &Path,
        config: &Path,
        loaded: &crate::schema::ServerConfig,
    ) -> Res<Self> {
        let raw = read(config, 1024 * 1024)?;
        if let Some(raw) = &raw {
            let actual = crate::schema::ServerConfig::parse(raw)?;
            if serde_json::to_vec(&actual).map_err(|_| "catalog_encoding_failed")?
                != serde_json::to_vec(loaded).map_err(|_| "catalog_encoding_failed")?
            {
                return Err("catalog_loaded_config_changed: reload before startup".into());
            }
        }
        let store = Self::new(root, config);
        *store.baseline.lock().unwrap() = Ok(raw.as_deref().map(hash));
        Ok(store)
    }
    fn bind_mode(&self, create: bool) -> Res<()> {
        use std::io::Write;
        if !self.root.is_absolute()
            || !self.config.is_absolute()
            || self
                .config
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("absolute_catalog_paths_required".into());
        }
        let root = directory(&self.root)?;
        let m = root.metadata().map_err(|_| "catalog_root_unavailable")?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("catalog_private_root_required".into());
        }
        let target = target_path(&self.config)?;
        {
            let mut expected = self.target.lock().unwrap();
            if expected.as_ref().is_some_and(|p| p != &target) {
                return Err("catalog_target_changed".into());
            }
            *expected = Some(target.clone());
        }
        let parent = target.parent().ok_or("catalog_parent_required")?;
        let dir = directory(parent)?;
        let m = dir.metadata().map_err(|_| "catalog_parent_unavailable")?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o022 != 0 {
            return Err("catalog_parent_requires_owner_and_no_other_writers".into());
        }
        use std::os::unix::ffi::OsStrExt;
        let name = parent.join(format!(
            ".readb-state-{}.json",
            hash(target.as_os_str().as_bytes())
        ));
        let binding = Binding {
            schema: 1,
            state: fs::canonicalize(&self.root).map_err(|_| "catalog_root_unavailable")?,
        };
        let bytes = serde_json::to_vec(&binding).map_err(|_| "catalog_binding_encoding_failed")?;
        if bytes.len() > 4096 {
            return Err("catalog_binding_too_large".into());
        }
        if read(&name, 4096)?.is_none() {
            if !create {
                return Err("catalog_existing_binding_required: original coordinator must establish ownership first".into());
            }
            match create_binding(&name, &bytes, |f, b| {
                f.write_all(b)
                    .map_err(|_| "catalog_binding_stage_failed".into())
            }) {
                Ok(()) => (),
                Err(e) if e == "catalog_binding_exists" => (),
                Err(e) => return Err(e),
            }
        }
        let raw = read(&name, 4096)?.ok_or("catalog_binding_unavailable")?;
        let current: Binding =
            serde_json::from_slice(&raw).map_err(|_| "catalog_binding_invalid")?;
        if current.schema != 1 || current.state != binding.state {
            return Err(
                "catalog_owned_by_other_state: use the original state directory for this config"
                    .into(),
            );
        }
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&name)
            .and_then(|f| f.sync_all())
            .map_err(|_| "catalog_binding_setup_unknown")?;
        dir.sync_all()
            .map_err(|_| "catalog_binding_setup_unknown")?;
        Ok(())
    }
    fn check_baseline(&self) -> Res<()> {
        let expected = self.baseline.lock().unwrap().clone()?;
        if read(&self.config, 1024 * 1024)?.as_deref().map(hash) != expected {
            return Err(
                "catalog_external_change: stop coordinator and reload; no config overwrite started"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn fenced(&self) -> bool {
        self.poisoned.load(std::sync::atomic::Ordering::SeqCst)
            || !matches!(fs::symlink_metadata(self.root.join("catalog-pending.json")),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
    }
    pub fn preflight(&self) -> Res<()> {
        self.preflight_mode(true)
    }
    pub(crate) fn preflight_existing(&self) -> Res<()> {
        self.preflight_mode(false)
    }
    fn preflight_mode(&self, create: bool) -> Res<()> {
        if !self.root.is_absolute()
            || !self.config.is_absolute()
            || self
                .config
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("absolute_catalog_paths_required".into());
        }
        let m = fs::symlink_metadata(&self.root).map_err(|_| "catalog_root_unavailable")?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err("catalog_private_root_required".into());
        }
        if self.fenced() {
            return Err("catalog_cleanup_unknown: stop coordinator, run --local config recover --file PATH, then restart".into());
        }
        let parent = self.config.parent().ok_or("catalog_parent_required")?;
        let _ = directory(parent)?;
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| "catalog_parent_invalid")?;
        if unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                c.as_ptr(),
                libc::W_OK | libc::X_OK,
                libc::AT_EACCESS,
            )
        } != 0
        {
            return Err("catalog_parent_not_writable".into());
        }
        self.bind_mode(create)?;
        self.check_baseline()?;
        Ok(())
    }
    fn prepare_locked(&self, next: &impl Serialize, added: Option<&str>) -> Res<Vec<u8>> {
        self.preflight()?;
        if added.is_some_and(|s| !crate::schema::valid_id(s)) {
            return Err("invalid_catalog_added_id".into());
        }
        let bytes = serde_json::to_vec(next).map_err(|_| "catalog_encoding_failed")?;
        if bytes.len() > 1024 * 1024 {
            return Err("catalog_file_too_large".into());
        }
        let pending = Pending {
            schema: 1,
            config: self.config.clone(),
            before: read(&self.config, 1024 * 1024)?.as_deref().map(hash),
            after: hash(&bytes),
            added: added.map(str::to_owned),
        };
        if serde_json::to_vec(&pending)
            .map_err(|_| "catalog_encoding_failed")?
            .len()
            > 4096
        {
            return Err("catalog_journal_too_large".into());
        }
        atomic(&self.root.join("catalog-pending.json"), &pending)?;
        Ok(bytes)
    }
    /// Persist only intent. Used by setup transactions and interrupted-write tests.
    pub fn prepare(&self, next: &impl Serialize, added: Option<&str>) -> Res<Vec<u8>> {
        let _lock = lock(&self.root, "catalog-write.lock")?;
        self.prepare_locked(next, added)
    }
    pub fn publish(&self, next: &impl Serialize, added: Option<&str>) -> Res<()> {
        self.publish_with(next, added, |p, v| atomic(p, v), || self.clear())
    }
    pub fn transaction<T>(
        &self,
        next: &impl Serialize,
        added: Option<&str>,
        stage: impl FnOnce() -> Res<T>,
    ) -> Res<T> {
        self.transaction_with(next, added, stage, |p, v| atomic(p, v), || self.clear())
    }
    fn publish_with<C: Serialize>(
        &self,
        next: &C,
        added: Option<&str>,
        publish: impl FnOnce(&Path, &C) -> Res<()>,
        clear: impl FnOnce() -> Res<()>,
    ) -> Res<()> {
        self.transaction_with(next, added, || Ok(()), publish, clear)
    }
    fn transaction_with<C: Serialize, T>(
        &self,
        next: &C,
        added: Option<&str>,
        stage: impl FnOnce() -> Res<T>,
        publish: impl FnOnce(&Path, &C) -> Res<()>,
        clear: impl FnOnce() -> Res<()>,
    ) -> Res<T> {
        let _lock = lock(&self.root, "catalog-write.lock")?;
        let bytes = self.prepare_locked(next, added)?;
        self.poisoned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let raw = read(&self.root.join("catalog-pending.json"), 4096)?
            .ok_or("catalog_journal_missing")?;
        let pending: Pending =
            serde_json::from_slice(&raw).map_err(|_| "invalid_catalog_journal")?;
        let result = (|| {
            let staged = stage()?;
            self.check_baseline()?;
            publish(&self.config, next)?;
            if read(&self.config, 1024 * 1024)?.as_deref().map(hash) != Some(hash(&bytes)) {
                return Err("catalog_external_change".into());
            }
            clear()?;
            Ok(staged)
        })();
        if result.is_err()
            && matches!(fs::symlink_metadata(self.root.join("catalog-pending.json")),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
        {
            let _ = atomic(&self.root.join("catalog-pending.json"), &pending);
        }
        if result.is_ok() {
            *self.baseline.lock().unwrap() = Ok(Some(hash(&bytes)));
            self.poisoned
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        result.map_err(|_:String|"catalog_cleanup_unknown: staging, publication or durability uncertain; stop coordinator and recover before further catalog writes".into())
    }
    fn clear(&self) -> Res<()> {
        fs::remove_file(self.root.join("catalog-pending.json"))
            .map_err(|_| "catalog_journal_cleanup_failed")?;
        directory(&self.root)?
            .sync_all()
            .map_err(|_| "catalog_journal_sync_failed".into())
    }
}
fn clean_empty_stage(root: &Path, id: &str) -> Res<bool> {
    fn child(parent: &File, name: &str) -> Res<Option<File>> {
        let c = std::ffi::CString::new(name).map_err(|_| "invalid_stage_component")?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err("stage_directory_unavailable".into())
            };
        }
        let f = unsafe { File::from_raw_fd(fd) };
        let m = f.metadata().map_err(|_| "stage_metadata_failed")?;
        if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("stage_private_directory_required".into());
        }
        Ok(Some(f))
    }
    let root = directory(root)?;
    let devices = match child(&root, "devices") {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(false),
        Err(e) => return Err(e),
    };
    let device = match child(&devices, id) {
        Ok(Some(f)) => f,
        Ok(None) => return Ok(false),
        Err(e) => return Err(e),
    };
    match child(&device, ".android") {
        Ok(Some(_)) => {
            if unsafe {
                libc::unlinkat(device.as_raw_fd(), c".android".as_ptr(), libc::AT_REMOVEDIR)
            } != 0
            {
                return if matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
                ) {
                    Ok(true)
                } else {
                    Err("catalog_stage_remove_failed".into())
                };
            }
        }
        Ok(None) => (),
        Err(e) => return Err(e),
    }
    device
        .sync_all()
        .map_err(|_| "catalog_stage_directory_sync_failed")?;
    let id = std::ffi::CString::new(id).unwrap();
    let retained =
        (unsafe { libc::unlinkat(devices.as_raw_fd(), id.as_ptr(), libc::AT_REMOVEDIR) }) != 0;
    if retained
        && !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOTEMPTY) | Some(libc::EEXIST)
        )
    {
        return Err("catalog_stage_remove_failed".into());
    }
    devices
        .sync_all()
        .map_err(|_| "catalog_stage_parent_sync_failed")?;
    Ok(retained)
}
pub fn recover(root: &Path, config: &Path) -> Res<serde_json::Value> {
    let s = Store::new(root, config);
    let raw =
        read(&root.join("catalog-pending.json"), 4096)?.ok_or("no_pending_catalog_operation")?;
    let p: Pending = serde_json::from_slice(&raw).map_err(|_| "invalid_catalog_journal")?;
    if p.schema != 1
        || p.config != config
        || !config.is_absolute()
        || !valid_hash(&p.after)
        || p.before.as_ref().is_some_and(|s| !valid_hash(s))
        || p.added
            .as_ref()
            .is_some_and(|s| !crate::schema::valid_id(s))
    {
        return Err("catalog_journal_target_or_schema_mismatch".into());
    }
    let _runtime = runtime_lock(root, config)?;
    let _write = lock(root, "catalog-write.lock")?;
    if read(&root.join("catalog-pending.json"), 4096)?.as_deref() != Some(raw.as_slice()) {
        return Err("catalog_journal_changed_during_recovery".into());
    }
    let current = read(config, 1024 * 1024)?;
    let current_hash = current.as_deref().map(hash);
    let committed = current_hash.as_deref() == Some(&p.after);
    if !committed && current_hash != p.before {
        return Err(
            "catalog_external_change: preserve journal and review actual configuration".into(),
        );
    }
    if current.is_some() {
        File::open(config)
            .and_then(|f| f.sync_all())
            .map_err(|_| "catalog_recovery_file_sync_failed")?;
    }
    directory(config.parent().ok_or("catalog_parent_required")?)?
        .sync_all()
        .map_err(|_| "catalog_recovery_parent_sync_failed")?;
    let retained = if !committed {
        match p.added.as_deref() {
            Some(id) => clean_empty_stage(root, id)?,
            None => false,
        }
    } else {
        false
    };
    if read(config, 1024 * 1024)?.as_deref().map(hash) != current_hash {
        return Err(
            "catalog_external_change: preserve journal and review actual configuration".into(),
        );
    }
    if let Err(e) = s.clear() {
        let _ = atomic(&root.join("catalog-pending.json"), &p);
        return Err(e);
    }

    Ok(
        serde_json::json!({"recovered":true,"committed":committed,"retained_stage":retained,"next":"Start coordinator to load the persisted configuration; retained keys are never deleted."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn partial_binding_write_never_publishes_a_broken_final_marker() {
        use std::io::Write;
        let root =
            std::env::temp_dir().join(format!("readb-binding-fault-{}", crate::policy::random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = root.join("binding.json");
        assert!(
            create_binding(&marker, b"complete", |f, b| {
                assert!(!marker.exists());
                f.write_all(&b[..2]).unwrap();
                Err("injected interrupted write".into())
            })
            .is_err()
        );
        assert!(!marker.exists());
        create_binding(&marker, b"complete", |f, b| {
            f.write_all(b)
                .and_then(|_| f.sync_all())
                .map_err(|_| "write failed".into())
        })
        .unwrap();
        assert_eq!(fs::read(&marker).unwrap(), b"complete");
        assert!(
            create_binding(&marker, b"replacement", |f, b| {
                f.write_all(b).map_err(|_| "write failed".into())
            })
            .is_err()
        );
        assert_eq!(fs::read(&marker).unwrap(), b"complete");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn injected_publication_and_cleanup_failures_stay_fenced_across_restart() {
        for failure in ["before_publish", "after_publish", "after_clear"] {
            let root = std::env::temp_dir()
                .join(format!("readb-catalog-fault-{}", crate::policy::random()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let cfg = root.join("server.json");
            let store = Store::new(&root, &cfg);
            store
                .publish(&serde_json::json!({"version":1}), None)
                .unwrap();
            let result = store.publish_with(
                &serde_json::json!({"version":2}),
                None,
                |p, value| {
                    if failure == "before_publish" {
                        return Err("injected pre-rename failure".into());
                    }
                    atomic(p, value)?;
                    if failure == "after_publish" {
                        return Err("injected config directory sync failure".into());
                    }
                    Ok(())
                },
                || {
                    if failure == "after_clear" {
                        fs::remove_file(root.join("catalog-pending.json")).unwrap();
                        return Err("injected journal directory sync failure".into());
                    }
                    store.clear()
                },
            );
            assert!(result.is_err());
            assert!(store.fenced());
            drop(store);
            assert!(Store::new(&root, &cfg).fenced());
            // Parallel tests fork sealed runner children. Until exec closes
            // CLOEXEC descriptors, a child can retain our just-released flock.
            // Production correctly refuses that busy state. Wait only for this
            // exact transient admission error; never hide recovery/fence errors.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            let proof = loop {
                match recover(&root, &cfg) {
                    Ok(proof) => break proof,
                    Err(e)
                        if e == "catalog_busy: stop the coordinator before offline recovery"
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(e) => panic!("recovery failed: {e}"),
                }
            };
            assert_eq!(proof["committed"], failure != "before_publish");
            assert!(!Store::new(&root, &cfg).fenced());
            fs::remove_dir_all(root).unwrap();
        }
    }
}
