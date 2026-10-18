//! Private durable upgrade marker. Runtime admission belongs to the registry;
//! this store alone never proves that jobs are quiescent or services may stop.
use crate::policy::Res;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    schema: u8,
    upgrade: String,
    config: String,
}
impl Marker {
    pub fn new(upgrade: &str, config: &str) -> Res<Self> {
        let m = Self {
            schema: 1,
            upgrade: upgrade.into(),
            config: config.into(),
        };
        m.validate()?;
        Ok(m)
    }
    fn validate(&self) -> Res<()> {
        if self.schema != 1 || !hash(&self.upgrade) || !hash(&self.config) {
            return Err("maintenance_marker_invalid".into());
        }
        Ok(())
    }
    pub fn upgrade(&self) -> &str {
        &self.upgrade
    }
    pub fn config(&self) -> &str {
        &self.config
    }
}
pub struct Store {
    dir: File,
    _lock: File,
}
fn private(f: &File) -> Res<()> {
    let m = f
        .metadata()
        .map_err(|_| "maintenance_metadata_unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o7077 != 0
    {
        return Err("maintenance_private_regular_file_required".into());
    }
    Ok(())
}
fn directory(path: &Path) -> Res<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("maintenance_absolute_state_path_required".into());
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "maintenance_state_unavailable")?;
    let m = dir
        .metadata()
        .map_err(|_| "maintenance_state_unavailable")?;
    if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7077 != 0 {
        return Err("maintenance_private_state_required".into());
    }
    Ok(dir)
}
fn read_marker(dir: &File, config: &str) -> Res<Option<Marker>> {
    if !hash(config) {
        return Err("maintenance_config_hash_invalid".into());
    }
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"upgrade-maintenance.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err("maintenance_marker_unavailable".into());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    private(&f)?;
    if f.metadata()
        .map_err(|_| "maintenance_metadata_unavailable")?
        .len()
        > 4096
    {
        return Err("maintenance_marker_too_large".into());
    }
    let mut bytes = Vec::new();
    f.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "maintenance_marker_read_failed")?;
    let m: Marker = serde_json::from_slice(&bytes).map_err(|_| "maintenance_marker_invalid")?;
    m.validate()?;
    if m.config != config {
        return Err("maintenance_config_changed".into());
    }
    Ok(Some(m))
}
/// Atomic read-only snapshot, not quiescence authority. Startup must recheck
/// after acquiring the catalog runtime lock; writers use Store's separate lock.
pub fn inspect(path: &Path, config: &str) -> Res<Option<Marker>> {
    read_marker(&directory(path)?, config)
}
impl Store {
    pub fn open(path: &Path) -> Res<Self> {
        let dir = directory(path)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c"upgrade-maintenance.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err("maintenance_lock_unavailable".into());
        }
        let lock = unsafe { File::from_raw_fd(fd) };
        private(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("maintenance_busy".into());
        }
        Ok(Self { dir, _lock: lock })
    }
    pub fn load(&self, config: &str) -> Res<Option<Marker>> {
        read_marker(&self.dir, config)
    }
    pub fn publish(&mut self, marker: &Marker) -> Res<()> {
        self.publish_sync(marker, File::sync_all)
    }
    fn publish_sync(
        &mut self,
        marker: &Marker,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Res<()> {
        marker.validate()?;
        if let Some(current) = self.load(&marker.config)? {
            if current != *marker {
                return Err("maintenance_owned_by_other_upgrade".into());
            }
            return sync(&self.dir).map_err(|_| "maintenance_publication_unconfirmed".into());
        }
        let name = std::ffi::CString::new(format!(
            "upgrade-maintenance-{}.tmp",
            crate::policy::random()
        ))
        .unwrap();
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("maintenance_intent_create_failed".into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| -> Res<()> {
            let bytes = serde_json::to_vec(marker).map_err(|_| "maintenance_encoding_failed")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "maintenance_intent_sync_failed")?;
            if unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    c"upgrade-maintenance.json".as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            } != 0
            {
                return Err("maintenance_publication_refused: existing marker preserved".into());
            }
            sync(&self.dir).map_err(|_| "maintenance_publication_unconfirmed".into())
        })();
        // Only this unique temp name; never consume a changed final marker on error.
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        result
    }
    pub fn remove(&mut self, expected: &Marker) -> Res<()> {
        self.remove_sync(expected, File::sync_all)
    }
    fn remove_sync(
        &mut self,
        expected: &Marker,
        sync: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Res<()> {
        expected.validate()?;
        match self.load(&expected.config)? {
            Some(current) if current == *expected => (),
            Some(_) => return Err("maintenance_owned_by_other_upgrade".into()),
            None => {
                return Err("maintenance_marker_missing: inspect completion before retry".into());
            }
        }
        if unsafe {
            libc::unlinkat(
                self.dir.as_raw_fd(),
                c"upgrade-maintenance.json".as_ptr(),
                0,
            )
        } != 0
        {
            return Err("maintenance_remove_failed".into());
        }
        sync(&self.dir).map_err(|_| "maintenance_resume_unconfirmed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn fixture() -> (std::path::PathBuf, Marker) {
        let p = std::env::temp_dir().join(format!("readb-maint-sync-{}", crate::policy::random()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        (p, Marker::new(&"a".repeat(64), &"b".repeat(64)).unwrap())
    }
    fn fail(_: &File) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    }
    #[test]
    fn post_rename_sync_failure_preserves_visible_marker_and_requires_confirmation() {
        let (p, m) = fixture();
        let mut store = Store::open(&p).unwrap();
        assert_eq!(
            store.publish_sync(&m, fail).unwrap_err(),
            "maintenance_publication_unconfirmed"
        );
        assert!(inspect(&p, m.config()).unwrap() == Some(m.clone()));
        // Exact retry only confirms the same published intent; no new owner.
        store.publish(&m).unwrap();
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn post_unlink_sync_failure_is_ambiguous_not_a_retryable_success() {
        let (p, m) = fixture();
        let mut store = Store::open(&p).unwrap();
        store.publish(&m).unwrap();
        assert_eq!(
            store.remove_sync(&m, fail).unwrap_err(),
            "maintenance_resume_unconfirmed"
        );
        assert!(inspect(&p, m.config()).unwrap().is_none());
        assert!(
            store
                .remove(&m)
                .unwrap_err()
                .contains("maintenance_marker_missing")
        );
        // A fresh daemon can see absence. Root must authorize release only as
        // its last verified phase and recover its journal before further writes.
        drop(store);
        fs::remove_dir_all(p).unwrap();
    }
}
