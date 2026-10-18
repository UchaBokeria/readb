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
impl Store {
    pub fn open(path: &Path) -> Res<Self> {
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
        if !hash(config) {
            return Err("maintenance_config_hash_invalid".into());
        }
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
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
    pub fn publish(&mut self, marker: &Marker) -> Res<()> {
        marker.validate()?;
        if let Some(current) = self.load(&marker.config)? {
            if current != *marker {
                return Err("maintenance_owned_by_other_upgrade".into());
            }
            return self
                .dir
                .sync_all()
                .map_err(|_| "maintenance_publication_unconfirmed".into());
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
            self.dir
                .sync_all()
                .map_err(|_| "maintenance_publication_unconfirmed".into())
        })();
        // Only this unique temp name; never consume a changed final marker on error.
        unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        result
    }
    pub fn remove(&mut self, expected: &Marker) -> Res<()> {
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
        self.dir
            .sync_all()
            .map_err(|_| "maintenance_resume_unconfirmed".into())
    }
}
