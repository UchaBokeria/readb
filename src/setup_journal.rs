//! Durable phase ordering. A running phase on restart needs explicit reconciliation.
//! This module grants no authority to provision networks or skip acceptance.
use crate::policy::Res;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preflight,
    Dependencies,
    Network,
    Coordinator,
    Persistence,
    Enrollment,
    Acceptance,
}
const PHASES: [Phase; 7] = [
    Phase::Preflight,
    Phase::Dependencies,
    Phase::Network,
    Phase::Coordinator,
    Phase::Persistence,
    Phase::Enrollment,
    Phase::Acceptance,
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u8,
    plan_sha256: String,
    completed: Vec<Phase>,
    running: Option<Phase>,
}
pub struct Journal {
    dir: File,
    state: State,
    admitted: Option<Phase>,
}
fn hash_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn directory(path: &Path) -> Res<File> {
    if !path.is_absolute() {
        return Err("absolute_journal_directory_required".into());
    }
    // Walk with pinned directory descriptors, never through an intermediate symlink.
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "journal_directory_unavailable")?;
    let mut count = 0;
    for c in path.components() {
        let name = match c {
            Component::RootDir => continue,
            Component::Normal(n) => n,
            _ => return Err("journal_path_components_invalid".into()),
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| "invalid_journal_path")?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("journal_directory_unavailable_or_symlink".into());
        }
        dir = unsafe { File::from_raw_fd(fd) };
        count += 1;
    }
    let m = dir.metadata().map_err(|_| "journal_metadata_unavailable")?;
    if count == 0 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("journal_requires_owned_private_directory".into());
    }
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("setup_busy: another setup holds this journal".into());
    }
    Ok(dir)
}
impl Journal {
    /// The caller creates a private directory first. No untrusted paths are created here.
    pub fn open(path: &Path, plan_sha256: &str) -> Res<Self> {
        if !hash_valid(plan_sha256) {
            return Err("invalid_plan_sha256".into());
        }
        let dir = directory(path)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c"journal.json".as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let state = if fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                return Err("journal_read_failed".into());
            }
            State {
                schema: 1,
                plan_sha256: plan_sha256.into(),
                completed: vec![],
                running: None,
            }
        } else {
            let f = unsafe { File::from_raw_fd(fd) };
            let m = f.metadata().map_err(|_| "journal_metadata_unavailable")?;
            if !m.is_file()
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0
                || m.len() > 16384
            {
                return Err("journal_private_regular_file_required".into());
            }
            let mut bytes = Vec::new();
            f.take(16385)
                .read_to_end(&mut bytes)
                .map_err(|_| "journal_read_failed")?;
            let state: State =
                serde_json::from_slice(&bytes).map_err(|_| "invalid_setup_journal")?;
            if state.schema != 1
                || !hash_valid(&state.plan_sha256)
                || state.completed.len() > PHASES.len()
                || state.completed != PHASES[..state.completed.len()]
                || state
                    .running
                    .is_some_and(|p| PHASES.get(state.completed.len()) != Some(&p))
            {
                return Err("invalid_setup_journal".into());
            }
            if state.plan_sha256 != plan_sha256 {
                return Err(
                    "setup_plan_changed: preserve the old journal and review the changed plan"
                        .into(),
                );
            }
            state
        };
        let mut j = Self {
            dir,
            state,
            admitted: None,
        };
        j.save()?;
        Ok(j)
    }
    fn save(&mut self) -> Res<()> {
        let name =
            std::ffi::CString::new(format!("journal-{}.tmp", crate::policy::random())).unwrap();
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("journal_write_failed".into());
        }
        let result = (|| {
            let mut f = unsafe { File::from_raw_fd(fd) };
            let bytes = serde_json::to_vec(&self.state).map_err(|_| "journal_encoding_failed")?;
            f.write_all(&bytes)
                .and_then(|_| f.sync_all())
                .map_err(|_| "journal_sync_failed")?;
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    c"journal.json".as_ptr(),
                )
            } != 0
            {
                return Err("journal_replace_failed".into());
            }
            self.dir
                .sync_all()
                .map_err(|_| "journal_directory_sync_failed")?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result
    }
    pub fn completed(&self, phase: Phase) -> bool {
        self.state.completed.contains(&phase)
    }
    pub fn begin(&mut self, phase: Phase) -> Res<()> {
        if self.state.running.is_some() {
            return Err(
                "setup_cleanup_unknown: reconcile the interrupted phase before any new work".into(),
            );
        }
        if PHASES.get(self.state.completed.len()) != Some(&phase) {
            return Err("setup_phase_out_of_order".into());
        }
        self.state.running = Some(phase);
        self.save()?;
        self.admitted = Some(phase);
        Ok(())
    }
    pub fn complete(&mut self, phase: Phase) -> Res<()> {
        if self.state.running.is_some() && self.admitted != Some(phase) {
            return Err(
                "setup_cleanup_unknown: only a phase begun by this handle can complete".into(),
            );
        }
        if self.state.running != Some(phase) {
            return Err("setup_phase_not_running".into());
        }
        self.state.completed.push(phase);
        self.state.running = None;
        self.admitted = None;
        // A write failure must keep this in-memory handle fenced too.
        if let Err(e) = self.save() {
            self.state.completed.pop();
            self.state.running = Some(phase);
            return Err(e);
        }
        Ok(())
    }
}
