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
    #[serde(default)]
    activation: crate::setup_activation::Progress,
    #[serde(default)]
    provider_sha256: Option<String>,
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
pub(crate) fn directory(path: &Path) -> Res<File> {
    let dir = open_directory(path)?;
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("setup_busy: another setup holds this journal".into());
    }
    Ok(dir)
}
fn open_directory(path: &Path) -> Res<File> {
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
    Ok(dir)
}
pub(crate) fn snapshot(path: &Path) -> Res<Vec<u8>> {
    existing(&open_directory(path)?)
}
/// Read-only original setup proof. Retaining this handle serializes setup writers.
/// Completion is journal evidence only; callers must still admit real services.
pub struct CompletedSetup {
    pub(crate) dir: File,
    pub(crate) bytes: Vec<u8>,
    pub(crate) plan: String,
    pub(crate) provider: String,
    digest: String,
}
impl CompletedSetup {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.digest
    }
}
fn decode(bytes: &[u8]) -> Res<State> {
    if bytes.len() > 16384 {
        return Err("setup_journal_too_large".into());
    }
    let state: State = serde_json::from_slice(bytes).map_err(|_| "invalid_setup_journal")?;
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
    state.activation.validate()?;
    if state
        .provider_sha256
        .as_ref()
        .is_some_and(|s| !hash_valid(s))
    {
        return Err("invalid_setup_provider_pin".into());
    }
    Ok(state)
}
pub(crate) fn existing(dir: &File) -> Res<Vec<u8>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"journal.json".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err("setup_original_journal_missing".into());
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata().map_err(|_| "journal_metadata_unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o7077 != 0
        || m.len() > 16384
    {
        return Err("journal_private_regular_file_required".into());
    }
    let mut bytes = Vec::new();
    f.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "journal_read_failed")?;
    Ok(bytes)
}
pub(crate) fn admit_completed(bytes: &[u8], plan: &str, provider: &str) -> Res<()> {
    let state = decode(bytes)?;
    if !hash_valid(plan)
        || !hash_valid(provider)
        || state.plan_sha256 != plan
        || state.provider_sha256.as_deref() != Some(provider)
    {
        return Err("setup_original_binding_changed".into());
    }
    if state.running.is_some()
        || !state.completed.contains(&Phase::Persistence)
        || !state.activation.complete()
    {
        return Err("setup_original_incomplete: finish or reconcile original setup first".into());
    }
    Ok(())
}
pub(crate) fn admit_successor(bytes: &[u8], binding: &[u8]) -> Res<()> {
    let current = decode(bytes)?;
    let expected = decode(binding)?;
    if current.plan_sha256 != expected.plan_sha256
        || current.provider_sha256 != expected.provider_sha256
        || !current.completed.starts_with(&expected.completed)
        || serde_json::to_vec(&current.activation)
            .map_err(|_| "setup_activation_encoding_failed")?
            != serde_json::to_vec(&expected.activation)
                .map_err(|_| "setup_activation_encoding_failed")?
    {
        return Err("setup_upgrade_completed_binding_changed".into());
    }
    Ok(())
}
pub fn inspect_completed(path: &Path, plan: &str, provider: &str) -> Res<CompletedSetup> {
    let dir = directory(path)?;
    let bytes = existing(&dir)?;
    admit_completed(&bytes, plan, provider)?;
    use sha2::Digest;
    let digest = sha2::Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(CompletedSetup {
        dir,
        bytes,
        plan: plan.into(),
        provider: provider.into(),
        digest,
    })
}
impl Journal {
    /// The caller creates a private directory first. No untrusted paths are created here.
    pub fn open(path: &Path, plan_sha256: &str) -> Res<Self> {
        if !hash_valid(plan_sha256) {
            return Err("invalid_plan_sha256".into());
        }
        let dir = directory(path)?;
        crate::setup_upgrade::ensure_complete(&dir)?;
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
                activation: Default::default(),
                provider_sha256: None,
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
            let state = decode(&bytes)?;
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
    pub(crate) fn activation_progress(&self) -> crate::setup_activation::Progress {
        self.state.activation.clone()
    }
    pub(crate) fn save_activation(
        &mut self,
        progress: crate::setup_activation::Progress,
    ) -> Res<()> {
        progress.validate()?;
        if self.state.running != Some(Phase::Coordinator)
            || self.admitted != Some(Phase::Coordinator)
        {
            return Err("setup_activation_phase_not_admitted".into());
        }
        self.state.activation = progress;
        self.save()
    }
    pub(crate) fn admit_activation(&mut self, recover: bool) -> Res<()> {
        if self.completed(Phase::Coordinator) {
            if !self.state.activation.complete() {
                return Err("setup_activation_phase_record_inconsistent".into());
            }
            return Ok(());
        }
        if self.state.running == Some(Phase::Coordinator) {
            if !recover {
                return Err("setup_activation_cleanup_unknown: explicit recovery required".into());
            }
            self.admitted = Some(Phase::Coordinator);
            return Ok(());
        }
        self.begin(Phase::Coordinator)
    }
    pub(crate) fn admit_persistence(&mut self, recover: bool) -> Res<()> {
        if self.state.running == Some(Phase::Persistence) {
            if !recover {
                return Err("setup_persistence_cleanup_unknown: explicit recovery required".into());
            }
            self.admitted = Some(Phase::Persistence);
            return Ok(());
        }
        self.begin(Phase::Persistence)
    }
    pub fn running(&self) -> Option<Phase> {
        self.state.running
    }
    /// Bind observed persistence and unrelated peers before activation effects.
    /// A missing legacy pin is not evidence for an already-started activation.
    pub fn bind_provider(&mut self, fingerprint: &str) -> Res<()> {
        if !hash_valid(fingerprint) {
            return Err("invalid_setup_provider_pin".into());
        }
        if let Some(saved) = &self.state.provider_sha256 {
            if saved != fingerprint {
                return Err("setup_provider_changed: preserve original network evidence".into());
            }
            return Ok(());
        }
        if self.completed(Phase::Coordinator)
            || matches!(
                self.running(),
                Some(
                    Phase::Coordinator | Phase::Persistence | Phase::Enrollment | Phase::Acceptance
                )
            )
        {
            return Err("setup_provider_pin_missing: prior activation cannot be adopted".into());
        }
        self.state.provider_sha256 = Some(fingerprint.into());
        self.save()
    }
    /// Only crate setup composition may reconcile. Caller first repeats real
    /// read-only admission, or verifies every journaled network file/receipt.
    pub(crate) fn reconcile_verified(&mut self, phase: Phase) -> Res<()> {
        if !matches!(
            phase,
            Phase::Preflight | Phase::Dependencies | Phase::Network
        ) || self.state.running != Some(phase)
        {
            return Err("setup_reconciliation_phase_mismatch".into());
        }
        self.admitted = Some(phase);
        self.complete(phase)
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

pub(crate) fn verified_upgrade_binding(
    original: &[u8],
    old: &str,
    new: &str,
    provider: &str,
    observations: Vec<(crate::setup_activation::Action, String)>,
) -> Res<Vec<u8>> {
    admit_completed(original, old, provider)?;
    if !hash_valid(new) || new == old {
        return Err("upgrade_new_binding_invalid".into());
    }
    let mut state = decode(original)?;
    state.plan_sha256 = new.into();
    state.activation = crate::setup_activation::Progress::verified(observations)?;
    let bytes = serde_json::to_vec(&state).map_err(|_| "upgrade_binding_encoding_failed")?;
    admit_completed(&bytes, new, provider)?;
    Ok(bytes)
}
