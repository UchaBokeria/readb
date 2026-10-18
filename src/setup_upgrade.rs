//! Software-only upgrade ordering. Adapters must prove actual service identity,
//! quiescence and subordinate file recovery; this journal grants none of those.
use crate::{
    policy::Res,
    setup_apply::ApplyPlan,
    setup_journal::{self, CompletedSetup},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
fn hash(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    schema: u8,
    old: String,
    new: String,
    provider: String,
    contract: String,
    old_image: String,
    new_image: String,
    empty_config: Option<String>,
}
impl Plan {
    pub fn new(
        old: &ApplyPlan,
        new: &ApplyPlan,
        old_binary: &[u8],
        new_binary: &[u8],
        provider: &str,
    ) -> Res<Self> {
        old.validate(old_binary)?;
        new.validate(new_binary)?;
        if !valid(provider) || !valid(&old.baseline_sha256) || old.plan_sha256 == new.plan_sha256 {
            return Err("upgrade_requires_changed_binary_and_provider_pin".into());
        }
        let contract = |p: &ApplyPlan| {
            serde_json::to_vec(&(
                &p.owner,
                &p.options,
                &p.policy,
                &p.install_dir,
                &p.baseline_sha256,
            ))
            .map_err(|_| "upgrade_contract_encoding_failed".to_string())
        };
        let before = contract(old)?;
        if before != contract(new)? {
            return Err("upgrade_nonbinary_contract_changed".into());
        }
        Ok(Self {
            schema: 1,
            old: old.plan_sha256.clone(),
            new: new.plan_sha256.clone(),
            provider: provider.into(),
            contract: hash(&before),
            old_image: hash(old_binary),
            new_image: hash(new_binary),
            empty_config: None,
        })
    }
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || self.old == self.new
            || self.old_image == self.new_image
            || self.empty_config.as_ref().is_some_and(|s| !valid(s))
            || [
                &self.old,
                &self.new,
                &self.provider,
                &self.contract,
                &self.old_image,
                &self.new_image,
            ]
            .iter()
            .any(|s| !valid(s))
        {
            Err("upgrade_plan_invalid".into())
        } else {
            Ok(())
        }
    }
    pub fn identity(&self) -> String {
        hash(&serde_json::to_vec(self).expect("fixed upgrade plan"))
    }
    pub fn old_image(&self) -> &str {
        &self.old_image
    }
    pub fn new_image(&self) -> &str {
        &self.new_image
    }
    pub fn empty_config(&self) -> Option<&str> {
        self.empty_config.as_deref()
    }
    pub fn for_empty_config(mut self, fingerprint: &str) -> Res<Self> {
        if !valid(fingerprint) {
            return Err("upgrade_config_hash_invalid".into());
        }
        self.empty_config = Some(fingerprint.into());
        Ok(self)
    }
}
/// Read-only recovery input. Reconstruct and validate the entire expected plan
/// before opening the executable recovery handle; this snapshot grants no effects.
pub(crate) struct RecordInspection {
    pub original: Vec<u8>,
    pub count: Option<usize>,
    pub pending: Option<RollbackAction>,
    pub complete: bool,
}
pub(crate) fn inspect_record(path: &Path, plan: &Plan) -> Res<RecordInspection> {
    let dir = setup_journal::directory(path)?;
    let bytes = read(&dir, c"upgrade.json")?.ok_or("upgrade_no_recorded_operation")?;
    let state: State = serde_json::from_slice(&bytes).map_err(|_| "upgrade_journal_invalid")?;
    state.validate()?;
    if state.plan != *plan {
        return Err("upgrade_plan_changed".into());
    }
    let j = Journal {
        dir,
        state,
        disk: Some(bytes),
        poisoned: false,
    };
    j.check_setup()?;
    Ok(RecordInspection {
        original: j.original_setup().to_vec(),
        count: j.rollback_count(),
        pending: j.rollback_pending(),
        complete: j.rollback_complete(),
    })
}
pub(crate) fn recorded_rollback(path: &Path) -> Res<Option<bool>> {
    let dir = setup_journal::directory(path)?;
    let Some(bytes) = read(&dir, c"upgrade.json")? else {
        return Ok(None);
    };
    let state: State = serde_json::from_slice(&bytes).map_err(|_| "upgrade_journal_invalid")?;
    state.validate()?;
    Ok(state.rollback.as_ref().map(RollbackState::complete))
}
pub fn recorded_plan(path: &Path) -> Res<Option<Plan>> {
    Ok(recorded_status(path)?.map(|(plan, _, _)| plan))
}
pub(crate) fn recorded_status(path: &Path) -> Res<Option<(Plan, Option<Action>, usize)>> {
    let dir = setup_journal::directory(path)?;
    let Some(bytes) = read(&dir, c"upgrade.json")? else {
        return Ok(None);
    };
    let state: State = serde_json::from_slice(&bytes).map_err(|_| "upgrade_journal_invalid")?;
    state.validate()?;
    Ok(Some((
        state.plan,
        state.pending.map(|p| p.action),
        state.completed.len(),
    )))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Maintenance,
    StopUser,
    StopHelper,
    RootFiles,
    UserFiles,
    StartHelper,
    StartUser,
    Binding,
    Resume,
}
pub const ACTIONS: [Action; 9] = [
    Action::Maintenance,
    Action::StopUser,
    Action::StopHelper,
    Action::RootFiles,
    Action::UserFiles,
    Action::StartHelper,
    Action::StartUser,
    Action::Binding,
    Action::Resume,
];
impl Action {
    pub fn index(self) -> usize {
        ACTIONS.iter().position(|a| *a == self).unwrap()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    action: Action,
    before: String,
    after: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    action: Action,
    before: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u8,
    plan: Plan,
    original: Vec<u8>,
    binding: Option<Vec<u8>>,
    completed: Vec<Receipt>,
    pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback: Option<RollbackState>,
}
impl State {
    fn validate(&self) -> Res<()> {
        self.plan.validate()?;
        if let Some(r) = &self.rollback {
            r.validate()?;
        }
        if self.schema != 1
            || self.original.len() > 16384
            || self.completed.len() > ACTIONS.len()
            || self
                .completed
                .iter()
                .enumerate()
                .any(|(i, r)| r.action != ACTIONS[i] || !valid(&r.before) || !valid(&r.after))
            || self.pending.as_ref().is_some_and(|p| {
                ACTIONS.get(self.completed.len()) != Some(&p.action) || !valid(&p.before)
            })
        {
            return Err("upgrade_journal_invalid".into());
        }
        setup_journal::admit_completed(&self.original, &self.plan.old, &self.plan.provider)?;
        if let Some(b) = &self.binding {
            if b.len() > 16384 || self.completed.len() < Action::Binding.index() {
                return Err("upgrade_binding_out_of_order".into());
            }
            setup_journal::admit_completed(b, &self.plan.new, &self.plan.provider)?;
        }
        if self.completed.len() > Action::Binding.index() && self.binding.is_none() {
            return Err("upgrade_binding_missing".into());
        }
        Ok(())
    }
}
fn read(dir: &File, name: &std::ffi::CStr) -> Res<Option<Vec<u8>>> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err("upgrade_file_unavailable".into())
        };
    }
    let f = unsafe { File::from_raw_fd(fd) };
    let m = f.metadata().map_err(|_| "upgrade_metadata_unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o7077 != 0
        || m.len() > 262144
    {
        return Err("upgrade_private_bounded_file_required".into());
    }
    let mut b = Vec::new();
    f.take(262145)
        .read_to_end(&mut b)
        .map_err(|_| "upgrade_read_failed")?;
    if b.len() > 262144 {
        return Err("upgrade_file_too_large".into());
    }
    Ok(Some(b))
}
fn write(dir: &File, name: &std::ffi::CStr, bytes: &[u8], exclusive: bool) -> Res<()> {
    write_sync(dir, name, bytes, exclusive, File::sync_all)
}
fn write_sync(
    dir: &File,
    name: &std::ffi::CStr,
    bytes: &[u8],
    exclusive: bool,
    sync: impl FnOnce(&File) -> std::io::Result<()>,
) -> Res<()> {
    let temp = std::ffi::CString::new(format!("upgrade-{}.tmp", crate::policy::random())).unwrap();
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("upgrade_intent_create_failed".into());
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Res<()> {
        f.write_all(bytes)
            .and_then(|_| f.sync_all())
            .map_err(|_| "upgrade_file_sync_failed")?;
        let flags = if exclusive { libc::RENAME_NOREPLACE } else { 0 };
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                flags,
            )
        } != 0
        {
            return Err("upgrade_publication_refused".into());
        }
        sync(dir).map_err(|_| "upgrade_publication_unconfirmed".into())
    })();
    unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
    result
}
pub(crate) fn ensure_complete(dir: &File) -> Res<()> {
    if let Some(bytes) = read(dir, c"upgrade.json")? {
        let s: State = serde_json::from_slice(&bytes).map_err(|_| "upgrade_journal_invalid")?;
        s.validate()?;
        let binding = if let Some(r) = &s.rollback {
            if !r.complete() {
                return Err(
                    "setup_rollback_pending: use exact rollback recovery before setup".into(),
                );
            }
            &s.original
        } else {
            if s.pending.is_some() || s.completed.len() != ACTIONS.len() {
                return Err(
                    "setup_upgrade_pending: use exact upgrade recovery before setup".into(),
                );
            }
            s.binding.as_ref().ok_or("upgrade_binding_missing")?
        };
        setup_journal::admit_successor(&setup_journal::existing(dir)?, binding)?;
    }
    Ok(())
}
pub struct Journal {
    dir: File,
    state: State,
    disk: Option<Vec<u8>>,
    poisoned: bool,
}
impl Journal {
    pub fn begin(proof: CompletedSetup, plan: Plan) -> Res<Self> {
        plan.validate()?;
        if proof.plan != plan.old || proof.provider != plan.provider {
            return Err("upgrade_original_binding_mismatch".into());
        }
        if setup_journal::existing(&proof.dir)? != proof.bytes {
            return Err("upgrade_original_journal_changed".into());
        }
        let disk = read(&proof.dir, c"upgrade.json")?;
        if let Some(bytes) = &disk {
            let prior: State =
                serde_json::from_slice(bytes).map_err(|_| "upgrade_journal_invalid")?;
            prior.validate()?;
            let prior_binding = if prior.rollback.as_ref().is_some_and(RollbackState::complete) {
                if prior.plan.old != plan.old {
                    return Err("rollback_original_plan_changed".into());
                }
                &prior.original
            } else {
                if prior.rollback.is_some()
                    || prior.pending.is_some()
                    || prior.completed.len() != ACTIONS.len()
                    || prior.plan.new != plan.old
                {
                    return Err("upgrade_already_recorded: inspect exact existing upgrade".into());
                }
                prior.binding.as_ref().ok_or("upgrade_binding_missing")?
            };
            if prior.plan.provider != plan.provider {
                return Err("upgrade_provider_changed".into());
            }
            setup_journal::admit_successor(&proof.bytes, prior_binding)?;
            let first =
                std::ffi::CString::new(format!("upgrade-history-{}.json", prior.plan.identity()))
                    .unwrap();
            let name = match read(&proof.dir, &first)? {
                Some(existing) if existing != *bytes => std::ffi::CString::new(format!(
                    "upgrade-history-{}-{}.json",
                    prior.plan.identity(),
                    hash(bytes)
                ))
                .unwrap(),
                _ => first,
            };
            match read(&proof.dir, &name)? {
                Some(existing) if existing == *bytes => proof
                    .dir
                    .sync_all()
                    .map_err(|_| "upgrade_history_sync_unconfirmed")?,
                Some(_) => return Err("upgrade_history_changed: preserve recorded evidence".into()),
                None => write(&proof.dir, &name, bytes, true)?,
            }
        }
        let mut j = Self {
            dir: proof.dir,
            state: State {
                schema: 1,
                plan,
                original: proof.bytes,
                binding: None,
                completed: vec![],
                pending: None,
                rollback: None,
            },
            disk,
            poisoned: false,
        };
        j.persist()?;
        Ok(j)
    }
    pub fn open(path: &Path, plan: &Plan) -> Res<Self> {
        Self::open_with(path, plan, write)
    }
    fn open_with(
        path: &Path,
        plan: &Plan,
        mut publish: impl FnMut(&File, &std::ffi::CStr, &[u8], bool) -> Res<()>,
    ) -> Res<Self> {
        plan.validate()?;
        let dir = setup_journal::directory(path)?;
        let bytes = read(&dir, c"upgrade.json")?.ok_or("upgrade_no_recorded_operation")?;
        let state: State = serde_json::from_slice(&bytes).map_err(|_| "upgrade_journal_invalid")?;
        state.validate()?;
        if state.plan != *plan {
            return Err("upgrade_plan_changed: preserve exact original operation".into());
        }
        let mut j = Self {
            dir,
            state,
            disk: Some(bytes),
            poisoned: false,
        };
        j.check_setup()?;
        // A prior process can die after rename but before directory fsync.
        // Reconfirm both accepted records before admitting recovery effects.
        j.persist_with(|d, n, b, e| publish(d, n, b, e))?;
        j.check_setup()?;
        let current = setup_journal::existing(&j.dir)?;
        publish(&j.dir, c"journal.json", &current, false)?;
        j.check_setup()?;
        Ok(j)
    }
    fn persist(&mut self) -> Res<()> {
        self.persist_with(write)
    }
    fn persist_with(
        &mut self,
        publish: impl FnOnce(&File, &std::ffi::CStr, &[u8], bool) -> Res<()>,
    ) -> Res<()> {
        if self.poisoned {
            return Err("upgrade_journal_unconfirmed: reopen exact recovery".into());
        }
        self.state.validate()?;
        if read(&self.dir, c"upgrade.json")? != self.disk {
            self.poisoned = true;
            return Err("upgrade_journal_changed_externally".into());
        }
        let bytes = serde_json::to_vec(&self.state).map_err(|_| "upgrade_encoding_failed")?;
        if bytes.len() > 262144 {
            return Err("upgrade_journal_too_large".into());
        }
        if let Err(e) = publish(&self.dir, c"upgrade.json", &bytes, self.disk.is_none()) {
            self.poisoned = true;
            return Err(e);
        }
        self.disk = Some(bytes);
        Ok(())
    }
    fn check_setup(&self) -> Res<()> {
        if self.poisoned {
            return Err("upgrade_journal_unconfirmed".into());
        }
        if read(&self.dir, c"upgrade.json")? != self.disk {
            return Err("upgrade_journal_changed_externally".into());
        }
        let current = setup_journal::existing(&self.dir)?;
        if let Some(r) = &self.state.rollback {
            if r.completed.len() > RollbackAction::Binding.index() {
                if r.complete() {
                    setup_journal::admit_successor(&current, &self.state.original)?;
                } else if current != self.state.original {
                    return Err("rollback_original_binding_changed".into());
                }
                return Ok(());
            }
            if r.pending
                .as_ref()
                .is_some_and(|p| p.action == RollbackAction::Binding)
                && current == self.state.original
            {
                return Ok(());
            }
        }
        if self.state.completed.len() > Action::Binding.index() {
            if self.complete() {
                setup_journal::admit_successor(
                    &current,
                    self.state
                        .binding
                        .as_ref()
                        .ok_or("upgrade_binding_missing")?,
                )?;
            } else if self.state.binding.as_ref() != Some(&current) {
                return Err("upgrade_completed_binding_changed".into());
            }
        } else if current != self.state.original
            && !(self
                .state
                .pending
                .as_ref()
                .is_some_and(|p| p.action == Action::Binding)
                && self.state.binding.as_ref() == Some(&current))
        {
            return Err("upgrade_original_journal_changed".into());
        }
        Ok(())
    }
    pub fn publish_binding(&mut self, bytes: &[u8]) -> Res<()> {
        self.publish_binding_with(bytes, write)
    }
    fn publish_binding_with(
        &mut self,
        bytes: &[u8],
        publish: impl FnOnce(&File, &std::ffi::CStr, &[u8], bool) -> Res<()>,
    ) -> Res<()> {
        self.check_setup()?;
        if self.state.rollback.is_some()
            || self.state.pending.as_ref().map(|p| p.action) != Some(Action::Binding)
        {
            return Err("upgrade_binding_phase_not_admitted".into());
        }
        if bytes.len() > 16384 {
            return Err("upgrade_binding_too_large".into());
        }
        setup_journal::admit_completed(bytes, &self.state.plan.new, &self.state.plan.provider)?;
        if self.state.binding.as_ref().is_some_and(|b| b != bytes) {
            return Err("upgrade_binding_changed".into());
        }
        self.state.binding = Some(bytes.to_vec());
        self.persist()?;
        if let Err(e) = publish(&self.dir, c"journal.json", bytes, false) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }
    pub fn complete(&self) -> bool {
        !self.poisoned
            && self.state.rollback.is_none()
            && self.state.pending.is_none()
            && self.state.completed.len() == ACTIONS.len()
    }
    pub fn original_setup(&self) -> &[u8] {
        &self.state.original
    }
    pub fn completed_count(&self) -> usize {
        self.state.completed.len()
    }
    pub fn pending(&self) -> Option<Action> {
        self.state.pending.as_ref().map(|p| p.action)
    }
    pub(crate) fn pending_before(&self) -> Option<&str> {
        self.state.pending.as_ref().map(|p| p.before.as_str())
    }
    pub fn identity(&self) -> String {
        self.state.plan.identity()
    }
}
pub struct Observation {
    pub fingerprint: String,
    pub ready: bool,
    pub retry_safe: bool,
}
pub trait Actions {
    /// Admit aggregate current state at this phase; earlier stop effects are no
    /// longer ready after a later start. Never replay completed destructive steps.
    fn admit(&mut self, journal: &Journal) -> Res<()>;
    fn inspect(&mut self, action: Action) -> Res<Observation>;
    fn apply(&mut self, action: Action, journal: &mut Journal, recover: bool) -> Res<()>;
    /// Reconfirm durable subordinate files/markers, including an already visible
    /// ready effect after lost acknowledgement. Never grants unrelated writes.
    fn confirm(&mut self, action: Action, journal: &Journal) -> Res<()>;
}
pub fn run(j: &mut Journal, adapter: &mut impl Actions, recover: bool) -> Res<()> {
    j.check_setup()?;
    if j.state.rollback.is_some() {
        return Err("upgrade_has_rollback: preserve recorded rollback".into());
    }
    if j.pending().is_some() && !recover {
        return Err("upgrade_cleanup_unknown: explicit exact recovery required".into());
    }
    for action in ACTIONS.into_iter().skip(j.completed_count()) {
        j.check_setup()?;
        adapter.admit(j)?;
        let observed = adapter.inspect(action)?;
        if !valid(&observed.fingerprint) {
            return Err("upgrade_observation_invalid".into());
        }
        let pending = j.pending().is_some();
        if let Some(p) = &j.state.pending {
            if p.action != action
                || (!observed.ready && (!observed.retry_safe || observed.fingerprint != p.before))
            {
                return Err("upgrade_unknown_state: preserve pending operation".into());
            }
        } else {
            if !observed.ready && !observed.retry_safe {
                return Err("upgrade_before_state_unsafe".into());
            }
            j.state.pending = Some(Pending {
                action,
                before: observed.fingerprint.clone(),
            });
            j.persist()?;
        }
        j.check_setup()?;
        if !observed.ready {
            adapter.apply(action, j, pending && recover)?;
        }
        let after = adapter.inspect(action)?;
        if !after.ready || !valid(&after.fingerprint) {
            return Err("upgrade_effect_unconfirmed".into());
        }
        adapter.confirm(action, j)?;
        j.check_setup()?;
        if action == Action::Binding {
            let current = setup_journal::existing(&j.dir)?;
            if j.state.binding.as_ref() != Some(&current) {
                return Err("upgrade_binding_effect_unconfirmed".into());
            }
        }
        let p = j.state.pending.take().unwrap();
        j.state.completed.push(Receipt {
            action,
            before: p.before,
            after: after.fingerprint,
        });
        j.persist()?;
    }
    j.check_setup()?;
    adapter.admit(j)?;
    Ok(())
}

/// Rollback starts legacy code only after the original binding and marker release
/// are durable. A separate progress stream preserves all forward receipts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackAction {
    Maintenance,
    StopUser,
    StopHelper,
    RootFiles,
    UserFiles,
    StartHelper,
    Binding,
    Release,
    StartUser,
}
pub const ROLLBACK_ACTIONS: [RollbackAction; 9] = [
    RollbackAction::Maintenance,
    RollbackAction::StopUser,
    RollbackAction::StopHelper,
    RollbackAction::RootFiles,
    RollbackAction::UserFiles,
    RollbackAction::StartHelper,
    RollbackAction::Binding,
    RollbackAction::Release,
    RollbackAction::StartUser,
];
impl RollbackAction {
    pub fn index(self) -> usize {
        ROLLBACK_ACTIONS.iter().position(|a| *a == self).unwrap()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackReceipt {
    action: RollbackAction,
    before: String,
    after: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackPending {
    action: RollbackAction,
    before: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackState {
    schema: u8,
    orchestrator: String,
    completed: Vec<RollbackReceipt>,
    pending: Option<RollbackPending>,
}
impl RollbackState {
    fn complete(&self) -> bool {
        self.pending.is_none() && self.completed.len() == ROLLBACK_ACTIONS.len()
    }
    fn validate(&self) -> Res<()> {
        if self.schema != 1
            || !valid(&self.orchestrator)
            || self.completed.len() > ROLLBACK_ACTIONS.len()
            || self.completed.iter().enumerate().any(|(i, r)| {
                r.action != ROLLBACK_ACTIONS[i] || !valid(&r.before) || !valid(&r.after)
            })
            || self.pending.as_ref().is_some_and(|p| {
                ROLLBACK_ACTIONS.get(self.completed.len()) != Some(&p.action) || !valid(&p.before)
            })
        {
            return Err("rollback_journal_invalid".into());
        }
        Ok(())
    }
}
impl Journal {
    pub fn begin_rollback(&mut self, image: &str) -> Res<()> {
        self.check_setup()?;
        if !valid(image) {
            return Err("rollback_orchestrator_hash_invalid".into());
        }
        if let Some(r) = &self.state.rollback {
            if r.orchestrator != image {
                return Err("rollback_orchestrator_changed: use exact recorded image".into());
            }
            return Ok(());
        }
        self.state.rollback = Some(RollbackState {
            schema: 1,
            orchestrator: image.into(),
            completed: vec![],
            pending: None,
        });
        self.persist()
    }
    pub fn rollback_complete(&self) -> bool {
        !self.poisoned
            && self
                .state
                .rollback
                .as_ref()
                .is_some_and(RollbackState::complete)
    }
    pub fn rollback_count(&self) -> Option<usize> {
        self.state.rollback.as_ref().map(|r| r.completed.len())
    }
    pub fn rollback_pending(&self) -> Option<RollbackAction> {
        self.state
            .rollback
            .as_ref()
            .and_then(|r| r.pending.as_ref().map(|p| p.action))
    }
    pub(crate) fn rollback_before(&self) -> Option<&str> {
        self.state
            .rollback
            .as_ref()
            .and_then(|r| r.pending.as_ref().map(|p| p.before.as_str()))
    }
    pub fn publish_original_binding(&mut self) -> Res<()> {
        self.publish_original_with(write)
    }
    fn publish_original_with(
        &mut self,
        publish: impl FnOnce(&File, &std::ffi::CStr, &[u8], bool) -> Res<()>,
    ) -> Res<()> {
        self.check_setup()?;
        if self.rollback_pending() != Some(RollbackAction::Binding) {
            return Err("rollback_binding_phase_not_admitted".into());
        }
        if let Err(e) = publish(&self.dir, c"journal.json", &self.state.original, false) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }
}
pub trait RollbackActions {
    fn admit(&mut self, journal: &Journal) -> Res<()>;
    fn inspect(&mut self, action: RollbackAction) -> Res<Observation>;
    fn apply(&mut self, action: RollbackAction, journal: &mut Journal, recover: bool) -> Res<()>;
    fn confirm(&mut self, action: RollbackAction, journal: &Journal) -> Res<()>;
}
pub fn run_rollback(j: &mut Journal, adapter: &mut impl RollbackActions, recover: bool) -> Res<()> {
    j.check_setup()?;
    let state = j.state.rollback.as_ref().ok_or("rollback_not_admitted")?;
    if state.pending.is_some() && !recover {
        return Err("rollback_cleanup_unknown: explicit exact recovery required".into());
    }
    for action in ROLLBACK_ACTIONS.into_iter().skip(state.completed.len()) {
        j.check_setup()?;
        adapter.admit(j)?;
        let observed = adapter.inspect(action)?;
        if !valid(&observed.fingerprint) {
            return Err("rollback_observation_invalid".into());
        }
        let pending = j.rollback_pending().is_some();
        if let Some(p) = &j.state.rollback.as_ref().unwrap().pending {
            if p.action != action
                || (!observed.ready && (!observed.retry_safe || observed.fingerprint != p.before))
            {
                return Err("rollback_unknown_state: preserve pending operation".into());
            }
        } else {
            if !observed.ready && !observed.retry_safe {
                return Err("rollback_before_state_unsafe".into());
            }
            j.state.rollback.as_mut().unwrap().pending = Some(RollbackPending {
                action,
                before: observed.fingerprint.clone(),
            });
            j.persist()?;
        }
        j.check_setup()?;
        if !observed.ready {
            adapter.apply(action, j, pending && recover)?;
        }
        let after = adapter.inspect(action)?;
        if !after.ready || !valid(&after.fingerprint) {
            return Err("rollback_effect_unconfirmed".into());
        }
        adapter.confirm(action, j)?;
        j.check_setup()?;
        if action == RollbackAction::Binding {
            if setup_journal::existing(&j.dir)? != j.state.original {
                return Err("rollback_binding_effect_unconfirmed".into());
            }
            // Even a ready observation needs directory durability, e.g. original bytes
            // were already visible before rollback or after a lost publication reply.
            j.publish_original_binding()?;
        }
        let r = j.state.rollback.as_mut().unwrap();
        let p = r.pending.take().unwrap();
        r.completed.push(RollbackReceipt {
            action,
            before: p.before,
            after: after.fingerprint,
        });
        j.persist()?;
    }
    j.check_setup()?;
    adapter.admit(j)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> (std::path::PathBuf, Journal, Plan) {
        let p =
            std::env::temp_dir().join(format!("readb-upgrade-sync-{}", crate::policy::random()));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        let original = serde_json::json!({"schema":1,"plan_sha256":"a".repeat(64),"provider_sha256":"b".repeat(64),"completed":["preflight","dependencies","network","coordinator","persistence"],"running":null,"activation":{"completed":crate::setup_activation::ACTIONS.iter().map(|a|serde_json::json!({"action":a,"before":"e".repeat(64),"after":"f".repeat(64)})).collect::<Vec<_>>(),"pending":null}});
        std::fs::write(
            p.join("journal.json"),
            serde_json::to_vec(&original).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            p.join("journal.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let plan = Plan {
            schema: 1,
            old: "a".repeat(64),
            new: "c".repeat(64),
            provider: "b".repeat(64),
            contract: "d".repeat(64),
            old_image: "1".repeat(64),
            new_image: "2".repeat(64),
            empty_config: None,
        };
        let proof = setup_journal::inspect_completed(&p, &plan.old, &plan.provider).unwrap();
        let j = Journal::begin(proof, plan.clone()).unwrap();
        (p, j, plan)
    }
    fn fail(_: &File) -> std::io::Result<()> {
        Err(std::io::Error::from_raw_os_error(libc::EIO))
    }
    #[test]
    fn post_rename_intent_sync_failure_poisoned_handle_and_restart_keeps_pending() {
        let (p, mut j, plan) = fixture();
        j.state.pending = Some(Pending {
            action: Action::Maintenance,
            before: "e".repeat(64),
        });
        assert!(
            j.persist_with(|d, n, b, e| write_sync(d, n, b, e, fail))
                .is_err()
        );
        assert!(j.check_setup().is_err());
        drop(j);
        assert!(
            Journal::open_with(&p, &plan, |d, n, b, e| write_sync(d, n, b, e, fail)).is_err(),
            "recovery cannot admit an undurable pending record"
        );
        let j = Journal::open(&p, &plan).unwrap();
        assert_eq!(j.pending(), Some(Action::Maintenance));
        assert!(!j.complete());
        drop(j);
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn post_rename_binding_sync_failure_keeps_durable_binding_intent() {
        let (p, mut j, plan) = fixture();
        j.state.completed = ACTIONS[..Action::Binding.index()]
            .iter()
            .map(|a| Receipt {
                action: *a,
                before: "e".repeat(64),
                after: "f".repeat(64),
            })
            .collect();
        j.state.pending = Some(Pending {
            action: Action::Binding,
            before: "e".repeat(64),
        });
        j.persist().unwrap();
        let mut next: serde_json::Value = serde_json::from_slice(j.original_setup()).unwrap();
        next["plan_sha256"] = serde_json::json!(plan.new);
        let binding = serde_json::to_vec(&next).unwrap();
        assert!(
            j.publish_binding_with(&binding, |d, n, b, e| write_sync(d, n, b, e, fail))
                .is_err()
        );
        assert!(j.check_setup().is_err());
        assert_eq!(std::fs::read(p.join("journal.json")).unwrap(), binding);
        drop(j);
        assert!(
            Journal::open_with(&p, &plan, |d, n, b, e| if n == c"journal.json" {
                write_sync(d, n, b, e, fail)
            } else {
                write(d, n, b, e)
            })
            .is_err(),
            "new binding must be durability-confirmed before resume"
        );
        let j = Journal::open(&p, &plan).unwrap();
        assert_eq!(j.pending(), Some(Action::Binding));
        assert!(!j.complete());
        drop(j);
        assert!(setup_journal::Journal::open(&p, &plan.new).is_err());
        std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn rollback_binding_sync_ambiguity_keeps_forward_and_rollback_pending() {
        let (p, mut j, plan) = fixture();
        j.begin_rollback(&"8".repeat(64)).unwrap();
        let r = j.state.rollback.as_mut().unwrap();
        r.completed = ROLLBACK_ACTIONS[..RollbackAction::Binding.index()]
            .iter()
            .map(|a| RollbackReceipt {
                action: *a,
                before: "e".repeat(64),
                after: "f".repeat(64),
            })
            .collect();
        r.pending = Some(RollbackPending {
            action: RollbackAction::Binding,
            before: "e".repeat(64),
        });
        j.persist().unwrap();
        let original = j.original_setup().to_vec();
        assert!(
            j.publish_original_with(|d, n, b, e| write_sync(d, n, b, e, fail))
                .is_err()
        );
        assert!(j.check_setup().is_err());
        drop(j);
        assert!(
            Journal::open_with(&p, &plan, |d, n, b, e| if n == c"journal.json" {
                write_sync(d, n, b, e, fail)
            } else {
                write(d, n, b, e)
            })
            .is_err()
        );
        let j = Journal::open(&p, &plan).unwrap();
        assert_eq!(j.rollback_pending(), Some(RollbackAction::Binding));
        assert!(!j.rollback_complete());
        assert!(!j.complete());
        assert_eq!(j.original_setup(), original);
        drop(j);
        assert!(setup_journal::Journal::open(&p, &plan.old).is_err());
        std::fs::remove_dir_all(p).unwrap();
    }
}
