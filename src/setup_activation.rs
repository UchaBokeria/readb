//! Durable activation ordering. The concrete adapter must independently admit
//! exact files, service identity, quiescence and subordinate installer recovery.
use crate::{
    policy::Res,
    setup_journal::{Journal, Phase},
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    HelperEnabled,
    HelperRunning,
    Linger,
    UserManager,
    UserFiles,
    UserEnabled,
    UserRunning,
}
pub const ACTIONS: [Action; 7] = [
    Action::HelperEnabled,
    Action::HelperRunning,
    Action::Linger,
    Action::UserManager,
    Action::UserFiles,
    Action::UserEnabled,
    Action::UserRunning,
];
impl Action {
    pub fn index(self) -> usize {
        ACTIONS.iter().position(|a| *a == self).unwrap()
    }
}
pub struct Observation {
    pub fingerprint: String,
    pub ready: bool,
    pub retry_safe: bool,
    pub subordinate_pending: bool,
}
pub trait Actions {
    fn inspect(&mut self, action: Action) -> Res<Observation>;
    /// Explicit recovery permits only a matching subordinate user-file journal;
    /// all ordinary unit mutations require a fresh exact-before observation.
    fn apply(&mut self, action: Action, recover: bool) -> Res<()>;
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
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Progress {
    completed: Vec<Receipt>,
    pending: Option<Pending>,
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Progress {
    pub(crate) fn complete(&self) -> bool {
        self.completed.len() == ACTIONS.len() && self.pending.is_none()
    }
    pub(crate) fn validate(&self) -> Res<()> {
        if self.completed.len() > ACTIONS.len()
            || self
                .completed
                .iter()
                .enumerate()
                .any(|(n, r)| r.action != ACTIONS[n] || !hash(&r.before) || !hash(&r.after))
            || self.pending.as_ref().is_some_and(|p| {
                ACTIONS.get(self.completed.len()) != Some(&p.action) || !hash(&p.before)
            })
        {
            return Err("setup_activation_record_invalid".into());
        }
        Ok(())
    }
}
pub fn activate(j: &mut Journal, adapter: &mut impl Actions, recover: bool) -> Res<()> {
    j.admit_activation(recover)?;
    let mut progress = j.activation_progress();
    progress.validate()?;
    for action in ACTIONS {
        let observed = adapter.inspect(action)?;
        if !hash(&observed.fingerprint) {
            return Err("setup_activation_observation_invalid".into());
        }
        if let Some(receipt) = progress.completed.get(action.index()) {
            if !observed.ready || observed.fingerprint != receipt.after {
                return Err("setup_activation_completed_state_changed".into());
            }
            continue;
        }
        let was_pending = progress.pending.is_some();
        if let Some(pending) = &progress.pending {
            if !recover {
                return Err("setup_activation_cleanup_unknown: explicit recovery required".into());
            }
            if !observed.ready
                && !(observed.retry_safe && observed.fingerprint == pending.before)
                && !(action == Action::UserFiles && observed.subordinate_pending)
            {
                return Err("setup_activation_unknown_state: preserve pending action".into());
            }
        } else {
            if !observed.ready && !observed.retry_safe {
                return Err("setup_activation_before_state_unsafe".into());
            }
            progress.pending = Some(Pending {
                action,
                before: observed.fingerprint.clone(),
            });
            j.save_activation(progress.clone())?;
        }
        if !observed.ready {
            adapter.apply(action, was_pending && recover)?;
        }
        let after = adapter.inspect(action)?;
        if !after.ready || !hash(&after.fingerprint) {
            return Err("setup_activation_effect_unconfirmed: pending action kept".into());
        }
        let pending = progress.pending.take().unwrap();
        progress.completed.push(Receipt {
            action,
            before: pending.before,
            after: after.fingerprint,
        });
        j.save_activation(progress.clone())?;
    }
    if !j.completed(Phase::Coordinator) {
        j.complete(Phase::Coordinator)?;
    }
    Ok(())
}
