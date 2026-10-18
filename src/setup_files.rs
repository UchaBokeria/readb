//! Journaled root files only. No systemctl, privilege-drop execution or VPN effects.
use crate::{
    network_install::{Installer, setup_journal_directory},
    policy::Res,
    setup_apply::ApplyPlan,
    setup_journal::{Journal, Phase},
};
use serde_json::{Value, json};
use std::path::Path;
fn result(plan: &ApplyPlan) -> Value {
    json!({"files_installed":true,"helper_active":false,"coordinator_active":false,"network_verified":false,"devices_accepted":false,"plan_sha256":plan.plan_sha256,"next":"Verify root unit and network persistence before activation; install coordinator as the selected user."})
}
fn prepare(image: &Path, plan: &ApplyPlan, binary: &[u8]) -> Res<(Journal, Installer)> {
    // Validate before creating even the private journal directory.
    plan.validate(binary)?;
    let path = setup_journal_directory(image)?;
    let journal = Journal::open(&path, &plan.plan_sha256)?;
    let installer = Installer::open(image)?;
    Ok((journal, installer))
}
fn write_files(i: &mut Installer, p: &ApplyPlan, binary: &[u8]) -> Res<()> {
    i.install_policy(&p.policy)?;
    i.install(p.root_install.clone(), binary)?;
    i.verify_setup_files(&p.policy, &p.root_install)
}
pub fn apply(image: &Path, plan: &ApplyPlan, binary: &[u8]) -> Res<Value> {
    let (mut j, mut i) = prepare(image, plan, binary)?;
    if j.running().is_some() {
        return Err(
            "setup_cleanup_unknown: use explicit files recovery with the original plan".into(),
        );
    }
    for phase in [Phase::Preflight, Phase::Dependencies] {
        if !j.completed(phase) {
            j.begin(phase)?;
            j.complete(phase)?;
        }
    }
    if !j.completed(Phase::Network) {
        j.begin(Phase::Network)?;
        write_files(&mut i, plan, binary)?;
        j.complete(Phase::Network)?;
    }
    // A completed journal is never proof files have not been edited later.
    i.verify_setup_files(&plan.policy, &plan.root_install)?;
    Ok(result(plan))
}
pub fn recover(image: &Path, plan: &ApplyPlan, binary: &[u8]) -> Res<Value> {
    let (mut j, mut i) = prepare(image, plan, binary)?;
    if j.running().is_none() && !j.completed(Phase::Preflight) {
        return Err("setup_files_no_recorded_operation".into());
    }
    i.recover_setup_pending(&plan.policy, &plan.root_install)?;
    for phase in [Phase::Preflight, Phase::Dependencies] {
        if j.running() == Some(phase) {
            j.reconcile_verified(phase)?;
        }
        if !j.completed(phase) {
            j.begin(phase)?;
            j.complete(phase)?;
        }
    }
    if j.completed(Phase::Network) {
        i.verify_setup_files(&plan.policy, &plan.root_install)?;
    } else if j.running() == Some(Phase::Network) {
        // Each subordinate operation independently admits current owned files,
        // preserving unknown edits. Replay happens only in this explicit mode,
        // with original immutable binding and recovered before/after intents.
        write_files(&mut i, plan, binary)?;
        j.reconcile_verified(Phase::Network)?;
    } else {
        j.begin(Phase::Network)?;
        write_files(&mut i, plan, binary)?;
        j.complete(Phase::Network)?;
    }
    Ok(result(plan))
}

/// Reconcile the phase record after exact files were published. This must not
/// take Installer's lock: the activated helper may already own it.
pub fn reconcile_installed(
    image: &Path,
    plan: &ApplyPlan,
    binary: &[u8],
    recover: bool,
) -> Res<()> {
    plan.validate(binary)?;
    crate::network_install::inspect_setup_files(image, &plan.policy, &plan.root_install)?;
    let path = setup_journal_directory(image)?;
    let mut j = Journal::open(&path, &plan.plan_sha256)?;
    for phase in [Phase::Preflight, Phase::Dependencies, Phase::Network] {
        if j.completed(phase) {
            continue;
        }
        if j.running() == Some(phase) {
            if !recover {
                return Err("setup_cleanup_unknown: explicit files recovery required".into());
            }
            j.reconcile_verified(phase)?;
        } else {
            j.begin(phase)?;
            j.complete(phase)?;
        }
    }
    Ok(())
}
