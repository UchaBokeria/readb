use readb::{
    policy::Res,
    setup_activation::{Action, Actions, Observation, activate},
    setup_journal::{Journal, Phase},
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Fake {
    state: [u8; 7],
    calls: usize,
    fail: Option<Action>,
}
impl Actions for Fake {
    fn inspect(&mut self, a: Action) -> Res<Observation> {
        let n = a.index();
        Ok(Observation {
            fingerprint: format!("{:064x}", n * 10 + self.state[n] as usize),
            ready: self.state[n] == 1,
            retry_safe: self.state[n] == 0,
            subordinate_pending: false,
        })
    }
    fn apply(&mut self, a: Action, _recover: bool) -> Res<()> {
        self.calls += 1;
        self.state[a.index()] = 1;
        if self.fail == Some(a) {
            Err("lost reply".into())
        } else {
            Ok(())
        }
    }
}
fn dir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-activation-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn journal(p: &std::path::Path) -> Journal {
    let mut j = Journal::open(p, &"a".repeat(64)).unwrap();
    for phase in [Phase::Preflight, Phase::Dependencies, Phase::Network] {
        if !j.completed(phase) {
            j.begin(phase).unwrap();
            j.complete(phase).unwrap();
        }
    }
    j
}
#[test]
fn interrupted_activation_needs_explicit_verified_recovery_and_never_replays_applied_action() {
    let p = dir();
    let mut f = Fake {
        state: [0; 7],
        calls: 0,
        fail: Some(Action::HelperRunning),
    };
    {
        let mut j = journal(&p);
        assert!(activate(&mut j, &mut f, false).is_err());
        assert_eq!(f.calls, 2);
    }
    let mut j = journal(&p);
    assert!(activate(&mut j, &mut f, false).is_err());
    assert_eq!(f.calls, 2);
    f.fail = None;
    activate(&mut j, &mut f, true).unwrap();
    assert_eq!(f.calls, 7);
    assert!(j.completed(Phase::Coordinator));
    activate(&mut j, &mut f, false).unwrap();
    assert_eq!(f.calls, 7);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn changed_pending_state_and_completed_drift_are_preserved() {
    let p = dir();
    let mut f = Fake {
        state: [0; 7],
        calls: 0,
        fail: Some(Action::HelperRunning),
    };
    {
        let mut j = journal(&p);
        assert!(activate(&mut j, &mut f, false).is_err());
    }
    f.state[1] = 2;
    let mut j = journal(&p);
    assert!(activate(&mut j, &mut f, true).is_err());
    assert_eq!(f.calls, 2);
    f.state[1] = 1;
    f.fail = None;
    activate(&mut j, &mut f, true).unwrap();
    f.state[0] = 2;
    assert!(activate(&mut j, &mut f, false).is_err());
    assert_eq!(f.calls, 7);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn unknown_or_unsafe_observation_cannot_start_an_action() {
    let p = dir();
    let mut f = Fake {
        state: [2; 7],
        calls: 0,
        fail: None,
    };
    let mut j = journal(&p);
    assert!(activate(&mut j, &mut f, false).is_err());
    assert_eq!(f.calls, 0);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn inconsistent_completed_phase_cannot_replay_a_pending_action() {
    let p = dir();
    {
        let mut j = journal(&p);
        j.begin(Phase::Coordinator).unwrap();
        j.complete(Phase::Coordinator).unwrap();
    }
    let file = p.join("journal.json");
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    state["activation"] = serde_json::json!({"completed":[],"pending":{"action":"helper_enabled","before":"0".repeat(64)}});
    fs::write(&file, serde_json::to_vec(&state).unwrap()).unwrap();
    let mut j = Journal::open(&p, &"a".repeat(64)).unwrap();
    let mut f = Fake {
        state: [0; 7],
        calls: 0,
        fail: None,
    };
    assert!(activate(&mut j, &mut f, true).is_err());
    assert_eq!(f.calls, 0);
    drop(j);
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn concrete_unit_admission_rejects_other_fragments_overrides_and_queued_jobs() {
    use readb::setup_systemd::admit_unit;
    let facts = "LoadState=loaded\nFragmentPath=/etc/systemd/system/readb-network.service\nDropInPaths=\nNeedDaemonReload=no\nJob=0\nActiveState=inactive\nSubState=dead\nMainPID=0\nUnitFileState=disabled\nControlGroup=\n";
    admit_unit(facts, "/etc/systemd/system/readb-network.service").unwrap();
    for bad in [
        facts.replace("DropInPaths=", "DropInPaths=/etc/override"),
        facts.replace("Job=0", "Job=17"),
        facts.replace("Reload=no", "Reload=yes"),
        facts.replace("/etc/systemd", "/home/user"),
    ] {
        assert!(admit_unit(&bad, "/etc/systemd/system/readb-network.service").is_err());
    }
}
#[test]
fn cached_missing_unit_can_reload_but_overrides_and_jobs_cannot_enable() {
    use readb::setup_systemd::enable_before;
    let missing = "LoadState=not-found\nUnitFileState=\nDropInPaths=\nJob=0\nMainPID=0\nActiveState=inactive\n";
    assert!(enable_before(missing).unwrap());
    assert!(!enable_before(&missing.replace("DropInPaths=", "DropInPaths=/bad")).unwrap());
    assert!(!enable_before(&missing.replace("Job=0", "Job=1")).unwrap());
    assert!(!enable_before(&missing.replace("not-found", "error")).unwrap());
}

#[test]
fn user_manager_cannot_adopt_overrides_or_wrong_identity() {
    let text = "LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/user@.service\nDropInPaths=\nNeedDaemonReload=no\nJob=0\nUser=1000\n";
    assert!(readb::setup_systemd::admit_user_manager(text, 1000).is_ok());
    for changed in [
        text.replace("User=1000", "User=0"),
        text.replace(
            "DropInPaths=",
            "DropInPaths=/etc/systemd/system/user@1000.service.d/override.conf",
        ),
        text.replace(
            "/usr/lib/systemd/system/user@.service",
            "/etc/systemd/system/user@1000.service",
        ),
    ] {
        assert!(readb::setup_systemd::admit_user_manager(&changed, 1000).is_err());
    }
}

#[test]
fn systemd_empty_job_printing_and_vendor_user_manager_defaults_are_supported() {
    let text = "LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/user@.service\nDropInPaths=/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf /usr/lib/systemd/system/user@.service.d/timeout.conf\nNeedDaemonReload=no\nJob=\nUser=1000\n";
    assert!(readb::setup_systemd::admit_user_manager(text, 1000).is_ok());
    assert!(readb::setup_systemd::admit_unit(&text.replace("DropInPaths=/usr/lib/systemd/system/user@.service.d/10-login-barrier.conf /usr/lib/systemd/system/user@.service.d/timeout.conf", "DropInPaths="), "/usr/lib/systemd/system/user@.service").is_ok());
    assert!(
        readb::setup_systemd::admit_user_manager(&text.replace("Job=", "Job=12"), 1000).is_err()
    );
}

#[test]
fn pending_user_files_recovery_requires_quiescence_even_if_reload_is_pending() {
    let text = "LoadState=loaded\nFragmentPath=/home/user/.config/systemd/user/readb.service\nDropInPaths=\nNeedDaemonReload=yes\nJob=\nMainPID=0\nActiveState=inactive\nControlGroup=\n";
    let fragment = "/home/user/.config/systemd/user/readb.service";
    assert!(readb::setup_systemd::admit_user_file_recovery(text, fragment).is_ok());
    for changed in [
        text.replace("MainPID=0", "MainPID=123"),
        text.replace("ActiveState=inactive", "ActiveState=active"),
        text.replace("Job=", "Job=12"),
        text.replace("DropInPaths=", "DropInPaths=/etc/override.conf"),
    ] {
        assert!(readb::setup_systemd::admit_user_file_recovery(&changed, fragment).is_err());
    }
}
