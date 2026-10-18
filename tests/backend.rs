use readb::{backend::*, policy::*};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt};
fn setup() -> Backend {
    let dir = std::env::temp_dir().join(format!("quest-rust-{}", random()));
    fs::create_dir(&dir).unwrap();
    // Write the shared fake before any test forks. Concurrent fixture writes can
    // leak a still-open write descriptor into another spawn and cause ETXTBSY.
    static FIXTURE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let adb=FIXTURE.get_or_init(||{
        let d=std::env::temp_dir().join(format!("quest-fake-adb-{}",random()));
        fs::create_dir(&d).unwrap();
    let adb = d.join("fake-adb");
    fs::write(&adb,"#!/bin/sh\ncase \"$*\" in\n*keygen*) printf 'fixture private key' > \"$6\";;\n*devices) printf 'List of devices attached\\n';;\n*connect*) echo connected to 192.0.2.5:40000;;\n*ro.serialno*) echo fixture-quest;;\n*) echo Quest3;;\nesac\n").unwrap();
    fs::set_permissions(&adb, fs::Permissions::from_mode(0o700)).unwrap();
        adb
    }).clone();
    Backend::new(Config {
        peer: "192.0.2.5".parse().unwrap(),
        adb_port: 5038,
        kind: readb::schema::Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb,
        token: "x".repeat(64),
        identity: Sha256::digest(b"fixture-quest")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        recipient: "1@s.whatsapp.net".into(),
    })
    .unwrap()
}
#[test]
fn startup_distrusts_saved_report() {
    let b = setup();
    assert!(!b.status()["connected"].as_bool().unwrap());
}
#[test]
fn failed_pinned_manual_connect_is_an_error() {
    let b = setup();
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "connect-failure".into(),
                job: "Failed-connect status".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert!(b.connect_device(&t, Some(40001)).is_err());
    assert_eq!(b.status()["connected"], false);
    b.release(&t).unwrap();
}
#[test]
fn managed_status_requires_a_live_owned_server() {
    let b = setup();
    assert!(
        b.report(Report {
            port: 40000,
            battery: 50
        })
        .unwrap()
    );
    assert_eq!(b.status()["connected"], true);
    b.enable_owned_server();
    assert_eq!(b.status()["connected"], false);
    assert_eq!(b.status()["adb_server_state"], "not_started");
}
#[test]
fn cancelled_pairing_never_starts_a_managed_server() {
    let b = setup();
    fs::set_permissions(&b.config.dir, fs::Permissions::from_mode(0o700)).unwrap();
    b.enable_owned_server();
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "cancel-before-spawn".into(),
                job: "Cancel pairing".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    let mut prepared = b.prepare(&t, vec!["pair".into(), "40000".into()]).unwrap();
    b.cancel(&t).unwrap();
    assert!(b.spawn(&t, &mut prepared).is_err());
    assert!(!b.config.dir.join("server.log").exists());
}
#[test]
fn stopped_server_gate_prevents_maintenance_restart() {
    let b = setup();
    fs::set_permissions(&b.config.dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        b.report(Report {
            port: 40000,
            battery: 50
        })
        .unwrap()
    );
    b.enable_owned_server();
    b.stop_owned_server().unwrap();
    assert!(b.keepalive().is_err());
    assert!(!b.config.dir.join("server.log").exists());
}
#[test]
fn genuine_report_then_claim_and_release() {
    let b = setup();
    assert!(
        b.report(Report {
            port: 40000,
            battery: 73
        })
        .unwrap()
    );
    let owner = Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "one".into(),
        job: "probe".into(),
        allow_sleep: false,
    };
    let t = b.claim(owner.clone(), 90).unwrap();
    assert!(b.claim(owner, 90).unwrap_err().contains("probe"));
    assert!(
        b.prepare(
            &t,
            vec!["shell".into(), "getprop".into(), "ro.product.model".into()]
        )
        .is_ok()
    );
    b.complete(false);
    b.release(&t).unwrap();
}
#[test]
fn stale_and_control_commands_fail_before_execution() {
    let b = setup();
    let o = Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "one".into(),
        job: "probe".into(),
        allow_sleep: false,
    };
    let t = b.claim(o, 90).unwrap();
    assert!(b.prepare(&t, vec!["kill-server".into()]).is_err());
    assert!(
        b.prepare(&t, vec!["shell".into(), "getprop".into()])
            .is_err()
    );
}
#[test]
fn unresolved_operation_survives_restart() {
    let b = setup();
    fs::write(b.config.dir.join("active-operation.json"), b"{}").unwrap();
    let next = Backend::new(b.config.clone()).unwrap();
    assert!(next.status()["cleanup_unknown"].is_string());
}
#[test]
fn shell_injection_is_never_classified_pure() {
    assert!(!is_pure(&[
        "shell".into(),
        "getprop".into(),
        "x; sleep 999 &".into()
    ]));
}
#[test]
fn mutating_logcat_is_not_pure() {
    assert!(!is_pure(&["logcat".into(), "-c".into()]));
    assert!(!is_pure(&[
        "logcat".into(),
        "-f".into(),
        "/sdcard/x".into()
    ]));
}
#[test]
fn detached_shell_requires_explicit_contract() {
    let b = setup();
    assert!(
        b.report(Report {
            port: 40000,
            battery: 73
        })
        .unwrap()
    );
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "one".into(),
                job: "probe".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert!(
        b.prepare(
            &t,
            vec![
                "shell".into(),
                "sh".into(),
                "-c".into(),
                "sleep 999 &".into()
            ]
        )
        .is_err()
    );
}
#[test]
fn cancelled_reservation_cannot_spawn() {
    let b = setup();
    b.report(Report {
        port: 40000,
        battery: 73,
    })
    .unwrap();
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "one".into(),
                job: "probe".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    let mut p = b
        .prepare(
            &t,
            vec!["shell".into(), "getprop".into(), "ro.product.model".into()],
        )
        .unwrap();
    b.cancel(&t).unwrap();
    assert!(b.spawn(&t, &mut p).is_err());
    b.complete(false);
    assert!(b.status()["cleanup_unknown"].is_null());
}
#[test]
fn shutdown_fences_queued_claim_and_reserved_dispatch() {
    let b = setup();
    b.report(Report {
        port: 40000,
        battery: 73,
    })
    .unwrap();
    let o = Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "one".into(),
        job: "shutdown".into(),
        allow_sleep: false,
    };
    let t = b.claim(o.clone(), 90).unwrap();
    let mut p = b
        .prepare(&t, vec!["shell".into(), "getprop".into()])
        .unwrap();
    b.begin_shutdown().unwrap();
    assert!(b.spawn(&t, &mut p).is_err());
    assert!(b.claim(o, 90).unwrap_err().contains("shutdown"));
    assert!(b.heartbeat(&t).is_err());
    assert!(
        b.report(Report {
            port: 40001,
            battery: 73
        })
        .is_err()
    );
    assert!(b.keepalive().is_err());
    b.complete(false);
    assert!(!b.status()["operation_running"].as_bool().unwrap());
}
#[test]
fn nested_shell_and_clustered_logcat_are_not_trusted() {
    assert!(!is_pure(&["logcat".into(), "-dc".into()]));
    let b = setup();
    b.report(Report {
        port: 40000,
        battery: 73,
    })
    .unwrap();
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "one".into(),
                job: "nested".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert!(
        b.prepare(
            &t,
            [
                "shell",
                "run-as",
                "dev.test",
                "/system/bin/sh",
                "/data/local/tmp/job.sh"
            ]
            .map(str::to_string)
            .to_vec()
        )
        .is_err()
    );
}
#[test]
fn receipt_expiry_between_prepare_and_spawn_blocks_dispatch() {
    let b = setup();
    assert!(
        b.report(Report {
            port: 40000,
            battery: 73,
        })
        .unwrap(),
        "report rejected: {}",
        b.status()
    );
    let t = b
        .claim(
            Owner {
                agent: "codex".into(),
                origin: "pc".into(),
                session: "one".into(),
                job: "expire".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    let mut p = b
        .prepare(&t, vec!["shell".into(), "getprop".into()])
        .unwrap();
    b.state.lock().unwrap().receipt.received_at = now() - 181.;
    assert!(b.spawn(&t, &mut p).is_err());
    b.complete(false);
}

#[test]
fn pairing_is_controller_only_offline_and_fixed_peer_without_code_in_argv() {
    let b = setup();
    let owner = Owner {
        agent: "test".into(),
        origin: "host".into(),
        session: "pair".into(),
        job: "pair device".into(),
        allow_sleep: false,
    };
    let view = b.watch(owner.clone(), 90).unwrap();
    assert!(
        b.prepare(&view, vec!["pair".into(), "40001".into()])
            .is_err()
    );
    b.release(&view).unwrap();
    let t = b.claim(owner, 90).unwrap();
    assert!(
        b.prepare(&t, vec!["pair".into(), "192.0.2.9:40001".into()])
            .is_err()
    );
    assert!(
        b.prepare(&t, vec!["pair".into(), "40001".into(), "192.0.2.9".into()])
            .err()
            .unwrap()
            .contains("pair_ip_must_match_configured_peer")
    );
    assert!(!b.config.dir.join("adbkey").exists());
    let p = b
        .prepare(&t, vec!["pair".into(), "40001".into(), "192.0.2.5".into()])
        .unwrap();
    let args = p
        .command
        .get_args()
        .map(|a| a.to_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        vec!["-H", "127.0.0.1", "-P", "5038", "pair", "192.0.2.5:40001"]
    );
    let env = p
        .command
        .get_envs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        env[std::ffi::OsStr::new("ANDROID_ADB_SERVER_ADDRESS")],
        None
    );
    assert_eq!(
        env[std::ffi::OsStr::new("HOME")],
        Some(b.config.dir.as_os_str())
    );
    assert!(b.running(&t, p.generation));
    assert!(
        b.report(Report {
            port: 40000,
            battery: 70
        })
        .unwrap_err()
        .contains("pairing_in_progress")
    );
    b.complete_for(&t, false);
    assert!(b.status()["cleanup_unknown"].is_null());
    b.release(&t).unwrap();
}

#[test]
fn first_identity_needs_explicit_matching_fresh_review() {
    let base = setup();
    let mut c = base.config.clone();
    c.identity.clear();
    let b = Backend::new(c).unwrap();
    let t = b
        .claim(
            Owner {
                agent: "test".into(),
                origin: "host".into(),
                session: "enroll".into(),
                job: "enroll".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert!(
        b.prepare(
            &t,
            vec!["shell".into(), "getprop".into(), "ro.product.model".into()]
        )
        .is_err()
    );
    let probe = b.probe_identity(&t, 40000).unwrap();
    let pin = probe["fingerprint"].as_str().unwrap();
    assert!(!probe.to_string().contains("fixture-quest"));
    assert!(b.trust_identity(&t, &"b".repeat(64), || Ok(())).is_err());
    assert!(
        b.trust_identity(&t, pin, || Err("persistence_failed".into()))
            .is_err()
    );
    b.trust_identity(&t, pin, || Ok(())).unwrap();
    assert!(b.trust_identity(&t, pin, || Ok(())).is_err());
    assert!(
        b.report(Report {
            port: 40000,
            battery: 70
        })
        .unwrap()
    );
    b.disconnect_device(&t).unwrap();
    assert_eq!(b.status()["paused"], true);
    assert_eq!(b.status()["connected"], false);
    b.state.lock().unwrap().last_attempt = None;
    assert!(
        !b.report(Report {
            port: 40000,
            battery: 70
        })
        .unwrap()
    );
}

#[test]
fn identity_review_cannot_transfer_to_another_controller_job() {
    let base = setup();
    let mut c = base.config.clone();
    c.identity.clear();
    let b = Backend::new(c).unwrap();
    let owner = |job: &str| Owner {
        agent: "test".into(),
        origin: "host".into(),
        session: "enroll".into(),
        job: job.into(),
        allow_sleep: false,
    };
    let a = b.claim(owner("review"), 90).unwrap();
    let v = b.probe_identity(&a, 40000).unwrap();
    b.release(&a).unwrap();
    let z = b.claim(owner("other job"), 90).unwrap();
    assert!(
        b.trust_identity(&z, v["fingerprint"].as_str().unwrap(), || Ok(()))
            .is_err()
    );
}

fn v2(epoch: &str, sequence: u64, port: Option<u16>) -> readb_protocol::Report {
    readb_protocol::Report::parse(&serde_json::to_vec(&serde_json::json!({"schema":2,"epoch":epoch,"sequence":sequence,"port":port,"battery":60,"observed":{"credential_storage_unlocked":true,"screen_lock":"unknown","vpn_active":true,"notifications":"granted","discovery":"granted","secure_settings":"granted"}})).unwrap()).unwrap()
}
#[test]
fn no_port_is_authenticated_telemetry_not_a_connection_and_replay_does_not_refresh() {
    let b = setup();
    assert!(!b.report_v2(v2("reporter-one", 1, None)).unwrap());
    assert_eq!(b.status()["connected"], false);
    assert_eq!(
        b.status()["companion"]["observed"]["screen_lock"],
        "unknown"
    );
    let received = b.state.lock().unwrap().receipt.received_at;
    b.state.lock().unwrap().last_attempt = None;
    assert!(
        b.report_v2(v2("reporter-one", 1, Some(40000)))
            .unwrap_err()
            .contains("stale_report")
    );
    assert_eq!(b.state.lock().unwrap().receipt.received_at, received);
    let reboot = Backend::new(b.config.clone()).unwrap();
    assert!(reboot.report_v2(v2("reporter-one", 1, None)).is_err());
    assert!(!reboot.report_v2(v2("reporter-one", 2, None)).unwrap());
}
#[test]
fn reporter_epoch_change_fences_dispatched_mutation_even_when_port_is_the_same() {
    let b = setup();
    assert!(b.report_v2(v2("reporter-one", 1, Some(40000))).unwrap());
    let owner = Owner {
        agent: "test".into(),
        origin: "host".into(),
        session: "v2".into(),
        job: "input".into(),
        allow_sleep: false,
    };
    let t = b.claim(owner.clone(), 90).unwrap();
    let view = b.watch(owner, 90).unwrap();
    let mut p = b
        .prepare(
            &t,
            vec![
                "shell".into(),
                "input".into(),
                "keyevent".into(),
                "3".into(),
            ],
        )
        .unwrap();
    let mut child = b.spawn(&t, &mut p).unwrap();
    child.wait().unwrap();
    let generation = p.generation;
    b.state.lock().unwrap().last_attempt = None;
    let _ = b.report_v2(v2("reporter-two", 1, Some(40000))).unwrap();
    assert!(!b.running(&t, generation));
    assert!(b.status()["cleanup_unknown"].is_string());
    assert!(
        b.prepare(
            &view,
            vec!["shell".into(), "getprop".into(), "ro.product.model".into()]
        )
        .is_err()
    );
    b.complete_for(&t, true);
}

#[test]
fn accepted_v2_rejects_wire_downgrade_across_restart_but_allows_pinned_manual_reconnect() {
    let b = setup();
    assert!(b.report_v2(v2("reporter-one", 1, Some(40000))).unwrap());
    b.state.lock().unwrap().last_attempt = None;
    let legacy = || Report {
        port: 41000,
        battery: 1,
    };
    assert_eq!(b.report(legacy()).unwrap_err(), "report_protocol_downgrade");
    assert_eq!(b.battery_sample().battery, 60);
    assert_eq!(b.state.lock().unwrap().receipt.port, 40000);
    let ticket = b
        .claim(
            Owner {
                agent: "test".into(),
                origin: "host".into(),
                session: "v2".into(),
                job: "manual reconnect".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert!(
        b.connect_device(&ticket, Some(40000)).unwrap()["connected"]
            .as_bool()
            .unwrap()
    );
    b.release(&ticket).unwrap();
    let restarted = Backend::new(b.config.clone()).unwrap();
    assert_eq!(
        restarted.report(legacy()).unwrap_err(),
        "report_protocol_downgrade"
    );
}

#[test]
fn rejected_manual_reconnect_preserves_pause_policy() {
    let b = setup();
    assert!(b.report_v2(v2("reporter-one", 1, Some(40000))).unwrap());
    let ticket = b
        .claim(
            Owner {
                agent: "test".into(),
                origin: "host".into(),
                session: "pause".into(),
                job: "connect".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    b.disconnect_device(&ticket).unwrap();
    assert_eq!(
        b.connect_device(&ticket, Some(40000)).unwrap_err(),
        "rate_limited"
    );
    assert_eq!(b.status()["paused"], true);
    b.state.lock().unwrap().last_attempt = None;
    assert_eq!(
        b.connect_device(&ticket, Some(40000)).unwrap()["connected"],
        true
    );
    assert_eq!(b.status()["paused"], false);
    b.release(&ticket).unwrap();
}

#[test]
fn manual_reconnect_cannot_promote_cached_v2_battery_after_server_restart() {
    let b = setup();
    assert!(b.report_v2(v2("reporter-one", 1, Some(40000))).unwrap());
    let b = Backend::new(b.config.clone()).unwrap();
    let ticket = b
        .claim(
            Owner {
                agent: "test".into(),
                origin: "host".into(),
                session: "restart".into(),
                job: "reconnect".into(),
                allow_sleep: false,
            },
            90,
        )
        .unwrap();
    assert_eq!(
        b.connect_device(&ticket, Some(40000)).unwrap()["connected"],
        true
    );
    assert!(!b.battery_sample().authenticated);
    b.release(&ticket).unwrap();
}

#[test]
fn package_path_query_is_observational_but_other_package_actions_are_not() {
    let args = |s: &[&str]| s.iter().map(|v| v.to_string()).collect::<Vec<_>>();
    assert!(is_pure(&args(&[
        "shell",
        "pm",
        "path",
        "dev.readb.companion"
    ])));
    for argv in [
        vec!["shell", "pm", "clear", "dev.readb.companion"],
        vec!["shell", "pm", "path", "--user", "0", "dev.readb.companion"],
        vec!["shell", "pm", "path", "-bad"],
        vec!["shell", "pm", "path", "dev.app;id"],
    ] {
        assert!(!is_pure(&args(&argv)));
    }
}
