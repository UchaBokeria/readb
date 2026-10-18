use readb::{
    backend::{Backend, Config},
    policy::{Owner, random},
    schema::Kind,
};
use std::{fs, os::unix::fs::PermissionsExt};
fn backend() -> Backend {
    let dir = std::env::temp_dir().join(format!("readb-network-job-{}", random()));
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    Backend::new(Config {
        peer: "10.88.0.100".parse().unwrap(),
        adb_port: 5050,
        kind: Kind::Quest,
        keepalive: Default::default(),
        dir,
        adb: "/not-executed".into(),
        token: "x".repeat(64),
        identity: String::new(),
        recipient: String::new(),
    })
    .unwrap()
}
fn owner(job: &str) -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "fixture".into(),
        session: "network-scope".into(),
        job: job.into(),
        allow_sleep: true,
    }
}
#[test]
fn network_job_requires_controller_but_does_not_require_connected_adb() {
    let b = backend();
    let c = b.claim(owner("enroll"), 90).unwrap();
    let v = b.watch(owner("view"), 90).unwrap();
    assert!(b.begin_network(&v, "network-enroll").is_err());
    assert!(b.begin_network("wrong", "network-enroll").is_err());
    assert!(b.begin_network(&c, "arbitrary-script").is_err());
    assert!(!b.config.dir.join("active-operation.json").exists());
    let op = b.begin_network(&c, "network-enroll").unwrap();
    assert_eq!(op.len(), 64);
    assert_eq!(b.status()["connected"], false);
    b.authorize_network(&c, &op).unwrap();
    assert!(b.authorize_network(&v, &op).is_err());
    assert!(b.authorize_network(&c, "wrong-operation").is_err());
    assert!(b.release(&c).is_err());
    assert!(b.begin_network(&c, "network-rm").is_err());
    let restored = Backend::new(b.config.clone()).unwrap();
    assert!(restored.status()["cleanup_unknown"].is_string());
    b.complete_result(&c, false, "network-applied");
    b.release(&c).unwrap();
    assert!(!b.config.dir.join("active-operation.json").exists());
    fs::remove_dir_all(&b.config.dir).unwrap();
}
#[test]
fn active_viewer_blocks_network_and_cancellation_fences_only_this_device() {
    let b = backend();
    let c = b.claim(owner("network"), 90).unwrap();
    let v = b.watch(owner("capture"), 90).unwrap();
    b.state.lock().unwrap().viewers.get_mut(&v).unwrap().active = true;
    assert!(
        b.begin_network(&c, "network-rm")
            .unwrap_err()
            .contains("viewer")
    );
    b.state.lock().unwrap().viewers.get_mut(&v).unwrap().active = false;
    let op = b.begin_network(&c, "network-rm").unwrap();
    assert!(!b.state.lock().unwrap().gate.active_pure);
    b.cancel(&c).unwrap();
    assert!(b.authorize_network(&c, &op).is_err());
    b.complete_result(&c, true, "network-unconfirmed");
    assert!(b.status()["cleanup_unknown"].is_string());
    let other = backend();
    let ticket = other.claim(owner("independent"), 90).unwrap();
    other.begin_network(&ticket, "network-enroll").unwrap();
    other.complete_result(&ticket, false, "network-refused");
    other.release(&ticket).unwrap();
    fs::remove_dir_all(&b.config.dir).unwrap();
    fs::remove_dir_all(&other.config.dir).unwrap();
}
#[test]
fn uncertain_network_intent_persistence_does_not_leave_a_reusable_lease() {
    let b = backend();
    let c = b.claim(owner("persist"), 90).unwrap();
    fs::create_dir(b.config.dir.join("active-operation.json")).unwrap();
    assert!(b.begin_network(&c, "network-enroll").is_err());
    assert!(b.status()["cleanup_unknown"].is_string());
    assert!(b.claim(owner("second"), 90).is_err());
    assert!(Backend::new(b.config.clone()).unwrap().status()["cleanup_unknown"].is_string());
    fs::remove_dir_all(&b.config.dir).unwrap();
}

#[test]
fn network_job_defers_reports_without_consuming_the_authenticated_cursor() {
    let b = backend();
    let c = b.claim(owner("network"), 90).unwrap();
    b.begin_network(&c, "network-enroll").unwrap();
    let report=readb_protocol::Report::parse(&serde_json::to_vec(&serde_json::json!({"schema":2,"epoch":"network-test","sequence":1,"port":null,"battery":60,"observed":{"credential_storage_unlocked":true,"screen_lock":"unknown","vpn_active":true,"notifications":"granted","discovery":"granted","secure_settings":"granted"}})).unwrap()).unwrap();
    assert!(
        b.report_v2(report.clone())
            .unwrap_err()
            .contains("network_change_in_progress")
    );
    assert!(!b.state.lock().unwrap().report_cursor.is_initialized());
    b.complete_result(&c, false, "network-refused");
    assert!(!b.report_v2(report).unwrap());
    assert!(b.state.lock().unwrap().report_cursor.is_initialized());
    fs::remove_dir_all(&b.config.dir).unwrap();
}
fn enroll(id: &str) -> readb::network::Request {
    readb::network::Request::Enroll {
        id: id.into(),
        key: format!("{}AAA=", "E".repeat(40)),
        address: "10.88.0.100".parse().unwrap(),
    }
}
#[test]
fn authority_nonce_is_one_use_and_bound_to_the_exact_request() {
    use readb::network_controller::{NetworkController, Outcome, request_digest};
    let (registry, b) = registered_backend();
    let c = b.claim(owner("enroll"), 90).unwrap();
    let authority = NetworkController::new();
    let request = enroll("quest");
    let digest = request_digest(&request).unwrap();
    let scope = authority.begin(&registry, &c, "quest", request).unwrap();
    let nonce = scope.nonce().to_owned();
    assert!(
        !fs::read_to_string(b.config.dir.join("active-operation.json"))
            .unwrap()
            .contains(&nonce)
    );
    assert!(authority.authorize(&nonce, &"0".repeat(64)).is_err());
    authority.authorize(&nonce, &digest).unwrap();
    assert!(authority.authorize(&nonce, &digest).is_err());
    scope.finish(Outcome::Applied).unwrap();
    assert!(authority.authorize(&nonce, &digest).is_err());
    assert!(b.status()["cleanup_unknown"].is_null());
    b.release(&c).unwrap();
    let events = fs::read_to_string(b.config.dir.join("events.jsonl")).unwrap();
    assert!(!events.contains(&nonce) && !events.contains(&c));
    fs::remove_dir_all(&registry.root).unwrap();
}
#[test]
fn authority_rejects_scope_mismatch_before_any_operation_record() {
    use readb::{network::Request, network_controller::NetworkController};
    let (registry, b) = registered_backend();
    let c = b.claim(owner("enroll"), 90).unwrap();
    let authority = NetworkController::new();
    for request in [
        enroll("other"),
        Request::Restore { id: "quest".into() },
        Request::Enroll {
            id: "quest".into(),
            key: "invalid".into(),
            address: b.config.peer,
        },
        Request::Enroll {
            id: "quest".into(),
            key: format!("{}AAA=", "E".repeat(40)),
            address: "10.88.0.101".parse().unwrap(),
        },
    ] {
        assert!(authority.begin(&registry, &c, "quest", request).is_err());
        assert!(!b.config.dir.join("active-operation.json").exists());
    }
    fs::remove_dir_all(&registry.root).unwrap();
}
#[test]
fn dropped_or_cancelled_authority_scope_keeps_a_durable_device_fence() {
    use readb::network_controller::{NetworkController, Outcome, request_digest};
    for cancel in [false, true] {
        let (registry, b) = registered_backend();
        let c = b.claim(owner("network"), 90).unwrap();
        let authority = NetworkController::new();
        let request = enroll("quest");
        let digest = request_digest(&request).unwrap();
        let scope = authority.begin(&registry, &c, "quest", request).unwrap();
        let nonce = scope.nonce().to_owned();
        if cancel {
            b.cancel(&c).unwrap();
            assert!(authority.authorize(&nonce, &digest).is_err());
            assert!(scope.finish(Outcome::Applied).is_err());
        } else {
            drop(scope);
        }
        assert!(authority.authorize(&nonce, &digest).is_err());
        assert!(b.status()["cleanup_unknown"].is_string());
        assert!(Backend::new(b.config.clone()).unwrap().status()["cleanup_unknown"].is_string());
        fs::remove_dir_all(&registry.root).unwrap();
    }
}

#[test]
fn stale_network_completion_cannot_cancel_a_new_operation() {
    let b = backend();
    let c = b.claim(owner("network"), 90).unwrap();
    let old = b.begin_network(&c, "network-enroll").unwrap();
    b.finish_network(&c, &old, false, "network-refused")
        .unwrap();
    let current = b.begin_network(&c, "network-rm").unwrap();
    let before = fs::read(b.config.dir.join("active-operation.json")).unwrap();
    assert!(b.finish_network(&c, &old, true, "late-result").is_err());
    b.authorize_network(&c, &current).unwrap();
    assert_eq!(
        fs::read(b.config.dir.join("active-operation.json")).unwrap(),
        before
    );
    b.finish_network(&c, &current, false, "network-refused")
        .unwrap();
    b.release(&c).unwrap();
    fs::remove_dir_all(&b.config.dir).unwrap();
}
#[test]
fn network_history_failure_is_fenced_before_any_authority_is_issued() {
    use readb::network_controller::NetworkController;
    let (registry, b) = registered_backend();
    let c = b.claim(owner("history"), 90).unwrap();
    fs::create_dir(b.config.dir.join("events.jsonl")).unwrap();
    assert!(
        NetworkController::new()
            .begin(&registry, &c, "quest", enroll("quest"))
            .is_err()
    );
    assert!(b.status()["cleanup_unknown"].is_string());
    assert!(b.state.lock().unwrap().operations.is_empty());
    assert!(Backend::new(b.config.clone()).unwrap().status()["cleanup_unknown"].is_string());
    fs::remove_dir_all(&registry.root).unwrap();
}
#[test]
fn applied_without_proof_and_expired_proof_are_not_success_but_definite_refusal_can_finish() {
    use readb::network_controller::{NetworkController, Outcome, request_digest};
    for case in ["no-proof", "expired", "refused"] {
        let (registry, b) = registered_backend();
        let c = b.claim(owner("result"), 90).unwrap();
        let authority = NetworkController::new();
        let request = enroll("quest");
        let digest = request_digest(&request).unwrap();
        let scope = authority.begin(&registry, &c, "quest", request).unwrap();
        if case == "expired" {
            b.state.lock().unwrap().gate.lease.as_mut().unwrap().expires = -1.;
            assert!(authority.authorize(scope.nonce(), &digest).is_err());
        }
        if case == "refused" {
            scope.finish(Outcome::Refused).unwrap();
            assert!(b.status()["cleanup_unknown"].is_null());
            b.release(&c).unwrap();
        } else {
            assert!(scope.finish(Outcome::Applied).is_err());
            assert!(b.status()["cleanup_unknown"].is_string());
        }
        fs::remove_dir_all(&registry.root).unwrap();
    }
}

fn fresh_fixture_state(b: &Backend) {
    let mut s = b.state.lock().unwrap();
    s.receipt = readb::policy::Receipt {
        port: 40000,
        received_at: readb::backend::now(),
        connected: true,
        identity_verified: true,
        ..Default::default()
    };
    s.target = Some(40000);
}
#[test]
fn idle_viewer_cannot_start_after_a_network_operation_begins() {
    let b = backend();
    let c = b.claim(owner("network"), 90).unwrap();
    let v = b.watch(owner("idle-viewer"), 90).unwrap();
    fresh_fixture_state(&b);
    b.begin_network(&c, "network-rm").unwrap();
    let result = b.prepare(
        &v,
        ["exec-out", "screencap", "-p"].map(str::to_string).to_vec(),
    );
    assert!(result.is_err_and(|e| e.contains("network_change_in_progress")));
    assert!(!b.state.lock().unwrap().viewers[&v].active);
    b.complete_result(&c, false, "network-refused");
    fs::remove_dir_all(&b.config.dir).unwrap();
}
#[test]
fn keepalive_is_excluded_during_network_work_even_when_owner_allows_wake() {
    let b = backend();
    let mut o = owner("network-awake");
    o.allow_sleep = false;
    let c = b.claim(o, 90).unwrap();
    fresh_fixture_state(&b);
    b.begin_network(&c, "network-rm").unwrap();
    assert!(
        b.keepalive()
            .unwrap_err()
            .contains("keepalive_not_permitted")
    );
    b.complete_result(&c, false, "network-refused");
    fs::remove_dir_all(&b.config.dir).unwrap();
}
#[test]
fn an_authoritative_registry_rejects_a_different_devices_controller_ticket() {
    use readb::{
        network::Request, network_controller::NetworkController, registry::Registry,
        schema::ServerConfig,
    };
    let root = std::env::temp_dir().join(format!("readb-registry-network-{}", random()));
    let config:ServerConfig=ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":"/not-executed","devices":[{"id":"quest","name":"Quest","kind":"quest","peer":"10.88.0.100","adb_port":5050,"token":"x".repeat(64)},{"id":"phone","name":"Phone","kind":"phone","peer":"10.88.0.101","adb_port":5051,"token":"y".repeat(64)}]})).unwrap()).unwrap();
    let registry = Registry::new(config, root.clone()).unwrap();
    let a = registry.device("quest").unwrap();
    let b = registry.device("phone").unwrap();
    let ticket = a.claim(owner("quest-network"), 90).unwrap();
    let authority = NetworkController::new();
    assert!(
        authority
            .begin(
                &registry,
                &ticket,
                "phone",
                Request::Remove { id: "phone".into() }
            )
            .is_err()
    );
    assert!(!a.config.dir.join("active-operation.json").exists());
    assert!(!b.config.dir.join("active-operation.json").exists());
    fs::remove_dir_all(root).unwrap();
}

fn registered_backend() -> (readb::registry::Registry, std::sync::Arc<Backend>) {
    let root = std::env::temp_dir().join(format!("readb-bound-network-{}", random()));
    let config=readb::schema::ServerConfig::parse(&serde_json::to_vec(&serde_json::json!({"schema":1,"adb":"/not-executed","devices":[{"id":"quest","name":"Quest","kind":"quest","peer":"10.88.0.100","adb_port":5050,"token":"x".repeat(64)},{"id":"phone","name":"Phone","kind":"phone","peer":"10.88.0.101","adb_port":5051,"token":"y".repeat(64)}]})).unwrap()).unwrap();
    let registry = readb::registry::Registry::new(config, root).unwrap();
    let backend = registry.device("quest").unwrap();
    (registry, backend)
}

#[test]
fn network_rpc_preflight_checks_ticket_and_helper_before_durable_intent() {
    use readb::network_runtime::Call;
    let (r, b) = registered_backend();
    let c = b.claim(owner("network"), 90).unwrap();
    let call = |_: Call| -> readb::policy::Res<serde_json::Value> {
        panic!("invalid ticket reached root")
    };
    assert!(
        r.network
            .execute(&r, "wrong", "quest", enroll("quest"), call, || true)
            .is_err()
    );
    let viewer = b.watch(owner("view"), 90).unwrap();
    assert!(
        r.network
            .execute(
                &r,
                &viewer,
                "quest",
                enroll("quest"),
                |_| panic!("viewer reached root"),
                || true
            )
            .is_err()
    );
    assert!(
        r.network
            .execute(
                &r,
                &c,
                "quest",
                enroll("phone"),
                |_| panic!("wrong device reached root"),
                || true
            )
            .is_err()
    );
    let active = b.begin_network(&c, "network-enroll").unwrap();
    assert!(
        r.network
            .execute(
                &r,
                &c,
                "quest",
                enroll("quest"),
                |_| panic!("active operation reached root"),
                || true
            )
            .is_err()
    );
    b.finish_network(&c, &active, false, "fixture-refusal")
        .unwrap();
    assert!(
        r.network
            .execute(
                &r,
                &c,
                "quest",
                enroll("quest"),
                |call| {
                    assert!(matches!(call, Call::Status));
                    Ok(serde_json::json!({"fenced":false}))
                },
                || true
            )
            .unwrap_err()
            .contains("upgrade")
    );
    assert!(!b.config.dir.join("active-operation.json").exists());
    b.release(&c).unwrap();
    fs::remove_dir_all(&r.root).unwrap();
}
#[test]
fn network_rpc_success_proves_request_and_loss_cancel_expiry_stay_fenced() {
    use readb::{network_controller::request_digest, network_runtime::Call};
    for case in 0..10 {
        let (r, b) = registered_backend();
        let c = b.claim(owner("network"), 90).unwrap();
        let dispatched = std::cell::Cell::new(false);
        let result = r.network.execute(
            &r,
            &c,
            "quest",
            enroll("quest"),
            |call| match call {
                Call::Status => Ok(serde_json::json!({"scoped_controller":true,"fenced":false})),
                Call::Scoped { nonce, request } => {
                    dispatched.set(true);
                    assert!(b.release(&c).is_err());
                    if case == 1 {
                        return Err("reply_lost".into());
                    }
                    if case == 2 {
                        return Ok(serde_json::json!({"outcome":"refused","error":"test_refusal"}));
                    }
                    r.network
                        .authorize(&nonce, &request_digest(&request)?)
                        .unwrap();
                    if case == 6 {
                        return Err("reply_lost_after_apply".into());
                    }
                    if case == 7 {
                        return Ok(serde_json::json!({"outcome":"unexpected"}));
                    }
                    if case == 8 {
                        return Ok(serde_json::json!({"outcome":"uncertain"}));
                    }
                    if case == 9 {
                        fs::remove_file(b.config.dir.join("events.jsonl")).unwrap();
                        fs::create_dir(b.config.dir.join("events.jsonl")).unwrap();
                    }
                    if case == 3 {
                        b.cancel(&c).unwrap();
                    }
                    if case == 4 {
                        b.state.lock().unwrap().gate.lease.as_mut().unwrap().expires = 0.;
                    }
                    Ok(serde_json::json!({"outcome":"applied"}))
                }
                _ => panic!("unexpected root call"),
            },
            || case != 5 || !dispatched.get(),
        );
        if case == 0 {
            assert!(result.is_ok());
            b.release(&c).unwrap();
        } else if case == 2 {
            assert!(result.unwrap_err().contains("test_refusal"));
            b.release(&c).unwrap();
        } else {
            assert!(result.is_err());
            assert!(b.status()["cleanup_unknown"].is_string());
            assert!(
                Backend::new(b.config.clone()).unwrap().status()["cleanup_unknown"].is_string()
            );
        }
        fs::remove_dir_all(&r.root).unwrap();
    }
}
