use readb::{
    enrollment_profile::Request,
    onboarding_store::{Store, request_hash},
    policy::Owner,
    schema::Kind,
};
use std::{fs, os::unix::fs::PermissionsExt};
fn fixture_root() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("readb-onboard-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn metadata() -> Request {
    Request {
        id: "new-phone".into(),
        name: "Phone".into(),
        kind: Kind::Phone,
        endpoint: "vpn.example.org:51820".into(),
        report_port: 19193,
    }
}
fn owner() -> Owner {
    Owner {
        agent: "codex".into(),
        origin: "pc".into(),
        session: "actual-fixture".into(),
        job: "Enroll phone".into(),
        allow_sleep: false,
    }
}
fn recipient(nonce: u8) -> Vec<u8> {
    use rsa::pkcs8::EncodePublicKey;
    let n = (rsa::BigUint::from(1u8) << 3071usize) + rsa::BigUint::from(1u8);
    let k = rsa::RsaPublicKey::new(n, rsa::BigUint::from(65537u32)).unwrap();
    let der = k.to_public_key_der().unwrap();
    let mut r = b"RER1".to_vec();
    r.extend_from_slice(&[nonce; 64]);
    r.extend_from_slice(&(der.as_bytes().len() as u32).to_be_bytes());
    r.extend_from_slice(der.as_bytes());
    r
}
#[test]
fn exact_claim_survives_reopen_and_lost_reply_without_saving_raw_code_or_auth() {
    let root = fixture_root();
    let auth = "b".repeat(64);
    let request = recipient(1);
    let mut store = Store::open(&root).unwrap();
    let invitation = store
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap();
    let code = invitation.code().to_string();
    let first = store
        .claim(&code, &request, &auth, "127.0.0.1", 1001)
        .unwrap();
    let tx = first.transaction().to_string();
    assert_eq!(first.id(), "new-phone");
    assert_eq!(
        store
            .claim(&code, &request, &auth, "127.0.0.1", 1002)
            .unwrap()
            .transaction(),
        tx
    );
    drop(store);
    let mut store = Store::open(&root).unwrap();
    assert_eq!(
        store
            .resume(&request_hash(&request), &auth, "127.0.0.1", 2000)
            .unwrap()
            .transaction(),
        tx
    );
    assert_eq!(
        store
            .claim(&code, &request, &auth, "127.0.0.1", 2000)
            .unwrap()
            .transaction(),
        tx,
        "sameclaim retry after boundcode expiry"
    );
    let raw = fs::read_to_string(root.join("onboarding/sessions.json")).unwrap();
    assert!(!raw.contains(&auth));
    assert!(!raw.contains(&code.replace('-', "")));
    assert!(!raw.contains(&code));
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn expired_code_other_recipient_and_wrong_resume_credential_are_uniform_and_preserve_binding() {
    let root = fixture_root();
    let auth = "b".repeat(64);
    let mut s = Store::open(&root).unwrap();
    let code = s
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    let req = recipient(2);
    let bound = s
        .claim(&code, &req, &auth, "127.0.0.1", 1001)
        .unwrap()
        .transaction()
        .to_string();
    let e1 = s
        .claim(&code, &recipient(3), &auth, "127.0.0.1", 1002)
        .err()
        .unwrap();
    let e2 = s
        .resume(&request_hash(&req), &"c".repeat(64), "127.0.0.1", 1002)
        .err()
        .unwrap();
    assert_eq!(e1, e2);
    assert_eq!(e1, "invalid_setup");
    assert_eq!(
        s.resume(&request_hash(&req), &auth, "127.0.0.1", 1003)
            .unwrap()
            .transaction(),
        bound
    );
    drop(s);
    fs::remove_dir_all(root).unwrap();
    let root = fixture_root();
    let mut s = Store::open(&root).unwrap();
    let code = s
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    assert_eq!(
        s.claim(&code, &req, &auth, "127.0.0.1", 1601)
            .err()
            .unwrap(),
        "invalid_setup"
    );
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn invalid_requests_do_not_consume_invite_and_competing_writer_fails_closed() {
    let root = fixture_root();
    let mut s = Store::open(&root).unwrap();
    let code = s
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    assert!(Store::open(&root).is_err());
    assert!(
        s.claim(&code, b"malformed", &"b".repeat(64), "127.0.0.1", 1001)
            .is_err()
    );
    assert!(
        s.claim(&code, &recipient(4), &"b".repeat(64), "127.0.0.1", 1002)
            .is_ok()
    );
    drop(s);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn failed_attempt_budget_is_bounded_and_expires_without_mutating_bound_session() {
    let root = fixture_root();
    let mut s = Store::open(&root).unwrap();
    let req = recipient(5);
    let auth = "b".repeat(64);
    let code = s
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    let bound = s
        .claim(&code, &req, &auth, "127.0.0.1", 1001)
        .unwrap()
        .transaction()
        .to_string();
    for _ in 0..5 {
        assert_eq!(
            s.claim("0000-0000-0000-0000", &req, &auth, "127.0.0.1", 1002)
                .err()
                .unwrap(),
            "invalid_setup"
        );
    }
    assert!(
        s.claim("0000-0000-0000-0000", &req, &auth, "127.0.0.1", 1002)
            .err()
            .unwrap()
            .starts_with("setup_rate_limited")
    );
    assert_eq!(
        s.claim(&code, &req, &auth, "127.0.0.1", 1002)
            .unwrap()
            .transaction(),
        bound,
        "exact authenticated retries ignore wrongattempt budget"
    );
    assert_eq!(
        s.claim("0000-0000-0000-0000", &req, &auth, "127.0.0.1", 1063)
            .err()
            .unwrap(),
        "invalid_setup"
    );
    drop(s);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn exhausted_attempt_budget_blocks_first_bind_even_for_a_valid_code() {
    let root = fixture_root();
    let mut store = Store::open(&root).unwrap();
    let req = recipient(6);
    let auth = "b".repeat(64);
    let code = store
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    for _ in 0..5 {
        assert_eq!(
            store
                .claim("0000-0000-0000-0000", &req, &auth, "127.0.0.1", 1001)
                .err()
                .unwrap(),
            "invalid_setup"
        );
    }
    assert!(
        store
            .claim(&code, &req, &auth, "127.0.0.1", 1002)
            .err()
            .is_some_and(|e| e.starts_with("setup_rate_limited"))
    );
    assert!(store.claim(&code, &req, &auth, "127.0.0.1", 1062).is_ok());
    drop(store);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn revoke_only_unused_original_owner_invite_and_never_erase_a_bound_session() {
    let root = fixture_root();
    let mut store = Store::open(&root).unwrap();
    let code = store
        .issue(&metadata(), &owner(), &"a".repeat(64), 1000)
        .unwrap()
        .code()
        .to_string();
    let mut other = owner();
    other.session = "other".into();
    assert!(store.revoke_unused("new-phone", &other).is_err());
    store.revoke_unused("new-phone", &owner()).unwrap();
    assert!(
        store
            .claim(&code, &recipient(7), &"b".repeat(64), "127.0.0.1", 1001)
            .is_err()
    );
    let code = store
        .issue(&metadata(), &owner(), &"a".repeat(64), 1002)
        .unwrap()
        .code()
        .to_string();
    let req = recipient(8);
    store
        .claim(&code, &req, &"b".repeat(64), "127.0.0.1", 1003)
        .unwrap();
    assert!(store.revoke_unused("new-phone", &owner()).is_err());
    assert!(
        store
            .resume(&request_hash(&req), &"b".repeat(64), "127.0.0.1", 1004)
            .is_ok()
    );
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
