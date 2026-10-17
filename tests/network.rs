use readb::network::*;
use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf};
fn key(c: char) -> String {
    format!("{}AAA=", c.to_string().repeat(40))
}
fn policy() -> Policy {
    Policy {
        schema: 1,
        uid: 1000,
        interface: "readb0".into(),
        server_key: key('E'),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.10".parse().unwrap(),
        last: "10.88.0.20".parse().unwrap(),
    }
}
fn state() -> PathBuf {
    let p = std::env::temp_dir().join(format!("readb-net-{}", readb::policy::random()));
    std::fs::create_dir(&p).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}
struct Fake {
    snapshot: Snapshot,
    fail: bool,
    calls: usize,
    drift: bool,
}
impl Kernel for Fake {
    fn snapshot(&mut self, _: &Policy) -> Result<Snapshot, String> {
        Ok(self.snapshot.clone())
    }
    fn set(&mut self, _: &Policy, peer_key: &str, address: Option<Ipv4Addr>) -> Result<(), String> {
        self.calls += 1;
        if self.fail {
            return Err("test interruption".into());
        }
        if let Some(a) = address {
            self.snapshot
                .peers
                .insert(peer_key.into(), vec![format!("{a}/32")]);
        } else {
            self.snapshot.peers.remove(peer_key);
        }
        if self.drift {
            self.snapshot
                .peers
                .insert(key('D'), vec!["10.88.0.44/32".into()]);
        }
        Ok(())
    }
}
fn kernel() -> Fake {
    Fake {
        snapshot: Snapshot {
            server_key: key('E'),
            addresses: vec!["10.88.0.1/24".into()],
            peers: BTreeMap::from([(key('B'), vec!["10.88.0.3/32".into()])]),
        },
        fail: false,
        calls: 0,
        drift: false,
    }
}
fn enroll() -> Request {
    Request::Enroll {
        id: "phone".into(),
        key: key('C'),
        address: "10.88.0.10".parse().unwrap(),
    }
}
#[test]
fn admitted_enrollment_and_removal_preserve_unrelated_peers() {
    let p = state();
    let mut m = Manager::open(&p, policy()).unwrap();
    let mut k = kernel();
    let unrelated = k.snapshot.peers.clone();
    m.apply(1000, enroll(), &mut k).unwrap();
    assert_eq!(k.calls, 1);
    assert_eq!(m.devices().len(), 1);
    m.apply(1000, Request::Remove { id: "phone".into() }, &mut k)
        .unwrap();
    assert_eq!(k.snapshot.peers, unrelated);
    assert!(m.devices().is_empty());
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn caller_scope_and_collisions_reject_before_kernel_write() {
    let p = state();
    let mut m = Manager::open(&p, policy()).unwrap();
    let mut k = kernel();
    assert!(m.apply(2000, enroll(), &mut k).is_err());
    assert!(
        m.apply(
            1000,
            Request::Remove {
                id: "unmanaged".into()
            },
            &mut k
        )
        .is_err()
    );
    for r in [
        Request::Enroll {
            id: "phone".into(),
            key: key('B'),
            address: "10.88.0.10".parse().unwrap(),
        },
        Request::Enroll {
            id: "phone".into(),
            key: key('C'),
            address: "10.88.0.3".parse().unwrap(),
        },
    ] {
        assert!(m.apply(1000, r, &mut k).is_err());
    }
    k.snapshot
        .peers
        .insert(key('B'), vec!["10.88.0.0/24".into()]);
    assert!(m.apply(1000, enroll(), &mut k).is_err());
    assert_eq!(k.calls, 0);
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn interrupted_apply_is_fenced_across_restart_and_reconciles_only_exact_snapshots() {
    let p = state();
    let mut k = kernel();
    {
        let mut m = Manager::open(&p, policy()).unwrap();
        k.fail = true;
        assert!(m.apply(1000, enroll(), &mut k).is_err());
        assert!(m.fenced());
    }
    let mut m = Manager::open(&p, policy()).unwrap();
    assert!(m.fenced());
    assert!(m.apply(1000, enroll(), &mut k).is_err());
    k.fail = false;
    m.reconcile(1000, &mut k).unwrap();
    assert!(!m.fenced());
    assert!(m.devices().is_empty());
    k.drift = true;
    assert!(m.apply(1000, enroll(), &mut k).is_err());
    assert!(m.reconcile(1000, &mut k).is_err());
    assert!(m.fenced());
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn a_changed_policy_or_server_identity_never_reuses_authority() {
    let p = state();
    let m = Manager::open(&p, policy()).unwrap();
    assert!(Manager::open(&p, policy()).is_err());
    drop(m);
    let mut other = policy();
    other.uid = 2000;
    assert!(Manager::open(&p, other).is_err());
    let mut m = Manager::open(&p, policy()).unwrap();
    let mut k = kernel();
    k.snapshot.server_key = key('D');
    assert!(m.apply(1000, enroll(), &mut k).is_err());
    assert_eq!(k.calls, 0);
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn a_durable_intent_survives_ambiguous_final_state_publication() {
    let p = state();
    let mut k = kernel();
    {
        let mut m = Manager::open(&p, policy()).unwrap();
        k.fail = true;
        assert!(m.apply(1000, enroll(), &mut k).is_err());
    }
    // Model a crash after final state rename, before intent removal is durable.
    let path = p.join("network.json");
    let old: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let marker = p.join("network-pending.json");
    if !marker.exists() {
        std::fs::write(&marker, serde_json::to_vec(&old).unwrap()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut committed = old;
    committed["pending"] = serde_json::Value::Null;
    committed["devices"] = serde_json::json!({"phone":{"key":key('C'),"address":"10.88.0.10"}});
    std::fs::write(&path, serde_json::to_vec(&committed).unwrap()).unwrap();
    let mut m = Manager::open(&p, policy()).unwrap();
    assert!(
        m.fenced(),
        "a committed-looking state must not erase unresolved durable intent"
    );
    k.fail = false;
    k.snapshot
        .peers
        .insert(key('C'), vec!["10.88.0.10/32".into()]);
    m.reconcile(1000, &mut k).unwrap();
    assert!(!m.fenced());
    assert_eq!(m.devices().len(), 1);
    drop(m);
    assert!(!Manager::open(&p, policy()).unwrap().fenced());
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn filesystem_and_policy_boundaries_fail_closed() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let p = state();
    let outside = state();
    symlink(&outside, p.join("link")).unwrap();
    assert!(Manager::open(&p.join("link"), policy()).is_err());
    symlink(outside.join("secret"), p.join("network.json")).unwrap();
    assert!(Manager::open(&p, policy()).is_err());
    assert!(!outside.join("secret").exists());
    std::fs::remove_file(p.join("network.json")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Manager::open(&p, policy()).is_err());
    for change in 0..5 {
        let mut bad = policy();
        match change {
            0 => bad.prefix = 0,
            1 => bad.server_key = "A".repeat(44),
            2 => bad.first = bad.server_address,
            3 => bad.interface = "-bad;cmd".into(),
            _ => bad.last = "8.8.8.8".parse().unwrap(),
        };
        assert!(bad.validate().is_err());
    }
    std::fs::remove_dir_all(p).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
}
#[test]
fn rpc_uses_socket_identity_and_rejects_unknown_fields_without_changes() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let p = state();
    let mut pol = policy();
    pol.uid = unsafe { libc::geteuid() };
    let mut m = Manager::open(&p, pol).unwrap();
    let mut k = kernel();
    for request in [
        r#"{"schema":2,"request":{"action":"status"}}"#,
        r#"{"schema":1,"uid":0,"request":{"action":"status"}}"#,
    ] {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(format!("{request}\n").as_bytes()).unwrap();
        readb::network_runtime::handle(&mut b, &mut m, &mut k).unwrap();
        drop(b);
        let mut result = String::new();
        a.read_to_string(&mut result).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["ok"], false);
    }
    assert_eq!(k.calls, 0);
    std::fs::remove_dir_all(p).unwrap();
}
#[test]
fn socket_client_cannot_claim_another_uid() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    let actual = unsafe { libc::geteuid() };
    if actual == 0 {
        return;
    }
    let p = state();
    let mut pol = policy();
    pol.uid = actual + 1;
    let mut m = Manager::open(&p, pol).unwrap();
    let mut k = kernel();
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(b"{\"schema\":1,\"request\":{\"action\":\"apply\",\"request\":{\"op\":\"remove\",\"id\":\"phone\"}}}\n").unwrap();
    readb::network_runtime::handle(&mut b, &mut m, &mut k).unwrap();
    drop(b);
    let mut result = String::new();
    a.read_to_string(&mut result).unwrap();
    assert!(result.contains("network_caller_denied"));
    assert_eq!(k.calls, 0);
    std::fs::remove_dir_all(p).unwrap();
}
