use readb::{
    network_authority::{Proof, ProofReply, exchange, handle},
    policy::Res,
};
use std::{io::Write, os::unix::net::UnixStream, thread};
fn proof() -> Proof {
    Proof {
        schema: 1,
        nonce: "a".repeat(64),
        request_digest: "b".repeat(64),
    }
}
#[test]
fn exact_reply_required_and_denial_never_grants() {
    for kind in 0..5 {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let h = thread::spawn(move || {
            let p: Proof =
                serde_json::from_slice(&readb::wire::line(&mut server, 4096).unwrap()).unwrap();
            let mut r = ProofReply {
                schema: 1,
                nonce: p.nonce,
                request_digest: p.request_digest,
                allowed: true,
            };
            match kind {
                1 => r.allowed = false,
                2 => r.schema = 2,
                3 => r.nonce = "c".repeat(64),
                4 => r.request_digest = "d".repeat(64),
                _ => (),
            };
            server.write_all(&serde_json::to_vec(&r).unwrap()).unwrap();
            server.write_all(b"\n").unwrap();
        });
        assert_eq!(exchange(&mut client, &proof()).is_ok(), kind == 0);
        h.join().unwrap();
    }
}
#[test]
fn wrong_uid_rejected_before_read_or_authorization() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let result = handle(
        &mut server,
        unsafe { libc::geteuid() }.wrapping_add(1),
        &|_: &str, _: &str| -> Res<()> { panic!("wrong peer must not authorize") },
    );
    assert!(result.unwrap_err().contains("peer"));
    client.write_all(b"ignored").unwrap();
}
#[test]
fn malformed_oversize_truncated_and_schema_never_authorize() {
    for bytes in [
        b"{}\n".to_vec(),
        vec![b'x'; 4097],
        b"{\"schema\":2,\"nonce\":\"a\",\"request_digest\":\"b\"}\n".to_vec(),
        b"{".to_vec(),
    ] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&bytes).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(
            handle(
                &mut server,
                unsafe { libc::geteuid() },
                &|_: &str, _: &str| -> Res<()> { panic!("invalid proof must not authorize") }
            )
            .is_err()
        );
    }
}
#[test]
fn authenticated_request_uses_exact_one_use_authority() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let h = thread::spawn(move || {
        handle(
            &mut server,
            unsafe { libc::geteuid() },
            &|n: &str, d: &str| {
                assert_eq!(n, "a".repeat(64));
                assert_eq!(d, "b".repeat(64));
                Ok(())
            },
        )
    });
    exchange(&mut client, &proof()).unwrap();
    h.join().unwrap().unwrap();
}

#[test]
fn scoped_root_request_requires_proof_before_any_kernel_access() {
    use readb::{
        network::{Kernel, Manager, Policy, Request, Snapshot},
        network_runtime::{Call, Rpc, handle_authority},
    };
    use std::{fs, net::Ipv4Addr, os::unix::fs::PermissionsExt};
    struct Never;
    impl Kernel for Never {
        fn snapshot(&mut self, _: &Policy) -> Res<Snapshot> {
            panic!("denied proof touched kernel")
        }
        fn set(&mut self, _: &Policy, _: &str, _: Option<Ipv4Addr>) -> Res<()> {
            panic!("denied proof wrote kernel")
        }
    }
    let root = std::env::temp_dir().join(format!("readb-proof-{}", readb::policy::random()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let policy = Policy {
        schema: 1,
        uid: unsafe { libc::geteuid() },
        interface: "readb0".into(),
        server_key: format!("{}AAA=", "E".repeat(40)),
        server_address: "10.88.0.1".parse().unwrap(),
        prefix: 24,
        first: "10.88.0.100".parse().unwrap(),
        last: "10.88.0.110".parse().unwrap(),
    };
    let mut manager = Manager::open(&root, policy).unwrap();
    let request = Request::Remove { id: "phone".into() };
    let digest = readb::network_controller::request_digest(&request).unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client
        .write_all(
            &serde_json::to_vec(&Rpc {
                schema: 1,
                request: Call::Scoped {
                    nonce: "a".repeat(64),
                    request,
                },
            })
            .unwrap(),
        )
        .unwrap();
    client.write_all(b"\n").unwrap();
    handle_authority(
        &mut server,
        &mut manager,
        &mut Never,
        &|n: &str, d: &str| {
            assert_eq!(n, "a".repeat(64));
            assert_eq!(d, digest);
            Err("test_denied".into())
        },
    )
    .unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&readb::wire::line(&mut client, 4096).unwrap()).unwrap();
    assert_eq!(value["result"]["outcome"], "refused");
    assert!(!manager.fenced());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scoped_results_distinguish_applied_refused_and_uncertain() {
    use readb::{
        network::{Kernel, Manager, Policy, Request, Snapshot},
        network_runtime::{Call, Rpc, handle_authority},
    };
    use std::{collections::BTreeMap, fs, net::Ipv4Addr, os::unix::fs::PermissionsExt};
    struct Fake {
        snapshot: Snapshot,
        fail: bool,
        calls: usize,
    }
    impl Kernel for Fake {
        fn snapshot(&mut self, _: &Policy) -> Res<Snapshot> {
            Ok(self.snapshot.clone())
        }
        fn set(&mut self, _: &Policy, key: &str, address: Option<Ipv4Addr>) -> Res<()> {
            self.calls += 1;
            if self.fail {
                return Err("fixture_write_unknown".into());
            }
            self.snapshot
                .peers
                .insert(key.into(), vec![format!("{}/32", address.unwrap())]);
            Ok(())
        }
    }
    for (case, outcome, calls, fenced) in [
        (0, "applied", 1, false),
        (1, "refused", 0, false),
        (2, "uncertain", 1, true),
    ] {
        let root = std::env::temp_dir().join(format!("readb-outcome-{}", readb::policy::random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            schema: 1,
            uid: unsafe { libc::geteuid() },
            interface: "readb0".into(),
            server_key: format!("{}AAA=", "E".repeat(40)),
            server_address: "10.88.0.1".parse().unwrap(),
            prefix: 24,
            first: "10.88.0.100".parse().unwrap(),
            last: "10.88.0.110".parse().unwrap(),
        };
        let mut kernel = Fake {
            snapshot: Snapshot {
                server_key: policy.server_key.clone(),
                addresses: vec!["10.88.0.1/24".into()],
                peers: BTreeMap::new(),
            },
            fail: case == 2,
            calls: 0,
        };
        let mut manager = Manager::open(&root, policy.clone()).unwrap();
        let request = Request::Enroll {
            id: "phone".into(),
            key: format!("{}AAA=", "D".repeat(40)),
            address: if case == 1 {
                "10.88.0.99"
            } else {
                "10.88.0.100"
            }
            .parse()
            .unwrap(),
        };
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .write_all(
                &serde_json::to_vec(&Rpc {
                    schema: 1,
                    request: Call::Scoped {
                        nonce: "a".repeat(64),
                        request,
                    },
                })
                .unwrap(),
            )
            .unwrap();
        client.write_all(b"\n").unwrap();
        handle_authority(
            &mut server,
            &mut manager,
            &mut kernel,
            &|_: &str, _: &str| Ok(()),
        )
        .unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&readb::wire::line(&mut client, 4096).unwrap()).unwrap();
        assert_eq!(value["result"]["outcome"], outcome);
        assert_eq!(kernel.calls, calls);
        assert_eq!(manager.fenced(), fenced);
        drop(manager);
        assert_eq!(Manager::open(&root, policy).unwrap().fenced(), fenced);
        fs::remove_dir_all(root).unwrap();
    }
}
#[test]
fn silent_peer_is_bounded_by_absolute_deadline() {
    let (_client, mut server) = UnixStream::pair().unwrap();
    let started = std::time::Instant::now();
    assert!(
        handle(
            &mut server,
            unsafe { libc::geteuid() },
            &|_: &str, _: &str| -> Res<()> { panic!("no proof") }
        )
        .is_err()
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
}
