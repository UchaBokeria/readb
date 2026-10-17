use crate::{
    backend::{atomic, now},
    control::{self, Request},
    http,
    policy::{Res, equal},
    registry::{Registry, parse_report},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    net::{TcpListener, TcpStream},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
fn reply(s: &mut UnixStream, v: &serde_json::Value, code: i32) {
    if crate::wire::message(
        s,
        if code == 0 { 1 } else { 2 },
        &serde_json::to_vec(v).unwrap(),
    )
    .is_err()
    {
        return;
    }
    let _ = crate::wire::frame(s, 3, &serde_json::to_vec(&json!({"code":code})).unwrap());
}
pub fn control_client(mut s: UnixStream, r: Arc<Registry>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
    let req = crate::wire::line(&mut s, 65536)
        .map_err(|_| "invalid_control_header".into())
        .and_then(|b| Request::parse(&b));
    match req {
        Ok(req) if req.action == "status" && req.device.is_empty() => reply(&mut s, &r.status(), 0),
        Ok(req) if req.action == "history" => {
            let limit = match req.args.as_slice() {
                [] => 200,
                [n] => match n.parse::<usize>() {
                    Ok(n) if (1..=1000).contains(&n) => n,
                    _ => {
                        reply(
                            &mut s,
                            &json!({"error":"history_limit_must_be_1_to_1000"}),
                            78,
                        );
                        return;
                    }
                },
                _ => {
                    reply(&mut s, &json!({"error":"invalid_history_arguments"}), 78);
                    return;
                }
            };
            let mut events = Vec::new();
            let mut error = None;
            for (id, b) in r.all() {
                if !req.device.is_empty() && req.device != id {
                    continue;
                }
                match crate::events::read(&b.config.dir, limit) {
                    Ok(rows) => {
                        for e in rows {
                            let mut v = serde_json::to_value(e).unwrap();
                            v["device"] = json!(id);
                            events.push(v)
                        }
                    }
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
            if !req.device.is_empty() && r.device(&req.device).is_err() {
                error = Some("unknown_device".into())
            }
            if let Some(e) = error {
                reply(&mut s, &json!({"error":e}), 78)
            } else {
                events.sort_by(|a, b| {
                    a["epoch"]
                        .as_f64()
                        .partial_cmp(&b["epoch"].as_f64())
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                if events.len() > limit {
                    events.drain(..events.len() - limit);
                }
                reply(&mut s, &json!({"events":events}), 0)
            }
        }
        Ok(req) if req.action == "device-add" => {
            let result = (|| -> Res<serde_json::Value> {
                let [raw] = req.args.as_slice() else {
                    return Err("device_add_requires_one_private_import".into());
                };
                let import: crate::schema::DeviceImport =
                    serde_json::from_str(raw).map_err(|_| "invalid_device_import")?;
                r.add(import.device, import.listener)
            })();
            match result {
                Ok(v) => reply(&mut s, &v, 0),
                Err(e) => reply(&mut s, &json!({"error":e}), 78),
            }
        }
        Ok(req) if req.action == "trust" => {
            let result = match req.args.as_slice() {
                [pin] => r.trust(&req.device, &req.ticket, pin),
                _ => Err("trust_requires_fingerprint".into()),
            };
            match result {
                Ok(v) => reply(&mut s, &v, 0),
                Err(e) => reply(&mut s, &json!({"error":e}), 73),
            }
        }
        Ok(req) if req.action == "device-rm" => match r.remove(&req.device, &req.ticket) {
            Ok(v) => reply(&mut s, &v, 0),
            Err(e) => reply(&mut s, &json!({"error":e}), 73),
        },
        Ok(req) if req.action == "config" => reply(&mut s, &r.config().public_view(), 0),
        Ok(req) if req.action == "dashboard" => {
            let v = match req.args.as_slice() {
                [a] if a == "status" => Ok(r.web.lock().unwrap().public_view()),
                [a] if a == "key-location" => Ok(crate::web::key_location(&r)),
                [a] if a == "disable" => crate::web::configure(r.clone(), false, 0),
                [a, p] if a == "enable" => p
                    .parse::<u16>()
                    .map_err(|_| "invalid_dashboard_port".into())
                    .and_then(|p| crate::web::configure(r.clone(), true, p)),
                _ => Err("invalid_dashboard_action".into()),
            };
            match v {
                Ok(v) => reply(&mut s, &v, 0),
                Err(e) => reply(&mut s, &json!({"error":e}), 78),
            }
        }
        Ok(req) if req.action == "ps" => reply(
            &mut s,
            &json!({"pid":std::process::id(),"service":"readb","devices":r.config().devices.len()}),
            0,
        ),
        Ok(req) => match r.device(&req.device) {
            Ok(b) => control::handle_request(s, b, req),
            Err(e) => reply(&mut s, &json!({"error":e}), 78),
        },
        Err(e) => reply(&mut s, &json!({"error":e}), 78),
    }
}
fn report(mut s: TcpStream, peer: std::net::IpAddr, r: Arc<Registry>, bind: std::net::SocketAddr) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(3)));
    let result = (|| -> Res<(u16, bool, Option<String>, Option<String>)> {
        let req = http::request(&mut s, 4096)?;
        let config = r.config();
        let Some(route) = config
            .listeners
            .iter()
            .find(|l| l.bind == bind && l.path == req.path && req.method == "POST")
        else {
            return Ok((404, false, None, Some("unknown_report_route".into())));
        };
        let b = r.device(&route.device)?;
        if peer != std::net::IpAddr::V4(b.config.peer)
            || !equal(
                req.headers
                    .get("authorization")
                    .map(String::as_str)
                    .unwrap_or(""),
                &format!("Bearer {}", b.config.token),
            )
        {
            return Ok((
                403,
                false,
                None,
                Some("report_authentication_failed".into()),
            ));
        }
        let result = match route.format {
            crate::schema::ReportFormat::V2 => {
                b.report_v2(readb_protocol::Report::parse(&req.body)?)
            }
            format => b.report(parse_report(&req.body, format)?),
        };
        match result {
            Ok(v) => Ok((200, v, Some(route.device.clone()), None)),
            Err(e) => {
                let code = match e.as_str() {
                    "stale_report_sequence"
                    | "retired_report_epoch"
                    | "report_protocol_downgrade" => 409,
                    "rate_limited" => 429,
                    _ => 503,
                };
                Ok((code, false, None, Some(e)))
            }
        }
    })();
    let (code, connected, id, error) = result.unwrap_or_else(|e| (400, false, None, Some(e)));
    let _ = http::answer(
        &mut s,
        code,
        &json!({"ok":code==200,"connected":connected,"error":error}),
    );
    drop(s);
    if let Some(id) = id {
        r.notify(&id);
    }
}

pub fn serve(r: Arc<Registry>, stop: Arc<AtomicBool>) -> Res<()> {
    let _catalog_runtime = crate::catalog::runtime_lock(&r.root, &r.config_path)?;
    r.enable_owned_servers();
    let path = r.root.join("control.sock");
    if path.as_os_str().as_encoded_bytes().len() >= 108 {
        return Err("state_path_too_long_for_unix_socket: choose a shorter --state-dir".into());
    }
    if let Ok(m) = fs::symlink_metadata(&path) {
        if !m.file_type().is_socket()
            || m.uid() != unsafe { libc::geteuid() }
            || UnixStream::connect(&path).is_ok()
        {
            return Err("control_socket_already_owned_or_invalid".into());
        }
        fs::remove_file(&path).map_err(|_| "stale_socket_cleanup_failed")?;
    }
    let unix = UnixListener::bind(&path).map_err(|_| "control_bind_failed")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "control_permissions_failed")?;
    unix.set_nonblocking(true)
        .map_err(|_| "control_setup_failed")?;
    crate::web::restore(r.clone());
    let mut listeners: BTreeMap<std::net::SocketAddr, TcpListener> = BTreeMap::new();
    let mut revision = 0;
    let mut last_retry = Instant::now() - Duration::from_secs(2);
    let mut maintained = std::collections::HashSet::new();
    let count = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        let current = r.revision.load(Ordering::SeqCst);
        if revision != current || last_retry.elapsed() >= Duration::from_secs(1) {
            let config = r.config();
            let binds: std::collections::BTreeSet<_> =
                config.listeners.iter().map(|l| l.bind).collect();
            listeners.retain(|a, _| binds.contains(a));
            let mut errors = BTreeMap::new();
            for addr in binds {
                if listeners.contains_key(&addr) {
                    continue;
                }
                match TcpListener::bind(addr).and_then(|tcp| {
                    tcp.set_nonblocking(true)?;
                    Ok(tcp)
                }) {
                    Ok(tcp) => {
                        listeners.insert(addr, tcp);
                    }
                    Err(e) => {
                        errors.insert(
                            addr.to_string(),
                            format!("report_listener_unavailable: {e}"),
                        );
                    }
                }
            }
            *r.listener_errors.lock().unwrap() = errors;
            for (id, b) in r.all() {
                if !maintained.insert(id) {
                    continue;
                }
                let stop = stop.clone();
                thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) && !b.state.lock().unwrap().stopping {
                        if let Err(reason) = b.keepalive() {
                            let _ = atomic(
                                &b.config.dir.join("keepalive.json"),
                                &json!({"active":true,"connected":false,"reason":reason,"last_check_epoch":now()}),
                            );
                        }
                        for _ in 0..200 {
                            if stop.load(Ordering::SeqCst) || b.state.lock().unwrap().stopping {
                                break;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                });
            }
            revision = current;
            last_retry = Instant::now();
        }
        if let Ok((stream, _)) = unix.accept()
            && count.load(Ordering::SeqCst) < 64
        {
            count.fetch_add(1, Ordering::SeqCst);
            let rr = r.clone();
            let c = count.clone();
            thread::spawn(move || {
                control_client(stream, rr);
                c.fetch_sub(1, Ordering::SeqCst);
            });
        }
        for (bind, listener) in &listeners {
            if let Ok((stream, addr)) = listener.accept()
                && count.load(Ordering::SeqCst) < 64
            {
                count.fetch_add(1, Ordering::SeqCst);
                let rr = r.clone();
                let bind = *bind;
                let c = count.clone();
                thread::spawn(move || {
                    report(stream, addr.ip(), rr, bind);
                    c.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    let shutdown = r.shutdown();
    let until = Instant::now() + Duration::from_secs(35);
    while r.active() && Instant::now() < until {
        thread::sleep(Duration::from_millis(50));
    }
    let _ = fs::remove_file(path);
    let servers = r.stop_owned_servers();
    shutdown?;
    servers?;
    Ok(())
}
