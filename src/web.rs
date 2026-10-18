use crate::{
    actions,
    backend::{atomic, now},
    client, control,
    policy::{Owner, Res, equal, random},
    registry::Registry,
    wire::{frame, read_frame},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
#[derive(Default)]
pub struct Dashboard {
    pub enabled: bool,
    pub port: u16,
    pub stop: Option<Arc<AtomicBool>>,
    pub listener_done: Option<Arc<AtomicBool>>,
    pub error: Option<String>,
}
impl Dashboard {
    pub fn public_view(&self) -> Value {
        json!({"enabled":self.enabled,"url":if self.enabled{Some(format!("http://127.0.0.1:{}/",self.port))}else{None},"error":self.error})
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema: u32,
    enabled: bool,
    port: u16,
}
pub fn authorized(h: &HashMap<String, String>, key: &str, port: u16) -> bool {
    let host = h.get("host").map(String::as_str).unwrap_or("");
    let allowed = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if !allowed.iter().any(|a| a == host) {
        return false;
    }
    if h.get("origin")
        .is_some_and(|o| o != &format!("http://{host}"))
    {
        return false;
    }
    equal(
        h.get("authorization").map(String::as_str).unwrap_or(""),
        &format!("Bearer {key}"),
    )
}
fn key(r: &Registry) -> Res<String> {
    let path = r.root.join("dashboard-key");
    if !path.exists() {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| "dashboard_key_create_failed")?;
        f.write_all(random().as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|_| "dashboard_key_write_failed")?;
    }
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "dashboard_key_unavailable")?;
    let m = f.metadata().map_err(|_| "dashboard_key_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() != 64
    {
        return Err("dashboard_key_permissions_or_shape_invalid".into());
    }
    use std::io::Read;
    let mut k = String::new();
    f.read_to_string(&mut k)
        .map_err(|_| "dashboard_key_read_failed")?;
    Ok(k)
}
pub fn configure(r: Arc<Registry>, enabled: bool, port: u16) -> Res<Value> {
    let mut w = r.web.lock().unwrap();
    if enabled && r.closing.load(Ordering::SeqCst) {
        return Err("coordinator_shutdown".into());
    }
    if !enabled {
        atomic(
            &r.root.join("dashboard.json"),
            &Saved {
                schema: 1,
                enabled: false,
                port: w.port,
            },
        )?;
        if let Some(s) = &w.stop {
            s.store(true, Ordering::SeqCst);
        }
        w.enabled = false;
        if let Some(done) = &w.listener_done {
            let until = std::time::Instant::now() + Duration::from_secs(1);
            while !done.load(Ordering::SeqCst) && std::time::Instant::now() < until {
                thread::sleep(Duration::from_millis(5));
            }
            if !done.load(Ordering::SeqCst) {
                return Err("dashboard_stop_pending: retry shortly".into());
            }
        }
        return Ok(w.public_view());
    }
    if w.enabled && w.port == port && w.stop.as_ref().is_some_and(|s| !s.load(Ordering::SeqCst)) {
        return Ok(w.public_view());
    }
    if port != 0 && port < 1024 {
        return Err("dashboard_port_must_be_unprivileged".into());
    }
    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|_| "dashboard_port_unavailable")?;
    let port = listener
        .local_addr()
        .map_err(|_| "dashboard_address_failed")?
        .port();
    let secret = key(&r)?;
    atomic(
        &r.root.join("dashboard.json"),
        &Saved {
            schema: 1,
            enabled: true,
            port,
        },
    )?;
    if let Some(s) = &w.stop {
        s.store(true, Ordering::SeqCst)
    }
    let stop = Arc::new(AtomicBool::new(false));
    w.enabled = true;
    w.port = port;
    w.error = None;
    w.stop = Some(stop.clone());
    let done = Arc::new(AtomicBool::new(false));
    w.listener_done = Some(done.clone());
    let view = w.public_view();
    drop(w);
    thread::spawn(move || {
        let result = serve(listener, r.clone(), secret, stop);
        done.store(true, Ordering::SeqCst);
        if let Err(e) = result {
            let mut w = r.web.lock().unwrap();
            if w.port == port {
                w.enabled = false;
                w.error = Some(e);
            }
        }
    });
    Ok(view)
}
pub fn restore(r: Arc<Registry>) {
    let path = r.root.join("dashboard.json");
    if !path.exists() {
        return;
    }
    let result = (|| -> Res<()> {
        let bytes = fs::read(path).map_err(|_| "dashboard_config_unavailable")?;
        if bytes.len() > 1024 {
            return Err("dashboard_config_too_large".into());
        }
        let c: Saved = serde_json::from_slice(&bytes).map_err(|_| "invalid_dashboard_config")?;
        if c.schema != 1 {
            return Err("unsupported_dashboard_config".into());
        }
        if c.enabled {
            configure(r.clone(), true, c.port)?;
        }
        Ok(())
    })();
    if let Err(e) = result {
        r.web.lock().unwrap().error = Some(e);
    }
}
pub fn key_location(r: &Registry) -> Value {
    json!({"key_file":r.root.join("dashboard-key"),"note":"Read this private file on the server. Never paste the key into logs or public chat."})
}
fn response(s: &mut TcpStream, code: u16, kind: &str, data: &[u8]) -> Res<()> {
    write!(s,"HTTP/1.1 {code} Response\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'\r\n\r\n",data.len()).and_then(|_|s.write_all(data)).map_err(|_|"dashboard_response_closed".into())
}
fn json_reply(s: &mut TcpStream, code: u16, value: &Value) {
    let _ = response(
        s,
        code,
        "application/json",
        &serde_json::to_vec(value).unwrap(),
    );
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionRequest {
    device: String,
    action: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    reviewed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairRequest {
    device: String,
    peer: std::net::Ipv4Addr,
    pair_port: u16,
    code: String,
    #[serde(default)]
    connect_port: Option<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRequest {
    device: String,
    enabled: bool,
    prevent_lock: bool,
}
fn history(r: &Registry) -> Res<Value> {
    let mut all = Vec::new();
    for (id, b) in r.all() {
        for row in crate::events::read(&b.config.dir, 100)? {
            let mut v = serde_json::to_value(row).unwrap();
            v["device"] = json!(id);
            all.push(v)
        }
    }
    all.sort_by(|a, b| {
        a["epoch"]
            .as_f64()
            .partial_cmp(&b["epoch"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if all.len() > 200 {
        all.drain(..all.len() - 200);
    }
    Ok(json!({"events":all}))
}
fn collect(
    b: Arc<crate::backend::Backend>,
    ticket: &str,
    args: Vec<String>,
) -> Res<(i32, Vec<u8>, Vec<u8>)> {
    collect_input(b, ticket, args, None, 300)
}
fn collect_input(
    b: Arc<crate::backend::Backend>,
    ticket: &str,
    args: Vec<String>,
    input: Option<Vec<u8>>,
    timeout: u64,
) -> Res<(i32, Vec<u8>, Vec<u8>)> {
    let mut req = client::request("exec", None);
    req.ticket = ticket.into();
    req.args = args;
    req.timeout = timeout;
    let req = control::Request::parse(&serde_json::to_vec(&req).unwrap())?;
    let (mut c, s) = UnixStream::pair().map_err(|_| "action_channel_failed")?;
    c.set_read_timeout(Some(Duration::from_secs(timeout + 10)))
        .map_err(|_| "action_channel_failed")?;
    thread::spawn(move || control::handle_request(s, b, req));
    if let Some(mut bytes) = input {
        let result = frame(&mut c, 0, &bytes);
        bytes.fill(0);
        result.map_err(|_| "action_channel_closed")?;
    }
    frame(&mut c, 4, b"").map_err(|_| "action_channel_closed")?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        let (tag, data) = read_frame(&mut c).map_err(|_| "action_channel_closed")?;
        if out.len() + err.len() + data.len() > 32 * 1024 * 1024 {
            return Err("action_output_too_large".into());
        }
        match tag {
            1 => out.extend(data),
            2 => err.extend(data),
            3 => {
                let v: Value =
                    serde_json::from_slice(&data).map_err(|_| "invalid_action_result")?;
                return Ok((
                    v["code"].as_i64().ok_or("invalid_action_result")? as i32,
                    out,
                    err,
                ));
            }
            _ => return Err("invalid_action_frame".into()),
        }
    }
}
fn pair(s: &mut TcpStream, r: Arc<Registry>, p: PairRequest, stopped: Arc<AtomicBool>) -> Res<()> {
    if p.pair_port < 1024
        || p.connect_port.is_some_and(|port| port < 1024)
        || p.code.len() != 6
        || !p.code.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(
            "invalid_pair_request: use the six-digit code and pairing port shown on the device"
                .into(),
        );
    }
    let b = r.device(&p.device)?;
    if p.peer != b.config.peer {
        return Err("pair_ip_must_match_configured_peer: use the enrolled VPN IP".into());
    }
    if stopped.load(Ordering::SeqCst) {
        return Err("dashboard_disabled".into());
    }
    let ticket = b.claim(
        Owner {
            agent: "web".into(),
            origin: "dashboard".into(),
            session: random(),
            job: "Pair secure ADB".into(),
            allow_sleep: false,
        },
        90,
    )?;
    let monitor = match s.try_clone() {
        Ok(value) => value,
        Err(_) => {
            b.release(&ticket)?;
            return Err("dashboard_monitor_failed".into());
        }
    };
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let bb = b.clone();
    let t = ticket.clone();
    thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        while !finished.load(Ordering::SeqCst) {
            let rc = unsafe { libc::poll(&mut poll, 1, 100) };
            if stopped.load(Ordering::SeqCst)
                || (rc > 0 && poll.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0)
            {
                let _ = bb.cancel(&t);
                break;
            }
        }
    });
    let mut bytes = p.code.into_bytes();
    bytes.push(b'\n');
    let result = (|| -> Res<Value> {
        // Pair output is deliberately discarded: implementations can echo input.
        let (code, _, _) = collect_input(
            b.clone(),
            &ticket,
            vec!["pair".into(), p.pair_port.to_string(), p.peer.to_string()],
            Some(bytes),
            30,
        )?;
        if code != 0 {
            return Err(if code == 124 { "pairing_timed_out: open a fresh pairing code and try again" } else if code == 130 { "pairing_cancelled: check device jobs for cleanup status" } else { "pairing_failed: code may be expired, wrong, or the VPN peer unavailable; open a fresh pairing code" }.into());
        }
        if let Some(port) = p.connect_port {
            // Never auto-trust a new fingerprint. Return the existing review flow.
            let connection = b.connect_device(&ticket, Some(port));
            return Ok(match connection {
                Ok(value) => {
                    json!({"paired":true,"connection":value,"message":"Paired. Check identity status before device work."})
                }
                Err(_) => {
                    json!({"paired":true,"message":"Paired. Connection still needs review; inspect the device identity and connection port."})
                }
            });
        }
        Ok(
            json!({"paired":true,"message":"Paired. The companion reports new connection ports automatically. Review the first device fingerprint before device work."}),
        )
    })();
    done.store(true, Ordering::SeqCst);
    let release = b.release(&ticket);
    let value = result?;
    release?;
    json_reply(s, 200, &value);
    Ok(())
}
fn action(
    s: &mut TcpStream,
    r: Arc<Registry>,
    a: ActionRequest,
    stopped: Arc<AtomicBool>,
) -> Res<()> {
    let spec = actions::find(&a.action)?;
    let args = actions::build(&a.action, &a.args, a.reviewed)?;
    let b = r.device(&a.device)?;
    if spec.class == "status" {
        json_reply(s, 200, &b.status());
        return Ok(());
    }
    if stopped.load(Ordering::SeqCst) {
        return Err("dashboard_disabled".into());
    }
    let owner = Owner {
        agent: "web".into(),
        origin: "dashboard".into(),
        session: random(),
        job: format!("{} on {}", a.action, a.device),
        allow_sleep: a.action == "allow-sleep",
    };
    let ticket = if spec.class == "view" {
        b.watch(owner, 90)?
    } else {
        b.claim(owner, 90)?
    };
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let bb = b.clone();
    let t = ticket.clone();
    let monitor = s.try_clone().map_err(|_| "dashboard_monitor_failed")?;
    thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        while !finished.load(Ordering::SeqCst) {
            let rc = unsafe { libc::poll(&mut poll, 1, 100) };
            if stopped.load(Ordering::SeqCst)
                || (rc > 0 && poll.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0)
            {
                let _ = bb.cancel(&t);
                break;
            }
        }
    });
    let result = (|| -> Res<(i32, Vec<u8>, Vec<u8>)> {
        if spec.class == "policy" {
            let on = a.action == "keep-awake";
            b.set_keepalive(&ticket, on, on)?;
            return Ok((0, serde_json::to_vec(&b.status()).unwrap(), Vec::new()));
        }
        if spec.class == "recipe" {
            for step in ["stop-app", "open-app"] {
                let result = collect(b.clone(), &ticket, actions::build(step, &a.args, true)?)?;
                if result.0 != 0 {
                    return Ok(result);
                }
            }
            return Ok((0, b"App restarted.".to_vec(), Vec::new()));
        }
        collect(b.clone(), &ticket, args)
    })();
    done.store(true, Ordering::SeqCst);
    let release = b.release(&ticket);
    let (code, out, err) = result?;
    if let Err(e) = release {
        return Err(format!("action_cleanup_needs_review: {e}"));
    }
    if code != 0 {
        return Err(format!(
            "action_failed ({code}): {}",
            String::from_utf8_lossy(&err)
        ));
    }
    if a.action == "screenshot" {
        if !out.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err("device_did_not_return_png".into());
        }
        response(s, 200, "image/png", &out)?;
    } else {
        json_reply(
            s,
            200,
            &json!({"code":code,"stdout":String::from_utf8_lossy(&out),"stderr":String::from_utf8_lossy(&err),"finished_at":now()}),
        );
    }
    Ok(())
}
fn handle(
    mut s: TcpStream,
    r: Arc<Registry>,
    secret: Arc<String>,
    port: u16,
    stop: Arc<AtomicBool>,
) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
    let result = (|| -> Res<()> {
        let req = crate::http::request(&mut s, 65536)?;
        let host = req.headers.get("host").map(String::as_str).unwrap_or("");
        if host != format!("127.0.0.1:{port}") && host != format!("localhost:{port}") {
            json_reply(&mut s, 403, &json!({"error":"invalid_dashboard_host"}));
            return Ok(());
        }
        if req.method == "GET" {
            let asset = match req.path.as_str() {
                "/" => Some((
                    "text/html; charset=utf-8",
                    include_str!("../web/index.html"),
                )),
                "/style.css" => Some(("text/css", include_str!("../web/style.css"))),
                "/app.js" => Some(("text/javascript", include_str!("../web/app.js"))),
                _ => None,
            };
            if let Some((kind, body)) = asset {
                return response(&mut s, 200, kind, body.as_bytes());
            }
        }
        if !authorized(&req.headers, &secret, port) {
            json_reply(
                &mut s,
                403,
                &json!({"error":"dashboard_key_or_origin_rejected"}),
            );
            return Ok(());
        }
        if stop.load(Ordering::SeqCst) {
            return Err("dashboard_disabled".into());
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/api/status") => json_reply(&mut s, 200, &r.status()),
            ("GET", "/api/config") => json_reply(&mut s, 200, &r.config().public_view()),
            ("GET", "/api/actions") => {
                json_reply(&mut s, 200, &json!({"actions":actions::catalog()}))
            }
            ("GET", "/api/history") => json_reply(&mut s, 200, &history(&r)?),
            ("POST", "/api/pair") => {
                let p: PairRequest =
                    serde_json::from_slice(&req.body).map_err(|_| "invalid_pair_request")?;
                pair(&mut s, r.clone(), p, stop.clone())?;
            }
            ("POST", "/api/action") => {
                let a: ActionRequest =
                    serde_json::from_slice(&req.body).map_err(|_| "invalid_action_request")?;
                action(&mut s, r.clone(), a, stop.clone())?;
            }
            ("POST", "/api/policy") => {
                let p: PolicyRequest =
                    serde_json::from_slice(&req.body).map_err(|_| "invalid_policy_request")?;
                let b = r.device(&p.device)?;
                let t = b.claim(
                    Owner {
                        agent: "web".into(),
                        origin: "dashboard".into(),
                        session: random(),
                        job: "Change keepalive".into(),
                        allow_sleep: !p.enabled,
                    },
                    90,
                )?;
                let result = b.set_keepalive(&t, p.enabled, p.prevent_lock);
                let release = b.release(&t);
                result?;
                release?;
                json_reply(&mut s, 200, &b.status());
            }
            _ => json_reply(&mut s, 404, &json!({"error":"dashboard_route_not_found"})),
        }
        Ok(())
    })();
    if let Err(e) = result {
        json_reply(&mut s, 409, &json!({"error":e}));
    }
}
fn serve(listener: TcpListener, r: Arc<Registry>, key: String, stop: Arc<AtomicBool>) -> Res<()> {
    let port = listener
        .local_addr()
        .map_err(|_| "dashboard_listener_failed")?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|_| "dashboard_listener_failed")?;
    let secret = Arc::new(key);
    let count = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        if let Ok((s, _)) = listener.accept() {
            if count.load(Ordering::SeqCst) < 8 {
                count.fetch_add(1, Ordering::SeqCst);
                let rr = r.clone();
                let key = secret.clone();
                let st = stop.clone();
                let c = count.clone();
                thread::spawn(move || {
                    handle(s, rr, key, port, st);
                    c.fetch_sub(1, Ordering::SeqCst);
                });
            } else {
                let mut s = s;
                json_reply(
                    &mut s,
                    503,
                    &json!({"error":"dashboard_busy: try again shortly"}),
                );
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}
