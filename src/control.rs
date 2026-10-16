use crate::{backend::Backend, policy::*, runner::kill_wait, wire::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default = "version")]
    pub version: u32,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub observe: bool,
    pub action: String,
    #[serde(default)]
    pub evidence: Option<Evidence>,
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub owner: Option<Owner>,
    #[serde(default = "ttl")]
    pub ttl: u64,
    #[serde(default = "timeout")]
    pub timeout: u64,
    #[serde(default)]
    pub args: Vec<String>,
}
fn version() -> u32 {
    1
}
fn ttl() -> u64 {
    90
}
fn timeout() -> u64 {
    600
}
impl Request {
    pub fn parse(b: &[u8]) -> Res<Self> {
        if b.len() > 65536 {
            return Err("control_request_too_large".into());
        }
        let r: Self = serde_json::from_slice(b).map_err(|_| "invalid_control_request")?;
        if r.version != 1 {
            return Err("unsupported_protocol_version".into());
        }
        if !(1..=3600).contains(&r.timeout)
            || r.args.len() > 1024
            || r.args.iter().any(|a| a.len() > 8192)
        {
            return Err("invalid_command_limits".into());
        }
        Ok(r)
    }
}
fn result(s: &mut UnixStream, value: &Value, code: i32) {
    let b = serde_json::to_vec(value).unwrap();
    if message(s, if code == 0 { 1 } else { 2 }, &b).is_err() {
        return;
    }
    let _ = frame(s, 3, &serde_json::to_vec(&json!({"code":code})).unwrap());
}
pub fn handle(mut stream: UnixStream, backend: Arc<Backend>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let request = line(&mut stream, 65536)
        .map_err(|_| "invalid_control_header".to_string())
        .and_then(|b| Request::parse(&b));
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            result(&mut stream, &json!({"error":e}), 78);
            return;
        }
    };
    handle_request(stream, backend, request);
}
pub fn handle_request(mut stream: UnixStream, backend: Arc<Backend>, request: Request) {
    if request.action == "exec" {
        execute(stream, backend, request);
        return;
    }
    let reply: Res<Value> = match request.action.as_str() {
        "status" => Ok(backend.status()),
        "connect" => {
            let port = match request.args.as_slice() {
                [] => Ok(None),
                [p] => p
                    .parse::<u16>()
                    .map(Some)
                    .map_err(|_| "invalid_connect_port".into()),
                _ => Err("invalid_connect_arguments".to_string()),
            };
            port.and_then(|p| backend.connect_device(&request.ticket, p))
        }
        "disconnect" => backend
            .disconnect_device(&request.ticket)
            .map(|_| backend.status()),
        "keepalive" => {
            let enabled = match request.args.as_slice() {
                [one] if one == "on" => Ok(true),
                [one] if one == "off" => Ok(false),
                _ => Err("keepalive_requires_on_or_off".to_string()),
            };
            enabled.and_then(|on| {
                backend
                    .set_keepalive(&request.ticket, on, on)
                    .map(|_| backend.status())
            })
        }
        "reconcile" => request
            .evidence
            .ok_or("explicit_evidence_required".into())
            .and_then(|e| backend.reconcile(&e).map(|_| json!({"reconciled":true}))),
        "claim" => request
            .owner
            .ok_or("owner_metadata_required".into())
            .and_then(|o| {
                (if request.observe {
                    backend.watch(o, request.ttl)
                } else {
                    backend.claim(o, request.ttl)
                })
                .map(|t| json!({"token":t,"job":backend.status()["job"]}))
            }),
        "heartbeat" => backend
            .heartbeat(&request.ticket)
            .map(|_| json!({"renewed":true})),
        "release" => backend
            .release(&request.ticket)
            .map(|_| json!({"released":true})),
        "cancel" => backend
            .cancel(&request.ticket)
            .map(|_| json!({"cancel_requested":true})),
        _ => Err("unsupported_control_action".into()),
    };
    match reply {
        Ok(v) => result(&mut stream, &v, 0),
        Err(e) => result(
            &mut stream,
            &json!({"error":e,"state":backend.status()}),
            73,
        ),
    }
}
fn output(
    mut input: impl Read + Send + 'static,
    tag: u8,
    stream: Arc<Mutex<UnixStream>>,
    lost: Arc<AtomicBool>,
) -> mpsc::Receiver<bool> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut b = [0; 16384];
        let ok = loop {
            match input.read(&mut b) {
                Ok(0) => break true,
                Ok(n) => {
                    if frame(&mut *stream.lock().unwrap(), tag, &b[..n]).is_err() {
                        lost.store(true, Ordering::SeqCst);
                        break false;
                    }
                }
                Err(_) => break false,
            }
        };
        let _ = tx.send(ok);
    });
    rx
}
fn execute(mut stream: UnixStream, b: Arc<Backend>, r: Request) {
    let mut prepared = match b.prepare(&r.ticket, r.args) {
        Ok(p) => p,
        Err(e) => {
            result(&mut stream, &json!({"error":e,"state":b.status()}), 73);
            return;
        }
    };
    let mut child = match b.spawn(&r.ticket, &mut prepared) {
        Ok(c) => c,
        Err(_) => {
            b.complete_result(&r.ticket, false, "spawn-failed");
            result(&mut stream, &json!({"error":"command_spawn_failed"}), 74);
            return;
        }
    };
    let _ = stream.set_read_timeout(None);
    let lost = Arc::new(AtomicBool::new(false));
    // Detect peer disappearance independently of a blocked child stdin pipe.
    let monitor = stream.try_clone().unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let done = finished.clone();
    let disconnected = lost.clone();
    thread::spawn(move || {
        let mut p = libc::pollfd {
            fd: monitor.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        while !done.load(Ordering::SeqCst) {
            let rc = unsafe { libc::poll(&mut p, 1, 100) };
            if rc > 0
                && p.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                    != 0
            {
                disconnected.store(true, Ordering::SeqCst);
                break;
            }
        }
    });
    let writer = Arc::new(Mutex::new(stream.try_clone().unwrap()));
    let out = output(
        child.stdout.take().unwrap(),
        1,
        writer.clone(),
        lost.clone(),
    );
    let err = output(
        child.stderr.take().unwrap(),
        2,
        writer.clone(),
        lost.clone(),
    );
    let mut stdin = child.stdin.take();
    let mut incoming = stream.try_clone().unwrap();
    let lost_in = lost.clone();
    thread::spawn(move || {
        loop {
            match read_frame(&mut incoming) {
                Ok((4, data)) if data.is_empty() => {
                    drop(stdin.take());
                }
                Ok((0, data)) => {
                    if let Some(input) = stdin.as_mut() {
                        if input.write_all(&data).is_err() {
                            break;
                        }
                    } else {
                        lost_in.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                _ => {
                    lost_in.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });
    let start = Instant::now();
    let mut reason = None;
    let mut local_unknown = false;
    let mut reaped = false;
    let exit = loop {
        if lost.load(Ordering::SeqCst) {
            reason = Some("client_disconnected");
            break 130;
        }
        if start.elapsed() >= Duration::from_secs(r.timeout) {
            reason = Some("command_timeout");
            break 124;
        }
        if !b.running(&r.ticket, prepared.generation) {
            reason = Some("job_expired_cancelled_or_transport_changed");
            break 74;
        }
        match child.try_wait() {
            Ok(Some(s)) => {
                reaped = true;
                break s.code().unwrap_or(128);
            }
            Ok(None) => {}
            Err(_) => {
                reason = Some("command_wait_failed");
                break 74;
            }
        }
        thread::sleep(Duration::from_millis(50));
    };
    if reason.is_some() {
        reaped = kill_wait(&mut child);
        local_unknown = !reaped;
    }
    // A local exit does not prove the device-side operation or inherited pipes ended.
    let drain = Instant::now();
    let mut out_ok = None;
    let mut err_ok = None;
    while drain.elapsed() < Duration::from_secs(30) {
        if out_ok.is_none() {
            out_ok = out.try_recv().ok();
        }
        if err_ok.is_none() {
            err_ok = err.try_recv().ok();
        }
        if out_ok.is_some() && err_ok.is_some() {
            break;
        }
        if lost.load(Ordering::SeqCst) {
            break;
        }
        let _ = b.running(&r.ticket, prepared.generation);
        thread::sleep(Duration::from_millis(20));
    }
    if out_ok.is_none() || err_ok.is_none() {
        reason = Some("output_or_local_cleanup_unknown");
        local_unknown = true;
        // A reaped PID/process-group may already have been reused.
        if !reaped {
            let _ = kill_wait(&mut child);
        }
    } else if out_ok == Some(false) || err_ok == Some(false) {
        reason = Some("output_stream_closed");
    }
    if local_unknown {
        let mut s = b.state.lock().unwrap();
        s.gate.cleanup_unknown = Some("local process/output cleanup unproved".into());
    }
    b.complete_result(
        &r.ticket,
        reason.is_some() || (exit != 0 && !prepared.pure),
        reason.unwrap_or(if exit == 0 { "finished" } else { "failed" }),
    );
    let mut w = writer.lock().unwrap();
    if let Some(reason) = reason {
        let _ = frame(
            &mut *w,
            2,
            &serde_json::to_vec(&json!({"error":reason,"state":b.status()})).unwrap(),
        );
    }
    let _ = frame(
        &mut *w,
        3,
        &serde_json::to_vec(
            &json!({"code":if reason.is_some(){if exit==0{74}else{exit}}else{exit}}),
        )
        .unwrap(),
    );
    finished.store(true, Ordering::SeqCst);
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
