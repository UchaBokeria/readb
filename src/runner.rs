use crate::policy::Res;
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
pub struct Captured {
    pub ok: bool,
    pub code: i32,
    pub out: Vec<u8>,
    pub err: Vec<u8>,
}
pub fn kill_wait(child: &mut Child) -> bool {
    // Only the process group created for this invocation. Never kill a generic adb daemon.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}
fn reader(mut pipe: impl Read + Send + 'static, limit: usize) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut b = Vec::new();
        let _ = pipe.by_ref().take(limit as u64 + 1).read_to_end(&mut b);
        let _ = tx.send(b);
    });
    rx
}
pub fn capture(program: &str, args: &[String], timeout: Duration, limit: usize) -> Res<Captured> {
    let mut c = Command::new(program);
    c.args(args);
    capture_cmd(c, timeout, limit)
}
pub fn capture_cmd(mut command: Command, timeout: Duration, limit: usize) -> Res<Captured> {
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("command_spawn_failed: errno={:?}", e.raw_os_error()))?;
    capture_child(child, timeout, limit)
}
/// Linux's empty pipe admits at most PIPE_BUF bytes without waiting for a reader.
/// Keep secrets out of argv and close stdin before bounded output collection.
pub fn capture_cmd_input(
    mut command: Command,
    input: &[u8],
    timeout: Duration,
    limit: usize,
) -> Res<Captured> {
    if input.len() > 4096 {
        return Err("command_private_input_too_large".into());
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("command_spawn_failed: errno={:?}", e.raw_os_error()))?;
    let write = child.stdin.take().unwrap().write_all(input);
    if write.is_err() {
        return Err(if kill_wait(&mut child) {
            "command_private_input_failed"
        } else {
            "local_cleanup_unknown"
        }
        .into());
    }
    capture_child(child, timeout, limit)
}
fn capture_child(mut child: Child, timeout: Duration, limit: usize) -> Res<Captured> {
    let out = reader(child.stdout.take().unwrap(), limit);
    let err = reader(child.stderr.take().unwrap(), limit);
    let started = Instant::now();
    let mut bo = None;
    let mut be = None;
    let status = loop {
        if bo.is_none() {
            bo = out.try_recv().ok();
        }
        if be.is_none() {
            be = err.try_recv().ok();
        }
        if bo.as_ref().is_some_and(|b| b.len() > limit)
            || be.as_ref().is_some_and(|b| b.len() > limit)
        {
            kill_wait(&mut child);
            return Err("output_overflow".into());
        }
        if let Some(status) = child.try_wait().map_err(|_| "command_wait_failed")? {
            break status;
        }
        if started.elapsed() >= timeout {
            let gone = kill_wait(&mut child);
            return Err(if gone {
                "command_timeout"
            } else {
                "local_cleanup_unknown"
            }
            .into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    let out = bo
        .or_else(|| out.recv_timeout(Duration::from_millis(250)).ok())
        .ok_or("output_pipe_cleanup_unknown")?;
    let err = be
        .or_else(|| err.recv_timeout(Duration::from_millis(250)).ok())
        .ok_or("error_pipe_cleanup_unknown")?;
    if out.len() > limit || err.len() > limit {
        return Err("output_overflow".into());
    }
    Ok(Captured {
        ok: status.success(),
        code: status.code().unwrap_or(128),
        out,
        err,
    })
}
