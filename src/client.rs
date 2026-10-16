use crate::{backend::atomic, control::Request, policy::Res, registry::private_dir, wire::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub ssh: Option<String>,
    #[serde(default = "default_binary")]
    pub binary: String,
    pub state: PathBuf,
}
fn default_binary() -> String {
    "~/.local/bin/readb".into()
}
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Contexts {
    pub current: Option<String>,
    pub contexts: BTreeMap<String, Context>,
}
pub fn config_dir() -> Res<PathBuf> {
    if let Some(p) = std::env::var_os("READB_CONFIG_DIR") {
        return Ok(p.into());
    }
    Ok(PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?).join(".config/readb"))
}
pub fn state_dir() -> Res<PathBuf> {
    if let Some(p) = std::env::var_os("READB_STATE_DIR") {
        return Ok(p.into());
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME_unavailable")?)
            .join(".local/share/readb"),
    )
}
pub fn contexts() -> Res<Contexts> {
    let p = config_dir()?.join("contexts.json");
    if !p.exists() {
        return Ok(Contexts::default());
    }
    let b = fs::read(p).map_err(|_| "context_configuration_unavailable")?;
    if b.len() > 65536 {
        return Err("context_configuration_too_large".into());
    }
    serde_json::from_slice(&b).map_err(|_| "invalid_context_configuration".into())
}
pub fn save(c: &Contexts) -> Res<()> {
    let dir = config_dir()?;
    private_dir(&dir)?;
    atomic(&dir.join("contexts.json"), c)
}
pub fn select(name: Option<&str>, local: bool) -> Res<Context> {
    if local {
        return Ok(Context {
            ssh: None,
            binary: default_binary(),
            state: state_dir()?,
        });
    }
    let c = contexts()?;
    let key=name.or(c.current.as_deref()).ok_or("no_context: run readb context add NAME --ssh HOST --state SERVER_STATE; or use --local only on the server")?;
    c.contexts
        .get(key)
        .cloned()
        .ok_or_else(|| format!("unknown_context: {key}; run readb context ls"))
}
fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\"'\"'"))
}
fn remote_binary(v: &str) -> Res<String> {
    if v.is_empty() || v.chars().any(char::is_control) {
        return Err("invalid_remote_binary".into());
    }
    Ok(if let Some(rest) = v.strip_prefix("~/") {
        format!("\"$HOME\"/{}", quote(rest))
    } else {
        quote(v)
    })
}
struct Transport {
    read: Box<dyn Read>,
    write: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Option<Child>,
}
fn connect(c: &Context, streaming: bool) -> Res<Transport> {
    if let Some(host) = &c.ssh {
        if host.is_empty()
            || host.starts_with('-')
            || host.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err("invalid_ssh_host".into());
        }
        let command = format!(
            "exec {} --local --state-dir {} rpc",
            remote_binary(&c.binary)?,
            quote(c.state.to_str().ok_or("invalid_state_path")?)
        );
        let mut child = Command::new("ssh")
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=3",
                "--",
                host,
                &command,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "ssh_start_failed")?;
        Ok(Transport {
            read: Box::new(child.stdout.take().unwrap()),
            write: Arc::new(Mutex::new(Box::new(child.stdin.take().unwrap()))),
            child: Some(child),
        })
    } else {
        let s = UnixStream::connect(c.state.join("control.sock")).map_err(
            |_| "coordinator_unavailable: inspect readb service status; no direct device fallback",
        )?;
        s.set_read_timeout(if streaming {
            None
        } else {
            Some(Duration::from_secs(40))
        })
        .map_err(|_| "socket_setup_failed")?;
        Ok(Transport {
            read: Box::new(s.try_clone().map_err(|_| "socket_clone_failed")?),
            write: Arc::new(Mutex::new(Box::new(s))),
            child: None,
        })
    }
}
pub fn call(c: &Context, r: &Request, streaming: bool) -> Res<(i32, Vec<u8>)> {
    call_with_input(c, r, streaming, None)
}
pub fn call_with_input(
    c: &Context,
    r: &Request,
    streaming: bool,
    input: Option<Vec<u8>>,
) -> Res<(i32, Vec<u8>)> {
    let mut t = connect(c, streaming)?;
    writeln!(
        *t.write.lock().unwrap(),
        "{}",
        serde_json::to_string(r).map_err(|_| "request_serialize_failed")?
    )
    .map_err(|_| "connection_closed")?;
    if let Some(input) = input {
        let mut writer = t.write.lock().unwrap();
        frame(&mut *writer, 0, &input)
            .and_then(|_| frame(&mut *writer, 4, b""))
            .map_err(|_| "connection_closed")?;
    } else if streaming {
        let writer = t.write.clone();
        thread::spawn(move || {
            let mut input = std::io::stdin().lock();
            let mut b = [0; 16384];
            loop {
                match input.read(&mut b) {
                    Ok(0) => {
                        let _ = frame(&mut *writer.lock().unwrap(), 4, b"");
                        break;
                    }
                    Ok(n) => {
                        if frame(&mut *writer.lock().unwrap(), 0, &b[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
    let mut data = Vec::new();
    let result = loop {
        let (tag, b) = read_frame(&mut t.read).map_err(
            |_| "coordinator_stream_closed: inspect job before retry; no direct ADB fallback",
        )?;
        match tag {
            1 => {
                if streaming {
                    std::io::stdout()
                        .write_all(&b)
                        .and_then(|_| std::io::stdout().flush())
                        .map_err(|_| "stdout_closed")?
                } else {
                    if data.len() + b.len() > 8 * 1024 * 1024 {
                        return Err("control_reply_too_large".into());
                    }
                    data.extend(b)
                }
            }
            2 => std::io::stderr()
                .write_all(&b)
                .and_then(|_| std::io::stderr().write_all(b"\n"))
                .map_err(|_| "stderr_closed")?,
            3 => {
                let v: Value = serde_json::from_slice(&b).map_err(|_| "invalid_exit_frame")?;
                let code = v["code"]
                    .as_i64()
                    .filter(|c| (0..=255).contains(c))
                    .ok_or("invalid_exit_frame")? as i32;
                break (code, data);
            }
            _ => return Err("unexpected_control_frame".into()),
        }
    };
    drop(t.write);
    if let Some(mut child) = t.child {
        let status = child.wait().map_err(|_| "ssh_wait_failed")?;
        if !status.success() && result.0 == 0 {
            return Err("remote_rpc_failed".into());
        }
    }
    Ok(result)
}
pub fn rpc(root: &Path) -> Res<()> {
    let s =
        UnixStream::connect(root.join("control.sock")).map_err(|_| "coordinator_unavailable")?;
    let mut input = s.try_clone().map_err(|_| "socket_clone_failed")?;
    thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut input);
        let _ = input.shutdown(std::net::Shutdown::Write);
    });
    let mut output = s.try_clone().map_err(|_| "socket_clone_failed")?;
    let result = std::io::copy(&mut output, &mut std::io::stdout().lock())
        .map_err(|_| "rpc_output_closed".into());
    let _ = s.shutdown(std::net::Shutdown::Both);
    result.map(|_| ())
}
pub fn request(action: &str, device: Option<&str>) -> Request {
    Request {
        version: 1,
        device: device.unwrap_or("").into(),
        observe: false,
        action: action.into(),
        evidence: None,
        ticket: String::new(),
        owner: None,
        ttl: 90,
        timeout: 600,
        args: Vec::new(),
    }
}
pub fn read_ticket(path: &Path) -> Res<String> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "private_ticket_unavailable")?;
    let m = f.metadata().map_err(|_| "ticket_metadata_unavailable")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() > 4096
    {
        return Err("private_ticket_permissions_invalid".into());
    }
    let mut b = Vec::new();
    f.read_to_end(&mut b).map_err(|_| "ticket_read_failed")?;
    let v: Value = serde_json::from_slice(&b).map_err(|_| "invalid_ticket")?;
    v["token"]
        .as_str()
        .map(str::to_string)
        .ok_or("invalid_ticket".into())
}
pub fn store_ticket(v: &mut Value, device: &str) -> Res<PathBuf> {
    let config = config_dir()?;
    private_dir(&config)?;
    let dir = config.join("tickets");
    private_dir(&dir)?;
    let p = dir.join(format!("job-{}.json", crate::policy::random()));
    atomic(&p, &json!({"token":v["token"],"device":device}))?;
    v.as_object_mut()
        .ok_or("invalid_claim_reply")?
        .remove("token");
    v["ticket_path"] = json!(p);
    Ok(p)
}
