//! Own each isolated foreground ADB server. Never adopt or kill an external server.
use crate::{policy::Res, runner};
use std::{
    fs::OpenOptions,
    io::Read,
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::net::UnixStream,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
pub struct ManagedServer {
    child: Child,
    stopped: bool,
    listener: Option<TcpListener>,
}
pub fn client(adb: &Path, dir: &Path, port: u16) -> Command {
    let mut c = environment(adb, dir);
    c.args(["-H", "127.0.0.1", "-P", &port.to_string()]);
    c
}
fn environment(adb: &Path, dir: &Path) -> Command {
    let mut c = Command::new(adb);
    c.env("ADB_VENDOR_KEYS", dir.join(".android/adbkey"))
        .env("HOME", dir)
        .env("ANDROID_ADB_LOG_PATH", dir.join("adb.log"))
        .env_remove("ADB_SERVER_SOCKET")
        .env_remove("ANDROID_ADB_SERVER_PORT")
        .env_remove("ANDROID_ADB_SERVER_ADDRESS")
        .env("ADB_MDNS_AUTO_CONNECT", "")
        .env("ADB_USB", "0")
        .env("ADB_EMU", "0")
        .env_remove("ADB_TRACE")
        .env_remove("ANDROID_SERIAL");
    c
}
impl ManagedServer {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn start(adb: &Path, dir: &Path, port: u16) -> Res<Self> {
        if port < 1024 || !adb.is_absolute() {
            return Err("invalid_isolated_adb_server_configuration".into());
        }
        crate::registry::private_dir(dir)?;
        let address = (std::net::Ipv4Addr::LOCALHOST, port);
        let probe = TcpListener::bind(address)
            .map_err(|_| "adb_server_port_busy: refusing to adopt an existing server")?;

        let log = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(dir.join("server.log"))
            .map_err(|_| "adb_server_log_unavailable")?;
        let m = log.metadata().map_err(|_| "adb_server_log_unavailable")?;
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            return Err("adb_server_log_requires_private_owned_file".into());
        }
        let err = log.try_clone().map_err(|_| "adb_server_log_unavailable")?;
        let (mut ack, child_ack) = UnixStream::pair().map_err(|_| "adb_ack_socket_failed")?;
        ack.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| "adb_ack_setup_failed")?;
        fn high_fd(fd: i32) -> Res<OwnedFd> {
            let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
            if n < 0 {
                return Err("adb_activation_fd_failed".into());
            }
            Ok(unsafe { OwnedFd::from_raw_fd(n) })
        }
        let listener = high_fd(probe.as_raw_fd())?;
        let reply = high_fd(child_ack.as_raw_fd())?;
        let listener_fd = listener.as_raw_fd();
        let reply_fd = reply.as_raw_fd();
        let mut command = environment(adb, dir);
        command
            .args(["-L", "acceptfd:3", "server", "nodaemon", "--reply-fd", "4"])
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err)
            .process_group(0);
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(listener_fd, 3) < 0 || libc::dup2(reply_fd, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::umask(0o077);
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| "adb_server_spawn_failed")?;
        drop(listener);
        drop(reply);
        drop(child_ack);
        let mut server = Self {
            child,
            stopped: false,
            listener: Some(probe),
        };
        let mut ready = [0u8; 3];
        ack.read_exact(&mut ready)
            .map_err(|_| "adb_server_readiness_ack_failed")?;
        if &ready != b"OK\n" {
            return Err("adb_server_readiness_ack_invalid".into());
        }
        let mut command = client(adb, dir, port);
        command.arg("devices");
        let result = runner::capture_cmd(command, Duration::from_secs(3), 16384)?;
        if !result.ok || !result.out.starts_with(b"List of devices attached") {
            return Err("adb_server_inventory_failed".into());
        }
        if !server.running()? {
            return Err("adb_server_exited_during_startup".into());
        }
        Ok(server)
    }
    pub fn stop(&mut self) -> Res<()> {
        if self.stopped {
            self.listener.take();
            return Ok(());
        }
        if self
            .child
            .try_wait()
            .map_err(|_| "adb_server_wait_failed")?
            .is_some()
        {
            self.stopped = true;
            self.listener.take();
            return Ok(());
        }
        if runner::kill_wait(&mut self.child) {
            self.stopped = true;
            self.listener.take();
            Ok(())
        } else {
            Err("adb_server_cleanup_unknown".into())
        }
    }
    pub fn running(&mut self) -> Res<bool> {
        if self.stopped {
            return Ok(false);
        }
        if self
            .child
            .try_wait()
            .map_err(|_| "adb_server_wait_failed")?
            .is_some()
        {
            self.stopped = true;
            return Ok(false);
        }
        Ok(true)
    }
}
impl Drop for ManagedServer {
    fn drop(&mut self) {
        if self.stop().is_err() {
            eprintln!("readb: adb_server_cleanup_unknown; inspect the owned process before retry");
        }
    }
}
