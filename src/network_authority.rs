//! Fixed, credential-checked root callback. No caller-selected authority paths.
use crate::{network_controller::NetworkController, policy::Res};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const DIRECTORY: &str = "/run/readb-network/authority";
const SOCKET: &str = "/run/readb-network/authority/control.sock";
const LIMIT: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(2);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema: u8,
    pub nonce: String,
    pub request_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReply {
    pub schema: u8,
    pub nonce: String,
    pub request_digest: String,
    pub allowed: bool,
}
pub trait Authority {
    fn check(&self, nonce: &str, digest: &str) -> Res<()>;
}
impl<F: Fn(&str, &str) -> Res<()>> Authority for F {
    fn check(&self, n: &str, d: &str) -> Res<()> {
        self(n, d)
    }
}
impl Authority for NetworkController {
    fn check(&self, n: &str, d: &str) -> Res<()> {
        self.authorize(n, d)
    }
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid(p: &Proof) -> Res<()> {
    if p.schema != 1 || !hash(&p.nonce) || !hash(&p.request_digest) {
        return Err("network_authority_invalid_proof".into());
    }
    Ok(())
}
pub(crate) fn peer_uid(s: &UnixStream) -> Res<u32> {
    let mut c = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            c.as_mut_ptr().cast(),
            &mut n,
        )
    } != 0
        || n as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err("network_authority_peer_unavailable".into());
    }
    Ok(unsafe { c.assume_init() }.uid)
}
// An absolute deadline also bounds slow, byte-at-a-time senders.
fn line(s: &mut UnixStream, deadline: Instant) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("network_authority_timeout")?;
        s.set_read_timeout(Some(remaining))
            .map_err(|_| "network_authority_timeout")?;
        let mut b = [0];
        s.read_exact(&mut b)
            .map_err(|_| "network_authority_missing_or_truncated")?;
        if b[0] == b'\n' {
            return Ok(out);
        }
        if out.len() == LIMIT {
            return Err("network_authority_oversize".into());
        }
        out.push(b[0]);
    }
}
fn write(s: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Res<()> {
    if bytes.len() > LIMIT {
        return Err("network_authority_oversize".into());
    }
    let mut framed = bytes.to_vec();
    framed.push(b'\n');
    let mut rest = framed.as_slice();
    while !rest.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or("network_authority_timeout")?;
        s.set_write_timeout(Some(remaining))
            .map_err(|_| "network_authority_timeout")?;
        let n = s
            .write(rest)
            .map_err(|_| "network_authority_write_failed")?;
        if n == 0 {
            return Err("network_authority_write_failed".into());
        }
        rest = &rest[n..];
    }
    Ok(())
}
pub fn handle(s: &mut UnixStream, allowed_uid: u32, authority: &impl Authority) -> Res<()> {
    // Never read untrusted data or disclose proofs to a different UID.
    if peer_uid(s)? != allowed_uid {
        return Err("network_authority_wrong_peer".into());
    }
    let deadline = Instant::now() + TIMEOUT;
    let p: Proof = serde_json::from_slice(&line(s, deadline)?)
        .map_err(|_| "network_authority_invalid_proof")?;
    valid(&p)?;
    let allowed = authority.check(&p.nonce, &p.request_digest).is_ok();
    let reply = ProofReply {
        schema: 1,
        nonce: p.nonce,
        request_digest: p.request_digest,
        allowed,
    };
    write(
        s,
        &serde_json::to_vec(&reply).map_err(|_| "network_authority_encoding_failed")?,
        deadline,
    )
}
pub fn exchange(s: &mut UnixStream, p: &Proof) -> Res<()> {
    valid(p)?;
    let deadline = Instant::now() + TIMEOUT;
    write(
        s,
        &serde_json::to_vec(p).map_err(|_| "network_authority_encoding_failed")?,
        deadline,
    )?;
    let r: ProofReply = serde_json::from_slice(&line(s, deadline)?)
        .map_err(|_| "network_authority_invalid_reply")?;
    if r.schema != 1 || r.nonce != p.nonce || r.request_digest != p.request_digest || !r.allowed {
        return Err("network_authority_denied_or_mismatched".into());
    }
    Ok(())
}
// Descriptor walk: no symlinks or writable root parents, even during replacement.
fn directory(uid: u32) -> Res<File> {
    let mut dir = File::open("/").map_err(|_| "network_authority_directory_unavailable")?;
    for (part, owner, mode) in [
        (c"run", 0, None),
        (c"readb-network", 0, Some(0o711)),
        (c"authority", uid, Some(0o711)),
    ] {
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                part.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("network_authority_directory_unavailable".into());
        }
        use std::os::fd::FromRawFd;
        dir = unsafe { File::from_raw_fd(fd) };
        let m = dir
            .metadata()
            .map_err(|_| "network_authority_directory_unavailable")?;
        if m.uid() != owner
            || m.mode() & 0o022 != 0
            || mode.is_some_and(|mode| m.mode() & 0o7777 != mode)
        {
            return Err("network_authority_directory_unsafe".into());
        }
    }
    Ok(dir)
}
pub(crate) fn prepare_directory(uid: u32) -> Res<()> {
    // Root helper holds its parent runtime lock before calling this.
    match fs::create_dir(DIRECTORY) {
        Ok(()) => {
            // chmod while still owned by root: the service has CHOWN, not FOWNER.
            fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o711))
                .map_err(|_| "network_authority_mode_failed")?;
            if unsafe { libc::chown(c"/run/readb-network/authority".as_ptr(), uid, u32::MAX) } != 0
            {
                return Err("network_authority_owner_failed".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err("network_authority_directory_unavailable".into()),
    }
    directory(uid).map(|_| ())
}
pub struct FixedAuthority {
    pub uid: u32,
}
impl Authority for FixedAuthority {
    fn check(&self, nonce: &str, digest: &str) -> Res<()> {
        let _dir = directory(self.uid)?;
        let m = fs::symlink_metadata(SOCKET).map_err(|_| "network_authority_unavailable")?;
        if !m.file_type().is_socket() || m.uid() != self.uid || m.mode() & 0o7777 != 0o602 {
            return Err("network_authority_socket_unsafe".into());
        }
        // Nonblocking connect is bounded; full listen queues cannot hang root.
        let mut stream = connect()?;
        if peer_uid(&stream)? != self.uid {
            return Err("network_authority_wrong_peer".into());
        }
        exchange(
            &mut stream,
            &Proof {
                schema: 1,
                nonce: nonce.into(),
                request_digest: digest.into(),
            },
        )
    }
}
fn connect() -> Res<UnixStream> {
    connect_to(SOCKET)
}
pub(crate) fn connect_control() -> Res<UnixStream> {
    connect_to("/run/readb-network/control.sock")
}
fn connect_to(path: &str) -> Res<UnixStream> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err("network_authority_connect_failed".into());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    for (dst, src) in addr
        .sun_path
        .iter_mut()
        .zip(path.as_bytes().iter().chain(std::iter::once(&0)))
    {
        *dst = *src as _;
    }
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&addr) as _,
        )
    };
    if rc != 0 {
        return Err("network_authority_unavailable".into());
    }
    stream
        .set_nonblocking(false)
        .map_err(|_| "network_authority_connect_failed")?;
    Ok(stream)
}
struct Bound {
    listener: UnixListener,
    _lock: File,
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Bound {
    fn bind() -> Res<Self> {
        let uid = unsafe { libc::geteuid() };
        let checked = directory(uid)?;
        let fd = unsafe {
            libc::openat(
                checked.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("network_authority_lock_unavailable".into());
        }
        use std::os::fd::FromRawFd;
        let lock = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("network_authority_busy".into());
        }
        if let Ok(m) = fs::symlink_metadata(SOCKET) {
            if !m.file_type().is_socket()
                || m.uid() != uid
                || m.mode() & 0o7777 != 0o602
                || connect().is_ok()
            {
                return Err("network_authority_socket_owned_or_unsafe".into());
            }
            fs::remove_file(SOCKET).map_err(|_| "network_authority_stale_cleanup_failed")?;
        }
        let listener = UnixListener::bind(SOCKET).map_err(|_| "network_authority_bind_failed")?;
        let m = fs::symlink_metadata(SOCKET).map_err(|_| "network_authority_socket_unavailable")?;
        let bound = Self {
            listener,
            _lock: lock,
            path: Path::new(SOCKET).into(),
            dev: m.dev(),
            ino: m.ino(),
        };
        fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o602))
            .map_err(|_| "network_authority_mode_failed")?;
        bound
            .listener
            .set_nonblocking(true)
            .map_err(|_| "network_authority_nonblocking_failed")?;
        Ok(bound)
    }
}
impl Drop for Bound {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.dev() == self.dev && m.ino() == self.ino)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub struct Server {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    pub fn start(authority: Arc<NetworkController>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let mut bound = None;
            let mut next = Instant::now();
            let mut workers: Vec<JoinHandle<()>> = Vec::new();
            let mut last_error = None;
            while !flag.load(Ordering::SeqCst) {
                if bound.is_none() && Instant::now() >= next {
                    match Bound::bind() {
                        Ok(b) => {
                            bound = Some(b);
                            last_error = None;
                        }
                        Err(e) => {
                            if last_error.as_ref() != Some(&e) {
                                eprintln!("readb network authority: {e}");
                                last_error = Some(e);
                            }
                        }
                    }
                    next = Instant::now() + Duration::from_secs(1);
                }
                let mut i = 0;
                while i < workers.len() {
                    if workers[i].is_finished() {
                        let _ = workers.swap_remove(i).join();
                    } else {
                        i += 1;
                    }
                }
                if let Some(b) = &bound {
                    match b.listener.accept() {
                        Ok((mut s, _)) => {
                            if workers.len() < 4 {
                                let a = authority.clone();
                                workers.push(thread::spawn(move || {
                                    let _ = handle(&mut s, 0, a.as_ref());
                                }));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                        Err(_) => {
                            bound = None;
                        }
                    }
                }
                thread::sleep(Duration::from_millis(25));
            }
            for worker in workers {
                let _ = worker.join();
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.worker.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    #[test]
    fn restricted_root_callback_in_isolated_namespace() {
        if std::env::var("READB_AUTHORITY_NS").as_deref() != Ok("1") {
            return;
        }
        if std::env::var("READB_AUTHORITY_CHILD").as_deref() == Ok("1") {
            assert_eq!(unsafe { libc::geteuid() }, 1000);
            for _ in 0..200 {
                if directory(1000).is_ok() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let b = Bound::bind().unwrap();
            assert!(
                Bound::bind().is_err(),
                "second coordinator must not replace socket"
            );
            for _ in 0..400 {
                match b.listener.accept() {
                    Ok((mut s, _)) => {
                        handle(&mut s, 0, &|n: &str, d: &str| {
                            if n == "a".repeat(64) && d == "b".repeat(64) {
                                Ok(())
                            } else {
                                Err("mismatch".into())
                            }
                        })
                        .unwrap();
                        drop(b);
                        assert!(!Path::new(SOCKET).exists());
                        let b = Bound::bind().unwrap();
                        let saved = Path::new(DIRECTORY).join("saved.sock");
                        fs::rename(SOCKET, &saved).unwrap();
                        let replacement = UnixListener::bind(SOCKET).unwrap();
                        fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o602)).unwrap();
                        drop(b);
                        assert!(
                            Path::new(SOCKET).exists(),
                            "shutdown removed a replacement socket"
                        );
                        drop(replacement);
                        let b = Bound::bind().unwrap(); // exact owned stale socket is recoverable
                        drop(b);
                        fs::remove_file(saved).unwrap();
                        assert!(!Path::new(SOCKET).exists());
                        return;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(25))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            panic!("root callback not received");
        }
        assert_ne!(
            fs::read_link("/proc/self/ns/mnt").unwrap(),
            fs::read_link("/proc/1/ns/mnt").unwrap(),
            "refuse host mount namespace"
        );
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap(),
            fs::read_link("/proc/1/ns/net").unwrap(),
            "refuse host network namespace"
        );
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            directory(1000).is_err(),
            "authority must not preexist in fresh private mount"
        );
        // These mutations are confined to the fresh private tmpfs.
        fs::set_permissions("/run/readb-network", fs::Permissions::from_mode(0o777)).unwrap();
        assert!(directory(1000).is_err());
        fs::set_permissions("/run/readb-network", fs::Permissions::from_mode(0o711)).unwrap();
        std::os::unix::fs::symlink("/run", DIRECTORY).unwrap();
        assert!(directory(1000).is_err());
        fs::remove_file(DIRECTORY).unwrap();
        fs::create_dir(DIRECTORY).unwrap();
        fs::set_permissions(DIRECTORY, fs::Permissions::from_mode(0o711)).unwrap();
        assert!(
            directory(1000).is_err(),
            "root-owned authority must not impersonate selected user"
        );
        fs::remove_dir(DIRECTORY).unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","network_authority::namespace_tests::restricted_root_callback_in_isolated_namespace","--nocapture"])
            .env("READB_AUTHORITY_CHILD","1");
        unsafe {
            command.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(1000) != 0
                    || libc::setuid(1000) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(command.spawn().unwrap());
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let data = [
            Data {
                effective: 0x1001,
                permitted: 0x1001,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) },
            0
        );
        let status = fs::read_to_string("/proc/thread-self/status").unwrap();
        assert!(status.lines().any(|l| l == "CapEff:\t0000000000001001"));
        prepare_directory(1000).unwrap();
        for _ in 0..200 {
            if fs::symlink_metadata(SOCKET).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(fs::symlink_metadata(SOCKET).unwrap().mode() & 0o7777, 0o602);
        FixedAuthority { uid: 1000 }
            .check(&"a".repeat(64), &"b".repeat(64))
            .unwrap();
        assert!(child.0.wait().unwrap().success());
    }
}
