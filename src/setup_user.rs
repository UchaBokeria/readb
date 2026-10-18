//! Selected-user installer execution. No service activation.
use crate::{
    policy::Res,
    runner::{self, Captured},
    setup_apply::Owner,
};
use std::{
    ffi::CString,
    fs::{File, Permissions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::Path,
    process::Command,
    time::Duration,
};
fn groups(owner: &Owner) -> Res<Vec<libc::gid_t>> {
    let name = CString::new(owner.name.as_str()).map_err(|_| "setup_user_name_invalid")?;
    let mut count = 16;
    loop {
        let mut groups = vec![0; count as usize];
        let mut needed = count;
        let result = unsafe {
            libc::getgrouplist(name.as_ptr(), owner.gid, groups.as_mut_ptr(), &mut needed)
        };
        if result >= 0 {
            groups.truncate(needed as usize);
            if groups.contains(&0) {
                return Err("setup_user_root_group_denied".into());
            }
            return Ok(groups);
        }
        if needed <= count || needed > 65536 {
            return Err("setup_user_groups_unavailable".into());
        }
        count = needed;
    }
}
fn run_image(owner: &Owner, args: &[String], extra: &[(&str, &str)]) -> Res<Captured> {
    let bytes =
        std::fs::read("/proc/self/exe").map_err(|_| "setup_user_executing_binary_unavailable")?;
    run_bytes(owner, args, extra, &bytes)
}
fn run_bytes(
    owner: &Owner,
    args: &[String],
    extra: &[(&str, &str)],
    bytes: &[u8],
) -> Res<Captured> {
    // Re-resolve immediately. A stale serialized owner cannot choose another UID/home.
    let current = Owner::resolve(&owner.name)?;
    if serde_json::to_vec(&current).map_err(|_| "setup_user_encoding_failed")?
        != serde_json::to_vec(owner).map_err(|_| "setup_user_encoding_failed")?
    {
        return Err("setup_user_identity_changed".into());
    }
    let root = unsafe { libc::geteuid() } == 0;
    if !root && (unsafe { libc::geteuid() } != owner.uid || unsafe { libc::getegid() } != owner.gid)
    {
        return Err("setup_user_root_or_same_identity_required".into());
    }
    let group_ids = groups(owner)?;
    let fd = unsafe {
        libc::memfd_create(
            c"readb-user-install".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err("setup_user_sealed_image_unavailable".into());
    }
    let mut image = unsafe { File::from_raw_fd(fd) };
    image
        .write_all(bytes)
        .map_err(|_| "setup_user_image_write_failed")?;
    image
        .set_permissions(Permissions::from_mode(0o555))
        .map_err(|_| "setup_user_image_permissions_failed")?;
    if unsafe {
        libc::fcntl(
            image.as_raw_fd(),
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
        )
    } < 0
    {
        return Err("setup_user_image_seal_failed".into());
    }
    let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
    command
        .args(args)
        .current_dir(&owner.home)
        .env_clear()
        .env("HOME", &owner.home)
        .env("USER", &owner.name)
        .env("LOGNAME", &owner.name)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8");
    let runtime = std::path::PathBuf::from(format!("/run/user/{}", owner.uid));
    if let Ok(m) = std::fs::symlink_metadata(&runtime)
        && m.is_dir()
        && m.uid() == owner.uid
        && m.mode() & 0o077 == 0
    {
        command.env("XDG_RUNTIME_DIR", &runtime).env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}/bus", runtime.display()),
        );
    }
    for (k, v) in extra {
        command.env(k, v);
    }
    let uid = owner.uid;
    let gid = owner.gid;
    // Only syscalls after fork. No NSS, allocation, shell or user code while root.
    unsafe {
        command.pre_exec(move || {
            if root
                && (libc::setgroups(group_ids.len(), group_ids.as_ptr()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            // Explicitly clear permitted/effective/inheritable and ambient
            // capabilities, even if an unusual root launcher retained them.
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
            let header = Header {
                version: 0x20080522,
                pid: 0,
            };
            let data = [
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &header as *const Header, data.as_ptr()) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // image stays alive until exec has opened it; CLOEXEC prevents an inherited
    // image descriptor. /proc/self/exe still pins the executed ELF after exec.
    runner::capture_cmd(command, Duration::from_secs(120), 1024 * 1024)
}
pub fn install_for(owner: &Owner, prefix: &Path) -> Res<serde_json::Value> {
    install_for_recover(owner, prefix, false)
}
pub(crate) fn install_for_recover(
    owner: &Owner,
    prefix: &Path,
    recover: bool,
) -> Res<serde_json::Value> {
    let bytes =
        std::fs::read("/proc/self/exe").map_err(|_| "setup_user_executing_binary_unavailable")?;
    install_image(owner, prefix, recover, &bytes)
}
pub(crate) fn install_image(
    owner: &Owner,
    prefix: &Path,
    recover: bool,
    bytes: &[u8],
) -> Res<serde_json::Value> {
    if !prefix.is_absolute() {
        return Err("setup_user_absolute_prefix_required".into());
    }
    let mut args = vec![
        "install".into(),
        "--server".into(),
        "--prefix".into(),
        prefix
            .to_str()
            .ok_or("setup_user_prefix_utf8_required")?
            .into(),
    ];
    if recover {
        args.push("--recover".into());
    }
    let result = run_bytes(owner, &args, &[], bytes).map_err(|e| {
        format!("setup_user_install_unconfirmed: {e}; inspect selected-user files before retry")
    })?;
    if !result.ok {
        return Err(format!(
            "setup_user_install_failed: {}",
            String::from_utf8_lossy(&result.err).trim()
        ));
    }
    let output: serde_json::Value =
        serde_json::from_slice(&result.out).map_err(|_| "setup_user_install_reply_invalid")?;
    if output.get("installed") != Some(&serde_json::Value::Bool(true))
        || output.get("server") != Some(&serde_json::Value::Bool(true))
    {
        return Err("setup_user_install_not_verified".into());
    }
    Ok(
        serde_json::json!({"user_files_installed":true,"owner":owner.name,"uid":owner.uid,"coordinator_active":false,"devices_accepted":false,"details":output}),
    )
}

pub(crate) fn value_for(owner: &Owner, args: &[String]) -> Res<serde_json::Value> {
    let r = run_image(owner, args, &[])?;
    if !r.ok {
        return Err(format!(
            "setup_selected_user_command_failed: exit={}; inspect the selected-user journal or unit before retry",
            r.code
        ));
    }
    serde_json::from_slice(&r.out).map_err(|_| "setup_selected_user_reply_invalid".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sealed_child_uses_selected_identity_and_executing_bytes() {
        if std::env::var_os("READB_TEST_CHILD").is_some() {
            let uid = std::env::var("READB_EXPECT_UID")
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let gid = std::env::var("READB_EXPECT_GID")
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert_ne!(uid, 0);
            assert_eq!(unsafe { libc::geteuid() }, uid);
            assert_eq!(unsafe { libc::getegid() }, gid);
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
                1
            );
            assert!(
                std::fs::read("/proc/self/exe")
                    .unwrap()
                    .starts_with(b"\x7fELF")
            );
            assert!(std::env::var_os("LD_PRELOAD").is_none());
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            for name in ["Uid:", "Gid:"] {
                let values = status
                    .lines()
                    .find_map(|l| l.strip_prefix(name))
                    .unwrap()
                    .split_whitespace()
                    .map(|s| s.parse::<u32>().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(values, vec![if name == "Uid:" { uid } else { gid }; 4]);
            }

            for name in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
                let value = status
                    .lines()
                    .find_map(|l| l.strip_prefix(name))
                    .unwrap()
                    .trim();
                assert_eq!(u64::from_str_radix(value, 16).unwrap(), 0);
            }

            println!("readb-user-probe-ok");
            return;
        }
        let name = if unsafe { libc::geteuid() } == 0 {
            std::env::var("READB_TEST_USER")
                .expect("root fixture needs explicit existing nonroot owner")
        } else {
            std::env::var("USER").unwrap()
        };
        let owner = crate::setup_apply::Owner::resolve(&name).unwrap();
        let result = super::run_image(
            &owner,
            &[
                "--exact".into(),
                "setup_user::tests::sealed_child_uses_selected_identity_and_executing_bytes".into(),
                "--nocapture".into(),
            ],
            &[
                ("READB_TEST_CHILD", "1"),
                ("READB_EXPECT_UID", &owner.uid.to_string()),
                ("READB_EXPECT_GID", &owner.gid.to_string()),
            ],
        )
        .unwrap();
        assert!(result.ok, "{}", String::from_utf8_lossy(&result.err));
        assert!(String::from_utf8_lossy(&result.out).contains("readb-user-probe-ok"));
    }
}
