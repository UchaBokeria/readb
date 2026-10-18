//! Atomic private host output, never Android-delivery/readiness evidence.
use crate::policy::{Res, random};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path},
};
use subtle::ConstantTimeEq;
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub fingerprint: String,
    pub recovered: bool,
}
fn parent(path: &Path) -> Res<(File, std::ffi::CString)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("enrollment_output_absolute_path_required".into());
    }
    let name = std::ffi::CString::new(
        path.file_name()
            .ok_or("enrollment_output_filename_required")?
            .as_bytes(),
    )
    .map_err(|_| "enrollment_output_filename_invalid")?;
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|_| "enrollment_output_parent_unavailable")?;
    for component in path
        .parent()
        .ok_or("enrollment_output_parent_required")?
        .components()
    {
        if let Component::Normal(name) = component {
            let name = std::ffi::CString::new(name.as_bytes())
                .map_err(|_| "enrollment_output_parent_invalid")?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("enrollment_output_parent_unavailable".into());
            }
            dir = unsafe { File::from_raw_fd(fd) };
        }
        let m = dir
            .metadata()
            .map_err(|_| "enrollment_output_parent_unavailable")?;
        let uid = unsafe { libc::geteuid() };
        if (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o7022 != 0 {
            return Err("enrollment_output_parent_not_safe".into());
        }
    }
    if dir
        .metadata()
        .map_err(|_| "enrollment_output_parent_unavailable")?
        .uid()
        != unsafe { libc::geteuid() }
    {
        return Err("enrollment_output_owned_parent_required".into());
    }
    Ok((dir, name))
}
fn matches_existing(dir: &File, name: &std::ffi::CStr, bytes: &[u8]) -> Res<bool> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err("enrollment_output_existing_file_not_safe".into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let m = file
        .metadata()
        .map_err(|_| "enrollment_output_metadata_failed")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o7077 != 0
        || m.len() != bytes.len() as u64
    {
        return Err("enrollment_output_existing_file_mismatch_or_not_private".into());
    }
    let mut saved = Vec::new();
    (&mut file)
        .take(8193)
        .read_to_end(&mut saved)
        .map_err(|_| "enrollment_output_read_failed")?;
    let same = saved.len() == bytes.len() && bool::from(saved.as_slice().ct_eq(bytes));
    saved.fill(0);
    if !same {
        return Err(
            "enrollment_output_existing_file_mismatch: choose another private output path".into(),
        );
    }
    file.sync_all()
        .and_then(|_| dir.sync_all())
        .map_err(|_| "enrollment_output_durability_unconfirmed")?;
    Ok(true)
}
/// A receipt is returned only after exact private bytes and parent are synced.
/// Existing different/unsafe files are preserved; only exact private retry wins.
pub fn write_private(path: &Path, bytes: &[u8]) -> Res<Receipt> {
    write_sync(path, bytes, File::sync_all)
}
fn write_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl FnOnce(&File) -> std::io::Result<()>,
) -> Res<Receipt> {
    if bytes.len() > 8192 {
        return Err("enrollment_output_profile_too_large".into());
    }
    let profile: readb_protocol::Profile =
        serde_json::from_slice(bytes).map_err(|_| "enrollment_output_profile_invalid")?;
    profile.validate()?;
    let (dir, name) = parent(path)?;
    let receipt = |recovered| Receipt {
        fingerprint: Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        recovered,
    };
    if matches_existing(&dir, &name, bytes)? {
        return Ok(receipt(true));
    }
    let temp = std::ffi::CString::new(format!(".readb-profile-{}.tmp", random())).unwrap();
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err("enrollment_output_stage_create_failed".into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> Res<Receipt> {
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "enrollment_output_stage_sync_failed")?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
                && matches_existing(&dir, &name, bytes)?
            {
                return Ok(receipt(true));
            }
            return Err("enrollment_output_publication_refused: existing file preserved".into());
        }
        sync(&dir).map_err(|_| "enrollment_output_durability_unconfirmed")?;
        if !matches_existing(&dir, &name, bytes)? {
            return Err("enrollment_output_publication_unconfirmed".into());
        }
        Ok(receipt(false))
    })();
    unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    #[test]
    fn lost_postrename_sync_receipt_can_only_recover_the_exact_durable_private_file() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache")
            .join(format!("readb-output-sync-{}", random()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let bytes=serde_json::to_vec(&serde_json::json!({"schema":1,"device_id":"pixel-readb","server_peer":"10.99.0.2","server_port":19193,"device_address":"10.99.0.102","token":"1".repeat(64),"private_key":format!("{}AAA=","B".repeat(40)),"server_public_key":format!("{}AAA=","E".repeat(40)),"endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true})).unwrap();
        let path = root.join("profile.json");
        assert!(
            write_sync(&path, &bytes, |_| Err(std::io::Error::from_raw_os_error(
                libc::EIO
            )))
            .unwrap_err()
            .contains("durability_unconfirmed")
        );
        assert!(path.is_file());
        assert!(fs::read(&path).unwrap() == bytes);
        assert!(write_private(&path, &bytes).unwrap().recovered);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
}
