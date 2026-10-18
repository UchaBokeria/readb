use readb::enrollment_output::write_private;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::PathBuf,
};
fn dir() -> PathBuf {
    let p = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache")
        .join(format!("readb-output-test-{}", readb::policy::random()));
    fs::create_dir(&p).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    p
}
fn profile() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"schema":1,"device_id":"pixel-readb","server_peer":"10.99.0.2","server_port":19193,"device_address":"10.99.0.102","token":"1".repeat(64),"private_key":format!("{}AAA=","B".repeat(40)),"server_public_key":format!("{}AAA=","E".repeat(40)),"endpoint":"vpn.example.org:51820","keep_awake":true,"prevent_lock":true})).unwrap()
}
#[test]
fn atomic_private_output_is_recoverable_only_when_bytes_and_private_owner_match() {
    let p = dir();
    let out = p.join("profile.json");
    let bytes = profile();
    let r = write_private(&out, &bytes).unwrap();
    assert!(!r.recovered);
    assert_eq!(fs::metadata(&out).unwrap().mode() & 0o777, 0o600);
    assert!(fs::read(&out).unwrap() == bytes);
    assert!(write_private(&out, &bytes).unwrap().recovered);
    let mut different = bytes.clone();
    different.push(b' ');
    assert!(write_private(&out, &different).is_err());
    assert!(fs::read(&out).unwrap() == bytes);
    fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(write_private(&out, &bytes).is_err());
    fs::remove_dir_all(p).unwrap();
}
#[test]
fn private_writer_refuses_symlinks_links_writable_parents_and_invalid_profiles_without_overwrite() {
    for case in 0..5 {
        let p = dir();
        let out = p.join("profile.json");
        let other = p.join("preserve");
        fs::write(&other, b"preserve").unwrap();
        match case {
            0 => symlink(&other, &out).unwrap(),
            1 => fs::hard_link(&other, &out).unwrap(),
            2 => fs::set_permissions(&p, fs::Permissions::from_mode(0o777)).unwrap(),
            3 => {
                fs::write(&out, b"partial old output").unwrap();
                fs::set_permissions(&out, fs::Permissions::from_mode(0o600)).unwrap();
            }
            _ => {
                assert!(write_private(&out, b"{}").is_err());
                assert!(!out.exists());
                fs::remove_dir_all(p).unwrap();
                continue;
            }
        }
        assert!(write_private(&out, &profile()).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"preserve");
        fs::remove_dir_all(p).unwrap();
    }
    assert!(write_private("relative.json".as_ref(), &profile()).is_err());
    let p = dir();
    let alias = p.with_extension("link");
    symlink(&p, &alias).unwrap();
    assert!(write_private(&alias.join("profile.json"), &profile()).is_err());
    fs::remove_file(alias).unwrap();
    fs::remove_dir_all(p).unwrap();
}
