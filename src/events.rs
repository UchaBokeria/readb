use crate::policy::Res;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub schema: u32,
    pub epoch: f64,
    pub kind: String,
    pub operation: String,
    pub command: String,
    pub role: String,
    pub outcome: String,
}
impl Event {
    pub fn new(kind: &str, operation: &str, command: &str, role: &str, outcome: &str) -> Self {
        Self {
            schema: 1,
            epoch: crate::backend::now(),
            kind: kind.into(),
            operation: operation.into(),
            command: command.into(),
            role: role.into(),
            outcome: outcome.into(),
        }
    }
}
pub fn append(dir: &Path, event: &Event) -> Res<()> {
    let path = dir.join("events.jsonl");
    if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("history_symlink_forbidden".into());
    }
    if fs::metadata(&path).is_ok_and(|m| m.len() > 4 * 1024 * 1024) {
        let old = dir.join("events.1.jsonl");
        if old.exists() {
            fs::remove_file(&old).map_err(|_| "history_rotate_failed")?
        }
        fs::rename(&path, old).map_err(|_| "history_rotate_failed")?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "history_open_failed")?;
    let meta = f.metadata().map_err(|_| "history_metadata_failed")?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err("history_permissions_invalid".into());
    }
    let mut line = serde_json::to_vec(event).map_err(|_| "history_serialize_failed")?;
    line.push(b'\n');
    f.write_all(&line)
        .and_then(|_| f.sync_data())
        .map_err(|_| "history_write_failed".into())
}
pub fn read(dir: &Path, limit: usize) -> Res<Vec<Event>> {
    if limit > 1000 {
        return Err("history_limit_maximum_1000".into());
    }
    let path = dir.join("events.jsonl");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "history_unavailable")?;
    let m = f.metadata().map_err(|_| "history_metadata_failed")?;
    if !m.is_file() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err("history_permissions_invalid".into());
    }
    let start = m.len().saturating_sub(256 * 1024);
    f.seek(SeekFrom::Start(start))
        .map_err(|_| "history_seek_failed")?;
    let mut b = Vec::new();
    f.take(256 * 1024)
        .read_to_end(&mut b)
        .map_err(|_| "history_read_failed")?;
    let mut lines = b.split(|c| *c == b'\n');
    if start > 0 {
        lines.next();
    }
    let mut events: Vec<Event> = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_slice::<Event>(l).ok())
        .filter(|e| e.schema == 1)
        .collect();
    if events.len() > limit {
        events.drain(..events.len() - limit);
    }
    Ok(events)
}
