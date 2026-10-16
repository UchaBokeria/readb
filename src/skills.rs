use crate::{backend::atomic, policy::Res, registry::private_dir};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::symlink, path::Path};
pub const SOURCE: &str = include_str!("../skills/readb/SKILL.md");
pub fn install(home: &Path, tool: &str) -> Res<Value> {
    let tools: Vec<&str> = match tool {
        "all" => vec!["codex", "claude", "opencode", "hermes"],
        "codex" | "claude" | "opencode" | "hermes" => vec![tool],
        _ => return Err("unknown_skill_tool".into()),
    };
    let canonical = home.join(".config/readb/skills/readb");
    private_dir(&canonical)?;
    let file = canonical.join("SKILL.md");
    // Validate every destination before updating the shared source.
    let destinations: Vec<_> = tools
        .iter()
        .map(|tool| {
            home.join(match *tool {
                "codex" => ".codex/skills/readb/SKILL.md",
                "claude" => ".claude/skills/readb/SKILL.md",
                "opencode" => ".config/opencode/skills/readb/SKILL.md",
                _ => ".hermes/skills/devices/readb/SKILL.md",
            })
        })
        .collect();
    for dest in &destinations {
        if let Ok(m) = fs::symlink_metadata(dest)
            && (!m.file_type().is_symlink()
                || fs::read_link(dest).map_err(|_| "skill_link_unreadable")? != file)
        {
            return Err(format!(
                "existing_unmanaged_skill_preserved: {}",
                dest.display()
            ));
        }
    }
    if let Ok(m) = fs::symlink_metadata(&file) {
        if !m.is_file() {
            return Err("canonical_skill_not_regular_file".into());
        }
        let old = fs::read_to_string(&file).map_err(|_| "skill_unreadable")?;
        if old != SOURCE {
            if !old.contains("<!-- managed-by: readb -->") {
                return Err("unmanaged_canonical_skill_preserved".into());
            }
            atomic(
                &canonical.join(format!("backup-{}.json", crate::policy::random())),
                &json!({"text":old}),
            )?;
        }
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = canonical.join(format!("new-{}", crate::policy::random()));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| "skill_create_failed")?;
    out.write_all(SOURCE.as_bytes())
        .and_then(|_| out.sync_all())
        .map_err(|_| "skill_write_failed")?;
    fs::rename(temp, &file).map_err(|_| "skill_commit_failed")?;
    for dest in &destinations {
        if fs::symlink_metadata(dest).is_err() {
            fs::create_dir_all(dest.parent().unwrap())
                .map_err(|_| "skill_directory_unavailable")?;
            symlink(&file, dest).map_err(|_| "skill_link_failed")?;
        }
    }
    Ok(
        json!({"installed":tools,"source":file,"paths":destinations,"note":"Reload skill discovery in existing tools. Model, provider and approval configuration were not changed."}),
    )
}
