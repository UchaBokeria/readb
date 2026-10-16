#[test]
fn skills_are_shared_concise_repeatable_and_preserve_custom_files() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let home =
        std::env::temp_dir().join(format!("readb-skills-{}", &readb::policy::random()[..12]));
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    for _ in 0..2 {
        let v = readb::skills::install(&home, "all").unwrap();
        assert_eq!(v["installed"].as_array().unwrap().len(), 4);
    }
    assert!(readb::skills::SOURCE.len() < 2700);
    assert_eq!(
        fs::read_to_string(home.join(".claude/skills/readb/SKILL.md")).unwrap(),
        readb::skills::SOURCE
    );
    let file = home.join(".codex/skills/readb/SKILL.md");
    fs::remove_file(&file).unwrap();
    fs::write(&file, b"owner custom skill").unwrap();
    assert!(readb::skills::install(&home, "codex").is_err());
    assert_eq!(fs::read(&file).unwrap(), b"owner custom skill");
}
