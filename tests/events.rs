use readb::{events::*, policy::random};
use std::{fs, os::unix::fs::PermissionsExt};
#[test]
fn history_is_bounded_private_and_has_no_command_arguments() {
    let root = std::env::temp_dir().join(format!("readb-events-{}", random()));
    fs::create_dir(&root).unwrap();
    for i in 0..5 {
        append(
            &root,
            &Event::new(
                "start",
                &format!("operation-{i}"),
                "input",
                "control",
                "queued",
            ),
        )
        .unwrap();
    }
    let h = read(&root, 2).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[1].operation, "operation-4");
    assert_eq!(
        fs::metadata(root.join("events.jsonl"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(read(&root, 1001).is_err());
}
