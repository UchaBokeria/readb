use std::{
    process::Command,
    time::{Duration, Instant},
};
#[test]
fn private_stdin_is_bounded_and_not_an_argument() {
    let c = Command::new("/bin/cat");
    let r = readb::runner::capture_cmd_input(c, b"private input\n", Duration::from_secs(1), 100)
        .unwrap();
    assert!(r.ok);
    assert_eq!(r.out, b"private input\n");
    assert!(r.err.is_empty());
    let bad = readb::runner::capture_cmd_input(
        Command::new("/bin/false"),
        &[0; 4097],
        Duration::from_secs(1),
        100,
    )
    .err()
    .unwrap();
    assert_eq!(bad, "command_private_input_too_large");
}
#[test]
fn unread_private_stdin_does_not_bypass_command_deadline() {
    let mut c = Command::new("/bin/sleep");
    c.arg("5");
    let start = Instant::now();
    assert!(
        readb::runner::capture_cmd_input(c, &[0; 4096], Duration::from_millis(50), 100).is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}
