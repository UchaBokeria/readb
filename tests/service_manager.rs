use readb::service::manager_output;
use std::{
    ffi::OsStr,
    time::{Duration, Instant},
};
#[test]
fn hanging_manager_is_bounded_and_reports_uncertain_completion() {
    let start = Instant::now();
    let error = manager_output(
        OsStr::new("/bin/sh"),
        &["-c", "sleep 5"],
        Duration::from_millis(50),
    )
    .err()
    .unwrap();
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(error.contains("service_manager_unconfirmed") && error.contains("verify"));
}
#[test]
fn large_manager_response_is_not_accepted_as_success() {
    let error = manager_output(
        OsStr::new("/bin/sh"),
        &["-c", "head -c 1048577 /dev/zero"],
        Duration::from_secs(2),
    )
    .err()
    .unwrap();
    assert!(error.contains("service_manager_unconfirmed"));
    let result = manager_output(
        OsStr::new("/bin/sh"),
        &["-c", "printf denied >&2; exit 7"],
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(!result.ok);
    assert_eq!(result.code, 7);
    assert_eq!(result.err, b"denied");
}
