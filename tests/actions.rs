use readb::actions::*;
#[test]
fn all_view_actions_use_positive_read_profiles() {
    for a in catalog() {
        if a.class == "view" {
            let args = build(a.id, &[], false).unwrap();
            assert!(readb::backend::is_pure(&args), "{}", a.id);
        }
    }
}
#[test]
fn risky_actions_and_injection_are_checked_before_dispatch() {
    assert!(build("clear-app-data", &["org.example.app".into()], false).is_err());
    assert!(build("open-app", &["org.example.app;reboot".into()], false).is_err());
    assert!(build("open-url", &["javascript:alert(1)".into()], false).is_err());
    assert!(build("tap", &["10".into(), "-10".into()], false).is_err());
    assert!(build("type", &["oops\nreboot".into()], false).is_err());
    assert_eq!(
        build("home", &[], false).unwrap(),
        ["shell", "input", "keyevent", "KEYCODE_HOME"]
    );
}
