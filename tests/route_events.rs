use readb::route_events::RouteEvents;
use std::{
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
#[test]
fn subscription_is_observational_nonblocking_and_control_remains_readable() {
    let mut events = RouteEvents::new().unwrap();
    let started = Instant::now();
    let _ = events.drain().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    let (a, mut b) = UnixStream::pair().unwrap();
    use std::io::Write;
    b.write_all(b"x").unwrap();
    let (control, _) = events
        .wait(a.as_raw_fd(), Duration::from_millis(50))
        .unwrap();
    assert!(control);
}
