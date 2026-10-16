use readb::{runner::*, wire::*};
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
#[test]
fn command_bounded_and_binary() {
    let r = capture(
        "/bin/sh",
        &["-c".into(), "printf '\\000hi'".into()],
        Duration::from_secs(1),
        8,
    )
    .unwrap();
    assert!(r.ok);
    assert_eq!(r.out, b"\0hi");
    assert!(
        capture(
            "/bin/sh",
            &["-c".into(), "sleep 4".into()],
            Duration::from_millis(50),
            8
        )
        .is_err()
    );
}
#[test]
fn output_overflow_rejected() {
    assert!(
        capture(
            "/bin/sh",
            &["-c".into(), "printf 123456789".into()],
            Duration::from_secs(1),
            4
        )
        .is_err()
    );
}
#[test]
fn bounded_binary_frames() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    frame(&mut a, 1, b"\0\xff").unwrap();
    assert_eq!(read_frame(&mut b).unwrap(), (1, vec![0, 255]));
    a.write_all(&[1, 0, 2, 0, 0]).unwrap();
    assert!(read_frame(&mut b).is_err());
}
#[test]
fn bounded_header_does_not_consume_stream() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    a.write_all(b"{}\nX").unwrap();
    assert_eq!(line(&mut b, 4).unwrap(), b"{}");
    let mut c = [0];
    b.read_exact(&mut c).unwrap();
    assert_eq!(c[0], b'X');
}
