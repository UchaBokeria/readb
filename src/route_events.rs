//! Observational Linux route-netlink subscription. It never sends a request.
use crate::policy::Res;
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, RawFd},
    time::Duration,
};
pub struct RouteEvents {
    socket: File,
}
impl RouteEvents {
    pub fn new() -> Res<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err("route_events_socket_unavailable".into());
        }
        let socket = unsafe { File::from_raw_fd(fd) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR) as u32;
        if unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err("route_events_subscription_unavailable".into());
        }
        Ok(Self { socket })
    }
    pub fn drain(&mut self) -> Res<bool> {
        let mut changed = false;
        let mut buffer = [0u8; 32768];
        // Bound a storm. Notifications only accelerate a pinned snapshot check;
        // packet contents never authorize a write. Overflow also requests a check.
        for _ in 0..16 {
            let size = unsafe {
                libc::recv(
                    self.socket.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if size >= 0 {
                changed = true;
                continue;
            }
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EAGAIN) => return Ok(changed),
                Some(libc::EINTR) => continue,
                Some(libc::ENOBUFS) => {
                    changed = true;
                    continue;
                }
                _ => return Err("route_events_read_failed".into()),
            }
        }
        Ok(changed)
    }
    pub fn wait(&self, control: RawFd, timeout: Duration) -> Res<(bool, bool)> {
        wait(control, Some(self), timeout)
    }
}
pub fn wait(control: RawFd, events: Option<&RouteEvents>, timeout: Duration) -> Res<(bool, bool)> {
    let mut descriptors = [
        libc::pollfd {
            fd: control,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: events.map_or(-1, |e| e.socket.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if result < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            return Ok((false, false));
        }
        return Err("network_poll_failed".into());
    }
    if descriptors
        .iter()
        .any(|p| p.revents & (libc::POLLHUP | libc::POLLNVAL) != 0)
    {
        return Err("network_poll_descriptor_closed".into());
    }
    Ok((
        descriptors[0].revents & (libc::POLLIN | libc::POLLERR) != 0,
        descriptors[1].revents & (libc::POLLIN | libc::POLLERR) != 0,
    ))
}
