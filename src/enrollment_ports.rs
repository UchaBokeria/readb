//! Process-local socket reservations. Persisted allocation still belongs to the
//! enrollment journal; after a restart, any occupied/unowned socket must refuse.
use crate::policy::Res;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
pub struct Ports {
    adb: Option<TcpListener>,
    report: Option<TcpListener>,
}
impl Ports {
    /// `shared` must come from this coordinator's actual listener table. A
    /// matching configured address alone is never listener readiness evidence.
    pub fn reserve(adb_port: u16, report: SocketAddr, shared: Option<&TcpListener>) -> Res<Self> {
        if adb_port < 1024
            || report.port() < 1024
            || adb_port == report.port()
            || !matches!(report.ip(),IpAddr::V4(a) if !a.is_unspecified() && !a.is_multicast())
        {
            return Err("enrollment_socket_scope_invalid".into());
        }
        let adb = TcpListener::bind((Ipv4Addr::LOCALHOST, adb_port))
            .map_err(|_| "enrollment_adb_port_busy: existing socket was not adopted")?;
        let listener = match shared {
            Some(listener) => {
                if listener
                    .local_addr()
                    .map_err(|_| "enrollment_shared_listener_unavailable")?
                    != report
                {
                    return Err("enrollment_shared_listener_scope_mismatch".into());
                }
                listener
                    .try_clone()
                    .map_err(|_| "enrollment_shared_listener_unavailable")?
            }
            None => TcpListener::bind(report)
                .map_err(|_| "enrollment_report_port_busy: existing socket was not adopted")?,
        };
        Ok(Self {
            adb: Some(adb),
            report: Some(listener),
        })
    }
    pub fn take_adb(&mut self) -> Res<TcpListener> {
        self.adb
            .take()
            .ok_or_else(|| "enrollment_adb_reservation_already_transferred".into())
    }
    pub fn take_report(&mut self) -> Res<TcpListener> {
        self.report
            .take()
            .ok_or_else(|| "enrollment_report_reservation_already_transferred".into())
    }
}
