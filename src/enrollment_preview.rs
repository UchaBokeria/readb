//! Read-only enrollment snapshots. No keygen, persistent lock, job or socket bind.
use crate::{
    control::Request as Rpc,
    enrollment_profile::{self, Facts, Plan, Request},
    policy::Res,
    registry::Registry,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, io::Read, sync::atomic::Ordering};
pub trait Probe {
    fn facts(&mut self) -> Res<Facts>;
    fn listening_ports(&mut self) -> Res<BTreeSet<u16>>;
}
pub struct SystemProbe;
impl Probe for SystemProbe {
    fn facts(&mut self) -> Res<Facts> {
        let value = crate::network_runtime::call(crate::network_runtime::Call::EnrollmentFacts)?;
        serde_json::from_value(value).map_err(|_| "enrollment_public_facts_invalid".into())
    }
    fn listening_ports(&mut self) -> Res<BTreeSet<u16>> {
        let mut ports = BTreeSet::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let file = File::open(path).map_err(|_| "listener_probe_unavailable")?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "listener_probe_unavailable")?;
            if bytes.len() > 1024 * 1024 {
                return Err("listener_probe_too_large".into());
            }
            ports.extend(parse_listeners(&bytes)?);
        }
        Ok(ports)
    }
}
fn parse_listeners(bytes: &[u8]) -> Res<BTreeSet<u16>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "listener_probe_invalid")?;
    let mut lines = text.lines();
    if !lines
        .next()
        .is_some_and(|line| line.contains("local_address"))
    {
        return Err("listener_probe_invalid_header".into());
    }
    let mut ports = BTreeSet::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            return Err("listener_probe_invalid_row".into());
        }
        if fields[3] != "0A" {
            continue;
        }
        let (_, port) = fields[1]
            .rsplit_once(':')
            .ok_or("listener_probe_invalid_address")?;
        if port.len() != 4 {
            return Err("listener_probe_invalid_port".into());
        }
        ports.insert(u16::from_str_radix(port, 16).map_err(|_| "listener_probe_invalid_port")?);
    }
    Ok(ports)
}
fn fingerprint(value: &impl serde::Serialize) -> Res<String> {
    Ok(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| "enrollment_snapshot_encoding_failed")?,
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect())
}
struct Local {
    config: crate::schema::ServerConfig,
    fingerprint: String,
}
fn local(registry: &Registry) -> Res<Local> {
    if registry.closing.load(Ordering::SeqCst)
        || crate::maintenance::inspect_active(&registry.root)?.is_some()
    {
        return Err("coordinator_maintenance: device setup is paused".into());
    }
    let records = crate::enrollment_journal::inspect(&registry.root)?;
    if !records.is_empty() {
        return Err(format!(
            "enrollment_pending: resume the original setup for {}",
            records.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if registry
        .all()
        .iter()
        .any(|(_, b)| b.state.lock().unwrap().enrollment.is_some())
    {
        return Err(
            "enrollment_state_unknown: a cached device barrier has no matching journal".into(),
        );
    }
    let config = registry.config();
    Ok(Local {
        fingerprint: fingerprint(&config)?,
        config,
    })
}
fn firewall() -> Value {
    let mut value = serde_json::to_value(crate::report_firewall::prerequisite())
        .expect("public prerequisite encoding");
    value["authenticated"] = json!(false);
    value
}
fn output(request: &Request, candidate: Option<Plan>, code: &str, detail: &str) -> Value {
    let detail = detail
        .chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect::<String>();
    json!({"schema":1,"dry_run":true,"device":request.id,"can_apply":false,"profile_deliverable":false,"allocation":"advisory_not_reserved","candidate":candidate,"firewall":firewall(),"blockers":[code],"checks":[{"code":code,"status":"blocked","detail":detail}]})
}
fn local_code(error: &str) -> &'static str {
    if error.contains("maintenance") {
        "coordinator_maintenance"
    } else if error.starts_with("enrollment_pending:") {
        "enrollment_pending"
    } else {
        "enrollment_state_unknown"
    }
}
/// Strict RPC validation precedes helper reads. Only public proposals cross this
/// interface. Production Probe verifies root credentials in network_runtime.
pub fn handle(registry: &Registry, rpc: &Rpc, probe: &mut impl Probe) -> Res<Value> {
    if rpc.version != 1
        || rpc.action != "device-enroll-preview"
        || rpc.device.is_empty()
        || rpc.observe
        || !rpc.ticket.is_empty()
        || rpc.owner.is_some()
        || rpc.evidence.is_some()
    {
        return Err("enrollment_preview_requires_public_device_scope_without_authority".into());
    }
    let [raw] = rpc.args.as_slice() else {
        return Err("enrollment_preview_requires_one_public_request".into());
    };
    if raw.len() > 2048 {
        return Err("enrollment_public_request_too_large".into());
    }
    let request: Request =
        serde_json::from_str(raw).map_err(|_| "invalid_enrollment_public_request")?;
    request.validate()?;
    if request.id != rpc.device {
        return Err("enrollment_device_scope_mismatch".into());
    }
    let before = match local(registry) {
        Ok(v) => v,
        Err(e) => return Ok(output(&request, None, local_code(&e), &e)),
    };
    let facts = match probe.facts() {
        Ok(v) => v,
        Err(e) => {
            return Ok(output(
                &request,
                None,
                "enrollment_network_facts_unavailable",
                &e,
            ));
        }
    };
    let ports = match probe.listening_ports() {
        Ok(v) => v,
        Err(e) => return Ok(output(&request, None, "listener_probe_unavailable", &e)),
    };
    let candidate = match enrollment_profile::plan(&facts, &before.config, &request, &[], &ports) {
        Ok(v) => v,
        Err(e) => return Ok(output(&request, None, "candidate_allocation_failed", &e)),
    };
    let fresh = match probe.facts() {
        Ok(v) => v,
        Err(e) => {
            return Ok(output(
                &request,
                None,
                "enrollment_network_facts_unavailable",
                &e,
            ));
        }
    };
    let fresh_ports = match probe.listening_ports() {
        Ok(v) => v,
        Err(e) => return Ok(output(&request, None, "listener_probe_unavailable", &e)),
    };
    let after = match local(registry) {
        Ok(v) => v,
        Err(e) => return Ok(output(&request, None, local_code(&e), &e)),
    };
    let fresh_candidate =
        enrollment_profile::plan(&fresh, &after.config, &request, &[], &fresh_ports);
    let same_candidate = match fresh_candidate {
        Ok(ref value) => fingerprint(value)? == fingerprint(&candidate)?,
        Err(_) => false,
    };
    if before.fingerprint != after.fingerprint
        || fingerprint(&facts)? != fingerprint(&fresh)?
        || !same_candidate
    {
        return Ok(output(
            &request,
            None,
            "enrollment_snapshot_changed",
            "Setup facts changed during preview. Run dry-run again; nothing was reserved.",
        ));
    }
    crate::enrollment_flow::Prerequisites::inspect(&fresh, &candidate)?;
    let mut result = output(
        &request,
        Some(candidate),
        "report_firewall_setup_required",
        "Authenticated report-firewall capability is unavailable in this build. Setup remains blocked.",
    );
    result["checks"].as_array_mut().unwrap().insert(0,json!({"code":"public_snapshot_checked","status":"observed","detail":"Candidate is advisory. Apply must recheck scope and own the actual descriptors."}));
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_listener_rows_cover_both_families_without_treating_connections_as_binds() {
        assert!(
            parse_listeners(b"sl local_address rem_address st\n")
                .unwrap()
                .is_empty()
        );
        let ports = parse_listeners(b"sl local_address rem_address st\n0: 0100007F:13B0 00000000:0000 0A\n1: 00000000000000000000000000000000:4AF9 00000000000000000000000000000000:0000 0A\n2: 0100007F:13B1 0100007F:13B2 01\n").unwrap();
        assert_eq!(ports, BTreeSet::from([5040, 19193]));
        for bad in [
            &b"no header\n"[..],
            &b"sl local_address\n0: short\n"[..],
            &b"sl local_address\n0: missing x 0A\n"[..],
            &b"sl local_address\n0: 0000:XYZ1 x 0A\n"[..],
        ] {
            assert!(parse_listeners(bad).is_err());
        }
    }
}
