//! Native first-use HTTP boundary. Invitation issuance stays blocked until the
//! installed authenticated broker and effect transaction are actually wired.
use crate::{
    enrollment_delivery::Context,
    enrollment_profile::Request,
    onboarding_store::{Session, Store},
    policy::{Owner, Res},
    registry::Registry,
    schema::Kind,
};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::Write;
pub struct Response {
    pub status: u16,
    pub value: Value,
    pub retry_after: Option<u64>,
}
impl Response {
    pub fn write(&self, w: &mut impl Write) -> Res<()> {
        let body =
            serde_json::to_vec(&self.value).map_err(|_| "onboarding_response_encoding_failed")?;
        let retry = self
            .retry_after
            .map(|s| format!("Retry-After: {s}\r\n"))
            .unwrap_or_default();
        write!(w,"HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n{}\r\n",self.status,body.len(),retry).and_then(|_|w.write_all(&body)).map_err(|_|"onboarding_response_closed".into())
    }
}
fn error(status: u16, code: &str, message: &str) -> Response {
    Response {
        status,
        value: json!({"schema":1,"code":code,"message":message}),
        retry_after: None,
    }
}
fn blocked(blocker: &str, message: &str) -> Response {
    let mut response = error(503, "setup_blocked", message);
    response.value["blocker"] = json!(blocker);
    response.value["retry_after_ms"] = json!(1000);
    response.retry_after = Some(1);
    response
}
fn invalid() -> Response {
    error(403, "invalid_setup", "Code or setup session is not valid.")
}
fn failure(e: &str) -> Response {
    if e == "invalid_setup" {
        invalid()
    } else if e.starts_with("setup_rate_limited") {
        let mut r = error(
            429,
            "setup_rate_limited",
            "Too many attempts. Try again in a minute.",
        );
        r.value["retry_after_ms"] = json!(60000);
        r.retry_after = Some(60);
        r
    } else if e == "onboarding_busy" {
        blocked(
            "setup_busy",
            "Another setup action is saving. Try again shortly.",
        )
    } else {
        blocked(
            "setup_state_unknown",
            "Server setup state needs review. Existing setup was preserved.",
        )
    }
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(s: &str, max: usize) -> Res<Vec<u8>> {
    if s.len() > max.div_ceil(3) * 4 {
        return Err("invalid_request".into());
    }
    let b = Base64::decode_vec(s).map_err(|_| "invalid_request")?;
    if b.len() > max || Base64::encode_string(&b) != s {
        return Err("invalid_request".into());
    }
    Ok(b)
}
fn maintenance(r: &Registry) -> Res<()> {
    if r.closing.load(std::sync::atomic::Ordering::SeqCst)
        || crate::maintenance::inspect_active(&r.root)?.is_some()
    {
        return Err("coordinator_maintenance".into());
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRequest {
    pub id: Option<String>,
    pub name: String,
    pub kind: Kind,
    pub endpoint: String,
    pub report_port: Option<u16>,
    pub client_session: String,
    pub setup_url: Option<String>,
}
impl InviteRequest {
    fn parse(bytes: &[u8]) -> Res<Self> {
        if bytes.len() > 2048 {
            return Err("invalid_request".into());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
        if !text(&value.client_session, 160) {
            return Err("invalid_request".into());
        }
        Request {
            id: value.id.clone().unwrap_or("new-device".into()),
            name: value.name.clone(),
            kind: value.kind,
            endpoint: value.endpoint.clone(),
            report_port: value.report_port.unwrap_or(19193),
        }
        .validate()?;
        Ok(value)
    }
}
/// Called only after existing dashboard authentication/Host/Origin checks.
pub fn admin_issue(r: &Registry, body: &[u8]) -> Response {
    let request = match InviteRequest::parse(body) {
        Ok(v) => v,
        Err(_) => {
            return error(
                400,
                "invalid_request",
                "Check the device name, kind and VPN endpoint.",
            );
        }
    };
    let owner = Owner {
        agent: "web".into(),
        origin: "dashboard".into(),
        session: request.client_session.clone(),
        job: format!("Enroll {}", request.id.as_deref().unwrap_or(&request.name)),
        allow_sleep: false,
    };
    issue(r, request, &owner)
}
/// Existing protected coordinator RPC, not a public HTTP authority grant.
pub fn cli_issue(r: &Registry, rpc: &crate::control::Request) -> Response {
    if rpc.version != 1
        || rpc.action != "device-setup-code"
        || rpc.observe
        || !rpc.ticket.is_empty()
        || rpc.evidence.is_some()
    {
        return error(
            400,
            "invalid_request",
            "Setup code requires public device metadata and the actual issuer.",
        );
    }
    let Some(owner) = &rpc.owner else {
        return error(400, "invalid_request", "Actual issuer is required.");
    };
    if [&owner.agent, &owner.origin, &owner.session, &owner.job]
        .iter()
        .any(|v| !text(v, 160))
        || owner.allow_sleep
    {
        return error(400, "invalid_request", "Actual issuer is required.");
    }
    let [body] = rpc.args.as_slice() else {
        return error(
            400,
            "invalid_request",
            "One public device request is required.",
        );
    };
    let request = match InviteRequest::parse(body.as_bytes()) {
        Ok(v) => v,
        Err(_) => return error(400, "invalid_request", "Device request is not valid."),
    };
    if request.client_session != owner.session || request.id.as_deref().unwrap_or("") != rpc.device
    {
        return error(
            400,
            "invalid_request",
            "Setup issuer or device scope changed.",
        );
    }
    issue(r, request, owner)
}
fn issue(r: &Registry, _request: InviteRequest, _owner: &Owner) -> Response {
    if maintenance(r).is_err() {
        return blocked(
            "coordinator_maintenance",
            "Server upgrade is in progress. Setup is paused.",
        );
    }
    // This pure prerequisite cannot mint runtime authority. Replace only with the
    // credential-checked installed broker client, then retain its scope through
    // exact allocation and durable invitation publication. No code while absent.
    let prerequisite = crate::report_firewall::prerequisite();
    if !prerequisite.available() {
        return blocked(
            prerequisite.code(),
            "Install and verify the report firewall broker first.",
        );
    }
    blocked(
        "setup_orchestration_required",
        "Server setup transaction is not available in this build.",
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    code: String,
    request_b64: String,
    client_auth: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resume {
    request_sha256: String,
    client_auth: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    request_sha256: String,
    client_auth: String,
    ack_b64: String,
}
fn progress(r: &Registry, session: &Session) -> Response {
    let context = match Context::new(
        session.server_binding(),
        session.id(),
        session.transaction(),
    ) {
        Ok(v) => Base64::encode_string(v.bytes()),
        Err(_) => return failure("invalid_context"),
    };
    let mut response = if maintenance(r).is_err() {
        blocked(
            "coordinator_maintenance",
            "Server upgrade is in progress. Your setup was saved.",
        )
    } else {
        blocked(
            "report_firewall_setup_required",
            "Server report firewall setup needs review. Your setup was saved.",
        )
    };
    for (key, value) in [
        ("phase", json!("bound")),
        ("request_sha256", json!(session.request_sha256())),
        ("context_b64", json!(context)),
        ("envelope_b64", Value::Null),
        ("final_b64", Value::Null),
    ] {
        response.value[key] = value;
    }
    response
}
/// Public native routes carry only the one-use code or bound client credential.
/// Real socket peer is supplied by caller; forwarding headers never set identity.
pub fn public_request(r: &Registry, request: &crate::http::Request, peer: &str) -> Response {
    if request.method != "POST"
        || !matches!(
            request.path.as_str(),
            "/onboard/v1/claim" | "/onboard/v1/resume" | "/onboard/v1/ack"
        )
    {
        return error(404, "not_found", "Setup route was not found.");
    }
    if request.headers.contains_key("origin") {
        return invalid();
    }
    if request
        .headers
        .get("content-type")
        .is_none_or(|v| v.split(';').next().map(str::trim) != Some("application/json"))
        || request.body.len() > 32768
    {
        return error(400, "invalid_request", "Setup request is not valid.");
    }
    let now = crate::backend::now().max(0.0) as u64;
    let session = (|| -> Res<Session> {
        match request.path.as_str() {
            "/onboard/v1/claim" => {
                let req: Claim =
                    serde_json::from_slice(&request.body).map_err(|_| "invalid_request")?;
                if !hex(&req.client_auth) || !text(&req.code, 19) {
                    return Err("invalid_request".into());
                }
                let recipient = decode(&req.request_b64, 2048)?;
                crate::enrollment_delivery::validate_request(&recipient)
                    .map_err(|_| "invalid_request")?;
                let mut store = Store::open(&r.root)?;
                store.claim(&req.code, &recipient, &req.client_auth, peer, now)
            }
            "/onboard/v1/resume" => {
                let req: Resume =
                    serde_json::from_slice(&request.body).map_err(|_| "invalid_request")?;
                if !hex(&req.client_auth) || !hex(&req.request_sha256) {
                    return Err("invalid_request".into());
                }
                let mut store = Store::open(&r.root)?;
                store.resume(&req.request_sha256, &req.client_auth, peer, now)
            }
            "/onboard/v1/ack" => {
                let req: Ack =
                    serde_json::from_slice(&request.body).map_err(|_| "invalid_request")?;
                if !hex(&req.client_auth) || !hex(&req.request_sha256) {
                    return Err("invalid_request".into());
                }
                let _ack = decode(&req.ack_b64, 512)?;
                let mut store = Store::open(&r.root)?;
                let session = store.resume(&req.request_sha256, &req.client_auth, peer, now)?;
                drop(store);
                // No stored envelope/finalization exists yet. A valid recovery credential is
                // never treated as evidence that Android stored a profile.
                Ok(session)
            }
            _ => unreachable!(),
        }
    })();
    match session {
        Ok(session) => progress(r, &session),
        Err(e) if e == "invalid_request" => {
            error(400, "invalid_request", "Setup request is not valid.")
        }
        Err(e) => failure(&e),
    }
}
