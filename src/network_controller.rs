//! One-use, exact-request proofs backed by durable device controller operations.
//! No kernel calls here. Caller must authenticate the root authority transport.
use crate::{
    backend::Backend,
    network::Request,
    policy::{Res, random},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
pub fn request_digest(request: &Request) -> Res<String> {
    let bytes = serde_json::to_vec(request).map_err(|_| "network_request_encoding_failed")?;
    if bytes.len() > 4096 {
        return Err("network_request_too_large".into());
    }
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
struct Pending {
    backend: Arc<Backend>,
    ticket: String,
    operation: String,
    digest: String,
    used: bool,
}
#[derive(Default)]
pub struct NetworkController {
    pending: Mutex<BTreeMap<String, Pending>>,
}
#[derive(Clone, Copy)]
pub enum Outcome {
    Applied,
    Refused,
    Uncertain,
}
pub struct Scope<'a> {
    authority: &'a NetworkController,
    backend: Arc<Backend>,
    ticket: String,
    operation: String,
    nonce: String,
    finished: bool,
}
impl NetworkController {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin<'a>(
        &'a self,
        registry: &crate::registry::Registry,
        ticket: &str,
        device: &str,
        request: Request,
    ) -> Res<Scope<'a>> {
        let digest = request_digest(&request)?;
        let (backend, operation) = registry.begin_network_operation(ticket, device, &request)?;
        let nonce = random();
        let mut pending = self.pending.lock().unwrap();
        if pending.contains_key(&nonce) {
            let _ = backend.finish_network(ticket, &operation, true, "network-nonce-collision");
            return Err("network_nonce_collision".into());
        }
        pending.insert(
            nonce.clone(),
            Pending {
                backend: backend.clone(),
                ticket: ticket.into(),
                operation: operation.clone(),
                digest,
                used: false,
            },
        );
        Ok(Scope {
            authority: self,
            backend,
            ticket: ticket.into(),
            operation,
            nonce,
            finished: false,
        })
    }
    pub fn authorize(&self, nonce: &str, digest: &str) -> Res<()> {
        if !valid_hash(nonce) || !valid_hash(digest) {
            return Err("network_authority_invalid_proof".into());
        }
        let mut pending = self.pending.lock().unwrap();
        let proof = pending
            .get_mut(nonce)
            .ok_or("network_authority_unknown_proof")?;
        if proof.used || proof.digest != digest {
            return Err("network_authority_used_or_mismatched_proof".into());
        }
        proof
            .backend
            .authorize_network(&proof.ticket, &proof.operation)?;
        proof.used = true;
        Ok(())
    }
}
impl Scope<'_> {
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    fn remove(&self) -> Option<bool> {
        let mut pending = self.authority.pending.lock().unwrap();
        if !pending
            .get(&self.nonce)
            .is_some_and(|p| p.operation == self.operation)
        {
            return None;
        }
        pending.remove(&self.nonce).map(|p| p.used)
    }
    pub fn finish(mut self, outcome: Outcome) -> Res<()> {
        let used = self.remove();
        let admitted = self
            .backend
            .authorize_network(&self.ticket, &self.operation)
            .is_ok();
        let definite = used.is_some()
            && admitted
            && match outcome {
                Outcome::Applied => used == Some(true),
                Outcome::Refused => true,
                Outcome::Uncertain => false,
            };
        self.finished = true;
        let label = if !definite {
            "network-unconfirmed"
        } else if matches!(outcome, Outcome::Applied) {
            "network-applied"
        } else {
            "network-refused"
        };
        let result = self
            .backend
            .finish_network(&self.ticket, &self.operation, !definite, label);
        if !definite {
            return Err(
                "network_completion_unconfirmed: inspect device and root state before retry".into(),
            );
        }
        result
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.remove();
            let _ = self.backend.finish_network(
                &self.ticket,
                &self.operation,
                true,
                "network-unconfirmed",
            );
        }
    }
}
