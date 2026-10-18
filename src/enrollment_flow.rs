//! Pure enrollment ordering, not an effect authority or a second durable store.
//! Future adapters must persist each intent in the existing enrollment journal
//! and mint confirmations only after their own authenticated evidence checks.
use crate::{
    enrollment_profile::{Facts, Plan, Request},
    policy::{Owner, Res},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
fn digest(value: &impl Serialize) -> Res<String> {
    Ok(
        Sha256::digest(serde_json::to_vec(value).map_err(|_| "enrollment_encoding_failed")?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_owner(o: &Owner) -> bool {
    [&o.agent, &o.origin, &o.session, &o.job]
        .iter()
        .all(|s| !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control))
}
fn same(a: &Owner, b: &Owner) -> bool {
    a.agent == b.agent
        && a.origin == b.origin
        && a.session == b.session
        && a.job == b.job
        && a.allow_sleep == b.allow_sleep
}
pub fn request_fingerprint(request: &Request) -> Res<String> {
    request.validate()?;
    digest(request)
}
#[derive(Clone)]
pub struct Scope {
    request: String,
    transaction: String,
    binding: String,
    owner: Owner,
}
impl Scope {
    pub fn new(request: &Request, plan: &Plan, owner: Owner, transaction: &str) -> Res<Self> {
        plan.validate()?;
        request.validate()?;
        let proposed = Request {
            id: plan.id.clone(),
            name: plan.name.clone(),
            kind: plan.kind,
            endpoint: plan.endpoint.clone(),
            report_port: plan.report_bind.port(),
        };
        let request = request_fingerprint(request)?;
        if !valid_owner(&owner) || !hash(transaction) || request != request_fingerprint(&proposed)?
        {
            return Err("enrollment_scope_invalid".into());
        }
        Ok(Self {
            request,
            transaction: transaction.into(),
            binding: digest(plan)?,
            owner,
        })
    }
    fn authorize(&self, owner: &Owner, request: &str) -> Res<()> {
        if !same(&self.owner, owner) || self.request != request {
            return Err("enrollment_original_owner_or_request_mismatch".into());
        }
        Ok(())
    }
}
/// No production constructor exists until a broker client verifies its actual
/// root transport, installed scope and policy. A proposal cannot create this.
pub struct AuthenticatedFirewallCapability {
    binding: String,
}
pub struct Prerequisites {
    binding: String,
    firewall: Option<AuthenticatedFirewallCapability>,
    fence: Option<Fence>,
}
#[derive(Clone, Copy)]
pub enum Fence {
    Upgrade,
    NetworkUnknown,
    NetworkChanged,
}
impl Prerequisites {
    pub fn inspect(facts: &Facts, plan: &Plan) -> Res<Self> {
        facts.validate()?;
        plan.validate()?;
        let peer = u32::from(plan.peer);
        if plan.policy_fingerprint != digest(&facts.policy)?
            || plan.snapshot_fingerprint != digest(&facts.snapshot)?
            || plan.server_peer != facts.policy.server_address
            || plan.server_public_key != facts.policy.server_key
            || peer < u32::from(facts.policy.first)
            || peer > u32::from(facts.policy.last)
        {
            return Err("enrollment_network_snapshot_changed".into());
        }
        Ok(Self {
            binding: digest(plan)?,
            firewall: None,
            fence: None,
        })
    }
    pub fn invalidate(&mut self, fence: Fence) {
        self.fence = Some(fence);
    }
    fn admit(&self, binding: &str) -> Res<()> {
        if let Some(fence) = self.fence {
            return Err(match fence {
                Fence::Upgrade => "coordinator_maintenance: enrollment paused",
                Fence::NetworkUnknown => "enrollment_network_unknown: inspect root helper",
                Fence::NetworkChanged => "enrollment_network_snapshot_changed",
            }
            .into());
        }
        if self.binding != binding {
            return Err("enrollment_prerequisite_scope_changed".into());
        }
        if !self.firewall.as_ref().is_some_and(|f| f.binding == binding) {
            return Err(
                "report_firewall_setup_required: authenticated ufw-v1 capability is unavailable"
                    .into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Empty,
    Prepared,
    CatalogAdded,
    ControllerHeld,
    PeerApplied,
    ReportReady,
    ListenerReady,
    RecipientBound,
    EnvelopeCommitted,
    AndroidStored,
    Complete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    GenerateMaterial,
    PublishCatalog,
    ClaimController,
    ApplyPeer,
    ApplyReportRule,
    OwnListener,
    BindRecipient,
    StoreEnvelope,
    StoreAndroid,
    Finalize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    PersistIntent(Effect),
    Inspect(Effect),
    Complete,
}
struct Intent {
    effect: Effect,
    after_catalog: Option<String>,
}
/// Deliberately not deserializable and without a public constructor. Each later
/// effect adapter must mint its exact authenticated confirmation; Android ACK
/// needs the encrypted receipt MAC, never a host-output acknowledgement.
pub struct VerifiedStep {
    effect: Effect,
    binding: String,
    request: String,
    transaction: String,
}
pub struct State {
    scope: Scope,
    phase: Phase,
    pending: Option<Intent>,
    catalog: String,
}
fn next(phase: Phase) -> Option<(Effect, Phase)> {
    Some(match phase {
        Phase::Empty => (Effect::GenerateMaterial, Phase::Prepared),
        Phase::Prepared => (Effect::PublishCatalog, Phase::CatalogAdded),
        Phase::CatalogAdded => (Effect::ClaimController, Phase::ControllerHeld),
        Phase::ControllerHeld => (Effect::ApplyPeer, Phase::PeerApplied),
        Phase::PeerApplied => (Effect::ApplyReportRule, Phase::ReportReady),
        Phase::ReportReady => (Effect::OwnListener, Phase::ListenerReady),
        Phase::ListenerReady => (Effect::BindRecipient, Phase::RecipientBound),
        Phase::RecipientBound => (Effect::StoreEnvelope, Phase::EnvelopeCommitted),
        Phase::EnvelopeCommitted => (Effect::StoreAndroid, Phase::AndroidStored),
        Phase::AndroidStored => (Effect::Finalize, Phase::Complete),
        Phase::Complete => return None,
    })
}
impl State {
    pub fn new(scope: Scope, plan: &Plan) -> Res<Self> {
        plan.validate()?;
        if scope.binding != digest(plan)? {
            return Err("enrollment_state_scope_mismatch".into());
        }
        Ok(Self {
            scope,
            phase: Phase::Empty,
            pending: None,
            catalog: plan.config_fingerprint.clone(),
        })
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn pending(&self) -> Option<Effect> {
        self.pending.as_ref().map(|p| p.effect)
    }
    pub fn catalog(&self) -> &str {
        &self.catalog
    }
    pub fn begin(
        &mut self,
        owner: &Owner,
        request: &str,
        prerequisites: &Prerequisites,
        after_catalog: Option<&str>,
    ) -> Res<Decision> {
        self.scope.authorize(owner, request)?;
        let Some((effect, _)) = next(self.phase) else {
            return Ok(Decision::Complete);
        };
        prerequisites.admit(&self.scope.binding)?;
        if let Some(intent) = &self.pending {
            if intent.effect != effect || intent.after_catalog.as_deref() != after_catalog {
                return Err("enrollment_recorded_intent_mismatch".into());
            }
            return Ok(Decision::Inspect(intent.effect));
        }
        if (effect == Effect::PublishCatalog) != after_catalog.is_some()
            || after_catalog.is_some_and(|s| !hash(s) || s == self.catalog)
        {
            return Err("enrollment_catalog_successor_required_or_unexpected".into());
        }
        self.pending = Some(Intent {
            effect,
            after_catalog: after_catalog.map(str::to_owned),
        });
        Ok(Decision::PersistIntent(effect))
    }
    pub fn confirm(
        &mut self,
        owner: &Owner,
        request: &str,
        prerequisites: &Prerequisites,
        proof: &VerifiedStep,
        actual_catalog: &str,
    ) -> Res<Phase> {
        self.scope.authorize(owner, request)?;
        prerequisites.admit(&self.scope.binding)?;
        let intent = self
            .pending
            .as_ref()
            .ok_or("enrollment_no_recorded_intent")?;
        let (effect, phase) = next(self.phase).ok_or("enrollment_already_complete")?;
        if proof.effect != effect
            || intent.effect != effect
            || proof.binding != self.scope.binding
            || proof.request != self.scope.request
            || proof.transaction != self.scope.transaction
        {
            return Err("enrollment_confirmation_scope_mismatch".into());
        }
        let expected = intent.after_catalog.as_deref().unwrap_or(&self.catalog);
        if !hash(actual_catalog) || actual_catalog != expected {
            return Err("enrollment_catalog_confirmation_mismatch".into());
        }
        self.catalog = actual_catalog.into();
        self.pending = None;
        self.phase = phase;
        Ok(phase)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        enrollment_profile::{Facts, Request, plan},
        network::{Policy, Snapshot},
        schema::{Kind, ServerConfig},
    };
    use std::collections::{BTreeMap, BTreeSet};
    fn key(c: char) -> String {
        format!("{}AAA=", c.to_string().repeat(40))
    }
    fn fixture() -> (
        Request,
        crate::enrollment_profile::Plan,
        Scope,
        Prerequisites,
    ) {
        let facts = Facts {
            policy: Policy {
                schema: 1,
                uid: 1000,
                interface: "mobile".into(),
                server_key: key('E'),
                server_address: "10.99.0.2".parse().unwrap(),
                prefix: 24,
                first: "10.99.0.100".parse().unwrap(),
                last: "10.99.0.150".parse().unwrap(),
            },
            snapshot: Snapshot {
                server_key: key('E'),
                addresses: vec!["10.99.0.2/24".into()],
                peers: BTreeMap::new(),
            },
            managed: BTreeMap::new(),
        };
        let request = Request {
            id: "pixel-readb".into(),
            name: "Pixel".into(),
            kind: Kind::Phone,
            endpoint: "vpn.example.org:51820".into(),
            report_port: 19193,
        };
        let config = ServerConfig {
            schema: 1,
            adb: "/not-executed".into(),
            devices: vec![],
            listeners: vec![],
        };
        let plan = plan(&facts, &config, &request, &[], &BTreeSet::new()).unwrap();
        let scope = Scope::new(&request, &plan, owner(), &"a".repeat(64)).unwrap();
        let prerequisites = Prerequisites::inspect(&facts, &plan).unwrap();
        (request, plan, scope, prerequisites)
    }
    fn owner() -> crate::policy::Owner {
        crate::policy::Owner {
            agent: "codex".into(),
            origin: "pc".into(),
            session: "actual-session".into(),
            job: "Enroll Pixel".into(),
            allow_sleep: false,
        }
    }
    fn proof(s: &State, tx: &str, effect: Effect) -> VerifiedStep {
        VerifiedStep {
            binding: s.scope.binding.clone(),
            request: s.scope.request.clone(),
            transaction: tx.into(),
            effect,
        }
    }
    fn available(mut p: Prerequisites) -> Prerequisites {
        p.firewall = Some(AuthenticatedFirewallCapability {
            binding: p.binding.clone(),
        });
        p
    }
    #[test]
    fn missing_authenticated_firewall_blocks_material_and_every_peer_profile_effect() {
        let (req, plan, scope, prerequisites) = fixture();
        let mut state = State::new(scope, &plan).unwrap();
        assert!(
            state
                .begin(
                    &owner(),
                    &request_fingerprint(&req).unwrap(),
                    &prerequisites,
                    None
                )
                .unwrap_err()
                .contains("report_firewall_setup_required")
        );
        assert_eq!(state.phase(), Phase::Empty);
        assert!(state.pending().is_none());
        for phase in [
            Phase::Prepared,
            Phase::CatalogAdded,
            Phase::ControllerHeld,
            Phase::PeerApplied,
            Phase::ReportReady,
            Phase::ListenerReady,
            Phase::RecipientBound,
            Phase::EnvelopeCommitted,
            Phase::AndroidStored,
        ] {
            state.phase = phase;
            assert!(
                state
                    .begin(
                        &owner(),
                        &request_fingerprint(&req).unwrap(),
                        &prerequisites,
                        None
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn original_owner_request_and_transaction_never_transfer_or_rebase() {
        let (req, plan, scope, p) = fixture();
        let mut state = State::new(scope, &plan).unwrap();
        let p = available(p);
        let hash = request_fingerprint(&req).unwrap();
        let mut other = owner();
        other.session = "another".into();
        assert!(state.begin(&other, &hash, &p, None).is_err());
        assert!(state.begin(&owner(), &"b".repeat(64), &p, None).is_err());
        assert_eq!(
            state.begin(&owner(), &hash, &p, None).unwrap(),
            Decision::PersistIntent(Effect::GenerateMaterial)
        );
        assert!(
            state
                .confirm(
                    &owner(),
                    &hash,
                    &p,
                    &proof(&state, &"b".repeat(64), Effect::GenerateMaterial),
                    &plan.config_fingerprint
                )
                .is_err()
        );
        assert_eq!(state.phase(), Phase::Empty);
        state
            .confirm(
                &owner(),
                &hash,
                &p,
                &proof(&state, &"a".repeat(64), Effect::GenerateMaterial),
                &plan.config_fingerprint,
            )
            .unwrap();
        assert!(state.begin(&owner(), &hash, &p, None).is_err());
        let next = "c".repeat(64);
        state.begin(&owner(), &hash, &p, Some(&next)).unwrap();
        assert!(
            state
                .confirm(
                    &owner(),
                    &hash,
                    &p,
                    &proof(&state, &"a".repeat(64), Effect::PublishCatalog),
                    &"d".repeat(64)
                )
                .is_err()
        );
        assert_eq!(state.catalog(), plan.config_fingerprint);
        state
            .confirm(
                &owner(),
                &hash,
                &p,
                &proof(&state, &"a".repeat(64), Effect::PublishCatalog),
                &next,
            )
            .unwrap();
        assert_eq!(state.catalog(), next);
    }
    #[test]
    fn pending_intents_are_inspected_not_reexecuted_and_sequence_is_bounded() {
        let (req, plan, scope, p) = fixture();
        let mut state = State::new(scope, &plan).unwrap();
        let p = available(p);
        let hash = request_fingerprint(&req).unwrap();
        let mut catalog = plan.config_fingerprint.clone();
        let mut count = 0;
        while state.phase() != Phase::Complete {
            let successor = (state.phase() == Phase::Prepared).then(|| "c".repeat(64));
            let Decision::PersistIntent(effect) = state
                .begin(&owner(), &hash, &p, successor.as_deref())
                .unwrap()
            else {
                panic!("expected new intent")
            };
            assert_eq!(
                state
                    .begin(&owner(), &hash, &p, successor.as_deref())
                    .unwrap(),
                Decision::Inspect(effect)
            );
            if let Some(next) = successor {
                catalog = next;
            }
            state
                .confirm(
                    &owner(),
                    &hash,
                    &p,
                    &proof(&state, &"a".repeat(64), effect),
                    &catalog,
                )
                .unwrap();
            count += 1;
            assert!(count <= 10);
            assert!(
                state
                    .confirm(
                        &owner(),
                        &hash,
                        &p,
                        &proof(&state, &"a".repeat(64), effect),
                        &catalog
                    )
                    .is_err()
            );
        }
        assert_eq!(count, 10);
        assert_eq!(
            state.begin(&owner(), &hash, &p, None).unwrap(),
            Decision::Complete
        );
    }
    #[test]
    fn changed_prerequisite_binding_never_reuses_stale_capability() {
        let (req, plan, scope, p) = fixture();
        let mut state = State::new(scope, &plan).unwrap();
        let mut p = available(p);
        p.binding = "f".repeat(64);
        assert!(
            state
                .begin(&owner(), &request_fingerprint(&req).unwrap(), &p, None)
                .is_err()
        );
        assert!(state.pending().is_none());
    }
    #[test]
    fn explicit_fences_override_even_a_verified_capability_without_creating_intent() {
        for fence in [Fence::Upgrade, Fence::NetworkUnknown, Fence::NetworkChanged] {
            let (req, plan, scope, p) = fixture();
            let mut state = State::new(scope, &plan).unwrap();
            let mut p = available(p);
            p.invalidate(fence);
            assert!(
                state
                    .begin(&owner(), &request_fingerprint(&req).unwrap(), &p, None)
                    .is_err()
            );
            assert!(state.pending().is_none());
            assert_eq!(state.phase(), Phase::Empty);
        }
    }
    #[test]
    fn a_fence_after_intent_preserves_pending_work_instead_of_confirming_it() {
        let (req, plan, scope, p) = fixture();
        let mut state = State::new(scope, &plan).unwrap();
        let mut p = available(p);
        let hash = request_fingerprint(&req).unwrap();
        state.begin(&owner(), &hash, &p, None).unwrap();
        p.invalidate(Fence::Upgrade);
        assert!(
            state
                .confirm(
                    &owner(),
                    &hash,
                    &p,
                    &proof(&state, &"a".repeat(64), Effect::GenerateMaterial),
                    &plan.config_fingerprint
                )
                .is_err()
        );
        assert_eq!(state.pending(), Some(Effect::GenerateMaterial));
        assert_eq!(state.phase(), Phase::Empty);
    }
}
