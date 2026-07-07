// SPDX-License-Identifier: MIT OR Apache-2.0
//! Resolving a [`VerifiedAuditChain`] to the identity's current DID-document state,
//! along two deliberately separate pathways. Comparing them is the tool.
//!
//! [`ResolvedState`] is the projection a did:plc directory serves at `/data`:
//! the derived [`did:plc`](DidPlc) plus the head operation's `verificationMethods`,
//! `rotationKeys`, `alsoKnownAs`, and `services`. A [`ChainResolver`] produces
//! it two ways:
//!
//! - [`reported`](ChainResolver::reported): the head the directory's `nullified`
//!   flags designate (the last non-nullified operation). Time-free; trusts the
//!   directory. What the directory says is current, i.e. what `/data` serves.
//! - [`canonical`](ChainResolver::canonical): the head recomputed from rotation-key
//!   authority at each fork point and the 72-hour window (from the log's own
//!   `createdAt`), ignoring the flags. What the protocol says should be current.
//!
//! When the two agree, the directory is serving the cryptographic truth. A divergence
//! is the core tamper signal: the directory is serving a head the protocol does
//! not support, including a recovery it accepted outside the 72-hour window (which
//! authority ranking alone would miss). Trusting `reported` is safe only because
//! it is checked against `canonical`.
//!
//! A `plc_tombstone` head has no current state along either pathway
//! ([`ResolveError::Deactivated`]); a wholly-nullified chain likewise has none
//! ([`ResolveError::NoActiveOperation`]).

use crate::audit::{AuditLogEntry, VerifiedAuditChain};
use crate::cid::Cid;
use crate::did::{Key as DidKey, Plc as DidPlc};
use crate::error::{OperationError, ResolveError};
use crate::operation::properties::Service;
use crate::operation::{Checked, Operation, OperationType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The recovery (nullification) window: a higher-authority key may supersede a
/// fork within 72 hours of the op it nullifies.
const RECOVERY_WINDOW_MS: i64 = 72 * 60 * 60 * 1000;

/// The current resolved state of a did:plc identity: the projection the directory
/// serves at `/data`. It is the head operation's fields (`verificationMethods`,
/// `rotationKeys`, `alsoKnownAs`, `services`) combined with the chain's derived
/// [`did:plc`](DidPlc), which is taken from the chain and never the wire, so the
/// identifier always commits to the genesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedState {
    /// The identity, derived from the genesis operation.
    did: DidPlc,
    /// The Cid of the currently resolved head operation.
    cid: Cid,
    /// The verification methods (key id → `did:key`), e.g. `atproto` → signing
    /// key.
    verification_methods: BTreeMap<String, DidKey>,
    /// The rotation keys in authority order (highest authority first).
    rotation_keys: Vec<DidKey>,
    /// The identity's aliases (`at://` handles).
    also_known_as: Vec<String>,
    /// The service endpoints (service id → endpoint).
    services: BTreeMap<String, Service>,
}
impl ResolvedState {
    /// Project the resolved state from a chain's head operation: pair the head's
    /// (normalised) document fields with the identity's derived DID.
    ///
    /// The fields are read through the operation's getters, which normalise a
    /// legacy `create` head to the modern shape, so both genesis forms project
    /// identically.
    ///
    /// # Errors
    /// - [`ResolveError::Projection`] if a document field of the head operation
    ///   is malformed (an invalid `did:key`, a wrong-shaped field, or a legacy
    ///   `create` missing one of its flat fields).
    pub fn project(did: &DidPlc, head: &Operation<Checked>) -> Result<Self, ResolveError> {
        let project = |e: OperationError| ResolveError::Projection(e.to_string());
        Ok(Self {
            did: did.clone(),
            cid: head.cid().map_err(project)?,
            verification_methods: head.verification_methods().map_err(project)?,
            rotation_keys: head.rotation_keys().map_err(project)?,
            also_known_as: head.also_known_as().map_err(project)?,
            services: head.services().map_err(project)?,
        })
    }

    /// The identity, derived from the genesis operation.
    #[must_use]
    pub fn did(&self) -> &DidPlc {
        &self.did
    }

    /// The Cid of the currently resolved head operation.
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// The verification methods (key id → `did:key`).
    #[must_use]
    pub fn verification_methods(&self) -> &BTreeMap<String, DidKey> {
        &self.verification_methods
    }

    /// The rotation keys, in authority order.
    #[must_use]
    pub fn rotation_keys(&self) -> &[DidKey] {
        &self.rotation_keys
    }

    /// The identity's aliases (`at://` handles).
    #[must_use]
    pub fn also_known_as(&self) -> &[String] {
        &self.also_known_as
    }

    /// The service endpoints (service id → endpoint).
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, Service> {
        &self.services
    }
}

/// Resolves a [`VerifiedAuditChain`] two ways, [`reported`](ChainResolver::reported)
/// (what the directory says) and [`canonical`](ChainResolver::canonical) (what
/// the protocol says), so the two can be compared. See the [module docs](self)
/// for the threat model.
#[derive(Debug, Clone, Copy)]
pub struct ChainResolver<'chain> {
    chain: &'chain VerifiedAuditChain,
}
impl<'chain> ChainResolver<'chain> {
    /// Wrap a verified chain for resolution.
    #[must_use]
    pub fn new(chain: &'chain VerifiedAuditChain) -> Self {
        Self { chain }
    }

    /// The state the directory reports as current: head = the last non-nullified
    /// operation (trusting the directory's `nullified` flags), projected to
    /// resolved state. This is what `/data` serves. Time-free.
    ///
    /// Safe to trust *only* when checked against [`canonical`](ChainResolver::canonical):
    /// a nullification the directory reports is backed by a real higher-authority
    /// recovery it cannot forge, but whether it reported them faithfully is
    /// `canonical`'s job.
    ///
    /// Returns the resolved state paired with the [`did:key`](DidKey) that signed
    /// the head operation. The signer is not part of [`ResolvedState`] (which
    /// mirrors the directory's signer-less `/data`); it is carried alongside so
    /// callers need not round-trip the head CID back through the chain. (Auditing
    /// attributes signers per op, so [`Baseline::audit`](crate::delta::Baseline::audit)
    /// does not consume this; it is a convenience for callers that want the live
    /// head's signer.)
    ///
    /// # Errors
    /// - [`ResolveError::Deactivated`] if the head is a `plc_tombstone`.
    /// - [`ResolveError::NoActiveOperation`] if every operation is nullified.
    /// - [`ResolveError::Projection`] if the head operation's fields are malformed.
    pub fn reported(&self) -> Result<(ResolvedState, DidKey), ResolveError> {
        let head = self.chain.entries().iter().rfind(|e| !e.nullified()).ok_or(ResolveError::NoActiveOperation)?;
        // A tombstone head deactivates the identity: there is no document state
        // to project.
        let operation = head.operation();
        match operation.operation_type() {
            Err(e) => Err(ResolveError::Projection(e.to_string())),
            Ok(OperationType::Tombstone) => Err(ResolveError::Deactivated),
            Ok(_) => Ok((ResolvedState::project(self.chain.did(), operation)?, head.signed_by().clone())),
        }
    }

    /// The state the protocol says should be current: the head recomputed from
    /// rotation-key authority at each fork point and the 72-hour window (from the
    /// log's `createdAt` deltas), ignoring the directory's `nullified` flags.
    /// This is the cryptographic ground truth that [`reported`](ChainResolver::reported)
    /// is checked against.
    ///
    /// Unlike `reported`, this is not time-free: the 72-hour window is what catches
    /// a directory that accepted an out-of-window recovery (which authority ranking
    /// alone would wave through). It needs no wall clock, only timestamp deltas
    /// within the log.
    ///
    /// The `createdAt` timestamps it reads are directory-asserted, the same trust
    /// tier as the `nullified` flags `reported` trusts. A directory that backdates
    /// an attacking op (so its window appears closed) defeats this check; catching
    /// that needs an observation timeline, which is beyond the scope of this core
    /// library.
    ///
    /// Like [`reported`](ChainResolver::reported), returns the resolved state
    /// paired with the [`did:key`](DidKey) that signed the canonical head operation.
    ///
    /// # Errors
    /// - [`ResolveError::Deactivated`] if the canonical head is a `plc_tombstone`.
    /// - [`ResolveError::NoActiveOperation`] if no operation survives.
    /// - [`ResolveError::Projection`] if the canonical head's fields are malformed.
    /// - [`ResolveError::Timestamp`] if an operation's `createdAt` is not RFC 3339.
    pub fn canonical(&self) -> Result<(ResolvedState, DidKey), ResolveError> {
        // Elect the canonical child of `fork_point` among `contestants` (children):
        // the op signed by the highest-authority key (lowest index in the
        // fork point's `rotationKeys`) that, where it supersedes the standing
        // branch, does so within the 72-hour window of the op it nullifies. Ties
        // (equal authority) and out-of-window recoveries leave the earlier op
        // standing. Returns `None` when there are no children (the head).
        fn elect_child<'entries>(
            fork_point: &AuditLogEntry<Checked>,
            contestants: &[&'entries AuditLogEntry<Checked>],
        ) -> Result<Option<&'entries AuditLogEntry<Checked>>, ResolveError> {
            let rotation_keys =
                fork_point.operation().rotation_keys().map_err(|e| ResolveError::Projection(e.to_string()))?;
            // Authority rank of a child's signer at the fork point; lower index
            // = higher authority. A signer absent from the set (impossible
            // post-verification) never wins.
            let rank = |entry: &AuditLogEntry<Checked>| {
                rotation_keys.iter().position(|k| k == entry.signed_by()).unwrap_or(usize::MAX)
            };
            // Resolve forks in (directory-asserted) submission order.
            let mut timed: Vec<(i64, &'entries AuditLogEntry<Checked>)> = contestants
                .iter()
                .map(|&c| Ok((created_at_ms(c.created_at())?, c)))
                .collect::<Result<_, ResolveError>>()?;
            timed.sort_by_key(|&(ms, _)| ms);
            let winner = timed
                .into_iter()
                .reduce(|(win_ts, winner), (cand_ts, candidate)| {
                    // A strictly higher-authority key supersedes the standing op,
                    // but only within 72h of it; a late recovery is rejected and
                    // the standing op keeps the branch.
                    if rank(candidate) < rank(winner) && cand_ts - win_ts <= RECOVERY_WINDOW_MS {
                        (cand_ts, candidate)
                    } else {
                        (win_ts, winner)
                    }
                })
                .map(|(_, winner)| winner);
            Ok(winner)
        }

        // Start at the genesis (the unique op with no `prev`), then walk the fork
        // DAG, electing the canonical child at each step by authority + window,
        // never reading the directory's `nullified` flags.
        let mut current = self
            .chain
            .entries()
            .iter()
            .find(|entry| matches!(entry.operation().prev(), Ok(None)))
            // We shouldn't ever get to this point. A verified audit chain
            // without a genesis operation? Codswallop!
            .ok_or(ResolveError::NoActiveOperation)?;
        while let Some(winner) = elect_child(current, &self.chain.children_of(current.cid()))? {
            current = winner;
        }
        let operation = current.operation();
        match operation.operation_type() {
            Err(e) => Err(ResolveError::Projection(e.to_string())),
            Ok(OperationType::Tombstone) => Err(ResolveError::Deactivated),
            Ok(_) => Ok((ResolvedState::project(self.chain.did(), operation)?, current.signed_by().clone())),
        }
    }

    /// Whether the directory's [`reported`](ChainResolver::reported) state agrees
    /// with the [`canonical`](ChainResolver::canonical) ground truth. This is the
    /// tool's central check.
    ///
    /// `false` is the tamper signal: the directory is serving a head the protocol
    /// does not support (e.g. a recovery it accepted outside the 72-hour window).
    /// Matching outcomes agree, including both resolving to no active operation
    /// (a tombstoned identity) or both failing the same way. Why they disagree
    /// is the (deferred) `diff` subsystem's job; this is only the yes/no.
    #[must_use]
    pub fn is_agreeable(&self) -> bool {
        // Compare the resolved *states* (the signer is a function of the head op,
        // which the state's `cid` already pins, so it adds nothing); `Err == Err`
        // keeps "both tombstoned/nullified" agreeable.
        self.reported().map(|(state, _)| state) == self.canonical().map(|(state, _)| state)
    }
}

/// Parse a directory `createdAt` (RFC 3339, UTC) to epoch milliseconds for window
/// comparison. The value is directory-asserted, the same trust tier as `nullified`.
fn created_at_ms(created_at: &str) -> Result<i64, ResolveError> {
    created_at
        .parse::<jiff::Timestamp>()
        .map(jiff::Timestamp::as_millisecond)
        .map_err(|e| ResolveError::Timestamp(format!("`{created_at}`: {e}")))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::audit::AuditLogEntry;
    use crate::operation::Signed;

    /// Build a chain from a `/log/audit` fixture via the `TryFrom` conversion.
    fn build_chain(chain_json: &str) -> VerifiedAuditChain {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(chain_json).unwrap();
        VerifiedAuditChain::try_from(entries).unwrap()
    }

    /// Assert a chain resolves to its directory `/data`. `/data` carries no operation
    /// CID, so the resolved head CID is grafted in to let the fixture deserialise;
    /// the document fields then confirm the correct (non-nullified) head was chosen.
    fn assert_resolves_to(chain_json: &str, data_json: &str) {
        let chain = build_chain(chain_json);
        let (resolved, _signer) = ChainResolver::new(&chain).reported().unwrap();

        let mut value: serde_json::Value = serde_json::from_str(data_json).unwrap();
        value["cid"] = serde_json::json!(resolved.cid().as_str());
        let expected: ResolvedState = serde_json::from_value(value).unwrap();
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolves_the_linear_chain_to_the_directory_data() {
        // The killer oracle: resolving the real chain reproduces the directory's
        // `/data`.
        assert_resolves_to(crate::test::TEST_AUDIT_CHAIN, crate::test::TEST_AUDIT_DATA);
    }

    #[test]
    fn resolves_a_genesis_only_chain_to_the_genesis_fields() {
        // A single-op chain resolves to the genesis op's own fields; it is the
        // head.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        let (resolved, _signer) = ChainResolver::new(&chain).reported().unwrap();
        assert_eq!(resolved.did(), &DidPlc::new(crate::test::TEST_DID_PLC).unwrap());
        assert_eq!(resolved.rotation_keys().len(), 2); // the genesis declares two
    }

    #[test]
    fn resolves_the_legacy_create_chain_to_the_directory_data() {
        // pfrazee: a `create` genesis (flat fields) followed by modern ops. The
        // DID is derived from the `create` op and the genesis is self-authorising;
        // `create` normalisation makes it resolve identically to a modern chain.
        let chain = build_chain(crate::test::TEST_LEGACY_CHAIN);
        assert_eq!(chain.did(), &DidPlc::new("did:plc:ragtjsm2j2vknwkz3zp4oxrd").unwrap());
        assert_resolves_to(crate::test::TEST_LEGACY_CHAIN, crate::test::TEST_LEGACY_DATA);
    }

    #[test]
    fn resolves_a_fork_to_the_surviving_branch() {
        // A real (benign) fork: two ops share parent op[1] (the DAG holds both).
        // The directory nullified the losing branch; resolution follows the flags
        // to the surviving head.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_FORK_CHAIN).unwrap();
        let chain = build_chain(crate::test::TEST_FORK_CHAIN);
        assert_eq!(chain.children_of(entries[1].cid()).len(), 2); // the fork is present...
        assert_resolves_to(crate::test::TEST_FORK_CHAIN, crate::test::TEST_FORK_DATA); // ...and resolves
    }

    #[test]
    fn resolves_the_interop_recovery_to_the_surviving_branch() {
        // The official did-method-plc vectors: a deep-`prev` recovery (op7,
        // `prev` → op1) nullifies ops 2..6; resolution lands on the surviving
        // recovery head.
        assert_resolves_to(crate::test::TEST_INTEROP_CHAIN, crate::test::TEST_INTEROP_DATA);
    }

    #[test]
    fn tombstone_chain_resolves_to_deactivated() {
        // The head is a `plc_tombstone`: the identity is deactivated, so there
        // is no resolved state (the directory reports the DID as "not available").
        let chain = build_chain(crate::test::TEST_TOMBSTONE_CHAIN);
        assert!(matches!(ChainResolver::new(&chain).reported(), Err(ResolveError::Deactivated)));
    }

    #[test]
    fn reported_pairs_the_state_with_the_head_signer() {
        // The returned signer is exactly the head entry's verified signer, obtained
        // without a CID round-trip through the chain.
        let chain = build_chain(crate::test::TEST_AUDIT_CHAIN);
        let (state, signer) = ChainResolver::new(&chain).reported().unwrap();
        assert_eq!(&signer, chain.get(state.cid()).unwrap().signed_by());
    }

    #[test]
    fn canonical_agrees_with_reported_for_honest_chains() {
        // For an honest directory the cryptographic recompute must match the
        // `nullified` flags for every fixture, the benign fork and the interop
        // recovery included.
        for chain_json in [
            crate::test::TEST_AUDIT_CHAIN,
            crate::test::TEST_LEGACY_CHAIN,
            crate::test::TEST_FORK_CHAIN,
            crate::test::TEST_INTEROP_CHAIN,
        ] {
            let chain = build_chain(chain_json);
            let r = ChainResolver::new(&chain);
            assert_eq!(r.canonical().unwrap(), r.reported().unwrap());
        }
        // The tombstone chain: both pathways agree the identity is deactivated.
        let tomb = build_chain(crate::test::TEST_TOMBSTONE_CHAIN);
        let r = ChainResolver::new(&tomb);
        assert!(matches!(r.canonical(), Err(ResolveError::Deactivated)));
        assert!(matches!(r.reported(), Err(ResolveError::Deactivated)));
    }

    #[test]
    fn canonical_diverges_when_a_recovery_is_out_of_window() {
        // Push the surviving recovery (op[3]) to well beyond 72h after the op
        // it nullified (op[2]). The directory's flags still elect op[3] (`reported`),
        // but `canonical` sees the recovery was out of window and leaves the
        // superseded branch standing; the two pathways diverge, which is exactly
        // the tamper signal. `createdAt` is envelope metadata, so editing it leaves
        // every signature and CID intact.
        let mut raw: Vec<serde_json::Value> = serde_json::from_str(crate::test::TEST_FORK_CHAIN).unwrap();
        raw[3]["createdAt"] = serde_json::json!("2026-01-10T00:00:00.000Z"); // op[2] is 2026-01-01
        let chain = build_chain(&serde_json::to_string(&raw).unwrap());

        let r = ChainResolver::new(&chain);
        assert_ne!(r.canonical().unwrap().0.cid(), r.reported().unwrap().0.cid());
    }

    #[test]
    fn is_agreeable_holds_for_honest_chains_and_fails_on_divergence() {
        // Every honest fixture agrees, the tombstone (both no-active-op) included.
        for chain_json in [
            crate::test::TEST_AUDIT_CHAIN,
            crate::test::TEST_LEGACY_CHAIN,
            crate::test::TEST_FORK_CHAIN,
            crate::test::TEST_INTEROP_CHAIN,
            crate::test::TEST_TOMBSTONE_CHAIN,
        ] {
            assert!(ChainResolver::new(&build_chain(chain_json)).is_agreeable());
        }
        // An out-of-window recovery: reported follows the flags, canonical does not.
        let mut raw: Vec<serde_json::Value> = serde_json::from_str(crate::test::TEST_FORK_CHAIN).unwrap();
        raw[3]["createdAt"] = serde_json::json!("2026-01-10T00:00:00.000Z");
        let chain = build_chain(&serde_json::to_string(&raw).unwrap());
        assert!(!ChainResolver::new(&chain).is_agreeable());
    }
}
