// SPDX-License-Identifier: MIT OR Apache-2.0
//! The structured difference between two [`ResolvedState`]s, a baseline and a
//! later observation.
//!
//! [`ChainResolver`] answers the directory-honesty axis (does the directory's
//! claim match the protocol's ground truth, in one fetch). This answers the
//! orthogonal baseline-vs-now axis: has the identity's document changed since
//! the user enrolled, and in what structural terms.
//!
//! The diff itself ([`ResolvedState::diff`]) is state-vs-state and key-agnostic:
//! it reports what changed, never how severe it is. Severity is the separate
//! classification step in this module, which folds in the key-aware context a bare
//! diff lacks: the user-controlled key set ([`Baseline::user_controlled_keys`]),
//! the contested op's signer, and the recovery window. Keeping `diff` pure and
//! pushing all key-awareness into classification is the deliberate split.
//!
//! Rotation-key order is semantic: a [`KeyOrderShift`](Delta::KeyOrderShift) demoting
//! a key matters as much as a removal, because nullification eligibility is decided
//! by a signer's index in `rotationKeys`. A diff that treated the key list as a
//! set would miss the demotion attack entirely.

use crate::audit::{AuditLogEntry, VerifiedAuditChain};
use crate::cid::Cid;
use crate::did::{Key as DidKey, Plc as DidPlc};
use crate::error::AuditError;
use crate::operation::Checked;
use crate::resolver::{ChainResolver, ResolvedState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single typed change between a baseline [`ResolvedState`] and an observed one.
///
/// The `type` tag serialises `snake_case` (`"key_added"`, `"signing_key_changed"`,
/// …) so the server can persist a `Vec<Delta>` as JSON. Each `key` is a `did:key`;
/// endpoints and handles are raw strings (`alsoKnownAs[0]` keeps its `at://` prefix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    /// A rotation key appeared that was absent from the baseline.
    KeyAdded {
        /// Absolute position in the observed `rotationKeys` array (lower = higher
        /// authority).
        index: usize,
        /// The `did:key` that appeared.
        key: DidKey,
    },
    /// A baseline rotation key is absent from the observed state. Key-agnostic:
    /// whether it was user-controlled (and the resulting severity split) is the
    /// server's call.
    KeyRemoved {
        /// The `did:key` that is no longer present.
        key: DidKey,
    },
    /// A rotation key present in both states changed its relative rank among the
    /// keys common to both, not the absolute-index shift an insertion or removal
    /// mechanically causes (those never emit a shift on their own).
    KeyOrderShift {
        /// The `did:key` whose relative rank changed.
        key: DidKey,
        /// Its rank among the common keys in the baseline.
        old: usize,
        /// Its rank among the common keys in the observed state.
        new: usize,
    },
    /// `verificationMethods["atproto"]` changed.
    SigningKeyChanged {
        /// Baseline signing key.
        from: DidKey,
        /// Observed signing key.
        to: DidKey,
    },
    /// `services["atproto_pds"].endpoint` changed.
    PdsEndpointChanged {
        /// Baseline endpoint.
        from: String,
        /// Observed endpoint.
        to: String,
    },
    /// `alsoKnownAs[0]` changed (the primary handle, `at://` prefix kept).
    HandleChanged {
        /// Baseline handle.
        from: String,
        /// Observed handle.
        to: String,
    },
}

impl ResolvedState {
    /// The structured diff from `self` to `observed`: the typed changes between
    /// two resolved states, in a stable order (rotation-key changes first, then
    /// signing key, PDS endpoint, handle). An empty `Vec` means no tracked field
    /// changed.
    ///
    /// Non-authoritative: a display primitive, not a tamper verdict. It is a net
    /// comparison of two snapshots, so it neither attributes a change to the operation
    /// (and signer) that made it nor sees an unauthorised op that a later op reverted.
    /// For the security verdict use [`Baseline::audit`], which attributes per
    /// operation over the chain. `diff` is reused internally by `audit` (per
    /// transition) and is fine for "what does my identity look like now versus
    /// my baseline" reporting.
    #[must_use]
    pub fn diff(&self, observed: &ResolvedState) -> Vec<Delta> {
        let mut deltas = Vec::new();

        let (base, obs) = (self.rotation_keys(), observed.rotation_keys());
        // Added: present in observed, absent from baseline (absolute index in
        // observed).
        for (index, key) in obs.iter().enumerate() {
            if !base.contains(key) {
                deltas.push(Delta::KeyAdded { index, key: key.clone() });
            }
        }
        // Removed: present in baseline, absent from observed.
        for key in base.iter().filter(|k| !obs.contains(k)) {
            deltas.push(Delta::KeyRemoved { key: key.clone() });
        }
        // Order shift: rank change among the keys common to both, so a pure
        // insertion/removal, which only shifts absolute indices, emits nothing
        // here.
        let obs_common: Vec<&DidKey> = obs.iter().filter(|k| base.contains(k)).collect();
        for (old, key) in base.iter().filter(|k| obs.contains(k)).enumerate() {
            let new = obs_common.iter().position(|k| *k == key).unwrap_or(old);
            if new != old {
                deltas.push(Delta::KeyOrderShift { key: key.clone(), old, new });
            }
        }

        // Signing key: verificationMethods["atproto"].
        if let (Some(from), Some(to)) =
            (self.verification_methods().get("atproto"), observed.verification_methods().get("atproto"))
            && from != to
        {
            deltas.push(Delta::SigningKeyChanged { from: from.clone(), to: to.clone() });
        }
        // PDS endpoint: services["atproto_pds"].endpoint.
        if let (Some(from), Some(to)) = (self.services().get("atproto_pds"), observed.services().get("atproto_pds"))
            && from.endpoint() != to.endpoint()
        {
            deltas.push(Delta::PdsEndpointChanged {
                from: from.endpoint().to_owned(),
                to: to.endpoint().to_owned(),
            });
        }
        // Handle: alsoKnownAs[0].
        if let (Some(from), Some(to)) = (self.also_known_as().first(), observed.also_known_as().first())
            && from != to
        {
            deltas.push(Delta::HandleChanged { from: from.clone(), to: to.clone() });
        }

        deltas
    }
}

/// A captured known-good [`ResolvedState`] plus the one piece of classification
/// context the resolved document cannot carry itself: which of its rotation keys
/// the user controls. This is what the CLI persists as its baseline and what a
/// later observation is classified against.
///
/// It composes [`ResolvedState`] rather than re-declaring its fields; the observed
/// side of a diff is also a bare `ResolvedState`, so the type is reused on both
/// sides. The document fields serialise [flattened](serde) alongside
/// `userControlledKeys`, so the persisted baseline is one flat camelCase object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Baseline {
    /// The resolved document captured at enrolment.
    #[serde(flatten)]
    state: ResolvedState,
    /// The rotation keys the user holds private keys for: the auto-rebaseline
    /// and severity discriminator. Usually a subset of `state.rotation_keys()`,
    /// but may be empty and may include keys the user has not added to the
    /// directory yet (everything intersects against the live arrays at
    /// classification time).
    user_controlled_keys: Vec<DidKey>,
}
impl Baseline {
    /// Capture `state` as a baseline, recording keys the user controls.
    /// `user_controlled_keys` is taken as given (the caller has already intersected
    /// its registry with the on-chain keys); it may be empty.
    #[must_use]
    pub fn new(state: ResolvedState, user_controlled_keys: Vec<DidKey>) -> Self {
        Self { state, user_controlled_keys }
    }

    /// The resolved state's [`did:plc`](crate::did::Plc): the identity the baseline
    /// commits to.
    #[must_use]
    pub fn did(&self) -> &DidPlc {
        self.state.did()
    }

    /// The captured resolved document.
    #[must_use]
    pub fn state(&self) -> &ResolvedState {
        &self.state
    }

    /// The user-controlled rotation keys recorded at capture (usually a subset
    /// of `state().rotation_keys()`; may be empty and may contain keys the user
    /// hasn't added to the directory yet).
    #[must_use]
    pub fn user_controlled_keys(&self) -> &[DidKey] {
        &self.user_controlled_keys
    }

    /// Record `key` as user-controlled, so a later change signed by it classifies
    /// as legitimate rather than tamper. Idempotent: returns `true` if `key` was
    /// newly added, `false` if it was already trusted.
    pub fn trust_key(&mut self, key: DidKey) -> bool {
        if self.user_controlled_keys.contains(&key) {
            return false;
        }
        self.user_controlled_keys.push(key);
        true
    }

    /// Drop `key` from the user-controlled set, so a later change signed by it is
    /// treated as tamper again. Idempotent: returns `true` if `key` was removed,
    /// `false` if it was not trusted. Removes every occurrence (a hand-edited
    /// baseline may carry duplicates).
    pub fn untrust_key(&mut self, key: &DidKey) -> bool {
        let before = self.user_controlled_keys.len();
        self.user_controlled_keys.retain(|k| k != key);
        before != self.user_controlled_keys.len()
    }

    /// Audit `chain` against this baseline: the sole tamper verdict.
    ///
    /// Authorisation in did:plc is per operation: each op carries one signature
    /// that authorises that op's changes. So a verdict cannot be read from a net
    /// snapshot diff plus a single (head) signer, which would launder a change
    /// made by an unauthorised op onto a later honest signer. `audit` composes
    /// the two axes: [`live_verdict`](Baseline::live_verdict) (is the current
    /// state authorised?) and the `mitigated_incidents` frontier scan (unauthorised
    /// post-baseline changes whose effect no longer persists), into an
    /// [`AuditReport`] of `{ live, mitigated }`.
    ///
    /// # Errors
    /// Propagates the fail-closed [`AuditError`]s of its two steps; treat any as
    /// an alert, never as clean: [`DirectoryDivergence`](AuditError::DirectoryDivergence),
    /// [`AnchorUnreachable`](AuditError::AnchorUnreachable), [`Projection`](AuditError::Projection).
    pub fn audit(&self, chain: &VerifiedAuditChain) -> Result<AuditReport, AuditError> {
        let live = self.live_verdict(chain)?;
        let mitigated = self.mitigated_incidents(chain, &live)?;
        Ok(AuditReport { live, mitigated })
    }

    /// The live axis of [`audit`](Baseline::audit): is the current reported state
    /// authorised?
    ///
    /// Gates on [`ChainResolver::is_agreeable`](crate::resolver::ChainResolver::is_agreeable)
    /// first (a dishonest directory is itself tamper, and makes the reported-path
    /// walk unsound), then walks the reported head's `prev`-ancestry back to this
    /// baseline's anchor, attributing each net surviving change to the op that
    /// set its current value, so a reverted change never counts and a persistent
    /// one is pinned to the op that made it, not the head signer.
    ///
    /// A net change with no attributable on-path op (reachable only for a relative
    /// [`KeyOrderShift`](Delta::KeyOrderShift) whose rank moved because other keys
    /// were added or removed around it) fails closed: it is treated as unauthorised,
    /// never silently blessed as legitimate.
    ///
    /// # Errors
    /// All fail-closed: [`DirectoryDivergence`](AuditError::DirectoryDivergence),
    /// [`AnchorUnreachable`](AuditError::AnchorUnreachable), or
    /// [`Projection`](AuditError::Projection).
    pub fn live_verdict(&self, chain: &VerifiedAuditChain) -> Result<Verdict, AuditError> {
        let resolver = ChainResolver::new(chain);
        // Gate once: a dishonest directory (reported != canonical) is itself
        // tamper, and makes the reported-path walk unsound, so short-circuit
        // before attributing anything. When it passes, reported == canonical,
        // so the reported ancestry is the protocol path.
        if !resolver.is_agreeable() {
            return Err(AuditError::DirectoryDivergence);
        }
        let (head_state, head_signer) = resolver.reported().map_err(|_| AuditError::AnchorUnreachable)?;

        // Walk the reported head's `prev`-ancestry back to the baseline anchor,
        // collecting the post-baseline ops in forward order. Reaching genesis
        // (or an unknown `prev`) without finding the anchor means the baseline
        // was superseded out from under us.
        let mut path: Vec<&AuditLogEntry<Checked>> = Vec::new();
        let mut cursor = chain.get(head_state.cid()).ok_or(AuditError::AnchorUnreachable)?;
        while cursor.cid() != self.state.cid() {
            path.push(cursor);
            // A `Checked` op's `prev` was validated when it entered the chain,
            // so it parses.
            let prev = cursor
                .operation()
                .prev()
                // Make sure the `prev` from the JSON is a valid CID.
                .map_err(|_| AuditError::AnchorUnreachable)?
                // If prev = None, we've hit the genesis operation without finding
                // the anchor, baseline is off the reported path.
                .ok_or(AuditError::AnchorUnreachable)?;
            cursor = chain.get(&prev).ok_or(AuditError::AnchorUnreachable)?;
        }
        // `path` now contains <baseline+1>..=head.
        path.reverse();

        // Forward fold: record, per tracked field, the last on-path op that changed
        // it, the op responsible for that field's current value. (Projection
        // failure is fatal, not skipped: a "poison op" must escalate, never
        // silently drop a change.)
        let mut setters = HashMap::new();
        let mut current = self.state.clone();
        for op in path {
            let next = ResolvedState::project(chain.did(), op.operation())
                .map_err(|e| AuditError::Projection(op.cid().clone(), e))?;
            for change in current.diff(&next) {
                setters.insert(FieldKey::of(&change), (op.cid().clone(), op.signed_by().clone()));
            }
            current = next;
        }

        // Live verdict: attribute each NET surviving change to its responsible
        // op, so a reverted change (absent from the net) never counts and a
        // persistent one is pinned to the op that made it, not the head signer.
        let live_changes: Vec<AttributedChange> = self
            .state
            .diff(&head_state)
            .into_iter()
            .map(|change| {
                let (op, signer, authorised) = match setters.get(&FieldKey::of(&change)) {
                    Some((op, signer)) => (op.clone(), signer.clone(), self.user_controlled_keys.contains(signer)),
                    // No on-path op set this field. Reachable only for a relative
                    // `KeyOrderShift` whose rank moved because *other* keys were
                    // added/removed around it, so no single op "made" it. Fail
                    // closed: attribute it to the head (where it manifests) but
                    // force `authorised = false`, so an unattributable change can
                    // never be silently blessed as legitimate.
                    None => (head_state.cid().clone(), head_signer.clone(), false),
                };
                let severity = change_severity(&change, &self.state, &head_state, &self.user_controlled_keys);
                AttributedChange { change, op, signer, authorised, severity }
            })
            .collect();
        let verdict = if live_changes.is_empty() {
            Verdict::Clean
        } else if live_changes.iter().all(|c| c.authorised) {
            Verdict::Legitimate { changes: live_changes }
        } else {
            Verdict::Tamper {
                severity: live_changes
                    .iter()
                    .filter(|c| !c.authorised)
                    .map(|c| c.severity)
                    .max()
                    .unwrap_or(Severity::Info),
                changes: live_changes,
            }
        };
        Ok(verdict)
    }

    /// The frontier scan behind [`audit`](Baseline::audit)'s `mitigated` axis:
    /// every unauthorised post-baseline change whose effect no longer persists,
    /// reverted later on the live path or on a nullified branch. A change "persists"
    /// iff it is the live setter for its field (the `(op, field)` pairs in `live`);
    /// everything else an unauthorised op touched is historical, so this catches
    /// both a linear revert and a recovered fork in one pass. The frontier is
    /// every op descended from the anchor across all branches (nullified recovery
    /// losers included), each transition diffed against its own parent.
    ///
    /// # Errors
    /// [`AuditError::Projection`] (fail-closed) if a frontier op cannot be projected.
    //
    // ponytail: re-projects on-path ops already projected by `audit` and walks
    // `prev` per entry O(n^2); fine for audit-log sizes (memoise the projections
    // if logs ever grow).
    fn mitigated_incidents(
        &self,
        chain: &VerifiedAuditChain,
        live: &Verdict,
    ) -> Result<Vec<AttributedChange>, AuditError> {
        /// Is `entry` a descendant of `anchor`? Reachable by walking `prev`.
        fn is_descendant_of(chain: &VerifiedAuditChain, entry: &AuditLogEntry<Checked>, anchor: &Cid) -> bool {
            let mut cursor = entry;
            while let Ok(Some(prev)) = cursor.operation().prev() {
                if prev == *anchor {
                    return true;
                }
                match chain.get(&prev) {
                    // Down, down, down the rabbit hole we go. Where does it lead?
                    // Nobody knows. Um, actually... it leads to the genesis
                    // operation. Or bust, I guess.
                    Some(parent) => cursor = parent,
                    // We reached genesis, entry ain't gonna be any lower than this.
                    None => return false,
                }
            }
            false
        }

        let live_fields: HashSet<(Cid, FieldKey)> =
            live.changes().iter().map(|c| (c.op.clone(), FieldKey::of(&c.change))).collect();
        let anchor = self.state.cid();
        let mut mitigated = Vec::new();
        for op in chain.entries() {
            if op.cid() == anchor || !is_descendant_of(chain, op, anchor) {
                continue;
            }
            let signer = op.signed_by();
            if self.user_controlled_keys.contains(signer) {
                continue; // authorised, never an incident
            }
            let op_state = ResolvedState::project(chain.did(), op.operation())
                .map_err(|e| AuditError::Projection(op.cid().clone(), e))?;
            // A descendant of the anchor always carries a `prev`; resolve its parent's state.
            let prev = op.operation().prev().ok().flatten().ok_or(AuditError::AnchorUnreachable)?;
            let parent_state = if prev == *anchor {
                self.state.clone()
            } else {
                let parent = chain.get(&prev).ok_or(AuditError::AnchorUnreachable)?;
                ResolvedState::project(chain.did(), parent.operation())
                    .map_err(|e| AuditError::Projection(parent.cid().clone(), e))?
            };
            for change in parent_state.diff(&op_state) {
                if live_fields.contains(&(op.cid().clone(), FieldKey::of(&change))) {
                    continue; // this change is the live verdict, not mitigated
                }
                let severity = change_severity(&change, &parent_state, &op_state, &self.user_controlled_keys);
                mitigated.push(AttributedChange {
                    change,
                    op: op.cid().clone(),
                    signer: signer.clone(),
                    authorised: false,
                    severity,
                });
            }
        }
        Ok(mitigated)
    }
}

/// The divergence severity ladder, ascending. The overall severity of a
/// multi-component divergence is the **maximum** across its components, so the
/// derived [`Ord`] (variant order = increasing severity) is load-bearing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Cosmetic / low-risk (e.g. a handle change).
    Info,
    /// Worth watching; not yet materially impactful.
    Suspicious,
    /// Likely needs action, but not identity seizure on its own.
    Warning,
    /// Threatens the user's override authority.
    Critical,
}

/// A single [`Delta`] bound to the operation that produced it and the verified
/// signer responsible: the unit of attribution an audit reports, so a change can
/// never be laundered onto the wrong signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributedChange {
    /// The change itself.
    pub change: Delta,
    /// The CID of the operation that produced the change.
    pub op: Cid,
    /// The verified key that signed that operation (its `signed_by()`).
    pub signer: DidKey,
    /// Whether `signer` is one of the baseline's user-controlled keys, i.e.
    /// whether the change was on-chain-authorised by the user.
    pub authorised: bool,
    /// The severity of this change (key-aware; see the per-component table).
    pub severity: Severity,
}

/// The authorisation of the current state, as decided by [`Baseline::audit`].
/// Each non-clean verdict carries the surviving [`changes`](AttributedChange) it
/// is about, every one attributed to the operation and signer responsible, so
/// the result is self-describing and a change can never be laundered onto the
/// wrong signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// No tracked field differs from the baseline.
    Clean,
    /// Every surviving change was signed by a user-controlled rotation key, all
    /// authorised.
    Legitimate {
        /// The (authorised) surviving changes, attributed.
        changes: Vec<AttributedChange>,
    },
    /// At least one surviving change was *not* signed by a user-controlled key.
    Tamper {
        /// The maximum severity across the **unauthorised** surviving changes.
        severity: Severity,
        /// All surviving changes (each flagged `authorised` or not).
        changes: Vec<AttributedChange>,
    },
}
impl Verdict {
    /// The changes the verdict is about; empty for [`Clean`](Verdict::Clean).
    #[must_use]
    pub fn changes(&self) -> &[AttributedChange] {
        match self {
            Verdict::Clean => &[],
            Verdict::Legitimate { changes } | Verdict::Tamper { changes, .. } => changes,
        }
    }
}

/// The result of [`Baseline::audit`](Baseline::audit): two orthogonal axes.
///
/// `live` is the verdict on the current served state: is what the directory
/// reports now authorised by the user? `mitigated` is the historical axis:
/// unauthorised operations that appeared since the baseline but no longer persist
/// (reverted on the live path, or on a nullified branch), surfaced so the operator
/// learns of an attack that was already undone, without it showing as a standing
/// live alarm. De-duplicating or acknowledging repeats across polls is the
/// (stateful) server's job; this report is pure and recomputed each time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    /// The authorisation verdict on the current reported state.
    pub live: Verdict,
    /// Unauthorised post-baseline changes that no longer persist in the current
    /// state.
    pub mitigated: Vec<AttributedChange>,
}

/// Identifies the tracked field (or the specific rotation key) a [`Delta`] concerns,
/// so an audit can record which operation last set that field's current value.
#[derive(PartialEq, Eq, Hash)]
enum FieldKey {
    Atproto,
    Pds,
    Handle,
    Key(DidKey),
}
impl FieldKey {
    fn of(change: &Delta) -> Self {
        match change {
            Delta::SigningKeyChanged { .. } => FieldKey::Atproto,
            Delta::PdsEndpointChanged { .. } => FieldKey::Pds,
            Delta::HandleChanged { .. } => FieldKey::Handle,
            Delta::KeyAdded { key, .. } | Delta::KeyRemoved { key } | Delta::KeyOrderShift { key, .. } => {
                FieldKey::Key(key.clone())
            },
        }
    }
}

/// The severity of one change, folding in the key-aware context a bare [`Delta`]
/// omits: the `baseline`/`observed` rotation arrays and the `user_keys` set.
fn change_severity(
    change: &Delta,
    baseline: &ResolvedState,
    observed: &ResolvedState,
    user_keys: &[DidKey],
) -> Severity {
    let is_user = |k: &DidKey| user_keys.iter().any(|u| u == k);
    match change {
        // A handle change is cosmetic; a real takeover co-occurs with key changes
        // that bite.
        Delta::HandleChanged { .. } => Severity::Info,
        // Each rated Warning on its own ("not identity seizure"); escalating a
        // signing-key + PDS co-occurrence into a content-takeover is a future
        // design choice.
        Delta::SigningKeyChanged { .. } | Delta::PdsEndpointChanged { .. } => Severity::Warning,
        // A key inserted at or above the user's highest-authority position outranks
        // them. `position` finds the first (lowest-index, highest-authority) user
        // key in `observed`.
        Delta::KeyAdded { index, .. } => match observed.rotation_keys().iter().position(is_user) {
            // Inserted at or above the user's top key.
            Some(min) if *index <= min => Severity::Critical,
            // Below the user's top key (or no user key present).
            _ => Severity::Suspicious,
        },
        // Demoting a user key is no worse than removing it (the key is still
        // held), so it mirrors the removal de-escalation below: Critical only
        // when no higher-authority user key survives the demotion, otherwise
        // Warning. A promotion, or a shift of a non-user key, is merely Suspicious.
        Delta::KeyOrderShift { key, old, new } => {
            if new <= old || !is_user(key) {
                // tl;dr: this delta always comes in pairs (one key cannot move
                // without changing the index of other keys). A key-shuffle that
                // doesn't touch a user's keys is benign.
                Severity::Suspicious
            } else {
                let demoted_index = observed.rotation_keys().iter().position(|k| k == key).unwrap_or(0);
                if observed.rotation_keys().iter().take(demoted_index).any(is_user) {
                    // A higher-authority user key still outranks it.
                    Severity::Warning
                } else {
                    // The user's top key was demoted.
                    Severity::Critical
                }
            }
        },
        // Removing the user's only or highest-authority key is Critical; Warning
        // when a still-superior user key survives; Suspicious when the removed
        // key was not the user's.
        Delta::KeyRemoved { key } => {
            if !is_user(key) {
                return Severity::Suspicious;
            }
            // `key` came from a `KeyRemoved` delta, so by construction it was in
            // the baseline this diff was taken against. The fallback is unreachable;
            // 0 (highest authority) is the fail-safe choice, since it makes
            // `superior_remains` false, i.e. Critical.
            let Some(removed_index) = baseline.rotation_keys().iter().position(|k| k == key) else {
                // A removed key must exist in the baseline if was diffed from it.
                // The fallback is unreachable. Return Severity::Info to satisfy
                // the type checker and prevent panicking, but this is a logic error.
                return Severity::Info;
            };
            // A higher-authority user key that itself survives into `observed`?
            let superior_remains = baseline
                .rotation_keys()
                .iter()
                .take(removed_index)
                .any(|k| is_user(k) && observed.rotation_keys().iter().any(|o| o == k));
            if superior_remains { Severity::Warning } else { Severity::Critical }
        },
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::resolver::ChainResolver;

    /// Build a `ResolvedState` from explicit fields, reusing a real `did:plc`
    /// and CID so the value types validate. `atproto`, `rotation`, `endpoint`,
    /// and `handle` are the knobs the diff tests turn. Lol, knob.
    fn state(did: &str, cid: &str, atproto: &str, rotation: &[&str], endpoint: &str, handle: &str) -> ResolvedState {
        let json = serde_json::json!({
            "did": did,
            "cid": cid,
            "verificationMethods": { "atproto": atproto },
            "rotationKeys": rotation,
            "alsoKnownAs": [handle],
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": endpoint } },
        });
        serde_json::from_value(json).unwrap()
    }

    /// A baseline plus three valid distinct `did:key`s and a valid CID, all
    /// pulled from a real resolved chain so the synthetic states deserialise.
    fn fixture() -> (ResolvedState, String, Vec<String>, String) {
        use crate::did::DidExt;
        let chain = {
            use crate::audit::{AuditLogEntry, VerifiedAuditChain};
            use crate::operation::Signed;
            let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
            VerifiedAuditChain::try_from(entries).unwrap()
        };
        let (base, _signer) = ChainResolver::new(&chain).reported().unwrap();
        let did = base.did().as_str().to_owned();
        let cid = base.cid().as_str().to_owned();
        let keys: Vec<String> = base.rotation_keys().iter().map(|k| k.as_str().to_owned()).collect();
        (base, did, keys, cid)
    }

    #[test]
    fn identical_states_have_no_delta() {
        let (base, _, _, _) = fixture();
        assert!(base.diff(&base).is_empty());
    }

    #[test]
    fn detects_signing_key_pds_and_handle_changes() {
        let (_, did, keys, cid) = fixture();
        let k: Vec<&str> = keys.iter().map(String::as_str).collect();
        let base = state(&did, &cid, k[0], &k, "https://pds.one", "at://alice.test");
        let obs = state(&did, &cid, k[1], &k, "https://pds.two", "at://bob.test");

        let deltas = base.diff(&obs);
        assert!(deltas.contains(&Delta::SigningKeyChanged {
            from: DidKey::new(k[0]).unwrap(),
            to: DidKey::new(k[1]).unwrap(),
        }));
        assert!(deltas.contains(&Delta::PdsEndpointChanged {
            from: "https://pds.one".to_owned(),
            to: "https://pds.two".to_owned(),
        }));
        assert!(deltas.contains(&Delta::HandleChanged {
            from: "at://alice.test".to_owned(),
            to: "at://bob.test".to_owned(),
        }));
    }

    #[test]
    fn detects_added_and_removed_rotation_keys() {
        let (_, did, keys, cid) = fixture();
        let k: Vec<&str> = keys.iter().map(String::as_str).collect();
        // Baseline has both keys; observed drops k[1] and adds the attacker
        // key on top.
        let attacker = crate::test::TEST_DID_KEY_ATTACKER;
        let base = state(&did, &cid, k[0], &k, "https://pds", "at://a.test");
        let obs = state(&did, &cid, k[0], &[attacker, k[0]], "https://pds", "at://a.test");

        let deltas = base.diff(&obs);
        assert!(deltas.contains(&Delta::KeyAdded {
            index: 0,
            key: DidKey::new(attacker).unwrap()
        }));
        assert!(deltas.contains(&Delta::KeyRemoved { key: DidKey::new(k[1]).unwrap() }));
        // A pure add/remove must NOT manufacture an order shift for the surviving key.
        assert!(!deltas.iter().any(|d| matches!(d, Delta::KeyOrderShift { .. })));
    }

    #[test]
    fn order_shift_fires_on_relative_rank_change_only() {
        let (_, did, keys, cid) = fixture();
        let k: Vec<&str> = keys.iter().map(String::as_str).collect();
        // Same two keys, swapped order: each changes relative rank among the
        // common set.
        let base = state(&did, &cid, k[0], &[k[0], k[1]], "https://pds", "at://a.test");
        let obs = state(&did, &cid, k[0], &[k[1], k[0]], "https://pds", "at://a.test");

        let deltas = base.diff(&obs);
        let shifts: Vec<_> = deltas.iter().filter(|d| matches!(d, Delta::KeyOrderShift { .. })).collect();
        assert_eq!(shifts.len(), 2);
        assert!(deltas.contains(&Delta::KeyOrderShift {
            key: DidKey::new(k[0]).unwrap(),
            old: 0,
            new: 1
        }));
        assert!(deltas.contains(&Delta::KeyOrderShift {
            key: DidKey::new(k[1]).unwrap(),
            old: 1,
            new: 0
        }));
        // Order-only change: no add/remove.
        assert!(!deltas.iter().any(|d| matches!(d, Delta::KeyAdded { .. } | Delta::KeyRemoved { .. })));
    }

    #[test]
    fn delta_round_trips_through_json() {
        let delta = Delta::KeyOrderShift {
            key: DidKey::new(crate::test::TEST_DID_KEY_ATTACKER).unwrap(),
            old: 0,
            new: 1,
        };
        let json = serde_json::to_string(&delta).unwrap();
        assert!(json.contains("\"type\":\"key_order_shift\""));
        assert_eq!(serde_json::from_str::<Delta>(&json).unwrap(), delta);
    }

    #[test]
    fn trust_and_untrust_key_are_idempotent() {
        let (state, _, keys, _) = fixture();
        let mut baseline = Baseline::new(state, vec![]);
        let key = DidKey::new(&keys[0]).unwrap();

        // trust: newly added, then a no-op.
        assert!(baseline.trust_key(key.clone()));
        assert!(!baseline.trust_key(key.clone()));
        assert_eq!(baseline.user_controlled_keys(), std::slice::from_ref(&key));

        // untrust: removed, then a no-op.
        assert!(baseline.untrust_key(&key));
        assert!(!baseline.untrust_key(&key));
        assert!(baseline.user_controlled_keys().is_empty());
    }

    #[test]
    fn baseline_round_trips_as_one_flat_object() {
        let (state, _, keys, _) = fixture();
        let user: Vec<DidKey> = keys.iter().map(|k| DidKey::new(k).unwrap()).collect();
        let baseline = Baseline::new(state.clone(), user.clone());

        // The document fields flatten alongside `userControlledKeys`, one flat
        // object, no nested `state`, all camelCase.
        let json = serde_json::to_value(&baseline).unwrap();
        assert!(json.get("state").is_none()); // flattened, not nested
        assert!(json.get("did").is_some() && json.get("rotationKeys").is_some()); // document fields at top level
        assert!(json.get("userControlledKeys").is_some()); // …alongside the camelCase annotation

        // Round-trips, and the accessors expose the composed state + recorded keys.
        let back: Baseline = serde_json::from_value(json).unwrap();
        assert_eq!(back, baseline);
        assert_eq!(back.state(), &state);
        assert_eq!(back.user_controlled_keys(), user.as_slice());
    }

    #[test]
    fn severity_orders_ascending() {
        assert!(Severity::Info < Severity::Suspicious);
        assert!(Severity::Suspicious < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
        // The max-reducer relies on this: the worst component wins.
        assert_eq!([Severity::Info, Severity::Critical, Severity::Warning].into_iter().max(), Some(Severity::Critical));
    }

    #[test]
    fn verdict_round_trips_through_json() {
        let v = Verdict::Tamper {
            severity: Severity::Critical,
            changes: vec![AttributedChange {
                change: Delta::KeyRemoved {
                    key: DidKey::new(crate::test::TEST_DID_KEY_ATTACKER).unwrap(),
                },
                op: Cid::unchecked("bafyreiguelocxy4pl2ubhdruqp3tgi3lf27k6l7zm5vbvzpq7zxubbp5vu"),
                signer: DidKey::new(crate::test::TEST_DID_KEY_ATTACKER).unwrap(),
                authorised: false,
                severity: Severity::Critical,
            }],
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"verdict\":\"tamper\"") && json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"type\":\"key_removed\"")); // the attributed change serialises inline
        assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
        assert_eq!(serde_json::to_string(&Verdict::Clean).unwrap(), "{\"verdict\":\"clean\"}");
    }

    #[test]
    fn change_severity_covers_every_component() {
        let (_, did, keys, cid) = fixture();
        let k: Vec<&str> = keys.iter().map(String::as_str).collect(); // k[0..3]: 3 distinct keys
        let extra = crate::test::TEST_DID_KEY_OPERATOR; // a 4th distinct, valid did:key

        // Drive `change_severity` directly (it is private to this module): build
        // a single rotation-key change with every other field held equal, then
        // read back the max severity  across the resulting deltas, the severity
        // that op's transition would contribute.
        let sev = |base_rot: &[&str], user: &[&str], obs_rot: &[&str]| -> Severity {
            let baseline = state(&did, &cid, k[0], base_rot, "https://pds", "at://a.test");
            let observed = state(&did, &cid, k[0], obs_rot, "https://pds", "at://a.test");
            let user_keys: Vec<DidKey> = user.iter().map(|u| DidKey::new(*u).unwrap()).collect();
            baseline.diff(&observed).iter().map(|c| change_severity(c, &baseline, &observed, &user_keys)).max().unwrap()
        };

        // KeyAdded: at/above the user's top key → Critical; below it → Suspicious.
        assert_eq!(sev(&[k[1]], &[k[1]], &[extra, k[1]]), Severity::Critical);
        assert_eq!(sev(&[k[1]], &[k[1]], &[k[1], extra]), Severity::Suspicious);

        // KeyRemoved: user's only key → Critical; non-user key → Suspicious; a
        // superior user key survives → Warning.
        assert_eq!(sev(&[k[0], k[1]], &[k[1]], &[k[0]]), Severity::Critical);
        assert_eq!(sev(&[k[0], k[1]], &[k[0]], &[k[0]]), Severity::Suspicious);
        assert_eq!(sev(&[k[0], k[1], k[2]], &[k[0], k[2]], &[k[0], k[1]]), Severity::Warning);

        // KeyOrderShift, the asymmetry fix: a demotion now mirrors the removal
        // de-escalation. Top user key demoted → Critical; demoted but a superior
        // user key remains → Warning; a promotion or a non-user-key shift → Suspicious.
        assert_eq!(sev(&[k[1], k[0]], &[k[1]], &[k[0], k[1]]), Severity::Critical);
        assert_eq!(sev(&[k[0], k[2], k[1]], &[k[0], k[2]], &[k[0], k[1], k[2]]), Severity::Warning);
        assert_eq!(sev(&[k[1], k[2]], &[k[0]], &[k[2], k[1]]), Severity::Suspicious);

        // Demoting a key is never rated worse than removing the same key in the
        // same context.
        let demote = sev(&[k[0], k[2], k[1]], &[k[0], k[2]], &[k[0], k[1], k[2]]); // k[2] demoted
        let remove = sev(&[k[0], k[2], k[1]], &[k[0], k[2]], &[k[0], k[1]]); // k[2] removed
        assert!(demote <= remove, "demotion ({demote:?}) must not exceed removal ({remove:?})");

        // Non-key components: handle → Info, signing key → Warning (no key context
        // needed).
        let plain = |atproto: &str, handle: &str| {
            let baseline = state(&did, &cid, k[0], &k, "https://pds", "at://a.test");
            let observed = state(&did, &cid, atproto, &k, "https://pds", handle);
            baseline.diff(&observed).iter().map(|c| change_severity(c, &baseline, &observed, &[])).max().unwrap()
        };
        assert_eq!(plain(k[0], "at://b.test"), Severity::Info); // handle only
        assert_eq!(plain(k[1], "at://a.test"), Severity::Warning); // signing key only
    }

    // audit (the per-op attribution verdict)

    use crate::crypto::{KeyPair, PrivateKey};
    use crate::did::DidExt;
    use crate::operation::{Operation, Signed, Unsigned};
    use serde_json::{Value, json};

    /// A valid `did:key` for the `atproto` verification method (never used to
    /// sign here).
    const ATPROTO: &str = crate::test::TEST_DID_KEY_OPERATOR;

    /// Sign an operation `fields` value (no `sig`) with `key`, returning the signed
    /// wire value and its CID string, the two pieces an audit-log envelope needs.
    fn sign_op(fields: Value, key: &PrivateKey) -> (Value, String) {
        let checked = Operation::<Unsigned>::from_value(fields).unwrap().sign(key).unwrap();
        let cid = checked.cid().unwrap().as_str().to_owned();
        (checked.value().clone(), cid)
    }

    /// One `/log/audit` envelope around a signed operation (consumes `operation`).
    fn envelope(operation: Value, cid: &str, nullified: bool, created_at: &str) -> Value {
        let mut map = serde_json::Map::new();
        map.insert("operation".to_owned(), operation);
        map.insert("cid".to_owned(), json!(cid));
        map.insert("nullified".to_owned(), json!(nullified));
        map.insert("createdAt".to_owned(), json!(created_at));
        Value::Object(map)
    }

    /// Verify a hand-built `/log/audit` array into a chain.
    fn chain_of(entries: Vec<Value>) -> VerifiedAuditChain {
        let signed: Vec<AuditLogEntry<Signed>> = serde_json::from_value(Value::Array(entries)).unwrap();
        VerifiedAuditChain::try_from(signed).unwrap()
    }

    /// A standard `plc_operation` value with the given fields (no `sig`).
    fn op(prev: Option<&str>, rotation: &[&str], handle: &str, pds: &str) -> Value {
        json!({
            "type": "plc_operation",
            "prev": prev,
            "rotationKeys": rotation,
            "verificationMethods": { "atproto": ATPROTO },
            "alsoKnownAs": [handle],
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": pds } },
        })
    }

    /// Project a chain entry by receipt index into a baseline-able resolved state.
    fn state_at(chain: &VerifiedAuditChain, index: usize) -> ResolvedState {
        ResolvedState::project(chain.did(), chain.entries()[index].operation()).unwrap()
    }

    #[test]
    fn audit_flags_a_masked_attacker_op_as_tamper() {
        // The headline regression: op A (non-user signer) adds an attacker key,
        // op B (user signer) makes a benign change and becomes head. The old
        // net-diff+head-signer classify laundered A onto B's signature; per-op
        // attribution pins the key-add to A.
        let user = KeyPair::generate();
        let other = KeyPair::generate(); // on-chain rotation key the user does NOT control
        let attacker = KeyPair::generate(); // the key op A inserts
        let g_rot = [user.1.as_str(), other.1.as_str()];
        let attacked_rot = [attacker.1.as_str(), user.1.as_str(), other.1.as_str()];

        let (g, g_cid) = sign_op(op(None, &g_rot, "at://alice.example", "https://pds.one"), &user.0);
        let (a, a_cid) = sign_op(op(Some(&g_cid), &attacked_rot, "at://alice.example", "https://pds.one"), &other.0);
        let (b, b_cid) = sign_op(op(Some(&a_cid), &attacked_rot, "at://bob.example", "https://pds.one"), &user.0);
        let chain = chain_of(vec![
            envelope(g, &g_cid, false, "2025-01-01T00:00:00.000Z"),
            envelope(a, &a_cid, false, "2025-01-02T00:00:00.000Z"),
            envelope(b, &b_cid, false, "2025-01-03T00:00:00.000Z"),
        ]);

        let baseline = Baseline::new(state_at(&chain, 0), vec![user.1.clone()]);
        let report = baseline.audit(&chain).unwrap();
        let Verdict::Tamper { severity, changes } = &report.live else {
            panic!("expected tamper")
        };
        assert_eq!(*severity, Severity::Critical); // the key inserted above the user's key

        // The attacker key-add is attributed to op A (signed by `other`), unauthorised.
        let added = changes.iter().find(|c| matches!(c.change, Delta::KeyAdded { .. })).unwrap();
        assert!(!added.authorised);
        assert_eq!(added.signer, other.1);
        assert_eq!(added.op.as_str(), a_cid);
        // The handle change is attributed to op B (the user), authorised.
        let handle = changes.iter().find(|c| matches!(c.change, Delta::HandleChanged { .. })).unwrap();
        assert!(handle.authorised);
        assert_eq!(handle.signer, user.1);
        // The attack persists in the current state, so it is live tamper, not a
        // mitigated incident.
        assert!(report.mitigated.is_empty());
    }

    #[test]
    fn audit_linear_mistake_then_undo_is_clean() {
        // Regression for the per-transition bug: a non-user key changes the PDS
        // and a later non-user op reverts it, linearly. Net == baseline, so the
        // live verdict is Clean, but the (since-reverted) hijack still surfaces
        // as a mitigated incident.
        let user = KeyPair::generate();
        let other = KeyPair::generate();
        let rot = [user.1.as_str(), other.1.as_str()];

        let (g, g_cid) = sign_op(op(None, &rot, "at://alice.example", "https://pds.one"), &user.0);
        let (m, m_cid) = sign_op(op(Some(&g_cid), &rot, "at://alice.example", "https://pds.evil"), &other.0);
        let (u, u_cid) = sign_op(op(Some(&m_cid), &rot, "at://alice.example", "https://pds.one"), &other.0);
        let chain = chain_of(vec![
            envelope(g, &g_cid, false, "2025-01-01T00:00:00.000Z"),
            envelope(m, &m_cid, false, "2025-01-02T00:00:00.000Z"),
            envelope(u, &u_cid, false, "2025-01-03T00:00:00.000Z"),
        ]);

        let baseline = Baseline::new(state_at(&chain, 0), vec![user.1.clone()]);
        let report = baseline.audit(&chain).unwrap();
        assert_eq!(report.live, Verdict::Clean); // net == baseline → no standing alarm

        // The non-user PDS hijack (op `m`), reverted on the live path, is a
        // mitigated incident.
        let hijack = report
            .mitigated
            .iter()
            .find(|c| matches!(&c.change, Delta::PdsEndpointChanged { to, .. } if to == "https://pds.evil"))
            .expect("the reverted hijack is surfaced");
        assert_eq!(hijack.op.as_str(), m_cid);
        assert_eq!(hijack.signer, other.1);
        assert!(!hijack.authorised);
    }

    #[test]
    fn audit_recovered_fork_is_clean_with_a_mitigated_incident() {
        // A non-user op hijacks the PDS on a branch the user recovers from (a
        // higher-authority user op forking from the same parent). The directory
        // nullifies the attacker branch, so the live state is Clean, but the
        // nullified attack still surfaces under `mitigated`.
        let user = KeyPair::generate();
        let other = KeyPair::generate();
        let rot = [user.1.as_str(), other.1.as_str()]; // user at index 0 = higher authority

        let (g, g_cid) = sign_op(op(None, &rot, "at://alice.example", "https://pds.one"), &user.0);
        // attacker forks from g, hijacks the PDS; later nullified.
        let (atk, atk_cid) = sign_op(op(Some(&g_cid), &rot, "at://alice.example", "https://pds.evil"), &other.0);
        // recovery forks from g too (higher-authority user key), restoring the original; survives.
        let (rec, rec_cid) = sign_op(op(Some(&g_cid), &rot, "at://alice.example", "https://pds.one"), &user.0);
        let chain = chain_of(vec![
            envelope(g, &g_cid, false, "2025-01-01T00:00:00.000Z"),
            envelope(atk, &atk_cid, true, "2025-01-02T00:00:00.000Z"), // nullified loser
            envelope(rec, &rec_cid, false, "2025-01-02T06:00:00.000Z"), // within 72h, higher authority
        ]);

        let baseline = Baseline::new(state_at(&chain, 0), vec![user.1.clone()]);
        let report = baseline.audit(&chain).unwrap();
        assert_eq!(report.live, Verdict::Clean);

        // The nullified attacker op is surfaced as a mitigated incident.
        let incident = report.mitigated.iter().find(|c| c.op.as_str() == atk_cid).expect("nullified attack surfaced");
        assert_eq!(incident.signer, other.1);
        assert!(matches!(incident.change, Delta::PdsEndpointChanged { .. }));
        assert!(!incident.authorised);
    }

    #[test]
    fn audit_honest_chain_against_its_head_is_clean() {
        // The real chain, baselined at its own reported head → net empty → Clean.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let chain = VerifiedAuditChain::try_from(entries).unwrap();
        let (head, _) = ChainResolver::new(&chain).reported().unwrap();
        assert_eq!(Baseline::new(head, vec![]).audit(&chain).unwrap().live, Verdict::Clean);
    }

    #[test]
    fn audit_rejects_a_diverging_directory() {
        // Out-of-window recovery: the directory's reported head ≠ canonical → fail closed.
        let mut raw: Vec<Value> = serde_json::from_str(crate::test::TEST_FORK_CHAIN).unwrap();
        raw[3]["createdAt"] = json!("2026-01-10T00:00:00.000Z"); // op[2] is 2026-01-01
        let chain = chain_of(raw);
        let (head, _) = ChainResolver::new(&chain).reported().unwrap();
        assert_eq!(Baseline::new(head, vec![]).audit(&chain), Err(AuditError::DirectoryDivergence));
    }

    #[test]
    fn audit_errors_when_the_anchor_is_off_the_reported_path() {
        // The benign fork's op[2] is nullified: a dead-branch sibling of the
        // surviving head. A baseline anchored there is unreachable by walking
        // the reported head's `prev`.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_FORK_CHAIN).unwrap();
        let chain = VerifiedAuditChain::try_from(entries).unwrap();
        let baseline = Baseline::new(state_at(&chain, 2), vec![]); // entries[2] is the nullified op
        assert_eq!(baseline.audit(&chain), Err(AuditError::AnchorUnreachable));
    }

    #[test]
    fn audit_fails_closed_on_an_unprojectable_intermediate_op() {
        // A "poison op": sig-valid (so it enters the chain; `add` only checks
        // rotation keys) but its `services` is malformed, so `project` fails.
        // As an intermediate op it must surface as Projection, never be skipped.
        let user = KeyPair::generate();
        let rot = [user.1.as_str()];
        let (g, g_cid) = sign_op(op(None, &rot, "at://alice.example", "https://pds.one"), &user.0);
        // op1: malformed `services` (no endpoint), verifies but won't project.
        let poison = json!({
            "type": "plc_operation", "prev": g_cid, "rotationKeys": rot,
            "verificationMethods": { "atproto": ATPROTO }, "alsoKnownAs": ["at://alice.example"],
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer" } },
        });
        let (p, p_cid) = sign_op(poison, &user.0);
        let (h, h_cid) = sign_op(op(Some(&p_cid), &rot, "at://bob.example", "https://pds.one"), &user.0);
        let chain = chain_of(vec![
            envelope(g, &g_cid, false, "2025-01-01T00:00:00.000Z"),
            envelope(p, &p_cid, false, "2025-01-02T00:00:00.000Z"),
            envelope(h, &h_cid, false, "2025-01-03T00:00:00.000Z"),
        ]);

        let baseline = Baseline::new(state_at(&chain, 0), vec![user.1.clone()]);
        assert!(matches!(baseline.audit(&chain), Err(AuditError::Projection(cid, _)) if cid.as_str() == p_cid));
    }

    #[test]
    fn audit_fails_closed_on_an_unattributable_key_order_shift() {
        // A relative `KeyOrderShift` can orphan: a key's rank moves because
        // *other* keys shift around it (here `A` is removed, then re-added in
        // front of `user`), with no op directly shifting `user`, so no on-path
        // setter exists. Even though every op is user-signed, an unattributable
        // net change must fail closed to Tamper, never be blessed as legitimate.
        let user = KeyPair::generate();
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let full = [user.1.as_str(), a.1.as_str(), b.1.as_str()];
        let without_a = [user.1.as_str(), b.1.as_str()];
        let a_in_front = [a.1.as_str(), user.1.as_str(), b.1.as_str()];

        let (g, g_cid) = sign_op(op(None, &full, "at://alice.example", "https://pds.one"), &user.0);
        let (o1, o1_cid) = sign_op(op(Some(&g_cid), &without_a, "at://alice.example", "https://pds.one"), &user.0);
        let (o2, o2_cid) = sign_op(op(Some(&o1_cid), &a_in_front, "at://alice.example", "https://pds.one"), &user.0);
        let chain = chain_of(vec![
            envelope(g, &g_cid, false, "2025-01-01T00:00:00.000Z"),
            envelope(o1, &o1_cid, false, "2025-01-02T00:00:00.000Z"),
            envelope(o2, &o2_cid, false, "2025-01-03T00:00:00.000Z"),
        ]);

        let baseline = Baseline::new(state_at(&chain, 0), vec![user.1.clone()]);
        let Verdict::Tamper { changes, .. } = baseline.audit(&chain).unwrap().live else {
            panic!("an unattributable shift must fail closed to Tamper");
        };
        // The user key's relative demotion has no on-path setter → attributed
        // to the head, forced unauthorised (conservative; this errs toward
        // alerting on an all-user reorder).
        let orphan = changes
            .iter()
            .find(|c| matches!(&c.change, Delta::KeyOrderShift { key, .. } if *key == user.1))
            .expect("the orphan shift is surfaced");
        assert!(!orphan.authorised);
        assert_eq!(orphan.op.as_str(), o2_cid);
    }
}
