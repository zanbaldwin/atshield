// SPDX-License-Identifier: MIT OR Apache-2.0
//! A did:plc audit log (`/log/audit`): its individual [`AuditLogEntry`] and the
//! authority-checked [`VerifiedAuditChain`] over them.

use crate::cid::Cid;
use crate::did::{Key as DidKey, Plc as DidPlc};
use crate::encoding;
use crate::error::VerifyError;
use crate::operation::{Checked, Operation, SigExt, Signed};
use serde::{Deserialize, Deserializer};

/// One element of the directory's `/log/audit` array: a signed operation plus the
/// envelope metadata the directory wraps it in (its CID, nullification flag, and
/// timestamp).
///
/// The state parameter `S` tracks the wrapped [`operation`](AuditLogEntry::operation)'s
/// verification state: an [`AuditLogEntry<Signed>`] is observed (carries a signature,
/// unverified), and
/// [`verify`](AuditLogEntry::verify) lifts it to an [`AuditLogEntry<Checked>`].
#[derive(Debug, Clone, PartialEq)]
pub struct AuditLogEntry<S: SigExt = Signed> {
    /// The signed operation.
    operation: Operation<S>,
    /// The directory's reported CID for `operation`.
    cid: Cid,
    /// Whether this operation was nullified by a later recovery fork.
    nullified: bool,
    /// The directory's wire `createdAt` timestamp, kept as a loose string.
    created_at: String,
}
// Deserialize is implemented for `AuditLogEntry<Signed>` *only*: an observed entry
// always carries a signature, and a `Checked` entry must be earned through `verify`,
// never forged from untrusted JSON.
impl<'de> Deserialize<'de> for AuditLogEntry<Signed> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The wire object also carries `did`, which we deliberately do **not**
        // capture: the real DID is derived from the genesis operation in the chain.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            operation: Operation<Signed>,
            cid: Cid,
            nullified: bool,
            created_at: String,
        }
        let Wire { operation, cid, nullified, created_at } = Wire::deserialize(deserializer)?;
        Ok(Self { operation, cid, nullified, created_at })
    }
}

impl<S: SigExt> AuditLogEntry<S> {
    /// The operation this entry wraps (`Signed` as observed, `Checked` once verified).
    #[must_use]
    pub fn operation(&self) -> &Operation<S> {
        &self.operation
    }

    /// The directory's reported CID for the operation.
    #[must_use]
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// Whether this operation was nullified by a later recovery fork.
    ///
    /// Informational only, as reported by the PLC directory. Do not rely on it
    /// for security.
    #[must_use]
    pub fn nullified(&self) -> bool {
        self.nullified
    }

    /// The wire `createdAt` timestamp (loose string).
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// Whether the operation's recomputed CID matches the directory's reported
    /// [`cid`](AuditLogEntry::cid).
    ///
    /// The per-entry integrity check the chain runs before trusting the reported
    /// linkage. A CID that cannot be computed counts as no match (`false`).
    #[must_use]
    pub fn cid_matches(&self) -> bool {
        self.operation.cid().is_ok_and(|computed| computed == self.cid)
    }
}

impl AuditLogEntry<Signed> {
    /// Verify the entry: confirm the operation hashes to the directory's reported
    /// [`cid`](AuditLogEntry::cid), then verify its signature against `key`. On
    /// success the entry is lifted to [`AuditLogEntry<Checked>`].
    ///
    /// `key` is the authorising rotation key the chain supplies. Verifying the
    /// *signature* is not the same as *authorising* it. The chain still checks
    /// that `key` is an authorised rotation key: for an additive op, one in the
    /// previous operation's rotation set; for a genesis op, one it declares itself.
    ///
    /// # Errors
    /// - [`VerifyError::InvalidChain`] if the operation does not hash to the
    ///   reported CID.
    /// - Any [`VerifyError`] from [`Operation::verify`]:
    ///   - [`Encode`](VerifyError::Encode) if the signing input cannot be encoded,
    ///   - [`SignatureDecode`](VerifyError::SignatureDecode) or
    ///     [`MalformedSignature`](VerifyError::MalformedSignature) if the `sig`
    ///     is unreadable, or
    ///   - [`SignatureInvalid`](VerifyError::SignatureInvalid) if it does not
    ///     verify against `key`.
    pub fn verify(&self, key: &DidKey) -> Result<AuditLogEntry<Checked>, VerifyError> {
        if !self.cid_matches() {
            return Err(VerifyError::InvalidChain(
                "operation does not hash to the directory's reported CID".to_owned(),
            ));
        }
        Ok(AuditLogEntry {
            operation: self.operation.verify(key)?,
            cid: self.cid.clone(),
            nullified: self.nullified,
            created_at: self.created_at.clone(),
        })
    }
}

impl AuditLogEntry<Checked> {
    /// The public key this entry's signature was verified against.
    #[must_use]
    pub fn signed_by(&self) -> &DidKey {
        self.operation.signed_by()
    }
}

/// A verified, authority-checked chain of did:plc operations for one identity:
/// the authority layer over [`AuditLogEntry`].
///
/// An [`AuditLogEntry`] verifies its own signature against a key the caller supplies,
/// but cannot know whether that key was allowed to sign. This type answers that:
/// it walks the directory's `/log/audit` array in order, checking each operation's
/// signing key against the rotation keys that authorise it. The identity's
/// [`did:plc`](DidPlc) is derived from the genesis, never trusted from the wire
/// `did`.
///
/// It holds that derived [`did:plc`](DidPlc) and the passing operations, every
/// element an [`AuditLogEntry<Checked>`] so the type system records that nothing
/// reaches the collection unverified. They are kept in receipt order (genesis
/// first); the active head is resolved by `prev`-linkage, not by list position
/// (see below).
///
/// # Forking
/// An operation's `prev` is the CID of some prior operation. Normally that is the
/// current head and the chain extends linearly, but a recovery op deliberately
/// points `prev` at an earlier ancestor, forking the chain: with a higher-authority
/// rotation key it nullifies everything signed after that fork point. That deep-`prev`
/// jump is a legitimate, expected shape; an attacker flooding operations and then
/// a recovery reaching back many ops is the very event this tool exists to catch,
/// not a malformed chain. So linkage always resolves `prev` against any known entry;
/// it never assumes `prev` equals the head.
///
/// [`add`](VerifiedAuditChain::add) therefore stores both sides of a fork: it
/// authority-checks each op against its parent's rotation keys but does not pick
/// a winner. Fork resolution (ranking sibling branches by rotation-key authority
/// and applying the 72-hour window) is
/// [`ChainResolver::canonical`](crate::resolver::ChainResolver::canonical)'s job,
/// kept separate so the chain stays a faithful record of what the directory served
/// and resolution can be recomputed two ways and compared.
#[derive(Debug, Clone)]
pub struct VerifiedAuditChain {
    /// The identity, derived from the genesis operation, not trusted from the wire.
    did: DidPlc,
    /// The verified operations, in receipt order (genesis first). The active head
    /// is resolved by `prev`-linkage, not by position.
    entries: Vec<AuditLogEntry<Checked>>,
}
impl VerifiedAuditChain {
    /// Start a chain from its genesis entry: derive the [`did:plc`](DidPlc) from
    /// the operation, confirm the entry's CID integrity, and verify its signature
    /// against one of *its own* declared rotation keys (the genesis is self-authorising).
    ///
    /// # Errors
    /// - [`VerifyError::InvalidChain`] if the entry carries a `prev` (a genesis
    ///   has none), fails its CID-integrity check, or no declared rotation key
    ///   signs it.
    /// - A [`VerifyError`] propagated from [`AuditLogEntry::verify`].
    #[allow(clippy::needless_pass_by_value)] // consume the entry, even if verify() only takes a ref
    pub fn genesis(op: AuditLogEntry<Signed>) -> Result<Self, VerifyError> {
        if op.operation().prev().map_err(|e| VerifyError::InvalidChain(e.to_string()))?.is_some() {
            return Err(VerifyError::InvalidChain("genesis operation must not carry `prev`".to_owned()));
        }
        if !op.cid_matches() {
            return Err(VerifyError::InvalidChain("genesis operation does not hash to its reported CID".to_owned()));
        }
        // Self-authorising: the genesis must be signed by one of its *own* rotation keys.
        let keys = op.operation().rotation_keys().map_err(|e| VerifyError::InvalidChain(e.to_string()))?;
        let verified = keys.iter().find_map(|key| op.verify(key).ok()).ok_or_else(|| {
            VerifyError::InvalidChain("genesis is not signed by any of its declared rotation keys".to_owned())
        })?;
        let did = encoding::derive_did(op.operation().value()).map_err(|e| VerifyError::InvalidChain(e.to_string()))?;
        Ok(Self { did, entries: vec![verified] })
    }

    /// Verify and store the next operation: resolve its `prev` to an existing
    /// verified entry (any ancestor, not just the head) then verify its signature
    /// against one of *that* entry's rotation keys (the authority check the entry
    /// cannot do alone).
    ///
    /// Returns a reference to the freshly verified entry.
    ///
    /// # Errors
    /// - [`VerifyError::InvalidChain`] if `prev` is absent or does not match a
    ///   known entry's CID, or no authorised rotation key of the prev op signs
    ///   this one.
    /// - A [`VerifyError`] propagated from [`AuditLogEntry::verify`].
    #[allow(clippy::needless_pass_by_value)] // consume the entry, even if verify() only takes a ref
    pub fn add(&mut self, entry: AuditLogEntry<Signed>) -> Result<&AuditLogEntry<Checked>, VerifyError> {
        // Linkage: an additive op must carry `prev`, resolving to an entry already
        // in the chain, any ancestor, not just the head (a recovery forks from
        // deeper).
        let prev = entry
            .operation()
            .prev()
            .map_err(|e| VerifyError::InvalidChain(e.to_string()))?
            .ok_or_else(|| VerifyError::InvalidChain("additive operation must carry `prev`".to_owned()))?;
        let parent = self
            .entries
            .iter()
            .find(|e| e.cid() == &prev)
            .ok_or_else(|| VerifyError::InvalidChain(format!("`prev` {prev} matches no operation in the chain")))?;
        // Integrity first, so a CID mismatch reports precisely rather than being
        // masked by the authority search below (which would just see every key
        // fail to verify).
        if !entry.cid_matches() {
            return Err(VerifyError::InvalidChain("operation does not hash to its reported CID".to_owned()));
        }
        // Authority: the op must be signed by one of the *parent* op's rotation
        // keys.
        let keys = parent.operation().rotation_keys().map_err(|e| VerifyError::InvalidChain(e.to_string()))?;
        let verified = keys.iter().find_map(|key| entry.verify(key).ok()).ok_or_else(|| {
            VerifyError::InvalidChain(
                "operation is not signed by any of the previous operation's rotation keys".to_owned(),
            )
        })?;
        self.entries.push(verified);
        Ok(self.most_recent())
    }

    /// Build a verified chain from a directory `/log/audit` array: the first entry
    /// is the genesis ([`genesis`](VerifiedAuditChain::genesis)), the rest are
    /// [`add`](VerifiedAuditChain::add)ed in receipt order.
    ///
    /// # Errors
    /// - [`VerifyError::InvalidChain`] if the array is empty (no genesis operation).
    /// - Any [`VerifyError`] from [`genesis`](VerifiedAuditChain::genesis) or
    ///   [`add`](VerifiedAuditChain::add) (a failed signature, linkage, or authority
    ///   check).
    pub fn try_from_iter<I: IntoIterator<Item = AuditLogEntry<Signed>>>(entries: I) -> Result<Self, VerifyError> {
        let mut entries = entries.into_iter();
        let genesis = entries
            .next()
            .ok_or_else(|| VerifyError::InvalidChain("empty audit log: no genesis operation".to_owned()))?;
        let mut chain = Self::genesis(genesis)?;
        for entry in entries {
            chain.add(entry)?;
        }
        Ok(chain)
    }

    /// The identity this chain belongs to, derived from its genesis operation.
    pub fn did(&self) -> &DidPlc {
        &self.did
    }

    /// The verified entry the chain holds for `cid`, if any.
    #[must_use]
    pub fn get(&self, cid: &Cid) -> Option<&AuditLogEntry<Checked>> {
        self.entries.iter().find(|entry| entry.cid == *cid)
    }

    /// Every verified entry that builds directly on `cid`. More than one child
    /// means a fork at `cid`.
    #[must_use]
    pub fn children_of(&self, cid: &Cid) -> Vec<&AuditLogEntry<Checked>> {
        self.entries.iter().filter(|entry| entry.operation().prev().ok().flatten().as_ref() == Some(cid)).collect()
    }

    /// The most recently added entry via [`add`](Self::add). Defaults to genesis
    /// operation if no further operations were added to the chain.
    ///
    /// # Panics
    /// If the struct somehow gets into a state where it does not have a genesis
    /// operation.
    pub fn most_recent(&self) -> &AuditLogEntry<Checked> {
        // Safety: entries always holds at least one entry from the genesis constructor.
        self.entries.last().unwrap()
    }

    /// All verified entries, in receipt order (genesis first).
    pub fn entries(&self) -> &[AuditLogEntry<Checked>] {
        &self.entries
    }
}
impl TryFrom<Vec<AuditLogEntry<Signed>>> for VerifiedAuditChain {
    type Error = VerifyError;
    fn try_from(entries: Vec<AuditLogEntry<Signed>>) -> Result<Self, Self::Error> {
        Self::try_from_iter(entries)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn deserialises_the_real_audit_chain_ignoring_did() {
        // Every real entry, including its (ignored) `did` and `createdAt`, parses
        // straight into a Signed entry, via the operation's own validating Deserialize.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn rejects_an_operation_without_a_signature() {
        // Strip the genesis op's `sig`: the entry must fail, as `Operation<Signed>`
        // requires one; the unforgeable property propagates up to the entry.
        let mut entries: Vec<Value> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        entries[0]["operation"].as_object_mut().unwrap().remove("sig");
        assert!(serde_json::from_value::<AuditLogEntry<Signed>>(entries[0].clone()).is_err());
    }

    #[test]
    fn getters_expose_the_parsed_fields() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let genesis = &entries[0];
        assert!(!genesis.nullified());
        assert_eq!(genesis.created_at(), "2023-12-04T12:44:38.479Z");
        // The reported CID matches the operation's own CID.
        assert!(genesis.cid_matches());
        assert_eq!(genesis.cid(), &genesis.operation().cid().unwrap());
    }

    #[test]
    fn verify_lifts_a_real_entry_to_checked() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let genesis = &entries[0];

        // The genesis is signed by one of its own rotation keys.
        let keys = genesis.operation().rotation_keys().unwrap();
        let signer = keys.iter().find(|k| genesis.verify(k).is_ok()).expect("a rotation key verifies the genesis");
        assert_eq!(genesis.verify(signer).unwrap().signed_by(), signer);

        // A stranger key is rejected.
        let stranger = DidKey::new(crate::test::TEST_DID_KEY_ATTACKER).unwrap();
        assert!(genesis.verify(&stranger).is_err());
    }

    #[test]
    fn verify_rejects_a_cid_that_does_not_match_the_operation() {
        // Swap in another entry's (valid) CID: it parses, but no longer matches
        // the op, so `verify` fails on the integrity check before even reaching
        // the signature.
        let mut raw: Vec<Value> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        raw[0]["cid"] = raw[1]["cid"].clone();
        let entry: AuditLogEntry<Signed> = serde_json::from_value(raw[0].clone()).unwrap();
        assert!(!entry.cid_matches());
        let keys = entry.operation().rotation_keys().unwrap();
        assert!(matches!(entry.verify(&keys[0]), Err(VerifyError::InvalidChain { .. })));
    }

    #[test]
    fn genesis_builds_a_chain_and_derives_the_did() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();

        // The DID is derived from the genesis bytes; the wire `did` is never trusted.
        assert_eq!(chain.did, DidPlc::new(crate::test::TEST_DID_PLC).unwrap());
        // One verified entry: the genesis, signed by one of its own rotation keys.
        assert_eq!(chain.entries.len(), 1);
        assert!(entries[0].operation().rotation_keys().unwrap().contains(chain.entries[0].signed_by()));
    }

    #[test]
    fn genesis_rejects_an_additive_op() {
        // entries[1] carries a `prev`, so it is an additive op, not a genesis.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        assert!(matches!(VerifiedAuditChain::genesis(entries[1].clone()), Err(VerifyError::InvalidChain(_))));
    }

    #[test]
    fn add_extends_the_chain_through_the_real_log() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let mut chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        chain.add(entries[1].clone()).unwrap();
        let head = chain.add(entries[2].clone()).unwrap();
        // Each op links to its parent and is signed by one of the parent's rotation
        // keys.
        assert_eq!(head.cid(), entries[2].cid());
        assert_eq!(chain.entries.len(), 3);
    }

    #[test]
    fn add_rejects_an_op_without_prev() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let mut chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        // The genesis carries no `prev`, so it cannot be added as an additive op.
        assert!(matches!(chain.add(entries[0].clone()), Err(VerifyError::InvalidChain(_))));
    }

    #[test]
    fn add_rejects_an_unlinked_prev() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let mut chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        // entries[2]'s `prev` points at entries[1], which was never added: no
        // known parent.
        assert!(matches!(chain.add(entries[2].clone()), Err(VerifyError::InvalidChain(_))));
    }

    #[test]
    fn get_finds_entries_by_cid_and_misses_absent_ones() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let mut chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        assert_eq!(chain.get(entries[0].cid()).unwrap().cid(), entries[0].cid());
        // entries[1] is a valid CID but not yet in the chain.
        assert!(chain.get(entries[1].cid()).is_none());
        chain.add(entries[1].clone()).unwrap();
        assert!(chain.get(entries[1].cid()).is_some());
    }

    #[test]
    fn children_of_walks_the_linear_chain() {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let mut chain = VerifiedAuditChain::genesis(entries[0].clone()).unwrap();
        chain.add(entries[1].clone()).unwrap();
        chain.add(entries[2].clone()).unwrap();

        // Linear: genesis → op1 → op2 (head). Each non-head op has exactly one
        // child.
        let kids = chain.children_of(entries[0].cid());
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].cid(), entries[1].cid());
        // The head has no children; the genesis never appears as its own child.
        assert!(chain.children_of(entries[2].cid()).is_empty());
    }

    #[test]
    fn try_from_builds_the_whole_chain_and_rejects_empty() {
        // The whole `/log/audit` array in one step: genesis + add the rest.
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let chain = VerifiedAuditChain::try_from(entries).unwrap();
        assert_eq!(chain.did(), &DidPlc::new(crate::test::TEST_DID_PLC).unwrap());
        assert_eq!(chain.entries().len(), 3);

        // An empty log has no genesis.
        assert!(matches!(VerifiedAuditChain::try_from(Vec::new()), Err(VerifyError::InvalidChain(_))));
    }
}
