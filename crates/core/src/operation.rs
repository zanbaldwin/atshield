// SPDX-License-Identifier: MIT OR Apache-2.0
//! `did:plc` operations as type-state value objects.
//!
//! An [`Operation<S>`] wraps the raw operation JSON [`Value`] as its single
//! source of truth; the marker `S` records how far it has been through verification:
//!
//! - [`Unsigned`]: no `sig`, the shape produced when authoring or re-signing.
//! - [`Signed`]: carries a `sig` string, present but neither decoded nor checked
//!   against any key. Every observed operation parses into this state.
//! - [`Checked`]: the signature has been verified against a [`PublicKey`], which
//!   is recorded as the witness and read back via [`signed_by`](Operation::signed_by).
//!
//! The signing transitions are the only way to reach [`Checked`]:
//! [`sign`](Operation::sign) consumes an [`Unsigned`] operation, signing it with
//! a borrowed [`PrivateKey`], and [`verify`](Operation::verify) lifts an observed
//! [`Signed`] one by checking its `sig`. [`unsign`](Operation::unsign) and
//! [`fork`](Operation::fork) go the other way, dropping the signature to re-author
//! or to build a successor.
//!
//! Verification here is valid, not authorised: a [`Checked`] operation proves its
//! signature was made by the witness key, not that the key is an authorised rotation
//! key. That is the verified chain's decision.
//!
//! Construction validates only structural shape (a known [`OperationType`], a
//! null-or-string `prev`, genesis/additive agreement). Field reads such as
//! [`rotation_keys`](Operation::rotation_keys) and [`prev`](Operation::prev) parse
//! and validate lazily, so a malformed-but-observed operation stays representable
//! rather than being rejected at the boundary.

use crate::cid::Cid;
use crate::crypto::{PrivateKey, PublicKey, Signature};
use crate::encoding;
use crate::error::{OperationError, SignError, VerifyError};
use crate::resolver::ResolvedState;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// The `type` discriminant of a did:plc operation, in its on-wire spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    /// A standard operation (`plc_operation`): genesis when `prev` is absent,
    /// additive otherwise.
    #[serde(rename = "plc_operation")]
    Normal,
    /// A tombstone (`plc_tombstone`) that deactivates the identity.
    #[serde(rename = "plc_tombstone")]
    Tombstone,
    /// The deprecated legacy genesis shape (`create`).
    Create,
}

mod sealed {
    pub trait SealedState {}
    /// Seals [`super::SigExt`] to the in-crate signed markers.
    pub trait SealedSig {}
}
/// The signedness state of an [`Operation`].
pub trait State: sealed::SealedState + Debug + Clone + PartialEq {
    /// The verification witness carried in this state.
    type SignedBy: Debug + Clone + PartialEq;
}
/// The states that carry a signature ([`Signed`] and [`Checked`]) and therefore
/// have a defined CID. Sealed.
pub trait SigExt: State + sealed::SealedSig {}

/// State marker: the operation carries no signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsigned;
impl sealed::SealedState for Unsigned {}
impl State for Unsigned {
    type SignedBy = ();
}

/// State marker: the operation carries a `sig` string, present but not decoded
/// or checked at construction (see [`signature`](Operation::signature), which
/// may still return [`OperationError::Malformed`]) and not yet verified against
/// any key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed;
impl sealed::SealedState for Signed {}
impl sealed::SealedSig for Signed {}
impl State for Signed {
    type SignedBy = ();
}
impl SigExt for Signed {}

/// State marker: the signature has been verified against a known [`PublicKey`];
/// valid, not yet authorised. The witness key is carried as [`State::SignedBy`]
/// and read via [`Operation::signed_by`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked;
impl sealed::SealedState for Checked {}
impl sealed::SealedSig for Checked {}
impl State for Checked {
    type SignedBy = PublicKey;
}
impl SigExt for Checked {}

/// A `did:plc` operation, backed by its raw JSON [`Value`] as the single source
/// of truth. The signedness is the type-state parameter `S`; an [`Operation<Checked>`]
/// additionally carries the [`PublicKey`] its signature verified against.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Operation<S: State = Unsigned> {
    value: Value,
    #[serde(skip)]
    signed_by: S::SignedBy,
}
impl<S: State> Operation<S> {
    /// Wrap a value with its state witness, without validation; internal to the
    /// validating public constructors and transitions.
    fn new(value: Value, signed_by: S::SignedBy) -> Self {
        Self { value, signed_by }
    }

    /// Validate the structural shape every getter relies on, independent of state:
    /// a known `type`, a null-or-string `prev`, and a genesis/additive shape that
    /// agrees with the type. Semantic validity (which fields an op must carry,
    /// signature authority) is the verified chain's job, so a malformed-but-observed
    /// op stays representable rather than being rejected at construction.
    fn validate_structure(value: &Value) -> Result<(), OperationError> {
        let t = value.get("type").ok_or_else(|| OperationError::Malformed("missing `type`".to_owned()))?;
        let op_type: OperationType =
            serde_json::from_value(t.clone()).map_err(|e| OperationError::Malformed(format!("invalid `type`: {e}")))?;
        let has_prev = match value.get("prev") {
            None | Some(Value::Null) => false,
            Some(Value::String(_)) => true,
            Some(_) => return Err(OperationError::Malformed("`prev` is not a string".to_owned())),
        };
        match op_type {
            // Legacy `create` is always a genesis; a tombstone deactivates an
            // existing identity, so it never is.
            OperationType::Create if has_prev => {
                Err(OperationError::Malformed("`create` is a genesis op and must not carry `prev`".to_owned()))
            },
            OperationType::Tombstone if !has_prev => {
                Err(OperationError::Malformed("`plc_tombstone` must carry `prev`".to_owned()))
            },
            _ => Ok(()),
        }
    }

    /// The raw operation JSON: the single source of truth every getter reads.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The operation's `type` discriminant.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if `type` is absent or not a recognised
    ///   value.
    pub fn operation_type(&self) -> Result<OperationType, OperationError> {
        let t = self.value.get("type").ok_or_else(|| OperationError::Malformed("missing `type`".to_owned()))?;
        serde_json::from_value(t.clone()).map_err(|e| OperationError::Malformed(format!("invalid `type`: {e}")))
    }

    /// The fork point this operation builds on: `None` for a genesis op, `Some`
    /// for an additive op.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if `prev` is present but not a valid CID
    ///   string.
    pub fn prev(&self) -> Result<Option<Cid>, OperationError> {
        match self.value.get("prev") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => {
                Cid::new(s.as_str()).map(Some).map_err(|e| OperationError::Malformed(format!("invalid `prev`: {e}")))
            },
            Some(_) => Err(OperationError::Malformed("`prev` is not a string".to_owned())),
        }
    }

    /// The operation's rotation keys, in authority order.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if a declared key is not a valid `did:key`,
    ///   or the field carrying them has the wrong JSON shape.
    pub fn rotation_keys(&self) -> Result<Vec<PublicKey>, OperationError> {
        /// Validate a `did:key` string into a [`PublicKey`], tagging failures with `field`.
        fn parse_key(s: &str, field: &str) -> Result<PublicKey, OperationError> {
            PublicKey::new(s).map_err(|e| OperationError::Malformed(format!("invalid `{field}`: {e}")))
        }

        match self.operation_type() {
            // A tombstone declares no rotation keys.
            Ok(OperationType::Tombstone) => Ok(vec![]),
            // Legacy `create` normalises to [recoveryKey, signingKey]; order is
            // authority.
            Ok(OperationType::Create) => {
                let recovery = self
                    .value
                    .get("recoveryKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OperationError::Malformed("legacy `create` missing `recoveryKey`".to_owned()))?;
                let signing = self
                    .value
                    .get("signingKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OperationError::Malformed("legacy `create` missing `signingKey`".to_owned()))?;
                Ok(vec![parse_key(recovery, "recoveryKey")?, parse_key(signing, "signingKey")?])
            },
            // A standard op (or an unreadable type) reads the ordered `rotationKeys`
            // array.
            Ok(OperationType::Normal) | Err(_) => match self.value.get("rotationKeys") {
                None => Ok(vec![]),
                Some(Value::Array(keys)) => keys
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        let s = v
                            .as_str()
                            .ok_or_else(|| OperationError::Malformed(format!("`rotationKeys[{i}]` is not a string")))?;
                        parse_key(s, &format!("rotationKeys[{i}]"))
                    })
                    .collect(),
                Some(_) => Err(OperationError::Malformed("`rotationKeys` is not an array".to_owned())),
            },
        }
    }

    /// The operation's verification methods (key id → `did:key`), e.g.
    /// `"atproto"` → the repo signing key.
    ///
    /// A legacy `create` normalises to `{ "atproto": signingKey }`; a tombstone
    /// declares none.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if a declared value is not a valid
    ///   `did:key`, the field has the wrong JSON shape, or a legacy `create`
    ///   is missing `signingKey`.
    pub fn verification_methods(&self) -> Result<BTreeMap<String, PublicKey>, OperationError> {
        match self.operation_type() {
            Ok(OperationType::Tombstone) => Ok(BTreeMap::new()),
            // Legacy `create` exposes its single `signingKey` as the `atproto`
            // method.
            Ok(OperationType::Create) => {
                let signing = self
                    .value
                    .get("signingKey")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OperationError::Malformed("legacy `create` missing `signingKey`".to_owned()))?;
                let key = PublicKey::new(signing)
                    .map_err(|e| OperationError::Malformed(format!("invalid `signingKey`: {e}")))?;
                Ok(BTreeMap::from([("atproto".to_owned(), key)]))
            },
            Ok(OperationType::Normal) | Err(_) => match self.value.get("verificationMethods") {
                None => Ok(BTreeMap::new()),
                Some(Value::Object(map)) => map
                    .iter()
                    .map(|(id, v)| {
                        let s = v.as_str().ok_or_else(|| {
                            OperationError::Malformed(format!("`verificationMethods[{id}]` is not a string"))
                        })?;
                        let key = PublicKey::new(s).map_err(|e| {
                            OperationError::Malformed(format!("invalid `verificationMethods[{id}]`: {e}"))
                        })?;
                        Ok((id.clone(), key))
                    })
                    .collect(),
                Some(_) => Err(OperationError::Malformed("`verificationMethods` is not an object".to_owned())),
            },
        }
    }

    /// The operation's aliases (`alsoKnownAs`): `at://` handles, index 0 canonical.
    ///
    /// A legacy `create` normalises its bare `handle` to `["at://{handle}"]`; a
    /// tombstone declares none.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if the field is the wrong JSON shape, an
    ///   entry is not a string, or a legacy `create` is missing `handle`.
    pub fn also_known_as(&self) -> Result<Vec<String>, OperationError> {
        match self.operation_type() {
            Ok(OperationType::Tombstone) => Ok(vec![]),
            Ok(OperationType::Create) => {
                let handle = self
                    .value
                    .get("handle")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OperationError::Malformed("legacy `create` missing `handle`".to_owned()))?;
                Ok(vec![format!("at://{handle}")])
            },
            Ok(OperationType::Normal) | Err(_) => match self.value.get("alsoKnownAs") {
                None => Ok(vec![]),
                Some(Value::Array(items)) => items
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| OperationError::Malformed(format!("`alsoKnownAs[{i}]` is not a string")))
                    })
                    .collect(),
                Some(_) => Err(OperationError::Malformed("`alsoKnownAs` is not an array".to_owned())),
            },
        }
    }

    /// The operation's service endpoints (service id → [`Service`](properties::Service)).
    ///
    /// A legacy `create` normalises its `service` URL to
    /// `{ "atproto_pds": { type: "AtprotoPersonalDataServer", endpoint: service } }`;
    /// a tombstone declares none.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if the field is the wrong JSON shape, an
    ///   entry is not a valid service, or a legacy `create` is missing `service`.
    pub fn services(&self) -> Result<BTreeMap<String, properties::Service>, OperationError> {
        match self.operation_type() {
            Ok(OperationType::Tombstone) => Ok(BTreeMap::new()),
            Ok(OperationType::Create) => {
                let endpoint = self
                    .value
                    .get("service")
                    .and_then(Value::as_str)
                    .ok_or_else(|| OperationError::Malformed("legacy `create` missing `service`".to_owned()))?;
                Ok(BTreeMap::from([(
                    "atproto_pds".to_owned(),
                    properties::Service::new("AtprotoPersonalDataServer", endpoint),
                )]))
            },
            Ok(OperationType::Normal) | Err(_) => match self.value.get("services") {
                None => Ok(BTreeMap::new()),
                Some(services @ Value::Object(_)) => serde_json::from_value(services.clone())
                    .map_err(|e| OperationError::Malformed(format!("invalid `services`: {e}"))),
                Some(_) => Err(OperationError::Malformed("`services` is not an object".to_owned())),
            },
        }
    }
}

impl<S: SigExt> Operation<S> {
    /// The operation's signature, parsed from its on-wire `sig` field.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if `sig` is absent, non-string, or not a
    ///   decodable signature.
    pub fn signature(&self) -> Result<Signature, OperationError> {
        let s = self
            .value()
            .get("sig")
            .and_then(Value::as_str)
            .ok_or_else(|| OperationError::Malformed("missing or non-string `sig`".to_owned()))?;
        s.parse().map_err(|e: VerifyError| OperationError::Malformed(format!("invalid `sig`: {e}")))
    }

    /// The operation's CIDv1: the identifier the directory reports and the next
    /// operation's `prev` points to. Defined only for the signed states, since
    /// it hashes the complete operation, `sig` included.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if the value cannot be DAG-CBOR encoded.
    pub fn cid(&self) -> Result<Cid, OperationError> {
        encoding::compute_operation_cid(&self.value)
    }

    /// Fork a new unsigned operation that builds on this one. Unlike
    /// [`unsign`](Operation::unsign), which re-opens *this* operation for
    /// re-signing, `fork` begins a *successor*: clones the fields, points `prev`
    /// at this operation's [`cid`](Operation::cid), and drops the signature.
    /// The result is [`Unsigned`]; edit it (e.g. swap a compromised key) and
    /// sign it.
    ///
    /// # Errors
    /// - [`OperationError::Malformed`] if this operation's CID cannot be computed.
    pub fn fork(&self) -> Result<Operation<Unsigned>, OperationError> {
        let prev = self.cid()?;
        let mut value = self.value.clone();
        if let Some(obj) = value.as_object_mut() {
            obj.remove("sig");
            obj.insert("prev".to_owned(), Value::String(prev.as_str().to_owned()));
        }
        Ok(Operation::<Unsigned>::new(value, ()))
    }

    /// Drop the signature, returning an [`Operation<Unsigned>`] over the same
    /// fields. Removing `sig` is the only change; the rest of the value is intact.
    ///
    /// Use it to re-sign with a different key, or to take an operation's fields
    /// as a template (reset `prev` and author a fresh op rather than editing
    /// history).
    #[must_use]
    pub fn unsign(mut self) -> Operation<Unsigned> {
        if let Some(obj) = self.value.as_object_mut() {
            obj.remove("sig");
        }
        Operation::<Unsigned>::new(self.value, ())
    }
}

impl Operation<Unsigned> {
    /// Wrap an operation value that carries no signature.
    ///
    /// # Errors
    /// - [`OperationError::UnexpectedSignature`] if the value carries a `sig`.
    /// - [`OperationError::Malformed`] if its `type` is absent or unrecognised.
    pub fn from_value(value: Value) -> Result<Self, OperationError> {
        Self::validate_structure(&value)?;
        if value.get("sig").is_some() {
            return Err(OperationError::UnexpectedSignature);
        }
        Ok(Self::new(value, ()))
    }

    /// The exact DAG-CBOR bytes this operation is hashed and signed over; what
    /// an out-of-band signer (e.g. `openssl dgst -sha256 -sign`) must sign to
    /// produce a valid `sig`. Byte-identical to what [`sign`](Self::sign) signs
    /// and what `verify_chain` recomputes.
    ///
    /// # Errors
    /// - [`OperationError`] if the value cannot be DAG-CBOR encoded.
    pub fn signing_input(&self) -> Result<Vec<u8>, OperationError> {
        encoding::signing_input(&self.value)
    }

    /// Attach `sig` to this operation, unverified against any key, producing a
    /// [`Signed`] operation.
    #[must_use]
    pub fn add_signature(self, sig: &Signature) -> Operation<Signed> {
        let mut value = self.value;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("sig".to_owned(), Value::String(sig.to_base64url()));
        }
        Operation::<Signed>::new(value, ())
    }

    /// Sign this operation with [`key`](PrivateKey), producing a [`Checked`]
    /// operation whose witness ([`signed_by`](Operation::signed_by)) is `key`'s
    /// public `did:key`.
    ///
    /// # Errors
    /// - [`SignError::Encode`] if the signing input cannot be DAG-CBOR encoded.
    /// - [`SignError::Sign`] if the ECDSA signing operation fails.
    pub fn sign(self, key: &PrivateKey) -> Result<Operation<Checked>, SignError> {
        let input = self.signing_input().map_err(|e| SignError::Encode(e.to_string()))?;
        let sig = key.sign(&input)?;
        let witness = key.did_key();
        let mut value = self.value;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("sig".to_owned(), Value::String(sig.to_base64url()));
        }
        Ok(Operation::<Checked>::new(value, witness))
    }

    /// Attach an externally-produced [`sig`](Signature) and verify it against
    /// [`key`](PublicKey), producing a [`Checked`] operation that records `key`
    /// as the witness: the off-box signing path. Verification is strict low-S
    /// (see [`PublicKey::verify`]), so a raw `openssl` signature (high-S roughly
    /// half the time) is rejected; canonicalise it first with
    /// [`PublicKey::normalise`](crate::crypto::PublicKey::normalise).
    ///
    /// # Errors
    /// - [`VerifyError::Encode`] if the signing input cannot be encoded.
    /// - [`VerifyError::SignatureInvalid`] if `sig` does not verify against `key`.
    pub fn sign_with(self, key: &PublicKey, sig: &Signature) -> Result<Operation<Checked>, VerifyError> {
        self.add_signature(sig).verify(key)
    }
}
impl<'de> Deserialize<'de> for Operation<Unsigned> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}
/// Reconstruct an unsigned `plc_operation` from a resolved state: `prev` is the
/// state's CID, the document fields are carried over. Edit the result into the
/// operation to submit (e.g. drop a compromised key), then sign it.
impl From<&ResolvedState> for Operation<Unsigned> {
    fn from(state: &ResolvedState) -> Self {
        let value = serde_json::json!({
            "type": "plc_operation",
            "prev": state.cid().as_str(),
            "rotationKeys": state.rotation_keys(),
            "verificationMethods": state.verification_methods(),
            "alsoKnownAs": state.also_known_as(),
            "services": state.services(),
        });
        Self::new(value, ())
    }
}

impl Operation<Signed> {
    /// Wrap an observed operation value that carries a signature.
    ///
    /// # Errors
    /// - [`OperationError::MissingSignature`] if the value has no `sig`.
    /// - [`OperationError::Malformed`] if `sig` is not a string or `type` is invalid.
    pub fn from_value(value: Value) -> Result<Self, OperationError> {
        Self::validate_structure(&value)?;
        match value.get("sig") {
            Some(Value::String(_)) => {},
            Some(_) => return Err(OperationError::Malformed("`sig` is not a string".to_owned())),
            None => return Err(OperationError::MissingSignature),
        }
        Ok(Self::new(value, ()))
    }

    /// Verify this operation's signature against [`key`](PublicKey) over its
    /// signing input, producing a [`Checked`] operation that records `key` as
    /// the witness.
    ///
    /// Valid, not authorised: a successful check proves the signature was made
    /// by `key` (strict low-S, via [`PublicKey::verify`]), not that `key` is an
    /// authorised rotation key. That is the verified chain's decision.
    ///
    /// # Errors
    /// - [`VerifyError::Encode`] if the signing input cannot be encoded.
    /// - [`VerifyError::SignatureDecode`] if the on-wire `sig` is undecodable.
    /// - [`VerifyError::MalformedSignature`] if the `sig` decodes but is neither
    ///   64-byte compact P1363 nor a well-formed DER signature.
    /// - [`VerifyError::SignatureInvalid`] if it does not verify against `key`.
    pub fn verify(&self, key: &PublicKey) -> Result<Operation<Checked>, VerifyError> {
        let input = encoding::signing_input(&self.value).map_err(|e| VerifyError::Encode(e.to_string()))?;
        let sig_str = self
            .value
            .get("sig")
            .and_then(Value::as_str)
            .ok_or_else(|| VerifyError::SignatureDecode("operation has no `sig` field".to_owned()))?;
        let sig: Signature = sig_str.parse()?;
        if key.verify(&sig, &input) {
            Ok(Operation::<Checked>::new(self.value.clone(), key.clone()))
        } else {
            Err(VerifyError::SignatureInvalid)
        }
    }
}
impl<'de> Deserialize<'de> for Operation<Signed> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

impl Operation<Checked> {
    /// The public key this operation's signature was verified against.
    ///
    /// Valid, not authorised: this key checked the signature, but whether it is
    /// an authorised rotation key is the verified chain's decision.
    #[must_use]
    pub fn signed_by(&self) -> &PublicKey {
        &self.signed_by
    }
}

pub mod properties {
    //! Typed value objects for the structured fields of a resolved identity.
    //!
    //! Currently just [`Service`], one entry of the `services` map that
    //! [`ResolvedState`](crate::resolver::ResolvedState) projects from a chain's
    //! head operation.

    use serde::{Deserialize, Serialize};

    /// One entry of a resolved identity's `services` map: a typed endpoint such
    /// as the `atproto_pds` personal-data server. Keyed by service id in
    /// [`ResolvedState::services`](crate::resolver::ResolvedState::services).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Service {
        /// The service type tag (e.g. `AtprotoPersonalDataServer`).
        #[serde(rename = "type")]
        service_type: String,
        /// The service endpoint URL.
        endpoint: String,
    }
    impl Service {
        /// Construct a service entry, used to normalise a legacy `create`'s
        /// `service` URL into the modern `atproto_pds` shape.
        pub(crate) fn new(service_type: impl Into<String>, endpoint: impl Into<String>) -> Self {
            Self {
                service_type: service_type.into(),
                endpoint: endpoint.into(),
            }
        }

        /// The service type tag.
        #[must_use]
        pub fn service_type(&self) -> &str {
            &self.service_type
        }

        /// The service endpoint URL.
        #[must_use]
        pub fn endpoint(&self) -> &str {
            &self.endpoint
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn signed_op() -> Value {
        serde_json::json!({
            "sig": "2ppmbUjV_duwAOaAhBDgoUv3WHDubty5TFFDKcuKK8oST_0SsVRTrfVz39LNwbItZEc_FkKvr0kh6MihE2xyiQ",
            "prev": null,
            "type": "plc_operation",
            "rotationKeys": [],
            "alsoKnownAs": []
        })
    }

    #[test]
    fn round_trips_through_wire_strings() {
        for (variant, wire) in [
            (OperationType::Normal, "\"plc_operation\""),
            (OperationType::Tombstone, "\"plc_tombstone\""),
            (OperationType::Create, "\"create\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), wire);
            assert_eq!(serde_json::from_str::<OperationType>(wire).unwrap(), variant);
        }
    }

    #[test]
    fn signed_construction_and_getters() {
        let op = Operation::<Signed>::from_value(signed_op()).unwrap();
        assert_eq!(op.operation_type().unwrap(), OperationType::Normal);
        assert_eq!(op.prev().unwrap(), None); // genesis
        assert_eq!(
            op.signature().unwrap().to_base64url(),
            "2ppmbUjV_duwAOaAhBDgoUv3WHDubty5TFFDKcuKK8oST_0SsVRTrfVz39LNwbItZEc_FkKvr0kh6MihE2xyiQ"
        );
    }

    #[test]
    fn signedness_is_enforced_at_construction() {
        // A value with a `sig` cannot be an Unsigned operation.
        assert!(matches!(Operation::<Unsigned>::from_value(signed_op()), Err(OperationError::UnexpectedSignature)));

        // Strip the `sig`: now it is Unsigned, and rejected as Signed.
        let mut unsigned = signed_op();
        unsigned.as_object_mut().unwrap().remove("sig");
        assert!(Operation::<Unsigned>::from_value(unsigned.clone()).is_ok());
        assert!(matches!(Operation::<Signed>::from_value(unsigned), Err(OperationError::MissingSignature)));
    }

    #[test]
    fn checked_state_carries_the_signing_key() {
        // `verify` (which mints Checked from Signed) needs the encoder, so exercise
        // the state machinery directly via the internal constructor.
        let key = PublicKey::new("did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg").unwrap();
        let op = Operation::<Checked>::new(signed_op(), key.clone());
        assert_eq!(op.signed_by(), &key);
        assert_eq!(op.operation_type().unwrap(), OperationType::Normal); // shared getters still work
    }

    #[test]
    fn serialises_transparently_ignoring_the_witness() {
        // Signed: straight through to the value.
        let signed = Operation::<Signed>::from_value(signed_op()).unwrap();
        assert_eq!(serde_json::to_value(&signed).unwrap(), signed_op());

        // Checked: the witness key is not serialised, still just the value.
        let key = PublicKey::new("did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg").unwrap();
        let checked = Operation::<Checked>::new(signed_op(), key);
        assert_eq!(serde_json::to_value(&checked).unwrap(), signed_op());
    }

    #[test]
    fn unsign_drops_signature_and_returns_unsigned() {
        let unsigned = Operation::<Signed>::from_value(signed_op()).unwrap().unsign();
        assert!(unsigned.value().get("sig").is_none());
        assert_eq!(unsigned.operation_type().unwrap(), OperationType::Normal); // fields intact
        assert_eq!(unsigned.prev().unwrap(), None);
        // The result satisfies the Unsigned constructor's no-`sig` invariant.
        assert!(Operation::<Unsigned>::from_value(unsigned.value().clone()).is_ok());
    }

    #[test]
    fn validate_structure_enforces_type_and_genesis_shape() {
        const CID: &str = "bafyreiguelocxy4pl2ubhdruqp3tgi3lf27k6l7zm5vbvzpq7zxubbp5vu";

        // Unrecognised type.
        let mut bogus = signed_op();
        bogus["type"] = Value::String("nope".to_owned());
        assert!(matches!(Operation::<Signed>::from_value(bogus), Err(OperationError::Malformed(_))));

        // `create` is a genesis: a `prev` is contradictory.
        let mut create = signed_op();
        create["type"] = Value::String("create".to_owned());
        create["prev"] = Value::String(CID.to_owned());
        assert!(matches!(Operation::<Signed>::from_value(create), Err(OperationError::Malformed(_))));

        // A tombstone must build on something: no `prev` is contradictory.
        let mut tomb = signed_op();
        tomb["type"] = Value::String("plc_tombstone".to_owned()); // prev stays null
        assert!(matches!(Operation::<Signed>::from_value(tomb), Err(OperationError::Malformed(_))));
    }

    #[test]
    fn rotation_keys_by_operation_type() {
        const K0: &str = "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg";
        const K1: &str = "did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK";
        const CID: &str = "bafyreiguelocxy4pl2ubhdruqp3tgi3lf27k6l7zm5vbvzpq7zxubbp5vu";

        let want = vec![PublicKey::new(K0).unwrap(), PublicKey::new(K1).unwrap()]; // order = authority

        // Standard op: the array, in order.
        let mut op = signed_op();
        op["rotationKeys"] = serde_json::json!([K0, K1]);
        assert_eq!(Operation::<Signed>::from_value(op).unwrap().rotation_keys().unwrap(), want);

        // Legacy `create`: normalised to [recoveryKey, signingKey].
        let create = serde_json::json!({
            "sig": signed_op()["sig"], "type": "create", "prev": null,
            "recoveryKey": K0, "signingKey": K1,
        });
        assert_eq!(Operation::<Signed>::from_value(create).unwrap().rotation_keys().unwrap(), want);

        // Tombstone: none.
        let mut tomb = signed_op();
        tomb["type"] = Value::String("plc_tombstone".to_owned());
        tomb["prev"] = Value::String(CID.to_owned());
        assert!(Operation::<Signed>::from_value(tomb).unwrap().rotation_keys().unwrap().is_empty());
    }

    #[test]
    fn rotation_keys_rejects_a_malformed_key() {
        let mut v = signed_op();
        v["rotationKeys"] = serde_json::json!(["did:key:zNotARealKey"]);
        let op = Operation::<Signed>::from_value(v).unwrap(); // constructs: keys validated lazily
        assert!(matches!(op.rotation_keys(), Err(OperationError::Malformed(_))));
    }

    #[test]
    fn additive_prev_parses_to_a_cid() {
        const PREV: &str = "bafyreiguelocxy4pl2ubhdruqp3tgi3lf27k6l7zm5vbvzpq7zxubbp5vu";
        let mut v = signed_op();
        v["prev"] = Value::String(PREV.to_owned());
        let op = Operation::<Signed>::from_value(v).unwrap();
        assert_eq!(op.prev().unwrap().unwrap().as_str(), PREV);
    }

    fn unsigned_op() -> Value {
        let mut v = signed_op();
        v.as_object_mut().unwrap().remove("sig");
        v
    }

    #[test]
    fn fork_builds_an_unsigned_successor_on_this_op() {
        let mut v = signed_op();
        v["rotationKeys"] = serde_json::json!(["did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg"]);
        let signed = Operation::<Signed>::from_value(v).unwrap();
        let source_cid = signed.cid().unwrap();

        let forked = signed.fork().unwrap();
        assert!(forked.value().get("sig").is_none()); // unsigned
        assert_eq!(forked.prev().unwrap(), Some(source_cid)); // builds on the source (genesis → additive)
        assert_eq!(forked.rotation_keys().unwrap(), signed.rotation_keys().unwrap()); // fields carried over
        assert!(Operation::<Unsigned>::from_value(forked.value().clone()).is_ok()); // a valid template
    }

    #[test]
    fn add_signature_inserts_the_signature() {
        let sig: Signature = signed_op()["sig"].as_str().unwrap().parse().unwrap();
        let signed = Operation::<Unsigned>::from_value(unsigned_op()).unwrap().add_signature(&sig);
        assert_eq!(signed.signature().unwrap(), sig);
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let key = PrivateKey::generate();
        let pubkey = key.did_key();
        let checked = Operation::<Unsigned>::from_value(unsigned_op()).unwrap().sign(&key).unwrap();
        assert_eq!(checked.signed_by(), &pubkey); // witness is the signer

        // The signature it produced verifies under the same key (strict low-S).
        let signed = Operation::<Signed>::from_value(checked.value().clone()).unwrap();
        assert_eq!(signed.verify(&pubkey).unwrap().signed_by(), &pubkey);

        // A different key does not verify.
        let other = PrivateKey::generate().did_key();
        assert!(matches!(signed.verify(&other), Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn sign_with_attaches_and_verifies_an_external_signature() {
        let key = PrivateKey::generate();
        let pubkey = key.did_key();
        let unsigned = Operation::<Unsigned>::from_value(unsigned_op()).unwrap();
        // Sign the operation's signing input off to the side, then attach + verify.
        let sig = key.sign(&crate::encoding::signing_input(unsigned.value()).unwrap()).unwrap();
        assert_eq!(unsigned.sign_with(&pubkey, &sig).unwrap().signed_by(), &pubkey);

        // The same signature under a different key is rejected.
        let other = PrivateKey::generate().did_key();
        let unsigned = Operation::<Unsigned>::from_value(unsigned_op()).unwrap();
        assert!(matches!(unsigned.sign_with(&other, &sig), Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn genesis_signature_verifies_against_its_own_rotation_key() {
        // Real-data oracle: `signing_input` must reproduce the exact bytes the
        // directory signed; the genesis is signed by one of its own rotation keys.
        let entries: Vec<Value> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let genesis = Operation::<Signed>::from_value(entries[0]["operation"].clone()).unwrap();
        let keys = genesis.rotation_keys().unwrap();

        let signer = keys.iter().find(|k| genesis.verify(k).is_ok()).expect("a rotation key must verify the genesis");
        assert_eq!(keys.iter().filter(|k| genesis.verify(k).is_ok()).count(), 1);
        assert_eq!(genesis.verify(signer).unwrap().signed_by(), signer);

        // A key not on the operation does not verify.
        let stranger = PublicKey::new(crate::test::TEST_DID_KEY_ATTACKER).unwrap();
        assert!(matches!(genesis.verify(&stranger), Err(VerifyError::SignatureInvalid)));
    }

    #[test]
    fn cid_matches_the_directory_reported_cids() {
        // The strongest oracle: our DAG-CBOR/CID must reproduce the CID the
        // directory itself assigned each operation in the real audit chain.
        let entries: Vec<Value> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        for entry in &entries {
            let op = Operation::<Signed>::from_value(entry["operation"].clone()).unwrap();
            assert_eq!(op.cid().unwrap().as_str(), entry["cid"].as_str().unwrap());
        }
    }

    #[test]
    fn parses_the_observed_audit_chain() {
        let entries: Vec<Value> = serde_json::from_str(crate::test::TEST_AUDIT_CHAIN).unwrap();
        let ops: Vec<Operation<Signed>> =
            entries.iter().map(|e| Operation::<Signed>::from_value(e["operation"].clone()).unwrap()).collect();

        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].operation_type().unwrap(), OperationType::Normal);
        assert_eq!(ops[0].prev().unwrap(), None); // genesis
        assert!(ops[1].prev().unwrap().is_some()); // additive
        assert!(ops[2].prev().unwrap().is_some());
    }

    #[test]
    fn create_genesis_normalises_to_modern_document_fields() {
        // Synthetic legacy `create` (we have no real one yet): its flat fields
        // must project to the modern document shape per the spec, not error.
        const SIGNING: &str = "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg";
        const RECOVERY: &str = "did:key:zQ3shpKnbdPx3g3CmPf5cRVTPe1HtSwVn5ish3wSnDPQCbLJK";
        let create = serde_json::json!({
            "type": "create", "prev": null,
            "signingKey": SIGNING, "recoveryKey": RECOVERY,
            "handle": "zanbaldwin.com", "service": "https://pds.example.com",
        });
        // Sign it to reach Checked, the state a resolved head is read from.
        let op = Operation::<Unsigned>::from_value(create).unwrap().sign(&PrivateKey::generate()).unwrap();

        // rotation_keys = [recoveryKey, signingKey] (order is authority).
        assert_eq!(
            op.rotation_keys().unwrap(),
            vec![PublicKey::new(RECOVERY).unwrap(), PublicKey::new(SIGNING).unwrap()]
        );
        // alsoKnownAs = ["at://{handle}"].
        assert_eq!(op.also_known_as().unwrap(), vec!["at://zanbaldwin.com".to_owned()]);
        // verificationMethods = { atproto: signingKey }.
        assert_eq!(op.verification_methods().unwrap().get("atproto"), Some(&PublicKey::new(SIGNING).unwrap()));
        // services = { atproto_pds: { AtprotoPersonalDataServer, service } }.
        let services = op.services().unwrap();
        let pds = services.get("atproto_pds").unwrap();
        assert_eq!(pds.service_type(), "AtprotoPersonalDataServer");
        assert_eq!(pds.endpoint(), "https://pds.example.com");
    }
}
