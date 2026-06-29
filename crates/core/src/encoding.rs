// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canonical did:plc operation encoding: the DAG-CBOR of a raw operation `Value`
//! and the CIDv1 derived from it.
//!
//! This is the one place those bytes are produced. [`crate::operation`] uses it
//! for `cid` and the signing input (and, later, for DID derivation), so the chain's
//! CID recomputation can never disagree with how an operation hashes. Everything
//! works from the raw served `Value`, never a typed round-trip, so the encoded
//! bytes are exactly what was signed and hashed.

use crate::cid::Cid;
use crate::did::Plc as DidPlc;
use crate::error::OperationError;
use multihash_codetable::{Code, MultihashDigest};
use serde_json::Value;

/// The number of base32 characters of the genesis hash that form a `did:plc` body.
const DID_PLC_BODY_LEN: usize = 24;

/// The DAG-CBOR multicodec (`0x71`), the codec every did:plc operation CID uses.
pub(crate) const DAG_CBOR_CODEC: u64 = 0x71;

/// Canonically DAG-CBOR-encode an operation value (length-first, byte-wise map-key
/// sort).
///
/// # Errors
/// - [`OperationError::Malformed`] if the value cannot be DAG-CBOR encoded; a
///   well-formed v1 operation (only strings, arrays, objects, bools, null) will
///   not error.
pub(crate) fn encode_canonical_dag_cbor(value: &Value) -> Result<Vec<u8>, OperationError> {
    serde_ipld_dagcbor::to_vec(value).map_err(|e| OperationError::Malformed(format!("cannot DAG-CBOR encode: {e}")))
}

/// The canonical bytes an operation's signature is computed over: the value with
/// its `sig` key removed (not nulled), DAG-CBOR encoded. This is exactly what the
/// directory signs and verifies, so [`Operation::sign`](crate::operation::Operation::sign)
/// and `verify` agree with it byte-for-byte.
///
/// Works on an unsigned value too: a missing `sig` makes the removal a no-op.
///
/// # Errors
/// - [`OperationError::Malformed`] if the value cannot be DAG-CBOR encoded.
pub(crate) fn signing_input(value: &Value) -> Result<Vec<u8>, OperationError> {
    let mut value = value.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("sig");
    }
    encode_canonical_dag_cbor(&value)
}

/// The CIDv1 (`dag-cbor`, `sha2-256`) of an operation value: the identifier the
/// directory reports and the next operation's `prev` points to. Hashes the complete
/// operation, `sig` included.
///
/// # Errors
/// - [`OperationError::Malformed`] if the value cannot be DAG-CBOR encoded.
pub(crate) fn compute_operation_cid(value: &Value) -> Result<Cid, OperationError> {
    let bytes = encode_canonical_dag_cbor(value)?;
    let cid = ::cid::Cid::new_v1(DAG_CBOR_CODEC, Code::Sha2_256.digest(&bytes));
    Ok(Cid::unchecked(cid.to_string()))
}

/// The [`did:plc`](DidPlc) derived from a genesis operation: the base32-lowercase
/// SHA-256 of its canonical DAG-CBOR, truncated to 24 characters. The hash covers
/// the complete signed genesis (`sig` included, the same bytes as
/// [`compute_operation_cid`]), so the identifier commits to the operation that
/// created it.
///
/// # Errors
/// - [`OperationError::Malformed`] if the value cannot be DAG-CBOR encoded (a
///   derived 24-character base32 body is always a syntactically valid `did:plc`).
pub(crate) fn derive_did(genesis: &Value) -> Result<DidPlc, OperationError> {
    let bytes = encode_canonical_dag_cbor(genesis)?;
    let digest = Code::Sha2_256.digest(&bytes);
    let body: String = multibase::Base::Base32Lower.encode(digest.digest()).chars().take(DID_PLC_BODY_LEN).collect();
    DidPlc::new(format!("did:plc:{body}"))
        .map_err(|e| OperationError::Malformed(format!("derived an invalid did:plc: {e}")))
}
