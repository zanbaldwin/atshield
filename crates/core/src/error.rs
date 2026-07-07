// SPDX-License-Identifier: MIT OR Apache-2.0
//! Public error enums for the pipeline.
//!
//! Error variants carry owned `String` detail rather than wrapping dependency
//! error types, so the public surface stays stable.

use crate::{Cid, DidKind};

/// Failure validating during construction of DID types.
///
/// Shared across all three methods so a caller has one error type to match on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// The expected `did:{method}:` prefix was absent, so the string is not a
    /// DID of this method (it may be another method, or not a DID at all).
    #[error("expected a {0:?} DID, got `{1}`")]
    WrongMethod(DidKind, String),
    /// DID string did not parse.
    #[error("invalid {0:?}: {1}")]
    Invalid(DidKind, String),
}

/// Failure verifying an operation's signature, or decoding raw signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The operation does not hash to the directory's reported CID: a hard security
    /// signal that the reported chain linkage cannot be trusted.
    #[error("invalid operation chain: {0}")]
    InvalidChain(String),
    /// The signature string could not be base64-decoded. Either alphabet (`-_`
    /// or `+/`) is accepted and `=` padding is tolerated, so this fires only on
    /// genuinely undecodable input.
    #[error("malformed signature encoding: {0}")]
    SignatureDecode(String),
    /// The bytes were neither valid DER nor a 64-byte compact P1363 signature.
    #[error("signature is neither DER nor 64-byte compact P1363")]
    MalformedSignature,
    /// The signature did not verify against the key over the message.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// The operation's signing input could not be DAG-CBOR encoded.
    #[error("cannot encode signing input: {0}")]
    Encode(String),
}

/// Failure parsing a private key
/// ([`from_multikey`](crate::crypto::PrivateKey::from_multikey)) or signing
/// with it ([`PrivateKey::sign`](crate::crypto::PrivateKey::sign),
/// [`Operation::sign`](crate::operation::Operation::sign)).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The supplied private key could not be parsed.
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    /// The key's multicodec prefix is not a supported curve.
    #[error("unsupported curve for the supplied key")]
    UnsupportedCurve,
    /// The ECDSA signing operation failed.
    #[error("signing failed: {0}")]
    Sign(String),
    /// The operation's signing input could not be DAG-CBOR encoded.
    #[error("cannot encode signing input: {0}")]
    Encode(String),
}

/// Failure validating a [`Cid`]. Strict: the string
/// must parse as a CID *and* use the DAG-CBOR codec a `did:plc` operation CID
/// always carries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CidError {
    /// The string did not parse as a CID.
    #[error("invalid CID: {0}")]
    Invalid(String),
    /// The CID parsed but uses a codec other than DAG-CBOR (`0x71`).
    #[error("CID uses codec {0:#x}, expected DAG-CBOR (0x71)")]
    WrongCodec(u64),
}

/// Failure constructing or reading an [`Operation`](crate::operation::Operation).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    /// A field was absent, the wrong JSON type, or failed to parse.
    #[error("malformed operation: {0}")]
    Malformed(String),
    /// An unsigned operation was expected, but the value carries a `sig`.
    #[error("expected an unsigned operation, but it carries a signature")]
    UnexpectedSignature,
    /// A signed operation was expected, but the value carries no `sig`.
    #[error("expected a signed operation, but it carries no signature")]
    MissingSignature,
}

/// Why a string failed to parse as a [`Nonce`](crate::crypto::Nonce).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NonceError {
    /// The string lacks the literal `INVALID:` prefix.
    #[error("nonce is missing the `INVALID:` prefix")]
    MissingPrefix,
    /// The hex body was not exactly 64 characters (value = the actual length).
    #[error("nonce body must be 64 hex characters, found {0}")]
    WrongLength(usize),
    /// The body contained a non-lowercase-hex character.
    #[error("nonce body must be lowercase hex")]
    NotLowercaseHex,
}

/// Why a string failed to parse as an [`Endpoint`](crate::endpoints::Endpoint).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// The host was empty once the scheme and any trailing slashes were stripped.
    #[error("endpoint host is empty")]
    EmptyHost,
    /// The string carried a `scheme://` that is neither `http(s)` nor `ws(s)`.
    /// A bare host with no scheme is accepted (and treated as secure).
    #[error("unsupported endpoint scheme in `{0}` (expected http(s):// , ws(s):// , or a bare host)")]
    UnsupportedScheme(String),
}

/// Failure resolving a [`VerifiedAuditChain`](crate::audit::VerifiedAuditChain)
/// to its current [`ResolvedState`](crate::resolver::ResolvedState).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The head operation is a `plc_tombstone`: the identity was deactivated.
    /// There is no current DID-document state, but (unlike a wholly-nullified
    /// chain) the deactivation is itself a real, attributable operation a caller
    /// may want to surface and recover from, so it is distinguished from
    /// [`NoActiveOperation`](Self::NoActiveOperation).
    #[error("identity is deactivated (head is a tombstone)")]
    Deactivated,
    /// The chain has no active operation to resolve: every operation is
    /// nullified, so there is no surviving head and no current DID-document
    /// state. The directory reports the DID as "not available".
    #[error("chain has no active operation (wholly nullified)")]
    NoActiveOperation,
    /// The head operation's fields could not be projected into resolved state:
    /// an invalid `did:key`, a wrong-shaped field, or a legacy `create` missing
    /// one of its flat fields. (A well-formed `create` is normalised, not rejected.)
    #[error("cannot project head operation into resolved state: {0}")]
    Projection(String),
    /// An operation's `createdAt` could not be parsed as an RFC 3339 timestamp during
    /// canonical resolution's 72-hour window check.
    #[error("invalid operation timestamp: {0}")]
    Timestamp(String),
}

/// Failure auditing a chain against a [`Baseline`](crate::delta::Baseline).
///
/// Every variant is fail-closed: each means the audit could not be computed
/// soundly and must be surfaced as an alert, never mapped to a clean result.
/// Each names a way the chain has moved out from under the baseline in a
/// security-relevant way.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The directory's reported head disagrees with the protocol-canonical head
    /// ([`ChainResolver::is_agreeable`](crate::resolver::ChainResolver::is_agreeable)
    /// is `false`): the directory is serving a head the protocol does not support,
    /// so its `nullified` flags cannot be trusted to walk.
    #[error("directory reported head diverges from the canonical head")]
    DirectoryDivergence,
    /// The baseline's anchor operation is not on the reported head's ancestry:
    /// the post-baseline history was superseded or nullified out from under it
    /// (e.g. a hostile deep-recovery), so there is no honest path from baseline
    /// to head to attribute.
    #[error("baseline anchor operation is not on the reported chain")]
    AnchorUnreachable,
    /// A post-baseline operation could not be projected into resolved state (a
    /// malformed field, i.e. a "poison op").
    #[error("cannot project operation {0}: {1}")]
    Projection(Cid, ResolveError),
}
