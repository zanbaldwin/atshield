// SPDX-License-Identifier: MIT OR Apache-2.0
//! A validated content identifier: the [`Cid`] newtype carried by every
//! operation-CID field across the audit chain.
//!
//! Construction parses via the cid crate and asserts the DAG-CBOR `0x71` codec,
//! so a `Cid` can't be transposed for another CID field or a DID, and nothing
//! the spec doesn't mint gets through.
//!
//! `Serialize` is transparent (a bare JSON string), so persisted shapes stay
//! byte-identical to a plain `String` field; only loading now validates.

use super::de_via_fromstr;
use crate::encoding::DAG_CBOR_CODEC;
use crate::error::CidError;
use serde::Serialize;
use serde::de::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

/// A validated did:plc operation CID: a CIDv1 over canonical DAG-CBOR.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Cid(String);
impl Cid {
    /// Validate `value` as a DAG-CBOR CID and wrap it.
    ///
    /// # Errors
    /// - [`CidError::Invalid`] if the string does not parse as a CID.
    /// - [`CidError::WrongCodec`] if it parses but uses a codec other than DAG-CBOR.
    pub fn new(value: impl Into<String>) -> Result<Self, CidError> {
        let s = value.into();
        let parsed = ::cid::Cid::from_str(&s).map_err(|e| CidError::Invalid(e.to_string()))?;
        if parsed.codec() != DAG_CBOR_CODEC {
            return Err(CidError::WrongCodec(parsed.codec()));
        }
        Ok(Self(s))
    }

    /// Wrap a freshly-computed, provably-valid CID without re-parsing. For CIDs
    /// minted in-crate (e.g. [`crate::encoding::compute_operation_cid`]), where
    /// re-validation would only re-check the constructor's own output.
    #[must_use]
    pub(crate) fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The full CID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl AsRef<str> for Cid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for Cid {
    type Err = CidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
impl TryFrom<String> for Cid {
    type Error = CidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl TryFrom<&str> for Cid {
    type Error = CidError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de_via_fromstr(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash_codetable::{Code, MultihashDigest};

    /// Mint a real CIDv1 with the given codec over a fixed digest, so the validating
    /// constructor sees genuine multihash bytes (mirrors how the crypto tests
    /// craft signatures via the library directly).
    fn cid_with_codec(codec: u64) -> String {
        let mh = Code::Sha2_256.digest(b"atshield");
        ::cid::Cid::new_v1(codec, mh).to_string()
    }

    #[test]
    fn accepts_dag_cbor_cid() {
        let s = cid_with_codec(DAG_CBOR_CODEC);
        assert_eq!(Cid::new(&s).unwrap().as_str(), s);
    }

    #[test]
    fn rejects_wrong_codec() {
        let raw = cid_with_codec(0x55); // raw, not DAG-CBOR
        assert!(matches!(Cid::new(&raw), Err(CidError::WrongCodec(0x55))));
    }

    #[test]
    fn rejects_malformed() {
        assert!(matches!(Cid::new("not-a-cid"), Err(CidError::Invalid(_))));
        assert!(matches!(Cid::new(""), Err(CidError::Invalid(_))));
    }

    #[test]
    fn serialises_transparently_and_deserialise_validates() {
        let s = cid_with_codec(DAG_CBOR_CODEC);
        let c = Cid::new(&s).unwrap();
        assert_eq!(serde_json::to_string(&c).unwrap(), format!("\"{s}\""));
        assert!(serde_json::from_str::<Cid>(&format!("\"{s}\"")).is_ok());
        assert!(serde_json::from_str::<Cid>("\"not-a-cid\"").is_err());
    }
}
