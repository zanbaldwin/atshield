// SPDX-License-Identifier: MIT OR Apache-2.0
//! Validating DID newtypes, one per method: [`Key`] (`did:key`), [`Plc`] (`did:plc`),
//! and [`Web`] (`did:web`), plus the shared [`DidExt`] trait over them.
//!
//! Each type wraps the full `did:{method}:{body}` string and serves two jobs:
//!
//! 1. Anti-transposition: distinct types stop the many `did:{method}:`-shaped
//!    fields and arguments across the value types from being swapped, so a
//!    transposed call is a compile error.
//! 2. Validation: construction parses the string, so a constructed value is always
//!    syntactically valid for its method. [`DidExt::new`], [`FromStr`], and
//!    [`Deserialize`] share one validator per type, so a hand-edited or corrupt
//!    baseline carrying a malformed DID is rejected at load.
//!
//! `Serialize` is transparent (the value serialises as a bare JSON string), so
//! persisted shapes stay byte-identical to a plain `String` field; only loading
//! now validates. [`DidExt::as_str`] returns the whole DID, [`DidExt::value`]
//! borrows the body after `did:{method}:`, and both are zero-alloc sub-slices of
//! the stored string.
//!
//! - [`Key`] accepts the two PLC curves (secp256k1 `did:key:zQ3s…`, P-256
//!   `did:key:zDn…`) via `atrium_crypto::did::parse_did_key`, the same parser
//!   the chain verifier uses.
//! - [`Plc`] is the canonical `did:plc` parser (24-char base32-lowercase `[a-z2-7]`
//!   body).
//! - [`Web`] validates a `did:web` domain offline (no DNS) against the ATProto
//!   handle-syntax rules.
//!
//! # Examples
//!
//! ```
//! use atshield_core::{DidExt, DidPlc};
//!
//! let id = DidPlc::new("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap();
//! assert_eq!(id.value(), "ewvi7nxzyoun6zhxrhs64oiz");
//!
//! // Construction is the validation boundary: a did:key is not a did:plc.
//! assert!(DidPlc::new("did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg").is_err());
//! ```

use crate::de_via_fromstr;
use crate::error::DidError;
use serde::Serialize;
use serde::de::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

/// The AT Protocol DID method a [`DidExt`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `did:key`: a public key ([`Key`]).
    Key,
    /// `did:plc`: a Public-Ledger-of-Credentials identity ([`Plc`]).
    Plc,
    /// `did:web`: a domain-hosted identity ([`Web`]).
    Web,
}
impl Kind {
    /// The DID URI prefix for this method (`"did:key:"`, `"did:plc:"`, `"did:web:"`).
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Kind::Key => "did:key:",
            Kind::Plc => "did:plc:",
            Kind::Web => "did:web:",
        }
    }
}

/// A validated DID newtype over one method: [`Key`], [`Plc`], or [`Web`].
pub trait DidExt: FromStr<Err = DidError> + AsRef<str> {
    /// The DID method this type represents; a constant, not per-instance state.
    const KIND: Kind;

    /// Validate `value` as a `did:{method}` of this type and wrap it.
    ///
    /// # Errors
    /// - [`DidError`] if `value` is not a syntactically valid DID for [`KIND`](Self::KIND).
    fn new(value: impl Into<String>) -> Result<Self, DidError>;

    /// The method body: the substring after `did:{method}:`.
    fn value(&self) -> &str {
        self.as_ref().strip_prefix(Self::KIND.prefix()).unwrap_or(self.as_ref())
    }

    /// This value's DID method (always [`KIND`](DidExt::KIND)).
    fn kind(&self) -> Kind {
        Self::KIND
    }

    /// The full `did:{method}:{body}` string.
    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

/// A validated `did:key`: the rotation and signing keys on a PLC operation. Accepts
/// only the two PLC curves, secp256k1 (`did:key:zQ3s…`) and P-256 (`did:key:zDn…`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Key(String);
impl Key {
    /// Validate `value` as a supported `did:key` and wrap it.
    ///
    /// # Errors
    /// - [`DidError::Invalid`] for a malformed string or an unsupported curve.
    pub fn new(value: impl Into<String>) -> Result<Self, DidError> {
        let s = value.into();
        atrium_crypto::did::parse_did_key(&s).map_err(|e| DidError::Invalid(Self::KIND, e.to_string()))?;
        Ok(Self(s))
    }

    /// Wrap without validation. Used only where re-parsing is provably pointless.
    #[must_use]
    pub(crate) fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}
impl AsRef<str> for Key {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for Key {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
impl DidExt for Key {
    const KIND: Kind = Kind::Key;
    fn new(value: impl Into<String>) -> Result<Self, DidError> {
        Self::new(value)
    }
}
impl TryFrom<String> for Key {
    type Error = DidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl TryFrom<&str> for Key {
    type Error = DidError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de_via_fromstr(deserializer)
    }
}

/// The fixed `did:plc` body length (base32 of a 15-byte hash).
const DID_PLC_LEN: usize = 24;

/// A validated `did:plc` identity. This type is the canonical `did:plc` parser;
/// its body is a 24-character base32-lowercase (`[a-z2-7]`) hash, which also
/// keeps it safe to use verbatim as a filename component (no `/`, no `..`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Plc(String);
impl Plc {
    /// Validate `value` as a `did:plc` identifier and wrap it.
    ///
    /// # Errors
    /// - [`DidError::WrongMethod`] if it is not a `did:plc` DID.
    /// - [`DidError::Invalid`] if the body is empty, out-of-alphabet, or not 24
    ///   characters.
    pub fn new(value: impl Into<String>) -> Result<Self, DidError> {
        let s = value.into();
        let body = s.strip_prefix(Self::KIND.prefix()).ok_or_else(|| DidError::WrongMethod(Self::KIND, s.clone()))?;
        if body.is_empty() {
            return Err(DidError::Invalid(Self::KIND, format!("empty identifier body in `{s}`")));
        }
        if !body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err(DidError::Invalid(Self::KIND, format!("body must be base32 lowercase [a-z2-7], got `{body}`")));
        }
        if body.len() != DID_PLC_LEN {
            return Err(DidError::Invalid(
                Self::KIND,
                format!("body must be exactly {DID_PLC_LEN} characters, got {} in `{s}`", body.len()),
            ));
        }
        Ok(Self(s))
    }

    /// Wrap without validation. Used only where re-parsing is provably pointless.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn unchecked(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}
impl AsRef<str> for Plc {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Plc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for Plc {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
impl DidExt for Plc {
    const KIND: Kind = Kind::Plc;
    fn new(value: impl Into<String>) -> Result<Self, DidError> {
        Self::new(value)
    }
}
impl TryFrom<String> for Plc {
    type Error = DidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl TryFrom<&str> for Plc {
    type Error = DidError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<'de> Deserialize<'de> for Plc {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de_via_fromstr(deserializer)
    }
}

// Web (did:web)

/// TLDs ATProto reserves and never resolves (plus `test`, handled separately).
const RESERVED_TLDS: [&str; 8] = [
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
];

/// A validated `did:web` identity. The domain is checked offline (no DNS) against
/// the ATProto handle-syntax rules: hostname only (no port or path), ASCII, lowercase,
/// at least two labels of `[a-z0-9-]`, a non-numeric-leading TLD, and no reserved TLD.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Web(String);
impl Web {
    /// Validate `value` as a `did:web` identity (domain checked offline) and wrap
    /// it. Strict-production posture: `localhost`, the `.test`/reserved TLDs,
    /// ports and path components are rejected.
    ///
    /// # Errors
    /// - [`DidError::WrongMethod`] if it is not a `did:web` DID.
    /// - [`DidError::Invalid`] if the domain fails the ATProto handle-syntax rules.
    pub fn new(value: impl Into<String>) -> Result<Self, DidError> {
        let s = value.into();
        let domain = s.strip_prefix(Self::KIND.prefix()).ok_or_else(|| DidError::WrongMethod(Self::KIND, s.clone()))?;
        if domain.is_empty() {
            return Err(DidError::Invalid(Self::KIND, "empty domain".to_owned()));
        }
        // ATProto did:web is hostname-only: no ports (`%3A`/`:`) or path components.
        if domain.contains(':') || domain.contains('%') {
            return Err(DidError::Invalid(
                Self::KIND,
                format!("did:web allows no port or path components: `{domain}`"),
            ));
        }
        if domain.len() > 253 {
            return Err(DidError::Invalid(Self::KIND, format!("domain exceeds 253 characters ({})", domain.len())));
        }
        if !domain.is_ascii() {
            return Err(DidError::Invalid(
                Self::KIND,
                format!("domain must be ASCII (punycode internationalised names): `{domain}`"),
            ));
        }
        // DIDs are case-sensitive and a handle normalises to lowercase, so an
        // uppercase did:web is rejected rather than silently lowercased.
        if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(DidError::Invalid(Self::KIND, format!("domain must be lowercase: `{domain}`")));
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return Err(DidError::Invalid(Self::KIND, format!("domain needs at least two labels: `{domain}`")));
        }
        for label in &labels {
            if label.is_empty() {
                return Err(DidError::Invalid(
                    Self::KIND,
                    format!("empty label (a leading, trailing, or double dot) in `{domain}`"),
                ));
            }
            if label.len() > 63 {
                return Err(DidError::Invalid(Self::KIND, format!("label `{label}` exceeds 63 characters")));
            }
            if !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return Err(DidError::Invalid(
                    Self::KIND,
                    format!("label `{label}` has a character outside [a-z0-9-]"),
                ));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(DidError::Invalid(Self::KIND, format!("label `{label}` starts or ends with a hyphen")));
            }
        }
        // `labels.len() >= 2` guarantees a last label; `unwrap_or` keeps it
        // panic-free.
        let tld = labels.last().copied().unwrap_or_default();
        if tld.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(DidError::Invalid(Self::KIND, format!("top-level domain `{tld}` may not start with a digit")));
        }
        if RESERVED_TLDS.contains(&tld) || tld == "test" {
            return Err(DidError::Invalid(Self::KIND, format!("reserved top-level domain `.{tld}`")));
        }
        Ok(Web(s))
    }
}
impl AsRef<str> for Web {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for Web {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for Web {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}
impl DidExt for Web {
    const KIND: Kind = Kind::Web;
    fn new(value: impl Into<String>) -> Result<Self, DidError> {
        Self::new(value)
    }
}
impl TryFrom<String> for Web {
    type Error = DidError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl TryFrom<&str> for Web {
    type Error = DidError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}
impl<'de> Deserialize<'de> for Web {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de_via_fromstr(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real keys (secp256k1 from live-directory fixtures; P-256 from a goat test
    // vector), so the validating constructor accepts them.
    const SECP: &str = "did:key:zQ3shhCGUqDKjStzuDxPkTxN6ujddP4RkEKJJouJGRRkaLGbg";
    const P256: &str = "did:key:zDnaehNSrUcaj95GnoB4RVRKpaJ99i1MUSXZz5MAXfRCi3SE8";
    const PLC: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    #[test]
    fn key_accepts_both_curves() {
        assert_eq!(Key::new(SECP).unwrap().as_str(), SECP);
        assert_eq!(Key::new(P256).unwrap().value(), "zDnaehNSrUcaj95GnoB4RVRKpaJ99i1MUSXZz5MAXfRCi3SE8");
        assert_eq!(Key::new(SECP).unwrap().kind(), Kind::Key);
    }

    #[test]
    fn key_rejects_malformed() {
        assert!(Key::new("not-a-did-key").is_err());
        assert!(Key::new("did:web:example.test").is_err());
        assert!(Key::new("did:key:zUserOne").is_err()); // synthetic, not a real key
        assert!(Key::new("").is_err());
    }

    #[test]
    fn key_serialises_transparently() {
        let k = Key::new(SECP).unwrap();
        assert_eq!(serde_json::to_string(&k).unwrap(), format!("\"{SECP}\""));
    }

    #[test]
    fn key_deserialise_validates() {
        assert!(serde_json::from_str::<Key>(&format!("\"{SECP}\"")).is_ok());
        assert!(serde_json::from_str::<Key>("\"did:key:zUserOne\"").is_err());
    }

    #[test]
    fn empty_signing_key_sentinel_degrades_gracefully() {
        // The one Key that satisfies neither `new` nor the prefix shape.
        let sentinel = Key::unchecked(String::new());
        assert_eq!(sentinel.as_str(), "");
        assert_eq!(sentinel.value(), "");
        assert_eq!(sentinel.kind(), Kind::Key);
    }

    #[test]
    fn plc_accepts_and_exposes_body() {
        let id = Plc::new(PLC).unwrap();
        assert_eq!(id.as_str(), PLC);
        assert_eq!(id.value(), "ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(id.kind(), Kind::Plc);
    }

    #[test]
    fn plc_rejects_wrong_method() {
        assert!(matches!(Plc::new("did:web:example.com"), Err(DidError::WrongMethod { .. })));
        assert!(matches!(Plc::new("did:key:zQ3sabc"), Err(DidError::WrongMethod { .. })));
    }

    #[test]
    fn plc_rejects_malformed_body() {
        // Empty, uppercase, out-of-alphabet, path chars, and wrong length.
        for bad in [
            "did:plc:",
            "did:plc:ABC",
            "did:plc:ab01",
            "did:plc:ab/cd",
            "did:plc:..ab",
            "did:plc:abc234",
        ] {
            assert!(matches!(Plc::new(bad), Err(DidError::Invalid { .. })), "{bad} should be InvalidPlc");
        }
    }

    #[test]
    fn plc_deserialise_validates() {
        assert!(serde_json::from_str::<Plc>(&format!("\"{PLC}\"")).is_ok());
        assert!(serde_json::from_str::<Plc>("\"did:plc:tooshort\"").is_err());
    }

    #[test]
    fn plc_unchecked_skips_validation() {
        // `unchecked` wraps verbatim, so it holds a body `new` would reject.
        let id = Plc::unchecked("did:plc:tooshort");
        assert_eq!(id.as_str(), "did:plc:tooshort");
        assert_eq!(id.value(), "tooshort");
        assert!(Plc::new("did:plc:tooshort").is_err());
    }

    #[test]
    fn web_accepts_valid_domains() {
        for ok in [
            "did:web:example.com",
            "did:web:sub.example.co.uk",
            "did:web:my-host.example.org",
        ] {
            let id = Web::new(ok).unwrap();
            assert_eq!(id.as_str(), ok);
            assert_eq!(id.kind(), Kind::Web);
        }
        assert_eq!(Web::new("did:web:example.com").unwrap().value(), "example.com");
    }

    #[test]
    fn web_rejects_wrong_method() {
        assert!(matches!(Web::new("did:plc:ewvi7nxzyoun6zhxrhs64oiz"), Err(DidError::WrongMethod { .. })));
    }

    #[test]
    fn web_rejects_invalid_domains() {
        // All carry the `did:web:` prefix, so each is InvalidWeb (not WrongMethod).
        for bad in [
            "did:web:",                        // empty
            "did:web:localhost",               // reserved + single label
            "did:web:example.local",           // reserved TLD
            "did:web:example.test",            // reserved dev TLD
            "did:web:host%3A1234.example.com", // percent-encoded port
            "did:web:host:1234",               // colon (port/path)
            "did:web:1.2.3.4",                 // IP / digit-leading TLD
            "did:web:UP.example.com",          // uppercase
            "did:web:single",                  // one label
            "did:web:example.com.",            // trailing dot
            "did:web:-bad.example.com",        // hyphen-bordered label
        ] {
            assert!(matches!(Web::new(bad), Err(DidError::Invalid { .. })), "{bad} should be InvalidWeb");
        }
    }

    #[test]
    fn web_serialises_transparently() {
        let w = Web::new("did:web:example.com").unwrap();
        assert_eq!(serde_json::to_string(&w).unwrap(), "\"did:web:example.com\"");
    }
}
