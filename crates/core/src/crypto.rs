// SPDX-License-Identifier: MIT OR Apache-2.0
//! Crypto value objects: public keys ([`PublicKey`]), signatures ([`Signature`]),
//! and private keys ([`PrivateKey`], [`KeyPair`]).
//!
//! Minimal key custody. A [`PrivateKey`] is parsed from a multikey
//! ([`PrivateKey::from_multikey`]), used in-memory, and dropped; once parsed it is
//! export-proof by construction. Only a freshly generated key ([`GeneratedKey`])
//! can be persisted as a multikey ([`GeneratedKey::to_multikey`]).
//!
//! [`Signature`] is a curveless 64-byte P1363-compact holder. The curve is metadata
//! of the verifying key (consulted only by the ECDSA check, which always has a key),
//! never of the signature bytes, so a pasted signature reconstructs without one
//! and every accessor is a byte operation. Accessors select the wire form:
//! [`Signature::to_base64url`] (compact, the PLC operation `sig` form) or
//! [`Signature::to_der`] (openssl-native DER).
//!
//! # Examples
//! Proof of possession: sign a challenge nonce and verify it with only the public
//! half of the key.
//!
//! ```
//! use atshield_core::crypto::{KeyPair, Nonce, PrivateKey, Signature};
//! use std::str::FromStr;
//!
//! let keys = KeyPair::from_private(PrivateKey::generate().into_inner());
//! let nonce = Nonce::generate();
//! let sig = keys.sign(nonce.as_bytes()).unwrap();
//!
//! // The detector holds no private keys; it only verifies.
//! assert!(keys.verify(&sig, nonce.as_bytes()));
//!
//! // A pasted signature round-trips through its base64url wire form.
//! let pasted = Signature::from_str(&sig.to_base64url()).unwrap();
//! assert!(keys.verify(&pasted, nonce.as_bytes()));
//! ```

pub use super::did::Key as PublicKey;
use crate::error::NonceError;
use crate::error::{SignError, VerifyError};
use atrium_crypto::Algorithm;
use atrium_crypto::did::parse_did_key;
use atrium_crypto::verify::Verifier;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::ops::Deref;
use std::str::FromStr;
use zeroize::Zeroizing;

/// The fixed nonce prefix.
pub const NONCE_PREFIX: &str = "INVALID:";
/// The number of encoded bytes following the prefix (256 bits).
pub const NONCE_BYTE_LENGTH: usize = 32;

/// A validated proof-of-possession nonce.
///
/// Constructed only via [`Nonce::generate`] or by parsing a string that
/// satisfies the `INVALID:`+64-lowercase-hex form, so a `Nonce` value is always
/// well-formed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Nonce(String);
impl Nonce {
    /// Generate a fresh nonce from 32 bytes of OS CSPRNG output.
    ///
    /// # Panics
    /// Panics if the operating-system CSPRNG is unavailable (fail-closed).
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_BYTE_LENGTH];
        getrandom::getrandom(&mut bytes).expect("operating-system CSPRNG must be available");
        Self::from_random_bytes(&bytes)
    }

    /// Build a nonce from raw randomness (lowercase-hex encodes `bytes`). The
    /// caller is responsible for supplying 32 CSPRNG bytes; see
    /// [`Nonce::generate`].
    pub(crate) fn from_random_bytes(bytes: &[u8; NONCE_BYTE_LENGTH]) -> Self {
        Nonce(format!("{NONCE_PREFIX}{}", hex::encode(bytes)))
    }

    /// The full ASCII nonce string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bytes the user's rotation key signs (the full ASCII string).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Validate that `s` is a well-formed nonce.
    ///
    /// # Errors
    /// - [`NonceError::MissingPrefix`] if `s` lacks the `INVALID:` prefix.
    /// - [`NonceError::WrongLength`] if the hex body is not 64 characters.
    /// - [`NonceError::NotLowercaseHex`] if the body is not lowercase hex.
    pub fn parse(s: &str) -> Result<Self, NonceError> {
        let hex = s.strip_prefix(NONCE_PREFIX).ok_or(NonceError::MissingPrefix)?;
        if hex.len() != NONCE_BYTE_LENGTH * 2 {
            return Err(NonceError::WrongLength(hex.len()));
        }
        if !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(NonceError::NotLowercaseHex);
        }
        Ok(Nonce(s.to_owned()))
    }
}
impl Display for Nonce {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.0)
    }
}
impl FromStr for Nonce {
    type Err = NonceError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Nonce::parse(s)
    }
}
impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Nonce::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// An ECDSA-SHA256 signature, stored as 64-byte P1363 compact. Curveless (see
/// the module header). Named distinctly from the RustCrypto `ecdsa::Signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);
impl Signature {
    /// The raw 64-byte P1363 compact signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Base64url-no-pad of the compact form: the wire form a PLC operation `sig`
    /// field carries (and which atshield's nonce challenge submits).
    #[must_use]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Standard (padded) base64 of the canonical DER encoding, byte-identical to
    /// `openssl dgst -sha256 -sign key | openssl base64 -A`. The ASN.1 of `(r, s)`
    /// depends only on the integer values, so it needs no curve.
    ///
    /// # Panics
    /// Never in practice: two 256-bit integers DER-encode to well under the
    /// 128-byte short-form length limit.
    #[must_use]
    pub fn to_der(&self) -> String {
        let (r, s) = self.0.split_at(32);
        let mut body = der::der_uint(r);
        body.extend(der::der_uint(s));
        let mut der = Vec::with_capacity(2 + body.len());
        der.push(0x30); // SEQUENCE
        der.push(u8::try_from(body.len()).expect("two 256-bit integers fit a short-form DER length"));
        der.extend(body);
        STANDARD.encode(der)
    }

    /// Reconstruct from a raw 64-byte P1363 compact signature.
    ///
    /// # Errors
    /// - [`VerifyError::MalformedSignature`] if `bytes` is not exactly 64 bytes.
    pub fn from_compact(bytes: &[u8]) -> Result<Self, VerifyError> {
        <[u8; 64]>::try_from(bytes).map(Signature).map_err(|_| VerifyError::MalformedSignature)
    }

    /// Reconstruct from a DER-encoded ECDSA signature (`SEQUENCE { INTEGER r, INTEGER s }`),
    /// as openssl emits. Parsed curve-free into 64-byte compact.
    ///
    /// # Errors
    /// - [`VerifyError::MalformedSignature`] if `der` is not a well-formed two-integer ECDSA
    ///   signature with scalars that fit 32 bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, VerifyError> {
        der::parse_der(der).map(Signature).ok_or(VerifyError::MalformedSignature)
    }

    /// Distinguish a raw signature byte string by structure: exactly 64 bytes is
    /// compact, otherwise it is parsed as DER. (A DER that happens to encode to
    /// exactly 64 bytes is ~2^(-48) and fails safe: read as compact, it merely
    /// fails verification.)
    ///
    /// # Errors
    /// - [`VerifyError::MalformedSignature`] if `bytes` is neither 64-byte compact
    ///   P1363 nor a well-formed DER ECDSA signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        if bytes.len() == 64 { Self::from_compact(bytes) } else { Self::from_der(bytes) }
    }
}
impl FromStr for Signature {
    type Err = VerifyError;
    /// Parse a pasted signature: base64 (either alphabet, optional `=` padding)
    /// of compact ([`Signature::to_base64url`]) or DER ([`Signature::to_der`]
    /// / openssl), distinguished on the decoded bytes.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(&der::decode_base64_lenient(s)?)
    }
}
impl TryFrom<&str> for Signature {
    type Error = VerifyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl PublicKey {
    /// Verify `sig` over `msg` under this public key. Returns `false` on any failure
    /// (unparseable key, unsupported curve, or a signature that does not check).
    ///
    /// Strict (low-S): a high-S (malleated) signature is rejected, matching how
    /// the directory verifies a did:plc operation. Accepting one would let a
    /// signature the directory rejects read as valid here. `Signature` is always
    /// 64-byte compact P1363, so DER and other non-compact forms cannot reach
    /// this path.
    ///
    /// A signature from a tool that does not low-S-normalise (e.g. `openssl`, in
    /// the proof-of-possession challenge flow) may be high-S and so fail here.
    /// Rather than keep a second, lenient verifier, canonicalise it first with
    /// [`normalise`](PublicKey::normalise) and this one strict `verify` accepts
    /// it; there is exactly one way to verify, and it stays strict.
    #[must_use]
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
        match parse_did_key(self.as_ref()) {
            Ok((alg, public_key)) => Verifier::new(false).verify(alg, &public_key, msg, sig.as_bytes()).is_ok(),
            Err(_) => false,
        }
    }

    /// The low-S canonical form of `sig` for this key's curve.
    ///
    /// ECDSA is malleable: `(r, s)` and `(r, n-s)` both verify, and
    /// [`verify`](PublicKey::verify) accepts only the low-S half (`s <= n/2`),
    /// matching how the directory verifies a `did:plc` operation. A signature produced
    /// off-box by a tool that does not canonicalise (e.g. `openssl`) may be high-S;
    /// pass it through `normalise` and the strict `verify` accepts it. Canonicalising
    /// changes only the representation, never which key or message it verifies
    /// under.
    ///
    /// The curve comes from this key, which is why this is a `PublicKey` method
    /// and not a `Signature` one. A signature that cannot be parsed for this curve
    /// (or an unparseable key) is returned unchanged, so it simply fails `verify`
    /// and never silently passes.
    ///
    /// # Panics
    /// Never in practice: an ECDSA P1363 signature is always exactly 64 bytes.
    #[must_use]
    pub fn normalise(&self, sig: &Signature) -> Signature {
        let Ok((alg, _)) = parse_did_key(self.as_ref()) else {
            // Unparseable key (e.g. the empty sentinel); cannot determine the curve.
            return *sig;
        };
        let canonical: Option<[u8; 64]> = match alg {
            Algorithm::Secp256k1 => k256::ecdsa::Signature::from_slice(sig.as_bytes()).ok().map(|s| {
                <[u8; 64]>::try_from(s.normalize_s().unwrap_or(s).to_bytes().as_slice())
                    .expect("ECDSA P1363 signature is exactly 64 bytes")
            }),
            Algorithm::P256 => p256::ecdsa::Signature::from_slice(sig.as_bytes()).ok().map(|s| {
                <[u8; 64]>::try_from(s.normalize_s().unwrap_or(s).to_bytes().as_slice())
                    .expect("ECDSA P1363 signature is exactly 64 bytes")
            }),
        };
        canonical.map_or(*sig, Signature)
    }
}

/// Multicodec varint prefix for a P-256 private key (`p256-priv`, 0x1306).
const MULTICODEC_P256_PRIV: [u8; 2] = [0x86, 0x26];
/// Multicodec varint prefix for a secp256k1 private key (`secp256k1-priv`, 0x1301).
const MULTICODEC_SECP256K1_PRIV: [u8; 2] = [0x81, 0x26];

enum KeyInner {
    P256(p256::ecdsa::SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
}

/// A rotation private key held in memory for the duration of a single signing
/// operation. Parsed from the multibase multikey `goat key generate` emits.
///
/// Opaque by design: the inner `SigningKey` cannot be extracted by downstream
/// code (the variants are private) and the type has no `Debug` or `Display`, so
/// a key parsed from an external secret store can never be re-exported or
/// accidentally logged. Only a freshly minted [`GeneratedKey`] can leave the
/// process (via [`GeneratedKey::to_multikey`]). `k256`/`p256` `SigningKey`
/// zeroise their scalar on drop (RustCrypto `zeroize` drop glue), so the key
/// material is wiped when the `PrivateKey` is dropped.
pub struct PrivateKey(KeyInner);
impl PrivateKey {
    /// Parse the self-describing multibase multikey emitted by `goat key generate`
    /// (`z…` base58btc of `[priv-multicodec] || scalar`). The curve is determined
    /// by the multicodec prefix.
    ///
    /// # Errors
    /// - [`SignError::InvalidKey`] for a malformed multikey
    /// - [`SignError::UnsupportedCurve`] for a prefix outside the two PLC curves.
    pub fn from_multikey(multikey: &str) -> Result<Self, SignError> {
        let (_base, bytes) = multibase::decode(multikey).map_err(|e| SignError::InvalidKey(e.to_string()))?;
        // The decoded buffer holds the raw private scalar; wipe it on drop.
        let bytes = Zeroizing::new(bytes);
        if bytes.len() < 2 {
            return Err(SignError::InvalidKey("multikey too short".to_owned()));
        }
        let (prefix, scalar) = bytes.split_at(2);
        match prefix {
            p if p == MULTICODEC_P256_PRIV => {
                let sk =
                    p256::ecdsa::SigningKey::from_slice(scalar).map_err(|e| SignError::InvalidKey(e.to_string()))?;
                Ok(PrivateKey(KeyInner::P256(sk)))
            },
            p if p == MULTICODEC_SECP256K1_PRIV => {
                let sk =
                    k256::ecdsa::SigningKey::from_slice(scalar).map_err(|e| SignError::InvalidKey(e.to_string()))?;
                Ok(PrivateKey(KeyInner::Secp256k1(sk)))
            },
            _ => Err(SignError::UnsupportedCurve),
        }
    }

    /// Generate a fresh random secp256k1 rotation key. A test/sandbox helper for
    /// minting keypairs (the detector never generates keys); pair it with its
    /// `did:key` via [`KeyPair::from_private`]. Uses the OS CSPRNG.
    ///
    /// Returns a [`GeneratedKey`]: the only key form that can be persisted
    /// ([`GeneratedKey::to_multikey`]). Convert it into an export-proof
    /// [`PrivateKey`] with [`GeneratedKey::into_inner`].
    ///
    /// # Panics
    /// Panics if the OS CSPRNG is unavailable (fail-closed, as in
    /// [`Nonce::generate`](crate::crypto::Nonce::generate)).
    #[must_use]
    pub fn generate() -> GeneratedKey {
        loop {
            // Reject the negligibly-rare out-of-range/zero scalar by re-drawing.
            let mut scalar = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(scalar.as_mut_slice()).expect("OS CSPRNG unavailable");
            if let Ok(sk) = k256::ecdsa::SigningKey::from_slice(scalar.as_slice()) {
                return GeneratedKey(PrivateKey(KeyInner::Secp256k1(sk)));
            }
        }
    }

    /// The corresponding public `did:key`. Useful for the CLI to display the key
    /// being signed with, and for round-trip verification.
    ///
    /// # Panics
    /// Never in practice: a parsed signing key always formats to a valid `did:key`.
    #[must_use]
    pub fn did_key(&self) -> PublicKey {
        let s = match &self.0 {
            KeyInner::P256(sk) => {
                atrium_crypto::did::format_did_key(Algorithm::P256, &sk.verifying_key().to_sec1_bytes())
            },
            KeyInner::Secp256k1(sk) => {
                atrium_crypto::did::format_did_key(Algorithm::Secp256k1, &sk.verifying_key().to_sec1_bytes())
            },
        }
        .expect("a parsed signing key always yields a valid did:key");
        PublicKey::unchecked(s)
    }

    /// ECDSA-SHA256-sign `msg` with this key, low-S normalised, returning a
    /// [`Signature`].
    ///
    /// # Errors
    /// - [`SignError::Sign`] if the ECDSA signing operation fails.
    ///
    /// # Panics
    /// Never in practice: an ECDSA P1363 signature is always exactly 64 bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, SignError> {
        let bytes = match &self.0 {
            KeyInner::P256(sk) => {
                let sig: p256::ecdsa::Signature = sk.try_sign(msg).map_err(|e| SignError::Sign(e.to_string()))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                <[u8; 64]>::try_from(sig.to_bytes().as_slice()).expect("ECDSA P1363 signature is exactly 64 bytes")
            },
            KeyInner::Secp256k1(sk) => {
                let sig: k256::ecdsa::Signature = sk.try_sign(msg).map_err(|e| SignError::Sign(e.to_string()))?;
                let sig = sig.normalize_s().unwrap_or(sig);
                <[u8; 64]>::try_from(sig.to_bytes().as_slice()).expect("ECDSA P1363 signature is exactly 64 bytes")
            },
        };
        Ok(Signature(bytes))
    }
}

/// A private key freshly generated in-process by [`PrivateKey::generate`]: the
/// only key form that can be exported ([`to_multikey`](Self::to_multikey)),
/// because its material never came from an external secret store. A key parsed
/// with [`PrivateKey::from_multikey`] can never become one, so downstream code
/// holding a `PrivateKey` cannot extract it.
///
/// Derefs to [`PrivateKey`], so it signs and derives its `did:key` directly;
/// convert with [`into_inner`](Self::into_inner) once persisted.
///
/// The field is private and [`PrivateKey::generate`] is the only constructor,
/// so an imported key cannot be wrapped to exfiltrate it:
///
/// ```compile_fail,E0423
/// use atshield_core::crypto::{GeneratedKey, PrivateKey};
///
/// let key = PrivateKey::from_multikey("zDummy").unwrap();
/// let wrapped = GeneratedKey(key); // the constructor is not visible
/// ```
pub struct GeneratedKey(PrivateKey);
impl GeneratedKey {
    /// Export as the multikey that [`PrivateKey::from_multikey`] round-trips;
    /// the same form `goat key generate` emits (`z…` of `[priv-multicodec] || scalar`).
    ///
    /// The one sanctioned way to *persist* a generated key (e.g. a sandbox
    /// operator key). The returned string holds the raw private scalar and is
    /// wiped on drop.
    #[must_use]
    pub fn to_multikey(&self) -> Zeroizing<String> {
        // The assembled buffer holds the raw private scalar; wipe it on drop.
        let mut buf = Zeroizing::new(Vec::with_capacity(2 + 32));
        match &self.0.0 {
            KeyInner::P256(sk) => {
                buf.extend_from_slice(&MULTICODEC_P256_PRIV);
                buf.extend_from_slice(sk.to_bytes().as_slice());
            },
            KeyInner::Secp256k1(sk) => {
                buf.extend_from_slice(&MULTICODEC_SECP256K1_PRIV);
                buf.extend_from_slice(sk.to_bytes().as_slice());
            },
        }
        Zeroizing::new(multibase::encode(multibase::Base::Base58Btc, buf.as_slice()))
    }

    /// De-privilege into an export-proof [`PrivateKey`] (lock inner material
    /// from being exported).
    #[must_use]
    pub fn into_inner(self) -> PrivateKey {
        self.0
    }
}
impl Deref for GeneratedKey {
    type Target = PrivateKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl From<GeneratedKey> for PrivateKey {
    fn from(key: GeneratedKey) -> Self {
        key.0
    }
}

/// A freshly generated rotation keypair: a [`PrivateKey`] and the validated
/// [`PublicKey`]/[`DidKey`](crate::did::Key) it derives. A test/sandbox
/// convenience over [`PrivateKey::generate`] (e.g. minting distinct keys for
/// fixtures); the detector never generates keys.
pub struct KeyPair(pub PrivateKey, pub PublicKey);
impl KeyPair {
    /// Build a [`KeyPair`] from an existing [`PrivateKey`], deriving its [`PublicKey`].
    #[must_use]
    pub fn from_private(key: PrivateKey) -> Self {
        let public = key.did_key();
        Self(key, public)
    }

    /// Sign `msg` with the private half (delegates to [`PrivateKey::sign`]).
    ///
    /// # Errors
    /// - [`SignError::Sign`] if the ECDSA signing operation fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, SignError> {
        self.0.sign(msg)
    }

    /// Verify `sig` over `msg` against the public half.
    #[must_use]
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
        self.1.verify(sig, msg)
    }
}

mod der {
    use super::VerifyError;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;

    /// Encode a big-endian scalar as a DER `INTEGER` (minimal length; a leading
    /// `0x00` is prepended when the high bit is set, to keep it positive).
    pub(crate) fn der_uint(scalar: &[u8]) -> Vec<u8> {
        let trimmed: Vec<u8> = scalar.iter().copied().skip_while(|&b| b == 0).collect();
        let trimmed = if trimmed.is_empty() { vec![0u8] } else { trimmed };
        let pad = usize::from(trimmed.first().is_some_and(|&b| b & 0x80 != 0));
        let mut out = Vec::with_capacity(2 + pad + trimmed.len());
        out.push(0x02); // INTEGER
        out.push(u8::try_from(trimmed.len() + pad).expect("a 32-byte integer fits a short-form DER length"));
        if pad == 1 {
            out.push(0x00);
        }
        out.extend_from_slice(&trimmed);
        out
    }

    /// Parse `SEQUENCE { INTEGER r, INTEGER s }` into 64-byte compact (`r || s`,
    /// each left-padded to 32 bytes). Panic-free; returns `None` for any malformation.
    /// Only short-form lengths are accepted (real ECDSA signatures never need
    /// long form).
    pub(crate) fn parse_der(der: &[u8]) -> Option<[u8; 64]> {
        let after_tag = der.strip_prefix(&[0x30])?;
        let (&seq_len, rest) = after_tag.split_first()?;
        if rest.len() != usize::from(seq_len) {
            return None;
        }
        let (r, rest) = read_der_int(rest)?;
        let (s, rest) = read_der_int(rest)?;
        if !rest.is_empty() {
            return None;
        }
        let mut out = [0u8; 64];
        write_scalar(r, out.get_mut(..32)?)?;
        write_scalar(s, out.get_mut(32..)?)?;
        Some(out)
    }

    /// Read one DER `INTEGER` (`02 <len> <bytes>`) from the front; return its
    /// content bytes and the remainder.
    pub(crate) fn read_der_int(buf: &[u8]) -> Option<(&[u8], &[u8])> {
        let after_tag = buf.strip_prefix(&[0x02])?;
        let (&len, rest) = after_tag.split_first()?;
        let len = usize::from(len);
        if len == 0 {
            return None;
        }
        rest.split_at_checked(len)
    }

    /// Left-pad a big-endian DER integer (dropping a single `0x00` sign byte)
    /// into a 32-byte slot.
    pub(crate) fn write_scalar(int: &[u8], slot: &mut [u8]) -> Option<()> {
        let int = match int.split_first() {
            Some((&0x00, tail)) if !tail.is_empty() => tail,
            _ => int,
        };
        let start = slot.len().checked_sub(int.len())?;
        slot.get_mut(start..)?.copy_from_slice(int);
        Some(())
    }

    /// Decode a pasted base64 signature, accepting either alphabet (`-_` or
    /// `+/`) and optional `=` padding; covers both [`Signature::to_base64url`]
    /// and [`Signature::to_der`] outputs.
    pub(crate) fn decode_base64_lenient(s: &str) -> Result<Vec<u8>, VerifyError> {
        let normalised: String = s
            .trim()
            .chars()
            .filter(|&c| c != '=')
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                c => c,
            })
            .collect();
        STANDARD_NO_PAD.decode(normalised.as_bytes()).map_err(|e| VerifyError::SignatureDecode(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // panics are fine (and wanted) in tests
mod tests {
    use super::*;
    use crate::crypto::Nonce;

    /// A throwaway secp256k1 key + a low-S compact signature over `msg`, crafted
    /// via RustCrypto directly (independent of [`PrivateKey::sign`]).
    fn secp_key_and_sig(msg: &[u8]) -> (String, [u8; 64]) {
        use k256::ecdsa::SigningKey;
        use k256::ecdsa::signature::Signer as _;
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = atrium_crypto::did::format_did_key(
            atrium_crypto::Algorithm::Secp256k1,
            &sk.verifying_key().to_sec1_bytes(),
        )
        .unwrap();
        let sig: k256::ecdsa::Signature = sk.sign(msg);
        let sig = sig.normalize_s().unwrap_or(sig);
        (did, <[u8; 64]>::try_from(sig.to_bytes().as_slice()).unwrap())
    }

    #[test]
    fn to_der_is_valid_asn1_and_all_forms_round_trip() {
        let (_did, compact) = secp_key_and_sig(b"hello");
        let sig = Signature::from_compact(&compact).unwrap();

        // to_der is valid ASN.1 that RustCrypto parses back to the same (r, s).
        let der = STANDARD.decode(sig.to_der()).unwrap();
        let parsed = k256::ecdsa::Signature::from_der(&der).unwrap();
        assert_eq!(parsed.to_bytes().as_slice(), compact.as_slice());

        // Every constructor recovers the same Signature.
        assert_eq!(Signature::from_der(&der).unwrap(), sig);
        assert_eq!(Signature::from_str(&sig.to_base64url()).unwrap(), sig); // compact b64url
        assert_eq!(Signature::from_str(&sig.to_der()).unwrap(), sig); // standard-b64 DER
    }

    #[test]
    fn to_multikey_round_trips_with_from_multikey() {
        let key = PrivateKey::generate();
        let multikey = key.to_multikey();
        assert!(multikey.starts_with('z')); // base58btc multibase
        let reparsed = PrivateKey::from_multikey(&multikey).expect("re-imports");
        // Same identity. (`reparsed.to_multikey()` would not compile: an imported
        // `PrivateKey` is export-proof; only a `GeneratedKey` can be persisted.)
        assert_eq!(key.did_key(), reparsed.did_key());
    }

    #[test]
    fn private_multikey_is_bare_and_did_key_prefix_is_public_only() {
        // The convention: private key material exports as the bare multibase
        // (`z…`), and the `did:key:` prefix belongs exclusively to the public
        // form.
        // Both encodings start with `z`, so a prefixed private key is
        // one copy-paste from being published as if it were public. I've already
        // done this multiple times and I'm just testing locally, I need this test
        // here to make sure I don't screw up later on like a big dum-dum.
        use crate::did::DidExt as _;
        let key = PrivateKey::generate();
        let multikey = key.to_multikey();
        assert!(!multikey.starts_with("did:key:"));
        assert!(key.did_key().as_str().starts_with("did:key:z"));
        // A did:key:-prefixed private key must not import.
        assert!(PrivateKey::from_multikey(&format!("did:key:{}", multikey.as_str())).is_err());
    }

    #[test]
    fn from_compact_rejects_wrong_length() {
        assert!(Signature::from_compact(&[0u8; 63]).is_err());
        assert!(Signature::from_compact(&[0u8; 65]).is_err());
    }

    #[test]
    fn verify_accepts_good_rejects_tampered_and_wrong_message() {
        let (did, compact) = secp_key_and_sig(b"hello");
        let key = PublicKey::new(did).unwrap();
        let sig = Signature::from_compact(&compact).unwrap();

        assert!(key.verify(&sig, b"hello"));
        assert!(!key.verify(&sig, b"goodbye")); // wrong message
        let mut bad = compact;
        bad[0] ^= 1;
        assert!(!key.verify(&Signature::from_compact(&bad).unwrap(), b"hello")); // tampered
    }

    #[test]
    fn sign_then_verify_via_public_key() {
        let key = PrivateKey::generate();
        let public = key.did_key();
        let nonce = Nonce::generate();
        let sig = key.sign(nonce.as_bytes()).unwrap();

        // Both wire forms round-trip through a paste and verify under the public
        // key.
        assert!(public.verify(&Signature::from_str(&sig.to_base64url()).unwrap(), nonce.as_bytes()));
        assert!(public.verify(&Signature::from_str(&sig.to_der()).unwrap(), nonce.as_bytes()));
    }

    /// The malleable high-S counterpart of a real signature over `msg`, with its
    /// `did:key`. `(r, n - s)` is an equally-valid signature that strict (low-S)
    /// verification rejects.
    fn secp_high_s_sig(msg: &[u8]) -> (String, Signature) {
        use k256::ecdsa::SigningKey;
        use k256::ecdsa::signature::Signer as _;
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        let did = atrium_crypto::did::format_did_key(
            atrium_crypto::Algorithm::Secp256k1,
            &sk.verifying_key().to_sec1_bytes(),
        )
        .unwrap();
        let sig: k256::ecdsa::Signature = sk.sign(msg);
        let low = sig.normalize_s().unwrap_or(sig); // canonical low-S
        // Flip s -> n - s; since `low` is low-S, the result is guaranteed high-S.
        let high = k256::ecdsa::Signature::from_scalars(low.r().to_bytes(), (-(*low.s())).to_bytes()).unwrap();
        let bytes = <[u8; 64]>::try_from(high.to_bytes().as_slice()).unwrap();
        (did, Signature::from_compact(&bytes).unwrap())
    }

    #[test]
    fn normalise_canonicalises_high_s_for_strict_verify() {
        let msg = b"prove possession";
        let (did, high) = secp_high_s_sig(msg);
        let key = PublicKey::new(did).unwrap();

        // The malleable high-S signature is rejected by strict verify as-is...
        assert!(!key.verify(&high, msg));
        // ...but its low-S canonical form verifies under the one strict verifier.
        let low = key.normalise(&high);
        assert_ne!(low, high);
        assert!(key.verify(&low, msg));
        // Idempotent: an already-low-S signature is returned unchanged.
        assert_eq!(key.normalise(&low), low);
    }

    #[test]
    fn normalise_passes_through_when_the_curve_is_unknown() {
        // An unparseable key (the empty sentinel) cannot determine the curve, so
        // the signature is unchanged.
        let (_did, high) = secp_high_s_sig(b"x");
        assert_eq!(PublicKey::unchecked(String::new()).normalise(&high), high);
    }
}
