// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_message;
use crate::cli::{KeySourceArgs, SignPayloadArgs, SignRawArgs};
use crate::output::{MUTED, paint};
use crate::{CliError, Outcome};
use atshield_core::DidExt;
use atshield_core::DidKey;
use atshield_core::crypto::PrivateKey;
use serde::Serialize;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;
use zeroize::Zeroizing;

/// The result of `challenge sign raw`: a base64url signature over the message and the public
/// `did:key` it verifies under.
#[derive(Serialize)]
pub struct ChallengeSign {
    schema: &'static str,
    signer: DidKey,
    signature: String,
}
impl ChallengeSign {
    /// Sign the message (verbatim bytes; `-` reads raw stdin) with the supplied
    /// rotation key.
    pub(crate) fn raw(args: &SignRawArgs) -> Result<Self, CliError> {
        let key = Self::load_key(&args.key_source)?;
        let message = read_message(&args.message)?;
        Ok(Self {
            schema: "atshield.signature.v1",
            signature: key
                .sign(&message)
                .map_err(|_| CliError::Usage("could not sign with the supplied key".into()))?
                .to_base64url(),
            signer: key.did_key(),
        })
    }

    /// Sign a JSON payload by its canonical form: parsed then re-serialised with
    /// sorted keys (`-` reads raw stdin), so whitespace, indentation, and key
    /// order don't change the signature. The signed bytes are the canonical JSON,
    /// not the input verbatim.
    pub(crate) fn payload(args: &SignPayloadArgs) -> Result<Self, CliError> {
        let key = Self::load_key(&args.key_source)?;
        let value: serde_json::Value = serde_json::from_slice(&read_message(&args.payload)?)
            .map_err(|_| CliError::Data("payload is not valid JSON".into()))?;
        let canonical = serde_json::to_vec(&value).map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
        Ok(Self {
            schema: "atshield.signature.v1",
            signature: key
                .sign(&canonical)
                .map_err(|_| CliError::Usage("could not sign with the supplied key".into()))?
                .to_base64url(),
            signer: key.did_key(),
        })
    }

    /// Load and parse the private rotation key from the mutually-exclusive
    /// `--key-file` / `ATSHIELD_KEY` sources. The base58 material is held in
    /// [`Zeroizing`] and wiped before this returns; only the opaque [`PrivateKey`]
    /// escapes.
    fn load_key(source: &KeySourceArgs) -> Result<PrivateKey, CliError> {
        let material = Zeroizing::new(if let Some(path) = &source.key_file {
            // 4 KiB cap (a multikey is ~50 bytes; guards against a path like `/dev/zero`).
            let mut buf = String::new();
            File::open(path)?.take(4096).read_to_string(&mut buf)?;
            buf
        } else if let Some(raw) = &source.key {
            raw.clone()
        } else {
            return Err(CliError::Usage("no signing key supplied".into()));
        });
        PrivateKey::from_multikey(material.trim()).map_err(|_| CliError::Usage("invalid signing key".into()))
    }
}
impl Outcome for ChallengeSign {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        _ = writeln!(s, "{} {}", paint(MUTED, "signed with:"), paint(MUTED, self.signer.as_str()));
        s
    }

    fn datum(&self) -> Option<String> {
        Some(self.signature.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{KeySourceArgs, SignPayloadArgs};
    use atshield_core::test::TEST_DID_SIGNING_PRIVATE;

    fn sign_payload(json: &str) -> String {
        let args = SignPayloadArgs {
            payload: json.to_owned(),
            key_source: KeySourceArgs {
                key_file: None,
                key: Some(TEST_DID_SIGNING_PRIVATE.to_owned()),
            },
        };
        ChallengeSign::payload(&args).expect("payload should sign").signature
    }

    /// `sign payload` signs the *canonical* JSON Value, not the input bytes, so two
    /// encodings of the SAME object differing only in key order and whitespace must
    /// produce a byte-identical signature. That canonicalisation holds only because
    /// `serde_json::Value` is BTreeMap-backed (no `preserve_order` in the tree); this
    /// test pins the property and tripwires any future feature unification that would
    /// silently re-order keys and break every signature. Relies on core's deterministic
    /// (RFC 6979) ECDSA: identical signed bytes yield an identical signature.
    #[test]
    fn payload_signature_is_canonical_over_key_order_and_whitespace() {
        let ordered = sign_payload(r#"{"alpha":1,"beta":[2,3],"gamma":{"x":1,"y":2}}"#);
        let shuffled = sign_payload(r#"  { "gamma": { "y": 2, "x": 1 }, "beta": [ 2, 3 ], "alpha": 1 }  "#);
        assert_eq!(ordered, shuffled, "key order / whitespace changed the signature; canonicalisation regressed");

        // The signature is real and content-sensitive, so the equality above is
        // meaningful rather than two empty or constant strings.
        assert!(!ordered.is_empty());
        let different = sign_payload(r#"{"alpha":2,"beta":[2,3],"gamma":{"x":1,"y":2}}"#);
        assert_ne!(ordered, different, "different content must change the signature");
    }
}
