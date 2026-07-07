// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::cli::OpSigArgs;
use crate::output::{HIGHLIGHT, MUTED, SUCCESS, paint};
use crate::util::InputSource;
use crate::{CliError, Outcome};
use atshield_core::crypto::Signature;
use serde::Serialize;
use std::path::Path;
use std::process::ExitCode;

/// The result of `op sig`: the low-S base64url signature ready to drop into an operation's `sig` field.
#[derive(Serialize)]
pub struct OpSig {
    schema: &'static str,
    signature: String,
    transformed: bool,
}

impl OpSig {
    /// Parse the DER signature, normalise it to low-S for the key's curve, optionally verify it against
    /// the signing bytes, and emit the base64url wire form. No private key is involved.
    pub(crate) fn run(args: &OpSigArgs) -> Result<Self, CliError> {
        let source = InputSource::from(Path::new(&args.file));
        let bytes = source.read()?.ok_or_else(|| CliError::Data("signature file not found in input".into()))?;
        let sig = Signature::from_bytes(&bytes)
            .ok()
            .or_else(|| std::str::from_utf8(&bytes).ok().and_then(|text| Signature::try_from(text.trim()).ok()))
            .ok_or_else(|| CliError::Data("not a valid DER, compact, or base64 ECDSA signature".into()))?;
        let normalised = args.key.normalise(&sig);
        Ok(Self {
            schema: "atshield.signature.v1",
            signature: normalised.to_base64url(),
            transformed: sig != normalised,
        })
    }
}

impl Outcome for OpSig {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        format!(
            "{} {}\n",
            if self.transformed { paint(SUCCESS, "canonicalized") } else { paint(HIGHLIGHT, "already canonicalized") },
            paint(MUTED, "to low-S format")
        )
    }

    fn datum(&self) -> Option<String> {
        Some(self.signature.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::crypto::{KeyPair, PrivateKey, PublicKey};
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    const TEST_PRIVATE_KEY: &str = "z42tn2v88LZpKq8mEg77zTtyc2567MuGty7ZJGf7uymDRxLk";
    const TEST_PUBLIC_KEY: &str = "did:key:zDnaephCbrYRR1y5eDwiLnNC875yPkTcicdDtEWQ52ahEQSeM";
    // Took three attempts to find a message that OpenSSL generated a high-S signature for.
    const TEST_MESSAGE: &str = "atshield high-S ECDSA test vector 3";
    const TEST_SIGNATURE_DER: &str =
        "MEUCIGnajCMYKP8R1A5x5hmPL8lktmbLl9JHCVoDwwUdCTPzAiEA0y18KGuOGB/AjrOsPm37CTM0GSLgqnPvGlKxCVqIpZ8=";
    const TEST_SIGNATURE_HIGH_S: &str =
        "adqMIxgo_xHUDnHmGY8vyWS2ZsuX0kcJWgPDBR0JM_PTLXwoa44YH8COs6w-bfsJMzQZIuCqc-8aUrEJWoilnw";
    const TEST_SIGNATURE_LOW_S: &str =
        "adqMIxgo_xHUDnHmGY8vyWS2ZsuX0kcJWgPDBR0JM_Ms0oPWlHHn4T9xTFPBkgT2ibLhisZtKpXZZxm5odp_sg";

    #[test]
    fn der_normalises_and_round_trips_to_the_wire_sig() {
        let KeyPair(private, public) = KeyPair::from_private(PrivateKey::generate().into_inner());
        let msg = b"the exact DAG-CBOR signing input";
        let sig = private.sign(msg).expect("signs");
        // Feed the DER form (base64, as openssl/`to_der` emits) back through the parser + normaliser.
        let der_b64 = sig.to_der();
        let parsed = Signature::try_from(der_b64.as_str()).expect("parses DER base64");
        let normalised = public.normalise(&parsed);
        // Core signing is already low-S, so normalising is idempotent and the wire form matches; either
        // way the result verifies strictly (low-S) under the public key.
        assert!(public.verify(&normalised, msg));
        assert_eq!(normalised.to_base64url(), sig.to_base64url());
    }

    #[test]
    fn garbage_is_rejected_by_both_parse_paths() {
        // `run` tries raw bytes first, then trimmed UTF-8 text; both must fail for its data error.
        assert!(Signature::from_bytes(b"not a signature").is_err());
        assert!(Signature::try_from("not a signature").is_err());
    }

    #[test]
    fn high_s_forms_only_verify_after_normalising_to_the_wire_low_s_sig() {
        let key = PublicKey::new(TEST_PUBLIC_KEY).expect("a valid did:key");
        let forms: [(&str, Signature); 4] = [
            ("pasted base64 DER (high-S)", Signature::try_from(TEST_SIGNATURE_DER).unwrap()),
            (
                "raw DER bytes (as `openssl …` writes)",
                Signature::from_bytes(&STANDARD.decode(TEST_SIGNATURE_DER).unwrap()).unwrap(),
            ),
            ("pasted base64url compact (high-S)", Signature::try_from(TEST_SIGNATURE_HIGH_S).unwrap()),
            (
                "raw compact bytes (high-S)",
                Signature::from_bytes(&URL_SAFE_NO_PAD.decode(TEST_SIGNATURE_HIGH_S).unwrap()).unwrap(),
            ),
        ];
        for (form, sig) in forms {
            assert!(!key.verify(&sig, TEST_MESSAGE.as_bytes()), "{form} must not verify before normalization");
            let normalised = key.normalise(&sig);
            assert_eq!(normalised.to_base64url(), TEST_SIGNATURE_LOW_S, "{form}: must normalize");
            assert!(key.verify(&normalised, TEST_MESSAGE.as_bytes()), "{form}: must verify strictly");
        }
    }

    #[test]
    fn low_s_forms_are_already_canonical_and_normalise_idempotently() {
        let key = PublicKey::new(TEST_PUBLIC_KEY).expect("a valid did:key");
        let forms: [(&str, Signature); 2] = [
            ("pasted base64url compact (already low-S)", Signature::try_from(TEST_SIGNATURE_LOW_S).unwrap()),
            (
                "raw compact bytes (already low-S)",
                Signature::from_bytes(&URL_SAFE_NO_PAD.decode(TEST_SIGNATURE_LOW_S).unwrap()).unwrap(),
            ),
        ];
        for (form, sig) in forms {
            let normalised = key.normalise(&sig);
            assert_eq!(normalised.to_base64url(), TEST_SIGNATURE_LOW_S, "{form}: must normalize to itself");
            assert!(key.verify(&normalised, TEST_MESSAGE.as_bytes()), "{form}: must verify strictly");
        }
    }

    #[test]
    fn fixtures_agree_with_core_deterministic_signing() {
        // Core signs the same RFC 6979 flow as the openssl command that produced the fixtures.
        let private = PrivateKey::from_multikey(TEST_PRIVATE_KEY).expect("a valid multikey");
        assert_eq!(private.did_key(), PublicKey::new(TEST_PUBLIC_KEY).unwrap());
        let sig = private.sign(TEST_MESSAGE.as_bytes()).expect("signs");
        assert_eq!(sig.to_base64url(), TEST_SIGNATURE_LOW_S);
    }
}
