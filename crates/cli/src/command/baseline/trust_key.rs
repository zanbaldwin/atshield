// SPDX-License-Identifier: MIT OR Apache-2.0
//! `atshield baseline trust-key`: mark a `did:key` as user-controlled in an
//! existing baseline. Offline: loads the baseline (a file, or stdin with
//! `--stdin`/`--file -`), adds the key to `userControlledKeys` (idempotent), and
//! writes it back. A later change signed by a trusted key then classifies as
//! Legitimate rather than Tamper. The baseline must already exist as `trust-key`
//! fetches no chain, so it cannot create one.

use crate::cli::BaselineKeyArgs;
use crate::output::{LABEL, MUTED, WARNING, paint};
use crate::util::InputSource;
use crate::{CliError, Outcome};
use atshield_core::delta::Baseline;
use atshield_core::{DidExt, DidKey};
use serde::Serialize;
use std::fmt::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// The result of `baseline trust-key`: the (possibly unchanged) [`Baseline`] plus
/// the skipped provenance the renderer needs. `#[serde(transparent)]` over the
/// single serialised field means `--json` / `--stdin` (or `--file -`) emit the
/// bare [`Baseline`], so the mutated document round-trips straight down a pipe.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct BaselineTrustKey {
    baseline: Baseline,
    /// The key that was trusted (for the status line).
    #[serde(skip)]
    key: DidKey,
    /// The file written, or `None` for `--stdin`/`--file -` (stdin -> stdout)
    /// or a no-op.
    #[serde(skip)]
    saved_to: Option<PathBuf>,
    /// The key was already in `userControlledKeys`: nothing changed.
    #[serde(skip)]
    already_trusted: bool,
    /// The key is not among the baseline's `rotationKeys` (trusted anyway; warned).
    #[serde(skip)]
    off_chain: bool,
}

impl BaselineTrustKey {
    /// Load the baseline, add `key` to its user-controlled set, and persist.
    pub(crate) fn run(args: &BaselineKeyArgs) -> Result<Self, CliError> {
        let (mut baseline, source) = args.load_baseline()?;
        if baseline.did() != &args.did {
            let msg = format!("baseline is for {}, not the requested {}", baseline.did().as_str(), args.did.as_str());
            return Err(CliError::Usage(msg.into()));
        }
        let off_chain = !baseline.state().rotation_keys().contains(&args.key);
        let already_trusted = !baseline.trust_key(args.key.clone());
        let saved_to = match source {
            InputSource::Stdin => None,
            // A no-op (already trusted) leaves the file untouched.
            InputSource::File(_) if already_trusted => None,
            ref s @ InputSource::File(ref path) => {
                let bytes = serde_json::to_vec_pretty(&baseline)
                    .map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
                s.write(&bytes)?;
                Some(path.clone())
            },
        };
        Ok(Self {
            baseline,
            key: args.key.clone(),
            saved_to,
            already_trusted,
            off_chain,
        })
    }
}

impl Outcome for BaselineTrustKey {
    fn exit_code(&self) -> ExitCode {
        // Recording trust always succeeds; an off-chain key is a warning.
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        if self.off_chain {
            _ = writeln!(
                s,
                "{} trusted key {} is not a current rotation key",
                paint(WARNING, "warning:"),
                paint(MUTED, self.key.as_str()),
            );
        }
        if self.already_trusted {
            _ = writeln!(s, "{} {} was already trusted (no change)", paint(LABEL, "trust:"), self.key.as_str());
        } else {
            _ = writeln!(
                s,
                "{} trusted {} for {}",
                paint(LABEL, "trust:"),
                self.key.as_str(),
                self.baseline.did().as_str(),
            );
        }
        let keys = self.baseline.user_controlled_keys().len();
        _ = writeln!(s, "{} {keys} trusted key{}", paint(LABEL, "keys:"), if keys == 1 { "" } else { "s" });
        s
    }

    /// stdout carries the file written; nothing on `--stdin`/`--file -` (JSON
    /// path) or a no-op (already trusted).
    fn datum(&self) -> Option<String> {
        self.saved_to.as_ref().map(|path| path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::audit::{AuditLogEntry, VerifiedAuditChain};
    use atshield_core::operation::Signed;
    use atshield_core::resolver::ChainResolver;
    use atshield_core::test::{TEST_AUDIT_CHAIN, TEST_DID_ROTATION_PUBLIC};

    /// A baseline over the fixture chain's reported state, plus one of its genuine
    /// on-chain rotation keys.
    fn fixture_baseline(keys: Vec<DidKey>) -> (Baseline, DidKey) {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(TEST_AUDIT_CHAIN).expect("fixture parses");
        let chain = VerifiedAuditChain::try_from(entries).expect("fixture verifies");
        let (state, _) = ChainResolver::new(&chain).reported().expect("reported");
        let on_chain = state.rotation_keys().first().expect("chain has rotation keys").clone();
        (Baseline::new(state, keys), on_chain)
    }

    #[test]
    fn trust_key_is_idempotent_and_flags_off_chain() {
        // Exercises the two lines `run` uses inline: the rotationKeys membership
        // check (the off-chain warning) and `Baseline::trust_key`.
        let (mut baseline, on_chain) = fixture_baseline(vec![]);

        // Trusting an on-chain key adds it; on-chain (not flagged), newly added.
        assert!(baseline.state().rotation_keys().contains(&on_chain));
        assert!(baseline.trust_key(on_chain.clone()));
        assert!(baseline.user_controlled_keys().contains(&on_chain));

        // Trusting it again is a no-op that leaves the set unchanged.
        assert!(!baseline.trust_key(on_chain.clone()));
        assert_eq!(baseline.user_controlled_keys().len(), 1);

        // An off-chain key (P-256; the fixture chain is secp256k1) is flagged but
        // still added.
        let off_chain: DidKey = TEST_DID_ROTATION_PUBLIC.parse().expect("valid did:key");
        assert!(!baseline.state().rotation_keys().contains(&off_chain));
        assert!(baseline.trust_key(off_chain.clone()));
        assert!(baseline.user_controlled_keys().contains(&off_chain));
        assert_eq!(baseline.user_controlled_keys().len(), 2);
    }
}
