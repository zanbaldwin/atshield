// SPDX-License-Identifier: MIT OR Apache-2.0
//! `atshield baseline untrust-key`: drop a `did:key` from an existing baseline's
//! user-controlled set. Offline mirror of `trust-key`: loads the baseline (a file,
//! or stdin with `--stdin`/`--file -`), removes the key from `userControlledKeys`
//! (idempotent), and writes it back. A later change signed by that key then
//! classifies as potential Tamper again rather than Legitimate.

use super::Source;
use crate::cli::BaselineKeyArgs;
use crate::output::{LABEL, MUTED, paint};
use crate::{CliError, Outcome, util};
use atshield_core::delta::Baseline;
use atshield_core::{DidExt, DidKey};
use serde::Serialize;
use std::fmt::Write;
use std::path::PathBuf;
use std::process::ExitCode;

/// The result of `baseline untrust-key`: the (possibly unchanged) [`Baseline`]
/// plus the skipped provenance the renderer needs. `#[serde(transparent)]` over
/// the single serialised field means `--json` / `--stdin` (or `--file -`) emit
/// the bare [`Baseline`], so the mutated document round-trips straight down a pipe.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct BaselineUntrustKey {
    baseline: Baseline,
    /// The key that was untrusted (for the status line).
    #[serde(skip)]
    key: DidKey,
    /// The file written, or `None` for `--stdin`/`--file -` (stdin -> stdout)
    /// or a no-op.
    #[serde(skip)]
    saved_to: Option<PathBuf>,
    /// The key was in `userControlledKeys` and got removed (else a no-op).
    #[serde(skip)]
    was_trusted: bool,
}

impl BaselineUntrustKey {
    /// Load the baseline, remove `key` from its user-controlled set, and persist.
    pub(crate) fn run(args: &BaselineKeyArgs) -> Result<Self, CliError> {
        let (mut baseline, source) = args.load_baseline()?;
        if baseline.did() != &args.did {
            let msg = format!("baseline is for {}, not the requested {}", baseline.did().as_str(), args.did.as_str());
            return Err(CliError::Usage(msg.into()));
        }
        let was_trusted = baseline.untrust_key(&args.key);
        let saved_to = match source {
            Source::Stdin => None,
            // A no-op (the key was not trusted) leaves the file untouched.
            Source::File(_) if !was_trusted => None,
            Source::File(path) => {
                let bytes = serde_json::to_vec_pretty(&baseline)
                    .map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
                util::write_atomic(&path, &bytes)?;
                Some(path)
            },
        };
        Ok(Self {
            baseline,
            key: args.key.clone(),
            saved_to,
            was_trusted,
        })
    }
}

impl Outcome for BaselineUntrustKey {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        if self.was_trusted {
            _ = writeln!(
                s,
                "{} untrusted {} for {}",
                paint(LABEL, "untrust:"),
                self.key.as_str(),
                self.baseline.did().as_str(),
            );
        } else {
            _ = writeln!(
                s,
                "{} {} was not trusted (no change)",
                paint(LABEL, "untrust:"),
                paint(MUTED, self.key.as_str())
            );
        }
        let keys = self.baseline.user_controlled_keys().len();
        _ = writeln!(s, "{} {keys} trusted key{}", paint(LABEL, "keys:"), if keys == 1 { "" } else { "s" });
        s
    }

    /// stdout carries the file written; nothing on `--stdin`/`--file -` (JSON
    /// path) or a no-op (the key was not trusted).
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
    use atshield_core::test::TEST_AUDIT_CHAIN;

    /// A baseline over the fixture chain's reported state that already trusts one
    /// of its genuine on-chain rotation keys.
    fn fixture_baseline() -> (Baseline, DidKey) {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(TEST_AUDIT_CHAIN).expect("fixture parses");
        let chain = VerifiedAuditChain::try_from(entries).expect("fixture verifies");
        let (state, _) = ChainResolver::new(&chain).reported().expect("reported");
        let key = state.rotation_keys().first().expect("chain has rotation keys").clone();
        (Baseline::new(state, vec![key.clone()]), key)
    }

    #[test]
    fn untrust_key_removes_then_is_a_no_op() {
        // Mirrors `run`'s inline `Baseline::untrust_key`.
        let (mut baseline, key) = fixture_baseline();
        assert!(baseline.user_controlled_keys().contains(&key));

        // Removing a trusted key drops it.
        assert!(baseline.untrust_key(&key));
        assert!(baseline.user_controlled_keys().is_empty());

        // Removing it again is a no-op.
        assert!(!baseline.untrust_key(&key));
        assert!(baseline.user_controlled_keys().is_empty());
    }
}
