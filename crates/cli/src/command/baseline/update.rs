// SPDX-License-Identifier: MIT OR Apache-2.0
//! `atshield baseline update`: refresh an existing baseline to the directory's
//! current state, carrying its `userControlledKeys` forward unchanged. Online like
//! `record` (fetches + verifies the chain, resolves the reported head) but seeded
//! from an existing baseline (loaded like `trust-key`) for the trust set. `--force`
//! is required for any disk write; without it the command is a dry-run that shows
//! the structural diff of what would change.

use crate::cli::BaselineUpdateArgs;
use crate::output::{DANGER, LABEL, MUTED, WARNING, describe_delta, paint};
use crate::util::{self, InputSource};
use crate::{CliError, Outcome};
use atshield_core::audit::VerifiedAuditChain;
use atshield_core::delta::{Baseline, Delta};
use atshield_core::error::ResolveError;
use atshield_core::resolver::ChainResolver;
use atshield_core::{DidExt, DidKey};
use serde::Serialize;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// The result of `baseline update`: the freshly-composed [`Baseline`] plus the
/// skipped provenance the renderer needs. `#[serde(transparent)]` over the single
/// serialised field means `--json` / `--stdin` (or `--file -`) emit the bare
/// [`Baseline`].
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct BaselineUpdate {
    baseline: Baseline,
    /// What became of the update: written, previewed, a no-op, or piped to stdout.
    #[serde(skip)]
    disposition: Disposition,
    /// The structural diff from the old baseline's state to the directory's now.
    #[serde(skip)]
    changes: Vec<Delta>,
    /// The fetched chain disagrees with rotation-key authority (`!is_agreeable()`).
    #[serde(skip)]
    divergent: bool,
    /// Carried `userControlledKeys` no longer in the new `rotationKeys`.
    #[serde(skip)]
    off_chain_keys: Vec<DidKey>,
}

/// What `run` did with the recomposed baseline.
enum Disposition {
    /// `--force` and the state changed: written to this path.
    Wrote(PathBuf),
    /// No `--force` and the state changed: previewed only, this path left untouched.
    DryRun(PathBuf),
    /// The directory already matches the baseline: nothing to do.
    UpToDate,
    /// `--stdin`/`--file -`: the updated baseline is emitted to stdout, never
    /// persisted.
    Stdout,
}

impl BaselineUpdate {
    /// Load the baseline, re-resolve the head, and (with `--force`) persist.
    pub(crate) fn run(args: &BaselineUpdateArgs) -> Result<Self, CliError> {
        let (old, source) = args.load_baseline()?;
        if old.did() != &args.did {
            let msg = format!("baseline is for {}, not the requested {}", old.did().as_str(), args.did.as_str());
            return Err(CliError::Usage(msg.into()));
        }

        let plc_host = args.net.plc_host.clone().unwrap_or_default();
        let timeout = Duration::from_secs(args.net.timeout);
        let agent = ureq::AgentBuilder::new().timeout_connect(timeout).timeout_read(timeout).build();
        let chain = util::fetch_audit_chain(&agent, &plc_host, &args.did)?;

        let (baseline, divergent, off_chain_keys, changes) =
            Self::build(&chain, &old, old.user_controlled_keys().to_vec())?;

        let disposition = match source {
            InputSource::Stdin => Disposition::Stdout,
            InputSource::File(path) => {
                if old.state() == baseline.state() {
                    Disposition::UpToDate
                } else if args.shared.force {
                    let bytes = serde_json::to_vec_pretty(&baseline)
                        .map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
                    util::write_atomic(&path, &bytes)?;
                    Disposition::Wrote(path)
                } else {
                    Disposition::DryRun(path)
                }
            },
        };

        Ok(Self {
            baseline,
            disposition,
            changes,
            divergent,
            off_chain_keys,
        })
    }

    /// The network-free core: resolve the reported head, diff it against `old`'s
    /// captured state, flag now-off-chain carried keys, and compose the new
    /// [`Baseline`] with the keys carried verbatim. Split out so it can be
    /// exercised against the fixture chains without a live directory.
    fn build(
        chain: &VerifiedAuditChain,
        old: &Baseline,
        carried: Vec<DidKey>,
    ) -> Result<(Baseline, bool, Vec<DidKey>, Vec<Delta>), CliError> {
        let resolver = ChainResolver::new(chain);
        let (state, _signer) = resolver.reported().map_err(|err| match err {
            ResolveError::Deactivated | ResolveError::NoActiveOperation => {
                CliError::ChainInvalid("identity is tombstoned or has no active operation; nothing to baseline".into())
            },
            other => CliError::ChainInvalid(format!("could not resolve head state: {other}").into()),
        })?;
        let divergent = !resolver.is_agreeable();
        let changes = old.state().diff(&state);
        let off_chain_keys: Vec<DidKey> =
            carried.iter().filter(|&k| !state.rotation_keys().contains(k)).cloned().collect();
        Ok((Baseline::new(state, carried), divergent, off_chain_keys, changes))
    }
}

impl Outcome for BaselineUpdate {
    fn exit_code(&self) -> ExitCode {
        // Updating always succeeds; divergence and dry-run are not failures.
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        if self.divergent {
            _ = writeln!(
                s,
                "{} identity is currently divergent (reported \u{2260} canonical); updated to the reported state anyway",
                paint(DANGER, "warning:"),
            );
        }
        for key in &self.off_chain_keys {
            _ = writeln!(
                s,
                "{} carried key {} is no longer a rotation key",
                paint(WARNING, "warning:"),
                paint(MUTED, key.as_str()),
            );
        }
        if self.changes.is_empty() {
            // An empty diff on a state that still changed means only the head
            // advanced.
            if !matches!(self.disposition, Disposition::UpToDate) {
                _ = writeln!(s, "{} head advanced; no tracked field changed", paint(LABEL, "change:"));
            }
        } else {
            for delta in &self.changes {
                _ = writeln!(s, "{} {}", paint(LABEL, "change:"), describe_delta(delta));
            }
        }
        let did = self.baseline.did().as_str();
        match &self.disposition {
            Disposition::Wrote(_) | Disposition::Stdout => {
                _ = writeln!(
                    s,
                    "{} baseline for {did} (head {})",
                    paint(LABEL, "updated:"),
                    self.baseline.state().cid().as_str(),
                );
            },
            Disposition::DryRun(path) => {
                _ = writeln!(s, "{} would update {}; pass --force to write", paint(LABEL, "dry-run:"), path.display());
            },
            Disposition::UpToDate => {
                _ = writeln!(s, "{} baseline for {did} is already up to date", paint(LABEL, "update:"));
            },
        }
        s
    }

    /// stdout carries the file written; nothing on a dry-run, no-op, or
    /// `--stdin`/`--file -` (whose JSON path emits the baseline itself).
    fn datum(&self) -> Option<String> {
        match &self.disposition {
            Disposition::Wrote(path) => Some(path.display().to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::audit::AuditLogEntry;
    use atshield_core::operation::Signed;
    use atshield_core::resolver::ResolvedState;
    use atshield_core::test::{TEST_AUDIT_CHAIN, TEST_DID_ROTATION_PUBLIC};

    fn fixture_chain() -> VerifiedAuditChain {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(TEST_AUDIT_CHAIN).expect("fixture parses");
        VerifiedAuditChain::try_from(entries).expect("fixture verifies")
    }

    #[test]
    fn update_diffs_old_against_directory_and_carries_keys() {
        let chain = fixture_chain();
        let (reported, _) = ChainResolver::new(&chain).reported().expect("reported");

        // An `old` baseline that differs from the directory only in its handle,
        // built by round-tripping the real resolved state through JSON and tweaking
        // one field (so it stays a valid `ResolvedState`).
        let mut value = serde_json::to_value(&reported).expect("serialise state");
        value
            .as_object_mut()
            .expect("resolved state serialises to a JSON object")
            .insert("alsoKnownAs".to_owned(), serde_json::json!(["at://stale.example"]));
        let old_state: ResolvedState = serde_json::from_value(value).expect("deserialise tweaked state");

        // Carry an on-chain key and an off-chain (P-256) key.
        let on_chain = reported.rotation_keys().first().expect("rotation keys").clone();
        let off_chain: DidKey = TEST_DID_ROTATION_PUBLIC.parse().expect("valid did:key");
        let old = Baseline::new(old_state, vec![on_chain.clone(), off_chain.clone()]);

        let (baseline, divergent, off, changes) =
            BaselineUpdate::build(&chain, &old, old.user_controlled_keys().to_vec()).expect("build");

        // The new baseline is the freshly-resolved state; the diff reports the handle move.
        assert_eq!(baseline.state(), &reported);
        assert!(changes.iter().any(|d| matches!(d, Delta::HandleChanged { .. })));
        // Keys carried verbatim; the off-chain one is flagged, not dropped.
        assert_eq!(baseline.user_controlled_keys().to_vec(), vec![on_chain, off_chain.clone()]);
        assert_eq!(off, vec![off_chain]);
        assert!(!divergent);
    }

    #[test]
    fn update_of_the_current_state_is_a_no_op() {
        let chain = fixture_chain();
        let (reported, _) = ChainResolver::new(&chain).reported().expect("reported");
        let old = Baseline::new(reported.clone(), vec![]);

        let (baseline, _, _, changes) = BaselineUpdate::build(&chain, &old, vec![]).expect("build");

        assert!(changes.is_empty());
        assert_eq!(baseline.state(), &reported);
    }
}
