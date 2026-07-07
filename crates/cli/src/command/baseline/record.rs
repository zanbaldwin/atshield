// SPDX-License-Identifier: MIT OR Apache-2.0
//! `atshield baseline record`: capture an identity's current verified state as a
//! [`Baseline`] file, the reference a later `check` diffs against. `record` fetches
//! the audit log, verifies the chain, resolves the reported head, and writes the
//! flat camelCase [`Baseline`] JSON. The `trust-key` / `untrust-key` subcommands
//! do not need to refetch the audit chain, and work completely offline.

use crate::cli::BaselineRecordArgs;
use crate::output::{DANGER, LABEL, MUTED, WARNING, paint};
use crate::util::{InputSource, default_path};
use crate::{CliError, Outcome, util};
use atshield_core::audit::VerifiedAuditChain;
use atshield_core::delta::Baseline;
use atshield_core::error::ResolveError;
use atshield_core::resolver::ChainResolver;
use atshield_core::{DidExt, DidKey};
use serde::Serialize;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// The result of `baseline record`: the captured [`Baseline`] plus the (skipped)
/// provenance the terminal renderer needs. `#[serde(transparent)]` over the single
/// serialised field means `--json` / `--stdout` (or `--file -`) emit the bare
/// [`Baseline`]. A document that round-trips back through `Baseline`'s `Deserialize`
/// (so a future `trust-key --file -` can read it straight off the pipe).
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct BaselineRecord {
    baseline: Baseline,
    /// The file written, or `None` when streaming to stdout (`--stdout`/`--file -`, implying `--json`).
    #[serde(skip)]
    saved_to: Option<PathBuf>,
    /// The directory disagrees with rotation-key authority right now
    /// (`!is_agreeable()`): baselined the reported state anyway, but warn.
    #[serde(skip)]
    divergent: bool,
    /// `--trust-key` values that are not in the resolved `rotationKeys` (recorded
    /// verbatim regardless; each earns a warning).
    #[serde(skip)]
    off_chain_keys: Vec<DidKey>,
}
impl BaselineRecord {
    /// Fetch, verify, resolve, and (unless streaming to stdout) persist the baseline.
    pub(crate) fn record(args: &BaselineRecordArgs) -> Result<Self, CliError> {
        let plc_host = args.net.plc_host.clone().unwrap_or_default();
        let timeout = Duration::from_secs(args.net.timeout);
        let agent = ureq::AgentBuilder::new().timeout_connect(timeout).timeout_read(timeout).build();
        let chain = util::fetch_audit_chain(&agent, &plc_host, &args.did)?;
        let (baseline, divergent, off_chain_keys) = Self::build(&chain, args.trust_key.clone())?;

        let source = match (args.file.as_deref(), args.stdout) {
            (None, false) => InputSource::File(default_path(&args.did)?),
            (f, s) => InputSource::from_toggle(f, s),
        };
        let saved_to = match source {
            InputSource::Stdin => None,
            ref s @ InputSource::File(ref path) => {
                if path.exists() && !args.shared.force {
                    let msg = format!("baseline already exists at {}; pass --force to overwrite", path.display());
                    return Err(CliError::Usage(msg.into()));
                }
                let bytes = serde_json::to_vec_pretty(&baseline)
                    .map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
                s.write(&bytes)?;
                Some(path.clone())
            },
        };

        Ok(Self {
            baseline,
            saved_to,
            divergent,
            off_chain_keys,
        })
    }

    /// The network-free core: resolve the reported head, detect current divergence,
    /// flag off-chain trust keys, and compose the [`Baseline`]. Split out so it can
    /// be exercised against the fixture chains without a live directory.
    fn build(chain: &VerifiedAuditChain, trust_keys: Vec<DidKey>) -> Result<(Baseline, bool, Vec<DidKey>), CliError> {
        let resolver = ChainResolver::new(chain);
        // Record the head the directory reports: `check`/`Baseline::audit` anchor on
        // this same reported head, so the baseline must agree with it.
        let (state, _signer) = resolver.reported().map_err(|err| match err {
            ResolveError::Deactivated | ResolveError::NoActiveOperation => {
                CliError::ChainInvalid("identity is tombstoned or has no active operation; nothing to baseline".into())
            },
            other => CliError::ChainInvalid(format!("could not resolve head state: {other}").into()),
        })?;
        let divergent = !resolver.is_agreeable();
        let off_chain_keys: Vec<DidKey> =
            trust_keys.iter().filter(|&k| !state.rotation_keys().contains(k)).cloned().collect();
        Ok((Baseline::new(state, trust_keys), divergent, off_chain_keys))
    }
}
impl Outcome for BaselineRecord {
    fn exit_code(&self) -> ExitCode {
        // Capture always succeeds; divergence is a warning, not a failure.
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        if self.divergent {
            _ = writeln!(
                s,
                "{} identity is currently divergent (reported \u{2260} canonical); baselined the reported state anyway",
                paint(DANGER, "warning:"),
            );
        }
        for key in &self.off_chain_keys {
            _ = writeln!(
                s,
                "{} trusted key {} is not a current rotation key",
                paint(WARNING, "warning:"),
                paint(MUTED, key.as_str()),
            );
        }
        let keys = self.baseline.user_controlled_keys().len();
        _ = writeln!(s, "{} recorded baseline for {}", paint(LABEL, "baseline:"), self.baseline.did().as_str());
        _ = writeln!(s, "{} head operation is CID {}", paint(LABEL, "head:"), self.baseline.state().cid().as_str());
        _ = writeln!(s, "{} {keys} trusted key{}", paint(LABEL, "keys:"), if keys == 1 { "" } else { "s" });
        s
    }

    /// stdout carries the machine datum: the path we wrote (nothing when streaming,
    /// which is JSON-only and never reaches this renderer).
    fn datum(&self) -> Option<String> {
        self.saved_to.as_ref().map(|path| path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::audit::AuditLogEntry;
    use atshield_core::operation::Signed;
    use atshield_core::test::{TEST_AUDIT_CHAIN, TEST_DID_PLC, TEST_DID_ROTATION_PUBLIC};

    fn fixture_chain() -> VerifiedAuditChain {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(TEST_AUDIT_CHAIN).expect("fixture parses");
        VerifiedAuditChain::try_from(entries).expect("fixture verifies")
    }

    #[test]
    fn build_captures_reported_head_and_flags_off_chain_trust_keys() {
        let chain = fixture_chain();
        // A synthetic P-256 key; the fixture chain's rotation keys are secp256k1,
        // so this one is not on-chain.
        let off_chain: DidKey = TEST_DID_ROTATION_PUBLIC.parse().expect("valid did:key");
        let (baseline, divergent, off) = BaselineRecord::build(&chain, vec![off_chain.clone()]).expect("build");

        // Identity + head anchor come from the verified chain, and the anchor is the
        // reported head (what `check` will walk back to).
        assert_eq!(baseline.did().as_str(), TEST_DID_PLC);
        let (reported, _) = ChainResolver::new(&chain).reported().expect("reported");
        assert_eq!(baseline.state().cid(), reported.cid());

        // Trust keys recorded verbatim; the off-chain one is flagged, not dropped.
        assert_eq!(baseline.user_controlled_keys(), std::slice::from_ref(&off_chain));
        assert_eq!(off, vec![off_chain]);

        // The happy-path fixture's directory flags agree with authority.
        assert!(!divergent);
    }
}
