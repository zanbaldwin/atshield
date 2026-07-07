// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::cli::{NetArgs, OpBuildArgs};
use crate::output::{DANGER, LABEL, MUTED, WARNING, paint};
use crate::util::InputSource;
use crate::{CliError, Outcome, util};
use atshield_core::audit::VerifiedAuditChain;
use atshield_core::operation::{Operation, Unsigned};
use atshield_core::resolver::ChainResolver;
use atshield_core::{Cid, DidPlc};
use serde::Serialize;
use std::process::ExitCode;
use std::time::Duration;

enum Method {
    /// Forked from previously specified operation. Edit as needed.
    Forked(Cid),
    /// Built from existing baseline. Edit as needed.
    Baseline(InputSource),
    /// No previous operation or baseline to fork from, built from current chain
    /// head. You must edit before signing.
    Head(DidPlc, Cid),
}

/// The result of `op build`: an unsigned operation for the user to edit (drop the attacker key, fix the
/// PDS, …) before encoding and signing it. The source is resolved in priority order — an explicit
/// `--prev`, then a baseline, then the directory's current head.
#[derive(Serialize)]
#[serde(transparent)]
pub struct OpBuild {
    op: Operation<Unsigned>,
    /// The method use to fork depending on the input source.
    #[serde(skip)]
    method: Method,
}

impl OpBuild {
    /// Resolve the operation source and build the editable unsigned op.
    pub(crate) fn run(args: &OpBuildArgs) -> Result<Self, CliError> {
        if let Some(prev) = &args.prev {
            // (1) explicit CID: fork the on-chain operation there.
            return Self::from_prev(&args.did, prev, &args.net);
        }
        if let Some((baseline, source)) = args.load_baseline()? {
            // (2) baseline (offline): a full-restore op reconstructed from the recorded good state.
            return Ok(Self {
                method: Method::Baseline(source),
                op: baseline.state().into(),
            });
        }
        // (3) fallback: the directory's current reported head, which the user must edit by hand.
        Self::from_chain_head(&args.did, &args.net)
    }

    fn from_prev(did: &DidPlc, prev: &Cid, args: &NetArgs) -> Result<Self, CliError> {
        let chain = Self::fetch(did, args)?;
        let prev_op = chain
            .get(prev)
            .ok_or_else(|| CliError::Usage(format!("no operation {prev} in the audit log for {}", chain.did()).into()))?
            .operation();
        let forked_from_prev = prev_op.fork().map_err(|e| CliError::Software(format!("fork: {e}").into()))?;
        Ok(Self {
            method: Method::Forked(prev.clone()),
            op: forked_from_prev,
        })
    }

    fn from_chain_head(did: &DidPlc, args: &NetArgs) -> Result<Self, CliError> {
        let chain = Self::fetch(did, args)?;
        let (state, _) = ChainResolver::new(&chain)
            .reported()
            .map_err(|e| CliError::ChainInvalid(format!("could not resolve the current head: {e}").into()))?;
        Ok(Self {
            method: Method::Head(did.clone(), state.cid().clone()),
            op: (&state).into(),
        })
    }

    /// Fetch and verify the audit log for `--did` (sources 1 and 3).
    fn fetch(did: &DidPlc, args: &NetArgs) -> Result<VerifiedAuditChain, CliError> {
        let plc_host = args.plc_host.clone().unwrap_or_default();
        let timeout = Duration::from_secs(args.timeout);
        let agent = ureq::AgentBuilder::new().timeout_connect(timeout).timeout_read(timeout).build();
        util::fetch_audit_chain(&agent, &plc_host, did)
    }
}
impl Outcome for OpBuild {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        match &self.method {
            Method::Forked(cid) => format!(
                "{} {}\n{} {}\n",
                paint(LABEL, "note:"),
                paint(MUTED, "forked from previous operation"),
                paint(LABEL, "input:"),
                paint(MUTED, cid.as_str())
            ),
            Method::Baseline(source) => format!(
                "{} {}\n{} {}\n",
                paint(LABEL, "note:"),
                paint(MUTED, "built from existing baseline"),
                paint(LABEL, "input:"),
                match source {
                    InputSource::File(file) => paint(MUTED, format!("file://{}", file.display())),
                    InputSource::Stdin => paint(MUTED, "stdin://"),
                },
            ),
            Method::Head(did, cid) => format!(
                "{} {}\n{} {}\n{}\n",
                paint(DANGER, "warning:"),
                paint(MUTED, "No previous operation or baseline to fork from; used current chain head"),
                paint(LABEL, "input:"),
                paint(MUTED, format!("{did}@HEAD ({cid})")),
                paint(WARNING, "You must manually edit operation before signing.")
            ),
        }
    }

    fn datum(&self) -> Option<String> {
        Some(serde_json::to_string_pretty(&self.op).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::audit::AuditLogEntry;
    use atshield_core::operation::Signed;

    fn chain(json: &str) -> VerifiedAuditChain {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(json).unwrap();
        VerifiedAuditChain::try_from(entries).unwrap()
    }

    #[test]
    fn fork_produces_an_unsigned_successor_with_prev_set() {
        // The network-free core of source (1), as `from_prev` runs it after its fetch.
        let chain = chain(atshield_core::test::TEST_AUDIT_CHAIN);
        let head = chain.most_recent().cid().clone();
        let op = chain.get(&head).expect("the head is in the chain").operation().fork().expect("forks the head");
        assert_eq!(op.value().get("prev").and_then(|v| v.as_str()), Some(head.to_string().as_str()));
        assert!(op.value().get("sig").is_none(), "a forked op must be unsigned");
    }

    #[test]
    fn unknown_prev_is_not_in_the_chain() {
        // A real CID that is not in this chain: reuse a head CID from a different fixture chain.
        // `from_prev` maps this failed lookup to a `CliError::Usage`.
        let chain = chain(atshield_core::test::TEST_AUDIT_CHAIN);
        let other = self::chain(atshield_core::test::TEST_FORK_CHAIN).most_recent().cid().clone();
        assert!(chain.get(&other).is_none());
    }

    #[test]
    fn op_from_state_carries_the_state_with_prev_and_no_sig() {
        // Source (2)/(3): reconstruct from a resolved state (here the reported head of a fixture chain).
        let chain = chain(atshield_core::test::TEST_AUDIT_CHAIN);
        let (state, _) = ChainResolver::new(&chain).reported().expect("resolves");
        let op = Operation::<Unsigned>::from(&state);
        assert_eq!(op.value().get("type").and_then(|v| v.as_str()), Some("plc_operation"));
        assert_eq!(op.value().get("prev").and_then(|v| v.as_str()), Some(state.cid().to_string().as_str()));
        assert!(op.value().get("rotationKeys").is_some_and(serde_json::Value::is_array));
        assert!(op.value().get("sig").is_none());
    }
}
