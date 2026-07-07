// SPDX-License-Identifier: MIT OR Apache-2.0
//! `atshield check`: the tamper verdict, and the point of the whole binary.
//!
//! Loads an existing [`Baseline`] (a file, or stdin with `--stdin`/`--baseline -`),
//! fetches and cryptographically verifies the live audit chain, and hands both
//! to core's [`Baseline::audit`] (the sole authorisation decision). `check` only
//! maps that result to an exit code, a human/JSON rendering, and (on divergence)
//! an `--alert-cmd` invocation. It is **fail-closed**: every way the audit can
//! decline to prove the state clean (a dishonest directory, a superseded baseline,
//! an unreadable on-path op, an unverifiable chain) is an alert (exit 1), never
//! a pass.

use crate::cli::CheckArgs;
use crate::output::{DANGER, LABEL, MUTED, SUCCESS, WARNING, describe_delta, paint};
use crate::{CliError, Outcome, util};
use anstyle::Style;
use atshield_core::audit::VerifiedAuditChain;
use atshield_core::delta::{AttributedChange, AuditReport, Baseline, Severity, Verdict};
use atshield_core::error::AuditError;
use atshield_core::resolver::ChainResolver;
use atshield_core::{Cid, DidExt, DidPlc};
use serde::Serialize;
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::time::Duration;

/// The result of `check`: the identity, its reported head, and the verdict. The
/// flattened [`CheckVerdict`] gives one flat JSON envelope; the same bytes `--json`
/// prints and `--alert-cmd` receives on stdin.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BaselineCheck {
    /// The audited identity.
    did: DidPlc,
    /// The directory's reported head [`Cid`], when it resolves (absent for a
    /// tombstoned head or an unverifiable chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<Cid>,
    /// The verdict and its attributed changes, flattened to the top level.
    #[serde(flatten)]
    verdict: CheckVerdict,
    /// A best-effort `--alert-cmd` dispatch warning (rendered to stderr, never
    /// serialised, never part of the alert payload).
    #[serde(skip)]
    alert_dispatch: Option<String>,
}

/// The flat verdict envelope. `Clean`/`Legitimate`/`Tamper` mirror core's
/// [`Verdict`] (carrying the historical `mitigated` axis alongside); `Error` is a
/// fail-closed alert that could not produce a live verdict at all.
#[derive(Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
enum CheckVerdict {
    /// No tracked field differs from the baseline.
    Clean {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        mitigated: Vec<AttributedChange>,
    },
    /// Every surviving change was signed by a user-controlled key.
    Legitimate {
        changes: Vec<AttributedChange>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        mitigated: Vec<AttributedChange>,
    },
    /// At least one surviving change was not user-authorised.
    Tamper {
        severity: Severity,
        changes: Vec<AttributedChange>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        mitigated: Vec<AttributedChange>,
    },
    /// The audit could not produce a live verdict; a fail-closed alert. `error` is
    /// the stable machine tag; `detail` is the plain-language operator message.
    Error { error: &'static str, detail: String },
}

impl BaselineCheck {
    /// Load the baseline, fetch and verify the live chain, audit, and (on divergence)
    /// fire `--alert-cmd`. Errors with [`CliError::Usage`] when the baseline names a
    /// different DID than `args.did`; transport failures propagate, but an
    /// unverifiable chain folds into an `Error` verdict rather than an error.
    pub(crate) fn run(args: &CheckArgs) -> Result<Self, CliError> {
        let (baseline, _) = args.load_baseline()?;
        if baseline.did() != &args.did {
            let msg = format!("baseline is for {}, not the requested {}", baseline.did().as_str(), args.did.as_str());
            return Err(CliError::Usage(msg.into()));
        }

        let plc_host = args.net.plc_host.clone().unwrap_or_default();
        let timeout = Duration::from_secs(args.net.timeout);
        let agent = ureq::AgentBuilder::new().timeout_connect(timeout).timeout_read(timeout).build();

        let mut report = match util::fetch_audit_chain(&agent, &plc_host, &args.did) {
            Ok(chain) => Self::classify(&baseline, &chain),
            // An unverifiable chain (parse / signature / cid / did-mismatch) is
            // fail-closed: we could not prove the identity clean, so alert rather
            // than abort. Transport failures stay `Unavailable` (transient).
            Err(CliError::ChainInvalid(msg)) => Self {
                did: args.did.clone(),
                head: None,
                alert_dispatch: None,
                verdict: CheckVerdict::Error {
                    error: "chain_invalid",
                    detail: msg.into_owned(),
                },
            },
            Err(err) => return Err(err),
        };

        let should_alert = match &report.verdict {
            CheckVerdict::Tamper { .. } | CheckVerdict::Error { .. } => true,
            CheckVerdict::Legitimate { .. } => args.alert_on_legitimate,
            CheckVerdict::Clean { .. } => false,
        };
        if let Some(cmd) = args.alert_cmd.as_deref()
            && should_alert
        {
            let alert_result = fire_alert_cmd(&report, cmd);
            report.alert_dispatch = match alert_result {
                Ok(status) if !status.success() => Some(format!("alert-cmd exited with status {status}")),
                Err(err) => Some(format!("alert-cmd failed: {err}")),
                _ => None,
            };
        }

        Ok(report)
    }

    /// The network-free core: audit the verified `chain` against `baseline` and map
    /// every outcome to a report. Infallible; a fail-closed [`AuditError`] becomes an
    /// `Error` verdict, not a [`CliError`]. Split out so the fixture chains can
    /// exercise it without a live directory.
    fn classify(baseline: &Baseline, chain: &VerifiedAuditChain) -> Self {
        let did = baseline.did().clone();
        let head = ChainResolver::new(chain).reported().ok().map(|(state, _)| state.cid().clone());
        match baseline.audit(chain) {
            Ok(AuditReport { live, mitigated }) => Self {
                did,
                head,
                alert_dispatch: None,
                verdict: match live {
                    Verdict::Clean => CheckVerdict::Clean { mitigated },
                    Verdict::Legitimate { changes } => CheckVerdict::Legitimate { changes, mitigated },
                    Verdict::Tamper { severity, changes } => CheckVerdict::Tamper { severity, changes, mitigated },
                },
            },
            Err(AuditError::DirectoryDivergence) => Self{
                did,
                head,
                alert_dispatch: None,
                verdict: CheckVerdict::Error {
                    error: "directory_divergence",
                    detail:
                        "the directory's reported state diverges from the canonical record atshield re-derives; the \
                        directory may be dishonest: treat as tampering"
                        .to_owned(),
                },
            },
            Err(AuditError::AnchorUnreachable) => Self{
                did,
                head,
                alert_dispatch: None,
                verdict: CheckVerdict::Error {
                    error: "anchor_unreachable",
                    detail:
                        "the baseline is no longer on the identity's reported history; if you deliberately rotated keys \
                        run `atshield baseline update`, otherwise treat this as tampering"
                        .to_owned(),
                },
            },
            Err(AuditError::Projection(cid, err)) => Self {
                did,
                head,
                alert_dispatch: None,
                verdict: CheckVerdict::Error {
                    error: "unreadable_operation",
                    detail: format!(
                        "the directory is serving a signed, authorised operation ({cid}) on this identity's history that \
                        atshield cannot read ({err}); a valid-but-unreadable operation on the live path can conceal a \
                        change: investigate the audit log before trusting this identity"
                    ),
                },
            },
        }
    }
}

/// Fire `--alert-cmd`, piping the alert JSON to its stdin. Yields the command's
/// [`ExitStatus`], or an error string if the payload could not be serialised or the
/// command could not be spawned, written to, or awaited.
///
// ponytail: no exec timeout, and the payload is assumed to fit the OS pipe buffer
// (a real alert command reads its stdin); thread the write if huge alerts appear.
fn fire_alert_cmd(report: &BaselineCheck, cmd: &str) -> Result<ExitStatus, String> {
    let json = serde_json::to_string(report).map_err(|e| format!("could not serialise alert payload: {e}"))?;
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("alert-cmd failed to start: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(json.as_bytes()).map_err(|e| format!("alert-cmd stdin write failed: {e}"))?;
        // stdin dropped at the end of this block -> EOF for the child.
    }
    child.wait().map_err(|e| format!("alert-cmd wait failed: {e}"))
}

impl Outcome for BaselineCheck {
    fn exit_code(&self) -> ExitCode {
        // Tamper and every fail-closed Error are alerts; Clean/Legitimate pass.
        match self.verdict {
            CheckVerdict::Tamper { .. } | CheckVerdict::Error { .. } => ExitCode::from(1),
            CheckVerdict::Clean { .. } | CheckVerdict::Legitimate { .. } => ExitCode::SUCCESS,
        }
    }

    fn status(&self) -> String {
        /// The lowercase name and colour for a [`Severity`].
        fn severity_label(severity: Severity) -> (&'static str, Style) {
            match severity {
                Severity::Info => ("info", MUTED),
                Severity::Suspicious => ("suspicious", WARNING),
                Severity::Warning => ("warning", WARNING),
                Severity::Critical => ("critical", DANGER),
            }
        }

        /// One `[severity] <delta>, signed by <signer> (un/authorised)` line.
        fn render_change(change: &AttributedChange) -> String {
            let (label, style) = severity_label(change.severity);
            let sev = format!("[{label}]");
            let (marker, mstyle) = if change.authorised { ("authorised", MUTED) } else { ("unauthorised", DANGER) };
            format!(
                "{} {}, signed by {} ({})",
                paint(style, &sev),
                describe_delta(&change.change),
                paint(MUTED, change.signer.as_str()),
                paint(mstyle, marker),
            )
        }

        /// Append the `mitigated:` block (already-undone incidents) when present.
        fn render_mitigated(s: &mut String, mitigated: &[AttributedChange]) {
            if mitigated.is_empty() {
                return;
            }
            _ = writeln!(
                s,
                "{} {} already-undone incident{} (no longer live)",
                paint(LABEL, "mitigated:"),
                mitigated.len(),
                if mitigated.len() == 1 { "" } else { "s" }
            );
            for change in mitigated {
                _ = writeln!(s, "  {}", render_change(change));
            }
        }

        let mut s = String::new();
        let did = self.did.as_str();
        match &self.verdict {
            CheckVerdict::Clean { mitigated } => {
                _ = writeln!(s, "{} no changes since baseline for {did}", paint(SUCCESS, "clean:"));
                render_mitigated(&mut s, mitigated);
            },
            CheckVerdict::Legitimate { changes, mitigated } => {
                _ = writeln!(
                    s,
                    "{} {} user-signed change{} since baseline for {did}",
                    paint(LABEL, "legitimate:"),
                    changes.len(),
                    if changes.len() == 1 { "" } else { "s" },
                );
                for change in changes {
                    _ = writeln!(s, "  {}", render_change(change));
                }
                render_mitigated(&mut s, mitigated);
            },
            CheckVerdict::Tamper { severity, changes, mitigated } => {
                let (label, style) = severity_label(*severity);
                _ = writeln!(s, "{} {} divergence for {did}", paint(DANGER, "TAMPER:"), paint(style, label));
                for change in changes {
                    _ = writeln!(s, "  {}", render_change(change));
                }
                render_mitigated(&mut s, mitigated);
            },
            CheckVerdict::Error { error: _, detail } => {
                _ = writeln!(s, "{} {detail}", paint(DANGER, "ALERT:"));
            },
        }
        if let Some(note) = &self.alert_dispatch {
            _ = writeln!(s, "{} {note}", paint(WARNING, "warning:"));
        }
        s
    }

    /// The one-word verdict on stdout (`--json` replaces this with the envelope).
    fn datum(&self) -> Option<String> {
        let word = match self.verdict {
            CheckVerdict::Clean { .. } => "clean",
            CheckVerdict::Legitimate { .. } => "legitimate",
            CheckVerdict::Tamper { .. } => "tamper",
            CheckVerdict::Error { .. } => "error",
        };
        Some(word.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::DidKey;
    use atshield_core::audit::AuditLogEntry;
    use atshield_core::delta::Delta;
    use atshield_core::operation::Signed;
    use atshield_core::resolver::ResolvedState;
    use atshield_core::test::{TEST_AUDIT_CHAIN, TEST_DID_PLC, TEST_DID_ROTATION_PUBLIC};

    fn fixture_chain() -> VerifiedAuditChain {
        let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_str(TEST_AUDIT_CHAIN).expect("fixture parses");
        VerifiedAuditChain::try_from(entries).expect("fixture verifies")
    }

    /// A baseline anchored at the chain's genesis state, so the later ops are
    /// post-baseline changes for the audit to classify.
    fn genesis_baseline(chain: &VerifiedAuditChain, user_keys: Vec<DidKey>) -> Baseline {
        let genesis = chain.entries().first().expect("chain is non-empty");
        let state = ResolvedState::project(chain.did(), genesis.operation()).expect("project genesis");
        Baseline::new(state, user_keys)
    }

    /// A report carrying `verdict` over a placeholder identity, for exercising the
    /// verdict-only surface (`exit_code`, `datum`, serialisation).
    fn report_with(verdict: CheckVerdict) -> BaselineCheck {
        BaselineCheck {
            did: DidPlc::new(TEST_DID_PLC).expect("valid did"),
            head: None,
            verdict,
            alert_dispatch: None,
        }
    }

    #[test]
    fn check_clean_when_baseline_is_the_reported_head() {
        let chain = fixture_chain();
        let (reported, _) = ChainResolver::new(&chain).reported().expect("reported");
        let report = BaselineCheck::classify(&Baseline::new(reported, vec![]), &chain);

        assert!(matches!(report.verdict, CheckVerdict::Clean { .. }));
        assert_eq!(report.datum().as_deref(), Some("clean"));
        assert!(matches!(report.exit_code(), ExitCode::SUCCESS));

        let value = serde_json::to_value(&report).expect("serialise");
        assert_eq!(value.get("verdict").and_then(serde_json::Value::as_str), Some("clean"));
        assert!(value.get("changes").is_none());
    }

    #[test]
    fn check_tamper_for_unauthorised_post_baseline_changes() {
        let chain = fixture_chain();
        // Trust nothing: every post-genesis change is unauthorised.
        let report = BaselineCheck::classify(&genesis_baseline(&chain, vec![]), &chain);

        assert!(matches!(report.verdict, CheckVerdict::Tamper { .. }));
        assert_eq!(report.datum().as_deref(), Some("tamper"));
        assert!(!matches!(report.exit_code(), ExitCode::SUCCESS));

        let value = serde_json::to_value(&report).expect("serialise");
        assert_eq!(value.get("verdict").and_then(serde_json::Value::as_str), Some("tamper"));
        assert!(value.get("severity").is_some_and(serde_json::Value::is_string));
        assert!(value.get("changes").and_then(serde_json::Value::as_array).is_some_and(|c| !c.is_empty()));

        // The rendered status names the verdict.
        let text = anstream::adapter::strip_str(&report.status()).to_string();
        assert!(text.contains("TAMPER"));
    }

    #[test]
    fn check_legitimate_when_every_signer_is_user_controlled() {
        let chain = fixture_chain();
        // Trust every key that signed any op -> every attributed change is authorised.
        let user_keys: Vec<DidKey> = chain.entries().iter().map(|e| e.signed_by().clone()).collect();
        let report = BaselineCheck::classify(&genesis_baseline(&chain, user_keys), &chain);

        // Clean (net-zero) or Legitimate (all authorised); never Tamper.
        assert!(matches!(report.verdict, CheckVerdict::Legitimate { .. } | CheckVerdict::Clean { .. }));
        assert!(matches!(report.exit_code(), ExitCode::SUCCESS));
    }

    #[test]
    fn legitimate_report_serialises_with_changes_and_no_severity() {
        let chain = fixture_chain();
        let signer: DidKey = TEST_DID_ROTATION_PUBLIC.parse().expect("valid did:key");
        let op = chain.entries().first().expect("non-empty").cid().clone();
        let change = AttributedChange {
            change: Delta::HandleChanged {
                from: "at://old.example".to_owned(),
                to: "at://new.example".to_owned(),
            },
            op,
            signer,
            authorised: true,
            severity: Severity::Info,
        };
        let report = BaselineCheck {
            did: chain.did().clone(),
            head: None,
            verdict: CheckVerdict::Legitimate { changes: vec![change], mitigated: vec![] },
            alert_dispatch: None,
        };

        assert_eq!(report.datum().as_deref(), Some("legitimate"));
        assert!(matches!(report.exit_code(), ExitCode::SUCCESS));

        let value = serde_json::to_value(&report).expect("serialise");
        assert_eq!(value.get("verdict").and_then(serde_json::Value::as_str), Some("legitimate"));
        assert!(value.get("changes").and_then(serde_json::Value::as_array).is_some_and(|c| c.len() == 1));
        // severity is present only on tamper; an absent head is skipped.
        assert!(value.get("severity").is_none());
        assert!(value.get("head").is_none());
    }

    #[test]
    fn error_report_alerts_and_serialises_flat() {
        let chain = fixture_chain();
        let report = BaselineCheck {
            did: chain.did().clone(),
            head: None,
            verdict: CheckVerdict::Error {
                error: "unreadable_operation",
                detail: "boom".to_owned(),
            },
            alert_dispatch: None,
        };

        assert_eq!(report.datum().as_deref(), Some("error"));
        assert!(!matches!(report.exit_code(), ExitCode::SUCCESS));

        let value = serde_json::to_value(&report).expect("serialise");
        assert_eq!(value.get("verdict").and_then(serde_json::Value::as_str), Some("error"));
        assert_eq!(value.get("error").and_then(serde_json::Value::as_str), Some("unreadable_operation"));
        assert_eq!(value.get("detail").and_then(serde_json::Value::as_str), Some("boom"));
    }

    #[test]
    fn exit_code_and_datum_by_verdict() {
        let clean = report_with(CheckVerdict::Clean { mitigated: vec![] });
        let legit = report_with(CheckVerdict::Legitimate { changes: vec![], mitigated: vec![] });
        let tamper = report_with(CheckVerdict::Tamper {
            severity: Severity::Critical,
            changes: vec![],
            mitigated: vec![],
        });
        let error = report_with(CheckVerdict::Error {
            error: "chain_invalid",
            detail: String::new(),
        });

        // Clean / Legitimate pass (exit 0); Tamper / Error are alerts (exit non-zero).
        assert!(matches!(clean.exit_code(), ExitCode::SUCCESS));
        assert!(matches!(legit.exit_code(), ExitCode::SUCCESS));
        assert!(!matches!(tamper.exit_code(), ExitCode::SUCCESS));
        assert!(!matches!(error.exit_code(), ExitCode::SUCCESS));

        assert_eq!(clean.datum().as_deref(), Some("clean"));
        assert_eq!(legit.datum().as_deref(), Some("legitimate"));
        assert_eq!(tamper.datum().as_deref(), Some("tamper"));
        assert_eq!(error.datum().as_deref(), Some("error"));
    }
}
