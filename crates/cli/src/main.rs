// SPDX-License-Identifier: MIT OR Apache-2.0
// A CLI legitimately writes to the process streams; the workspace lints (tuned
// for libraries) warn on that. missing_docs: a binary crate has no public API
// to document.
#![allow(clippy::print_stdout, clippy::print_stderr, missing_docs)]

mod cli;
mod command;
mod output;
mod util;

use crate::cli::{BaselineCommand, ChallengeCommand, OpCommand, SignCommand};
use crate::cli::{Cli, Command};
use crate::command::baseline::{BaselineCheck, BaselineRecord, BaselineTrustKey, BaselineUntrustKey, BaselineUpdate};
use crate::command::challenge::{ChallengeNew, ChallengeSign, ChallengeVerify};
use crate::command::handle::HandleResolution;
use crate::command::op::{OpBuild, OpEncode, OpSig};
use crate::output::Emit;
use clap::Parser;
use std::borrow::Cow;
use std::io::Write;
use std::process::ExitCode;

/// Operational failures that abort a command and fall back to the flat
/// `atshield error: {err}` handler in [`main`]; anything a command can render
/// richly (a divergence, a missing back-reference) is an [`Outcome`], not a
/// `CliError`. This is the generic last resort, so it holds only enough variants
/// to carry a message and pick an exit code (see [`CliError::exit_code`]).
#[derive(Debug, thiserror::Error)]
enum CliError {
    /// EX_USAGE (64): the invocation cannot proceed (bad signing key, bad handle).
    /// The message is caller-built and never contains key material.
    #[error("{0}")]
    Usage(Cow<'static, str>),
    /// EX_DATAERR (65): input or resolved data was malformed (bad JSON, an
    /// unsupported DID method).
    #[error("{0}")]
    Data(Cow<'static, str>),
    /// EX_DATAERR (65): the audit chain could not be cryptographically verified
    /// (parse failure, bad signature, tombstoned head, or a log served for another
    /// DID). Distinct from [`Data`](Self::Data): a crypto failure, not bad user
    /// input. Fail-closed: an unverifiable chain is an operational alert.
    #[error("{0}")]
    ChainInvalid(Cow<'static, str>),
    /// EX_UNAVAILABLE (69): a remote lookup or fetch could not be completed
    /// (resolving the handle, or fetching the audit log).
    #[error("{0}")]
    Unavailable(Cow<'static, str>),
    /// EX_SOFTWARE (70): an internal invariant broke (e.g. a serialise that
    /// should be unreachable), or a command is not built yet.
    #[error("{0}")]
    Software(Cow<'static, str>),
    /// EX_IOERR (74): reading input (stdin, a key file) failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
impl CliError {
    /// Process exit code, per the committed table: `64` EX_USAGE, `65` EX_DATAERR,
    /// `69` EX_UNAVAILABLE, `70` EX_SOFTWARE, `74` EX_IOERR. The success codes
    /// `0` (clean, or a user-signed divergence) and `1` (tampering) come from
    /// [`Outcome::exit_code`]; `2` (arg error) is emitted by clap.
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::from(64),
            Self::Data(_) | Self::ChainInvalid(_) => ExitCode::from(65),
            Self::Unavailable(_) => ExitCode::from(69),
            Self::Software(_) => ExitCode::from(70),
            Self::Io(_) => ExitCode::from(74),
        }
    }
}

/// A command's result value, emittable two ways: serialised to JSON (`--json`)
/// or rendered to the terminal. The terminal split is [`status`](Self::status)
/// (human, stderr) plus an optional [`datum`](Self::datum) (machine, stdout);
/// the `erased_serde::Serialize` supertrait (+ `serialize_trait_object!`) lets
/// `dyn Outcome` serialise so [`dispatch`] can box heterogeneous command outcomes
/// behind one type.
trait Outcome: erased_serde::Serialize {
    fn exit_code(&self) -> ExitCode;

    /// The human-facing status block for stderr: zero or more newline-terminated
    /// lines, styled inline with [`output::paint`]. Empty when the command has
    /// nothing to say; suppressed wholesale by `--quiet`.
    fn status(&self) -> String;

    /// The single machine datum for stdout, if any (plain, except `verify` which
    /// colours its one-word verdict).
    fn datum(&self) -> Option<String>;
}
erased_serde::serialize_trait_object!(Outcome);

/// Emit an [`Outcome`]: JSON to stdout when `json`, else the human status block
/// to stderr and the machine datum to stdout through the [`Emit`] sink. Returns
/// the outcome's own process exit code.
fn emit(outcome: &dyn Outcome, out: &mut Emit, json: bool) -> Result<ExitCode, CliError> {
    if json {
        let body = serde_json::to_string(outcome).map_err(|e| CliError::Software(format!("serialise: {e}").into()))?;
        // `println!` panics if the write fails; a closed reader makes that an
        // EPIPE (eg, `… --json | head`). Return an I/O error if the pipe was
        // broken, instead of panicking.
        let mut stdout = std::io::stdout().lock();
        if let Err(e) = writeln!(stdout, "{body}")
            && e.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(CliError::Io(e));
        }
    } else {
        out.write_status(&outcome.status()).map_err(CliError::Io)?;
        if let Some(datum) = outcome.datum() {
            out.write_datum(&datum).map_err(CliError::Io)?;
        }
    }
    Ok(outcome.exit_code())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = Emit::new(cli.color, cli.quiet);
    match dispatch(&cli).and_then(|report| emit(&*report, &mut out, wants_json(&cli))) {
        Ok(code) => code,
        Err(err) => {
            // Best-effort: swallow a broken stderr pipe rather than panicking
            // as eprintln! would.
            let mut stderr = std::io::stderr().lock();
            _ = writeln!(stderr, "atshield error: {err}");
            err.exit_code()
        },
    }
}

/// Emit JSON when `--json` is set, or when a `baseline` subcommand writes its
/// document to stdout (`--stdout`/`--stdin`, or the equivalent `--file -`). A
/// document on a pipe wants to be machine-readable. `check` reading a baseline
/// on stdin does NOT force JSON: its output (a one-word verdict) is unchanged
/// either way, so it is deliberately absent from the match.
fn wants_json(cli: &Cli) -> bool {
    cli.json
        || match &cli.command {
            Command::Baseline(args) => match &args.command {
                // BaselineCommand::Record(r) => r.stdout || baseline::is_dash(r.file.as_deref()),
                BaselineCommand::Record(r) => r.stdout || util::is_stdio(r.file.as_deref()),
                BaselineCommand::Update(u) => u.stdin || util::is_stdio(u.file.as_deref()),
                BaselineCommand::TrustKey(k) | BaselineCommand::UntrustKey(k) => {
                    k.stdin || util::is_stdio(k.file.as_deref())
                },
            },
            _ => false,
        }
}

/// Route the parsed command to its body, returning the boxed [`Outcome`] to emit.
/// Each command adds one arm; the `Box<dyn Outcome>` lets heterogeneous outcomes
/// funnel through one `emit`.
fn dispatch(cli: &Cli) -> Result<Box<dyn Outcome>, CliError> {
    Ok(match &cli.command {
        Command::Baseline(args) => match &args.command {
            BaselineCommand::Record(args) => Box::new(BaselineRecord::record(args)?),
            BaselineCommand::Update(args) => Box::new(BaselineUpdate::run(args)?),
            BaselineCommand::TrustKey(args) => Box::new(BaselineTrustKey::run(args)?),
            BaselineCommand::UntrustKey(args) => Box::new(BaselineUntrustKey::run(args)?),
        },
        Command::Check(args) => Box::new(BaselineCheck::run(args)?),
        Command::Handle(args) => Box::new(HandleResolution::run(args)?),
        Command::Challenge(args) => match &args.command {
            ChallengeCommand::New => Box::new(ChallengeNew::new()),
            ChallengeCommand::Verify(args) => Box::new(ChallengeVerify::new(args)?),
            ChallengeCommand::Sign(args) => match &args.command {
                SignCommand::Raw(args) => Box::new(ChallengeSign::raw(args)?),
                SignCommand::Payload(args) => Box::new(ChallengeSign::payload(args)?),
            },
        },
        Command::Op(args) => match &args.command {
            OpCommand::Build(args) => Box::new(OpBuild::run(args)?),
            OpCommand::Encode(args) => Box::new(OpEncode::run(args)?),
            OpCommand::Sig(args) => Box::new(OpSig::run(args)?),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::test::{TEST_DID_PLC, TEST_DID_ROTATION_PUBLIC};

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("atshield").chain(args.iter().copied()))
    }

    #[test]
    fn stream_forms_imply_json_for_baseline() {
        // Both the named flag and the equivalent `-` path put the document on
        // stdout, so both must force JSON.
        for args in [
            &["baseline", "record", TEST_DID_PLC, "--stdout"][..],
            &["baseline", "record", TEST_DID_PLC, "--file", "-"][..],
            &["baseline", "update", TEST_DID_PLC, "--stdin"][..],
            &["baseline", "update", TEST_DID_PLC, "--file", "-"][..],
            &[
                "baseline",
                "trust-key",
                TEST_DID_PLC,
                TEST_DID_ROTATION_PUBLIC,
                "--stdin",
            ][..],
            &[
                "baseline",
                "trust-key",
                TEST_DID_PLC,
                TEST_DID_ROTATION_PUBLIC,
                "--file",
                "-",
            ][..],
        ] {
            assert!(wants_json(&parse(args).expect("parses")), "{args:?} should imply --json");
        }
    }

    #[test]
    fn check_stdin_does_not_imply_json() {
        // `check` reads a baseline on stdin but its verdict output is unchanged.
        assert!(!wants_json(&parse(&["check", TEST_DID_PLC, "--stdin"]).expect("parses")));
        assert!(!wants_json(&parse(&["check", TEST_DID_PLC, "--baseline", "-"]).expect("parses")));
        assert!(!wants_json(&parse(&["baseline", "record", TEST_DID_PLC]).expect("parses")));
    }

    #[test]
    fn stream_flag_conflicts_with_path() {
        // The named stream flag and an explicit `--file`/`--baseline` are mutually
        // exclusive ways to say the same thing, so together they are a usage error.
        assert!(parse(&["baseline", "record", TEST_DID_PLC, "--stdout", "--file", "x.json"]).is_err());
        assert!(parse(&["baseline", "update", TEST_DID_PLC, "--stdin", "--file", "x.json"]).is_err());
        assert!(parse(&["check", TEST_DID_PLC, "--stdin", "--baseline", "x.json"]).is_err());
    }
}
