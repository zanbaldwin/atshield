// SPDX-License-Identifier: MIT OR Apache-2.0
//! The clap command tree: the binary's public contract. Business logic lives in
//! `main.rs`'s dispatch; this file only declares the surface.

use atshield_core::Handle;
use atshield_core::crypto::Signature;
use atshield_core::{Cid, DidKey, DidPlc, Endpoint};
use clap::{Args, ColorChoice, Parser, Subcommand};
use std::path::PathBuf;

/// Command-line client for atshield did:plc identity-tampering detection.
#[derive(Parser)]
#[command(name = "atshield", version, about, long_about = None)]
pub struct Cli {
    /// Control colour output [auto, always, never]
    #[arg(long, global = true, default_value = "auto")]
    pub color: ColorChoice,

    /// Emit machine-readable JSON to stdout (the shape is per-command)
    #[arg(short, long, global = true, env = "ATSHIELD_JSON")]
    pub json: bool,

    /// Show extra detail (whisper-level diagnostics)
    #[arg(short, long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Suppress non-essential output (keep only must-show lines)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Capture the current verified identity state as a baseline file
    Baseline(BaselineArgs),
    /// Check the live identity against a baseline; exit non-zero on tampering
    Check(CheckArgs),
    /// Resolve a `@handle` to its `did:plc` DID (bidirectionally verified)
    Handle(HandleArgs),
    /// Proof-of-possession: mint, sign, or verify a challenge nonce (offline)
    Challenge(ChallengeArgs),
    /// Recovery-operation helpers (never touches a private key)
    Op(OpArgs),
}

/// Network options shared by the commands that contact plc.directory.
#[derive(Args)]
pub struct NetArgs {
    /// plc.directory base URL
    #[arg(short = 'p', long = "plc-host", env = "ATSHIELD_PLC_HOST", value_name = "PLC_HOST")]
    pub plc_host: Option<Endpoint>,

    /// HTTP/DNS timeout, seconds
    #[arg(
        short = 't',
        long,
        env = "ATSHIELD_TIMEOUT",
        default_value_t = 30,
        value_name = "TIMEOUT"
    )]
    pub timeout: u64,
}

#[derive(Args)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub command: BaselineCommand,
}

#[derive(Subcommand)]
pub enum BaselineCommand {
    /// Capture the current verified identity state as a baseline file
    Record(BaselineRecordArgs),
    /// Refresh an existing baseline to the directory's current state, keeping its
    /// user-controlled keys
    Update(BaselineUpdateArgs),
    /// Trust a `did:key` as user-controlled (its changes classify as Legitimate,
    /// not Tamper)
    TrustKey(BaselineKeyArgs),
    /// Untrust a `did:key` (its changes no longer classify as Legitimate)
    UntrustKey(BaselineKeyArgs),
}

/// Options common to every `baseline` subcommand.
#[derive(Args)]
pub struct BaselineSharedArgs {
    /// Overwrite an existing baseline (required only when the output file exists)
    #[arg(short = 'f', long, default_value_t = false)]
    pub force: bool,
}

#[derive(Args)]
pub struct BaselineRecordArgs {
    /// The `did:plc:` identity to baseline.
    #[arg(env = "ATSHIELD_DID", value_name = "DID")]
    pub did: DidPlc,

    /// Where to write the baseline JSON (default `<baseline_dir>/baseline-<suffix>.json`;
    /// `-` writes to stdout, implying --json)
    #[arg(short = 'o', long = "file", env = "ATSHIELD_OUTPUT", value_name = "OUTPUT")]
    pub file: Option<PathBuf>,

    /// Write the baseline to stdout instead of a file (implies --json); the
    /// explicit spelling is `--file -`.
    #[arg(long, conflicts_with = "file")]
    pub stdout: bool,

    /// A `did:key` you control (repeatable; env is comma-separated). Recorded
    /// so a self-initiated change classifies as Legitimate rather than Tamper.
    #[arg(
        short = 'k',
        long = "trust-key",
        env = "ATSHIELD_TRUST_KEY",
        value_delimiter = ',',
        value_name = "TRUST_KEY"
    )]
    pub trust_key: Vec<DidKey>,

    #[command(flatten)]
    pub shared: BaselineSharedArgs,

    #[command(flatten)]
    pub net: NetArgs,
}

/// `baseline trust-key` / `baseline untrust-key` have identical surface; the
/// subcommand name (and its body) decides whether `<KEY>` is trusted or untrusted
/// as user-controlled.
#[derive(Args)]
pub struct BaselineKeyArgs {
    /// The `did:plc:` identity to baseline.
    #[arg(env = "ATSHIELD_DID", value_name = "DID")]
    pub did: DidPlc,

    /// The `did:key` to trust / untrust as user-controlled.
    #[arg(value_name = "KEY")]
    pub key: DidKey,

    /// Where to read+write the baseline JSON
    /// (default `<baseline_dir>/baseline-<suffix>.json`; `-` is stdin -> stdout)
    #[arg(short = 'o', long = "file", env = "ATSHIELD_OUTPUT", value_name = "OUTPUT")]
    pub file: Option<PathBuf>,

    /// Read the baseline from stdin and emit the updated one to stdout (implies
    /// --json); the explicit spelling is `--file -`.
    #[arg(long, conflicts_with = "file")]
    pub stdin: bool,

    #[command(flatten)]
    pub shared: BaselineSharedArgs,
}

/// `baseline update` re-resolve the identity's current state and rewrite the
/// baseline, carrying its `userControlledKeys` forward unchanged. Needs an existing
/// baseline; `--force` is required for any write (without it, a dry-run preview).
#[derive(Args)]
pub struct BaselineUpdateArgs {
    /// The `did:plc:` identity whose baseline to update.
    #[arg(env = "ATSHIELD_DID", value_name = "DID")]
    pub did: DidPlc,

    /// Where to read+write the baseline JSON
    /// (default `<baseline_dir>/baseline-<suffix>.json`; `-` is stdin -> stdout)
    #[arg(short = 'o', long = "file", env = "ATSHIELD_OUTPUT", value_name = "OUTPUT")]
    pub file: Option<PathBuf>,

    /// Read the baseline from stdin and emit the updated one to stdout (implies
    /// --json; never writes to disk); the explicit spelling is `--file -`.
    #[arg(long, conflicts_with = "file")]
    pub stdin: bool,

    #[command(flatten)]
    pub shared: BaselineSharedArgs,

    #[command(flatten)]
    pub net: NetArgs,
}

#[derive(Args)]
pub struct CheckArgs {
    /// The `did:plc:` identity to check.
    #[arg(env = "ATSHIELD_DID", value_name = "DID")]
    pub did: DidPlc,

    /// Baseline JSON path (default `<baseline_dir>/baseline-<suffix>.json`;
    /// `-` is stdin)
    #[arg(short, long, env = "ATSHIELD_BASELINE", value_name = "BASELINE")]
    pub baseline: Option<PathBuf>,

    /// Read the baseline from stdin instead of a file (does not imply --json);
    /// the explicit spelling is `--baseline -`.
    #[arg(long, conflicts_with = "baseline")]
    pub stdin: bool,

    /// Shell command run on divergence; the alert JSON is piped to its stdin
    #[arg(
        short = 'a',
        long = "alert-cmd",
        env = "ATSHIELD_ALERT_CMD",
        value_name = "ALERT_CMD"
    )]
    pub alert_cmd: Option<String>,

    /// Also fire `--alert-cmd` on a Legitimate (user-signed) divergence
    #[arg(
        short = 'l',
        long = "alert-on-legitimate",
        env = "ATSHIELD_ALERT_ON_LEGITIMATE",
        default_value_t = false
    )]
    pub alert_on_legitimate: bool,

    #[command(flatten)]
    pub net: NetArgs,
}

#[derive(Args)]
pub struct HandleArgs {
    /// The `@handle` to resolve (domain may or may not start with `@`)
    #[arg(value_name = "HANDLE", required = true)]
    pub handle: Handle,

    #[command(flatten)]
    pub net: NetArgs,

    /// XRPC AppView for the last-resort `resolveHandle` fallback
    #[arg(
        short = 'r',
        long = "resolver-host",
        env = "ATSHIELD_RESOLVER_HOST",
        value_name = "RESOLVER_HOST"
    )]
    pub resolver_host: Option<Endpoint>,
}

#[derive(Args)]
pub struct ChallengeArgs {
    #[command(subcommand)]
    pub command: ChallengeCommand,
}

#[derive(Subcommand)]
pub enum ChallengeCommand {
    /// Mint a fresh challenge nonce (`INVALID:` + 64 hex). Stateless: no identity,
    /// purpose, or expiry binding (those live server-side).
    New,
    /// Sign a message locally with a rotation key (raw bytes or canonical JSON).
    /// Reads the key in-memory and makes zero network calls.
    Sign(ChallengeSignArgs),
    /// Verify that a signature covers a nonce under a `did:key`
    Verify(ChallengeVerifyArgs),
}

#[derive(Args)]
pub struct ChallengeSignArgs {
    #[command(subcommand)]
    pub command: SignCommand,
}

#[derive(Subcommand)]
pub enum SignCommand {
    /// Sign a message's raw bytes verbatim
    Raw(SignRawArgs),
    /// Sign a JSON payload by its canonical Value. Reformatting or re-indenting
    /// the JSON does not change the signature.
    Payload(SignPayloadArgs),
}

/// The private rotation key for the `sign raw` / `sign payload` commands;
/// supplied as a path or as material, never both (the `key_source` group is
/// mutually exclusive).
#[derive(Args)]
#[command(group = clap::ArgGroup::new("key_source").args(["key_file", "key"]).multiple(false))]
pub struct KeySourceArgs {
    /// File holding the private rotation key (base58btc multikey). Never passed
    /// on argv.
    #[arg(
        short = 'k',
        long = "key-file",
        env = "ATSHIELD_KEY_FILE",
        value_name = "KEY_FILE",
        group = "key_source"
    )]
    pub key_file: Option<PathBuf>,

    /// Private rotation key material; intended for the `ATSHIELD_KEY` env (secret
    /// stores that inject values, not files).
    #[arg(
        long = "key-raw",
        env = "ATSHIELD_KEY",
        value_name = "KEY_RAW",
        hide = true,
        group = "key_source"
    )]
    pub key: Option<String>,
}

/// `challenge sign raw` signs a message's raw bytes verbatim.
#[derive(Args)]
pub struct SignRawArgs {
    /// The message to sign (`-` reads raw bytes from stdin). For
    /// proof-of-possession, pass the nonce string verbatim.
    // Remove the angle brackets if this ever becomes a required arg.
    #[arg(value_name = "<MESSAGE>", default_value = "-")]
    pub message: String,

    #[command(flatten)]
    pub key_source: KeySourceArgs,
}

/// `challenge sign payload` signs a JSON payload by its canonical Value, not
/// its bytes.
#[derive(Args)]
pub struct SignPayloadArgs {
    /// The JSON payload to sign (`-` reads it from stdin). The canonical JSON Value is signed, so insignificant
    /// whitespace and formatting do not change the signature.
    // Remove the angle brackets if this ever becomes a required arg.
    #[arg(value_name = "<JSON>", default_value = "-")]
    pub payload: String,

    #[command(flatten)]
    pub key_source: KeySourceArgs,
}

#[derive(Args)]
pub struct ChallengeVerifyArgs {
    /// The signed message (`-` reads raw bytes from stdin). For proof-of-possession, the nonce string verbatim.
    // Remove the angle brackets if this ever becomes a required arg.
    #[arg(value_name = "<MESSAGE>", default_value = "-")]
    pub message: String,

    /// The `did:key` the signature should verify under
    #[arg(short = 'k', long = "did-key", value_name = "DID_KEY")]
    pub did_key: DidKey,

    /// The signature to verify (base64url or DER)
    #[arg(short = 's', long, value_name = "SIGNATURE")]
    pub signature: Signature,
}

#[derive(Args)]
pub struct OpArgs {
    #[command(subcommand)]
    pub command: OpCommand,
}

/// Composable, key-free helpers for a goat-free recovery: `build` an editable operation, `encode` it to
/// the exact bytes to sign, and normalise the resulting `sig`. The private key crosses only your signer
/// (e.g. openssl), never atshield; every output is deterministic and independently verifiable.
#[derive(Subcommand)]
pub enum OpCommand {
    /// Build an editable unsigned operation, forked from a last-known-good CID (fetches the audit log)
    Build(OpBuildArgs),
    /// Canonicalise an operation JSON to the exact DAG-CBOR bytes that must be signed (offline)
    Encode(OpEncodeArgs),
    /// Normalise an openssl DER signature to the low-S base64url `sig` a PLC operation carries (offline)
    Sig(OpSigArgs),
}

#[derive(Args)]
pub struct OpBuildArgs {
    /// The `did:plc:` identity to build the operation for
    #[arg(env = "ATSHIELD_DID", value_name = "DID")]
    pub did: DidPlc,
    /// Fork from this specific last-known-good operation CID (highest-priority source; baked in as `prev`)
    #[arg(long = "prev", value_name = "CID")]
    pub prev: Option<Cid>,
    /// Build a full-restore op from this baseline JSON. Without `--prev`, a baseline is preferred over the
    /// live head; if this is omitted the default `<baseline_dir>/baseline-<suffix>.json` is used when present.
    #[arg(
        short = 'b',
        long = "baseline",
        env = "ATSHIELD_BASELINE",
        value_name = "BASELINE",
        conflicts_with = "prev"
    )]
    pub baseline: Option<PathBuf>,
    /// Read the baseline from stdin instead of a file; the explicit spelling is `--baseline -`.
    #[arg(long, conflicts_with_all = ["baseline", "prev"])]
    pub stdin: bool,
    #[command(flatten)]
    pub net: NetArgs,
}

#[derive(Args)]
pub struct OpEncodeArgs {
    /// The operation JSON to encode (`-` reads it from stdin)
    #[arg(value_name = "FILE", default_value = "-")]
    pub file: String,
    /// Emit hex-encoded string instead of raw DAG-CBOR bytes; for debugging, printing, and piping to `xxd`.
    #[arg(long)]
    pub hex: bool,
}

#[derive(Args)]
pub struct OpSigArgs {
    /// The DER/high-S signature from your signer (`-` reads stdin; accepts raw DER bytes or base64)
    #[arg(value_name = "FILE", default_value = "-")]
    pub file: String,
    /// Your public rotation `did:key` — supplies the curve for low-S normalisation
    #[arg(short = 'k', long = "key", value_name = "DID_KEY")]
    pub key: DidKey,
}
