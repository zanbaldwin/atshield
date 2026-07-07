use crate::CliError;
use atshield_core::audit::{AuditLogEntry, VerifiedAuditChain};
use atshield_core::delta::Baseline;
use atshield_core::operation::Signed;
use atshield_core::{DidExt, DidPlc, Endpoint};
use directories::ProjectDirs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use ureq::Agent;

/// Cap on the audit-log body we will read (a single identity's log is tiny;
/// this only guards against a hostile/oversized response).
pub(crate) const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) fn fetch_audit_chain(
    agent: &Agent,
    plc_host: &Endpoint,
    did: &DidPlc,
) -> Result<VerifiedAuditChain, CliError> {
    let url = plc_host.audit(did.as_ref());
    // A non-2xx status and a transport error are both "could not fetch" (exit 69).
    let response = agent.get(&url).call().map_err(|err| match err {
        ureq::Error::Status(code, _) => {
            CliError::Unavailable(format!("could not fetch audit log: HTTP {code} from {url}").into())
        },
        e @ ureq::Error::Transport(_) => CliError::Unavailable(format!("could not fetch audit log: {e}").into()),
    })?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_BODY_BYTES)
        .read_to_end(&mut body)
        .map_err(|e| CliError::Unavailable(format!("could not fetch audit log: {e}").into()))?;
    let entries: Vec<AuditLogEntry<Signed>> = serde_json::from_slice(&body)
        .map_err(|e| CliError::ChainInvalid(format!("could not parse audit log: {e}").into()))?;
    let chain = VerifiedAuditChain::try_from(entries)
        .map_err(|e| CliError::ChainInvalid(format!("audit-log chain failed verification: {e}").into()))?;
    if chain.did() != did {
        let msg = format!("audit log is for {}, not the requested {did}", chain.did());
        return Err(CliError::ChainInvalid(msg.into()));
    }
    Ok(chain)
}

/// `-` as an explicit path means the stream too, the long spelling of the
/// `--stdin`/`--stdout` flag.
pub(crate) fn is_stdio<P: AsRef<Path>>(path: Option<P>) -> bool {
    path.is_some_and(|p| p.as_ref() == Path::new("-"))
}

/// Write `bytes` to `path` atomically: a sibling temp file (fsync'd) renamed over
/// the target, so a crash mid-write never leaves a torn baseline. Mirrors the
/// daemon's FileStore (see `state/decisions/filestore-atomic-write.md`).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("baseline.json");
    // pid-suffixed so two concurrent writers don't clobber one temp.
    let tmp = path.with_file_name(format!("{name}.{}.tmp", std::process::id()));
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// `<data_dir>/atshield/baseline-<plc-suffix>.json` (XDG on Linux). The 24-char
/// base32 suffix is a filesystem-safe path component by construction.
pub(crate) fn default_path(did: &DidPlc) -> Result<PathBuf, CliError> {
    let dirs = ProjectDirs::from("", "", "atshield")
        .ok_or_else(|| CliError::Usage("could not determine a config directory; pass an explicit path".into()))?;
    let suffix = did.as_str().strip_prefix("did:plc:").unwrap_or_else(|| did.as_str());
    Ok(dirs.data_dir().join(format!("baseline-{suffix}.json")))
}

/// Where the baseline was loaded from = the same place it is written back to
/// (`Stdin` is emitted as JSON, not persisted).
pub(crate) enum InputSource {
    Stdin,
    File(PathBuf),
}
/// Load an existing baseline from stdin (`stream`, or a `-` path) or a file (`file` /
/// the default path for `did`). A missing file is a usage error pointing at `baseline
/// record`. Shared by every `baseline` subcommand that reads a baseline back in.
pub(crate) fn load_baseline(
    stream: bool,
    file: Option<&Path>,
    did: &DidPlc,
) -> Result<(Baseline, InputSource), CliError> {
    if stream || is_stdio(file) {
        let mut buf = Vec::new();
        std::io::stdin().take(MAX_BODY_BYTES).read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(CliError::Data("no baseline on stdin".into()));
        }
        let baseline = serde_json::from_slice(&buf)
            .map_err(|e| CliError::Data(format!("stdin is not a valid baseline: {e}").into()))?;
        return Ok((baseline, InputSource::Stdin));
    }
    let path = match file {
        Some(path) => path.to_path_buf(),
        None => default_path(did)?,
    };
    let bytes = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            CliError::Usage(format!("no baseline at {}; run `atshield baseline record` first", path.display()).into())
        },
        _ => CliError::Io(e),
    })?;
    let baseline = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::Data(format!("baseline at {} is not valid: {e}", path.display()).into()))?;
    Ok((baseline, InputSource::File(path)))
}
