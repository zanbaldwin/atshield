use crate::CliError;
use atshield_core::audit::{AuditLogEntry, VerifiedAuditChain};
use atshield_core::delta::Baseline;
use atshield_core::operation::Signed;
use atshield_core::{DidExt, DidPlc, Endpoint};
use directories::ProjectDirs;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
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

/// Where the baseline was loaded from = the same place it is written back to
/// (`Stdin` is emitted as JSON, not persisted).
pub(crate) enum InputSource {
    Stdin,
    File(PathBuf),
}
impl InputSource {
    pub(crate) fn from_toggle<'a, O: Into<Option<&'a Path>>>(value: O, stream: bool) -> Self {
        match (stream, value.into()) {
            (false, Some(p)) if p != Path::new("-") => Self::File(p.to_path_buf()),
            _ => Self::Stdin,
        }
    }

    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, CliError> {
        let mut buf = Vec::new();
        let _bytes_read = match self {
            Self::File(p) => match File::open(p) {
                Ok(f) => f.take(MAX_BODY_BYTES).read_to_end(&mut buf).map_err(CliError::Io),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => Err(CliError::Io(e)),
            },
            Self::Stdin => io::stdin().take(MAX_BODY_BYTES).read_to_end(&mut buf).map_err(CliError::Io),
        }?;
        match self {
            Self::Stdin if buf.is_empty() => Ok(None),
            Self::Stdin | Self::File(_) => Ok(Some(buf)),
        }
    }

    /// Persist `bytes` back to this source: an atomic write for a file (returning the
    /// path written), `None` for stdin — the caller streams the document to stdout via
    /// the JSON datum instead, keeping stdout ownership with the `Emit` sink.
    pub(crate) fn write(&self, bytes: &[u8]) -> Result<usize, CliError> {
        match self {
            Self::Stdin => Ok(0), // TODO: Write to stdout?
            Self::File(path) => {
                use std::fs;
                if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                    fs::create_dir_all(parent)?;
                }
                let name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
                    CliError::Data(format!("could not determine file name: {}", path.display()).into())
                })?;
                // pid-suffixed so two concurrent writers don't clobber one temp.
                let tmp = path.with_file_name(format!("{name}.{}.tmp", std::process::id()));
                let mut file = File::create(&tmp)?;
                file.write_all(bytes)?;
                file.sync_all()?;
                fs::rename(&tmp, path)?;
                Ok(bytes.len())
            },
        }
    }
}
impl<'a, O: Into<Option<&'a Path>>> From<O> for InputSource {
    fn from(value: O) -> Self {
        Self::from_toggle(value, false)
    }
}

/// `<data_dir>/atshield/baseline-<plc-suffix>.json` (XDG on Linux). The 24-char
/// base32 suffix is a filesystem-safe path component by construction.
pub(crate) fn default_path(did: &DidPlc) -> Result<PathBuf, CliError> {
    let dirs = ProjectDirs::from("", "", "atshield")
        .ok_or_else(|| CliError::Usage("could not determine a config directory; pass an explicit path".into()))?;
    let suffix = did.as_str().strip_prefix("did:plc:").unwrap_or_else(|| did.as_str());
    Ok(dirs.data_dir().join(format!("baseline-{suffix}.json")))
}

/// Load an existing baseline from stdin (`stream`, or a `-` path) or a file (`file` /
/// the default path for `did`). A missing file is a usage error pointing at `baseline
/// record`. Shared by every `baseline` subcommand that reads a baseline back in.
pub(crate) fn load_baseline(
    stream: bool,
    file: Option<&Path>,
    did: &DidPlc,
) -> Result<Option<(Baseline, InputSource)>, CliError> {
    let source = match (file, stream) {
        (None, false) => InputSource::File(default_path(did)?),
        (f, s) => InputSource::from_toggle(f, s),
    };
    let Some(bytes) = source.read()? else {
        return Ok(None);
    };
    let baseline = match (&source, serde_json::from_slice(&bytes)) {
        (_, Ok(b)) => Ok(b),
        (InputSource::Stdin, Err(e)) => {
            Err(CliError::Data(format!("baseline streamed via stdin is not valid: {e}").into()))
        },
        (InputSource::File(p), Err(e)) => {
            Err(CliError::Data(format!("baseline in file {} is not valid: {e}", p.display()).into()))
        },
    }?;
    Ok(Some((baseline, source)))
}
