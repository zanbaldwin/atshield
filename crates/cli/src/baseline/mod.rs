mod check;
mod record;
mod trust_key;
mod untrust_key;
mod update;

pub(crate) use self::check::BaselineCheck;
pub(crate) use self::record::BaselineRecord;
pub(crate) use self::trust_key::BaselineTrustKey;
pub(crate) use self::untrust_key::BaselineUntrustKey;
pub(crate) use self::update::BaselineUpdate;
use crate::cli::{BaselineKeyArgs, BaselineUpdateArgs, CheckArgs};
use crate::{CliError, util};
use atshield_core::DidPlc;
use atshield_core::delta::Baseline;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Where the baseline was loaded from = the same place it is written back to
/// (`Stdin` is emitted as JSON, not persisted).
enum Source {
    Stdin,
    File(PathBuf),
}

/// Load an existing baseline from stdin (`stream`, or a `-` path) or a file (`file` /
/// the default path for `did`). A missing file is a usage error pointing at `baseline
/// record`. Shared by every `baseline` subcommand that reads a baseline back in.
fn load_baseline(stream: bool, file: Option<&Path>, did: &DidPlc) -> Result<(Baseline, Source), CliError> {
    if stream || util::is_stdio(file) {
        let mut buf = Vec::new();
        std::io::stdin().take(util::MAX_BODY_BYTES).read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(CliError::Data("no baseline on stdin".into()));
        }
        let baseline = serde_json::from_slice(&buf)
            .map_err(|e| CliError::Data(format!("stdin is not a valid baseline: {e}").into()))?;
        return Ok((baseline, Source::Stdin));
    }
    let path = match file {
        Some(path) => path.to_path_buf(),
        None => util::default_path(did)?,
    };
    let bytes = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            CliError::Usage(format!("no baseline at {}; run `atshield baseline record` first", path.display()).into())
        },
        _ => CliError::Io(e),
    })?;
    let baseline = serde_json::from_slice(&bytes)
        .map_err(|e| CliError::Data(format!("baseline at {} is not valid: {e}", path.display()).into()))?;
    Ok((baseline, Source::File(path)))
}
impl BaselineKeyArgs {
    /// The `trust-key` / `untrust-key` view of [`load_baseline`].
    fn load_baseline(&self) -> Result<(Baseline, Source), CliError> {
        load_baseline(self.stdin, self.file.as_deref(), &self.did)
    }
}
impl BaselineUpdateArgs {
    /// The `update` view of [`load_baseline`].
    fn load_baseline(&self) -> Result<(Baseline, Source), CliError> {
        load_baseline(self.stdin, self.file.as_deref(), &self.did)
    }
}
impl CheckArgs {
    /// The `check` view of [`load_baseline`] (its path arg is `--baseline`).
    fn load_baseline(&self) -> Result<(Baseline, Source), CliError> {
        load_baseline(self.stdin, self.baseline.as_deref(), &self.did)
    }
}
