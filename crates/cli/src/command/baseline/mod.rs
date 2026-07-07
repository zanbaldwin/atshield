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
use atshield_core::delta::Baseline;

impl BaselineKeyArgs {
    /// The `trust-key` / `untrust-key` view of [`load_baseline`].
    fn load_baseline(&self) -> Result<(Baseline, util::InputSource), CliError> {
        util::load_baseline(self.stdin, self.file.as_deref(), &self.did)?
            .ok_or_else(|| CliError::Data("baseline not found in input".into()))
    }
}
impl BaselineUpdateArgs {
    /// The `update` view of [`load_baseline`].
    fn load_baseline(&self) -> Result<(Baseline, util::InputSource), CliError> {
        util::load_baseline(self.stdin, self.file.as_deref(), &self.did)?
            .ok_or_else(|| CliError::Data("baseline not found in input".into()))
    }
}
impl CheckArgs {
    /// The `check` view of [`load_baseline`] (its path arg is `--baseline`).
    fn load_baseline(&self) -> Result<(Baseline, util::InputSource), CliError> {
        util::load_baseline(self.stdin, self.baseline.as_deref(), &self.did)?
            .ok_or_else(|| CliError::Data("baseline not found in input".into()))
    }
}
