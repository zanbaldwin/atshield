// SPDX-License-Identifier: MIT OR Apache-2.0
//! Composable, key-free helpers for a goat-free recovery: `build` an editable operation from a
//! last-known-good CID, `encode` it to the exact DAG-CBOR bytes to sign, and `sig`-normalise the DER
//! signature your off-box signer (e.g. openssl) produces into the low-S base64url wire form. atshield
//! never sees a private key; every transform is deterministic and independently verifiable.

mod build;
mod encode;
mod sig;

pub use self::build::OpBuild;
pub use self::encode::OpEncode;
pub use self::sig::OpSig;
use crate::cli::OpBuildArgs;
use crate::{CliError, util};
use atshield_core::delta::Baseline;

impl OpBuildArgs {
    /// The `op build` view of [`load_baseline`](util::load_baseline): stdin or an explicit `--baseline`
    /// must yield a baseline; a missing default path is `None` (fall through to the live head).
    fn load_baseline(&self) -> Result<Option<(Baseline, util::InputSource)>, CliError> {
        util::load_baseline(self.stdin, self.baseline.as_deref(), &self.did)
    }
}
