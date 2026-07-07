// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::Outcome;
use crate::output::{MUTED, WARNING, paint};
use atshield_core::crypto::Nonce;
use serde::Serialize;
use std::fmt::Write;
use std::process::ExitCode;

/// The result of `challenge new`: a freshly minted nonce plus its wire-schema
/// tag.
#[derive(Serialize)]
pub struct ChallengeNew {
    schema: &'static str,
    nonce: Nonce,
}
impl ChallengeNew {
    /// Mint a fresh challenge nonce.
    pub fn new() -> Self {
        Self {
            schema: "atshield.challenge.v1",
            nonce: Nonce::generate(),
        }
    }
}
impl Outcome for ChallengeNew {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        let mut s = String::new();
        _ = writeln!(
            s,
            "{} stateless mint{}",
            paint(WARNING, "note:"),
            paint(MUTED, " (identity, purpose, and expiry are bound server-side)"),
        );
        s
    }

    fn datum(&self) -> Option<String> {
        Some(self.nonce.as_str().to_owned())
    }
}
