// SPDX-License-Identifier: MIT OR Apache-2.0

use super::read_message;
use crate::cli::ChallengeVerifyArgs;
use crate::output::{DANGER, SUCCESS, paint};
use crate::{CliError, Outcome};
use serde::Serialize;
use std::process::ExitCode;

/// The result of `challenge verify`: whether `signature` covers `message` under
/// `did_key`.
#[derive(Serialize)]
pub struct ChallengeVerify {
    schema: &'static str,
    verified: bool,
}
impl ChallengeVerify {
    /// Verify the signature over the message (verbatim bytes; `-` reads raw
    /// stdin) under the key.
    pub(crate) fn new(args: &ChallengeVerifyArgs) -> Result<Self, CliError> {
        let message = read_message(&args.message)?;
        let verified = args.did_key.verify(&args.signature, &message);
        Ok(Self {
            schema: "atshield.verification.v1",
            verified,
        })
    }
}
impl Outcome for ChallengeVerify {
    fn exit_code(&self) -> ExitCode {
        if self.verified {
            ExitCode::SUCCESS
        } else {
            // EX_DATAERR
            ExitCode::from(65)
        }
    }

    fn status(&self) -> String {
        String::new()
    }

    /// The verdict is the machine datum (stdout), coloured; `AutoStream` strips
    /// the colour when stdout is not a TTY.
    fn datum(&self) -> Option<String> {
        Some(if self.verified {
            paint(SUCCESS, "verified").to_string()
        } else {
            paint(DANGER, "verification failed").to_string()
        })
    }
}
