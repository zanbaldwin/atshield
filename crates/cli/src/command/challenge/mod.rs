mod new;
mod sign;
mod verify;

pub use self::new::ChallengeNew;
pub use self::sign::ChallengeSign;
pub use self::verify::ChallengeVerify;
use crate::CliError;
use std::io::Read;

/// Resolve a message argument to the exact bytes to sign/verify: `-` reads raw
/// bytes from stdin, anything else is the argument's own bytes verbatim (no
/// trimming, no nonce parsing).
pub(super) fn read_message(arg: &str) -> Result<Vec<u8>, CliError> {
    if arg == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.is_empty() {
            return Err(CliError::Data("no input on stdin".into()));
        }
        Ok(buf)
    } else {
        Ok(arg.as_bytes().to_vec())
    }
}
