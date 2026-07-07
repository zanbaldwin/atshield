mod new;
mod sign;
mod verify;

pub use self::new::ChallengeNew;
pub use self::sign::ChallengeSign;
pub use self::verify::ChallengeVerify;
use crate::CliError;
use crate::util::InputSource;

/// Resolve a message argument to the exact bytes to sign/verify: `-` reads raw
/// bytes from stdin, anything else is the argument's own bytes verbatim (no
/// trimming, no nonce parsing).
pub(super) fn read_message(arg: &str) -> Result<Vec<u8>, CliError> {
    match arg {
        "-" => InputSource::Stdin.read()?.ok_or_else(|| CliError::Data("message data not found in input".into())),
        data => Ok(data.as_bytes().to_vec()),
    }
}
