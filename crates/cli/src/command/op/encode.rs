// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::cli::OpEncodeArgs;
use crate::util::InputSource;
use crate::{CliError, Outcome};
use atshield_core::operation::{Operation, Unsigned};
use serde::Serialize;
use serde_json::Value;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

/// The result of `op encode`: the operation's DAG-CBOR signing bytes as hex (default), or nothing
/// (`--raw` — the bytes were written straight to stdout).
#[derive(Serialize)]
pub struct OpEncode {
    /// `None` when `--raw` already streamed the bytes to stdout.
    encoded: Option<String>,
}

impl OpEncode {
    /// Parse the operation JSON and emit its DAG-CBOR signing bytes (hex, or raw with `--raw`).
    pub(crate) fn run(args: &OpEncodeArgs) -> Result<Self, CliError> {
        let source = InputSource::from(Path::new(&args.file));
        let bytes = source.read()?.ok_or_else(|| CliError::Data("JSON not found in input".into()))?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| CliError::Data("operation is not valid JSON".into()))?;
        let op = Operation::<Unsigned>::from_value(value)
            .map_err(|e| CliError::Data(format!("not a valid unsigned operation: {e}").into()))?;
        let cbor = op.signing_input().map_err(|e| CliError::Software(format!("encode: {e}").into()))?;
        if !args.hex {
            // Binary bytes bypass the text Outcome/Emit path: write them straight to stdout.
            std::io::stdout().lock().write_all(&cbor).map_err(CliError::Io)?;
            return Ok(Self { encoded: None });
        }
        let mut hex = String::with_capacity(cbor.len() * 2);
        cbor.iter().fold(&mut hex, |s, b| {
            _ = write!(s, "{b:02x}");
            s
        });
        Ok(Self { encoded: Some(hex) })
    }
}

impl Outcome for OpEncode {
    fn exit_code(&self) -> ExitCode {
        ExitCode::SUCCESS
    }

    fn status(&self) -> String {
        String::new()
    }

    fn datum(&self) -> Option<String> {
        self.encoded.clone()
    }
}
