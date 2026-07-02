// SPDX-License-Identifier: MIT OR Apache-2.0
//! Terminal output for the CLI: a semantic style palette plus the [`Emit`] sink
//! that routes the machine datum to stdout (always) and human status to stderr
//! (styled, suppressed by `--quiet`).
//!
//! Styling is [`anstyle`] value types rendered inline via [`paint`]; the
//! stream-aware colour decision (honouring `--color`, `NO_COLOR`, `CLICOLOR`,
//! `TERM=dumb`, and whether each stream is a TTY) is left to [`anstream::AutoStream`],
//! which strips the escapes when a stream should not be coloured.

use anstyle::{AnsiColor, Color, Effects, Style};
use atshield_core::DidExt;
use atshield_core::delta::Delta;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{self, Write};

const fn fg(colour: AnsiColor) -> Style {
    Style::new().fg_color(Some(Color::Ansi(colour)))
}

/// A resolved / verified result (green).
pub const SUCCESS: Style = fg(AnsiColor::Green);
/// A hard failure or an unverifiable state (red).
pub const DANGER: Style = fg(AnsiColor::Red);
/// A non-fatal caveat (yellow).
pub const WARNING: Style = fg(AnsiColor::Yellow);
/// A neutral field label (cyan).
pub const LABEL: Style = fg(AnsiColor::Cyan);
/// The salient datum within a status line (bold).
pub const HIGHLIGHT: Style = Style::new().effects(Effects::BOLD);
/// Secondary detail (dimmed).
pub const MUTED: Style = Style::new().effects(Effects::DIMMED);

/// `text` wrapped in `style`'s ANSI escapes, rendered lazily into a `write!`.
/// The escapes are always emitted; [`anstream::AutoStream`] strips them when the
/// target stream should not be coloured.
pub fn paint(style: Style, text: &str) -> Painted<'_> {
    Painted { style, text }
}

/// The [`Display`] adapter returned by [`paint`].
pub struct Painted<'a> {
    style: Style,
    text: &'a str,
}
impl Display for Painted<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // `{s}` opens the style; the alternate `{s:#}` emits the reset.
        let s = self.style;
        write!(f, "{s}{}{s:#}", self.text)
    }
}

/// Output sink for one command: the machine datum to stdout, human status to
/// stderr. Both streams are [`anstream::AutoStream`]s built from `--color`, so
/// ANSI is kept on a colour-capable TTY and stripped otherwise (piped, `NO_COLOR`,
/// `--color never`, `TERM=dumb`).
pub struct Emit {
    out: anstream::AutoStream<io::Stdout>,
    err: anstream::AutoStream<io::Stderr>,
    quiet: bool,
}
impl Emit {
    /// Build the sink from the `--color` choice and the `--quiet` flag.
    pub fn new(colour: clap::ColorChoice, quiet: bool) -> Self {
        let choice = match colour {
            clap::ColorChoice::Auto => anstream::ColorChoice::Auto,
            clap::ColorChoice::Always => anstream::ColorChoice::Always,
            clap::ColorChoice::Never => anstream::ColorChoice::Never,
        };
        Self {
            out: anstream::AutoStream::new(io::stdout(), choice),
            err: anstream::AutoStream::new(io::stderr(), choice),
            quiet,
        }
    }

    /// Write the human status `block` (newline-terminated lines) to stderr,
    /// unless `--quiet` or the block is empty. A broken pipe is swallowed.
    pub fn write_status(&mut self, block: &str) -> io::Result<()> {
        if self.quiet || block.is_empty() {
            return Ok(());
        }
        swallow_pipe(self.err.write_all(block.as_bytes()).and_then(|()| self.err.flush()))
    }

    /// Write the machine `datum` (one line) to stdout. A broken pipe is swallowed
    /// (e.g. `… | head`); any other write error propagates.
    pub fn write_datum(&mut self, datum: &str) -> io::Result<()> {
        swallow_pipe(writeln!(self.out, "{datum}").and_then(|()| self.out.flush()))
    }
}

/// One human line describing a single [`Delta`], diff-style (`+`/`-`/`~`). Shared
/// by the `baseline update` preview and the `check` change list.
pub(crate) fn describe_delta(delta: &Delta) -> String {
    match delta {
        Delta::KeyAdded { index, key } => format!("+ rotation key {} (position {index})", key.as_str()),
        Delta::KeyRemoved { key } => format!("- rotation key {}", key.as_str()),
        Delta::KeyOrderShift { key, old, new } => format!("~ rotation key {} moved {old} -> {new}", key.as_str()),
        Delta::SigningKeyChanged { from, to } => format!("~ signing key {} -> {}", from.as_str(), to.as_str()),
        Delta::PdsEndpointChanged { from, to } => format!("~ PDS endpoint {from} -> {to}"),
        Delta::HandleChanged { from, to } => format!("~ handle {from} -> {to}"),
    }
}

/// Map a broken pipe to success: the reader went away, which is not our failure.
fn swallow_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}
