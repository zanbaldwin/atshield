// SPDX-License-Identifier: MIT OR Apache-2.0
//! URL builders for the PLC directory HTTP API.
//!
//! Pure string construction: core performs no I/O and bundles no HTTP client. A
//! caller parses a host into an [`Endpoint`] once, builds the URL it needs, fetches
//! it with its own client, and feeds the bytes back to the library.
//!
//! Per-DID endpoints ([`audit`](Endpoint::audit), [`data`](Endpoint::data)) take
//! a `did`; the bulk firehose ([`export`](Endpoint::export), [`stream`](Endpoint::stream))
//! is global and takes none.

use crate::error::EndpointError;
use std::fmt;
use std::str::FromStr;

/// The default PLC directory host (`https://plc.directory`).
pub const DEFAULT_PLC_HOST: &str = "https://plc.directory";
/// The maximum `count` the directory's `/export` accepts; larger requests are
/// clamped to this server-side, so [`export`](Endpoint::export) clamps too.
pub const MAX_EXPORT_COUNT: u32 = 1000;

/// A PLC directory origin: a bare host plus whether it is reached over TLS.
///
/// Parse one with [`FromStr`] (`"https://plc.directory".parse()`), then call the
/// builder methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    secure: bool,
}
impl Endpoint {
    /// Construct from an already-bare host (no scheme). A trailing slash, if any,
    /// is stripped to uphold the no-double-slash invariant.
    #[must_use]
    pub fn new(host: impl Into<String>, is_secure: bool) -> Self {
        let host = host.into().trim_end_matches('/').to_string();
        Self { host, secure: is_secure }
    }

    /// The bare host (no scheme, no trailing slash).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether requests use TLS (`https`/`wss` rather than `http`/`ws`).
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// `GET /{did}/log/audit`: the audit log with the `nullified` flag, and the
    /// core endpoint for monitoring and recovery.
    #[must_use]
    pub fn audit(&self, did: impl AsRef<str>) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        format!("{scheme}://{}/{}/log/audit", self.host, did.as_ref())
    }

    /// `GET /{did}/data`: the directory's resolved structured state. Diagnostics
    /// and seeding only; not authoritative for tamper detection.
    #[must_use]
    pub fn data(&self, did: impl AsRef<str>) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        format!("{scheme}://{}/{}/data", self.host, did.as_ref())
    }

    /// `GET /export`: global JSON-Lines bulk export (cursor-paginated) for backfill
    /// and firehose gap recovery. `count` is clamped to [`MAX_EXPORT_COUNT`];
    /// `after` is an ISO timestamp or integer sequence and is percent-encoded.
    #[must_use]
    pub fn export<'a>(&self, count: impl Into<Option<u32>>, after: impl Into<Option<&'a str>>) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        let mut params = Vec::with_capacity(2);
        if let Some(c) = count.into() {
            params.push(format!("count={}", c.min(MAX_EXPORT_COUNT)));
        }
        if let Some(a) = after.into() {
            params.push(format!("after={}", percent_encode(a)));
        }
        let query = if params.is_empty() { String::new() } else { format!("?{}", params.join("&")) };
        format!("{scheme}://{}/export{query}", self.host)
    }

    /// `wss://{host}/export/stream`: global WebSocket firehose. `cursor` is an
    /// integer sequence and is percent-encoded.
    #[must_use]
    pub fn stream<'a>(&self, cursor: impl Into<Option<&'a str>>) -> String {
        let scheme = if self.secure { "wss" } else { "ws" };
        let query = if let Some(c) = cursor.into() { format!("?cursor={}", percent_encode(c)) } else { String::new() };
        format!("{scheme}://{}/export/stream{query}", self.host)
    }
}
impl Default for Endpoint {
    fn default() -> Self {
        DEFAULT_PLC_HOST.parse().expect("DEFAULT_PLC_HOST is a valid Endpoint")
    }
}
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.secure { "https" } else { "http" };
        write!(f, "{scheme}://{}", self.host)
    }
}
impl FromStr for Endpoint {
    type Err = EndpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (secure, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("wss://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = s.strip_prefix("ws://") {
            (false, r)
        } else if s.contains("://") {
            return Err(EndpointError::UnsupportedScheme(s.to_string()));
        } else {
            (true, s) // schemeless → assume TLS; never silently downgrade to http.
        };
        let host = rest.trim_end_matches('/');
        if host.is_empty() {
            return Err(EndpointError::EmptyHost);
        }
        Ok(Self { host: host.to_string(), secure })
    }
}

/// Percent-encode a query-component value: keep RFC 3986 unreserved bytes,
/// `%XX`-escape everything else. Correct-but-naive (escapes more than strictly
/// required); fine for the short `after`/`cursor` values we build.
// ponytail: inline encoder over a `percent-encoding` dep. This crate is pure
// primitives with a curated, =-pinned dep list; swap in the crate if we ever
// need full RFC 3986 component sets elsewhere.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let hex = |n: u8| char::from_digit(u32::from(n), 16).unwrap_or('0').to_ascii_uppercase();
            out.push('%');
            out.push(hex(b >> 4));
            out.push(hex(b & 0x0f));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";

    #[test]
    fn builds_audit_and_data_urls() {
        assert_eq!(Endpoint::default().audit(DID), format!("https://plc.directory/{DID}/log/audit"));
        assert_eq!(Endpoint::default().data(DID), format!("https://plc.directory/{DID}/data"));
    }

    #[test]
    fn trims_a_trailing_host_slash() {
        let a: Endpoint = "https://plc.directory/".parse().unwrap();
        assert_eq!(a, "https://plc.directory".parse().unwrap());
        assert_eq!(a.audit(DID), "https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit");
    }

    #[test]
    fn export_is_global_with_no_did_and_clamps_count() {
        assert_eq!(Endpoint::default().export(None, None), "https://plc.directory/export");
        assert_eq!(Endpoint::default().export(Some(5000), None), "https://plc.directory/export?count=1000");
    }

    #[test]
    fn stream_is_global_and_uses_ws_scheme() {
        assert_eq!(Endpoint::default().stream(None::<&str>), "wss://plc.directory/export/stream");
        let insecure = Endpoint::new("localhost:2582", false);
        assert_eq!(insecure.stream(Some("42")), "ws://localhost:2582/export/stream?cursor=42");
    }

    #[test]
    fn iso_timestamp_after_is_percent_encoded() {
        assert_eq!(
            Endpoint::default().export(Some(10), Some("2026-06-28T12:00:00.000Z")),
            "https://plc.directory/export?count=10&after=2026-06-28T12%3A00%3A00.000Z"
        );
    }

    #[test]
    fn schemeless_defaults_to_https() {
        let e: Endpoint = "plc.directory".parse().unwrap();
        assert!(e.is_secure());
        assert_eq!(e.audit(DID), format!("https://plc.directory/{DID}/log/audit"));
    }

    #[test]
    fn rejects_empty_host_and_unknown_scheme() {
        assert_eq!("https://".parse::<Endpoint>(), Err(EndpointError::EmptyHost));
        assert!(matches!("ftp://x".parse::<Endpoint>(), Err(EndpointError::UnsupportedScheme(_))));
    }

    #[test]
    fn local_directory() {
        let e: Endpoint = "http://localhost:2582/plc-directory/".parse().unwrap();
        assert!(!e.is_secure());
        assert_eq!(e.audit(DID), "http://localhost:2582/plc-directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit");
    }

    #[test]
    fn default_endpoint() {
        let e = Endpoint::default();
        assert_eq!(e, "https://plc.directory".parse().unwrap());
        assert_eq!(e, "https://plc.directory/".parse().unwrap());
        assert_eq!(e, DEFAULT_PLC_HOST.parse().unwrap());
    }
}
