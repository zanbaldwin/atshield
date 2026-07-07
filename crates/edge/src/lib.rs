// SPDX-License-Identifier: LicenseRef-Proprietary
//! Stateless filter rules for the Fakesky sandbox edge.
//!
//! This is the abuse boundary in front of the vanilla `did-method-plc` reference
//! server: anything not rejected here is accepted or refused purely by the
//! directory's own operation validation. Three rules, all pure request-local
//! inspection (no shared state):
//!
//! 1. Route allow-list ([`route`]): only the endpoints `goat` needs during
//!    a recovery drill reach the directory (verified against the goat source;
//!    see `state/fakesky-pivot/research.md` §2); every other request is
//!    [`PlcRoute::AppPassthru`], handed to the control plane untouched.
//! 2. Genesis filter ([`body_verdict`]): a `POST /:did` whose body is a
//!    genesis operation (legacy `type: "create"`, or a `prev` that is not a
//!    non-empty string) is refused; only the control plane's private side door
//!    may mint sandbox identities.
//! 3. Body cap ([`MAX_BODY_BYTES`]): bounded buffering so body inspection
//!    cannot be abused (the same 100 kB as the upstream's own `express.json` cap).
//!
//! Everything here is transport-free (no I/O; the embedding runtime routes on
//! the request head, buffers a guarded body up to the cap, and asks for a verdict
//! at end of stream) so any runtime can share it verbatim.
//! Currently only shipping a Pingora runtime.
#![forbid(unsafe_code)]

/// Maximum accepted `POST` body size, in bytes.
///
/// Real PLC operations are a few kilobytes at most; the upstream reference server
/// caps request bodies at 100 kB. Anything larger is refused before it is buffered
/// further.
pub const MAX_BODY_BYTES: usize = 100 * 1024;

/// The routing decision for an incoming request, produced by [`route`].
///
/// This is how one public hostname is split between the two backends. Note that
/// [`AppPassthru`](Self::AppPassthru) is not a rejection: anything the directory
/// allow-list does not recognise belongs to the control plane, which applies its
/// own auth and abuse controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlcRoute {
    /// An allow-listed directory read; forward to the PLC upstream as-is.
    AllowedGet,
    /// An operation submission (`POST /:did`); forward to the PLC upstream only
    /// if the buffered body passes [`body_verdict`].
    GuardedPost,
    /// Not a directory route; hand to the control-plane upstream untouched.
    AppPassthru,
}

fn is_plc_did(segment: &str) -> bool {
    // Quick and dirty check; we only care that it looks DID-like instead of
    // validating it by constructing a [`DidPlc`](atshield_core::DidPlc).
    segment
        .strip_prefix("did:plc:")
        .is_some_and(|body| body.len() == 24 && body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

/// Classifies a request against the sandbox directory's allow-list.
///
/// A path is a directory route only when its first segment is a well-formed
/// `did:plc` identifier (24 lowercase base32 characters) and the method/tail
/// pair is one of the five endpoints `goat` exercises during a recovery drill:
/// `GET /:did`, `GET /:did/log`, `GET /:did/log/audit`, `GET /:did/data`, and
/// `POST /:did`. Everything else, including near-misses (a trailing slash,
/// `/:did/log/last`, an uppercase or truncated DID), is [`PlcRoute::AppPassthru`].
///
/// Matching is exact and case-sensitive; pass the canonical uppercase HTTP method.
///
/// # Examples
/// ```
/// use fakesky_edge::{PlcRoute, route};
///
/// let did = "/did:plc:ewvi7nxzyoun6zhxrhs64oiz";
/// assert_eq!(route("GET", &format!("{did}/log/audit")), PlcRoute::AllowedGet);
/// assert_eq!(route("POST", did), PlcRoute::GuardedPost);
/// assert_eq!(route("GET", "/export"), PlcRoute::AppPassthru);
/// ```
#[must_use]
pub fn route(method: &str, path: &str) -> PlcRoute {
    let Some(rest) = path.strip_prefix('/') else {
        return PlcRoute::AppPassthru;
    };
    let mut segments = rest.split('/');
    let Some(did) = segments.next() else {
        return PlcRoute::AppPassthru;
    };
    if !is_plc_did(did) {
        return PlcRoute::AppPassthru;
    }
    let tail: Vec<&str> = segments.collect();
    match (method, tail.as_slice()) {
        ("GET", [] | ["log" | "data"] | ["log", "audit"] | &["_health"]) => PlcRoute::AllowedGet,
        ("POST", []) => PlcRoute::GuardedPost,
        _ => PlcRoute::AppPassthru,
    }
}

/// The genesis-filter decision for a [`GuardedPost`](PlcRoute::GuardedPost) body,
/// produced by [`body_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyVerdict {
    /// Not a genesis shape; pass it on for the directory's own operation
    /// validation to judge.
    Forward,
    /// A genesis operation; refuse it (only the control plane's private side
    /// door may mint sandbox identities).
    RejectGenesis,
}

/// Judges whether a complete, buffered submission body is a genesis operation.
///
/// Deny by default on the two genesis shapes: a legacy creation (`"type": "create"`),
/// or a `prev` field that is anything other than a non-empty JSON string (missing,
/// `null`, empty, or a non-string). Bodies that are not JSON objects at all are
/// deliberately forwarded: they cannot be an acceptable genesis, and the directory's
/// own 400 is a more faithful teaching error than a synthetic edge rejection.
///
/// Pass the whole body (buffered up to [`MAX_BODY_BYTES`]), never a prefix; a
/// truncated genesis would fail to parse and be forwarded.
#[must_use]
pub fn body_verdict(body: &[u8]) -> BodyVerdict {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return BodyVerdict::Forward;
    };
    let Some(object) = value.as_object() else {
        return BodyVerdict::Forward;
    };
    if object.get("type").and_then(serde_json::Value::as_str) == Some("create") {
        return BodyVerdict::RejectGenesis;
    }
    match object.get("prev").and_then(serde_json::Value::as_str) {
        Some(prev) if !prev.is_empty() => BodyVerdict::Forward,
        _ => BodyVerdict::RejectGenesis,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

    fn path(suffix: &str) -> String {
        format!("/{DID}{suffix}")
    }

    #[test]
    fn allow_list_matches_the_goat_drill_surface() {
        for suffix in ["", "/log", "/log/audit", "/data"] {
            assert_eq!(route("GET", &path(suffix)), PlcRoute::AllowedGet, "GET {suffix:?}");
        }
        assert_eq!(route("POST", &path("")), PlcRoute::GuardedPost);
    }

    #[test]
    fn everything_else_is_denied() {
        assert_eq!(route("GET", "/export"), PlcRoute::AppPassthru);
        assert_eq!(route("GET", "/export/stream"), PlcRoute::AppPassthru);
        assert_eq!(route("GET", &path("/log/last")), PlcRoute::AppPassthru);
        assert_eq!(route("GET", "/_health"), PlcRoute::AppPassthru);
        assert_eq!(route("POST", "/admin/removeInvalidOps"), PlcRoute::AppPassthru);
        assert_eq!(route("POST", &path("/log")), PlcRoute::AppPassthru);
        assert_eq!(route("PUT", &path("")), PlcRoute::AppPassthru);
        assert_eq!(route("GET", &path("/")), PlcRoute::AppPassthru, "trailing slash");
        assert_eq!(route("GET", "/"), PlcRoute::AppPassthru);
        // The health endpoint belongs to the runtime, not the allow-list.
        assert_eq!(route("GET", "/healthz"), PlcRoute::AppPassthru);
    }

    #[test]
    fn malformed_dids_are_denied() {
        for bad in [
            "/did:plc:short",
            "/did:plc:EWVI7NXZYOUN6ZHXRHS64OIZ",
            "/did:plc:ewvi7nxzyoun6zhxrhs64oi1",
            "/did:web:example.com",
            "/ewvi7nxzyoun6zhxrhs64oiz",
        ] {
            assert_eq!(route("GET", bad), PlcRoute::AppPassthru, "{bad}");
        }
    }

    #[test]
    fn genesis_shapes_are_rejected() {
        for body in [
            r#"{"type":"create","signingKey":"z..."}"#,
            r#"{"type":"plc_operation","prev":null}"#,
            r#"{"type":"plc_operation"}"#,
            r#"{"type":"plc_operation","prev":42}"#,
            r#"{"type":"plc_operation","prev":""}"#,
        ] {
            assert_eq!(body_verdict(body.as_bytes()), BodyVerdict::RejectGenesis, "{body}");
        }
    }

    #[test]
    fn additive_shapes_are_forwarded_for_the_directory_to_judge() {
        for body in [
            r#"{"type":"plc_operation","prev":"bafyreib2rxk3rh6kzwq"}"#,
            r#"{"type":"plc_tombstone","prev":"bafyreib2rxk3rh6kzwq"}"#,
            "not json at all",
            "[1,2,3]",
        ] {
            assert_eq!(body_verdict(body.as_bytes()), BodyVerdict::Forward, "{body}");
        }
    }
}
