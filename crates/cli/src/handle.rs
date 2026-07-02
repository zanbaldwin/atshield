// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `handle` subcommand: resolve a `@handle` to its `did:plc` and verify the
//! link in both directions.
//!
//! Resolution runs the standard ATProto ladder and takes the first method that
//! answers: an `_atproto` DNS TXT record, then `/.well-known/atproto-did` over
//! HTTPS, then the XRPC `resolveHandle` fallback on an AppView
//! ([`DEFAULT_RESOLVER_HOST`]). [`SystemResolver`] is the production
//! [`HandleResolver`]; the trait exists so the network side effects can be
//! substituted in tests.
//!
//! Verification then fetches the DID's full audit chain and cross-checks two
//! things: that the directory record names the queried handle back (the
//! `alsoKnownAs` back-reference), and that the state the directory currently
//! serves ("reported") matches the state atshield re-derives as legitimate
//! ("canonical"). A mismatch is a tampering *warning*, not an error: the command
//! always resolves and shouts the bare DID (exit 0), recording any verification
//! problem on the [`HandleResolution`] rather than aborting.

use crate::cli::HandleArgs;
use crate::output::{DANGER, HIGHLIGHT, LABEL, MUTED, SUCCESS, WARNING, paint};
use crate::util::{MAX_BODY_BYTES, fetch_audit_chain};
use crate::{CliError, Outcome};
use atshield_core::error::DidError;
use atshield_core::resolver::ChainResolver;
use atshield_core::{DidPlc, Endpoint};
use c_ares_resolver::{BlockingResolver, Options};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Read;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use ureq::Agent;

/// XRPC AppView for the last-resort `resolveHandle` fallback.
pub(crate) const DEFAULT_RESOLVER_HOST: &str = "https://public.api.bsky.app";

/// The resolution and verification side-effect seam, split into the two phases
/// the `handle` command runs in sequence: forward resolution (handle to DID) and
/// chain verification (DID back to handle). [`SystemResolver`] is the live
/// implementation; tests provide their own.
pub(crate) trait HandleResolver {
    /// Forward-resolve a handle to its `did:plc`, trying each [`Method`] in turn
    /// and returning the first that answers. Returns `Err` when no method produces
    /// a DID, when a record is ambiguous, or when the resolved value is not a
    /// supported `did:plc`.
    fn resolve(&self, domain: &BareHandle) -> Result<ResolvedDid, CliError>;

    /// Fetch and cryptographically verify `did`'s audit chain, then assemble the
    /// full [`HandleResolution`]: the directory back-reference, the primary handle,
    /// and whether the reported state diverges from the canonical one. Returns
    /// `Err` if the chain cannot be fetched, fails verification, or its reported
    /// head cannot be resolved; a failure to derive the *canonical* head is
    /// recorded on the result instead.
    fn verify(&self, domain: &BareHandle, did: &ResolvedDid) -> Result<HandleResolution, CliError>;
}

/// The outcome of the `handle` command: a resolved DID plus the cross-checks
/// that say whether the handle and its directory record still agree.
///
/// Produced by [`run`](Self::run); the [`Outcome`] impl renders the status and
/// warning lines to stderr and the bare DID to stdout (the machine datum) so it
/// can be piped into `check --did`. The directory and divergence fields are only
/// meaningful while [`verification_error`](Self::verification_error) is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HandleResolution {
    /// The queried handle, normalised (no `@`, lowercased).
    pub handle: BareHandle,
    /// The DID it resolved to, tagged with the [`Method`] that found it.
    pub did: ResolvedDid,
    /// Whether the DID's directory record lists this handle in its `alsoKnownAs`
    /// (the back-reference). `false` means the link only holds one way.
    pub directory_verified: bool,
    /// The account's primary handle (the first `alsoKnownAs` entry), when one
    /// is published and parses. The rendered output only remarks on it when it
    /// differs from [`handle`](Self::handle).
    pub aka_primary: Option<BareHandle>,
    /// `true` when the directory's reported state diverges from the canonical
    /// state atshield re-derives from the chain, i.e. a possible tamper inside
    /// the 72-hour window. Always `false` while
    /// [`verification_error`](Self::verification_error) is set.
    pub tampering_detected: bool,
    /// Set when the chain could not be fully verified (fetch failed, the chain
    /// failed verification, or the canonical head could not be resolved). When
    /// present, the directory and divergence signals are unreliable and the
    /// rendered output shows this message in their place.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_error: Option<String>,
}
impl HandleResolution {
    /// Run the `handle` command: build a [`SystemResolver`] from `args`,
    /// forward-resolve the handle, then verify the DID it found.
    ///
    /// Forward-resolution failure is fatal and returns `Err`; verification failure
    /// is not. If [`verify`](HandleResolver::verify) fails, its error is recorded
    /// on the returned value (with the cross-check fields left cleared) so the
    /// command still reports the DID and exits cleanly.
    pub(crate) fn run(args: &HandleArgs) -> Result<Self, CliError> {
        let plc_host = args.net.plc_host.clone().unwrap_or_default();
        let resolver_host: Endpoint = match &args.resolver_host {
            Some(host) => host.clone(),
            None => DEFAULT_RESOLVER_HOST.parse().expect("DEFAULT_RESOLVER_HOST is a valid Endpoint"),
        };
        let bare = args.handle.clone();
        let timeout = Duration::from_secs(args.net.timeout);
        let agent = ureq::AgentBuilder::new().timeout_connect(timeout).timeout_read(timeout).build();
        // --timeout now bounds each DNS try too (one resolver, built once, not
        // per call).
        let mut dns_options = Options::new();
        // Override c-ares' built-in default (5000 ms/try) only when the value
        // fits its u32 millisecond field; an absurd --timeout leaves that default
        // rather than a ~49-day (!!) ceiling.
        if let Ok(ms) = u32::try_from(timeout.as_millis())
            && ms > 0
        {
            dns_options.set_timeout(ms);
        }
        let dns = BlockingResolver::with_options(dns_options)
            .map_err(|e| CliError::Unavailable(format!("DNS resolver init failed: {e}").into()))?;
        let resolver = SystemResolver::new(agent, dns, resolver_host, plc_host);
        let did = resolver.resolve(&bare)?;
        resolver.verify(&bare, &did).or_else(|e| {
            Ok(Self {
                handle: bare,
                did,
                directory_verified: false,
                aka_primary: None,
                tampering_detected: false,
                verification_error: Some(e.to_string()),
            })
        })
    }
}
impl Outcome for HandleResolution {
    /// The human status block for stderr: the resolved line plus any verification
    /// caveats, styled inline. The bare DID is the machine [`datum`](Outcome::datum)
    /// on stdout, not part of this block.
    fn status(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let at = format!("@{}", self.handle.domain());
        let via = format!(" (via {})", self.did.method.label());
        _ = writeln!(s, "{} {}{}", paint(SUCCESS, "resolved"), paint(HIGHLIGHT, &at), paint(MUTED, &via));
        // The directory/divergence checks are only meaningful once the chain
        // verified. If it could not, surface the real reason and skip the rest.
        if let Some(error) = &self.verification_error {
            _ = writeln!(
                s,
                "{} DID reported by domain could not be verified via PLC directory",
                paint(DANGER, "warning:")
            );
            _ = writeln!(s, "  {}", paint(MUTED, error));
        } else {
            if let Some(primary) = self.aka_primary.as_ref()
                && primary != &self.handle
            {
                _ = writeln!(
                    s,
                    "{} @{} is not the primary handle for this DID",
                    paint(LABEL, "note:"),
                    self.handle.domain()
                );
                let alias = format!("  @{} is an alias of @{}", self.handle.domain(), primary.domain());
                _ = writeln!(s, "{}", paint(MUTED, &alias));
            }
            if !self.directory_verified {
                _ = writeln!(
                    s,
                    "{} the DID does not list @{} in its directory record (no back-reference)",
                    paint(WARNING, "warning:"),
                    self.handle.domain(),
                );
            }
            if self.tampering_detected {
                _ = writeln!(
                    s,
                    "{} directory state diverges from the canonical record; run `check`",
                    paint(WARNING, "warning:")
                );
            }
        }
        s
    }

    fn datum(&self) -> Option<String> {
        Some(self.did.did.to_string())
    }

    /// The DID is always resolved and printed; this code reports how far the
    /// bidirectional check got, per the committed exit-code table.
    ///
    /// `0` the handle and its directory record agree · `1` the reported state
    /// diverges from the canonical record (possible tampering) · `65` EX_DATAERR
    /// the DID does not claim the handle back, or its chain could not be verified.
    /// Verification failures are fail-closed; splitting transient fetch errors
    /// back out to `69` waits on the upcoming `CliError` pass (when
    /// [`verification_error`](Self::verification_error) carries the error kind
    /// rather than a string).
    fn exit_code(&self) -> ExitCode {
        // Checked first: an unverifiable chain makes the directory/divergence signals
        // below unreliable, so it wins regardless of their values.
        if self.verification_error.is_some() {
            // Provisional EX_DATAERR for every unverifiable chain; the CliError
            // pass splits transient fetch failures back out to 69 (EX_UNAVAILABLE).
            return ExitCode::from(65);
        }
        if self.tampering_detected {
            // Tampering: reported diverges from canonical.
            return ExitCode::from(1);
        }
        if !self.directory_verified {
            // EX_DATAERR: the directory back-reference is absent.
            return ExitCode::from(65);
        }
        ExitCode::SUCCESS
    }
}

/// Which resolution method produced the DID. The `handle` command tries them in
/// this order and records the first that answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Method {
    /// `_atproto.<handle>` DNS TXT record.
    Dns,
    /// `https://<handle>/.well-known/atproto-did`.
    WellKnown,
    /// XRPC `com.atproto.identity.resolveHandle` fallback.
    Xrpc,
}
impl Method {
    /// The method's name for terminal output (e.g. `"DNS TXT"`).
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Dns => "DNS TXT",
            Self::WellKnown => "well-known",
            Self::Xrpc => "XRPC resolveHandle",
        }
    }
}

/// A resolved `did:plc` paired with the [`Method`] that found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ResolvedDid {
    pub did: DidPlc,
    pub method: Method,
}

/// A syntactically valid ATProto handle (a domain name), held in bare normalised
/// form: no leading `@`, lowercased, no trailing dot. [`Display`] and [`Serialize`]
/// re-add the `@` to match the directory's `@handle` shape, so reach for
/// [`domain`](Self::domain) when you want the bare string. Construct via [`FromStr`];
/// [`validate`](Self::validate) defines the accepted syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BareHandle(String);
impl BareHandle {
    /// The bare domain form (no `@`, lowercased); the inverse of the `@`-prefixed
    /// [`Display`] output.
    pub(crate) fn domain(&self) -> &str {
        &self.0
    }

    /// Check `domain` against the subset of ATProto handle syntax atshield accepts:
    /// a domain of two or more LDH labels (ASCII letters, digits, hyphens), each
    /// label 1-63 bytes with no leading or trailing hyphen, total length 1-253 bytes,
    /// and a top-level label that starts with a letter (which rejects bare IPs
    /// and numeric TLDs). Returns [`CliError::Usage`] naming the first rule that
    /// fails.
    pub(crate) fn validate(domain: impl AsRef<str>) -> Result<(), CliError> {
        let reject = |msg: String| Err(CliError::Usage(format!("invalid handle: {msg}").into()));
        let domain = domain.as_ref();
        if domain.is_empty() || domain.len() > 253 {
            return reject(format!("handle length out of range: `{domain}`"));
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return reject(format!("handle must be a domain with at least two labels: `{domain}`"));
        }
        for label in &labels {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return reject(format!("invalid label length in `{domain}`"));
            }
            if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
                return reject(format!("label has a leading/trailing hyphen in `{domain}`"));
            }
            if !bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')) {
                return reject(format!("invalid characters in handle `{domain}`"));
            }
        }
        // The top-level label must start with a letter (rejects IPs and numeric TLDs).
        let tld_ok = labels.last().and_then(|t| t.as_bytes().first()).is_some_and(u8::is_ascii_lowercase);
        if !tld_ok {
            return reject(format!("top-level label must start with a letter: `{domain}`"));
        }
        Ok(())
    }
}
impl Serialize for BareHandle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // The wire form keeps the `@` prefix (the `Display` form), matching the
        // directory's `@handle` shape, whereas the str ref does not contain the
        // `@` prefix.
        #[allow(clippy::unnecessary_to_owned)]
        serializer.serialize_str(&self.to_string())
    }
}
impl Display for BareHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "@{}", self.0)
    }
}
impl FromStr for BareHandle {
    type Err = CliError;
    /// Strip an *optional* leading `@`, lowercase, strip a trailing dot, then validate
    /// the domain syntax. The stored value is the bare handle (no `@`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix('@').unwrap_or(s);
        let s = s.strip_suffix('.').unwrap_or(s).to_lowercase();
        Self::validate(&s)?;
        Ok(Self(s))
    }
}
impl AsRef<str> for BareHandle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The production [`HandleResolver`]: a blocking HTTP [`Agent`] plus the two
/// endpoints it needs, the PLC directory (`plc_host`) for audit chains and the
/// XRPC AppView (`resolver_host`) for the `resolveHandle` fallback.
pub(crate) struct SystemResolver {
    agent: Agent,
    dns: BlockingResolver,
    resolver_host: Endpoint,
    plc_host: Endpoint,
}
impl SystemResolver {
    pub(crate) fn new(agent: Agent, dns: BlockingResolver, resolver_host: Endpoint, plc_host: Endpoint) -> Self {
        Self { agent, dns, resolver_host, plc_host }
    }

    /// Resolve via the `_atproto.<handle>` DNS TXT record. `Ok(None)` means no
    /// authoritative answer (NXDOMAIN/NODATA/SERVFAIL, or no `did=` record), so
    /// the caller falls through to the next method; two distinct `did=` values
    /// are an ambiguity reported as [`CliError::Unavailable`].
    fn dns_txt(&self, bare: &BareHandle) -> Result<Option<DidPlc>, CliError> {
        let name = format!("_atproto.{}", bare.domain());
        // NXDOMAIN / NODATA / SERVFAIL -> no authoritative answer here, fall through.
        let Ok(results) = self.dns.query_txt(&name) else {
            return Ok(None);
        };
        // A short `did=` value always fits one TXT character-string, so scan each
        // record independently (no continuation-chunk reassembly needed).
        let mut dids = BTreeSet::new();
        results
            .into_iter()
            .filter_map(|record| {
                std::str::from_utf8(record.text()).ok().and_then(|text| text.trim().strip_prefix("did="))
            })
            .for_each(|did| {
                dids.insert(did.trim().to_owned());
            });

        match dids.len() {
            0 => Ok(None),
            1 => dids.into_iter().next().map(|did| Self::parse(&did)).transpose(),
            _ => {
                Err(CliError::Unavailable(format!("ambiguous: multiple distinct `did=` TXT records at {name}").into()))
            },
        }
    }

    /// Resolve via `https://<handle>/.well-known/atproto-did`. A transport error
    /// or a non-2xx response counts as "not here" (`Ok(None)`); the body read is
    /// capped at 512 bytes since a DID is tiny.
    fn well_known(&self, bare: &BareHandle) -> Result<Option<DidPlc>, CliError> {
        let url = format!("https://{}/.well-known/atproto-did", bare.domain());
        let Ok(resp) = self.agent.get(&url).call() else {
            return Ok(None);
        };
        // A DID is tiny; cap the read so a hostile endpoint can't stream megabytes.
        let mut body = String::new();
        resp.into_reader()
            .take(512)
            .read_to_string(&mut body)
            .map_err(|e| CliError::Unavailable(e.to_string().into()))?;
        let did = body.trim();
        (!did.is_empty()).then_some(did).map(Self::parse).transpose()
    }

    /// Resolve via the XRPC `com.atproto.identity.resolveHandle` call on the
    /// configured AppView, the last-resort fallback. A failed request is `Ok(None)`,
    /// as is a valid JSON response without a `did` field; only a malformed body
    /// is a [`CliError::Unavailable`].
    fn xrpc(&self, bare: &BareHandle) -> Result<Option<DidPlc>, CliError> {
        let url = format!("{}/xrpc/com.atproto.identity.resolveHandle", self.resolver_host);
        let Ok(resp) = self.agent.get(&url).query("handle", bare.domain()).call() else {
            return Ok(None);
        };
        let mut body = String::new();
        resp.into_reader()
            .take(MAX_BODY_BYTES)
            .read_to_string(&mut body)
            .map_err(|e| CliError::Unavailable(e.to_string().into()))?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| CliError::Unavailable(format!("malformed resolveHandle response: {e}").into()))?;
        value.get("did").and_then(serde_json::Value::as_str).map(Self::parse).transpose()
    }

    /// Parse a resolved DID string into a [`DidPlc`], translating a `did:web`
    /// result into the explicit [`CliError::Data`] (atshield v1 monitors `did:plc`
    /// only) and any other malformed value into [`CliError::ChainInvalid`].
    fn parse(did: &str) -> Result<DidPlc, CliError> {
        DidPlc::new(did).map_err(|e| match e {
            DidError::WrongMethod(_, got) if got.starts_with("did:web:") => CliError::Data(
                format!("did:web is not supported yet (atshield v1 monitors did:plc only); got `{got}`").into(),
            ),
            other => CliError::ChainInvalid(format!("resolved DID is not a valid did:plc: {other}").into()),
        })
    }
}

impl HandleResolver for SystemResolver {
    fn resolve(&self, bare: &BareHandle) -> Result<ResolvedDid, CliError> {
        if let Some(did) = self.dns_txt(bare)? {
            return Ok(ResolvedDid { did, method: Method::Dns });
        }
        if let Some(did) = self.well_known(bare)? {
            return Ok(ResolvedDid { did, method: Method::WellKnown });
        }
        if let Some(did) = self.xrpc(bare)? {
            return Ok(ResolvedDid { did, method: Method::Xrpc });
        }
        let msg = format!(
            "no DID for @{bare}: no _atproto TXT record, no /.well-known/atproto-did, and the XRPC fallback had no match"
        );
        Err(CliError::Unavailable(msg.into()))
    }

    fn verify(&self, bare: &BareHandle, resolution: &ResolvedDid) -> Result<HandleResolution, CliError> {
        // Fetch and cryptographically verify the whole chain, never trust `/data`.
        // Any failure propagates so `run` can record it on the result as `error`.
        let chain = fetch_audit_chain(&self.agent, &self.plc_host, &resolution.did)?;
        let resolver = ChainResolver::new(&chain);
        let (reported_state, _) = resolver.reported().map_err(|e| CliError::ChainInvalid(e.to_string().into()))?;
        let present = reported_state.also_known_as().iter().any(|handle| {
            handle.trim().strip_prefix("at://").is_some_and(|handle| handle.eq_ignore_ascii_case(bare.domain()))
        });
        let aka_primary = reported_state
            .also_known_as()
            .first()
            .and_then(|handle| handle.trim().strip_prefix("at://"))
            .map(BareHandle::from_str)
            .transpose()
            .ok()
            .flatten();
        let canonical = resolver.canonical().map_err(|e| CliError::ChainInvalid(e.to_string().into()));
        Ok(HandleResolution {
            handle: bare.clone(),
            did: resolution.clone(),
            directory_verified: present,
            aka_primary,
            tampering_detected: canonical.as_ref().is_ok_and(|(state, _)| state != &reported_state),
            verification_error: canonical.err().map(|e| e.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atshield_core::test::TEST_DID_PLC;

    fn resolution(tampering_detected: bool) -> HandleResolution {
        HandleResolution {
            handle: "zanbaldwin.com".parse().unwrap(),
            did: ResolvedDid {
                did: DidPlc::new(TEST_DID_PLC).unwrap(),
                method: Method::Dns,
            },
            directory_verified: true,
            aka_primary: None,
            tampering_detected,
            verification_error: None,
        }
    }

    /// The colour-stripped human status plus machine datum, concatenated (the
    /// plain text a non-TTY sink would emit, for substring assertions).
    fn rendered(resolution: &HandleResolution) -> String {
        let status = anstream::adapter::strip_str(&resolution.status()).to_string();
        let datum = resolution.datum().map_or_else(String::new, |d| anstream::adapter::strip_str(&d).to_string());
        format!("{status}{datum}")
    }

    #[test]
    fn parse_normalises_and_optional_at() {
        // The `@` is optional now (the old crate required it); a trailing dot and
        // mixed case are both folded away.
        assert_eq!("alice.bsky.social".parse::<BareHandle>().unwrap().domain(), "alice.bsky.social");
        assert_eq!("@Alice.BSKY.social.".parse::<BareHandle>().unwrap().domain(), "alice.bsky.social");
        assert_eq!("@zanbaldwin.com".parse::<BareHandle>().unwrap().domain(), "zanbaldwin.com");
    }

    #[test]
    fn parse_rejects_junk_and_ips() {
        let rejects = |s: &str| s.parse::<BareHandle>();
        assert!(matches!(rejects("@nodot"), Err(CliError::Usage(_))));
        assert!(matches!(rejects("nodot"), Err(CliError::Usage(_))));
        assert!(matches!(rejects("1.2.3.4"), Err(CliError::Usage(_))));
        assert!(matches!(rejects("@1.2.3.4"), Err(CliError::Usage(_))));
        assert!(matches!(rejects("@-bad.example"), Err(CliError::Usage(_))));
        assert!(matches!(rejects("a_b.example"), Err(CliError::Usage(_))));
    }

    #[test]
    fn method_serialises_snake_case() {
        assert_eq!(serde_json::to_string(&Method::Dns).unwrap(), "\"dns\"");
        assert_eq!(serde_json::to_string(&Method::WellKnown).unwrap(), "\"well_known\"");
        assert_eq!(serde_json::to_string(&Method::Xrpc).unwrap(), "\"xrpc\"");
        assert!(!Method::Dns.label().is_empty());
    }

    #[test]
    fn display_and_serialize_prefix_at() {
        let handle: BareHandle = "alice.bsky.social".parse().unwrap();
        assert_eq!(handle.to_string(), "@alice.bsky.social");
        assert_eq!(serde_json::to_string(&handle).unwrap(), "\"@alice.bsky.social\"");
    }

    #[test]
    fn resolution_serialises_and_exits_success() {
        let resolved = resolution(false);
        assert!(matches!(resolved.exit_code(), ExitCode::SUCCESS));

        let value = serde_json::to_value(&resolved).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "handle": "@zanbaldwin.com",
                "did": { "did": TEST_DID_PLC, "method": "dns" },
                "directory_verified": true,
                "aka_primary": null,
                "tampering_detected": false,
            })
        );

        // The machine datum carries the bare DID for piping into `--did`.
        assert_eq!(resolved.datum().as_deref(), Some(TEST_DID_PLC));
        assert!(rendered(&resolved).contains(TEST_DID_PLC));
    }

    #[test]
    fn tampering_flag_drives_divergence_warning() {
        // `tampering_detected == true` means reported diverges from canonical.
        assert!(rendered(&resolution(true)).contains("diverges"));
        assert!(!rendered(&resolution(false)).contains("diverges"));
    }

    #[test]
    fn unverified_surfaces_error_not_divergence() {
        let handle = "zanbaldwin.com".parse().unwrap();
        let did = ResolvedDid {
            did: DidPlc::new(TEST_DID_PLC).unwrap(),
            method: Method::Dns,
        };
        let text = rendered(&HandleResolution {
            handle,
            did,
            directory_verified: false,
            aka_primary: None,
            tampering_detected: false,
            verification_error: Some("boom".to_owned()),
        });
        assert!(text.contains("could not be verified"));
        assert!(text.contains("boom"));
        assert!(!text.contains("diverges"));
    }

    #[test]
    fn missing_backreference_warns() {
        let text = rendered(&HandleResolution {
            directory_verified: false,
            ..resolution(false)
        });
        assert!(text.contains("no back-reference"));
        assert!(!text.contains("diverges"));
    }
}
