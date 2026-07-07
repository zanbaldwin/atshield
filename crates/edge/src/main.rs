// SPDX-License-Identifier: LicenseRef-Proprietary
//! Pingora runtime of the Fakesky sandbox edge.
//!
//! A thin shell mapping the transport-free rules in this crate's library onto
//! pingora's proxy phases:
//! - `request_filter`: allow-list routing, rate limiting and a `Content-Length`
//!   precheck.
//! - `request_body_filter`: genesis inspection (reading it in `request_filter`
//!   consumes it and breaks upstream forwarding, pingora issue #349).
//! - `upstream_peer`: backend selection.
//!
//! One public domain, path-routed to two optional backends (min one required, a
//! route whose upstream is disabled gets a 404):
//! - request matching the directory allow-list goes to `--plc-upstream`,
//! - everything else goes to `--app-upstream`.
//!
//! TLS termination is opt-in via `--tls-cert`/`--tls-key` (PEM; external renewal
//! as Pingora+RusTLS has no ACME). Plain TCP by default.
//!
//! Shutdown:
//! - `SIGTERM` drains gracefully (`--shutdown-grace-seconds` /
//!   `--shutdown-timeout-seconds` for in-flight requests),
//! - `SIGINT` (Fly.io default signal) exits fast,
//! - `SIGQUIT` hands off to a zero-downtime upgrade.

use async_trait::async_trait;
use clap::{ArgGroup, Parser};
use fakesky_edge::{BodyVerdict, MAX_BODY_BYTES, PlcRoute, body_verdict, route};
use http::uri::Authority;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::server::configuration::ServerConf;
use pingora::{Error, ErrorType};
use pingora_limits::rate::Rate;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tracing::instrument;
use tracing_subscriber::EnvFilter;

#[derive(Default)]
enum Target {
    Plc,
    #[default]
    App,
}
/// A backend the edge forwards to. One type serves both the PLC directory and
/// the Fakesky app; they differ only in which requests are routed to them, not
/// in how they are proxied.
#[derive(Clone)]
struct Upstream {
    /// Bare `host:port`, re-resolved on every request (container DNS); never
    /// carries a scheme (always HTTP).
    forward: Authority,
}
impl Upstream {
    /// A plaintext peer to this backend; passing the `host:port` string (rather
    /// than a resolved address). Defers DNS to connect time.
    fn peer(&self) -> Box<HttpPeer> {
        Box::new(HttpPeer::new(self.forward.as_str(), false, String::new()))
    }
}
impl FromStr for Upstream {
    type Err = String;
    /// Accepts bare `host:port`; refuses any other scheme, since the upstream
    /// leg is always plaintext on the private network. [`Authority`] validates
    /// the host/port syntax, we check for Basic auth or portless (would
    /// fail per-request inside `upstream_peer`). Refuse at startup instead.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let forward = s.parse::<Authority>().map_err(|e| e.to_string())?;
        if forward.as_str().contains('@') {
            return Err(String::from("must not carry userinfo"));
        }
        if forward.port_u16().is_none_or(|port| port == 0) {
            return Err(String::from("must include a port (1-65535)"));
        }
        Ok(Self { forward })
    }
}

/// The stateless abuse boundary in front of a sandbox PLC directory: exposes
/// only the reads a recovery drill needs plus a genesis-filtered submit,
/// rate-limits by client IP, and hands everything else to the Fakesky control
/// plane.
#[derive(Parser)]
#[command(version, about)]
// A proxy needs at least one backend: clap refuses to start unless one of the
// two upstream flags (or their env fallbacks) is present.
#[command(group(
    ArgGroup::new("targets").required(true).multiple(true).args(["plc_upstream", "app_upstream"])
))]
struct Args {
    /// Address (IP:port, not a hostname) to listen on.
    #[arg(
        short = 'l',
        long,
        value_name = "IP:PORT",
        env = "EDGE_LISTEN",
        default_value = "0.0.0.0:2580"
    )]
    listen: SocketAddr,
    /// PLC directory upstream (`host:port` defined as `plc:2582` in the default
    /// Docker stack); receives only the allow-listed directory routes. Omit to
    /// disable (return 404 for allowed GET and guarded POST routes).
    #[arg(short = 'p', long, value_name = "HOST:PORT", env = "EDGE_PLC_UPSTREAM")]
    plc_upstream: Option<Upstream>,
    /// Fakesky control-plane upstream (`host:port` defined as `app:2584` in the
    /// default Docker stack); receives every non-directory request. Omit to
    /// disable (return 404 for every non-PLC route).
    #[arg(short = 'a', long, value_name = "HOST:PORT", env = "EDGE_APP_UPSTREAM")]
    app_upstream: Option<Upstream>,
    /// Per-client-IP request ceiling per minute (directory routes only; the app
    /// self-limits).
    #[arg(
        short = 'r',
        long,
        value_name = "N",
        env = "EDGE_RATE_LIMIT_PER_MIN",
        default_value_t = 30,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    rate_limit: u32,
    /// Rooted path the edge answers 200 on itself, before any routing (never
    /// proxied).
    #[arg(
        short = 'H',
        long,
        value_name = "PATH",
        env = "EDGE_HEALTH_PATH",
        default_value = "/healthz",
        value_parser = util::parse_health_path
    )]
    health_path: String,
    /// PEM certificate chain for TLS termination. Omit both TLS flags for a
    /// plain-TCP listener (dev, or behind Fly's edge).
    #[arg(short = 'c', long, value_name = "FILE", env = "EDGE_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<String>,
    /// PEM private key matching --tls-cert
    #[arg(short = 'k', long, value_name = "FILE", env = "EDGE_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<String>,
    /// On `SIGTERM`, seconds to keep serving before draining (lets a fronting
    /// load balancer deregister first). An unconditional wait, so keep it small;
    /// 0 drains immediately.
    #[arg(
        short = 'g',
        long,
        value_name = "SECS",
        env = "EDGE_SHUTDOWN_GRACE",
        default_value_t = 0
    )]
    shutdown_grace_seconds: u64,
    /// On `SIGTERM`, max seconds to let in-flight requests finish before the
    /// process exits.
    #[arg(
        short = 't',
        long,
        value_name = "SECS",
        env = "EDGE_SHUTDOWN_TIMEOUT",
        default_value_t = 5
    )]
    shutdown_timeout_seconds: u64,
}

/// Per-request state, created fresh for every request and filled in by
/// `request_filter`.
#[derive(Default)]
struct Ctx {
    /// Route to the app backend instead of the directory.
    target: Target,
    /// This is a `POST /:did`: buffer the body and judge it before forwarding.
    guarded_post: bool,
    /// The buffered submission body; only populated for a guarded post, and
    /// capped at [`MAX_BODY_BYTES`] (checked after each chunk).
    body: Vec<u8>,
}

/// The proxy service: the two optional backends plus the shared rate estimator.
struct Edge {
    /// Directory backend; the allow-listed routes go here. `None` means those
    /// routes 404.
    plc: Option<Upstream>,
    /// Control-plane backend; every other request goes here. `None` means those
    /// requests 404.
    app: Option<Upstream>,
    /// Per-IP ceiling over the sliding window (`isize` because that is what
    /// `Rate::observe` returns; always positive, from a `u32` flag).
    limit_per_minute: isize,
    /// The edge's own health endpoint, answered before routing.
    health_path: String,
    /// Sliding-window rate estimator keyed by client IP (directory routes only).
    limiter: Rate,
}
#[async_trait]
impl ProxyHttp for Edge {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx::default()
    }

    /// Everything decidable from the request head alone: the edge's own health
    /// answer, path routing, the 404 for a disabled backend, per-IP rate limiting,
    /// and a fast 413 when a guarded post declares an oversized `Content-Length`.
    ///
    /// Returning `Ok(true)` tells pingora a response has already been written
    /// and proxying stops there; `Ok(false)` continues towards the upstream chosen
    /// in [`upstream_peer`](Self::upstream_peer).
    #[instrument(skip_all, fields(method = %session.req_header().method, path = %session.req_header().uri.path()))]
    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let head = session.req_header();
        if head.method == http::Method::GET && head.uri.path() == self.health_path {
            util::respond(session, 200).await?;
            return Ok(true);
        }

        let decision = route(head.method.as_str(), head.uri.path());
        // Not a directory route: the control plane's traffic, forwarded untouched
        // (it owns its own auth and rate limits). The directory upstream therefore
        // only ever sees allow-listed paths.
        if decision == PlcRoute::AppPassthru {
            // If the app upstream is disabled, stop proxy propagation/bubbling
            // to avoid Pingora spamming loads of "ERROR fail to proxy" logs.
            if self.app.is_none() {
                util::respond(session, 404).await?;
                return Ok(true);
            }
            ctx.target = Target::App;
            return Ok(false);
        }

        // Not an app route, definitely for proxy at this point.
        // If the plc upstream is disabled, stop proxy propagation/bubbling
        // to avoid Pingora spamming loads of "ERROR fail to proxy" logs.
        ctx.target = Target::Plc;
        if self.plc.is_none() {
            util::respond(session, 404).await?;
            return Ok(true);
        }
        let bucket = util::client_key(session);
        if self.limiter.observe(&bucket, 1) > self.limit_per_minute {
            tracing::debug!(client = %bucket, "rate limit exceeded");
            util::respond(session, 429).await?;
            return Ok(true);
        }
        if decision == PlcRoute::GuardedPost {
            ctx.guarded_post = true;
            // Cheap refusal for honestly-declared oversized bodies; chunked or
            // lying requests are still capped as they buffer in
            // [`request_body_filter`].
            let declared = session
                .req_header()
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok());
            if declared.is_some_and(|len| len > MAX_BODY_BYTES) {
                util::respond(session, 413).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Buffers a guarded submission chunk by chunk and judges the complete body
    /// at end of stream. Working at this layer is framing-agnostic, so genesis
    /// rejection behaves identically over HTTP/1.1 and h2.
    ///
    /// Refusals are `Err(HTTPStatus(4xx))`, which pingora renders as that status;
    /// pingora also logs each one as a `pingora_proxy` ERROR "Fail to proxy" line.
    /// That line is benign (it is how a short-circuiting filter is reported);
    /// our own `info` event is the real signal.
    #[instrument(skip_all)]
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if !ctx.guarded_post {
            return Ok(());
        }
        if let Some(chunk) = body {
            ctx.body.extend_from_slice(chunk);
        }
        if ctx.body.len() > MAX_BODY_BYTES {
            return Err(Error::explain(ErrorType::HTTPStatus(413), "submission body exceeds the edge cap"));
        }
        if end_of_stream && body_verdict(&ctx.body) == BodyVerdict::RejectGenesis {
            // Security-relevant and rare: only the control plane's side door may mint identities.
            tracing::info!(client = %util::client_key(session), "rejected genesis submission");
            return Err(Error::explain(
                ErrorType::HTTPStatus(403),
                "genesis operations are not accepted at the public edge",
            ));
        }
        Ok(())
    }

    /// Connects the request to the backend picked in
    /// [`request_filter`](Self::request_filter).
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        // Resolved per request so a recreated container (new address, same DNS
        // name) never requires an edge restart.
        // Maybe cache this? Or no?
        let upstream = match ctx.target {
            Target::App => self.app.as_ref(),
            Target::Plc => self.plc.as_ref(),
        };
        match upstream {
            Some(upstream) => Ok(upstream.peer()),
            None => Err(Error::explain(ErrorType::HTTPStatus(404), "the routed upstream is disabled")),
        }
    }
}

fn main() {
    let args = Args::parse();
    // Log to stderr; default to `info` so pingora's own lifecycle/shutdown/error
    // lines surface without needing RUST_LOG.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("error,fakesky_edge=info,pingora=info"));
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(filter).with_target(true).init();
    tracing::info!(
        listen = %args.listen,
        scheme = if args.tls_cert.is_some() { "https" } else { "http" },
        plc_upstream = args.plc_upstream.as_ref().map_or("disabled", |u| u.forward.as_str()),
        app_upstream = args.app_upstream.as_ref().map_or("disabled", |u| u.forward.as_str()),
        rate_limit_per_min = args.rate_limit,
        "fakesky-edge listening",
    );
    // Graceful shutdown. Pingora's run_forever() already installs the signal
    // handlers.
    // - `SIGTERM` drains gracefully (what `docker stop` or a rolling deploy sends),
    // - `SIGINT` exits fast,
    // - `SIGQUIT` is a zero-downtime upgrade.
    // An unset grace period falls back to EXIT_TIMEOUT=300s (unconditional sleep),
    // so SIGTERM would hang for 5 minutes and the orchestrator would SIGKILL
    // mid-shutdown. Set both to small, bounded values.
    #[allow(clippy::field_reassign_with_default)]
    let conf = {
        let mut conf = ServerConf::default();
        conf.grace_period_seconds = Some(args.shutdown_grace_seconds);
        conf.graceful_shutdown_timeout_seconds = Some(args.shutdown_timeout_seconds);
        conf
    };
    let mut server = Server::new_with_opt_and_conf(None::<Opt>, conf);
    server.bootstrap();
    let mut service = http_proxy_service(
        &server.configuration,
        Edge {
            plc: args.plc_upstream,
            app: args.app_upstream,
            limit_per_minute: isize::try_from(args.rate_limit).expect("u32 fits isize"),
            health_path: args.health_path,
            limiter: Rate::new(Duration::from_mins(1)),
        },
    );
    let listen = args.listen.to_string();
    match args.tls_cert.zip(args.tls_key) {
        Some((cert, key)) => {
            // TLS termination advertises h2 + http/1.1 in ALPN, so a modern client
            // negotiates `HTTP/2` and older ones fall back to `HTTP/1.1`.
            // The genesis body filter is framing-agnostic (it buffers the decoded
            // body either way, verified over both protocols).
            let mut tls = TlsSettings::intermediate(&cert, &key)
                // Panic: fuck it, no TLS no safety. Yolo.
                .expect("failed to load the TLS certificate/key");
            tls.enable_h2();
            service.add_tls_with_settings(&listen, None, tls);
        },
        None => service.add_tcp(&listen),
    }
    server.add_service(service);
    server.run_forever();
}

mod util {
    use fakesky_edge::{PlcRoute, route};
    use pingora::Result;
    use pingora::http::ResponseHeader;
    use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
    use pingora::proxy::Session;

    /// The rate-limit key: the client IP. Non-inet transports collapse onto one
    /// shared "unknown" bucket, which is moot while the edge only listens on TCP.
    pub(super) fn client_key(session: &Session) -> String {
        match session.client_addr() {
            Some(PingoraSocketAddr::Inet(addr)) => addr.ip().to_string(),
            _ => String::from("unknown"),
        }
    }

    /// Answers directly from the edge with a bare status code and no body (health
    /// and refusals).
    pub(super) async fn respond(session: &mut Session, code: u16) -> Result<()> {
        let header = ResponseHeader::build(code, None)?;
        session.write_response_header(Box::new(header), true).await
    }

    /// A health path must be rooted and must not shadow the proxied directory
    /// surface: it is answered before routing, so a directory-shaped path (say
    /// `/did:plc:…/log`) would silently hide a real PLC read behind a bare 200.
    pub(super) fn parse_health_path(value: &str) -> Result<String, String> {
        if !value.starts_with('/') || value.len() < 2 {
            return Err(String::from("must be a rooted path like /healthz"));
        }
        if route("GET", value) != PlcRoute::AppPassthru {
            return Err(String::from("must not shadow the proxied directory surface"));
        }
        Ok(value.to_owned())
    }
}
