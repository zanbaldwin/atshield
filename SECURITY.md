# Security Policy
**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.** Use the
private channel described below.

## Supported Versions
Only the latest release of `zanbaldwin/atshield` is supported (the project is currently pre-release). If you are on an
older version, the fix for any reported issue will be to upgrade to the latest one.

The project also pins a Rust toolchain to a specific version for consistent compilation. Since minor versions of the
Rust language become end-of-life as soon as the next minor version is released (every ~6 weeks), this project will bump
the MSRV _as and when I remember_.

**tl;dr:** I am one person, and I have ADHD. Sometimes I need reminding.

## Reporting a Vulnerability
Please report security vulnerabilities **privately** using GitHub's private vulnerability reporting: go to the Security
tab and click [Report a vulnerability](https://github.com/zanbaldwin/atshield/security/advisories/new). If you are
unable to use GitHub for this, email [**`hello+reporting@zanbaldwin.com`**](mailto:hello+reporting@zanbaldwin.com)
instead.

To help triage and resolve the report quickly, please include as much of the following as you can:

- the type of issue, e.g. _security_ (verification bypass, signature or CID-integrity flaw, acceptance of an
  unauthorised key), _utility_ (handle-resolution spoofing), _correctness_ (panic or memory blow-up, private-key
  material exposure), etc;
- the full path of the source file(s) involved;
- the affected tag, branch, or commit hash (or a direct URL);
- any special configuration required to reproduce the issue;
- step-by-step instructions to reproduce it;
- proof-of-concept or exploit code, if you have it; and
- the impact — including how an attacker might exploit the issue.

## What to Expect
This is a volunteer-maintained open-source project. With that in mind:

- I will acknowledge your report as soon as I read it (email notifications are turned on for reporting via GitHub and
  filtered to never be sent to spam).
- A confirmed issue is fixed and a new release is published **before** any public advisory goes out (via GitHub Security
  Advisories, plus a RUSTSEC advisory once the crates are published to crates.io).
- With your permission, you will be credited in the advisory.
- There is no bug bounty or monetary reward; I will not agree to fixed-date embargoes, multi-vendor coordination, or
  NDAs.

## Scope
**In scope:** defects with a security impact in `atshield`'s own code (both the `atshield-core` library and the
`atshield-cli` binary). For a detection tool, **false negatives are security vulnerabilities**: if `atshield` reports an
identity as clean or legitimate when its audit chain has been tampered with (or a fail-closed error path turns out to
fail open) please report it privately.

False positives (a clean identity flagged as tampered) are ordinary reliability bugs; feel free to open a public issue
for those.

**Out of scope:**

- vulnerabilities in your application's or scripts' _use_ of `atshield`;
- flaws in the PLC/ATProto protocol design, or in the `plc.directory` service itself;
- the documented backdating limitation (the recovery window relies on `createdAt` timestamps asserted by the directory;
  see "Limits worth knowing" in the README); and
- consequences of trusting a compromised or wrong key via `--trust-key`.

Issues in third-party dependencies are also out of scope (please report those to their respective maintainers), with one
caveat: c-ares is vendored and statically linked into release binaries, so a heads-up about an upstream c-ares
vulnerability is welcome. The fix belongs upstream, but `atshield` needs to rebuild a release.

## A Note on AI-Assisted Reports
In the age of AI, any security exploit found by AI should be assumed to already be known to the public. AI-assisted
reports hold the same weight as those reported by humans, but _accountability always lands with the human controlling
the AI_. Use of AIs does not disqualify reports; unnecessary and abusive reporting does.

> **tl;dr:** AI-assisted reports welcome, must be human-verified.
