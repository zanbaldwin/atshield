# 🛡️ ATShield
`atshield` is a command-line tool that detects tampering with an ATProto identity: the `did:plc` record that Bluesky,
and every other service in the Atmosphere, derives your account from. It fetches the public audit log for an identity,
re-verifies the entire cryptographic chain from scratch, and tells you (with an exit code you can put in cron) whether
anything changed that you didn't sign yourself.

- It trusts nothing transmitted over the network: every operation's CID is recomputed, every signature is re-verified,
  and the DID itself is re-derived from the genesis operation's bytes rather than read off the response.
- It cross-examines the directory by resolving the identity's current state two independent ways: what the directory
  reports, and what rotation-key authority plus the 72-hour recovery window actually permit. If the two disagree, the
  directory is serving a history the protocol doesn't support.
- A baseline records your identity's known-good state plus the keys you control; `check` then classifies every change as
  legitimate (signed by you) or tampering, with severity, because "I rotated my keys" and "someone else rotated my keys"
  produce identical-looking records.
- Handles are verified in both directions: an `@handle` resolves to its DID (DNS `TXT`, then well-known, then XRPC
  fallback), and the DID has to point back.
- It reports back with a non-zero exit code anything that it can't cryptographically prove (with some exceptions; see
  **Limits worth knowing**).

## Why
I assumed Bluesky was, structurally, like Twitter or Facebook or any of the other major centralized social media
platforms: if the company ever went rogue, the worst case was losing my Bluesky account, and life blissfully would carry
on. But then I got sucked into a rabbit hole of [ATProto specs](https://atproto.com/guides/identity) instead of enjoying
my vacation days like a normal person.

Your ATProto identity is not your Bluesky account. It's a DID (a `did:plc` record listing your handle, your data server,
and your signing keys), and it's the same identity you carry into every other Atmosphere service; sign in to Tangled and
you're signing in with it. Control of that record belongs to whoever holds its rotation keys
([the spec](https://web.plc.directory/spec/v0.1/did-plc) allows one to five, in priority order), and on a standard
account those keys are held by the operator you set up your account with. So
"rogue provider" doesn't mean losing one social account it means whoever controls the provider controls your identity
everywhere it's used.

The protocol does give you an escape hatch: a higher-priority rotation key can rewrite an unauthorised operation, but
only within a 72-hour window. That's a genuinely good recovery mechanism with one obvious catch: people who have a life
do not read their own PLC audit logs for fun. No one's gonna _notice_ if you don't get _notified_.

`atshield` reads it for you, cryptographically, and categorizes changes to your identity. Schedule it into a cron job,
configure how you want to be alerted, and you can go back to not thinking about your ATProto identity just like you did
before you learnt about it.

> Shout-out to the following articles that ~~sucked me in~~ helped me understand:
>
> - [Who Actually Owns Your ATProto Identity? Hint: It's Probably Not You](https://kevinak.se/blog/who-actually-owns-your-atproto-identity-hint-its-probably-not-you),
>   by [Kevin Åberg Kultalahti](https://kevinak.se/).
> - [Registering Identity Recovery Keys via PDS, using goat](https://whtwnd.com/bnewbold.net/3lj7jmt2ct72r), by
>   [Bryan Newbold](https://bnewbold.net/).
> - [Adversarial ATProto PDS Migration](https://www.da.vidbuchanan.co.uk/blog/adversarial-pds-migration.html), by
>   [David Buchanan](https://www.da.vidbuchanan.co.uk/).
> - [I Was Right About ATProto Key Management](https://notes.nora.codes/atproto-again/) by
>   [Nora Tindall](https://nora.codes/), and its
>   [Lobste.rs comment thread](https://lobste.rs/s/5qylwg/i_was_right_about_atproto_key_management).

## What a check looks like

```shell
$ atshield check "did:plc:2qrnyk7dr5pkqe4ogsb7omzd"
clean: no changes since baseline for did:plc:2qrnyk7dr5pkqe4ogsb7omzd
```

And on a bad day:

```shell
$ atshield check "did:plc:2qrnyk7dr5pkqe4ogsb7omzd"
TAMPER: critical divergence for did:plc:2qrnyk7dr5pkqe4ogsb7omzd
  [critical] + rotation key did:key:zQ3shP… (position 0), signed by did:key:zQ3shh… (unauthorised)
  [warning] ~ signing key did:key:zQ3shq… -> did:key:zDnaXX…, signed by did:key:zQ3shh… (unauthorised)
```

Exit code `0` on the first, `1` on the second. The human detail goes to stderr and a one-word verdict goes to stdout, so
scripts and people can read the same run.

## Philosophy
> Anything `atshield` cannot cryptographicly prove is an alert.

An audit log that fails verification, a baseline that has fallen off the reported history, an operation the tool cannot
read: each exits non-zero with a plain-language explanation, because from the outside, each is also what a real attack
looks like.

The tool is inert everywhere else. It holds no private credentials and submits no operations; it never writes to the
remote PLC directory.

> The tool also provides the ability to sign and verify message signatures, wiping the private key material from memory
> before the command finishes. I added this functionality because I wanted it for myself; it is out-of-scope for the
> original _detection_ functionality. You never need to provide a private key to use the tool yourself.

## Quick Start

1. Build it via `cargo build --release` (pre-built binaries will arrive with the first tagged release)
2. Find your DID: `atshield handle @your-handle.com`
3. Record a baseline, trusting any rotation keys _you_ hold (the same multikey format
   [Goat](https://github.com/bluesky-social/goat "Go AT protocol CLI tool") produces with `goat key generate`)
4. Put `atshield check` somewhere that runs on a schedule (see **Automation**)
5. That's it. From now on, silence means nothing changed that you didn't authorize

```shell
$ atshield handle "zanbaldwin.com"
resolved @zanbaldwin.com (via DNS TXT)
did:plc:2qrnyk7dr5pkqe4ogsb7omzd

$ atshield baseline \
    record "did:plc:2qrnyk7dr5pkqe4ogsb7omzd" \
    --trust-key "did:key:zDnaeYhzavkAFRGtQKJ7RC4Rb627RyhNWtthbmrmTXc2SsY6V"
baseline: recorded baseline for did:plc:2qrnyk7dr5pkqe4ogsb7omzd
head: head operation is CID bafyreieu22h63hwr6m5r5tjoxwsvj2qbppurd4j4pzjrsfaot224jshpum
keys: 1 trusted key
/home/username/.config/atshield/baseline-2qrnyk7dr5pkqe4ogsb7omzd.json

# Run the following command on a schedule (cron, systemd timer, etc.)
$ atshield check "did:plc:2qrnyk7dr5pkqe4ogsb7omzd"
clean: no changes since baseline for did:plc:2qrnyk7dr5pkqe4ogsb7omzd
```

<!-- rumdl-disable-next-line MD025 -->
# The Technical Stuff

## Installation
Build from source:

```shell
cargo build --release
```

The `cargo deploy` alias builds a fully static `x86_64-unknown-linux-musl` binary (size-optimised, fat LTO, stripped)
that runs on any Linux box. You can run the whole thing in a container:

<details>
<summary>Static build via Podman/Docker (click to expand)</summary>

```shell
$ podman run --rm \
    --volume "$(pwd):/build:z,ro" \
    --volume 'atshield-cargo:/usr/local/cargo/registry:rw' \
    --volume 'atshield-target:/build/target:rw' \
    --env 'CARGO_TARGET_DIR=/build/target' \
    --workdir '/build' \
    docker.io/library/rust:1-slim \
    bash -c '\
        apt-get update \
        && apt-get install -y --no-install-recommends cmake make musl-tools \
        && rustup target add x86_64-unknown-linux-musl \
        && cargo deploy'
```

</details>

## Commands

| Command                            | What it does                                                                          |
|------------------------------------|---------------------------------------------------------------------------------------|
| `handle <HANDLE>`                  | Resolve `@handle` to its `did:plc`, verified in both directions                       |
| `baseline record <DID>`            | Capture identity's current verified state as baseline to check against                |
| `baseline update <DID>`            | Refresh baseline after purposeful change (dry-run by default; `--force` writes)       |
| `baseline trust-key <DID> <KEY>`   | Mark `did:key` as yours, so its changes classify as legitimate                        |
| `baseline untrust-key <DID> <KEY>` | The reverse, for a key that's retired or compromised                                  |
| `check <DID>`                      | The verdict: `clean`, `legitimate`, or `tamper`; non-zero exit on anything unprovable |

Additional commands for offline proof-of-possession, which is out-of-scope for the main tamper-detection functionality:

| Command                     | What it does                                                                      |
|-----------------------------|-----------------------------------------------------------------------------------|
| `challenge new/sign/verify` | Offline proof-of-possession: mint token, sign with rotation key, verify signature |

Private keys are read from the `--key-file` flag or `ATSHIELD_KEY_FILE` environment variable.

## Automation
`check` is built to live in cron. Everything a scheduled run needs has an `ATSHIELD_*` environment variable
(`ATSHIELD_DID`, `ATSHIELD_BASELINE`, `ATSHIELD_PLC_HOST`, `ATSHIELD_ALERT_CMD`, …), `--json` swaps the output for a
single machine-readable object, and `--alert-cmd` pipes the full alert JSON into any shell command's stdin when
something diverges:

```shell
ATSHIELD_DID='did:plc:2qrnyk7dr5pkqe4ogsb7omzd' atshield check --quiet \
    --alert-cmd 'curl -s -X POST -d @- https://ntfy.sh/my-identity'
```

Exit codes are chosen so that a cron job can tell "the network hiccuped" from "someone is rewriting your
identity":

| Exit                   | Meaning                                                                          |
|------------------------|----------------------------------------------------------------------------------|
| `0`                    | Clean, or every change was signed by a key you trust                             |
| `1`                    | Tampering, or a fail-closed audit error (treat it as tampering)                  |
| `2`                    | Argument errors                                                                  |
| `64`, `65`, `70`, `74` | BSD `sysexits`: usage, bad data, internal error, I/O                             |
| `69`                   | Network/resolver unavailable. Transient, so retry; **not** evidence of tampering |

## Under the bonnet
The workspace is split in two: `atshield-core` is a stateless, transport-free library of `did:plc` primitives
(zero network or I/O), and the `atshield-cli` owns everything that touches the world: network/filesystem/terminal. Both
crates build under `#![forbid(unsafe_code)]` and (mostly) `clippy::pedantic`.

- The network is never trusted. The audit-log entry's `did` field isn't even deserialised; the identity is always
  re-derived from the genesis operation's bytes (base32 SHA-256 of its canonical DAG-CBOR, truncated to 24 characters,
  per the spec), so the identifier commits to the operation that created it. Every later operation's signature is
  checked against the rotation keys of the operation before it.
- Operations are type-state (`Unsigned` → `Signed` → `Checked`): a `Checked` operation can only be produced by an actual
  signature verification, and the state markers are sealed, so one can't be forged from untrusted JSON. Signature
  validity and rotation-key authority are separate layers on top; a valid signature isn't necessarily an authorised one.
- Resolution runs twice: `reported` follows the directory's nullification flags; `canonical` recomputes the winner of
  every fork from rotation-key priority and the 72-hour window, ignoring the flags entirely. Divergence between the two
  is a signal the PLC directory itself is tampering.
- Rotation-key _order_ is diffed too, not just membership: quietly demoting a key you control to a lower priority is
  itself an attack, because fork election respects priority.
- ECDSA verification is strict low-S only, matching the directory. Includes functionality to canonicalise High-S
  signatures produced by OpenSSL, but not used by default.
- The cryptography dependencies are exact-pinned (`=`); private-key material is zeroised on drop; baselines are
  atomically written.

## Limits worth knowing

- The 72-hour-window check reads `createdAt` timestamps asserted by the directory itself. Timestamps are **not** part
  of the cryptographic chain, so a directory that _backdates_ a hostile operation can defeat that check; catching it
  requires an independent observation timeline, which is what independent PLC mirrors currently provide.
- Classification is only as good as your trusted-key list. With no `--trust-key` at all, every change classifies as
  tampering (intentional: a change nobody claims must be alerted).
- `did:plc` only for now; `handle` will tell you: "did:web is not supported yet (atshield v1 monitors did:plc
  only)".
- This is pre-release software. Interfaces and functionality may shift.

## Roadmap

- [x] Cryptographic audit-chain verification (forked histories, tombstones, the legacy `create` format, official interop
      vectors)
- [x] Baseline monitoring with severity-classified verdicts (`record`, `check`, `update`, `trust-key`)
- [x] Bidirectional handle resolution
- [x] Offline proof-of-possession challenges
- [ ] Long-lived monitoring with independent observation timeline (long-lived daemon version of `check`+cron)
- [ ] Fake directory for practicing attack scenarios and recovery runbooks
- [ ] Pre-built binaries and a [crates.io](https://crates.io/) release

## Contributing
`atshield` is a young, solo-maintained project. The following are genuinely welcome:

- Bug reports and/or fixes,
- Documentation improvements, and
- War stories about identity migrations gone wrong (they make for fantasic test fixtures)

Reviews can take a little while, see [CONTRIBUTING](CONTRIBUTING.md) for more details.

<!-- rumdl-disable-next-line MD025 -->
# Authors

- [Zan Baldwin](https://zanbaldwin.com)

> If you make a contribution (submit a pull request), don't forget to add your name here!

## Licence
Dual-licensed under [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
