<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# 🛡️ atshield-core

`atshield-core` is the stateless, transport-free engine behind [`atshield`](https://github.com/zanbaldwin/atshield): a
set of `did:plc` primitives that verify an ATProto identity's audit log, resolve its current state, classify every
change against a known-good baseline, and sign proof-of-possession challenges. It does the cryptography and none of the
plumbing; you bring the bytes.

> **Looking for the tool you actually run?** This is the library. The command-line program (with a baseline store,
> handle resolution, and an exit code you can put in cron) is
> [`atshield-cli`](https://github.com/zanbaldwin/atshield/tree/main/crates/cli).

- **It trusts nothing off the wire.** Every operation's CID is recomputed from its canonical DAG-CBOR, every signature
  re-verified against the previous operation's rotation keys, and the DID itself re-derived from the genesis operation's
  bytes rather than read off the response. The wire `did` field is dropped at parse and never trusted.
- **Verified by construction, in the type system.** An operation moves `Unsigned` to `Signed` to `Checked`, and a
  `Checked` value can only be produced by an actual signature check. The states are sealed, so you cannot forge a
  verified operation out of untrusted JSON; the compiler enforces the property the security rests on.
- **The tamper signal is a disagreement, not a flag.** The head is resolved two independent ways (what the directory
  reports through its `nullified` flags, versus what rotation-key authority plus the 72-hour recovery window actually
  permit) and compared. When the two disagree, the directory is serving a history the protocol does not support.
- **Change classification with attribution.** Given a baseline and the keys you control, it attributes every change to
  the operation and signer that made it and rates severity, because "I rotated my keys" and "someone else rotated my
  keys" produce identical-looking records.
- **No I/O, no state, no custody.** No HTTP client, no async runtime, no persistence, no scheduler. Private-key material
  lives only for the single in-memory call that signs with it, and is zeroised on drop.

## Why

Your ATProto identity isn't your Bluesky account; it's a `did:plc` record listing your handle, your data server, and
your signing keys, and it's the same identity you carry into every other service in the Atmosphere. Control of that
record belongs to whoever holds its rotation keys, and the protocol gives you exactly one escape hatch if the wrong
person gets hold of them: a higher-priority key can rewrite an unauthorised operation, but only within a 72-hour window.
That's a genuinely good recovery mechanism with one catch: nobody reads their own PLC audit log for fun. `atshield`
reads it for you, cryptographically, and this crate is the part that does the reading.

It's split out from the CLI: verification should not depend on how the bytes arrived.
`atshield-core` takes audit-log JSON (and `serde_json::Value`) from `plc.directory`, a local mirror, a fixture file, a
test harness, etc. It returns plain value types, and never opens a socket.
The verifier is hand-rolled rather than borrowed, backed by real-world fixtures; a detector that verifies differently
from the thing it's auditing is worse than useless. Plus it was really fun to build.

## In practice

Constructing the chain _is_ the verification. There's no separate `verify()` to remember to call:

```rust
use atshield_core::audit::{AuditLogEntry, VerifiedAuditChain};
use atshield_core::resolver::ChainResolver;

// You fetch the bytes; the crate never touches the network.
let entries: Vec<AuditLogEntry> = serde_json::from_str(&audit_log_json)?;

// Every CID is recomputed and every signature checked against the prior
// operation's rotation keys. One tampered byte anywhere and this is Err.
let chain = VerifiedAuditChain::try_from(entries)?;

// Resolve the head two independent ways and compare. `false` is the alert.
if !ChainResolver::new(&chain).is_agreeable() {
    println!("directory divergence for {}", chain.did());
}
```

To decide whether a change was made by _you_ or by someone else, hand a baseline the keys you control and audit against
the same chain:

```rust
use atshield_core::delta::{Baseline, Verdict};
use atshield_core::resolver::ChainResolver;

// Record
let (state, _head_signer) = ChainResolver::new(&chain).reported()?;
let baseline = Baseline::new(state, my_rotation_keys);

// Later...
let report = baseline.audit(&fresh_chain)?;
match report.live {
    Verdict::Clean => {}                    // nothing changed since the baseline
    Verdict::Legitimate { .. } => {}        // changed, but every change was signed by a key you hold
    Verdict::Tamper { severity, .. } => {}  // changed, and someone else did it
}
```

<!-- rumdl-disable-next-line MD025 -->
# The Technical Stuff

## Installation

```shell
cargo add atshield-core
```

Edition 2024, MSRV `1.96`, `#![forbid(unsafe_code)]`. Fetching the bytes is the caller's job.

## What's in the crate

| Module      | What it gives you                                                                                      |
|-------------|--------------------------------------------------------------------------------------------------------|
| `audit`     | `AuditLogEntry`, `VerifiedAuditChain`: parse `/log/audit` into a chain that's verified by construction |
| `resolver`  | `ChainResolver`, `ResolvedState`: resolve the head two ways; `is_agreeable()` is the tamper signal     |
| `delta`     | `Baseline`, `AuditReport`, `Verdict`, `Delta`, `Severity`: classify changes against a baseline         |
| `operation` | `Operation<S>`: the typestate operation value object (`Unsigned`, `Signed`, `Checked`)                 |
| `crypto`    | `PrivateKey`, `KeyPair`, `Signature`, `Nonce`: ECDSA signing and proof-of-possession primitives        |
| `error`     | the nine `thiserror` enums, one per failure surface                                                    |
| _root_      | `DidKey`, `DidPlc`, `DidWeb`, `Cid`, `Endpoint`: validating value types that fail at parse, not in use |

## Design decisions worth knowing

- Identity is always genesis-derived.
- One value, three byte-streams.
- Strict low-S, always.
- Rotation-key _order_ is load-bearing.
- Exact-pinned cryptography.

## Maturity, and limits worth knowing
This is `0.1.0`, pre-1.0 software: the API will shift before it stabilises, so pin it. Beyond that, a few honest edges:

- `did:plc`-only (v1). The `did:web` newtype validates offline, but the verification pipeline operates on `did:plc`.
- The 72-hour check trusts asserted timestamps. `canonical` resolution reads the `createdAt` values the directory
  asserts, and those are **not** part of the cryptographic chain. A directory that backdates a hostile operation can
  defeat the window check; catching that needs an independent observation timeline, which is intentionally out of scope
  for this crate.
- Classification is only as good as the key list you pass in. Hand `Baseline::new` an empty key set and every change
  classifies as tampering.

## Status

- [x] Audit-chain verification (forked histories, tombstones, the legacy `create` format, official interop vectors)
- [x] Two-way head resolution and the divergence signal
- [x] Baseline classification with per-change attribution and severity
- [x] ECDSA signing and proof-of-possession (secp256k1 and P-256, strict low-S)
- [ ] `did:web` support
- [ ] A stable `1.0` API

## Contributing
`atshield` is a young, solo-maintained project. The following are genuinely welcome:

- Bug reports and/or fixes,
- Documentation improvements, and
- War stories about identity migrations gone wrong (they make for fantastic test fixtures)

Reviews can take a little while, see [CONTRIBUTING](https://github.com/zanbaldwin/atshield/blob/main/CONTRIBUTING.md)
for more details.

## Licence
Dual-licensed under [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).
