<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# 🛡️ atshield
`atshield` detects tampering with an ATProto identity: the `did:plc` record that Bluesky, and every other service in
the Atmosphere, derives your account from. It fetches an identity's public audit log, re-verifies the entire
cryptographic chain from scratch, and reports (with an exit code you can put in cron) whether anything changed that you
didn't sign yourself.

Control of a `did:plc` record belongs to whoever holds its rotation keys, and the protocol gives you only a 72-hour
window to undo an operation you didn't authorise. `atshield` watches that window for you, because nobody reads their own
PLC audit log for fun.

> The verification recomputes every CID from canonical DAG-CBOR, re-checks every ECDSA signature (secp256k1/P-256,
> strict low-S), re-derives the DID from genesis bytes, and is validated against the official protocol interop vectors.

## The published crates
This repository is a Cargo workspace. Each crate carries its own README with details.

- **[`atshield-core`](crates/core)** is the engine: stateless, transport-free `did:plc` primitives that verify an audit
  log, resolve its current state two independent ways, classify changes against a baseline, and sign proof-of-possession
  challenges. No I/O, no state, no key custody. Start here if you want a library to build on.
- **[`atshield-cli`](crates/cli)** is the `atshield` command: the tool that fetches the bytes, keeps a baseline on disk,
  resolves handles, and renders the verdict. Start here if you want something to run.

```shell
cargo install atshield-cli
```

## The sandbox
**[`fakesky-edge`](crates/edge)** is an edge proxy (built on [Pingora](https://github.com/cloudflare/pingora)) that
proxies between a throwaway PLC directory and control plane application. Currently complete but unused.

## Licence
`atshield-core` and `atshield-cli` are dual-licensed under [MIT](https://opensource.org/license/mit) or
[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0). `fakesky-edge` is currently not licensed.
