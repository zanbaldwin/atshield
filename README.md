# ATShield
ATProto identity-tampering detection for `did:plc` accounts.

## Environment

Required packages:
- `cmake`
- `make`
- `musl-tools`

Or, without messing with system:
```shell
podman run --rm \
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

### Formatters
- `.md` via `rumdl fmt`,
- `.rs` via `rustfmt +nightly` (per-file; matches `cargo +nightly fmt --all`)
