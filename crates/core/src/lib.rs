// SPDX-License-Identifier: MIT OR Apache-2.0
#![forbid(unsafe_code)]
//! Stateless `did:plc` primitives for identity-tampering detection: validating
//! value types, verifying audit-log operations, and proof of possession.
//!
//! Everything here is transport-free and stateless. The crate parses and validates
//! audit-log JSON and verifies operation signatures, but performs no I/O, owns
//! no persistence or scheduler, and never holds private-key material beyond the
//! single in-memory call that signs with it.

pub mod audit;
mod cid;
pub mod crypto;
pub mod delta;
mod did;
mod encoding;
mod endpoints;
pub mod error;
mod handle;
pub mod operation;
pub mod resolver;
#[cfg(any(test, feature = "test-utils"))]
pub mod test;

pub use self::handle::Handle;
pub use cid::Cid;
pub use did::{DidExt, Key as DidKey, Kind as DidKind, Plc as DidPlc, Web as DidWeb};
pub use endpoints::{DEFAULT_PLC_HOST, Endpoint, MAX_EXPORT_COUNT};
use serde::de::{Deserialize, Deserializer, Error as _};
use std::fmt;
use std::str::FromStr;

/// Read a JSON string and validate it through `T`'s [`FromStr`].
fn de_via_fromstr<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: fmt::Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(D::Error::custom)
}
