//! osis-vectors: conformance vector format (`.vec` files), manifest with the freeze policy,
//! per-subject checkers and generators. Format and policy: vectors/README.md.
//! Layer 9 (notes/architecture.md). Plan: plans/test-infra.md.
#![forbid(unsafe_code)]
// Test tooling: a panic is a test failure, not a peer-triggered crash.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod corpus;
pub mod diag;
pub mod file;
pub mod manifest;
pub mod subjects;

use std::path::PathBuf;

/// The `vectors/` directory.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub use osis_core::hex::encode as hex;

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    osis_core::hex::decode(s).ok_or_else(|| format!("bad hex: {s}"))
}

/// `n` bytes of the unkeyed BLAKE3 XOF of `seed` (the `xof` input form of README.md).
pub fn xof(seed: &str, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    osis_core::hash::Hasher::new().update(seed.as_bytes()).finalize_xof(&mut out);
    out
}
