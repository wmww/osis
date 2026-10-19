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

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return Err(format!("bad hex: {s}"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex {s}: {e}"))).collect()
}

/// `n` bytes of the unkeyed BLAKE3 XOF of `seed` (the `xof` input form of README.md).
pub fn xof(seed: &str, n: usize) -> Vec<u8> {
    let mut out = vec![0; n];
    osis_core::hash::Hasher::new().update(seed.as_bytes()).finalize_xof(&mut out);
    out
}
