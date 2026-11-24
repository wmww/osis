//! BLAKE3 wrappers (spec/crypto.md §1, spec/data-model.md §7). `kdf` lives in osis-crypto.

/// Unkeyed BLAKE3: tids, commit IDs, blob IDs.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Keyed BLAKE3 (MAC mode).
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// BLAKE3 key derivation; `context` is a fixed domain string.
pub fn derive_key(context: &str, material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, material)
}

/// Incremental unkeyed or keyed hashing, for inputs that arrive in pieces.
#[derive(Clone, Debug)]
pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Hasher {
        Hasher(blake3::Hasher::new())
    }
    pub fn update(&mut self, data: &[u8]) -> &mut Hasher {
        self.0.update(data);
        self
    }
    pub fn finalize(&self) -> [u8; 32] {
        *self.0.finalize().as_bytes()
    }
    /// Extendable output: fills `out`.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        self.0.finalize_xof().fill(out);
    }
}

impl Default for Hasher {
    fn default() -> Hasher {
        Hasher::new()
    }
}
