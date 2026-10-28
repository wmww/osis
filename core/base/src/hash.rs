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
    pub fn new_keyed(key: &[u8; 32]) -> Hasher {
        Hasher(blake3::Hasher::new_keyed(key))
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

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §1: BLAKE3; known answer for the empty input (BLAKE3 test vectors).
    #[test]
    fn blake3_known_answer() {
        let h = hash(b"");
        assert_eq!(h[..4], [0xaf, 0x13, 0x49, 0xb9]);
        assert_eq!(Hasher::new().update(b"ab").update(b"c").finalize(), hash(b"abc"));
        let k = [7u8; 32];
        assert_eq!(Hasher::new_keyed(&k).update(b"x").finalize(), keyed_hash(&k, b"x"));
        assert_ne!(keyed_hash(&k, b"x"), hash(b"x"));
        assert_ne!(derive_key("osis v1 a", b"m"), derive_key("osis v1 b", b"m"));
        let mut out = [0u8; 64];
        Hasher::new().update(b"abc").finalize_xof(&mut out);
        assert_eq!(out[..32], hash(b"abc"));
    }
}
