//! Deterministic CSPRNG for tests, vectors and the simulator: the BLAKE3 XOF keyed by a seed.
//! Libraries never own randomness (notes/architecture.md §2); drivers pass `OsRng`.

use rand_core::{CryptoRng, RngCore};

/// BLAKE3 XOF stream keyed by a 32-byte seed. A secure stream, but its seed is the whole secret:
/// production code uses the OS generator.
pub struct SeededRng(blake3::OutputReader);

/// A node's generator: a secure one, which a test's world copy can copy (`test_copy`).
pub trait NodeRng: rand_core::CryptoRngCore + Send {
    /// Tests only (world copies, notes/testing.md): a generator continuing as this one would,
    /// the same stream for a seeded one. Never in a product: two nodes drawing one stream draw
    /// the same nonces and keys.
    #[doc(hidden)]
    fn test_copy(&self) -> Box<dyn NodeRng>;
}

impl NodeRng for SeededRng {
    fn test_copy(&self) -> Box<dyn NodeRng> {
        Box::new(SeededRng::test_copy(self))
    }
}

impl NodeRng for rand_core::OsRng {
    fn test_copy(&self) -> Box<dyn NodeRng> {
        Box::new(rand_core::OsRng)
    }
}

impl SeededRng {
    /// Tests only: `NodeRng::test_copy` unboxed. Inside `osis_base::copying::copying_reseeded`
    /// a new stream instead, keyed by the salt and this stream's next 32 bytes (this one does
    /// not move).
    #[doc(hidden)]
    pub fn test_copy(&self) -> SeededRng {
        let mut same = SeededRng(self.0.clone());
        let Some(salt) = osis_base::copying::reseed() else { return same };
        let mut key = [0u8; 32];
        same.fill_bytes(&mut key);
        let mut h = blake3::Hasher::new_keyed(&key);
        h.update(&salt.to_le_bytes());
        SeededRng(h.finalize_xof())
    }
}

impl SeededRng {
    pub fn from_seed(seed: [u8; 32]) -> SeededRng {
        SeededRng(blake3::Hasher::new_keyed(&seed).finalize_xof())
    }
    /// Seed from a number (simulator and test seeds).
    pub fn from_u64(n: u64) -> SeededRng {
        let mut seed = [0u8; 32];
        if let Some(head) = seed.get_mut(..8) {
            head.copy_from_slice(&n.to_le_bytes());
        }
        SeededRng::from_seed(seed)
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

impl CryptoRng for SeededRng {}

impl Drop for SeededRng {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (notes/architecture.md §3: a failure is a seed; same seed, same stream)
    #[test]
    fn deterministic() {
        let (mut a, mut b) = (SeededRng::from_u64(0), SeededRng::from_u64(0));
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(SeededRng::from_u64(1).next_u64(), SeededRng::from_u64(0).next_u64());
    }

    // spec: none (notes/testing.md, Copied worlds): a copy goes on with the same stream; a
    // reseeded copy with a stream of its salt, the same for the same salt, the original unmoved
    #[test]
    fn reseeded_copy_draws_the_salts_stream() {
        let mut a = SeededRng::from_u64(7);
        let same = a.test_copy().next_u64();
        let draw = |salt| osis_base::copying::copying_reseeded(salt, || a.test_copy().next_u64());
        let (x, x2, y) = (draw(1), draw(1), draw(2));
        assert!(x == x2 && x != y && x != same);
        assert_eq!(a.next_u64(), same);
    }
}
