//! Deterministic CSPRNG for tests, vectors and the simulator: the BLAKE3 XOF keyed by a seed.
//! Libraries never own randomness (notes/architecture.md §2); drivers pass `OsRng` (feature `os-rng`).

use rand_core::{CryptoRng, RngCore};

/// BLAKE3 XOF stream keyed by a 32-byte seed. A secure stream, but its seed is the whole secret:
/// production code uses the OS generator.
pub struct SeededRng(blake3::OutputReader);

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
        let (mut a, mut b) = (SeededRng::from_u64(7), SeededRng::from_u64(7));
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(SeededRng::from_u64(8).next_u64(), SeededRng::from_u64(7).next_u64());
    }
}
