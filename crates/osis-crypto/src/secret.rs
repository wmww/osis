//! Zeroizing 32-byte secret (notes/architecture.md §3: secrets never printed).

use rand_core::CryptoRngCore;
use std::fmt;
use zeroize::Zeroize;

/// A 32-byte secret: role secret, seed, blob key, token. Zeroized on drop; `Debug` redacted.
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    pub const fn from_bytes(b: [u8; 32]) -> Secret32 {
        Secret32(b)
    }
    pub fn random(rng: &mut dyn CryptoRngCore) -> Secret32 {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        Secret32(b)
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(..)")
    }
}

/// Constant-time comparison.
impl PartialEq for Secret32 {
    fn eq(&self, other: &Secret32) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for Secret32 {}

#[cfg(test)]
mod tests {
    use super::*;

    // spec: none (notes/architecture.md §3: Debug of secrets is redacted)
    #[test]
    fn debug_redacted() {
        let s = Secret32::from_bytes([0xab; 32]);
        let d = format!("{s:?}");
        assert!(!d.contains("ab") && !d.contains("171"), "{d}");
    }
}
