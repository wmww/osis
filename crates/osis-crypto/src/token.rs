//! Delete tokens, token hashes and prefix commitments (spec/crypto.md §7).

use crate::kdf::{self, kdf};
use crate::{Error, Secret32};

/// Token `kdf("delete token", secret, salt)`: header salt for a commit blob, the chunk's prefix
/// salt for a chunk. Secret until presented.
pub fn delete_token(secret: &Secret32, salt: &[u8; 16]) -> Secret32 {
    kdf(kdf::DELETE_TOKEN, secret.expose(), salt)
}

/// Token hash = BLAKE3(token)[..16], listed in the header.
pub fn token_hash(token: &[u8; 32]) -> [u8; 16] {
    first16(blake3::hash(token).as_bytes())
}

/// Prefix commitment = level || BLAKE3(token hash || prefix salt)[..16]; level 1..=3.
pub fn commitment(level: u8, token_hash: &[u8; 16], prefix_salt: &[u8; 16]) -> Result<[u8; 17], Error> {
    if !(1..=3).contains(&level) {
        return Err(Error::Malformed("token level"));
    }
    let mut h = blake3::Hasher::new();
    h.update(token_hash).update(prefix_salt);
    let mut c = [level; 17];
    if let Some(dst) = c.get_mut(1..) {
        dst.copy_from_slice(&first16(h.finalize().as_bytes()));
    }
    Ok(c)
}

/// Whether a presented token matches a prefix commitment (hashing twice); the caller then requires
/// the signature the commitment's level calls for (spec/sync.md §5).
pub fn verify_presented_token(token: &[u8; 32], commitment_bytes: &[u8; 17], prefix_salt: &[u8; 16]) -> bool {
    let [level, ..] = *commitment_bytes;
    commitment(level, &token_hash(token), prefix_salt).is_ok_and(|c| c == *commitment_bytes)
}

fn first16(h: &[u8; 32]) -> [u8; 16] {
    let mut o = [0u8; 16];
    o.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/crypto.md §7: a token verifies only against its own commitment and salt.
    #[test]
    fn token_commitments() {
        let secret = Secret32::from_bytes([1; 32]);
        let t = delete_token(&secret, &[2; 16]);
        assert_ne!(t, delete_token(&secret, &[3; 16]));
        let salt = [4u8; 16];
        let c = commitment(2, &token_hash(t.expose()), &salt).unwrap();
        assert_eq!(c[0], 2);
        assert!(verify_presented_token(t.expose(), &c, &salt));
        assert!(!verify_presented_token(t.expose(), &c, &[5; 16]));
        let other = delete_token(&Secret32::from_bytes([9; 32]), &[2; 16]);
        assert!(!verify_presented_token(other.expose(), &c, &salt));
        // The level is not hashed: the blob prefix holding it is what the blob ID authenticates.
        let mut relevel = c;
        relevel[0] = 3;
        assert!(verify_presented_token(t.expose(), &relevel, &salt));
        relevel[0] = 0;
        assert!(!verify_presented_token(t.expose(), &relevel, &salt));
        assert!(commitment(4, &[0; 16], &salt).is_err());
        assert_eq!(token_hash(t.expose()), blake3::hash(t.expose()).as_bytes()[..16]);
    }
}
