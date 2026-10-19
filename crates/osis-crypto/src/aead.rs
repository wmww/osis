//! XChaCha20-Poly1305 (spec/crypto.md §1): 32-byte key, 24-byte nonce, 16-byte tag.

use crate::Error;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const ZERO_NONCE: [u8; NONCE_LEN] = [0; NONCE_LEN];

/// Ciphertext || tag.
pub fn seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(nonce.into(), Payload { msg: plaintext, aad: ad })
        .map_err(|_| Error::TooLarge)
}

pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad: ad })
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // spec/crypto.md §1: XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03 §A.3.1).
    #[test]
    fn xchacha_known_answer() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").try_into().unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657").try_into().unwrap();
        let ad = hex("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = hex(concat!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
            "21f9664c97637da9768812f615c68b13b52e",
            "c0875924c1c7987947deafd8780acf49"
        ));
        assert_eq!(seal(&key, &nonce, &ad, pt).unwrap(), ct);
        assert_eq!(open(&key, &nonce, &ad, &ct).unwrap(), pt);
        assert_eq!(open(&key, &nonce, b"", &ct), Err(Error::Decrypt));
        assert_eq!(open(&key, &nonce, &ad, &ct[..10]), Err(Error::Decrypt));
    }
}
