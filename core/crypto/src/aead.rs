//! XChaCha20-Poly1305 (spec/crypto.md §1): 32-byte key, 24-byte nonce, 16-byte tag.

use crate::{Error, SUITE_1, Secret32};
use zeroize::Zeroizing;
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

/// XChaCha20's keystream under one key and nonce, its HChaCha20 step done once: plaintext bytes
/// of ciphertexts sealed under them, NOT authenticated. Forensic tests only (`osis_store::attack`
/// tries tens of thousands of candidate keys): a byte every plaintext of its kind has (a padded
/// one ends in 0x80 or 0x00) rules a key out without `open`'s pass over the whole ciphertext.
#[doc(hidden)]
pub struct Keystream {
    subkey: Zeroizing<[u8; 32]>,
    /// ChaCha20's nonce: four zero bytes, then the last 8 of XChaCha's.
    nonce: [u8; 12],
}

impl Keystream {
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Keystream {
        let (head, tail) = nonce.split_at(16);
        let mut subkey = Zeroizing::new([0u8; 32]);
        let mut h = chacha20::hchacha::<chacha20::cipher::consts::U10>(key.into(), head.into());
        subkey.copy_from_slice(&h);
        zeroize::Zeroize::zeroize(h.as_mut_slice());
        let mut n = [0u8; 12];
        n.get_mut(4..).unwrap_or_default().copy_from_slice(tail);
        Keystream { subkey, nonce: n }
    }

    /// Keystream byte `i` of the message (block 0 is the Poly1305 key; the message starts at
    /// block 1).
    pub fn byte(&self, i: usize) -> u8 {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        let mut c = chacha20::ChaCha20::new((&*self.subkey).into(), (&self.nonce).into());
        c.seek(64 + i as u64);
        let mut b = [0u8];
        c.apply_keystream(&mut b);
        let [b] = b;
        b
    }

    /// Plaintext byte `i` of `ciphertext` (with its tag); `None`: the plaintext has no byte `i`.
    pub fn plain_byte(&self, ciphertext: &[u8], i: usize) -> Option<u8> {
        if i >= ciphertext.len().checked_sub(TAG_LEN)? {
            return None;
        }
        Some(ciphertext.get(i)? ^ self.byte(i))
    }

    /// The last plaintext byte.
    pub fn last_plain_byte(&self, ciphertext: &[u8]) -> Option<u8> {
        self.plain_byte(ciphertext, ciphertext.len().checked_sub(TAG_LEN + 1)?)
    }
}

/// A 49-byte `suite || key` sealing (spec/wire.md §7): symmetric boxes.
pub const SUITE_KEY_LEN: usize = 1 + 32 + TAG_LEN;

/// Encrypts `SUITE_1 || secret` under `ad`.
pub(crate) fn seal_suite_key(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], secret: &Secret32) -> Result<[u8; SUITE_KEY_LEN], Error> {
    let mut pt = Zeroizing::new([SUITE_1; 33]);
    if let Some(dst) = pt.get_mut(1..) {
        dst.copy_from_slice(secret.expose());
    }
    seal(key, nonce, ad, &pt[..])?.try_into().map_err(|_| Error::Malformed("wrap length"))
}

/// Opens a `suite || key` wrap; an unknown suite parks.
pub(crate) fn open_suite_key(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], wrap: &[u8]) -> Result<Secret32, Error> {
    if wrap.len() != SUITE_KEY_LEN {
        return Err(Error::Malformed("wrap length"));
    }
    let pt = Zeroizing::new(open(key, nonce, ad, wrap)?);
    let (suite, k) = pt.split_first().ok_or(Error::Decrypt)?;
    if *suite != SUITE_1 {
        return Err(Error::UnknownSuite(u64::from(*suite)));
    }
    let k: [u8; 32] = k.try_into().map_err(|_| Error::Decrypt)?;
    Ok(Secret32::from_bytes(k))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        osis_base::hex::decode(s).unwrap()
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

    // spec: none (forensic test support): the unauthenticated first and last bytes are the
    // plaintext's, at every length across block boundaries
    #[test]
    fn keystream_bytes_are_the_plaintexts() {
        // bytes all distinct: a key or nonce byte out of place shows
        let key: [u8; 32] = std::array::from_fn(|i| i as u8 * 7 + 1);
        let nonce: [u8; NONCE_LEN] = std::array::from_fn(|i| i as u8 * 5 + 100);
        for n in 0..200usize {
            let pt: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            let ct = seal(&key, &nonce, b"ad", &pt).unwrap();
            let ks = Keystream::new(&key, &nonce);
            assert_eq!(ks.last_plain_byte(&ct), pt.last().copied(), "length {n}");
            assert_eq!(ks.plain_byte(&ct, 0), pt.first().copied(), "length {n}");
            assert_eq!(ks.plain_byte(&ct, n), None);
        }
        assert_eq!(Keystream::new(&key, &nonce).last_plain_byte(&[0; TAG_LEN]), None);
    }
}
