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
/// One ChaCha20 block per byte (RFC 8439 §2.3; HChaCha20, draft-irtf-cfrg-xchacha §2.2),
/// computed here: the `chacha20` crate's vector backend makes four.
#[doc(hidden)]
pub struct Keystream {
    subkey: Zeroizing<[u32; 8]>,
    /// The last 8 bytes of XChaCha's nonce (ChaCha20's: four zero bytes, then these).
    nonce: [u32; 2],
}

/// "expand 32-byte k"
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

fn words<const N: usize>(b: &[u8]) -> [u32; N] {
    let mut w = [0u32; N];
    for (x, c) in w.iter_mut().zip(b.as_chunks::<4>().0) {
        *x = u32::from_le_bytes(*c);
    }
    w
}

/// A ChaCha20 input: constants, key, then counter and nonce (`n`).
fn input(k: &[u32; 8], n: [u32; 4]) -> [u32; 16] {
    let [s0, s1, s2, s3] = SIGMA;
    let [k0, k1, k2, k3, k4, k5, k6, k7] = *k;
    let [n0, n1, n2, n3] = n;
    [s0, s1, s2, s3, k0, k1, k2, k3, k4, k5, k6, k7, n0, n1, n2, n3]
}

fn quarter(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(12);
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(8);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// ChaCha20's 20 rounds over an input, without the final addition.
fn rounds(s: &[u32; 16]) -> [u32; 16] {
    let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7, mut x8, mut x9, mut x10, mut x11, mut x12, mut x13, mut x14, mut x15] = *s;
    for _ in 0..10 {
        (x0, x4, x8, x12) = quarter(x0, x4, x8, x12);
        (x1, x5, x9, x13) = quarter(x1, x5, x9, x13);
        (x2, x6, x10, x14) = quarter(x2, x6, x10, x14);
        (x3, x7, x11, x15) = quarter(x3, x7, x11, x15);
        (x0, x5, x10, x15) = quarter(x0, x5, x10, x15);
        (x1, x6, x11, x12) = quarter(x1, x6, x11, x12);
        (x2, x7, x8, x13) = quarter(x2, x7, x8, x13);
        (x3, x4, x9, x14) = quarter(x3, x4, x9, x14);
    }
    [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15]
}

impl Keystream {
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Keystream {
        let (head, tail) = nonce.split_at(16);
        // HChaCha20: the rounds over the key and the nonce's first 16 bytes; words 0-3 and 12-15
        let [x0, x1, x2, x3, _, _, _, _, _, _, _, _, x12, x13, x14, x15] = rounds(&input(&Zeroizing::new(words(key)), words(head)));
        Keystream { subkey: Zeroizing::new([x0, x1, x2, x3, x12, x13, x14, x15]), nonce: words(tail) }
    }

    /// Keystream byte `i` of the message (block 0 is the Poly1305 key; the message starts at
    /// block 1).
    pub fn byte(&self, i: usize) -> u8 {
        let [n0, n1] = self.nonce;
        let s = input(&self.subkey, [u32::try_from(i / 64 + 1).unwrap_or(u32::MAX), 0, n0, n1]);
        let w = (i % 64) / 4;
        let word = rounds(&s).get(w).copied().unwrap_or(0).wrapping_add(s.get(w).copied().unwrap_or(0));
        word.to_le_bytes().get(i % 4).copied().unwrap_or(0)
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
        // bytes all distinct: a word out of place shows
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
