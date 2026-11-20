//! XChaCha20-Poly1305 (spec/crypto.md §1): 32-byte key, 24-byte nonce, 16-byte tag.

use crate::{Error, SUITE_1, Secret32};
use zeroize::Zeroizing;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
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

/// `seal` in place: `buf` becomes the ciphertext and the tag is returned (`seal`'s output is
/// `buf || tag`). A buffer built to hold a plaintext then holds none, so it needs no wipe.
pub fn seal_in_place(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
    XChaCha20Poly1305::new(key.into()).encrypt_in_place_detached(nonce.into(), ad, buf).map(Into::into).map_err(|_| Error::TooLarge)
}

pub fn open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad: ad })
        .map_err(|_| Error::Decrypt)
}

/// XChaCha20's keystream under one key and nonce, its HChaCha20 step done once: plaintext bytes
/// of ciphertexts sealed under them, NOT authenticated, and `open`'s tag check alone. Forensic
/// tests only (`osis_store::attack` tries hundreds of thousands of candidate keys): a byte every
/// plaintext of its kind has (a padded one ends in 0x80 or 0x00) rules a key out without
/// `open`'s pass over the whole ciphertext. Scalar ChaCha20 and Poly1305 (RFC 8439), a block at a
/// time: the crates' wide backends set up for long messages cost several times one block.
#[doc(hidden)]
pub struct Keystream {
    subkey: Zeroizing<[u32; 8]>,
    /// ChaCha20's nonce words: zero, then the last 8 bytes of XChaCha's.
    nonce: [u32; 3],
    /// The message's first keystream block (block 1), once asked.
    first: std::sync::OnceLock<[u32; 16]>,
}

/// ChaCha20's 20 rounds over `s` (RFC 8439 §2.3), no feed-forward.
fn rounds(s: &mut [u32; 16]) {
    #[inline(always)]
    fn q(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let a = a.wrapping_add(b);
        let d = (d ^ a).rotate_left(16);
        let c = c.wrapping_add(d);
        let b = (b ^ c).rotate_left(12);
        let a = a.wrapping_add(b);
        let d = (d ^ a).rotate_left(8);
        let c = c.wrapping_add(d);
        (a, (b ^ c).rotate_left(7), c, d)
    }
    let [mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7, mut x8, mut x9, mut x10, mut x11, mut x12, mut x13, mut x14, mut x15] = *s;
    for _ in 0..10 {
        (x0, x4, x8, x12) = q(x0, x4, x8, x12);
        (x1, x5, x9, x13) = q(x1, x5, x9, x13);
        (x2, x6, x10, x14) = q(x2, x6, x10, x14);
        (x3, x7, x11, x15) = q(x3, x7, x11, x15);
        (x0, x5, x10, x15) = q(x0, x5, x10, x15);
        (x1, x6, x11, x12) = q(x1, x6, x11, x12);
        (x2, x7, x8, x13) = q(x2, x7, x8, x13);
        (x3, x4, x9, x14) = q(x3, x4, x9, x14);
    }
    *s = [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15];
}

/// The ChaCha20 state of `key` and `words` (counter and nonce, or HChaCha20's 16-byte input).
fn state(key: &[u32; 8], words: [u32; 4]) -> [u32; 16] {
    let mut s = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    s[4..12].copy_from_slice(key);
    s[12..].copy_from_slice(&words);
    s
}

fn le_words<const N: usize>(b: &[u8]) -> [u32; N] {
    std::array::from_fn(|i| b.get(i * 4..i * 4 + 4).and_then(|w| w.try_into().ok()).map_or(0, u32::from_le_bytes))
}

impl Keystream {
    pub fn new(key: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> Keystream {
        // HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2): the rounds' words 0-3 and 12-15
        let mut s = state(&le_words(key), le_words(nonce));
        rounds(&mut s);
        let subkey = Zeroizing::new([s[0], s[1], s[2], s[3], s[12], s[13], s[14], s[15]]);
        zeroize::Zeroize::zeroize(&mut s);
        let [_, n1, n2] = le_words::<3>(nonce.get(12..).unwrap_or_default());
        Keystream { subkey, nonce: [0, n1, n2], first: std::sync::OnceLock::new() }
    }

    /// Keystream block `counter`'s words (block 0 is the Poly1305 key; the message starts at
    /// block 1).
    fn block(&self, counter: u32) -> [u32; 16] {
        let [_, n1, n2] = self.nonce;
        let init = state(&self.subkey, [counter, 0, n1, n2]);
        let mut s = init;
        rounds(&mut s);
        for (x, i) in s.iter_mut().zip(init) {
            *x = x.wrapping_add(i);
        }
        s
    }

    /// The one-time Poly1305 key (block 0): forensic tests building a ciphertext that
    /// authenticates under two keys (Poly1305 commits to no key).
    pub fn poly_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (k, w) in key.as_chunks_mut::<4>().0.iter_mut().zip(self.block(0)) {
            *k = w.to_le_bytes();
        }
        key
    }

    /// Keystream byte `i` of the message.
    pub fn byte(&self, i: usize) -> u8 {
        let at = |b: &[u32; 16]| b.get(i % 64 / 4).map_or(0, |w| (w >> (8 * (i % 4))) as u8);
        if i < 64 {
            return at(self.first.get_or_init(|| self.block(1)));
        }
        // a message past 2^38 bytes has no such byte under one nonce
        u32::try_from(i / 64 + 1).map_or(0, |c| at(&self.block(c)))
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

    /// Whether `sealed` (ciphertext || tag) authenticates under this key and nonce with `ad`:
    /// whether `open` would.
    pub fn authentic(&self, ad: &[u8], sealed: &[u8]) -> bool {
        let Some((ct, tag)) = sealed.len().checked_sub(TAG_LEN).map(|n| sealed.split_at(n)) else { return false };
        let mut p = Poly1305::new(&self.poly_key());
        p.padded(ad);
        p.padded(ct);
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        p.block(&lens, 1);
        // a forgery test only: equal or not, no secret is compared
        p.tag() == tag
    }
}

/// Poly1305 (RFC 8439 §2.5) in 44, 44 and 42-bit limbs.
struct Poly1305 {
    r: [u64; 3],
    h: [u64; 3],
    pad: [u64; 2],
}

const M44: u64 = (1 << 44) - 1;
const M42: u64 = (1 << 42) - 1;

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Poly1305 {
        let w = |i: usize| key.get(i..i + 8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_le_bytes);
        let (t0, t1) = (w(0), w(8));
        let r = [t0 & 0xffc_0fff_ffff, ((t0 >> 44) | (t1 << 20)) & 0xfff_ffc0_ffff, (t1 >> 24) & 0x00f_ffff_fc0f];
        Poly1305 { r, h: [0; 3], pad: [w(16), w(24)] }
    }

    /// One 16-byte block; `hi` 1 for a whole block (the appended 1 bit), 0 for padding's own.
    fn block(&mut self, m: &[u8; 16], hi: u64) {
        let w = |i: usize| m.get(i..i + 8).and_then(|b| b.try_into().ok()).map_or(0, u64::from_le_bytes);
        let (t0, t1) = (w(0), w(8));
        let [r0, r1, r2] = self.r;
        let (s1, s2) = (r1 * 20, r2 * 20);
        let m = |a: u64, b: u64| u128::from(a) * u128::from(b);
        let h0 = self.h[0] + (t0 & M44);
        let h1 = self.h[1] + (((t0 >> 44) | (t1 << 20)) & M44);
        let h2 = self.h[2] + (((t1 >> 24) & M42) | hi << 40);
        let d0 = m(h0, r0) + m(h1, s2) + m(h2, s1);
        let mut d1 = m(h0, r1) + m(h1, r0) + m(h2, s2);
        let mut d2 = m(h0, r2) + m(h1, r1) + m(h2, r0);
        d1 += d0 >> 44;
        d2 += d1 >> 44;
        let mut h0 = (d0 as u64 & M44) + (d2 >> 42) as u64 * 5;
        let h1 = (d1 as u64 & M44) + (h0 >> 44);
        h0 &= M44;
        self.h = [h0, h1, d2 as u64 & M42];
    }

    /// `b` in 16-byte blocks, the last zero-padded (the AEAD's padding: every block whole).
    fn padded(&mut self, b: &[u8]) {
        for c in b.chunks(16) {
            let mut m = [0u8; 16];
            m.iter_mut().zip(c).for_each(|(m, c)| *m = *c);
            self.block(&m, 1);
        }
    }

    fn tag(&self) -> [u8; 16] {
        let [mut h0, mut h1, mut h2] = self.h;
        // carry fully, then h mod p: h - p where that does not underflow
        for _ in 0..2 {
            h1 += h0 >> 44;
            h0 &= M44;
            h2 += h1 >> 44;
            h1 &= M44;
            h0 += (h2 >> 42) * 5;
            h2 &= M42;
        }
        h1 += h0 >> 44;
        h0 &= M44;
        let mut g0 = h0 + 5;
        let mut g1 = h1 + (g0 >> 44);
        g0 &= M44;
        let g2 = (h2 + (g1 >> 44)).wrapping_sub(1 << 42);
        g1 &= M44;
        let keep_g = (g2 >> 63).wrapping_sub(1);
        h0 = (h0 & !keep_g) | (g0 & keep_g);
        h1 = (h1 & !keep_g) | (g1 & keep_g);
        h2 = (h2 & !keep_g) | (g2 & keep_g);
        let [p0, p1] = self.pad;
        let mut a0 = h0 + (p0 & M44);
        let mut a1 = h1 + (((p0 >> 44) | (p1 << 20)) & M44) + (a0 >> 44);
        a0 &= M44;
        let a2 = (h2 + ((p1 >> 24) & M42) + (a1 >> 44)) & M42;
        a1 &= M44;
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&(a0 | (a1 << 44)).to_le_bytes());
        t[8..].copy_from_slice(&((a1 >> 20) | (a2 << 24)).to_le_bytes());
        t
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
        let mut buf = pt.to_vec();
        let tag = seal_in_place(&key, &nonce, &ad, &mut buf).unwrap();
        assert_eq!([buf, tag.to_vec()].concat(), ct, "in place: the same ciphertext and tag");
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

    // spec: none (forensic test support): `authentic` is `open`'s verdict, at every length of
    // ad and message across block boundaries, for the sealing key and nonce and for others
    #[test]
    fn authentic_is_opens_verdict() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8 * 7 + 1);
        let nonce: [u8; NONCE_LEN] = std::array::from_fn(|i| i as u8 * 5 + 100);
        let mut other = nonce;
        other[23] ^= 1;
        for n in [0usize, 1, 15, 16, 17, 32, 33, 64, 100, 129] {
            for a in [0usize, 1, 16, 32, 37] {
                // all-0xff blocks push every limb's carry
                let pt: Vec<u8> = (0..n).map(|i| if n == 64 { 0xff } else { (i * 13 + n) as u8 }).collect();
                let ad: Vec<u8> = (0..a).map(|i| (i * 3 + a) as u8).collect();
                let ct = seal(&key, &nonce, &ad, &pt).unwrap();
                assert!(Keystream::new(&key, &nonce).authentic(&ad, &ct), "length {n}, ad {a}");
                assert!(!Keystream::new(&key, &other).authentic(&ad, &ct), "another nonce");
                assert!(!Keystream::new(&[9; 32], &nonce).authentic(&ad, &ct), "another key");
                for i in [0, ct.len() - 1] {
                    let mut bad = ct.clone();
                    bad[i] ^= 0x80;
                    assert!(!Keystream::new(&key, &nonce).authentic(&ad, &bad), "a flipped bit at {i}");
                }
            }
        }
        assert!(!Keystream::new(&key, &nonce).authentic(b"", &[0; TAG_LEN - 1]));
    }
}
