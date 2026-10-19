//! Blob encryption with Padmé padding, wraps and inbox blobs (spec/crypto.md §5, spec/wire.md §5,
//! §9). The clear prefix layout is osis-label's: this module takes its bytes.

use crate::aead::{self, TAG_LEN, WRAP_LEN, ZERO_NONCE};
use crate::kdf::{self, kdf};
use crate::{Error, KemPublicKey, KemSecret, SEALED_OVERHEAD, Secret32, open_sealed, seal};
use osis_core::format::MAX_BLOB;
use osis_core::{BlobId, Tid, Value, encode};
use rand_core::CryptoRngCore;

/// Padmé length for `l = len(P) + 1` (spec/wire.md §5).
pub fn padme(l: usize) -> usize {
    if l < 2 {
        return l;
    }
    let e = l.ilog2();
    let s = u32::BITS - e.leading_zeros();
    let m = (1usize << (e - s)) - 1;
    l.saturating_add(m) & !m
}

/// `P || 0x80 || zeros` up to `padme(len(P) + 1)`.
pub fn pad(p: &[u8]) -> Vec<u8> {
    let l = p.len().saturating_add(1);
    let mut out = Vec::with_capacity(padme(l));
    out.extend_from_slice(p);
    out.push(0x80);
    out.resize(padme(l), 0);
    out
}

/// Strips trailing zeros and the `0x80` marker; the padded length must be `padme`'s.
pub fn unpad(padded: &[u8]) -> Result<&[u8], Error> {
    let end = padded.iter().rposition(|&b| b != 0).ok_or(Error::BadPadding)?;
    let (p, marker) = padded.split_at_checked(end).ok_or(Error::BadPadding)?;
    if marker.first() != Some(&0x80) || padme(end + 1) != padded.len() {
        return Err(Error::BadPadding);
    }
    Ok(p)
}

/// Blob ID = BLAKE3 of the whole blob.
pub fn blob_id(blob: &[u8]) -> BlobId {
    BlobId(*blake3::hash(blob).as_bytes())
}

/// Encrypts `plaintext` under a fresh random key: `prefix || AEAD(key, nonce 0, AD prefix,
/// pad(plaintext))`. Returns the blob key and the blob; `TooLarge` above `MAX_BLOB`.
pub fn encrypt_blob(prefix: &[u8], plaintext: &[u8], rng: &mut dyn CryptoRngCore) -> Result<(Secret32, Vec<u8>), Error> {
    let total = prefix.len().saturating_add(padme(plaintext.len().saturating_add(1))).saturating_add(TAG_LEN);
    if total > MAX_BLOB {
        return Err(Error::TooLarge);
    }
    let key = Secret32::random(rng);
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(prefix);
    blob.extend_from_slice(&aead::seal(key.expose(), &ZERO_NONCE, prefix, &pad(plaintext))?);
    Ok((key, blob))
}

/// Decrypts a blob whose clear prefix is its first `prefix_len` bytes; returns the unpadded plaintext.
pub fn decrypt_blob(blob: &[u8], prefix_len: usize, key: &Secret32) -> Result<Vec<u8>, Error> {
    if blob.len() > MAX_BLOB {
        return Err(Error::Malformed("blob too large"));
    }
    let (prefix, ct) = blob.split_at_checked(prefix_len).ok_or(Error::Malformed("blob shorter than prefix"))?;
    let mut padded = aead::open(key.expose(), &ZERO_NONCE, prefix, ct)?;
    let len = unpad(&padded)?.len();
    padded.truncate(len);
    Ok(padded)
}

/// Wrap of a blob key under a label read secret: nonce = blob ID[..24], empty AD (spec/wire.md §5).
pub fn wrap(read_secret: &Secret32, blob: &BlobId, blob_key: &Secret32) -> [u8; WRAP_LEN] {
    aead::seal_suite_key(&kdf(kdf::WRAP, read_secret.expose(), b""), &wrap_nonce(blob), b"", blob_key)
}

/// Opens a wrap; a reader tries its read secrets newest first.
pub fn unwrap(read_secret: &Secret32, blob: &BlobId, wrap: &[u8]) -> Result<Secret32, Error> {
    aead::open_suite_key(&kdf(kdf::WRAP, read_secret.expose(), b""), &wrap_nonce(blob), b"", wrap)
}

/// 49 random bytes: the wrap of an inbox blob.
pub fn filler_wrap(rng: &mut dyn CryptoRngCore) -> [u8; WRAP_LEN] {
    let mut w = [0u8; WRAP_LEN];
    rng.fill_bytes(&mut w);
    w
}

fn wrap_nonce(blob: &BlobId) -> [u8; 24] {
    let mut n = [0u8; 24];
    n.copy_from_slice(blob.0.get(..24).unwrap_or(&[0; 24]));
    n
}

/// Inbox blob: `prefix || sealed box(pad(payload))` to the recipient's read KEM key, AD =
/// `[recipient, "inbox", prefix]` (spec/wire.md §9).
pub fn seal_inbox(prefix: &[u8], recipient: &Tid, kem: &KemPublicKey, payload: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let total = prefix.len().saturating_add(padme(payload.len().saturating_add(1))).saturating_add(SEALED_OVERHEAD);
    if total > MAX_BLOB {
        return Err(Error::TooLarge);
    }
    let mut blob = Vec::with_capacity(total);
    blob.extend_from_slice(prefix);
    blob.extend_from_slice(&seal(kem, &inbox_ad(recipient, prefix), &pad(payload), rng)?);
    Ok(blob)
}

pub fn open_inbox(blob: &[u8], prefix_len: usize, recipient: &Tid, kem: &KemSecret) -> Result<Vec<u8>, Error> {
    if blob.len() > MAX_BLOB {
        return Err(Error::Malformed("blob too large"));
    }
    let (prefix, sealed) = blob.split_at_checked(prefix_len).ok_or(Error::Malformed("blob shorter than prefix"))?;
    let padded = open_sealed(kem, &inbox_ad(recipient, prefix), sealed)?;
    Ok(unpad(&padded)?.to_vec())
}

fn inbox_ad(recipient: &Tid, prefix: &[u8]) -> Vec<u8> {
    encode(&Value::List(vec![Value::Bytes(recipient.as_bytes().to_vec()), Value::Str("inbox".into()), Value::Bytes(prefix.to_vec())]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeededRng;
    use proptest::prelude::*;

    // spec/wire.md §5: Padmé values (the test-infra padme/ list).
    #[test]
    fn padme_values() {
        let cases = [
            (1, 1), (2, 2), (4, 4), (8, 8), (9, 10), (15, 16), (17, 18), (100, 104), (255, 256), (257, 272), (1000, 1024),
            (4097, 4352), (65537, 67584), (131073, 135168), (1000000, 1015808),
        ];
        for (l, p) in cases {
            assert_eq!(padme(l), p, "padme({l})");
        }
    }

    // spec/wire.md §5: unpad rejections.
    #[test]
    fn unpad_rejections() {
        assert_eq!(unpad(&pad(b"abc")), Ok(&b"abc"[..]));
        assert_eq!(unpad(&pad(b"")), Ok(&b""[..]));
        assert_eq!(unpad(b""), Err(Error::BadPadding));
        assert_eq!(unpad(&[0, 0, 0, 0]), Err(Error::BadPadding)); // no marker
        assert_eq!(unpad(&[1, 2, 3, 4]), Err(Error::BadPadding)); // nonzero after the data, no marker
        assert_eq!(unpad(&[0x80, 0, 0, 1]), Err(Error::BadPadding)); // nonzero after the marker
        assert_eq!(unpad(&[1, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Error::BadPadding)); // not padme length
        let mut long = pad(&[7; 100]);
        long.push(0);
        assert_eq!(unpad(&long), Err(Error::BadPadding));
    }

    proptest! {
        // spec/wire.md §5: padding round-trips and lands on padme lengths; Padmé leaks at most
        // O(log log L) bits: the overhead is below 12% beyond the smallest sizes.
        #[test]
        fn pad_round_trip(p in proptest::collection::vec(any::<u8>(), 0..5000)) {
            let padded = pad(&p);
            prop_assert_eq!(padded.len(), padme(p.len() + 1));
            prop_assert_eq!(unpad(&padded), Ok(&p[..]));
            if p.len() >= 64 {
                prop_assert!(padded.len() - p.len() <= p.len() / 8 + 1);
            }
        }

        // spec/wire.md §5: bucket property: lengths in the same Padmé bucket pad identically,
        // and padme is monotone.
        #[test]
        fn padme_buckets(l in 1usize..10_000_000) {
            let p = padme(l);
            prop_assert!(p >= l);
            prop_assert_eq!(padme(p), p);
            prop_assert!(padme(l + 1) >= p);
        }

        // spec/crypto.md §5: no panic on malformed blobs.
        #[test]
        fn decrypt_never_panics(blob in proptest::collection::vec(any::<u8>(), 0..200), prefix_len in 0usize..250) {
            prop_assert!(decrypt_blob(&blob, prefix_len, &Secret32::from_bytes([1; 32])).is_err());
            let wr = unwrap(&Secret32::from_bytes([1; 32]), &BlobId([0; 32]), &blob);
            prop_assert!(wr.is_err());
        }
    }

    // spec/crypto.md §5: blob = prefix || ciphertext under a fresh key, AD the prefix; blob ID is
    // BLAKE3 of the whole; the prefix and every ciphertext byte are authenticated.
    #[test]
    fn blob_round_trip() {
        let mut rng = SeededRng::from_u64(3);
        let prefix = [1u8; 26];
        let (k1, b1) = encrypt_blob(&prefix, b"hello", &mut rng).unwrap();
        let (k2, b2) = encrypt_blob(&prefix, b"hello", &mut rng).unwrap();
        assert!(k1 != k2 && b1 != b2);
        assert_eq!(b1[..26], prefix);
        assert_eq!(b1.len(), 26 + padme(6) + TAG_LEN);
        assert_eq!(decrypt_blob(&b1, 26, &k1).unwrap(), b"hello");
        assert_eq!(blob_id(&b1).0, *blake3::hash(&b1).as_bytes());
        for i in [0, 25, 26, b1.len() - 1] {
            let mut t = b1.clone();
            t[i] ^= 1;
            assert_eq!(decrypt_blob(&t, 26, &k1), Err(Error::Decrypt));
        }
        assert_eq!(decrypt_blob(&b1, 25, &k1), Err(Error::Decrypt));
        assert_eq!(decrypt_blob(&b1, 26, &k2), Err(Error::Decrypt));
        let big = vec![0u8; MAX_BLOB];
        assert_eq!(encrypt_blob(&prefix, &big, &mut rng).err(), Some(Error::TooLarge));
    }

    // spec/crypto.md §5: wraps are deterministic, 49 bytes, bound to the blob ID and secret.
    #[test]
    fn wraps() {
        let (s, k, id) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]), BlobId([3; 32]));
        let w = wrap(&s, &id, &k);
        assert_eq!(w, wrap(&s, &id, &k));
        assert_eq!(unwrap(&s, &id, &w), Ok(k));
        assert_eq!(unwrap(&s, &BlobId([4; 32]), &w), Err(Error::Decrypt));
        assert_eq!(unwrap(&Secret32::from_bytes([5; 32]), &id, &w), Err(Error::Decrypt));
        let f = filler_wrap(&mut SeededRng::from_u64(1));
        assert!(unwrap(&s, &id, &f).is_err());
    }

    // spec/wire.md §9: inbox blob AD binds recipient and prefix.
    #[test]
    fn inbox() {
        let mut rng = SeededRng::from_u64(4);
        let kem = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let r = Tid::from_bytes([1; 15]);
        let b = seal_inbox(&[9; 26], &r, kem.public(), b"commit", &mut rng).unwrap();
        assert_eq!(open_inbox(&b, 26, &r, &kem).unwrap(), b"commit");
        assert_eq!(open_inbox(&b, 26, &Tid::from_bytes([2; 15]), &kem), Err(Error::Decrypt));
        let mut t = b.clone();
        t[3] ^= 1;
        assert_eq!(open_inbox(&t, 26, &r, &kem), Err(Error::Decrypt));
    }
}
