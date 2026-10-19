//! Blob framing: the clear prefix (spec/wire.md §5), encryption to a blob and back, blob IDs,
//! the prefix-versus-header agreement check (spec/commits.md §4) and label wraps (spec/crypto.md §5).

use crate::Error;
use osis_core::format::{BLOB_FRAMING_VERSION, MAX_BLOB, MAX_COMMITMENTS};
use osis_core::{BlobId, WallMs};
use osis_crypto::{CryptoRngCore, Secret32, commitment, decrypt_blob, delete_token, encrypt_blob, token_hash, verify_presented_token};

/// Bytes of a prefix before its commitments.
pub const PREFIX_FIXED_LEN: usize = 26;
/// Bytes of one commitment: level, then 16 bytes.
pub const COMMITMENT_LEN: usize = 17;

/// A token level (spec/wire.md §1): 1 admin secret, 2 author chain, 3 thing write secret.
pub type Level = u8;

/// The clear prefix of a blob: salt, optional expiry, commitments strictly ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    salt: [u8; 16],
    expiry: Option<WallMs>,
    commitments: Vec<[u8; COMMITMENT_LEN]>,
}

impl Prefix {
    /// Sorts the commitments; `Malformed` for a duplicate, a level outside 1..=3, more than
    /// `MAX_COMMITMENTS`, or an expiry of 0 (which means none on the wire).
    pub fn new(salt: [u8; 16], expiry: Option<WallMs>, mut commitments: Vec<[u8; COMMITMENT_LEN]>) -> Result<Prefix, Error> {
        commitments.sort();
        let p = Prefix { salt, expiry, commitments };
        p.validate()?;
        Ok(p)
    }

    /// Prefix of an encryption of a commit: commitments of the header's `(level, token hash)`
    /// pairs its deltas call for, under this prefix's salt (spec/crypto.md §7).
    pub fn for_tokens(salt: [u8; 16], expiry: Option<WallMs>, tokens: &[(Level, [u8; 16])]) -> Result<Prefix, Error> {
        let cs = tokens.iter().map(|(l, h)| commitment(*l, h, &salt)).collect::<Result<Vec<_>, _>>()?;
        Prefix::new(salt, expiry, cs)
    }

    /// Prefix of a chunk, tree node or page: chunk tokens `kdf("delete token", secret, salt)`
    /// per `(level, secret)`. Returns the prefix and the token hashes in input order (the header's
    /// chunk list carries them).
    pub fn for_chunk(salt: [u8; 16], expiry: Option<WallMs>, secrets: &[(Level, &Secret32)]) -> Result<(Prefix, Vec<[u8; 16]>), Error> {
        let hashes: Vec<[u8; 16]> = secrets.iter().map(|(_, s)| token_hash(delete_token(s, &salt).expose())).collect();
        let pairs: Vec<(Level, [u8; 16])> = secrets.iter().map(|(l, _)| *l).zip(hashes.iter().copied()).collect();
        Ok((Prefix::for_tokens(salt, expiry, &pairs)?, hashes))
    }

    /// A random salt.
    pub fn random_salt(rng: &mut dyn CryptoRngCore) -> [u8; 16] {
        let mut s = [0u8; 16];
        rng.fill_bytes(&mut s);
        s
    }

    fn validate(&self) -> Result<(), Error> {
        if self.commitments.len() > MAX_COMMITMENTS {
            return Err(Error::Malformed("more than MAX_COMMITMENTS"));
        }
        if self.commitments.iter().any(|c| !(1..=3).contains(&c[0])) {
            return Err(Error::Malformed("commitment level"));
        }
        if self.commitments.windows(2).any(|w| w.first() >= w.get(1)) {
            return Err(Error::Malformed("commitments not strictly ascending"));
        }
        if self.expiry == Some(WallMs(0)) {
            return Err(Error::Malformed("expiry 0"));
        }
        Ok(())
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
    pub fn expiry(&self) -> Option<WallMs> {
        self.expiry
    }
    pub fn commitments(&self) -> &[[u8; COMMITMENT_LEN]] {
        &self.commitments
    }

    /// Encoded length.
    pub fn len(&self) -> usize {
        PREFIX_FIXED_LEN + COMMITMENT_LEN * self.commitments.len()
    }

    /// Never empty; for clippy's `len` convention.
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.push(BLOB_FRAMING_VERSION);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.expiry.map_or(0, |t| t.0).to_le_bytes());
        // At most MAX_COMMITMENTS (16) by construction.
        out.push(u8::try_from(self.commitments.len()).unwrap_or(u8::MAX));
        for c in &self.commitments {
            out.extend_from_slice(c);
        }
        out
    }

    /// Parses the prefix at the start of `blob` (which may continue with ciphertext). An unknown
    /// framing version is `UnknownFraming` (parked: no expiry, no commitments).
    pub fn parse(blob: &[u8]) -> Result<Prefix, Error> {
        let (&version, rest) = blob.split_first().ok_or(Error::Malformed("empty blob"))?;
        if version != BLOB_FRAMING_VERSION {
            return Err(Error::UnknownFraming(version));
        }
        let fixed = rest.get(..PREFIX_FIXED_LEN - 1).ok_or(Error::Malformed("short prefix"))?;
        let (salt, rest) = fixed.split_at(16);
        let (expiry, n) = rest.split_at(8);
        let n = usize::from(*n.first().ok_or(Error::Malformed("short prefix"))?);
        if n > MAX_COMMITMENTS {
            return Err(Error::Malformed("more than MAX_COMMITMENTS"));
        }
        let body = blob.get(PREFIX_FIXED_LEN..PREFIX_FIXED_LEN + COMMITMENT_LEN * n).ok_or(Error::Malformed("short prefix"))?;
        let commitments: Vec<[u8; COMMITMENT_LEN]> = body.as_chunks::<COMMITMENT_LEN>().0.to_vec();
        let mut s = [0u8; 16];
        s.copy_from_slice(salt);
        let mut e = [0u8; 8];
        e.copy_from_slice(expiry);
        let t = u64::from_le_bytes(e);
        let p = Prefix { salt: s, expiry: (t != 0).then_some(WallMs(t)), commitments };
        p.validate()?;
        Ok(p)
    }

    /// Whether this prefix is what an encryption of a commit's deltas computes (spec/commits.md
    /// §4, spec/sync.md §1): the same expiry, and exactly the commitments of `tokens` under this
    /// salt. A mismatch makes the commit blob bad input.
    pub fn agrees(&self, expiry: Option<WallMs>, tokens: &[(Level, [u8; 16])]) -> bool {
        Prefix::for_tokens(self.salt, expiry, tokens).is_ok_and(|p| p == *self)
    }

    /// The level of the commitment a presented token matches, hashing twice with the salt
    /// (spec/crypto.md §7). The server then requires the signature that level calls for.
    pub fn match_token(&self, token: &[u8; 32]) -> Option<Level> {
        self.commitments.iter().find(|c| verify_presented_token(token, c, &self.salt)).map(|c| c[0])
    }
}

/// Server-side view of a blob: its prefix, or none for an unknown framing version (spec/wire.md
/// §5: stored and relayed as a blob with no expiry and no commitments). Checks `MAX_BLOB`.
pub fn server_prefix(blob: &[u8]) -> Result<Option<Prefix>, Error> {
    check_size(blob)?;
    match Prefix::parse(blob) {
        Ok(p) if blob.len() >= p.len() + MIN_CIPHERTEXT => Ok(Some(p)),
        Ok(_) => Err(Error::Malformed("blob shorter than prefix and tag")),
        Err(Error::UnknownFraming(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Smallest ciphertext: one padded byte plus the 16-byte tag.
const MIN_CIPHERTEXT: usize = 17;

/// `Malformed` above `MAX_BLOB` (spec/wire.md §13).
pub fn check_size(blob: &[u8]) -> Result<(), Error> {
    if blob.len() > MAX_BLOB {
        return Err(Error::Malformed("blob above MAX_BLOB"));
    }
    Ok(())
}

/// Encrypts `plaintext` behind `prefix` under a fresh key (spec/crypto.md §5). Returns the blob
/// key and the blob; `TooLarge` above `MAX_BLOB`.
pub fn frame(prefix: &Prefix, plaintext: &[u8], rng: &mut dyn CryptoRngCore) -> Result<(Secret32, Vec<u8>), Error> {
    encrypt_blob(&prefix.to_bytes(), plaintext, rng).map_err(|e| match e {
        osis_crypto::Error::TooLarge => Error::TooLarge("blob above MAX_BLOB"),
        e => Error::Crypto(e),
    })
}

/// Parses the prefix and decrypts; returns both.
pub fn open(blob: &[u8], key: &Secret32) -> Result<(Prefix, Vec<u8>), Error> {
    check_size(blob)?;
    let p = Prefix::parse(blob)?;
    let pt = decrypt_blob(blob, p.len(), key)?;
    Ok((p, pt))
}

/// Blob ID = BLAKE3 of the whole blob.
pub fn blob_id(blob: &[u8]) -> BlobId {
    osis_crypto::blob_id(blob)
}

/// Opens a wrap with the read secrets in the order given (newest first, spec/crypto.md §5).
/// Returns the index of the secret that opened it and the blob key; `None` if none does (a
/// filler, or an epoch not held).
pub fn unwrap_any<'a>(secrets: impl IntoIterator<Item = &'a Secret32>, blob: &BlobId, wrap: &[u8]) -> Option<(usize, Secret32)> {
    secrets.into_iter().enumerate().find_map(|(i, s)| osis_crypto::unwrap(s, blob, wrap).ok().map(|k| (i, k)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::SeededRng;
    use proptest::prelude::*;

    fn c(level: u8, b: u8) -> [u8; 17] {
        let mut x = [b; 17];
        x[0] = level;
        x
    }

    // spec/wire.md §5: prefix layout, offsets and round trip.
    #[test]
    fn layout() {
        let p = Prefix::new([7; 16], Some(WallMs(0x0102)), vec![c(2, 9), c(1, 5)]).unwrap();
        let b = p.to_bytes();
        assert_eq!(b.len(), 26 + 34);
        assert_eq!(b[0], 1);
        assert_eq!(b[1..17], [7; 16]);
        assert_eq!(b[17..25], [2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(b[25], 2);
        assert_eq!(b[26..43], c(1, 5));
        assert_eq!(Prefix::parse(&b).unwrap(), p);
        let none = Prefix::new([0; 16], None, vec![]).unwrap();
        assert_eq!(none.to_bytes()[17..26], [0; 9]);
        assert_eq!(Prefix::parse(&none.to_bytes()).unwrap().expiry(), None);
    }

    // spec/wire.md §5: rejections: unsorted or duplicate, level 0 or 4, more than 16, short,
    // unknown framing version.
    #[test]
    fn rejections() {
        let mut b = Prefix::new([0; 16], None, vec![c(1, 1), c(1, 2)]).unwrap().to_bytes();
        b.swap(26, 26 + 17);
        b.swap(27, 27 + 17);
        b[26..43].copy_from_slice(&c(1, 2));
        b[43..60].copy_from_slice(&c(1, 1));
        assert!(Prefix::parse(&b).is_err());
        b[43..60].copy_from_slice(&c(1, 2));
        assert!(Prefix::parse(&b).is_err());
        for level in [0, 4] {
            assert!(Prefix::new([0; 16], None, vec![c(level, 1)]).is_err());
        }
        let many: Vec<_> = (0..17).map(|i| c(1, i)).collect();
        assert!(Prefix::new([0; 16], None, many).is_err());
        let mut b = Prefix::new([0; 16], None, vec![]).unwrap().to_bytes();
        b[25] = 17;
        b.extend(std::iter::repeat_n(1, 17 * 17));
        assert_eq!(Prefix::parse(&b), Err(Error::Malformed("more than MAX_COMMITMENTS")));
        assert!(Prefix::parse(&b[..25]).is_err());
        let mut b = Prefix::new([0; 16], None, vec![c(1, 1)]).unwrap().to_bytes();
        b.pop();
        assert!(Prefix::parse(&b).is_err());
        b[0] = 2;
        assert_eq!(Prefix::parse(&b), Err(Error::UnknownFraming(2)));
        assert_eq!(server_prefix(&b), Ok(None));
        assert!(Prefix::new([0; 16], Some(WallMs(0)), vec![]).is_err());
    }

    // spec/crypto.md §5, spec/wire.md §5: a framed blob opens with its key; the prefix is
    // authenticated; blob ID is BLAKE3 of the whole; MAX_BLOB.
    #[test]
    fn frame_and_open() {
        let mut rng = SeededRng::from_u64(1);
        let p = Prefix::new(Prefix::random_salt(&mut rng), Some(WallMs(5)), vec![c(3, 3)]).unwrap();
        let (k, blob) = frame(&p, b"chunk", &mut rng).unwrap();
        assert_eq!(open(&blob, &k).unwrap(), (p.clone(), b"chunk".to_vec()));
        assert_eq!(blob_id(&blob).0, osis_core::hash::hash(&blob));
        assert_eq!(server_prefix(&blob), Ok(Some(p.clone())));
        let mut t = blob.clone();
        t[20] ^= 1;
        assert!(open(&t, &k).is_err());
        assert!(matches!(frame(&p, &vec![0; MAX_BLOB], &mut rng), Err(Error::TooLarge(_))));
        assert!(server_prefix(&vec![1; MAX_BLOB + 1]).is_err());
        assert!(server_prefix(&p.to_bytes()).is_err());
    }

    // spec/commits.md §4, spec/crypto.md §7: the prefix agrees with the header's tokens and
    // expiry only; a presented token matches its commitment and level.
    #[test]
    fn agreement_and_tokens() {
        let salt = [4u8; 16];
        let secret = Secret32::from_bytes([1; 32]);
        let tok = delete_token(&secret, &[9; 16]);
        let th = token_hash(tok.expose());
        let p = Prefix::for_tokens(salt, Some(WallMs(10)), &[(2, th)]).unwrap();
        assert!(p.agrees(Some(WallMs(10)), &[(2, th)]));
        assert!(!p.agrees(None, &[(2, th)]));
        assert!(!p.agrees(Some(WallMs(10)), &[(3, th)]));
        assert!(!p.agrees(Some(WallMs(10)), &[]));
        assert_eq!(p.match_token(tok.expose()), Some(2));
        assert_eq!(p.match_token(&[0; 32]), None);
        let (cp, hashes) = Prefix::for_chunk(salt, None, &[(1, &secret)]).unwrap();
        assert_eq!(hashes, vec![token_hash(delete_token(&secret, &salt).expose())]);
        assert_eq!(cp.match_token(delete_token(&secret, &salt).expose()), Some(1));
    }

    // spec/crypto.md §5: a reader tries its read secrets newest first; a filler opens under none.
    #[test]
    fn wraps() {
        let (old, new) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
        let (id, k) = (BlobId([3; 32]), Secret32::from_bytes([4; 32]));
        let w = osis_crypto::wrap(&old, &id, &k).unwrap();
        assert_eq!(unwrap_any([&new, &old], &id, &w), Some((1, k)));
        assert_eq!(unwrap_any([&new, &old], &id, &osis_crypto::filler_wrap(&mut SeededRng::from_u64(2))), None);
    }

    proptest! {
        // spec/wire.md §5: the parser never panics and accepts only what re-encodes to the same
        // bytes.
        #[test]
        fn parse_round_trip(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            if let Ok(p) = Prefix::parse(&b) {
                prop_assert_eq!(&p.to_bytes()[..], &b[..p.len()]);
            }
        }
    }
}
