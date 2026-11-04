//! Blob framing: the clear prefix (spec/wire.md §5), encryption to a blob and back, blob IDs,
//! the prefix-versus-header agreement check (spec/commits.md §4) and label wraps (spec/crypto.md §5).

use crate::Error;
use osis_base::format::{BLOB_FRAMING_VERSION, COMMITMENT_LEN, DELETE_ADMIN, DELETE_WRITER, MAX_BLOB, PREFIX_FIXED_LEN};
use osis_base::{BlobId, WallMs};
use osis_crypto::{CryptoRngCore, Secret32, VerifyingKey, commitment, decrypt_blob, encrypt_blob};

/// At most one commitment per level in a group.
const MAX_LEVELS: usize = 3;
/// Most groups a prefix lists: its le16 count (spec/wire.md §5).
pub const MAX_GROUPS: usize = u16::MAX as usize;

/// A delete level (spec/wire.md §1): 1 thing admin, 2 author chain, 3 thing write.
pub type Level = u8;

/// A blob's class (spec/wire.md §5, spec/sync.md §1): what a host does with it. Durable
/// blobs are stored; ephemeral ones are held in memory only; relay-only ones are pushed to the
/// label's current subscribers and held by nobody.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    #[default]
    Durable = 0,
    Ephemeral = 1,
    Relay = 2,
}

impl Class {
    pub fn from_byte(b: u8) -> Option<Class> {
        [Class::Durable, Class::Ephemeral, Class::Relay].into_iter().find(|c| *c as u8 == b)
    }

    /// The class of a commit blob carrying a header with this ephemeral marker.
    pub fn of_marker(m: Option<osis_commit::EphClass>) -> Class {
        match m {
            None => Class::Durable,
            Some(osis_commit::EphClass::Plain) => Class::Ephemeral,
            Some(osis_commit::EphClass::Relay) => Class::Relay,
        }
    }

    /// Held in memory as an entry.
    pub fn in_memory(self) -> bool {
        self == Class::Ephemeral
    }
}

/// One commitment group: the blinded delete keys of one delete-key set, strictly ascending
/// levels (spec/wire.md §5).
pub type Group = Vec<[u8; COMMITMENT_LEN]>;

/// The clear prefix of a blob: salt, optional expiry, class, commitment groups. A Delete needs
/// a delete-key signature per group, a Replace one from any group (spec/sync.md §5): an empty
/// group (a `nobody` delta's) blocks deletion by level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    salt: [u8; 16],
    expiry: Option<WallMs>,
    class: Class,
    groups: Vec<Group>,
}

impl Prefix {
    /// Sorts each group's commitments; `Malformed` for two at one level in a group, a level
    /// outside 1..=3, more than `MAX_GROUPS` groups, or an expiry of 0 (which means none on the
    /// wire).
    pub fn new(salt: [u8; 16], expiry: Option<WallMs>, mut groups: Vec<Group>) -> Result<Prefix, Error> {
        for g in &mut groups {
            g.sort();
        }
        let p = Prefix { salt, expiry, class: Class::Durable, groups };
        p.validate()?;
        Ok(p)
    }

    /// Prefix of a chunk, tree node or page serving deltas whose delete keys are `keys`: one
    /// group, one commitment per `(level, key)`, the key blinded by this prefix's salt and the
    /// header's blind `hb` (spec/crypto.md §7). A repeated pair gives one commitment.
    pub fn for_keys(salt: [u8; 16], hb: &[u8; 16], expiry: Option<WallMs>, keys: &[(Level, VerifyingKey)]) -> Result<Prefix, Error> {
        Prefix::for_groups(salt, hb, expiry, &[keys.to_vec()])
    }

    /// Prefix of a blob whose deltas' delete-key sets are `groups`, in their order.
    pub fn for_groups(salt: [u8; 16], hb: &[u8; 16], expiry: Option<WallMs>, groups: &[Vec<(Level, VerifyingKey)>]) -> Result<Prefix, Error> {
        let mut out = Vec::with_capacity(groups.len());
        for keys in groups {
            let mut ks = keys.to_vec();
            ks.sort_by_key(|(l, k)| (*l, k.to_bytes()));
            ks.dedup();
            out.push(ks.iter().map(|(l, k)| commitment(*l, k, &salt, hb)).collect::<Result<Vec<_>, _>>()?);
        }
        Prefix::new(salt, expiry, out)
    }

    /// `for_groups` of a commit's delete-key groups (`osis_commit::prefix_groups`).
    pub fn for_delete_keys(salt: [u8; 16], hb: &[u8; 16], expiry: Option<WallMs>, groups: &[Vec<osis_commit::DeleteKey>]) -> Result<Prefix, Error> {
        let groups = groups.iter().map(|g| g.iter().map(|k| Ok((k.level, k.verifying_key()?))).collect::<Result<Vec<_>, osis_commit::Error>>()).collect::<Result<Vec<_>, _>>()?;
        Prefix::for_groups(salt, hb, expiry, &groups)
    }

    /// A random salt.
    pub fn random_salt(rng: &mut dyn CryptoRngCore) -> [u8; 16] {
        let mut s = [0u8; 16];
        rng.fill_bytes(&mut s);
        s
    }

    fn validate(&self) -> Result<(), Error> {
        if self.groups.len() > MAX_GROUPS {
            return Err(Error::Malformed("more than MAX_GROUPS commitment groups"));
        }
        for g in &self.groups {
            if g.len() > MAX_LEVELS {
                return Err(Error::Malformed("more than 3 commitments in a group"));
            }
            if g.iter().any(|c| !(DELETE_ADMIN..=DELETE_WRITER).contains(&c[0])) {
                return Err(Error::Malformed("commitment level"));
            }
            if g.windows(2).any(|w| matches!(w, [a, b] if a[0] >= b[0])) {
                return Err(Error::Malformed("commitment levels not strictly ascending"));
            }
        }
        if self.expiry == Some(WallMs(0)) {
            return Err(Error::Malformed("expiry 0"));
        }
        Ok(())
    }

    /// This prefix with class `c`.
    pub fn with_class(mut self, c: Class) -> Prefix {
        self.class = c;
        self
    }

    pub fn class(&self) -> Class {
        self.class
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }
    pub fn expiry(&self) -> Option<WallMs> {
        self.expiry
    }
    /// The commitment groups in prefix order.
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }
    /// Every commitment of every group (a chunk, tree node or page has one group).
    pub fn commitments(&self) -> impl Iterator<Item = &[u8; COMMITMENT_LEN]> {
        self.groups.iter().flatten()
    }

    /// The blinded key group `gi` commits to at `level`, if any.
    pub fn key_at(&self, gi: usize, level: Level) -> Option<[u8; 32]> {
        self.groups.get(gi)?.iter().find(|c| c[0] == level).and_then(|c| c.get(1..)).and_then(|k| k.try_into().ok())
    }

    /// Encoded length.
    pub fn len(&self) -> usize {
        PREFIX_FIXED_LEN + self.groups.iter().map(|g| 1 + COMMITMENT_LEN * g.len()).sum::<usize>()
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
        out.push(self.class as u8);
        // at most MAX_GROUPS by construction
        out.extend_from_slice(&u16::try_from(self.groups.len()).unwrap_or(u16::MAX).to_le_bytes());
        for g in &self.groups {
            // at most 3 by construction
            out.push(u8::try_from(g.len()).unwrap_or(u8::MAX));
            for c in g {
                out.extend_from_slice(c);
            }
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
        let (expiry, rest) = rest.split_at(8);
        let class = rest.first().and_then(|b| Class::from_byte(*b)).ok_or(Error::Malformed("blob class"))?;
        let n = usize::from(u16::from_le_bytes([*rest.get(1).ok_or(Error::Malformed("short prefix"))?, *rest.get(2).ok_or(Error::Malformed("short prefix"))?]));
        let mut at = PREFIX_FIXED_LEN;
        let mut groups = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let m = usize::from(*blob.get(at).ok_or(Error::Malformed("short prefix"))?);
            if m > MAX_LEVELS {
                return Err(Error::Malformed("more than 3 commitments in a group"));
            }
            let body = blob.get(at + 1..at + 1 + COMMITMENT_LEN * m).ok_or(Error::Malformed("short prefix"))?;
            groups.push(body.as_chunks::<COMMITMENT_LEN>().0.to_vec());
            at += 1 + COMMITMENT_LEN * m;
        }
        let mut s = [0u8; 16];
        s.copy_from_slice(salt);
        let mut e = [0u8; 8];
        e.copy_from_slice(expiry);
        let t = u64::from_le_bytes(e);
        let p = Prefix { salt: s, expiry: (t != 0).then_some(WallMs(t)), class, groups };
        p.validate()?;
        Ok(p)
    }

    /// Whether this prefix is what an encryption of a commit's deltas computes (spec/commits.md
    /// §4, spec/sync.md §1): the same expiry, exactly the commitment groups of `groups` under
    /// this salt and the header's blind `hb`, and the class of the header's ephemeral marker. A
    /// mismatch makes the commit blob bad input.
    pub fn agrees(&self, expiry: Option<WallMs>, hb: &[u8; 16], groups: &[Vec<osis_commit::DeleteKey>], class: Class) -> bool {
        Prefix::for_delete_keys(self.salt, hb, expiry, groups).is_ok_and(|p| p.with_class(class) == *self)
    }
}

/// The bytes of a blob's prefix (what a host keeps to check delete signatures): the parsed
/// prefix, or the version byte alone for a framing version this build does not know.
pub fn prefix_bytes(blob: &[u8]) -> &[u8] {
    let n = match Prefix::parse(blob) {
        Ok(p) => p.len(),
        Err(_) => 1,
    };
    blob.get(..n).unwrap_or(blob)
}

/// A host's view of a blob: its prefix, or none for an unknown framing version (spec/wire.md
/// §5: stored and relayed as a blob with no expiry and no commitments). Checks `MAX_BLOB`.
pub fn host_prefix(blob: &[u8]) -> Result<Option<Prefix>, Error> {
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

/// The fetch order of a wrap that opens (spec/crypto.md §5), else `None`.
pub fn wrap_order<'a>(secrets: impl IntoIterator<Item = &'a Secret32>, blob: &BlobId, wrap: &[u8]) -> Option<u64> {
    secrets.into_iter().find_map(|s| osis_crypto::unwrap_order(s, blob, wrap).ok().map(|x| x.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_crypto::SeededRng;
    use proptest::prelude::*;

    fn c(level: u8, b: u8) -> [u8; 33] {
        let mut x = [b; 33];
        x[0] = level;
        x
    }

    // spec/wire.md §5: prefix layout, offsets and round trip: le16 group count, per group a
    // count byte and its commitments.
    #[test]
    fn layout() {
        let p = Prefix::new([7; 16], Some(WallMs(0x0102)), vec![vec![c(2, 9), c(1, 5)], vec![], vec![c(3, 4)]]).unwrap();
        let b = p.to_bytes();
        assert_eq!(b.len(), 28 + (1 + 66) + 1 + (1 + 33));
        assert_eq!(b[0], 1);
        assert_eq!(b[1..17], [7; 16]);
        assert_eq!(b[17..25], [2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(b[25], 0);
        assert_eq!(b[26..28], [3, 0]);
        assert_eq!(b[28], 2);
        assert_eq!(b[29..62], c(1, 5));
        assert_eq!(b[62..95], c(2, 9));
        assert_eq!(b[95], 0);
        assert_eq!(b[96], 1);
        assert_eq!(b[97..130], c(3, 4));
        assert_eq!(Prefix::parse(&b).unwrap(), p);
        assert_eq!(p.key_at(0, 2), Some([9; 32]));
        assert_eq!(p.key_at(0, 3), None);
        assert_eq!(p.key_at(1, 2), None);
        assert_eq!(p.key_at(2, 3), Some([4; 32]));
        assert_eq!(p.key_at(3, 3), None);
        assert_eq!(p.commitments().count(), 3);
        let none = Prefix::new([0; 16], None, vec![]).unwrap();
        assert_eq!(none.to_bytes()[17..28], [0; 11]);
        assert_eq!(Prefix::parse(&none.to_bytes()).unwrap().expiry(), None);
        for c in [Class::Ephemeral, Class::Relay] {
            let e = none.clone().with_class(c);
            assert_eq!(e.to_bytes()[25], c as u8);
            assert_eq!(Prefix::parse(&e.to_bytes()).unwrap().class(), c);
        }
        let mut bad = none.to_bytes();
        bad[25] = 3;
        assert_eq!(Prefix::parse(&bad), Err(Error::Malformed("blob class")));
        // many groups: the count is le16
        let many = Prefix::new([0; 16], None, vec![vec![c(2, 1)]; 300]).unwrap();
        assert_eq!(many.to_bytes()[26..28], [44, 1]);
        assert_eq!(Prefix::parse(&many.to_bytes()).unwrap(), many);
        assert_eq!(prefix_bytes(&many.to_bytes()), &many.to_bytes()[..]);
        assert_eq!(prefix_bytes(&[9, 1, 2]), &[9]);
    }

    // spec/wire.md §5: rejections: two at one level in a group, unsorted, level 0 or 4, more
    // than 3 in a group, short, unknown framing version.
    #[test]
    fn rejections() {
        assert!(Prefix::new([0; 16], None, vec![vec![c(1, 1), c(1, 2)]]).is_err());
        let mut b = Prefix::new([0; 16], None, vec![vec![c(1, 1), c(2, 2)]]).unwrap().to_bytes();
        b[29..62].copy_from_slice(&c(2, 2));
        b[62..95].copy_from_slice(&c(1, 1));
        assert!(Prefix::parse(&b).is_err());
        b[29..62].copy_from_slice(&c(1, 2));
        assert!(Prefix::parse(&b).is_err(), "two at level 1");
        b[62..95].copy_from_slice(&c(3, 1));
        assert!(Prefix::parse(&b).is_ok());
        for level in [0, 4] {
            assert!(Prefix::new([0; 16], None, vec![vec![c(level, 1)]]).is_err());
        }
        let mut b = Prefix::new([0; 16], None, vec![vec![]]).unwrap().to_bytes();
        b[28] = 4;
        b.extend(std::iter::repeat_n(1, 33 * 4));
        assert_eq!(Prefix::parse(&b), Err(Error::Malformed("more than 3 commitments in a group")));
        assert!(Prefix::parse(&b[..27]).is_err());
        let mut b = Prefix::new([0; 16], None, vec![vec![c(1, 1)]]).unwrap().to_bytes();
        b.pop();
        assert!(Prefix::parse(&b).is_err());
        b[0] = 2;
        assert_eq!(Prefix::parse(&b), Err(Error::UnknownFraming(2)));
        assert_eq!(host_prefix(&b), Ok(None));
        assert!(Prefix::new([0; 16], Some(WallMs(0)), vec![]).is_err());
        // a group count past the bytes
        let mut b = Prefix::new([0; 16], None, vec![]).unwrap().to_bytes();
        b[26] = 5;
        assert!(Prefix::parse(&b).is_err());
    }

    // spec/crypto.md §5, spec/wire.md §5: a framed blob opens with its key; the prefix is
    // authenticated; blob ID is BLAKE3 of the whole; MAX_BLOB.
    #[test]
    fn frame_and_open() {
        let mut rng = SeededRng::from_u64(1);
        let p = Prefix::new(Prefix::random_salt(&mut rng), Some(WallMs(5)), vec![vec![c(3, 3)]]).unwrap();
        let (k, blob) = frame(&p, b"chunk", &mut rng).unwrap();
        assert_eq!(open(&blob, &k).unwrap(), (p.clone(), b"chunk".to_vec()));
        assert_eq!(blob_id(&blob).0, osis_base::hash::hash(&blob));
        assert_eq!(host_prefix(&blob), Ok(Some(p.clone())));
        let mut t = blob.clone();
        t[20] ^= 1;
        assert!(open(&t, &k).is_err());
        assert!(matches!(frame(&p, &vec![0; MAX_BLOB], &mut rng), Err(Error::TooLarge(_))));
        assert!(host_prefix(&vec![1; MAX_BLOB + 1]).is_err());
        assert!(host_prefix(&p.to_bytes()).is_err());
    }

    // spec/commits.md §4, spec/crypto.md §7: the prefix agrees with the header's delete keys and
    // expiry only; it commits to each key blinded by its salt.
    #[test]
    fn agreement() {
        let salt = [4u8; 16];
        let k = osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([1; 32])).verifying_key();
        let k3 = osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([2; 32])).verifying_key();
        let hb = [6u8; 16];
        let dk = |l, k: &VerifyingKey| osis_commit::DeleteKey::new(l, k);
        let p = Prefix::for_keys(salt, &hb, Some(WallMs(10)), &[(2, k)]).unwrap();
        let g = |ks: &[osis_commit::DeleteKey]| vec![ks.to_vec()];
        assert!(p.agrees(Some(WallMs(10)), &hb, &g(&[dk(2, &k)]), Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &hb, &g(&[dk(2, &k)]), Class::Ephemeral));
        assert!(!p.agrees(None, &hb, &g(&[dk(2, &k)]), Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &hb, &g(&[dk(3, &k)]), Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &hb, &g(&[dk(2, &k3)]), Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &[7; 16], &g(&[dk(2, &k)]), Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &hb, &[], Class::Durable));
        assert!(!p.agrees(Some(WallMs(10)), &hb, &[vec![]], Class::Durable));
        // the same keys in two groups is another prefix (a Delete then needs both signed)
        assert!(!p.agrees(Some(WallMs(10)), &hb, &[vec![dk(2, &k)], vec![dk(2, &k)]], Class::Durable));
        assert_eq!(p.key_at(0, 2), Some(osis_crypto::blind(&k, &salt, &hb).to_bytes()));
        // Repeated pairs on either side give one commitment; two keys at one level are refused.
        assert_eq!(Prefix::for_keys(salt, &hb, Some(WallMs(10)), &[(2, k), (2, k)]).unwrap(), p);
        assert!(Prefix::for_keys(salt, &hb, None, &[(2, k), (2, k3)]).is_err());
        // another salt or header blind, another blinded key
        assert_ne!(Prefix::for_keys([5; 16], &hb, None, &[(2, k)]).unwrap().key_at(0, 2), p.key_at(0, 2));
        assert_ne!(Prefix::for_keys(salt, &[8; 16], None, &[(2, k)]).unwrap().key_at(0, 2), p.key_at(0, 2));
        // a commit's delete keys give the same prefix; a delete signature under that salt and
        // blind verifies under the committed key
        let d = osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([1; 32]));
        assert_eq!(Prefix::for_delete_keys(salt, &hb, Some(WallMs(10)), &g(&[dk(2, &k)])).unwrap(), p);
        assert!(Prefix::for_delete_keys(salt, &hb, None, &g(&[dk(2, &k), dk(2, &k3)])).is_err());
        let key = p.key_at(0, 2).unwrap();
        osis_crypto::verify_delete(&key, &[4; 32], &d.sign(&salt, &hb, &[4; 32])).unwrap();
        assert!(osis_crypto::verify_delete(&key, &[4; 32], &d.sign(&[3; 16], &hb, &[4; 32])).is_err());
        assert!(osis_crypto::verify_delete(&key, &[4; 32], &d.sign(&salt, &[1; 16], &[4; 32])).is_err());
    }

    // spec/wire.md §5, spec/crypto.md §7: a prefix is the commitments of the distinct keys sorted,
    // whatever their order or repeats; two keys at one level, a level outside 1..=3, an expiry
    // of 0 or a key off the curve fail; `agrees` holds exactly for the prefix's own inputs.
    #[test]
    fn for_delete_keys_differential() {
        use osis_commit::DeleteKey;
        use osis_crypto::RngCore;
        let reference = |salt: [u8; 16], hb: &[u8; 16], expiry: Option<WallMs>, groups: &[Vec<DeleteKey>]| -> Option<Prefix> {
            let mut out = Vec::new();
            for keys in groups {
                let mut cs = Vec::new();
                for k in keys {
                    cs.push(commitment(k.level, &VerifyingKey::from_bytes(&k.key).ok()?, &salt, hb).ok()?);
                }
                cs.sort_unstable();
                cs.dedup();
                if cs.windows(2).any(|w| w[0][0] == w[1][0]) {
                    return None;
                }
                out.push(cs);
            }
            if expiry == Some(WallMs(0)) {
                return None;
            }
            Some(Prefix { salt, expiry, class: Class::Durable, groups: out })
        };
        let pool: Vec<VerifyingKey> = (1..=3u8).map(|i| osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([i; 32])).verifying_key()).collect();
        let off_curve = (0..=255u8).map(|b| [b; 32]).find(|b| VerifyingKey::from_bytes(b).is_err()).unwrap();
        let mut rng = osis_crypto::SeededRng::from_u64(77);
        for _ in 0..2000 {
            let r = |rng: &mut osis_crypto::SeededRng, n: u32| (rng.next_u32() % n) as u8;
            let n = r(&mut rng, 6);
            let keys: Vec<DeleteKey> = (0..n)
                .map(|_| {
                    let level = r(&mut rng, 5);
                    match r(&mut rng, 20) {
                        0 => DeleteKey { level, key: off_curve },
                        i => DeleteKey::new(level, &pool[usize::from(i) % 3]),
                    }
                })
                .collect();
            let expiry = match r(&mut rng, 4) {
                0 => None,
                1 => Some(WallMs(0)),
                _ => Some(WallMs(u64::from(rng.next_u32()))),
            };
            let (salt, hb) = ([r(&mut rng, 3); 16], [r(&mut rng, 3); 16]);
            // one to three groups, the first the keys above, the others drawn from the pool
            let mut groups = vec![keys.clone()];
            for _ in 0..r(&mut rng, 3) {
                groups.push((0..r(&mut rng, 3)).map(|_| DeleteKey::new(r(&mut rng, 3) + 1, &pool[usize::from(r(&mut rng, 3))])).collect());
            }
            let got = Prefix::for_delete_keys(salt, &hb, expiry, &groups).ok();
            assert_eq!(got, reference(salt, &hb, expiry, &groups), "{groups:?} {expiry:?}");
            let Some(p) = got else { continue };
            assert_eq!(Prefix::parse(&p.to_bytes()).unwrap(), p);
            assert_eq!(p.groups().len(), groups.len());
            let mut rev = groups.clone();
            for g in &mut rev {
                g.reverse();
            }
            assert!(p.agrees(expiry, &hb, &rev, Class::Durable));
            assert!(!p.agrees(expiry, &[hb[0] ^ 1; 16], &groups, Class::Durable) || groups.iter().all(Vec::is_empty));
            assert!(!p.agrees(expiry.map(|t| WallMs(t.0 + 1)).or(Some(WallMs(1))), &hb, &groups, Class::Durable));
            let mut more = groups.clone();
            more[0].push(DeleteKey::new(r(&mut rng, 3) + 1, &pool[0]));
            assert_eq!(p.agrees(expiry, &hb, &more, Class::Durable), reference(salt, &hb, expiry, &more).as_ref() == Some(&p));
            // groups in another order are another prefix unless alike
            if groups.len() > 1 {
                let mut swapped = groups.clone();
                swapped.swap(0, 1);
                assert_eq!(p.agrees(expiry, &hb, &swapped, Class::Durable), reference(salt, &hb, expiry, &swapped).as_ref() == Some(&p));
            }
        }
    }

    // spec/crypto.md §5: a reader tries its read secrets newest first; a filler opens under none.
    #[test]
    fn wraps() {
        let (old, new) = (Secret32::from_bytes([1; 32]), Secret32::from_bytes([2; 32]));
        let (id, k) = (BlobId([3; 32]), Secret32::from_bytes([4; 32]));
        let w = osis_crypto::wrap(&old, &id, &k, 1).unwrap();
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
