//! Stated paths (spec/wire.md §4 `Path`, `Paths`, `Split`; spec/permissions.md §1): what a commit
//! is judged along on each thing it writes: one path in the clear where every thing's own path is
//! read off it, else the split form, one purge author in the clear and each thing's path sealed
//! under that thing's path key (spec/crypto.md §5 Path entry).

use crate::Error;
use crate::cbor::item;
use osis_base::cbor::{Item, head_len, put_array, put_bytes, put_uint};
use osis_base::format::{MAX_PATH_THINGS, TID_LEN};
use osis_base::Tid;
use osis_crypto::Secret32;
use std::collections::BTreeSet;

/// One stated path `[i, A1, …, Ak, marks?]`: the purge-author index `purge` (0 names the signer, j
/// the listed thing Aj, spec/permissions.md §6), the listed things in order, and the hops it marks
/// direct (`direct`: bit j marks hop j, joining members j and j + 1; spec/permissions.md §1
/// Path, Direct mark). The empty path naming the signer is `Path::default()`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Path {
    pub purge: usize,
    pub things: Vec<Tid>,
    pub direct: Marks,
}

/// Hops marked direct, bit j for hop j (spec/wire.md §4 `marks`).
pub type Marks = osis_base::format::PathMarks;

/// The canonical `marks` bytes: bit j in byte j div 8, least significant first, no trailing zero
/// byte; empty for none (then absent from the encoding).
pub fn marks_bytes(m: Marks) -> Vec<u8> {
    let mut b = m.to_le_bytes().to_vec();
    while b.last() == Some(&0) {
        b.pop();
    }
    b
}

/// Reads `marks` bytes: 1 to 9 bytes, the last nonzero, no bit above `k` (spec/wire.md §4).
fn read_marks(b: &[u8], k: usize) -> Option<Marks> {
    if b.is_empty() || b.len() > MARKS_MAX || b.last() == Some(&0) {
        return None;
    }
    let m = b.iter().rev().fold(0, |m: Marks, x| (m << 8) | Marks::from(*x));
    (!past(m, k)).then_some(m)
}

/// Whether `m` marks a hop past the `k` + 1 hops of a path listing `k` things (any `k`: a decoder
/// meets lists longer than `MAX_PATH_THINGS` before checking their length).
fn past(m: Marks, k: usize) -> bool {
    u32::try_from(k + 1).ok().and_then(|s| m.checked_shr(s)).unwrap_or(0) != 0
}

/// Bytes of the longest `marks`: `MAX_PATH_THINGS` + 1 hops.
const MARKS_MAX: usize = (MAX_PATH_THINGS + 1).div_ceil(8);

/// An array: `before` (a `Path`'s index), the things listed, then `marks`
/// where any hop is marked: a `Path`, and a split entry's plaintext (no index).
fn put_listed(out: &mut Vec<u8>, before: Option<u64>, things: &[Tid], m: Marks) {
    let mb = marks_bytes(m);
    put_array(out, usize::from(before.is_some()) + things.len() + usize::from(!mb.is_empty()));
    before.iter().for_each(|i| put_uint(out, *i));
    things.iter().for_each(|t| put_bytes(out, t.as_bytes()));
    if !mb.is_empty() {
        put_bytes(out, &mb);
    }
}

/// Reads listed things and an optional trailing `marks` (a byte string of other than a tid's
/// length) from `items`, against the count of things.
fn read_listed(items: &[Item]) -> Result<(Vec<Tid>, Marks), Error> {
    let (things, m) = match items.split_last() {
        Some((last, rest)) if last.as_bytes().is_some_and(|b| b.len() != TID_LEN) => (rest, last.as_bytes()),
        _ => (items, None),
    };
    let things = things.iter().map(|v| item::tid(*v)).collect::<Result<Vec<Tid>, Error>>()?;
    let direct = match m {
        Some(b) => read_marks(b, things.len()).ok_or(Error::Malformed("path marks not canonical or past its hops"))?,
        None => 0,
    };
    Ok((things, direct))
}

impl Path {
    /// The path of one listed thing `x`, naming it as purge author.
    pub fn through(x: Tid) -> Path {
        Path { purge: 1, things: vec![x], direct: 0 }
    }

    /// The purge author it names, `signer` for index 0.
    pub fn purge_author(&self, signer: Tid) -> Tid {
        self.purge.checked_sub(1).and_then(|j| self.things.get(j)).copied().unwrap_or(signer)
    }

    /// The things between the signer and `t` along which it writes `t` (spec/permissions.md §1
    /// Path): the listed things, less the last where that is `t` (the end, written along the path
    /// ending there); every other thing is written one hop past the end.
    pub fn to(&self, t: &Tid) -> &[Tid] {
        match self.things.split_last() {
            Some((last, rest)) if last == t => rest,
            _ => &self.things,
        }
    }

    /// The one path off which every `(thing, own path)` of `each` is read (`to` of each thing
    /// equal to its own path's), its index naming `author`; `None` where they are no one path
    /// (the split form) or `author` is not on it. Of the paths that serve, the one listing a
    /// written thing last where that is the end of every other thing's path, or the first thing's
    /// own as stated.
    pub fn one_of<'a>(each: impl IntoIterator<Item = (&'a Tid, &'a Path)> + Clone, signer: Tid, author: Tid) -> Option<Path> {
        let (t0, p0) = each.clone().into_iter().next()?;
        // the first thing is the end, or one hop past it
        let below = p0.to(t0).to_vec();
        let ended: Vec<Tid> = below.iter().copied().chain([*t0]).collect();
        [p0.things.clone(), below, ended].into_iter().find_map(|things| {
            let q = Path { purge: 0, things, direct: p0.direct };
            if !each.clone().into_iter().all(|(t, p)| q.to(t) == p.to(t) && q.direct == p.direct) {
                return None;
            }
            let purge = if author == signer { 0 } else { 1 + q.things.iter().position(|x| *x == author)? };
            Some(Path { purge, ..q })
        })
    }

    /// Canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 16 * self.things.len());
        self.put(&mut out);
        out
    }

    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        put_listed(out, Some(self.purge as u64), &self.things, self.direct);
    }

    /// Reads a `Path` of a commit signed by `signer`: i ≤ k, k ≤ `MAX_PATH_THINGS`, no tid twice
    /// and none equal to `signer` (spec/wire.md §4), else malformed.
    pub(crate) fn read(v: Item, signer: &Tid) -> Result<Path, Error> {
        let l: Vec<Item> = item::list(v)?.iter().collect();
        let (first, rest) = l.split_first().ok_or(Error::Malformed("empty path"))?;
        let purge = item::idx(*first)?;
        let (things, direct) = read_listed(rest)?;
        let p = Path { purge, things, direct };
        p.check(signer)?;
        Ok(p)
    }

    /// The decoder's rules on a path of a commit signed by `signer` (spec/wire.md §4).
    pub(crate) fn check(&self, signer: &Tid) -> Result<(), Error> {
        if self.purge > self.things.len() {
            return Err(Error::Malformed("purge-author index out of range"));
        }
        if past(self.direct, self.things.len()) {
            return Err(Error::Malformed("path marks a hop past its own"));
        }
        listed_ok(&self.things, signer).then_some(()).ok_or(Error::Malformed("path longer than MAX_PATH_THINGS, or listing a thing twice or its signer"))
    }
}

/// `Path`'s rules on listed things: at most `MAX_PATH_THINGS`, no tid twice, none the signer.
fn listed_ok(things: &[Tid], signer: &Tid) -> bool {
    let mut seen = BTreeSet::new();
    things.len() <= MAX_PATH_THINGS && things.iter().all(|t| t != signer && seen.insert(*t))
}

// For Tess 3 (notes/path-form.md): what a split entry's size shows of the count of things its path
// lists. Padding to these classes shows only the class; `[MAX_PATH_THINGS]` alone hides the count
// at about 1 KiB a thing; no padding shows it exactly.
/// The listed-thing counts a split entry's plaintext is padded to: the smallest at or above its
/// count (spec/wire.md §4 `Split`).
pub const ENTRY_CLASSES: [usize; 3] = [4, 16, MAX_PATH_THINGS];

/// Bytes of the canonical `[tid*, marks]` of `k` things with every one of its `k` + 1 hops
/// marked: a class's padded plaintext (spec/wire.md §4 `Split`).
fn listed_len(k: usize) -> usize {
    let m = (k + 1).div_ceil(8);
    head_len(k as u64 + 1) + k * (1 + TID_LEN) + head_len(m as u64) + m
}

/// Bytes of an entry's commitment to its path key (`key_commitment`).
pub const COMMITMENT_LEN: usize = 32;

/// Bytes of a sealed entry of a path listing `k` things: the key commitment, its class's padded
/// plaintext and the tag; `None` past `MAX_PATH_THINGS`.
pub fn entry_len(k: usize) -> Option<usize> {
    ENTRY_CLASSES.iter().find(|c| **c >= k).map(|c| COMMITMENT_LEN + listed_len(*c) + osis_crypto::aead::TAG_LEN)
}

/// An entry's commitment to its path key (spec/crypto.md §5 Path entry): `kdf("path commit", key,
/// "")`, 32 bytes, so a writer choosing both keys needs a BLAKE3 collision to make one entry
/// accept two (128-bit security).
pub fn key_commitment(key: &[u8; 32]) -> [u8; COMMITMENT_LEN] {
    *osis_crypto::kdf::kdf(osis_crypto::kdf::PATH_COMMIT, key, b"").expose()
}

/// A header's `path` (spec/wire.md §4 `Paths`): one `Path` off which every thing's own path is
/// read, or the split form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Paths {
    One(Path),
    Split(Split),
}

impl Default for Paths {
    fn default() -> Paths {
        Paths::One(Path::default())
    }
}

/// The split form `[Opt(tid), [bytes+]]` (spec/wire.md §4): the purge author (`None`: the
/// signer), then one sealed entry per thing written, in the order of the things (`Header::things`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Split {
    pub author: Option<Tid>,
    pub entries: Vec<Vec<u8>>,
}

/// A thing's path key (spec/crypto.md §5 Path entry): `kdf("path", roles, blind ‖ tid)`, `roles`
/// the read roles secret of the thing's independent at the epoch its section is sealed under.
pub fn path_key(roles: &Secret32, blind: &[u8; 16], t: &Tid) -> [u8; 32] {
    let mut input = Vec::with_capacity(16 + TID_LEN);
    input.extend_from_slice(blind);
    input.extend_from_slice(t.as_bytes());
    *osis_crypto::kdf::kdf(osis_crypto::kdf::PATH, roles.expose(), &input).expose()
}

impl Split {
    /// Thing `t`'s entry: the commitment to its path key, then its listed things, canonical,
    /// zero-padded to their class, sealed under that key, nonce zero, empty AD (one plaintext per
    /// key: the blind is fresh per commit).
    pub fn seal(key: &[u8; 32], listed: &[Tid], direct: Marks) -> Result<Vec<u8>, Error> {
        let len = entry_len(listed.len()).ok_or(Error::Build("path longer than MAX_PATH_THINGS"))? - COMMITMENT_LEN - osis_crypto::aead::TAG_LEN;
        if past(direct, listed.len()) {
            return Err(Error::Build("path marks a hop past its own"));
        }
        let mut pt = Vec::with_capacity(len);
        put_listed(&mut pt, None, listed, direct);
        pt.resize(len, 0);
        let mut out = key_commitment(key).to_vec();
        out.extend(osis_crypto::aead::seal(key, &osis_crypto::aead::ZERO_NONCE, &[], &pt)?);
        Ok(out)
    }

    /// Opens `entry` under `key`: `None` where the entry does not commit to `key` (it is no key of
    /// this entry); else the things it lists and the hops it marks, `None` inside where the
    /// committed key does not open it or the plaintext is no canonical `[tid*, marks?]` padded
    /// with zeros to its class.
    ///
    /// Invariant (spec/crypto.md §5 Path entry): every key an entry accepts is the one it commits
    /// to (up to a BLAKE3 collision), and XChaCha20-Poly1305 under one key opens one ciphertext
    /// to one plaintext, so every reader reading a thing's path reads the same one, whichever
    /// route its key came by (an encryption of the thing's parts, a copy, a header-only copy, a
    /// roles secret) and in whatever order: a reading is a function of the commit.
    pub fn open(key: &[u8; 32], entry: &[u8]) -> Option<Option<(Vec<Tid>, Marks)>> {
        let (commitment, sealed) = entry.split_at_checked(COMMITMENT_LEN)?;
        if *commitment != key_commitment(key) {
            return None;
        }
        let Ok(pt) = osis_crypto::aead::open(key, &osis_crypto::aead::ZERO_NONCE, &[], sealed) else { return Some(None) };
        let Ok(head) = osis_base::cbor::item_prefix(&pt, &crate::header::LIMITS) else { return Some(None) };
        let listed = Item::parse(head, &crate::header::LIMITS).ok().and_then(|v| item::list(v).ok()).and_then(|l| read_listed(&l.iter().collect::<Vec<_>>()).ok());
        let padded = listed.as_ref().is_some_and(|(l, _)| entry_len(l.len()) == Some(entry.len()) && pt.get(head.len()..).is_some_and(|r| r.iter().all(|b| *b == 0)));
        Some(listed.filter(|_| padded))
    }

    fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 2);
        put_array(out, usize::from(self.author.is_some()));
        self.author.iter().for_each(|a| put_bytes(out, a.as_bytes()));
        put_array(out, self.entries.len());
        self.entries.iter().for_each(|e| put_bytes(out, e));
    }

    fn read(v: Item, signer: &Tid) -> Result<Split, Error> {
        let Some([a, es]) = item::list(v)?.tuple() else { return Err(Error::Malformed("split path arity")) };
        let author = item::opt(a)?.map(item::tid).transpose()?;
        if author == Some(*signer) {
            return Err(Error::Malformed("split path naming its signer as purge author"));
        }
        let entries = item::list(es)?.iter().map(|e| e.as_bytes().map(<[u8]>::to_vec).ok_or(Error::Malformed("split path entry"))).collect::<Result<Vec<_>, _>>()?;
        if entries.len() < 2 {
            return Err(Error::Malformed("split path of fewer than two things"));
        }
        entries_ok(&entries)?;
        Ok(Split { author, entries })
    }
}

/// The rules on a `Split`'s sealed entries: each of a padded length, and
/// one key per entry and one entry per key (two entries under one key would share its zero
/// nonce).
pub(crate) fn entries_ok(entries: &[Vec<u8>]) -> Result<(), Error> {
    if entries.iter().any(|e| !ENTRY_CLASSES.iter().any(|c| entry_len(*c) == Some(e.len()))) {
        return Err(Error::Malformed("path entry of no padded length"));
    }
    let mut seen = BTreeSet::new();
    if !entries.iter().all(|e| seen.insert(e.get(..COMMITMENT_LEN))) {
        return Err(Error::Malformed("path entries committing to one key"));
    }
    Ok(())
}

impl Paths {
    /// Its one purge author (spec/permissions.md §6), `signer` where it names none.
    pub fn purge_author(&self, signer: Tid) -> Tid {
        match self {
            Paths::One(p) => p.purge_author(signer),
            Paths::Split(s) => s.author.unwrap_or(signer),
        }
    }

    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        match self {
            Paths::One(p) => p.put(out),
            Paths::Split(s) => s.put(out),
        }
    }

    /// Reads a header's `path`: a `Path` (its first item a uint) or a `Split`.
    pub(crate) fn read(v: Item, signer: &Tid) -> Result<Paths, Error> {
        match item::list(v)?.first() {
            Some(first) if first.as_uint().is_some() => Ok(Paths::One(Path::read(v, signer)?)),
            _ => Ok(Paths::Split(Split::read(v, signer)?)),
        }
    }
}

/// What a node knows of the path a split commit states for one thing (`Header::open_path`).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ThingPath {
    /// Its path, the purge author's index naming it (the thing itself listed last where it is
    /// the author and not listed: the same members).
    Known(Path),
    /// An entry opening to a list breaking `Path`'s rules, or whose members leave out the purge
    /// author (notes/a1-spec/README.md Open 16): the thing's parts hold nothing, at every reader.
    Bad,
}

/// Reads the things thing `t`'s entry lists, opened, against the commit's signer and purge author
/// `author`: `Path`'s rules, `t` listed last if at all, and `author` among `t`'s members
/// [signer, listed…, t].
pub(crate) fn thing_path(listed: Option<(Vec<Tid>, Marks)>, signer: &Tid, author: &Tid, t: &Tid) -> ThingPath {
    let Some((mut things, direct)) = listed else { return ThingPath::Bad };
    if !listed_ok(&things, signer) || things.iter().rev().skip(1).any(|x| x == t) {
        return ThingPath::Bad;
    }
    let purge = if author == signer {
        0
    } else if let Some(j) = things.iter().position(|x| x == author) {
        j + 1
    } else if author == t {
        things.push(*t);
        things.len()
    } else {
        return ThingPath::Bad;
    };
    ThingPath::Known(Path { purge, things, direct })
}
