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

/// One stated path `[i, A1, …, Ak]`: the purge-author index `purge` (0 names the signer, j the
/// listed thing Aj, spec/permissions.md §6) and the listed things in order. The empty path naming
/// the signer is `Path::default()`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Path {
    pub purge: usize,
    pub things: Vec<Tid>,
}

impl Path {
    /// The path of one listed thing `x`, naming it as purge author.
    pub fn through(x: Tid) -> Path {
        Path { purge: 1, things: vec![x] }
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
            let q = Path { purge: 0, things };
            if !each.clone().into_iter().all(|(t, p)| q.to(t) == p.to(t)) {
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
        put_array(out, 1 + self.things.len());
        put_uint(out, self.purge as u64);
        self.things.iter().for_each(|t| put_bytes(out, t.as_bytes()));
    }

    /// Reads a `Path` of a commit signed by `signer`: i ≤ k, k ≤ `MAX_PATH_THINGS`, no tid twice
    /// and none equal to `signer` (spec/wire.md §4), else malformed.
    pub(crate) fn read(v: Item, signer: &Tid) -> Result<Path, Error> {
        let l = item::list(v)?;
        let mut it = l.iter();
        let purge = item::idx(it.next().ok_or(Error::Malformed("empty path"))?)?;
        let p = Path { purge, things: it.map(item::tid).collect::<Result<Vec<Tid>, Error>>()? };
        p.check(signer)?;
        Ok(p)
    }

    /// The decoder's rules on a path of a commit signed by `signer` (spec/wire.md §4).
    pub(crate) fn check(&self, signer: &Tid) -> Result<(), Error> {
        if self.purge > self.things.len() {
            return Err(Error::Malformed("purge-author index out of range"));
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

/// Bytes of the canonical `[tid*]` of `k` things.
fn listed_len(k: usize) -> usize {
    head_len(k as u64) + k * (1 + TID_LEN)
}

/// Bytes of a sealed entry of a path listing `k` things: its class's padded plaintext and the
/// tag; `None` past `MAX_PATH_THINGS`.
pub fn entry_len(k: usize) -> Option<usize> {
    ENTRY_CLASSES.iter().find(|c| **c >= k).map(|c| listed_len(*c) + osis_crypto::aead::TAG_LEN)
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
    /// Thing `t`'s entry: its listed things, canonical, zero-padded to their class, sealed under its
    /// path key, nonce zero, empty AD (one plaintext per key: the blind is fresh per commit).
    pub fn seal(key: &[u8; 32], listed: &[Tid]) -> Result<Vec<u8>, Error> {
        let len = entry_len(listed.len()).ok_or(Error::Build("path longer than MAX_PATH_THINGS"))? - osis_crypto::aead::TAG_LEN;
        let mut pt = Vec::with_capacity(len);
        put_array(&mut pt, listed.len());
        listed.iter().for_each(|t| put_bytes(&mut pt, t.as_bytes()));
        pt.resize(len, 0);
        Ok(osis_crypto::aead::seal(key, &osis_crypto::aead::ZERO_NONCE, &[], &pt)?)
    }

    /// Opens `entry` under `key`: `None` where the key does not open it; else the things it lists,
    /// `None` inside where the plaintext is no canonical `[tid*]` padded with zeros to its class.
    pub fn open(key: &[u8; 32], entry: &[u8]) -> Option<Option<Vec<Tid>>> {
        let pt = osis_crypto::aead::open(key, &osis_crypto::aead::ZERO_NONCE, &[], entry).ok()?;
        let Ok(head) = osis_base::cbor::item_prefix(&pt, &crate::header::LIMITS) else { return Some(None) };
        let listed = Item::parse(head, &crate::header::LIMITS).ok().and_then(|v| item::list(v).ok()).and_then(|l| l.iter().map(item::tid).collect::<Result<Vec<Tid>, _>>().ok());
        let padded = listed.as_ref().is_some_and(|l| entry_len(l.len()) == Some(entry.len()) && listed_len(l.len()) == head.len() && pt.get(head.len()..).is_some_and(|r| r.iter().all(|b| *b == 0)));
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
        if entries.iter().any(|e| !ENTRY_CLASSES.iter().any(|c| entry_len(*c) == Some(e.len()))) {
            return Err(Error::Malformed("split path entry of no padded length"));
        }
        Ok(Split { author, entries })
    }
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
pub(crate) fn thing_path(listed: Option<Vec<Tid>>, signer: &Tid, author: &Tid, t: &Tid) -> ThingPath {
    let Some(mut things) = listed else { return ThingPath::Bad };
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
    ThingPath::Known(Path { purge, things })
}
