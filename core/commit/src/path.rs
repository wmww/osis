//! Stated paths (spec/wire.md §4 `Path`, `Paths`, `Salted`; spec/permissions.md §5.2 Interim): what
//! a commit acts along on each thing it writes: one path in the clear where every thing's is the
//! same, else a salted hash per thing in the header with each thing's own path in its sections.

use crate::Error;
use crate::cbor::item;
use osis_base::cbor::{Item, put_array, put_bytes, put_uint};
use osis_base::format::MAX_PATH_THINGS;
use osis_base::Tid;
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

    // Interim (notes/a1-spec/README.md step 3): the walk judges along every edge of the path.
    /// The thing the walk reads as the commit acting on it: the last listed thing, `signer` for
    /// the empty path. Things listed before it are not yet read.
    pub fn acting(&self, signer: Tid) -> Tid {
        self.things.last().copied().unwrap_or(signer)
    }

    // Interim (notes/a1-spec/README.md step 3): any index i ≤ k, judged along the path.
    /// Whether its purge-author index names the last listed thing (i = k), as the walk that
    /// reads only that thing needs.
    pub fn interim_index(&self) -> bool {
        self.purge == self.things.len()
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
        if self.things.len() > MAX_PATH_THINGS {
            return Err(Error::Malformed("path longer than MAX_PATH_THINGS"));
        }
        if self.purge > self.things.len() {
            return Err(Error::Malformed("purge-author index out of range"));
        }
        let mut seen = BTreeSet::new();
        if !self.things.iter().all(|t| t != signer && seen.insert(*t)) {
            return Err(Error::Malformed("path lists a thing twice or its signer"));
        }
        Ok(())
    }
}

/// A header's `path` (spec/wire.md §4 `Paths`): one `Path` for every thing it writes, where all are
/// equal, else one 32-byte hash per thing it writes, in the order of its aspects' tids.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Paths {
    One(Path),
    Hashed(Vec<[u8; 32]>),
}

impl Default for Paths {
    fn default() -> Paths {
        Paths::One(Path::default())
    }
}

impl Paths {
    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        match self {
            Paths::One(p) => p.put(out),
            Paths::Hashed(hs) => {
                put_array(out, hs.len());
                hs.iter().for_each(|h| put_bytes(out, h));
            }
        }
    }

    /// Reads a header's `path`: a `Path` (its first item a uint) or two or more hashes.
    pub(crate) fn read(v: Item, signer: &Tid) -> Result<Paths, Error> {
        let l = item::list(v)?;
        match l.first() {
            Some(first) if first.as_uint().is_some() => Ok(Paths::One(Path::read(v, signer)?)),
            _ => {
                let hs = l.iter().map(item::bytes::<32>).collect::<Result<Vec<_>, Error>>()?;
                if hs.len() < 2 {
                    return Err(Error::Malformed("hashed path of fewer than two things"));
                }
                Ok(Paths::Hashed(hs))
            }
        }
    }
}

/// A thing's path in its sections where its commit's paths are hashed (spec/wire.md §4
/// `Salted`): the random salt its header's hash is keyed by, and the path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Salted {
    pub salt: [u8; 16],
    pub path: Path,
}

impl Salted {
    /// Its entry in the header: `kdf("path", salt, canonical bytes of the Path)`.
    pub fn hash(&self) -> [u8; 32] {
        *osis_crypto::kdf::kdf(osis_crypto::kdf::PATH, &self.salt, &self.path.encode()).expose()
    }

    pub(crate) fn put(&self, out: &mut Vec<u8>) {
        put_array(out, 2);
        put_bytes(out, &self.salt);
        self.path.put(out);
    }

    pub(crate) fn read(v: Item, signer: &Tid) -> Result<Salted, Error> {
        let Some([salt, path]) = item::list(v)?.tuple() else { return Err(Error::Malformed("salted path arity")) };
        Ok(Salted { salt: item::bytes(salt)?, path: Path::read(path, signer)? })
    }
}
