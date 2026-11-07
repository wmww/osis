//! Local record keys and byte layouts of what the engine keeps in the store
//! (notes/engine-store.md). Everything lives in `Transaction::*_local` records except aspect
//! units, counters, death records, pending commits and blob ciphertexts, which have their own kinds.

use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};

/// The node's seed.
pub const SEED: &[u8] = b"seed";
/// The last `ts` issued or seen (the HLC survives restarts).
pub const HLC: &[u8] = b"hlc";
/// Applied commit records: `c/` + commit ID.
pub const COMMIT: &[u8] = b"c/";
/// Creation records: `t/` + tid.
pub const CREATED: &[u8] = b"t/";
/// Aspects with a state (the `aspects.0` index): `a/` + aspect key, empty value.
pub const ASPECTS: &[u8] = b"a/";
/// Receipt record per aspect: `r/` + aspect key.
pub const RECEIPT: &[u8] = b"r/";
/// Value-less deltas per aspect (expired, purged): `v/` + aspect key.
pub const VALUELESS: &[u8] = b"v/";
/// The leftover of a part whose values went (expired, purged; `Meta::stripped`): its body with
/// every value-carrying write value-less (spec/crdt.md §4.7), read as the held body
/// (`apply::each_held_piece`): `w/` + aspect key + commit ID + aspect index (4 bytes). A waiting
/// part a held purge request names keeps what was stripped of it here too, its pending copy's
/// slot holding an empty delta (`retention::emptied`) until it joins (`retention::leftover`).
pub const LEFTOVER: &[u8] = b"w/";
/// Purge requests with an item on a whole aspect or an author's deltas on it, which any delta
/// arriving may fall under: `p/` + aspect key.
pub const PURGES: &[u8] = b"p/";
/// A purge request that dropped a permanent delta on a thing (`retention::lasting`): `z/` + commit
/// ID + tid, empty.
pub const NAMED_PERMANENT: &[u8] = b"z/";
/// Purge requests naming a commit's deltas: `pn/` + aspect key + commit ID, the requests.
pub const PURGES_NAMED: &[u8] = b"pn/";
/// Timers: `x/` + T (8 bytes, big endian) + commit ID + aspect index (4 bytes).
pub const TIMER: &[u8] = b"x/";
/// Things this node syncs: `s/` + tid.
pub const SYNCING: &[u8] = b"s/";
/// Commits voided by overlapping session ranges: `o/` + commit ID.
pub const VOID: &[u8] = b"o/";
/// `ad/<commit>`: explicit demotions this node has not answered with addenda yet
/// (`Indexes::addenda_due`).
pub const ADDENDA_DUE: &[u8] = b"ad/";
/// Commits whose `keys.0` part on a thing wrote a keyset in its body (`Indexes::keyset_parts`;
/// kept while the commit is held, whatever becomes of the body): `g/` + tid + commit ID.
pub const OWN_KEYS: &[u8] = b"g/";
/// Aspects whose deaths wait for a recompute (`retention::settle_deaths`): `e/` + aspect key.
pub const DEATHS_DUE: &[u8] = b"e/";
/// Suspect aspects (`retention::suspect`): `q/` + aspect key, le64 corrected wall ms last
/// raised, then per body its commit ID, aspect index and `Why` bits.
pub const SUSPECT: &[u8] = b"q/";
/// The local schema of each app AK (`Core::schemas`): `d/` + AK, the schema's canonical form.
pub const SCHEMAS: &[u8] = b"d/";
/// Records the API layer keeps (identity choices, settings): `u/` + name.
pub const APP: &[u8] = b"u/";
/// The sides taken in admin disputes (`crate::sides`), one record.
pub const SIDES: &[u8] = b"sides";

/// A dot as a value (local records).
pub fn dot_value(d: &osis_crdt::Dot) -> osis_base::Value {
    use osis_base::Value;
    use osis_crdt::SourceKind;
    let src = match d.src.kind() {
        SourceKind::Session(s) => Value::List(vec![Value::Int(0), Value::Bytes(s.to_bytes().to_vec())]),
        SourceKind::Commit(c) => Value::List(vec![Value::Int(1), Value::Bytes(c.0.to_vec())]),
        SourceKind::Derived(x) => Value::List(vec![Value::Int(2), dot_value(x)]),
    };
    Value::List(vec![src, Value::uint(d.ctr)])
}

pub fn dot_of(v: &osis_base::Value) -> Result<osis_crdt::Dot> {
    use osis_base::Value;
    use osis_crdt::{Dot, Source};
    let bad = || Error::Corrupt("dot");
    let Value::List(items) = v else { return Err(bad()) };
    let [Value::List(src), Value::Int(ctr)] = items.as_slice() else { return Err(bad()) };
    let src = match src.as_slice() {
        [Value::Int(0), Value::Bytes(s)] => Source::session(osis_crdt::Session::from_bytes(s.as_slice().try_into().map_err(|_| bad())?)),
        [Value::Int(1), Value::Bytes(c)] => Source::commit(CommitId(c.as_slice().try_into().map_err(|_| bad())?)),
        [Value::Int(2), x] => Source::derived(dot_of(x)?).ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    Ok(Dot::new(src, u64::try_from(*ctr).map_err(|_| bad())?))
}

/// `tid || u16 len || ak`: aspect part of a key.
pub fn aspect_key(prefix: &[u8], tid: &Tid, ak: &Ak) -> Vec<u8> {
    let a = ak.as_str().as_bytes();
    let mut k = Vec::with_capacity(prefix.len() + 17 + a.len());
    k.extend_from_slice(prefix);
    k.extend_from_slice(tid.as_bytes());
    k.extend_from_slice(&(a.len() as u16).to_be_bytes());
    k.extend_from_slice(a);
    k
}

pub fn purges_named_key(tid: &Tid, ak: &Ak, id: &CommitId) -> Vec<u8> {
    [aspect_key(PURGES_NAMED, tid, ak).as_slice(), &id.0[..]].concat()
}

pub fn leftover_key(tid: &Tid, ak: &Ak, id: &CommitId, ai: usize) -> Vec<u8> {
    [aspect_key(LEFTOVER, tid, ak), id.0.to_vec(), (ai as u32).to_be_bytes().to_vec()].concat()
}

pub fn named_permanent_key(id: &CommitId, tid: &Tid) -> Vec<u8> {
    [NAMED_PERMANENT, &id.0[..], tid.as_bytes()].concat()
}

pub fn own_keys_key(tid: &Tid, id: &CommitId) -> Vec<u8> {
    [OWN_KEYS, tid.as_bytes(), &id.0[..]].concat()
}

pub fn commit_key(id: &CommitId) -> Vec<u8> {
    [COMMIT, &id.0[..]].concat()
}

pub fn timer_key(t: u64, id: &CommitId, ai: usize) -> Vec<u8> {
    let mut k = TIMER.to_vec();
    k.extend_from_slice(&t.to_be_bytes());
    k.extend_from_slice(&id.0);
    k.extend_from_slice(&(ai as u32).to_be_bytes());
    k
}

/// Parses a timer key's tail (after `x/`).
pub fn parse_timer(k: &[u8]) -> Result<(u64, CommitId, usize)> {
    let mut r = Rd::new(k);
    let t = r.u64()?;
    let id = CommitId(r.arr()?);
    let ai = r.u32()? as usize;
    r.end()?;
    Ok((t, id, ai))
}

/// Byte writer for local layouts.
#[derive(Default)]
pub struct Wr(pub Vec<u8>);

impl Wr {
    pub fn new() -> Wr {
        Wr(Vec::new())
    }
    pub fn u8(mut self, v: u8) -> Wr {
        self.0.push(v);
        self
    }
    pub fn u32(mut self, v: u32) -> Wr {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Wr {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn raw(mut self, b: &[u8]) -> Wr {
        self.0.extend_from_slice(b);
        self
    }
    /// Length-prefixed bytes.
    pub fn bytes(self, b: &[u8]) -> Wr {
        self.u32(b.len() as u32).raw(b)
    }
    pub fn take(self) -> Vec<u8> {
        self.0
    }
}

/// Byte reader for local layouts; every failure is `Corrupt`.
pub struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Rd<'a> {
        Rd(b)
    }
    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n).ok_or(Error::Corrupt("short record"))?;
        self.0 = b;
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8> {
        let [b] = self.arr::<1>()?;
        Ok(b)
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Corrupt("short record"))
    }
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    pub fn tid(&mut self) -> Result<Tid> {
        Ok(Tid::from_bytes(self.arr()?))
    }
    pub fn ak(&mut self) -> Result<Ak> {
        let n = u16::from_be_bytes(self.arr()?) as usize;
        let s = std::str::from_utf8(self.take(n)?).map_err(|_| Error::Corrupt("ak"))?;
        Ak::new(s).map_err(|_| Error::Corrupt("ak"))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(Error::Corrupt("trailing bytes")) }
    }
}
