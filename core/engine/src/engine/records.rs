//! Local record keys and byte layouts of what the engine keeps in the store
//! (notes/engine-store.md). Everything lives in `Transaction::*_local` records except aspect
//! units, counters, pending commits and blob ciphertexts, which have their own kinds.

use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};

/// The node's seed.
pub const SEED: &[u8] = b"seed";
/// This node's node root's tid (spec/sync-set.md §1), written at its first start.
pub const NODE_ROOT: &[u8] = b"node root";
/// The last ciphertext-store transaction this store committed (`blobs::Cipher`, `Engine::settle_blobs`).
pub const BLOB_SEQ: &[u8] = b"blobseq";
/// The last `ts` issued or seen (the HLC survives restarts).
pub const HLC: &[u8] = b"hlc";
/// A thing's own secrets held (`Indexes::secrets`): `k/` + tid, its epochs.
pub const SECRETS: &[u8] = b"k/";
/// Applied commit records: `c/` + commit ID.
pub const COMMIT: &[u8] = b"c/";
/// Creation records: `t/` + tid.
pub const CREATED: &[u8] = b"t/";
/// Aspects with a state (the `aspects.0` index): `a/` + aspect key, empty value.
pub const ASPECTS: &[u8] = b"a/";
/// Value-less deltas per aspect (expired, purged): `v/` + aspect key.
pub const VALUELESS: &[u8] = b"v/";
/// The leftover of a part whose values went (expired, purged; `Hold::Leftover`): its body with
/// every value-carrying write value-less (spec/crdt.md §4.7), read as the held body
/// (`apply::each_held_piece`): `w/` + aspect key + commit ID + aspect index (4 bytes). A waiting
/// part a held purge request names keeps what was stripped of it here too, its pending copy's
/// slot holding an empty delta (`retention::emptied`) until it joins (`retention::leftover`).
pub const LEFTOVER: &[u8] = b"w/";
/// Purge requests with an item on a whole aspect or an author's deltas on it, which any delta
/// arriving may fall under: `p/` + aspect key.
pub const PURGES: &[u8] = b"p/";
/// A purge request that dropped a permanent delta on a thing (`retention::lasting`): `z/` + tid +
/// commit ID, empty (thing first: a forgetting clears its things' rows by prefix).
pub const NAMED_PERMANENT: &[u8] = b"z/";
/// Purge requests naming a commit's deltas: `pn/` + aspect key + commit ID, the requests.
pub const PURGES_NAMED: &[u8] = b"pn/";
/// Re-snapshots owed after purge requests (`Indexes::resnapshots_owed`): `ro/` + aspect key, the
/// named bodies applied here (commit IDs, 32 bytes each); in memory for an ephemeral aspect.
pub const RESNAPSHOTS_OWED: &[u8] = b"ro/";
/// Per aspect, the newest `ts` of a durable commit forgotten on it (`Indexes::forgotten`):
/// `f/` + aspect key (`aspect_key`), gone with the thing.
pub const FORGOTTEN: &[u8] = b"f/";
/// A forgotten commit's name while a held snapshot carries its writes (`retention::names`):
/// `fn/` + aspect key + commit ID, its stamp and purge facts.
pub const FORGOTTEN_NAMES: &[u8] = b"fn/";
/// A forgotten coverer's covers while something names it (`retention::handed`): `cv/` + commit ID,
/// per aspect the covers its part dropped under; a memory coverer's in memory.
pub const HANDED: &[u8] = b"cv/";
/// Freed links (`retention::freed`): `fl/` + blob ID + tid, flags, the author's tid and the link,
/// in the class of the body that freed them.
pub const FREED: &[u8] = b"fl/";
/// Each freed link again by its thing: `ft/` + tid + blob ID, empty, in its row's class (a
/// forgetting finds its things' rows by prefix).
pub const FREED_OF: &[u8] = b"ft/";
/// Timers: `x/` + T (8 bytes, big endian) + commit ID + aspect index (4 bytes), the kind.
pub const TIMER: &[u8] = b"x/";
/// Each timer again by its part: `xc/` + commit ID + aspect index + T, empty (a forgetting finds
/// its parts' timers by prefix).
pub const TIMER_OF: &[u8] = b"xc/";
/// History rows (`Indexes::leaving`): `hr/` + aspect key + replaced-at (`Ts`, 8 bytes) +
/// commit ID, empty.
pub const LEAVING: &[u8] = b"hr/";
/// History cursors (`Indexes::leave_from`): `hf/` + aspect key, the due wall ms (8 bytes), then
/// 0, or 1 + the last place out (`Ts`, commit ID).
pub const LEAVE_FROM: &[u8] = b"hf/";
/// A paged part's page index (`osis_crdt::PageIndex::to_bytes`, `apply::held_part_at`): `pi/` +
/// commit ID + aspect index (4 bytes), in its commit's class; written when the part is applied,
/// gone with the part.
pub const PAGE_INDEX: &[u8] = b"pi/";
/// An aspect's held writes (`retention::bounds::settle_index`): `hx/` + tid + 16 bytes of the
/// AK's hash, then the rows of `osis_crdt::Held` (module doc there) and `!`, empty: the index
/// is built.
pub const HELD: &[u8] = b"hx/";
/// Things held destroyed (`Indexes::destroyed`): `dt/` + tid, empty.
pub const DESTROYED: &[u8] = b"dt/";
/// Commits voided by overlapping session ranges: `o/` + commit ID.
pub const VOID: &[u8] = b"o/";
/// `rd/<commit>`: accounts' rotations not yet answered with this node's listing (its own
/// account's) or addenda (another's) (`Indexes::rotations_due`).
pub const ROTATIONS_DUE: &[u8] = b"rd/";
/// Commits whose `keys.0` part on a thing wrote a keyset in its body (`Indexes::keyset_parts`;
/// kept while the commit is held, whatever becomes of the body): `g/` + tid + commit ID.
pub const OWN_SECRETS: &[u8] = b"g/";
/// Derived read epochs this node sealed a section under while their thing was dependent here, not
/// yet carried by a rotation of it (`Indexes::derived_written`, `rotation::merge`): `dw/` + tid +
/// the epoch's n (8 bytes, big endian) + nonce, empty.
pub const DERIVED_WRITTEN: &[u8] = b"dw/";
/// The epochs sections of commits another wrote opened under, per part, and those this node's own
/// content parts were made under where their floor is above 0 (`sync_ids::opened`):
/// `ou/` + commit ID + aspect index (4 bytes, big endian) + the epoch's n (8 bytes, big endian)
/// + nonce; the value a byte (1: the delta checked against its header) and the delta's hash.
pub const OPENED_UNDER: &[u8] = b"ou/";
/// The read floor up to which this node owed the state at a cut of an actor's content
/// (`rotation::floors::owe_state`): `cs/` + tid, the floor (le64).
pub const CUT_SETTLED: &[u8] = b"cs/";
/// Suspect aspects (`retention::suspect`): `q/` + aspect key, le64 wall ms last
/// raised, then per body its commit ID, aspect index and `Why` bits.
pub const SUSPECT: &[u8] = b"q/";
/// The local schema of each app AK (`Core::schemas`): `d/` + AK, the schema's canonical form.
pub const SCHEMAS: &[u8] = b"d/";
/// Records the API layer keeps (identity choices, settings): `u/` + name.
pub const APP: &[u8] = b"u/";
/// The sides taken in admin disputes (`crate::sides`), one record.
pub const SIDES: &[u8] = b"sides";
/// The seeds of account epochs in this node's custody (`flows::custody`): `sd/` + the account's
/// tid + the epoch's signing key, the 32-byte seed. Shredded when the node leaves the account.
pub const SEEDS: &[u8] = b"sd/";
/// The account this node belongs to and its account root (two tids).
pub const ACCOUNT: &[u8] = b"account";
/// Thing lists held (`flows::lists`): `tl/` + rotation ID + thing + be64 index, the `ThingCert`.
/// Kept for good, like the role commits they name.
pub const LISTS: &[u8] = b"tl/";
/// Names of accounts' commits (`flows::lists`): `tn/` + commit ID + thing + source (a rotation
/// whose thing list, or a listing whose `listing.0`, names the commit on the thing).
pub const NAMES: &[u8] = b"tn/";
/// The same rows by source: `tb/` + source + commit ID + thing.
pub const NAMED_BY: &[u8] = b"tb/";

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

/// The `PURGES_NAMED` key of the commit stamped `ts` with own source `src` on `(tid, ak)`: the
/// aspect key, then `STAMP_KEY` bytes (`ts`, the source's kind, its bytes zero-padded to 32).
pub fn purges_named_key(tid: &Tid, ak: &Ak, ts: osis_base::Ts, src: &osis_crdt::Source) -> Vec<u8> {
    let (kind, bytes) = match src.kind() {
        osis_crdt::SourceKind::Session(s) => (0u8, s.to_bytes().to_vec()),
        osis_crdt::SourceKind::Commit(c) => (1, c.0.to_vec()),
        osis_crdt::SourceKind::Derived(_) => (2, Vec::new()),
    };
    let mut padded = [0u8; 32];
    for (p, b) in padded.iter_mut().zip(&bytes) {
        *p = *b;
    }
    [aspect_key(PURGES_NAMED, tid, ak).as_slice(), &ts.to_u64().to_be_bytes(), &[kind], &padded].concat()
}

/// The length of the stamp after the aspect key in a `PURGES_NAMED` key.
pub const STAMP_KEY: usize = 8 + 1 + 32;

pub fn leftover_key(tid: &Tid, ak: &Ak, id: &CommitId, ai: usize) -> Vec<u8> {
    [aspect_key(LEFTOVER, tid, ak), id.0.to_vec(), (ai as u32).to_be_bytes().to_vec()].concat()
}

pub fn named_permanent_key(id: &CommitId, tid: &Tid) -> Vec<u8> {
    [NAMED_PERMANENT, tid.as_bytes(), &id.0[..]].concat()
}

pub fn own_secrets_key(tid: &Tid, id: &CommitId) -> Vec<u8> {
    [OWN_SECRETS, tid.as_bytes(), &id.0[..]].concat()
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

/// The `TIMER_OF` row of timer `timer_key(t, id, ai)`.
pub fn timer_of_key(t: u64, id: &CommitId, ai: usize) -> Vec<u8> {
    [TIMER_OF, &id.0[..], &(ai as u32).to_be_bytes(), &t.to_be_bytes()].concat()
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
