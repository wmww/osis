//! The persisted index (notes/local-store.md: a rebuildable index unit): what `apply::load`
//! would otherwise re-derive at every open by decoding every commit and re-judging every delta.
//! Each applied commit's meta (header, validity, dropped parts) and the indexes derived from
//! membership bodies (rotation roles, grant overreach, box keys, epoch introductions, own keys)
//! are written in the transaction that changes them, from the journal of the in-memory indexes.
//! Tagged with the build: another build (or a store without it, or one whose commit records
//! changed outside the indexes, `invalidate`) rebuilds it from the commit records once.

use super::journal::{JMap, JSet, JSetMap};
use super::{Core, Meta, Tx, records};
use osis_store::Transaction;
use crate::error::{Error, Result};
use crate::events::Origin;
use osis_core::{CommitId, Role, Tid, Ts, Value, WallMs};
use osis_crdt::Dot;
use osis_schema::Codec;
use osis_schema::core_types::BoxKey;
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Whether the index on disk was written by this build.
const VERSION_KEY: &[u8] = b"i/v";
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/index 3");
// The derived indexes live in rebuildable store index tables of their own (a node's local
// records table is not deepened by them).
const BOX_KEYS: &[u8] = b"node/box keys";
const BOXES_TO: &[u8] = b"node/boxes to";
const EPOCH_INTRO: &[u8] = b"node/epoch intro";
const BOX_WRITTEN: &[u8] = b"node/box written";
const OWN_KEYS: &[u8] = b"node/own keys";
const SNAPSHOTS: &[u8] = b"node/snapshots";
const CARRIED: &[u8] = b"node/carried";

/// A record key or value of the persisted index.
trait Rec: Sized {
    fn to(&self) -> Value;
    fn from(v: &Value) -> Option<Self>;
}

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

impl Rec for CommitId {
    fn to(&self) -> Value {
        Value::Bytes(self.0.to_vec())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Bytes(b) => Some(CommitId(b.as_slice().try_into().ok()?)),
            _ => None,
        }
    }
}
impl Rec for Tid {
    fn to(&self) -> Value {
        Value::Bytes(self.as_bytes().to_vec())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Bytes(b) => Some(Tid::from_bytes(b.as_slice().try_into().ok()?)),
            _ => None,
        }
    }
}
impl Rec for usize {
    fn to(&self) -> Value {
        uint(*self as u64)
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Int(i) => usize::try_from(*i).ok(),
            _ => None,
        }
    }
}
impl Rec for Ts {
    fn to(&self) -> Value {
        uint(self.to_u64())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Int(i) => Ts::from_u64(u64::try_from(*i).ok()?),
            _ => None,
        }
    }
}
impl Rec for Role {
    fn to(&self) -> Value {
        self.to_value()
    }
    fn from(v: &Value) -> Option<Self> {
        Role::from_value(v).ok()
    }
}
impl Rec for BoxKey {
    fn to(&self) -> Value {
        self.to_value()
    }
    fn from(v: &Value) -> Option<Self> {
        BoxKey::from_value(v).ok()
    }
}
impl Rec for osis_crypto::Epoch {
    fn to(&self) -> Value {
        self.to_wire()
    }
    fn from(v: &Value) -> Option<Self> {
        osis_crypto::Epoch::from_wire(v).ok()
    }
}
impl Rec for Value {
    fn to(&self) -> Value {
        self.clone()
    }
    fn from(v: &Value) -> Option<Self> {
        Some(v.clone())
    }
}
impl Rec for Dot {
    fn to(&self) -> Value {
        records::dot_value(self)
    }
    fn from(v: &Value) -> Option<Self> {
        records::dot_of(v).ok()
    }
}
impl Rec for osis_core::Ak {
    fn to(&self) -> Value {
        Value::Str(self.as_str().to_string())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Str(s) => osis_core::Ak::new(s).ok(),
            _ => None,
        }
    }
}
impl Rec for osis_crdt::Frontiers {
    fn to(&self) -> Value {
        Value::List(self.0.iter().map(|(t, c)| Value::List(vec![t.to(), uint(*c)])).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let mut out = std::collections::BTreeMap::new();
        for e in x {
            let (t, c) = <(Tid, usize) as Rec>::from(e)?;
            out.insert(t, c as u64);
        }
        Some(osis_crdt::Frontiers(out))
    }
}
impl<T: Rec> Rec for Vec<T> {
    fn to(&self) -> Value {
        Value::List(self.iter().map(Rec::to).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        x.iter().map(T::from).collect()
    }
}
impl Rec for crate::apply::validity::Carried {
    fn to(&self) -> Value {
        Value::List(vec![self.node.to(), self.ts.to(), uint(self.lo), uint(self.hi), Value::Bool(self.valid)])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [n, ts, Value::Int(lo), Value::Int(hi), Value::Bool(valid)] = x.as_slice() else { return None };
        Some(crate::apply::validity::Carried { node: <Tid as Rec>::from(n)?, ts: <Ts as Rec>::from(ts)?, lo: u64::try_from(*lo).ok()?, hi: u64::try_from(*hi).ok()?, valid: *valid })
    }
}
impl Rec for () {
    fn to(&self) -> Value {
        Value::List(Vec::new())
    }
    fn from(_: &Value) -> Option<Self> {
        Some(())
    }
}
impl<A: Rec, B: Rec> Rec for (A, B) {
    fn to(&self) -> Value {
        Value::List(vec![self.0.to(), self.1.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [a, b] = x.as_slice() else { return None };
        Some((A::from(a)?, B::from(b)?))
    }
}
impl<A: Rec, B: Rec, C: Rec> Rec for (A, B, C) {
    fn to(&self) -> Value {
        Value::List(vec![self.0.to(), self.1.to(), self.2.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [a, b, c] = x.as_slice() else { return None };
        Some((A::from(a)?, B::from(b)?, C::from(c)?))
    }
}

fn enc<T: Rec>(x: &T) -> Vec<u8> {
    osis_core::encode(&x.to())
}

fn dec<T: Rec>(b: &[u8]) -> Result<T> {
    let lim = osis_core::Limits { max_depth: 16, max_bytes: b.len() };
    let v = osis_core::decode(b, &lim).map_err(|_| Error::Corrupt("index record"))?;
    T::from(&v).ok_or(Error::Corrupt("index record"))
}

fn put_map<K: Rec + Ord + Clone, V: Rec + Clone>(txn: &mut Transaction<'_>, name: &[u8], m: &JMap<K, V>, keys: &[K]) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let t = txn.index(name)?;
    for k in keys {
        let key = enc(k);
        match m.get(k) {
            Some(v) => txn.table_put(t, &key, enc(v), Shred::No).map(|_| ())?,
            None => txn.table_remove(t, &key, Shred::No).map(|_| ())?,
        }
    }
    Ok(())
}

fn put_set<T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, name: &[u8], s: &JSet<T>, items: &[T]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let tb = txn.index(name)?;
    for t in items {
        let key = enc(t);
        if s.contains(t) {
            txn.table_put(tb, &key, Vec::new(), Shred::No)?;
        } else {
            txn.table_remove(tb, &key, Shred::No)?;
        }
    }
    Ok(())
}

fn put_setmap<K: Rec + Ord + Clone, T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, name: &[u8], s: &JSetMap<K, T>, items: &[(K, T)]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let tb = txn.index(name)?;
    for (k, t) in items {
        let key = enc(&(k.clone(), t.clone()));
        if s.get(k).is_some_and(|x| x.contains(t)) {
            txn.table_put(tb, &key, Vec::new(), Shred::No)?;
        } else {
            txn.table_remove(tb, &key, Shred::No)?;
        }
    }
    Ok(())
}

/// What of a commit the engine indexes, ahead of its blob in its record (version 2): received,
/// origin, dropped parts, and per part one byte: bit 0 valid, bits 1-2 the rotation role it
/// needs (0 none, 1 read, 2 write, 3 admin), bit 3 a grant's overreach.
pub(crate) struct RecordHead {
    pub received: WallMs,
    pub origin: Origin,
    pub dropped: BTreeSet<(usize, usize)>,
    pub parts: Vec<u8>,
}

pub(crate) fn record_head(core: &Core, id: &CommitId, m: &Meta) -> Vec<u8> {
    let mut w = records::Wr::new().u8(2).u64(m.received.0).u8(match m.origin {
        Origin::Local => 0,
        Origin::Remote => 1,
    });
    w = w.u32(m.dropped.len() as u32);
    for (a, d) in &m.dropped {
        w = w.u32(*a as u32).u32(*d as u32);
    }
    w = w.u32(m.valid.len() as u32);
    for (ai, v) in m.valid.iter().enumerate() {
        let role = match core.rotation_role.get(&(*id, ai)) {
            None => 0,
            Some(Role::Read) => 1,
            Some(Role::Write) => 2,
            Some(Role::Admin) => 3,
        };
        w = w.u8(u8::from(*v) | (role << 1) | (u8::from(core.grant_overreach.contains(&(*id, ai))) << 3));
    }
    w.take()
}

/// A commit record's head and its blob bytes (version 1 records have no part bytes).
pub(crate) fn parse_head(v: &[u8]) -> Result<(RecordHead, &[u8])> {
    let mut r = records::Rd::new(v);
    let version = r.u8()?;
    if version != 1 && version != 2 {
        return Err(Error::Corrupt("commit record version"));
    }
    let received = WallMs(r.u64()?);
    let origin = if r.u8()? == 0 { Origin::Local } else { Origin::Remote };
    let mut dropped = BTreeSet::new();
    for _ in 0..r.u32()? {
        dropped.insert((r.u32()? as usize, r.u32()? as usize));
    }
    let mut parts = Vec::new();
    if version == 2 {
        for _ in 0..r.u32()? {
            parts.push(r.u8()?);
        }
    }
    Ok((RecordHead { received, origin, dropped, parts }, r.rest()))
}

/// Rewrites the head of commit `id`'s record where what the engine indexes of it changed (its
/// validity, the roles its parts need): the blob bytes stay.
fn restamp(txn: &mut Transaction<'_>, core: &Core, id: &CommitId) -> Result<()> {
    let Some(m) = core.commits.get(id) else { return Ok(()) };
    let key = records::commit_key(id);
    let Some(v) = txn.get_local(&key)? else { return Ok(()) };
    let head = record_head(core, id, m);
    if v.starts_with(&head) && parse_head(&v)?.0.parts.len() == m.valid.len() {
        return Ok(());
    }
    let (_, blob) = parse_head(&v)?;
    txn.put_local(&key, &[head.as_slice(), blob].concat(), Shred::No)?;
    Ok(())
}

/// Writes the given changes (`all`: everything) of the indexes to the persisted index.
fn write(tx: &mut Tx<'_>, all: bool) -> Result<()> {
    let c = &*tx.core;
    let txn = &mut tx.txn;
    // a commit's meta carries its parts' rotation roles and grant overreach
    let ids: Vec<CommitId> = if all {
        c.commits.keys().copied().collect()
    } else {
        let mut s: BTreeSet<CommitId> = c.commits.logged().into_iter().collect();
        s.extend(c.rotation_role.logged().into_iter().map(|k| k.0));
        s.extend(c.grant_overreach.logged().into_iter().map(|k| k.0));
        s.into_iter().collect()
    };
    for id in &ids {
        restamp(txn, c, id)?;
    }
    let k = if all { c.box_keys.keys().cloned().collect() } else { c.box_keys.logged() };
    put_map(txn, BOX_KEYS, &c.box_keys, &k)?;
    let k = if all { c.boxes_to.iter().flat_map(|(m, s)| s.iter().map(|x| (*m, x.clone()))).collect() } else { c.boxes_to.logged() };
    put_setmap(txn, BOXES_TO, &c.boxes_to, &k)?;
    let k = if all { c.epoch_intro.keys().cloned().collect() } else { c.epoch_intro.logged() };
    put_map(txn, EPOCH_INTRO, &c.epoch_intro, &k)?;
    let k = if all { c.box_written.keys().cloned().collect() } else { c.box_written.logged() };
    put_map(txn, BOX_WRITTEN, &c.box_written, &k)?;
    let k = if all { c.own_keys.iter().cloned().collect() } else { c.own_keys.logged() };
    put_set(txn, OWN_KEYS, &c.own_keys, &k)?;
    let k = if all { c.snapshots.keys().cloned().collect() } else { c.snapshots.logged() };
    put_map(txn, SNAPSHOTS, &c.snapshots, &k)?;
    let k = if all { c.carried.keys().cloned().collect() } else { c.carried.logged() };
    put_map(txn, CARRIED, &c.carried, &k)?;
    Ok(())
}

/// Writes what the running transaction changed in the persisted indexes (before it commits).
pub(crate) fn persist(tx: &mut Tx<'_>) -> Result<()> {
    write(tx, false)
}

/// Writes the whole persisted index (after a rebuild from the commit records) and tags it; what
/// an older one held goes shredded (forgotten commits' headers among it).
pub(crate) fn write_all(tx: &mut Tx<'_>) -> Result<()> {
    // what an older index held goes shredded (forgotten things' entries among it)
    tx.txn.drop_indexes()?;
    write(tx, true)?;
    tx.txn.put_local(VERSION_KEY, VERSION.as_bytes(), Shred::No)?;
    Ok(())
}

/// Whether the persisted index was written by this build (else `load` rebuilds it).
pub(crate) fn current(tx: &mut Tx<'_>) -> Result<bool> {
    Ok(tx.txn.get_local(VERSION_KEY)?.is_some_and(|v| v == VERSION.as_bytes()))
}

/// Marks the persisted index stale: the next open rebuilds it (commit records changed outside
/// the in-memory indexes, e.g. by forgetting).
pub(crate) fn invalidate(tx: &mut Tx<'_>) -> Result<()> {
    tx.txn.remove_local(VERSION_KEY, Shred::No)?;
    Ok(())
}

fn scan<T: Rec>(tx: &mut Tx<'_>, name: &[u8]) -> Result<Vec<(T, Vec<u8>)>> {
    let t = tx.txn.index(name)?;
    let mut out = Vec::new();
    let mut from = Vec::new();
    loop {
        let rows = tx.txn.table_range(t, &from, None, 256)?;
        let n = rows.len();
        for (k, v) in rows {
            out.push((dec(&k)?, v));
            from = [k.as_slice(), &[0]].concat();
        }
        if n < 256 {
            return Ok(out);
        }
    }
}

/// Loads the persisted index into `core`: commit metas (headers resolved), and the indexes
/// derived from membership bodies.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    // commit records: the head and the header only, no part decoded
    let mut metas = Vec::new();
    tx.scan(records::COMMIT, |k, v| {
        let id = CommitId(k.try_into().map_err(|_| Error::Corrupt("commit record key"))?);
        let (head, blob) = parse_head(&v)?;
        // the blob is `[header, signature, parts]`: its first item
        let lim = osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: blob.len() };
        let (_, hb) = osis_core::decode_prefix(blob.get(1..).unwrap_or_default(), &lim).map_err(|_| Error::Corrupt("commit record header"))?;
        let h = osis_commit::Header::decode(hb).map_err(|_| Error::Corrupt("commit record header"))?;
        metas.push((id, head, h));
        Ok(())
    })?;
    for (id, head, mut h) in metas {
        if head.parts.len() != h.aspects.len() {
            return Err(Error::Corrupt("commit record head"));
        }
        let mut valid = Vec::with_capacity(head.parts.len());
        for (ai, p) in head.parts.into_iter().enumerate() {
            valid.push(p & 1 != 0);
            if let Some(r) = [Role::Read, Role::Write, Role::Admin].get(<usize as From<u8>>::from((p >> 1) & 3).wrapping_sub(1)) {
                tx.core.rotation_role.insert((id, ai), *r);
            }
            if p & 8 != 0 {
                tx.core.grant_overreach.insert((id, ai));
            }
        }
        if !h.is_resolved()
            && let Some(dedup) = tx.core.dedup(&h.actor)
        {
            h.resolve(&mut super::blobs::TxBlobs::new(&mut tx.txn), &dedup, osis_commit::MAX_LIST_BYTES).map_err(|_| Error::Corrupt("header lists"))?;
        }
        if h.id() != id {
            return Err(Error::Corrupt("commit record"));
        }
        let h = Arc::new(h);
        crate::apply::index_commit(tx.core, &id, &h);
        tx.core.commits.insert(id, Meta { header: h, received: head.received, origin: head.origin, valid, dropped: head.dropped });
        tx.core.index_validity(&id);
    }
    for (k, v) in scan::<(Tid, Dot)>(tx, BOX_KEYS)? {
        tx.core.box_keys.insert(k, dec(&v)?);
    }
    for ((m, x), _) in scan::<(Tid, (Tid, Value))>(tx, BOXES_TO)? {
        tx.core.boxes_to.insert(m, x);
    }
    for (k, v) in scan::<(Tid, Role, osis_crypto::Epoch)>(tx, EPOCH_INTRO)? {
        tx.core.epoch_intro.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, BoxKey)>(tx, BOX_WRITTEN)? {
        tx.core.box_written.insert(k, dec(&v)?);
    }
    for (k, _) in scan::<Tid>(tx, OWN_KEYS)? {
        tx.core.own_keys.insert(k);
    }
    for (k, v) in scan::<(Tid, osis_core::Ak)>(tx, SNAPSHOTS)? {
        tx.core.snapshots.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, osis_core::Ak)>(tx, CARRIED)? {
        tx.core.carried.insert(k, dec(&v)?);
    }
    Ok(())
}




impl super::Engine {
    /// A dump of the indexes open rebuilds (tests: a load from the persisted index equals a
    /// rebuild from the commit records).
    #[doc(hidden)]
    pub fn index_digest(&self) -> String {
        use std::fmt::Write;
        let c = &self.core;
        let mut out = String::new();
        for (id, m) in c.commits.iter() {
            let _ = writeln!(out, "commit {id:?} {:?} {:?} {:?} {:?}", m.valid, m.dropped, m.received, m.origin);
        }
        let held = osis_perm::HeldSet::things(&c.held);
        for t in held {
            let cs: Vec<CommitId> = osis_perm::HeldSet::edge_commits(&c.held, &t).iter().map(|x| x.id).collect();
            let ss: Vec<CommitId> = osis_perm::HeldSet::roster_snapshots(&c.held, &t).iter().map(|x| x.id).collect();
            let _ = writeln!(out, "held {t:?} {cs:?} {ss:?} {:?}", c.held.created(&t).is_some());
        }
        let _ = writeln!(out, "by_aspect {:?}\ninvalid {:?}\nranges {:?}", *c.by_aspect, *c.invalid, *c.ranges);
        let _ = writeln!(out, "rotation_role {:?}\ngrant_overreach {:?}\nbox_keys {:?}\nboxes_to {:?}", *c.rotation_role, *c.grant_overreach, *c.box_keys, *c.boxes_to);
        let _ = writeln!(out, "epoch_intro {:?}\nbox_written {:?}\nown_keys {:?}", *c.epoch_intro, *c.box_written, *c.own_keys);
        let _ = writeln!(out, "member_keys {:?}\nunresolved {:?}\nwas {:?}\nmoved {:?}\ngroups {:?}", *c.member_keys, *c.unresolved, *c.was, *c.moved, c.groups.of);
        let _ = writeln!(out, "secrets {:?}\nvoid {:?}\nvalueless {:?}\nsnapshots {:?}\ncarried {:?}", *c.secrets, *c.void, *c.valueless, *c.snapshots, *c.carried);
        out
    }

    /// Rebuilds the in-memory indexes from the commit records (and the persisted index), as a
    /// store written by another build would (tests).
    #[doc(hidden)]
    pub fn rebuild_index(&mut self) -> Result<()> {
        self.run(invalidate)?;
        self.reload()
    }

    /// Reloads the in-memory indexes from the store (tests: what an open reads).
    #[doc(hidden)]
    pub fn reload_index(&mut self) -> Result<()> {
        self.reload()
    }
}
