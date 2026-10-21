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
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/index 1");
/// Commit metas: `i/h/` + commit ID.
const META: &[u8] = b"i/h/";
const ROTATION_ROLE: &[u8] = b"i/r/";
const GRANT_OVERREACH: &[u8] = b"i/g/";
const BOX_KEYS: &[u8] = b"i/b/";
const BOXES_TO: &[u8] = b"i/t/";
const EPOCH_INTRO: &[u8] = b"i/e/";
const BOX_WRITTEN: &[u8] = b"i/w/";
const OWN_KEYS: &[u8] = b"i/k/";
const SNAPSHOTS: &[u8] = b"i/s/";
const CARRIED: &[u8] = b"i/c/";

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

fn put_map<K: Rec + Ord + Clone, V: Rec + Clone>(txn: &mut Transaction<'_>, prefix: &[u8], m: &JMap<K, V>, keys: &[K]) -> Result<()> {
    for k in keys {
        let key = [prefix, &enc(k)].concat();
        match m.get(k) {
            Some(v) => txn.put_local(&key, &enc(v), Shred::No)?,
            None => txn.remove_local(&key, Shred::No).map(|_| ())?,
        }
    }
    Ok(())
}

fn put_set<T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, prefix: &[u8], s: &JSet<T>, items: &[T]) -> Result<()> {
    for t in items {
        let key = [prefix, &enc(t)].concat();
        if s.contains(t) {
            txn.put_local(&key, &[], Shred::No)?;
        } else {
            txn.remove_local(&key, Shred::No)?;
        }
    }
    Ok(())
}

fn put_setmap<K: Rec + Ord + Clone, T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, prefix: &[u8], s: &JSetMap<K, T>, items: &[(K, T)]) -> Result<()> {
    for (k, t) in items {
        let key = [prefix, &enc(&(k.clone(), t.clone()))].concat();
        if s.get(k).is_some_and(|x| x.contains(t)) {
            txn.put_local(&key, &[], Shred::No)?;
        } else {
            txn.remove_local(&key, Shred::No)?;
        }
    }
    Ok(())
}

fn put_meta(txn: &mut Transaction<'_>, core: &Core, ids: &[CommitId]) -> Result<()> {
    for id in ids {
        let key = [META, &id.0[..]].concat();
        match core.commits.get(id).map(meta_bytes) {
            Some(b) => txn.put_local(&key, &b, Shred::No)?,
            None => txn.remove_local(&key, Shred::No).map(|_| ())?,
        }
    }
    Ok(())
}

/// Writes the given changes (`all`: everything) of the indexes to the persisted index.
fn write(tx: &mut Tx<'_>, all: bool) -> Result<()> {
    let c = &*tx.core;
    let txn = &mut tx.txn;
    let ids: Vec<CommitId> = if all { c.commits.keys().copied().collect() } else { c.commits.logged() };
    put_meta(txn, c, &ids)?;
    let k = if all { c.rotation_role.keys().cloned().collect() } else { c.rotation_role.logged() };
    put_map(txn, ROTATION_ROLE, &c.rotation_role, &k)?;
    let k = if all { c.grant_overreach.iter().cloned().collect() } else { c.grant_overreach.logged() };
    put_set(txn, GRANT_OVERREACH, &c.grant_overreach, &k)?;
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
    let mut old = Vec::new();
    tx.scan(b"i/", |k, _| {
        old.push([b"i/".as_slice(), k].concat());
        Ok(())
    })?;
    for k in old {
        tx.txn.remove_local(&k, Shred::Yes)?;
    }
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

fn scan<T: Rec>(tx: &mut Tx<'_>, prefix: &[u8]) -> Result<Vec<(T, Vec<u8>)>> {
    let mut out = Vec::new();
    tx.scan(prefix, |k, v| {
        out.push((dec(k)?, v));
        Ok(())
    })?;
    Ok(out)
}

/// Loads the persisted index into `core`: commit metas (headers resolved), and the indexes
/// derived from membership bodies.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut metas = Vec::new();
    tx.scan(META, |k, v| {
        let id = CommitId(k.try_into().map_err(|_| Error::Corrupt("index meta key"))?);
        metas.push((id, v));
        Ok(())
    })?;
    for (id, v) in metas {
        let (received, origin, dropped, valid, mut h) = meta_of(&v)?;
        if !h.is_resolved()
            && let Some(dedup) = tx.core.dedup(&h.actor)
        {
            h.resolve(&mut super::blobs::TxBlobs::new(&mut tx.txn), &dedup, osis_commit::MAX_LIST_BYTES).map_err(|_| Error::Corrupt("header lists"))?;
        }
        if h.id() != id {
            return Err(Error::Corrupt("index meta"));
        }
        let h = Arc::new(h);
        crate::apply::index_commit(tx.core, &id, &h);
        tx.core.commits.insert(id, Meta { header: h, received, origin, valid, dropped });
        tx.core.index_validity(&id);
    }
    for (k, v) in scan::<(CommitId, usize)>(tx, ROTATION_ROLE)? {
        tx.core.rotation_role.insert(k, dec(&v)?);
    }
    for (k, _) in scan::<(CommitId, usize)>(tx, GRANT_OVERREACH)? {
        tx.core.grant_overreach.insert(k);
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

fn meta_bytes(m: &Meta) -> Vec<u8> {
    let mut w = records::Wr::new().u64(m.received.0).u8(match m.origin {
        Origin::Local => 0,
        Origin::Remote => 1,
    });
    w = w.u32(m.dropped.len() as u32);
    for (a, d) in &m.dropped {
        w = w.u32(*a as u32).u32(*d as u32);
    }
    w = w.u32(m.valid.len() as u32);
    for v in &m.valid {
        w = w.u8(u8::from(*v));
    }
    w.raw(&m.header.encode()).take()
}

/// A commit meta record: received, origin, dropped parts, validity, header.
type MetaRecord = (WallMs, Origin, BTreeSet<(usize, usize)>, Vec<bool>, osis_commit::Header);

fn meta_of(b: &[u8]) -> Result<MetaRecord> {
    let mut r = records::Rd::new(b);
    let received = WallMs(r.u64()?);
    let origin = if r.u8()? == 0 { Origin::Local } else { Origin::Remote };
    let mut dropped = BTreeSet::new();
    for _ in 0..r.u32()? {
        dropped.insert((r.u32()? as usize, r.u32()? as usize));
    }
    let mut valid = Vec::new();
    for _ in 0..r.u32()? {
        valid.push(r.u8()? != 0);
    }
    let h = osis_commit::Header::decode(r.rest()).map_err(|_| Error::Corrupt("index header"))?;
    Ok((received, origin, dropped, valid, h))
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
