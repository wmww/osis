//! The persisted index (notes/local-store.md: a rebuildable index unit): what `apply::load`
//! would otherwise re-derive at every open by decoding every commit and re-judging every delta.
//! Each applied commit's meta (header and dropped parts in its record's head; per part its
//! validity, rotation role and overreach in a small table) and the indexes derived from
//! membership bodies (box keys, epoch introductions, own keys, snapshots, carried writes) are
//! written in the transaction that changes them, from the journal of the in-memory indexes.
//! Tagged with a hash of the sources its judgments follow from (`build.rs`): a build with other
//! rules, a store without the tag, one whose commit records changed outside the indexes
//! (`invalidate`), or one that fails to decode rebuilds it from the commit records once (a full
//! re-judge).

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
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Whether the index on disk was written by a build with these rules.
const VERSION_KEY: &[u8] = b"i/v";
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/", env!("OSIS_INDEX_RULES"));
/// Per commit, one byte per part: bit 0 valid, bits 1-2 the rotation role it needs (0 none,
/// 1 read, 2 write, 3 admin), bit 3 a grant's overreach.
const PARTS: &[u8] = b"node/parts";
// The derived indexes live in rebuildable store index tables of their own (a node's local
// records table is not deepened by them).
const BOX_KEYS: &[u8] = b"node/box keys";
const BOXES_TO: &[u8] = b"node/boxes to";
const EPOCH_INTRO: &[u8] = b"node/epoch intro";
const BOX_WRITTEN: &[u8] = b"node/box written";
const OWN_KEYS: &[u8] = b"node/own keys";
const SNAPSHOTS: &[u8] = b"node/snapshots";
const CARRIED: &[u8] = b"node/carried";
const AUTHORS: &[u8] = b"node/authors";

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
impl Rec for osis_crdt::Source {
    fn to(&self) -> Value {
        Value::Bytes(match self.kind() {
            osis_crdt::SourceKind::Node(t) => t.as_bytes().to_vec(),
            osis_crdt::SourceKind::Commit(c) => c.0.to_vec(),
            osis_crdt::SourceKind::Derived(_) => Vec::new(),
        })
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::Bytes(b) = v else { return None };
        if let Ok(t) = <[u8; 15]>::try_from(b.as_slice()) {
            return Some(osis_crdt::Source::node(Tid::from_bytes(t)));
        }
        Some(osis_crdt::Source::commit(CommitId(b.as_slice().try_into().ok()?)))
    }
}
fn uints(v: &[u64]) -> Value {
    Value::List(v.iter().map(|c| uint(*c)).collect())
}
fn uints_of(v: &Value) -> Option<Vec<u64>> {
    let Value::List(x) = v else { return None };
    x.iter().map(|c| if let Value::Int(c) = c { u64::try_from(*c).ok() } else { None }).collect()
}
impl Rec for crate::apply::validity::Carried {
    fn to(&self) -> Value {
        Value::List(vec![self.snap.to(), self.src.to(), self.node.to(), self.ts.to(), uints(&self.ctrs), uints(&self.invalid)])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [snap, src, n, ts, ctrs, invalid] = x.as_slice() else { return None };
        Some(crate::apply::validity::Carried { snap: <CommitId as Rec>::from(snap)?, src: <osis_crdt::Source as Rec>::from(src)?, node: <Tid as Rec>::from(n)?, ts: <Ts as Rec>::from(ts)?, ctrs: uints_of(ctrs)?, invalid: uints_of(invalid)? })
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
impl<A: Rec, B: Rec, C: Rec, D: Rec> Rec for (A, B, C, D) {
    fn to(&self) -> Value {
        Value::List(vec![self.0.to(), self.1.to(), self.2.to(), self.3.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [a, b, c, d] = x.as_slice() else { return None };
        Some((A::from(a)?, B::from(b)?, C::from(c)?, D::from(d)?))
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

/// What of a commit its record holds ahead of its blob (version 1): received, origin, dropped
/// parts.
pub(crate) struct RecordHead {
    pub received: WallMs,
    pub origin: Origin,
    pub dropped: BTreeSet<(usize, usize)>,
}

pub(crate) fn record_head(m: &Meta) -> Vec<u8> {
    let mut w = records::Wr::new().u8(1).u64(m.received.0).u8(match m.origin {
        Origin::Local => 0,
        Origin::Remote => 1,
    });
    w = w.u32(m.dropped.len() as u32);
    for (a, d) in &m.dropped {
        w = w.u32(*a as u32).u32(*d as u32);
    }
    w.take()
}

/// A commit's `PARTS` row.
fn parts_row(core: &Core, id: &CommitId, m: &Meta) -> Vec<u8> {
    let mut out = Vec::with_capacity(m.valid.len());
    for (ai, v) in m.valid.iter().enumerate() {
        let role = match core.rotation_role.get(&(*id, ai)) {
            None => 0,
            Some(Role::Read) => 1,
            Some(Role::Write) => 2,
            Some(Role::Admin) => 3,
        };
        out.push(u8::from(*v) | (role << 1) | (u8::from(core.grant_overreach.contains(&(*id, ai))) << 3));
    }
    out
}

/// A commit record's head and its blob bytes (version 2 heads, of earlier builds, carry part
/// bytes, skipped).
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
    if version == 2 {
        for _ in 0..r.u32()? {
            r.u8()?;
        }
    }
    Ok((RecordHead { received, origin, dropped }, r.rest()))
}

/// Writes the given changes (`all`: everything) of the indexes to the persisted index.
fn write(tx: &mut Tx<'_>, all: bool) -> Result<()> {
    let c = &*tx.core;
    let txn = &mut tx.txn;
    // a commit's parts row carries their validity, rotation roles and grant overreach
    let ids: Vec<CommitId> = if all {
        c.commits.keys().copied().collect()
    } else {
        let mut s: BTreeSet<CommitId> = c.commits.logged().into_iter().collect();
        s.extend(c.rotation_role.logged().into_iter().map(|k| k.0));
        s.extend(c.grant_overreach.logged().into_iter().map(|k| k.0));
        s.into_iter().collect()
    };
    if !ids.is_empty() {
        let t = txn.index(PARTS)?;
        for id in &ids {
            match c.commits.get(id) {
                Some(m) => txn.table_put(t, &id.0, parts_row(c, id, m), Shred::No)?,
                None => txn.table_remove(t, &id.0, Shred::No)?,
            };
        }
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
    let k = if all { c.authors.keys().cloned().collect() } else { c.authors.logged() };
    put_map(txn, AUTHORS, &c.authors, &k)?;
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

/// What the persisted index judged, read before a rebuild replaces it: per commit its parts'
/// validity, per aspect its carried groups. `None` when it does not decode.
pub(crate) type OldJudgments = (BTreeMap<CommitId, Vec<bool>>, BTreeMap<(Tid, osis_core::Ak), Vec<crate::apply::validity::Carried>>);

pub(crate) fn old_judgments(tx: &mut Tx<'_>) -> Option<OldJudgments> {
    let mut parts = BTreeMap::new();
    let t = tx.txn.index(PARTS).ok()?;
    let mut from = Vec::new();
    loop {
        let got = tx.txn.table_range(t, &from, None, 256).ok()?;
        let n = got.len();
        for (k, v) in got {
            from = [k.as_slice(), &[0]].concat();
            parts.insert(CommitId(k.as_slice().try_into().ok()?), v.iter().map(|p| p & 1 != 0).collect());
        }
        if n < 256 {
            break;
        }
    }
    let mut carried = BTreeMap::new();
    for (k, v) in scan::<(Tid, osis_core::Ak)>(tx, CARRIED).ok()? {
        carried.insert(k, dec(&v).ok()?);
    }
    Some((parts, carried))
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
    let mut rows: BTreeMap<CommitId, Vec<u8>> = BTreeMap::new();
    let t = tx.txn.index(PARTS)?;
    let mut from = Vec::new();
    loop {
        let got = tx.txn.table_range(t, &from, None, 256)?;
        let n = got.len();
        for (k, v) in got {
            from = [k.as_slice(), &[0]].concat();
            rows.insert(CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("parts row key"))?), v);
        }
        if n < 256 {
            break;
        }
    }
    for (id, head, mut h) in metas {
        let parts = rows.remove(&id).ok_or(Error::Corrupt("parts row missing"))?;
        if parts.len() != h.aspects.len() {
            return Err(Error::Corrupt("parts row"));
        }
        let mut valid = Vec::with_capacity(parts.len());
        for (ai, p) in parts.into_iter().enumerate() {
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
    for (k, v) in scan::<(Tid, CommitId)>(tx, AUTHORS)? {
        tx.core.authors.insert(k, dec(&v)?);
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
        let _ = writeln!(out, "secrets {:?}\nvoid {:?}\nvalueless {:?}\nsnapshots {:?}\ncarried {:?}\nauthors {:?}", *c.secrets, *c.void, *c.valueless, *c.snapshots, *c.carried, *c.authors);
        out
    }

    /// Damages the persisted index (tests): `garble` a commit's parts row, else mislabel its tag.
    #[doc(hidden)]
    pub fn damage_index(&mut self, garble: bool) -> Result<()> {
        if !garble {
            // another build's rules judged differently: every part valid, nothing carried, and
            // the states joined so
            return self.run(|tx| {
                let aspects: Vec<(Tid, osis_core::Ak)> = tx.core.invalid.keys().cloned().chain(tx.core.carried.keys().cloned()).collect();
                for (tid, ak) in aspects {
                    let held: Vec<CommitId> = tx.core.by_aspect.get(&(tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
                    let mut st = osis_crdt::Fragment::default();
                    for c in held {
                        let Some(ai) = tx.core.commits.get(&c).and_then(|m| m.header.aspects.iter().position(|a| a.tid == tid && a.ak == ak)) else { continue };
                        for d in crate::apply::held_parts(tx, &c, ai)? {
                            st.join(match d {
                                osis_commit::Decoded::Delta(x) => x.fragment,
                                osis_commit::Decoded::Snapshot(x) => x.fragment,
                            });
                        }
                    }
                    tx.set_state(&tid, &ak, (!st.is_empty()).then_some(st), Shred::No, false)?;
                }
                let t = tx.txn.index(PARTS)?;
                let rows: Vec<(CommitId, usize)> = tx.core.commits.iter().map(|(id, m)| (*id, m.valid.len())).collect();
                for (id, n) in rows {
                    tx.txn.table_put(t, &id.0, vec![1; n], Shred::No)?;
                }
                let t = tx.txn.index(CARRIED)?;
                let keys: Vec<(Tid, osis_core::Ak)> = tx.core.carried.keys().cloned().collect();
                for k in keys {
                    tx.txn.table_remove(t, &enc(&k), Shred::No)?;
                }
                tx.txn.put_local(VERSION_KEY, b"another build", Shred::No).map_err(Error::from)
            });
        }
        self.run(|tx| {
            if garble {
                let Some(id) = tx.core.commits.keys().next().copied() else { return Ok(()) };
                let t = tx.txn.index(PARTS)?;
                tx.txn.table_put(t, &id.0, vec![1; 300], Shred::No)?;
                Ok(())
            } else {
                tx.txn.put_local(VERSION_KEY, b"another build", Shred::No).map_err(Error::from)
            }
        })
    }

    /// Whether the persisted index is tagged as this build's (tests).
    #[doc(hidden)]
    pub fn index_current(&mut self) -> Result<bool> {
        self.run(current)
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
