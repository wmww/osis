//! The persisted index (notes/local-store.md: a rebuildable index unit): what `apply::load`
//! would otherwise re-derive at every open by decoding every commit and re-judging every delta.
//! Each applied commit's meta (header and dropped parts in its record's head; per part its
//! validity, rotation role and overreach in a small table), the indexes derived from
//! membership bodies (box keys, epoch introductions, own keys, snapshots, carried writes) and
//! perm's reading of each membership commit's held parts (`EDGES`, written with the commit
//! record) are written in the transaction that changes them, from the journal of the in-memory
//! indexes.
//! Tagged with a hash of the sources its judgments follow from (`build.rs`): a build with other
//! rules, a store without the tag, one whose commit records changed outside the indexes
//! (`invalidate`), or one that fails to decode rebuilds it from the commit records once (a full
//! re-judge).

use super::journal::{JMap, JSet, JSetMap};
use super::{Core, Meta, Tx, records, scan_table};
use osis_store::Transaction;
use crate::error::{Error, Result};
use crate::events::Origin;
use osis_base::{CommitId, Role, Tid, Ts, Value, WallMs};
use osis_crdt::Dot;
use osis_schema::Codec;
use osis_schema::core_types::BoxKey;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Whether the index on disk was written by a build with these rules.
pub(super) const VERSION_KEY: &[u8] = b"i/v";
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/", env!("OSIS_INDEX_RULES"));
/// Per commit (`meta_row`): one byte per part (bit 0 valid, bits 1-2 the rotation role it
/// needs: 0 none, 1 read, 2 write, 3 admin; bit 3 a grant's overreach), then its header's
/// `View` (a membership commit's frontier and every chunk list with it), so an open indexes and adapts the commit
/// without decoding its header.
pub(super) const METAS: &[u8] = b"node/metas";
// The derived indexes live in rebuildable store index tables of their own (a node's local
// records table is not deepened by them).
const BOXES_TO: &[u8] = b"node/boxes to";
const EPOCH_INTRO: &[u8] = b"node/epoch intro";
const BOX_WRITTEN: &[u8] = b"node/box written";
const OWN_KEYS: &[u8] = b"node/own keys";
const DELETE_HINTS: &[u8] = b"node/delete hints";
const SNAPSHOTS: &[u8] = b"node/snapshots";
pub(super) const CARRIED: &[u8] = b"node/carried";
const IMPORTS: &[u8] = b"node/imports";
/// Per membership commit, what perm's adaptation reads of its held `/members` and `/tenures`
/// parts (`validity::EdgeParts`): written with the commit record (`Tx::put_commit`), so an open
/// adapts these rows instead of decoding the bodies.
pub(super) const EDGES: &[u8] = b"node/edges";
/// Saved membership walks (osis-perm `Timelines::to_save`), by component root: a cache unit
/// tagged with these rules and its exact inputs; one that does not match is evaluated anew.
pub(super) const WALKS: &[u8] = b"node/walks";
/// Components with fewer commits and snapshots are evaluated at open rather than saved.
pub(crate) const WALK_CACHE_MIN: usize = 64;

/// A record key or value of the persisted index.
pub(super) trait Rec: Sized {
    fn to(&self) -> Value;
    fn from(v: &Value) -> Option<Self>;
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
        Value::uint(*self as u64)
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
        Value::uint(self.to_u64())
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
impl Rec for osis_base::Ak {
    fn to(&self) -> Value {
        Value::Str(self.as_str().to_string())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Str(s) => osis_base::Ak::new(s).ok(),
            _ => None,
        }
    }
}
impl Rec for osis_crdt::Frontiers {
    fn to(&self) -> Value {
        Value::List(self.0.iter().map(|(t, c)| Value::List(vec![t.to(), Value::uint(*c)])).collect())
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
    Value::List(v.iter().map(|c| Value::uint(*c)).collect())
}
fn uints_of(v: &Value) -> Option<Vec<u64>> {
    let Value::List(x) = v else { return None };
    x.iter().map(|c| if let Value::Int(c) = c { u64::try_from(*c).ok() } else { None }).collect()
}
impl Rec for crate::apply::validity::Carried {
    fn to(&self) -> Value {
        Value::List(vec![self.snap.to(), self.src.to(), uints(&self.ctrs)])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [snap, src, ctrs] = x.as_slice() else { return None };
        Some(crate::apply::validity::Carried { snap: <CommitId as Rec>::from(snap)?, src: <osis_crdt::Source as Rec>::from(src)?, ctrs: uints_of(ctrs)? })
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

impl Rec for osis_perm::Point {
    fn to(&self) -> Value {
        Value::List(vec![self.ts.to(), self.node.to(), self.commit.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let (ts, node, commit) = Rec::from(v)?;
        Some(osis_perm::Point { ts, node, commit })
    }
}
impl<T: Rec> Rec for Option<T> {
    fn to(&self) -> Value {
        Value::List(self.iter().map(Rec::to).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::List(l) if l.is_empty() => Some(None),
            Value::List(l) if l.len() == 1 => Some(Some(T::from(l.first()?)?)),
            _ => None,
        }
    }
}
impl Rec for osis_perm::Edge {
    fn to(&self) -> Value {
        Value::List(vec![self.role.to(), self.until.map(|u| u.0).to(), self.invite.to(), self.since.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [role, until, invite, since] = x.as_slice() else { return None };
        let until = <Option<u64> as Rec>::from(until)?.map(WallMs);
        let e = osis_perm::Edge { role: Rec::from(role)?, until, invite: Rec::from(invite)?, since: Rec::from(since)? };
        // as `validity::edge_of` reads them
        e.well_formed().then_some(e)
    }
}
impl Rec for u64 {
    fn to(&self) -> Value {
        Value::uint(*self)
    }
    fn from(v: &Value) -> Option<Self> {
        match v {
            Value::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }
}

impl Rec for crate::apply::validity::EdgeParts {
    fn to(&self) -> Value {
        use crate::apply::validity::EdgePart;
        Value::List(
            self.0
                .iter()
                .map(|(ai, p)| match p {
                    EdgePart::Members(es) => Value::List(vec![
                        Value::uint(*ai as u64),
                        Value::Int(0),
                        Value::List(
                            es.iter()
                                .map(|(d, k, v)| {
                                    let v = match v {
                                        None => Value::Int(0),
                                        Some(v) => v.to(),
                                    };
                                    Value::List(vec![records::dot_value(d), k.to(), v])
                                })
                                .collect(),
                        ),
                    ]),
                    EdgePart::Tenures(ts) => Value::List(vec![Value::uint(*ai as u64), Value::Int(1), Value::List(ts.clone())]),
                })
                .collect(),
        )
    }
    fn from(v: &Value) -> Option<Self> {
        use crate::apply::validity::EdgePart;
        let Value::List(x) = v else { return None };
        let mut out = Vec::with_capacity(x.len());
        for p in x {
            let Value::List(p) = p else { return None };
            let [ai, kind, Value::List(items)] = p.as_slice() else { return None };
            let ai = <usize as Rec>::from(ai)?;
            out.push((
                ai,
                match kind {
                    Value::Int(0) => EdgePart::Members(
                        items
                            .iter()
                            .map(|e| {
                                let Value::List(e) = e else { return None };
                                let [d, k, v] = e.as_slice() else { return None };
                                let v = match v {
                                    Value::Int(0) => None,
                                    v => Some(Rec::from(v)?),
                                };
                                Some((records::dot_of(d).ok()?, Rec::from(k)?, v))
                            })
                            .collect::<Option<Vec<_>>>()?,
                    ),
                    Value::Int(1) => EdgePart::Tenures(items.clone()),
                    _ => return None,
                },
            ));
        }
        Some(crate::apply::validity::EdgeParts(out))
    }
}

pub(super) fn enc<T: Rec>(x: &T) -> Vec<u8> {
    osis_base::encode(&x.to())
}

fn dec<T: Rec>(b: &[u8]) -> Result<T> {
    let lim = osis_base::Limits { max_depth: 16, max_bytes: b.len() };
    let v = osis_base::decode(b, &lim).map_err(|_| Error::Corrupt("index record"))?;
    T::from(&v).ok_or(Error::Corrupt("index record"))
}

/// Writes the rows of `keys` (`value`: a key's row value, `None` to remove it) to index `name`.
fn put_rows<K: Rec>(txn: &mut Transaction<'_>, name: &[u8], keys: Vec<K>, value: impl Fn(&K) -> Option<Vec<u8>>) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let t = txn.index(name)?;
    for k in &keys {
        match value(k) {
            Some(v) => txn.table_put(t, &enc(k), v, Shred::No)?,
            None => txn.table_remove(t, &enc(k), Shred::No)?,
        };
    }
    Ok(())
}

/// Writes what the running transaction changed of `m` (`all`: every entry) to index `name`.
fn put_map<K: Rec + Ord + Clone, V: Rec + Clone>(txn: &mut Transaction<'_>, name: &[u8], m: &JMap<K, V>, all: bool) -> Result<()> {
    let keys = if all { m.keys().cloned().collect() } else { m.logged() };
    put_rows(txn, name, keys, |k| m.get(k).map(enc))
}

/// `put_map` of a set: a row per item.
fn put_set<T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, name: &[u8], s: &JSet<T>, all: bool) -> Result<()> {
    let items = if all { s.iter().cloned().collect() } else { s.logged() };
    put_rows(txn, name, items, |t| s.contains(t).then(Vec::new))
}

/// `put_map` of a map of sets: a row per (key, item).
fn put_setmap<K: Rec + Ord + Clone, T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, name: &[u8], s: &JSetMap<K, T>, all: bool) -> Result<()> {
    let items = if all { s.iter().flat_map(|(k, x)| x.iter().map(|t| (k.clone(), t.clone()))).collect() } else { s.logged() };
    put_rows(txn, name, items, |(k, t)| s.get(k).is_some_and(|x| x.contains(t)).then(Vec::new))
}

/// Writes a membership commit's `EDGES` row (with its record).
pub(crate) fn put_edges(tx: &mut Tx<'_>, id: &CommitId, parts: &crate::apply::validity::EdgeParts, shred: Shred) -> Result<()> {
    let t = tx.txn.index(EDGES)?;
    tx.txn.table_put(t, &id.0, enc(parts), shred)?;
    Ok(())
}

/// Removes a commit's `EDGES` row, shredded (with its record).
pub(crate) fn remove_edges(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let t = tx.txn.index(EDGES)?;
    tx.txn.table_remove(t, &id.0, Shred::Yes)?;
    Ok(())
}

/// Every membership commit's `EDGES` row, from its record (after a rebuild).
fn write_edges_all(tx: &mut Tx<'_>) -> Result<()> {
    let ids: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_membership()).map(|(id, _)| *id).collect();
    for id in ids {
        let parts = crate::apply::edge_parts(tx, &id)?;
        put_edges(tx, &id, &parts, Shred::No)?;
    }
    Ok(())
}

/// The `EDGES` rows of the held membership commits; an error when one is missing or does not
/// decode (the open then rebuilds).
pub(crate) fn load_edges(tx: &mut Tx<'_>) -> Result<BTreeMap<CommitId, crate::apply::validity::EdgeParts>> {
    let _s = crate::costs::span("open: edges rows");
    let t = tx.txn.index(EDGES)?;
    let lim = |n: usize| osis_base::Limits { max_depth: 2 * osis_base::format::MAX_OBJECT_DEPTH, max_bytes: n };
    let mut out = BTreeMap::new();
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        let id = CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("edges row key"))?);
        let v = osis_base::decode(&v, &lim(v.len())).map_err(|_| Error::Corrupt("edges row"))?;
        out.insert(id, Rec::from(&v).ok_or(Error::Corrupt("edges row"))?);
        Ok(())
    })?;
    Ok(out)
}

/// What of a commit its record holds ahead of its blob (version 1): received, origin, dropped
/// parts and what each keeps (`Meta::dropped`).
pub(crate) struct RecordHead {
    pub received: WallMs,
    pub origin: Origin,
    pub dropped: BTreeMap<usize, super::Dropped>,
}

pub(crate) fn record_head(m: &Meta) -> Vec<u8> {
    let mut w = records::Wr::new().u8(1).u64(m.received.0).u8(match m.origin {
        Origin::Local => 0,
        Origin::Remote => 1,
    });
    w = w.u32(m.dropped.len() as u32);
    for (a, d) in &m.dropped {
        let role = match d.role {
            None => 0,
            Some(Role::Read) => 1,
            Some(Role::Write) => 2,
            Some(Role::Admin) => 3,
        };
        w = w.u32(*a as u32).u8(u8::from(d.as_cover) | u8::from(d.live) << 1 | role << 2 | u8::from(d.overreach) << 4).u32(d.covered_by.len() as u32);
        for s in &d.covered_by {
            w = w.raw(&s.0);
        }
        let Some((fr, abs)) = &d.gives else {
            w = w.u8(0);
            continue;
        };
        w = w.u8(1).u32(fr.0.len() as u32);
        for (n, c) in &fr.0 {
            w = w.raw(n.as_bytes()).u64(*c);
        }
        w = w.u32(abs.len() as u32);
        for (c, n) in abs {
            w = w.raw(&c.0).raw(n.as_bytes());
        }
    }
    w.take()
}

/// A commit's `METAS` row: version 1, the part count, a byte per part, the view.
pub(super) fn meta_row(core: &Core, id: &CommitId, m: &Meta) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 48 * m.valid.len());
    out.push(1);
    out.extend_from_slice(&(m.valid.len() as u32).to_be_bytes());
    for (ai, v) in m.valid.iter().enumerate() {
        let role = match core.ix.rotation_role.get(&(*id, ai)) {
            None => 0,
            Some(Role::Read) => 1,
            Some(Role::Write) => 2,
            Some(Role::Admin) => 3,
        };
        out.push(u8::from(*v) | (role << 1) | (u8::from(core.ix.grant_overreach.contains(&(*id, ai))) << 3) | (u8::from(m.missing.contains(&ai)) << 4));
    }
    let v = &m.view;
    let mut w = records::Wr(out).u64(v.ts.to_u64()).u8(v.kind.id() as u8).u8(match v.form {
        osis_commit::Form::Node => 0,
        osis_commit::Form::Commit => 1,
    });
    w = w.raw(v.author.as_bytes()).raw(v.actor.as_bytes()).u8(u8::from(v.linked));
    for a in &v.aspects {
        let ak = a.ak.as_str().as_bytes();
        w = w.raw(a.tid.as_bytes()).raw(&(ak.len() as u16).to_be_bytes()).raw(ak).u64(a.lo).u64(a.hi).u8(u8::from(a.bounded));
    }
    w = w.u32(v.chunks.len() as u32);
    for b in &v.chunks {
        w = w.raw(&b.0);
    }
    match &v.frontier {
        None => w = w.u8(0),
        Some(f) => {
            let f = osis_schema::core_types::Frontier { writes: f.writes.clone(), commits: f.commits.clone() };
            w = w.u8(1).bytes(&osis_base::encode(&f.to_value()));
        }
    }
    w.take()
}

/// A `METAS` row's part bytes and view.
fn parse_meta_row(row: &[u8]) -> Result<(&[u8], super::View)> {
    let mut r = records::Rd::new(row);
    if r.u8()? != 1 {
        return Err(Error::Corrupt("meta row version"));
    }
    let n = r.u32()? as usize;
    let parts = r.take(n)?;
    let ts = Ts::from_u64(r.u64()?).ok_or(Error::Corrupt("meta row ts"))?;
    let kind = osis_commit::Kind::from_id(<u64 as From<u8>>::from(r.u8()?)).ok_or(Error::Corrupt("meta row kind"))?;
    let form = match r.u8()? {
        0 => osis_commit::Form::Node,
        1 => osis_commit::Form::Commit,
        _ => return Err(Error::Corrupt("meta row form")),
    };
    let (author, actor) = (r.tid()?, r.tid()?);
    let linked = r.u8()? != 0;
    let mut aspects = Vec::with_capacity(n);
    for _ in 0..n {
        let (tid, ak) = (r.tid()?, r.ak()?);
        aspects.push(super::AspectView { tid, ak, lo: r.u64()?, hi: r.u64()?, bounded: r.u8()? != 0 });
    }
    let mut chunks = Vec::new();
    for _ in 0..r.u32()? {
        chunks.push(osis_base::BlobId(r.arr()?));
    }
    let frontier = match r.u8()? {
        0 => None,
        1 => {
            let b = r.bytes()?;
            let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
            let v = osis_base::decode(b, &lim).map_err(|_| Error::Corrupt("meta row frontier"))?;
            let f = osis_schema::core_types::Frontier::from_value(&v).map_err(|_| Error::Corrupt("meta row frontier"))?;
            Some(Arc::new(osis_perm::Frontier { writes: f.writes, commits: f.commits }))
        }
        _ => return Err(Error::Corrupt("meta row frontier")),
    };
    r.end()?;
    Ok((parts, super::View { ts, kind, form, author, actor, linked, aspects, frontier, chunks }))
}

/// A commit record's head and its blob bytes.
pub(crate) fn parse_head(v: &[u8]) -> Result<(RecordHead, &[u8])> {
    let mut r = records::Rd::new(v);
    if r.u8()? != 1 {
        return Err(Error::Corrupt("commit record version"));
    }
    let received = WallMs(r.u64()?);
    let origin = if r.u8()? == 0 { Origin::Local } else { Origin::Remote };
    let mut dropped = BTreeMap::new();
    for _ in 0..r.u32()? {
        let a = r.u32()? as usize;
        let flags = r.u8()?;
        let mut covered_by = BTreeSet::new();
        for _ in 0..r.u32()? {
            covered_by.insert(CommitId(r.arr()?));
        }
        let gives = match r.u8()? {
            0 => None,
            _ => {
                let mut fr = BTreeMap::new();
                for _ in 0..r.u32()? {
                    let n = r.tid()?;
                    fr.insert(n, r.u64()?);
                }
                let mut abs = Vec::new();
                for _ in 0..r.u32()? {
                    abs.push((CommitId(r.arr()?), r.tid()?));
                }
                Some((osis_crdt::Frontiers(fr), abs))
            }
        };
        let role = [Role::Read, Role::Write, Role::Admin].get(<usize as From<u8>>::from((flags >> 2) & 3).wrapping_sub(1)).copied();
        dropped.insert(a, super::Dropped { covered_by, as_cover: flags & 1 != 0, live: flags & 2 != 0, gives, role, overreach: flags & 16 != 0 });
    }
    Ok((RecordHead { received, origin, dropped }, r.rest()))
}

/// Writes the given changes (`all`: everything) of the indexes to the persisted index.
fn write(tx: &mut Tx<'_>, all: bool) -> Result<()> {
    let c = &*tx.core;
    let txn = &mut tx.txn;
    // a commit's parts row carries their validity, rotation roles and grant overreach
    let ids: Vec<CommitId> = if all {
        c.ix.commits.keys().copied().collect()
    } else {
        let mut s: BTreeSet<CommitId> = c.ix.commits.logged().into_iter().collect();
        s.extend(c.ix.rotation_role.logged().into_iter().map(|k| k.0));
        s.extend(c.ix.grant_overreach.logged().into_iter().map(|k| k.0));
        s.into_iter().collect()
    };
    if !ids.is_empty() {
        let t = txn.index(METAS)?;
        for id in &ids {
            match c.ix.commits.get(id) {
                Some(m) => txn.table_put(t, &id.0, meta_row(c, id, m), Shred::No)?,
                None => txn.table_remove(t, &id.0, Shred::No)?,
            };
        }
    }
    put_setmap(txn, BOXES_TO, &c.ix.boxes_to, all)?;
    put_map(txn, EPOCH_INTRO, &c.ix.epoch_intro, all)?;
    put_map(txn, BOX_WRITTEN, &c.ix.box_written, all)?;
    put_set(txn, OWN_KEYS, &c.ix.own_keys, all)?;
    put_map(txn, DELETE_HINTS, &c.ix.delete_hints, all)?;
    put_map(txn, SNAPSHOTS, &c.ix.snapshots, all)?;
    put_map(txn, CARRIED, &c.ix.carried, all)?;
    put_setmap(txn, IMPORTS, &c.ix.imports, all)?;
    // after the indexes and in their transaction: a saved walk never runs ahead of the
    // commits it covers
    let min = tx.core.walk_cache_min;
    let mut saves = tx.core.timelines.to_save(VERSION.as_bytes(), min, all);
    // `Timelines::saved` once the transaction is durable (`Engine::run`)
    tx.core.walks_done = Some(std::mem::take(&mut saves.done));
    if !saves.put.is_empty() || !saves.delete.is_empty() {
        // shredded: a walk may name writes no longer held (rare, amortized: one root write)
        let t = tx.txn.index(WALKS)?;
        for r in saves.delete {
            tx.txn.table_remove(t, r.as_bytes(), Shred::Yes)?;
        }
        for (r, bytes) in saves.put {
            tx.txn.table_put(t, r.as_bytes(), bytes, Shred::Yes)?;
        }
    }
    Ok(())
}

/// `Core::update_timelines` at open: components restored from their saved walks where those
/// match (else evaluated); a unit that does not read is evaluated anew, never an error.
pub(crate) fn update_timelines_saved(tx: &mut Tx<'_>) -> Result<()> {
    let touched = tx.core.ix.held.take_touched();
    let t = tx.txn.index(WALKS)?;
    let txn = &mut tx.txn;
    let core = &mut *tx.core;
    let changed = core.timelines.update_touched_cached(&core.ix.held, &touched, &mut |r| txn.table_get(t, r.as_bytes()).ok().flatten(), VERSION.as_bytes());
    core.stale_things.extend(changed.evaluated);
    let below = core.ix.held.reach(&changed.extended);
    core.stale_things.extend(below);
    core.membership_changed();
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
    write_edges_all(tx)?;
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
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        out.push((dec(&k)?, v));
        Ok(())
    })?;
    Ok(out)
}

/// What the persisted index judged, read before a rebuild replaces it: per commit its parts'
/// validity. `None` when it does not decode.
pub(crate) type OldJudgments = BTreeMap<CommitId, Vec<bool>>;

pub(crate) fn old_judgments(tx: &mut Tx<'_>) -> Option<OldJudgments> {
    let mut parts = BTreeMap::new();
    let t = tx.txn.index(METAS).ok()?;
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        let p = parse_meta_row(&v)?.0;
        let id = CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("meta row key"))?);
        parts.insert(id, p.iter().map(|p| p & 1 != 0).collect());
        Ok(())
    })
    .ok()?;
    Some(parts)
}

/// Loads the persisted index into `core`: commit metas (headers held undecoded, decoded on
/// first use; those with lists by link resolved now), and the indexes derived from membership
/// bodies.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    // commit records: the head and the header's bytes only, nothing decoded
    let hs = crate::costs::span("open: headers");
    let mut recs = Vec::new();
    tx.scan(records::COMMIT, |k, v| {
        let id = CommitId(k.try_into().map_err(|_| Error::Corrupt("commit record key"))?);
        let (head, blob) = parse_head(&v)?;
        // the blob is `[header, signature, parts]`: its first item
        let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: blob.len() };
        let hb = osis_base::item_prefix(blob.get(1..).unwrap_or_default(), &lim).map_err(|_| Error::Corrupt("commit record header"))?;
        recs.push((id, head, Box::<[u8]>::from(hb)));
        Ok(())
    })?;
    drop(hs);
    let _ms = crate::costs::span("open: metas");
    let mut rows: BTreeMap<CommitId, Vec<u8>> = BTreeMap::new();
    let t = tx.txn.index(METAS)?;
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        rows.insert(CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("meta row key"))?), v);
        Ok(())
    })?;
    let fault = tx.core.header_fault.clone();
    for (id, head, bytes) in recs {
        let row = rows.remove(&id).ok_or(Error::Corrupt("meta row missing"))?;
        let (parts, view) = parse_meta_row(&row)?;
        let mut valid = Vec::with_capacity(parts.len());
        let mut missing = BTreeSet::new();
        for (ai, p) in parts.iter().enumerate() {
            valid.push(p & 1 != 0);
            if p & 16 != 0 {
                missing.insert(ai);
            }
            if let Some(r) = [Role::Read, Role::Write, Role::Admin].get(<usize as From<u8>>::from((p >> 1) & 3).wrapping_sub(1)) {
                tx.core.ix.rotation_role.insert((id, ai), *r);
            }
            if p & 8 != 0 {
                tx.core.ix.grant_overreach.insert((id, ai));
            }
        }
        let view = Arc::new(view);
        let header = if view.linked || cfg!(debug_assertions) {
            // lists by link resolve from blobs now; a debug build decodes every header and
            // checks the persisted view against it
            let mut h = super::decode_stored_header(&id, &bytes).ok_or(Error::Corrupt("commit record header"))?;
            if !h.is_resolved()
                && let Some(dedup) = tx.core.dedup(&h.actor)
            {
                h.resolve(&mut super::blobs::TxBlobs::new(&mut tx.txn), &dedup, osis_commit::MAX_LIST_BYTES).map_err(|_| Error::Corrupt("header lists"))?;
            }
            debug_assert_eq!(super::View::of(&h), *view, "meta row of {id:?} is stale");
            if view.linked { super::LazyHeader::ready(Arc::new(h)) } else { super::LazyHeader::stored(id, bytes, view.clone(), fault.clone()) }
        } else {
            super::LazyHeader::stored(id, bytes, view.clone(), fault.clone())
        };
        if view.aspects.len() != valid.len() {
            return Err(Error::Corrupt("meta row"));
        }
        crate::apply::index_commit(tx.core, &id, &view);
        tx.core.ix.commits.insert(id, Meta { view, header, received: head.received, origin: head.origin, valid, dropped: head.dropped, missing });
        crate::apply::note_gives(tx.core, &id);
        tx.core.index_validity(&id);
    }
    drop(_ms);
    for ((m, x), _) in scan::<(Tid, (Tid, Value))>(tx, BOXES_TO)? {
        tx.core.ix.boxes_to.insert(m, x);
    }
    for (k, v) in scan::<(Tid, Role, osis_crypto::Epoch)>(tx, EPOCH_INTRO)? {
        tx.core.ix.epoch_intro.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, BoxKey)>(tx, BOX_WRITTEN)? {
        tx.core.ix.box_written.insert(k, dec(&v)?);
    }
    for (k, _) in scan::<Tid>(tx, OWN_KEYS)? {
        tx.core.ix.own_keys.insert(k);
    }
    for (k, v) in scan::<Tid>(tx, DELETE_HINTS)? {
        tx.core.ix.delete_hints.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, osis_base::Ak)>(tx, SNAPSHOTS)? {
        tx.core.ix.snapshots.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, osis_base::Ak)>(tx, CARRIED)? {
        tx.core.ix.carried.insert(k, dec(&v)?);
    }
    for ((k, x), _) in scan::<((Tid, CommitId), CommitId)>(tx, IMPORTS)? {
        tx.core.ix.imports.insert(k, x);
    }
    Ok(())
}
