//! The persisted index (notes/local-store.md: a rebuildable index unit): what `apply::load`
//! would otherwise re-derive at every open by decoding every commit and re-judging every delta.
//! Each applied commit's meta (header and dropped parts in its record's head; per part its
//! validity, rotation role and overreach in a small table), the indexes derived from
//! role bodies (box keys, epoch introductions, own keys, snapshots) and
//! perm's reading of each role commit's held parts (`EDGES`, written with the commit
//! record) are written in the transaction that changes them, from the journal of the in-memory
//! indexes.
//! Tagged with a hash of the sources its judgments follow from (`build.rs`): a build with other
//! rules, a store without the tag, one whose commit records changed outside the indexes
//! (`invalidate`), or one that fails to decode rebuilds it from the commit records once (a full
//! re-judge).

use super::journal::{JMap, JSetMap};
use super::{Core, Meta, Tx, records, scan_table};
use osis_store::Transaction;
use crate::error::{Error, Result};
use crate::events::Origin;
use osis_base::{BlobId, CommitId, Role, Tid, Ts, Value, WallMs};
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
/// `View` (a role commit's frontier with it), so an open indexes and adapts the commit
/// without decoding its header.
pub(super) const METAS: &[u8] = b"node/metas";
// The derived indexes live in rebuildable store index tables of their own (a node's local
// records table is not deepened by them).
const BOXES_TO: &[u8] = b"node/boxes to";
const EPOCH_INTRO: &[u8] = b"node/epoch intro";
const KEYSETS: &[u8] = b"node/keysets";
const SEALED: &[u8] = b"node/sealed";
const DELETE_HINTS: &[u8] = b"node/delete hints";
const RETENTION: &[u8] = b"node/retention";
const ORIGINALS: &[u8] = b"node/originals";
const SNAPSHOTS: &[u8] = b"node/snapshots";
/// Per account with a rotation judged, what the epoch rule says of its commits
/// (`Indexes::epochs`): an open builds no signing chain.
const EPOCHS: &[u8] = b"node/epochs";
/// Per held rotation of an account, its inner and merge signatures as its blob carries them
/// (`Indexes::rotation_sigs`): what the signing chain reads, so an open reads no blob.
const ROTATION_SIGS: &[u8] = b"node/rotation sigs";
/// What each addendum commit says (`validity::AddendaParts`), by commit ID.
pub(super) const ADDENDA: &[u8] = b"node/addenda";
/// Per role commit, what perm's adaptation reads of its held `roles.0` parts (`validity::EdgeParts`): written with the commit record (`Tx::put_commit`), so an open
/// adapts these rows instead of decoding the bodies.
pub(super) const EDGES: &[u8] = b"node/edges";
/// Saved role walks (osis-perm `Timelines::to_save`), by component root: a cache unit
/// tagged with these rules and its exact inputs; one that does not match is evaluated anew.
pub(super) const WALKS: &[u8] = b"node/walks";
/// Components with fewer commits and snapshots are evaluated at open rather than saved.
pub(crate) const WALK_CACHE_MIN: usize = 64;

/// A record key or value of the persisted index.
pub(crate) trait Rec: Sized {
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
impl Rec for Arc<crate::engine::RotationSigs> {
    fn to(&self) -> Value {
        let inner = self.inner.as_ref().map_or(Value::bytes(&[]), |i| Value::bytes(i));
        Value::List(vec![inner, Value::List(self.merge.iter().map(|s| Value::bytes(&s.0)).collect())])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(top) = v else { return None };
        let [Value::Bytes(inner), Value::List(xs)] = top.as_slice() else { return None };
        let inner = if inner.is_empty() { None } else { Some(inner.as_slice().try_into().ok()?) };
        let merge = xs.iter().map(|x| match x {
            Value::Bytes(b) => Some(osis_crypto::Signature(b.as_slice().try_into().ok()?)),
            _ => None,
        }).collect::<Option<Vec<_>>>()?;
        Some(Arc::new(crate::engine::RotationSigs { inner, merge }))
    }
}
impl Rec for Arc<crate::flows::account::JudgedEpochs> {
    fn to(&self) -> Value {
        self.to_value()
    }
    fn from(v: &Value) -> Option<Self> {
        crate::flows::account::JudgedEpochs::from_value(v).map(Arc::new)
    }
}
impl Rec for super::HeldKeyset {
    fn to(&self) -> Value {
        let kem = Value::List(self.kem.iter().map(|k| Value::bytes(k.as_bytes())).collect());
        let lists: Vec<osis_crypto::Epoch> = self.lists.iter().copied().collect();
        let since = Value::List(self.since.iter().map(Rec::to).collect());
        let names = Value::List(self.names.iter().map(|(d, a)| Value::List(vec![Value::bytes(d), Value::bytes(a.as_bytes())])).collect());
        let left_out = by_holder_to(&self.left_out);
        let demotions = Value::List(self.demotions.iter().map(|c| Value::bytes(&c.0)).collect());
        Value::List(vec![lists.to(), kem, since, names, left_out, demotions, Value::Bool(self.demotes)])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(f) = v else { return None };
        let [lists, kem, since, names, left_out, Value::List(demotions), Value::Bool(demotes)] = f.as_slice() else { return None };
        let demotions = demotions.iter().map(|x| match x {
            Value::Bytes(b) => Some(osis_base::CommitId(<[u8; 32]>::try_from(b.as_slice()).ok()?)),
            _ => None,
        }).collect::<Option<BTreeSet<_>>>()?;
        let out = by_holder_from(left_out)?;
        let Value::List(names) = names else { return None };
        let names = names
            .iter()
            .map(|x| match x {
                Value::List(p) => match p.as_slice() {
                    [Value::Bytes(d), Value::Bytes(a)] => Some((<[u8; 32]>::try_from(d.as_slice()).ok()?, Tid::from_bytes(a.as_slice().try_into().ok()?))),
                    _ => None,
                },
                _ => None,
            })
            .collect::<Option<BTreeSet<_>>>()?;
        let since = match since {
            Value::List(x) => match x.as_slice() {
                [] => None,
                [p] => Some(Rec::from(p)?),
                _ => return None,
            },
            _ => return None,
        };
        let kem = match kem {
            Value::List(x) => match x.as_slice() {
                [] => None,
                [Value::Bytes(b)] => Some(osis_crypto::KemPublicKey::from_slice(b).ok()?),
                _ => return None,
            },
            _ => return None,
        };
        let lists: Vec<osis_crypto::Epoch> = Rec::from(lists)?;
        Some(super::HeldKeyset { lists: lists.into_iter().collect(), kem, since, names, left_out: out, demotions, demotes: *demotes })
    }
}
/// `[holder, epoch]` pairs of a by-holder set map.
fn by_holder_to(x: &BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>>) -> Value {
    Value::List(x.iter().flat_map(|(m, xs)| xs.iter().map(|x| Value::List(vec![Value::bytes(m.as_bytes()), x.to()]))).collect())
}
fn by_holder_from(x: &Value) -> Option<BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>>> {
    let Value::List(x) = x else { return None };
    let mut out: BTreeMap<Tid, BTreeSet<osis_crypto::Epoch>> = BTreeMap::new();
    for y in x {
        let Value::List(p) = y else { return None };
        let [Value::Bytes(m), e] = p.as_slice() else { return None };
        out.entry(Tid::from_bytes(m.as_slice().try_into().ok()?)).or_default().insert(Rec::from(e)?);
    }
    Some(out)
}
impl Rec for super::SealedAt {
    fn to(&self) -> Value {
        Value::List(vec![by_holder_to(&self.keysets), Value::List(self.by.iter().map(|c| Value::bytes(&c.0)).collect())])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(f) = v else { return None };
        let [keysets, Value::List(by)] = f.as_slice() else { return None };
        let by = by.iter().map(|x| match x {
            Value::Bytes(b) => Some(osis_base::CommitId(<[u8; 32]>::try_from(b.as_slice()).ok()?)),
            _ => None,
        }).collect::<Option<BTreeSet<_>>>()?;
        Some(super::SealedAt { keysets: by_holder_from(keysets)?, by })
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
        Value::List(self.sources().map(|(s, c)| Value::List(vec![s.to(), Value::uint(c)])).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let mut out = osis_crdt::Frontiers::default();
        for e in x {
            let (s, c) = <(osis_crdt::Source, usize) as Rec>::from(e)?;
            out.insert(&s, c as u64).then_some(())?;
        }
        Some(out)
    }
}
impl Rec for crate::retention::snapshot::Hull {
    fn to(&self) -> Value {
        Value::List(self.entries().map(|(s, (lo, hi))| Value::List(vec![s.to(), Value::uint(*lo), Value::uint(*hi)])).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let e = x.iter().map(|e| <(osis_crdt::Source, u64, u64) as Rec>::from(e).map(|(s, lo, hi)| (s, (lo, hi)))).collect::<Option<Vec<_>>>()?;
        Some(crate::retention::snapshot::Hull::of(e))
    }
}
impl Rec for crate::retention::snapshot::Carried {
    fn to(&self) -> Value {
        let (a, b) = self.hulls();
        Value::List(vec![a.to(), b.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let (a, b) = <(crate::retention::snapshot::Hull, crate::retention::snapshot::Hull) as Rec>::from(v)?;
        Some(crate::retention::snapshot::Carried::of(a, b))
    }
}
impl Rec for osis_crdt::Facts {
    fn to(&self) -> Value {
        let row = |((ts, src), f): (&(Ts, osis_crdt::Source), &osis_crdt::Fact)| Value::List(vec![ts.to(), src.to(), Value::uint(f.by as u64), f.actor.to()]);
        Value::List(self.iter().map(row).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let mut out = osis_crdt::Facts::new();
        for e in x {
            let Value::List(r) = e else { return None };
            let [ts, src, by, actor] = r.as_slice() else { return None };
            let by = osis_base::PurgeBy::from_id(<u64 as Rec>::from(by)?)?;
            out.insert((<Ts as Rec>::from(ts)?, <osis_crdt::Source as Rec>::from(src)?), osis_crdt::Fact { by, actor: Rec::from(actor)? });
        }
        Some(out)
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
            osis_crdt::SourceKind::Session(s) => s.to_bytes().to_vec(),
            osis_crdt::SourceKind::Commit(c) => c.0.to_vec(),
            osis_crdt::SourceKind::Derived(_) => Vec::new(),
        })
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::Bytes(b) = v else { return None };
        if let Ok(s) = <[u8; 31]>::try_from(b.as_slice()) {
            return Some(osis_crdt::Source::session(osis_crdt::Session::from_bytes(&s)));
        }
        Some(osis_crdt::Source::commit(CommitId(b.as_slice().try_into().ok()?)))
    }
}
impl Rec for std::sync::Arc<osis_schema::core_types::RetentionSetting> {
    fn to(&self) -> Value {
        self.to_value()
    }
    fn from(v: &Value) -> Option<Self> {
        Codec::from_value(v).ok().map(std::sync::Arc::new)
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

impl<A: Rec, B: Rec, C: Rec, D: Rec, E: Rec> Rec for (A, B, C, D, E) {
    fn to(&self) -> Value {
        Value::List(vec![self.0.to(), self.1.to(), self.2.to(), self.3.to(), self.4.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [a, b, c, d, e] = x.as_slice() else { return None };
        Some((A::from(a)?, B::from(b)?, C::from(c)?, D::from(d)?, E::from(e)?))
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
        Value::List(vec![self.role.to(), self.until.map(|u| u.0).to(), self.invite.to(), self.tied.map(crate::flows::tied::tie_ct).as_ref().map(Codec::to_value).to(), self.floor.to()])
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let [role, until, invite, tied, floor] = x.as_slice() else { return None };
        let until = <Option<u64> as Rec>::from(until)?.map(WallMs);
        let tied = match <Option<Value> as Rec>::from(tied)? {
            None => None,
            Some(t) => Some(crate::flows::tied::tie_perm(osis_schema::core_types::Tie::from_value(&t).ok()?)),
        };
        Some(osis_perm::Edge { role: Rec::from(role)?, until, invite: Rec::from(invite)?, tied, floor: Rec::from(floor)? })
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

impl Rec for crate::apply::validity::AddendaParts {
    fn to(&self) -> Value {
        Value::List(self.0.iter().map(|(t, es)| Value::List(vec![t.to(), Value::List(es.iter().map(|(r, l)| Value::List(vec![r.to(), Value::List(l.iter().map(Rec::to).collect())])).collect())])).collect())
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let mut out = Vec::with_capacity(x.len());
        for p in x {
            let Value::List(p) = p else { return None };
            let [t, Value::List(items)] = p.as_slice() else { return None };
            let es = items
                .iter()
                .map(|e| {
                    let Value::List(e) = e else { return None };
                    let [r, Value::List(l)] = e.as_slice() else { return None };
                    Some((Rec::from(r)?, std::sync::Arc::new(l.iter().map(Rec::from).collect::<Option<_>>()?)))
                })
                .collect::<Option<Vec<_>>>()?;
            out.push((Rec::from(t)?, es));
        }
        Some(crate::apply::validity::AddendaParts(out))
    }
}

impl Rec for crate::apply::validity::EdgeParts {
    fn to(&self) -> Value {
        Value::List(
            self.0
                .iter()
                .map(|(ai, es)| {
                    let es = es
                        .iter()
                        .map(|(d, k, v)| {
                            let v = match v {
                                None => Value::Int(0),
                                Some(v) => v.to(),
                            };
                            Value::List(vec![records::dot_value(d), k.to(), v])
                        })
                        .collect();
                    Value::List(vec![Value::uint(*ai as u64), Value::List(es)])
                })
                .collect(),
        )
    }
    fn from(v: &Value) -> Option<Self> {
        let Value::List(x) = v else { return None };
        let mut out = Vec::with_capacity(x.len());
        for p in x {
            let Value::List(p) = p else { return None };
            let [ai, Value::List(items)] = p.as_slice() else { return None };
            let es = items
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
                .collect::<Option<Vec<_>>>()?;
            out.push((<usize as Rec>::from(ai)?, es));
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
fn put_map<K: Rec + Ord + Clone + std::hash::Hash + Send + Sync + 'static, V: Rec + Clone>(txn: &mut Transaction<'_>, name: &[u8], m: &JMap<K, V>, all: bool) -> Result<()> {
    let keys = if all { m.keys().cloned().collect() } else { m.logged() };
    put_rows(txn, name, keys, |k| m.get(k).map(enc))
}

/// `put_map` of a map keyed by aspect: a memory aspect's row is memory, whichever transaction
/// writes it.
fn put_aspect_map<V: Rec + Clone>(txn: &mut Transaction<'_>, name: &[u8], m: &JMap<(Tid, osis_base::Ak), V>, all: bool) -> Result<()> {
    let keys: Vec<(Tid, osis_base::Ak)> = if all { m.keys().cloned().collect() } else { m.logged() };
    if keys.is_empty() {
        return Ok(());
    }
    let mode = txn.is_memory();
    let (mem, dur): (Vec<_>, Vec<_>) = keys.into_iter().partition(|(_, a)| a.ephemeral());
    put_rows(txn, name, dur, |k| m.get(k).map(enc))?;
    txn.set_memory(true);
    let r = put_rows(txn, name, mem, |k| m.get(k).map(enc));
    txn.set_memory(mode);
    r
}

/// `put_map` of a map of sets: a row per (key, item).
fn put_setmap<K: Rec + Ord + Clone + std::hash::Hash + Send + Sync + 'static, T: Rec + Ord + Clone>(txn: &mut Transaction<'_>, name: &[u8], s: &JSetMap<K, T>, all: bool) -> Result<()> {
    let items = if all { s.iter().flat_map(|(k, x)| x.iter().map(|t| (k.clone(), t.clone()))).collect() } else { s.logged() };
    put_rows(txn, name, items, |(k, t)| s.get(k).is_some_and(|x| x.contains(t)).then(Vec::new))
}

/// Writes a role commit's `EDGES` row (with its record).
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

/// Writes an addendum commit's `ADDENDA` row (with its record).
pub(crate) fn put_addenda(tx: &mut Tx<'_>, id: &CommitId, parts: &crate::apply::validity::AddendaParts, shred: Shred) -> Result<()> {
    let t = tx.txn.index(ADDENDA)?;
    tx.txn.table_put(t, &id.0, enc(parts), shred)?;
    Ok(())
}

/// Removes a commit's `ADDENDA` row, shredded (with its record).
pub(crate) fn remove_addenda(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let t = tx.txn.index(ADDENDA)?;
    tx.txn.table_remove(t, &id.0, Shred::Yes)?;
    Ok(())
}

/// Every addendum's `ADDENDA` row, from the in-memory index (after a rebuild, which read the
/// bodies).
fn write_addenda_all(tx: &mut Tx<'_>) -> Result<()> {
    let ids: Vec<CommitId> = tx.core.ix.addenda.keys().map(|(_, c)| *c).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    for id in ids {
        let Some(aspects) = tx.core.ix.commits.get(&id).map(|m| m.view.aspects.clone()) else { continue };
        let parts = crate::apply::validity::AddendaParts::from_index(tx.core, &id, &aspects);
        put_addenda(tx, &id, &parts, Shred::No)?;
    }
    Ok(())
}

/// The `ADDENDA` rows (what each addendum commit says); an error when one does not decode (the
/// open then rebuilds).
pub(crate) fn load_addenda(tx: &mut Tx<'_>) -> Result<BTreeMap<CommitId, crate::apply::validity::AddendaParts>> {
    let t = tx.txn.index(ADDENDA)?;
    let lim = |n: usize| osis_base::Limits { max_depth: 2 * osis_base::format::MAX_OBJECT_DEPTH, max_bytes: n };
    let mut out = BTreeMap::new();
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        let id = CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("addenda row key"))?);
        let v = osis_base::decode(&v, &lim(v.len())).map_err(|_| Error::Corrupt("addenda row"))?;
        out.insert(id, Rec::from(&v).ok_or(Error::Corrupt("addenda row"))?);
        Ok(())
    })?;
    Ok(out)
}

/// Every role commit's `EDGES` row, from its record (after a rebuild).
fn write_edges_all(tx: &mut Tx<'_>) -> Result<()> {
    let ids: Vec<CommitId> = tx.core.ix.commits.iter().filter(|(_, m)| m.view.kind.is_role()).map(|(id, _)| *id).collect();
    for id in ids {
        let parts = crate::apply::edge_parts(tx, &id)?;
        put_edges(tx, &id, &parts, Shred::No)?;
    }
    Ok(())
}

/// The `EDGES` rows of the held role commits; an error when one is missing or does not
/// decode (the open then rebuilds).
pub(crate) fn load_edges(tx: &mut Tx<'_>) -> Result<BTreeMap<CommitId, crate::apply::validity::EdgeParts>> {
    let _s = osis_base::costs::span("open: edges rows");
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
/// parts and what each keeps (`Hold::Dropped`), and the header's linked lists (a held header is
/// whole on its own: the list blobs live by the sync rules, gone at the commit's expiry).
pub(crate) struct RecordHead {
    pub received: WallMs,
    pub origin: Origin,
    /// `Meta::repair`.
    pub repair: Option<Arc<BTreeSet<BlobId>>>,
    pub signed: osis_commit::Signed,
    pub dropped: BTreeMap<usize, super::Dropped>,
    pub stripped: BTreeSet<usize>,
    pub valued: BTreeSet<usize>,
    pub lists: Vec<(osis_commit::ListField, Vec<u8>)>,
}

impl RecordHead {
    /// Fills `h`'s linked lists from the record (`Corrupt` when one is missing there).
    pub fn resolve(&self, h: &mut osis_commit::Header) -> Result<()> {
        for (f, b) in &self.lists {
            h.fill_stored_list(*f, b).map_err(|_| Error::Corrupt("header lists"))?;
        }
        if !h.is_resolved() {
            return Err(Error::Corrupt("header lists"));
        }
        Ok(())
    }
}

pub(crate) fn record_head(m: &Meta) -> Vec<u8> {
    let mut w = records::Wr::new().u8(1).u64(m.received.0).u8(match (m.origin, &m.repair) {
        (Origin::Local, None) => 0,
        (Origin::Remote, _) => 1,
        (Origin::Local, Some(_)) => 2,
    });
    // a repair's blobs encrypted afresh
    if let (Origin::Local, Some(fresh)) = (m.origin, &m.repair) {
        w = w.u32(fresh.len() as u32);
        for b in fresh.iter() {
            w = w.raw(&b.0);
        }
    }
    w = w.raw(&m.signed.to_bytes()).u32(m.dropped_parts().count() as u32);
    for (a, d) in m.dropped_parts() {
        let role = d.role.map_or(0, |r| 1 + r as u8);
        w = w.u32(a as u32).u8(u8::from(d.as_cover()) | role << 2 | u8::from(d.overreach) << 5 | u8::from(d.why == super::DropFor::Invalid) << 6).u32(d.covered_by.len() as u32);
        for s in &d.covered_by {
            w = w.raw(&s.0);
        }
        w = w.u32(d.keysets.len() as u32);
        for k in &d.keysets {
            w = w.u8(k.role as u8).u64(k.epoch.n()).raw(k.epoch.nonce()).u32(k.lists.len() as u32);
            for x in &k.lists {
                w = w.u64(x.n()).raw(x.nonce());
            }
            w = match &k.kem {
                Some(x) => w.u8(1).bytes(x.as_bytes()),
                None => w.u8(0),
            };
            w = w.raw(&k.names).u32(k.left_out.len() as u32);
            for (m, x) in &k.left_out {
                w = w.raw(m.as_bytes()).u64(x.n()).raw(x.nonce());
            }
            w = w.u32(k.demotions.len() as u32);
            for c in &k.demotions {
                w = w.raw(&c.0);
            }
            w = w.u8(u8::from(k.demotes));
        }
        w = w.u8(u8::from(d.stands_in)).u64(d.hosts_from);
    }
    w = w.u32(m.stripped_parts().count() as u32);
    for a in m.stripped_parts() {
        w = w.u32(a as u32).u8(u8::from(m.valued(a)));
    }
    // a header applies resolved (spec/commits.md §4)
    debug_assert!(m.header.is_resolved(), "record of an unresolved header");
    let lists = m.header.linked_lists();
    w = w.u8(lists.len() as u8);
    for (f, b) in &lists {
        w = w.u8(osis_commit::ListField::ALL.iter().position(|x| x == f).unwrap_or_default() as u8).bytes(b);
    }
    w.take()
}

/// A commit's `METAS` row: version 1, the part count, a byte per part, the view.
pub(super) fn meta_row(core: &Core, id: &CommitId, m: &Meta) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + 48 * m.valid.len());
    out.push(1);
    out.extend_from_slice(&(m.valid.len() as u32).to_be_bytes());
    for (ai, v) in m.valid.iter().enumerate() {
        let role = core.ix.rotation_role.get(&(*id, ai)).map_or(0, |r| 1 + *r as u8);
        out.push(u8::from(*v) | (role << 1) | (u8::from(core.ix.grant_overreach.contains(&(*id, ai))) << 4) | (u8::from(m.missing(ai)) << 5) | (u8::from(m.whole(ai)) << 6) | (u8::from(m.missing_as(ai) == Some(super::Missing::Forgot)) << 7));
    }
    let v = &m.view;
    let mut w = records::Wr(out).u64(v.ts.to_u64()).u8(v.kind.id() as u8);
    w = match v.form {
        osis_commit::Form::Commit => w.u8(0),
        osis_commit::Form::Session(n) => w.u8(1).raw(&n),
    };
    w = w.raw(v.author.as_bytes()).raw(v.actor.as_bytes()).u8(u8::from(v.linked) | (u8::from(v.memory) << 1) | (u8::from(v.purges) << 2) | (u8::from(v.epoch.is_some()) << 3));
    if let Some(e) = &v.epoch {
        w = w.raw(&e.0);
    }
    for a in &v.aspects {
        let ak = a.ak.as_str().as_bytes();
        w = w.raw(a.tid.as_bytes()).raw(&(ak.len() as u16).to_be_bytes()).raw(ak).u64(a.lo).u64(a.hi).u8(u8::from(a.replaces.is_some()));
        if let Some(c) = &a.replaces {
            w = w.raw(&c.0);
        }
    }
    match &v.frontier {
        None => w = w.u8(0),
        Some(f) => {
            let f = osis_schema::core_types::Frontier { commits: f.commits.clone() };
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
        0 => osis_commit::Form::Commit,
        1 => osis_commit::Form::Session(r.take(osis_crdt::SESSION_NONCE_LEN)?.try_into().map_err(|_| Error::Corrupt("meta row form"))?),
        _ => return Err(Error::Corrupt("meta row form")),
    };
    let (author, actor) = (r.tid()?, r.tid()?);
    let flags = r.u8()?;
    let (linked, memory, purges) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
    let epoch = if flags & 8 != 0 { Some(CommitId(r.arr()?)) } else { None };
    let mut aspects = Vec::with_capacity(n);
    for _ in 0..n {
        let (tid, ak) = (r.tid()?, r.ak()?);
        let (lo, hi, bits) = (r.u64()?, r.u64()?, r.u8()?);
        let replaces = if bits & 1 != 0 { Some(CommitId(r.arr()?)) } else { None };
        aspects.push(super::AspectView { tid, ak, lo, hi, replaces });
    }
    let frontier = match r.u8()? {
        0 => None,
        1 => {
            let b = r.bytes()?;
            let lim = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: b.len() };
            let v = osis_base::decode(b, &lim).map_err(|_| Error::Corrupt("meta row frontier"))?;
            let f = osis_schema::core_types::Frontier::from_value(&v).map_err(|_| Error::Corrupt("meta row frontier"))?;
            Some(Arc::new(osis_perm::Frontier { commits: f.commits }))
        }
        _ => return Err(Error::Corrupt("meta row frontier")),
    };
    r.end()?;
    Ok((parts, super::View { ts, kind, form, author, actor, linked, memory, aspects, frontier, purges, epoch }))
}

/// A commit record's head and its blob bytes.
pub(crate) fn parse_head(v: &[u8]) -> Result<(RecordHead, &[u8])> {
    let mut r = records::Rd::new(v);
    if r.u8()? != 1 {
        return Err(Error::Corrupt("commit record version"));
    }
    let received = WallMs(r.u64()?);
    let (origin, repair) = match r.u8()? {
        0 => (Origin::Local, None),
        1 => (Origin::Remote, None),
        2 => {
            let n = r.u32()? as usize;
            let mut fresh = BTreeSet::new();
            for _ in 0..n {
                fresh.insert(BlobId(r.take(32)?.try_into().map_err(|_| Error::Corrupt("commit record repair"))?));
            }
            (Origin::Local, Some(Arc::new(fresh)))
        }
        _ => return Err(Error::Corrupt("commit record origin")),
    };
    let signed = osis_commit::Signed::from_kept(r.arr()?);
    let mut dropped = BTreeMap::new();
    for _ in 0..r.u32()? {
        let a = r.u32()? as usize;
        let flags = r.u8()?;
        let mut covered_by = BTreeSet::new();
        for _ in 0..r.u32()? {
            covered_by.insert(CommitId(r.arr()?));
        }
        let mut keysets = Vec::new();
        for _ in 0..r.u32()? {
            let role = Role::ALL.get(<usize as From<u8>>::from(r.u8()?)).copied().ok_or(Error::Corrupt("dropped keyset role"))?;
            let e = osis_crypto::Epoch::new(r.u64()?, r.arr()?).map_err(|_| Error::Corrupt("dropped keyset epoch"))?;
            let mut lists = Vec::new();
            for _ in 0..r.u32()? {
                lists.push(osis_crypto::Epoch::new(r.u64()?, r.arr()?).map_err(|_| Error::Corrupt("dropped keyset epoch"))?);
            }
            let key = || Error::Corrupt("dropped keyset key");
            let kem = if r.u8()? != 0 { Some(osis_crypto::KemPublicKey::from_slice(r.bytes()?).map_err(|_| key())?) } else { None };
            let names = r.arr()?;
            let mut left_out = Vec::new();
            for _ in 0..r.u32()? {
                let m = Tid::from_bytes(r.arr()?);
                left_out.push((m, osis_crypto::Epoch::new(r.u64()?, r.arr()?).map_err(|_| Error::Corrupt("dropped keyset epoch"))?));
            }
            let mut demotions = Vec::new();
            for _ in 0..r.u32()? {
                demotions.push(CommitId(r.arr()?));
            }
            let demotes = r.u8()? != 0;
            keysets.push(super::KeysetRec { role, epoch: e, lists, kem, names, left_out, demotions, demotes });
        }
        let stands_in = r.u8()? != 0;
        let hosts_from = r.u64()?;
        let role = Role::ALL.get(<usize as From<u8>>::from((flags >> 2) & 7).wrapping_sub(1)).copied();
        dropped.insert(a, super::Dropped { covered_by, why: if flags & 1 != 0 { super::DropFor::Cover } else if flags & 64 != 0 { super::DropFor::Invalid } else { super::DropFor::Other }, hosts_from, stands_in, role, overreach: flags & 32 != 0, keysets, superseded_by: BTreeSet::new() });
    }
    let (mut stripped, mut valued) = (BTreeSet::new(), BTreeSet::new());
    for _ in 0..r.u32()? {
        let a = r.u32()? as usize;
        stripped.insert(a);
        if r.u8()? != 0 {
            valued.insert(a);
        }
    }
    let mut lists = Vec::new();
    for _ in 0..r.u8()? {
        let f = *osis_commit::ListField::ALL.get(<usize as From<u8>>::from(r.u8()?)).ok_or(Error::Corrupt("header list field"))?;
        lists.push((f, r.bytes()?.to_vec()));
    }
    Ok((RecordHead { received, origin, repair, signed, dropped, stripped, valued, lists }, r.rest()))
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
        let mode = txn.is_memory();
        for id in &ids {
            match c.ix.commits.get(id) {
                Some(m) => {
                    // a memory commit's row is memory, whichever transaction writes it
                    txn.set_memory(mode || m.view.memory);
                    txn.table_put(t, &id.0, meta_row(c, id, m), Shred::No)?;
                    txn.set_memory(mode);
                }
                None => {
                    txn.table_remove(t, &id.0, Shred::No)?;
                }
            };
        }
    }
    put_setmap(txn, BOXES_TO, &c.ix.boxes_to, all)?;
    put_map(txn, EPOCH_INTRO, &c.ix.epoch_intro, all)?;
    put_map(txn, KEYSETS, &c.ix.keysets, all)?;
    put_map(txn, SEALED, &c.ix.sealed, all)?;
    put_map(txn, DELETE_HINTS, &c.ix.delete_hints, all)?;
    put_map(txn, RETENTION, &c.ix.retention, all)?;
    put_setmap(txn, ORIGINALS, &c.ix.originals, all)?;
    put_aspect_map(txn, SNAPSHOTS, &c.ix.snapshots, all)?;
    put_map(txn, EPOCHS, &c.ix.epochs, all)?;
    put_map(txn, ROTATION_SIGS, &c.ix.rotation_sigs, all)?;
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
    let ever = core.ix.held.take_ever();
    core.timelines.ever_moved(&ever);
    core.timelines_changed(changed);
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
    // the tables memory rows go to exist whatever they hold: a memory transaction registering
    // one would write it durably (a table's registration is always durable)
    for name in [METAS, SNAPSHOTS, ADDENDA, super::refs::TO, super::refs::FROM] {
        tx.txn.index(name)?;
    }
    super::refs::write_all(tx)?;
    write_edges_all(tx)?;
    write_addenda_all(tx)?;
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
/// first use; those with lists by link resolved now), and the indexes derived from role-commit
/// bodies.
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    // commit records: the head and the header's bytes only, nothing decoded
    let hs = osis_base::costs::span("open: headers");
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
    let _ms = osis_base::costs::span("open: metas");
    let mut rows: BTreeMap<CommitId, Vec<u8>> = BTreeMap::new();
    let t = tx.txn.index(METAS)?;
    scan_table(&mut tx.txn, t, &[], None, |k, v| {
        rows.insert(CommitId(k.as_slice().try_into().map_err(|_| Error::Corrupt("meta row key"))?), v);
        Ok(())
    })?;
    let fault = tx.core.header_fault.clone();
    for (id, mut head, bytes) in recs {
        let row = rows.remove(&id).ok_or(Error::Corrupt("meta row missing"))?;
        let (parts, view) = parse_meta_row(&row)?;
        let mut valid = Vec::with_capacity(parts.len());
        let mut hold = Vec::with_capacity(parts.len());
        for (ai, p) in parts.iter().enumerate() {
            valid.push(p & 1 != 0);
            hold.push(super::Hold::stored(ai, &mut head, p & 32 != 0, p & 64 != 0, p & 128 != 0));
            if let Some(r) = Role::ALL.get(<usize as From<u8>>::from((p >> 1) & 7).wrapping_sub(1)) {
                tx.core.ix.rotation_role.insert((id, ai), *r);
            }
            if p & 16 != 0 {
                tx.core.ix.grant_overreach.insert((id, ai));
            }
        }
        let view = Arc::new(view);
        let header = if view.linked {
            // lists by link from the record
            let mut h = super::decode_stored_header(&id, &bytes).ok_or(Error::Corrupt("commit record header"))?;
            head.resolve(&mut h)?;
            debug_assert_eq!(super::View::of(&h), *view, "meta row of {id:?} is stale");
            super::LazyHeader::ready(Arc::new(h))
        } else {
            // a debug build checks the view against the header where it decodes
            super::LazyHeader::stored(id, bytes, view.clone(), fault.clone())
        };
        if view.aspects.len() != valid.len() {
            return Err(Error::Corrupt("meta row"));
        }
        crate::apply::index_commit(tx.core, &id, &view);
        tx.core.put_meta(id, Meta { view, header, received: head.received, origin: head.origin, repair: head.repair.clone(), signed: head.signed, valid, hold });
        crate::apply::note_stands_in(tx.core, &id);
        tx.core.index_validity(&id);
    }
    drop(_ms);
    // every held durable delta may be one a cover drops: the set is not stored, so after an open
    // the next snapshot of each aspect judges them all once (`Core::cover_judged_on`)
    let cands: Vec<((Tid, osis_base::Ak), CommitId)> = tx.core.ix.commits.iter().filter(|(_, m)| !m.view.kind.is_compaction() && !m.view.memory).flat_map(|(c, m)| m.view.aspects.iter().enumerate().filter(|(ai, _)| m.holds(*ai)).map(|(_, a)| ((a.tid, a.ak.clone()), *c))).collect();
    for (k, c) in cands {
        tx.core.cover_candidates.entry(k).or_default().insert(c);
    }
    for ((m, x), _) in scan::<(Tid, (Tid, Value))>(tx, BOXES_TO)? {
        tx.core.ix.boxes_to.insert(m, x);
    }
    for (k, v) in scan::<(Tid, Role, osis_crypto::Epoch)>(tx, EPOCH_INTRO)? {
        tx.core.ix.epoch_intro.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, Role, osis_crypto::Epoch)>(tx, KEYSETS)? {
        tx.core.ix.keysets.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, Role, osis_crypto::Epoch)>(tx, SEALED)? {
        tx.core.ix.sealed.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<Tid>(tx, DELETE_HINTS)? {
        tx.core.ix.delete_hints.insert(k, dec(&v)?);
    }
    for ((k, x), _) in scan::<((Tid, osis_base::Ak), (Ts, CommitId))>(tx, ORIGINALS)? {
        tx.core.ix.originals.insert(k, x);
    }
    for (k, v) in scan::<Tid>(tx, RETENTION)? {
        tx.core.ix.retention.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<(Tid, osis_base::Ak)>(tx, SNAPSHOTS)? {
        tx.core.ix.snapshots.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<Tid>(tx, EPOCHS)? {
        tx.core.ix.epochs.insert(k, dec(&v)?);
    }
    for (k, v) in scan::<CommitId>(tx, ROTATION_SIGS)? {
        tx.core.ix.rotation_sigs.insert(k, dec(&v)?);
    }
    // the epochs as persisted are judged: every change was before the index was written
    let due: Vec<Tid> = tx.core.ix.epochs_due.iter().copied().collect();
    for p in due {
        tx.core.ix.epochs_due.remove(&p);
    }
    let due: Vec<CommitId> = tx.core.ix.names_due.iter().copied().collect();
    for c in due {
        tx.core.ix.names_due.remove(&c);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::{DropFor, Dropped, Hold, Missing};
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Value, WallMs};

    // spec: none (internal: notes/engine-store.md, the commit record and meta row). Every part
    // state and the repair mark are stored as the record head and the meta row's bits and read
    // back as they were, but `Missing::ToFetch`, a memory commit's mark, which no store keeps.
    #[test]
    fn every_part_state_reads_back_as_stored() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        for k in ["a", "b", "c", "d", "e", "f", "g", "h"] {
            m.set(t, &Ak::new(format!("x:{k}.0")).unwrap(), &Value::Int(1)).unwrap();
        }
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let e = &lp.peers[0].engine;
        let mut meta = e.core.ix.commits[&id].clone();
        let cover = Dropped { covered_by: [c].into(), why: DropFor::Cover, hosts_from: 7, ..Dropped::default() };
        let invalid = Dropped { why: DropFor::Invalid, ..Dropped::default() };
        let states = [
            Hold::Body { whole: false },
            Hold::Body { whole: true },
            Hold::Leftover { whole: true, valued: true },
            Hold::Leftover { whole: false, valued: false },
            Hold::Dropped(cover),
            Hold::Dropped(invalid),
            Hold::Missing(Missing::Plain),
            Hold::Missing(Missing::Forgot),
        ];
        assert_eq!(meta.hold.len(), states.len());
        meta.hold = states.to_vec();
        let head = super::record_head(&meta);
        let row = super::meta_row(&e.core, &id, &meta);
        let (mut head, _) = super::parse_head(&head).unwrap();
        let (parts, _) = super::parse_meta_row(&row).unwrap();
        let back: Vec<Hold> = parts.iter().enumerate().map(|(ai, p)| Hold::stored(ai, &mut head, p & 32 != 0, p & 64 != 0, p & 128 != 0)).collect();
        assert_eq!(back, states.to_vec());
        // an own commit and an own repair (`Meta::repair`) read back as written
        assert!(head.origin == crate::events::Origin::Local && head.repair.is_none());
        let fresh: std::collections::BTreeSet<osis_base::BlobId> = [osis_base::BlobId([7; 32]), osis_base::BlobId([9; 32])].into();
        meta.repair = Some(std::sync::Arc::new(fresh.clone()));
        let (head, _) = super::parse_head(&super::record_head(&meta)).unwrap();
        assert!(head.origin == crate::events::Origin::Local && head.repair.as_deref() == Some(&fresh));
        // memory only: read back as a plain missing part
        meta.hold[6] = Hold::Missing(Missing::ToFetch);
        let row = super::meta_row(&e.core, &id, &meta);
        let (parts, _) = super::parse_meta_row(&row).unwrap();
        assert_eq!(parts[6] & (32 | 64 | 128), 32);
    }
}
