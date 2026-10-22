//! Reads (notes/api.md Reads): aspect values from local state, the synthetic aspects `/tid`,
//! `/aspects`, `/groups` (spec/data-model.md §8, §9), `/members` as the membership timeline's
//! roster (spec/permissions.md §2), roles, and move resolution of tids in returned values
//! (spec/permissions.md §7).

use super::{Core, Engine, records};
use crate::error::{Error, Result};
use osis_core::{Ak, Role, Tid, Value};
use osis_crdt::Fragment;
use osis_perm::{At, Edge, MoveIndex};
use osis_schema::AspectKey;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

struct Moves<'c>(&'c Core);

impl MoveIndex for Moves<'_> {
    fn continued_by(&self, t: &Tid) -> Vec<Tid> {
        self.0.was.get(t).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }
    fn moved(&self, t: &Tid) -> Option<Tid> {
        self.0.moved.get(t).copied()
    }
}

/// Aspects whose tids are not resolved through moves: they name things as such.
fn unresolved_ak(ak: &str) -> bool {
    matches!(ak, "/tid" | "/created" | "/was" | "/moved")
}

/// Navigates a read value along `path` (synthetic aspects).
fn value_at(v: Value, path: &[osis_crdt::PathSeg]) -> Option<Value> {
    use osis_crdt::PathSeg;
    let Some((seg, rest)) = path.split_first() else { return Some(v) };
    let next = match (seg, v) {
        (PathSeg::Field(id), Value::Map(mut m)) => m.remove(&Value::Int(i64::try_from(*id).ok()?))?,
        (PathSeg::Key(k), Value::Map(mut m)) => m.remove(k)?,
        (PathSeg::Index(i), Value::List(l)) => l.into_iter().nth(*i)?,
        (PathSeg::Case(id), Value::Enum(c, Some(p))) if c == *id => *p,
        _ => return None,
    };
    value_at(next, rest)
}

fn edge_value(e: &Edge) -> Value {
    ct::Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(|k| ct::EdgeKey { ts: k.ts, node: k.node, commit: k.commit }) }.to_value()
}

impl Core {
    pub(crate) fn resolve(&self, r: &Tid, t: &Tid) -> Tid {
        if self.was.is_empty() && self.moved.is_empty() {
            return *t;
        }
        match self.timelines.get(r) {
            Some(tl) => tl.resolve(&Moves(self), r, t, At::now(osis_core::Ts::make(self.now(), 0).unwrap_or_default())),
            None => {
                let mut cur = *t;
                for _ in 0..osis_perm::RESOLUTION_HOPS {
                    match self.moved.get(&cur) {
                        Some(x) => cur = *x,
                        None => break,
                    }
                }
                cur
            }
        }
    }

    fn resolve_value(&self, r: &Tid, v: Value) -> Value {
        match v {
            Value::Tid(t) => Value::Tid(self.resolve(r, &t)),
            Value::List(l) => Value::List(l.into_iter().map(|x| self.resolve_value(r, x)).collect()),
            Value::Set(s) => Value::Set(s.into_iter().map(|x| self.resolve_value(r, x)).collect()),
            Value::Map(m) => Value::Map(m.into_iter().map(|(k, x)| (self.resolve_value(r, k), self.resolve_value(r, x))).collect()),
            Value::Enum(c, Some(p)) => Value::Enum(c, Some(Box::new(self.resolve_value(r, *p)))),
            v => v,
        }
    }

    pub(crate) fn roster_of(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        let ts = osis_core::Ts::make(self.now(), 0).unwrap_or_default();
        self.timelines.get(thing).map(|tl| tl.roster(thing, At::now(ts))).unwrap_or_default()
    }
}

impl Engine {
    /// The value of `(tid, ak)` as this node reads it; `None` if absent.
    pub fn get(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Value>> {
        let (tid, ak) = (*tid, ak.clone());
        if self.core.created(&tid).is_none() {
            return Ok(None);
        }
        let v = match ak.as_str() {
            "/tid" => Some(Value::Tid(tid)),
            "/aspects" => Some(Value::Set(self.aspects(&tid)?.into_iter().map(|a| Value::Str(a.as_str().to_string())).collect())),
            "/groups" => Some(Value::Set(self.core.groups.of.get(&tid).into_iter().flatten().map(|g| Value::Tid(*g)).collect())),
            "/members" => {
                let r = self.core.roster_of(&tid);
                (!r.is_empty()).then(|| Value::Map(r.iter().map(|(m, e)| (Value::Tid(*m), edge_value(e))).collect()))
            }
            _ => self.run(|tx| Ok(tx.state(&tid, &ak)?.and_then(Fragment::read)))?,
        };
        Ok(match v {
            Some(v) if !unresolved_ak(ak.as_str()) => Some(self.core.resolve_value(&tid, v)),
            v => v,
        })
    }

    /// The value at `path` inside `(tid, ak)` (a field, a map key, a list index, a case payload);
    /// `None` if absent. A key of a large map costs O(log n), not a read of the whole aspect.
    pub fn get_at(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg]) -> Result<Option<Value>> {
        if path.is_empty() || matches!(ak.as_str(), "/tid" | "/aspects" | "/groups" | "/members") {
            return Ok(self.get(tid, ak)?.and_then(|v| value_at(v, path)));
        }
        if self.core.created(tid).is_none() {
            return Ok(None);
        }
        // a paged state loads only the pages on the path
        let v = self.run(|tx| {
            tx.ensure_paths(tid, ak, &[path.to_vec()])?;
            Ok(tx.cached(tid, ak).and_then(|f| f.at(path)).filter(Fragment::present).and_then(|f| f.read()))
        })?;
        Ok(match v {
            Some(v) if !unresolved_ak(ak.as_str()) => Some(self.core.resolve_value(tid, v)),
            v => v,
        })
    }

    /// A typed read (reader defaults, spec/versioning.md §5).
    pub fn get_typed<K: AspectKey>(&mut self, tid: &Tid, key: &K) -> Result<Option<K::T>> {
        let ak = Ak::new(key.ak()).map_err(|_| Error::Misuse("invalid AK"))?;
        match self.get(tid, &ak)? {
            Some(v) => Ok(Some(key.decode(&v)?)),
            None => Ok(None),
        }
    }

    /// AKs present on the thing (`/aspects`).
    pub fn aspects(&mut self, tid: &Tid) -> Result<Vec<Ak>> {
        let tid = *tid;
        self.run(|tx| {
            let mut aks = Vec::new();
            let prefix = [b"a/".as_slice(), tid.as_bytes()].concat();
            tx.scan(&prefix, |k, _| {
                let mut r = records::Rd::new(k);
                aks.push(r.ak()?);
                Ok(())
            })?;
            let mut out = Vec::new();
            for ak in aks {
                if tx.state(&tid, &ak)?.is_some_and(Fragment::present) {
                    out.push(ak);
                }
            }
            Ok(out)
        })
    }

    /// Groups containing the thing, transitively (`/groups`).
    pub fn groups_of(&self, tid: &Tid) -> BTreeSet<Tid> {
        self.core.groups.of.get(tid).cloned().unwrap_or_default()
    }

    /// The membership timeline's roster of `thing` (spec/permissions.md §2).
    pub fn roster(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        self.core.roster_of(thing)
    }

    /// This node's effective role on `tid` now.
    pub fn role_on(&self, tid: &Tid) -> Option<Role> {
        let ts = osis_core::Ts::make(self.now(), 0).unwrap_or_default();
        super::write::role_of(&self.core, &self.tid(), tid, ts)
    }

    /// Resolves tid `t` held in a value of thing `r` through moves.
    pub fn resolve(&self, r: &Tid, t: &Tid) -> Tid {
        self.core.resolve(r, t)
    }

    /// The local state fragment of `(tid, ak)` (tests, simulator invariants).
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| Ok(tx.state(&tid, &ak)?.cloned()))
    }

    /// The epochs this node holds for actor `tid` (its own, opened ones with their
    /// establishment, or derived from the owner's).
    pub fn epochs(&self, tid: &Tid) -> Option<osis_keys::ActorEpochs> {
        self.core.secrets.get(tid).cloned().or_else(|| self.core.epochs(tid))
    }

    /// Whether `/created` of `tid` is held.
    pub fn knows(&self, tid: &Tid) -> bool {
        self.core.created(tid).is_some()
    }

    /// Every aspect with a held state, as `(tid, ak)` (simulator invariants).
    pub fn all_aspects(&mut self) -> Result<Vec<(Tid, Ak)>> {
        self.run(|tx| {
            let mut out = Vec::new();
            tx.scan(b"a/", |k, _| {
                let mut r = records::Rd::new(k);
                out.push((r.tid()?, r.ak()?));
                Ok(())
            })?;
            Ok(out)
        })
    }
}
