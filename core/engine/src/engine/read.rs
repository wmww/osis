//! Reads (notes/api.md Reads): aspect values from local state, the synthetic aspects `tid.0`,
//! `aspects.0`, `groups.0` (spec/data-model.md §8, §9), `roles.0` as the role timeline's
//! roster (spec/permissions.md §2) and roles.

use super::{Core, Engine, records};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_crdt::Fragment;
use osis_perm::{At, Edge};
use osis_schema::RawKey;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::BTreeMap;

/// Aspects read from the in-memory indexes, not from a state.
fn synthetic_ak(ak: &str) -> bool {
    matches!(ak, "tid.0" | "aspects.0" | "groups.0" | "roles.0")
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
    let key = |k: osis_perm::Point| ct::EdgeKey { ts: k.ts, node: k.node, commit: k.commit };
    ct::Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(key), tied: e.tied.map(crate::flows::tied::tie_ct), keyset: e.keyset.map(key) }.to_value()
}

impl Core {
    pub(crate) fn roster_of(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
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
        // an ephemeral thing's record is held beside its deltas, not as `created.0` state
        if let Some(v) = self.ephemeral_core_value(&tid, &ak)? {
            return Ok(v);
        }
        let v = match ak.as_str() {
            "tid.0" => Some(Value::Tid(tid)),
            "aspects.0" => Some(Value::Set(self.aspects(&tid)?.into_iter().map(|a| Value::Str(a.as_str().to_string())).collect())),
            "groups.0" => Some(Value::Set(self.groups_of(&tid).into_iter().map(Value::Tid).collect())),
            "roles.0" => {
                let r = self.core.roster_of(&tid);
                (!r.is_empty()).then(|| Value::Map(r.iter().map(|(m, e)| (Value::Tid(*m), edge_value(e))).collect()))
            }
            // the group its items and subgroups make (`placed.0~` adds carry no presence)
            "placed.0~" => self.placed_value(&tid),
            _ => self.run(|tx| Ok(tx.state(&tid, &ak)?.and_then(Fragment::read)))?,
        };
        Ok(v)
    }

    /// What held commit `c`'s own part on `(tid, ak)` reads, alone (not the aspect's joined
    /// state): `None` when not held. A heartbeat is read per commit (spec/permissions.md §4).
    pub fn part_value(&mut self, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Value>> {
        let (c, tid, ak) = (*c, *tid, ak.clone());
        let Some(ai) = self.core.ix.commits.get(&c).and_then(|m| m.aspect(&tid, &ak).filter(|ai| m.holds(*ai))) else { return Ok(None) };
        self.run(|tx| {
            let mut st: Option<Fragment> = None;
            for f in crate::apply::held_fragments(tx, &c, ai)? {
                st.get_or_insert_default().join(f);
            }
            Ok(st.as_ref().and_then(Fragment::read))
        })
    }

    /// `path` with its map keys in the form the state holds them (a large one as its link,
    /// spec/data-model.md §6).
    fn lookup_path(&self, tid: &Tid, path: &[osis_crdt::PathSeg]) -> Result<Vec<osis_crdt::PathSeg>> {
        let mut path = path.to_vec();
        if let Some(dedup) = self.core.dedup(tid) {
            for s in &mut path {
                if let osis_crdt::PathSeg::Key(k) = s {
                    *k = super::large::lookup_form(k, &dedup)?;
                }
            }
        }
        Ok(path)
    }

    /// The value at `path` inside `(tid, ak)` (a field, a map key, a list index, a case payload);
    /// `None` if absent. A key of a large map costs O(log n), not a read of the whole aspect.
    pub fn get_at(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg]) -> Result<Option<Value>> {
        if path.is_empty() || synthetic_ak(ak.as_str()) || ak.as_str() == "placed.0~" {
            return Ok(self.get(tid, ak)?.and_then(|v| value_at(v, path)));
        }
        if self.core.created(tid).is_none() {
            return Ok(None);
        }
        let path = self.lookup_path(tid, path)?;
        // a paged state loads only the pages on the path
        let v = self.run(|tx| {
            tx.ensure_paths(tid, ak, std::slice::from_ref(&path))?;
            Ok(tx.cached(tid, ak).and_then(|f| f.at(&path)).filter(Fragment::present).and_then(|f| f.read()))
        })?;
        Ok(v)
    }

    /// The visible elements `r` (by index, clamped to the length) of the text or list at `path`
    /// inside `(tid, ak)`: a string or a list; `None` if absent or not a sequence. A large
    /// sequence loads only the pages holding them (spec/crdt.md §6 placement kept per page set).
    pub fn get_range(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg], r: std::ops::Range<usize>) -> Result<Option<Value>> {
        if synthetic_ak(ak.as_str()) {
            return Ok(None);
        }
        if self.core.created(tid).is_none() {
            return Ok(None);
        }
        let path = self.lookup_path(tid, path)?;
        let v = self.run(|tx| tx.read_range(tid, ak, &path, r))?;
        Ok(v)
    }

    /// A typed read (reader defaults, spec/versioning.md §5).
    pub fn get_typed<K: RawKey>(&mut self, tid: &Tid, key: &K) -> Result<Option<K::T>> {
        let ak = Ak::new(key.ak()).map_err(|_| Error::Misuse("invalid AK"))?;
        match self.get(tid, &ak)? {
            Some(v) => Ok(Some(key.decode(&v)?)),
            None => Ok(None),
        }
    }

    /// AKs present on the thing (`aspects.0`).
    pub fn aspects(&mut self, tid: &Tid) -> Result<Vec<Ak>> {
        let tid = *tid;
        if self.core.created(&tid).is_none() {
            return Ok(Vec::new());
        }
        let mut out = self.run(|tx| {
            let mut aks = Vec::new();
            let prefix = [records::ASPECTS, tid.as_bytes()].concat();
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
        })?;
        out.sort();
        Ok(out)
    }

    /// Whether the thing holds content: some present aspect a content write sets (not
    /// `created.0`, not role-class), durable or ephemeral. Stops at the first.
    pub fn has_content(&mut self, tid: &Tid) -> Result<bool> {
        let content = |ak: &Ak| ct::is_content(ak.as_str());
        if self.core.created(tid).is_none() {
            return Ok(false);
        }
        let tid = *tid;
        self.run(|tx| {
            let mut aks = Vec::new();
            let prefix = [records::ASPECTS, tid.as_bytes()].concat();
            tx.scan(&prefix, |k, _| {
                let mut r = records::Rd::new(k);
                aks.push(r.ak()?);
                Ok(())
            })?;
            for ak in aks.iter().filter(|a| content(a)) {
                if tx.state(&tid, ak)?.is_some_and(Fragment::present) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// The role timeline's roster of `thing` (spec/permissions.md §2).
    pub fn roster(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        self.core.roster_of(thing)
    }

    /// This node's effective role on `tid` now.
    pub fn role_on(&self, tid: &Tid) -> Option<Role> {
        if self.core.ix.held.is_memory(tid) {
            return self.ephemeral_role(tid);
        }
        let ts = osis_base::Ts::make(self.now(), 0).unwrap_or_default();
        super::write::role_of(&self.core, &self.tid(), tid, ts)
    }

    /// The local state fragment of `(tid, ak)` (tests, simulator invariants).
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| Ok(tx.state(&tid, &ak)?.cloned()))
    }

    /// The epochs this node holds for actor `tid` (its own, opened ones with their
    /// establishment, or derived from the owner's).
    pub fn epochs(&self, tid: &Tid) -> Option<osis_keys::ActorEpochs> {
        self.core.epochs(tid).or_else(|| self.core.ix.secrets.get(tid).cloned())
    }

    /// Whether the creation record of `tid` is held here, durable or memory class.
    pub fn knows(&self, tid: &Tid) -> bool {
        self.core.created(tid).is_some()
    }

    /// Every aspect with a held state, as `(tid, ak)` (simulator invariants).
    pub fn all_aspects(&mut self) -> Result<Vec<(Tid, Ak)>> {
        self.run(|tx| {
            let mut out = Vec::new();
            tx.scan(records::ASPECTS, |k, _| {
                let mut r = records::Rd::new(k);
                out.push((r.tid()?, r.ak()?));
                Ok(())
            })?;
            Ok(out)
        })
    }
}
