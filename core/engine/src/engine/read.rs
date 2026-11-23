//! Reads (notes/api.md Reads): aspect values from local state, the synthetic aspect `aspects.0`
//! (spec/data-model.md §9), `roles.0` as the role timeline's roster (spec/permissions.md §2) and
//! roles.

use super::{Core, Engine, records};
use crate::error::{Error, Result};
use osis_base::{Ak, Role, Tid, Value};
use osis_crdt::Fragment;
use osis_perm::{At, Edge};
use osis_schema::RawKey;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Aspects read from the in-memory indexes, not from a state.
fn synthetic_ak(ak: &str) -> bool {
    matches!(ak, "aspects.0" | "roles.0")
}

fn edge_value(e: &Edge) -> Value {
    crate::apply::validity::schema_edge(e).to_value()
}

impl Core {
    /// `thing`'s roster now, read on the memo clock up to the earliest `until` ahead in it, so a
    /// memo or follower reading it moves when the clock alone ends a role there, with a wake then
    /// (`Engine::clock_next`).
    pub(crate) fn roster_of(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        if let Some(h) = self.root_holders(thing) {
            return h.into_iter().map(|(m, role)| (m, Edge::new(role))).collect();
        }
        self.time.at(|now| {
            let r = self.timelines().on(thing).map(|on| on.roster(At::now(crate::flows::ts_at(now)))).unwrap_or_default();
            let until = r.values().filter_map(|e| e.until).map(|u| u.0).filter(|u| *u > now).min();
            (r, until)
        })
    }
}

impl Engine {
    /// The reference index's rows naming `target` (`refs`): who holds a reference to it in a
    /// held value, on which aspect, of which kind, how many times.
    pub fn references_to(&mut self, target: &Tid) -> Result<Vec<super::refs::Reference>> {
        self.read(|tx| super::refs::to(tx, target))
    }

    /// Up to `n` of the reference index's rows naming `target`, on aspect `on` alone where given,
    /// after `after` (source, AK, kind; exclusive), in (AK, source, kind) order: O(n) rows read.
    pub fn references_page(&mut self, target: &Tid, on: Option<&Ak>, after: Option<(&Tid, &Ak, osis_base::RefKind)>, n: usize) -> Result<Vec<(Tid, Ak, osis_base::RefKind)>> {
        self.read(|tx| super::refs::to_page(tx, target, on, after, n))
    }

    /// Whether `source`'s value on `ak` references `target` by `kind` (the reference index's row).
    pub fn references(&mut self, target: &Tid, source: &Tid, ak: &Ak, kind: osis_base::RefKind) -> Result<bool> {
        self.read(|tx| super::refs::has(tx, target, source, ak, kind))
    }

    /// Turns `Event::References` on for this open; it stays on (as `watch_commits`).
    pub fn watch_references(&mut self) {
        self.core.refs_watched = true;
    }

    /// The reference index's rows of `source`'s values, every aspect.
    pub fn references_from(&mut self, source: &Tid) -> Result<Vec<super::refs::Reference>> {
        self.read(|tx| super::refs::from(tx, source))
    }

    /// The value of `(tid, ak)` as this node reads it; `None` if absent.
    pub fn get(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Value>> {
        self.get_within(tid, ak, None)
    }

    /// `get` holding at most `max` bytes of the state as it loads it (`pages::charge`): past
    /// that it fails `TooLarge` without loading the rest.
    pub fn get_within(&mut self, tid: &Tid, ak: &Ak, max: Option<usize>) -> Result<Option<Value>> {
        let (tid, ak) = (*tid, ak.clone());
        if !self.core.exists(&tid) {
            return Ok(None);
        }
        let v = match ak.as_str() {
            "aspects.0" => Some(Value::Set(self.aspects_within(&tid, max)?.into_iter().map(|a| Value::Str(a.as_str().to_string())).collect())),
            "roles.0" => {
                let r = self.core.roster_of(&tid);
                (!r.is_empty()).then(|| Value::Map(r.iter().map(|(m, e)| (Value::Weak(*m), edge_value(e))).collect()))
            }
            _ => self.read(|tx| tx.reading(&tid, &ak, max, |tx| Ok(tx.state(&tid, &ak)?.and_then(Fragment::read))))?,
        };
        Ok(v)
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
    /// `None` if absent. Reads only that position: a key of a large map costs O(log n) and the
    /// value there, not a read of the whole aspect.
    pub fn get_at(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg]) -> Result<Option<Value>> {
        self.get_at_within(tid, ak, path, None)
    }

    /// `get_at` holding at most `max` bytes of the state as it loads it (`get_within`).
    pub fn get_at_within(&mut self, tid: &Tid, ak: &Ak, path: &[osis_crdt::PathSeg], max: Option<usize>) -> Result<Option<Value>> {
        if path.is_empty() || synthetic_ak(ak.as_str()) {
            return Ok(self.get_within(tid, ak, max)?.and_then(|v| osis_crdt::value_at(&v, path).cloned()));
        }
        if !self.core.exists(tid) {
            return Ok(None);
        }
        let path = self.lookup_path(tid, path)?;
        // a paged state loads only the pages on the path
        let v = self.read(|tx| {
            tx.reading(tid, ak, max, |tx| {
                tx.ensure_paths(tid, ak, std::slice::from_ref(&path))?;
                Ok(tx.cached(tid, ak).and_then(|f| f.read_at(&path)))
            })
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
        if !self.core.exists(tid) {
            return Ok(None);
        }
        let path = self.lookup_path(tid, path)?;
        let v = self.read(|tx| tx.reading(tid, ak, None, |tx| tx.read_range(tid, ak, &path, r)))?;
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
        self.aspects_within(tid, None)
    }

    /// `aspects`, each state read within `max` (`Tx::present_within`).
    pub fn aspects_within(&mut self, tid: &Tid, max: Option<usize>) -> Result<Vec<Ak>> {
        let tid = *tid;
        if !self.core.exists(&tid) {
            return Ok(Vec::new());
        }
        let mut out = self.read(|tx| {
            let mut out = Vec::new();
            for ak in tx.state_aks(&tid)? {
                if tx.present_within(&tid, &ak, max)? {
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
        if !self.core.exists(tid) {
            return Ok(false);
        }
        let tid = *tid;
        self.read(|tx| has_content_in(tx, &tid))
    }

    /// The role timeline's roster of `thing` (spec/permissions.md §2).
    pub fn roster(&self, thing: &Tid) -> BTreeMap<Tid, Edge> {
        if !self.core.exists(thing) {
            return BTreeMap::new();
        }
        self.core.roster_of(thing)
    }

    /// This node's effective role on `tid` now.
    pub fn role_on(&self, tid: &Tid) -> Option<Role> {
        if !self.core.exists(tid) {
            return None;
        }
        self.core.role_now(&self.core.me()?, tid)
    }

    /// The local state fragment of `(tid, ak)` (tests, simulator invariants).
    pub fn state(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
        let (tid, ak) = (*tid, ak.clone());
        self.read(|tx| Ok(tx.state(&tid, &ak)?.cloned()))
    }

    /// The epochs this node holds for actor `tid` (its own, opened ones with their
    /// establishment, or derived from its mint admin's).
    pub fn epochs(&self, tid: &Tid) -> Option<Arc<osis_keys::ActorEpochs>> {
        self.core.epochs(tid).or_else(|| self.core.ix.secrets.get(tid).map(|x| Arc::new(x.clone())))
    }

    /// Whether the creation record of `tid` is held here, durable or memory class.
    pub fn knows(&self, tid: &Tid) -> bool {
        self.core.exists(tid)
    }

    /// Whether `tid` was destroyed here (purged, expired or released, spec/commits.md §5 Destruction): it
    /// reads as absent, its kept record and creation included.
    pub fn destroyed(&self, tid: &Tid) -> bool {
        self.core.destroyed(tid)
    }

    /// Every aspect with a held state, as `(tid, ak)` (simulator invariants).
    pub fn all_aspects(&mut self) -> Result<Vec<(Tid, Ak)>> {
        self.read(|tx| {
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

/// `Engine::has_content` in `tx`.
pub(crate) fn has_content_in(tx: &mut super::Tx<'_>, tid: &Tid) -> Result<bool> {
    if !tx.core.exists(tid) {
        return Ok(false);
    }
    for ak in tx.state_aks(tid)?.iter().filter(|a| ct::counts_as_content(a.as_str())) {
        if tx.present_within(tid, ak, None)? {
            return Ok(true);
        }
    }
    Ok(false)
}
