//! The delta facts the walk reads by point lookup (`osis_perm::paths::Store`; notes/perm-paths.md,
//! The delta-facts seam), kept as the engine's index: what a delta's validity reads, held once per
//! (commit, thing) where every delta of a commit on a thing shares it (its `ts`, signer, position,
//! [signer, A1..Ak], hops, purge author: the path half of a `Fact`), and per delta only what is
//! its own (thing, aspect, role needed, class, retention); with the indexes content reads (by
//! commit, what lists or carries a commit, requests by author, addenda and deltas by (edge,
//! position)) and the stored addenda verdicts. Every lookup is a B-tree point or range read: none
//! scans what is held but `all` (full readings: disputes, tests). `reads` counts lookups and
//! index entries returned (the count tests).

use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use osis_perm::paths::{Fact, FactClass, Holding, Key, NameKey, Names, Pair, Right, Store};
use osis_perm::WriteId;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// What every delta of a commit on one thing shares.
#[derive(Clone, Debug, PartialEq)]
struct PathFacts {
    ts: Ts,
    signer: Tid,
    pos: Key,
    hops: Vec<Pair>,
    well: bool,
    purge_author: Option<Tid>,
    chain: Vec<Tid>,
}

/// One delta's own facts.
#[derive(Clone, Debug)]
struct Row {
    on: Tid,
    aspect: Ak,
    needs: Role,
    class: FactClass,
    retention: PurgeBy,
    path: Arc<PathFacts>,
}

#[derive(Default)]
pub struct EngineStore {
    deltas: BTreeMap<WriteId, Row>,
    /// The path facts per (commit, thing), shared by its deltas.
    paths: BTreeMap<(CommitId, Tid), Arc<PathFacts>>,
    listing: BTreeMap<CommitId, BTreeSet<WriteId>>,
    carrying: BTreeMap<CommitId, BTreeSet<WriteId>>,
    /// Requests by what they name and the holding their stored right gives, by stamp.
    requests: BTreeMap<(NameKey, Holding), BTreeSet<(Ts, WriteId)>>,
    requests_on: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    rights: BTreeMap<WriteId, Right>,
    own: BTreeMap<Tid, BTreeSet<WriteId>>,
    addenda_on: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    through: BTreeMap<Pair, BTreeSet<(Key, WriteId)>>,
    valid: BTreeSet<WriteId>,
    /// Lookups answered and index entries they visited (count tests).
    reads: Arc<AtomicU64>,
    /// Facts put (count tests).
    puts: u64,
}

impl Clone for EngineStore {
    fn clone(&self) -> EngineStore {
        EngineStore {
            deltas: self.deltas.clone(),
            paths: self.paths.clone(),
            listing: self.listing.clone(),
            carrying: self.carrying.clone(),
            requests: self.requests.clone(),
            requests_on: self.requests_on.clone(),
            rights: self.rights.clone(),
            own: self.own.clone(),
            addenda_on: self.addenda_on.clone(),
            through: self.through.clone(),
            valid: self.valid.clone(),
            reads: Arc::new(AtomicU64::new(self.reads.load(Ordering::Relaxed))),
            puts: self.puts,
        }
    }
}

fn set<K: Ord, V: Ord>(m: &mut BTreeMap<K, BTreeSet<V>>, k: K, v: V, add: bool) {
    if add {
        m.entry(k).or_default().insert(v);
    } else if let Some(s) = m.get_mut(&k) {
        s.remove(&v);
        if s.is_empty() {
            m.remove(&k);
        }
    }
}

const LO: WriteId = WriteId(CommitId([0; 32]), 0);
const HI: WriteId = WriteId(CommitId([u8::MAX; 32]), u32::MAX);

fn in_range(m: &BTreeMap<Pair, BTreeSet<(Key, WriteId)>>, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
    let from = match from {
        Bound::Included(k) => Bound::Included((k, LO)),
        Bound::Excluded(k) => Bound::Excluded((k, HI)),
        Bound::Unbounded => Bound::Unbounded,
    };
    let to = match to {
        Bound::Included(k) => Bound::Included((k, HI)),
        Bound::Excluded(k) => Bound::Excluded((k, LO)),
        Bound::Unbounded => Bound::Unbounded,
    };
    m.get(e).into_iter().flat_map(|s| s.range((from, to))).map(|x| x.1).collect()
}

impl EngineStore {
    /// Lookups answered plus index entries returned, since construction.
    pub fn reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Facts put since construction.
    pub fn puts(&self) -> u64 {
        self.puts
    }

    /// Entries held per kind: (deltas, path facts shared by them).
    pub fn sizes(&self) -> (usize, usize) {
        (self.deltas.len(), self.paths.len())
    }

    fn read<T>(&self, out: Vec<T>) -> Vec<T> {
        self.reads.fetch_add(1 + out.len() as u64, Ordering::Relaxed);
        out
    }

    fn index(&mut self, id: WriteId, r: &Row, add: bool) {
        for e in &r.path.hops {
            set(&mut self.through, *e, (r.path.pos, id), add);
        }
        match &r.class {
            FactClass::Addendum(_, list) => {
                for x in list.commits() {
                    set(&mut self.listing, *x, id, add);
                }
                for e in &r.path.hops {
                    set(&mut self.addenda_on, *e, (r.path.pos, id), add);
                }
            }
            FactClass::Snapshot { carries, own, .. } => {
                for x in carries.commits() {
                    set(&mut self.carrying, *x, id, add);
                }
                if *own {
                    set(&mut self.own, r.path.signer, id, add);
                }
            }
            FactClass::Purge(_) => {
                for e in &r.path.hops {
                    set(&mut self.requests_on, *e, (r.path.pos, id), add);
                }
            }
            FactClass::Plain | FactClass::Role => {}
        }
    }
}

impl Store for EngineStore {
    fn put(&mut self, f: Fact) {
        self.puts += 1;
        let path = PathFacts { ts: f.ts, signer: f.signer, pos: f.pos, hops: f.hops, well: f.well, purge_author: f.purge_author, chain: f.chain };
        let shared = match self.paths.get(&(f.id.0, f.on)) {
            Some(p) if **p == path => p.clone(),
            _ => {
                let p = Arc::new(path);
                self.paths.insert((f.id.0, f.on), p.clone());
                p
            }
        };
        let row = Row { on: f.on, aspect: f.aspect, needs: f.needs, class: f.class, retention: f.retention, path: shared };
        if let Some(old) = self.deltas.remove(&f.id) {
            self.index(f.id, &old, false);
        }
        self.index(f.id, &row, true);
        self.deltas.insert(f.id, row);
    }
    fn remove(&mut self, id: &WriteId) -> Option<Fact> {
        self.set_right(id, Right::default());
        let f = self.get(id)?;
        let r = self.deltas.remove(id)?;
        self.index(*id, &r, false);
        self.valid.remove(id);
        // the path facts go with the last delta of their commit on the thing
        let lo = WriteId(id.0, 0);
        if !self.deltas.range(lo..=WriteId(id.0, u32::MAX)).any(|(_, x)| x.on == r.on) {
            self.paths.remove(&(id.0, r.on));
        }
        Some(f)
    }
    fn get(&self, id: &WriteId) -> Option<Fact> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let r = self.deltas.get(id)?;
        let p = &*r.path;
        Some(Fact { id: *id, ts: p.ts, signer: p.signer, pos: p.pos, on: r.on, aspect: r.aspect.clone(), needs: r.needs, class: r.class.clone(), hops: p.hops.clone(), well: p.well, purge_author: p.purge_author, retention: r.retention, chain: p.chain.clone() })
    }
    fn of_commit(&self, c: &CommitId, on: Option<&Tid>) -> Vec<WriteId> {
        let mut visited = 0;
        let ids = self.deltas.range(WriteId(*c, 0)..=WriteId(*c, u32::MAX)).inspect(|_| visited += 1).filter(|(_, r)| on.is_none_or(|t| r.on == *t)).map(|(id, _)| *id).collect();
        self.reads.fetch_add(1 + visited, Ordering::Relaxed);
        ids
    }
    fn listing(&self, c: &CommitId) -> Vec<WriteId> {
        self.read(self.listing.get(c).into_iter().flatten().copied().collect())
    }
    fn carrying(&self, c: &CommitId) -> Vec<WriteId> {
        self.read(self.carrying.get(c).into_iter().flatten().copied().collect())
    }
    fn latest(&self, key: &NameKey, holding: Holding) -> Option<Ts> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.requests.get(&(key.clone(), holding)).and_then(|s| s.last()).map(|x| x.0)
    }
    fn requests_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.read(in_range(&self.requests_on, e, from, to))
    }
    fn right(&self, id: &WriteId) -> Right {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.rights.get(id).copied().unwrap_or_default()
    }
    fn set_right(&mut self, id: &WriteId, right: Right) {
        let was = self.rights.get(id).copied().unwrap_or_default();
        if was == right {
            return;
        }
        let Some(r) = self.deltas.get(id) else { return };
        let FactClass::Purge(names) = &r.class else { return };
        let key: NameKey = (r.on, (*names != Names::Destroy).then(|| r.aspect.clone()), *names);
        let (ts, chain) = (r.path.ts, r.path.chain.clone());
        let holdings = |x: Right| {
            let mut out = BTreeSet::new();
            if x.admin {
                out.insert(Holding::Admin);
            }
            if x.write {
                out.insert(Holding::Write);
                out.extend(chain.iter().map(|t| Holding::WriteFor(*t)));
            }
            out
        };
        let (old, new) = (holdings(was), holdings(right));
        for h in old.symmetric_difference(&new) {
            set(&mut self.requests, (key.clone(), *h), (ts, *id), new.contains(h));
        }
        if right.any() {
            self.rights.insert(*id, right);
        } else {
            self.rights.remove(id);
        }
    }
    fn own_covers(&self, signer: &Tid) -> Vec<WriteId> {
        self.read(self.own.get(signer).into_iter().flatten().copied().collect())
    }
    fn addenda_through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.read(in_range(&self.addenda_on, e, from, to))
    }
    fn through(&self, e: &Pair, from: Bound<Key>, to: Bound<Key>) -> Vec<WriteId> {
        self.read(in_range(&self.through, e, from, to))
    }
    fn valid_addendum(&self, id: &WriteId) -> bool {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.valid.contains(id)
    }
    fn set_valid_addendum(&mut self, id: &WriteId, valid: bool) {
        if valid {
            self.valid.insert(*id);
        } else {
            self.valid.remove(id);
        }
    }
    fn all(&self) -> Vec<WriteId> {
        self.deltas.keys().copied().collect()
    }
}
