//! Fetching what judges what the node holds (notes/expiry-creation-design.md §3): which entries a
//! node can open, what it keeps of an entry it cannot judge, and the fixed point it reaches.
//! A sync ID holds a commit's parts on its things, or the whole commit where a copy is logged under
//! it (a sibling under another sync ID). An entry is delivered only under a sync ID the node holds a key for.
//! A part or commit that cannot be judged is discarded (`act`); before that, boxes opening with
//! the node's own key are read: reading-only keys, sourced from the commit, that open further
//! sync IDs. They go when the commit's last part applies (a valid grant's key stays) or it is judged
//! bad. Parts are re-fetched when a record or grant arrives, modelled as whole passes over the
//! entries until nothing changes: a pass refetches only what is not held.

use crate::model::{act, evaluate};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// What peers hold.
#[derive(Clone, Debug, Default)]
pub struct Library {
    pub now: u64,
    pub me: NodeId,
    /// Records known from the start.
    pub records: Vec<Record>,
    /// The sync IDs each thing's parts are logged under.
    pub sync_ids: BTreeMap<ThingId, BTreeSet<SyncId>>,
    /// Further sync IDs holding a whole commit (a sibling copy under another sync ID).
    pub copies: BTreeMap<CommitId, BTreeSet<SyncId>>,
    pub commits: Vec<Commit>,
    /// Keys the node holds from the start.
    pub keys: BTreeSet<SyncId>,
}

impl Library {
    fn logs(&self, c: &Commit, sync_id: SyncId) -> bool {
        self.copies.get(&c.id).is_some_and(|s| s.contains(&sync_id)) || c.parts.iter().any(|p| self.part_in(p, sync_id))
    }
    fn part_in(&self, p: &Part, sync_id: SyncId) -> bool {
        self.sync_ids.get(&p.thing).is_some_and(|s| s.contains(&sync_id))
    }
    fn entries(&self) -> Vec<(SyncId, CommitId)> {
        let mut ls: BTreeSet<SyncId> = self.sync_ids.values().flatten().copied().collect();
        ls.extend(self.copies.values().flatten());
        ls.into_iter().flat_map(|l| self.commits.iter().filter(move |c| self.logs(c, l)).map(move |c| (l, c.id))).collect()
    }
    /// The commit as delivered under `sync_id`.
    fn delivered(&self, c: &Commit, sync_id: SyncId) -> Commit {
        let whole = self.copies.get(&c.id).is_some_and(|s| s.contains(&sync_id));
        let mut v = c.clone();
        for p in &mut v.parts {
            if !whole && !self.part_in(p, sync_id) {
                p.body = Body::Missing;
            }
        }
        v.boxes = c.boxes.iter().filter(|b| whole || self.sync_ids.get(&b.thing).is_some_and(|s| s.contains(&sync_id))).copied().collect();
        v
    }
}

/// Merges a delivered copy into `held` (a part held stays).
fn arrive(h: &mut Held, v: Commit) {
    match h.commits.iter_mut().find(|c| c.id == v.id) {
        Some(c) => {
            for (a, b) in c.parts.iter_mut().zip(v.parts) {
                if a.body == Body::Missing {
                    *a = b;
                }
            }
            for b in v.boxes {
                if !c.boxes.contains(&b) {
                    c.boxes.push(b);
                }
            }
        }
        None => h.commits.push(v),
    }
}

/// The fixed point: every sync ID the node can come to hold a key for, and what it holds.
pub struct Fetched {
    pub held: Held,
    pub keys: BTreeSet<SyncId>,
}

/// Runs the node's fetch loop to quiescence. `order` shuffles a pass's entries (arrival order);
/// `reading_only` false throws boxes away with what is discarded (the deadlock this design avoids).
pub fn settle(lib: &Library, order: &mut dyn FnMut(&mut Vec<(SyncId, CommitId)>), reading_only: bool) -> Fetched {
    let mut held = Held { now: lib.now, me: lib.me, records: lib.records.clone(), commits: vec![], dots: vec![], external_fires: ExternalFires::Any };
    // reading-only keys by the commit they are sourced from
    let mut reading: BTreeMap<CommitId, BTreeSet<SyncId>> = BTreeMap::new();
    loop {
        let keys = key_set(lib, &held, &reading);
        let before = (held.clone(), keys.clone());
        let mut es: Vec<(SyncId, CommitId)> = lib.entries().into_iter().filter(|(l, _)| keys.contains(l)).collect();
        order(&mut es);
        for (l, id) in es {
            let c = lib.commits.iter().find(|c| c.id == id).unwrap();
            let v = lib.delivered(c, l);
            if holds_all(&held, &v) {
                continue;
            }
            let boxes = v.boxes.clone();
            arrive(&mut held, v);
            if reading_only {
                reading.entry(id).or_default().extend(boxes.iter().map(|b| b.key));
            }
            let o = evaluate(&held);
            held = act(&held, &o, None);
            settle_reading(&held, &o, &mut reading, id);
        }
        // every held fate carried out (records and grants changed: discards wake)
        let o = evaluate(&held);
        held = act(&held, &o, None);
        for id in reading.keys().copied().collect::<Vec<_>>() {
            settle_reading(&held, &o, &mut reading, id);
        }
        let keys = key_set(lib, &held, &reading);
        if (held.clone(), keys.clone()) == before {
            return Fetched { held, keys };
        }
    }
}

/// Whether a delivered copy brings nothing the node does not hold.
fn holds_all(h: &Held, v: &Commit) -> bool {
    h.commits.iter().find(|c| c.id == v.id).is_some_and(|c| c.parts.iter().zip(&v.parts).all(|(a, b)| a.body != Body::Missing || b.body == Body::Missing))
}

/// Reading-only keys are dropped once their commit is judged in full: its last part applied, or
/// it is judged bad. A commit thrown out whole keeps them (`Outcome::revisit`).
fn settle_reading(h: &Held, o: &crate::model::Outcome, reading: &mut BTreeMap<CommitId, BTreeSet<SyncId>>, id: CommitId) {
    let thrown = !o.applied.contains(&id) || h.commits.iter().find(|c| c.id == id).is_some_and(|c| c.parts.iter().any(|p| p.body == Body::Missing));
    if !thrown {
        reading.remove(&id);
    }
}

/// The node's keys: its own, reading-only, and those of valid grants held.
fn key_set(lib: &Library, h: &Held, reading: &BTreeMap<CommitId, BTreeSet<SyncId>>) -> BTreeSet<SyncId> {
    let o = evaluate(h);
    let mut keys = lib.keys.clone();
    keys.extend(reading.values().flatten());
    for c in h.commits.iter().filter(|c| o.applied.contains(&c.id)) {
        // a box on a part judged invalid opens nothing the node may rely on
        for b in &c.boxes {
            let ok = c.parts.iter().enumerate().any(|(i, p)| p.thing == b.thing && o.valid.get(&(c.id, i)) == Some(&true));
            if ok {
                keys.insert(b.key);
            }
        }
    }
    keys
}

/// `held` of every entry the given keys open, at once (the order the creation-first reader sees).
pub fn creation_first(lib: &Library, keys: &BTreeSet<SyncId>) -> Held {
    let mut held = Held { now: lib.now, me: lib.me, records: lib.records.clone(), commits: vec![], dots: vec![], external_fires: ExternalFires::Any };
    let es: BTreeSet<(SyncId, CommitId)> = lib.entries().into_iter().filter(|(l, _)| keys.contains(l)).collect();
    for (l, id) in es {
        arrive(&mut held, lib.delivered(lib.commits.iter().find(|c| c.id == id).unwrap(), l));
    }
    held
}

/// The sync IDs reachable through every box of what is reachable (a valid-grant world: every box
/// that names a real sync ID is a valid grant's).
pub fn reachable(lib: &Library) -> BTreeSet<SyncId> {
    let mut keys = lib.keys.clone();
    loop {
        let before = keys.clone();
        for (l, id) in lib.entries() {
            if keys.contains(&l) {
                let c = lib.commits.iter().find(|c| c.id == id).unwrap();
                keys.extend(lib.delivered(c, l).boxes.iter().map(|b| b.key));
            }
        }
        if keys == before {
            return keys;
        }
    }
}
