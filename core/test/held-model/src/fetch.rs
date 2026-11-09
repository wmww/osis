//! Fetching what judges what the node holds (notes/expiry-creation-design.md §3): which entries a
//! node can open, what it keeps of an entry it cannot judge, and the fixed point it reaches.
//! A label holds a commit's parts on its things, or the whole commit where a copy is placed under
//! it (a home-label sibling). An entry is delivered only under a label the node holds a key for.
//! A part or commit that cannot be judged is discarded (`act`); before that, boxes opening with
//! the node's own key are read: reading-only keys, sourced from the commit, that open further
//! labels. They go when the commit's last part applies (a valid grant's key stays) or it is judged
//! bad. Parts are re-fetched when a record or edge arrives, modelled as whole passes over the
//! entries until nothing changes: a pass refetches only what is not held.

use crate::model::{act, evaluate};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// What hosts hold.
#[derive(Clone, Debug, Default)]
pub struct Library {
    pub now: u64,
    pub me: NodeId,
    /// Records known from the start.
    pub records: Vec<Record>,
    /// The labels each thing's parts are placed under.
    pub labels: BTreeMap<ThingId, BTreeSet<Label>>,
    /// Further labels holding a whole commit (a home-label sibling copy).
    pub copies: BTreeMap<CommitId, BTreeSet<Label>>,
    pub commits: Vec<Commit>,
    /// Keys the node holds from the start.
    pub keys: BTreeSet<Label>,
}

impl Library {
    fn places(&self, c: &Commit, label: Label) -> bool {
        self.copies.get(&c.id).is_some_and(|s| s.contains(&label)) || c.parts.iter().any(|p| self.part_in(p, label))
    }
    fn part_in(&self, p: &Part, label: Label) -> bool {
        self.labels.get(&p.thing).is_some_and(|s| s.contains(&label))
    }
    fn entries(&self) -> Vec<(Label, CommitId)> {
        let mut ls: BTreeSet<Label> = self.labels.values().flatten().copied().collect();
        ls.extend(self.copies.values().flatten());
        ls.into_iter().flat_map(|l| self.commits.iter().filter(move |c| self.places(c, l)).map(move |c| (l, c.id))).collect()
    }
    /// The commit as delivered under `label`.
    fn delivered(&self, c: &Commit, label: Label) -> Commit {
        let whole = self.copies.get(&c.id).is_some_and(|s| s.contains(&label));
        let mut v = c.clone();
        for p in &mut v.parts {
            if !whole && !self.part_in(p, label) {
                p.body = Body::Missing;
            }
        }
        v.boxes = c.boxes.iter().filter(|b| whole || self.labels.get(&b.thing).is_some_and(|s| s.contains(&label))).copied().collect();
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

/// The fixed point: every label the node can come to hold a key for, and what it holds.
pub struct Fetched {
    pub held: Held,
    pub keys: BTreeSet<Label>,
    pub fetches: u64,
}

/// Runs the node's fetch loop to quiescence. `order` shuffles a pass's entries (arrival order);
/// `reading_only` false throws boxes away with what is discarded (the deadlock this design avoids).
pub fn settle(lib: &Library, order: &mut dyn FnMut(&mut Vec<(Label, CommitId)>), reading_only: bool) -> Fetched {
    let mut held = Held { now: lib.now, me: lib.me, records: lib.records.clone(), commits: vec![], dots: vec![] };
    // reading-only keys by the commit they are sourced from
    let mut reading: BTreeMap<CommitId, BTreeSet<Label>> = BTreeMap::new();
    let mut fetches = 0;
    loop {
        let keys = key_set(lib, &held, &reading);
        let before = (held.clone(), keys.clone());
        let mut es: Vec<(Label, CommitId)> = lib.entries().into_iter().filter(|(l, _)| keys.contains(l)).collect();
        order(&mut es);
        for (l, id) in es {
            let c = lib.commits.iter().find(|c| c.id == id).unwrap();
            let v = lib.delivered(c, l);
            if holds_all(&held, &v) {
                continue;
            }
            fetches += 1;
            let boxes = v.boxes.clone();
            arrive(&mut held, v);
            if reading_only {
                reading.entry(id).or_default().extend(boxes.iter().map(|b| b.key));
            }
            let o = evaluate(&held);
            held = act(&held, &o, None);
            settle_reading(&held, &o, &mut reading, id);
        }
        // every held fate carried out (records and edges changed: discards wake)
        let o = evaluate(&held);
        held = act(&held, &o, None);
        for id in reading.keys().copied().collect::<Vec<_>>() {
            settle_reading(&held, &o, &mut reading, id);
        }
        let keys = key_set(lib, &held, &reading);
        if (held.clone(), keys.clone()) == before {
            return Fetched { held, keys, fetches };
        }
    }
}

/// Whether a delivered copy brings nothing the node does not hold.
fn holds_all(h: &Held, v: &Commit) -> bool {
    h.commits.iter().find(|c| c.id == v.id).is_some_and(|c| c.parts.iter().zip(&v.parts).all(|(a, b)| a.body != Body::Missing || b.body == Body::Missing))
}

/// Reading-only keys are dropped once their commit is judged in full: its last part applied, or
/// it is judged bad. A commit thrown out whole keeps them (`Outcome::revisit`).
fn settle_reading(h: &Held, o: &crate::model::Outcome, reading: &mut BTreeMap<CommitId, BTreeSet<Label>>, id: CommitId) {
    let thrown = !o.applied.contains(&id) || h.commits.iter().find(|c| c.id == id).is_some_and(|c| c.parts.iter().any(|p| p.body == Body::Missing));
    if !thrown {
        reading.remove(&id);
    }
}

/// The node's keys: its own, reading-only, and those of valid grants held.
fn key_set(lib: &Library, h: &Held, reading: &BTreeMap<CommitId, BTreeSet<Label>>) -> BTreeSet<Label> {
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
pub fn creation_first(lib: &Library, keys: &BTreeSet<Label>) -> Held {
    let mut held = Held { now: lib.now, me: lib.me, records: lib.records.clone(), commits: vec![], dots: vec![] };
    let es: BTreeSet<(Label, CommitId)> = lib.entries().into_iter().filter(|(l, _)| keys.contains(l)).collect();
    for (l, id) in es {
        arrive(&mut held, lib.delivered(lib.commits.iter().find(|c| c.id == id).unwrap(), l));
    }
    held
}

/// The labels reachable through every box of what is reachable (a valid-grant world: every box
/// that names a real label is a valid grant's).
pub fn reachable(lib: &Library) -> BTreeSet<Label> {
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
