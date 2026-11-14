//! Deleting a large value's pieces by link (notes/chunk-links.md): a link carries its
//! blob's salt and delete keys (Del, the writer's claim); a node dropping a body records the
//! body's links in a durable per-thing **freed set** and, link by link, judges each against the
//! sources of its thing it still holds (bodies and live states): a piece one of them reaches stays;
//! an unreached interior node is walked (its plaintext held or fetched) and its links join the set;
//! an unreached piece is deleted at every host entry of the thing's labels the node holds the
//! label key of, signed by a key Del names that the node holds. A host accepts a delete only when
//! the blob's commitments, under the thing it was signed for, bear that key (the thing blind binds
//! commitments to one thing). A judgment needing a node blob nobody serves waits.
//!
//! Brute force and small: every judgment recomputes reach from the truth of the trees, which the
//! node may use only once it holds every node blob on the way (else it fetches or waits).
//! Independent of the engine; written from the design, not the code.

use crate::gen::Rng;
use std::collections::{BTreeMap, BTreeSet};

pub type Thing = u8;
pub type SyncId = u8;
pub type Pid = usize;
/// A delete key at its level (1 admin, 2 author, 3 writer) and its identity.
pub type DelKey = (u8, u16);

/// A blob: its commitments are bound to `thing` (the thing blind of its link blind) and bear
/// `group`; an interior node links `kids` (a chunk links nothing).
#[derive(Clone, Debug)]
pub struct Piece {
    pub thing: Thing,
    pub group: BTreeSet<DelKey>,
    pub kids: Vec<Link>,
}

/// A link: the piece and the delete keys its writer claims (salt implied by the piece).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Link {
    pub piece: Pid,
    pub del: Vec<DelKey>,
}

/// A body or a live state of a thing: the links it holds (value roots, pages).
#[derive(Clone, Debug)]
pub struct Source {
    pub thing: Thing,
    pub links: Vec<Link>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeState {
    /// Sources held (indices into `World::sources`).
    pub held: BTreeSet<usize>,
    /// Interior node blobs whose plaintext the node holds.
    pub blobs: BTreeSet<Pid>,
    /// Delete keys the node holds, per thing (a key signs for any thing; listed per thing for
    /// generation only).
    pub keys: BTreeSet<DelKey>,
    /// Labels whose key the node holds.
    pub labels: BTreeSet<SyncId>,
    /// The freed set: (thing, link) still to judge or delete.
    pub freed: BTreeSet<(Thing, Link)>,
}

/// A delete the host accepted: by `node`, of `piece`'s entry under `label`, signed for `thing`.
#[derive(Clone, Debug)]
pub struct Deleted {
    pub node: usize,
    pub label: SyncId,
    pub piece: Pid,
    pub thing: Thing,
    pub key: DelKey,
}

#[derive(Clone, Debug, Default)]
pub struct World {
    pub pieces: Vec<Piece>,
    pub sources: Vec<Source>,
    /// The labels of each thing.
    pub labels: BTreeMap<Thing, Vec<SyncId>>,
    /// Live host entries (label, piece).
    pub entries: BTreeSet<(SyncId, Pid)>,
    pub nodes: Vec<NodeState>,
    pub deleted: Vec<Deleted>,
}

/// What one step of a node's freed set did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A piece a held source of its thing reaches: leaves the set, kept.
    Kept,
    /// Walked (interior links joined the set) and deleted where the node could.
    Done,
    /// Waits for a node blob nobody serves.
    Waits,
}

impl World {
    /// The pieces `links` reach, following interior nodes by the truth of the trees.
    pub fn reach(&self, links: impl IntoIterator<Item = Pid>) -> BTreeSet<Pid> {
        let mut out = BTreeSet::new();
        let mut todo: Vec<Pid> = links.into_iter().collect();
        while let Some(p) = todo.pop() {
            if out.insert(p) {
                todo.extend(self.pieces[p].kids.iter().map(|l| l.piece));
            }
        }
        out
    }

    /// The pieces the held sources of `thing` at node `n` reach.
    pub fn held_reach(&self, n: usize, thing: Thing) -> BTreeSet<Pid> {
        let roots = self.nodes[n].held.iter().filter(|s| self.sources[**s].thing == thing).flat_map(|s| self.sources[*s].links.iter().map(|l| l.piece));
        self.reach(roots)
    }

    /// Whether node `n` may read interior node `p`: it holds it, or fetches it (a host entry of
    /// one of its labels, or another node holding it).
    fn fetch(&mut self, n: usize, p: Pid) -> bool {
        if self.nodes[n].blobs.contains(&p) {
            return true;
        }
        let at_host = self.entries.iter().any(|(g, q)| *q == p && self.nodes[n].labels.contains(g));
        let at_peer = self.nodes.iter().enumerate().any(|(m, s)| m != n && s.blobs.contains(&p));
        if at_host || at_peer {
            self.nodes[n].blobs.insert(p);
        }
        at_host || at_peer
    }

    /// Node `n` drops held source `s`: its links join the freed set first (durable), then the
    /// body goes.
    pub fn drop_source(&mut self, n: usize, s: usize) {
        let src = self.sources[s].clone();
        for l in src.links {
            self.nodes[n].freed.insert((src.thing, l));
        }
        self.nodes[n].held.remove(&s);
    }

    /// One step of node `n` on freed link `(thing, l)`.
    pub fn step(&mut self, n: usize, thing: Thing, l: &Link) -> Step {
        // the reach of the held sources needs every interior node on the way
        let roots: Vec<Pid> = self.nodes[n].held.iter().filter(|s| self.sources[**s].thing == thing).flat_map(|s| self.sources[*s].links.iter().map(|l| l.piece)).collect();
        for p in self.reach(roots) {
            if !self.pieces[p].kids.is_empty() && !self.fetch(n, p) {
                return Step::Waits;
            }
        }
        if self.held_reach(n, thing).contains(&l.piece) {
            self.nodes[n].freed.remove(&(thing, l.clone()));
            return Step::Kept;
        }
        let kids = self.pieces[l.piece].kids.clone();
        if !kids.is_empty() {
            if !self.fetch(n, l.piece) {
                return Step::Waits;
            }
            for k in kids {
                self.nodes[n].freed.insert((thing, k));
            }
            self.nodes[n].blobs.remove(&l.piece);
        }
        let labels = self.labels.get(&thing).cloned().unwrap_or_default();
        for g in labels {
            if !self.nodes[n].labels.contains(&g) || !self.entries.contains(&(g, l.piece)) {
                continue;
            }
            // sign with a key Del names that the node holds; the host checks the prefix
            let Some(key) = l.del.iter().copied().find(|k| self.nodes[n].keys.contains(k)) else { continue };
            let piece = &self.pieces[l.piece];
            if piece.thing == thing && piece.group.contains(&key) {
                self.entries.remove(&(g, l.piece));
                self.deleted.push(Deleted { node: n, label: g, piece: l.piece, thing, key });
            }
        }
        self.nodes[n].freed.remove(&(thing, l.clone()));
        Step::Done
    }

    /// Runs every node's freed set in a random interleaving until nothing moves.
    pub fn settle(&mut self, rng: &mut Rng) {
        loop {
            let mut work: Vec<(usize, Thing, Link)> = self.nodes.iter().enumerate().flat_map(|(n, s)| s.freed.iter().map(move |(t, l)| (n, *t, l.clone()))).collect();
            rng.shuffle(&mut work);
            let mut moved = false;
            for (n, t, l) in work {
                if self.nodes[n].freed.contains(&(t, l.clone())) && self.step(n, t, &l) != Step::Waits {
                    moved = true;
                }
            }
            if !moved {
                return;
            }
        }
    }
}

/// A writer making values on things: honest reuse follows the re-encryption rule (a piece is
/// reused iff its level-1 and level-3 commitments are exactly the delta's keys and its level-2
/// key is the delta's, or the delta lists another level-2 key beside a level-1 or 3 one); a
/// hostile one copies any link it read, of any thing, Del and all, or claims a false Del.
pub struct Writer {
    pub keys: BTreeSet<DelKey>,
    pub hostile: bool,
}

impl Writer {
    pub fn keeps(&self, group: &BTreeSet<DelKey>) -> bool {
        let non2 = |s: &BTreeSet<DelKey>| s.iter().filter(|k| k.0 != 2).copied().collect::<BTreeSet<_>>();
        let author = |s: &BTreeSet<DelKey>| s.iter().filter(|k| k.0 == 2).copied().collect::<BTreeSet<_>>();
        let shared = !author(&self.keys).is_empty() && !non2(&self.keys).is_empty();
        non2(group) == non2(&self.keys) && (shared || author(group).is_subset(&author(&self.keys)))
    }
}

/// Generates a world: two things (labels 1 and 2 for thing 1, label 1 for thing 2), writers with
/// per-thing level-1 and level-3 keys and author keys, values as trees of depth up to two
/// reusing earlier pieces of their thing, the odd forged link or false Del, and nodes holding a
/// subset of the sources, of the node blobs, of the keys and of the labels.
pub fn world(seed: u64) -> (World, Rng) {
    let mut rng = Rng::new(seed);
    let mut w = World::default();
    w.labels.insert(1, vec![1, 2]);
    w.labels.insert(2, vec![1]);
    // thing t: admin key (1, t*10+e), writer key (3, t*10+e) per epoch e; authors (2, 100+a)
    let epoch = |rng: &mut Rng| rng.below(2) as u16;
    let mut known: BTreeMap<Thing, Vec<Link>> = BTreeMap::new();
    let n_values = 2 + rng.below(4) as usize;
    for _ in 0..n_values {
        let thing: Thing = 1 + rng.below(2) as Thing;
        let e = epoch(&mut rng);
        let mut keys = BTreeSet::new();
        if rng.chance(70) {
            keys.insert((1, thing as u16 * 10 + e));
        }
        if rng.chance(50) {
            keys.insert((2, 100 + rng.below(2) as u16));
        }
        if rng.chance(40) {
            keys.insert((3, thing as u16 * 10 + e));
        }
        let wr = Writer { keys, hostile: rng.chance(15) };
        let mut roots = Vec::new();
        for _ in 0..1 + rng.below(2) {
            let root = value(&mut w, &mut rng, &wr, thing, &known, 2);
            roots.push(root);
        }
        // a hostile writer copies a link of the other thing it reads
        if wr.hostile {
            let other = if thing == 1 { 2 } else { 1 };
            if let Some(l) = known.get(&other).and_then(|ls| (!ls.is_empty()).then(|| ls[rng.below(ls.len() as u64) as usize].clone())) {
                for g in w.labels[&thing].clone() {
                    w.entries.insert((g, l.piece));
                }
                roots.push(l);
            }
        }
        for r in &roots {
            known.entry(thing).or_default().push(r.clone());
            let mut todo = vec![r.clone()];
            while let Some(l) = todo.pop() {
                known.entry(thing).or_default().push(l.clone());
                todo.extend(w.pieces[l.piece].kids.clone());
            }
        }
        w.sources.push(Source { thing, links: roots });
    }
    let all_keys: BTreeSet<DelKey> = w.pieces.iter().flat_map(|p| p.group.iter().copied()).collect();
    for _ in 0..2 + rng.below(2) {
        let mut s = NodeState::default();
        for i in 0..w.sources.len() {
            if rng.chance(60) {
                s.held.insert(i);
            }
        }
        for p in w.reach(s.held.iter().flat_map(|i| w.sources[*i].links.iter().map(|l| l.piece)).collect::<Vec<_>>()) {
            if !w.pieces[p].kids.is_empty() && rng.chance(80) {
                s.blobs.insert(p);
            }
        }
        for k in &all_keys {
            if rng.chance(60) {
                s.keys.insert(*k);
            }
        }
        for g in [1, 2] {
            if rng.chance(75) {
                s.labels.insert(g);
            }
        }
        w.nodes.push(s);
    }
    (w, rng)
}

/// A value tree of up to `depth` levels on `thing` by `wr`: each child reuses a known piece of the
/// thing when the rule keeps it (half the time), else is new.
fn value(w: &mut World, rng: &mut Rng, wr: &Writer, thing: Thing, known: &BTreeMap<Thing, Vec<Link>>, depth: u32) -> Link {
    if let Some(ls) = known.get(&thing) {
        let fits: Vec<&Link> = ls.iter().filter(|l| wr.hostile || (w.pieces[l.piece].thing == thing && wr.keeps(&w.pieces[l.piece].group) && l.del.iter().copied().collect::<BTreeSet<_>>() == w.pieces[l.piece].group)).collect();
        if !fits.is_empty() && rng.chance(40) {
            return fits[rng.below(fits.len() as u64) as usize].clone();
        }
    }
    let kids = if depth > 0 && rng.chance(60) { (0..1 + rng.below(3)).map(|_| value(w, rng, wr, thing, known, depth - 1)).collect() } else { Vec::new() };
    let id = w.pieces.len();
    w.pieces.push(Piece { thing, group: wr.keys.clone(), kids });
    for g in w.labels[&thing].clone() {
        w.entries.insert((g, id));
    }
    let mut del: Vec<DelKey> = wr.keys.iter().copied().collect();
    if wr.hostile && rng.chance(50) {
        del = vec![(1, 999)];
    }
    Link { piece: id, del }
}
