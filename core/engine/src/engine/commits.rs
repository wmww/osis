//! The commits index (`Indexes::commits`) and the `Meta` it holds per applied commit, read facet
//! by facet: a commit's fixed facts (its view, header, arrival and origin) are read by its key,
//! which moves only when the commit comes or goes; each part's hold and validity by a key of its
//! own (`Facet::Part`); the parts whole and the rest (signature verdict, repair mark) by a key
//! each. A meta in the index carries a reader of the index's stamps, and each accessor of a
//! mutable field records its facet as it is used, so a judgement of one part's body moves when
//! that part's state does, not with every other part of the commit.

use super::journal::Journaled;
use super::{Dropped, DropFor, Hold, LazyHeader, Missing, View, index};
use crate::events::Origin;
use osis_base::memo::{Reader, Stamps};
use osis_base::{Ak, BlobId, CommitId, Tid, WallMs};
use osis_commit::Header;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::sync::Arc;

/// A key of a commit's mutable state in the index's stamps (the commit ID itself stands for its
/// presence and fixed facts).
#[derive(Hash)]
enum Facet {
    /// Part `ai`'s hold and validity.
    Part(CommitId, usize),
    /// Every part's, read together (`Meta::valid`, `hold_all`, the parts by state).
    Parts(CommitId),
    /// The signature verdict and the repair mark.
    Rest(CommitId),
}

/// An indexed meta's reader of the index's stamps (`None` for a meta outside it: a copy, one
/// being built). A clone reads everything mutable of the original and records nothing itself.
#[derive(Default)]
struct Rec(Option<(Reader, CommitId)>);

impl Rec {
    fn read(&self, f: impl FnOnce(CommitId) -> Facet) {
        if let Some((r, c)) = &self.0 {
            r.read(&f(*c));
        }
    }
}

impl Clone for Rec {
    fn clone(&self) -> Rec {
        self.read(Facet::Parts);
        self.read(Facet::Rest);
        Rec(None)
    }
}

impl std::fmt::Debug for Rec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("..")
    }
}

/// An applied commit as the engine indexes it.
#[derive(Clone, Debug)]
pub struct Meta {
    /// What the per-commit indexes read of the header (an open reads it from the index).
    pub view: Arc<View>,
    /// Decoded on first use (an open decodes no header the indexes do not need).
    pub header: LazyHeader,
    pub received: WallMs,
    pub origin: Origin,
    /// An own commit a repair wrote (`Engine::relink`, spec/sync-ids.md §1 Repair), with the blobs
    /// it encrypted afresh: those are never repaired by way of it (the chunks it reused are).
    repair: Option<Arc<BTreeSet<BlobId>>>,
    /// Its held signatures' verdict (`apply::signature`), kept in its record's head.
    signed: osis_commit::Signed,
    /// Validity per aspect (spec/permissions.md §5.2).
    valid: Vec<bool>,
    /// What this node holds of each part, by aspect index (`Hold`).
    hold: Vec<Hold>,
    rec: Rec,
}

impl Meta {
    /// A commit's meta from its decoded header: parts in `missing` missing, the rest as `head`
    /// says (`Hold::stored`).
    pub(crate) fn new(header: Arc<Header>, paths: Option<Arc<BTreeMap<Tid, bool>>>, valid: Vec<bool>, mut head: index::RecordHead, missing: BTreeSet<usize>) -> Meta {
        let hold = (0..valid.len()).map(|ai| Hold::stored(ai, &mut head, missing.contains(&ai), false)).collect();
        Meta::of(Arc::new(View::of(&header, paths)), LazyHeader::ready(header), head.received, head.origin, head.repair.clone(), head.signed, valid, hold)
    }
    /// A meta of its fields.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn of(view: Arc<View>, header: LazyHeader, received: WallMs, origin: Origin, repair: Option<Arc<BTreeSet<BlobId>>>, signed: osis_commit::Signed, valid: Vec<bool>, hold: Vec<Hold>) -> Meta {
        Meta { view, header, received, origin, repair, signed, valid, hold, rec: Rec::default() }
    }
    /// How many parts the commit has (fixed by its header).
    pub fn parts(&self) -> usize {
        self.hold.len()
    }
    /// The index of aspect `(tid, ak)` in the commit.
    pub(crate) fn aspect(&self, tid: &Tid, ak: &Ak) -> Option<usize> {
        self.view.aspect(tid, ak.as_str())
    }
    /// The blobs a repair encrypted afresh, if a repair wrote it.
    pub fn repair(&self) -> Option<&Arc<BTreeSet<BlobId>>> {
        self.rec.read(Facet::Rest);
        self.repair.as_ref()
    }
    pub(crate) fn set_repair(&mut self, r: Option<Arc<BTreeSet<BlobId>>>) {
        self.repair = r;
    }
    /// Its held signatures' verdict.
    pub fn signed(&self) -> osis_commit::Signed {
        self.rec.read(Facet::Rest);
        self.signed
    }
    /// Validity per aspect, every part read.
    pub fn valid(&self) -> &[bool] {
        self.rec.read(Facet::Parts);
        &self.valid
    }
    pub(crate) fn set_valid(&mut self, v: Vec<bool>) {
        self.valid = v;
    }
    pub(crate) fn valid_mut(&mut self) -> &mut Vec<bool> {
        &mut self.valid
    }
    /// What is held of each part, every part read.
    pub fn hold_all(&self) -> &[Hold] {
        self.rec.read(Facet::Parts);
        &self.hold
    }
    /// What is held of part `ai`.
    pub fn hold(&self, ai: usize) -> Option<&Hold> {
        self.rec.read(|c| Facet::Part(c, ai));
        self.hold.get(ai)
    }
    /// Whether part `ai` is valid here.
    pub(crate) fn valid_at(&self, ai: usize) -> bool {
        self.rec.read(|c| Facet::Part(c, ai));
        self.valid.get(ai).copied().unwrap_or(false)
    }
    /// Sets what is held of part `ai`.
    pub(crate) fn set_hold(&mut self, ai: usize, h: Hold) {
        if let Some(x) = self.hold.get_mut(ai) {
            *x = h;
        }
    }
    /// Whether part `ai` is held: its body or its leftover.
    pub fn holds(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Body { .. } | Hold::Leftover { .. }))
    }
    /// Whether part `ai` is held as its leftover (`Hold::Leftover`).
    pub fn stripped(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Leftover { .. }))
    }
    /// Whether part `ai` is held as a leftover holding values (`Hold::Leftover::valued`).
    pub fn valued(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Leftover { valued: true, .. }))
    }
    /// Whether part `ai` is held as a leftover for its own writes gone value-less (expired,
    /// purged): no values to keep, so no keep bounds.
    pub fn bare(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Leftover { valued: false, .. }))
    }
    /// Whether held part `ai` replaces its aspect whole (`Hold::Body::whole`).
    pub fn whole(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Body { whole: true } | Hold::Leftover { whole: true, .. }))
    }
    /// Marks held part `ai` as a whole replace.
    pub(crate) fn set_whole(&mut self, ai: usize) {
        if let Some(Hold::Body { whole } | Hold::Leftover { whole, .. }) = self.hold.get_mut(ai) {
            *whole = true;
        }
    }
    /// Whether part `ai` is missing (`Hold::Missing`).
    pub fn missing(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Missing(_)))
    }
    /// Why part `ai` is missing, if it is.
    pub fn missing_as(&self, ai: usize) -> Option<Missing> {
        match self.hold(ai) {
            Some(Hold::Missing(x)) => Some(*x),
            _ => None,
        }
    }
    /// What dropped part `ai` keeps, if it is dropped.
    pub fn dropped(&self, ai: usize) -> Option<&Dropped> {
        match self.hold(ai) {
            Some(Hold::Dropped(d)) => Some(d),
            _ => None,
        }
    }
    /// `dropped`, to change what it keeps.
    pub(crate) fn dropped_mut(&mut self, ai: usize) -> Option<&mut Dropped> {
        match self.hold.get_mut(ai) {
            Some(Hold::Dropped(d)) => Some(d),
            _ => None,
        }
    }
    /// Whether part `ai` is dropped.
    pub fn is_dropped(&self, ai: usize) -> bool {
        self.dropped(ai).is_some()
    }
    /// The dropped parts, by aspect index.
    pub fn dropped_parts(&self) -> impl Iterator<Item = (usize, &Dropped)> + '_ {
        self.hold_all().iter().enumerate().filter_map(|(ai, h)| match h {
            Hold::Dropped(d) => Some((ai, d)),
            _ => None,
        })
    }
    /// The missing parts, by aspect index.
    pub fn missing_parts(&self) -> impl Iterator<Item = usize> + '_ {
        self.hold_all().iter().enumerate().filter(|(_, h)| matches!(h, Hold::Missing(_))).map(|(ai, _)| ai)
    }
    /// The parts held as their leftover, by aspect index.
    pub fn stripped_parts(&self) -> impl Iterator<Item = usize> + '_ {
        self.hold_all().iter().enumerate().filter(|(_, h)| matches!(h, Hold::Leftover { .. })).map(|(ai, _)| ai)
    }
    /// Whether part `ai` has no body to log or keep at peers: dropped, or held as its leftover
    /// (spec/commits.md §5: purged, expired).
    pub fn body_gone(&self, ai: usize) -> bool {
        matches!(self.hold(ai), Some(Hold::Dropped(_) | Hold::Leftover { .. }))
    }
    /// Whether part `ai` was dropped while invalid (`DropFor::Invalid`).
    pub fn dropped_invalid(&self, ai: usize) -> bool {
        self.dropped(ai).is_some_and(|d| d.why == DropFor::Invalid)
    }
}

/// The commits index: a journaled map of `Meta` (each change journals the value it replaced,
/// once per transaction or step), stamped by facet (the module doc).
#[derive(Debug, Default)]
pub struct Commits {
    map: BTreeMap<CommitId, Meta>,
    stamps: Stamps,
    log: Vec<(CommitId, Option<Meta>)>,
    /// The keys `log` holds since the last mark.
    seen: BTreeSet<CommitId>,
}

/// A copy's metas read the copy's stamps.
impl Clone for Commits {
    fn clone(&self) -> Commits {
        let stamps = self.stamps.clone();
        let mut map = self.map.clone();
        for (c, m) in map.iter_mut() {
            m.rec = Rec(Some((stamps.reader(), *c)));
        }
        Commits { map, stamps, log: self.log.clone(), seen: self.seen.clone() }
    }
}

impl Deref for Commits {
    type Target = BTreeMap<CommitId, Meta>;
    fn deref(&self) -> &BTreeMap<CommitId, Meta> {
        self.stamps.read_all();
        &self.map
    }
}

/// Whether two metas of one commit hold the same fixed facts (those its key stands for).
fn fixed_same(a: &Meta, b: &Meta) -> bool {
    (Arc::ptr_eq(&a.view, &b.view) || a.view == b.view) && a.header.same(&b.header) && a.received == b.received && a.origin == b.origin
}

impl Commits {
    /// Commit `c`'s meta (a read of its fixed facts; its accessors read the rest as used).
    pub fn get(&self, c: &CommitId) -> Option<&Meta> {
        self.stamps.read(c);
        self.map.get(c)
    }
    pub fn contains_key(&self, c: &CommitId) -> bool {
        self.stamps.read(c);
        self.map.contains_key(c)
    }
    /// Stamps what replacing `old` by `new` at `c` moved (`added`: `c` was absent).
    fn stamp(&self, c: &CommitId, old: Option<&Meta>, new: Option<&Meta>) {
        let parts = old.map_or(0, |m| m.hold.len()).max(new.map_or(0, |m| m.hold.len()));
        match (old, new) {
            (None, None) => {}
            (Some(o), Some(n)) => {
                if !fixed_same(o, n) {
                    self.stamps.wrote(c, true);
                }
                if o.signed != n.signed || o.repair != n.repair {
                    self.stamps.wrote(&Facet::Rest(*c), true);
                }
                let mut any = false;
                for ai in 0..parts {
                    if o.hold.get(ai) != n.hold.get(ai) || o.valid.get(ai) != n.valid.get(ai) {
                        self.stamps.wrote(&Facet::Part(*c, ai), true);
                        any = true;
                    }
                }
                if any {
                    self.stamps.wrote(&Facet::Parts(*c), true);
                }
            }
            (o, n) => {
                let present = n.is_some();
                match present {
                    true => self.stamps.wrote_added(c, true, o.is_none()),
                    false => self.stamps.wrote_removed(c),
                }
                self.stamps.wrote(&Facet::Rest(*c), present);
                self.stamps.wrote(&Facet::Parts(*c), present);
                for ai in 0..parts {
                    self.stamps.wrote(&Facet::Part(*c, ai), present);
                }
            }
        }
    }
    /// Journals `c`'s value before this transaction's first change of it.
    fn note(&mut self, c: &CommitId, old: &Option<Meta>) {
        if self.seen.insert(*c) {
            self.log.push((*c, old.as_ref().map(Meta::clone_raw)));
        }
    }
    fn attach(&self, c: &CommitId, m: &mut Meta) {
        m.rec = Rec(Some((self.stamps.reader(), *c)));
    }
    pub fn insert(&mut self, c: CommitId, mut m: Meta) -> Option<Meta> {
        self.stamp(&c, self.map.get(&c), Some(&m));
        self.attach(&c, &mut m);
        let mut old = self.map.insert(c, m);
        self.note(&c, &old);
        if let Some(o) = &mut old {
            o.rec = Rec::default();
        }
        old
    }
    pub fn remove(&mut self, c: &CommitId) -> Option<Meta> {
        let mut old = self.map.remove(c);
        self.stamp(c, old.as_ref(), None);
        self.note(c, &old);
        if let Some(o) = &mut old {
            o.rec = Rec::default();
        }
        old
    }
    /// Changes `c`'s meta in place by `f`, if it is held.
    pub fn update(&mut self, c: &CommitId, f: impl FnOnce(&mut Meta)) {
        let Some(old) = self.map.get(c).map(Meta::clone_raw) else { return };
        let mut new = old.clone_raw();
        f(&mut new);
        self.insert(*c, new);
    }
    /// A reader's cursor over the commits added from now on (`memo::Feed`), an undo restoring one
    /// included; one added and then undone is given too (the reader finds it absent).
    pub fn feed(&self) -> osis_base::memo::Feed<CommitId> {
        self.stamps.feed()
    }
    /// A reader's cursor over the commits removed from now on (`memo::Removals`).
    pub fn removals(&self) -> osis_base::memo::Removals<CommitId> {
        self.stamps.removals()
    }
    /// What the running transaction changed, each commit with its meta before it.
    pub fn before(&self) -> BTreeMap<&CommitId, Option<&Meta>> {
        let mut out = BTreeMap::new();
        for (k, v) in &self.log {
            out.entry(k).or_insert(v.as_ref());
        }
        out
    }
    /// The commits the running transaction changed.
    pub fn logged(&self) -> Vec<CommitId> {
        let s: BTreeSet<&CommitId> = self.log.iter().map(|(k, _)| k).collect();
        s.into_iter().copied().collect()
    }
}

impl Meta {
    /// A copy outside the index, reading nothing (the index's own upkeep).
    fn clone_raw(&self) -> Meta {
        Meta { view: self.view.clone(), header: self.header.clone(), received: self.received, origin: self.origin, repair: self.repair.clone(), signed: self.signed, valid: self.valid.clone(), hold: self.hold.clone(), rec: Rec::default() }
    }
}

impl Journaled for Commits {
    #[cfg(test)]
    fn contents(&self) -> String {
        format!("{:?}", self.map)
    }
    type Mark = usize;
    fn name(&mut self, name: &'static str) {
        self.stamps.rename(name);
    }
    fn commit(&mut self) {
        self.log.clear();
        self.seen.clear();
    }
    // a key changed after the mark is journaled again: its entry restores the value at the mark
    fn mark(&mut self) -> usize {
        self.seen.clear();
        self.log.len()
    }
    fn rollback_to(&mut self, m: usize) {
        self.seen.clear();
        while self.log.len() > m {
            let Some((c, old)) = self.log.pop() else { break };
            self.stamp(&c, self.map.get(&c), old.as_ref());
            match old {
                Some(mut v) => {
                    self.attach(&c, &mut v);
                    self.map.insert(c, v);
                }
                None => {
                    self.map.remove(&c);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Commits, Hold, Journaled, Meta};
    use crate::Mutation;
    use crate::engine::Dropped;
    use crate::local_peer::LocalPeer;
    use osis_base::memo::Effects;
    use osis_base::{Ak, CommitId, Value, WallMs};

    /// A held commit's meta with a part on each of two things.
    fn two_parts() -> (CommitId, Meta) {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let (t, u) = (lp.peers[0].engine.new_thing(&mut m, a), lp.peers[0].engine.new_thing(&mut m, a));
        lp.peers[0].commit(m).unwrap();
        let mut m = Mutation::new();
        for x in [t, u] {
            m.set(x, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        }
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let meta = lp.peers[0].engine.core.ix.commits.get(&id).unwrap().clone();
        assert_eq!(meta.parts(), 2);
        (id, meta)
    }

    /// Settles every due key of `fx` (0: part 0's hold, 1: part 1's, 2: the fixed facts, 3: every
    /// part, 4: a copy taken), the keys due first.
    fn settle(fx: &mut Effects<u8, String>, ix: &Commits, c: &CommitId) -> Vec<u8> {
        let due = fx.due();
        for k in &due {
            fx.settle(k, || {
                let Some(m) = ix.get(c) else { return String::new() };
                match k {
                    0 => format!("{:?}", m.hold(0)),
                    1 => format!("{:?}", m.hold(1)),
                    2 => format!("{:?}", m.view.kind),
                    3 => format!("{:?}", m.valid()),
                    _ => format!("{:?}", m.clone().hold_all()),
                }
            });
        }
        due
    }

    // spec/sync.md §2, notes/engine.md (Stamps): a part's record bytes are read at its hold; read
    // mid-write, its hold saying held and its record not yet carrying it (or the reverse), the
    // reader reads the record's row too, so the record's write (here its undo) moves it.
    #[test]
    fn a_part_read_while_its_record_disagrees_moves_with_the_record() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        let mut m = Mutation::new();
        m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let mut fx: Effects<u8, bool> = Effects::new("record test");
        fx.want(0);
        let e = &mut lp.peers[0].engine;
        let failed = e.run(|tx| {
            tx.txn.remove_local(&crate::engine::records::commit_key(&c), osis_store::Shred::No)?;
            assert_eq!(fx.due(), vec![0]);
            fx.settle(&0, || crate::apply::held_part(tx, &c, 0).ok().flatten().is_some());
            Err::<(), _>(crate::Error::Misuse("undone"))
        });
        assert!(failed.is_err());
        assert_eq!(fx.due(), vec![0], "the record back moves what read it gone");
        let e = &mut lp.peers[0].engine;
        e.run(|tx| {
            fx.settle(&0, || crate::apply::held_part(tx, &c, 0).ok().flatten().is_some());
            Ok(())
        })
        .unwrap();
        assert!(fx.due().is_empty(), "agreeing, nothing moved");
    }

    // spec/sync.md §2 (work in proportion to change), notes/engine.md (Stamps): a commit's meta is
    // read facet by facet, so a reader of one part's hold moves when that part's state does, not
    // with the commit's other parts; the fixed facts move only as the commit comes or goes; a
    // reader of every part, or a copy, with any part.
    #[test]
    fn a_part_moves_what_read_it_alone() {
        let (c, meta) = two_parts();
        let mut ix = Commits::default();
        ix.insert(c, meta);
        ix.commit();
        let mut fx: Effects<u8, String> = Effects::new("commits test");
        for k in 0..5 {
            fx.want(k);
        }
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 1, 2, 3, 4]);
        assert!(settle(&mut fx, &ix, &c).is_empty());
        let drop = |m: &mut Meta| m.set_hold(1, Hold::Dropped(Dropped::default()));
        ix.update(&c, drop);
        assert_eq!(settle(&mut fx, &ix, &c), vec![1, 3, 4], "part 1 dropped");
        ix.update(&c, drop);
        assert!(settle(&mut fx, &ix, &c).is_empty(), "the same value again moves nothing");
        ix.update(&c, |m| m.set_valid(vec![false, true]));
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 3, 4], "part 0 invalid");
        // an undo moves what the change did, and the meta it restores reads as one in the index
        let at = ix.mark();
        ix.update(&c, |m| m.set_hold(0, Hold::Dropped(Dropped::default())));
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 3, 4]);
        ix.rollback_to(at);
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 3, 4], "undone");
        ix.update(&c, |m| m.set_hold(0, Hold::Dropped(Dropped::default())));
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 3, 4], "the restored meta's reads are recorded");
        // gone or back: every reader
        let saved = ix.remove(&c).unwrap();
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 1, 2, 3, 4], "gone");
        ix.insert(c, saved);
        assert_eq!(settle(&mut fx, &ix, &c), vec![0, 1, 2, 3, 4], "back");
        // a copy's metas read the copy
        let copy = ix.clone();
        ix.update(&c, |m| m.set_hold(1, Hold::Body { whole: false }));
        assert_eq!(settle(&mut fx, &copy, &c), vec![1, 3, 4], "settled over the copy, moved by the original");
        let mut copy = copy;
        copy.update(&c, |m| m.set_hold(1, Hold::Body { whole: true }));
        assert_eq!(settle(&mut fx, &copy, &c), vec![1, 3, 4], "moved by the copy it read");
    }
}
