//! The permission walk along stated paths (notes/perm-paths.md; draft spec
//! notes/a1-spec/permissions.md §1, §2, §5.1, §5.2, §6): every edge-class part (edge writes,
//! vouches) is judged along the one path its commit states for its thing, in key order, each
//! lowering judged once, in two walks (vouch entries unread, then read); every delta is judged
//! along its path by point queries on the second walk. Not yet called by the engine (A1 steps 2
//! and 3 wire it in).
//!
//! The input is plain structs, independent of the header's types; the output is per part
//! (`Status`, `Content`), per edge (history, point queries, final values), the trusted writes
//! left void, the dispute set and, per update, `Changed`.

mod content;
mod path;
mod walk;

use crate::types::{Edge, Frontier, WriteId};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use content::{Fact, FactClass, MemStore, Pair, Store};
pub use walk::{Applied, Counts, History, Key};

/// A held commit's parts.
#[derive(Clone, Debug)]
pub struct Commit {
    pub id: CommitId,
    pub ts: Ts,
    pub signer: Tid,
    /// In the header's order: a part's index here is its `WriteId` index.
    pub parts: Vec<Part>,
}

/// One part: what it writes on `on`, along the path the commit states for `on`.
#[derive(Clone, Debug)]
pub struct Part {
    pub on: Tid,
    /// [A1..Ak]: the things between the signer and `on` (draft §1 Path).
    pub path: Vec<Tid>,
    pub kind: PartKind,
}

#[derive(Clone, Debug)]
pub enum PartKind {
    Edge(EdgeWrite),
    /// A `vouches.0` entry (draft §5.1 Vouches): an edge-class part, its entries counting by the
    /// first walk.
    Vouch { removal: CommitId, list: Frontier },
    /// Any other delta, judged as content (draft §5.2).
    Delta(Delta),
}

/// A `roles.0` write on `holder`'s grant.
#[derive(Clone, Debug)]
pub struct EdgeWrite {
    pub holder: Tid,
    /// `None`: a removal.
    pub value: Option<Edge>,
    /// A removal of another holder's grant with none that is no self-removal is a finalize.
    pub frontier: Option<Arc<Frontier>>,
    /// The holder whose edge on `on` is the remaining admin the write names (header `remains`).
    pub remains: Option<Tid>,
    /// The adminless mark (header flags bit 1).
    pub adminless: bool,
}

/// A delta judged as content (draft §5.2).
#[derive(Clone, Debug)]
pub struct Delta {
    pub aspect: Ak,
    /// The role its aspect needs: write; admin for an admin-only aspect, `sync.0`, `keys.0`,
    /// `secrets.0` and a snapshot carrying one (draft §5.2, Compaction snapshot).
    pub needs: Role,
    /// Its purge author: an index into [signer, A1..Ak] (draft §6); past the path, bad input.
    pub purge_author: u32,
    pub retention: PurgeBy,
    pub class: DeltaClass,
}

#[derive(Clone, Debug)]
pub enum DeltaClass {
    /// A content commit's delta.
    Plain,
    /// A role-class delta judged like content (`secrets.0`, `keys.0`, `sync.0`, draft §5.1).
    RoleClass,
    /// A compaction snapshot's delta, carrying copies of these commits' writes on its thing and
    /// aspect; a list naming the snapshot names them (draft §5.1 Own cover).
    Snapshot { carries: Frontier },
    /// An `addenda.0` entry its delta creates (draft §5.2 Addenda).
    Addendum { removal: CommitId, list: Frontier },
    /// A purge request by author on this part's thing and aspect (draft §6), judged as a delta
    /// needing write along its path.
    PurgeByAuthor { author: Tid },
}

/// What the settled walk did with an edge-class part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Applied,
    /// Applied as an invite grant (draft §2).
    Invited,
    /// A lowering judged void: its drops would take its authority or its remaining admin.
    Void,
    /// In D: put in question by a lowering, or a trusted write's seed.
    Dropped,
    /// Held, applying in no pass.
    Unapplied,
}

/// A delta's verdict (draft §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Content {
    Valid(By),
    /// Not valid, but shown by a valid snapshot's copy (draft §5.2 Copies).
    Copied,
    Invalid,
}

/// Why a delta is valid, the first that holds in the draft's order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum By {
    /// Its path gives the role just before it and no cut of it follows.
    Held,
    /// A cut's list names it.
    Listed,
    /// A valid addendum vouches for it.
    Vouched,
    /// Its path is re-granted.
    Regranted,
}

/// What an update changed. A delta's verdict can change only where: it is in `parts` (new), an
/// edge of its path is in `edges` at a key before its position, in `cuts` at a key at or after
/// it, or in `regrant`, its commit is in `named`, or an addendum in `parts` names it; a purge
/// follows its requests.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Changed {
    /// Edge-class parts whose status changed, every new part, addenda whose validity changed.
    pub parts: BTreeSet<WriteId>,
    /// Per edge (holder, target), the earliest key from which its history changed.
    pub edges: BTreeMap<(Tid, Tid), Key>,
    /// Per edge, the latest key of a cut added or removed.
    pub cuts: BTreeMap<(Tid, Tid), Key>,
    /// Edges whose final role or first chained point changed.
    pub regrant: BTreeSet<(Tid, Tid)>,
    /// Commits whose namers changed: carried by a new snapshot, or a counting entry's.
    pub named: BTreeSet<CommitId>,
}

/// A counting entry: (removal, commit, the vouch's thing).
type Entry = (CommitId, CommitId, Tid);

/// The walk over a held set of commits, under a trust set, reading delta facts through `S`.
#[derive(Clone)]
pub struct Paths<S: Store = MemStore> {
    /// The first walk: vouch entries unread.
    first: walk::Walk,
    /// The second walk, the timeline: counting entries read as named by their removals' lists.
    timeline: walk::Walk,
    trust: BTreeSet<WriteId>,
    /// The held trusted edge writes walked as trusted, and those void (draft §5.1 Trust set).
    active: BTreeSet<WriteId>,
    void: BTreeSet<WriteId>,
    /// The counting entries, each with the vouches keeping it.
    counting: BTreeSet<Entry>,
    keeping: BTreeMap<Entry, u32>,
    by_vouch: BTreeMap<WriteId, BTreeSet<Entry>>,
    facts: content::Facts<S>,
}

impl Paths<MemStore> {
    /// An empty held set over `records` (thing to mint admin) and `trust`, delta facts in memory.
    pub fn new(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        Paths::with_store(records, trust, MemStore::default())
    }

    /// As `new`, partitioning off: every part walked, inert or not, in one component. A test
    /// mode: the walk by components must read exactly as this (notes/perm-paths.md, Components).
    pub fn single(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        let mut p = Paths::new(records, trust);
        p.first = walk::Walk::new(records, false, true, true);
        p.timeline = walk::Walk::new(records, true, true, true);
        p
    }

    /// As `new`, every part of a component after an update's earliest change walked again, not
    /// only those whose reads changed. A test mode: the walk by reach must read exactly as this
    /// (notes/perm-paths.md, Reach).
    pub fn whole(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        let mut p = Paths::new(records, trust);
        p.first = walk::Walk::new(records, false, false, true);
        p.timeline = walk::Walk::new(records, true, false, true);
        p
    }

    /// The settled walks of `commits` from scratch.
    pub fn evaluate(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>, commits: &[Commit]) -> Paths {
        let mut p = Paths::new(records, trust);
        p.add(commits);
        p
    }
}

impl<S: Store> Paths<S> {
    /// An empty held set over `records` and `trust`, delta facts kept in `store`.
    pub fn with_store(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>, store: S) -> Paths<S> {
        Paths {
            first: walk::Walk::new(records, false, false, false),
            timeline: walk::Walk::new(records, true, false, false),
            trust,
            active: BTreeSet::new(),
            void: BTreeSet::new(),
            counting: BTreeSet::new(),
            keeping: BTreeMap::new(),
            by_vouch: BTreeMap::new(),
            facts: content::Facts::new(records, store),
        }
    }

    /// The delta facts store.
    pub fn store(&self) -> &S {
        &self.facts.store
    }

    /// Adds held commits (a commit already held is ignored) and settles again.
    pub fn add(&mut self, commits: &[Commit]) -> Changed {
        let fresh = self.fresh(commits);
        if fresh.is_empty() {
            return Changed::default();
        }
        self.begin();
        let taken = self.take(&fresh);
        let named = self.settle(&taken.roles, &BTreeSet::new());
        self.finish(taken, named)
    }

    /// Forgets held commits (a commit not held is ignored): the reading is the walk without them
    /// (notes/perm-paths.md, Forget and update).
    pub fn forget(&mut self, ids: &[CommitId]) -> Changed {
        let held: Vec<CommitId> = ids.iter().filter(|c| self.holds(c)).copied().collect::<BTreeSet<_>>().into_iter().collect();
        if held.is_empty() {
            return Changed::default();
        }
        self.begin();
        let gone = self.let_go(&held);
        let mut named = self.drop_entries(&held);
        named.extend(self.settle(&gone.roles, &BTreeSet::new()));
        self.finish(gone, named)
    }

    /// Replaces held commits by the versions given (a chunked frontier's leaf arriving: the same
    /// commit, its frontier read further), adding those not held, as one update: every part of
    /// a commit given is reported as new.
    pub fn update(&mut self, commits: &[Commit]) -> Changed {
        let mut seen = BTreeSet::new();
        let given: Vec<&Commit> = commits.iter().filter(|c| seen.insert(c.id)).collect();
        if given.is_empty() {
            return Changed::default();
        }
        self.begin();
        let held: Vec<CommitId> = given.iter().map(|c| c.id).filter(|c| self.holds(c)).collect();
        let mut taken = self.let_go(&held);
        let mut named = self.drop_entries(&held);
        let t = self.take(&given);
        // a list read further names more with the walk unchanged: what it names is reported
        for c in &given {
            for p in &c.parts {
                if let PartKind::Edge(EdgeWrite { frontier: Some(f), .. }) = &p.kind {
                    taken.carried.extend(f.commits());
                }
            }
        }
        taken.roles.extend(t.roles);
        taken.carried.extend(t.carried);
        taken.deltas.extend(t.deltas);
        taken.addenda.extend(t.addenda);
        named.extend(self.settle(&taken.roles, &BTreeSet::new()));
        self.finish(taken, named)
    }

    /// Replaces the trust set and settles the components whose trusted writes changed.
    pub fn set_trust(&mut self, trust: BTreeSet<WriteId>) -> Changed {
        let changed: BTreeSet<WriteId> = self.trust.symmetric_difference(&trust).copied().collect();
        self.trust = trust;
        self.begin();
        let named = self.settle(&BTreeSet::new(), &changed);
        self.finish(content::Taken::default(), named)
    }

    fn fresh<'a>(&self, commits: &'a [Commit]) -> Vec<&'a Commit> {
        let mut seen = BTreeSet::new();
        commits.iter().filter(|c| !self.holds(&c.id) && seen.insert(c.id)).collect()
    }

    /// Whether commit `c` is held: by its edge-class parts, its role facts or its deltas.
    fn holds(&self, c: &CommitId) -> bool {
        self.timeline.holds(c) || self.facts.holds(c)
    }

    fn begin(&mut self) {
        self.first.begin();
        self.timeline.begin();
    }

    fn take(&mut self, fresh: &[&Commit]) -> content::Taken {
        let owned: Vec<Commit> = fresh.iter().map(|c| (*c).clone()).collect();
        self.first.take(&owned);
        self.timeline.take(&owned);
        self.facts.take(fresh)
    }

    /// Forgets `held` from the walks and the facts.
    fn let_go(&mut self, held: &[CommitId]) -> content::Taken {
        self.first.forget(held);
        self.timeline.forget(held);
        self.active.retain(|id| !held.contains(&id.0));
        self.void.retain(|id| !held.contains(&id.0));
        self.facts.forget(held)
    }

    /// The counting entries kept by the vouches of `held` go; the commits whose entries changed.
    fn drop_entries(&mut self, held: &[CommitId]) -> BTreeSet<CommitId> {
        let ids: Vec<WriteId> = self.by_vouch.keys().filter(|id| held.contains(&id.0)).copied().collect();
        let mut named = BTreeSet::new();
        for id in ids {
            self.set_entries(id, BTreeSet::new(), &mut named);
        }
        if !named.is_empty() {
            self.facts.set_counted(&self.counting);
            self.timeline.set_vouched(self.counting.clone());
        }
        named
    }

    /// `Changed` from the timeline's journal, the addenda and what arrived or went.
    fn finish(&mut self, taken: content::Taken, named: BTreeSet<CommitId>) -> Changed {
        let _ = self.first.changed();
        let mut ch = self.timeline.changed();
        // a list naming a snapshot names what it carries
        let through = self.facts.carried_by(&taken.carried);
        ch.named.extend(taken.carried);
        ch.named.extend(through);
        ch.named.extend(named);
        let addenda = self.facts.addenda_update(&self.timeline, &ch, &taken.addenda);
        ch.parts.extend(addenda);
        ch.parts.extend(taken.deltas);
        ch
    }

    /// Settles every component an input change reached, each as from scratch under the trust set
    /// (draft §5.1 Trust set): its void trusted writes walked as trusted again, then both walks,
    /// the counting entries, and the trusted writes the timeline does not apply void, all at
    /// once, both walks again, until none is (notes/perm-paths.md, Trust per component).
    /// `roles`: role commits arrived or forgotten (the vouches listing them count again);
    /// `changed`: trusted writes added to or taken from the trust set. The commits whose counting
    /// entries changed.
    fn settle(&mut self, roles: &BTreeSet<CommitId>, changed: &BTreeSet<WriteId>) -> BTreeSet<CommitId> {
        let held: BTreeSet<WriteId> = self.trust.iter().filter(|id| self.timeline.is_edge_write(id)).copied().collect();
        self.active.retain(|id| held.contains(id));
        self.void.retain(|id| held.contains(id));
        for id in &held {
            if !self.void.contains(id) {
                self.active.insert(*id);
            }
        }
        let extra: BTreeSet<_> = changed.iter().filter_map(|id| self.timeline.comp_of(id)).collect();
        let mut seen = BTreeSet::new();
        let mut named = BTreeSet::new();
        let mut listing = roles.clone();
        loop {
            // a component walked again reads as from scratch: its void trusted writes count again
            let touched: BTreeSet<_> = self.first.touched().into_iter().chain(self.timeline.touched()).chain(extra.iter().copied()).filter(|c| !seen.contains(c)).collect();
            let again: Vec<WriteId> = self.void.iter().filter(|id| self.timeline.comp_of(id).is_some_and(|c| touched.contains(&c))).copied().collect();
            for id in again {
                self.void.remove(&id);
                self.active.insert(id);
            }
            seen.extend(touched);
            self.first.set_active(&self.active);
            self.timeline.set_active(&self.active);
            self.first.run_dirty();
            named.extend(self.recount(&self.first.touched(), &std::mem::take(&mut listing)));
            self.timeline.set_vouched(self.counting.clone());
            if self.first.touched().into_iter().chain(self.timeline.touched()).any(|c| !seen.contains(&c)) {
                continue;
            }
            self.timeline.run_dirty();
            let gone = self.timeline.unapplied_trusted();
            if gone.is_empty() && !self.first.is_dirty() && !self.timeline.is_dirty() {
                return named;
            }
            self.timeline.counts.scratch += 1;
            for r in gone {
                self.active.remove(&r);
                self.void.insert(r);
            }
        }
    }

    /// Counts again the entries of the vouches of components `comps` and of those listing a
    /// commit of `listing` (draft §5.1 Vouches): an entry of an applied vouch V on N keyed by R
    /// and listing c counts where an edge write of R on h applies as a lowering, V is ordered
    /// after it, and c, held, has a role-class part on N, is ordered before R, rests on h by a
    /// part on N and is not signed by V's signer. It keeps c's parts on N alone: V applies by its
    /// voucher's admin on N, which says nothing of another thing c writes. The commits whose
    /// entries changed.
    fn recount(&mut self, comps: &BTreeSet<u32>, listing: &BTreeSet<CommitId>) -> BTreeSet<CommitId> {
        let mut all = vec![];
        for v in self.first.vouches(comps, listing) {
            let mut pairs = BTreeSet::new();
            if v.applied {
                for (h, rkey) in self.first.lowers(&v.removal) {
                    if v.key <= rkey {
                        continue;
                    }
                    for c in v.list.commits() {
                        let Some(cf) = self.facts.commits.get(c) else { continue };
                        if cf.key < rkey.commit_start() && cf.role_on.contains(&v.on) && cf.rests.contains(&(v.on, h)) && cf.signer != v.signer {
                            pairs.insert((v.removal, *c, v.on));
                        }
                    }
                }
            }
            all.push((v.id, pairs));
        }
        let mut named = BTreeSet::new();
        for (id, pairs) in all {
            self.set_entries(id, pairs, &mut named);
        }
        if !named.is_empty() {
            self.facts.set_counted(&self.counting);
        }
        named
    }

    /// Sets the entries vouch `id` keeps; the commits whose entries changed join `named`.
    fn set_entries(&mut self, id: WriteId, pairs: BTreeSet<Entry>, named: &mut BTreeSet<CommitId>) {
        let was = self.by_vouch.remove(&id).unwrap_or_default();
        for t in was.difference(&pairs) {
            let n = self.keeping.get(t).copied().unwrap_or(0).saturating_sub(1);
            if n == 0 {
                self.keeping.remove(t);
                self.counting.remove(t);
                named.insert(t.1);
            } else {
                self.keeping.insert(*t, n);
            }
        }
        for t in pairs.difference(&was) {
            let n = self.keeping.get(t).copied().unwrap_or(0) + 1;
            self.keeping.insert(*t, n);
            if n == 1 {
                self.counting.insert(*t);
                named.insert(t.1);
            }
        }
        if !pairs.is_empty() {
            self.by_vouch.insert(id, pairs);
        }
    }

    pub fn status(&self, id: &WriteId) -> Option<Status> {
        self.timeline.status(id)
    }

    /// Every held edge-class part's status.
    pub fn statuses(&self) -> BTreeMap<WriteId, Status> {
        self.timeline.statuses()
    }

    /// A held delta's verdict: a point query along its path (notes/perm-paths.md).
    pub fn content(&self, id: &WriteId) -> Option<Content> {
        self.facts.content(&self.timeline, id, &mut Counts::default())
    }

    /// `content`, counting its work into `counts`.
    pub fn content_counted(&self, id: &WriteId, counts: &mut Counts) -> Option<Content> {
        self.facts.content(&self.timeline, id, counts)
    }

    /// Every held delta's verdict.
    pub fn contents(&self) -> BTreeMap<WriteId, Content> {
        let mut c = Counts::default();
        self.facts.ids().into_iter().filter_map(|id| Some((id, self.facts.content(&self.timeline, &id, &mut c)?))).collect()
    }

    /// Commits a valid snapshot carries that no valid held delta of its thing and aspect is: shown
    /// by the snapshot's copy alone (draft §5.2 Copies).
    pub fn copies(&self) -> BTreeSet<CommitId> {
        self.facts.copies(&self.timeline, &mut Counts::default())
    }

    /// Held deltas a valid request by author holds the right over (draft §6, `author` class).
    pub fn purged(&self) -> BTreeSet<WriteId> {
        let mut c = Counts::default();
        self.facts.ids().into_iter().filter(|id| self.facts.purged(&self.timeline, id, &mut c)).collect()
    }

    /// Per edge, the key of its first chained write giving write and giving admin (draft §4).
    pub fn chained(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        self.timeline.chained()
    }

    /// A held delta's path edges and position (the start of its `ts`): where the engine indexes
    /// it to turn `Changed` into the deltas to judge again.
    pub fn rests(&self, id: &WriteId) -> Option<(Vec<(Tid, Tid)>, Key)> {
        self.facts.rests(id)
    }

    /// What names a held delta: addenda listing it, snapshots carrying it, requests by its purge
    /// author. A delta's verdict follows theirs (`Changed`).
    pub fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        self.facts.naming(id)
    }

    /// The counting entries: (removal, commit, the vouch's thing).
    pub fn counting(&self) -> &BTreeSet<(CommitId, CommitId, Tid)> {
        &self.counting
    }

    /// The part's key (draft §5.1 step 1).
    pub fn key(&self, id: &WriteId) -> Option<Key> {
        self.timeline.key_of(id)
    }

    /// The applied writes on (holder, target) in key order.
    pub fn history(&self, holder: &Tid, target: &Tid) -> History {
        self.timeline.history(holder, target)
    }

    /// The applied writes on (holder, target) with what each found there.
    pub fn writes(&self, holder: &Tid, target: &Tid) -> Vec<Applied> {
        self.timeline.writes(holder, target)
    }

    /// Every edge with an applied write, and every record edge, with its history (empty for a
    /// record edge nothing wrote).
    pub fn histories(&self) -> BTreeMap<(Tid, Tid), History> {
        self.timeline.histories()
    }

    /// The value of (holder, target) just before `key`: the last applied write before it, else
    /// the record edge's admin, else none.
    pub fn value_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Edge> {
        self.timeline.value_before(holder, target, key)
    }

    /// The role (holder, target) gives just before `key`, its `until` read at `key`'s `ts`.
    pub fn role_before(&self, holder: &Tid, target: &Tid, key: &Key) -> Option<Role> {
        self.timeline.role_before(holder, target, key)
    }

    /// The final role of each edge the settled walk set (and each record edge), every `until`
    /// counted removed, and the invite it gives.
    pub fn finals(&self) -> BTreeMap<(Tid, Tid), (Option<Role>, Option<Role>)> {
        self.timeline.finals()
    }

    /// Trusted writes the timeline does not apply (void: their seeds lost).
    pub fn void_trusted(&self) -> BTreeSet<WriteId> {
        self.void.clone()
    }


    /// The held lowerings whose trust would change what applies, which deltas are valid or the
    /// final roles (draft §5.1 Trust set, dispute; `Candidates::Explicit`): per candidate the
    /// trust switched on and back in place, each an update of the candidate's component, the
    /// readings compared only where the switch's `Changed` reaches (notes/perm-paths.md, Trust
    /// per component). The reading after equals the reading before.
    pub fn disputes(&mut self) -> BTreeSet<WriteId> {
        self.disputes_counted(&mut Counts::default())
    }

    /// `disputes`, counting into `counts` the work of the switches' walks and of the verdicts
    /// compared.
    pub fn disputes_counted(&mut self, counts: &mut Counts) -> BTreeSet<WriteId> {
        let mut out = BTreeSet::new();
        let cands = self.timeline.candidates();
        let base = self.counts();
        let held = self.trust.clone();
        for id in cands {
            let mut trust = held.clone();
            trust.insert(id);
            let ch = self.set_trust(trust);
            let invited = self.status(&id) == Some(Status::Invited);
            let reached = self.facts.reached(&ch);
            let with = self.probe(&ch, &reached, counts);
            self.set_trust(held.clone());
            if !invited && self.probe(&ch, &reached, counts) != with {
                out.insert(id);
            }
        }
        counts.add(&self.counts().since(&base));
        out
    }

    /// What a dispute compares, read only where `ch` reaches: whether each part it reports
    /// applies, the final role of each edge it reports, whether each delta `reached` is valid.
    fn probe(&self, ch: &Changed, reached: &BTreeSet<WriteId>, counts: &mut Counts) -> (Vec<bool>, Vec<Option<Role>>, Vec<bool>) {
        let applied = ch.parts.iter().map(|id| matches!(self.status(id), Some(Status::Applied | Status::Invited))).collect();
        let finals = ch.regrant.iter().map(|(h, e)| self.timeline.final_of(h, e)).collect();
        let valid = reached.iter().map(|id| matches!(self.content_counted(id, counts), Some(Content::Valid(_)))).collect();
        (applied, finals, valid)
    }

    /// Where no counting entry's removal is, the first walk reads as the timeline
    /// (notes/perm-paths.md, Two walks): the first part of a component holding a vouch whose
    /// statuses differ there, if any.
    pub fn first_walk_differs(&self) -> Option<WriteId> {
        let counted: BTreeSet<u32> = self.counting.iter().flat_map(|e| self.timeline.parts_of(&e.0)).filter_map(|id| self.timeline.comp_of(&id)).collect();
        self.first.vouch_comps().into_iter().filter(|(c, _)| !counted.contains(c)).flat_map(|(_, ids)| ids).find(|id| self.first.status(id) != self.timeline.status(id))
    }

    /// Entries the walks keep in memory (parts, edges, events, chain entries, histories,
    /// readers): edge-class state alone (notes/perm-paths.md, The delta-facts seam).
    pub fn footprint(&self) -> u64 {
        self.first.footprint() + self.timeline.footprint() + self.facts.footprint()
    }

    /// Work done since construction: both walks, the chained pass and the addenda.
    pub fn counts(&self) -> Counts {
        let mut c = self.first.counts;
        c.add(&self.timeline.counts);
        c.add(&self.facts.counts);
        c
    }
}
