//! The permission walk along stated paths (notes/perm-paths.md; draft spec
//! spec/permissions.md §1, §2, §5.1, §5.2, §6): every edge-class part (an edge write)
//! is judged along the one path its commit states for its thing, in key order, each lowering
//! judged once; every delta is judged along its path by point queries on the walk, and a purge
//! request's right as a delta of
//! it needing each role its class needs, so whether a delta is purged is a reading too (§6). Not
//! yet called by the engine (A1 steps 2 and 3 wire it in).
//!
//! The input is plain structs, independent of the header's types; the output is per part
//! (`Status`, `Content`, chained-ness), per delta and copy (purged), per request (its right,
//! what it could hold), per edge (history, point queries, final values), the trusted writes left
//! void, the dispute set and, per update, `Changed`.

mod content;
mod path;
mod walk;

use crate::types::{Edge, Frontier, WriteId};
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use content::{Fact, FactClass, Holding, MemStore, NameKey, Pair, Store};
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
    /// The hops its path marks direct (draft §1 Path, Direct mark): bit j for the hop joining
    /// members j and j + 1 of [S, A1..Ak, on].
    pub direct: osis_base::format::PathMarks,
    pub kind: PartKind,
}

#[derive(Clone, Debug)]
pub enum PartKind {
    Edge(EdgeWrite),
    /// Any other delta, judged as content (draft §5.2).
    Delta(Delta),
}

/// A lowering's list (draft §5.1 The list) by leaf: per thing, the commits its leaf names. An
/// entry in thing t's leaf names its commit's parts on t alone, so a reader holding t's leaf alone
/// reads it as a node holding every leaf (notes/evidence-model-findings.md 24). A single list
/// naming commits whole (A1's header field) is the leaf of every thing those commits write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct List(BTreeMap<Tid, Frontier>);

impl List {
    /// The list of entries (thing, commit).
    pub fn new(entries: impl IntoIterator<Item = (Tid, CommitId)>) -> List {
        let mut by: BTreeMap<Tid, BTreeSet<CommitId>> = BTreeMap::new();
        for (t, c) in entries {
            by.entry(t).or_default().insert(c);
        }
        List(by.into_iter().map(|(t, cs)| (t, Frontier::new(cs))).collect())
    }

    /// Whether it names `commit`'s parts on `on`: its leaf of `on` lists the commit.
    pub fn names(&self, commit: &CommitId, on: &Tid) -> bool {
        self.0.get(on).is_some_and(|f| f.covers(commit))
    }

    /// Its entries, (thing, commit).
    pub fn entries(&self) -> impl Iterator<Item = (Tid, CommitId)> + '_ {
        self.0.iter().flat_map(|(t, f)| f.commits().iter().map(|c| (*t, *c)))
    }
}

/// A `roles.0` write on `holder`'s grant.
#[derive(Clone, Debug)]
pub struct EdgeWrite {
    pub holder: Tid,
    /// `None`: a removal.
    pub value: Option<Edge>,
    /// A removal of another holder's grant with none that is no self-removal is a finalize.
    pub frontier: Option<Arc<List>>,
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
    pub purge_by: PurgeBy,
    pub class: DeltaClass,
}

#[derive(Clone, Debug)]
pub enum DeltaClass {
    /// A content commit's delta.
    Plain,
    /// A role-class delta judged like content (`secrets.0`, `keys.0`, `sync.0`, draft §5.1).
    RoleClass,
    /// A compaction snapshot's delta, carrying copies of these commits' writes on its thing and
    /// aspect; a list naming the snapshot names them (draft §5.1 Own cover). `stated`: what it
    /// states of each carried commit (spec/crdt.md §8 `Facts`), read for a copy whose commit is not
    /// held (draft §6 Copies); `own`: marked as its signer's own cover (draft §5.2 Own cover).
    Snapshot { carries: Frontier, stated: BTreeMap<CommitId, Stated>, own: bool },
    /// An `addenda.0` entry its delta creates (draft §5.2 Addenda).
    Addendum { removal: CommitId, list: Frontier },
    /// A purge request on this part's thing (draft §6), naming deltas of its aspect (a
    /// destruction: of every aspect): an edit, judged as a delta along its path.
    Purge { names: Names },
}

/// What a purge request names on its thing (draft §6; spec/wire.md §4 field 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Names {
    /// The deltas of its aspect stamped before it whose purge author is exactly this thing.
    Author(Tid),
    /// Every delta of its aspect stamped before it.
    Aspect,
    /// This commit's delta of its aspect, stamped before it.
    Commit(CommitId),
    /// A destruction (a request on `created.0`): every delta of the thing, whatever its aspect and
    /// `ts`, by the `admin` right alone.
    Destroy,
}

/// What a snapshot states of a commit it carries (spec/crdt.md §8 `Facts`): its stamp, purge
/// author and purge-by.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Stated {
    pub ts: Ts,
    pub purge_author: Tid,
    pub purge_by: PurgeBy,
}

/// A purge request's description of what it names (its thing, aspect, selector and stamp): the
/// engine finds the deltas and copies it covers in its own index (`Scope::covers`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope {
    pub on: Tid,
    pub aspect: Ak,
    pub names: Names,
    pub ts: Ts,
}

impl Scope {
    /// Whether it names the delta (or copy) of `commit` on `on`'s `aspect` stamped `ts` with
    /// purge author `author` (draft §6: by author exactly that author's, by aspect every one, by
    /// commit that one, each stamped before it; a destruction every delta of the thing).
    pub fn covers(&self, on: &Tid, aspect: &Ak, ts: Ts, commit: &CommitId, author: Option<&Tid>) -> bool {
        *on == self.on
            && match &self.names {
                Names::Destroy => true,
                n => {
                    *aspect == self.aspect
                        && ts < self.ts
                        && match n {
                            Names::Author(a) => author == Some(a),
                            Names::Commit(c) => c == commit,
                            Names::Aspect | Names::Destroy => true,
                        }
                }
            }
    }
}

/// The right a purge request holds (draft §6 Holding a role): admin, and write, each judged as a
/// delta of it needing that role (a later cut below write that its list leaves out takes write
/// alone where a cut below admin listing it keeps admin). A destruction holds admin alone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Right {
    pub admin: bool,
    pub write: bool,
}

impl Right {
    pub fn any(self) -> bool {
        self.admin || self.write
    }
}

/// What the settled walk did with an edge-class part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Applied,
    /// Applied as an invite grant (draft §2).
    Invited,
    /// A lowering judged void: its drops would take its authority.
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
    /// An own cover whose writer's applied lowering lists it (draft §5.2 Own cover).
    OwnCover,
}

/// What an update changed. A delta's verdict can change only where: it is in `parts` (new), an
/// edge of its path is in `edges` at a key before its position, in `cuts` at a key at or after
/// it, or in `regrant`, its commit is in `named`, or an addendum in `parts` names it. Whether a
/// delta or copy is purged changes only where it is new, a `purges` scope covers it, or (a copy)
/// a snapshot carrying it changed its verdict.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Changed {
    /// Edge-class parts whose status changed, every new part, addenda whose validity changed.
    pub parts: BTreeSet<WriteId>,
    /// Per edge (holder, target), the earliest key from which its history changed.
    pub edges: BTreeMap<(Tid, Tid), Key>,
    /// Per edge, the latest key of a cut added or removed.
    pub cuts: BTreeMap<(Tid, Tid), Key>,
    /// Edges whose final role or first point (spec/permissions.md §5.2 Re-grant) changed.
    pub regrant: BTreeSet<(Tid, Tid)>,
    /// Commits whose namers changed: carried by a new snapshot; an own cover a lowering of its
    /// signer lists whose status changed.
    pub named: BTreeSet<CommitId>,
    /// What the requests whose right changed, arrived holding one or went name (draft §6): a
    /// description, never a list of deltas.
    pub purges: BTreeSet<Scope>,
    /// Edge-class parts whose chained-ness changed (draft §4), a held one turning chained on
    /// arrival and a chained one forgotten included.
    pub chained: BTreeSet<WriteId>,
}

/// The walk over a held set of commits, under a trust set, reading delta facts through `S`.
#[derive(Clone)]
pub struct Paths<S: Store = MemStore> {
    /// The walk, the timeline.
    timeline: walk::Walk,
    trust: BTreeSet<WriteId>,
    facts: content::Facts<S>,
}

impl Paths<MemStore> {
    /// An empty held set over `records` (thing to mint admin) and `trust`, delta facts in memory.
    pub fn new(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        Paths::with_store(records, trust, MemStore::default())
    }

    /// As `new`, every part walked in one component. A test mode: the walk by components must
    /// read exactly as this (notes/perm-paths.md, Components).
    pub fn single(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        let mut p = Paths::new(records, trust);
        p.timeline = walk::Walk::new(records, true);
        p
    }

    /// The settled walk of `commits` from scratch.
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
            timeline: walk::Walk::new(records, false),
            trust,
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
        self.timeline.settle(&self.trust, &BTreeSet::new());
        self.finish(taken)
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
        self.timeline.settle(&self.trust, &BTreeSet::new());
        self.finish(gone)
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
        let t = self.take(&given);
        // a list read further names more with the walk unchanged: what it names is reported
        for c in &given {
            for p in &c.parts {
                if let PartKind::Edge(EdgeWrite { frontier: Some(f), .. }) = &p.kind {
                    taken.carried.extend(f.entries().map(|(_, c)| c));
                }
            }
        }
        taken.carried.extend(t.carried);
        taken.deltas.extend(t.deltas);
        taken.addenda.extend(t.addenda);
        self.timeline.settle(&self.trust, &BTreeSet::new());
        self.finish(taken)
    }

    /// Replaces the trust set and settles the components whose trusted writes changed.
    pub fn set_trust(&mut self, trust: BTreeSet<WriteId>) -> Changed {
        let changed: BTreeSet<WriteId> = self.trust.symmetric_difference(&trust).copied().collect();
        self.trust = trust;
        self.begin();
        self.timeline.settle(&self.trust, &changed);
        self.finish(content::Taken::default())
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
        self.timeline.begin();
    }

    fn take(&mut self, fresh: &[&Commit]) -> content::Taken {
        let owned: Vec<Commit> = fresh.iter().map(|c| (*c).clone()).collect();
        self.timeline.take(&owned);
        self.facts.take(fresh)
    }

    /// Forgets `held` from the walks and the facts.
    fn let_go(&mut self, held: &[CommitId]) -> content::Taken {
        self.timeline.forget(held);
        self.facts.forget(held)
    }

    /// `Changed` from the timeline's journal, the addenda and what arrived or went.
    fn finish(&mut self, taken: content::Taken) -> Changed {
        let mut ch = self.timeline.changed();
        // a list naming a snapshot names what it carries
        let through = self.facts.carried_by(&taken.carried);
        ch.named.extend(taken.carried);
        ch.named.extend(through);
        let own = self.facts.own_listed(&ch.parts);
        ch.named.extend(own);
        let addenda = self.facts.addenda_update(&self.timeline, &ch, &taken.addenda);
        ch.parts.extend(addenda);
        let purges = self.facts.rights_update(&self.timeline, &ch, &taken.deltas);
        ch.purges.extend(purges);
        ch.purges.extend(taken.scopes);
        ch.parts.extend(taken.deltas);
        ch
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

    /// Held plain deltas a request holds a right over (draft §6): a full reading of `is_purged`.
    pub fn purged(&self) -> BTreeSet<WriteId> {
        let mut c = Counts::default();
        self.facts.ids().into_iter().filter(|id| self.facts.purged(id, &mut c)).collect()
    }

    /// Whether a request holds a right over held delta `id` (draft §6): a point query over the
    /// requests that name it and hold a right (by its thing, aspect, purge author, commit, stamp).
    pub fn is_purged(&self, id: &WriteId) -> bool {
        self.facts.purged(id, &mut Counts::default())
    }

    /// `is_purged`, counting its work into `counts`.
    pub fn is_purged_counted(&self, id: &WriteId, counts: &mut Counts) -> bool {
        self.facts.purged(id, counts)
    }

    /// The copies (`copies`) of commits not held on the snapshot's thing and aspect that a request
    /// holds a right over, judged by what every valid held snapshot carrying them states (draft
    /// §6 Copies).
    pub fn purged_copies(&self) -> BTreeSet<CommitId> {
        self.facts.purged_copies(&self.timeline, &mut Counts::default())
    }

    /// Whether a request holds a right over the copy of `commit`'s write on `on`'s `aspect` (a
    /// point query; false where no valid held snapshot shows one).
    pub fn copy_purged(&self, commit: &CommitId, on: &Tid, aspect: &Ak) -> bool {
        self.facts.copy_purged(&self.timeline, commit, on, aspect, &mut Counts::default())
    }

    /// The right a held purge request holds (draft §6 Holding a role): a point query along its
    /// path, as a delta's validity.
    pub fn right(&self, id: &WriteId) -> Option<Right> {
        self.facts.right_of(&self.timeline, id, &mut Counts::default())
    }

    /// Whether held request `id` could hold role `r` (spec/commits.md §4 Could hold the
    /// right): every edge of its path a record edge or set at `r` or above by some held edge
    /// write, whatever that write's validity. What a node that cannot judge acts on.
    pub fn could_give(&self, id: &WriteId, r: Role) -> Option<bool> {
        self.facts.could_give(id, r)
    }

    /// Whether held request `id` could hold the right over a delta of `purge_by` whose purge
    /// author is `author` (spec/commits.md §4 Could hold the right): admin on every edge,
    /// or write where the class allows a writer (`writer`; `author_or_admin` where its path holds
    /// the author). A destruction: admin.
    pub fn could_hold(&self, id: &WriteId, purge_by: PurgeBy, author: Option<&Tid>) -> Option<bool> {
        self.facts.could_hold(id, purge_by, author)
    }

    /// Whether held edge-class part `id` is chained (spec/permissions.md §4 Chained writes; a self-removal by
    /// admin on its path, a finalize by write).
    pub fn is_chained(&self, id: &WriteId) -> Option<bool> {
        self.timeline.is_chained(id)
    }

    /// Per edge a chained write set, the key of its first chained write giving write and giving
    /// admin (spec/permissions.md §4 Chained writes).
    pub fn chained(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        self.timeline.chained()
    }

    /// Per edge with one, its first points for write and for admin (spec/permissions.md §5.2
    /// Re-grant): the key of its first held write giving the role made by right.
    pub fn first_points(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        self.timeline.first_points()
    }

    /// A held delta's path edges and position (the start of its `ts`): where the engine indexes
    /// it to turn `Changed` into the deltas to judge again.
    pub fn rests(&self, id: &WriteId) -> Option<(Vec<(Tid, Tid)>, Key)> {
        self.facts.rests(id)
    }

    /// What names a held delta: addenda listing it, snapshots carrying it. A delta's verdict
    /// follows theirs (`Changed`); its purge follows `Changed::purges`.
    pub fn naming(&self, id: &WriteId) -> Vec<WriteId> {
        self.facts.naming(id)
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
        self.timeline.void_trusted().clone()
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
        let cands = self.timeline.candidates(&self.trust);
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

    /// Entries the walk keeps in memory (parts, edges, events, chain entries, histories,
    /// readers): edge-class state alone (notes/perm-paths.md, The delta-facts seam).
    pub fn footprint(&self) -> u64 {
        self.timeline.footprint() + self.facts.footprint()
    }

    /// Work done since construction: the walk, the chained pass and the addenda.
    pub fn counts(&self) -> Counts {
        let mut c = self.timeline.counts;
        c.add(&self.facts.counts);
        c
    }
}
