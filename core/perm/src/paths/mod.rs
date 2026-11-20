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

/// The walk over a held set of commits, under a trust set.
#[derive(Clone)]
pub struct Paths {
    /// The first walk: vouch entries unread.
    first: walk::Walk,
    /// The second walk, the timeline: counting entries read as named by their removals' lists.
    timeline: walk::Walk,
    trust: BTreeSet<WriteId>,
    void: BTreeSet<WriteId>,
    /// The counting entries: (removal, commit, the vouch's thing).
    counting: BTreeSet<(CommitId, CommitId, Tid)>,
    facts: content::Facts,
}

impl Paths {
    /// An empty held set over `records` (thing to mint admin) and `trust`.
    pub fn new(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>) -> Paths {
        Paths { first: walk::Walk::new(records), timeline: walk::Walk::new(records), trust, void: BTreeSet::new(), counting: BTreeSet::new(), facts: content::Facts::new(records) }
    }

    /// The settled walks of `commits` from scratch.
    pub fn evaluate(records: &BTreeMap<Tid, Tid>, trust: BTreeSet<WriteId>, commits: &[Commit]) -> Paths {
        let mut p = Paths::new(records, trust);
        p.add(commits);
        p
    }

    /// Adds held commits (a commit already held is ignored) and settles again.
    pub fn add(&mut self, commits: &[Commit]) -> Changed {
        let fresh: Vec<&Commit> = commits.iter().filter(|c| !self.facts.commits.contains_key(&c.id)).collect();
        let mut seen = BTreeSet::new();
        let fresh: Vec<&Commit> = fresh.into_iter().filter(|c| seen.insert(c.id)).collect();
        if fresh.is_empty() {
            return Changed::default();
        }
        let owned: Vec<Commit> = fresh.iter().map(|c| (*c).clone()).collect();
        self.first.begin();
        self.timeline.begin();
        let p1 = self.first.take(&owned);
        let p2 = self.timeline.take(&owned);
        let first = &self.first;
        let taken = self.facts.take(&fresh, |id| first.key_of(id));
        if let Some(p) = taken.edge_from {
            self.facts.chain_from(p);
        }
        let mut named = BTreeSet::new();
        if self.trust.is_empty() {
            if let Some(p) = p1 {
                self.first.update_from(p);
            }
            let ch1 = self.first.changed();
            if ch1 != Changed::default() || taken.role {
                named = self.recount();
            }
            let extra = self.timeline.set_vouched(self.counting.clone());
            if let Some(p) = [p2, extra].into_iter().flatten().min() {
                self.timeline.update_from(p);
            }
        } else {
            named = self.settle();
        }
        self.finish(taken, named)
    }

    /// Replaces the trust set and settles from scratch.
    pub fn set_trust(&mut self, trust: BTreeSet<WriteId>) -> Changed {
        self.trust = trust;
        self.first.begin();
        self.timeline.begin();
        let named = self.settle();
        self.finish(content::Taken::default(), named)
    }

    /// `Changed` from the timeline's journal, the chained pass, the addenda and what arrived.
    fn finish(&mut self, taken: content::Taken, named: BTreeSet<CommitId>) -> Changed {
        let _ = self.first.changed();
        let mut ch = self.timeline.changed();
        ch.regrant.extend(self.facts.chain_changed());
        // the walk or the counting entries changed: from scratch; else only addenda or snapshots
        // arrived: the fixpoint grows from where it stood
        if ch != Changed::default() || !named.is_empty() {
            ch.parts.extend(self.facts.addenda_fixpoint(&self.timeline));
        } else if !taken.addenda.is_empty() || !taken.snapshots.is_empty() {
            ch.parts.extend(self.facts.addenda_more(&self.timeline, &taken));
        }
        ch.parts.extend(taken.deltas);
        ch.named.extend(taken.carried);
        ch.named.extend(named);
        ch
    }

    /// From scratch under the trust set: both walks, then the void trusted writes lose their
    /// seeds all at once and both walks are redone, until none is void (draft §5.1 Trust set).
    /// The commits whose counting entries changed.
    fn settle(&mut self) -> BTreeSet<CommitId> {
        let mut active: BTreeSet<WriteId> = self.trust.iter().copied().filter(|id| self.first.key_of(id).is_some() && self.first.is_edge_write(id)).collect();
        self.void.clear();
        let mut named = BTreeSet::new();
        loop {
            self.first.scratch(&active);
            named.extend(self.recount());
            self.timeline.set_vouched(self.counting.clone());
            self.timeline.scratch(&active);
            let applied = self.timeline.applied_ids();
            let gone: Vec<WriteId> = active.iter().copied().filter(|r| !applied.contains(r)).collect();
            if gone.is_empty() {
                return named;
            }
            for r in gone {
                active.remove(&r);
                self.void.insert(r);
            }
        }
    }

    /// Derives the counting entries from the first walk (draft §5.1 Vouches): an entry of an
    /// applied vouch V on N keyed by R and listing c counts where an edge write of R on h applies
    /// as a lowering, V is ordered after it, and c,
    /// held, has a role-class part on N, is ordered before R, rests on h by a part on N and is not
    /// signed by V's signer. It keeps c's parts on N alone: V applies by its voucher's admin on N, which says
    /// nothing of another thing c writes. The commits whose entries changed.
    fn recount(&mut self) -> BTreeSet<CommitId> {
        let mut pairs = BTreeSet::new();
        for v in self.first.vouches() {
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
        let named = pairs.symmetric_difference(&self.counting).map(|p| p.1).collect();
        self.facts.set_counted(&pairs);
        self.counting = pairs;
        named
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
        self.facts.ids().filter_map(|id| Some((*id, self.facts.content(&self.timeline, id, &mut c)?))).collect()
    }

    /// Commits a valid snapshot carries that no valid held delta of its thing and aspect is: shown
    /// by the snapshot's copy alone (draft §5.2 Copies).
    pub fn copies(&self) -> BTreeSet<CommitId> {
        self.facts.copies(&self.timeline, &mut Counts::default())
    }

    /// Held deltas a valid request by author holds the right over (draft §6, `author` class).
    pub fn purged(&self) -> BTreeSet<WriteId> {
        let mut c = Counts::default();
        self.facts.ids().filter(|id| self.facts.purged(&self.timeline, id, &mut c)).copied().collect()
    }

    /// Per edge, the key of its first chained write giving write and giving admin (draft §4).
    pub fn chained(&self) -> BTreeMap<(Tid, Tid), [Option<Key>; 2]> {
        self.facts.chained()
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

    /// The held deltas valid (copies aside).
    fn valid_set(&self) -> BTreeSet<WriteId> {
        self.contents().into_iter().filter(|(_, c)| matches!(c, Content::Valid(_))).map(|(id, _)| id).collect()
    }

    /// The held lowerings whose trust would change what applies, which deltas are valid or the
    /// final roles (draft §5.1 Trust set, dispute; `Candidates::Explicit`): both walks per
    /// candidate.
    pub fn disputes(&self) -> BTreeSet<WriteId> {
        let applied = self.timeline.applied_ids();
        let roles = self.roles();
        let valid = self.valid_set();
        let mut out = BTreeSet::new();
        for id in self.timeline.candidates() {
            let mut t = self.clone();
            t.trust.insert(id);
            t.set_trust(t.trust.clone());
            if t.status(&id) == Some(Status::Invited) {
                continue;
            }
            if t.timeline.applied_ids() != applied || t.roles() != roles || t.valid_set() != valid {
                out.insert(id);
            }
        }
        out
    }

    fn roles(&self) -> BTreeMap<(Tid, Tid), Option<Role>> {
        self.finals().into_iter().map(|(k, v)| (k, v.0)).collect()
    }

    /// Work done since construction: both walks, the chained pass and the addenda.
    pub fn counts(&self) -> Counts {
        let mut c = self.first.counts;
        c.add(&self.timeline.counts);
        c.add(&self.facts.counts);
        c
    }
}
