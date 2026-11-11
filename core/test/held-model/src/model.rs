//! `evaluate`: the whole judgment of a held set, recomputed from scratch.

use crate::roles::{addenda, edge_events, namings, Timeline, World};
use crate::thing_history;
use crate::types::*;
use crdt_model::death::{self, covers, holds, keys, supersedes, valued, winning};
use crdt_model::origins::Origins;
use crdt_model::writes::{writes, Name, Step};
use std::collections::{BTreeMap, BTreeSet};

/// A part: its commit and its index in the header's aspect list.
pub type PartRef = (CommitId, usize);
/// A delta by its commit, thing and aspect.
pub type DeltaRef = (CommitId, ThingId, Aspect);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeepWhy {
    /// It or its commit waits (spec/commits.md §4); spec/commits.md §5: kept until it joins.
    Pending,
    /// Role-class: fixed retention; the model drops none (ASSUMPTIONS.md).
    Role,
    /// In history (the thing's setting keeps it, `Outcome::out`), or before a purge request's
    /// floor: only purge or expiry act on it.
    Until,
    /// Nothing lets it go: uncovered, or covered by no snapshot holding the right.
    Plain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeftoverWhy {
    /// Its commit's expiry passed (spec/commits.md §6).
    Expired,
    /// A purge request that holds the right names it (spec/commits.md §5 Purge).
    Purged,
    /// A waiting part a purge request names (spec/commits.md §5).
    PendingPurged,
    /// It carries a copy of a value the node holds value-less (spec/crdt.md §4.7 Copies).
    Copy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropWhy {
    /// Covered by a valid snapshot whose commit holds the right over it (spec/commits.md §5).
    Covered { by: CommitId },
    /// A waiting part past its expiry, or an unjoinable (parked) body expired or purged: it counts
    /// as never received (spec/commits.md §5, spec/versioning.md §2).
    Gone,
    /// Judged invalid, not the node's own (spec/permissions.md §6): missing from then on, so
    /// fetched again if it turns valid.
    Invalid,
    /// A signal body out of history (spec/commits.md §5 Signals): no state needs it and no
    /// history lists it, so a node may drop it, whole or leftover, and takes no copy of it again.
    PastBound,
    /// On a thing that does not exist here (no creation joined), or of a commit whose author
    /// record or whose thing's record chain the node lacks: not held, and fetched again once
    /// known (notes/expiry-creation-design.md §3 Throw out and revisit).
    Unknown,
    /// On an ended thing (every creation of it joined is expired or purged): the node forgets the
    /// thing whole (notes/expiry-creation-design.md §3 Ending).
    Ended,
}

/// What the node does with a held body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fate {
    Keep(KeepWhy),
    /// Hold it with the values of value-less writes stripped.
    Leftover(LeftoverWhy),
    /// It may drop it now (out of history and covered, or a signal's out of history).
    MayDrop(DropWhy),
    /// It must have dropped it by now (under purge on replace once a right holder covers it; gone
    /// and invalid parts).
    MustDrop(DropWhy),
    /// Its own writes are held value-less with no reason left (a purge that fell): it counts as
    /// never received and is fetched again (spec/permissions.md §6).
    NeverReceived,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Outcome {
    pub parked: BTreeSet<CommitId>,
    pub applied: BTreeSet<CommitId>,
    /// Validity of each part of an applied commit (role parts: whether the edge write applied).
    pub valid: BTreeMap<PartRef, bool>,
    /// Parts a purge request drops, with the request (lowest commit ID among those that do).
    pub purged: BTreeMap<PartRef, CommitId>,
    /// Deltas whose value-carrying writes the node holds value-less (expired or purged).
    pub valueless: BTreeSet<DeltaRef>,
    /// What each aspect reads (spec/crdt.md §4.4), None absent.
    pub reads: BTreeMap<(ThingId, Aspect), Option<Value>>,
    /// Canonical state per aspect (what a snapshot from this node's whole state carries).
    pub states: BTreeMap<(ThingId, Aspect), Frag>,
    /// Fate of every held body.
    pub fates: BTreeMap<PartRef, Fate>,
    /// Held valid bodies holding a write the canonical state does not (replaced content).
    pub replaced: BTreeSet<PartRef>,
    /// Per replaced body: wall ms when it was replaced (spec/commits.md §5): per dead write, the
    /// earliest `ts` among the held valid writes superseding it (read from any other held valid
    /// body holding one, a vouched copy of an invalid delta's write by its own `ts` too); a body
    /// at its latest; a signal's at its own `ts`. History counts from it.
    /// None: nothing held supersedes a
    /// write of it (its content left the canonical state otherwise: a reset pruned it to an
    /// anchor, a copy without it).
    pub replaced_at: BTreeMap<PartRef, Option<u64>>,
    /// `history()`: per aspect, the replaced writes (stamp, carrying commit) of held valid bodies
    /// in history (`Outcome::in_history` at their replaced-at), not purged. A function of the held set.
    pub history: BTreeMap<(ThingId, Aspect), BTreeSet<(Stamp, CommitId)>>,
    /// Per thing, its held valid `retention^.0` settings in key order: its timeline (issues/thing-history.md, In force).
    pub settings: BTreeMap<ThingId, Vec<(Key, Setting)>>,
    /// Replaced value bodies under purge on replace: the entry governing their AK in the setting
    /// in force at their replaced-at says so (never a signal's).
    pub under_purge: BTreeSet<PartRef>,
    /// Bodies under purge on replace that no valid snapshot holding the right covers, while `me`
    /// holds the right: the covering snapshot `me` owes in the transaction in which that comes to
    /// hold (`cover`). A node without the right owes none.
    pub owed: BTreeSet<PartRef>,
    /// Bodies dropped as covered whose cover no longer stands (invalid, purged, or not held):
    /// never received, to be fetched again (spec/permissions.md §5.2).
    pub uncovered: BTreeSet<PartRef>,
    /// Every clock value after `now` at which the output may change with the held set unchanged
    /// (unparking, expiry, a body leaving history, a purge floor): between two of them, and after
    /// the last, it is constant.
    pub deadlines: BTreeSet<u64>,
    /// Values held that the node must not hold: `(body, carrying delta, write)`, the write by
    /// `death::key`.
    pub forbidden: BTreeSet<(PartRef, DeltaRef, Name)>,
    /// Things the node forgets: ended (`DropWhy::Ended`).
    pub ended: BTreeSet<ThingId>,
    /// Commits held of which the node holds nothing (every part it holds is `DropWhy::Unknown`, or
    /// its author's or actor's record is unknown): thrown out whole, their IDs kept to fetch them again once a
    /// record comes (`act` removes them).
    pub revisit: BTreeSet<CommitId>,
}

impl Outcome {
    /// The thing's timeline for aspect `a`, each setting as its governing entry reads.
    fn timeline_of(&self, t: ThingId, a: Aspect) -> Vec<thing_history::Setting> {
        let s = self.settings.get(&t).map_or(&[][..], |v| &v[..]);
        s.iter().enumerate().map(|(i, (k, x))| thing_history::Setting { ts: wall(k.0), id: i as u32, opt: x.entry(a.name).map_or(Opt::None, |e| e.history) }).collect()
    }
    /// The moment a body of `(t, a)` replaced at wall ms `r` leaves history (issues/thing-history.md,
    /// History): the first moment from `r` at which the setting in force does not keep it, one way
    /// (purge on replace once in force, a later keep reads as none). `NEVER`: a fixed-retention
    /// aspect, or a setting keeping it for good.
    pub fn out(&self, t: ThingId, a: Aspect, r: u64) -> u64 {
        if a.fixed() {
            return NEVER;
        }
        thing_history::out(&self.timeline_of(t, a), true, r)
    }
    /// Whether a body of `(t, a)` replaced at `r` is in history at `now`: it leaves later than
    /// replaced (one under no history or purge on replace never is, AMBIGUITIES 68), and not yet.
    pub fn in_history(&self, t: ThingId, a: Aspect, r: u64, now: u64) -> bool {
        let o = self.out(t, a, r);
        o > r && now < o
    }
    /// Whether a body of `(t, a)` replaced at `r` is kept from a covered drop at `now`: where
    /// some held setting keeps history for `a` (its own entry or the default, at any moment),
    /// until it is out of history on the node's clock (spec/commits.md §5 Keep bounds: never
    /// before the clock reaches `r`); elsewhere nothing is dated and a covered body drops at
    /// once, whatever the thing's other aspects keep. Per part: `r` is the part's own
    /// replacement, so another part of its commit, kept or not, neither dates nor keeps it (the
    /// engine keeps a body class until the latest of its parts' bounds, a keep at least on top).
    /// Listing follows history.
    pub fn kept(&self, t: ThingId, a: Aspect, r: u64, now: u64) -> bool {
        self.in_history(t, a, r, now) || now < r && self.aspect_keeps(t, a)
    }
    /// Whether some held valid setting of `t` keeps history for `a` (the entry governing it
    /// reads `keep`).
    pub fn aspect_keeps(&self, t: ThingId, a: Aspect) -> bool {
        self.timeline_of(t, a).iter().any(|s| matches!(s.opt, Opt::Keep { .. }))
    }
    /// The entry option in force for `(t, a)` at wall ms `at` (one way).
    pub fn in_force(&self, t: ThingId, a: Aspect, at: u64) -> Opt {
        if a.fixed() {
            return Opt::None;
        }
        thing_history::in_force(&self.timeline_of(t, a), true, at)
    }
}

/// The record a part's creation mints, when it is one held.
pub fn creation(p: &Part) -> Option<RecordLink> {
    match &p.body {
        Body::Held(Delta::Created(l)) if p.aspect == Aspect::CREATED => Some(*l),
        _ => None,
    }
}

/// The records the node knows (spec/permissions.md §1: a record proves itself by its hash):
/// `Held::records`, and each held creation's whose commit is not parked and whose author and
/// first admin records are known (a node holds no part whose author or chain record it lacks).
fn records(h: &Held, parked: &BTreeSet<CommitId>) -> World {
    let mut world = World::new(&h.records);
    loop {
        let more: Vec<(ThingId, RecordLink)> = h
            .commits
            .iter()
            .filter(|c| !parked.contains(&c.id) && world.known(c.author))
            .flat_map(|c| c.parts.iter())
            .filter_map(|p| Some((p.thing, creation(p)?)))
            .filter(|(t, l)| !world.known(*t) && !matches!(l, RecordLink::Admin(a) if !world.known(*a)))
            .collect();
        if more.is_empty() {
            return world;
        }
        world.links.extend(more);
    }
}

fn body(p: &Part) -> Option<&Frag> {
    match &p.body {
        Body::Held(Delta::Writes(f)) => Some(f),
        _ => None,
    }
}

/// Which commit each write belongs to (spec/crdt.md §2.4, §4.7 Attribution): `Held::dots`, and
/// every other commit in commit form (`commit_source`).
pub struct Dots {
    ranged: BTreeMap<(ThingId, Aspect), Origins<CommitId>>,
    commits: Origins<CommitId>,
}

impl Dots {
    pub fn new(h: &Held) -> Dots {
        let mut ranged: BTreeMap<(ThingId, Aspect), Origins<CommitId>> = BTreeMap::new();
        for r in &h.dots {
            ranged.entry((r.thing, r.aspect)).or_default().add(r.source.clone(), r.lo, r.hi, r.commit);
        }
        let named: BTreeSet<CommitId> = h.dots.iter().map(|r| r.commit).collect();
        let mut commits = Origins::default();
        for c in h.commits.iter().filter(|c| !named.contains(&c.id)) {
            let Source::Commit(b) = commit_source(c.id) else { unreachable!() };
            commits.commit_form(b, c.id);
        }
        Dots { ranged, commits }
    }
    /// The commit a write under `d` on `(t, a)` belongs to.
    pub fn commit(&self, t: ThingId, a: Aspect, d: &Dot) -> Option<CommitId> {
        self.ranged.get(&(t, a)).and_then(|o| o.of(d)).or_else(|| self.commits.of(d)).copied()
    }
    /// The commits whose values `f` on `(t, a)` holds value-less (spec/crdt.md §4.7).
    pub fn valueless(&self, t: ThingId, a: Aspect, f: &Frag) -> BTreeSet<CommitId> {
        death::valueless(f).iter().filter_map(|s| self.commit(t, a, &s.dot)).collect()
    }
    /// `f` with the values of the commits `drop` names stripped (spec/crdt.md §4.7).
    pub fn strip(&self, t: ThingId, a: Aspect, f: &Frag, drop: &dyn Fn(CommitId) -> bool) -> Frag {
        let mut f = f.clone();
        f.strip(&|d| self.commit(t, a, d).is_some_and(|c| drop(c)));
        f
    }
    /// The writes of `f` carrying a value of a commit `drop` names, by `death::key`, with it.
    pub fn values_of(&self, t: ThingId, a: Aspect, f: &Frag, drop: &dyn Fn(CommitId) -> bool) -> Vec<(Name, CommitId)> {
        writes(f)
            .into_iter()
            .filter_map(|(n, w)| {
                let c = self.commit(t, a, &death::stamp(&n).dot)?;
                (drop(c) && valued(&w)).then(|| (death::key(&n), c))
            })
            .collect()
    }
}

pub(crate) fn expired(c: &Commit, now: u64) -> bool {
    c.expires.is_some_and(|t| now >= t)
}

fn names(q: &Commit, c: &Commit, p: &Part) -> bool {
    c.ts < q.ts
        && !c.is_role()
        // an expiring request reaches only deltas expiring no later
        && q.expires.is_none_or(|e| c.expires.is_some_and(|x| x <= e))
        && q.purge.iter().any(|it| match *it {
            PurgeItem::Commit { commit, thing, aspect } => commit == c.id && p.thing == thing && p.aspect == aspect,
            PurgeItem::Aspect { thing, aspect } => p.thing == thing && p.aspect == aspect,
            PurgeItem::Author { thing, aspect, author } => p.thing == thing && p.aspect == aspect && c.actor == author,
        })
}

/// What applied and joined, and the role timeline over it.
struct Joined<'a> {
    live: Vec<&'a Commit>,
    applied: BTreeSet<CommitId>,
    /// Held parts that wait, of any commit (spec/commits.md §4).
    waiting: BTreeSet<PartRef>,
    /// Held parts the node does not hold (`DropWhy::Unknown`).
    thrown: BTreeSet<PartRef>,
    /// Commits thrown out whole (`Outcome::revisit`).
    revisit: BTreeSet<CommitId>,
    /// The applied commits as joined: their waiting and thrown parts count as not received.
    view: Vec<Commit>,
    tl: Timeline,
}

fn join_held<'a>(h: &'a Held, parked: &BTreeSet<CommitId>) -> Joined<'a> {
    let world = records(h, parked);
    let mut live: Vec<&Commit> = h.commits.iter().filter(|c| !parked.contains(&c.id)).collect();
    live.sort_by_key(|c| c.id);
    // spec/commits.md §4 Apply: every held part that does not wait applies; nothing waits for a
    // part. Least fixpoint: what leads from an author to a thing, and which things exist, grow
    // with the applied parts.
    let mut applied: BTreeSet<CommitId> = BTreeSet::new();
    let mut waiting: BTreeSet<PartRef> = BTreeSet::new();
    let mut thrown: BTreeSet<PartRef> = BTreeSet::new();
    let held = |p: &Part| matches!(p.body, Body::Held(_) | Body::Parked | Body::Dropped(_));
    let view = loop {
        let out: BTreeSet<PartRef> = waiting.union(&thrown).copied().collect();
        let view: Vec<Commit> = live.iter().filter(|c| applied.contains(&c.id)).map(|c| without(c, &out)).collect();
        let leads = leads(&world, &live, &view);
        // a thing exists while a creation of it joins, or while it is known by its record alone,
        // no held commit listing a creation of it (spec/commits.md §5: a record is identity)
        let listed: BTreeSet<ThingId> = live.iter().flat_map(|c| c.parts.iter()).filter(|p| p.aspect == Aspect::CREATED).map(|p| p.thing).collect();
        let exists: BTreeSet<ThingId> = view.iter().flat_map(|c| c.parts.iter()).filter(|p| creation(p).is_some()).map(|p| p.thing).chain(world.links.keys().copied().filter(|t| !listed.contains(t))).collect();
        let parts = || live.iter().flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| (c, i, p))).filter(|(_, _, p)| held(p));
        // a part the node cannot judge (notes/expiry-creation-design.md §3 Unjudgeable): not held
        let t: BTreeSet<PartRef> = parts()
            .filter(|(c, _, p)| unknown(&world, &exists, c, p) || (matches!(p.body, Body::Held(_)) && unreached(&leads, c, p, &world)))
            .map(|(c, i, _)| (c.id, i))
            .collect();
        // parked parts wait; nothing else does
        let w: BTreeSet<PartRef> = parts().filter(|(c, i, p)| !t.contains(&(c.id, *i)) && p.body == Body::Parked).map(|(c, i, _)| (c.id, i)).collect();
        let a: BTreeSet<CommitId> = live.iter().filter(|c| applies(c, &w, &t, &world, h.now)).map(|c| c.id).collect();
        if a == applied && w == waiting && t == thrown {
            break view;
        }
        applied = a;
        waiting = w;
        thrown = t;
    };
    // thrown out whole: nothing of it held but parts the node does not hold
    let revisit = live
        .iter()
        .filter(|c| !applied.contains(&c.id))
        .filter(|c| !judgeable(&world, c) || ((0..c.parts.len()).any(|i| thrown.contains(&(c.id, i))) && (0..c.parts.len()).all(|i| thrown.contains(&(c.id, i)) || !held(&c.parts[i]))))
        .map(|c| c.id)
        .collect();
    // Role timeline over the joined role commits.
    let mut tl = Timeline::walk(world, edge_events(view.iter()));
    tl.vouch(addenda(view.iter()));
    Joined { live, applied, waiting, thrown, revisit, view, tl }
}

/// Notes/expiry-creation-design.md §3: a node holds no part whose author record or thing's
/// record chain it lacks, nor one on a thing that does not exist (a creation's own thing is
/// the one it makes).
fn unknown(world: &World, exists: &BTreeSet<ThingId>, c: &Commit, p: &Part) -> bool {
    let t = p.thing;
    if !judgeable(world, c) || !world.known(t) || world.chain_above(t).iter().any(|&o| !world.known(o)) {
        return true;
    }
    creation(p).is_none() && !exists.contains(&t)
}

/// A commit is unjudgeable while its author's or actor's record is unknown.
fn judgeable(world: &World, c: &Commit) -> bool {
    world.known(c.author) && world.known(c.actor)
}

/// Per author, the things something leads to from it (spec/commits.md §4 A held part waits):
/// record edges, and holders named by a joined part of an applied role commit, whether the walk
/// applies it or not.
fn leads(world: &World, live: &[&Commit], view: &[Commit]) -> BTreeMap<NodeId, BTreeSet<ThingId>> {
    let mut adj: BTreeMap<NodeId, BTreeSet<ThingId>> = BTreeMap::new();
    for (&t, o) in &world.links {
        if let RecordLink::Admin(a) = o {
            adj.entry(*a).or_default().insert(t);
        }
    }
    for (th, _, h, _) in namings(view.iter()) {
        adj.entry(h).or_default().insert(th);
    }
    let authors: BTreeSet<NodeId> = live.iter().map(|c| c.author).collect();
    authors
        .into_iter()
        .map(|a| {
            let mut seen = BTreeSet::from([a]);
            let mut todo = vec![a];
            while let Some(x) = todo.pop() {
                for &y in adj.get(&x).into_iter().flatten() {
                    if seen.insert(y) {
                        todo.push(y);
                    }
                }
            }
            (a, seen)
        })
        .collect()
}

/// Notes/expiry-creation-design.md §3: nothing leads from the author to the part's thing: not
/// judgeable (record waits are `unknown`).
fn unreached(leads: &BTreeMap<NodeId, BTreeSet<ThingId>>, c: &Commit, p: &Part, world: &World) -> bool {
    let t = p.thing;
    t != c.author && !world.chain_above(t).contains(&c.author) && !leads.get(&c.author).is_some_and(|s| s.contains(&t))
}

/// The commit as joined: its waiting and thrown parts count as not received.
fn without(c: &Commit, waiting: &BTreeSet<PartRef>) -> Commit {
    let mut c = c.clone();
    for (i, p) in c.parts.iter_mut().enumerate() {
        if waiting.contains(&(c.id, i)) {
            p.body = Body::Missing;
        }
    }
    c
}

/// spec/commits.md §4 Pending (drift is `parked`): the author's record known, and a held part that
/// does not wait or no part held; a commit holding only parts the node does not hold is thrown
/// out (`unknown`). A waiting part past its expiry has gone (§5); a dropped body's commit
/// applied when it was held (README.md).
fn applies(c: &Commit, waiting: &BTreeSet<PartRef>, thrown: &BTreeSet<PartRef>, world: &World, now: u64) -> bool {
    if !judgeable(world, c) {
        return false;
    }
    let held: Vec<usize> = (0..c.parts.len())
        .filter(|&i| {
            let gone = waiting.contains(&(c.id, i)) && expired(c, now);
            matches!(c.parts[i].body, Body::Held(_) | Body::Parked | Body::Dropped(_)) && !gone && !thrown.contains(&(c.id, i))
        })
        .collect();
    let any_thrown = (0..c.parts.len()).any(|i| thrown.contains(&(c.id, i)));
    (held.is_empty() && !any_thrown) || held.iter().any(|&i| !waiting.contains(&(c.id, i)))
}

fn parked(h: &Held) -> BTreeSet<CommitId> {
    // Parking (spec/crdt.md §2.2): more than MAX_DRIFT ahead counts as not received.
    h.commits.iter().filter(|c| wall(c.ts) > h.now.saturating_add(MAX_DRIFT)).map(|c| c.id).collect()
}

/// The settled role timeline of a held set (its ended things forgotten).
pub fn timeline(h: &Held) -> Timeline {
    let (hv, _) = forgotten(h);
    join_held(&hv, &parked(&hv)).tl
}

/// Whether an ended thing keeps this part: its creation and `roles.0` while a purge request's
/// part on it is held, as the ending is judged from them (spec/commits.md §5 Ending).
fn kept_when_ended(h: &Held, p: &Part) -> bool {
    (p.aspect == Aspect::ROLES || p.aspect == Aspect::CREATED) && h.commits.iter().flat_map(|c| &c.parts).any(|q| q.thing == p.thing && q.aspect == crate::gen::PURGE)
}

/// `h` with every part on `things` counting as never received, but what an ending keeps.
fn forget(h: &Held, things: &BTreeSet<ThingId>) -> Held {
    let mut n = h.clone();
    for p in n.commits.iter_mut().flat_map(|c| c.parts.iter_mut()).filter(|p| things.contains(&p.thing) && !kept_when_ended(h, p)) {
        p.body = Body::Missing;
        p.stripped.clear();
    }
    n
}

/// The held set as judged once its ended things are forgotten, with its judgment. What an ending
/// keeps (`kept_when_ended`) still counts, so a purge's right reads the same before and after.
fn forgotten(h: &Held) -> (Held, Outcome) {
    let mut gone: BTreeSet<ThingId> = BTreeSet::new();
    loop {
        let hv = forget(h, &gone);
        let mut o = judge(&hv);
        if o.ended.is_subset(&gone) {
            o.ended = gone;
            return (hv, o);
        }
        gone.extend(o.ended);
    }
}

pub fn evaluate(h: &Held) -> Outcome {
    let (_, mut o) = forgotten(h);
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            if o.ended.contains(&p.thing) && matches!(p.body, Body::Held(_) | Body::Parked) && !kept_when_ended(h, p) {
                o.fates.insert((c.id, i), Fate::MustDrop(DropWhy::Ended));
            }
        }
    }
    o
}

/// The judgment of a held set with no thing forgotten; `Outcome::ended` is the things it ends.
fn judge(h: &Held) -> Outcome {
    let now = h.now;
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    let mut o = Outcome::default();
    o.parked = parked(h);
    let Joined { live, applied, waiting, thrown, revisit, view, tl } = join_held(h, &o.parked);
    o.revisit = revisit;
    o.applied = applied.clone();
    let is_applied = |c: &Commit| applied.contains(&c.id);

    // Validity of every part of an applied commit.
    for c in live.iter().filter(|c| is_applied(c)) {
        for (i, p) in c.parts.iter().enumerate() {
            // a record needs no authority (spec/permissions.md §1)
            let v = match c.kind {
                _ if p.aspect == Aspect::CREATED => true,
                CommitKind::Role => tl.applied_part(c.id, i),
                // no validity depends on a setting (issues/thing-history.md, The setting)
                _ => tl.valid_delta(c, p.thing, p.aspect),
            };
            o.valid.insert((c.id, i), v);
        }
    }
    let delta_valid: BTreeMap<DeltaRef, bool> = live
        .iter()
        .filter(|c| is_applied(c) && c.kind == CommitKind::Content)
        .flat_map(|c| c.parts.iter().enumerate().map(|(i, p)| ((c.id, p.thing, p.aspect), o.valid[&(c.id, i)])))
        .collect();

    // The settings (issues/thing-history.md, The setting): every held valid `retention^.0` delta
    // of an applied commit, by key; one in an expiring commit is no setting (it carries no `expires`)
    for c in view.iter().filter(|c| c.kind == CommitKind::Content && c.expires.is_none()) {
        for (i, p) in c.parts.iter().enumerate() {
            if let Body::Held(Delta::Retention(x)) = &p.body {
                if p.aspect == Aspect::RETENTION && o.valid.get(&(c.id, i)) == Some(&true) {
                    o.settings.entry(p.thing).or_default().push((c.key(), x.clone()));
                }
            }
        }
    }
    for v in o.settings.values_mut() {
        v.sort();
    }

    // Purge (spec/commits.md §5, spec/permissions.md §6): an applied request drops the named
    // joined or missing deltas of applied commits and marks waiting parts value-less. A snapshot
    // has no values of its own: a request naming it takes nothing.
    let mut pending_purged: BTreeSet<PartRef> = BTreeSet::new();
    for q in live.iter().filter(|q| !q.purge.is_empty() && is_applied(q)) {
        for c in live.iter().filter(|c| c.kind != CommitKind::Snapshot) {
            for (i, p) in c.parts.iter().enumerate() {
                // a part the node does not hold is judged once fetched again
                let right = tl.right(q.author, q.actor, q.key(), q.id, p.retention.by, c.actor, p.thing);
                if thrown.contains(&(c.id, i)) || !names(q, c, p) || !right {
                    continue;
                }
                if is_applied(c) && !waiting.contains(&(c.id, i)) {
                    let e = o.purged.entry((c.id, i)).or_insert(q.id);
                    *e = (*e).min(q.id);
                } else {
                    pending_purged.insert((c.id, i));
                }
            }
        }
    }

    // Value-less deltas: expired, or purged.
    for c in &live {
        for (i, p) in c.parts.iter().enumerate() {
            let purged = o.purged.contains_key(&(c.id, i)) || pending_purged.contains(&(c.id, i));
            if c.kind != CommitKind::Snapshot && (expired(c, now) || purged) {
                o.valueless.insert((c.id, p.thing, p.aspect));
            }
        }
    }
    // ended: every creation joined of the thing is value-less (notes/expiry-creation-design.md §3)
    let joined = || view.iter().flat_map(|c| c.parts.iter().map(move |p| (c, p))).filter(|(_, p)| creation(p).is_some());
    o.ended = joined().map(|(_, p)| p.thing).filter(|&t| joined().filter(|(_, p)| p.thing == t).all(|(c, p)| o.valueless.contains(&(c.id, t, p.aspect)))).collect();
    let vls = o.valueless.clone();
    let valid_m = o.valid.clone();
    let vl = |c: CommitId, t: ThingId, a: Aspect| vls.contains(&(c, t, a));

    // A body whose own writes are value-less with no reason (a purge that fell) counts as never
    // received (spec/permissions.md §6). One this node stripped of another delta's values stays
    // held: its value-less copies yield to a valued one (spec/crdt.md §4.7 Join). A text creation
    // its own commit inserted and deleted, kept because another write of the delta anchors at it,
    // comes without its char (spec/crdt.md §4.5): that is no value-less write (`death::valueless`).
    let dots = Dots::new(h);
    let never_received = |c: &Commit, p: &Part| -> bool {
        c.kind == CommitKind::Content && !vl(c.id, p.thing, p.aspect) && body(p).is_some_and(|f| dots.valueless(p.thing, p.aspect, f).contains(&c.id))
    };

    // Snapshot validity and contribution.
    let snap_ok = |c: &Commit, i: usize| valid_m.get(&(c.id, i)) == Some(&true);

    // Build each aspect's state: the join of the valid held bodies, invalid deltas un-merged
    // (spec/crdt.md §4.6: a valid snapshot's copies and the records it holds stay), value-less
    // deltas stripped (spec/crdt.md §4.7). `bodies`: what each held body contributes.
    let mut aspects: BTreeSet<(ThingId, Aspect)> = BTreeSet::new();
    for c in &live {
        for p in &c.parts {
            if !c.is_role() && body(p).is_some() {
                aspects.insert((p.thing, p.aspect));
            }
        }
    }
    let mut contrib: BTreeMap<(ThingId, Aspect), Vec<(CommitId, Frag)>> = BTreeMap::new();
    for &(t, a) in &aspects {
        // a signal has no current value: nothing of it joins (spec/data-model.md §2)
        if a.signal {
            o.reads.insert((t, a), None);
            o.states.insert((t, a), Frag::empty(0));
            continue;
        }
        let mut snaps: Vec<(CommitId, Frag)> = Vec::new();
        let mut own: Vec<(CommitId, Frag)> = Vec::new();
        for c in &view {
            for (i, p) in c.parts.iter().enumerate() {
                if p.thing != t || p.aspect != a {
                    continue;
                }
                let Some(f) = body(p) else { continue };
                match c.kind {
                    CommitKind::Snapshot if snap_ok(c, i) && !never_received(c, p) => snaps.push((c.id, f.clone())),
                    CommitKind::Content if !never_received(c, p) => own.push((c.id, f.clone())),
                    _ => {}
                }
            }
        }
        // a record is held by its dot, wherever a valid snapshot holds it (spec/crdt.md §4.6, §5.6)
        let mut held = BTreeSet::new();
        for (_, f) in &snaps {
            f.held_records(&mut held);
        }
        let invalid = |d: &Dot| dots.commit(t, a, d).is_some_and(|c| delta_valid.get(&(c, t, a)) == Some(&false));
        let mut bodies = Vec::new();
        for (id, mut f) in own {
            f.unmerge(&invalid, &|d| held.contains(d));
            bodies.push((id, f));
        }
        bodies.extend(snaps);
        let bodies: Vec<(CommitId, Frag)> = bodies.into_iter().map(|(id, f)| (id, dots.strip(t, a, &f, &|c| vl(c, t, a)))).collect();
        let st = join(bodies.iter().map(|x| x.1.clone()));
        o.reads.insert((t, a), st.read());
        o.states.insert((t, a), st);
        contrib.insert((t, a), bodies);
    }

    // Replaced bodies (spec/commits.md §5 Bodies and deaths): a held valid body holding a write the
    // state does not hold, joining into the state leaving it unchanged (the write is dead, not
    // un-merged). An expiring delta is judged with its values value-less on both sides (a
    // snapshot carries them so, spec/crdt.md §8): replaced only once none of its values lives.
    for c in view.iter().filter(|c| !c.is_role()) {
        for (i, p) in c.parts.iter().enumerate() {
            let Some(f) = body(p) else { continue };
            let (t, a) = (p.thing, p.aspect);
            // a signal write is replaced the moment it is written (spec/commits.md §5 Signals):
            // history from its own `ts` under the entry governing its AK
            if a.signal {
                if c.kind != CommitKind::Content || valid_m.get(&(c.id, i)) != Some(&true) || never_received(c, p) {
                    continue;
                }
                o.replaced.insert((c.id, i));
                o.replaced_at.insert((c.id, i), Some(wall(c.ts)));
                if o.in_history(t, a, wall(c.ts), now) && !o.purged.contains_key(&(c.id, i)) {
                    o.history.entry((t, a)).or_default().extend(writes(f).iter().map(|(n, _)| (death::stamp(n).clone(), c.id)));
                }
                continue;
            }
            let (Some(st), Some(bodies)) = (o.states.get(&(t, a)), contrib.get(&(t, a))) else { continue };
            if valid_m.get(&(c.id, i)) != Some(&true) || never_received(c, p) {
                continue;
            }
            let own = |x: CommitId| vl(x, t, a) || (x == c.id && c.expires.is_some());
            let b = dots.strip(t, a, f, &own);
            let st = if c.expires.is_some() { dots.strip(t, a, st, &own) } else { st.clone() };
            let held = keys(&st);
            let gone: Vec<(Name, Frag)> = writes(&b).into_iter().filter(|(n, _)| !holds(&held, n)).collect();
            if gone.is_empty() || !covers(&st, &b) {
                continue;
            }
            o.replaced.insert((c.id, i));
            // per gone write, the earliest `ts` among the held valid writes superseding it, read
            // from any other held valid body holding one (spec/crdt.md §4.8; its own commit, or a
            // snapshot carrying it, a valid snapshot's copy of a write whose own delta is held
            // invalid included: each by its own `ts`); none held: the superseder's own `ts`. A text
            // element's creation dies only by a delete stamped after the latest undelete of the
            // element held. A body counts from the latest of its writes' deaths (its
            // replacement), a snapshot's leaving out those a held valid snapshot stamped later
            // carries as a winning write (that one keeps it)
            let died = |w: &Frag| -> Option<u64> {
                let ws = winning(w);
                let name = ws.iter().next();
                let at = name.map(|n| death::stamp(n).clone());
                // the element of a text creation, and the latest undelete held there: a flag
                // write at the element that does not supersede the creation
                let creation = name.is_some_and(|n| matches!(n.last(), Some(Step::Created(_))));
                let elem = name.filter(|_| creation).map(|n| n[..n.len() - 1].to_vec());
                let undeleted = elem.as_ref().and_then(|e| {
                    bodies.iter().flat_map(|(_, bf)| writes(bf)).filter(|(n, x)| matches!(n.last(), Some(Step::Flag(_))) && death::key(n)[..n.len() - 1] == e[..] && !supersedes(x, w)).map(|(n, _)| death::stamp(&n).clone()).max()
                });
                let mut first: Option<u64> = None;
                let mut own_ts: Option<u64> = None;
                for (b_id, bf) in bodies {
                    for (n, x) in writes(bf) {
                        if at.as_ref().is_some_and(|s| death::stamp(&n) < s) || !supersedes(&x, w) {
                            continue;
                        }
                        if matches!(n.last(), Some(Step::Flag(_))) && undeleted.as_ref().is_some_and(|u| death::stamp(&n) <= u) {
                            continue;
                        }
                        let wt = wall(death::stamp(&n).ts);
                        own_ts = Some(own_ts.map_or(wt, |x| x.min(wt)));
                        if *b_id != c.id {
                            first = Some(first.map_or(wt, |x| x.min(wt)));
                        }
                    }
                }
                first.or(own_ts)
            };
            let carried_later = |n: &Name| {
                view.iter().any(|s| {
                    s.kind == CommitKind::Snapshot
                        && s.ts > c.ts
                        && s.parts.iter().enumerate().any(|(j, q)| snap_ok(s, j) && q.thing == t && q.aspect == a && !never_received(s, q) && body(q).is_some_and(|sf| winning(sf).contains(&death::key(n))))
                })
            };
            let each = gone.iter().filter(|(n, _)| c.kind != CommitKind::Snapshot || !carried_later(n)).filter_map(|(_, w)| died(w));
            let at = each.max();
            o.replaced_at.insert((c.id, i), at);
            // under purge on replace by the setting in force when it was replaced; history() while
            // the settings keep it (nothing dates a body nothing held supersedes: not history)
            if at.is_some_and(|r| o.in_force(t, a, r) == Opt::Purge) {
                o.under_purge.insert((c.id, i));
            }
            if at.is_some_and(|r| o.in_history(t, a, r, now)) && !o.purged.contains_key(&(c.id, i)) {
                o.history.entry((t, a)).or_default().extend(gone.iter().map(|(n, _)| (death::stamp(n).clone(), c.id)));
            }
        }
    }

    // Fates.
    let mut fates = BTreeMap::new();
    for c in by_id.values() {
        for (i, p) in c.parts.iter().enumerate() {
            if matches!(p.body, Body::Held(_) | Body::Parked) {
                let (f, owed) = if thrown.contains(&(c.id, i)) { (Fate::MustDrop(DropWhy::Unknown), false) } else { fate(c, i, p, &o, &live, &tl, h.me, &pending_purged, &waiting, now, &never_received, &vl, &dots) };
                fates.insert((c.id, i), f);
                if owed {
                    o.owed.insert((c.id, i));
                }
            }
        }
    }
    o.fates = fates;

    // A dropped body whose cover no longer stands (or whose purge fell) counts as never received.
    let stands = |by: CommitId, pr: PartRef, t: ThingId, a: Aspect| -> bool {
        by_id.get(&by).is_some_and(|s| {
            if s.kind != CommitKind::Snapshot {
                return o.purged.contains_key(&pr);
            }
            o.applied.contains(&s.id)
                && s.parts.iter().enumerate().any(|(j, q)| {
                    q.thing == t && q.aspect == a && matches!(q.body, Body::Held(_) | Body::Dropped(_)) && o.valid.get(&(s.id, j)) == Some(&true)
                })
        })
    };
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            if let Body::Dropped(by) = p.body {
                if !stands(by, (c.id, i), p.thing, p.aspect) {
                    o.uncovered.insert((c.id, i));
                }
            }
        }
    }

    // Timing: every clock value past `now` at which the output may change (drift, expiry,
    // keep-until).
    for c in &h.commits {
        if o.parked.contains(&c.id) {
            o.deadlines.insert(wall(c.ts) - MAX_DRIFT);
        }
        o.deadlines.extend(c.expires);
        o.deadlines.insert(kept_until(c));
        for (i, p) in c.parts.iter().enumerate() {
            if let Some(Some(r)) = o.replaced_at.get(&(c.id, i)) {
                o.deadlines.insert(o.out(p.thing, p.aspect, *r));
            }
        }
    }
    o.deadlines.retain(|&t| t > now && t != NEVER);

    // Forbidden values: any value of a value-less delta still held.
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            // a waiting body is stripped of others' values only when its commit applies; one the
            // node does not hold goes
            if matches!(o.fates.get(&(c.id, i)), Some(Fate::Keep(KeepWhy::Pending) | Fate::MustDrop(DropWhy::Unknown))) {
                continue;
            }
            let Some(f) = body(p) else { continue };
            for (n, own) in dots.values_of(p.thing, p.aspect, f, &|x| o.valueless.contains(&(x, p.thing, p.aspect))) {
                o.forbidden.insert(((c.id, i), (own, p.thing, p.aspect), n));
            }
        }
    }
    o
}

/// The wall ms before which a commit's bodies are must-hold at every node whatever the settings:
/// a purge request's floor `wall(ts) + ROLE_KEEP` for a commit carrying one (spec/commits.md §5
/// Purge), else 0. History counts from the held set and the settings (`Outcome::out`).
pub fn kept_until(c: &Commit) -> u64 {
    if c.purge.is_empty() { 0 } else { wall(c.ts).saturating_add(ROLE_KEEP) }
}

/// Whether a signal body is kept: in history from its own `ts` (spec/commits.md §5 Signals), or
/// before its commit's purge floor.
pub fn signal_kept(o: &Outcome, c: &Commit, p: &Part, now: u64) -> bool {
    now < kept_until(c) || o.in_history(p.thing, p.aspect, wall(c.ts), now)
}

/// A body's fate, and whether `me` owes it a covering snapshot (`Outcome::owed`).
#[allow(clippy::too_many_arguments)]
fn fate(
    c: &Commit,
    i: usize,
    p: &Part,
    o: &Outcome,
    live: &[&Commit],
    tl: &Timeline,
    me: NodeId,
    pending_purged: &BTreeSet<PartRef>,
    waiting: &BTreeSet<PartRef>,
    now: u64,
    never_received: &dyn Fn(&Commit, &Part) -> bool,
    vl: &dyn Fn(CommitId, ThingId, Aspect) -> bool,
    dots: &Dots,
) -> (Fate, bool) {
    let pr = (c.id, i);
    if c.is_role() {
        return (Fate::Keep(KeepWhy::Role), false);
    }
    let waits = !o.applied.contains(&c.id) || waiting.contains(&pr);
    // a waiting part past its expiry goes (spec/commits.md §5); an unjoinable body cannot be
    // stripped, so a purge or expiry drops it whole (spec/versioning.md §2)
    if (waits && expired(c, now)) || (p.body == Body::Parked && (expired(c, now) || o.purged.contains_key(&pr) || pending_purged.contains(&pr))) {
        return (Fate::MustDrop(DropWhy::Gone), false);
    }
    let (t, a) = (p.thing, p.aspect);
    let copy = body(p).is_some_and(|f| !dots.values_of(t, a, f, &|x| vl(x, t, a)).is_empty());
    if !waits && p.body != Body::Parked && o.valid.get(&pr) == Some(&false) && c.author != me {
        return (Fate::MustDrop(DropWhy::Invalid), false);
    }
    if waits || p.body == Body::Parked {
        if pending_purged.contains(&pr) {
            return (Fate::Leftover(LeftoverWhy::PendingPurged), false);
        }
        // a waiting body keeps its body, copies of value-less values included, until its commit
        // applies (spec/commits.md §5, spec/crdt.md §4.7 Copies)
        return (Fate::Keep(KeepWhy::Pending), false);
    }
    // a signal body is never covered (no state to snapshot): kept until its keep bound, then it
    // may go, whole or as an expired or purged leftover (spec/commits.md §5 Signals)
    if p.aspect.signal && !signal_kept(o, c, p, now) {
        return (Fate::MayDrop(DropWhy::PastBound), false);
    }
    if expired(c, now) {
        return (Fate::Leftover(LeftoverWhy::Expired), false);
    }
    if o.purged.contains_key(&pr) {
        return (Fate::Leftover(LeftoverWhy::Purged), false);
    }
    if never_received(c, p) {
        return (Fate::NeverReceived, false);
    }
    if p.aspect.signal {
        return (Fate::Keep(KeepWhy::Until), false);
    }
    // A body carrying a copy of a value held value-less is held as its leftover, and is a body
    // like a whole one for its mode and covering (spec/commits.md §5 Dropping a body).
    let ws = body(p).map_or_else(|| Frag::empty(0), |f| dots.strip(t, a, f, &|x| vl(x, t, a)));
    let keep = |why| if copy { Fate::Leftover(LeftoverWhy::Copy) } else { Fate::Keep(why) };
    if now < kept_until(c) {
        return (keep(KeepWhy::Until), false);
    }
    // fixed retention is never out of history
    if p.aspect.fixed() {
        return (keep(KeepWhy::Plain), false);
    }
    // Covers: a valid snapshot whose part on the aspect covers the body by the join; an expiring
    // delta only once no value of it lives (a snapshot carries its values value-less,
    // spec/crdt.md §8); a snapshot body only by one stamped later, or at the same `ts` by one with
    // a lower commit ID (covered-equal, spec/sync.md §7). Each with whether its commit holds the
    // purge right over the body.
    let covering: Vec<(CommitId, bool)> = live
        .iter()
        .filter(|s| s.kind == CommitKind::Snapshot && s.id != c.id && o.applied.contains(&s.id) && !(c.kind == CommitKind::Snapshot && (c.ts, s.id) > (s.ts, c.id)))
        .filter(|s| {
            s.parts.iter().enumerate().any(|(j, q)| {
                q.thing == t && q.aspect == a && o.valid.get(&(s.id, j)) == Some(&true) && !never_received(s, q) && body(q).is_some_and(|sw| covers(sw, &ws))
            })
        })
        .map(|s| (s.id, tl.right(s.author, s.actor, s.key(), s.id, p.retention.by, c.actor, t)))
        .collect();
    let by_right = covering.iter().find(|x| x.1).map(|x| x.0);
    let by_any = by_right.or(covering.first().map(|x| x.0));
    let right = tl.right(me, me, (u64::MAX, me, u32::MAX), u32::MAX, p.retention.by, c.actor, t);
    // issues/thing-history.md: in history, kept (compaction may not drop it); under purge on
    // replace, gone at every node once a right holder covers it and the clock reaches its
    // replacement, owed by a right holder until then; out of history, any valid writer's cover
    // drops it (Decisions 4)
    let kept = o.replaced_at.get(&pr).copied().flatten().is_some_and(|r| o.kept(t, a, r, now));
    let under = o.under_purge.contains(&pr);
    let owes = under && by_right.is_none() && right;
    match (by_right, by_any) {
        (Some(by), _) if under && !kept => (Fate::MustDrop(DropWhy::Covered { by }), false),
        (_, Some(_)) if kept => (keep(KeepWhy::Until), false),
        (_, Some(by)) => (Fate::MayDrop(DropWhy::Covered { by }), owes),
        (_, None) => (keep(KeepWhy::Plain), owes),
    }
}

/// The covering snapshot `me` writes for an aspect from its whole state (spec/commits.md §2), its
/// retention `writer`: what a writer owes for an `owed` body (`Outcome::owed`), or writes to
/// compact. A snapshot carries writes of expiring deltas value-less (spec/crdt.md §8).
pub fn cover(h: &Held, o: &Outcome, thing: ThingId, aspect: Aspect, id: CommitId, ts: u64) -> Commit {
    let f = snapshot_state(h, o, thing, aspect);
    let part = Part { thing, aspect, retention: Retention::WRITER, body: Body::Held(Delta::Writes(f)), stripped: Default::default(), replaces: None };
    Commit { id, author: h.me, actor: h.me, ts, expires: None, kind: CommitKind::Snapshot, parts: vec![part], purge: vec![], frontier: None, undoes: None , boxes: vec![] }
}

/// What a snapshot of an aspect carries: the state, writes of expiring deltas value-less
/// (spec/crdt.md §8).
pub fn snapshot_state(h: &Held, o: &Outcome, thing: ThingId, aspect: Aspect) -> Frag {
    let st = o.states.get(&(thing, aspect)).cloned().unwrap_or_else(|| Frag::empty(0));
    Dots::new(h).strip(thing, aspect, &st, &|c| h.commits.iter().any(|k| k.id == c && k.expires.is_some()))
}

/// The join of fragments, pruned (spec/crdt.md §4.1, §7); nothing is the empty register.
pub fn join(fs: impl IntoIterator<Item = Frag>) -> Frag {
    let mut out = Frag::empty(0);
    for f in fs {
        out.join(f);
    }
    out
}

/// Carries out the fates: strips leftovers, drops bodies that must go, makes the uncovered and
/// the never received missing, throws out the commits to revisit, and also drops the one `may`
/// names. The result is what the node holds next.
pub fn act(h: &Held, o: &Outcome, may: Option<PartRef>) -> Held {
    let dots = Dots::new(h);
    let mut n = h.clone();
    n.commits.retain(|c| !o.revisit.contains(&c.id));
    for c in &mut n.commits {
        for (i, p) in c.parts.iter_mut().enumerate() {
            if o.uncovered.contains(&(c.id, i)) {
                p.body = Body::Missing;
                p.stripped.clear();
                continue;
            }
            let Some(&f) = o.fates.get(&(c.id, i)) else { continue };
            let (t, a) = (p.thing, p.aspect);
            match f {
                // a body that stays held holds no value of a value-less write (spec/crdt.md §4.7
                // Copies), whatever else its fate says
                Fate::Leftover(_) | Fate::Keep(_) | Fate::MayDrop(_) if f != Fate::Keep(KeepWhy::Pending) && may != Some((c.id, i)) => {
                    if let Body::Held(Delta::Writes(f)) = &mut p.body {
                        let drop = |x: CommitId| o.valueless.contains(&(x, t, a));
                        p.stripped.extend(dots.values_of(t, a, f, &drop).into_iter().map(|x| x.1));
                        *f = dots.strip(t, a, f, &drop);
                    }
                }
                Fate::MustDrop(DropWhy::Gone | DropWhy::Invalid | DropWhy::Unknown | DropWhy::Ended) | Fate::NeverReceived => {
                    p.body = Body::Missing;
                    p.stripped.clear();
                }
                Fate::MustDrop(DropWhy::Covered { by }) => p.body = Body::Dropped(by),
                Fate::MayDrop(DropWhy::Covered { by }) if may == Some((c.id, i)) => p.body = Body::Dropped(by),
                Fate::MayDrop(DropWhy::PastBound) if may == Some((c.id, i)) => {
                    p.body = Body::Missing;
                    p.stripped.clear();
                }
                _ => {}
            }
        }
    }
    n
}
