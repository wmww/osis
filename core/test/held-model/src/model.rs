//! `evaluate`: the whole judgment of a held set, recomputed from scratch.

use crate::crdt::{self, Read, State};
use crate::roles::{addenda, edge_events, namings, Timeline, World};
use crate::types::*;
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
    /// Before its keep-at-least (absolute T, a purge request's floor, or D after the earliest
    /// valid replacing write the node holds): only purge or expiry act on it.
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
    /// A signal body past its keep bound (spec/commits.md §5 Signals): no state needs it and no
    /// history keeps it, so it goes at every node, whole or leftover, and counts as never received.
    PastBound,
}

/// What the node does with a held body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fate {
    Keep(KeepWhy),
    /// Hold it with the values of value-less writes stripped.
    Leftover(LeftoverWhy),
    /// It may drop it now (convenient, or past its keep-until).
    MayDrop(DropWhy),
    /// It must have dropped it by now (purge-on-replace once covered; gone and invalid parts).
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
    pub reads: BTreeMap<(ThingId, Aspect), Read>,
    /// Canonical state per aspect (what a snapshot from this node's whole state carries).
    pub states: BTreeMap<(ThingId, Aspect), Vec<Write>>,
    /// Fate of every held body.
    pub fates: BTreeMap<PartRef, Fate>,
    /// Held valid bodies holding a write the canonical state does not (replaced content).
    pub replaced: BTreeSet<PartRef>,
    /// Per replaced body: wall ms when it was replaced (spec/commits.md §5): per dead write, the
    /// `ts` of the earliest other held valid body holding a write that supersedes it; a delta at
    /// its earliest, a snapshot at its latest. The relative keep-at-least bound counts from it.
    /// None: nothing held supersedes a
    /// write of it (its content left the canonical state otherwise: a reset pruned it to an
    /// anchor, a copy without it).
    pub replaced_at: BTreeMap<PartRef, Option<u64>>,
    /// `history()`: per aspect, the replaced writes (stamp, carrying commit) of held valid bodies
    /// whose keep-at-least still holds here: before its absolute T, or within D of the earliest
    /// replacing write the node holds. A function of the held set.
    pub history: BTreeMap<(ThingId, Aspect), BTreeSet<(Stamp, CommitId)>>,
    /// Replaced purge-on-replace bodies that no valid snapshot holding the right covers, while `me` holds
    /// the right: the covering snapshot `me` owes in the replacing transaction (`cover`). A node
    /// without the right owes none and keeps the body.
    pub owed: BTreeSet<PartRef>,
    /// Bodies dropped as covered whose cover no longer stands (invalid, purged, or not held):
    /// never received, to be fetched again (spec/permissions.md §5.2).
    pub uncovered: BTreeSet<PartRef>,
    /// Every clock value after `now` at which the output may change with the held set unchanged
    /// (unparking, expiry, keep-until): between two of them, and after the last, it is constant.
    pub deadlines: BTreeSet<u64>,
    /// Values held that the node must not hold: `(body, carrying delta, write, value)`.
    pub forbidden: BTreeSet<(PartRef, DeltaRef, WriteId, Val)>,
}

fn writes(p: &Part) -> Option<&Vec<Write>> {
    match &p.body {
        Body::Held(Delta::Writes(w)) => Some(w),
        _ => None,
    }
}

fn expired(c: &Commit, now: u64) -> bool {
    c.expires.is_some_and(|t| now >= t)
}

fn names(q: &Commit, c: &Commit, p: &Part) -> bool {
    c.ts < q.ts
        && !c.is_role()
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
    /// The applied commits as joined: their waiting parts count as not received.
    view: Vec<Commit>,
    tl: Timeline,
}

fn join_held<'a>(h: &'a Held, parked: &BTreeSet<CommitId>) -> Joined<'a> {
    let world = World::new(&h.things);
    let mut live: Vec<&Commit> = h.commits.iter().filter(|c| !parked.contains(&c.id)).collect();
    live.sort_by_key(|c| c.id);
    // spec/commits.md §4 Apply: every held part that does not wait applies; nothing waits for a
    // part. Least fixpoint: what leads from an author to a thing grows with the applied parts.
    let mut applied: BTreeSet<CommitId> = BTreeSet::new();
    let mut waiting: BTreeSet<PartRef> = BTreeSet::new();
    let view = loop {
        let view: Vec<Commit> = live.iter().filter(|c| applied.contains(&c.id)).map(|c| without(c, &waiting)).collect();
        let leads = leads(&world, &live, &view);
        let w: BTreeSet<PartRef> = live
            .iter()
            .flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| (c, i, p)))
            .filter(|(c, _, p)| matches!(p.body, Body::Held(_) | Body::Parked) && part_waits(&world, &leads, c, p))
            .map(|(c, i, _)| (c.id, i))
            .collect();
        let a: BTreeSet<CommitId> = live.iter().filter(|c| applies(c, &w, &world, h.now)).map(|c| c.id).collect();
        if a == applied && w == waiting {
            break view;
        }
        applied = a;
        waiting = w;
    };
    // Role timeline over the joined role commits.
    let mut tl = Timeline::walk(world, edge_events(view.iter()));
    tl.vouch(addenda(view.iter()));
    Joined { live, applied, waiting, view, tl }
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

/// spec/commits.md §4: a held part waits while its thing's record or one up its record chain is
/// unknown, nothing leads from the author to it, or it is parked.
fn part_waits(world: &World, leads: &BTreeMap<NodeId, BTreeSet<ThingId>>, c: &Commit, p: &Part) -> bool {
    let t = p.thing;
    let chain = world.chain_above(t);
    if p.body == Body::Parked || !world.known(t) || chain.iter().any(|&o| !world.known(o)) {
        return true;
    }
    t != c.author && !chain.contains(&c.author) && !leads.get(&c.author).is_some_and(|s| s.contains(&t))
}

/// The commit as joined: its waiting parts count as not received.
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
/// does not wait or no part held. A waiting part past its expiry has gone (§5); a dropped body's
/// commit applied when it was held (README.md).
fn applies(c: &Commit, waiting: &BTreeSet<PartRef>, world: &World, now: u64) -> bool {
    if !world.known(c.author) {
        return false;
    }
    let held: Vec<usize> = (0..c.parts.len())
        .filter(|&i| {
            let gone = waiting.contains(&(c.id, i)) && expired(c, now);
            matches!(c.parts[i].body, Body::Held(_) | Body::Parked | Body::Dropped(_)) && !gone
        })
        .collect();
    held.is_empty() || held.iter().any(|&i| !waiting.contains(&(c.id, i)))
}

/// Does a delta break its governing entry of a `required^.0` setting (spec/commits.md §5).
fn breaks(rules: &[Rule], c: &Commit, p: &Part) -> bool {
    let entry = rules.iter().find(|r| r.aspect == Some(p.aspect.name)).or_else(|| rules.iter().find(|r| r.aspect.is_none()));
    entry.is_some_and(|e| e.retention != p.retention || c.expires != e.expiry.map(|d| wall(c.ts) + d))
}

fn parked(h: &Held) -> BTreeSet<CommitId> {
    // Parking (spec/crdt.md §2.2): more than MAX_DRIFT ahead counts as not received.
    h.commits.iter().filter(|c| wall(c.ts) > h.now.saturating_add(MAX_DRIFT)).map(|c| c.id).collect()
}

/// The settled role timeline of a held set.
pub fn timeline(h: &Held) -> Timeline {
    join_held(h, &parked(h)).tl
}

pub fn evaluate(h: &Held) -> Outcome {
    let now = h.now;
    let by_id: BTreeMap<CommitId, &Commit> = h.commits.iter().map(|c| (c.id, c)).collect();
    let mut o = Outcome::default();
    o.parked = parked(h);
    let Joined { live, applied, waiting, view, tl } = join_held(h, &o.parked);
    o.applied = applied.clone();
    let is_applied = |c: &Commit| applied.contains(&c.id);

    // Required retention (spec/commits.md §5): the valid `required^.0` deltas, by key.
    let required: Vec<(Key, ThingId, Vec<Rule>)> = view
        .iter()
        .filter(|c| c.kind == CommitKind::Content)
        .flat_map(|c| c.parts.iter().map(move |p| (c, p)))
        .filter_map(|(c, p)| match &p.body {
            Body::Held(Delta::Required(rules)) if p.aspect == Aspect::REQUIRED => {
                tl.valid_delta(c, p.thing, p.aspect).then(|| (c.key(), p.thing, rules.clone()))
            }
            _ => None,
        })
        .collect();
    let in_force = |t: ThingId, key: Key| -> Option<&Vec<Rule>> {
        required.iter().filter(|(k, th, _)| *th == t && *k < key).max_by_key(|(k, _, _)| *k).map(|(_, _, r)| r)
    };

    // Validity of every part of an applied commit.
    for c in live.iter().filter(|c| is_applied(c)) {
        for (i, p) in c.parts.iter().enumerate() {
            let v = match c.kind {
                CommitKind::Role => tl.applied_part(c.id, i),
                _ => {
                    let ok = tl.valid_delta(c, p.thing, p.aspect);
                    let breaks = c.kind == CommitKind::Content
                        && !p.aspect.fixed()
                        && in_force(p.thing, c.key()).is_some_and(|rules| breaks(rules, c, p));
                    ok && !breaks
                }
            };
            o.valid.insert((c.id, i), v);
        }
    }
    let delta_valid: BTreeMap<DeltaRef, bool> = live
        .iter()
        .filter(|c| is_applied(c) && c.kind == CommitKind::Content)
        .flat_map(|c| c.parts.iter().enumerate().map(|(i, p)| ((c.id, p.thing, p.aspect), o.valid[&(c.id, i)])))
        .collect();

    // Purge (spec/commits.md §5, spec/permissions.md §6): an applied request drops the named
    // joined or missing deltas of applied commits and marks waiting parts value-less. A snapshot
    // has no values of its own: a request naming it takes nothing.
    let mut pending_purged: BTreeSet<PartRef> = BTreeSet::new();
    for q in live.iter().filter(|q| !q.purge.is_empty() && is_applied(q)) {
        for c in live.iter().filter(|c| c.kind != CommitKind::Snapshot) {
            for (i, p) in c.parts.iter().enumerate() {
                if !names(q, c, p) || !tl.right(q.author, q.actor, q.key(), q.id, p.retention.by, c.actor, p.thing) {
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
    let vls = o.valueless.clone();
    let valid_m = o.valid.clone();
    let vl = |c: CommitId, t: ThingId, a: Aspect| vls.contains(&(c, t, a));

    // A body whose own writes are value-less with no reason (a purge that fell) counts as never
    // received (spec/permissions.md §6). One this node stripped of another delta's values stays
    // held: its value-less copies yield to a valued one (spec/crdt.md §4.7 Join). A text creation
    // its own delta deletes may come without its char (canonical form carries no dead content,
    // spec/crdt.md §5.7): that is no value-less write.
    let never_received = |c: &Commit, p: &Part| -> bool {
        let dead_char = |ws: &[Write], w: &Write| matches!(w.op, Op::Insert { ch: None, .. }) && ws.iter().any(|d| d.op == Op::Delete { elem: w.stamp.dot });
        c.kind == CommitKind::Content && !vl(c.id, p.thing, p.aspect) && writes(p).is_some_and(|ws| ws.iter().any(|w| !dead_char(ws, w) && w.values().iter().any(|&(own, v)| own == c.id && v.is_none())))
    };

    // Snapshot validity and contribution.
    let snap_ok = |c: &Commit, i: usize| valid_m.get(&(c.id, i)) == Some(&true);

    // Build each aspect's state: the valid held bodies, invalid deltas un-merged
    // (spec/crdt.md §4.6), value-less deltas stripped (spec/crdt.md §4.7).
    let mut aspects: BTreeSet<(ThingId, Aspect)> = BTreeSet::new();
    for c in &live {
        for p in &c.parts {
            if !c.is_role() && writes(p).is_some() {
                aspects.insert((p.thing, p.aspect));
            }
        }
    }
    let mut full: BTreeMap<(ThingId, Aspect), State> = BTreeMap::new();
    let mut canons: BTreeMap<(ThingId, Aspect), State> = BTreeMap::new();
    for &(t, a) in &aspects {
        // a signal has no current value: nothing of it joins (spec/data-model.md §2)
        if a.signal {
            o.reads.insert((t, a), Read::Absent);
            o.states.insert((t, a), Vec::new());
            continue;
        }
        let mut snap_ws: Vec<Write> = Vec::new();
        let mut own_ws: Vec<Write> = Vec::new();
        for c in &view {
            for (i, p) in c.parts.iter().enumerate() {
                if p.thing != t || p.aspect != a {
                    continue;
                }
                let Some(ws) = writes(p) else { continue };
                match c.kind {
                    CommitKind::Snapshot if snap_ok(c, i) && !never_received(c, p) => snap_ws.extend(ws.iter().cloned()),
                    CommitKind::Content if !never_received(c, p) => own_ws.extend(ws.iter().cloned()),
                    _ => {}
                }
            }
        }
        let invalid = |c: CommitId| delta_valid.get(&(c, t, a)) == Some(&false);
        let snap_records: BTreeSet<Dot> =
            snap_ws.iter().filter(|w| matches!(w.op, Op::Create { .. })).map(|w| w.stamp.dot).collect();
        let mut ws: Vec<Write> = Vec::new();
        for mut w in own_ws {
            // an undelete's char goes with its creator's delta (spec/crdt.md §4.7)
            if let Op::Undelete { elem, ch } = &mut w.op {
                if invalid(elem.commit) {
                    *ch = None;
                }
            }
            // an invalid delta's writes go, seq creations included (spec/crdt.md §4.6, §6.1)
            if invalid(w.origin()) {
                continue;
            }
            // writes nested in a record an invalid delta created go, unless a valid snapshot holds it
            if let Op::SetIn { entry, .. } | Op::Remove { entry } = w.op {
                if invalid(entry.commit) && !snap_records.contains(&entry) {
                    continue;
                }
            }
            ws.push(w);
        }
        ws.extend(snap_ws);
        let mut ws: Vec<Write> = ws.into_iter().filter(|w| w.fits(a.kind)).collect();
        for w in &mut ws {
            w.strip(|c| vl(c, t, a));
        }
        let s = crdt::join(ws.iter());
        let cs = crdt::canon(&s, a.kind);
        o.reads.insert((t, a), crdt::read(&cs, a.kind));
        o.states.insert((t, a), cs.values().cloned().collect());
        full.insert((t, a), s);
        canons.insert((t, a), cs);
    }

    // Replaced bodies (spec/commits.md §5 history purge-on-replace): a held valid body holding a write the
    // canonical state does not (pruned, beaten, its element reset to a bare anchor): what a
    // snapshot from the state would leave out. Not "has a dead write" (spec/crdt.md §4.8): the
    // aspect's root reset dies once a later write implies one, yet canonical form keeps it, so
    // every snapshot carrying it would count as replaced for good. An invalid delta's writes, and
    // a valid delta's writes an un-merge took (nested in an invalid record), are not replaced; an
    // expiring delta holding a live value is not (no snapshot covers it, spec/crdt.md §8).
    for c in view.iter().filter(|c| !c.is_role()) {
        for (i, p) in c.parts.iter().enumerate() {
            let Some(ws) = writes(p) else { continue };
            // a signal write is replaced the moment it is written (spec/commits.md §5 Signals):
            // history from its own `ts` while its keep bound holds
            if p.aspect.signal {
                if c.kind != CommitKind::Content || valid_m.get(&(c.id, i)) != Some(&true) || never_received(c, p) {
                    continue;
                }
                o.replaced.insert((c.id, i));
                o.replaced_at.insert((c.id, i), Some(wall(c.ts)));
                if signal_kept(c, p, now) && !o.purged.contains_key(&(c.id, i)) {
                    o.history.entry((p.thing, p.aspect)).or_default().extend(ws.iter().map(|w| (w.stamp, c.id)));
                }
                continue;
            }
            let (Some(cs), Some(s)) = (canons.get(&(p.thing, p.aspect)), full.get(&(p.thing, p.aspect))) else { continue };
            if valid_m.get(&(c.id, i)) != Some(&true) || never_received(c, p) {
                continue;
            }
            // a write the state joined (not un-merged: one nested in an invalid delta's record or
            // an undelete's char is not replaced, it comes back with the delta's validity)
            let gone: Vec<&Write> = ws.iter().filter(|w| w.fits(p.aspect.kind) && s.contains_key(&w.id()) && !cs.contains_key(&w.id())).collect();
            if gone.is_empty() {
                continue;
            }
            if c.expires.is_some() {
                let mut sw: Vec<Write> = cs.values().cloned().collect();
                for w in &mut sw {
                    w.strip(|x| x == c.id);
                }
                if !crdt::covers(&sw, ws, p.aspect.kind) {
                    continue;
                }
            }
            o.replaced.insert((c.id, i));
            // per gone write, the `ts` of the earliest other held valid body holding a write the
            // state holds that supersedes it (its superseder's own commit, or a later snapshot
            // carrying it); none held: the superseder's own `ts`. A delta counts from the first of
            // its writes' deaths (its replacement), a snapshot from the last among those no held
            // valid snapshot stamped later, keeping history at least as long, carries: it keeps
            // the history of every write it carries, each for D after that write's own
            // replacement, but such a later snapshot carrying one keeps that one's
            let died = |w: &Write| -> Option<u64> {
                let sups: BTreeSet<WriteId> = s.values().filter(|x| crdt::supersedes(x, w)).map(|x| x.id()).collect();
                let held = view
                    .iter()
                    .filter(|b| b.id != c.id)
                    .filter(|b| {
                        b.parts.iter().enumerate().any(|(j, q)| {
                            let ok = match b.kind {
                                CommitKind::Snapshot => snap_ok(b, j),
                                CommitKind::Content => valid_m.get(&(b.id, j)) == Some(&true),
                                CommitKind::Role => false,
                            };
                            ok && q.thing == p.thing && q.aspect == p.aspect && !never_received(b, q) && writes(q).is_some_and(|bw| bw.iter().any(|y| sups.contains(&y.id())))
                        })
                    })
                    .map(|b| wall(b.ts))
                    .min();
                held.or_else(|| s.values().filter(|x| sups.contains(&x.id())).map(|x| wall(x.stamp.ts)).min())
            };
            let carried_later = |w: &Write| {
                view.iter().any(|b| {
                    b.kind == CommitKind::Snapshot
                        && b.ts > c.ts
                        && b.parts.iter().enumerate().any(|(j, q)| snap_ok(b, j) && q.retention.kept_after() >= p.retention.kept_after() && q.thing == p.thing && q.aspect == p.aspect && !never_received(b, q) && writes(q).is_some_and(|bw| bw.iter().any(|y| y.id() == w.id())))
                })
            };
            let each = gone.iter().filter(|w| c.kind != CommitKind::Snapshot || !carried_later(w)).filter_map(|w| died(w));
            let at = if c.kind == CommitKind::Snapshot { each.max() } else { each.min() };
            o.replaced_at.insert((c.id, i), at);
            // history(): shown while the keep-at-least holds, the later bound counting
            let r = p.retention;
            let shown = now < r.kept_until() || (r.kept_after() > 0 && at.is_some_and(|t| now < t.saturating_add(r.kept_after())));
            if shown && r.keeps() && !o.purged.contains_key(&(c.id, i)) {
                o.history.entry((p.thing, p.aspect)).or_default().extend(gone.iter().map(|w| (w.stamp, c.id)));
            }
        }
    }

    // Fates.
    let mut fates = BTreeMap::new();
    for c in by_id.values() {
        for (i, p) in c.parts.iter().enumerate() {
            if matches!(p.body, Body::Held(_) | Body::Parked) {
                let (f, owed) = fate(c, i, p, &o, &live, &tl, h.me, &pending_purged, &waiting, now, &never_received, &vl);
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
        for (i, p) in c.parts.iter().enumerate() {
            o.deadlines.insert(kept_until(c, p));
            if p.aspect.signal && p.retention.kept_after() > 0 {
                o.deadlines.insert(wall(c.ts).saturating_add(p.retention.kept_after()));
            }
            if let Some(Some(t)) = o.replaced_at.get(&(c.id, i)) {
                o.deadlines.insert(t.saturating_add(p.retention.kept_after()));
            }
        }
    }
    o.deadlines.retain(|&t| t > now && t != FOREVER);

    // Forbidden values: any value of a value-less delta still held.
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            // a waiting body is stripped of others' values only when its commit applies
            if o.fates.get(&(c.id, i)) == Some(&Fate::Keep(KeepWhy::Pending)) {
                continue;
            }
            for w in writes(p).into_iter().flatten() {
                for (own, v) in w.values() {
                    if let Some(v) = v {
                        if o.valueless.contains(&(own, p.thing, p.aspect)) {
                            o.forbidden.insert(((c.id, i), (own, p.thing, p.aspect), w.id(), v));
                        }
                    }
                }
            }
        }
    }
    o
}

/// The wall ms before which a body is must-hold at every node: its absolute keep-at-least T,
/// raised to a purge request's floor `wall(ts) + ROLE_KEEP` for a commit carrying one
/// (spec/commits.md §5 Purge). The relative bound counts from the held set (`fate`).
pub fn kept_until(c: &Commit, p: &Part) -> u64 {
    let floor = if c.purge.is_empty() { 0 } else { wall(c.ts).saturating_add(ROLE_KEEP) };
    p.retention.kept_until().max(floor)
}

/// Whether a signal body is before its keep bound: its absolute T (or a purge request's floor), or
/// D after its own write (spec/commits.md §5 Signals).
pub fn signal_kept(c: &Commit, p: &Part, now: u64) -> bool {
    let after = p.retention.kept_after();
    now < kept_until(c, p) || (after > 0 && now < wall(c.ts).saturating_add(after))
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
    let copy = writes(p).is_some_and(|ws| ws.iter().any(|w| w.values().iter().any(|&(own, v)| v.is_some() && vl(own, p.thing, p.aspect))));
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
    // goes, whole or as an expired or purged leftover (spec/commits.md §5 Signals)
    if p.aspect.signal && !signal_kept(c, p, now) {
        return (Fate::MustDrop(DropWhy::PastBound), false);
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
    let mut ws = writes(p).cloned().unwrap_or_default();
    for w in &mut ws {
        w.strip(|x| vl(x, p.thing, p.aspect));
    }
    let keep = |why| if copy { Fate::Leftover(LeftoverWhy::Copy) } else { Fate::Keep(why) };
    let r = p.retention;
    if now < kept_until(c, p) {
        return (keep(KeepWhy::Until), false);
    }
    // Covered by a valid snapshot whose commit holds the right over the body (one purging on
    // replace only if the body keeps no history or has no live write); an expiring delta only
    // once no value of it lives, by the join (a snapshot carries its values value-less,
    // spec/crdt.md §8); a snapshot body only by one stamped later, or at the same `ts` by
    // one with a lower commit ID (covered-equal, spec/sync.md §7). Under purge-on-replace the drop
    // is forced everywhere, and a writer holding the right owes the cover once the body is
    // replaced.
    let none = r.history == History::PurgeOnReplace;
    // a purge-on-replace snapshot cannot keep the history of a write it carries: it covers no
    // body that keeps history while that body has a live write
    let live_write = o.states.get(&(p.thing, p.aspect)).is_some_and(|st| ws.iter().any(|w| st.iter().any(|x| x.id() == w.id())));
    let covered = (r.by != PurgeBy::Nobody)
        .then(|| {
            live.iter().find_map(|s| {
                if s.kind != CommitKind::Snapshot || s.id == c.id || !o.applied.contains(&s.id) || (c.kind == CommitKind::Snapshot && (c.ts, s.id) > (s.ts, c.id)) {
                    return None;
                }
                s.parts.iter().enumerate().find_map(|(j, q)| {
                    let sw = writes(q)?;
                    let ok = q.thing == p.thing
                        && q.aspect == p.aspect
                        && o.valid.get(&(s.id, j)) == Some(&true)
                        && !never_received(s, q)
                        && !(q.retention.history == History::PurgeOnReplace && r.keeps() && live_write)
                        && tl.right(s.author, s.actor, s.key(), s.id, r.by, c.actor, p.thing)
                        && crdt::covers(sw, &ws, p.aspect.kind);
                    ok.then_some(s.id)
                })
            })
        })
        .flatten();
    let right = tl.right(me, me, (u64::MAX, me, u32::MAX), u32::MAX, r.by, c.actor, p.thing);
    // the relative keep-at-least, at every node alike: no drop before D after the earliest valid
    // replacing write the node holds (a body nothing held supersedes is past it)
    let within_d = r.kept_after() > 0 && o.replaced_at.get(&pr).copied().flatten().is_some_and(|t| now < t.saturating_add(r.kept_after()));
    match covered {
        Some(by) if none => (Fate::MustDrop(DropWhy::Covered { by }), false),
        Some(_) if within_d => (keep(KeepWhy::Until), false),
        Some(by) => (Fate::MayDrop(DropWhy::Covered { by }), false),
        None => {
            let owes = none && o.replaced.contains(&pr) && right;
            (keep(KeepWhy::Plain), owes)
        }
    }
}

/// The retention of a compaction snapshot carrying `ws` live on one aspect (spec/commits.md §5
/// Fixed retention): `writer`, purge-on-replace when any carried write's own delta on that aspect
/// is (its content must go once replaced, the snapshot's copy with it), else kept for the longest
/// D after replaced among them (no T), else convenient.
pub fn snapshot_retention(commits: &[Commit], thing: ThingId, aspect: Aspect, ws: &[Write]) -> Retention {
    let own: Vec<History> = ws
        .iter()
        .flat_map(|w| commits.iter().filter(|c| c.id == w.origin()).flat_map(|c| c.parts.iter()).filter(|p| p.thing == thing && p.aspect == aspect).map(|p| p.retention.history))
        .collect();
    let mut after = 0;
    for h in own {
        match h {
            History::PurgeOnReplace => return Retention::PURGE_ON_REPLACE,
            History::Keep { after: d, .. } => after = after.max(d),
        }
    }
    Retention::WRITER.after(after)
}

/// The covering snapshot `me` writes for an aspect from its whole state (spec/commits.md §2):
/// what a writer owes for an `owed` body (`Outcome::owed`) in the kill's transaction, or writes
/// to compact. A snapshot carries writes of expiring deltas value-less (spec/crdt.md §8).
pub fn cover(h: &Held, o: &Outcome, thing: ThingId, aspect: Aspect, id: CommitId, ts: u64) -> Commit {
    let mut ws = o.states.get(&(thing, aspect)).cloned().unwrap_or_default();
    for w in &mut ws {
        w.strip(|c| h.commits.iter().any(|k| k.id == c && k.expires.is_some()));
    }
    let retention = snapshot_retention(&h.commits, thing, aspect, &ws);
    let part = Part { thing, aspect, retention, body: Body::Held(Delta::Writes(ws)), stripped: Default::default() };
    Commit { id, author: h.me, actor: h.me, ts, expires: None, kind: CommitKind::Snapshot, parts: vec![part], purge: vec![], frontier: None, undoes: None }
}

/// Carries out the fates: strips leftovers, drops bodies that must go, makes the uncovered and
/// the never received missing, and also drops the one `may` names. The result is what the node
/// holds next.
pub fn act(h: &Held, o: &Outcome, may: Option<PartRef>) -> Held {
    let mut n = h.clone();
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
                    if let Body::Held(Delta::Writes(ws)) = &mut p.body {
                        for w in ws {
                            for (own, v) in w.values() {
                                if v.is_some() && o.valueless.contains(&(own, t, a)) {
                                    p.stripped.insert(own);
                                }
                            }
                            w.strip(|x| o.valueless.contains(&(x, t, a)));
                        }
                    }
                }
                Fate::MustDrop(DropWhy::Gone | DropWhy::Invalid | DropWhy::PastBound) | Fate::NeverReceived => {
                    p.body = Body::Missing;
                    p.stripped.clear();
                }
                Fate::MustDrop(DropWhy::Covered { by }) => p.body = Body::Dropped(by),
                Fate::MayDrop(DropWhy::Covered { by }) if may == Some((c.id, i)) => p.body = Body::Dropped(by),
                _ => {}
            }
        }
    }
    n
}
