//! `evaluate`: the whole judgment of a held set, recomputed from scratch.

use crate::crdt::{self, Read, State};
use crate::roles::{edge_events, namings, need, rosters, Timeline, World};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet};

/// A part: its commit and its index in the header's aspect list.
pub type PartRef = (CommitId, usize);
/// A delta by owner: commit, thing, aspect.
pub type DeltaRef = (CommitId, ThingId, Aspect);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeepWhy {
    /// It or its commit waits (spec/commits.md §4); spec/commits.md §5: kept until it joins.
    Pending,
    /// Role-class: fixed retention; the model drops none (ASSUMPTIONS.md).
    Role,
    /// Before its keep-at-least bound.
    AtLeast,
    /// Nothing lets it go.
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
    /// A snapshot a purge request names (no values of its own).
    PurgedSnapshot,
    /// Covered by a valid snapshot that holds the right (spec/commits.md §5 Between the bounds).
    Covered { by: CommitId },
    /// Past keep at most; `carrier`: it has live writes, which stay in the state.
    AtMost { carrier: bool },
    /// A waiting part past its expiry, or an unjoinable (parked) body expired or purged: it counts
    /// as never received (spec/commits.md §5, spec/versioning.md §2).
    Gone,
}

/// What the node does with a held body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fate {
    Keep(KeepWhy),
    /// Hold it with the values of value-less writes stripped.
    Leftover(LeftoverWhy),
    /// It may drop it now.
    MayDrop(DropWhy),
    /// It must have dropped it by now.
    MustDrop(DropWhy),
    /// Its own writes are held value-less with no reason left (a purge that fell): it counts as
    /// never received and is fetched again (spec/permissions.md §7).
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
    /// Per held body dropped at keep at most: its live writes, which stay in the state.
    pub keep_in_state: BTreeMap<PartRef, Vec<Write>>,
    /// First and last death of each held body of an applied commit, wall ms.
    pub deaths: BTreeMap<PartRef, (Option<u64>, Option<u64>)>,
    /// Keep-at-most bound (wall ms) of each held body whose keep bounds decide its fate: the node
    /// drops it no earlier and by then (spec/commits.md §5). From the model's dates (the earliest
    /// superseder, ASSUMPTIONS.md), so an engine's bound may be later, never earlier.
    pub at_most: BTreeMap<PartRef, u64>,
    /// Every clock value after `now` at which the output may change with the held set unchanged
    /// (unparking, expiry, keep bounds): between two of them, and after the last, it is constant.
    pub deadlines: BTreeSet<u64>,
    /// Values held that the node must not hold: `(where, owning delta, write, value)`; where is the
    /// body, or None for the own state.
    pub forbidden: BTreeSet<(Option<PartRef>, DeltaRef, WriteId, Val)>,
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
    // Role timeline over the joined role commits, epoch starts chosen in rounds.
    let tl = Timeline::settle(world, edge_events(view.iter()), rosters(view.iter()));
    Joined { live, applied, waiting, view, tl }
}

/// Per author, the things something leads to from it (spec/commits.md §4 A held part waits): owner
/// links, first admins, and holders named by a joined part of an applied role commit, whether the
/// walk applies it or not.
fn leads(world: &World, live: &[&Commit], view: &[Commit]) -> BTreeMap<NodeId, BTreeSet<ThingId>> {
    let mut adj: BTreeMap<NodeId, BTreeSet<ThingId>> = BTreeMap::new();
    for (&t, o) in &world.owners {
        if let Owner::Actor(a) | Owner::Ownerless { first_admin: a } = o {
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

/// spec/commits.md §4: a held part waits while its thing's record or one up its owner chain is
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
            matches!(c.parts[i].body, Body::Held(_) | Body::Parked | Body::Dropped) && !gone
        })
        .collect();
    held.is_empty() || held.iter().any(|&i| !waiting.contains(&(c.id, i)))
}

/// Does a delta break its governing entry of a `required.0^` setting (spec/commits.md §5).
fn breaks(rules: &[Rule], c: &Commit, p: &Part) -> bool {
    let entry = rules.iter().find(|r| r.prefix == Some(p.aspect.name)).or_else(|| rules.iter().find(|r| r.prefix.is_none()));
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

    // Required retention (spec/commits.md §5): the valid `required.0^` deltas, by key.
    let required: Vec<(Key, ThingId, Vec<Rule>)> = view
        .iter()
        .filter(|c| c.kind == CommitKind::Content)
        .flat_map(|c| c.parts.iter().map(move |p| (c, p)))
        .filter_map(|(c, p)| match &p.body {
            Body::Held(Delta::Required(rules)) if p.aspect == Aspect::REQUIRED => {
                tl.valid_delta(c.author, c.actor, p.thing, Role::Admin, c.key(), c.id).then(|| (c.key(), p.thing, rules.clone()))
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
                CommitKind::Roster => tl.rosters_applied.contains(&c.id),
                _ => {
                    let ok = tl.valid_delta(c.author, c.actor, p.thing, need(p.aspect), c.key(), c.id);
                    let breaks = c.kind == CommitKind::Content
                        && !p.aspect.fixed()
                        && in_force(p.thing, c.key()).is_some_and(|rules| breaks(rules, c, p));
                    ok && !breaks
                }
            };
            o.valid.insert((c.id, i), v);
        }
    }
    let owner_valid: BTreeMap<DeltaRef, bool> = live
        .iter()
        .filter(|c| is_applied(c) && c.kind == CommitKind::Content)
        .flat_map(|c| c.parts.iter().enumerate().map(|(i, p)| ((c.id, p.thing, p.aspect), o.valid[&(c.id, i)])))
        .collect();

    // Purge (spec/commits.md §5, spec/permissions.md §7): an applied request drops the named
    // joined or missing deltas of applied commits and marks waiting parts value-less.
    let mut pending_purged: BTreeSet<PartRef> = BTreeSet::new();
    for q in live.iter().filter(|q| !q.purge.is_empty() && is_applied(q)) {
        for c in &live {
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

    // Value-less deltas: expired, or purged (a snapshot has no values of its own).
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
    let purged_m = o.purged.clone();
    let vl = |c: CommitId, t: ThingId, a: Aspect| vls.contains(&(c, t, a));

    // A body whose own writes are value-less with no reason, or that this node stripped of an
    // owner's values no longer held value-less (a purge that fell), counts as never received
    // (spec/permissions.md §7): its stripped copy joins nothing until it is fetched again.
    let never_received = |c: &Commit, p: &Part| -> bool {
        p.stripped.iter().any(|&own| !vl(own, p.thing, p.aspect))
            || (c.kind == CommitKind::Content
                && !vl(c.id, p.thing, p.aspect)
                && writes(p).is_some_and(|ws| ws.iter().any(|w| w.values().iter().any(|&(own, v)| own == c.id && v.is_none()))))
    };

    // Snapshot validity and contribution.
    let snap_ok = |c: &Commit, i: usize| valid_m.get(&(c.id, i)) == Some(&true) && !purged_m.contains_key(&(c.id, i));

    // Build each aspect's state: valid bodies and own state, invalid deltas un-merged
    // (spec/crdt.md §4.6), value-less deltas stripped (spec/crdt.md §4.7).
    let mut aspects: BTreeSet<(ThingId, Aspect)> = BTreeSet::new();
    for c in &live {
        for p in &c.parts {
            if !c.is_role() && writes(p).is_some() {
                aspects.insert((p.thing, p.aspect));
            }
        }
    }
    for s in &h.own_state {
        aspects.insert((s.thing, s.aspect));
    }
    let mut full: BTreeMap<(ThingId, Aspect), State> = BTreeMap::new();
    let mut canons: BTreeMap<(ThingId, Aspect), State> = BTreeMap::new();
    for &(t, a) in &aspects {
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
        // A snapshot dropped here while valid, held again and judged invalid, takes back what it
        // gave (spec/permissions.md §5.2): the own-state writes it carries, but under dots of
        // deltas dropped here otherwise (their writes are in the state alone).
        let dropped_here = |own: CommitId| {
            h.commits.iter().any(|c| c.id == own && c.parts.iter().any(|q| q.thing == t && q.aspect == a && q.body == Body::Dropped))
        };
        let taken: BTreeSet<WriteId> = view
            .iter()
            .filter(|c| c.kind == CommitKind::Snapshot)
            .flat_map(|c| c.parts.iter().enumerate().map(move |(i, p)| (c, i, p)))
            .filter(|(c, i, p)| p.thing == t && p.aspect == a && h.dropped_valid.contains(&(c.id, *i)) && valid_m.get(&(c.id, *i)) == Some(&false))
            .flat_map(|(_, _, p)| writes(p).into_iter().flatten())
            .filter(|w| !dropped_here(w.owner()))
            .map(|w| w.id())
            .collect();
        own_ws.extend(h.own_state.iter().filter(|s| s.thing == t && s.aspect == a && !taken.contains(&s.write.id())).map(|s| s.write.clone()));
        let invalid = |c: CommitId| owner_valid.get(&(c, t, a)) == Some(&false);
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
            if invalid(w.owner()) {
                match &mut w.op {
                    // un-merged seq creations stay as content-less hidden anchors
                    Op::Insert { ch, .. } => *ch = None,
                    Op::Anchor => {}
                    _ => continue,
                }
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

    // Deaths per held body (spec/crdt.md §4.8, spec/commits.md §5 Bodies and deaths).
    let falls: BTreeMap<(ThingId, Aspect), u64> = {
        let mut m: BTreeMap<(ThingId, Aspect), u64> = BTreeMap::new();
        for c in view.iter().filter(|c| !c.is_role()) {
            for (i, p) in c.parts.iter().enumerate() {
                if valid_m.get(&(c.id, i)) == Some(&false) {
                    let f = tl.fall(c.author, p.thing, need(p.aspect), wall(c.ts));
                    let e = m.entry((p.thing, p.aspect)).or_insert(f);
                    *e = (*e).max(f);
                }
            }
        }
        m
    };
    for c in view.iter().filter(|c| !c.is_role()) {
        for (i, p) in c.parts.iter().enumerate() {
            let Some(ws) = writes(p) else { continue };
            let key = (p.thing, p.aspect);
            let (Some(s), Some(cs)) = (full.get(&key), canons.get(&key)) else { continue };
            let valid = valid_m.get(&(c.id, i)) == Some(&true);
            let mut ds: Vec<u64> = Vec::new();
            let mut live_ws: Vec<Write> = Vec::new();
            for w in ws.iter().filter(|w| w.fits(p.aspect.kind)) {
                let d = if valid && s.contains_key(&w.id()) {
                    // an expiry dates no death (spec/commits.md §5): the body is then a leftover
                    s.values().filter(|x| crdt::supersedes(x, w)).map(|x| wall(x.stamp.ts)).min()
                } else if p.retention.most_zero {
                    // a write invalid here or un-merged with nothing superseding it dies at its fall
                    let own = wall(w.stamp.ts);
                    if !valid {
                        Some(tl.fall(c.author, p.thing, need(p.aspect), wall(c.ts)).max(own))
                    } else {
                        Some(falls.get(&key).copied().unwrap_or(own).max(own))
                    }
                } else {
                    None
                };
                ds.extend(d);
                // an invalid delta's seq creations stay in the state as hidden anchors: live too
                if crdt::holds(cs, w) {
                    let cw = cs.get(&w.id()).cloned().or_else(|| {
                        cs.values().find(|x| matches!(x.op, Op::Insert { .. } | Op::Anchor) && x.stamp.dot == w.stamp.dot).cloned()
                    });
                    live_ws.extend(cw);
                }
            }
            o.deaths.insert((c.id, i), (ds.iter().min().copied(), ds.iter().max().copied()));
            live_ws.sort();
            live_ws.dedup();
            if !live_ws.is_empty() {
                o.keep_in_state.insert((c.id, i), live_ws);
            }
        }
    }

    // Fates.
    let mut fates = BTreeMap::new();
    for c in by_id.values() {
        for (i, p) in c.parts.iter().enumerate() {
            if matches!(p.body, Body::Held(_) | Body::Parked) {
                fates.insert((c.id, i), fate(c, i, p, &o, &live, &tl, h.me, &pending_purged, &waiting, now, &never_received, &vl));
            }
        }
    }
    o.fates = fates;

    // Timing: each body's keep-at-most bound where keep bounds decide its fate, and every clock
    // value past `now` at which the output may change (drift, expiry, keep bounds).
    for c in &h.commits {
        if o.parked.contains(&c.id) {
            o.deadlines.insert(wall(c.ts) - MAX_DRIFT);
        }
        o.deadlines.extend(c.expires);
    }
    for (&pr, &d) in &o.deaths {
        let p = &by_id[&pr.0].parts[pr.1];
        let (at_most, least) = bounds(p, Some(d), o.keep_in_state.contains_key(&pr));
        o.deadlines.extend(at_most.into_iter().chain(least).chain(least.map(|b| b.saturating_add(MAX_DRIFT))));
        let bounded = matches!(
            o.fates.get(&pr),
            Some(Fate::Keep(KeepWhy::Plain | KeepWhy::AtLeast) | Fate::Leftover(LeftoverWhy::Copy) | Fate::MayDrop(_) | Fate::MustDrop(DropWhy::AtMost { .. }))
        );
        if let (true, Some(b)) = (bounded, at_most) {
            o.at_most.insert(pr, b);
        }
    }
    o.deadlines.retain(|&t| t > now);
    // Only bodies dropped at keep at most leave writes in the state.
    o.keep_in_state.retain(|k, _| matches!(o.fates.get(k), Some(Fate::MustDrop(DropWhy::AtMost { .. }))));

    // Forbidden values: any value of a value-less delta still held.
    let seen = |at: Option<PartRef>, t: ThingId, a: Aspect, w: &Write, o: &mut Outcome| {
        for (own, v) in w.values() {
            if let Some(v) = v {
                if o.valueless.contains(&(own, t, a)) {
                    o.forbidden.insert((at, (own, t, a), w.id(), v));
                }
            }
        }
    };
    for c in &h.commits {
        for (i, p) in c.parts.iter().enumerate() {
            // a waiting body is stripped of others' values only when its commit applies
            if o.fates.get(&(c.id, i)) == Some(&Fate::Keep(KeepWhy::Pending)) {
                continue;
            }
            for w in writes(p).into_iter().flatten() {
                seen(Some((c.id, i)), p.thing, p.aspect, w, &mut o);
            }
        }
    }
    for s in &h.own_state {
        seen(None, s.thing, s.aspect, &s.write, &mut o);
    }
    o
}

/// A joined body's keep-at-most and keep-at-least bounds, wall ms (spec/commits.md §5 Keep bounds),
/// from its first and last deaths and whether it has a live write. Keep at most: T, or the first
/// death (plus `AT_MOST_GRACE` while it has a live write), the earlier. Keep at least: T and the
/// last death plus D, the later; a body with no dead write is past a relative bound.
fn bounds(p: &Part, deaths: Option<(Option<u64>, Option<u64>)>, live_writes: bool) -> (Option<u64>, Option<u64>) {
    let r = p.retention;
    let (first, last) = deaths.unwrap_or((None, None));
    let rel = if r.most_zero { first.map(|d| d + if live_writes { AT_MOST_GRACE } else { 0 }) } else { None };
    let at_most = [r.most_abs, rel].into_iter().flatten().min();
    let least = [r.least_abs, r.least_rel.and_then(|d| last.map(|l| l.saturating_add(d)))].into_iter().flatten().max();
    (at_most, least)
}

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
) -> Fate {
    let pr = (c.id, i);
    if c.is_role() {
        return Fate::Keep(KeepWhy::Role);
    }
    let waits = !o.applied.contains(&c.id) || waiting.contains(&pr);
    // a waiting part past its expiry goes (spec/commits.md §5); an unjoinable body cannot be
    // stripped, so a purge or expiry drops it whole (spec/versioning.md §2)
    if (waits && expired(c, now)) || (p.body == Body::Parked && (expired(c, now) || o.purged.contains_key(&pr) || pending_purged.contains(&pr))) {
        return Fate::MustDrop(DropWhy::Gone);
    }
    let copy = writes(p).is_some_and(|ws| ws.iter().any(|w| w.values().iter().any(|&(own, v)| v.is_some() && vl(own, p.thing, p.aspect))));
    if waits || p.body == Body::Parked {
        if pending_purged.contains(&pr) && c.kind != CommitKind::Snapshot {
            return Fate::Leftover(LeftoverWhy::PendingPurged);
        }
        // a waiting body keeps its body, copies of value-less values included, until its commit
        // applies (spec/commits.md §5, spec/crdt.md §4.7 Copies)
        return Fate::Keep(KeepWhy::Pending);
    }
    if expired(c, now) {
        return Fate::Leftover(LeftoverWhy::Expired);
    }
    if o.purged.contains_key(&pr) {
        return if c.kind == CommitKind::Snapshot {
            Fate::MustDrop(DropWhy::PurgedSnapshot)
        } else {
            Fate::Leftover(LeftoverWhy::Purged)
        };
    }
    if never_received(c, p) {
        return Fate::NeverReceived;
    }
    // A body carrying a copy of a value held value-less is held as its leftover, and is a body
    // like a whole one for keep bounds and covering (spec/commits.md §5 Dropping a body).
    let mut ws = writes(p).cloned().unwrap_or_default();
    for w in &mut ws {
        w.strip(|x| vl(x, p.thing, p.aspect));
    }
    let keep = |why| if copy { Fate::Leftover(LeftoverWhy::Copy) } else { Fate::Keep(why) };
    let r = p.retention;
    let (at_most, least) = bounds(p, o.deaths.get(&pr).copied(), o.keep_in_state.contains_key(&pr));
    if at_most.is_some_and(|b| now >= b) {
        return Fate::MustDrop(DropWhy::AtMost { carrier: o.keep_in_state.contains_key(&pr) });
    }
    if least.is_some_and(|b| now < b) {
        return keep(KeepWhy::AtLeast);
    }
    // Covered by a valid snapshot holding the right, me holding it too, keep at least MAX_DRIFT past.
    let drift_past = least.map_or(true, |b| now >= b.saturating_add(MAX_DRIFT));
    if c.expires.is_none() && drift_past && r.by != PurgeBy::Nobody {
        for s in live {
            if s.kind != CommitKind::Snapshot || s.id == c.id || !o.applied.contains(&s.id) {
                continue;
            }
            if c.kind == CommitKind::Snapshot && c.ts > s.ts {
                continue;
            }
            for (j, q) in s.parts.iter().enumerate() {
                let Some(sw) = writes(q) else { continue };
                if q.thing != p.thing || q.aspect != p.aspect || q.retention.carrier_only() {
                    continue;
                }
                if o.valid.get(&(s.id, j)) != Some(&true) || o.purged.contains_key(&(s.id, j)) || never_received(s, q) {
                    continue;
                }
                if !tl.right(s.author, s.actor, s.key(), s.id, r.by, c.actor, p.thing) || !tl.right(me, me, (u64::MAX, me, u32::MAX), u32::MAX, r.by, c.actor, p.thing) {
                    continue;
                }
                if crdt::covers(sw, &ws, p.aspect.kind) {
                    return Fate::MayDrop(DropWhy::Covered { by: s.id });
                }
            }
        }
    }
    keep(KeepWhy::Plain)
}

/// Carries out the fates: strips leftovers, drops bodies that must go (their live writes kept in
/// the state), and also the one `may` names. The result is what the node holds next.
pub fn act(h: &Held, o: &Outcome, may: Option<PartRef>) -> Held {
    let mut n = h.clone();
    let mut keep: Vec<StateWrite> = Vec::new();
    let mut gave: Vec<PartRef> = Vec::new();
    for c in &mut n.commits {
        for (i, p) in c.parts.iter_mut().enumerate() {
            let Some(&f) = o.fates.get(&(c.id, i)) else { continue };
            let (t, a) = (p.thing, p.aspect);
            let drop_it = match f {
                Fate::Leftover(_) => {
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
                    false
                }
                Fate::MustDrop(DropWhy::Gone) => {
                    p.body = Body::Missing;
                    p.stripped.clear();
                    false
                }
                Fate::MustDrop(_) => true,
                Fate::MayDrop(_) => may == Some((c.id, i)),
                Fate::NeverReceived => {
                    p.body = Body::Missing;
                    p.stripped.clear();
                    false
                }
                Fate::Keep(_) => false,
            };
            if drop_it {
                if c.kind == CommitKind::Snapshot && o.valid.get(&(c.id, i)) == Some(&true) {
                    gave.push((c.id, i));
                }
                p.body = Body::Dropped;
                for w in o.keep_in_state.get(&(c.id, i)).into_iter().flatten() {
                    keep.push(StateWrite { thing: t, aspect: a, write: w.clone() });
                }
            }
        }
    }
    n.own_state.extend(keep);
    n.dropped_valid.extend(gave);
    let mut st: BTreeMap<(ThingId, Aspect, WriteId), StateWrite> = BTreeMap::new();
    for mut s in std::mem::take(&mut n.own_state) {
        s.write.strip(|x| o.valueless.contains(&(x, s.thing, s.aspect)));
        st.entry((s.thing, s.aspect, s.write.id())).and_modify(|x| x.write.join_copy(&s.write)).or_insert(s);
    }
    n.own_state = st.into_values().collect();
    n
}
