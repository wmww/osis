//! Departures from an actor (spec/permissions.md §3, spec/crypto.md §4): the ones this node
//! knows of, read from the role timeline (the points at which a holder's grant for keys was
//! lowered, by an edge write or a raise applying nothing here, whose holder holds less now) and from the
//! `secrets.0` state (box holders at a current epoch that hold less than that role now), and
//! the makers of current epochs that hold less than that role now by any path, each attributed
//! to the name a rotation knowing it writes (`events`); the names rotations write (`names`). A
//! departure from a holder actor of `a` is none of `a`'s (spec/crypto.md §4, Holder actors), but
//! a maker whose role ran through one holds the epoch it made: its lowering departs `a`.
//! Departures are recomputed on demand (O(edge history)) and cached per actor (`departures`),
//! never stored. Keys read no clock: an edge counts by its role with its `until` disregarded
//! (`key_role`), so an edge past its `until` departs only by its removal (a finalize,
//! spec/permissions.md §2).

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{now_ts, secrets_in};
use osis_base::{Role, Tid};
use osis_keys::{Departure, Name};
use osis_perm::{At, EdgeOp, RoleCommit, Timeline, WriteId};
use std::collections::{BTreeMap, BTreeSet};

/// The departure of a holder now holding `cur` from a role above it: from the role just above.
fn above_role(cur: Option<Role>) -> Option<Role> {
    match cur {
        None => Some(Role::Read),
        Some(Role::Read) => Some(Role::Write),
        Some(Role::Write) => Some(Role::Admin),
        Some(Role::Admin) => None,
    }
}

/// The applied writes on edges into `t` in its timeline `tl`, each with its commit.
fn edge_writes<'t>(tl: &'t Timeline, t: &'t Tid) -> impl Iterator<Item = (&'t RoleCommit, &'t EdgeOp)> + 't {
    tl.applied_on(t)
}

/// The role an edge value gives for keys (spec/crypto.md §4): its role, its `until`
/// disregarded; none for a removal's value saying retain (`until` 0, spec/permissions.md §2).
pub(crate) fn key_role(e: Option<&osis_perm::Edge>) -> Option<Role> {
    e.filter(|e| !e.says_retain()).map(|e| e.role)
}

/// The departure edge write `op` of `mc` on `t` makes, if it lowers the holder's edge for keys
/// (`key_role`).
fn departure_of(tl: &Timeline, t: &Tid, mc: &RoleCommit, op: &EdgeOp) -> Option<Departure> {
    let old = key_role(tl.edges_at(Some(mc.point())).get(&op.holder, t));
    Departure::of_change(op.holder, old, key_role(op.edge.as_ref()))
}

/// The key (spec/permissions.md §5.1) of point `p`.
fn key_of(p: &osis_perm::Point) -> osis_keys::Key {
    osis_keys::Key { ts: p.ts.to_u64(), node: p.node, commit: p.commit }
}

/// The names a rotation of `a` writes (spec/crypto.md §4), from this node's own timeline of `a`:
/// every commit at whose point a holder's grant on `a` for keys was lowered (`lowerings`), on
/// every thing it is named on. They are what an epoch covers (`osis_keys::covers`): every
/// departure from `a` this node knows is attributed to one of them (`events`), so its own epochs
/// cover what it knows (else a rotator could never cover what it knows: a livelock). `departs`:
/// the rotation commit itself, when it departs a holder of `a` (it cannot name its own ID).
pub(crate) fn names(core: &Core, a: &Tid, departs: Option<osis_keys::Own>) -> osis_keys::Names {
    let mut list = BTreeSet::new();
    if let Some(tl) = core.timelines.get(a) {
        for l in lowerings(core, tl, a) {
            list.extend(l.names);
        }
    }
    osis_keys::Names { list, departs }
}

/// A point of `a`'s timeline at which some holder's grant on `a` for keys was lowered: by an
/// applied edge write on `a` (a removal, demotion, self-removal or finalize), or by a raise
/// that applies nothing here, at the point it stops applying: a demotion elsewhere whose audit
/// dropped an edge write on `a` that had raised a holder, or a held edge write on `a` raising
/// one that never applied (invalid at its point), by an author holding write on `a` there (a box
/// written on that write's word is no longer the timeline's; a dropped lowering write raised
/// nobody and lowers nobody by going).
struct Lowering {
    /// The holders lowered there, each with the roles it left (from, up to) and the name its
    /// departure is attributed to.
    holders: Vec<(Tid, Role, Role, Name)>,
    /// What a rotation names of it: on `a` for an applied edge write on `a`, on the targets of
    /// its edge writes for a drop, on `a` with the holder it raised for a raise that never
    /// applied (a rotator that applied that raise, as a lowering or not, never names that).
    names: BTreeSet<Name>,
}

/// At one point: the holders an applied edge write on `a` touches, and the holders raises
/// applying nothing had raised, each with the roles it left: dropped ones (at the demotion),
/// and the point's own invalid ones.
#[derive(Default)]
struct Touched {
    written: BTreeSet<Tid>,
    dropped: Vec<(Tid, Role, Role)>,
    invalid: Vec<(Tid, Role, Role)>,
}

/// The lowerings on `a` this node holds (spec/crypto.md §4, Names): at each point where an
/// applied edge write on `a` changes `a`'s edges, the holders holding less for keys just after
/// it than just before (`a`'s edges are constant between such points); for each raise applying
/// nothing here (its value above the holder's grant for keys just before its own point), the
/// holder it raised, from read up to that value: at the demotion whose audit dropped it, or, for
/// a held resolved write that never applied, at its own point when its author held write on
/// `a` there (`invalid_raises`). Only commits this node holds: names are met by holding them.
fn lowerings(core: &Core, tl: &Timeline, a: &Tid) -> Vec<Lowering> {
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    let raised = |mc: &RoleCommit, op: &EdgeOp| key_role(op.edge.as_ref()).filter(|put| key_role(tl.edges_at(Some(mc.point())).get(&op.holder, a)).is_none_or(|had| had < *put));
    let mut points: BTreeMap<osis_perm::Point, Touched> = BTreeMap::new();
    for (mc, op) in edge_writes(tl, a) {
        points.entry(mc.point()).or_default().written.insert(op.holder);
    }
    for (w, p) in tl.dropped() {
        let WriteId(c, i) = w;
        let Some(mc) = tl.role_commit(c) else { continue };
        let Some(op) = mc.ops.get(*i as usize).filter(|op| op.target == *a) else { continue };
        if let Some(put) = raised(mc, op) {
            points.entry(*p).or_default().dropped.push((op.holder, Role::Read, put));
        }
    }
    for (mc, op) in invalid_raises(core, tl, a) {
        if let Some(put) = raised(mc, op) {
            points.entry(mc.point()).or_default().invalid.push((op.holder, Role::Read, put));
        }
    }
    let pts: Vec<osis_perm::Point> = points.keys().copied().collect();
    let mut out = Vec::new();
    for (i, p) in pts.iter().enumerate() {
        let Some(t) = points.get(p).filter(|_| held(&p.commit)) else { continue };
        let key = key_of(p);
        let before = tl.edges_at(Some(*p));
        let after = tl.edges_at(pts.get(i + 1).copied());
        let lowered: Vec<(Tid, Role, Role)> = t
            .written
            .iter()
            .filter_map(|h| Departure::of_change(*h, key_role(before.get(h, a)), key_role(after.get(h, a))).map(|d| (*h, d.from, d.upto)))
            .collect();
        // an applied lowering and a drop at one point are one commit, its departures attributed
        // to the greatest thing it is named on, so the choice never depends on order
        let mut things = BTreeSet::new();
        if !lowered.is_empty() {
            things.insert(*a);
        }
        if !t.dropped.is_empty() {
            things.extend(drop_things(tl, p, a));
        }
        let mut names: BTreeSet<Name> = things.iter().map(|x| Name::of(*x, key)).collect();
        let mut holders = Vec::new();
        if let Some(thing) = things.iter().next_back() {
            holders.extend(lowered.iter().chain(&t.dropped).map(|(h, from, upto)| (*h, *from, *upto, Name::of(*thing, key))));
        }
        for (h, from, upto) in &t.invalid {
            let name = Name { thing: *a, key, raised: Some(*h) };
            names.insert(name);
            holders.push((*h, *from, *upto, name));
        }
        if !holders.is_empty() {
            out.push(Lowering { holders, names });
        }
    }
    out
}

/// The held edge writes on `a` that never applied here (invalid at their point: neither applied
/// nor dropped), their commits resolved (one that is not applies nothing until it is, like one
/// not held), by an author holding write on `a` just before its point (`At::before`, as its
/// authority is judged there). Such a raise's boxes open for the holder it raised wherever its
/// author held the epoch, and nothing on the timeline stands behind them; a rotator that applied
/// it boxed that holder too, whatever befell the author after (a later removal of it keeps it a
/// lowering). An author holding write there could have forced a rotation by that commit anyway,
/// by a valid box to a non-holder; a reader's writes force nothing (spec/requirements.md:
/// malicious readers only waste storage).
fn invalid_raises<'t>(core: &'t Core, tl: &'t Timeline, a: &'t Tid) -> impl Iterator<Item = (&'t RoleCommit, &'t EdgeOp)> + 't {
    tl.held_on(a)
        .filter(|(w, mc, _)| !tl.is_applied(w) && !tl.dropped().contains_key(w) && !core.ix.unresolved.contains(&mc.id))
        .filter(|(_, mc, _)| tl.role(&mc.author, a, At::before(mc.point())) >= Some(Role::Write))
        .map(|(_, mc, op)| (mc, op))
}

/// The things a demotion at `p` that dropped an edge write on `a` is named on: the targets of
/// its edge writes, else `a`.
fn drop_things(tl: &Timeline, p: &osis_perm::Point, a: &Tid) -> BTreeSet<Tid> {
    tl.role_commit(&p.commit).map(|mc| mc.ops.iter().map(|op| op.target).collect()).unwrap_or_else(|| BTreeSet::from([*a]))
}

/// The departure events on `a` (spec/crypto.md §4, Attributes): each lowering (`lowerings`)
/// per holder it lowered, with the roles it left and its name.
fn events(core: &Core, tl: &Timeline, a: &Tid) -> Vec<(Tid, Role, Role, Name)> {
    lowerings(core, tl, a).into_iter().flat_map(|l| l.holders).collect()
}

/// Departures from `a` itself: holders that hold less now (`Core::key_holders`) than a departure event
/// of theirs (`events`) or a box of the `secrets.0` state at a current epoch had them hold, and
/// makers of a current epoch holding less than its role now (`Timeline::role` at `At::KEYS`,
/// through holder actors alike) (spec/crypto.md §4), each concerning the roles above its current
/// one up to the highest it left, and named by its newest event (a box holder or maker with none:
/// by nothing, so no epoch covers it until a rotation supersedes the epoch).
fn direct_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Departure>> {
    let current: BTreeMap<Tid, Role> = tx.core.key_holders(a).into_iter().collect();
    // per holder: the roles it left that it holds less than now, and its newest event
    let mut left: BTreeMap<Tid, (Role, Role, Option<Name>)> = BTreeMap::new();
    let mut note = |m: Tid, cur: Option<Role>, from: Role, upto: Role, at: Option<Name>| {
        let Some(from) = above_role(cur).map(|x| x.max(from)).filter(|f| *f <= upto) else { return };
        if m == *a {
            return;
        }
        let x = left.entry(m).or_insert((from, upto, None));
        x.0 = x.0.min(from);
        x.1 = x.1.max(upto);
        // the newest event by key (spec/permissions.md §5.1)
        if at.map(|n| (n.key, n.thing, n.raised)) > x.2.map(|n| (n.key, n.thing, n.raised)) {
            x.2 = at;
        }
    };
    if let Some(tl) = tx.core.timelines.get(a) {
        for (m, from, upto, name) in events(tx.core, tl, a) {
            note(m, current.get(&m).copied(), from, upto, Some(name));
        }
    }
    if let Some(epochs) = tx.core.epochs(a) {
        // from the `secrets.0` state: a box at a current epoch of a role its holder no longer holds
        let s = secrets_in(tx, a)?;
        for k in s.boxes.keys() {
            if osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e)) {
                note(k.holder, current.get(&k.holder).copied(), Role::Read, k.role, None);
            }
        }
        // the maker of a current epoch holds its secret whatever the boxes say: one holding
        // less than that role now, for keys, by any path (its role may have run through a holder
        // actor, whose departures are none of `a`'s), departed it
        let tl = tx.core.timelines.get(a);
        for r in osis_keys::ROLES {
            for e in epochs.role(r).current() {
                let Some(author) = tx.core.ix.epoch_intro.get(&(*a, r, e)).and_then(|(_, c)| tx.core.ix.commits.get(c)).map(|m| m.view.author) else { continue };
                note(author, tl.and_then(|tl| tl.role(&author, a, At::KEYS)), Role::Read, r, None);
            }
        }
    }
    let tl = tx.core.timelines.get(a);
    Ok(left.into_iter().map(|(m, (from, upto, at))| Departure::holder(m, from).upto(upto).at(at).later(later_writes(tx.core, tl, a, &m, from, at))).collect())
}

/// The names of the held edge writes on `m`'s edge into `a`, applied or not, ordered after its
/// newest lowering `at` that hold it below `from` (spec/crypto.md §4, Attributes): each was made
/// knowing `m` out of those roles. Concurrent removals of one holder (every writer finalizing an
/// ended grant) each lower it where made, but in the merged timeline only the first in order
/// applies; a rotation carrying another (its departs mark) covers the departure alike, else
/// each such rotation is uncovered wherever the first arrives and every rotator rotates again.
/// Nothing held raises `m` back to `from` after `at`: an applied raise would leave `m` holding
/// it or meet a newer lowering, and one applying nothing here is a newer lowering itself
/// (`lowerings`), so a rotator naming one of them boxed `m` at none of those roles on the word
/// of any raise this node holds.
fn later_writes(core: &Core, tl: Option<&Timeline>, a: &Tid, m: &Tid, from: Role, at: Option<Name>) -> Vec<Name> {
    let (Some(tl), Some(at)) = (tl, at) else { return Vec::new() };
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    tl.held_on(a)
        .filter(|(_, mc, op)| op.holder == *m && key_of(&mc.point()) > at.key && key_role(op.edge.as_ref()) < Some(from) && held(&mc.id))
        .map(|(_, mc, _)| Name::of(*a, key_of(&mc.point())))
        .collect()
}

/// Every departure `a`'s epochs must cover: its own (`direct_departures`). A memo
/// (`Core::departures`).
pub(crate) fn departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    crate::engine::memo::Memo::get_in(tx, |tx| &tx.core.departures, a, |tx| Ok(direct_departures(tx, a)?.into_iter().collect()))
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may rotate now: write
/// and above rotates its role and below.
pub fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    core.timelines.get(a).map(|tl| tl.may_rotate(who, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The known departures of `a`, each with the commit that made it when that is this node's
/// own self-removal (`own_leaving`): node-sync's cover check ignores such a departure until the
/// commit is placed (spec/crypto.md §4).
pub fn departures_placing(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Departure, Option<osis_base::CommitId>)>> {
    Ok(departures(tx, a)?.into_iter().map(|d| { let c = own_leaving(tx.core, a, &d); (d, c) }).collect())
}

/// The commit of departure `d` from `a` when it is this node's own self-removal (spec/permissions.md §2): the newest applied write on the
/// holder's edge there lowers it and it was made here or its author is this node, its account
/// or a key actor it holds, whichever node of the account made it: each waits for it to be placed, so a sibling
/// that pulled it from the maker keeps it until a source has it. From stored commits only, so
/// a restart keeps it.
fn own_leaving(core: &Core, a: &Tid, d: &Departure) -> Option<osis_base::CommitId> {
    let tl = core.timelines.get(a)?;
    let (mc, op) = edge_writes(tl, a).filter(|(_, op)| op.holder == d.holder).max_by_key(|(mc, _)| mc.point())?;
    let own = core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local) || mc.author == core.id.tid() || core.account.get() == Some(mc.author) || core.key_actors.contains_key(&mc.author);
    (own && departure_of(tl, a, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, a, &op.holder, mc.ts)).then_some(mc.id)
}
