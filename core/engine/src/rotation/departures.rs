//! Departures from an actor (spec/permissions.md §3, spec/crypto.md §4): the ones this node
//! knows of, read from the role timeline (applied edge writes that lowered an edge, edge writes a
//! demotion's audit dropped, whose holder holds less now) and from the `secrets.0` state (box
//! holders at a current epoch that hold less than that role now), each attributed to the
//! name a rotation knowing it writes (`events`); the names rotations write (`names`). A
//! departure from a holder actor of `a` is none of `a`'s (spec/crypto.md §4, Holder actors).
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

/// The names a rotation of `a` writes (spec/crypto.md §4), from this node's own timeline of `a`
/// (`thing_names`). They are what an epoch covers (`osis_keys::covers`): every departure from
/// `a` this node knows is named (`events`), so its own epochs cover what it knows. `departs`:
/// the rotation commit itself, when it makes a departure from `a` (it cannot name its own ID).
pub(crate) fn names(core: &Core, a: &Tid, departs: Option<osis_keys::Own>) -> osis_keys::Names {
    let mut out = osis_keys::Names { departs, ..osis_keys::Names::default() };
    thing_names(core, a, &mut out.list);
    out
}

/// The things a demotion at `p` that dropped an edge write on `a` is named once per: the targets
/// of its edge writes, else `a`.
fn drop_things(tl: &Timeline, p: &osis_perm::Point, a: &Tid) -> BTreeSet<Tid> {
    tl.role_commit(&p.commit).map(|mc| mc.ops.iter().map(|op| op.target).collect()).unwrap_or_else(|| BTreeSet::from([*a]))
}

/// The departure events on `a` (spec/crypto.md §4), each with its holder, the roles it left
/// (from, up to), and its name: an applied commit lowering the holder's edge (its key); a
/// demotion whose audit dropped an edge write putting the holder's edge (its key, on the first of
/// `drop_things`). Only commits this node holds: names are met by holding them.
fn events(core: &Core, tl: &Timeline, a: &Tid) -> Vec<(Tid, Role, Role, Name)> {
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    let mut out = Vec::new();
    for (mc, op) in edge_writes(tl, a) {
        let p = mc.point();
        if let Some(d) = departure_of(tl, a, mc, op)
            && held(&p.commit)
        {
            out.push((op.holder, d.from, d.upto, Name { thing: *a, key: key_of(&p) }));
        }
    }
    for (w, p) in tl.dropped() {
        let WriteId(c, i) = w;
        let Some(op) = tl.role_commit(c).and_then(|mc| mc.ops.get(*i as usize)).filter(|op| op.target == *a) else { continue };
        let (Some(e), Some(t)) = (op.edge, drop_things(tl, p, a).first().copied()) else { continue };
        if held(&p.commit) {
            out.push((op.holder, Role::Read, e.role, Name { thing: t, key: key_of(p) }));
        }
    }
    out
}

/// The names of the departures from `a` (spec/crypto.md §4): every applied commit with an edge
/// write on `a` lowering an edge (`events`), and every applied commit whose demotion's audit
/// dropped an edge write on `a` (once per thing its edge writes target). A superset of the
/// departures from `a` this node knows of (`events`): a missed kind of departure would be a
/// missed name.
fn thing_names(core: &Core, a: &Tid, out: &mut BTreeSet<Name>) {
    let Some(tl) = core.timelines.get(a) else { return };
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    for (w, p) in tl.dropped() {
        let on_a = tl.role_commit(&w.0).and_then(|mc| mc.ops.get(w.1 as usize)).is_some_and(|op| op.target == *a);
        if on_a && held(&p.commit) {
            out.extend(drop_things(tl, p, a).into_iter().map(|t| Name { thing: t, key: key_of(p) }));
        }
    }
    out.extend(events(core, tl, a).into_iter().map(|x| x.3));
}

/// Departures from `a` itself: holders that hold less now (`Core::key_holders`) than a departure event
/// of theirs (`events`) or a box of the `secrets.0` state at a current epoch had them hold (spec/crypto.md §4), each
/// concerning the roles above its current one up to the highest it left, and named by its newest
/// event (a box holder with none: by nothing, so no epoch covers it until a rotation supersedes
/// the box). The owner never departs.
fn direct_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Departure>> {
    let owner = tx.core.owner(a);
    let current: BTreeMap<Tid, Role> = tx.core.key_holders(a).into_iter().collect();
    // per holder: the roles it left that it holds less than now, and its newest event
    let mut left: BTreeMap<Tid, (Role, Role, Option<Name>)> = BTreeMap::new();
    let mut note = |m: Tid, from: Role, upto: Role, at: Option<Name>| {
        let cur = current.get(&m).copied();
        let Some(from) = above_role(cur).map(|x| x.max(from)).filter(|f| *f <= upto) else { return };
        if Some(m) == owner || m == *a {
            return;
        }
        let x = left.entry(m).or_insert((from, upto, None));
        x.0 = x.0.min(from);
        x.1 = x.1.max(upto);
        // the newest event by key (spec/permissions.md §5.1), whatever thing names it; one commit
        // named on two things (a lowering on `a` that is also a demotion's audit drop) by the
        // greater thing, so the choice never depends on the order events are noted
        if at.map(|n| (n.key, n.thing)) > x.2.map(|n| (n.key, n.thing)) {
            x.2 = at;
        }
    };
    if let Some(tl) = tx.core.timelines.get(a) {
        for (m, from, upto, name) in events(tx.core, tl, a) {
            note(m, from, upto, Some(name));
        }
    }
    // from the `secrets.0` state: a box at a current epoch of a role its holder no longer holds
    if let Some(epochs) = tx.core.epochs(a) {
        let s = secrets_in(tx, a)?;
        for k in s.boxes.keys() {
            if osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e)) {
                note(k.holder, Role::Read, k.role, None);
            }
        }
    }
    Ok(left.into_iter().map(|(m, (from, upto, at))| Departure::holder(m, from).upto(upto).at(at)).collect())
}

/// Every departure `a`'s epochs must cover: its own (`direct_departures`). Cached per actor
/// (`Core::departures`) until a roster, `secrets.0` or held epochs change.
pub(crate) fn departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    if let Some(d) = tx.core.ix.departures.get(a) {
        return Ok(d.clone());
    }
    let _s = crate::costs::span("departures");
    let out: Vec<Departure> = direct_departures(tx, a)?.into_iter().collect();
    tx.core.ix.departures.insert(*a, out.clone());
    Ok(out)
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
/// holder's edge there lowers it and is a commit made here (signed by this node or a key actor
/// it holds). From stored commits only, so a restart keeps it.
fn own_leaving(core: &Core, a: &Tid, d: &Departure) -> Option<osis_base::CommitId> {
    let tl = core.timelines.get(a)?;
    let (mc, op) = edge_writes(tl, a).filter(|(_, op)| op.holder == d.holder).max_by_key(|(mc, _)| mc.point())?;
    let own = mc.author == core.id.tid() || core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local);
    (own && departure_of(tl, a, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, a, &op.holder, mc.ts)).then_some(mc.id)
}
