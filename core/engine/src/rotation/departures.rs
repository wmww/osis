//! Departures from an actor (spec/permissions.md §3, spec/crypto.md §4): the ones this node
//! knows of, read from the role timeline (the points at which a holder's grant for keys was
//! lowered, by an edge write or an audit drop, whose holder holds less now) and from the
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
            list.extend(l.things.iter().map(|t| Name { thing: *t, key: key_of(&l.point) }));
        }
    }
    osis_keys::Names { list, departs }
}

/// A point of `a`'s timeline at which some holder's grant on `a` for keys was lowered: by an
/// applied edge write on `a` (a removal, demotion, self-removal or finalize), or by a demotion
/// elsewhere whose audit dropped an edge write on `a` that had raised a holder (a box written
/// on that write's word is no longer the timeline's; a dropped lowering write raised nobody
/// and lowers nobody by going).
struct Lowering {
    point: osis_perm::Point,
    /// The holders lowered there, each with the roles it left (from, up to).
    holders: Vec<(Tid, Role, Role)>,
    /// The things it is named on: `a` for an edge write on `a`, the targets of its edge writes
    /// for a drop.
    things: BTreeSet<Tid>,
}

/// At one point: the holders an edge write on `a` touches, and the holders dropped raising
/// writes had raised, each with the roles it left.
type Touched = (BTreeSet<Tid>, Vec<(Tid, Role, Role)>);

/// The lowerings on `a` this node holds (spec/crypto.md §4, Names): at each point where an
/// applied edge write on `a` changes `a`'s edges, the holders holding less for keys just after
/// it than just before (`a`'s edges are constant between such points); at each demotion whose
/// audit dropped an edge write on `a`, the holders a dropped write had raised (its value above
/// the holder's grant for keys just before its own point), from read up to that value. Only
/// commits this node holds: names are met by holding them.
fn lowerings(core: &Core, tl: &Timeline, a: &Tid) -> Vec<Lowering> {
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    // per point: the holders an edge write on `a` touches there, and the holders dropped
    // raising writes had raised, with the roles each left
    let mut points: BTreeMap<osis_perm::Point, Touched> = BTreeMap::new();
    for (mc, op) in edge_writes(tl, a) {
        points.entry(mc.point()).or_default().0.insert(op.holder);
    }
    for (w, p) in tl.dropped() {
        let WriteId(c, i) = w;
        let Some(mc) = tl.role_commit(c) else { continue };
        let Some(op) = mc.ops.get(*i as usize).filter(|op| op.target == *a) else { continue };
        let Some(put) = key_role(op.edge.as_ref()) else { continue };
        if key_role(tl.edges_at(Some(mc.point())).get(&op.holder, a)).is_none_or(|had| had < put) {
            points.entry(*p).or_default().1.push((op.holder, Role::Read, put));
        }
    }
    let pts: Vec<osis_perm::Point> = points.keys().copied().collect();
    let mut out = Vec::new();
    for (i, p) in pts.iter().enumerate() {
        let Some((written, raised)) = points.get(p).filter(|_| held(&p.commit)) else { continue };
        let before = tl.edges_at(Some(*p));
        let after = tl.edges_at(pts.get(i + 1).copied());
        let mut holders: Vec<(Tid, Role, Role)> = written
            .iter()
            .filter_map(|h| Departure::of_change(*h, key_role(before.get(h, a)), key_role(after.get(h, a))).map(|d| (*h, d.from, d.upto)))
            .collect();
        let mut things = BTreeSet::new();
        if !holders.is_empty() {
            things.insert(*a);
        }
        if !raised.is_empty() {
            holders.extend(raised.iter().copied());
            things.extend(drop_things(tl, p, a));
        }
        if !holders.is_empty() {
            out.push(Lowering { point: *p, holders, things });
        }
    }
    out
}

/// The things a demotion at `p` that dropped an edge write on `a` is named on: the targets of
/// its edge writes, else `a`.
fn drop_things(tl: &Timeline, p: &osis_perm::Point, a: &Tid) -> BTreeSet<Tid> {
    tl.role_commit(&p.commit).map(|mc| mc.ops.iter().map(|op| op.target).collect()).unwrap_or_else(|| BTreeSet::from([*a]))
}

/// The departure events on `a` (spec/crypto.md §4, Attributes): each lowering (`lowerings`)
/// per holder it lowered, with the roles it left and its name (on the greatest thing the
/// lowering is named on, so the choice never depends on order).
fn events(core: &Core, tl: &Timeline, a: &Tid) -> Vec<(Tid, Role, Role, Name)> {
    let mut out = Vec::new();
    for l in lowerings(core, tl, a) {
        let Some(thing) = l.things.iter().next_back().copied() else { continue };
        let name = Name { thing, key: key_of(&l.point) };
        out.extend(l.holders.iter().map(|(h, from, upto)| (*h, *from, *upto, name)));
    }
    out
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
        if at.map(|n| (n.key, n.thing)) > x.2.map(|n| (n.key, n.thing)) {
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
    let own = core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local);
    (own && departure_of(tl, a, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, a, &op.holder, mc.ts)).then_some(mc.id)
}
