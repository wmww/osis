//! Departures (spec/permissions.md §3, spec/crypto.md §4): the ones this node knows of, read
//! from the role timeline (applied edge writes that lowered an edge, edges past their `until`,
//! edge writes a demotion's audit dropped, whose holder holds less now) and from state (box
//! holders at a current epoch that hold less than that role now), recursively through holder
//! and owner actors (departures inside a holder), each attributed to the name a rotation
//! knowing it writes (`events`); the names rotations and grants write (`names`); the covers
//! rule over them (by names: an epoch covers what its rotator named); the box judgement of a
//! holder actor's keyset over the held actors (`held_actors`). Departures are recomputed on
//! demand (O(edge history)) and cached per actor (`departures`), never stored.

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{now_ts, secrets_in};
use osis_base::{Role, Tid, Ts, WallMs};
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, Name, ROLES, uncovered};
use osis_perm::{At, EdgeOp, RoleCommit, Timeline, WriteId};
use osis_schema::core_types::BoxKey;
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
    tl.applied()
        .keys()
        .filter_map(|w| match w {
            WriteId::Op(c, i) => tl.role_commit(c).and_then(|mc| mc.ops.get(*i as usize).map(|op| (&**mc, op))),
            _ => None,
        })
        .filter(move |(_, op)| op.target == *t)
}

/// The departure edge write `op` of `mc` on `t` makes, if it lowers the holder's edge. An edge
/// past its `until` at the write still counts: its departure is the `until`'s.
fn departure_of(tl: &Timeline, t: &Tid, mc: &RoleCommit, op: &EdgeOp) -> Option<Departure> {
    let old = tl.edges_at(Some(mc.point())).get(&op.holder, t).map(|e| e.role);
    let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
    Departure::of_change(op.holder, old, new)
}

/// The key (spec/permissions.md §6) of point `p`.
fn key_of(p: &osis_perm::Point) -> osis_keys::Key {
    osis_keys::Key { ts: p.ts.to_u64(), node: p.node, commit: p.commit }
}

/// The names a rotation of `a` writes (spec/crypto.md §4), from this node's own timelines: those
/// of `a` and of every thing below it (`admin_paths_into`: its current holders, transitively,
/// owners included; `thing_names`); a grant boxing holder actor `a` writes them too (with the
/// keyset it boxes, `keyset_names`). They are what an epoch covers (`osis_keys::covers`): every
/// departure this node knows from those things is named (`events`), so its own epochs cover
/// what it knows. A holder actor's are named because its admins write its keyset: a node
/// lacking an admin's departure from it holds that admin's later keysets valid and would box the
/// actor there. Invariant (with `keyset_names`): where these names are met, every `keys.0` body
/// of a boxed holder actor valid there is by an author the rotator did not see depart (every
/// admin path into the actor runs through things below `a`). `departs`: the rotation commit
/// itself, when it makes a departure from `a` (it cannot name its own ID).
pub(crate) fn names(core: &Core, a: &Tid, departs: Option<osis_keys::Own>) -> osis_keys::Names {
    let mut out = osis_keys::Names { departs, ..osis_keys::Names::default() };
    for v in admin_paths_into(core, a) {
        thing_names(core, &v, &mut out.list);
    }
    out
}

/// `a` and every thing on a path of current holders into it (owners included), transitively,
/// whether or not it has secrets of its own: an owner chain passing a plain thing (derived
/// secrets) still gives its admins admin below it, so `below_of` (holders with secrets of their
/// own) would miss their departures.
fn admin_paths_into(core: &Core, a: &Tid) -> Vec<Tid> {
    let mut out = vec![*a];
    let mut seen = BTreeSet::from([*a]);
    let mut i = 0;
    while let Some(v) = out.get(i).copied() {
        i += 1;
        for (x, _, _) in core.current_holders(&v) {
            if seen.insert(x) {
                out.push(x);
            }
        }
    }
    out
}

/// `a`'s epoch start at this node (a roster snapshot, spec/permissions.md §6), as its point.
fn start_of(core: &Core, tl: &Timeline, a: &Tid) -> Option<osis_perm::Point> {
    tl.epoch_start(a).and_then(|id| core.ix.commits.get(&id).map(|m| osis_perm::Point { ts: m.view.ts, node: m.view.author, commit: id }))
}

/// The things a demotion at `p` that dropped an edge write on `a` is named once per: the targets
/// of its edge writes (any one's epoch start may stand in for it), else `a`.
fn drop_things(tl: &Timeline, p: &osis_perm::Point, a: &Tid) -> BTreeSet<Tid> {
    tl.role_commit(&p.commit).map(|mc| mc.ops.iter().map(|op| op.target).collect()).unwrap_or_else(|| BTreeSet::from([*a]))
}

/// The departure events on `a` (spec/crypto.md §4), each with its holder, the roles it left
/// (from, up to), and its name: an applied commit ordered after `a`'s epoch start lowering the
/// holder's edge (its key); the holder's current edge past its `until` (`Key::expiry`); a
/// demotion ordered after the start whose audit dropped an edge write putting the holder's edge
/// (its key, on the first of `drop_things`). Only commits this node holds: names are met by
/// holding them.
fn events(core: &Core, tl: &Timeline, a: &Tid) -> Vec<(Tid, Role, Role, Name)> {
    let now = now_ts(core);
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    let start = start_of(core, tl, a);
    let after = |p: &osis_perm::Point| start.is_none_or(|s| key_of(p) > key_of(&s));
    let mut out = Vec::new();
    for (mc, op) in edge_writes(tl, a) {
        let p = mc.point();
        if let Some(d) = departure_of(tl, a, mc, op)
            && after(&p)
            && held(&p.commit)
        {
            out.push((op.holder, d.from, d.upto, Name { thing: *a, key: key_of(&p) }));
        }
    }
    for (m, e) in tl.edges_at(None).holders(a) {
        if let Some(u) = e.until.filter(|_| !e.alive_at(Some(now))) {
            let ts = Ts::make(u, 0).map_or(u64::MAX, Ts::to_u64);
            out.push((*m, Role::Read, e.role, Name { thing: *a, key: osis_keys::Key::expiry(ts, *m) }));
        }
    }
    for (w, p) in tl.dropped() {
        let WriteId::Op(c, i) = w else { continue };
        let Some(op) = tl.role_commit(c).and_then(|mc| mc.ops.get(*i as usize)).filter(|op| op.target == *a) else { continue };
        let (Some(e), Some(t)) = (op.edge, drop_things(tl, p, a).first().copied()) else { continue };
        if after(p) && held(&p.commit) {
            out.push((op.holder, Role::Read, e.role, Name { thing: t, key: key_of(p) }));
        }
    }
    out
}

/// The names of the departures from `a` (spec/crypto.md §4): `a`'s epoch start, then every
/// applied commit ordered after it with an edge write on `a` lowering an edge or setting an
/// `until` passed by now, every expiry of a current edge (`events`), and every applied commit
/// ordered after it whose demotion's audit dropped an edge write on `a` (once per thing its edge
/// writes target: that thing's epoch start may stand in for it). A superset of the departures
/// from `a` this node knows of (`events`): a missed kind of departure would be a missed name.
fn thing_names(core: &Core, a: &Tid, out: &mut BTreeSet<Name>) {
    let Some(tl) = core.timelines.get(a) else { return };
    let now = now_ts(core);
    let held = |c: &osis_base::CommitId| core.ix.commits.contains_key(c);
    let start = start_of(core, tl, a);
    let after = |p: &osis_perm::Point| start.is_none_or(|s| key_of(p) > key_of(&s));
    if let Some(s) = start {
        out.insert(Name { thing: *a, key: key_of(&s) });
    }
    for (mc, op) in edge_writes(tl, a) {
        let p = mc.point();
        if op.edge.is_some_and(|e| !e.alive_at(Some(now))) && after(&p) && held(&p.commit) {
            out.insert(Name { thing: *a, key: key_of(&p) });
        }
    }
    for (w, p) in tl.dropped() {
        let on_a = match w {
            WriteId::Op(c, i) => tl.role_commit(c).and_then(|mc| mc.ops.get(*i as usize)).is_some_and(|op| op.target == *a),
            WriteId::Snapshot(_) => false,
        };
        if on_a && after(p) && held(&p.commit) {
            out.extend(drop_things(tl, p, a).into_iter().map(|t| Name { thing: t, key: key_of(p) }));
        }
    }
    out.extend(events(core, tl, a).into_iter().map(|x| x.3));
}

/// Whether this node holds what every grant of holder actor `m` on `a` it holds knew of `m`
/// (spec/crypto.md §4, boxing a holder actor): the names carried by every box to `m` at a current
/// epoch of `a`, and by the boxes to `m` of every applied commit putting `m`'s edge on `a` whose
/// `secrets.0` body it holds (so a rotation that removed the grant's boxes, leaving `m` out,
/// does not drop what they carried), met here; such a commit whose `secrets.0` part on `a` is
/// missing (held only as a projection) counts as not met, a dropped one as held. Names it cannot open (it lacks the boxed epochs'
/// secrets, or they are malformed) count as not met. Invariant: a departure inside `m` the
/// granter knew, and so kept from its box to `m` by `keys.0` validity or the box judgement, is
/// held here before this node boxes `m` while it holds that grant, so the box judgement here
/// keeps it out too; nobody relies on an epoch for a departure inside `m` unless the epoch's
/// own names name it (`osis_keys::covers`).
pub(crate) fn grant_names_held(tx: &mut Tx<'_>, a: &Tid, m: &Tid) -> Result<bool> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(true) };
    let to_m = |w: osis_keys::SecretsWrite| -> Vec<(osis_schema::core_types::BoxKey, osis_schema::core_types::SecretBox)> {
        w.boxes.into_iter().filter(|(k, b)| k.holder == *m && osis_keys::carries_names(b)).collect()
    };
    // each group needs one box whose names open and are met: a box at a current epoch alone, a
    // grant's boxes together (they carry the same names, one per boxed epoch)
    let mut groups: Vec<Vec<_>> = secrets_in(tx, a)?
        .boxes
        .into_iter()
        .filter(|(k, b)| k.holder == *m && osis_keys::carries_names(b) && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e)))
        .map(|x| vec![x])
        .collect();
    let grants: Vec<osis_base::CommitId> = tx.core.timelines.get(a).map(|tl| edge_writes(tl, a).filter(|(_, op)| op.holder == *m && op.edge.is_some()).map(|(mc, _)| mc.id).collect()).unwrap_or_default();
    for c in grants {
        let Some((ai, missing)) = tx.core.ix.commits.get(&c).and_then(|x| x.header.aspects.iter().position(|x| x.tid == *a && x.ak.as_str() == "secrets.0").map(|ai| (ai, x.missing.contains(&ai)))) else { continue };
        // held only as a projection (its `roles.0` part without its boxes): what it carried is
        // unknown here
        if missing {
            return Ok(false);
        }
        for d in crate::apply::held_parts(tx, &c, ai)? {
            if let osis_commit::Decoded::Delta(d) = d {
                groups.push(to_m(crate::apply::keys::secrets_write(&d.fragment)));
            }
        }
    }
    let held = tx.core.names_held(a);
    let met = |(k, b): &(osis_schema::core_types::BoxKey, osis_schema::core_types::SecretBox)| {
        let Ok(e) = osis_keys::aspects::from_schema(&k.epoch) else { return false };
        epochs.role(k.role).reading_secret(&e).and_then(|s| osis_keys::box_names(a, k, b, s)).is_some_and(|n| n.met(&held))
    };
    Ok(groups.iter().all(|g| g.is_empty() || g.iter().any(met)))
}

/// The names a grant boxing holder actor `m` carries in its boxes (spec/crypto.md §4): those of
/// `m` and the things below it (`names`), and the keyset epochs its boxes name.
pub(crate) fn grant_names(core: &Core, boxed: &osis_keys::Recipient, roles: &BTreeSet<Role>) -> osis_keys::Names {
    let mut n = names(core, &boxed.holder, None);
    n.keysets = keyset_names(std::slice::from_ref(boxed), roles);
    n
}

/// The keyset names of a rotation (spec/crypto.md §4): per boxed holder actor and rotated role it
/// holds, the epoch of the actor its box names. A departure inside a holder actor rides in the
/// actor's rotation that made that epoch: a node not holding it would box the actor at an older
/// keyset a departed holder of it opens, and the new epoch's history box would carry this one.
pub(crate) fn keyset_names(boxed: &[osis_keys::Recipient], roles: &BTreeSet<Role>) -> BTreeSet<osis_keys::KeysetName> {
    let mut out = BTreeSet::new();
    for rc in boxed {
        let osis_keys::HolderKeys::Actor { keysets, own } = &rc.keys else { continue };
        for r in roles.iter().filter(|r| **r <= rc.role) {
            let ks = keysets.get(r).map(|x| x.0);
            let named = match own.get(r) {
                Some((es, _)) if osis_keys::symmetric_box(es, ks.as_ref()) => Some(*es),
                _ => ks,
            };
            if let Some(e) = named {
                out.insert(osis_keys::KeysetName { thing: rc.holder, role: *r, epoch: e });
            }
        }
    }
    out
}

/// Each holder's role on `a` at `now`, from `a`'s timeline `tl`.
fn roles_now(tl: &Timeline, a: &Tid, now: Ts) -> BTreeMap<Tid, Role> {
    tl.roster(a, At::now(now)).into_iter().map(|(m, e)| (m, e.role)).collect()
}

/// Departures from `a` itself: holders that hold less now than a departure event of theirs
/// (`events`) or a box at a current epoch had them hold (spec/crypto.md §4), each concerning the
/// roles above its current one up to the highest it left, and named by its newest event (a box
/// holder with none: by `a`'s epoch start, which its snapshot dropped it at; with no start
/// either, by nothing, so no epoch covers it until a rotation supersedes the box). The owner
/// never departs. `horizon`: lowered to the next time the answer may change by the clock alone
/// (an edge's `until`, a write's `ts` ahead of now).
pub(crate) fn direct_departures(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>) -> Result<BTreeSet<Departure>> {
    let now = now_ts(tx.core);
    let mut later = |t: WallMs| lower_horizon(horizon, t, now.wall_ms());
    let owner = tx.core.owner(a);
    let current = tx.core.timelines.get(a).map(|tl| roles_now(tl, a, now)).unwrap_or_default();
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
        // the newest event by key (spec/permissions.md §6), whatever thing names it
        if at.map(|n| n.key) > x.2.map(|n| n.key) {
            x.2 = at;
        }
    };
    let mut start = None;
    if let Some(tl) = tx.core.timelines.get(a) {
        for (mc, _) in edge_writes(tl, a) {
            later(mc.ts.wall_ms());
        }
        // a roster snapshot ahead of the clock changes the roster when its `ts` passes
        for sn in tx.core.ix.held.snapshots_of(a) {
            later(sn.ts.wall_ms());
        }
        for (_, e) in tl.edges_at(None).holders(a) {
            if let Some(u) = e.until {
                later(u);
            }
        }
        for (m, from, upto, name) in events(tx.core, tl, a) {
            note(m, from, upto, Some(name));
        }
        start = start_of(tx.core, tl, a).map(|s| Name { thing: *a, key: key_of(&s) });
    }
    // from state: a box at a current epoch of a role its holder no longer holds
    if let Some(epochs) = tx.core.epochs(a) {
        let secrets = secrets_in(tx, a)?;
        for k in secrets.boxes.keys() {
            if osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e)) {
                note(k.holder, Role::Read, k.role, None);
            }
        }
    }
    Ok(left.into_iter().map(|(m, (from, upto, at))| Departure::holder(m, from).upto(upto).at(at.or(start))).collect())
}

/// Every departure `a`'s epochs must cover: its own, and inside each holder or owner actor
/// with secrets of its own, recursively (spec/crypto.md §4), along every chain that never
/// passes the departed holder; a chain may pass an actor more than once, `a` included (a
/// role cycle). Chains that the covers rule cannot tell apart (same first and second
/// actor, same actor left, holder and role, and the same verdict of the first actor's newest
/// epoch of each role) are one departure, carrying one of them: work is polynomial in the actor
/// graph below `a`, whatever its depth, and finite with cycles. Cached per actor
/// (`Core::departures`) until a roster, `secrets.0`, `keys.0` or held epochs change, or the clock
/// reaches the next time the answer may change.
pub(crate) fn departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    let now = tx.core.now();
    if let Some((d, until)) = tx.core.ix.departures.get(a)
        && until.is_none_or(|u| now < u)
    {
        return Ok(d.clone());
    }
    let mut horizon = None;
    let out: Vec<Departure> = collect(tx, a, &mut horizon, &[])?.into_iter().collect();
    tx.core.ix.departures.insert(*a, (out.clone(), horizon));
    Ok(out)
}

/// A class of departures seen from actor V: the actor after V on the chain, the actor left,
/// the holder, the roles, and whether V's newest epoch of each role keeps it out.
type Class = (Option<Tid>, Tid, Tid, Role, Role, [bool; 3]);

/// Whether `v`'s newest epoch of each role keeps `d` out by its boxes (seen from `v`,
/// `osis_keys::keeps_out`); unheld counts as not. The box judgement of a holder actor's keyset
/// reaches below `v` only through these verdicts.
pub(super) fn verdicts(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> [bool; 3] {
    let (Some(s), Some(e)) = (osis_keys::HeldActors::secrets(held, v), osis_keys::HeldActors::epochs(held, v)) else { return [false; 3] };
    ROLES.map(|r| e.role(r).newest().is_some_and(|k| osis_keys::keeps_out(s, r, &k, d, held)))
}

pub(super) fn class_of(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> Class {
    (d.via.first().copied(), d.via.last().copied().unwrap_or(*v), d.holder, d.from, d.upto, verdicts(held, v, d))
}

/// The departures of `departures`: the walk below `a` (`a` too when it is on a cycle), then
/// `a`'s own departures (`pending` added: ones a commit being made makes) and those inside its
/// holders.
pub(super) fn collect(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>, pending: &[Departure]) -> Result<BTreeSet<Departure>> {
    let held = held_actors(tx)?;
    let (below, parents) = below_of(tx.core, a);
    let mut direct = Vec::with_capacity(below.len() + 1);
    let mut mine = direct_departures(tx, a, horizon)?;
    mine.extend(pending.iter().cloned());
    direct.push((*a, mine.clone()));
    for v in below {
        let d = direct_departures(tx, &v, horizon)?;
        direct.push((v, d));
    }
    let found = walk(&parents, direct, |v, d| class_of(&held, v, d));
    let mut out = mine;
    for (m, ps) in &parents {
        let Some((_, role)) = ps.iter().find(|(p, _)| p == a) else { continue };
        for d in found.get(m).into_iter().flat_map(|f| f.values()) {
            if d.holder != *a {
                out.extend(Departure::through(*m, *role, d));
            }
        }
    }
    Ok(out)
}

/// Lowers `horizon` to `t` when `t` is ahead of `now` and before it.
fn lower_horizon(horizon: &mut Option<WallMs>, t: WallMs, now: WallMs) {
    if t > now && horizon.is_none_or(|h| t < h) {
        *horizon = Some(t);
    }
}

/// Per actor, the actors it is a holder of, with its role there.
pub(super) type Parents = BTreeMap<Tid, Vec<(Tid, Role)>>;

/// The actors below `a` with secrets of its own (holders, transitively; `a` left out), and who
/// each of them and `a` is a holder of among `a` and them, with its role there.
pub(super) fn below_of(core: &Core, a: &Tid) -> (Vec<Tid>, Parents) {
    let mut parents = Parents::new();
    let mut below: Vec<Tid> = Vec::new();
    let mut queue = std::collections::VecDeque::from([*a]);
    let mut seen = BTreeSet::from([*a]);
    while let Some(v) = queue.pop_front() {
        let ms: BTreeMap<Tid, Role> = core.current_holders(&v).into_iter().filter(|x| x.0 != v && core.has_own_secrets(&x.0)).map(|x| (x.0, x.1)).collect();
        for (x, role) in ms {
            parents.entry(x).or_default().push((v, role));
            if seen.insert(x) {
                below.push(x);
                queue.push_back(x);
            }
        }
    }
    (below, parents)
}

/// The fixpoint over the holder graph: each actor keeps one departure per class, starting from
/// the actors' own (`direct`, in walk order); a chain is extended by every actor it is a holder
/// of except the departed holder itself, concerning at most its role there (`Departure::through`). Classes are finite, so this ends on cycles too, and
/// the merge is exact: the class of a chain's extension depends only on the chain's class.
/// Chains share their tails (`osis_keys::Via`), so each kept departure costs one hop.
pub(super) fn walk(parents: &Parents, direct: Vec<(Tid, BTreeSet<Departure>)>, class_of: impl Fn(&Tid, &Departure) -> Class) -> BTreeMap<Tid, BTreeMap<Class, Departure>> {
    let mut found: BTreeMap<Tid, BTreeMap<Class, Departure>> = BTreeMap::new();
    let mut work = std::collections::VecDeque::new();
    let keep = |found: &mut BTreeMap<Tid, BTreeMap<Class, Departure>>, work: &mut std::collections::VecDeque<(Tid, Departure)>, v: Tid, d: Departure| {
        if let std::collections::btree_map::Entry::Vacant(e) = found.entry(v).or_default().entry(class_of(&v, &d)) {
            e.insert(d.clone());
            work.push_back((v, d));
        }
    };
    for (v, ds) in direct {
        for d in ds {
            keep(&mut found, &mut work, v, d);
        }
    }
    while let Some((w, d)) = work.pop_front() {
        for (u, role) in parents.get(&w).into_iter().flatten() {
            if d.holder != *u
                && let Some(x) = Departure::through(w, *role, &d)
            {
                keep(&mut found, &mut work, *u, x);
            }
        }
    }
    found
}

/// What the box judgement of a holder actor's keyset (`osis_keys::keeps_out`) needs of every
/// actor this node holds secrets of; an actor with secrets of its own whose secrets it does not
/// hold is judged by its newest `keys.0` keysets (spec/permissions.md §3, Left out): those
/// epochs, established in this view only, with the `secrets.0` boxes held of it, and a holder
/// that left it presumed boxed there unless the keyset's commit shows otherwise
/// (`presumed_boxes`). Epochs observed without any secret (boxes or keysets seen) are not
/// holding: such an actor is judged by its `keys.0` too, or a newer keyset arriving alone never
/// counted.
pub(crate) fn held_actors(tx: &mut Tx<'_>) -> Result<MemoryHeldActors> {
    let mut h = MemoryHeldActors::default();
    let actors: Vec<Tid> = tx.core.ix.secrets.keys().copied().collect();
    for a in actors {
        // a plain thing's leftover epochs (an invalid rotation's) are no secrets of its own
        let Some(e) = tx.core.own_epochs(&a) else { continue };
        let held = ROLES.iter().any(|r| e.role(*r).newest_held().is_some());
        if !held && tx.core.ix.own_keys.contains(&a) {
            continue;
        }
        let s = secrets_in(tx, &a)?;
        h.map.insert(a, (s, e));
    }
    let unheld: Vec<Tid> = tx.core.ix.own_keys.iter().filter(|a| !h.map.contains_key(a)).copied().collect();
    for a in unheld {
        let Some(keys) = Core::keys_in(tx, &a)? else { continue };
        let mut e = ActorEpochs::default();
        for (r, ks) in [(Role::Read, &keys.read), (Role::Write, &keys.write), (Role::Admin, &keys.admin)] {
            if let Some(ep) = ks.as_ref().and_then(|k| osis_keys::aspects::from_schema(&k.epoch).ok()) {
                e.role_mut(r).set_established(ep, osis_keys::Provenance::Fixed);
            }
        }
        let mut s = secrets_in(tx, &a)?;
        presumed_boxes(tx, &a, &e, &mut s)?;
        h.map.insert(a, (s, e));
    }
    Ok(h)
}

/// Boxes presumed in actor `a`'s keyset epochs, on top of the `secrets.0` boxes held of it
/// (spec/crypto.md §4): a holder that left a role of `a` (an applied lowering write, or an edge
/// past its `until`) and holds less now counts as boxed at `a`'s keyset epoch of each role it
/// left, unless that keyset was set by the commit that made the departure (a removal carrying
/// its rotation), or this node holds the `secrets.0` delta of the commit that set it and that
/// delta boxes no such holder (a rotation boxes every holder current to its author). Times are
/// the authors' word, so they decide nothing: a self-removal backdated before a rotation that
/// still boxed the leaver, or a rotation made unaware of a departure, presumes the leaver
/// boxed. A self-removal or an expiry thus keeps `a`'s epoch from covering until `a` rotates
/// (spec/permissions.md §3).
fn presumed_boxes(tx: &mut Tx<'_>, a: &Tid, e: &ActorEpochs, s: &mut osis_schema::core_types::Secrets) -> Result<()> {
    let Some(tl) = tx.core.timelines.get(a) else { return Ok(()) };
    let now = now_ts(tx.core);
    let current = roles_now(tl, a, now);
    // (holder, the roles it left, the commit that made the departure)
    let mut left: Vec<(Tid, Role, Role, Option<osis_base::CommitId>)> = Vec::new();
    for (mc, op) in edge_writes(tl, a) {
        if let Some(d) = departure_of(tl, a, mc, op) {
            left.push((op.holder, d.from, d.upto, Some(mc.id)));
        }
    }
    for (m, x) in tl.edges_at(None).holders(a) {
        if x.until.is_some() && !x.alive_at(Some(now)) {
            left.push((*m, Role::Read, x.role, None));
        }
    }
    let owner = tx.core.owner(a);
    for (m, from, upto, by) in left {
        if current.get(&m).copied() >= Some(from) || owner == Some(m) {
            continue;
        }
        for r in ROLES.into_iter().filter(|r| (from..=upto).contains(r)) {
            let Some(ep) = e.role(r).newest() else { continue };
            let k = BoxKey { holder: m, role: r, epoch: osis_keys::aspects::to_schema(&ep) };
            let intro = tx.core.ix.epoch_intro.get(&(*a, r, ep)).map(|x| x.1);
            let boxed = match intro {
                Some(c) if Some(c) == by => false,
                Some(c) => rotation_boxes(tx, a, &c)?.is_none_or(|b| b.contains(&k)),
                None => true,
            };
            if boxed {
                let placeholder = osis_schema::core_types::SecretBox::Symmetric(osis_schema::core_types::SymmetricBox { epoch: k.epoch.clone(), wrap: Vec::new(), names: None });
                s.boxes.entry(k).or_insert(placeholder);
            }
        }
    }
    Ok(())
}

/// The box keys commit `c`'s `secrets.0` delta on `a` writes, when this node holds that delta.
fn rotation_boxes(tx: &mut Tx<'_>, a: &Tid, c: &osis_base::CommitId) -> Result<Option<BTreeSet<BoxKey>>> {
    let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.header.aspects.iter().position(|x| x.tid == *a && x.ak.as_str() == "secrets.0")) else { return Ok(None) };
    let parts = crate::apply::held_parts(tx, c, ai)?;
    if parts.is_empty() {
        return Ok(None);
    }
    let mut out = BTreeSet::new();
    for d in parts {
        if let osis_commit::Decoded::Delta(d) = d {
            out.extend(crate::apply::keys::secrets_write(&d.fragment).boxes.into_keys());
        }
    }
    Ok(Some(out))
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may rotate now: write
/// and above rotates its role and below.
pub fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    core.timelines.get(a).map(|tl| tl.may_rotate(who, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The known departures `a`'s newest held epochs (any role) do not cover now.
pub(crate) fn uncovered_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    let deps = departures(tx, a)?;
    let mut out: Vec<Departure> = Vec::new();
    for (_, ds) in uncovered_by_role(tx, a, &deps)?.unwrap_or_default() {
        for d in ds {
            if !out.contains(&d) {
                out.push(d);
            }
        }
    }
    Ok(out)
}

/// The roles of `a` whose newest current epoch does not cover a known departure.
pub(crate) fn uncovered_roles(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
    uncovered_roles_of(tx, a, deps)
}

pub fn uncovered_roles_of(tx: &mut Tx<'_>, a: &Tid, deps: Vec<Departure>) -> Result<BTreeSet<Role>> {
    Ok(uncovered_by_role(tx, a, &deps)?.unwrap_or_default().into_iter().filter(|(_, ds)| !ds.is_empty()).map(|(r, _)| r).collect())
}

pub(super) type ByRole = Vec<(Role, Vec<Departure>)>;

/// For each role of `a` with a held epoch, the departures of `deps` its newest held epoch does
/// not cover (by names, `osis_keys::covers`); `None` when `deps` is empty or no epochs of `a`
/// are held.
pub(super) fn uncovered_by_role(tx: &mut Tx<'_>, a: &Tid, deps: &[Departure]) -> Result<Option<ByRole>> {
    if deps.is_empty() {
        return Ok(None);
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(None) };
    let held = tx.core.names_held(a);
    let by_role = ROLES.into_iter().filter_map(|r| Some((r, uncovered(a, &epochs, r, &epochs.role(r).newest_held()?.0, deps, &held).into_iter().cloned().collect()))).collect();
    Ok(Some(by_role))
}

/// The known departures of `a`, each with the commit that made it when that is this node's
/// own self-removal (`own_leaving`): node-sync's cover check ignores such a departure until the
/// commit is placed (spec/crypto.md §4).
pub fn departures_placing(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Departure, Option<osis_base::CommitId>)>> {
    Ok(departures(tx, a)?.into_iter().map(|d| { let c = own_leaving(tx.core, a, &d); (d, c) }).collect())
}

/// The commit of departure `d` (from `a`, or from the innermost actor on its way) when it is
/// this node's own self-removal (spec/permissions.md §2): the newest applied write on the
/// holder's edge there lowers it and is a commit made here (signed by this node or a key actor
/// it holds). From stored commits only, so a restart keeps it.
fn own_leaving(core: &Core, a: &Tid, d: &Departure) -> Option<osis_base::CommitId> {
    let t = d.via.last().unwrap_or(a);
    let tl = core.timelines.get(t)?;
    let (mc, op) = edge_writes(tl, t).filter(|(_, op)| op.holder == d.holder).max_by_key(|(mc, _)| mc.point())?;
    let own = mc.author == core.id.tid() || core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local);
    (own && departure_of(tl, t, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, t, &op.holder, mc.ts)).then_some(mc.id)
}
