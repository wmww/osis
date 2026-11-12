//! Departures from an actor (spec/permissions.md §3, spec/crypto.md §4): the ones this node
//! knows of, read from the role timeline (each holder's edge into the actor as this node holds
//! it, `EdgeLog`: a holder holding less now than its edge gave it) and from the `secrets.0`
//! state (box holders at a current epoch that hold less than that role now), and the makers of
//! current epochs that hold less than that role now by any path; the names rotations write
//! (`names`), read from the same edges. A departure from a holder actor of `a` is none of `a`'s
//! (spec/crypto.md §4, Holder actors), but a maker whose role ran through one holds the epoch
//! it made: its lowering departs `a`. Departures are recomputed on demand (O(edge history)) and
//! cached per actor (`departures`), never stored. Keys read no clock: an edge counts by its role
//! with its `until` disregarded (`key_role`), so an edge past its `until` departs only by its
//! removal (a finalize, spec/permissions.md §2).

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{now_ts, secrets_in};
use osis_base::{Role, Tid};
use osis_keys::{Departure, EdgeLog, EdgeWrite};
use osis_perm::{At, EdgeOp, RoleCommit, Timeline, WriteId};
use std::collections::{BTreeMap, BTreeSet};

/// The departure of a holder now holding `cur` from a role above it: from the role just above.
fn above_role(cur: Option<Role>) -> Option<Role> {
    match cur {
        None => Some(Role::Sync),
        Some(Role::Sync) => Some(Role::Read),
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

/// Each holder's edge into `a` as this node holds it (spec/crypto.md §4, Edge writes): the held
/// writes on it whose commits are resolved (one that is not applies nothing until it is, like
/// one not held), in key order, each applied or not; applying nothing, whether it would over
/// the edge the newest applied write before it giving more set (`Timeline::applies_over`: a
/// second finalize of a removed grant), and whether its author held write on `a` just before
/// its point (`At::before`, as its authority is judged there: an author removed since still
/// counts); its start is the edge before the first of them (the record edge). Only commits this
/// node holds: names are met by holding them.
fn edge_logs(core: &Core, tl: &Timeline, a: &Tid) -> BTreeMap<Tid, EdgeLog> {
    let mut by: BTreeMap<Tid, Vec<(osis_perm::Point, WriteId, &RoleCommit, &EdgeOp)>> = BTreeMap::new();
    for (w, mc, op) in tl.held_on(a) {
        if op.holder == *a || !core.ix.commits.contains_key(&mc.id) || core.ix.unresolved.contains(&mc.id) {
            continue;
        }
        by.entry(op.holder).or_default().push((mc.point(), w, mc, op));
    }
    by.into_iter()
        .map(|(m, mut ws)| {
            ws.sort_by_key(|x| x.0);
            let first = ws.first().map(|x| x.0);
            let start_edge = first.and_then(|p| tl.edges_at(Some(p)).get(&m, a).copied());
            // the applied writes so far, each with the edge it set
            let mut set: Vec<Option<osis_perm::Edge>> = Vec::new();
            let mut writes = Vec::new();
            for (p, w, mc, op) in ws {
                let role = key_role(op.edge.as_ref());
                let applied = tl.is_applied(&w);
                let (takes, counts) = if applied {
                    set.push(op.edge);
                    (true, false)
                } else {
                    let over = set.iter().rev().copied().find(|e| key_role(e.as_ref()) > role).unwrap_or(start_edge);
                    let takes = role < Some(Role::Admin) && tl.applies_over(&w, over);
                    (takes, tl.role(&mc.author, a, At::before(p)) >= Some(Role::Write))
                };
                writes.push(EdgeWrite { key: key_of(&p), role, applied, takes, counts });
            }
            (m, EdgeLog { start: key_role(start_edge.as_ref()), writes })
        })
        .collect()
}

/// The names a rotation of `a` writes (spec/crypto.md §4), from this node's own timeline of `a`:
/// per holder's edge (`edge_logs`), each applied write lowering it and each write applying
/// nothing that counts and gives a role (`EdgeLog::names`). They are what an epoch covers
/// (`osis_keys::pins`), read from the same edges as the departures this node knows, so its own
/// epochs cover what it knows (else a rotator could never cover what it knows: a livelock).
/// `departs`: the rotation commit itself, when it departs a holder of `a` (it cannot name its own
/// ID).
pub(crate) fn names(core: &Core, a: &Tid, departs: Option<osis_keys::Own>) -> osis_keys::Names {
    let mut list = BTreeSet::new();
    if let Some(tl) = core.timelines.get(a) {
        for (m, log) in edge_logs(core, tl, a) {
            list.extend(log.names(m));
        }
    }
    osis_keys::Names { list, departs }
}

/// Departures from `a` itself (spec/crypto.md §4): each holder whose edge (`edge_logs`) gave it
/// more than the edge holds it at now and than it holds now (`Core::key_holders`), shown by that
/// edge (a destroyed holder actor's edge stands, and its departure is its box's); and, shown by nothing (no
/// epoch covers them until a rotation supersedes the epoch), each holder with a box of the
/// `secrets.0` state at a current epoch of a role it holds less than now, and each maker of a
/// current epoch holding less than its role now (`Timeline::role` at `At::KEYS`, through holder
/// actors alike). Each concerns the roles above its current one up to the highest it had.
fn direct_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Departure>> {
    let current: BTreeMap<Tid, Role> = tx.core.key_holders(a).into_iter().collect();
    let mut out = BTreeSet::new();
    if let Some(tl) = tx.core.timelines.get(a) {
        for (m, log) in edge_logs(tx.core, tl, a) {
            // what the edge holds it at now, or more by another path (a destroyed actor's stand-in)
            let from = above_role(current.get(&m).copied().max(log.now()));
            if let (Some(from), Some(upto)) = (from, log.most())
                && from <= upto
            {
                out.insert(Departure::holder(m, from).upto(upto).edge(log));
            }
        }
    }
    // per holder: the roles a box or a made epoch had it hold that it holds less than now
    let mut left: BTreeMap<Tid, (Role, Role)> = BTreeMap::new();
    let mut note = |m: Tid, cur: Option<Role>, upto: Role| {
        if let Some(from) = above_role(cur).filter(|f| *f <= upto && m != *a) {
            let x = left.entry(m).or_insert((from, upto));
            *x = (x.0.min(from), x.1.max(upto));
        }
    };
    if let Some(epochs) = tx.core.epochs(a) {
        // from the `secrets.0` state: a box at a current epoch of a role its holder no longer holds
        let s = secrets_in(tx, a)?;
        for k in s.boxes.keys() {
            if osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e)) {
                note(k.holder, current.get(&k.holder).copied(), k.role);
            }
        }
        // the maker of a current epoch holds its secret whatever the boxes say: one holding
        // less than that role now, for keys, by any path (its role may have run through a holder
        // actor, whose departures are none of `a`'s), departed it
        let tl = tx.core.timelines.get(a);
        for r in osis_keys::ROLES {
            for e in epochs.role(r).current() {
                let Some(author) = tx.core.ix.epoch_intro.get(&(*a, r, e)).and_then(|(_, c)| tx.core.ix.commits.get(c)).map(|m| m.view.author) else { continue };
                note(author, tl.and_then(|tl| tl.role(&author, a, At::KEYS)), r);
            }
        }
    }
    out.extend(left.into_iter().map(|(m, (from, upto))| Departure::holder(m, from).upto(upto)));
    Ok(out)
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
