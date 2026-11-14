//! Departures from an actor (spec/permissions.md §3, spec/crypto.md §4): the ones this node
//! knows of, read from the role timeline (each holder's edge into the actor as this node holds
//! it, `EdgeLog`: a holder holding less now than its edge gave it) and from the `secrets.0`
//! state (box holders at a current epoch that hold less than that role now), and the makers of
//! current epochs that hold less than that role now by any path with key access; the names rotations write
//! (`names`), read from the same edges. A departure from a holder actor of `a` is none of `a`'s
//! (spec/crypto.md §4, Holder actors), but a maker whose role ran through one holds the epoch
//! it made: its lowering departs `a`. Departures are recomputed on demand (O(edge history)) and
//! cached per actor (`departures`), never stored. Keys read no clock: an edge counts by its role
//! with its `until` disregarded (`key_role`), so an edge past its `until` departs only by its
//! removal (a finalize, spec/permissions.md §2).

use crate::engine::{Core, On, Tx};
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
/// second finalize of a removed grant), whether it would over the start or the edge any
/// applied write before it set (it stands), and whether its author held write on `a` just before
/// its point (`At::before`, as its authority is judged there: an author removed since still
/// counts); its start is the edge before the first of them (the record edge). Only commits this
/// node holds: names are met by holding them. The timeline is read whole only for a write
/// applying nothing (its verdicts over other edges and its author's role are judged there).
pub(crate) fn edge_logs<'t>(core: &Core, on: &On<'t>, a: &Tid) -> BTreeMap<Tid, EdgeLog> {
    let mut by: BTreeMap<Tid, Vec<(osis_perm::Point, WriteId, &'t RoleCommit, &'t EdgeOp)>> = BTreeMap::new();
    for (w, mc, op) in on.held() {
        if op.holder == *a || !core.ix.commits.contains_key(&mc.id) || core.ix.unresolved.contains(&mc.id) {
            continue;
        }
        by.entry(op.holder).or_default().push((mc.point(), w, mc, op));
    }
    by.into_iter()
        .map(|(m, mut ws)| {
            ws.sort_by_key(|x| x.0);
            let first = ws.first().map(|x| x.0);
            let start_edge = first.and_then(|p| on.edge_at(&m, Some(p)));
            // the applied writes so far, each with the edge it set
            let mut set: Vec<Option<osis_perm::Edge>> = Vec::new();
            let mut writes = Vec::new();
            for (p, w, mc, op) in ws {
                let role = key_role(op.edge.as_ref());
                let applied = on.is_applied(&w);
                let (takes, stands, counts) = if applied {
                    set.push(op.edge);
                    (true, true, false)
                } else {
                    let tl = on.whole();
                    let over = set.iter().rev().copied().find(|e| key_role(e.as_ref()) > role).unwrap_or(start_edge);
                    let takes = role < Some(Role::Admin) && tl.applies_over(&w, over);
                    let mut edges: Vec<Option<osis_perm::Edge>> = Vec::new();
                    for e in std::iter::once(start_edge).chain(set.iter().copied()) {
                        if !edges.contains(&e) {
                            edges.push(e);
                        }
                    }
                    let stands = takes || edges.into_iter().any(|e| tl.applies_over(&w, e));
                    (takes, stands, tl.role(&mc.author, a, At::before(p)) >= Some(Role::Write))
                };
                writes.push(EdgeWrite { key: key_of(&p), role, applied, takes, stands, counts });
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
    if let Some(on) = core.timelines.on(a) {
        for (m, log) in edge_logs(core, &on, a) {
            list.extend(log.names(m));
        }
    }
    osis_keys::Names { list, departs }
}

/// The demotions a rotation of `a` carries (spec/crypto.md §4, Carried demotions): the commits
/// of the explicit demotions on `a` held here that took a party below write or admin there, its
/// own or through an actor below `a` at any depth (the walk records a demotion on everything the
/// lowered edge's target reaches, spec/permissions.md §5.1 step 4), and that the party has not
/// regained. A reader's removal records none: it stays hidden from what holds `a`.
pub(crate) fn carried(core: &Core, a: &Tid) -> BTreeSet<osis_base::CommitId> {
    let Some(tl) = core.timelines.get(a) else { return BTreeSet::new() };
    tl.demotions_in_effect(a).map(|(_, d)| d.point.commit).collect()
}

/// Departures from `a` itself (spec/crypto.md §4): each holder whose edge (`edge_logs`) gave it
/// more than the edge holds it at now and than it holds now (`Core::key_holders`), shown by that
/// edge (a destroyed holder actor's edge stands, and its departure is its box's); and, shown by nothing (no
/// epoch covers them until a rotation supersedes the epoch), each holder with a box of the
/// `secrets.0` state at a current epoch of a role it holds less than now, and each maker of a
/// current epoch holding less than its role now (`members::role_for_keys`: through holder
/// actors with key access). An edge departure concerns the roles above its current one up to the highest
/// it had; a box or maker departure that role alone (an epoch of another role it neither made
/// nor holds a box at is no concern of it: counted, a link maker that left kept the link's
/// admin epoch, which nobody may rotate, uncovered, and so every role of the link and of what it
/// holds, for good: osis `sharing::leave_of_a_links_maker_gives_up_the_link`).
fn direct_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Departure>> {
    let current: BTreeMap<Tid, Role> = tx.core.key_holders(a).into_iter().collect();
    let mut out = BTreeSet::new();
    if let Some(on) = tx.core.timelines.on(a) {
        for (m, log) in edge_logs(tx.core, &on, a) {
            // what the edge holds it at now, or more by another path (a destroyed actor's stand-in)
            let from = above_role(current.get(&m).copied().max(log.now()));
            if let (Some(from), Some(upto)) = (from, log.most())
                && from <= upto
            {
                out.insert(Departure::holder(m, from).upto(upto).edge(log));
            }
        }
    }
    // per holder: each role a box or a made epoch had it hold that it holds less than now (that
    // role only: its other roles' epochs it neither made nor holds a box at)
    let mut left: BTreeSet<(Tid, Role)> = BTreeSet::new();
    let mut note = |m: Tid, cur: Option<Role>, r: Role| {
        if cur < Some(r) && m != *a {
            left.insert((m, r));
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
        // less than that role now, for keys, by any path with key access (its role may have run
        // through a holder actor, whose departures are none of `a`'s; a keyless grant reads
        // nothing), departed it
        for r in osis_keys::ROLES {
            for e in epochs.role(r).current() {
                let Some(author) = tx.core.ix.epoch_intro.get(&(*a, r, e)).and_then(|(_, c)| tx.core.ix.commits.get(c)).map(|m| m.view.author) else { continue };
                note(author, super::members::role_for_keys(tx.core, &author, a), r);
            }
        }
    }
    out.extend(left.into_iter().map(|(m, r)| Departure::holder(m, r).upto(r)));
    Ok(out)
}

/// Every departure `a`'s epochs must cover: its own (`direct_departures`). A memo
/// (`Core::departures`).
pub(crate) fn departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.departures, a, |tx| Ok(direct_departures(tx, a)?.into_iter().collect()))
}

/// The roles of `a` that `who` (this node, a key actor it signs as, or a holder actor) may
/// rotate now (spec/permissions.md §3, Who rotates): write and above rotates its role and below,
/// over grants with key access only. A role through a keyless grant is a role (a rotation by it
/// is valid), but its holder never gets the secret of the holder actor it reaches `a` through,
/// so holds none of `a`'s epochs to judge a rotation due by: it leaves rotating to those that do
/// (spec/crypto.md §4, Key access).
pub fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    let Some(tl) = core.timelines.get(a) else { return BTreeSet::new() };
    let at = At::now(now_ts(core));
    let keyless = super::members::key_access(core);
    if keyless.is_empty() {
        return tl.may_rotate(who, a, at).into_iter().collect();
    }
    let role = tl.roles_without(who, at, &keyless).get(a).copied();
    osis_keys::ROLES.into_iter().filter(|r| role >= Some(Role::Write) && Some(*r) <= role).collect()
}

/// The known departures of `a`, each with the commit that made it when that is this node's
/// own self-removal (`own_leaving`): node-sync's cover check ignores such a departure until the
/// commit is placed (spec/crypto.md §4).
pub fn departures_placing(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Departure, Option<osis_base::CommitId>)>> {
    Ok(departures(tx, a)?.into_iter().map(|d| { let c = own_leaving(tx.core, a, &d); (d, c) }).collect())
}

/// The commit of departure `d` from `a` when it is this node's own self-removal
/// (`own_removal_on`). From stored commits only, so a restart keeps it.
fn own_leaving(core: &Core, a: &Tid, d: &Departure) -> Option<osis_base::CommitId> {
    own_removal_on(core, core.timelines.get(a)?, a, &d.holder)
}

/// The newest applied write on `holder`'s edge on `a` that changed its role for keys
/// (`key_role`), when it is this node's own self-removal (`own_leaving_write`). A later write
/// changing nothing (a sibling's concurrent removal of the same edge) leaves the removal it
/// follows the one behind the departure.
fn own_removal_on(core: &Core, tl: &Timeline, a: &Tid, holder: &Tid) -> Option<osis_base::CommitId> {
    let changed = |mc: &RoleCommit, op: &EdgeOp| key_role(tl.edges_at(Some(mc.point())).get(&op.holder, a)) != key_role(op.edge.as_ref());
    let (mc, op) = edge_writes(tl, a).filter(|(mc, op)| op.holder == *holder && changed(mc, op)).max_by_key(|(mc, _)| mc.point())?;
    own_leaving_write(core, tl, a, mc, op).then_some(mc.id)
}

/// Whether applied write `op` of `mc` on `a`, the newest changing the holder's edge there, is this
/// node's own self-removal (spec/permissions.md §2, §3 Lost access): it lowers the edge, and it
/// was made here or its author is this node, its account or a key actor it holds, whichever node
/// of the account made it: each waits for it to be held elsewhere, so a sibling that pulled it
/// from the maker keeps it until a source has it.
fn own_leaving_write(core: &Core, tl: &Timeline, a: &Tid, mc: &RoleCommit, op: &EdgeOp) -> bool {
    let own = core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local) || mc.author == core.id.tid() || core.account.get() == Some(mc.author) || core.key_actors.contains_key(&mc.author);
    own && departure_of(tl, a, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, a, &op.holder, mc.ts)
}

/// Whether applied role commit `c` is an own self-removal (`own_removal_on`) on one of
/// `targets`: the one rule for every node of the account, the one that made it and its
/// siblings alike (`sync::held::wait_if_own`). Reads the targets' writes only for a commit
/// by an own author.
pub(crate) fn own_self_removal(core: &Core, c: &osis_base::CommitId, targets: &BTreeSet<Tid>) -> bool {
    let Some(m) = core.ix.commits.get(c) else { return false };
    let a = m.view.author;
    if m.origin != crate::events::Origin::Local && a != core.id.tid() && core.account.get() != Some(a) && !core.key_actors.contains_key(&a) {
        return false;
    }
    targets.iter().any(|t| core.timelines.get(t).is_some_and(|tl| edge_writes(tl, t).any(|(mc, op)| mc.id == *c && own_removal_on(core, tl, t, &op.holder) == Some(*c))))
}
