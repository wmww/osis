//! Departures (spec/permissions.md §3, spec/crypto.md §4): the ones this node knows of, read
//! from the membership timeline (every applied edge write that lowered an edge, and edges past
//! their `until`, whose member holds less now) and from state (every box holder at a current
//! epoch that holds less than that role now), recursively through member and owner actors
//! (departures inside a member); and the covers rule's view over the held actors, plus: an
//! epoch introduced by a departed party (or a node not holding that role on the actor now but
//! through it) does not cover its departure, nor, for a rotator, one whose rotation commit it
//! does not hold and a departed party could have written. Departures are recomputed on demand
//! (O(edge history)) and cached per actor (`departures`), never stored.

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{now_ts, secrets_in};
use osis_base::{Role, Tid, Ts, WallMs};
use osis_crypto::Epoch;
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, uncovered};
use osis_perm::{At, EdgeOp, MembershipCommit, Timeline, WriteId};
use osis_schema::core_types::BoxKey;
use std::collections::{BTreeMap, BTreeSet};

/// The departure of a member now holding `cur` from a role above it: from the role just above.
fn above_role(cur: Option<Role>) -> Option<Role> {
    match cur {
        None => Some(Role::Read),
        Some(Role::Read) => Some(Role::Write),
        Some(Role::Write) => Some(Role::Admin),
        Some(Role::Admin) => None,
    }
}

/// The applied writes on edges into `t` in its timeline `tl`, each with its commit.
fn edge_writes<'t>(tl: &'t Timeline, t: &'t Tid) -> impl Iterator<Item = (&'t MembershipCommit, &'t EdgeOp)> + 't {
    tl.applied()
        .keys()
        .filter_map(|w| match w {
            WriteId::Op(c, i) => tl.membership_commit(c).and_then(|mc| mc.ops.get(*i as usize).map(|op| (&**mc, op))),
            _ => None,
        })
        .filter(move |(_, op)| op.target == *t)
}

/// The departure edge write `op` of `mc` on `t` makes, if it lowers the member's edge. An edge
/// past its `until` at the write still counts: its departure is the `until`'s.
fn departure_of(tl: &Timeline, t: &Tid, mc: &MembershipCommit, op: &EdgeOp) -> Option<Departure> {
    let old = tl.edges_at(Some(mc.point())).get(&op.member, t).map(|e| e.role);
    let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
    Departure::of_change(op.member, old, new)
}

/// Each member's role on `a` at `now`, from `a`'s timeline `tl`.
fn roles_now(tl: &Timeline, a: &Tid, now: Ts) -> BTreeMap<Tid, Role> {
    tl.roster(a, At::now(now)).into_iter().map(|(m, e)| (m, e.role)).collect()
}

/// Departures from `a` itself: lowered edges whose member holds less now than before, edges
/// past their `until`, and box holders at a current epoch of a role they no longer hold
/// (spec/crypto.md §4). The owner never departs. `horizon`: lowered to the next time the answer
/// may change by the clock alone (an edge's `until`, a write's `ts` ahead of now).
pub(crate) fn direct_departures(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>) -> Result<BTreeSet<Departure>> {
    let mut out = BTreeSet::new();
    let now = now_ts(tx.core);
    let mut later = |t: WallMs| lower_horizon(horizon, t, now.wall_ms());
    let owner = tx.core.owner(a);
    let current = tx.core.timelines.get(a).map(|tl| roles_now(tl, a, now)).unwrap_or_default();
    if let Some(tl) = tx.core.timelines.get(a) {
        for (mc, op) in edge_writes(tl, a) {
            later(mc.ts.wall_ms());
            out.extend(departure_of(tl, a, mc, op));
        }
        // a roster snapshot ahead of the clock changes the roster when its `ts` passes
        for sn in tx.core.ix.held.snapshots_of(a) {
            later(sn.ts.wall_ms());
        }
        for (m, e) in tl.edges_at(None).members(a) {
            if let Some(u) = e.until {
                later(u);
            }
            if !e.alive_at(Some(now)) {
                out.insert(Departure::member(*m, Role::Read));
            }
        }
    }
    // from state: a box at a current epoch of a role its holder no longer holds
    if let Some(epochs) = tx.core.epochs(a) {
        let secrets = secrets_in(tx, a)?;
        for k in secrets.boxes.keys() {
            let Ok(e) = osis_keys::aspects::from_schema(&k.epoch) else { continue };
            if !epochs.role(k.role).is_current(&e) || Some(k.member) == owner || k.member == *a {
                continue;
            }
            let cur = current.get(&k.member).copied();
            if cur < Some(k.role)
                && let Some(from) = above_role(cur)
            {
                out.insert(Departure::member(k.member, from));
            }
        }
    }
    out.retain(|d| Some(d.member) != owner && current.get(&d.member).copied() < Some(d.from));
    Ok(out)
}

/// Every departure `a`'s epochs must cover: its own, and inside each member or owner actor
/// with secrets of its own, recursively (spec/crypto.md §4), along every chain that never
/// passes the departed member; a chain may pass an actor more than once, `a` included (a
/// membership cycle). Chains that the covers rule cannot tell apart (same first and second
/// actor, same actor left, member and role, and the same verdict of the first actor's newest
/// epoch of each role) are one departure, carrying one of them: work is polynomial in the actor
/// graph below `a`, whatever its depth, and finite with cycles. Cached per actor
/// (`Core::departures`) until a roster, `/secrets`, `/keys` or held epochs change, or the clock
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
/// the member, the role, and whether V's newest epoch of each role covers it.
type Class = (Option<Tid>, Tid, Tid, Role, [bool; 3]);

/// Whether `v`'s newest epoch of each role covers `d` (seen from `v`); unheld counts as not.
/// The covers rule reaches below `v` only through these verdicts (`osis_keys::covers`).
pub(super) fn verdicts(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> [bool; 3] {
    let (Some(s), Some(e)) = (osis_keys::HeldActors::secrets(held, v), osis_keys::HeldActors::epochs(held, v)) else { return [false; 3] };
    ROLES.map(|r| e.role(r).newest().is_some_and(|k| osis_keys::covers(v, s, e, r, &k, d, held)))
}

pub(super) fn class_of(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> Class {
    (d.via.first().copied(), d.via.last().copied().unwrap_or(*v), d.member, d.from, verdicts(held, v, d))
}

/// The covers rule's view of this node (spec/crypto.md §4): what it holds of each actor
/// (`held_actors`) and who introduced each epoch, so that "written by a departed party" is
/// judged wherever an epoch is, `a`'s own and every member actor's along a chain alike.
pub(crate) struct Judge<'c> {
    core: &'c Core,
    held: &'c MemoryHeldActors,
}

impl<'c> Judge<'c> {
    pub(crate) fn new(core: &'c Core, held: &'c MemoryHeldActors) -> Self {
        Judge { core, held }
    }
}

impl osis_keys::HeldActors for Judge<'_> {
    fn secrets(&self, actor: &Tid) -> Option<&osis_schema::core_types::Secrets> {
        self.held.secrets(actor)
    }
    fn epochs(&self, actor: &Tid) -> Option<&ActorEpochs> {
        self.held.epochs(actor)
    }
    fn stale_box_carries(&self, key: &BoxKey, r: Role, e: &Epoch) -> bool {
        self.held.stale_box_carries(key, r, e)
    }
    fn departed_wrote(&self, a: &Tid, r: Role, e: &Epoch, d: &Departure) -> bool {
        match introduced_by(self.core, a, r, e) {
            Some((au, ac, _)) => written_by(self.core, a, r, &au, &ac, &d.member),
            // the rotation commit not held (synced after a compaction, or its body missing
            // again): a node that may rotate r counts it as written by any departed party that
            // could have rotated r (a rotation more, never a leak); one that may not, as not
            None => may_rotate(self.core, &self.core.id.tid(), a).contains(&r) && could_rotate(self.core, a, d, r),
        }
    }
}

/// The departures of `departures`: the walk below `a` (`a` too when it is on a cycle), then
/// `a`'s own departures (`pending` added: ones a commit being made makes) and those inside its
/// members.
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
    until_horizon(tx.core, direct.iter().map(|x| &x.0), horizon);
    let judge = Judge::new(tx.core, &held);
    let found = walk(&parents, direct, |v, d| class_of(&judge, v, d));
    let mut out = mine;
    for (m, ps) in &parents {
        if !ps.contains(a) {
            continue;
        }
        for d in found.get(m).into_iter().flat_map(|f| f.values()) {
            if d.member != *a {
                out.insert(Departure::inside(*m, d));
            }
        }
    }
    Ok(out)
}

/// Lowers `horizon` to the next edge `until` anywhere in the timelines of `actors`: the verdicts
/// judge "written by a departed party" by roles now over any path, owner chains included
/// (`Judge::departed_wrote`), so an `until` outside the walked actors may change them.
fn until_horizon<'t>(core: &Core, actors: impl Iterator<Item = &'t Tid>, horizon: &mut Option<WallMs>) {
    let now = now_ts(core).wall_ms();
    let mut seen: Vec<&osis_perm::Timeline> = Vec::new();
    for a in actors {
        let Some(tl) = core.timelines.get(a) else { continue };
        if seen.iter().any(|t| std::ptr::eq(*t, tl)) {
            continue;
        }
        seen.push(tl);
        for u in tl.edges_at(None).iter().filter_map(|(_, _, e)| e.until) {
            lower_horizon(horizon, u, now);
        }
    }
}

/// Lowers `horizon` to `t` when `t` is ahead of `now` and before it.
fn lower_horizon(horizon: &mut Option<WallMs>, t: WallMs, now: WallMs) {
    if t > now && horizon.is_none_or(|h| t < h) {
        *horizon = Some(t);
    }
}

/// The actors below `a` with secrets of its own (members, transitively; `a` left out), and who
/// each of them and `a` is a member of among `a` and them.
pub(super) fn below_of(core: &Core, a: &Tid) -> (Vec<Tid>, BTreeMap<Tid, Vec<Tid>>) {
    let mut parents: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
    let mut below: Vec<Tid> = Vec::new();
    let mut queue = std::collections::VecDeque::from([*a]);
    let mut seen = BTreeSet::from([*a]);
    while let Some(v) = queue.pop_front() {
        let ms: BTreeSet<Tid> = core.current_members(&v).into_iter().map(|x| x.0).filter(|x| *x != v && core.has_own_secrets(x)).collect();
        for x in ms {
            parents.entry(x).or_default().push(v);
            if seen.insert(x) {
                below.push(x);
                queue.push_back(x);
            }
        }
    }
    (below, parents)
}

/// The fixpoint over the member graph: each actor keeps one departure per class, starting from
/// the actors' own (`direct`, in walk order); a chain is extended by every actor it is a member
/// of except the departed member itself. Classes are finite, so this ends on cycles too, and
/// the merge is exact: the class of a chain's extension depends only on the chain's class.
/// Chains share their tails (`osis_keys::Via`), so each kept departure costs one hop.
pub(super) fn walk(parents: &BTreeMap<Tid, Vec<Tid>>, direct: Vec<(Tid, BTreeSet<Departure>)>, class_of: impl Fn(&Tid, &Departure) -> Class) -> BTreeMap<Tid, BTreeMap<Class, Departure>> {
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
        for u in parents.get(&w).into_iter().flatten() {
            if d.member != *u {
                keep(&mut found, &mut work, *u, Departure::inside(w, &d));
            }
        }
    }
    found
}

/// What the covers rule needs of every actor this node holds secrets of; an actor with secrets
/// of its own whose secrets it does not hold is judged by its newest `/keys` keysets (spec/crypto.md
/// §4): those epochs, established in this view only, with the `/secrets` boxes held of it.
/// Epochs observed without any secret (boxes or keysets seen) are not holding: such an actor is
/// judged by its `/keys` too, or a newer keyset arriving alone never covered its departures.
/// Holding no `/secrets` state of it, a departure from it counts as boxed at a keyset epoch
/// unless that keyset's rotation commit is not ordered before the departure (`presumed_boxes`).
pub(crate) fn held_actors(tx: &mut Tx<'_>) -> Result<MemoryHeldActors> {
    let mut h = MemoryHeldActors::default();
    let actors: Vec<Tid> = tx.core.ix.secrets.keys().copied().collect();
    for a in actors {
        // a plain thing's leftover epochs (an invalid rotation's) are no secrets of its own
        let Some(e) = tx.core.own_epochs(&a).cloned() else { continue };
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
    // key-actor boxes keyed at a superseded epoch of a higher role still carry lower roles'
    // secrets (a grant raced by a rotation of that role only): the covers rule counts them
    let mut stale = BTreeSet::new();
    for (a, (s, e)) in &h.map {
        for (k, b) in &s.boxes {
            let osis_schema::core_types::SecretBox::Sealed(sb) = b else { continue };
            let Ok(ke) = osis_keys::aspects::from_schema(&k.epoch) else { continue };
            if sb.keyset.is_some() || e.role(k.role).is_current(&ke) {
                continue;
            }
            for r in ROLES.into_iter().filter(|r| *r < k.role) {
                for ce in e.role(r).current() {
                    if box_knew(tx.core, a, k, r, &ce) != Some(false) {
                        stale.insert((k.clone(), r, ce));
                    }
                }
            }
        }
    }
    h.stale = stale;
    Ok(h)
}

/// Boxes presumed in actor `a`'s keyset epochs, on top of the `/secrets` boxes held of it
/// (spec/crypto.md §4): a member that left a role of `a` (an applied lowering write, or an edge
/// past its `until`) and holds less now counts as boxed at `a`'s keyset epoch of each role it
/// left, unless that keyset was set by the commit that made the departure (a removal carrying
/// its rotation), or this node holds the `/secrets` delta of the commit that set it and that
/// delta boxes no such member (a rotation boxes every member current to its author). Times are
/// the authors' word, so they decide nothing: a self-removal backdated before a rotation that
/// still boxed the leaver, or a rotation made unaware of a departure, presumes the leaver
/// boxed. A self-removal or an expiry thus keeps `a`'s epoch from covering until `a` rotates
/// (spec/permissions.md §3).
fn presumed_boxes(tx: &mut Tx<'_>, a: &Tid, e: &ActorEpochs, s: &mut osis_schema::core_types::Secrets) -> Result<()> {
    let Some(tl) = tx.core.timelines.get(a) else { return Ok(()) };
    let now = now_ts(tx.core);
    let current = roles_now(tl, a, now);
    // (member, the role it left and above, the commit that made the departure)
    let mut left: Vec<(Tid, Role, Option<osis_base::CommitId>)> = Vec::new();
    for (mc, op) in edge_writes(tl, a) {
        if let Some(d) = departure_of(tl, a, mc, op) {
            left.push((op.member, d.from, Some(mc.id)));
        }
    }
    for (m, x) in tl.edges_at(None).members(a) {
        if x.until.is_some() && !x.alive_at(Some(now)) {
            left.push((*m, Role::Read, None));
        }
    }
    let owner = tx.core.owner(a);
    for (m, from, by) in left {
        if current.get(&m).copied() >= Some(from) || owner == Some(m) {
            continue;
        }
        for r in ROLES.into_iter().filter(|r| *r >= from) {
            let Some(ep) = e.role(r).newest() else { continue };
            let k = BoxKey { member: m, role: r, epoch: osis_keys::aspects::to_schema(&ep) };
            let intro = tx.core.ix.epoch_intro.get(&(*a, r, ep)).map(|x| x.3);
            let boxed = match intro {
                Some(c) if Some(c) == by => false,
                Some(c) => rotation_boxes(tx, a, &c)?.is_none_or(|b| b.contains(&k)),
                None => true,
            };
            if boxed {
                let placeholder = osis_schema::core_types::SecretBox::Symmetric(osis_schema::core_types::SymmetricBox { epoch: k.epoch.clone(), wrap: Vec::new() });
                s.boxes.entry(k).or_insert(placeholder);
            }
        }
    }
    Ok(())
}

/// The box keys commit `c`'s `/secrets` delta on `a` writes, when this node holds that delta.
fn rotation_boxes(tx: &mut Tx<'_>, a: &Tid, c: &osis_base::CommitId) -> Result<Option<BTreeSet<BoxKey>>> {
    let Some(ai) = tx.core.ix.commits.get(c).and_then(|m| m.header.aspects.iter().position(|x| x.tid == *a && x.ak.as_str() == "/secrets")) else { return Ok(None) };
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

/// Whether the commit that wrote key-actor box `k` of `a` knew epoch `e` of role `r` (it
/// carries that role's newest then, osis-keys `Carries`): its first write is ordered at or after
/// the commit that introduced `e` (its rotation, `introduced_by`); `None` unless both are held.
/// The first write, not the newest: a later rewrite of the box (a re-seal, a grant) by a writer
/// ordered after `e` need not have held `e` (a concurrent fork), so it proves nothing; a
/// rotation that introduces an epoch writes its key-actor boxes under fresh keys anyway.
/// Unknown counts as carrying for the covers rule (a rotation, never a leak) and as not for the
/// re-seal trigger (a re-seal to a current member costs a box, never a leak).
pub(super) fn box_knew(core: &Core, a: &Tid, k: &BoxKey, r: Role, e: &Epoch) -> Option<bool> {
    let boxed = core.ix.box_written.get(&(*a, k.clone()))?;
    Some(*boxed >= introduced_by(core, a, r, e)?.2)
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may rotate now: write
/// and above rotates its role and below.
pub fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    core.timelines.get(a).map(|tl| tl.may_rotate(who, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The commit that introduced epoch `e` of role `r` of `a` (its rotation: the earliest valid
/// held commit writing its keyset in `/keys`), if held: its author node, actor and `ts`.
fn introduced_by(core: &Core, a: &Tid, r: Role, e: &Epoch) -> Option<(Tid, Tid, Ts)> {
    core.ix.epoch_intro.get(&(*a, r, *e)).map(|(ts, au, ac, _)| (*au, *ac, *ts))
}

/// Whether the commit by `author` acting for `actor`, introducing an epoch of role `r` of `a`,
/// counts as written by departed party `m` (spec/crypto.md §4: such an epoch does not cover
/// `m`'s departure): `m` wrote it, or its author does not hold `r` on `a` now over paths that
/// avoid `m`. Judged now, not at the commit: an author that has since lost its own path (left
/// the actor it went through, which then left too) still knows the secret.
pub(super) fn written_by(core: &Core, a: &Tid, r: Role, author: &Tid, actor: &Tid, m: &Tid) -> bool {
    author == m || actor == m || core.timelines.get(a).is_none_or(|tl| tl.role_avoiding(author, a, m, At::now(now_ts(core))) < Some(r))
}

/// Whether departed party `d` (or a node acting through it) may have rotated role `r` of `a`:
/// the first actor on its chain is `a`'s owner or held an edge on `a` of write and at least `r`.
fn could_rotate(core: &Core, a: &Tid, d: &Departure, r: Role) -> bool {
    let first = d.via.first().copied().unwrap_or(d.member);
    core.owner(a) == Some(first) || core.timelines.get(a).and_then(|tl| tl.highest_edge(&first, a)) >= Some(r.max(Role::Write))
}

/// The known departures `a`'s newest held epochs (any role) do not cover now.
pub(crate) fn uncovered_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    let deps = departures(tx, a)?;
    let mut out: Vec<Departure> = Vec::new();
    for (_, ds) in uncovered_by_role(tx, a, &deps)?.map(|x| x.1).unwrap_or_default() {
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
    Ok(uncovered_by_role(tx, a, &deps)?.map(|x| x.1).unwrap_or_default().into_iter().filter(|(_, ds)| !ds.is_empty()).map(|(r, _)| r).collect())
}

pub(super) type ByRole = Vec<(Role, Vec<Departure>)>;

/// For each role of `a` with a held epoch, the departures of `deps` its newest held epoch does
/// not cover, with the held actors they were judged over (`held_actors`); `None` when `deps` is
/// empty or no epochs of `a` are held.
pub(super) fn uncovered_by_role(tx: &mut Tx<'_>, a: &Tid, deps: &[Departure]) -> Result<Option<(MemoryHeldActors, ByRole)>> {
    if deps.is_empty() {
        return Ok(None);
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(None) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let judge = Judge::new(tx.core, &held);
    let by_role = ROLES.into_iter().filter_map(|r| Some((r, uncovered(a, &secrets, &epochs, r, &epochs.role(r).newest_held()?.0, deps, &judge).into_iter().cloned().collect()))).collect();
    Ok(Some((held, by_role)))
}

/// The known departures of `a`, each with the commit that made it when that is this node's
/// own self-removal (`own_leaving`): node-sync's cover check ignores such a departure until the
/// commit is placed (spec/crypto.md §4).
pub fn departures_placing(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Departure, Option<osis_base::CommitId>)>> {
    Ok(departures(tx, a)?.into_iter().map(|d| { let c = own_leaving(tx.core, a, &d); (d, c) }).collect())
}

/// The commit of departure `d` (from `a`, or from the innermost actor on its way) when it is
/// this node's own self-removal (spec/permissions.md §2): the newest applied write on the
/// member's edge there lowers it and is a commit made here (signed by this node or a key actor
/// it holds). From stored commits only, so a restart keeps it.
fn own_leaving(core: &Core, a: &Tid, d: &Departure) -> Option<osis_base::CommitId> {
    let t = d.via.last().unwrap_or(a);
    let tl = core.timelines.get(t)?;
    let (mc, op) = edge_writes(tl, t).filter(|(_, op)| op.member == d.member).max_by_key(|(mc, _)| mc.point())?;
    let own = mc.author == core.id.tid() || core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local);
    (own && departure_of(tl, t, mc, op).is_some() && crate::apply::validity::self_removal(core, &mc.author, t, &op.member, mc.ts)).then_some(mc.id)
}
