//! Rotations (spec/permissions.md §3, spec/crypto.md §4): the
//! departures this node knows of, read from the membership timeline (every applied edge write
//! that lowered an edge, and edges past their `until`, whose member holds less now) and from
//! state (every box holder at a current epoch that holds less than that role now), recursively
//! through member and owner actors (departures inside a member); the covers rule over the held
//! actors, plus: an epoch introduced by a departed party (or a node not holding that role on
//! the actor now but through it) does not cover its departure, nor, for a rotator, one whose rotation commit it does not hold and a
//! departed party could have written; the cascade (`ensure_rotated`: intermediate actors first,
//! bottom-up, where the signer may rotate; one that may not stays stranded on what is below; a
//! member actor whose epoch does not cover is left out of a rotation and re-sealed once it
//! rotates); giving a thing
//! secrets of its own; re-seal decisions. Departures are recomputed on demand (O(edge history)),
//! never stored.

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{self, Delivery, Done, SyncState, now_ts, put_keysets, put_secrets, recipient, save_epochs, secrets_in};
use crate::Mutation;
use crate::retention::forget::Forgotten;
use osis_base::{Role, Tid, Ts, WallMs};
use osis_crypto::Epoch;
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, Recipient, Rotation, rotate, uncovered};
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
fn verdicts(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> [bool; 3] {
    let (Some(s), Some(e)) = (osis_keys::HeldActors::secrets(held, v), osis_keys::HeldActors::epochs(held, v)) else { return [false; 3] };
    ROLES.map(|r| e.role(r).newest().is_some_and(|k| osis_keys::covers(v, s, e, r, &k, d, held)))
}

fn class_of(held: &dyn osis_keys::HeldActors, v: &Tid, d: &Departure) -> Class {
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
fn collect(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>, pending: &[Departure]) -> Result<BTreeSet<Departure>> {
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
fn below_of(core: &Core, a: &Tid) -> (Vec<Tid>, BTreeMap<Tid, Vec<Tid>>) {
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
fn walk(parents: &BTreeMap<Tid, Vec<Tid>>, direct: Vec<(Tid, BTreeSet<Departure>)>, class_of: impl Fn(&Tid, &Departure) -> Class) -> BTreeMap<Tid, BTreeMap<Class, Departure>> {
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
fn box_knew(core: &Core, a: &Tid, k: &BoxKey, r: Role, e: &Epoch) -> Option<bool> {
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
fn written_by(core: &Core, a: &Tid, r: Role, author: &Tid, actor: &Tid, m: &Tid) -> bool {
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

type ByRole = Vec<(Role, Vec<Departure>)>;

/// For each role of `a` with a held epoch, the departures of `deps` its newest held epoch does
/// not cover, with the held actors they were judged over (`held_actors`); `None` when `deps` is
/// empty or no epochs of `a` are held.
fn uncovered_by_role(tx: &mut Tx<'_>, a: &Tid, deps: &[Departure]) -> Result<Option<(MemoryHeldActors, ByRole)>> {
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

/// The roles of `a` that `may` (the roles the rotator may rotate) holds and a rotation of `a` is
/// worth now (spec/permissions.md §3): their newest held epoch does not cover a known departure,
/// and none of those lies inside a current member M whose fresh box would not cover the rest
/// (`fresh_box_covers`) and that `a` is not below (no membership cycle through both). Such an M
/// heals by its own rotation: the node waits for it, so that `a`'s rotation then reaches M's
/// members in-band. An M on a cycle with `a` may wait on `a`: `a` rotates, leaving M out
/// (`rotation_into`). So no actor waits on itself through others.
fn rotation_due(tx: &mut Tx<'_>, a: &Tid, may: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
    let Some((held, by_role)) = uncovered_by_role(tx, a, &deps)? else { return Ok(BTreeSet::new()) };
    let current: BTreeSet<Tid> = tx.core.current_members(a).into_iter().map(|x| x.0).collect();
    let mut out = BTreeSet::new();
    let mut on_cycle: BTreeMap<Tid, bool> = BTreeMap::new();
    'roles: for (r, ds) in by_role {
        if ds.is_empty() || !may.contains(&r) {
            continue;
        }
        for d in ds {
            if let Some((m, rest)) = d.via.split_first()
                && current.contains(m)
                && !*on_cycle.entry(*m).or_insert_with(|| below_of(tx.core, m).0.contains(a))
                && !fresh_box_covers(tx, &held, m, r, &Departure { via: rest.clone(), member: d.member, from: d.from })?
            {
                continue 'roles;
            }
        }
        out.insert(r);
    }
    Ok(out)
}

/// Whether member actor `m` of `a` may be boxed role `r` of `a` (spec/permissions.md §3,
/// Membership cycles): a fresh box would name `m`'s newest epoch of `r` (`fresh_box_covers`)
/// and that epoch covers every departure of `deps` (those of `a`) inside `m`. Boxing to an
/// epoch is encrypting under it: a rotation leaves such a member out and the re-seal trigger
/// skips it until `m` rotates.
fn member_covers(tx: &mut Tx<'_>, held: &MemoryHeldActors, deps: &[Departure], m: &Tid, r: Role) -> Result<bool> {
    for d in deps.iter().filter(|d| d.via.first() == Some(m) && r >= d.from) {
        let Some((_, tail)) = d.via.split_first() else { continue };
        let inner = Departure { via: tail.clone(), member: d.member, from: d.from };
        if !fresh_box_covers(tx, held, m, r, &inner)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `rc` with its role cut at the first its newest epoch does not cover (`member_covers`, given
/// `deps` of the actor boxing it); `None` when that leaves no role. Key actors are kept whole.
pub(crate) fn left_out(tx: &mut Tx<'_>, held: &MemoryHeldActors, deps: &[Departure], rc: &Recipient) -> Result<Option<Recipient>> {
    if !matches!(rc.keys, osis_keys::MemberKeys::Actor { .. }) {
        return Ok(Some(rc.clone()));
    }
    let mut top = None;
    for r in ROLES.into_iter().filter(|r| *r <= rc.role) {
        if !member_covers(tx, held, deps, &rc.member, r)? {
            break;
        }
        top = Some(r);
    }
    Ok(top.map(|role| Recipient { role, ..rc.clone() }))
}

/// `left_out` for a grant to `rc.member`: by its own departures, as the target will see them
/// once it is a member.
pub(crate) fn grantee_left_out(tx: &mut Tx<'_>, rc: &Recipient) -> Result<Option<Recipient>> {
    let deps: Vec<Departure> = departures(tx, &rc.member)?.iter().map(|d| Departure::inside(rc.member, d)).collect();
    let held = held_actors(tx)?;
    left_out(tx, &held, &deps, rc)
}

/// Whether a fresh box of role `r` to member actor `m` would name `m`'s newest epoch (its
/// newest held secret, else its keyset in `/keys`) and that epoch covers `inner`.
fn fresh_box_covers(tx: &mut Tx<'_>, held: &MemoryHeldActors, m: &Tid, r: Role, inner: &Departure) -> Result<bool> {
    let (Some(me), Some(ms)) = (osis_keys::HeldActors::epochs(held, m), osis_keys::HeldActors::secrets(held, m)) else { return Ok(false) };
    let keys = Core::keys_in(tx, m)?;
    let ks = keys.as_ref().and_then(|k| osis_keys::aspects::keyset_of(k, r)).and_then(|ks| osis_keys::aspects::from_schema(&ks.epoch).ok());
    let named = match me.role(r).newest_held().map(|x| x.0) {
        Some(es) if osis_keys::symmetric_box(&es, ks.as_ref()) => Some(es),
        _ => ks,
    };
    Ok(me.role(r).newest().is_some_and(|k| named == Some(k) && osis_keys::covers(m, ms, me, r, &k, inner, &Judge::new(tx.core, held))))
}

/// Current members of `a` as box recipients; each of `skip` gets its new role or is left out
/// (departing members). Members
/// whose keys are unknown are left out (re-sealed later).
pub(crate) fn recipients(tx: &mut Tx<'_>, a: &Tid, skip: &[(Tid, Option<Role>)]) -> Result<Vec<Recipient>> {
    let now = tx.core.now();
    let mut out = Vec::new();
    for (m, role, until) in tx.core.current_members(a) {
        if until.is_some_and(|u| u <= now) {
            continue;
        }
        let role = match skip.iter().find(|(s, _)| *s == m) {
            Some((_, new)) => match new {
                Some(r) => *r,
                None => continue,
            },
            None => role,
        };
        if let Ok(r) = recipient(tx, m, role) {
            out.push(r);
        }
    }
    Ok(out)
}

/// A fresh deposit seed for `a` in `m` (spec/crypto.md §3; an admin's write).
pub(crate) fn fresh_deposit_seed(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid) -> Result<()> {
    let mut seed = [0u8; 32];
    tx.rng.fill_bytes(&mut seed);
    m.op(a, &osis_schema::core_types::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(5)], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&Some(seed))) })?;
    seed.fill(0);
    Ok(())
}

/// Whether a rotation of `roles` of `a` by `who` also refreshes `a`'s deposit seed (spec/crypto.md
/// §3): it rotates read for a departure, so the departed party (which read the seed in `/keys`)
/// can no longer deposit under `a`'s labels, and `who` is an admin (the seed is admin-written).
pub(crate) fn refreshes_deposit(core: &Core, who: &Tid, a: &Tid, roles: &BTreeSet<Role>) -> bool {
    roles.contains(&Role::Read) && may_rotate(core, who, a).contains(&Role::Admin)
}

/// The rotation of `roles` of `a` (boxes for `members`), written into `m`. The superseded
/// epochs' secrets must be held: `held` is this node's view (derived epochs for the switch to
/// secrets of its own). `pending`: departures from `a` the same commit makes (a removal's).
/// A member actor is boxed only the roles up to the first its newest epoch does not cover
/// (`member_covers`): left out, it is re-sealed once it rotates (spec/permissions.md §3).
pub(crate) fn rotation_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, members: &[Recipient], pending: &[Departure]) -> Result<Rotation> {
    let secrets = secrets_in(tx, &a)?;
    let deps = if pending.is_empty() { departures(tx, &a)? } else { collect(tx, &a, &mut None, pending)?.into_iter().collect() };
    let actors = held_actors(tx)?;
    let mut boxed = Vec::with_capacity(members.len());
    for rc in members {
        if let Some(rc) = left_out(tx, &actors, &deps, rc)? {
            boxed.push(rc);
        }
    }
    let judge = Judge::new(tx.core, &actors);
    let may_carry = |r: Role, e: &Epoch| uncovered(&a, &secrets, held, r, e, &deps, &judge).is_empty();
    let rot = rotate(&a, roles, held, &secrets, &boxed, &may_carry, &mut *tx.rng)?;
    put_secrets(m, a, &rot.secrets, false)?;
    put_keysets(m, a, &rot.keys)?;
    Ok(rot)
}

/// Members a rotation `rot` of `a` boxes that hold no box at a current read epoch before it (a
/// key actor: at any current epoch, its boxes are keyed at its top role): its commit is wrapped
/// under that epoch, so they cannot open it from the label (a grant this node learned of after
/// an epoch that left it out, the single-use link race's winner). They get it by inbox
/// (spec/permissions.md §3). Called before the rotation is committed.
pub(crate) fn unreached(tx: &mut Tx<'_>, a: &Tid, rot: &Rotation) -> Result<Vec<Tid>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let me = tx.core.id.tid();
    let mut out: Vec<Tid> = rot.secrets.boxes.keys().map(|k| k.member).filter(|m| *m != me).collect();
    out.sort();
    out.dedup();
    out.retain(|m| {
        let key_actor = tx.core.is_key_actor(m);
        !secrets.boxes.keys().any(|k| {
            k.member == *m && (key_actor || k.role == Role::Read) && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(k.role).is_current(&e))
        })
    });
    Ok(out)
}

/// The inbox (a node: direct) deliveries of rotation commit `c` of `a` to `members`.
pub(crate) fn deliver_rotation(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, members: &[Tid]) -> Result<Vec<Delivery>> {
    let mut out = Vec::new();
    if let Some(c) = c {
        for m in members {
            out.extend(flows::edges::deliver_to(tx, *m, c, &[a])?);
        }
    }
    Ok(out)
}

/// Records a rotation this node made (spec/crypto.md §4: its own epochs are established).
pub(crate) fn record(tx: &mut Tx<'_>, a: Tid, rot: &Rotation) -> Result<()> {
    tx.core.touch();
    // a plain thing's: derived from its owner, with what an invalid rotation gave it for reading
    let base = tx.core.epochs(&a).or_else(|| tx.core.ix.secrets.get(&a).cloned()).unwrap_or_default();
    tx.core.ix.secrets.insert(a, base);
    let e = tx.core.ix.secrets.entry_or_default(a);
    rot.record(e);
    e.establish();
    save_epochs(tx, &a)
}

fn signer_of(tx: &Tx<'_>, who: Tid) -> Option<Tid> {
    (who != tx.core.id.tid()).then_some(who)
}

/// Rotates `roles` of `a` in a commit of its own (a cascade rotation: changes no edge), signed
/// by `who`.
pub(crate) fn rotate_now(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let members = recipients(tx, &a, &[])?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, a, roles, &held, &members, &[])?;
    if refreshes_deposit(tx.core, &who, &a, roles) {
        fresh_deposit_seed(tx, &mut m, a)?;
    }
    let unreached = unreached(tx, &a, &rot)?;
    if let Some(s) = signer_of(tx, who) {
        m.sign_as(s);
    }
    let c = Engine::commit_tx(tx, m)?;
    let mut done = Done::default();
    recorded(tx, a, c, &rot, &unreached, &mut done)?;
    Ok(done)
}

/// Records rotation `rot` of `a`, committed as `c`, into `done` with its deliveries: by inbox to
/// `to`, and first under the labels above `a`, which must learn its new `/keys`
/// (spec/permissions.md §3).
fn recorded(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, rot: &Rotation, to: &[Tid], done: &mut Done) -> Result<()> {
    record(tx, a, rot)?;
    done.add(c);
    done.deliveries.extend(deliver_rotation(tx, a, c, to)?);
    if let Some(c) = c {
        done.deliveries.push(Delivery::First { commits: vec![c], under: above(tx.core, &a) });
    }
    Ok(())
}

/// Things whose labels must learn a rotated actor's new `/keys`: what it is a member of and
/// itself.
pub(crate) fn above(core: &Core, a: &Tid) -> Vec<Tid> {
    let mut out = vec![*a];
    if let Some(tl) = core.timelines.get(a) {
        let edges = tl.edges_at(None);
        out.extend(edges.targets(a).copied());
    }
    out.sort();
    out.dedup();
    out
}

/// Performs the rotations due on `a` before `who` (this node, or a key actor it signs as)
/// encrypts under its secrets: first those of the intermediate actors of departures inside
/// members (bottom-up: each actor after every actor on its departures' chains below it, each
/// once; on a membership cycle, in walk order), then `a`'s uncovered roles `who` may rotate
/// (spec/permissions.md §3) where that helps (`rotation_due`). Returns the roles still
/// uncovered: it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, who: Tid, a: Tid, done: &mut Done) -> Result<BTreeSet<Role>> {
    // a plain thing follows its owner's epochs
    let mut a = a;
    let mut owners = BTreeSet::new();
    while !tx.core.has_own_secrets(&a) {
        match tx.core.owner(&a) {
            Some(o) if owners.insert(a) && !owners.contains(&o) && !tx.core.is_key_actor(&o) => a = o,
            _ => return Ok(BTreeSet::new()),
        }
    }
    let firsts = |tx: &mut Tx<'_>, x: &Tid| -> Result<Vec<Tid>> {
        let f: BTreeSet<Tid> = departures(tx, x)?.into_iter().filter_map(|d| d.via.first().copied()).collect();
        Ok(f.into_iter().rev().collect())
    };
    // depth-first, post-order, without recursion (chains have no depth bound)
    let mut entered = BTreeSet::from([a]);
    let mut stack = vec![(a, firsts(tx, &a)?)];
    while let Some((x, next)) = stack.last_mut() {
        if let Some(y) = next.pop() {
            if entered.insert(y) {
                let f = firsts(tx, &y)?;
                stack.push((y, f));
            }
            continue;
        }
        let x = *x;
        stack.pop();
        let may = may_rotate(tx.core, &who, &x);
        let mine = rotation_due(tx, &x, &may)?;
        if !mine.is_empty() {
            done.extend(rotate_now(tx, who, x, &mine)?);
        }
    }
    uncovered_roles(tx, &a)
}

/// `ensure_rotated`, failing when `roles` stay uncovered.
pub(crate) fn require_covered(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>, done: &mut Done) -> Result<()> {
    let still = ensure_rotated(tx, who, a, done)?;
    if roles.iter().any(|r| still.contains(r)) {
        return Err(Error::Misuse("an epoch to encrypt under does not cover a known departure (another node must rotate first)"));
    }
    Ok(())
}

/// Gives `t` secrets of its own (spec/permissions.md §3, spec/crypto.md §3): a rotation of all
/// three roles from its derived epochs (the owner's: rotated first where a departure is
/// uncovered, the history boxes carry them), boxed to its owner and current members, with a
/// `/keys` carrying the keysets and a fresh deposit seed. Nothing when it has them already.
pub(crate) fn own_secrets(tx: &mut Tx<'_>, t: Tid, done: &mut Done) -> Result<()> {
    if let Some((c, rot, _)) = own_secrets_rot(tx, t, done)? {
        record(tx, t, &rot)?;
        done.add(c);
    }
    Ok(())
}

/// `own_secrets` up to its commit, not yet recorded: the commit, the rotation, and the
/// members it boxes that held no box at a current read epoch before it (`unreached`).
type OwnRot = (Option<osis_base::CommitId>, Rotation, Vec<Tid>);
fn own_secrets_rot(tx: &mut Tx<'_>, t: Tid, done: &mut Done) -> Result<Option<OwnRot>> {
    if tx.core.has_own_secrets(&t) || tx.core.is_key_actor(&t) {
        return Ok(None);
    }
    let who = tx.core.id.tid();
    require_covered(tx, who, t, &ROLES.into_iter().collect(), done)?;
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the owner's secrets are not held"))?;
    let members = recipients(tx, &t, &[])?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &members, &[])?;
    fresh_deposit_seed(tx, &mut m, t)?;
    let to = unreached(tx, &t, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    Ok(Some((c, rot, to)))
}

/// The plain things whose secrets derive from `a` that this node, an admin of each, sees with a
/// current non-owner member (spec/permissions.md §3: such a thing is left by its only keyset
/// part turning invalid, spec/crypto.md §3); each gets secrets of its own again.
pub(crate) fn own_secrets_candidates(core: &Core, a: &Tid) -> Vec<Tid> {
    let me = core.id.tid();
    // keys sort by target: each target once (a scan per call; only plain targets go further)
    let mut last = None;
    core.ix
        .member_keys
        .keys()
        .map(|(t, _)| *t)
        .filter(|t| last.replace(*t) != Some(*t))
        .filter(|t| !core.has_own_secrets(t) && !core.is_key_actor(t) && core.secret_actor(t) == Some(*a))
        .filter(|t| core.role_now(&me, t) == Some(Role::Admin) && core.current_members(t).iter().any(|(m, _, _)| Some(*m) != core.owner(t)))
        .collect()
}

/// `own_secrets` for a plain thing with current members, delivering the rotation by inbox to
/// each member it boxes (they hold no box at the derived epochs it wraps under) and placing it
/// first under the labels above the thing (its new `/keys`).
fn own_secrets_delivered(tx: &mut Tx<'_>, t: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some((c, rot, mut to)) = own_secrets_rot(tx, t, &mut done)? else { return Ok(done) };
    let owner = tx.core.owner(&t);
    to.retain(|m| Some(*m) != owner);
    recorded(tx, t, c, &rot, &to, &mut done)?;
    Ok(done)
}

/// The re-seal trigger for `a` (spec/permissions.md §3): current members lacking a box at a
/// chain-established current epoch of a role this node may rotate, never at an epoch
/// established by a snapshot alone, never for an edge whose `until` is within `MAX_DRIFT`.
pub(crate) fn reseal_candidates(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    let me = tx.core.id.tid();
    let may = may_rotate(tx.core, &me, a);
    if may.is_empty() {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let members: Vec<osis_keys::Member> = tx.core.current_members(a).into_iter().map(|(member, role, until)| osis_keys::Member { member, role, until }).collect();
    let now = tx.core.now();
    let due = osis_keys::reseal_needed(&secrets, &epochs, &members, now, &|k, r, e| box_knew(tx.core, a, k, r, e) == Some(true));
    let deps = departures(tx, a)?;
    let held = held_actors(tx)?;
    let mut out = Vec::new();
    for (m, roles) in due {
        let mut keep = BTreeSet::new();
        for r in roles {
            // not without the secret (this node may reach the actor through a member actor left
            // out); a member actor left out waits until its newest epoch covers
            let re = epochs.role(r);
            let holds = re.current().iter().any(|e| re.provenance(e).is_some_and(osis_keys::Provenance::reseals) && re.secret(e).is_some());
            if may.contains(&r) && holds && !re.newest_is_snapshot() && member_covers(tx, &held, &deps, &m, r)? {
                keep.insert(r);
            }
        }
        if !keep.is_empty() {
            out.push((m, keep));
        }
    }
    Ok(out)
}

/// A re-seal of `member` for `roles` of `a` (spec/permissions.md §3): its boxes at the
/// chain-established current epochs, with history boxes, delivered by inbox (a node: over a
/// direct connection) and placed under the actor's labels like any membership commit (later
/// removals reset its box entries: every node must hold them, or the removal waits for good).
pub(crate) fn reseal_one(tx: &mut Tx<'_>, a: Tid, member: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let mut done = Done::default();
    // boxing is encrypting under: rotate first where a departure is uncovered
    let me = tx.core.id.tid();
    require_covered(tx, me, a, roles, &mut done)?;
    let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let secrets = secrets_in(tx, &a)?;
    let role = tx.core.current_members(&a).into_iter().find(|(m, _, _)| *m == member).map(|x| x.1).ok_or(Error::Misuse("not a current member"))?;
    let rcpt = recipient(tx, member, role)?;
    let Some(w) = osis_keys::reseal_member(&a, &epochs, &secrets, &rcpt, roles, &mut *tx.rng)? else {
        return Err(Error::Misuse("the member's keyset is unknown"));
    };
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, false)?;
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.extend(flows::edges::deliver_to(tx, member, c, &[a])?);
    }
    Ok(done)
}

/// The lost-access trigger's work list (spec/permissions.md §3, "a node that learns it lost
/// read access"): `l/` + tid, a roster target of an applied received membership commit, or an
/// aspect's thing of a dropped pending one. The held actors a role on it reaches are
/// re-evaluated after the apply, in a transaction of their own (node-sync, every step).
pub(crate) const LOST_DUE: &[u8] = b"l/";

/// Adds `tids` to the work list.
pub(crate) fn mark_lost_due(tx: &mut Tx<'_>, tids: impl IntoIterator<Item = Tid>) -> Result<()> {
    for t in tids {
        tx.txn.put_local(&[LOST_DUE, t.as_bytes()].concat(), &[], osis_store::Shred::No)?;
        tx.core.ix.lost_due.insert(t);
    }
    Ok(())
}

/// Loads the work list.
pub(crate) fn load_lost_due(tx: &mut Tx<'_>) -> Result<()> {
    let mut v = Vec::new();
    tx.scan(LOST_DUE, |k, _| {
        v.push(Tid::from_bytes(k.try_into().map_err(|_| Error::Corrupt("lost-access work list"))?));
        Ok(())
    })?;
    tx.core.ix.lost_due.extend(v);
    Ok(())
}

/// Empties the work list, returning it.
fn take_due(tx: &mut Tx<'_>) -> Result<BTreeSet<Tid>> {
    let due: BTreeSet<Tid> = tx.core.ix.lost_due.iter().copied().collect();
    for t in &due {
        tx.core.ix.lost_due.remove(t);
        tx.txn.remove_local(&[LOST_DUE, t.as_bytes()].concat(), osis_store::Shred::No)?;
    }
    Ok(due)
}

/// Whether the node or a held key actor has a role on `a` now (any path, `until` honoured).
fn readable(core: &Core, a: &Tid) -> bool {
    let node = core.id.tid();
    core.role_now(&node, a).is_some() || core.key_actors.keys().any(|k| core.role_now(k, a).is_some())
}

/// Whether box recipient `m` is this node, a held key actor or an actor it holds and reads now.
fn ours(core: &Core, m: &Tid) -> bool {
    *m == core.id.tid() || core.key_actors.contains_key(m) || (core.ix.secrets.contains_key(m) && readable(core, m))
}

/// Whether a role on `x` gives one on `a`: `x` is `a`, on its owner chain, or holds a role on it.
fn reaches(core: &Core, x: &Tid, a: &Tid) -> bool {
    let mut cur = *a;
    for _ in 0..64 {
        if cur == *x {
            return true;
        }
        match core.owner(&cur) {
            Some(o) => cur = o,
            None => break,
        }
    }
    core.role_now(x, a).is_some()
}

/// How long after its `ts` a held pending grant by a plausible granter keeps this node from
/// dropping an actor it holds checked secrets of. Minor consequence: past it the node drops and
/// re-learns the secrets from the grant's own boxes when it applies, re-fetching the content. At
/// 0 every such grant waits that way; at infinity a grant that never applies (a part parked for
/// good) keeps a node that lost access holding the actor's secrets and content for good.
pub(crate) const PENDING_GRANT_WAIT_MS: u64 = 24 * 60 * 60 * 1000;

/// A held, not applied membership commit's boxes to this node on actor `x`.
struct PendingGrant {
    x: Tid,
    /// Its author may grant on `x` now, as this node sees it (admin or an invite), and its `ts`
    /// is within `PENDING_GRANT_WAIT_MS` before now (and not past `MAX_DRIFT` ahead), checked by
    /// its signature (`authentic`).
    plausible: bool,
}

/// Actors a held, not applied membership commit (pending, parked readable, or late parts)
/// boxes secrets of to this node, a held key actor or an actor it reads now: grants this node
/// may yet get (their secrets may be read already, spec/crypto.md §4), never a loss.
fn pending_grants(tx: &mut Tx<'_>) -> Result<Vec<PendingGrant>> {
    let mut out = Vec::new();
    let now = tx.now().0;
    let mut after = None;
    loop {
        let page = tx.txn.pending(after.as_ref(), 256)?;
        let n = page.len();
        for (id, _, bytes) in page {
            after = Some(id);
            let Ok(blob) = osis_commit::CommitBlob::decode(&bytes) else { continue };
            let (author, ts) = (blob.header.author, blob.header.ts.wall_ms().0);
            let recent = ts.saturating_add(PENDING_GRANT_WAIT_MS) > now && ts <= now.saturating_add(osis_base::format::MAX_DRIFT_MS);
            for (x, w) in crate::apply::keys::pending_secrets_writes(&blob, &id) {
                let core = &*tx.core;
                if w.boxes.keys().any(|k| ours(core, &k.member)) {
                    out.push(PendingGrant { x, plausible: recent && may_grant(core, &author, &x) && authentic(core, &blob, &id, &x) });
                }
            }
        }
        if n < 256 {
            return Ok(out);
        }
    }
}

/// The actors not applied commit `id` boxes to this node, a held key actor or an actor it reads
/// a read epoch newer than any it held checked (`held`: newest checked read epoch number per
/// dropped actor; a grant from after a rotation that left the node out; reading candidates, as
/// a re-grant read before the removal applied gives, do not count), signed (`authentic`) by an
/// author who may grant on them now: forgetting keeps those `/secrets` parts, whatever the
/// commit's age (spec/permissions.md §3), so a re-grant applied after the loss brings its boxes.
/// A box only at an epoch the node held (a grant from before the removal, which applied gives no
/// role) goes: kept, it would hold the lost secrets for good. Cost: such a re-grant that never
/// applies keeps its sealed box.
pub(crate) fn boxes_kept(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, held: &BTreeMap<Tid, u64>) -> BTreeSet<Tid> {
    if core.ix.commits.contains_key(id) {
        return BTreeSet::new();
    }
    let newer = |x: &Tid, k: &BoxKey| ours(core, &k.member) && k.role == Role::Read && held.get(x).is_none_or(|n| k.epoch.n > *n);
    crate::apply::keys::pending_secrets_writes(blob, id).into_iter().filter(|(x, w)| w.boxes.keys().any(|k| newer(x, k)) && may_grant(core, &blob.header.author, x) && authentic(core, blob, id, x)).map(|(x, _)| x).collect()
}

impl Engine {
    /// Whether a held, not applied commit (parked ones aside) writes `a`'s `/keys`, signed
    /// (`authentic`) by an admin of `a` now: a newer deposit seed may be on its way (node-sync
    /// holds back a deposit-only step meanwhile). Anyone can send a pending commit naming any
    /// aspect, so an unsigned one never counts: it would hold the step back for good.
    pub fn keys_write_pending(&mut self, a: &Tid) -> Result<bool> {
        let a = *a;
        let ids: Vec<osis_base::CommitId> = self.core.ix.pending.iter().filter(|(_, r)| **r != crate::Reason::Parked).map(|(c, _)| *c).collect();
        self.run(|tx| {
            for id in ids {
                let Some((_, bytes)) = tx.txn.get_pending(&id)? else { continue };
                let Ok(blob) = osis_commit::CommitBlob::decode(&bytes) else { continue };
                let h = &blob.header;
                if h.aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "/keys") && tx.core.role_now(&h.author, &a) == Some(Role::Admin) && authentic(tx.core, &blob, &id, &a) {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

/// Whether pending `blob` is signed by its author and its `/secrets` parts on `x` are the ones its
/// header lists: a commit waiting on its author's chain or a creation record is stored unchecked, so its
/// `author` and `ts` could be anyone's.
pub(crate) fn authentic(core: &Core, blob: &osis_commit::CommitBlob, id: &osis_base::CommitId, x: &Tid) -> bool {
    let h = &blob.header;
    let Some(osis_base::CreationRecord::KeyActor { public_key, .. }) = core.created(&h.author) else { return false };
    let Ok(vk) = osis_crypto::VerifyingKey::from_slice(public_key) else { return false };
    let mut interner = osis_crdt::Interner::new();
    osis_commit::verify_signature(id, &blob.signature, &vk).is_ok()
        && blob.parts.iter().all(|p| match h.aspects.get(p.ai) {
            Some(a) if a.tid == *x && a.ak.as_str() == "/secrets" => core.dedup(x).is_some_and(|d| osis_commit::verify_part(h, id, p, &d, &mut interner, None).is_ok()),
            _ => true,
        })
}

/// Whether `author` may grant on `x` now: admin, or an invite (spec/permissions.md §2).
fn may_grant(core: &Core, author: &Tid, x: &Tid) -> bool {
    let at = At::now(now_ts(core));
    core.role_now(author, x) == Some(Role::Admin) || core.timelines.get(x).and_then(|t| t.invite(author, x, at)).is_some()
}

/// Of `cands`, the actors this node holds a secret of and lost read access to
/// (spec/permissions.md §3): no role on them by any path now and no pending grant or `contested` thing reaching them.
/// Each actor is judged on its own, so what the node reached only through a lost one is lost
/// with it. (Epochs observed without a secret are no access.) An actor this node holds checked
/// secrets of is kept only by a plausible grant: anyone can send a pending commit, which is kept
/// until it applies, so any other would keep a node that lost access holding it for good;
/// reading-only candidates go with the commit that gave them.
fn lost_among(tx: &mut Tx<'_>, cands: Vec<Tid>) -> Result<Vec<Tid>> {
    let unread: Vec<Tid> = cands.into_iter().filter(|a| tx.core.ix.secrets.get(a).is_some_and(ActorEpochs::holds_any) && !readable(tx.core, a)).collect();
    if unread.is_empty() {
        return Ok(unread);
    }
    let pend = pending_grants(tx)?;
    let core = &*tx.core;
    let checked = |a: &Tid| core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).held().next().is_some()));
    let held: Vec<Tid> = unread.iter().filter(|k| contested(core, k)).copied().collect();
    let kept = |a: &Tid| pend.iter().any(|g| (g.plausible || !checked(a)) && reaches(core, &g.x, a)) || held.iter().any(|x| reaches(core, x, a));
    Ok(unread.into_iter().filter(|a| !kept(a)).collect())
}

/// Whether `k` is a thing where a held single-use redemption granting one of ours stands void
/// only because an applied redemption by the same signer removed the signer's edge first, with
/// no explicit write on that edge since: a link race the sharer has not finalized
/// (spec/permissions.md §3, §9). The finalization may drop the competing redemption and make
/// ours stand, so until it arrives the loser keeps the secrets (and with them follows the
/// labels) it would get back. A redemption is a commit removing its signer's own edge on `k`
/// beside a grant: a plain leave followed by a void grant (a leaver's forgery) defers nothing.
fn contested(core: &Core, k: &Tid) -> bool {
    let Some(tl) = core.timelines.get(k) else { return false };
    let op = |mc: &osis_perm::MembershipCommit, i: usize| osis_perm::WriteId::Op(mc.id, i as u32);
    // the index of the redemption's self-removal
    let leave = |mc: &osis_perm::MembershipCommit| {
        let j = mc.ops.iter().position(|o| o.target == *k && o.member == mc.author && o.edge.is_none())?;
        mc.ops.iter().any(|o| o.target == *k && o.member != mc.author && o.edge.is_some()).then_some(j)
    };
    let reds: Vec<_> = core.ix.by_thing.get(k).into_iter().flatten().filter_map(|c| tl.membership_commit(c)).filter_map(|mc| Some((mc, leave(mc)?))).collect();
    reds.iter().any(|(mc, j)| {
        tl.lowered_unaudited(&mc.author, k)
            && mc.ops.iter().enumerate().any(|(i, o)| i != *j && o.target == *k && o.edge.is_some() && ours(core, &o.member) && !tl.is_applied(&op(mc, i)))
            && reds.iter().any(|(w, jw)| w.author == mc.author && w.id != mc.id && tl.is_applied(&op(w, *jw)))
    })
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read.
fn drop_actors(tx: &mut Tx<'_>, lost: Vec<Tid>) -> Result<(Vec<Tid>, Forgotten)> {
    if lost.is_empty() {
        return Ok((lost, Forgotten::default()));
    }
    tx.core.touch();
    let held: BTreeMap<Tid, u64> = lost.iter().filter_map(|a| Some((*a, tx.core.ix.secrets.get(a)?.read.held().map(|(e, _)| e.n()).max()?))).collect();
    for a in &lost {
        tx.core.ix.secrets.remove(a);
        tx.core.membership_changed();
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: "lost read access: secrets and what only they read dropped".into() }, now);
    }
    let f = crate::retention::forget::forget(tx, &lost, &held)?;
    Ok((lost, f))
}

/// Drops every held actor this node lost read access to (the work list is done with it).
pub(crate) fn drop_lost(tx: &mut Tx<'_>) -> Result<(Vec<Tid>, Forgotten)> {
    take_due(tx)?;
    let all: Vec<Tid> = tx.core.ix.secrets.keys().copied().collect();
    let lost = lost_among(tx, all)?;
    drop_actors(tx, lost)
}

/// The trigger: takes the work list and drops the held actors a role on one of its things
/// reaches that this node lost read access to (idempotent: the list goes in the same
/// transaction).
pub(crate) fn drop_lost_due(tx: &mut Tx<'_>) -> Result<(Vec<Tid>, Forgotten)> {
    let due = take_due(tx)?;
    let cands: Vec<Tid> = tx.core.ix.secrets.keys().filter(|a| due.iter().any(|t| reaches(tx.core, t, a))).copied().collect();
    let lost = lost_among(tx, cands)?;
    drop_actors(tx, lost)
}

impl Engine {
    /// Rotations due before this node next encrypts under `actor`'s secrets (spec/permissions.md
    /// §3), performed now: labeling calls it before wrapping, stamping or boxing under the actor
    /// (or eagerly). Returns the commits written and the roles it still may not encrypt under.
    pub fn ensure_rotated(&mut self, actor: &Tid) -> Result<(Done, BTreeSet<Role>)> {
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            let me = tx.core.id.tid();
            let still = ensure_rotated(tx, me, a, &mut done)?;
            Ok((done, still))
        })
    }

    /// Every rotation this node may make that a known departure requires, now (the eager
    /// option).
    pub fn rotate_eagerly(&mut self) -> Result<Done> {
        let actors: Vec<Tid> = self.core.ix.own_keys.iter().copied().collect();
        let mut done = Done::default();
        for a in actors {
            done.extend(self.ensure_rotated(&a)?.0);
        }
        Ok(done)
    }

    /// The departures `actor`'s epochs must cover, as this node knows them.
    pub fn departures(&mut self, actor: &Tid) -> Result<Vec<Departure>> {
        let a = *actor;
        self.run(|tx| departures(tx, &a))
    }

    /// Gives `thing` secrets of its own (spec/permissions.md §3): before its first non-owner
    /// member, or before it is made a member of anything.
    pub fn give_own_secrets(&mut self, thing: &Tid) -> Result<Done> {
        let t = *thing;
        self.run(|tx| {
            let mut done = Done::default();
            own_secrets(tx, t, &mut done)?;
            Ok(done)
        })
    }

    /// Gives secrets of their own again to the plain things whose secrets derive from `actor`
    /// that this node administers and sees with a current non-owner member (spec/permissions.md
    /// §3), decided at the end of a complete pass of `actor`'s labels (`sync`); nothing
    /// otherwise. Each thing in a run of its own: one that fails leaves the others.
    pub fn own_secrets_due(&mut self, actor: &Tid, sync: &dyn SyncState) -> Result<Vec<(Tid, Result<Done>)>> {
        if !sync.complete_pass(actor) {
            return Ok(Vec::new());
        }
        let ts = own_secrets_candidates(&self.core, actor);
        Ok(ts.into_iter().map(|t| (t, self.run(|tx| own_secrets_delivered(tx, t)))).collect())
    }

    /// Re-seals the members of `actor` the trigger names (spec/permissions.md §3), decided at
    /// the end of a complete pass of its labels (`sync`); nothing otherwise.
    pub fn reseal_due(&mut self, actor: &Tid, sync: &dyn SyncState) -> Result<Done> {
        if !sync.complete_pass(actor) {
            return Ok(Done::default());
        }
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            for (m, roles) in reseal_candidates(tx, &a)? {
                done.extend(reseal_one(tx, a, m, &roles)?);
            }
            Ok(done)
        })
    }

    /// "Re-share with M" by hand (issues/reseal-triggers.md): re-seals current member `member`
    /// of `actor` for every role it holds that this node may rotate, whatever the trigger says
    /// (a member whose deposits are refused, a stranded heartbeat, a re-paired device).
    pub fn reshare(&mut self, actor: &Tid, member: &Tid) -> Result<Done> {
        let (a, m) = (*actor, *member);
        self.run(|tx| {
            let role = tx.core.current_members(&a).into_iter().find(|(x, _, _)| *x == m).map(|x| x.1).ok_or(Error::Misuse("not a current member"))?;
            let me = tx.core.id.tid();
            let may = may_rotate(tx.core, &me, &a);
            let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
            let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= role && may.contains(r) && !epochs.role(*r).newest_is_snapshot()).collect();
            if roles.is_empty() {
                return Err(Error::Misuse("this node may not re-seal that member"));
            }
            let deps = departures(tx, &a)?;
            let held = held_actors(tx)?;
            for &r in &roles {
                if !member_covers(tx, &held, &deps, &m, r)? {
                    return Err(Error::Misuse("the member's epoch does not cover a known departure (it must rotate first)"));
                }
            }
            reseal_one(tx, a, m, &roles)
        })
    }

    /// Drops the secrets of actors this node lost read access to, and of what it reached only
    /// through them, and forgets every thing it no longer reads by another path
    /// (spec/permissions.md §3), with a diagnostic per actor. Returns them.
    pub fn drop_lost_secrets(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(false)?.0)
    }

    /// Whether the lost-access trigger has work (`drop_lost_due`).
    pub fn lost_due(&self) -> bool {
        !self.core.ix.lost_due.is_empty()
    }

    /// The lost-access trigger (spec/permissions.md §3): after received membership commits
    /// applied, drops the secrets of the actors they touched that this node lost read access to
    /// by every path, unless a held pending grant reaches them, and forgets what only those
    /// read. node-sync runs it every step; an app driving the engine alone calls it after
    /// ingesting. Returns the actors dropped.
    pub fn drop_lost_due(&mut self) -> Result<Vec<Tid>> {
        Ok(self.forget_lost(true)?.0)
    }

    /// `drop_lost_secrets` (or, `due`, `drop_lost_due`), with what was forgotten (node-sync
    /// drops its label sessions).
    pub fn forget_lost(&mut self, due: bool) -> Result<(Vec<Tid>, Forgotten)> {
        let r = self.run(|tx| if due { drop_lost_due(tx) } else { drop_lost(tx) })?;
        if !r.1.things.is_empty() {
            self.reload()?;
            self.reexamine()?;
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::flows::{Demotion, PreSync};
    use crate::local_peer::LocalPeer;
    use crate::engine::Tx;
    use osis_base::{Role, Tid, WallMs};
    use osis_keys::Departure;
    use osis_schema::core_types as ct;
    use std::collections::{BTreeMap, BTreeSet};

    /// Delivers every commit of peer `from` to peer `to` without the `/secrets` deltas of `x`
    /// (what a node that does not read `x` gets of them: certificates).
    fn deliver_without_secrets(lp: &mut LocalPeer, from: usize, to: usize, x: Tid) {
        for pk in lp.packages(from).unwrap() {
            let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            let cut = osis_commit::rewrite(&b, |ai, _| b.header.aspects.get(ai).is_some_and(|a| a.tid == x && a.ak.as_str() == "/secrets"));
            let _ = lp.peers[to].engine.ingest(&cut.encode(), pk.blobs.clone());
        }
    }

    /// Peers: 0 = a (G's admin), 1 = b (X's admin), 2 = W, 3 = Z (members of X); X a writer
    /// of G. Every commit reaches a without X's `/secrets` deltas when `strip`.
    fn team(seed: u64) -> (LocalPeer, Tid, Tid, Tid, Tid) {
        let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b, w, z) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
        let mut m = Mutation::new();
        let x = lp.peers[1].engine.new_thing(&mut m, b);
        lp.peers[1].commit(m).unwrap();
        lp.peers[1].engine.give_own_secrets(&x).unwrap();
        lp.peers[1].engine.grant(&x, &w, &write).unwrap();
        lp.peers[1].engine.grant(&x, &z, &write).unwrap();
        lp.sync(1, 2).unwrap();
        lp.sync(1, 3).unwrap();
        deliver_without_secrets(&mut lp, 1, 0, x);
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        lp.peers[0].engine.grant(&g, &x, &write).unwrap();
        assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "covered before");
        (lp, x, g, w, z)
    }

    // spec/crypto.md §4 (times are the authors' word: only the departure's own commit setting
    // M's keyset, or a held rotation delta without the leaver's box, shows it unboxed): W leaves
    // X by itself with a `ts` before a rotation of X that, made unaware of it (b removes Z),
    // still boxed W; G's admin, holding none of X's `/secrets`, keeps G's epoch uncovered.
    #[test]
    fn backdated_self_removal_uncovered_spec_crypto_4() {
        let (mut lp, x, g, w, z) = team(932);
        // b's clock runs ahead of W's: its rotation's ts is later than W's departure
        lp.peers[1].clock.advance(120_000);
        lp.peers[1].engine.demote(&x, &Demotion { member: z, new: None, presync: PreSync::Synced }).unwrap();
        lp.peers[2].engine.demote(&x, &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap();
        deliver_without_secrets(&mut lp, 1, 0, x);
        deliver_without_secrets(&mut lp, 2, 0, x);
        assert_eq!(lp.peers[0].engine.roster(&x).get(&w), None, "a sees W gone");
        let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
        assert!(still.contains(&Role::Read), "W's departure is not covered by the later-stamped rotation: {still:?}");
    }

    // spec/crypto.md §4: the same unaware rotation, its `/secrets` delta held by G's admin: the
    // delta boxes W, so the departure stays uncovered; after a rotation of X by an admin that
    // saw W leave (its delta boxes no W), G's admin rotates G and covers it.
    #[test]
    fn unaware_rotation_uncovered_aware_covers_spec_crypto_4() {
        let (mut lp, x, g, w, z) = team(933);
        lp.peers[1].clock.advance(120_000);
        lp.peers[1].engine.demote(&x, &Demotion { member: z, new: None, presync: PreSync::Synced }).unwrap();
        lp.peers[2].engine.demote(&x, &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap();
        lp.sync(1, 0).unwrap();
        lp.sync(2, 0).unwrap();
        let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
        assert!(still.contains(&Role::Read), "the unaware rotation boxed W: {still:?}");
        // b learns of W's departure and rotates X again
        lp.sync(2, 1).unwrap();
        lp.peers[1].engine.rotate_eagerly().unwrap();
        lp.sync(1, 0).unwrap();
        let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
        assert!(still.is_empty(), "an aware rotation of X lets G's admin rotate G and cover W: {still:?}");
    }

    // spec/permissions.md §4 (exception: under an uncovered epoch a non-rotator places only the
    // revokes of the departures that leave it uncovered now): Z's removal from X, which G's
    // admin already covered by rotating G, is not among them; W's later self-removal is.
    #[test]
    fn only_uncovering_revokes_placed_spec_permissions_4() {
        let (mut lp, x, g, w, z) = team(934);
        let rz = *lp.peers[1].engine.demote(&x, &Demotion { member: z, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
        lp.sync(1, 0).unwrap();
        assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "G's admin rotated G past Z's removal");
        lp.sync(1, 2).unwrap();
        let rw = *lp.peers[2].engine.demote(&x, &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
        lp.sync(2, 0).unwrap();
        let revokes = lp.peers[0].engine.inside_member_revokes(&g, &Default::default());
        assert!(revokes.contains_key(&rw), "W's self-removal leaves G uncovered");
        // Z's removal may ride along as chain material (edges), never as a whole write
        let h = lp.peers[0].engine.header(&rz).unwrap();
        let si = h.aspects.iter().position(|a| a.tid == x && a.ak.as_str() == "/secrets").unwrap();
        assert!(revokes.get(&rz).is_none_or(|p| p.iter().all(|(ai, _)| *ai != si)), "Z's removal is covered: not placed whole");
    }

    // spec/permissions.md §4 (the revoke of a departure inside a member is the write lowering
    // the departed member's edge on the actor it left, the last on its chain): G <- X1 <- ... <-
    // Xk, W a writer of Xk leaves it by itself; G's admin finds W's removal on Xk at every depth.
    #[test]
    fn nested_departure_revoke_is_the_leavers_write_spec_permissions_4() {
        for k in 1..=4 {
            let mut lp = LocalPeer::new(3, 935 + k as u64, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let w = lp.peers[2].engine.tid();
            let xs: Vec<Tid> = (0..k).map(|_| group(&mut lp, 1)).collect();
            lp.peers[1].engine.grant(&xs[k - 1], &w, &edge(Role::Write)).unwrap();
            for i in (1..k).rev() {
                lp.peers[1].engine.grant(&xs[i - 1], &xs[i], &edge(Role::Write)).unwrap();
            }
            let g = group(&mut lp, 0);
            lp.sync_all().unwrap();
            lp.peers[0].engine.grant(&g, &xs[0], &edge(Role::Write)).unwrap();
            assert!(lp.peers[0].engine.inside_member_revokes(&g, &Default::default()).is_empty(), "k={k}: nothing departed yet");
            let rw = *lp.peers[2].engine.demote(&xs[k - 1], &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
            lp.sync(2, 0).unwrap();
            assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.contains(&Role::Read), "k={k}: W's departure leaves G uncovered");
            let revokes = lp.peers[0].engine.inside_member_revokes(&g, &Default::default());
            assert!(revokes.contains_key(&rw), "k={k}: W's removal from X{k} is placed");
        }
    }

    // spec/crypto.md §4 (a node holding no secret of member M judges by M's keyset and the
    // boxes of M it holds; holding none, a departure from M that M's keyset predates is not
    // covered): W leaves team X by self-removal (nothing rotates X); G's admin, who holds no
    // secret and no `/secrets` of X, must not count G's epoch as covering W's departure inside
    // X (W still reads through X's old epoch), and cannot fix it by rotating G.
    #[test]
    fn departure_inside_unheld_actor_uncovered_spec_crypto_4() {
        let mut lp = LocalPeer::new(3, 931, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
        // X: b's team with W
        let mut m = Mutation::new();
        let x = lp.peers[1].engine.new_thing(&mut m, b);
        lp.peers[1].commit(m).unwrap();
        lp.peers[1].engine.give_own_secrets(&x).unwrap();
        lp.peers[1].engine.grant(&x, &w, &write).unwrap();
        lp.sync(1, 2).unwrap();
        deliver_without_secrets(&mut lp, 1, 0, x);
        // G: a's group, X a writer of it
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        lp.peers[0].engine.grant(&g, &x, &write).unwrap();
        assert!(lp.peers[0].engine.get_typed(&x, &ct::SECRETS).unwrap().is_none_or(|s| s.boxes.is_empty()), "a holds nothing of X's /secrets");
        assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "covered before");
        // W leaves X by itself: no rotation of X
        lp.peers[2].engine.demote(&x, &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap();
        deliver_without_secrets(&mut lp, 2, 0, x);
        assert_eq!(lp.peers[0].engine.roster(&x).get(&w), None, "a sees W gone");
        let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
        assert!(still.contains(&Role::Read), "W's departure inside X is not covered: {still:?}");
    }

    /// Peers: 0 = the owner of group `t`, 1 = W (a writer, then removed: rotation R1 of read
    /// and write), 2 = P (an admin), 3 = N (an admin when `n_first`, else granted later by the
    /// caller). Returns R1's commits.
    fn removed_writer(seed: u64, n_first: bool) -> (LocalPeer, Tid, Vec<osis_base::CommitId>) {
        let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let t = group(&mut lp, 0);
        let (w, p, n) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&t, &p, &edge(Role::Admin)).unwrap();
        if n_first {
            lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
        }
        lp.sync_all().unwrap();
        let r1 = lp.peers[0].engine.demote(&t, &Demotion { member: w, new: None, presync: PreSync::Synced }).unwrap().commits;
        (lp, t, r1)
    }

    fn uncovered_at(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<Role> {
        lp.peers[i].engine.run(|tx| super::uncovered_roles(tx, &t)).unwrap()
    }

    fn keys_secrets() -> [osis_base::Ak; 2] {
        ["/keys", "/secrets"].map(|k| osis_base::Ak::new(k).unwrap())
    }

    // spec/crypto.md §4 (an epoch whose rotation commit a rotator does not hold counts as
    // written by any departed party that could have rotated it): N, granted admin after the
    // owner compacted and dropped R1's bodies, does not know who wrote the read epoch, and W (a
    // writer) is gone: it rotates read before encrypting under it. Holding R1 it does not.
    #[test]
    fn unheld_rotation_counts_as_departed_partys_spec_crypto_4() {
        for compact in [true, false] {
            let (mut lp, t, r1) = removed_writer(941, false);
            if compact {
                for k in keys_secrets() {
                    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
                    for c in &r1 {
                        if lp.peers[0].engine.body_not_dropped(c, &t, &k) {
                            lp.peers[0].engine.drop_body(c, &t, &k).unwrap();
                        }
                    }
                }
            }
            let n = lp.peers[3].engine.tid();
            lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
            lp.sync(0, 3).unwrap();
            let before = newest_read(&lp, 3, t);
            assert!(before.is_some(), "N holds the read epoch");
            if !compact {
                assert!(uncovered_at(&mut lp, 3, t).is_empty(), "R1 held: covered");
                assert!(lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "no extra rotation");
                continue;
            }
            assert!(uncovered_at(&mut lp, 3, t).contains(&Role::Read), "introducer unknown, a writer gone");
            let (done, still) = lp.peers[3].engine.ensure_rotated(&t).unwrap();
            assert!(!done.commits.is_empty() && still.is_empty(), "{still:?}");
            assert_ne!(newest_read(&lp, 3, t), before, "rotated");
            assert!(uncovered_at(&mut lp, 3, t).is_empty(), "its own rotation is known");
            // the owner, holding R1's record, needs no rotation
            assert!(uncovered_at(&mut lp, 0, t).is_empty());
        }
    }

    // spec/crypto.md §4, spec/permissions.md §5.2: N drops R1's `/keys` body under admin P's
    // compaction snapshot S; the owner then demotes P with a frontier not listing S, so S turns
    // invalid and that body is missing again at N (R1's `/secrets` still held): the read epoch's
    // introducer is unknown there and N rotates read.
    #[test]
    fn rotation_missing_again_counts_as_departed_partys_spec_crypto_4() {
        let (mut lp, t, r1) = removed_writer(942, true);
        lp.sync_all().unwrap();
        let p = lp.peers[2].engine.tid();
        let k = osis_base::Ak::new("/keys").unwrap();
        let s = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
        let pk = lp.peers[2].engine.package(&s).unwrap().unwrap();
        lp.deliver(3, &pk).unwrap();
        for c in &r1 {
            let e = &mut lp.peers[3].engine;
            if e.body_not_dropped(c, &t, &k) && e.covered(&s, c, &t, &k).unwrap() == Some(true) {
                e.drop_body(c, &t, &k).unwrap();
            }
        }
        assert!(r1.iter().any(|c| !lp.peers[3].engine.body_not_dropped(c, &t, &k)), "R1's /keys dropped at N");
        assert!(uncovered_at(&mut lp, 3, t).is_empty(), "the dropped rotation stays known");
        lp.peers[0].engine.demote(&t, &Demotion { member: p, new: Some(edge(Role::Read)), presync: PreSync::Synced }).unwrap();
        lp.sync(0, 3).unwrap();
        assert!(!lp.peers[3].engine.core.ix.commits.get(&s).unwrap().valid.iter().any(|v| *v), "S invalid at N");
        assert!(uncovered_at(&mut lp, 3, t).contains(&Role::Read), "R1 missing again: introducer unknown");
        let (done, still) = lp.peers[3].engine.ensure_rotated(&t).unwrap();
        assert!(!done.commits.is_empty() && still.is_empty(), "{still:?}");
    }

    /// A thing of peer `i`'s with secrets of its own.
    fn group(lp: &mut LocalPeer, i: usize) -> Tid {
        let me = lp.peers[i].engine.tid();
        let mut m = Mutation::new();
        let g = lp.peers[i].engine.new_thing(&mut m, me);
        lp.peers[i].commit(m).unwrap();
        lp.peers[i].engine.give_own_secrets(&g).unwrap();
        g
    }

    fn edge(role: Role) -> ct::Edge {
        ct::Edge { role, until: None, invite: None, since: None }
    }

    fn newest_read(lp: &LocalPeer, i: usize, t: Tid) -> Option<osis_crypto::Epoch> {
        lp.peers[i].engine.epochs(&t).and_then(|e| e.read.newest_held().map(|x| x.0))
    }

    /// Every chain of at most `depth` actors below `a` (revisits allowed, never through the
    /// departed member), one departure each: the oracle of `walk_matches_path_walk` and
    /// `walk_with_cycles_keeps_every_bounded_chain`.
    fn path_walk(tx: &mut Tx<'_>, a: &Tid, depth: usize, out: &mut BTreeSet<Departure>) -> crate::error::Result<()> {
        let mut mine = super::direct_departures(tx, a, &mut None)?;
        if depth > 0 {
            for (x, _, _) in tx.core.current_members(a) {
                if x == *a || !tx.core.has_own_secrets(&x) {
                    continue;
                }
                let mut inner = BTreeSet::new();
                path_walk(tx, &x, depth - 1, &mut inner)?;
                for d in inner {
                    if d.member != *a {
                        mine.insert(Departure::inside(x, &d));
                    }
                }
            }
        }
        out.extend(mine);
        Ok(())
    }

    type Key = (Option<Tid>, Option<Tid>, Tid, Tid, Role);
    type Decisions = (BTreeSet<(Key, [bool; 3])>, Vec<BTreeSet<Key>>, BTreeSet<Role>);

    /// What the rotation decisions read of departures `deps` of `a`: each class (first and
    /// second actor, actor left, member, role) with the first actor's verdicts, the uncovered
    /// classes per role at `a`'s newest held epoch, and the uncovered roles.
    fn decisions(tx: &mut Tx<'_>, a: &Tid, deps: Vec<Departure>) -> Decisions {
        let held = super::held_actors(tx).unwrap();
        let secrets = crate::flows::secrets_in(tx, a).unwrap();
        let held = super::Judge::new(tx.core, &held);
        let key = |d: &Departure| (d.via.first().copied(), d.via.get(1).copied(), d.via.last().copied().unwrap_or(*a), d.member, d.from);
        let classes = deps
            .iter()
            .map(|d| match d.via.split_first() {
                Some((m, rest)) => (key(d), super::verdicts(&held, m, &Departure { via: rest.clone(), member: d.member, from: d.from })),
                None => (key(d), super::verdicts(&held, a, d)),
            })
            .collect();
        let mut per_role = Vec::new();
        if let Some(epochs) = tx.core.epochs(a) {
            for r in osis_keys::ROLES {
                let un = epochs.role(r).newest_held().map(|(e, _)| osis_keys::uncovered(a, &secrets, &epochs, r, &e, &deps, &held).into_iter().map(key).collect()).unwrap_or_default();
                per_role.push(un);
            }
        }
        let roles = super::uncovered_roles_of(tx, a, deps).unwrap();
        (classes, per_role, roles)
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self, n: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % n
        }
    }

    /// Random member graphs of 7 actors (with back edges: cycles, when `cyclic`), three leaf
    /// nodes, random removals, demotions and partial cascades; compares, for every actor, the
    /// rotation decisions from `departures` with those from the path walk.
    fn differential(seed: u64, cyclic: bool) -> (usize, usize) {
        const N: usize = 7;
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let leaves = [1, 2, 3].map(|i| lp.peers[i].engine.tid());
        let gs: Vec<Tid> = (0..N).map(|_| group(&mut lp, 0)).collect();
        let roles = [Role::Read, Role::Write, Role::Admin];
        let mut edges: Vec<(Tid, Tid)> = Vec::new();
        for i in 0..N {
            for j in 0..N {
                let p = if i < j { 50 } else if cyclic && i > j { 12 } else { 0 };
                if rng.next(100) < p && lp.peers[0].engine.grant(&gs[i], &gs[j], &edge(roles[rng.next(3) as usize])).is_ok() {
                    edges.push((gs[i], gs[j]));
                }
            }
        }
        let mut leaf_edges: Vec<(Tid, Tid)> = Vec::new();
        for l in leaves {
            for _ in 0..3 {
                let g = gs[N / 2 + rng.next((N - N / 2) as u64) as usize];
                if lp.peers[0].engine.grant(&g, &l, &edge(roles[rng.next(3) as usize])).is_ok() {
                    leaf_edges.push((g, l));
                }
            }
        }
        for _ in 0..8 {
            let pick = rng.next(10);
            let pool = if pick < 7 { &leaf_edges } else { &edges };
            if pick < 9 && !pool.is_empty() {
                let (t, m) = pool[rng.next(pool.len() as u64) as usize];
                let new = [None, Some(edge(Role::Read)), Some(edge(Role::Write))][rng.next(3) as usize].clone();
                let _ = lp.peers[0].engine.demote(&t, &Demotion { member: m, new, presync: PreSync::Synced });
            } else {
                let _ = lp.peers[0].engine.ensure_rotated(&gs[rng.next(N as u64) as usize]);
            }
        }
        let (mut same, mut all) = (0, 0);
        for a in &gs {
            let a = *a;
            let (old, new) = lp.peers[0]
                .engine
                .run(|tx| {
                    let mut out = BTreeSet::new();
                    path_walk(tx, &a, 8, &mut out)?;
                    let old = decisions(tx, &a, out.into_iter().collect());
                    let deps = super::departures(tx, &a)?;
                    let new = decisions(tx, &a, deps);
                    Ok((old, new))
                })
                .unwrap();
            all += 1;
            if old == new {
                same += 1;
            } else {
                // with cycles, a chain longer than the bounded walk's could add a class
                assert!(cyclic, "seed {seed}: {a:?}\nold {old:?}\nnew {new:?}");
                assert!(old.0.is_subset(&new.0) && old.2.is_subset(&new.2), "seed {seed}: every bounded chain's class is kept");
            }
        }
        (same, all)
    }

    // spec/crypto.md §4: on acyclic member graphs (depth under the old cap), one departure per
    // class gives exactly the path walk's rotation decisions.
    #[test]
    fn walk_matches_path_walk() {
        for seed in 0..6 {
            differential(7_100 + seed, false);
        }
    }

    // spec/crypto.md §4: with cycles, the walk's classes and decisions are those of every
    // chain up to 8 actors, revisits included (the merge is exact; on these seeds no longer
    // chain adds a class).
    #[test]
    fn walk_with_cycles_keeps_every_bounded_chain() {
        let (mut same, mut all) = (0, 0);
        for seed in 0..6 {
            let (s, n) = differential(7_200 + seed, true);
            same += s;
            all += n;
        }
        assert_eq!(same, all, "{same} of {all} alike");
    }

    /// The walk over a chain G0 (the walked actor) <- G1 <- ... <- GL, departures from the
    /// levels in `departed`: (kept departures, distinct chain hops they hold, chain actors they
    /// would hold unshared).
    fn chain_walk(l: usize, departed: impl Fn(usize) -> bool) -> (usize, usize, usize) {
        let t = |i: usize| Tid::from_bytes({
            let mut b = [0u8; 15];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            b
        });
        let leaf = |i: usize| t(i + 1_000_000);
        let parents: BTreeMap<Tid, Vec<Tid>> = (1..=l).map(|i| (t(i), vec![t(i - 1)])).collect();
        let direct = (1..=l).map(|i| (t(i), if departed(i) { BTreeSet::from([Departure::member(leaf(i), Role::Read)]) } else { BTreeSet::new() })).collect();
        let held = osis_keys::MemoryHeldActors::default();
        let found = super::walk(&parents, direct, |v, d| super::class_of(&held, v, d));
        let deps: Vec<&Departure> = found.iter().filter(|(v, _)| **v != t(0)).flat_map(|(_, f)| f.values()).collect();
        let hops: std::collections::HashSet<usize> = deps.iter().flat_map(|d| d.via.hop_ids()).collect();
        (deps.len(), hops.len(), deps.iter().map(|d| d.via.len()).sum())
    }

    // issues/rotation-chain-cost.md: the walk's memory is linear in the departures it keeps
    // (one hop each, tails shared), not in the sum of their chain lengths.
    #[test]
    fn walk_memory_linear_in_chain_depth() {
        for l in [100, 1000] {
            let (kept, hops, unshared) = chain_walk(l, |i| i == l);
            assert_eq!((kept, hops, unshared), (l, l - 1, l * (l - 1) / 2), "L = {l}");
        }
        // a departure at every level: kept departures grow with L^2, each holding one hop
        for l in [100, 200] {
            let (kept, hops, _) = chain_walk(l, |_| true);
            assert_eq!((kept, hops), (l * (l + 1) / 2, l * (l - 1) / 2), "L = {l}");
        }
    }

    // spec/crypto.md §4 (no depth bound): a node removed 12 actors below G0 (G11 in G10 ... in
    // G0): the cascade rotates every level, top-down, and the removed node holds none of it.
    #[test]
    fn removal_twelve_deep_rotates_every_level_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 941, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let gs: Vec<Tid> = (0..12).map(|_| group(&mut lp, 0)).collect();
        for w in gs.windows(2) {
            lp.peers[0].engine.grant(&w[0], &w[1], &edge(Role::Write)).unwrap();
        }
        lp.peers[0].engine.grant(&gs[11], &d, &edge(Role::Write)).unwrap();
        lp.sync(0, 1).unwrap();
        assert!(newest_read(&lp, 1, gs[0]).is_some(), "d reads G0 through 11 actors");
        let before: Vec<_> = gs.iter().map(|g| newest_read(&lp, 0, *g)).collect();
        lp.peers[0].engine.demote(&gs[11], &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let deps = lp.peers[0].engine.departures(&gs[0]).unwrap();
        assert!(deps.iter().any(|x| x.member == d && x.via == gs[1..].to_vec()), "{deps:?}");
        let (done, still) = lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 11, "G10 up to G0");
        for (i, g) in gs.iter().enumerate() {
            assert_ne!(newest_read(&lp, 0, *g), before[i], "G{i} rotated");
        }
        assert!(lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap().0.commits.is_empty(), "covered");
        lp.sync(0, 1).unwrap();
        let top = newest_read(&lp, 0, gs[0]).unwrap();
        assert!(lp.peers[1].engine.epochs(&gs[0]).unwrap().read.secret(&top).is_none(), "d does not hold G0's new secret");
    }

    // spec/crypto.md §4, spec/permissions.md §3: a diamond (A over X and Y, both over Z) and a
    // cycle (A over P, P and Q members of each other): a removal from Z, and from Q, rotates
    // each intermediate once, and a second cascade finds nothing to do.
    #[test]
    fn diamond_and_cycle_rotate_once_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 942, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let [a, x, y, z] = [0; 4].map(|_| group(&mut lp, 0));
        for (t, m) in [(a, x), (a, y), (x, z), (y, z)] {
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
        }
        lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.demote(&z, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let (done, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 3, "X, Y, then A");
        assert!(lp.peers[0].engine.ensure_rotated(&a).unwrap().0.commits.is_empty());
        let [b, p, q] = [0; 3].map(|_| group(&mut lp, 0));
        for (t, m) in [(b, p), (p, q), (q, p)] {
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
        }
        lp.peers[0].engine.grant(&q, &d, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.demote(&q, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let (done, still) = lp.peers[0].engine.ensure_rotated(&b).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 2, "P, then B (the removal rotated Q, leaving P out)");
        assert_eq!(lp.peers[0].engine.reseal_due(&q, &Pass).unwrap().commits.len(), 1, "P re-sealed on Q");
        assert!(lp.peers[0].engine.ensure_rotated(&b).unwrap().0.commits.is_empty(), "no churn around the cycle");
        assert!(lp.peers[0].engine.reseal_due(&q, &Pass).unwrap().commits.is_empty());
    }

    /// Every (actor, role, epoch) of `actors` a party holding `known` opens from the `/secrets`
    /// peer `i` holds of them: a box to `party` itself, or to a member at a keyset (sealed) or
    /// secret (symmetric) epoch known, transitively. What a departed party that kept its secrets
    /// can read, whatever its own node does.
    fn openable(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, mut known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
        use osis_keys::aspects::from_schema;
        let all: Vec<(Tid, ct::Secrets)> = actors.iter().filter_map(|a| lp.peers[i].engine.get_typed(a, &ct::SECRETS).unwrap().map(|s| (*a, s))).collect();
        // a box to the party itself (a key actor) carries every role at or below its key's
        if let Some(p) = lp.peers.iter().find(|p| p.engine.tid() == party) {
            let seed = p.engine.core.id.seed().clone();
            for (a, s) in &all {
                for o in osis_keys::open_boxes(a, s, &osis_keys::Opener::KeyActor { member: party, seed: &seed }).0 {
                    known.insert((*a, o.role, o.epoch));
                }
            }
        }
        loop {
            let n = known.len();
            for (a, s) in &all {
                for (k, b) in &s.boxes {
                    let Ok(e) = from_schema(&k.epoch) else { continue };
                    let via = match b {
                        ct::SecretBox::Sealed(sb) => sb.keyset.as_ref().and_then(|x| from_schema(x).ok()),
                        ct::SecretBox::Symmetric(sb) => from_schema(&sb.epoch).ok(),
                    };
                    if k.member == party || via.is_some_and(|x| known.contains(&(k.member, k.role, x))) {
                        known.insert((*a, k.role, e));
                    }
                }
            }
            if known.len() == n {
                return known;
            }
        }
    }

    /// The epochs of `actors` whose secrets peer `i` holds.
    fn held_by(lp: &LocalPeer, i: usize, actors: &[Tid]) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
        let mut out = BTreeSet::new();
        for a in actors {
            if let Some(e) = lp.peers[i].engine.epochs(a) {
                for r in osis_keys::ROLES {
                    out.extend(e.role(r).held().map(|(ep, _)| (*a, r, ep)));
                }
            }
        }
        out
    }

    /// Peer `i`'s newest read epoch of each of `actors` that `party` opens from `known`.
    fn leaked(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> Vec<Tid> {
        let o = openable(lp, i, actors, party, known);
        actors.iter().filter(|t| newest_read(lp, i, **t).is_some_and(|e| o.contains(&(**t, Role::Read, e)))).copied().collect()
    }

    /// A complete pass of every actor's labels (re-seal decisions in tests).
    struct Pass;
    impl crate::flows::SyncState for Pass {
        fn complete_pass(&self, _: &Tid) -> bool {
            true
        }
    }

    /// Rounds of every peer of `admins` acting alone on every actor of `actors` (the cascade,
    /// then the re-seal trigger), synced after each, until nothing changes; the rounds taken.
    fn settle(lp: &mut LocalPeer, admins: &[usize], actors: &[Tid]) -> usize {
        for round in 0..8 {
            let mut n = 0;
            for &p in admins {
                for x in actors {
                    n += lp.peers[p].engine.ensure_rotated(x).unwrap().0.commits.len();
                    n += lp.peers[p].engine.reseal_due(x, &Pass).unwrap().commits.len();
                }
                lp.sync_all().unwrap();
            }
            if n == 0 {
                return round;
            }
        }
        panic!("no fixpoint in 8 rounds");
    }

    /// Whether every current member of each of `actors`, at peer `i`, holds a box at each
    /// current epoch of its roles (left-out members re-sealed).
    fn all_boxed(lp: &mut LocalPeer, i: usize, actors: &[Tid]) -> bool {
        actors.iter().all(|t| {
            let e = lp.peers[i].engine.epochs(t).unwrap();
            let s = lp.peers[i].engine.get_typed(t, &ct::SECRETS).unwrap().unwrap();
            let core = &lp.peers[i].engine.core;
            let ms: Vec<osis_keys::Member> = core.current_members(t).into_iter().map(|(member, role, until)| osis_keys::Member { member, role, until }).collect();
            osis_keys::reseal_needed(&s, &e, &ms, core.now(), &|_, _, _| true).is_empty()
        })
    }

    // spec/crypto.md §4, spec/permissions.md §3 (left out): X and Y readers of each
    // other, D a reader of X (2-cycle), or X <- Y <- Z <- X (3-cycle). D's removal from X
    // rotates X, leaving out its member actor whose epoch D opens; D, keeping its old secrets,
    // opens no epoch judged covered after the removal, and no new epoch after the cascade and
    // re-seals, after which every member is boxed again and a remaining member of X reads the
    // whole cycle.
    #[test]
    fn removal_in_cycle_leaves_out_spec_crypto_4() {
        for len in [2, 3] {
            let mut lp = LocalPeer::new(3, 950 + len as u64, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let (d, n) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
            let cyc: Vec<Tid> = (0..len).map(|_| group(&mut lp, 0)).collect();
            for i in 0..len {
                lp.peers[0].engine.grant(&cyc[i], &cyc[(i + 1) % len], &edge(Role::Read)).unwrap();
            }
            lp.peers[0].engine.grant(&cyc[0], &d, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.grant(&cyc[0], &n, &edge(Role::Read)).unwrap();
            lp.sync(0, 1).unwrap();
            let start = held_by(&lp, 1, &cyc);
            assert!(cyc.iter().all(|t| start.contains(&(*t, Role::Read, newest_read(&lp, 0, *t).unwrap()))), "len {len}: D reads the whole cycle");
            lp.peers[0].engine.demote(&cyc[0], &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
            let gs: Vec<(Tid, usize)> = cyc.iter().map(|t| (*t, 0)).collect();
            assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "len {len}: after the removal");
            assert!(!all_boxed(&mut lp, 0, &cyc), "len {len}: the member actor is left out");
            settle(&mut lp, &[0], &cyc);
            for t in &cyc {
                assert!(uncovered_at(&mut lp, 0, *t).is_empty(), "len {len}");
            }
            assert!(all_boxed(&mut lp, 0, &cyc), "len {len}: re-sealed");
            assert_eq!(leaked(&mut lp, 0, &cyc, d, start), Vec::<Tid>::new(), "len {len}: after the cascade");
            lp.sync(0, 2).unwrap();
            for t in &cyc {
                assert_eq!(newest_read(&lp, 2, *t), newest_read(&lp, 0, *t), "len {len}: N reads the cycle");
            }
        }
    }

    // spec/crypto.md §4, spec/permissions.md §3: X and Y readers of each other, Z a reader of
    // X, D a reader of Z. D's removal from Z leaves X uncovered also through Y (X <- Y <- X <-
    // Z); the cascade rotates Y (leaving X out), then X, a re-seal boxes X on Y again, and D
    // opens no new epoch.
    #[test]
    fn departure_below_cycle_leaves_out_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 953, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let [x, y, z] = [0; 3].map(|_| group(&mut lp, 0));
        for (t, m) in [(x, y), (y, x), (x, z)] {
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
        }
        lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
        lp.sync(0, 1).unwrap();
        let all = [x, y, z];
        let start = held_by(&lp, 1, &all);
        lp.peers[0].engine.demote(&z, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let deps = lp.peers[0].engine.departures(&x).unwrap();
        assert!(deps.iter().any(|q| q.member == d && q.via == vec![y, x, z]), "{deps:?}");
        let (done, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 2, "Y (leaving X out), then X");
        assert_eq!(leaked(&mut lp, 0, &all, d, start.clone()), Vec::<Tid>::new());
        assert!(lp.peers[0].engine.ensure_rotated(&y).unwrap().0.commits.is_empty(), "Y covered too");
        assert_eq!(lp.peers[0].engine.reseal_due(&y, &Pass).unwrap().commits.len(), 1, "X re-sealed on Y");
        assert!(all_boxed(&mut lp, 0, &all));
        assert_eq!(leaked(&mut lp, 0, &all, d, start), Vec::<Tid>::new());
        assert_eq!(settle(&mut lp, &[0], &all), 0, "settled");
    }

    // spec/permissions.md §3 (Membership cycles; each admin acts alone): X (peer 0's) and Y
    // (peer 2's) readers of each other, no common admin (two people's shared tags), D a reader
    // of X. Peer 0 removes D: X rotates leaving Y out (Y's epoch boxes X's old one, which D
    // holds), so peer 0 may encrypt under X at once. Peer 2's cascade rotates Y, boxing X's new
    // epoch; peer 0's re-seal trigger then boxes X to Y's new one. D opens neither.
    #[test]
    fn cycle_with_disjoint_admins_converges_spec_permissions_3() {
        let mut lp = LocalPeer::new(3, 955, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let x = group(&mut lp, 0);
        let y = group(&mut lp, 2);
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&x, &d, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let start = held_by(&lp, 1, &[x, y]);
        assert!(start.contains(&(y, Role::Read, newest_read(&lp, 1, y).unwrap())), "D reads Y through X");
        lp.peers[0].engine.demote(&x, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let (_, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
        assert!(still.is_empty(), "peer 0 not stranded on X: {still:?}");
        assert!(lp.peers[0].engine.reseal_due(&x, &Pass).unwrap().commits.is_empty(), "Y not re-sealed before it rotates");
        lp.sync(0, 2).unwrap();
        let (done, still) = lp.peers[2].engine.ensure_rotated(&y).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 1, "Y");
        lp.sync(2, 0).unwrap();
        assert_eq!(lp.peers[0].engine.reseal_due(&x, &Pass).unwrap().commits.len(), 1, "Y re-sealed on X");
        lp.sync_all().unwrap();
        for i in [0, 2] {
            assert!(all_boxed(&mut lp, i, &[x, y]));
            assert_eq!(leaked(&mut lp, i, &[x, y], d, start.clone()), Vec::<Tid>::new());
        }
        assert_eq!(settle(&mut lp, &[0, 2], &[x, y]), 0, "settled");
    }

    // spec/permissions.md §3 (left out), §2 (invite grants): D leaves M by itself (no rotation
    // of M yet). A grant of M on T by a node that may not rotate M (a reader of M; T's admin,
    // or an invite holder on T whose grant then carries no box and stays valid) would box T's
    // epoch to M's newest, which D holds, so it leaves M out; M is re-sealed on T once M's admin
    // rotates it. A granter that may rotate M rotates it first and boxes M at once
    // (spec/crypto.md §4: boxing to M is encrypting under M's epoch).
    #[test]
    fn grant_to_stale_member_leaves_out_spec_permissions_3() {
        // granter: 0 T's admin reading M, 2 M's admin owning T, 0 by invite on T owned by 3
        for (g, owner) in [(0, 0), (2, 2), (0, 3)] {
            let mut lp = LocalPeer::new(4, 957, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let d = lp.peers[1].engine.tid();
            let p0 = lp.peers[0].engine.tid();
            let m = group(&mut lp, 2);
            lp.peers[2].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
            lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
            let t = group(&mut lp, owner);
            if owner != g {
                lp.peers[owner].engine.grant(&t, &p0, &ct::Edge { invite: Some(Role::Write), ..edge(Role::Write) }).unwrap();
            }
            lp.sync_all().unwrap();
            let start = held_by(&lp, 1, &[m]);
            lp.peers[1].engine.demote(&m, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
            lp.sync_all().unwrap();
            assert!(uncovered_at(&mut lp, 0, m).contains(&Role::Read), "M stale");
            lp.peers[g].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
            lp.sync_all().unwrap();
            assert_eq!(lp.peers[owner].engine.roster(&t).get(&m).map(|e| e.role), Some(Role::Write), "a valid grant");
            assert!(!leaked(&mut lp, owner, &[m, t], d, start.clone()).contains(&t), "after the grant");
            assert_eq!(all_boxed(&mut lp, owner, &[t]), g == 2, "M left out unless its admin granted");
            settle(&mut lp, &[2, owner], &[m, t]);
            assert!(all_boxed(&mut lp, owner, &[m, t]), "re-sealed");
            assert_eq!(leaked(&mut lp, owner, &[m, t], d, start), Vec::<Tid>::new());
        }
    }

    /// Peer `i` rotates `roles` of `a` as a malicious writer would: boxing every current member,
    /// itself only at `keep` (the role it is about to keep), so the box rule finds no box for it
    /// at the roles it leaves, while it holds the new secrets.
    fn rotate_unboxed(lp: &mut LocalPeer, i: usize, a: Tid, roles: &[Role], keep: Option<Role>) {
        let me = lp.peers[i].engine.tid();
        let roles: BTreeSet<Role> = roles.iter().copied().collect();
        lp.peers[i]
            .engine
            .run(|tx| {
                let held = tx.core.epochs(&a).unwrap();
                let members = super::recipients(tx, &a, &[(me, keep)])?;
                let mut m = Mutation::new();
                let rot = super::rotation_into(tx, &mut m, a, &roles, &held, &members, &[])?;
                crate::engine::Engine::commit_tx(tx, m)?;
                super::record(tx, a, &rot)
            })
            .unwrap();
    }

    // spec/crypto.md §4 (written by a departed party, along a chain): D, a writer of M, rotates
    // M's read and write (its untouched write box would carry read) without boxing itself, then
    // leaves M. M reads A; A's admin reads M (so holds M's `/secrets`) but may not rotate it.
    // M's newest epoch has no box for D but D wrote it, so it does not cover D's departure: A's
    // admin waits for M (or leaves it out) instead of boxing A's new epoch to an epoch D holds;
    // once M's admin rotates M, everything is boxed again and D opens nothing new.
    #[test]
    fn member_epoch_written_by_departed_spec_crypto_4() {
        let mut lp = LocalPeer::new(3, 959, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let a = group(&mut lp, 0);
        let m = group(&mut lp, 2);
        lp.sync_all().unwrap();
        let p0 = lp.peers[0].engine.tid();
        lp.peers[2].engine.grant(&m, &d, &edge(Role::Write)).unwrap();
        lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        rotate_unboxed(&mut lp, 1, m, &[Role::Read, Role::Write], None);
        lp.sync_all().unwrap();
        let start = held_by(&lp, 1, &[m, a]);
        assert!(start.contains(&(m, Role::Read, newest_read(&lp, 2, m).unwrap())), "D holds M's newest");
        lp.peers[1].engine.demote(&m, &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        lp.sync_all().unwrap();
        assert!(lp.peers[0].engine.departures(&a).unwrap().iter().any(|q| q.member == d && q.via == vec![m]), "A sees D leave M");
        let before = newest_read(&lp, 0, a);
        let _ = lp.peers[0].engine.ensure_rotated(&a).unwrap();
        let _ = lp.peers[0].engine.reseal_due(&a, &Pass).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(leaks_judged_covered(&mut lp, &[(m, 2), (a, 0)], d, &start), vec![], "before M rotates");
        let rotated = newest_read(&lp, 0, a) != before;
        assert!(!rotated || !leaked(&mut lp, 0, &[m, a], d, start.clone()).contains(&a), "A's new epoch not boxed to D's");
        settle(&mut lp, &[0, 2], &[m, a]);
        assert!(all_boxed(&mut lp, 0, &[a]) && all_boxed(&mut lp, 2, &[m]), "re-sealed");
        assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
    }

    /// Pairs (actor, role) whose newest epoch at the owner peer `owner(t)` is judged covered there
    /// but that `d` opens from its old secrets `start` beyond what boxes to `d` itself give it.
    fn leaks_judged_covered(lp: &mut LocalPeer, gs: &[(Tid, usize)], d: Tid, start: &BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> Vec<(Tid, Role)> {
        let actors: Vec<Tid> = gs.iter().map(|g| g.0).collect();
        let mut out = Vec::new();
        for &(t, i) in gs {
            let legit = openable(lp, i, &actors, d, BTreeSet::new());
            let all = openable(lp, i, &actors, d, start.clone());
            let un = uncovered_at(lp, i, t);
            let Some(e) = lp.peers[i].engine.epochs(&t) else { continue };
            for r in osis_keys::ROLES {
                if let Some((n, _)) = e.role(r).newest_held()
                    && !un.contains(&r)
                    && all.contains(&(t, r, n))
                    && !legit.contains(&(t, r, n))
                {
                    out.push((t, r));
                }
            }
        }
        out
    }

    // spec/crypto.md §4, spec/permissions.md §3 (Membership cycles): random role graphs of 2-4
    // actors through a forced cycle, owned by one or two peers (sometimes with a common admin),
    // a party D on one or two of them; D is removed or demoted on one, or leaves by itself (a
    // writer having first rotated it without boxing itself). After the removal, and
    // after each admin acting alone (cascade and re-seal trigger) until nothing changes, D's old
    // secrets open no newest epoch its owner judges covered beyond what D's remaining boxes give
    // it; then nothing stays uncovered and every member holds a box at the newest epoch.
    #[test]
    fn cycle_removals_leak_nothing_random() {
        cycle_removals(0..6);
    }

    #[test]
    #[ignore = "tier 2"]
    fn cycle_removals_leak_nothing_random_large() {
        cycle_removals(1_000..1_200);
    }

    /// `cycle_removals_leak_nothing_random` over `seeds`; peers: 0 and 2 admins, 1 the party D.
    fn cycle_removals(seeds: std::ops::Range<u64>) {
        let roles = [Role::Read, Role::Write, Role::Admin];
        let (mut rounds, mut runs, mut lonely, mut wrote) = (0, 0, 0, 0);
        for seed in seeds {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut lp = LocalPeer::new(3, 1_300 + seed, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let [d, c] = [1, 2].map(|i| lp.peers[i].engine.tid());
            let two = rng.next(2) == 0;
            let common = two && rng.next(2) == 0;
            let k = 2 + rng.next(3) as usize;
            let gs: Vec<(Tid, usize)> = (0..k)
                .map(|_| {
                    let o = if two && rng.next(2) == 0 { 2 } else { 0 };
                    (group(&mut lp, o), o)
                })
                .collect();
            lp.sync_all().unwrap();
            if common {
                // peer 2 an admin of every actor of peer 0's
                for &(t, o) in &gs {
                    if o == 0 {
                        lp.peers[0].engine.grant(&t, &c, &edge(Role::Admin)).unwrap();
                    }
                }
            }
            for i in 0..k {
                for j in 0..k {
                    if i != j && (j == (i + 1) % k || rng.next(3) == 0) {
                        let (t, o) = gs[i];
                        let _ = lp.peers[o].engine.grant(&t, &gs[j].0, &edge(roles[rng.next(3) as usize]));
                    }
                }
            }
            let mut held_by_d = Vec::new();
            for _ in 0..1 + rng.next(2) {
                let (t, o) = gs[rng.next(k as u64) as usize];
                let r = roles[rng.next(3) as usize];
                if lp.peers[o].engine.grant(&t, &d, &edge(r)).is_ok() {
                    held_by_d.push((t, o, r));
                }
            }
            lp.sync_all().unwrap();
            let all: Vec<Tid> = gs.iter().map(|g| g.0).collect();
            let (t, o, r) = held_by_d[rng.next(held_by_d.len() as u64) as usize];
            let new = match (r, rng.next(2)) {
                (Role::Admin, 0) => Some(edge(Role::Write)),
                (Role::Admin | Role::Write, 1) => Some(edge(Role::Read)),
                _ => None,
            };
            // sometimes D, before leaving by itself, rotates the roles of `t` it leaves without
            // boxing itself at them (spec/crypto.md §4: written by a departed party)
            let by_d = rng.next(2) == 0;
            let keep = new.as_ref().map(|e| e.role);
            if by_d && r >= Role::Write {
                let rot: Vec<Role> = roles.into_iter().filter(|x| Some(*x) > keep && *x <= r).collect();
                rotate_unboxed(&mut lp, 1, t, &rot, keep);
                lp.sync_all().unwrap();
                wrote += 1;
            }
            let start = held_by(&lp, 1, &all);
            lp.peers[if by_d { 1 } else { o }].engine.demote(&t, &Demotion { member: d, new, presync: PreSync::Synced }).unwrap();
            lp.sync_all().unwrap();
            assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "seed {seed}: after the removal");
            let admins: &[usize] = if two { &[0, 2] } else { &[0] };
            rounds = rounds.max(settle(&mut lp, admins, &all));
            assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "seed {seed}: after the cascade and re-seals");
            for &(x, i) in &gs {
                assert!(uncovered_at(&mut lp, i, x).is_empty(), "seed {seed}: each admin alone covers every cycle");
            }
            assert!(gs.iter().all(|&(x, i)| all_boxed(&mut lp, i, &[x])), "seed {seed}: every member re-sealed");
            runs += 1;
            lonely += usize::from(two && !common && gs.iter().any(|g| g.1 == 0) && gs.iter().any(|g| g.1 == 2));
        }
        eprintln!("cycle removals: {runs} runs, {lonely} with disjoint admins, {wrote} written by D, at most {rounds} rounds to settle");
    }

    // A lattice 4 wide and 10 deep, each actor a member of all 4 above it (4^9 chains from the
    // top to one bottom actor): departures stay one per class, polynomial in the graph.
    #[test]
    fn wide_lattice_departures_bounded() {
        let mut lp = LocalPeer::new(2, 943, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let top = group(&mut lp, 0);
        let mut layer = vec![top];
        for _ in 0..9 {
            let next: Vec<Tid> = (0..4).map(|_| group(&mut lp, 0)).collect();
            for t in &layer {
                for m in &next {
                    lp.peers[0].engine.grant(t, m, &edge(Role::Write)).unwrap();
                }
            }
            layer = next;
        }
        lp.peers[0].engine.grant(&layer[0], &d, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.demote(&layer[0], &Demotion { member: d, new: None, presync: PreSync::Synced }).unwrap();
        let deps = lp.peers[0].engine.departures(&top).unwrap();
        // first and second actor (4 x 4), 8 verdict vectors at most
        assert!(!deps.is_empty() && deps.len() <= 4 * 4 * 8, "{}", deps.len());
        let (done, still) = lp.peers[0].engine.ensure_rotated(&top).unwrap();
        assert!(still.is_empty(), "{still:?}");
        assert_eq!(done.commits.len(), 8 * 4 + 1, "every actor above the bottom one once");
    }

    // spec/crypto.md §4 (an epoch does not cover a departure when its rotation commit's author
    // reaches the actor at that role only through the departed party): Alice's thing N, her
    // tag T shared with Bob; T a writer of N, then removed, then granted read again. Alice's
    // node reaches T as its owner but N by its own chain, so her removal's rotation covers T's
    // departure and the re-grant goes through. Bob, who reaches N's write only through T,
    // counts as T (also with a read edge of his own on N), not at read, and again once he
    // holds nothing on N.
    #[test]
    fn regrant_after_tag_removal_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 944, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (alice, bob) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let tag = group(&mut lp, 0);
        let n = group(&mut lp, 0);
        lp.peers[0].engine.grant(&tag, &bob, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&n, &tag, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.demote(&n, &Demotion { member: tag, new: None, presync: PreSync::Synced }).unwrap();
        lp.peers[0].engine.grant(&n, &tag, &edge(Role::Read)).unwrap();
        assert!(lp.peers[0].engine.ensure_rotated(&n).unwrap().1.is_empty(), "covered");
        let core = &lp.peers[0].engine.core;
        let by = |who: &Tid, r: Role| super::written_by(core, &n, r, who, who, &tag);
        assert!(!by(&alice, Role::Write) && !by(&alice, Role::Admin), "Alice's node reaches N by its own chain");
        assert!(by(&bob, Role::Write), "Bob reaches N only through T");
        assert!(by(&tag, Role::Read), "T itself");
        lp.peers[0].engine.grant(&n, &bob, &edge(Role::Read)).unwrap();
        let core = &lp.peers[0].engine.core;
        let by = |who: &Tid, r: Role| super::written_by(core, &n, r, who, who, &tag);
        assert!(by(&bob, Role::Write), "Bob's own read edge gives no write");
        assert!(!by(&bob, Role::Read), "Bob reads N on his own");
        // judged now: once Bob has left both T and N, an epoch he wrote while reading N on his
        // own no longer covers T's departure (he still knows its secret)
        lp.peers[0].engine.demote(&n, &Demotion { member: bob, new: None, presync: PreSync::Synced }).unwrap();
        lp.peers[0].engine.demote(&tag, &Demotion { member: bob, new: None, presync: PreSync::Synced }).unwrap();
        let core = &lp.peers[0].engine.core;
        assert!(super::written_by(core, &n, Role::Read, &bob, &bob, &tag), "Bob holds nothing on N now");
    }
}
