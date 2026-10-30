//! Rotations (spec/permissions.md §3, spec/crypto.md §4): the
//! departures this node knows of, read from the membership timeline (every applied edge write
//! that lowered an edge, and edges past their `until`, whose member holds less now) and from
//! state (every box holder at a current epoch that holds less than that role now), recursively
//! through member and owner actors (departures inside a member); the covers rule over the held
//! actors, plus: an epoch introduced by a departed party (or a node acting through it) does not
//! cover its departure; the cascade (`ensure_rotated`: intermediate actors first, top-down, where
//! the signer may rotate; one that may not stays stranded on what is below); giving a thing
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
use osis_perm::{At, WriteId};
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

/// Departures from `a` itself: lowered edges whose member holds less now than before, edges
/// past their `until`, and box holders at a current epoch of a role they no longer hold
/// (spec/crypto.md §4). The owner never departs. `horizon`: lowered to the next time the answer
/// may change by the clock alone (an edge's `until`, a write's `ts` ahead of now).
pub(crate) fn direct_departures(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>) -> Result<BTreeSet<Departure>> {
    let mut out = BTreeSet::new();
    let now = now_ts(tx.core);
    let mut later = |t: WallMs| {
        if t > now.wall_ms() && horizon.is_none_or(|h| t < h) {
            *horizon = Some(t);
        }
    };
    let owner = tx.core.owner(a);
    let current: BTreeMap<Tid, Role> = tx.core.timelines.get(a).map(|tl| tl.roster(a, At::now(now)).into_iter().map(|(m, e)| (m, e.role)).collect()).unwrap_or_default();
    if let Some(tl) = tx.core.timelines.get(a) {
        for wid in tl.applied().keys() {
            let WriteId::Op(c, i) = wid else { continue };
            let Some(mc) = tl.membership_commit(c) else { continue };
            let Some(op) = mc.ops.get(*i as usize) else { continue };
            if op.target != *a {
                continue;
            }
            later(mc.ts.wall_ms());
            // an edge past its `until` still counts: its departure is the `until`'s
            let old = tl.edges_at(Some(mc.point())).get(&op.member, a).map(|e| e.role);
            let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
            out.extend(Departure::of_change(op.member, old, new));
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
/// with secrets of its own, recursively (spec/crypto.md §4), along simple chains that never
/// return to `a` and never pass the departed member. Chains that the covers rule cannot tell
/// apart (same first and second actor, same actor left, member and role, and the same verdict
/// of the first actor's newest epoch of each role) are one departure, carrying one of them:
/// work is polynomial in the actor graph below `a`, whatever its depth. Cached per actor
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
    let out: Vec<Departure> = collect(tx, a, &mut horizon)?.into_iter().collect();
    tx.core.ix.departures.insert(*a, (out.clone(), horizon));
    Ok(out)
}

/// A class of departures seen from actor V: the actor after V on the chain, the actor left,
/// the member, the role, and whether V's newest epoch of each role covers it.
type Class = (Option<Tid>, Tid, Tid, Role, [bool; 3]);

/// Whether `v`'s newest epoch of each role covers `d` (seen from `v`); unheld counts as not.
/// The covers rule reaches below `v` only through these verdicts (`osis_keys::covers`).
fn verdicts(held: &MemoryHeldActors, v: &Tid, d: &Departure) -> [bool; 3] {
    let (Some(s), Some(e)) = (osis_keys::HeldActors::secrets(held, v), osis_keys::HeldActors::epochs(held, v)) else { return [false; 3] };
    ROLES.map(|r| e.role(r).newest().is_some_and(|k| osis_keys::covers(s, e, r, &k, d, held)))
}

fn class_of(held: &MemoryHeldActors, v: &Tid, d: &Departure) -> Class {
    (d.via.first().copied(), d.via.last().copied().unwrap_or(*v), d.member, d.from, verdicts(held, v, d))
}

/// The departures of `departures`: the walk below `a`, then `a`'s own departures and those
/// inside its members.
fn collect(tx: &mut Tx<'_>, a: &Tid, horizon: &mut Option<WallMs>) -> Result<BTreeSet<Departure>> {
    let held = held_actors(tx)?;
    // the actors below `a` with secrets of their own, and who each is a member of
    let mut parents: BTreeMap<Tid, Vec<Tid>> = BTreeMap::new();
    let mut below: Vec<Tid> = Vec::new();
    let mut queue = std::collections::VecDeque::from([*a]);
    let mut seen = BTreeSet::from([*a]);
    while let Some(v) = queue.pop_front() {
        let ms: BTreeSet<Tid> = tx.core.current_members(&v).into_iter().map(|x| x.0).filter(|x| *x != v && x != a && tx.core.has_own_secrets(x)).collect();
        for x in ms {
            parents.entry(x).or_default().push(v);
            if seen.insert(x) {
                below.push(x);
                queue.push_back(x);
            }
        }
    }
    let mut direct = Vec::with_capacity(below.len());
    for v in below {
        let d = direct_departures(tx, &v, horizon)?;
        direct.push((v, d));
    }
    let found = walk(a, &parents, direct, |v, d| class_of(&held, v, d));
    let mut out = direct_departures(tx, a, horizon)?;
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

/// The fixpoint over the member graph below `a` (`a` left out): each actor keeps one departure
/// per class, starting from the actors' own (`direct`, in walk order); a chain is extended by an
/// actor only when it does not pass that actor already nor is that actor's departure (simple
/// chains). Chains share their tails (`osis_keys::Via`), so each kept departure costs one hop.
fn walk(a: &Tid, parents: &BTreeMap<Tid, Vec<Tid>>, direct: Vec<(Tid, BTreeSet<Departure>)>, class_of: impl Fn(&Tid, &Departure) -> Class) -> BTreeMap<Tid, BTreeMap<Class, Departure>> {
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
            if u != a && d.member != *u && !d.via.contains(u) {
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
        let held = tx.core.ix.secrets.get(&a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).newest_held().is_some()));
        if !held && tx.core.ix.own_keys.contains(&a) {
            continue;
        }
        let s = secrets_in(tx, &a)?;
        if let Some(e) = tx.core.ix.secrets.get(&a) {
            h.map.insert(a, (s, e.clone()));
        }
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
        let knew = box_knew(tx.core, a);
        for (k, b) in &s.boxes {
            let osis_schema::core_types::SecretBox::Sealed(sb) = b else { continue };
            let Ok(ke) = osis_keys::aspects::from_schema(&k.epoch) else { continue };
            if sb.keyset.is_some() || e.role(k.role).is_current(&ke) {
                continue;
            }
            for r in ROLES.into_iter().filter(|r| *r < k.role) {
                for ce in e.role(r).current() {
                    if knew(k, r, &ce) {
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
    let current: BTreeMap<Tid, Role> = tl.roster(a, At::now(now)).into_iter().map(|(m, x)| (m, x.role)).collect();
    // (member, the role it left and above, the commit that made the departure)
    let mut left: Vec<(Tid, Role, Option<osis_base::CommitId>)> = Vec::new();
    for wid in tl.applied().keys() {
        let WriteId::Op(c, i) = wid else { continue };
        let Some(mc) = tl.membership_commit(c) else { continue };
        let Some(op) = mc.ops.get(*i as usize) else { continue };
        if op.target != *a {
            continue;
        }
        let old = tl.edges_at(Some(mc.point())).get(&op.member, a).map(|x| x.role);
        let new = op.edge.filter(|x| x.alive_at(Some(mc.ts))).map(|x| x.role);
        if let Some(d) = Departure::of_change(op.member, old, new) {
            left.push((op.member, d.from, Some(*c)));
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
            out.extend(crate::apply::keys::secrets_write(tx.core, a, &d.fragment).0.boxes.into_keys());
        }
    }
    Ok(Some(out))
}

/// For the covers rule: whether the commit that wrote key-actor box `k` may have known epoch `e`
/// of role `r` (it carries that role's newest then). Only a box written before `e` was introduced
/// (both commits held) is known not to carry it; unknown counts as carrying (a rotation, never a
/// leak).
fn box_knew<'c>(core: &'c Core, a: &Tid) -> impl Fn(&BoxKey, Role, &Epoch) -> bool + 'c {
    let a = *a;
    move |k: &BoxKey, r: Role, e: &Epoch| {
        let boxed = core.ix.box_written.get(&(a, k.clone()));
        let introduced = introduced_by(core, &a, r, e).map(|x| x.2);
        !matches!((boxed, introduced), (Some(b), Some(i)) if *b < i)
    }
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may rotate now: write
/// and above rotates its role and below.
pub fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    core.timelines.get(a).map(|tl| tl.may_rotate(who, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The commit that introduced epoch `e` of role `r` of `a` (the earliest commit boxing it or
/// writing its keyset in `/keys`): its author node, actor and `ts`.
fn introduced_by(core: &Core, a: &Tid, r: Role, e: &Epoch) -> Option<(Tid, Tid, Ts)> {
    core.ix.epoch_intro.get(&(*a, r, *e)).map(|(ts, au, ac, _)| (*au, *ac, *ts))
}

/// Whether the commit by `author` acting for `actor` at `ts` was written by departed party `m`
/// or a node acting through it (spec/crypto.md §4: such an epoch does not cover `m`'s departure).
fn written_by(core: &Core, author: &Tid, actor: &Tid, ts: Ts, m: &Tid) -> bool {
    author == m || actor == m || core.timelines.get(m).is_some_and(|tl| tl.role(author, m, At::now(ts)).is_some())
}

/// The known departures `a`'s newest held epochs (any role) do not cover now.
pub(crate) fn uncovered_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    let deps = departures(tx, a)?;
    if deps.is_empty() {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let mut out: Vec<Departure> = Vec::new();
    for r in ROLES {
        let Some((e, _)) = epochs.role(r).newest_held() else { continue };
        for d in uncovered(&secrets, &epochs, r, &e, &deps, &held) {
            if !out.contains(d) {
                out.push(d.clone());
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
    let (mc, op) = tl
        .applied()
        .keys()
        .filter_map(|w| match w {
            WriteId::Op(c, i) => tl.membership_commit(c).and_then(|mc| mc.ops.get(*i as usize).map(|op| (mc, op))),
            _ => None,
        })
        .filter(|(_, op)| op.target == *t && op.member == d.member)
        .max_by_key(|(mc, _)| mc.point())?;
    let old = tl.edges_at(Some(mc.point())).get(&op.member, t).map(|e| e.role);
    let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
    let own = mc.author == core.id.tid() || core.ix.commits.get(&mc.id).is_some_and(|m| m.origin == crate::events::Origin::Local);
    (own && Departure::of_change(op.member, old, new).is_some() && crate::apply::validity::self_removal(core, &mc.author, t, &op.member, mc.ts)).then_some(mc.id)
}

pub fn uncovered_roles_of(tx: &mut Tx<'_>, a: &Tid, deps: Vec<Departure>) -> Result<BTreeSet<Role>> {
    if deps.is_empty() {
        return Ok(BTreeSet::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let mut out = BTreeSet::new();
    for r in ROLES {
        let Some((e, _)) = epochs.role(r).newest_held() else { continue };
        let by_departed = || {
            introduced_by(tx.core, a, r, &e).is_some_and(|(au, ac, ts)| deps.iter().any(|d| d.from <= r && written_by(tx.core, &au, &ac, ts, &d.member)))
        };
        if !uncovered(&secrets, &epochs, r, &e, &deps, &held).is_empty() || by_departed() {
            out.insert(r);
        }
    }
    Ok(out)
}

/// The roles of `uncovered` that a fresh rotation of `a` would cover: one uncovered departure
/// at least is a member's own (the rotation omits it), or lies inside a member M that is no
/// longer current or whose newest epoch covers the rest and is the one its fresh box names (M's
/// keyset in `/keys`: a node holding a newer `/keys` than secrets of M would otherwise rotate
/// without end). A role whose departures a rotation cannot help is not rotated: the node may
/// not encrypt under it until the intermediate rotates (spec/permissions.md §3).
fn rotation_helps(tx: &mut Tx<'_>, a: &Tid, uncovered_roles: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    if uncovered_roles.is_empty() {
        return Ok(BTreeSet::new());
    }
    let deps = departures(tx, a)?;
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let current: BTreeSet<Tid> = tx.core.current_members(a).into_iter().map(|x| x.0).collect();
    // M's keyset epoch per role in `/keys` (a fresh box names it when newer than M's secrets)
    let mut keysets: BTreeMap<(Tid, Role), Option<Epoch>> = BTreeMap::new();
    for d in &deps {
        if let Some(m) = d.via.first()
            && !keysets.contains_key(&(*m, Role::Read))
        {
            let keys = Core::keys_in(tx, m)?;
            for r in ROLES {
                let e = keys.as_ref().and_then(|k| osis_keys::aspects::keyset_of(k, r)).and_then(|ks| osis_keys::aspects::from_schema(&ks.epoch).ok());
                keysets.insert((*m, r), e);
            }
        }
    }
    let mut out = BTreeSet::new();
    for &r in uncovered_roles {
        let Some((e, _)) = epochs.role(r).newest_held() else {
            out.insert(r);
            continue;
        };
        let helps = deps.iter().filter(|d| !osis_keys::covers(&secrets, &epochs, r, &e, d, &held)).any(|d| {
            let Some((m, rest)) = d.via.split_first() else { return true };
            if !current.contains(m) {
                return true;
            }
            let inner = Departure { via: rest.clone(), member: d.member, from: d.from };
            match (osis_keys::HeldActors::epochs(&held, m), osis_keys::HeldActors::secrets(&held, m)) {
                (Some(me), Some(ms)) => {
                    let ks = keysets.get(&(*m, r)).copied().flatten();
                    let named = match me.role(r).newest_held().map(|x| x.0) {
                        Some(es) if ks.is_none_or(|ek| !osis_keys::is_newer(&ek, &es)) => Some(es),
                        _ => ks,
                    };
                    me.role(r).newest().is_some_and(|k| named == Some(k) && osis_keys::covers(ms, me, r, &k, &inner, &held))
                }
                _ => false,
            }
        });
        // an epoch introduced by the departed party is replaced by any rotation
        if helps || uncovered(&secrets, &epochs, r, &e, &deps, &held).is_empty() {
            out.insert(r);
        }
    }
    Ok(out)
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

/// The rotation of `roles` of `a` (boxes for `members`), written into `m`. The superseded
/// epochs' secrets must be held: `held` is this node's view (derived epochs for the switch to
/// secrets of its own).
pub(crate) fn rotation_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, members: &[Recipient]) -> Result<Rotation> {
    let secrets = secrets_in(tx, &a)?;
    let deps = departures(tx, &a)?;
    let actors = held_actors(tx)?;
    let may_carry = |r: Role, e: &Epoch| uncovered(&secrets, held, r, e, &deps, &actors).is_empty();
    let rot = rotate(&a, roles, held, &secrets, members, &may_carry, &mut *tx.rng)?;
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
    let base = match tx.core.ix.secrets.get(&a) {
        Some(e) => e.clone(),
        None => tx.core.epochs(&a).unwrap_or_default(),
    };
    let e = tx.core.ix.secrets.entry_or(a, || base);
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
    let rot = rotation_into(tx, &mut m, a, roles, &held, &members)?;
    let unreached = unreached(tx, &a, &rot)?;
    if let Some(s) = signer_of(tx, who) {
        m.sign_as(s);
    }
    let c = Engine::commit_tx(tx, m)?;
    record(tx, a, &rot)?;
    let mut done = Done::default();
    done.add(c);
    done.deliveries.extend(deliver_rotation(tx, a, c, &unreached)?);
    // the rotated actor's new /keys travels under the labels above it (spec/permissions.md §3)
    if let Some(c) = c {
        done.deliveries.push(Delivery::First { commits: vec![c], under: above(tx.core, &a) });
    }
    Ok(done)
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
/// members (top-down: each actor after every actor on its departures' chains below it, each
/// once), then `a`'s uncovered roles `who` may rotate (spec/permissions.md §3). Returns the
/// roles still uncovered: it must not encrypt under them.
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
        let due = uncovered_roles(tx, &x)?;
        let may = may_rotate(tx.core, &who, &x);
        let mine: BTreeSet<Role> = due.intersection(&may).copied().collect();
        let mine = rotation_helps(tx, &x, &mine)?;
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
    if tx.core.has_own_secrets(&t) || tx.core.is_key_actor(&t) {
        return Ok(());
    }
    let who = tx.core.id.tid();
    require_covered(tx, who, t, &ROLES.into_iter().collect(), done)?;
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the owner's secrets are not held"))?;
    let members = recipients(tx, &t, &[])?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &members)?;
    let mut seed = [0u8; 32];
    tx.rng.fill_bytes(&mut seed);
    m.op(t, &osis_schema::core_types::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(5)], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&Some(seed))) })?;
    seed.fill(0);
    let c = Engine::commit_tx(tx, m)?;
    record(tx, t, &rot)?;
    done.add(c);
    Ok(())
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
    let carries = carries_fn(tx.core, a);
    let now = tx.core.now();
    let out = osis_keys::reseal_needed(&secrets, &epochs, &members, now, &|k, r, e| carries(k, r, e))
        .into_iter()
        .map(|(m, roles)| (m, roles.into_iter().filter(|r| may.contains(r) && !epochs.role(*r).newest_is_snapshot()).collect::<BTreeSet<Role>>()))
        .filter(|(_, roles)| !roles.is_empty())
        .collect();
    Ok(out)
}

/// Whether the commit that wrote a key actor's box keyed at a higher role knew epoch `e` of
/// role `r` (osis-keys `Carries`): its first write is ordered at or after the commit that
/// introduced `e` (found by its boxes or, for an epoch boxed to key actors only, its keyset).
/// The first write, not the newest: a later rewrite of the box (a re-seal, a grant) by a writer
/// ordered after `e` need not have held `e` (a concurrent fork), so it proves nothing; a
/// rotation that introduces an epoch writes its key-actor boxes under fresh keys anyway.
/// Unknown: no (a re-seal to a current member costs a box, never a leak).
fn carries_fn<'c>(core: &'c Core, a: &Tid) -> impl Fn(&BoxKey, Role, &Epoch) -> bool + 'c {
    let a = *a;
    move |k: &BoxKey, r: Role, e: &Epoch| {
        let boxed = core.ix.box_written.get(&(a, k.clone()));
        let introduced = introduced_by(core, &a, r, e).map(|x| x.2);
        matches!((boxed, introduced), (Some(b), Some(i)) if *b >= i)
    }
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
    /// is within `PENDING_GRANT_WAIT_MS` before now (and not past `MAX_DRIFT` ahead).
    plausible: bool,
}

/// Actors a held, not applied membership commit (pending, parked readable, or late parts)
/// boxes secrets of to this node, a held key actor or an actor it reads now: grants this node
/// may yet get (their secrets may be read already, spec/crypto.md §4), never a loss.
fn pending_grants(tx: &mut Tx<'_>) -> Result<Vec<PendingGrant>> {
    let mut out = Vec::new();
    let node = tx.core.id.tid();
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
            for (x, w) in crate::apply::keys::pending_secrets_writes(tx.core, &blob, &id) {
                let core = &*tx.core;
                let ours = |m: &Tid| *m == node || core.key_actors.contains_key(m) || (core.ix.secrets.contains_key(m) && readable(core, m));
                if w.boxes.keys().any(|k| ours(&k.member)) {
                    out.push(PendingGrant { x, plausible: recent && may_grant(core, &author, &x) });
                }
            }
        }
        if n < 256 {
            return Ok(out);
        }
    }
}

/// Whether `author` may grant on `x` now: admin, or an invite (spec/permissions.md §2).
fn may_grant(core: &Core, author: &Tid, x: &Tid) -> bool {
    let at = At::now(now_ts(core));
    core.role_now(author, x) == Some(Role::Admin) || core.timelines.get(x).and_then(|t| t.invite(author, x, at)).is_some()
}

/// Of `cands`, the actors this node holds a secret of and lost read access to
/// (spec/permissions.md §3): no role on them by any path now and no pending grant reaching them.
/// Each actor is judged on its own, so what the node reached only through a lost one is lost
/// with it. (Epochs observed without a secret are no access.) An actor this node holds checked
/// secrets of is kept only by a plausible grant: anyone can send a pending commit, which is kept
/// until it applies, so any other would keep a node that lost access holding it for good;
/// reading-only candidates go with the commit that gave them.
fn lost_among(tx: &mut Tx<'_>, cands: Vec<Tid>) -> Result<Vec<Tid>> {
    let holds = |e: &ActorEpochs| ROLES.iter().any(|r| !e.role(*r).held_newest_first().is_empty());
    let unread: Vec<Tid> = cands.into_iter().filter(|a| tx.core.ix.secrets.get(a).is_some_and(holds) && !readable(tx.core, a)).collect();
    if unread.is_empty() {
        return Ok(unread);
    }
    let pend = pending_grants(tx)?;
    let core = &*tx.core;
    let checked = |a: &Tid| core.ix.secrets.get(a).is_some_and(|e| ROLES.iter().any(|r| e.role(*r).held().next().is_some()));
    Ok(unread.into_iter().filter(|a| !pend.iter().any(|g| (g.plausible || !checked(a)) && reaches(core, &g.x, a))).collect())
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read.
fn drop_actors(tx: &mut Tx<'_>, lost: Vec<Tid>) -> Result<(Vec<Tid>, Forgotten)> {
    if lost.is_empty() {
        return Ok((lost, Forgotten::default()));
    }
    tx.core.touch();
    for a in &lost {
        tx.core.ix.secrets.remove(a);
        tx.core.membership_changed();
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: "lost read access: secrets and what only they read dropped".into() }, now);
    }
    let f = crate::retention::forget::forget(tx, &lost)?;
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

    /// The path walk `collect` replaced (every simple chain, at most 8 actors): the oracle of
    /// `walk_matches_path_walk`.
    fn path_walk(tx: &mut Tx<'_>, a: &Tid, path: &mut Vec<Tid>, out: &mut BTreeSet<Departure>) -> crate::error::Result<()> {
        if path.len() >= 8 || path.contains(a) {
            return Ok(());
        }
        let mut mine = super::direct_departures(tx, a, &mut None)?;
        path.push(*a);
        for (x, _, _) in tx.core.current_members(a) {
            if x == *a || !tx.core.has_own_secrets(&x) {
                continue;
            }
            let mut inner = BTreeSet::new();
            path_walk(tx, &x, path, &mut inner)?;
            for d in inner {
                if !d.via.contains(a) && d.member != *a {
                    mine.insert(Departure::inside(x, &d));
                }
            }
        }
        path.pop();
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
            let secrets = crate::flows::secrets_in(tx, a).unwrap();
            for r in osis_keys::ROLES {
                let un = epochs.role(r).newest_held().map(|(e, _)| osis_keys::uncovered(&secrets, &epochs, r, &e, &deps, &held).into_iter().map(key).collect()).unwrap_or_default();
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
                    path_walk(tx, &a, &mut Vec::new(), &mut out)?;
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
                assert!(cyclic, "seed {seed}: {a:?}\nold {old:?}\nnew {new:?}");
                assert!(new.0.is_subset(&old.0), "seed {seed}: chains followed are the walk's");
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

    // spec/crypto.md §4: with cycles, the chains followed are the walk's simple chains (one per
    // class; a class whose kept chain revisits an actor is not extended through it).
    #[test]
    fn walk_with_cycles_follows_simple_chains() {
        let (mut same, mut all) = (0, 0);
        for seed in 0..6 {
            let (s, n) = differential(7_200 + seed, true);
            same += s;
            all += n;
        }
        assert!(same * 10 >= all * 9, "{same} of {all} alike");
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
        let found = super::walk(&t(0), &parents, direct, |v, d| super::class_of(&held, v, d));
        let deps: Vec<&Departure> = found.values().flat_map(|f| f.values()).collect();
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
        assert_eq!(done.commits.len(), 2, "P, then B");
        assert!(lp.peers[0].engine.ensure_rotated(&b).unwrap().0.commits.is_empty(), "no churn around the cycle");
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
}
