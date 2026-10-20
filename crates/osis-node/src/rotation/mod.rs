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
use osis_core::{Role, Tid, Ts};
use osis_crypto::Epoch;
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, Recipient, Rotation, rotate, uncovered};
use osis_perm::{At, WriteId};
use osis_schema::core_types::BoxKey;
use std::collections::{BTreeMap, BTreeSet};

/// Chains of actors followed for departures inside members (spec/crypto.md §4).
const MAX_DEPTH: usize = 8;

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
/// (spec/crypto.md §4). The owner never departs.
pub(crate) fn direct_departures(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Departure>> {
    let mut out = BTreeSet::new();
    let now = now_ts(tx.core);
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
            // an edge past its `until` still counts: its departure is the `until`'s
            let old = tl.edges_at(Some(mc.point())).get(&op.member, a).map(|e| e.role);
            let new = op.edge.filter(|e| e.alive_at(Some(mc.ts))).map(|e| e.role);
            out.extend(Departure::of_change(op.member, old, new));
        }
        for (m, e) in tl.edges_at(None).members(a) {
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
/// with secrets of its own, recursively.
pub(crate) fn departures(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<Departure>> {
    let mut out = BTreeSet::new();
    collect(tx, a, &mut Vec::new(), &mut out)?;
    Ok(out.into_iter().collect())
}

fn collect(tx: &mut Tx<'_>, a: &Tid, path: &mut Vec<Tid>, out: &mut BTreeSet<Departure>) -> Result<()> {
    if path.len() >= MAX_DEPTH || path.contains(a) {
        return Ok(());
    }
    let base = path.len();
    let mut mine = direct_departures(tx, a)?;
    path.push(*a);
    for (x, _, _) in tx.core.current_members(a) {
        if x == *a || !tx.core.has_own_secrets(&x) {
            continue;
        }
        let mut inner = BTreeSet::new();
        collect(tx, &x, path, &mut inner)?;
        for d in inner {
            if !d.via.contains(a) && d.member != *a {
                mine.insert(Departure::inside(x, &d));
            }
        }
    }
    path.truncate(base);
    out.extend(mine);
    Ok(())
}

/// What the covers rule needs of every actor this node holds secrets of; an actor with secrets
/// of its own whose secrets it does not hold is judged by its newest `/keys` keysets alone
/// (spec/crypto.md §4): those epochs, established in this view only, with no boxes.
pub(crate) fn held_actors(tx: &mut Tx<'_>) -> Result<MemoryHeldActors> {
    let mut h = MemoryHeldActors::default();
    let actors: Vec<Tid> = tx.core.secrets.keys().copied().collect();
    for a in actors {
        let s = secrets_in(tx, &a)?;
        if let Some(e) = tx.core.secrets.get(&a) {
            h.map.insert(a, (s, e.clone()));
        }
    }
    let unheld: Vec<Tid> = tx.core.own_keys.iter().filter(|a| !h.map.contains_key(a)).copied().collect();
    for a in unheld {
        let Some(keys) = Core::keys_in(tx, &a)? else { continue };
        let mut e = ActorEpochs::default();
        for (r, ks) in [(Role::Read, &keys.read), (Role::Write, &keys.write), (Role::Admin, &keys.admin)] {
            if let Some(ep) = ks.as_ref().and_then(|k| osis_keys::aspects::from_schema(&k.epoch).ok()) {
                e.role_mut(r).set_established(ep, osis_keys::Provenance::Fixed);
            }
        }
        h.map.insert(a, (Default::default(), e));
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

/// For the covers rule: whether the commit that wrote key-actor box `k` may have known epoch `e`
/// of role `r` (it carries that role's newest then). Only a box written before `e` was introduced
/// (both commits held) is known not to carry it; unknown counts as carrying (a rotation, never a
/// leak).
fn box_knew<'c>(core: &'c Core, a: &Tid) -> impl Fn(&BoxKey, Role, &Epoch) -> bool + 'c {
    let a = *a;
    move |k: &BoxKey, r: Role, e: &Epoch| {
        let Ok(secrets_ak) = flows::ak("/secrets") else { return true };
        let boxed = core
            .box_keys
            .iter()
            .filter(|((t, _), v)| *t == a && osis_schema::Codec::from_value(v).ok().is_some_and(|bk: BoxKey| bk == *k))
            .filter_map(|((t, d), _)| core.commit_of(t, &secrets_ak, d))
            .filter_map(|c| core.commits.get(&c).map(|m| m.header.ts))
            .min();
        let introduced = introduced_by(core, &a, r, e).map(|x| x.2);
        !matches!((boxed, introduced), (Some(b), Some(i)) if b < i)
    }
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may rotate now: write
/// and above rotates its role and below.
pub(crate) fn may_rotate(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Role> {
    core.timelines.get(a).map(|tl| tl.may_rotate(who, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The commit that introduced epoch `e` of role `r` of `a` (the earliest commit boxing it):
/// its author node, actor and `ts`.
fn introduced_by(core: &Core, a: &Tid, r: Role, e: &Epoch) -> Option<(Tid, Tid, Ts)> {
    let secrets_ak = flows::ak("/secrets").ok()?;
    core.box_keys
        .iter()
        .filter(|((t, _), _)| t == a)
        .filter(|(_, v)| osis_schema::Codec::from_value(v).ok().is_some_and(|bk: BoxKey| bk.role == r && osis_keys::aspects::from_schema(&bk.epoch).is_ok_and(|x| x == *e)))
        .filter_map(|((t, d), _)| core.commit_of(t, &secrets_ak, d))
        .filter_map(|c| core.commits.get(&c).map(|m| (m.header.ts, m.header.author, m.header.actor)))
        .min()
        .map(|(ts, au, ac)| (au, ac, ts))
}

/// Whether the commit by `author` acting for `actor` at `ts` was written by departed party `m`
/// or a node acting through it (spec/crypto.md §4: such an epoch does not cover `m`'s departure).
fn written_by(core: &Core, author: &Tid, actor: &Tid, ts: Ts, m: &Tid) -> bool {
    author == m || actor == m || core.timelines.get(m).is_some_and(|tl| tl.role(author, m, At::now(ts)).is_some())
}

/// The roles of `a` whose newest current epoch does not cover a known departure.
pub(crate) fn uncovered_roles(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
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
/// longer current or whose newest epoch (the one its fresh box names) covers the rest. A role
/// whose departures a rotation cannot help is not rotated: the node may not encrypt under it
/// until the intermediate rotates (spec/permissions.md §3).
fn rotation_helps(tx: &mut Tx<'_>, a: &Tid, uncovered_roles: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    if uncovered_roles.is_empty() {
        return Ok(BTreeSet::new());
    }
    let deps = departures(tx, a)?;
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let current: BTreeSet<Tid> = tx.core.current_members(a).into_iter().map(|x| x.0).collect();
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
            let inner = Departure { via: rest.to_vec(), member: d.member, from: d.from };
            match (osis_keys::HeldActors::epochs(&held, m), osis_keys::HeldActors::secrets(&held, m)) {
                (Some(me), Some(ms)) => me.role(r).newest().is_some_and(|k| osis_keys::covers(ms, me, r, &k, &inner, &held)),
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

/// Current members of `a` as box recipients; `skip` is left out (a departing member). Members
/// whose keys are unknown are left out (re-sealed later).
pub(crate) fn recipients(tx: &mut Tx<'_>, a: &Tid, skip: Option<(Tid, Option<Role>)>) -> Result<Vec<Recipient>> {
    let now = tx.core.now();
    let mut out = Vec::new();
    for (m, role, until) in tx.core.current_members(a) {
        if until.is_some_and(|u| u <= now) {
            continue;
        }
        let role = match skip {
            Some((s, new)) if s == m => match new {
                Some(r) => r,
                None => continue,
            },
            _ => role,
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
    put_secrets(m, a, &rot.secrets)?;
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
pub(crate) fn deliver_rotation(tx: &mut Tx<'_>, a: Tid, c: Option<osis_core::CommitId>, members: &[Tid]) -> Result<Vec<Delivery>> {
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
    let base = match tx.core.secrets.get(&a) {
        Some(e) => e.clone(),
        None => tx.core.epochs(&a).unwrap_or_default(),
    };
    let e = tx.core.secrets.entry(a).or_insert(base);
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
    let members = recipients(tx, &a, None)?;
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
/// members (top-down), then `a`'s uncovered roles `who` may rotate (spec/permissions.md §3).
/// Returns the roles still uncovered: it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, who: Tid, a: Tid, visiting: &mut Vec<Tid>, done: &mut Done) -> Result<BTreeSet<Role>> {
    if !tx.core.has_own_secrets(&a) {
        // a plain thing follows its owner's epochs
        return match tx.core.owner(&a) {
            Some(o) if !visiting.contains(&o) && !tx.core.is_key_actor(&o) => {
                visiting.push(a);
                let r = ensure_rotated(tx, who, o, visiting, done);
                visiting.pop();
                r
            }
            _ => Ok(BTreeSet::new()),
        };
    }
    if visiting.contains(&a) || visiting.len() >= MAX_DEPTH {
        return Ok(BTreeSet::new());
    }
    visiting.push(a);
    let firsts: BTreeSet<Tid> = departures(tx, &a)?.into_iter().filter_map(|d| d.via.first().copied()).collect();
    for x in firsts {
        ensure_rotated(tx, who, x, visiting, done)?;
    }
    visiting.pop();
    let due = uncovered_roles(tx, &a)?;
    let may = may_rotate(tx.core, &who, &a);
    let mine: BTreeSet<Role> = due.intersection(&may).copied().collect();
    let mine = rotation_helps(tx, &a, &mine)?;
    if !mine.is_empty() {
        done.extend(rotate_now(tx, who, a, &mine)?);
    }
    uncovered_roles(tx, &a)
}

/// `ensure_rotated`, failing when `roles` stay uncovered.
pub(crate) fn require_covered(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>, done: &mut Done) -> Result<()> {
    let still = ensure_rotated(tx, who, a, &mut Vec::new(), done)?;
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
    let members = recipients(tx, &t, None)?;
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
/// role `r` (osis-keys `Carries`): it is ordered at or after the commit that introduced `e`.
/// Unknown: no (a re-seal to a current member costs a box, never a leak).
fn carries_fn<'c>(core: &'c Core, a: &Tid) -> impl Fn(&BoxKey, Role, &Epoch) -> bool + 'c {
    let a = *a;
    move |k: &BoxKey, r: Role, e: &Epoch| {
        let Ok(secrets_ak) = flows::ak("/secrets") else { return false };
        let boxed = core
            .box_keys
            .iter()
            .filter(|((t, _), v)| *t == a && osis_schema::Codec::from_value(v).ok().is_some_and(|bk: BoxKey| bk == *k))
            .filter_map(|((t, d), _)| core.commit_of(t, &secrets_ak, d))
            .filter_map(|c| core.commits.get(&c).map(|m| m.header.ts))
            .min();
        let introduced = introduced_by(core, &a, r, e).map(|x| x.2);
        matches!((boxed, introduced), (Some(b), Some(i)) if b >= i)
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
    put_secrets(&mut m, a, &w)?;
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.extend(flows::edges::deliver_to(tx, member, c, &[a])?);
    }
    Ok(done)
}

/// Secrets this node no longer may read: actors it lost read on and what it reaches only
/// through them (spec/permissions.md §3, osis-keys `lost_access`).
pub(crate) fn lost(core: &Core) -> Vec<Tid> {
    let node = core.id.tid();
    let mut out = Vec::new();
    for a in core.secrets.keys() {
        let readable = core.role_now(&node, a).is_some() || core.key_actors.keys().any(|k| core.role_now(k, a).is_some());
        if !readable {
            out.push(*a);
        }
    }
    out
}

/// Drops the secrets of `lost` actors (diagnostic each) and forgets what only they read.
pub(crate) fn drop_lost(tx: &mut Tx<'_>) -> Result<(Vec<Tid>, Forgotten)> {
    let lost = lost(tx.core);
    if lost.is_empty() {
        return Ok((lost, Forgotten::default()));
    }
    tx.core.touch();
    for a in &lost {
        tx.core.secrets.remove(a);
        tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: "lost read access: secrets and what only they read dropped".into() }, now);
    }
    let f = crate::retention::forget::forget(tx, &lost)?;
    Ok((lost, f))
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
            let still = ensure_rotated(tx, me, a, &mut Vec::new(), &mut done)?;
            Ok((done, still))
        })
    }

    /// Every rotation this node may make that a known departure requires, now (the eager
    /// option).
    pub fn rotate_eagerly(&mut self) -> Result<Done> {
        let actors: Vec<Tid> = self.core.own_keys.iter().copied().collect();
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
        Ok(self.forget_lost()?.0)
    }

    /// `drop_lost_secrets`, with what was forgotten (node-sync drops its label sessions).
    pub(crate) fn forget_lost(&mut self) -> Result<(Vec<Tid>, Forgotten)> {
        let r = self.run(drop_lost)?;
        if !r.1.things.is_empty() {
            self.reload()?;
            self.reexamine()?;
        }
        Ok(r)
    }
}
