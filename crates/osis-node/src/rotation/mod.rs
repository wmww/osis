//! Rotations (spec/permissions.md §3, spec/crypto.md §4; plans/membership-flows.md): the
//! departures this node knows of, read from the membership timeline (every applied edge write
//! that lowered an edge, and edges past their `until`, whose member holds less now), recursively
//! through member and owner actors (departures inside a member); the covers rule over the held
//! actors; the cascade (`ensure_rotated`: intermediate actors first, top-down, where this node may
//! rotate; a node that may not stays stranded on what is below); giving a thing secrets of its
//! own; re-seal decisions. Departures are recomputed from the timeline on demand (O(edge
//! history)), never stored.

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{self, Delivery, Done, SyncState, now_ts, put_keysets, put_secrets, recipient, save_epochs, secrets_in};
use crate::Mutation;
use osis_core::{Role, Tid};
use osis_crypto::Epoch;
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, Recipient, Rotation, rotate, uncovered};
use osis_perm::{At, WriteId};
use osis_schema::core_types::BoxKey;
use std::collections::{BTreeMap, BTreeSet};

/// Chains of actors followed for departures inside members (spec/crypto.md §4).
const MAX_DEPTH: usize = 8;

/// Departures from `a` itself: lowered edges whose member holds less now than before, and
/// edges past their `until` (spec/crypto.md §4). The owner never departs.
pub(crate) fn direct_departures(core: &Core, a: &Tid) -> BTreeSet<Departure> {
    let mut out = BTreeSet::new();
    let Some(tl) = core.timelines.get(a) else { return out };
    let now = now_ts(core);
    let current: BTreeMap<Tid, Role> = tl.roster(a, At::now(now)).into_iter().map(|(m, e)| (m, e.role)).collect();
    for wid in tl.applied().keys() {
        let WriteId::Op(c, i) = wid else { continue };
        let Some(mc) = tl.membership_commit(c) else { continue };
        let Some(op) = mc.ops.get(*i as usize) else { continue };
        if op.target != *a {
            continue;
        }
        let at = Some(mc.ts);
        // an edge past its `until` still counts: its departure is the `until`'s
        let old = tl.edges_at(Some(mc.point())).get(&op.member, a).map(|e| e.role);
        let new = op.edge.filter(|e| e.alive_at(at)).map(|e| e.role);
        out.extend(Departure::of_change(op.member, old, new));
    }
    for (m, e) in tl.edges_at(None).members(a) {
        if !e.alive_at(Some(now)) {
            out.insert(Departure::member(*m, Role::Read));
        }
    }
    let owner = core.owner(a);
    out.retain(|d| Some(d.member) != owner && current.get(&d.member).copied() < Some(d.from));
    out
}

/// Every departure `a`'s epochs must cover: its own, and inside each member or owner actor
/// with secrets of its own, recursively.
pub(crate) fn departures(core: &Core, a: &Tid) -> Vec<Departure> {
    let mut out = BTreeSet::new();
    collect(core, a, &mut Vec::new(), &mut out);
    out.into_iter().collect()
}

fn collect(core: &Core, a: &Tid, path: &mut Vec<Tid>, out: &mut BTreeSet<Departure>) {
    if path.len() >= MAX_DEPTH || path.contains(a) {
        return;
    }
    let base = path.len();
    let mut mine = direct_departures(core, a);
    path.push(*a);
    for (x, _, _) in core.current_members(a) {
        if x == *a || !core.has_own_secrets(&x) {
            continue;
        }
        let mut inner = BTreeSet::new();
        collect(core, &x, path, &mut inner);
        for d in inner {
            if !d.via.contains(a) && d.member != *a {
                mine.insert(Departure::inside(x, &d));
            }
        }
    }
    path.truncate(base);
    out.extend(mine);
}

/// What the covers rule needs of every actor this node holds secrets of.
pub(crate) fn held_actors(tx: &mut Tx<'_>) -> Result<MemoryHeldActors> {
    let mut h = MemoryHeldActors::default();
    let actors: Vec<Tid> = tx.core.secrets.keys().copied().collect();
    for a in actors {
        let s = secrets_in(tx, &a)?;
        if let Some(e) = tx.core.secrets.get(&a) {
            h.map.insert(a, (s, e.clone()));
        }
    }
    Ok(h)
}

/// The roles of `a` this node may rotate now (write and above rotates its role and below).
pub(crate) fn may_rotate(core: &Core, a: &Tid) -> BTreeSet<Role> {
    let node = core.id.tid();
    core.timelines.get(a).map(|tl| tl.may_rotate(&node, a, At::now(now_ts(core))).into_iter().collect()).unwrap_or_default()
}

/// The roles of `a` whose newest current epoch does not cover a known departure.
pub(crate) fn uncovered_roles(tx: &mut Tx<'_>, a: &Tid) -> Result<BTreeSet<Role>> {
    let deps = departures(tx.core, a);
    if deps.is_empty() {
        return Ok(BTreeSet::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let secrets = secrets_in(tx, a)?;
    let held = held_actors(tx)?;
    let mut out = BTreeSet::new();
    for r in ROLES {
        if let Some((e, _)) = epochs.role(r).newest_held()
            && !uncovered(&secrets, &epochs, r, &e, &deps, &held).is_empty()
        {
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
    let deps = departures(tx.core, &a);
    let actors = held_actors(tx)?;
    let may_carry = |r: Role, e: &Epoch| uncovered(&secrets, held, r, e, &deps, &actors).is_empty();
    let rot = rotate(&a, roles, held, &secrets, members, &may_carry, &mut *tx.rng)?;
    put_secrets(m, a, &rot.secrets)?;
    put_keysets(m, a, &rot.keys)?;
    Ok(rot)
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

/// Rotates `roles` of `a` in a commit of its own (a cascade rotation: changes no edge).
pub(crate) fn rotate_now(tx: &mut Tx<'_>, a: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let members = recipients(tx, &a, None)?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, a, roles, &held, &members)?;
    let c = Engine::commit_tx(tx, m)?;
    record(tx, a, &rot)?;
    let mut done = Done::default();
    done.add(c);
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

/// Performs the rotations due on `a` before this node encrypts under its secrets: first those
/// of the intermediate actors of departures inside members (top-down), then `a`'s uncovered
/// roles it may rotate (spec/permissions.md §3). Returns the roles still uncovered (this node
/// may not rotate them, or an intermediate stays stale): it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, a: Tid, visiting: &mut Vec<Tid>, done: &mut Done) -> Result<BTreeSet<Role>> {
    if !tx.core.has_own_secrets(&a) {
        // a plain thing follows its owner's epochs
        return match tx.core.owner(&a) {
            Some(o) if !visiting.contains(&o) && !tx.core.is_key_actor(&o) => {
                visiting.push(a);
                let r = ensure_rotated(tx, o, visiting, done);
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
    let firsts: BTreeSet<Tid> = departures(tx.core, &a).into_iter().filter_map(|d| d.via.first().copied()).collect();
    for x in firsts {
        ensure_rotated(tx, x, visiting, done)?;
    }
    visiting.pop();
    let due = uncovered_roles(tx, &a)?;
    let may = may_rotate(tx.core, &a);
    let mine: BTreeSet<Role> = due.intersection(&may).copied().collect();
    if !mine.is_empty() {
        done.extend(rotate_now(tx, a, &mine)?);
    }
    uncovered_roles(tx, &a)
}

/// Gives `t` secrets of its own (spec/permissions.md §3, spec/crypto.md §3): a rotation of all
/// three roles from its derived epochs, boxed to its owner and current members, with a `/keys`
/// carrying the keysets and a fresh deposit seed. Nothing when it has them already.
pub(crate) fn own_secrets(tx: &mut Tx<'_>, t: Tid) -> Result<Option<osis_core::CommitId>> {
    if tx.core.has_own_secrets(&t) || tx.core.is_key_actor(&t) {
        return Ok(None);
    }
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the owner's secrets are not held"))?;
    let members = recipients(tx, &t, None)?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &members)?;
    let mut seed = [0u8; 32];
    tx.rng.fill_bytes(&mut seed);
    m.op(t, &osis_schema::core_types::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(5)], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&Some(seed))) })?;
    let c = Engine::commit_tx(tx, m)?;
    record(tx, t, &rot)?;
    Ok(c)
}

/// The re-seal trigger for `a` (spec/permissions.md §3): current members lacking a box at a
/// chain-established current epoch of a role this node may rotate, never at an epoch
/// established by a snapshot alone, never for an edge whose `until` is within `MAX_DRIFT`.
pub(crate) fn reseal_candidates(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    let may = may_rotate(tx.core, a);
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
        let ts_of = |want: &dyn Fn(&BoxKey) -> bool| -> Option<osis_core::Ts> {
            core.box_keys
                .iter()
                .filter(|((t, _), _)| *t == a)
                .filter(|(_, v)| osis_schema::Codec::from_value(v).ok().is_some_and(|bk: BoxKey| want(&bk)))
                .filter_map(|((t, d), _)| core.commit_of(t, &secrets_ak, d))
                .filter_map(|c| core.commits.get(&c).map(|m| m.header.ts))
                .min()
        };
        let boxed = ts_of(&|bk| bk == k);
        let introduced = ts_of(&|bk| bk.role == r && osis_keys::aspects::from_schema(&bk.epoch).is_ok_and(|x| x == *e));
        matches!((boxed, introduced), (Some(b), Some(i)) if b >= i)
    }
}

/// A re-seal of `member` for `roles` of `a` (spec/permissions.md §3): its boxes at the
/// chain-established current epochs, with history boxes, delivered by inbox only (a node: over
/// a direct connection).
pub(crate) fn reseal_one(tx: &mut Tx<'_>, a: Tid, member: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let mut done = Done::default();
    // boxing is encrypting under: rotate first where a departure is uncovered
    let still = ensure_rotated(tx, a, &mut Vec::new(), &mut done)?;
    if roles.iter().any(|r| still.contains(r)) {
        return Err(Error::Misuse("an epoch to re-seal under does not cover a departure"));
    }
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

impl Engine {
    /// Rotations due before this node next encrypts under `actor`'s secrets (spec/permissions.md
    /// §3), performed now: labeling calls it before wrapping, stamping or boxing under the actor
    /// (or eagerly). Returns the commits written and the roles it still may not encrypt under.
    pub fn ensure_rotated(&mut self, actor: &Tid) -> Result<(Done, BTreeSet<Role>)> {
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            let still = ensure_rotated(tx, a, &mut Vec::new(), &mut done)?;
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
    pub fn departures(&self, actor: &Tid) -> Vec<Departure> {
        departures(&self.core, actor)
    }

    /// Gives `thing` secrets of its own (spec/permissions.md §3): before its first non-owner
    /// member, or before it is made a member of anything.
    pub fn give_own_secrets(&mut self, thing: &Tid) -> Result<Option<osis_core::CommitId>> {
        let t = *thing;
        self.run(|tx| own_secrets(tx, t))
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
            let may = may_rotate(tx.core, &a);
            let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
            let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= role && may.contains(r) && !epochs.role(*r).newest_is_snapshot()).collect();
            if roles.is_empty() {
                return Err(Error::Misuse("this node may not re-seal that member"));
            }
            reseal_one(tx, a, m, &roles)
        })
    }

    /// Drops the secrets of actors this node lost read access to, and of what it reached only
    /// through them (spec/permissions.md §3), with a diagnostic per actor. Returns them.
    pub fn drop_lost_secrets(&mut self) -> Result<Vec<Tid>> {
        self.run(|tx| {
            let lost = lost(tx.core);
            if lost.is_empty() {
                return Ok(lost);
            }
            tx.core.touch();
            for a in &lost {
                tx.core.secrets.remove(a);
                tx.txn.remove_local(&[b"k/".as_slice(), a.as_bytes()].concat(), osis_store::Shred::Yes)?;
                let now = tx.now();
                tx.core.events.diagnostic(
                    crate::Diagnostic { kind: crate::DiagnosticKind::Removed, tids: vec![*a], commit: None, peer: None, detail: "lost read access: secrets dropped".into() },
                    now,
                );
            }
            Ok(lost)
        })
    }
}
