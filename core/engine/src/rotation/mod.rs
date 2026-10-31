//! Rotations (spec/permissions.md §3, spec/crypto.md §4): the cascade (`ensure_rotated`:
//! intermediate actors first, bottom-up, where the signer may rotate; one that may not stays
//! stranded on what is below; a member actor whose epoch does not cover is left out of a
//! rotation and re-sealed once it rotates); giving a thing secrets of its own; re-seal
//! decisions. The departures and the covers rule's view of them: `departures`; dropping what
//! this node lost read access to: `lost`.

mod departures;
mod lost;

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{self, Delivery, Done, SyncState, put_keysets, put_secrets, recipient, save_epochs, secrets_in};
use crate::Mutation;
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, Recipient, Rotation, rotate, uncovered};
use std::collections::{BTreeMap, BTreeSet};

pub use departures::{departures_placing, may_rotate, uncovered_roles_of};
pub(crate) use departures::{departures, held_actors, uncovered_departures, uncovered_roles, Judge};
use departures::{below_of, box_knew, collect, uncovered_by_role};
pub(crate) use lost::{boxes_kept, load_lost_due, mark_lost_due};
#[cfg(test)]
pub(crate) use lost::{PENDING_GRANT_WAIT_MS, authentic};

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
            if let Some((m, inner)) = inside_first(&d)
                && current.contains(&m)
                && !*on_cycle.entry(m).or_insert_with(|| below_of(tx.core, &m).0.contains(a))
                && !fresh_box_covers(tx, &held, &m, r, &inner)?
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
        if let Some((_, inner)) = inside_first(d)
            && !fresh_box_covers(tx, held, m, r, &inner)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The first actor on `d`'s chain and the departure inside it, as that actor sees it.
fn inside_first(d: &Departure) -> Option<(Tid, Departure)> {
    let (m, rest) = d.via.split_first()?;
    Some((*m, Departure { via: rest.clone(), member: d.member, from: d.from }))
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
/// (departing members). Members whose keys are unknown are left out (re-sealed later).
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
    if who != tx.core.id.tid() {
        m.sign_as(who);
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

}

#[cfg(test)]
mod tests;
