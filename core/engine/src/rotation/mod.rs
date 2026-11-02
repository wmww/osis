//! Rotations (spec/permissions.md §3, spec/crypto.md §4): the cascade (`ensure_rotated`:
//! intermediate actors first, bottom-up, where the signer may rotate; one that may not stays
//! stranded on what is below; a holder actor whose epoch does not cover is left out of a
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
use osis_keys::{ActorEpochs, Departure, MemoryHeldActors, ROLES, Recipient, Rotation, rotate};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

pub use departures::{departures_placing, may_rotate, uncovered_roles_of};
pub use lost::{Dropped, Leaving, LostScope, PENDING_GRANT_WAIT_MS};
pub(crate) use lost::{load_kept, without_frozen};
pub(crate) use departures::{departures, grant_names, held_actors, uncovered_departures, uncovered_roles};
use departures::{below_of, collect, uncovered_by_role};
pub(crate) use lost::{boxes_kept, load_lost_due, mark_lost_due};
#[cfg(test)]
pub(crate) use lost::authentic;

/// The roles of `a` that `may` (the roles the rotator may rotate) holds and a rotation of `a` is
/// worth now (spec/permissions.md §3): their newest held epoch does not cover a known departure
/// (by names), and none of those lies inside a current holder M whose fresh box would not keep
/// the rest out (`fresh_box_keeps_out`) and that `a` is not below (no role cycle through both).
/// Such an M heals by its own rotation: the node waits for it, so that `a`'s rotation then
/// reaches M's holders in-band. An M on a cycle with `a` may wait on `a`: `a` rotates, leaving
/// M out (`rotation_into`). So no actor waits on itself through others.
fn rotation_due(tx: &mut Tx<'_>, a: &Tid, may: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
    let Some(by_role) = uncovered_by_role(tx, a, &deps)? else { return Ok(BTreeSet::new()) };
    let held = held_actors(tx)?;
    let current: BTreeSet<Tid> = tx.core.current_holders(a).into_iter().map(|x| x.0).collect();
    let mut out = BTreeSet::new();
    let mut on_cycle: BTreeMap<Tid, bool> = BTreeMap::new();
    'roles: for (r, ds) in by_role {
        if !may.contains(&r) || ds.is_empty() {
            continue;
        }
        for d in ds {
            if let Some((m, inner)) = inside_first(&d)
                && current.contains(&m)
                && !*on_cycle.entry(m).or_insert_with(|| below_of(tx.core, &m).0.contains(a))
                && !fresh_box_keeps_out(tx, &held, &m, r, &inner)?
            {
                continue 'roles;
            }
        }
        out.insert(r);
    }
    Ok(out)
}

/// How this node may seal `a`'s secrets to holder actor `m` (spec/crypto.md §4, boxing a holder
/// actor; `departures::sealers`).
enum Seal {
    /// At the keyset a fresh box names, by this node's box judgement; the box carries this
    /// node's names for `m`.
    Free,
    /// Not at all: left out.
    Out,
    /// Only at these keysets, per role of `m`: the read keyset of the applied valid `keys.0`
    /// commit `m`'s roster entry on `a` names (its key first; the entry names the read box's
    /// commit only, so the roles above are left out); the box carries no names.
    Bound(ct::EdgeKey, BTreeMap<Role, (osis_crypto::Epoch, osis_crypto::KemPublicKey)>),
}

fn seal_of(tx: &mut Tx<'_>, a: &Tid, m: &Tid, roles: &BTreeSet<Role>) -> Result<Seal> {
    if tx.core.is_key_actor(m) {
        return Ok(Seal::Free);
    }
    Ok(match departures::sealers(tx, a, m, roles)? {
        departures::Sealers::Free => Seal::Free,
        departures::Sealers::Unmet => Seal::Out,
        departures::Sealers::Bound(k) => {
            let ks = named_keysets(tx, m, &k)?;
            Seal::Bound(k, ks)
        }
    })
}

/// The read keyset the `keys.0` commit of `m` with key `k` wrote, when this node holds it applied
/// with that part valid and not missing (a dropped body: `m`'s read keyset in `keys.0` now, if it
/// is the one the part wrote); else none. Only read: the edge names the commit of the granter's
/// read box, and its boxes of the roles above may name later keysets (a write rotation of `m`
/// after a departure from write the granter knew), so the commit's older ones may open to it.
fn named_keysets(tx: &mut Tx<'_>, m: &Tid, k: &ct::EdgeKey) -> Result<BTreeMap<Role, (osis_crypto::Epoch, osis_crypto::KemPublicKey)>> {
    let mut out = BTreeMap::new();
    let keys_ak = flows::ak("keys.0")?;
    let Some((ai, dropped)) = tx.core.ix.commits.get(&k.commit).filter(|c| c.view.ts == k.ts && c.view.author == k.node && !tx.core.ix.pending.contains_key(&k.commit)).and_then(|c| {
        let ai = c.aspect(m, &keys_ak).filter(|ai| c.valid_at(*ai) && !c.missing.contains(ai))?;
        Some((ai, c.dropped.get(&ai).map(|d| d.keysets.iter().map(|x| (x.0, x.1)).collect::<Vec<_>>())))
    }) else {
        return Ok(out);
    };
    let kem = |ks: &osis_schema::core_types::Keyset| -> Option<(osis_crypto::Epoch, osis_crypto::KemPublicKey)> {
        let osis_schema::core_types::KemKey::X25519MlKem768(b) = &ks.kem_key;
        (ks.suite == osis_keys::SUITE).then_some(())?;
        Some((osis_keys::aspects::from_schema(&ks.epoch).ok()?, osis_crypto::KemPublicKey::from_slice(b).ok()?))
    };
    match dropped {
        Some(ds) => {
            let now = Core::keys_in(tx, m)?;
            for (r, e) in ds.into_iter().filter(|x| x.0 == Role::Read) {
                if let Some(x) = now.as_ref().and_then(|k| osis_keys::aspects::keyset_of(k, r)).and_then(kem).filter(|x| x.0 == e) {
                    out.insert(r, x);
                }
            }
        }
        None => {
            for d in crate::apply::held_parts(tx, &k.commit, ai)? {
                for (r, ks) in crate::apply::keys::keys_write(d.fragment()).keysets {
                    if r == Role::Read
                        && let Some(x) = kem(&ks)
                    {
                        out.insert(r, x);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Whether holder actor `m` of `a` may be boxed role `r` of `a` (spec/permissions.md §3, Left
/// out; spec/crypto.md §4) as `seal` allows: free, a fresh box would name `m`'s newest epoch of
/// `r` (`fresh_box_keeps_out`); bound, at the named keyset of `r`; either way that epoch's boxes
/// keep out every departure of `deps` (those of `a`) inside `m`. Boxing to an epoch is
/// encrypting under: a rotation leaves such a holder out and the re-seal trigger skips it until
/// `m` rotates (or this node holds the grants' names).
fn role_keeps_out(tx: &mut Tx<'_>, held: &MemoryHeldActors, deps: &[Departure], m: &Tid, r: Role, seal: &Seal) -> Result<bool> {
    let named = match seal {
        Seal::Out => return Ok(false),
        Seal::Free => None,
        Seal::Bound(_, ks) => match ks.get(&r) {
            Some((e, _)) => Some(*e),
            None => return Ok(false),
        },
    };
    for d in deps.iter().filter(|d| d.via.first() == Some(m) && d.concerns(r)) {
        if let Some((_, inner)) = inside_first(d) {
            let at = match named {
                Some(e) => Some(e),
                None => fresh_box_epoch(tx, held, m, r)?,
            };
            if !at.is_some_and(|e| epoch_keeps_out(held, m, r, &e, &inner)) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// `role_keeps_out` for role `r` of `a` and holder `m`.
fn holder_keeps_out(tx: &mut Tx<'_>, a: &Tid, held: &MemoryHeldActors, deps: &[Departure], m: &Tid, r: Role) -> Result<bool> {
    let seal = seal_of(tx, a, m, &BTreeSet::from([r]))?;
    role_keeps_out(tx, held, deps, m, r, &seal)
}

/// The first actor on `d`'s chain and the departure inside it, as that actor sees it.
fn inside_first(d: &Departure) -> Option<(Tid, Departure)> {
    let (m, rest) = d.via.split_first()?;
    Some((*m, Departure { via: rest.clone(), ..d.clone() }))
}

/// A holder as this node may box it on `a` (`left_out`): the recipient, and the key of the
/// `keys.0` commit it is sealed bound to (spec/crypto.md §4), none when sealed free (a holder
/// actor's boxes then carry this node's names for it, `grant_names`) or a key actor.
pub(crate) struct Boxed {
    pub rcpt: Recipient,
    pub bound: Option<ct::EdgeKey>,
}

impl Boxed {
    /// The names the boxes to this holder carry for `roles`: a holder actor's sealed free.
    pub(crate) fn names(&self, core: &Core, roles: &BTreeSet<Role>) -> Option<osis_keys::Names> {
        (self.bound.is_none() && matches!(self.rcpt.keys, osis_keys::HolderKeys::Actor { .. })).then(|| grant_names(core, &self.rcpt, roles))
    }
}

/// `rc` as this node may box it on `a` for `roles` (given `deps` of `a`): sealed to the named
/// keysets where bound (`Seal`), its role cut at the first `role_keeps_out` refuses; `None` when
/// that leaves no role. Key actors are kept whole.
pub(crate) fn left_out(tx: &mut Tx<'_>, a: &Tid, held: &MemoryHeldActors, deps: &[Departure], rc: &Recipient, roles: &BTreeSet<Role>) -> Result<Option<Boxed>> {
    if !matches!(rc.keys, osis_keys::HolderKeys::Actor { .. }) {
        return Ok(Some(Boxed { rcpt: rc.clone(), bound: None }));
    }
    let sealed: BTreeSet<Role> = roles.iter().copied().filter(|r| *r <= rc.role).collect();
    let seal = seal_of(tx, a, &rc.holder, &sealed)?;
    let mut top = None;
    for r in ROLES.into_iter().filter(|r| *r <= rc.role) {
        if !role_keeps_out(tx, held, deps, &rc.holder, r, &seal)? {
            break;
        }
        top = Some(r);
    }
    let (keys, bound) = match seal {
        Seal::Bound(k, ks) => (osis_keys::HolderKeys::Actor { keysets: ks, own: BTreeMap::new() }, Some(k)),
        _ => (rc.keys.clone(), None),
    };
    Ok(top.map(|role| Boxed { rcpt: Recipient { holder: rc.holder, role, keys }, bound }))
}

/// `left_out` for a grant on `a` to `rc.holder`: by its own departures, as `a` will see them
/// once it is a holder.
pub(crate) fn grantee_left_out(tx: &mut Tx<'_>, a: &Tid, rc: &Recipient) -> Result<Option<Boxed>> {
    let deps: Vec<Departure> = departures(tx, &rc.holder)?.iter().filter_map(|d| Departure::through(rc.holder, rc.role, d)).collect();
    let held = held_actors(tx)?;
    left_out(tx, a, &held, &deps, rc, &osis_keys::roles_up_to(rc.role))
}

/// The epoch of `m` a fresh box of role `r` names (its newest held secret, else its keyset in
/// `keys.0`), when that is `m`'s newest epoch in this node's view (`held`).
fn fresh_box_epoch(tx: &mut Tx<'_>, held: &MemoryHeldActors, m: &Tid, r: Role) -> Result<Option<osis_crypto::Epoch>> {
    let Some(me) = osis_keys::HeldActors::epochs(held, m) else { return Ok(None) };
    let keys = Core::keys_in(tx, m)?;
    let ks = keys.as_ref().and_then(|k| osis_keys::aspects::keyset_of(k, r)).and_then(|ks| osis_keys::aspects::from_schema(&ks.epoch).ok());
    let named = match me.role(r).newest_held().map(|x| x.0) {
        Some(es) if osis_keys::symmetric_box(&es, ks.as_ref()) => Some(es),
        _ => ks,
    };
    Ok(named.filter(|e| me.role(r).newest() == Some(*e)))
}

/// Whether epoch `e` of role `r` of holder actor `m`, `m`'s newest in this node's view (`held`),
/// keeps `inner` out (the box judgement, `osis_keys::keeps_out`). An older epoch never does: its
/// boxes are judged from the newest only.
fn epoch_keeps_out(held: &MemoryHeldActors, m: &Tid, r: Role, e: &osis_crypto::Epoch, inner: &Departure) -> bool {
    let (Some(me), Some(ms)) = (osis_keys::HeldActors::epochs(held, m), osis_keys::HeldActors::secrets(held, m)) else { return false };
    me.role(r).newest() == Some(*e) && osis_keys::keeps_out(ms, r, e, inner, held)
}

/// Whether a fresh box of role `r` to holder actor `m` would name `m`'s newest epoch and that
/// epoch's boxes keep `inner` out.
fn fresh_box_keeps_out(tx: &mut Tx<'_>, held: &MemoryHeldActors, m: &Tid, r: Role, inner: &Departure) -> Result<bool> {
    Ok(fresh_box_epoch(tx, held, m, r)?.is_some_and(|e| epoch_keeps_out(held, m, r, &e, inner)))
}

/// Current holders of `a` as box recipients; each of `skip` gets its new role or is left out
/// (departing holders). Holders whose keys are unknown are left out (re-sealed later).
pub(crate) fn recipients(tx: &mut Tx<'_>, a: &Tid, skip: &[(Tid, Option<Role>)]) -> Result<Vec<Recipient>> {
    let now = tx.core.now();
    let mut out = Vec::new();
    for (m, role, until) in tx.core.current_holders(a) {
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
/// §3): it rotates read for a departure, so the departed party (which read the seed in `keys.0`)
/// can no longer deposit under `a`'s labels, and `who` is an admin (the seed is admin-written).
pub(crate) fn refreshes_deposit(core: &Core, who: &Tid, a: &Tid, roles: &BTreeSet<Role>) -> bool {
    roles.contains(&Role::Read) && may_rotate(core, who, a).contains(&Role::Admin)
}

/// The rotation of `roles` of `a` (boxes for `holders`), written into `m`, its history boxes
/// carrying the names of the departures from `a` this node holds (`departures::names`) and of the
/// keysets its boxes to holder actors name (`departures::keyset_names`). The
/// superseded epochs' secrets must be held: `held` is this node's view (derived epochs for the
/// switch to secrets of its own). `pending`: departures from `a` the same commit makes (a
/// removal's: the names' departs flag).
/// A holder actor is boxed only the roles up to the first its newest epoch does not cover
/// (`holder_keeps_out`): left out, it is re-sealed once it rotates (spec/permissions.md §3);
/// sealed free, its boxes carry this node's names for it (spec/crypto.md §4).
pub(crate) fn rotation_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, holders: &[Recipient], pending: &[Departure]) -> Result<Rotation> {
    let secrets = secrets_in(tx, &a)?;
    let deps = if pending.is_empty() { departures(tx, &a)? } else { collect(tx, &a, &mut None, pending)?.into_iter().collect() };
    let actors = held_actors(tx)?;
    let mut boxed = Vec::with_capacity(holders.len());
    let mut box_names = Vec::new();
    for rc in holders {
        if let Some(b) = left_out(tx, &a, &actors, &deps, rc, roles)? {
            if let Some(n) = b.names(tx.core, roles) {
                box_names.push((b.rcpt.holder, n));
            }
            boxed.push(b.rcpt);
        }
    }
    // a departing commit names itself by its `ts`, fixed here, and signer (set before this)
    let departs = if pending.is_empty() {
        None
    } else {
        let ts = *m.ts.get_or_insert_with(|| tx.core.hlc.next());
        Some(osis_keys::Own { ts: ts.to_u64(), node: m.signer.unwrap_or(tx.core.id.tid()) })
    };
    let mut names = departures::names(tx.core, &a, departs);
    names.keysets = departures::keyset_names(&boxed, roles);
    let mut rot = rotate(&a, roles, held, &secrets, &boxed, &names, &mut *tx.rng)?;
    for (holder, n) in &box_names {
        rot.with_names(&a, holder, n, &mut *tx.rng)?;
    }
    put_secrets(m, a, &rot.secrets, false)?;
    put_keysets(m, a, &rot.keys)?;
    Ok(rot)
}

/// Holders a rotation `rot` of `a` boxes that hold no box at a current read epoch before it: its
/// commit is wrapped under that epoch, so they cannot open it from the label (a grant this node
/// learned of after an epoch that left it out, the single-use link race's winner). They get it
/// by inbox (spec/permissions.md §3). Called before the rotation is committed.
pub(crate) fn unreached(tx: &mut Tx<'_>, a: &Tid, rot: &Rotation) -> Result<Vec<Tid>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let me = tx.core.id.tid();
    let mut out: Vec<Tid> = rot.secrets.boxes.keys().map(|k| k.holder).filter(|m| *m != me).collect();
    out.sort();
    out.dedup();
    out.retain(|m| !secrets.boxes.keys().any(|k| k.holder == *m && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.read.is_current(&e))));
    Ok(out)
}

/// The inbox (a node: direct) deliveries of rotation commit `c` of `a` to `holders`.
pub(crate) fn deliver_rotation(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, holders: &[Tid]) -> Result<Vec<Delivery>> {
    let mut out = Vec::new();
    if let Some(c) = c {
        for m in holders {
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
    tx.core.ix.secrets.insert(a, base.into_record());
    let e = tx.core.ix.secrets.entry_or_default(a);
    rot.record(e);
    save_epochs(tx, &a)
}

/// Rotates `roles` of `a` in a commit of its own (a cascade rotation: changes no edge), signed
/// by `who`.
pub(crate) fn rotate_now(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let holders = recipients(tx, &a, &[])?;
    let mut m = Mutation::new();
    if who != tx.core.id.tid() {
        m.sign_as(who);
    }
    let rot = rotation_into(tx, &mut m, a, roles, &held, &holders, &[])?;
    if refreshes_deposit(tx.core, &who, &a, roles) {
        fresh_deposit_seed(tx, &mut m, a)?;
    }
    let unreached = unreached(tx, &a, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    let mut done = Done::default();
    recorded(tx, a, c, &rot, &unreached, &mut done)?;
    Ok(done)
}

/// Records rotation `rot` of `a`, committed as `c`, into `done` with its deliveries: by inbox to
/// `to`, and first under the labels above `a`, which must learn its new `keys.0`
/// (spec/permissions.md §3).
fn recorded(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, rot: &Rotation, to: &[Tid], done: &mut Done) -> Result<()> {
    record(tx, a, rot)?;
    done.add(c);
    done.deliveries.extend(deliver_rotation(tx, a, c, to)?);
    if let Some(c) = c {
        let under = above(tx.core, &a);
        done.deliveries.push(flows::owe(tx, Delivery::First { commits: placed_with(c, Some(&rot.names)), under })?);
    }
    Ok(())
}

/// Commit `c` (a rotation or a grant) and the commits `names` (its names) name: placed together,
/// first, under each label `c` goes under (spec/crypto.md §4, names), so whoever reads `c` there
/// can meet them.
pub(crate) fn placed_with(c: osis_base::CommitId, names: Option<&osis_keys::Names>) -> Vec<osis_base::CommitId> {
    let named: BTreeSet<osis_base::CommitId> = names.into_iter().flat_map(|n| n.list.iter().map(|n| n.key.commit)).filter(|x| *x != c && *x != osis_keys::EXPIRY).collect();
    std::iter::once(c).chain(named).collect()
}

/// Things whose labels must learn a rotated actor's new `keys.0`: what it is a holder of and
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
/// holders (bottom-up: each actor after every actor on its departures' chains below it, each
/// once; on a role cycle, in walk order), then `a`'s uncovered roles `who` may rotate
/// (spec/permissions.md §3) where that helps (`rotation_due`). Returns the roles still
/// uncovered: it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, who: Tid, a: Tid, done: &mut Done) -> Result<BTreeSet<Role>> {
    // a plain thing follows its owner's epochs
    let mut found = None;
    for step in tx.core.owner_chain(&a) {
        let Some(t) = step.thing() else { break };
        if tx.core.has_own_secrets(&t) {
            found = Some(t);
            break;
        }
        match step {
            osis_base::ChainStep::Up { owner, .. } if !tx.core.is_key_actor(&owner) => {}
            _ => break,
        }
    }
    let Some(a) = found else { return Ok(BTreeSet::new()) };
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
/// uncovered, the history boxes carry them), boxed to its owner and current holders, with a
/// `keys.0` carrying the keysets and a fresh deposit seed. Nothing when it has them already.
pub(crate) fn own_secrets(tx: &mut Tx<'_>, t: Tid, done: &mut Done) -> Result<()> {
    if let Some((c, rot, _)) = own_secrets_rot(tx, t, done)? {
        record(tx, t, &rot)?;
        done.add(c);
    }
    Ok(())
}

/// `own_secrets` up to its commit, not yet recorded: the commit, the rotation, and the
/// holders it boxes that held no box at a current read epoch before it (`unreached`).
type OwnRot = (Option<osis_base::CommitId>, Rotation, Vec<Tid>);
fn own_secrets_rot(tx: &mut Tx<'_>, t: Tid, done: &mut Done) -> Result<Option<OwnRot>> {
    if tx.core.has_own_secrets(&t) || tx.core.is_key_actor(&t) {
        return Ok(None);
    }
    let who = tx.core.id.tid();
    require_covered(tx, who, t, &ROLES.into_iter().collect(), done)?;
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the owner's secrets are not held"))?;
    let holders = recipients(tx, &t, &[])?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &holders, &[])?;
    fresh_deposit_seed(tx, &mut m, t)?;
    let to = unreached(tx, &t, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    Ok(Some((c, rot, to)))
}

/// The plain things whose secrets derive from `a` that this node, an admin of each, sees with a
/// current non-owner holder (spec/permissions.md §3: such a thing is left by its only keyset
/// part turning invalid, spec/crypto.md §3); each gets secrets of its own again.
pub(crate) fn own_secrets_candidates(core: &Core, a: &Tid) -> Vec<Tid> {
    let me = core.id.tid();
    // keys sort by target: each target once (a scan per call; only plain targets go further)
    let mut last = None;
    core.ix
        .holder_keys
        .keys()
        .map(|(t, _)| *t)
        .filter(|t| last.replace(*t) != Some(*t))
        .filter(|t| !core.has_own_secrets(t) && !core.is_key_actor(t) && core.secret_actor(t) == Some(*a))
        .filter(|t| core.role_now(&me, t) == Some(Role::Admin) && core.current_holders(t).iter().any(|(m, _, _)| Some(*m) != core.owner(t)))
        .collect()
}

/// `own_secrets` for a plain thing with current holders, delivering the rotation by inbox to
/// each holder it boxes (they hold no box at the derived epochs it wraps under) and placing it
/// first under the labels above the thing (its new `keys.0`).
fn own_secrets_delivered(tx: &mut Tx<'_>, t: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some((c, rot, mut to)) = own_secrets_rot(tx, t, &mut done)? else { return Ok(done) };
    let owner = tx.core.owner(&t);
    to.retain(|m| Some(*m) != owner);
    recorded(tx, t, c, &rot, &to, &mut done)?;
    Ok(done)
}

/// The re-seal trigger for `a` (spec/permissions.md §3): current holders lacking a box at a
/// current epoch of a role this node may rotate, never for an edge whose `until` is within
/// `MAX_DRIFT`.
///
/// Invariant: once re-seals settle (every node holding the same commits finds no holder to
/// re-seal), every node counts the same current epochs of each role, since what a rotation
/// supersedes is read from its commit alone (its keyset's list,
/// `osis_keys::SecretsWrite::rotation_commit`, and its history box), and every
/// holder of a role holds every current epoch of it that a node that may rotate the role holds,
/// since a holder lacking one lacks its box there (one box per (holder, role, epoch)), and such
/// a node holding it re-seals (issues/fork-held-by-non-rotators.md: one that may not, cannot).
/// `tests::forked_reseals_settle_*` and `tests::forks_with_departures_settle_*` check it.
pub(crate) fn reseal_candidates(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    let me = tx.core.id.tid();
    let may = may_rotate(tx.core, &me, a);
    if may.is_empty() {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let holders: Vec<osis_keys::Holder> = tx.core.current_holders(a).into_iter().map(|(holder, role, until)| osis_keys::Holder { holder, role, until }).collect();
    let now = tx.core.now();
    let due = osis_keys::reseal_needed(&secrets, &epochs, &holders, now);
    let deps = departures(tx, a)?;
    let held = held_actors(tx)?;
    let mut out = Vec::new();
    for (m, roles) in due {
        let mut keep = BTreeSet::new();
        for r in roles {
            // Fixpoint (the re-seal is written on every pass otherwise): a re-seal is made only
            // when it adds a box the trigger asks for, each at its own key: so only by a node
            // holding the secret of an epoch the holder lacks a box at (`box_at` boxes just those
            // held; a node may lack a fork's, or reach the actor through a holder actor left
            // out). Every re-seal adds a box until the forks end, so the trigger settles;
            // requiring every fork's secret instead stranded a holder when no rotator held them
            // all. A holder actor left out waits until its newest epoch covers.
            let re = epochs.role(r);
            let missing = osis_keys::reseal_missing(&secrets, &epochs, &m, r);
            let holds = missing.iter().any(|e| re.secret(e).is_some());
            if may.contains(&r) && holds {
                keep.insert(r);
            }
        }
        // as `reseal_one` will box it (`left_out`): a holder actor left out of a role is left out
        // of the roles above, whether or not it lacks a box at that role
        if !keep.is_empty()
            && let Some(role) = holders.iter().find(|h| h.holder == m).map(|h| h.role)
            && let Ok(rc) = recipient(tx, m, role)
            && let Some(b) = left_out(tx, a, &held, &deps, &rc, &keep)?
        {
            keep.retain(|r| *r <= b.rcpt.role);
            if !keep.is_empty() {
                out.push((m, keep));
            }
        }
    }
    Ok(out)
}

/// A re-seal of `holder` for `roles` of `a` (spec/permissions.md §3): its boxes at the current
/// epochs, with history boxes, delivered by inbox (a node: over a
/// direct connection) and placed under the actor's labels like any role commit (later
/// removals reset its box entries: every node must hold them, or the removal waits for good).
pub(crate) fn reseal_one(tx: &mut Tx<'_>, a: Tid, holder: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let mut done = Done::default();
    // boxing is encrypting under: rotate first where a departure is uncovered
    let me = tx.core.id.tid();
    require_covered(tx, me, a, roles, &mut done)?;
    let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let secrets = secrets_in(tx, &a)?;
    let role = tx.core.current_holders(&a).into_iter().find(|(m, _, _)| *m == holder).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
    // a holder actor at the keyset this node may seal it to (`left_out`)
    let rcpt = recipient(tx, holder, role)?;
    let deps = departures(tx, &a)?;
    let held = held_actors(tx)?;
    let b = left_out(tx, &a, &held, &deps, &rcpt, roles)?.ok_or(Error::Misuse("the holder's epoch does not cover a known departure (it must rotate first)"))?;
    let roles: BTreeSet<Role> = roles.iter().copied().filter(|r| *r <= b.rcpt.role).collect();
    let Some(mut w) = osis_keys::box_holder(&a, &epochs, &secrets, &b.rcpt, &roles, &mut *tx.rng)? else {
        return Err(Error::Misuse("the holder's keyset is unknown"));
    };
    if let Some(n) = b.names(tx.core, &roles) {
        osis_keys::with_names(&a, &holder, &mut w, &n, &epochs, &mut *tx.rng)?;
    }
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, false)?;
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.extend(flows::edges::deliver_to(tx, holder, c, &[a])?);
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
    /// holder, or before it is made a holder of anything.
    pub fn give_own_secrets(&mut self, thing: &Tid) -> Result<Done> {
        let t = *thing;
        self.run(|tx| {
            let mut done = Done::default();
            own_secrets(tx, t, &mut done)?;
            Ok(done)
        })
    }

    /// Gives secrets of their own again to the plain things whose secrets derive from `actor`
    /// that this node administers and sees with a current non-owner holder (spec/permissions.md
    /// §3), decided at the end of a complete pass of `actor`'s labels (`sync`); nothing
    /// otherwise. Each thing in a run of its own: one that fails leaves the others.
    pub fn own_secrets_due(&mut self, actor: &Tid, sync: &dyn SyncState) -> Result<Vec<(Tid, Result<Done>)>> {
        if !sync.complete_pass(actor) {
            return Ok(Vec::new());
        }
        let ts = own_secrets_candidates(&self.core, actor);
        Ok(ts.into_iter().map(|t| (t, self.run(|tx| own_secrets_delivered(tx, t)))).collect())
    }

    /// Re-seals the holders of `actor` the trigger names (spec/permissions.md §3), decided at
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

    /// "Re-share with M" by hand (issues/reseal-triggers.md): re-seals current holder `holder`
    /// of `actor` for every role it holds that this node may rotate, whatever the trigger says
    /// (a holder whose deposits are refused, a stranded heartbeat, a re-paired device).
    pub fn reshare(&mut self, actor: &Tid, holder: &Tid) -> Result<Done> {
        let (a, m) = (*actor, *holder);
        self.run(|tx| {
            let role = tx.core.current_holders(&a).into_iter().find(|(x, _, _)| *x == m).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
            let me = tx.core.id.tid();
            let may = may_rotate(tx.core, &me, &a);
            let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= role && may.contains(r)).collect();
            if roles.is_empty() {
                return Err(Error::Misuse("this node may not re-seal that holder"));
            }
            let deps = departures(tx, &a)?;
            let held = held_actors(tx)?;
            for &r in &roles {
                if !holder_keeps_out(tx, &a, &held, &deps, &m, r)? {
                    return Err(Error::Misuse("the holder's epoch does not cover a known departure (it must rotate first)"));
                }
            }
            reseal_one(tx, a, m, &roles)
        })
    }

}

#[cfg(test)]
mod tests;
