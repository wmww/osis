//! Rotations (spec/permissions.md §3, spec/crypto.md §4): when one is due (`rotation_due`:
//! departures from the actor not covered, by any current epoch; forks, by their merger; stale
//! boxes to holder actors; holders boxed through a keyless grant), the cascade
//! (`ensure_rotated`: the holder actors this node may rotate first, then the actor), giving a
//! thing secrets of its own, re-seals and history adds. Rotating needs only the right to rotate,
//! never a prior secret: a rotation supersedes every current epoch, held or not, and any holder
//! of a superseded secret adds it to the new epoch's history (`add_history`). Departures from an
//! actor: `departures`; holder actors (key access, keysets, sealing, staleness): `members`;
//! dropping what this node lost read access to: `lost`.

mod departures;
mod lost;
mod members;

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{self, Delivery, Done, SyncState, put_keysets, put_secrets, save_epochs, secrets_in};
use crate::Mutation;
use osis_base::{Role, Tid};
use osis_keys::{ActorEpochs, Departure, HistoryBoxes, ROLES, Recipient, Rotation, rotate};
use std::collections::BTreeSet;

pub use departures::{departures_placing, may_rotate};
pub use lost::{Dropped, Leaving, LostScope, LOST_HEARD_WAIT_MS, PENDING_GRANT_WAIT_MS};
pub(crate) use lost::{load_kept, without_frozen};
pub(crate) use departures::{departures, key_role};
pub(crate) use members::{Sealed, grant_keyless, sealed};
pub(crate) use lost::{arm_untils, boxes_kept, load_lost_due, mark_lost_due};
#[cfg(test)]
pub(crate) use lost::authentic;

/// The roles of `a` that `who` (this node, or a key actor it signs as) may not encrypt under
/// (spec/crypto.md §4, encrypting under): those whose newest held current epoch is blocked
/// (`blocked_epoch`, `deps` the departures from `a` counted).
pub fn blocked_roles_of(tx: &mut Tx<'_>, who: &Tid, a: &Tid, deps: &[Departure]) -> Result<BTreeSet<Role>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let mut out = BTreeSet::new();
    for r in ROLES {
        let Some((e, _)) = epochs.role(r).newest_held() else { continue };
        if blocked_epoch(tx, who, a, r, &e, deps)? {
            out.insert(r);
        }
    }
    Ok(out)
}

/// Whether `who` may not encrypt under epoch `e` of role `r` of `a` (spec/crypto.md §4,
/// encrypting under), `deps` the departures from `a` counted: `e` does not cover one of them;
/// or `who` may rotate `r` and `e` has a stale box to a holder actor (rule 2), boxes a holder
/// whose grant on `a` is keyless (rule 4), or boxes a holder actor M at a keyset of M under which
/// `who` may not encrypt, by this same rule with every departure from M this node knows (sealing
/// at that keyset was encrypting under it). The last three bind rotators only: a node that may
/// not rotate places its chain certificates (and revokes) under the actor's labels meanwhile,
/// the holder actors' new `keys.0` among them, which is how the rotators learn of the staleness.
/// Only epochs whose secret this node holds are judged (a node that cannot open a history box
/// cannot tell what it covers: a holder actor sealed at a keyset it lacks is judged by that
/// actor's own writers, the stated limit).
///
/// Invariant: a node holding M's secrets that knows a departure from M seals nothing at a keyset
/// of M not covering it (`members::sealed` leaves M out), and, where it may rotate the role,
/// writes no content or box under an epoch boxing M at such a keyset, at any height above M: the
/// party removed from M opens none of it, M's rotation made or not (model `D0_above`,
/// `NoLeakAbove`). Walked over the boxes without recursion (chains have no depth bound), each
/// (actor, epoch) once (boxes may cycle).
pub(crate) fn blocked_epoch(tx: &mut Tx<'_>, who: &Tid, a: &Tid, r: Role, e: &osis_crypto::Epoch, deps: &[Departure]) -> Result<bool> {
    let mut seen = BTreeSet::from([(*a, *e)]);
    let mut todo = vec![(*a, *e)];
    while let Some((x, k)) = todo.pop() {
        let Some(epochs) = tx.core.epochs(&x).filter(|ep| ep.role(r).is_established(&k) && ep.role(r).secret(&k).is_some()) else { continue };
        let known;
        let deps = if x == *a {
            deps
        } else {
            known = departures(tx, &x)?;
            &known
        };
        let held = tx.core.names_held(&x);
        if !osis_keys::uncovered(&x, &epochs, r, &k, deps, &held).is_empty() {
            return Ok(true);
        }
        if !may_rotate(tx.core, who, &x).contains(&r) {
            continue;
        }
        if members::stale_at(tx, &x, r, &k)? || members::keyless_at(tx, &x, r, &k)? {
            return Ok(true);
        }
        for (m, j) in members::boxed_keysets(tx, &x, r, &k)? {
            if seen.insert((m, j)) {
                todo.push((m, j));
            }
        }
    }
    Ok(false)
}

/// `blocked_roles_of` with every departure of `a` this node knows.
pub(crate) fn blocked_roles(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
    blocked_roles_of(tx, who, a, &deps)
}

/// The roles of `a` that `who` may rotate whose rotation is due
/// (spec/crypto.md §4, encrypting under): blocked (`blocked_roles_of`), or some current epoch,
/// not only the newest, does not cover a known departure (one whose secret this node lacks
/// covers nothing: it is superseded unread), or the role forked and `who` is its merger (merge,
/// rule 3), or some current epoch, held or not, has a stale box (rule 2) or a box to an actor
/// whose grant is keyless (the knowing re-key, rule 4). No secret of the role is needed; the
/// commit must be uploadable (`wrappable`), else the rotation waits for a re-seal.
fn rotation_due(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<BTreeSet<Role>> {
    let may = may_rotate(tx.core, who, a);
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let deps = departures(tx, a)?;
    let blocked = blocked_roles_of(tx, who, a, &deps)?;
    let mut out = BTreeSet::new();
    let roles: Vec<Role> = ROLES.into_iter().filter(|r| may.contains(r) && !epochs.role(*r).current().is_empty()).collect();
    for r in roles {
        let held = tx.core.names_held(a);
        let mut due = blocked.contains(&r) || osis_keys::merge_due(a, &epochs, r, &deps, &held) || osis_keys::fork_merger(&epochs, r, |e| maker(tx.core, who, a, r, e));
        // judged from the state, so for current epochs whose secret this node lacks too
        for e in epochs.role(r).current() {
            due = due || members::keyless_at(tx, a, r, &e)? || members::stale_at(tx, a, r, &e)?;
        }
        if due {
            out.insert(r);
        }
    }
    Ok(if wrappable(&epochs, &out) { out } else { BTreeSet::new() })
}

/// Whether a rotation of `roles` can be uploaded (spec/crypto.md §5): rotating read, its commit
/// wraps under the newest established read secret held (current or not); otherwise under the
/// newest current read secret held, as any commit. A node holding neither is stranded
/// (spec/permissions.md §4): it waits for a re-seal.
fn wrappable(epochs: &ActorEpochs, roles: &BTreeSet<Role>) -> bool {
    if roles.contains(&Role::Read) { epochs.read.newest_secret().is_some() } else { epochs.read.newest_held().is_some() }
}

/// The maker of epoch `e` of role `r` of `a` as `who` sees it (`osis_keys::fork_merger`): the
/// author of its rotation commit (`epoch_intro`); unknown without one (a snapshot's epoch).
fn maker(core: &Core, who: &Tid, a: &Tid, r: Role, e: &osis_crypto::Epoch) -> Option<osis_keys::Maker> {
    let (_, c) = core.ix.epoch_intro.get(&(*a, r, *e))?;
    let author = core.ix.commits.get(c)?.view.author;
    Some(osis_keys::Maker { me: author == *who, may_rotate: may_rotate(core, &author, a).contains(&r) })
}

/// Current holders of `a` for keys (`Core::key_holders`) as a rotation by `who` boxes them
/// (`members::sealed`); each of `skip` gets its new role or is left out (departing holders).
/// Holders boxed nothing (keys unknown, no keyset to seal to or encrypt under, no key access) are left out:
/// re-sealed later where the re-seal trigger finds them. `None`: the rotation waits (Seal waits
/// for a holder actor's keyset).
pub(crate) fn recipients(tx: &mut Tx<'_>, who: &Tid, a: &Tid, skip: &[(Tid, Option<Role>)]) -> Result<Option<Vec<Recipient>>> {
    let mut out = Vec::new();
    for (m, role) in tx.core.key_holders(a) {
        let role = match skip.iter().find(|(s, _)| *s == m) {
            Some((_, Some(r))) => *r,
            Some((_, None)) => continue,
            None => role,
        };
        match members::sealed(tx, who, a, &m, role)? {
            Sealed::Boxed(r) => out.push(r),
            Sealed::Out => {}
            Sealed::Wait => return Ok(None),
        }
    }
    Ok(Some(out))
}

/// The error a rotation, grant or re-seal gets while Seal waits (`recipients`); a removal or
/// finalize goes without its rotation then (`flows::edges::demote_in`, `finalize_in`).
pub(crate) const SEAL_WAITS: Error = Error::Misuse("a holder actor's keysets have forked: this waits until that actor's merger merges them (spec/crypto.md §4, Seal)");

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

/// The rotation of `roles` of `a` (boxes for `holders`, from `recipients`), written into `m`, its
/// history boxes carrying the secrets this node holds and the names of the departures from `a`
/// it holds (`departures::names`). `held` is this node's view (derived epochs for the switch to
/// secrets of its own). `departs`: the same commit makes a departure from `a` (a removal's
/// rotation): its names mark it by `ts` and signer, and the commit covers that departure itself
/// (spec/crypto.md §4, covers).
pub(crate) fn rotation_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, holders: &[Recipient], departs: bool) -> Result<Rotation> {
    let secrets = secrets_in(tx, &a)?;
    let own = departs.then(|| {
        let ts = *m.ts.get_or_insert_with(|| tx.core.hlc.next());
        osis_keys::Own { ts: ts.to_u64(), node: m.signer.unwrap_or(tx.core.id.tid()) }
    });
    let names = departures::names(tx.core, &a, own);
    let rot = rotate(&a, roles, held, &secrets, holders, &names, &mut *tx.rng)?;
    put_secrets(m, a, &rot.secrets, false)?;
    put_keysets(m, a, &rot.keys)?;
    Ok(rot)
}

/// Whether `who` may rotate `roles` of `a` boxing `holders` (`members::authority`), needing the
/// role every node judges the rotation's `secrets.0` delta by (`apply::validity::secrets_role`):
/// the highest rotated, and at least write. A removal or finalize whose rotation fails it goes
/// alone (`flows::edges::demote_in`).
pub(crate) fn possessed(core: &Core, who: &Tid, a: &Tid, roles: &BTreeSet<Role>, holders: &[Recipient]) -> bool {
    roles.iter().max().is_none_or(|top| members::authority(core, who, a, roles, (*top).max(Role::Write), holders))
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
    // a plain thing's: derived from its base actor, with what an invalid rotation gave it for reading
    let base = tx.core.epochs(&a).or_else(|| tx.core.ix.secrets.get(&a).cloned()).unwrap_or_default();
    tx.core.ix.secrets.insert(a, base.into_record());
    let e = tx.core.ix.secrets.entry_or_default(a);
    rot.record(e);
    save_epochs(tx, &a)?;
    // the history boxes the new secrets open (spec/crypto.md §4), as a rebuild reads them
    crate::apply::observe_state(tx, &a, &flows::ak("secrets.0")?)
}

/// Rotates `roles` of `a` in a commit of its own (a cascade rotation: changes no edge), signed
/// by `who`.
pub(crate) fn rotate_now(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let holders = recipients(tx, &who, &a, &[])?.ok_or(SEAL_WAITS)?;
    rotate_boxing(tx, who, a, roles, &holders)
}

/// `rotate_now` boxing `holders` (`recipients`).
fn rotate_boxing(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>, holders: &[Recipient]) -> Result<Done> {
    let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let mut m = Mutation::new();
    if who != tx.core.id.tid() {
        m.sign_as(who);
    }
    let rot = rotation_into(tx, &mut m, a, roles, &held, holders, false)?;
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
/// `to`; first under the labels above `a`, which must learn its new `keys.0`
/// (spec/permissions.md §3), with the commits its names name; and under `a`'s own labels the
/// keyset commits its boxes to holder actors name (spec/crypto.md §4, Carried).
fn recorded(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, rot: &Rotation, to: &[Tid], done: &mut Done) -> Result<()> {
    record(tx, a, rot)?;
    done.add(c);
    done.deliveries.extend(deliver_rotation(tx, a, c, to)?);
    if let Some(c) = c {
        let under = above(tx.core, &a);
        done.deliveries.push(flows::owe(tx, Delivery::First { commits: placed_with(c, Some(&rot.names)), under })?);
        carry(tx, a, &rot.secrets, done)?;
    }
    Ok(())
}

/// The keyset commits the boxes `w` of `a` name (`members::carried`), placed first under `a`'s
/// labels (spec/crypto.md §4, Carried): `a`'s writers judge those keysets from them (stale).
pub(crate) fn carry(tx: &mut Tx<'_>, a: Tid, w: &osis_keys::SecretsWrite, done: &mut Done) -> Result<()> {
    let commits = members::carried(tx.core, w);
    if !commits.is_empty() {
        done.deliveries.push(flows::owe(tx, Delivery::First { commits, under: vec![a] })?);
    }
    Ok(())
}

/// Commit `c` (a rotation) and the commits `names` (its names) name: placed together, first,
/// under each label `c` goes under (spec/crypto.md §4, names), so whoever reads `c` there can
/// meet them.
pub(crate) fn placed_with(c: osis_base::CommitId, names: Option<&osis_keys::Names>) -> Vec<osis_base::CommitId> {
    let named: BTreeSet<osis_base::CommitId> = names.into_iter().flat_map(|n| n.list.iter().map(|n| n.key.commit)).filter(|x| *x != c).collect();
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
/// encrypts under its secrets (spec/permissions.md §3): first, depth-first, those of the holder
/// actors of `a` with key access that `who` may rotate (boxing `a` to one is encrypting under
/// its epoch, so its rotation due goes first and `a`'s boxes then name its new keyset), each
/// once, then `a`'s (`rotation_due`). Each of those actors first gets the finalize `who` may
/// write of its edges past their `until` (`finalize_due`). Returns the roles of `a` still
/// blocked: it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, who: Tid, a: Tid, done: &mut Done) -> Result<BTreeSet<Role>> {
    ensure_rotated_but(tx, who, a, &[], done)
}

/// `ensure_rotated`, finalizing on `a` no edge of a holder in `rewriting`: the commit about to
/// be written writes those edges anew (a removal, which is their departure, or a renewal).
pub(crate) fn ensure_rotated_but(tx: &mut Tx<'_>, who: Tid, a: Tid, rewriting: &[Tid], done: &mut Done) -> Result<BTreeSet<Role>> {
    let target = a;
    // a plain thing follows the epochs of the next actor up its record chain
    let mut found = None;
    for step in tx.core.record_chain(&a) {
        let Some(t) = step.thing() else { break };
        if tx.core.has_own_secrets(&t) {
            found = Some(t);
            break;
        }
        match step {
            osis_base::ChainStep::Up { admin: up, .. } if !tx.core.is_key_actor(&up) => {}
            _ => break,
        }
    }
    let Some(a) = found else { return Ok(BTreeSet::new()) };
    let members = |tx: &mut Tx<'_>, x: &Tid| -> Vec<Tid> {
        let ms: Vec<Tid> = tx.core.key_holders(x).into_iter().map(|m| m.0).filter(|m| m != x && !tx.core.is_key_actor(m) && tx.core.has_own_secrets(m)).collect();
        let mut out: Vec<Tid> = ms.into_iter().filter(|m| members::keyed(tx.core, x, m) && !may_rotate(tx.core, &who, m).is_empty()).collect();
        out.reverse();
        out
    };
    // depth-first, post-order, without recursion (chains have no depth bound)
    let mut entered = BTreeSet::from([a]);
    let mut stack = vec![(a, members(tx, &a))];
    while let Some((x, next)) = stack.last_mut() {
        if let Some(y) = next.pop() {
            if entered.insert(y) {
                let f = members(tx, &y);
                stack.push((y, f));
            }
            continue;
        }
        let x = *x;
        stack.pop();
        finalize_due(tx, who, x, if x == target { rewriting } else { &[] }, done)?;
        let mine = rotation_due(tx, &who, &x)?;
        if mine.is_empty() {
            continue;
        }
        // a rotation due waits (its roles stay blocked) while Seal waits for a holder actor's
        // keyset, or for want of possession: every node would judge it invalid
        if let Some(holders) = recipients(tx, &who, &x, &[])?
            && possessed(tx.core, &who, &x, &mine, &holders)
        {
            done.extend(rotate_boxing(tx, who, x, &mine, &holders)?);
        }
    }
    blocked_roles(tx, &who, &a)
}

/// The finalize `who` may write of the edges on `a` past their `until` by this node's clock
/// (spec/permissions.md §2, `flows::edges::finalizable`), written now: a node with write on `a`
/// writes it before its next commit encrypting under `a`. It is `a`'s departure for keys, and
/// carries the rotation where `who` can make it now, else goes alone (the departure uncovered,
/// so `a`'s roles stay blocked until a rotation covers it).
pub(crate) fn finalize_due(tx: &mut Tx<'_>, who: Tid, a: Tid, skip: &[Tid], done: &mut Done) -> Result<()> {
    let mut ended = flows::edges::finalizable(tx.core, &who, &a);
    ended.retain(|x| !skip.contains(&x.0));
    if ended.is_empty() {
        return Ok(());
    }
    flows::edges::finalize_in(tx, who, a, &ended, done)
}

/// `ensure_rotated`, failing when `roles` stay blocked: for what encrypts under the epochs
/// (steps, entry boxes, content), not for a grant or re-seal (a box carrying a secret is
/// encrypted under its recipient's key, spec/crypto.md §4, Encrypting under).
pub(crate) fn require_covered(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>, done: &mut Done) -> Result<()> {
    let still = ensure_rotated(tx, who, a, done)?;
    if roles.iter().any(|r| still.contains(r)) {
        return Err(Error::Misuse("an epoch to encrypt under does not cover a known departure (another node must rotate first)"));
    }
    Ok(())
}

/// Gives `t` secrets of its own (spec/permissions.md §3, spec/crypto.md §3): a rotation of all
/// three roles from its derived epochs (those of the next actor up its record chain: rotated
/// first where this node can, the history boxes carry them), boxed to its current holders (its
/// first admin included; not one whose grant this node may finalize, `ended_holders`), with a
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
    ensure_rotated(tx, who, t, done)?;
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the secrets it derives from are not held"))?;
    // a holder whose grant this node may finalize is boxed nothing (spec/permissions.md §2), as
    // a re-seal boxes it nothing: its departure is due, and the finalize follows
    let ended: Vec<(Tid, Option<Role>)> = ended_holders(tx.core, &who, &t).into_iter().map(|m| (m, None)).collect();
    let holders = recipients(tx, &who, &t, &ended)?.ok_or(SEAL_WAITS)?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &holders, false)?;
    fresh_deposit_seed(tx, &mut m, t)?;
    // a labeled thing becomes an actor with a home label: it names it as its inbox (spec/sync.md §2)
    if let Some((label, _, hosts)) = crate::flows::own_label(tx, &t)?
        && crate::flows::labels::takes_inbox(tx, &t, None)?
    {
        crate::flows::labels::name_inbox(&mut m, t, label, &hosts)?;
    }
    let to = unreached(tx, &t, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    Ok(Some((c, rot, to)))
}

/// The plain things whose secrets derive from `a` that this node, an admin of each, sees with a
/// current holder other than its first admin (spec/permissions.md §3: such a thing is left by its
/// only keyset part turning invalid, spec/crypto.md §3); each gets secrets of its own again.
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
        .filter(|t| core.role_now(&me, t) == Some(Role::Admin) && core.key_holders(t).iter().any(|(m, _)| Some(*m) != core.first_admin(t)))
        .collect()
}

/// `own_secrets` for a plain thing with current holders, delivering the rotation by inbox to
/// each holder it boxes (they hold no box at the derived epochs it wraps under) and placing it
/// first under the labels above the thing (its new `keys.0`).
fn own_secrets_delivered(tx: &mut Tx<'_>, t: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some((c, rot, mut to)) = own_secrets_rot(tx, t, &mut done)? else { return Ok(done) };
    let up = tx.core.first_admin(&t);
    to.retain(|m| Some(*m) != up);
    recorded(tx, t, c, &rot, &to, &mut done)?;
    Ok(done)
}

/// The re-seal trigger for `a` (spec/permissions.md §3): current holders for keys lacking a box
/// at a current epoch of a role this node may rotate, as `members::sealed` boxes them (none for
/// an actor without key access or one Seal leaves out, until a keyset exists).
///
/// Invariant: once re-seals and history adds settle (every node holding the same commits finds
/// no holder to re-seal and no history to add), every node counts the same current epochs of
/// each role, since what a rotation supersedes is read from its commit alone (its keyset's list,
/// `osis_keys::SecretsWrite::rotation_commit`, and its history box); every holder of a role
/// holds every current epoch of it that a node that may rotate the role holds, since a holder
/// lacking one lacks its box there (one box per (holder, role, epoch)), and such a node holding
/// it re-seals; and every holder of a current epoch holds every earlier established secret any
/// holder of that epoch holds (`add_history`: a current epoch only non-rotators hold is superseded
/// by the next rotation and its secret added by them). `tests_property::rotation_holds_*` checks it.
pub(crate) fn reseal_candidates(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    if tx.core.reseal_quiet.contains(a) && tx.core.ix.departures.contains_key(a) {
        #[cfg(debug_assertions)]
        assert_eq!(reseal_scan(tx, a)?, Vec::new(), "reseal_quiet of {a:?} went stale");
        return Ok(Vec::new());
    }
    let _s = crate::costs::span("reseal: scan");
    let out = reseal_scan(tx, a)?;
    if out.is_empty() {
        // held while `departures` holds its entry (same rosters, secrets and epochs)
        departures(tx, a)?;
        tx.core.reseal_quiet.insert(*a);
    } else {
        tx.core.reseal_quiet.remove(a);
    }
    Ok(out)
}

fn reseal_scan(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    let me = tx.core.id.tid();
    let may = may_rotate(tx.core, &me, a);
    if may.is_empty() {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let holders: Vec<osis_keys::Holder> = tx.core.key_holders(a).into_iter().map(|(holder, role)| osis_keys::Holder { holder, role }).collect();
    let due = osis_keys::reseal_needed(&secrets, &epochs, &holders);
    let ended = ended_holders(tx.core, &me, a);
    let mut out = Vec::new();
    for (m, roles) in due.into_iter().filter(|(m, _)| !ended.contains(m)) {
        // Fixpoint (the re-seal is written on every pass otherwise): a re-seal is made only
        // when it adds a box the trigger asks for, each at its own key: so only by a node
        // holding the secret of an epoch the holder lacks a box at (`box_holder` boxes just
        // those held; a node may lack a fork's). Every re-seal adds a box until the forks end,
        // so the trigger settles.
        let mut keep: BTreeSet<Role> = roles.into_iter().filter(|r| may.contains(r) && osis_keys::reseal_missing(&secrets, &epochs, &m, *r).iter().any(|e| epochs.role(*r).secret(e).is_some())).collect();
        let Some(role) = holders.iter().find(|h| h.holder == m).map(|h| h.role) else { continue };
        if keep.is_empty() {
            continue;
        }
        // as `reseal_one` boxes it: a holder actor left out of a role is left out of the roles above
        let Sealed::Boxed(rc) = members::sealed(tx, &me, a, &m, role)? else { continue };
        keep.retain(|r| *r <= rc.role);
        if !keep.is_empty() {
            out.push((m, keep));
        }
    }
    Ok(out)
}

/// A re-seal of `holder` for `roles` of `a` (spec/permissions.md §3): its boxes at the current
/// epochs, with history boxes, delivered by inbox (a node: over a direct connection) and placed
/// under the actor's labels like any role commit (later removals reset its box entries: every
/// node must hold them, or the removal waits for good), with the keyset commits it names.
/// The holders of `a` whose grant `who` may finalize (`flows::edges::finalizable`: past its
/// `until` by this node's clock): their departure is due here, so no grant or re-seal by `who`
/// boxes them, whether or not the finalize can be written yet (spec/permissions.md §2).
fn ended_holders(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Tid> {
    flows::edges::finalizable(core, who, a).into_iter().map(|x| x.0).collect()
}

pub(crate) fn reseal_one(tx: &mut Tx<'_>, a: Tid, holder: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let mut done = Done::default();
    // rotate first where due; then re-seal, blocked roles included: a box carrying a secret is
    // encrypted under its recipient's key (`members::sealed` leaves out a blocked keyset of a
    // holder actor), not under the epoch it carries (spec/crypto.md §4, Encrypting under), so
    // nobody new reads under a blocked epoch (`tests::grant_while_blocked_boxes_grantee_only_*`)
    let me = tx.core.id.tid();
    ensure_rotated(tx, me, a, &mut done)?;
    let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let secrets = secrets_in(tx, &a)?;
    let role = tx.core.key_holders(&a).into_iter().find(|(m, _)| *m == holder).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
    if ended_holders(tx.core, &me, &a).contains(&holder) {
        return Err(Error::Misuse("the holder's grant has ended: it is finalized, not re-sealed"));
    }
    let rcpt = match members::sealed(tx, &me, &a, &holder, role)? {
        Sealed::Boxed(r) => r,
        Sealed::Out => return Err(Error::Misuse("the holder has no key access or no keyset this node may seal it to")),
        Sealed::Wait => return Err(SEAL_WAITS),
    };
    // a rotation just made (a merge) boxed the holder at the new epoch already
    let rotated = !done.commits.is_empty();
    let roles: BTreeSet<Role> = roles.iter().copied().filter(|r| *r <= rcpt.role && !(rotated && osis_keys::reseal_missing(&secrets, &epochs, &holder, *r).is_empty())).collect();
    if roles.is_empty() {
        return Ok(done);
    }
    let hist = history_boxes(tx, &me, &a)?;
    let Some(w) = osis_keys::box_holder(&a, &epochs, &hist, &rcpt, &roles, &mut *tx.rng)? else {
        return Err(Error::Misuse("the holder's keyset is unknown"));
    };
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, false)?;
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.extend(flows::edges::deliver_to(tx, holder, c, &[a])?);
        carry(tx, a, &w, &mut done)?;
    }
    Ok(done)
}

/// The history boxes `who` writes for `a`'s current epochs (`osis_keys::history_boxes`): what the
/// live entries list, every earlier superseded established secret held, the names of a met
/// entry. At an epoch blocked for `who` (`blocked_epoch`) only what the live entries list: a
/// history entry is encrypted under its epoch (spec/crypto.md §4, Encrypting under), and a
/// party the epoch does not cover opens it, so a grant or re-seal made while blocked (Seal
/// waiting, Authority failing) copies the history and adds nothing to it.
pub(crate) fn history_boxes(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<HistoryBoxes> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(HistoryBoxes::new()) };
    let secrets = secrets_in(tx, a)?;
    let alts = flows::secrets_alts(tx, a)?;
    let mut hist = osis_keys::history_boxes(a, &epochs, &secrets, &alts, &tx.core.names_held(a));
    let deps = departures(tx, a)?;
    for ((r, e), h) in hist.iter_mut() {
        if blocked_epoch(tx, who, a, *r, e, &deps)? {
            h.earlier.retain(|x, _| h.listed.contains(x));
        }
    }
    Ok(hist)
}

/// The history add for `a` (spec/crypto.md §4, History box): for each current epoch whose
/// secret this node holds established and may encrypt under (`history_boxes`), an entry carrying
/// every earlier superseded established secret it holds when one is not listed, put beside the
/// entries there, by any holder (a reader too: a secret once shared cannot be un-shared, and
/// every holder of the epoch reads its history). Placed under `a`'s labels like any role commit;
/// nothing when every secret held is listed.
pub(crate) fn add_history(tx: &mut Tx<'_>, a: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some(epochs) = tx.core.epochs(&a) else { return Ok(done) };
    let me = tx.core.id.tid();
    if tx.core.role_now(&me, &a).is_none() {
        return Ok(done);
    }
    let hist = history_boxes(tx, &me, &a)?;
    let w = osis_keys::history_adds(&a, &epochs, &hist)?;
    if w.is_empty() {
        return Ok(done);
    }
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, true)?;
    // a reader's write on `secrets.0`: judged by the history-add rule, not the plain role check
    m.unchecked();
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        done.deliveries.push(flows::owe(tx, Delivery::First { commits: vec![c], under: vec![a] })?);
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

    /// The departures from `actor` its epochs must cover, as this node knows them.
    pub fn departures(&mut self, actor: &Tid) -> Result<Vec<Departure>> {
        let a = *actor;
        self.run(|tx| departures(tx, &a))
    }

    /// Gives `thing` secrets of its own (spec/permissions.md §3): before its first holder other
    /// than its first admin, or before it is made a holder of anything.
    pub fn give_own_secrets(&mut self, thing: &Tid) -> Result<Done> {
        let t = *thing;
        self.run(|tx| {
            let mut done = Done::default();
            own_secrets(tx, t, &mut done)?;
            Ok(done)
        })
    }

    /// Gives secrets of their own again to the plain things whose secrets derive from `actor`
    /// that this node administers and sees with a current holder other than its first admin (spec/permissions.md
    /// §3), decided at the end of a complete pass of `actor`'s labels (`sync`); nothing
    /// otherwise. Each thing in a run of its own: one that fails leaves the others.
    pub fn own_secrets_due(&mut self, actor: &Tid, sync: &dyn SyncState) -> Result<Vec<(Tid, Result<Done>)>> {
        if !sync.complete_pass(actor) {
            return Ok(Vec::new());
        }
        let ts = own_secrets_candidates(&self.core, actor);
        Ok(ts.into_iter().map(|t| (t, self.run(|tx| own_secrets_delivered(tx, t)))).collect())
    }

    /// Re-seals the holders of `actor` the trigger names and adds the history its current epochs
    /// lack (spec/permissions.md §3, spec/crypto.md §4 History box), decided at the end of a
    /// complete pass of its labels (`sync`); nothing otherwise.
    pub fn reseal_due(&mut self, actor: &Tid, sync: &dyn SyncState) -> Result<Done> {
        if !sync.complete_pass(actor) {
            return Ok(Done::default());
        }
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            let mut due = reseal_candidates(tx, &a)?;
            if !due.is_empty() {
                // an ended edge is finalized first where this node can (its rotation boxes the
                // others); an ended holder is no candidate either way (`ended_holders`)
                let me = tx.core.id.tid();
                finalize_due(tx, me, a, &[], &mut done)?;
                due = reseal_candidates(tx, &a)?;
            }
            for (m, roles) in due {
                done.extend(reseal_one(tx, a, m, &roles)?);
            }
            done.extend(add_history(tx, a)?);
            Ok(done)
        })
    }

    /// "Re-share with M" by hand (issue reseal-triggers, closed: a manual re-share, notes/label-access.md): re-seals current holder `holder`
    /// of `actor` for every role it holds that this node may rotate, whatever the trigger says
    /// (a holder whose deposits are refused, a stranded heartbeat, a re-paired node).
    pub fn reshare(&mut self, actor: &Tid, holder: &Tid) -> Result<Done> {
        let (a, m) = (*actor, *holder);
        self.run(|tx| {
            let role = tx.core.key_holders(&a).into_iter().find(|(x, _)| *x == m).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
            let me = tx.core.id.tid();
            let may = may_rotate(tx.core, &me, &a);
            let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= role && may.contains(r)).collect();
            if roles.is_empty() {
                return Err(Error::Misuse("this node may not re-seal that holder"));
            }
            reseal_one(tx, a, m, &roles)
        })
    }

}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_members;
#[cfg(test)]
mod tests_possession;
#[cfg(test)]
mod tests_departs;
#[cfg(test)]
mod tests_property;
