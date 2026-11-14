//! Rotations (spec/permissions.md §3, spec/crypto.md §4): when one is due (`rotation_due`:
//! departures from the actor not covered, by any current epoch; stale
//! boxes to holder actors; holders boxed through a keyless grant; an epoch no rotator can
//! re-seal), the cascade
//! (`ensure_rotated`: the holder actors this node may rotate first, then the actor), giving a
//! thing secrets of its own, re-seals and history adds. Rotating needs only the right to rotate,
//! never a prior secret: a rotation supersedes every current epoch, held or not, and any holder
//! of a superseded secret adds it to the new epoch's history (`add_history`). Departures from an
//! actor: `departures`; holder actors (key access, keysets, sealing, staleness): `members`;
//! dropping what this node lost read access to: `lost`.

pub(crate) mod departures;
pub(crate) mod floors;
mod lost;
pub(crate) mod members;
pub(crate) mod merge;
#[cfg(test)]
mod tests_account;
#[cfg(test)]
mod tests_signing;

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{self, Done, put_keysets, put_secrets, save_epochs, secrets_in};
use crate::Mutation;
use osis_base::{Role, Tid};
use osis_keys::{ActorEpochs, Departure, HistoryBoxes, ROLES, Rotation};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use departures::{departures_placing, may_rotate};
pub use lost::{Dropped, Leaving, LostScope, LOST_HEARD_WAIT_MS};
pub(crate) use lost::{load_kept, without_frozen};
pub(crate) use departures::{departures, key_role, own_self_removal};
pub(crate) use members::{Boxing, Sealed, grant_keyless, sealed};
pub(crate) use lost::{arm_untils, boxes_kept, load_lost_due, mark_lost_due, may_learn, may_take};

/// How far `blocked_epoch` follows boxes to holder actors (spec/crypto.md §4, Encrypting under).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// For encrypting under, sealing a holder actor at a keyset included: through every holder
    /// actor whose boxes this node holds, rights aside (what a departed party opens does not
    /// depend on who may rotate), a stale box at any epoch walked blocking.
    Encrypt,
    /// For placing role commits and certificates under labels (spec/sync-judgement.md §1): through the
    /// holder actors this node may rotate only, so a node that may not rotate an actor still
    /// places the keysets and revokes that tell that actor's rotators (node-sync's pass).
    Place,
}

/// The roles of `a` that `who` (this node, or a key actor it signs as) may not encrypt under
/// (spec/crypto.md §4, encrypting under), or place under (`walk`): those whose newest held
/// current epoch is blocked (`blocked_epoch`, `deps` the departures from `a` counted).
pub fn blocked_roles_of(tx: &mut Tx<'_>, who: &Tid, a: &Tid, deps: &[Departure], walk: Walk) -> Result<BTreeSet<Role>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let mut out = BTreeSet::new();
    for r in ROLES {
        let Some((e, _)) = epochs.role(r).newest_held() else { continue };
        if blocked_epoch(tx, who, a, r, &e, deps, walk)? {
            out.insert(r);
        }
    }
    Ok(out)
}

/// Whether `who` may not encrypt under epoch `e` of role `r` of `a` (spec/crypto.md §4,
/// encrypting under; sealing a holder actor at keyset `e` is encrypting under it), `deps` the
/// departures from `a` counted: `e` does not cover one of them (`uncovered`); or `e`, or an
/// epoch the walk follows from it, has a stale box to a holder actor (rule 2), whoever may rotate
/// it and whether or not its secret is held; or `who` may rotate `r` and `e` boxes a holder past
/// its key access to `a` (rule 4); or `e` boxes a holder actor M at a keyset of M under which
/// `who` may not encrypt, by this same rule with every departure from M this node knows (sealing
/// at that keyset was encrypting under it). A stale box names a keyset its own holder actor has
/// moved past: what that keyset's departed party opens, the epoch boxing it hands on, and past an
/// epoch whose secret this node lacks it is all the node can judge (a writer of G holding M's
/// new keyset but none of A's secrets would otherwise write under G's epoch boxing A at an epoch
/// boxing M at the old one). Keyless binds rotators only: it says a rotation is due, not that a
/// departed party opens `e`. The box clause follows every box at an epoch whose secret this node
/// holds (`Walk::Encrypt`: what a departed party opens does not depend on who may rotate), or for
/// placing only those of actors it may rotate, stale boxes binding only those rotators
/// (`Walk::Place`): a node that may not rotate places its chain certificates (and revokes) under
/// the actor's labels meanwhile, the holder actors' new `keys.0` among them, which is how the
/// rotators learn of the staleness. Only epochs whose secret this node holds are
/// walked past (it reads that actor's labels, so it learns the actor's next keyset and re-seals
/// it), and only other parties' departures count (`others`); past any other epoch (but for
/// placing) only a box to this node's own account is judged, at any depth: an account epoch it
/// cannot show covers a removal from its devices actor it knows (`uncovered`) blocks the keyset
/// boxing it, secret held or not (it learns its account's next epochs from its devices actor's
/// labels, and so re-seals once either moves).
///
/// A joint box (several keysets) is judged as a whole: blocked by a departure only when every
/// keyset it names is (it opens only for a holder of every one, so for no party, alone or pooled
/// with others, that one of them keeps out), by a stale or keyless box when any is
/// (`joint_blocked`).
///
/// Invariant: a node holding M's secrets that knows a departure from M seals nothing at a keyset
/// of M not covering it (`members::sealed` leaves M out), and writes no box or history entry
/// under an epoch boxing M at such a keyset, at any height above M: the party removed from M
/// opens none of it, M's rotation made or not (model `D0_above`, `D0_readers_out`,
/// `NoLeakAbove`). Walked over the boxes without recursion (chains have no depth bound) but
/// at a joint box, each (actor, epoch) once per walk (boxes may cycle).
pub(crate) fn blocked_epoch(tx: &mut Tx<'_>, who: &Tid, a: &Tid, r: Role, e: &osis_crypto::Epoch, deps: &[Departure], walk: Walk) -> Result<bool> {
    let mut own = None;
    Ok(walk_from(tx, who, a, r, (*a, *e, true), deps, walk, false, BTreeSet::new(), &mut own)?.is_some())
}

/// Why `who` may not encrypt under an epoch (`blocking`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    /// It misses a departure it must cover, here or at a keyset it boxes: the departed party may
    /// open it.
    Departure,
    /// It, or an epoch it boxes, has a stale box or one past key access: its rotator re-keys,
    /// whoever opens it.
    Box,
}

/// `blocked_epoch`, with why: a box reason where any is found, else a missed departure.
pub(crate) fn blocking(tx: &mut Tx<'_>, who: &Tid, a: &Tid, r: Role, e: &osis_crypto::Epoch, deps: &[Departure], walk: Walk) -> Result<Option<Block>> {
    let mut own = None;
    walk_from(tx, who, a, r, (*a, *e, true), deps, walk, true, BTreeSet::new(), &mut own)
}

/// Whether the keysets `why` judged (`blocking`) block a box naming `n` of them, one or jointly:
/// any by a stale or keyless box, or every one by a missed departure. The keysets that leave the
/// holder out (`members::left_out` records them), none when the box may be made.
pub(crate) fn joint_blocked(why: BTreeMap<osis_crypto::Epoch, Block>, n: usize) -> BTreeSet<osis_crypto::Epoch> {
    if why.len() == n || why.values().any(|b| *b == Block::Box) { why.into_keys().collect() } else { BTreeSet::new() }
}

/// `blocking` from `root` (an epoch of an actor, with whether every epoch above it on the walk is
/// one whose secret this node holds), past the epochs in `seen`; `own`: whether this node knows a
/// removal from its devices actor, found when first needed. `full`: on past a missed departure,
/// for a box reason (else the first reason found).
#[allow(clippy::too_many_arguments)]
fn walk_from(tx: &mut Tx<'_>, who: &Tid, a: &Tid, r: Role, root: (Tid, osis_crypto::Epoch, bool), deps: &[Departure], walk: Walk, full: bool, mut seen: BTreeSet<(Tid, osis_crypto::Epoch)>, own: &mut Option<bool>) -> Result<Option<Block>> {
    seen.insert((root.0, root.1));
    let mut todo = vec![root];
    let mut missed = false;
    while let Some((x, k, read)) = todo.pop() {
        if !missed && (read || tx.core.me() == Some(x)) {
            let known = if x == *a { deps.to_vec() } else { keyset_departures(tx, &x)? };
            let deps = others(tx.core, known);
            missed = uncovered(tx, &x, r, &k, &deps)?;
            if missed && !full {
                return Ok(Some(Block::Departure));
            }
        }
        // encrypting under an epoch that boxes, at any depth, a superseded keyset hands the secret
        // to what that keyset's departed party opens; the box and keysets are state, so judged
        // without the epoch's secret; an account boxes only its key actors, which have no keysets
        // to go stale (its `secrets.0` is not read for it)
        if read && walk == Walk::Encrypt && !tx.core.is_account(&x) && members::stale_at(tx, &x, r, &k)? {
            return Ok(Some(Block::Box));
        }
        let next = if !read || !tx.core.epochs(&x).is_some_and(|ep| ep.role(r).is_established(&k) && ep.role(r).secret(&k).is_some()) {
            // past an epoch whose secret this node lacks: boxes to its own account, at any depth
            let mine = match *own {
                Some(b) => b,
                None => {
                    let b = match tx.core.me() {
                        Some(p) if walk != Walk::Place => {
                            let known = keyset_departures(tx, &p)?;
                            !others(tx.core, known).is_empty()
                        }
                        _ => false,
                    };
                    *own.insert(b)
                }
            };
            if !mine {
                continue;
            }
            false
        } else {
            let rotator = may_rotate(tx.core, who, &x).contains(&r);
            if rotator && ((walk == Walk::Place && members::stale_at(tx, &x, r, &k)?) || members::keyless_at(tx, &x, r, &k)?) {
                return Ok(Some(Block::Box));
            }
            if !rotator && walk == Walk::Place {
                continue;
            }
            true
        };
        for (m, js) in members::boxed_keysets(tx, &x, r, &k)? {
            if let [j] = js.as_slice() {
                if seen.insert((m, *j)) {
                    todo.push((m, *j, next));
                }
                continue;
            }
            // a joint box: each keyset it names judged on its own walk, the box as a whole. A
            // keyset already on this walk (or an enclosing one) counts as not blocked here: that
            // walk judges it, and blocks for it whatever this box does. The keysets are not marked
            // seen: one reached alone by another box is still walked.
            let mut why = BTreeMap::new();
            for j in js.iter().filter(|j| !seen.contains(&(m, **j))) {
                if let Some(b) = walk_from(tx, who, a, r, (m, *j, next), deps, walk, true, seen.clone(), own)? {
                    why.insert(*j, b);
                }
            }
            let boxed = why.values().any(|b| *b == Block::Box);
            if !joint_blocked(why, js.len()).is_empty() {
                if boxed {
                    return Ok(Some(Block::Box));
                }
                if !full {
                    return Ok(Some(Block::Departure));
                }
                missed = true;
            }
        }
    }
    Ok(missed.then_some(Block::Departure))
}

/// The departures from holder actor `x` its keysets must cover, as this node knows them: an
/// account's are those from its devices actor, which only the account's own nodes hold.
pub(crate) fn keyset_departures(tx: &mut Tx<'_>, x: &Tid) -> Result<Vec<Departure>> {
    match tx.core.accounts.get(x).map(|h| h.devices) {
        Some(d) => departures(tx, &d),
        None => departures(tx, x),
    }
}

/// Whether epoch `k` of role `r` of `x` does not cover one of `deps` as this node can tell
/// (spec/crypto.md §4, Encrypting under): by its history entries where it holds `k`'s secret
/// established; else by order: an epoch covers no departure ordered after its minting rotation
/// (its rotator held none of them), read from the earliest held valid body of the keyset
/// (`HeldKeyset::since`). An account's epoch, by descent: it covers a removal from its devices
/// actor D only descending from a rotation D's roster authorizes whose thing list for D names
/// every write a covering epoch must name (`Departure::needed`); the first epoch covers none,
/// nor one of which this node holds no counting rotation (not by order: a concurrent rotation
/// ordered after the removal by a node not holding it sealed its seed under D's epoch the
/// removed node opens). A departure no keyset of `x` held is known to cover leaves `x` out
/// until one is (a stranded report carries it, spec/permissions.md §4).
pub(crate) fn uncovered(tx: &mut Tx<'_>, x: &Tid, r: Role, k: &osis_crypto::Epoch, deps: &[Departure]) -> Result<bool> {
    if tx.core.is_account(x) {
        // only the account's own nodes hold D's departures
        let (Some(d), Some(v)) = (tx.core.accounts.get(x).map(|h| h.devices), tx.core.account_view(x)) else { return Ok(false) };
        // an epoch no counting rotation of which is held here shows no line: it covers nothing
        let held = v.holds_name(k);
        for key in deps.iter().filter(|d| d.concerns(r)).flat_map(|d| d.needed(r)) {
            if !held || !crate::flows::lists::names_of(tx, &key.commit)?.iter().any(|(t, s)| *t == d && v.descends_authorized(k, s)) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    let point = |k: osis_keys::Key| osis_base::Ts::from_u64(k.ts).map(|ts| osis_perm::Point { ts, node: k.node, commit: k.commit });
    let core = &*tx.core;
    Ok(match core.epochs(x).filter(|ep| ep.role(r).is_established(k) && ep.role(r).secret(k).is_some()) {
        Some(epochs) => !osis_keys::uncovered(&epochs, r, k, deps, &core.names_held(x)).is_empty(),
        None => core.keyset(x, r, k).is_some_and(|held| deps.iter().any(|d| d.concerns(r) && d.newest_needed(r).and_then(point).is_some_and(|p| held.held_before(&p)))),
    })
}

/// `deps` less this node's own departures (its account's or its own): the departed party is the
/// node itself, which holds the epoch already, so its own removal holds back none of its
/// encrypting (spec/crypto.md §4, Encrypting under). Counted, a node removed from holder actor M
/// before M's new keyset reached it left M out of what it rotated and, gone from M, could never
/// re-seal it.
fn others(core: &Core, deps: Vec<Departure>) -> Vec<Departure> {
    let own = |h: &Tid| core.me() == Some(*h) || *h == core.id.tid();
    deps.into_iter().filter(|d| !own(&d.holder)).collect()
}

/// `blocked_roles_of` with every departure of `a` this node knows.
pub(crate) fn blocked_roles(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<BTreeSet<Role>> {
    let deps = departures(tx, a)?;
    blocked_roles_of(tx, who, a, &deps, Walk::Encrypt)
}

/// What a rotation is due for (`rotation_due`) besides what encrypting waits for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Due {
    /// Only what encrypting under the actor waits for (`ensure_rotated`).
    Encrypt,
    /// Also withdraws (`pass_end_rotations`).
    PassEnd,
}

/// The roles of `a` that `who` may rotate, but `kept` (`Keep`), whose rotation is due
/// (spec/crypto.md §4, encrypting under): blocked (`blocked_roles_of`), or some current epoch,
/// not only the newest, does not cover a known departure (one whose secret this node lacks
/// covers nothing: it is superseded unread), or some current epoch, held or not, has a stale box
/// (rule 2) or a box to an actor whose grant is keyless (the knowing re-key, rule 4), or is
/// orphaned (`orphaned`), or is a derived read epoch this node wrote under (`merge::due`); one
/// due only for current epochs whose secret this node lacks, where
/// its new epoch boxes a rotator (`boxes_rotator`). With `Due::PassEnd` also when an unsuperseded
/// epoch is not current here and `who` withdraws it, or when a current read epoch's floor is
/// below a holder's (`floors::low_floor_due`). A fork alone is due nothing else: it stands until
/// the role next rotates (spec/crypto.md §4). No secret of the role is needed; the commit
/// must be uploadable (`wrappable`), else the rotation waits for a re-seal.
fn rotation_due(tx: &mut Tx<'_>, who: &Tid, a: &Tid, mode: Due, kept: &BTreeSet<Role>) -> Result<BTreeSet<Role>> {
    let may = may_rotate(tx.core, who, a);
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let deps = departures(tx, a)?;
    let blocked = blocked_roles_of(tx, who, a, &deps, Walk::Encrypt)?;
    let mut out = BTreeSet::new();
    let roles: Vec<Role> = ROLES.into_iter().filter(|r| may.contains(r) && !kept.contains(r) && !epochs.role(*r).current().is_empty()).collect();
    for r in roles {
        let held = tx.core.names_held(a);
        let mut due = blocked.contains(&r);
        // any current epoch, not only the newest, missing a known departure; a
        // fork made unaware of it stays current otherwise and may win the (n, nonce) order, and a
        // holder actor anchored on it never moves to the knowing one. Judged from the state, so
        // for current epochs whose secret this node lacks too; such an
        // epoch covers nothing here, and one orphaned has no re-sealer: a rotation due only for
        // those is made where its new epoch reaches a rotator (`boxes_rotator`)
        let current: Vec<(osis_crypto::Epoch, bool)> = epochs.role(r).current().into_iter().map(|e| (e, !osis_keys::uncovered(&epochs, r, &e, &deps, &held).is_empty())).collect();
        let mut unread = false;
        for (e, uncovered) in current {
            due = due || members::keyless_at(tx, a, r, &e)? || members::stale_at(tx, a, r, &e)?;
            if epochs.role(r).secret(&e).is_some() {
                due = due || uncovered;
            } else {
                unread = unread || uncovered || orphaned(tx, a, r, &e)?;
            }
        }
        due = due || unread && boxes_rotator(tx, who, a, r)?;
        // a derived epoch this node wrote under, current until a rotation carries it
        due = due || r == Role::Read && merge::due(tx, a)?;
        // withdraw: an unsuperseded epoch whose names this node does not meet, by its maker,
        // or by any node that may rotate when its maker may not (or is unknown: a snapshot's
        // epoch); withdraws by several fork, which stands
        let current = epochs.role(r).current();
        due = due || mode == Due::PassEnd && epochs.role(r).unsuperseded().iter().any(|e| !current.contains(e) && maker(tx.core, who, a, r, e).is_none_or(|m| m.me || !m.may_rotate));
        // a current read epoch a holder's floor bars it from (spec/crypto.md §4, Floors)
        due = due || mode == Due::PassEnd && r == Role::Read && floors::low_floor_due(tx, who, a)?;
        if due {
            out.insert(r);
        }
    }
    Ok(if wrappable(&epochs, &out) { out } else { BTreeSet::new() })
}

/// Whether current epoch `e` of role `r` of `a`, whose secret this node lacks, is orphaned
/// (spec/crypto.md §4): it boxes no holder of `a` that may rotate `r`, so no node
/// can re-seal a holder it leaves out (a re-seal needs both). Judged from the state.
fn orphaned(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &osis_crypto::Epoch) -> Result<bool> {
    let secrets = secrets_in(tx, a)?;
    let boxed = secrets.boxes.keys().filter(|k| k.role == r && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == *e));
    Ok(!boxed.into_iter().any(|k| may_rotate(tx.core, &k.holder, a).contains(&r)))
}

/// Whether a rotation of `a` by `who` would box a holder that may rotate `r` at `r`, so that
/// rotator reads its new epoch (spec/crypto.md §4, Encrypting under). A rotation due only for
/// current epochs whose secret this node lacks (covering nothing here, or orphaned) is made only
/// then: else its epoch is one every other rotator lacks alike, which rotates again, for good (a
/// rotator holding `r` only through a holder actor with no keyset to seal to, which every
/// rotation leaves out: `orphaned_rotations_do_not_trade_spec_crypto_4`).
fn boxes_rotator(tx: &mut Tx<'_>, who: &Tid, a: &Tid, r: Role) -> Result<bool> {
    let boxing = recipients(tx, who, a, &[])?;
    Ok(boxing.holders.iter().any(|h| h.role >= r && may_rotate(tx.core, &h.holder, a).contains(&r)))
}

/// Whether a rotation of `roles` can be uploaded (spec/crypto.md §5): rotating read, its commit
/// wraps under the newest established read secret held (current or not); otherwise under the
/// newest current read secret held, as any commit. A node holding neither is stranded
/// (spec/permissions.md §4): it waits for a re-seal.
fn wrappable(epochs: &ActorEpochs, roles: &BTreeSet<Role>) -> bool {
    if roles.contains(&Role::Read) { epochs.read.newest_secret().is_some() } else { epochs.read.newest_held().is_some() }
}

/// The maker of an epoch as a node sees it (`maker`): whether it is this node, and whether it
/// may rotate the role now.
struct Maker {
    me: bool,
    may_rotate: bool,
}

/// The maker of epoch `e` of role `r` of `a` as `who` sees it (withdraw, `rotation_due`): the
/// author of its rotation commit (`epoch_intro`); unknown without one (a snapshot's epoch). It
/// may rotate (`may_rotate`: over grants with key access): a maker
/// whose role runs through a keyless grant makes no valid rotation. `me` is this node, not its
/// account: nodes of one account share an author, and two of them withdrawing alike would fork.
fn maker(core: &Core, who: &Tid, a: &Tid, r: Role, e: &osis_crypto::Epoch) -> Option<Maker> {
    let (_, c) = core.ix.epoch_intro.get(&(*a, r, *e))?;
    let m = core.ix.commits.get(c)?;
    let author = m.view.author;
    Some(Maker { me: author == *who && m.origin == crate::events::Origin::Local, may_rotate: may_rotate(core, &author, a).contains(&r) })
}

/// Current holders of `a` for keys (`Core::key_holders`) as a rotation by `who` boxes them
/// (`members::sealed`); each of `skip` gets its new role or is left out (departing holders).
/// Holders boxed nothing (keys unknown, no keyset to seal to or encrypt under, no key access) are left out:
/// re-sealed later where the re-seal trigger finds them; what the rotation records of the holder
/// actors so left out (`members::left_out`) goes with it.
pub(crate) fn recipients(tx: &mut Tx<'_>, who: &Tid, a: &Tid, skip: &[(Tid, Option<Role>)]) -> Result<Boxing> {
    let mut out = Boxing { holders: Vec::new(), left_out: osis_keys::LeftOut::new() };
    for (m, role) in tx.core.key_holders(a) {
        let role = match skip.iter().find(|(s, _)| *s == m) {
            Some((_, Some(r))) => *r,
            Some((_, None)) => continue,
            None => role,
        };
        let (sealed, blocked) = members::sealing(tx, who, a, &m, role)?;
        let boxed = match sealed {
            Sealed::Boxed(r) => {
                let top = r.role;
                out.holders.push(r);
                Some(top)
            }
            Sealed::Out => None,
        };
        members::left_out(tx, a, &m, role, boxed, &blocked, &mut out.left_out)?;
    }
    Ok(out)
}

/// A fresh deposit seed for `a` in `m` (spec/crypto.md §3; an admin's write).
pub(crate) fn fresh_deposit_seed(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid) -> Result<osis_crypto::Secret32> {
    let mut seed = [0u8; 32];
    tx.rng.fill_bytes(&mut seed);
    m.op(a, &osis_schema::core_types::KEYS, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(5)], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&Some(seed))) })?;
    let out = osis_crypto::Secret32::from_bytes(seed);
    seed.fill(0);
    Ok(out)
}

/// Whether a rotation of `roles` of `a` by `who` also refreshes `a`'s deposit seed (spec/crypto.md
/// §3): it rotates sync (every departure from sync or above does), so the departed party (which
/// read the seed in `keys.0`, a holder of sync alone included) can no longer deposit under `a`'s
/// labels, and `who` is an admin (the seed is admin-written).
/// A devices actor's labels derive deposit keys from its account's inbox seed, which anyone may
/// deposit by: none to refresh.
pub(crate) fn refreshes_deposit(core: &Core, who: &Tid, a: &Tid, roles: &BTreeSet<Role>) -> bool {
    roles.contains(&Role::Sync) && may_rotate(core, who, a).contains(&Role::Admin) && core.devices_of(a).is_none()
}

/// What the commit carrying a rotation of an actor departs from it (`rotation_into`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Departs {
    No,
    /// A holder's departure (a removal's or finalize's rotation): its names mark it.
    Holder,
    /// One that also demotes a writer or admin (an explicit lowering from write or above): its
    /// keysets carry their own commit too (spec/crypto.md §4, Carried demotions).
    Demoting,
}

/// The rotation of `roles` of `a` (boxes and left-out records from `recipients`), written into `m`, its
/// history boxes carrying the secrets this node holds and the names of the departures from `a`
/// it holds (`departures::names`), its keysets the demotions it holds in effect on `a`
/// (`departures::carried`). `held` is this node's view (derived epochs for the switch to secrets
/// of its own). `departs`: what the same commit departs from `a` (a removal's rotation): its
/// names mark it by `ts`, signer and blind, and the commit covers that departure itself
/// (spec/crypto.md §4, covers).
pub(crate) fn rotation_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, boxing: &Boxing, departs: Departs) -> Result<Rotation> {
    cut_into(tx, m, a, roles, held, boxing, departs, false)
}

/// `rotation_into`; `cut`: a grant without history's rotation (spec/crypto.md §4, Floors): its
/// read history box carries no earlier secret and its floor is its own n.
#[allow(clippy::too_many_arguments)]
pub(crate) fn cut_into(tx: &mut Tx<'_>, m: &mut Mutation, a: Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, boxing: &Boxing, departs: Departs, cut: bool) -> Result<Rotation> {
    let secrets = secrets_in(tx, &a)?;
    let own = if departs != Departs::No {
        let ts = *m.ts.get_or_insert_with(|| tx.core.hlc.next());
        let blind = *m.blind.get_or_insert_with(|| crate::engine::write::draw_blind(&mut *tx.rng));
        let author = match m.signer {
            Some(s) => s,
            None => tx.core.writer()?,
        };
        Some(osis_keys::Own { ts: ts.to_u64(), author, blind })
    } else {
        None
    };
    let names = departures::names(tx.core, &a, own);
    let carried = osis_keys::Carried { demotions: departures::carried(tx.core, &a), demotes: departs == Departs::Demoting };
    let rot = osis_keys::rotate_leaving_out(&a, roles, held, &secrets, &boxing.holders, &boxing.left_out, &carried, &names, cut, &mut *tx.rng)?;
    put_secrets(m, a, &rot.secrets, false)?;
    flows::unseal(tx, m, a, &rot.secrets.removed)?;
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
    let me = tx.core.writer()?;
    let mut out: Vec<Tid> = rot.secrets.boxes.keys().map(|k| k.holder).filter(|m| *m != me).collect();
    out.sort();
    out.dedup();
    // reached: boxed at the epoch the commit is wrapped under (a current one: held by box), or,
    // with none, at a current epoch. A holder a floor bars from that epoch (spec/crypto.md §4,
    // Floors: a fork beside its cut) is boxed at another and must take the commit by inbox
    let wrap = rot.wrap_epoch();
    out.retain(|m| !secrets.boxes.keys().any(|k| k.holder == *m && k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| wrap.map_or(epochs.read.is_current(&e), |w| e == w))));
    Ok(out)
}

/// The inbox (a node: direct) deliveries of rotation commit `c` of `a` to `holders`.
pub(crate) fn deliver_rotation(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, holders: &[Tid]) -> Result<()> {
    if let Some(c) = c {
        for m in holders {
            flows::edges::deliver_to(tx, *m, c, &[a])?;
        }
    }
    Ok(())
}

/// Records a rotation this node made (spec/crypto.md §4: its own epochs are established).
pub(crate) fn record(tx: &mut Tx<'_>, a: Tid, rot: &Rotation) -> Result<()> {
    tx.core.touch();
    // a plain thing's: derived from its base actor, with what an invalid rotation gave it for reading
    let base = tx.core.epochs(&a).map(Arc::unwrap_or_clone).or_else(|| tx.core.ix.secrets.get(&a).cloned()).unwrap_or_default();
    tx.core.ix.secrets.insert(a, base.into_record());
    let e = tx.core.ix.secrets.entry_or_default(a);
    rot.record(e);
    save_epochs(tx, &a)?;
    // the history boxes the new secrets open (spec/crypto.md §4), as a rebuild reads them
    crate::apply::observe_state(tx, &a, &flows::ak("secrets.0")?)?;
    merge::settle(tx, &a).map(|_| ())
}

/// Rotates `roles` of `a` in a commit of its own (a cascade rotation: changes no edge), signed
/// by `who` (the tests' rotation by hand).
#[cfg(test)]
pub(crate) fn rotate_now(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>) -> Result<Done> {
    let mut done = Done::default();
    let holders = recipients(tx, &who, &a, &[])?;
    done.extend(rotate_boxing(tx, who, a, roles, &holders)?);
    Ok(done)
}

/// `rotate_now` boxing `holders` (`recipients`).
fn rotate_boxing(tx: &mut Tx<'_>, who: Tid, a: Tid, roles: &BTreeSet<Role>, holders: &Boxing) -> Result<Done> {
    let held = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let mut m = Mutation::new();
    if who != tx.core.writer()? {
        m.sign_as(who);
    }
    let rot = rotation_into(tx, &mut m, a, roles, &held, holders, Departs::No)?;
    if refreshes_deposit(tx.core, &who, &a, roles) {
        fresh_deposit_seed(tx, &mut m, a)?;
    }
    let unreached = unreached(tx, &a, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    let mut done = Done::default();
    recorded(tx, a, c, &rot, &unreached, &mut done)?;
    Ok(done)
}

/// Records rotation `rot` of `a`, committed as `c`, into `done` with its inbox deliveries to
/// `to`.
pub(crate) fn recorded(tx: &mut Tx<'_>, a: Tid, c: Option<osis_base::CommitId>, rot: &Rotation, to: &[Tid], done: &mut Done) -> Result<()> {
    record(tx, a, rot)?;
    done.add(c);
    deliver_rotation(tx, a, c, to)
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
/// write of its edges past their `until` (`finalize_due`). Then, for each actor rotated, the
/// same for the actors it is a holder of, upward (`rotate_above`). Returns the roles of `a`
/// still blocked: it must not encrypt under them.
pub(crate) fn ensure_rotated(tx: &mut Tx<'_>, who: Tid, a: Tid, done: &mut Done) -> Result<BTreeSet<Role>> {
    ensure_rotated_but(tx, who, a, &[], &BTreeSet::new(), done)
}

/// What the cascade before a commit leaves alone on the actor `on` the commit writes, wherever
/// it meets `on` (below, or upward from a holder actor it rotated): it finalizes no edge of a
/// holder in `rewriting` (the commit writes those edges anew: a removal, which is their
/// departure, or a renewal) and no rotation of it, a finalize's included, rotates any of
/// `leaving` (the roles the removal's holders leave, which its own rotation rotates: so none
/// boxes a party at a role it is leaving).
#[derive(Clone, Copy)]
pub(crate) struct Keep<'k> {
    on: Tid,
    rewriting: &'k [Tid],
    leaving: &'k BTreeSet<Role>,
}

impl Keep<'_> {
    /// The roles of `x` no rotation in the cascade may rotate: `leaving` on `on`, none elsewhere.
    fn kept(keep: Option<Self>, x: &Tid) -> BTreeSet<Role> {
        keep.filter(|k| k.on == *x).map(|k| k.leaving.clone()).unwrap_or_default()
    }
}

/// `ensure_rotated` before a commit writing `rewriting`'s edges on `a`, whose holders leave
/// `leaving` of it (`Keep`).
pub(crate) fn ensure_rotated_but(tx: &mut Tx<'_>, who: Tid, a: Tid, rewriting: &[Tid], leaving: &BTreeSet<Role>, done: &mut Done) -> Result<BTreeSet<Role>> {
    let keep = Keep { on: a, rewriting, leaving };
    let rotated = rotate_below(tx, who, a, Some(keep), Due::Encrypt, done)?;
    rotate_above(tx, who, rotated, Some(keep), done)?;
    let Some(a) = secret_actor_up(tx.core, &a) else { return Ok(BTreeSet::new()) };
    blocked_roles(tx, &who, &a)
}

/// After `who` rotated each of `rotated`: the rotations due (`rotate_below`) on the actors they
/// are holders of (`above`) that `who` may rotate, upward, each once. A rotation of M makes the
/// boxes to M at its old keyset stale; answered by M's rotator at once, no other rotator above M
/// meets them and answers with a fork of its own. On `keep.on`, what `keep` says.
fn rotate_above(tx: &mut Tx<'_>, who: Tid, mut rotated: Vec<Tid>, keep: Option<Keep<'_>>, done: &mut Done) -> Result<()> {
    let mut entered: BTreeSet<Tid> = rotated.iter().copied().collect();
    while let Some(x) = rotated.pop() {
        for y in above(tx.core, &x) {
            if tx.core.has_own_secrets(&y) && !may_rotate(tx.core, &who, &y).is_empty() && entered.insert(y) {
                rotated.extend(rotate_below(tx, who, y, keep, Due::Encrypt, done)?);
            }
        }
    }
    Ok(())
}

/// The actor whose epochs `a` follows: itself with secrets of its own, else a plain thing follows
/// the next actor up its record chain that has them.
fn secret_actor_up(core: &Core, a: &Tid) -> Option<Tid> {
    for step in core.record_chain(a) {
        let t = step.thing()?;
        if core.has_own_secrets(&t) {
            return Some(t);
        }
        match step {
            osis_base::ChainStep::Up { admin: up, .. } if !core.is_key_actor(&up) => {}
            _ => return None,
        }
    }
    None
}

/// The rotations due on `a` and the holder actors below it (`ensure_rotated`, the downward
/// cascade): the actors rotated. On `keep.on`, what `keep` says.
fn rotate_below(tx: &mut Tx<'_>, who: Tid, a: Tid, keep: Option<Keep<'_>>, mode: Due, done: &mut Done) -> Result<Vec<Tid>> {
    let mut rotated = Vec::new();
    let Some(a) = secret_actor_up(tx.core, &a) else { return Ok(rotated) };
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
        finalize_due(tx, who, x, keep, done)?;
        let mine = rotation_due(tx, &who, &x, mode, &Keep::kept(keep, &x))?;
        if mine.is_empty() {
            continue;
        }
        let holders = recipients(tx, &who, &x, &[])?;
        done.extend(rotate_boxing(tx, who, x, &mine, &holders)?);
        rotated.push(x);
    }
    Ok(rotated)
}

/// The rotations nothing waits for, on `a` and the holder actors below it (`rotate_below`) by
/// `who`, with the other rotations due there: withdraws of unsuperseded epochs not current here.
/// Decided at the end of a complete pass of `a`'s labels (`Engine::pass_end`), as re-seals and
/// history adds are, never by `ensure_rotated`: no epoch they supersede is one this node would
/// encrypt under while it misses a departure.
fn pass_end_rotations(tx: &mut Tx<'_>, who: Tid, a: Tid, done: &mut Done) -> Result<()> {
    let rotated = rotate_below(tx, who, a, None, Due::PassEnd, done)?;
    rotate_above(tx, who, rotated, None, done)
}

/// The finalize `who` may write of the edges on `a` past their `until` by this node's clock
/// (spec/permissions.md §2, `flows::edges::finalizable`), written now: a node with write on `a`
/// writes it before its next commit encrypting under `a`. It is `a`'s departure for keys, and
/// carries the rotation where `who` can make it now, else goes alone (the departure uncovered,
/// so `a`'s roles stay blocked until a rotation covers it). Under `keep`: on `keep.on`, none of
/// its `rewriting`.
fn finalize_due(tx: &mut Tx<'_>, who: Tid, a: Tid, keep: Option<Keep<'_>>, done: &mut Done) -> Result<()> {
    let mut ended = flows::edges::finalizable(tx.core, &who, &a);
    ended.retain(|x| !keep.is_some_and(|k| k.on == a && k.rewriting.contains(&x.0)));
    if ended.is_empty() {
        return Ok(());
    }
    flows::edges::finalize_in(tx, who, a, &ended, &Keep::kept(keep, &a), done)
}

/// Gives `t` secrets of its own (spec/permissions.md §3, spec/crypto.md §3): a rotation of all
/// three roles from its derived epochs (those of the next actor up its record chain: rotated
/// first where this node can, the history boxes carry them), boxed to its current holders (its
/// first admin included; not one whose grant this node may finalize, `ended_holders`), with a
/// `keys.0` carrying the keysets and a fresh deposit seed, delivered by inbox to each holder it
/// boxes (none held a box before it), the first admin included: this node may not sync it, and
/// its sync IDs must learn the thing's own secrets (spec/permissions.md §3, Own secrets add only).
/// Nothing when it has them already.
pub(crate) fn own_secrets(tx: &mut Tx<'_>, t: Tid, done: &mut Done) -> Result<()> {
    own_secrets_listing(tx, t, &[], done)
}

/// `own_secrets`, its genesis step listing `also` besides the holders it boxes (a link's key,
/// granted next).
pub(crate) fn own_secrets_listing(tx: &mut Tx<'_>, t: Tid, also: &[crate::flows::sync_ids::ReaderKey], done: &mut Done) -> Result<()> {
    if let Some((c, rot, to)) = own_secrets_rot(tx, t, also, done)? {
        recorded(tx, t, c, &rot, &to, done)?;
    }
    Ok(())
}

/// `own_secrets` up to its commit, not yet recorded: the commit, the rotation, and the
/// holders it boxes that held no box at a current read epoch before it (`unreached`).
type OwnRot = (Option<osis_base::CommitId>, Rotation, Vec<Tid>);
fn own_secrets_rot(tx: &mut Tx<'_>, t: Tid, also: &[crate::flows::sync_ids::ReaderKey], done: &mut Done) -> Result<Option<OwnRot>> {
    if tx.core.has_own_secrets(&t) || tx.core.is_key_actor(&t) {
        return Ok(None);
    }
    let who = tx.core.writer()?;
    // its boxes make its first admin a holder actor of `t`, which has secrets of its own first, as
    // a grant's holder does (spec/permissions.md §3): a plain one has no keyset to be sealed at, so
    // it is left out and its holders lose `t` (where this node administers it). Up the record
    // chain only, so the recursion ends (holders may form cycles, record chains do not).
    let up = tx.core.first_admin(&t).filter(|m| tx.core.key_holders(&t).iter().any(|(h, _)| h == m));
    if let Some(m) = up
        && !tx.core.is_key_actor(&m)
        && !tx.core.is_account(&m)
        && !tx.core.has_own_secrets(&m)
        && tx.core.role_now(&who, &m) == Some(Role::Admin)
    {
        own_secrets(tx, m, done)?;
    }
    ensure_rotated(tx, who, t, done)?;
    let held = tx.core.epochs(&t).ok_or(Error::Misuse("the secrets it derives from are not held"))?;
    // a holder whose grant this node may finalize is boxed nothing (spec/permissions.md §2), as
    // a re-seal boxes it nothing: its departure is due, and the finalize follows
    let ended: Vec<(Tid, Option<Role>)> = ended_holders(tx.core, &who, &t).into_iter().map(|m| (m, None)).collect();
    let holders = recipients(tx, &who, &t, &ended)?;
    let mut m = Mutation::new();
    let rot = rotation_into(tx, &mut m, t, &ROLES.into_iter().collect(), &held, &holders, Departs::No)?;
    let deposit = fresh_deposit_seed(tx, &mut m, t)?;
    // the rule (spec/sync-ids.md §2): role secrets of its own and its one sync ID, its home and inbox,
    // in this one commit
    let sync_id = match crate::flows::home_sync_id(tx, &t)? {
        Some(id) => id,
        None => {
            let mut readers = Vec::new();
            for r in &holders.holders {
                readers.extend(crate::flows::sync_ids::reader_key(tx, &r.holder)?);
            }
            let after = rot.preview(&held)?;
            let readers: Vec<_> = readers.into_iter().chain(also.iter().cloned()).collect();
            crate::flows::sync_ids::new_sync_id(tx, &mut m, t, &after, &readers, &deposit)?
        }
    };
    if crate::flows::sync_ids::takes_inbox(tx, &t)? {
        crate::flows::sync_ids::name_inbox(&mut m, t, sync_id)?;
    }
    let to = unreached(tx, &t, &rot)?;
    let c = Engine::commit_tx(tx, m)?;
    Ok(Some((c, rot, to)))
}

/// The plain things whose secrets derive from `a` that this node, an admin of each, sees with a
/// current holder other than its first admin, or holding a role with key access on an actor with
/// secrets of its own (spec/permissions.md §3: such a thing is left by its only keyset part
/// turning invalid, spec/crypto.md §3); each gets secrets of its own again. A plain holder actor has no keyset to
/// be sealed at, so no rotation of what it holds a role on boxes it: its members read nothing new
/// there, and rotators reaching it only through it hold no epoch there (`boxes_rotator`).
pub(crate) fn own_secrets_candidates(core: &Core, a: &Tid) -> Vec<Tid> {
    let Some(me) = core.me() else { return Vec::new() };
    let plain = |t: &Tid| !core.has_own_secrets(t) && !core.is_key_actor(t) && core.secret_actor(t) == Some(*a) && core.role_now(&me, t) == Some(Role::Admin);
    // a scan per call; only plain targets and holders go further
    let mut out = BTreeSet::new();
    for ((x, _), m) in core.ix.holder_keys.iter() {
        if !out.contains(x) && plain(x) && core.key_holders(x).iter().any(|(h, _)| Some(*h) != core.first_admin(x)) {
            out.insert(*x);
        }
        // a plain thing holds its plain record children by derivation: only an actor with secrets
        // of its own seals to its holders
        if !out.contains(m) && plain(m) && core.has_own_secrets(x) && core.key_holders(x).iter().any(|(h, _)| h == m) && members::keyed(core, x, m) {
            out.insert(*m);
        }
    }
    out.into_iter().collect()
}

/// `own_secrets` for a plain thing with current holders, delivering the rotation by inbox to
/// each holder it boxes (they hold no box at the derived epochs it wraps under) and placing it
/// first under the labels above the thing (its new `keys.0`).
fn own_secrets_delivered(tx: &mut Tx<'_>, t: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some((c, rot, to)) = own_secrets_rot(tx, t, &[], &mut done)? else { return Ok(done) };
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
/// A memo (`Core::reseal_scans`).
pub(crate) fn reseal_candidates(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.reseal_scans, a, |tx| reseal_scan(tx, a))
}

fn reseal_scan(tx: &mut Tx<'_>, a: &Tid) -> Result<Vec<(Tid, BTreeSet<Role>)>> {
    // the roles at now it reads (`may_rotate`, `ended_holders`) hold until the clock reaches the
    // next `until` or role commit in `a`'s component, which holds its holders
    tx.core.time.until(tx.core.horizon(std::iter::once(*a)));
    let me = tx.core.writer()?;
    let may = may_rotate(tx.core, &me, a);
    if may.is_empty() {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(a) else { return Ok(Vec::new()) };
    let secrets = secrets_in(tx, a)?;
    let holders: Vec<osis_keys::Holder> = tx.core.key_holders(a).into_iter().filter(|(m, _)| tx.core.seals_to(a, m)).map(|(holder, role)| osis_keys::Holder { holder, role }).collect();
    let due = osis_keys::reseal_needed(&secrets, &epochs, &holders);
    let ended = ended_holders(tx.core, &me, a);
    let mut out = Vec::new();
    for (m, roles) in due.into_iter().filter(|(m, _)| !ended.contains(m)) {
        // Fixpoint (the re-seal is written on every pass otherwise): a re-seal is made only
        // when it adds a box the trigger asks for, each at its own key: so only by a node
        // holding the secret of an epoch the holder lacks a box at (`box_holder` boxes just
        // those held; a node may lack a fork's). Every re-seal adds a box until the forks end,
        // so the trigger settles.
        // and only at an epoch the holder's floor allows (spec/crypto.md §4, the boxing rule)
        let floor = floors::holder_floor(tx.core, a, &m);
        let mut keep: BTreeSet<Role> = roles.into_iter().filter(|r| may.contains(r) && osis_keys::reseal_missing(&secrets, &epochs, &m, *r).iter().any(|e| epochs.role(*r).secret(e).is_some() && epochs.role(*r).allows(e, floor))).collect();
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

/// The holders of `a` whose grant `who` may finalize (`flows::edges::finalizable`: past its
/// `until` by this node's clock): their departure is due here, so no grant or re-seal by `who`
/// boxes them, whether or not the finalize can be written yet (spec/permissions.md §2).
fn ended_holders(core: &Core, who: &Tid, a: &Tid) -> BTreeSet<Tid> {
    flows::edges::finalizable(core, who, a).into_iter().map(|x| x.0).collect()
}

/// Which boxes a re-seal writes (`reseal_one`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reseal {
    /// The trigger's (`pass_end`): at the current epochs the holder has no box at, whose
    /// secret this node holds; it replaces no box (`osis_keys::reseal_holder`).
    Missing,
    /// A re-share (`Engine::reshare`): at every current epoch held, replacing the holder's boxes
    /// there (a re-paired node's, a stranded holder's).
    All,
}

/// A re-seal of `holder` for `roles` of `a` (spec/permissions.md §3): its boxes at the current
/// epochs `which` names, with history boxes, delivered by inbox (a node: over a direct connection) and placed
/// under the actor's labels like any role commit (later removals reset its box entries: every
/// node must hold them, or the removal waits for good), with the keyset commits it names.
pub(crate) fn reseal_one(tx: &mut Tx<'_>, a: Tid, holder: Tid, roles: &BTreeSet<Role>, which: Reseal) -> Result<Done> {
    let mut done = Done::default();
    // rotate first where due; then re-seal, blocked roles included: a box carrying a secret is
    // encrypted under its recipient's key (`members::sealed` leaves out a blocked keyset of a
    // holder actor), not under the epoch it carries (spec/crypto.md §4, Encrypting under), so
    // nobody new reads under a blocked epoch (`tests::grant_while_blocked_boxes_grantee_only_*`)
    let me = tx.core.writer()?;
    ensure_rotated(tx, me, a, &mut done)?;
    let epochs = tx.core.epochs(&a).ok_or(Error::Misuse("no secrets held for the actor"))?;
    let secrets = secrets_in(tx, &a)?;
    let role = tx.core.key_holders(&a).into_iter().find(|(m, _)| *m == holder).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
    if ended_holders(tx.core, &me, &a).contains(&holder) {
        return Err(Error::Misuse("the holder's grant has ended: it is finalized, not re-sealed"));
    }
    // a rotation just made boxed the holder at the new epoch already
    let rotated = !done.commits.is_empty();
    let rcpt = match members::sealed(tx, &me, &a, &holder, role)? {
        Sealed::Boxed(r) => r,
        Sealed::Out => return Err(Error::Misuse("the holder has no key access or no keyset this node may seal it to")),
    };
    let missing = |r: Role| osis_keys::reseal_missing(&secrets, &epochs, &holder, r).iter().any(|e| epochs.role(r).secret(e).is_some());
    let roles: BTreeSet<Role> = roles.iter().copied().filter(|r| *r <= rcpt.role && (which == Reseal::All && !rotated || missing(*r))).collect();
    if roles.is_empty() {
        return Ok(done);
    }
    let hist = history_boxes(tx, &me, &a)?;
    let w = match which {
        Reseal::Missing => osis_keys::reseal_holder(&a, &epochs, &secrets, &hist, &rcpt, &roles, &mut *tx.rng)?,
        Reseal::All => osis_keys::box_holder(&a, &epochs, &hist, &rcpt, &roles, &mut *tx.rng)?,
    };
    let Some(w) = w else {
        return Err(Error::Misuse("the holder's keyset is unknown"));
    };
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, false)?;
    let c = Engine::commit_tx(tx, m)?;
    done.add(c);
    if let Some(c) = c {
        // an account's own nodes read it under the label it is written to
        if holder != me {
            flows::edges::deliver_to(tx, holder, c, &[a])?;
        }
    }
    Ok(done)
}

/// The history boxes `who` writes for `a`'s current epochs (`osis_keys::history_boxes`): what the
/// live entries list, every earlier superseded established secret held, the names of a met
/// entry. At an epoch blocked for `who` (`blocked_epoch`) only what the live entries list: a
/// history entry is encrypted under its epoch (spec/crypto.md §4, Encrypting under), and a
/// party the epoch does not cover opens it, so a grant or re-seal made while blocked (Seal
/// waiting, a remover that may not rotate) copies the history and adds nothing to it.
pub(crate) fn history_boxes(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<HistoryBoxes> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(HistoryBoxes::new()) };
    let secrets = secrets_in(tx, a)?;
    let alts = flows::secrets_alts(tx, a)?;
    let mut hist = osis_keys::history_boxes(a, &epochs, &secrets, &alts, &tx.core.names_held(a));
    let deps = departures(tx, a)?;
    for ((r, e), h) in hist.iter_mut() {
        if blocked_epoch(tx, who, a, *r, e, &deps, Walk::Encrypt)? {
            h.earlier.retain(|x, _| h.listed.contains(x));
            h.roles.retain(|x, _| h.roles_listed.contains(x));
        }
    }
    Ok(hist)
}

/// The history add for `a` (spec/crypto.md §4, History box): for each current epoch whose
/// secret this node holds established and may encrypt under (`history_boxes`), an entry carrying
/// every earlier superseded established secret it holds when one is not listed, put beside the
/// entries there, by any holder of the epoch's role now (a reader too: a secret once shared cannot be un-shared, and
/// every holder of the epoch reads its history). Placed under `a`'s labels like any role commit;
/// nothing when every secret held is listed.
pub(crate) fn add_history(tx: &mut Tx<'_>, a: Tid) -> Result<Done> {
    let mut done = Done::default();
    let Some(epochs) = tx.core.epochs(&a) else { return Ok(done) };
    let me = tx.core.writer()?;
    let Some(role) = tx.core.role_now(&me, &a) else { return Ok(done) };
    // only at roles held: an add needs the role its keys name (a holder lowered still holds
    // the higher role's secrets, and its own departure does not block it)
    let mut hist = history_boxes(tx, &me, &a)?;
    hist.retain(|(r, _), _| *r <= role);
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
    Ok(done)
}

/// The tip add for `a` (spec/crypto.md §4, Floors): a node that may rotate read and holds a
/// dropped epoch (one no history entry carries on: what a cut lists, a fork beside a cut) boxes
/// it to each current holder of read its floor allows that cannot open it, as this node sees,
/// from the live boxes and the entries it opens; and a holder re-added without history, each
/// epoch its removal's rotation listed (`floors::readd_epochs`) alike. One commit; nothing when
/// none lacks one.
pub(crate) fn tip_add(tx: &mut Tx<'_>, a: Tid) -> Result<Done> {
    let mut done = Done::default();
    // no floors: nothing is dropped and nobody re-added without history
    let Some(epochs) = tx.core.epochs(&a).filter(|e| e.read.has_floors()) else { return Ok(done) };
    let dropped: BTreeSet<osis_crypto::Epoch> = epochs.read.dropped().into_iter().collect();
    let me = tx.core.writer()?;
    if !may_rotate(tx.core, &me, &a).contains(&Role::Read) {
        return Ok(done);
    }
    let secrets = secrets_in(tx, &a)?;
    let mut w = osis_keys::SecretsWrite::default();
    for (x, role) in tx.core.key_holders(&a) {
        if x == me || role < Role::Read {
            continue;
        }
        let floor = floors::holder_floor(tx.core, &a, &x);
        let readd = floors::readd_epochs(tx.core, &a, &x, &epochs);
        let mut want: BTreeSet<osis_crypto::Epoch> = dropped.iter().filter(|t| epochs.read.allows(t, floor)).copied().collect();
        want.extend(readd.into_iter().filter(|t| epochs.read.is_established(t) && epochs.read.secret(t).is_some()));
        if want.is_empty() {
            continue;
        }
        let opens = opened_from(&epochs, &secrets, &x);
        want.retain(|t| !opens.contains(t));
        if want.is_empty() {
            continue;
        }
        let Sealed::Boxed(rcpt) = sealed(tx, &me, &a, &x, Role::Read)? else { continue };
        // the floors were judged above: a re-added holder's listed epochs lie below its floor
        let rcpt = osis_keys::Recipient { floor: 0, ..rcpt };
        if let Some(b) = osis_keys::box_dropped(&a, &epochs, &rcpt, &want, &mut *tx.rng)? {
            w.extend(b);
        }
    }
    if w.is_empty() {
        return Ok(done);
    }
    let mut m = Mutation::new();
    put_secrets(&mut m, a, &w, false)?;
    // logged under `a`'s sync IDs as an own commit, with the keysets its boxes carry (sync's
    // logging, notes/sync-facade.md)
    done.add(Engine::commit_tx(tx, m)?);
    Ok(done)
}

/// The read epochs of the actor holder `x` opens from the live boxes `secrets` to it and, through
/// them, the entries this node opens (`EpochInfo::supersedes`).
fn opened_from(epochs: &ActorEpochs, secrets: &osis_schema::core_types::Secrets, x: &Tid) -> BTreeSet<osis_crypto::Epoch> {
    let mut out: BTreeSet<osis_crypto::Epoch> = secrets.boxes.keys().filter(|k| k.holder == *x && k.role == Role::Read).filter_map(|k| osis_keys::aspects::from_schema(&k.epoch).ok()).collect();
    let mut todo: Vec<osis_crypto::Epoch> = out.iter().copied().collect();
    while let Some(e) = todo.pop() {
        for f in epochs.read.get(&e).map(|i| i.supersedes.clone()).unwrap_or_default() {
            if out.insert(f) {
                todo.push(f);
            }
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
            let me = tx.core.writer()?;
            let still = ensure_rotated(tx, me, a, &mut done)?;
            Ok((done, still))
        })
    }

    /// What `ensure_rotated` would leave blocked of `actor`, changing nothing: the roles, or
    /// `None` when it would write or deliver something. Its transaction always rolls back, so
    /// neither its run nor the transaction's own follow-ups commit anything.
    pub fn rotated_already(&mut self, actor: &Tid) -> Result<Option<BTreeSet<Role>>> {
        const ASKED: &str = "rotated_already rolls back";
        let a = *actor;
        let mut out = None;
        let r = self.run(|tx| {
            let mut done = Done::default();
            let me = tx.core.writer()?;
            let still = ensure_rotated(tx, me, a, &mut done)?;
            if done.commits.is_empty() {
                out = Some(still);
            }
            Err::<(), _>(Error::Misuse(ASKED))
        });
        match r {
            Ok(()) | Err(Error::Misuse(ASKED)) => Ok(out),
            Err(e) => Err(e),
        }
    }

    /// The actors this node holds secrets of: the keys of the role duties (`role_duty_due`),
    /// with `held_actors_feed` for those added later.
    pub fn held_actors(&self) -> Vec<Tid> {
        self.core.ix.secrets.keys_held().copied().collect()
    }

    /// Whether this node holds secrets of `actor` (`held_actors`).
    pub fn held_actors_has(&self, actor: &Tid) -> bool {
        self.core.ix.secrets.contains_key(actor)
    }

    /// A cursor over the actors whose secrets this node comes to hold from now on.
    pub fn held_actors_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.core.ix.secrets.feed()
    }

    /// Whether this node owes a role commit on `actor` now (spec/permissions.md §2 Finalize, §3
    /// Required rotation; spec/crypto.md §4 Encrypting under): `ensure_rotated` would write
    /// something (the finalize of a grant past its `until`, a rotation a departure, a stale or
    /// keyless box or a blocked epoch makes due, on `actor` or a holder actor below it). Derived
    /// from the state alone, whatever made it due (an own commit, one received, a keyset or
    /// record arriving, a restart), so a follower (sync's `Life`, one `Effects` key per held
    /// actor) runs `ensure_rotated` when it settles true; its reads are stamped, and the memo
    /// clock is read up to the earliest `until` ahead on `actor`, so its passing moves it.
    pub fn role_duty_due(&mut self, actor: &Tid) -> Result<bool> {
        if self.core.writer().is_err() || !self.core.ix.secrets.contains_key(actor) {
            return Ok(false);
        }
        self.core.time.until(lost::next_until(&self.core, actor));
        Ok(self.rotated_already(actor)?.is_none())
    }

    /// The departures from `actor` its epochs must cover, as this node knows them.
    pub fn departures(&mut self, actor: &Tid) -> Result<Vec<Departure>> {
        let a = *actor;
        self.read(|tx| departures(tx, &a))
    }

    /// Gives `thing` secrets of its own (spec/permissions.md §3), with its one sync ID in the same
    /// commit (spec/sync-ids.md §2): before its first holder other than its first admin, or before it
    /// is made a holder of anything.
    pub fn give_own_secrets(&mut self, thing: &Tid) -> Result<Done> {
        let t = *thing;
        self.run(|tx| {
            let mut done = Done::default();
            own_secrets(tx, t, &mut done)?;
            Ok(done)
        })
    }

    /// The plain things whose secrets derive from `actor` that this node administers and sees
    /// with a current holder other than their first admin, or holding a role with key access on
    /// an actor with secrets of its own (spec/permissions.md §3): each is
    /// due secrets of its own again (`give_own_secrets_again`), decided at the end of a complete
    /// pass of `actor`'s labels (node-sync's).
    pub fn own_secrets_candidates(&self, actor: &Tid) -> Vec<Tid> {
        own_secrets_candidates(&self.core, actor)
    }

    /// Gives `t`, one of `own_secrets_candidates`, secrets of its own again, delivered to the
    /// holders it boxes and placed under the labels above it.
    pub fn give_own_secrets_again(&mut self, t: &Tid) -> Result<Done> {
        let t = *t;
        self.run(|tx| own_secrets_delivered(tx, t))
    }

    /// `pass_end` after a complete pass of `actor`'s sync IDs noted now (tests: the pass sync
    /// would note), run whether or not the actor has a sync ID read here.
    #[doc(hidden)]
    pub fn reseal_after_pass(&mut self, actor: &Tid) -> Result<Done> {
        let now = self.now();
        if let crate::sync::ThingSync::Read(ids) = self.thing_sync(actor)? {
            for s in ids {
                self.note_complete_pass_now(&s, now)?;
            }
        }
        self.reseal_run(actor)
    }

    /// What a complete pass of `actor`'s sync IDs makes due, once one began after every role
    /// commit on it received from elsewhere (`note_complete_pass`); nothing otherwise: the
    /// rotations of `actor` nothing waits for (`pass_end_rotations`: withdraws), the re-seals of
    /// the holders the trigger names, the history its current epochs lack (spec/permissions.md §3,
    /// spec/crypto.md §4 History box), the snapshots a cut owes (spec/crypto.md §4, State at a
    /// cut) and, for this node's devices actor D, what the account owes its signing chain
    /// (`signing_due`, spec/permissions.md §3, §5.5: decided at the end of a complete pass of D's
    /// sync IDs).
    pub fn pass_end(&mut self, actor: &Tid) -> Result<Done> {
        if !self.complete_pass(actor)? {
            return Ok(Done::default());
        }
        let mut done = self.reseal_run(actor)?;
        if self.core.account_devices().is_some_and(|(_, d)| d == *actor) {
            done.extend(self.signing_due()?);
        }
        Ok(done)
    }

    /// `pass_end`'s re-seal work, its complete pass found.
    fn reseal_run(&mut self, actor: &Tid) -> Result<Done> {
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            let me = tx.core.writer()?;
            pass_end_rotations(tx, me, a, &mut done)?;
            let mut due = reseal_candidates(tx, &a)?;
            if !due.is_empty() {
                // the rotations due and the finalizes of ended edges go first where this node can
                // (`reseal_one` would make them before its re-seal): the candidates are read from
                // the state they leave, where a holder a rotation boxed or left out is none (an
                // ended holder is none either way, `ended_holders`)
                let me = tx.core.writer()?;
                ensure_rotated(tx, me, a, &mut done)?;
                due = reseal_candidates(tx, &a)?;
            }
            for (m, roles) in due {
                done.extend(reseal_one(tx, a, m, &roles, Reseal::Missing)?);
            }
            done.extend(add_history(tx, a)?);
            done.extend(tip_add(tx, a)?);
            floors::owe_state(tx, &a)?;
            Ok(done)
        })
        .and_then(|done| {
            // the snapshots a cut owes (spec/crypto.md §4, State at a cut)
            self.purge_resnapshots()?;
            Ok(done)
        })
    }

    /// `pass_end_rotations` alone, as a complete pass's end runs it (tests: the withdraws without the
    /// re-seals and history adds of `pass_end`).
    #[cfg(test)]
    pub(crate) fn pass_end_rotations(&mut self, actor: &Tid) -> Result<Done> {
        let a = *actor;
        self.run(|tx| {
            let mut done = Done::default();
            let me = tx.core.writer()?;
            pass_end_rotations(tx, me, a, &mut done)?;
            Ok(done)
        })
    }

    /// "Re-share with M" by hand (issue reseal-triggers, closed: a manual re-share, notes/sync-access.md): re-seals current holder `holder`
    /// of `actor` for every role it holds that this node may rotate, whatever the trigger says
    /// (a holder whose deposits are refused, a stranded report, a re-paired node).
    pub fn reshare(&mut self, actor: &Tid, holder: &Tid) -> Result<Done> {
        let (a, m) = (*actor, *holder);
        self.run(|tx| {
            let role = tx.core.key_holders(&a).into_iter().find(|(x, _)| *x == m).map(|x| x.1).ok_or(Error::Misuse("not a current holder"))?;
            let me = tx.core.writer()?;
            let may = may_rotate(tx.core, &me, &a);
            let roles: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= role && may.contains(r)).collect();
            if roles.is_empty() {
                return Err(Error::Misuse("this node may not re-seal that holder"));
            }
            reseal_one(tx, a, m, &roles, Reseal::All)
        })
    }

}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_members;
#[cfg(test)]
mod tests_carried;
#[cfg(test)]
mod tests_deep;
#[cfg(test)]
mod tests_departs;
#[cfg(test)]
mod tests_cut;
#[cfg(test)]
mod tests_property;
#[cfg(test)]
mod tests_reseal;
#[cfg(test)]
mod tests_planted;
