//! Holder actors as this node judges them (spec/crypto.md §4, Holder actors): key access over the
//! actor grants it holds (cached), a holder actor's held keysets, the recipient a box seals it
//! to, stale and keyless boxes of an actor, and the demotions its keysets carry. The rules are
//! osis-keys' (`osis_keys::members`); this gathers their inputs.
//! A departure from a holder actor counts only as what this node may encrypt under
//! (`super::blocking`): sealing at a keyset is encrypting under it, and a joint box is held back
//! by departures only where every keyset it names misses one.

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{recipient, secrets_in};
use osis_base::{Role, Tid};
use osis_crypto::Epoch;
use osis_keys::{Grant, HolderKeys, Keysets, ROLES, Recipient, Seal};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The order of an actor grant (spec/crypto.md §4, key access): an edge by the write that began
/// its standing (`None`: a record edge, since before every change, so never the one left
/// keyless), then a grant being written now.
type Order = (u8, Option<osis_perm::Point>);

/// The actor grants this node holds (spec/crypto.md §4, key access): each holder actor's standing
/// on each thing with a timeline (`Timeline::standing_since`, record edges included), and the
/// record edge of each of `also` without a timeline here (nothing wrote it: in force).
fn grants(core: &Core, also: &[Tid]) -> Vec<osis_keys::Grant<Order>> {
    let mut grants = Vec::new();
    let actors = |m: &Tid| !core.is_key_actor(m);
    for t in core.timelines.things() {
        let Some(on) = core.timelines.on(t) else { continue };
        if !on.holders().iter().any(|(m, _)| actors(m)) {
            continue;
        }
        for (h, since) in on.standing_since() {
            if actors(&h) {
                grants.push(Grant { order: (1, since), target: *t, holder: h });
            }
        }
    }
    for t in also {
        if core.timelines.get(t).is_none()
            && let Some(a) = core.first_admin(t).filter(actors)
        {
            grants.push(Grant { order: (1, None), target: *t, holder: a });
        }
    }
    grants
}

/// The keyless grants (target, holder) among those this node holds (`grants`,
/// `osis_keys::key_access`), kept by the timelines (`held::Timelines::keyless`).
pub(crate) fn key_access(core: &Core) -> Arc<BTreeSet<(Tid, Tid)>> {
    core.timelines.keyless()
}

/// The keyless grants among the actor grants of one component's timeline `tl`: each holder
/// actor's standing on each thing (`Timeline::standing_since_all`, record edges included), as
/// `grants` gathers them. A keyless grant closes a cycle of actor grants (`osis_keys::key_access`),
/// and a cycle lies in one component, so the union over components is the answer over all.
pub(crate) fn keyless_in(tl: &osis_perm::Timeline) -> BTreeSet<(Tid, Tid)> {
    let mut grants = Vec::new();
    for (t, on) in tl.standing_since_all() {
        for (h, since) in on {
            if !tl.records().is_key(&h) {
                grants.push(Grant { order: (1, since), target: t, holder: h });
            }
        }
    }
    osis_keys::key_access(grants)
}

/// `who`'s role on `a` now for keys (spec/crypto.md §4, Holds: `At::KEYS`, every `until`
/// disregarded), over its record chain and through holder actors whose grants have key access
/// only: a keyless grant gives no read through it (spec/requirements.md Permissions), so a party
/// holding `a` only so has left it.
pub(crate) fn role_for_keys(core: &Core, who: &Tid, a: &Tid) -> Option<Role> {
    core.timelines.roles_on(a, osis_perm::At::KEYS, &key_access(core)).get(who).copied()
}

/// Whether holder `h` of `a` has key access to it (`keyed_role`).
pub(crate) fn keyed(core: &Core, a: &Tid, h: &Tid) -> bool {
    keyed_role(core, a, h, Role::Admin).is_some()
}

/// Holder `h`'s role on `a` for keys, `role`, as far as it has key access: `None` without it
/// (spec/crypto.md §4, Key access). A holder not yet granted keeps `role` (`grant_keyless` judges
/// the new grant).
pub(crate) fn keyed_role(core: &Core, a: &Tid, h: &Tid, role: Role) -> Option<Role> {
    let Some(roles) = key_roles(core, a) else { return Some(role) };
    match roles.get(h) {
        Some((_, keyed)) => keyed.map(|r| r.min(role)),
        None => Some(role),
    }
}

/// Holders for keys, each at its role for keys and at its role with key access (`key_roles`).
pub(crate) type KeyRoles = BTreeMap<Tid, (Role, Option<Role>)>;

/// Each holder of `a` for keys at its role for keys and at its role with key access: the
/// greatest over the paths of grants from it to `a` with key access at every grant, through
/// destroyed actors in their frozen holders' place at the lesser role along the way
/// (`Core::keyed_holders`; a key actor's grant is never keyless), `None` without one. `None`
/// when no grant held is keyless (the usual case): every holder keyed at its role for keys.
fn key_roles(core: &Core, a: &Tid) -> Option<Arc<KeyRoles>> {
    if key_access(core).is_empty() {
        return None;
    }
    // `key_access` read inside: the answer depends on it
    Some(core.key_roles.get(a, || {
        let keyed = core.keyed_holders(a, &key_access(core));
        Arc::new(core.key_holders(a).into_iter().map(|(h, r)| (h, (r, keyed.get(&h).copied()))).collect())
    }))
}

/// Whether a grant of `holder` on `target` written now would be keyless (spec/crypto.md §4): a
/// standing edge on `target` (`edge_holders`) keeps its standing's judgement, a new one comes
/// after every grant held.
pub(crate) fn grant_keyless(core: &mut Core, target: &Tid, holder: &Tid) -> bool {
    if core.is_key_actor(holder) {
        return false;
    }
    if core.edge_holders(target).iter().any(|(m, _)| m == holder) {
        return key_access(core).contains(&(*target, *holder));
    }
    // the grants held with this one last, and the record edges of both ends (an actor whose
    // first admin is the target closes a cycle through its record edge, though it holds nothing
    // yet)
    let mut gs = grants(core, &[*target, *holder]);
    gs.push(Grant { order: (2, None), target: *target, holder: *holder });
    osis_keys::key_access(gs).contains(&(*target, *holder))
}

/// The held keysets of role `r` of actor `m` (spec/crypto.md §4): the valid ones from `keysets`,
/// and `k`, when it is none of those, if held invalid.
pub(super) fn keysets_of(tx: &mut Tx<'_>, m: &Tid, r: Role, k: Option<&Epoch>) -> Result<Keysets> {
    if tx.core.is_account(m) {
        return tx.core.account_view(m).map(|v| v.keysets()).ok_or(crate::error::Error::UnknownThing(*m));
    }
    let mut out = Keysets::default();
    for (_, e, x) in tx.core.keysets_of(m).filter(|x| x.0 == r) {
        out.valid.insert(e, x.lists.clone());
        out.since.extend(x.since.map(|p| (e, p)));
    }
    if let Some(k) = k.filter(|k| !out.valid.contains_key(k))
        && held_invalid(tx, m, r, k)?
    {
        out.invalid.insert(*k);
    }
    Ok(out)
}

/// Whether this node holds a `keys.0` body of `m` writing `k` as its keyset of `r` (none valid:
/// `keysets_of` asks only then). Only a box naming a keyset not held valid asks, so this scans
/// `m`'s keyset-writing commits and reads the bodies of the invalid ones only.
fn held_invalid(tx: &mut Tx<'_>, m: &Tid, r: Role, k: &Epoch) -> Result<bool> {
    let ids: Vec<osis_base::CommitId> = tx.core.ix.keyset_parts.get(m).into_iter().flatten().copied().collect();
    for id in ids {
        let Some(meta) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let Some(ai) = meta.view.aspect(m, "keys.0") else { continue };
        if meta.valid_at(ai) {
            continue;
        }
        let mut recs = meta.dropped(ai).map(|d| d.keysets.clone()).unwrap_or_default();
        if let Some(d) = crate::apply::held_part(tx, &id, ai)? {
            recs.extend(crate::apply::keys::keysets_of(&meta.header, ai, std::slice::from_ref(d.fragment())));
        }
        if recs.iter().any(|x| x.role == r && x.epoch == *k) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The holders of `a` for keys a box of role `r` to which goes past their key access
/// (`key_roles`): without key access at `r`, or at their role for keys if lower (a box above
/// that is a demotion's departure, not a key cycle). None in the usual case, with no cycle among
/// the grants held.
pub(super) fn keyless_holders(core: &Core, a: &Tid, r: Role) -> BTreeSet<Tid> {
    let Some(roles) = key_roles(core, a) else { return BTreeSet::new() };
    roles.iter().filter(|(_, (role, keyed))| *keyed < Some(r.min(*role))).map(|(h, _)| *h).collect()
}

/// The tainted keysets of role `r` of actor `a` (spec/crypto.md §4, Tainted): the epochs at
/// which `a`'s `secrets.0` state boxes a holder past its key access to it (`keyless_holders`,
/// `osis_keys::boxing_keyless`), which for an actor this node may rotate its knowing re-key
/// leaves. `a`'s `secrets.0` is read only when such a holder exists.
fn tainted(tx: &mut Tx<'_>, a: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    // a box to a holder that departed is a departure from `a` (its own rotators' covers rule),
    // not a key cycle
    let none = keyless_holders(tx.core, a, r);
    if none.is_empty() {
        return Ok(BTreeSet::new());
    }
    let s = secrets_in(tx, a)?;
    let boxes: Vec<(Tid, Epoch)> = s.boxes.iter().map(|x| x.0).filter(|k| k.role == r).filter_map(|k| Some((k.holder, osis_keys::aspects::from_schema(&k.epoch).ok()?))).collect();
    Ok(osis_keys::boxing_keyless(boxes, |h| none.contains(h)))
}

/// The anchors of holder actor `m` for role `r` of `a` (spec/crypto.md §4): the epochs of `m`
/// the boxes to it of role `r` at `a`'s current epochs name.
fn anchors(tx: &mut Tx<'_>, a: &Tid, m: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let s = secrets_in(tx, a)?;
    Ok(s.boxes
        .iter()
        .filter(|(k, _)| k.holder == *m && k.role == r)
        .filter(|(k, _)| osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(r).is_current(&e)))
        .flat_map(|(_, b)| osis_keys::box_keysets(b))
        .collect())
}

/// The keysets of holder actor `m` of role `r` that `a`'s current keysets of `r` record `m` was
/// left out at (spec/crypto.md §4, Left out), each with the latest key of those keysets'
/// earliest bodies: Seal seals `m` only past each (`osis_keys::Keysets::past`).
fn left_out_at(core: &Core, a: &Tid, m: &Tid, r: Role) -> BTreeMap<Epoch, osis_perm::Point> {
    let mut out = BTreeMap::new();
    let Some(epochs) = core.epochs(a) else { return out };
    for x in epochs.role(r).current().iter().filter_map(|e| core.keyset(a, r, e)) {
        let (Some(at), Some(ks)) = (x.since, x.left_out.get(m)) else { continue };
        for q in ks {
            out.entry(*q).and_modify(|p: &mut osis_perm::Point| *p = (*p).max(at)).or_insert(at);
        }
    }
    out
}

/// How a rotation, grant or re-seal of an actor boxes one holder (`sealed`).
pub(crate) enum Sealed {
    /// These boxes.
    Boxed(Recipient),
    /// Nothing: left out until re-sealed (no key access, keys or keyset to seal to, or one the
    /// sealer may not encrypt under).
    Out,
}

/// Holder `m` of `a`, holding `role`, as a rotation, grant or re-seal of `a` by `who` (this node,
/// or a key actor it signs as) boxes it (spec/crypto.md §4), up to `role` capped at its key
/// access (`keyed_role`; none without it): a key actor whole; a holder actor per role, at the keysets Seal gives
/// (`osis_keys::seal_keyset`): one, symmetric where this node holds that
/// established epoch's secret, or several jointly; cut at the first role with none or whose box
/// `who` may not make (`seal_blocked`: a departure from `m` it knows that keyset, or every keyset
/// of a joint box, does not cover, say), left out of it and the roles above.
pub(crate) fn sealed(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    Ok(sealing(tx, who, a, m, role)?.0)
}

/// `sealed`, with the keysets Seal gives at each role up to `role` that leave `m` out
/// (`seal_blocked`), the roles above the cut included: what a rotation leaving `m`
/// out records (`left_out`).
pub(crate) fn sealing(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<(Sealed, BTreeMap<Role, BTreeSet<Epoch>>)> {
    let mut blocked = BTreeMap::new();
    if !tx.core.seals_to(a, m) {
        return Ok((Sealed::Out, blocked));
    }
    let Some(role) = keyed_role(tx.core, a, m, role) else { return Ok((Sealed::Out, blocked)) };
    if tx.core.is_account(m) {
        return sealed_to_account(tx, who, a, m, role);
    }
    if tx.core.is_key_actor(m) {
        return Ok((recipient(tx, *m, role).ok().map_or(Sealed::Out, Sealed::Boxed), blocked));
    }
    let own = tx.core.own_epochs(m);
    let deps = super::departures(tx, m)?;
    let (mut keysets, mut secrets, mut top, mut cut) = (BTreeMap::new(), BTreeMap::new(), None, false);
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        let held = keysets_of(tx, m, r, None)?;
        let ks = match osis_keys::seal_keyset(&held, &anchors(tx, a, m, r)?, &tainted(tx, m, r)?, &left_out_at(tx.core, a, m, r)) {
            Seal::At(ks) => ks,
            Seal::Out => {
                cut = true;
                continue;
            }
        };
        let out = seal_blocked(tx, who, m, r, &ks, &deps)?;
        if !out.is_empty() {
            blocked.insert(r, out);
            cut = true;
        }
        if cut {
            continue;
        }
        let (mut row, mut wrap) = (Vec::new(), None);
        for k in &ks {
            let secret = own.as_ref().filter(|e| e.role(r).is_established(k)).and_then(|e| e.role(r).secret(k)).cloned();
            let written = tx.core.keyset(m, r, k).and_then(|x| x.kem.clone());
            let Some(kem) = written.or_else(|| secret.as_ref().map(|s| osis_crypto::role_kem(s).public().clone())) else {
                cut = true;
                break;
            };
            row.push((*k, kem));
            if wrap.is_none() {
                wrap = secret.map(|s| (*k, s));
            }
        }
        if cut {
            continue;
        }
        keysets.insert(r, row);
        secrets.extend(wrap.map(|p| (r, p)));
        top = Some(r);
    }
    let sealed = top.map_or(Sealed::Out, |role| Sealed::Boxed(Recipient { holder: *m, role, keys: HolderKeys::Actor { keysets, own: secrets } }));
    Ok((sealed, blocked))
}

/// The keysets `ks` Seal gives for `m` at `r` that leave `m` out (`super::joint_blocked`): a box
/// naming them is encrypting under each (`super::blocking`), and a joint one opens only for a
/// holder of every one, so it waits on a missed departure only when every keyset misses one.
fn seal_blocked(tx: &mut Tx<'_>, who: &Tid, m: &Tid, r: Role, ks: &BTreeSet<Epoch>, deps: &[osis_keys::Departure]) -> Result<BTreeSet<Epoch>> {
    let mut why = BTreeMap::new();
    for k in ks {
        if let Some(b) = super::blocking(tx, who, m, r, k, deps, super::Walk::Seal)? {
            why.insert(*k, b);
        }
    }
    Ok(super::joint_blocked(why, ks.len()))
}

/// `sealing` for account `m`: one keyset names every role (spec/crypto.md §3), so its boxes up
/// to `role` go at the epochs Seal gives past every role's anchors and left-out keysets (one, or
/// several jointly); left out where a role of one of them is blocked at this node.
fn sealed_to_account(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<(Sealed, BTreeMap<Role, BTreeSet<Epoch>>)> {
    let mut blocked = BTreeMap::new();
    let (mut anchored, mut out) = (BTreeSet::new(), BTreeMap::new());
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        anchored.extend(anchors(tx, a, m, r)?);
        for (q, at) in left_out_at(tx.core, a, m, r) {
            out.entry(q).and_modify(|p: &mut osis_perm::Point| *p = (*p).max(at)).or_insert(at);
        }
    }
    let held = keysets_of(tx, m, role, None)?;
    let Seal::At(ks) = osis_keys::seal_keyset(&held, &anchored, &BTreeSet::new(), &out) else { return Ok((Sealed::Out, blocked)) };
    let deps = super::keyset_departures(tx, m)?;
    let mut top = None;
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        let b = seal_blocked(tx, who, m, r, &ks, &deps)?;
        if !b.is_empty() {
            blocked.insert(r, b);
        } else if blocked.is_empty() {
            top = Some(r);
        }
    }
    let Some(role) = top else { return Ok((Sealed::Out, blocked)) };
    if let [k] = Vec::from_iter(&ks).as_slice() {
        let sealed = crate::flows::account::holder_keys_at(tx, m, k)?.map_or(Sealed::Out, |keys| Sealed::Boxed(Recipient { holder: *m, role, keys }));
        return Ok((sealed, blocked));
    }
    // jointly: sealed to each epoch's KEM key, at every role
    let mut row = Vec::new();
    for k in &ks {
        let Some(HolderKeys::Account { kem, .. }) = crate::flows::account::holder_keys_at(tx, m, k)? else { return Ok((Sealed::Out, blocked)) };
        row.push((*k, kem));
    }
    let keysets = ROLES.into_iter().filter(|r| *r <= role).map(|r| (r, row.clone())).collect();
    Ok((Sealed::Boxed(Recipient { holder: *m, role, keys: HolderKeys::Actor { keysets, own: BTreeMap::new() } }), blocked))
}

/// The holders of `a` as a rotation by `who` boxes them, and what it records of the holder
/// actors it leaves out (`super::recipients`).
pub(crate) struct Boxing {
    pub(crate) holders: Vec<Recipient>,
    pub(crate) left_out: osis_keys::LeftOut,
}

/// What a rotation of `a` records of holder actor `m`, holding `role`, that it boxes only
/// up to `boxed` (`None`: not at all) (spec/crypto.md §4, Left out): at each role above, the
/// keysets Seal gives that the rotator may not encrypt under (`blocked`, from `sealing`), and the keysets `a`'s current
/// keysets of that role record already, less those another of them descends from (a holder
/// actor left out across rotations records its frontier, not its history). A key actor's boxes
/// name no keyset: nothing.
pub(crate) fn left_out(tx: &mut Tx<'_>, a: &Tid, m: &Tid, role: Role, boxed: Option<Role>, blocked: &BTreeMap<Role, BTreeSet<Epoch>>, out: &mut osis_keys::LeftOut) -> Result<()> {
    if tx.core.is_key_actor(m) && !tx.core.is_account(m) {
        return Ok(());
    }
    for r in ROLES.into_iter().filter(|r| *r <= role && Some(*r) > boxed) {
        let mut ks: BTreeSet<Epoch> = left_out_at(tx.core, a, m, r).into_keys().collect();
        ks.extend(blocked.get(&r).into_iter().flatten());
        if ks.is_empty() {
            continue;
        }
        let held = keysets_of(tx, m, r, None)?;
        let frontier: BTreeSet<Epoch> = ks.iter().copied().filter(|q| !ks.iter().any(|x| x != q && held.descends(x, q))).collect();
        out.entry(r).or_default().insert(*m, frontier);
    }
    Ok(())
}

/// The holder actors `a`'s epoch `e` of role `r` boxes, each with the keysets its box names (one,
/// or several jointly), by the boxes of `a`'s `secrets.0` state.
pub(crate) fn boxed_keysets(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<Vec<(Tid, Vec<Epoch>)>> {
    let s = secrets_in(tx, a)?;
    Ok(s.boxes
        .iter()
        .filter(|(k, _)| k.role == r && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == *e))
        .filter(|(k, _)| !tx.core.is_key_actor(&k.holder) || tx.core.is_account(&k.holder))
        .map(|(k, b)| (k.holder, osis_keys::box_keysets(b)))
        .collect())
}

/// Whether `a`'s epoch `e` of role `r` has a stale box (spec/crypto.md §4, rule 2): a box of its
/// `secrets.0` state to a holder actor, or a keyset of it a box record of `a`'s `keys.0` names
/// at `e` (what a node holding none of `a`'s boxes judges by: every box, whoever wrote it, is
/// recorded beside it), naming a keyset of it held invalid, tainted, or listed by a held valid
/// keyset of it.
pub(crate) fn stale_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    let mut named: Vec<(Tid, Epoch)> = boxed_keysets(tx, a, r, e)?.into_iter().flat_map(|(m, ks)| ks.into_iter().map(move |k| (m, k))).collect();
    named.extend(tx.core.ix.sealed.get(&(*a, r, *e)).into_iter().flat_map(|x| x.keysets.iter().flat_map(|(m, ks)| ks.iter().map(move |k| (*m, *k)))));
    for (m, k) in named {
        let held = keysets_of(tx, &m, r, Some(&k))?;
        if osis_keys::stale(&k, &held, &tainted(tx, &m, r)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `a`'s epoch `e` of role `r` boxes a holder past its key access to `a`, by a box of
/// its `secrets.0` state (spec/crypto.md §4, rule 4: a node that may rotate `a` re-keys while a current
/// epoch does).
pub(crate) fn keyless_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    Ok(tainted(tx, a, r)?.contains(e))
}

/// The held rotation commits of the keysets the boxes `w` writes to holder actors name, and those
/// the keysets `keys` writes record holder actors were left out at (spec/crypto.md §4, Carried),
/// with the demotions each of those carries (Carried demotions): logged under `a`'s sync IDs with
/// the commit carrying `w`.
pub(crate) fn carried(core: &Core, w: &osis_keys::SecretsWrite, keys: Option<&osis_keys::KeysWrite>) -> Vec<osis_base::CommitId> {
    let boxed = w.boxes.iter().flat_map(|(k, b)| osis_keys::box_keysets(b).into_iter().map(|e| (k.holder, k.role, e)));
    let out = keys.into_iter().flat_map(|k| k.keysets.iter()).flat_map(|(r, ks)| ks.left_out.iter().flat_map(move |(m, xs)| xs.iter().filter_map(move |x| Some((*m, *r, osis_keys::aspects::from_schema(x).ok()?)))));
    let mut out: Vec<osis_base::CommitId> = boxed
        .chain(out)
        .flat_map(|(m, r, e)| {
            if core.is_account(&m) {
                return core.account_view(&m).and_then(|v| v.rotation_named(&e)).into_iter().collect();
            }
            if core.is_key_actor(&m) {
                return Vec::new();
            }
            let carries = core.keyset(&m, r, &e).into_iter().flat_map(|x| x.demotions.iter().copied());
            // the epoch's box records travel with its keyset (spec/crypto.md §4, Stale)
            let records = core.ix.sealed.get(&(m, r, e)).into_iter().flat_map(|x| x.by.iter().copied());
            core.ix.epoch_intro.get(&(m, r, e)).map(|x| x.1).into_iter().chain(carries).chain(records).collect::<Vec<_>>()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
