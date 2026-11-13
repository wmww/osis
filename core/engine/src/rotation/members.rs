//! Holder actors as this node judges them (spec/crypto.md §4, Holder actors): key access over the
//! actor grants it holds (cached), a holder actor's held keysets, the recipient a box seals it
//! to, stale and keyless boxes of an actor, and the writer's side of possession (a rotation only
//! with the authority its proofs show). The rules
//! are osis-keys' (`osis_keys::members`, `osis_keys::possession`); this gathers their inputs.
//! A departure from a holder actor counts only as what this node may encrypt under
//! (`super::blocked_epoch`): sealing at a keyset is encrypting under it.

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
        let Some(tl) = core.timelines.get(t) else { continue };
        if !tl.edges_at(None).holders(t).any(|(m, _)| actors(m)) {
            continue;
        }
        for (h, since) in tl.standing_since(t) {
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
/// `osis_keys::key_access`; `Core::key_access`).
pub(crate) fn key_access(core: &Core) -> Arc<BTreeSet<(Tid, Tid)>> {
    core.key_access.get(&(), || Arc::new(osis_keys::key_access(grants(core, &[]))))
}

/// `who`'s role on `a` now for keys (spec/crypto.md §4, Holds: `At::KEYS`, every `until`
/// disregarded), over its record chain and through holder actors whose grants have key access
/// only: a keyless grant gives no read through it (spec/requirements.md Permissions), so a party
/// holding `a` only so has left it.
pub(crate) fn role_for_keys(core: &Core, who: &Tid, a: &Tid) -> Option<Role> {
    let tl = core.timelines.get(a)?;
    let keyless = key_access(core);
    if keyless.is_empty() {
        return tl.role(who, a, osis_perm::At::KEYS);
    }
    tl.roles_without(who, osis_perm::At::KEYS, &keyless).get(a).copied()
}

/// Whether holder actor `h` of `a` has key access to it: unless it is among `keyless_holders`
/// (a holder not yet granted is judged by `grant_keyless`).
pub(crate) fn keyed(core: &Core, a: &Tid, h: &Tid) -> bool {
    !keyless_holders(core, a).contains(h)
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

/// The holders of `x` for keys in standing order (spec/crypto.md §4, Merger): the record edge
/// first, then by the key of the write that began each one's present standing (`Timeline::
/// standing_since`), ties by tid.
fn standing_order(core: &Core, x: &Tid) -> Vec<Tid> {
    let holders: BTreeSet<Tid> = core.edge_holders(x).into_iter().map(|h| h.0).collect();
    let Some(tl) = core.timelines.get(x) else { return holders.into_iter().collect() };
    let mut order: Vec<(Option<osis_perm::Point>, Tid)> = tl.standing_since(x).into_iter().filter(|(h, _)| holders.contains(h)).map(|(h, p)| (p, h)).collect();
    order.sort();
    order.into_iter().map(|(_, h)| h).collect()
}

/// The first party (an account or another key actor) that may rotate `r` of `a` over grants with
/// key access, depth first over each actor's holders in standing order from `a` (`Merger`).
/// None also when an actor ahead of it that may rotate `r` has holders this node holds no roster
/// of: the merger may be among them, so this node is none.
fn first_rotator(core: &Core, a: &Tid, r: Role) -> Option<Tid> {
    let mut seen = BTreeSet::from([*a]);
    let mut stack = vec![standing_order(core, a).into_iter()];
    while let Some(next) = stack.last_mut() {
        let Some(h) = next.next() else {
            stack.pop();
            continue;
        };
        if !super::may_rotate(core, &h, a).contains(&r) || !seen.insert(h) {
            continue;
        }
        if core.is_key_actor(&h) {
            return Some(h);
        }
        if core.timelines.get(&h).is_none() && core.first_admin(&h).is_none() {
            return None;
        }
        stack.push(standing_order(core, &h).into_iter());
    }
    None
}

/// Whether this node, signing as `who`, is the merger of role `r` of `a` (spec/crypto.md §4,
/// Merger): the first party that may rotate it (`first_rotator`), and for an account, its first
/// node in its devices actor's standing order. Read from rosters alone, never from the epochs
/// held: nodes holding the same edge writes name one merger whatever forks each holds, so
/// merges never fork each other. Nobody, when no party may rotate `r` as this node sees it.
pub(crate) fn is_merger(core: &Core, who: &Tid, a: &Tid, r: Role) -> bool {
    let Some(p) = first_rotator(core, a, r) else { return false };
    if p != *who {
        return false;
    }
    let Some(d) = core.accounts.get(&p).map(|h| h.devices) else { return true };
    let me = core.id.tid();
    standing_order(core, &d).into_iter().find(|n| *n != p && core.is_key_actor(n)) == Some(me)
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
        let Some(ai) = meta.view.aspects.iter().position(|a| a.tid == *m && a.ak.as_str() == "keys.0") else { continue };
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

/// The holders of `a` for keys without key access to it: none in the usual case, with no cycle
/// among the grants held. A holder has key access when every grant on some path from it to `a`
/// has it, through destroyed actors standing in their frozen holders' place
/// (`Core::keyed_holders`); a key actor always has (nothing holds one, so boxing it closes no
/// cycle).
fn keyless_holders(core: &Core, a: &Tid) -> BTreeSet<Tid> {
    let keyless = key_access(core);
    if keyless.is_empty() {
        return BTreeSet::new();
    }
    let keyed = core.keyed_holders(a, &keyless);
    core.key_holders(a).into_iter().map(|x| x.0).filter(|h| !core.is_key_actor(h) && !keyed.contains(h)).collect()
}

/// The tainted keysets of role `r` of actor `a` (spec/crypto.md §4, Tainted): the epochs at
/// which `a`'s `secrets.0` state boxes a holder without key access to it
/// (`osis_keys::boxing_keyless`), which for an actor this node may rotate its knowing re-key
/// leaves. `a`'s `secrets.0` is read only when such a holder exists.
fn tainted(tx: &mut Tx<'_>, a: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    // a box to a holder that departed is a departure from `a` (its own rotators' covers rule),
    // not a key cycle
    let none = keyless_holders(tx.core, a);
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
        .filter_map(|(_, b)| osis_keys::box_epoch(b))
        .collect())
}

/// The keysets of holder actor `m` of role `r` that `a`'s current keysets of `r` record `m` was
/// left out at (spec/crypto.md §4, Left out), each with the latest key of those keysets'
/// earliest bodies: Seal seals `m` only past each (`osis_keys::Keysets::past`).
fn left_out_at(core: &Core, a: &Tid, m: &Tid, r: Role) -> BTreeMap<Epoch, osis_perm::Point> {
    let mut out = BTreeMap::new();
    let Some(epochs) = core.epochs(a) else { return out };
    for x in epochs.role(r).current().iter().filter_map(|e| core.ix.keysets.get(&(*a, r, *e))) {
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
    /// No such commit is made yet: Seal waits for a keyset of a holder actor that descends from
    /// its anchors (`osis_keys::Seal::Wait`).
    Wait,
}

/// Holder `m` of `a`, holding `role`, as a rotation, grant or re-seal of `a` by `who` (this node,
/// or a key actor it signs as) boxes it (spec/crypto.md §4): a key actor whole; a holder actor
/// without key access not at all; one with it, per role up to `role`, at the keyset Seal gives
/// (`osis_keys::seal_keyset`), symmetric (signed: it shows possession) where this node holds that
/// established epoch's secret, cut at the first role with none or whose keyset `who` may not
/// encrypt under (`super::blocked_epoch`: a departure from `m` it knows that keyset does not
/// cover, say), left out of it and the roles above; `Wait` if Seal waits at any role up to
/// `role`.
pub(crate) fn sealed(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    Ok(sealing(tx, who, a, m, role)?.0)
}

/// `sealed`, with the keyset Seal gives at each role up to `role` that `who` may not encrypt
/// under (`super::blocked_epoch`), the roles above the cut included: what a rotation leaving `m`
/// out records (`left_out`).
pub(crate) fn sealing(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<(Sealed, BTreeMap<Role, Epoch>)> {
    let mut blocked = BTreeMap::new();
    if !tx.core.seals_to(a, m) {
        return Ok((Sealed::Out, blocked));
    }
    if tx.core.is_account(m) {
        return sealed_to_account(tx, who, a, m, role);
    }
    if tx.core.is_key_actor(m) {
        return Ok((recipient(tx, *m, role).ok().map_or(Sealed::Out, Sealed::Boxed), blocked));
    }
    if !keyed(tx.core, a, m) {
        return Ok((Sealed::Out, blocked));
    }
    let own = tx.core.own_epochs(m);
    let deps = super::departures(tx, m)?;
    let (mut keysets, mut secrets, mut top, mut cut) = (BTreeMap::new(), BTreeMap::new(), None, false);
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        let held = keysets_of(tx, m, r, None)?;
        let k = match osis_keys::seal_keyset(&held, &anchors(tx, a, m, r)?, &tainted(tx, m, r)?, &left_out_at(tx.core, a, m, r)) {
            Seal::At(k) => k,
            Seal::Out => {
                cut = true;
                continue;
            }
            // above the cut nothing is boxed, so nothing waits
            Seal::Wait if cut => continue,
            Seal::Wait => return Ok((Sealed::Wait, blocked)),
        };
        if super::blocked_epoch(tx, who, m, r, &k, &deps, super::Walk::Seal)? {
            blocked.insert(r, k);
            cut = true;
        }
        if cut {
            continue;
        }
        let secret = own.as_ref().filter(|e| e.role(r).is_established(&k)).and_then(|e| e.role(r).secret(&k)).cloned();
        let written = tx.core.ix.keysets.get(&(*m, r, k)).and_then(|x| x.kem.clone());
        let kem = written.or_else(|| secret.as_ref().map(|s| osis_crypto::role_kem(s).public().clone()));
        let Some(kem) = kem else {
            cut = true;
            continue;
        };
        keysets.insert(r, (k, kem));
        if let Some(s) = secret {
            secrets.insert(r, (k, s));
        }
        top = Some(r);
    }
    let sealed = top.map_or(Sealed::Out, |role| Sealed::Boxed(Recipient { holder: *m, role, keys: HolderKeys::Actor { keysets, own: secrets } }));
    Ok((sealed, blocked))
}

/// `sealing` for account `m`: one keyset names every role (spec/crypto.md §3), so its boxes up
/// to `role` go at one epoch, the newest Seal gives descending from every role's anchors and
/// left-out keysets; left out where a role of it is blocked at this node.
fn sealed_to_account(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<(Sealed, BTreeMap<Role, Epoch>)> {
    let mut blocked = BTreeMap::new();
    let (mut anchored, mut out) = (BTreeSet::new(), BTreeMap::new());
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        anchored.extend(anchors(tx, a, m, r)?);
        for (q, at) in left_out_at(tx.core, a, m, r) {
            out.entry(q).and_modify(|p: &mut osis_perm::Point| *p = (*p).max(at)).or_insert(at);
        }
    }
    let held = keysets_of(tx, m, role, None)?;
    let k = match osis_keys::seal_keyset(&held, &anchored, &BTreeSet::new(), &out) {
        Seal::At(k) => k,
        Seal::Out => return Ok((Sealed::Out, blocked)),
        Seal::Wait => return Ok((Sealed::Wait, blocked)),
    };
    let deps = super::keyset_departures(tx, m)?;
    let mut top = None;
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        if super::blocked_epoch(tx, who, m, r, &k, &deps, super::Walk::Seal)? {
            blocked.insert(r, k);
        } else if blocked.is_empty() {
            top = Some(r);
        }
    }
    let Some(role) = top else { return Ok((Sealed::Out, blocked)) };
    let sealed = crate::flows::account::holder_keys_at(tx, m, &k)?.map_or(Sealed::Out, |keys| Sealed::Boxed(Recipient { holder: *m, role, keys }));
    Ok((sealed, blocked))
}

/// The holders of `a` as a rotation by `who` boxes them, and what it records of the holder
/// actors it leaves out (`super::recipients`).
pub(crate) struct Boxing {
    pub(crate) holders: Vec<Recipient>,
    pub(crate) left_out: osis_keys::LeftOut,
}

/// What a rotation of `a` records of holder actor `m`, holding `role`, that it boxes only
/// up to `boxed` (`None`: not at all) (spec/crypto.md §4, Left out): at each role above, the
/// keyset Seal gives that the rotator may not encrypt under (`blocked`, from `sealing`), and the keysets `a`'s current
/// keysets of that role record already, less those another of them descends from (a holder
/// actor left out across rotations records its frontier, not its history). A key actor's boxes
/// name no keyset: nothing.
pub(crate) fn left_out(tx: &mut Tx<'_>, a: &Tid, m: &Tid, role: Role, boxed: Option<Role>, blocked: &BTreeMap<Role, Epoch>, out: &mut osis_keys::LeftOut) -> Result<()> {
    if tx.core.is_key_actor(m) && !tx.core.is_account(m) {
        return Ok(());
    }
    for r in ROLES.into_iter().filter(|r| *r <= role && Some(*r) > boxed) {
        let mut ks: BTreeSet<Epoch> = left_out_at(tx.core, a, m, r).into_keys().collect();
        ks.extend(blocked.get(&r));
        if ks.is_empty() {
            continue;
        }
        let held = keysets_of(tx, m, r, None)?;
        let frontier: BTreeSet<Epoch> = ks.iter().copied().filter(|q| !ks.iter().any(|x| x != q && held.descends(x, q))).collect();
        out.entry(r).or_default().insert(*m, frontier);
    }
    Ok(())
}

/// `who`'s roles now on paths through none of `avoid` (spec/crypto.md §4, Possession: as nodes
/// judge it), on `a`'s timeline.
fn roles_avoiding(core: &Core, who: &Tid, a: &Tid, avoid: &BTreeSet<Tid>) -> BTreeMap<Tid, Role> {
    let Some(tl) = core.timelines.get(a) else { return BTreeMap::new() };
    tl.roles_avoiding(who, osis_perm::At::now(crate::flows::now_ts(core)), avoid)
}

/// Whether `who` may make a rotation of `roles` of `a` needing `needed`, boxing `holders`
/// (`sealed`) (spec/crypto.md §4, Possession, Authority): `who` does not hold `needed` on `a`
/// only through holder actors of `a` with a keyset held that the rotation's keyset of `needed`
/// carries no proof for (`osis_keys::rotate` proves a holder at each rotated role it boxes
/// symmetric under the holder's secret: so none at `needed` in a rotation of read alone; an
/// account, one keyset for every role, at any). Otherwise it waits (`shown_roles` rotates write
/// with read): every node would judge that rotation invalid.
pub(crate) fn authority(core: &Core, who: &Tid, a: &Tid, roles: &BTreeSet<Role>, needed: Role, holders: &[Recipient]) -> bool {
    let proves = |h: &Recipient| match &h.keys {
        HolderKeys::Actor { own, keysets } => roles.contains(&needed) && needed <= h.role && own.get(&needed).is_some_and(|(es, _)| osis_keys::symmetric_box(es, keysets.get(&needed).map(|k| &k.0))),
        // one keyset for every role: a proof at any rotated role shows it
        HolderKeys::Account { keys, .. } => keys.is_some() && roles.iter().any(|r| *r <= h.role),
        HolderKeys::KeyActor { .. } => false,
    };
    let shown: BTreeSet<Tid> = holders.iter().filter(|h| proves(h)).map(|h| h.holder).collect();
    let avoid: BTreeSet<Tid> = core.key_holders(a).into_iter().map(|x| x.0).filter(|m| m != who && core.is_holder_actor(m) && !shown.contains(m)).collect();
    let on_a = |avoid: &BTreeSet<Tid>| roles_avoiding(core, who, a, avoid).get(a).copied();
    avoid.is_empty() || on_a(&avoid) >= Some(needed) || on_a(&BTreeSet::new()) < Some(needed)
}

/// The holder actors `a`'s epoch `e` of role `r` boxes, each with the keyset its box names, by
/// the boxes of `a`'s `secrets.0` state.
pub(crate) fn boxed_keysets(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<Vec<(Tid, Epoch)>> {
    let s = secrets_in(tx, a)?;
    Ok(s.boxes
        .iter()
        .filter(|(k, _)| k.role == r && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == *e))
        .filter(|(k, _)| !tx.core.is_key_actor(&k.holder) || tx.core.is_account(&k.holder))
        .filter_map(|(k, b)| Some((k.holder, osis_keys::box_epoch(b)?)))
        .collect())
}

/// The holder actors `a`'s epoch `e` of role `r` proves, each with the keyset its proof names:
/// the proofs of `e`'s keyset in its rotation commit (`epoch_intro`; spec/crypto.md §4,
/// Possession).
fn proved_keysets(core: &Core, a: &Tid, r: Role, e: &Epoch) -> Vec<(Tid, Epoch)> {
    let Some((_, c)) = core.ix.epoch_intro.get(&(*a, r, *e)) else { return Vec::new() };
    let Some(m) = core.ix.commits.get(c) else { return Vec::new() };
    let Some(ki) = m.header.aspects.iter().position(|x| x.tid == *a && x.ak.as_str() == "keys.0") else { return Vec::new() };
    let Some(x) = core.ix.shown.get(&(*c, ki)) else { return Vec::new() };
    x.shown.iter().filter(|s| s.role == r && (!core.is_key_actor(&s.holder) || core.is_account(&s.holder))).map(|s| (s.holder, s.keyset)).collect()
}

/// Whether `a`'s epoch `e` of role `r` has a stale box (spec/crypto.md §4, rule 2): a box of its
/// `secrets.0` state to a holder actor, or a proof of `e`'s keyset, naming a keyset of it held
/// invalid, tainted, or listed by a held valid keyset of it.
pub(crate) fn stale_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    let mut named = boxed_keysets(tx, a, r, e)?;
    named.extend(proved_keysets(tx.core, a, r, e));
    for (m, k) in named {
        let held = keysets_of(tx, &m, r, Some(&k))?;
        if osis_keys::stale(&k, &held, &tainted(tx, &m, r)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `a`'s epoch `e` of role `r` boxes a holder without key access to `a`, by a box of
/// its `secrets.0` state (spec/crypto.md §4, rule 4: a node that may rotate `a` re-keys while a current
/// epoch does).
pub(crate) fn keyless_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    Ok(tainted(tx, a, r)?.contains(e))
}

/// The held rotation commits of the keysets the boxes `w` writes to holder actors name, and those
/// the keysets `keys` writes record holder actors were left out at (spec/crypto.md §4, Carried):
/// placed under `a`'s labels with the commit carrying `w`.
pub(crate) fn carried(core: &Core, w: &osis_keys::SecretsWrite, keys: Option<&osis_keys::KeysWrite>) -> Vec<osis_base::CommitId> {
    let boxed = w.boxes.iter().filter_map(|(k, b)| Some((k.holder, k.role, osis_keys::box_epoch(b)?)));
    let out = keys.into_iter().flat_map(|k| k.keysets.iter()).flat_map(|(r, ks)| ks.left_out.iter().flat_map(move |(m, xs)| xs.iter().filter_map(move |x| Some((*m, *r, osis_keys::aspects::from_schema(x).ok()?)))));
    let mut out: Vec<osis_base::CommitId> = boxed
        .chain(out)
        .filter_map(|(m, r, e)| {
            if core.is_account(&m) {
                return core.account_view(&m)?.rotation_named(&e);
            }
            if core.is_key_actor(&m) {
                return None;
            }
            core.ix.epoch_intro.get(&(m, r, e)).map(|x| x.1)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
