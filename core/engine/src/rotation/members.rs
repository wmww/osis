//! Holder actors as this node judges them (spec/crypto.md §4, Holder actors): key access over the
//! actor grants it holds (cached), a holder actor's held keysets, the recipient a box seals it
//! to, stale and keyless boxes of an actor, and the writer's side of possession (a rotation only
//! with the authority its signed boxes show). The rules
//! are osis-keys' (`osis_keys::members`, `osis_keys::possession`); this gathers their inputs.
//! Nothing here reads a departure from a holder actor.

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::{recipient, secrets_in};
use osis_base::{CommitId, Role, Tid};
use osis_crypto::Epoch;
use osis_keys::{Grant, HolderKeys, Keysets, ROLES, Recipient, Seal};
use osis_schema::core_types::{BoxKey, SecretBox, Secrets};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The order of an actor grant (spec/crypto.md §4, key access): an owner's first, then an edge
/// by the write that began its standing (`None`: since before every change), then a grant being
/// written now.
type Order = (u8, Option<osis_perm::Point>);

/// The actor grants this node holds (spec/crypto.md §4, key access): each holder actor's standing
/// on each thing with a timeline (`Timeline::standing_since`), and the owner, if an actor, of
/// each thing such a grant touches and of each of `also` (its implicit edge from creation, ordered
/// before every edge, never the one left keyless).
fn grants(core: &Core, also: &[Tid]) -> Vec<osis_keys::Grant<Order>> {
    let mut grants = Vec::new();
    let mut seen: BTreeSet<Tid> = also.iter().copied().collect();
    for t in core.timelines.things() {
        let Some(tl) = core.timelines.get(t) else { continue };
        let owner = core.owner(t);
        let actors = |m: &Tid| Some(*m) != owner && !core.is_key_actor(m);
        if !tl.edges_at(None).holders(t).any(|(m, _)| actors(m)) {
            continue;
        }
        for (h, since) in tl.standing_since(t) {
            if actors(&h) {
                grants.push(Grant { order: (1, since), target: *t, holder: h });
                seen.extend([*t, h]);
            }
        }
    }
    for t in seen {
        if let Some(o) = core.owner(&t).filter(|o| !core.is_key_actor(o)) {
            grants.push(Grant { order: (0, None), target: t, holder: o });
        }
    }
    grants
}

/// The keyless grants (target, holder) among those this node holds (`grants`,
/// `osis_keys::key_access`), cached until a roster changes (`Core::role_changed`).
pub(crate) fn key_access(core: &mut Core) -> Arc<BTreeSet<(Tid, Tid)>> {
    if let Some(k) = &core.key_access {
        return k.clone();
    }
    let _s = crate::costs::span("key access");
    let k = Arc::new(osis_keys::key_access(grants(core, &[])));
    core.key_access = Some(k.clone());
    k
}

/// Whether holder actor `h` of `a` has key access to it (a key actor always has).
pub(crate) fn keyed(core: &mut Core, a: &Tid, h: &Tid) -> bool {
    core.is_key_actor(h) || !key_access(core).contains(&(*a, *h))
}

/// Whether a grant of `holder` on `target` written now would be keyless (spec/crypto.md §4): a
/// standing edge keeps its standing's judgement, a new one comes after every grant held.
pub(crate) fn grant_keyless(core: &mut Core, target: &Tid, holder: &Tid) -> bool {
    if core.is_key_actor(holder) {
        return false;
    }
    if core.key_holders(target).iter().any(|(m, _)| m == holder) {
        return key_access(core).contains(&(*target, *holder));
    }
    // the grants held with this one last, and the owners of both ends (an actor owned by the
    // target closes a cycle through its implicit edge, though it holds nothing yet)
    let mut gs = grants(core, &[*target, *holder]);
    gs.push(Grant { order: (2, None), target: *target, holder: *holder });
    osis_keys::key_access(gs).contains(&(*target, *holder))
}

/// The held keysets of role `r` of actor `m` (spec/crypto.md §4): the valid ones from `keysets`,
/// and `k`, when it is none of those, if held invalid.
fn keysets_of(tx: &mut Tx<'_>, m: &Tid, r: Role, k: Option<&Epoch>) -> Result<Keysets> {
    let mut out = Keysets::default();
    for (_, e, x) in tx.core.keysets_of(m).filter(|x| x.0 == r) {
        out.valid.insert(e, x.lists.clone());
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
        let mut recs = meta.dropped.get(&ai).map(|d| d.keysets.clone()).unwrap_or_default();
        for d in crate::apply::held_parts(tx, &id, ai)? {
            recs.extend(crate::apply::keys::keysets_of(&meta.header, ai, std::slice::from_ref(d.fragment())));
        }
        if recs.iter().any(|x| x.role == r && x.epoch == *k) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every box of an actor's `secrets.0` this node holds, valid or not (`held_boxes`).
pub(crate) struct HeldBoxes {
    state: Arc<Secrets>,
    invalid: Vec<(BoxKey, SecretBox)>,
}

impl HeldBoxes {
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&BoxKey, &SecretBox)> {
        self.state.boxes.iter().chain(self.invalid.iter().map(|(k, b)| (k, b)))
    }
}

/// Every box of `a`'s `secrets.0` this node holds, valid or not (spec/crypto.md §4, Held boxes):
/// the state's, and those of each held delta judged invalid. Invalidity decides whose writes
/// count, not what opens: a box an invalid commit wrote still opens for whoever holds the keyset
/// it names, so the rules a leak turns on (departures read from boxes, staleness, taint, the
/// knowing re-key) judge it too.
///
/// Invariant: a key cycle, a stale keyset or a box to a party holding no role, written by a commit
/// this node judges invalid (its author demoted concurrently, a box removal failing Authority),
/// is rotated away like one a valid commit wrote: a removed party reads none of the new content
/// once the writer holds that commit. A writer of `a` writing junk boxes makes `a`'s rotators
/// rotate once per such commit: no more than it could by rotating `a` itself.
pub(crate) fn held_boxes(tx: &mut Tx<'_>, a: &Tid) -> Result<HeldBoxes> {
    let state = secrets_in(tx, a)?;
    let ak = crate::flows::ak("secrets.0")?;
    let commits: Vec<CommitId> = tx.core.ix.invalid.get(&(*a, ak.clone())).into_iter().flatten().copied().collect();
    let mut invalid = Vec::new();
    for c in commits {
        let Some(ai) = tx.core.ix.commits.get(&c).and_then(|m| m.aspect(a, &ak).filter(|ai| !m.valid_at(*ai))) else { continue };
        for d in crate::apply::held_parts(tx, &c, ai)? {
            if let osis_commit::Decoded::Delta(d) = d {
                invalid.extend(crate::apply::keys::secrets_write(&d.fragment).boxes);
            }
        }
    }
    Ok(HeldBoxes { state, invalid })
}

/// The tainted keysets of role `r` of actor `m` (spec/crypto.md §4, 4b): the epochs at which
/// the boxes of `m`'s `secrets.0` this node holds (`held_boxes`) box a holder whose grant on `m`
/// is keyless.
fn tainted(tx: &mut Tx<'_>, m: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    if !has_keyless(tx.core, m) {
        return Ok(BTreeSet::new());
    }
    let boxes = held_boxes(tx, m)?;
    Ok(keyless_boxed(tx.core, m, &boxes, r))
}

/// Whether some grant on `a` is keyless: else no box of `a` goes through one (the usual case,
/// with no cycle among the grants held: `a`'s `secrets.0` is not read for it).
fn has_keyless(core: &mut Core, a: &Tid) -> bool {
    key_access(core).range((*a, Tid::from_bytes([0; 15]))..).next().is_some_and(|x| x.0 == *a)
}

/// The epochs of role `r` of `a` at which `boxes` (`a`'s held boxes) box a holder whose grant on
/// `a` is keyless (`osis_keys::boxing_keyless`): `a`'s tainted keysets, or, for an actor this
/// node may rotate, the epochs its knowing re-key leaves.
fn keyless_boxed(core: &mut Core, a: &Tid, boxes: &HeldBoxes, r: Role) -> BTreeSet<Epoch> {
    let boxes: Vec<(Tid, Epoch)> = boxes.iter().map(|x| x.0).filter(|k| k.role == r).filter_map(|k| Some((k.holder, osis_keys::aspects::from_schema(&k.epoch).ok()?))).collect();
    // holders whose grant is keyless; a box to a holder that departed is a departure from `a`
    // (its own rotators' covers rule), not a key cycle
    let holders: BTreeSet<Tid> = core.key_holders(a).into_iter().map(|x| x.0).collect();
    let mut none = BTreeSet::new();
    for h in boxes.iter().map(|x| x.0).filter(|h| holders.contains(h)).collect::<BTreeSet<Tid>>() {
        if !keyed(core, a, &h) {
            none.insert(h);
        }
    }
    osis_keys::boxing_keyless(boxes, |h| none.contains(h))
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

/// How a rotation, grant or re-seal of an actor boxes one holder (`sealed`).
pub(crate) enum Sealed {
    /// These boxes.
    Boxed(Recipient),
    /// Nothing: left out until re-sealed (no key access, keys or keyset to seal to).
    Out,
    /// No such commit is made yet: Seal waits for a keyset of a holder actor that descends from
    /// its anchors (`osis_keys::Seal::Wait`).
    Wait,
}

/// Holder `m` of `a`, holding `role`, as a rotation, grant or re-seal of `a` boxes it
/// (spec/crypto.md §4): a key actor whole; a holder actor without key access not at all; one with
/// it, per role up to `role`, at the keyset Seal gives (`osis_keys::seal_keyset`), symmetric
/// (signed: it shows possession) where this node holds that established epoch's secret, cut at
/// the first role with none (left out of it and the roles above); `Wait` if Seal waits at any
/// role up to `role`.
pub(crate) fn sealed(tx: &mut Tx<'_>, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    if tx.core.is_key_actor(m) {
        return Ok(recipient(tx, *m, role).ok().map_or(Sealed::Out, Sealed::Boxed));
    }
    if !keyed(tx.core, a, m) {
        return Ok(Sealed::Out);
    }
    let own = tx.core.own_epochs(m);
    let (mut keysets, mut secrets, mut top) = (BTreeMap::new(), BTreeMap::new(), None);
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        let held = keysets_of(tx, m, r, None)?;
        let k = match osis_keys::seal_keyset(&held, &anchors(tx, a, m, r)?, &tainted(tx, m, r)?) {
            Seal::At(k) => k,
            Seal::Out => break,
            Seal::Wait => return Ok(Sealed::Wait),
        };
        let secret = own.as_ref().filter(|e| e.role(r).is_established(&k)).and_then(|e| e.role(r).secret(&k)).cloned();
        let written = tx.core.ix.keysets.get(&(*m, r, k)).and_then(|x| x.kem.clone());
        let kem = match (written, &secret) {
            (Some(b), _) => osis_crypto::KemPublicKey::from_slice(&b).ok(),
            (None, Some(s)) => Some(osis_crypto::role_kem(s).public().clone()),
            (None, None) => None,
        };
        let Some(kem) = kem else { break };
        keysets.insert(r, (k, kem));
        if let Some(s) = secret {
            secrets.insert(r, (k, s));
        }
        top = Some(r);
    }
    Ok(top.map_or(Sealed::Out, |role| Sealed::Boxed(Recipient { holder: *m, role, keys: HolderKeys::Actor { keysets, own: secrets } })))
}

/// `who`'s roles now on paths through none of `avoid` (spec/crypto.md §4, Possession: as nodes
/// judge it), on `a`'s timeline.
fn roles_avoiding(core: &Core, who: &Tid, a: &Tid, avoid: &BTreeSet<Tid>) -> BTreeMap<Tid, Role> {
    let Some(tl) = core.timelines.get(a) else { return BTreeMap::new() };
    tl.roles_avoiding(who, osis_perm::At::now(crate::flows::now_ts(core)), avoid)
}

/// Whether `who` may make a rotation of `a` needing `needed`, boxing `holders` (`sealed`)
/// (spec/crypto.md §4, Possession, Authority): `who` does not hold `needed` on `a` only through
/// holder actors of `a` with a keyset held that it does not box symmetric (signed).
/// Otherwise it waits: every node would judge that rotation invalid.
pub(crate) fn authority(core: &Core, who: &Tid, a: &Tid, needed: Role, holders: &[Recipient]) -> bool {
    let shown: BTreeSet<Tid> = holders.iter().filter(|h| matches!(&h.keys, HolderKeys::Actor { own, .. } if !own.is_empty())).map(|h| h.holder).collect();
    let avoid: BTreeSet<Tid> = core.key_holders(a).into_iter().map(|x| x.0).filter(|m| !core.is_key_actor(m) && core.keysets_of(m).next().is_some() && !shown.contains(m)).collect();
    let on_a = |avoid: &BTreeSet<Tid>| roles_avoiding(core, who, a, avoid).get(a).copied();
    avoid.is_empty() || on_a(&avoid) >= Some(needed) || on_a(&BTreeSet::new()) < Some(needed)
}

/// Whether `a`'s epoch `e` of role `r` has a stale box (spec/crypto.md §4, rule 2): a box held
/// (`held_boxes`) to a holder actor naming a keyset held invalid, tainted, or listed by a held
/// valid keyset of it.
pub(crate) fn stale_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    let boxes = held_boxes(tx, a)?;
    let named: Vec<(Tid, Epoch)> = boxes
        .iter()
        .filter(|(k, _)| k.role == r && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == *e))
        .filter(|(k, _)| !tx.core.is_key_actor(&k.holder))
        .filter_map(|(k, b)| Some((k.holder, osis_keys::box_epoch(b)?)))
        .collect();
    for (m, k) in named {
        let held = keysets_of(tx, &m, r, Some(&k))?;
        if osis_keys::stale(&k, &held, &tainted(tx, &m, r)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `a`'s epoch `e` of role `r` boxes a holder whose grant on `a` is keyless, by a box held
/// (`held_boxes`; spec/crypto.md §4, rule 4: a node that may rotate `a` re-keys while a current
/// epoch does).
pub(crate) fn keyless_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<bool> {
    if !has_keyless(tx.core, a) {
        return Ok(false);
    }
    let boxes = held_boxes(tx, a)?;
    Ok(keyless_boxed(tx.core, a, &boxes, r).contains(e))
}

/// The held rotation commits of the keysets the boxes `w` writes to holder actors name
/// (spec/crypto.md §4, Carried): placed under `a`'s labels with the commit carrying `w`.
pub(crate) fn carried(core: &Core, w: &osis_keys::SecretsWrite) -> Vec<osis_base::CommitId> {
    let mut out: Vec<osis_base::CommitId> = w
        .boxes
        .iter()
        .filter(|(k, _)| !core.is_key_actor(&k.holder))
        .filter_map(|(k, b)| core.ix.epoch_intro.get(&(k.holder, k.role, osis_keys::box_epoch(b)?)).map(|x| x.1))
        .collect();
    out.sort();
    out.dedup();
    out
}
