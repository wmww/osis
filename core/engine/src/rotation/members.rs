//! Holder actors as this node judges them (spec/crypto.md §4, Holder actors): key access over the
//! actor grants it holds (cached), a holder actor's held keysets, the recipient a box seals it
//! to, stale and keyless boxes of an actor, and the demotions its keysets carry. The rules are
//! osis-keys' (`osis_keys::members`); this gathers their inputs.
//! A departure from a holder actor counts only as what this node may encrypt under
//! (`super::blocking`): sealing at a keyset is encrypting under it, and a joint box is held back
//! by departures only where every keyset it names misses one.

use crate::engine::{Core, Tx};
use crate::error::Result;
use crate::flows::secrets_in;
use osis_base::{CommitId, Role, Tid};
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
    for t in &core.timelines().things() {
        let Some(on) = core.timelines().on(t) else { continue };
        for (h, since) in on.standing_since() {
            grants.push(Grant { order: (1, since), target: *t, holder: h });
        }
    }
    for t in also {
        if core.timelines().get(t).is_none()
            && let Some(a) = core.mint_admin(t)
        {
            grants.push(Grant { order: (1, None), target: *t, holder: a });
        }
    }
    grants
}

/// The keyless grants (target, holder) among those this node holds (`grants`,
/// `osis_keys::key_access`), kept by the timelines (`held::Timelines::keyless`).
pub(crate) fn key_access(core: &Core) -> Arc<BTreeSet<(Tid, Tid)>> {
    core.timelines().keyless()
}

/// The keyless grants among the actor grants of one component's timeline `tl`: each holder
/// actor's standing on each thing (`Timeline::standing_since_all`, record edges included), as
/// `grants` gathers them. A keyless grant closes a cycle of actor grants (`osis_keys::key_access`),
/// and a cycle lies in one component, so the union over components is the answer over all.
pub(crate) fn keyless_in(tl: &osis_perm::Timeline) -> BTreeSet<(Tid, Tid)> {
    let standing = tl.standing_since_all(None);
    // counted: tests read that making a thing judges no component's grants anew
    osis_base::costs::count("keys: grants judged for key access", standing.values().map(|on| on.len() as u64).sum());
    keyless_among(standing)
}

/// Whether `h`'s grant on `a`, ended by the removal at `p`, had key access just before it: it
/// stood then and was no keyless grant among the actor grants standing over the writes before
/// `p` (`keyless_in`'s rule there; spec/permissions.md §3 Retain). Invariant: it reads only
/// applied, permission-checked writes and `p`, the removal's own point, so a writer choosing `p`
/// gets the answer an honest removal written there would have.
pub(crate) fn keyed_before(tl: &osis_perm::Timeline, a: &Tid, h: &Tid, p: osis_perm::Point) -> bool {
    let standing = tl.standing_since_all(Some(p));
    standing.get(a).is_some_and(|on| on.contains_key(h)) && !keyless_among(standing).contains(&(*a, *h))
}

/// `keyless_in` over the writes before `p` alone: the keyless grants as they stood there.
#[cfg(test)]
pub(crate) fn keyless_before(tl: &osis_perm::Timeline, p: osis_perm::Point) -> BTreeSet<(Tid, Tid)> {
    keyless_among(tl.standing_since_all(Some(p)))
}

/// The keyless grants among the actor grants `standing` (per thing, each holder's standing since).
fn keyless_among(standing: BTreeMap<Tid, BTreeMap<Tid, Option<osis_perm::Point>>>) -> BTreeSet<(Tid, Tid)> {
    let mut grants = Vec::new();
    for (t, on) in standing {
        for (h, since) in on {
            grants.push(Grant { order: (1, since), target: t, holder: h });
        }
    }
    osis_keys::key_access(grants)
}

/// `who`'s role on `a` now for keys (spec/crypto.md §4, Holds: `At::KEYS`, every `until`
/// disregarded), over its record chain and through holder actors whose grants have key access
/// only (`key_skip`): a keyless grant gives no read through it (spec/requirements.md
/// Permissions), and a destroyed thing holds nothing, so a party holding `a` only so has left it.
pub(crate) fn role_for_keys(core: &Core, who: &Tid, a: &Tid) -> Option<Role> {
    core.timelines().roles_on(a, osis_perm::At::KEYS, &key_skip(core)).get(who).copied()
}

/// The actor grants (target, holder) a role for keys does not pass through: the keyless ones
/// (`key_access`) and those a destroyed thing holds (spec/crypto.md §4, Holds; Destroyed). The
/// keyless set itself where nothing destroyed is named as a holder.
pub(crate) fn key_skip(core: &Core) -> Arc<BTreeSet<(Tid, Tid)>> {
    let keyless = key_access(core);
    let held = &core.ix.held;
    let gone: Vec<(Tid, Tid)> = core.ix.destroyed.iter().flat_map(|g| held.named_on(g).filter(|t| *t != g).map(|t| (*t, *g)).collect::<Vec<_>>()).collect();
    if gone.is_empty() {
        return keyless;
    }
    Arc::new(keyless.iter().copied().chain(gone).collect())
}

/// Whether holder `h` of `a` has key access to it: its grant is not keyless (spec/crypto.md §4,
/// Key access). A holder not yet granted has it (`grant_keyless` judges the new grant).
pub(crate) fn keyed(core: &Core, a: &Tid, h: &Tid) -> bool {
    !key_access(core).contains(&(*a, *h))
}

/// Whether a grant of `holder` on `target` written now would be keyless (spec/crypto.md §4): a
/// standing edge on `target` (`edge_holders`) keeps its standing's judgement, a new one comes
/// after every grant held.
pub(crate) fn grant_keyless(core: &mut Core, target: &Tid, holder: &Tid) -> bool {
    if core.edge_holders(target).iter().any(|(m, _)| m == holder) {
        return key_access(core).contains(&(*target, *holder));
    }
    // the grants held with this one last, and the record edges of both ends (an actor whose
    // mint admin is the target closes a cycle through its record edge, though it holds nothing
    // yet)
    let mut gs = grants(core, &[*target, *holder]);
    gs.push(Grant { order: (2, None), target: *target, holder: *holder });
    osis_keys::key_access(gs).contains(&(*target, *holder))
}

/// The held keysets of role `r` of actor `m` (spec/crypto.md §4): the valid ones from `keysets`
/// (a foreign one among them: its list keeps what it lists stale, Foreign), and `k`, when it is
/// none of those, if held invalid.
pub(super) fn keysets_of(tx: &mut Tx<'_>, m: &Tid, r: Role, k: Option<&Epoch>) -> Result<Keysets> {
    let mut out = Keysets::default();
    for (_, e, x) in tx.core.keysets_of(m).filter(|x| x.0 == r) {
        out.valid.insert(e, x.lists.clone());
    }
    if let Some(k) = k.filter(|k| !out.valid.contains_key(k))
        && tx.core.keyset_invalid(m, r, k)
    {
        out.invalid.insert(*k);
    }
    Ok(out)
}

/// The invalid commits whose `keys.0` body of `m` writes `k` as its keyset of `r`, where `k` is
/// held invalid (`Core::keyset_invalid`): a stale box's causes (Left out).
fn invalid_writers(core: &Core, m: &Tid, r: Role, k: &Epoch) -> BTreeSet<CommitId> {
    match core.keyset_invalid(m, r, k) {
        true => core.ix.keysets_invalid.get(&(*m, r, *k)).cloned().unwrap_or_default(),
        false => BTreeSet::new(),
    }
}

/// Foreign keysets (spec/crypto.md §4 Holder actors, Foreign): a held valid keyset k of role r of
/// thing x is foreign when its box records (`Indexes::sealed`: written by a commit writing
/// k's keyset) name a keyset held invalid or foreign here. So k is foreign when the own records,
/// followed through held valid keysets, reach one held invalid. One `Foreign` judges any number
/// of keysets, each (thing, role, keyset) walked once: one found to reach nothing invalid is
/// remembered so (`clean`).
///
/// Invariant: a foreign epoch rests on a write the node's side does not apply (one side per
/// party, notes/disputes.md Rotations under a fork), so it supersedes nothing here and makes no
/// rotation due here (`RoleEpochs::set_foreign`, `rotation_due`); it is blocked here by the very
/// box that makes it foreign (a box naming a keyset held invalid is stale, `box_blocked`; one
/// naming a foreign keyset is blocked through the box walk at that keyset's own such box,
/// `blocked_epoch`), so nobody here encrypts under it; a rotation here carries it in its history
/// box and lists it nowhere (`osis_keys::rotate_leaving_out`). To what holds a role on x, a
/// foreign keyset's list keeps what it lists stale, so a party removed below a knowing keyset
/// made foreign by an honest race is kept out above it
/// (`a_box_naming_an_invalid_keyset_is_recorded_with_its_rotation_spec_crypto_4`), but it anchors
/// nothing and is sealed to nowhere (`sealing_at`; a stale keyset Seal then gives is blocked,
/// `seal_blocked`): counted as any keyset there, or listed by rotations, a fork below x makes
/// each side's keysets of x stale above x at the other, which leaves x out and re-keys it in
/// turn for good (ForkDepth `FD_fork_builder`, `FD_fork_list`;
/// `fork_two_below_one_side_first_stops_rotating_spec_crypto_4`). Who writes the inputs: a box record
/// is written by the writer of `x`'s rotation commit (a party on the other side of a fork on a
/// holder actor among them); a keyset is held invalid by this node's own walk (a removed party's
/// forgery, the other side's rotations, a keyset planted at some nodes only). A writer of `x`
/// may re-write any keyset of `x`, one this node made included, beside a record naming a keyset
/// held invalid here, making it foreign (spec/crypto.md §4 Foreign reads any commit writing the
/// keyset): that costs a rotation, never a leak, as a foreign epoch only stops superseding, so what it listed stays current here and is
/// judged by the ordinary rules (an uncovered departure there is due as ever).
#[derive(Default)]
pub(crate) struct Foreign {
    clean: BTreeSet<(Tid, Role, Epoch)>,
}

impl Foreign {
    /// Whether held valid keyset `k` of role `r` of `x` is foreign here (false where it is not
    /// held valid).
    pub(crate) fn is(&mut self, core: &Core, x: &Tid, r: Role, k: &Epoch) -> bool {
        if self.clean.contains(&(*x, r, *k)) || core.keyset(x, r, k).is_none() {
            return false;
        }
        let mut seen = BTreeSet::from([(*x, r, *k)]);
        let mut todo = vec![(*x, *k)];
        while let Some((y, j)) = todo.pop() {
            let Some(at) = core.ix.sealed.get(&(y, r, j)) else { continue };
            for (h, js) in &at.keysets {
                for i in js {
                    if core.keyset_invalid(h, r, i) {
                        return true;
                    }
                    if !self.clean.contains(&(*h, r, *i)) && core.keyset(h, r, i).is_some() && seen.insert((*h, r, *i)) {
                        todo.push((*h, *i));
                    }
                }
            }
        }
        self.clean.extend(seen);
        false
    }
}

/// Marks the foreign epochs of actor `a` in `view`, its epochs as this node holds them
/// (`RoleEpochs::set_foreign`): those whose held valid keyset is foreign (`Foreign`).
pub(crate) fn set_foreign(core: &Core, a: &Tid, view: &mut osis_keys::ActorEpochs) {
    let mut foreign = Foreign::default();
    for r in ROLES {
        let found: Vec<Epoch> = view.role(r).epochs().map(|(e, _)| *e).filter(|e| foreign.is(core, a, r, e)).collect();
        for e in found {
            view.role_mut(r).set_foreign(&e);
        }
    }
}

/// The holders of `a` for keys a box of role `r` to which goes past their key access: those
/// whose grant on `a` is keyless (a box above their role for keys is a demotion's departure, not
/// a key cycle). None in the usual case, with no cycle among the grants held.
pub(super) fn keyless_holders(core: &Core, a: &Tid) -> BTreeSet<Tid> {
    let keyless = key_access(core);
    if keyless.is_empty() {
        return BTreeSet::new();
    }
    core.key_holders(a).into_iter().map(|(h, _)| h).filter(|h| keyless.contains(&(*a, *h))).collect()
}

/// The tainted keysets of role `r` of actor `a` (spec/crypto.md §4, Tainted): the epochs at
/// which `a`'s `secrets.0` state boxes a holder past its key access to it (`keyless_holders`,
/// `osis_keys::boxing_keyless`), which for an actor this node may rotate its knowing re-key
/// leaves. `a`'s `secrets.0` is read only when such a holder exists.
fn tainted(tx: &mut Tx<'_>, a: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    // a box to a holder that departed is a departure from `a` (its own rotators' covers rule),
    // not a key cycle
    let none = keyless_holders(tx.core, a);
    if none.is_empty() {
        return Ok(BTreeSet::new());
    }
    let s = secrets_in(tx, a)?;
    let boxes: Vec<(Tid, Epoch)> = s.boxes.iter().map(|x| x.0).filter(|k| k.role == r).filter_map(|k| Some((k.holder.0, osis_keys::aspects::from_schema(&k.epoch).ok()?))).collect();
    Ok(osis_keys::boxing_keyless(boxes, |h| none.contains(h)))
}

/// The anchors of holder actor `m` for role `r` of `a` (spec/crypto.md §4): the epochs of `m`
/// the boxes to it of role `r` at `a`'s current epochs name.
fn anchors(tx: &mut Tx<'_>, a: &Tid, m: &Tid, r: Role) -> Result<BTreeSet<Epoch>> {
    let Some(epochs) = tx.core.epochs(a) else { return Ok(BTreeSet::new()) };
    let s = secrets_in(tx, a)?;
    Ok(s.boxes
        .iter()
        .filter(|(k, _)| k.holder == osis_base::Weak(*m) && k.role == r)
        .filter(|(k, _)| osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|e| epochs.role(r).is_current(&e)))
        .flat_map(|(_, b)| osis_keys::box_keysets(b))
        .collect())
}

/// The keysets of holder actor `m` of role `r` that `a` leaves it out at (spec/crypto.md §4,
/// Left out), each with its causes: those held valid that a keyset of a current epoch of `r` of
/// `a` records for `m` with a cause that stands here (`stands`), or with a cause not held (judged
/// once each is: a record is never read void for want of a cause that travels with it,
/// spec/crypto.md §4 Carried; `a`'s keyset does not wait for it, so a cause nobody holds keeps
/// no keyset of `a` from arriving). Each is blocked by a
/// box (`box_blocked`, `seal_blocked`), so Seal leaves `m` out at it.
///
/// Invariant: a record is evidence, not a verdict. Its effect is re-derived here from the commits
/// it names, so a record whose every cause this node holds and judges void (a departure ended by
/// a regrant or its invalidity, a grant given key access) counts nothing; one standing on a
/// rotation commit keeps `m` out until `m` re-keys (`stands`). Who writes it: any writer of `a`, naming any
/// keyset and any commits; a false record counts only while a commit it names is a standing cause
/// here (or is never held), so it can keep `m` out only at that keyset, until `m` rotates
/// (`rekey_due`) or leaves `a`.
pub(crate) fn left_out_at(tx: &mut Tx<'_>, a: &Tid, m: &Tid, r: Role) -> Result<BTreeMap<Epoch, BTreeSet<CommitId>>> {
    let mut out = BTreeMap::new();
    let Some(epochs) = tx.core.epochs(a) else { return Ok(out) };
    // the noted keysets, held or not (one waiting for its carried demotions counts its record)
    let mut recs: BTreeMap<Epoch, BTreeSet<CommitId>> = BTreeMap::new();
    for e in epochs.role(r).current() {
        if let Some(ks) = tx.core.ix.keysets.get(&(*a, r, e)).and_then(|x| x.left_out.get(m)) {
            for (q, c) in ks {
                recs.entry(*q).or_default().extend(c.iter().copied());
            }
        }
    }
    if recs.is_empty() {
        return Ok(out);
    }
    let held: BTreeSet<Epoch> = tx.core.keysets_of(m).filter(|x| x.0 == r).map(|x| x.1).collect();
    for (q, causes) in recs.into_iter().filter(|(q, _)| held.contains(q)) {
        let mut counts = false;
        for c in &causes {
            if !tx.core.cause_held(c) || stands(tx, c)? {
                counts = true;
                break;
            }
        }
        if counts {
            out.insert(q, causes);
        }
    }
    Ok(out)
}

/// Whether left-out cause `c`, held here, stands (spec/crypto.md §4, Left out): a commit writing
/// a keyset (a rotation) while held, valid or not: valid, its keyset supersedes what it lists or
/// is an epoch a departed party holds; invalid, it is a keyset no box may name; any other while
/// one of its edge writes is a departure's that its holder still has here, other than this
/// node's own (`super::others`), or a grant still keyless here.
///
/// Invariant: a cause stops standing only where this node can show what it showed is gone. An
/// edge write's departure ends with a regrant or its invalidity, a keyless grant with key
/// access, each judged by this node's own walk over held commits; a commit writing a keyset as
/// well (a removal's own rotation) stands as a rotation, since a record does not say which of
/// its writes it was named for. A keyset proves its block by
/// existing: invalid, a reader lacking what invalidates it would find it valid, so validity
/// cannot end it either way; the record it keeps ends with `m`'s re-key (`rekey_due`). Who
/// writes it: anyone; a hostile record naming any held rotation counts as one naming a standing
/// departure does, one rotation of `m` per record.
fn stands(tx: &mut Tx<'_>, c: &CommitId) -> Result<bool> {
    if writes_keyset(tx.core, c) {
        return Ok(true);
    }
    if let Some(rc) = tx.core.ix.held.edge_commit(c).cloned() {
        let keyless = key_access(tx.core);
        for op in &rc.ops {
            let Some(h) = op.holder.thing() else { continue };
            if keyless.contains(&(op.target, h)) {
                return Ok(true);
            }
            let deps = super::departures(tx, &op.target)?;
            let wrote = |d: &osis_keys::Departure| d.holder == h && d.edge.as_ref().is_some_and(|e| e.writes.iter().any(|w| w.key.commit == *c));
            if super::others(tx.core, &op.target, None, deps).iter().any(wrote) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The commit that wrote keyset `e` of role `r` of `x` (a left-out cause, spec/crypto.md §4):
/// its rotation commit (`Indexes::epoch_intro`), else the earliest held valid body writing it (a
/// compaction snapshot's, `HeldKeyset::since`).
pub(crate) fn keyset_commit(core: &Core, x: &Tid, r: Role, e: &Epoch) -> Option<CommitId> {
    core.ix.epoch_intro.get(&(*x, r, *e)).map(|v| v.1).or_else(|| core.keyset(x, r, e).and_then(|k| k.since).map(|p| p.commit))
}

/// Whether held commit `c` has a `keys.0` part writing a keyset (`Indexes::keyset_parts`).
fn writes_keyset(core: &Core, c: &CommitId) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.view.aspects.iter().any(|a| a.ak.as_str() == "keys.0" && core.ix.keyset_parts.get(&a.tid).is_some_and(|s| s.contains(c))))
}

/// Re-key (spec/crypto.md §4, Left out): whether `a` leaves its holder actor `m`, holding `r` or
/// more on `a` for keys with key access, out of `r` at a current keyset of `m` (a held valid one
/// no other held valid keyset that is not foreign lists, and none this node's view of `m`
/// holds superseded: a foreign keyset is listed nowhere, superseded by the history box of the
/// rotation carrying it, so the re-key's maker holds it superseded). A node
/// that may rotate `r` of `m` rotates it at the end of a complete pass of `a`'s sync IDs: the
/// fresh keyset is recorded nowhere, so `a` re-seals `m` there.
///
/// Invariant (hostile inputs): it makes `m`'s rotators rotate `m` only, as any rotation of `m`,
/// boxing `m`'s holders for keys and no one else, so it hands no party anything a rotation of `m`
/// would not; a party removed from `m` holding its old keys gains nothing. A record is written
/// by a writer of `a`: each of its rotations of `a` recording a current keyset of `m` with a
/// standing (or never held) cause forces at most one rotation of `m` per rotator of `m`, after
/// which that keyset is no longer current; a hostile writer's end with its removal from `a`.
/// `m`'s keysets and `a`'s holders are read only where a record counts.
pub(crate) fn rekey_due(tx: &mut Tx<'_>, a: &Tid, m: &Tid, r: Role) -> Result<bool> {
    let out = left_out_at(tx, a, m, r)?;
    if out.is_empty() {
        return Ok(false);
    }
    let held = keysets_of(tx, m, r, None)?;
    // a foreign keyset supersedes nothing (spec/crypto.md §4 Holder actors, Foreign)
    let mut foreign = Foreign::default();
    let listing: Vec<&BTreeSet<Epoch>> = held.valid.iter().filter(|(k, _)| !foreign.is(tx.core, m, r, k)).map(|(_, l)| l).collect();
    // and none this node's view of `m` holds superseded: a foreign keyset is listed nowhere, its
    // supersession read from the history box of the rotation carrying it, at a node holding its
    // secret (spec/crypto.md §4 Supersedes; the re-key's maker does)
    let view = tx.core.epochs(m);
    let current = |q: &Epoch| held.valid.contains_key(q) && !listing.iter().any(|l| l.contains(q)) && !view.as_ref().is_some_and(|v| v.role(r).superseded(q));
    if !out.keys().any(current) {
        return Ok(false);
    }
    Ok(tx.core.key_holders(a).into_iter().any(|(h, role)| h == *m && role >= r && keyed(tx.core, a, m)))
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
/// or a link key it signs as) boxes it (spec/crypto.md §4), up to `role`, none without key
/// access (`keyed`): per role, at the keysets Seal gives
/// (`osis_keys::seal_keyset`): one, symmetric where this node holds that
/// established epoch's secret, or several jointly; cut at the first role with none or whose box
/// `who` may not make (`seal_blocked`: a departure from `m` it knows that keyset, or every keyset
/// of a joint box, does not cover, say, or a keyset `a` leaves `m` out at), left out of it and
/// the roles above.
pub(crate) fn sealed(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    if !keyed(tx.core, a, m) {
        return Ok(Sealed::Out);
    }
    sealed_granted(tx, who, a, m, role)
}

/// `sealed` for a grant of `role` to `m` with key access (`grant_keyless` judged it): up to
/// `role` itself, which the grant's own edge gives `m`.
pub(crate) fn sealed_granted(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    let mut sealed = sealing_at(tx, who, a, m, role)?;
    if let Sealed::Boxed(r) = &mut sealed {
        r.floor = super::floors::holder_floor(tx.core, a, m);
    }
    Ok(sealed)
}

/// `sealed` at `role` as given (key access judged by the caller), the recipient's floor 0.
fn sealing_at(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role) -> Result<Sealed> {
    // the public holds no keys and is no holder actor: boxed in clear at every role it holds,
    // with no keyset, block or left-out record (spec/crypto.md §4 Boxes, Holder actors)
    if m.is_public() {
        return Ok(Sealed::Boxed(Recipient::public(role, 0)));
    }
    let own = tx.core.own_epochs(m);
    let deps = super::departures(tx, m)?;
    let (mut keysets, mut secrets, mut top) = (BTreeMap::new(), BTreeMap::new(), None);
    for r in ROLES.into_iter().filter(|r| *r <= role) {
        let held = keysets_of(tx, m, r, None)?;
        // a foreign keyset anchors nothing and is sealed to nowhere (spec/crypto.md §4 Holder
        // actors, Foreign): its list keeps what it lists stale all the same
        let mut foreign = Foreign::default();
        let foreign: BTreeSet<Epoch> = held.valid.keys().filter(|k| foreign.is(tx.core, m, r, k)).copied().collect();
        let anchors: BTreeSet<Epoch> = anchors(tx, a, m, r)?.difference(&foreign).copied().collect();
        // a candidate carries a KEM key or its secret is held here (spec/crypto.md §4 Seal): a
        // newer KEM-less keyset leaves the older ones stale, so Seal gives a stale one and `m` is
        // left out (blocked by a box), never sealed at a keyset a party removed since may hold
        let bare: BTreeSet<Epoch> = held.valid.keys().filter(|k| tx.core.keyset(m, r, k).is_none_or(|x| x.kem_in.is_none()) && own.as_ref().is_none_or(|e| !e.role(r).is_established(k) || e.role(r).secret(k).is_none())).copied().collect();
        let skip: BTreeSet<Epoch> = tainted(tx, m, r)?.union(&foreign).chain(&bare).copied().collect();
        let Seal::At(ks) = osis_keys::seal_keyset(&held, &anchors, &skip) else { break };
        if !seal_blocked(tx, who, a, m, r, &ks, &deps)?.is_empty() {
            break;
        }
        let (mut row, mut wrap) = (Vec::new(), None);
        for k in &ks {
            let secret = own.as_ref().filter(|e| e.role(r).is_established(k)).and_then(|e| e.role(r).secret(k)).cloned();
            let written = crate::apply::keys::keyset_kem(tx, m, r, k)?;
            let Some(kem) = written.or_else(|| secret.as_ref().map(|s| s.kem().public().clone())) else { break };
            row.push((*k, kem));
            if wrap.is_none() {
                wrap = secret.map(|s| (*k, s.secret().clone()));
            }
        }
        if row.len() < ks.len() {
            break;
        }
        keysets.insert(r, row);
        secrets.extend(wrap.map(|p| (r, p)));
        top = Some(r);
    }
    Ok(top.map_or(Sealed::Out, |role| Sealed::Boxed(Recipient { holder: *m, role, keys: HolderKeys { keysets, own: secrets }, floor: 0 })))
}

/// The read keyset of holder actor `m` of `a` a notice of its removal from `a` is sealed to
/// (spec/permissions.md §4 Notices): as Seal gives it with no anchor (the newest candidate: held
/// valid, not foreign or tainted, carrying a KEM key or whose secret is held here), none where
/// that is blocked here (`seal_blocked`): its epoch and read KEM key. The public, holding no
/// keys, has none.
pub(crate) fn notice_keyset(tx: &mut Tx<'_>, a: &Tid, m: &Tid) -> Result<Option<(Epoch, osis_crypto::KemPublicKey)>> {
    if m.is_public() {
        return Ok(None);
    }
    let r = Role::Read;
    let own = tx.core.own_epochs(m);
    let deps = super::departures(tx, m)?;
    let held = keysets_of(tx, m, r, None)?;
    let mut foreign = Foreign::default();
    let foreign: BTreeSet<Epoch> = held.valid.keys().filter(|k| foreign.is(tx.core, m, r, k)).copied().collect();
    let secret = |k: &Epoch| own.as_ref().filter(|e| e.role(r).is_established(k)).and_then(|e| e.role(r).secret(k)).cloned();
    let bare: BTreeSet<Epoch> = held.valid.keys().filter(|k| tx.core.keyset(m, r, k).is_none_or(|x| x.kem_in.is_none()) && secret(k).is_none()).copied().collect();
    let skip: BTreeSet<Epoch> = tainted(tx, m, r)?.union(&foreign).chain(&bare).copied().collect();
    let Seal::At(ks) = osis_keys::seal_keyset(&held, &BTreeSet::new(), &skip) else { return Ok(None) };
    let me = tx.core.tid();
    let (Some(k), true) = (ks.first().copied(), seal_blocked(tx, &me, a, m, r, &ks, &deps)?.is_empty()) else { return Ok(None) };
    let kem = crate::apply::keys::keyset_kem(tx, m, r, &k)?.or_else(|| secret(&k).map(|s| s.kem().public().clone()));
    Ok(kem.map(|kem| (k, kem)))
}

/// The keysets `ks` Seal gives for `m` at `r` that leave `m` out of `a` (`super::joint_blocked`):
/// a box naming them is encrypting under each (`super::blocking`), and a joint one opens only for
/// a holder of every one, so it waits on a missed departure only when every keyset misses one; a
/// keyset `a` leaves `m` out at (`left_out_at`) is blocked by a box.
fn seal_blocked(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, r: Role, ks: &BTreeSet<Epoch>, deps: &[osis_keys::Departure]) -> Result<BTreeSet<Epoch>> {
    let out = left_out_at(tx, a, m, r)?;
    let held = keysets_of(tx, m, r, None)?;
    let mut why = BTreeMap::new();
    for k in ks {
        // stale: Seal gives it only where the keyset listing it is foreign (no candidate)
        if out.contains_key(k) || osis_keys::stale(k, &held, &BTreeSet::new()) {
            why.insert(*k, super::Block::Box);
        } else if let Some((b, _)) = super::blocking(tx, who, m, r, k, deps, super::Walk::Encrypt)? {
            why.insert(*k, b);
        }
    }
    Ok(super::joint_blocked(why, ks.len()))
}

/// The holders of `a` as a rotation by `who` boxes them, and what it records of the holder
/// actors it leaves out (`super::recipients`).
pub(crate) struct Boxing {
    pub(crate) holders: Vec<Recipient>,
    pub(crate) left_out: osis_keys::LeftOut,
}

/// What a rotation of `a` by `who` records of holder actor `m`, holding `role`, that it boxes
/// only up to `boxed` (`None`: not at all) (spec/crypto.md §4, Left out): at each role above, each
/// current keyset of `m` (held valid, listed by no other) blocked at the rotator with the causes
/// its judgement read (`super::blocking`), and the keysets `a`'s current keysets of that role
/// record already with theirs, a keyset recorded twice taking the union, less those another of
/// them descends from (a holder actor left out across rotations records its frontier, not its
/// history).
///
/// Invariant: every block has a cause, and every record names only commits the rotator's own
/// judgement read, so at a node holding them they block what they blocked at the rotator, and
/// stop where that node can show what they showed is gone (`stands`).
pub(crate) fn left_out(tx: &mut Tx<'_>, who: &Tid, a: &Tid, m: &Tid, role: Role, boxed: Option<Role>, out: &mut osis_keys::LeftOut) -> Result<()> {
    // the public is no holder actor: never left out (`sealing_at` boxes it whole)
    if m.is_public() {
        return Ok(());
    }
    let deps = super::departures(tx, m)?;
    for r in ROLES.into_iter().filter(|r| *r <= role && Some(*r) > boxed) {
        let mut ks: BTreeMap<Epoch, BTreeSet<CommitId>> = BTreeMap::new();
        if let Some(epochs) = tx.core.epochs(a) {
            for e in epochs.role(r).current() {
                for (q, c) in tx.core.ix.keysets.get(&(*a, r, e)).and_then(|x| x.left_out.get(m)).into_iter().flatten() {
                    ks.entry(*q).or_default().extend(c.iter().copied());
                }
            }
        }
        let held = keysets_of(tx, m, r, None)?;
        // current as `rekey_due` reads it: a foreign keyset a rotation carries is superseded
        // where this node holds that rotation's secret
        let view = tx.core.epochs(m);
        let current: Vec<Epoch> = held.valid.keys().filter(|q| !held.valid.values().any(|l| l.contains(q)) && !view.as_ref().is_some_and(|v| v.role(r).superseded(q))).copied().collect();
        for k in current {
            if let Some((_, causes)) = super::blocking(tx, who, m, r, &k, &deps, super::Walk::Encrypt)? {
                ks.entry(k).or_default().extend(causes);
            }
        }
        if ks.is_empty() {
            continue;
        }
        let frontier: BTreeMap<Epoch, BTreeSet<CommitId>> = ks.iter().filter(|(q, _)| !ks.keys().any(|x| x != *q && held.descends(x, q))).map(|(q, c)| (*q, c.clone())).collect();
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
        .map(|(k, b)| (k.holder.0, osis_keys::box_keysets(b)))
        .collect())
}

/// The box clauses of `a`'s epoch `e` of role `r` (spec/crypto.md §4, Encrypting under), with
/// their causes (Left out), `None` when none holds: a stale box (rule 2), a box to a holder
/// actor that a held valid `secrets.0` body of `a` puts at `e` (`Indexes::boxed`: whatever later
/// bodies write at its key, so a rotation foreign here removing it hides nothing) naming a
/// keyset of it held invalid, tainted, or listed by a held valid keyset of it; or a box so
/// naming a keyset `a` leaves its holder out at (`left_out_at`). The causes: each listing keyset's rotation commit, the invalid rotation
/// commits of a keyset held invalid, each keyless grant behind a taint, each left-out record's
/// causes.
pub(crate) fn box_blocked(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<Option<BTreeSet<CommitId>>> {
    let mut named: Vec<(Tid, Epoch)> = boxed_keysets(tx, a, r, e)?.into_iter().flat_map(|(m, ks)| ks.into_iter().map(move |k| (m, k))).collect();
    named.extend(tx.core.ix.boxed.get(&(*a, r, *e)).into_iter().flat_map(|x| x.keysets.iter().flat_map(|(m, ks)| ks.iter().map(move |k| (*m, *k)))));
    named.sort();
    named.dedup();
    let (mut hit, mut causes) = (false, BTreeSet::new());
    let mut outs: BTreeMap<Tid, BTreeMap<Epoch, BTreeSet<CommitId>>> = BTreeMap::new();
    for (m, k) in named {
        let held = keysets_of(tx, &m, r, Some(&k))?;
        let tainted = tainted(tx, &m, r)?;
        if osis_keys::stale(&k, &held, &tainted) {
            hit = true;
            for (j, _) in held.valid.iter().filter(|(_, l)| l.contains(&k)) {
                causes.extend(keyset_commit(tx.core, &m, r, j));
            }
            if held.invalid.contains(&k) {
                causes.extend(invalid_writers(tx.core, &m, r, &k));
            }
            if tainted.contains(&k) {
                causes.extend(keyless_causes(tx.core, &m));
            }
        }
        if let std::collections::btree_map::Entry::Vacant(v) = outs.entry(m) {
            v.insert(left_out_at(tx, a, &m, r)?);
        }
        if let Some(c) = outs.get(&m).and_then(|o| o.get(&k)) {
            hit = true;
            causes.extend(c.iter().copied());
        }
    }
    Ok(hit.then_some(causes))
}

/// Whether `a`'s epoch `e` of role `r` boxes a holder past its key access to `a`, by a box of
/// its `secrets.0` state (spec/crypto.md §4, rule 4: a node that may rotate `a` re-keys while a
/// current epoch does), with the causes (Left out: the keyless grants' edge writes); `None`
/// when it does not.
pub(crate) fn keyless_at(tx: &mut Tx<'_>, a: &Tid, r: Role, e: &Epoch) -> Result<Option<BTreeSet<CommitId>>> {
    Ok(tainted(tx, a, r)?.contains(e).then(|| keyless_causes(tx.core, a)))
}

/// The edge writes of the keyless grants on `a` (spec/crypto.md §4, Left out: a taint's or a box
/// past key access's cause), each as the write that began its standing.
fn keyless_causes(core: &Core, a: &Tid) -> BTreeSet<CommitId> {
    let mut out = BTreeSet::new();
    let Some(on) = core.timelines().on(a) else { return out };
    for (h, p) in on.standing_since() {
        if key_access(core).contains(&(*a, h)) {
            out.extend(p.map(|p| p.commit));
        }
    }
    out
}

/// The held rotation commits of the keysets the boxes `w` writes to holder actors name, and those
/// the keysets `keys` writes record holder actors were left out at (spec/crypto.md §4, Carried),
/// with the demotions each of those carries (Carried demotions), and the held causes those
/// keysets record (Left out): logged under `a`'s sync IDs with the commit carrying `w`.
pub(crate) fn carried(core: &Core, w: &osis_keys::SecretsWrite, keys: Option<&osis_keys::KeysWrite>) -> Vec<osis_base::CommitId> {
    let boxed = w.boxes.iter().flat_map(|(k, b)| osis_keys::box_keysets(b).into_iter().map(|e| (k.holder, k.role, e)));
    let out = keys.into_iter().flat_map(|k| k.keysets.iter()).flat_map(|(r, ks)| ks.left_out.iter().flat_map(move |(m, xs)| xs.keys().filter_map(move |x| Some((*m, *r, osis_keys::aspects::from_schema(x).ok()?)))));
    // the causes the keysets record (Left out), each held
    let causes: Vec<CommitId> = keys.into_iter().flat_map(|k| k.keysets.values()).flat_map(|ks| ks.left_out.values().flat_map(|xs| xs.values().flatten().copied())).filter(|c| core.cause_held(c)).collect();
    let mut out: Vec<osis_base::CommitId> = boxed
        .chain(out)
        .flat_map(|(m, r, e)| {
            let carries = core.keyset(&m.0, r, &e).into_iter().flat_map(|x| x.demotions.iter().copied());
            core.ix.epoch_intro.get(&(m.0, r, e)).map(|x| x.1).into_iter().chain(carries).collect::<Vec<_>>()
        })
        .chain(causes)
        .collect();
    out.sort();
    out.dedup();
    out
}
