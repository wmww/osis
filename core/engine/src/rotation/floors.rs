//! Floors (spec/crypto.md §4, Floors): what a holder granted without history may be handed. A
//! party's floor on an actor is its newest grant's (a cut's n; a grant with history, its
//! author's), the least over the paths it reaches the actor by; the read role of an actor's view
//! reads each epoch's floor from its opened history entries and each maker's from its grant.
//!
//! Invariant (the property every rule here serves): no secret of an epoch below a holder's floor
//! reaches it from a box or history entry an honest node writes. A box goes only to a holder whose
//! floor the epoch's floor reaches (`RoleEpochs::allows`); an entry at e carries f only when f's
//! floor reaches e's and e's maker's (`RoleEpochs::carries`): every epoch below a cut has a floor
//! below the cut's n (floors never exceed n, n grows along every supersedes chain), so neither
//! hands it to a holder of the cut's floor, nor to a maker that wrote a low floor.

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{Role, Tid};
use osis_keys::ActorEpochs;
use std::collections::{BTreeMap, BTreeSet};

/// `p`'s floor on `a` (spec/crypto.md §4, A party's floor): its edge in force there (its floor,
/// at least its author's: a party hands no history it was not given) and its floor through each
/// holder actor of `a` it reads for keys, the least of them; 0 holding `a` by none.
pub(crate) fn party_floor(core: &Core, a: &Tid, p: &Tid) -> u64 {
    if !any_floor(core, a) {
        return 0;
    }
    floor_in(core, a, p, &mut BTreeSet::new())
}

/// `party_floor` where `a`'s view (`Core::epochs`) reads floors, else 0 at once: what a write path
/// asks per holder, so an actor never cut pays nothing per holder.
pub(crate) fn holder_floor(core: &Core, a: &Tid, p: &Tid) -> u64 {
    match core.epochs(a).is_some_and(|e| e.read.has_floors()) {
        true => floor_in(core, a, p, &mut BTreeSet::new()),
        false => 0,
    }
}

/// Whether some edge on `a` in force carries a floor: else every party's is 0.
fn any_floor(core: &Core, a: &Tid) -> bool {
    core.timelines.on(a).is_some_and(|on| on.holders().iter().any(|(_, e)| e.floor.is_some()))
}

/// `party_floor`, `seen` the parties on the way (a cycle of grants reads as the greatest of its
/// written floors: the least fixpoint).
fn floor_in(core: &Core, a: &Tid, p: &Tid, seen: &mut BTreeSet<Tid>) -> u64 {
    if !seen.insert(*p) {
        return 0;
    }
    let Some(on) = core.timelines.on(a) else { return 0 };
    let mut paths = Vec::new();
    if let Some(e) = on.edge_at(p, None) {
        let author = on.in_force(p).and_then(|c| core.ix.commits.get(&c)).map(|m| m.view.author).filter(|x| x != p);
        let by = author.map_or(0, |x| floor_in(core, a, &x, &mut seen.clone()));
        paths.push(e.floor.unwrap_or(0).max(by));
    }
    let actors: Vec<Tid> = on.holders().into_iter().map(|(h, _)| h).filter(|h| h != p && !core.is_key_actor(h)).collect();
    for h in actors {
        if super::members::role_for_keys(core, p, &h).is_some_and(|r| r >= Role::Read) {
            paths.push(floor_in(core, a, &h, &mut seen.clone()));
        }
    }
    paths.into_iter().min().unwrap_or(0)
}

/// Sets the read floors of `view`, `a`'s epochs as this node holds them (`RoleEpochs::set_floors`,
/// each epoch's own floor read from its opened history entries): its maker's floor (the author of its
/// rotation commit; unknown, as for an epoch held by a snapshot alone: the greatest floor of any
/// holder, every maker it could be), and this node's own.
pub(crate) fn set(core: &Core, a: &Tid, view: &mut ActorEpochs) {
    // no party has a floor: no rule has anyone to keep anything from (actors never cut pay nothing)
    if !any_floor(core, a) {
        return;
    }
    let re = view.role(Role::Read);
    let epochs: Vec<osis_crypto::Epoch> = re.epochs().map(|(e, _)| *e).collect();
    let mut makers = BTreeMap::new();
    let mut unknown = None;
    for e in &epochs {
        let author = core.ix.epoch_intro.get(&(*a, Role::Read, *e)).and_then(|(_, c)| core.ix.commits.get(c)).map(|m| m.view.author);
        let f = match author {
            Some(x) => party_floor(core, a, &x),
            None => *unknown.get_or_insert_with(|| greatest(core, a)),
        };
        makers.insert(*e, f);
    }
    let own = core.account.get().map_or(0, |p| party_floor(core, a, &p));
    view.role_mut(Role::Read).set_floors(makers, own);
}

/// The greatest floor of a holder of `a`.
fn greatest(core: &Core, a: &Tid) -> u64 {
    let Some(on) = core.timelines.on(a) else { return 0 };
    let holders: Vec<Tid> = on.holders().into_iter().map(|(h, _)| h).collect();
    holders.iter().map(|h| party_floor(core, a, h)).max().unwrap_or(0)
}

/// The read epochs the rotation of `x`'s newest removal from `a` listed, of those `view` holds
/// (spec/crypto.md §4, Floors: re-added without history): what `x`'s earlier nodes read before it
/// left. Empty without an applied removal of `x`, or when it went without its rotation. `before`:
/// only a removal ordered before that point (the re-add's grant).
pub(crate) fn removal_listed(core: &Core, a: &Tid, x: &Tid, view: &ActorEpochs, before: Option<osis_perm::Point>) -> BTreeSet<osis_crypto::Epoch> {
    let Some(on) = core.timelines.on(a) else { return BTreeSet::new() };
    let rm = on
        .applied()
        .filter(|(c, o)| o.holder == *x && o.edge.is_none_or(|e| e.says_retain()) && before.is_none_or(|p| c.point() < p))
        .max_by_key(|(c, _)| c.point())
        .map(|(c, _)| c.id);
    let Some(rm) = rm else { return BTreeSet::new() };
    let mut out = BTreeSet::new();
    for (e, _) in view.role(Role::Read).epochs() {
        if core.ix.epoch_intro.get(&(*a, Role::Read, *e)).is_some_and(|(_, c)| *c == rm) {
            out.extend(core.ix.keysets.get(&(*a, Role::Read, *e)).map(|k| k.lists.clone()).unwrap_or_default());
        }
    }
    out
}

/// The epochs re-added holder `x` of `a` is boxed at beside its floor (spec/crypto.md §4, Floors):
/// those its removal's rotation listed, when its grant in force is without history and follows
/// that removal; else none.
pub(crate) fn readd_epochs(core: &Core, a: &Tid, x: &Tid, view: &ActorEpochs) -> BTreeSet<osis_crypto::Epoch> {
    let Some(on) = core.timelines.on(a) else { return BTreeSet::new() };
    if !on.edge_at(x, None).is_some_and(|e| e.floor.is_some()) {
        return BTreeSet::new();
    }
    let Some(grant) = on.in_force(x).and_then(|c| on.applied().find(|(rc, _)| rc.id == c).map(|(rc, _)| rc.point())) else { return BTreeSet::new() };
    removal_listed(core, a, x, view, Some(grant))
}

/// Whether some current read epoch of `a` has a floor below that of a holder a rotation by `who`
/// would box (spec/crypto.md §4, Floors: a low floor): the boxing rule bars a re-seal of that
/// holder there, so its rotation is due instead, at the end of a complete pass. The rotation's
/// floor is the greatest of those holders' (`osis_keys::rotate`), so it settles: a fork beside a
/// cut, or a writer's low-floor epoch after it, is merged into one the holder is boxed at, whose
/// history entry carries the fork's roles secret (Roles secrets).
pub(crate) fn low_floor_due(tx: &mut Tx<'_>, who: &Tid, a: &Tid) -> Result<bool> {
    let Some(epochs) = tx.core.epochs(a).filter(|e| e.read.has_floors()) else { return Ok(false) };
    // not while it holds an epoch whose names it does not meet: it may lack a removal that epoch
    // descends from, and would box the removed holder (model `X_rmrace`)
    if epochs.read.unsuperseded().iter().any(|e| !epochs.read.is_established(e)) {
        return Ok(false);
    }
    // epochs whose secret is held: their floor is known (one held by others alone is re-sealed or
    // rotated by them)
    let Some(low) = epochs.read.current().iter().filter(|e| epochs.read.secret(e).is_some()).map(|e| epochs.read.floor(e)).min() else { return Ok(false) };
    // cheap first: no holder's floor above the lowest current epoch's
    if !tx.core.key_holders(a).iter().any(|(m, r)| *r >= Role::Read && holder_floor(tx.core, a, m) > low) {
        return Ok(false);
    }
    let boxing = super::recipients(tx, who, a, &[])?;
    Ok(boxing.holders.iter().any(|h| h.role >= Role::Read && h.floor > low))
}

/// The bodies of `(tid, ak)` held here with content whose floor (`labeling::opened::part_floor`)
/// is below `f`, or unknown where `unknown` counts them.
fn below(tx: &mut Tx<'_>, tid: &Tid, ak: &osis_base::Ak, f: u64, unknown: bool) -> Result<BTreeSet<osis_base::CommitId>> {
    let held: Vec<(osis_base::CommitId, usize)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|(_, c)| {
        let m = tx.core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        matches!(m.hold.get(ai), Some(crate::engine::Hold::Body { .. } | crate::engine::Hold::Leftover { valued: true, .. })).then_some((*c, ai))
    }).collect();
    let mut out = BTreeSet::new();
    for (c, ai) in held {
        if crate::labeling::opened::part_floor(tx, &c, ai, tid)?.map_or(unknown, |x| x < f) {
            out.insert(c);
        }
    }
    Ok(out)
}

/// Whether `(tid, ak)` is content a snapshot carries (spec/commits.md §2): no role part,
/// record, setting, addendum or signal.
fn stateful(ak: &osis_base::Ak) -> bool {
    osis_schema::core_types::is_content(ak.as_str()) && crate::retention::snapshot::compacted(ak)
}

/// State at a cut (spec/crypto.md §4): where the floor of the epoch this node seals `a`'s
/// content under (`Core::seal_epoch`) rose past what it last owed for, it owes a snapshot
/// (`retention::purge::owe_resnapshot`) of every content aspect of a thing whose secrets are
/// `a`'s holding a body written below that floor (or of unknown floor): the snapshot, sealed under
/// that epoch, carries the current state to a holder granted without history, which never opens
/// those bodies (spec/crypto.md §5 Passing on). Signals hold no state, so nothing of them goes.
/// Run by a cut's author in its grant and by every node at the end of a complete pass: a scan of
/// the aspects held here once per floor the actor's content is sealed under (a cut is rare),
/// nothing for an actor never cut. The snapshots owed for bodies that arrived late
/// (`late_part`) fall due here too: the pass brought whatever snapshots cover them (a first
/// sync fetches the bodies before the cut's snapshots, spec/crypto.md §5 Order), so a node
/// fetching history writes none of what those carry.
pub(crate) fn owe_state(tx: &mut Tx<'_>, a: &Tid) -> Result<()> {
    if !any_floor(tx.core, a) {
        return Ok(());
    }
    let late: Vec<(Tid, osis_base::Ak)> = tx.core.ix.resnapshots_owed.iter().filter(|(t, _)| tx.core.secret_actor(t) == Some(*a)).flat_map(|(t, m)| m.keys().map(|ak| (*t, ak.clone()))).collect();
    tx.core.resnapshots_due.extend(late);
    let Some((_, f)) = tx.core.seal_epoch(a) else { return Ok(()) };
    let key = [crate::engine::records::CUT_SETTLED, a.as_bytes().as_slice()].concat();
    let settled = tx.txn.get_local(&key)?.and_then(|v| v.try_into().ok()).map_or(0, u64::from_le_bytes);
    if f <= settled {
        return Ok(());
    }
    let aspects: Vec<(Tid, osis_base::Ak)> = tx.core.ix.by_aspect.keys().filter(|(t, ak)| stateful(ak) && tx.core.secret_actor(t) == Some(*a)).cloned().collect();
    for (t, ak) in aspects {
        let held = below(tx, &t, &ak, f, true)?;
        if !held.is_empty() {
            crate::retention::purge::owe_resnapshot(tx, &t, &ak, held, true)?;
        }
    }
    tx.txn.put_local(&key, &f.to_le_bytes(), osis_store::Shred::No)?;
    Ok(())
}

/// State at a cut, for part `ai` of commit `c` (header `h`) applied here: one opened under an
/// epoch whose floor is below the one this node seals its thing under (written beside the cut,
/// or arriving late) owes a snapshot of its aspect, due at the end of the next complete pass
/// (`owe_state`). A part of unknown floor (read
/// in no section) owes nothing here, nor does this node's own (`owe_state` judges it).
pub(crate) fn late_part(tx: &mut Tx<'_>, c: &osis_base::CommitId, h: &osis_commit::Header, ai: usize) -> Result<()> {
    let Some(x) = h.aspects.get(ai) else { return Ok(()) };
    if !stateful(&x.ak) || tx.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local) {
        return Ok(());
    }
    // the memoized view: 0 on every actor never cut, so a part pays nothing more there
    let Some((_, f)) = tx.core.seal_epoch(&x.tid) else { return Ok(()) };
    if f == 0 || !crate::labeling::opened::part_floor(tx, c, ai, &x.tid)?.is_some_and(|p| p < f) {
        return Ok(());
    }
    crate::retention::purge::owe_resnapshot(tx, &x.tid, &x.ak, BTreeSet::from([*c]), false)
}
