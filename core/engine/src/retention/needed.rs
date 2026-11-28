//! What the node holds of a thing outside its node closure (spec/commits.md §5 What a held thing
//! needs, spec/permissions.md §4; `Holding`, the one rule a pass end and a release both judge
//! by): its certificates alone (its record, its role-class parts, its secrets; all of a key
//! actor, its card) while something held needs it, never its content, whether or not it was
//! ever in the node closure; nothing once nothing does. So another account's chain (its record,
//! its `keys.0` commits, its inbox's) and a released thing's record and role-class state stay
//! only while needed. Its certificates stay while a thing that needs it is kept: one in the node closure whose
//! current values hold a strong to it (`refs::to`, ephemeral aspects included) or whose held
//! history does (`refs::kept`, held fires included; a weak only points and needs nothing), one in the node closure holding a card of it or naming it
//! its inbox, one whose record names it mint admin, one
//! whose held edge write names it holder (`Held::named_on`), one a held commit acting as it writes on
//! (`Indexes::by_actor`), one a pending commit it authored or acted
//! in, or first awaiting its record, writes on (`Indexes::pend_by`),
//! one in the node closure a held commit on it has a part missing on (`Meta::missing_parts`: a
//! part the node fetches again).
//! A thing is rooted, kept for itself (`Root`): held (in the node closure
//! or leaving it), a retained copy, a thing an own self-removal still waits to seal under, or a
//! thing whose record what waits under Pending storage awaits (nothing on it applies before its
//! record: what came for it pends, kept while carried, `apply::carriers`).
//! Keys held here root nothing: the node itself is needed by its node root (its mint admin), and
//! a link being redeemed keeps its sync ID in the sync set, so what a pass end drops of K comes
//! again with the next pass, and the join is written once a pass brought what it needs
//! (`Engine::redeemable`). Nothing is rooted by whose it is: a thing minted with the node as admin
//! goes as any once released. Everything else goes whole, as never
//! received, when the pass that brought it ends or its last need went (`settle`).
//!
//! An arrival is judged once the pass in flight ends (`Engine::settle_needs`): a thing whose
//! record was learned (`apply::atomic::learn_record`), that a commit that pends awaits
//! (`apply::set_pending`), or outside the node closure a content part on which is newly held
//! (`Core::put_meta`) is noted in `Core::pass_due` until then, so a parent's record arriving
//! before what needs it stays. A lost need waits for nothing but a pass in flight: a thing that
//! lost one (a strong row, a `keys.0` row naming it an inbox or a card gone, durable or ephemeral, `refs::note`; a signer's commit
//! leaving pending; the last held commit acting as it gone, `apply::unindex`; a
//! commit's part no longer missing, `Core::note_on`; a holder unnamed, `Held::take_unnamed`; the
//! last held vertex no longer following its strong) is noted in `Core::lost_due`, judged at a pass's end or, with
//! none in flight, at once (`Engine::settle_lost`). A release judges what it released, and what
//! each was named holder on, in its own transaction
//! (`Engine::released`). Either way at the end of a transaction (`Engine::run`, in turn with
//! destructions, on the node closure settled). The judgement walks the needs up from the thing
//! (`search`) and stops at the first rooted one, so it costs O(1) while the thing is needed and
//! the unrooted things reached when it is not, which go together: needs may form cycles (holder
//! actors granted on each other).

use crate::engine::{Core, Engine, Tx};
use crate::error::Result;
use osis_base::Tid;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// A pass ended (sync: every connected peer's pass in flight; a test: a delivery batch): what
    /// arrived outside the node closure or lost a need since the last call and nothing held needs
    /// goes (spec/commits.md §5 What a held thing needs), as at a release. The first call after an
    /// open judges every held record and every record a pending commit awaits, as an open keeps
    /// no list of what arrived. O(what arrived). First the stale cards the pass moved are written
    /// again (`refresh_cards`), and this node's dial entry where missing (`refresh_reach`).
    pub fn settle_needs(&mut self) -> Result<()> {
        // the cards the pass moved are rewritten where stale, from what it brought; this node's
        // dial entry goes on the things it names that the pass brought
        self.refresh_cards()?;
        self.refresh_reach()?;
        // what waits on a thing it brought counts as never received from now (`Core::brought`)
        self.core.brought.clear();
        let mut due: BTreeSet<Tid> = match self.core.pass_due.replace(BTreeSet::new()) {
            Some(a) => a,
            None => {
                let awaited = self.core.ix.pend_on.keys().filter_map(|w| if let crate::apply::Wake::Record(t) | crate::apply::Wake::Enters(t) = w { Some(*t) } else { None });
                self.core.ix.held.things().copied().chain(awaited).collect()
            }
        };
        due.append(&mut self.core.lost_due);
        let r = self.settle_due(&due);
        // judged again at the next pass's end
        if r.is_err() {
            for t in due {
                self.core.note_pass_due(t);
            }
        }
        r
    }

    /// No pass is in flight (sync: none begun and not ended): what lost a need since the last
    /// judgement and nothing held needs goes, as at a pass end. A lost need waits for nothing;
    /// an arrival waits for the pass that brought it (a parent's record before what needs it),
    /// so one also arrived since (`Core::pass_due`) waits for that pass. After an open no pass is
    /// in flight, what arrived before it came by a pass the open ended: every held record is
    /// judged as at the first pass end (`settle_needs`), else what was leaving at a crash (no
    /// open keeps that) would wait for a pass an idle node never ends. What a sealed fire
    /// brought came whole with it, by no pass, and is judged here (`Core::note_pass_due`). First
    /// the stale cards are written again (`refresh_cards`), as at a pass end: an own write moving
    /// `keys.0` (a rotation, a removal) ends no pass. O(what lost a need and the cards due), and
    /// O(held) once after an open.
    pub fn settle_lost(&mut self) -> Result<()> {
        if self.core.pass_due.is_none() {
            return self.settle_needs();
        }
        self.refresh_cards()?;
        let Some(arrived) = &self.core.pass_due else { return Ok(()) };
        let due: BTreeSet<Tid> = self.core.lost_due.difference(arrived).copied().collect();
        if due.is_empty() {
            return Ok(());
        }
        self.core.lost_due.retain(|t| !due.contains(t));
        let r = self.settle_due(&due);
        if r.is_err() {
            self.core.lost_due.extend(due);
        }
        r
    }

    /// `due` judged: those outside the node closure nothing held needs go.
    pub(crate) fn settle_due(&mut self, due: &BTreeSet<Tid>) -> Result<()> {
        // scale checks: a pass end reads what is due, not what is held
        osis_base::costs::count("needed: things due", due.len() as u64);
        let cl = &self.core.ix.closure;
        let due: Vec<Tid> = due.iter().filter(|t| !cl.holds(t)).copied().collect();
        if due.is_empty() {
            return Ok(());
        }
        // judged in a read first: a pass that leaves only what is held writes nothing
        let goes = self.read(|tx| {
            for t in &due {
                if excess(tx, t)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })?;
        if !goes {
            return Ok(());
        }
        self.run(|tx| {
            tx.core.needs_due.extend(due.iter().copied());
            Ok(())
        })
    }
}

/// What the node holds of a thing (spec/commits.md §5 What a held thing needs): the one rule
/// both a pass end and a release judge by (`settle`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holding {
    /// All of it: in the node closure or leaving it and not released yet, or a retained copy.
    Whole,
    /// Its certificates alone (its record, role-class parts and secrets, `forget::content`
    /// not): a held thing needs it, or an own self-removal from it waits to be sealed.
    Certificates,
    /// Nothing: it goes whole, with `reached`, every thing needing it (`search`).
    Nothing,
}

/// What the node holds of `t` (`Holding`), by its state alone: never by what arrived when.
/// `reached` as `search` leaves it.
pub(crate) fn holding(tx: &mut Tx<'_>, t: &Tid, reached: &mut Reached) -> Result<Holding> {
    Ok(match search(tx, t, reached)? {
        Some((x, Root::Held | Root::Copy(_))) if x == *t && whole(tx.core, t) => Holding::Whole,
        Some(_) => Holding::Certificates,
        None => Holding::Nothing,
    })
}

/// Whether the node holds a content part on `t` (`forget::content`): what a thing held as
/// certificates loses. O(the commits on `t`).
pub(crate) fn holds_content(core: &Core, t: &Tid) -> bool {
    core.aspects_of(t).filter(|((_, ak), _)| super::forget::content(ak)).any(|((_, ak), cs)| cs.iter().any(|(_, c)| core.ix.commits.get(c).is_some_and(|m| m.aspect(t, ak).is_some_and(|ai| m.holds(ai)))))
}

/// Whether a part on `(t, ak)` applies here (spec/commits.md §4 Outside the node closure): it is
/// no content (`forget::content`), or `t` is held whole (`whole`). Else it waits for `t` to enter
/// (`apply::Reason::Outside`).
pub(crate) fn applies_on(core: &Core, t: &Tid, ak: &osis_base::Ak) -> bool {
    !super::forget::content(ak) || whole(core, t)
}

/// Whether the node holds `t` whole, so content on it applies (spec/commits.md §4 Outside the
/// node closure, spec/permissions.md §3 Lost access): the node closure reads it (`Closure::reads`:
/// in the local part or a read sync unit, held or leaving), or it is a retained copy. Invariant:
/// content applies on a thing only where the node's roles read it now. Whatever blob carries a
/// part, under whichever sync ID, opened by whichever held secret (a section a thing that became
/// independent left under its mint admin's epochs, readable by that admin's readers after it no
/// longer reads the thing), and whenever it arrives against a loss, a thing kept unread or outside the node closure takes none of its content.
pub(crate) fn whole(core: &Core, t: &Tid) -> bool {
    core.ix.closure.reads(t) || super::forget::copy_of(core, t).is_some()
}

/// Whether the node holds a part on `(t, ak)` once it arrives: `t`'s record is held and the part
/// applies (`applies_on`). Such a part missing keeps its commit's header (spec/commits.md §5 A
/// released thing).
pub(crate) fn takes_part(core: &Core, t: &Tid, ak: &osis_base::Ak) -> bool {
    core.created(t).is_some() && applies_on(core, t, ak)
}

/// Whether the node holds the commit minting `t` (a held `created.0` part on it): then it judges
/// which sync units hold `t` by its own view (spec/commits.md §4 Pending storage, Outside the
/// node closure). Until then a strong bringing `t` in may come with its record in one transaction
/// (the commit minting it), which pulls nothing anew (spec/sync-judgement.md §3 Dropped bodies),
/// so what waits on `t` is kept while carried. O(the commits on `t`'s `created.0`).
pub(crate) fn minted_here(core: &Core, t: &Tid) -> bool {
    let Ok(ak) = osis_base::Ak::new("created.0") else { return false };
    core.ix.by_aspect.get(&(*t, ak.clone())).is_some_and(|cs| cs.iter().any(|(_, c)| core.ix.commits.get(c).is_some_and(|m| m.aspect(t, &ak).is_some_and(|ai| m.holds(ai)))))
}

/// Whether parts wait on `t` to enter the node closure that no sync ID the node syncs carries
/// (spec/commits.md §4 Pending storage): `t` is not held whole and the node judges it in no sync
/// unit (`minted_here`; a unit holds only things of the node closure). They count as never
/// received once the pass that brought them ends (`settle`).
pub(crate) fn uncarried(core: &Core, t: &Tid) -> bool {
    core.ix.pend_on.contains_key(&crate::apply::Wake::Enters(*t)) && !whole(core, t) && minted_here(core, t)
}

/// Whether the node holds more of `t` than `holding` allows.
fn excess(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    if !holds_any(tx.core, t) {
        return Ok(false);
    }
    if uncarried(tx.core, t) {
        return Ok(true);
    }
    Ok(match holding(tx, t, &mut Reached::new())? {
        Holding::Whole => false,
        Holding::Certificates => holds_content(tx.core, t),
        Holding::Nothing => true,
    })
}

/// Why a thing is kept for itself (the module doc, `rooted`).
#[derive(Clone, Debug)]
pub(crate) enum Root {
    /// In the node closure, or leaving it and not released yet.
    Held,
    /// A retained copy (`rotation::lost`) under this kept actor, itself or the secret actor it is
    /// a copy under (`forget::copy_of`).
    Copy(Tid),
    /// An own self-removal from it waits to be sealed under its sync IDs.
    SelfRemoval(osis_base::CommitId),
    /// What waits under Pending storage awaits its record or its entry into the node closure
    /// (`apply::awaited`): nothing on it applies before its record, nor content before it
    /// enters, so what came for it pends, kept while carried. An entry is awaited only until the
    /// node holds the commit minting it (`uncarried`).
    Awaited,
}

/// Why `x` needs `t` held (the module doc, `needs`).
#[derive(Clone, Debug)]
pub(crate) enum Need {
    /// `t` is named holder on `x` by a held edge write (`Held::named_on`).
    Holder,
    /// A pending commit `t` signed, or one awaiting `t`'s record first, writes on `x`.
    Pending(osis_base::CommitId),
    /// A held commit acting as `t` writes on `x`: `t`'s record judges it.
    Acting(osis_base::CommitId),
    /// `x` is in the node closure and a held commit on `t` has a part missing on it.
    Missing(osis_base::CommitId),
    /// `x` is in the node closure and its aspect holds a strong to `t`.
    Strong(osis_base::Ak),
    /// `x` is in the node closure and a card on it is of `t` or names `t` its inbox
    /// (spec/sync-inbox.md §1 Card): their keys, which a granter seals to.
    Card,
}

/// Why `t` is kept for itself (the module doc), if it is.
pub(crate) fn rooted(core: &Core, t: &Tid) -> Option<Root> {
    let cl = &core.ix.closure;
    if cl.holds_any(t) || cl.left().contains_key(t) {
        return Some(Root::Held);
    }
    if let Some(a) = super::forget::copy_of(core, t) {
        return Some(Root::Copy(a));
    }
    if core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*t)) || (core.ix.pend_on.contains_key(&crate::apply::Wake::Enters(*t)) && !minted_here(core, t)) {
        return Some(Root::Awaited);
    }
    // an own self-removal from it waits to be sealed under its sync IDs (`sync::held::wait_if_own`)
    core.ix.held_wait.iter().find(|c| core.ix.commits.get(c).is_some_and(|m| m.view.aspect(t, "roles.0").is_some())).map(|c| Root::SelfRemoval(*c))
}

/// The things that need `t` held (the module doc), but `t`, each with why (one thing may come
/// more than once): those naming it, those in the node closure whose state holds a strong to it
/// (`refs::to`), those holding a card of it or of a thing naming it its inbox, those a
/// pending commit it signed or whose first awaited record it is (`Indexes::pend_by`) writes on
/// (a record only another part awaits is due once the commit pends on it), and, in the node
/// closure, those a held commit on it has a part missing on and those an edge write on it names
/// holder. The rule (`holding`) and the explainer (`Engine::why_kept`)
/// both read it.
pub(crate) fn needs(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<(Tid, Need)>> {
    let core = &*tx.core;
    // a pending commit it signed or whose record it awaits first (`pend_by`), on the things it
    // writes on (`Wake::Thing`), as if held
    let pending = core.ix.pend_by.get(t).into_iter().flatten().flat_map(|c| core.ix.pend_keys.get(c).into_iter().flat_map(|ws| ws.iter()).filter_map(move |w| if let crate::apply::Wake::Thing(x) = w { Some((*x, Need::Pending(*c))) } else { None }));
    // a held commit on it still waiting for a part (counted missing), by the things the node
    // closure holds those parts are on (spec/commits.md §5: one the node fetches again): what
    // arrives there may reference it, and the commit stays whole for it
    let waiting = core.on_thing(t).flat_map(|c| core.ix.commits.get(&c).into_iter().flat_map(move |m| m.missing_parts().filter_map(move |ai| m.view.aspects.get(ai).map(|a| (a.tid, Need::Missing(c)))))).filter(|(x, _)| core.ix.closure.holds(x));
    // a held commit naming it as purge author (a member of its path, `apply::header_wait`), on the
    // things it writes on: its path lists it, so its record judges the commit (spec/commits.md §4
    // Unjudgeable)
    let acting = core.acting_for(t).flat_map(|c| core.ix.commits.get(&c).into_iter().flat_map(move |m| m.view.aspects.iter().map(move |a| (a.tid, Need::Acting(c)))));
    let mut out: Vec<(Tid, Need)> = core.ix.held.named_on(t).map(|x| (*x, Need::Holder)).chain(pending).chain(acting).chain(waiting).collect();
    // a strong from a thing the node closure holds (a weak only points; one kept only
    // as a certificate needs nothing by what its state names)
    let refs = crate::engine::refs::to(tx, t)?;
    // a strong in a held body of a thing whose history holds its targets (`refs::kept`)
    let kept = crate::engine::refs::kept::to(tx, t)?;
    let core = &*tx.core;
    out.extend(kept.into_iter().filter(|(s, _)| core.ix.closure.holds(s)).map(|(s, ak)| (s, Need::Strong(ak))));
    for r in refs {
        if crate::engine::refs::holds_target(r.kind, &r.ak) && core.ix.closure.holds(&r.source) {
            out.push((r.source, Need::Strong(r.ak)));
        }
    }
    // its own cards on things the node closure holds
    for (h, _) in crate::flows::cards::cards_of(tx, t)? {
        if tx.core.ix.closure.holds(&h) {
            out.push((h, Need::Card));
        }
    }
    // the card aspects there of the things naming it their inbox (a card carries its inbox's keys)
    for a in crate::flows::cards::naming_inbox(tx, t)? {
        let hosts = tx.core.ix.aspect_things.get(&osis_schema::core_types::card_ak(&a)).into_iter().flatten().filter(|h| tx.core.ix.closure.holds(h));
        out.extend(hosts.map(|h| (*h, Need::Card)));
    }
    out.retain(|(x, _)| x != t);
    Ok(out)
}

/// What `search` reached: each thing with the thing it needs and why (`None` for the start).
pub(crate) type Reached = BTreeMap<Tid, Option<(Tid, Need)>>;

/// Walks the needs up from `t` (`needs`), breadth first, to the first rooted thing: that thing
/// and why it is rooted, its chain to `t` in `reached`. `None` when nothing rooted needs `t`,
/// through any chain of needs: `reached` then holds `t` and every thing needing it, none rooted.
pub(crate) fn search(tx: &mut Tx<'_>, t: &Tid, reached: &mut Reached) -> Result<Option<(Tid, Root)>> {
    reached.insert(*t, None);
    let mut todo = std::collections::VecDeque::from([*t]);
    while let Some(x) = todo.pop_front() {
        if let Some(r) = rooted(tx.core, &x) {
            return Ok(Some((x, r)));
        }
        for (y, why) in needs(tx, &x)? {
            if let std::collections::btree_map::Entry::Vacant(e) = reached.entry(y) {
                e.insert(Some((x, why)));
                todo.push_back(y);
            }
        }
    }
    Ok(None)
}

/// Whether anything of `t` is held: its record, a commit on it, its secrets, or a pending part
/// awaiting its record or its entry.
pub(crate) fn holds_any(core: &Core, t: &Tid) -> bool {
    core.created(t).is_some() || core.on_thing(t).next().is_some() || core.ix.secrets.get(t).is_some() || crate::apply::awaited(core, t)
}

/// Judges the things due (`Core::needs_due`) by what the node holds of each (`holding`): one
/// held as certificates loses its content as never received (`forget::Scope::Local`), and every
/// one nothing rooted needs goes, with what only it kept, whole, as never received
/// (`forget::Scope::Whole`), its secrets, record and role arrival with it. Whether anything
/// went: what it named and signed is due in turn.
pub(crate) fn settle(tx: &mut Tx<'_>) -> Result<bool> {
    let due = std::mem::take(&mut tx.core.needs_due);
    // what waits on a thing no synced sync ID carries counts as never received (`uncarried`)
    for t in &due {
        if uncarried(tx.core, t) {
            crate::apply::unreceive_outside(tx, t)?;
        }
    }
    let mut gone: BTreeSet<Tid> = BTreeSet::new();
    let mut content: BTreeSet<Tid> = BTreeSet::new();
    for t in due {
        if gone.contains(&t) || !holds_any(tx.core, &t) {
            continue;
        }
        let mut reached = Reached::new();
        let h = holding(tx, &t, &mut reached)?;
        // scale checks: a pass end judges the things due, each searching what needs it
        osis_base::costs::count("needed: things judged", 1);
        osis_base::costs::count("needed: things searched", reached.len() as u64);
        match h {
            Holding::Whole => {}
            Holding::Certificates => {
                if holds_content(tx.core, &t) {
                    content.insert(t);
                }
            }
            Holding::Nothing => gone.extend(reached.into_keys()),
        }
    }
    content.retain(|t| !gone.contains(t));
    osis_base::costs::count("needed: things stripped", content.len() as u64);
    super::forget::forget(tx, super::forget::Scope::Local(&content), &BTreeMap::new())?;
    gone.retain(|t| holds_any(tx.core, t));
    if gone.is_empty() {
        return Ok(!content.is_empty());
    }
    osis_base::costs::count("needed: things dropped", gone.len() as u64);
    // the things whose entries their records and secrets may have opened, found before they go
    let opened = crate::retention::forget::deriving_from(tx.core, &gone);
    // what waits on a thing going whole goes with it, as never received
    for t in &gone {
        crate::apply::unreceive_outside(tx, t)?;
    }
    // the role commits with a part on them
    let core = &*tx.core;
    let roles: BTreeSet<osis_base::CommitId> = gone.iter().flat_map(|t| core.ix.held.commits_on(t).iter().map(|c| c.id).chain(core.on_thing(t).filter(|c| core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_role())))).collect();
    // what they noted of each such commit's parts on them goes with the parts: the holders their
    // `roles.0` entries keyed (as a destruction's, `destroy::destroy_thing`), the boxes their
    // `secrets.0` bodies wrote (`Indexes::boxes_to`, `keys::forget_dropped`)
    let mut boxes = Vec::new();
    for id in &roles {
        let Some(m) = tx.core.ix.commits.get(id).cloned() else { continue };
        crate::apply::validity::unkey_holders(tx, id, &|t| gone.contains(t))?;
        for (ai, a) in m.header.aspects.iter().enumerate() {
            if a.ak.as_str() == "secrets.0" && gone.contains(&a.tid) && m.holds(ai) {
                let body = crate::apply::held_fragment(tx, id, ai)?;
                boxes.push((m.header.clone(), ai, body.into_iter().collect::<Vec<_>>()));
            }
        }
    }
    super::forget::forget(tx, super::forget::Scope::Whole(&gone), &BTreeMap::new())?;
    for (h, ai, bodies) in boxes {
        crate::apply::keys::forget_dropped(tx, &h, ai, &bodies)?;
    }
    // perm's held set reads each such commit left without its parts on them (one gone whole
    // left it with its record, `apply::unindex`)
    for id in roles {
        let Some((view, path)) = tx.core.ix.commits.get(&id).map(|m| (m.view.clone(), m.header.path.clone())) else { continue };
        let parts = crate::apply::perm_parts(tx, &id)?;
        crate::apply::validity::hold_role_commit(tx.core, &view, &path, &id, &parts);
        crate::engine::index::put_perm(tx, &id, &parts, Shred::Yes)?;
    }
    for t in &gone {
        super::destroy::note(tx, t, false)?;
        crate::sync_ids::opened::forget_thing(tx, t)?;
        // its keyset notes go with it, though a held commit keeps its other parts
        let keyed: Vec<osis_base::CommitId> = tx.core.ix.keyset_parts.get(t).into_iter().flatten().copied().collect();
        for id in keyed {
            tx.core.ix.keyset_parts.remove(t, &id);
            tx.txn.remove_local(&crate::engine::records::own_secrets_key(t, &id), Shred::Yes)?;
        }
        tx.core.ix.independent.remove(t);
        tx.core.ix.secrets.remove(t);
        crate::sync_ids::unread::forget(tx, t)?;
        crate::sync::stranded::drop_asks(tx, t, |_| false)?;
        crate::sync::held::forget_actor(tx, t)?;
        crate::flows::inbox::drop_fires_on(tx, t)?;
        if tx.core.created(t).is_some() {
            tx.txn.remove_local(&[crate::engine::records::CREATED, t.as_bytes()].concat(), Shred::Yes)?;
            tx.core.ix.held.forget_record(t);
            tx.core.tree_reach.remove(t);
            crate::rotation::merge::forget(tx, t)?;
        }
    }
    tx.core.update_timelines();
    // the paths their records and secrets opened, decided again without them
    crate::apply::paths::openers_gone(tx, &opened)?;
    crate::apply::rejudged(tx, true)?;
    Ok(true)
}
