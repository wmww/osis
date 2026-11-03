//! Purge requests (spec/commits.md §5, spec/permissions.md §8): which held requests name a delta,
//! whether one stands, what standing drops, and judging them again as roles change.

use super::{drop_carrying, expire, reopen, snapshots_of, suspect, uncover, valueless, aspect_index, mark_deaths_due, note_carried_again, purged_changed};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Engine, Owned, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{Header, Kind, PurgeItem};
use osis_perm::Point;
use osis_schema::core_types::is_role_class;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Does purge item `item` of commit `pc` (header `p`) name aspect `ai` of commit `c` (header
/// `ch`), with its author holding the right at the request's time, and the actor it acts for too
/// (spec/permissions.md §8)? The second holds a client to its own rights in any arrival order: its
/// node's would reach a delta of the person it acts for that the node did not hold yet.
fn purge_allowed(core: &Core, p: &Header, pc: &CommitId, item: &PurgeItem, ch: &Header, c: &CommitId, ai: usize) -> bool {
    let Some(a) = ch.aspects.get(ai) else { return false };
    if is_role_class(a.ak.as_str()) || a.tid != *item.tid() || a.ak != *item.ak() {
        return false;
    }
    names(p, item, ch, c) && holds_right(core, p, pc, a, ch)
}

/// Whether purge item `item` of a commit with header `p` reaches commit `c` (header `ch`): named, on the whole aspect or
/// on its actor's deltas, and stamped before the request (spec/commits.md §5).
fn names(p: &Header, item: &PurgeItem, ch: &Header, c: &CommitId) -> bool {
    ch.ts < p.ts
        && match item {
            PurgeItem::Commit { commit, .. } => commit == c,
            PurgeItem::Aspect { .. } => true,
            PurgeItem::Author { actor, .. } => ch.purge_actor() == *actor,
        }
}

/// Whether commit `pc` (header `p`: a purge request or a compaction snapshot) holds the right over
/// delta `a` of a commit with header `ch`, at its own key (spec/permissions.md §8): its author
/// does, and the actor it acts for, neither by a role a demotion's frontier took from this commit.
/// A function of the role timeline, the void set and the headers, so any node holding them judges
/// alike, in any arrival order; `rejudge_purges` follows it when those change.
pub(super) fn holds_right(core: &Core, p: &Header, pc: &CommitId, a: &osis_commit::AspectEntry, ch: &Header) -> bool {
    if core.ix.void.contains(pc) {
        return false;
    }
    let point = Point { ts: p.ts, node: p.author, commit: *pc };
    let (by, actor) = (a.retention.by, ch.purge_actor());
    core.timelines.get(&a.tid).is_some_and(|tl| tl.purge_stands(&p.author, &a.tid, by, &actor, point) && (p.actor == p.author || tl.purge_stands(&p.actor, &a.tid, by, &actor, point)))
}

/// Whether a signer of a commit could ever hold the right of class `by` over a delta on `tid` of
/// actor `actor`: `holds_right` with roles of any validity at any time, so held inputs only widen
/// it. For what must not turn on arrival (`counts_as_purged`).
fn could_hold_right(core: &Core, who: &Tid, tid: &Tid, by: osis_base::PurgeBy, actor: &Tid) -> bool {
    (by.admin() && core.ix.held.ever_admins(tid).contains(who))
        || (by.writer() && core.ix.held.ever_writers(tid).contains(who))
        || (by.author() && (who == actor || core.ix.held.ever_writers(actor).contains(who)) && core.ix.held.ever_writers(tid).contains(actor))
}

/// Whether a request with header `p` is signed by ones that could ever hold the right over delta
/// `a` of a commit with header `ch` (`could_hold_right`).
fn signers_could(core: &Core, p: &Header, a: &osis_commit::AspectEntry, ch: &Header) -> bool {
    let (by, actor) = (a.retention.by, ch.purge_actor());
    could_hold_right(core, &p.author, &a.tid, by, &actor) && (p.actor == p.author || could_hold_right(core, &p.actor, &a.tid, by, &actor))
}

/// Whether snapshot `s` may stand for body `(tid, ak)` of `c`: its actor holds the right over it
/// (`holds_right`; spec/commits.md §5). Without it the snapshot still carries the body's live
/// writes and leaves it may-hold, but no node drops it for this snapshot. Memory class: no
/// retention to judge.
pub(crate) fn snapshot_right(core: &Core, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    let (Some(sm), Some(m)) = (core.ix.commits.get(s), core.ix.commits.get(c)) else { return false };
    if m.view.memory {
        return true;
    }
    let Some(a) = m.aspect(tid, ak).and_then(|ai| m.header.aspects.get(ai)) else { return false };
    holds_right(core, &sm.header, s, a, &m.header)
}

/// Whether held commit `id` keeps a blob under a label whose things `on` says, for good (spec/commits.md
/// §5, a lasting header): a permanent delta of it on such a thing is dropped (a broken one is no
/// tombstone: spec/permissions.md §8), or its purge request
/// dropped one there (`purge_one` notes it: a new device needs the request to count the missing
/// delta as held). Noted, not walked: a writer's aspect-wide request naming nothing it may purge
/// would walk the aspect on every pass.
pub(crate) fn lasting(tx: &mut Tx<'_>, id: &CommitId, on: &dyn Fn(&Core, &Tid) -> bool) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(false) };
    if m.view.aspects.iter().enumerate().any(|(ai, a)| a.permanent && m.dropped.get(&ai).is_some_and(|d| !d.broke) && on(tx.core, &a.tid)) {
        return Ok(true);
    }
    if !m.view.purges {
        return Ok(false);
    }
    for item in &m.header.purge {
        if on(tx.core, item.tid()) && tx.txn.get_local(&records::named_permanent_key(id, item.tid()))?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn request_list(tx: &mut Tx<'_>, key: &[u8]) -> Result<Vec<CommitId>> {
    let mut out = Vec::new();
    if let Some(b) = tx.txn.get_local(key)? {
        let mut r = Rd::new(&b);
        while !r.is_empty() {
            out.push(CommitId(r.arr()?));
        }
    }
    Ok(out)
}

/// Adds request `pc` to the list at `key`.
pub(super) fn note_request(tx: &mut Tx<'_>, key: &[u8], pc: &CommitId) -> Result<bool> {
    let mut b = tx.txn.get_local(key)?.unwrap_or_default();
    if b.chunks(32).any(|x| x == pc.0) {
        return Ok(false);
    }
    b.extend_from_slice(&pc.0);
    tx.txn.put_local(key, &b, Shred::No)?;
    Ok(true)
}

/// The held requests that may name delta `(tid, ak)` of commit `c`: those naming it and those
/// with an item on more than one delta. Delete-for-everyone at scale: a request by name costs
/// other deltas nothing.
pub(super) fn purge_requests(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, c: &CommitId) -> Result<Vec<CommitId>> {
    let mut out = request_list(tx, &records::aspect_key(records::PURGES, tid, ak))?;
    out.extend(request_list(tx, &records::purges_named_key(tid, ak, c))?);
    Ok(out)
}

/// The held commits on `item`'s aspect it may name, for a request stamped `at`, off the views: a
/// walk of an aspect decodes no header (`purge_allowed` decides).
pub(super) fn named_by(core: &Core, item: &PurgeItem, at: Ts) -> Vec<CommitId> {
    if let PurgeItem::Commit { commit, .. } = item {
        return vec![*commit];
    }
    let held = core.ix.by_aspect.get(&(*item.tid(), item.ak().clone())).into_iter().flatten();
    let by = |c: &CommitId| match item {
        PurgeItem::Author { actor, .. } => core.ix.commits.get(c).is_some_and(|m| m.view.kind == Kind::Import || m.view.actor == *actor),
        _ => true,
    };
    held.take_while(|x| x.0 < at).map(|x| x.1).filter(by).collect()
}

/// The earliest held request by `(ts, ID)` that purges delta `ai` of commit `c`, what a history
/// read shows as purged.
pub(crate) fn purged_by(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<Option<CommitId>> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(None) };
    let mut best: Option<(Ts, CommitId)> = None;
    for pc in purge_requests(tx, &a.tid, &a.ak, c)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        if best.is_none_or(|b| (p.ts, pc) < b) && p.purge.iter().any(|item| purge_allowed(tx.core, &p, &pc, item, ch, c, ai)) {
            best = Some((p.ts, pc));
        }
    }
    Ok(best.map(|b| b.1))
}

/// Every held request with an item on `(tid, ak)`, by name or not, each once.
fn aspect_requests(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<CommitId>> {
    let mut out = request_list(tx, &records::aspect_key(records::PURGES, tid, ak))?;
    let mut lists = Vec::new();
    tx.scan(&records::aspect_key(records::PURGES_NAMED, tid, ak), |_, v| {
        lists.push(v);
        Ok(())
    })?;
    for l in lists {
        let mut r = Rd::new(&l);
        while !r.is_empty() {
            out.push(CommitId(r.arr()?));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The held purge requests whose right may rest on `node` standing on `things`: signed by it or a
/// possible writer of it (the right by author runs signer, actor, thing), on one of `things` or on
/// a thing one of them may write. A role elsewhere on the path may stay, so the class falling on the
/// request's own thing does not say. Listing one more costs its bytes only.
pub(crate) fn requests_resting_on(core: &Core, node: &Tid, things: &BTreeSet<Tid>) -> Vec<CommitId> {
    let writers = core.ix.held.ever_writers(node);
    let mut reach: BTreeMap<Tid, bool> = BTreeMap::new();
    let mut out = Vec::new();
    for (pc, m) in core.ix.commits.iter().filter(|(_, m)| m.view.purges && !m.view.memory) {
        if !(m.view.author == *node || m.view.actor == *node || writers.contains(&m.view.author) || writers.contains(&m.view.actor)) {
            continue;
        }
        let on = |t: &Tid| *reach.entry(*t).or_insert_with(|| things.contains(t) || !core.ix.held.ever_writers(t).is_disjoint(things));
        if m.header.purge.iter().map(|i| *i.tid()).collect::<BTreeSet<_>>().iter().any(on) {
            out.push(*pc);
        }
    }
    out
}

/// Is aspect `ai` of commit `c` (not applied yet) already purged by a held request? Such a
/// missing delta counts as held (spec/commits.md §4).
pub(crate) fn known_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    for pc in purge_requests(tx, &a.tid, &a.ak, c)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        if p.purge.iter().any(|item| purge_allowed(tx.core, &p, &pc, item, ch, c, ai)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether missing delta `ai` of `c` counts as held for a held purge request naming it, signed by
/// one that could ever hold the right (spec/commits.md §4). Unlike `known_purged` it reads no
/// validity, so a demotion arriving later changes nothing here: what this let apply it goes on
/// letting apply, and the delta joins when it comes. Possible holders only grow.
pub(crate) fn counts_as_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    if is_role_class(a.ak.as_str()) {
        return Ok(false);
    }
    for pc in purge_requests(tx, &a.tid, &a.ak, c)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        if p.purge.iter().any(|i| i.tid() == &a.tid && i.ak() == &a.ak && names(&p, i, ch, c)) && signers_could(tx.core, &p, a, ch) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The aspects a timeline change on `things` or a change to commits `whole` may change purges of:
/// those with a held request (`aspect_requests`), each once.
pub(crate) fn purged_aspects(tx: &mut Tx<'_>, things: &BTreeSet<Tid>, whole: &BTreeSet<CommitId>) -> Result<BTreeSet<(Tid, Ak)>> {
    let mut out = BTreeSet::new();
    for t in things {
        tx.scan(&[records::PURGES, t.as_bytes()].concat(), |k, _| {
            let ak = k.get(2..).and_then(|b| std::str::from_utf8(b).ok()).and_then(|a| Ak::new(a).ok()).ok_or(Error::Corrupt("purge key"))?;
            out.insert((*t, ak));
            Ok(())
        })?;
        // by name: the key goes on with the named commit's ID
        tx.scan(&[records::PURGES_NAMED, t.as_bytes()].concat(), |k, _| {
            let ak = k.get(2..k.len().saturating_sub(32)).and_then(|b| std::str::from_utf8(b).ok()).and_then(|a| Ak::new(a).ok()).ok_or(Error::Corrupt("purge key"))?;
            out.insert((*t, ak));
            Ok(())
        })?;
    }
    for c in whole {
        let Some(h) = tx.core.ix.commits.get(c).filter(|m| m.view.purges).map(|m| m.header.clone()) else { continue };
        out.extend(h.purge.iter().map(|i| (*i.tid(), i.ak().clone())));
    }
    Ok(out)
}

/// A request not by name on one aspect: its ID, item and header.
type WideRequest = (CommitId, PurgeItem, crate::engine::LazyHeader);

/// The newest standing request not by name: its `ts`, ID and item.
type WideStanding = (Ts, CommitId, PurgeItem);

/// The requests not by name on one aspect, asked per delta in one walk of it: a request's right is
/// the same for every delta of one class and actor, and of those reaching that actor the newest
/// standing reaches every delta any of them does. So a walk costs the aspect's length, plus the
/// requests per class and actor met, whatever their number.
struct Widest {
    wide: Vec<WideRequest>,
    of: BTreeMap<(u64, Tid), Option<WideStanding>>,
}

impl Widest {
    fn new(wide: Vec<WideRequest>) -> Widest {
        Widest { wide, of: BTreeMap::new() }
    }

    /// Per class and actor: the newest standing request.
    fn of(&mut self, core: &Core, a: &osis_commit::AspectEntry, ch: &Header) -> &Option<WideStanding> {
        let actor = ch.purge_actor();
        let wide = &self.wide;
        self.of.entry((a.retention.by as u64, actor)).or_insert_with(|| {
            let on = wide.iter().filter(|x| !matches!(&x.1, PurgeItem::Author { actor: of, .. } if *of != actor));
            on.filter(|x| holds_right(core, &x.2, &x.0, a, ch)).max_by_key(|x| (x.2.ts, x.0)).map(|x| (x.2.ts, x.0, x.1.clone()))
        })
    }
}

/// Judges the held purge requests on `(tid, ak)` again (spec/permissions.md §8): a part one now
/// drops is purged as on arrival, and a part dropped for a purge that none drops any more counts
/// as never received from here on: out of the value-less list, its residue and writes gone until a
/// copy comes (node-sync fetches it, `Changed::undropped`; a holder uploads it). A snapshot dropped
/// for carrying purged values does not say whose: every such one comes back with a fall, and goes
/// again on arrival if it carries another's, so a value a standing purge drops stays gone; until a
/// writer's next snapshot what it alone covered is missing too, where no copy is left. Cost: the aspect's requests and what they name, its snapshots'
/// views, and with an aspect-wide request a walk of its parts, as `validity::rejudge_once` walks them
/// (`scale::purge_rejudge_cost`). A memory delta purged has vanished whole and stays gone.
pub(crate) fn rejudge_purges(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let reqs = aspect_requests(tx, tid, ak)?;
    if reqs.is_empty() || is_role_class(ak.as_str()) || tx.txn.is_memory_aspect(tid, ak) {
        return Ok(());
    }
    // the items on the aspect: by name, per named commit; the others ask of every part
    let mut named: BTreeMap<CommitId, Vec<(CommitId, PurgeItem)>> = BTreeMap::new();
    let mut wide: Vec<(CommitId, PurgeItem)> = Vec::new();
    let mut heads = BTreeMap::new();
    for pc in &reqs {
        let Some(p) = tx.core.ix.commits.get(pc).map(|m| m.header.clone()) else { continue };
        for item in p.purge.iter().filter(|i| i.tid() == tid && i.ak() == ak) {
            match item {
                PurgeItem::Commit { commit, .. } => named.entry(*commit).or_default().push((*pc, item.clone())),
                PurgeItem::Aspect { .. } | PurgeItem::Author { .. } => wide.push((*pc, item.clone())),
            }
        }
        heads.insert(*pc, p);
    }
    let now = tx.now().0;
    // with no aspect-wide request only the named parts and the snapshots can flip, so a role change
    // costs the aspect's requests, not its length
    let core = &*tx.core;
    let mut parts: Vec<(Ts, CommitId)> = if wide.is_empty() {
        named.keys().copied().chain(snapshots_of(core, tid, ak)).collect::<BTreeSet<_>>().into_iter().filter_map(|c| Some((core.ix.commits.get(&c)?.view.ts, c))).collect()
    } else {
        core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().copied().collect()
    };
    parts.sort();
    let (mut rise, mut fall, mut bare) = (Vec::new(), Vec::new(), Vec::new());
    let mut fell = false;
    let mut widest = Widest::new(wide.iter().filter_map(|(pc, i)| Some((*pc, i.clone(), heads.get(pc)?.clone()))).collect());
    for (_, c) in parts {
        let core = &*tx.core;
        let Some(m) = core.ix.commits.get(&c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        let Some(a) = m.header.aspects.get(ai) else { continue };
        // past its expiry it goes whatever the requests say
        if a.expires.is_some_and(|t| t <= now) {
            continue;
        }
        let by_name = || named.get(&c).into_iter().flatten().filter(|x| heads.get(&x.0).is_some_and(|p| names(p, &x.1, &m.header, &c)));
        let standing_name = by_name().find(|x| heads.get(&x.0).is_some_and(|p| holds_right(core, p, &x.0, a, &m.header))).map(|x| (x.0, x.1.clone()));
        let by = standing_name.or_else(|| widest.of(core, a, &m.header).as_ref().filter(|n| m.header.ts < n.0).map(|n| (n.1, n.2.clone())));
        let dropped = m.dropped.get(&ai);
        match (by, m.header.kind.has_own_writes()) {
            (Some(x), true) if !valueless(core, &c, ai) => rise.push((x.0, x.1, c, ai)),
            (None, true) if valueless(core, &c, ai) => fall.push((c, ai)),
            (Some(x), false) if dropped.is_none() => rise.push((x.0, x.1, c, ai)),
            (None, false) if dropped.is_some_and(|d| d.purged) => {
                // named itself and not standing: its own request fell, whatever else did
                fell |= by_name().next().is_some() || wide.iter().any(|(pc, i)| heads.get(pc).is_some_and(|p| names(p, i, &m.header, &c)));
                bare.push((c, ai));
            }
            _ => {}
        }
    }
    let mut purged = BTreeSet::new();
    for (pc, item, c, ai) in rise {
        purge_one(tx, &pc, &item, &c, ai, &mut purged)?;
    }
    purged_changed(tx, purged, changed);
    if fall.is_empty() && !fell {
        return Ok(());
    }
    let mut gone = Vec::new();
    let mut back = bare;
    for (c, ai, o, returns) in out_of_valueless(tx, tid, ak, &fall)? {
        if returns {
            gone.push(o);
            back.push((c, ai));
        }
    }
    tx.core.forget_live(tid, ak);
    // until each comes back, this node may read less than one that kept it
    suspect::raise(tx, tid, ak, suspect::Why::Uncovered, &back)?;
    for (c, ai) in back {
        reopen(tx, &c, ai)?;
        tx.core.mark_changed(c);
        if let Some(ch) = &mut tx.core.changed {
            ch.undropped.insert(c);
        }
    }
    gone.extend(uncover(tx, tid, ak)?);
    if !gone.is_empty() {
        note_carried_again(tx, tid, ak)?;
    }
    crate::apply::rebuild_without(tx, tid, ak, &gone)?;
    mark_deaths_due(tx, tid, ak)?;
    tx.core.mark_aspect_changed(tid, ak);
    changed.insert((*tid, ak.clone()));
    Ok(())
}

/// Takes `parts` of `(tid, ak)` out of the value-less list: each one's commit, aspect index, own
/// writes and whether it comes back as missing. One dropped as covered does not: its cover's copies
/// are its writes while one carries it (`uncover`). Their residue rows stay, read only while in the
/// list (`records::RESIDUE`).
fn out_of_valueless(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, parts: &[(CommitId, usize)]) -> Result<Vec<(CommitId, usize, Owned, bool)>> {
    tx.core.touch();
    let mut out = Vec::new();
    for (c, ai) in parts {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        let Some(o) = Owned::of(&m.header, c, *ai) else { continue };
        let returns = m.dropped.get(ai).is_some_and(|d| !d.as_cover);
        out.push((*c, *ai, o, returns));
    }
    let k = (*tid, ak.clone());
    let leaving: BTreeSet<&Owned> = out.iter().map(|x| &x.2).collect();
    let list = tx.core.ix.valueless.entry_or_default(k.clone());
    list.retain(|x| !leaving.contains(x));
    if list.is_empty() {
        tx.core.ix.valueless.remove(&k);
    }
    tx.core.valueless_dirty.insert(k);
    Ok(out)
}

/// Applies purge item `item` of commit `pc` to held delta `(c, ai)` if it may: its values go
/// value-less, its body and every snapshot body carrying them drop (node-sync re-snapshots
/// where no covering snapshot is left, spec/commits.md §5).
pub(super) fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, item: &PurgeItem, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.ix.commits.get(pc), tx.core.ix.commits.get(c)) else { return Ok(()) };
    if !purge_allowed(tx.core, &p.header, pc, item, &m.header, c, ai) {
        return Ok(());
    }
    let m = m.clone();
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    // the part may have gone already, for another reason: its entry now reads purged
    tx.core.history_named(a.tid, a.ak.clone(), *c);
    // a lasting header from now on (`lasting`), whichever came first
    if m.view.aspects.get(ai).is_some_and(|x| x.permanent) {
        tx.txn.put_local(&records::named_permanent_key(pc, &a.tid), &[], Shred::No)?;
        tx.core.mark_changed(*pc);
    }
    expire(tx, c, ai, true, changed)?;
    // snapshots carrying the purged values (spec/commits.md §5)
    if let Some(o) = Owned::of(&m.header, c, ai) {
        // the held ones (no walk of the aspect: a delete for everyone costs the same at any length)
        let held: Vec<CommitId> = tx.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        for s in held {
            if let Some(sai) = aspect_index(tx.core, &s, &a.tid, &a.ak) {
                drop_carrying(tx, &s, sai, std::slice::from_ref(&o))?;
            }
        }
    }
    Ok(())
}

/// Drops held snapshot part `(s, sai)` if it carries a value of a delta a held purge request
/// purges (spec/commits.md §5): `purge_one` judges the snapshots held when the request or the
/// named delta arrives; this one a snapshot part arriving after both.
pub(super) fn drop_purged_snapshot(tx: &mut Tx<'_>, s: &CommitId, sai: usize) -> Result<()> {
    // runs for every applied delta: the kind first, nothing cloned
    let Some(sm) = tx.core.ix.commits.get(s) else { return Ok(()) };
    if !sm.header.kind.is_compaction() {
        return Ok(());
    }
    let Some((tid, ak)) = sm.header.aspects.get(sai).map(|a| (a.tid, a.ak.clone())) else { return Ok(()) };
    if is_role_class(ak.as_str()) {
        return Ok(());
    }
    let mut owned = Vec::new();
    // a snapshot's arrival, rarer than a delta's: every request on the aspect, one walk for those
    // not by name (`Widest`)
    let mut wide = Vec::new();
    for pc in aspect_requests(tx, &tid, &ak)? {
        let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
        for item in p.purge.iter().filter(|i| *i.tid() == tid && *i.ak() == ak) {
            if let PurgeItem::Commit { commit: c, .. } = item {
                let Some((m, ai)) = tx.core.ix.commits.get(c).and_then(|m| Some((m, m.aspect(&tid, &ak)?))) else { continue };
                if c != s && purge_allowed(tx.core, &p, &pc, item, &m.header, c, ai)
                    && let Some(o) = Owned::of(&m.header, c, ai)
                {
                    owned.push(o);
                }
            } else {
                wide.push((pc, item.clone(), p.clone()));
            }
        }
    }
    if !wide.is_empty() {
        let core = &*tx.core;
        let mut widest = Widest::new(wide);
        for (ts, c) in core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten().filter(|x| x.1 != *s) {
            let Some((m, ai)) = core.ix.commits.get(c).and_then(|m| Some((m, m.aspect(&tid, &ak)?))) else { continue };
            let Some(a) = m.header.aspects.get(ai) else { continue };
            if widest.of(core, a, &m.header).as_ref().is_some_and(|n| *ts < n.0)
                && let Some(o) = Owned::of(&m.header, c, ai)
            {
                owned.push(o);
            }
        }
    }
    if owned.is_empty() {
        return Ok(());
    }
    drop_carrying(tx, s, sai, &owned)
}

impl Engine {
    /// The held commits a held purge request drops a delta of on `(tid, ak)`, each with the earliest
    /// such request by `(ts, ID)` (spec/commits.md §5). Costs a walk of the aspect's views, then its
    /// requests per dropped delta.
    pub fn purged_on(&mut self, tid: &Tid, ak: &Ak) -> Result<BTreeMap<CommitId, CommitId>> {
        let core = &self.core;
        let dropped: Vec<CommitId> = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|c| core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.dropped.contains_key(&ai)))).collect();
        self.run(|tx| {
            let mut out = BTreeMap::new();
            for c in dropped {
                let Some((h, Some(ai))) = tx.core.ix.commits.get(&c).map(|m| (m.header.clone(), m.aspect(tid, ak))) else { continue };
                if let Some(by) = purged_by(tx, &h, &c, ai)? {
                    out.insert(c, by);
                }
            }
            Ok(out)
        })
    }

    /// Whether a held request names a delta of `parts` of `c` and does not drop it, signed by one
    /// that could ever hold the right: a delete that took the body at a host may be that request's,
    /// not its keep bounds' (spec/sync.md §6). A request no signer ever had the right for took
    /// nothing: a plain writer's aspect-wide one must not reopen every delete on the aspect.
    pub fn named_by_a_fallen_purge(&mut self, c: &CommitId, parts: &[(usize, usize)]) -> Result<bool> {
        let (c, ais): (CommitId, BTreeSet<usize>) = (*c, parts.iter().map(|p| p.0).collect());
        self.run(|tx| {
            let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { return Ok(false) };
            for ai in ais {
                let Some(a) = h.aspects.get(ai) else { continue };
                for pc in purge_requests(tx, &a.tid, &a.ak, &c)? {
                    let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
                    let items = || p.purge.iter().filter(|i| i.tid() == &a.tid && i.ak() == &a.ak);
                    if items().any(|i| names(&p, i, &h, &c)) && signers_could(tx.core, &p, a, &h) && !items().any(|i| purge_allowed(tx.core, &p, &pc, i, &h, &c, ai)) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }
}
