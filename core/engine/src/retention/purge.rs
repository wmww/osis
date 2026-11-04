//! Purge requests (spec/commits.md §5, spec/permissions.md §8). Every question about one comes down
//! to two: does it name a delta (`names`), and does it have the right? The right has two readings:
//! `holds_right` by the role timeline, which what a request drops follows (`stands`,
//! `rejudge_purges`), and `signers_could`, by roles of any validity at any time, for what must not
//! turn on arrival (`could_stand`). A header never names role-class deltas (`Header::validate`).

use super::{aspect_index, drop_carrying, gone_of, hold_valueless, mark_deaths_due, note_carried_again, off_valueless, purged_changed, reopen_to_fetch, sharing, snapshots_of, suspect, uncover, writes_of};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, DropFor, Engine, LazyHeader, Owned, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{AspectEntry, Header, Kind, PurgeItem};
use osis_perm::Point;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// A held request: its ID and header.
type Request = (CommitId, LazyHeader);

/// Whether `item` reaches commit `c` (header `ch`) on its aspect: by commit, the whole aspect, or
/// by its actor.
fn reaches(item: &PurgeItem, ch: &Header, c: &CommitId) -> bool {
    match item {
        PurgeItem::Commit { commit, .. } => commit == c,
        PurgeItem::Aspect { .. } => true,
        PurgeItem::Author { actor, .. } => ch.purge_actor() == *actor,
    }
}

/// Whether a request with header `p` names delta `a` of commit `c` (header `ch`): an item on its
/// aspect reaches it, and it is stamped before the request (spec/commits.md §5).
fn names(p: &Header, a: &AspectEntry, ch: &Header, c: &CommitId) -> bool {
    ch.ts < p.ts && p.purge.iter().any(|i| i.tid() == &a.tid && i.ak() == &a.ak && reaches(i, ch, c))
}

/// Whether commit `pc` (header `p`: a purge request or a compaction snapshot) holds the right over
/// delta `a` of a commit with header `ch`, at its own key (spec/permissions.md §8): its author
/// does, and the actor it acts for, neither by a role a demotion's frontier took from this commit.
/// The actor holds a client to its own rights in any arrival order: its node's would reach a delta
/// of the person it acts for that the node did not hold yet. A function of the role timeline, the
/// void set and the headers, so any node holding them judges alike, in any arrival order;
/// `rejudge_purges` follows it when those change.
pub(super) fn holds_right(core: &Core, p: &Header, pc: &CommitId, a: &AspectEntry, ch: &Header) -> bool {
    if core.ix.void.contains(pc) {
        return false;
    }
    let point = Point { ts: p.ts, node: p.author, commit: *pc };
    let (by, actor) = (a.retention.by, ch.purge_actor());
    core.timelines.get(&a.tid).is_some_and(|tl| tl.purge_stands(&p.author, &a.tid, by, &actor, point) && (p.actor == p.author || tl.purge_stands(&p.actor, &a.tid, by, &actor, point)))
}

/// Whether request `pc` (header `p`) drops delta `a` of commit `c` (header `ch`).
fn stands(core: &Core, p: &Header, pc: &CommitId, a: &AspectEntry, ch: &Header, c: &CommitId) -> bool {
    names(p, a, ch, c) && holds_right(core, p, pc, a, ch)
}

/// Whether a request with header `p` is signed by ones that could ever hold the right over delta
/// `a` of a commit with header `ch`: `holds_right` with roles of any validity at any time, so held
/// inputs only widen it.
fn signers_could(core: &Core, p: &Header, a: &AspectEntry, ch: &Header) -> bool {
    let (held, by, actor) = (&core.ix.held, a.retention.by, ch.purge_actor());
    let could = |who: &Tid| {
        (by.admin() && held.ever_admins(&a.tid).contains(who))
            || (by.writer() && held.ever_writers(&a.tid).contains(who))
            || (by.author() && (*who == actor || held.ever_writers(&actor).contains(who)) && held.ever_writers(&a.tid).contains(&actor))
    };
    could(&p.author) && (p.actor == p.author || could(&p.actor))
}

/// Whether a request with header `p` names delta `a` of commit `c` (header `ch`), signed by ones
/// that could ever hold the right.
fn could_stand(core: &Core, p: &Header, a: &AspectEntry, ch: &Header, c: &CommitId) -> bool {
    names(p, a, ch, c) && signers_could(core, p, a, ch)
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
    if m.view.aspects.iter().enumerate().any(|(ai, a)| a.permanent && m.dropped.get(&ai).is_some_and(|d| d.why != DropFor::Broke) && on(tx.core, &a.tid)) {
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

/// The requests in a list record: their IDs back to back.
fn request_ids(b: &[u8]) -> Result<Vec<CommitId>> {
    let mut r = Rd::new(b);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(CommitId(r.arr()?));
    }
    Ok(out)
}

/// Adds request `pc` to the list at `key`.
fn note_request(tx: &mut Tx<'_>, key: &[u8], pc: &CommitId) -> Result<bool> {
    let mut b = tx.txn.get_local(key)?.unwrap_or_default();
    if b.chunks(32).any(|x| x == pc.0) {
        return Ok(false);
    }
    b.extend_from_slice(&pc.0);
    tx.txn.put_local(key, &b, Shred::No)?;
    Ok(true)
}

/// The held requests that may name delta `a` of commit `c`: those naming it and those with an item
/// on more than one delta. Delete-for-everyone at scale: a request by name costs other deltas
/// nothing.
fn requests_on(tx: &mut Tx<'_>, a: &AspectEntry, c: &CommitId) -> Result<Vec<Request>> {
    let mut ids = Vec::new();
    for key in [records::aspect_key(records::PURGES, &a.tid, &a.ak), records::purges_named_key(&a.tid, &a.ak, c)] {
        if let Some(b) = tx.txn.get_local(&key)? {
            ids.extend(request_ids(&b)?);
        }
    }
    Ok(ids.into_iter().filter_map(|pc| Some((pc, tx.core.ix.commits.get(&pc)?.header.clone()))).collect())
}

/// Every held request with an item on `(tid, ak)`, by name or not, each once.
fn aspect_requests(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Vec<CommitId>> {
    let mut out = match tx.txn.get_local(&records::aspect_key(records::PURGES, tid, ak))? {
        Some(b) => request_ids(&b)?,
        None => Vec::new(),
    };
    let mut lists = Vec::new();
    tx.scan(&records::aspect_key(records::PURGES_NAMED, tid, ak), |_, v| {
        lists.push(v);
        Ok(())
    })?;
    for l in lists {
        out.extend(request_ids(&l)?);
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// The held commits on `item`'s aspect it may name, for a request stamped `at`, off the views: a
/// walk of an aspect decodes no header (`names` decides).
fn named_by(core: &Core, item: &PurgeItem, at: Ts) -> Vec<CommitId> {
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
    let requests = requests_on(tx, a, c)?;
    Ok(requests.iter().filter(|(pc, p)| stands(tx.core, p, pc, a, ch, c)).min_by_key(|(pc, p)| (p.ts, *pc)).map(|x| x.0))
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
    let requests = requests_on(tx, a, c)?;
    Ok(requests.iter().any(|(pc, p)| stands(tx.core, p, pc, a, ch, c)))
}

/// Whether missing delta `ai` of `c` counts as held for a held purge request naming it, signed by
/// one that could ever hold the right (spec/commits.md §4; `apply::gates`). Unlike `known_purged`
/// it reads no validity, so a demotion arriving later changes nothing here. A request naming
/// another import of an origin of an import counts for it too (`writes_of`).
pub(crate) fn counts_as_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    if requests_on(tx, a, c)?.iter().any(|(_, p)| could_stand(tx.core, p, a, ch, c)) {
        return Ok(true);
    }
    for i in sharing(tx.core, ch, ai).into_iter().filter(|i| i != c) {
        let Some(h) = tx.core.ix.commits.get(&i).map(|m| m.header.clone()) else { continue };
        let Some(ia) = h.aspects.iter().find(|x| x.tid == a.tid && x.ak == a.ak) else { continue };
        if requests_on(tx, ia, &i)?.iter().any(|(_, p)| could_stand(tx.core, p, ia, &h, &i)) {
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

/// The held requests with an item on one aspect, asked per delta in one walk of it. Those by name
/// wait under the commit they name. For the others, a request's right is the same for every delta
/// of one class and actor, and of those reaching that actor the newest standing reaches every delta
/// any of them does. So a walk costs the aspect's length, plus the requests per class and actor
/// met, whatever their number.
struct AspectRequests {
    named: BTreeMap<CommitId, Vec<Request>>,
    wide: Vec<(CommitId, PurgeItem, LazyHeader)>,
    /// Per class and actor: the newest standing request of `wide`, its `ts` and ID.
    newest: BTreeMap<(u64, Tid), Option<(Ts, CommitId)>>,
}

impl AspectRequests {
    fn load(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<AspectRequests> {
        let mut out = AspectRequests { named: BTreeMap::new(), wide: Vec::new(), newest: BTreeMap::new() };
        for pc in aspect_requests(tx, tid, ak)? {
            let Some(p) = tx.core.ix.commits.get(&pc).map(|m| m.header.clone()) else { continue };
            for item in p.purge.iter().filter(|i| i.tid() == tid && i.ak() == ak) {
                match item {
                    PurgeItem::Commit { commit, .. } => out.named.entry(*commit).or_default().push((pc, p.clone())),
                    _ => out.wide.push((pc, item.clone(), p.clone())),
                }
            }
        }
        Ok(out)
    }

    fn is_empty(&self) -> bool {
        self.named.is_empty() && self.wide.is_empty()
    }

    /// The commits on `(tid, ak)` these may name: with one not by name, all of them.
    fn may_name(&self, core: &Core, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
        if self.wide.is_empty() {
            return self.named.keys().copied().collect();
        }
        core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect()
    }

    /// A request of these that drops delta `a` of commit `c` (header `ch`).
    fn standing(&mut self, core: &Core, a: &AspectEntry, ch: &Header, c: &CommitId) -> Option<CommitId> {
        let by_name = self.named.get(c).into_iter().flatten().find(|(pc, p)| ch.ts < p.ts && holds_right(core, p, pc, a, ch));
        if let Some((pc, _)) = by_name {
            return Some(*pc);
        }
        let actor = ch.purge_actor();
        let wide = &self.wide;
        let newest = self.newest.entry((a.retention.by as u64, actor)).or_insert_with(|| {
            let on = wide.iter().filter(|x| !matches!(&x.1, PurgeItem::Author { actor: of, .. } if *of != actor));
            on.filter(|x| holds_right(core, &x.2, &x.0, a, ch)).map(|x| (x.2.ts, x.0)).max()
        });
        newest.filter(|n| ch.ts < n.0).map(|n| n.1)
    }

    /// Whether one of these names commit `c` (header `ch`), standing or not.
    fn names_it(&self, ch: &Header, c: &CommitId) -> bool {
        self.named.get(c).into_iter().flatten().any(|(_, p)| ch.ts < p.ts) || self.wide.iter().any(|(_, i, p)| ch.ts < p.ts && reaches(i, ch, c))
    }
}

/// Judges the held purge requests on `(tid, ak)` again (spec/permissions.md §8): a part one now
/// drops is purged as on arrival, and a part dropped for a purge that none drops any more counts
/// as never received from here on: out of the value-less list, its residue and writes gone until a
/// copy comes (node-sync fetches it, `Changed::undropped`; a holder uploads it). A snapshot dropped
/// for carrying purged values does not say whose: every such one comes back with a fall, and goes
/// again on arrival if it carries another's, so a value a standing purge drops stays gone; until a
/// writer's next snapshot what it alone covered is missing too, where no copy is left. Cost: the
/// aspect's requests and what they name, its snapshots' views, and with an aspect-wide request a
/// walk of its parts, as `validity::rejudge_once` walks them (`scale::purge_rejudge_cost`). A
/// memory delta purged has vanished whole and stays gone. An import's writes are its origins' dots
/// (`writes_of`), and several imports may share them: an owner leaves the list only when no
/// standing request takes it, and an import comes back only when none of its writes is left on
/// the list.
pub(crate) fn rejudge_purges(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    if tx.txn.is_memory_aspect(tid, ak) {
        return Ok(());
    }
    let mut requests = AspectRequests::load(tx, tid, ak)?;
    if requests.is_empty() {
        return Ok(());
    }
    let now = tx.now().0;
    let core = &*tx.core;
    // with no aspect-wide request only the named parts and the snapshots can flip, so a role change
    // costs the aspect's requests, not its length
    let mut parts = requests.may_name(core, tid, ak);
    if requests.wide.is_empty() {
        let shared: Vec<CommitId> = parts.iter().filter_map(|c| core.ix.commits.get(c).and_then(|m| Some(sharing(core, &m.header, m.aspect(tid, ak)?)))).flatten().collect();
        parts.extend(shared);
        parts.extend(snapshots_of(core, tid, ak));
    }
    let parts: BTreeSet<(Ts, CommitId)> = parts.into_iter().filter_map(|c| Some((core.ix.commits.get(&c)?.view.ts, c))).collect();
    // `kept`: the writes a standing request takes; `quiet`: parts with writes none takes
    let (mut rise, mut quiet, mut bare, mut kept) = (Vec::new(), Vec::new(), Vec::new(), BTreeSet::new());
    let mut fell = false;
    for (_, c) in parts {
        let Some(m) = core.ix.commits.get(&c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        let Some(a) = m.header.aspects.get(ai) else { continue };
        // past its expiry it goes whatever the requests say
        if m.header.expires.is_some_and(|t| t <= now) {
            continue;
        }
        let by = requests.standing(core, a, &m.header, &c);
        let dropped = m.dropped.get(&ai);
        let own = writes_of(core, &m.header, &c, ai);
        match (by, !own.is_empty()) {
            (Some(pc), true) => {
                if gone_of(core, &m.header, &c, ai).len() < own.len() {
                    rise.push((pc, c, ai));
                }
                kept.extend(own);
            }
            (None, true) => quiet.push((c, ai)),
            (Some(pc), false) if dropped.is_none() => rise.push((pc, c, ai)),
            (None, false) if dropped.is_some_and(|d| d.why == DropFor::Purge) => {
                // named itself and not standing: its own request fell, whatever else did
                fell |= requests.names_it(&m.header, &c);
                bare.push((c, ai));
            }
            _ => {}
        }
    }
    let mut purged = BTreeSet::new();
    for (pc, c, ai) in rise {
        purge_one(tx, &pc, &c, ai, &mut purged)?;
    }
    purged_changed(tx, purged, changed);
    // after the rises: what they put on the list keeps a part that shares it from coming back
    let mut back = bare;
    let (mut leaving, mut gone) = (Vec::new(), Vec::new());
    for (c, ai) in quiet {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let listed = gone_of(tx.core, &m.header, &c, ai);
        let going: Vec<Owned> = listed.iter().filter(|o| !kept.contains(*o)).cloned().collect();
        if going.is_empty() {
            continue;
        }
        // dropped as covered it stays so: its cover's copies are its writes while one carries it
        if m.dropped.get(&ai).is_some_and(|d| !d.as_cover()) {
            gone.extend(going.iter().cloned());
            if going.len() == listed.len() {
                back.push((c, ai));
            }
        }
        leaving.extend(going);
    }
    if leaving.is_empty() && !fell {
        return Ok(());
    }
    // their residue rows stay, read only while on the list (`records::RESIDUE`)
    off_valueless(tx, tid, ak, &leaving);
    tx.core.forget_live(tid, ak);
    // until each comes back, this node may read less than one that kept it
    suspect::raise(tx, tid, ak, suspect::Why::Uncovered, &back)?;
    for (c, ai) in back {
        reopen_to_fetch(tx, &c, ai)?;
        tx.core.mark_changed(c);
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

/// Applies request `pc` to held delta `(c, ai)` if it stands: its values go value-less, its body and
/// every snapshot body carrying them drop (node-sync re-snapshots where no covering snapshot is
/// left, spec/commits.md §5).
pub(super) fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.ix.commits.get(pc), tx.core.ix.commits.get(c)) else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    if !stands(tx.core, &p.header, pc, a, &m.header, c) {
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
    hold_valueless(tx, c, ai, true, changed)?;
    // snapshots carrying the purged values (spec/commits.md §5)
    let o = writes_of(tx.core, &m.header, c, ai);
    // the held ones (no walk of the aspect: a delete for everyone costs the same at any length)
    let held: Vec<CommitId> = tx.core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for s in held {
        if let Some(sai) = aspect_index(tx.core, &s, &a.tid, &a.ak) {
            drop_carrying(tx, &s, sai, &o)?;
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
    let mut requests = AspectRequests::load(tx, &tid, &ak)?;
    if requests.is_empty() {
        return Ok(());
    }
    let core = &*tx.core;
    let mut owned = Vec::new();
    for c in requests.may_name(core, &tid, &ak).iter().filter(|c| *c != s) {
        let Some((m, ai)) = core.ix.commits.get(c).and_then(|m| Some((m, m.aspect(&tid, &ak)?))) else { continue };
        let Some(a) = m.header.aspects.get(ai) else { continue };
        if requests.standing(core, a, &m.header, c).is_some() {
            owned.extend(writes_of(core, &m.header, c, ai));
        }
    }
    if owned.is_empty() {
        return Ok(());
    }
    drop_carrying(tx, s, sai, &owned)
}

/// Request `id` (header `h`) just applied: against the held deltas it names, then on the lists later
/// ones find it by.
pub(super) fn apply_request(tx: &mut Tx<'_>, id: &CommitId, h: &Header, purged: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for item in &h.purge {
        // one that is not by name asks of every delta: the right once per class and actor, so a
        // request with none costs a look per delta
        let mut rights: BTreeMap<(u64, Tid), bool> = BTreeMap::new();
        for c in named_by(tx.core, item, h.ts) {
            let core = &*tx.core;
            let Some((m, ai)) = core.ix.commits.get(&c).and_then(|m| Some((m, m.aspect(item.tid(), item.ak())?))) else { continue };
            let Some(a) = m.header.aspects.get(ai) else { continue };
            if matches!(item, PurgeItem::Commit { .. }) || *rights.entry((a.retention.by as u64, m.header.purge_actor())).or_insert_with(|| holds_right(core, h, id, a, &m.header)) {
                purge_one(tx, id, &c, ai, purged)?;
            }
        }
        // pending commits holding a part it names: examined again, the part held value-less
        // (`pending_drops`)
        tx.core.waits.wake_thing(item.tid());
        let key = match item {
            PurgeItem::Commit { commit, tid, ak } => records::purges_named_key(tid, ak, commit),
            _ => records::aspect_key(records::PURGES, item.tid(), item.ak()),
        };
        if note_request(tx, &key, id)? {
            tx.core.waits.wake(item.tid(), item.ak());
        }
    }
    Ok(())
}

/// Held requests already naming delta `ai` of `id` (header `h`), just applied.
pub(super) fn purge_arrived(tx: &mut Tx<'_>, id: &CommitId, h: &Header, ai: usize, purged: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    for (pc, _) in requests_on(tx, a, id)? {
        purge_one(tx, &pc, id, ai, purged)?;
    }
    Ok(())
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

    /// Whether request `pc` drops delta `(tid, ak)` of `c` as the node now judges it (spec/permissions.md
    /// §8), held or not.
    pub fn purge_stands(&self, pc: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        let core = &self.core;
        let (Some(p), Some(m)) = (core.ix.commits.get(pc), core.ix.commits.get(c)) else { return false };
        let Some(a) = m.aspect(tid, ak).and_then(|ai| m.header.aspects.get(ai)) else { return false };
        stands(core, &p.header, pc, a, &m.header, c)
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
                // an import's body also goes for a request on another import of its origin
                for x in sharing(tx.core, &h, ai).into_iter().chain([c]) {
                    let Some(xh) = tx.core.ix.commits.get(&x).map(|m| m.header.clone()) else { continue };
                    let Some(xa) = xh.aspects.iter().find(|x| x.tid == a.tid && x.ak == a.ak) else { continue };
                    let requests = requests_on(tx, xa, &x)?;
                    if requests.iter().any(|(pc, p)| could_stand(tx.core, p, xa, &xh, &x) && !holds_right(tx.core, p, pc, xa, &xh)) {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
    }

    /// `snapshot_right`: may snapshot `s` drop body `(tid, ak)` of `c` when it covers it?
    pub fn snapshot_right(&self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        snapshot_right(&self.core, s, c, tid, ak)
    }
}
