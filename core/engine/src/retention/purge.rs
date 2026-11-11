//! Purge requests (spec/commits.md §5, spec/permissions.md §6). Every question about one comes down
//! to two: does it name a delta (`names`), and does it have the right? The right has two readings:
//! `holds_right` by the role timeline, which what a request drops follows (`stands`,
//! `rejudge_purges`), and `signers_could`, by roles of any validity at any time, for what must not
//! turn on arrival (`could_stand`). A header never names role-class deltas (`Header::validate`).

use super::{gone_of, hold_valueless, off_valueless, purged_changed, refetch, reopen_to_fetch, suspect, unstrip, writes_of};
use crate::engine::records::{self, Rd};
use crate::engine::{Core, Engine, LazyHeader, Tx};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{AspectEntry, Header, PurgeItem};
use osis_perm::{HeldSet, Point};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// A held request: its ID and header.
type Request = (CommitId, LazyHeader);

/// Whether a request stamped `at` may name a delta on `ak` stamped `ts`: one stamped before it, or
/// any minting (`created.0`): a request ending a thing ends every minting of it, so a later minting
/// is held value-less as the earlier ones (spec/commits.md §5 Ending).
fn stamped_before(at: Ts, ak: &Ak, ts: Ts) -> bool {
    ts < at || ak.as_str() == osis_commit::retention::CREATED
}

/// Whether `item` reaches commit `c` (header `ch`) on its aspect: by commit, the whole aspect, or
/// by its actor.
fn reaches(item: &PurgeItem, ch: &Header, c: &CommitId) -> bool {
    match item {
        PurgeItem::Commit { commit, .. } => commit == c,
        PurgeItem::Aspect { .. } => true,
        PurgeItem::Author { actor, .. } => ch.actor == *actor,
    }
}

/// Whether a request with header `p` names delta `a` of commit `c` (header `ch`): a delta with
/// writes of its own (a snapshot has none, so no request names it: it is never purged, its copies
/// of purged values go as any carrying body's), an item on its aspect reaches it, it is stamped
/// before the request, and a request that expires reaches only deltas expiring no later than it
/// (spec/commits.md §5).
fn names(p: &Header, a: &AspectEntry, ch: &Header, c: &CommitId) -> bool {
    ch.kind.has_own_writes()
        && stamped_before(p.ts, &a.ak, ch.ts) && p.expires.is_none_or(|e| ch.expires.is_some_and(|x| x <= e)) && p.purge.iter().any(|i| i.tid() == &a.tid && i.ak() == &a.ak && reaches(i, ch, c))
}

/// Whether commit `pc` (header `p`: a purge request or a compaction snapshot) holds the right over
/// delta `a` of a commit with header `ch`, at its own key (spec/permissions.md §6): its author
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
    let (by, actor) = (a.retention.by, ch.actor);
    let judge = |tl: &osis_perm::Timeline| tl.purge_stands(&p.author, &a.tid, by, &actor, point) && (p.actor == p.author || tl.purge_stands(&p.actor, &a.tid, by, &actor, point));
    // an ending is judged by the thing's history before it: nothing written on the thing after it
    // counts (spec/commits.md §5 Ending), so an edge write on it stamped later, held here before
    // the ending arrived, is left out of the walk that judges it. Such a write is not held once
    // the thing ended (`end::Ending`): a walk from scratch only while one is, only for signers
    // that could ever hold the right (held inputs only grow, so neither can a cut's), and only
    // over what authority on the thing and the delta's actor comes from (`Held::upstream`), not
    // the node's whole role graph
    if a.ak.as_str() == osis_commit::retention::CREATED {
        let later: BTreeSet<CommitId> = HeldSet::edge_commits(&core.ix.held, &a.tid).iter().filter(|c| c.point() > point).map(|c| c.id).collect();
        if !later.is_empty() {
            if !signers_could(core, p, a, ch) {
                return false;
            }
            let things = core.ix.held.upstream(&BTreeSet::from([a.tid, actor]));
            crate::costs::count("ending: cut walk things", things.len() as u64);
            let cut = Cut { held: &core.ix.held, things, later };
            return judge(&osis_perm::Timeline::evaluate_with(&cut, &core.sides.trust()));
        }
    }
    core.timelines.get(&a.tid).is_some_and(judge)
}

/// The held set over `things` (closed upstream: roles on them come from them alone) without
/// commits `later` (`holds_right`).
struct Cut<'a> {
    held: &'a crate::engine::held::Held,
    things: BTreeSet<Tid>,
    later: BTreeSet<CommitId>,
}

impl HeldSet for Cut<'_> {
    fn things(&self) -> Vec<Tid> {
        self.things.iter().copied().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<std::sync::Arc<osis_perm::RoleCommit>> {
        if !self.things.contains(thing) {
            return Vec::new();
        }
        self.held.edge_commits(thing).into_iter().filter(|c| !self.later.contains(&c.id)).collect()
    }
    fn created(&self, thing: &Tid) -> Option<osis_base::CreationRecord> {
        self.things.contains(thing).then(|| HeldSet::created(self.held, thing)).flatten()
    }
}

/// The writer's check of its own request `pc` (header `p`), built but not applied: each item that
/// names held deltas must drop one of them by `holds_right`, as a receiver judges it, or the
/// request is refused (`Permission` on the item's thing). An item naming none held is written: a
/// request naming a delta that arrives later is honored then.
pub(crate) fn check_request(core: &Core, p: &Header, pc: &CommitId) -> Result<()> {
    for item in &p.purge {
        // a request that expires reaches only deltas expiring no later: one naming a held delta
        // beyond it is refused, never written to drop less than it says (no request names a
        // snapshot, `names`)
        if let Some(e) = p.expires {
            for c in named_by(core, item, p.ts) {
                let Some(m) = core.ix.commits.get(&c).filter(|m| m.header.kind.has_own_writes() && m.aspect(item.tid(), item.ak()).is_some()) else { continue };
                if stamped_before(p.ts, item.ak(), m.header.ts) && reaches(item, &m.header, &c) && m.header.expires.is_none_or(|x| x > e) {
                    return Err(Error::Clash(format!("a purge in a commit that expires reaches only commits expiring no later, and {c:?} on {} {} expires later or never. Write the purge as a commit of its own", item.tid(), item.ak())));
                }
            }
        }
        // the right once per class and actor, as `apply_request` judges it; `names` skips
        // snapshots, so whether one is held (a compaction, a purge's re-snapshot) never decides
        let mut rights: BTreeMap<(u64, Tid), bool> = BTreeMap::new();
        for c in named_by(core, item, p.ts) {
            let Some((m, ai)) = core.ix.commits.get(&c).and_then(|m| Some((m, m.aspect(item.tid(), item.ak())?))) else { continue };
            let Some(a) = m.header.aspects.get(ai).filter(|a| names(p, a, &m.header, &c)) else { continue };
            if *rights.entry((a.retention.by as u64, m.header.actor)).or_insert_with(|| holds_right(core, p, pc, a, &m.header)) {
                break;
            }
        }
        if !rights.is_empty() && !rights.values().any(|r| *r) {
            return Err(Error::Permission { tid: *item.tid() });
        }
    }
    Ok(())
}

/// Whether request `pc` (header `p`) drops delta `a` of commit `c` (header `ch`).
pub(crate) fn stands(core: &Core, p: &Header, pc: &CommitId, a: &AspectEntry, ch: &Header, c: &CommitId) -> bool {
    names(p, a, ch, c) && holds_right(core, p, pc, a, ch)
}

/// Whether a request with header `p` is signed by ones that could ever hold the right over delta
/// `a` of a commit with header `ch`: `holds_right` with roles of any validity at any time, so held
/// inputs only widen it.
fn signers_could(core: &Core, p: &Header, a: &AspectEntry, ch: &Header) -> bool {
    let (held, by, actor) = (&core.ix.held, a.retention.by, ch.actor);
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
/// §5, a lasting header): a permanent delta of it on such a thing is dropped, or its purge request
/// dropped one there (`purge_one` notes it: a new node needs the request to hold a copy of the
/// delta that comes back as purged). Noted, not walked: a writer's aspect-wide request naming nothing it may purge
/// would walk the aspect on every pass.
pub(crate) fn lasting(tx: &mut Tx<'_>, id: &CommitId, on: &dyn Fn(&Core, &Tid) -> bool) -> Result<bool> {
    let Some(m) = tx.core.ix.commits.get(id).cloned() else { return Ok(false) };
    let now = tx.now().0;
    if m.header.aspects.iter().enumerate().any(|(ai, a)| (m.stripped.contains(&ai) || m.dropped.contains_key(&ai)) && on(tx.core, &a.tid) && super::history::permanent(tx.core, &m.header, a, now)) {
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
fn note_request(tx: &mut Tx<'_>, key: &[u8], pc: &CommitId) -> Result<()> {
    let mut b = tx.txn.get_local(key)?.unwrap_or_default();
    if b.chunks(32).any(|x| x == pc.0) {
        return Ok(());
    }
    b.extend_from_slice(&pc.0);
    tx.txn.put_local(key, &b, Shred::No)?;
    Ok(())
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
        PurgeItem::Author { actor, .. } => core.ix.commits.get(c).is_some_and(|m| m.view.actor == *actor),
        _ => true,
    };
    held.take_while(|x| stamped_before(at, item.ak(), x.0)).map(|x| x.1).filter(by).collect()
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

/// Is aspect `ai` of commit `c` (not applied yet) already purged by a held request?
pub(crate) fn known_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    let requests = requests_on(tx, a, c)?;
    Ok(requests.iter().any(|(pc, p)| stands(tx.core, p, pc, a, ch, c)))
}

/// Whether a held purge request names delta `ai` of `c`, signed by one that could ever hold the
/// right (`Held::ever_holders`). Unlike `known_purged` it reads no validity, so a demotion
/// arriving later changes nothing here.
pub(crate) fn counts_as_purged(tx: &mut Tx<'_>, ch: &Header, c: &CommitId, ai: usize) -> Result<bool> {
    let Some(a) = ch.aspects.get(ai) else { return Ok(false) };
    Ok(requests_on(tx, a, c)?.iter().any(|(_, p)| could_stand(tx.core, p, a, ch, c)))
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
        let by_name = self.named.get(c).into_iter().flatten().find(|(pc, p)| stamped_before(p.ts, &a.ak, ch.ts) && holds_right(core, p, pc, a, ch));
        if let Some((pc, _)) = by_name {
            return Some(*pc);
        }
        let actor = ch.actor;
        let wide = &self.wide;
        let newest = self.newest.entry((a.retention.by as u64, actor)).or_insert_with(|| {
            let on = wide.iter().filter(|x| !matches!(&x.1, PurgeItem::Author { actor: of, .. } if *of != actor));
            on.filter(|x| holds_right(core, &x.2, &x.0, a, ch)).map(|x| (x.2.ts, x.0)).max()
        });
        newest.filter(|n| stamped_before(n.0, &a.ak, ch.ts)).map(|n| n.1)
    }
}

/// Judges the held purge requests on `(tid, ak)` again (spec/permissions.md §6): a part one now
/// drops is purged as on arrival; one held value-less for a purge that none drops any more
/// counts as never received from here on: off the value-less list, its leftover set aside
/// (`unstrip`) and its writes gone from the state until a copy comes (node-sync fetches it,
/// `Changed::undropped`; a holder uploads it). A body stripped for carrying others' values stays held
/// as its leftover (spec/permissions.md §6); no request names a snapshot (`names`). Cost: the aspect's requests
/// and what they name, its snapshots' views, and with an aspect-wide request a walk of its parts, as
/// `validity::rejudge_once` walks them (`scale::purge_rejudge_is_linear_in_requests_spec_permissions_6`). A memory delta purged stays
/// purged: no fall restores it (a divergence, notes/ephemeral.md Divergences left).
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
    // with no aspect-wide request only the named parts can flip, so a role change costs the
    // aspect's requests, not its length
    let parts = requests.may_name(core, tid, ak);
    let parts: BTreeSet<(Ts, CommitId)> = parts.into_iter().filter_map(|c| Some((core.ix.commits.get(&c)?.view.ts, c))).collect();
    // `quiet`: parts with writes no standing request takes
    let (mut rise, mut quiet, mut back) = (Vec::new(), Vec::new(), Vec::new());
    for (_, c) in parts {
        let Some(m) = core.ix.commits.get(&c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        let Some(a) = m.header.aspects.get(ai) else { continue };
        // past its expiry, or a signal's past its keep bound, it goes whatever the requests say
        if m.header.expires.is_some_and(|t| t <= now) || super::past_signal_bound(core, &m.header, ai, now) {
            continue;
        }
        // no request names a snapshot (`names`)
        if writes_of(&m.header, &c, ai).is_empty() {
            continue;
        }
        match requests.standing(core, a, &m.header, &c) {
            Some(pc) if gone_of(core, &m.header, &c, ai).is_empty() => rise.push((pc, c, ai)),
            Some(_) => {}
            None => quiet.push((c, ai)),
        }
    }
    let mut purged = BTreeSet::new();
    for (pc, c, ai) in rise {
        purge_one(tx, &pc, &c, ai, &mut purged)?;
    }
    purged_changed(tx, purged, changed);
    let mut leaving = Vec::new();
    for (c, ai) in quiet {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let going = gone_of(tx.core, &m.header, &c, ai);
        if going.is_empty() {
            continue;
        }
        // dropped as covered it stays so: its cover's copies are its writes while one carries it
        if m.stripped.contains(&ai) || m.missing.contains(&ai) || m.dropped.get(&ai).is_some_and(|d| !d.as_cover()) {
            back.push((c, ai));
        }
        leaving.extend(going);
    }
    if leaving.is_empty() && back.is_empty() {
        return Ok(());
    }
    // a body stripped for carrying others' values (a snapshot; a delta carrying a copy) stays held
    // as its leftover: its copies of the values coming back stay value-less, so the valued copy
    // wins wherever one joins (spec/crdt.md §4.7 Join), and every other write it carries stays
    off_valueless(tx, tid, ak, &leaving);
    // until each comes back, this node may read less than one that kept it
    suspect::raise(tx, tid, ak, suspect::Why::Uncovered, &back)?;
    for (c, ai) in back {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        if m.stripped.contains(&ai) {
            // never received until a copy comes; its leftover set aside for a rise before one
            unstrip(tx, &c, ai, true)?;
            refetch(tx, &c);
        } else if m.missing.contains(&ai) {
            refetch(tx, &c);
        } else {
            reopen_to_fetch(tx, &c, ai)?;
        }
        tx.core.mark_changed(c);
    }
    if leaving.is_empty() {
        return Ok(());
    }
    crate::apply::rebuild(tx, tid, ak)?;
    changed.insert((*tid, ak.clone()));
    Ok(())
}

/// Applies request `pc` to held delta `(c, ai)` if it stands: its values go value-less, its body and
/// every held body carrying them are held as their leftovers (node-sync re-snapshots where no
/// covering snapshot is left, spec/commits.md §5, `apply_request`).
pub(super) fn purge_one(tx: &mut Tx<'_>, pc: &CommitId, c: &CommitId, ai: usize, changed: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    let (Some(p), Some(m)) = (tx.core.ix.commits.get(pc), tx.core.ix.commits.get(c)) else { return Ok(()) };
    let Some(a) = m.header.aspects.get(ai) else { return Ok(()) };
    if !stands(tx.core, &p.header, pc, a, &m.header, c) {
        return Ok(());
    }
    let m = m.clone();
    let Some(a) = m.header.aspects.get(ai).cloned() else { return Ok(()) };
    // the part may have gone already, for another reason: its entry now reads purged
    tx.core.commits_named(a.tid, a.ak.clone(), *c);
    // a lasting header from now on (`lasting`), whichever came first
    if super::history::permanent(tx.core, &m.header, &a, tx.now().0) {
        tx.txn.put_local(&records::named_permanent_key(pc, &a.tid), &[], Shred::No)?;
        tx.core.mark_changed(*pc);
    }
    // every held body carrying the purged values, snapshots included, is stripped of them by the
    // rebuild this runs (`apply::rebuild`, spec/commits.md §5)
    hold_valueless(tx, c, ai, true, changed)
}

/// Request `id` (header `h`) just applied: against the held deltas it names, then on the lists later
/// ones find it by. Each named aspect goes to node-sync with the named bodies applied here before
/// (`Changed::purges`): a writer re-snapshots unless a snapshot the purge left whole covers them
/// all (spec/commits.md §5 Purge).
pub(super) fn apply_request(tx: &mut Tx<'_>, id: &CommitId, h: &Header, purged: &mut BTreeSet<(Tid, Ak)>) -> Result<()> {
    for item in &h.purge {
        // one that is not by name asks of every delta: the right once per class and actor, so a
        // request with none costs a look per delta
        let mut rights: BTreeMap<(u64, Tid), bool> = BTreeMap::new();
        let mut held = BTreeSet::new();
        for c in named_by(tx.core, item, h.ts) {
            let core = &*tx.core;
            let Some((m, ai)) = core.ix.commits.get(&c).and_then(|m| Some((m, m.aspect(item.tid(), item.ak())?))) else { continue };
            let Some(a) = m.header.aspects.get(ai) else { continue };
            // applied here: held, or dropped as covered (its writes in the state through its cover)
            if m.view.kind.has_own_writes() && (!m.body_gone(ai) || m.dropped.get(&ai).is_some_and(|d| d.as_cover())) {
                held.insert(c);
            }
            if matches!(item, PurgeItem::Commit { .. }) || *rights.entry((a.retention.by as u64, m.header.actor)).or_insert_with(|| holds_right(core, h, id, a, &m.header)) {
                purge_one(tx, id, &c, ai, purged)?;
            }
        }
        if let Some(ch) = &mut tx.core.changed {
            ch.purges.entry((*item.tid(), item.ak().clone())).or_default().extend(held);
        }
    }
    Ok(())
}

/// Notes request `id` (header `h`) on the lists later deltas find it by (`requests_on`), before
/// its commit's joins: a kill and the request naming the killed body in one commit purges it,
/// its leftover bare, so no cover drops it.
pub(crate) fn note_requests(tx: &mut Tx<'_>, id: &CommitId, h: &Header) -> Result<()> {
    for item in &h.purge {
        let key = match item {
            PurgeItem::Commit { commit, tid, ak } => records::purges_named_key(tid, ak, commit),
            _ => records::aspect_key(records::PURGES, item.tid(), item.ak()),
        };
        note_request(tx, &key, id)?;
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
        let dropped: Vec<CommitId> = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|c| core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.body_gone(ai)))).collect();
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
    /// §6), held or not.
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
    pub fn named_by_a_fallen_purge(&mut self, c: &CommitId, parts: &[usize]) -> Result<bool> {
        let c = *c;
        self.run(|tx| {
            let Some(h) = tx.core.ix.commits.get(&c).map(|m| m.header.clone()) else { return Ok(false) };
            for ai in parts {
                let Some(a) = h.aspects.get(*ai) else { continue };
                let requests = requests_on(tx, a, &c)?;
                if requests.iter().any(|(pc, p)| could_stand(tx.core, p, a, &h, &c) && !holds_right(tx.core, p, pc, a, &h)) {
                    return Ok(true);
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
