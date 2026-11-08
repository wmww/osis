//! Listing commits (notes/api.md Commits): which parts of a commit are listed, each read from its
//! own body whatever the state says of it; the commits listed at a set of aspects, paged by
//! `(ts, ID)` off `by_aspect` (a page costs the places it walks, no walk of the rest); and which
//! commits changed (`Core::commit_changes`).
//!
//! The listing rule, one at every address: a part is listed while it is in its aspect's read (a
//! write of it live, `body_live`) or kept by history until its keep bound (`body_keep`), a purge
//! tombstone (its value-less writes are judged alike), or this node's own invalid write. Replaced
//! with no history kept, expired, dropped (compacted), another node's invalid write: not listed,
//! whatever this node still holds. So every node holding the same commits lists the same ones.

use super::{Engine, Tx};
use crate::error::Result;
use osis_base::{Ak, CommitId, Tid, Ts, Value, WallMs};
use osis_commit::{Header, Kind};
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};

/// A place among an aspect's commits. `CommitPos::time(ts)` is one before every commit stamped `ts`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitPos {
    pub ts: Ts,
    pub id: CommitId,
}

impl CommitPos {
    pub fn time(ts: Ts) -> CommitPos {
        CommitPos { ts, id: CommitId([0; 32]) }
    }
}

/// Where a page starts, and which way it goes: `Newest` and `Before` towards older commits,
/// `Oldest` and `After` towards newer ones. Neither bound counts itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFrom {
    Newest,
    Oldest,
    Before(CommitPos),
    After(CommitPos),
}

impl CommitFrom {
    fn newer(&self) -> bool {
        matches!(self, CommitFrom::Oldest | CommitFrom::After(_))
    }
}

/// What is here of a part's body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartBody {
    /// Its read (`None`: it holds no whole value, a removal). May hold links.
    Held(Option<Value>),
    /// Held, and past the byte bound asked for.
    TooLarge,
    /// A held purge request dropped it: the earliest by `(ts, ID)`.
    Purged(CommitId),
    /// Gone for another reason: expiry, a keep bound, compaction, invalid. Never listed.
    Dropped,
    /// Its header is here and its body is not.
    NotFetched,
}

/// One part of a commit, and what this node judged of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartRow {
    pub tid: Tid,
    pub ak: Ak,
    pub valid: bool,
    pub body: PartBody,
}

/// A commit, what its signed header says, with its listed parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRow {
    pub id: CommitId,
    pub kind: Kind,
    /// The commit it reverts (a content commit's `undoes`).
    pub undoes: Option<CommitId>,
    pub actor: Tid,
    pub node: Tid,
    pub ts: Ts,
    pub received: WallMs,
    pub parts: Vec<PartRow>,
}

/// What this node holds of one commit's part on an aspect, listed or not (`Engine::held_parts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldPart {
    pub id: CommitId,
    pub actor: Tid,
    pub ts: Ts,
    pub valid: bool,
    pub body: PartBody,
}

/// What is here of part `ai` of commit `c`, its body unread (`Here::Holds`).
enum Here {
    Holds,
    Purged(CommitId),
    Dropped,
    NotFetched,
}

/// What is here of part `ai` of commit `c`, listed or not, its body not read.
fn part_here(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Here> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(Here::Dropped) };
    // a bare leftover (expired, purged) shows as what took its values, not as its read
    let holds = m.holds(ai) && !m.bare(ai);
    let dropped = m.body_gone(ai);
    let header = m.header.clone();
    Ok(if holds {
        if past_due(&header, ai, tx.now().0) { Here::Dropped } else { Here::Holds }
    } else if let Some(by) = crate::retention::purged_by(tx, &header, c, ai)? {
        Here::Purged(by)
    } else if dropped {
        Here::Dropped
    } else {
        Here::NotFetched
    })
}

/// What is here of part `ai` of commit `c`, listed or not.
fn part_body(tx: &mut Tx<'_>, c: &CommitId, ai: usize, budget: usize) -> Result<PartBody> {
    Ok(match part_here(tx, c, ai)? {
        Here::Holds => held_body(tx, c, ai, budget)?,
        Here::Purged(by) => PartBody::Purged(by),
        Here::Dropped => PartBody::Dropped,
        Here::NotFetched => PartBody::NotFetched,
    })
}

/// Whether part `ai` of `c` on `(tid, ak)` is in kept history at wall ms `now`: a write of it in
/// the aspect's read (`body_live`: value-less writes count, so a purge tombstone of a live write
/// does) or its body kept by a keep bound (`body_keep`). By headers and the state alone.
pub(crate) fn in_kept_history(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, now: u64) -> Result<bool> {
    let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak).and_then(|ai| m.header.aspects.get(ai).cloned())) else { return Ok(false) };
    if osis_commit::retention::KeepRule::of_aspect(&a).until.is_some_and(|t| now < t) {
        return Ok(true);
    }
    Ok(crate::retention::bounds::body_live(tx, c, tid, ak)? || crate::retention::bounds::body_keep(tx, c, tid, ak)? > now)
}

/// Part `ai` of `c` as listed, `None` when it is not (the listing rule, above).
fn listed_part(tx: &mut Tx<'_>, c: &CommitId, ai: usize, budget: usize) -> Result<Option<PartRow>> {
    let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.view.aspects.get(ai)) else { return Ok(None) };
    let (tid, ak) = (a.tid, a.ak.clone());
    let Some((valid, here)) = listed(tx, c, ai)? else { return Ok(None) };
    let body = match here {
        Here::Holds => held_body(tx, c, ai, budget)?,
        Here::Purged(by) => PartBody::Purged(by),
        Here::Dropped | Here::NotFetched => PartBody::NotFetched,
    };
    Ok(Some(PartRow { tid, ak, valid, body }))
}

/// Whether part `ai` of `c` is listed, with its validity and what is here of it; its body not
/// read. A purged part is judged as if the purge had replaced it: in the read by its value-less
/// writes, else kept by its keep rule counted from the request's `ts` (its body is gone, so no
/// death of its writes can be judged from it).
fn listed(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<Option<(bool, Here)>> {
    let me = tx.core.id.tid();
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(a) = m.view.aspects.get(ai) else { return Ok(None) };
    let (tid, ak, valid, own) = (a.tid, a.ak.clone(), m.valid_at(ai), m.view.author == me);
    if !valid && !own {
        return Ok(None);
    }
    let here = part_here(tx, c, ai)?;
    let now = tx.now().0;
    let kept = match &here {
        Here::Dropped => false,
        _ if !valid => true,
        Here::Purged(by) => {
            let rule = tx.core.ix.commits.get(c).and_then(|m| m.header.aspects.get(ai).map(osis_commit::retention::KeepRule::of_aspect));
            let at = tx.core.ix.commits.get(by).map(|m| m.view.ts.wall_ms().0);
            let kept = rule.is_some_and(|k| k.until.is_some_and(|t| now < t) || k.after.zip(at).is_some_and(|(d, t)| now < t.saturating_add(d)));
            kept || crate::retention::bounds::body_live(tx, c, &tid, &ak)?
        }
        _ => in_kept_history(tx, c, &tid, &ak, now)?,
    };
    Ok(kept.then_some((valid, here)))
}

/// The commits listed on `(tid, ak)` whose listing a change of its state may turn: every one
/// but those kept by an absolute bound (`keep_history` until a time, or for good), whose
/// listing no state decides. Costs the commits held there, and a liveness read of each of the
/// rest.
fn listed_by_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeSet<CommitId>> {
    let now = tx.now().0;
    let on: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    let mut out = BTreeSet::new();
    for c in on {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        let fixed = m.header.aspects.get(ai).is_some_and(|a| osis_commit::retention::KeepRule::of_aspect(a).until.is_some_and(|t| now < t));
        if !fixed && listed(tx, &c, ai)?.is_some() {
            out.insert(c);
        }
    }
    Ok(out)
}

/// Whether a commit listener is on a thing `(tid, _)` is of: the thing, or a group it is in
/// (`Engine::listen_commits`).
fn listened(tx: &mut Tx<'_>, tid: &Tid) -> bool {
    if !tx.core.commits_watched {
        return false;
    }
    let Some(f) = tx.core.commit_listeners.clone() else { return false };
    let on = tx.core.listened.get_or_insert_with(|| f().into_iter().collect());
    on.contains(tid) || tx.core.ix.groups.of.get(tid).is_some_and(|g| g.iter().any(|g| on.contains(g)))
}

/// Before the state of `(tid, ak)` first changes in a transaction: the commits listed there by
/// it, when a commit listener may be on it (`listing_moved` compares them at the end).
pub(crate) fn before_state_change(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<()> {
    if ak.signal() || tx.core.listed_before.iter().any(|(k, _)| k.0 == *tid && k.1 == *ak) || !listened(tx, tid) {
        return Ok(());
    }
    let l = listed_by_state(tx, tid, ak)?;
    tx.core.listed_before.push(((*tid, ak.clone()), l));
    Ok(())
}

/// At the end of a transaction: each commit that entered or left the listing of an aspect whose
/// state it changed, judged against the listing before (`before_state_change`), is told
/// (`Core::commits_named`). Brute force, for aspects with a listener only: a part with no
/// history kept leaves when a later write replaces it, which changes no meta of its own.
pub(crate) fn listing_moved(tx: &mut Tx<'_>) -> Result<()> {
    for ((tid, ak), before) in std::mem::take(&mut tx.core.listed_before) {
        let after = listed_by_state(tx, &tid, &ak)?;
        for c in before.symmetric_difference(&after) {
            tx.core.commits_named(tid, ak.clone(), *c);
        }
    }
    Ok(())
}

/// Whether part `ai` of `h` is past its expiry or, a signal's, its keep bound: the next tick
/// drops it, and no read shows it until then.
fn past_due(h: &Header, ai: usize, now: u64) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    let bound = if a.ak.signal() { crate::retention::signal_bound(h, a) } else { None };
    bound.into_iter().chain(h.expires).any(|t| t <= now)
}

/// The read of a held part, its pieces joined up to `budget` bytes.
fn held_body(tx: &mut Tx<'_>, c: &CommitId, ai: usize, budget: usize) -> Result<PartBody> {
    let mut out: Option<osis_crdt::Fragment> = None;
    let mut over = false;
    crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        if over {
            return Ok(());
        }
        match &mut out {
            Some(o) => {
                o.join(f);
            }
            None => out = Some(f),
        }
        over = out.as_ref().is_some_and(|o| o.approx_bytes() > budget);
        Ok(())
    })?;
    Ok(match out {
        _ if over => PartBody::TooLarge,
        Some(f) => PartBody::Held(f.read_written()),
        None => PartBody::NotFetched,
    })
}

/// The content commit `h` reverts.
fn undoes(h: &Header) -> Option<CommitId> {
    h.undoes.filter(|_| h.kind == Kind::Content)
}

impl Engine {
    /// Turns `Event::Commits` on for this open: a transaction changing many commits then lists them
    /// all, so it stays off until someone listens. It stays on: no count to keep right.
    pub fn watch_commits(&mut self) {
        self.core.commits_watched = true;
    }

    /// `f` names the things commit listeners are on (a group's: its things too): at the end of
    /// each transaction the listing of each of their aspects whose state it changed is compared
    /// with the one before (`listing_moved`). Asked once per transaction that changes a state.
    pub fn listen_commits(&mut self, f: std::sync::Arc<dyn Fn() -> Vec<Tid> + Send + Sync>) {
        self.core.commits_watched = true;
        self.core.commit_listeners = Some(f);
    }

    /// What is here of `c`'s part on `(tid, ak)`, listed or not; `None` when it has none.
    pub fn part(&mut self, tid: &Tid, ak: &Ak, c: &CommitId, budget: usize) -> Result<Option<PartRow>> {
        let Some(m) = self.core.ix.commits.get(c) else { return Ok(None) };
        let Some(ai) = m.aspect(tid, ak) else { return Ok(None) };
        let valid = m.valid_at(ai);
        let (c, tid, ak) = (*c, *tid, ak.clone());
        self.run(|tx| Ok(Some(PartRow { tid, ak, valid, body: part_body(tx, &c, ai, budget)? })))
    }

    /// What is here of each commit's part on `(tid, ak)`, listed or not: at most `limit` from
    /// `from`, stopping early past `budget` bytes of bodies, and whether more lie that way. The
    /// engine's own view of what it holds, under the listing rule.
    pub fn held_parts(&mut self, tid: &Tid, ak: &Ak, from: CommitFrom, limit: usize, budget: usize) -> Result<(Vec<HeldPart>, bool)> {
        let mut places = self.places(&[(*tid, ak.clone())], from, limit.saturating_add(1));
        let mut more = places.len() > limit;
        places.truncate(limit);
        let mut out = Vec::with_capacity(places.len());
        let mut used = 0usize;
        for (n, p) in places.iter().enumerate() {
            if used > budget {
                more = more || n < places.len();
                break;
            }
            if let Some(h) = self.held_part(tid, ak, &p.id, budget)? {
                used = used.saturating_add(match &h.body {
                    PartBody::Held(Some(v)) => osis_base::cbor::encode(v).len(),
                    PartBody::TooLarge => usize::MAX,
                    _ => 0,
                });
                out.push(h);
            }
        }
        Ok((out, more))
    }

    /// `held_parts` of one commit; `None` when it has no part there.
    pub fn held_part(&mut self, tid: &Tid, ak: &Ak, c: &CommitId, budget: usize) -> Result<Option<HeldPart>> {
        let Some(m) = self.core.ix.commits.get(c) else { return Ok(None) };
        let (actor, ts) = (m.view.actor, m.view.ts);
        Ok(self.part(tid, ak, c, budget)?.map(|p| HeldPart { id: *c, actor, ts, valid: p.valid, body: p.body }))
    }

    /// Whether `c` has a listed part on one of `aspects`.
    pub fn listed_at(&mut self, c: &CommitId, aspects: &[(Tid, Ak)]) -> Result<bool> {
        let Some(m) = self.core.ix.commits.get(c) else { return Ok(false) };
        let on: Vec<usize> = aspects.iter().filter_map(|(t, a)| m.aspect(t, a)).collect();
        let c = *c;
        self.run(|tx| {
            for ai in on {
                if listed_part(tx, &c, ai, 0)?.is_some() {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Commit `c` with its listed parts on the things `shown` lets through, bodies read up to
    /// `budget` bytes each; `None` when its header is not held.
    pub fn commit_row(&mut self, c: &CommitId, shown: &dyn Fn(&mut Engine, &Tid) -> bool, budget: usize) -> Result<Option<CommitRow>> {
        let Some(m) = self.core.ix.commits.get(c) else { return Ok(None) };
        let (kind, actor, node, ts, received) = (m.view.kind, m.view.actor, m.view.author, m.view.ts, m.received);
        let header = m.header.clone();
        let things: Vec<(usize, Tid)> = m.view.aspects.iter().enumerate().map(|(ai, a)| (ai, a.tid)).collect();
        let on: Vec<usize> = things.into_iter().filter(|(_, t)| shown(self, t)).map(|(ai, _)| ai).collect();
        let c = *c;
        let parts = self.run(|tx| {
            let mut parts = Vec::new();
            for ai in on {
                if let Some(p) = listed_part(tx, &c, ai, budget)? {
                    parts.push(p);
                }
            }
            Ok(parts)
        })?;
        Ok(Some(CommitRow { id: c, kind, undoes: header.decoded().and_then(|h| undoes(&h)), actor, node, ts, received, parts }))
    }

    /// Up to `n` places among the commits on `aspects` past `from` in its direction, each commit
    /// once, in order.
    pub fn places(&self, aspects: &[(Tid, Ak)], from: CommitFrom, n: usize) -> Vec<CommitPos> {
        let mut all: BTreeSet<(Ts, CommitId)> = BTreeSet::new();
        for k in aspects {
            let Some(set) = self.core.ix.by_aspect.get(k) else { continue };
            let it: Box<dyn Iterator<Item = &(Ts, CommitId)>> = match from {
                CommitFrom::Newest => Box::new(set.iter().rev()),
                CommitFrom::Oldest => Box::new(set.iter()),
                CommitFrom::Before(p) => Box::new(set.range(..(p.ts, p.id)).rev()),
                CommitFrom::After(p) => Box::new(set.range((Excluded((p.ts, p.id)), Unbounded))),
            };
            all.extend(it.take(n).copied());
        }
        let pos = |x: &(Ts, CommitId)| CommitPos { ts: x.0, id: x.1 };
        if from.newer() { all.iter().take(n).map(pos).collect() } else { all.iter().rev().take(n).map(pos).collect() }
    }

    /// The held commits reverting `c` (a revert touches what its target touched, so it is among
    /// the commits on `c`'s aspects stamped after it), oldest first. A commit touching only
    /// signals has none: a revert of it writes nothing.
    pub fn reverters(&self, c: &CommitId) -> Vec<CommitId> {
        let Some(m) = self.core.ix.commits.get(c) else { return Vec::new() };
        let at = (m.view.ts, *c);
        let mut out: BTreeSet<(Ts, CommitId)> = BTreeSet::new();
        for a in m.view.aspects.iter().filter(|a| !a.ak.signal()) {
            let Some(set) = self.core.ix.by_aspect.get(&(a.tid, a.ak.clone())) else { continue };
            for x in set.range((Excluded(at), Unbounded)) {
                if !out.contains(x) && self.core.ix.commits.get(&x.1).and_then(|m| m.header.decoded()).is_some_and(|h| undoes(&h) == Some(*c)) {
                    out.insert(*x);
                }
            }
        }
        out.into_iter().map(|x| x.1).collect()
    }
}
