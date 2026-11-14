//! The judgement of one body at S (`body`), of what it calls for at one source keeping S unread
//! (`toward`), and of S's destruction (`doom`), from the ground's values alone. Pure reads: `Read`
//! runs these inside its effects and acts on what a new value adds.

use super::ground::{Facts, Ground, Seen, SrcView};
use super::{Verdict, Why};
use crate::store::{Source, Stand};
use crate::types::{ConnId, Result};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::memo::{Clock, Stamped};
use osis_base::{BlobId, CommitId, SyncId};
use osis_engine::sync::{BodyMeta, ReadCredentials};
use osis_label::StepId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One thing read does (spec/sync-judgement.md §3-§5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Act {
    /// The body into the own store (§3 Own store).
    Log,
    /// The entry leaves the own log (§3 Own store: must-not-hold, or covered and dropped).
    DropOwn(BlobId),
    /// The body counts missing again: its own tombstone ends (§4, §3 Dropped bodies).
    Lift(BlobId),
    /// A Delete at a source keeping S unread, by its head's delete key (§3 Deletes, §5 Emptying).
    Delete { at: Source, conn: ConnId, head: StepId, blob: BlobId },
    /// Logged again once past a delete at the source (§4), a fresh encryption: `old` leaves the
    /// own log; the stand records `head` and `fall`.
    Again { at: Source, conn: ConnId, head: StepId, fall: u64, old: Vec<BlobId> },
    /// The body given to a source this node does not stamp for (§3 Reader that is not a writer).
    Deposit { at: Source, conn: ConnId, blob: BlobId },
    /// §5: S left (emptied and heard out, no delete key, or untold): forget it, then the thing's
    /// secrets.
    Forget,
}

/// One body's judgement at S, and what it calls for in the own store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Judged {
    pub verdict: Verdict,
    /// An own role commit S must hold (what Role entries first waits for).
    pub role: bool,
    pub acts: BTreeSet<Act>,
    /// Nothing of the body is under S here or at a source: no longer followed.
    pub idle: bool,
}

impl Default for Judged {
    fn default() -> Self {
        Judged { verdict: Verdict::Unjudged, role: false, acts: BTreeSet::new(), idle: false }
    }
}

/// What one body at S calls for at one source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Toward {
    pub acts: BTreeSet<Act>,
    /// Nothing to do there and nothing of it shown there: no longer followed.
    pub idle: bool,
}

/// S's destruction as judged here (§5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Doom {
    #[default]
    Alive,
    /// Destroyed, not told (yet): S syncs as any.
    Untold,
    /// Told: every entry but the destroying requests is must-not-hold.
    Told { requests: Arc<BTreeSet<CommitId>> },
}

/// What a judgement reads of read's own state.
pub(crate) struct Mine<'a> {
    pub verdicts: &'a Stamped<(SyncId, CommitId), Verdict>,
    pub roles: &'a Stamped<SyncId, BTreeSet<CommitId>>,
    pub told: &'a Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    pub clock: &'a Clock,
}

impl Mine<'_> {
    /// `t` has come (the answer moves when the clock reaches it).
    fn reached(&self, t: u64) -> bool {
        t <= self.clock.until(Some(t))
    }
}

/// spec/sync-judgement.md §2: what the body is at S.
fn classify(mine: &Mine, f: &Facts, meta: &BodyMeta, later_held: bool) -> Verdict {
    if let Some(w) = f.must_not {
        return Verdict::MustNot(w);
    }
    if meta.expires.is_some_and(|e| mine.reached(e.0)) {
        return Verdict::MustNot(Why::Expired);
    }
    if !f.body.required {
        return Verdict::MustNot(Why::OutsideRequired);
    }
    // not held here (dropped): kept by none of must-hold's clauses
    if f.body.dropped.is_some() {
        return Verdict::May;
    }
    // a certificate, header-only or not: must-hold but a sole one (its author has no other blob)
    if meta.certificate || !f.body.closure {
        return if f.body.sole_certificate { Verdict::May } else { Verdict::Must };
    }
    if meta.header_only {
        return if f.body.lasting_header { Verdict::Must } else { Verdict::May };
    }
    if f.body.kept {
        return Verdict::Must;
    }
    match f.body.covered {
        None => Verdict::Unjudged,
        Some(false) if !later_held => Verdict::Must,
        Some(_) => Verdict::May,
    }
}

/// Covered and dropped where `held` says which commits are held (spec/sync-judgement.md §3,
/// spec/sync-compaction.md §1 Carriers): a may-hold body a held valid snapshot covers, past its
/// keep-at-least bound, each delta needing a carrier having one held there. A must-hold body
/// (a certificate, a lasting header) is must-hold whatever snapshot covers it.
fn covered_dropped(v: &Verdict, f: &Facts, mut held: impl FnMut(&CommitId) -> Result<bool>) -> Result<bool> {
    if *v != Verdict::May || f.body.covered != Some(true) || f.body.kept {
        return Ok(false);
    }
    for alternatives in &f.carriers {
        let mut any = false;
        for c in alternatives {
            if held(c)? {
                any = true;
                break;
            }
        }
        if !any {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One body at S: its verdict and what it calls for in the own store.
pub(crate) fn body(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId) -> Result<Judged> {
    osis_base::costs::count("read: judged", 1);
    let mut j = Judged::default();
    if !g.reads(s)? {
        j.idle = true;
        return Ok(j);
    }
    let bodies = g.bodies(c)?;
    let own = g.own(s, c)?;
    let (f, verdict) = match bodies.get(s) {
        None if !g.closure_settled(s)? => (None, Verdict::Unjudged),
        None => (None, Verdict::MustNot(Why::OutsideRequired)),
        Some(meta) => {
            let f = g.facts(s, c)?;
            let mut later_held = false;
            // one this node judged invalid does not count (never-quiet)
            for (snap, invalid) in &f.later_unheld {
                if !*invalid && (!g.own(s, snap)?.is_empty() || g.present_anywhere(s, snap)?) {
                    later_held = true;
                    break;
                }
            }
            let mut v = classify(mine, &f, meta, later_held);
            if mine.told.get(s).is_some_and(|req| !req.contains(c)) {
                v = Verdict::MustNot(Why::Emptied);
            }
            (Some(f), v)
        }
    };
    j.verdict = verdict.clone();
    j.role = verdict == Verdict::Must && f.as_ref().is_some_and(|f| f.own && f.role);
    // a body counting missing again: its own tombstones end, so it is fetched again
    if f.as_ref().is_some_and(|f| f.missing) {
        j.acts.extend(g.own_tombstones(s, c)?.into_iter().map(Act::Lift));
    }
    j.idle = bodies.get(s).is_none() && own.is_empty() && !g.present_anywhere(s, c)?;
    if verdict == Verdict::Unjudged {
        return Ok(j);
    }
    // own store (§3 Own store): it follows this node's judgement alone, no delete key needed
    let dropped_here = match &f {
        Some(f) => covered_dropped(&verdict, f, |x| Ok(!g.own(s, x)?.is_empty()))?,
        None => false,
    };
    if matches!(verdict, Verdict::MustNot(_)) || dropped_here {
        j.acts.extend(own.iter().map(|e| Act::DropOwn(e.blob)));
    }
    let neither = f.as_ref().is_some_and(|f| f.neither);
    if verdict == Verdict::Must && own.is_empty() && !neither && g.pullable(s)? {
        j.acts.insert(Act::Log);
    }
    Ok(j)
}

/// What a body at S calls for at the source at `at` (§3 At a source keeping S unread; §4).
/// Between readers nothing but streams: a source reading S calls for nothing.
pub(crate) fn toward(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId, at: &Source) -> Result<Toward> {
    osis_base::costs::count("read: toward", 1);
    let mut t = Toward::default();
    let src = match g.source(s, at)? {
        Some(src) if src.store => src,
        _ => {
            t.idle = true;
            return Ok(t);
        }
    };
    let seen = g.seen(at, s, c)?;
    let verdict = mine.verdicts.get(&(*s, *c)).cloned().unwrap_or(Verdict::Unjudged);
    let creds = g.credentials(s)?;
    let keys = src.head.and_then(|h| creds.as_ref()?.keys.get(&h).cloned());
    let writer = keys.as_ref().is_some_and(|k| k.write.is_some());
    let quiet = seen.present.is_empty() && seen.deleted.is_empty();
    t.idle = quiet && (writer || verdict != Verdict::Must);
    // emptying is S's (`doom`); unjudged calls for nothing yet
    if matches!(verdict, Verdict::Unjudged | Verdict::MustNot(Why::Emptied)) {
        return Ok(t);
    }
    let (Some(head), Some(creds)) = (src.head, creds.as_deref()) else { return Ok(t) };
    let f = match g.bodies(c)?.contains_key(s) {
        true => Some(g.facts(s, c)?),
        false => None,
    };
    if let Some(f) = &f {
        at_source(g, mine, &mut t, &src, &seen, s, c, f, &verdict, head, creds, writer)?;
    }
    if keys.is_some_and(|k| k.delete.is_some()) && !seen.present.is_empty() {
        deletes(g, mine, &mut t, &src, &seen, s, c, f.as_ref(), &verdict, head, creds)?;
    }
    t.idle &= t.acts.is_empty();
    Ok(t)
}

/// §3 Role entries first: the source, on this node's head, not full, lacks an own role commit
/// S must hold (not present there and not deleted there; one it refused included), read from the
/// own store and the source's stream, never from what was sent. `c` itself waits for no other
/// copy of itself.
fn role_wait(g: &mut impl Ground, mine: &Mine, src: &SrcView, s: &SyncId, c: &CommitId, creds: &ReadCredentials) -> Result<bool> {
    let ours = creds.head.as_ref().map(|h| h.id());
    if src.full || src.head.is_none() || src.head != ours {
        return Ok(false);
    }
    let Some(roles) = mine.roles.get(s) else { return Ok(false) };
    for r in roles.iter().filter(|r| *r != c) {
        let own = g.own(s, r)?;
        let seen = g.seen(&src.at, s, r)?;
        if seen.present.is_empty() && !own.iter().any(|e| seen.deleted.contains(&e.blob)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Deletes at a source keeping S unread (§3 Deletes, Agreement of grounds; compaction §1
/// Carriers, Duplicates), while no role entry of this node's is lacking there and its stream
/// shows no role commit this node does not hold.
#[allow(clippy::too_many_arguments)]
fn deletes(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, seen: &Seen, s: &SyncId, c: &CommitId, f: Option<&Facts>, verdict: &Verdict, head: StepId, creds: &ReadCredentials) -> Result<()> {
    let why = match verdict {
        // an expired entry leaves every store by itself
        Verdict::MustNot(Why::Expired) => return Ok(()),
        Verdict::MustNot(_) => true,
        // a carrier it lacks counts as held at a full source: it takes it with the delete
        _ => match f {
            Some(f) => covered_dropped(verdict, f, |x| Ok(src.full || !g.seen(&src.at, s, x)?.present.is_empty()))?,
            None => false,
        },
    };
    // a body dropped as invalid is never deleted at a peer (spec/permissions.md §6)
    if f.is_some_and(|f| f.body.dropped == Some(osis_engine::engine::DropFor::Invalid)) {
        return Ok(());
    }
    let blobs: Vec<BlobId> = if why {
        seen.present.iter().copied().collect()
    } else {
        let copy = g.bodies(c)?.get(s).is_some_and(|m| m.copy);
        duplicates(g, seen, copy)?
    };
    if blobs.is_empty() || src.role_unheld || role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    t.acts.extend(blobs.into_iter().map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob }));
    Ok(())
}

/// spec/sync-compaction.md §1 Duplicates: of entries of one commit with the same delta set, both
/// copies or both not, all but the lowest blob ID go; where S's body is a per-sync-ID copy, a
/// shared blob beside a copy goes whatever its ID. An entry whose bytes are not held is none.
fn duplicates(g: &mut impl Ground, seen: &Seen, copy_body: bool) -> Result<Vec<BlobId>> {
    if seen.present.len() < 2 {
        return Ok(Vec::new());
    }
    let mut groups: BTreeMap<_, (Vec<BlobId>, Vec<BlobId>)> = BTreeMap::new();
    for b in &seen.present {
        if let Some(info) = g.blob(b)? {
            let (copies, shared) = groups.entry(info.parts).or_default();
            if info.copy { copies } else { shared }.push(*b);
        }
    }
    let mut out = Vec::new();
    for (copies, shared) in groups.into_values() {
        out.extend(copies.iter().skip(1));
        if copy_body && !copies.is_empty() {
            out.extend(shared);
        } else {
            out.extend(shared.iter().skip(1));
        }
    }
    Ok(out)
}

/// A must-hold body the source lacks (§3 Reader that is not a writer; §4 Logged again once).
#[allow(clippy::too_many_arguments)]
fn at_source(g: &mut impl Ground, mine: &Mine, t: &mut Toward, src: &SrcView, seen: &Seen, s: &SyncId, c: &CommitId, f: &Facts, verdict: &Verdict, head: StepId, creds: &ReadCredentials, writer: bool) -> Result<()> {
    if *verdict != Verdict::Must || !seen.present.is_empty() || f.neither {
        return Ok(());
    }
    let own = g.own(s, c)?;
    if let Some(e) = own.iter().find(|e| !seen.deleted.contains(&e.blob)) {
        // a writer's own store is pulled; a non-writer gives it
        if !writer {
            t.acts.insert(Act::Deposit { at: src.at, conn: src.conn, blob: e.blob });
        }
        return Ok(());
    }
    if own.is_empty() {
        return Ok(());
    }
    // every own entry of it was deleted there: logged again once per change of ground, but not a
    // body expiring within MAX_DRIFT
    let expires = g.bodies(c)?.get(s).and_then(|m| m.expires);
    if expires.is_some_and(|e| mine.reached(e.0.saturating_sub(MAX_DRIFT_MS))) {
        return Ok(());
    }
    let fall = g.fall_mark(s, c)?;
    if g.stand(&src.at, s, c)?.is_some_and(|st: Stand| st.head == head && st.fall == fall) {
        return Ok(());
    }
    if role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    t.acts.insert(Act::Again { at: src.at, conn: src.conn, head, fall, old: own.iter().map(|e| e.blob).collect() });
    Ok(())
}

/// S's destruction (§5): told once an entry of each destroying request is held at a source (at
/// once for one by expiry alone), and from then on; untold past every request's expiry.
pub(crate) fn doom(g: &mut impl Ground, mine: &Mine, told_before: bool, s: &SyncId) -> Result<(Doom, BTreeSet<Act>)> {
    osis_base::costs::count("read: doom", 1);
    let mut acts = BTreeSet::new();
    let Some(d) = g.destruction(s)? else { return Ok((Doom::Alive, acts)) };
    let requests: BTreeSet<CommitId> = d.requests.iter().copied().collect();
    let mut over = true;
    for r in &requests {
        let exp = g.bodies(r)?.get(s).and_then(|m| m.expires);
        over &= exp.is_some_and(|e| mine.reached(e.0));
    }
    let sources = g.sources(s)?;
    // per source: the blobs of the requests it holds, when it holds each
    let mut holds_all: BTreeMap<Source, BTreeSet<BlobId>> = BTreeMap::new();
    for src in sources.iter() {
        let mut blobs = BTreeSet::new();
        let mut all = true;
        for r in &requests {
            let seen = g.seen(&src.at, s, r)?;
            all &= !seen.present.is_empty();
            blobs.extend(seen.present);
        }
        if all {
            holds_all.insert(src.at, blobs);
        }
    }
    // told stays told: its requests leave at their expiry
    let told = told_before || requests.is_empty() || !holds_all.is_empty();
    if !told {
        if over {
            acts.insert(Act::Forget);
        }
        return Ok((Doom::Untold, acts));
    }
    let creds = g.credentials(s)?;
    let newest = creds.as_ref().and_then(|c| c.head.as_ref().map(|h| h.id()));
    let delete_key = |h: &StepId| creds.as_ref().and_then(|c| c.keys.get(h)).is_some_and(|k| k.delete.is_some());
    let holder = newest.is_some_and(|h| delete_key(&h));
    let mut empty = true;
    for src in sources.iter() {
        let all = g.seen_all(&src.at, s)?;
        empty &= all.is_empty();
        // deleted where the source holds every request (told there first), or once the requests
        // are past their expiry (no reader can be told any more)
        let keep = match holds_all.get(&src.at) {
            Some(keep) => keep,
            None if over => &BTreeSet::new(),
            None => continue,
        };
        let (true, Some(head)) = (src.store, src.head) else { continue };
        if holder && delete_key(&head) {
            acts.extend(all.iter().filter(|b| !keep.contains(*b)).map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob: *blob }));
        }
    }
    if !holder || (empty && g.heard_out(s)? && !g.deletes_known(s)? && g.own_empty(s)?) {
        acts.insert(Act::Forget);
    }
    Ok((Doom::Told { requests: Arc::new(requests) }, acts))
}
