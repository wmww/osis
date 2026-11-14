//! The judgement of one body at S and of S's destruction, from the ground's values alone: what it
//! is (`Verdict`) and the acts it calls for now (`Act`). Pure reads: `Read` runs these inside its
//! effects and acts on what a new value adds.

use super::ground::{Facts, Ground, Seen, SrcView};
use super::{Verdict, Why};
use crate::store::{Source, Stand};
use crate::types::{ConnId, Entry, Result};
use osis_base::format::MAX_DRIFT_MS;
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId};
use osis_engine::sync::{BodyMeta, ReadCredentials};
use osis_label::StepId;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// One thing read does (spec/sync-judgement.md §3-§5).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Act {
    /// A fresh encryption of the body into the own store (§3 Own store).
    Log,
    /// The entry leaves the own log (§3 Own store: must-not-hold, or covered and dropped).
    DropOwn(BlobId),
    /// The body counts missing again: its own tombstone ends (§4, §3 Dropped bodies).
    Lift(BlobId),
    /// A Delete at a source keeping S unread, by its head's delete key (§3 Deletes, §5 Emptying).
    Delete { at: Source, conn: ConnId, head: StepId, blob: BlobId },
    /// Logged again once past a delete at the source (§4): `old` leaves the own log.
    Again { at: Source, conn: ConnId, head: StepId, ground: u64, old: Vec<BlobId> },
    /// A held entry relayed or deposited at a source this node does not stamp for (§3 Reader
    /// that is not a writer).
    Deposit { at: Source, conn: ConnId, blob: BlobId },
    /// §5: S emptied and heard out; forget it, then the thing's secrets.
    Forget,
    /// §5 Untold: leave S deleting nothing.
    Leave,
}

/// One body's judgement at S.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Judged {
    pub verdict: Verdict,
    /// An own role commit S must hold (what Role entries first waits for).
    pub role: bool,
    pub acts: BTreeSet<Act>,
    /// Nothing of the body is under S here or at a source: no longer followed.
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

/// What a judgement reads of read's own stamped state.
pub(crate) struct Mine<'a> {
    pub roles: &'a Stamped<SyncId, BTreeSet<CommitId>>,
    pub told: &'a Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    pub left: &'a StampedSet<SyncId>,
}

/// spec/sync-judgement.md §2: what the body is at S.
fn classify(f: &Facts, meta: &BodyMeta, now: u64, later_held: bool) -> Verdict {
    if let Some(w) = f.must_not {
        return Verdict::MustNot(w);
    }
    if meta.expires.is_some_and(|e| e.0 <= now) {
        return Verdict::MustNot(Why::Expired);
    }
    if !f.body.required {
        return Verdict::MustNot(Why::OutsideRequired);
    }
    // not held here (dropped): a body dropped as invalid is never deleted at a peer
    // (spec/permissions.md §6), one dropped as covered leaves by the own-store rule
    if f.body.dropped.is_some() {
        return Verdict::May;
    }
    if meta.header_only {
        return if f.body.lasting_header { Verdict::Must } else { Verdict::May };
    }
    if !f.body.closure {
        return if f.body.sole_certificate { Verdict::May } else { Verdict::Must };
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
/// spec/sync-compaction.md §1 Carriers): a held valid snapshot covers it, its keep-at-least bound
/// is past, and each delta needing a carrier has one held there.
fn covered_dropped(f: &Facts, mut held: impl FnMut(&CommitId) -> Result<bool>) -> Result<bool> {
    if f.body.covered != Some(true) || f.body.kept {
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

/// Whether a source with `seen` holds an entry of `c`.
fn present(g: &mut impl Ground, at: &Source, s: &SyncId, c: &CommitId) -> Result<bool> {
    Ok(!g.seen(at, s, c)?.present.is_empty())
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

/// §4: the stand lets the body be logged again at a source on `head` with ground `mark`.
fn stand_allows(stand: Option<&Stand>, head: &StepId, mark: u64) -> bool {
    stand.is_none_or(|st| st.head != *head || ground_mark(st) != Some(mark))
}

pub(crate) fn ground_bytes(mark: u64) -> Vec<u8> {
    mark.to_be_bytes().to_vec()
}

fn ground_mark(st: &Stand) -> Option<u64> {
    st.ground.get(..8).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes)
}

/// One body at S: its verdict and the acts it calls for.
pub(crate) fn body(g: &mut impl Ground, mine: &Mine, s: &SyncId, c: &CommitId) -> Result<Judged> {
    osis_base::costs::count("read: judged", 1);
    let mut j = Judged { verdict: Verdict::Unjudged, role: false, acts: BTreeSet::new(), idle: false };
    if mine.left.contains(s) {
        j.idle = true;
        return Ok(j);
    }
    let bodies = g.bodies(c)?;
    let own = g.own(s, c)?;
    let sources = g.sources(s)?;
    let told = mine.told.get(s).cloned();
    let (f, verdict) = match bodies.get(s) {
        None => (None, Verdict::MustNot(Why::OutsideRequired)),
        Some(meta) => {
            let f = g.facts(s, c)?;
            let mut later_held = false;
            for (snap, invalid) in &f.later_unheld {
                // one this node judged invalid does not count (never-quiet)
                if *invalid {
                    continue;
                }
                if !g.own(s, snap)?.is_empty() {
                    later_held = true;
                    break;
                }
                for src in sources.iter() {
                    if present(g, &src.at, s, snap)? {
                        later_held = true;
                        break;
                    }
                }
            }
            let mut v = classify(&f, meta, g.now().0, later_held);
            if told.as_ref().is_some_and(|req| !req.contains(c)) {
                v = Verdict::MustNot(Why::Emptied);
            }
            (Some(f), v)
        }
    };
    j.verdict = verdict.clone();
    j.role = matches!(verdict, Verdict::Must) && f.as_ref().is_some_and(|f| f.own && f.role);
    // a body counting missing again: its own tombstones end, so it is fetched again
    if f.as_ref().is_some_and(|f| f.missing) {
        j.acts.extend(g.own_tombstones(s, c)?.into_iter().map(Act::Lift));
    }
    if matches!(verdict, Verdict::Unjudged) {
        return Ok(j);
    }
    // own store (§3 Own store): it follows this node's judgement alone, no delete key needed
    let dropped_here = match &f {
        Some(f) => covered_dropped(f, |x| Ok(!g.own(s, x)?.is_empty()))?,
        None => false,
    };
    if matches!(verdict, Verdict::MustNot(_)) || dropped_here {
        j.acts.extend(own.iter().map(|e| Act::DropOwn(e.blob)));
    }
    let neither = f.as_ref().is_some_and(|f| f.neither);
    if matches!(verdict, Verdict::Must) && own.is_empty() && !neither {
        j.acts.insert(Act::Log);
    }
    // sources: only those keeping S unread (§3 Between readers: nothing but streams)
    let mut held_anywhere = !own.is_empty();
    let creds = g.credentials(s)?;
    for src in sources.iter() {
        let seen = g.seen(&src.at, s, c)?;
        held_anywhere |= !seen.present.is_empty();
        if !src.store || matches!(verdict, Verdict::MustNot(Why::Emptied)) {
            continue;
        }
        let (Some(head), Some(creds)) = (src.head, creds.as_deref()) else { continue };
        let keys = creds.keys.get(&head);
        if let Some(f) = &f {
            at_source(g, mine, &mut j, src, &seen, &own, s, c, f, head, creds, keys.is_some_and(|k| k.write.is_some()))?;
        }
        if keys.and_then(|k| k.delete.as_ref()).is_some() && !seen.present.is_empty() {
            deletes(g, mine, &mut j, src, &seen, s, c, f.as_ref(), &verdict, head, creds)?;
        }
    }
    j.idle = bodies.get(s).is_none() && !held_anywhere;
    Ok(j)
}

/// Deletes at a source keeping S unread (§3 Deletes, Agreement of grounds; compaction §1
/// Carriers, Duplicates), while no role entry of this node's is lacking there and its stream
/// shows no role commit this node does not hold.
#[allow(clippy::too_many_arguments)]
fn deletes(g: &mut impl Ground, mine: &Mine, j: &mut Judged, src: &SrcView, seen: &Seen, s: &SyncId, c: &CommitId, f: Option<&Facts>, verdict: &Verdict, head: StepId, creds: &ReadCredentials) -> Result<()> {
    let why = match verdict {
        // an expired entry leaves every store by itself
        Verdict::MustNot(Why::Expired) => return Ok(()),
        Verdict::MustNot(_) => true,
        // a carrier it lacks counts as held at a full source: it takes it with the delete
        _ => match f {
            Some(f) => covered_dropped(f, |x| Ok(src.full || present(g, &src.at, s, x)?))?,
            None => false,
        },
    };
    let blobs: Vec<BlobId> = if why {
        seen.present.iter().copied().collect()
    } else if seen.present.len() > 1 {
        // of two entries of one body, the higher goes
        seen.present.iter().next_back().copied().into_iter().collect()
    } else {
        return Ok(());
    };
    if src.role_unheld || role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    j.acts.extend(blobs.into_iter().map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob }));
    Ok(())
}

/// A must-hold body the source lacks (§3 Reader that is not a writer; §4 Logged again once).
#[allow(clippy::too_many_arguments)]
fn at_source(g: &mut impl Ground, mine: &Mine, j: &mut Judged, src: &SrcView, seen: &Seen, own: &[Entry], s: &SyncId, c: &CommitId, f: &Facts, head: StepId, creds: &ReadCredentials, writer: bool) -> Result<()> {
    if !matches!(j.verdict, Verdict::Must) || !seen.present.is_empty() || f.neither {
        return Ok(());
    }
    let standing: Vec<&Entry> = own.iter().filter(|e| !seen.deleted.contains(&e.blob)).collect();
    if let Some(e) = standing.first() {
        // a writer's own store is pulled; a non-writer gives it
        if !writer {
            j.acts.insert(Act::Deposit { at: src.at, conn: src.conn, blob: e.blob });
        }
        return Ok(());
    }
    if own.is_empty() {
        return Ok(());
    }
    // every own entry of it was deleted there: logged again once per change of ground
    let expires = g.bodies(c)?.get(s).and_then(|m| m.expires);
    if expires.is_some_and(|e| e.0 <= g.now().0.saturating_add(MAX_DRIFT_MS)) {
        return Ok(());
    }
    let mark = g.fall_mark(s, c)?;
    if !stand_allows(g.stand(&src.at, s, c)?.as_ref(), &head, mark) {
        return Ok(());
    }
    if !f.role && role_wait(g, mine, src, s, c, creds)? {
        return Ok(());
    }
    j.acts.insert(Act::Again { at: src.at, conn: src.conn, head, ground: mark, old: own.iter().map(|e| e.blob).collect() });
    Ok(())
}

/// S's destruction (§5): told once an entry of each destroying request is held at a source (at
/// once for one by expiry alone), and from then on; untold past every request's expiry.
pub(crate) fn doom(g: &mut impl Ground, told_before: bool, s: &SyncId) -> Result<(Doom, BTreeSet<Act>)> {
    osis_base::costs::count("read: doom", 1);
    let mut acts = BTreeSet::new();
    let Some(d) = g.destruction(s)? else { return Ok((Doom::Alive, acts)) };
    let requests: BTreeSet<CommitId> = d.requests.iter().copied().collect();
    let sources = g.sources(s)?;
    // per source: the blobs of the requests it holds, and whether it holds each
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
        let mut over = true;
        for r in &requests {
            let exp = g.bodies(r)?.get(s).and_then(|m| m.expires);
            over &= exp.is_some_and(|e| e.0 <= g.now().0);
        }
        if over {
            acts.insert(Act::Leave);
        }
        return Ok((Doom::Untold, acts));
    }
    let creds = g.credentials(s)?;
    let newest = creds.as_ref().and_then(|c| c.head.as_ref().map(|h| h.id()));
    let delete_key = |creds: &Option<Arc<ReadCredentials>>, h: &StepId| creds.as_ref().and_then(|c| c.keys.get(h)).is_some_and(|k| k.delete.is_some());
    let holder = newest.is_some_and(|h| delete_key(&creds, &h));
    let mut empty = true;
    for src in sources.iter() {
        let all = g.seen_all(&src.at, s)?;
        let keep = holds_all.get(&src.at);
        // deleted only where the source holds every request: it is told there first
        let (Some(keep), true, Some(head)) = (keep, src.store, src.head) else { continue };
        if holder && delete_key(&creds, &head) {
            acts.extend(all.iter().filter(|b| !keep.contains(*b)).map(|blob| Act::Delete { at: src.at, conn: src.conn, head, blob: *blob }));
        }
        if !all.is_empty() {
            empty = false;
        }
    }
    if !holder || (empty && g.heard_out(s)? && !g.deletes_known(s)? && g.own_empty(s)?) {
        acts.insert(Act::Forget);
    }
    Ok((Doom::Told { requests: Arc::new(requests) }, acts))
}
