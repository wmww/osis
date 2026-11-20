//! Entries in this node's store to act on (spec/sync-inbox.md §3 Sending, §4 Promotion and
//! Clearing).
//!
//! Every entry added or changed reaches this module through the store's entry feed, and each is
//! judged by one `Effects` key over what it reads (the entry, the engine's verdicts), so a change
//! costs what it touched. Per entry:
//! - a deposit under a sync ID this node reads and writes that `promotion` says read promotes:
//!   kept from clearing (read stamps it in place, its own-store rule: one mechanism stamps what
//!   this node logs under S);
//! - an own deposit: offered (`offers`, to the sources keeping S unread) until stamped or gone.
//!
//! Clearing: a node holding S's delete key keeps at most `DEPOSITS_WAITING` (and
//! `DEPOSITS_WAITING_BYTES`) of the deposits in its own store it can do nothing with, judged
//! again for S each time a deposit of S changed: O(S's deposits), which its deposit budget bounds.

use super::offers::{Offers, Target};
use super::Here;
use crate::store::Store;
use crate::types::{Entry, Holding, Result};
use osis_base::format::{DEPOSITS_WAITING, DEPOSITS_WAITING_BYTES};
use osis_base::memo::{Effects, Feed};
use osis_base::{BlobId, CommitId, SyncId};
use osis_engine::Engine;
use osis_engine::sync::{Opened, PartSet, Promote, SealedSet};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Key = (SyncId, BlobId);

/// What one entry calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Act {
    /// Not held (gone, expired, never there).
    Gone,
    /// Nothing: a stamped entry.
    Nothing,
    /// A deposit read promotes (`promotion`): kept from clearing.
    Promote,
    /// An own deposit: offered.
    Offer,
    /// A deposit nothing is done with yet.
    Waiting,
}

#[derive(Clone)]
pub(super) struct Held {
    feed: Option<Feed<Key>>,
    judged: Effects<Key, Act>,
    acts: BTreeMap<Key, Act>,
    /// Sync IDs a deposit of which changed: clearing judges them again.
    clear_due: BTreeSet<SyncId>,
}

impl Default for Held {
    fn default() -> Self {
        Held { feed: None, judged: Effects::new("inbox: held"), acts: BTreeMap::new(), clear_due: BTreeSet::new() }
    }
}

impl Held {
    /// A start: every deposit held is judged once.
    pub(super) fn start(&mut self, h: &mut Here<'_>, _offers: &mut Offers) -> Result<()> {
        self.feed = Some(h.store.entry_feed());
        for (s, e) in h.store.all_deposits()? {
            self.judged.want((s, e.blob));
        }
        Ok(())
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        if let Some(feed) = self.feed.as_mut() {
            for k in feed.added() {
                osis_base::costs::count("inbox: entry fed", 1);
                self.judged.want(k);
            }
        }
        for k in self.judged.due() {
            let moved = {
                let (engine, store) = (&mut *h.engine, &*h.store);
                self.judged.try_settle(&k, || judge(engine, store, &k))?
            };
            let Some((was, now)) = moved else { continue };
            acted = true;
            if matches!(was, Some(Act::Offer)) && now != Act::Offer {
                offers.remove(&k.0, &k.1);
            }
            self.act(offers, &k, &now);
        }
        for s in std::mem::take(&mut self.clear_due) {
            acted |= self.clear(h, &s)?;
        }
        Ok(acted)
    }

    fn act(&mut self, offers: &mut Offers, k: &Key, now: &Act) {
        let (s, _) = k;
        if matches!(now, Act::Promote | Act::Offer | Act::Waiting) || matches!(self.acts.get(k), Some(Act::Offer | Act::Waiting)) {
            self.clear_due.insert(*s);
        }
        match now {
            Act::Gone | Act::Nothing => {
                self.judged.unwant(k);
                self.acts.remove(k);
                return;
            }
            Act::Offer => offers.add(*s, k.1, Target::Stores),
            Act::Promote | Act::Waiting => {}
        }
        self.acts.insert(*k, now.clone());
    }

    /// Clears S's deposits past the bounds (spec/sync-inbox.md §4 Clearing deposits) when this
    /// node holds S's delete key.
    fn clear(&mut self, h: &mut Here<'_>, s: &SyncId) -> Result<bool> {
        if h.engine.signers(s, None)?.delete.is_none() {
            return Ok(false);
        }
        let mut idle = Vec::new();
        for e in h.store.deposits(s)? {
            let act = self.acts.get(&(*s, e.blob));
            if matches!(act, Some(Act::Promote)) {
                continue;
            }
            let Some(size) = h.store.blob_len(&e.blob)?.filter(|n| *n > 0) else { continue };
            idle.push((e, size));
        }
        osis_base::costs::count("inbox: clearing read", idle.len() as u64);
        let mut acted = false;
        for b in to_clear(idle) {
            h.store.drop_entry(s, &b, Vec::new())?;
            acted = true;
        }
        Ok(acted)
    }
}

/// spec/sync-inbox.md §4 Clearing deposits: of the deposits a holder of S's delete key can do
/// nothing with (each with its size), the ones it drops to keep at most `DEPOSITS_WAITING` and
/// `DEPOSITS_WAITING_BYTES`: those with no prefix expiry first, then earliest to expire.
pub fn to_clear(mut idle: Vec<(Entry, u64)>) -> Vec<BlobId> {
    let (mut n, mut bytes) = (idle.len(), idle.iter().map(|(_, b)| *b).sum::<u64>());
    let mut out = Vec::new();
    idle.sort_by_key(|(e, _)| e.expires.map_or((false, 0), |t| (true, t.0)));
    for (e, size) in idle {
        if n <= DEPOSITS_WAITING && bytes <= DEPOSITS_WAITING_BYTES as u64 {
            break;
        }
        out.push(e.blob);
        n -= 1;
        bytes = bytes.saturating_sub(size);
    }
    out
}

/// A blob of a commit as this node judges it for promotion: the parts it opened and checked, and
/// its other sections by their bytes (`BlobOf::parts`, `BlobOf::sealed`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Judged {
    pub parts: PartSet,
    pub sealed: SealedSet,
}

/// spec/sync-inbox.md §4 Promotion: whether a deposit `mine` of a commit S must hold parts `need`
/// of adds to the entries of S holding that commit stamped (`stamped`):
/// - by a delta: a part of `need` it holds is in none of them (one stamped copy per delta);
/// - by its bytes alone: some section it did not open or check is byte-identical to none in any
///   one stamped entry, so it is no duplicate of one nor loses to one as needed, as this node judges it
///   (spec/sync-compaction.md §1 Duplicates), while no stamped entry adds only bytes (each of
///   its `need` parts held by another stamped entry): one bytes-only promotion per commit while
///   one stands.
pub fn adds_delta(need: &PartSet, mine: &Judged, stamped: &[Judged]) -> bool {
    if mine.parts.iter().any(|p| need.contains(p) && !stamped.iter().any(|x| x.parts.contains(p))) {
        return true;
    }
    let covered = |x: &Judged| mine.sealed.is_subset(&x.sealed);
    // a stamped entry promoted by its bytes alone: it holds a needed part, every one of which
    // another stamped entry holds (one holding no needed part, a certificate copy, was not)
    let bytes_only = |(i, x): (usize, &Judged)| {
        let mut needed = x.parts.iter().filter(|p| need.contains(p)).peekable();
        needed.peek().is_some() && needed.all(|p| stamped.iter().enumerate().any(|(j, y)| j != i && y.parts.contains(p)))
    };
    !mine.sealed.is_empty() && !stamped.iter().any(covered) && !stamped.iter().enumerate().any(bytes_only)
}

/// Whether read promotes deposit `b` of commit `c` under `s` (spec/sync-inbox.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Promotion {
    /// Stamped in place now.
    Yes,
    /// Not yet: the commit is not applied here, or its author's chain is not under S.
    Wait,
    /// Never as things stand: no writer here, its author lacked write, S carries nothing of it,
    /// or it adds no delta to the entries of `c` held stamped under S (`adds_delta`).
    No,
}

/// spec/sync-inbox.md §4 Promotion: whether this node, a writer of S, promotes deposited entry
/// `b` of commit `c`: the engine's word (`Engine::promotable`: applied, a body S must hold, its
/// author held write at its `ts`), the deposit adds a delta (`adds_delta`), and the author's chain
/// is under S (`chain_under`). The one judgement of it: read stamps by it, held keeps such a
/// deposit from clearing.
pub fn promotion(engine: &mut Engine, store: &Store, s: &SyncId, c: &CommitId, b: &BlobId) -> Result<Promotion> {
    if store.holding(s) != Some(Holding::Read) || engine.signers(s, None)?.stamp.is_none() {
        return Ok(Promotion::No);
    }
    let chain = match engine.promotable(s, c)? {
        Promote::Never => return Ok(Promotion::No),
        Promote::NotYet => return Ok(Promotion::Wait),
        Promote::Yes { chain } => chain,
    };
    let need = engine.sync_bodies(c)?.get(s).map(|m| m.parts.clone()).unwrap_or_default();
    let judged = |o: Arc<osis_engine::sync::BlobOf>| Judged { parts: o.parts.clone(), sealed: o.sealed.clone() };
    let mine = engine.blob_of(b).map(judged).unwrap_or_default();
    let mut others = Vec::new();
    for x in engine.commit_blobs(c)?.iter().filter(|x| *x != b) {
        if store.entry(s, x)?.is_some_and(|e| !e.deposited)
            && let Some(held) = engine.blob_of(x)
        {
            others.push(judged(held));
        }
    }
    if !adds_delta(&need, &mine, &others) {
        return Ok(Promotion::No);
    }
    Ok(if chain_under(engine, store, s, &chain)? { Promotion::Yes } else { Promotion::Wait })
}

/// Whether the author's chain `chain` of a commit is under S as S carries it (spec/sync-inbox.md
/// §4: a promoter completes the chain it holds, logging the missing deltas as its own certificate
/// copies): of each chain commit S must hold a body of, the parts of that body the chain names
/// are held by entries of S stamped or this node's own (never a deposit), and a header-only one
/// by some such entry. What S carries of the chain is in its required set, so read logs it as
/// any certificate (spec/sync-judgement.md §1); a part S does not carry is not waited for.
/// Record blobs are read's certificate blobs, not waited for here.
fn chain_under(engine: &mut Engine, store: &Store, s: &SyncId, chain: &osis_engine::sync_ids::Certs) -> Result<bool> {
    let commits = chain.commits.iter().map(|(c, p)| (*c, Some(p))).chain(chain.headers.iter().map(|c| (*c, None)));
    for (c, parts) in commits {
        let Some(meta) = engine.sync_bodies(&c)?.get(s).cloned() else { continue };
        let mut held = PartSet::new();
        let mut any = false;
        for x in engine.commit_blobs(&c)?.iter() {
            if store.entry(s, x)?.is_some_and(|e| !e.deposited) {
                any = true;
                held.extend(engine.blob_parts(x).unwrap_or_default());
            }
        }
        let complete = match parts {
            Some(p) => p.iter().filter(|ai| meta.parts.contains(*ai)).all(|ai| held.contains(ai)),
            None => any,
        };
        if !complete {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The commit deposit `b` of S holds: as opened or sealed here, else opened now (a deposit a
/// peer left is opened once, under a read S).
fn deposit_commit(engine: &mut Engine, store: &Store, s: &SyncId, e: &Entry) -> Result<Option<CommitId>> {
    if let Some(c) = engine.blob_commit(&e.blob) {
        return Ok(Some(c));
    }
    let Some(bytes) = store.bytes(&e.blob)? else { return Ok(None) };
    Ok(match crate::store::open_entry(engine, store, s, &e.blob, &e.wrap, &bytes)? {
        Opened::Commit(c, _) => Some(c),
        _ => None,
    })
}

fn judge(engine: &mut Engine, store: &Store, k: &Key) -> Result<Act> {
    osis_base::costs::count("inbox: held judged", 1);
    let (s, b) = k;
    let Some(e) = store.entry(s, b)? else { return Ok(Act::Gone) };
    if !e.deposited {
        return Ok(Act::Nothing);
    }
    let holding = store.holding(s);
    // an own deposit is offered until stamped (read stamps it once this node writes S's head)
    if e.own && holding.is_some() {
        return Ok(Act::Offer);
    }
    // a peer's deposit under a read S this node writes: whether read promotes it
    if !e.own
        && holding == Some(Holding::Read)
        && engine.signers(s, None)?.stamp.is_some()
        && let Some(c) = deposit_commit(engine, store, s, &e)?
        && promotion(engine, store, s, &c, b)? == Promotion::Yes
    {
        return Ok(Act::Promote);
    }
    Ok(Act::Waiting)
}
