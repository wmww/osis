//! Entries in this node's store to act on (spec/sync-inbox.md §2 Taking and Stamping in place,
//! §3 Sending, §4 Promotion and Clearing).
//!
//! Every entry added or changed reaches this module through the store's entry feed, and each is
//! judged by one `Effects` key over what it reads (the entry, the engine's verdicts), so a change
//! costs what it touched (`inbox-full-walk-scale`: a contact's blobs up to the caps cost a change
//! O(change)). Per entry:
//! - under an inbox this node reads: taken (`Ground::take_inbox`, judged again as what it read
//!   moves); a deposited one whose commit applied is stamped in place by a writer of the inbox,
//!   at most one blob per commit and none whose expiry is more than `INBOX_LIFETIME + 2 ×
//!   MAX_DRIFT` ahead; its dial hint kept while it lives;
//! - a deposit under a sync ID this node reads and writes: promoted (stamped, with the author's
//!   chain logged as certificate copies) once `Ground::promotable` says so and it holds a part of
//!   the commit S must hold that no other entry of S holds stamped;
//! - an own deposit: offered (`offers`, to the sources keeping S unread) until stamped or gone.
//!
//! Clearing: a node holding S's delete key keeps at most `DEPOSITS_WAITING` (and
//! `DEPOSITS_WAITING_BYTES`) of the deposits in its own store it can do nothing with, judged
//! again for S each time a deposit of S changed: O(S's deposits), which its deposit budget bounds.

use super::offers::{Offers, Target};
use super::{DialHint, Ground, Here, settled};
use crate::types::{Entry, Holding, Result};
use osis_base::format::{DEPOSITS_WAITING, DEPOSITS_WAITING_BYTES, INBOX_LIFETIME_MS, MAX_DRIFT_MS};
use osis_base::memo::{Effects, Feed, Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_engine::labeling::Certs;
use osis_engine::sync::{Promote, Taken};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Key = (SyncId, BlobId);

/// What one entry calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Act {
    /// Not held (gone, expired, never there).
    Gone,
    /// Nothing: a stamped entry of a sync ID that is no inbox here.
    Nothing,
    /// An inbox blob, and how taking it went (`None`: nothing here opens it).
    Inbox { stamped: bool, taken: Option<Taken>, commit: Option<CommitId>, dial: Option<DialHint>, expires: Option<WallMs> },
    /// A deposited inbox blob a writer stamps in place.
    StampInbox(CommitId),
    /// A deposit a writer promotes, with the author's chain.
    Promote(Certs),
    /// An own deposit: offered.
    Offer,
    /// A deposit nothing is done with yet (`never`: promotable never).
    Waiting { never: bool },
}

#[derive(Clone)]
pub(super) struct Held {
    feed: Option<Feed<Key>>,
    inbox_list: Effects<(), Arc<BTreeSet<SyncId>>>,
    inboxes: StampedSet<SyncId>,
    judged: Effects<Key, Act>,
    acts: BTreeMap<Key, Act>,
    /// The inbox blob stamped per (inbox, commit).
    stamped: Stamped<(SyncId, CommitId), BlobId>,
    /// Sync IDs a deposit of which changed: clearing judges them again.
    clear_due: BTreeSet<SyncId>,
}

impl Default for Held {
    fn default() -> Self {
        let mut inbox_list = Effects::new("inbox: inboxes");
        inbox_list.want(());
        Held { feed: None, inbox_list, inboxes: StampedSet::default(), judged: Effects::new("inbox: held"), acts: BTreeMap::new(), stamped: Stamped::default(), clear_due: BTreeSet::new() }
    }
}

impl Held {
    /// A start: every deposit held is judged once (inbox entries once the inboxes are known).
    pub(super) fn start<G: Ground>(&mut self, h: &mut Here<'_, G>, _offers: &mut Offers) -> Result<()> {
        self.feed = Some(h.store.entry_feed());
        for (s, e) in h.store.all_deposits()? {
            self.judged.want((s, e.blob));
        }
        Ok(())
    }

    pub(super) fn settle<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        if !self.inbox_list.due().is_empty() {
            let g = &mut *h.g;
            if let Some((_, now)) = settled(&mut self.inbox_list, &(), Arc::default(), || g.inboxes())? {
                let gone: Vec<SyncId> = self.inboxes.iter().filter(|s| !now.contains(*s)).copied().collect();
                for s in gone {
                    self.inboxes.remove(&s);
                }
                for s in now.iter() {
                    if self.inboxes.insert(*s) {
                        // a new inbox: each of its entries judged once
                        for e in h.store.entries(s)? {
                            self.judged.want((*s, e.blob));
                        }
                    }
                }
            }
        }
        if let Some(feed) = self.feed.as_mut() {
            for k in feed.added() {
                osis_base::costs::count("inbox: entry fed", 1);
                self.judged.want(k);
            }
        }
        for k in self.judged.due() {
            let (inboxes, stamped) = (&self.inboxes, &self.stamped);
            let now_ms = h.now;
            let moved = {
                let (g, store) = (&mut *h.g, &*h.store);
                settled(&mut self.judged, &k, Act::Gone, || judge(g, store, inboxes, stamped, now_ms, &k))?
            };
            let Some((was, now)) = moved else { continue };
            acted = true;
            if matches!(was, Some(Act::Offer)) && now != Act::Offer {
                offers.remove(&k.0, &k.1);
            }
            self.act(h, offers, &k, &now)?;
        }
        for s in std::mem::take(&mut self.clear_due) {
            acted |= self.clear(h, &s)?;
        }
        Ok(acted)
    }

    fn act<G: Ground>(&mut self, h: &mut Here<'_, G>, offers: &mut Offers, k: &Key, now: &Act) -> Result<()> {
        let (s, b) = k;
        let deposit = matches!(now, Act::StampInbox(_) | Act::Promote(_) | Act::Offer | Act::Waiting { .. }) || matches!(now, Act::Inbox { stamped: false, .. });
        if deposit || matches!(self.acts.get(k), Some(Act::Offer | Act::Waiting { .. } | Act::Inbox { stamped: false, .. })) {
            self.clear_due.insert(*s);
        }
        match now {
            Act::Gone | Act::Nothing => {
                self.judged.unwant(k);
                self.acts.remove(k);
                let held: Vec<(SyncId, CommitId)> = self.stamped.iter().filter(|(_, x)| *x == b).map(|(c, _)| *c).collect();
                for c in held {
                    self.stamped.remove(&c);
                }
                return Ok(());
            }
            Act::Inbox { stamped: true, commit: Some(c), .. } => {
                if !self.stamped.contains_key(&(*s, *c)) {
                    self.stamped.insert((*s, *c), *b);
                }
            }
            Act::StampInbox(c) => {
                if stamp(h, s, b)? {
                    self.stamped.insert((*s, *c), *b);
                }
            }
            Act::Promote(chain) => {
                if stamp(h, s, b)? {
                    osis_base::costs::count("inbox: promoted", 1);
                    h.g.log_chain(s, chain)?;
                }
            }
            Act::Offer => offers.add(*s, *b, Target::Stores),
            Act::Inbox { .. } | Act::Waiting { .. } => {}
        }
        self.acts.insert(*k, now.clone());
        Ok(())
    }

    /// Clears S's deposits past the bounds (spec/sync-inbox.md §4 Clearing deposits) when this
    /// node holds S's delete key.
    fn clear<G: Ground>(&mut self, h: &mut Here<'_, G>, s: &SyncId) -> Result<bool> {
        if h.g.signers(s, None)?.delete.is_none() {
            return Ok(false);
        }
        let mut idle = Vec::new();
        for e in h.store.deposits(s)? {
            let act = self.acts.get(&(*s, e.blob));
            if matches!(act, Some(Act::StampInbox(_) | Act::Promote(_))) {
                continue;
            }
            let Some(size) = h.store.blob_len(&e.blob)?.filter(|n| *n > 0) else { continue };
            // an invite request: an opened inbox blob not taken (a refused one is none)
            let request = matches!(act, Some(Act::Inbox { taken: Some(Taken::Waiting), .. })) && within_bound(e.expires, h.now);
            idle.push((e, size, request));
        }
        osis_base::costs::count("inbox: clearing read", idle.len() as u64);
        let (mut n, mut bytes) = (idle.len(), idle.iter().map(|(_, b, _)| *b).sum::<u64>());
        if n <= DEPOSITS_WAITING && bytes <= DEPOSITS_WAITING_BYTES as u64 {
            return Ok(false);
        }
        idle.sort_by_key(|(e, _, request)| clearing_order(e, *request, h.now));
        let mut acted = false;
        for (e, size, _) in idle {
            if n <= DEPOSITS_WAITING && bytes <= DEPOSITS_WAITING_BYTES as u64 {
                break;
            }
            h.store.drop_entry(s, &e.blob, Vec::new())?;
            n -= 1;
            bytes = bytes.saturating_sub(size);
            acted = true;
        }
        Ok(acted)
    }

    /// Dial hints of the inbox blobs held (spec/sync-inbox.md §2: for dialing only).
    pub(super) fn hints(&self) -> impl Iterator<Item = &DialHint> {
        self.acts.values().filter_map(|a| match a {
            Act::Inbox { dial: Some(d), .. } => Some(d),
            _ => None,
        })
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

/// The order deposits are cleared in (spec/sync-inbox.md §4): every deposit but the invite
/// requests first, those with no expiry or one past the bound before the rest, then earliest to
/// expire; then the invite requests, earliest to expire (an invite request counts toward the
/// bounds and goes last).
fn clearing_order(e: &Entry, request: bool, now: WallMs) -> (bool, bool, u64) {
    let t = e.expires.map_or(u64::MAX, |t| t.0);
    (request, within_bound(e.expires, now), t)
}

/// The prefix expiry is within `INBOX_LIFETIME + 2 × MAX_DRIFT` of `now` (spec/sync-inbox.md §2).
fn within_bound(expires: Option<WallMs>, now: WallMs) -> bool {
    expires.is_some_and(|t| t.0 <= now.0.saturating_add(INBOX_LIFETIME_MS + 2 * MAX_DRIFT_MS))
}

/// Deposit `b` of commit `c` holds a part of `c` S must hold that no other entry of S holds
/// stamped (spec/sync-inbox.md §4 Promotion: one stamped copy per delta).
fn adds_delta<G: Ground>(g: &mut G, store: &crate::store::Store, s: &SyncId, b: &BlobId, c: &CommitId) -> Result<bool> {
    let (Some(need), Some(mut mine)) = (g.body_parts(s, c)?, g.blob_parts(b)?) else { return Ok(false) };
    mine.retain(|p| need.contains(p));
    for x in g.commit_blobs(c)?.iter().filter(|x| *x != b) {
        if store.entry(s, x)?.is_some_and(|e| !e.deposited)
            && let Some(held) = g.blob_parts(x)?
        {
            mine.retain(|p| !held.contains(p));
        }
    }
    Ok(!mine.is_empty())
}

/// Stamps entry `b` of S in place with this node's write key: whether it did.
fn stamp<G: Ground>(h: &mut Here<'_, G>, s: &SyncId, b: &BlobId) -> Result<bool> {
    let Some(e) = h.store.entry(s, b)? else { return Ok(false) };
    let Some(w) = h.g.signers(s, None)?.stamp else { return Ok(false) };
    let stamp = osis_label::sign_stamp(&w, s, b, &e.wrap, e.role);
    let code = h.store.log(s, Entry { stamp: Some(stamp), deposited: false, ..e }, None, None)?;
    Ok(code == osis_proto::Code::OK)
}

fn judge<G: Ground>(g: &mut G, store: &crate::store::Store, inboxes: &StampedSet<SyncId>, stamped: &Stamped<(SyncId, CommitId), BlobId>, now: WallMs, k: &Key) -> Result<Act> {
    osis_base::costs::count("inbox: held judged", 1);
    let (s, b) = k;
    let Some(e) = store.entry(s, b)? else { return Ok(Act::Gone) };
    if inboxes.contains(s) {
        let o = g.take_inbox(s, b)?;
        let (taken, commit) = (o.as_ref().map(|o| o.taken), o.as_ref().map(|o| o.commit));
        if e.deposited
            && let Some(o) = &o
            && o.taken == Taken::Applied
            && within_bound(e.expires, now)
            && stamped.get(&(*s, o.commit)).is_none_or(|x| x == b)
            && g.signers(s, None)?.stamp.is_some()
        {
            return Ok(Act::StampInbox(o.commit));
        }
        let dial = o.and_then(|o| o.dial).map(|a| DialHint { key: a.key, urls: vec![a.url] });
        return Ok(Act::Inbox { stamped: !e.deposited, taken, commit, dial, expires: e.expires });
    }
    if !e.deposited {
        return Ok(Act::Nothing);
    }
    let mut never = false;
    if store.holding(s) == Some(Holding::Read)
        && g.signers(s, None)?.stamp.is_some()
        && let Some(c) = g.blob_commit(s, b)?
    {
        match g.promotable(s, &c)? {
            // one stamped copy per delta under S, however many encryptions are deposited
            Promote::Yes { .. } if !adds_delta(g, store, s, b, &c)? => {}
            Promote::Yes { chain } => return Ok(Act::Promote(chain)),
            Promote::Never => never = true,
            Promote::NotYet => {}
        }
    }
    // an own deposit under a sync ID not held is an inbox blob to another's inbox: `deliveries`'
    Ok(if e.own && store.holding(s).is_some() { Act::Offer } else { Act::Waiting { never } })
}
