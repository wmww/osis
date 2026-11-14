//! Entries in this node's store to act on (spec/sync-inbox.md §2 Taking and Stamping in place,
//! §3 Sending, §4 Promotion and Clearing).
//!
//! Every entry added or changed reaches this module through the store's entry feed, and each is
//! judged by one `Effects` key over what it reads (the entry, the engine's verdicts), so a change
//! costs what it touched (`inbox-full-walk-scale`: a contact's blobs up to the caps cost a change
//! O(change)). Per entry:
//! - under an inbox this node reads: taken (`Engine::take_inbox`, vouched for once stamped: a
//!   writer of the inbox, a node of this account, took it; judged again as what it read moves) until its commit applied, then taken for good: while the commit is held it is judged
//!   from the commit alone (`taken`), never opened or taken again; a deposited one whose commit applied is stamped in place by a writer of the inbox,
//!   at most one blob per commit and none whose expiry is more than `INBOX_LIFETIME + 2 ×
//!   MAX_DRIFT` ahead; its dial hint kept while it lives. A boxes payload is never taken or
//!   stamped: the engine holds it as an offer (spec/sync.md §3), its dial hint given once the
//!   account keeps its sync IDs;
//! - a deposit under a sync ID this node reads and writes: promoted (stamped, with the author's
//!   chain logged as certificate copies) once `Engine::promotable` says so and it holds a part of
//!   the commit S must hold that no other entry of S holds stamped;
//! - an own deposit: offered (`offers`, to the sources keeping S unread) until stamped or gone.
//!
//! Clearing: a node holding S's delete key keeps at most `DEPOSITS_WAITING` (and
//! `DEPOSITS_WAITING_BYTES`) of the deposits in its own store it can do nothing with, judged
//! again for S each time a deposit of S changed: O(S's deposits), which its deposit budget bounds.

use super::offers::{Offers, Target};
use super::{DialHint, Here};
use crate::store::Store;
use crate::types::{Entry, Holding, Result};
use osis_base::format::{DEPOSITS_WAITING, DEPOSITS_WAITING_BYTES, INBOX_LIFETIME_MS, MAX_DRIFT_MS};
use osis_base::memo::{Effects, Feed, Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, WallMs};
use osis_engine::Engine;
use osis_engine::labeling::Certs;
use osis_engine::sync::{InboxOpened, Opened, PartSet, Promote, Taken};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type Key = (SyncId, BlobId);

/// What one entry calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Act {
    /// Not held (gone, expired, never there).
    Gone,
    /// Nothing: a stamped entry of a sync ID that is no inbox here.
    Nothing,
    /// An inbox blob, and how taking it went (`None`: nothing here opens it).
    Inbox { stamped: bool, taken: Option<Taken>, commit: Option<CommitId>, dial: Option<DialHint>, expires: Option<WallMs> },
    /// A deposited inbox blob a writer stamps in place (with its dial hint).
    StampInbox(CommitId, Option<DialHint>),
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
    /// The dial hint of each inbox blob acted on that carries one (`hints`): stamped, so the
    /// driver follows them as they move.
    dials: Stamped<Key, DialHint>,
    /// Inbox blobs whose commit applied, with their dial hints: taken once (spec/sync-inbox.md
    /// §2 Taking), so judged again from the commit alone.
    taken: Stamped<Key, (CommitId, Option<DialHint>)>,
    /// Sync IDs a deposit of which changed: clearing judges them again.
    clear_due: BTreeSet<SyncId>,
}

impl Default for Held {
    fn default() -> Self {
        let mut inbox_list = Effects::new("inbox: inboxes");
        inbox_list.want(());
        Held { feed: None, inbox_list, inboxes: StampedSet::default(), judged: Effects::new("inbox: held"), acts: BTreeMap::new(), stamped: Stamped::default(), dials: Stamped::default(), taken: Stamped::default(), clear_due: BTreeSet::new() }
    }
}

impl Held {
    /// A start: every deposit held is judged once (inbox entries once the inboxes are known).
    pub(super) fn start(&mut self, h: &mut Here<'_>, _offers: &mut Offers) -> Result<()> {
        self.feed = Some(h.store.entry_feed());
        for (s, e) in h.store.all_deposits()? {
            self.judged.want((s, e.blob));
        }
        Ok(())
    }

    pub(super) fn settle(&mut self, h: &mut Here<'_>, offers: &mut Offers) -> Result<bool> {
        let mut acted = false;
        if !self.inbox_list.due().is_empty() {
            let engine = &mut *h.engine;
            if let Some((_, now)) = self.inbox_list.settle(&(), || Arc::new(engine.inbox_actors().keys().copied().collect())) {
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
            let (inboxes, stamped, taken) = (&self.inboxes, &self.stamped, &self.taken);
            let now_ms = h.now;
            let moved = {
                let (engine, store) = (&mut *h.engine, &*h.store);
                self.judged.try_settle(&k, || judge(engine, store, inboxes, stamped, taken, now_ms, &k))?
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

    fn act(&mut self, h: &mut Here<'_>, offers: &mut Offers, k: &Key, now: &Act) -> Result<()> {
        let (s, b) = k;
        let deposit = matches!(now, Act::StampInbox(..) | Act::Promote(_) | Act::Offer | Act::Waiting { .. }) || matches!(now, Act::Inbox { stamped: false, .. });
        if deposit || matches!(self.acts.get(k), Some(Act::Offer | Act::Waiting { .. } | Act::Inbox { stamped: false, .. })) {
            self.clear_due.insert(*s);
        }
        let dial = match now {
            Act::Inbox { dial, .. } | Act::StampInbox(_, dial) => dial.as_ref(),
            _ => None,
        };
        if self.dials.get(k) != dial {
            match dial {
                Some(d) => self.dials.insert(*k, d.clone()),
                None => self.dials.remove(k),
            };
        }
        match now {
            Act::Gone | Act::Nothing => {
                self.judged.unwant(k);
                self.acts.remove(k);
                let held: Vec<(SyncId, CommitId)> = self.stamped.iter().filter(|(_, x)| *x == b).map(|(c, _)| *c).collect();
                for c in held {
                    self.stamped.remove(&c);
                }
                if self.taken.contains_key(k) {
                    self.taken.remove(k);
                }
                return Ok(());
            }
            Act::Inbox { stamped, taken, commit: Some(c), dial, .. } => {
                if *stamped && !self.stamped.contains_key(&(*s, *c)) {
                    self.stamped.insert((*s, *c), *b);
                }
                self.took(k, *taken, c, dial);
            }
            Act::StampInbox(c, dial) => {
                self.took(k, Some(Taken::Applied), c, dial);
                if stamp(h, s, b)? {
                    self.stamped.insert((*s, *c), *b);
                }
            }
            Act::Promote(chain) => {
                // the author's chain goes beside it first; nothing promotes until it can
                if log_chain(h, s, chain)? && stamp(h, s, b)? {
                    osis_base::costs::count("inbox: promoted", 1);
                }
            }
            Act::Offer => offers.add(*s, *b, Target::Stores),
            Act::Inbox { .. } | Act::Waiting { .. } => {}
        }
        self.acts.insert(*k, now.clone());
        Ok(())
    }

    /// Notes an inbox blob whose commit applied as taken for good; one taken otherwise is not.
    fn took(&mut self, k: &Key, taken: Option<Taken>, c: &CommitId, dial: &Option<DialHint>) {
        let now = (taken == Some(Taken::Applied)).then(|| (*c, dial.clone()));
        if self.taken.get(k) != now.as_ref() {
            match now {
                Some(v) => {
                    self.taken.insert(*k, v);
                }
                None => {
                    self.taken.remove(k);
                }
            }
        }
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
            if matches!(act, Some(Act::StampInbox(..) | Act::Promote(_))) {
                continue;
            }
            let Some(size) = h.store.blob_len(&e.blob)?.filter(|n| *n > 0) else { continue };
            // an invite request (an opened inbox blob not taken; a refused one is none) or a boxes
            // payload held as an offer: both go last
            let request = matches!(act, Some(Act::Inbox { taken: Some(Taken::Waiting | Taken::Offered), .. })) && within_bound(e.expires, h.now);
            idle.push((e, size, request));
        }
        osis_base::costs::count("inbox: clearing read", idle.len() as u64);
        let mut acted = false;
        for b in to_clear(idle, h.now) {
            h.store.drop_entry(s, &b, Vec::new())?;
            acted = true;
        }
        Ok(acted)
    }

    /// Dial hints of the inbox blobs held (spec/sync-inbox.md §2: for dialing only).
    pub(super) fn hints(&self) -> impl Iterator<Item = &DialHint> {
        self.dials.values()
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        None
    }
}

/// spec/sync-inbox.md §4 Clearing deposits: of the deposits a holder of S's delete key can do
/// nothing with (each with its size and whether it is an invite request or a boxes payload), the
/// ones it drops to
/// keep at most `DEPOSITS_WAITING` and `DEPOSITS_WAITING_BYTES`: every deposit but the invite
/// requests first, those with no expiry or one past the bound before the rest, then earliest to
/// expire; then the invite requests, earliest to expire (they count toward the bounds and go
/// last).
pub fn to_clear(mut idle: Vec<(Entry, u64, bool)>, now: WallMs) -> Vec<BlobId> {
    let (mut n, mut bytes) = (idle.len(), idle.iter().map(|(_, b, _)| *b).sum::<u64>());
    let mut out = Vec::new();
    idle.sort_by_key(|(e, _, request)| (*request, within_bound(e.expires, now), e.expires.map_or(u64::MAX, |t| t.0)));
    for (e, size, _) in idle {
        if n <= DEPOSITS_WAITING && bytes <= DEPOSITS_WAITING_BYTES as u64 {
            break;
        }
        out.push(e.blob);
        n -= 1;
        bytes = bytes.saturating_sub(size);
    }
    out
}

/// The prefix expiry is within `INBOX_LIFETIME + 2 × MAX_DRIFT` of `now` (spec/sync-inbox.md §2).
fn within_bound(expires: Option<WallMs>, now: WallMs) -> bool {
    expires.is_some_and(|t| t.0 <= now.0.saturating_add(INBOX_LIFETIME_MS + 2 * MAX_DRIFT_MS))
}

/// spec/sync-inbox.md §4 Promotion (one stamped copy per delta): a deposit holding parts `mine`
/// of a commit S must hold parts `need` of adds a delta when some part of `need` it holds is in
/// none of the parts `stamped` (the other entries of S holding that commit stamped).
pub fn adds_delta(need: &PartSet, mine: &PartSet, stamped: &[PartSet]) -> bool {
    mine.iter().any(|p| need.contains(p) && !stamped.iter().any(|x| x.contains(p)))
}

/// What one held entry is judged on (spec/sync-inbox.md §2 Taking, Stamping in place, §4).
#[derive(Clone, Debug)]
pub struct Facts {
    pub blob: BlobId,
    pub deposited: bool,
    pub own: bool,
    pub expires: Option<WallMs>,
    /// S is an inbox this node reads; then how taking the blob went (`None`: nothing here opens
    /// it).
    pub inbox: Option<Option<InboxOpened>>,
    /// The blob already stamped for this inbox commit, if any (one per commit).
    pub stamped: Option<BlobId>,
    /// This node holds S's head write key.
    pub writer: bool,
    /// How this node holds S.
    pub holding: Option<Holding>,
    /// A deposit under a read S this node writes: the engine's word on promoting its commit and
    /// whether it adds a delta (`adds_delta`).
    pub promote: Option<(Promote, bool)>,
}

/// The act one held entry calls for, from its facts alone.
pub fn act_of(f: &Facts, now: WallMs) -> Act {
    if let Some(o) = &f.inbox {
        let (taken, commit) = (o.as_ref().map(|o| o.taken), o.as_ref().and_then(|o| o.commit));
        if f.deposited
            && taken == Some(Taken::Applied)
            && let Some(c) = commit
            && within_bound(f.expires, now)
            && f.stamped.is_none_or(|x| x == f.blob)
            && f.writer
        {
            return Act::StampInbox(c, o.as_ref().and_then(|o| o.dial.clone()));
        }
        let dial = o.as_ref().and_then(|o| o.dial.clone());
        return Act::Inbox { stamped: !f.deposited, taken, commit, dial, expires: f.expires };
    }
    if !f.deposited {
        return Act::Nothing;
    }
    let mut never = false;
    match &f.promote {
        Some((Promote::Yes { chain }, true)) => return Act::Promote(chain.clone()),
        Some((Promote::Never, _)) => never = true,
        _ => {}
    }
    // an own deposit under a sync ID not held is an inbox blob to another's inbox: `deliveries`'
    if f.own && f.holding.is_some() { Act::Offer } else { Act::Waiting { never } }
}

/// Logs a promoted commit's author's chain under S as this node's certificate copies: whether
/// it did. Not built: the engine seals no certificate copy yet (issues/sync-unbuilt.md, inbox),
/// so nothing is promoted.
fn log_chain(h: &mut Here<'_>, s: &SyncId, chain: &Certs) -> Result<bool> {
    let _ = (h, s, chain);
    Ok(false)
}

/// Stamps entry `b` of S in place with this node's write key: whether it did.
fn stamp(h: &mut Here<'_>, s: &SyncId, b: &BlobId) -> Result<bool> {
    let Some(e) = h.store.entry(s, b)? else { return Ok(false) };
    let Some(w) = h.engine.signers(s, None)?.stamp else { return Ok(false) };
    let stamp = osis_label::sign_stamp(&w, s, b, &e.wrap, e.role);
    let code = h.store.log(s, Entry { stamp: Some(stamp), deposited: false, ..e }, None, None)?;
    Ok(code == osis_proto::Code::OK)
}

/// The commit deposit `b` of S holds: as opened or sealed here, else opened now (a deposit a
/// peer left is opened once, under a read S).
fn deposit_commit(engine: &mut Engine, store: &Store, s: &SyncId, e: &Entry) -> Result<Option<CommitId>> {
    if let Some(c) = engine.blob_commit(&e.blob)? {
        return Ok(Some(c));
    }
    let Some(bytes) = store.bytes(&e.blob)? else { return Ok(None) };
    Ok(match engine.open_entry(s, &e.blob, &e.wrap, &bytes)? {
        Opened::Commit(c, _) => Some(c),
        _ => None,
    })
}

fn judge(engine: &mut Engine, store: &Store, inboxes: &StampedSet<SyncId>, stamped: &Stamped<(SyncId, CommitId), BlobId>, taken: &Stamped<Key, (CommitId, Option<DialHint>)>, now: WallMs, k: &Key) -> Result<Act> {
    osis_base::costs::count("inbox: held judged", 1);
    let (s, b) = k;
    let Some(e) = store.entry(s, b)? else { return Ok(Act::Gone) };
    let holding = store.holding(s);
    let mut f = Facts { blob: *b, deposited: e.deposited, own: e.own, expires: e.expires, inbox: None, stamped: None, writer: false, holding, promote: None };
    if inboxes.contains(s) {
        // taken once: while its commit is held, nothing of the blob is opened or taken again
        let o = match taken.get(k) {
            Some((c, dial)) if engine.holds_commit(c) => Some(InboxOpened { commit: Some(*c), taken: Taken::Applied, hints: Vec::new(), dial: dial.clone() }),
            // stamped by a writer of the inbox, a node of this account, that took it (vouched): a
            // stamp verified here, never the deposited flag alone (a peer's stamp is kept
            // unverified)
            _ => engine.take_inbox(s, b, store.stamp_verifies(s, b)?)?,
        };
        f.stamped = o.as_ref().and_then(|o| o.commit).and_then(|c| stamped.get(&(*s, c)).copied());
        f.writer = e.deposited && engine.signers(s, None)?.stamp.is_some();
        f.inbox = Some(o);
        return Ok(act_of(&f, now));
    }
    if e.deposited && holding == Some(Holding::Read) && engine.signers(s, None)?.stamp.is_some() {
        f.writer = true;
        if let Some(c) = deposit_commit(engine, store, s, &e)? {
            let p = engine.promotable(s, &c)?;
            let adds = matches!(p, Promote::Yes { .. }) && {
                let need = engine.sync_bodies(&c)?.get(s).map(|m| m.parts.clone()).unwrap_or_default();
                let mine = engine.blob_parts(b)?.unwrap_or_default();
                let mut others = Vec::new();
                for x in engine.commit_blobs(&c)?.iter().filter(|x| *x != b) {
                    if store.entry(s, x)?.is_some_and(|e| !e.deposited)
                        && let Some(held) = engine.blob_parts(x)?
                    {
                        others.push(held);
                    }
                }
                adds_delta(&need, &mine, &others)
            };
            f.promote = Some((p, adds));
        }
    }
    Ok(act_of(&f, now))
}
