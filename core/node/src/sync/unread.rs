//! The serving side for sync IDs this node keeps and cannot read (issues/net-one-peer.md step 3,
//! Opens; issues/net-shared-set.md, Peers that cannot read): their heads come from the hub's
//! store, whose head credentials (sync key, deposit key, the claim set's static entries) go in
//! the filter to every connection; a member opened by one is served from the hub's store (its
//! rows, its ephemeral entries as the log's memory part, its relay-only entries past the hub's
//! relay gate) and ends through the event of a head that no longer bears it. This node tests
//! nothing for them; it pulls each from every reader that opened it here, taking what it pulls by
//! the store's rules for a stamped entry (`unread_events`).

use super::state::hub_err;
use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_crypto::{Signature, WRAP_LEN};
use osis_host::MemEvent;
use osis_label::{ClaimSet, Step};
use osis_proto::{Code, LabelStore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// An unread sync ID's head at the hub's store, with its claim set when held.
#[derive(Clone)]
pub(crate) struct UnreadHead {
    pub(crate) step: Step,
    pub(crate) claims: Option<Arc<ClaimSet>>,
}

/// What node sync keeps of the unread sync IDs.
#[derive(Clone, Default)]
pub(crate) struct Unread {
    /// The heads as of the hub store's heads generation.
    heads: Option<(u64, Arc<BTreeMap<LabelId, UnreadHead>>)>,
    /// The generation `changed_at` was last stamped for.
    stamped: Option<u64>,
    /// The unread sync IDs some shared set holds (the hub's store keeps their ephemeral events).
    streamed: BTreeSet<LabelId>,
    /// A head moved since the last step: its opens are judged before the step's event.
    pub(super) moved: bool,
    /// Stamped entries announced without bytes while the store lacked the blob, with their wrap,
    /// stamp and announcement number: taken once the blob is held, whichever sync ID's fetch
    /// brought it, in the order they were announced (`unread_take_held`); kept while some stream
    /// owes them.
    pending: BTreeMap<(LabelId, BlobId), Pending>,
    /// The next announcement number of `pending`.
    announced: u64,
    /// Sync IDs full here: an entry pulled for them was refused for room (`Full`).
    full: BTreeMap<LabelId, Full>,
}

/// An entry announced without bytes and not taken yet (`Unread::pending`): its wrap, stamp and
/// announcement number.
#[derive(Clone)]
struct Pending {
    wrap: [u8; WRAP_LEN],
    stamp: Signature,
    n: u64,
}

/// A sync ID full here (spec/sync.md §10, Full): what its refusals found used, the entries
/// refused (not fetched again while it is full), and the connections told.
#[derive(Clone, Default)]
struct Full {
    durable: Option<osis_host::Room>,
    memory: Option<osis_host::Room>,
    refused: BTreeSet<BlobId>,
    told: BTreeSet<ConnId>,
}

impl SyncEngine {
    fn hub(&self) -> std::sync::MutexGuard<'_, osis_host::HostStore> {
        self.hub_store.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The unread sync IDs' heads, read again only when one moved (`heads_generation`).
    pub(crate) fn unread_heads(&mut self) -> Result<Arc<BTreeMap<LabelId, UnreadHead>>> {
        // the read set first: a label turning read leaves this map
        self.labels();
        let generation = self.hub().heads_generation();
        if let Some((g, h)) = &self.unread.heads
            && *g == generation
        {
            return Ok(h.clone());
        }
        let heads = {
            let hub = self.hub();
            let mut heads = BTreeMap::new();
            for l in hub.unread_labels().map_err(hub_err)? {
                if let Some((step, claims)) = hub.head_step(&l).map_err(hub_err)? {
                    heads.insert(l, UnreadHead { step, claims });
                }
            }
            Arc::new(heads)
        };
        self.unread.heads = Some((generation, heads.clone()));
        Ok(heads)
    }

    /// Whether `l` is a sync ID this node keeps and does not read.
    pub(crate) fn is_unread(&mut self, l: &LabelId) -> Result<bool> {
        Ok(self.unread_heads()?.contains_key(l))
    }

    /// What the hub changed of the unread sync IDs since the last step: a head moved (their
    /// credentials are stamped again and every connection re-judged), and the ephemeral entries
    /// of those streamed, taken into the log's memory part.
    pub(super) fn unread_moved(&mut self) {
        let (generation, memory) = {
            let mut hub = self.hub();
            (hub.heads_generation(), hub.take_memory())
        };
        if self.unread.stamped != Some(generation) {
            self.unread.stamped = Some(generation);
            self.unread.moved = true;
            self.changed_due = true;
        }
        let now = self.now();
        for e in memory {
            match e {
                MemEvent::Added(l, b) => self.state.mem_log.added(l, b, now),
                MemEvent::Deleted(l, b) => self.state.mem_log.deleted(l, b, now),
                MemEvent::Gone(l, b) => self.state.mem_log.gone(l, b),
            }
        }
    }

    /// The unread sync IDs some shared set holds now: the hub keeps their ephemeral events for
    /// the log's memory part, a newly streamed one's live entries listed there first; one no
    /// longer streamed leaves it.
    pub(super) fn unread_restream(&mut self) -> Result<()> {
        let heads = self.unread_heads()?;
        let now: BTreeSet<LabelId> = self.records.shared.values().flat_map(|s| s.member_ids().collect::<Vec<_>>()).filter(|l| heads.contains_key(l)).collect();
        if now == self.unread.streamed {
            return Ok(());
        }
        let wall = self.now();
        let added: Vec<LabelId> = now.difference(&self.unread.streamed).copied().collect();
        for l in self.unread.streamed.difference(&now) {
            self.state.mem_log.forget(l);
        }
        let live: Vec<(LabelId, Vec<BlobId>)> = {
            let mut hub = self.hub();
            hub.set_streamed(now.clone());
            added.iter().map(|l| (*l, hub.ephemeral_live(l))).collect()
        };
        for (l, bs) in live {
            for b in bs {
                self.state.mem_log.added(l, b, wall);
            }
        }
        self.unread.streamed = now;
        Ok(())
    }

    /// Entry `b` of unread `l` as the hub's store holds it, durable or ephemeral: its wrap and
    /// stamp.
    pub(crate) fn unread_entry(&mut self, l: &LabelId, b: &BlobId) -> Result<Option<([u8; WRAP_LEN], Option<Signature>)>> {
        if !self.is_unread(l)? {
            return Ok(None);
        }
        Ok(self.hub().entry(l, b).map_err(hub_err)?.map(|m| (m.wrap, m.stamp)))
    }

    /// Blob bytes as the hub's store holds them (memory entries included).
    pub(crate) fn unread_blob(&self, b: &BlobId) -> Result<Option<Vec<u8>>> {
        self.hub().blob(b).map_err(hub_err)
    }

    /// What a holder of static entry `entry` needs to read unread `l` (a static entry's Hit): the
    /// head's entry box for it and the path from the genesis step to the head.
    pub(crate) fn unread_grant(&mut self, l: &LabelId, entry: &[u8; 32]) -> Result<Option<osis_proto::msg::Grant>> {
        let heads = self.unread_heads()?;
        let Some(entry_box) = heads.get(l).and_then(|h| h.claims.as_ref()).and_then(|c| c.entries.get(entry)).cloned() else { return Ok(None) };
        let steps = self.hub().path(l).map_err(hub_err)?;
        Ok(Some(osis_proto::msg::Grant { entry_box: Some(entry_box), steps }))
    }

    /// The answer to a Behind item on `l` (spec/sync.md §5, Behind), its key `key` shown by `sig`,
    /// an open signature over this side's Hello challenge and the listener's key (`challenge`,
    /// `listener`): when `step` is not the head and `key` is a credential of it (its sync key, a
    /// claim of its held claim set, or a key actor's signing key whose static entry the set
    /// lists), the steps after it on the hub store's path through the first whose sync key is not
    /// its own (one sync key's run: an old credential learns one rotation past what it read);
    /// naming no step, by a sync key, the step after the newest bearing it; naming no step, by a
    /// key actor's signing key whose static entry the head's claim set lists, the head's entry box
    /// for it and the path (a Static item's grant). A label this node neither keeps nor reads is
    /// unknown. `budget` is the steps the Offer's answers may still carry (what one reply holds):
    /// each step read takes one; spent, the answer is the steps read so far, none read refused for
    /// now.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn unread_behind(&mut self, l: &LabelId, step: Option<&osis_label::StepId>, key: &[u8; 32], sig: &Signature, challenge: &[u8; 32], listener: &[u8; 32], budget: &mut usize) -> Result<BehindAnswer> {
        if *budget == 0 {
            return Ok(BehindAnswer::ForNow);
        }
        if !self.is_unread(l)? {
            return Ok(if self.things().contains_key(l) { BehindAnswer::Refused } else { BehindAnswer::Unknown });
        }
        let Ok(pk) = osis_crypto::VerifyingKey::from_slice(key) else { return Ok(BehindAnswer::Refused) };
        if osis_crypto::verify_open(&pk, l, challenge, listener, sig).is_err() {
            return Ok(BehindAnswer::Refused);
        }
        let hub = self.hub();
        let id = match step {
            Some(s) => *s,
            None => match hub.step_with_sync(l, &pk).map_err(hub_err)? {
                Some(s) => s,
                None => {
                    drop(hub);
                    let entry = osis_crypto::static_entry(l, &pk);
                    let Some(g) = self.unread_grant(l, &entry)? else { return Ok(BehindAnswer::Refused) };
                    // the path read; past what the reply still holds it does not go
                    let fits = g.steps.len() <= *budget;
                    *budget = budget.saturating_sub(g.steps.len());
                    return Ok(if fits { BehindAnswer::Grant(Box::new(g)) } else { BehindAnswer::ForNow });
                }
            },
        };
        if hub.head(l).map_err(hub_err)?.is_none_or(|h| h == id) {
            return Ok(BehindAnswer::Refused);
        }
        let Some(at) = hub.step(l, &id).map_err(hub_err)? else { return Ok(BehindAnswer::Refused) };
        // a credential of the named step: its sync key, a claim of its held set, or a key
        // actor's whose static entry the set lists
        let listed = || -> Result<bool> {
            let Some(set) = hub.claim_set(l, &id).map_err(hub_err)? else { return Ok(false) };
            Ok(set.contains(key) || set.contains(&osis_crypto::static_entry(l, &pk)))
        };
        if at.keys.sync != pk && !(step.is_some() && listed()?) {
            return Ok(BehindAnswer::Refused);
        }
        // the steps after it by the child index, through the first under another sync key
        let mut steps = Vec::new();
        let mut cur = id;
        while *budget > 0
            && let Some(c) = hub.child(l, Some(&cur)).map_err(hub_err)?
        {
            let Some(st) = hub.step(l, &c).map_err(hub_err)? else { break };
            *budget -= 1;
            let rotated = st.keys.sync != at.keys.sync;
            steps.push(st);
            cur = c;
            if rotated {
                break;
            }
        }
        Ok(if !steps.is_empty() {
            BehindAnswer::Steps(steps)
        } else if *budget == 0 {
            BehindAnswer::ForNow
        } else {
            BehindAnswer::Refused
        })
    }

    /// Where a member of unread `l` opened by a credential its head no longer bears ends
    /// (`until`): the head's event, the one that ended it, else the log's end.
    pub(crate) fn unread_until(&mut self, l: &LabelId) -> Result<u64> {
        self.engine.run(|tx| {
            let at = super::state::hub(tx)?.node_log(|t| t.log_head_at(l))?;
            Ok(match at {
                Some(p) => p,
                None => super::state::hub(tx)?.node_log(|t| t.log_end())?,
            })
        })
    }

    /// Events of unread `l` pulled from `conn`'s reader (spec/sync.md §10, Stream): a stamped
    /// entry with its bytes, or whose blob the hub's store holds already under any sync ID (bytes
    /// cross once), goes into the hub's store by its rules for a stamped entry (the stamp under its head's
    /// write key); a relay-only one passes the store's relay gate and goes on to the other members
    /// sharing `l`. A deposited entry (no stamp) is not taken: it carries no deposit signature,
    /// so deposits reach this node only as Deposit items. Deletions and heads do nothing (a
    /// delete comes by a delete-key holder's Delete, a head by Register). One refused for room makes
    /// it full (`unread_refused`); one refused for anything else is told to the reader as a
    /// Refused event with its code. Returns the stamped entries
    /// announced without bytes that the store lacks: owed until fetched, then taken in the order
    /// announced (`unread_take_held`).
    pub(crate) fn unread_events(&mut self, conn: ConnId, l: LabelId, events: Vec<osis_proto::Event>, out: &mut Vec<Action>) -> Result<BTreeSet<BlobId>> {
        let now = self.now();
        let mut owed = BTreeSet::new();
        let mut relays = Vec::new();
        let mut taken = Vec::new();
        let mut pending = Vec::new();
        let mut refused = Vec::new();
        // refused for anything but room, with its code: the reader is told (`Event::Refused`)
        let mut told = Vec::new();
        // refused for room while full: announced again, the reader is told (a new connection)
        let was_refused = self.unread.full.get(&l).map(|f| f.refused.clone()).unwrap_or_default();
        {
            let mut hub = self.hub();
            let Some(k) = hub.head_keys(&l).map_err(hub_err)? else { return Ok(owed) };
            for e in events {
                let osis_proto::Event::Added { blob_id, blob, wrap, stamp: Some(stamp) } = e else { continue };
                if blob.is_none() && was_refused.contains(&blob_id) {
                    refused.push((blob_id, None));
                    continue;
                }
                if hub.entry(&l, &blob_id).map_err(hub_err)?.is_some_and(|m| m.stamp.is_some()) {
                    continue;
                }
                let bytes = match blob {
                    Some(b) if osis_label::blob_id(&b) == blob_id => b,
                    Some(_) => continue,
                    None => match hub.blob(&blob_id).map_err(hub_err)? {
                        Some(b) => b,
                        None if osis_proto::store::LabelStore::tombstoned(&*hub, &l, &blob_id).map_err(hub_err)? => {
                            told.push((blob_id, Code::TOMBSTONED));
                            continue;
                        }
                        None => {
                            owed.insert(blob_id);
                            pending.push((blob_id, wrap, stamp));
                            continue;
                        }
                    },
                };
                let mut struck = false;
                match osis_proto::session::pulled(&mut *hub, now, &l, &k, &bytes, wrap, stamp, &mut struck).map_err(hub_err)? {
                    osis_proto::session::Taken::Relay(r) => relays.push(r),
                    osis_proto::session::Taken::Code(c) => {
                        if c == Code::OK {
                            taken.push(blob_id);
                        } else if c == Code::STORAGE_CAP {
                            let memory = osis_label::Prefix::parse(&bytes).is_ok_and(|p| p.class().in_memory());
                            refused.push((blob_id, Some(hub.room(&l, memory).map_err(hub_err)?)));
                        } else {
                            told.push((blob_id, c));
                        }
                    }
                }
            }
        }
        for (b, wrap, stamp) in pending {
            let n = self.unread.announced;
            self.unread.announced += 1;
            self.unread.pending.entry((l, b)).or_insert(Pending { wrap, stamp, n });
        }
        if !refused.is_empty() {
            self.unread_refused(conn, l, refused, out)?;
        }
        // refused for anything but room (its stamp under keys of no head here, expired, this
        // store's tombstone, ...): the reader is told with the code, so it neither waits for this
        // node to take it nor offers it again until its stamp or this node's head changes
        if !told.is_empty() {
            let events = told.into_iter().map(|(b, c)| (l, osis_proto::Event::Refused(b, c))).collect();
            self.shared_send(conn, osis_proto::Message::Stream(Box::new(osis_proto::msg::Stream { events, cursor: None, report: false })), out)?;
        }
        self.stream_crossed(conn, taken);
        for r in relays {
            self.stream_relay(Some(conn), r.label, r.blob_id, &r.blob, r.wrap, Some(r.stamp), out)?;
        }
        Ok(owed)
    }

    /// Owed entries of unread sync IDs whose blob the store holds now (fetched under another
    /// sync ID: bytes cross once) are taken by its rules for a stamped entry, as `unread_events`
    /// takes one with its bytes: per sync ID in the order they were announced, up to the first
    /// whose blob is still lacking, so this store logs them in the reader's order (a removal
    /// before the content placed beside it, spec/permissions.md §3), never by which fetch came
    /// first.
    pub(crate) fn unread_take_held(&mut self, conn: ConnId, owed: &BTreeSet<(LabelId, BlobId)>, out: &mut Vec<Action>) -> Result<()> {
        let mut by_label: BTreeMap<LabelId, Vec<(u64, BlobId)>> = BTreeMap::new();
        for (l, b) in owed {
            if let Some(p) = self.unread.pending.get(&(*l, *b)) {
                by_label.entry(*l).or_default().push((p.n, *b));
            }
        }
        for (l, mut ids) in by_label {
            ids.sort();
            let mut held = Vec::new();
            {
                let hub = self.hub();
                for (_, b) in ids {
                    if hub.blob(&b).map_err(hub_err)?.is_none() {
                        break;
                    }
                    held.push(b);
                }
            }
            let mut evs = Vec::new();
            for b in held {
                let Some(p) = self.unread.pending.remove(&(l, b)) else { continue };
                evs.push(osis_proto::Event::Added { blob_id: b, blob: None, wrap: p.wrap, stamp: Some(p.stamp) });
            }
            if !evs.is_empty() {
                self.unread_events(conn, l, evs, out)?;
            }
        }
        Ok(())
    }

    /// Whether entry `b` of unread `l` is held here and waits to be taken behind one announced
    /// before it (`unread_take_held`): owed on its stream until then.
    pub(crate) fn unread_waits(&self, l: &LabelId, b: &BlobId) -> bool {
        self.unread.pending.contains_key(&(*l, *b)) && self.hub().blob(b).is_ok_and(|x| x.is_some())
    }

    /// `ids` of unread `l` in the order they were announced without bytes (`pending`), the rest
    /// after them as they were: what this store fetches and takes keeps the reader's order.
    pub(crate) fn unread_order(&self, l: &LabelId, ids: &mut [BlobId]) {
        ids.sort_by_key(|b| self.unread.pending.get(&(*l, *b)).map_or(u64::MAX, |p| p.n));
    }

    /// Drops what `unread_take_held` keeps for entries no stream owes any more.
    pub(crate) fn unread_prune(&mut self, owed: &BTreeSet<(LabelId, BlobId)>) {
        self.unread.pending.retain(|k, _| owed.contains(k));
    }

    /// Entries of unread `l` pulled from `conn` and refused for room, each with what its kind
    /// found used: `l` is full here, and `conn`'s reader is told so once (an event of a Stream
    /// without cursor, as no position names it).
    fn unread_refused(&mut self, conn: ConnId, l: LabelId, refused: Vec<(BlobId, Option<osis_host::Room>)>, out: &mut Vec<Action>) -> Result<()> {
        let f = self.unread.full.entry(l).or_default();
        for (b, room) in refused {
            f.refused.insert(b);
            match room {
                Some(r) if r.memory => f.memory = Some(r),
                Some(r) => f.durable = Some(r),
                None => {}
            }
        }
        if f.told.insert(conn) {
            self.shared_send(conn, osis_proto::Message::Stream(Box::new(osis_proto::msg::Stream { events: vec![(l, osis_proto::Event::Full(true))], cursor: None, report: false })), out)?;
        }
        Ok(())
    }

    /// Each sync ID full here whose kind of room grew since its refusals (an entry deleted,
    /// expired, or evicted, here or under another sync ID) has room again: the connections told
    /// are told so, and it is pulled again from the start at each, so what it refused comes
    /// again (taken now, or refused and full again).
    pub(super) fn unread_room(&mut self, out: &mut Vec<Action>) -> Result<()> {
        if self.unread.full.is_empty() {
            return Ok(());
        }
        let heads = self.unread_heads()?;
        self.unread.full.retain(|l, _| heads.contains_key(l));
        let freed: Vec<LabelId> = {
            let hub = self.hub();
            let grew = |l: &LabelId, r: &Option<osis_host::Room>| r.as_ref().is_some_and(|r| hub.room(l, r.memory).is_ok_and(|now| now.below(r)));
            self.unread.full.iter().filter(|(l, f)| grew(l, &f.durable) || grew(l, &f.memory)).map(|(l, _)| *l).collect()
        };
        for l in freed {
            let Some(f) = self.unread.full.remove(&l) else { continue };
            for conn in f.told {
                if self.records.shared.get(&conn).is_some_and(|s| s.has(&l)) {
                    self.shared_send(conn, osis_proto::Message::Stream(Box::new(osis_proto::msg::Stream { events: vec![(l, osis_proto::Event::Full(false))], cursor: None, report: false })), out)?;
                }
            }
            self.stream_rejoin(&l, out)?;
        }
        Ok(())
    }

    /// Whether this node wants the bytes of unread `l`'s entry `b`: its store holds neither the
    /// entry stamped nor the blob, holds no tombstone of it, and did not refuse it for room while
    /// `l` is full here.
    pub(crate) fn unread_wants(&mut self, l: &LabelId, b: &BlobId) -> Result<bool> {
        if self.unread.full.get(l).is_some_and(|f| f.refused.contains(b)) {
            return Ok(false);
        }
        let hub = self.hub();
        Ok(!hub.entry(l, b).map_err(hub_err)?.is_some_and(|m| m.stamp.is_some()) && hub.blob(b).map_err(hub_err)?.is_none() && !osis_proto::store::LabelStore::tombstoned(&*hub, l, b).map_err(hub_err)?)
    }

    /// A Deposit item for unread inbox `l` (issues/net-shared-set.md, Deposits): taken as a
    /// Deposit by the hub's store (its signature, budget, rate, caps: spec/sync.md §5): 0,
    /// refused for now (4, 5, 12), else 14.
    pub(crate) fn unread_deposit(&mut self, l: LabelId, blob: &[u8], wrap: [u8; WRAP_LEN], sig: &Signature) -> Result<Code> {
        let now = self.now();
        let code = {
            let mut hub = self.hub();
            // a sync ID not held here (yet: a label is registered after its first deposits may
            // go) is refused for now where its registration would be taken, as any Deposit before
            // its label is (spec/sync.md §5)
            let Some(k) = hub.head_keys(&l).map_err(hub_err)? else { return Ok(if hub.admits(&l) { Code::RATE_LIMITED } else { Code::NOT_ADMITTED }) };
            let mut struck = false;
            let (code, signed) = osis_proto::session::deposit(&mut *hub, now, &l, &k, blob, wrap, sig, &mut struck).map_err(hub_err)?;
            // refused for now passes on (spec/sync.md §10, Deposit items); any other refusal is 14
            match code {
                Code::OK | Code::RATE_LIMITED | Code::BUDGET_FULL | Code::STORAGE_CAP if signed => code,
                _ => Code::NOT_ADMITTED,
            }
        };
        Ok(code)
    }
}

/// The answer to a Behind item (`SyncEngine::unread_behind`).
pub(crate) enum BehindAnswer {
    /// The label is not held here (code 13).
    Unknown,
    /// Anything else refused (code 14).
    Refused,
    /// Not answered within the Offer's budget (code 4, refused for now).
    ForNow,
    /// The steps after the named one, in order, through the first under another sync key.
    Steps(Vec<Step>),
    /// A static entry the head lists: its entry box and the path.
    Grant(Box<osis_proto::msg::Grant>),
}
