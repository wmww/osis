//! Deposit items out (spec/sync-inbox.md §3 Sending).
//!
//! An offer is an own deposited entry (S, blob) and who may take it: a source of S keeping S
//! unread (`Target::Stores`: readers pull deposited entries), or, for an inbox blob, a peer that
//! may hold that inbox (`Target::Recipient`): one where S is open, one where the recipient is
//! proven (its own nodes read it), or one whose filter shows S's deposit key (a node keeping S
//! unread shows it to every connection, spec/sync-opens.md §4 Audiences). Never another peer: a
//! deposit tells its taker that this connection's node sends to that inbox.
//!
//! Per connection: one Deposit item unanswered at a time; answered 0, it is done there and every
//! other offer of S backed off there is ready again (one taken ends the others' back-off); 4, 5
//! or 12 (refused for now) back it off, doubling from `BACKOFF_MIN_MS` to `BACKOFF_MAX_MS`; 14
//! (or any other refusal) sends it again only when signing again changes the signature (the
//! deposit key moved), else not until the receiver's next filter arrives. An offer whose entry
//! was stamped, dropped or sealed again is removed (moot).
//!
//! Work follows change: each connection keeps the offers ready for it; an offer added is placed
//! at the connections it may go to (O(connections)), a connection proved gets the offers it may
//! take (O(offers)), a member joining gets the offers of its S (a range), a peer's filter arriving
//! gets the inbox offers (O(offers), tested against it); a settle sends only on connections with
//! something ready, a back-off due or a refusal waiting for a filter, and reads each connection's
//! filter count (O(connections)).

use super::{Ground, Here, Net, settled};
use crate::session::RequestId;
use crate::types::{ConnId, Result, SourceClass};
use osis_base::{BlobId, SyncId, Tid, WallMs};
use osis_base::memo::Effects;
use osis_crypto::{Signature, VerifyingKey};
use osis_proto::{Code, DepositItem, Msg, OfferItem};
use std::collections::{BTreeMap, BTreeSet};

/// The first back-off after a refusal for now (local policy; minor consequence: how soon a
/// deposit is offered again). At 0 a full peer is asked again at once, every settle; at infinity
/// a deposit refused once is never offered there again.
pub const BACKOFF_MIN_MS: u64 = 2_000;
/// The longest back-off (local policy, the spec's bound): at 0 as above; at infinity a peer full
/// for a while is asked again ever more rarely, so a deposit waits long after room returned.
pub const BACKOFF_MAX_MS: u64 = 10 * 60 * 1000;

type Key = (SyncId, BlobId);

/// Who may take an offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    /// Sources of S keeping S unread.
    Stores,
    /// A peer where S is open, where this recipient is proven, or whose filter shows S's
    /// deposit key.
    Recipient(Tid),
}

#[derive(Clone, Debug, Default)]
struct Conn {
    actors: Vec<Tid>,
    /// The peer's filter arrivals seen: one more readies the inbox offers again.
    filter: u64,
    out: Option<(RequestId, Key, Signature)>,
    ready: BTreeSet<Key>,
    /// Refused for now: until when, and how many times in a row.
    backoff: BTreeMap<Key, (WallMs, u32)>,
    /// Refused (14) with this signature; the filter generation it waits past, once known.
    parked: BTreeMap<Key, (Signature, Option<u64>)>,
}

#[derive(Clone)]
pub(super) struct Offers {
    items: BTreeMap<Key, Target>,
    /// The deposit key of each offer refused (14) somewhere: one moving sends it again there.
    keys: Effects<Key, Option<VerifyingKey>>,
    conns: BTreeMap<ConnId, Conn>,
    /// Connections with an offer ready and none out.
    active: BTreeSet<ConnId>,
    /// Back-offs by when they end.
    wakes: BTreeSet<(WallMs, ConnId, Key)>,
    /// Connections with a refusal waiting for the next filter.
    parked: BTreeSet<ConnId>,
}

impl Default for Offers {
    fn default() -> Self {
        Offers { items: BTreeMap::new(), keys: Effects::new("inbox: deposit keys"), conns: BTreeMap::new(), active: BTreeSet::new(), wakes: BTreeSet::new(), parked: BTreeSet::new() }
    }
}

impl std::fmt::Debug for Offers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Offers").field("items", &self.items).field("conns", &self.conns).finish_non_exhaustive()
    }
}

impl Offers {
    /// Whether a deposit to `conn` may land (spec/sync-opens.md §1 Keep or close): one is out,
    /// ready, or refused for now and backed off. One refused (14) waits for the peer's next filter,
    /// which a later connection sends.
    pub(super) fn may_land(&self, conn: ConnId) -> bool {
        self.conns.get(&conn).is_some_and(|c| c.out.is_some() || !c.ready.is_empty() || !c.backoff.is_empty())
    }

    pub(super) fn add(&mut self, s: SyncId, b: BlobId, target: Target) {
        let k = (s, b);
        match self.items.get(&k) {
            // a recipient's offer goes wherever a store's would
            Some(Target::Recipient(_)) => return,
            Some(t) if *t == target => return,
            _ => {}
        }
        self.items.insert(k, target);
        osis_base::costs::count("inbox: offer placed", self.conns.len() as u64);
        // eligibility needs `Net`: placed at the next settle on every connection
        for (c, conn) in &mut self.conns {
            conn.ready.insert(k);
            self.active.insert(*c);
        }
    }

    pub(super) fn remove(&mut self, s: &SyncId, b: &BlobId) {
        let k = (*s, *b);
        if self.items.remove(&k).is_none() {
            return;
        }
        for conn in self.conns.values_mut() {
            conn.ready.remove(&k);
            conn.parked.remove(&k);
            conn.backoff.remove(&k);
        }
        self.wakes.retain(|(_, _, x)| *x != k);
        self.keys.unwant(&k);
    }

    /// A connection's proofs are done.
    pub(super) fn connected(&mut self, conn: ConnId, net: &impl Net) {
        let c = Conn { actors: net.actors(conn), filter: net.filter_generation(conn), ready: self.items.keys().copied().collect(), ..Conn::default() };
        osis_base::costs::count("inbox: offer placed", self.items.len() as u64);
        if !c.ready.is_empty() {
            self.active.insert(conn);
        }
        self.conns.insert(conn, c);
    }

    /// S joined a connection's shared set: its offers may go there now.
    pub(super) fn joined(&mut self, conn: ConnId, s: &SyncId, net: &impl Net) {
        if !self.conns.contains_key(&conn) {
            self.connected(conn, net);
        }
        let Some(c) = self.conns.get_mut(&conn) else { return };
        for k in self.items.range((*s, BlobId([0; 32]))..=(*s, BlobId([0xff; 32]))).map(|(k, _)| *k) {
            if !c.backoff.contains_key(&k) && !c.parked.contains_key(&k) {
                c.ready.insert(k);
            }
        }
        if !c.ready.is_empty() {
            self.active.insert(conn);
        }
    }

    pub(super) fn closed(&mut self, conn: ConnId) {
        self.conns.remove(&conn);
        self.active.remove(&conn);
        self.parked.remove(&conn);
        self.wakes.retain(|(_, c, _)| *c != conn);
    }

    /// Sends one Deposit item on each connection with one ready and none out.
    pub(super) fn settle<G: Ground>(&mut self, h: &mut Here<'_, G>, net: &mut impl Net) -> Result<bool> {
        let mut acted = false;
        for k in self.keys.due() {
            let Some(target) = self.items.get(&k).copied() else {
                self.keys.unwant(&k);
                continue;
            };
            let g = &mut *h.g;
            let Some((Some(_), _)) = settled(&mut self.keys, &k, None, || Ok(g.signers(&k.0, target.actor().as_ref())?.deposit.map(|d| d.verifying_key())))? else { continue };
            // the deposit key moved: signed again, it goes again wherever it was refused
            for (c, conn) in &mut self.conns {
                if conn.parked.remove(&k).is_some() {
                    conn.ready.insert(k);
                    self.active.insert(*c);
                }
            }
        }
        while let Some(&(t, conn, k)) = self.wakes.first() {
            if t > h.now {
                break;
            }
            self.wakes.remove(&(t, conn, k));
            if let Some(c) = self.conns.get_mut(&conn)
                && c.backoff.get(&k).is_some_and(|(at, _)| *at == t)
                && self.items.contains_key(&k)
            {
                c.ready.insert(k);
                self.active.insert(conn);
            }
        }
        // a peer's new filter may show an inbox's deposit key
        for (id, c) in &mut self.conns {
            let arrived = net.filter_generation(*id);
            if arrived == c.filter {
                continue;
            }
            c.filter = arrived;
            let inbox = self.items.iter().filter(|(_, t)| matches!(t, Target::Recipient(_))).map(|(k, _)| *k);
            let fresh: Vec<Key> = inbox.filter(|k| !c.backoff.contains_key(k) && !c.parked.contains_key(k) && c.out.is_none_or(|(_, o, _)| o != *k)).collect();
            osis_base::costs::count("inbox: offer placed", fresh.len() as u64);
            if !fresh.is_empty() {
                c.ready.extend(fresh);
                self.active.insert(*id);
            }
        }
        for conn in std::mem::take(&mut self.parked) {
            let generation = net.filter_generation(conn);
            let Some(c) = self.conns.get_mut(&conn) else { continue };
            let keys: Vec<Key> = c.parked.keys().copied().collect();
            for k in keys {
                let Some(&(sig, waits)) = c.parked.get(&k) else { continue };
                let again = match waits {
                    Some(g) => g != generation,
                    // just refused: again at once only if signing again changes the signature
                    None => match self.items.get(&k) {
                        Some(target) => item(h, &k, target)?.is_some_and(|i| i.sig != sig),
                        None => true,
                    },
                };
                if again {
                    c.parked.remove(&k);
                    c.ready.insert(k);
                } else if waits.is_none() {
                    c.parked.insert(k, (sig, Some(generation)));
                }
            }
            if !c.parked.is_empty() {
                self.parked.insert(conn);
            }
            if !c.ready.is_empty() {
                self.active.insert(conn);
            }
        }
        for conn in std::mem::take(&mut self.active) {
            let Some(c) = self.conns.get_mut(&conn) else { continue };
            if c.out.is_some() {
                continue;
            }
            while let Some(k) = c.ready.pop_first() {
                let Some(target) = self.items.get(&k) else { continue };
                osis_base::costs::count("inbox: offer judged", 1);
                let Some(key) = h.g.signers(&k.0, target.actor().as_ref())?.deposit else {
                    self.items.remove(&k);
                    continue;
                };
                if !may_take(net, conn, &c.actors, &k.0, *target, &key.verifying_key().to_bytes()) {
                    continue;
                }
                let Some(item) = item(h, &k, target)? else {
                    self.items.remove(&k);
                    continue;
                };
                let sig = item.sig;
                let Some(id) = net.request(conn, Msg::Offer { id: 0, items: vec![OfferItem::Deposit(item)] }) else { break };
                c.out = Some((id, k, sig));
                acted = true;
                break;
            }
        }
        Ok(acted)
    }

    /// A Shared (or Error) answering a Deposit item of ours: whether it was one.
    pub(super) fn answered(&mut self, now: WallMs, conn: ConnId, id: RequestId, m: &Msg) -> bool {
        let Some(c) = self.conns.get_mut(&conn) else { return false };
        let Some((out, k, sig)) = c.out else { return false };
        if out != id {
            return false;
        }
        c.out = None;
        let code = match m {
            Msg::Shared { items, .. } => items.first().map_or(Code::DECLINED, |i| i.code),
            _ => Code::DECLINED,
        };
        if self.items.contains_key(&k) {
            match code {
                Code::OK => {
                    // one taken ends the back-off of the others of S at this peer
                    c.backoff.remove(&k);
                    let s = k.0;
                    let waiting: Vec<Key> = c.backoff.range((s, BlobId([0; 32]))..=(s, BlobId([0xff; 32]))).map(|(k, _)| *k).collect();
                    for w in waiting {
                        c.backoff.remove(&w);
                        c.ready.insert(w);
                    }
                }
                Code::RATE_LIMITED | Code::DEPOSIT_BUDGET_FULL | Code::STORAGE_CAP => {
                    let n = c.backoff.get(&k).map_or(0, |(_, n)| n.saturating_add(1));
                    let at = WallMs(now.0.saturating_add(backoff_ms(n)));
                    c.backoff.insert(k, (at, n));
                    self.wakes.insert((at, conn, k));
                }
                _ => {
                    c.parked.insert(k, (sig, None));
                    self.keys.want(k);
                    self.parked.insert(conn);
                }
            }
        }
        self.active.insert(conn);
        true
    }

    pub(super) fn next_wake(&self) -> Option<WallMs> {
        self.wakes.first().map(|(t, _, _)| *t)
    }
}

/// The back-off after the `n`th refusal for now in a row.
pub fn backoff_ms(n: u32) -> u64 {
    BACKOFF_MIN_MS.saturating_mul(1u64 << n.min(32)).min(BACKOFF_MAX_MS)
}

impl Target {
    /// The actor whose `keys.0` names the deposit seed.
    fn actor(self) -> Option<Tid> {
        match self {
            Target::Recipient(r) => Some(r),
            Target::Stores => None,
        }
    }
}

/// Whether the peer on `conn` may take a deposit of S signed by `key` (spec/sync-inbox.md §3
/// Sending).
fn may_take(net: &impl Net, conn: ConnId, actors: &[Tid], s: &SyncId, target: Target, key: &[u8; 32]) -> bool {
    let member = net.member(conn, s);
    match target {
        Target::Stores => member.is_some_and(|m| m.class == SourceClass::Store),
        Target::Recipient(r) => member.is_some() || actors.contains(&r) || net.shows_deposit_key(conn, s, key),
    }
}

/// The Deposit item of offer `k`, signed with the deposit key now; `None`: moot (its entry is
/// no longer an own deposit, or no deposit key is held).
fn item<G: Ground>(h: &mut Here<'_, G>, k: &Key, target: &Target) -> Result<Option<DepositItem>> {
    let (s, b) = k;
    let Some(e) = h.store.entry(s, b)? else { return Ok(None) };
    if !e.deposited || !e.own {
        return Ok(None);
    }
    let Some(blob) = h.store.bytes(b)? else { return Ok(None) };
    let Some(key) = h.g.signers(s, target.actor().as_ref())?.deposit else { return Ok(None) };
    let sig = osis_label::sign_deposit(&key, s, b, &e.wrap, e.role);
    Ok(Some(DepositItem { sync_id: *s, blob, wrap: e.wrap, sig }))
}
