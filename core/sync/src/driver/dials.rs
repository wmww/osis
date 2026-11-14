//! Whom the node dials and when (spec/sync-opens.md §1 Where to dial, Whom to dial, Redial, Dial
//! timeout, One connection per pair).
//!
//! A **candidate** is a dialable key with the reasons it is one (`Why`), each with the address
//! it is known by: the dial peers of a sync ID it syncs (`Engine::dial_peers`: holders of sync or
//! above, granters, its own nodes holding S), configured addresses, discovered nodes. Reasons
//! are priorities, never a filter on what opens: they order the dials, nothing else.
//!
//! One retry rule: a candidate not connected is due again `REDIAL_MS` after its last dial, or at
//! once after a change this node knows of that could make a peer share something (opens'
//! `changed_at` moved, or the candidate's address). Dials go out while fewer than `max_peers`
//! connections share something or are being dialed. A dialer whose connection lost the pair rule
//! to another connection (`Opens::lost_to`) does not dial that peer while the winner lasts.
//!
//! Work follows change: the due candidates wait in priority order, the waiting ones by time; a
//! step with nothing due touches no candidate. A change of what the node shares moves every
//! waiting candidate to due once (the spec's "any change" redials every peer not connected).

use crate::types::ConnId;
use osis_base::memo::Effects;
use osis_base::{SyncId, WallMs};
use osis_engine::Engine;
use osis_label::Address;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// `max_peers` by default (spec/sync-opens.md §1, local policy): connections that share
/// something with this node, or are being dialed, before it dials no more. Resource bound: at 0
/// the node dials nobody (it only serves); at infinity it dials every candidate at once.
pub const MAX_PEERS: usize = 32;

/// `REDIAL_MS` (spec/sync-opens.md §1, local policy): a candidate not connected is dialed again
/// this long after its last dial, unless a change makes it due sooner. Minor consequence: at 0 a
/// failing peer is dialed at every event (a dial per failure, at the transport's pace); at
/// infinity a peer is dialed again only on a change.
pub const REDIAL_MS: u64 = 30_000;

/// Discovered candidates remembered (spec/sync-transport.md §4: what a node remembers of its
/// discoveries is bounded): past it the oldest discovery is forgotten. Resource bound against a
/// LAN announcing fresh keys: at 0 discovery dials nothing; at infinity a flood of announcements
/// fills memory.
pub const DISCOVERED_KEEP: usize = 1024;

/// Why a key is a candidate, best first: its priority among due dials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Why {
    /// A dial peer of a sync ID this node syncs (`Engine::dial_peers`).
    Sync(SyncId),
    /// A configured address (`SyncConfig::dial`).
    Configured,
    /// Found by discovery (`Input::Discovered`).
    Discovered,
}

impl Why {
    fn rank(&self) -> u8 {
        match self {
            Why::Sync(_) => 0,
            Why::Configured => 1,
            Why::Discovered => 2,
        }
    }
}

/// Where a candidate stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Not connected by a dial of its own.
    Idle,
    Dialing(ConnId),
    Up(ConnId),
    /// Its dial lost the pair rule to this connection: not dialed while it lasts.
    Held(ConnId),
}

#[derive(Clone, Debug)]
struct Cand {
    why: BTreeMap<Why, Address>,
    state: State,
    /// Its last dial.
    last: Option<WallMs>,
    /// The change epoch at its last dial: a later change makes it due at once.
    epoch: u64,
    /// Where it waits while idle: due now (its priority), or at a time.
    wait: Option<Wait>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wait {
    Due(u8),
    At(WallMs),
}

impl Cand {
    fn rank(&self) -> u8 {
        self.why.keys().next().map_or(u8::MAX, Why::rank)
    }

    fn address(&self) -> Option<&Address> {
        self.why.values().next()
    }
}

/// What the node may dial for each sync ID it syncs: the product's reads `Engine::dial_peers`
/// through memo effects (`NodePeers`); a test's a table.
pub trait Peers {
    /// The sync IDs whose dial peers may have moved since the last call, those that left the
    /// sync set included.
    fn due(&mut self) -> Vec<SyncId>;
    /// S's dial peers now (empty: S is not synced).
    fn peers(&mut self, s: &SyncId) -> Arc<Vec<Address>>;
}

/// The memo effects the product's `Peers` settles: the sync set, and per sync ID its dial peers.
#[derive(Clone)]
pub struct PeersFx {
    set: Effects<(), Vec<SyncId>>,
    peers: Effects<SyncId, Arc<Vec<Address>>>,
}

impl Default for PeersFx {
    fn default() -> PeersFx {
        PeersFx { set: Effects::new("dials sync set"), peers: Effects::new("dial peers") }
    }
}

impl std::fmt::Debug for PeersFx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PeersFx")
    }
}

/// The product's `Peers`: the engine's facade. A part not built answers as if nothing were.
pub struct NodePeers<'a> {
    pub engine: &'a mut Engine,
    pub fx: &'a mut PeersFx,
}

fn dial_peers(engine: &mut Engine, s: &SyncId) -> Arc<Vec<Address>> {
    engine.dial_peers(s).unwrap_or_default()
}

impl Peers for NodePeers<'_> {
    fn due(&mut self) -> Vec<SyncId> {
        let mut out = Vec::new();
        self.fx.set.want(());
        for k in self.fx.set.due() {
            let engine = &mut *self.engine;
            if let Some((was, now)) = self.fx.set.settle(&k, || engine.sync_set().map(|s| s.ids.keys().copied().collect()).unwrap_or_default()) {
                let was: BTreeSet<SyncId> = was.unwrap_or_default().into_iter().collect();
                let now: BTreeSet<SyncId> = now.into_iter().collect();
                for s in now.difference(&was) {
                    self.fx.peers.want(*s);
                }
                for s in was.difference(&now) {
                    self.fx.peers.unwant(s);
                    out.push(*s);
                }
            }
        }
        for s in self.fx.peers.due() {
            let engine = &mut *self.engine;
            if self.fx.peers.settle(&s, || dial_peers(engine, &s)).is_some() {
                out.push(s);
            }
        }
        out
    }

    fn peers(&mut self, s: &SyncId) -> Arc<Vec<Address>> {
        if !self.fx.peers.wants(s) {
            return Arc::default();
        }
        dial_peers(self.engine, s)
    }
}

/// Work done, counted (tests: scaling by counting work).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Candidates touched (scheduled, moved, dialed, given up).
    pub touched: u64,
    /// Dials made.
    pub dials: u64,
}

/// The node's dial state.
#[derive(Clone, Debug, Default)]
pub struct Dials {
    cands: BTreeMap<[u8; 32], Cand>,
    due: BTreeSet<(u8, [u8; 32])>,
    timer: BTreeSet<(WallMs, [u8; 32])>,
    /// Connections this node dialed, to their candidate.
    conns: BTreeMap<ConnId, [u8; 32]>,
    in_flight: BTreeSet<ConnId>,
    /// Candidates held by a connection that won their pair.
    held: BTreeMap<ConnId, BTreeSet<[u8; 32]>>,
    /// Connections whose shared set has a member.
    sharing: BTreeSet<ConnId>,
    /// The change epoch: each change this node knows of that could make a peer share
    /// something.
    epoch: u64,
    /// Each sync ID's dial peers as last applied.
    by_sync: BTreeMap<SyncId, Arc<Vec<Address>>>,
    configured: Vec<Address>,
    discovered: VecDeque<[u8; 32]>,
    next_conn: u64,
    /// This node's own dialable key: never dialed.
    own: Option<[u8; 32]>,
    work: Work,
}

impl Dials {
    /// This node's own key: never a candidate.
    pub fn set_own(&mut self, key: Option<[u8; 32]>) {
        self.own = key;
        if let Some(k) = key {
            for w in self.cands.get(&k).map(|c| c.why.keys().copied().collect::<Vec<_>>()).unwrap_or_default() {
                self.withdraw(&w, &k);
            }
        }
    }

    /// `to` is a candidate for `why`; a new candidate or a new address for it is a change for it.
    pub fn offer(&mut self, why: Why, to: Address, now: WallMs) {
        if Some(to.key) == self.own {
            return;
        }
        let key = to.key;
        let c = self.cands.entry(key).or_insert_with(|| Cand { why: BTreeMap::new(), state: State::Idle, last: None, epoch: 0, wait: None });
        let before = c.address().cloned();
        if c.why.insert(why, to).is_some() && c.address().cloned() == before {
            return;
        }
        let changed = c.address().cloned() != before;
        if why == Why::Discovered {
            self.discovered.push_back(key);
            if self.discovered.len() > DISCOVERED_KEEP
                && let Some(old) = self.discovered.pop_front()
            {
                self.withdraw(&Why::Discovered, &old);
            }
        }
        if changed && let Some(c) = self.cands.get_mut(&key) {
            // an address it was not dialed at: due at once
            c.last = None;
        }
        self.schedule(key, now);
    }

    /// `key` is no longer a candidate for `why`; one with no reason left is forgotten once idle.
    pub fn withdraw(&mut self, why: &Why, key: &[u8; 32]) {
        let Some(c) = self.cands.get_mut(key) else { return };
        if c.why.remove(why).is_none() {
            return;
        }
        if *why == Why::Discovered
            && let Some(i) = self.discovered.iter().position(|k| k == key)
        {
            self.discovered.remove(i);
        }
        self.work.touched += 1;
        if c.why.is_empty() && c.state == State::Idle {
            self.unwait(key);
            self.cands.remove(key);
        } else if c.state == State::Idle {
            // its priority may have moved
            self.unwait(key);
            self.schedule(*key, WallMs(0));
        }
    }

    /// The configured addresses are now `addrs`.
    pub fn configure(&mut self, addrs: &[Address], now: WallMs) {
        if self.configured == addrs {
            return;
        }
        let old = std::mem::replace(&mut self.configured, addrs.to_vec());
        for a in old.iter().filter(|a| !addrs.iter().any(|b| b.key == a.key)) {
            self.withdraw(&Why::Configured, &a.key);
        }
        for a in addrs {
            self.offer(Why::Configured, a.clone(), now);
        }
    }

    /// Applies the sync IDs whose dial peers moved.
    pub fn settle_peers(&mut self, src: &mut impl Peers, now: WallMs) {
        for s in src.due() {
            let new = src.peers(&s);
            let old = if new.is_empty() { self.by_sync.remove(&s) } else { self.by_sync.insert(s, new.clone()) }.unwrap_or_default();
            for a in old.iter().filter(|a| !new.iter().any(|b| b.key == a.key)) {
                self.withdraw(&Why::Sync(s), &a.key);
            }
            for a in new.iter() {
                self.offer(Why::Sync(s), a.clone(), now);
            }
        }
    }

    /// A change this node knows of that could make a peer share something: every candidate not
    /// connected is due at once.
    pub fn changed(&mut self) {
        self.epoch += 1;
        for (_, key) in std::mem::take(&mut self.timer) {
            self.work.touched += 1;
            if let Some(c) = self.cands.get_mut(&key) {
                let r = c.rank();
                c.wait = Some(Wait::Due(r));
                self.due.insert((r, key));
            }
        }
    }

    /// The time is `now`: candidates whose pause ended are due.
    pub fn tick(&mut self, now: WallMs) {
        while let Some((at, key)) = self.timer.first().copied().filter(|(at, _)| *at <= now) {
            self.timer.remove(&(at, key));
            self.work.touched += 1;
            if let Some(c) = self.cands.get_mut(&key) {
                let r = c.rank();
                c.wait = Some(Wait::Due(r));
                self.due.insert((r, key));
            }
        }
    }

    /// The dials to make now, best first, while fewer than `max_peers` connections share
    /// something or are being dialed: each is numbered here and is `Dialing` until it is up or
    /// ends.
    pub fn dial(&mut self, now: WallMs, max_peers: usize) -> Vec<(ConnId, Address)> {
        let mut out = Vec::new();
        while self.room(max_peers) > 0 {
            let Some((_, key)) = self.due.pop_first() else { break };
            let Some(c) = self.cands.get_mut(&key) else { continue };
            let Some(to) = c.address().cloned() else { continue };
            self.next_conn += 1;
            let conn = ConnId(self.next_conn);
            c.wait = None;
            c.state = State::Dialing(conn);
            c.last = Some(now);
            c.epoch = self.epoch;
            self.conns.insert(conn, key);
            self.in_flight.insert(conn);
            self.work.touched += 1;
            self.work.dials += 1;
            out.push((conn, to));
        }
        out
    }

    /// Dials this node may still make: `max_peers` less the connections sharing something and
    /// the dials in flight (spec/sync-opens.md §1 Whom to dial: never candidates).
    pub fn room(&self, max_peers: usize) -> usize {
        max_peers.saturating_sub(self.sharing.len() + self.in_flight.len())
    }

    /// A connection this node dialed is up.
    pub fn up(&mut self, conn: ConnId) {
        self.in_flight.remove(&conn);
        if let Some(c) = self.conns.get(&conn).and_then(|k| self.cands.get_mut(k)) {
            c.state = State::Up(conn);
        }
    }

    /// A connection ended (or a dial failed): its candidate is idle again, due by the redial
    /// rule; one whose dial lost its pair to the live connection `lost_to` is held by it. The
    /// candidates it held are idle again.
    pub fn ended(&mut self, conn: ConnId, lost_to: Option<ConnId>, now: WallMs) {
        self.in_flight.remove(&conn);
        self.sharing.remove(&conn);
        for key in self.held.remove(&conn).unwrap_or_default() {
            self.idle(key, now);
        }
        let Some(key) = self.conns.remove(&conn) else { return };
        match (lost_to, self.cands.get_mut(&key)) {
            (Some(w), Some(c)) => {
                c.state = State::Held(w);
                self.held.entry(w).or_default().insert(key);
            }
            (None, Some(_)) => self.idle(key, now),
            _ => {}
        }
    }

    /// The candidate a dialed connection is to, and its candidate dialed again at once: it came
    /// to act for an actor it did not prove there (spec/sync-opens.md §1).
    pub fn redial_now(&mut self, conn: ConnId) {
        if let Some(c) = self.conns.get(&conn).and_then(|k| self.cands.get_mut(k)) {
            c.last = None;
        }
    }

    fn idle(&mut self, key: [u8; 32], now: WallMs) {
        let Some(c) = self.cands.get_mut(&key) else { return };
        c.state = State::Idle;
        if c.why.is_empty() {
            self.cands.remove(&key);
            return;
        }
        self.schedule(key, now);
    }

    /// An idle candidate waits for its next dial: at once if never dialed or a change came since
    /// its last dial, else `REDIAL_MS` after it.
    fn schedule(&mut self, key: [u8; 32], now: WallMs) {
        let epoch = self.epoch;
        let Some(c) = self.cands.get_mut(&key) else { return };
        if c.state != State::Idle {
            return;
        }
        let at = match c.last {
            Some(t) if c.epoch >= epoch => WallMs(t.0.saturating_add(REDIAL_MS)),
            _ => WallMs(0),
        };
        let wait = if at <= now { Wait::Due(c.rank()) } else { Wait::At(at) };
        if c.wait == Some(wait) {
            return;
        }
        let old = c.wait.replace(wait);
        self.work.touched += 1;
        match old {
            Some(Wait::Due(r)) => {
                self.due.remove(&(r, key));
            }
            Some(Wait::At(t)) => {
                self.timer.remove(&(t, key));
            }
            None => {}
        }
        match wait {
            Wait::Due(r) => self.due.insert((r, key)),
            Wait::At(t) => self.timer.insert((t, key)),
        };
    }

    fn unwait(&mut self, key: &[u8; 32]) {
        let Some(c) = self.cands.get_mut(key) else { return };
        match c.wait.take() {
            Some(Wait::Due(r)) => {
                self.due.remove(&(r, *key));
            }
            Some(Wait::At(t)) => {
                self.timer.remove(&(t, *key));
            }
            None => {}
        }
    }

    /// Whether a connection's shared set has a member (opens' word after each member moved).
    pub fn sharing(&mut self, conn: ConnId, shares: bool) {
        if shares {
            self.sharing.insert(conn);
        } else {
            self.sharing.remove(&conn);
        }
    }

    /// When a waiting candidate is next due.
    pub fn next_wake(&self) -> Option<WallMs> {
        self.timer.first().map(|(at, _)| *at)
    }

    /// Where candidate `key` stands (`None`: not a candidate).
    pub fn state(&self, key: &[u8; 32]) -> Option<State> {
        self.cands.get(key).map(|c| c.state)
    }

    /// The candidate a dialed connection is to.
    pub fn dialed(&self, conn: ConnId) -> Option<[u8; 32]> {
        self.conns.get(&conn).copied()
    }

    /// Tests only: candidates kept, and the work counted so far.
    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.cands.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.cands.is_empty()
    }

    #[doc(hidden)]
    pub fn work(&self) -> Work {
        self.work
    }
}
