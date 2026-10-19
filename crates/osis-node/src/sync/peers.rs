//! Reachability and co-reader dialing (spec/sync.md §5 last bullet, §10; spec/data-model.md §9;
//! spec/permissions.md §4): this node's `/reach` (dialable key, relays, lan secret), the co-reader
//! nodes it knows from theirs, and LAN discovery tags. A co-reader of a label is a node thing
//! other than this node, holding `/reach`, that may read the label's group; this node dials it at
//! `peer://` + its relays (osis-transport finds it by key), or at the address a matching LAN
//! announcement gave, and syncs those labels with it as with a server.

use super::{Action, Event, SyncEngine};
use crate::error::Result;
use crate::Mutation;
use osis_core::{LabelId, Tid};
use osis_crypto::Secret32;
use osis_label::Address;
use osis_schema::core_types::{self as ct, Reach};
use std::collections::{BTreeMap, BTreeSet};

/// LAN tag window (spec/sync.md §10).
pub const LAN_WINDOW_MS: u64 = 600_000;
/// How long a LAN announcement is used for dialing.
pub const LAN_FRESH_MS: u64 = 2 * LAN_WINDOW_MS;

/// The LAN announcement tag of a lan secret at `unix_ms` (spec/sync.md §10):
/// `kdf("lan tag", lan secret, le64(floor(unix ms / 600000)))`, first 16 bytes.
pub fn lan_tag(lan_secret: &[u8; 32], unix_ms: u64) -> [u8; 16] {
    let window = unix_ms / LAN_WINDOW_MS;
    let k = osis_crypto::kdf::kdf("lan tag", lan_secret, &window.to_le_bytes());
    let mut t = [0u8; 16];
    t.copy_from_slice(k.expose().get(..16).unwrap_or(&[0; 16]));
    t
}

/// A co-reader's dialable key and lan secret.
pub(crate) type LanSecret = ([u8; 32], [u8; 32]);

/// A co-reader node this node may dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub node: Tid,
    pub reach: Reach,
    /// Labels this node syncs that the peer may read (it is dialed for these).
    pub labels: BTreeSet<LabelId>,
}

/// Where a co-reader was heard on the LAN. A new address is only a candidate until a session
/// through it opens a label (spec/sync.md §10 does not bind the LAN transport key to the node,
/// so an announcement alone must not divert a working route); a failed candidate is backed off,
/// not the peer.
#[derive(Clone, Debug, Default)]
pub(crate) struct LanRoute {
    /// Proven address and when last heard (raw ms).
    pub good: Option<(Address, u64)>,
    pub candidate: Option<(Address, u64)>,
    /// Candidate addresses that failed, until when.
    pub failed: BTreeMap<Address, u64>,
}

impl SyncEngine {
    /// This node's dialable transport secret (spec/sync.md §10; separate from its signing key):
    /// generated on first use and kept in the local records. The driver listens with it and
    /// publishes the key the listener presents (`publish_reach`).
    pub fn dialable_secret(&mut self) -> Secret32 {
        if let Some(s) = &self.state.reach_secret {
            return s.clone();
        }
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        let s = Secret32::from_bytes(b);
        self.state.set_reach_secret(s.clone());
        if let Err(e) = self.state.flush(&mut self.engine) {
            self.diag(format!("sync state: {e}"));
        }
        s
    }

    /// A new dialable secret, and a new lan secret at the next `publish_reach` (a co-reader
    /// removed from every label still knows the old ones, notes/networking.md decision 4).
    pub fn rotate_reach(&mut self) -> Secret32 {
        self.state.reach_secret = None;
        self.lan_rotate = true;
        self.dialable_secret()
    }

    /// This node's `/reach`, if published.
    pub fn own_reach(&mut self) -> Option<Reach> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::REACH).ok().flatten()
    }

    /// Writes `/reach` on this node (spec/data-model.md §9) when it changed: `dialable` the key
    /// the listener presents, the relays, and the lan secret (kept; fresh when none or after
    /// `rotate_reach`). The node card goes under every synced label with the next pass
    /// (spec/permissions.md §4).
    pub fn publish_reach(&mut self, dialable: [u8; 32], relays: Vec<String>) -> Result<Vec<Action>> {
        let old = self.own_reach();
        let lan_secret = match &old {
            Some(r) if !self.lan_rotate => r.lan_secret,
            _ => {
                let mut b = [0u8; 32];
                self.rng.fill_bytes(&mut b);
                b
            }
        };
        let reach = Reach { dialable, relays, lan_secret };
        if old.as_ref() == Some(&reach) {
            return Ok(Vec::new());
        }
        let me = self.engine.tid();
        let mut m = Mutation::new();
        m.replace(me, &ct::REACH, &reach)?;
        self.engine.commit(m)?;
        self.lan_rotate = false;
        Ok(self.handle(Event::Local))
    }

    /// This node's LAN announcement tag now (spec/sync.md §10), once `/reach` is published.
    pub fn lan_tag_now(&mut self) -> Option<[u8; 16]> {
        let r = self.own_reach()?;
        Some(lan_tag(&r.lan_secret, self.now()))
    }

    /// Co-reader nodes known from their `/reach`, by dialable key (spec/sync.md §5, §10): node
    /// things other than this one that may read a label this node syncs now. Per label at most
    /// `SyncConfig.max_peers_per_label`, in total at most `max_peers`, newest heartbeat first.
    pub fn peers(&mut self) -> BTreeMap<[u8; 32], Peer> {
        let me = self.engine.tid();
        let mut nodes: Vec<Tid> = self.engine.core.by_aspect.keys().filter(|(t, ak)| ak.as_str() == "/reach" && *t != me).map(|(t, _)| *t).collect();
        nodes.dedup();
        let own = self.own_reach().map(|r| r.dialable);
        let mut reaches = Vec::new();
        for n in nodes {
            if let Ok(Some(r)) = self.engine.get_typed(&n, &ct::REACH)
                && Some(r.dialable) != own
            {
                let seen = self.engine.get_typed(&n, &ct::SEEN).ok().flatten().map(|s| s.ts.0);
                reaches.push((seen, n, r));
            }
        }
        let mut out: BTreeMap<[u8; 32], Peer> = BTreeMap::new();
        if reaches.is_empty() {
            return out;
        }
        // newest heartbeat first, unknown last
        reaches.sort_by_key(|x| std::cmp::Reverse(x.0));
        for (g, l) in self.labels() {
            let mut n_label = 0;
            for (_, n, r) in &reaches {
                if n_label >= self.cfg.max_peers_per_label {
                    break;
                }
                if !self.engine.may_read(n, &g) {
                    continue;
                }
                if !out.contains_key(&r.dialable) && out.len() >= self.cfg.max_peers {
                    continue;
                }
                n_label += 1;
                out.entry(r.dialable).or_insert_with(|| Peer { node: *n, reach: r.clone(), labels: BTreeSet::new() }).labels.insert(l.id);
            }
        }
        out
    }

    /// Where to dial each co-reader: a LAN candidate not backed off, else its proven LAN
    /// address while fresh, else `peer://` with its relays.
    pub(crate) fn peer_addresses(&mut self) -> BTreeMap<[u8; 32], (Address, BTreeSet<LabelId>)> {
        let now = self.raw_now();
        for r in self.lan.values_mut() {
            if r.good.as_ref().is_some_and(|(_, at)| at.saturating_add(LAN_FRESH_MS) <= now) {
                r.good = None;
            }
            if r.candidate.as_ref().is_some_and(|(_, at)| at.saturating_add(LAN_FRESH_MS) <= now) {
                r.candidate = None;
            }
            r.failed.retain(|_, until| *until > now);
        }
        self.lan.retain(|_, r| r.good.is_some() || r.candidate.is_some() || !r.failed.is_empty());
        let mut out = BTreeMap::new();
        for (k, p) in self.peers() {
            let route = self.lan.get(&k);
            let addr = route
                .and_then(|r| r.candidate.as_ref().filter(|(a, _)| !r.failed.contains_key(a)).or(r.good.as_ref()))
                .map(|(a, _)| a.clone())
                .unwrap_or_else(|| Address { url: osis_transport::peer_url(&p.reach.relays), key: k });
            out.insert(k, (addr, p.labels));
        }
        out
    }

    /// A session to a co-reader opened a label: a LAN candidate it went through is proven.
    pub(crate) fn lan_proven(&mut self, peer: [u8; 32], addr: &Address) {
        let now = self.raw_now();
        if let Some(r) = self.lan.get_mut(&peer)
            && r.candidate.as_ref().is_some_and(|(a, _)| a == addr)
        {
            r.candidate = None;
            r.good = Some((addr.clone(), now));
        }
    }

    /// A connection to a co-reader ended before opening anything: when it went to a LAN
    /// candidate, that address is backed off (true), not the peer.
    pub(crate) fn lan_failed(&mut self, peer: [u8; 32], addr: &Address) -> bool {
        let until = self.raw_now().saturating_add(self.cfg.peer_retry_ms);
        let Some(r) = self.lan.get_mut(&peer) else { return false };
        if r.candidate.as_ref().is_some_and(|(a, _)| a == addr) {
            r.candidate = None;
            r.failed.insert(addr.clone(), until);
            return true;
        }
        false
    }

    /// A LAN announcement (spec/sync.md §10): `tag` and the address with the announced transport
    /// key. When the tag is a co-reader's for the current or an adjacent window, the address
    /// becomes that node's candidate (dialed when no connection to it runs; it replaces the
    /// proven route only once a session through it opens a label). The co-readers are evaluated
    /// once per tag window. Returns whose dialable key matched.
    pub fn lan_seen(&mut self, tag: [u8; 16], address: Address) -> (Option<[u8; 32]>, Vec<Action>) {
        let now = self.now();
        let window = now / LAN_WINDOW_MS;
        if self.lan_peers.as_ref().is_none_or(|(w, _)| *w != window) {
            let v = self.peers().into_iter().map(|(k, p)| (k, p.reach.lan_secret)).collect();
            self.lan_peers = Some((window, v));
        }
        let times = [now.saturating_sub(LAN_WINDOW_MS), now, now.saturating_add(LAN_WINDOW_MS)];
        let hit = self.lan_peers.as_ref().and_then(|(_, v)| v.iter().find(|(_, s)| times.iter().any(|w| lan_tag(s, *w) == tag)).map(|(k, _)| *k));
        let Some(k) = hit else { return (None, Vec::new()) };
        let raw = self.raw_now();
        let r = self.lan.entry(k).or_default();
        if r.failed.contains_key(&address) {
            return (Some(k), Vec::new());
        }
        match &mut r.good {
            Some((a, at)) if *a == address => *at = raw,
            _ => {
                let fresh = r.candidate.as_ref().is_none_or(|(a, _)| *a != address);
                r.candidate = Some((address, raw));
                if fresh {
                    // dial there now, even inside a retry pause
                    self.retry.remove(&k);
                }
            }
        }
        (Some(k), self.handle(Event::Local))
    }
}
