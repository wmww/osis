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
use osis_crypto::{Domain, Secret32, Signature, SigningSecret, VerifyingKey};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Reach};
use osis_transport::lan::Announce;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

/// LAN tag window (spec/sync.md §10).
pub const LAN_WINDOW_MS: u64 = 600_000;
/// How long a LAN announcement is used for dialing.
pub const LAN_FRESH_MS: u64 = 2 * LAN_WINDOW_MS;
/// Co-readers are computed again at least this often (edges expire with time).
const PEERS_TTL_MS: u64 = 60_000;

/// The LAN announcement tag of a lan secret at `unix_ms` (spec/sync.md §10):
/// `kdf("lan tag", lan secret, le64(floor(unix ms / 600000)))`, first 16 bytes.
pub fn lan_tag(lan_secret: &[u8; 32], unix_ms: u64) -> [u8; 16] {
    let window = unix_ms / LAN_WINDOW_MS;
    let k = osis_crypto::kdf::kdf("lan tag", lan_secret, &window.to_le_bytes());
    let mut t = [0u8; 16];
    t.copy_from_slice(k.expose().get(..16).unwrap_or(&[0; 16]));
    t
}

/// A co-reader node this node may dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub node: Tid,
    pub reach: Reach,
    /// Labels this node syncs that the peer may read (it is dialed for these).
    pub labels: BTreeSet<LabelId>,
}

/// Where a co-reader was heard on the LAN (spec/sync.md §10). The announcement's signature binds
/// its transport key to the node, so a connection through an address that comes up (the
/// transport authenticated that key) proves the route. Until then the address is a candidate:
/// the proven route is dialed first, a candidate never displaces a running connection, and an
/// address whose connection fails before coming up is backed off (not the peer).
#[derive(Clone, Debug, Default)]
pub(crate) struct LanRoute {
    /// Proven address and when last heard (raw ms).
    pub good: Option<(Address, u64)>,
    pub candidate: Option<(Address, u64)>,
    /// Addresses that failed, until when.
    pub failed: BTreeMap<Address, u64>,
}

/// The digest a LAN announcement's signature covers: BLAKE3(tag || key || port).
fn announce_digest(a: &Announce) -> [u8; 32] {
    osis_core::hash::hash(&a.signed())
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

    /// A fresh transport secret for a LAN listener (one per network join, spec/sync.md §10).
    pub fn lan_secret(&mut self) -> Secret32 {
        let mut b = [0u8; 32];
        self.rng.fill_bytes(&mut b);
        Secret32::from_bytes(b)
    }

    /// This node's LAN announcement now for a listener with transport key `key` at `port`:
    /// the current tag, signed under the dialable key (spec/sync.md §10). None before `/reach`
    /// is published, or when its dialable key is not the Ed25519 key of the dialable secret.
    pub fn lan_announcement(&mut self, key: [u8; 32], port: u16) -> Option<Announce> {
        let r = self.own_reach()?;
        let sk = SigningSecret::from_seed(self.state.reach_secret.as_ref()?);
        if sk.verifying_key().to_bytes() != r.dialable {
            self.diag("LAN: the published dialable key is not the dialable secret's".into());
            return None;
        }
        let mut a = Announce { tag: lan_tag(&r.lan_secret, self.now()), key, port, sig: [0; 64] };
        a.sig = sk.sign(Domain::LanAnnounce, &announce_digest(&a)).0;
        Some(a)
    }

    /// Node things with a `/reach` this node holds, other than itself, by dialable key (cached
    /// until a commit applies).
    pub(crate) fn reach_nodes(&mut self) -> Arc<BTreeMap<[u8; 32], Tid>> {
        self.peers_fresh();
        if let Some(r) = &self.reach_index {
            return r.clone();
        }
        let me = self.engine.tid();
        let mut nodes: Vec<Tid> = self.engine.core.by_aspect.keys().filter(|(t, ak)| ak.as_str() == "/reach" && *t != me).map(|(t, _)| *t).collect();
        nodes.dedup();
        let own = self.own_reach().map(|r| r.dialable);
        let mut m = BTreeMap::new();
        for n in nodes {
            if let Ok(Some(r)) = self.engine.get_typed(&n, &ct::REACH)
                && Some(r.dialable) != own
            {
                m.insert(r.dialable, n);
            }
        }
        let m = Arc::new(m);
        self.reach_index = Some(m.clone());
        m
    }

    /// Co-reader nodes known from their `/reach`, by dialable key (spec/sync.md §5, §10): node
    /// things other than this one that may read a label this node syncs now. Per label at most
    /// `SyncConfig.max_peers_per_label`, in total at most `max_peers`, newest heartbeat first.
    /// Cached until the engine's state changes, and at most a minute (edges expire).
    pub fn peers(&mut self) -> Arc<BTreeMap<[u8; 32], Peer>> {
        self.peers_fresh();
        if let Some(p) = &self.peers_cache {
            return p.clone();
        }
        let mut reaches = Vec::new();
        for n in self.reach_nodes().values() {
            if let Ok(Some(r)) = self.engine.get_typed(n, &ct::REACH) {
                let seen = self.engine.get_typed(n, &ct::SEEN).ok().flatten().map(|s| s.ts.0);
                reaches.push((seen, *n, r));
            }
        }
        let mut out: BTreeMap<[u8; 32], Peer> = BTreeMap::new();
        if !reaches.is_empty() {
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
        }
        let out = Arc::new(out);
        self.peers_cache = Some(out.clone());
        out
    }

    /// Forgets the cached co-readers, `/reach` holders and LAN tags when the engine's state
    /// changed or a minute passed since they were computed.
    fn peers_fresh(&mut self) {
        let key = (self.engine.core.generation, self.raw_now() / PEERS_TTL_MS);
        if self.peers_key != key {
            self.peers_key = key;
            self.peers_cache = None;
            self.reach_index = None;
            self.lan_tags = None;
        }
    }

    /// Where to dial each co-reader: its proven LAN address while fresh, else a LAN candidate,
    /// else `peer://` with its relays; never an address backed off.
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
        for (k, p) in self.peers().iter() {
            let route = self.lan.get(k);
            let ok = |x: &Option<(Address, u64)>| x.as_ref().filter(|(a, _)| route.is_none_or(|r| !r.failed.contains_key(a))).map(|(a, _)| a.clone());
            let addr = route.and_then(|r| ok(&r.good).or_else(|| ok(&r.candidate))).unwrap_or_else(|| Address { url: osis_transport::peer_url(&p.reach.relays), key: *k });
            out.insert(*k, (addr, p.labels.clone()));
        }
        out
    }

    /// A connection to a co-reader came up: the transport authenticated the address's key, so a
    /// LAN candidate it went to is the proven route (spec/sync.md §10).
    pub(crate) fn lan_up(&mut self, peer: [u8; 32], addr: &Address) {
        if let Some(r) = self.lan.get_mut(&peer)
            && let Some(c) = r.candidate.take_if(|(a, _)| a == addr)
        {
            r.good = Some(c);
        }
    }

    /// A connection to a co-reader ended before coming up: when it went to a LAN address, that
    /// address is backed off (true; the next route is dialed at once), not the peer.
    pub(crate) fn lan_failed(&mut self, peer: [u8; 32], addr: &Address) -> bool {
        let until = self.raw_now().saturating_add(self.cfg.peer_retry_ms);
        let Some(r) = self.lan.get_mut(&peer) else { return false };
        let mut hit = r.candidate.take_if(|(a, _)| a == addr).is_some();
        hit |= r.good.take_if(|(a, _)| a == addr).is_some();
        if hit {
            r.failed.insert(addr.clone(), until);
        }
        hit
    }

    /// A LAN announcement heard from `from` (spec/sync.md §10). It counts when the source can be
    /// on the LAN, the tag is a co-reader's for the current or an adjacent window (tags computed
    /// once per window) and the signature verifies under that co-reader's dialable key; the
    /// address then becomes the co-reader's candidate route. Returns whose dialable key matched,
    /// and the actions (only when the candidate changed: a repeat costs a lookup).
    pub fn lan_seen(&mut self, a: &Announce, from: IpAddr) -> (Option<[u8; 32]>, Vec<Action>) {
        if !osis_transport::lan::is_local(from) {
            return (None, Vec::new());
        }
        let window = self.now() / LAN_WINDOW_MS;
        self.peers_fresh();
        if self.lan_tags.as_ref().is_none_or(|(w, _)| *w != window) {
            let mut tags = BTreeMap::new();
            for (k, p) in self.peers().iter() {
                for w in [window.saturating_sub(1), window, window.saturating_add(1)] {
                    tags.insert(lan_tag(&p.reach.lan_secret, w.saturating_mul(LAN_WINDOW_MS)), *k);
                }
            }
            self.lan_tags = Some((window, tags));
        }
        let Some(k) = self.lan_tags.as_ref().and_then(|(_, t)| t.get(&a.tag)).copied() else { return (None, Vec::new()) };
        let signed = VerifyingKey::from_bytes(&k).is_ok_and(|vk| vk.verify(Domain::LanAnnounce, &announce_digest(a), &Signature(a.sig)).is_ok());
        if !signed {
            return (None, Vec::new());
        }
        let at = a.address(from);
        let address = Address { url: at.url, key: at.key };
        let raw = self.raw_now();
        let r = self.lan.entry(k).or_default();
        if r.failed.contains_key(&address) {
            return (Some(k), Vec::new());
        }
        for x in [&mut r.good, &mut r.candidate] {
            if let Some((a, at)) = x
                && *a == address
            {
                *at = raw;
                return (Some(k), Vec::new());
            }
        }
        r.candidate = Some((address, raw));
        (Some(k), self.handle(Event::Local))
    }

    /// Entries of `label` arrived on `conn`: from a co-reader, a complete pass of the label then
    /// waits for that co-reader while a connection to it is up (spec/permissions.md §3).
    pub(crate) fn received_from(&mut self, conn: super::ConnId, label: LabelId) {
        if let Some(c) = self.conns.get(&conn).filter(|c| c.peer) {
            self.peer_received.entry(label).or_default().insert(c.server);
        }
    }

    /// Whether `label`'s group gets no `/reach` (an open audience, spec/permissions.md §4).
    pub fn set_no_reach(&mut self, group: Tid, excluded: bool) {
        if excluded {
            self.cfg.no_reach.insert(group);
        } else {
            self.cfg.no_reach.remove(&group);
        }
    }

    /// This node's chain certificates and node card for `g` (`Engine::certificates`), without
    /// its `/reach` commit when `g` is in `SyncConfig.no_reach` (spec/permissions.md §4).
    pub(crate) fn card_certificates(&mut self, g: &Tid) -> BTreeMap<osis_core::CommitId, std::collections::BTreeSet<(usize, usize)>> {
        let mut certs = self.engine.certificates(g);
        if self.cfg.no_reach.contains(g) {
            let me = self.engine.tid();
            certs.retain(|c, _| !self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == me && a.ak.as_str() == "/reach")));
        }
        certs
    }
}
