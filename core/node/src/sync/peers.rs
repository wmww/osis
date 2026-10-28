//! Reachability and co-reader dialing (spec/sync.md §5 last bullet, §10; spec/data-model.md §9;
//! spec/permissions.md §4): this node's `/reach` (dialable key, relays, lan secret), the co-reader
//! nodes it knows from theirs, and LAN discovery tags. A co-reader of a label is a node thing
//! other than this node, holding `/reach`, that may read the label's group; this node dials it at
//! `peer://` + its relays (osis-transport finds it by key), or at the address a matching LAN
//! announcement gave, and syncs those labels with it as with a server.

use super::{Action, Event, SyncEngine};
use crate::error::Result;
use crate::Mutation;
use osis_base::{LabelId, Tid};
use osis_crypto::{Secret32, SigningSecret, VerifyingKey};
use osis_label::Address;
use osis_schema::core_types::{self as ct, Reach};
use osis_transport::lan::Announce;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

/// LAN tag window (spec/sync.md §10).
pub const LAN_WINDOW_MS: u64 = 600_000;
/// How long a LAN announcement is used for dialing.
pub const LAN_FRESH_MS: u64 = 2 * LAN_WINDOW_MS;
/// Co-readers are computed again at least this often (edges expire with time).
const PEERS_TTL_MS: u64 = 60_000;
/// A co-reader's LAN candidate changes at most once in this long (announcement floods).
pub const LAN_CHANGE_MS: u64 = 5_000;

/// The LAN announcement tag of a lan secret at `unix_ms` (spec/sync.md §10):
/// `kdf("lan tag", lan secret, le64(floor(unix ms / 600000)))`, first 16 bytes.
pub fn lan_tag(lan_secret: &[u8; 32], unix_ms: u64) -> [u8; 16] {
    let window = unix_ms / LAN_WINDOW_MS;
    let k = osis_crypto::kdf::kdf("lan tag", lan_secret, &window.to_le_bytes());
    let mut t = [0u8; 16];
    t.copy_from_slice(k.expose().get(..16).unwrap_or(&[0; 16]));
    t
}

/// Whether an address names a node by dialable key (`peer://`), not a server.
pub fn is_peer(a: &Address) -> bool {
    osis_transport::peer_relays(&a.url).is_some()
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
/// address whose connection fails before coming up is backed off (not the peer). A new
/// candidate ends the peer's retry pause at most once per `peer_retry_ms`, so replayed
/// announcements from many sources cannot make the node dial in a loop.
#[derive(Clone, Debug, Default)]
pub(crate) struct LanRoute {
    /// Proven address and when last heard (raw ms).
    pub good: Option<(Address, u64)>,
    pub candidate: Option<(Address, u64)>,
    /// Addresses that failed, until when.
    pub failed: BTreeMap<Address, u64>,
    /// When a new candidate last ended the peer's retry pause (raw ms).
    pub cut: Option<u64>,
    /// When the candidate last changed (raw ms).
    pub changed: Option<u64>,
    /// The last announcement whose signature verified (a repeat is not verified again).
    pub verified: Option<Announce>,
    /// Verified source addresses and how often each was heard (at most `LAN_HEARD`): a failed
    /// candidate falls back to the most heard, so a replay from a spoofed source that wins the
    /// candidate costs one failed dial.
    pub heard: BTreeMap<Address, u32>,
}

/// Verified source addresses remembered per co-reader.
const LAN_HEARD: usize = 4;

/// Co-readers' LAN tags (the cached window and its neighbours) to their dialable key, lan
/// secret and window.
pub(crate) type LanTags = BTreeMap<[u8; 16], ([u8; 32], [u8; 32], u64)>;


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

    /// Rotates this node's reach now (`Osis::rotate_reach`; also done by itself when a label
    /// holding the current `/reach` stopped qualifying, `check_reach`): a new dialable secret and
    /// lan secret, `/reach` written with the new key and the same relays (it goes only under
    /// labels that qualify, spec/permissions.md §4), and `Action::Reach` so the driver listens
    /// with the new key and joins the LAN with a fresh one. The osis handle also rotates when a
    /// direct link ends. A co-reader removed since can no longer dial this node or recognise it
    /// on a LAN; a link holder (who got the dialable key only, never the lan secret) can no
    /// longer dial it. Direct links still open lose first contact (they work through servers).
    #[must_use]
    pub fn rotate_reach(&mut self) -> Vec<Action> {
        let mut out = Vec::new();
        if let Err(e) = self.rotate_now(&mut out) {
            self.diag(format!("rotating /reach: {e}"));
        }
        out.extend(self.handle(Event::Local));
        out
    }

    fn rotate_now(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let relays = self.own_reach().map(|r| r.relays);
        self.state.reach_secret = None;
        self.lan_rotate = true;
        let s = self.dialable_secret();
        // every transport's key is the Ed25519 key of its secret (the driver's listener presents it)
        if let Some(relays) = relays {
            self.write_reach(SigningSecret::from_seed(&s).verifying_key().to_bytes(), relays)?;
        }
        out.push(Action::Reach);
        Ok(())
    }

    /// Looks for this node's current `/reach` under a label of a group that no longer qualifies
    /// (`publishes_reach`: its policy turned to exclude, a reader is no contact any more) and
    /// rotates it then (spec/permissions.md §4): readers there keep the old one, useless.
    pub(crate) fn check_reach(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let me = self.engine.tid();
        let Some((c, _)) = self.engine.aspect_commit(&me, "/reach") else { return Ok(()) };
        let placed: Vec<(Tid, LabelId)> = self.labels().into_iter().map(|(g, l)| (g, l.id)).filter(|(_, l)| self.state.certs.contains(&(*l, c))).collect();
        if placed.iter().any(|(g, _)| !self.publishes_reach(g)) {
            self.rotate_now(out)?;
            self.engine_events()?;
        }
        Ok(())
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
        if !self.write_reach(dialable, relays)? {
            return Ok(Vec::new());
        }
        Ok(self.handle(Event::Local))
    }

    /// Commits `/reach` when it changed; true when it did.
    fn write_reach(&mut self, dialable: [u8; 32], relays: Vec<String>) -> Result<bool> {
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
            return Ok(false);
        }
        let me = self.engine.tid();
        let mut m = Mutation::new();
        m.replace(me, &ct::REACH, &reach)?;
        self.engine.commit(m)?;
        self.lan_rotate = false;
        Ok(true)
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
    /// the current tag and the signature under the dialable key, sealed under the lan secret
    /// and window (spec/sync.md §10). None before `/reach` is published, or when its dialable
    /// key is not the Ed25519 key of the dialable secret.
    pub fn lan_announcement(&mut self, key: [u8; 32], port: u16) -> Option<Announce> {
        let r = self.own_reach()?;
        let sk = SigningSecret::from_seed(self.state.reach_secret.as_ref()?);
        if sk.verifying_key().to_bytes() != r.dialable {
            self.diag("LAN: the published dialable key is not the dialable secret's".into());
            return None;
        }
        let window = self.now() / LAN_WINDOW_MS;
        let tag = lan_tag(&r.lan_secret, self.now());
        let sig = osis_crypto::seal_lan_sig(&sk, &Secret32::from_bytes(r.lan_secret), window, &tag, &key, port);
        Some(Announce { tag, key, port, sig })
    }

    /// Node things with a `/reach` this node holds, other than itself, by dialable key (cached
    /// until a commit applies). A key two node things claim matches neither.
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
        let mut twice = BTreeSet::new();
        for n in nodes {
            if let Ok(Some(r)) = self.engine.get_typed(&n, &ct::REACH)
                && Some(r.dialable) != own
                && m.insert(r.dialable, n).is_some_and(|x| x != n)
            {
                twice.insert(r.dialable);
            }
        }
        m.retain(|k, _| !twice.contains(k));
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
                // a group whose labels carry no `/reach` of ours: its co-readers are not dialed
                if !self.publishes_reach(&g) {
                    continue;
                }
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
        let pause = self.cfg.peer_retry_ms;
        self.lan.retain(|_, r| r.good.is_some() || r.candidate.is_some() || !r.failed.is_empty() || r.cut.is_some_and(|t| t.saturating_add(pause) > now));
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
    /// LAN candidate it went to is the proven route (spec/sync.md §10). True when the connection
    /// goes through the proven LAN route.
    pub(crate) fn lan_up(&mut self, peer: [u8; 32], addr: &Address) -> bool {
        let raw = self.raw_now();
        let Some(r) = self.lan.get_mut(&peer) else { return false };
        if let Some(c) = r.candidate.take_if(|(a, _)| a == addr) {
            r.good = Some(c);
        } else if r.good.as_ref().is_none_or(|(a, _)| a != addr) && r.heard.contains_key(addr) {
            // a verified source the candidate moved away from while its dial ran
            r.good = Some((addr.clone(), raw));
        }
        r.good.as_ref().is_some_and(|(a, _)| a == addr)
    }

    /// Whether to dial a co-reader's LAN route `addr` beside its running connection: one
    /// connection runs, it is up and goes elsewhere (a relay), and `addr` is the LAN route.
    pub(crate) fn lan_probe(&self, peer: &[u8; 32], addr: &Address) -> bool {
        let Some(r) = self.lan.get(peer) else { return false };
        let lan = [&r.good, &r.candidate].into_iter().flatten().any(|(a, _)| a == addr) && !r.failed.contains_key(addr);
        let mut running = self.conns.values().filter(|c| c.server == *peer);
        lan && matches!((running.next(), running.next()), (Some(c), None) if c.up && c.address != *addr)
    }

    /// A co-reader's connection through its proven LAN route came up: the other connections to
    /// it (a relay route it ran over before) close; its labels go on over the LAN connection
    /// from their cursors (spec/sync.md §10: the proven route first).
    pub(crate) fn lan_switched(&mut self, conn: super::ConnId, peer: [u8; 32], out: &mut Vec<Action>) {
        let old: Vec<super::ConnId> = self.conns.iter().filter(|(id, c)| **id != conn && c.server == peer).map(|(id, _)| *id).collect();
        if old.is_empty() {
            return;
        }
        for c in old {
            out.push(Action::Close { conn: c });
            self.lost(c);
        }
        // the peer is connected: no pause from the closed route
        self.retry.remove(&peer);
    }

    /// Connections to co-readers: dialable key, the address dialed (a LAN route or `peer://`
    /// with relays) and whether it is up.
    pub fn peer_routes(&self) -> Vec<([u8; 32], Address, bool)> {
        self.conns.values().filter(|c| c.peer).map(|c| (c.server, c.address.clone(), c.up)).collect()
    }

    /// Records the sharer node a followed link names (`peers`: its `peer://` addresses, from
    /// the link text only; spec/permissions.md §9). It is dialed like a co-reader (ephemeral key,
    /// no member proof) for K's labels and the target's, and nothing else, until `forget_link`.
    /// This node shows the sharer its IP, never its dialable key.
    pub fn follow_link_peer(&mut self, k: Tid, target: Tid, peers: Vec<Address>) {
        let peers: Vec<Address> = peers.into_iter().filter(is_peer).collect();
        if peers.is_empty() {
            return;
        }
        self.state.set_link_peer(k, super::state::LinkPeer { target, peers });
        let _ = self.state.flush(&mut self.engine);
    }

    /// The sharer nodes of followed links (their dialable keys).
    pub fn link_peer_keys(&self) -> BTreeSet<[u8; 32]> {
        self.state.link_peers.values().flat_map(|lp| lp.peers.iter().map(|a| a.key)).collect()
    }

    /// A link follow ended without a redemption (it failed, or its key guard went): its hint
    /// and sharer node are forgotten.
    #[must_use]
    pub fn forget_link(&mut self, k: Tid) -> Vec<Action> {
        self.state.remove_link_peer(&k);
        let hinted: Vec<LabelId> = self.state.hints.iter().filter(|(_, h)| h.thing == k && h.via.is_some()).map(|(l, _)| *l).collect();
        for l in hinted {
            self.state.remove_hint(&l);
        }
        self.handle(Event::Local)
    }

    /// Where to dial followed links' sharer nodes, by key, with the labels each serves here: K's
    /// hinted label and the synced labels of K and of the target.
    pub(crate) fn link_routes(&mut self) -> BTreeMap<[u8; 32], (Address, BTreeSet<LabelId>)> {
        if self.state.link_peers.is_empty() {
            return BTreeMap::new();
        }
        let synced = self.labels();
        let mut out: BTreeMap<[u8; 32], (Address, BTreeSet<LabelId>)> = BTreeMap::new();
        for (k, lp) in &self.state.link_peers {
            let mut labels: BTreeSet<LabelId> = synced.iter().filter(|(g, _)| g == k || *g == lp.target).map(|(_, l)| l.id).collect();
            labels.extend(self.state.hints.iter().filter(|(_, h)| h.thing == *k && h.via.is_some()).map(|(l, _)| *l));
            for a in &lp.peers {
                out.entry(a.key).or_insert_with(|| (a.clone(), BTreeSet::new())).1.extend(labels.iter().copied());
            }
        }
        out
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
            r.heard.remove(addr);
            // the most heard other address takes over
            let next = r.heard.iter().filter(|(a, _)| !r.failed.contains_key(*a)).max_by_key(|(_, n)| **n).map(|(a, _)| a.clone());
            if r.good.is_none()
                && let Some(a) = next
            {
                r.candidate = Some((a, self.clock.now_wall_ms().0));
            }
        }
        hit
    }

    /// The co-readers a complete pass of each label waits for now (`pass_peers`): those it
    /// received the label from that still read it, with a connection up that has it started.
    pub(crate) fn update_pass_peers(&mut self) {
        if self.peer_received.is_empty() {
            self.pass_peers.clear();
            return;
        }
        let peers = self.peers();
        let mut out: BTreeMap<LabelId, BTreeSet<[u8; 32]>> = BTreeMap::new();
        for (l, ks) in &self.peer_received {
            for k in ks {
                let reads = peers.get(k).is_some_and(|p| p.labels.contains(l));
                if reads && self.conns.values().any(|c| c.peer && c.up && c.server == *k && c.labels.contains_key(l)) {
                    out.entry(*l).or_default().insert(*k);
                }
            }
        }
        self.pass_peers = out;
    }

    /// Whether a waiting LAN candidate may skip the peer's retry pause now (at most once per
    /// `peer_retry_ms`); records the cut.
    pub(crate) fn lan_cut(&mut self, peer: [u8; 32]) -> bool {
        let raw = self.raw_now();
        let pause = self.cfg.peer_retry_ms;
        let Some(r) = self.lan.get_mut(&peer) else { return false };
        let waiting = r.candidate.as_ref().is_some_and(|(a, _)| !r.failed.contains_key(a));
        if waiting && r.cut.is_none_or(|t| t.saturating_add(pause) <= raw) {
            r.cut = Some(raw);
            return true;
        }
        false
    }

    /// A LAN announcement heard from `from` (spec/sync.md §10). It counts when the source can be
    /// on the LAN, the tag is a co-reader's for the current or an adjacent window (tags computed
    /// once per window) and the signature verifies under that co-reader's dialable key; the
    /// address then becomes the co-reader's candidate route. Returns whose dialable key matched,
    /// and the actions (only when the candidate changed: a repeat costs a lookup).
    pub fn lan_seen(&mut self, a: &Announce, from: SocketAddr) -> (Option<[u8; 32]>, Vec<Action>) {
        if !osis_transport::lan::is_local(from.ip()) {
            return (None, Vec::new());
        }
        let window = self.now() / LAN_WINDOW_MS;
        self.peers_fresh();
        if self.lan_tags.as_ref().is_none_or(|(w, _)| *w != window) {
            let mut tags = BTreeMap::new();
            for (k, p) in self.peers().iter() {
                for w in [window.saturating_sub(1), window, window.saturating_add(1)] {
                    tags.insert(lan_tag(&p.reach.lan_secret, w.saturating_mul(LAN_WINDOW_MS)), (*k, p.reach.lan_secret, w));
                }
            }
            self.lan_tags = Some((window, tags));
        }
        let Some((k, secret, w)) = self.lan_tags.as_ref().and_then(|(_, t)| t.get(&a.tag)).copied() else { return (None, Vec::new()) };
        let raw = self.raw_now();
        let r = self.lan.entry(k).or_default();
        if r.verified.as_ref() != Some(a) {
            let ok = VerifyingKey::from_bytes(&k).is_ok_and(|vk| osis_crypto::open_lan_sig(&vk, &Secret32::from_bytes(secret), w, &a.tag, &a.key, a.port, &a.sig));
            if !ok {
                return (None, Vec::new());
            }
            r.verified = Some(*a);
        }
        let at = a.address(from);
        let address = Address { url: at.url, key: at.key };
        if r.failed.contains_key(&address) {
            return (Some(k), Vec::new());
        }
        if !r.heard.contains_key(&address) && r.heard.len() >= LAN_HEARD
            && let Some(least) = r.heard.iter().min_by_key(|(_, n)| **n).map(|(a, _)| a.clone())
        {
            r.heard.remove(&least);
        }
        *r.heard.entry(address.clone()).or_default() += 1;
        for x in [&mut r.good, &mut r.candidate] {
            if let Some((a, at)) = x
                && *a == address
            {
                *at = raw;
                return (Some(k), Vec::new());
            }
        }
        if r.changed.is_some_and(|t| t.saturating_add(LAN_CHANGE_MS) > raw) {
            return (Some(k), Vec::new());
        }
        r.candidate = Some((address, raw));
        r.changed = Some(raw);
        // dial it now, even inside the retry pause, once per pause length
        if self.retry.contains_key(&k) && self.lan_cut(k) {
            self.retry.remove(&k);
        }
        // nothing to do while its pause holds, or while a connection to the peer runs but over
        // a relay, where the LAN route is dialed beside it (`lan_probe`)
        let running = self.conns.values().any(|c| c.server == k);
        let address = Address { url: a.address(from).url, key: a.key };
        if running && !self.lan_probe(&k, &address) || !running && self.retry.get(&k).is_some_and(|(_, t)| *t > raw) {
            return (Some(k), Vec::new());
        }
        (Some(k), self.handle(Event::Local))
    }

    /// Entries of `label` arrived on `conn`: from a co-reader, a complete pass of the label then
    /// waits for that co-reader while a connection to it is up (spec/permissions.md §3).
    pub(crate) fn received_from(&mut self, conn: super::ConnId, label: LabelId) {
        if let Some(c) = self.conns.get(&conn).filter(|c| c.peer) {
            self.peer_received.entry(label).or_default().insert(c.server);
        }
    }

    /// Whether `group`'s labels carry this node's `/reach` (spec/permissions.md §4): `Some`
    /// sets it, `None` returns to the default (`publishes_reach`). Stored. A group that stops
    /// qualifying while its labels hold the current `/reach` rotates it (`check_reach`).
    #[must_use]
    pub fn set_reach_policy(&mut self, group: Tid, publish: Option<bool>) -> Vec<Action> {
        self.state.set_reach_policy(group, publish);
        self.policy_changed()
    }

    /// Marks a person as a contact of this node's person (stored): groups whose readers are only
    /// contacts get `/reach` by default. Unmarking may rotate `/reach` (`check_reach`).
    #[must_use]
    pub fn set_contact(&mut self, person: Tid, contact: bool) -> Vec<Action> {
        self.state.set_contact(person, contact);
        self.policy_changed()
    }

    fn policy_changed(&mut self) -> Vec<Action> {
        self.peers_cache = None;
        self.reach_check = true;
        self.handle(Event::Local)
    }

    /// Whether `/reach` goes under `g`'s labels: the policy set for `g`, else when everyone who
    /// reads it is this node's own or a contact (notes/sync.md: excluded by default from labels
    /// shared with non-contacts): its reader actor is this node's own (an actor this node is a
    /// member of), or each member of it is this node's own, a contact, or a thing such an actor
    /// owns whose own members pass the same test (a link's group holds a key actor: it fails).
    pub fn publishes_reach(&self, g: &Tid) -> bool {
        if let Some(p) = self.state.reach_policy.get(g) {
            return *p;
        }
        self.contacts_only(&self.engine.group_actor(g), 4)
    }

    fn contacts_only(&self, actor: &Tid, depth: u32) -> bool {
        let me = self.engine.tid();
        let own = |x: &Tid| *x == me || self.engine.core.current_members(x).iter().any(|(t, _, _)| *t == me);
        if own(actor) {
            return true;
        }
        let owned = |t: &Tid| {
            let mut cur = self.engine.owner(t).filter(|o| o != t);
            for _ in 0..16 {
                match cur {
                    Some(x) if own(&x) => return true,
                    Some(x) => cur = self.engine.owner(&x).filter(|o| *o != x),
                    None => return false,
                }
            }
            false
        };
        self.engine.core.current_members(actor).iter().all(|(m, _, _)| own(m) || self.state.contacts.contains(m) || depth > 0 && owned(m) && self.contacts_only(m, depth - 1))
    }

    /// This node's chain certificates and node card for `g` (`Engine::certificates`), without
    /// its `/reach` commit where `publishes_reach` says no (spec/permissions.md §4).
    pub(crate) fn card_certificates(&mut self, g: &Tid) -> BTreeMap<osis_base::CommitId, std::collections::BTreeSet<(usize, usize)>> {
        let mut certs = self.engine.certificates(g);
        if !self.publishes_reach(g) {
            let me = self.engine.tid();
            certs.retain(|c, _| !self.engine.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == me && a.ak.as_str() == "/reach")));
        }
        certs
    }
}
