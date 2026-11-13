//! Connections this node dialed: dialing, the labels on each, its own requests in flight and their
//! answers. Every dialed connection is a session of the node's hub (`osis_host::Hub::dial`), as
//! every served one is; node sync sends its requests through it, picking their ids, and takes
//! their answers back (`dialed_up`).

use super::*;
use osis_proto::Message;
use osis_proto::msg::{Id, NODE_IDS};

/// A Deposit item or delete whose request was answered without settling it (a refusal, an entry
/// the source's stream does not show) goes again at the first pass this long after it was given
/// (ms).
/// Minor consequence: pacing of retries only (an unanswered request never goes again: a slow
/// link only queues the copy behind the first, and a dead one closes at `STALL_TIMEOUT_MS`);
/// 0 retries at every pass, infinity never retries on this connection (the next one does).
const RESEND_MS: u64 = 30_000;

/// Whether a request for `k` on `c` is still unanswered (the id it went under, 0 for none), or
/// was given less than `RESEND_MS` before `now`.
pub(crate) fn in_flight(c: &Conn, m: &BTreeMap<(LabelId, osis_base::BlobId), (u64, Id)>, k: (LabelId, osis_base::BlobId), now: u64) -> bool {
    m.get(&k).is_some_and(|(t, id)| now < t.saturating_add(RESEND_MS) || (*id != 0 && c.pending.contains_key(id)))
}

/// A request this node sent on a dialed connection and has no answer to yet (ids below
/// `NODE_IDS`; the shared set's and the stream's are theirs).
#[derive(Clone, Debug)]
pub(crate) enum Pending {
    /// A clock sample's start (spec/sync.md §6), wall ms.
    Ping { sent: u64 },
    Prove,
    Resume,
    Register(LabelId),
    /// The entries a Delete names.
    Delete(LabelId, Vec<osis_base::BlobId>),
}

/// Open state of a label on a connection: one per (connection, label), and `Open` exactly while
/// the label is a member of the connection's shared set (notes/node-sync.md, Label states).
#[derive(Clone, Debug)]
pub(crate) enum Phase {
    /// Waiting for the peer's filter: each arrival tests the credential of `shown` (the walk found
    /// it shown: a recorded step's, or a held sync key no recorded step bears, its step `None`),
    /// else of the newest step known there (`SyncEngine::newest_known`), and a Hit opens it
    /// (issues/net-one-peer.md 3h2, Stale head).
    Testing { shown: Option<Box<(Option<Step>, osis_crypto::SigningSecret)>> },
    /// Registering the recorded path at a peer that lacks the label: its steps not answered yet.
    Registering { path: Vec<Step> },
    /// The peer's head is past the newest step known, or off it: Behind items ask
    /// (`SyncEngine::behind`); `refused`, the recorded steps the peer refused one on in this
    /// walk, not asked again.
    Behind { refused: Vec<osis_label::StepId> },
    /// A member of the connection's shared set. `by`: the key whose open signature opened it at
    /// a peer that cannot read L (a sync key, or a claim's; none by read credentials or a static
    /// entry), its credential there until the head moves past it (`new_head`). `doubted`: the
    /// head the peer refused a child of, or named another head past (two admins' sibling steps
    /// share their keys, so a Hit opens at whichever the peer holds): no child is registered
    /// under it, and Behind items walk back from it to the peer's path (`SyncEngine::doubt`).
    Open { by: Option<Box<osis_crypto::SigningSecret>>, doubted: Option<osis_label::StepId> },
    /// No key opens it here (`entry_refused`: the peer answered a Behind item by this node's
    /// static entry with a refusal, its head not listing it, `SyncEngine::static_entry_refused`).
    Failed { entry_refused: bool },
    /// The peer refused registering it for now (not admitted, full, the rate) or does not hold it
    /// and this node cannot register it: tested again from scratch at `retry_at` (wall ms).
    Refused { retry_at: u64 },
}

impl Phase {
    pub(crate) fn is_open(&self) -> bool {
        matches!(self, Phase::Open { .. })
    }

    pub(crate) fn is_testing(&self) -> bool {
        matches!(self, Phase::Testing { .. })
    }

    pub(crate) fn is_failed(&self) -> bool {
        matches!(self, Phase::Failed { .. })
    }
}

/// One label on one connection.
#[derive(Clone)]
pub(crate) struct LConn {
    pub group: Tid,
    pub phase: Phase,
    /// The newest step of the label known at the peer here: its head while open (its stream
    /// names each move), else where a Behind walk, a static entry's grant or the last open there
    /// got to.
    pub head: Option<Step>,
    pub keys: HeadKeys,
    /// `SyncEngine::seq` when the connection's last Pull was sent: its end is no pass end after
    /// a role commit applied since (`stream_read`).
    pub sync_seq: u64,
    /// The stream read it to the peer's end since it last joined there (`stream_read`).
    pub synced: bool,
    /// The label's first sync at this host is under way (`fill`).
    pub fill: Option<fill::Fill>,
    /// A child step sent for registration.
    pub registering: Option<(Step, osis_label::ClaimSet)>,
    /// The node log position the peer's reports must reach before a step is registered here:
    /// the role commits it lacks were logged under its head and go first (`roles_unreported`).
    pub report_at: Option<u64>,
    /// The peer said it refused an entry of the label it pulled for room and has none again
    /// yet (spec/sync.md §10, Full): what it lacks it lacks, and nothing waits for it to take
    /// it.
    pub full: bool,
    /// Bodies this node places, stamped for the peer's head, that the last pass found the peer
    /// lacking (it pulls them): while any is and the peer is not full, the label is not caught
    /// up there (`label_status`).
    pub lacking: usize,
    /// Bodies this node logs, stamped for the peer's head, that the peer refused under that
    /// stamp and head (spec/sync.md §10, Refused; `State::refused`), at the last pass: it will
    /// not take them, so nothing waits for them, and status names it (`refused_by`).
    pub refused: usize,
    /// A child step refused for now: no pass registers one before this (wall ms).
    pub step_retry: u64,
    /// Child steps refused in a row (the back-off doubles per refusal; an open or a registered
    /// step resets it).
    pub step_refusals: u32,
    /// Failed: when it failed; Testing: when it was last walked (each again `resync_ms` on).
    pub last_sync: u64,
    /// A listing from the start under way here: what was present here before it, and whether
    /// the peer marked it trimmed (`known_join`, `stream_read`).
    pub relisted: Option<(BTreeSet<osis_base::BlobId>, bool)>,
    /// Write keys of steps verified here that `label.0` does not record (a grant's path, a
    /// Behind walk's): stamps under them vouch for an entry.
    pub writers: Vec<osis_crypto::VerifyingKey>,
}

impl LConn {
    /// The log was read to its end and nothing runs.
    pub(super) fn ready(&self) -> bool {
        self.synced && self.registering.is_none()
    }

    /// A fill here has not all that judging needs.
    pub(super) fn first_waits(&self) -> bool {
        self.phase.is_open() && self.fill.as_ref().is_some_and(|f| !f.first_done)
    }

    /// Ready, with no fill under way: nothing to do here until something changes.
    pub(super) fn settled(&self) -> bool {
        self.ready() && self.fill.is_none()
    }

    /// Settled, and lacking nothing this node places unless full: caught up there.
    pub(super) fn idle(&self) -> bool {
        self.settled() && (self.lacking == 0 || self.full)
    }
}

#[derive(Clone)]
pub(crate) struct Conn {
    /// A host's address key, or a co-reader node's dialable key (its LAN address may present
    /// another transport key).
    pub host: HostKey,
    pub address: Address,
    /// A co-reader node, not a host.
    pub peer: bool,
    /// The hub's connection, once the transport is up (`Event::Up`).
    pub hub: Option<osis_host::ConnId>,
    /// `(dialer challenge, listener challenge, listener key)`, once the peer's Hello arrived
    /// (`Up::Start`): requests go from then on.
    pub binding: Option<([u8; 32], [u8; 32], [u8; 32])>,
    /// This node's requests not answered yet, by id (`request`), and the last id taken.
    pub pending: BTreeMap<Id, Pending>,
    pub next_id: Id,
    /// When the next Ping goes (`PING_INTERVAL_MS`), and the Pongs' clock samples.
    pub next_ping: u64,
    /// When node sync last sent or got a message on it (wall ms; `refresh`).
    pub heard: u64,
    pub clock: osis_proto::ClockSamples,
    /// What this connection's peer proved (spec/sync.md §10), read by `SyncEngine::proven`.
    pub proven: super::proofs::Proven,
    /// The actors this node proved on it (its Prove), read by `SyncEngine::proved`.
    pub proved: BTreeSet<Tid>,
    pub up: bool,
    pub labels: BTreeMap<LabelId, LConn>,
    pub req: Requests,
}

impl Conn {
    /// The peer's Hello arrived: requests may go.
    pub(crate) fn is_ready(&self) -> bool {
        self.binding.is_some()
    }
}

/// Requests on a connection not answered yet, and what its host would not deliver: they go
/// with the connection (asked again on the next one).
#[derive(Clone, Default)]
pub(crate) struct Requests {
    /// Bodies sent to this connection's source as Deposit items (`deposit_items`), with when
    /// (wall ms) and no request id: passes skip them within `RESEND_MS` (`in_flight`).
    pub sent: BTreeMap<(LabelId, osis_base::BlobId), (u64, Id)>,
    /// Deletes sent, with when and the Delete's id: skipped while it is unanswered too.
    pub deleting: BTreeMap<(LabelId, osis_base::BlobId), (u64, Id)>,
    /// Blobs the host did not deliver when fetched (since it last announced them).
    pub missing: BTreeSet<osis_base::BlobId>,
    /// Labels walked because they were not members after a filter arrival, with that arrival's
    /// number: once per arrival (`shared_unopened`).
    pub walked: BTreeMap<LabelId, u64>,
    /// Sync-key credentials whose Hit the peer refused since its last filter arrival: not shown
    /// to the walk (a filter keeps a moved head's entries until a whole one is sent).
    pub refused: BTreeSet<(LabelId, [u8; 32])>,
    /// Labels whose recorded path the peer took to its newest step since they were last open
    /// or started here (`start_label` clears it), with the filter arrival and time then: a walk at a later arrival, or `resync_ms`
    /// on (a registration the peer held already changes no filter), that finds no credential
    /// shown strands the label (`shared_unopened`) instead of registering again.
    pub registered: BTreeMap<LabelId, (u64, u64)>,
}

impl Requests {
    /// Drops what is recorded of the labels `gone` names (left this connection).
    pub fn forget(&mut self, gone: impl Fn(&LabelId) -> bool) {
        self.sent.retain(|(l, _), _| !gone(l));
        self.deleting.retain(|(l, _), _| !gone(l));
        self.walked.retain(|l, _| !gone(l));
        self.registered.retain(|l, _| !gone(l));
        self.refused.retain(|(l, _)| !gone(l));
    }
}

impl SyncEngine {
    /// Until when blob `b` counts as asked (wall ms), `None` when it is asked nowhere now. One rule
    /// for every source, a host or a reader: a fetch counts while it is younger than
    /// `STALL_TIMEOUT_MS`; older, it may be held behind a reply its source trickles (the stall
    /// rule only wants the oldest request to move), so the next source is asked too and whichever
    /// answers first settles it (spec/sync.md §10, Bodies).
    pub(crate) fn asked(&self, b: &osis_base::BlobId) -> Option<u64> {
        let now = self.now();
        self.stream_asks(b).map(|at| at.saturating_add(osis_proto::window::STALL_TIMEOUT_MS)).filter(|t| *t > now).max()
    }

    /// `asked`, with a pass of `l` (`settle_by`) when it ends: what skipped or waited on `b` for
    /// it (a fill, a pass, a stream) looks again then.
    pub(crate) fn asked_for(&mut self, l: LabelId, b: &osis_base::BlobId) -> bool {
        let Some(t) = self.asked(b) else { return false };
        self.settle_by(t, l);
        true
    }

    /// Whether `b` may be fetched of `conn`'s source under `l`: not out there already, whatever
    /// its age (each source asked once while its fetch is out), and not asked anywhere now.
    pub(crate) fn may_ask(&mut self, conn: ConnId, l: LabelId, b: &osis_base::BlobId) -> bool {
        let here = self.stream_asks_on(conn, b);
        !here && !self.asked_for(l, b)
    }

    /// Label `l` on connection `conn`.
    pub(crate) fn lc(&self, conn: ConnId, l: &LabelId) -> Option<&LConn> {
        self.conns.get(&conn)?.labels.get(l)
    }


    pub(crate) fn lc_mut(&mut self, conn: ConnId, l: &LabelId) -> Option<&mut LConn> {
        self.conns.get_mut(&conn)?.labels.get_mut(l)
    }

    /// A dialed connection ended (or was closed here): redial after the retry pause.
    pub(crate) fn lost(&mut self, conn: ConnId) {
        // its requests not answered go with it (asked again on the next connection)
        if let Some(c) = self.conns.remove(&conn) {
            if let Some(h) = c.hub {
                self.hub_conns.remove(&h);
            }
            self.rooms.remove(&conn);
            self.records.conn_gone(conn);
            self.streams.remove(&conn);
            if let Err(e) = self.memory_lost(conn, c.host) {
                self.diag(format!("forgetting a connection's memory entries: {e}"));
            }
            // deposits not answered on this connection go out again on the next one
            for o in self.outbox.values_mut().filter(|o| o.sent == Some(conn)) {
                o.sent = None;
            }
            // a LAN address that never came up: back off that address, not the peer (the next
            // route is dialed at once)
            if c.peer && !c.up && self.lan_failed(c.host, &c.address) {
                return;
            }
            // another route failed while a LAN candidate waited: it goes now (once per pause)
            if c.peer && !c.up && self.lan_cut(c.host) {
                return;
            }
            // a co-reader whose connection was up is redialed at once, at most once per
            // `peer_retry_ms` (a peer closing every session must not make a dial loop): a P2P dial
            // that punched through ends its relayed connection and the redial takes the direct
            // one (notes/networking.md, switching)
            let now = self.now();
            let pause = self.cfg.peer_retry_ms;
            self.redialed.retain(|_, t| t.saturating_add(pause) > now);
            let quick = c.peer && c.up && !self.redialed.contains_key(&c.host);
            // the sharer node of a link being redeemed is that redemption's one route (first
            // contact, its key perhaps not listened on yet): redialed after a host's pause, not a
            // co-reader's; once redeemed it is paced like any co-reader
            let sharer = c.peer && self.state.link_peers.iter().any(|(k, lp)| self.redeeming.contains(k) && lp.peers.iter().any(|a| a.key == c.host));
            let pause = match (quick, c.peer && !sharer) {
                (true, _) => {
                    self.redialed.insert(c.host, now);
                    0
                }
                (false, true) => pause,
                (false, false) => self.cfg.retry_ms,
            };
            self.retry.insert(c.host, (c.address, self.now().saturating_add(pause)));
        }
    }

    /// The hosts and co-reader nodes to keep connections to (true: a node).
    pub(super) fn wanted_hosts(&mut self) -> BTreeMap<HostKey, (Address, bool)> {
        let mut m: BTreeMap<HostKey, (Address, bool)> = self.cfg.hosts.iter().map(|a| (a.key, (a.clone(), false))).collect();
        // an address names a node by its key, whatever its scheme
        fn add<'a>(m: &mut BTreeMap<HostKey, (Address, bool)>, hosts: impl IntoIterator<Item = &'a Address>) {
            for a in hosts {
                m.entry(a.key).or_insert_with(|| (a.clone(), false));
            }
        }
        for (_, l) in self.labels() {
            add(&mut m, &l.hosts);
        }
        for h in self.state.hints.values() {
            add(&mut m, &h.hosts);
        }
        // a queued deposit's host until it takes it (an inbox host of no label synced here)
        add(&mut m, self.state.outbox.values().filter_map(|o| if let super::state::Dest::Host(a) = &o.to { Some(a) } else { None }));
        if self.cfg.peers {
            for (k, (a, _)) in self.peer_addresses() {
                m.entry(k).or_insert((a, true));
            }
            // a link's sharer node (first contact, spec/permissions.md §7) is dialed as a co-reader
            for (k, (a, _)) in self.link_routes() {
                m.entry(k).or_insert((a, true));
            }
        }
        if let Some(me) = self.own_key() {
            m.remove(&me);
        }
        m
    }

    /// Dials wanted hosts without a connection (after their retry time); adds labels to
    /// open connections.
    pub(super) fn connect(&mut self, out: &mut Vec<Action>) {
        let now = self.now();
        let wanted = self.wanted_hosts();
        // a host no longer wanted keeps no retry time (it would hold the wake in the past)
        self.retry.retain(|k, _| wanted.contains_key(k));
        // a peer connected by a session it dialed is not dialed (`bind_record`)
        self.stand_in.retain(|_, c| self.served.contains_key(c));
        for (key, (addr, peer)) in wanted {
            if self.stand_in.contains_key(&key) {
                continue;
            }
            // a co-reader reached off the LAN that is heard on it: its LAN route is dialed beside
            // the running connection, which goes once that is up (`lan_switched`)
            if self.conns.values().any(|c| c.host == key) && !(peer && self.lan_probe(&key, &addr)) {
                continue;
            }
            if self.retry.get(&key).is_some_and(|(_, t)| *t > now) {
                continue;
            }
            self.retry.remove(&key);
            let conn = self.next_conn;
            self.next_conn += 1;
            let c = Conn { host: key, address: addr.clone(), peer, hub: None, binding: None, pending: BTreeMap::new(), next_id: 0, next_ping: 0, heard: 0, clock: Default::default(), proven: super::proofs::Proven::default(), proved: BTreeSet::new(), up: false, labels: BTreeMap::new(), req: Requests::default() };
            self.conns.insert(conn, c);
            out.push(Action::Dial { conn, address: addr });
        }
    }

    /// Closes connections to co-readers no longer wanted (removed, or sharing only labels
    /// whose `reach.0` this node withholds).
    pub(super) fn drop_unwanted_peers(&mut self, out: &mut Vec<Action>) {
        if self.conns.values().all(|c| !c.peer) {
            return;
        }
        let wanted: BTreeSet<HostKey> = if self.cfg.peers { self.peers().keys().copied().chain(self.link_routes().into_keys()).collect() } else { BTreeSet::new() };
        let gone: Vec<ConnId> = self.conns.iter().filter(|(_, c)| c.peer && !wanted.contains(&c.host)).map(|(id, _)| *id).collect();
        for conn in gone {
            self.close_dialed(conn, out);
        }
    }

    /// Closes dialed connection `conn` from this side: its hub session, or its dial while not
    /// up yet.
    pub(crate) fn close_dialed(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        match self.conns.get(&conn).map(|c| c.hub) {
            Some(Some(hub)) => out.push(Action::Hub { conn: hub, down: osis_host::Down::Close }),
            Some(None) => out.push(Action::Close { conn }),
            None => return,
        }
        self.lost(conn);
    }

    /// The transport of dialed connection `conn` is up as the hub's connection `hub`, whose
    /// session sent its Hello.
    pub(super) fn dialed(&mut self, conn: ConnId, hub: osis_host::ConnId, out: &mut Vec<Action>) {
        // a dial this node gave up meanwhile closes
        let Some(c) = self.conns.get_mut(&conn) else {
            out.push(Action::Hub { conn: hub, down: osis_host::Down::Close });
            return;
        };
        c.up = true;
        c.hub = Some(hub);
        self.hub_conns.insert(hub, conn);
        if c.peer {
            let (k, a) = (c.host, c.address.clone());
            if self.lan_up(k, &a) {
                self.lan_switched(conn, k, out);
            }
        }
    }

    /// Sends request `msg` (under an id this picks, below `NODE_IDS`) on dialed connection
    /// `conn`, its answer awaited as `p`; none before the peer's Hello. Returns the id.
    pub(crate) fn request(&mut self, conn: ConnId, msg: impl FnOnce(Id) -> Message, p: Pending, out: &mut Vec<Action>) -> Option<Id> {
        let now = self.now();
        let c = self.conns.get_mut(&conn)?;
        let hub = c.hub.filter(|_| c.is_ready())?;
        let id = loop {
            c.next_id = c.next_id.wrapping_add(1) & !NODE_IDS;
            if c.next_id != 0 && !c.pending.contains_key(&c.next_id) {
                break c.next_id;
            }
        };
        c.pending.insert(id, p);
        c.heard = now;
        out.push(Action::Hub { conn: hub, down: osis_host::Down::Message(Box::new(msg(id))) });
        Some(id)
    }

    /// A Ping on `conn` (a clock sample; a request out, so its stall clock finds a dead
    /// connection).
    pub(crate) fn ping(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        let now = self.now();
        self.request(conn, |id| Message::Ping { id, wall_ms: now }, Pending::Ping { sent: now }, out);
    }

    /// A Delete of `items` of `l` on `conn`, `MAX_ITEMS` per request, each entry recorded with the
    /// id it went under (`Requests::deleting`). An item that cannot be encoded refuses the delete
    /// of `l` whole (`refused`), as a malformed answer would.
    pub(crate) fn delete(&mut self, conn: ConnId, l: LabelId, items: Vec<osis_proto::msg::DeleteItem>, out: &mut Vec<Action>) -> Result<()> {
        let (items, bad): (Vec<_>, Vec<_>) = items.into_iter().partition(|i| i.to_value().is_ok());
        let now = self.now();
        for chunk in items.chunks(osis_proto::msg::MAX_ITEMS) {
            let ids: Vec<osis_base::BlobId> = chunk.iter().map(|i| i.blob).collect();
            let Some(id) = self.request(conn, |id| Message::Delete { id, label: l, items: chunk.to_vec() }, Pending::Delete(l, ids.clone()), out) else { break };
            if let Some(c) = self.conns.get_mut(&conn) {
                for b in ids {
                    c.req.deleting.insert((l, b), (now, id));
                }
            }
        }
        if !bad.is_empty() {
            self.refused(conn, &Pending::Delete(l, Vec::new()), Code::MALFORMED, out)?;
        }
        Ok(())
    }

    /// The peer's Hello on dialed connection `conn` arrived (`Up::Start`): pings, this node's
    /// proofs signed over the binding, and every label the peer may hold starts opening.
    pub(super) fn dialed_start(&mut self, conn: ConnId, binding: ([u8; 32], [u8; 32], [u8; 32]), relayed: bool, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        c.binding = Some(binding);
        c.next_ping = now.saturating_add(osis_proto::hello::PING_INTERVAL_MS);
        let host = c.host;
        if relayed {
            self.set_relayed(conn);
        }
        let (_, listener, key) = binding;
        for _ in 0..osis_proto::hello::INITIAL_PINGS {
            self.ping(conn, out);
        }
        // to a key this node chose to dial, a co-reader's or a host's (spec/sync.md §10): the
        // shared set follows on either; signed over the listener's challenge and key
        let own = self.dials_own_node(&host);
        let provers = proofs::provers(&mut self.engine, own)?;
        if let Some(c) = self.conns.get_mut(&conn) {
            c.proved = provers.iter().map(|p| p.record.tid()).collect();
        }
        let proofs = provers.iter().map(|p| p.sign(false, &listener, &key)).collect();
        self.request(conn, |id| Message::Prove { id, proofs }, Pending::Prove, out);
        self.add_new_labels(out)
    }

    /// A message on dialed connection `conn`: an answer to one of this node's requests here
    /// (below `NODE_IDS`), or the shared set's and the stream's (`peer_message`). A reply to
    /// nothing never comes up (the session refuses it).
    pub(super) fn dialed_message(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        if m.for_node() || !osis_proto::msg::is_reply_kind(m.kind()) {
            // a Notify: this side made no subscription
            if matches!(m, Message::Notify { .. }) {
                return Ok(());
            }
            return self.peer_message(conn, m, out);
        }
        let Some(p) = self.conns.get_mut(&conn).and_then(|c| c.pending.remove(&m.id())) else { return Ok(()) };
        let now = self.now();
        use Message as M;
        match (p, m) {
            (Pending::Ping { sent }, M::Pong { wall_ms, .. }) => {
                let sample = osis_proto::OffsetSample { sent, peer: wall_ms, received: now };
                let offset = self.conns.get_mut(&conn).and_then(|c| c.clock.pong(sample));
                // a diagnostic only: nothing another node sends moves this node's clock (spec/sync.md §6)
                if let Some(offset_ms) = offset.filter(|o| o.unsigned_abs() > osis_proto::hello::OFFSET_DIAGNOSTIC_MS)
                    && let Some(c) = self.conns.get(&conn)
                {
                    let detail = format!("the clock of {} is {offset_ms:+} ms from this node's", osis_label::address_to_text(&c.address));
                    self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::ClockSkew, tids: Vec::new(), commit: None, peer: None, detail }, self.engine.now());
                    self.engine.core.events.flush();
                }
            }
            (Pending::Prove, M::Proved { proofs, .. }) => {
                // proved over this side's challenge and the key it dialed: a proof of any other
                // connection, or the listener's relayed from one, does not verify
                let Some((dialer, _, key)) = self.conns.get(&conn).and_then(|c| c.binding) else { return Ok(()) };
                let proofs = osis_proto::prove::verified(proofs, true, &dialer, &key);
                let proven = super::proofs::proven_actors(&mut self.engine, &proofs)?;
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.proven = proven;
                }
                self.send_resume(conn, out)?;
            }
            (Pending::Resume, M::Resumed { nonce, tag, .. }) => self.resumed(conn, nonce, tag, out)?,
            (Pending::Register(l), M::Ok { .. }) => self.registered(conn, l, out)?,
            (Pending::Delete(l, blob_ids), M::Status { codes, .. }) if codes.len() == blob_ids.len() => self.delete_status(conn, l, blob_ids, codes)?,
            (p, M::Error { code, .. }) => self.refused(conn, &p, code, out)?,
            (_, _) => self.diag("peer: reply of the wrong kind".into()),
        }
        Ok(())
    }

    /// Labels to open, with their group and host keys: the synced labels and inbox hints.
    pub(super) fn wanted_labels(&mut self) -> Vec<(Tid, LabelId, Vec<HostKey>)> {
        let mut want: Vec<(Tid, LabelId, Vec<HostKey>)> = self.labels().into_iter().map(|(g, l)| (g, l.id, l.hosts.iter().map(|a| a.key).collect())).collect();
        for (l, h) in &self.state.hints {
            if !want.iter().any(|(_, x, _)| x == l) {
                want.push((h.thing, *l, h.hosts.iter().map(|a| a.key).collect()));
            }
        }
        want
    }

    /// Starts every wanted label not yet on a ready connection to one of its hosts.
    pub(super) fn add_new_labels(&mut self, out: &mut Vec<Action>) -> Result<()> {
        // a host's: a peer's sync IDs are its shared set's, read by the stream (`stream`)
        let conns: Vec<(ConnId, HostKey)> = self.conns.iter().filter(|(_, c)| c.is_ready() && !c.peer).map(|(id, c)| (*id, c.host)).collect();
        if conns.is_empty() {
            return Ok(());
        }
        // a label a held `label.0` records is that group's on every connection (spec/sync.md
        // §3): one a hint opened under another thing there (a host a sender names took the
        // claim) leaves it, and starts again below as the group's where the group names that
        // host. Otherwise it stayed open under the hint's thing for the connection's life, and
        // what that host sent was judged under it (`group_of`). Any group recording it will do:
        // two `label.0`s may name one label (an admin may copy another group's), and moving
        // between them would reopen it at every call.
        let mut recorded: BTreeMap<LabelId, BTreeSet<Tid>> = BTreeMap::new();
        for (g, l) in self.labels() {
            recorded.entry(l.id).or_default().insert(g);
        }
        for c in self.conns.values_mut() {
            let stale: Vec<LabelId> = c.labels.iter().filter(|(l, x)| recorded.get(l).is_some_and(|gs| !gs.contains(&x.group))).map(|(l, _)| *l).collect();
            for l in &stale {
                c.labels.remove(l);
            }
            c.req.forget(|l| stale.contains(l));
        }
        self.refusals.retain(|(_, l), _| recorded.contains_key(l));
        let labels = self.wanted_labels();
        for (conn, host) in conns {
            for (g, l, hosts) in &labels {
                // failed under another thing (a hint's sender named this label so): it starts
                // again as what wants it now
                let known = self.conns.get(&conn).and_then(|c| c.labels.get(l)).is_some_and(|x| x.group == *g || !matches!(x.phase, Phase::Failed { .. } | Phase::Refused { .. }));
                if !known && hosts.contains(&host) {
                    self.start_label(conn, *g, *l, out)?;
                }
            }
        }
        Ok(())
    }
}
