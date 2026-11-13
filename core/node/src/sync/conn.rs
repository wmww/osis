//! Connections to hosts and co-readers: dialing, the labels on each, requests in flight, and the
//! session's outputs and events.

use super::*;

/// A Deposit item or delete whose request was answered without settling it (a refusal, an entry
/// the source's stream does not show) goes again at the first pass this long after it was given
/// (ms).
/// Minor consequence: pacing of retries only (an unanswered request never goes again: a slow
/// link only queues the copy behind the first, and a dead one closes at `STALL_TIMEOUT_MS`);
/// 0 retries at every pass, infinity never retries on this connection (the next one does).
const RESEND_MS: u64 = 30_000;

/// A request recorded in `Requests` before the command carrying it is given: never answered
/// until `Requests::given` tags it.
pub(crate) const UNTAGGED: u64 = u64::MAX;

/// Whether a request for `k` on `c` is still unanswered, or was given less than `RESEND_MS`
/// before `now`.
pub(crate) fn in_flight(c: &Conn, m: &BTreeMap<(LabelId, osis_base::BlobId), (u64, u64)>, k: (LabelId, osis_base::BlobId), now: u64) -> bool {
    m.get(&k).is_some_and(|(t, tag)| now < t.saturating_add(RESEND_MS) || !c.session.answered(*tag))
}

/// Open state of a label on a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Waiting for the peer's filter: the credential of the newest recorded head (or of the step
    /// the walk found shown, `LConn::shown`) is tested at each arrival, and a Hit opens it
    /// (issues/net-one-peer.md 3h2, Stale head).
    Testing,
    /// Registering the recorded path at a peer that lacks the label.
    Registering,
    /// The peer's head is past the newest step this node knows: a Behind item asks for the
    /// next step (`SyncEngine::behind`).
    Behind,
    Open,
    /// No key opens it here.
    Failed,
    /// The peer refused registering it for now (not admitted, full, the rate) or does not hold it
    /// and this node cannot register it: tested again from scratch at `retry_at` (wall ms).
    Refused { retry_at: u64 },
}

/// One label on one connection.
#[derive(Clone)]
pub(crate) struct LConn {
    pub group: Tid,
    /// The label's index (recorded, or the hint's).
    pub index: u64,
    pub phase: Phase,
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
    /// This node's log end when the peer's head here last moved: entries logged before then the
    /// peer may have read and refused under the old head's keys (`relog_for_head`).
    pub head_moved_at: Option<u64>,
    /// How far the peer had reported reading this node's log when its head here last moved:
    /// what it read up to there it read under the old head (`relog_for_head`).
    pub head_moved_read: Option<u64>,
    /// The peer said it refused an entry of the label it pulled for room and has none again
    /// yet (spec/sync.md §10, Full): what it lacks it lacks, and nothing waits for it to take
    /// it.
    pub full: bool,
    /// Bodies this node places, stamped for the peer's head, that the last pass found the peer
    /// lacking (it pulls them): while any is and the peer is not full, the label is not caught
    /// up there (`label_status`).
    pub lacking: usize,
    /// A child step refused for now: no pass registers one before this (wall ms).
    pub step_retry: u64,
    /// Child steps refused in a row (the back-off doubles per refusal; an open or a registered
    /// step resets it).
    pub step_refusals: u32,
    /// Failed: when it failed; Testing: when it was last walked (each again `resync_ms` on).
    pub last_sync: u64,
    /// The recorded path's steps whose registration is not answered yet.
    pub path: Vec<Step>,
    /// A verified step of the peer's path past `label.0`'s (a static entry's grant's head, or
    /// where a Behind walk got to): the newest step known there (`SyncEngine::newest_known`).
    pub walk: Option<Step>,
    /// The peer answered a Behind item by this node's static entry with a refusal: its head
    /// does not list it (`SyncEngine::static_entry_refused`).
    pub static_refused: bool,
    /// Steps a Behind item on was refused in this walk (off the peer's path, or its head): not
    /// asked again until the walk ends (`SyncEngine::behind_from`).
    pub behind_refused: Vec<osis_label::StepId>,
    /// The head the peer's stream named past the open head, which Behind items walk to.
    pub walk_to: Option<osis_label::StepId>,
    /// A recorded step and the key of its credential the peer's filter showed when the newest
    /// recorded head's was not: it is Hit, and L opens at that step (`walked`).
    pub shown: Option<(Step, osis_crypto::SigningSecret)>,
    /// A listing from the start under way here: what was present here before it, and whether
    /// the peer marked it trimmed (`known_join`, `stream_read`).
    pub relisted: Option<(BTreeSet<osis_base::BlobId>, bool)>,
    /// The key whose open signature this node's Hit opened the label by here (a sync key, or a
    /// claim's): what it tests there while it holds no secret of the head yet (`peer_creds`).
    pub hit_key: Option<osis_crypto::SigningSecret>,
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
        self.phase == Phase::Open && self.fill.as_ref().is_some_and(|f| !f.first_done)
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
    pub session: ClientSession,
    /// What this connection's peer proved (spec/sync.md §10), read by `SyncEngine::proven`.
    pub proven: super::proofs::Proven,
    /// The actors this node proved on it (its Prove), read by `SyncEngine::proved`.
    pub proved: BTreeSet<Tid>,
    pub up: bool,
    pub labels: BTreeMap<LabelId, LConn>,
    pub timer: Option<u64>,
    pub req: Requests,
}

/// Requests on a connection not answered yet, and what its host would not deliver: they go
/// with the connection (asked again on the next one).
#[derive(Clone, Default)]
pub(crate) struct Requests {
    /// Bodies sent to this connection's source as Deposit items (`deposit_items`), with when
    /// (wall ms): passes skip them within `RESEND_MS` (`in_flight`).
    pub sent: BTreeMap<(LabelId, osis_base::BlobId), (u64, u64)>,
    /// Deletes sent, likewise.
    pub deleting: BTreeMap<(LabelId, osis_base::BlobId), (u64, u64)>,
    /// Blobs the host did not deliver when fetched (since it last announced them).
    pub missing: BTreeSet<osis_base::BlobId>,
    /// Labels walked because they were not members after a filter arrival, with that arrival's
    /// number: once per arrival (`shared_unopened`).
    pub walked: BTreeMap<LabelId, u64>,
    /// Sync-key credentials whose Hit the peer refused since its last filter arrival: not shown
    /// to the walk (a filter keeps a moved head's entries until a whole one is sent).
    pub refused: BTreeSet<(LabelId, [u8; 32])>,
    /// Labels whose recorded path the peer took to its newest step since they were last open
    /// here, with the filter arrival and time then: a walk at a later arrival, or `resync_ms`
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

    /// The commands carrying the `UNTAGGED` requests were given, the last tagged `tag`.
    pub fn given(&mut self, tag: u64) {
        for v in self.sent.values_mut().chain(self.deleting.values_mut()) {
            if v.1 == UNTAGGED {
                v.1 = tag;
            }
        }
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
        self.stream_asks(b).map(|at| at.saturating_add(osis_proto::client::STALL_TIMEOUT_MS)).filter(|t| *t > now).max()
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
            let mut challenge = [0u8; 32];
            self.rng.fill_bytes(&mut challenge);
            // the key the transport authenticates (a LAN address presents its own)
            let session = ClientSession::new(ClientConfig { peer_static_key: addr.key, challenge });
            self.conns.insert(conn, Conn { host: key, address: addr.clone(), peer, session, proven: super::proofs::Proven::default(), proved: BTreeSet::new(), up: false, labels: BTreeMap::new(), timer: None, req: Requests::default() });
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
            out.push(Action::Close { conn });
            self.lost(conn);
        }
    }

    /// Runs the session's outputs: frames out, timers, events in.
    pub(crate) fn outputs(&mut self, conn: ConnId, outputs: Vec<ClientOutput>, out: &mut Vec<Action>) -> Result<()> {
        for o in outputs {
            match o {
                ClientOutput::Send(bytes) => out.push(Action::Send { conn, bytes }),
                ClientOutput::Close => {
                    out.push(Action::Close { conn });
                    self.lost(conn);
                }
                ClientOutput::SetTimer(t) => {
                    if let Some(c) = self.conns.get_mut(&conn) {
                        c.timer = Some(t);
                    }
                }
                ClientOutput::Event(e) => self.session_event(conn, e, out)?,
            }
        }
        Ok(())
    }

    /// Sends a command on a connection.
    pub(crate) fn command(&mut self, conn: ConnId, cmd: Command, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        let Some(c) = self.conns.get_mut(&conn) else { return Ok(()) };
        let o = c.session.handle(now, ClientInput::Command(cmd));
        self.outputs(conn, o, out)
    }

    /// Tags the requests recorded on `conn` before their commands were given (`Requests::given`).
    pub(crate) fn given(&mut self, conn: ConnId) {
        if let Some(c) = self.conns.get_mut(&conn) {
            let tag = c.session.commands();
            c.req.given(tag);
        }
    }

    pub(super) fn session_event(&mut self, conn: ConnId, e: ClientEvent, out: &mut Vec<Action>) -> Result<()> {
        use ClientEvent as E;
        match e {
            // the node's own dials send no client-port requests
            E::Reply { .. } | E::Notify { .. } => {}
            E::Proved { proofs } => {
                let proven = super::proofs::proven_actors(&mut self.engine, &proofs)?;
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.proven = proven;
                }
                self.send_resume(conn, out)?;
            }
            E::Resumed { nonce, tag } => self.resumed(conn, nonce, tag, out)?,
            E::Peer(m) => self.peer_message(conn, *m, out)?,
            // Hellos done: every label this host holds starts opening
            E::Ready { .. } => self.add_new_labels(out)?,
            // a diagnostic only: nothing another node sends moves this node's clock (spec/sync.md §6)
            E::ClockOffset { offset_ms, diagnostic } => {
                if diagnostic && let Some(c) = self.conns.get(&conn) {
                    let detail = format!("the clock of {} is {offset_ms:+} ms from this node's", osis_label::address_to_text(&c.address));
                    let now = self.engine.now();
                    self.engine.core.events.diagnostic(Diagnostic { kind: DiagnosticKind::ClockSkew, tids: Vec::new(), commit: None, peer: None, detail }, now);
                    self.engine.core.events.flush();
                }
            }
            E::Registered { label } => self.registered(conn, label, out)?,
            E::DeleteStatus { label, blob_ids, codes } => self.delete_status(conn, label, blob_ids, codes)?,
            // the listener keeps no record of this side (it refused the proofs or the Resume): the
            // set still runs
            E::Refused { kind: osis_proto::client::Request::Prove | osis_proto::client::Request::Resume, .. } => self.no_record(conn, out)?,
            E::Refused { label, kind, code, .. } => self.refused(conn, label, kind, code, out)?,
            E::PeerError(e) => self.diag(format!("host: {e}")),
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
        let conns: Vec<(ConnId, HostKey)> = self.conns.iter().filter(|(_, c)| c.session.is_ready() && !c.peer).map(|(id, c)| (*id, c.host)).collect();
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
                // failed under another thing or a hint's other index (a hint's sender named this
                // label so): it starts again as what wants it now
                let index = self.state.hints.get(l).filter(|h| h.via.is_none() && h.thing == *g).map(|h| h.index);
                let known = self.conns.get(&conn).and_then(|c| c.labels.get(l)).is_some_and(|x| (x.group == *g && index.is_none_or(|i| i == x.index)) || !matches!(x.phase, Phase::Failed | Phase::Refused { .. }));
                if !known && hosts.contains(&host) {
                    self.start_label(conn, *g, *l, out)?;
                }
            }
        }
        Ok(())
    }
}
