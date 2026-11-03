//! Connections to hosts and co-readers: dialing, the labels on each, requests in flight, and the
//! session's outputs and events.

use super::*;

/// An upload, deposit or delete whose request was answered without settling it (a refusal, an
/// entry the reply did not mark) goes again at the first pass this long after it was given (ms).
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

/// Whether `OSIS_TRACE_UPLOADS` asks for the upload trace (`SyncEngine::trace`).
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("OSIS_TRACE_UPLOADS").is_some())
}

/// Open state of a label on a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Trying open keys in order.
    Opening,
    /// Registering the recorded path at a host that lacks the label.
    Registering,
    /// Waiting for the host's path to verify its head.
    Verifying,
    Open,
    /// No key opens it here.
    Failed,
    /// The host refused registering it for now (not admitted, full, the rate) or does not hold it
    /// and this node cannot register it: opened again from scratch at `retry_at` (raw ms).
    Refused { retry_at: u64 },
}

/// One label on one connection.
pub(crate) struct LConn {
    pub group: Tid,
    /// The label's index (recorded, or the hint's).
    pub index: u64,
    pub phase: Phase,
    pub tries: Vec<open::Try>,
    pub tried_claim: bool,
    pub head: Option<Step>,
    pub keys: HeadKeys,
    /// A Sync exchange is running.
    pub syncing: bool,
    /// The log was read to its end at least once on this connection.
    pub synced: bool,
    /// A pass is wanted once the running exchange ends.
    pub dirty: bool,
    /// The label's first sync at this host is under way (`fill`).
    pub fill: Option<fill::Fill>,
    /// A child step sent for registration.
    pub registering: Option<(Step, osis_label::ClaimSet)>,
    /// A child step refused for now: no pass registers one before this (raw ms).
    pub step_retry: u64,
    /// Child steps refused in a row (the back-off doubles per refusal; an open or a registered
    /// step resets it).
    pub step_refusals: u32,
    /// What the next pass judges (`work`).
    pub work: work::Work,
    pub budget: Option<u64>,
    pub last_sync: u64,
    pub path: Vec<Step>,
    /// A hinted open walked to an unverified step: the host's path is checked after the open.
    pub walk: Option<Step>,
    /// A static-entry open's entry box, opened once the host's path verified the head.
    pub entry_box: Option<osis_schema::core_types::SecretBox>,
    /// Write keys of a host path verified here (a label not recorded in `label.0`): stamps
    /// under them vouch for an entry.
    pub writers: Vec<osis_crypto::VerifyingKey>,
    /// Read for receipts only (`receipts`): no pass, nothing placed, nothing kept.
    pub receipts: bool,
}

impl LConn {
    /// The log was read to its end and nothing runs.
    pub(super) fn ready(&self) -> bool {
        self.synced && !self.syncing && self.registering.is_none()
    }

    /// A fill here has not all that judging needs.
    pub(super) fn first_waits(&self) -> bool {
        self.phase == Phase::Open && self.fill.as_ref().is_some_and(|f| !f.first_done)
    }

    /// A pass is wanted; a fill's at its next due (`sync_label`), its end or this node's own next
    /// write, not per batch applied.
    pub(super) fn want_pass(&mut self) {
        self.dirty |= self.fill.is_none();
    }

    /// Ready, with no pass wanted and no fill under way.
    pub(super) fn idle(&self) -> bool {
        self.ready() && !self.dirty && self.fill.is_none()
    }
}

pub(crate) struct Conn {
    /// A host's address key, or a co-reader node's dialable key (its LAN address may present
    /// another transport key).
    pub host: HostKey,
    pub address: Address,
    /// A co-reader node, not a host.
    pub peer: bool,
    pub session: ClientSession,
    pub up: bool,
    pub labels: BTreeMap<LabelId, LConn>,
    pub timer: Option<u64>,
    pub offset: Option<i64>,
    pub req: Requests,
}

/// Requests on a connection not answered yet, and what its host would not deliver: they go
/// with the connection (asked again on the next one).
#[derive(Default)]
pub(crate) struct Requests {
    /// Entries uploaded or deposited, with when (raw ms) and the tag of the command carrying them
    /// (`ClientSession::commands`): passes skip them while unanswered or within `RESEND_MS`
    /// (`in_flight`).
    pub sent: BTreeMap<(LabelId, osis_base::BlobId), (u64, u64)>,
    /// Deletes sent, likewise.
    pub deleting: BTreeMap<(LabelId, osis_base::BlobId), (u64, u64)>,
    /// Timed deletes sent: recorded once the host says OK.
    pub timed_sent: BTreeSet<(LabelId, osis_base::BlobId)>,
    /// Uploads sent replacing entries (spec/sync.md §5): those are gone once one is answered OK.
    /// A plain upload of the same blob waits meanwhile (two statuses could not be told apart).
    pub replacing: BTreeMap<(LabelId, osis_base::BlobId), Vec<osis_base::BlobId>>,
    /// Blobs asked for and not received yet.
    pub fetching: BTreeSet<osis_base::BlobId>,
    /// Blobs the host did not deliver when fetched (since it last announced them).
    pub missing: BTreeSet<osis_base::BlobId>,
    /// Reopens in a row per label.
    pub reopens: BTreeMap<LabelId, u32>,
    /// Registrations refused for now in a row per label (the back-off doubles per refusal),
    /// with the last refusal's code (status shows a label not admitted, code 14).
    pub refusals: BTreeMap<LabelId, (u32, Code)>,
    /// Labels whose cursor the host's log was trimmed past (code 15), until their
    /// reconciliation answers (`reconciled`: what it lacks of the present entries was deleted).
    pub trimmed: BTreeSet<LabelId>,
}

impl Requests {
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
    /// Whether blob `b` was asked for on some connection and not received yet.
    pub(crate) fn fetching(&self, b: &osis_base::BlobId) -> bool {
        self.conns.values().any(|c| c.req.fetching.contains(b))
    }

    /// Blob `b` arrived, or a host said it does not hold it: no longer in flight.
    pub(crate) fn fetched(&mut self, b: &osis_base::BlobId) {
        for c in self.conns.values_mut() {
            c.req.fetching.remove(b);
        }
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
            self.eph_lost(conn, c.host, &c.req.fetching);
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
            let pause = if c.peer { self.cfg.peer_retry_ms } else { self.cfg.retry_ms };
            self.retry.insert(c.host, (c.address, self.raw_now().saturating_add(pause)));
        }
    }

    /// The hosts and co-reader nodes to keep connections to (true: a node).
    pub(super) fn wanted_hosts(&mut self) -> BTreeMap<HostKey, (Address, bool)> {
        let mut m: BTreeMap<HostKey, (Address, bool)> = self.cfg.hosts.iter().map(|a| (a.key, (a.clone(), false))).collect();
        // an admin's word: hosts only (`peer://` nodes come from `reach.0` or a link)
        fn add<'a>(m: &mut BTreeMap<HostKey, (Address, bool)>, hosts: impl IntoIterator<Item = &'a Address>) {
            for a in hosts.into_iter().filter(|a| !peers::is_peer(a)) {
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
        add(&mut m, self.state.outbox.values().map(|o| &o.host));
        let reads: Vec<Tid> = self.receipts.values().map(|r| r.group).collect();
        for g in reads {
            for l in self.engine.labels_of(&g) {
                add(&mut m, &l.hosts);
            }
        }
        if self.cfg.peers {
            for (k, (a, _)) in self.peer_addresses() {
                m.entry(k).or_insert((a, true));
            }
            // a link's sharer node (first contact, spec/permissions.md §9) is dialed as a co-reader
            for (k, (a, _)) in self.link_routes() {
                m.entry(k).or_insert((a, true));
            }
        }
        m
    }

    /// Dials wanted hosts without a connection (after their retry time); adds labels to
    /// open connections.
    pub(super) fn connect(&mut self, out: &mut Vec<Action>) {
        let now = self.raw_now();
        let wanted = self.wanted_hosts();
        // a host no longer wanted keeps no retry time (it would hold the wake in the past)
        self.retry.retain(|k, _| wanted.contains_key(k));
        for (key, (addr, peer)) in wanted {
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
            self.conns.insert(conn, Conn { host: key, address: addr.clone(), peer, session, up: false, labels: BTreeMap::new(), timer: None, offset: None, req: Requests::default() });
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
        let now = self.raw_now();
        if tracing() {
            self.trace(conn, &cmd);
        }
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

    /// One stderr line per entry sent (cost attribution, `OSIS_TRACE_UPLOADS`): node, group,
    /// how, bytes, what the entry is (commit, kind, certificate copy, aspects).
    pub(super) fn trace(&self, conn: ConnId, cmd: &Command) {
        let short = |b: &[u8]| b.iter().take(3).map(|x| format!("{x:02x}")).collect::<String>();
        let t4 = |t: &Tid| t.to_string().chars().take(4).collect::<String>();
        let sent: Vec<(LabelId, osis_base::BlobId, usize, &str)> = match cmd {
            Command::Upload { label, entries } | Command::Sync { label, entries, .. } => entries.iter().map(|e| (*label, osis_label::blob_id(&e.blob), e.blob.len(), "up")).collect(),
            Command::Deposit { label, blob, .. } => vec![(*label, osis_label::blob_id(blob), blob.len(), "dep")],
            _ => return,
        };
        let group = |l: &LabelId| self.conns.get(&conn).and_then(|c| c.labels.get(l)).map(|x| t4(&x.group)).unwrap_or_default();
        for (l, id, n, how) in sent {
            let what = match self.state.entries.get(&(l, id)) {
                Some(e) => match &e.kind {
                    state::Kind::Commit { commit, parts, .. } => {
                        let h = self.engine.header(commit);
                        let aspects: Vec<String> = parts.iter().filter_map(|(ai, _)| h.as_ref().and_then(|h| h.aspects.get(*ai))).map(|a| format!("{}{}", t4(&a.tid), a.ak.as_str())).collect();
                        let kind = h.as_ref().map(|h| format!("{:?}", h.kind)).unwrap_or_default();
                        let author = h.as_ref().map(|h| t4(&h.author)).unwrap_or_default();
                        format!("commit {} {kind} by {author}{} [{}]", short(&commit.0), if e.cert { " cert" } else { "" }, aspects.join(" "))
                    }
                    k => format!("{k:?}"),
                },
                None => "unknown".into(),
            };
            eprintln!("TRACE node {} group {} {how} {n} B blob {}: {what}", t4(&self.engine.tid()), group(&l), short(&id.0));
        }
    }

    pub(super) fn session_event(&mut self, conn: ConnId, e: ClientEvent, out: &mut Vec<Action>) -> Result<()> {
        use ClientEvent as E;
        // a receipts-only label's data never reaches the entry records (`receipts`)
        if self.receipts_event(conn, &e, out)? {
            return Ok(());
        }
        if let E::Refused { label: Some(l), fetch, .. } = &e
            && self.receipts_lc(conn, l)
        {
            self.receipts_refused(conn, l, fetch);
        }
        match e {
            // the node's own dials send no client-port requests
            E::Reply { .. } | E::Notify { .. } => {}
            // Hellos done: every label this host holds starts opening
            E::Ready { .. } => self.add_new_labels(out)?,
            E::ClockOffset { offset_ms, .. } => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.offset = Some(offset_ms);
                }
                let mut v: Vec<i64> = self.conns.values().filter_map(|c| c.offset).collect();
                v.sort_unstable();
                if let Some(m) = v.get(v.len() / 2) {
                    self.engine.set_clock_offset(*m);
                }
            }
            E::Opened { label, head, entry_box } => self.opened(conn, label, head, entry_box, out)?,
            E::Step { label, step } => self.stale_step(conn, label, step, out)?,
            E::Registered { label } => self.registered(conn, label, out)?,
            E::PathSteps { label, steps, more } => self.path_steps(conn, label, steps, more, out)?,
            E::EntryStatus { label, blob_ids, codes } => self.entry_status(conn, label, blob_ids, codes, out)?,
            E::DeleteStatus { label, blob_ids, codes } => self.delete_status(conn, label, blob_ids, codes)?,
            E::Budget { label, blob_id, code, budget } => self.budget(conn, label, blob_id, code, budget.map(|b| b.0))?,
            // a Push names its label: one not started on this connection is junk (spec/wire.md
            // §11.2; peer input never grows storage unasked)
            E::Events { label, .. } if !self.conns.get(&conn).is_some_and(|c| c.labels.contains_key(&label)) => self.diag("host pushed a label not opened".into()),
            // a session not open yet: a push left from an earlier session (a forgotten label's,
            // a reopen's) would move the cursor past what its replay has not listed
            E::Events { label, .. } if !self.lc(conn, &label).is_some_and(|x| x.phase == Phase::Open) => {}
            E::Events { label, events, cursor } => {
                if !events.is_empty() {
                    self.received_from(conn, label);
                }
                self.log_events(Some(conn), label, events, cursor, out)?
            }
            E::Want { label, ids } => {
                let rest = self.eph_want(conn, label, ids, out)?;
                self.want(conn, label, rest, out)?
            }
            E::Synced { label } => {
                self.synced(conn, label, out)?;
                self.eph_synced(conn, label, out)?
            }
            E::NeedReconcile { label, trimmed } => {
                let s = self.conns.get_mut(&conn).map(|c| {
                    if trimmed {
                        c.req.trimmed.insert(label);
                    }
                    c.host
                });
                if let Some(s) = s {
                    self.state.set_cursor(s, label, None);
                    // a lane reconciliation running lists the present entries too and syncs from
                    // no cursor after it; this one's reply would be taken for it (`reconciled`)
                    if !self.eph.reconciling.contains_key(&(conn, label)) {
                        let ids = self.state.present_at(&s, &label);
                        self.command(conn, Command::Reconcile { label, ids }, out)?;
                    }
                }
            }
            E::Reconciled { label, need, have } => self.reconciled(conn, label, need, have, out)?,
            E::Fetched { label, items } => {
                let ids: Vec<osis_base::BlobId> = items.iter().map(|f| f.blob_id).collect();
                self.eph_fetch_done(conn, label, &ids, false);
                // asked for and not there: not asked again on this connection
                let mut gone = false;
                for f in items.iter().filter(|f| f.entry.is_none()) {
                    self.fetched(&f.blob_id);
                    gone |= self.conns.get_mut(&conn).is_some_and(|c| c.req.missing.insert(f.blob_id));
                }
                if gone && let Some(lc) = self.lc_mut(conn, &label) {
                    lc.dirty = true;
                }
                let evs: Vec<osis_proto::Event> = items.into_iter().filter_map(|f| f.entry.map(|(blob, wrap, stamp)| osis_proto::Event::Added { blob_id: f.blob_id, blob: Some(blob), wrap, stamp })).collect();
                if !evs.is_empty() {
                    self.received_from(conn, label);
                }
                self.log_events(Some(conn), label, evs, None, out)?;
            }
            E::Subscribed { .. } => {}
            E::Refused { label, kind, code, fetch } => {
                // no longer in flight on this connection: a pass asks again (after a reopen);
                // a reconciliation's ephemeral ones only a reconciliation names again
                if let Some(c) = self.conns.get_mut(&conn) {
                    for b in &fetch {
                        c.req.fetching.remove(b);
                    }
                }
                if let Some(l) = label {
                    self.eph_fetch_done(conn, l, &fetch, true);
                }
                self.refused(conn, label, kind, code, out)?
            }
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
        if self.cfg.peers && self.conns.values().any(|c| c.peer) {
            let routes: Vec<_> = self.peer_addresses().into_iter().chain(self.link_routes()).collect();
            for (k, (_, labels)) in routes {
                for (_, l, keys) in want.iter_mut() {
                    if labels.contains(l) {
                        keys.push(k);
                    }
                }
            }
        }
        // receipts-only reads: at their hosts only
        for r in self.receipts_wanted() {
            if !want.iter().any(|(_, x, _)| *x == r.1) {
                want.push(r);
            }
        }
        want
    }

    /// Starts every wanted label not yet on a ready connection to one of its hosts.
    pub(super) fn add_new_labels(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let conns: Vec<(ConnId, HostKey)> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.host)).collect();
        if conns.is_empty() {
            return Ok(());
        }
        let labels = self.wanted_labels();
        for (conn, host) in conns {
            for (g, l, hosts) in &labels {
                // failed under another thing (a hint's sender named this label under it): no Open
                // is in flight, so it starts again under the thing that wants it now
                let known = self.conns.get(&conn).and_then(|c| c.labels.get(l)).is_some_and(|x| x.group == *g || !matches!(x.phase, Phase::Failed | Phase::Refused { .. }));
                if !known && hosts.contains(&host) {
                    self.start_label(conn, *g, *l, out)?;
                }
            }
        }
        Ok(())
    }
}
