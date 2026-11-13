//! Connections at the hub (spec/sync.md §5, §10): every connection, dialed or one a peer opens
//! on one of this node's listeners, is a session of the node's hub (`osis_host::Hub`), which
//! answers the store's kinds; node sync is its upper layer (`hub_up`) and keeps one record of
//! it (`Conn`): proofs, records, the shared set, the stream, push room and the client port run
//! on it alike, its messages going down as `Action::Hub`. It serves any number of connections
//! (spec/sync.md §10 Served connections). What a peer's stream or Deposit items bring is charged to
//! its source (`Proven::source`) when known here, else the label (dialer keys are fresh per
//! connection), and to a node-wide total (`SyncConfig` `peer_bytes`, `peer_total_bytes`) while
//! it gives nothing held and is at no host; the source is kept with the entry (`Entry::source`).

use super::state::Entry;
use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::Tid;
use osis_crypto::Secret32;
use osis_host::Down;
use osis_schema::core_types as ct;

/// How often carriers and certificate placements nothing needs are forgotten (they wait
/// `TOMBSTONE_LIFETIME` anyway): at 0 every tick scans every entry, at infinity they stay.
pub(crate) const RECORD_SWEEP_MS: u64 = 3_600_000;
use osis_base::{BlobId, LabelId};
use osis_label::{ClaimSet, Step, StepId};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

/// A served label: its group, its path to the head and the claim sets held (the head's entry
/// boxes answer a static entry's Hit, `grant`).
pub struct ServedLabel {
    path: Vec<Step>,
    claims: BTreeMap<StepId, Arc<ClaimSet>>,
}

impl ServedLabel {
    /// The served head.
    pub(crate) fn head(&self) -> Option<&Step> {
        self.path.last()
    }

    /// What a holder of static entry `entry` needs to read the label (spec/sync.md §10, Shared
    /// set): the head's entry box for it and the path to the head.
    pub(crate) fn grant(&self, entry: &[u8; 32]) -> Option<osis_proto::msg::Grant> {
        let head = self.path.last()?;
        let entry_box = self.claims.get(&head.id())?.entries.get(entry)?.clone();
        Some(osis_proto::msg::Grant { entry_box: Some(entry_box), steps: self.path.clone() })
    }

    /// The path to the deepest step of `steps` (the lowest ID among equals).
    pub(crate) fn new(steps: &super::open::Steps) -> Option<ServedLabel> {
        let path: Vec<Step> = super::open::deepest_path(steps)?.into_iter().map(|(s, _)| s.clone()).collect();
        let claims = steps.iter().filter_map(|(id, (_, c))| c.clone().map(|c| (*id, Arc::new(c)))).collect();
        Some(ServedLabel { path, claims })
    }
}

/// Who pushes on a connection: the client port's Notifies or the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pusher {
    Port,
    Stream,
}

/// A connection's push room (`Down::WantRoom`, `Up::Room`), shared by its pushers one
/// grant at a time, in the order they asked: the holder of a grant gives it back when its push
/// went (the stream's page, the port's Notifies) or it had none (an empty `Down::Notify`: the
/// session reserves a grant against its output bound until then), and the next asks again.
#[derive(Clone, Default)]
pub(crate) struct Room {
    waiting: VecDeque<Pusher>,
    /// A `WantRoom` went down and no `Room` came back yet.
    asked: bool,
    held: Option<(Pusher, usize)>,
}

/// How far a dialer's proof exchange went (`Conn::asked`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Asked {
    Nothing,
    Prove,
    Resume,
}

/// A thin client's: the hash of the secret it authenticated with and its entry's end (wall ms).
#[derive(Clone, Copy)]
pub(crate) struct ClientBinding {
    hash: [u8; 32],
    until: Option<u64>,
}

impl ClientBinding {
    /// Entry `e` still stands for this session at `now`: the same secret, not past its `until`.
    fn holds(&self, e: &ct::Client, now: u64) -> bool {
        Secret32::from_bytes(e.secret_hash) == Secret32::from_bytes(self.hash) && e.until.is_none_or(|u| u.0 > now)
    }
}

/// What peers brought here that gives nothing held and is at no host (notes/peers.md, Budget):
/// each entry's source (`Entry::source`) and size, with running sums per charge key
/// (`charge_key`) and in all (stale charges pruned at ticks and when a budget is reached).
/// Rebuilt at open from the entries (`charge_held`).
#[derive(Clone, Default)]
pub(crate) struct Charges {
    by_entry: BTreeMap<(LabelId, BlobId), (Option<Tid>, u64)>,
    per: BTreeMap<[u8; 32], u64>,
    total: u64,
    /// When charges were last pruned (wall ms), and whether a budget was reached since.
    pruned: u64,
    full: bool,
    /// A reached budget was reported (`InputCapped`), and nothing was pruned since.
    reported: bool,
}

impl Charges {
    fn charge(&mut self, l: LabelId, b: BlobId, source: Option<Tid>, n: u64) {
        if let Some((p, old)) = self.by_entry.insert((l, b), (source, n)) {
            self.uncharge(charge_key(p, &l), old);
        }
        *self.per.entry(charge_key(source, &l)).or_default() += n;
        self.total = self.total.saturating_add(n);
    }

    fn uncharge(&mut self, k: [u8; 32], n: u64) {
        self.total = self.total.saturating_sub(n);
        if let Some(x) = self.per.get_mut(&k) {
            *x = x.saturating_sub(n);
            if *x == 0 {
                self.per.remove(&k);
            }
        }
    }

    /// Whether `n` more bytes from `source` under `l` fit both budgets.
    fn fits(&self, cfg: &super::SyncConfig, source: Option<Tid>, l: &LabelId, n: u64) -> bool {
        let used = self.per.get(&charge_key(source, l)).copied().unwrap_or(0);
        n <= cfg.peer_bytes.saturating_sub(used) && n <= cfg.peer_total_bytes.saturating_sub(self.total)
    }
}

/// Whom bytes a peer session put here are charged to: its source (`Proven::source`: its node, for
/// a node of this node's account, else its first account known here), else the label they went
/// under (a dialer key is fresh per connection, so charging it would bound nothing: a link
/// holder's sessions share its K label's budget).
fn charge_key(source: Option<Tid>, label: &LabelId) -> [u8; 32] {
    match source {
        Some(t) => {
            let mut k = [0u8; 32];
            if let Some(d) = k.get_mut(..15) {
                d.copy_from_slice(t.as_bytes());
            }
            k
        }
        None => {
            let mut k = [0xff; 32];
            if let Some(d) = k.get_mut(16..) {
                d.copy_from_slice(&label.0);
            }
            k
        }
    }
}

impl SyncEngine {
    /// What the node's hub handed up for its connection `id` (`osis_host::Up`), dialed or served:
    /// a served one's start makes its record, its start starts it (`conn_start`), its node-kind
    /// messages are judged here, its client-port requests go to the holder of the engine
    /// (`admit`), its push room to the pusher whose turn it is, its end ends it.
    pub(super) fn hub_up(&mut self, id: osis_host::ConnId, up: osis_host::Up, out: &mut Vec<Action>) -> Result<()> {
        use osis_host::Up;
        // a connection a peer dialed: its record from its start
        if matches!(up, Up::Start(_)) && !self.hub_conns.contains_key(&id) {
            let conn = self.next_conn;
            self.next_conn += 1;
            self.conns.insert(conn, super::Conn::new(None, Some(id), super::Tier::Keyed));
            self.hub_conns.insert(id, conn);
        }
        let Some(conn) = self.hub_conns.get(&id).copied() else { return Ok(()) };
        let now = self.now();
        if let Some(c) = self.conns.get_mut(&conn) {
            c.heard = now;
        }
        match up {
            Up::Start(b) => self.conn_start(conn, b, out)?,
            Up::Message(m) => {
                self.state.now = self.now();
                if let Some(bound) = self.conn_message(conn, *m, out)? {
                    self.bind_record(conn, bound, out)?;
                }
            }
            // nothing of an unauthenticated keyed session goes on, and no secret ever does
            Up::Request(msg) => {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.ported = true;
                }
                match self.admit(conn, *msg) {
                    Ok((tier, msg)) => out.push(Action::Request { conn, tier, msg: Box::new(msg) }),
                    Err((id, code)) => self.hub_down(conn, Down::Reply { id, reply: Err(code) }, out),
                }
            }
            Up::Room { budget } => self.room_granted(conn, budget, out),
            Up::End => self.lost(conn, out),
        }
        Ok(())
    }

    /// The session of `conn` granted push room: to the pusher whose turn it is.
    fn room_granted(&mut self, conn: ConnId, budget: usize, out: &mut Vec<Action>) {
        let Some(r) = self.conns.get_mut(&conn).map(|c| &mut c.room) else { return };
        r.asked = false;
        if let Some(p) = r.waiting.pop_front() {
            r.held = Some((p, budget));
            if p == Pusher::Port {
                out.push(Action::Room { conn, budget });
            }
        }
    }

    /// A message, answer or close for connection `conn`, dialed or served, to its hub session.
    pub(crate) fn hub_down(&mut self, conn: ConnId, down: Down, out: &mut Vec<Action>) {
        let now = self.now();
        let Some(c) = self.conns.get_mut(&conn) else { return };
        c.heard = now;
        if let Some(hub) = c.hub {
            out.push(Action::Hub { conn: hub, down });
        }
    }

    /// Pusher `p` of connection `conn` waits for room (behind those that asked first).
    fn want_room(&mut self, conn: ConnId, p: Pusher, out: &mut Vec<Action>) {
        let Some(r) = self.conns.get_mut(&conn).map(|c| &mut c.room) else { return };
        if r.held.is_some_and(|(h, _)| h == p) || r.waiting.contains(&p) {
            return;
        }
        r.waiting.push_back(p);
        self.ask_room(conn, out);
    }

    /// Asks the session for room when someone waits and no grant is out or asked.
    fn ask_room(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        let Some(r) = self.conns.get_mut(&conn).map(|c| &mut c.room) else { return };
        if r.held.is_none() && !r.asked && !r.waiting.is_empty() {
            r.asked = true;
            self.hub_down(conn, Down::WantRoom, out);
        }
    }

    /// Pusher `p` is done with the room it held: the next in line asks.
    fn release_room(&mut self, conn: ConnId, p: Pusher, out: &mut Vec<Action>) {
        let Some(r) = self.conns.get_mut(&conn).map(|c| &mut c.room) else { return };
        if r.held.is_some_and(|(h, _)| h == p) {
            r.held = None;
            self.ask_room(conn, out);
        }
    }

    /// The client port's Notifies after an `Action::Room` (none: it had nothing to send): sent
    /// down, the room given back (an empty `Notify` gives the session's reservation back too).
    pub(super) fn port_notify(&mut self, conn: ConnId, notes: Vec<(osis_proto::msg::Id, osis_proto::Payload)>, out: &mut Vec<Action>) {
        self.hub_down(conn, Down::Notify(notes), out);
        self.release_room(conn, Pusher::Port, out);
    }

    /// The client port has Notifies for `conn`: `Action::Room` in its turn.
    pub(super) fn port_wants_room(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        self.want_room(conn, Pusher::Port, out);
    }

    /// Bytes a stream push on `conn` may take now: only within the room its session granted the
    /// stream, dialed or served; none: it waits (room asked in its turn).
    pub(super) fn push_room(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Option<usize> {
        if let Some((Pusher::Stream, b)) = self.conns.get(&conn)?.room.held {
            return Some(b);
        }
        self.want_room(conn, Pusher::Stream, out);
        None
    }

    /// The stream's push went on `conn`, or it had none to make: the room goes to the next.
    pub(super) fn room_used(&mut self, conn: ConnId, out: &mut Vec<Action>) {
        self.release_room(conn, Pusher::Stream, out);
    }

    /// Connections whose stream holds room it did not use in this step (its push went elsewhere
    /// or nothing was due): given back.
    pub(super) fn stream_room_unused(&mut self, pushed: &BTreeSet<ConnId>, out: &mut Vec<Action>) {
        let holding: Vec<ConnId> = self.conns.iter().filter(|(c, x)| matches!(x.room.held, Some((Pusher::Stream, _))) && !pushed.contains(c)).map(|(c, _)| *c).collect();
        for c in holding {
            // the session's reservation of it too
            self.hub_down(c, Down::Notify(Vec::new()), out);
            self.release_room(c, Pusher::Stream, out);
        }
    }

    /// Each served connection's shared set's members (tests, diagnostics).
    pub fn served_opened(&self) -> BTreeMap<ConnId, BTreeSet<LabelId>> {
        self.conns.iter().filter(|(_, c)| c.dial.is_none()).map(|(c, _)| (*c, self.shared_members(*c).into_iter().collect())).collect()
    }

    /// Each served connection's per-label states (`LabelAt`; tests: only what its dialer proved).
    #[doc(hidden)]
    pub fn served_label_states(&self) -> BTreeMap<ConnId, usize> {
        self.conns.iter().filter(|(_, c)| c.dial.is_none()).map(|(id, c)| (*id, c.labels.len())).collect()
    }

    /// The labels this node serves to readers: those it syncs, at the deepest recorded step.
    /// Cached until `label.0` or role change.
    pub(crate) fn served_labels(&mut self) -> Arc<BTreeMap<LabelId, ServedLabel>> {
        if let Some(c) = &self.served_cache {
            return c.clone();
        }
        let mut m = BTreeMap::new();
        for (_, gl) in self.labels() {
            if let Some(s) = ServedLabel::new(&gl.steps) {
                // the hub's store keeps the path this node serves
                self.state.note_path(gl.id, s.path.iter().map(|x| (x.clone(), s.claims.get(&x.id()).map(|c| (**c).clone()))).collect());
                m.insert(gl.id, s);
            }
        }
        let m = Arc::new(m);
        self.served_cache = Some(m.clone());
        m
    }

    /// Bytes new here that reader `conn`'s stream or fetches brought for entries of `l` with no
    /// stamp under the served head, with their sizes as they came: those holding nothing here
    /// (`gives_nothing`: unjudged, or a header kept for a part dropped while invalid) count
    /// against the peer budgets (`charge_key`), and past either the entry is not kept, nor its
    /// commit once no entry names it (`forget_forgettable`; spec/requirements.md: peer input
    /// never grows storage unbounded).
    pub(crate) fn charge_reader(&mut self, conn: ConnId, l: LabelId, fresh: &[(BlobId, u64)]) -> Result<()> {
        if fresh.is_empty() {
            return Ok(());
        }
        self.prune_due();
        let who = self.connection_proven(conn).and_then(|p| p.source(&self.engine.core));
        let mut gone = Vec::new();
        for (b, size) in fresh {
            let size = *size;
            if !self.state.entries.get(&(l, *b)).is_some_and(|e| e.stamp.is_none() && self.gives_nothing(e)) {
                continue;
            }
            if !self.charges.fits(&self.cfg, who, &l, size) {
                self.budget_reached(Some(l));
                self.state.drop_entry(l, *b);
                // an opened one's blob record goes with it (`forget_blob`), so nothing carries
                // its pending commit (`sweep_pending`)
                self.forget_blob(b)?;
                if !self.state.blobs.contains_key(b) && !self.state.named(b) {
                    gone.push(*b);
                }
                continue;
            }
            self.charges.charge(l, *b, who, size);
            self.keep_source(l, *b);
        }
        self.delete_blobs(&gone)
    }

    /// Charges a Deposit item's blob `b` (`size` bytes under `l`) from `conn`'s peer as a
    /// reader's entry is charged (`charge_key`); false, charging nothing, past either budget. The
    /// entry, made once the item is taken, gets its source then (`keep_source`).
    pub(crate) fn charge_deposit(&mut self, conn: ConnId, l: LabelId, b: BlobId, size: u64) -> bool {
        self.prune_due();
        let node = self.connection_proven(conn).and_then(|p| p.node).filter(|_| self.connection_proven(conn).is_some_and(|p| self.engine.core.judge(p.all()).known()));
        if !self.charges.fits(&self.cfg, node, &l, size) {
            self.budget_reached(Some(l));
            return false;
        }
        self.charges.charge(l, b, node, size);
        true
    }

    /// Records the source entry `b` of `l` is charged to with the entry (`Entry::source`), so
    /// its charge outlives a restart.
    pub(crate) fn keep_source(&mut self, l: LabelId, b: BlobId) {
        let Some((source, _)) = self.charges.by_entry.get(&(l, b)).copied() else { return };
        if let Some(e) = self.state.entries.get(&(l, b)).filter(|e| e.source != source) {
            let e = Entry { source, ..e.clone() };
            self.state.set_entry(l, b, e);
        }
    }

    /// Whether entry `e` (`b` of `l`) counts against the peer budgets: unstamped, giving nothing
    /// held and at no host.
    fn counts(&self, l: &LabelId, b: &BlobId, e: &Entry) -> bool {
        e.stamp.is_none() && self.gives_nothing(e) && !self.state.present_anywhere(l, b)
    }

    /// Charges what the store holds at open (notes/peers.md, Budget): every entry that counts,
    /// at its size, to its source (`Entry::source`, else its label), so a restart gives no peer a
    /// fresh budget; a source left on one that no longer counts goes.
    pub(crate) fn charge_held(&mut self) {
        let mut counted = Vec::new();
        let mut cleared = Vec::new();
        for ((l, b), e) in &self.state.entries {
            if self.counts(l, b, e) {
                counted.push((*l, *b, e.source, e.size.map_or(0, u64::from)));
            } else if e.source.is_some() {
                cleared.push((*l, *b));
            }
        }
        for (l, b, source, n) in counted {
            self.charges.charge(l, b, source, n);
        }
        for (l, b) in cleared {
            self.clear_source(l, b);
        }
    }

    /// Drops entry `b` of `l`'s source: it no longer counts.
    fn clear_source(&mut self, l: LabelId, b: BlobId) {
        if let Some(e) = self.state.entries.get(&(l, b)).filter(|e| e.source.is_some()) {
            let e = Entry { source: None, ..e.clone() };
            self.state.set_entry(l, b, e);
        }
    }

    /// A peer budget refused what a peer sent (under `l`): the app hears of it once until
    /// charges are freed (`InputCapped`).
    fn budget_reached(&mut self, l: Option<LabelId>) {
        self.charges.full = true;
        if !std::mem::replace(&mut self.charges.reported, true) {
            let at = l.map(|l| format!(" under label {l:?}")).unwrap_or_default();
            self.report_capped(format!("peer budget reached{at}: unverified entries from peers refused (`peer_bytes` {}, `peer_total_bytes` {})", self.cfg.peer_bytes, self.cfg.peer_total_bytes));
        }
    }

    /// Whether entry `e` gives nothing held here (notes/node-sync.md, Input giving nothing):
    /// unopened, bad, parked, awaiting, its commit pending and not applied, or its commit known
    /// with no part held, only for a part dropped while invalid (`Engine::kept_invalid`: its
    /// header). Such an entry no writer vouched for counts against the unvouched bounds
    /// (`unvouched_cap`, the peer budgets).
    pub(crate) fn gives_nothing(&self, e: &Entry) -> bool {
        use super::state::Kind;
        let ix = &self.engine.core.ix;
        match &e.kind {
            Kind::Unknown | Kind::Bad | Kind::Parked(_) | Kind::Awaits { .. } => true,
            Kind::Commit { commit, .. } => (ix.pending.contains_key(commit) && !ix.commits.contains_key(commit)) || self.engine.kept_invalid(commit),
            _ => false,
        }
    }

    /// A budget was reached: charges that no longer count go first, at most once a second.
    fn prune_due(&mut self) {
        if self.charges.full && self.now() >= self.charges.pruned.saturating_add(1000) {
            self.prune_charges();
        }
    }

    /// Drops charges that no longer count (`counts`): entries no longer held, stamped, judged
    /// since, or present at a host, with the source they kept.
    pub(crate) fn prune_charges(&mut self) {
        let stale: Vec<(LabelId, BlobId)> = self.charges.by_entry.keys().filter(|(l, b)| !self.state.entries.get(&(*l, *b)).is_some_and(|e| self.counts(l, b, e))).copied().collect();
        self.charges.reported &= stale.is_empty();
        for (l, b) in stale {
            if let Some((p, n)) = self.charges.by_entry.remove(&(l, b)) {
                self.charges.uncharge(charge_key(p, &l), n);
            }
            self.clear_source(l, b);
        }
        self.charges.pruned = self.now();
        self.charges.full = false;
    }

    /// The Prove of `conn`'s dialer, on a connection the peer dialed (spec/sync.md §10): its proofs over this side's challenge and
    /// key count (one made for another connection or listener proves nothing here); this node
    /// answers its own, over the dialer's challenge, only to a dialer that proved an actor it
    /// knows. At most one per connection, after the dialer's Hello.
    pub(super) fn answer_prove(&mut self, conn: ConnId, id: osis_proto::msg::Id, proofs: Vec<osis_proto::ActorProof>, out: &mut Vec<Action>) -> Result<()> {
        use osis_proto::{Code, Message};
        let Some(s) = self.conns.get_mut(&conn) else { return Ok(()) };
        let Some((dialer, ch, key)) = s.binding.filter(|_| s.asked == Asked::Nothing) else {
            self.hub_down(conn, Down::Message(Box::new(Message::Error { id, code: Code::MALFORMED })), out);
            return Ok(());
        };
        s.asked = Asked::Prove;
        let good = osis_proto::prove::verified(proofs, false, &ch, &key);
        let answer = (|| -> Result<_> {
            let proven = super::proofs::proven_actors(&mut self.engine, &good)?;
            let known = self.engine.core.judge(proven.all()).known();
            let own = super::proofs::own_peer(&self.engine, &proven);
            let mine: Vec<osis_proto::ActorProof> = if known { super::proofs::provers(&mut self.engine, own)?.iter().map(|p| p.sign(true, &dialer, &key)).collect() } else { Vec::new() };
            Ok((proven, mine, known))
        })();
        // an engine error is this node's, not the peer's: answered Error 1, the step goes on
        let (proven, mine, known) = match answer {
            Ok(a) => a,
            Err(e) => {
                self.diag(format!("serve prove: {e}"));
                self.hub_down(conn, Down::Message(Box::new(Message::Error { id, code: Code::REFUSED })), out);
                return Ok(());
            }
        };
        if let Some(s) = self.conns.get_mut(&conn) {
            s.proven = proven;
            s.proved = mine.iter().map(|p| p.actor()).collect();
            s.answered = known;
        }
        self.hub_down(conn, Down::Message(Box::new(Message::Proved { id, proofs: mine })), out);
        Ok(())
    }

    /// The Resume of `conn`'s dialer, on a connection the peer dialed (spec/sync.md §10, Pair key): answered with a record of the
    /// actors it proved that are known here, found by its tags or made; Error 1 when it proved
    /// none. At most one per connection, after its Prove. Returns the record for `bind_record`,
    /// which waits until the answer is out (`serve_with`).
    pub(super) fn answer_resume(&mut self, conn: ConnId, id: osis_proto::msg::Id, nonce: [u8; 32], tags: Vec<[u8; 32]>, out: &mut Vec<Action>) -> Result<Option<(osis_store::RecordId, bool)>> {
        use osis_proto::{Code, Message};
        let Some(s) = self.conns.get_mut(&conn) else { return Ok(None) };
        let Some((dialer, ch, key)) = s.binding.filter(|_| s.asked == Asked::Prove) else {
            self.hub_down(conn, Down::Message(Box::new(Message::Error { id, code: Code::MALFORMED })), out);
            return Ok(None);
        };
        s.asked = Asked::Resume;
        let actors = super::records::counted_actors(&self.engine, &s.proven);
        if actors.is_empty() {
            self.hub_down(conn, Down::Message(Box::new(Message::Error { id, code: Code::REFUSED })), out);
            return Ok(None);
        }
        let ((mine, tag), bound, looked) = match super::records::answer_resume(&mut self.engine, &actors, &self.records.live(), &nonce, &tags, (&dialer, &ch, &key)) {
            Ok(a) => a,
            Err(e) => {
                self.diag(format!("serve resume: {e}"));
                self.hub_down(conn, Down::Message(Box::new(Message::Error { id, code: Code::REFUSED })), out);
                return Ok(None);
            }
        };
        self.records.lookups += looked;
        self.hub_down(conn, Down::Message(Box::new(Message::Resumed { id, nonce: mine, tag })), out);
        Ok(Some(bound))
    }

    /// Decides what a connection's client-port request goes up as (notes/client-port.md §3).
    /// A main session's Auth without a secret; a keyed session's with a secret matching a current
    /// `clients^.0` entry, which binds the session to that client actor, its secret stripped;
    /// any other Auth (a second one too) is Error 1. Proto refuses Call, Sub and Unsub before an
    /// answered Auth, so a keyed session never gets further unauthenticated.
    fn admit(&mut self, conn: ConnId, msg: osis_proto::Message) -> std::result::Result<(super::Tier, osis_proto::Message), (osis_proto::msg::Id, osis_proto::Code)> {
        use super::Tier;
        use osis_proto::{Code, Message};
        let tier = self.conns.get(&conn).map_or(Tier::Keyed, |s| s.tier);
        let id = msg.id();
        let Message::Auth { secret, session, .. } = msg else {
            return if tier == Tier::Keyed { Err((id, Code::REFUSED)) } else { Ok((tier, msg)) };
        };
        match (tier, secret) {
            (Tier::Main, None) => Ok((tier, Message::Auth { id, secret: None, session })),
            (Tier::Keyed, Some(secret)) => {
                let hash = osis_base::hash::hash(secret.expose());
                let Some((actor, until)) = self.client_entry_by_hash(&hash) else { return Err((id, Code::REFUSED)) };
                let of_it = self.conns.values().filter(|s| s.tier == Tier::Client(actor)).count();
                let all = self.conns.values().filter(|s| matches!(s.tier, Tier::Client(_))).count();
                if of_it >= super::MAX_CONNS_PER_CLIENT || all >= self.cfg.max_clients {
                    return Err((id, Code::RATE_LIMITED));
                }
                let Some(s) = self.conns.get_mut(&conn) else { return Err((id, Code::REFUSED)) };
                s.tier = Tier::Client(actor);
                s.client = Some(ClientBinding { hash, until });
                Ok((s.tier, Message::Auth { id, secret: None, session }))
            }
            _ => Err((id, Code::REFUSED)),
        }
    }

    /// This node's `clients^.0`.
    fn client_entries(&mut self) -> BTreeMap<Tid, ct::Client> {
        let me = self.engine.tid();
        self.engine.get_typed(&me, &ct::CLIENTS).ok().flatten().unwrap_or_default()
    }

    /// The current entry (actor, end) whose secret hash is `hash`: every entry compared in
    /// constant time, none skipped.
    fn client_entry_by_hash(&mut self, hash: &[u8; 32]) -> Option<(Tid, Option<u64>)> {
        let now = self.now();
        let probe = Secret32::from_bytes(*hash);
        let mut hit = None;
        for (t, c) in self.client_entries() {
            if Secret32::from_bytes(c.secret_hash) == probe {
                hit = Some((t, c.until.map(|u| u.0)));
            }
        }
        hit.filter(|(_, until)| until.is_none_or(|u| u > now))
    }

    /// The client actor connection `conn` runs as now: none unless the session is bound to
    /// a client whose entry is still there, under the same secret, and not past its `until`.
    /// The port asks at every request and every send, so no answer outlives the entry.
    pub fn client_of(&mut self, conn: ConnId) -> Option<Tid> {
        let now = self.now();
        let (super::Tier::Client(actor), Some(b)) = self.conns.get(&conn).map(|s| (s.tier, s.client))? else { return None };
        let e = self.client_entries().remove(&actor)?;
        b.holds(&e, now).then_some(actor)
    }

    /// After a `clients^.0` change: sessions of a client removed, rotated or past its `until` end;
    /// the others take their entry's `until` (the timer `serve_timers` closes them by).
    pub(crate) fn clients_changed(&mut self, out: &mut Vec<Action>) {
        if !self.conns.values().any(|s| s.client.is_some()) {
            return;
        }
        let entries = self.client_entries();
        let now = self.now();
        let mut stale = Vec::new();
        for (c, s) in self.conns.iter_mut() {
            let (super::Tier::Client(actor), Some(b)) = (s.tier, s.client.as_mut()) else { continue };
            match entries.get(&actor) {
                Some(e) if b.holds(e, now) => b.until = e.until.map(|u| u.0),
                _ => stale.push(*c),
            }
        }
        for c in stale {
            self.close(c, out);
        }
    }

    /// The connection the hub runs as its connection `id`, dialed or served (test harnesses).
    #[doc(hidden)]
    pub fn served_conn(&self, id: osis_host::ConnId) -> Option<ConnId> {
        self.hub_conns.get(&id).copied()
    }

    /// The hub's connection `conn` runs on, dialed or served (test harnesses).
    #[doc(hidden)]
    pub fn hub_conn(&self, conn: ConnId) -> Option<osis_host::ConnId> {
        self.conns.get(&conn).and_then(|c| c.hub)
    }

    /// Closes the sessions of a client past its `until`; expires the memory log's deletions and this node's
    /// tombstones; forgets carriers and certificate placements nothing needs; prunes charges
    /// and blob sizes.
    pub(crate) fn serve_timers(&mut self, out: &mut Vec<Action>) {
        let now = self.now();
        // a thin client's `until` passed: no other change is needed to end it
        let stale: Vec<ConnId> = self.conns.iter().filter(|(_, s)| s.client.is_some_and(|b| b.until.is_some_and(|u| u <= now))).map(|(c, _)| *c).collect();
        for c in stale {
            self.close(c, out);
        }
        let wall = self.state.now;
        self.state.mem_log.expire(wall);
        self.state.expire_tombs(wall);
        self.sweep_forgotten();
        // these scan every entry and placement: at most once per `RECORD_SWEEP_MS`
        if wall >= self.swept.saturating_add(RECORD_SWEEP_MS) {
            self.swept = wall;
            self.state.sweep_carriers(wall);
            let ix = &self.engine.core.ix.commits;
            self.state.sweep_certs(|c| ix.get(c).is_some_and(|m| (0..m.header.aspects.len()).any(|ai| !m.body_gone(ai))));
        }
        if let Err(e) = self.forget_forgettable() {
            self.diag(format!("forget: {e}"));
        }
        self.prune_charges();
        if self.blob_sizes.len() > self.state.entries.len() {
            let held: BTreeSet<BlobId> = self.state.entries.keys().map(|(_, b)| *b).collect();
            self.blob_sizes.retain(|b, _| held.contains(b));
        }
    }

    /// When the next client's `until` comes.
    pub(crate) fn serve_wake(&self) -> Option<u64> {
        self.conns.values().filter_map(|s| s.client.and_then(|b| b.until)).min()
    }
}
