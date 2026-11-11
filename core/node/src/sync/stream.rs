//! The node log stream between readers (spec/sync.md §10, Stream; issues/net-reconnect.md, One
//! node log, one cursor): one stream per connection over the node log (`osis_store` nodelog),
//! filtered by the connection's shared set S, behind opaque cursors.
//!
//! The invariant the stream's correctness rests on: **a requester holds every event of each
//! member it tracks up to that member's position, and a position only moves over what the
//! server scanned for that member.** So no write is dropped and a source judged caught up holds
//! nothing the requester lacks:
//! - A reply scans the log once, in position order, from the lowest start among the stream's
//!   cursor and the joins', and gives a member an event only past that member's own start. Its
//!   end is a position every member it covers was scanned to; a member is moved only to there.
//! - The log keeps each subject's latest event (compaction, never trimming by position), so a
//!   later read of a subject shows that event or a newer one: re-delivery is harmless, and a
//!   position never needs an event the log dropped but a deletion past `TOMBSTONE_LIFETIME`,
//!   which no read carries (issues/net-reconnect.md, Deletions).
//! - A member enters the requester's stream only with its join merged at the stream's position;
//!   one leaving keeps its position as a lag. A connection with a record starts from the record's
//!   S, each member where the record holds it (at the cursor, or joining from its own position),
//!   and pulls only once the two records agree (`shared_agreed`): a member only one side held
//!   leaves both streams with no lag, so neither claims a position the other did not serve it.
//! - A cursor is stored only after what it covers is applied (state flushed first), an entry
//!   announced without bytes once its bytes are held (`stream_settle`); Applied and a pass end
//!   wait alike. A member leaves the stream when it leaves S here, before any later message is
//!   applied, at the last settled position.
//! - Within a connection a requester joins L only after the server opened it: the side answering
//!   an Offer opens and joins after sending its answer, the tester on reading it; and the
//!   server's `Lost` follows every event it sent for L. So the server's S covers the requester's
//!   tracked members wherever the stream moves them.
//!
//! Checked by the randomized differentials `stream_differential_no_write_dropped_spec_sync_10`
//! and `stream_differential_paged_spec_sync_10` (core/node/tests/it/stream.rs).
//!
//! Both sides of a connection pull and serve: a member of S is pulled by the side it is open at,
//! whoever dialed. Bodies announced without bytes are fetched from one source at a time
//! (`stream_fetch`, by ids in the node's range), the next (a host, or a reader that announced
//! them) once the first is slower than the stall time (`asked`); what a stream owes lives in its
//! memory alone (no entry row before the bytes), so a lost connection or a restart forgets it and the stream,
//! from its last stored position, announces it again. A stream waiting on `MAX_WAITING`
//! positions or bodies takes no new one (flow control: its cursor stays, nothing is skipped),
//! and a peer answers stream requests in order, so a Fetch it skipped is asked elsewhere
//! (`stream_skipped`). Memory entries are the log's memory part
//! (`MemLog`), which no cursor names: the first Pull of a connection, and every join, list the
//! memory events of what they start; later ones follow in counter order on that connection,
//! paged by the same budget as the durable part. Relay-only entries go as a Stream with no
//! cursor (`stream_relay`): no position names them.

use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_proto::msg::{Join, Pull, PullReply, Stream};
use osis_proto::{Event, Message};
use osis_store::{At, LoggedEvent, NodeEvent, RecordId};
use std::collections::{BTreeMap, BTreeSet};

/// Log rows one reply or push scans at most, matching or not. Resource bound: 0 never moves
/// (no reply could end), infinity lets one request read the whole log in one go.
const SCAN_ROWS: usize = 1 << 16;
/// Rows read from the store at a time while scanning.
const READ_PAGE: usize = 1024;
/// Ids this module draws for its Pulls: the shared set's range (top bit) with the next bit, so
/// they never meet a session's own or the shared set's.
const ID_BASE: u32 = osis_proto::msg::NODE_IDS | (1 << 30);
/// Positions waiting to settle, and bodies they owe, from which a stream takes no new position
/// (`Pulling::full`): no Pull goes and a push is not taken, the cursor staying where it is, so
/// nothing is skipped; past it only the reply of the Pull in flight and the push taken last add
/// to it, each within a message. Resource bound: 0 never moves; infinity lets a source that never
/// serves make this node keep a position per push and an id per announcement.
const MAX_WAITING: usize = 1024;

/// The node log's memory part: one latest event per memory entry, ordered by an in-memory
/// counter, a deletion kept `MAX_DRIFT_MS` (a memory entry's tombstone). Bounded by the live
/// memory entries plus recent deletions; nothing of it outlives the process.
#[derive(Clone, Default)]
pub(crate) struct MemLog {
    seq: u64,
    /// By counter: entry, added (else deleted), when (wall ms).
    by_seq: BTreeMap<u64, (LabelId, BlobId, bool, u64)>,
    slot: BTreeMap<(LabelId, BlobId), u64>,
}

impl MemLog {
    fn put(&mut self, l: LabelId, b: BlobId, added: bool, now: u64) {
        self.seq += 1;
        if let Some(old) = self.slot.insert((l, b), self.seq) {
            self.by_seq.remove(&old);
        }
        self.by_seq.insert(self.seq, (l, b, added, now));
    }

    pub(crate) fn added(&mut self, l: LabelId, b: BlobId, now: u64) {
        self.put(l, b, true, now);
    }

    pub(crate) fn deleted(&mut self, l: LabelId, b: BlobId, now: u64) {
        self.put(l, b, false, now);
    }

    /// A label left this node: its events go, none logged.
    pub(crate) fn forget(&mut self, l: &LabelId) {
        let gone: Vec<((LabelId, BlobId), u64)> = self.slot.range((*l, BlobId([0; 32]))..=(*l, BlobId([0xff; 32]))).map(|(k, v)| (*k, *v)).collect();
        for (k, s) in gone {
            self.slot.remove(&k);
            self.by_seq.remove(&s);
        }
    }

    /// Deletions past a memory tombstone's life go.
    pub(crate) fn expire(&mut self, now: u64) {
        let old: Vec<u64> = self.by_seq.iter().filter(|(_, (_, _, added, at))| !*added && at.saturating_add(osis_base::format::MAX_DRIFT_MS) <= now).map(|(s, _)| *s).collect();
        for s in old {
            if let Some((l, b, ..)) = self.by_seq.remove(&s) {
                self.slot.remove(&(l, b));
            }
        }
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    /// Events after counter `after`, in order: (counter, label, blob, added).
    fn after(&self, after: u64) -> impl Iterator<Item = (u64, LabelId, BlobId, bool)> + '_ {
        self.by_seq.range(after.saturating_add(1)..).map(|(s, (l, b, a, _))| (*s, *l, *b, *a))
    }
}

/// The serving side of one connection's stream.
#[derive(Clone, Default)]
pub(crate) struct Serving {
    /// Following: pushes go on from this durable position.
    follow: Option<u64>,
    /// The memory part's counter this connection was given events up to.
    mem_seq: u64,
    inline_limit: u64,
    /// Blobs whose bytes came over this connection: announced back without them. At most
    /// `MAX_CROSSED` (an optimization: past it the set starts over).
    crossed: BTreeSet<BlobId>,
    /// The last reply or push left nothing of the log or its memory part unscanned.
    at_end: bool,
    /// Members the requester tracks on this connection (the record's, and a Pull's `join` this
    /// node shares).
    pulled: BTreeSet<LabelId>,
    /// Replies and pushes asked to report and not reported yet, in order. At most
    /// `MAX_UNREPORTED`: past it the oldest two merge, their members waiting for the later
    /// cursor.
    unreported: std::collections::VecDeque<Unreported>,
    /// A Pull came on this connection.
    asked: bool,
    /// Where the requester reported storing the stream (spec/sync.md §10 Reports): the first
    /// Pull's cursor (what it stored before this connection), then each `Applied`'s. A later
    /// Pull's cursor reports nothing: it may name positions not stored yet. For this connection
    /// only; it names every member `pulled` but those in `own`.
    reported: Option<u64>,
    /// Members the requester stores at a position of their own: joins, at the position the first
    /// Pull naming them carried (stored: a lag, a record's) or a reported page reached, until the
    /// message merging them into the stream is reported.
    own: BTreeMap<LabelId, Own>,
    /// Replies and pushes sent, counted (`Own::merged`, `Unreported::seq`).
    seq: u64,
}

/// A join the requester stores at its own position (`Serving::own`).
#[derive(Clone)]
struct Own {
    /// Its reported position; none for a join from the start.
    at: Option<u64>,
    /// The message (`Serving::seq`) that merged it into the stream.
    merged: Option<u64>,
}

/// A reply or push asked to report (`Serving::unreported`): its cursor, the members it carried
/// events of, its count (`Serving::seq`), the stream position it brings the requester to and
/// the joins it left in pages at theirs.
#[derive(Clone)]
struct Unreported {
    cursor: Vec<u8>,
    labels: BTreeSet<LabelId>,
    seq: u64,
    at: u64,
    paging: Vec<(LabelId, u64)>,
}

const MAX_CROSSED: usize = 1 << 14;
/// Unreported messages kept apart (`Serving::unreported`). Any value from 1 is correct: fewer
/// only make a member wait for a later report; it bounds what a requester that never reports
/// makes this node keep.
const MAX_UNREPORTED: usize = 16;

impl Serving {
    /// Where the requester reported storing member `l`, if anywhere (`reported`, `own`).
    fn position(&self, l: &LabelId) -> Option<u64> {
        match self.own.get(l) {
            Some(o) => o.at,
            None => self.reported.filter(|_| self.pulled.contains(l)),
        }
    }

    /// Where message `seq`, bringing the stream to `at` and leaving `paging` in pages, brings
    /// member `l`: none for one it does not carry (not tracked, or a join not merged by then).
    fn brings(&self, l: &LabelId, seq: u64, at: u64, paging: &[(LabelId, u64)]) -> Option<u64> {
        if let Some((_, p)) = paging.iter().find(|(x, _)| x == l) {
            return Some(*p);
        }
        let merged = self.own.get(l).is_none_or(|o| o.merged.is_some_and(|m| m <= seq));
        (self.pulled.contains(l) && merged).then_some(at)
    }

    /// A Pull came, its stream position `base` and its joins' (none: from the start): the first
    /// Pull reports the stream's, and a join is reported where the first Pull naming it puts it.
    fn pull_reports(&mut self, base: Option<u64>, joins: &[(LabelId, Option<u64>)]) {
        if !std::mem::replace(&mut self.asked, true) {
            self.reported = base;
        }
        for (l, at) in joins {
            self.own.entry(*l).or_insert(Own { at: *at, merged: None });
        }
    }

    /// A reply or push went with `cursor`, events of `labels`, bringing the stream to `at`,
    /// merging the joins `merged` and leaving `paging` in pages: it asks for its report when it
    /// carries events, or when it brings a member to its `until` that no report awaited covers
    /// (`until_due`).
    fn sent(&mut self, cursor: &Option<Vec<u8>>, labels: BTreeSet<LabelId>, at: u64, merged: &[LabelId], paging: Vec<(LabelId, u64)>, untils: &BTreeMap<LabelId, u64>) -> bool {
        self.seq += 1;
        let seq = self.seq;
        for l in merged {
            if let Some(o) = self.own.get_mut(l) {
                o.merged.get_or_insert(seq);
            }
        }
        let Some(c) = cursor else { return false };
        if labels.is_empty() && !self.until_due(seq, at, &paging, untils) {
            return false;
        }
        self.unreported.push_back(Unreported { cursor: c.clone(), labels, seq, at, paging });
        if self.unreported.len() > MAX_UNREPORTED
            && let Some(first) = self.unreported.pop_front()
            && let Some(next) = self.unreported.front_mut()
        {
            next.labels.extend(first.labels);
            for (l, p) in first.paging {
                if !next.paging.iter().any(|(x, _)| *x == l) {
                    next.paging.push((l, p));
                }
            }
        }
        true
    }

    /// Whether message `seq` (as `brings`) must ask a report for an `until`: it brings a member
    /// to it, not reported there yet nor covered by a report awaited.
    fn until_due(&self, seq: u64, at: u64, paging: &[(LabelId, u64)], untils: &BTreeMap<LabelId, u64>) -> bool {
        untils.iter().any(|(l, u)| {
            self.brings(l, seq, at, paging).is_some_and(|p| p >= *u)
                && self.position(l).is_none_or(|r| r < *u)
                && !self.unreported.iter().any(|x| self.brings(l, x.seq, x.at, &x.paging).is_some_and(|p| p >= *u))
        })
    }

    /// The requester reported storing what `cursor` covers (`Applied`): that message and every
    /// one before it (a requester applies and stores in order).
    fn reported(&mut self, cursor: &[u8]) {
        let Some(i) = self.unreported.iter().position(|x| x.cursor == cursor) else { return };
        let done: Vec<Unreported> = self.unreported.drain(..=i).collect();
        for x in done {
            self.reported = Some(self.reported.map_or(x.at, |r| r.max(x.at)));
            for (l, p) in x.paging {
                if let Some(o) = self.own.get_mut(&l) {
                    o.at = Some(o.at.map_or(p, |a| a.max(p)));
                }
            }
            self.own.retain(|_, o| o.merged.is_none_or(|m| m > x.seq));
        }
    }
}

/// The requesting side of one connection's stream.
#[derive(Clone, Default)]
pub(crate) struct Pulling {
    /// The stream's position in the peer's log.
    cursor: Option<Vec<u8>>,
    /// Members whose events up to `cursor` are applied here.
    in_stream: BTreeSet<LabelId>,
    /// Members entering the stream, each from its own position (none: the start).
    joins: BTreeMap<LabelId, Option<Vec<u8>>>,
    /// The Pull in flight: its id, its place in send order (`sent`) and the joins it named.
    asked: Option<(u32, u64, Vec<LabelId>)>,
    /// Fetches asked, by id.
    fetching: BTreeMap<u32, Fetching>,
    /// Requests of the stream sent on this connection (Pulls and Fetches): answered in this order
    /// (`stream_skipped`).
    sent: u64,
    /// A push was not taken (`MAX_WAITING`): none is until the next reply, which reads it again
    /// from `cursor`.
    dropped: bool,
    /// Positions reached whose bodies announced without bytes are not all held here yet, oldest
    /// first (`stream_settle`).
    unsettled: std::collections::VecDeque<Unsettled>,
    /// The cursor stored last: what this node holds of the stream for certain.
    settled: Option<Vec<u8>>,
    /// A Pull went on this connection (the first asks for the live memory entries).
    started: bool,
    /// The `inline_limit` of the last Pull: what the peer's pushes carry inline.
    inline: u64,
    /// The last reply ended the peer's log and nothing waits.
    caught_up: bool,
    next_id: u32,
    record: Option<RecordId>,
    /// Pulls sent (tests count them).
    pulls: u64,
    /// The last Pull was answered Error: asked again at this time (wall ms), `resync_ms` after.
    retry_at: Option<u64>,
}

/// A Fetch of the stream not answered yet: its place in send order (`Pulling::sent`), the member,
/// the blobs, the `max_reply` asked and when they were first asked there (wall ms; the rest of an
/// answered Fetch keeps it: past `STALL_TIMEOUT_MS` its bodies are asked of the next source too,
/// `SyncEngine::asked`).
#[derive(Clone)]
struct Fetching {
    seq: u64,
    label: LabelId,
    ids: Vec<BlobId>,
    max_reply: u64,
    at: u64,
}

/// A position the stream reached that waits for bodies (`Pulling::unsettled`): stored, reported
/// and counted as a pass end only once every body announced up to it is held here.
#[derive(Clone)]
struct Unsettled {
    cursor: Option<Vec<u8>>,
    /// Bodies its message announced without bytes that this node lists and does not hold yet.
    owed: BTreeSet<(LabelId, BlobId)>,
    /// Members it merged into the stream, and those it left paging with their lag.
    merged: Vec<LabelId>,
    paging: Vec<(LabelId, Vec<u8>)>,
    /// Its message asked for a report.
    report: bool,
    /// Members it read the peer's log to its end for.
    passed: Vec<LabelId>,
}

impl Pulling {
    /// Whether any position not settled yet names member `l`.
    fn unsettled_names(&self, l: &LabelId) -> bool {
        self.unsettled.iter().any(|u| u.merged.contains(l) || u.paging.iter().any(|(x, _)| x == l))
    }

    /// A request's id, and its place in send order.
    fn next(&mut self) -> (u32, u64) {
        self.next_id = self.next_id.wrapping_add(1);
        self.sent += 1;
        (ID_BASE | (self.next_id & ((1 << 30) - 1)), self.sent)
    }

    /// The stream waits on `MAX_WAITING` positions or bodies: it takes no new position.
    fn full(&self) -> bool {
        self.unsettled.len() >= MAX_WAITING || self.unsettled.iter().map(|u| u.owed.len()).sum::<usize>() >= MAX_WAITING
    }
}

/// Where a member leaving S stops in this side's stream of the peer (`stream_leave`).
pub(crate) enum Stop {
    /// Where this side holds it.
    Here,
    /// Where the peer's `Lost` says it stopped for this side: a position this side reported
    /// storing it at (or none), always kept.
    Lost(Option<Vec<u8>>),
    /// Nowhere: the records disagreed on it (a digest difference), its rejoin is a listing.
    Listing,
}

/// One connection's stream, either side.
#[derive(Clone, Default)]
pub(crate) struct ConnStream {
    pub(crate) serving: Serving,
    pub(crate) pulling: Pulling,
}

/// Stream events by sync ID.
type Events = Vec<(LabelId, Event)>;

/// What one scan found: events with their positions, where it ended, the log's end.
struct Scan {
    events: Vec<LoggedEvent>,
    end: u64,
    log_end: u64,
}

/// Scans the log from `from` for events of `starts`' members past their start, at most
/// `SCAN_ROWS` rows. A member being ended (its `until` below `u64::MAX`) gets only events of
/// entries first logged at or below `until`: an entry it was served stays served when it is
/// logged again (a stamp, a re-wrap, its deletion), the rotation among them.
fn scan(tx: &mut osis_store::Transaction<'_>, from: u64, starts: &BTreeMap<LabelId, (u64, u64)>) -> std::result::Result<Scan, osis_store::Error> {
    let log_end = tx.log_end()?;
    let (mut pos, mut rows, mut events) = (from, 0usize, Vec::new());
    loop {
        let (page, at, more) = tx.log_after(pos, READ_PAGE.min(SCAN_ROWS - rows))?;
        rows += page.len();
        for e in page {
            let (l, entry) = match e.event {
                NodeEvent::Added(l, b) | NodeEvent::Deleted { label: l, blob: b, .. } => (l, Some(b)),
                NodeEvent::Head(l) => (l, None),
            };
            let Some((s, until)) = starts.get(&l) else { continue };
            let shown = e.pos <= *until
                || match entry {
                    Some(b) => tx.log_entry_first(&l, &b)?.is_some_and(|f| f <= *until),
                    None => false,
                };
            if e.pos > *s && shown {
                events.push(e);
            }
        }
        pos = at;
        if !more || rows >= SCAN_ROWS {
            return Ok(Scan { events, end: pos, log_end });
        }
    }
}

impl SyncEngine {
    /// A stream message from `conn`'s peer (the shared set's go to `shared_message`).
    pub(super) fn peer_message(&mut self, conn: ConnId, m: Message, out: &mut Vec<Action>) -> Result<()> {
        match m {
            Message::Pull(p) => self.stream_serve(conn, *p, out),
            Message::PullReply(r) => self.stream_reply(conn, *r, out),
            Message::Stream(s) => self.stream_pushed(conn, *s, out),
            Message::Applied { cursor } => {
                if let Some(s) = self.streams.get_mut(&conn) {
                    s.serving.reported(&cursor);
                }
                self.shared_until_due(conn, out)
            }
            Message::Stranded { id, label, holder, keys } => {
                self.shared_send(conn, Message::Ok { id }, out)?;
                self.stranded_report(label, holder, keys)
            }
            Message::Suspect { id, label, entries } => {
                self.shared_send(conn, Message::Ok { id }, out)?;
                self.suspect_message(conn, label, entries)
            }
            // only a dialer proves first (a served session's go to `served_prove`, `served_resume`)
            Message::Prove { id, .. } | Message::Resume { id, .. } => self.shared_send(conn, Message::Error { id, code: osis_proto::Code::UNSUPPORTED }, out),
            Message::Fetch { id, label, max_reply, ids } => self.stream_serve_fetch(conn, id, label, max_reply, ids, out),
            Message::FetchReply { id, items } => self.stream_fetch_reply(conn, id, items, out),
            Message::Error { id, code } => {
                if self.stream_refused(conn, id, code, out)? {
                    return Ok(());
                }
                self.shared_message(conn, Message::Error { id, code }, out)
            }
            m => self.shared_message(conn, m, out),
        }
    }

    /// The members of `conn`'s S on this side.
    fn stream_members(&self, conn: ConnId) -> BTreeSet<LabelId> {
        self.shared_members(conn)
    }

    /// Blobs uploaded over `conn`: not inlined back on its stream.
    pub(super) fn stream_crossed(&mut self, conn: ConnId, ids: Vec<BlobId>) {
        let s = &mut self.streams.entry(conn).or_default().serving;
        if s.crossed.len() + ids.len() > MAX_CROSSED {
            s.crossed.clear();
        }
        s.crossed.extend(ids);
    }

    /// Builds wire events from scanned log events, within `budget` bytes (past it only as the
    /// message's first event, `alone`): the events taken, and the position the page covers if
    /// the budget cut it (else `None`).
    fn stream_events(&mut self, conn: ConnId, scanned: &[LoggedEvent], budget: &mut usize, alone: bool) -> Result<(Events, Option<u64>)> {
        let labels = self.served_labels();
        let (inline, crossed) = self.streams.get(&conn).map_or((0, BTreeSet::new()), |s| (s.serving.inline_limit, s.serving.crossed.clone()));
        let mut out = Vec::new();
        for e in scanned {
            let ev = match e.event {
                NodeEvent::Added(l, b) => match self.stream_added(l, b, inline, &crossed, *budget)? {
                    Some(ev) => (l, ev),
                    None => continue,
                },
                NodeEvent::Deleted { label, blob, .. } => (label, Event::Deleted(blob)),
                NodeEvent::Head(l) => match labels.get(&l).and_then(|s| s.head()) {
                    Some(h) => (l, Event::Head(h.clone())),
                    None => continue,
                },
            };
            let n = osis_proto::msg::stream_event_size(&ev.1);
            if n > *budget && (!out.is_empty() || !alone) {
                return Ok((out, Some(e.pos.saturating_sub(1))));
            }
            *budget = budget.saturating_sub(n);
            out.push(ev);
        }
        Ok((out, None))
    }

    /// An entry as the stream shows it: only one whose bytes are held here (an entry kept with
    /// its bytes dropped has nothing to serve), inline when it fits.
    fn stream_added(&mut self, l: LabelId, b: BlobId, inline: u64, crossed: &BTreeSet<BlobId>, budget: usize) -> Result<Option<Event>> {
        let Some(e) = self.state.entries.get(&(l, b)) else { return Ok(None) };
        let (wrap, stamp) = (e.wrap, e.stamp);
        if !self.engine.has_blob(&b) {
            return Ok(None);
        }
        let size = match self.blob_sizes.get(&b) {
            Some(n) => *n,
            None => match self.engine.blob(&b)? {
                Some(x) => {
                    self.blob_sizes.insert(b, x.len() as u64);
                    x.len() as u64
                }
                None => return Ok(None),
            },
        };
        let blob = if size <= inline && !crossed.contains(&b) && (size as usize).saturating_add(200) <= budget { self.engine.blob(&b)? } else { None };
        Ok(Some(Event::Added { blob_id: b, blob, wrap, stamp }))
    }

    /// The memory part, in counter order within `budget` (its counter is the connection's alone,
    /// never a cursor's): every event of the `list` members (entering the stream here: a
    /// listing) and the events after the connection's counter of its other members. Whether the
    /// budget cut it: the counter then stops before the first event left, which the next reply
    /// or push takes.
    fn stream_memory(&mut self, conn: ConnId, list: &BTreeSet<LabelId>, members: &BTreeSet<LabelId>, budget: &mut usize) -> Result<(Vec<(LabelId, Event)>, bool)> {
        let after = self.streams.get(&conn).map_or(0, |s| s.serving.mem_seq);
        let from = if list.is_empty() { after } else { 0 };
        let picked: Vec<(u64, LabelId, BlobId, bool)> = self.state.mem_log.after(from).filter(|(s, l, _, added)| (list.contains(l) && (*added || *s > after)) || (members.contains(l) && *s > after)).collect();
        let mut at = self.state.mem_log.seq();
        let (inline, crossed) = self.streams.get(&conn).map_or((0, BTreeSet::new()), |s| (s.serving.inline_limit, s.serving.crossed.clone()));
        let mut out = Vec::new();
        let mut cut = false;
        for (seq, l, b, added) in picked {
            let ev = if added {
                match self.stream_added(l, b, inline, &crossed, *budget)? {
                    Some(e) => e,
                    None => continue,
                }
            } else {
                Event::Deleted(b)
            };
            let n = osis_proto::msg::stream_event_size(&ev);
            if n > *budget && !out.is_empty() {
                at = seq.saturating_sub(1);
                cut = true;
                break;
            }
            *budget = budget.saturating_sub(n);
            out.push((l, ev));
        }
        self.streams.entry(conn).or_default().serving.mem_seq = at;
        Ok((out, cut))
    }

    /// Answers a Pull (issues/net-reconnect.md, One node log): after `served_labels` and a flush
    /// (a moved head enters the log only there), read in a transaction of its own, filtered by S
    /// and by the bytes held. The Pull first reports what the requester stored (`pull_reports`):
    /// a member being ended whose `until` that passed closes before the reply
    /// (`shared_until_due`).
    fn stream_serve(&mut self, conn: ConnId, p: Pull, out: &mut Vec<Action>) -> Result<()> {
        // a connection with no shared set serves no stream (spec/sync.md §10)
        if !self.records.shared.contains_key(&conn) {
            return self.shared_send(conn, Message::Error { id: p.id, code: osis_proto::Code::NOT_ADMITTED }, out);
        }
        let (base, join_at) = self.engine.run(|tx| {
            let base = match &p.cursor {
                Some(c) => tx.txn.log_position(c)?,
                None => None,
            };
            let mut join_at = Vec::with_capacity(p.joins.len());
            for (l, c) in &p.joins {
                join_at.push((*l, match c {
                    Some(c) => tx.txn.log_position(c)?,
                    None => Some(0),
                }));
            }
            Ok((base, join_at))
        })?;
        let members = self.stream_members(conn);
        {
            let reports: Vec<(LabelId, Option<u64>)> = p.joins.iter().zip(&join_at).filter(|((l, _), _)| members.contains(l)).map(|((l, c), (_, at))| (*l, at.filter(|_| c.is_some()))).collect();
            self.streams.entry(conn).or_default().serving.pull_reports(base, &reports);
        }
        self.shared_until_due(conn, out)?;
        let members = self.stream_members(conn);
        let untils = self.shared_untils(conn);
        let _ = self.served_labels();
        self.state.flush(&mut self.engine)?;
        {
            let s = &mut self.streams.entry(conn).or_default().serving;
            s.inline_limit = p.inline_limit;
            s.follow = None;
        }
        let first = p.ephemeral;
        // a cursor naming no position, the stream's or a join's: the stream from the start
        // (else a join read from the start would not be known as a listing there)
        let mut whole = base.is_none();
        let (mut joined, mut refused) = (Vec::new(), Vec::new());
        for (l, at) in &join_at {
            if !members.contains(l) {
                refused.push(*l);
                continue;
            }
            whole |= at.is_none();
            joined.push((*l, at.unwrap_or(0)));
        }
        if whole {
            joined.clear();
        }
        let base = base.filter(|_| !whole).unwrap_or(0);
        let bound = |l: &LabelId| untils.get(l).copied().unwrap_or(u64::MAX);
        let mut starts: BTreeMap<LabelId, (u64, u64)> = members.iter().map(|l| (*l, (base, bound(l)))).collect();
        starts.extend(joined.iter().map(|(l, at)| (*l, (*at, bound(l)))));
        let from = starts.values().map(|(s, _)| *s).min().unwrap_or(base);
        let scan = self.engine.run(|tx| Ok(scan(&mut tx.txn, from, &starts)?))?;
        let mut budget = usize::try_from(p.max_reply).unwrap_or(usize::MAX).saturating_sub(256);
        // the memory part first: a cursor names no memory event, so each member entering the
        // stream gets its live entries listed; then what followed for the rest. A member being
        // ended gets none: no position bounds them
        let live: BTreeSet<LabelId> = members.iter().filter(|l| !untils.contains_key(l)).copied().collect();
        let listed: BTreeSet<LabelId> = if whole || first { live.clone() } else { joined.iter().map(|(l, ..)| *l).filter(|l| live.contains(l)).collect() };
        let (mut events, memory_cut) = self.stream_memory(conn, &listed, &live, &mut budget)?;
        let (durable, cut) = self.stream_events(conn, &scan.events, &mut budget, events.is_empty())?;
        events.extend(durable);
        let end = cut.unwrap_or(scan.end);
        let more = end < scan.log_end || memory_cut;
        // every member scanned past its start is at `end`; the stream's own position does not go
        // back (a reply ending below it moves only the joins)
        let stream_at = if whole { end } else { base.max(end) };
        let still: Vec<(LabelId, u64)> = if whole { Vec::new() } else { joined.iter().map(|(l, at)| (*l, (*at).max(end))).filter(|(_, at)| *at < base).collect() };
        let (cursor, joins) = self.engine.run(|tx| {
            let cursor = tx.txn.log_cursor(stream_at)?;
            let mut joins: Vec<Join> = refused.iter().map(|l| (*l, None)).collect();
            for (l, at) in &still {
                joins.push((*l, tx.txn.log_cursor(*at)?));
            }
            Ok((cursor, joins))
        })?;
        let labels: BTreeSet<LabelId> = events.iter().map(|(l, _)| *l).collect();
        let s = &mut self.streams.entry(conn).or_default().serving;
        if p.follow && !more {
            s.follow = Some(stream_at);
        }
        s.at_end = !more;
        s.pulled.extend(p.joins.iter().map(|(l, _)| *l).filter(|l| members.contains(l)));
        let merged: Vec<LabelId> = if whole { s.own.keys().copied().collect() } else { joined.iter().map(|(l, _)| *l).filter(|l| !still.iter().any(|(x, _)| x == l)).collect() };
        let report = s.sent(&cursor, labels, stream_at, &merged, still, &untils);
        let reply = PullReply { id: p.id, events, cursor, whole, more, report, joins };
        self.shared_send(conn, Message::PullReply(Box::new(reply)), out)
    }

    /// Pushes what the log gained to each connection following its stream, at most one page
    /// each per step (the next goes at the next step). A push also goes, with no events, when it
    /// brings a member being ended to its `until` with no report awaited there (`until_due`). On a
    /// hub session a push waits for the room the session grants (`push_room`), within it.
    pub(super) fn stream_push(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let following: Vec<(ConnId, u64, u64)> = self.streams.iter().filter_map(|(c, s)| s.serving.follow.map(|f| (*c, f, s.serving.mem_seq))).collect();
        let mut pushed = BTreeSet::new();
        if following.is_empty() {
            self.stream_room_unused(&pushed, out);
            return Ok(());
        }
        let _ = self.served_labels();
        self.state.flush(&mut self.engine)?;
        let log_end = self.engine.run(|tx| Ok(tx.txn.log_end()?))?;
        let mem_seq = self.state.mem_log.seq();
        for (conn, at, seen) in following {
            let untils = self.shared_untils(conn);
            let due = |s: &Self, end: u64| s.streams.get(&conn).is_some_and(|x| x.serving.until_due(x.serving.seq + 1, end, &[], &untils));
            if at >= log_end && seen >= mem_seq && !due(self, at) {
                continue;
            }
            let Some(room) = self.push_room(conn, out) else {
                // something waits to go: not at the log's end for this connection
                if let Some(s) = self.streams.get_mut(&conn) {
                    s.serving.at_end = false;
                }
                continue;
            };
            let members = self.stream_members(conn);
            let starts: BTreeMap<LabelId, (u64, u64)> = members.iter().map(|l| (*l, (at, untils.get(l).copied().unwrap_or(u64::MAX)))).collect();
            let scan = self.engine.run(|tx| Ok(scan(&mut tx.txn, at, &starts)?))?;
            let mut budget = room.min(osis_proto::serving::REPLY_BUDGET).saturating_sub(256);
            let live: BTreeSet<LabelId> = members.iter().filter(|l| !untils.contains_key(l)).copied().collect();
            let (mut events, memory_cut) = self.stream_memory(conn, &BTreeSet::new(), &live, &mut budget)?;
            let (durable, cut) = self.stream_events(conn, &scan.events, &mut budget, events.is_empty())?;
            events.extend(durable);
            let end = cut.unwrap_or(scan.end);
            if let Some(s) = self.streams.get_mut(&conn) {
                s.serving.follow = Some(end);
                s.serving.at_end = end >= log_end && !memory_cut;
            }
            if events.is_empty() && !due(self, end) {
                continue;
            }
            let cursor = self.engine.run(|tx| Ok(tx.txn.log_cursor(end)?))?;
            let labels: BTreeSet<LabelId> = events.iter().map(|(l, _)| *l).collect();
            let Some(s) = self.streams.get_mut(&conn).map(|s| &mut s.serving) else { continue };
            let report = s.sent(&cursor, labels, end, &[], Vec::new(), &untils);
            pushed.insert(conn);
            self.room_used(conn, out);
            self.shared_send(conn, Message::Stream(Box::new(Stream { events, cursor, report })), out)?;
        }
        self.stream_room_unused(&pushed, out);
        Ok(())
    }

    /// Where `conn`'s requester reported storing member `l` (`Serving::position`).
    pub(super) fn stream_reported(&self, conn: ConnId, l: &LabelId) -> Option<u64> {
        self.streams.get(&conn).and_then(|s| s.serving.position(l))
    }

    // ---- the requesting side ----

    /// `conn` took record `id`: its stream goes on from the record's cursor with the record's
    /// members where the record holds them, pulled once the two records agree; the peer is
    /// served them as members it tracks.
    pub(super) fn stream_bind(&mut self, conn: ConnId, id: RecordId, cursor: Option<Vec<u8>>, members: &[(LabelId, osis_store::Member)]) {
        let st = self.streams.entry(conn).or_default();
        st.serving.pulled = members.iter().map(|(l, _)| *l).collect();
        let p = &mut st.pulling;
        p.record = Some(id);
        p.settled = cursor.clone();
        p.cursor = cursor;
        for (l, m) in members {
            match &m.at {
                At::Stream => {
                    p.in_stream.insert(*l);
                }
                At::Join(c) => {
                    p.joins.insert(*l, c.clone());
                }
            }
        }
    }

    /// `conn`'s record is no longer honoured: its stream keeps nothing in it from now on.
    pub(super) fn stream_unbind(&mut self, conn: ConnId) {
        if let Some(s) = self.streams.get_mut(&conn) {
            s.pulling.record = None;
        }
    }

    /// Member `l` opened in `conn`'s shared set here: it joins the stream, from its lag or the
    /// start, and the record keeps it (`m`, joining from there) in the same transaction.
    pub(super) fn stream_join(&mut self, conn: ConnId, l: LabelId, m: osis_store::Member, out: &mut Vec<Action>) -> Result<()> {
        let tracked = self.streams.get(&conn).is_some_and(|s| s.pulling.in_stream.contains(&l) || s.pulling.joins.contains_key(&l));
        if tracked {
            return Ok(());
        }
        let record = self.streams.get(&conn).and_then(|s| s.pulling.record);
        let lag = match record {
            Some(id) => self.engine.run(|tx| {
                let lag = tx.txn.record_take_lag(&id, &l)?;
                tx.txn.record_open(&id, l, &osis_store::Member { at: At::Join(lag.clone()), ..m })?;
                Ok(lag)
            })?,
            None => None,
        };
        let p = &mut self.streams.entry(conn).or_default().pulling;
        p.joins.insert(l, lag);
        p.caught_up = false;
        self.stream_ask(conn, false, out)
    }

    /// Member `l` left `conn`'s shared set here: nothing more of it is applied or served, its
    /// position is kept as `stop` says for a rejoin, and the record re-marks it pending (below
    /// `changed_at`) in the same transaction.
    pub(super) fn stream_leave(&mut self, conn: ConnId, l: &LabelId, changed_at: u64, stop: Stop) -> Result<()> {
        let Some(s) = self.streams.get_mut(&conn) else { return Ok(()) };
        s.serving.pulled.remove(l);
        s.serving.own.remove(l);
        let p = &mut s.pulling;
        // the position it leaves at is the last one settled for it: a member whose merge or
        // page is not settled yet keeps no newer lag (read again from its last stored one, else
        // from the start)
        let named = p.unsettled_names(l);
        let (was_in, join) = (p.in_stream.remove(l), p.joins.remove(l));
        let listing = matches!(stop, Stop::Listing);
        let lag = match (stop, was_in, join) {
            (Stop::Listing, ..) => None,
            // a position this side reported storing L at (spec/sync.md §10 Lost)
            (Stop::Lost(c), ..) => c,
            _ if named => None,
            (Stop::Here, true, _) => p.settled.clone(),
            (Stop::Here, false, j) => j.flatten(),
        };
        for u in &mut p.unsettled {
            u.owed.retain(|(x, _)| x != l);
            u.passed.retain(|x| x != l);
            u.merged.retain(|x| x != l);
            u.paging.retain(|(x, _)| x != l);
        }
        let Some(id) = p.record else { return Ok(()) };
        self.engine.run(|tx| {
            if listing {
                tx.txn.record_drop(&id, l, changed_at)?;
            } else {
                tx.txn.record_close(&id, l, changed_at, lag)?;
            }
            Ok(())
        })
    }

    /// The connections `l` comes by now: hosts with it open, and readers with it in their shared
    /// set.
    pub(crate) fn sources_of(&self, l: &LabelId) -> Vec<ConnId> {
        let hosts = self.conns.iter().filter(|(_, c)| c.up && c.labels.get(l).is_some_and(|x| x.phase == super::Phase::Open)).map(|(id, _)| *id);
        let readers = self.records.shared.iter().filter(|(_, s)| s.has(l)).map(|(id, _)| *id);
        hosts.chain(readers).collect()
    }

    /// A refused request of this node's answered Error: a Pull is no longer in flight and goes
    /// again after `resync_ms` (`stream_retry`), as a refused Sync would; a fetch is a fetch
    /// answered with nothing. Whether it answered one.
    fn stream_refused(&mut self, conn: ConnId, id: u32, code: osis_proto::Code, out: &mut Vec<Action>) -> Result<bool> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(false) };
        if let Some(f) = p.fetching.remove(&id) {
            self.stream_skipped(conn, f.seq, out)?;
            self.stream_unfetched(conn, f.label, f.ids, out)?;
            return Ok(true);
        }
        let Some(seq) = p.asked.as_ref().filter(|(x, ..)| *x == id).map(|(_, s, _)| *s) else { return Ok(false) };
        self.stream_pull_refused(conn);
        self.diag(format!("pull refused: code {}", code.0));
        self.stream_skipped(conn, seq, out)?;
        Ok(true)
    }

    /// `conn`'s Pull in flight is refused: asked again after `resync_ms` (`stream_retry`).
    fn stream_pull_refused(&mut self, conn: ConnId) {
        let at = self.now().saturating_add(self.cfg.resync_ms);
        if let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) {
            p.asked = None;
            p.caught_up = false;
            p.retry_at = Some(at);
        }
    }

    /// A fetch of `ids` answered with none of them.
    fn stream_unfetched(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<()> {
        let none = ids.into_iter().map(|blob_id| osis_proto::msg::Fetched { blob_id, entry: None }).collect();
        self.stream_fetched(conn, l, none, out)
    }

    /// The request sent `seq`-th on `conn`'s stream was answered. The peer answers them in order
    /// (spec/wire.md §11.2, Pull), so every one sent before it and still unanswered was skipped:
    /// a skipped Fetch is one answered with none of its bodies (the next source is asked), a
    /// skipped Pull one refused.
    fn stream_skipped(&mut self, conn: ConnId, seq: u64, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let fetches: Vec<u32> = p.fetching.iter().filter(|(_, f)| f.seq < seq).map(|(id, _)| *id).collect();
        let pull = p.asked.as_ref().is_some_and(|(_, s, _)| *s < seq);
        let skipped: Vec<(LabelId, Vec<BlobId>)> = fetches.into_iter().filter_map(|id| p.fetching.remove(&id)).map(|f| (f.label, f.ids)).collect();
        if pull {
            self.stream_pull_refused(conn);
            self.diag("pull skipped".to_string());
        }
        for (l, ids) in skipped {
            self.stream_unfetched(conn, l, ids, out)?;
        }
        Ok(())
    }

    /// Asks again the streams whose Pull was answered Error once their time came.
    pub(super) fn stream_retry(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        let due: Vec<ConnId> = self.streams.iter().filter(|(_, s)| s.pulling.retry_at.is_some_and(|t| t <= now)).map(|(c, _)| *c).collect();
        for conn in due {
            if let Some(s) = self.streams.get_mut(&conn) {
                s.pulling.retry_at = None;
            }
            self.stream_ask(conn, true, out)?;
        }
        Ok(())
    }

    /// When a refused Pull goes again (`next_wake`).
    pub(super) fn stream_wake(&self) -> Option<u64> {
        self.streams.values().filter_map(|s| s.pulling.retry_at).min()
    }

    /// Asks every stream fresh: when the replies are in, this node has what its readers had.
    pub(super) fn stream_ask_all(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let conns: Vec<ConnId> = self.streams.keys().copied().collect();
        for conn in conns {
            self.stream_ask(conn, true, out)?;
        }
        Ok(())
    }

    /// Sends a Pull on `conn` unless one is in flight: with joins waiting, a reply that left
    /// more, or `fresh` (a caller that must hear everything the peer holds now).
    /// A Pull whose `inline_limit` is no longer the one due (`stream_inline`) also goes, so the
    /// peer's pushes carry bodies inline only while it is this node's one source.
    pub(super) fn stream_ask(&mut self, conn: ConnId, fresh: bool, out: &mut Vec<Action>) -> Result<()> {
        // no Pull before the two records agree (issues/net-reconnect.md, Agreement)
        if !self.shared_agreed(conn) {
            return Ok(());
        }
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        if p.asked.is_some() || p.retry_at.is_some() || (p.in_stream.is_empty() && p.joins.is_empty()) {
            return Ok(());
        }
        // waiting on bodies: asked once positions settle (`stream_settle`)
        if p.full() {
            p.caught_up &= !fresh;
            return Ok(());
        }
        let inline_limit = self.stream_inline(conn);
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let stale = p.started && p.inline != inline_limit;
        if p.caught_up && p.joins.is_empty() && !fresh && !stale {
            return Ok(());
        }
        p.inline = inline_limit;
        let (id, seq) = p.next();
        let joins: Vec<Join> = p.joins.iter().map(|(l, c)| (*l, c.clone())).collect();
        p.asked = Some((id, seq, joins.iter().map(|(l, _)| *l).collect()));
        let ephemeral = !p.started;
        p.started = true;
        p.pulls += 1;
        let pull = Pull { id, cursor: p.cursor.clone(), joins, inline_limit, max_reply: osis_proto::serving::REPLY_BUDGET as u64, follow: true, ephemeral };
        self.shared_send(conn, Message::Pull(Box::new(pull)), out)
    }

    /// The `inline_limit` due on `conn`'s Pulls: 0 while any member it tracks has another source
    /// here, so a body crosses once in a mesh (announcements only, fetched from one source),
    /// else this node's preference.
    fn stream_inline(&self, conn: ConnId) -> u64 {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return 0 };
        let other = p.in_stream.iter().chain(p.joins.keys()).any(|l| self.sources_of(l).iter().any(|c| *c != conn));
        if other { 0 } else { self.cfg.inline_limit }
    }

    /// `l` gained a source here (`conn`): every other stream tracking it Pulls again if its
    /// pushes still carry bodies inline (`stream_ask`).
    pub(crate) fn stream_source_gained(&mut self, conn: ConnId, l: &LabelId, out: &mut Vec<Action>) -> Result<()> {
        let others: Vec<ConnId> = self.streams.iter().filter(|(c, s)| **c != conn && (s.pulling.in_stream.contains(l) || s.pulling.joins.contains_key(l))).map(|(c, _)| *c).collect();
        for c in others {
            self.stream_ask(c, false, out)?;
        }
        Ok(())
    }

    /// Applies stream events of tracked members, by label in order: the bodies they announced
    /// without bytes that this node wants (owed until held; no entry row is made before its
    /// bytes, so what a source announces costs this node only the stream's memory). A deletion
    /// says the source no longer holds the entry: nothing of it is owed on this stream.
    fn stream_apply(&mut self, conn: ConnId, events: Vec<(LabelId, Event)>, out: &mut Vec<Action>) -> Result<BTreeSet<(LabelId, BlobId)>> {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(BTreeSet::new()) };
        let mut by_label: BTreeMap<LabelId, Vec<Event>> = BTreeMap::new();
        for (l, e) in events {
            if p.in_stream.contains(&l) || p.joins.contains_key(&l) {
                by_label.entry(l).or_default().push(e);
            }
        }
        let (mut owed, mut gone) = (BTreeSet::new(), BTreeSet::new());
        for (l, evs) in by_label {
            let announced: Vec<BlobId> = evs.iter().filter_map(|e| if let Event::Added { blob_id, blob: None, .. } = e { Some(*blob_id) } else { None }).collect();
            gone.extend(evs.iter().filter_map(|e| if let Event::Deleted(b) = e { Some((l, *b)) } else { None }));
            self.received_from(conn, l);
            self.reader_events(conn, l, evs, out)?;
            for b in announced {
                if self.wants(&l, &b) {
                    owed.insert((l, b));
                }
            }
        }
        self.stream_unowe(conn, &gone);
        Ok(owed)
    }

    /// Whether this node wants the bytes of entry `b` of `l`: not held, not removed here within
    /// its tombstone, not refused by the ephemeral cap (which waits for room, not for a fetch).
    fn wants(&mut self, l: &LabelId, b: &BlobId) -> bool {
        !self.engine.has_blob(b) && !self.memory_skips(l, b)
    }

    /// `conn`'s source no longer holds these entries: they are owed on its stream no more.
    fn stream_unowe(&mut self, conn: ConnId, gone: &BTreeSet<(LabelId, BlobId)>) {
        if gone.is_empty() {
            return;
        }
        if let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) {
            for u in &mut p.unsettled {
                u.owed.retain(|x| !gone.contains(x));
            }
        }
    }

    /// The stream on `conn` reached position `u`: settled now if it owes nothing.
    fn stream_reached(&mut self, conn: ConnId, u: Unsettled, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        p.unsettled.push_back(u);
        self.stream_settle(conn, out)
    }

    /// Settles `conn`'s positions in order while every body they owe is held here (or no longer
    /// wanted, `wants`): the last one settled is stored with the members it covers, reported if
    /// one of them asked, and is a pass end for the members read to the peer's end. So a
    /// position, an Applied and a caught-up source never cover a body this node lacks. A stream
    /// that waited (`Pulling::full`) asks again.
    fn stream_settle(&mut self, conn: ConnId, out: &mut Vec<Action>) -> Result<()> {
        let mut done: Option<Unsettled> = None;
        let mut report = None;
        while let Some(owed) = self.streams.get(&conn).and_then(|s| s.pulling.unsettled.front()).map(|u| u.owed.clone()) {
            let left: BTreeSet<(LabelId, BlobId)> = owed.into_iter().filter(|(l, b)| self.wants(l, b)).collect();
            let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { break };
            let Some(front) = p.unsettled.front_mut() else { break };
            if !left.is_empty() {
                front.owed = left;
                break;
            }
            let Some(u) = p.unsettled.pop_front() else { break };
            if u.report {
                report = u.cursor.clone();
            }
            done = Some(match done {
                None => u,
                Some(mut d) => {
                    d.cursor = u.cursor;
                    d.merged.extend(u.merged);
                    d.paging.extend(u.paging);
                    d.passed.extend(u.passed);
                    d
                }
            });
        }
        let Some(d) = done else { return Ok(()) };
        if let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) {
            p.settled = d.cursor.clone();
        }
        self.stream_store(conn, d.cursor, &d.merged, &d.paging)?;
        if let Some(c) = report {
            self.shared_send(conn, Message::Applied { cursor: c }, out)?;
        }
        let passed: BTreeSet<LabelId> = d.passed.into_iter().collect();
        for l in passed {
            self.source_passed(conn, l)?;
        }
        self.stream_ask(conn, false, out)
    }

    /// At the end of each step: every stream's positions settle as far as the bodies held now
    /// allow, and each body a stream owes that is held nowhere and asked nowhere is fetched from
    /// the first stream owing it (a fetch lost with its connection, or answered without it).
    pub(super) fn stream_settle_all(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let waiting: Vec<ConnId> = self.streams.iter().filter(|(_, s)| !s.pulling.unsettled.is_empty()).map(|(c, _)| *c).collect();
        for conn in waiting {
            self.stream_settle(conn, out)?;
            let owed: BTreeSet<(LabelId, BlobId)> = self.streams.get(&conn).map(|s| s.pulling.unsettled.iter().flat_map(|u| u.owed.iter().copied()).collect()).unwrap_or_default();
            let mut ask: BTreeMap<LabelId, Vec<BlobId>> = BTreeMap::new();
            for (l, b) in owed {
                if self.wants(&l, &b) && self.may_ask(conn, l, &b) {
                    ask.entry(l).or_default().push(b);
                }
            }
            for (l, ids) in ask {
                self.stream_fetch(conn, l, ids, None, out)?;
            }
        }
        Ok(())
    }

    /// Stores the stream's position `cursor`, and the members it covers, once what it covers is
    /// applied (`stream_settle`).
    fn stream_store(&mut self, conn: ConnId, cursor: Option<Vec<u8>>, merged: &[LabelId], paging: &[(LabelId, Vec<u8>)]) -> Result<()> {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        let Some(id) = p.record else { return Ok(()) };
        self.state.flush(&mut self.engine)?;
        self.engine.run(|tx| {
            tx.txn.record_set_cursor(&id, cursor)?;
            for l in merged {
                tx.txn.record_member_at(&id, *l, At::Stream)?;
            }
            for (l, c) in paging {
                tx.txn.record_member_at(&id, *l, At::Join(Some(c.clone())))?;
            }
            Ok(())
        })
    }

    fn stream_reply(&mut self, conn: ConnId, r: PullReply, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let Some((id, seq, sent)) = p.asked.take() else { return Ok(()) };
        if id != r.id {
            p.asked = Some((id, seq, sent));
            return Ok(());
        }
        // the reply reads from the cursor: pushes go on from its end
        p.dropped = false;
        self.stream_skipped(conn, seq, out)?;
        let owed = self.stream_apply(conn, r.events, out)?;
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let left: BTreeMap<LabelId, Option<Vec<u8>>> = r.joins.into_iter().collect();
        let (mut merged, mut paging) = (Vec::new(), Vec::new());
        for l in sent {
            if !p.joins.contains_key(&l) {
                continue;
            }
            match left.get(&l) {
                Some(Some(c)) if !r.whole => {
                    p.joins.insert(l, Some(c.clone()));
                    paging.push((l, c.clone()));
                }
                // not shared there: its `Lost` is on its way
                Some(None) => {
                    p.joins.remove(&l);
                }
                _ => {
                    p.joins.remove(&l);
                    p.in_stream.insert(l);
                    merged.push(l);
                }
            }
        }
        if r.whole {
            merged.extend(p.in_stream.iter().copied());
        }
        p.cursor = r.cursor.clone();
        let done = !r.more && p.joins.is_empty();
        p.caught_up = done;
        // the peer's log was read to its end: a pass end there for each member, once settled
        let passed: Vec<LabelId> = if done { p.in_stream.iter().copied().collect() } else { Vec::new() };
        self.stream_reached(conn, Unsettled { cursor: r.cursor, owed, merged, paging, report: r.report, passed }, out)?;
        self.stream_ask(conn, false, out)
    }

    fn stream_pushed(&mut self, conn: ConnId, s: Stream, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let Some(c) = s.cursor else {
            // what no position names: relay-only entries, which carry their bytes (an
            // announcement without them owes nothing)
            let events = s.events.into_iter().filter(|(_, e)| !matches!(e, Event::Added { blob: None, .. })).collect();
            self.stream_apply(conn, events, out)?;
            return Ok(());
        };
        // flow control: a push is not taken while the stream waits on bodies, nor after one was
        // not until a reply reads from the cursor again (pushes follow on from each other)
        if p.dropped || p.full() {
            p.dropped = true;
            p.caught_up = false;
            return self.stream_ask(conn, false, out);
        }
        let owed = self.stream_apply(conn, s.events, out)?;
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        p.cursor = Some(c.clone());
        // a push to a stream read to its end moves it to the server's newer end: a pass end there
        // for each member, as a host's push is (`log_events_from`)
        let passed: Vec<LabelId> = if p.caught_up && p.asked.is_none() { p.in_stream.iter().copied().collect() } else { Vec::new() };
        self.stream_reached(conn, Unsettled { cursor: Some(c), owed, merged: Vec::new(), paging: Vec::new(), report: s.report, passed }, out)
    }

    /// A relay-only entry to each reader sharing `l` but `except` (its source) and a member being
    /// ended (`until`): a Stream with no cursor, as no position names it (spec/sync.md §9).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stream_relay(&mut self, except: Option<ConnId>, l: LabelId, blob_id: BlobId, blob: &[u8], wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<osis_crypto::Signature>, out: &mut Vec<Action>) -> Result<()> {
        let to: Vec<ConnId> = self.records.shared.iter().filter(|(c, s)| Some(**c) != except && s.live(&l)).map(|(c, _)| *c).collect();
        for c in to {
            let ev = Event::Added { blob_id, blob: Some(blob.to_vec()), wrap, stamp };
            self.shared_send(c, Message::Stream(Box::new(Stream { events: vec![(l, ev)], cursor: None, report: false })), out)?;
        }
        Ok(())
    }

    // ---- bodies ----

    /// When `b` was asked of readers, by Fetches not answered yet (`asked`).
    pub(crate) fn stream_asks<'a>(&'a self, b: &'a BlobId) -> impl Iterator<Item = u64> + 'a {
        self.streams.values().flat_map(|s| s.pulling.fetching.values()).filter(|f| f.ids.contains(b)).map(|f| f.at)
    }

    /// Whether `b` is asked of `conn`'s reader by a Fetch not answered yet.
    pub(crate) fn stream_asks_on(&self, conn: ConnId, b: &BlobId) -> bool {
        self.streams.get(&conn).is_some_and(|s| s.pulling.fetching.values().any(|f| f.ids.contains(b)))
    }

    /// Fetches the bodies `ids` of member `l` from `conn`'s peer, but those asked for already
    /// (`may_ask`): one source at a time per blob, a second only once the first is slower than
    /// the stall time. As any Fetch (spec/wire.md §11.3): `FIRST_REPLY` per ID, or
    /// `REPLY_BUDGET` for the rest of an answered one (`again`: when that one was asked, which the
    /// rest keeps, so answering one body at a time does not hold the others longer).
    pub(crate) fn stream_fetch(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, again: Option<u64>, out: &mut Vec<Action>) -> Result<()> {
        let now = self.now();
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| self.may_ask(conn, l, b)).collect();
        if ids.is_empty() {
            return Ok(());
        }
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let budget = osis_proto::serving::REPLY_BUDGET;
        let mut msgs = Vec::new();
        for batch in ids.chunks(osis_proto::msg::MAX_ITEMS) {
            let (id, seq) = p.next();
            let max_reply = if again.is_some() { budget } else { osis_proto::client::FIRST_REPLY.saturating_mul(batch.len()).min(budget) } as u64;
            p.fetching.insert(id, Fetching { seq, label: l, ids: batch.to_vec(), max_reply, at: again.unwrap_or(now) });
            msgs.push(Message::Fetch { id, label: l, max_reply, ids: batch.to_vec() });
        }
        for m in msgs {
            self.shared_send(conn, m, out)?;
        }
        Ok(())
    }

    /// Answers a reader's Fetch from what this node holds of a member of the connection's
    /// shared set, in order within `max_reply`: what does not fit is left out (asked again; under
    /// `REPLY_BUDGET` any blob fits), what is not held is answered with nothing, and so is an
    /// entry of a member being ended first logged past its `until`.
    fn stream_serve_fetch(&mut self, conn: ConnId, id: u32, l: LabelId, max_reply: u64, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<()> {
        let member = self.records.shared.get(&conn).is_some_and(|s| s.has(&l));
        let until = self.shared_untils(conn).get(&l).copied();
        let mut budget = osis_proto::serving::reply_bound(max_reply);
        let mut items = Vec::new();
        for b in ids {
            let shown = match until {
                Some(u) => self.engine.run(|tx| Ok(tx.txn.log_entry_first(&l, &b)?))?.is_some_and(|p| p <= u),
                None => true,
            };
            let held = if member && shown { self.state.entries.get(&(l, b)).map(|e| (e.wrap, e.stamp)) } else { None };
            let entry = match held {
                Some((wrap, stamp)) => self.engine.blob(&b)?.map(|x| (x, wrap, stamp)),
                None => None,
            };
            let n = entry.as_ref().map_or(40, |(x, ..)| x.len().saturating_add(200));
            if n > budget {
                break;
            }
            budget = budget.saturating_sub(n);
            items.push(osis_proto::msg::Fetched { blob_id: b, entry });
        }
        self.shared_send(conn, Message::FetchReply { id, items }, out)
    }

    /// A reader answered a fetch: what it delivered is applied as its events are; what it did
    /// not is asked of the next source of `l` (by connection order), else waits for an
    /// announcement; what did not fit is asked again here under `REPLY_BUDGET`, where any blob
    /// fits (none fitting there: answered with none).
    fn stream_fetch_reply(&mut self, conn: ConnId, id: u32, items: Vec<osis_proto::msg::Fetched>, out: &mut Vec<Action>) -> Result<()> {
        let Some(f) = self.streams.get_mut(&conn).and_then(|s| s.pulling.fetching.remove(&id)) else { return Ok(()) };
        self.stream_skipped(conn, f.seq, out)?;
        let l = f.label;
        let answered: BTreeSet<BlobId> = items.iter().map(|f| f.blob_id).collect();
        let none = items.is_empty();
        self.stream_fetched(conn, l, items, out)?;
        let rest: Vec<BlobId> = f.ids.into_iter().filter(|b| !answered.contains(b)).collect();
        if rest.is_empty() {
            Ok(())
        } else if none && f.max_reply >= osis_proto::serving::REPLY_BUDGET as u64 {
            self.stream_unfetched(conn, l, rest, out)
        } else {
            self.stream_fetch(conn, l, rest, Some(f.at), out)
        }
    }

    fn stream_fetched(&mut self, conn: ConnId, l: LabelId, items: Vec<osis_proto::msg::Fetched>, out: &mut Vec<Action>) -> Result<()> {
        let mut evs = Vec::new();
        let mut failed = Vec::new();
        for f in items {
            match f.entry {
                Some((blob, wrap, stamp)) if osis_label::blob_id(&blob) == f.blob_id => evs.push(Event::Added { blob_id: f.blob_id, blob: Some(blob), wrap, stamp }),
                _ => failed.push(f.blob_id),
            }
        }
        if !evs.is_empty() && self.records.shared.get(&conn).is_some_and(|s| s.has(&l)) {
            let delivered: Vec<BlobId> = evs.iter().filter_map(|e| if let Event::Added { blob_id, .. } = e { Some(*blob_id) } else { None }).collect();
            self.reader_events(conn, l, evs, out)?;
            // bytes served and not kept (a relay-only blob, one past a budget): the source gave
            // what it holds, so nothing of them is owed on its stream (else asked every step)
            let unkept: BTreeSet<(LabelId, BlobId)> = delivered.into_iter().filter(|b| self.wants(&l, b)).map(|b| (l, b)).collect();
            self.stream_unowe(conn, &unkept);
        }
        if failed.is_empty() {
            return Ok(());
        }
        // the source does not hold them: nothing of them is owed on its own stream
        let gone: BTreeSet<(LabelId, BlobId)> = failed.iter().map(|b| (l, *b)).collect();
        self.stream_unowe(conn, &gone);
        let next = self.records.shared.iter().find(|(c, s)| **c > conn && s.has(&l)).map(|(c, _)| *c);
        match next {
            Some(c) => self.stream_fetch(c, l, failed, None, out),
            None => Ok(()),
        }
    }

    /// Pulls sent on `conn` so far (tests count them).
    pub fn stream_pulls(&self, conn: ConnId) -> u64 {
        self.streams.get(&conn).map_or(0, |s| s.pulling.pulls)
    }

    /// What `conn`'s stream keeps waiting: positions not settled, and the bodies they owe (tests).
    pub fn stream_waiting(&self, conn: ConnId) -> (usize, usize) {
        self.streams.get(&conn).map_or((0, 0), |s| (s.pulling.unsettled.len(), s.pulling.unsettled.iter().map(|u| u.owed.len()).sum()))
    }

    /// `conn`'s stream position in the peer's log (tests).
    pub fn stream_cursor(&self, conn: ConnId) -> Option<Vec<u8>> {
        self.streams.get(&conn).and_then(|s| s.pulling.cursor.clone())
    }

    /// Whether `conn`'s stream read the peer's log to its end with nothing waiting (tests).
    pub fn stream_caught_up(&self, conn: ConnId) -> bool {
        self.streams.get(&conn).is_some_and(|s| s.pulling.caught_up && s.pulling.unsettled.is_empty())
    }

    /// Whether `conn`'s reader is caught up on member `l` both ways (`label_status`'s idle
    /// source): this node applied the reader's stream of `l` to its end with no body asked
    /// there, and the reader joined `l`, was served this node's log to its end and reported
    /// applying every message carrying events of `l`.
    pub(crate) fn stream_idle(&self, conn: ConnId, l: &LabelId) -> bool {
        self.streams.get(&conn).is_some_and(|s| {
            let pulled = s.pulling.caught_up && s.pulling.in_stream.contains(l) && s.pulling.fetching.is_empty() && s.pulling.unsettled.is_empty();
            let v = &s.serving;
            let served = v.follow.is_some() && v.at_end && v.pulled.contains(l) && !v.unreported.iter().any(|x| x.labels.contains(l));
            pulled && served
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/sync.md §10 (Reports): a message bringing an ended member the requester tracks to its
    // `until` asks a report, events or none, unless one awaited covers it or the requester
    // already reported a position past it; a member it does not track is not reported for
    #[test]
    fn a_message_reaching_until_asks_its_report_once() {
        let l = LabelId([1; 16]);
        let untils: BTreeMap<LabelId, u64> = [(l, 10)].into();
        let mut s = Serving::default();
        assert!(!s.until_due(1, 12, &[], &untils), "not tracked: no end");
        s.pulled.insert(l);
        assert!(!s.until_due(1, 9, &[], &untils), "short of until");
        assert!(!s.until_due(1, 12, &[(l, 8)], &untils), "a join in pages is at its own position");
        assert!(s.until_due(1, 12, &[], &untils));
        assert!(s.sent(&Some(vec![1]), BTreeSet::new(), 12, &[], Vec::new(), &untils), "asked with no events");
        assert!(!s.until_due(2, 13, &[], &untils), "one awaited covers it");
        s.reported(&[1]);
        assert_eq!(s.position(&l), Some(12));
        assert!(!s.until_due(2, 14, &[], &untils), "reported past it");
        assert!(!s.sent(&Some(vec![2]), BTreeSet::new(), 14, &[], Vec::new(), &untils), "nothing to ask");
    }

    // spec/sync.md §10 (Reports): what the requester reported storing, per member: the first
    // Pull's cursor and a join's first position; a later Pull's cursor reports nothing (it may
    // name what is not stored yet); a join is at its own position until the message merging it
    // is reported, a page it reached once that page is
    #[test]
    fn a_member_is_where_the_requester_reported_storing_it() {
        let (l, j) = (LabelId([1; 16]), LabelId([2; 16]));
        let none = BTreeMap::new();
        let mut s = Serving::default();
        s.pulled.insert(l);
        s.pull_reports(Some(5), &[]);
        assert_eq!(s.position(&l), Some(5), "the first Pull's cursor");
        s.pull_reports(Some(9), &[]);
        assert_eq!(s.position(&l), Some(5), "a later Pull's is not stored yet");
        s.pulled.insert(j);
        s.pull_reports(Some(9), &[(j, Some(2))]);
        assert_eq!(s.position(&j), Some(2), "a join where its first Pull puts it");
        assert!(s.sent(&Some(vec![1]), [l, j].into(), 12, &[], vec![(j, 7)], &none));
        s.pull_reports(Some(12), &[(j, Some(7))]);
        assert_eq!(s.position(&j), Some(2), "a page reached is not stored yet");
        assert!(s.sent(&Some(vec![2]), [l, j].into(), 14, &[j], Vec::new(), &none), "merging j");
        s.reported(&[1]);
        assert_eq!((s.position(&l), s.position(&j)), (Some(12), Some(7)), "the page, once reported");
        s.reported(&[2]);
        assert_eq!((s.position(&l), s.position(&j)), (Some(14), Some(14)), "merged, once reported");
    }
}
