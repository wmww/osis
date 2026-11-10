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
//!   one leaving keeps its position as a lag. A connection's start stops every member of the
//!   record at the position it holds (`record_stop_all`), so one this connection does not open
//!   claims nothing past what it applied.
//! - A cursor is stored only after what it covers is applied (state flushed first); a member
//!   leaves the stream when it leaves S here, before any later message is applied.
//! - Within a connection a requester joins L only after the server opened it: the side answering
//!   an Offer opens and joins after sending its answer, the tester on reading it; and the
//!   server's `Lost` follows every event it sent for L. So the server's S covers the requester's
//!   tracked members wherever the stream moves them.
//!
//! Checked by the randomized differentials `stream_differential_no_write_dropped_spec_sync_10`
//! and `stream_differential_paged_spec_sync_10` (core/node/tests/it/stream.rs).
//!
//! Both sides of a connection pull and serve: a member of S is pulled by the side it is open at,
//! whoever dialed. Bodies announced without bytes are fetched from one reader at a time
//! (`stream_fetch`, by ids in the node's range). Memory entries are the log's memory part
//! (`MemLog`), which no cursor names: the first Pull of a connection, and every join, list the
//! memory events of what they start; later ones follow in counter order on that connection,
//! paged by the same budget as the durable part. Relay-only entries go as a Stream with no
//! cursor (`stream_relay`): no position names them.

use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{BlobId, LabelId};
use osis_proto::msg::{Join, Pull, PullReply, Stream};
use osis_proto::{Event, Message};
use osis_store::{LoggedEvent, NodeEvent, RecordId};
use std::collections::{BTreeMap, BTreeSet};

/// Log rows one reply or push scans at most, matching or not. Resource bound: 0 never moves
/// (no reply could end), infinity lets one request read the whole log in one go.
const SCAN_ROWS: usize = 1 << 16;
/// Rows read from the store at a time while scanning.
const READ_PAGE: usize = 1024;
/// Ids this module draws for its Pulls: the shared set's range (top bit) with the next bit, so
/// they never meet a session's own or the shared set's.
const ID_BASE: u32 = osis_proto::msg::NODE_IDS | (1 << 30);

/// The node log's memory part: one latest event per memory entry, ordered by an in-memory
/// counter, a deletion kept `MAX_DRIFT_MS` (a memory entry's tombstone). Bounded by the live
/// memory entries plus recent deletions; nothing of it outlives the process.
#[derive(Default)]
pub(crate) struct MemLog {
    seq: u64,
    /// By counter: entry, added (else deleted), when (corrected wall ms).
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
#[derive(Default)]
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
    /// Members the requester joined on this connection (a Pull's `join` this node shares).
    pulled: BTreeSet<LabelId>,
    /// Replies and pushes asked to report and not reported yet, in order: their cursor and
    /// the members they carried events of. At most `MAX_UNREPORTED`: past it the oldest two
    /// merge, their members waiting for the later cursor.
    unreported: std::collections::VecDeque<(Vec<u8>, BTreeSet<LabelId>)>,
}

const MAX_CROSSED: usize = 1 << 14;
/// Unreported messages kept apart (`Serving::unreported`). Any value from 1 is correct: fewer
/// only make a member wait for a later report; it bounds what a requester that never reports
/// makes this node keep.
const MAX_UNREPORTED: usize = 16;

impl Serving {
    /// A reply or push with events of `labels` went with `cursor`, asking for its report.
    fn sent(&mut self, cursor: &Option<Vec<u8>>, labels: BTreeSet<LabelId>) -> bool {
        let Some(c) = cursor else { return false };
        if labels.is_empty() {
            return false;
        }
        self.unreported.push_back((c.clone(), labels));
        if self.unreported.len() > MAX_UNREPORTED
            && let Some((_, first)) = self.unreported.pop_front()
            && let Some((_, next)) = self.unreported.front_mut()
        {
            next.extend(first);
        }
        true
    }

    /// The requester reported applying what `cursor` covers: that message and every one
    /// before it are applied (a requester applies in order).
    fn reported(&mut self, cursor: &[u8]) {
        if let Some(i) = self.unreported.iter().position(|(c, _)| c == cursor) {
            self.unreported.drain(..=i);
        }
    }
}

/// The requesting side of one connection's stream.
#[derive(Default)]
pub(crate) struct Pulling {
    /// The stream's position in the peer's log.
    cursor: Option<Vec<u8>>,
    /// Members whose events up to `cursor` are applied here.
    in_stream: BTreeSet<LabelId>,
    /// Members entering the stream, each from its own position (none: the start).
    joins: BTreeMap<LabelId, Option<Vec<u8>>>,
    /// The Pull in flight: its id and the joins it named.
    asked: Option<(u32, Vec<LabelId>)>,
    /// Fetches in flight, by id: the member and the blobs asked.
    fetching: BTreeMap<u32, (LabelId, Vec<BlobId>)>,
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
    /// The last Pull was answered Error: asked again at this time (raw ms), `resync_ms` after.
    retry_at: Option<u64>,
}

impl Pulling {
    fn next(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        ID_BASE | (self.next_id & ((1 << 30) - 1))
    }
}

/// One connection's stream, either side.
#[derive(Default)]
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
/// `SCAN_ROWS` rows.
fn scan(tx: &mut osis_store::Transaction<'_>, from: u64, starts: &BTreeMap<LabelId, u64>) -> std::result::Result<Scan, osis_store::Error> {
    let log_end = tx.log_end()?;
    let (mut pos, mut rows, mut events) = (from, 0usize, Vec::new());
    loop {
        let (page, at, more) = tx.log_after(pos, READ_PAGE.min(SCAN_ROWS - rows))?;
        rows += page.len();
        for e in page {
            let l = match e.event {
                NodeEvent::Added(l, _) | NodeEvent::Deleted { label: l, .. } | NodeEvent::Head(l) => l,
            };
            if starts.get(&l).is_some_and(|s| e.pos > *s) {
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
                Ok(())
            }
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
    /// and by the bytes held.
    fn stream_serve(&mut self, conn: ConnId, p: Pull, out: &mut Vec<Action>) -> Result<()> {
        // a connection with no shared set serves no stream (spec/sync.md §10)
        if !self.records.shared.contains_key(&conn) {
            return self.shared_send(conn, Message::Error { id: p.id, code: osis_proto::Code::NOT_ADMITTED }, out);
        }
        let members = self.stream_members(conn);
        let _ = self.served_labels();
        self.state.flush(&mut self.engine)?;
        {
            let s = &mut self.streams.entry(conn).or_default().serving;
            s.inline_limit = p.inline_limit;
            s.follow = None;
        }
        let first = p.ephemeral;
        let (base, whole, joined, refused, scan) = self.engine.run(|tx| {
            let base = match &p.cursor {
                Some(c) => tx.txn.log_position(c)?,
                None => None,
            };
            // a cursor naming no position, the stream's or a join's: the stream from the start
            // (else a join read from the start would not be known as a listing there)
            let mut whole = base.is_none();
            let (mut joined, mut refused) = (Vec::new(), Vec::new());
            for (l, c) in &p.joins {
                if !members.contains(l) {
                    refused.push(*l);
                    continue;
                }
                let at = match c {
                    Some(c) => tx.txn.log_position(c)?,
                    None => Some(0),
                };
                whole |= at.is_none();
                joined.push((*l, at.unwrap_or(0)));
            }
            if whole {
                joined.clear();
            }
            let base = base.filter(|_| !whole).unwrap_or(0);
            let mut starts: BTreeMap<LabelId, u64> = members.iter().map(|l| (*l, base)).collect();
            starts.extend(joined.iter().copied());
            let from = starts.values().copied().min().unwrap_or(base);
            let scan = scan(&mut tx.txn, from, &starts)?;
            Ok((base, whole, joined, refused, scan))
        })?;
        let mut budget = usize::try_from(p.max_reply).unwrap_or(usize::MAX).saturating_sub(256);
        // the memory part first: a cursor names no memory event, so each member entering the
        // stream gets its live entries listed; then what followed for the rest
        let listed: BTreeSet<LabelId> = if whole || first { members.clone() } else { joined.iter().map(|(l, ..)| *l).collect() };
        let (mut events, memory_cut) = self.stream_memory(conn, &listed, &members, &mut budget)?;
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
        let report = s.sent(&cursor, labels);
        let reply = PullReply { id: p.id, events, cursor, whole, more, report, joins };
        self.shared_send(conn, Message::PullReply(Box::new(reply)), out)
    }

    /// Pushes what the log gained to each connection following its stream, at most one page
    /// each per step (the next goes at the next step).
    pub(super) fn stream_push(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let following: Vec<(ConnId, u64, u64)> = self.streams.iter().filter_map(|(c, s)| s.serving.follow.map(|f| (*c, f, s.serving.mem_seq))).collect();
        if following.is_empty() {
            return Ok(());
        }
        let _ = self.served_labels();
        self.state.flush(&mut self.engine)?;
        let log_end = self.engine.run(|tx| Ok(tx.txn.log_end()?))?;
        let mem_seq = self.state.mem_log.seq();
        for (conn, at, seen) in following {
            if at >= log_end && seen >= mem_seq {
                continue;
            }
            let members = self.stream_members(conn);
            let starts: BTreeMap<LabelId, u64> = members.iter().map(|l| (*l, at)).collect();
            let scan = self.engine.run(|tx| Ok(scan(&mut tx.txn, at, &starts)?))?;
            let mut budget = osis_proto::serving::REPLY_BUDGET - 256;
            let (mut events, memory_cut) = self.stream_memory(conn, &BTreeSet::new(), &members, &mut budget)?;
            let (durable, cut) = self.stream_events(conn, &scan.events, &mut budget, events.is_empty())?;
            events.extend(durable);
            let end = cut.unwrap_or(scan.end);
            if let Some(s) = self.streams.get_mut(&conn) {
                s.serving.follow = Some(end);
                s.serving.at_end = end >= log_end && !memory_cut;
            }
            if events.is_empty() {
                continue;
            }
            let cursor = self.engine.run(|tx| Ok(tx.txn.log_cursor(end)?))?;
            let labels: BTreeSet<LabelId> = events.iter().map(|(l, _)| *l).collect();
            let report = self.streams.get_mut(&conn).is_some_and(|s| s.serving.sent(&cursor, labels));
            self.shared_send(conn, Message::Stream(Box::new(Stream { events, cursor, report })), out)?;
        }
        Ok(())
    }

    // ---- the requesting side ----

    /// `conn` took record `id`: every member it held leaves the stream at its position, kept as
    /// a lag for its rejoin, and the stream goes on from the record's cursor.
    pub(super) fn stream_bind(&mut self, conn: ConnId, id: RecordId) -> Result<()> {
        let cursor = self.engine.run(|tx| {
            tx.txn.record_stop_all(&id)?;
            Ok(tx.txn.record(&id)?.and_then(|r| r.cursor))
        })?;
        let p = &mut self.streams.entry(conn).or_default().pulling;
        p.record = Some(id);
        p.cursor = cursor;
        Ok(())
    }

    /// Member `l` opened in `conn`'s shared set here: it joins the stream, from its lag or the
    /// start.
    pub(super) fn stream_join(&mut self, conn: ConnId, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        let tracked = self.streams.get(&conn).is_some_and(|s| s.pulling.in_stream.contains(&l) || s.pulling.joins.contains_key(&l));
        if tracked {
            return Ok(());
        }
        let record = self.streams.get(&conn).and_then(|s| s.pulling.record);
        let lag = match record {
            Some(id) => self.engine.run(|tx| Ok(tx.txn.record_take_lag(&id, &l)?))?,
            None => None,
        };
        let p = &mut self.streams.entry(conn).or_default().pulling;
        p.joins.insert(l, lag);
        p.caught_up = false;
        self.stream_ask(conn, false, out)
    }

    /// Member `l` left `conn`'s shared set here: nothing more of it is applied or served, and its
    /// position is kept as a lag for a rejoin.
    pub(super) fn stream_leave(&mut self, conn: ConnId, l: &LabelId) -> Result<()> {
        let Some(s) = self.streams.get_mut(&conn) else { return Ok(()) };
        s.serving.pulled.remove(l);
        let p = &mut s.pulling;
        let stop = if p.in_stream.remove(l) { p.cursor.clone() } else { p.joins.remove(l).flatten() };
        if let Some(id) = p.record {
            self.engine.run(|tx| Ok(tx.txn.record_stop(&id, l, stop)?))?;
        }
        Ok(())
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
        let at = self.raw_now().saturating_add(self.cfg.resync_ms);
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(false) };
        if let Some((l, ids)) = p.fetching.remove(&id) {
            let none = ids.into_iter().map(|blob_id| osis_proto::msg::Fetched { blob_id, entry: None }).collect();
            self.stream_fetched(conn, l, none, out)?;
            return Ok(true);
        }
        if p.asked.as_ref().is_none_or(|(x, _)| *x != id) {
            return Ok(false);
        }
        p.asked = None;
        p.caught_up = false;
        p.retry_at = Some(at);
        self.diag(format!("pull refused: code {}", code.0));
        Ok(true)
    }

    /// Asks again the streams whose Pull was answered Error once their time came.
    pub(super) fn stream_retry(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let now = self.raw_now();
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
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        if p.asked.is_some() || p.retry_at.is_some() || (p.in_stream.is_empty() && p.joins.is_empty()) {
            return Ok(());
        }
        let inline_limit = self.stream_inline(conn);
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let stale = p.started && p.inline != inline_limit;
        if p.caught_up && p.joins.is_empty() && !fresh && !stale {
            return Ok(());
        }
        p.inline = inline_limit;
        let id = p.next();
        let joins: Vec<Join> = p.joins.iter().map(|(l, c)| (*l, c.clone())).collect();
        p.asked = Some((id, joins.iter().map(|(l, _)| *l).collect()));
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

    /// Applies stream events of tracked members, by label in order.
    fn stream_apply(&mut self, conn: ConnId, events: Vec<(LabelId, Event)>, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        let mut by_label: BTreeMap<LabelId, Vec<Event>> = BTreeMap::new();
        for (l, e) in events {
            if p.in_stream.contains(&l) || p.joins.contains_key(&l) {
                by_label.entry(l).or_default().push(e);
            }
        }
        for (l, evs) in by_label {
            self.received_from(conn, l);
            self.reader_events(conn, l, evs, out)?;
        }
        Ok(())
    }

    /// Stores the stream's position, and the members it covers, once what it covers is applied.
    fn stream_store(&mut self, conn: ConnId, merged: &[LabelId], paging: &[(LabelId, Vec<u8>)]) -> Result<()> {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        let Some(id) = p.record else { return Ok(()) };
        let cursor = p.cursor.clone();
        self.state.flush(&mut self.engine)?;
        self.engine.run(|tx| {
            tx.txn.record_set_cursor(&id, cursor)?;
            for l in merged {
                tx.txn.record_open(&id, *l, &osis_store::Member { proved: (0, 0), until: None, lag: None })?;
            }
            for (l, c) in paging {
                tx.txn.record_open(&id, *l, &osis_store::Member { proved: (0, 0), until: None, lag: Some(c.clone()) })?;
            }
            Ok(())
        })
    }

    fn stream_reply(&mut self, conn: ConnId, r: PullReply, out: &mut Vec<Action>) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let Some((id, sent)) = p.asked.take() else { return Ok(()) };
        if id != r.id {
            p.asked = Some((id, sent));
            return Ok(());
        }
        self.stream_apply(conn, r.events, out)?;
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
        let caught: Vec<LabelId> = if done { p.in_stream.iter().copied().collect() } else { Vec::new() };
        self.stream_store(conn, &merged, &paging)?;
        if r.report
            && let Some(c) = r.cursor
        {
            self.shared_send(conn, Message::Applied { cursor: c }, out)?;
        }
        if done {
            // the peer's log was read to its end: a pass end there for each member
            for l in caught {
                self.source_passed(conn, l)?;
            }
        }
        self.stream_ask(conn, false, out)
    }

    fn stream_pushed(&mut self, conn: ConnId, s: Stream, out: &mut Vec<Action>) -> Result<()> {
        if !self.streams.contains_key(&conn) {
            return Ok(());
        }
        self.stream_apply(conn, s.events, out)?;
        // a push with no cursor carries what no position names (a relay-only entry)
        let Some(c) = s.cursor else { return Ok(()) };
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        p.cursor = Some(c.clone());
        // a push to a stream read to its end moves it to the server's newer end: a pass end there
        // for each member, as a host's push is (`log_events_from`)
        let caught: Vec<LabelId> = if p.caught_up && p.asked.is_none() { p.in_stream.iter().copied().collect() } else { Vec::new() };
        self.stream_store(conn, &[], &[])?;
        if s.report {
            self.shared_send(conn, Message::Applied { cursor: c }, out)?;
        }
        for l in caught {
            self.source_passed(conn, l)?;
        }
        Ok(())
    }

    /// A relay-only entry to each reader sharing `l` but `except` (its source): a Stream with
    /// no cursor, as no position names it (spec/sync.md §9).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stream_relay(&mut self, except: Option<ConnId>, l: LabelId, blob_id: BlobId, blob: &[u8], wrap: [u8; osis_crypto::WRAP_LEN], stamp: Option<osis_crypto::Signature>, out: &mut Vec<Action>) -> Result<()> {
        let to: Vec<ConnId> = self.records.shared.iter().filter(|(c, s)| Some(**c) != except && s.has(&l)).map(|(c, _)| *c).collect();
        for c in to {
            let ev = Event::Added { blob_id, blob: Some(blob.to_vec()), wrap, stamp };
            self.shared_send(c, Message::Stream(Box::new(Stream { events: vec![(l, ev)], cursor: None, report: false })), out)?;
        }
        Ok(())
    }

    // ---- bodies ----

    /// Whether blob `b` is asked of a reader and not received yet.
    pub(crate) fn stream_fetching(&self, b: &BlobId) -> bool {
        self.streams.values().any(|s| s.pulling.fetching.values().any(|(_, ids)| ids.contains(b)))
    }

    /// Fetches the bodies `ids` of member `l` from `conn`'s peer, but those asked for already
    /// on any connection: one source at a time per blob.
    pub(crate) fn stream_fetch(&mut self, conn: ConnId, l: LabelId, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<()> {
        let ids: Vec<BlobId> = ids.into_iter().filter(|b| !self.fetching(b)).collect();
        if ids.is_empty() {
            return Ok(());
        }
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let mut msgs = Vec::new();
        for batch in ids.chunks(osis_proto::msg::MAX_ITEMS) {
            let id = p.next();
            p.fetching.insert(id, (l, batch.to_vec()));
            msgs.push(Message::Fetch { id, label: l, max_reply: osis_proto::serving::REPLY_BUDGET as u64, ids: batch.to_vec() });
        }
        for m in msgs {
            self.shared_send(conn, m, out)?;
        }
        Ok(())
    }

    /// Answers a reader's Fetch from what this node holds of a member of the connection's
    /// shared set, in order within `max_reply`: what does not fit is left out (asked again), what
    /// is not held is answered with nothing.
    fn stream_serve_fetch(&mut self, conn: ConnId, id: u32, l: LabelId, max_reply: u64, ids: Vec<BlobId>, out: &mut Vec<Action>) -> Result<()> {
        let member = self.records.shared.get(&conn).is_some_and(|s| s.has(&l));
        let mut budget = usize::try_from(max_reply).unwrap_or(usize::MAX).min(osis_proto::serving::REPLY_BUDGET).saturating_sub(256);
        let mut items = Vec::new();
        for b in ids {
            let held = if member { self.state.entries.get(&(l, b)).map(|e| (e.wrap, e.stamp)) } else { None };
            let entry = match held {
                Some((wrap, stamp)) => self.engine.blob(&b)?.map(|x| (x, wrap, stamp)),
                None => None,
            };
            let n = entry.as_ref().map_or(40, |(x, ..)| x.len().saturating_add(200));
            if n > budget && !items.is_empty() {
                break;
            }
            budget = budget.saturating_sub(n);
            items.push(osis_proto::msg::Fetched { blob_id: b, entry });
        }
        self.shared_send(conn, Message::FetchReply { id, items }, out)
    }

    /// A reader answered a fetch: what it delivered is applied as its events are; what it did
    /// not is asked of the next source of `l` (by connection order), else waits for an
    /// announcement; what did not fit is asked again here.
    fn stream_fetch_reply(&mut self, conn: ConnId, id: u32, items: Vec<osis_proto::msg::Fetched>, out: &mut Vec<Action>) -> Result<()> {
        let Some((l, asked)) = self.streams.get_mut(&conn).and_then(|s| s.pulling.fetching.remove(&id)) else { return Ok(()) };
        let answered: BTreeSet<BlobId> = items.iter().map(|f| f.blob_id).collect();
        self.stream_fetched(conn, l, items, out)?;
        let rest: Vec<BlobId> = asked.into_iter().filter(|b| !answered.contains(b)).collect();
        if !rest.is_empty() {
            self.stream_fetch(conn, l, rest, out)?;
        }
        Ok(())
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
            self.reader_events(conn, l, evs, out)?;
        }
        if failed.is_empty() {
            return Ok(());
        }
        let next = self.records.shared.iter().find(|(c, s)| **c > conn && s.has(&l)).map(|(c, _)| *c);
        match next {
            Some(c) => self.stream_fetch(c, l, failed, out),
            None => Ok(()),
        }
    }

    /// Pulls sent on `conn` so far (tests count them).
    pub fn stream_pulls(&self, conn: ConnId) -> u64 {
        self.streams.get(&conn).map_or(0, |s| s.pulling.pulls)
    }

    /// Whether `conn`'s stream read the peer's log to its end with nothing waiting (tests).
    pub fn stream_caught_up(&self, conn: ConnId) -> bool {
        self.streams.get(&conn).is_some_and(|s| s.pulling.caught_up)
    }

    /// Whether `conn`'s reader is caught up on member `l` both ways (`label_status`'s idle
    /// source): this node applied the reader's stream of `l` to its end with no body asked
    /// there, and the reader joined `l`, was served this node's log to its end and reported
    /// applying every message carrying events of `l`.
    pub(crate) fn stream_idle(&self, conn: ConnId, l: &LabelId) -> bool {
        self.streams.get(&conn).is_some_and(|s| {
            let pulled = s.pulling.caught_up && s.pulling.in_stream.contains(l) && s.pulling.fetching.is_empty();
            let v = &s.serving;
            let served = v.follow.is_some() && v.at_end && v.pulled.contains(l) && !v.unreported.iter().any(|(_, ls)| ls.contains(l));
            pulled && served
        })
    }
}
