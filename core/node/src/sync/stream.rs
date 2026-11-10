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
//! - A cursor is stored only after what it covers is applied (state flushed first); a member no
//!   longer open here leaves the stream before a message is applied (`stream_prune`).
//! - Within a connection a requester opens L only after the server has (the shared set's reply
//!   order) and the server's `Lost` follows every event it sent for L, so the server's S covers
//!   the requester's tracked members wherever the stream moves them.
//!
//! Checked by the randomized differentials `stream_differential_no_write_dropped_spec_sync_10`
//! and `stream_differential_paged_spec_sync_10` (core/node/tests/it/stream.rs).
//!
//! As built: the dialer pulls; the listener serves (both sides serve). Memory entries are the
//! log's memory part (`MemLog`), which no cursor names: the first Pull of a connection, and
//! every join, list the memory events of what they start; later ones follow in counter order on
//! that connection, paged by the same budget as the durable part.

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
const ID_BASE: u32 = (1 << 31) | (1 << 30);

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
}

const MAX_CROSSED: usize = 1 << 14;

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
    /// A Pull went on this connection (the first asks for the live memory entries).
    started: bool,
    /// The last reply ended the peer's log and nothing waits.
    caught_up: bool,
    next_id: u32,
    record: Option<RecordId>,
    /// Pulls sent (tests count them).
    pulls: u64,
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
            // a report is asked only by an `until`, which this node never sets
            Message::Applied { .. } => Ok(()),
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
        if p.follow && !more {
            self.streams.entry(conn).or_default().serving.follow = Some(stream_at);
        }
        let reply = PullReply { id: p.id, events, cursor, whole, more, report: false, joins };
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
            let (mut events, _) = self.stream_memory(conn, &BTreeSet::new(), &members, &mut budget)?;
            let (durable, cut) = self.stream_events(conn, &scan.events, &mut budget, events.is_empty())?;
            events.extend(durable);
            let end = cut.unwrap_or(scan.end);
            if let Some(s) = self.streams.get_mut(&conn) {
                s.serving.follow = Some(end);
            }
            if events.is_empty() {
                continue;
            }
            let cursor = self.engine.run(|tx| Ok(tx.txn.log_cursor(end)?))?;
            self.shared_send(conn, Message::Stream(Box::new(Stream { events, cursor, report: false })), out)?;
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

    /// Member `l` is open here on `conn`: it joins the stream, from its lag or the start.
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
        // a listing shows what is there now: what was known present there starts over
        if lag.is_none()
            && let Some(host) = self.conns.get(&conn).map(|c| c.host)
        {
            for b in self.state.present_at(&host, &l) {
                self.state.set_present(host, l, b, false);
            }
        }
        if let Some(lc) = self.lc_mut(conn, &l) {
            lc.syncing = true;
        }
        let p = &mut self.streams.entry(conn).or_default().pulling;
        p.joins.insert(l, lag);
        p.caught_up = false;
        self.stream_ask(conn, false, out)
    }

    /// Member `l` left `conn` here: its position is kept as a lag for a rejoin.
    pub(super) fn stream_leave(&mut self, conn: ConnId, l: &LabelId) -> Result<()> {
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        let stop = if p.in_stream.remove(l) { p.cursor.clone() } else { p.joins.remove(l).flatten() };
        if let Some(id) = p.record {
            self.engine.run(|tx| Ok(tx.txn.record_stop(&id, l, stop)?))?;
        }
        Ok(())
    }

    /// Drops what `conn`'s stream tracks that is no longer an open member there.
    fn stream_prune(&mut self, conn: ConnId) -> Result<()> {
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        let open = |l: &LabelId| self.lc(conn, l).is_some_and(|x| x.phase == super::Phase::Open);
        let gone: Vec<LabelId> = p.in_stream.iter().chain(p.joins.keys()).filter(|l| !open(l)).copied().collect();
        for l in gone {
            self.stream_leave(conn, &l)?;
        }
        Ok(())
    }

    /// Sends a Pull on `conn` unless one is in flight: with joins waiting, a reply that left
    /// more, or `fresh` (a caller that must hear everything the peer holds now).
    pub(super) fn stream_ask(&mut self, conn: ConnId, fresh: bool, out: &mut Vec<Action>) -> Result<()> {
        self.stream_prune(conn)?;
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        if p.asked.is_some() || (p.in_stream.is_empty() && p.joins.is_empty()) || (p.caught_up && p.joins.is_empty() && !fresh) {
            return Ok(());
        }
        // a body crosses once in a mesh: with another source of any member, announcements only
        let tracked: Vec<LabelId> = p.in_stream.iter().chain(p.joins.keys()).copied().collect();
        let other = tracked.iter().any(|l| self.conns.iter().any(|(c, x)| *c != conn && x.labels.get(l).is_some_and(|lc| lc.phase == super::Phase::Open)));
        let inline_limit = if other { 0 } else { self.cfg.inline_limit };
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        p.next_id = p.next_id.wrapping_add(1);
        let id = ID_BASE | (p.next_id & ((1 << 30) - 1));
        let joins: Vec<Join> = p.joins.iter().map(|(l, c)| (*l, c.clone())).collect();
        p.asked = Some((id, joins.iter().map(|(l, _)| *l).collect()));
        let ephemeral = !p.started;
        p.started = true;
        p.pulls += 1;
        let pull = Pull { id, cursor: p.cursor.clone(), joins, inline_limit, max_reply: osis_proto::serving::REPLY_BUDGET as u64, follow: true, ephemeral };
        self.shared_send(conn, Message::Pull(Box::new(pull)), out)
    }

    /// Applies stream events of tracked members, by label in order. A member no longer open
    /// here (one opening again) leaves the stream first, at the position it holds: the message's
    /// cursor then moves only the members whose events were applied.
    fn stream_apply(&mut self, conn: ConnId, events: Vec<(LabelId, Event)>, out: &mut Vec<Action>) -> Result<()> {
        self.stream_prune(conn)?;
        let Some(p) = self.streams.get(&conn).map(|s| &s.pulling) else { return Ok(()) };
        let mut by_label: BTreeMap<LabelId, Vec<Event>> = BTreeMap::new();
        for (l, e) in events {
            if p.in_stream.contains(&l) || p.joins.contains_key(&l) {
                by_label.entry(l).or_default().push(e);
            }
        }
        for (l, evs) in by_label {
            if self.lc(conn, &l).is_none_or(|x| x.phase != super::Phase::Open) {
                continue;
            }
            self.received_from(conn, l);
            self.log_events(Some(conn), l, evs, None, out)?;
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
        // a stream from the start: every tracked member is listed, presence starts over
        if r.whole {
            let all: Vec<LabelId> = p.in_stream.iter().chain(p.joins.keys()).copied().collect();
            if let Some(host) = self.conns.get(&conn).map(|c| c.host) {
                for l in &all {
                    for b in self.state.present_at(&host, l) {
                        self.state.set_present(host, *l, b, false);
                    }
                }
            }
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
                if let Some(lc) = self.lc_mut(conn, &l) {
                    lc.syncing = false;
                }
                self.synced(conn, l, out)?;
            }
            return Ok(());
        }
        self.stream_ask(conn, false, out)
    }

    fn stream_pushed(&mut self, conn: ConnId, s: Stream, out: &mut Vec<Action>) -> Result<()> {
        if !self.streams.contains_key(&conn) {
            return Ok(());
        }
        self.stream_apply(conn, s.events, out)?;
        let Some(p) = self.streams.get_mut(&conn).map(|s| &mut s.pulling) else { return Ok(()) };
        p.cursor = s.cursor.clone();
        self.stream_store(conn, &[], &[])?;
        if s.report
            && let Some(c) = s.cursor
        {
            self.shared_send(conn, Message::Applied { cursor: c }, out)?;
        }
        Ok(())
    }

    /// Pulls sent on `conn` so far (tests count them).
    pub fn stream_pulls(&self, conn: ConnId) -> u64 {
        self.streams.get(&conn).map_or(0, |s| s.pulling.pulls)
    }

    /// Whether `conn`'s stream read the peer's log to its end with nothing waiting (tests).
    pub fn stream_caught_up(&self, conn: ConnId) -> bool {
        self.streams.get(&conn).is_some_and(|s| s.pulling.caught_up)
    }
}
