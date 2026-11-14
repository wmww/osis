//! The serving side of a stream (spec/sync-streams.md §4 Reading, Pushes, Reports; spec/wire.md
//! §11.2 Pull, Fetch): Pulls answered from the node log filtered by the connection's shared set
//! now, pages by `max_reply`, joins in pages, ephemeral listings, pushes under `follow` with
//! `seq`, Fetches, and the reported positions a requester gives.

use super::{Ctx, Streams};
use crate::opens::Reported;
use crate::store::Members;
use crate::types::{ConnId, Cursor, Position, Result};
use osis_base::{BlobId, SyncId};
use osis_proto::limits::REPLY_BUDGET;
use osis_proto::msg::stream_event_len;
use osis_proto::{Code, Event, Fetched, Id, Msg, Pull, PullReply, Stream};
use osis_store::NodeEvent;
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Bytes of a reply's frame body besides its events and joins (kind, id, cursor, flags), and of
/// one join (a sync ID and a cursor): what paging keeps aside.
const OVERHEAD: usize = 512;
const JOIN_LEN: usize = 300;
/// A Fetch item's entry: the blob, its wrap and stamp.
type Body = (Vec<u8>, osis_proto::Wrap, Option<osis_proto::Stamp>);

/// Log events read at a time while paging.
const CHUNK: usize = 256;

#[derive(Clone, Debug, Default)]
pub(super) struct Serve {
    /// Pushing from here, until the next Pull (`follow`).
    follow: Option<Follow>,
    /// The first Pull came: only its cursor is a reported position (spec/sync-opens.md §6).
    pulled: bool,
    /// Joins named before on this connection.
    named: BTreeSet<SyncId>,
    /// Joins merged into the stream at a reply's position, awaiting an Applied covering it.
    merging: BTreeMap<SyncId, Position>,
    /// Blobs whose bytes crossed this connection, either way (spec/wire.md §11.2 Pull).
    pub(super) crossed: HashSet<BlobId>,
    inline: u64,
    /// The ephemeral listing per member: the memory counter read to.
    eph: BTreeMap<SyncId, u64>,
    mem_mark: u64,
    /// Ended members (an `until`), and those told they reached it by an empty Stream.
    ending: BTreeSet<SyncId>,
    told_until: BTreeSet<SyncId>,
    /// The highest position an Applied reported.
    applied: Option<Position>,
    /// Members reported at a position of their own (a join not merged yet).
    own: BTreeSet<SyncId>,
}

#[derive(Clone, Debug)]
struct Follow {
    cursor: Option<Cursor>,
    pos: Position,
    seq: u64,
}

/// A message being filled: its events within the budget, and what sending it commits.
struct Page {
    events: Vec<(SyncId, Event)>,
    left: usize,
    /// At `REPLY_BUDGET` a page holds at least one event.
    one: bool,
    full: bool,
    crossed: Vec<BlobId>,
    eph: BTreeMap<SyncId, u64>,
}

impl Page {
    fn new(max_reply: u64, aside: usize) -> Page {
        let max = (max_reply as usize).min(REPLY_BUDGET);
        Page { events: Vec::new(), left: max.saturating_sub(OVERHEAD + aside), one: max >= REPLY_BUDGET, full: false, crossed: Vec::new(), eph: BTreeMap::new() }
    }

    /// Takes the event if it fits; a page that refused one is full.
    fn take(&mut self, s: SyncId, e: Event, inlined: bool) -> bool {
        let n = stream_event_len(&e);
        if self.full || (n > self.left && !(self.one && self.events.is_empty())) {
            self.full = true;
            return false;
        }
        self.left = self.left.saturating_sub(n);
        if inlined && let Event::Added { blob_id, .. } = &e {
            self.crossed.push(*blob_id);
        }
        self.events.push((s, e));
        true
    }
}

/// Where a read of the log stopped.
struct Read {
    cursor: Option<Cursor>,
    pos: Position,
    more: bool,
}

fn wire_cursor(c: &Option<Cursor>) -> Option<osis_proto::Cursor> {
    c.clone().and_then(|b| osis_proto::Cursor::new(b).ok())
}

impl Streams {
    /// A Pull (spec/sync-streams.md §4 Reading, Joining; spec/wire.md §11.2 Pull).
    pub(super) fn on_pull(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, p: Pull) {
        if !ctx.shared.agreed(conn) {
            ctx.wire.answer(conn, id, Msg::Error { id, code: Code::DECLINED });
            return;
        }
        match self.reply(ctx, conn, id, p) {
            Ok(r) => ctx.wire.answer(conn, id, Msg::PullReply(Box::new(r))),
            Err(_) => ctx.wire.answer(conn, id, Msg::Error { id, code: Code::DECLINED }),
        }
    }

    fn reply(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, p: Pull) -> Result<PullReply> {
        let members: BTreeMap<SyncId, Option<Position>> = ctx.shared.members(conn).iter().map(|(s, m)| (*s, m.until)).collect();
        self.work.members += members.len() as u64;
        let (_, horizon) = ctx.store.log_bounds()?;
        let own = match &p.cursor {
            Some(c) => Some(ctx.store.position(c.as_bytes())?),
            None => None,
        };
        let mut joins = Vec::with_capacity(p.joins.len());
        for (s, c) in &p.joins {
            let pos = match c {
                Some(c) => Some(ctx.store.position(c.as_bytes())?),
                None => None,
            };
            joins.push((*s, c.as_ref().map(|c| c.as_bytes().to_vec()), pos));
        }
        // SN_inc, SN_copies: a cursor not of this history (or past its end) names no position:
        // every member from the start. A cursor below the deletion horizon: the same, trimmed.
        let named = own.iter().chain(joins.iter().filter_map(|(_, _, p)| p.as_ref()));
        let mut whole = own.is_none() || own == Some(None);
        let mut trimmed = false;
        for pos in named {
            match pos {
                None => whole = true,
                Some(x) if *x < horizon => {
                    whole = true;
                    trimmed = true;
                }
                Some(_) => {}
            }
        }
        let serve = self.serve.entry(conn).or_default();
        serve.follow = None;
        serve.inline = p.inline_limit;
        // reported positions: the first Pull's cursor, each join's in the first Pull naming it
        if !serve.pulled {
            serve.pulled = true;
            if !whole && let (Some(c), Some(Some(pos))) = (&p.cursor, own) {
                serve.applied = Some(pos);
                ctx.reported.push(Reported::Stream(conn, pos, c.as_bytes().to_vec()));
            }
        }
        if !whole {
            for (s, c, pos) in &joins {
                if members.contains_key(s) && serve.named.insert(*s) {
                    serve.own.insert(*s);
                    ctx.reported.push(Reported::Member(conn, *s, pos.flatten().zip(c.clone())));
                }
            }
        }
        if p.ephemeral {
            serve.eph = members.keys().map(|s| (*s, 0)).collect();
        }
        for (s, ..) in &joins {
            if members.contains_key(s) {
                serve.eph.insert(*s, 0);
            }
        }
        let mut page = Page::new(p.max_reply, joins.len() * JOIN_LEN);
        // the stream part: every member not joining, after the stream's cursor (SN_gate: the
        // shared set now)
        let joining: BTreeSet<SyncId> = if whole { BTreeSet::new() } else { joins.iter().map(|(s, ..)| *s).collect() };
        let stream: BTreeMap<SyncId, Option<Position>> = members.iter().filter(|(s, _)| !joining.contains(*s)).map(|(s, u)| (*s, *u)).collect();
        let from = if whole { None } else { p.cursor.as_ref().map(|c| c.as_bytes().to_vec()) };
        let start = if whole { 0 } else { own.flatten().unwrap_or(0) };
        let read = self.read_into(ctx, conn, &mut page, &stream, None, from, start)?;
        // joins: each from its own cursor; one that reaches the log's end merges
        let mut reply_joins = Vec::new();
        if !whole {
            for (s, c, pos) in joins {
                let Some(until) = members.get(&s) else {
                    reply_joins.push((s, None));
                    continue;
                };
                if page.full {
                    let c = match c {
                        Some(c) => Some(c),
                        None => ctx.store.cursor_at(0)?,
                    };
                    reply_joins.push((s, c.and_then(|c| osis_proto::Cursor::new(c).ok())));
                    continue;
                }
                let one = BTreeMap::from([(s, *until)]);
                let r = self.read_into(ctx, conn, &mut page, &one, Some(s), c, pos.flatten().unwrap_or(0))?;
                if r.more {
                    reply_joins.push((s, wire_cursor(&r.cursor)));
                } else {
                    self.serve.entry(conn).or_default().merging.insert(s, read.pos);
                }
            }
        } else {
            // joins ignored, but one of a member not shared here is still answered so; every
            // member at a position of its own follows the stream once this reply is covered
            let serve = self.serve.entry(conn).or_default();
            for s in serve.own.clone() {
                serve.merging.insert(s, read.pos);
            }
            for (s, ..) in &p.joins {
                if !members.contains_key(s) {
                    reply_joins.push((*s, None));
                }
            }
        }
        self.ephemeral(ctx, conn, &mut page, &members)?;
        let serve = self.serve.entry(conn).or_default();
        serve.crossed.extend(page.crossed.iter().copied());
        serve.eph.extend(page.eph.iter().map(|(s, n)| (*s, *n)));
        if p.follow && !read.more {
            serve.follow = Some(Follow { cursor: read.cursor.clone(), pos: read.pos, seq: 0 });
            serve.mem_mark = ctx.store.memory_mark();
        }
        let cursor = wire_cursor(&read.cursor);
        let report = !page.events.is_empty() && cursor.is_some();
        Ok(PullReply { id, events: page.events, cursor, whole, trimmed, more: read.more, report, joins: reply_joins })
    }

    /// Reads `members`' events after `from` (none: the start) into `page`; `one`: a join's read
    /// of that sync ID alone (its index), else the log.
    #[allow(clippy::too_many_arguments)]
    fn read_into(&mut self, ctx: &mut Ctx, conn: ConnId, page: &mut Page, members: &impl Members, one: Option<SyncId>, from: Option<Cursor>, start: Position) -> Result<Read> {
        let mut cursor = from;
        let mut pos = start;
        if members.is_empty() {
            let (end, _) = ctx.store.log_bounds()?;
            let at = ctx.store.cursor_at(end)?;
            return Ok(Read { cursor: at.or(cursor), pos: end.max(pos), more: false });
        }
        let inline = self.serve.get(&conn).map_or(0, |s| s.inline);
        loop {
            let r = match one {
                Some(s) => ctx.store.read_sync(&s, members.until(&s).flatten(), cursor.as_ref(), CHUNK)?,
                None => ctx.store.read_log(members, cursor.as_ref(), CHUNK)?,
            };
            self.work.served += r.events.len() as u64;
            for e in &r.events {
                if let Some((s, ev, inlined)) = self.event(ctx, conn, page, inline, &e.event)?
                    && !page.take(s, ev, inlined)
                {
                    // ends before the event that would pass the budget
                    let c = if pos == start { cursor } else { ctx.store.cursor_at(pos)? };
                    return Ok(Read { cursor: c, pos, more: true });
                }
                pos = e.pos;
            }
            cursor = r.cursor;
            if !r.more {
                let (end, _) = ctx.store.log_bounds()?;
                return Ok(Read { cursor, pos: end.max(pos), more: false });
            }
        }
    }

    /// A log event as sent: an add carries its entry as held now (none if it left since).
    fn event(&mut self, ctx: &mut Ctx, conn: ConnId, page: &Page, inline: u64, e: &NodeEvent) -> Result<Option<(SyncId, Event, bool)>> {
        Ok(match *e {
            NodeEvent::Added(s, b) => {
                let Some(entry) = ctx.store.entry(&s, &b)? else { return Ok(None) };
                let crossed = self.serve.get(&conn).is_some_and(|x| x.crossed.contains(&b)) || page.crossed.contains(&b);
                let blob = if inline > 0 && !crossed { ctx.store.bytes(&b)?.filter(|v| v.len() as u64 <= inline) } else { None };
                let inlined = blob.is_some();
                Some((s, Event::Added { blob_id: b, blob, wrap: entry.wrap, stamp: entry.stamp }, inlined))
            }
            NodeEvent::Deleted { label, blob, .. } => Some((label, Event::Deleted(blob), false)),
            NodeEvent::Head(s) => ctx.store.head(&s)?.map(|st| (s, Event::Head(st), false)),
        })
    }

    /// The ephemeral listing (spec/wire.md §11.2 Pull `ephemeral`): each listed member's memory
    /// events after where its listing stands, with their bytes, while the page has room.
    fn ephemeral(&mut self, ctx: &mut Ctx, conn: ConnId, page: &mut Page, members: &impl Members) -> Result<()> {
        let listing: Vec<(SyncId, u64)> = self.serve.get(&conn).map(|x| x.eph.iter().filter(|(s, _)| members.until(s) == Some(None)).map(|(s, n)| (*s, *n)).collect()).unwrap_or_default();
        for (s, mut at) in listing {
            loop {
                let (evs, last) = ctx.store.read_memory(&s, at, CHUNK);
                if evs.is_empty() {
                    page.eph.insert(s, last);
                    break;
                }
                for (n, b, present) in evs {
                    let ev = if present {
                        let (Some(entry), Some(bytes)) = (ctx.store.entry(&s, &b)?, ctx.store.bytes(&b)?) else {
                            at = n;
                            continue;
                        };
                        let crossed = self.serve.get(&conn).is_some_and(|x| x.crossed.contains(&b));
                        Event::Added { blob_id: b, blob: (!crossed).then_some(bytes), wrap: entry.wrap, stamp: entry.stamp }
                    } else {
                        Event::Deleted(b)
                    };
                    let inlined = matches!(&ev, Event::Added { blob: Some(_), .. });
                    if !page.take(s, ev, inlined) {
                        page.eph.insert(s, at);
                        return Ok(());
                    }
                    at = n;
                }
                page.eph.insert(s, at);
            }
        }
        Ok(())
    }

    /// Pushes under `follow` (spec/sync-streams.md §4 Pushes, §2): the later events of the shared
    /// set from the follow cursor, each Stream numbered by `seq`; nothing moves while one does
    /// not fit. An ended member that reached its `until` is told by a Stream with no events.
    pub(super) fn push(&mut self, ctx: &mut Ctx, conn: ConnId) -> Result<bool> {
        let Some(f) = self.serve.get(&conn).and_then(|s| s.follow.clone()) else { return Ok(false) };
        let (end, _) = ctx.store.log_bounds()?;
        let mark = ctx.store.memory_mark();
        let mem_moved = self.serve.get(&conn).is_some_and(|s| s.mem_mark != mark);
        // the shared set now, read per event: a push costs its events, not the members
        let shared = ctx.shared;
        let members = shared.members(conn);
        let mut acted = false;
        if end > f.pos || mem_moved {
            let mut page = Page::new(REPLY_BUDGET as u64, 0);
            let read = if end > f.pos { self.read_into(ctx, conn, &mut page, members, None, f.cursor.clone(), f.pos)? } else { Read { cursor: f.cursor.clone(), pos: f.pos, more: false } };
            if mem_moved {
                self.ephemeral(ctx, conn, &mut page, members)?;
            }
            if page.events.is_empty() {
                let s = self.serve.entry(conn).or_default();
                s.follow = Some(Follow { cursor: read.cursor, pos: read.pos, seq: f.seq });
                if !page.full {
                    s.mem_mark = mark;
                }
                s.eph.extend(page.eph);
            } else {
                let st = Stream { events: page.events, cursor: wire_cursor(&read.cursor), report: true, seq: f.seq };
                if !ctx.wire.push(conn, Msg::Stream(Box::new(st))) {
                    return Ok(false);
                }
                let s = self.serve.entry(conn).or_default();
                s.follow = Some(Follow { cursor: read.cursor, pos: read.pos, seq: f.seq + 1 });
                s.crossed.extend(page.crossed);
                s.eph.extend(page.eph);
                if !page.full && !read.more {
                    s.mem_mark = mark;
                }
                acted = true;
            }
        }
        // ended members at their `until`
        let Some(f) = self.serve.get(&conn).and_then(|s| s.follow.clone()) else { return Ok(acted) };
        let ending: Vec<SyncId> = self.serve.get(&conn).map(|x| x.ending.iter().copied().collect()).unwrap_or_default();
        for s in &ending {
            let Some(Some(u)) = members.until(s) else { continue };
            let serve = self.serve.entry(conn).or_default();
            if f.pos < u || serve.told_until.contains(s) || shared.reported(conn, s).is_some_and(|r| r >= u) {
                continue;
            }
            let st = Stream { events: Vec::new(), cursor: wire_cursor(&f.cursor), report: true, seq: f.seq };
            if !ctx.wire.push(conn, Msg::Stream(Box::new(st))) {
                break;
            }
            let serve = self.serve.entry(conn).or_default();
            serve.told_until.insert(*s);
            if let Some(x) = serve.follow.as_mut() {
                x.seq += 1;
            }
            acted = true;
            break;
        }
        Ok(acted)
    }

    /// An Applied: the requester stored this cursor (spec/sync-opens.md §6 reported positions).
    pub(super) fn on_applied(&mut self, ctx: &mut Ctx, conn: ConnId, cursor: Cursor) {
        let Ok(Some(pos)) = ctx.store.position(&cursor) else { return };
        let serve = self.serve.entry(conn).or_default();
        if serve.applied.is_some_and(|p| p >= pos) {
            return;
        }
        serve.applied = Some(pos);
        ctx.reported.push(Reported::Stream(conn, pos, cursor));
        let merged: Vec<SyncId> = serve.merging.iter().filter(|(_, p)| **p <= pos).map(|(s, _)| *s).collect();
        for s in merged {
            serve.merging.remove(&s);
            serve.own.remove(&s);
            ctx.reported.push(Reported::Merged(conn, s));
        }
    }

    /// A member joined, as server: one opened after the first Pull has no reported position
    /// until a join names it.
    pub(super) fn served_joined(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        if let Some(serve) = self.serve.get_mut(&conn)
            && serve.pulled
        {
            serve.own.insert(s);
            ctx.reported.push(Reported::Member(conn, s, None));
        }
        self.served_ending(ctx, conn, s);
    }

    /// A member left, as server: a later join is another, reported afresh.
    pub(super) fn served_left(&mut self, conn: ConnId, s: &SyncId) {
        let Some(serve) = self.serve.get_mut(&conn) else { return };
        serve.named.remove(s);
        serve.merging.remove(s);
        serve.own.remove(s);
        serve.eph.remove(s);
        serve.ending.remove(s);
        serve.told_until.remove(s);
    }

    /// Member S's `until` was set or cleared.
    pub(super) fn served_ending(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let ended = ctx.shared.members(conn).get(&s).is_some_and(|m| m.until.is_some());
        let serve = self.serve.entry(conn).or_default();
        serve.told_until.remove(&s);
        if ended {
            serve.ending.insert(s);
        } else {
            serve.ending.remove(&s);
        }
    }

    /// A Fetch (spec/wire.md §11.2 Fetch): each ID's entry of S with its bytes, a prefix of them
    /// within `max_reply`; none for one not held, not shared here, or (an ended member) first
    /// logged past its `until`.
    pub(super) fn on_fetch(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, s: SyncId, max_reply: u64, ids: Vec<BlobId>) {
        let until = ctx.shared.members(conn).get(&s).map(|m| m.until);
        let mut left = (max_reply as usize).min(REPLY_BUDGET).saturating_sub(OVERHEAD);
        let mut items = Vec::new();
        for b in ids {
            let entry = match until {
                None => None,
                Some(u) => self.fetchable(ctx, &s, &b, u).ok().flatten(),
            };
            let n = entry.as_ref().map_or(40, |(v, ..)| v.len() + 200);
            if n > left && !items.is_empty() {
                break;
            }
            left = left.saturating_sub(n);
            if entry.is_some() {
                self.serve.entry(conn).or_default().crossed.insert(b);
            }
            items.push(Fetched { blob_id: b, entry });
        }
        ctx.wire.answer(conn, id, Msg::FetchReply { id, items });
    }

    fn fetchable(&self, ctx: &mut Ctx, s: &SyncId, b: &BlobId, until: Option<Position>) -> Result<Option<Body>> {
        let Some(e) = ctx.store.entry(s, b)? else { return Ok(None) };
        if let Some(u) = until
            && ctx.store.first_logged(s, b)?.is_none_or(|f| f > u)
        {
            return Ok(None);
        }
        Ok(ctx.store.bytes(b)?.map(|v| (v, e.wrap, e.stamp)))
    }
}
