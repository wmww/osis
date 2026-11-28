//! The serving side of a stream (spec/sync-streams.md §4 Reading, Pushes, Reports; spec/wire.md
//! §11.2 Pull, Fetch): Pulls answered from the node log filtered by the connection's shared set
//! now, pages by `max_reply`, joins in pages, ephemeral listings, pushes under `follow` with
//! `seq`, Fetches, and the reported positions a requester gives.

use super::known::Op;
use super::{Ctx, Streams};
use crate::opens::Reported;
use crate::store::Members;
use crate::types::{ConnId, Cursor, Entry, Holding, Position, Result, SourceClass};
use osis_base::{BlobId, SyncId};
use osis_proto::limits::REPLY_BUDGET;
use osis_proto::msg::stream_event_len;
use osis_proto::{Code, Event, Fetched, Id, Msg, Pull, PullReply, Stream};
use osis_store::NodeEvent;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    /// Joins merged into the stream by a reply, with that reply's message number (the number the
    /// next message asking a report takes, where the reply asks none): awaiting an Applied
    /// covering that message. An Applied of an earlier message covers no merge, whatever
    /// position it names.
    merging: BTreeMap<SyncId, u64>,
    inline: u64,
    /// The ephemeral listing per member: the memory counter read to.
    eph: BTreeMap<SyncId, u64>,
    mem_mark: u64,
    /// Ended members (an `until`), and those told they reached it by an empty Stream.
    ending: BTreeSet<SyncId>,
    told_until: BTreeSet<SyncId>,
    /// The highest position an Applied reported (reported positions, spec/sync-opens.md §6).
    applied: Option<Position>,
    /// Messages asking a report sent so far: each one's number, in send order.
    sent: u64,
    /// The highest number an Applied named (covering every message before it).
    reported: u64,
    /// The cursors of messages asking a report not yet covered, each sealed afresh so an Applied
    /// names one message, with its number, the entries its `Added` events carried (counted held
    /// by the peer once an Applied covers it, `Streams::count_applied`) and, for a Stream, the
    /// Pulls this side had answered when it went (`pulls`): the newest `REPORTS_KEPT`.
    asked: VecDeque<Asked>,
    /// Pulls answered on the connection: the Streams sent since the last one follow its reply.
    pulls: u64,
    /// Entries of `asked` the peer told it does not hold (a refusal event) since its last
    /// Applied: the next Applied counts none of them held.
    told: BTreeSet<(SyncId, BlobId)>,
    /// What the peer counts this node holding: entries it sent that this node holds as sent, each
    /// with this node's log end and memory mark when it applied them, put here as the Applied
    /// reporting them goes (`Streams::run`). No event of one at or below its marks is served
    /// the peer outside a listing from the start (spec/sync-streams.md §4 Reports); one at or below
    /// the position the peer reported applied goes, never served it again on the connection.
    pub(super) counted: BTreeMap<(SyncId, BlobId), At>,
    /// Members whose listing from the start (a whole reply's, or a join from the start) is under
    /// way on this connection: served whole, with no entry left out for being counted.
    listing: BTreeSet<SyncId>,
    /// Per member, the number of the last message carrying an event of it that asked a report:
    /// S's messages served are applied once `reported` reaches it (spec/sync-status.md §1 caught
    /// up). Kept while above `reported`.
    unapplied: BTreeMap<SyncId, u64>,
    /// Members that joined after the first Pull and that no reply has read for the peer since
    /// (its join merged, or a reply from the start): caught up waits for that reply.
    unjoined: BTreeSet<SyncId>,
    /// Per member, its last event the log holds past the follow cursor (not pushed yet), and how
    /// far the log was read for them (`Streams::scan_unpushed`): kept while past the cursor.
    unpushed: BTreeMap<SyncId, Position>,
    scanned: Option<(Option<Cursor>, Position)>,
    /// The members whose join the last reply left to read on (the peer pulls again for them).
    joins_left: BTreeSet<SyncId>,
    /// Members reported at a position of their own (a join not merged yet).
    own: BTreeSet<SyncId>,
    /// Blobs whose bytes went inline in a message asking a report, with the last such message's
    /// number, until an Applied covers it or it leaves `asked`: the peer holds them or is taking
    /// them, so they go inline no more under any sync ID (`peer_holds_blob`); once applied, its
    /// stream shows them. At most the blobs of `REPORTS_KEPT` messages.
    inlined: BTreeMap<BlobId, u64>,
}

impl Serve {
    /// The follow cursor reached `pos`: what was logged up to it is pushed or skipped.
    fn followed_to(&mut self, pos: Position) {
        self.unpushed.retain(|_, p| *p > pos);
    }

    /// A message carrying `events`, asking a report with `cursor`, went out.
    fn served(&mut self, events: &[(SyncId, Event)], cursor: Cursor) {
        self.sent += 1;
        let added = events.iter().filter_map(|(s, e)| if let Event::Added { blob_id, .. } = e { Some((*s, *blob_id)) } else { None }).collect();
        self.asked.push_back(Asked { cursor, n: self.sent, added, stream: None });
        // a message no Applied can name alone: its blobs may go inline again (`inlined` stays
        // within the newest `REPORTS_KEPT` messages, whether or not the peer reports), and what it
        // sent is counted held nowhere
        if self.asked.len() > REPORTS_KEPT
            && let Some(a) = self.asked.pop_front()
        {
            self.inlined.retain(|_, x| *x > a.n);
            self.keep_told();
        }
        for (s, e) in events {
            self.unapplied.insert(*s, self.sent);
            if let Event::Added { blob_id, blob: Some(_), .. } = e {
                self.inlined.insert(*blob_id, self.sent);
            }
        }
    }

    /// The message `served` last was a Stream, sent after the reply to the last Pull.
    fn streamed(&mut self) {
        let pulls = self.pulls;
        if let Some(a) = self.asked.back_mut() {
            a.stream = Some(pulls);
        }
    }

    /// Whether a message served asking a report is not reported applied yet: the next message
    /// with a cursor asks one too, so the last is answered whatever it carries.
    fn owed(&self) -> bool {
        self.sent > self.reported
    }

    /// An Applied named `cursor`: the message it was sent with, and every one before it, is
    /// applied; the entries their `Added` events carried, less those the peer told it does not
    /// hold. A cursor of no message asking a report here (one dropped from `asked`, or not this
    /// connection's) covers nothing.
    fn reported_by(&mut self, cursor: &[u8]) -> Vec<(SyncId, BlobId)> {
        let told = std::mem::take(&mut self.told);
        let Some((i, n)) = self.asked.iter().enumerate().find_map(|(i, a)| (a.cursor.as_slice() == cursor).then_some((i, a.n))) else { return Vec::new() };
        let sent: BTreeSet<(SyncId, BlobId)> = self.asked.drain(..=i).flat_map(|a| a.added).filter(|x| !told.contains(x)).collect();
        self.reported = self.reported.max(n);
        let r = self.reported;
        self.unapplied.retain(|_, x| *x > r);
        self.inlined.retain(|_, x| *x > r);
        sent.into_iter().collect()
    }

    /// Tests only: what the next Applied of the peer is judged against beyond `asked`.
    pub(super) fn holding(&self) -> usize {
        self.told.len()
    }

    /// The peer told it does not hold entry `b` of S: kept for the next Applied only where a
    /// message it may report carried it.
    pub(super) fn told(&mut self, s: SyncId, b: BlobId) {
        if self.asked.iter().any(|a| a.added.contains(&(s, b))) {
            self.told.insert((s, b));
        }
    }

    /// Refusals told of entries no message in `asked` carries any more count for nothing.
    fn keep_told(&mut self) {
        let asked = &self.asked;
        self.told.retain(|x| asked.iter().any(|a| a.added.contains(x)));
    }

    /// A Pull naming `cursor` came: its reply reads again from there, so the Streams sent since
    /// the last reply after the message `cursor` names (each, where it names none of them) report
    /// nothing; the requester applying one does not report it (spec/sync-streams.md §4 Reports).
    fn pulled_at(&mut self, cursor: Option<&[u8]>) {
        let named = cursor.and_then(|c| self.asked.iter().position(|a| a.cursor.as_slice() == c));
        let pulls = self.pulls;
        let mut i = 0;
        self.asked.retain(|a| {
            let keep = a.stream != Some(pulls) || named.is_some_and(|x| i <= x);
            i += 1;
            keep
        });
        self.keep_told();
        self.pulls += 1;
    }

    /// Whether the peer counts this node holding entry `b` of S as of its event at `pos` (its
    /// memory event `mem`, an ephemeral entry's): none served it outside a listing from the start.
    fn counts(&self, s: &SyncId, b: &BlobId, at: At) -> bool {
        !self.listing.contains(s)
            && self.counted.get(&(*s, *b)).is_some_and(|m| match (at, m) {
                (At::Log(pos), At::Log(mark)) => pos <= *mark,
                (At::Memory(n), At::Memory(mark)) => n < *mark,
                _ => false,
            })
    }
}

/// An entry an `Added` event carried to the peer: its sync ID and blob.
pub(super) type Sent = (SyncId, BlobId);

/// A message asking a report (`Serve::asked`).
#[derive(Clone, Debug)]
struct Asked {
    cursor: Cursor,
    n: u64,
    added: Vec<Sent>,
    stream: Option<u64>,
}

/// Where an event stands: a log position, or an ephemeral entry's memory counter. As a mark
/// (`Serve::counted`): where this node's log (an ephemeral entry's: its memory part) stood when
/// it applied the entry its peer sent: its end, or the counter its next memory event takes.
#[derive(Clone, Copy, Debug)]
pub(super) enum At {
    Log(Position),
    Memory(u64),
}

/// Messages asking a report whose cursors a server keeps to tell which one an Applied names. At
/// 0 no Applied is recognized (never caught up); at infinity a peer that never reports grows them
/// per message served. A requester answers in order and holds at most `PENDING_CAP` messages,
/// so an honest one's Applied names one of the newest; an older one dropped only delays caught up
/// to the next Applied.
const REPORTS_KEPT: usize = 2 * super::PENDING_CAP;

/// A cursor sealed afresh at the position `c` names, so the message carrying it is the only one
/// with these bytes (an Applied names one message).
fn fresh(ctx: &Ctx, c: Cursor) -> Result<Cursor> {
    Ok(match ctx.store.position(&c)? {
        Some(pos) => ctx.store.cursor_at(pos)?.unwrap_or(c),
        None => c,
    })
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
    /// Blobs whose bytes this page carries: each goes once.
    inlined: BTreeSet<BlobId>,
    eph: BTreeMap<SyncId, u64>,
}

impl Page {
    fn new(max_reply: u64, aside: usize) -> Page {
        let max = (max_reply as usize).min(REPLY_BUDGET);
        Page { events: Vec::new(), left: max.saturating_sub(OVERHEAD + aside), one: max >= REPLY_BUDGET, full: false, inlined: BTreeSet::new(), eph: BTreeMap::new() }
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
            self.inlined.insert(*blob_id);
        }
        self.events.push((s, e));
        true
    }
}

/// Whether the peer on `conn` is shown part of S alone (`shown`): it holds S's thing as a stub, as
/// it declared opening S (spec/sync-opens.md §4 Source).
pub(super) fn as_stub(ctx: &Ctx, conn: ConnId, s: &SyncId) -> bool {
    ctx.shared.members(conn).get(s).is_some_and(|m| m.class == SourceClass::Stub)
}

/// Whether entry `e` of S is shown the peer on `conn`: to one held as a stub, a role entry alone
/// (`role_entry`).
fn shown(ctx: &mut Ctx, conn: ConnId, s: &SyncId, e: &Entry) -> bool {
    match ctx.shared.members(conn).get(s) {
        Some(m) if m.class == SourceClass::Stub => role_entry(ctx, s, e),
        _ => true,
    }
}

/// Whether entry `e` of S is a role entry: by its stamp or deposit signature where this node
/// keeps S unread (`Entry::role`), else by its own judgement of what the blob holds.
fn role_entry(ctx: &mut Ctx, s: &SyncId, e: &Entry) -> bool {
    e.role || (ctx.store.holding(s).is_some_and(Holding::opens) && ctx.ground.role_entry(s, &e.blob))
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
        self.serve.entry(conn).or_default().pulled_at(p.cursor.as_ref().map(|c| c.as_bytes()));
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
        // SN_echoanchor: an anchor naming no position of this history (a store restored from
        // before it) the same, whatever the horizon: what the requester counts this node holding
        // stands on a history it lacks (spec/sync-streams.md §4 Reports)
        let lost = match &p.anchor {
            Some(a) => ctx.store.position(a.as_bytes())?.is_none(),
            None => false,
        };
        let named = own.iter().chain(joins.iter().filter_map(|(_, _, p)| p.as_ref()));
        let mut whole = own.is_none() || own == Some(None) || lost;
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
        // the Pull's cursor says where to read on from (what the requester received), never
        // what it applied: only an Applied reports that
        // reported positions: the first Pull's cursor, each join's in the first Pull naming it
        if !serve.pulled {
            serve.pulled = true;
            if !whole && let (Some(c), Some(Some(pos))) = (&p.cursor, own) {
                serve.applied = Some(pos);
                ctx.reported.push(Reported::Stream(conn, pos, c.as_bytes().to_vec()));
            }
        }
        // each join's position in the first Pull naming it (a whole one reads it from the start:
        // none, and it follows the stream once the reply is covered)
        for (s, c, pos) in &joins {
            if members.contains_key(s) && serve.named.insert(*s) {
                serve.own.insert(*s);
                let at = if whole { None } else { pos.flatten().zip(c.clone()) };
                ctx.reported.push(Reported::Member(conn, *s, at));
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
        // a listing from the start is served whole until its end: its members' and each join's
        // from the start (SN_echocount: the requester's listing replaces presence by what it lists)
        let serve = self.serve.entry(conn).or_default();
        if whole {
            serve.listing = members.keys().copied().collect();
        }
        for (s, c, _) in &joins {
            if c.is_none() && !whole {
                serve.listing.insert(*s);
            }
        }
        let read = self.read_into(ctx, conn, &mut page, &stream, None, from, start)?;
        if !read.more {
            let serve = self.serve.entry(conn).or_default();
            serve.listing.retain(|s| joining.contains(s));
        }
        // joins: each from its own cursor; one that reaches the log's end merges
        let mut reply_joins = Vec::new();
        let mut joins_left = BTreeSet::new();
        let mut merged = Vec::new();
        if !whole {
            for (s, c, pos) in joins {
                let Some(until) = members.get(&s) else {
                    reply_joins.push((s, None));
                    continue;
                };
                if page.full {
                    joins_left.insert(s);
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
                    joins_left.insert(s);
                    reply_joins.push((s, wire_cursor(&r.cursor)));
                } else {
                    merged.push(s);
                    let serve = self.serve.entry(conn).or_default();
                    serve.unjoined.remove(&s);
                    serve.listing.remove(&s);
                }
            }
        } else {
            // joins ignored, but one of a member not shared here is still answered so; every
            // member at a position of its own follows the stream once this reply is covered
            let serve = self.serve.entry(conn).or_default();
            merged.extend(serve.own.iter().copied());
            serve.unjoined.clear();
            for (s, ..) in &p.joins {
                if !members.contains_key(s) {
                    reply_joins.push((*s, None));
                }
            }
        }
        // ephemeral entries go only in a message with a cursor, so an Applied can report them: a
        // log naming no position yet lists them once it does
        if read.cursor.is_some() {
            self.ephemeral(ctx, conn, &mut page, &members, None)?;
        }
        let serve = self.serve.entry(conn).or_default();
        serve.eph.extend(page.eph.iter().map(|(s, n)| (*s, *n)));
        serve.joins_left = joins_left;
        if p.follow && !read.more {
            serve.follow = Some(Follow { cursor: read.cursor.clone(), pos: read.pos, seq: 0 });
            // a listing the page cut (or not begun) follows in Streams: pushes read on from its
            // least counter
            let mark = ctx.store.memory_mark();
            serve.mem_mark = if page.full || read.cursor.is_none() { serve.eph.values().min().map_or(mark, |n| (*n).min(mark)) } else { mark };
            serve.followed_to(read.pos);
        }
        let report = read.cursor.is_some() && (!page.events.is_empty() || serve.owed());
        let cursor = match read.cursor {
            Some(c) if report => {
                let c = fresh(ctx, c)?;
                self.serve.entry(conn).or_default().served(&page.events, c.clone());
                Some(c)
            }
            c => c,
        };
        // the joins this reply merged follow the stream once an Applied covers it
        let serve = self.serve.entry(conn).or_default();
        let n = if report { serve.sent } else { serve.sent + 1 };
        serve.merging.extend(merged.into_iter().map(|s| (s, n)));
        let cursor = wire_cursor(&cursor);
        let from_start: Vec<SyncId> = if whole { members.keys().copied().collect() } else { p.joins.iter().filter(|(s, c)| c.is_none() && members.contains_key(s)).map(|(s, _)| *s).collect() };
        self.offered(ctx, conn, &page.events, &from_start);
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
                if let Some((s, ev, inlined)) = self.event(ctx, conn, page, inline, e.pos, &e.event)?
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

    /// A log event at `pos` as sent: an add carries its entry as held now (none if it left
    /// since, or the peer counts this node holding it as of this event, `Serve::counts`).
    fn event(&mut self, ctx: &mut Ctx, conn: ConnId, page: &Page, inline: u64, pos: Position, e: &NodeEvent) -> Result<Option<(SyncId, Event, bool)>> {
        Ok(match *e {
            NodeEvent::Added(s, b) => {
                if self.serve.get(&conn).is_some_and(|x| x.counts(&s, &b, At::Log(pos))) {
                    return Ok(None);
                }
                let Some(entry) = ctx.store.entry(&s, &b)? else { return Ok(None) };
                if !shown(ctx, conn, &s, &entry) {
                    return Ok(None);
                }
                // its bytes read (made again, where the engine keeps its seal) only to inline them
                let fits = inline > 0 && !page.inlined.contains(&b) && ctx.store.blob_len(&b)?.is_some_and(|n| n <= inline) && !self.peer_holds_blob(ctx, conn, &b);
                let blob = if fits { ctx.ground.bytes(ctx.store, &b)? } else { None };
                let inlined = blob.is_some();
                Some((s, Event::Added { blob_id: b, blob, wrap: entry.wrap, stamp: entry.stamp }, inlined))
            }
            NodeEvent::Deleted { sync_id, blob, .. } => Some((sync_id, Event::Deleted(blob), false)),
            NodeEvent::Head(s) => ctx.store.head(&s)?.map(|st| (s, Event::Head(st), false)),
        })
    }

    /// What a message served on `conn` offers its peer again (spec/sync-streams.md §4 Refused):
    /// the refusals the peer's source sent of each entry it carries an event of, and of every
    /// entry of each member listed from the start (`from_start`), end. Reads one row per sync
    /// ID it carries; writes only where a refusal stood.
    fn offered(&mut self, ctx: &mut Ctx, conn: ConnId, events: &[(SyncId, Event)], from_start: &[SyncId]) {
        let src = self.source(ctx.shared, conn);
        let mut refusing: BTreeMap<SyncId, bool> = BTreeMap::new();
        let mut ops = Vec::new();
        for s in from_start {
            if *refusing.entry(*s).or_insert_with(|| self.known.refusing(src, s)) {
                ops.push((src, Op::Lift(*s, None)));
            }
        }
        for (s, e) in events {
            let (Event::Added { blob_id: b, .. } | Event::Deleted(b)) = e else { continue };
            if !from_start.contains(s) && *refusing.entry(*s).or_insert_with(|| self.known.refusing(src, s)) {
                ops.push((src, Op::Lift(*s, Some(*b))));
            }
        }
        if !ops.is_empty() {
            self.save(ctx, src, &[], false, ops);
        }
    }

    /// Whether the peer on `conn` holds blob `b` under some sync ID: its stream showed it under one
    /// naming the blob here (`known`), or its bytes went to it inline on this connection in a
    /// message not reported applied yet. Its bytes go to it inline under no sync ID (spec/wire.md
    /// §11.2 Pull): a blob several sync IDs carry (a key record, a commit under its thing's unit
    /// and its admin's) crosses a connection once; the peer takes another entry of it with the
    /// bytes it holds (spec/sync-streams.md §4 Bodies).
    fn peer_holds_blob(&self, ctx: &Ctx, conn: ConnId, b: &BlobId) -> bool {
        if self.serve.get(&conn).is_some_and(|x| x.inlined.contains_key(b)) {
            return true;
        }
        let src = self.source(ctx.shared, conn);
        ctx.store.naming(b).unwrap_or_default().iter().any(|s| self.knows(src, Some(conn), s, b))
    }

    /// The ephemeral listing (spec/wire.md §11.2 Pull `ephemeral`): each listed member's memory
    /// events after where its listing stands, with their bytes, while the page has room. `moved`:
    /// only those members (the ones with memory events since the mark, at a push), else all.
    fn ephemeral(&mut self, ctx: &mut Ctx, conn: ConnId, page: &mut Page, members: &impl Members, moved: Option<&BTreeSet<SyncId>>) -> Result<()> {
        let listing: Vec<(SyncId, u64)> = match (self.serve.get(&conn), moved) {
            (None, _) => Vec::new(),
            (Some(x), None) => x.eph.iter().map(|(s, n)| (*s, *n)).collect(),
            (Some(x), Some(m)) => m.iter().filter_map(|s| Some((*s, *x.eph.get(s)?))).collect(),
        };
        // no ephemeral entry is a role entry: a peer holding S's thing as a stub is listed none
        let listing: Vec<(SyncId, u64)> = listing.into_iter().filter(|(s, _)| members.until(s) == Some(None) && !as_stub(ctx, conn, s)).collect();
        self.work.members += listing.len() as u64;
        for (s, mut at) in listing {
            loop {
                let (evs, last) = ctx.store.read_memory(&s, at, CHUNK);
                if evs.is_empty() {
                    page.eph.insert(s, last);
                    break;
                }
                for (n, b, present) in evs {
                    if present && self.serve.get(&conn).is_some_and(|x| x.counts(&s, &b, At::Memory(n))) {
                        at = n;
                        continue;
                    }
                    let ev = if present {
                        let (Some(entry), Some(bytes)) = (ctx.store.entry(&s, &b)?, ctx.ground.bytes(ctx.store, &b)?) else {
                            at = n;
                            continue;
                        };
                        let shown = page.inlined.contains(&b) || self.peer_holds_blob(ctx, conn, &b);
                        Event::Added { blob_id: b, blob: (!shown).then_some(bytes), wrap: entry.wrap, stamp: entry.stamp }
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
        // a log naming no position holds ephemeral entries back (no Stream carries events without
        // a cursor): they are read again once the log moves, not at every call
        let mem_moved = self.serve.get(&conn).is_some_and(|s| s.mem_mark != mark) && (f.cursor.is_some() || end > f.pos);
        // the shared set now, read per event: a push costs its events, not the members
        let shared = ctx.shared;
        let members = shared.members(conn);
        let mut acted = false;
        if end > f.pos || mem_moved {
            let mut page = Page::new(REPLY_BUDGET as u64, 0);
            let read = if end > f.pos { self.read_into(ctx, conn, &mut page, members, None, f.cursor.clone(), f.pos)? } else { Read { cursor: f.cursor.clone(), pos: f.pos, more: false } };
            if mem_moved {
                let since = self.serve.get(&conn).map_or(0, |s| s.mem_mark);
                let moved: BTreeSet<SyncId> = ctx.store.memory_since(since).into_iter().map(|(_, s)| s).collect();
                self.ephemeral(ctx, conn, &mut page, members, Some(&moved))?;
            }
            if page.events.is_empty() {
                let s = self.serve.entry(conn).or_default();
                s.follow = Some(Follow { cursor: read.cursor, pos: read.pos, seq: f.seq });
                s.followed_to(read.pos);
                if !page.full {
                    s.mem_mark = mark;
                }
                s.eph.extend(page.eph);
            } else {
                // a log naming no position yet holds ephemeral entries back (no Stream carries
                // events without a cursor): they go once it has one
                let Some(at) = read.cursor.clone() else { return Ok(acted) };
                let at = fresh(ctx, at)?;
                let events = page.events.clone();
                let st = Stream { events: page.events, cursor: wire_cursor(&Some(at.clone())), report: true, seq: f.seq };
                if !ctx.wire.push(conn, Msg::Stream(Box::new(st))) {
                    return Ok(false);
                }
                self.offered(ctx, conn, &events, &[]);
                let s = self.serve.entry(conn).or_default();
                s.follow = Some(Follow { cursor: read.cursor, pos: read.pos, seq: f.seq + 1 });
                s.followed_to(read.pos);
                s.served(&events, at);
                s.streamed();
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
            let Some(at) = f.cursor.clone() else { break };
            let at = fresh(ctx, at)?;
            let st = Stream { events: Vec::new(), cursor: wire_cursor(&Some(at.clone())), report: true, seq: f.seq };
            if !ctx.wire.push(conn, Msg::Stream(Box::new(st))) {
                break;
            }
            let serve = self.serve.entry(conn).or_default();
            serve.served(&[], at);
            serve.streamed();
            serve.told_until.insert(*s);
            if let Some(x) = serve.follow.as_mut() {
                x.seq += 1;
            }
            acted = true;
            break;
        }
        Ok(acted)
    }

    /// The connection's part of the peer having pulled this side's stream to its end
    /// (spec/sync-status.md §1): its last Pull was answered to the end and is followed.
    pub(super) fn followed(&self, conn: ConnId) -> bool {
        self.serve.get(&conn).is_some_and(|x| x.follow.is_some())
    }

    /// Reads the log past the follow cursor on `conn` for the members it holds events of
    /// (`unpushed`), from where the last read stopped: O(events logged since).
    pub(super) fn scan_unpushed(&mut self, ctx: &Ctx, conn: ConnId) -> Result<()> {
        let Some(x) = self.serve.get(&conn) else { return Ok(()) };
        let Some(f) = &x.follow else { return Ok(()) };
        let (end, _) = ctx.store.log_bounds()?;
        let (mut cursor, mut pos) = match &x.scanned {
            Some((c, p)) if *p > f.pos => (c.clone(), *p),
            _ => (f.cursor.clone(), f.pos),
        };
        if end <= pos {
            return Ok(());
        }
        let members = ctx.shared.members(conn);
        let mut found = Vec::new();
        loop {
            let r = ctx.store.read_log(members, cursor.as_ref(), CHUNK)?;
            self.work.served += r.events.len() as u64;
            for e in &r.events {
                found.push((e.event.sync_id(), e.pos));
                pos = pos.max(e.pos);
            }
            cursor = r.cursor;
            if !r.more {
                break;
            }
        }
        let Some(x) = self.serve.get_mut(&conn) else { return Ok(()) };
        x.unpushed.extend(found);
        x.scanned = Some((cursor, end.max(pos)));
        Ok(())
    }

    /// The members the peer on `conn` has not yet applied all of (spec/sync-status.md §1): an
    /// event of S served and not reported applied, logged and not pushed, listed in memory and
    /// not sent, a join of S left to read on, or S joined and not read for the peer since.
    pub(super) fn served_busy(&self, ctx: &Ctx, conn: ConnId, out: &mut BTreeSet<SyncId>) {
        let Some(x) = self.serve.get(&conn) else { return };
        out.extend(x.unapplied.keys().copied());
        out.extend(x.unpushed.keys().copied());
        out.extend(x.joins_left.iter().copied());
        out.extend(x.unjoined.iter().copied());
        let members = ctx.shared.members(conn);
        for (n, s) in ctx.store.memory_since(x.mem_mark) {
            if x.eph.get(&s).is_some_and(|at| *at < n) && members.until(&s) == Some(None) {
                out.insert(s);
            }
        }
    }

    /// An Applied: the requester stored this cursor (spec/sync-opens.md §6 reported positions),
    /// and holds what the messages it covers sent it but what it told it does not
    /// (`count_applied`); `anchor` is a position of its own log at or past its events of them.
    pub(super) fn on_applied(&mut self, ctx: &mut Ctx, conn: ConnId, cursor: Cursor, anchor: Option<Cursor>) {
        let Ok(Some(pos)) = ctx.store.position(&cursor) else { return };
        let serve = self.serve.entry(conn).or_default();
        let sent = serve.reported_by(&cursor);
        if serve.applied.is_none_or(|p| p < pos) {
            serve.applied = Some(pos);
            ctx.reported.push(Reported::Stream(conn, pos, cursor));
        }
        // what the peer counts this node holding at or below where it applied (its ephemeral
        // listing read past) is served it no more on this connection
        let eph = serve.eph.clone();
        serve.counted.retain(|(s, _), m| match m {
            At::Log(mark) => *mark > pos,
            At::Memory(mark) => eph.get(s).is_none_or(|n| *mark > *n + 1),
        });
        self.count_applied(ctx, conn, sent, anchor);
        let serve = self.serve.entry(conn).or_default();
        // a merge is covered by message order, never by position: an Applied of a message sent
        // before the merging reply may name the very position the merge stood at
        let r = serve.reported;
        let merged: Vec<SyncId> = serve.merging.iter().filter(|(_, n)| **n <= r).map(|(s, _)| *s).collect();
        for s in merged {
            serve.merging.remove(&s);
            serve.own.remove(&s);
            ctx.reported.push(Reported::Merged(conn, s));
        }
    }

    /// A member joined, as server: one opened after the first Pull is not caught up until a
    /// reply reads it for the peer (it has no reported position until a join names it:
    /// `Positions::opened`).
    pub(super) fn served_joined(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        if let Some(serve) = self.serve.get_mut(&conn)
            && serve.pulled
        {
            serve.own.insert(s);
            serve.unjoined.insert(s);
        }
        self.served_ending(ctx, conn, s);
    }

    /// A member left, as server: a later join is another, reported afresh.
    pub(super) fn served_left(&mut self, conn: ConnId, s: &SyncId) {
        let Some(serve) = self.serve.get_mut(&conn) else { return };
        serve.listing.remove(s);
        serve.named.remove(s);
        serve.merging.remove(s);
        serve.unapplied.remove(s);
        serve.unpushed.remove(s);
        serve.joins_left.remove(s);
        serve.unjoined.remove(s);
        serve.own.remove(s);
        serve.eph.remove(s);
        serve.ending.remove(s);
        serve.told_until.remove(s);
    }

    /// Member S's `until` was set or cleared (or S joined).
    pub(super) fn served_ending(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let ended = ctx.shared.members(conn).get(&s).is_some_and(|m| m.until.is_some());
        let serve = self.serve.entry(conn).or_default();
        // the log past the follow cursor is read again for the shared set now (`scan_unpushed`)
        serve.scanned = None;
        serve.told_until.remove(&s);
        if ended {
            serve.ending.insert(s);
        } else {
            serve.ending.remove(&s);
        }
    }

    /// A Fetch (spec/wire.md §11.2 Fetch): each ID's entry of its sync ID with its bytes, in
    /// request order, a prefix of them within `max_reply`; none for one not held, of a sync ID not
    /// shared here, or (an ended member) first logged past its `until`.
    pub(super) fn on_fetch(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, max_reply: u64, ids: Vec<(SyncId, Vec<BlobId>)>) {
        let mut left = (max_reply as usize).min(REPLY_BUDGET).saturating_sub(OVERHEAD);
        let mut items = Vec::new();
        for (s, b) in ids.into_iter().flat_map(|(s, bs)| bs.into_iter().map(move |b| (s, b))) {
            let until = ctx.shared.members(conn).get(&s).map(|m| m.until);
            let entry = match until {
                None => None,
                Some(u) => self.fetchable(ctx, conn, &s, &b, u).ok().flatten(),
            };
            let n = entry.as_ref().map_or(40, |(v, ..)| v.len() + 200);
            if n > left && !items.is_empty() {
                break;
            }
            left = left.saturating_sub(n);
            items.push(Fetched { blob_id: b, entry });
        }
        ctx.wire.answer(conn, id, Msg::FetchReply { id, items });
    }

    /// A Want (spec/wire.md §11.2 Want; spec/sync-judgement.md §3 Asked by ID): for each commit, in
    /// request order, an entry of its body under its sync ID this node holds or makes, a prefix of
    /// them within `max_reply`; none under a sync ID not shared here, not read here, or open to a
    /// peer holding it as a stub.
    pub(super) fn on_want(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, max_reply: u64, ids: Vec<(SyncId, Vec<osis_base::CommitId>)>) {
        let mut left = (max_reply as usize).min(REPLY_BUDGET).saturating_sub(OVERHEAD);
        let mut items = Vec::new();
        for (s, c) in ids.into_iter().flat_map(|(s, cs)| cs.into_iter().map(move |c| (s, c))) {
            let open = ctx.shared.members(conn).contains_key(&s) && ctx.store.holding(&s) == Some(Holding::Read) && !as_stub(ctx, conn, &s);
            let entry = if open { ctx.ground.want(ctx.store, &s, &c).ok().flatten() } else { None };
            let n = entry.as_ref().map_or(40, |(v, ..)| v.len() + 200);
            if n > left && !items.is_empty() {
                break;
            }
            left = left.saturating_sub(n);
            items.push(osis_proto::WantedItem { commit: c, entry });
        }
        osis_base::costs::count("streams: wanted answered", items.iter().filter(|w| w.entry.is_some()).count() as u64);
        ctx.wire.answer(conn, id, Msg::Wanted { id, items });
    }

    fn fetchable(&self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, b: &BlobId, until: Option<Position>) -> Result<Option<Body>> {
        let Some(e) = ctx.store.entry(s, b)? else { return Ok(None) };
        if !shown(ctx, conn, s, &e) {
            return Ok(None);
        }
        if let Some(u) = until
            && ctx.store.first_logged(s, b)?.is_none_or(|f| f > u)
        {
            return Ok(None);
        }
        Ok(ctx.ground.bytes(ctx.store, b)?.map(|v| (v, e.wrap, e.stamp)))
    }
}
