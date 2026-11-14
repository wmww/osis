//! The pulling side of a stream (spec/sync-streams.md §4 Joining, Pushes, Flow control, Applying,
//! Bodies, Fill order, Full, Refused, Reports; §5 First sync): Pulls with the stream's cursor and
//! its joins, messages applied in order once their bodies are held, the cursor stored only then,
//! `seq` checked and a gap read again, bodies fetched one source at a time in the fill order.

use super::known::{self, Op};
use super::{ASKED_MS, Ctx, FETCHES_OUT, INLINE_LIMIT, Opening, PENDING_CAP, RESYNC_MS, Rank, Refusal, Streams};
use crate::opens::Rejoin;
use crate::store::rows::tag::{AT_STREAM, CURSOR, JOINING, STOPPED};
use crate::store::{Source, Store};
use crate::types::{ConnId, Cursor, Entry, RecordId, Result};
use osis_store::Transaction;
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, SyncId, WallMs};
use osis_engine::sync::Holding;
use osis_label::{Class, Prefix};
use osis_proto::limits::{MAX_FETCH_IDS, REPLY_BUDGET};
use osis_proto::{Code, Event, Fetched, Id, Msg, Pull, PullReply, Stamp, Stream, Wrap};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Where this node stands in one source's log: what it stored (spec/sync-opens.md §3: the
/// stream's cursor, each member at it or joining from its own position, where members that left
/// stopped).
#[derive(Clone, Debug, Default)]
pub(super) struct Place {
    pub cursor: Option<Cursor>,
    /// Stamped: status follows a member's caught up per (source, S) (`Streams::caught_up`).
    pub at_stream: StampedSet<SyncId>,
    pub joining: Stamped<SyncId, Option<Cursor>>,
    pub stopped: BTreeMap<SyncId, Option<Cursor>>,
}

impl Place {
    /// S goes from this place (its rows went with the shred).
    pub(super) fn forget(&mut self, s: &SyncId) {
        if self.at_stream.contains(s) {
            self.at_stream.remove(s);
        }
        if self.joining.contains_key(s) {
            self.joining.remove(s);
        }
        self.stopped.remove(s);
    }
}

fn opt_cursor(c: &Option<Cursor>) -> Vec<u8> {
    match c {
        Some(c) => [&[1u8][..], c].concat(),
        None => vec![0],
    }
}

fn read_cursor(v: &[u8]) -> std::result::Result<Option<Cursor>, osis_store::Error> {
    match v.split_first() {
        Some((0, [])) => Ok(None),
        Some((1, c)) => Ok(Some(c.to_vec())),
        _ => Err(osis_store::Error::Corrupt("streams place row")),
    }
}

impl Place {
    /// Record `rec`'s place as its rows hold it. O(its members and those that left).
    fn load(t: &mut Transaction<'_>, rec: &RecordId) -> std::result::Result<Place, osis_store::Error> {
        let mut p = Place::default();
        if let Some(v) = t.record_get_wide_row(rec, CURSOR, b"")? {
            p.cursor = read_cursor(&v)?;
        }
        for (s, ..) in t.record_tag_rows(rec, AT_STREAM)? {
            p.at_stream.insert(s);
        }
        for (s, _, v) in t.record_tag_rows(rec, JOINING)? {
            p.joining.insert(s, read_cursor(&v)?);
        }
        for (s, _, v) in t.record_tag_rows(rec, STOPPED)? {
            p.stopped.insert(s, read_cursor(&v)?);
        }
        Ok(p)
    }

    /// Writes member S's place into record `rec`'s rows as memory holds it.
    fn write(&self, t: &mut Transaction<'_>, rec: &RecordId, s: &SyncId) -> std::result::Result<(), osis_store::Error> {
        if self.at_stream.contains(s) {
            t.record_put_row(rec, AT_STREAM, s, b"", Vec::new())?;
        } else {
            t.record_remove_row(rec, AT_STREAM, s, b"")?;
        }
        match self.joining.get(s) {
            Some(c) => t.record_put_row(rec, JOINING, s, b"", opt_cursor(c))?,
            None => drop(t.record_remove_row(rec, JOINING, s, b"")?),
        }
        match self.stopped.get(s) {
            Some(c) => t.record_put_row(rec, STOPPED, s, b"", opt_cursor(c)),
            None => t.record_remove_row(rec, STOPPED, s, b"").map(drop),
        }
    }
}

/// A join on this connection: its generation (a join after a member left and opened again is
/// another), and the cursor to name next.
#[derive(Clone, Debug)]
struct Join {
    generation: u64,
    cursor: Option<Cursor>,
}

/// A message in hand: applied once every body it owes is settled.
#[derive(Clone, Debug)]
struct Batch {
    events: Vec<(SyncId, Event)>,
    cursor: Option<Cursor>,
    report: bool,
    reply: Option<ReplyInfo>,
    owed: Vec<(SyncId, BlobId)>,
}

#[derive(Clone, Debug)]
struct ReplyInfo {
    whole: bool,
    more: bool,
    joins: BTreeMap<SyncId, Option<Cursor>>,
    asked: Vec<(SyncId, u64)>,
}

#[derive(Clone, Debug)]
pub(super) struct Pulling {
    pub src: Source,
    /// The Pull out, with the joins it named.
    out: Option<(Id, Vec<(SyncId, u64)>)>,
    first_sent: bool,
    eph_next: bool,
    /// The latest cursor received (applied or in hand): what the next Pull names.
    recv: Option<Cursor>,
    joins: BTreeMap<SyncId, Join>,
    generation: u64,
    /// Streams with a cursor taken since the last PullReply.
    seq: u64,
    gap: bool,
    more: bool,
    quiet: bool,
    pending: VecDeque<Batch>,
    fetches: BTreeMap<Id, (SyncId, Vec<BlobId>, u8)>,
    queue: BTreeMap<(u8, u64, u64), (SyncId, BlobId)>,
    arrivals: u64,
    /// What this source answered without, until it announces it again.
    failed: BTreeSet<BlobId>,
    /// Bodies settled (taken, opened, refused) while messages are in hand.
    pub(super) settled: BTreeSet<(SyncId, BlobId)>,
    retry_at: Option<WallMs>,
    rejoin_at: BTreeMap<SyncId, WallMs>,
    inline: u64,
    pub(super) inline_check: bool,
    /// A whole listing from the start (trimmed or not) under way: what it listed so far.
    listing: Option<BTreeMap<SyncId, BTreeSet<BlobId>>>,
    /// Joins from the start under way: what each listed so far.
    join_listing: BTreeMap<SyncId, BTreeSet<BlobId>>,
    /// Full and Refused events to tell the source.
    tell: Vec<(SyncId, Event)>,
    told_full: BTreeSet<SyncId>,
    applied_owed: Option<Cursor>,
    /// When the Pull out was sent, and when the one the last reply answered was: a stream caught
    /// up since a moment read its end from a Pull sent after it (spec/sync-status.md §1).
    out_at: WallMs,
    pub(super) answered_at: WallMs,
    /// A Pull is wanted though nothing else is due (a complete pass, `Streams::pull_again`).
    pub(super) again: bool,
}

impl Pulling {
    fn new(src: Source, cursor: Option<Cursor>) -> Pulling {
        Pulling {
            src,
            out: None,
            first_sent: false,
            eph_next: false,
            recv: cursor,
            joins: BTreeMap::new(),
            generation: 0,
            seq: 0,
            gap: false,
            more: false,
            quiet: false,
            pending: VecDeque::new(),
            fetches: BTreeMap::new(),
            queue: BTreeMap::new(),
            arrivals: 0,
            failed: BTreeSet::new(),
            settled: BTreeSet::new(),
            retry_at: None,
            rejoin_at: BTreeMap::new(),
            inline: INLINE_LIMIT,
            inline_check: false,
            listing: None,
            join_listing: BTreeMap::new(),
            tell: Vec::new(),
            told_full: BTreeSet::new(),
            applied_owed: None,
            out_at: WallMs(0),
            answered_at: WallMs(0),
            again: false,
        }
    }

    /// SN_rearm: caught up only with the last reply at the end, no Pull out (a change announced
    /// during one denies it), no gap and nothing in hand.
    pub(super) fn caught_up(&self) -> bool {
        self.quiet && self.out.is_none() && !self.gap && self.pending.is_empty()
    }

    pub(super) fn holding(&self) -> usize {
        self.pending.len() + self.queue.len() + self.failed.len() + self.settled.len() + self.tell.len()
    }

    pub(super) fn wake(&self) -> Option<WallMs> {
        self.retry_at.into_iter().chain(self.rejoin_at.values().copied()).min()
    }

    fn join(&mut self, s: SyncId, cursor: Option<Cursor>) {
        // a join from the start lists S's live set at the source
        if cursor.is_none() {
            self.join_listing.insert(s, BTreeSet::new());
        } else {
            self.join_listing.remove(&s);
        }
        self.generation += 1;
        self.joins.insert(s, Join { generation: self.generation, cursor });
        self.rejoin_at.remove(&s);
    }
}

/// A body's fill-order class (spec/sync-streams.md §4 Fill order, §5): order 0, deposited
/// entries that do not open, the highest order, the rest; and the key within it.
fn class(rank: Rank, deposited: bool) -> Option<(u8, u64)> {
    match rank {
        Rank::Order(0) => Some((0, 0)),
        Rank::Unopened if deposited => Some((1, 0)),
        Rank::Order(n) => Some((2, u64::MAX - n)),
        Rank::Unopened => Some((3, 0)),
        Rank::Never => None,
    }
}

fn entry_of(b: BlobId, wrap: Wrap, stamp: Option<Stamp>, bytes: &[u8]) -> Entry {
    let (class, expires) = Prefix::parse(bytes).map_or((Class::Durable, None), |p| (p.class(), p.expiry()));
    Entry { blob: b, wrap, stamp, deposited: stamp.is_none(), own: false, role: false, class, expires }
}

impl Streams {
    /// The source's place, held in memory while a connection pulls from it: a record's read from
    /// its rows first. Never one of a shredded S (`forget_shredded`).
    fn place(&mut self, store: &Store, src: Source) -> &mut Place {
        self.forget_shredded();
        if !self.places.contains_key(&src) {
            let p = match src {
                Source::Record(rec) => match store.with_read(|t| Place::load(t, &rec)) {
                    Ok(p) => p,
                    Err(e) => {
                        self.failed(Err(e));
                        Place::default()
                    }
                },
                Source::Conn(_) => Place::default(),
            };
            self.places.insert(src, p);
        }
        self.places.entry(src).or_default()
    }

    /// Makes durable what moved: `ops` of what sources showed, the place of each of `ss` and,
    /// with `cursor`, the stream's cursor, in one transaction for a record source (the one
    /// applying what they cover); a connection's in memory. Whether it was written (a store
    /// failure fails the step at its settle).
    pub(super) fn save(&mut self, ctx: &mut Ctx, src: Source, ss: &[SyncId], cursor: bool, ops: Vec<(Source, Op)>) -> bool {
        let (rec_ops, conn_ops): (Vec<_>, Vec<_>) = ops.into_iter().partition(|(at, _)| matches!(at, Source::Record(_)));
        for (at, op) in conn_ops {
            self.known.apply_conn(at, std::slice::from_ref(&op));
            self.known.logged(at, &op);
        }
        if rec_ops.is_empty() && !matches!(src, Source::Record(_)) {
            return true;
        }
        let place = self.places.get(&src);
        let r = ctx.store.with_tx(|t| {
            for (at, op) in &rec_ops {
                if let Source::Record(rec) = at {
                    known::write(t, rec, op)?;
                }
            }
            if let (Source::Record(rec), Some(p)) = (src, place) {
                for s in ss {
                    p.write(t, &rec, s)?;
                }
                if cursor {
                    t.record_put_wide_row(&rec, CURSOR, b"", opt_cursor(&p.cursor))?;
                }
            }
            Ok(())
        });
        let ok = r.is_ok();
        if ok {
            for (at, op) in &rec_ops {
                self.known.logged(*at, op);
            }
        }
        self.failed(r);
        ok
    }

    /// A member joined: from where opens says, else where this side's record holds it, else from
    /// the start; none for a member at the stream's cursor (spec/sync-streams.md §4 Joining).
    pub(super) fn joined(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, rejoin: Rejoin) {
        let src = self.source(ctx.shared, conn);
        let cursor = self.place(ctx.store, src).cursor.clone();
        self.pull.entry(conn).or_insert_with(|| Pulling::new(src, cursor));
        let place = self.place(ctx.store, src);
        let from = match rejoin {
            Rejoin::From(c) => Some(c),
            Rejoin::Held => {
                if let Some(c) = place.stopped.get(&s) {
                    Some(c.clone())
                } else if let Some(c) = place.joining.get(&s) {
                    Some(c.clone())
                } else if place.at_stream.contains(&s) {
                    None
                } else {
                    Some(None)
                }
            }
        };
        // a join's cursor is its place from now on, durably: a restart joins from it again
        let Some(c) = from else { return };
        place.stopped.remove(&s);
        place.at_stream.remove(&s);
        if place.joining.get(&s) != Some(&c) {
            place.joining.insert(s, c.clone());
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.join(s, c);
            p.quiet = false;
        }
        self.save(ctx, src, &[s], false, Vec::new());
    }

    /// A member left: its stream stops where it stands (its stored position kept for its rejoin);
    /// a sync ID the node no longer holds leaves no position and no `known`.
    pub(super) fn left(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        p.joins.remove(&s);
        p.rejoin_at.remove(&s);
        let src = p.src;
        let held = ctx.store.holding(&s).is_some();
        let place = self.place(ctx.store, src);
        let at = if let Some(c) = place.joining.remove(&s) {
            Some(c)
        } else if place.at_stream.remove(&s) {
            Some(place.cursor.clone())
        } else {
            None
        };
        let mut ops = Vec::new();
        if !held {
            place.stopped.remove(&s);
            ops.push((src, Op::Forget(s)));
            ops.push((Source::Conn(conn), Op::Forget(s)));
        } else if let Some(c) = at {
            place.stopped.insert(s, c);
        }
        self.save(ctx, src, &[s], false, ops);
    }

    /// Whatever is due on a connection: messages applied, fetches and a Pull sent, refusals told.
    pub(super) fn run(&mut self, ctx: &mut Ctx, conn: ConnId) {
        if !self.pull.contains_key(&conn) {
            return;
        }
        self.drain(ctx, conn);
        self.fetch(ctx, conn);
        let Some(p) = self.pull.get_mut(&conn) else { return };
        if !p.tell.is_empty() {
            let st = Stream { events: p.tell.clone(), cursor: None, report: false, seq: 0 };
            if ctx.wire.push(conn, Msg::Stream(Box::new(st))) {
                p.tell.clear();
            }
        }
        if let Some(c) = p.applied_owed.clone()
            && let Ok(cursor) = osis_proto::Cursor::new(c)
            && ctx.wire.push(conn, Msg::Applied { cursor })
        {
            p.applied_owed = None;
        }
        self.send_pull(ctx, conn);
    }

    /// Sends the next Pull when one is due: the first, a page on, a join, a gap or a dropped
    /// push to read again, a change of `inline_limit` (spec/sync-streams.md §4). None before
    /// agreement, while one is out, or while the messages in hand reach the local bound.
    fn send_pull(&mut self, ctx: &mut Ctx, conn: ConnId) {
        if !ctx.shared.agreed(conn) {
            return;
        }
        let members = ctx.shared.members(conn);
        let Some(p) = self.pull.get_mut(&conn) else { return };
        // refusals not told yet hold the stream like messages in hand: what a peer makes this side
        // owe it stays bounded
        // an Applied goes before the next Pull: the server reads a reported position as covering
        // only what came before the Pull (a join merging there is not yet stored)
        if p.out.is_some() || p.pending.len() >= PENDING_CAP || !p.tell.is_empty() || p.applied_owed.is_some() || members.is_empty() || p.retry_at.is_some_and(|t| t > ctx.now) {
            return;
        }
        p.retry_at = None;
        // a join refused while S stays a member is joined again `resync_ms` later
        let due: Vec<SyncId> = p.rejoin_at.iter().filter(|(s, t)| **t <= ctx.now && members.contains_key(*s)).map(|(s, _)| *s).collect();
        p.rejoin_at.retain(|s, t| *t > ctx.now && members.contains_key(s));
        for s in due {
            let c = self.places.get(&p.src).and_then(|pl| pl.joining.get(&s).cloned()).flatten();
            p.join(s, c);
        }
        let mut inline_moved = false;
        if p.inline_check {
            p.inline_check = false;
            self.work.members += members.len() as u64;
            let many = members.keys().any(|s| self.holders.get(s).is_some_and(|h| h.len() > 1));
            let want = if many { 0 } else { INLINE_LIMIT };
            inline_moved = want != p.inline && p.first_sent;
            p.inline = want;
        }
        if p.first_sent && !p.more && !p.gap && !p.eph_next && p.joins.is_empty() && !inline_moved && !p.again {
            return;
        }
        let joins: Vec<(SyncId, Option<osis_proto::Cursor>)> = p.joins.iter().map(|(s, j)| (*s, j.cursor.clone().and_then(|c| osis_proto::Cursor::new(c).ok()))).collect();
        let asked = p.joins.iter().map(|(s, j)| (*s, j.generation)).collect();
        let pull = Pull { id: 0, cursor: p.recv.clone().and_then(|c| osis_proto::Cursor::new(c).ok()), joins, inline_limit: p.inline, max_reply: REPLY_BUDGET as u64, follow: true, ephemeral: !p.first_sent || p.eph_next };
        let Some(id) = ctx.wire.request(conn, Msg::Pull(Box::new(pull))) else { return };
        p.first_sent = true;
        p.eph_next = false;
        p.again = false;
        p.quiet = false;
        p.out = Some((id, asked));
        p.out_at = ctx.now;
    }

    /// A reply to a request of this side's: a PullReply (or a Pull refused or skipped), a
    /// FetchReply.
    pub(super) fn on_reply(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, m: Msg) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        if p.fetches.contains_key(&id) {
            let items = match m {
                Msg::FetchReply { items, .. } => items,
                _ => Vec::new(),
            };
            self.fetched(ctx, conn, id, items);
            return;
        }
        if p.out.as_ref().is_none_or(|(x, _)| *x != id) {
            return;
        }
        let (_, asked) = p.out.take().unwrap_or_default();
        match m {
            Msg::PullReply(r) => self.on_pull_reply(ctx, conn, *r, asked),
            _ => p.retry_at = Some(WallMs(ctx.now.0.saturating_add(RESYNC_MS))),
        }
    }

    fn on_pull_reply(&mut self, ctx: &mut Ctx, conn: ConnId, r: PullReply, asked: Vec<(SyncId, u64)>) {
        let members = ctx.shared.members(conn);
        let Some(p) = self.pull.get_mut(&conn) else { return };
        p.seq = 0;
        p.gap = false;
        p.more = r.more;
        p.quiet = !r.more;
        p.answered_at = p.out_at;
        if r.cursor.is_some() || r.whole {
            p.recv = r.cursor.clone().map(osis_proto::Cursor::into_bytes);
        }
        let joins: BTreeMap<SyncId, Option<Cursor>> = r.joins.iter().map(|(s, c)| (*s, c.clone().map(osis_proto::Cursor::into_bytes))).collect();
        for (s, generation) in &asked {
            let ours = p.joins.get(s).is_some_and(|j| j.generation == *generation);
            match joins.get(s) {
                // still in pages: name it again from its own cursor (SN_joindur)
                Some(Some(c)) if !r.whole => {
                    if let Some(j) = p.joins.get_mut(s).filter(|_| ours) {
                        j.cursor = Some(c.clone());
                    }
                }
                // not shared there (SN_joinans): out of the stream, joined again later
                Some(None) => {
                    if ours {
                        p.joins.remove(s);
                        if members.contains_key(s) {
                            p.rejoin_at.insert(*s, WallMs(ctx.now.0.saturating_add(RESYNC_MS)));
                        }
                    }
                }
                _ => {
                    if ours {
                        p.joins.remove(s);
                    }
                }
            }
        }
        let info = ReplyInfo { whole: r.whole, more: r.more, joins, asked };
        let batch = Batch { events: r.events, cursor: r.cursor.map(osis_proto::Cursor::into_bytes), report: r.report, reply: Some(info), owed: Vec::new() };
        self.stage(ctx, conn, batch);
    }

    /// A Stream: with no cursor, Full and Refused events (and relay-only entries, not built);
    /// with one, applied only in `seq` order since the last PullReply, else a gap read again at
    /// the next PullReply (spec/sync-streams.md §4 Pushes).
    pub(super) fn on_stream(&mut self, ctx: &mut Ctx, conn: ConnId, st: Stream) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let src = p.src;
        let Some(cursor) = st.cursor else {
            // kept only for members and entries held here: a peer's word on anything else is
            // nothing this side keeps
            let members = ctx.shared.members(conn);
            let mut ops = Vec::new();
            for (s, e) in st.events {
                if !members.contains_key(&s) {
                    continue;
                }
                match e {
                    Event::Full(f) => ops.push((src, Op::Full(s, f))),
                    // code 6 counts as the entry deleted there
                    Event::Refused(b, Code::TOMBSTONED) => {
                        ops.push((src, Op::Remove(s, b)));
                        // a store failure loses this row only: the next delete seen there writes it again
                        let _ = ctx.store.saw_deleted(src, &s, &b);
                    }
                    Event::Refused(b, code) => {
                        let Ok(Some(e)) = ctx.store.entry(&s, &b) else { continue };
                        let head = self.known.head(src, &s);
                        ops.push((src, Op::Refused(s, b, Refusal { code, stamp: e.stamp, head })));
                    }
                    _ => {}
                }
            }
            if !ops.is_empty() {
                self.save(ctx, src, &[], false, ops);
            }
            return;
        };
        if p.gap || st.seq != p.seq || p.pending.len() >= PENDING_CAP {
            p.gap = true;
            p.eph_next = true;
            return;
        }
        p.seq += 1;
        p.recv = Some(cursor.as_bytes().to_vec());
        let batch = Batch { events: st.events, cursor: Some(cursor.into_bytes()), report: st.report, reply: None, owed: Vec::new() };
        self.stage(ctx, conn, batch);
    }

    /// Takes a message in hand: bodies that came inline are taken now, those announced without
    /// bytes that this node lacks and wants are owed and queued for fetching.
    fn stage(&mut self, ctx: &mut Ctx, conn: ConnId, mut batch: Batch) {
        let members: BTreeSet<SyncId> = batch.events.iter().map(|(s, _)| *s).filter(|s| ctx.shared.members(conn).contains_key(s)).collect();
        for (s, e) in &batch.events {
            let Event::Added { blob_id: b, blob, wrap, stamp } = e else { continue };
            if !members.contains(s) {
                continue;
            }
            if let Some(p) = self.pull.get_mut(&conn) {
                p.failed.remove(b);
            }
            if let Some(bytes) = blob {
                self.take_body(ctx, conn, *s, *b, *wrap, *stamp, bytes);
            } else if let Some(c) = self.wanted(ctx, conn, s, b, wrap, *stamp) {
                batch.owed.push((*s, *b));
                if let Some(p) = self.pull.get_mut(&conn)
                    && !p.queue.values().any(|x| *x == (*s, *b))
                {
                    p.arrivals += 1;
                    let key = (c.0, c.1, u64::MAX - p.arrivals);
                    p.queue.insert(key, (*s, *b));
                }
            }
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.pending.push_back(batch);
        }
        self.drain(ctx, conn);
    }

    /// Whether a body announced without bytes is to be fetched, and its fill-order class: only
    /// what this node lacks and may take (spec/sync-streams.md §4 Bodies); one held is taken now.
    fn wanted(&mut self, ctx: &mut Ctx, conn: ConnId, s: &SyncId, b: &BlobId, wrap: &Wrap, stamp: Option<Stamp>) -> Option<(u8, u64)> {
        let holding = ctx.store.holding(s)?;
        let held = ctx.store.bytes(b).ok().flatten();
        let tomb = ctx.store.tombstone(s, b).ok().flatten().is_some();
        match holding {
            Holding::Unread => {
                // a node keeping S unread takes stamped entries only, never one refused while full
                let stamp = stamp?;
                if self.room.get(s).is_some_and(|(_, r)| r.contains(b)) {
                    return None;
                }
                if tomb {
                    self.tell(conn, *s, Event::Refused(*b, Code::TOMBSTONED));
                    return None;
                }
                if let Some(bytes) = held {
                    self.take_body(ctx, conn, *s, *b, *wrap, Some(stamp), &bytes);
                    return None;
                }
                class(Rank::Unopened, false)
            }
            Holding::Read => {
                if tomb || held.is_some() {
                    return None;
                }
                class(ctx.ground.rank(s, b, wrap), stamp.is_none())
            }
        }
    }

    fn tell(&mut self, conn: ConnId, s: SyncId, e: Event) {
        if let Some(p) = self.pull.get_mut(&conn) {
            p.tell.push((s, e));
        }
    }

    /// A body's bytes arrived (inline or fetched): taken into the store (kept unread) or opened
    /// (read); settled for every stream owing it. Wrong bytes count as this source lacking it.
    #[allow(clippy::too_many_arguments)]
    fn take_body(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, b: BlobId, wrap: Wrap, stamp: Option<Stamp>, bytes: &[u8]) {
        if osis_label::blob_id(bytes) != b {
            if let Some(p) = self.pull.get_mut(&conn) {
                p.failed.insert(b);
            }
            return;
        }
        // a body crosses a connection once: its bytes are not sent back on it
        self.serve.entry(conn).or_default().crossed.insert(b);
        let e = entry_of(b, wrap, stamp, bytes);
        // a store or engine failure takes nothing: the body stays owed (no cursor passes it) and
        // the step fails
        match ctx.store.holding(&s) {
            Some(Holding::Unread) if stamp.is_some() => match ctx.store.take_stamped(&s, &e, bytes.to_vec()) {
                Ok(code) => self.refused(ctx, conn, s, b, code),
                Err(e) => return self.failed(Err(e)),
            },
            Some(Holding::Read) => match ctx.ground.open(&s, &e, bytes) {
                Ok(Opening::Bad) => {
                    if let Some(p) = self.pull.get_mut(&conn) {
                        p.failed.insert(b);
                    }
                    return;
                }
                // kept to open as secrets arrive, or as the carrier of its pending commit
                // (store::Follow), an unstamped one within the source's peer budget
                // (spec/sync-ids.md §5; spec/sync-streams.md §4 Fill order; spec/commits.md §4
                // Pending storage); one that can never open here is not kept, nor what pends
                // from one not kept
                Ok(o @ (Opening::Pends | Opening::NotOpen)) if o == Opening::Pends || ctx.ground.rank(&s, &b, &wrap) != Rank::Never => {
                    let src = self.pull.get(&conn).map(|p| p.src);
                    match ctx.store.log(&s, e, Some(bytes.to_vec()), src) {
                        Ok(Code::OK) => {}
                        Ok(_) if o == Opening::Pends => {
                            if let Err(e) = ctx.ground.unkept(ctx.store, &b) {
                                return self.failed(Err(e));
                            }
                        }
                        Ok(_) => {}
                        Err(e) => return self.failed(Err(e)),
                    }
                }
                Ok(_) => {}
                Err(e) => return self.failed(Err(e)),
            },
            _ => {}
        }
        for c in self.holders.get(&s).into_iter().flatten().chain(std::iter::once(&conn)) {
            if let Some(p) = self.pull.get_mut(c) {
                p.settled.insert((s, b));
                p.queue.retain(|_, x| *x != (s, b));
            }
        }
        if self.asked.get(&b).is_some_and(|(c, _)| *c == conn) {
            self.asked.remove(&b);
        }
    }

    /// What a node keeping S unread does with a pulled entry it did not take
    /// (spec/sync-streams.md §4 Full, Refused): for room it is full for S there, else it tells the
    /// refusal's code.
    fn refused(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, b: BlobId, code: Code) {
        match code {
            Code::OK | Code::DECLINED => {}
            Code::STORAGE_CAP => {
                let bytes = ctx.store.usage(&s).map_or(0, |(d, m)| d.bytes + m.bytes);
                let r = self.room.entry(s).or_default();
                r.0 = bytes;
                r.1.insert(b);
                if let Some(p) = self.pull.get_mut(&conn)
                    && p.told_full.insert(s)
                {
                    p.tell.push((s, Event::Full(true)));
                }
            }
            c => self.tell(conn, s, Event::Refused(b, c)),
        }
    }

    /// Room grew under a sync ID this node is full for (an entry left): `full` false where it
    /// told, and S pulled again from the start from each source.
    pub(super) fn room_grew(&mut self, ctx: &mut Ctx) -> Result<bool> {
        let mut grew = Vec::new();
        for (s, (at, _)) in &self.room {
            let (d, m) = ctx.store.usage(s)?;
            if d.bytes + m.bytes < *at {
                grew.push(*s);
            }
        }
        for s in &grew {
            self.room.remove(s);
            for c in self.holders.get(s).cloned().unwrap_or_default() {
                let Some(p) = self.pull.get_mut(&c) else { continue };
                if p.told_full.remove(s) {
                    p.tell.push((*s, Event::Full(false)));
                }
                p.join(*s, None);
                let src = p.src;
                let place = self.place(ctx.store, src);
                place.at_stream.remove(s);
                place.stopped.remove(s);
                place.joining.insert(*s, None);
                self.save(ctx, src, &[*s], false, Vec::new());
            }
        }
        Ok(!grew.is_empty())
    }

    /// Sends Fetches while fewer than `FETCHES_OUT` are out: one sync ID's bodies of one fill
    /// class at a time, the best first, order 0 before anything else; a blob asked at another
    /// source stays queued here until that ask is past `ASKED_MS` (spec/sync-streams.md §4 Bodies).
    fn fetch(&mut self, ctx: &mut Ctx, conn: ConnId) {
        loop {
            let Some(p) = self.pull.get(&conn) else { return };
            if p.fetches.len() >= FETCHES_OUT {
                return;
            }
            let order0_out = p.fetches.values().any(|(_, _, c)| *c == 0);
            let mut pick: Option<(SyncId, u8)> = None;
            let mut ids = Vec::new();
            let mut drop = Vec::new();
            for (k, (s, b)) in &p.queue {
                if p.settled.contains(&(*s, *b)) || p.failed.contains(b) || !ctx.shared.members(conn).contains_key(s) {
                    drop.push(*k);
                    continue;
                }
                if self.asked.get(b).is_some_and(|(c, at)| *c != conn && at.0.saturating_add(ASKED_MS) > ctx.now.0) {
                    continue;
                }
                match pick {
                    None => {
                        if order0_out && k.0 != 0 {
                            break;
                        }
                        pick = Some((*s, k.0));
                    }
                    Some((ps, pc)) if ps != *s || pc != k.0 => continue,
                    _ => {}
                }
                ids.push((*k, *b));
                if ids.len() >= MAX_FETCH_IDS {
                    break;
                }
            }
            let Some(p) = self.pull.get_mut(&conn) else { return };
            for k in drop {
                p.queue.remove(&k);
            }
            let Some((s, c)) = pick else { return };
            let blobs: Vec<BlobId> = ids.iter().map(|(_, b)| *b).collect();
            let Some(id) = ctx.wire.request(conn, Msg::Fetch { id: 0, sync_id: s, max_reply: REPLY_BUDGET as u64, ids: blobs.clone() }) else { return };
            for (k, b) in &ids {
                p.queue.remove(k);
                self.asked.insert(*b, (conn, ctx.now));
            }
            p.fetches.insert(id, (s, blobs, c));
        }
    }

    /// A FetchReply (or a Fetch skipped or refused: none of its IDs): the rest of a prefix is asked
    /// again before what came is applied, so it stays asked and owed (a partial fill never counts
    /// as caught up); what came is taken; a reply with none fails every ID at this source. An item
    /// for an ID not asked is ignored.
    fn fetched(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<Fetched>) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let Some((s, ids, c)) = p.fetches.remove(&id) else { return };
        let mut items = items;
        let mut seen = BTreeSet::new();
        items.retain(|f| ids.contains(&f.blob_id) && seen.insert(f.blob_id));
        let rest: Vec<BlobId> = if items.is_empty() { Vec::new() } else { ids.iter().filter(|b| !seen.contains(b)).copied().collect() };
        if !rest.is_empty()
            && let Some(again) = ctx.wire.request(conn, Msg::Fetch { id: 0, sync_id: s, max_reply: REPLY_BUDGET as u64, ids: rest.clone() })
        {
            for b in &rest {
                self.asked.insert(*b, (conn, ctx.now));
            }
            p.fetches.insert(again, (s, rest, c));
        }
        let Some(p) = self.pull.get_mut(&conn) else { return };
        if items.is_empty() {
            p.failed.extend(ids.iter().copied());
        }
        for b in ids.iter().filter(|b| items.is_empty() || seen.contains(b)) {
            if self.asked.get(b).is_some_and(|(x, _)| *x == conn) {
                self.asked.remove(b);
            }
        }
        for f in items {
            match f.entry {
                Some((bytes, wrap, stamp)) => self.take_body(ctx, conn, s, f.blob_id, wrap, stamp, &bytes),
                None => {
                    if let Some(p) = self.pull.get_mut(&conn) {
                        p.failed.insert(f.blob_id);
                    }
                }
            }
        }
        self.drain(ctx, conn);
    }

    /// Applies the messages in hand, in order, while the first owes nothing: an owed body is
    /// settled once held, no longer wanted (not a member here), or this source lacks it.
    fn drain(&mut self, ctx: &mut Ctx, conn: ConnId) {
        loop {
            let Some(p) = self.pull.get(&conn) else { return };
            let Some(front) = p.pending.front() else { break };
            let members = ctx.shared.members(conn);
            let ready = front.owed.iter().all(|(s, b)| p.settled.contains(&(*s, *b)) || p.failed.contains(b) || !members.contains_key(s) || ctx.store.bytes(b).ok().flatten().is_some());
            if !ready {
                return;
            }
            let Some(batch) = self.pull.get_mut(&conn).and_then(|p| p.pending.pop_front()) else { return };
            self.apply(ctx, conn, batch);
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.settled.clear();
            // what failed here matters only to messages in hand (an announcement again clears it)
            if p.pending.is_empty() {
                let failed = std::mem::take(&mut p.failed);
                p.queue.retain(|_, (_, b)| !failed.contains(b));
            }
        }
    }

    /// Applies one message: what each source holds (`known`; a deletion only says the source no
    /// longer holds it, a head names its step), then the cursor stored (SN_cursor: only now),
    /// joins moved, and an Applied when asked (spec/sync-streams.md §4 Applying, Reports); for a
    /// record source all in one transaction.
    fn apply(&mut self, ctx: &mut Ctx, conn: ConnId, batch: Batch) {
        let members: BTreeSet<SyncId> = ctx.shared.members(conn).keys().copied().collect();
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let src = p.src;
        if batch.reply.as_ref().is_some_and(|r| r.whole) && p.listing.is_none() {
            p.listing = Some(BTreeMap::new());
            // the whole listing covers every member: joins from the start are part of it
            p.join_listing.clear();
        }
        let mut listing = p.listing.take();
        let mut join_listing = std::mem::take(&mut p.join_listing);
        let mut ops = Vec::new();
        for (s, e) in &batch.events {
            if !members.contains(s) {
                continue;
            }
            self.work.applied += 1;
            match e {
                Event::Added { blob_id: b, blob, .. } => {
                    let class = match blob {
                        Some(v) => Prefix::parse(v).map_or(Class::Durable, |p| p.class()),
                        None => ctx.store.entry(s, b).ok().flatten().map_or(Class::Durable, |e| e.class),
                    };
                    let at = if class == Class::Ephemeral { Source::Conn(conn) } else { src };
                    ops.push((at, Op::Add(*s, *b)));
                    if let Some(l) = listing.as_mut() {
                        l.entry(*s).or_default().insert(*b);
                    }
                    if let Some(l) = join_listing.get_mut(s) {
                        l.insert(*b);
                    }
                }
                Event::Deleted(b) => {
                    ops.push((src, Op::Remove(*s, *b)));
                    ops.push((Source::Conn(conn), Op::Remove(*s, *b)));
                    let _ = ctx.store.saw_deleted(src, s, b);
                }
                Event::Head(step) => ops.push((src, Op::Head(*s, step.id()))),
                _ => {}
            }
        }
        // a listing from the start stores no cursor until it is read to its end: one cut short (a
        // connection lost, a restart) is read from the start again, so a listing that replaces
        // presence is always a whole one (spec/sync-streams.md §4 Applying)
        let mid_listing = batch.reply.as_ref().is_some_and(|r| r.more) && listing.is_some();
        let place = self.place(ctx.store, src);
        let cursor = (batch.cursor.is_some() || batch.reply.as_ref().is_some_and(|r| r.whole)) && !mid_listing;
        if cursor {
            place.cursor = batch.cursor.clone();
        }
        let mut touched: Vec<SyncId> = Vec::new();
        let mut listed: BTreeMap<SyncId, BTreeSet<BlobId>> = BTreeMap::new();
        if let Some(r) = &batch.reply {
            if r.whole {
                // every member from the start: each at the stream now
                for s in members.iter().filter(|s| !matches!(r.joins.get(s), Some(None))) {
                    place.at_stream.insert(*s);
                    place.joining.remove(s);
                    place.stopped.remove(s);
                    touched.push(*s);
                }
            } else {
                for (s, _) in &r.asked {
                    touched.push(*s);
                    match r.joins.get(s) {
                        // a join from the start keeps its stored start until it ends
                        Some(Some(c)) if !join_listing.contains_key(s) => {
                            place.joining.insert(*s, Some(c.clone()));
                        }
                        Some(Some(_)) => {}
                        Some(None) => {
                            place.joining.remove(s);
                            join_listing.remove(s);
                        }
                        None => {
                            place.joining.remove(s);
                            if members.contains(s) {
                                place.at_stream.insert(*s);
                                // a join from the start read to its end: S's live set there
                                if let Some(l) = join_listing.remove(s) {
                                    listed.insert(*s, l);
                                }
                            }
                        }
                    }
                }
            }
            // a whole listing read to its end is the source's live set (spec/sync-streams.md §3
            // Node log: compacted, never trimmed by position), trimmed or not
            if !r.more
                && let Some(seen) = listing.take()
            {
                for s in &members {
                    listed.insert(*s, seen.get(s).cloned().unwrap_or_default());
                }
            }
        }
        // what a listing from the start did not list, the source no longer holds
        for (s, l) in &listed {
            match self.known.list(src, s) {
                Ok(held) => ops.extend(held.into_iter().filter(|b| !l.contains(b)).map(|b| (src, Op::Remove(*s, b)))),
                // nothing is stored (no cursor, no Applied); the step fails
                Err(e) => return self.failed(Err(e.into())),
            }
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.listing = listing;
            p.join_listing = join_listing;
        }
        // an Applied says what is stored: none for what failed to be
        if !self.save(ctx, src, &touched, cursor, ops) {
            return;
        }
        let Some(p) = self.pull.get_mut(&conn) else { return };
        // an Applied says the cursor and each join's position are stored: none while a listing
        // from the start is under way
        if batch.report
            && cursor
            && p.join_listing.is_empty()
            && let Some(c) = batch.cursor
        {
            p.applied_owed = Some(c);
        }
    }
}
