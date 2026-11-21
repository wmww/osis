//! The pulling side of a stream (spec/sync-streams.md §4 Joining, Pushes, Flow control, Applying,
//! Bodies, Fill order, Full, Refused, Reports; §5 First sync): Pulls with the stream's cursor and
//! its joins, messages applied in order once their bodies are held, the cursor stored only then,
//! `seq` checked and a gap read again, bodies fetched one source at a time in the fill order.

use super::known::{self, Op};
use super::{ASKED_MS, Ctx, FETCHES_OUT, INLINE_LIMIT, Opening, PENDING_CAP, Rank, Streams};
use crate::opens::{Leaving, Rejoin};
use crate::store::rows::tag::{AT_STREAM, CLOSED, CURSOR, JOIN_FROM, TOLD};
use crate::store::{Source, Store};
use crate::types::{ConnId, Cursor, Entry, RESYNC_MS, RecordId, SourceClass};
use osis_store::Transaction;
use osis_base::memo::{Stamped, StampedSet};
use osis_base::{BlobId, Mono, SyncId};
use osis_engine::sync::Holding;
use osis_blob::{Class, Prefix, StepId};
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
    /// Members closed on the connection up whose stop is kept (spec/sync-opens.md §6 Where it
    /// stopped): it lasts that connection. Row `CLOSED`, so a start finds those a crash left.
    pub closed: BTreeSet<SyncId>,
    /// Members whose rows hold another form of the same position (`effective`): a member at the
    /// stream that left it, stopped at the stream's cursor, still stored as at it. Written with
    /// the next cursor that moves (`Pulling::save`), before it could mean another position.
    stale: BTreeSet<SyncId>,
    /// The head of S this node last told this source a refusal of S under (no head: `None`),
    /// until S is pulled from the start there (spec/sync-streams.md §4 Refused). Row `TOLD`.
    pub told: BTreeMap<SyncId, Option<StepId>>,
}

impl Place {
    /// S goes from this place (its rows went with the shred).
    pub(super) fn forget(&mut self, s: &SyncId) {
        self.at_stream.remove(s);
        self.joining.remove(s);
        self.stopped.remove(s);
        self.closed.remove(s);
        self.stale.remove(s);
        self.told.remove(s);
    }
}

/// Whether this node's head of S moving may lift a refusal of code `c` it told
/// (spec/sync-streams.md §4 Refused): a stamp under no key it knows (1) may be under a later
/// head's; an earlier key (9) only grows older, and expiry, malformed bytes and a tombstone do not
/// turn on the head.
fn head_may_lift(c: Code) -> bool {
    c == Code::REFUSED
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

/// At a start: where members closed on a connection that ended without letting its record go
/// (a crash) stopped goes, with what their sources showed (spec/sync-opens.md §6 Where it
/// stopped: it lasts the connection). O(records), once a start.
pub(super) fn forget_unkept(mut store: Store) -> crate::types::Result<()> {
    store.with_tx(|t| {
        for rec in t.records_all()? {
            for (s, ..) in t.record_tag_rows(&rec.id, CLOSED)? {
                for tag in [CLOSED, AT_STREAM, JOIN_FROM] {
                    t.record_remove_row(&rec.id, tag, &s, b"")?;
                }
                known::write(t, &rec.id, &Op::Forget(s))?;
            }
        }
        Ok(())
    })
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
        // no connection at a load: a member not at the stream rejoins from where it stood
        for (s, _, v) in t.record_tag_rows(rec, JOIN_FROM)? {
            p.stopped.insert(s, read_cursor(&v)?);
        }
        for (s, ..) in t.record_tag_rows(rec, CLOSED)? {
            p.closed.insert(s);
        }
        for (s, _, v) in t.record_tag_rows(rec, TOLD)? {
            let head = match v.len() {
                0 => None,
                _ => Some(StepId(v.try_into().map_err(|_| osis_store::Error::Corrupt("streams told row"))?)),
            };
            p.told.insert(s, head);
        }
        Ok(p)
    }

    /// Writes member S's told head into record `rec`'s rows as memory holds it.
    fn write_told(&self, t: &mut Transaction<'_>, rec: &RecordId, s: &SyncId) -> std::result::Result<(), osis_store::Error> {
        match self.told.get(s) {
            Some(h) => t.record_put_row(rec, TOLD, s, b"", h.map_or(Vec::new(), |h| h.0.to_vec())),
            None => t.record_remove_row(rec, TOLD, s, b"").map(drop),
        }
    }

    /// Writes member S's place into record `rec`'s rows as memory holds it.
    fn write(&self, t: &mut Transaction<'_>, rec: &RecordId, s: &SyncId) -> std::result::Result<(), osis_store::Error> {
        if self.at_stream.contains(s) {
            t.record_put_row(rec, AT_STREAM, s, b"", Vec::new())?;
        } else {
            t.record_remove_row(rec, AT_STREAM, s, b"")?;
        }
        if self.closed.contains(s) {
            t.record_put_row(rec, CLOSED, s, b"", Vec::new())?;
        } else {
            t.record_remove_row(rec, CLOSED, s, b"")?;
        }
        match self.join_from(s) {
            Some(c) => t.record_put_row(rec, JOIN_FROM, s, b"", opt_cursor(c)),
            None => t.record_remove_row(rec, JOIN_FROM, s, b"").map(drop),
        }
    }

    /// Where member `s` joins from, as stored: joining from it, or stopped there.
    fn join_from(&self, s: &SyncId) -> Option<&Option<Cursor>> {
        self.joining.get(s).or_else(|| self.stopped.get(s))
    }

    /// Where member `s` stands, whichever form its place takes: at the stream (its cursor), or
    /// joining or stopped at its own. Rows holding the same position need no write.
    fn effective(&self, s: &SyncId) -> Option<Option<Cursor>> {
        match self.at_stream.contains(s) {
            true => Some(self.cursor.clone()),
            false => self.join_from(s).cloned(),
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
    /// The members a whole reply lists from the start (`covered`).
    covered: BTreeSet<SyncId>,
    more: bool,
    joins: BTreeMap<SyncId, Option<Cursor>>,
    asked: Vec<(SyncId, u64)>,
}

/// The members a whole reply covers (spec/sync-streams.md §4 Applying): each shared now whose
/// join is not waiting for a later Pull. One that joined after the Pull went out is joined by its
/// own join, whatever the server listed.
fn covered(members: &BTreeMap<SyncId, crate::opens::Member>, p: &Pulling, asked: &[(SyncId, u64)]) -> BTreeSet<SyncId> {
    members.keys().filter(|s| p.joins.get(s).is_none_or(|j| asked.contains(&(**s, j.generation)))).copied().collect()
}

/// A body queued for fetching: its sync ID, blob and the announcement's wrap and stamp.
type Queued = (SyncId, BlobId, Option<(Wrap, Option<Stamp>)>);

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
    /// Messages in hand, in order (`hold`, `next_held`).
    pending: VecDeque<Batch>,
    /// Per member, the pushes in hand carrying an event of it: S is busy here while one is
    /// (spec/sync-status.md §1); a reply in hand keeps the whole connection so (`replies`).
    in_hand: BTreeMap<SyncId, usize>,
    replies: usize,
    /// Fetches out: the (sync ID, blob) pairs each asked, and their fill class.
    fetches: BTreeMap<Id, (Vec<(SyncId, BlobId)>, u8)>,
    /// Bodies to fetch, by fill order: each with the wrap and stamp it was announced under, when
    /// one was (`refetch`'s come with the reply), so one whose bytes arrive meanwhile under another
    /// sync ID is taken with them at its turn, not fetched again.
    queue: BTreeMap<(u8, u64, u64), Queued>,
    arrivals: u64,
    /// Entries this source answered without (or gave wrong bytes of), until it announces the
    /// entry again: per sync ID, as owed (the same blob announced under another sync ID is
    /// another entry).
    failed: BTreeSet<(SyncId, BlobId)>,
    /// Bodies settled (taken, opened, refused) while messages are in hand.
    pub(super) settled: BTreeSet<(SyncId, BlobId)>,
    /// Of those, the ones that opened to what no entry keeps (`Opening::Taken`): what the
    /// source shows of them is kept as of an entry held (`concerns`).
    taken: BTreeSet<(SyncId, BlobId)>,
    retry_at: Option<Mono>,
    rejoin_at: BTreeMap<SyncId, Mono>,
    inline: u64,
    pub(super) inline_check: bool,
    /// A whole listing from the start under way: per member its first page covers, what it listed so far.
    listing: Option<BTreeMap<SyncId, BTreeSet<BlobId>>>,
    /// Joins from the start under way: what each listed so far.
    join_listing: BTreeMap<SyncId, BTreeSet<BlobId>>,
    /// Full and Refused events to tell the source.
    tell: Vec<(SyncId, Event)>,
    /// The members this side told `full` true on this connection and not false since.
    told_full: BTreeSet<SyncId>,
    applied_owed: Option<Cursor>,
    /// The places (`Streams::pull_seq`) of the Pull out and of the one the last reply answered:
    /// a stream caught up since a pass began read its end from a Pull sent after it
    /// (spec/sync-status.md §1).
    out_at: u64,
    pub(super) answered_at: u64,
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
            in_hand: BTreeMap::new(),
            replies: 0,
            fetches: BTreeMap::new(),
            queue: BTreeMap::new(),
            arrivals: 0,
            failed: BTreeSet::new(),
            settled: BTreeSet::new(),
            taken: BTreeSet::new(),
            retry_at: None,
            rejoin_at: BTreeMap::new(),
            inline: INLINE_LIMIT,
            inline_check: false,
            listing: None,
            join_listing: BTreeMap::new(),
            tell: Vec::new(),
            told_full: BTreeSet::new(),
            applied_owed: None,
            out_at: 0,
            answered_at: 0,
            again: false,
        }
    }

    /// SN_rearm, the connection's part: the last reply at the end, no Pull out (a change
    /// announced during one denies it), no gap and no reply in hand. A push in hand keeps only
    /// the members it carries from caught up (`in_hand`).
    pub(super) fn caught_up(&self) -> bool {
        self.quiet && self.out.is_none() && !self.gap && self.replies == 0
    }

    /// The members a push in hand carries an event of.
    pub(super) fn in_hand(&self) -> impl Iterator<Item = &SyncId> {
        self.in_hand.keys()
    }

    /// Takes a message in hand, last.
    fn hold(&mut self, b: Batch) {
        match b.reply {
            Some(_) => self.replies += 1,
            None => {
                for s in b.events.iter().map(|(s, _)| *s).collect::<BTreeSet<_>>() {
                    *self.in_hand.entry(s).or_default() += 1;
                }
            }
        }
        self.pending.push_back(b);
    }

    /// The first message in hand, no longer held.
    fn next_held(&mut self) -> Option<Batch> {
        let b = self.pending.pop_front()?;
        match b.reply {
            Some(_) => self.replies -= 1,
            None => {
                for s in b.events.iter().map(|(s, _)| *s).collect::<BTreeSet<_>>() {
                    if let Some(n) = self.in_hand.get_mut(&s) {
                        *n -= 1;
                        if *n == 0 {
                            self.in_hand.remove(&s);
                        }
                    }
                }
            }
        }
        Some(b)
    }

    pub(super) fn holding(&self) -> usize {
        let listed = self.listing.iter().flat_map(|l| l.values()).chain(self.join_listing.values()).map(BTreeSet::len).sum::<usize>();
        self.pending.len() + self.queue.len() + self.failed.len() + self.settled.len() + self.taken.len() + self.tell.len() + listed
    }

    pub(super) fn wake(&self) -> Option<Mono> {
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

/// A Fetch's groups of `pairs`: each run of one sync ID's blobs, in order.
fn grouped(pairs: &[(SyncId, BlobId)]) -> Vec<(SyncId, Vec<BlobId>)> {
    let mut out: Vec<(SyncId, Vec<BlobId>)> = Vec::new();
    for (s, b) in pairs {
        match out.last_mut() {
            Some((x, bs)) if x == s => bs.push(*b),
            _ => out.push((*s, vec![*b])),
        }
    }
    out
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

/// Whether what a source shows of entry `b` of S is kept (spec/sync-judgement.md §3 `known`),
/// once its message's bodies settled: only of an entry this node holds or holds a tombstone of
/// under S, or one whose body it took while the message was in hand (`taken`: a piece, records,
/// a sealed fire), or a record or list blob it counts (`Ground::counted`: opened before, not
/// fetched again), so what a source lists costs this node in proportion to what it holds or
/// took; a store read that fails keeps nothing (a later listing shows it again). Not built: a
/// body fetched lazily.
fn concerns(ctx: &mut Ctx, p: Option<&Pulling>, s: &SyncId, b: &BlobId) -> bool {
    p.is_some_and(|p| p.taken.contains(&(*s, *b))) || ctx.store.entry(s, b).ok().flatten().is_some() || ctx.store.tombstone(s, b).ok().flatten().is_some() || ctx.ground.counted(s, b)
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
        if rec_ops.is_empty() && (!matches!(src, Source::Record(_)) || (ss.is_empty() && !cursor)) {
            return true;
        }
        // a record's head that moves ends its refusals kept in memory too (`Known::wrote_record`)
        let moved: Vec<bool> = rec_ops.iter().map(|(at, op)| matches!(op, Op::Head(s, h) if self.known.head(*at, s).is_some_and(|old| old != *h))).collect();
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
                // a cursor moving: a member stored as at the stream that is not stands where it did
                if cursor {
                    for s in p.stale.iter().filter(|s| !ss.contains(s)) {
                        p.write(t, &rec, s)?;
                    }
                    t.record_put_wide_row(&rec, CURSOR, b"", opt_cursor(&p.cursor))?;
                }
            }
            Ok(())
        });
        let ok = r.is_ok();
        if ok {
            for ((at, op), moved) in rec_ops.iter().zip(moved) {
                self.known.logged(*at, op);
                self.known.wrote_record(*at, op, moved);
            }
            if let Some(p) = self.places.get_mut(&src) {
                match cursor {
                    true => p.stale.clear(),
                    false => p.stale.retain(|s| !ss.contains(s)),
                }
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
        // whether it keeps S unread, as it opened: the record's, kept with what its stream shows
        // (read judges what is owed there by it while the source is away); it moves only with an
        // open, and the same class again writes nothing
        let kept = ctx.shared.members(conn).get(&s).is_some_and(|m| m.class == SourceClass::Store);
        if self.known.kept(src, &s) != kept {
            self.save(ctx, src, &[], false, vec![(src, Op::Kept(s, kept))]);
        }
        self.join_member(ctx, conn, s, rejoin);
    }

    /// Kept record `rid` is connected on `conn` (spec/sync-streams.md §4 Joining: a connection
    /// that takes a record pulls its members from where the record holds them): its place, kept
    /// in memory with the record, is this connection's; a member at the stream needs no join and
    /// nothing of it is read or written.
    pub(super) fn taken(&mut self, ctx: &mut Ctx, conn: ConnId, rid: RecordId) {
        let src = Source::Record(rid);
        let cursor = self.place(ctx.store, src).cursor.clone();
        if let Some(was) = self.pull.insert(conn, Pulling::new(src, cursor)) {
            self.dropped_in_hand(&was);
        }
        let members: Vec<SyncId> = ctx.shared.members(conn).keys().copied().collect();
        for s in members {
            self.holders.entry(s).or_default().insert(conn);
            self.served_joined(ctx, conn, s);
            self.join_member(ctx, conn, s, Rejoin::Held);
        }
        // its members gained a source: every stream asks inline 0 again where one has two
        for p in self.pull.values_mut() {
            p.inline_check = true;
        }
    }

    /// Member S stands on `conn`'s stream: full told if S is, joined from where `rejoin` says,
    /// else where the place holds it, else from the start; none at the stream's cursor.
    fn join_member(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, rejoin: Rejoin) {
        let src = self.source(ctx.shared, conn);
        // full for S: told on each connection S joins
        if ctx.store.waits_room(&s) {
            self.tell_full(conn, s, true);
        }
        // the cursor this connection's first Pull names, while none went out: a member stopped
        // there is at the stream's cursor (spec/sync-streams.md §4 Joining)
        let first = self.pull.get(&conn).filter(|p| !p.first_sent).map(|p| p.recv.clone());
        let place = self.place(ctx.store, src);
        let first = first.filter(|c| *c == place.cursor);
        let from = match rejoin {
            // a pull from the start since (fetched anew) stands over where a Lost said it stopped
            Rejoin::From(c) => Some(if place.join_from(&s) == Some(&None) { None } else { c }),
            Rejoin::Held => {
                if let Some(c) = place.stopped.get(&s).filter(|c| first.as_ref() != Some(*c)) {
                    Some(c.clone())
                } else if let Some(c) = place.joining.get(&s) {
                    Some(c.clone())
                } else if place.at_stream.contains(&s) || place.stopped.contains_key(&s) {
                    // at the stream, or stopped at the first Pull's cursor
                    None
                } else {
                    Some(None)
                }
            }
        };
        // stopped at the cursor the connection's first Pull names (it left with a connection, and
        // the stream has not moved since): it is at the stream, with no join; its rows hold that
        // position
        let Some(c) = from else {
            if place.stopped.remove(&s).is_some() {
                place.at_stream.insert(s);
                let reopened = place.closed.remove(&s);
                if matches!(src, Source::Record(_)) {
                    place.stale.insert(s);
                }
                if reopened {
                    self.save(ctx, src, &[s], false, Vec::new());
                }
            }
            return;
        };
        let was = place.effective(&s);
        let reopened = place.closed.remove(&s);
        place.stopped.remove(&s);
        place.at_stream.remove(&s);
        if place.joining.get(&s) != Some(&c) {
            place.joining.insert(s, c.clone());
        }
        let moved = place.effective(&s) != was;
        if !moved && matches!(src, Source::Record(_)) {
            place.stale.insert(s);
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.join(s, c);
            p.quiet = false;
        }
        if moved || reopened {
            self.save(ctx, src, &[s], false, Vec::new());
        }
    }

    /// A member left: its stream stops where it stands (its stored position kept for its rejoin,
    /// a closed one's marked so as long as its connection lasts); one closed keeping nothing of
    /// where it stopped (spec/sync-opens.md §6 Where it stopped), or a sync ID the node no longer
    /// holds, leaves no position and no `known`.
    pub(super) fn left(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, how: Leaving) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        p.joins.remove(&s);
        p.rejoin_at.remove(&s);
        // `full` both ways is a fact of S on this connection: told again at a rejoin
        p.told_full.remove(&s);
        p.tell.retain(|(x, e)| *x != s || !matches!(e, Event::Full(_)));
        self.known.apply_conn(Source::Conn(conn), &[Op::Full(s, false)]);
        let Some(p) = self.pull.get(&conn) else { return };
        let src = p.src;
        let held = ctx.store.holding(&s).is_some();
        let place = self.place(ctx.store, src);
        let was = place.effective(&s);
        let at = if let Some(c) = place.joining.remove(&s) {
            Some(c)
        } else if place.at_stream.remove(&s) {
            Some(place.cursor.clone())
        } else {
            None
        };
        let mut ops = Vec::new();
        let mut marked = false;
        if !held || how == Leaving::Forgot {
            place.stopped.remove(&s);
            place.closed.remove(&s);
            ops.push((src, Op::Forget(s)));
            ops.push((Source::Conn(conn), Op::Forget(s)));
        } else {
            if let Some(c) = at {
                place.stopped.insert(s, c);
            }
            marked = how == Leaving::Kept && matches!(src, Source::Record(_)) && place.closed.insert(s);
        }
        if ops.is_empty() && !marked && place.effective(&s) == was {
            if matches!(src, Source::Record(_)) {
                place.stale.insert(s);
            }
            return;
        }
        self.save(ctx, src, &[s], false, ops);
    }

    /// Where S, closed on `conn`, stopped is no longer kept (spec/sync-opens.md §6 Where it
    /// stopped): its stored position and what its source showed go.
    pub(super) fn forgot(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let Some(src) = self.pull.get(&conn).map(|p| p.src) else { return };
        self.forget_stops(ctx, src, &[s]);
        self.known.apply_conn(Source::Conn(conn), &[Op::Forget(s)]);
    }

    /// The stops `ss` of source `src` go with what it showed of them.
    pub(super) fn forget_stops(&mut self, ctx: &mut Ctx, src: Source, ss: &[SyncId]) {
        let held = self.pull.values().any(|p| p.src == src);
        let place = self.place(ctx.store, src);
        for s in ss {
            place.forget(s);
        }
        self.save(ctx, src, ss, false, ss.iter().map(|s| (src, Op::Forget(*s))).collect());
        // a record's place stays in memory with the record (`record_left`)
        if !held && matches!(src, Source::Conn(_)) {
            self.places.remove(&src);
        }
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
        if p.out.is_some() || p.pending.len() >= PENDING_CAP || !p.tell.is_empty() || p.applied_owed.is_some() || members.is_empty() || p.retry_at.is_some_and(|t| t > ctx.mono) {
            return;
        }
        p.retry_at = None;
        // a join refused while S stays a member is joined again `resync_ms` later
        let due: Vec<SyncId> = p.rejoin_at.iter().filter(|(s, t)| **t <= ctx.mono && members.contains_key(*s)).map(|(s, _)| *s).collect();
        p.rejoin_at.retain(|s, t| *t > ctx.mono && members.contains_key(s));
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
        let first = !p.first_sent;
        p.first_sent = true;
        p.eph_next = false;
        p.again = false;
        p.quiet = false;
        p.out = Some((id, asked));
        self.pulls_sent += 1;
        p.out_at = self.pulls_sent;
        // the first Pull covers only the members shared now: one the place holds at the stream
        // that is not one (no member when the record was taken) stopped at the cursor it names,
        // so once it opens it joins from there (spec/sync-streams.md §4 Joining); its rows hold
        // that position as at the stream until the cursor moves
        let src = p.src;
        if first && let Some(place) = self.places.get_mut(&src) {
            let idle: Vec<SyncId> = place.at_stream.iter().filter(|s| !members.contains_key(*s)).copied().collect();
            for s in idle {
                place.at_stream.remove(&s);
                place.stopped.insert(s, place.cursor.clone());
                if matches!(src, Source::Record(_)) {
                    place.stale.insert(s);
                }
            }
        }
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
            _ => p.retry_at = Some(ctx.mono.after(RESYNC_MS)),
        }
    }

    fn on_pull_reply(&mut self, ctx: &mut Ctx, conn: ConnId, r: PullReply, asked: Vec<(SyncId, u64)>) {
        let members = ctx.shared.members(conn);
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let covered = covered(members, p, &asked);
        // a listing from the start shows again what the source holds of S: its room mark goes
        // as the listing starts, before any of its bodies is judged (spec/sync-streams.md §4
        // Full); what it refuses again marks it again
        let from_start: Vec<SyncId> = match r.whole {
            true => covered.iter().copied().collect(),
            false => asked.iter().filter(|(s, g)| p.joins.get(s).is_some_and(|j| j.generation == *g && j.cursor.is_none())).map(|(s, _)| *s).collect(),
        };
        let src = p.src;
        for s in &from_start {
            if let Err(e) = ctx.store.listed_from_start(s, src) {
                return self.failed(Err(e));
            }
        }
        let Some(p) = self.pull.get_mut(&conn) else { return };
        // what a message in hand settled of S kept unread without taking it (a refusal) is asked
        // again: counted settled, the listing's place would pass it unjudged, its mark not set
        // again (and room grown, never fetched); asked, the messages owing it still settle
        let again: Vec<(SyncId, BlobId)> = p.settled.iter().filter(|(s, b)| from_start.contains(s) && ctx.store.holding(s) == Some(Holding::Unread) && ctx.store.bytes(b).ok().flatten().is_none()).copied().collect();
        for (s, b) in again {
            p.settled.remove(&(s, b));
            if !p.queue.values().any(|x| (x.0, x.1) == (s, b))
                && let Some(c) = class(Rank::Unopened, false)
            {
                p.arrivals += 1;
                p.queue.insert((c.0, c.1, u64::MAX - p.arrivals), (s, b, None));
            }
        }
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
                            p.rejoin_at.insert(*s, ctx.mono.after(RESYNC_MS));
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
        let info = ReplyInfo { whole: r.whole, covered, more: r.more, joins, asked };
        let batch = Batch { events: r.events, cursor: r.cursor.map(osis_proto::Cursor::into_bytes), report: r.report, reply: Some(info), owed: Vec::new() };
        self.stage(ctx, conn, batch);
    }

    /// A Stream: with no cursor, Full and Refused events and relay-only entries;
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
                    // a fact of this connection, whatever the source (`known`)
                    Event::Full(f) => ops.push((Source::Conn(conn), Op::Full(s, f))),
                    // code 6 counts as the entry deleted there
                    Event::Refused(b, Code::TOMBSTONED) => {
                        ops.push((src, Op::Remove(s, b)));
                        // a store failure loses this row only: the next delete seen there writes it again
                        if concerns(ctx, self.pull.get(&conn), &s, &b) || self.known.knows(src, &s, &b) {
                            let _ = ctx.store.saw_deleted(src, &s, &b);
                        }
                    }
                    // an ephemeral entry's refusal is kept in memory: it goes with the entry
                    Event::Refused(b, code) => match ctx.store.entry(&s, &b) {
                        Ok(Some(e)) if e.class == Class::Ephemeral => self.known.refused_here(src, s, b, code),
                        Ok(Some(_)) => ops.push((src, Op::Refused(s, b, code))),
                        _ => {}
                    },
                    // a relay-only entry (spec/sync-streams.md §4 Relay-only entries); any other
                    // announcement with no cursor is ignored
                    Event::Added { blob_id, blob: Some(bytes), wrap, stamp } => {
                        let e = entry_of(blob_id, wrap, stamp, &bytes);
                        if e.class == Class::Relay {
                            self.relay_in(ctx, conn, s, e, bytes);
                        }
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

    /// The messages `p` held in hand are dropped unapplied: what they showed is shown no more.
    pub(super) fn dropped_in_hand(&mut self, p: &Pulling) {
        for (s, b) in p.pending.iter().flat_map(|m| m.owed.iter()) {
            self.known.hand(s, b, false);
        }
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
                p.failed.remove(&(*s, *b));
            }
            if let Some(bytes) = blob {
                self.take_body(ctx, conn, *s, *b, *wrap, *stamp, bytes);
            } else if let Some(c) = self.wanted(ctx, conn, s, b, wrap, *stamp) {
                batch.owed.push((*s, *b));
                if let Some(p) = self.pull.get_mut(&conn)
                    && !p.queue.values().any(|x| (x.0, x.1) == (*s, *b))
                {
                    p.arrivals += 1;
                    let key = (c.0, c.1, u64::MAX - p.arrivals);
                    p.queue.insert(key, (*s, *b, Some((*wrap, *stamp))));
                }
            }
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            for (s, b) in &batch.owed {
                self.known.hand(s, b, true);
            }
            p.hold(batch);
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
                // a node keeping S unread takes stamped entries only
                let stamp = stamp?;
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
                if tomb {
                    return None;
                }
                // bytes held under another sync ID (a certificate copy is one blob wrapped under
                // each sync ID needing it): this entry is taken with them, its wrap for S
                if let Some(bytes) = held {
                    if ctx.store.entry(s, b).ok().flatten().is_none() {
                        self.take_body(ctx, conn, *s, *b, *wrap, stamp, &bytes);
                    }
                    return None;
                }
                // a record or list blob opened before: what it carries counts while a source
                // shows it, and a fetch would only open it again
                if ctx.ground.counted(s, b) {
                    return None;
                }
                class(ctx.ground.rank(s, b, wrap), stamp.is_none())
            }
        }
    }

    /// A queued body whose bytes arrived since it was announced (under another sync ID, or from
    /// another source): taken with them under its announced wrap, as `wanted` takes one held at
    /// its announcement.
    #[allow(clippy::too_many_arguments)]
    fn take_held(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, b: BlobId, wrap: Wrap, stamp: Option<Stamp>, bytes: &[u8]) {
        let tomb = ctx.store.tombstone(&s, &b).ok().flatten().is_some();
        match ctx.store.holding(&s) {
            Some(Holding::Unread) if tomb => self.tell(conn, s, Event::Refused(b, Code::TOMBSTONED)),
            Some(Holding::Unread) if stamp.is_some() => return self.take_body(ctx, conn, s, b, wrap, stamp, bytes),
            Some(Holding::Read) if !tomb && ctx.store.entry(&s, &b).ok().flatten().is_none() => return self.take_body(ctx, conn, s, b, wrap, stamp, bytes),
            _ => {}
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.settled.insert((s, b));
        }
    }

    /// A stamp new to entry `b` of S held here under the same wrap, applied in stream order (the
    /// step's commit a writer logged before stamping under it is held by then): the store logs it
    /// on an entry held unstamped (stamped in place at a writer, spec/sync-inbox.md §2), judged as
    /// any peer's stamp, and replaces a held one not under the head S's `sync.0` records here
    /// (`Ground::head_write`; the served path may still be the old one) by one that is (stamped in
    /// place on a head move, spec/sync-judgement.md §3 Own store; spec/sync-ids.md §5 Peer budget:
    /// one that does not verify replaces no stamp held), each stamp checked once (`Store::take_stamp`).
    fn new_stamp(&mut self, ctx: &mut Ctx, src: Source, s: &SyncId, b: &BlobId, wrap: &Wrap, stamp: &Stamp) {
        let head = ctx.ground.head_write(s);
        let r = ctx.store.take_stamp(s, b, wrap, stamp, head, src);
        self.failed(r);
    }

    /// Entry `b` of S queued for fetching on `conn` outside any message (`Streams::fetch_again`):
    /// only while S is a member there and this node lacks the bytes and holds no tombstone of it.
    /// Its wrap comes with the reply; until then it ranks as a body that opens, after the rest.
    pub(super) fn refetch(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, b: BlobId) {
        if !ctx.shared.members(conn).contains_key(&s) || ctx.store.holding(&s) != Some(Holding::Read) {
            return;
        }
        if ctx.store.bytes(&b).ok().flatten().is_some() || ctx.store.tombstone(&s, &b).ok().flatten().is_some() {
            return;
        }
        let Some(p) = self.pull.get_mut(&conn) else { return };
        // an earlier take of the same body settled it here; it is not held now
        p.failed.remove(&(s, b));
        p.settled.remove(&(s, b));
        p.taken.remove(&(s, b));
        if !p.queue.values().any(|x| (x.0, x.1) == (s, b)) {
            p.arrivals += 1;
            let key = (2, u64::MAX, u64::MAX - p.arrivals);
            p.queue.insert(key, (s, b, None));
        }
        self.fetch(ctx, conn);
        self.track(ctx, conn);
    }

    /// The sources whose place passes an entry of S once it settles: every connection's holding
    /// S, and `conn`'s (`take_body` settles it at each).
    fn settling_at(&self, s: SyncId, conn: ConnId) -> Vec<Source> {
        let srcs: BTreeSet<Source> = self.holders.get(&s).into_iter().flatten().chain(std::iter::once(&conn)).filter_map(|c| self.pull.get(c).map(|p| p.src)).collect();
        srcs.into_iter().collect()
    }

    fn tell(&mut self, conn: ConnId, s: SyncId, e: Event) {
        if let Some(p) = self.pull.get_mut(&conn) {
            p.tell.push((s, e));
        }
    }

    /// `full` told on `conn` for S as it now stands, once per change (spec/sync-streams.md §4
    /// Full: once per connection while full).
    fn tell_full(&mut self, conn: ConnId, s: SyncId, full: bool) {
        if let Some(p) = self.pull.get_mut(&conn) {
            let changed = if full { p.told_full.insert(s) } else { p.told_full.remove(&s) };
            if changed {
                p.tell.push((s, Event::Full(full)));
            }
        }
    }

    /// `full` false on each connection told it for each of `ended`, full no longer
    /// (`Store::room_grew`: room for what it refused, or no longer kept unread). O(`ended` times
    /// the connections pulling).
    pub(super) fn untell_full(&mut self, ended: &[SyncId]) {
        let conns: Vec<ConnId> = self.pull.keys().copied().collect();
        for s in ended {
            for c in &conns {
                self.tell_full(*c, *s, false);
            }
        }
    }

    /// A body's bytes arrived (inline or fetched): taken into the store (kept unread) or opened
    /// (read); settled for every stream owing it. Wrong bytes count as this source lacking it.
    #[allow(clippy::too_many_arguments)]
    fn take_body(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId, b: BlobId, wrap: Wrap, stamp: Option<Stamp>, bytes: &[u8]) {
        if osis_blob::blob_id(bytes) != b {
            if let Some(p) = self.pull.get_mut(&conn) {
                p.failed.insert((s, b));
            }
            return;
        }
        let e = entry_of(b, wrap, stamp, bytes);
        let mut took = false;
        // a store or engine failure takes nothing: the body stays owed (no cursor passes it) and
        // the step fails
        match ctx.store.holding(&s) {
            // refused for room, a room mark at each source whose place passes it once settled
            Some(Holding::Unread) if stamp.is_some() => match ctx.store.take_stamped(&s, &e, bytes.to_vec(), &self.settling_at(s, conn)) {
                Ok(code) => self.refused(ctx, conn, s, b, code),
                Err(e) => return self.failed(Err(e)),
            },
            Some(Holding::Read) => match ctx.ground.open(&s, &e, bytes) {
                Ok(Opening::Bad) => {
                    if let Some(p) = self.pull.get_mut(&conn) {
                        p.failed.insert((s, b));
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
                // an ephemeral commit held: its entry is kept, off the peer's budget, counted at
                // what the commit costs held
                // a commit held: its entry is kept as it came, read judges it as any entry of the
                // body under S; charged to no one when it gave something held, else (a duplicate)
                // charged to its bringer unless stamped, so a peer's fresh encryptions of held
                // commits fill its own budget alone
                Ok(Opening::Held { gave }) => {
                    let src = if gave { None } else { self.pull.get(&conn).map(|p| p.src) };
                    if let Err(e) = ctx.store.log(&s, e, Some(bytes.to_vec()), src) {
                        return self.failed(Err(e));
                    }
                }
                Ok(Opening::Memory(n)) => {
                    let src = self.pull.get(&conn).map(|p| p.src);
                    let r = ctx.store.log(&s, e, Some(bytes.to_vec()), src).and_then(|_| ctx.store.uncharge(&s, &b));
                    if let Err(e) = r {
                        return self.failed(Err(e));
                    }
                    ctx.store.set_memory_charge(&b, n);
                }
                Ok(_) => took = true,
                Err(e) => return self.failed(Err(e)),
            },
            _ => {}
        }
        for c in self.holders.get(&s).into_iter().flatten().chain(std::iter::once(&conn)) {
            if let Some(p) = self.pull.get_mut(c) {
                p.settled.insert((s, b));
                if took {
                    p.taken.insert((s, b));
                }
                p.queue.retain(|_, x| (x.0, x.1) != (s, b));
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
            // the store keeps S full (`Store::waits_room`)
            Code::STORAGE_CAP => self.tell_full(conn, s, true),
            c => {
                self.tell(conn, s, Event::Refused(b, c));
                if head_may_lift(c) {
                    self.told(ctx, conn, s);
                }
            }
        }
    }

    /// A refusal of S told on `conn` that a head move may lift: the source's place keeps the head it was told under, so a
    /// head move pulls S from the start there (`pull_anew`). One row per (source, S).
    fn told(&mut self, ctx: &mut Ctx, conn: ConnId, s: SyncId) {
        let Some(src) = self.pull.get(&conn).map(|p| p.src) else { return };
        let head = match ctx.store.head_id(&s) {
            Ok(h) => h,
            Err(e) => return self.failed(Err(e)),
        };
        let place = self.place(ctx.store, src);
        if place.told.get(&s) == Some(&head) {
            return;
        }
        place.told.insert(s, head);
        if let (Source::Record(rec), Some(place)) = (src, self.places.get(&src)) {
            let r = ctx.store.with_tx(|t| place.write_told(t, &rec, &s));
            self.failed(r);
        }
    }

    /// S kept unread whose dropped copy is fetched anew (spec/sync-judgement.md §6 Stops: a box
    /// of its head's sync secret keeps S again) or raised to read (§6 Read and unread move):
    /// pulled again from the start at every source; S whose head moved kept unread: at each
    /// source told a refusal of S under another head (spec/sync-streams.md §4 Refused); S whose
    /// room mark is owed somewhere (§4 Full): at each such source.
    pub(super) fn fetch_anew(&mut self, ctx: &mut Ctx) -> bool {
        // once each, written twice or not (a raise to read off a dropped copy)
        let anew: BTreeSet<SyncId> = self.anew.added().into_iter().collect();
        for s in &anew {
            self.pull_anew(ctx, *s);
        }
        !anew.is_empty()
    }

    /// S pulled from the start: from each source pulling it now, and from the start at its next
    /// join at every source whose place passed it, those only stored included (a restart since),
    /// in one transaction with clearing the store's durable mark (`N/`) and those sources' room
    /// marks (`Store::reset_anew`). Everywhere when the store's mark says so
    /// (`Store::anew_everywhere`: a dropped copy, a raise); else (`ANEW_SOME`, or none) only at
    /// the sources told a refusal of S under a head other than S's now and those whose room mark
    /// of S is owed (`Store::room_marks`). Nothing while S takes nothing (`Store::unheld`): its
    /// mark stands until it is judged again. A place it loaded (its record not in memory) goes
    /// once written. O(the sources holding a place or a room mark of S, and the
    /// connections).
    fn pull_anew(&mut self, ctx: &mut Ctx, s: SyncId) {
        if ctx.store.unheld(&s) {
            return;
        }
        let pulling: BTreeMap<Source, ConnId> = self.holders.get(&s).into_iter().flatten().filter_map(|c| self.pull.get(c).map(|p| (p.src, *c))).collect();
        let held: BTreeSet<Source> = self.places.keys().copied().collect();
        let read = ctx.store.with_read(|t| {
            let everywhere = Store::anew_everywhere(t, &s)?;
            let mut out = BTreeSet::new();
            let tags: &[u8] = if everywhere { &[AT_STREAM, JOIN_FROM, TOLD] } else { &[TOLD] };
            for tag in tags {
                out.extend(t.records_with_row(&s, *tag, b"", usize::MAX)?);
            }
            Ok((everywhere, out))
        });
        let head = ctx.store.head_id(&s);
        let marks = ctx.store.room_marks(&s);
        let ((everywhere, stored), head, marks) = match (read, head, marks) {
            (Ok(x), Ok(h), Ok(m)) => (x, h, m),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return self.failed(Err(e)),
        };
        let owed: BTreeSet<Source> = marks.iter().filter(|(_, owed)| *owed).map(|(src, _)| *src).collect();
        let read: BTreeSet<Source> = if everywhere {
            self.places.iter().filter(|(_, pl)| pl.at_stream.contains(&s) || pl.stopped.contains_key(&s) || pl.joining.contains_key(&s) || pl.told.contains_key(&s)).map(|(src, _)| *src).chain(pulling.keys().copied()).chain(stored.into_iter().map(Source::Record)).chain(marks.iter().map(|(src, _)| *src)).collect()
        } else {
            self.places.iter().filter(|(_, pl)| pl.told.contains_key(&s)).map(|(src, _)| *src).chain(stored.into_iter().map(Source::Record)).chain(owed.iter().copied()).collect()
        };
        let srcs: Vec<Source> = match everywhere {
            true => read.iter().copied().collect(),
            false => read.iter().copied().filter(|src| owed.contains(src) || self.place(ctx.store, *src).told.get(&s).is_some_and(|h| *h != head)).collect(),
        };
        for src in &srcs {
            if let Some(p) = pulling.get(src).and_then(|c| self.pull.get_mut(c)) {
                p.join(s, None);
            }
            let place = self.place(ctx.store, *src);
            place.at_stream.remove(&s);
            place.stopped.remove(&s);
            place.joining.insert(s, None);
            place.stale.remove(&s);
            place.told.remove(&s);
        }
        let places = &self.places;
        let r = ctx.store.reset_anew(&s, &srcs, |t| {
            for src in &srcs {
                if let (Source::Record(rec), Some(p)) = (src, places.get(src)) {
                    p.write(t, rec, &s)?;
                    p.write_told(t, rec, &s)?;
                }
            }
            Ok(())
        });
        self.failed(r);
        // a place loaded here alone (its record not in memory) is in its rows
        for src in read.iter().filter(|src| !held.contains(src)) {
            self.places.remove(src);
        }
    }

    /// Sends Fetches while fewer than `FETCHES_OUT` are out: bodies of one fill class at a time,
    /// whatever sync IDs they are under (so a first sync of n sync IDs fetches in O(bodies /
    /// `MAX_FETCH_IDS`) round trips, not O(n)), the best first, order 0 before anything else; a blob asked anywhere (here
    /// under another sync ID, or at another source) stays queued until that ask is answered or
    /// past `ASKED_MS`, and one whose bytes arrived meanwhile is taken with them under its
    /// announced wrap, never fetched again (spec/sync-streams.md §4 Bodies: only blob IDs its
    /// store lacks are fetched).
    fn fetch(&mut self, ctx: &mut Ctx, conn: ConnId) {
        loop {
            let Some(p) = self.pull.get(&conn) else { return };
            if p.fetches.len() >= FETCHES_OUT {
                return;
            }
            let order0_out = p.fetches.values().any(|(_, c)| *c == 0);
            let mut pick: Option<u8> = None;
            let mut blobs = BTreeSet::new();
            let mut ids = Vec::new();
            let mut drop = Vec::new();
            let mut held = Vec::new();
            for (k, (s, b, announced)) in &p.queue {
                if p.settled.contains(&(*s, *b)) || p.failed.contains(&(*s, *b)) || !ctx.shared.members(conn).contains_key(s) {
                    drop.push(*k);
                    continue;
                }
                if self.asked.get(b).is_some_and(|(_, at)| at.after(ASKED_MS) > ctx.mono) {
                    continue;
                }
                if let Some((wrap, stamp)) = *announced
                    && let Some(bytes) = ctx.store.bytes(b).ok().flatten()
                {
                    held.push((*k, *s, *b, wrap, stamp, bytes));
                    continue;
                }
                match pick {
                    None => {
                        if order0_out && k.0 != 0 {
                            break;
                        }
                        pick = Some(k.0);
                    }
                    Some(pc) if pc != k.0 => continue,
                    _ => {}
                }
                // one blob once per Fetch: the same blob under another sync ID waits for it
                if !blobs.insert(*b) {
                    continue;
                }
                ids.push((*k, *s, *b));
                if ids.len() >= MAX_FETCH_IDS {
                    break;
                }
            }
            let Some(p) = self.pull.get_mut(&conn) else { return };
            for k in drop {
                p.queue.remove(&k);
            }
            if !held.is_empty() {
                for (k, s, b, wrap, stamp, bytes) in held {
                    if let Some(p) = self.pull.get_mut(&conn) {
                        p.queue.remove(&k);
                    }
                    self.take_held(ctx, conn, s, b, wrap, stamp, &bytes);
                }
                self.drain(ctx, conn);
                continue;
            }
            let Some(c) = pick else { return };
            let pairs: Vec<(SyncId, BlobId)> = ids.iter().map(|(_, s, b)| (*s, *b)).collect();
            let Some(id) = ctx.wire.request(conn, Msg::Fetch { id: 0, max_reply: REPLY_BUDGET as u64, ids: grouped(&pairs) }) else { return };
            for (k, _, b) in &ids {
                p.queue.remove(k);
                self.asked.insert(*b, (conn, ctx.mono));
            }
            p.fetches.insert(id, (pairs, c));
        }
    }

    /// A FetchReply (or a Fetch skipped or refused: none of its IDs): the rest of a prefix is asked
    /// again before what came is applied, so it stays asked and owed (a partial fill never counts
    /// as caught up); what came is taken; a reply with none fails every ID at this source. An item
    /// for an ID not asked is ignored.
    fn fetched(&mut self, ctx: &mut Ctx, conn: ConnId, id: Id, items: Vec<Fetched>) {
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let Some((ids, c)) = p.fetches.remove(&id) else { return };
        // each blob is asked once per Fetch: an item names its pair by its blob
        let of: BTreeMap<BlobId, SyncId> = ids.iter().map(|(s, b)| (*b, *s)).collect();
        let mut items = items;
        let mut seen = BTreeSet::new();
        items.retain(|f| of.contains_key(&f.blob_id) && seen.insert(f.blob_id));
        let rest: Vec<(SyncId, BlobId)> = if items.is_empty() { Vec::new() } else { ids.iter().filter(|(_, b)| !seen.contains(b)).copied().collect() };
        if !rest.is_empty()
            && let Some(again) = ctx.wire.request(conn, Msg::Fetch { id: 0, max_reply: REPLY_BUDGET as u64, ids: grouped(&rest) })
        {
            for (_, b) in &rest {
                self.asked.insert(*b, (conn, ctx.mono));
            }
            p.fetches.insert(again, (rest, c));
        }
        let Some(p) = self.pull.get_mut(&conn) else { return };
        if items.is_empty() {
            p.failed.extend(ids.iter().copied());
        }
        for (_, b) in ids.iter().filter(|(_, b)| items.is_empty() || seen.contains(b)) {
            if self.asked.get(b).is_some_and(|(x, _)| *x == conn) {
                self.asked.remove(b);
            }
        }
        for f in items {
            let Some(s) = of.get(&f.blob_id).copied() else { continue };
            match f.entry {
                Some((bytes, wrap, stamp)) => self.take_body(ctx, conn, s, f.blob_id, wrap, stamp, &bytes),
                None => {
                    if let Some(p) = self.pull.get_mut(&conn) {
                        p.failed.insert((s, f.blob_id));
                    }
                }
            }
        }
        self.drain(ctx, conn);
    }

    /// Applies the messages in hand, in order, while the first owes nothing: an owed body is
    /// settled once its entry is taken under its own sync ID (bytes held under another are taken
    /// with them first, `fetch`), no longer wanted (not a member here), or this source lacks it.
    fn drain(&mut self, ctx: &mut Ctx, conn: ConnId) {
        loop {
            let Some(p) = self.pull.get(&conn) else { return };
            let Some(front) = p.pending.front() else { break };
            let members = ctx.shared.members(conn);
            let ready = front.owed.iter().all(|(s, b)| p.settled.contains(&(*s, *b)) || p.failed.contains(&(*s, *b)) || !members.contains_key(s) || ctx.store.entry(s, b).ok().flatten().is_some());
            if !ready {
                return;
            }
            let Some(batch) = self.pull.get_mut(&conn).and_then(|p| p.next_held()) else { return };
            for (s, b) in &batch.owed {
                self.known.hand(s, b, false);
            }
            self.apply(ctx, conn, batch);
        }
        if let Some(p) = self.pull.get_mut(&conn) {
            p.settled.clear();
            p.taken.clear();
            // what failed here matters only to messages in hand (an announcement again clears it)
            if p.pending.is_empty() {
                let failed = std::mem::take(&mut p.failed);
                p.queue.retain(|_, x| !failed.contains(&(x.0, x.1)));
            }
        }
    }

    /// Applies one message: what each source holds (`known`; a deletion only says the source no
    /// longer holds it, a head names its step), then the cursor stored (SN_cursor: only now),
    /// joins moved, and an Applied when asked (spec/sync-streams.md §4 Applying, Reports); for a
    /// record source all in one transaction.
    fn apply(&mut self, ctx: &mut Ctx, conn: ConnId, batch: Batch) {
        let members: BTreeSet<SyncId> = ctx.shared.members(conn).keys().copied().collect();
        // the members a reply's whole listing covers, as still shared
        let covered: BTreeSet<SyncId> = batch.reply.iter().flat_map(|r| r.covered.intersection(&members).copied()).collect();
        let Some(p) = self.pull.get_mut(&conn) else { return };
        let src = p.src;
        if batch.reply.as_ref().is_some_and(|r| r.whole) && p.listing.is_none() {
            // the whole listing covers the members its first page does: their joins from the
            // start are part of it
            p.listing = Some(covered.iter().map(|s| (*s, BTreeSet::new())).collect());
            p.join_listing.retain(|s, _| !covered.contains(s));
        }
        let mut listing = p.listing.take();
        let mut join_listing = std::mem::take(&mut p.join_listing);
        let mut ops = Vec::new();
        // the members a deletion here shows a refused entry of may be gone at this source
        // (`Store::refused_may_be_gone`)
        let mut gone: BTreeSet<SyncId> = BTreeSet::new();
        for (s, e) in &batch.events {
            if !members.contains(s) {
                continue;
            }
            self.work.applied += 1;
            match e {
                Event::Added { blob_id: b, blob, wrap, stamp } => {
                    if let Some(st) = stamp
                        && ctx.store.holding(s) == Some(Holding::Read)
                    {
                        self.new_stamp(ctx, src, s, b, wrap, st);
                    }
                    let class = match blob {
                        Some(v) => Prefix::parse(v).map_or(Class::Durable, |p| p.class()),
                        None => ctx.store.entry(s, b).ok().flatten().map_or(Class::Durable, |e| e.class),
                    };
                    let at = if class == Class::Ephemeral { Source::Conn(conn) } else { src };
                    let concerned = concerns(ctx, self.pull.get(&conn), s, b);
                    if concerned {
                        ops.push((at, Op::Add(*s, *b)));
                    }
                    // a listing under way keeps only what its end could replace (presence of
                    // `src`, which `concerns` bounds), so a source listing made-up IDs grows it not
                    let listed = listing.as_ref().is_some_and(|l| l.contains_key(s)) || join_listing.contains_key(s);
                    if listed && (concerned || self.known.knows(src, s, b)) {
                        if let Some(l) = listing.as_mut().and_then(|l| l.get_mut(s)) {
                            l.insert(*b);
                        }
                        if let Some(l) = join_listing.get_mut(s) {
                            l.insert(*b);
                        }
                    }
                }
                Event::Deleted(b) => {
                    ops.push((src, Op::Remove(*s, *b)));
                    ops.push((Source::Conn(conn), Op::Remove(*s, *b)));
                    let concerned = concerns(ctx, self.pull.get(&conn), s, b);
                    if concerned || self.knows(src, Some(conn), s, b) {
                        let _ = ctx.store.saw_deleted(src, s, b);
                    }
                    if !concerned && listing.is_none() && !join_listing.contains_key(s) {
                        gone.insert(*s);
                    }
                }
                Event::Head(step) => ops.push((src, Op::Head(*s, step.id()))),
                _ => {}
            }
        }
        // marked durably before the place passes what showed it
        for s in &gone {
            if let Err(e) = ctx.store.refused_may_be_gone(s, src) {
                return self.failed(Err(e));
            }
        }
        // a listing from the start stores no cursor until it is read to its end: one cut short (a
        // connection lost, a restart) is read from the start again, so a listing that replaces
        // presence is always a whole one (spec/sync-streams.md §4 Applying)
        let mid_listing = batch.reply.as_ref().is_some_and(|r| r.more) && listing.is_some();
        let place = self.place(ctx.store, src);
        let cursor = (batch.cursor.is_some() || batch.reply.as_ref().is_some_and(|r| r.whole)) && !mid_listing;
        let was_cursor = place.cursor.clone();
        let was: BTreeMap<SyncId, (bool, Option<Option<Cursor>>)> = batch.reply.iter().flat_map(|r| if r.whole { covered.iter().copied().collect::<Vec<_>>() } else { r.asked.iter().map(|(s, _)| *s).collect() }).map(|s| (s, (place.at_stream.contains(&s), place.join_from(&s).cloned()))).collect();
        if cursor {
            place.cursor = batch.cursor.clone();
        }
        let mut touched: Vec<SyncId> = Vec::new();
        let mut listed: BTreeMap<SyncId, BTreeSet<BlobId>> = BTreeMap::new();
        if let Some(r) = &batch.reply {
            if r.whole {
                // every member it covers from the start: each at the stream now
                for s in covered.iter().filter(|s| !matches!(r.joins.get(s), Some(None))) {
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
                for (s, l) in seen {
                    if members.contains(&s) {
                        listed.insert(s, l);
                    }
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
        // only rows that differ from what is stored are written: a reply that moved nothing writes
        // nothing
        let place = self.place(ctx.store, src);
        touched.retain(|s| was.get(s) != Some(&(place.at_stream.contains(s), place.join_from(s).cloned())));
        let moved_cursor = cursor && place.cursor != was_cursor;
        // an Applied says what is stored: none for what failed to be
        if !self.save(ctx, src, &touched, moved_cursor, ops) {
            return;
        }
        // a listing from the start read to its end, its bodies settled (`drain`): S's first sync
        // here ended (spec/sync-streams.md §5)
        let place = self.place(ctx.store, src);
        let ended: Vec<SyncId> = listed.keys().filter(|s| place.at_stream.contains(*s)).copied().collect();
        for s in ended {
            let r = ctx.store.set_first_synced(&s);
            self.failed(r);
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
