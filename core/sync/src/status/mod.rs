//! Status (spec/sync-status.md): sources and caught up, the complete pass, own commits held
//! elsewhere, and what `status` and `wait` say per sync ID.
//!
//! **Principle:** status says only what is true now, per sync ID, of the sources connected now;
//! nothing is synced with nobody connected, and no word of a peer counts until its stream showed
//! it (model: core/test/tla/net/NetStream.tla, `Synced` and `CaughtUpHolds`: a source is caught
//! up once this side applied its stream to the end and it applied everything served to it).
//!
//! What a source is caught up on, full or refusing is streams' (stamped per connection and per
//! (source, S)), so a sync ID's status is read when asked, from its sources: O(sources of S),
//! nothing per sync ID while idle and nothing on a push that changes no answer someone asked
//! for. Status itself keeps what needs acting on, each an `Effects` key over stamped values:
//! - the members of S per source (a record, or the connection of one kept nowhere), from opens'
//!   member-level `Moved` (an open, a close, `Gone`, a record read from its rows at its take,
//!   `record_gone`), and the connection per source (`Moved::Taken`, `Released`): S's sources are
//!   its members whose record a connection holds, read where asked, so a reconnect moves only
//!   what reads that record's connection;
//! - lacking counts per (S, source keeping S unread): the stamped entries here its stream did
//!   not show (spec/sync-status.md §1: a source lacks only what it would pull);
//! - per own commit under a read S: held elsewhere (§2), recorded on the entry durably
//!   (`Store::set_elsewhere`);
//! - per self-removal the engine waits on: done once, under each read S it has a body under, it
//!   is held elsewhere or no peer but this account's own nodes shares S (spec/permissions.md §3
//!   Lost access); with no such S, at once. Told to the engine (`removal_done`);
//! - complete passes (§1) of each sync ID the engine wants one of, a fresh Pull at each source,
//!   ended by every source caught up since and every recorded peer read at its next connection,
//!   or `PASS_WAIT_MS` on the monotonic clock; each end told to the engine
//!   (`note_complete_pass`). Its start is also a wall-dated row (`Ground::set_pass_begun`), kept
//!   while it is under way and only to say how much was waited before a restart: a start begins
//!   each pass under way at the stop again, its wait cut by the wall time since the row, between
//!   0 and `PASS_WAIT_MS`; a row ahead of the wall clock (set back across a restart) counts as
//!   now and is rewritten so, so each run waits at most `PASS_WAIT_MS` and what the wall clock
//!   shows waited across restarts adds up;
//! - per read S, whether this node is stranded there (spec/permissions.md §4, `stranding`): the
//!   engine's word (a current read epoch of S's thing known, none held) once S is heard out, the
//!   reading of "after a complete pass there"; or, with no source, opens' walk stopped at a
//!   source (`walk_stop`); inbox sends the report.
//!
//! Only `handle` makes outputs: reading status or a wait changes nothing.

mod live;

pub use live::{Live, NetView};

use crate::opens::{LeftAt, Moved, Opens};
use crate::read::{Read, Verdict};
use crate::session::Sessions;
use crate::store::Source;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Holding, Position, RecordId, Result, Scope, SourceClass, Waiting};
use crate::unread::Unread;
use osis_base::memo::{Clock, Effects, Stamped, StampedSet};
use osis_base::{BlobId, CommitId, Mono, SyncId, Tid, WallMs};
use osis_engine::sync::{Stranding, SyncSet};
use osis_proto::limits::PASS_WAIT_MS;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The connection holding a source now, and who its peer proved there: readers are counted by
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Up {
    pub conn: ConnId,
    pub node: Option<Tid>,
}

/// A source of S: a peer with S open on a connection up now (spec/sync-status.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Src {
    pub class: SourceClass,
    /// Its record, else the connection.
    pub at: Source,
    /// The node it proved: readers are counted by identity.
    pub node: Option<Tid>,
}

impl Src {
    pub fn record(&self) -> Option<RecordId> {
        match self.at {
            Source::Record(r) => Some(r),
            Source::Conn(_) => None,
        }
    }
}

/// One source's state for S (spec/sync-status.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStatus {
    pub src: Src,
    pub caught_up: bool,
    /// Stamped entries here its stream did not show (sources keeping S unread; 0 for readers).
    pub lacking: u64,
    pub full: bool,
    pub refusing: bool,
}

impl SourceStatus {
    /// A full or refusing source is named, not waited on (§1).
    pub fn waited(&self) -> bool {
        !self.full && !self.refusing
    }
}

/// How S stands here now (spec/sync-status.md §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    /// How this node holds S (none: S is no longer in the sync set, a source still sharing it).
    pub holding: Option<Holding>,
    /// Its sources, by connection: none is unconnected.
    pub sources: BTreeMap<ConnId, SourceStatus>,
    /// Stranded here (spec/permissions.md §4): kept unread at a head past its keys, or read and
    /// heard out holding no current read secret (`Status::strandings`).
    pub stranded: bool,
    /// While a complete pass of S waits: the recorded peers it waits for.
    pub pass_waits: Option<BTreeSet<RecordId>>,
    /// This node's own commits under S not held elsewhere yet (none: not known yet).
    pub unheld: Option<usize>,
}

impl SyncStatus {
    /// Every source caught up but those named full or refusing, and one such at least (§1).
    pub fn heard_out(&self) -> bool {
        heard_out(self.sources.values().map(|x| (x.waited(), x.caught_up)))
    }

    /// The readers among its sources, counted by the nodes proven (§1).
    pub fn readers(&self) -> BTreeSet<Tid> {
        self.sources.values().filter(|x| x.src.class == SourceClass::Reader).filter_map(|x| x.src.node).collect()
    }

    /// What `wait` waits for: heard out, and every own commit under S held elsewhere (§3).
    pub fn synced(&self) -> bool {
        self.heard_out() && self.unheld == Some(0)
    }
}

/// Over (waited, caught up) per source: a source full or refusing is not waited on, and only
/// such sources is no more heard out than none (§1).
fn heard_out(sources: impl Iterator<Item = (bool, bool)>) -> bool {
    let mut any = false;
    for (waited, caught_up) in sources {
        if waited {
            if !caught_up {
                return false;
            }
            any = true;
        }
    }
    any
}

/// `heard_out` over S's sources `srcs` as `net` reads them now.
fn heard_out_at(net: &(impl Net + ?Sized), s: &SyncId, srcs: &BTreeMap<ConnId, Src>) -> bool {
    heard_out(srcs.iter().map(|(c, src)| (!net.full(*c, s) && !net.refusing(src.at, s), net.caught_since(*c, s).is_some())))
}

/// What status reads of streams and unread when asked (all stamped reads, memo-safe).
pub trait Net {
    /// The place of the Pull whose answer S's stream on `conn` is caught up by (none: not caught
    /// up, both ways: spec/sync-status.md §1), among `pull_seq`'s.
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<u64>;
    /// The Pulls sent so far (`Streams::pull_seq`): a pass begun now counts only a Pull sent
    /// after it, whatever the clock reads.
    fn pull_seq(&self) -> u64;
    /// The peer on `conn` told on it that it is full for S (spec/sync-streams.md §4 Full).
    fn full(&self, conn: ConnId, s: &SyncId) -> bool;
    fn refusing(&self, at: Source, s: &SyncId) -> bool;
    fn stranded(&self, s: &SyncId) -> bool;
}

/// What status reads and does at a settle besides `Net` (the product's is `Live`; a test's a
/// fake). Reads are stamped.
pub trait Ground: Net {
    /// The monotonic clock (a pass's `PASS_WAIT_MS` runs on it).
    fn mono(&self) -> Mono;
    /// The latest wall reading: dates a pass's start row, which says only how much a pass begun
    /// again at a start waited already.
    fn now(&self) -> WallMs;
    /// The start of each pass under way, kept durably: one row per S, written as it begins.
    fn passes_begun(&mut self) -> Result<BTreeMap<SyncId, WallMs>>;
    /// Writes S's pass start (`Some`, as it begins) or drops it (`None`, as it ends).
    fn set_pass_begun(&mut self, s: &SyncId, at: Option<WallMs>) -> Result<()>;
    /// The sync IDs this node syncs (`Store::syncs`: the sync set, and each leaving one while it
    /// waits), whole.
    fn syncs(&mut self) -> Arc<SyncSet>;
    /// The entries of S here a source keeping S unread would pull: the stamped ones.
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>>;
    /// Whether that source's stream showed `b` present under S (streams' `knows`).
    fn knows(&self, at: Source, conn: ConnId, s: &SyncId, b: &BlobId) -> bool;
    /// `knows` of the record at `at`: by its rows, else on the connection holding it now (that
    /// connection read only where its rows show nothing).
    fn knows_now(&self, at: Source, s: &SyncId, b: &BlobId) -> bool;
    /// The position of this node's log the peer on `conn` reported for S (opens' Positions).
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position>;
    /// The `until` of member S on `conn` (opens: a member being ended).
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position>;
    /// The records holding S as a member (opens).
    fn records_holding(&mut self, s: &SyncId) -> Result<BTreeSet<RecordId>>;
    /// This node's commits and self-removals with a body under S (engine).
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>>;
    /// The self-removals whose secrets wait on being held elsewhere (engine).
    fn self_removals(&mut self) -> Arc<BTreeSet<CommitId>>;
    /// Read's verdict on `c`'s body under S.
    fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict>;
    /// The entries of S here holding a blob of `c` (the engine's `commit_blobs`, the store's
    /// entries: both stamped).
    fn commit_entries(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>>;
    /// Where this node's log first held entry `b` of S.
    fn first_logged(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<Position>>;
    /// Whether a source was recorded holding entry `b` of S, durably.
    fn elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<bool>;
    fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Whether a source that proved node `node` counts toward own commit `c` being held
    /// elsewhere (`Engine::counts_for_leave`): for a self-removal the engine waits on, only one
    /// whose proven node still holds a role on each thing left, with the leave applied
    /// (spec/sync-status.md §2); for any other commit, every source.
    fn counts_for(&mut self, c: &CommitId, node: Option<Tid>) -> bool;
    /// Some peer is to be waited for on S (`Opens::waited`); `own`: this account's own nodes
    /// count (a self-removal skips them). Stamped.
    fn waited(&mut self, s: &SyncId, own: bool) -> Result<bool>;
    /// Tells the engine sync is done waiting for a self-removal (it drops the secrets).
    fn removal_done(&mut self, c: &CommitId) -> Result<()>;
    /// Whether the engine wants a complete pass of S, and the pass place the pass must begin
    /// after (spec/permissions.md §3 Complete pass: the newest role commit of one of S's actors
    /// from elsewhere it applied; spec/sync-status.md §3).
    fn pass_wanted(&mut self, s: &SyncId) -> Result<Option<u64>>;
    /// Begins a pass: the next pass place (`Engine::begin_pass`), one count with role arrivals and
    /// leaves, so a pass counts for a want only when begun above its place.
    fn begin_pass(&mut self) -> u64;
    /// A complete pass of S begun at place `began` ended (the engine drops S from
    /// `pass_wanted` once `began` is above its place).
    fn note_complete_pass(&mut self, s: &SyncId, began: u64) -> Result<()>;
    /// No pass is in flight: what lost a need goes now (`Engine::settle_lost`).
    fn settle_lost(&mut self) -> Result<()> {
        Ok(())
    }
    /// Whether this node holds no current read secret of read S's thing though one is known
    /// (`Engine::stranded`), with what its report names.
    fn stranding(&mut self, s: &SyncId) -> Result<Option<Arc<Stranding>>>;
    /// Where this node's walk of S stopped at a source (`Opens::walk_stop`, stamped).
    fn walk_stop(&self, s: &SyncId) -> Option<crate::opens::Stop>;
    /// The report of this node stranded on read S, its walk stopped at `step`
    /// (`Engine::stranding`).
    fn walk_stranding(&mut self, s: &SyncId, step: crate::opens::Stop) -> Result<Option<Arc<Stranding>>>;
    /// The passes other modules want, each after a pass place: a leaving sync ID's, after the
    /// place it left at (crate::leave); read's, after its judgements outside S's required set
    /// (`Read::passes_wanted`). The newer place where both want one.
    fn module_passes(&mut self) -> Arc<BTreeMap<SyncId, u64>> {
        Arc::default()
    }
}

/// A complete pass of S under way (§1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pass {
    /// When it gives up on the recorded peers, on the monotonic clock: `PASS_WAIT_MS` after it
    /// began, less what it waited before a restart.
    deadline: Mono,
    /// Its pass place (`Ground::begin_pass`): what the engine is told, and what the engine's
    /// and leave's wants are compared with.
    noted: u64,
    /// The recorded peers not read since it began.
    waits: BTreeSet<RecordId>,
    /// The Pulls sent before it began (`Net::pull_seq`): a source is fresh by a later one.
    pulled: u64,
}

/// One own commit under S: held elsewhere, and by which entry (to record it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum Held {
    #[default]
    No,
    Yes(Option<BlobId>),
}

/// A pass's state as its sources now stand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PassNow {
    /// Recorded peers read since it began.
    read: BTreeSet<RecordId>,
    done: bool,
}

/// Work done, counted (tests: scaling by counting work).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Source states read (status asked, passes judged).
    pub sources: u64,
    /// Own commits judged for held elsewhere.
    pub commits: u64,
    /// Lacking counts taken again.
    pub lacking: u64,
    /// Self-removals judged for done.
    pub removals: u64,
}

#[derive(Clone)]
pub struct Status {
    clock: Clock,
    set: Effects<(), Arc<SyncSet>>,
    holding: Stamped<SyncId, Holding>,
    /// Per S, its members by source and the class each opened with: kept across the record's
    /// connections, moved only by a member opening or closing (stamped per S).
    members: Stamped<SyncId, Arc<BTreeMap<Source, SourceClass>>>,
    /// The sync IDs each source holds as members: what a record going, or read from its rows,
    /// moves.
    of_source: BTreeMap<Source, BTreeSet<SyncId>>,
    /// Per source, the connection holding it now (stamped per source: a take or release moves
    /// only what read it).
    up: Stamped<Source, Up>,
    /// Per (S, source) of a store member: followed across the record's connections, until S
    /// leaves the record (a record kept nowhere: until its connection ends).
    lacking_fx: Effects<(SyncId, Source), u64>,
    lacking: Stamped<(SyncId, Source), u64>,
    own_fx: Effects<SyncId, Arc<BTreeSet<CommitId>>>,
    held_fx: Effects<(SyncId, CommitId), Held>,
    /// Per read S whose own commits are known: those not held elsewhere.
    unheld: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    /// The read sync IDs each own commit has a body under.
    by_commit: BTreeMap<CommitId, BTreeSet<SyncId>>,
    /// Per read S, its own commits as `by_commit` holds them (`own_fx`'s value last taken).
    own: BTreeMap<SyncId, Arc<BTreeSet<CommitId>>>,
    /// Own commits held elsewhere under every sync ID they have a body under.
    held: StampedSet<CommitId>,
    removals_fx: Effects<(), Arc<BTreeSet<CommitId>>>,
    removals: StampedSet<CommitId>,
    /// Per self-removal: sync is done waiting for it (held, or not shared, under each read S).
    release_fx: Effects<CommitId, bool>,
    wanted_fx: Effects<SyncId, Option<u64>>,
    passes: Stamped<SyncId, Pass>,
    pass_fx: Effects<SyncId, PassNow>,
    /// Per read S: stranded there (heard out, and the engine's `stranded`).
    stranding_fx: Effects<SyncId, Option<Arc<Stranding>>>,
    strandings: Stamped<SyncId, Arc<Stranding>>,
    /// Per S held, the place (`Ground::pass_seq`) of its last complete pass here: what a leaving S
    /// waits on (crate::leave). Goes with S.
    done: Stamped<SyncId, u64>,
    /// The passes leave and read want (`Ground::module_passes`), whole.
    modules_fx: Effects<(), Arc<BTreeMap<SyncId, u64>>>,
    /// S owes another pass once the one under way ends.
    again: BTreeSet<SyncId>,
    /// The passes under way at the stop are begun again (at the first settle).
    resumed: bool,
    /// Sources that left since the last settle: what their streams showed still counts for held
    /// elsewhere at that settle (a source closing S in the step that showed an entry, as a peer
    /// judging this node departed by the self-removal it just applied does).
    leaving: BTreeMap<SyncId, BTreeMap<ConnId, (Src, LeftAt)>>,
    work: Work,
}

impl Default for Status {
    fn default() -> Self {
        Status {
            clock: Clock::default(),
            set: Effects::new("status: sync set"),
            holding: Stamped::default(),
            members: Stamped::default(),
            of_source: BTreeMap::new(),
            up: Stamped::default(),
            lacking_fx: Effects::new("status: lacking"),
            lacking: Stamped::default(),
            own_fx: Effects::new("status: own commits"),
            held_fx: Effects::new("status: held elsewhere"),
            unheld: Stamped::default(),
            by_commit: BTreeMap::new(),
            own: BTreeMap::new(),
            held: StampedSet::default(),
            removals_fx: Effects::new("status: self-removals"),
            removals: StampedSet::default(),
            release_fx: Effects::new("status: self-removal done"),
            wanted_fx: Effects::new("status: passes wanted"),
            passes: Stamped::default(),
            pass_fx: Effects::new("status: pass"),
            stranding_fx: Effects::new("status: stranded"),
            strandings: Stamped::default(),
            done: Stamped::default(),
            modules_fx: Effects::new("status: passes modules want"),
            again: BTreeSet::new(),
            resumed: false,
            leaving: BTreeMap::new(),
            work: Work::default(),
        }
    }
}

impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Status").field("passes", &self.passes.len()).finish_non_exhaustive()
    }
}

/// S's sources now: its members a connection holds, by that connection. Stamped reads of S's
/// members and of each member's connection, so a take or release moves only what read it.
fn sources_of(members: &Stamped<SyncId, Arc<BTreeMap<Source, SourceClass>>>, up: &Stamped<Source, Up>, s: &SyncId) -> BTreeMap<ConnId, Src> {
    let Some(m) = members.get(s) else { return BTreeMap::new() };
    m.iter().filter_map(|(src, class)| up.get(src).map(|u| (u.conn, Src { class: *class, at: *src, node: u.node }))).collect()
}

impl Status {
    // ---- the product's entry points ----

    /// A member or a record moved (the driver hands each `Moved` here as to streams): a member
    /// opening or closing moves its S; a take or release moves only the record's connection.
    pub fn moved(&mut self, sessions: &Sessions, opens: &Opens, m: &Moved) {
        let up = |conn: ConnId| {
            let proven = sessions.get(conn).map(|x| x.proven());
            Up { conn, node: proven.and_then(|p| p.node()) }
        };
        match *m {
            Moved::Joined(conn, s, _) => {
                let Some(member) = opens.member(conn, &s) else { return };
                let src = opens.record(conn).map_or(Source::Conn(conn), Source::Record);
                // a record kept nowhere is its connection: up while it has a member
                if matches!(src, Source::Conn(_)) && !self.up.contains_key(&src) {
                    self.taken(src, up(conn));
                }
                self.opened(s, src, member.class);
            }
            Moved::Left(conn, s, at) => self.left(s, conn, at),
            Moved::Gone(rid, s) => self.gone(rid, s),
            Moved::Taken(conn, rid, read) => {
                let src = Source::Record(rid);
                self.taken(src, up(conn));
                // read from its rows: its members are learned now
                if read {
                    for (s, m) in opens.members(conn) {
                        self.opened(*s, src, m.class);
                    }
                }
            }
            Moved::Released(_, rid) => self.released(Source::Record(rid)),
            Moved::Until(..) | Moved::Forgot(..) => {}
        }
    }

    /// The product's settle: over the engine, the store, opens, streams, read and unread.
    /// `pulls`: the connections streams is to Pull again on for a pass (`Streams::pull_again`).
    #[allow(clippy::too_many_arguments)]
    pub fn settle(&mut self, cx: &mut Cx, opens: &Opens, streams: &Streams, read: &Read, unread: &Unread, leave: &crate::leave::Leave, pulls: &mut Vec<ConnId>) -> Result<bool> {
        self.settle_on(&mut Live { cx, opens, streams, read, unread, leave }, pulls)
    }

    // ---- the core ----

    /// Member S of the record at `src` opened (or opened again with `class`).
    pub fn opened(&mut self, s: SyncId, src: Source, class: SourceClass) {
        osis_base::costs::count("status: members moved", 1);
        let mut now = self.members.get(&s).map(|x| (**x).clone()).unwrap_or_default();
        if now.insert(src, class) != Some(class) {
            self.members.insert(s, Arc::new(now));
        }
        self.of_source.entry(src).or_default().insert(s);
        if class == SourceClass::Store {
            self.lacking_fx.want((s, src));
        } else {
            self.unwant_lacking(src, s);
        }
    }

    /// A connection holds the record at `src` now: its members are sources there.
    pub fn taken(&mut self, src: Source, up: Up) {
        self.up.insert(src, up);
    }

    /// No connection holds the record at `src`: it keeps its members, none a source. Nothing of
    /// where its peer stood is kept: a report racing the drop is made again by the next
    /// connection's Pull.
    pub fn released(&mut self, src: Source) {
        self.up.remove(&src);
    }

    /// Member S of the record at `src` is a member no more: its lacking count goes.
    fn drop_member(&mut self, s: SyncId, src: Source) -> Option<SourceClass> {
        self.unwant_lacking(src, s);
        if let Some(ids) = self.of_source.get_mut(&src) {
            ids.remove(&s);
            if ids.is_empty() {
                self.of_source.remove(&src);
                // a record kept nowhere is its connection: down with its last member
                if matches!(src, Source::Conn(_)) {
                    self.released(src);
                }
            }
        }
        let was = self.members.get(&s)?.clone();
        let mut now = (*was).clone();
        let class = now.remove(&src)?;
        osis_base::costs::count("status: members moved", 1);
        if now.is_empty() {
            self.members.remove(&s);
        } else {
            self.members.insert(s, Arc::new(now));
        }
        Some(class)
    }

    fn unwant_lacking(&mut self, src: Source, s: SyncId) {
        self.lacking_fx.unwant(&(s, src));
        self.lacking.remove(&(s, src));
    }

    /// Member S of record `id`, which no connection holds, closed (`Moved::Gone`).
    pub fn gone(&mut self, id: crate::types::RecordId, s: SyncId) {
        self.drop_member(s, Source::Record(id));
    }

    /// Record `id` went (evicted past `RECORD_BUDGET`, or another of its pair taken): its members go.
    pub fn record_gone(&mut self, id: crate::types::RecordId) {
        let src = Source::Record(id);
        for s in self.of_source.get(&src).cloned().unwrap_or_default() {
            self.drop_member(s, src);
        }
        self.released(src);
    }

    /// Member S closed on `conn`. `at`: where the peer stood as it closed, counted for held
    /// elsewhere at the next settle (its report and its close come in one step).
    pub fn left(&mut self, s: SyncId, conn: ConnId, at: LeftAt) {
        let up = self.up.get(&at.src).copied().filter(|u| u.conn == conn);
        let Some(class) = self.drop_member(s, at.src) else { return };
        if let Some(u) = up {
            let src = Src { class, at: at.src, node: u.node };
            self.leaving.entry(s).or_default().insert(conn, (src, at));
        }
    }

    /// One settle over `g`: whether anything another module reads changed. `pulls`: the
    /// connections a pass wants a fresh Pull on.
    pub fn settle_on(&mut self, g: &mut impl Ground, pulls: &mut Vec<ConnId>) -> Result<bool> {
        self.clock.set(g.mono().0);
        let mut acted = false;
        self.sync_set(g)?;
        self.count_lacking(g)?;
        acted |= self.held_elsewhere(g)?;
        self.leaving.clear();
        acted |= self.passes(g, pulls)?;
        // a lost need waits for no pass (spec/commits.md §5 What a held thing needs)
        if self.passes.is_empty() {
            g.settle_lost()?;
        }
        self.judge_strandings(g)?;
        Ok(acted)
    }

    /// The projection of the sync IDs this node syncs: a row per S held, read or kept unread (§3), and own commits
    /// followed per read S. A sync ID leaving the set takes its pass and its row with it, unless
    /// another module still wants that pass.
    fn sync_set(&mut self, g: &mut impl Ground) -> Result<()> {
        self.set.want(());
        if self.set.due().is_empty() {
            return Ok(());
        }
        let Some(set) = whole(&mut self.set, || g.syncs()) else { return Ok(()) };
        let gone: Vec<SyncId> = self.holding.keys().filter(|s| !set.ids.contains_key(*s)).copied().collect();
        let wanted = if gone.is_empty() { Arc::default() } else { g.module_passes() };
        for s in gone {
            self.holding.remove(&s);
            self.done.remove(&s);
            self.own_fx.unwant(&s);
            self.wanted_fx.unwant(&s);
            self.forget_own(&s);
            self.unstrand(&s);
            // its pass goes with it, but where a release waits on it (crate::leave: a thing that
            // left the node closure waits for a pass of each sync ID that carried it)
            if !wanted.contains_key(&s) && self.passes.remove(&s).is_some() {
                self.pass_fx.unwant(&s);
                self.again.remove(&s);
                g.set_pass_begun(&s, None)?;
            }
        }
        for (s, (_, h)) in &set.ids {
            if self.holding.insert(*s, *h) != Some(*h) {
                if h.opens() {
                    self.own_fx.want(*s);
                    self.wanted_fx.want(*s);
                    self.stranding_fx.want(*s);
                } else {
                    self.own_fx.unwant(s);
                    self.wanted_fx.unwant(s);
                    self.forget_own(s);
                    self.unstrand(s);
                }
            }
        }
        Ok(())
    }

    fn unstrand(&mut self, s: &SyncId) {
        self.stranding_fx.unwant(s);
        self.strandings.remove(s);
    }

    /// Per read S, whether this node is stranded there (spec/permissions.md §4): heard out (the
    /// reading of "after a complete pass there": every unrefusing source caught up) and the
    /// engine holding no current read secret of S's thing though one is known; or no source
    /// has S open and its walk stopped at one (spec/sync-ids.md §6 Stranded there: every source
    /// it reached refused every open it had to try). O(keys moved): S's sources are read only
    /// where the engine's word or a walk stop could make it stranded, so a source joining or
    /// leaving (a reconnect) judges no other S again.
    fn judge_strandings(&mut self, g: &mut impl Ground) -> Result<()> {
        for s in self.stranding_fx.due() {
            let (members, up) = (&self.members, &self.up);
            let r = self.stranding_fx.try_settle(&s, || {
                let (engine, walk) = (g.stranding(&s)?, g.walk_stop(&s));
                if engine.is_none() && walk.is_none() {
                    return Ok(None);
                }
                let srcs = sources_of(members, up, &s);
                if srcs.is_empty() {
                    return match walk {
                        Some(step) => g.walk_stranding(&s, step),
                        None => Ok(None),
                    };
                }
                Ok(if heard_out_at(&*g, &s, &srcs) { engine } else { None })
            })?;
            match r {
                Some((_, Some(x))) => {
                    self.strandings.insert(s, x);
                }
                Some((_, None)) => {
                    self.strandings.remove(&s);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The read sync IDs this node is stranded on, with what each report names (stamped).
    pub fn strandings(&self) -> &Stamped<SyncId, Arc<Stranding>> {
        &self.strandings
    }

    fn forget_own(&mut self, s: &SyncId) {
        let Some(commits) = self.own.remove(s) else { return };
        self.unheld.remove(s);
        for c in commits.iter().copied() {
            self.held_fx.unwant(&(*s, c));
            self.untrack(s, &c);
        }
    }

    /// Lacking counts per (S, source keeping S unread): O(S's stamped entries) per change of
    /// what that source showed or of S's entries here.
    fn count_lacking(&mut self, g: &mut impl Ground) -> Result<()> {
        for k in self.lacking_fx.due() {
            let (s, at) = k;
            self.work.lacking += 1;
            let Some((_, n)) = self.lacking_fx.try_settle(&k, || Ok::<_, crate::types::Error>(g.stamped(&s)?.iter().filter(|b| !g.knows_now(at, &s, b)).count() as u64))? else { continue };
            self.lacking.insert(k, n);
        }
        Ok(())
    }

    /// Own commits under each read S, held elsewhere (§2); a self-removal sync is done waiting
    /// for is told to the engine.
    fn held_elsewhere(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        self.removals_fx.want(());
        if !self.removals_fx.due().is_empty()
            && let Some(now) = whole(&mut self.removals_fx, || g.self_removals())
        {
            let gone: Vec<CommitId> = self.removals.iter().filter(|c| !now.contains(*c)).copied().collect();
            for c in gone {
                self.removals.remove(&c);
                self.release_fx.unwant(&c);
            }
            for c in now.iter() {
                if self.removals.insert(*c) {
                    self.release_fx.want(*c);
                }
            }
        }
        let mut moved = BTreeSet::new();
        for s in self.own_fx.due() {
            let Some((_, now)) = self.own_fx.try_settle(&s, || g.own_commits(&s))? else { continue };
            // by difference: one more own commit moves one entry
            let before = self.own.insert(s, now.clone()).unwrap_or_default();
            let was: Vec<CommitId> = before.difference(&now).copied().collect();
            let came: Vec<CommitId> = now.difference(&before).copied().collect();
            let mut unheld = self.unheld.get(&s).map(|x| (**x).clone()).unwrap_or_default();
            for c in was {
                self.held_fx.unwant(&(s, c));
                unheld.remove(&c);
                self.untrack(&s, &c);
                moved.insert(c);
            }
            for c in came.iter() {
                if self.by_commit.entry(*c).or_default().insert(s) {
                    self.held_fx.want((s, *c));
                    unheld.insert(*c);
                    moved.insert(*c);
                }
            }
            self.unheld.insert(s, Arc::new(unheld));
        }
        for (s, c) in self.held_fx.due() {
            self.work.commits += 1;
            let (members, up, leaving) = (&self.members, &self.up, &self.leaving);
            let r = self.held_fx.try_settle(&(s, c), || {
                let srcs = || {
                    let now = sources_of(members, up, &s);
                    now.into_iter().map(|(k, v)| (k, v, None)).chain(leaving.get(&s).into_iter().flatten().map(|(k, (v, at))| (*k, *v, Some(*at)))).collect()
                };
                held_at(g, &s, &c, srcs)
            });
            let Some((_, now)) = r? else { continue };
            if let Held::Yes(Some(b)) = now {
                g.set_elsewhere(&s, &b)?;
                acted = true;
            }
            let mut unheld = self.unheld.get(&s).map(|x| (**x).clone()).unwrap_or_default();
            let changed = if now == Held::No { unheld.insert(c) } else { unheld.remove(&c) };
            if changed {
                self.unheld.insert(s, Arc::new(unheld));
                moved.insert(c);
            }
        }
        for c in moved {
            let ids = self.by_commit.get(&c);
            let held = ids.is_some_and(|ids| !ids.is_empty() && ids.iter().all(|s| self.unheld.get(s).is_some_and(|u| !u.contains(&c))));
            if held {
                self.held.insert(c);
            } else {
                self.held.remove(&c);
            }
        }
        // `by_commit` is no stamped read, but each change of it writes `unheld` of that sync ID,
        // which the judgement reads (a sync ID added after a judgement can only keep it waiting)
        for c in self.release_fx.due() {
            self.work.removals += 1;
            let (by_commit, unheld) = (&self.by_commit, &self.unheld);
            let r = self.release_fx.try_settle(&c, || removal_done(g, &c, by_commit.get(&c).into_iter().flatten(), unheld));
            if let Some((_, true)) = r? {
                g.removal_done(&c)?;
                acted = true;
            }
        }
        Ok(acted)
    }

    fn untrack(&mut self, s: &SyncId, c: &CommitId) {
        if let Some(ids) = self.by_commit.get_mut(c) {
            ids.remove(s);
            if ids.is_empty() {
                self.by_commit.remove(c);
                self.held.remove(c);
            }
        }
    }

    /// Complete passes (§1, spec/permissions.md §3 Complete pass): begun for each sync ID the
    /// engine wants one of, each pass's end told.
    fn passes(&mut self, g: &mut impl Ground, pulls: &mut Vec<ConnId>) -> Result<bool> {
        let mut acted = false;
        // a pass under way at the stop is begun again, having waited what the wall clock shows
        // since its row, between 0 and PASS_WAIT_MS (spec/sync-status.md §1); a row ahead of the
        // wall clock counts as now, rewritten so: what is waited from here counts at a later start
        if !self.resumed {
            let (wall, mono) = (g.now(), g.mono());
            let wanted = g.module_passes();
            for (s, at) in g.passes_begun()? {
                // a sync ID out of the sync set no module wants a pass of takes its row with it
                if !self.holding.contains_key(&s) && !wanted.contains_key(&s) {
                    g.set_pass_begun(&s, None)?;
                    continue;
                }
                if at > wall {
                    g.set_pass_begun(&s, Some(wall))?;
                }
                let waited = wall.0.saturating_sub(at.0).min(PASS_WAIT_MS);
                self.begin_at(g, s, mono.after(PASS_WAIT_MS - waited), pulls)?;
            }
            self.resumed = true;
        }
        // per read S: whether the engine wants a pass, moved only when its want does
        for s in self.wanted_fx.due() {
            let Some((_, Some(since))) = self.wanted_fx.try_settle(&s, || g.pass_wanted(&s))? else { continue };
            self.want_pass(g, s, since, pulls)?;
        }
        // a pass of each S leave or read wants, begun after its place (crate::leave, read)
        self.modules_fx.want(());
        if !self.modules_fx.due().is_empty()
            && let Some(wanted) = whole(&mut self.modules_fx, || g.module_passes())
        {
            for (s, since) in wanted.iter() {
                if !self.done.get(s).is_some_and(|d| d > since) {
                    self.want_pass(g, *s, *since, pulls)?;
                }
            }
        }
        for s in self.pass_fx.due() {
            let Some(p) = self.passes.get(&s).cloned() else {
                self.pass_fx.unwant(&s);
                continue;
            };
            let (members, up, passes, clock, work) = (&self.members, &self.up, &self.passes, &self.clock, &mut self.work);
            let Some((_, now)) = self.pass_fx.settle(&s, || match passes.get(&s) {
                Some(p) => pass_now(&mut *g, clock, work, &s, p, &sources_of(members, up, &s)),
                None => PassNow::default(),
            }) else {
                continue;
            };
            if now.done {
                self.passes.remove(&s);
                self.pass_fx.unwant(&s);
                g.set_pass_begun(&s, None)?;
                self.done.insert(s, p.noted);
                // the engine is told of a pass's end only while it wants one of S: what its end
                // decides (re-seals, history adds, owed rotations) runs on the engine's causes,
                // not on a pass only leave or read wanted
                if g.pass_wanted(&s)?.is_some() {
                    g.note_complete_pass(&s, p.noted)?;
                }
                acted = true;
                if self.again.remove(&s) {
                    self.begin(g, s, pulls)?;
                }
            } else if !now.read.is_empty() {
                let waits = p.waits.difference(&now.read).copied().collect();
                self.passes.insert(s, Pass { waits, ..p });
            }
        }
        Ok(acted)
    }

    /// A pass of S begun after place `since` is wanted: one under way begun after it serves; one
    /// begun before it (a Pull sent before the moment ends no pass after it) is followed by one
    /// more once it ends; else one begins now.
    fn want_pass(&mut self, g: &mut impl Ground, s: SyncId, since: u64, pulls: &mut Vec<ConnId>) -> Result<()> {
        match self.passes.get(&s) {
            Some(p) if p.noted > since => {}
            Some(_) => {
                self.again.insert(s);
            }
            None => self.begin(g, s, pulls)?,
        }
        Ok(())
    }

    /// Begins a pass of S now, its start kept durably while it is under way.
    fn begin(&mut self, g: &mut impl Ground, s: SyncId, pulls: &mut Vec<ConnId>) -> Result<()> {
        let at = g.now();
        g.set_pass_begun(&s, Some(at))?;
        self.begin_at(g, s, g.mono().after(PASS_WAIT_MS), pulls)
    }

    /// Begins a pass of S giving up at `deadline`: a fresh Pull at each source, the recorded
    /// peers to wait for, and a new pass place (one begun again at a start counts for what
    /// wants a pass after a moment before the start).
    fn begin_at(&mut self, g: &mut impl Ground, s: SyncId, deadline: Mono, pulls: &mut Vec<ConnId>) -> Result<()> {
        let noted = g.begin_pass();
        let waits = g.records_holding(&s)?;
        pulls.extend(sources_of(&self.members, &self.up, &s).into_keys());
        self.passes.insert(s, Pass { deadline, noted, waits, pulled: g.pull_seq() });
        self.pass_fx.want(s);
        Ok(())
    }

    // ---- reads (stamped: memo-safe; none makes an output) ----

    /// Whether S has a source now (§1).
    pub fn sourced(&self, s: &SyncId) -> bool {
        !sources_of(&self.members, &self.up, s).is_empty()
    }

    /// Whether a complete pass of S begun after pass place `seq` (`Engine::pass_place`) ended,
    /// while S is held.
    pub fn passed_since(&self, s: &SyncId, seq: u64) -> bool {
        self.done.get(s).is_some_and(|d| *d > seq)
    }

    /// How S stands now: O(sources of S). None for a sync ID neither held nor shared.
    pub fn of(&self, s: &SyncId, net: &impl Net) -> Option<SyncStatus> {
        let holding = self.holding.get(s).copied();
        let srcs = sources_of(&self.members, &self.up, s);
        if holding.is_none() && srcs.is_empty() {
            return None;
        }
        let sources = srcs
            .iter()
            .map(|(c, src)| {
                let lacking = self.lacking.get(&(*s, src.at)).copied().unwrap_or(0);
                (*c, SourceStatus { src: *src, caught_up: net.caught_since(*c, s).is_some(), lacking, full: net.full(*c, s), refusing: net.refusing(src.at, s) })
            })
            .collect();
        let unheld = match holding {
            Some(Holding::Read | Holding::Keys) => self.unheld.get(s).map(|u| u.len()),
            _ => Some(0),
        };
        let pass_waits = self.passes.get(s).map(|p| p.waits.clone());
        Some(SyncStatus { holding, sources, stranded: net.stranded(s) || self.strandings.contains_key(s), pass_waits, unheld })
    }

    /// Every sync ID held or shared, as `of` says each: O(sync IDs × their sources).
    pub fn all(&self, net: &impl Net) -> BTreeMap<SyncId, SyncStatus> {
        let ids: BTreeSet<SyncId> = self.holding.keys().chain(self.members.keys()).copied().collect();
        ids.into_iter().filter_map(|s| Some((s, self.of(&s, net)?))).collect()
    }

    /// S heard out (§1): every source caught up but those full or refusing, and one such at
    /// least.
    /// O(sources of S).
    pub fn heard_out(&self, s: &SyncId, net: &impl Net) -> bool {
        heard_out_at(net, s, &sources_of(&self.members, &self.up, s))
    }

    /// S heard out for what waits on it (read's repairs and store deletes, spec/sync-ids.md §6):
    /// at once when no peer is to be waited for on it (`Opens::waited`: none has it open or in its
    /// kept record, none the rosters name has a record not acknowledging it), so a node alone
    /// waits for none; else `heard_out`.
    pub fn heard_out_or_alone(&self, opens: &Opens, engine: &mut osis_engine::Engine, store: &crate::store::Store, s: &SyncId, net: &impl Net) -> Result<bool> {
        Ok(!opens.waited(engine, store, s, true)? || self.heard_out(s, net))
    }

    /// Whether own commit `c` is held elsewhere under every read sync ID it has a body under
    /// (§2); false while it has none here.
    pub fn held(&self, c: &CommitId) -> bool {
        self.held.contains(c)
    }

    /// Whether own commit `c` is held elsewhere under read sync ID `s` (§2); false while it has
    /// no body under `s` here. Stamped: `by_commit` changes for `s` write `unheld` of `s`.
    pub fn held_under(&self, s: &SyncId, c: &CommitId) -> bool {
        self.unheld.get(s).is_some_and(|u| !u.contains(c)) && self.by_commit.get(c).is_some_and(|ids| ids.contains(s))
    }

    /// Where a wait on `scope`'s sync IDs stands (§3): each heard out with its own commits held
    /// elsewhere, or held by no other node (nothing anyone else holds to wait for); never while
    /// one some other node may hold is unconnected; failed `Stranded` while one is stranded here
    /// (notes/api-design.md: a wait on `Stranded` fails). Reads only.
    /// `ids_of`: the sync IDs carrying a thing (the engine's `carrying`); `others`: whether some
    /// other node may hold S (the engine's `others_may_hold`).
    pub fn wait(&self, net: &impl Net, scope: Scope, ids_of: impl FnOnce(&Tid) -> Result<Vec<SyncId>>, mut others: impl FnMut(&SyncId) -> bool) -> Waiting {
        let ids: Vec<SyncId> = match scope {
            Scope::All => self.holding.keys().copied().collect(),
            Scope::Thing(t) => match ids_of(&t) {
                // a thing that never arrives runs to the caller's timeout (§3)
                Ok(ids) if !ids.is_empty() => ids,
                _ => return Waiting::Pending,
            },
        };
        let stranded: Vec<SyncId> = ids.iter().filter(|s| net.stranded(s) || self.strandings.contains_key(*s)).copied().collect();
        if !stranded.is_empty() {
            return Waiting::Stranded(stranded);
        }
        match ids.iter().all(|s| !others(s) || self.of(s, net).is_some_and(|st| st.synced())) {
            true => Waiting::Done,
            false => Waiting::Pending,
        }
    }

    /// When the earliest pass waiting on a recorded peer gives up (`PASS_WAIT_MS`).
    pub fn next_wake(&self) -> Option<Mono> {
        self.clock.next().map(Mono)
    }

    /// Tests only: the work counted so far.
    #[doc(hidden)]
    pub fn work(&self) -> Work {
        self.work
    }
}

/// Whether own commit `c`'s body under S is held at a source (§2): an entry recorded held, or one
/// a source's stream showed present, or a reader
/// reported a position at or past where this node's log first held it (for a member being ended,
/// only an entry first logged at or below its `until`); else nothing S must hold (by read's
/// verdict). A source holding it is recorded whatever the verdict: one that is may-hold only as
/// this node may not log it (it lost access) still counts as held only there, for what reads the
/// recorded mark (a leave, a loss by an `until`). A store's position says nothing of an entry: it applies past what it refused for
/// room or does not pull (unstamped), so a store counts by its stream alone. `sources` gives S's
/// sources, asked only past the recorded check (a commit held elsewhere moves at no source joining
/// or leaving), each with where it stood as it left, for one that left since the last settle (its
/// stream's word still counts: a report and the close that follows it come in one step).
fn held_at(g: &mut impl Ground, s: &SyncId, c: &CommitId, sources: impl FnOnce() -> Vec<(ConnId, Src, Option<LeftAt>)>) -> Result<Held> {
    let must = match g.verdict(s, c) {
        Some(Verdict::Must) => true,
        Some(Verdict::May | Verdict::MustNot(_)) => false,
        Some(Verdict::Unjudged) | None => return Ok(Held::No),
    };
    let mut sources = Some(sources);
    let mut srcs = Vec::new();
    for b in g.commit_entries(s, c)? {
        if g.elsewhere(s, &b)? {
            return Ok(Held::Yes(None));
        }
        let first = g.first_logged(s, &b)?;
        if let Some(f) = sources.take() {
            srcs = f();
        }
        for &(conn, src, left) in &srcs {
            // a peer that leaves by the same self-removal (the account's other node, a group's
            // member) holds nothing for those who stay (roles-model leave, control `-any-source`)
            if !g.counts_for(c, src.node) {
                continue;
            }
            let shown = g.knows(src.at, conn, s, &b);
            let (at, until) = match left {
                Some(l) => (l.reported, l.until),
                None => (g.reported(conn, s), g.until(conn, s)),
            };
            let reported = src.class == SourceClass::Reader && first.is_some_and(|f| at.is_some_and(|p| p >= f) && until.is_none_or(|u| f <= u));
            if shown || reported {
                return Ok(Held::Yes(Some(b)));
            }
        }
    }
    Ok(if must { Held::No } else { Held::Yes(None) })
}

/// Whether sync is done waiting for self-removal `c` (spec/permissions.md §3 Lost access): under
/// each read S it has a body under (`ids`), held elsewhere or no peer but this account's own
/// nodes (which leave by the same commit, §2) to wait for (`Opens::waited`). With no such S, done at once: no
/// peer could take it.
fn removal_done<'a>(g: &mut impl Ground, c: &CommitId, ids: impl Iterator<Item = &'a SyncId>, unheld: &Stamped<SyncId, Arc<BTreeSet<CommitId>>>) -> Result<bool> {
    for s in ids {
        let held = unheld.get(s).is_some_and(|u| !u.contains(c));
        if !held && g.waited(s, false)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A pass of S as its sources stand: every source waited on caught up from a Pull sent since it
/// began, each recorded peer read at a connection since, or `PASS_WAIT_MS` past. With no source,
/// not while some peer is to be waited for on S (`Opens::waited`: a sync ID just joined waits for
/// its other holders as a leave does).
fn pass_now(g: &mut impl Ground, clock: &Clock, work: &mut Work, s: &SyncId, p: &Pass, sources: &BTreeMap<ConnId, Src>) -> PassNow {
    let mut fresh_all = true;
    let mut read = BTreeSet::new();
    for (conn, src) in sources {
        work.sources += 1;
        let fresh = g.caught_since(*conn, s).is_some_and(|t| t > p.pulled);
        if fresh {
            if let Some(r) = src.record().filter(|r| p.waits.contains(r)) {
                read.insert(r);
            }
        } else if !g.full(*conn, s) && !g.refusing(src.at, s) {
            fresh_all = false;
        }
    }
    let deadline = p.deadline.0;
    let timed_out = clock.until(Some(deadline)) >= deadline;
    // a record that no longer holds S has nothing of S left to read (closed: a Lost, or
    // its peer judged this node departed)
    let holding = g.records_holding(s).unwrap_or_default();
    let records = p.waits.iter().all(|r| read.contains(r) || !holding.contains(r));
    let done = timed_out || (fresh_all && records && !(sources.is_empty() && g.waited(s, true).unwrap_or(true)));
    PassNow { read, done }
}

fn whole<T: Default + PartialEq + std::fmt::Debug>(fx: &mut Effects<(), Arc<T>>, f: impl FnOnce() -> Arc<T>) -> Option<Arc<T>> {
    fx.settle(&(), f).map(|(_, now)| now)
}
