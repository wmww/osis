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
//! - the sources of S, from opens' `Moved` (the driver hands each here);
//! - lacking counts per (S, source keeping S unread): the stamped entries here its stream did
//!   not show (spec/sync-status.md §1: a source lacks only what it would pull);
//! - per own commit under a read S: held elsewhere (§2), recorded on the entry durably
//!   (`Store::set_elsewhere`) and told to the engine for a self-removal (`held_elsewhere`);
//! - complete passes (§1) of each sync ID the engine wants one of, a fresh Pull at each source,
//!   ended by every source caught up since and every recorded peer read at its next connection,
//!   or `PASS_WAIT_MS`; each end told to the engine (`note_complete_pass`).
//!
//! Only `handle` makes outputs: reading status or a wait changes nothing.

mod live;

pub use live::{Live, NetView};

use crate::opens::{Moved, Opens};
use crate::read::{Read, Verdict};
use crate::session::Sessions;
use crate::store::Source;
use crate::streams::Streams;
use crate::types::{ConnId, Cx, Error, Holding, Position, RecordId, Result, Scope, SourceClass, Waiting};
use crate::unread::Unread;
use osis_base::memo::{Clock, Effects, Stamped, StampedSet};
use osis_base::{BlobId, CommitId, SyncId, Tid, WallMs};
use osis_engine::sync::SyncSet;
use osis_proto::limits::PASS_WAIT_MS;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A source of S: a peer with S open on a connection up now (spec/sync-status.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Src {
    pub class: SourceClass,
    /// Its record, else the connection.
    pub at: Source,
    /// The account it proved: readers are counted by identity.
    pub account: Option<Tid>,
    /// Another node of this node's account: never counts for a self-removal (§2).
    pub own_node: bool,
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
    /// Kept unread here and stranded (spec/permissions.md §4).
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

    /// The readers among its sources, counted by the accounts proven (§1).
    pub fn readers(&self) -> BTreeSet<Tid> {
        self.sources.values().filter(|x| x.src.class == SourceClass::Reader).filter_map(|x| x.src.account).collect()
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

/// What status reads of streams and unread when asked (all stamped reads, memo-safe).
pub trait Net {
    /// When the Pull was sent whose answer S's stream on `conn` is caught up by (none: not caught
    /// up, both ways: spec/sync-status.md §1).
    fn caught_since(&self, conn: ConnId, s: &SyncId) -> Option<WallMs>;
    fn full(&self, at: Source, s: &SyncId) -> bool;
    fn refusing(&self, at: Source, s: &SyncId) -> bool;
    fn stranded(&self, s: &SyncId) -> bool;
}

/// What status reads and does at a settle besides `Net` (the product's is `Live`; a test's a
/// fake). Reads are stamped.
pub trait Ground: Net {
    fn now(&self) -> WallMs;
    fn sync_set(&mut self) -> Result<Arc<SyncSet>>;
    /// The entries of S here a source keeping S unread would pull: the stamped ones.
    fn stamped(&mut self, s: &SyncId) -> Result<Vec<BlobId>>;
    /// Whether that source's stream showed `b` present under S (streams' `knows`).
    fn knows(&self, at: Source, conn: ConnId, s: &SyncId, b: &BlobId) -> bool;
    /// The position of this node's log the peer on `conn` reported for S (opens' Positions).
    fn reported(&self, conn: ConnId, s: &SyncId) -> Option<Position>;
    /// The `until` of member S on `conn` (opens: a member being ended).
    fn until(&self, conn: ConnId, s: &SyncId) -> Option<Position>;
    /// The records holding S as a member (opens).
    fn records_holding(&self, s: &SyncId) -> Result<BTreeSet<RecordId>>;
    /// This node's commits and self-removals with a body under S (engine).
    fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>>;
    /// The self-removals whose secrets wait on being held elsewhere (engine).
    fn self_removals(&mut self) -> Result<Arc<BTreeSet<CommitId>>>;
    /// Read's verdict on `c`'s body under S.
    fn verdict(&self, s: &SyncId, c: &CommitId) -> Option<Verdict>;
    /// This node's own entries of `c` under S.
    fn own_entries(&mut self, s: &SyncId, c: &CommitId) -> Result<Vec<BlobId>>;
    /// Where this node's log first held entry `b` of S.
    fn first_logged(&mut self, s: &SyncId, b: &BlobId) -> Result<Option<Position>>;
    /// Whether a source was recorded holding entry `b` of S, durably.
    fn elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<bool>;
    fn set_elsewhere(&mut self, s: &SyncId, b: &BlobId) -> Result<()>;
    /// Tells the engine a self-removal is held elsewhere (it drops the secrets).
    fn held_elsewhere(&mut self, c: &CommitId) -> Result<()>;
    /// The sync IDs the engine wants a complete pass of, each with the moment the pass must begin
    /// at or after (spec/permissions.md §3 Complete pass: the newest role commit of one of S's
    /// actors from elsewhere it applied, a role found gone, a tied demotion's scope).
    fn passes_wanted(&mut self) -> Result<Arc<BTreeMap<SyncId, WallMs>>>;
    /// The engine's clock (`Engine::pass_clock`): a pass's `began` and a want's moment are read on
    /// the same clock.
    fn pass_clock(&mut self) -> WallMs;
    /// A complete pass of S begun at `began` ended (the engine drops S from `passes_wanted` once
    /// `began` is at or past its moment).
    fn note_complete_pass(&mut self, s: &SyncId, began: WallMs) -> Result<()>;
}

/// A complete pass of S under way (§1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pass {
    /// When it began, on the node's clock (what streams' caught-up times are read on).
    began: WallMs,
    /// When it began on the engine's clock (`Engine::pass_clock`): what the engine is told and
    /// its wants are compared with.
    noted: WallMs,
    /// The recorded peers not read since it began.
    waits: BTreeSet<RecordId>,
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
}

#[derive(Clone)]
pub struct Status {
    clock: Clock,
    set: Effects<(), Arc<SyncSet>>,
    holding: Stamped<SyncId, Holding>,
    sources: Stamped<SyncId, Arc<BTreeMap<ConnId, Src>>>,
    lacking_fx: Effects<(SyncId, ConnId), u64>,
    lacking: Stamped<(SyncId, ConnId), u64>,
    own_fx: Effects<SyncId, Arc<BTreeSet<CommitId>>>,
    held_fx: Effects<(SyncId, CommitId), Held>,
    /// Per read S whose own commits are known: those not held elsewhere.
    unheld: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    /// The read sync IDs each own commit has a body under.
    by_commit: BTreeMap<CommitId, BTreeSet<SyncId>>,
    /// Own commits held elsewhere under every sync ID they have a body under.
    held: StampedSet<CommitId>,
    removals_fx: Effects<(), Arc<BTreeSet<CommitId>>>,
    removals: StampedSet<CommitId>,
    wanted_fx: Effects<(), Arc<BTreeMap<SyncId, WallMs>>>,
    passes: Stamped<SyncId, Pass>,
    pass_fx: Effects<SyncId, PassNow>,
    /// S owes another pass once the one under way ends.
    again: BTreeSet<SyncId>,
    /// The engine's `own_commits` is not built: a wait cannot know own commits.
    own_unbuilt: bool,
    work: Work,
}

impl Default for Status {
    fn default() -> Self {
        Status {
            clock: Clock::default(),
            set: Effects::new("status: sync set"),
            holding: Stamped::default(),
            sources: Stamped::default(),
            lacking_fx: Effects::new("status: lacking"),
            lacking: Stamped::default(),
            own_fx: Effects::new("status: own commits"),
            held_fx: Effects::new("status: held elsewhere"),
            unheld: Stamped::default(),
            by_commit: BTreeMap::new(),
            held: StampedSet::default(),
            removals_fx: Effects::new("status: self-removals"),
            removals: StampedSet::default(),
            wanted_fx: Effects::new("status: passes wanted"),
            passes: Stamped::default(),
            pass_fx: Effects::new("status: pass"),
            again: BTreeSet::new(),
            own_unbuilt: false,
            work: Work::default(),
        }
    }
}

impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Status").field("passes", &self.passes.len()).finish_non_exhaustive()
    }
}

static NO_SOURCES: BTreeMap<ConnId, Src> = BTreeMap::new();

impl Status {
    // ---- the product's entry points ----

    /// A member moved on a connection (the driver hands each `Moved` here as to streams).
    pub fn moved(&mut self, sessions: &Sessions, opens: &Opens, m: &Moved) {
        match *m {
            Moved::Joined(conn, s, _) => {
                let Some(member) = opens.members(conn).get(&s) else { return };
                let proven = sessions.get(conn).map(|x| x.proven());
                let src = Src { class: member.class, at: opens.record(conn).map_or(Source::Conn(conn), Source::Record), account: proven.and_then(|p| p.account()), own_node: proven.is_some_and(|p| p.node.is_some()) };
                self.joined(s, conn, src);
            }
            Moved::Left(conn, s) => self.left(s, conn),
            Moved::Until(..) => {}
        }
    }

    /// The product's settle: over the engine, the store, opens, streams, read and unread.
    /// `pulls`: the connections streams is to Pull again on for a pass (`Streams::pull_again`).
    #[allow(clippy::too_many_arguments)]
    pub fn settle(&mut self, cx: &mut Cx, opens: &Opens, streams: &Streams, read: &Read, unread: &Unread, pulls: &mut Vec<ConnId>) -> Result<bool> {
        self.settle_on(&mut Live { cx, opens, streams, read, unread }, pulls)
    }

    // ---- the core ----

    /// S became a member on `conn`: a source.
    pub fn joined(&mut self, s: SyncId, conn: ConnId, src: Src) {
        let mut now = self.sources.get(&s).map(|x| (**x).clone()).unwrap_or_default();
        now.insert(conn, src);
        self.sources.insert(s, Arc::new(now));
        if src.class == SourceClass::Store {
            self.lacking_fx.want((s, conn));
        }
    }

    /// S stopped being a member on `conn` (closed, or the connection ended).
    pub fn left(&mut self, s: SyncId, conn: ConnId) {
        let Some(was) = self.sources.get(&s).cloned() else { return };
        let mut now = (*was).clone();
        if now.remove(&conn).is_none() {
            return;
        }
        if now.is_empty() {
            self.sources.remove(&s);
        } else {
            self.sources.insert(s, Arc::new(now));
        }
        self.lacking_fx.unwant(&(s, conn));
        if self.lacking.contains_key(&(s, conn)) {
            self.lacking.remove(&(s, conn));
        }
    }

    /// One settle over `g`: whether anything another module reads changed. `pulls`: the
    /// connections a pass wants a fresh Pull on.
    pub fn settle_on(&mut self, g: &mut impl Ground, pulls: &mut Vec<ConnId>) -> Result<bool> {
        self.clock.set(g.now().0);
        let mut acted = false;
        self.sync_set(g)?;
        self.count_lacking(g)?;
        acted |= self.held_elsewhere(g)?;
        acted |= self.passes(g, pulls)?;
        Ok(acted)
    }

    /// The sync set's projection: a row per S held, read or kept unread (§3), and own commits
    /// followed per read S.
    fn sync_set(&mut self, g: &mut impl Ground) -> Result<()> {
        self.set.want(());
        if self.set.due().is_empty() {
            return Ok(());
        }
        let Some(set) = skip_unbuilt(whole(&mut self.set, || g.sync_set()))? else { return Ok(()) };
        let gone: Vec<SyncId> = self.holding.keys().filter(|s| !set.ids.contains_key(*s)).copied().collect();
        for s in gone {
            self.holding.remove(&s);
            self.own_fx.unwant(&s);
            self.forget_own(&s);
        }
        for (s, (_, h)) in &set.ids {
            if self.holding.get(s) != Some(h) {
                self.holding.insert(*s, *h);
                if *h == Holding::Read {
                    self.own_fx.want(*s);
                } else {
                    self.own_fx.unwant(s);
                    self.forget_own(s);
                }
            }
        }
        Ok(())
    }

    fn forget_own(&mut self, s: &SyncId) {
        if self.unheld.remove(s).is_none() {
            return;
        }
        let commits: Vec<CommitId> = self.by_commit.iter().filter(|(_, ids)| ids.contains(s)).map(|(c, _)| *c).collect();
        for c in commits {
            self.held_fx.unwant(&(*s, c));
            self.untrack(s, &c);
        }
    }

    /// Lacking counts per (S, source keeping S unread): O(S's stamped entries) per change of
    /// what that source showed or of S's entries here.
    fn count_lacking(&mut self, g: &mut impl Ground) -> Result<()> {
        for k in self.lacking_fx.due() {
            let (s, conn) = k;
            let Some(src) = self.sources.get(&s).and_then(|x| x.get(&conn)).copied() else {
                self.lacking_fx.unwant(&k);
                continue;
            };
            self.work.lacking += 1;
            let r = run(&mut self.lacking_fx, &k, || Ok(g.stamped(&s)?.iter().filter(|b| !g.knows(src.at, conn, &s, b)).count() as u64));
            let Some(Some((_, n))) = skip_unbuilt(r.map(Some))? else { continue };
            self.lacking.insert(k, n);
        }
        Ok(())
    }

    /// Own commits under each read S, held elsewhere (§2); a self-removal held elsewhere is told
    /// to the engine.
    fn held_elsewhere(&mut self, g: &mut impl Ground) -> Result<bool> {
        let mut acted = false;
        self.removals_fx.want(());
        if !self.removals_fx.due().is_empty()
            && let Some(now) = skip_unbuilt(whole(&mut self.removals_fx, || g.self_removals()))?
        {
            let gone: Vec<CommitId> = self.removals.iter().filter(|c| !now.contains(*c)).copied().collect();
            for c in gone {
                self.removals.remove(&c);
            }
            for c in now.iter() {
                if !self.removals.contains(c) {
                    self.removals.insert(*c);
                }
            }
        }
        let mut moved = BTreeSet::new();
        for s in self.own_fx.due() {
            let r = skip_unbuilt(run(&mut self.own_fx, &s, || g.own_commits(&s)).map(Some))?;
            if r.is_none() {
                self.own_unbuilt = true;
            }
            let Some(Some((_, now))) = r else { continue };
            let was: Vec<CommitId> = self.by_commit.iter().filter(|(c, ids)| ids.contains(&s) && !now.contains(*c)).map(|(c, _)| *c).collect();
            let mut unheld = self.unheld.get(&s).map(|x| (**x).clone()).unwrap_or_default();
            for c in was {
                self.held_fx.unwant(&(s, c));
                unheld.remove(&c);
                self.untrack(&s, &c);
                moved.insert(c);
            }
            for c in now.iter() {
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
            let (all, removals) = (&self.sources, &self.removals);
            let r = run(&mut self.held_fx, &(s, c), || held_at(g, &s, &c, all.get(&s).map_or(&NO_SOURCES, |x| &**x), removals.contains(&c)));
            let Some(Some((_, now))) = skip_unbuilt(r.map(Some))? else { continue };
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
            if held && !self.held.contains(&c) {
                self.held.insert(c);
                if self.removals.contains(&c) {
                    skip_unbuilt(g.held_elsewhere(&c).map(Some))?;
                    acted = true;
                }
            } else if !held && self.held.contains(&c) {
                self.held.remove(&c);
            }
        }
        Ok(acted)
    }

    fn untrack(&mut self, s: &SyncId, c: &CommitId) {
        if let Some(ids) = self.by_commit.get_mut(c) {
            ids.remove(s);
            if ids.is_empty() {
                self.by_commit.remove(c);
                if self.held.contains(c) {
                    self.held.remove(c);
                }
            }
        }
    }

    /// Complete passes (§1, spec/permissions.md §3 Complete pass): begun for each sync ID the
    /// engine wants one of, each pass's end told.
    fn passes(&mut self, g: &mut impl Ground, pulls: &mut Vec<ConnId>) -> Result<bool> {
        let mut acted = false;
        self.wanted_fx.want(());
        if !self.wanted_fx.due().is_empty()
            && let Some(wanted) = skip_unbuilt(whole(&mut self.wanted_fx, || g.passes_wanted()))?
        {
            for (s, since) in wanted.iter() {
                match self.passes.get(s) {
                    Some(p) if p.noted >= *since => {}
                    // a Pull sent before the moment ends no pass after it: one more once it ends
                    Some(_) => {
                        self.again.insert(*s);
                    }
                    None => self.begin(g, *s, pulls)?,
                }
            }
        }
        for s in self.pass_fx.due() {
            let Some(p) = self.passes.get(&s).cloned() else {
                self.pass_fx.unwant(&s);
                continue;
            };
            let (all, passes, clock, work) = (&self.sources, &self.passes, &self.clock, &mut self.work);
            let Some((_, now)) = self.pass_fx.settle(&s, || match passes.get(&s) {
                Some(p) => pass_now(g, clock, work, &s, p, all.get(&s).map_or(&NO_SOURCES, |x| &**x)),
                None => PassNow::default(),
            }) else {
                continue;
            };
            if now.done {
                self.passes.remove(&s);
                self.pass_fx.unwant(&s);
                skip_unbuilt(g.note_complete_pass(&s, p.noted).map(Some))?;
                acted = true;
                if self.again.remove(&s) {
                    self.begin(g, s, pulls)?;
                }
            } else if !now.read.is_empty() {
                let waits = p.waits.difference(&now.read).copied().collect();
                self.passes.insert(s, Pass { began: p.began, noted: p.noted, waits });
            }
        }
        Ok(acted)
    }

    /// Begins a pass of S now: a fresh Pull at each source, the recorded peers to wait for.
    fn begin(&mut self, g: &mut impl Ground, s: SyncId, pulls: &mut Vec<ConnId>) -> Result<()> {
        let (began, noted) = (g.now(), g.pass_clock());
        let waits = g.records_holding(&s)?;
        pulls.extend(self.sources.get(&s).into_iter().flat_map(|x| x.keys().copied()));
        self.passes.insert(s, Pass { began, noted, waits });
        self.pass_fx.want(s);
        Ok(())
    }

    // ---- reads (stamped: memo-safe; none makes an output) ----

    /// How S stands now: O(sources of S). None for a sync ID neither held nor shared.
    pub fn of(&self, s: &SyncId, net: &impl Net) -> Option<SyncStatus> {
        let holding = self.holding.get(s).copied();
        let srcs = self.sources.get(s).map_or(&NO_SOURCES, |x| &**x);
        if holding.is_none() && srcs.is_empty() {
            return None;
        }
        let sources = srcs
            .iter()
            .map(|(c, src)| {
                let lacking = self.lacking.get(&(*s, *c)).copied().unwrap_or(0);
                (*c, SourceStatus { src: *src, caught_up: net.caught_since(*c, s).is_some(), lacking, full: net.full(src.at, s), refusing: net.refusing(src.at, s) })
            })
            .collect();
        let unheld = match holding {
            Some(Holding::Read) => self.unheld.get(s).map(|u| u.len()),
            _ => Some(0),
        };
        let pass_waits = self.passes.get(s).map(|p| p.waits.clone());
        Some(SyncStatus { holding, sources, stranded: net.stranded(s), pass_waits, unheld })
    }

    /// Every sync ID held or shared, as `of` says each: O(sync IDs × their sources).
    pub fn all(&self, net: &impl Net) -> BTreeMap<SyncId, SyncStatus> {
        let ids: BTreeSet<SyncId> = self.holding.keys().chain(self.sources.keys()).copied().collect();
        ids.into_iter().filter_map(|s| Some((s, self.of(&s, net)?))).collect()
    }

    /// S heard out (§1): every source caught up but those full or refusing, and one such at
    /// least.
    /// O(sources of S).
    pub fn heard_out(&self, s: &SyncId, net: &impl Net) -> bool {
        let srcs = self.sources.get(s).map_or(&NO_SOURCES, |x| &**x);
        heard_out(srcs.iter().map(|(c, src)| (!net.full(src.at, s) && !net.refusing(src.at, s), net.caught_since(*c, s).is_some())))
    }

    /// Whether own commit `c` is held elsewhere under every read sync ID it has a body under
    /// (§2); false while it has none here.
    pub fn held(&self, c: &CommitId) -> bool {
        self.held.contains(c)
    }

    /// Where a wait on `scope` stands (§3): each sync ID in scope heard out with its own commits
    /// held elsewhere; never while one is unconnected. Reads only.
    /// `ids_of`: the sync IDs carrying a thing (the engine's `sync_ids`).
    pub fn wait(&self, net: &impl Net, scope: Scope, ids_of: impl FnOnce(&Tid) -> Result<Vec<SyncId>>) -> Waiting {
        let ids: Vec<SyncId> = match scope {
            Scope::All => self.holding.keys().copied().collect(),
            Scope::Thing(t) => match ids_of(&t) {
                Ok(ids) => ids,
                Err(e) if not_built(&e) => return Waiting::Never("engine: sync_ids not built"),
                Err(_) => return Waiting::Pending,
            },
            Scope::Deliveries => return Waiting::Never("inbox: deliveries are inbox's wait"),
        };
        // a thing that never arrives runs to the caller's timeout (§3)
        if ids.is_empty() {
            return Waiting::Pending;
        }
        for s in &ids {
            match self.of(s, net) {
                Some(st) if st.synced() => {}
                Some(SyncStatus { holding: Some(Holding::Read), unheld: None, .. }) if self.own_unbuilt => return Waiting::Never("engine: own_commits not built"),
                _ => return Waiting::Pending,
            }
        }
        Waiting::Done
    }

    /// When the earliest pass waiting on a recorded peer gives up (`PASS_WAIT_MS`).
    pub fn next_wake(&self) -> Option<WallMs> {
        self.clock.next().map(WallMs)
    }

    /// Tests only: the work counted so far.
    #[doc(hidden)]
    pub fn work(&self) -> Work {
        self.work
    }
}

/// Whether own commit `c`'s body under S is held at a source (§2): nothing S must hold (by
/// read's verdict), an entry recorded held, or one a source's stream showed present (a self-
/// removal: not at this account's own nodes), or a reader reported a position at or past where
/// this node's log first held it (for a member being ended, only an entry first logged at or below
/// its `until`). A store's position says nothing of an entry: it applies past what it refused for
/// room or does not pull (unstamped), so a store counts by its stream alone.
fn held_at(g: &mut impl Ground, s: &SyncId, c: &CommitId, sources: &BTreeMap<ConnId, Src>, removal: bool) -> Result<Held> {
    match g.verdict(s, c) {
        Some(Verdict::Must) => {}
        Some(Verdict::May | Verdict::MustNot(_)) => return Ok(Held::Yes(None)),
        Some(Verdict::Unjudged) | None => return Ok(Held::No),
    }
    for b in g.own_entries(s, c)? {
        if g.elsewhere(s, &b)? {
            return Ok(Held::Yes(None));
        }
        let first = g.first_logged(s, &b)?;
        for (conn, src) in sources {
            if removal && src.own_node {
                continue;
            }
            let shown = g.knows(src.at, *conn, s, &b);
            let reported = src.class == SourceClass::Reader
                && first.is_some_and(|f| g.reported(*conn, s).is_some_and(|p| p >= f) && g.until(*conn, s).is_none_or(|u| f <= u));
            if shown || reported {
                return Ok(Held::Yes(Some(b)));
            }
        }
    }
    Ok(Held::No)
}

/// A pass of S as its sources stand: every source waited on caught up from a Pull sent since it
/// began, each recorded peer read at a connection since, or `PASS_WAIT_MS` past.
fn pass_now(g: &impl Ground, clock: &Clock, work: &mut Work, s: &SyncId, p: &Pass, sources: &BTreeMap<ConnId, Src>) -> PassNow {
    let mut fresh_all = true;
    let mut read = BTreeSet::new();
    for (conn, src) in sources {
        work.sources += 1;
        let fresh = g.caught_since(*conn, s).is_some_and(|t| t >= p.began);
        if fresh {
            if let Some(r) = src.record().filter(|r| p.waits.contains(r)) {
                read.insert(r);
            }
        } else if !g.full(src.at, s) && !g.refusing(src.at, s) {
            fresh_all = false;
        }
    }
    let deadline = p.began.0.saturating_add(PASS_WAIT_MS);
    let timed_out = clock.until(Some(deadline)) >= deadline;
    let records = p.waits.iter().all(|r| read.contains(r));
    PassNow { read, done: timed_out || (fresh_all && records) }
}

fn whole<T: Default + PartialEq>(fx: &mut Effects<(), Arc<T>>, f: impl FnOnce() -> Result<Arc<T>>) -> Result<Option<Arc<T>>> {
    Ok(run(fx, &(), f)?.map(|(_, now)| now))
}

/// `Effects::settle` with a failing function: the key stays due, the error goes up.
fn run<K: std::hash::Hash + Eq + Clone, V: Clone + PartialEq + Default>(fx: &mut Effects<K, V>, k: &K, f: impl FnOnce() -> Result<V>) -> Result<Option<(Option<V>, V)>> {
    let mut failed = None;
    let moved = fx.settle(k, || {
        f().unwrap_or_else(|e| {
            failed = Some(e);
            V::default()
        })
    });
    if let Some(e) = failed {
        // a part not built stays so in this build: the key keeps the default, not due again
        if !not_built(&e) {
            fx.unwant(k);
            fx.want(k.clone());
        }
        return Err(e);
    }
    Ok(moved)
}

/// A call status needs is not built (the engine facade, the store by commit): that part of
/// status does nothing until it is.
fn skip_unbuilt<T>(r: Result<Option<T>>) -> Result<Option<T>> {
    match r {
        Err(e) if not_built(&e) => Ok(None),
        r => r,
    }
}

fn not_built(e: &Error) -> bool {
    matches!(e, Error::NotBuilt(_) | Error::Engine(osis_engine::Error::NotBuilt(_)))
}
