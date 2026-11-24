//! Wire grammar (spec/crdt.md §3.2, §3.3, §8): delta and snapshot types, the header context,
//! and the `Sources`/`Commits` tables that turn stamps and dots into their bare or array forms.
//!
//! Encoding runs the fragment encoder twice: a collecting pass records sources in order of first
//! appearance and each foreign commit's smallest counter (§3.3 rule 1), then the real pass. Every
//! encoder (sequences included) goes through `Enc::dot`/`Enc::stamp`, so both passes agree.

use crate::error::Error;
use crate::fragment::Fragment;
use crate::page::{PageSink, PageSource};
use crate::paging::Step;
use crate::stamp::{CounterRange, Dot, Interner, Session, Source, SourceKind, Stamp};
use osis_base::cbor::{Item, List, put_array, put_bytes, put_tid, put_uint};
use osis_base::{CommitId, Tid, Ts, WallMs};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

/// Nonce length of a delta (§3).
pub const NONCE_LEN: usize = 16;
/// Largest number of elements in a sequence run (§3.3 rule 3). Resource bound: a run is one page
/// element, about 36 items per element at most (two position writes, a flag write, a segment,
/// a char), so a run stays far below `MAX_PAGE_ITEMS` (notes/crdt.md, Page items); 0 allows no
/// sequence, infinity an unbounded page.
pub const MAX_RUN: u64 = 1 << 12;

/// What kind of commit carries a delta (§2.4); decides which writes it may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaKind {
    /// A writer's own writes: own-source stamps only, inside the header range (§2.3).
    Writer,
    /// A snapshot (§8): foreign writes only, no counters.
    Snapshot,
}

/// The commit header facts a delta is read against (§2.4).
#[derive(Clone, Debug)]
pub struct DeltaCtx {
    pub ts: Ts,
    /// Session form: the author's session; commit form: this commit (writers use a placeholder,
    /// `Writer`).
    pub own: Source,
    pub range: CounterRange,
    pub kind: DeltaKind,
}

/// Per `Session` source the snapshot lists (§8: each occurring in its fragment, and each of a
/// commit with a delta on the aspect its writer held), the largest counter up to which the
/// snapshot writer applied all of that source's writes in the aspect, 0 when it applied none
/// contiguously. A source without an entry left no write in the fragment and was no held
/// commit's (`lists`); on the wire every occurring source has an entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontiers {
    pub sessions: BTreeMap<Session, u64>,
}

impl Frontiers {
    /// Every entry as its source, with its counter.
    pub fn sources(&self) -> impl Iterator<Item = (Source, u64)> + '_ {
        self.sessions.iter().map(|(s, c)| (Source::session(*s), *c))
    }
    /// Whether `src` has an entry: it occurs in the snapshot's fragment, or its writer held a
    /// commit of it on the aspect.
    pub fn lists(&self, src: &Source) -> bool {
        src.as_session().is_some_and(|s| self.sessions.contains_key(&s))
    }
    /// Entries with a counter: tests comparing a snapshot with its decoding, which lists every
    /// source of the fragment.
    #[cfg(test)]
    pub fn without_zeros(mut self) -> Frontiers {
        self.sessions.retain(|_, c| *c > 0);
        self
    }
    /// The frontier of `src` (0 when none, or not a `Session` source).
    pub fn of(&self, src: &Source) -> u64 {
        src.as_session().and_then(|s| self.sessions.get(&s).copied()).unwrap_or(0)
    }
    /// Sets the frontier of `src`; false when `src` is not a `Session` source.
    pub fn insert(&mut self, src: &Source, ctr: u64) -> bool {
        src.as_session().is_some_and(|s| self.sessions.insert(s, ctr).is_none())
    }
    /// Keeps the entries of the sources `keep` holds (§8: those a snapshot lists).
    pub fn retain(&mut self, keep: &std::collections::BTreeSet<Source>) {
        self.sessions.retain(|s, _| keep.contains(&Source::session(*s)));
    }
}

/// `[nonce, Sources, Commits, Fragment]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub nonce: [u8; NONCE_LEN],
    pub fragment: Fragment,
}

/// `[nonce, Sources, Commits, Fragment, Frontiers, Absorbed, Facts]` (§8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub nonce: [u8; NONCE_LEN],
    pub fragment: Fragment,
    pub frontiers: Frontiers,
    /// Commit-form commits whose writes in this aspect the
    /// writer had applied, with their signers (§8).
    pub absorbed: BTreeMap<CommitId, Tid>,
    /// The purge facts of the commits whose stamps the fragment carries, by `(ts, source)`
    /// (§8 `Facts`), but `Fact::NARROWEST`, which a missing one stands for.
    pub facts: Facts,
}

/// A carried commit's facts a purge judges it by where its header is not held (§8 `Facts`,
/// spec/commits.md §5 Purge): its purge-by class on the aspect, and its purge author where
/// that is not its signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fact {
    pub by: osis_base::PurgeBy,
    pub purge_author: Option<Tid>,
}

impl Fact {
    /// `admin`, the signer its purge author: what only admins may purge, whoever wrote it.
    pub const NARROWEST: Fact = Fact { by: osis_base::PurgeBy::Admin, purge_author: None };
}

/// A snapshot's facts per `Commits` entry `(ts, source)`; a commit is judged by its origin
/// source's entry (`fact_source`).
pub type Facts = BTreeMap<(Ts, Source), Fact>;

/// The source a carried commit's facts are keyed by: a `Derived` one's origin (§2.1: its writes
/// belong to the commit of the dot it derives from).
pub fn fact_source(src: &Source) -> Source {
    match src.kind() {
        SourceKind::Derived(d) => fact_source(&d.src),
        _ => src.clone(),
    }
}

/// A non-negative integer.
pub(crate) fn as_uint(v: Item) -> Result<u64, Error> {
    v.as_uint().ok_or(Error::Malformed("expected an unsigned integer"))
}

/// An array's items.
pub(crate) fn as_array(v: Item) -> Result<List, Error> {
    v.as_list().ok_or(Error::Malformed("expected an array"))
}

#[derive(Clone, Debug)]
struct CommitEntry {
    ts: Ts,
    src: Source,
    base: u64,
}

/// Encoder context of one delta or snapshot.
pub struct Enc<'p> {
    ts: Ts,
    own: Source,
    lo: u64,
    collecting: bool,
    sources: Vec<Source>,
    src_idx: HashMap<Source, u64>,
    commits: Vec<CommitEntry>,
    commit_idx: HashMap<(Ts, Source), u64>,
    pages: Option<&'p mut dyn PageSink>,
    kind: DeltaKind,
    /// Elements in runs without `Content` so far (§3.3 rule 7), pages included.
    bare: u64,
    /// While a run's position (0) or flag (1) writes are encoded, the sources they name, noted
    /// when the run closes (§3.3 rule 1).
    defer: Option<usize>,
    deferred: [Vec<Source>; 2],
    /// Check mode (`stream`): re-encoding a decoded delta against its own tables.
    pub(crate) check: Option<Box<Check>>,
    /// The state's pages, where it is encoded from a skeleton and its pages (`Paged`).
    pub(crate) walk: Option<Walk<'p>>,
    /// The test oracle's whole paging (`codec::oracle`).
    #[cfg(any(test, fuzzing))]
    pub(crate) whole: bool,
}

/// An `Enc` reading a state's paged collections from its pages (`Paged`): where the walk of the
/// root is, and what serves the pages.
pub(crate) struct Walk<'p> {
    pub(crate) view: crate::page_view::View<'p>,
    pub(crate) track: Track,
}

/// One source appearance or a streamed position, in encoding order (`Check::log`).
pub(crate) enum Ev {
    Src(u64),
    Stream(Vec<crate::paging::Step>),
}

/// Check mode of an `Enc`: the tables are the input's; every source appearance is held against
/// them (first appearances must come in table order, §3.3 rule 1) and every commit's smallest
/// counter recorded (rule 1 `base`), checked when the delta ends (`stream`).
pub(crate) struct Check {
    /// The next table index not yet seen (1-based).
    next: u64,
    /// Per commit table entry, the smallest counter seen (`u64::MAX`: none).
    min: Vec<u64>,
    /// Set by an appearance out of table order or of a source not in the table.
    pub(crate) bad: bool,
    /// While the root is encoded: appearances and streamed positions, replayed after it.
    pub(crate) log: Option<Vec<Ev>>,
    pub(crate) track: Track,
    /// The paged positions left for streaming, with their link lists as written.
    pub(crate) streams: BTreeMap<Vec<crate::paging::Step>, Vec<u8>>,
    /// Pages the decode fetched outside streamed positions, given back by content.
    pub(crate) replay: Replay,
}

/// Replays the pages a decode fetched, so a canonical re-encode reproduces their links.
pub(crate) struct Replay {
    pages: HashMap<Vec<u8>, std::collections::VecDeque<osis_base::Link>>,
    params: crate::page::PageParams,
}

impl Replay {
    pub(crate) fn new(params: crate::page::PageParams) -> Replay {
        Replay { pages: HashMap::new(), params }
    }
    /// Adds pages (plaintext, link) in the order the encoder will put them.
    pub(crate) fn extend(&mut self, fetched: Vec<(Vec<u8>, osis_base::Link)>) {
        for (b, l) in fetched {
            self.pages.entry(b).or_default().push_back(l);
        }
    }
}

impl Check {
    /// A source of table index `i` appears.
    pub(crate) fn seen(&mut self, i: u64) {
        match i.cmp(&self.next) {
            Ordering::Less => {}
            Ordering::Equal => self.next += 1,
            Ordering::Greater => self.bad = true,
        }
    }
    /// A stamp of commit table entry `ci` (1-based; 0: not in the table) with counter `ctr`.
    fn counter(&mut self, ci: u64, ctr: u64) {
        match ci.checked_sub(1).and_then(|i| self.min.get_mut(i as usize)) {
            Some(m) => *m = (*m).min(ctr),
            None => self.bad = true,
        }
    }

    /// Whether the root encoding is at a streamed position: then its link list, logged.
    pub(crate) fn streamed(&mut self) -> Option<Vec<u8>> {
        let log = self.log.as_mut().filter(|_| self.track.on)?;
        let v = self.streams.remove(&self.track.path)?;
        log.push(Ev::Stream(self.track.path.clone()));
        Some(v)
    }
}

/// Where a walk of the root is (`stream`): the path through `Step`s from the root, the step the
/// next fragment is reached by, and whether the current position is reached through steps
/// only (anything else, a sequence's content or a `Slots` slot, is not streamed).
pub(crate) struct Track {
    pub(crate) path: Vec<crate::paging::Step>,
    pub(crate) next_step: Option<crate::paging::Step>,
    pub(crate) on: bool,
    level: usize,
}

impl Track {
    pub(crate) fn new() -> Track {
        Track { path: Vec::new(), next_step: None, on: true, level: 0 }
    }
    /// Announces the step the next fragment is reached by.
    pub(crate) fn step(&mut self, s: impl FnOnce() -> crate::paging::Step) {
        if self.on {
            self.next_step = Some(s());
        }
    }

    /// Entering a fragment: the step it is reached by extends the path (any other nesting
    /// leaves the steps-only part). Returns what `leave` restores.
    pub(crate) fn enter(&mut self) -> (bool, bool) {
        let step = self.next_step.take();
        let was = self.on;
        let pushed = match step {
            Some(s) if self.on => {
                self.path.push(s);
                true
            }
            _ => {
                self.on &= self.level == 0;
                false
            }
        };
        self.level += 1;
        (was, pushed)
    }
    pub(crate) fn leave(&mut self, (was, pushed): (bool, bool)) {
        self.level -= 1;
        if pushed {
            self.path.pop();
        }
        self.on = was;
    }
}

impl PageSink for Replay {
    /// Gives a page back once; a page given back is dropped (a stream replays nested pages of
    /// every leaf page: kept, they would add up to the whole delta).
    fn put(&mut self, plaintext: &[u8]) -> Result<osis_base::Link, crate::page::PageError> {
        let q = self.pages.get_mut(plaintext).ok_or(crate::page::PageError::Corrupt)?;
        let l = q.pop_front().ok_or(crate::page::PageError::Corrupt)?;
        if q.is_empty() {
            self.pages.remove(plaintext);
        }
        Ok(l)
    }
    fn params(&self) -> crate::page::PageParams {
        self.params
    }
}

impl<'p> Enc<'p> {
    pub(crate) fn new(cx: &DeltaCtx, pages: Option<&'p mut dyn PageSink>) -> Enc<'p> {
        Enc {
            ts: cx.ts,
            own: cx.own.clone(),
            lo: cx.range.lo,
            collecting: true,
            sources: Vec::new(),
            src_idx: HashMap::new(),
            commits: Vec::new(),
            commit_idx: HashMap::new(),
            pages,
            kind: cx.kind,
            bare: 0,
            defer: None,
            deferred: [Vec::new(), Vec::new()],
            check: None,
            walk: None,
            #[cfg(any(test, fuzzing))]
            whole: false,
        }
    }

    /// The root walk's tracker, while the root is encoded in check mode or from pages.
    pub(crate) fn track(&mut self) -> Option<&mut Track> {
        if let Some(w) = self.walk.as_mut() {
            return Some(&mut w.track);
        }
        self.check.as_mut().filter(|c| c.log.is_some()).map(|c| &mut c.track)
    }

    /// Where the fragment being encoded is a collection kept as pages (`Paged`): its path.
    pub(crate) fn paged_here(&self) -> Option<Vec<Step>> {
        let w = self.walk.as_ref().filter(|w| w.track.on)?;
        w.view.paths.below(&w.track.path).is_some_and(|p| p.here).then(|| w.track.path.clone())
    }

    /// The state the walk reads.
    pub(crate) fn walk_pages(&mut self) -> Result<&mut crate::page_view::View<'p>, Error> {
        match self.walk.as_mut() {
            Some(w) => Ok(&mut w.view),
            None => Err(Error::Mismatch("no pages to walk")),
        }
    }
    /// Announces the step to the fragment encoded next (`Track`).
    pub(crate) fn step(&mut self, s: impl FnOnce() -> crate::paging::Step) {
        if let Some(t) = self.track() {
            t.step(s);
        }
    }
    pub(crate) fn step_done(&mut self) {
        if let Some(t) = self.track() {
            t.next_step = None;
        }
    }

    /// Sources of position (`w` 0) or flag (1) writes are held, not noted, until `undefer`.
    pub(crate) fn defer(&mut self, w: usize) {
        self.defer = Some(w);
    }
    /// Ends holding: the sources held, for `note_held` when their run closes.
    pub(crate) fn undefer(&mut self) -> [Vec<Source>; 2] {
        self.defer = None;
        std::mem::take(&mut self.deferred)
    }
    /// Notes held sources: position writes', then flag writes' (§3.3 rule 1).
    pub(crate) fn note_held(&mut self, [p, f]: [Vec<Source>; 2]) {
        for s in p.iter().chain(&f) {
            self.note(s);
        }
    }

    /// Records an appearance of `s`: the collecting pass builds `Sources` from it, check mode
    /// holds it against the input's table.
    fn note(&mut self, s: &Source) {
        if !self.collecting && self.check.is_none() {
            return;
        }
        if let Some(w) = self.defer {
            if let Some(b) = self.deferred.get_mut(w) {
                b.push(s.clone());
            }
            return;
        }
        if self.collecting {
            return self.note_source(s);
        }
        if *s == self.own {
            return;
        }
        if let SourceKind::Derived(d) = s.kind() {
            let under = d.src.clone();
            self.note(&under);
        }
        let idx = self.src_idx.get(s).copied();
        let Some(c) = self.check.as_mut() else { return };
        match idx {
            None => c.bad = true,
            Some(i) => match &mut c.log {
                Some(log) => log.push(Ev::Src(i)),
                None => c.seen(i),
            },
        }
    }

    /// The page sink, reborrowed.
    pub(crate) fn sink(&mut self) -> Option<&mut dyn PageSink> {
        if let Some(c) = self.check.as_mut() {
            return Some(&mut c.replay);
        }
        match &mut self.pages {
            Some(p) => Some(&mut **p),
            None => None,
        }
    }

    /// Counts `n` elements of a run without `Content`: more than `MAX_DELTA_BARE` in a writer's
    /// delta is refused (§3.3 rule 7).
    pub(crate) fn note_bare(&mut self, n: u64) -> Result<(), Error> {
        if self.collecting || self.kind == DeltaKind::Snapshot {
            return Ok(());
        }
        self.bare = self.bare.saturating_add(n);
        if self.bare > osis_base::format::MAX_DELTA_BARE {
            return Err(Error::Mismatch("more than MAX_DELTA_BARE elements without content"));
        }
        Ok(())
    }

    /// Whether `s` is a stamp of this commit.
    pub(crate) fn is_own(&self, s: &Stamp) -> bool {
        s.ts == self.ts && s.dot.src == self.own
    }

    /// `Ci` of the commit of stamp `s` (a creation's commit, §3.2).
    pub fn commit_of(&mut self, s: &Stamp) -> u64 {
        self.stamp_parts(s).0
    }

    /// True during the collecting pass; outputs are then discarded and no page is written.
    pub fn collecting(&self) -> bool {
        self.collecting
    }

    fn note_source(&mut self, s: &Source) {
        if *s == self.own || self.src_idx.contains_key(s) {
            return;
        }
        if let SourceKind::Derived(d) = s.kind() {
            // the underlying source precedes (§3.3 rule 1)
            let under = d.src.clone();
            self.note_source(&under);
        }
        self.sources.push(s.clone());
        self.src_idx.insert(s.clone(), self.sources.len() as u64);
    }

    /// Ends the collecting pass and orders the commit table (§3.2: by `Src`, then `ts`).
    pub(crate) fn finish_collecting(&mut self) {
        let idx = |s: &Source| if *s == self.own { 0 } else { self.src_idx.get(s).copied().unwrap_or(u64::MAX) };
        let mut commits = std::mem::take(&mut self.commits);
        commits.sort_by_key(|c| (idx(&c.src), c.ts));
        self.commit_idx = commits.iter().enumerate().map(|(i, c)| ((c.ts, c.src.clone()), i as u64 + 1)).collect();
        self.commits = commits;
        self.collecting = false;
    }

    fn src_index(&self, s: &Source) -> u64 {
        if *s == self.own { 0 } else { self.src_idx.get(s).copied().unwrap_or(0) }
    }

    /// Whether `s` appears in the fragment (after the collecting pass).
    pub(crate) fn has_source(&self, s: &Source) -> bool {
        *s == self.own || self.src_idx.contains_key(s)
    }

    /// The sources that appear in the fragment, own one aside (after the collecting pass).
    pub(crate) fn sources(&self) -> impl Iterator<Item = &Source> + '_ {
        self.sources.iter()
    }

    /// Check mode, at the end: every source's first appearance came in table order and every
    /// table entry appeared but, in a snapshot (`snapshot`), its frontier-only sessions after them
    /// in ascending order (§3.3 rule 1, §8); every commit entry's base is its smallest counter
    /// seen.
    pub(crate) fn check_tables(&mut self, snapshot: bool) -> bool {
        let Some(c) = self.check.as_ref() else { return false };
        let seen = usize::try_from(c.next - 1).unwrap_or(usize::MAX);
        let rest = self.sources.get(seen..).unwrap_or_default();
        let sessions: Vec<Session> = rest.iter().filter_map(Source::as_session).collect();
        let rest_ok = rest.is_empty() || (snapshot && sessions.len() == rest.len() && sessions.is_sorted_by(|a, b| a < b));
        !c.bad && rest_ok && c.min.iter().zip(&self.commits).all(|(m, e)| *m == e.base)
    }

    /// A snapshot's frontier-only sessions (§3.3 rule 1, §8), after the collecting pass: each
    /// session `fr` lists that the fragment does not, at the table's end in ascending order.
    pub(crate) fn add_frontier_sessions(&mut self, fr: &Frontiers) {
        for s in fr.sessions.keys() {
            let src = Source::session(*s);
            if !self.has_source(&src) {
                self.sources.push(src.clone());
                self.src_idx.insert(src, self.sources.len() as u64);
            }
        }
    }

    /// A root table (§3.2 `Sources`, `Commits`; §8 `Frontiers`, `Absorbed`, `Facts`) of `n`
    /// entries as written, each by `entry`: plain at or below the page target, else paged like an
    /// element array (§8, spec/wire.md §6), its pages through the sink.
    pub(crate) fn put_table(&mut self, out: &mut Vec<u8>, n: usize, entry: impl Fn(&Enc, usize, &mut Vec<u8>)) -> Result<(), Error> {
        let params = self.sink().map_or_else(crate::page::PageParams::wire, |p| p.params());
        let mut p = crate::codec::Pager::new(false, params);
        for i in 0..n {
            entry(self, i, p.out());
            p.end(self.sink())?;
        }
        p.finish(self.sink(), out)
    }

    /// `Frontiers := [[Src, ctr]*]`: one entry per `Session` source of the table, in table order,
    /// `ctr` 0 for a source `fr` has none for (§8; after the collecting pass).
    pub(crate) fn put_frontiers(&mut self, out: &mut Vec<u8>, fr: &Frontiers) -> Result<(), Error> {
        let sessions: Vec<usize> = self.sources.iter().enumerate().filter(|(_, s)| matches!(s.kind(), SourceKind::Session(_))).map(|(i, _)| i).collect();
        self.put_table(out, sessions.len(), |enc, k, out| {
            let i = sessions.get(k).copied().unwrap_or_default();
            put_array(out, 2);
            put_uint(out, i as u64 + 1);
            put_uint(out, enc.sources.get(i).map_or(0, |s| fr.of(s)));
        })
    }

    /// `Facts := [Fact*]`, `Fact := by | [by, tid]` (§8): one per `Commits` entry, in table
    /// order; a commit `facts` misses gets `Fact::NARROWEST`.
    pub(crate) fn put_facts(&mut self, out: &mut Vec<u8>, facts: &Facts) -> Result<(), Error> {
        self.put_table(out, self.commits.len(), |enc, i, out| {
            let f = enc.commits.get(i).and_then(|c| facts.get(&(c.ts, c.src.clone()))).copied().unwrap_or(Fact::NARROWEST);
            match f.purge_author {
                None => put_uint(out, f.by as u64),
                Some(a) => {
                    put_array(out, 2);
                    put_uint(out, f.by as u64);
                    put_tid(out, &a);
                }
            }
        })
    }

    /// `Absorbed := [[bytes(32), tid]*]` (§8), ascending by commit ID.
    pub(crate) fn put_absorbed(&mut self, out: &mut Vec<u8>, absorbed: &BTreeMap<CommitId, Tid>) -> Result<(), Error> {
        let params = self.sink().map_or_else(crate::page::PageParams::wire, |p| p.params());
        let mut p = crate::codec::Pager::new(false, params);
        for (c, a) in absorbed {
            let out = p.out();
            put_array(out, 2);
            put_bytes(out, &c.0);
            put_tid(out, a);
            p.end(self.sink())?;
        }
        p.finish(self.sink(), out)
    }

    /// Notes the source of dot `d` where `dot` would, writing nothing.
    pub(crate) fn note_dot(&mut self, d: &Dot) {
        self.note(&d.src);
    }

    /// `Dot := ctr | [Src, ctr]`.
    pub fn dot(&mut self, out: &mut Vec<u8>, d: &Dot) {
        self.note(&d.src);
        if self.collecting {
            return put_uint(out, 0);
        }
        if d.src == self.own {
            put_uint(out, d.ctr);
        } else {
            put_array(out, 2);
            put_uint(out, self.src_index(&d.src));
            put_uint(out, d.ctr);
        }
    }

    /// `Anchor := 0 | Dot`; `None` is HEAD.
    pub fn anchor(&mut self, out: &mut Vec<u8>, a: Option<&Dot>) {
        match a {
            None => put_uint(out, 0),
            Some(d) => self.dot(out, d),
        }
    }

    /// `Ci` of stamp `s`, and its counter where it is not the commit's base (the array form).
    fn stamp_parts(&mut self, s: &Stamp) -> (u64, Option<u64>) {
        let own_commit = self.is_own(s);
        self.note(&s.dot.src);
        if self.collecting {
            if !own_commit {
                // while collecting, `commit_idx` holds positions in `commits`
                let key = (s.ts, s.dot.src.clone());
                match self.commit_idx.get(&key).and_then(|i| self.commits.get_mut(*i as usize)) {
                    Some(c) => c.base = c.base.min(s.dot.ctr),
                    None => {
                        self.commit_idx.insert(key, self.commits.len() as u64);
                        self.commits.push(CommitEntry { ts: s.ts, src: s.dot.src.clone(), base: s.dot.ctr });
                    }
                }
            }
            return (0, None);
        }
        let (ci, base) = if own_commit {
            (0, self.lo)
        } else {
            let ci = self.commit_idx.get(&(s.ts, s.dot.src.clone())).copied().unwrap_or(0);
            let base = ci.checked_sub(1).and_then(|i| self.commits.get(i as usize)).map_or(0, |c| c.base);
            if let Some(c) = self.check.as_mut() {
                c.counter(ci, s.dot.ctr);
            }
            (ci, base)
        };
        (ci, (s.dot.ctr != base).then_some(s.dot.ctr))
    }

    /// `Stamp := Ci | [Ci, ctr]`.
    pub fn stamp(&mut self, out: &mut Vec<u8>, s: &Stamp) {
        match self.stamp_parts(s) {
            (ci, None) => put_uint(out, ci),
            (ci, Some(ctr)) => {
                put_array(out, 2);
                put_uint(out, ci);
                put_uint(out, ctr);
            }
        }
    }

    /// `Opt(Stamp)`: a reset `R` or presence `W`.
    pub(crate) fn opt_stamp(&mut self, out: &mut Vec<u8>, s: Option<&Stamp>) {
        put_array(out, usize::from(s.is_some()));
        if let Some(s) = s {
            self.stamp(out, s);
        }
    }

    /// `Sources := [Source*]`.
    pub(crate) fn put_sources(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.put_table(out, self.sources.len(), |enc, i, out| match enc.sources.get(i).map(Source::kind) {
            Some(SourceKind::Session(x)) => put_bytes(out, &x.to_bytes()),
            Some(SourceKind::Commit(c)) => put_bytes(out, &c.0),
            Some(SourceKind::Derived(d)) => {
                put_array(out, 2);
                put_uint(out, enc.src_index(&d.src));
                put_uint(out, d.ctr);
            }
            None => {}
        })
    }

    /// `Commits := [[Src, dwall, logical, base]*]`: `dwall` from the previous entry of the same
    /// `Src` (absolute for its first).
    pub(crate) fn put_commits(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.put_table(out, self.commits.len(), |enc, i, out| {
            let Some(c) = enc.commits.get(i) else { return };
            let prev = i.checked_sub(1).and_then(|j| enc.commits.get(j)).filter(|p| p.src == c.src).map_or(0, |p| p.ts.wall_ms().0);
            let wall = c.ts.wall_ms().0;
            put_array(out, 4);
            put_uint(out, enc.src_index(&c.src));
            put_uint(out, wall.saturating_sub(prev));
            put_uint(out, c.ts.logical());
            put_uint(out, c.base);
        })
    }

    /// Wire order of dots for sorting element, entry and run arrays (§3.3 rule 2): §2.2 order,
    /// except that the delta's own commit-form source sorts below every other commit, since a
    /// writer does not know its commit ID while encoding.
    pub(crate) fn dot_order(&self, a: &Dot, b: &Dot) -> Ordering {
        crate::stamp::dot_cmp(a, b, &|x, y| self.src_order(x, y))
    }

    /// The entries of `m` in wire order (§3.3 rule 2).
    pub fn sorted<'m, T>(&self, m: &'m BTreeMap<Dot, T>) -> Vec<(&'m Dot, &'m T)> {
        self.sorted_by(m, |d| d)
    }

    /// The entries of `m`, keyed by something holding a dot (`dot`), in wire order (§3.3 rule
    /// 2): by dot, then in `m`'s order.
    pub fn sorted_by<'m, K: Ord, T>(&self, m: &'m BTreeMap<K, T>, dot: impl Fn(&K) -> &Dot) -> Vec<(&'m K, &'m T)> {
        let mut v: Vec<(&K, &T)> = m.iter().collect();
        if matches!(self.own.kind(), SourceKind::Commit(_)) {
            v.sort_by(|a, b| self.dot_order(dot(a.0), dot(b.0)));
        }
        v
    }

    /// Order of non-`Derived` sources with the own commit-form source first among commits.
    fn src_order(&self, a: &Source, b: &Source) -> Ordering {
        if !matches!(self.own.kind(), SourceKind::Commit(_)) || a == b {
            return crate::stamp::base_cmp(a, b);
        }
        match (a.kind(), b.kind()) {
            (SourceKind::Commit(_), SourceKind::Commit(_)) if *a == self.own => Ordering::Less,
            (SourceKind::Commit(_), SourceKind::Commit(_)) if *b == self.own => Ordering::Greater,
            _ => crate::stamp::base_cmp(a, b),
        }
    }

    /// Encodes a nested fragment.
    pub fn fragment(&mut self, out: &mut Vec<u8>, f: &Fragment) -> Result<(), Error> {
        crate::codec::encode_fragment(self, out, f)
    }
}

/// Decoder context of one delta or snapshot.
pub struct Dec<'a> {
    ts: Ts,
    own: Source,
    range: CounterRange,
    kind: DeltaKind,
    sources: Vec<Source>,
    commits: Vec<CommitEntry>,
    interner: &'a mut Interner,
    pub(crate) pages: Option<&'a mut dyn PageSource>,
    /// Pages fetched, with their links, for the canonical re-encode.
    pub(crate) fetched: Vec<(Vec<u8>, osis_base::Link)>,
    /// Blobs of the pages read so far: each at most once.
    pub(crate) links_seen: std::collections::HashSet<osis_base::BlobId>,
    /// Fragment nesting, across pages.
    pub(crate) depth: usize,
    /// Sequence elements in runs without `Content` so far, across pages (§3.3 rule 7).
    pub(crate) bare: u64,
    /// While a root is decoded for streaming: where the walk is, and the paged positions
    /// reached through steps, left undecoded (`stream`).
    pub(crate) streaming: Option<(Track, BTreeMap<Vec<crate::paging::Step>, crate::stream::Deferred>)>,
    /// A full check, not a decode-only read of checked bytes: a link tree's walk goes on past a
    /// missing page for the tree rule (`codec::walk_tree`).
    pub(crate) checking: bool,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Dec<'a> {
        let own = interner.intern(&cx.own);
        Dec { ts: cx.ts, own, range: cx.range, kind: cx.kind, sources: Vec::new(), commits: Vec::new(), interner, pages, fetched: Vec::new(), links_seen: Default::default(), depth: 0, bare: 0, streaming: None, checking: true }
    }

    pub fn kind(&self) -> DeltaKind {
        self.kind
    }
    pub fn range(&self) -> CounterRange {
        self.range
    }
    pub fn own(&self) -> &Source {
        &self.own
    }
    pub fn ts(&self) -> Ts {
        self.ts
    }

    /// The table's sources in order (after `codec::root_tables`).
    pub(crate) fn sources(&self) -> impl Iterator<Item = &Source> + '_ {
        self.sources.iter()
    }

    /// Source of `Src` index `i`.
    pub fn source(&self, i: u64) -> Result<Source, Error> {
        if i == 0 {
            return Ok(self.own.clone());
        }
        let i = usize::try_from(i - 1).map_err(|_| Error::Malformed("source index"))?;
        self.sources.get(i).cloned().ok_or(Error::Malformed("source index out of range"))
    }

    pub fn src(&self, v: Item) -> Result<Source, Error> {
        self.source(as_uint(v)?)
    }

    fn counter(v: Item) -> Result<u64, Error> {
        match as_uint(v)? {
            0 => Err(Error::Malformed("counter 0")),
            c => Ok(c),
        }
    }

    /// `Dot := ctr | [Src, ctr]`. In a writer's delta an own-source dot names an element created
    /// here or earlier: its counter is below `hi` (§2.3).
    pub fn dot(&self, v: Item) -> Result<Dot, Error> {
        let d = if v.is_int() {
            Dot::new(self.own.clone(), Self::counter(v)?)
        } else {
            match v.as_list().map(List::tuple) {
                Some(Some([s, c])) => {
                    if as_uint(s)? == 0 {
                        return Err(Error::Malformed("own dot in array form"));
                    }
                    Dot::new(self.src(s)?, Self::counter(c)?)
                }
                _ => return Err(Error::Malformed("dot")),
            }
        };
        if self.kind == DeltaKind::Writer && d.src == self.own && d.ctr >= self.range.hi {
            return Err(Error::Malformed("own dot above the counter range"));
        }
        Ok(d)
    }

    /// `Anchor := 0 | Dot`; `None` is HEAD.
    pub fn anchor(&self, v: Item) -> Result<Option<Dot>, Error> {
        if v.as_uint() == Some(0) { Ok(None) } else { self.dot(v).map(Some) }
    }

    fn commit(&self, ci: u64) -> Result<(Ts, Source, u64), Error> {
        if ci == 0 {
            if self.kind != DeltaKind::Writer {
                return Err(Error::Malformed("own write in a snapshot"));
            }
            return Ok((self.ts, self.own.clone(), self.range.lo));
        }
        let i = usize::try_from(ci - 1).map_err(|_| Error::Malformed("commit index"))?;
        let c = self.commits.get(i).ok_or(Error::Malformed("commit index out of range"))?;
        Ok((c.ts, c.src.clone(), c.base))
    }

    /// `Stamp := Ci | [Ci, ctr]`. In a writer's delta every write stamp is this commit's and
    /// inside `[lo, hi)`.
    pub fn stamp(&self, v: Item) -> Result<Stamp, Error> {
        let s = self.key_stamp(v)?;
        if self.kind == DeltaKind::Writer && (s.ts != self.ts || s.dot.src != self.own) {
            // the commit table names only sibling keys' commits (§3.3 rule 7)
            return Err(Error::Malformed("foreign stamps in a writer's delta"));
        }
        if self.kind == DeltaKind::Writer && !self.range.contains(s.dot.ctr) {
            return Err(Error::Malformed("own write outside the counter range"));
        }
        Ok(s)
    }

    /// A stamp that names no write of this delta (a position write's sibling key, §5.7): any
    /// commit's, in a writer's delta too.
    pub fn key_stamp(&self, v: Item) -> Result<Stamp, Error> {
        let s = if v.is_int() {
            let (ts, src, base) = self.commit(as_uint(v)?)?;
            Stamp::new(ts, src, base)
        } else {
            match v.as_list().map(List::tuple) {
                Some(Some([ci, c])) => {
                    let (ts, src, base) = self.commit(as_uint(ci)?)?;
                    let ctr = Self::counter(c)?;
                    if ctr == base {
                        return Err(Error::Malformed("stamp in array form at its base"));
                    }
                    if ctr < base {
                        return Err(Error::Malformed("stamp below its commit's base"));
                    }
                    Stamp::new(ts, src, ctr)
                }
                _ => return Err(Error::Malformed("stamp")),
            }
        };
        Ok(s)
    }

    /// A commit-level write's stamp (§2.3): in a writer's delta the delta stamp `(ts, own, lo)`.
    pub(crate) fn level_stamp(&self, v: Item) -> Result<Stamp, Error> {
        let s = self.stamp(v)?;
        if self.kind == DeltaKind::Writer && s.dot.ctr != self.range.lo {
            return Err(Error::Malformed("commit-level write off the delta stamp"));
        }
        Ok(s)
    }

    /// `Opt(Stamp)` of a commit-level write (`level_stamp`); every `Opt(Stamp)` is one.
    pub(crate) fn opt_level_stamp(&self, v: Item) -> Result<Option<Stamp>, Error> {
        let a = as_array(v)?;
        match a.tuple() {
            _ if a.is_empty() => Ok(None),
            Some([s]) => self.level_stamp(s).map(Some),
            None => Err(Error::Malformed("Opt(Stamp)")),
        }
    }

    /// Reads one `Sources` entry (§3.2), in table order.
    pub(crate) fn add_source(&mut self, s: Item) -> Result<(), Error> {
        let src = match (s.as_bytes(), s.as_list().map(List::tuple)) {
            (Some(b), _) => {
                if let Ok(x) = <[u8; 31]>::try_from(b) {
                    Source::session(Session::from_bytes(&x))
                } else if let Ok(c) = <[u8; 32]>::try_from(b) {
                    Source::commit(CommitId(c))
                } else {
                    return Err(Error::Malformed("source length"));
                }
            }
            (None, Some(Some([i, c]))) => {
                // a Derived source names an earlier entry or own (§3.3 rule 1)
                let dot = Dot::new(self.src(i)?, Self::counter(c)?);
                Source::derived(dot).ok_or(Error::Malformed("Derived of a Derived source"))?
            }
            _ => return Err(Error::Malformed("source")),
        };
        if src == self.own || self.sources.contains(&src) {
            return Err(Error::Malformed("repeated source"));
        }
        let src = self.interner.intern(&src);
        self.sources.push(src);
        Ok(())
    }

    /// Reads one `Commits` entry `[Src, dwall, logical, base]` (§3.2), in table order: `Src`
    /// ascending, within one `Src` strictly ascending `ts`, `dwall` from that `Src`'s previous
    /// entry (`last`: the previous entry's `Src`, wall and `ts`). A writer's delta lists only its
    /// sibling keys' commits (§3.3 rule 7, checked per stamp; the re-encoding drops unused
    /// entries).
    pub(crate) fn add_commit(&mut self, e: Item, last: &mut Option<(u64, u64, Ts)>) -> Result<(), Error> {
        let Some([s, dwall, logical, base]) = as_array(e)?.tuple() else { return Err(Error::Malformed("commit entry")) };
        let si = as_uint(s)?;
        let src = self.source(si)?;
        let dwall = as_uint(dwall)?;
        let prev = match *last {
            Some((l, _, _)) if si < l => return Err(Error::Malformed("commit entries out of order")),
            Some((l, w, t)) if si == l => Some((w, t)),
            _ => None,
        };
        let wall = match prev {
            None => dwall,
            Some((w, _)) => w.checked_add(dwall).ok_or(Error::Malformed("commit wall overflow"))?,
        };
        let ts = Ts::make(WallMs(wall), as_uint(logical)?).ok_or(Error::Malformed("commit ts out of range"))?;
        if prev.is_some_and(|(_, p)| ts <= p) {
            return Err(Error::Malformed("commit entries out of order"));
        }
        if ts == self.ts && src == self.own {
            return Err(Error::Malformed("this commit in the commit table"));
        }
        *last = Some((si, wall, ts));
        self.commits.push(CommitEntry { ts, src, base: Self::counter(base)? });
        Ok(())
    }

    /// `Commits` entries read.
    pub(crate) fn commit_count(&self) -> usize {
        self.commits.len()
    }

    /// Reads the `Facts` entry (§8) of `Commits` entry `k` into `out`: a purge-by class (0 to 3),
    /// a purge author only where it is not the commit's signer (its session's tid; a
    /// commit-form one's `Absorbed` signer where listed). The narrowest are left out.
    pub(crate) fn add_fact(&self, k: usize, f: Item, absorbed: &BTreeMap<CommitId, Tid>, out: &mut Facts) -> Result<(), Error> {
        let c = self.commits.get(k).ok_or(Error::Malformed("facts not one per commit entry"))?;
        let (by, purge_author) = match f.as_list().map(List::tuple) {
            Some(Some([by, a])) if a.as_tid().is_some() => (as_uint(by)?, a.as_tid()),
            Some(_) => return Err(Error::Malformed("fact")),
            None => (as_uint(f)?, None),
        };
        let by = osis_base::PurgeBy::from_id(by).ok_or(Error::Malformed("fact class"))?;
        let signer = match fact_source(&c.src).kind() {
            SourceKind::Session(s) => Some(s.node),
            SourceKind::Commit(id) => absorbed.get(id).copied(),
            SourceKind::Derived(_) => None,
        };
        if purge_author.is_some() && purge_author == signer {
            return Err(Error::Malformed("fact purge author is the signer"));
        }
        let f = Fact { by, purge_author };
        if f != Fact::NARROWEST {
            out.insert((c.ts, c.src.clone()), f);
        }
        Ok(())
    }

    /// An encoder in check mode over this delta's tables (`stream`): streamed positions
    /// `streams`, the pages fetched so far given back by `Replay`.
    pub(crate) fn checker(&mut self, cx: &DeltaCtx, streams: BTreeMap<Vec<crate::paging::Step>, Vec<u8>>) -> Enc<'static> {
        let mut enc = Enc::new(cx, None);
        enc.collecting = false;
        enc.src_idx = self.sources.iter().enumerate().map(|(i, s)| (s.clone(), i as u64 + 1)).collect();
        enc.sources = self.sources.clone();
        enc.commit_idx = self.commits.iter().enumerate().map(|(i, c)| ((c.ts, c.src.clone()), i as u64 + 1)).collect();
        enc.commits = self.commits.clone();
        let mut replay = Replay::new(self.pages.as_ref().map_or_else(crate::page::PageParams::wire, |p| p.params()));
        replay.extend(std::mem::take(&mut self.fetched));
        let min = vec![u64::MAX; self.commits.len()];
        enc.check = Some(Box::new(Check { next: 1, min, bad: false, log: Some(Vec::new()), track: Track::new(), streams, replay }));
        enc
    }

    /// Announces the step to the fragment decoded next (`Track`).
    pub(crate) fn step(&mut self, s: impl FnOnce() -> crate::paging::Step) {
        if let Some((t, _)) = self.streaming.as_mut() {
            t.step(s);
        }
    }
    pub(crate) fn step_done(&mut self) {
        if let Some((t, _)) = self.streaming.as_mut() {
            t.next_step = None;
        }
    }

    /// Decodes a nested fragment (no own reset on a register, §3.3 rule 7).
    pub fn fragment(&mut self, v: Item) -> Result<Fragment, Error> {
        crate::codec::decode_fragment(self, v, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osis_base::Value;

    fn tid(n: u8) -> Tid {
        let mut b = [0u8; 15];
        b[14] = n;
        Tid::from_bytes(b)
    }
    fn sess(n: u8) -> Source {
        Source::session(Session { node: tid(n), nonce: [n; crate::SESSION_NONCE_LEN] })
    }
    /// What `f` writes, as a value.
    fn written(f: impl FnOnce(&mut Vec<u8>)) -> Value {
        let mut b = Vec::new();
        f(&mut b);
        osis_base::decode(&b, &osis_base::Limits::DEFAULT).unwrap()
    }
    /// `f` of `v` read in place.
    fn with<T>(v: &Value, f: impl FnOnce(Item) -> T) -> T {
        let b = osis_base::encode(v);
        f(Item::parse(&b, &osis_base::Limits::DEFAULT).unwrap())
    }
    fn ts(wall: u64, logical: u64) -> Ts {
        Ts::make(WallMs(wall), logical).unwrap()
    }
    /// `Sources` and `Commits` written as `sources` and `commits` into `dec`.
    fn tables(dec: &mut Dec, sources: &Value, commits: &Value) -> Result<(), Error> {
        let (s, c) = (osis_base::encode(sources), osis_base::encode(commits));
        let (s, c) = (Item::parse(&s, &osis_base::Limits::DEFAULT).unwrap(), Item::parse(&c, &osis_base::Limits::DEFAULT).unwrap());
        crate::codec::root_tables(dec, s, c)
    }

    /// §3.2, §3.3 rule 1: tables in order of first appearance, commits grouped by `Src` then
    /// `ts` with delta-coded wall times and bases; bare forms where possible; decoding inverts.
    #[test]
    fn tables_round_trip_spec_3_2() {
        let own = sess(1);
        let a = sess(9);
        let b = Source::commit(CommitId([7; 32]));
        let d = Source::derived(Dot::new(b.clone(), 2)).unwrap();
        let cx = DeltaCtx { ts: ts(100, 0), own: own.clone(), range: CounterRange::EMPTY, kind: DeltaKind::Snapshot };
        let stamps = [
            Stamp::new(ts(50, 1), a.clone(), 4),
            Stamp::new(ts(50, 1), a.clone(), 6),
            Stamp::new(ts(20, 0), a.clone(), 2),
            Stamp::new(ts(30, 3), own.clone(), 5),
            Stamp::new(ts(40, 0), d.clone(), 1),
        ];
        let dots = [Dot::new(own.clone(), 3), Dot::new(b.clone(), 1)];
        let mut enc = Enc::new(&cx, None);
        for pass in 0..2 {
            let mut out: Vec<Value> = stamps.iter().map(|s| written(|o| enc.stamp(o, s))).collect();
            out.extend(dots.iter().map(|d| written(|o| enc.dot(o, d))));
            if pass == 0 {
                enc.finish_collecting();
                continue;
            }
            // sources: a, then b (underlying of d), then d
            let sources = written(|o| enc.put_sources(o).unwrap());
            assert_eq!(
                sources,
                Value::List(vec![
                    Value::Bytes(Session { node: tid(9), nonce: [9; crate::SESSION_NONCE_LEN] }.to_bytes().to_vec()),
                    Value::Bytes(vec![7; 32]),
                    Value::List(vec![Value::Int(2), Value::Int(2)]),
                ])
            );
            // own source (Src 0) first, then a (20 then 50: dwall 30), then d
            let commits = written(|o| enc.put_commits(o).unwrap());
            let e = |s: i64, w: i64, l: i64, b: i64| Value::List(vec![Value::Int(s), Value::Int(w), Value::Int(l), Value::Int(b)]);
            assert_eq!(commits, Value::List(vec![e(0, 30, 3, 5), e(1, 20, 0, 2), e(1, 30, 1, 4), e(3, 40, 0, 1)]));
            // bare where the counter is the base
            assert_eq!(out[0], Value::Int(3));
            assert_eq!(out[1], Value::List(vec![Value::Int(3), Value::Int(6)]));
            assert_eq!(out[5], Value::Int(3));
            assert_eq!(out[6], Value::List(vec![Value::Int(2), Value::Int(1)]));
            let mut interner = Interner::new();
            let mut dec = Dec::new(&cx, &mut interner, None);
            tables(&mut dec, &sources, &commits).unwrap();
            for (s, v) in stamps.iter().zip(&out) {
                assert_eq!(&with(v, |i| dec.stamp(i)).unwrap(), s);
            }
            for (d, v) in dots.iter().zip(&out[stamps.len()..]) {
                assert_eq!(&with(v, |i| dec.dot(i)).unwrap(), d);
            }
        }
    }

    /// §2.3, §3.3 rule 7: writer deltas carry own write stamps in `[lo, hi)` and own dots below
    /// `hi`; the commit table serves only sibling keys.
    #[test]
    fn writer_rejections_spec_3_3() {
        let own = sess(1);
        let cx = DeltaCtx { ts: ts(100, 0), own, range: CounterRange { lo: 5, hi: 7 }, kind: DeltaKind::Writer };
        let mut interner = Interner::new();
        let mut dec = Dec::new(&cx, &mut interner, None);
        assert_eq!(with(&Value::Int(0), |i| dec.stamp(i)).unwrap().dot.ctr, 5);
        assert_eq!(with(&Value::List(vec![Value::Int(0), Value::Int(6)]), |i| dec.stamp(i)).unwrap().dot.ctr, 6);
        assert!(with(&Value::List(vec![Value::Int(0), Value::Int(5)]), |i| dec.stamp(i)).is_err()); // not bare
        assert!(with(&Value::List(vec![Value::Int(0), Value::Int(7)]), |i| dec.stamp(i)).is_err()); // above hi
        assert!(with(&Value::Int(1), |i| dec.stamp(i)).is_err());
        assert!(with(&Value::Int(2), |i| dec.dot(i)).is_ok());
        assert!(with(&Value::Int(7), |i| dec.dot(i)).is_err());
        assert!(with(&Value::Int(0), |i| dec.dot(i)).is_err());
        let foreign = Value::List(vec![Value::List(vec![Value::Int(0), Value::Int(1), Value::Int(0), Value::Int(1)])]);
        tables(&mut dec, &Value::List(vec![]), &foreign).unwrap();
        assert!(with(&Value::Int(1), |i| dec.stamp(i)).is_err()); // a write of another commit
        assert_eq!(with(&Value::Int(1), |i| dec.key_stamp(i)).unwrap().ts, ts(1, 0));
    }

    /// §3.3 rule 2 clarification: the own commit-form source sorts below other commits.
    #[test]
    fn own_commit_sorts_first_spec_3_3() {
        let own = Source::commit(CommitId([0xff; 32]));
        let other = Source::commit(CommitId([1; 32]));
        let session = sess(1);
        let cx = DeltaCtx { ts: ts(1, 0), own: own.clone(), range: CounterRange { lo: 1, hi: 2 }, kind: DeltaKind::Writer };
        let enc = Enc::new(&cx, None);
        assert_eq!(enc.dot_order(&Dot::new(own.clone(), 1), &Dot::new(other.clone(), 1)), Ordering::Less);
        assert_eq!(enc.dot_order(&Dot::new(session, 1), &Dot::new(own, 1)), Ordering::Less);
    }
}
