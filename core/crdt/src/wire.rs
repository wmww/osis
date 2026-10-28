//! Wire grammar (spec/crdt.md §3.2, §3.3, §8): delta and snapshot types, the header context,
//! and the `Sources`/`Commits` tables that turn stamps and dots into their bare or array forms.
//!
//! Encoding runs the fragment encoder twice: a collecting pass records sources in order of first
//! appearance and each foreign commit's smallest counter (§3.3 rule 1), then the real pass. Every
//! encoder (sequences included) goes through `Enc::dot`/`Enc::stamp`, so both passes agree.

use crate::error::Error;
use crate::fragment::Fragment;
use crate::page::{PageSink, PageSource};
use crate::stamp::{CounterRange, Dot, Interner, Source, SourceKind, Stamp};
use osis_core::{CommitId, Tid, Ts, Value, WallMs};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Nonce length of a delta (§3).
pub const NONCE_LEN: usize = 16;
/// Largest number of elements in a sequence run (§3.3 rule 3).
pub const MAX_RUN: u64 = 1 << 16;

/// What kind of commit carries a delta (§2.4); decides which writes it may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaKind {
    /// A writer's own writes: own-source stamps only, inside the header range (§2.3).
    Writer,
    /// A snapshot (§8): foreign writes only, no counters.
    Snapshot,
    /// An import (spec/permissions.md §7): re-sourced foreign writes, no counters.
    Import,
}

/// The commit header facts a delta is read against (§2.4).
#[derive(Clone, Debug)]
pub struct DeltaCtx {
    pub ts: Ts,
    /// Node form: the author node; commit form: this commit (writers use a placeholder, `Writer`).
    pub own: Source,
    pub range: CounterRange,
    pub kind: DeltaKind,
}

/// Per `Node` source, the largest counter up to which the snapshot writer applied all of that
/// node's writes in the aspect (§8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontiers(pub BTreeMap<Tid, u64>);

/// Received counter ranges per `Node` source for one aspect: what a snapshot's frontiers say
/// and what revoke frontiers are built from (§8; spec/permissions.md §5.1). Parked commits are
/// not added until joined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Received(BTreeMap<Tid, Vec<(u64, u64)>>);

impl Received {
    pub fn new() -> Received {
        Received::default()
    }
    /// Records counters `range` of node `tid` as applied.
    pub fn add(&mut self, tid: Tid, range: CounterRange) {
        if range.is_empty() {
            return;
        }
        let v = self.0.entry(tid).or_default();
        v.push((range.lo, range.hi));
        v.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
        for (a, b) in v.drain(..) {
            match out.last_mut() {
                Some(l) if a <= l.1 => l.1 = l.1.max(b),
                _ => out.push((a, b)),
            }
        }
        *v = out;
    }
    /// The largest `ctr` with `[1, ctr]` applied; 0 if none.
    pub fn frontier(&self, tid: &Tid) -> u64 {
        match self.0.get(tid).and_then(|v| v.first()) {
            Some((1, hi)) => hi.saturating_sub(1),
            _ => 0,
        }
    }
    /// The frontiers a snapshot of this state carries (nodes with counter 1 applied).
    pub fn frontiers(&self) -> Frontiers {
        Frontiers(self.0.keys().map(|t| (*t, self.frontier(t))).filter(|x| x.1 > 0).collect())
    }
    /// A received snapshot closes `[1, ctr]` per frontier.
    pub fn add_frontiers(&mut self, fr: &Frontiers) {
        for (t, c) in &fr.0 {
            self.add(*t, CounterRange { lo: 1, hi: c.saturating_add(1) });
        }
    }
}

/// `[nonce, Sources, Commits, Fragment]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub nonce: [u8; NONCE_LEN],
    pub fragment: Fragment,
}

/// `[nonce, Sources, Commits, Fragment, Frontiers, Absorbed]` or, with commit-form sources'
/// authors, `[nonce, Sources, Commits, Fragment, Frontiers, Absorbed, Authors]` (§8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub nonce: [u8; NONCE_LEN],
    pub fragment: Fragment,
    pub frontiers: Frontiers,
    /// Commits judged by commit ID (commit form, imports) whose writes in this aspect the
    /// writer had applied, with their author nodes (§8).
    pub absorbed: BTreeMap<CommitId, Tid>,
    /// Per `Commit` source of the fragment, the node its writes are judged as and at which `ts`
    /// (spec/permissions.md §5.2). Entries for sources the fragment does not hold are dropped.
    pub authors: BTreeMap<CommitId, (Tid, Ts)>,
}

/// A non-negative integer as a value. Counters and `ts` stay below 2^63 (decoded ones are `Int`).
pub(crate) fn uint(n: u64) -> Value {
    debug_assert!(n <= i64::MAX as u64);
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// A non-negative integer from a value.
pub(crate) fn as_uint(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Int(i) => u64::try_from(*i).map_err(|_| Error::Malformed("negative integer")),
        _ => Err(Error::Malformed("expected an unsigned integer")),
    }
}

/// An array's items.
pub(crate) fn as_array(v: &Value) -> Result<&[Value], Error> {
    match v {
        Value::List(a) => Ok(a),
        _ => Err(Error::Malformed("expected an array")),
    }
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
    pub(crate) pages: Option<&'p mut dyn PageSink>,
    kind: DeltaKind,
    /// Elements in runs without `Content` so far (§3.3 rule 7), pages included.
    bare: u64,
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
        }
    }

    /// Counts `n` elements of a run without `Content`: more than `MAX_DELTA_BARE` in a writer's
    /// or an import delta is refused (§3.3 rule 7).
    pub(crate) fn note_bare(&mut self, n: u64) -> Result<(), Error> {
        if self.collecting || self.kind == DeltaKind::Snapshot {
            return Ok(());
        }
        self.bare = self.bare.saturating_add(n);
        if self.bare > osis_core::format::MAX_DELTA_BARE {
            return Err(Error::Mismatch("more than MAX_DELTA_BARE elements without content"));
        }
        Ok(())
    }

    /// Whether `s` is a stamp of this commit.
    pub fn is_own(&self, s: &Stamp) -> bool {
        s.ts == self.ts && s.dot.src == self.own
    }

    /// `Ci` of the commit of stamp `s` (a creation's commit, §3.2).
    pub fn commit_of(&mut self, s: &Stamp) -> Value {
        match self.stamp(s) {
            Value::List(a) => a.into_iter().next().unwrap_or(uint(0)),
            v => v,
        }
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

    /// Ends the collecting pass: appends `extra` (a snapshot's frontier-only sources, ascending)
    /// and orders the commit table (§3.2: by `Src`, then `ts`).
    pub(crate) fn finish_collecting(&mut self, extra: &[Source]) {
        let mut extra = extra.to_vec();
        extra.sort();
        for s in &extra {
            self.note_source(s);
        }
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

    /// `Src` of a source (0 = own).
    pub fn src(&mut self, s: &Source) -> Value {
        if self.collecting {
            self.note_source(s);
            return uint(0);
        }
        uint(self.src_index(s))
    }

    /// `Dot := ctr | [Src, ctr]`.
    pub fn dot(&mut self, d: &Dot) -> Value {
        if self.collecting {
            self.note_source(&d.src);
            return uint(0);
        }
        if d.src == self.own {
            uint(d.ctr)
        } else {
            Value::List(vec![uint(self.src_index(&d.src)), uint(d.ctr)])
        }
    }

    /// `Anchor := 0 | Dot`; `None` is HEAD.
    pub fn anchor(&mut self, a: Option<&Dot>) -> Value {
        match a {
            None => uint(0),
            Some(d) => self.dot(d),
        }
    }

    /// `Stamp := Ci | [Ci, ctr]`.
    pub fn stamp(&mut self, s: &Stamp) -> Value {
        let own_commit = s.ts == self.ts && s.dot.src == self.own;
        if self.collecting {
            self.note_source(&s.dot.src);
            if !own_commit {
                match self.commits.iter_mut().find(|c| c.ts == s.ts && c.src == s.dot.src) {
                    Some(c) => c.base = c.base.min(s.dot.ctr),
                    None => self.commits.push(CommitEntry { ts: s.ts, src: s.dot.src.clone(), base: s.dot.ctr }),
                }
            }
            return uint(0);
        }
        let (ci, base) = if own_commit {
            (0, self.lo)
        } else {
            let ci = self.commit_idx.get(&(s.ts, s.dot.src.clone())).copied().unwrap_or(0);
            let base = ci.checked_sub(1).and_then(|i| self.commits.get(i as usize)).map_or(0, |c| c.base);
            (ci, base)
        };
        if s.dot.ctr == base { uint(ci) } else { Value::List(vec![uint(ci), uint(s.dot.ctr)]) }
    }

    /// `Opt(Stamp)`: a reset `R` or presence `W`.
    pub fn opt_stamp(&mut self, s: Option<&Stamp>) -> Value {
        Value::List(s.map(|s| self.stamp(s)).into_iter().collect())
    }

    /// The `Commit` sources of `Sources` with their `Src`, ascending.
    pub(crate) fn commit_sources(&self) -> Vec<(u64, CommitId)> {
        self.sources.iter().enumerate().filter_map(|(i, s)| match s.kind() {
            SourceKind::Commit(c) => Some((i as u64 + 1, *c)),
            _ => None,
        }).collect()
    }

    /// `Sources := [Source*]`.
    pub(crate) fn sources_value(&self) -> Value {
        Value::List(
            self.sources
                .iter()
                .map(|s| match s.kind() {
                    SourceKind::Node(t) => Value::Bytes(t.as_bytes().to_vec()),
                    SourceKind::Commit(c) => Value::Bytes(c.0.to_vec()),
                    SourceKind::Derived(d) => Value::List(vec![uint(self.src_index(&d.src)), uint(d.ctr)]),
                })
                .collect(),
        )
    }

    /// `Commits := [[Src, [[dwall, logical, base]*]]*]`.
    pub(crate) fn commits_value(&self) -> Value {
        let mut groups: Vec<Value> = Vec::new();
        let mut cur: Option<(u64, Vec<Value>, u64)> = None;
        for c in &self.commits {
            let src = self.src_index(&c.src);
            let wall = c.ts.wall_ms().0;
            match &mut cur {
                Some((s, entries, prev)) if *s == src => {
                    entries.push(Value::List(vec![uint(wall.saturating_sub(*prev)), uint(c.ts.logical()), uint(c.base)]));
                    *prev = wall;
                }
                _ => {
                    if let Some((s, entries, _)) = cur.take() {
                        groups.push(Value::List(vec![uint(s), Value::List(entries)]));
                    }
                    let first = Value::List(vec![uint(wall), uint(c.ts.logical()), uint(c.base)]);
                    cur = Some((src, vec![first], wall));
                }
            }
        }
        if let Some((s, entries, _)) = cur {
            groups.push(Value::List(vec![uint(s), Value::List(entries)]));
        }
        Value::List(groups)
    }

    /// Wire order of dots for sorting element, entry and run arrays (§3.3 rule 2): §2.2 order,
    /// except that the delta's own commit-form source sorts below every other commit, since a
    /// writer does not know its commit ID while encoding.
    pub fn dot_order(&self, a: &Dot, b: &Dot) -> Ordering {
        crate::stamp::dot_cmp(a, b, &|x, y| self.src_order(x, y))
    }

    /// The entries of `m` in wire order (§3.3 rule 2).
    pub fn sorted<'m, T>(&self, m: &'m BTreeMap<Dot, T>) -> Vec<(&'m Dot, &'m T)> {
        let mut v: Vec<(&Dot, &T)> = m.iter().collect();
        if matches!(self.own.kind(), SourceKind::Commit(_)) {
            v.sort_by(|a, b| self.dot_order(a.0, b.0));
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
    pub fn fragment(&mut self, f: &Fragment) -> Result<Value, Error> {
        crate::codec::encode_fragment(self, f)
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
    /// Own counters taken by creations and position writes in a writer's delta (§2.3).
    used: BTreeSet<u64>,
    pub(crate) pages: Option<&'a mut dyn PageSource>,
    /// Pages fetched, with their links, for the canonical re-encode.
    pub(crate) fetched: Vec<(Vec<u8>, osis_core::Link)>,
    /// Blobs of the pages read so far: each at most once.
    pub(crate) links_seen: std::collections::HashSet<osis_core::BlobId>,
    /// Fragment nesting, across pages.
    pub(crate) depth: usize,
    /// Sequence elements in runs without `Content` so far, across pages (§3.3 rule 7).
    pub(crate) bare: u64,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(cx: &DeltaCtx, interner: &'a mut Interner, pages: Option<&'a mut dyn PageSource>) -> Dec<'a> {
        let own = interner.intern(&cx.own);
        Dec { ts: cx.ts, own, range: cx.range, kind: cx.kind, sources: Vec::new(), commits: Vec::new(), interner, used: BTreeSet::new(), pages, fetched: Vec::new(), links_seen: Default::default(), depth: 0, bare: 0 }
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

    /// In a writer's delta, records that an own creation or position write takes counter `ctr`;
    /// two taking one counter is bad input (§2.3, §3.3 rule 6).
    pub fn claim(&mut self, d: &Dot) -> Result<(), Error> {
        if self.kind == DeltaKind::Writer && d.src == self.own && !self.used.insert(d.ctr) {
            return Err(Error::Malformed("own counter used twice"));
        }
        Ok(())
    }

    /// Source of `Src` index `i`.
    pub fn source(&self, i: u64) -> Result<Source, Error> {
        if i == 0 {
            return Ok(self.own.clone());
        }
        let i = usize::try_from(i - 1).map_err(|_| Error::Malformed("source index"))?;
        self.sources.get(i).cloned().ok_or(Error::Malformed("source index out of range"))
    }

    pub fn src(&self, v: &Value) -> Result<Source, Error> {
        self.source(as_uint(v)?)
    }

    fn counter(v: &Value) -> Result<u64, Error> {
        match as_uint(v)? {
            0 => Err(Error::Malformed("counter 0")),
            c => Ok(c),
        }
    }

    /// `Dot := ctr | [Src, ctr]`. In a writer's delta an own-source dot names an element created
    /// here or earlier: its counter is below `hi` (§2.3).
    pub fn dot(&self, v: &Value) -> Result<Dot, Error> {
        let d = match v {
            Value::Int(_) => Dot::new(self.own.clone(), Self::counter(v)?),
            Value::List(a) => match a.as_slice() {
                [s, c] => {
                    if as_uint(s)? == 0 {
                        return Err(Error::Malformed("own dot in array form"));
                    }
                    Dot::new(self.src(s)?, Self::counter(c)?)
                }
                _ => return Err(Error::Malformed("dot")),
            },
            _ => return Err(Error::Malformed("dot")),
        };
        if self.kind == DeltaKind::Writer && d.src == self.own && d.ctr >= self.range.hi {
            return Err(Error::Malformed("own dot above the counter range"));
        }
        Ok(d)
    }

    /// `Anchor := 0 | Dot`; `None` is HEAD.
    pub fn anchor(&self, v: &Value) -> Result<Option<Dot>, Error> {
        if matches!(v, Value::Int(0)) { Ok(None) } else { self.dot(v).map(Some) }
    }

    fn commit(&self, ci: u64) -> Result<(Ts, Source, u64), Error> {
        if ci == 0 {
            if self.kind != DeltaKind::Writer {
                return Err(Error::Malformed("own write in a snapshot or import"));
            }
            return Ok((self.ts, self.own.clone(), self.range.lo));
        }
        let i = usize::try_from(ci - 1).map_err(|_| Error::Malformed("commit index"))?;
        let c = self.commits.get(i).ok_or(Error::Malformed("commit index out of range"))?;
        Ok((c.ts, c.src.clone(), c.base))
    }

    /// `Stamp := Ci | [Ci, ctr]`. In a writer's delta every stamp is own and inside `[lo, hi)`.
    pub fn stamp(&self, v: &Value) -> Result<Stamp, Error> {
        let s = match v {
            Value::Int(_) => {
                let (ts, src, base) = self.commit(as_uint(v)?)?;
                Stamp::new(ts, src, base)
            }
            Value::List(a) => match a.as_slice() {
                [ci, c] => {
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
            },
            _ => return Err(Error::Malformed("stamp")),
        };
        if self.kind == DeltaKind::Writer && !self.range.contains(s.dot.ctr) {
            return Err(Error::Malformed("own write outside the counter range"));
        }
        Ok(s)
    }

    /// `Opt(Stamp)`.
    pub fn opt_stamp(&self, v: &Value) -> Result<Option<Stamp>, Error> {
        match as_array(v)? {
            [] => Ok(None),
            [s] => self.stamp(s).map(Some),
            _ => Err(Error::Malformed("Opt(Stamp)")),
        }
    }

    /// Reads `Sources` (§3.2).
    pub(crate) fn load_sources(&mut self, v: &Value) -> Result<(), Error> {
        self.sources.clear();
        for s in as_array(v)? {
            let src = match s {
                Value::Bytes(b) => {
                    if let Ok(t) = <[u8; 15]>::try_from(b.as_slice()) {
                        Source::node(Tid::from_bytes(t))
                    } else if let Ok(c) = <[u8; 32]>::try_from(b.as_slice()) {
                        Source::commit(CommitId(c))
                    } else {
                        return Err(Error::Malformed("source length"));
                    }
                }
                Value::List(a) => match a.as_slice() {
                    [i, c] => {
                        // a Derived source names an earlier entry or own (§3.3 rule 1)
                        let dot = Dot::new(self.src(i)?, Self::counter(c)?);
                        Source::derived(dot).ok_or(Error::Malformed("Derived of a Derived source"))?
                    }
                    _ => return Err(Error::Malformed("source")),
                },
                _ => return Err(Error::Malformed("source")),
            };
            if src == self.own || self.sources.contains(&src) {
                return Err(Error::Malformed("repeated source"));
            }
            let src = self.interner.intern(&src);
            self.sources.push(src);
        }
        Ok(())
    }

    /// Reads `Commits` (§3.2): groups by strictly ascending `Src`, entries by strictly ascending
    /// `ts`. A writer's delta has an empty table (§3.3 rule 7: no foreign stamps).
    pub(crate) fn load_commits(&mut self, v: &Value) -> Result<(), Error> {
        self.commits.clear();
        let groups = as_array(v)?;
        if self.kind == DeltaKind::Writer && !groups.is_empty() {
            return Err(Error::Malformed("foreign stamps in a writer's delta"));
        }
        let mut last_src: Option<u64> = None;
        for g in groups {
            let [s, entries] = as_array(g)? else { return Err(Error::Malformed("commit group")) };
            let si = as_uint(s)?;
            if last_src.is_some_and(|l| si <= l) {
                return Err(Error::Malformed("commit groups out of order"));
            }
            last_src = Some(si);
            let src = self.source(si)?;
            let entries = as_array(entries)?;
            if entries.is_empty() {
                return Err(Error::Malformed("empty commit group"));
            }
            let mut prev: Option<(u64, Ts)> = None;
            for e in entries {
                let [dwall, logical, base] = as_array(e)? else { return Err(Error::Malformed("commit entry")) };
                let dwall = as_uint(dwall)?;
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
                prev = Some((wall, ts));
                self.commits.push(CommitEntry { ts, src: src.clone(), base: Self::counter(base)? });
            }
        }
        Ok(())
    }

    /// Decodes a nested fragment (no own reset on a register, §3.3 rule 7).
    pub fn fragment(&mut self, v: &Value) -> Result<Fragment, Error> {
        crate::codec::decode_fragment(self, v, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u8) -> Tid {
        let mut b = [0u8; 15];
        b[14] = n;
        Tid::from_bytes(b)
    }
    fn ts(wall: u64, logical: u64) -> Ts {
        Ts::make(WallMs(wall), logical).unwrap()
    }

    /// §3.2, §3.3 rule 1: tables in order of first appearance, commits grouped by `Src` then
    /// `ts` with delta-coded wall times and bases; bare forms where possible; decoding inverts.
    #[test]
    fn tables_round_trip_spec_3_2() {
        let own = Source::node(tid(1));
        let a = Source::node(tid(9));
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
            let mut out: Vec<Value> = stamps.iter().map(|s| enc.stamp(s)).collect();
            out.extend(dots.iter().map(|d| enc.dot(d)));
            if pass == 0 {
                enc.finish_collecting(&[]);
                continue;
            }
            // sources: a, then b (underlying of d), then d
            let sources = enc.sources_value();
            assert_eq!(
                sources,
                Value::List(vec![
                    Value::Bytes(tid(9).as_bytes().to_vec()),
                    Value::Bytes(vec![7; 32]),
                    Value::List(vec![Value::Int(2), Value::Int(2)]),
                ])
            );
            // own group (Src 0) first, then a (20 then 50: dwall 30), then d
            let commits = enc.commits_value();
            let e = |w: i64, l: i64, b: i64| Value::List(vec![Value::Int(w), Value::Int(l), Value::Int(b)]);
            assert_eq!(
                commits,
                Value::List(vec![
                    Value::List(vec![Value::Int(0), Value::List(vec![e(30, 3, 5)])]),
                    Value::List(vec![Value::Int(1), Value::List(vec![e(20, 0, 2), e(30, 1, 4)])]),
                    Value::List(vec![Value::Int(3), Value::List(vec![e(40, 0, 1)])]),
                ])
            );
            // bare where the counter is the base
            assert_eq!(out[0], Value::Int(3));
            assert_eq!(out[1], Value::List(vec![Value::Int(3), Value::Int(6)]));
            assert_eq!(out[5], Value::Int(3));
            assert_eq!(out[6], Value::List(vec![Value::Int(2), Value::Int(1)]));
            let mut interner = Interner::new();
            let mut dec = Dec::new(&cx, &mut interner, None);
            dec.load_sources(&sources).unwrap();
            dec.load_commits(&commits).unwrap();
            for (s, v) in stamps.iter().zip(&out) {
                assert_eq!(&dec.stamp(v).unwrap(), s);
            }
            for (d, v) in dots.iter().zip(&out[stamps.len()..]) {
                assert_eq!(&dec.dot(v).unwrap(), d);
            }
        }
    }

    /// §2.3, §3.3 rule 7: writer deltas carry own stamps in `[lo, hi)`, own dots below `hi`, and
    /// no commit table.
    #[test]
    fn writer_rejections_spec_3_3() {
        let own = Source::node(tid(1));
        let cx = DeltaCtx { ts: ts(100, 0), own, range: CounterRange { lo: 5, hi: 7 }, kind: DeltaKind::Writer };
        let mut interner = Interner::new();
        let mut dec = Dec::new(&cx, &mut interner, None);
        assert_eq!(dec.stamp(&Value::Int(0)).unwrap().dot.ctr, 5);
        assert_eq!(dec.stamp(&Value::List(vec![Value::Int(0), Value::Int(6)])).unwrap().dot.ctr, 6);
        assert!(dec.stamp(&Value::List(vec![Value::Int(0), Value::Int(5)])).is_err()); // not bare
        assert!(dec.stamp(&Value::List(vec![Value::Int(0), Value::Int(7)])).is_err()); // above hi
        assert!(dec.stamp(&Value::Int(1)).is_err());
        assert!(dec.dot(&Value::Int(2)).is_ok());
        assert!(dec.dot(&Value::Int(7)).is_err());
        assert!(dec.dot(&Value::Int(0)).is_err());
        let foreign = Value::List(vec![Value::List(vec![Value::Int(0), Value::List(vec![Value::List(vec![Value::Int(1), Value::Int(0), Value::Int(1)])])])]);
        assert!(dec.load_commits(&foreign).is_err());
    }

    /// §3.3 rule 2 clarification: the own commit-form source sorts below other commits.
    #[test]
    fn own_commit_sorts_first_spec_3_3() {
        let own = Source::commit(CommitId([0xff; 32]));
        let other = Source::commit(CommitId([1; 32]));
        let node = Source::node(tid(1));
        let cx = DeltaCtx { ts: ts(1, 0), own: own.clone(), range: CounterRange { lo: 1, hi: 2 }, kind: DeltaKind::Writer };
        let enc = Enc::new(&cx, None);
        assert_eq!(enc.dot_order(&Dot::new(own.clone(), 1), &Dot::new(other.clone(), 1)), Ordering::Less);
        assert_eq!(enc.dot_order(&Dot::new(node, 1), &Dot::new(own, 1)), Ordering::Less);
    }
}
