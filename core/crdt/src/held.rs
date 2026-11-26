//! The writes the bodies of one aspect hold, by position, and when each died (spec/crdt.md §4.8
//! When): rows in an ordered store (`Rows`), a function of the bodies joined and not left,
//! whatever the order. A body joining or leaving reads and writes the rows of its own writes
//! and of the writes whose death it moves (`moved`), never another body.
//!
//! Rows (keys relative to the aspect). A position's rows start with 0, a 16-byte hash per step
//! of its path and 16 zero bytes, so they lie in path order: a position's own rows, then those
//! of the positions below it. A body's start with 1 and its commit ID.
//! - position + `W` + kind + stamp: a write: when it died, and its holders;
//! - position + `B`: the writes on the sequence elements of one bucket (`Bucket`: `BUCKET`
//!   consecutive counters of one source), run-length coded, so a run record costs a row per
//!   bucket, not per element;
//! - position + `A`: its tops (`Tops`): the greatest stamp held at or below it, the greatest of
//!   its own writes per kind, and how many steps down it has; position + `S` + the greatest
//!   stamp below a step (inverted: greatest first) + the step's hash, the step: its steps down
//!   by theirs, so a reset reads only the positions written since the reset before it
//!   (`below`), and a write asks only the positions holding a kind written after it for the
//!   writes superseding it;
//! - set + `V` + the reference's hash + the removal's hash, its dot and stamp: the set's value
//!   removals by the reference their joined copy names (§5.5);
//! - body + `D` + death (inverted): how many of the body's winning writes died then, so its
//!   date (the latest, `date`) follows each death moved without reading the body;
//! - body + `N`: a body joined, with the caller's tag; body + `L` + chunk: its own writes, so
//!   it leaves without being read.
//!
//! A sequence element's position has its bucket before it, and its own writes (creation,
//! position, flag, element reset) live in the bucket's row.
//!
//! A change (a body joining or leaving, `date_every`) reads each position's tops once and
//! keeps the rows it writes (`Held::tops`, `Held::cells`), so a walk up a write's ancestors or
//! across the kinds at its position reads rows only where a kind there was written after it: a
//! join reads a few rows per write, whatever its depth and the writes held.
//!
//! Interim (issues/dating-ignores-lifetimes.md): a write dies at any later write superseding it,
//! whatever either's lifetime (spec/crdt.md §4.8 counts only superseders lasting at least as
//! long); cells carrying their write's lifetime replace it.

use crate::fragment::{Elem, Fragment, Removal};
use crate::stamp::{Dot, DotRange, Session, Source, SourceKind, Stamp};
use crate::winners::{Kind, Place, Winners, Won, supersedes};
use osis_base::{CommitId, Ts, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

/// Sequence elements per bucket row. At 1 a run record costs a row per element; unbounded, an
/// edit of one element reads and writes every write on its source's elements. A power of two
/// near a placement block's rows: a row of an unedited run is one entry, and an edit rewrites
/// the writes of at most this many elements.
pub const BUCKET: u64 = 256;

/// A stored row that does not decode, or rows that contradict each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corrupt(pub &'static str);

/// A row: key and value.
pub type Row = (Vec<u8>, Vec<u8>);

/// When a held write died (`None`: not dead) and the snapshots holding it winning, by (`ts`,
/// commit) (`Held::held`).
pub type HeldWrite = (Option<Ts>, Vec<(Ts, CommitId)>);

/// An ordered byte-keyed store.
pub trait Rows {
    type Err: From<Corrupt>;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Err>;
    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), Self::Err>;
    fn del(&mut self, key: &[u8]) -> Result<(), Self::Err>;
    /// Up to `limit` rows with `from <= key < to`, least first.
    fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Self::Err>;
    /// Up to `limit` rows with `from <= key < to`, greatest first.
    fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Self::Err>;
    /// Writes what the store held back (`row_pages::PagedRows`): called once a caller's change
    /// is whole.
    fn flush(&mut self) -> Result<(), Self::Err> {
        Ok(())
    }
}

/// `Rows` in memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemRows(pub BTreeMap<Vec<u8>, Vec<u8>>);

impl Rows for MemRows {
    type Err = Corrupt;
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        Ok(self.0.get(key).cloned())
    }
    fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), Corrupt> {
        self.0.insert(key.to_vec(), val.to_vec());
        Ok(())
    }
    fn del(&mut self, key: &[u8]) -> Result<(), Corrupt> {
        self.0.remove(key);
        Ok(())
    }
    fn scan(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Corrupt> {
        if from >= to {
            return Ok(Vec::new());
        }
        Ok(self.0.range::<[u8], _>((Bound::Included(from), Bound::Excluded(to))).take(limit).map(|(k, v)| (k.clone(), v.clone())).collect())
    }
    fn scan_back(&mut self, from: &[u8], to: &[u8], limit: usize) -> Result<Vec<Row>, Corrupt> {
        if from >= to {
            return Ok(Vec::new());
        }
        Ok(self.0.range::<[u8], _>((Bound::Included(from), Bound::Excluded(to))).rev().take(limit).map(|(k, v)| (k.clone(), v.clone())).collect())
    }
}

/// A body of the aspect: its commit, the commit's `ts`, and whether it is a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Body {
    pub c: CommitId,
    pub ts: Ts,
    pub snap: bool,
}

/// What a body gives the index: every write it holds (`Fragment::held_writes`), those winning in
/// it (`Fragment::winners`; none for a body whose values are not kept, which dates nothing), and
/// its copies of what decides hiding (§5.5): each set element register write's value and each
/// value removal.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BodyWrites {
    held: Winners,
    wins: Winners,
    values: BTreeMap<Won, Option<Value>>,
    removals: BTreeMap<Won, Removal>,
}

impl BodyWrites {
    /// Of fragment `f`; `dates`: whether the body is dated by its winners (it holds its values).
    pub fn of(f: &Fragment, dates: bool) -> BodyWrites {
        let mut out = BodyWrites { held: f.held_writes(), wins: if dates { f.winners() } else { Winners::default() }, ..Default::default() };
        f.each_set_elem(&mut |set, d, e| out.elem(set, d, e));
        out
    }
    fn elem(&mut self, set: &[Place], d: &Dot, e: &Elem) {
        if let Some((v, s)) = e.written() {
            let path = [set, &[Place::Elem(d.clone()), Place::In]].concat();
            self.values.insert(Won { path, kind: Kind::Value, stamp: s.clone() }, Some(v.clone()));
        }
        if let Some(g) = &e.gone {
            let path = [set, &[Place::Gone(d.clone())]].concat();
            self.removals.insert(Won { path, kind: Kind::Reset, stamp: g.stamp.clone() }, g.clone());
        }
    }
    /// Of a set of writes alone: no body winning them, no copies.
    #[cfg(test)]
    pub fn of_writes(held: Winners) -> BodyWrites {
        BodyWrites { held, ..Default::default() }
    }
    /// A holder's copy payload of write `w`.
    fn payload(&self, w: &Won) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(v) = self.values.get(w) {
            match v {
                None => out.push(1),
                Some(v) => {
                    out.push(2);
                    osis_base::cbor::encode_into(v, &mut out);
                }
            }
        } else if let Some(g) = self.removals.get(w) {
            out.push(3);
            osis_base::cbor::encode_into(&g.value, &mut out);
            put_u64(&mut out, g.seen.len() as u64);
            for r in &g.seen {
                put_dot(&mut out, &r.first);
                put_u64(&mut out, r.hi);
            }
        }
        out
    }
}

// ---- bytes

pub(crate) fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_be_bytes());
}

/// Order-preserving, self-delimiting bytes of a dot (§2.2: the base source, the counter under
/// it, then for a `Derived` dot its own counter after a plain dot's end).
pub(crate) fn put_dot(out: &mut Vec<u8>, d: &Dot) {
    let (base, i) = match d.src.kind() {
        SourceKind::Derived(x) => (x, Some(d.ctr)),
        _ => (d, None),
    };
    match base.src.kind() {
        SourceKind::Session(s) => {
            out.push(0);
            out.extend_from_slice(&s.to_bytes());
        }
        SourceKind::Commit(c) => {
            out.push(1);
            out.extend_from_slice(&c.0);
        }
        // never built (`Source::derived`)
        SourceKind::Derived(_) => out.push(2),
    }
    put_u64(out, base.ctr);
    match i {
        None => out.push(0),
        Some(i) => {
            out.push(1);
            put_u64(out, i);
        }
    }
}

fn put_stamp(out: &mut Vec<u8>, s: &Stamp) {
    put_u64(out, s.ts.to_u64());
    put_dot(out, &s.dot);
}

fn stamp_bytes(s: &Stamp) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    put_stamp(&mut out, s);
    out
}

pub(crate) struct Rd<'a>(pub(crate) &'a [u8]);

impl<'a> Rd<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Corrupt> {
        let (a, b) = self.0.split_at_checked(n).ok_or(Corrupt("held writes row: short"))?;
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, Corrupt> {
        Ok(self.take(1)?.first().copied().unwrap_or(0))
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], Corrupt> {
        self.take(N)?.try_into().map_err(|_| Corrupt("held writes row: short"))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Corrupt> {
        Ok(u64::from_be_bytes(self.arr()?))
    }
    fn ts(&mut self) -> Result<Ts, Corrupt> {
        Ts::from_u64(self.u64()?).ok_or(Corrupt("held writes row: ts"))
    }
    pub(crate) fn dot(&mut self) -> Result<Dot, Corrupt> {
        let src = match self.u8()? {
            0 => Source::session(Session::from_bytes(&self.arr()?)),
            1 => Source::commit(CommitId(self.arr()?)),
            _ => return Err(Corrupt("held writes row: source")),
        };
        let base = Dot::new(src, self.u64()?);
        match self.u8()? {
            0 => Ok(base),
            1 => Ok(Dot::new(Source::derived(base).ok_or(Corrupt("held writes row: source"))?, self.u64()?)),
            _ => Err(Corrupt("held writes row: dot")),
        }
    }
    fn stamp(&mut self) -> Result<Stamp, Corrupt> {
        Ok(Stamp { ts: self.ts()?, dot: self.dot()? })
    }
    fn opt_ts(&mut self) -> Result<Option<Ts>, Corrupt> {
        Ok(match self.u8()? {
            0 => None,
            _ => Some(self.ts()?),
        })
    }
    pub(crate) fn value(&mut self) -> Result<Value, Corrupt> {
        let (v, span) = osis_base::cbor::decode_prefix(self.0, &osis_base::cbor::Limits::DEFAULT).map_err(|_| Corrupt("held writes row: value"))?;
        self.take(span.len())?;
        Ok(v)
    }
    pub(crate) fn end(&self) -> Result<(), Corrupt> {
        if self.0.is_empty() { Ok(()) } else { Err(Corrupt("held writes row: long")) }
    }
}

fn put_opt_ts(out: &mut Vec<u8>, t: Option<Ts>) {
    match t {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            put_u64(out, t.to_u64());
        }
    }
}

fn kind_byte(k: Kind) -> u8 {
    Kind::ALL.iter().position(|x| *x == k).unwrap_or(0) as u8
}

fn kind_of(b: u8) -> Result<Kind, Corrupt> {
    Kind::ALL.get(b as usize).copied().ok_or(Corrupt("held writes row: kind"))
}

// ---- positions

/// A step of a stored position: a `Place`, or the bucket of the sequence element after it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StepOf {
    At(Place),
    /// The bucket's dot: an element's with its counter divided by `BUCKET`.
    Bucket(Dot),
}

/// A step with its hash in keys (`pos_key`), hashed once where the step is made. Steps compare
/// by hash, as keys do.
#[derive(Clone, Debug)]
struct Step {
    of: StepOf,
    h: [u8; 16],
}

impl PartialEq for Step {
    fn eq(&self, o: &Step) -> bool {
        self.h == o.h
    }
}

impl Eq for Step {}

impl PartialOrd for Step {
    fn partial_cmp(&self, o: &Step) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Step {
    fn cmp(&self, o: &Step) -> std::cmp::Ordering {
        u128::from_be_bytes(self.h).cmp(&u128::from_be_bytes(o.h))
    }
}

impl Step {
    fn new(of: StepOf) -> Step {
        let mut b = Vec::new();
        put_step(&mut b, &of);
        let mut h = short(&b);
        // no step's hash is the zeros ending a position
        if h == [0; 16] {
            h = [1; 16];
        }
        Step { of, h }
    }
    fn at(p: Place) -> Step {
        Step::new(StepOf::At(p))
    }
    fn place(&self) -> Option<&Place> {
        match &self.of {
            StepOf::At(p) => Some(p),
            StepOf::Bucket(_) => None,
        }
    }
    fn bucket(&self) -> Option<&Dot> {
        match &self.of {
            StepOf::Bucket(d) => Some(d),
            StepOf::At(_) => None,
        }
    }
}

type Pos = Vec<Step>;

fn bucket_of(d: &Dot) -> Dot {
    Dot::new(d.src.clone(), d.ctr / BUCKET)
}

/// The stored position of `path`.
fn pos_of(path: &[Place]) -> Pos {
    let mut out = Vec::with_capacity(path.len() + 1);
    for p in path {
        if let Place::Item(d) = p {
            out.push(Step::new(StepOf::Bucket(bucket_of(d))));
        }
        out.push(Step::at(p.clone()));
    }
    out
}

/// The path of a stored position.
fn path_of(pos: &[Step]) -> Vec<Place> {
    pos.iter().filter_map(|s| s.place().cloned()).collect()
}

fn put_step(out: &mut Vec<u8>, s: &StepOf) {
    match s {
        StepOf::At(Place::Field(n)) => {
            out.push(1);
            put_u64(out, *n);
        }
        StepOf::At(Place::Case(n)) => {
            out.push(2);
            put_u64(out, *n);
        }
        StepOf::At(Place::Entry(d)) => {
            out.push(3);
            put_dot(out, d);
        }
        StepOf::At(Place::Elem(d)) => {
            out.push(4);
            put_dot(out, d);
        }
        StepOf::Bucket(d) => {
            out.push(5);
            put_dot(out, d);
        }
        StepOf::At(Place::Item(d)) => {
            out.push(6);
            put_dot(out, d);
        }
        StepOf::At(Place::In) => out.push(7),
        StepOf::At(Place::Gone(d)) => {
            out.push(8);
            put_dot(out, d);
        }
    }
}

fn read_step(r: &mut Rd<'_>) -> Result<Step, Corrupt> {
    Ok(Step::new(match r.u8()? {
        1 => StepOf::At(Place::Field(r.u64()?)),
        2 => StepOf::At(Place::Case(r.u64()?)),
        3 => StepOf::At(Place::Entry(r.dot()?)),
        4 => StepOf::At(Place::Elem(r.dot()?)),
        5 => StepOf::Bucket(r.dot()?),
        6 => StepOf::At(Place::Item(r.dot()?)),
        7 => StepOf::At(Place::In),
        8 => StepOf::At(Place::Gone(r.dot()?)),
        _ => return Err(Corrupt("held writes row: step")),
    }))
}

/// The position's steps, each self-delimiting, none starting with 0.
fn pos_bytes(pos: &[Step]) -> Vec<u8> {
    let mut out = Vec::new();
    pos.iter().for_each(|s| put_step(&mut out, &s.of));
    out
}

/// 16 bytes of a hash: what stands in a key for bytes of any length (a store bounds its keys:
/// the longest here, an `S` row's, is 91 bytes).
fn short(b: &[u8]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(osis_base::hash::hash(b).get(..16).unwrap_or(&[0; 16]));
    out
}

/// The position in path order, + `tag`: 0, a 16-byte hash per step, 16 zero bytes, the tag. A
/// position's rows (its writes, its top, its steps down) lie together, the positions below it
/// right after them, so a write, what it supersedes and the tops above it share pages
/// (`row_pages`).
fn pos_key(tag: u8, pos: &[Step]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 * pos.len() + 64);
    out.push(0);
    for s in pos {
        out.extend_from_slice(&s.h);
    }
    out.extend_from_slice(&[0; 16]);
    out.push(tag);
    out
}

/// The `V` key of the set at `set`'s value removal at dot `d` stamped `s` naming `value`, and
/// its row: the dot and stamp.
fn named_key(set: &[Step], value: &Value, d: &Dot, s: &Stamp) -> (Vec<u8>, Vec<u8>) {
    let mut row = Vec::new();
    put_dot(&mut row, d);
    put_stamp(&mut row, s);
    let mut k = under(b'V', set);
    k.extend_from_slice(&short(&osis_base::cbor::encode(value)));
    k.extend_from_slice(&short(&row));
    (k, row)
}

/// The prefix of the rows under one position.
fn under(tag: u8, pos: &[Step]) -> Vec<u8> {
    pos_key(tag, pos)
}

/// The least key above every key starting with `prefix`.
pub(crate) fn end_of(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    while let Some(b) = out.pop() {
        if b < 0xff {
            out.push(b + 1);
            return out;
        }
    }
    vec![0xff; prefix.len() + 1]
}

fn point_key(pos: &[Step], kind: Kind, s: &Stamp) -> Vec<u8> {
    let mut out = under(b'W', pos);
    out.push(kind_byte(kind));
    put_stamp(&mut out, s);
    out
}

// ---- rows

/// A body holding a write: whether the write wins in it, and its copy of what decides hiding.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Holder {
    body: Body,
    wins: bool,
    payload: Vec<u8>,
}

/// A write's row: when it died (`None`: no held write supersedes it) and who holds it, by
/// (`ts`, commit).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Cell {
    death: Option<Ts>,
    holders: Vec<Holder>,
}

fn put_holders(out: &mut Vec<u8>, hs: &[Holder]) {
    put_u64(out, hs.len() as u64);
    for h in hs {
        out.extend_from_slice(&h.body.c.0);
        put_u64(out, h.body.ts.to_u64());
        out.push(u8::from(h.body.snap) | u8::from(h.wins) << 1);
        put_u64(out, h.payload.len() as u64);
        out.extend_from_slice(&h.payload);
    }
}

fn read_holders(r: &mut Rd<'_>) -> Result<Vec<Holder>, Corrupt> {
    let n = r.u64()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let c = CommitId(r.arr()?);
        let ts = r.ts()?;
        let flags = r.u8()?;
        let len = r.u64()? as usize;
        out.push(Holder { body: Body { c, ts, snap: flags & 1 != 0 }, wins: flags & 2 != 0, payload: r.take(len)?.to_vec() });
    }
    Ok(out)
}

impl Cell {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_opt_ts(&mut out, self.death);
        put_holders(&mut out, &self.holders);
        out
    }
    fn decode(b: &[u8]) -> Result<Cell, Corrupt> {
        let mut r = Rd(b);
        let c = Cell { death: r.opt_ts()?, holders: read_holders(&mut r)? };
        r.end()?;
        Ok(c)
    }
    /// The holders it dates (spec/commits.md §5): those it wins in, a snapshot only when no
    /// snapshot stamped later holds it winning (that one keeps its history).
    fn dated(&self) -> impl Iterator<Item = &Holder> {
        self.holders.iter().filter(|h| h.wins && !(h.body.snap && self.holders.iter().any(|o| o.wins && o.body.snap && o.body.ts > h.body.ts && o.body.c != h.body.c)))
    }
    fn add(&mut self, h: Holder) {
        self.holders.retain(|x| x.body.c != h.body.c);
        let at = self.holders.partition_point(|x| (x.body.ts, x.body.c) < (h.body.ts, h.body.c));
        self.holders.insert(at, h);
    }
    /// The joined copy of a set element register write's value (§4.1 copy order), if this is one.
    fn value(&self) -> Result<Option<Value>, Corrupt> {
        let mut best: Option<Value> = None;
        for h in &self.holders {
            if h.payload.first() == Some(&2) {
                let mut r = Rd(h.payload.get(1..).unwrap_or_default());
                let v = r.value()?;
                if crate::state::opt_value_cmp(Some(&v), best.as_ref()).is_gt() {
                    best = Some(v);
                }
            }
        }
        Ok(best)
    }
    /// The joined copy of a value removal (§5.5: the greatest), if this is one.
    fn removal(&self, stamp: &Stamp) -> Result<Option<Removal>, Corrupt> {
        let mut best: Option<Removal> = None;
        for h in &self.holders {
            if h.payload.first() == Some(&3) {
                let mut r = Rd(h.payload.get(1..).unwrap_or_default());
                let value = r.value()?;
                let mut seen = Vec::new();
                for _ in 0..r.u64()? {
                    seen.push(DotRange { first: r.dot()?, hi: r.u64()? });
                }
                let g = Removal { stamp: stamp.clone(), value, seen };
                if best.as_ref().is_none_or(|b| g > *b) {
                    best = Some(g);
                }
            }
        }
        Ok(best)
    }
}

/// The writes on one bucket's sequence elements, by element counter, then kind and stamp.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Bucket(BTreeMap<u64, BTreeMap<(Kind, Stamp), Cell>>);

impl Bucket {
    /// Run-length coded: a holders table, then runs of consecutive counters of one kind, death
    /// and holders whose stamps are their elements' own dots at one `ts` (a creation run), or
    /// one stamp (a flag write over a range).
    fn encode(&self, src: &Source) -> Vec<u8> {
        /// A run: first counter, length, kind, first stamp, own-dot stamps, death, holders.
        type Run<'a> = (u64, u64, Kind, &'a Stamp, bool, Option<Ts>, usize);
        let mut table: Vec<&Vec<Holder>> = Vec::new();
        let mut runs: Vec<Run<'_>> = Vec::new();
        // by kind, stamp class, then counter, so a run's elements are adjacent
        let mut cells: Vec<((u64, Kind, &Stamp), &Cell, bool)> = self.cells().map(|(ctr, k, c)| ((ctr, k.0, &k.1), c, k.1.dot.src == *src && k.1.dot.ctr == ctr)).collect();
        cells.sort_by(|a, b| (a.0.1, a.2, a.0.2.ts).cmp(&(b.0.1, b.2, b.0.2.ts)).then_with(|| if a.2 { a.0.0.cmp(&b.0.0) } else { (a.0.2, a.0.0).cmp(&(b.0.2, b.0.0)) }));
        for (k, c, own) in cells {
            let t = match table.iter().position(|x| **x == c.holders) {
                Some(t) => t,
                None => {
                    table.push(&c.holders);
                    table.len() - 1
                }
            };
            if let Some(r) = runs.last_mut()
                && r.0 + r.1 == k.0
                && r.2 == k.1
                && r.4 == own
                && r.5 == c.death
                && r.6 == t
                && if own { r.3.ts == k.2.ts } else { r.3 == k.2 }
            {
                r.1 += 1;
                continue;
            }
            runs.push((k.0, 1, k.1, k.2, own, c.death, t));
        }
        let mut out = Vec::new();
        put_u64(&mut out, table.len() as u64);
        table.iter().for_each(|hs| put_holders(&mut out, hs));
        for (lo, n, kind, stamp, own, death, t) in runs {
            put_u64(&mut out, lo);
            put_u64(&mut out, n);
            out.push(kind_byte(kind));
            out.push(u8::from(own));
            if own {
                put_u64(&mut out, stamp.ts.to_u64());
            } else {
                put_stamp(&mut out, stamp);
            }
            put_opt_ts(&mut out, death);
            put_u64(&mut out, t as u64);
        }
        out
    }
    fn decode(b: &[u8], src: &Source) -> Result<Bucket, Corrupt> {
        let mut r = Rd(b);
        let mut table = Vec::new();
        for _ in 0..r.u64()? {
            table.push(read_holders(&mut r)?);
        }
        let mut out: BTreeMap<u64, BTreeMap<(Kind, Stamp), Cell>> = BTreeMap::new();
        while !r.0.is_empty() {
            let (lo, n, kind, own) = (r.u64()?, r.u64()?, kind_of(r.u8()?)?, r.u8()? != 0);
            let (ts, stamp) = if own { (Some(r.ts()?), None) } else { (None, Some(r.stamp()?)) };
            let death = r.opt_ts()?;
            let holders = table.get(r.u64()? as usize).ok_or(Corrupt("held writes row: holders"))?;
            if n > BUCKET {
                return Err(Corrupt("held writes row: run"));
            }
            for i in 0..n {
                let ctr = lo.checked_add(i).ok_or(Corrupt("held writes row: run"))?;
                let s = match (&stamp, ts) {
                    (Some(s), _) => s.clone(),
                    (None, Some(ts)) => Stamp { ts, dot: Dot::new(src.clone(), ctr) },
                    (None, None) => return Err(Corrupt("held writes row: run")),
                };
                out.entry(ctr).or_default().insert((kind, s), Cell { death, holders: holders.clone() });
            }
        }
        Ok(Bucket(out))
    }
    fn cells(&self) -> impl Iterator<Item = (u64, &(Kind, Stamp), &Cell)> {
        self.0.iter().flat_map(|(ctr, m)| m.iter().map(move |(k, c)| (*ctr, k, c)))
    }
    fn top(&self) -> Option<&Stamp> {
        self.cells().map(|x| &x.1.1).max()
    }
    fn get(&self, ctr: u64, kind: Kind, s: &Stamp) -> Option<&Cell> {
        self.0.get(&ctr)?.get(&(kind, s.clone()))
    }
    fn set(&mut self, ctr: u64, kind: Kind, s: &Stamp, c: Option<Cell>) {
        match c {
            Some(c) => _ = self.0.entry(ctr).or_default().insert((kind, s.clone()), c),
            None => {
                if let Some(m) = self.0.get_mut(&ctr) {
                    m.remove(&(kind, s.clone()));
                    if m.is_empty() {
                        self.0.remove(&ctr);
                    }
                }
            }
        }
    }
}

/// A position's tops (`A` row; none: nothing held at or below it): the greatest stamp held at or
/// below it, the greatest of its own writes per kind (a point's `W` rows; a bucket's writes are
/// its row's), and how many steps down it has (`S` rows).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Tops {
    all: Option<Stamp>,
    own: BTreeMap<Kind, Stamp>,
    steps: u64,
}

impl Tops {
    /// The greatest stamp, the steps, then per kind its byte and 0 where its top is the greatest,
    /// else 1 and the stamp.
    fn encode(&self, all: &Stamp) -> Vec<u8> {
        let mut out = stamp_bytes(all);
        put_u64(&mut out, self.steps);
        for (k, s) in &self.own {
            out.push(kind_byte(*k));
            if s == all {
                out.push(0);
            } else {
                out.push(1);
                put_stamp(&mut out, s);
            }
        }
        out
    }
    fn decode(b: &[u8]) -> Result<Tops, Corrupt> {
        let mut r = Rd(b);
        let all = r.stamp()?;
        let steps = r.u64()?;
        let mut own = BTreeMap::new();
        while !r.0.is_empty() {
            let k = kind_of(r.u8()?)?;
            let s = if r.u8()? == 0 { all.clone() } else { r.stamp()? };
            own.insert(k, s);
        }
        Ok(Tops { all: Some(all), own, steps })
    }
}

/// Stamps `(lo, hi)` of two writes of one kind at one position with none between (`lo` `None`:
/// none below `hi`).
type Gap = (Option<Stamp>, Stamp);

/// A position's tops as a change reads and writes them (`Held::tops`).
#[derive(Clone, Debug)]
struct At {
    tops: Tops,
    /// Changed since read: written at `flush`.
    dirty: bool,
    /// Nothing was held at or below it when read: its `W` rows are those the change wrote
    /// (`Held::cells`).
    fresh: bool,
    /// Per kind, the gaps between its writes the change read, once its writes move no key.
    gaps: BTreeMap<Kind, Vec<Gap>>,
}

/// A body's own writes: at points (with whether each wins in it and its copy payload), and per
/// bucket on its elements.
#[derive(Default)]
struct Own {
    points: Vec<(Pos, Kind, Stamp, bool, Vec<u8>)>,
    buckets: BTreeMap<Pos, Vec<(u64, Kind, Stamp, bool)>>,
}

/// Bytes of a body's own writes per row (`L` rows): one row per write at 0; unbounded, a row
/// as large as the body. About a state page.
const OWN_CHUNK: usize = 4096;

/// What may have moved: a write, or every write of a bucket.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Moved {
    Point(Pos, Kind, Stamp),
    Bucket(Pos),
}

/// The held writes of one aspect in `rows` (module doc).
#[derive(Clone, Debug)]
pub struct Held<R: Rows> {
    pub rows: R,
    /// Changes to the `D` rows not written yet (`flush`).
    dated: BTreeMap<(CommitId, Ts), i64>,
    /// The bodies whose dates may have moved since `take_moved`.
    moved: BTreeSet<CommitId>,
    /// Whether a held write's death went to none since `take_revived` (§4.8 Revival).
    revived: bool,
    /// The tops of the positions the change under way read, until `flush`.
    tops: BTreeMap<Pos, At>,
    /// The `W` rows the change under way wrote, by key (`None`: gone), until `flush`.
    cells: BTreeMap<Vec<u8>, Option<Cell>>,
}

fn inv(b: &[u8]) -> Vec<u8> {
    b.iter().map(|x| !x).collect()
}

/// A body's rows lie together, after every position's: 1, its commit ID, `tag`.
fn of_body(tag: u8, c: &CommitId) -> Vec<u8> {
    [&[1], &c.0[..], &[tag]].concat()
}

fn date_key(c: &CommitId, t: Option<Ts>) -> Vec<u8> {
    let mut out = of_body(b'D', c);
    if let Some(t) = t {
        out.extend_from_slice(&inv(&t.to_u64().to_be_bytes()));
    }
    out
}

fn own_key(c: &CommitId, chunk: Option<u64>) -> Vec<u8> {
    let mut out = of_body(b'L', c);
    if let Some(i) = chunk {
        put_u64(&mut out, i);
    }
    out
}

fn body_key(c: &CommitId) -> Vec<u8> {
    of_body(b'N', c)
}

fn min_ts(a: Option<Ts>, b: Option<Ts>) -> Option<Ts> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

/// Whether a write of kind `s`, `same`: at the position of a write of kind `w` (else above it),
/// can supersede it (`supersedes` without the stamps).
fn can_supersede(s: Kind, w: Kind, same: bool) -> bool {
    let flag = |k: Kind| matches!(k, Kind::Delete | Kind::Undelete);
    match s {
        Kind::Reset | Kind::Value => true,
        Kind::ElemReset => !same || w == Kind::ElemReset,
        k => same && (k == w || flag(k) && flag(w) || k == Kind::Created && (w == Kind::Pos || flag(w))),
    }
}

impl<R: Rows> Held<R> {
    pub fn new(rows: R) -> Held<R> {
        Held { rows, dated: BTreeMap::new(), moved: BTreeSet::new(), revived: false, tops: BTreeMap::new(), cells: BTreeMap::new() }
    }

    /// Whether a write still held stopped being dead since the last call: a body leaving took
    /// every write that superseded it (§4.8 Revival).
    pub fn take_revived(&mut self) -> bool {
        std::mem::take(&mut self.revived)
    }

    /// The bodies whose date (`date`) may have moved since the last call.
    pub fn take_moved(&mut self) -> BTreeSet<CommitId> {
        std::mem::take(&mut self.moved)
    }

    /// The tag body `c` joined with (`join`), if it is joined.
    pub fn joined(&mut self, c: &CommitId) -> Result<Option<Vec<u8>>, R::Err> {
        self.rows.get(&body_key(c))
    }

    /// Whether some held write is dead.
    pub fn any_dead(&mut self) -> Result<bool, R::Err> {
        Ok(self.rows.scan(&[1], &[2], usize::MAX)?.iter().any(|(k, _)| k.get(33) == Some(&b'D')))
    }

    /// Whether no body is joined: no row is kept.
    pub fn empty(&mut self) -> Result<bool, R::Err> {
        Ok(self.rows.scan(&[], &[2], 1)?.is_empty())
    }

    /// When body `c` was replaced (spec/commits.md §5): the latest death among the writes it
    /// dates; `None`: none of them is dead (or it is not joined).
    pub fn date(&mut self, c: &CommitId) -> Result<Option<Ts>, R::Err> {
        let from = date_key(c, None);
        let Some((k, _)) = self.rows.scan(&from, &end_of(&from), 1)?.pop() else { return Ok(None) };
        let t = inv(k.get(from.len()..).unwrap_or_default());
        Ok(Some(Rd(&t).ts()?))
    }

    /// When held write `w` died (`None`: not held; `Some(None)`: not dead), and the snapshots
    /// holding it winning, by (`ts`, commit).
    pub fn held(&mut self, w: &Won) -> Result<Option<HeldWrite>, R::Err> {
        let pos = pos_of(&w.path);
        let cell = match item_of(&pos) {
            Some((bucket, ctr)) => self.bucket(bucket)?.get(ctr, w.kind, &w.stamp).cloned(),
            None => self.point(&pos, w.kind, &w.stamp)?,
        };
        Ok(cell.map(|c| (c.death, c.holders.iter().filter(|h| h.wins && h.body.snap).map(|h| (h.body.ts, h.body.c)).collect())))
    }

    fn point(&mut self, pos: &[Step], kind: Kind, s: &Stamp) -> Result<Option<Cell>, R::Err> {
        let key = point_key(pos, kind, s);
        if let Some(c) = self.cells.get(&key) {
            return Ok(c.clone());
        }
        if self.tops.get(pos).is_some_and(|a| a.fresh) {
            return Ok(None);
        }
        self.stored_cell(&key)
    }

    /// The write at `pos` keyed `key`, its position's tops read first: one read at most, none
    /// at a fresh position.
    fn cell_at(&mut self, pos: &[Step], key: &[u8]) -> Result<Option<Cell>, R::Err> {
        if let Some(c) = self.cells.get(key) {
            return Ok(c.clone());
        }
        if self.at(pos)?.fresh {
            return Ok(None);
        }
        self.stored_cell(key)
    }

    fn stored_cell(&mut self, key: &[u8]) -> Result<Option<Cell>, R::Err> {
        match self.rows.get(key)? {
            Some(b) => Ok(Some(Cell::decode(&b)?)),
            None => Ok(None),
        }
    }

    /// Writes the write keyed `key` (`None`: gone), kept for the change's later reads.
    fn put_cell(&mut self, key: &[u8], c: Option<Cell>) -> Result<(), R::Err> {
        match &c {
            Some(c) => self.rows.put(key, &c.encode())?,
            None => self.rows.del(key)?,
        }
        self.cells.insert(key.to_vec(), c);
        Ok(())
    }

    fn bucket(&mut self, pos: &[Step]) -> Result<Bucket, R::Err> {
        let Some(d) = pos.last().and_then(Step::bucket) else { return Err(Corrupt("held writes: not a bucket").into()) };
        match self.rows.get(&pos_key(b'B', pos))? {
            Some(b) => Ok(Bucket::decode(&b, &d.src)?),
            None => Ok(Bucket::default()),
        }
    }

    fn put_bucket(&mut self, pos: &[Step], b: &Bucket) -> Result<(), R::Err> {
        let Some(d) = pos.last().and_then(Step::bucket) else { return Err(Corrupt("held writes: not a bucket").into()) };
        let key = pos_key(b'B', pos);
        if b.0.is_empty() { self.rows.del(&key) } else { self.rows.put(&key, &b.encode(&d.src)) }
    }

    /// Notes `n` writes going from (`old`'s holders, death) to `new`'s in the bodies' dates.
    fn redate(&mut self, old: Option<&Cell>, new: Option<&Cell>) {
        if old.is_some_and(|c| c.death.is_some()) && new.is_some_and(|c| c.death.is_none() && !c.holders.is_empty()) {
            self.revived = true;
        }
        for (c, sign) in [(old, -1), (new, 1)] {
            let Some(c) = c else { continue };
            let Some(t) = c.death else { continue };
            for h in c.dated() {
                *self.dated.entry((h.body.c, t)).or_default() += sign;
                self.moved.insert(h.body.c);
            }
        }
    }

    /// Writes the tops the change moved and the `D` rows `redate` moved; the change's reads
    /// are forgotten.
    fn flush(&mut self) -> Result<(), R::Err> {
        self.cells.clear();
        for (pos, at) in std::mem::take(&mut self.tops) {
            if !at.dirty {
                continue;
            }
            let key = pos_key(b'A', &pos);
            match &at.tops.all {
                Some(all) => self.rows.put(&key, &at.tops.encode(all))?,
                None => self.rows.del(&key)?,
            }
        }
        for ((c, t), n) in std::mem::take(&mut self.dated) {
            if n == 0 {
                continue;
            }
            let key = date_key(&c, Some(t));
            let was = match self.rows.get(&key)? {
                Some(b) => Rd(&b).u64()?,
                None => 0,
            };
            let now = (was as i64).checked_add(n).filter(|x| *x >= 0).ok_or(Corrupt("held writes: a body's deaths below none"))?;
            if now == 0 { self.rows.del(&key)? } else { self.rows.put(&key, &(now as u64).to_be_bytes())? }
        }
        self.rows.flush()
    }

    // ---- tops

    /// The tops of `pos`, read once per change.
    fn at(&mut self, pos: &[Step]) -> Result<&mut At, R::Err> {
        if !self.tops.contains_key(pos) {
            // below a fresh position, nothing was held either
            let under_fresh = (0..pos.len()).rev().find_map(|n| self.tops.get(pos.get(..n).unwrap_or_default())).is_some_and(|a| a.fresh);
            let tops = match under_fresh {
                true => None,
                false => self.rows.get(&pos_key(b'A', pos))?,
            };
            let tops = match tops {
                Some(b) => Tops::decode(&b)?,
                None => Tops::default(),
            };
            let fresh = tops.all.is_none();
            self.tops.insert(pos.to_vec(), At { tops, dirty: false, fresh, gaps: BTreeMap::new() });
        }
        Ok(self.tops.get_mut(pos).ok_or(Corrupt("held writes: tops"))?)
    }

    fn top(&mut self, pos: &[Step]) -> Result<Option<Stamp>, R::Err> {
        Ok(self.at(pos)?.tops.all.clone())
    }

    /// The `S` key of step `step` below `up` with top `top`, and its row: the step.
    fn step_key(up: &[Step], top: &Stamp, step: &Step) -> (Vec<u8>, Vec<u8>) {
        let mut row = Vec::new();
        put_step(&mut row, &step.of);
        let mut out = under(b'S', up);
        out.extend_from_slice(&inv(&stamp_bytes(top)));
        out.extend_from_slice(&step.h);
        (out, row)
    }

    /// Sets the top of `pos` (`None`: none) from `old`, and its step row above.
    fn set_top(&mut self, pos: &[Step], old: Option<&Stamp>, new: Option<&Stamp>) -> Result<(), R::Err> {
        let at = self.at(pos)?;
        at.tops.all = new.cloned();
        at.dirty = true;
        if let Some((step, up)) = pos.split_last() {
            if let Some(o) = old {
                self.rows.del(&Self::step_key(up, o, step).0)?;
            }
            if let Some(s) = new {
                let (k, row) = Self::step_key(up, s, step);
                self.rows.put(&k, &row)?;
            }
            if old.is_none() != new.is_none() {
                let up = self.at(up)?;
                up.tops.steps = if new.is_some() { up.tops.steps.checked_add(1) } else { up.tops.steps.checked_sub(1) }.ok_or(Corrupt("held writes: steps"))?;
                up.dirty = true;
            }
        }
        Ok(())
    }

    /// A write stamped `st` came at `pos`: the tops at and above it rise, up to the first as high.
    fn raise(&mut self, pos: &[Step], st: &Stamp) -> Result<(), R::Err> {
        for n in (0..=pos.len()).rev() {
            let Some(q) = pos.get(..n) else { continue };
            let old = self.top(q)?;
            if old.as_ref().is_some_and(|x| x >= st) {
                return Ok(());
            }
            self.set_top(q, old.as_ref(), Some(st))?;
        }
        Ok(())
    }

    /// The greatest stamp among the writes at `pos` itself.
    fn own_top(&mut self, pos: &[Step]) -> Result<Option<Stamp>, R::Err> {
        if pos.last().and_then(Step::bucket).is_some() {
            return Ok(self.bucket(pos)?.top().cloned());
        }
        Ok(self.at(pos)?.tops.own.values().max().cloned())
    }

    /// A write stamped `st` left `pos`: the tops at and above it, while `st` was a position's
    /// greatest, drop to the greatest left there.
    fn lower(&mut self, pos: &[Step], st: &Stamp) -> Result<(), R::Err> {
        for n in (0..=pos.len()).rev() {
            let Some(q) = pos.get(..n) else { continue };
            let Some(old) = self.top(q)? else { return Ok(()) };
            if old > *st {
                return Ok(());
            }
            let own = self.own_top(q)?;
            let from = under(b'S', q);
            let step = match self.at(q)?.tops.steps {
                0 => None,
                _ => match self.rows.scan(&from, &end_of(&from), 1)?.pop() {
                    Some((k, _)) => Some(Rd(&inv(k.get(from.len()..).unwrap_or_default())).stamp()?),
                    None => None,
                },
            };
            let new = own.max(step);
            if new.as_ref() == Some(&old) {
                return Ok(());
            }
            self.set_top(q, Some(&old), new.as_ref())?;
        }
        Ok(())
    }

    /// The positions at or below `pos` holding a write stamped at or after `floor` (every one,
    /// `None`), and some above those: O(those positions times their depth below `pos`).
    fn below(&mut self, pos: &[Step], floor: Option<&Stamp>) -> Result<Vec<Pos>, R::Err> {
        let high = |t: &Stamp| floor.is_none_or(|f| t >= f);
        let mut out = Vec::new();
        let mut todo = vec![pos.to_vec()];
        while let Some(q) = todo.pop() {
            let at = &self.at(&q)?.tops;
            if !at.all.as_ref().is_some_and(high) {
                continue;
            }
            if at.steps == 0 {
                out.push(q);
                continue;
            }
            let from = under(b'S', &q);
            let to = match floor {
                // inverted: stamps at or after the floor sort at or before it
                Some(f) => end_of(&[&from[..], &inv(&stamp_bytes(f))].concat()),
                None => end_of(&from),
            };
            let mut at = from.clone();
            loop {
                let page = self.rows.scan(&at, &to, 64)?;
                let n = page.len();
                for (k, v) in page {
                    let step = read_step(&mut Rd(&v))?;
                    todo.push([q.as_slice(), std::slice::from_ref(&step)].concat());
                    at = [&k[..], &[0]].concat();
                }
                if n < 64 {
                    break;
                }
            }
            out.push(q);
        }
        Ok(out)
    }

    // ---- writes at a point

    /// The greatest stamp of kind `k` at point `pos`, below `before` if given: by its tops, read
    /// in the rows only where one of kind `k` there is stamped at or after `before`.
    fn pred(&mut self, pos: &[Step], k: Kind, before: Option<&Stamp>) -> Result<Option<Stamp>, R::Err> {
        let Some(top) = self.at(pos)?.tops.own.get(&k).cloned() else { return Ok(None) };
        let Some(before) = before.filter(|b| top >= **b) else { return Ok(Some(top)) };
        let gaps = self.at(pos)?.gaps.get(&k);
        if let Some((lo, _)) = gaps.into_iter().flatten().find(|(lo, hi)| lo.as_ref().is_none_or(|l| l < before) && before <= hi) {
            return Ok(lo.clone());
        }
        let lo = self.edge(pos, k, None, Some(before), true)?;
        // `before` written by this change: held, with none between
        if matches!(self.cells.get(&point_key(pos, k, before)), Some(Some(_))) {
            self.at(pos)?.gaps.entry(k).or_default().push((lo.clone(), before.clone()));
        }
        Ok(lo)
    }

    /// The least stamp of kind `k` at point `pos` above `after`: by its tops, read in the rows
    /// only where one of kind `k` there is stamped after `after`.
    fn succ(&mut self, pos: &[Step], k: Kind, after: &Stamp) -> Result<Option<Stamp>, R::Err> {
        let at = self.at(pos)?;
        if at.tops.own.get(&k).is_none_or(|t| t <= after) {
            return Ok(None);
        }
        let gaps = at.gaps.get(&k);
        if let Some((_, hi)) = gaps.into_iter().flatten().find(|(lo, hi)| lo.as_ref().is_none_or(|l| l <= after) && after < hi) {
            return Ok(Some(hi.clone()));
        }
        self.edge(pos, k, Some(after), None, false)
    }

    /// The greatest (`back`) or least stamp of kind `k` at point `pos` above `after` and below
    /// `before`: in the rows the change wrote at a fresh position, else in the stored rows.
    fn edge(&mut self, pos: &[Step], k: Kind, after: Option<&Stamp>, before: Option<&Stamp>, back: bool) -> Result<Option<Stamp>, R::Err> {
        let mut prefix = under(b'W', pos);
        prefix.push(kind_byte(k));
        let from = match after {
            Some(s) => {
                let mut f = prefix.clone();
                put_stamp(&mut f, s);
                f.push(0);
                f
            }
            None => prefix.clone(),
        };
        let to = match before {
            Some(s) => {
                let mut t = prefix.clone();
                put_stamp(&mut t, s);
                t
            }
            None => end_of(&prefix),
        };
        if from >= to {
            return Ok(None);
        }
        let key = if self.tops.get(pos).is_some_and(|a| a.fresh) {
            let mut written = self.cells.range::<[u8], _>((Bound::Included(&from[..]), Bound::Excluded(&to[..]))).filter(|x| x.1.is_some()).map(|x| x.0.clone());
            if back { written.next_back() } else { written.next() }
        } else {
            let found = if back { self.rows.scan_back(&from, &to, 1)? } else { self.rows.scan(&from, &to, 1)? };
            found.into_iter().next().map(|x| x.0)
        };
        match key {
            Some(key) => Ok(Some(Rd(key.get(prefix.len()..).unwrap_or_default()).stamp()?)),
            None => Ok(None),
        }
    }

    /// The greatest reset or register write (one implies a reset, §5.1) stamped before `st` on
    /// the positions at and above `pos`: it supersedes every write at or below `pos` stamped
    /// before it, no later than one stamped `st` would.
    fn floor(&mut self, pos: &[Step], st: &Stamp) -> Result<Option<Stamp>, R::Err> {
        let mut out = None;
        for n in 0..=pos.len() {
            let Some(q) = pos.get(..n) else { continue };
            if !is_point(q) {
                continue;
            }
            for (k, top) in self.covers(q)? {
                match top {
                    Some(t) if t < *st => out = out.max(Some(t)),
                    Some(_) => out = out.max(self.pred(q, k, Some(st))?),
                    None => {}
                }
            }
        }
        Ok(out)
    }

    /// The greatest reset and register write at point `pos`, the writes superseding every write
    /// below them.
    fn covers(&mut self, pos: &[Step]) -> Result<[(Kind, Option<Stamp>); 2], R::Err> {
        let own = &self.at(pos)?.tops.own;
        Ok([Kind::Reset, Kind::Value].map(|k| (k, own.get(&k).cloned())))
    }

    /// The least stamp above `st` among the writes above position `pos` (not at it) that
    /// supersede any write below them: resets and register writes, and element resets of the
    /// sequence elements on the way. `memo`: the last answer, good for a stamp between its
    /// question and its answer.
    fn above(&mut self, pos: &[Step], st: &Stamp, memo: &mut Option<(Stamp, Option<Stamp>)>) -> Result<Option<Stamp>, R::Err> {
        if let Some((lo, next)) = memo
            && *lo <= *st
            && next.as_ref().is_none_or(|n| n > st)
        {
            return Ok(next.clone());
        }
        let mut out: Option<Stamp> = None;
        let mut least = |x: Option<Stamp>| {
            if let Some(x) = x
                && out.as_ref().is_none_or(|o| x < *o)
            {
                out = Some(x);
            }
        };
        for n in 0..pos.len() {
            let Some(q) = pos.get(..n) else { continue };
            match item_of(q) {
                Some((bucket, ctr)) => {
                    let b = self.bucket(bucket)?;
                    let at = b.0.get(&ctr);
                    least(at.and_then(|m| m.range((Kind::ElemReset, st.clone())..).take_while(|(k, _)| k.0 == Kind::ElemReset).map(|(k, _)| &k.1).find(|s| *s > st).cloned()));
                }
                None if is_point(q) => {
                    for (k, top) in self.covers(q)? {
                        if top.is_some_and(|t| t > *st) {
                            least(self.succ(q, k, st)?);
                        }
                    }
                }
                None => {}
            }
        }
        *memo = Some((st.clone(), out.clone()));
        Ok(out)
    }

    /// When the write `kind` stamped `st` at point `pos` (row `cell`) died, by the rows as they
    /// are (§4.8 When): the earliest `ts` among the writes superseding it, which is the least
    /// stamp's (stamps order by `ts` first).
    fn point_death(&mut self, pos: &[Step], kind: Kind, st: &Stamp, cell: &Cell) -> Result<Option<Ts>, R::Err> {
        let mut best = self.above(pos, st, &mut None)?.map(|s| s.ts);
        for k in Kind::ALL {
            if can_supersede(k, kind, true) {
                best = min_ts(best, self.succ(pos, k, st)?.map(|s| s.ts));
            }
        }
        // a set element's register write: the value removals hiding it (§5.5)
        if kind == Kind::Value
            && let [set @ .., e, Step { of: StepOf::At(Place::In), .. }] = pos
            && let Some(Place::Elem(d)) = e.place()
            && let Some(v) = cell.value()?
        {
            let mut from = under(b'V', set);
            from.extend_from_slice(&short(&osis_base::cbor::encode(&v)));
            for (_, row) in self.rows.scan(&from, &end_of(&from), usize::MAX)? {
                let mut r = Rd(&row);
                let (rd, rs) = (r.dot()?, r.stamp()?);
                let gone = [set, &[Step::at(Place::Gone(rd))]].concat();
                if let Some(c) = self.point(&gone, Kind::Reset, &rs)?
                    && c.removal(&rs)?.is_some_and(|g| g.hides(d, st))
                {
                    best = min_ts(best, Some(rs.ts));
                }
            }
        }
        Ok(best)
    }

    /// When the write `kind` stamped `st` on an element of bucket `pos` died, `at`: the writes
    /// on that element: by those (a text element's creation only by a delete beating its
    /// latest undelete) and those above the sequence.
    fn item_death(&mut self, pos: &[Step], at: Option<&BTreeMap<(Kind, Stamp), Cell>>, kind: Kind, st: &Stamp, memo: &mut Option<(Stamp, Option<Stamp>)>) -> Result<Option<Ts>, R::Err> {
        let mut best = self.above(pos, st, memo)?.map(|s| s.ts);
        let Some(at) = at else { return Ok(best) };
        let undeleted = if kind == Kind::Created { at.keys().filter(|x| x.0 == Kind::Undelete).map(|x| &x.1).max() } else { None };
        let w = Won { path: Vec::new(), kind, stamp: st.clone() };
        for (k, s) in at.keys() {
            if s < st || *k == Kind::Delete && undeleted.is_some_and(|u| s < u) {
                continue;
            }
            // one position: `supersedes` reads the paths' depths alone
            if supersedes(0, *k, s, &w) {
                best = min_ts(best, Some(s.ts));
            }
        }
        Ok(best)
    }

    /// Dates every write of bucket `pos` again (`b`: its row).
    fn bucket_deaths(&mut self, pos: &[Step], b: &mut Bucket) -> Result<(), R::Err> {
        let mut memo = None;
        let mut dated: Vec<(u64, Kind, Stamp, Option<Ts>)> = Vec::new();
        for (ctr, at) in &b.0 {
            for ((kind, st), c) in at {
                let best = self.item_death(pos, Some(at), *kind, st, &mut memo)?;
                if c.death != best {
                    dated.push((*ctr, *kind, st.clone(), best));
                }
            }
        }
        for (ctr, kind, st, death) in dated {
            let Some(c) = b.get(ctr, kind, &st) else { continue };
            let new = Cell { death, holders: c.holders.clone() };
            self.redate(Some(c), Some(&new));
            b.set(ctr, kind, &st, Some(new));
        }
        Ok(())
    }

    /// When write `w` dies by the writes held (§4.8 When), held itself or not.
    #[cfg(test)]
    pub fn dies(&mut self, w: &Won) -> Result<Option<Ts>, R::Err> {
        let pos = pos_of(&w.path);
        match item_of(&pos) {
            Some((bucket, ctr)) => {
                let b = self.bucket(bucket)?;
                self.item_death(bucket, b.0.get(&ctr), w.kind, &w.stamp, &mut None)
            }
            None => {
                let c = self.point(&pos, w.kind, &w.stamp)?.unwrap_or_default();
                self.point_death(&pos, w.kind, &w.stamp, &c)
            }
        }
    }

    // ---- bodies

    /// Body `b` joins with writes `w` under the caller's tag `tag`.
    pub fn join(&mut self, b: &Body, w: &BodyWrites, tag: &[u8]) -> Result<(), R::Err> {
        self.join_as(b, w, tag, true)
    }

    /// Body `b` joins as `join`, but no death moves: rows built from nothing (`date_every`
    /// after the last), where each write is dated once, not again at each join.
    pub fn place(&mut self, b: &Body, w: &BodyWrites, tag: &[u8]) -> Result<(), R::Err> {
        self.join_as(b, w, tag, false)
    }

    /// Dates every write by the rows (`point_death`, `bucket_deaths`), and each body's deaths
    /// with them: after bodies `place`d, the rows joining them gives, in any order.
    pub fn date_every(&mut self) -> Result<(), R::Err> {
        for pos in self.below(&[], None)? {
            if pos.last().and_then(Step::bucket).is_some() {
                self.redate_bucket(&pos)?;
                continue;
            }
            let from = under(b'W', &pos);
            for (k, v) in self.rows.scan(&from, &end_of(&from), usize::MAX)? {
                let mut r = Rd(k.get(from.len()..).unwrap_or_default());
                let (kind, st) = (kind_of(r.u8()?)?, r.stamp()?);
                self.redate_point(&pos, kind, &st, &Cell::decode(&v)?, &k)?;
            }
        }
        self.flush()
    }

    fn join_as(&mut self, b: &Body, w: &BodyWrites, tag: &[u8], date: bool) -> Result<(), R::Err> {
        let mut own = Own::default();
        for won in w.held.iter() {
            let pos = pos_of(&won.path);
            let wins = w.wins.contains(&won);
            match item_of(&pos) {
                Some((bucket, ctr)) => own.buckets.entry(bucket.to_vec()).or_default().push((ctr, won.kind, won.stamp, wins)),
                None => {
                    let payload = w.payload(&won);
                    own.points.push((pos, won.kind, won.stamp, wins, payload));
                }
            }
        }
        self.rows.put(&body_key(&b.c), tag)?;
        // the body's own writes, kept so it can leave unread (`leave`)
        let mut chunks: Vec<Vec<u8>> = vec![Vec::new()];
        let mut add = |rec: Vec<u8>| {
            if chunks.last().is_some_and(|c| c.len() >= OWN_CHUNK) {
                chunks.push(Vec::new());
            }
            if let Some(c) = chunks.last_mut() {
                put_u64(c, rec.len() as u64);
                c.extend_from_slice(&rec);
            }
        };
        for (pos, kind, st, ..) in &own.points {
            let mut rec = vec![0];
            rec.extend_from_slice(&pos_bytes(pos));
            rec.extend_from_slice(&[0, kind_byte(*kind)]);
            put_stamp(&mut rec, st);
            add(rec);
        }
        for (pos, cells) in &own.buckets {
            let Some(d) = pos.last().and_then(Step::bucket) else { continue };
            let mut b = Bucket::default();
            cells.iter().for_each(|(ctr, kind, st, _)| b.set(*ctr, *kind, st, Some(Cell::default())));
            let mut rec = vec![1];
            rec.extend_from_slice(&pos_bytes(pos));
            rec.push(0);
            rec.extend_from_slice(&b.encode(&d.src));
            add(rec);
        }
        for (i, c) in chunks.iter().enumerate().filter(|(_, c)| !c.is_empty()) {
            self.rows.put(&own_key(&b.c, Some(i as u64)), c)?;
        }
        self.change(b, own, true, date)
    }

    /// Body `b`, joined before, leaves: its writes are those its join kept.
    pub fn leave(&mut self, b: &Body) -> Result<(), R::Err> {
        let mut own = Own::default();
        let from = own_key(&b.c, None);
        for (k, v) in self.rows.scan(&from, &end_of(&from), usize::MAX)? {
            let mut r = Rd(&v);
            while !r.0.is_empty() {
                let len = r.u64()? as usize;
                let mut rec = Rd(r.take(len)?);
                let point = rec.u8()? == 0;
                let mut pos = Vec::new();
                while rec.0.first().is_some_and(|b| *b != 0) {
                    pos.push(read_step(&mut rec)?);
                }
                rec.u8()?;
                if point {
                    own.points.push((pos, kind_of(rec.u8()?)?, rec.stamp()?, false, Vec::new()));
                    rec.end()?;
                } else {
                    let Some(d) = pos.last().and_then(Step::bucket) else { return Err(Corrupt("held writes: not a bucket").into()) };
                    let cells = Bucket::decode(rec.0, &d.src)?.cells().map(|(ctr, k, _)| (ctr, k.0, k.1.clone(), false)).collect();
                    own.buckets.insert(pos, cells);
                }
            }
            self.rows.del(&k)?;
        }
        self.rows.del(&body_key(&b.c))?;
        self.change(b, own, false, true)
    }

    /// `date`: the deaths it moves are dated (else none is: `place`).
    fn change(&mut self, body: &Body, own: Own, join: bool, date: bool) -> Result<(), R::Err> {
        self.moved.insert(body.c);
        self.tops.values_mut().for_each(|a| a.gaps.clear());
        // the writes whose coming, going or joined copy may move a death, and the positions
        // whose tops they move
        let mut sources: Vec<Won> = Vec::new();
        let mut raised: Vec<(Pos, Stamp)> = Vec::new();
        let mut lowered: Vec<(Pos, Stamp)> = Vec::new();
        // the kinds whose greatest write left a position
        let mut recount: BTreeSet<(Pos, Kind)> = BTreeSet::new();
        // a joining write's row and the one of its kind below it, read at once (`gaps`)
        let mut read: Vec<((Pos, Kind), Gap)> = Vec::new();
        let mut added: BTreeMap<(Pos, Kind), Vec<Stamp>> = BTreeMap::new();
        for (pos, kind, stamp, wins, payload) in own.points {
            let key = point_key(&pos, kind, &stamp);
            let old = match join && !self.cells.contains_key(&key) && !self.at(&pos)?.fresh {
                true => {
                    let mut prefix = under(b'W', &pos);
                    prefix.push(kind_byte(kind));
                    let mut found = self.rows.scan_back(&prefix, &[&key[..], &[0]].concat(), 2)?.into_iter();
                    let mut old = None;
                    let mut lo = found.next();
                    if let Some((_, v)) = lo.take_if(|x| x.0 == key) {
                        old = Some(Cell::decode(&v)?);
                        lo = found.next();
                    }
                    let lo = match lo {
                        Some((k, _)) => Some(Rd(k.get(prefix.len()..).unwrap_or_default()).stamp()?),
                        None => None,
                    };
                    read.push(((pos.clone(), kind), (lo, stamp.clone())));
                    old
                }
                false => self.cell_at(&pos, &key)?,
            };
            if join {
                added.entry((pos.clone(), kind)).or_default().push(stamp.clone());
            }
            let mut new = old.clone().unwrap_or_default();
            if join {
                new.add(Holder { body: *body, wins, payload });
            } else {
                new.holders.retain(|h| h.body.c != body.c);
            }
            self.redate(old.as_ref(), Some(&new));
            let gone = new.holders.is_empty();
            if gone {
                self.put_cell(&key, None)?;
                lowered.push((pos.clone(), stamp.clone()));
                if self.at(&pos)?.tops.own.get(&kind) == Some(&stamp) {
                    recount.insert((pos.clone(), kind));
                }
            } else {
                self.put_cell(&key, Some(new.clone()))?;
            }
            if old.is_none() {
                raised.push((pos.clone(), stamp.clone()));
                let at = self.at(&pos)?;
                if at.tops.own.get(&kind).is_none_or(|t| *t < stamp) {
                    at.tops.own.insert(kind, stamp.clone());
                    at.dirty = true;
                }
            }
            // a value removal's row under the reference its joined copy names
            let mut copies = old.is_none() || gone;
            if let [set @ .., Step { of: StepOf::At(Place::Gone(d)), .. }] = pos.as_slice() {
                let (was, now) = (old.as_ref().map(|c| c.removal(&stamp)).transpose()?.flatten(), new.removal(&stamp)?);
                if was != now {
                    copies = true;
                    for (g, put) in [(was, false), (now, true)] {
                        let Some(g) = g else { continue };
                        let (k, row) = named_key(set, &g.value, d, &stamp);
                        if put { self.rows.put(&k, &row)? } else { self.rows.del(&k)? }
                    }
                }
            } else if kind == Kind::Value && old.as_ref().map(|c| c.value()).transpose()?.flatten() != new.value()? {
                copies = true;
            }
            if copies {
                sources.push(Won { path: path_of(&pos), kind, stamp });
            }
        }
        // a gap holding another write the change added is none
        for ((pos, k), (lo, hi)) in read {
            if !added.get(&(pos.clone(), k)).into_iter().flatten().any(|x| lo.as_ref().is_none_or(|l| l < x) && x < &hi) {
                self.at(&pos)?.gaps.entry(k).or_default().push((lo, hi));
            }
        }
        for (pos, kind) in recount {
            let top = self.edge(&pos, kind, None, None, true)?;
            let at = self.at(&pos)?;
            match top {
                Some(t) => at.tops.own.insert(kind, t),
                None => at.tops.own.remove(&kind),
            };
            at.dirty = true;
        }
        let mut moved: BTreeSet<Moved> = BTreeSet::new();
        for (pos, cells) in &own.buckets {
            let mut bucket = self.bucket(pos)?;
            let before = bucket.top().cloned();
            let mut changed = false;
            for (ctr, kind, stamp, wins) in cells {
                let old = bucket.get(*ctr, *kind, stamp).cloned();
                let mut new = old.clone().unwrap_or_default();
                if join {
                    new.add(Holder { body: *body, wins: *wins, payload: Vec::new() });
                } else {
                    new.holders.retain(|h| h.body.c != body.c);
                }
                self.redate(old.as_ref(), Some(&new));
                if old.is_none() || new.holders.is_empty() {
                    changed = true;
                    // an element reset supersedes what lies below its element
                    if *kind == Kind::ElemReset
                        && let Some(d) = pos.last().and_then(Step::bucket)
                    {
                        let item = Place::Item(Dot::new(d.src.clone(), *ctr));
                        sources.push(Won { path: [path_of(pos).as_slice(), &[item]].concat(), kind: *kind, stamp: stamp.clone() });
                    }
                }
                let new = (!new.holders.is_empty()).then_some(new);
                bucket.set(*ctr, *kind, stamp, new);
            }
            self.put_bucket(pos, &bucket)?;
            let after = bucket.top().cloned();
            match (before, after) {
                (b, Some(a)) if b.as_ref().is_none_or(|b| a > *b) => raised.push((pos.clone(), a)),
                (Some(b), a) if a.as_ref().is_none_or(|a| *a < b) => lowered.push((pos.clone(), b)),
                _ => {}
            }
            if changed {
                moved.insert(Moved::Bucket(pos.clone()));
            }
        }
        // greatest first: each later one stops at the first position already as high
        raised.sort_by(|a, b| b.1.cmp(&a.1));
        for (pos, st) in &raised {
            self.raise(pos, st)?;
        }
        for (pos, st) in &lowered {
            self.lower(pos, st)?;
        }
        if !date {
            return self.flush();
        }
        for s in &sources {
            self.moved_by(s, &mut moved)?;
        }
        for m in moved {
            match m {
                Moved::Point(pos, kind, st) => {
                    if let Some(c) = self.point(&pos, kind, &st)? {
                        self.redate_point(&pos, kind, &st, &c, &point_key(&pos, kind, &st))?;
                    }
                }
                Moved::Bucket(pos) => self.redate_bucket(&pos)?,
            }
        }
        self.flush()
    }

    /// Writes the cell `c` of a write at `pos` (row `key`) back when the rows date it otherwise.
    fn redate_point(&mut self, pos: &[Step], kind: Kind, st: &Stamp, c: &Cell, key: &[u8]) -> Result<(), R::Err> {
        let death = self.point_death(pos, kind, st, c)?;
        if death != c.death {
            let new = Cell { death, holders: c.holders.clone() };
            self.redate(Some(c), Some(&new));
            self.put_cell(key, Some(new))?;
        }
        Ok(())
    }

    /// Writes the bucket at `pos` back when the rows date its writes otherwise.
    fn redate_bucket(&mut self, pos: &[Step]) -> Result<(), R::Err> {
        let mut b = self.bucket(pos)?;
        let was = b.clone();
        self.bucket_deaths(pos, &mut b)?;
        if b != was {
            self.put_bucket(pos, &b)?;
        }
        Ok(())
    }

    /// The writes whose death may have moved when write `s` came or went, or its joined copy
    /// changed, on the rows after: `s` itself; per kind at each position at or below `s`'s, the
    /// greatest write stamped no later than `s` (every lower one is superseded by that one, no
    /// later than by `s`); every write of a bucket there; of a value removal, every element
    /// register write of its set (which it hides is read in the copies as joined). None stamped
    /// before the `floor` of `s`: superseded by that reset, stamped before `s`. So a reset
    /// reads only what came since the reset before it.
    fn moved_by(&mut self, s: &Won, out: &mut BTreeSet<Moved>) -> Result<(), R::Err> {
        let pos = pos_of(&s.path);
        let depth = s.path.len();
        let floor = self.floor(&pos, &s.stamp)?;
        let high = |st: &Stamp| floor.as_ref().is_none_or(|f| st >= f);
        if is_point(&pos) {
            out.insert(Moved::Point(pos.clone(), s.kind, s.stamp.clone()));
        }
        for q in self.below(&pos, floor.as_ref())? {
            if q.last().and_then(Step::bucket).is_some() {
                out.insert(Moved::Bucket(q));
                continue;
            }
            if !is_point(&q) {
                continue;
            }
            let path = path_of(&q);
            let same = path.len() == depth;
            let tops = self.at(&q)?.tops.own.clone();
            for (k, top) in tops {
                if !can_supersede(s.kind, k, same) {
                    continue;
                }
                // the greatest stamped no later than `s`, but `s`: its top, unless stamped later
                let other = !(same && k == s.kind);
                let w = if top < s.stamp || top == s.stamp && other {
                    Some(top)
                } else if other && self.point(&q, k, &s.stamp)?.is_some() {
                    Some(s.stamp.clone())
                } else {
                    self.pred(&q, k, Some(&s.stamp))?
                };
                if let Some(st) = w.filter(|st| high(st))
                    && supersedes(depth, s.kind, &s.stamp, &Won { path: path.clone(), kind: k, stamp: st.clone() })
                {
                    out.insert(Moved::Point(q.clone(), k, st));
                }
            }
        }
        if let [set @ .., Step { of: StepOf::At(Place::Gone(_)), .. }] = pos.as_slice() {
            let floor = self.floor(set, &s.stamp)?;
            for q in self.below(set, floor.as_ref())? {
                if !matches!(q.get(set.len()..), Some([Step { of: StepOf::At(Place::Elem(_)), .. }, Step { of: StepOf::At(Place::In), .. }])) {
                    continue;
                }
                let mut from = under(b'W', &q);
                from.push(kind_byte(Kind::Value));
                let start = match &floor {
                    Some(f) => [&from[..], &stamp_bytes(f)].concat(),
                    None => from.clone(),
                };
                for (k, _) in self.rows.scan(&start, &end_of(&from), usize::MAX)? {
                    out.insert(Moved::Point(q.clone(), Kind::Value, Rd(k.get(from.len()..).unwrap_or_default()).stamp()?));
                }
            }
        }
        Ok(())
    }

    /// Checks the rows against themselves: every write's death as the
    /// rows date it now, and every body's deaths as its writes give them.
    #[cfg(test)]
    pub fn check(&mut self) -> Result<Result<(), String>, R::Err> {
        let mut dated: BTreeMap<(CommitId, Ts), u64> = BTreeMap::new();
        let mut count = |c: &Cell| {
            if let Some(t) = c.death {
                c.dated().for_each(|h| *dated.entry((h.body.c, t)).or_default() += 1);
            }
        };
        // every position holding a write is under the root's steps
        for pos in self.below(&[], None)? {
            // its tops: its own writes' greatest per kind, its steps down, the greatest of all
            let mut want = Tops::default();
            let from = under(b'S', &pos);
            let steps = self.rows.scan(&from, &end_of(&from), usize::MAX)?;
            want.steps = steps.len() as u64;
            let below = match steps.first() {
                Some((k, _)) => Some(Rd(&inv(k.get(from.len()..).unwrap_or_default())).stamp()?),
                None => None,
            };
            let own = if pos.last().and_then(Step::bucket).is_some() {
                self.bucket(&pos)?.top().cloned()
            } else {
                let from = under(b'W', &pos);
                for (k, _) in self.rows.scan(&from, &end_of(&from), usize::MAX)? {
                    let mut r = Rd(k.get(from.len()..).unwrap_or_default());
                    let (kind, st) = (kind_of(r.u8()?)?, r.stamp()?);
                    want.own.insert(kind, st);
                }
                want.own.values().max().cloned()
            };
            want.all = own.max(below);
            let kept = match self.rows.get(&pos_key(b'A', &pos))? {
                Some(b) => Tops::decode(&b)?,
                None => Tops::default(),
            };
            if kept != want {
                return Ok(Err(format!("{:?}: tops {kept:?} kept, {want:?} by the rows", path_of(&pos))));
            }
            if pos.last().and_then(Step::bucket).is_some() {
                let b = self.bucket(&pos)?;
                let mut again = b.clone();
                let pending = std::mem::take(&mut self.dated);
                let moved = self.moved.clone();
                self.bucket_deaths(&pos, &mut again)?;
                self.dated = pending;
                self.moved = moved;
                if again != b {
                    return Ok(Err(format!("bucket {:?}: deaths kept differ from those by the rows", path_of(&pos))));
                }
                b.cells().for_each(|x| count(x.2));
                continue;
            }
            let from = under(b'W', &pos);
            for (k, v) in self.rows.scan(&from, &end_of(&from), usize::MAX)? {
                let mut r = Rd(k.get(from.len()..).unwrap_or_default());
                let (kind, st) = (kind_of(r.u8()?)?, r.stamp()?);
                let c = Cell::decode(&v)?;
                let want = self.point_death(&pos, kind, &st, &c)?;
                if c.death != want {
                    return Ok(Err(format!("{:?} {kind:?} {st:?}: death {:?} kept, {want:?} by the rows", path_of(&pos), c.death)));
                }
                count(&c);
            }
        }
        let mut kept: BTreeMap<(CommitId, Ts), u64> = BTreeMap::new();
        for (k, v) in self.rows.scan(&[1], &[2], usize::MAX)? {
            if k.get(33) != Some(&b'D') {
                continue;
            }
            let c = CommitId(k.get(1..33).unwrap_or_default().try_into().map_err(|_| Corrupt("held writes row: short"))?);
            let t = Rd(&inv(k.get(34..).unwrap_or_default())).ts()?;
            kept.insert((c, t), Rd(&v).u64()?);
        }
        if kept != dated {
            return Ok(Err(format!("bodies' deaths kept {kept:?}, by their writes {dated:?}")));
        }
        Ok(Ok(()))
    }
}

/// Whether `pos` is a position with writes of its own in `W` rows: not a bucket, nor a sequence
/// element (its writes are its bucket's).
fn is_point(pos: &[Step]) -> bool {
    !matches!(pos.last().map(|s| &s.of), Some(StepOf::Bucket(_) | StepOf::At(Place::Item(_))))
}

/// The bucket's position and the element's counter, where `pos` is a sequence element's.
fn item_of(pos: &[Step]) -> Option<(&[Step], u64)> {
    match pos.split_last() {
        Some((Step { of: StepOf::At(Place::Item(d)), .. }, bucket)) => Some((bucket, d.ctr)),
        _ => None,
    }
}
