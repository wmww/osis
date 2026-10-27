//! A component's walk as bytes, for the node's rebuildable store cache (notes/permissions.md,
//! Implementation; notes/local-store.md). Local format, never on the wire. A saved walk is
//! restored only over exactly the inputs it was walked from: the bytes carry a BLAKE3 tag over
//! the format, the caller's salt (the rules), the walk's whole input (owner links, every
//! membership commit and roster snapshot, frontiers by their sizes: a record's frontier is
//! fixed by its commit ID, `HeldSet`) and the body, so anything else (other rules, other or
//! changed inputs, damaged bytes) gives `None` and the caller evaluates from scratch. Commits
//! added since go on through `Timeline::extend`, as at run time.
//!
//! Layout: tag (32) ‖ body; body = the component's things, held commit and snapshot IDs and
//! `/created` tids (`Inputs`), then the walk (`Walked` with its undo log, D, epoch starts,
//! passes, `reach`). Frontiers are referenced by where the input holds them (a commit's, or
//! a snapshot's ledger entry), not copied.

use crate::graph::{Class, Edges, Owner, Owners};
use crate::held::HeldSet;
use crate::timeline::Timeline;
use crate::types::{Dots, Edge, Frontier, MembershipCommit, Point, RosterSnapshot, WriteId};
use crate::walk::{Applied, Attr, Change, Demotion, Fall, Input, Outcome, Rest, Undo, Walked};
use osis_core::{CommitId, CreationRecord, Role, Tid, Ts, WallMs};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

const FORMAT: &[u8] = b"osis-perm walk cache 3";

/// A component's exact inputs: its things, the IDs of its commits and snapshots, and its
/// held `/created` records (by tid; a record's tid fixes its content).
pub(crate) type Inputs = (BTreeSet<Tid>, BTreeSet<CommitId>, BTreeSet<Tid>);

/// Where a frontier sits in the input.
#[derive(Clone, Copy)]
enum FRef {
    Commit(CommitId),
    Ledger(CommitId, u32),
}

/// Tids and commit IDs of a walk body by index: the component's things, then the other tids
/// in first use (listed after the inputs); commit IDs among the inputs' (else 0 and raw).
#[derive(Default)]
struct Dict {
    tids: HashMap<Tid, u64>,
    extra: Vec<Tid>,
    cids: HashMap<CommitId, u64>,
}

#[derive(Default)]
struct W {
    out: Vec<u8>,
    dict: Option<Dict>,
}

impl W {
    fn u8(&mut self, b: u8) {
        self.out.push(b);
    }
    fn n(&mut self, mut x: u64) {
        while x >= 0x80 {
            self.out.push((x as u8) | 0x80);
            x >>= 7;
        }
        self.out.push(x as u8);
    }
    fn len(&mut self, x: usize) {
        self.n(x as u64);
    }
    fn tid(&mut self, t: &Tid) {
        let Some(d) = &mut self.dict else { return self.out.extend_from_slice(t.as_bytes()) };
        let next = d.tids.len() as u64;
        let i = *d.tids.entry(*t).or_insert_with(|| {
            d.extra.push(*t);
            next
        });
        self.n(i);
    }
    fn cid(&mut self, c: &CommitId) {
        match self.dict.as_ref().and_then(|d| d.cids.get(c)).copied() {
            Some(i) => self.n(i + 1),
            None => {
                if self.dict.is_some() {
                    self.u8(0);
                }
                self.out.extend_from_slice(&c.0);
            }
        }
    }
    fn bool(&mut self, b: bool) {
        self.u8(u8::from(b));
    }
    fn ts(&mut self, t: Ts) {
        self.n(t.to_u64());
    }
    fn role(&mut self, r: Role) {
        self.u8(match r {
            Role::Read => 0,
            Role::Write => 1,
            Role::Admin => 2,
        });
    }
    fn opt<T>(&mut self, x: Option<T>, f: impl FnOnce(&mut W, T)) {
        match x {
            None => self.u8(0),
            Some(v) => {
                self.u8(1);
                f(self, v);
            }
        }
    }
    fn point(&mut self, p: &Point) {
        self.ts(p.ts);
        self.tid(&p.node);
        self.cid(&p.commit);
    }
    fn edge(&mut self, e: &Edge) {
        self.role(e.role);
        self.opt(e.until, |w, u| w.n(u.0));
        self.opt(e.invite, W::role);
        self.opt(e.since.as_ref(), W::point);
    }
    fn dots(&mut self, d: &Dots) {
        match d {
            Dots::Node { lo, hi } => {
                self.u8(0);
                self.n(*lo);
                self.n(*hi);
            }
            Dots::Commit => self.u8(1),
        }
    }
    fn wid(&mut self, w: &WriteId) {
        match w {
            WriteId::Op(c, k) => {
                self.u8(0);
                self.cid(c);
                self.n(u64::from(*k));
            }
            WriteId::Snapshot(c) => {
                self.u8(1);
                self.cid(c);
            }
        }
    }
    fn class(&mut self, c: Class) {
        match c {
            Class::None => self.u8(0),
            Class::Invite(r) => {
                self.u8(1);
                self.role(r);
            }
            Class::Edge => self.u8(2),
            Class::Chain => self.u8(3),
        }
    }
    fn applied(&mut self, a: &Applied) {
        self.tid(&a.author);
        self.tid(&a.target);
        self.point(&a.point);
        match a.attr {
            Attr::By(c) => {
                self.u8(0);
                self.class(c);
            }
            Attr::SelfRemoval => self.u8(1),
        }
        self.dots(&a.dots);
    }
    fn pair(&mut self, (a, b): &(Tid, Tid)) {
        self.tid(a);
        self.tid(b);
    }
    fn edges(&mut self, e: &Edges) {
        let all: Vec<_> = e.iter().collect();
        self.len(all.len());
        for (m, t, e) in all {
            self.tid(m);
            self.tid(t);
            self.edge(e);
        }
    }
    /// A frontier as the tag covers it: its sizes. Its content is fixed by the record holding
    /// it (`HeldSet`), and hashing it would cost O(frontier) per save and restore.
    fn frontier_shape(&mut self, f: &Frontier) {
        self.len(f.writes.len());
        self.len(f.writes.values().map(|a| a.values().map(BTreeMap::len).sum::<usize>()).sum());
        self.len(f.commits.len());
    }
}

/// Hashes the walk's whole input, as the tag covers it.
fn put_input(h: &mut osis_core::hash::Hasher, owners: &Owners, commits: &BTreeMap<CommitId, Arc<MembershipCommit>>, snaps: &BTreeMap<CommitId, Arc<RosterSnapshot>>) {
    let mut w = W::default();
    let mut flush = |w: &mut W| {
        h.update(&w.out);
        w.out.clear();
    };
    let links: Vec<_> = owners.links().collect();
    w.len(links.len());
    for (t, o) in links {
        w.tid(t);
        match o {
            Owner::Actor(y) => {
                w.u8(0);
                w.tid(y);
            }
            Owner::Key => w.u8(1),
        }
    }
    w.len(commits.len());
    for c in commits.values() {
        w.cid(&c.id);
        w.ts(c.ts);
        w.tid(&c.author);
        w.tid(&c.actor);
        w.opt(c.frontier.as_deref(), W::frontier_shape);
        w.len(c.ops.len());
        for o in &c.ops {
            w.tid(&o.target);
            w.tid(&o.member);
            w.opt(o.edge.as_ref(), W::edge);
            w.dots(&o.dots);
        }
        flush(&mut w);
    }
    w.len(snaps.len());
    for s in snaps.values() {
        w.cid(&s.id);
        w.ts(s.ts);
        w.tid(&s.author);
        w.tid(&s.actor);
        w.tid(&s.thing);
        w.dots(&s.dots);
        w.len(s.roster.len());
        for (m, e) in &s.roster {
            w.tid(m);
            w.edge(e);
        }
        w.len(s.ledger.len());
        for t in &s.ledger {
            w.tid(&t.member);
            w.role(t.role);
            w.opt(t.since.as_ref(), W::point);
            w.point(&t.until);
            w.opt(t.frontier.as_deref(), W::frontier_shape);
        }
        flush(&mut w);
    }
    flush(&mut w);
}

fn tag(salt: &[u8], owners: &Owners, commits: &BTreeMap<CommitId, Arc<MembershipCommit>>, snaps: &BTreeMap<CommitId, Arc<RosterSnapshot>>, body: &[u8]) -> [u8; 32] {
    let mut h = osis_core::hash::Hasher::new();
    h.update(FORMAT).update(&(salt.len() as u64).to_le_bytes()).update(salt);
    put_input(&mut h, owners, commits, snaps);
    h.update(body);
    h.finalize()
}

/// Encodes `tl`, walked over `inputs`; `None` if a frontier it holds is not in its input
/// (never, by construction).
pub(crate) fn save(inputs: &Inputs, tl: &Timeline, salt: &[u8]) -> Option<Vec<u8>> {
    // A frontier the walk holds came from the commit at its point or from a ledger entry
    // ending at it (a timeline continued over a held set handing out new Arcs holds equal
    // frontiers in other Arcs).
    let mut ledger_at: HashMap<Point, Vec<(FRef, &Arc<Frontier>)>> = HashMap::new();
    for s in tl.input.snaps.values() {
        for (i, t) in s.ledger.iter().enumerate() {
            if let Some(f) = &t.frontier {
                ledger_at.entry(t.until).or_default().push((FRef::Ledger(s.id, u32::try_from(i).ok()?), f));
            }
        }
    }
    let memo: std::cell::RefCell<HashMap<(*const Frontier, Point), FRef>> = Default::default();
    let fref = |w: &mut W, f: &Arc<Frontier>, at: &Point| -> Option<()> {
        let key = (Arc::as_ptr(f), *at);
        let got = memo.borrow().get(&key).copied();
        let r = match got {
            Some(r) => r,
            None => {
                let commit = tl.input.commits.get(&at.commit).and_then(|c| c.frontier.as_ref()).map(|g| (FRef::Commit(at.commit), g));
                let mut cands: Vec<(FRef, &Arc<Frontier>)> = commit.into_iter().chain(ledger_at.get(at).into_iter().flatten().copied()).collect();
                // one candidate: that is where it came from; else by pointer, then by value
                cands.sort_by_key(|(_, g)| !Arc::ptr_eq(g, f));
                let one = cands.len() == 1;
                let r = cands.into_iter().find(|(_, g)| one || Arc::ptr_eq(g, f) || ***g == **f)?.0;
                memo.borrow_mut().insert(key, r);
                r
            }
        };
        match r {
            FRef::Commit(c) => {
                w.u8(0);
                w.cid(&c);
            }
            FRef::Ledger(c, i) => {
                w.u8(1);
                w.cid(&c);
                w.n(u64::from(i));
            }
        }
        Some(())
    };
    let ofref = |w: &mut W, f: &Option<Arc<Frontier>>, at: &Point| -> Option<()> {
        match f {
            None => w.u8(0),
            Some(f) => {
                w.u8(1);
                fref(w, f, at)?;
            }
        }
        Some(())
    };
    let mut head = W::default();
    for set in [&inputs.0, &inputs.2] {
        head.len(set.len());
        for t in set {
            head.tid(t);
        }
    }
    head.len(inputs.1.len());
    for c in &inputs.1 {
        head.cid(c);
    }
    let tids = inputs.0.iter().enumerate().map(|(i, t)| (*t, i as u64)).collect();
    let cids = inputs.1.iter().enumerate().map(|(i, c)| (*c, i as u64)).collect();
    let mut w = W { out: Vec::new(), dict: Some(Dict { tids, extra: Vec::new(), cids }) };
    let wk = &tl.walked;
    w.edges(&wk.initial);
    w.edges(&wk.edges);
    w.len(wk.history.len());
    for c in &wk.history {
        w.point(&c.point);
        w.tid(&c.member);
        w.tid(&c.target);
        w.opt(c.edge.as_ref(), W::edge);
        match &c.explicit {
            None => w.u8(0),
            Some(f) => {
                w.u8(1);
                ofref(&mut w, f, &c.point)?;
            }
        }
        w.opt(c.audited, W::role);
    }
    w.len(wk.applied.len());
    for (id, a) in &wk.applied {
        w.wid(id);
        w.applied(a);
    }
    w.len(wk.demotions.len());
    for (k, ds) in &wk.demotions {
        w.pair(k);
        w.len(ds.len());
        for d in ds {
            w.point(&d.point);
            w.role(d.below);
            ofref(&mut w, &d.frontier, &d.point)?;
            w.bool(d.ledger);
        }
    }
    w.len(wk.falls.len());
    for (k, ps) in &wk.falls {
        w.pair(k);
        w.len(ps.len());
        for f in ps {
            w.point(&f.point);
            w.class(f.now);
            w.class(f.held);
        }
    }
    let r = &wk.rest;
    w.len(r.prior.len());
    for (k, e) in &r.prior {
        w.pair(k);
        w.edge(e);
    }
    w.len(r.dead.len());
    for k in &r.dead {
        w.pair(k);
    }
    w.len(r.prior_node.len());
    for (k, m) in &r.prior_node {
        w.pair(k);
        w.len(m.len());
        for (n, e) in m {
            w.tid(n);
            w.edge(e);
        }
    }
    w.len(r.by_author_target.len());
    for (k, v) in &r.by_author_target {
        w.pair(k);
        w.len(v.len());
        for id in v {
            w.wid(id);
        }
    }
    w.len(r.setter.len());
    for (k, id) in &r.setter {
        w.pair(k);
        w.wid(id);
    }
    w.len(r.candidates.len());
    for (c, a) in &r.candidates {
        w.cid(c);
        w.applied(a);
    }
    w.len(r.log.len());
    for u in &r.log {
        match u {
            Undo::Edge(m, t, e) => {
                w.u8(0);
                w.tid(m);
                w.tid(t);
                w.opt(e.as_ref(), W::edge);
            }
            Undo::Dead(k, on) => {
                w.u8(1);
                w.pair(k);
                w.bool(*on);
            }
            Undo::Setter(k, id) => {
                w.u8(2);
                w.pair(k);
                w.opt(id.as_ref(), W::wid);
            }
            Undo::Prior(k, e) => {
                w.u8(3);
                w.pair(k);
                w.opt(e.as_ref(), W::edge);
            }
            Undo::PriorNode(k, m) => {
                w.u8(4);
                w.pair(k);
                w.opt(m.as_ref(), |w, m| {
                    w.len(m.len());
                    for (n, e) in m {
                        w.tid(n);
                        w.edge(e);
                    }
                });
            }
            Undo::Applied(id, a) => {
                w.u8(5);
                w.wid(id);
                w.opt(a.as_ref(), W::applied);
            }
            Undo::Candidate(c, a) => {
                w.u8(6);
                w.cid(c);
                w.opt(a.as_ref(), W::applied);
            }
            Undo::ByAuthorTarget(k) => {
                w.u8(7);
                w.pair(k);
            }
            Undo::Demotion(k) => {
                w.u8(8);
                w.pair(k);
            }
            Undo::Fall(k) => {
                w.u8(9);
                w.pair(k);
            }
        }
    }
    w.len(r.marks.len());
    for (l, h) in &r.marks {
        w.len(*l);
        w.len(*h);
    }
    // D in the order the walks found it (`Rest::found`)
    w.len(r.found.len());
    for id in &r.found {
        w.wid(id);
        w.point(tl.dropped().get(id)?);
    }
    w.len(tl.epoch_starts().len());
    for (t, c) in tl.epoch_starts() {
        w.tid(t);
        w.cid(c);
    }
    w.len(tl.passes());
    w.bool(tl.epoch_changed);
    w.opt(tl.reach.as_ref(), W::point);
    let extra = w.dict.map(|d| d.extra).unwrap_or_default();
    head.len(extra.len());
    for t in &extra {
        head.tid(t);
    }
    let mut body = head.out;
    body.extend_from_slice(&w.out);
    let mut out = tag(salt, &tl.input.owners, &tl.input.commits, &tl.input.snaps, &body).to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

struct R<'a> {
    b: &'a [u8],
    /// The body's tids and commit IDs by index (`Dict`), if it uses them.
    tids: Vec<Tid>,
    cids: Vec<CommitId>,
}

impl<'a> R<'a> {
    fn plain(b: &'a [u8]) -> R<'a> {
        R { b, tids: Vec::new(), cids: Vec::new() }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.b.len() < n {
            return None;
        }
        let (a, b) = self.b.split_at(n);
        self.b = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }
    fn n(&mut self) -> Option<u64> {
        let mut x: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            x |= u64::from(b & 0x7f).checked_shl(7 * i)?;
            if b & 0x80 == 0 {
                return Some(x);
            }
        }
        None
    }
    /// A count, bounded by the bytes left (every item takes at least one).
    fn len(&mut self) -> Option<usize> {
        let n = usize::try_from(self.n()?).ok()?;
        (n <= self.b.len()).then_some(n)
    }
    fn usize(&mut self) -> Option<usize> {
        usize::try_from(self.n()?).ok()
    }
    fn raw_tid(&mut self) -> Option<Tid> {
        Some(Tid::from_bytes(self.take(15)?.try_into().ok()?))
    }
    fn raw_cid(&mut self) -> Option<CommitId> {
        Some(CommitId(self.take(32)?.try_into().ok()?))
    }
    fn tid(&mut self) -> Option<Tid> {
        let i = self.usize()?;
        self.tids.get(i).copied()
    }
    fn cid(&mut self) -> Option<CommitId> {
        match self.usize()? {
            0 => self.raw_cid(),
            i => self.cids.get(i - 1).copied(),
        }
    }
    fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    fn ts(&mut self) -> Option<Ts> {
        Ts::from_u64(self.n()?)
    }
    fn role(&mut self) -> Option<Role> {
        match self.u8()? {
            0 => Some(Role::Read),
            1 => Some(Role::Write),
            2 => Some(Role::Admin),
            _ => None,
        }
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut R<'a>) -> Option<T>) -> Option<Option<T>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(f(self)?)),
            _ => None,
        }
    }
    fn point(&mut self) -> Option<Point> {
        Some(Point { ts: self.ts()?, node: self.tid()?, commit: self.cid()? })
    }
    fn edge(&mut self) -> Option<Edge> {
        let role = self.role()?;
        let until = self.opt(|r| r.n().map(WallMs))?;
        let invite = self.opt(R::role)?;
        let since = self.opt(R::point)?;
        Some(Edge { role, until, invite, since })
    }
    fn dots(&mut self) -> Option<Dots> {
        match self.u8()? {
            0 => Some(Dots::Node { lo: self.n()?, hi: self.n()? }),
            1 => Some(Dots::Commit),
            _ => None,
        }
    }
    fn wid(&mut self) -> Option<WriteId> {
        match self.u8()? {
            0 => Some(WriteId::Op(self.cid()?, u32::try_from(self.n()?).ok()?)),
            1 => Some(WriteId::Snapshot(self.cid()?)),
            _ => None,
        }
    }
    fn class(&mut self) -> Option<Class> {
        match self.u8()? {
            0 => Some(Class::None),
            1 => Some(Class::Invite(self.role()?)),
            2 => Some(Class::Edge),
            3 => Some(Class::Chain),
            _ => None,
        }
    }
    fn applied(&mut self) -> Option<Applied> {
        let (author, target, point) = (self.tid()?, self.tid()?, self.point()?);
        let attr = match self.u8()? {
            0 => Attr::By(self.class()?),
            1 => Attr::SelfRemoval,
            _ => return None,
        };
        Some(Applied { author, target, point, attr, dots: self.dots()? })
    }
    fn pair(&mut self) -> Option<(Tid, Tid)> {
        Some((self.tid()?, self.tid()?))
    }
    fn edges(&mut self) -> Option<Edges> {
        let mut e = Edges::default();
        for _ in 0..self.len()? {
            let (m, t) = (self.tid()?, self.tid()?);
            e.set(m, t, Some(self.edge()?));
        }
        Some(e)
    }
    fn raw_tids(&mut self) -> Option<Vec<Tid>> {
        (0..self.len()?).map(|_| self.raw_tid()).collect()
    }
    fn edge_map(&mut self) -> Option<BTreeMap<Tid, Edge>> {
        (0..self.len()?).map(|_| Some((self.tid()?, self.edge()?))).collect()
    }
}

/// Saved bytes split: the tag, the inputs they were walked over, the rest of the body.
pub(crate) struct Saved<'a> {
    tag: &'a [u8],
    body: &'a [u8],
    pub inputs: Inputs,
    /// The things, then the other tids the walk names.
    tids: Vec<Tid>,
    walk: &'a [u8],
}

/// Reads what a saved walk's inputs were; `None` if the bytes do not parse so far.
pub(crate) fn parse(bytes: &[u8]) -> Option<Saved<'_>> {
    let (tag, body) = bytes.split_at_checked(32)?;
    let mut r = R::plain(body);
    let mut tids = r.raw_tids()?;
    let created = r.raw_tids()?.into_iter().collect();
    let ids = (0..r.len()?).map(|_| r.raw_cid()).collect::<Option<BTreeSet<_>>>()?;
    let things: BTreeSet<Tid> = tids.iter().copied().collect();
    tids.extend(r.raw_tids()?);
    Some(Saved { tag, body, inputs: (things, ids, created), tids, walk: r.b })
}

/// The held set of `held` restricted to `things`, the `/created` records of `created` and
/// the commits and snapshots in `ids`.
pub(crate) struct Only<'a> {
    pub held: &'a dyn HeldSet,
    pub things: &'a BTreeSet<Tid>,
    pub created: &'a BTreeSet<Tid>,
    pub ids: &'a BTreeSet<CommitId>,
}

impl HeldSet for Only<'_> {
    fn things(&self) -> Vec<Tid> {
        self.things.iter().copied().collect()
    }
    fn edge_commits(&self, thing: &Tid) -> Vec<Arc<MembershipCommit>> {
        if !self.things.contains(thing) {
            return Vec::new();
        }
        self.held.edge_commits(thing).into_iter().filter(|c| self.ids.contains(&c.id)).collect()
    }
    fn roster_snapshots(&self, thing: &Tid) -> Vec<Arc<RosterSnapshot>> {
        if !self.things.contains(thing) {
            return Vec::new();
        }
        self.held.roster_snapshots(thing).into_iter().filter(|s| self.ids.contains(&s.id)).collect()
    }
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        if self.created.contains(thing) { self.held.created(thing) } else { None }
    }
}

/// The timeline `s` saved, over `held` (a held set holding at least the saved inputs: their
/// things, `/created` records and commits): `None` unless its tag matches `salt` and the input
/// `held` gives for exactly those.
pub(crate) fn restore(s: &Saved<'_>, held: &dyn HeldSet, salt: &[u8]) -> Option<Timeline> {
    let input = Input::gather(&Only { held, things: &s.inputs.0, created: &s.inputs.2, ids: &s.inputs.1 });
    if tag(salt, &input.owners, &input.commits, &input.snaps, s.body)[..] != *s.tag {
        return None;
    }
    let mut r = R { b: s.walk, tids: s.tids.clone(), cids: s.inputs.1.iter().copied().collect() };
    let out = walk(&mut r, &input)?;
    Some(Timeline::from_outcome(input, out))
}

fn walk(r: &mut R<'_>, input: &Input) -> Option<Outcome> {
    let fref = |r: &mut R<'_>| -> Option<Arc<Frontier>> {
        match r.u8()? {
            0 => input.commits.get(&r.cid()?)?.frontier.clone(),
            1 => {
                let s = input.snaps.get(&r.cid()?)?;
                s.ledger.get(r.usize()?)?.frontier.clone()
            }
            _ => None,
        }
    };
    let ofref = |r: &mut R<'_>| -> Option<Option<Arc<Frontier>>> {
        match r.u8()? {
            0 => Some(None),
            1 => Some(Some(fref(r)?)),
            _ => None,
        }
    };
    let initial = r.edges()?;
    let edges = r.edges()?;
    let mut history = Vec::new();
    for _ in 0..r.len()? {
        let (point, member, target) = (r.point()?, r.tid()?, r.tid()?);
        let edge = r.opt(R::edge)?;
        let explicit = match r.u8()? {
            0 => None,
            1 => Some(ofref(r)?),
            _ => return None,
        };
        let audited = r.opt(R::role)?;
        history.push(Change { point, member, target, edge, explicit, audited });
    }
    let applied = (0..r.len()?).map(|_| Some((r.wid()?, r.applied()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let mut demotions = BTreeMap::new();
    for _ in 0..r.len()? {
        let k = r.pair()?;
        let mut v = Vec::new();
        for _ in 0..r.len()? {
            let (point, below) = (r.point()?, r.role()?);
            let frontier = ofref(r)?;
            v.push(Demotion { point, below, frontier, ledger: r.bool()? });
        }
        demotions.insert(k, v);
    }
    let fall = |r: &mut R| Some(Fall { point: r.point()?, now: r.class()?, held: r.class()? });
    let falls = (0..r.len()?).map(|_| Some((r.pair()?, (0..r.len()?).map(|_| fall(r)).collect::<Option<Vec<_>>>()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let prior = (0..r.len()?).map(|_| Some((r.pair()?, r.edge()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let dead = (0..r.len()?).map(|_| r.pair()).collect::<Option<BTreeSet<_>>>()?;
    let prior_node = (0..r.len()?).map(|_| Some((r.pair()?, r.edge_map()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let by_author_target = (0..r.len()?).map(|_| Some((r.pair()?, (0..r.len()?).map(|_| r.wid()).collect::<Option<Vec<_>>>()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let setter = (0..r.len()?).map(|_| Some((r.pair()?, r.wid()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let candidates = (0..r.len()?).map(|_| Some((r.cid()?, r.applied()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let mut log = Vec::new();
    for _ in 0..r.len()? {
        log.push(match r.u8()? {
            0 => Undo::Edge(r.tid()?, r.tid()?, r.opt(R::edge)?),
            1 => Undo::Dead(r.pair()?, r.bool()?),
            2 => Undo::Setter(r.pair()?, r.opt(R::wid)?),
            3 => Undo::Prior(r.pair()?, r.opt(R::edge)?),
            4 => Undo::PriorNode(r.pair()?, r.opt(R::edge_map)?),
            5 => Undo::Applied(r.wid()?, r.opt(R::applied)?),
            6 => Undo::Candidate(r.cid()?, r.opt(R::applied)?),
            7 => Undo::ByAuthorTarget(r.pair()?),
            8 => Undo::Demotion(r.pair()?),
            9 => Undo::Fall(r.pair()?),
            _ => return None,
        });
    }
    let marks = (0..r.len()?).map(|_| Some((r.usize()?, r.usize()?))).collect::<Option<Vec<_>>>()?;
    let found = (0..r.len()?).map(|_| Some((r.wid()?, r.point()?))).collect::<Option<Vec<_>>>()?;
    let dropped: BTreeMap<WriteId, Point> = found.iter().copied().collect();
    if dropped.len() != found.len() {
        return None;
    }
    let found = found.into_iter().map(|f| f.0).collect();
    let epoch_starts = (0..r.len()?).map(|_| Some((r.tid()?, r.cid()?))).collect::<Option<BTreeMap<_, _>>>()?;
    let passes = r.usize()?;
    let epoch_changed = r.bool()?;
    let reach = r.opt(R::point)?;
    if !r.b.is_empty() {
        return None;
    }
    let rest = Rest { prior, dead, prior_node, by_author_target, setter, candidates, log, marks, found };
    let walked = Walked { initial, history, edges, applied, demotions, falls, rest };
    Some(Outcome { walked, dropped, epoch_starts, passes, epoch_changed, reach, items: None, common: None })
}
