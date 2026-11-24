//! Compaction snapshots (spec/commits.md §2, §5, spec/crdt.md §8): writing one, the bounds it
//! carries, and the covered test.

use super::aspect_index;
#[cfg(test)]
use super::oracle;
use crate::engine::write::{CommitPlan, MayWrite, Resolved, build_and_apply};
use crate::engine::{Engine, Owned, Tx, Core};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{Form, Header, Kind};
use osis_crdt::{Fragment, Frontiers};
use osis_schema::core_types::{is_content, is_role_class};
use std::collections::{BTreeMap, BTreeSet};

/// What a held snapshot carries (spec/crdt.md §4.7 Gone writes, spec/permissions.md §5.2 Copies): per
/// source, the counters of the writes its held body holds (`Fragment::write_ranges`), and of
/// those it holds valued (`Fragment::each_valued`). The commits it carries copies
/// of are the held ones whose counters on the aspect meet a write (`carried`, `carriers`): what
/// the body holds, never what its frontiers or `Absorbed` claim (spec/crdt.md §8). An honest
/// snapshot holds no write of an expiring delta (§8); one holding a write gone here is held as its
/// leftover (`meets`). The value-less counters say where a cover holds a write value-less
/// (`covered_join`: such a cover covers no body of it not gone here).
///
/// Memory: one `(lo, hi)` per run of consecutive counters of a source, in each of the three: a
/// session writing the aspect alone is one run however many writes the body holds of it; one
/// writing other aspects between is a run per stretch, at most one per commit carried.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    writes: Spans,
    valued: Spans,
}

/// Per source, counters as runs `lo..hi`: ascending, disjoint, none adjacent to the next.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Spans(BTreeMap<osis_crdt::Source, Vec<(u64, u64)>>);

impl Spans {
    /// Adds counters `lo..hi` of `src`, joined with the runs they meet or touch.
    fn add(&mut self, src: &osis_crdt::Source, lo: u64, hi: u64) {
        if lo >= hi {
            return;
        }
        let v = self.0.entry(src.clone()).or_default();
        let (from, to) = (v.partition_point(|r| r.1 < lo), v.partition_point(|r| r.0 <= hi));
        let run = v.get(from..to).into_iter().flatten().fold((lo, hi), |(a, b), r| (a.min(r.0), b.max(r.1)));
        v.splice(from..to, [run]);
    }
    fn add_dot(&mut self, d: &osis_crdt::Dot) {
        self.add(&d.src, d.ctr, d.ctr.saturating_add(1));
    }
    /// Whether a counter of `src` in `lo..hi` is here.
    fn meets(&self, src: &osis_crdt::Source, lo: u64, hi: u64) -> bool {
        self.0.get(src).is_some_and(|v| v.get(v.partition_point(|r| r.1 <= lo)).is_some_and(|r| r.0 < hi))
    }
    /// Whether a write of `own` is here.
    fn meets_owned(&self, own: &[Owned]) -> bool {
        own.iter().any(|o| match o {
            Owned::Range { src, lo, hi } => self.meets(src, *lo, *hi),
            Owned::Commit(c) => self.0.contains_key(&osis_crdt::Source::commit(*c)),
            Owned::Dots { src, ctrs } => ctrs.iter().any(|c| self.meets(src, *c, c.saturating_add(1))),
        })
    }
    #[cfg(debug_assertions)]
    fn holds(&self, o: &Spans) -> bool {
        o.entries().all(|(s, lo, hi)| self.0.get(s).is_some_and(|v| v.get(v.partition_point(|r| r.1 <= lo)).is_some_and(|r| r.0 <= lo && hi <= r.1)))
    }
    /// Its runs: (source, lo, hi).
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&osis_crdt::Source, u64, u64)> {
        self.0.iter().flat_map(|(s, v)| v.iter().map(move |(lo, hi)| (s, *lo, *hi)))
    }
    pub(crate) fn of(v: impl IntoIterator<Item = (osis_crdt::Source, u64, u64)>) -> Spans {
        let mut out = Spans::default();
        v.into_iter().for_each(|(s, lo, hi)| out.add(&s, lo, hi));
        out
    }
}

impl Carried {
    /// Adds what `f` holds: every write, and those valued.
    pub(crate) fn add(&mut self, f: &Fragment) {
        f.write_ranges(&mut |src, lo, hi| self.writes.add(src, lo, hi));
        f.each_valued(&mut |d| self.valued.add_dot(d));
    }
    /// Whether it holds a write of `own`.
    pub(crate) fn meets(&self, own: &[Owned]) -> bool {
        self.writes.meets_owned(own)
    }
    /// Whether it holds every write `o` does, and every one `o` holds valued.
    #[cfg(debug_assertions)]
    pub(crate) fn holds(&self, o: &Carried) -> bool {
        self.writes.holds(&o.writes) && self.valued.holds(&o.valued)
    }
    /// Whether it holds the writes `o` does: the commits carried are the same.
    pub(crate) fn same_writes(&self, o: &Carried) -> bool {
        self.writes == o.writes
    }
    /// The runs of its writes (its memory: the valued runs lie within them).
    pub(crate) fn len(&self) -> usize {
        self.writes.0.values().map(Vec::len).sum()
    }
    /// Its writes, and those valued.
    pub(crate) fn spans(&self) -> [&Spans; 2] {
        [&self.writes, &self.valued]
    }
    pub(crate) fn of([writes, valued]: [Spans; 2]) -> Carried {
        Carried { writes, valued }
    }
}

/// The held commits held snapshot `s` of `(tid, ak)` carries copies of (spec/permissions.md §5.2
/// Copies: a list naming `s` names them): those with a delta on the aspect whose counters meet a
/// write its held body holds, found per run in `ix.ranges`, no body read; none while its body is
/// not held (no row). A void commit is carried by none: the walk reads nothing of it, and the
/// other commits of a source have disjoint counters on an aspect (spec/commits.md §4), so the
/// one holding a run's first counter is the last starting at or below it.
pub(crate) fn carried(core: &Core, s: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
    let Some(row) = core.ix.snapshots.get(&(*tid, ak.clone())).and_then(|v| v.iter().find(|x| x.1 == *s)) else { return Vec::new() };
    let zero = CommitId([0; 32]);
    let mut out = Vec::new();
    for (src, runs) in &row.4.writes.0 {
        match src.kind() {
            osis_crdt::SourceKind::Commit(c) => out.extend(core.ix.commits.get(c).filter(|m| by_id(m.view.kind, m.view.form) && m.view.aspect(tid, ak.as_str()).is_some()).map(|_| *c)),
            osis_crdt::SourceKind::Session(_) => {
                let Some(m) = core.ix.ranges.get(&(*tid, ak.clone(), src.clone())) else { continue };
                for (lo, hi) in runs {
                    let before = m.range(..(*lo, zero)).next_back().filter(|(_, end)| **end > *lo);
                    out.extend(before.into_iter().chain(m.range((*lo, zero)..(*hi, zero))).map(|((_, c), _)| *c));
                }
            }
            osis_crdt::SourceKind::Derived(_) => {}
        }
    }
    out.retain(|c| c != s && !core.ix.void.contains(c));
    osis_base::costs::count("snapshot: carried commits", out.len() as u64);
    out
}

/// The held snapshots' parts carrying commit `c` (view `v`, held or about to be): `carried` from
/// the commit's side, per aspect of it a lookup in each held snapshot's writes.
pub(crate) fn carriers(core: &Core, c: &CommitId, v: &crate::engine::View) -> Vec<osis_perm::WriteId> {
    if !v.kind.has_own_writes() || core.ix.void.contains(c) {
        return Vec::new();
    }
    let src = v.form.own_source(v.signer, *c);
    let mut out = Vec::new();
    for a in &v.aspects {
        let meets = |w: &Spans| if v.form.counted() { a.lo < a.hi && w.meets(&src, a.lo, a.hi) } else { by_id(v.kind, v.form) && w.0.contains_key(&src) };
        for x in core.ix.snapshots.get(&(a.tid, a.ak.clone())).into_iter().flatten().filter(|x| x.1 != *c && meets(&x.4.writes)) {
            out.extend(core.ix.commits.get(&x.1).and_then(|m| m.view.aspect(&a.tid, a.ak.as_str())).map(|sai| osis_perm::WriteId(x.1, sai as u32)));
        }
    }
    out
}

/// Whether a held snapshot of `(tid, ak)` may carry a write of `own` (`Carried`).
pub(crate) fn carried_meets(core: &Core, tid: &Tid, ak: &Ak, own: &[Owned]) -> bool {
    core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().any(|s| s.4.meets(own))
}

/// The state of `(tid, ak)` a snapshot of it carries: this node's state without every write whose
/// lifetime ends (spec/crdt.md §4.7, §8: an unexpiring snapshot carries no write of a delta with
/// an expiry, nor one it holds only from an expiring snapshot, so its copy never outlives the
/// write; so it covers no such delta, nor what only those writes superseded, `covered`).
pub(crate) fn snapshot_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
    let mut expiring: Vec<Owned> = tx
        .core
        .ix
        .by_aspect
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        .filter_map(|(_, c)| {
            let m = tx.core.ix.commits.get(c)?;
            let ai = m.aspect(tid, ak)?;
            m.header.aspects.get(ai)?;
            m.header.expires?;
            Owned::of(&m.header, c, ai)
        })
        .collect();
    // values held from an expiring snapshot alone (a holder granted without history holds no
    // delta of them): its copies end at its expiry (spec/crdt.md §4.7)
    expiring.extend(expiring_copies(tx, tid, ak)?.into_values().flatten());
    let Some(mut st) = tx.state(tid, ak)?.cloned() else { return Ok(None) };
    if !expiring.is_empty() {
        // sorted: a lookup per dot (`sorted_owns`), not a scan of every expiring delta
        expiring.sort();
        expiring.dedup();
        st.remove_gone(&|d| super::sorted_owns(&expiring, d));
    }
    Ok(Some(st))
}

/// The bodies of `(tid, ak)` held here, valid, whose values live and end at an expiry still ahead,
/// by that expiry: each as the writes whose values it gives (spec/crdt.md §4.7, §8): a delta's own
/// writes, and `expiring_copies`.
pub(crate) fn expiring_carriers(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<u64, Vec<Owned>>> {
    let now = tx.now().0;
    let mut out = expiring_copies(tx, tid, ak)?;
    for (_, c) in tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        let Some(ai) = m.aspect(tid, ak) else { continue };
        let Some(t) = m.header.expires.filter(|t| *t > now && !m.header.kind.is_compaction()) else { continue };
        if live_valued(tx.core, c, ai) {
            out.entry(t).or_default().extend(Owned::of(&m.header, c, ai));
        }
    }
    Ok(out)
}

/// Whether part `ai` of held commit `c` is held with its values, valid.
fn live_valued(core: &Core, c: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.holds(ai) && !m.own_gone(ai) && m.valid_at(ai) && !super::is_gone(core, c, ai))
}

/// The valued copies of the expiring snapshots of `(tid, ak)` held here, valid, by their expiry
/// still ahead, as exact dots (they have no writes of their own): of the writes this node knows
/// no other lifetime of. Reads the aspect's snapshots alone. Invariant: an expiring snapshot's
/// expiry is any writer's claim, so it decides only for a value held from expiring snapshots
/// alone: a write whose own delta's header is held ends as that delta does, and one a lasting
/// body holds valued lasts (else a forged expiring snapshot ends a lasting value, or extends an
/// expiring one, in what an honest node writes from it: its snapshots, its undo).
pub(crate) fn expiring_copies(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<BTreeMap<u64, Vec<Owned>>> {
    let now = tx.now().0;
    // each held valid snapshot with its values: its expiry, if any
    let snaps: Vec<(CommitId, usize, Option<u64>)> = tx
        .core
        .ix
        .snapshots
        .get(&(*tid, ak.clone()))
        .into_iter()
        .flatten()
        .filter_map(|x| {
            let m = tx.core.ix.commits.get(&x.1)?;
            let ai = m.aspect(tid, ak)?;
            let t = m.header.expires;
            (t.is_none_or(|t| t > now) && live_valued(tx.core, &x.1, ai)).then_some((x.1, ai, t))
        })
        .collect();
    let mut out: BTreeMap<u64, Vec<Owned>> = BTreeMap::new();
    if snaps.iter().all(|x| x.2.is_none()) {
        return Ok(out);
    }
    let mut lasting: BTreeSet<(osis_crdt::Source, u64)> = BTreeSet::new();
    let mut expiring: Vec<(u64, Fragment)> = Vec::new();
    for (s, ai, t) in snaps {
        crate::apply::each_held_piece(tx, &s, ai, &mut |_, f| {
            match t {
                Some(t) => expiring.push((t, f)),
                None => f.each_valued(&mut |d| {
                    lasting.insert((d.src.clone(), d.ctr));
                }),
            }
            Ok(())
        })?;
    }
    let mut dots: BTreeMap<u64, BTreeMap<osis_crdt::Source, BTreeSet<u64>>> = BTreeMap::new();
    for (t, f) in &expiring {
        f.each_valued(&mut |d| {
            if tx.core.write_expiry(tid, ak, d).is_none() && !lasting.contains(&(d.src.clone(), d.ctr)) {
                dots.entry(*t).or_default().entry(d.src.clone()).or_default().insert(d.ctr);
            }
        });
    }
    for (t, by) in dots {
        out.insert(t, by.into_iter().map(|(src, ctrs)| Owned::Dots { src, ctrs: ctrs.into_iter().collect() }).collect());
    }
    Ok(out)
}

/// State at a cut (spec/crypto.md §4), beside the snapshot from this node's whole state, which
/// carries every expiring value value-less: for each expiry still ahead of a body of `owed`
/// holding values, a snapshot expiring then, carrying of this node's state the writes whose values
/// the bodies ending then give (`expiring_carriers`), valued (spec/crdt.md §8). It ends with them
/// at every node, read or not, so a holder granted without history reads each value while it
/// lives and never after. Its tables claim nothing (frontiers 0, nothing absorbed): it carries
/// part of the state. The snapshots written.
pub(crate) fn write_expiring(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, owed: &BTreeSet<CommitId>) -> Result<Vec<CommitId>> {
    let carriers = expiring_carriers(tx, tid, ak)?;
    if carriers.is_empty() {
        return Ok(Vec::new());
    }
    let due: BTreeSet<u64> = owed.iter().filter_map(|c| tx.core.ix.commits.get(c).and_then(|m| m.header.expires)).filter(|t| carriers.contains_key(t)).collect();
    let node = tx.core.writer_for(tid)?;
    // every carried write, sorted (`sorted_owns`: a lookup per dot); the state cut to them once,
    // so each expiry's part is cut from those writes alone, not from the whole state again
    let sorted = |mut v: Vec<Owned>| {
        v.sort();
        v.dedup();
        v
    };
    let all = sorted(due.iter().filter_map(|t| carriers.get(t)).flatten().cloned().collect());
    let Some(mut rest) = tx.state(tid, ak)?.cloned() else { return Ok(Vec::new()) };
    rest.remove_writes(&|d| !super::sorted_owns(&all, d));
    let mut out = Vec::new();
    for t in due {
        let Some(own) = carriers.get(&t).cloned().map(sorted) else { continue };
        // stamped at or past its expiry (this node's clock ahead of its wall clock: a peer's
        // fast clock read), a snapshot ending then is invalid (spec/commits.md §6) and its value
        // has ended by the writer's clock: none is written, so its copy never outlives the value
        let ts = tx.core.hlc.next();
        if t <= ts.wall_ms().0 {
            continue;
        }
        let mut part = rest.clone();
        part.remove_writes(&|d| !super::sorted_owns(&own, d));
        // canonical form (`remove_writes` leaves it to a join)
        let mut f = Fragment::default();
        f.join(part);
        let mut any = false;
        f.each_valued(&mut |_| any = true);
        if !any {
            continue;
        }
        out.push(build_snapshot(tx, *tid, ak.clone(), f, ts, node, Frontiers::default(), Default::default(), Some(t), false)?);
    }
    Ok(out)
}

/// Whether frontiers `fr` list the session of commit `c` (header `h`, a session-form commit
/// with own writes) and miss some of its counters below `hi`; `false` for others, and for a
/// session `fr` does not list: the snapshot holds no write of it and its writer held no commit of
/// it holding a part (spec/crdt.md §8), so it reaches none of its counters and covers what joins
/// unchanged.
pub(super) fn unseen_by(fr: &osis_crdt::Frontiers, h: &Header, c: &CommitId, hi: u64) -> bool {
    if !h.form.counted() || !h.kind.has_own_writes() {
        return false;
    }
    let src = h.form.own_source(h.signer, *c);
    fr.lists(&src) && fr.of(&src).saturating_add(1) < hi
}

/// Whether a snapshot's tables `(fr, abs)` show it holds what of commit `c`'s own writes in the
/// aspect was live to its writer (header `h`, part counters below `hi`; spec/crdt.md §8): its
/// session listed up to them, or the commit absorbed. An unlisted one is not reached: the tables
/// cannot tell a commit whose writes all died from one the writer never applied. A commit with
/// an expiry is never reached: a snapshot carries its values value-less.
pub(crate) fn reaches((fr, abs): (&Frontiers, &[(CommitId, Tid)]), h: &Header, c: &CommitId, hi: u64) -> bool {
    if h.expires.is_some() {
        return false;
    }
    if by_id(h.kind, h.form) {
        return abs.iter().any(|x| x.0 == *c);
    }
    h.form.counted() && h.kind.has_own_writes() && fr.lists(&h.form.own_source(h.signer, *c)) && !unseen_by(fr, h, c, hi)
}

/// The frontiers a snapshot of `(tid, ak)` built now carries, and the session-form commits
/// they reflect (spec/crdt.md §8: up to the largest counter below which this node applied every
/// write of the source on the aspect). Per source: from the held valid snapshots' frontiers on
/// (their writes are in this state; the commits they covered may be forgotten with their
/// counters, spec/commits.md §5 Forgetting), the held valid commits in counter order while they
/// join without a hole. A held valid own whole replace of the source's author (`own_replace`)
/// passes a hole below it: its reset drops every earlier write of the author's session on the
/// aspect (spec/crdt.md §1), so those writes are applied as dead, whether held, forgotten under
/// own replaces, or never received. An invalid or missing body stops its source's frontier below
/// it (the snapshot does not carry its writes, so it must not claim them), and what follows in
/// that source is not reflected (the callers' `valid_on`).
pub(crate) fn frontiers_now(tx: &Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, valid_on: &dyn Fn(&CommitId) -> bool) -> (Frontiers, BTreeSet<CommitId>) {
    frontiers_upto(tx, tid, ak, memory, valid_on, None)
}

/// `frontiers_now`, walking only the sources `upto` names, each no further than the commit at
/// the counter it gives (the compaction trigger asks whether its candidates are reflected, and
/// walks no source past them). With `upto`, the frontiers are partial.
pub(crate) fn frontiers_upto(tx: &Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, valid_on: &dyn Fn(&CommitId) -> bool, upto: Option<&BTreeMap<osis_crdt::Source, u64>>) -> (Frontiers, BTreeSet<CommitId>) {
    let mut frontiers = Frontiers::default();
    let mut reflected = BTreeSet::new();
    for (_, s, fr, _, _) in tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten() {
        if valid_on(s) {
            for (src, f) in fr.sources() {
                if f > frontiers.of(&src) {
                    frontiers.insert(&src, f);
                }
            }
        }
    }
    let from = (*tid, ak.clone(), osis_crdt::Source::session(osis_crdt::Session { node: Tid::from_bytes([0; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }));
    for ((_, _, n), ranges) in tx.core.ix.ranges.range(from..).take_while(|((t, a, _), _)| t == tid && a == ak) {
        let max = match upto {
            Some(u) => match u.get(n) {
                Some(m) => *m,
                None => continue,
            },
            None => u64::MAX,
        };
        let (next, _) = walk_source(valid_on, &|c| !memory && own_replace(tx.core, c, tid, ak), ranges.iter(), frontiers.of(n).saturating_add(1), max, &mut |c| {
            reflected.insert(c);
        });
        if next > 1 {
            frontiers.insert(n, next - 1);
        }
    }
    (frontiers, reflected)
}

/// One session source's frontier walk on `(tid, ak)` (`frontiers_upto`), from `next`, its first
/// counter not reflected, through `ranges` (its held ranges by start, `Indexes::ranges`, from
/// any start on) up to start `max`: a range below `next` is reflected (by a snapshot's
/// frontier); one that joins (starts at or below `next`, or `resets` passes it: a durable own
/// whole replace, whose reset passes a hole below it) and that `valid_on` passes is reflected and moves `next`
/// past it; the first other stops the walk. `reflected` gets each one reflected. Returns `next`
/// and whether a range stopped the walk (the source has held ranges behind a gap at `next`).
pub(crate) fn walk_source<'r>(valid_on: &dyn Fn(&CommitId) -> bool, resets: &dyn Fn(&CommitId) -> bool, ranges: impl Iterator<Item = (&'r (u64, CommitId), &'r u64)>, mut next: u64, max: u64, reflected: &mut dyn FnMut(CommitId)) -> (u64, bool) {
    for ((lo, c), hi) in ranges {
        if *lo > max {
            break;
        }
        // below a snapshot's frontier: reflected by it
        if *hi <= next {
            reflected(*c);
            continue;
        }
        let joins = *lo <= next || resets(c);
        if !joins || !valid_on(c) {
            return (next, true);
        }
        next = *hi;
        reflected(*c);
    }
    (next, false)
}

/// What delta `a` of a commit with view `v` is judged by in a purge (spec/crdt.md §8 `Facts`):
/// its purge-by, and its purge author where that is not its signer.
pub(crate) fn header_fact(v: &crate::engine::View, a: &osis_commit::AspectEntry) -> osis_crdt::Fact {
    osis_crdt::Fact { by: a.purge_by, purge_author: v.other_purge_author() }
}

/// What a snapshot's `Facts` (with its `Absorbed` signers, `absorbed`) state of carried commit
/// `k` (spec/crdt.md §8): its purge-by and its purge author, the signer where the fact names
/// none (a session's tid; a commit-form commit's `Absorbed` signer). `None` where the snapshot
/// names no signer (a commit-form commit it does not list as absorbed): it states nothing of it.
pub(crate) fn stated(facts: &osis_crdt::Facts, absorbed: &dyn Fn(&CommitId) -> Option<Tid>, k: &(Ts, osis_crdt::Source)) -> Option<(osis_base::PurgeBy, Tid)> {
    let f = facts.get(k).copied().unwrap_or(osis_crdt::Fact::NARROWEST);
    let signer = match k.1.kind() {
        osis_crdt::SourceKind::Session(s) => Some(s.node),
        osis_crdt::SourceKind::Commit(c) => absorbed(c),
        osis_crdt::SourceKind::Derived(_) => None,
    };
    Some((f.by, f.purge_author.or(signer)?))
}

/// The carried commits `(ts, origin source)` whose writes `f` holds.
fn stamps_of(f: &Fragment) -> BTreeSet<(Ts, osis_crdt::Source)> {
    f.writes().into_iter().filter_map(|(d, ts)| Some((ts?, osis_crdt::fact_source(&d.src)))).collect()
}

/// The held commit on `(tid, ak)` stamped `ts` whose own writes are `src`'s (spec/crdt.md §2.1:
/// one commit per `ts` and source on an aspect; equivocating ones are all held), with its
/// aspect index.
pub(crate) fn held_by_stamp(core: &Core, tid: &Tid, ak: &Ak, ts: Ts, src: &osis_crdt::Source) -> Vec<(CommitId, usize)> {
    let lo = (ts, CommitId([0; 32]));
    let hi = (ts, CommitId([0xff; 32]));
    let on = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flat_map(|s| s.range(lo..=hi));
    on.filter_map(|(_, c)| {
        let m = core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        (m.header.kind.has_own_writes() && m.header.form.own_source(m.header.signer, *c) == *src).then_some((*c, ai))
    })
    .collect()
}

/// The facts of the commits whose stamps `st` carries (spec/crdt.md §8 `Facts`): a held
/// commit's from its header, else as the first held valid snapshot of the aspect by `(ts, ID)`
/// carrying it states them. One neither gives (none should be) is left to `Fact::NARROWEST`.
pub(crate) fn facts_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, st: &Fragment) -> Result<osis_crdt::Facts> {
    let carried = stamps_of(st);
    let mut out = osis_crdt::Facts::new();
    let mut rest = BTreeSet::new();
    for (ts, src) in carried {
        let held = held_by_stamp(tx.core, tid, ak, ts, &src);
        let fact = held.first().and_then(|(c, ai)| {
            let m = tx.core.ix.commits.get(c)?;
            Some(header_fact(&m.view, m.header.aspects.get(*ai)?))
        });
        match fact {
            Some(f) => {
                out.insert((ts, src), f);
            }
            None => {
                rest.insert((ts, src));
            }
        }
    }
    let snaps: Vec<CommitId> = if rest.is_empty() { Vec::new() } else { tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).collect() };
    for s in snaps {
        if rest.is_empty() {
            break;
        }
        let Some(sai) = super::held_part(tx.core, &s, tid, ak) else { continue };
        if !crate::apply::copies::snapshot_valid(tx.core, &s, tid, ak) {
            continue;
        }
        let mut part = Fragment::default();
        let Some(Some((_, _, facts))) = crate::apply::each_held_piece(tx, &s, sai, &mut |_, f| {
            part.join(f);
            Ok(())
        })?
        else {
            continue;
        };
        // a commit it carries with no fact left out is stated the narrowest
        let carries = stamps_of(&part);
        rest.retain(|k| {
            if !carries.contains(k) {
                return true;
            }
            out.insert(k.clone(), facts.get(k).copied().unwrap_or(osis_crdt::Fact::NARROWEST));
            false
        });
    }
    #[cfg(test)]
    if let Some(lie) = &tx.core.lie_facts {
        out.extend(lie.clone());
    }
    out.retain(|_, f| *f != osis_crdt::Fact::NARROWEST);
    Ok(out)
}

/// Whether a snapshot of `(tid, ak)` written now at wall ms `now` claims the writes of `c`'s part
/// (`frontiers_now`'s walk passes it, `Absorbed` lists it): valid here; held, as a part still
/// missing gives the state nothing (applied without it, spec/commits.md §4), but an expiring
/// one, whose writes would go here anyway. A part gone for a purge is
/// claimed: the snapshot carries its writes value-less, and no node counts a body it lacks
/// covered by a value-less copy (`covered_join`), so a fall of the purge brings it back. The
/// writer and the compaction trigger both ask it.
pub(crate) fn claims(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && (!m.missing(ai) || m.header.expires.is_some())))
}

/// Whether a commit's own writes are judged by its ID (commit form: a snapshot lists those whose
/// writes it holds as absorbed) rather than by counters under a frontier.
pub(super) fn by_id(kind: Kind, form: Form) -> bool {
    form == Form::Commit && kind.has_own_writes()
}

/// Whether snapshot `s` may cover body `c` by their expiries (spec/commits.md §5 Covered): a
/// lasting one any; an expiring one, whose copies end at its expiry, sooner than another body's
/// may, only an expiring snapshot ending then (so each cut's expiring snapshots replace the last
/// cut's: one per expiry and aspect stays).
pub(crate) fn expiry_covers(core: &Core, s: &CommitId, c: &CommitId) -> bool {
    let ends = |x: &CommitId| core.ix.commits.get(x).and_then(|m| m.header.expires.filter(|_| m.header.kind.is_compaction()));
    ends(s).is_none_or(|t| ends(c) == Some(t))
}

/// Whether `c` is a compaction snapshot stamped later than `s`.
pub(super) fn stamped_later(core: &Core, c: &CommitId, s: &CommitId) -> bool {
    let ts = |x: &CommitId| core.ix.commits.get(x).map(|m| m.view.ts);
    core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction()) && ts(c) > ts(s)
}

/// Whether `ak` is an aspect its author's own replaces may cover: content, neither ephemeral
/// nor a signal (spec/commits.md §5 Own replaces).
pub(crate) fn own_aspect(ak: &Ak) -> bool {
    is_content(ak.as_str()) && !ak.ephemeral() && !ak.signal()
}

/// Whether fragment `f` is a delta replacing the aspect whole: its root reset, or a register
/// write, which implies one (spec/crdt.md §5.1).
pub(crate) fn replaces(f: &Fragment) -> bool {
    f.reset().is_some() || matches!(f, Fragment::Register(_) | Fragment::Slots(_))
}

/// Whether held body `f` of a part of commit `m` on `ak` stands as a whole replace
/// (`Hold::Body::whole`): a plain durable commit's delta with no expiry (its writes go at T,
/// spec/crdt.md §4.7, so it covers nothing) on an own aspect replacing it whole, as apply and a
/// load from the commit records judge it.
pub(crate) fn whole_replace(m: &crate::engine::Meta, ak: &Ak, f: &Fragment) -> bool {
    m.view.kind == Kind::Content && !m.view.memory && m.header.expires.is_none() && own_aspect(ak) && replaces(f)
}

/// `author`'s valid own replaces of `(tid, ak)` held here, oldest first.
fn own_replaces<'c>(core: &'c Core, tid: &Tid, ak: &Ak, author: &Tid) -> impl DoubleEndedIterator<Item = (Ts, CommitId)> + 'c {
    let (tid, ak2) = (*tid, ak.clone());
    core.ix
        .own_replaces
        .get(&(tid, ak2.clone(), *author))
        .into_iter()
        .flatten()
        .filter(move |(_, c)| core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak2).is_some_and(|ai| m.valid_at(ai))))
        .copied()
}

/// Whether held commit `s` stands as an own replace of `(tid, ak)` (spec/commits.md §5 Own
/// replaces): a plain whole replace of its author, valid here.
pub(crate) fn own_replace(core: &Core, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    let Some(m) = core.ix.commits.get(s) else { return false };
    core.ix.own_replaces.get(&(*tid, ak.clone(), m.view.signer)).is_some_and(|x| x.contains(&(m.view.ts, *s))) && m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai))
}

/// The own replaces that may cover `c` on `(tid, ak)`: its author's two newest valid held
/// own replaces later than it, none for a memory commit (`covered` asks for two).
pub(crate) fn own_covers(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
    let Some(m) = core.ix.commits.get(c) else { return Vec::new() };
    if m.view.memory || !own_aspect(ak) {
        return Vec::new();
    }
    let ts = m.view.ts;
    own_replaces(core, tid, ak, &m.view.signer).rev().take_while(|x| x.0 > ts).take(2).map(|x| x.1).collect()
}

/// Whether `s` drops held body `c` as its cover: `covered`, but of two covered-equal snapshots only
/// the higher commit ID goes (spec/sync-compaction.md §1).
pub(crate) fn drops_under(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<bool> {
    if covered(tx, s, c, tid, ak)? != Some(true) {
        return Ok(false);
    }
    let snapshot = tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction());
    Ok(!(snapshot && c < s && covered(tx, c, s, tid, ak)? == Some(true)))
}

/// `Engine::covered` in `tx`: a plain commit `s` covers `c` only as its author's own replace
/// (spec/commits.md §5, Own replaces), with a second own replace later than `c`, so what
/// `c`'s author wrote before their last replace stays: a function of the commits held here,
/// the same at every node holding them. A memo (`Core::covers`): sync's judgement of a body asks
/// it per snapshot of its aspects at every rerun, and a join reads both bodies.
pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let key = (*s, *c, *tid, ak.clone());
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.covers, &key, |tx| covered_read(tx, &key.0, &key.1, &key.2, &key.3))
}

/// `covered` read anew.
fn covered_read(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let Some(sm) = tx.core.ix.commits.get(s) else { return covered_join(tx, s, c, tid, ak) };
    if sm.view.kind.is_compaction() {
        return covered_join(tx, s, c, tid, ak);
    }
    let (s_author, s_ts) = (sm.view.signer, sm.view.ts);
    let Some(cm) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let (author, cts) = (cm.view.signer, cm.view.ts);
    let may = own_replace(tx.core, s, tid, ak) && s_author == author && s_ts > cts && !cm.view.memory && cm.view.kind == Kind::Content;
    if !may {
        return Ok(Some(false));
    }
    match covered_join(tx, s, c, tid, ak)? {
        Some(true) => {}
        other => return Ok(other),
    }
    let Some(second) = own_replaces(tx.core, tid, ak, &author).rev().take_while(|x| x.0 > cts).map(|x| x.1).find(|x| x != s) else { return Ok(Some(false)) };
    covered_join(tx, &second, c, tid, ak)
}

/// The body whole against the snapshot's part at the body's positions (`apply::held_part_at`).
/// Cost: the body and that part, about twice the body, plus the snapshot's root and the pages
/// at the body's positions (`PageIndex`, kept per write of its record): flat in the snapshot's
/// size past one page.
pub(crate) fn covered_join(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    // counted: tests read how many pairs are joined
    let _s = osis_base::costs::span("covered: join");
    let (Some(sai), Some(cai)) = (aspect_index(tx.core, s, tid, ak), aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2); an expiring
    // one only what ends with it (`expiry_covers`)
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) || !expiry_covers(tx.core, s, c) {
        return Ok(Some(false));
    }
    // a snapshot stamped later settles the suspect flags of more commits than this one
    // (`receipt::settled`), and dropped as covered it would stop: never covered by one stamped
    // earlier
    if stamped_later(tx.core, c, s) {
        return Ok(Some(false));
    }
    // a snapshot body still to arrive (or missing again, `uncover`): nothing is established
    // without its content (a delta's frontier or absorbed check below stands alone)
    if tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction() && m.missing(cai)) {
        return Ok(None);
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    // a memory body not held that the snapshot's frontier (indexed) does not reach: judged
    // before the snapshot is read, as below. A held body is judged by the join alone: a
    // snapshot whose writer held it behind a gap in its session carries its writes past its
    // own frontier, and saying otherwise here breaks the chain of covers (`retention::coverers`) a node
    // with the body dropped judges by (a holder places it again, every pass, for that node to
    // delete)
    if !m.holds(cai)
        && m.header.ephemeral.is_some()
        && m.header.form.counted()
        && m.header.kind.has_own_writes()
        && let Some(a) = m.header.aspects.get(cai)
        && tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().any(|x| x.1 == *s && unseen_by(&x.2, &m.header, c, a.hi))
    {
        return Ok(Some(false));
    }
    let is_snapshot = m.header.kind.is_compaction();
    // a valid snapshot body's copies all count (spec/permissions.md §5.2): it must carry them
    // all; an invalid one gives nothing, its copies of writes a received valid delta supplies
    // are left out
    let strip = is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak);
    let body = covered_body(tx, s, sai, c, cai, strip, tid, ak)?;
    let (held, gives) = (body.held, body.gives);
    let body_facts = body.facts;
    // counted: tests read how much of the snapshot a judgment walks
    osis_base::costs::count("covered: snapshot part bytes", body.part_bytes);
    // a snapshot never carries an expiring delta's values (spec/crdt.md §8): held with its
    // values, the join below judges it (covered once no value of it lives); not held and not
    // value-less, the frontier alone would wrongly say covered
    if !held && m.header.aspects.get(cai).is_some_and(|_| m.header.expires.is_some()) && !super::is_gone(tx.core, c, cai) {
        return Ok(Some(false));
    }
    // the snapshot not held: nothing is established
    let Some(g) = &gives else { return Ok(None) };
    if let Some((fr, abs, facts)) = g {
        let h = &m.header;
        // the snapshot states what a purge judges the body's writes by as the body does
        // (spec/commits.md §5 Covered): a cover never leaves another class or actor standing
        // for them where the header is not held. Judged on the commits both carry, each as
        // stated (a fact left out is the narrowest, the actor the author where it names none)
        let both: Vec<_> = if held { body.stamps.intersection(&body.part_stamps).cloned().collect() } else { Vec::new() };
        let cover = |k: &(Ts, osis_crdt::Source)| stated(facts, &|x| abs.iter().find(|a| a.0 == *x).map(|a| a.1), k);
        let same = match &body_facts {
            Some((bf, babs)) => both.iter().all(|k| stated(bf, &|x| babs.get(x).copied(), k) == cover(k)),
            None => {
                let k = (h.ts, h.form.own_source(h.signer, *c));
                !both.contains(&k) || h.aspects.get(cai).is_none_or(|a| cover(&k) == Some((a.purge_by, m.view.purge_author)))
            }
        };
        if held && !same {
            return Ok(Some(false));
        }
        // a held body is judged by the join below whatever the tables say; its session listed
        // short of it only says what the writer had applied, and the writer may never get it
        if !held && h.aspects.get(cai).is_some_and(|a| unseen_by(fr, h, c, a.hi)) {
            return Ok(Some(false));
        }
        // the snapshot holds nothing of the body's session or commit (spec/crdt.md §8): its
        // writes are dead where the body is held and joins unchanged (below); a body not held
        // here establishes nothing, as the writer may never have applied it.
        let untraced = match (h.form.counted() && h.kind.has_own_writes(), by_id(h.kind, h.form)) {
            (true, _) => !fr.lists(&h.form.own_source(h.signer, *c)),
            (_, true) => !abs.iter().any(|x| x.0 == *c),
            _ => false,
        };
        if untraced && m.missing(cai) {
            return Ok(None);
        }
    }
    // a body this node holds no delta of (dropped at its keep bounds or as covered, a purge
    // rewrite) joins nothing: covered. Before an own replace the part must really have
    // dropped: a part not fetched yet is not established (a set add or map put still to come).
    if !held {
        if g.is_none() && !m.is_dropped(cai) {
            return Ok(None);
        }
        return Ok(Some(true));
    }
    // the snapshot holds the body's live writes as the body does, judged on its part at the
    // body's positions: with its writes under the body's dots taken out and the body joined
    // back, its canonical bytes are unchanged (`covered_body`, a group of pieces at a time). A
    // copy the snapshot holds otherwise leaves the body uncovered whichever wins the copy order
    // (spec/crdt.md §4.1): the body is kept.
    Ok(Some(body.unchanged))
}

/// What `covered_join` reads of body `c` (part `cai`) against snapshot `s` (part `sai`).
struct CoveredBody {
    held: bool,
    /// The snapshot's frontiers, `Absorbed` and facts (`held_part_at`); `None`: not held.
    gives: Option<Option<crate::engine::Gives>>,
    /// A snapshot body's facts and `Absorbed`.
    facts: Option<(osis_crdt::Facts, BTreeMap<CommitId, Tid>)>,
    /// The stamps of the body's writes, and of the snapshot's at the body's positions.
    stamps: BTreeSet<(Ts, osis_crdt::Source)>,
    part_stamps: BTreeSet<(Ts, osis_crdt::Source)>,
    part_bytes: u64,
    /// Some group was judged.
    judged: bool,
    /// The snapshot's part at the body's positions, its writes under the body's dots taken
    /// out (but value-less ones) and the body joined back, encodes as before.
    unchanged: bool,
}

/// Reads body `c` a piece at a time (`each_held_piece`; `strip`: an invalid snapshot's copies
/// of what a valid delta supplies taken out): its writes by dot, value-less ones and stamps,
/// then judges it against the snapshot's part at its positions (`held_part_at`) in groups of
/// its pages, each with its skeleton (where pages meet: their paths' records and resets), so a
/// judgment holds the skeleton and pages of about the two parts' root bytes, not the body.
/// Positions join independently (spec/crdt.md §4.1), so the groups' judgments are the whole
/// body's. A body that fits one group is read once.
#[allow(clippy::too_many_arguments)]
fn covered_body(tx: &mut Tx<'_>, s: &CommitId, sai: usize, c: &CommitId, cai: usize, strip: bool, tid: &Tid, ak: &Ak) -> Result<CoveredBody> {
    let root = |tx: &mut Tx<'_>, x: &CommitId, ai: usize| -> Result<usize> { Ok(tx.get_commit(x)?.and_then(|b| b.part(ai).map(|p| p.delta.len())).unwrap_or(0)) };
    let room = root(tx, s, sai)?.saturating_add(root(tx, c, cai)?);
    let mut out = CoveredBody { held: false, gives: None, facts: None, stamps: BTreeSet::new(), part_stamps: BTreeSet::new(), part_bytes: 0, judged: false, unchanged: true };
    let mut ix = osis_crdt::CopyIndex::default();
    let mut skeleton: Option<Fragment> = None;
    // the body joined while it fits one group
    let (mut whole, mut size, mut fits, mut whole_only) = (Fragment::default(), 0usize, true, false);
    let read = |tx: &mut Tx<'_>, mut f: Fragment| {
        if strip {
            let core = &*tx.core;
            f.remove_writes(&|d| crate::apply::copies::any_delta(core, tid, ak, d, &|_, m, ai| !m.missing(ai) && m.valid_at(ai)));
        }
        f
    };
    let body_gives = crate::apply::each_held_page(tx, c, cai, None, &mut |tx, p| {
        let f = match p {
            osis_crdt::Piece::Skeleton(f) => f,
            osis_crdt::Piece::Page { path, fragment, .. } => {
                // a page below a map entry meets the snapshot's whole record there
                // (`Fragment::positions_at`), every page of it: judged in one group
                whole_only |= path.iter().any(|s| matches!(s, osis_crdt::Step::Entry(_)));
                fragment
            }
        };
        let f = read(tx, f);
        ix.extend(f.copy_index());
        out.stamps.extend(stamps_of(&f));
        // the skeleton, in every group, counts in none
        if skeleton.is_none() {
            skeleton = Some(f.clone());
        } else {
            size = size.saturating_add(f.approx_bytes());
        }
        if fits {
            whole.join(f);
            fits = whole_only || size <= room;
            if !fits {
                whole = Fragment::default();
            }
        }
        Ok(())
    })?;
    out.held = body_gives.is_some();
    out.facts = body_gives.flatten().map(|(_, abs, facts)| (facts, abs.into_iter().collect()));
    let judge = |tx: &mut Tx<'_>, out: &mut CoveredBody, group: Fragment| -> Result<()> {
        let (mut part, gives) = crate::apply::held_part_at(tx, s, sai, &group)?;
        osis_base::costs::peak("covered: body group held", group.approx_bytes() as u64);
        out.part_bytes = out.part_bytes.saturating_add(part.approx_bytes() as u64);
        out.part_stamps.extend(stamps_of(&part));
        if !std::mem::replace(&mut out.judged, true) {
            out.gives = gives;
        }
        let before = crate::engine::state::encode(&part)?;
        part.remove_writes(&|d| ix.holds(d));
        part.join(group);
        out.unchanged &= crate::engine::state::encode(&part)? == before;
        Ok(())
    };
    if fits {
        judge(tx, &mut out, whole)?;
        return Ok(out);
    }
    let skeleton = skeleton.unwrap_or_default();
    let (mut group, mut size, mut first) = (skeleton.clone(), 0usize, true);
    crate::apply::each_held_piece(tx, c, cai, &mut |tx, f| {
        // the skeleton heads every group
        if std::mem::take(&mut first) {
            return Ok(());
        }
        let f = read(tx, f);
        size = size.saturating_add(f.approx_bytes());
        group.join(f);
        if size > room {
            judge(tx, &mut out, std::mem::replace(&mut group, skeleton.clone()))?;
            size = 0;
        }
        Ok(())
    })?;
    if size > 0 || !out.judged {
        judge(tx, &mut out, group)?;
    }
    Ok(out)
}

/// Whether the state of `(tid, ak)` holds a live write of a node `of` picks that stands only
/// through a cover: a session write of such a node, or a commit-form write, whose commit is not
/// held here (forgotten under a cover, or never received: a snapshot carried it here; a
/// commit-form write's author is unknown without its header, so any such write counts). What a
/// removal's frontier can no longer name by ID (spec/permissions.md §5.1, §5.5 Own cover). Only
/// writes stamped from `since` on (or whose stamp the state does not carry). Read only where a
/// cover can stand for a commit: a forgotten one noted, or a snapshot held.
pub(crate) fn carried_only(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, of: &dyn Fn(&Tid) -> bool, since: Option<Ts>) -> Result<bool> {
    let k = (*tid, ak.clone());
    if !tx.core.ix.forgotten.contains_key(&k) && tx.core.ix.snapshots.get(&k).is_none_or(|v| v.is_empty()) {
        return Ok(false);
    }
    let live = tx.state(tid, ak)?.map(|st| st.live_writes()).unwrap_or_default();
    Ok(live.iter().filter(|(_, ts)| since.is_none_or(|s| ts.is_none_or(|ts| ts >= s))).any(|(d, ts)| match d.src.kind() {
        // a session write's own commit is the held one of its stamp (spec/crdt.md §2.1)
        osis_crdt::SourceKind::Session(s) => of(&s.node) && ts.is_none_or(|ts| held_by_stamp(tx.core, tid, ak, ts, &osis_crdt::fact_source(&d.src)).is_empty()),
        osis_crdt::SourceKind::Commit(c) => !tx.core.ix.commits.contains_key(c),
        osis_crdt::SourceKind::Derived(_) => false,
    }))
}

/// Whether this node may write a snapshot of `(tid, ak)` stamped `ts` (`write::may_write`): as the
/// node that writes on the thing (`writer_for`: not one removed from its account), holding the
/// strictest role a write the snapshot carries could need (`snapshot_role`; tests may write one a
/// receiver judges invalid). `write_snapshot`'s check, so what a purge-on-replace cover asks
/// (`replace::settle_none`).
pub(crate) fn may_snapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, ts: Ts) -> Result<MayWrite> {
    let Ok(node) = tx.core.writer_for(tid) else { return Ok(MayWrite::No) };
    if is_content(ak.as_str()) && !carried_passes_on(tx, tid, ak)? || !carried_lasts(tx, tid, ak)? {
        return Ok(MayWrite::Later);
    }
    let skip = tx.core.skip_writer_rules;
    let need = match (skip, memory) {
        (true, true) => None,
        (true, false) => Some(crate::engine::write::required_role(ak.as_str())),
        (false, _) => Some(crate::engine::write::snapshot_role(ak.as_str())),
    };
    crate::engine::write::may_write(tx, node, tid, ak.as_str(), need, ts)
}

/// Whether every write a snapshot of `(tid, ak)` would carry from a held body may go under this
/// node's epoch (`sync_ids::opened::passes_on`): a write it read only under an epoch not
/// established here waits for that epoch (its withheld removal arriving) or stays uncompacted.
/// A body none of whose writes lives in the state gives the snapshot nothing (spec/crypto.md §5
/// Passing on binds the writes a snapshot carries): a writer granted later holds the maker's
/// first writes under epochs it reads but never establishes (derived from the maker's account
/// root), and their replacement leaves them nothing to pass on. A snapshot carries state, not
/// the commits: the floor clause binds it not, so one written after a cut carries the state
/// written before it to the cut's holder (spec/crypto.md §4, State at a cut).
pub(crate) fn carried_passes_on(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<bool> {
    let held: Vec<(CommitId, usize)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|(_, c)| {
        let m = tx.core.ix.commits.get(c)?;
        let ai = m.aspect(tid, ak)?;
        matches!(m.hold(ai), Some(crate::engine::Hold::Body { .. } | crate::engine::Hold::Leftover { .. })).then_some((*c, ai))
    }).collect();
    for (c, ai) in held {
        if !crate::sync_ids::opened::passes_on(tx, &c, ai, tid, ak.as_str(), None)? && super::bounds::live(tx, &c, ai)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether every held body of `(tid, ak)` whose writes live in the state stands as it will once
/// every head of its account closes (`signing::lasts`, spec/permissions.md §5.5 Carrying): a
/// snapshot carries nothing that counts only at an open head, so it never lends a write a
/// standing the write lacks. Woken when a standing moves (`replace::standing_moved`).
pub(crate) fn carried_lasts(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<bool> {
    let held: Vec<(CommitId, usize)> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter_map(|(_, c)| {
        let m = tx.core.ix.commits.get(c)?;
        m.view.epoch?;
        let ai = m.aspect(tid, ak)?;
        matches!(m.hold(ai), Some(crate::engine::Hold::Body { .. } | crate::engine::Hold::Leftover { .. })).then_some((*c, ai))
    }).collect();
    for (c, ai) in held {
        if !crate::flows::signing::lasts(tx, &c)? && super::bounds::live(tx, &c, ai)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `Engine::snapshot` in `tx` (`memory`: the aspect is ephemeral, `tx` in the memory class):
/// a snapshot of `(tid, ak)` from this node's whole state, applied here.
pub(crate) fn write_snapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool) -> Result<Option<CommitId>> {
    snapshot_from_state(tx, tid, ak, memory, false)
}

/// This node's own cover of durable `(tid, ak)` at a removal (spec/permissions.md §5.1, Own
/// cover): `write_snapshot` marked so (spec/wire.md §4 field 17).
pub(crate) fn write_own_cover(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
    snapshot_from_state(tx, tid, ak, false, true)
}

/// `write_snapshot`, an own cover when `own_cover`.
fn snapshot_from_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, own_cover: bool) -> Result<Option<CommitId>> {
    let (tid, ak) = (*tid, ak.clone());
    // what no write can show any more goes first, by ordinary commits of at most
    // `MAX_DELTA_BARE` content-less elements each: its bodies die and the snapshot does not
    // carry it (spec/sync-compaction.md §1)
    let probe = osis_crdt::Stamp::new(Default::default(), osis_crdt::Source::commit(CommitId([0; 32])), 1);
    let mut last = None;
    while !memory && osis_schema::core_types::is_content(ak.as_str()) {
        let Some(sweep) = crate::engine::write::sweep_of(tx, &tid, &ak, &probe)? else { break };
        // each commit takes what it sweeps for good (`sweep_laws`): never loop on one
        if last.as_ref() == Some(&sweep) {
            return Err(Error::Misuse("a sweep commit took nothing"));
        }
        let mut m = crate::engine::write::Mutation::new();
        m.sweep(tid, ak.clone(), tx.core.schemas.get(ak.as_str()).cloned());
        crate::engine::write::commit_in(tx, m)?;
        last = Some(sweep);
    }
    let ts = tx.core.hlc.next();
    if may_snapshot(tx, &tid, &ak, memory, ts)? != MayWrite::Yes {
        return Err(Error::Permission { tid, needs: osis_base::Role::Write });
    }
    let node = tx.core.writer_for(&tid)?;
    if tx.state(&tid, &ak)?.is_none() {
        return Ok(None);
    }
    let Some(mut st) = snapshot_state(tx, &tid, &ak)? else { return Ok(None) };
    let left_out = if ak.as_str() == "secrets.0" { crate::apply::keys::vouched_only(tx.core, &tid, &mut st)? } else { Default::default() };
    let valid_on = |c: &CommitId| claims(tx.core, c, &tid, &ak);
    // frontiers cover only counters whose writes this state reflects: applied, valid, from the
    // held valid snapshots' frontiers on (`frontiers_now`); `build_snapshot` lists the sessions
    // occurring in it and those of the commits held (spec/crdt.md §8)
    let (frontiers, _) = frontiers_now(tx, &tid, &ak, memory, &valid_on);
    // commit-form commits whose valid writes the state reflects, every one (none left out)
    let mut absorbed = std::collections::BTreeMap::new();
    for (_, c) in tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten() {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        if by_id(m.header.kind, m.header.form) && valid_on(c) && !left_out.contains(c) {
            absorbed.insert(*c, m.header.signer);
        }
    }
    build_snapshot(tx, tid, ak, st, ts, node, frontiers, absorbed, None, own_cover).map(Some)
}

/// Writes and applies by `node` at `ts` the snapshot of `(tid, ak)` carrying `st`, its tables
/// listing the sources that occur in `st` and those of the commits this node holds with a part
/// on the aspect (`held_sources`, spec/crdt.md §8: so a covered part stays reached by the
/// snapshot covering its cover, while no source outlives the commits held), with the facts of
/// the commits it carries, expiring at `expires` (an expiring snapshot, `write_expiring`), an own
/// cover when `own_cover` (`write_own_cover`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_snapshot(tx: &mut Tx<'_>, tid: Tid, ak: Ak, st: Fragment, ts: Ts, node: Tid, mut frontiers: Frontiers, mut absorbed: std::collections::BTreeMap<CommitId, Tid>, expires: Option<u64>, own_cover: bool) -> Result<CommitId> {
    let kind = if is_role_class(ak.as_str()) { Kind::RoleSnapshot } else { Kind::ContentSnapshot };
    let mut listed = osis_crdt::sources_of(&st, &osis_commit::writer_ctx(Form::Commit, kind, ts, node, 0, 0))?;
    let held = held_sources(tx.core, &tid, &ak);
    for src in &held {
        if src.as_session().is_some() && !frontiers.lists(src) {
            frontiers.insert(src, 0);
        }
    }
    listed.extend(held);
    frontiers.retain(&listed);
    absorbed.retain(|c, _| listed.contains(&osis_crdt::Source::commit(*c)));
    let facts = facts_of(tx, &tid, &ak, &st)?;
    let purge_by = osis_commit::retention::snapshot_purge_by(ak.as_str());
    let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires, restores: false, rotation: None, reseal: None, own_cover, adminless: false };
    let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, purge_by: Some(purge_by), expires, replaces: None, original_floor: 0, frontiers: Some((frontiers, absorbed, facts)), chunks: Vec::new() };
    build_and_apply(tx, plan, vec![d])
}

/// The own sources of the commits held with a part on `(tid, ak)` that still hold some part
/// (whatever this one's validity or whether its body is held): what a snapshot of the aspect lists
/// beside the sources occurring in it (spec/crdt.md §8). A commit holding nothing (every part
/// dropped) is no new reader's to count: its record alone stays no source, so a steady aspect's
/// tables hold steady across sessions (notes/growth.md). Cost: per commit on the aspect, its
/// parts up to the first held.
fn held_sources(core: &Core, tid: &Tid, ak: &Ak) -> BTreeSet<osis_crdt::Source> {
    let on = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten();
    on.filter_map(|(_, c)| {
        let m = core.ix.commits.get(c).filter(|m| (0..m.view.aspects.len()).any(|ai| m.holds(ai)))?;
        let h = &m.header;
        (h.kind.has_own_writes() && (h.form.counted() || by_id(h.kind, h.form))).then(|| h.form.own_source(h.signer, *c))
    })
    .collect()
}

/// Whether `ak` is ever compacted (spec/commits.md §2): not role-class, `created.0`,
/// `addenda.0` or a signal (no state).
pub(crate) fn compacted(ak: &Ak) -> bool {
    let a = ak.as_str();
    !is_role_class(a) && a != "created.0" && !osis_schema::core_types::is_addenda(a) && !ak.signal()
}

/// The re-snapshot owed on `(tid, ak)` (`Indexes::resnapshots_owed`), in `tx`: one this node may
/// write only later (its minting or delete keys are not here) stays owed, waiting with the
/// purge-on-replace covers for what moves that (`replace::await_cover`, `wake_covers`); else it is
/// owed no more, and where this node may write it writes a snapshot from its whole state unless it
/// holds a valid snapshot the purge left whole covering every named body it had applied
/// (spec/commits.md §5 Purge). The write's error, if it failed (it then leaves nothing).
fn owed_resnapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<Error>> {
    let Some(held) = tx.core.ix.resnapshots_owed.get(tid).and_then(|m| m.get(ak)).cloned() else { return Ok(None) };
    let memory = ak.ephemeral();
    let ts = tx.core.hlc.peek();
    let may = may_snapshot(tx, tid, ak, memory, ts)?;
    if may == MayWrite::Later {
        super::replace::await_cover(tx.core, tid);
        return Ok(None);
    }
    tx.core.ix.resnapshots_owed.remove(tid, ak);
    tx.txn.remove_local(&crate::engine::records::aspect_key(crate::engine::records::RESNAPSHOTS_OWED, tid, ak), osis_store::Shred::No)?;
    if may == MayWrite::No {
        return Ok(None);
    }
    // a snapshot the purge stripped goes at sources (`snapshot_first`): only a whole, valid one
    // carries (and with no named body applied here, it alone decides); and one under an epoch of
    // at least the floor this node seals under (0 where its actor was never cut): what a holder
    // granted without history reads (spec/crypto.md §4, State at a cut)
    let floor = tx.core.seal_epoch(tid).map_or(0, |x| x.1);
    let mut snaps = Vec::new();
    for s in tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|x| x.1).filter(|s| super::bounds::valid_snapshot_held(tx.core, s, tid, ak)).collect::<Vec<_>>() {
        let ai = tx.core.ix.commits.get(&s).and_then(|m| m.aspect(tid, ak));
        let reads = floor == 0 || match ai {
            Some(ai) => crate::sync_ids::opened::part_floor(tx, &s, ai, tid)?.is_some_and(|f| f >= floor),
            None => false,
        };
        if reads {
            snaps.push(s);
        }
    }
    'snaps: for s in &snaps {
        for b in &held {
            if covered(tx, s, b, tid, ak)? != Some(true) {
                continue 'snaps;
            }
        }
        return Ok(None);
    }
    // a holder granted without history holds none of the expiring bodies below its floor: their
    // values go beside the snapshot, in snapshots ending with them (`write_expiring`)
    Ok(tx
        .step(crate::engine::Step::Resnapshot, |tx| {
            tx.in_class(memory, |tx| {
                write_snapshot(tx, tid, ak, memory)?;
                if floor > 0 {
                    write_expiring(tx, tid, ak, &held)?;
                }
                Ok(())
            })
        })
        .err())
}

impl Engine {
    /// Writes the re-snapshots owed after purge requests (`Indexes::resnapshots_owed`) that are
    /// due (`Core::resnapshots_due`), each in a transaction of its own (`owed_resnapshot`): it
    /// carries the purged writes value-less, so a node that never held them reads as this one
    /// once it holds it; duplicates from several writers are harmless (spec/sync-compaction.md §1). Each
    /// aspect whose snapshot failed, with why.
    pub fn purge_resnapshots(&mut self) -> Result<Vec<(Tid, Ak, Error)>> {
        let mut due = std::mem::take(&mut self.core.resnapshots_due);
        let mut refused = Vec::new();
        while let Some((t, a)) = due.pop_first() {
            match self.run(|tx| owed_resnapshot(tx, &t, &a)) {
                Ok(Some(e)) => refused.push((t, a, e)),
                Ok(None) => {}
                Err(e) => {
                    due.insert((t, a));
                    self.core.resnapshots_due.extend(due);
                    return Err(e);
                }
            }
        }
        Ok(refused)
    }
}

impl Engine {
    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from what this node applied (`frontiers_now`). On a `+` aspect a memory commit. `None`: no state to snapshot (a signal
    /// has none).
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        // the role timeline walks every edge write (spec/commits.md §2)
        if osis_schema::core_types::never_compacted(ak.as_str()) {
            return Err(Error::Misuse("roles.0 is never compacted"));
        }
        if ak.as_str() == "created.0" {
            return Err(Error::Misuse("created.0 is never compacted"));
        }
        // the judgment reads every addendum delta (spec/permissions.md §5.2)
        if osis_schema::core_types::is_addenda(ak.as_str()) {
            return Err(Error::Misuse("addenda.0 is never compacted"));
        }
        // a signal holds no state: nothing to snapshot (spec/sync-compaction.md §1)
        if ak.signal() {
            return Ok(None);
        }
        #[cfg(test)]
        if self.core.snapshot_fault.as_ref() == Some(&(tid, ak.clone())) {
            return Err(Error::Crdt(osis_crdt::Error::Mismatch("snapshot fault")));
        }
        // an ephemeral aspect's snapshot is a memory commit (spec/commits.md §2)
        let memory = ak.ephemeral();
        self.run(|tx| {
            if memory {
                tx.set_memory();
            }
            write_snapshot(tx, &tid, &ak, memory)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, whatever its tables say, and the snapshot holds each live write of the body
    /// with the body's payload where the body's write has one. A body not held here: covered, unless the snapshot's
    /// frontier lists its session short of its counters, so a body dropped here as covered past
    /// a gap reads uncovered from then on (`Dropped::covered_by` keeps what covered it), or the
    /// snapshot holds a write of it value-less that this node does not hold so for good (past
    /// its expiry). A snapshot
    /// covers none stamped later, nor, purging on replace, a live body that keeps history. `None` when either is not
    /// held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.read(|tx| {
            let r = covered(tx, &s, &c, &tid, &ak)?;
            #[cfg(test)]
            if tx.core.ix.commits.get(&s).is_some_and(|m| m.view.kind.is_compaction()) {
                let w = osis_base::costs::paused(|| oracle::covered(tx, &s, &c, &tid, &ak))?;
                assert_eq!(r, w, "covered streamed vs whole");
            }
            Ok(r)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Spans;
    use osis_crdt::{Session, Source};

    // spec/permissions.md §5.2 Copies: a snapshot carries exactly the commits whose counters meet
    // a write its body holds, so runs join where they meet or touch and keep every gap.
    #[test]
    fn runs_keep_their_gaps() {
        let (a, b) = (Source::session(Session::from_bytes(&[1; 31])), Source::session(Session::from_bytes(&[2; 31])));
        let s = Spans::of([(a.clone(), 5, 7), (a.clone(), 1, 3), (a.clone(), 3, 4), (a.clone(), 9, 10), (b.clone(), 4, 5), (a.clone(), 6, 9)]);
        assert_eq!(s.entries().map(|(x, lo, hi)| (x == &a, lo, hi)).collect::<Vec<_>>(), [(true, 1, 4), (true, 5, 10), (false, 4, 5)]);
        for (lo, hi, want) in [(0, 1, false), (0, 2, true), (4, 5, false), (3, 5, true), (4, 6, true), (10, 20, false), (9, 10, true)] {
            assert_eq!(s.meets(&a, lo, hi), want, "{lo}..{hi}");
        }
        assert!(!s.meets(&b, 3, 4) && s.meets(&b, 4, 5) && !s.meets(&b, 5, 6));
    }
}
