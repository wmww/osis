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

/// What a held snapshot carries, bounded (spec/crdt.md §4.7 Copies): per source, the least and
/// greatest counter of a write its held body holds valued (`Fragment::each_valued`), and apart
/// of one it holds value-less, O(sources). An honest snapshot holds an expiring write
/// value-less (§8), so its valued bound need not meet one; an expiry strips the state in place
/// only where no held snapshot's valued bound meets its writes (`meets`), else it rebuilds,
/// which finds the carriers. The value-less bound says where a cover may hold a write
/// value-less (`covered_join`: such a cover covers no body of it not held value-less here).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    valued: Hull,
    valueless: Hull,
}

/// Per source, the least and greatest counter of the writes it bounds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Hull(BTreeMap<osis_crdt::Source, (u64, u64)>);

impl Hull {
    fn add(&mut self, d: &osis_crdt::Dot) {
        let e = self.0.entry(d.src.clone()).or_insert((d.ctr, d.ctr));
        e.0 = e.0.min(d.ctr);
        e.1 = e.1.max(d.ctr);
    }
    /// Whether the bound may hold a write of `own`.
    fn meets(&self, own: &[Owned]) -> bool {
        let hull = |src: &osis_crdt::Source| self.0.get(src).copied();
        own.iter().any(|o| match o {
            Owned::Range { src, lo, hi } => hull(src).is_some_and(|(a, b)| a < *hi && *lo <= b),
            Owned::Commit(c) => hull(&osis_crdt::Source::commit(*c)).is_some(),
            Owned::Dots { src, ctrs } => hull(src).is_some_and(|(a, b)| ctrs.iter().any(|c| (a..=b).contains(c))),
        })
    }
    #[cfg(debug_assertions)]
    fn holds(&self, o: &Hull) -> bool {
        o.0.iter().all(|(s, (lo, hi))| self.0.get(s).is_some_and(|(a, b)| a <= lo && hi <= b))
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&osis_crdt::Source, &(u64, u64))> {
        self.0.iter()
    }
    pub(crate) fn of(v: impl IntoIterator<Item = (osis_crdt::Source, (u64, u64))>) -> Hull {
        Hull(v.into_iter().collect())
    }
}

impl Carried {
    /// Widens the bounds by what `f` holds, valued and value-less.
    pub(crate) fn add(&mut self, f: &Fragment) {
        f.each_valued(&mut |d| self.valued.add(d));
        let mut none = BTreeSet::new();
        f.valueless_dots(&mut none);
        none.iter().for_each(|d| self.valueless.add(d));
    }
    /// Whether the bound may hold a value of a write of `own`.
    pub(crate) fn meets(&self, own: &[Owned]) -> bool {
        self.valued.meets(own)
    }
    /// Whether the bound may hold a write of `own` value-less.
    pub(crate) fn meets_valueless(&self, own: &[Owned]) -> bool {
        self.valueless.meets(own)
    }
    /// Whether these bounds hold every write `o` bounds.
    #[cfg(debug_assertions)]
    pub(crate) fn holds(&self, o: &Carried) -> bool {
        self.valued.holds(&o.valued) && self.valueless.holds(&o.valueless)
    }
    /// The sources of its valued bound, each one entry.
    pub(crate) fn len(&self) -> usize {
        self.valued.0.len()
    }
    pub(crate) fn hulls(&self) -> (&Hull, &Hull) {
        (&self.valued, &self.valueless)
    }
    pub(crate) fn of(valued: Hull, valueless: Hull) -> Carried {
        Carried { valued, valueless }
    }
}

/// Whether a held snapshot of `(tid, ak)` may carry a value of a write of `own` (`Carried`).
pub(crate) fn carried_meets(core: &Core, tid: &Tid, ak: &Ak, own: &[Owned]) -> bool {
    core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().any(|s| s.4.meets(own))
}

/// The state of `(tid, ak)` a snapshot of it carries: this node's state with the values of
/// deltas with an expiry held value-less (spec/crdt.md §8: a snapshot never carries them, so
/// covers one only once it is held value-less, `covered`).
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
    let Some(mut st) = tx.state(tid, ak)?.cloned() else { return Ok(None) };
    if !expiring.is_empty() {
        // sorted: a lookup per dot (`sorted_owns`), not a scan of every expiring delta
        expiring.sort();
        st.strip(&|d| super::sorted_owns(&expiring, d));
    }
    Ok(Some(st))
}

/// Whether frontiers `fr` list the session of commit `c` (header `h`, a session-form commit
/// with own writes) and miss some of its counters below `hi`; `false` for others, and for a
/// session `fr` does not list: the snapshot holds no write of it (spec/crdt.md §8), so it
/// reaches none of its counters and covers what joins unchanged.
pub(super) fn unseen_by(fr: &osis_crdt::Frontiers, h: &Header, c: &CommitId, hi: u64) -> bool {
    if !h.form.counted() || !h.kind.has_own_writes() {
        return false;
    }
    let src = h.form.own_source(h.author, *c);
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
    h.form.counted() && h.kind.has_own_writes() && fr.lists(&h.form.own_source(h.author, *c)) && !unseen_by(fr, h, c, hi)
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
/// that source is not reflected. So does a body held value-less for a purge (the callers'
/// `valid_on`, `retention::held_purged`).
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

/// What delta `a` of a commit with header `h` is judged by in a purge (spec/crdt.md §8 `Facts`):
/// its purgeable-by, and its actor where that is not its author.
pub(crate) fn header_fact(h: &Header, a: &osis_commit::AspectEntry) -> osis_crdt::Fact {
    osis_crdt::Fact { by: a.retention.by, actor: (h.actor != h.author).then_some(h.actor) }
}

/// What a snapshot's `Facts` (with its `Absorbed` authors, `absorbed`) state of carried commit
/// `k` (spec/crdt.md §8): its purgeable-by and its actor, the author where the fact names none (a
/// session's node; a commit-form commit's `Absorbed` author). `None` where the snapshot names no
/// author (a commit-form commit it does not list as absorbed): it states nothing of it.
pub(crate) fn stated(facts: &osis_crdt::Facts, absorbed: &dyn Fn(&CommitId) -> Option<Tid>, k: &(Ts, osis_crdt::Source)) -> Option<(osis_base::PurgeBy, Tid)> {
    let f = facts.get(k).copied().unwrap_or(osis_crdt::Fact::NARROWEST);
    let author = match k.1.kind() {
        osis_crdt::SourceKind::Session(s) => Some(s.node),
        osis_crdt::SourceKind::Commit(c) => absorbed(c),
        osis_crdt::SourceKind::Derived(_) => None,
    };
    Some((f.by, f.actor.or(author)?))
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
        (m.header.kind.has_own_writes() && m.header.form.own_source(m.header.author, *c) == *src).then_some((*c, ai))
    })
    .collect()
}

/// The facts of the commits whose stamps `st` carries (spec/crdt.md §8 `Facts`): a held
/// commit's from its header, else as the first held valid snapshot of the aspect by `(ts, ID)`
/// carrying it states them. One neither gives (none should be) is left to `Fact::NARROWEST`.
pub(crate) fn facts_of(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, st: &Fragment) -> Result<osis_crdt::Facts> {
    let carried: BTreeSet<(Ts, osis_crdt::Source)> = st.writes().into_iter().filter_map(|(d, ts)| Some((ts?, osis_crdt::fact_source(&d.src)))).collect();
    let mut out = osis_crdt::Facts::new();
    let mut rest = BTreeSet::new();
    for (ts, src) in carried {
        let held = held_by_stamp(tx.core, tid, ak, ts, &src);
        let fact = held.first().and_then(|(c, ai)| {
            let m = tx.core.ix.commits.get(c)?;
            Some(header_fact(&m.header, m.header.aspects.get(*ai)?))
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
/// one, whose writes would go value-less here anyway; not held value-less for a purge
/// (`retention::held_purged`). The writer and the compaction trigger both ask it.
pub(crate) fn claims(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak, now: u64) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai) && (!m.missing(ai) || m.header.expires.is_some()) && !super::held_purged(core, c, tid, ak, ai, now)))
}

/// Whether a commit's own writes are judged by its ID (commit form: a snapshot lists those whose
/// writes it holds as absorbed) rather than by counters under a frontier.
pub(super) fn by_id(kind: Kind, form: Form) -> bool {
    form == Form::Commit && kind.has_own_writes()
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

/// Whether held body `f` (whole or a leftover, which keeps every reset) of a part of commit `m`
/// on `ak` stands as a whole replace (`Hold::Body::whole`): a plain durable commit's delta on an
/// own aspect replacing it whole, as apply and a load from the commit records judge it.
pub(crate) fn whole_replace(m: &crate::engine::Meta, ak: &Ak, f: &Fragment) -> bool {
    m.view.kind == Kind::Content && !m.view.memory && own_aspect(ak) && replaces(f)
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
    core.ix.own_replaces.get(&(*tid, ak.clone(), m.view.author)).is_some_and(|x| x.contains(&(m.view.ts, *s))) && m.aspect(tid, ak).is_some_and(|ai| m.valid_at(ai))
}

/// The commits own replaces `qs` (of one author on `(tid, ak)`, held here) newly let go: the
/// author's held commits older than the newest of `qs` with at most one other own replace later
/// than them, so `qs` give them their second (spec/commits.md §5 Own replaces). What a pass
/// judges when `qs` arrive or turn valid: older ones had two covers before.
pub(crate) fn own_newly_covered(core: &Core, qs: &[CommitId], tid: &Tid, ak: &Ak) -> Vec<CommitId> {
    let Some(m) = qs.first().and_then(|q| core.ix.commits.get(q)) else { return Vec::new() };
    let author = m.view.author;
    let Some(hi) = qs.iter().filter_map(|q| core.ix.commits.get(q)).map(|m| m.view.ts).max() else { return Vec::new() };
    let lo = own_replaces(core, tid, ak, &author).rev().filter(|x| !qs.contains(&x.1)).map(|x| x.0).nth(1);
    // from `lo` only: what stays under older covers (another part of it uncovered) is not walked
    let from = (lo.unwrap_or(Ts::ZERO), CommitId([0; 32]));
    core.ix.own_held.get(&(*tid, ak.clone(), author)).into_iter().flat_map(|x| x.range(from..)).take_while(|(ts, _)| *ts < hi).filter(|(_, c)| !qs.contains(c)).map(|x| x.1).collect()
}

/// The own replaces that may cover `c` on `(tid, ak)`: its author's two newest valid held
/// own replaces later than it, none for a memory commit (`covered` asks for two).
pub(crate) fn own_covers(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> Vec<CommitId> {
    let Some(m) = core.ix.commits.get(c) else { return Vec::new() };
    if m.view.memory || !own_aspect(ak) {
        return Vec::new();
    }
    let ts = m.view.ts;
    own_replaces(core, tid, ak, &m.view.author).rev().take_while(|x| x.0 > ts).take(2).map(|x| x.1).collect()
}

/// `Engine::covered` in `tx`: a plain commit `s` covers `c` only as its author's own replace
/// (spec/commits.md §5, Own replaces), with a second own replace later than `c`, so what
/// `c`'s author wrote before their last replace stays: a function of the commits held here,
/// the same at every node holding them.
pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let Some(sm) = tx.core.ix.commits.get(s) else { return covered_join(tx, s, c, tid, ak) };
    if sm.view.kind.is_compaction() {
        return covered_join(tx, s, c, tid, ak);
    }
    let (s_author, s_ts) = (sm.view.author, sm.view.ts);
    let Some(cm) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let (author, cts) = (cm.view.author, cm.view.ts);
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
/// Cost: the body and that part, about twice the body, plus the snapshot streamed once per
/// write of its record while it fits `CARRIED_MAX` (above it, once per judgment).
pub(crate) fn covered_join(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    // counted: tests read how many pairs are joined
    let _s = crate::costs::span("covered: join");
    let (Some(sai), Some(cai)) = (aspect_index(tx.core, s, tid, ak), aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2)
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) {
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
    // a memory body the snapshot's frontier (indexed) does not reach: judged before either
    // body is decoded (a memory apply weighs every held body against every held snapshot)
    if m.header.ephemeral.is_some()
        && m.header.form.counted()
        && m.header.kind.has_own_writes()
        && let Some(a) = m.header.aspects.get(cai)
        && tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().any(|x| x.1 == *s && unseen_by(&x.2, &m.header, c, a.hi))
    {
        return Ok(Some(false));
    }
    let is_snapshot = m.header.kind.is_compaction();
    let decoded = crate::apply::held_part(tx, c, cai)?;
    let body_facts = match &decoded {
        Some(osis_commit::Decoded::Snapshot(x)) => Some((x.facts.clone(), x.absorbed.clone())),
        _ => None,
    };
    let mut body: Option<Fragment> = decoded.map(osis_commit::Decoded::into_fragment);
    // a snapshot never carries an expiring delta's values (spec/crdt.md §8): held with its
    // values, the join below judges it (covered once no value of it lives); not held and not
    // value-less, the frontier alone would wrongly say covered
    if body.is_none() && m.header.aspects.get(cai).is_some_and(|_| m.header.expires.is_some()) && !super::valueless(tx.core, c, cai) {
        return Ok(Some(false));
    }
    // a valid snapshot body's copies all count (spec/permissions.md §5.2): it must carry them
    // all; an invalid one gives nothing, its copies of writes a received valid delta supplies
    // are left out
    if is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        if let Some(b) = &mut body {
            b.remove_writes(&|d| crate::apply::copies::any_delta(core, tid, ak, d, &|_, m, ai| !m.missing(ai) && m.valid_at(ai)));
        }
    }
    let held = body.is_some();
    let mut joined = Fragment::default();
    if let Some(b) = body {
        joined.join(b);
    }
    let (mut part, gives) = crate::apply::held_part_at(tx, s, sai, &joined)?;
    // counted: tests read how much of the snapshot a judgment walks
    crate::costs::count_with("covered: snapshot part bytes", || part.approx_bytes() as u64);
    // the snapshot not held: nothing is established
    let Some(g) = &gives else { return Ok(None) };
    if let Some((fr, abs, facts)) = g {
        let h = &m.header;
        // the snapshot states what a purge judges the body's writes by as the body does
        // (spec/commits.md §5 Covered): a cover never leaves another class or actor standing
        // for them where the header is not held. Judged on the commits both carry, each as
        // stated (a fact left out is the narrowest, the actor the author where it names none)
        let both: Vec<_> = if held { stamps_of(&joined).intersection(&stamps_of(&part)).cloned().collect() } else { Vec::new() };
        let cover = |k: &(Ts, osis_crdt::Source)| stated(facts, &|x| abs.iter().find(|a| a.0 == *x).map(|a| a.1), k);
        let same = match &body_facts {
            Some((bf, babs)) => both.iter().all(|k| stated(bf, &|x| babs.get(x).copied(), k) == cover(k)),
            None => {
                let k = (h.ts, h.form.own_source(h.author, *c));
                !both.contains(&k) || h.aspects.get(cai).is_none_or(|a| cover(&k) == Some((a.retention.by, h.actor)))
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
            (true, _) => !fr.lists(&h.form.own_source(h.author, *c)),
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
        let own = g.is_none();
        if own && !m.is_dropped(cai) {
            return Ok(None);
        }
        // a snapshot holding a write of the body value-less covers it only where this node
        // holds that write value-less for good (past its expiry; one with an expiry not held is
        // value-less here, above): a copy stripped for a purge that fell
        // (`purge::rejudge_purges`), or under the request still standing (it may fall, as a
        // bare leftover stays, `drops_as_covered`), or written by a node holding a request this
        // one does not, gives no value, and the body counted covered would never be fetched
        // again (spec/commits.md §5 Covered)
        if !own && !m.header.expires.is_some_and(|t| t <= tx.now().0) && holds_valueless(tx, s, sai, &super::writes_of(&m.header, c, cai), tid, ak)? {
            return Ok(Some(false));
        }
        return Ok(Some(true));
    }
    // the snapshot holds the body's live writes as the body does, judged on its part at the
    // body's positions: with its writes under the body's dots taken out and the body joined
    // back, its canonical bytes are unchanged. A copy the snapshot holds otherwise leaves the
    // body uncovered whichever wins the copy order (spec/crdt.md §4.1): the body is kept. A
    // value-less write of the body has no payload to hold: the snapshot's copy stays and the
    // join decides (a valued copy takes it).
    let before = crate::engine::state::encode(&part)?;
    let mut valueless = std::collections::BTreeSet::new();
    joined.valueless_dots(&mut valueless);
    let ix = joined.copy_index();
    part.remove_writes(&|d| ix.holds(d) && !valueless.contains(d));
    part.join(joined);
    Ok(Some(crate::engine::state::encode(&part)? == before))
}

/// Whether held snapshot `s` (part `sai` on `(tid, ak)`) holds a write of `own` value-less. Its
/// value-less bound (`Carried`) answers most without the body; where it may, the body is read.
fn holds_valueless(tx: &mut Tx<'_>, s: &CommitId, sai: usize, own: &[Owned], tid: &Tid, ak: &Ak) -> Result<bool> {
    let meets = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().find(|x| x.1 == *s).is_none_or(|x| x.4.meets_valueless(own));
    if own.is_empty() || !meets {
        return Ok(false);
    }
    // counted: tests read how often a cover's body is read for it
    let _s = crate::costs::span("covered: value-less copies");
    let mut found = false;
    crate::apply::each_held_piece(tx, s, sai, &mut |_, f| {
        let mut none = BTreeSet::new();
        f.valueless_dots(&mut none);
        found |= none.iter().any(|d| own.iter().any(|o| o.owns(d)));
        Ok(())
    })?;
    Ok(found)
}

/// Whether this node may write a snapshot of `(tid, ak)` stamped `ts` (`write::may_write`): as the
/// node that writes on the thing (`writer_for`: not one removed from its account), holding the
/// strictest role a write the snapshot carries could need (`snapshot_role`; tests may write one a
/// receiver judges invalid). `write_snapshot`'s check, so what a purge-on-replace cover asks
/// (`replace::settle_none`).
pub(crate) fn may_snapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, ts: Ts) -> Result<MayWrite> {
    // a release request is a content commit of its own (spec/wire.md §4): never compacted
    if ak.as_str() == osis_commit::retention::RELEASED {
        return Ok(MayWrite::No);
    }
    let Ok(node) = tx.core.writer_for(tid) else { return Ok(MayWrite::No) };
    let skip = tx.core.skip_writer_rules;
    let need = match (skip, memory) {
        (true, true) => None,
        (true, false) => Some(crate::engine::write::required_role(ak.as_str())),
        (false, _) => Some(crate::engine::write::snapshot_role(ak.as_str())),
    };
    crate::engine::write::may_write(tx, node, tid, ak.as_str(), need, ts)
}

/// `Engine::snapshot` in `tx` (`memory`: the aspect is ephemeral, `tx` in the memory class):
/// a snapshot of `(tid, ak)` from this node's whole state, applied here.
pub(crate) fn write_snapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool) -> Result<Option<CommitId>> {
    let (tid, ak) = (*tid, ak.clone());
    // what no write can show any more goes first, by ordinary commits of at most
    // `MAX_DELTA_BARE` content-less elements each: its bodies die and the snapshot does not
    // carry it (spec/sync.md §7)
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
        return Err(Error::Permission { tid });
    }
    let node = tx.core.writer_for(&tid)?;
    if tx.state(&tid, &ak)?.is_none() {
        return Ok(None);
    }
    let Some(st) = snapshot_state(tx, &tid, &ak)? else { return Ok(None) };
    if ak.as_str() == "secrets.0" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
        return Err(Error::Misuse("secrets.0 keys an epoch not established here (spec/crypto.md §4)"));
    }
    let now = tx.now().0;
    let valid_on = |c: &CommitId| claims(tx.core, c, &tid, &ak, now);
    // frontiers cover only counters whose writes this state reflects: applied, valid, of
    // the sessions that occur in it (spec/crdt.md §8: a session with no write left in the
    // state is pruned with them), from the held valid snapshots' frontiers on (`frontiers_now`)
    let (mut frontiers, _) = frontiers_now(tx, &tid, &ak, memory, &valid_on);
    // commit-form commits whose valid writes the state reflects
    let mut absorbed = std::collections::BTreeMap::new();
    for (_, c) in tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten() {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        if by_id(m.header.kind, m.header.form) && valid_on(c) {
            absorbed.insert(*c, m.header.author);
        }
    }
    // only sources that occur in the state (spec/crdt.md §8): a reader takes an absent
    // source as one with no write left, so a frontier never grows with sessions gone by
    let kind = if is_role_class(ak.as_str()) { Kind::RoleSnapshot } else { Kind::ContentSnapshot };
    let traced = osis_crdt::sources_of(&st, &osis_commit::writer_ctx(Form::Commit, kind, ts, node, 0, 0))?;
    frontiers.retain(&traced);
    absorbed.retain(|c, _| traced.contains(&osis_crdt::Source::commit(*c)));
    let facts = facts_of(tx, &tid, &ak, &st)?;
    let retention = osis_commit::retention::snapshot_retention(ak.as_str());
    let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false, rotation: None };
    let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, replaces: None, frontiers: Some((frontiers, absorbed, facts)), chunks: Vec::new() };
    build_and_apply(tx, plan, vec![d]).map(Some)
}

impl Engine {
    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from what this node applied (`frontiers_now`). On a `+` aspect a memory commit. `None`: no state to snapshot (a signal
    /// has none).
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        // the role timeline walks every edge write (spec/commits.md §2)
        if ak.as_str() == "roles.0" {
            return Err(Error::Misuse("roles.0 is never compacted"));
        }
        if ak.as_str() == "created.0" {
            return Err(Error::Misuse("created.0 is never compacted"));
        }
        if ak.as_str() == osis_commit::retention::RELEASED {
            return Err(Error::Misuse("released.0 is never compacted"));
        }
        // the judgment reads every addendum delta (spec/permissions.md §5.2)
        if osis_schema::core_types::is_addenda(ak.as_str()) {
            return Err(Error::Misuse("addenda.0 is never compacted"));
        }
        // a signal holds no state: nothing to snapshot (spec/sync.md §7)
        if ak.signal() {
            return Ok(None);
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

    /// Writes a memory snapshot of `(tid, ak)` carrying only the join of this node's own unsent
    /// plain commits `ids` on it (spec/commits.md §2, the coalescing snapshot): its frontier
    /// reaches the last of their counters, so it covers exactly them (and nothing another
    /// session wrote, which joining would change). One entry goes up per round trip instead of
    /// one per write; the covered commits are forgotten here at once (`drop_covered`) and never
    /// uploaded. `None` when nothing of them is held, or the aspect keeps them while live.
    pub fn coalesce(&mut self, tid: &Tid, ak: &Ak, ids: &[CommitId]) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        // kept while live (spec/commits.md §5): the snapshot would drop none of them
        if super::history::of(&self.core, &tid, &ak).live_until() > self.now().0 {
            return Ok(None);
        }
        let ids = ids.to_vec();
        self.run(|tx| {
            tx.set_memory();
            let node = tx.core.writer_for(&tid)?;
            let ts = tx.core.hlc.next();
            let own = osis_crdt::Source::session(tx.core.session);
            let mut st: Option<Fragment> = None;
            let mut hi = 0u64;
            for c in &ids {
                let Some(m) = tx.core.ix.commits.get(c).cloned() else { continue };
                let Some(ai) = m.aspect(&tid, &ak).filter(|ai| m.holds(*ai)) else { continue };
                if m.header.form != Form::Session(tx.core.session.nonce) || m.header.aspects.get(ai).is_some_and(|_| m.header.expires.is_some()) {
                    return Err(Error::Misuse("coalescing takes this session's plain commits"));
                }
                hi = hi.max(m.header.aspects.get(ai).map_or(0, |a| a.hi));
                if let Some(f) = crate::apply::held_fragment(tx, c, ai)? {
                    st.get_or_insert_with(Fragment::default).join(f);
                }
            }
            let Some(st) = st else { return Ok(None) };
            let kind = if is_role_class(ak.as_str()) { Kind::RoleSnapshot } else { Kind::ContentSnapshot };
            let traced = osis_crdt::sources_of(&st, &osis_commit::writer_ctx(Form::Commit, kind, ts, node, 0, 0))?;
            let mut frontiers = Frontiers::default();
            if hi > 1 {
                frontiers.insert(&own, hi - 1);
            }
            frontiers.retain(&traced);
            let facts = facts_of(tx, &tid, &ak, &st)?;
            let retention = osis_commit::retention::snapshot_retention(ak.as_str());
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false, rotation: None };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, replaces: None, frontiers: Some((frontiers, std::collections::BTreeMap::new(), facts)), chunks: Vec::new() };
            build_and_apply(tx, plan, vec![d]).map(Some)
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
        self.run(|tx| {
            let r = covered(tx, &s, &c, &tid, &ak)?;
            #[cfg(test)]
            if tx.core.ix.commits.get(&s).is_some_and(|m| m.view.kind.is_compaction()) {
                let w = crate::costs::paused(|| oracle::covered(tx, &s, &c, &tid, &ak))?;
                assert_eq!(r, w, "covered streamed vs whole");
            }
            Ok(r)
        })
    }
}
