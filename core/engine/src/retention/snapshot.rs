//! Compaction snapshots (spec/commits.md §2, §5, spec/crdt.md §8): writing one, the bounds it
//! carries, and the covered test.

use super::aspect_index;
#[cfg(test)]
use super::oracle;
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Engine, Owned, Tx, Core};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid};
use osis_commit::{Form, Header, Kind};
use osis_crdt::{Fragment, Frontiers};
use osis_schema::core_types::is_role_class;
use std::collections::BTreeSet;

/// The state of memory aspect `(tid, ak)` a snapshot of it carries: rebuilt without the
/// expiring deltas (an expiring memory write vanishes whole at T, spec/crdt.md §4.7: no
/// snapshot carries it, nor counts it received, so it goes from every holder alike).
pub(crate) fn memory_state(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
    let expiring: Vec<(CommitId, Owned)> = tx
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
            Some((*c, Owned::of(&m.header, c, ai)?))
        })
        .collect();
    let gone: Vec<Owned> = expiring.iter().map(|x| x.1.clone()).collect();
    let skip: BTreeSet<CommitId> = expiring.iter().map(|x| x.0).collect();
    Ok(crate::apply::rebuilt(tx, tid, ak, &gone, &skip, None)?.0)
}

/// The retentions standing for the writes snapshot state `st` of `(tid, ak)` carries live
/// (spec/commits.md §5): each write's own delta (spec/permissions.md §5.2: the session-form delta
/// whose counter range holds it, the commit-form commit it names); for writes whose own delta's header is not held, the held snapshot bodies of
/// the aspect carrying them, and for any of those none carries, every snapshot of the aspect
/// applied here. Cost: a lookup and a header per live write; the aspect's headers (and its held
/// snapshot bodies) only when some write's own commit is not found directly.
fn own_retentions(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, st: &Fragment) -> Result<Vec<osis_schema::Retention>> {
    if osis_commit::retention::fixed_retention(ak.as_str()).is_some() {
        return Ok(Vec::new());
    }
    let entry = |h: &Header| h.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak).map(|a| a.retention);
    let mut own: BTreeSet<CommitId> = BTreeSet::new();
    let mut out = Vec::new();
    // live writes whose own commit is not a held commit with its own writes on the aspect
    let mut unknown: BTreeSet<osis_crdt::Dot> = BTreeSet::new();
    for (d, _) in st.live_writes() {
        let c = tx.core.commit_of(tid, ak, &d);
        let found = c.and_then(|c| {
            let h = &tx.core.ix.commits.get(&c)?.header;
            (!h.kind.is_compaction()).then_some(())?;
            entry(h)
        });
        match (found, c) {
            (Some(r), Some(c)) => {
                if own.insert(c) {
                    out.push(r);
                }
            }
            _ => _ = unknown.insert(d),
        }
    }
    if unknown.is_empty() {
        return Ok(out);
    }
    let commits: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().map(|(_, c)| *c).collect();
    let mut snapshots = Vec::new();
    for c in &commits {
        let Some(h) = tx.core.ix.commits.get(c).map(|m| &m.header) else { continue };
        let Some(r) = entry(h) else { continue };
        if h.kind.is_compaction() {
            snapshots.push((*c, r));
        }
    }
    let mut carried = BTreeSet::new();
    for (c, r) in &snapshots {
        let Some(ai) = aspect_index(tx.core, c, tid, ak) else { continue };
        let mut carries = false;
        crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
            for (d, _) in f.live_writes() {
                if unknown.contains(&d) {
                    carries = true;
                    carried.insert(d);
                }
            }
            Ok(())
        })?;
        if carries {
            out.push(*r);
        }
    }
    if carried.len() < unknown.len() {
        out.extend(snapshots.iter().map(|x| x.1));
    }
    Ok(out)
}

/// Whether part `ai` of snapshot `s` is a carrier only (`osis_commit::retention::carrier_only`).
pub(super) fn carrier_at(core: &Core, s: &CommitId, ai: usize) -> bool {
    core.ix.commits.get(s).and_then(|m| m.header.aspects.get(ai).map(|a| osis_commit::retention::carrier_only(&a.retention))).unwrap_or(false)
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

/// The frontiers a snapshot of `(tid, ak)` built now carries, and the session-form commits
/// they reflect: per source the held valid commits (not `left_out`) in counter order from the
/// held valid snapshots' frontiers on (memory: a covered commit is forgotten with its counters,
/// so their frontiers count as reflected) while they join without a hole; an invalid, missing
/// or left-out body stops its source's frontier below it (the snapshot does not carry its
/// writes, so it must not claim them), and what follows in that source is not reflected.
pub(crate) fn frontiers_now(tx: &Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, valid_on: &dyn Fn(&CommitId) -> bool, left_out: &dyn Fn(&CommitId) -> bool) -> (Frontiers, BTreeSet<CommitId>) {
    let mut frontiers = Frontiers::default();
    let mut reflected = BTreeSet::new();
    if memory {
        for (_, s, fr, _) in tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten() {
            if valid_on(s) {
                for (src, f) in fr.sources() {
                    if f > frontiers.of(&src) {
                        frontiers.insert(&src, f);
                    }
                }
            }
        }
    }
    let from = (*tid, ak.clone(), osis_crdt::Source::session(osis_crdt::Session { node: Tid::from_bytes([0; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }));
    for ((_, _, n), ranges) in tx.core.ix.ranges.range(from..).take_while(|((t, a, _), _)| t == tid && a == ak) {
        let mut next = frontiers.of(n).saturating_add(1);
        for (lo, (hi, c)) in ranges {
            if memory && *hi <= next {
                continue;
            }
            // contiguous (a memory range may start below a snapshot's frontier)
            let joins = *lo == next || (memory && *lo < next);
            if !joins || !valid_on(c) || left_out(c) {
                break;
            }
            next = *hi;
            reflected.insert(*c);
        }
        if next > 1 {
            frontiers.insert(n, next - 1);
        }
    }
    (frontiers, reflected)
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

/// `Engine::covered` in `tx`: the body whole, the snapshot a piece at a time (its part at the
/// body's positions, `Fragment::part_at`, and each piece's copies of the body's writes against
/// the body's part at the piece's positions: a copy lies where its write does). Cost: the body
/// and the snapshot's part at its positions, about twice the body; both whole only with a
/// pull decoder walking them side by side (issues/durable-decode-bound.md).
pub(crate) fn covered(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    let (Some(sai), Some(cai)) = (aspect_index(tx.core, s, tid, ak), aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2); a
    // carrier only covers none (spec/commits.md §5)
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) || carrier_at(tx.core, s, sai) {
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
    if tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction() && m.missing.contains(&cai)) {
        return Ok(None);
    }
    let Some(m) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    // a snapshot never carries an expiring delta's values, so it never covers one
    // (spec/crdt.md §8), held, dropped at its expiry or still to come
    if m.header.aspects.get(cai).is_some_and(|_| m.header.expires.is_some()) {
        return Ok(Some(false));
    }
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
    let mut body: Option<Fragment> = crate::apply::held_fragment(tx, c, cai)?;
    // a valid snapshot body's copies all count (spec/permissions.md §5.2): it must carry them
    // all; an invalid one gives nothing, its copies of writes a received valid delta supplies
    // are left out
    if is_snapshot && !crate::apply::copies::snapshot_valid(tx.core, c, tid, ak) {
        let core = &*tx.core;
        if let Some(b) = &mut body {
            b.strip_copies(&|d| crate::apply::copies::any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
        }
    }
    // the snapshot's copies of the body's writes are the body's (a copy at another
    // value, `ts` or position, or under a dot the body owns but lacks, joins as
    // unchanged): under its own dots, or a snapshot body's carried writes (records
    // without a `ts`, such as the entry another's write is nested in, are no writes)
    let mut ranges: Vec<(osis_crdt::Source, u64, u64)> = if is_snapshot {
        body.iter().flat_map(|b| b.writes()).filter(|w| w.1.is_some()).map(|(d, _)| (d.src.clone(), d.ctr, d.ctr.saturating_add(1))).collect()
    } else {
        crate::apply::copies::owned_ranges(&m.header, c, cai)
    };
    ranges.sort();
    ranges.dedup();
    let held = body.is_some();
    let mut joined = Fragment::default();
    if let Some(b) = body {
        joined.join(b);
    }
    let mut part = Fragment::default();
    let mut outside = false;
    let gives = crate::apply::each_held_piece(tx, s, sai, &mut |_, p| {
        // a copy in `p` is compared with the body's write at its position
        outside = outside || !p.copy_index_in(&ranges).outside(&ranges, &osis_crdt::CopySet::of(&[&joined.part_at(&p)])).is_empty();
        part.join(p.part_at(&joined));
        Ok(())
    })?;
    // the snapshot not held: nothing is established
    let Some(g) = &gives else { return Ok(None) };
    if let Some((fr, abs)) = g {
        let h = &m.header;
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
        if untraced && m.missing.contains(&cai) {
            return Ok(None);
        }
    }
    // a body this node holds no delta of (dropped at its keep bounds or as covered, a purge
    // rewrite) joins nothing: covered
    if !held {
        return Ok(Some(true));
    }
    // joining the body changes the snapshot's canonical bytes, judged on its part at the
    // body's positions (the rest is left as it is)
    let before = crate::engine::state::encode(&part)?;
    part.join(joined);
    if crate::engine::state::encode(&part)? != before {
        return Ok(Some(false));
    }
    Ok(Some(!outside))
}

impl Engine {
    /// Whether snapshot `s` is a carrier only on `(tid, ak)` (`osis_commit::retention::carrier_only`
    /// of its retention there): it drops no body as covered and covers none for must-hold.
    pub fn carrier_only(&self, s: &CommitId, tid: &Tid, ak: &Ak) -> bool {
        self.header(s).and_then(|h| h.aspects.iter().find(|a| a.tid == *tid && a.ak == *ak).map(|a| osis_commit::retention::carrier_only(&a.retention))).unwrap_or(false)
    }

    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from the receipt record. A carrier-only one included. On a `~`
    /// aspect a memory commit: deltas with an expiry left out whole, frontiers continuing from
    /// the held valid memory snapshots'.
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        self.snapshot_if(tid, ak, false)
    }

    /// `snapshot` for compaction: none when it would be a carrier only (spec/commits.md §5:
    /// it would drop nothing).
    pub fn compaction_snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        self.snapshot_if(tid, ak, true)
    }

    fn snapshot_if(&mut self, tid: &Tid, ak: &Ak, compaction: bool) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        // the role timeline walks every edge write (spec/commits.md §2)
        if ak.as_str() == "roles.0" {
            return Err(Error::Misuse("roles.0 is never compacted"));
        }
        if ak.as_str() == "created.0" {
            return Err(Error::Misuse("created.0 is kept forever, never compacted"));
        }
        // a memory aspect's snapshot is a memory commit (spec/commits.md §2); signals are never
        // held
        let memory = match ak.lifetime() {
            osis_schema::Lifetime::Durable => false,
            osis_schema::Lifetime::Ephemeral => true,
            osis_schema::Lifetime::Signal => return Err(Error::Misuse("a signal aspect holds no state to compact")),
        };
        self.run(|tx| {
            if memory {
                tx.set_memory();
            }
            // what a removal or expiry hid goes first, by an ordinary commit: its bodies die and
            // the snapshot does not carry it (spec/sync.md §7)
            let probe = osis_crdt::Stamp::new(Default::default(), osis_crdt::Source::commit(CommitId([0; 32])), 1);
            if !memory && osis_schema::core_types::is_content(ak.as_str()) && crate::engine::write::sweep_of(tx, &tid, &ak, &probe)?.is_some() {
                let mut m = crate::engine::write::Mutation::new();
                m.sweep(tid, ak.clone(), tx.core.schemas.get(ak.as_str()).cloned());
                crate::engine::write::commit_in(tx, m)?;
            }
            let node = tx.core.id.tid();
            let ts = tx.core.hlc.next();
            // a snapshot needs the strictest role a write it carries could need (tests may write
            // one a receiver judges invalid)
            let need = if tx.core.skip_writer_rules { crate::engine::write::required_role(ak.as_str()) } else { crate::engine::write::snapshot_role(ak.as_str()) };
            if !(memory && tx.core.skip_writer_rules) {
                let core = &*tx.core;
                let records: crate::engine::write::Records<'_> = &|t| core.created_for(t, true).filter(|_| core.ix.held.is_memory(t));
                crate::engine::write::check_role_with(core, core.id.tid(), records, &tid, ak.as_str(), need, ts)?;
            }
            if tx.state(&tid, &ak)?.is_none() {
                return Ok(None);
            }
            let expiring: Vec<(CommitId, Owned)> = tx
                .core
                .ix.by_aspect
                .get(&(tid, ak.clone()))
                .into_iter()
                .flatten()
                .filter_map(|(_, c)| {
                    let m = tx.core.ix.commits.get(c)?;
                    let ai = m.aspect(&tid, &ak)?;
                    m.header.aspects.get(ai)?;
                    m.header.expires?;
                    Some((*c, Owned::of(&m.header, c, ai)?))
                })
                .collect();
            let st = if memory {
                let Some(st) = memory_state(tx, &tid, &ak)? else { return Ok(None) };
                st
            } else {
                let Some(mut st) = tx.state(&tid, &ak)?.cloned() else { return Ok(None) };
                if !expiring.is_empty() {
                    st.strip(&|d| expiring.iter().any(|o| o.1.owns(d)));
                }
                st
            };
            if ak.as_str() == "secrets.0" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
                return Err(Error::Misuse("secrets.0 keys an epoch not established here (spec/crypto.md §4)"));
            }
            // a part still missing gives this state nothing (applied without it, spec/commits.md
            // §4): an expiring one's writes would go value-less here anyway
            let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak).is_some_and(|ai| m.valid_at(ai) && (!m.missing.contains(&ai) || m.header.aspects.get(ai).is_some_and(|_| m.header.expires.is_some()))));
            let left_out = |c: &CommitId| memory && expiring.iter().any(|x| x.0 == *c);
            // frontiers cover only counters whose writes this state reflects: applied, valid
            // (and for memory, not expiring), of the sessions that occur in it (spec/crdt.md §8:
            // a session with no write left in the state is pruned with them). A memory commit
            // is forgotten once covered, its counters with it: there the held valid snapshots'
            // frontiers count as reflected (their writes are joined), and own ranges continue
            // from them
            let (mut frontiers, _) = frontiers_now(tx, &tid, &ak, memory, &valid_on, &left_out);
            // commit-form commits whose valid writes the state reflects
            let mut absorbed = std::collections::BTreeMap::new();
            for (_, c) in tx.core.ix.by_aspect.get(&(tid, ak.clone())).into_iter().flatten() {
                let Some(m) = tx.core.ix.commits.get(c) else { continue };
                if by_id(m.header.kind, m.header.form) && valid_on(c) && !left_out(c) {
                    absorbed.insert(*c, m.header.author);
                }
            }
            // only sources that occur in the state (spec/crdt.md §8): a reader takes an absent
            // source as one with no write left, so a frontier never grows with sessions gone by
            let kind = if is_role_class(ak.as_str()) { Kind::RoleSnapshot } else { Kind::ContentSnapshot };
            let traced = osis_crdt::sources_of(&st, &osis_commit::writer_ctx(Form::Commit, kind, ts, node, 0, 0))?;
            frontiers.retain(&traced);
            absorbed.retain(|c, _| traced.contains(&osis_crdt::Source::commit(*c)));
            // bounds from the retention of the writes it carries, schema known here or not
            // (spec/commits.md §5); a memory one's are `writer` without bounds (spec/commits.md §2)
            let retention = if memory {
                osis_commit::retention::EPHEMERAL_RETENTION
            } else {
                osis_commit::retention::snapshot_retention(ak.as_str(), own_retentions(tx, &tid, &ak, &st)?, ts.wall_ms().0)
            };
            if compaction && osis_commit::retention::carrier_only(&retention) {
                return Ok(None);
            }
            // the records of the memory things it is on or places beside it (spec/commits.md §2)
            let records = if memory {
                let placed = crate::ephemeral::def_of(&st).map(|(i, s)| i.into_iter().chain(s).collect::<Vec<_>>()).unwrap_or_default();
                crate::engine::write::memory_records(tx.core, &tid, &ak, placed.into_iter())
            } else {
                Vec::new()
            };
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), first: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, frontiers: Some((frontiers, absorbed)), chunks: Vec::new(), records };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Writes a memory snapshot of `(tid, ak)` carrying only the join of this node's own unsent
    /// plain commits `ids` on it (spec/commits.md §2, the coalescing snapshot): its frontier
    /// reaches the last of their counters, so it covers exactly them (and nothing another
    /// session wrote, which joining would change). One entry goes up per round trip instead of
    /// one per write; the covered commits are forgotten here at once (`drop_covered`) and never
    /// uploaded. `None` when nothing of them is held.
    pub fn coalesce(&mut self, tid: &Tid, ak: &Ak, ids: &[CommitId]) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        let ids = ids.to_vec();
        self.run(|tx| {
            tx.set_memory();
            let node = tx.core.id.tid();
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
            let retention = osis_commit::retention::EPHEMERAL_RETENTION;
            let placed = crate::ephemeral::def_of(&st).map(|(i, s)| i.into_iter().chain(s).collect::<Vec<_>>()).unwrap_or_default();
            let records = crate::engine::write::memory_records(tx.core, &tid, &ak, placed.into_iter());
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), first: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, frontiers: Some((frontiers, std::collections::BTreeMap::new())), chunks: Vec::new(), records };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, whatever its tables say. A body not held here: covered, unless the snapshot's
    /// frontier lists its session short of its counters, so a body dropped here as covered past
    /// a gap reads uncovered from then on (`Dropped::covered_by` keeps what covered it). A carrier
    /// only covers none, nor does a snapshot cover one stamped later. `None` when either is not
    /// held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| {
            let r = covered(tx, &s, &c, &tid, &ak)?;
            #[cfg(test)]
            {
                let w = oracle::covered(tx, &s, &c, &tid, &ak)?;
                assert_eq!(r, w, "covered streamed vs whole");
            }
            Ok(r)
        })
    }
}
