//! Compaction snapshots (spec/commits.md §2, §5, spec/crdt.md §8): writing one, the bounds it
//! carries, and the covered test.

use super::aspect_index;
#[cfg(test)]
use super::oracle;
use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Engine, Owned, Tx, Core};
use crate::error::{Error, Result};
use osis_base::{Ak, CommitId, Tid, Ts};
use osis_commit::{Form, Header, Kind};
use osis_crdt::{Fragment, Frontiers};
use osis_schema::core_types::{is_content, is_role_class};
use std::collections::BTreeSet;

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
/// they reflect: per source the held valid commits in counter order from the
/// held valid snapshots' frontiers on (memory: a covered commit is forgotten with its counters,
/// so their frontiers count as reflected) while they join without a hole; an invalid or missing
/// body stops its source's frontier below it (the snapshot does not carry its
/// writes, so it must not claim them), and what follows in that source is not reflected.
pub(crate) fn frontiers_now(tx: &Tx<'_>, tid: &Tid, ak: &Ak, memory: bool, valid_on: &dyn Fn(&CommitId) -> bool) -> (Frontiers, BTreeSet<CommitId>) {
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
        for ((lo, c), hi) in ranges {
            if memory && *hi <= next {
                continue;
            }
            // contiguous (a memory range may start below a snapshot's frontier)
            let joins = *lo == next || (memory && *lo < next);
            if !joins || !valid_on(c) {
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

/// Whether snapshot `s` (part `sai`) purges on replace while body `c` (part `cai`) keeps history
/// and has a live write: dropped, that write would live on only in a snapshot that cannot keep its
/// history, so `s` covers it not (spec/commits.md §5 Covered). Liveness changes only by a kill,
/// which drops `s` too (its first death), or a validity change, after which `s` covers it at most
/// later than it could.
pub(super) fn cannot_keep(tx: &mut Tx<'_>, s: &CommitId, sai: usize, c: &CommitId, cai: usize, tid: &Tid, ak: &Ak) -> Result<bool> {
    use osis_schema::History;
    let history = |x: &CommitId, ai: usize| tx.core.ix.commits.get(x).and_then(|m| m.header.aspects.get(ai)).and_then(|a| a.retention.history);
    if history(s, sai) != Some(History::PurgeOnReplace) || !matches!(history(c, cai), Some(History::Keep { .. })) {
        return Ok(false);
    }
    super::bounds::body_live(tx, c, tid, ak)
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

/// The body whole, the snapshot a piece at a time (its part at the
/// body's positions, `Fragment::part_at`, and each piece's copies of the body's writes against
/// the body's part at the piece's positions: a copy lies where its write does). Cost: the body
/// and the snapshot's part at its positions, about twice the body; both whole only with a
/// pull decoder walking them side by side (issues/durable-decode-bound.md).
pub(crate) fn covered_join(tx: &mut Tx<'_>, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
    // counted: tests read how many pairs are joined
    let _s = crate::costs::span("covered: join");
    let (Some(sai), Some(cai)) = (aspect_index(tx.core, s, tid, ak), aspect_index(tx.core, c, tid, ak)) else { return Ok(None) };
    // an invalid snapshot gives nothing, so covers nothing (spec/permissions.md §5.2)
    if !crate::apply::copies::snapshot_valid(tx.core, s, tid, ak) || cannot_keep(tx, s, sai, c, cai, tid, ak)? {
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
            b.remove_writes(&|d| crate::apply::copies::any_delta(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && m.valid_at(ai)));
        }
    }
    let held = body.is_some();
    let mut joined = Fragment::default();
    if let Some(b) = body {
        joined.join(b);
    }
    let mut part = Fragment::default();
    let gives = match &tx.core.cover_cache {
        Some((cs, cai, pieces, gives)) if cs == s && *cai == sai => {
            for p in pieces {
                part.join(p.part_at(&joined));
            }
            gives.clone()
        }
        _ => crate::apply::each_held_piece(tx, s, sai, &mut |_, p| {
            part.join(p.part_at(&joined));
            Ok(())
        })?,
    };
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
    // rewrite) joins nothing: covered. Before an own replace the part must really have
    // dropped: a part not fetched yet is not established (a set add or map put still to come).
    if !held {
        let own = g.is_none();
        return Ok(if own && !m.dropped.contains_key(&cai) { None } else { Some(true) });
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

/// `Engine::snapshot` in `tx` (`memory`: the aspect is ephemeral, `tx` in the memory class):
/// a snapshot of `(tid, ak)` from this node's whole state, applied here.
pub(crate) fn write_snapshot(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, memory: bool) -> Result<Option<CommitId>> {
    let (tid, ak) = (*tid, ak.clone());
    // what a removal or expiry hid goes first, by an ordinary commit: its bodies die and
    // the snapshot does not carry it (spec/sync.md §7)
    let probe = osis_crdt::Stamp::new(Default::default(), osis_crdt::Source::commit(CommitId([0; 32])), 1);
    if !memory && osis_schema::core_types::is_content(ak.as_str()) && crate::engine::write::sweep_of(tx, &tid, &ak, &probe)?.is_some() {
        let mut m = crate::engine::write::Mutation::new();
        m.sweep(tid, ak.clone(), tx.core.schemas.get(ak.as_str()).cloned());
        crate::engine::write::commit_in(tx, m)?;
    }
    let node = tx.core.writer_for(&tid)?;
    let ts = tx.core.hlc.next();
    // a snapshot needs the strictest role a write it carries could need (tests may write
    // one a receiver judges invalid)
    let need = if tx.core.skip_writer_rules { crate::engine::write::required_role(ak.as_str()) } else { crate::engine::write::snapshot_role(ak.as_str()) };
    if !(memory && tx.core.skip_writer_rules) {
        let core = &*tx.core;
        crate::engine::write::check_role_with(core, node, &|_| None, &tid, ak.as_str(), need, ts)?;
    }
    if tx.state(&tid, &ak)?.is_none() {
        return Ok(None);
    }
    let Some(st) = snapshot_state(tx, &tid, &ak)? else { return Ok(None) };
    if ak.as_str() == "secrets.0" && !crate::apply::keys::may_compact(tx.core, &tid, &st) {
        return Err(Error::Misuse("secrets.0 keys an epoch not established here (spec/crypto.md §4)"));
    }
    // a part still missing gives this state nothing (applied without it, spec/commits.md
    // §4): an expiring one's writes would go value-less here anyway
    let valid_on = |c: &CommitId| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&tid, &ak).is_some_and(|ai| m.valid_at(ai) && (!m.missing.contains(&ai) || m.header.aspects.get(ai).is_some_and(|_| m.header.expires.is_some()))));
    // frontiers cover only counters whose writes this state reflects: applied, valid, of
    // the sessions that occur in it (spec/crdt.md §8:
    // a session with no write left in the state is pruned with them). A memory commit
    // is forgotten once covered, its counters with it: there the held valid snapshots'
    // frontiers count as reflected (their writes are joined), and own ranges continue
    // from them
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
    // history from the retention of the writes it carries, schema known here or not
    // (spec/commits.md §5), memory or durable alike
    let retention = osis_commit::retention::snapshot_retention(ak.as_str(), own_retentions(tx, &tid, &ak, &st)?);
    let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false, rotation: None };
    let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, replaces: None, frontiers: Some((frontiers, absorbed)), chunks: Vec::new() };
    build_and_apply(tx, plan, vec![d]).map(Some)
}

impl Engine {
    /// Writes a compaction snapshot of `(tid, ak)` from this node's whole state (spec/commits.md
    /// §2, spec/crdt.md §8): values of deltas with an expiry and of purged writes go
    /// value-less; frontiers from what this node received. On a `+` aspect a memory commit, frontiers
    /// continuing from the held valid memory snapshots'. `None`: no state to snapshot (a signal
    /// has none).
    pub fn snapshot(&mut self, tid: &Tid, ak: &Ak) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        // the role timeline walks every edge write (spec/commits.md §2)
        if ak.as_str() == "roles.0" {
            return Err(Error::Misuse("roles.0 is never compacted"));
        }
        if ak.as_str() == "created.0" {
            return Err(Error::Misuse("created.0 is kept forever, never compacted"));
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
    /// uploaded. `None` when nothing of them is held.
    pub fn coalesce(&mut self, tid: &Tid, ak: &Ak, ids: &[CommitId]) -> Result<Option<CommitId>> {
        let (tid, ak) = (*tid, ak.clone());
        let ids = ids.to_vec();
        self.run(|tx| {
            tx.set_memory();
            let node = tx.core.writer_for(&tid)?;
            let ts = tx.core.hlc.next();
            let own = osis_crdt::Source::session(tx.core.session);
            let mut st: Option<Fragment> = None;
            let mut hi = 0u64;
            let mut kept = Vec::new();
            for c in &ids {
                let Some(m) = tx.core.ix.commits.get(c).cloned() else { continue };
                let Some(ai) = m.aspect(&tid, &ak).filter(|ai| m.holds(*ai)) else { continue };
                if m.header.form != Form::Session(tx.core.session.nonce) || m.header.aspects.get(ai).is_some_and(|_| m.header.expires.is_some()) {
                    return Err(Error::Misuse("coalescing takes this session's plain commits"));
                }
                hi = hi.max(m.header.aspects.get(ai).map_or(0, |a| a.hi));
                kept.extend(m.header.aspects.get(ai).map(|a| a.retention));
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
            let retention = osis_commit::retention::snapshot_retention(ak.as_str(), kept);
            let plan = CommitPlan { kind, ts, actor: node, form: Form::Commit, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false, rotation: None };
            let d = Resolved { tid, ak, fragment: st, lo: 0, hi: 0, schema: None, retention: Some(retention), expires: None, replaces: None, frontiers: Some((frontiers, std::collections::BTreeMap::new())), chunks: Vec::new() };
            build_and_apply(tx, plan, vec![d]).map(Some)
        })
    }

    /// Is the body of `ak` in commit `c` covered by snapshot commit `s` (spec/commits.md §5):
    /// joining each of its deltas into the snapshot's fragment leaves its canonical bytes
    /// unchanged, whatever its tables say, and the snapshot holds each live write of the body
    /// with the body's payload where the body's write has one. A body not held here: covered, unless the snapshot's
    /// frontier lists its session short of its counters, so a body dropped here as covered past
    /// a gap reads uncovered from then on (`Dropped::covered_by` keeps what covered it). A snapshot
    /// covers none stamped later, nor, purging on replace, a live body that keeps history. `None` when either is not
    /// held (nothing is established).
    pub fn covered(&mut self, s: &CommitId, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<bool>> {
        let (s, c, tid, ak) = (*s, *c, *tid, ak.clone());
        self.run(|tx| {
            let r = covered(tx, &s, &c, &tid, &ak)?;
            #[cfg(test)]
            if tx.core.ix.commits.get(&s).is_some_and(|m| m.view.kind.is_compaction()) {
                let w = oracle::covered(tx, &s, &c, &tid, &ak)?;
                assert_eq!(r, w, "covered streamed vs whole");
            }
            Ok(r)
        })
    }
}
