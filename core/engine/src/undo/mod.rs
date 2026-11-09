//! Revert, an undo commit (spec/commits.md §7, spec/crdt.md §4.6), of a durable or an ephemeral
//! commit alike: stacks, scopes and redo live in the `osis` crate (`held_commits`). An undo
//! commit's deltas come from osis-crdt's `undo` against the current state and the state before
//! the undone commit as kept history gives it (`kept_before`): never from a body held but not
//! kept, so whether an undo works and what it writes is alike at every node holding the same
//! commits. It reverts every part of the commit or none: a part it inverts whose body is not held
//! (dropped, or not fetched yet) is `ContentGone`, as is an inverse writing back replaced content
//! (`osis_crdt::restores`, by the writes' kinds) where a part it may have replaced is not kept
//! (`replaced_kept`).

use crate::engine::write::{CommitPlan, Resolved, build_one, check_acts, check_authority};
use crate::engine::{Core, Engine, Mutation, Tx};
use crate::ephemeral::Written;
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Header, Kind};
use osis_base::{Ak, CommitId, Role, Tid, Ts, Value};
use osis_schema::RawKey;
use osis_schema::core_types::{CREATED, GROUP};
use osis_crdt::{AnyView, CounterRange, Dot, Fragment, Op, PathOp, PathSeg, Source, Undone, Writer};
use std::collections::{BTreeMap, BTreeSet};

/// What a revert did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reverted {
    Written(Written),
    /// Nothing to write: everything it wrote was superseded since.
    Superseded,
    /// A part's body is not held whole here, or its inverse writes back content no kept history
    /// holds (`Error::ContentGone`).
    ContentGone,
}

/// Whether part `a`'s history would be kept at wall ms `now` had a write stamped by `h`
/// replaced it: until its keep bound (spec/commits.md §5), a relative one counted from `h`'s
/// `ts`. By the part's retention alone, never by what is held.
fn keeps_now(h: &Header, a: &osis_commit::AspectEntry, now: u64) -> bool {
    let k = osis_commit::retention::KeepRule::of_aspect(a);
    k.until.is_some_and(|t| now < t) || k.after.is_some_and(|d| now < h.ts.wall_ms().0.saturating_add(d))
}

/// The valid parts of `(tid, ak)` ordered before `at` whose headers are held, oldest first, each
/// as `(ts, commit, aspect index)`.
fn parts_before(core: &Core, tid: &Tid, ak: &Ak, at: (Ts, CommitId)) -> Vec<(Ts, CommitId, usize)> {
    let ids = core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| **x < at);
    ids.filter_map(|(ts, c)| core.ix.commits.get(c).and_then(|m| m.aspect(tid, ak).filter(|ci| m.valid_at(*ci))).map(|ci| (*ts, *c, ci))).collect()
}

/// Whether part `ci` of `c` on `(tid, ak)` is in kept history at wall ms `now`: held, and in
/// the aspect's read (a write of it live, `body_live`) or kept by its history until its bound
/// (`body_keep`), so listed (notes/listener-design.md).
fn kept(tx: &mut Tx<'_>, c: &CommitId, ci: usize, tid: &Tid, ak: &Ak, now: u64) -> Result<bool> {
    if !tx.core.ix.commits.get(c).is_some_and(|m| m.holds(ci)) {
        return Ok(false);
    }
    crate::engine::listing::in_kept_history(tx, c, tid, ak, now)
}

/// The state of `(tid, ak)` just before the commit at `at`, as kept history gives it: the join
/// of the parts ordered before it that are `kept`, newest first and no further than the newest
/// kept whole reset, which supersedes every write stamped before it (`resets_whole`). A part
/// replaced and not kept is left out, held or not.
fn kept_before(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, at: (Ts, CommitId)) -> Result<Fragment> {
    let now = tx.now().0;
    let mut f = Fragment::default();
    let mut floor: Option<Ts> = None;
    for (ts, c, ci) in parts_before(tx.core, tid, ak, at).into_iter().rev() {
        if floor.is_some_and(|x| ts < x) {
            break;
        }
        if kept(tx, &c, ci, tid, ak, now)?
            && let Some(d) = crate::apply::held_part(tx, &c, ci)?
        {
            if floor.is_none() && resets_whole(&d) {
                floor = Some(ts);
            }
            f.join(d.into_fragment());
        }
    }
    #[cfg(test)]
    {
        let whole = crate::costs::paused(|| kept_join(tx, tid, ak, at, now))?;
        assert_eq!(crate::engine::state::encode(&f)?, crate::engine::state::encode(&whole)?, "kept_before stopped at a reset: the whole join");
    }
    Ok(f)
}

/// Tests: `kept_before` joining every kept part.
#[cfg(test)]
fn kept_join(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, at: (Ts, CommitId), now: u64) -> Result<Fragment> {
    let mut f = Fragment::default();
    for (_, c, ci) in parts_before(tx.core, tid, ak, at) {
        if kept(tx, &c, ci, tid, ak, now)?
            && let Some(d) = crate::apply::held_part(tx, &c, ci)?
        {
            f.join(d.into_fragment());
        }
    }
    Ok(f)
}

/// Whether every part the restoring part `a` of commit `h` (ID `id`) may have replaced is kept
/// at wall ms `now`, judged by each part's own retention and age (spec/commits.md §7), never by
/// the undone part's own. A write does not record what it overwrote, so the valid parts of the
/// aspect ordered before it count, newest first. A part is excused only by a kept part that
/// supersedes it: a delta resetting the aspect whole stamped after it (`resets_whole`; the walk
/// stops there), or a snapshot whose tables reach it (`retention::reaches`: what of it was still
/// live is in that snapshot). A snapshot part is excused only by a later reset: tables name
/// only commits with writes of their own, and a node may hold a snapshot without the parts that
/// wrote it. Any other part counts unless it is `kept` or, held or dropped, its retention would
/// keep it now had this write replaced it (then, not kept, it was replaced earlier). A part not
/// fetched yet counts (notes/listener-design.md), and so does a memory commit forgotten here
/// (`Indexes::forgotten`) unless a reset stamped after it is kept: its header is gone, so no
/// snapshot can be shown to reach it. By headers and kept history
/// alone, never by a body held but not kept.
fn replaced_kept(tx: &mut Tx<'_>, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry, now: u64) -> Result<bool> {
    let k = (a.tid, a.ak.clone());
    // the `ts` of the newest kept reset met: older parts are covered by it
    let mut floor: Option<Ts> = None;
    // the kept snapshots met
    let mut snaps: Vec<CommitId> = Vec::new();
    for (ts, c, ci) in parts_before(tx.core, &a.tid, &a.ak, (h.ts, *id)).into_iter().rev() {
        if floor.is_some_and(|f| ts < f) {
            break;
        }
        if kept(tx, &c, ci, &a.tid, &a.ak, now)? {
            if tx.core.ix.commits.get(&c).is_some_and(|m| m.view.kind.is_compaction()) {
                snaps.push(c);
            } else if floor.is_none() && crate::apply::held_part(tx, &c, ci)?.is_some_and(|d| resets_whole(&d)) {
                floor = Some(ts);
            }
            continue;
        }
        let Some(m) = tx.core.ix.commits.get(&c) else { return Ok(false) };
        let Some(p) = m.header.aspects.get(ci) else { return Ok(false) };
        let held = tx.core.ix.snapshots.get(&k).into_iter().flatten();
        if held.filter(|x| snaps.contains(&x.1)).any(|x| crate::retention::reaches((&x.2, &x.3), &m.header, &c, p.hi)) {
            continue;
        }
        if m.missing.contains(&ci) || !keeps_now(h, p, now) {
            return Ok(false);
        }
    }
    let forgotten = tx.core.ix.forgotten.get(&k);
    Ok(forgotten.is_none_or(|t| floor.is_some_and(|f| *t < f)))
}

/// Whether part `d` is a delta resetting the aspect whole (its root reset, or a register write,
/// which implies one, spec/crdt.md §5.1), so superseding every write stamped before it.
fn resets_whole(d: &Decoded) -> bool {
    matches!(d, Decoded::Delta(x) if x.fragment.reset().is_some() || matches!(x.fragment, Fragment::Register(_) | Fragment::Slots(_)))
}

/// The expiry of the write dotted `d` in `(tid, ak)` an undo copies back (`undo_expiring`): its
/// held commit's (`None`: none). An ephemeral write no held commit carries: a plain write of this
/// open's sessions never expires (covered by a snapshot); another session's expired or was
/// superseded (`Some(0)`: a session's write held nowhere vanished whole, spec/crdt.md §4.7).
fn copied_expiry(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> Option<u64> {
    if let Some(e) = core.write_expiry(tid, ak, d) {
        return e;
    }
    match d.src.author().kind() {
        osis_crdt::SourceKind::Session(s) if ak.ephemeral() && !core.own_plain(&s.node, &s.nonce) => Some(0),
        _ => None,
    }
}

/// The expiries of the writes an undo copies back (`None`: one that never expires).
pub(crate) type Copies = BTreeSet<Option<u64>>;

/// The undo delta of `undone` against `state`, `pre` the state before it (spec/crdt.md §4.6),
/// and the expiries still ahead of the writes it copies back (`expiry` of an origin dot: `None`
/// for none, or for a dot whose commit is not known; a header outlives its body, so the commit
/// of a write still held is known). Invariant (§4.6, §4.7): an undo never extends a value's
/// lifetime, and never writes back content gone by expiry or purge: what has expired by `wall`
/// (the undo's `ts`) is stripped from `pre` first, and the caller strips what the node holds
/// value-less (`strip_valueless`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn undo_expiring(mut w: Writer, undone: &Undone, state: &Fragment, mut pre: Fragment, schema: Option<&osis_schema::Schema>, ak: &Ak, wall: u64, expiry: &dyn Fn(&Dot) -> Option<u64>) -> Result<Option<(Fragment, CounterRange, Copies)>> {
    pre.strip(&|d| expiry(d).is_some_and(|t| t <= wall));
    let out = match schema.and_then(|s| s.view(ak.as_str())) {
        Some(v) => osis_crdt::undo(&mut w, undone, state, &pre, &v)?,
        None => osis_crdt::undo(&mut w, undone, state, &pre, &AnyView)?,
    };
    let copies = w.copied().iter().map(expiry).filter(|t| t.is_none_or(|t| t > wall)).collect();
    Ok(out.map(|f| (f, w.range(), copies)))
}

/// The one expiry of an undo writing back values that expire at `copies` (`None`: never;
/// spec/crdt.md §4.6). An undo is one commit with one expiry, so it is refused while
/// they differ: taking the earliest would make a lasting value expire with the copy. Once the
/// sooner ones have expired nothing of theirs is written back and it goes through.
pub(crate) fn copy_expiry(copies: &Copies) -> Result<Option<u64>> {
    let mut it = copies.iter();
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => {
            let at = |e: &Option<u64>| e.map_or("never".to_string(), |t| format!("at {t}"));
            Err(Error::Clash(format!("this undo writes back values expiring {} and {}: an undo is one commit with one expiry, so it cannot be undone while both stand", at(a), at(b))))
        }
        (a, _) => Ok(a.copied().flatten()),
    }
}

/// Builds and applies the undo commit of `target` (spec/crdt.md §4.6), in its class (an
/// ephemeral commit's undo is a memory commit): the things it created are deleted.
/// `confined`: every write it makes is held to `actor`'s rights (`Engine::revert_as`).
/// `Misuse("nothing to undo")` when it writes nothing (`undo_writes`).
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Option<Ts>, confined: bool) -> Result<CommitId> {
    let ts = ts.unwrap_or_else(|| tx.core.hlc.next());
    let Some((deltas, nonce)) = undo_writes(tx, target, actor, ts, confined)? else { return Err(Error::Misuse("nothing to undo")) };
    let node = tx.core.writer()?;
    // rights: its own commit applies only if valid here, as at every receiver (`apply_local`)
    check_acts(tx.core, node, &|_| None, &actor, ts)?;
    if confined {
        crate::engine::acting::check_undo(tx, actor, &deltas, ts)?;
    }
    // an undo writes under this open's session, like any content commit (spec/commits.md §3)
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Session(nonce), creates: Default::default(), purge: Vec::new(), undoes: Some(target), frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false };
    build_one(tx, plan, deltas)
}

/// The writes of `target`'s undo stamped `ts`, with the session nonce they are under; `None`
/// when it writes nothing (everything it wrote was superseded since). It expires with the writes
/// it copies back, refused while those expire differently (`copy_expiry`); an ephemeral one
/// copying back an expiring value is under the open's expiring session (spec/crdt.md §2.1).
/// `ContentGone` when a part is not held whole or its inverse writes back replaced content not
/// kept (`undone_parts`).
fn undo_writes(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Ts, confined: bool) -> Result<Option<(Vec<Resolved>, [u8; osis_crdt::SESSION_NONCE_LEN])>> {
    let m = tx.core.ix.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let memory = m.view.memory;
    let node = tx.core.writer()?;
    let made = made_by(&h, &m.valid);
    let writers: &[Tid] = if confined { &[node, actor] } else { &[node] };
    // the parts it undoes, each with the state before it as kept history gives it
    let mut parts = Vec::new();
    for (a, delta, source) in undone_parts(tx, &target, ts.wall_ms().0)? {
        let mut pre = kept_before(tx, &a.tid, &a.ak, (h.ts, target))?;
        crate::apply::strip_valueless(tx.core, &a.tid, &a.ak, &mut pre);
        parts.push((a, delta, source, pre));
    }
    let [plain, expiring] = [tx.core.session.nonce, tx.core.expiring.nonce];
    let mut nonce = plain;
    let (mut deltas, expires) = loop {
        let unmade = unmake_ops(tx, &made, ts, node, writers)?;
        let (deltas, copies) = inverse(tx, &parts, unmade, ts, nonce)?;
        // tests: a writer predating the undo expiry rule (spec/crdt.md §4.6)
        let expires = if tx.core.skip_writer_rules { None } else { copy_expiry(&copies)? };
        if !memory || expires.is_none() || nonce == expiring {
            break (deltas, expires);
        }
        nonce = expiring;
    };
    if deltas.is_empty() {
        return Ok(None);
    }
    deltas.iter_mut().for_each(|d| d.expires = expires);
    Ok(Some((deltas, nonce)))
}

/// The parts of content commit `target` its undo inverts, each with its delta and its writer's
/// source. Left out: one invalid here, a signal's (it reads absent before and after), the creation
/// record and the parts on things the commit created (those are deleted, `unmake_ops`). Every
/// other part is reverted, or there is no undo (`ContentGone`): its body dropped (spec/commits.md
/// §7: by cover, expiry or purge) or not fetched yet, so an undo is the same on every node; or it
/// writes back replaced content (`osis_crdt::restores`) not kept at wall ms `now`
/// (`replaced_kept`).
fn undone_parts(tx: &mut Tx<'_>, target: &CommitId, now: u64) -> Result<Vec<(osis_commit::AspectEntry, Fragment, Source)>> {
    let m = tx.core.ix.commits.get(target).cloned().ok_or(Error::UnknownCommit(*target))?;
    let h = m.header.clone();
    let made = made_by(&h, &m.valid);
    let mut parts = Vec::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if !m.valid_at(ai) || a.ak.signal() || a.ak.as_str() == CREATED.ak() || a.ak.as_str() == osis_commit::retention::REQUIRED || made.contains(&a.tid) {
            continue;
        }
        if m.body_gone(ai) || m.missing.contains(&ai) {
            return Err(Error::ContentGone(*target));
        }
        let Some(Decoded::Delta(d)) = crate::apply::held_part(tx, target, ai)? else { return Err(Error::Corrupt("content part held without its delta")) };
        let source = h.form.own_source(h.author, *target);
        let undone = Undone { delta: &d.fragment, source: &source, range: CounterRange { lo: a.lo, hi: a.hi } };
        if osis_crdt::restores(&undone) && !replaced_kept(tx, &h, target, a, now)? {
            return Err(Error::ContentGone(*target));
        }
        parts.push((a.clone(), d.fragment, source));
    }
    Ok(parts)
}

/// The undo's deltas of `parts` (each undone delta with its writer's source and the state before
/// it) and of the creations' undoing (`unmade`), stamped under session `nonce`, with the expiries
/// of what they copy back.
fn inverse(tx: &mut Tx<'_>, parts: &[(osis_commit::AspectEntry, Fragment, Source, Fragment)], mut unmade: BTreeMap<(Tid, Ak), Vec<PathOp>>, ts: Ts, nonce: [u8; osis_crdt::SESSION_NONCE_LEN]) -> Result<(Vec<Resolved>, Copies)> {
    let own = Form::Session(nonce).own_source(tx.core.writer()?, CommitId([0; 32]));
    let mut deltas = Vec::new();
    let mut copies = Copies::new();
    for (a, delta, source, pre) in parts {
        let undone = Undone { delta, source, range: CounterRange { lo: a.lo, hi: a.hi } };
        let schema = schema_of(tx.core, &a.ak);
        // the undo reads the current state along the delta's paths, or whole where the aspect was
        // absent before. A spot it resets is judged by its read (it may be made absent again), so
        // an undo whose reset reaches a paged collection held in part runs again on the whole
        // state: the collection may hold others' entries on pages the delta does not touch. A
        // reset elsewhere lies inside a loaded page or the skeleton, read whole already.
        let mut whole = !pre.present();
        let out = loop {
            if whole {
                tx.load(&a.tid, &a.ak)?;
            } else {
                tx.load_lazy(&a.tid, &a.ak)?;
                let touch = crate::engine::pages::touch_of(delta, tx.core.pages.get(&(a.tid, a.ak.clone())));
                tx.ensure_touch(&a.tid, &a.ak, &touch)?;
            }
            let lo = tx.txn.counter(&a.tid, &a.ak, &nonce)?;
            let empty = Fragment::default();
            let state = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
            let w = Writer::new(ts, own.clone(), lo).keyed_removals(osis_schema::core_types::is_role_class(a.ak.as_str()));
            let core = &*tx.core;
            let expiry = |d: &Dot| copied_expiry(core, &a.tid, &a.ak, d);
            let out = undo_expiring(w, &undone, state, pre.clone(), schema.as_deref(), &a.ak, ts.wall_ms().0, &expiry)?;
            let pages = tx.core.pages.get(&(a.tid, a.ak.clone())).filter(|i| !i.whole());
            if whole || !out.as_ref().is_some_and(|x| pages.is_some() && x.0.has_position_reset() && crate::engine::pages::touch_of(&x.0, pages).is_none()) {
                break out;
            }
            whole = true;
        };
        if let Some((f, r, e)) = out {
            copies.extend(e);
            deltas.push(Resolved { tid: a.tid, ak: a.ak.clone(), fragment: f, lo: r.lo, hi: r.hi, schema, retention: None, expires: None, frontiers: None, chunks: Vec::new() });
            // joined into the delta just pushed, so its counters stay the last allocated
            if let Some(ops) = unmade.remove(&(a.tid, a.ak.clone())) {
                unmake_one(tx, (a.tid, a.ak.clone()), ops, ts, &own, nonce, &mut deltas)?;
            }
        }
    }
    for (k, ops) in unmade {
        unmake_one(tx, k, ops, ts, &own, nonce, &mut deltas)?;
    }
    Ok((deltas, copies))
}

/// The schema an undo writes `ak` under, so its writes take the aspect's retention and expiry
/// defaults as any write of it does: the registered one, else the core schema for a core key.
fn schema_of(core: &Core, ak: &Ak) -> Option<std::sync::Arc<osis_schema::Schema>> {
    core.schemas.get(ak.as_str()).cloned().or_else(|| osis_schema::core_types::is_core_key(ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone())))
}

/// The things content commit `m` created: those whose `created.0` it validly carries.
pub(crate) fn made_by(h: &osis_commit::Header, valid: &[bool]) -> BTreeSet<Tid> {
    if h.kind != Kind::Content {
        return BTreeSet::new();
    }
    h.aspects.iter().enumerate().filter(|(ai, a)| a.ak.as_str() == "created.0" && valid.get(*ai).copied().unwrap_or(false)).map(|(_, a)| a.tid).collect()
}

/// Undoing a creation deletes the thing (spec/crdt.md §4.6): `delete`'s writes for each of
/// `made`, its aspects that may hold content reset (`read::deleted_aspects`; its ephemeral
/// state is dropped, `Engine::revert_inner`) and its entries removed from every `group.0`
/// listing it that all of `writers` may write (this node, a confined revert's actor too), each
/// resolved after the undo's own delta of that aspect and
/// joined into it (`unmake_one`). `Permission` when this node may not write one of `made`
/// (`delete` would refuse; never a partial revert).
fn unmake_ops(tx: &mut Tx<'_>, made: &BTreeSet<Tid>, ts: Ts, node: Tid, writers: &[Tid]) -> Result<BTreeMap<(Tid, Ak), Vec<PathOp>>> {
    if made.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut ops: BTreeMap<(Tid, Ak), Vec<PathOp>> = BTreeMap::new();
    for x in made {
        if crate::engine::write::role_of(tx.core, &node, x, ts) < Some(Role::Write) {
            return Err(Error::Permission { tid: *x });
        }
        for ak in crate::engine::read::deleted_aspects(tx, x)? {
            ops.entry((*x, ak)).or_default().push(PathOp { path: Vec::new(), op: Op::RemoveAspect });
        }
    }
    let gak = Ak::new(GROUP.ak()).map_err(|_| Error::Misuse("ak"))?;
    for (g, (items, subs)) in &tx.core.ix.groups.defs {
        if made.contains(g) || !writers.iter().all(|w| crate::engine::write::check_authority(tx.core, *w, &Default::default(), g, GROUP.ak(), ts).is_ok()) {
            continue;
        }
        let rm = |field: u64, set: &BTreeSet<Tid>| set.intersection(made).map(|x| PathOp { path: vec![PathSeg::Field(field)], op: Op::Remove(Value::Tid(*x)) }).collect::<Vec<_>>();
        let v: Vec<PathOp> = [rm(crate::engine::groups::ITEMS, items), rm(crate::engine::groups::SUBGROUPS, subs)].concat();
        if !v.is_empty() {
            ops.entry((*g, gak.clone())).or_default().extend(v);
        }
    }
    Ok(ops)
}

/// Runs `unmake_ops`' ops on `k` under the undo's own source `own` (of session `nonce`), joined into the undo's
/// delta of `k` when it is the last one in `deltas` (its counters the last allocated).
fn unmake_one(tx: &mut Tx<'_>, (tid, ak): (Tid, Ak), ops: Vec<PathOp>, ts: Ts, own: &Source, nonce: [u8; osis_crdt::SESSION_NONCE_LEN], deltas: &mut Vec<Resolved>) -> Result<()> {
    let mut state = tx.state(&tid, &ak)?.cloned().unwrap_or_default();
    let joined = deltas.last().is_some_and(|d| d.tid == tid && d.ak == ak);
    // joined: one delta, so its commit-level writes keep that delta's stamp (spec/crdt.md §2.3)
    let (lo, resume) = match deltas.last() {
        Some(d) if joined => {
            state.join(d.fragment.clone());
            (d.lo, d.hi)
        }
        _ => {
            let c = tx.txn.counter(&tid, &ak, &nonce)?;
            (c, c)
        }
    };
    let schema = schema_of(tx.core, &ak);
    let view = schema.as_ref().and_then(|s| s.view(ak.as_str()));
    let w = Writer::new(ts, own.clone(), lo).resume(resume).keyed_removals(osis_schema::core_types::is_role_class(ak.as_str()));
    let out = match &view {
        Some(v) => crate::engine::write::run_ops(&state, w, &ops, v)?,
        None => crate::engine::write::run_ops(&state, w, &ops, &AnyView)?,
    };
    let Some((f, r)) = out else { return Ok(()) };
    match deltas.last_mut() {
        Some(d) if joined => {
            d.fragment.join(f);
            d.hi = r.hi;
        }
        _ => deltas.push(Resolved { tid, ak, fragment: f, lo: r.lo, hi: r.hi, schema, retention: None, expires: None, frontiers: None, chunks: Vec::new() }),
    }
    Ok(())
}

/// A held commit as the `osis` commit query reads it: its signed header and, per aspect it
/// validly touches, whether the body is still held.
#[derive(Clone, Debug)]
pub struct HeldCommit {
    pub id: CommitId,
    pub header: std::sync::Arc<osis_commit::Header>,
    pub received: osis_base::WallMs,
    /// `(tid, ak, body held)` of each valid aspect (in scope, when one is given).
    pub aspects: Vec<(Tid, Ak, bool)>,
}

impl Engine {
    /// Reverts `target` (any held content commit; spec/crdt.md §4.6: an undo commit). `None` if
    /// there is nothing to write; `ContentGone` (`Error`) when a part's body is not held whole or
    /// its inverse needs content no kept history holds; `Clash` if its writes cannot share a commit.
    pub fn revert(&mut self, target: &CommitId) -> Result<Option<CommitId>> {
        let me = self.core.writer()?;
        match self.revert_commit(*target, me)? {
            Reverted::Written(w) => Ok(Some(w.id)),
            Reverted::Superseded => Ok(None),
            Reverted::ContentGone => Err(Error::ContentGone(*target)),
        }
    }

    /// Whether reverting held content commit `c` now writes anything (`revert_commit` would
    /// answer `Superseded` when not), failing as it would before writing (`ContentGone` when a
    /// part is not held whole or its inverse writes back content no kept history holds). Computes
    /// the revert's writes in a transaction rolled back after.
    pub fn check_revertible(&mut self, c: &CommitId) -> Result<bool> {
        let me = self.core.writer()?;
        self.check_revert(*c, me, false)
    }

    /// `check_revertible` acting as `actor`; `confined` as `revert_inner`.
    pub(crate) fn check_revert(&mut self, c: CommitId, actor: Tid, confined: bool) -> Result<bool> {
        let memory = self.core.ix.commits.get(&c).is_some_and(|m| m.view.memory);
        // a probe stamps nothing: the clock is not stepped
        let ts = self.core.hlc.peek();
        self.probe(|tx| tx.in_class(memory, |tx| undo_writes(tx, c, actor, ts, confined)).map(|w| w.is_some()))
    }

    /// Reverts commit `id`, durable or ephemeral, acting as `actor`, by an undo commit of its
    /// class (spec/crdt.md §4.6).
    pub fn revert_commit(&mut self, id: CommitId, actor: Tid) -> Result<Reverted> {
        self.revert_inner(id, actor, false)
    }

    /// `revert_commit`; `confined`: held to `actor`'s rights on every write it really makes
    /// (`Engine::revert_as`), before anything applies. Undoing a creation deletes the thing
    /// (spec/crdt.md §4.6): the undo commit deletes it durably and its ephemeral state is dropped
    /// here, as a delete does (`retention::memory::drop_things`).
    pub(crate) fn revert_inner(&mut self, c: CommitId, actor: Tid, confined: bool) -> Result<Reverted> {
        let mut del: BTreeSet<Tid> = BTreeSet::new();
        let mut memory = false;
        if let Some(m) = self.core.ix.commits.get(&c) {
            memory = m.view.memory;
            if let Some(h) = m.header.decoded() {
                del.extend(made_by(&h, &m.valid));
            }
        }
        let ts = self.core.hlc.next();
        let node = self.core.writer()?;
        // who must hold write on all it does: this node (spec/crdt.md §4.6), a confined revert's
        // actor too; things it deletes count though no write is left to make
        let writers: &[Tid] = if confined { &[node, actor] } else { &[node] };
        let done = self.run(|tx| {
            if !del.is_empty() {
                let core = &*tx.core;
                check_acts(core, node, &|_| None, &actor, ts)?;
                for w in writers {
                    for t in &del {
                        check_authority(core, *w, &Default::default(), t, CREATED.ak(), ts)?;
                    }
                }
            }
            let mut m = Mutation::new();
            m.act_as(actor).undo(c);
            m.confined = confined;
            m.ts = Some(ts);
            let Some(u) = tx.in_class(memory, |tx| crate::engine::write::commit_in(tx, m))? else { return Ok(None) };
            let ts = tx.core.ix.commits.get(&u).map(|m| m.view.ts).unwrap_or(ts);
            Ok(Some((u, ts, crate::retention::memory::drop_things(tx, &del)?)))
        });
        let (u, ts, dropped) = match done {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(Reverted::Superseded),
            Err(Error::ContentGone(_)) => return Ok(Reverted::ContentGone),
            Err(e) => return Err(e),
        };
        if memory {
            self.ephemeral_written(u, actor);
        } else {
            self.dropped_event(u, actor, ts, dropped);
        }
        Ok(Reverted::Written(Written { id: u, ts }))
    }

    /// Held commits validly touching `scope` (every held commit with `None`: decodes every header),
    /// newest first by `(ts, ID)`. Commits valid on no aspect in scope are left out.
    pub fn held_commits(&self, scope: Option<&[(Tid, Ak)]>) -> Vec<HeldCommit> {
        let ids: BTreeSet<(Ts, CommitId)> = match scope {
            Some(sc) => sc.iter().flat_map(|k| self.core.ix.by_aspect.get(k).into_iter().flatten().copied()).collect(),
            None => self.core.ix.commits.iter().map(|(id, m)| (m.view.ts, *id)).collect(),
        };
        let keep: Option<BTreeSet<&(Tid, Ak)>> = scope.map(|sc| sc.iter().collect());
        ids.into_iter()
            .rev()
            .filter_map(|(_, id)| {
                let m = self.core.ix.commits.get(&id)?;
                let header = m.header.decoded()?;
                let aspects: Vec<(Tid, Ak, bool)> = header
                    .aspects
                    .iter()
                    .enumerate()
                    .filter(|(ai, a)| m.valid_at(*ai) && keep.as_ref().is_none_or(|k| k.contains(&(a.tid, a.ak.clone()))))
                    .map(|(ai, a)| (a.tid, a.ak.clone(), !m.body_gone(ai)))
                    .collect();
                (!aspects.is_empty()).then_some(HeldCommit { id, header, received: m.received, aspects })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Mutation;
    use crate::error::Error;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_crdt::{Op, PathOp};
    use osis_schema::core_types as ct;

    // spec/commits.md §7: a kept snapshot excuses only the parts its tables reach. B writes
    // entry `k` keeping no history, unsynced; C then snapshots the map. A gets both and removes
    // `k` keeping history. B's part is neither kept nor reached by C's snapshot, so undoing the
    // removal (which would write back the map without `k`) is refused; with C having applied
    // B's write before its snapshot, the snapshot holds `k` and the undo brings it back.
    #[test]
    fn snapshot_excuses_only_what_it_reaches_spec_commits_7() {
        for seen in [false, true] {
            let mut lp = LocalPeer::new(3, 961, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let [a, b, c] = [0, 1, 2].map(|i| lp.peers[i].engine.me());
            let x = Ak::new("x:m.0").unwrap();
            let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, history: Some(osis_schema::History::Keep { until: None, after: Some(86_400_000) }) };
            let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
            for h in [b, c] {
                lp.peers[0].engine.grant(&t, &h, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
            }
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Map([(Value::Str("j".into()), Value::Int(1))].into_iter().collect())).unwrap().retention(t, &x, keep).unwrap();
            lp.peers[0].commit(m).unwrap().unwrap();
            lp.sync_all().unwrap();
            lp.advance(10);
            let mut m = Mutation::new();
            m.op(t, &x, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str("k".into()))], op: Op::Put(Value::Int(2)) }).unwrap();
            lp.peers[1].commit(m).unwrap().unwrap();
            if seen {
                lp.sync(1, 2).unwrap();
            }
            lp.advance(10);
            lp.peers[2].engine.snapshot(&t, &x).unwrap().unwrap();
            lp.sync(2, 0).unwrap();
            lp.sync(1, 0).unwrap();
            lp.advance(10);
            let before = lp.peers[0].engine.get(&t, &x).unwrap();
            let mut m = Mutation::new();
            m.op(t, &x, PathOp { path: Vec::new(), op: Op::Remove(Value::Str("k".into())) }).unwrap().retention(t, &x, keep).unwrap();
            let rm = lp.peers[0].commit(m).unwrap().unwrap();
            let e = &mut lp.peers[0].engine;
            match e.revert(&rm) {
                Err(Error::ContentGone(_)) => assert!(!seen, "the snapshot holds `k`"),
                Ok(Some(_)) => {
                    assert!(seen, "undone without `k`, which no kept part holds");
                    assert_eq!(e.get(&t, &x).unwrap(), before);
                }
                r => panic!("{r:?}"),
            }
        }
    }

    // `check_revertible` runs the revert's own writes in a transaction rolled back after: it
    // changes nothing, whatever it answers. A creates a thing (its creation's undo would delete
    // it) and sets register `x` twice keeping history, C overwriting the first. Probing the creation, the
    // first set (superseded) and the second (revertible) leaves the state, the clock, the
    // generations, the session counters and the events as they were; the revert then writes.
    #[test]
    fn check_revertible_changes_nothing() {
        let (mut lp, t, _, keep) = two(966);
        let x = Ak::new("x:r.0").unwrap();
        let set = |lp: &mut LocalPeer, i: usize, v: i64| {
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Int(v)).unwrap().retention(t, &x, keep).unwrap();
            lp.advance(10);
            lp.peers[i].commit(m).unwrap().unwrap()
        };
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let n = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(n, &x, &Value::Int(1)).unwrap();
        let made = lp.peers[0].commit(m).unwrap().unwrap();
        let first = set(&mut lp, 0, 1);
        lp.sync_all().unwrap();
        set(&mut lp, 1, 2);
        lp.sync_all().unwrap();
        let second = set(&mut lp, 0, 3);
        let p = &mut lp.peers[0];
        p.drain_events();
        let nonce = p.engine.core.session.nonce;
        let seen = |e: &mut crate::Engine| {
            let ctr = e.run(|tx| Ok((tx.txn.counter(&t, &x, &nonce)?, tx.txn.counter(&n, &x, &nonce)?))).unwrap();
            (e.get(&t, &x).unwrap(), e.get(&n, &x).unwrap(), e.core.hlc.last(), e.core.generation, e.core.memory_generation, ctr, e.commit_ids().len())
        };
        let before = seen(&mut p.engine);
        assert!(p.engine.check_revertible(&made).unwrap());
        assert!(!p.engine.check_revertible(&first).unwrap(), "C overwrote it");
        assert!(p.engine.check_revertible(&second).unwrap());
        assert_eq!(seen(&mut p.engine), before);
        assert!(p.drain_events().is_empty());
        p.engine.revert(&second).unwrap().unwrap();
    }

    /// What one check of `shape`'s newest commit costs after `n` commits to a text field kept
    /// past replacement (written whole: until a date; typing: for a while after replaced, the case that
    /// judges each part against the state): right after a commit to the field (nothing about it known), as
    /// `(commits read, whole states copied)`. The check agrees with the revert.
    fn check_cost(shape: &str, n: usize) -> (u64, u64) {
        static TS: osis_schema::StaticSchema = osis_schema::StaticSchema::new("t.osis", "revision 1; purgeable_by(author, admin) aspect k:t.0: text;\n");
        let key: osis_schema::Aspect<Value> = osis_schema::Aspect::new("k:t.0", &TS);
        let x = Ak::new("k:t.0").unwrap();
        let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, history: Some(if shape == "whole" { osis_schema::History::Keep { until: Some(4_000_000_000_000), after: None } } else { osis_schema::History::Keep { until: None, after: Some(86_400_000) } }) };
        let mut lp = LocalPeer::new(1, 977, WallMs(1_700_000_000_000)).unwrap();
        let a = lp.peers[0].engine.me();
        let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
        let (mut last, mut text) = (None, String::new());
        for i in 0..n {
            lp.advance(10);
            text.push('a');
            let op = if shape == "whole" { Op::Replace(Value::Str(text.clone())) } else { Op::Insert { at: i, items: vec![Value::Str("a".into())] } };
            let mut m = Mutation::new();
            m.op(t, &key, PathOp { path: vec![], op }).unwrap().retention(t, &x, keep).unwrap();
            last = lp.peers[0].commit(m).unwrap();
        }
        let last = last.unwrap();
        let e = &mut lp.peers[0].engine;
        crate::costs::take();
        assert!(e.check_revertible(&last).unwrap());
        let c = crate::costs::take();
        let count = |name: &str| c.iter().find(|x| x.0 == name).map_or(0, |x| x.2);
        let cost = (count("commit read"), count("state copied whole"));
        e.revert(&last).unwrap().unwrap();
        text.pop();
        assert_eq!(e.get(&t, &x).unwrap(), Some(Value::Str(text)));
        cost
    }

    // The check never copies the state per part (quadratic in the history), a field written whole
    // reads the same few commits however long its history, and typing reads each kept part
    // a bounded number of times (issues/undo-target-cost.md: no index says which parts touch a
    // position).
    #[test]
    fn check_cost_scales() {
        let [whole_small, whole_big] = [30, 120].map(|n| check_cost("whole", n));
        assert_eq!(whole_small, whole_big, "written whole: the cost grows with the history");
        let [typing_small, typing_big] = [30, 120].map(|n| check_cost("typing", n));
        assert_eq!((typing_small.1, typing_big.1), (0, 0), "a whole state copied per part");
        assert!(typing_big.0 <= 4 * typing_small.0 + 8, "typing: more than linear: {typing_small:?} {typing_big:?}");
    }

    /// `f` is `Value::Map` of `(key, int)` pairs on aspect `x`.
    fn map_of(p: &[(&str, i64)]) -> Value {
        Value::Map(p.iter().map(|(k, v)| (Value::Str((*k).into()), Value::Int(*v))).collect())
    }

    fn put(lp: &mut LocalPeer, who: usize, t: osis_base::Tid, x: &Ak, k: &str, v: i64, keep: osis_schema::Retention) -> osis_base::CommitId {
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, x, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str(k.into()))], op: Op::Put(Value::Int(v)) }).unwrap().retention(t, x, keep).unwrap();
        lp.peers[who].commit(m).unwrap().unwrap()
    }

    fn replace(lp: &mut LocalPeer, who: usize, t: osis_base::Tid, x: &Ak, v: Value, keep: osis_schema::Retention, expires: Option<WallMs>) -> osis_base::CommitId {
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, x, PathOp { path: vec![], op: Op::Replace(v) }).unwrap().retention(t, x, keep).unwrap();
        if let Some(e) = expires {
            m.expires(t, x, e).unwrap();
        }
        lp.peers[who].commit(m).unwrap().unwrap()
    }

    // spec/crdt.md §4.2: a reset prunes by stamp, so the walk stops at the newest kept reset
    // whichever writes are concurrent with it, and a write stamped after it stays in. Each
    // revert also runs `kept_before`'s check against the whole join.
    #[test]
    fn pre_state_stops_at_a_reset_by_stamp() {
        for reset_first in [false, true] {
            let (mut lp, t, x, keep) = two(963);
            replace(&mut lp, 0, t, &x, map_of(&[("o", 0)]), keep, None);
            lp.sync_all().unwrap();
            let concurrent = |lp: &mut LocalPeer| { put(lp, 1, t, &x, "k", 1, keep); };
            let reset = |lp: &mut LocalPeer| { replace(lp, 0, t, &x, map_of(&[("j", 1)]), keep, None); };
            if reset_first {
                reset(&mut lp);
                concurrent(&mut lp);
            } else {
                concurrent(&mut lp);
                reset(&mut lp);
            }
            lp.sync_all().unwrap();
            let before = lp.peers[0].engine.get(&t, &x).unwrap();
            assert_eq!(before, Some(if reset_first { map_of(&[("j", 1), ("k", 1)]) } else { map_of(&[("j", 1)]) }), "a reset prunes what is stamped before it, seen or not");
            let last = put(&mut lp, 0, t, &x, "j", 2, keep);
            lp.peers[0].engine.revert(&last).unwrap().unwrap();
            assert_eq!(lp.peers[0].engine.get(&t, &x).unwrap(), before);
        }
    }

    // An expired reset still resets (its leftover holds it), a purged one is left behind by the
    // purge's own reset, and an invalid one gives nothing, so the walk passes it. Either way the
    // undo reads as the whole join does.
    #[test]
    fn pre_state_at_a_reset_gone_or_invalid() {
        for case in ["expired", "purged", "invalid"] {
            let (mut lp, t, x, keep) = two(964);
            let expires = (case == "expired").then(|| WallMs(lp.peers[0].engine.now().0 + 100));
            replace(&mut lp, 0, t, &x, map_of(&[("j", 1)]), keep, None);
            lp.sync_all().unwrap();
            let r = replace(&mut lp, 1, t, &x, map_of(&[("r", 1)]), keep, expires);
            if case != "invalid" {
                lp.sync_all().unwrap();
            }
            match case {
                "expired" => {
                    lp.advance(1000);
                    (0..2).for_each(|i| lp.peers[i].engine.tick().unwrap());
                }
                "purged" => {
                    lp.advance(10);
                    let mut m = Mutation::new();
                    m.purge(osis_commit::PurgeItem::Commit { commit: r, tid: t, ak: x.clone() }).op(t, &x, PathOp { path: vec![], op: Op::Replace(map_of(&[("p", 1)])) }).unwrap().retention(t, &x, keep).unwrap();
                    lp.peers[0].commit(m).unwrap();
                }
                _ => {
                    // not seen by the demoter, so not vouched for
                    let c = lp.peers[1].engine.me();
                    lp.peers[0].engine.demote(&t, &crate::flows::Demotion { holder: c, new: None, retain: None }).unwrap();
                }
            }
            lp.sync_all().unwrap();
            let before = lp.peers[0].engine.get(&t, &x).unwrap();
            let want_before = match case {
                "invalid" => Some(map_of(&[("j", 1)])),
                "purged" => Some(map_of(&[("p", 1)])),
                _ => None,
            };
            assert_eq!(before, want_before, "{case}");
            let last = put(&mut lp, 0, t, &x, "k", 2, keep);
            lp.peers[0].engine.revert(&last).unwrap().unwrap();
            assert_eq!(lp.peers[0].engine.get(&t, &x).unwrap(), before, "{case}");
        }
    }

    // A and C, a thing of A's that C may write, map aspect `x`, and a keep-history retention.
    fn two(seed: u64) -> (LocalPeer, osis_base::Tid, Ak, osis_schema::Retention) {
        let mut lp = LocalPeer::new(2, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let [a, c] = [0, 1].map(|i| lp.peers[i].engine.me());
        let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, history: Some(osis_schema::History::Keep { until: None, after: Some(86_400_000) }) };
        let (t, _) = lp.peers[0].engine.create_with_admin(&a).unwrap();
        lp.peers[0].engine.grant(&t, &c, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        lp.sync_all().unwrap();
        lp.advance(10);
        (lp, t, Ak::new("x:m.0").unwrap(), keep)
    }

    // A removes entry `k` keeping history and undoes the removal.
    fn remove_k(lp: &mut LocalPeer, t: osis_base::Tid, x: &Ak, keep: osis_schema::Retention) -> crate::error::Result<Option<osis_base::CommitId>> {
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, x, PathOp { path: Vec::new(), op: Op::Remove(Value::Str("k".into())) }).unwrap().retention(t, x, keep).unwrap();
        let rm = lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.revert(&rm)
    }

    // spec/commits.md §7: a snapshot part not kept is excused by no snapshot, whether or not
    // the node holds the parts that wrote it. C writes `k` keeping no history and snapshots;
    // A, holding C's delta or only the snapshot, removes `k`: no kept part holds `k`.
    #[test]
    fn unkept_snapshot_without_its_writers_spec_commits_7() {
        for headers in [true, false] {
            let (mut lp, t, x, keep) = two(961);
            let mut m = Mutation::new();
            m.set(t, &x, &Value::Map([(Value::Str("k".into()), Value::Int(2))].into_iter().collect())).unwrap();
            let d = lp.peers[1].commit(m).unwrap().unwrap();
            lp.advance(10);
            lp.peers[1].engine.snapshot(&t, &x).unwrap().unwrap();
            for pk in lp.packages(1).unwrap() {
                if headers || pk.id != d {
                    lp.deliver(0, &pk).unwrap();
                }
            }
            assert!(matches!(remove_k(&mut lp, t, &x, keep), Err(Error::ContentGone(_))), "headers {headers}");
        }
    }

    // Delivers `from`'s commits `to` peer `to`, `id` without its parts on `leave`'s thing (held
    // as missing there).
    fn deliver_leaving(lp: &mut LocalPeer, from: usize, to: usize, id: osis_base::CommitId, leave: osis_base::Tid) {
        for pk in lp.packages(from).unwrap() {
            let bytes = if pk.id == id {
                let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
                osis_commit::rewrite(&b, |ai| b.header.aspects[ai].tid == leave).encode()
            } else {
                pk.bytes.clone()
            };
            lp.peers[to].receive(&bytes, pk.blobs.clone()).unwrap();
        }
    }

    // A and B, things of A's that B may write, register aspects `x` and `y`.
    fn writable(seed: u64, n: usize) -> (LocalPeer, Vec<osis_base::Tid>, Ak, Ak) {
        let mut lp = LocalPeer::new(2, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let [a, b] = [0, 1].map(|i| lp.peers[i].engine.me());
        let ts: Vec<_> = (0..n).map(|_| lp.peers[0].engine.create_with_admin(&a).unwrap().0).collect();
        for t in &ts {
            lp.peers[0].engine.grant(t, &b, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        }
        lp.sync_all().unwrap();
        lp.advance(10);
        (lp, ts, Ak::new("x:r.0").unwrap(), Ak::new("y:r.0").unwrap())
    }

    // spec/commits.md §7: an undo reverts every part of the commit or there is none, alike at
    // every node. T writes `x` on P and `y` on Q; B holds T's part on Q as missing. A's undo
    // reverts both; B's is `ContentGone`, never an undo of `x` alone, until the part arrives.
    #[test]
    fn undo_needs_every_part_held_spec_commits_7() {
        let (mut lp, ts, x, y) = writable(963, 2);
        let (p, q) = (ts[0], ts[1]);
        let mut m = Mutation::new();
        m.set(p, &x, &Value::Int(1)).unwrap().set(q, &y, &Value::Int(1)).unwrap();
        let t = lp.peers[0].commit(m).unwrap().unwrap();
        deliver_leaving(&mut lp, 0, 1, t, q);
        lp.advance(10);
        let b = &mut lp.peers[1].engine;
        assert!(matches!(b.revert(&t), Err(Error::ContentGone(_))), "B holds T's part on Q as missing");
        assert!(matches!(b.check_revertible(&t), Err(Error::ContentGone(_))));
        assert_eq!(b.get(&p, &x).unwrap(), Some(Value::Int(1)), "nothing reverted");
        lp.sync(0, 1).unwrap();
        lp.peers[1].engine.check_revertible(&t).unwrap();
        let a = &mut lp.peers[0].engine;
        a.revert(&t).unwrap().unwrap();
        assert_eq!((a.get(&p, &x).unwrap(), a.get(&q, &y).unwrap()), (None, None));
    }

    // spec/crdt.md §4.6: undoing a creation deletes the thing, alike at every node: B holds the
    // header of A's later write of `y` on N but not its body; B's undo of N's creation resets `y`
    // too (it may hold content), so once synced N has no content.
    #[test]
    fn undo_creation_resets_unfetched_writes_spec_crdt_4_6() {
        let (mut lp, ts, x, y) = writable(964, 1);
        let [a, b] = [0, 1].map(|i| lp.peers[i].engine.me());
        let mut m = Mutation::new();
        let n = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(n, &x, &Value::Int(1)).unwrap().set(ts[0], &x, &Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].engine.grant(&n, &b, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None }).unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.set(n, &y, &Value::Int(2)).unwrap();
        let w = lp.peers[0].commit(m).unwrap().unwrap();
        deliver_leaving(&mut lp, 0, 1, w, n);
        lp.advance(10);
        assert_eq!(lp.peers[1].engine.get(&n, &y).unwrap(), None, "B holds `y`'s header only");
        lp.peers[1].engine.revert(&c).unwrap().unwrap();
        lp.sync(1, 0).unwrap();
        let e = &mut lp.peers[0].engine;
        assert_eq!((e.get(&n, &x).unwrap(), e.get(&n, &y).unwrap(), e.get(&ts[0], &x).unwrap()), (None, None, None));
    }

    // spec/crdt.md §4.6: a part not received yet that a held reset stamped after it covers holds
    // no content, so a delete leaves its aspect alone (it may never arrive: holders drop it as
    // covered). B holds W's part on `y` as missing, then A's removal of `y`.
    #[test]
    fn delete_skips_covered_unfetched_writes_spec_crdt_4_6() {
        let (mut lp, ts, _, y) = writable(965, 1);
        let p = ts[0];
        let mut m = Mutation::new();
        m.set(p, &y, &Value::Int(1)).unwrap();
        let w = lp.peers[0].commit(m).unwrap().unwrap();
        deliver_leaving(&mut lp, 0, 1, w, p);
        lp.advance(10);
        assert_eq!(lp.peers[1].engine.deleted_aspects(&p).unwrap(), vec![y.clone()], "W's part may hold content");
        let mut m = Mutation::new();
        m.remove_aspect(p, &y).unwrap();
        let r = lp.peers[0].commit(m).unwrap().unwrap();
        for pk in lp.packages(0).unwrap().into_iter().filter(|pk| pk.id == r) {
            lp.peers[1].receive(&pk.bytes, pk.blobs.clone()).unwrap();
        }
        assert_eq!(lp.peers[1].engine.deleted_aspects(&p).unwrap(), Vec::<Ak>::new(), "the removal covers W");
    }

    // spec/commits.md §7, spec/crdt.md §8: a snapshot holds an expiring delta's writes
    // value-less, so reaching it excuses nothing. C writes `k` expiring, keeping no history,
    // and snapshots the map (kept: A's `j` lives in it); A removes `k`.
    #[test]
    fn snapshot_excuses_no_expiring_part_spec_commits_7() {
        let (mut lp, t, x, keep) = two(962);
        let mut m = Mutation::new();
        m.set(t, &x, &Value::Map([(Value::Str("j".into()), Value::Int(1))].into_iter().collect())).unwrap().retention(t, &x, keep).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync(0, 1).unwrap();
        lp.advance(10);
        let mut m = Mutation::new();
        m.op(t, &x, PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Str("k".into()))], op: Op::Put(Value::Int(2)) }).unwrap().expires(t, &x, WallMs(1_800_000_000_000)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(10);
        lp.peers[1].engine.snapshot(&t, &x).unwrap().unwrap();
        lp.sync(1, 0).unwrap();
        assert!(matches!(remove_k(&mut lp, t, &x, keep), Err(Error::ContentGone(_))));
    }
}
