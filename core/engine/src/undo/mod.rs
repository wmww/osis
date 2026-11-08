//! Revert, an undo commit (spec/commits.md §7, spec/crdt.md §4.6), of a durable or an ephemeral
//! commit alike: stacks, scopes and redo live in the `osis` crate (`held_commits`). An undo
//! commit's deltas come from osis-crdt's `undo` against the current state and the state before
//! the undone commit as kept history gives it (`kept_before`): never from a body held but not
//! kept, so whether an undo works and what it writes is alike at every node holding the same
//! commits. Where the inverse writes back replaced content (`osis_crdt::restores`, by the
//! writes' kinds) and a part it may have replaced is not kept (`replaced_kept`), it is
//! `ContentGone`.

use crate::engine::records::Rd;
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
    /// Its inverse writes back content no kept history holds (`Error::ContentGone`).
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
    Ok(crate::retention::bounds::body_live(tx, c, tid, ak)? || crate::retention::bounds::body_keep(tx, c, tid, ak)? > now)
}

/// The state of `(tid, ak)` just before the commit at `at`, as kept history gives it: the join
/// of the parts ordered before it that are `kept`. A part replaced and not kept is left out,
/// held or not.
fn kept_before(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, at: (Ts, CommitId)) -> Result<Fragment> {
    let now = tx.now().0;
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
/// live is in that snapshot). A snapshot has no writes of its own: what it carries is judged
/// through the parts that wrote it. Any other part counts unless it is `kept` or, held or
/// dropped, its retention would keep it now had this write replaced it (then, not kept, it was
/// replaced earlier). A part not fetched yet counts (notes/listener-design.md), and so does a
/// memory commit forgotten here (`Indexes::forgotten`) unless a reset stamped after it is kept:
/// its header is gone, so no snapshot can be shown to reach it. By headers and kept history
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
        if !m.header.kind.has_own_writes() {
            continue;
        }
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
        osis_crdt::SourceKind::Session(s) if ak.ephemeral() && !core.own_plain(&s.nonce) => Some(0),
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
/// `confined`: every write it makes is held to `actor`'s rights (`Engine::revert_as`). It
/// expires with the writes it copies back, refused while those expire differently
/// (`copy_expiry`); an ephemeral one copying back an expiring value is under the open's
/// expiring session (spec/crdt.md §2.1). `ContentGone` when its inverse writes back replaced
/// content not kept (`replaced_kept`).
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Option<Ts>, confined: bool) -> Result<CommitId> {
    let m = tx.core.ix.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let memory = m.view.memory;
    let node = tx.core.id.tid();
    let ts = ts.unwrap_or_else(|| tx.core.hlc.next());
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
    let (deltas, expires) = loop {
        let unmade = unmake_ops(tx, &made, ts, node, writers)?;
        let (deltas, copies) = inverse(tx, &parts, unmade, ts, nonce)?;
        // tests: a writer predating the undo expiry rule (spec/crdt.md §4.6)
        let expires = if tx.core.skip_writer_rules { None } else { copy_expiry(&copies)? };
        if !memory || expires.is_none() || nonce == expiring {
            break (deltas, expires);
        }
        nonce = expiring;
    };
    let mut deltas = deltas;
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    deltas.iter_mut().for_each(|d| d.expires = expires);
    // rights: its own commit applies only if valid here, as at every receiver (`apply_local`)
    check_acts(tx.core, node, &|_| None, &actor, ts)?;
    if confined {
        crate::engine::acting::check_undo(tx, actor, &deltas, ts)?;
    }
    // an undo writes under this open's session, like any content commit (spec/commits.md §3)
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form: Form::Session(nonce), creates: Default::default(), purge: Vec::new(), undoes: Some(target), frontier: None, signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false };
    build_one(tx, plan, deltas)
}

/// The parts of content commit `target` its undo inverts, each with its delta and its writer's
/// source; `ContentGone` when one writes back replaced content (`osis_crdt::restores`) not kept at
/// wall ms `now` (`replaced_kept`). Left out: a part whose body was dropped (spec/commits.md
/// §7), one invalid here, a signal's (it reads absent before and after), the creation record and
/// the parts on things the commit created (those are deleted, `unmake_ops`).
fn undone_parts(tx: &mut Tx<'_>, target: &CommitId, now: u64) -> Result<Vec<(osis_commit::AspectEntry, Fragment, Source)>> {
    let m = tx.core.ix.commits.get(target).cloned().ok_or(Error::UnknownCommit(*target))?;
    let h = m.header.clone();
    let made = made_by(&h, &m.valid);
    let mut parts = Vec::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if m.dropped.contains_key(&ai) || !m.valid_at(ai) || a.ak.signal() || a.ak.as_str() == CREATED.ak() || a.ak.as_str() == osis_commit::retention::REQUIRED || made.contains(&a.tid) {
            continue;
        }
        let Some(Decoded::Delta(d)) = crate::apply::held_part(tx, target, ai)? else { continue };
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
    let own = Form::Session(nonce).own_source(tx.core.id.tid(), CommitId([0; 32]));
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
/// `made`, its held durable aspects reset (not `created.0` or role-class ones; its ephemeral
/// ones go in the revert's memory commit, `Engine::revert_batch`) and its entries
/// removed from every `group.0` listing it that all of `writers` may write (this node, a
/// confined revert's actor too), each resolved after the undo's own delta of that aspect and
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
        let prefix = [crate::engine::records::ASPECTS, x.as_bytes()].concat();
        let mut aks = Vec::new();
        tx.scan(&prefix, |k, _| {
            aks.push(Rd::new(k).ak()?);
            Ok(())
        })?;
        for ak in aks.into_iter().filter(|a| osis_schema::core_types::is_content(a.as_str()) && !a.ephemeral()) {
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
    /// there is nothing to write; `ContentGone` (`Error`) when its inverse needs content no kept
    /// history holds; `Clash` if its writes cannot share a commit.
    pub fn revert(&mut self, target: &CommitId) -> Result<Option<CommitId>> {
        let me = self.tid();
        match self.revert_commit(*target, me)? {
            Reverted::Written(w) => Ok(Some(w.id)),
            Reverted::Superseded => Ok(None),
            Reverted::ContentGone => Err(Error::ContentGone(*target)),
        }
    }

    /// `ContentGone` when reverting held content commit `c` now writes back content no kept
    /// history holds, by its writes' kinds and keep bounds alone (what `revert_commit` checks
    /// first; whether it then writes anything is not judged).
    pub fn check_revertible(&mut self, c: &CommitId) -> Result<()> {
        let c = *c;
        let now = self.now().0;
        self.run(|tx| undone_parts(tx, &c, now).map(drop))
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
        let node = self.tid();
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
            let [a, b, c] = [0, 1, 2].map(|i| lp.peers[i].engine.tid());
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
}
