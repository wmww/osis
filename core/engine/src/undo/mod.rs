//! Revert, an undo commit (spec/commits.md §7, spec/crdt.md §4.6): stacks, scopes and redo
//! live in the `osis` crate (`held_commits`); an undo commit's deltas come
//! from osis-crdt's `undo` against the current state and the undo buffer, which holds the
//! pre-commit state of this node's recent local commits (in the aspect's store unit, cleared
//! whenever a body of the aspect is dropped).

use crate::engine::records::{Rd, Wr};
use crate::engine::write::{CommitPlan, Resolved, build_one};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Kind};
use osis_base::{Ak, CommitId, Role, Tid, Ts, Value};
use osis_schema::RawKey;
use osis_schema::core_types::GROUP;
use osis_crdt::{AnyView, CounterRange, Dot, Fragment, Op, PathOp, PathSeg, Undone, Writer};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Local commits per aspect whose pre-commit state is kept.
pub const UNDO_DEPTH: usize = 16;

fn decode_buffer(b: &[u8]) -> Result<Vec<(CommitId, Vec<u8>)>> {
    let mut r = Rd::new(b);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push((CommitId(r.arr()?), r.bytes()?.to_vec()));
    }
    Ok(out)
}

/// The pre-write footprint `remember` kept for commit `c` on `(tid, ak)` (the ephemeral undo
/// log copies it when a batch applies).
pub(crate) fn remembered(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak) -> Result<Option<Fragment>> {
    let buffer = decode_buffer(&tx.unit(tid, ak)?.undo)?.into_iter().find(|x| x.0 == *c).map(|x| x.1);
    match buffer {
        Some(b) if !b.is_empty() => Ok(Some(crate::engine::state::decode(&b)?)),
        Some(_) => Ok(Some(Fragment::default())),
        None => Ok(None),
    }
}

/// Joins into `acc` the part of the state of `(tid, ak)` that undoing `piece` of a delta reads
/// (`Fragment::footprint`; of a delta's pieces, their join is the delta's): a paged state loads
/// what the piece touches, then drops it again. `acc` stays `None` while there is no state.
pub(crate) fn footprint(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, piece: &Fragment, acc: &mut Option<Fragment>) -> Result<()> {
    tx.load_lazy(tid, ak)?;
    let touch = crate::engine::pages::touch_of(piece, tx.core.pages.get(&(*tid, ak.clone())));
    tx.ensure_touch(tid, ak, &touch)?;
    if let Some(f) = tx.cached(tid, ak) {
        let fp = f.footprint(piece);
        match acc {
            Some(a) => {
                a.join(fp);
            }
            None => *acc = Some(fp),
        }
    }
    tx.evict_pages(tid, ak);
    Ok(())
}

/// Records the state of `(tid, ak)` before local commit `id` applies: `pre`, the part undoing
/// its delta reads (`footprint`; `Some(None)`: there was no state), or all of it (`None`: not
/// one delta).
pub(crate) fn remember(tx: &mut Tx<'_>, id: &CommitId, tid: &Tid, ak: &Ak, pre: Option<Option<Fragment>>) -> Result<()> {
    let pre = match pre {
        Some(fp) => fp.as_ref().map(crate::engine::state::encode).transpose()?.unwrap_or_default(),
        None => {
            tx.load(tid, ak)?;
            tx.cached(tid, ak).map(crate::engine::state::encode).transpose()?.unwrap_or_default()
        }
    };
    let mut unit = tx.unit(tid, ak)?;
    let mut list = decode_buffer(&unit.undo)?;
    list.push((*id, pre));
    if list.len() > UNDO_DEPTH {
        list.remove(0);
    }
    let mut w = Wr::new();
    for (c, s) in &list {
        w = w.raw(&c.0).bytes(s);
    }
    unit.undo = w.take();
    tx.txn.put_aspect(tid, ak, &unit, Shred::No)?;
    Ok(())
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
    pre.expire(&|d| expiry(d).is_some_and(|t| t <= wall));
    let out = match schema.and_then(|s| s.view(ak.as_str())) {
        Some(v) => osis_crdt::undo(&mut w, undone, state, &pre, &v)?,
        None => osis_crdt::undo(&mut w, undone, state, &pre, &AnyView)?,
    };
    let copies = w.copied().iter().map(expiry).filter(|t| t.is_none_or(|t| t > wall)).collect();
    Ok(out.map(|f| (f, w.range(), copies)))
}

/// The one expiry of an undo writing back values that expire at `copies` (`None`: never;
/// spec/crdt.md §4.7 copy expiry). An undo is one commit with one expiry, so it is refused while
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

/// Builds and applies the undo commit of `target` (spec/crdt.md §4.6): the things it created
/// are deleted. `confined`: every write it makes is held to
/// `actor`'s rights (`Engine::revert_as`). It expires with the writes it copies back, refused
/// while those expire differently (`copy_expiry`).
pub(crate) fn undo_in(tx: &mut Tx<'_>, target: CommitId, actor: Tid, ts: Option<Ts>, confined: bool) -> Result<CommitId> {
    let m = tx.core.ix.commits.get(&target).cloned().ok_or(Error::UnknownCommit(target))?;
    let h = m.header.clone();
    if !matches!(h.kind, Kind::Content) {
        return Err(Error::Misuse("only content commits are undone here"));
    }
    let node = tx.core.id.tid();
    let ts = ts.unwrap_or_else(|| tx.core.hlc.next());
    let mut deltas = Vec::new();
    let mut copies = Copies::new();
    let made = made_by(&h, &m.valid);
    let writers: &[Tid] = if confined { &[node, actor] } else { &[node] };
    let mut unmade = unmake_ops(tx, &made, ts, node, writers)?;
    // an undo writes under this open's session, like any content commit (spec/commits.md §3)
    let form = Form::Session(tx.core.session.nonce);
    let own = form.own_source(node, CommitId([0; 32]));
    for (ai, a) in h.aspects.iter().enumerate() {
        // a commit whose body was dropped cannot be undone (spec/commits.md §7); a thing it
        // created is deleted below instead; a signal always reads absent, so reads as before
        if m.dropped.contains_key(&ai) || !m.valid_at(ai) || a.ak.signal() || a.ak.as_str() == "created.0" || a.ak.as_str() == osis_commit::retention::REQUIRED || made.contains(&a.tid) {
            continue;
        }
        let Some(Decoded::Delta(d)) = crate::apply::held_part(tx, &target, ai)? else { continue };
        let source = h.form.own_source(h.author, target);
        let buffer = decode_buffer(&tx.unit(&a.tid, &a.ak)?.undo)?.into_iter().find(|x| x.0 == target).map(|x| x.1);
        let mut pre = match buffer {
            Some(b) if !b.is_empty() => crate::engine::state::decode(&b)?,
            Some(_) => Fragment::default(),
            // not a recent local commit: the join of the held bodies ordered before it
            None => {
                let held: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().copied().filter(|x| *x < (h.ts, target)).collect();
                let mut f = Fragment::default();
                for (_, c) in held {
                    let Some(m) = tx.core.ix.commits.get(&c) else { continue };
                    let Some(ci) = m.valid.iter().zip(&m.header.aspects).position(|(v, x)| *v && x.tid == a.tid && x.ak == a.ak) else { continue };
                    if let Some(d) = crate::apply::held_part(tx, &c, ci)? {
                        f.join(d.into_fragment());
                    }
                }
                f
            }
        };
        crate::apply::strip_valueless(tx.core, &a.tid, &a.ak, &mut pre);
        let undone = Undone { delta: &d.fragment, source: &source, range: CounterRange { lo: a.lo, hi: a.hi } };
        let schema = tx.core.schemas.get(a.ak.as_str()).cloned().or_else(|| osis_schema::core_types::is_core_key(a.ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone())));
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
                let touch = crate::engine::pages::touch_of(&d.fragment, tx.core.pages.get(&(a.tid, a.ak.clone())));
                tx.ensure_touch(&a.tid, &a.ak, &touch)?;
            }
            let lo = tx.txn.counter(&a.tid, &a.ak, &tx.core.session.nonce)?;
            let empty = Fragment::default();
            let state = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).unwrap_or(&empty);
            let w = Writer::new(ts, own.clone(), lo).keyed_removals(osis_schema::core_types::is_role_class(a.ak.as_str()));
            let core = &*tx.core;
            let expiry = |d: &Dot| core.write_expiry(&a.tid, &a.ak, d).flatten();
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
                unmake_one(tx, (a.tid, a.ak.clone()), ops, ts, &own, &mut deltas)?;
            }
        }
    }
    for (k, ops) in unmade {
        unmake_one(tx, k, ops, ts, &own, &mut deltas)?;
    }
    if deltas.is_empty() {
        return Err(Error::Misuse("nothing to undo"));
    }
    // tests: a writer predating the copy expiry rule (spec/crdt.md §4.7)
    if !tx.core.skip_writer_rules {
        let expires = copy_expiry(&copies)?;
        deltas.iter_mut().for_each(|d| d.expires = expires);
    }
    // rights: its own commit applies only if valid here, as at every receiver (`apply_local`)
    crate::engine::write::check_acts(tx.core, tx.core.id.tid(), &|_| None, &actor, ts)?;
    if confined {
        crate::engine::acting::check_undo(tx, actor, &deltas, ts)?;
    }
    let plan = CommitPlan { kind: Kind::Content, ts, actor, form, creates: Default::default(), purge: Vec::new(), undoes: Some(target), frontier: None, signer: tx.core.id.tid(), blind: crate::engine::write::draw_blind(&mut *tx.rng), expires: None, restores: false };
    build_one(tx, plan, deltas)
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

/// Runs `unmake_ops`' ops on `k` under the undo's own source `own`, joined into the undo's
/// delta of `k` when it is the last one in `deltas` (its counters the last allocated).
fn unmake_one(tx: &mut Tx<'_>, (tid, ak): (Tid, Ak), ops: Vec<PathOp>, ts: Ts, own: &osis_crdt::Source, deltas: &mut Vec<Resolved>) -> Result<()> {
    let mut state = tx.state(&tid, &ak)?.cloned().unwrap_or_default();
    let joined = deltas.last().is_some_and(|d| d.tid == tid && d.ak == ak);
    // joined: one delta, so its commit-level writes keep that delta's stamp (spec/crdt.md §2.3)
    let (lo, resume) = match deltas.last() {
        Some(d) if joined => {
            state.join(d.fragment.clone());
            (d.lo, d.hi)
        }
        _ => {
            let c = tx.txn.counter(&tid, &ak, &crate::engine::write::nonce_of(Form::Session(tx.core.session.nonce)))?;
            (c, c)
        }
    };
    let schema = osis_schema::core_types::is_core_key(ak.as_str()).then(|| std::sync::Arc::new(osis_schema::core_schema().clone()));
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
    /// there is nothing to write; `Clash` if its writes cannot share a commit.
    pub fn revert(&mut self, target: &CommitId) -> Result<Option<CommitId>> {
        let t = *target;
        let me = self.tid();
        match self.run(|tx| undo_in(tx, t, me, None, false)).map(Some) {
            Err(Error::Misuse("nothing to undo")) => Ok(None),
            r => r,
        }
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
                // this session's own memory commits are listed as the batches that made them
                // (the undo log), not as commits
                if self.own_memory_commit(&id) {
                    return None;
                }
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
