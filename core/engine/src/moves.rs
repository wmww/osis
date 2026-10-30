//! Moving a thing (spec/permissions.md §7): a copy M under a new owner that imports T's
//! history. One import commit per origin commit (each delta carries its origin delta's
//! retention and schema), `/was` on M; the guard against importing a thing a held copy already
//! continues. Each write is imported from one origin: the newest held compaction snapshot of
//! its aspect where that covers it (its frontier holds the write's counter, or it carries writes
//! of the write's commit-form commit) and carries it, else its own commit. A write of origin C
//! gets the dot `(Commit(C), k)` (k its counter in C, or for a snapshot its rank by (source,
//! counter) among the writes the snapshot carries on the aspect), and references to writes (anchors,
//! reset stamps) map the same way. A frontier is not trusted alone: a write it claims but the
//! snapshot does not carry is imported from its commit while the current state holds it.
//! Resolution of moved tids in reads lives in `engine/read.rs`.

use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Core, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_commit::{Decoded, Form, Header, Kind, Origin};
use osis_base::{Ak, CommitId, SchemaId, Tid, Ts};
use osis_crdt::{Dot, Fragment, Shown, Source, SourceKind};
use osis_schema::core_types as ct;
use osis_schema::core_types::is_membership_class;
use std::collections::{BTreeMap, BTreeSet};

/// The snapshot an aspect's writes are imported from where it carries them: its ID, its
/// carried writes by rank, and its frontiers.
struct Carrier {
    id: CommitId,
    ts: Ts,
    rank: BTreeMap<Dot, u64>,
    frontiers: osis_crdt::Frontiers,
}

impl Carrier {
    /// Whether the snapshot covers the write with owner dot `x`: its frontier holds the counter
    /// of a node-form write; it carries writes of a commit-form write's commit.
    fn covers_dot(&self, x: &Dot) -> bool {
        match x.src.kind() {
            SourceKind::Node(n) => self.frontiers.0.get(n).is_some_and(|f| *f >= x.ctr),
            SourceKind::Commit(c) => self.rank.keys().any(|d| matches!(d.src.kind(), SourceKind::Commit(y) if y == c)),
            _ => false,
        }
    }

    /// Whether the snapshot claims every write of ordinary commit `c` (spec/crdt.md §8: up to
    /// its frontiers; commit-form writes when it carries some of them).
    fn covers(&self, h: &Header, c: &CommitId, ai: usize) -> bool {
        if h.ts >= self.ts {
            return false;
        }
        let Some(a) = h.aspects.get(ai) else { return false };
        match h.form {
            Form::Node => self.frontiers.0.get(&h.author).is_some_and(|f| a.hi > 0 && *f >= a.hi - 1),
            Form::Commit => self.rank.keys().any(|d| matches!(d.src.kind(), SourceKind::Commit(x) if x == c)),
        }
    }
}

/// The dot an imported write or reference gets (spec/permissions.md §7): covered and carried by
/// the snapshot origin, its rank there; else its own commit's ID with its counter (a carried
/// write whose commit is not held: its rank).
fn imported(core: &Core, tid: &Tid, ak: &Ak, carrier: Option<&Carrier>, own: Option<(&Source, &CommitId, Form, u64, u64)>, x: &Dot) -> Option<Dot> {
    let rank = carrier.and_then(|s| Some((s.id, *s.rank.get(x)?, s.covers_dot(x))));
    if let Some((s, r, true)) = rank {
        return Some(Dot::new(Source::commit(s), r));
    }
    if let Some((src, c, form, lo, hi)) = own
        && x.src == *src
        && (form == Form::Commit || (lo <= x.ctr && x.ctr < hi))
    {
        return Some(Dot::new(Source::commit(*c), x.ctr));
    }
    // a commit that is itself imported (held, valid, kept): its own dot
    if let SourceKind::Node(_) = x.src.kind()
        && from_own(core, tid, ak, x)
        && let Some(k) = core.commit_of(tid, ak, x)
    {
        return Some(Dot::new(Source::commit(k), x.ctr));
    }
    rank.map(|(s, r, _)| Dot::new(Source::commit(s), r))
}

/// Whether the write with owner dot `d` is imported from its own commit rather than from a
/// snapshot carrying it beyond its frontier: that commit's part is held, valid and not dropped.
fn from_own(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    let Some(k) = core.commit_of(tid, ak, d) else { return false };
    let Some(m) = core.ix.commits.get(&k) else { return false };
    m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak).is_some_and(|ai| m.valid.get(ai).copied().unwrap_or(false) && !m.dropped.contains_key(&ai))
}

/// The schema table entry of aspect `ai` of a header.
fn schema_of(h: &Header, ai: usize) -> Option<(SchemaId, u64)> {
    h.aspects.get(ai)?.schema.and_then(|i| h.schemas.get(i)).copied()
}

/// Writes the importer does not import from a valid snapshot (spec/permissions.md §7): values
/// of deltas with an expiry and purged ones (it vouches for the rest, §5.2).
fn excluded(tx: &Tx<'_>, tid: &Tid, ak: &Ak) -> Vec<Owned> {
    let mut out: Vec<Owned> = tx.core.ix.valueless.get(&(*tid, ak.clone())).into_iter().flatten().cloned().collect();
    for (_, c) in tx.core.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = tx.core.ix.commits.get(c) else { continue };
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak) else { continue };
        if m.header.aspects.get(ai).is_some_and(|a| a.expires.is_some())
            && let Some(o) = Owned::of(&m.header, c, ai)
        {
            out.push(o);
        }
    }
    out
}

/// One import commit of origin `c` into `m`, its deltas on `aspects` (`None` when nothing of it
/// is importable).
fn import_one(tx: &mut Tx<'_>, t: &Tid, m: &Tid, c: &CommitId, carriers: &BTreeMap<Ak, Carrier>, live: &mut BTreeMap<Ak, BTreeSet<Dot>>, shown: &mut BTreeMap<Ak, Option<Shown>>) -> Result<Option<CommitId>> {
    let Some(meta) = tx.core.ix.commits.get(c).cloned() else { return Ok(None) };
    let h = meta.header.clone();
    let snapshot = h.kind == Kind::ContentSnapshot;
    if h.kind != Kind::Content && !snapshot {
        return Ok(None);
    }
    let own = match h.form {
        Form::Node => Source::node(h.author),
        Form::Commit => Source::commit(*c),
    };
    let mut deltas = Vec::new();
    for (ai, a) in h.aspects.iter().enumerate() {
        if a.tid != *t || is_membership_class(a.ak.as_str()) || a.ak.as_str() == "/created" || a.expires.is_some() || !meta.valid.get(ai).copied().unwrap_or(false) || meta.dropped.contains_key(&ai) {
            continue;
        }
        let carrier = carriers.get(&a.ak);
        // a snapshot is the origin of what it carries only where it was chosen
        match (snapshot, carrier) {
            (true, Some(s)) if s.id == *c => {}
            (true, _) => continue,
            _ => {}
        }
        // an ordinary commit the snapshot claims to cover whole gives only what the current
        // state holds that the snapshot does not carry (a frontier is not trusted alone)
        let claimed = !snapshot && carrier.is_some_and(|s| s.covers(&h, c, ai));
        if claimed && !live.contains_key(&a.ak) {
            tx.load(&a.tid, &a.ak)?;
            let w: BTreeSet<Dot> = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).map(|f| f.writes().into_iter().map(|(d, _)| d).collect()).unwrap_or_default();
            live.insert(a.ak.clone(), w);
        }
        if let Some(o) = Owned::of(&h, c, ai)
            && !snapshot
            && tx.core.ix.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| v.contains(&o))
        {
            continue;
        }
        let mut f = match crate::apply::held_parts(tx, c, ai)?.into_iter().next() {
            Some(Decoded::Delta(d)) => d.fragment,
            Some(Decoded::Snapshot(s)) => s.fragment,
            None => continue,
        };
        if snapshot {
            // not imported: expiring and purged writes it carries, and those beyond its frontier
            // whose own commit is imported
            let out = excluded(tx, &a.tid, &a.ak);
            let (core, s) = (&*tx.core, carrier);
            f.remove_dots(&|d| out.iter().any(|o| o.owns(d)) || (s.is_some_and(|s| !s.covers_dot(d)) && from_own(core, &a.tid, &a.ak, d)));
        } else if let (Some(s), Some(o)) = (carrier, Owned::of(&h, c, ai)) {
            // its own writes the snapshot covers and carries come from the snapshot
            let l = live.get(&a.ak);
            f.remove_dots(&|d| o.owns(d) && ((s.rank.contains_key(d) && s.covers_dot(d)) || (claimed && !l.is_some_and(|l| l.contains(d)))));
            if claimed && !f.writes().iter().any(|(d, _)| o.owns(d)) {
                continue;
            }
        }
        // canonical again after the removals above (spec/crdt.md §5.6, §7)
        f.prune(None, &mut osis_crdt::Changes::new());
        // only the sequence elements what the state shows needs (deleted elements and bare
        // anchors nothing shown depends on stay behind), so an import stays within
        // `MAX_DELTA_BARE` where its shown writes do (spec/permissions.md §7)
        if !shown.contains_key(&a.ak) {
            tx.load(&a.tid, &a.ak)?;
            let n = tx.core.states.get(&(a.tid, a.ak.clone())).and_then(Option::as_ref).map(Fragment::shown);
            shown.insert(a.ak.clone(), n);
        }
        if let Some(Some(n)) = shown.get(&a.ak) {
            f.keep_shown(n);
        }
        let core = &*tx.core;
        let (tid, ak, lo, hi, form) = (a.tid, a.ak.clone(), a.lo, a.hi, h.form);
        let own_writes = (!snapshot).then_some((&own, c, form, lo, hi));
        f.map_dots(&|x| imported(core, &tid, &ak, carrier, own_writes, x));
        if f.is_empty() {
            continue;
        }
        deltas.push(Resolved { tid: *m, ak: a.ak.clone(), fragment: f, lo: 0, hi: 0, schema: None, schema_ref: schema_of(&h, ai), retention: Some(a.retention), expires: None, frontiers: None, chunks: Vec::new(), split: false });
    }
    if deltas.is_empty() {
        return Ok(None);
    }
    let node = tx.core.id.tid();
    let ts = tx.core.hlc.next();
    // a hostile test writer (`Engine::reimport`) imports without rights too
    for d in deltas.iter().filter(|_| !tx.core.skip_writer_rules) {
        crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &Default::default(), &d.tid, d.ak.as_str(), ts)?;
    }
    let plan = CommitPlan { kind: Kind::Import, ts, actor: node, form: Form::Node, creates: Default::default(), purge: Vec::new(), undoes: None, frontier: None, origins: vec![Origin { commit: *c, author: h.author, actor: h.actor, ts: h.ts }], signer: node, blind: crate::engine::write::draw_blind(&mut *tx.rng) };
    build_and_apply(tx, plan, deltas).map(Some)
}

/// The snapshot each aspect of `t` imports from: the newest held one, valid and not dropped.
fn carriers(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeMap<Ak, Carrier>> {
    let mut out = BTreeMap::new();
    let aspects: Vec<(Ak, Vec<(Ts, CommitId)>)> = tx.core.ix.snapshots.iter().filter(|((x, _), _)| x == t).map(|((_, ak), v)| (ak.clone(), v.iter().map(|s| (s.0, s.1)).collect())).collect();
    for (ak, mut snaps) in aspects {
        if is_membership_class(ak.as_str()) {
            continue;
        }
        snaps.sort();
        for (ts, id) in snaps.into_iter().rev() {
            let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
            let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *t && a.ak == ak) else { continue };
            if m.header.kind != Kind::ContentSnapshot || m.dropped.contains_key(&ai) || !m.valid.get(ai).copied().unwrap_or(false) {
                continue;
            }
            let Some(Decoded::Snapshot(s)) = crate::apply::held_parts(tx, &id, ai)?.into_iter().next() else { continue };
            // a snapshot copying a held write otherwise than its delta holds it gives nothing
            // (spec/permissions.md §5.2): not a carrier
            if !copies_held(tx, t, &ak, &s.fragment)? {
                continue;
            }
            let carried: BTreeSet<Dot> = s.fragment.writes().into_iter().map(|(d, _)| d).filter(|d| !d.src.is_derived()).collect();
            let rank = carried.into_iter().zip(1u64..).collect();
            out.insert(ak.clone(), Carrier { id, ts, rank, frontiers: s.frontiers });
            break;
        }
    }
    Ok(out)
}

/// Whether snapshot fragment `f` of `(t, ak)` holds its copies of writes whose own delta is
/// held here as those deltas hold them.
fn copies_held(tx: &mut Tx<'_>, t: &Tid, ak: &Ak, f: &Fragment) -> Result<bool> {
    let mut own = Vec::new();
    let held: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*t, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for c in held {
        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
        if m.header.kind.is_compaction() {
            continue;
        }
        let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *t && a.ak == *ak) else { continue };
        own.extend(crate::apply::held_parts(tx, &c, ai)?.into_iter().map(Decoded::into_fragment));
    }
    let own: Vec<&Fragment> = own.iter().collect();
    let core = &*tx.core;
    Ok(f.copies_within(&own, &|d| crate::apply::validity::owner_held(core, t, ak, d)))
}

impl Engine {
    /// Moves `t` to `owner`: creates the copy M (with `/was = t`) and imports `t`'s held
    /// history into it. Returns M and the import commits. T's admins write `/moved` on T.
    pub fn move_thing(&mut self, t: &Tid, owner: Tid) -> Result<(Tid, Vec<CommitId>)> {
        let t = *t;
        if !self.knows(&t) {
            return Err(Error::UnknownThing(t));
        }
        if self.core.ix.was.get(&t).is_some_and(|s| !s.is_empty()) {
            return Err(Error::Misuse("a held thing already continues it"));
        }
        let mut m = Mutation::new();
        // the copy names this node its creator: only its imports apply to it
        let copy = self.new_copy(&mut m, owner);
        m.set(copy, &ct::WAS, &t)?;
        // one local transaction: the copy, `/was` and every import (spec/permissions.md §7)
        let out = self.run(|tx| {
            crate::engine::write::commit_in(tx, m)?;
            import_all(tx, &t, &copy)
        })?;
        Ok((copy, out))
    }

    /// Imports `t`'s held history into the existing copy `copy` again, as a hostile node
    /// breaking spec/permissions.md §7 ("a move is one import by one node") would, whether or
    /// not it created the copy or may write it (the writer-side rules are off for it). Tests only.
    #[doc(hidden)]
    pub fn reimport(&mut self, t: &Tid, copy: &Tid) -> Result<Vec<CommitId>> {
        let was = std::mem::replace(&mut self.core.skip_writer_rules, true);
        let out = self.run(|tx| import_all(tx, t, copy));
        self.core.skip_writer_rules = was;
        out
    }
}

/// One import commit per held origin commit of `t`, into `copy`.
fn import_all(tx: &mut Tx<'_>, t: &Tid, copy: &Tid) -> Result<Vec<CommitId>> {
    let carriers = carriers(tx, t)?;
    let mut live = BTreeMap::new();
    let mut shown = BTreeMap::new();
    let mut origins: Vec<(Ts, CommitId)> = tx.core.ix.by_aspect.iter().filter(|((x, _), _)| x == t).flat_map(|(_, s)| s.iter().copied()).collect();
    origins.sort();
    origins.dedup();
    let mut out = Vec::new();
    for (_, c) in origins {
        if let Some(id) = import_one(tx, t, copy, &c, &carriers, &mut live, &mut shown)? {
            out.push(id);
        }
    }
    Ok(out)
}
