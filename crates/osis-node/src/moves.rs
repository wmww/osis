//! Moving a thing (spec/permissions.md §7): a copy M under a new owner that imports T's
//! history. One import commit per origin commit (each delta carries its origin delta's
//! retention and schema), `/was` on M; the guard against importing a thing a held copy already
//! continues. Origins per aspect: the newest held compaction snapshot, whose carried writes are
//! imported, and the ordinary commits it does not cover, whose own writes are; a write of origin
//! C gets the dot `(Commit(C), k)` (k its counter in C, or for a snapshot its rank by (source,
//! counter) among the writes the snapshot carries on the aspect), and references to writes map
//! the same way. Resolution of moved tids in reads lives in `engine/read.rs`.

use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Core, Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_commit::{Decoded, Form, Header, Kind, Origin};
use osis_core::{Ak, CommitId, SchemaId, Tid, Ts};
use osis_crdt::{Dot, Source, SourceKind};
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
    /// Whether the snapshot reflects every write of ordinary commit `c` (spec/crdt.md §8: up to
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

/// The dot an imported write or reference gets (spec/permissions.md §7): carried by the snapshot
/// origin, its rank there; else its own commit's ID with its counter.
fn imported(core: &Core, tid: &Tid, ak: &Ak, carrier: Option<&Carrier>, own: Option<(&Source, &CommitId, Form, u64, u64)>, x: &Dot) -> Option<Dot> {
    if let Some(r) = carrier.and_then(|s| Some((s.id, *s.rank.get(x)?))) {
        return Some(Dot::new(Source::commit(r.0), r.1));
    }
    if let Some((src, c, form, lo, hi)) = own
        && x.src == *src
        && (form == Form::Commit || (lo <= x.ctr && x.ctr < hi))
    {
        return Some(Dot::new(Source::commit(*c), x.ctr));
    }
    match x.src.kind() {
        SourceKind::Node(_) => core.commit_of(tid, ak, x).map(|k| Dot::new(Source::commit(k), x.ctr)),
        _ => None,
    }
}

/// The schema table entry of aspect `ai` of a header.
fn schema_of(h: &Header, ai: usize) -> Option<(SchemaId, u64)> {
    h.aspects.get(ai)?.schema.and_then(|i| h.schemas.get(i)).copied()
}

/// Writes the importer does not import (spec/permissions.md §7): values of deltas with an
/// expiry, purged ones, and those invalid here.
fn excluded(tx: &Tx<'_>, tid: &Tid, ak: &Ak) -> Vec<Owned> {
    let mut out = crate::apply::invalid_of(tx.core, tid, ak);
    out.extend(tx.core.valueless.get(&(*tid, ak.clone())).into_iter().flatten().cloned());
    for (_, c) in tx.core.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten() {
        let Some(m) = tx.core.commits.get(c) else { continue };
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
fn import_one(tx: &mut Tx<'_>, t: &Tid, m: &Tid, c: &CommitId, carriers: &BTreeMap<Ak, Carrier>) -> Result<Option<CommitId>> {
    let Some(meta) = tx.core.commits.get(c).cloned() else { return Ok(None) };
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
        if a.tid != *t || is_membership_class(a.ak.as_str()) || a.ak.as_str() == "/created" || a.expires.is_some() || !meta.valid.get(ai).copied().unwrap_or(false) || meta.dropped.contains(&(ai, 0)) {
            continue;
        }
        let carrier = carriers.get(&a.ak);
        // a snapshot is the origin of what it carries only where it was chosen; an ordinary
        // commit it covers gives nothing of its own
        match (snapshot, carrier) {
            (true, Some(s)) if s.id == *c => {}
            (true, _) => continue,
            (false, Some(s)) if s.covers(&h, c, ai) => continue,
            _ => {}
        }
        if let Some(o) = Owned::of(&h, c, ai)
            && !snapshot
            && tx.core.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| v.contains(&o))
        {
            continue;
        }
        let mut f = match crate::apply::held_parts(tx, c, ai)?.into_iter().next() {
            Some(Decoded::Delta(d)) => d.fragment,
            Some(Decoded::Snapshot(s)) => s.fragment,
            None => continue,
        };
        if snapshot {
            // not imported: expiring, purged and invalid writes it carries
            let out = excluded(tx, &a.tid, &a.ak);
            if !out.is_empty() {
                f.remove_dots(&|d| out.iter().any(|o| o.owns(d)));
            }
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
    for d in &deltas {
        crate::engine::write::check_authority(tx.core, tx.core.id.tid(), &[], &d.tid, d.ak.as_str(), ts)?;
    }
    let plan = CommitPlan { kind: Kind::Import, ts, actor: node, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, origins: vec![Origin { commit: *c, author: h.author, actor: h.actor, ts: h.ts }], signer: node };
    build_and_apply(tx, plan, deltas).map(Some)
}

/// The snapshot each aspect of `t` imports from: the newest held one, valid and not dropped,
/// whose carried writes the import delta may hold (no bare anchor: only snapshots carry those,
/// spec/crdt.md §3.3; such an aspect imports from its ordinary commits alone,
/// issues/import-bare-anchors.md).
fn carriers(tx: &mut Tx<'_>, t: &Tid) -> Result<BTreeMap<Ak, Carrier>> {
    let mut out = BTreeMap::new();
    let aspects: Vec<(Ak, Vec<(Ts, CommitId)>)> = tx.core.snapshots.iter().filter(|((x, _), _)| x == t).map(|((_, ak), v)| (ak.clone(), v.iter().map(|s| (s.0, s.1)).collect())).collect();
    for (ak, mut snaps) in aspects {
        if is_membership_class(ak.as_str()) {
            continue;
        }
        snaps.sort();
        for (ts, id) in snaps.into_iter().rev() {
            let Some(m) = tx.core.commits.get(&id).cloned() else { continue };
            let Some(ai) = m.header.aspects.iter().position(|a| a.tid == *t && a.ak == ak) else { continue };
            if m.header.kind != Kind::ContentSnapshot || m.dropped.contains(&(ai, 0)) || !m.valid.get(ai).copied().unwrap_or(false) {
                continue;
            }
            let Some(Decoded::Snapshot(s)) = crate::apply::held_parts(tx, &id, ai)?.into_iter().next() else { continue };
            if s.fragment.has_bare_anchors() {
                break;
            }
            let carried: BTreeSet<Dot> = s.fragment.writes().into_iter().map(|(d, _)| d).filter(|d| !d.src.is_derived()).collect();
            let rank = carried.into_iter().zip(1u64..).collect();
            out.insert(ak.clone(), Carrier { id, ts, rank, frontiers: s.frontiers });
            break;
        }
    }
    Ok(out)
}

impl Engine {
    /// Moves `t` to `owner`: creates the copy M (with `/was = t`) and imports `t`'s held
    /// history into it. Returns M and the import commits. T's admins write `/moved` on T.
    pub fn move_thing(&mut self, t: &Tid, owner: Tid) -> Result<(Tid, Vec<CommitId>)> {
        let t = *t;
        if !self.knows(&t) {
            return Err(Error::UnknownThing(t));
        }
        if self.core.was.get(&t).is_some_and(|s| !s.is_empty()) {
            return Err(Error::Misuse("a held thing already continues it"));
        }
        let mut m = Mutation::new();
        let copy = self.new_thing(&mut m, owner);
        m.set(copy, &ct::WAS, &t)?;
        // one local transaction: the copy, `/was` and every import (spec/permissions.md §7)
        let out = self.run(|tx| {
            crate::engine::write::commit_in(tx, m)?;
            let carriers = carriers(tx, &t)?;
            let mut origins: Vec<(Ts, CommitId)> = tx.core.by_aspect.iter().filter(|((x, _), _)| *x == t).flat_map(|(_, s)| s.iter().copied()).collect();
            origins.sort();
            origins.dedup();
            let mut out = Vec::new();
            for (_, c) in origins {
                if let Some(id) = import_one(tx, &t, &copy, &c, &carriers)? {
                    out.push(id);
                }
            }
            Ok(out)
        })?;
        Ok((copy, out))
    }
}
