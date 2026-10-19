//! Moving a thing (spec/permissions.md §7): a copy M under a new owner that imports T's
//! history. One import commit per origin commit (each delta carries its origin delta's
//! retention), writes re-sourced to `(Commit(origin), counter)` with their `ts` kept, `/was`
//! on M; the guard against importing a thing a held copy already continues. Resolution of
//! moved tids in reads lives in `engine/read.rs`.

use crate::engine::write::{CommitPlan, Resolved, build_and_apply};
use crate::engine::{Engine, Owned, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_commit::{Decoded, Form, Kind, Origin};
use osis_core::{CommitId, Tid, Ts};
use osis_crdt::{Dot, Source, SourceKind};
use osis_schema::core_types as ct;
use osis_schema::core_types::is_membership_class;

/// Builds the import commit of origin `c` into `m` (`None` when nothing of it is importable:
/// expiring, purged, invalid or dropped deltas are not imported).
fn import_one(tx: &mut Tx<'_>, t: &Tid, m: &Tid, c: &CommitId) -> Result<Option<CommitId>> {
    let Some(meta) = tx.core.commits.get(c).cloned() else { return Ok(None) };
    let h = meta.header.clone();
    if h.kind != Kind::Content {
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
        if let Some(o) = Owned::of(&h, c, ai)
            && tx.core.valueless.get(&(a.tid, a.ak.clone())).is_some_and(|v| v.contains(&o))
        {
            continue;
        }
        let Some(Decoded::Delta(d)) = crate::apply::held_parts(tx, c, ai)?.into_iter().next() else { continue };
        let core = &*tx.core;
        let (tid, ak, lo, hi, form) = (a.tid, a.ak.clone(), a.lo, a.hi, h.form);
        let map = |x: &Dot| -> Option<Dot> {
            if x.src == own && (form == Form::Commit || (lo <= x.ctr && x.ctr < hi)) {
                return Some(Dot::new(Source::commit(*c), x.ctr));
            }
            match x.src.kind() {
                SourceKind::Node(_) => core.commit_of(&tid, &ak, x).map(|k| Dot::new(Source::commit(k), x.ctr)),
                _ => None,
            }
        };
        let mut f = d.fragment;
        f.map_dots(&map);
        deltas.push(Resolved { tid: *m, ak: a.ak.clone(), fragment: f, lo: 0, hi: 0, schema: None, retention: Some(a.retention), expires: None, frontiers: None, chunks: Vec::new() });
    }
    if deltas.is_empty() {
        return Ok(None);
    }
    let node = tx.core.id.tid();
    let ts = tx.core.hlc.next();
    for d in &deltas {
        crate::engine::write::check_authority(tx.core, &[], &d.tid, d.ak.as_str(), ts)?;
    }
    let plan = CommitPlan { kind: Kind::Import, ts, actor: node, form: Form::Node, creates: Vec::new(), purge: Vec::new(), undoes: None, frontier: None, origins: vec![Origin { commit: *c, author: h.author, actor: h.actor, ts: h.ts }] };
    build_and_apply(tx, plan, deltas).map(Some)
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
            let mut origins: Vec<(Ts, CommitId)> = tx.core.by_aspect.iter().filter(|((x, _), _)| *x == t).flat_map(|(_, s)| s.iter().copied()).collect();
            origins.sort();
            origins.dedup();
            let mut out = Vec::new();
            for (_, c) in origins {
                if let Some(id) = import_one(tx, &t, &copy, &c)? {
                    out.push(id);
                }
            }
            Ok(out)
        })?;
        Ok((copy, out))
    }
}
