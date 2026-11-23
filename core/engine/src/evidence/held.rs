//! The derivation's input from the engine's held set (notes/evidence-derivation.md, What the
//! switch must know): per held copy (commit, thing) its parts on that thing, and the record
//! edges. Read from the index and the held `sync.0` bodies; nothing is kept.
//!
//! `Engine::check_evidence` is the engine side of the joint property (spec/permissions.md §4;
//! held-model `World::joint`), tests only: per thing, a reader holding the thing's bodies plus
//! exactly the copies the derivation requires judges each of those bodies under osis-perm `paths`
//! as the node holding everything does.

use super::{Config, CopyId, Del, Evidence, Kind, Level, Part, Step, Write};
use crate::engine::secrets::DeleteBase;
use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_base::{CommitId, Role, Tid};
use osis_perm::paths::{Commit, Paths, PartKind};
use osis_perm::WriteId;
use std::collections::{BTreeMap, BTreeSet};

/// A step ID or a delete key: 32 bytes.
pub type Key32 = [u8; 32];
/// The derivation over the engine's held set.
pub type Ev = Evidence<CommitId, Tid, Key32>;
/// The held copies with their parts as the derivation takes them.
pub type Copies = BTreeMap<CopyId<CommitId, Tid>, Vec<Part<Tid, Key32>>>;

/// Things to their mint admins, of every held creation record naming one.
pub(crate) fn mint(core: &Core) -> BTreeMap<Tid, Tid> {
    let held = &core.ix.held;
    held.things().filter_map(|t| Some((*t, held.created(t)?.mint_admin()?))).collect()
}

/// Every held copy with its parts: per aspect on the thing a part (a `roles.0` aspect: one per
/// edge write it makes there, else one with no edge write), per purge item on it a content part.
/// Hops from the path the commit states for the thing (`None` while a split entry has not opened
/// here); delete keys at levels 1 and 3 where the thing's delete base is an actor; steps from a
/// held `sync.0` body, snapshots included (a compaction snapshot carrying steps records them).
pub(crate) fn copies(tx: &mut Tx<'_>) -> Result<Copies> {
    let mint = mint(tx.core);
    let ids: Vec<CommitId> = tx.core.ix.commits.keys().copied().collect();
    let mut out = Copies::new();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let h = m.header.clone();
        let core: &Core = tx.core;
        let rc = core.ix.held.edge_commit(&id).cloned();
        let hops = |t: &Tid, holder: Option<Tid>, edge_class: bool| -> Option<Vec<(Tid, Tid)>> {
            let (along, direct, _) = crate::apply::validity::stated(&h, &m.view, t)?;
            Some(osis_perm::paths::hops(&mint, h.signer, &along, direct, *t, holder, edge_class))
        };
        let mut bases: BTreeMap<Tid, Option<Tid>> = BTreeMap::new();
        let mut parts: BTreeMap<Tid, Vec<Part<Tid, Key32>>> = BTreeMap::new();
        let mut steps_at: Vec<(Tid, usize, usize)> = Vec::new();
        for (ai, a) in h.aspects.iter().enumerate() {
            let t = a.tid;
            let base = *bases.entry(t).or_insert_with(|| match core.delete_base(&t) {
                Some(DeleteBase::Actor(b, _)) => Some(b),
                _ => None,
            });
            let dels: Vec<Del<Tid, Key32>> = base
                .map(|base| {
                    a.keys.iter().filter_map(|k| h.keys.get(*k)).filter_map(|k| Some(Del { base, level: level(k.level)?, key: k.key })).collect()
                })
                .unwrap_or_default();
            let on = parts.entry(t).or_default();
            let writes: Vec<&osis_perm::EdgeOp> = match (&rc, a.ak.as_str()) {
                (Some(rc), "roles.0") => rc.ops.iter().filter(|o| o.target == t).collect(),
                _ => Vec::new(),
            };
            if let (Some(rc), false) = (&rc, writes.is_empty()) {
                for o in writes {
                    let path = rc.path_to(&t);
                    let leave = o.holder == *path.last().unwrap_or(&rc.signer);
                    let kind = Kind::Write(Write { holder: o.holder, gives_read: o.edge.is_some_and(|e| e.role >= Role::Read) && !leave });
                    let hops = osis_perm::paths::hops(&mint, rc.signer, path, rc.direct, t, Some(o.holder), true);
                    on.push(Part { kind, hops: Some(hops), dels: dels.clone(), steps: vec![] });
                }
                continue;
            }
            if a.ak.as_str() == "sync.0" {
                steps_at.push((t, on.len(), ai));
            }
            on.push(Part { kind: Kind::Content, hops: hops(&t, None, false), dels, steps: vec![] });
        }
        for item in &h.purge {
            let (t, _, _) = crate::retention::purge::item_names(item);
            parts.entry(*t).or_default().push(Part::new(Kind::Content, hops(t, None, false)));
        }
        for (t, i, ai) in steps_at {
            let steps = recorded_steps(tx, &id, ai)?;
            if let Some(p) = parts.get_mut(&t).and_then(|v| v.get_mut(i)) {
                p.steps = steps;
            }
        }
        for (t, ps) in parts {
            out.insert((id, t), ps);
        }
    }
    Ok(out)
}

fn level(l: u8) -> Option<Level> {
    match l {
        1 => Some(Level::Admin),
        3 => Some(Level::Writer),
        _ => None,
    }
}

/// The steps the held `sync.0` body of commit `id` (aspect `ai`) records: each step entry whose
/// step it writes, in any sync ID's entry, created there or not (a step joins the entry its
/// sync ID's genesis made, so a read of the delta alone shows none of it: spec/crdt.md §5.6). None
/// where the body is not held; a step that does not parse is none.
fn recorded_steps(tx: &mut Tx<'_>, id: &CommitId, ai: usize) -> Result<Vec<Step<Key32>>> {
    use osis_crdt::{Encoding, Fragment, SlotRef};
    fn at(f: &Fragment, enc: Encoding) -> Option<&Fragment> {
        match f.slot(enc)? {
            SlotRef::Frag(x) => Some(x),
            SlotRef::Reg(_) => None,
        }
    }
    // map<sync ID, {0 steps: map<step ID, {0 step, ..}>}>
    fn entries(f: &Fragment) -> Vec<&Fragment> {
        match at(f, Encoding::Map) {
            Some(Fragment::Map(m)) => m.entries().filter_map(|e| e.3).collect(),
            _ => vec![],
        }
    }
    fn field(f: &Fragment, id: u64) -> Option<&Fragment> {
        match at(f, Encoding::Struct)? {
            Fragment::Struct(s) => s.field(id),
            _ => None,
        }
    }
    let Some(f) = crate::apply::held_fragment(tx, id, ai)? else { return Ok(vec![]) };
    let mut out = Vec::new();
    for e in entries(&f) {
        for r in field(e, 0).map(entries).unwrap_or_default() {
            let Some(osis_base::Value::Bytes(b)) = field(r, 0).and_then(Fragment::read) else { continue };
            let Ok(s) = osis_blob::step::Step::parse(&b) else { continue };
            out.push(Step { id: s.id().0, prev: s.prev.map(|p| p.0), delete: s.keys.delete.to_bytes(), write: s.keys.write.to_bytes() });
        }
    }
    Ok(out)
}

/// The derivation over `copies` and the held records, with sync IDs `sids` (sync ID, actor, its
/// unit's things), keys-open travel on (spec/permissions.md §4 Role changes travel).
pub fn derive(core_mint: &BTreeMap<Tid, Tid>, copies: &Copies, sids: &[(Tid, Tid, Vec<Tid>)]) -> Ev {
    let mut ev = Ev::new(Config { keys_open: true });
    for (t, m) in core_mint {
        ev.add_record((*m, *t));
    }
    for (s, a, unit) in sids {
        ev.add_sid(*s, *a);
        for t in unit {
            ev.join(s, *t);
        }
    }
    for (c, ps) in copies {
        ev.add(*c, ps.clone());
    }
    ev
}

impl crate::Engine {
    /// The held copies as the evidence derivation takes them (tests).
    #[doc(hidden)]
    pub fn evidence_copies(&mut self) -> Result<Copies> {
        osis_base::costs::paused(|| osis_perm::uncounted(|| osis_base::memo::unrecorded(|| self.read(copies))))
    }

    /// Things to their mint admins, of the held creation records (tests).
    #[doc(hidden)]
    pub fn evidence_mint(&self) -> BTreeMap<Tid, Tid> {
        mint(&self.core)
    }

    /// The derivation over the held set with sync IDs `sids` (tests).
    #[doc(hidden)]
    pub fn evidence(&mut self, sids: &[(Tid, Tid, Vec<Tid>)]) -> Result<Ev> {
        let copies = self.evidence_copies()?;
        Ok(derive(&self.evidence_mint(), &copies, sids))
    }

    /// The engine side of the joint property (tests): per thing `t` with a held part, as the
    /// sync ID of a unit holding `t` alone, the derivation built with the copies taken in two
    /// orders agrees with itself and from scratch; and a reader holding `t`'s bodies plus exactly
    /// the copies it requires judges each body on `t` (content validity, edge write status) under
    /// osis-perm `paths` as the node holding everything does. `Some`: the first difference.
    #[doc(hidden)]
    pub fn check_evidence(&mut self) -> Result<Option<String>> {
        let copies = self.evidence_copies()?;
        let mint = self.evidence_mint();
        let walk: Vec<Commit> = {
            let core = &self.core;
            core.ix.commits.keys().filter_map(|id| crate::apply::validity::reading(core, id)).map(|h| h.commit()).collect()
        };
        let things: BTreeSet<Tid> = copies.keys().map(|c| c.1).collect();
        let sids: Vec<(Tid, Tid, Vec<Tid>)> = things.iter().map(|t| (*t, *t, vec![*t])).collect();
        let ev = derive(&mint, &copies, &sids);
        if let Err(e) = ev.check() {
            return Ok(Some(format!("incremental against from scratch: {e}")));
        }
        // the copies in the reverse order, the units after
        let mut back = Ev::new(Config { keys_open: true });
        for (t, m) in &mint {
            back.add_record((*m, *t));
        }
        for (c, ps) in copies.iter().rev() {
            back.add(*c, ps.clone());
        }
        for (s, a, unit) in &sids {
            back.add_sid(*s, *a);
            for t in unit {
                back.join(s, *t);
            }
        }
        let full = Paths::evaluate(&mint, BTreeSet::new(), &walk);
        for t in &things {
            let req: BTreeSet<CopyId<CommitId, Tid>> = ev.required(t).map(|r| r.keys().copied().collect()).unwrap_or_default();
            let req_back: BTreeSet<CopyId<CommitId, Tid>> = back.required(t).map(|r| r.keys().copied().collect()).unwrap_or_default();
            if req != req_back {
                return Ok(Some(format!("{t:?}: copies taken in reverse order give {req_back:?}, in order {req:?}")));
            }
            let (held, ids) = reader_set(&walk, t, &req);
            let reader = Paths::evaluate(&mint, BTreeSet::new(), &held);
            for c in &walk {
                for (i, p) in c.parts.iter().enumerate().filter(|(_, p)| p.on == *t) {
                    let w = WriteId(c.id, i as u32);
                    let r = ids.get(&w).copied().unwrap_or(w);
                    let (a, b) = match p.kind {
                        PartKind::Delta(_) => (format!("{:?}", full.content(&w)), format!("{:?}", reader.content(&r))),
                        PartKind::Edge(_) => (format!("{:?}", full.status(&w)), format!("{:?}", reader.status(&r))),
                        PartKind::None => continue,
                    };
                    if a != b {
                        return Ok(Some(format!("{t:?}: part {w:?} judged {a} holding everything, {b} holding the bodies and the required copies {req:?}")));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// A reader's held commits: every part on `t` and each part on a required copy's thing, with each
/// kept part's index in its full commit.
fn reader_set(walk: &[Commit], t: &Tid, req: &BTreeSet<CopyId<CommitId, Tid>>) -> (Vec<Commit>, BTreeMap<WriteId, WriteId>) {
    let mut out = Vec::new();
    let mut ids = BTreeMap::new();
    for c in walk {
        let keep: Vec<usize> = (0..c.parts.len()).filter(|&i| c.parts.get(i).is_some_and(|p| p.on == *t || req.contains(&(c.id, p.on)))).collect();
        if keep.is_empty() {
            continue;
        }
        for (n, &i) in keep.iter().enumerate() {
            ids.insert(WriteId(c.id, i as u32), WriteId(c.id, n as u32));
        }
        out.push(Commit { parts: keep.iter().filter_map(|&i| c.parts.get(i).cloned()).collect(), ..c.clone() });
    }
    (out, ids)
}
