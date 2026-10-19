//! Validity through osis-perm (spec/permissions.md §5): membership commits and roster
//! snapshots become perm's edge-write records (the node's `HeldSet` is perm's `MemoryHeldSet`,
//! kept current), each delta is judged on its own (layer 2), and a change of the held set
//! re-judges every held delta; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the membership-commit content rules
//! osis-commit cannot see (issues/commit-delta-content-rules.md).

use crate::engine::write::required_role;
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Header, Kind};
use osis_core::{Ak, CommitId, Role, Tid, Value};
use osis_crdt::{Dot, Fragment};
use osis_perm::{At, Dots, Edge, EdgeKey, EdgeOp, Frontier, MembershipCommit, Point, RosterSnapshot, Tenure, Validity, WriteId};
use osis_schema::core_types as ct;
use osis_schema::{Codec, Type, typed_read};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

pub(crate) fn edge_of(v: &Value) -> Option<Edge> {
    let e = ct::Edge::from_value(&typed(v, "edge")?).ok()?;
    let edge = Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(|k| EdgeKey { ts: k.ts, node: k.node }) };
    edge.well_formed().then_some(edge)
}

fn frontier_of(f: ct::Frontier) -> Frontier {
    Frontier { writes: f.writes, commits: f.commits }
}

/// The header's frontier (inline, or resolved from its link).
pub(crate) fn header_frontier(h: &Header) -> Option<Arc<Frontier>> {
    let v = h.frontier.as_ref()?;
    let f = ct::Frontier::from_value(&typed(v, "frontier")?).ok()?;
    Some(Arc::new(frontier_of(f)))
}

fn dots_of(h: &Header, ai: usize) -> Dots {
    match (h.form, h.aspects.get(ai)) {
        (Form::Node, Some(a)) if a.lo < a.hi => Dots::Node { lo: a.lo, hi: a.hi },
        _ => Dots::Commit,
    }
}

fn fragment(d: &Decoded) -> &Fragment {
    match d {
        Decoded::Delta(x) => &x.fragment,
        Decoded::Snapshot(x) => &x.fragment,
    }
}

/// Entries of a `/members` (map) fragment: (dot, key, fragment).
fn entries(f: &Fragment) -> Vec<(Dot, Option<Value>, Option<Fragment>)> {
    let Some(osis_crdt::MemberRef::Frag(Fragment::Map(m))) = f.slot(osis_crdt::Encoding::Map) else { return Vec::new() };
    m.entries().map(|(d, _, k, f)| (d.clone(), k.cloned(), f.cloned())).collect()
}

/// Records every keyed `/members` entry of these deltas: (target, entry dot) -> (member, value).
fn note_keys(core: &mut Core, target: &Tid, f: &Fragment) -> bool {
    let mut new = false;
    for (d, k, frag) in entries(f) {
        if let (Some(Value::Tid(m)), Some(frag)) = (k, frag) {
            let slot = core.member_keys.entry((*target, d)).or_insert_with(|| (m, None));
            if slot.1.is_none() {
                slot.1 = frag.read();
                new = true;
            }
        }
    }
    new
}

/// The edge writes of one `/members` delta of a membership commit, per member: a keyed entry
/// with a fragment sets the edge it reads; an entry reset of a known key removes it; nested
/// writes into a known entry change it (overlaid on the entry's creation). `None` while a
/// removed key is unknown here.
fn edge_ops(core: &Core, target: &Tid, f: &Fragment, dots: Dots) -> Option<Vec<EdgeOp>> {
    let mut per: BTreeMap<Tid, Option<Edge>> = BTreeMap::new();
    let mut set: BTreeSet<Tid> = BTreeSet::new();
    for (d, k, frag) in entries(f) {
        match (k, frag) {
            (Some(Value::Tid(m)), Some(frag)) => {
                if let Some(e) = frag.read().as_ref().and_then(edge_of) {
                    per.insert(m, Some(e));
                    set.insert(m);
                }
            }
            (_, frag) => {
                let (m, base) = core.member_keys.get(&(*target, d))?.clone();
                if set.contains(&m) {
                    continue;
                }
                let edge = match frag.and_then(|x| x.read()) {
                    // nested field writes: overlay on the entry's created value
                    Some(Value::Map(changes)) => match base {
                        Some(Value::Map(mut b)) => {
                            b.extend(changes);
                            edge_of(&Value::Map(b))
                        }
                        _ => None,
                    },
                    _ => None,
                };
                per.insert(m, edge);
            }
        }
    }
    Some(per.into_iter().map(|(member, edge)| EdgeOp { target: *target, member, edge, dots }).collect())
}

/// A roster snapshot's parts on one thing: roster, ledger, `/members` dots.
type RosterParts = (BTreeMap<Tid, Edge>, Vec<Tenure>, Dots);

/// Adds a membership commit's edge writes (or a roster snapshot) to perm's held set.
pub(crate) fn add_membership(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    for (ai, _, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && a.ak.as_str() == "/members"
        {
            note_keys(core, &a.tid, fragment(d));
        }
    }
    match h.kind {
        Kind::Membership => {
            let mut ops = Vec::new();
            for (ai, _, d) in parts {
                let Some(a) = h.aspects.get(*ai) else { continue };
                if a.ak.as_str() != "/members" {
                    continue;
                }
                match edge_ops(core, &a.tid, fragment(d), dots_of(h, *ai)) {
                    Some(v) => ops.extend(v),
                    None => {
                        core.unresolved.insert(*id);
                        return;
                    }
                }
            }
            core.unresolved.remove(id);
            core.members_seen.extend(ops.iter().map(|o| o.member));
            if !ops.is_empty() {
                core.held.add_commit(MembershipCommit { id: *id, ts: h.ts, author: h.author, actor: h.actor, frontier: header_frontier(h), ops });
            }
        }
        Kind::RosterSnapshot => {
            let mut by_thing: BTreeMap<Tid, RosterParts> = BTreeMap::new();
            for (ai, _, d) in parts {
                let Some(a) = h.aspects.get(*ai) else { continue };
                let e = by_thing.entry(a.tid).or_insert_with(|| (BTreeMap::new(), Vec::new(), Dots::Commit));
                match a.ak.as_str() {
                    "/members" => {
                        e.2 = dots_of(h, *ai);
                        for (_, k, frag) in entries(fragment(d)) {
                            if let (Some(Value::Tid(m)), Some(edge)) = (k, frag.and_then(|f| f.read()).as_ref().and_then(edge_of)) {
                                e.0.insert(m, edge);
                            }
                        }
                    }
                    "/tenures" => {
                        if let Some(Value::Set(s)) = fragment(d).read() {
                            for t in s {
                                if let Some(t) = typed(&t, "tenure").and_then(|v| ct::Tenure::from_value(&v).ok()) {
                                    let frontier = match t.frontier {
                                        Some(osis_schema::Chunked::Inline(f)) => Some(Arc::new(frontier_of(f))),
                                        // a linked frontier this node has not resolved audits as empty
                                        Some(osis_schema::Chunked::Link(_)) => Some(Arc::new(Frontier::default())),
                                        None => None,
                                    };
                                    e.1.push(Tenure { member: t.member, role: t.role, since: t.since.map(|k| EdgeKey { ts: k.ts, node: k.node }), until: EdgeKey { ts: t.until.ts, node: t.until.node }, frontier });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (thing, (roster, ledger, dots)) in by_thing {
                core.members_seen.extend(roster.keys().copied());
                core.members_seen.extend(ledger.iter().map(|t| t.member));
                core.held.add_snapshot(RosterSnapshot { id: *id, ts: h.ts, author: h.author, actor: h.actor, thing, dots, roster, ledger });
            }
        }
        _ => {}
    }
}

/// Re-derives the edge writes of commits whose removed keys were unknown.
pub(crate) fn resolve_unresolved(tx: &mut Tx<'_>) -> Result<bool> {
    let ids: Vec<CommitId> = tx.core.unresolved.iter().copied().collect();
    let mut any = false;
    for id in ids {
        let Some(m) = tx.core.commits.get(&id).cloned() else { continue };
        let mut parts = Vec::new();
        for (ai, a) in m.header.aspects.iter().enumerate() {
            if a.ak.as_str() == "/members" {
                for d in super::held_parts(tx, &id, ai)? {
                    parts.push((ai, 0, d));
                }
            }
        }
        add_membership(tx.core, &m.header, &id, &parts);
        any |= !tx.core.unresolved.contains(&id);
    }
    Ok(any)
}

/// Is aspect `ai` of a held commit valid (spec/permissions.md §5.2)?
pub(crate) fn part_valid(core: &Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    if core.void.contains(id) {
        return false;
    }
    let Some(a) = h.aspects.get(ai) else { return false };
    let ak = a.ak.as_str();
    // `/created` hashes to its tid; edge writes are layer 1 (reads go through the timeline);
    // a compaction snapshot's writes are judged as their authors' when bodies are rebuilt
    if ak == "/created" || ak == "/members" || ak == "/tenures" || super::is_kind_snapshot(h.kind) {
        return true;
    }
    let Some(tl) = core.timelines.get(&a.tid) else { return false };
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    // an applied invite grant carries the grantee's boxes (spec/permissions.md §1, §2)
    if ak == "/secrets"
        && let Some(c) = tl.membership_commit(id)
        && c.ops.iter().enumerate().any(|(i, o)| o.target == a.tid && tl.is_applied(&WriteId::Op(*id, i as u32)))
    {
        return true;
    }
    let dots = if h.kind == Kind::Import { Dots::Commit } else { dots_of(h, ai) };
    tl.delta_valid(point, &a.tid, ak, dots, required_role(ak)) == Validity::Valid
}

/// Re-judges every held delta after the held set changed; rebuilds aspects whose validity
/// flipped. Returns them.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    if resolve_unresolved(tx)? {
        tx.core.timelines.update(&tx.core.held);
    }
    let mut flipped: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let ids: Vec<CommitId> = tx.core.commits.keys().copied().collect();
    for id in ids {
        let Some(m) = tx.core.commits.get(&id) else { continue };
        let h = m.header.clone();
        let now: Vec<bool> = (0..h.aspects.len()).map(|ai| part_valid(tx.core, &h, &id, ai)).collect();
        if let Some(m) = tx.core.commits.get_mut(&id)
            && m.valid != now
        {
            for (ai, (a, b)) in m.valid.iter().zip(&now).enumerate() {
                if a != b
                    && let Some(x) = h.aspects.get(ai)
                {
                    flipped.insert((x.tid, x.ak.clone()));
                }
            }
            m.valid = now;
        }
    }
    if rebuild {
        for (tid, ak) in &flipped {
            super::rebuild(tx, tid, ak)?;
        }
    }
    Ok(flipped.into_iter().collect())
}

/// Rules of a membership commit that need its deltas (issues/commit-delta-content-rules.md;
/// spec/commits.md §2, spec/wire.md §4 position 13, spec/permissions.md §3).
pub(crate) fn check_content_rules(core: &Core, h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    if h.kind != Kind::Membership {
        return Ok(());
    }
    let mut changed: Vec<(Tid, Tid, Option<Edge>)> = Vec::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "/members" {
            continue;
        }
        for (dot, k, frag) in entries(fragment(d)) {
            match k {
                Some(Value::Tid(m)) => changed.push((a.tid, m, frag.and_then(|f| f.read()).as_ref().and_then(edge_of))),
                _ => {
                    if let Some((m, _)) = core.member_keys.get(&(a.tid, dot)) {
                        changed.push((a.tid, *m, None));
                    }
                }
            }
        }
    }
    let mut members: Vec<(Tid, Tid)> = changed.iter().map(|c| (c.0, c.1)).collect();
    members.sort();
    members.dedup();
    if members.len() > 1 {
        // the one exception for edge writes in a plain membership commit: a single-use
        // redemption (a grant plus the author key's own self-removal, spec/permissions.md §9)
        let redemption = members.len() == 2 && changed.iter().any(|c| c.1 == h.author && c.2.is_none()) && changed.iter().any(|c| c.1 != h.author && c.2.is_some());
        if !redemption {
            return Err(Error::BadInput("a membership commit changes more than one edge"));
        }
    }
    let lowers = changed.iter().any(|(target, m, new)| {
        let old = core.timelines.get(target).map(|tl| tl.roster(target, At::END)).and_then(|r| r.get(m).copied());
        old.is_some() && osis_perm::types::lowers(new.as_ref(), old.as_ref())
    });
    if h.frontier.is_some() && !lowers && !changed.is_empty() {
        return Err(Error::BadInput("a frontier on a commit that demotes nobody"));
    }
    // a removal or demotion on a thing with secrets of its own carries its rotation
    for (target, m, new) in &changed {
        if *m == h.author {
            continue;
        }
        let old = core.timelines.get(target).map(|tl| tl.roster(target, At::END)).and_then(|r| r.get(m).copied());
        let demotes = match (old, new) {
            (Some(o), None) => o.role >= Role::Read,
            (Some(o), Some(n)) => n.role < o.role,
            _ => false,
        };
        if demotes && core.own_keys.contains(target) {
            let has = |ak: &str| h.aspects.iter().any(|a| a.tid == *target && a.ak.as_str() == ak);
            if !has("/secrets") || !has("/keys") {
                return Err(Error::BadInput("a removal without the rotation it requires"));
            }
        }
    }
    Ok(())
}
