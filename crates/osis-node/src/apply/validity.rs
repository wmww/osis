//! Validity through osis-perm (spec/permissions.md §5): membership commits and roster
//! snapshots become perm's edge-write records (the node's `HeldSet` is perm's `MemoryHeldSet`,
//! kept current), each delta is judged on its own (layer 2), and a change of the held set
//! re-judges every held delta; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the membership-commit content rules
//! osis-commit cannot see (spec/commits.md §2).

use crate::engine::write::required_role;
use crate::engine::{Core, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Header, Kind};
use osis_core::{Ak, CommitId, CreationRecord, Role, Tid, Value};
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
                core.held.add_snapshot(RosterSnapshot { id: *id, ts: h.ts, author: h.author, actor: h.actor, thing, dots, roster, ledger });
            }
        }
        _ => {}
    }
}

/// Do held edge writes lead from `author` (as member, through member actors) to a thing on
/// `chain`? (The author's chain certificates, spec/permissions.md §4.)
pub(crate) fn reaches(core: &Core, author: &Tid, chain: &[Tid]) -> bool {
    let mut frontier = vec![*author];
    let mut seen: BTreeSet<Tid> = BTreeSet::new();
    while let Some(x) = frontier.pop() {
        if !seen.insert(x) || seen.len() > 4096 {
            continue;
        }
        for cs in core.held.commits.values() {
            for c in cs {
                for o in &c.ops {
                    if o.member == x {
                        if chain.contains(&o.target) {
                            return true;
                        }
                        frontier.push(o.target);
                    }
                }
            }
        }
        for ss in core.held.snapshots.values() {
            for sn in ss {
                if sn.roster.contains_key(&x) || sn.ledger.iter().any(|t| t.member == x) {
                    if chain.contains(&sn.thing) {
                        return true;
                    }
                    frontier.push(sn.thing);
                }
            }
        }
    }
    false
}

/// The role a `/secrets` or `/keys` delta needs (spec/permissions.md §3): a writer rotates
/// read and write, only an admin the admin role; at least write. A delta that is not a plain
/// struct (a write or reset of the whole value) replaces every field: admin.
fn rotation_required(ak: &str, f: &Fragment) -> Option<Role> {
    if (ak == "/keys" || ak == "/secrets") && !f.is_plain_struct() {
        return Some(Role::Admin);
    }
    let role_of = |v: &Value| match v {
        Value::Enum(c, _) => [Role::Read, Role::Write, Role::Admin].get(usize::try_from(*c).ok()?).copied(),
        _ => None,
    };
    let field = |v: &Value, id: i64| match v {
        Value::Map(m) => m.get(&Value::Int(id)).cloned(),
        _ => None,
    };
    if ak == "/keys" {
        // the admin keyset, a key actor's KEM key, the inbox and the deposit seed need admin
        // (spec/crypto.md §3: inbox and deposit seed by an admin); read and write keysets their
        // rotator
        let admin = match f.slot(osis_crdt::Encoding::Struct) {
            Some(osis_crdt::MemberRef::Frag(Fragment::Struct(st))) => (2..=5).any(|id| st.field(id).is_some()),
            _ => false,
        };
        return Some(if admin { Role::Admin } else { Role::Write });
    }
    let v = f.read()?;
    let top = match ak {
        "/secrets" => {
            let mut roles = Vec::new();
            for (fid, rid) in [(0, 1), (1, 0)] {
                if let Some(Value::Map(m)) = field(&v, fid) {
                    roles.extend(m.keys().filter_map(|k| field(k, rid)).filter_map(|r| role_of(&r)));
                }
            }
            roles.into_iter().max()
        }
        _ => return None,
    };
    Some(top.unwrap_or(Role::Write).max(Role::Write))
}

/// Records the roles `/secrets` and `/keys` deltas of a commit need, and the `/secrets` parts
/// of a membership commit that write beyond its grantees' boxes.
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    for (ai, _, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(r) = rotation_required(a.ak.as_str(), fragment(d))
        {
            let e = core.rotation_role.entry((*id, *ai)).or_insert(r);
            *e = (*e).max(r);
        }
    }
    if h.kind != Kind::Membership {
        return;
    }
    // the edges this commit puts, per target: what an invite grant may box
    let mut granted: BTreeMap<(Tid, Tid), Role> = BTreeMap::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "/members" {
            for (_, k, frag) in entries(fragment(d)) {
                if let (Some(Value::Tid(m)), Some(e)) = (k, frag.and_then(|f| f.read()).as_ref().and_then(edge_of)) {
                    granted.insert((a.tid, m), e.role);
                }
            }
        }
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "/secrets" && !crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, fragment(d), &granted, &own)) {
            core.grant_overreach.insert((*id, *ai));
        }
    }
    // one delta per `/secrets` aspect, known from the signed header: a node that never holds a
    // part (dropped by expiry or purge) judges the others as one that held it does
    for (ai, a) in h.aspects.iter().enumerate() {
        if a.ak.as_str() == "/secrets" && a.hashes.len() != 1 {
            core.grant_overreach.insert((*id, ai));
        }
    }
}

/// Whether a `/secrets` delta writes only the boxes of the members `granted` puts on `actor`, at
/// or below each one's role, and history boxes at or below the highest granted role, as puts
/// only: entries this delta creates (`own` dots), no reset of the value, a field, a map or any
/// entry (spec/permissions.md §2). Judged from
/// the delta alone, so every node judges it alike whatever it holds.
fn grantee_boxes_only(actor: &Tid, f: &Fragment, granted: &BTreeMap<(Tid, Tid), Role>, own: &crate::engine::Owned) -> bool {
    // a write or reset of the whole value removes every box
    if !f.is_plain_struct() {
        return false;
    }
    let Some(osis_crdt::MemberRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct) else { return false };
    let top = granted.iter().filter(|((t, _), _)| t == actor).map(|(_, r)| *r).max();
    let fits = |k: &ct::BoxKey| granted.get(&(*actor, k.member)).is_some_and(|r| k.role <= *r);
    for id in [0, 1] {
        let Some(field) = st.field(id) else { continue };
        // every entry new: created by this delta (its own dots), never a write into another's
        if !field.is_put_only_map(&|d| own.owns(d)) {
            return false;
        }
        let Some(osis_crdt::MemberRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map) else { return false };
        for (_, _, k, _) in m.entries() {
            let Some(k) = k else { return false };
            let ok = match id {
                0 => typed(k, "box_key").and_then(|k| ct::BoxKey::from_value(&k).ok()).is_some_and(|k| fits(&k)),
                _ => typed(k, "history_key").and_then(|k| ct::HistoryKey::from_value(&k).ok()).is_some_and(|k| top.is_some_and(|t| k.role <= t)),
            };
            if !ok {
                return false;
            }
        }
    }
    true
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

/// Whether `t`'s owner chain is not known to end at a key actor within `MAX_OWNER_DEPTH`
/// owner links (spec/permissions.md §1): deeper, or a creation record on it is not held (unknown
/// counts as invalid, so forgetting a record never makes a deep delta valid). O(`MAX_OWNER_DEPTH`).
pub(crate) fn too_deep(core: &Core, t: &Tid) -> bool {
    let mut cur = *t;
    for _ in 0..=osis_core::format::MAX_OWNER_DEPTH {
        match core.created(&cur) {
            Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
            Some(CreationRecord::KeyActor { .. }) => return false,
            None => return true,
        }
    }
    true
}

/// Is aspect `ai` of a held commit valid (spec/permissions.md §5.2)?
pub(crate) fn part_valid(core: &Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    if core.void.contains(id) {
        return false;
    }
    let Some(a) = h.aspects.get(ai) else { return false };
    let ak = a.ak.as_str();
    // a thing more than `MAX_OWNER_DEPTH` owner links below its key actor: nothing written on
    // it applies (spec/permissions.md §1); judged per delta from creation records alone
    if ak != "/created" && too_deep(core, &a.tid) {
        return false;
    }
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
        && !core.grant_overreach.contains(&(*id, ai))
    {
        return true;
    }
    let dots = if h.kind == Kind::Import { Dots::Commit } else { dots_of(h, ai) };
    let required = core.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| required_role(ak));
    tl.delta_valid(point, &a.tid, ak, dots, required) == Validity::Valid
}

/// Re-judges every held delta after the held set changed; rebuilds aspects whose validity
/// flipped. Returns them.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    if resolve_unresolved(tx)? {
        tx.core.timelines.update(&tx.core.held);
    }
    let mut flipped: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut secrets_flips: Vec<(CommitId, usize, bool)> = Vec::new();
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
                    if x.ak.as_str() == "/secrets" {
                        secrets_flips.push((id, ai, *b));
                    }
                }
            }
            m.valid = now;
            tx.core.index_validity(&id);
        }
    }
    if rebuild {
        for (tid, ak) in &flipped {
            super::rebuild(tx, tid, ak)?;
        }
    }
    for (c, ai, now_valid) in secrets_flips {
        if now_valid {
            super::keys::revalidated(tx, &c, ai)?;
        } else {
            super::keys::invalidated(tx, &c, ai)?;
        }
    }
    Ok(flipped.into_iter().collect())
}

/// Whether `author` lowering `member`'s edge on `target` at `ts` is a self-removal
/// (spec/permissions.md §2): its own edge, or its authority on the target comes only through the
/// member (admin on the member, and no admin on the target without the member's edge).
pub(crate) fn self_removal(core: &Core, author: &Tid, target: &Tid, member: &Tid, ts: osis_core::Ts) -> bool {
    if author == member {
        return true;
    }
    let Some(tl) = core.timelines.get(target) else { return false };
    if tl.role(author, member, At::now(ts)) != Some(Role::Admin) {
        return false;
    }
    let mut edges = tl.edges_at(None).into_owned();
    edges.set(*member, *target, None);
    let view = osis_perm::graph::View { owners: tl.owners(), edges: &edges, ts: Some(ts) };
    view.roles_from(author).get(target).copied() != Some(Role::Admin)
}

/// Rules of a membership commit that need its deltas
/// (spec/commits.md §2, spec/wire.md §4 position 13, spec/permissions.md §3).
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
    // a change is remove + put of one entry: the put is the member's new edge
    let mut net: BTreeMap<(Tid, Tid), Option<Edge>> = BTreeMap::new();
    for (t, m, e) in changed {
        let slot = net.entry((t, m)).or_insert(None);
        if e.is_some() {
            *slot = e;
        }
    }
    let changed: Vec<(Tid, Tid, Option<Edge>)> = net.into_iter().map(|((t, m), e)| (t, m, e)).collect();
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
        let old = core.timelines.get(target).and_then(|tl| tl.edges_at(None).get(m, target).copied());
        // an explicit removal of an absent edge is an edge write too (spec/permissions.md §2)
        new.is_none() || (old.is_some() && osis_perm::types::lowers(new.as_ref(), old.as_ref()))
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
        // a self-removal carries no rotation: the next node that may rotate does it
        // (spec/permissions.md §3)
        if demotes && !self_removal(core, &h.author, target, m, h.ts) && core.own_keys.contains(target) {
            let has = |ak: &str| h.aspects.iter().any(|a| a.tid == *target && a.ak.as_str() == ak);
            if !has("/secrets") || !has("/keys") {
                return Err(Error::BadInput("a removal without the rotation it requires"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_core::{Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/permissions.md §1, §2: the membership-class aspects are written only by admins, except
    // invite grants, which "carry the grantee's boxes for those roles". A grant's `/secrets` part
    // that writes another member's box is not the grantee's: it gets no invite exemption.
    #[test]
    fn invite_grant_secrets_limited_to_grantee_spec_perm_2() {
        let mut lp = LocalPeer::new(3, 901, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let done = lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let grant = *done.commits.last().unwrap();
        let h = lp.peers[0].engine.header(&grant).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "/secrets").unwrap();
        // an admin's grant writes remove + put (no exemption needed): valid as the admin's
        assert!(lp.peers[0].engine.core.commits.get(&grant).unwrap().valid[ai], "an honest grant");
        // a grant of c that also writes a box keyed to b
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (bk, bx) = s.boxes.iter().find(|(k, _)| k.member == b).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &edge).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(bk, bx)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "/secrets").unwrap();
        assert!(lp.peers[0].engine.core.grant_overreach.contains(&(id, ai)));
    }
    // spec/permissions.md §2: an invite grant's `/secrets` delta carries only puts of its
    // grantees' boxes. One that also resets a box entry (here one the receiver has not seen yet)
    // or a history box is un-merged at every node whatever the arrival order: validity depends on
    // the delta alone.
    #[test]
    fn invite_grant_resets_unmerged_any_order_spec_perm_2() {
        use osis_crdt::{Op, PathOp, PathSeg};
        use osis_schema::Codec;
        let mut lp = LocalPeer::new(6, 903, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        // 0 admin, 1 invite holder, 2 grantee, 3 and 4 receivers, 5 a member whose box is reset
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, c, e) = (tid(&mut lp, 0), tid(&mut lp, 2), tid(&mut lp, 5));
        let b = tid(&mut lp, 1);
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // a grant of e the receivers have not seen yet
        let ge = *lp.peers[0].engine.grant(&t, &e, &read).unwrap().commits.last().unwrap();
        let ge = lp.peers[0].engine.package(&ge).unwrap().unwrap();
        lp.deliver(1, &ge).unwrap();
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let ek = s.boxes.keys().find(|k| k.member == e).unwrap().clone();
        let hk = s.history.keys().next().unwrap().clone();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &read).unwrap();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(ek.to_value()) }).unwrap();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1)], op: Op::Remove(hk.to_value()) }).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let bad = lp.peers[1].commit(m).unwrap().unwrap();
        let bad = lp.peers[1].engine.package(&bad).unwrap().unwrap();
        // receiver 3 gets the bad grant first, receiver 4 after the grant of e
        lp.deliver(3, &bad).unwrap();
        lp.deliver(3, &ge).unwrap();
        lp.deliver(4, &ge).unwrap();
        lp.deliver(4, &bad).unwrap();
        let want = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(want.boxes.contains_key(&ek) && want.history.contains_key(&hk));
        for r in [3, 4] {
            assert_eq!(lp.peers[r].engine.roster(&t).get(&c).map(|x| x.role), Some(Role::Read), "the edge itself is a valid invite grant");
            assert_eq!(lp.peers[r].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "receiver {r}");
        }
    }
    // spec/permissions.md §2: an invite grant's `/secrets` entries are new, created by its own
    // delta. A record claiming the grantee's key at another member's entry dot would merge into
    // that entry (the stored key wins), overwriting its box: not a put, no invite exemption.
    #[test]
    fn invite_grant_foreign_entry_dot_rejected_spec_perm_2() {
        use osis_crdt::{Batch, Dot, Encoding, MemberRef, Op, PathOp, PathSeg, Source, Writer};
        use osis_schema::Codec;
        fn box_entries(f: &osis_crdt::Fragment) -> Vec<(Dot, Option<Value>)> {
            let Some(MemberRef::Frag(osis_crdt::Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return Vec::new() };
            let Some(MemberRef::Frag(osis_crdt::Fragment::Map(m))) = st.field(0).and_then(|x| x.slot(Encoding::Map)) else { return Vec::new() };
            m.entries().map(|(d, _, k, _)| (d.clone(), k.cloned())).collect()
        }
        let mut lp = LocalPeer::new(3, 904, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b, g) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), since: None };
        lp.peers[0].engine.grant(&t, &b, &read).unwrap();
        let ak = osis_core::Ak::new("/secrets").unwrap();
        let st = lp.peers[0].engine.state(&t, &ak).unwrap().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        // the admin's own box entry
        let (a_dot, a_key) = box_entries(&st).into_iter().find_map(|(d, k)| Some((d, ct::BoxKey::from_value(&k?).ok().filter(|k| k.member == a)?))).unwrap();
        let bx = s.boxes.get(&a_key).unwrap().clone();
        let g_key = ct::BoxKey { member: g, role: Role::Read, epoch: a_key.epoch.clone() };
        let schema = osis_schema::core_schema();
        let view = schema.view("/secrets").unwrap();
        let ts = osis_core::Ts::make(WallMs(1_700_000_000_100), 0).unwrap();
        let mut batch = Batch::new(&st, Writer::new(ts, Source::node(b), 1));
        batch.apply(&PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(g_key.to_value())], op: Op::Put(bx.to_value()) }, &view).unwrap();
        let (d, range) = batch.finish().unwrap();
        let own = crate::engine::Owned::Node { node: b, lo: range.lo, hi: range.hi };
        let granted = std::collections::BTreeMap::from([((t, g), Role::Read)]);
        assert!(super::grantee_boxes_only(&t, &d, &granted, &own), "an honest put");
        let (g_dot, _) = box_entries(&d).remove(0);
        let mut forged = d.clone();
        forged.map_dots(&|x| (*x == g_dot).then(|| a_dot.clone()));
        assert_eq!(box_entries(&forged).remove(0).0, a_dot);
        assert!(!super::grantee_boxes_only(&t, &forged, &granted, &own), "a write into the admin's entry");
    }
    // spec/permissions.md §1: an owner chain reaches its key actor within `MAX_OWNER_DEPTH` owner
    // links; a delta written on a thing deeper is invalid and the rest of its commit applies, at
    // every node alike. The writer refuses such a commit.
    #[test]
    fn owner_chain_deeper_than_cap_invalid_spec_permissions_1() {
        use osis_core::format::MAX_OWNER_DEPTH;
        let mut lp = LocalPeer::new(3, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let x = osis_core::Ak::new("/x/a").unwrap();
        let mut owner = lp.peers[0].engine.tid();
        let mut shallow = owner;
        for i in 0..MAX_OWNER_DEPTH {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, owner);
            m.set(t, &x, &Value::Int(1)).unwrap();
            lp.peers[0].commit(m).unwrap();
            if i == 0 {
                shallow = t;
            }
            owner = t;
        }
        let at_cap = owner;
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.get(&at_cap, &x).unwrap(), Some(Value::Int(1)), "at the cap: applies");
        // one commit writing a shallow thing and a thing one link too deep
        let mut m = Mutation::new();
        let d = lp.peers[0].engine.new_thing(&mut m, owner);
        m.set(d, &x, &Value::Int(9)).unwrap();
        m.set(shallow, &x, &Value::Int(2)).unwrap();
        assert!(lp.peers[0].commit(m.clone()).is_err(), "the writer refuses it");
        lp.peers[0].engine.core.skip_writer_rules = true;
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        for r in [0, 1, 2] {
            if r > 0 {
                lp.deliver(r, &pk).unwrap();
            }
            assert_eq!(lp.peers[r].engine.get(&shallow, &x).unwrap(), Some(Value::Int(2)), "peer {r}");
            assert_eq!(lp.peers[r].engine.get(&d, &x).unwrap(), None, "peer {r}");
        }
    }
    // spec/permissions.md §2: an invite grant's `/secrets` aspect is one delta (the header
    // says so to every node), so validity never depends on which of several parts a node holds.
    #[test]
    fn invite_grant_secrets_one_delta_spec_perm_2() {
        let mut lp = LocalPeer::new(2, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let done = lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, invite: None, since: None }).unwrap();
        let grant = *done.commits.last().unwrap();
        let mut h = (*lp.peers[0].engine.header(&grant).unwrap()).clone();
        let ai = h.aspects.iter().position(|x| x.ak.as_str() == "/secrets").unwrap();
        let core = &mut lp.peers[0].engine.core;
        let fake = osis_core::CommitId([0xfe; 32]);
        super::note_required(core, &h, &fake, &[]);
        assert!(!core.grant_overreach.contains(&(fake, ai)));
        h.aspects[ai].hashes.push([0; 32]);
        super::note_required(core, &h, &fake, &[]);
        assert!(core.grant_overreach.contains(&(fake, ai)), "two deltas: no exemption whatever is held");
    }
}

#[cfg(test)]
mod keys_tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_core::{Role, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;

    // spec/crypto.md §3: "inbox and deposit seed by an admin; a key actor's by its own key". A
    // writer's `/keys` write of the deposit seed or of a key-actor KEM key is invalid: otherwise a
    // writer (kept valid by its demoter's frontier after removal) set an actor's `key` field and
    // every later grant to the actor was sealed to it.
    #[test]
    fn writer_cannot_write_admin_keys_fields_spec_crypto_3() {
        let mut lp = LocalPeer::new(2, 902, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[1].engine.role_on(&t), Some(Role::Write));
        let before = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let kem = lp.peers[1].engine.core.id.keys().kem.public().clone();
        for (field, v) in [(5u64, Some([9u8; 32]).to_value()), (3, Some(ct::KemKey::X25519MlKem768(kem.as_bytes().to_vec())).to_value())] {
            let mut m = Mutation::new();
            m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(field)], op: Op::Set(v) }).unwrap();
            assert!(lp.peers[1].commit(m.clone()).is_err(), "refused writer-side");
            lp.peers[1].engine.core.skip_writer_rules = true;
            lp.peers[1].commit(m).unwrap().unwrap();
            lp.peers[1].engine.core.skip_writer_rules = false;
        }
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), before);
        // spec/permissions.md §3: a writer rotates read and write only; an admin history box is
        // an admin's write
        let e = lp.peers[0].engine.epochs(&t).unwrap().admin.newest().unwrap();
        let hk = ct::HistoryKey { role: Role::Admin, epoch: osis_keys::aspects::to_schema(&e) };
        let mut m = Mutation::new();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(hk.to_value())], op: Op::Set(Value::Bytes(vec![0; 48])) }).unwrap();
        assert!(lp.peers[1].commit(m.clone()).is_err(), "refused writer-side");
        lp.peers[1].engine.core.skip_writer_rules = true;
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert_ne!(s.history.get(&hk), Some(&vec![0; 48]));
    }

    /// Peer 1 commits `m` past the writer-side rules (they refuse it first).
    fn force(lp: &mut LocalPeer, i: usize, mut m: Mutation) {
        assert!(lp.peers[i].commit(m.clone()).is_err(), "refused writer-side");
        m.unchecked();
        lp.peers[i].engine.core.skip_writer_rules = true;
        lp.peers[i].commit(m).unwrap().unwrap();
        lp.peers[i].engine.core.skip_writer_rules = false;
    }

    // spec/permissions.md §3 (a writer rotates read and write; the admin keyset is an admin's),
    // spec/crypto.md §3: a write or reset of the whole `/keys` or `/secrets` value replaces the
    // admin fields and every box: an admin's write, invalid from a writer
    #[test]
    fn writer_cannot_replace_keys_or_secrets_spec_perm_3() {
        let mut lp = LocalPeer::new(2, 903, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        lp.sync_all().unwrap();
        let keys = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        for ak in ["/keys", "/secrets"] {
            let mut m = Mutation::new();
            m.set(t, &osis_core::Ak::new(ak).unwrap(), &Value::Int(1)).unwrap();
            force(&mut lp, 1, m);
        }
        // a root reset with writer fields only
        let mut k = keys.clone();
        k.admin = None;
        let mut m = Mutation::new();
        m.replace(t, &ct::KEYS, &k).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), keys);
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }

    // spec/permissions.md §2: an invite grant carries the grantee's boxes only; a write of the
    // whole `/secrets` value is no grantee's box
    #[test]
    fn invite_grant_cannot_replace_secrets_spec_perm_2() {
        let mut lp = LocalPeer::new(3, 904, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), since: None }).unwrap();
        lp.sync_all().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &ct::Edge { role: Role::Read, until: None, invite: None, since: None }).unwrap();
        m.set(t, &osis_core::Ak::new("/secrets").unwrap(), &Value::Int(1)).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }
}
