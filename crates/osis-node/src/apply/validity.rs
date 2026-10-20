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

/// Members a roster snapshot's `/members` or `/tenures` delta names (its edges or ledger
/// entries): what a certificate copy of it is projected by (spec/permissions.md §6).
pub(crate) fn named_members(ak: &str, f: &Fragment) -> Vec<Tid> {
    match ak {
        "/members" => entries(f)
            .into_iter()
            .filter_map(|(_, k, _)| match k {
                Some(Value::Tid(m)) => Some(m),
                _ => None,
            })
            .collect(),
        "/tenures" => tenures(f).into_iter().map(|t| t.member).collect(),
        _ => Vec::new(),
    }
}

/// The tenures a `/tenures` delta writes, each typed as a set element (a linked frontier inside
/// it reads as its link); malformed ones are skipped.
fn tenures(f: &Fragment) -> Vec<ct::Tenure> {
    let Some(Value::Set(s)) = f.read() else { return Vec::new() };
    s.into_iter().filter_map(|t| osis_schema::AspectKey::decode(&ct::TENURES, &Value::Set([t].into())).ok()).flat_map(|x| x.0).collect()
}

/// A roster snapshot's parts on one thing: roster, ledger, `/members` dots.
type RosterParts = (BTreeMap<Tid, Edge>, Vec<Tenure>, Dots);

/// Links of the frontiers a `/tenures` delta's tenures carry by link.
fn tenure_links(f: &Fragment) -> Vec<osis_core::Link> {
    tenures(f)
        .into_iter()
        .filter_map(|t| match t.frontier {
            Some(osis_schema::Chunked::Link(l)) => Some(l),
            _ => None,
        })
        .collect()
}

/// A tenure's frontier held by link (spec/permissions.md §6), read from its chunk tree under
/// thing `tid`'s dedup secret; `None` while a blob of it is not held.
fn linked_frontier(tx: &mut Tx<'_>, tid: &Tid, link: &osis_core::Link) -> Result<Option<Frontier>> {
    let Some(dedup) = tx.core.dedup(tid) else { return Ok(None) };
    let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.txn);
    let mut r = osis_label::BlobReader::new(&dedup, &mut blobs);
    match osis_label::read_value(*link, &dedup, &mut r, osis_label::LargeParams::FORMAT, osis_commit::MAX_LIST_BYTES) {
        Ok(v) => {
            let f = typed(&v, "frontier").and_then(|v| ct::Frontier::from_value(&v).ok()).ok_or(Error::BadInput("a linked frontier is not a frontier"))?;
            Ok(Some(frontier_of(f)))
        }
        Err(osis_label::Error::Missing) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The linked frontiers of a roster snapshot's `/tenures` parts, by link content hash; `None`
/// while a blob of one is not held (the commit waits for it, spec/commits.md §4).
pub(crate) fn linked_frontiers(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<Option<BTreeMap<[u8; 32], Arc<Frontier>>>> {
    let mut out = BTreeMap::new();
    if h.kind != Kind::RosterSnapshot {
        return Ok(Some(out));
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "/tenures" {
            continue;
        }
        for l in tenure_links(fragment(d)) {
            match linked_frontier(tx, &a.tid, &l)? {
                Some(f) => {
                    out.insert(l.hash, Arc::new(f));
                }
                None => return Ok(None),
            }
        }
    }
    Ok(Some(out))
}

/// Adds a membership commit's edge writes (or a roster snapshot) to perm's held set. A linked
/// tenure frontier not held here (a part kept from before) audits as empty.
pub(crate) fn add_membership(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    let linked = linked_frontiers(tx, h, parts)?.unwrap_or_default();
    add_membership_in(tx.core, h, id, parts, &linked);
    Ok(())
}

fn add_membership_in(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)], linked: &BTreeMap<[u8; 32], Arc<Frontier>>) {
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
                        for t in tenures(fragment(d)) {
                            let frontier = match t.frontier {
                                Some(osis_schema::Chunked::Inline(f)) => Some(Arc::new(frontier_of(f))),
                                Some(osis_schema::Chunked::Link(l)) => Some(linked.get(&l.hash).cloned().unwrap_or_default()),
                                None => None,
                            };
                            e.1.push(Tenure { member: t.member, role: t.role, since: t.since.map(|k| EdgeKey { ts: k.ts, node: k.node }), until: EdgeKey { ts: t.until.ts, node: t.until.node }, frontier });
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
        if a.ak.as_str() == "/secrets" && !grantee_boxes_only(core, &a.tid, fragment(d), &granted) {
            core.grant_overreach.insert((*id, *ai));
        }
    }
}

/// Whether a `/secrets` delta writes only the boxes of the members `granted` puts on `actor`, at
/// or below each one's role, and history boxes at or below the highest granted role
/// (spec/permissions.md §2: an invite grant carries the grantee's boxes for those roles). A
/// reset of a box entry must be of a grantee's box this node knows (a remove + put); resets of
/// unknown entries and of history entries pass (issues/invite-grant-secrets.md).
fn grantee_boxes_only(core: &Core, actor: &Tid, f: &Fragment, granted: &BTreeMap<(Tid, Tid), Role>) -> bool {
    // a write or reset of the whole value removes every box
    if !f.is_plain_struct() {
        return false;
    }
    let Some(osis_crdt::MemberRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct) else { return false };
    let top = granted.iter().filter(|((t, _), _)| t == actor).map(|(_, r)| *r).max();
    let map_of = |id: u64| match st.field(id).and_then(|x| x.slot(osis_crdt::Encoding::Map)) {
        Some(osis_crdt::MemberRef::Frag(Fragment::Map(m))) => Some(m.clone()),
        _ => None,
    };
    let fits = |k: &ct::BoxKey| granted.get(&(*actor, k.member)).is_some_and(|r| k.role <= *r);
    if let Some(m) = map_of(0) {
        for (d, _, k, _) in m.entries() {
            let key = match k {
                Some(k) => typed(k, "box_key").and_then(|k| ct::BoxKey::from_value(&k).ok()),
                None => match core.box_keys.get(&(*actor, d.clone())) {
                    Some(k) => typed(k, "box_key").and_then(|k| ct::BoxKey::from_value(&k).ok()),
                    None => continue,
                },
            };
            if !key.is_some_and(|k| fits(&k)) {
                return false;
            }
        }
    }
    if let Some(m) = map_of(1) {
        for (_, _, k, _) in m.entries() {
            let Some(k) = k else { continue };
            let ok = typed(k, "history_key").and_then(|k| ct::HistoryKey::from_value(&k).ok()).is_some_and(|k| top.is_some_and(|t| k.role <= t));
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
        add_membership(tx, &m.header, &id, &parts)?;
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
        tx.core.update_timelines();
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
        assert!(!lp.peers[0].engine.core.grant_overreach.contains(&(grant, ai)), "an honest grant");
        // a grant of c that also writes a box keyed to b
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (bk, bx) = s.boxes.iter().find(|(k, _)| k.member == b).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &edge).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(bk, bx)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let h = lp.peers[0].engine.header(&id).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "/secrets").unwrap();
        assert!(lp.peers[0].engine.core.grant_overreach.contains(&(id, ai)));
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
