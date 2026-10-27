//! Validity through osis-perm (spec/permissions.md §5): membership commits and roster
//! snapshots become perm's edge-write records (the node's `HeldSet` is perm's `MemoryHeldSet`,
//! kept current), each delta is judged on its own (layer 2), and a change of the held set
//! re-judges every held delta; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the membership-commit content rules
//! osis-commit cannot see (spec/commits.md §2).

use crate::engine::write::required_role;
use crate::engine::{Core, Owned, Tx};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Header, Kind};
use osis_core::{Ak, CommitId, CreationRecord, Role, Tid, Value};
use osis_crdt::{Dot, Fragment};
use osis_perm::{At, Dots, Edge, EdgeOp, Frontier, MembershipCommit, Point, RosterSnapshot, Tenure, Validity, WriteId};
use osis_schema::core_types as ct;
use osis_schema::{Codec, Type, typed_read};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

pub(crate) fn edge_of(v: &Value) -> Option<Edge> {
    let e = ct::Edge::from_value(&typed(v, "edge")?).ok()?;
    let edge = Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(point_of) };
    edge.well_formed().then_some(edge)
}

fn point_of(k: ct::EdgeKey) -> Point {
    Point { ts: k.ts, node: k.node, commit: k.commit }
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

/// A `/members` entry as perm's adaptation reads it: dot, key, and its fragment's value (`None`:
/// no fragment, an entry reset; `Some(None)`: a fragment reading nothing).
pub(crate) type Entry = (Dot, Option<Value>, Option<Option<Value>>);

/// One held `/members` or `/tenures` part of a membership commit as perm's adaptation reads it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EdgePart {
    Members(Vec<Entry>),
    /// The tenure set's elements.
    Tenures(Vec<Value>),
}

/// What perm's adaptation reads of a membership commit's held parts, by aspect index: a function
/// of the commit record, persisted per commit in the index (`engine::index`, `EDGES`) so an open
/// decodes no membership body.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct EdgeParts(pub Vec<(usize, EdgePart)>);

impl EdgeParts {
    pub(crate) fn of(h: &Header, parts: &[(usize, usize, Decoded)]) -> EdgeParts {
        let mut out = Vec::new();
        for (ai, _, d) in parts {
            let f = fragment(d);
            match h.aspects.get(*ai).map(|a| a.ak.as_str()) {
                Some("/members") => out.push((*ai, EdgePart::Members(entries(f).into_iter().map(|(d, k, x)| (d, k, x.map(|x| x.read()))).collect()))),
                Some("/tenures") => out.push((*ai, EdgePart::Tenures(match f.read() {
                    Some(Value::Set(s)) => s.into_iter().collect(),
                    _ => Vec::new(),
                }))),
                _ => {}
            }
        }
        EdgeParts(out)
    }

    fn members(&self) -> impl Iterator<Item = (usize, &[Entry])> {
        self.0.iter().filter_map(|(ai, p)| match p {
            EdgePart::Members(e) => Some((*ai, e.as_slice())),
            EdgePart::Tenures(_) => None,
        })
    }

    fn tenures(&self) -> impl Iterator<Item = (usize, Vec<ct::Tenure>)> + '_ {
        self.0.iter().filter_map(|(ai, p)| match p {
            EdgePart::Tenures(t) => Some((*ai, tenures_of(t))),
            EdgePart::Members(_) => None,
        })
    }
}

/// Records the member of every `/members` entry these deltas create: (target, entry dot) ->
/// member. Only the delta owning the entry's dot (`own`) creates it (a nested write into
/// another's entry is bad input, `check_members_parts`).
fn note_keys(core: &mut Core, target: &Tid, es: &[Entry], own: Option<&Owned>) -> bool {
    let mut new = false;
    for (d, k, _) in es {
        if let Some(Value::Tid(m)) = k
            && own.is_some_and(|o| o.owns(d.owner()))
            && core.member_keys.get(&(*target, d.clone())).is_none()
        {
            core.member_keys.insert((*target, d.clone()), *m);
            new = true;
        }
    }
    new
}

/// The edge writes of one `/members` delta of a membership commit, per member: an entry the
/// delta creates sets the edge it reads; an entry reset of a known key removes it (an edge
/// change is remove + put, spec/permissions.md §2). With whether every reset's key is known
/// here: a reset of an entry whose creation is not held names no member yet.
fn edge_ops(core: &Core, target: &Tid, es: &[Entry], dots: Dots, own: Option<&Owned>) -> (Vec<EdgeOp>, bool) {
    let mut known = true;
    let mut per: BTreeMap<Tid, Option<Edge>> = BTreeMap::new();
    let mut set: BTreeSet<Tid> = BTreeSet::new();
    for (d, k, v) in es {
        let created = own.is_some_and(|o| o.owns(d.owner()));
        match (k, v) {
            (Some(Value::Tid(m)), Some(v)) if created => {
                if let Some(e) = v.as_ref().and_then(edge_of) {
                    per.insert(*m, Some(e));
                    set.insert(*m);
                }
            }
            // a nested write into another's entry is no edge write (bad input on receipt)
            (_, Some(_)) => {}
            (_, None) => match core.member_keys.get(&(*target, d.clone())) {
                Some(m) if !set.contains(m) => {
                    per.insert(*m, None);
                }
                Some(_) => {}
                None => known = false,
            },
        }
    }
    (per.into_iter().map(|(member, edge)| EdgeOp { target: *target, member, edge, dots }).collect(), known)
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
    tenures_of(&s.into_iter().collect::<Vec<_>>())
}

fn tenures_of(s: &[Value]) -> Vec<ct::Tenure> {
    s.iter().filter_map(|t| osis_schema::AspectKey::decode(&ct::TENURES, &Value::Set([t.clone()].into())).ok()).flat_map(|x| x.0).collect()
}

/// A roster snapshot's parts on one thing: roster, ledger, `/members` dots.
type RosterParts = (BTreeMap<Tid, Edge>, Vec<Tenure>, Dots);

/// A roster snapshot naming one member in two `/members` deltas of a thing is bad input
/// (spec/permissions.md §6): which one counts would depend on the deltas a node holds.
pub(crate) fn check_roster_parts(h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    if h.kind != Kind::RosterSnapshot {
        return Ok(());
    }
    let mut seen: BTreeSet<(Tid, Tid)> = BTreeSet::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "/members" {
            continue;
        }
        for m in named_members("/members", fragment(d)) {
            if !seen.insert((a.tid, m)) {
                return Err(Error::BadInput("a roster snapshot names a member twice"));
            }
        }
    }
    Ok(())
}


/// A `/members` delta writing inside an entry it did not create is bad input: an edge change is
/// remove + put (spec/permissions.md §2), judged from the delta and its header alone.
pub(crate) fn check_members_parts(h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "/members" || !h.kind.has_own_writes() {
            continue;
        }
        let own = Owned::of(h, id, *ai);
        if entries(fragment(d)).iter().any(|(dot, _, f)| f.is_some() && !own.as_ref().is_some_and(|o| o.owns(dot.owner()))) {
            return Err(Error::BadInput("a /members write inside an entry the delta did not create"));
        }
    }
    Ok(())
}

/// Local records of linked frontiers read once (`n/` + link content hash -> the frontier's
/// canonical bytes), so judging never depends on the tree blobs staying held.
const FRONTIERS: &[u8] = b"n/";

/// Blob reads restricted to a commit's chunk list (spec/permissions.md §6: a linked frontier's
/// tree blobs are listed); an unlisted blob is bad input, never waited for.
struct Listed<'t, 'a, 'l> {
    blobs: crate::engine::blobs::TxBlobs<'t, 'a>,
    listed: &'l BTreeSet<osis_core::BlobId>,
}

impl osis_label::BlobFetch for Listed<'_, '_, '_> {
    fn fetch(&mut self, id: &osis_core::BlobId) -> std::result::Result<Vec<u8>, osis_label::Error> {
        if !self.listed.contains(id) {
            return Err(osis_label::Error::Verify("a linked frontier blob outside the commit's chunk list"));
        }
        self.blobs.fetch(id)
    }
}

/// What a roster snapshot's linked tenure frontiers resolve to here.
#[derive(Default)]
pub(crate) struct Linked {
    /// By link content hash.
    pub frontiers: BTreeMap<[u8; 32], Arc<Frontier>>,
    /// Things with a linked frontier whose blobs are not held (the commit waits, spec/commits.md
    /// §4; already applied: kept out of perm).
    pub waiting: BTreeSet<Tid>,
    /// Things with a linked frontier not held whose later epoch start is applied: no wait, kept
    /// out of perm.
    pub superseded: BTreeSet<Tid>,
}

/// One linked frontier: from the in-memory cache, the local record, or its tree (recorded then).
/// `Ok(None)` while a listed blob is not held. Charges its canonical bytes to `budget`.
fn linked_frontier(tx: &mut Tx<'_>, tid: &Tid, link: &osis_core::Link, listed: &BTreeSet<osis_core::BlobId>, budget: &mut usize) -> Result<Option<Arc<Frontier>>> {
    let charge = |budget: &mut usize, n: usize| -> Result<()> {
        *budget = budget.checked_sub(n).ok_or(Error::BadInput("linked frontiers above MAX_LINKED_FRONTIERS"))?;
        Ok(())
    };
    if let Some((f, n)) = tx.core.frontiers.get(&link.hash).cloned() {
        charge(budget, n)?;
        return Ok(Some(f));
    }
    let key = [FRONTIERS, &link.hash[..]].concat();
    let bytes = match tx.txn.get_local(&key)? {
        Some(b) => b,
        None => {
            let Some(dedup) = tx.core.dedup(tid) else { return Ok(None) };
            let mut src = Listed { blobs: crate::engine::blobs::TxBlobs::new(&mut tx.txn), listed };
            let mut r = osis_label::BlobReader::new(&dedup, &mut src);
            let v = match osis_label::read_value(*link, &dedup, &mut r, osis_label::LargeParams::FORMAT, *budget) {
                Ok(v) => v,
                Err(osis_label::Error::Missing) => return Ok(None),
                Err(osis_label::Error::TooLarge(_)) => return Err(Error::BadInput("linked frontiers above MAX_LINKED_FRONTIERS")),
                Err(_) => return Err(Error::BadInput("a linked frontier does not read")),
            };
            let b = osis_core::encode(&v);
            tx.txn.put_local(&key, &b, osis_store::Shred::No)?;
            b
        }
    };
    charge(budget, bytes.len())?;
    let v = osis_core::decode(&bytes, &osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() }).map_err(|_| Error::BadInput("a linked frontier is not canonical"))?;
    let f = typed(&v, "frontier").and_then(|v| ct::Frontier::from_value(&v).ok()).ok_or(Error::BadInput("a linked frontier is not a frontier"))?;
    let f = Arc::new(frontier_of(f));
    tx.core.frontiers.insert(link.hash, (f.clone(), bytes.len()));
    Ok(Some(f))
}

/// Resolves the linked frontiers of a roster snapshot's `/tenures` parts (spec/permissions.md
/// §6): each distinct link (by content hash) read once, within `MAX_LINKED_FRONTIERS`.
pub(crate) fn linked_frontiers(tx: &mut Tx<'_>, h: &Header, parts: &EdgeParts) -> Result<Linked> {
    linked_frontiers_capped(tx, h, parts, osis_core::format::MAX_LINKED_FRONTIERS)
}

pub(crate) fn linked_frontiers_capped(tx: &mut Tx<'_>, h: &Header, parts: &EdgeParts, cap: usize) -> Result<Linked> {
    let mut out = Linked::default();
    if h.kind != Kind::RosterSnapshot {
        return Ok(out);
    }
    let mut links: BTreeMap<[u8; 32], (Tid, osis_core::Link)> = BTreeMap::new();
    for (ai, ts) in parts.tenures() {
        let Some(a) = h.aspects.get(ai) else { continue };
        for t in ts {
            if let Some(osis_schema::Chunked::Link(l)) = t.frontier {
                links.entry(l.hash).or_insert((a.tid, l));
            }
        }
    }
    if links.is_empty() {
        return Ok(out);
    }
    let listed: BTreeSet<osis_core::BlobId> = h.chunks.iter().map(|c| c.blob).collect();
    let mut budget = cap;
    for (hash, (tid, l)) in links {
        if !listed.contains(&l.blob) {
            return Err(Error::BadInput("a linked frontier outside the commit's chunk list"));
        }
        match linked_frontier(tx, &tid, &l, &listed, &mut budget)? {
            Some(f) => {
                out.frontiers.insert(hash, f);
            }
            None => {
                let later = tx.core.timelines.get(&tid).and_then(|tl| tl.epoch_start(&tid)).and_then(|c| tx.core.commits.get(&c)).is_some_and(|m| m.header.ts > h.ts);
                if later {
                    out.superseded.insert(tid);
                } else {
                    out.waiting.insert(tid);
                }
            }
        }
    }
    Ok(out)
}

/// Adds a membership commit's edge writes (or a roster snapshot) to perm's held set. A roster
/// snapshot's thing whose linked frontier is not held here (an applied commit whose tree went:
/// store loss, a partial import) is kept out of perm, never audited by an empty frontier, and
/// `roster_snapshot` refuses it (`Core::frontier_unknown`).
pub(crate) fn add_membership(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &EdgeParts) -> Result<()> {
    tx.core.stale_commits.insert(*id);
    let linked = match linked_frontiers(tx, h, parts) {
        Ok(l) => l,
        Err(_) if tx.core.skip_writer_rules && h.author == tx.core.id.tid() => Linked::default(),
        Err(e) => return Err(e),
    };
    if !linked.waiting.is_empty() {
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::BadInput, tids: linked.waiting.iter().copied().collect(), commit: Some(*id), peer: None, detail: "a roster snapshot's linked frontier is not held: kept out of the timeline".into() }, now);
        tx.core.frontier_unknown.extend(linked.waiting.iter().copied());
    }
    add_membership_in(tx.core, h, id, parts, &linked);
    Ok(())
}

fn add_membership_in(core: &mut Core, h: &Header, id: &CommitId, parts: &EdgeParts, linked: &Linked) {
    for (ai, es) in parts.members() {
        if let Some(a) = h.aspects.get(ai) {
            note_keys(core, &a.tid, es, Owned::of(h, id, ai).as_ref());
        }
    }
    match h.kind {
        Kind::Membership => {
            // the writes whose member is known go to perm now; a commit resetting an entry of
            // unknown key stays in `unresolved` and is derived again when keys arrive
            let mut ops = Vec::new();
            let mut known = true;
            for (ai, es) in parts.members() {
                let Some(a) = h.aspects.get(ai) else { continue };
                let (v, k) = edge_ops(core, &a.tid, es, dots_of(h, ai), Owned::of(h, id, ai).as_ref());
                ops.extend(v);
                known &= k;
            }
            if known {
                core.unresolved.remove(id);
            } else {
                core.unresolved.insert(*id);
            }
            match core.held.edge_commit(id) {
                Some(c) if c.ops == ops => return,
                None if ops.is_empty() => return,
                _ => {}
            }
            if ops.is_empty() {
                core.held.remove(id);
            } else {
                core.held.add_commit(MembershipCommit { id: *id, ts: h.ts, author: h.author, actor: h.actor, frontier: header_frontier(h), ops });
            }
        }
        Kind::RosterSnapshot => {
            let mut by_thing: BTreeMap<Tid, RosterParts> = BTreeMap::new();
            for (ai, p) in &parts.0 {
                let Some(a) = h.aspects.get(*ai) else { continue };
                let e = by_thing.entry(a.tid).or_insert_with(|| (BTreeMap::new(), Vec::new(), Dots::Commit));
                match p {
                    EdgePart::Members(es) => {
                        e.2 = dots_of(h, *ai);
                        for (_, k, v) in es {
                            if let (Some(Value::Tid(m)), Some(edge)) = (k, v.as_ref().and_then(|v| v.as_ref()).and_then(edge_of)) {
                                e.0.insert(*m, edge);
                            }
                        }
                    }
                    EdgePart::Tenures(ts) => {
                        for t in tenures_of(ts) {
                            let frontier = match t.frontier {
                                Some(osis_schema::Chunked::Inline(f)) => Some(Arc::new(frontier_of(f))),
                                Some(osis_schema::Chunked::Link(l)) => linked.frontiers.get(&l.hash).cloned(),
                                None => None,
                            };
                            e.1.push(Tenure { member: t.member, role: t.role, since: t.since.map(point_of), until: point_of(t.until), frontier });
                        }
                    }
                }
            }
            for (thing, (roster, ledger, dots)) in by_thing {
                if linked.waiting.contains(&thing) || linked.superseded.contains(&thing) {
                    continue;
                }
                core.held.add_snapshot(RosterSnapshot { id: *id, ts: h.ts, author: h.author, actor: h.actor, thing, dots, roster, ledger });
            }
        }
        _ => {}
    }
}

/// Does a path of held edge writes and owner links lead from `author` to a thing on `chain`?
/// (The author's chain certificates, spec/permissions.md §1, §4: a path climbs membership
/// edges and owner links, as perm's effective role counts them.) Searched backward from
/// `chain`, as perm's `roles_to_any`: from a thing to its owner and to the members named on
/// it, so the search stays within what has authority over the chain.
pub(crate) fn reaches(core: &Core, author: &Tid, chain: &[Tid]) -> bool {
    let held = &core.held;
    let mut stack: Vec<Tid> = chain.to_vec();
    let mut seen: BTreeSet<Tid> = chain.iter().copied().collect();
    while let Some(t) = stack.pop() {
        let owner = match held.created(&t) {
            Some(CreationRecord::Thing { owner, .. }) => Some(owner),
            _ => None,
        };
        for y in owner.into_iter().chain(held.members_of(&t)) {
            if y == author {
                return true;
            }
            if seen.insert(*y) {
                stack.push(*y);
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
/// of a membership commit that write beyond its grantees' boxes. `parts`: every held part of the
/// commit (a late `/secrets` part is judged with the `/members` part held before it).
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    core.stale_commits.insert(*id);
    for (ai, _, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(r) = rotation_required(a.ak.as_str(), fragment(d))
        {
            core.rotation_role.upsert((*id, *ai), || r, |e| *e = (*e).max(r));
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
        if a.ak.as_str() == "/secrets" {
            if crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, fragment(d), &granted, &own)) {
                core.grant_overreach.remove(&(*id, *ai));
            } else {
                core.grant_overreach.insert((*id, *ai));
            }
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
        let Some(h) = tx.core.commits.get(&id).map(|m| m.header.clone()) else { continue };
        let parts = super::edge_parts(tx, &id)?;
        let before = tx.core.held.edge_commit(&id).map(|c| c.ops.clone());
        add_membership(tx, &h, &id, &parts)?;
        any |= tx.core.held.edge_commit(&id).map(|c| &c.ops) != before.as_ref();
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
    // `/created` hashes to its tid; edge writes are layer 1 (reads go through the timeline); a
    // compaction snapshot vouches for nothing: its carried writes are judged each as its
    // author's (`Carried`, spec/permissions.md §5.2)
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

/// Writes a held compaction snapshot carries while their own commit is not held here, per
/// snapshot (`snap`): one group per source and `ts`, its author node, the exact counters
/// (sorted), and those invalid as the author's writes (spec/permissions.md §5.2: a snapshot
/// vouches for nothing). Each counter is judged on its own; exactly the invalid dots are
/// un-merged. A commit-form group (`src` a commit) is judged as that commit's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Carried {
    pub snap: CommitId,
    pub src: osis_crdt::Source,
    pub node: Tid,
    pub ts: osis_core::Ts,
    pub ctrs: Vec<u64>,
    pub invalid: Vec<u64>,
}

/// The writes of snapshot fragment `f` of `(tid, ak)` whose commit is not held, grouped by
/// (source, author node, `ts`) with their exact counters. Every write is judged at the `ts` it
/// carries (a stamp's, an element creation's); a record carrying none (a tombstone, a bare
/// anchor) carries no write of its creator.
pub(crate) fn carried_of(core: &Core, tid: &Tid, ak: &Ak, f: &Fragment) -> Vec<(osis_crdt::Source, Tid, osis_core::Ts, BTreeSet<u64>)> {
    let mut groups: BTreeMap<(osis_crdt::Source, Tid, osis_core::Ts), BTreeSet<u64>> = BTreeMap::new();
    for (d, ts) in f.writes() {
        let Some(ts) = ts else { continue };
        let node = match d.src.kind() {
            // a dot a held commit owns is that commit's write, judged with it
            osis_crdt::SourceKind::Node(n) if core.commit_of(tid, ak, &d).is_none() => *n,
            osis_crdt::SourceKind::Commit(c) if !core.commits.contains_key(c) => match core.authors.get(&(*tid, *c)) {
                Some((n, _)) => *n,
                None => continue,
            },
            _ => continue,
        };
        groups.entry((d.src.clone(), node, ts)).or_default().insert(d.ctr);
    }
    groups.into_iter().map(|((s, n, ts), c)| (s, n, ts, c)).collect()
}

/// The counters of carried group `c` of `(tid, ak)` invalid as their author's writes (§5.2),
/// each judged at the group's `ts` like a delta of its own (commit form: as its commit).
/// Validity only falls once with the counter (a demotion's frontier covers a prefix), so the
/// ends decide where they agree and a binary search finds the split otherwise.
pub(crate) fn carried_invalid(core: &Core, tid: &Tid, ak: &Ak, c: &Carried) -> Vec<u64> {
    if ak.as_str() == "/created" {
        return Vec::new();
    }
    let Some(tl) = core.timelines.get(tid).filter(|_| !too_deep(core, tid)) else { return c.ctrs.clone() };
    let required = required_role(ak.as_str());
    if let osis_crdt::SourceKind::Commit(id) = c.src.kind() {
        let point = Point { ts: c.ts, node: c.node, commit: *id };
        return if tl.delta_valid(point, tid, ak.as_str(), Dots::Commit, required) == Validity::Valid { Vec::new() } else { c.ctrs.clone() };
    }
    // no commit ID is known: the point sorts before the author's commits at that `ts`
    let point = Point { ts: c.ts, node: c.node, commit: CommitId([0; 32]) };
    let ok = |x: u64| x.checked_add(1).is_some_and(|hi| tl.delta_valid(point, tid, ak.as_str(), Dots::Node { lo: x, hi }, required) == Validity::Valid);
    let (Some(first), Some(last)) = (c.ctrs.first().copied(), c.ctrs.last().copied()) else { return Vec::new() };
    match (ok(first), ok(last)) {
        (true, true) => Vec::new(),
        (false, false) if c.ctrs.iter().all(|x| !ok(*x)) => c.ctrs.clone(),
        (true, false) => {
            // the first invalid counter
            let (mut lo, mut hi) = (0usize, c.ctrs.len() - 1);
            while lo + 1 < hi {
                let mid = lo + (hi - lo) / 2;
                if c.ctrs.get(mid).copied().is_some_and(ok) { lo = mid } else { hi = mid }
            }
            c.ctrs.get(hi..).map(<[u64]>::to_vec).unwrap_or_default()
        }
        _ => c.ctrs.iter().copied().filter(|x| !ok(*x)).collect(),
    }
}

/// Records whom commit-form writes on the commit's things are judged as (`Core::authors`): a
/// commit-form commit's author, an import's origins as the importer, a snapshot's `Authors`.
/// A snapshot naming another author or `ts` than a held commit or an earlier snapshot, lacking
/// the author of a commit-form write it carries, or carrying a `ts` for a dot of a held commit
/// other than that commit's, is bad input (spec/crdt.md §8).
pub(crate) fn note_authors(core: &mut Core, id: &CommitId, h: &Header, parts: &[(usize, usize, osis_commit::Decoded)]) -> Result<()> {
    let mut held: Vec<((Tid, CommitId), (Tid, osis_core::Ts))> = Vec::new();
    if h.form == Form::Commit && h.kind.has_own_writes() {
        held.extend(h.aspects.iter().map(|a| ((a.tid, *id), (h.author, h.ts))));
    }
    if h.kind == Kind::Import {
        for a in &h.aspects {
            held.extend(h.origins.iter().map(|o| ((a.tid, o.commit), (h.author, h.ts))));
        }
    }
    for (k, v) in held {
        if core.authors.get(&k) != Some(&v) {
            core.authors.insert(k, v);
            // groups recorded under another claim follow the held commit
            let ks: Vec<(Tid, Ak)> = core.carried.keys().filter(|x| x.0 == k.0).cloned().collect();
            for ak in ks {
                let Some(mut gs) = core.carried.get(&ak).cloned() else { continue };
                let src = osis_crdt::Source::commit(k.1);
                if !gs.iter().any(|g| g.src == src) {
                    continue;
                }
                for g in gs.iter_mut().filter(|g| g.src == src) {
                    (g.node, g.ts) = v;
                    g.invalid = carried_invalid(core, &ak.0, &ak.1, g);
                }
                core.carried.insert(ak, gs);
            }
        }
    }
    // carried writes are stamped no later than the commit carrying them (spec/crdt.md §8,
    // spec/permissions.md §7), so a node's next stamp exceeds every stamp it holds (§2.2)
    for (_, _, d) in parts {
        let carried = match d {
            osis_commit::Decoded::Snapshot(s) => Some(&s.fragment),
            osis_commit::Decoded::Delta(x) if h.kind == Kind::Import => Some(&x.fragment),
            osis_commit::Decoded::Delta(_) => None,
        };
        if carried.and_then(osis_crdt::Fragment::max_ts).is_some_and(|t| t > h.ts) {
            return Err(crate::error::Error::BadInput("carried write stamped after its commit"));
        }
    }
    for (ai, _, d) in parts {
        let (osis_commit::Decoded::Snapshot(s), Some(a)) = (d, h.aspects.get(*ai)) else { continue };
        for (c, v) in &s.authors {
            match core.authors.get(&(a.tid, *c)) {
                Some(x) if x != v => return Err(crate::error::Error::BadInput("snapshot author differs from the held one")),
                Some(_) => {}
                None => {
                    core.authors.insert((a.tid, *c), *v);
                }
            }
        }
        for (d, ts) in s.fragment.writes() {
            match d.src.kind() {
                osis_crdt::SourceKind::Commit(c) => {
                    if !core.authors.contains_key(&(a.tid, *c)) {
                        return Err(crate::error::Error::BadInput("snapshot without the author of a commit-form write"));
                    }
                    if let (Some(ts), Some(m)) = (ts, core.commits.get(c))
                        && m.header.form == Form::Commit
                        && m.header.ts != ts
                    {
                        return Err(crate::error::Error::BadInput("snapshot ts differs from the held commit's"));
                    }
                }
                osis_crdt::SourceKind::Node(_) => {
                    if let Some(ts) = ts
                        && let Some(k) = core.commit_of(&a.tid, &a.ak, &d)
                        && core.commits.get(&k).is_some_and(|m| m.header.ts != ts)
                    {
                        return Err(crate::error::Error::BadInput("snapshot ts differs from the held commit's"));
                    }
                }
                osis_crdt::SourceKind::Derived(_) => {}
            }
        }
    }
    Ok(())
}

/// Records and judges the writes snapshot `snap`'s fragment `f` of `(tid, ak)` carries without
/// their commit (any snapshot held, whatever its validity); whether the aspect's judged set
/// changed.
pub(crate) fn note_carried(core: &mut Core, tid: &Tid, ak: &Ak, snap: &CommitId, f: &Fragment) -> bool {
    let k = (*tid, ak.clone());
    let before = core.carried.get(&k).cloned().unwrap_or_default();
    let mut cur: Vec<Carried> = before.iter().filter(|c| c.snap != *snap).cloned().collect();
    for (src, node, ts, ctrs) in carried_of(core, tid, ak, f) {
        let mut c = Carried { snap: *snap, src, node, ts, ctrs: ctrs.into_iter().collect(), invalid: Vec::new() };
        c.invalid = carried_invalid(core, tid, ak, &c);
        cur.push(c);
    }
    // in one order whatever order the snapshots arrived in
    cur.sort_by(|x, y| (x.snap, &x.src, x.node, x.ts).cmp(&(y.snap, &y.src, y.node, y.ts)));
    if cur == before {
        return false;
    }
    if cur.is_empty() {
        core.carried.remove(&k);
    } else {
        core.carried.insert(k, cur);
    }
    true
}

/// Whether snapshot `snap` carries writes on `(tid, ak)` that are invalid here: they may
/// already sit in the state, joined from other bodies (another's write nested under an entry
/// creation repeats its key), so the aspect is rebuilt (un-merge is a function of the held set,
/// spec/crdt.md §4.6).
pub(crate) fn carries_invalid(core: &Core, tid: &Tid, ak: &Ak, snap: &CommitId) -> bool {
    core.carried.get(&(*tid, ak.clone())).is_some_and(|v| v.iter().any(|c| c.snap == *snap && !c.invalid.is_empty()))
}

/// Drops the carried writes a commit now held owns (judged with it): its counters (node form),
/// its whole source (commit form).
pub(crate) fn uncarry(core: &mut Core, id: &CommitId, h: &Header) {
    if !h.kind.has_own_writes() {
        return;
    }
    let commit_src = osis_crdt::Source::commit(*id);
    let node_src = osis_crdt::Source::node(h.author);
    for a in &h.aspects {
        let k = (a.tid, a.ak.clone());
        let owns = |c: &Carried, x: u64| match h.form {
            Form::Node => c.src == node_src && a.lo <= x && x < a.hi,
            Form::Commit => c.src == commit_src,
        };
        if !core.carried.get(&k).is_some_and(|v| v.iter().any(|c| c.ctrs.iter().any(|x| owns(c, *x)))) {
            continue;
        }
        let mut v = core.carried.get(&k).cloned().unwrap_or_default();
        for c in v.iter_mut() {
            let gone: Vec<u64> = c.ctrs.iter().copied().filter(|x| owns(c, *x)).collect();
            c.ctrs.retain(|x| !gone.contains(x));
            c.invalid.retain(|x| !gone.contains(x));
        }
        v.retain(|c| !c.ctrs.is_empty());
        if v.is_empty() {
            core.carried.remove(&k);
        } else {
            core.carried.insert(k, v);
        }
    }
}


/// Re-judges the held deltas whose validity may have changed since the last call: those on the
/// things whose timeline changed (`Core::stale_things`, filled by `update_timelines`: the things
/// of components evaluated anew, and below what a continued walk touched), the commits whose
/// other inputs changed (`stale_commits`: void, required roles, overreach), every one after a
/// rebuild at open (`stale_all`); so the cost follows the change, not the held set. Writes
/// snapshots carry without their commit on those things too. Rebuilds aspects whose validity
/// flipped; returns them.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    let _s = crate::costs::span("rejudge");
    if resolve_unresolved(tx)? {
        tx.core.update_timelines();
    }
    let mut flipped: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    let mut secrets_flips: Vec<(CommitId, usize, bool)> = Vec::new();
    let mut intro_flips: BTreeSet<Tid> = BTreeSet::new();
    let things = std::mem::take(&mut tx.core.stale_things);
    let explicit = std::mem::take(&mut tx.core.stale_commits);
    let all = std::mem::take(&mut tx.core.stale_all);
    let mut ids = explicit.clone();
    if all {
        ids.extend(tx.core.commits.keys().copied());
    } else {
        ids.extend(things.iter().flat_map(|t| tx.core.by_thing.get(t).into_iter().flatten().copied()));
    }
    for id in ids {
        let Some(m) = tx.core.commits.get(&id) else { continue };
        let h = m.header.clone();
        // parts on things not re-judged keep their flag
        let now: Vec<bool> = (0..h.aspects.len()).map(|ai| if all || explicit.contains(&id) || h.aspects.get(ai).is_some_and(|a| things.contains(&a.tid)) { part_valid(tx.core, &h, &id, ai) } else { m.valid.get(ai).copied().unwrap_or(false) }).collect();
        if tx.core.commits.get(&id).is_some_and(|m| m.valid != now)
            && let Some(m) = tx.core.commits.get_mut(&id)
        {
            for (ai, (a, b)) in m.valid.iter().zip(&now).enumerate() {
                if a != b
                    && let Some(x) = h.aspects.get(ai)
                {
                    flipped.insert((x.tid, x.ak.clone()));
                    if x.ak.as_str() == "/secrets" {
                        secrets_flips.push((id, ai, *b));
                    }
                    if matches!(x.ak.as_str(), "/secrets" | "/keys") {
                        intro_flips.insert(x.tid);
                    }
                }
            }
            m.valid = now;
            tx.core.index_validity(&id);
        }
    }
    // writes carried by snapshots without their commit, on the same things
    let aspects: Vec<(Tid, Ak)> = tx.core.carried.keys().filter(|(t, _)| all || things.contains(t)).cloned().collect();
    for k in aspects {
        let Some(mut v) = tx.core.carried.get(&k).cloned() else { continue };
        let mut any = false;
        for c in v.iter_mut() {
            let now = carried_invalid(tx.core, &k.0, &k.1, c);
            if now != c.invalid {
                c.invalid = now;
                any = true;
            }
        }
        if any {
            tx.core.carried.insert(k.clone(), v);
            flipped.insert(k);
        }
    }
    // what was not re-judged has not changed
    #[cfg(debug_assertions)]
    for (id, m) in tx.core.commits.iter() {
        let now: Vec<bool> = (0..m.header.aspects.len()).map(|ai| part_valid(tx.core, &m.header, id, ai)).collect();
        debug_assert!(now == m.valid, "validity of {id:?} changed outside the re-judged set");
    }
    for (tid, ak) in &flipped {
        tx.core.mark_aspect_changed(tid, ak);
    }
    if rebuild {
        for (tid, ak) in &flipped {
            super::rebuild(tx, tid, ak)?;
            crate::retention::mark_deaths_due(tx, tid, ak)?;
        }
    }
    super::keys::rebuild_intro(tx, &intro_flips)?;
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
    let edges = tl.edges_at(None);
    let view = osis_perm::graph::View::at(tl.owners(), &edges, Some(ts)).patched(*member, *target, None);
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
                    if let Some(m) = core.member_keys.get(&(a.tid, dot)) {
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
        // redemption (a grant plus the author key's own self-removal, both on K,
        // spec/permissions.md §9, spec/commits.md §2)
        let redemption = members.len() == 2 && members.first().map(|m| m.0) == members.last().map(|m| m.0) && changed.iter().any(|c| c.1 == h.author && c.2.is_none()) && changed.iter().any(|c| c.1 != h.author && c.2.is_some());
        // or an explicit removal of several others' edges on one target (a link joiner with
        // the link key), under one frontier and one rotation: no edge of it a self-removal
        let first = members.first().map(|m| m.0);
        let removal = h.frontier.is_some() && changed.iter().all(|c| Some(c.0) == first && c.1 != h.author && c.2.is_none() && !self_removal(core, &h.author, &c.0, &c.1, h.ts));
        if !redemption && !removal {
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
    // spec/permissions.md §2 (an edge change is remove + put): a received `/members` delta
    // writing inside an entry it did not create is bad input, whoever signed it.
    #[test]
    fn nested_members_write_is_bad_input_spec_perm_2() {
        let mut lp = LocalPeer::new(2, 907, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, b, &ct::Edge { role: Role::Write, until: Some(WallMs(1_700_000_100_000)), invite: None, since: None }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.sync_all().unwrap();
        // the role field alone, into the grant's entry: admin, with the `until` left behind
        let mut m = Mutation::new();
        let path = vec![osis_crdt::PathSeg::Key(Value::Tid(b)), osis_crdt::PathSeg::Field(0)];
        m.op(t, &ct::MEMBERS, osis_crdt::PathOp { path, op: osis_crdt::Op::Set(Value::Enum(2, None)) }).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = true;
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        assert!(matches!(lp.peers[1].engine.ingest(&pk.bytes, pk.blobs), Err(crate::Error::BadInput(_))));
        assert_eq!(lp.peers[1].engine.roster(&t).get(&b).map(|e| e.role), Some(Role::Write));
    }
    // spec/permissions.md §2, spec/commits.md §4 (late deltas): an invite holder's grant whose
    // `/secrets` part boxes beyond its grantee is invalid whatever the arrival order; here the
    // `/members` part arrives first and the overreaching `/secrets` part joins late.
    #[test]
    fn overreaching_grant_late_secrets_invalid_spec_perm_2() {
        let mut lp = LocalPeer::new(4, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, b, c) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        // the invite holder grants c and also writes a box keyed to the admin
        let s = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (ak, ab) = s.boxes.iter().find(|(k, _)| k.member == a).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &read).unwrap();
        let w = osis_keys::SecretsWrite { boxes: [(ak, ab)].into_iter().collect(), ..Default::default() };
        crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
        m.unchecked = true;
        lp.peers[1].engine.core.skip_writer_rules = true;
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        let pk = lp.peers[1].engine.package(&id).unwrap().unwrap();
        let blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let si = blob.header.aspects.iter().position(|x| x.ak.as_str() == "/secrets").unwrap();
        let first = osis_commit::rewrite(&blob, |ai, _| ai == si);
        lp.peers[3].engine.ingest(&first.encode(), pk.blobs.clone()).unwrap();
        assert!(lp.peers[3].engine.header(&id).is_some() && !lp.peers[3].engine.core.pending.contains_key(&id), "applied without its /secrets part");
        lp.deliver(3, &pk).unwrap();
        let m = lp.peers[3].engine.core.commits.get(&id).unwrap();
        assert!(!m.valid[si], "the late overreaching part is invalid");
        assert!(lp.peers[3].engine.core.grant_overreach.contains(&(id, si)));
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
