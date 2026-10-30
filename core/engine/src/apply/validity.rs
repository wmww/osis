//! Validity through osis-perm (spec/permissions.md §5): membership commits and roster
//! snapshots become perm's edge-write records (the node's `HeldSet` is perm's `MemoryHeldSet`,
//! kept current), each delta is judged on its own (layer 2), and a change of the held set
//! re-judges every held delta; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the membership-commit content rules
//! osis-commit cannot see (spec/commits.md §2).

use crate::engine::write::required_role;
use crate::engine::{Core, Meta, Owned, Tx, View};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Form, Header, Kind};
use osis_base::{Ak, CommitId, CreationRecord, Role, Tid, Value};
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

fn dots_of_view(v: &View, ai: usize) -> Dots {
    match (v.form, v.aspects.get(ai)) {
        (Form::Node, Some(a)) if a.lo < a.hi => Dots::Node { lo: a.lo, hi: a.hi },
        _ => Dots::Commit,
    }
}


/// Entries of a `/members` (map) fragment: (dot, key, fragment).
fn entries(f: &Fragment) -> Vec<(Dot, Option<Value>, Option<Fragment>)> {
    let Some(osis_crdt::MemberRef::Frag(Fragment::Map(m))) = f.slot(osis_crdt::Encoding::Map) else { return Vec::new() };
    m.entries().map(|(d, _, k, f)| (d.clone(), k.cloned(), f.cloned())).collect()
}

/// A `/members` entry as perm's adaptation reads it: dot, the member its key names (`None`: a
/// key that is no tid), and the edge its fragment reads (`None`: no fragment, an entry reset;
/// `Some(None)`: a fragment reading no well-formed edge).
pub(crate) type Entry = (Dot, Option<Tid>, Option<Option<Edge>>);

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
            let f = d.fragment();
            match h.aspects.get(*ai).map(|a| a.ak.as_str()) {
                Some("/members") => out.push((
                    *ai,
                    EdgePart::Members(
                        entries(f)
                            .into_iter()
                            // a removal record keyed by no tid acts on no member's entry
                            // (spec/crdt.md §5.6)
                            .filter(|(_, k, x)| x.is_some() || k.as_ref().is_none_or(|k| matches!(k, Value::Tid(_))))
                            .map(|(d, k, x)| {
                                let m = match k {
                                    Some(Value::Tid(m)) => Some(m),
                                    _ => None,
                                };
                                (d, m, x.map(|x| x.read().as_ref().and_then(edge_of)))
                            })
                            .collect(),
                    ),
                )),
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
        if let Some(m) = k
            && own.is_some_and(|o| o.owns(d.owner()))
            && core.ix.member_keys.get(&(*target, d.clone())).is_none()
        {
            core.ix.member_keys.insert((*target, d.clone()), *m);
            new = true;
        }
    }
    new
}

/// The edge writes of one `/members` delta of a membership commit, per member: an entry the
/// delta creates sets the edge it reads; an entry reset removes the edge its entry's creation
/// keyed, when the reset carries that key or none (a record acts only on the entry of its key,
/// spec/crdt.md §5.6; an edge change is remove + put, spec/permissions.md §2). With whether
/// every reset's entry is known here: a reset of an entry whose creation is not held names no
/// member yet.
fn edge_ops(core: &Core, target: &Tid, es: &[Entry], dots: Dots, own: Option<&Owned>) -> (Vec<EdgeOp>, bool) {
    let mut known = true;
    let mut per: BTreeMap<Tid, Option<Edge>> = BTreeMap::new();
    let mut set: BTreeSet<Tid> = BTreeSet::new();
    for (d, k, v) in es {
        let created = own.is_some_and(|o| o.owns(d.owner()));
        match (k, v) {
            (Some(m), Some(v)) if created => {
                if let Some(e) = v {
                    per.insert(*m, Some(*e));
                    set.insert(*m);
                }
            }
            // a nested write into another's entry is no edge write (bad input on receipt)
            (_, Some(_)) => {}
            (_, None) => match core.ix.member_keys.get(&(*target, d.clone())) {
                Some(m) if k.is_some_and(|k| k != *m) => {}
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

/// Members whose edge on `target` a `/members` delta writes: an entry it creates names its key,
/// an entry reset the member its creation keyed (known here or not named).
pub(crate) fn edge_members(core: &Core, target: &Tid, f: &Fragment) -> Vec<Tid> {
    entries(f)
        .into_iter()
        .filter_map(|(d, k, v)| match (k, v) {
            (Some(Value::Tid(m)), Some(_)) => Some(m),
            (k, None) => core.ix.member_keys.get(&(*target, d)).copied().filter(|m| k.as_ref().is_none_or(|k| *k == Value::Tid(*m))),
            _ => None,
        })
        .collect()
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
        for m in named_members("/members", d.fragment()) {
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
        if entries(d.fragment()).iter().any(|(dot, _, f)| f.is_some() && !own.as_ref().is_some_and(|o| o.owns(dot.owner()))) {
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
    listed: &'l BTreeSet<osis_base::BlobId>,
}

impl osis_label::BlobFetch for Listed<'_, '_, '_> {
    fn fetch(&mut self, id: &osis_base::BlobId) -> std::result::Result<Vec<u8>, osis_label::Error> {
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
}

/// One linked frontier: from the in-memory cache, the local record, or its tree (recorded then).
/// `Ok(None)` while a listed blob is not held. Charges its canonical bytes to `budget`.
fn linked_frontier(tx: &mut Tx<'_>, tid: &Tid, link: &osis_base::Link, listed: &BTreeSet<osis_base::BlobId>, budget: &mut usize) -> Result<Option<Arc<Frontier>>> {
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
            let b = osis_base::encode(&v);
            tx.txn.put_local(&key, &b, osis_store::Shred::No)?;
            b
        }
    };
    charge(budget, bytes.len())?;
    let v = osis_base::decode(&bytes, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: bytes.len() }).map_err(|_| Error::BadInput("a linked frontier is not canonical"))?;
    let f = typed(&v, "frontier").and_then(|v| ct::Frontier::from_value(&v).ok()).ok_or(Error::BadInput("a linked frontier is not a frontier"))?;
    let f = Arc::new(frontier_of(f));
    tx.core.frontiers.insert(link.hash, (f.clone(), bytes.len()));
    Ok(Some(f))
}

/// Resolves the linked frontiers of a roster snapshot's `/tenures` parts (spec/permissions.md
/// §6): each distinct link (by content hash) read once, within `MAX_LINKED_FRONTIERS`.
pub(crate) fn linked_frontiers(tx: &mut Tx<'_>, h: &Header, parts: &EdgeParts) -> Result<Linked> {
    linked_frontiers_capped(tx, h, parts, osis_base::format::MAX_LINKED_FRONTIERS)
}

pub(crate) fn linked_frontiers_capped(tx: &mut Tx<'_>, h: &Header, parts: &EdgeParts, cap: usize) -> Result<Linked> {
    let mut out = Linked::default();
    if h.kind != Kind::RosterSnapshot {
        return Ok(out);
    }
    let mut links: BTreeMap<[u8; 32], (Tid, osis_base::Link)> = BTreeMap::new();
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
    let listed: BTreeSet<osis_base::BlobId> = h.chunks.iter().map(|c| c.blob).collect();
    let mut budget = cap;
    for (hash, (tid, l)) in links {
        if !listed.contains(&l.blob) {
            return Err(Error::BadInput("a linked frontier outside the commit's chunk list"));
        }
        match linked_frontier(tx, &tid, &l, &listed, &mut budget)? {
            Some(f) => {
                out.frontiers.insert(hash, f);
            }
            // always a wait, whatever this node's epoch start: what counts must not depend on
            // the order snapshots arrived in
            None => {
                out.waiting.insert(tid);
            }
        }
    }
    Ok(out)
}

/// Adds a membership commit's edge writes (or a roster snapshot) to perm's held set. A roster
/// snapshot's thing whose linked frontier is not held here (an applied commit whose tree went:
/// store loss, a partial import) is kept out of perm, never audited by an empty frontier, and
/// `roster_snapshot` refuses it (`Indexes::frontier_unknown`).
///
/// Reads the commit's `View` (`v`); its header (`h`, else decoded from `Core::commits`) only
/// for a roster snapshot whose tenures link their frontiers (the chunk list), so an open adapts
/// without decoding headers.
pub(crate) fn add_membership(tx: &mut Tx<'_>, v: &View, h: Option<&Header>, id: &CommitId, parts: &EdgeParts) -> Result<()> {
    tx.core.stale_commits.insert(*id);
    let links = v.kind == Kind::RosterSnapshot && parts.tenures().any(|(_, ts)| ts.iter().any(|t| matches!(t.frontier, Some(osis_schema::Chunked::Link(_)))));
    let found = if links && h.is_none() { tx.core.ix.commits.get(id).map(|m| m.header.arc()) } else { None };
    let linked = match h.or(found.as_deref()) {
        Some(h) if links => linked_frontiers(tx, h, parts),
        _ => Ok(Linked::default()),
    };
    let linked = match linked {
        Ok(l) => l,
        Err(_) if tx.core.skip_writer_rules && v.author == tx.core.id.tid() => Linked::default(),
        Err(e) => return Err(e),
    };
    if !linked.waiting.is_empty() {
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::BadInput, tids: linked.waiting.iter().copied().collect(), commit: Some(*id), peer: None, detail: "a roster snapshot's linked frontier is not held: kept out of the timeline".into() }, now);
        tx.core.ix.frontier_unknown.extend(linked.waiting.iter().copied());
    }
    add_membership_in(tx.core, v, id, parts, &linked);
    Ok(())
}

fn add_membership_in(core: &mut Core, h: &View, id: &CommitId, parts: &EdgeParts, linked: &Linked) {
    for (ai, es) in parts.members() {
        if let Some(a) = h.aspects.get(ai) {
            note_keys(core, &a.tid, es, Owned::of_view(h, id, ai).as_ref());
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
                // nothing written on a thing too deep applies (spec/permissions.md §1); its owner
                // chain is held whole at apply (`examine`), so this never changes later
                if too_deep(core, &a.tid) {
                    continue;
                }
                let (v, k) = edge_ops(core, &a.tid, es, dots_of_view(h, ai), Owned::of_view(h, id, ai).as_ref());
                ops.extend(v);
                known &= k;
            }
            if known {
                core.ix.unresolved.remove(id);
            } else {
                core.ix.unresolved.insert(*id);
            }
            match core.ix.held.edge_commit(id) {
                Some(c) if c.ops == ops => return,
                None if ops.is_empty() => return,
                _ => {}
            }
            if ops.is_empty() {
                core.ix.held.remove(id);
            } else {
                core.ix.held.add_commit(MembershipCommit { id: *id, ts: h.ts, author: h.author, actor: h.actor, frontier: h.frontier.clone(), ops });
            }
        }
        Kind::RosterSnapshot => {
            let mut by_thing: BTreeMap<Tid, RosterParts> = BTreeMap::new();
            for (ai, p) in &parts.0 {
                let Some(a) = h.aspects.get(*ai) else { continue };
                let e = by_thing.entry(a.tid).or_insert_with(|| (BTreeMap::new(), Vec::new(), Dots::Commit));
                match p {
                    EdgePart::Members(es) => {
                        e.2 = dots_of_view(h, *ai);
                        for (_, k, v) in es {
                            if let (Some(m), Some(Some(edge))) = (k, v) {
                                e.0.insert(*m, *edge);
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
                if linked.waiting.contains(&thing) || too_deep(core, &thing) {
                    continue;
                }
                core.ix.held.add_snapshot(RosterSnapshot { id: *id, ts: h.ts, author: h.author, actor: h.actor, thing, dots, roster, ledger });
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
    let held = &core.ix.held;
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

/// The role a `/keys` or `/secrets` delta needs (spec/permissions.md §3). `/keys`: a writer
/// rotates read and write, only an admin the admin role; at least write. A delta that is not a
/// plain struct (a write or reset of the whole value) replaces every field: admin.
fn rotation_required(ak: &str, f: &Fragment) -> Option<Role> {
    match ak {
        "/secrets" => return Some(secrets_role(f)),
        "/keys" => {}
        _ => return None,
    }
    if !f.is_plain_struct() {
        return Some(Role::Admin);
    }
    // the admin keyset, a key actor's KEM key, the inbox and the deposit seed need admin
    // (spec/crypto.md §3: inbox and deposit seed by an admin); read and write keysets their
    // rotator
    let admin = match f.slot(osis_crdt::Encoding::Struct) {
        Some(osis_crdt::MemberRef::Frag(Fragment::Struct(st))) => (2..=5).any(|id| st.field(id).is_some()),
        _ => false,
    };
    Some(if admin { Role::Admin } else { Role::Write })
}

/// The role a `/secrets` delta needs (spec/permissions.md §3, spec/crypto.md §4): at least
/// write, and for each entry record (a put, a write into an entry, a removal) the role its key
/// names; a record acts only on the entry of its key (spec/crdt.md §5.6), so this is judged
/// from the delta alone. A key-erased record, a key that is no box or history key, or a write
/// or reset of the whole value or of a field: admin.
fn secrets_role(f: &Fragment) -> Role {
    let Some(osis_crdt::MemberRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct).filter(|_| f.is_plain_struct()) else { return Role::Admin };
    let mut top = Role::Write;
    for id in [0, 1] {
        let Some(field) = st.field(id) else { continue };
        let Some(osis_crdt::MemberRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map).filter(|_| !field.has_reset()) else { return Role::Admin };
        for (_, _, k, _) in m.entries() {
            let role = k.and_then(|k| match id {
                0 => typed(k, "box_key").and_then(|k| ct::BoxKey::from_value(&k).ok()).map(|k| k.role),
                _ => typed(k, "history_key").and_then(|k| ct::HistoryKey::from_value(&k).ok()).map(|k| k.role),
            });
            top = top.max(role.unwrap_or(Role::Admin));
        }
    }
    top
}

/// Records the roles `/secrets` and `/keys` deltas of a commit need, and the `/secrets` parts
/// of a membership commit that write beyond its grantees' boxes. `parts`: every held part of the
/// commit (a late `/secrets` part is judged with the `/members` part held before it).
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    core.stale_commits.insert(*id);
    for (ai, _, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(r) = rotation_required(a.ak.as_str(), d.fragment())
        {
            core.ix.rotation_role.upsert((*id, *ai), || r, |e| *e = (*e).max(r));
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
            for (_, k, frag) in entries(d.fragment()) {
                if let (Some(Value::Tid(m)), Some(e)) = (k, frag.and_then(|f| f.read()).as_ref().and_then(edge_of)) {
                    granted.insert((a.tid, m), e.role);
                }
            }
        }
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "/secrets" {
            if crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, d.fragment(), &granted, &own)) {
                core.ix.grant_overreach.remove(&(*id, *ai));
            } else {
                core.ix.grant_overreach.insert((*id, *ai));
            }
        }
    }
    // one delta per `/secrets` aspect, known from the signed header: a node that never holds a
    // part (dropped by expiry or purge) judges the others as one that held it does
    for (ai, a) in h.aspects.iter().enumerate() {
        if a.ak.as_str() == "/secrets" && a.hashes.len() != 1 {
            core.ix.grant_overreach.insert((*id, ai));
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
    let ids: Vec<CommitId> = tx.core.ix.unresolved.iter().copied().collect();
    let mut any = false;
    for id in ids {
        let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        let parts = super::edge_parts(tx, &id)?;
        let before = tx.core.ix.held.edge_commit(&id).map(|c| c.ops.clone());
        add_membership(tx, &v, None, &id, &parts)?;
        any |= tx.core.ix.held.edge_commit(&id).map(|c| &c.ops) != before.as_ref();
    }
    Ok(any)
}

/// Whether `t`'s owner chain is not known to end at a key actor within `MAX_OWNER_DEPTH`
/// owner links (spec/permissions.md §1): deeper, or a creation record on it is not held (unknown
/// counts as invalid, so forgetting a record never makes a deep delta valid). O(`MAX_OWNER_DEPTH`).
pub(crate) fn too_deep(core: &Core, t: &Tid) -> bool {
    let mut cur = *t;
    for _ in 0..=osis_base::format::MAX_OWNER_DEPTH {
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
    Judge::new(core).part(h, id, ai)
}

/// `part_valid` over many parts: what is per thing (owner depth, timeline) looked up once per
/// run of parts on one thing.
pub(crate) struct Judge<'a> {
    core: &'a Core,
    last: Option<(Tid, bool, Option<&'a osis_perm::Timeline>)>,
    /// On the last thing: per (author, required role), from where its deltas are valid
    /// whatever else (`Timeline::valid_from`).
    from: BTreeMap<(Tid, Role), Option<Option<Point>>>,
}

impl<'a> Judge<'a> {
    pub(crate) fn new(core: &'a Core) -> Judge<'a> {
        Judge { core, last: None, from: BTreeMap::new() }
    }

    /// (too deep, timeline) of `t`.
    fn thing(&mut self, t: &Tid) -> (bool, Option<&'a osis_perm::Timeline>) {
        match self.last {
            Some((x, d, tl)) if x == *t => (d, tl),
            _ => {
                let v = (too_deep(self.core, t), self.core.timelines.get(t));
                self.last = Some((*t, v.0, v.1));
                self.from.clear();
                v
            }
        }
    }

    pub(crate) fn part(&mut self, h: &Header, id: &CommitId, ai: usize) -> bool {
        let core = self.core;
        if core.ix.void.contains(id) {
            return false;
        }
        let Some(a) = h.aspects.get(ai) else { return false };
        let ak = a.ak.as_str();
        // `/created` hashes to its tid; edge writes are layer 1 (reads go through the timeline); a
        // compaction snapshot is judged as its author's write (below), which vouches for every
        // write it carries (spec/permissions.md §5.2)
        if ak == "/created" {
            return true;
        }
        // a thing more than `MAX_OWNER_DEPTH` owner links below its key actor: nothing written on
        // it applies (spec/permissions.md §1); judged per delta from creation records alone
        let (deep, tl) = self.thing(&a.tid);
        if deep {
            return false;
        }
        if ak == "/members" || ak == "/tenures" {
            return true;
        }
        let Some(tl) = tl else { return false };
        // a compaction snapshot: valid iff its author could write the aspect at the snapshot,
        // judged by commit ID (a demotion's frontier lists it), needing the strictest role a
        // write it carries could need (`snapshot_role`: admin for `/keys` and `/secrets`)
        if h.kind.is_compaction() {
            let required = crate::engine::write::snapshot_role(ak);
            let point = Point { ts: h.ts, node: h.author, commit: *id };
            return tl.delta_valid(point, &a.tid, ak, Dots::Commit, required) == Validity::Valid;
        }
        // the author's deltas from its standing tenure on are valid, found once per author
        if !core.ix.rotation_role.contains_key(&(*id, ai)) && ak != "/secrets" {
            let required = required_role(ak);
            let from = *self.from.entry((h.author, required)).or_insert_with(|| tl.valid_from(&h.author, &a.tid, required));
            let point = Point { ts: h.ts, node: h.author, commit: *id };
            if from.is_some_and(|b| b.is_none_or(|b| b <= point)) {
                debug_assert!(valid_on(core, tl, h, id, ai, a), "valid_from disagrees with delta_valid");
                return true;
            }
        }
        valid_on(core, tl, h, id, ai, a)
    }
}

/// `part_valid` of a content part on its thing's timeline `tl`.
fn valid_on(core: &Core, tl: &osis_perm::Timeline, h: &Header, id: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> bool {
    let ak = a.ak.as_str();
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    // an applied invite grant carries the grantee's boxes (spec/permissions.md §1, §2): every
    // put on the thing applied as an invite grant (`grant_overreach` checked the boxes against
    // all of them), so a self-removal beside a failing put exempts nothing
    if ak == "/secrets"
        && let Some(c) = tl.membership_commit(id)
        && !core.ix.grant_overreach.contains(&(*id, ai))
    {
        let grant = |i: usize| matches!(tl.applied().get(&WriteId::Op(*id, i as u32)), Some(x) if matches!(x.attr, osis_perm::Attr::By(osis_perm::Class::Invite(_))));
        let mut puts = c.ops.iter().enumerate().filter(|(_, o)| o.target == a.tid && o.edge.is_some()).peekable();
        if puts.peek().is_some() && puts.all(|(i, _)| grant(i)) {
            return true;
        }
    }
    let dots = if h.kind == Kind::Import { Dots::Commit } else { dots_of(h, ai) };
    let required = core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| required_role(ak));
    tl.delta_valid(point, &a.tid, ak, dots, required) == Validity::Valid
}

/// Writes a held compaction snapshot holds under dots whose owning delta was never received here
/// (`owner_received`), per snapshot and source, counters sorted: the snapshots to compare with
/// that delta once it arrives (`uncarry`, `differing_copies`), and what a snapshot gave, removed
/// when it turns invalid (`given_by`). Kept for every held snapshot whatever its validity, in
/// (snapshot, source) order whatever the arrival order. Nothing is judged per write: a valid
/// snapshot vouches for every write it carries (spec/permissions.md §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Carried {
    pub snap: CommitId,
    pub src: osis_crdt::Source,
    pub ctrs: Vec<u64>,
}

/// The writes of snapshot fragment `f` of `(tid, ak)` whose owning delta was never received
/// here, by source. A record carrying no `ts` (a tombstone, a bare anchor) carries no write.
fn carried_of(core: &Core, tid: &Tid, ak: &Ak, f: &Fragment) -> BTreeMap<osis_crdt::Source, BTreeSet<u64>> {
    let mut out: BTreeMap<osis_crdt::Source, BTreeSet<u64>> = BTreeMap::new();
    for (d, ts) in f.writes() {
        if ts.is_some() && !d.src.is_derived() && !owner_received(core, tid, ak, &d) {
            out.entry(d.src.clone()).or_default().insert(d.ctr);
        }
    }
    out
}

/// Whether some held commit owning dot `d` on `(tid, ak)` (spec/permissions.md §5.2) has its
/// delta of that aspect as `f` judges it: the node-form commit whose range holds it; for
/// `Commit(c)`, `c` itself as a commit-form commit with the aspect, else any held import of `c`
/// with it (§7, `Core::imports`; `c` on the moved thing owns nothing there).
pub(crate) fn any_owner(core: &Core, tid: &Tid, ak: &Ak, d: &Dot, f: &dyn Fn(&CommitId, &Meta, usize) -> bool) -> bool {
    let at = |m: &Meta| m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak);
    let d = d.owner();
    match d.src.kind() {
        osis_crdt::SourceKind::Node(_) => core.commit_of(tid, ak, d).is_some_and(|c| core.ix.commits.get(&c).is_some_and(|m| at(m).is_some_and(|ai| f(&c, m, ai)))),
        osis_crdt::SourceKind::Commit(c) => {
            if let Some(m) = core.ix.commits.get(c).filter(|m| m.view.form == Form::Commit && m.view.kind.has_own_writes())
                && let Some(ai) = at(m)
            {
                return f(c, m, ai);
            }
            core.ix.imports.get(&(*tid, *c)).is_some_and(|s| s.iter().any(|i| core.ix.commits.get(i).is_some_and(|m| at(m).is_some_and(|ai| f(i, m, ai)))))
        }
        osis_crdt::SourceKind::Derived(_) => false,
    }
}

/// Whether the delta owning dot `d` on `(tid, ak)` was ever held here (held or dropped): the
/// write counts from that delta alone, a snapshot's copy of it for nothing (spec/permissions.md
/// §5.2, `Fragment::strip_copies`).
pub(crate) fn owner_received(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai))
}

/// Whether the delta owning dot `d` on `(tid, ak)` is held here (not dropped).
pub(crate) fn owner_held(core: &Core, tid: &Tid, ak: &Ak, d: &Dot) -> bool {
    any_owner(core, tid, ak, d, &|_, m, ai| !m.missing.contains(&ai) && !m.dropped.contains_key(&ai))
}

/// Whether held snapshot `snap`'s part on `(tid, ak)` is valid (`Judge::part`: its author could
/// write the aspect at it).
pub(crate) fn snapshot_valid(core: &Core, snap: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(snap).is_some_and(|m| m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak).is_some_and(|ai| m.valid.get(ai).copied().unwrap_or(false)))
}

/// Whether held commit `c` is a compaction snapshot whose part on `(tid, ak)` is invalid: its
/// body gives nothing (not joined, replayed or covering).
pub(crate) fn invalid_snapshot(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction()) && !snapshot_valid(core, c, tid, ak)
}

/// Whether held commit `c` owns its `Commit(c)` dots on `(tid, ak)`: a commit-form commit with
/// own writes and a delta of that aspect (spec/permissions.md §5.2), as `any_owner` prefers it.
pub(crate) fn owns_commit_dots(core: &Core, c: &CommitId, tid: &Tid, ak: &Ak) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.view.form == Form::Commit && m.view.kind.has_own_writes() && m.view.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak))
}

/// The imports that commit `id` (header `h`, being applied) makes void: itself if it is an
/// import naming as origin a held commit with a delta on its thing, else the held imports on its
/// things naming it (spec/permissions.md §7: origins are commits of other things).
pub(crate) fn self_origin_imports(core: &Core, id: &CommitId, h: &Header) -> BTreeSet<CommitId> {
    let mut out = BTreeSet::new();
    if h.kind == Kind::Import {
        if h.origins.iter().any(|o| core.ix.commits.get(&o.commit).is_some_and(|m| m.view.aspects.iter().any(|x| h.aspects.iter().any(|a| a.tid == x.tid)))) {
            out.insert(*id);
        }
        return out;
    }
    let things: BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
    for t in things {
        out.extend(core.ix.imports.get(&(t, *id)).into_iter().flatten().copied());
    }
    out
}

/// Records the held imports per (thing, origin) (`Core::imports`: which delta owns a `Commit`
/// source's writes on a thing, spec/permissions.md §7), and refuses carried writes stamped after
/// the commit carrying them (spec/crdt.md §8, §7): a node's next stamp exceeds every stamp it
/// holds (§2.2).
pub(crate) fn note_imports(core: &mut Core, id: &CommitId, h: &Header, parts: &[(usize, usize, osis_commit::Decoded)]) -> Result<()> {
    if h.kind == Kind::Import {
        for a in &h.aspects {
            for o in &h.origins {
                core.ix.imports.insert((a.tid, o.commit), *id);
            }
        }
    }
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
    Ok(())
}

/// Records the writes snapshot `snap`'s fragment `f` of `(tid, ak)` carries whose owning delta
/// was never received here (any snapshot held, whatever its validity).
pub(crate) fn note_carried(core: &mut Core, tid: &Tid, ak: &Ak, snap: &CommitId, f: &Fragment) {
    let k = (*tid, ak.clone());
    let before = core.ix.carried.get(&k).cloned().unwrap_or_default();
    let mut cur: Vec<Carried> = before.iter().filter(|c| c.snap != *snap).cloned().collect();
    cur.extend(carried_of(core, tid, ak, f).into_iter().map(|(src, ctrs)| Carried { snap: *snap, src, ctrs: ctrs.into_iter().collect() }));
    // in one order whatever order the snapshots arrived in
    cur.sort_by(|x, y| (x.snap, &x.src).cmp(&(y.snap, &y.src)));
    if cur == before {
        return;
    }
    if cur.is_empty() {
        core.ix.carried.remove(&k);
    } else {
        core.ix.carried.insert(k, cur);
    }
}

/// The writes of held snapshot `snap` on `(tid, ak)` whose owning delta was never received: they
/// go from the state when it turns invalid (spec/permissions.md §5.2), all of them, also those
/// another held valid snapshot carries (its body gives its own copy back in the rebuild; the
/// state may hold this one's differing copy, which would otherwise stay).
pub(crate) fn given_by(core: &Core, tid: &Tid, ak: &Ak, snap: &CommitId) -> Vec<Owned> {
    let gs = core.ix.carried.get(&(*tid, ak.clone())).map(Vec::as_slice).unwrap_or_default();
    gs.iter().filter(|g| g.snap == *snap).map(|g| Owned::Dots { src: g.src.clone(), ctrs: g.ctrs.clone() }).collect()
}

/// Drops the carried writes a commit owns on the aspects whose deltas it now holds (`held`):
/// its counters (node form), its whole source (commit form), its origins' sources (an import).
/// Returns, per such aspect, the snapshots whose copies it dropped: they are compared with the
/// delta (`differing_copies`).
pub(crate) fn uncarry(core: &mut Core, id: &CommitId, h: &Header, held: &dyn Fn(usize) -> bool) -> Vec<(Tid, Ak, BTreeSet<CommitId>)> {
    let mut srcs: Vec<osis_crdt::Source> = h.origins.iter().filter(|_| h.kind == Kind::Import).map(|o| osis_crdt::Source::commit(o.commit)).collect();
    if h.kind.has_own_writes() && h.form == Form::Commit {
        srcs.push(osis_crdt::Source::commit(*id));
    }
    let node_src = (h.kind.has_own_writes() && h.form == Form::Node).then(|| osis_crdt::Source::node(h.author));
    let mut out = Vec::new();
    if srcs.is_empty() && node_src.is_none() {
        return out;
    }
    for (_, a) in h.aspects.iter().enumerate().filter(|(ai, _)| held(*ai)) {
        let k = (a.tid, a.ak.clone());
        let owns = |src: &osis_crdt::Source, x: u64| srcs.contains(src) || (node_src.as_ref() == Some(src) && a.lo <= x && x < a.hi);
        if !core.ix.carried.get(&k).is_some_and(|v| v.iter().any(|c| c.ctrs.iter().any(|x| owns(&c.src, *x)))) {
            continue;
        }
        let mut v = core.ix.carried.get(&k).cloned().unwrap_or_default();
        let mut snaps = BTreeSet::new();
        for c in v.iter_mut() {
            let n = c.ctrs.len();
            let src = c.src.clone();
            c.ctrs.retain(|x| !owns(&src, *x));
            if c.ctrs.len() != n {
                snaps.insert(c.snap);
            }
        }
        v.retain(|c| !c.ctrs.is_empty());
        if v.is_empty() {
            core.ix.carried.remove(&k);
        } else {
            core.ix.carried.insert(k, v);
        }
        out.push((a.tid, a.ak.clone(), snaps));
    }
    out
}

/// Writes held snapshots' copy indexes may hold in all (`Core::copy_index`).
const COPY_CACHE_MAX: usize = 1 << 20;

/// The owner dots of commit `id`'s delta `ai` (header `h`) as (source, counters `lo..hi`):
/// its counter range, its source in commit form, an import's origins' sources.
pub(crate) fn owned_ranges(h: &Header, id: &CommitId, ai: usize) -> Vec<(osis_crdt::Source, u64, u64)> {
    if h.kind == Kind::Import {
        return h.origins.iter().map(|o| (osis_crdt::Source::commit(o.commit), 1, u64::MAX)).collect();
    }
    match (h.form, h.aspects.get(ai)) {
        (_, None) => Vec::new(),
        (_, Some(_)) if !h.kind.has_own_writes() => Vec::new(),
        (Form::Node, Some(a)) => vec![(osis_crdt::Source::node(h.author), a.lo, a.hi)],
        (Form::Commit, Some(_)) => vec![(osis_crdt::Source::commit(*id), 1, u64::MAX)],
    }
}

/// Held snapshot `s`'s writes on `(tid, ak)` by dot (`Core::copy_index`); `have`: its
/// fragment, when the caller read it.
pub(crate) fn copy_index(tx: &mut Tx<'_>, s: &CommitId, tid: &Tid, ak: &Ak, have: Option<&Fragment>) -> Result<Option<Arc<osis_crdt::CopyIndex>>> {
    let k = (*s, *tid, ak.clone());
    if let Some(ix) = tx.core.copy_index.get(&k) {
        return Ok(Some(ix.clone()));
    }
    let ix = match have {
        Some(f) => Arc::new(f.copy_index()),
        None => {
            let Some(sai) = tx.core.ix.commits.get(s).and_then(|m| m.view.aspects.iter().position(|x| x.tid == *tid && x.ak == *ak)) else { return Ok(None) };
            let Some(f) = super::held_parts(tx, s, sai)?.into_iter().next().map(Decoded::into_fragment) else { return Ok(None) };
            Arc::new(f.copy_index())
        }
    };
    if tx.core.copy_index.values().map(|x| x.len()).sum::<usize>() + ix.len() > COPY_CACHE_MAX {
        tx.core.copy_index.clear();
    }
    tx.core.copy_index.insert(k, ix.clone());
    Ok(Some(ix))
}

/// The dots among those `owned` matches under which a held valid snapshot of `(tid, ak)` holds a
/// write: those writes count whatever their own delta's validity, as the snapshot's writer
/// vouched for them (spec/permissions.md §5.2). `have`: valid snapshots' fragments the caller
/// read, by commit.
pub(crate) fn vouched(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, owned: &[Owned], have: &BTreeMap<CommitId, &Fragment>) -> Result<BTreeSet<Dot>> {
    let mut out = BTreeSet::new();
    if owned.is_empty() {
        return Ok(out);
    }
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().map(|s| s.1).filter(|s| snapshot_valid(tx.core, s, tid, ak)).collect();
    for s in snaps {
        let Some(ix) = copy_index(tx, &s, tid, ak, have.get(&s).copied())? else { continue };
        for o in owned {
            let (src, lo, hi) = match o {
                Owned::Node { node, lo, hi } => (osis_crdt::Source::node(*node), *lo, *hi),
                Owned::Commit(c) => (osis_crdt::Source::commit(*c), 0, u64::MAX),
                Owned::Dots { src, ctrs } => (src.clone(), ctrs.first().copied().unwrap_or(0), ctrs.last().map_or(0, |x| x.saturating_add(1))),
            };
            out.extend(ix.dots_in(&src, lo, hi).filter(|d| o.owns(d)).cloned());
        }
    }
    Ok(out)
}

/// The dots under which the snapshots `snaps` hold copies of the writes of commit `id`'s delta
/// `ai` (header `h`, stored) otherwise than that delta holds them (spec/permissions.md §5.2:
/// another value, `ts` or position, or a dot the delta does not use). Copies a snapshot taken
/// here before the delta gave the state; a rebuild replaces those with the delta's. O(delta)
/// once a snapshot is indexed.
pub(crate) fn differing_copies(tx: &mut Tx<'_>, h: &Header, id: &CommitId, ai: usize, snaps: &BTreeSet<CommitId>) -> Result<BTreeSet<Dot>> {
    let mut out = BTreeSet::new();
    let Some(a) = h.aspects.get(ai) else { return Ok(out) };
    let ranges = owned_ranges(h, id, ai);
    let own: Vec<Fragment> = super::held_parts(tx, id, ai)?.into_iter().map(Decoded::into_fragment).collect();
    let own: Vec<&Fragment> = own.iter().collect();
    for s in snaps {
        if let Some(ix) = copy_index(tx, s, &a.tid, &a.ak, None)? {
            out.extend(ix.outside(&ranges, &own));
        }
    }
    Ok(out)
}

/// Re-judges the held deltas whose validity may have changed since the last call: those on the
/// things whose timeline changed (`Core::stale_things`, filled by `update_timelines`: the things
/// of components evaluated anew, and below what a continued walk touched), the commits whose
/// other inputs changed (`stale_commits`: void, required roles, overreach), every one after a
/// rebuild at open (`stale_all`); so the cost follows the change, not the held set. Rebuilds
/// aspects whose validity flipped; returns them.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    let _s = crate::costs::span("rejudge");
    if resolve_unresolved(tx)? {
        tx.core.update_timelines();
    }
    let mut flipped: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // aspects where something became valid again: re-merging needs the held bodies
    let mut rose: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // per aspect, the parts that went invalid (their bodies say which pages to un-merge)
    let mut fell: BTreeMap<(Tid, Ak), Vec<(CommitId, usize)>> = BTreeMap::new();
    let mut secrets_flips: Vec<(CommitId, usize, bool)> = Vec::new();
    let mut intro_flips: BTreeSet<Tid> = BTreeSet::new();
    let things = std::mem::take(&mut tx.core.stale_things);
    let explicit = std::mem::take(&mut tx.core.stale_commits);
    let all = std::mem::take(&mut tx.core.stale_all);
    let judge = crate::costs::span("rejudge: judge");
    // verdicts first (the core read only), each held commit once: by thing, a commit under the
    // first re-judged thing among its aspects; then the commits re-judged whole
    let mut news: Vec<(CommitId, Vec<bool>)> = Vec::new();
    {
        let core: &Core = tx.core;
        let mut judge = Judge::new(core);
        let mut one = |id: &CommitId, m: &Meta, whole: bool| {
            let mut now: Option<Vec<bool>> = None;
            for (ai, a) in m.header.aspects.iter().enumerate() {
                // parts on things not re-judged keep their flag
                if !(whole || things.contains(&a.tid)) {
                    continue;
                }
                let v = judge.part(&m.header, id, ai);
                let old = m.valid.get(ai).copied().unwrap_or(false);
                if v != old {
                    let n = now.get_or_insert_with(|| m.valid.clone());
                    if let Some(x) = n.get_mut(ai) {
                        *x = v;
                    }
                }
            }
            if let Some(n) = now {
                news.push((*id, n));
            }
        };
        if all {
            // after a rebuild only (its headers are decoded)
            for (id, m) in core.ix.commits.iter() {
                one(id, m, true);
            }
        } else {
            // things in order: a commit is met first under the first re-judged thing it writes
            let mut met: BTreeSet<CommitId> = BTreeSet::new();
            for t in &things {
                for id in core.ix.by_thing.get(t).into_iter().flatten() {
                    let Some(m) = core.ix.commits.get(id) else { continue };
                    if !explicit.contains(id) && met.insert(*id) {
                        one(id, m, false);
                    }
                }
            }
            for id in &explicit {
                if let Some(m) = core.ix.commits.get(id) {
                    one(id, m, true);
                }
            }
        }
    }
    for (id, now) in news {
        let Some(m) = tx.core.ix.commits.get_mut(&id) else { continue };
        let h = m.header.clone();
        for (ai, (a, b)) in m.valid.iter().zip(&now).enumerate() {
            if a != b
                && let Some(x) = h.aspects.get(ai)
            {
                flipped.insert((x.tid, x.ak.clone()));
                if *b {
                    rose.insert((x.tid, x.ak.clone()));
                } else {
                    fell.entry((x.tid, x.ak.clone())).or_default().push((id, ai));
                }
                if x.ak.as_str() == "/secrets" {
                    secrets_flips.push((id, ai, *b));
                }
                if matches!(x.ak.as_str(), "/secrets" | "/keys") {
                    intro_flips.insert(x.tid);
                }
                // a snapshot's frontiers count as received while it is valid (`receipt::received`)
                if h.kind.is_compaction() {
                    tx.core.waits.wake(&x.tid, &x.ak);
                }
            }
        }
        m.valid = now;
        tx.core.index_validity(&id);
        tx.core.mark_changed(id);
    }
    drop(judge);
    // what was not re-judged has not changed (debug builds: decodes every header)
    #[cfg(debug_assertions)]
    for (id, m) in tx.core.ix.commits.iter() {
        let now: Vec<bool> = (0..m.header.aspects.len()).map(|ai| part_valid(tx.core, &m.header, id, ai)).collect();
        debug_assert!(now == m.valid, "validity of {id:?} changed outside the re-judged set");
    }
    for (tid, ak) in &flipped {
        tx.core.mark_aspect_changed(tid, ak);
    }
    if rebuild {
        for (tid, ak) in &flipped {
            let k = (*tid, ak.clone());
            // a snapshot turned invalid gives nothing: what it gave goes (its writer no longer
            // vouches for it, spec/permissions.md §5.2; other valid carriers give theirs back),
            // and with it its vouching
            let snaps: Vec<CommitId> = fell.get(&k).into_iter().flatten().filter(|(c, _)| tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction())).map(|x| x.0).collect();
            if rose.contains(&k) || !snaps.is_empty() {
                let _s = crate::costs::span("rejudge: rebuild");
                let mut gone: Vec<Owned> = snaps.iter().flat_map(|s| given_by(tx.core, tid, ak, s)).collect();
                // parts dropped under its cover alone are missing again, their writes gone
                if !snaps.is_empty() {
                    gone.extend(crate::retention::uncover(tx, tid, ak)?);
                }
                super::atomic::rebuild_without(tx, tid, ak, &gone)?;
            } else {
                let _s = crate::costs::span("rejudge: unmerge");
                let bodies = fell_bodies(tx, fell.get(&k).map(Vec::as_slice).unwrap_or_default())?;
                super::atomic::unmerge_fell(tx, tid, ak, bodies)?;
            }
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

/// The bodies of `parts` joined into one fragment (their pages are where un-merging them
/// changes a state), or `None` when one is not held whole (dropped, partly received).
fn fell_bodies(tx: &mut Tx<'_>, parts: &[(CommitId, usize)]) -> Result<Option<Fragment>> {
    let mut out = Fragment::default();
    let mut ch = osis_crdt::Changes::new();
    for (id, ai) in parts {
        let n = tx.core.ix.commits.get(id).filter(|m| !m.dropped.contains_key(ai)).and_then(|m| m.header.aspects.get(*ai)).map(|a| a.hashes.len());
        let bodies = super::held_parts(tx, id, *ai)?;
        if bodies.is_empty() || n != Some(bodies.len()) {
            return Ok(None);
        }
        for d in &bodies {
            out.join_into(d.fragment().clone(), None, &mut ch);
        }
    }
    Ok(Some(out))
}

/// Whether `author` lowering `member`'s edge on `target` at `ts` is a self-removal
/// (spec/permissions.md §2): its own edge, or its authority on the target comes only through the
/// member (admin on the member, and no admin on the target without the member's edge).
pub(crate) fn self_removal(core: &Core, author: &Tid, target: &Tid, member: &Tid, ts: osis_base::Ts) -> bool {
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
        for (dot, k, frag) in entries(d.fragment()) {
            match k {
                Some(Value::Tid(m)) => changed.push((a.tid, m, frag.and_then(|f| f.read()).as_ref().and_then(edge_of))),
                _ => {
                    if let Some(m) = core.ix.member_keys.get(&(a.tid, dot)) {
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
        if demotes && !self_removal(core, &h.author, target, m, h.ts) && core.ix.own_keys.contains(target) {
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
    use osis_base::{Role, Value, WallMs};
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let done = lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        let grant = *done.commits.last().unwrap();
        let h = lp.peers[0].engine.header(&grant).unwrap();
        let ai = h.aspects.iter().position(|a| a.ak.as_str() == "/secrets").unwrap();
        // an admin's grant writes remove + put (no exemption needed): valid as the admin's
        assert!(lp.peers[0].engine.core.ix.commits.get(&grant).unwrap().valid[ai], "an honest grant");
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
        assert!(lp.peers[0].engine.core.ix.grant_overreach.contains(&(id, ai)));
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
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
        assert!(lp.peers[3].engine.header(&id).is_some() && !lp.peers[3].engine.core.ix.pending.contains_key(&id), "applied without its /secrets part");
        lp.deliver(3, &pk).unwrap();
        let m = lp.peers[3].engine.core.ix.commits.get(&id).unwrap();
        assert!(!m.valid[si], "the late overreaching part is invalid");
        assert!(lp.peers[3].engine.core.ix.grant_overreach.contains(&(id, si)));
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), since: None };
        lp.peers[0].engine.grant(&t, &b, &read).unwrap();
        let ak = osis_base::Ak::new("/secrets").unwrap();
        let st = lp.peers[0].engine.state(&t, &ak).unwrap().unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        // the admin's own box entry
        let (a_dot, a_key) = box_entries(&st).into_iter().find_map(|(d, k)| Some((d, ct::BoxKey::from_value(&k?).ok().filter(|k| k.member == a)?))).unwrap();
        let bx = s.boxes.get(&a_key).unwrap().clone();
        let g_key = ct::BoxKey { member: g, role: Role::Read, epoch: a_key.epoch.clone() };
        let schema = osis_schema::core_schema();
        let view = schema.view("/secrets").unwrap();
        let ts = osis_base::Ts::make(WallMs(1_700_000_000_100), 0).unwrap();
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
        use osis_base::format::MAX_OWNER_DEPTH;
        let mut lp = LocalPeer::new(3, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let x = osis_base::Ak::new("/x/a").unwrap();
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
    // spec/permissions.md §1: an edge write on a thing too deep is invalid like any of its
    // deltas: it never reaches perm (else a deep actor's members would gain its roles on a
    // shallow thing it is a member of), at the writer and at receivers.
    #[test]
    fn edge_on_deep_thing_not_held_spec_permissions_1() {
        use osis_base::format::MAX_OWNER_DEPTH;
        use osis_base::Tid;
        use osis_crdt::{Op, PathOp, PathSeg};
        use osis_perm::HeldSet;
        use osis_schema::Codec;
        let mut lp = LocalPeer::new(2, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let x = lp.peers[1].engine.tid();
        let mut owner = me;
        for _ in 0..MAX_OWNER_DEPTH {
            let mut m = Mutation::new();
            owner = lp.peers[0].engine.new_thing(&mut m, owner);
            lp.peers[0].commit(m).unwrap();
        }
        let mut m = Mutation::new();
        let shallow = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        let edge_in = |m: &mut Mutation, t: Tid, member: Tid| {
            m.op(t, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(ct::Edge { role: Role::Write, until: None, invite: None, since: None }.to_value()) }).unwrap();
        };
        let edge = |t: Tid, member: Tid| {
            let mut m = Mutation::new();
            edge_in(&mut m, t, member);
            m
        };
        lp.peers[0].engine.core.skip_writer_rules = true;
        let mut m = Mutation::new();
        let deep = lp.peers[0].engine.new_thing(&mut m, owner);
        edge_in(&mut m, deep, x);
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        lp.peers[0].commit(edge(shallow, deep)).unwrap();
        lp.peers[0].engine.core.skip_writer_rules = false;
        lp.sync_all().unwrap();
        assert!(lp.peers[1].engine.header(&c).is_some(), "applied at the receiver");
        for r in [0, 1] {
            let held = &lp.peers[r].engine.core.ix.held;
            assert!(held.edge_commits(&deep).is_empty(), "peer {r}");
            assert!(!held.edge_commits(&shallow).is_empty(), "peer {r}: the shallow edge counts");
        }
    }
    // spec/permissions.md §2: the invite exemption is for an applied invite grant's boxes. A
    // reader pairing its own removal (which always applies) with a put that fails gets no
    // exemption: its boxes for the failed grantee and its history boxes are judged as its own
    // `/secrets` write (admin), invalid. A redemption-shaped grant by an invite holder stays valid.
    #[test]
    fn self_removal_beside_failing_grant_no_exemption_spec_perm_2() {
        use osis_base::Tid;
        use osis_crdt::{Op, PathOp};
        let mut lp = LocalPeer::new(4, 908, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (a, r, z, g) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let read = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &r, &read).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let (rk, rb) = before.boxes.iter().find(|(k, _)| k.member == r).map(|(k, v)| (k.clone(), v.clone())).unwrap();
        let zk = ct::BoxKey { member: z, role: Role::Admin, epoch: rk.epoch.clone() };
        let hk = ct::HistoryKey { role: Role::Admin, epoch: rk.epoch.clone() };
        let commit = |lp: &mut LocalPeer, who: Tid, edge: ct::Edge, i: usize| {
            let mut m = Mutation::new();
            m.op(t, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(lp.peers[i].engine.tid())) }).unwrap();
            crate::flows::put_edge(&mut m, t, who, &edge).unwrap();
            let k = ct::BoxKey { member: who, role: edge.role, ..zk.clone() };
            let h = ct::HistoryKey { role: edge.role, ..hk.clone() };
            let w = osis_keys::SecretsWrite { boxes: [(k, rb.clone())].into_iter().collect(), history: [(h, vec![0; 48])].into_iter().collect(), ..Default::default() };
            crate::flows::put_secrets(&mut m, t, &w, true).unwrap();
            m.unchecked = true;
            lp.peers[i].engine.core.skip_writer_rules = true;
            let id = lp.peers[i].commit(m).unwrap().unwrap();
            lp.peers[i].engine.core.skip_writer_rules = false;
            let pk = lp.peers[i].engine.package(&id).unwrap().unwrap();
            lp.deliver(0, &pk).unwrap();
            let h = lp.peers[0].engine.header(&id).unwrap();
            let si = h.aspects.iter().position(|x| x.ak.as_str() == "/secrets").unwrap();
            lp.peers[0].engine.core.ix.commits.get(&id).unwrap().valid[si]
        };
        // the reader's self-removal plus a put of z at admin (no authority: fails)
        assert!(!commit(&mut lp, z, ct::Edge { role: Role::Admin, ..read.clone() }, 1), "no exemption beside a failing put");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&z), None);
        assert!(!lp.peers[0].engine.roster(&t).contains_key(&r), "the self-removal applies");
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(!s.boxes.contains_key(&zk) && s.history.get(&hk) != Some(&vec![0; 48]));
        // honest shape: an invite holder's grant of g plus its own removal (a redemption)
        lp.peers[0].engine.grant(&t, &z, &ct::Edge { invite: Some(Role::Read), ..read.clone() }).unwrap();
        lp.sync_all().unwrap();
        assert!(commit(&mut lp, g, ct::Edge { role: Role::Read, ..read.clone() }, 2), "an applied invite grant's boxes");
        assert_eq!(lp.peers[0].engine.roster(&t).get(&g).map(|e| e.role), Some(Role::Read));
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let done = lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, invite: None, since: None }).unwrap();
        let grant = *done.commits.last().unwrap();
        let mut h = (*lp.peers[0].engine.header(&grant).unwrap()).clone();
        let ai = h.aspects.iter().position(|x| x.ak.as_str() == "/secrets").unwrap();
        let core = &mut lp.peers[0].engine.core;
        let fake = osis_base::CommitId([0xfe; 32]);
        super::note_required(core, &h, &fake, &[]);
        assert!(!core.ix.grant_overreach.contains(&(fake, ai)));
        h.aspects[ai].hashes.push([0; 32]);
        super::note_required(core, &h, &fake, &[]);
        assert!(core.ix.grant_overreach.contains(&(fake, ai)), "two deltas: no exemption whatever is held");
    }
}

#[cfg(test)]
mod keys_tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Role, Value, WallMs};
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        lp.sync_all().unwrap();
        let keys = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        for ak in ["/keys", "/secrets"] {
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new(ak).unwrap(), &Value::Int(1)).unwrap();
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

    // spec/permissions.md §5.2: a compaction snapshot of `/keys` or `/secrets` needs admin (the
    // strictest role a write it carries could need). Else a writer's `/keys` snapshot carrying a
    // forged admin keyset under a dot nobody holds joined at every receiver, and later admin
    // secrets were sealed to the writer.
    #[test]
    fn writer_snapshot_of_keys_invalid_spec_perm_5_2() {
        use osis_crdt::{Batch, Source, Writer};
        let mut lp = LocalPeer::new(2, 905, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let w = lp.peers[1].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        lp.sync_all().unwrap();
        let keys_ak = osis_base::Ak::new("/keys").unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap();
        assert!(matches!(lp.peers[1].engine.snapshot(&t, &keys_ak), Err(crate::Error::Permission { .. })), "refused writer-side");
        // the writer's state with a forged admin keyset (its write keyset) under a dot nobody holds
        let forged = before.write.clone().unwrap();
        assert_ne!(Some(&forged), before.admin.as_ref());
        let st = lp.peers[1].engine.state(&t, &keys_ak).unwrap().unwrap();
        let ts = lp.peers[1].engine.core.hlc.next();
        let view = osis_schema::core_schema().view("/keys").unwrap();
        let mut batch = Batch::new(&st, Writer::new(ts, Source::commit(osis_base::CommitId([7; 32])), 1));
        batch.apply(&PathOp { path: vec![PathSeg::Field(2)], op: Op::Set(Some(forged.clone()).to_value()) }, &view).unwrap();
        let (d, _) = batch.finish().unwrap();
        let mut st = st.clone();
        st.join(d);
        lp.peers[1].engine.core.states.insert((t, keys_ak.clone()), Some(st));
        lp.peers[1].engine.core.skip_writer_rules = true;
        let snap = lp.peers[1].engine.snapshot(&t, &keys_ak).unwrap().unwrap();
        lp.peers[1].engine.core.skip_writer_rules = false;
        let pk = lp.peers[1].engine.package(&snap).unwrap().unwrap();
        lp.deliver(0, &pk).unwrap();
        assert!(!lp.peers[0].engine.core.ix.commits.get(&snap).unwrap().valid[0], "a writer's /keys snapshot is invalid");
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap(), before);
    }

    // spec/permissions.md §3, spec/crdt.md §5.6: writers W1 and W2 both remove read box X; the
    // admin compacts after W1, drops X's creation and W1's body, then gets W2. A removal carries
    // X's key, so W2 needs the read role wherever it is judged: valid at open, after a rebuild
    // and at every node.
    #[test]
    fn secrets_removal_dropped_creation_open_equals_rebuild() {
        let mut lp = LocalPeer::new(4, 907, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, w1, w2, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let we = ct::Edge { role: Role::Write, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &w1, &we).unwrap();
        lp.peers[0].engine.grant(&t, &w2, &we).unwrap();
        let g = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, ..we.clone() }).unwrap().commits.last().unwrap();
        lp.sync_all().unwrap();
        let rk = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.member == r).unwrap().clone();
        let rm = |lp: &mut LocalPeer, i: usize| {
            let mut m = Mutation::new();
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(rk.to_value()) }).unwrap();
            let id = lp.peers[i].commit(m).unwrap().unwrap();
            (id, lp.peers[i].engine.package(&id).unwrap().unwrap())
        };
        let (c1, p1) = rm(&mut lp, 1);
        let (c2, p2) = rm(&mut lp, 2);
        lp.deliver(0, &p1).unwrap();
        let secrets = osis_base::Ak::new("/secrets").unwrap();
        lp.peers[0].engine.snapshot(&t, &secrets).unwrap().unwrap();
        lp.peers[0].engine.drop_body(&g, &t, &secrets).unwrap();
        lp.peers[0].engine.drop_body(&c1, &t, &secrets).unwrap();
        lp.deliver(0, &p2).unwrap();
        let v = |lp: &LocalPeer| lp.peers[0].engine.core.ix.commits.get(&c2).unwrap().valid[0];
        assert!(v(&lp), "a writer's removal of a read box");
        let d0 = lp.peers[0].engine.index_digest();
        lp.peers[0].engine.rebuild_index().unwrap();
        assert!(v(&lp), "rebuilt alike");
        // validity alike (what dropped bodies noted beyond it: issues/rebuild-dropped-body-notes.md)
        assert_eq!(d0.commits, lp.peers[0].engine.index_digest().commits);
        lp.sync_all().unwrap();
        let want = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        assert!(!want.boxes.contains_key(&rk));
        for i in 0..4 {
            assert!(lp.peers[i].engine.core.ix.commits.get(&c2).unwrap().valid[0], "peer {i}");
            assert_eq!(lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), want, "peer {i}");
        }
    }

    // spec/permissions.md §3, spec/crypto.md §4: a writer rotates read and write only. A removal
    // carries its entry's key and acts only on the entry of that key (spec/crdt.md §5.6), so it
    // needs the role its key names: a writer's removal of admin boxes and admin history boxes is
    // invalid; its removal of a read box is valid, also where it arrives before the box, which
    // it then removes on arrival.
    #[test]
    fn writer_cannot_remove_admin_boxes_spec_perm_3() {
        let mut lp = LocalPeer::new(4, 906, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, w, r) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 3));
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        lp.sync_all().unwrap();
        let before = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        let admin: Vec<_> = before.boxes.keys().filter(|k| k.role == Role::Admin).cloned().collect();
        let hist: Vec<_> = before.history.keys().filter(|k| k.role == Role::Admin).cloned().collect();
        assert!(!admin.is_empty() && !hist.is_empty());
        for k in &admin {
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) }).unwrap();
        }
        for k in &hist {
            m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1)], op: Op::Remove(k.to_value()) }).unwrap();
        }
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        for i in [0, 2] {
            assert_eq!(lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), before, "peer {i}");
        }
        // a read box: the writer may remove it, judged alike before and after its grant arrives
        let grant = *lp.peers[0].engine.grant(&t, &r, &ct::Edge { role: Role::Read, until: None, invite: None, since: None }).unwrap().commits.last().unwrap();
        let grant = lp.peers[0].engine.package(&grant).unwrap().unwrap();
        lp.deliver(1, &grant).unwrap();
        let rk = lp.peers[1].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.keys().find(|k| k.member == r).unwrap().clone();
        let mut m = Mutation::new();
        m.op(t, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(rk.to_value()) }).unwrap();
        let id = lp.peers[1].commit(m).unwrap().unwrap();
        let rm = lp.peers[1].engine.package(&id).unwrap().unwrap();
        lp.deliver(2, &rm).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid[0], "a read box's removal, before the box");
        lp.deliver(2, &grant).unwrap();
        assert!(lp.peers[2].engine.core.ix.commits.get(&id).unwrap().valid[0], "and after it");
        lp.deliver(0, &rm).unwrap();
        for i in [0, 1, 2] {
            assert!(!lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap().boxes.contains_key(&rk), "peer {i}");
        }
    }

    // spec/permissions.md §3, spec/crdt.md §5.6: a `/secrets` removal's role is its record's
    // key's, whatever entry holds its dot (an equivocated or forged key acts only on the entry
    // of that key); a key-erased removal resets every record of its dot: admin
    #[test]
    fn secrets_removal_role_from_its_key_spec_perm_3() {
        let mut lp = LocalPeer::new(2, 908, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let wt = lp.peers[1].engine.tid();
        lp.peers[0].engine.grant(&t, &wt, &ct::Edge { role: Role::Write, until: None, invite: None, since: None }).unwrap();
        let s = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let admin = s.boxes.keys().find(|k| k.role == Role::Admin).unwrap().clone();
        let read = ct::BoxKey { role: Role::Read, ..admin.clone() };
        let src = osis_crdt::Source::node(lp.peers[1].engine.tid());
        let w = osis_crdt::Writer::new(osis_base::Ts::make(WallMs(1_700_000_000_000), 0).unwrap(), src.clone(), 1).keyed_removals(true);
        let dot = osis_crdt::Dot::new(osis_crdt::Source::node(me), 3);
        let rm = |k: Option<&ct::BoxKey>| {
            let f = match k {
                Some(k) => osis_crdt::reset_entries(&w, &[(dot.clone(), k.to_value())]),
                None => osis_crdt::reset_entries(&w.clone().keyed_removals(false), &[(dot.clone(), Value::Int(0))]),
            };
            osis_crdt::Fragment::wrap(&[(osis_crdt::Step::Field(0), None, None)], f)
        };
        assert_eq!(super::secrets_role(&rm(Some(&read))), Role::Write, "a read box's removal: at least write");
        assert_eq!(super::secrets_role(&rm(Some(&admin))), Role::Admin);
        assert_eq!(super::secrets_role(&rm(None)), Role::Admin, "key-erased");
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &b, &ct::Edge { role: Role::Read, until: None, invite: Some(Role::Read), since: None }).unwrap();
        lp.sync_all().unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let mut m = Mutation::new();
        crate::flows::put_edge(&mut m, t, c, &ct::Edge { role: Role::Read, until: None, invite: None, since: None }).unwrap();
        m.set(t, &osis_base::Ak::new("/secrets").unwrap(), &Value::Int(1)).unwrap();
        force(&mut lp, 1, m);
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap(), secrets);
    }
}
