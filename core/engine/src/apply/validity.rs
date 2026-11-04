//! Validity through osis-perm (spec/permissions.md §5): role commits and roster
//! snapshots become perm's edge-write records (the node's `HeldSet` is perm's `MemoryHeldSet`,
//! kept current), each delta is judged on its own (layer 2), and a change of the held set
//! re-judges every held delta; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the role-commit content rules
//! osis-commit cannot see (spec/commits.md §2).

use crate::engine::write::required_role;
use crate::engine::{Core, Meta, Owned, Tx, View};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Header, Kind};
use osis_base::{Ak, ChainStep, CommitId, CreationRecord, Role, Tid, Value};
use osis_crdt::{Dot, Fragment};
use osis_perm::{At, Edge, EdgeOp, Frontier, RoleCommit, Point, RosterSnapshot, Tenure, Validity, WriteId};
use osis_schema::core_types as ct;
use osis_schema::{Codec, Type, typed_read};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

/// The edge a `roles.0` value reads as: `None` when it is not one, or its `invite` is above its
/// `role` (spec/permissions.md §2), which makes the delta bad by itself (`check_holders_parts`).
pub(crate) fn edge_of(v: &Value) -> Option<Edge> {
    let e = ct::Edge::from_value(&typed(v, "edge")?).ok()?;
    if e.invite.is_some_and(|i| i > e.role) {
        return None;
    }
    Some(Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(point_of), tied: e.tied.map(crate::flows::tied::tie_perm), keyset: e.keyset.map(point_of) })
}

fn point_of(k: ct::EdgeKey) -> Point {
    Point { ts: k.ts, node: k.node, commit: k.commit }
}

fn frontier_of(f: ct::Frontier) -> Frontier {
    Frontier { commits: f.commits }
}

/// The header's frontier (inline, or resolved from its link).
pub(crate) fn header_frontier(h: &Header) -> Option<Arc<Frontier>> {
    let v = h.frontier.as_ref()?;
    let f = ct::Frontier::from_value(&typed(v, "frontier")?).ok()?;
    Some(Arc::new(frontier_of(f)))
}

/// Whether `ak` holds edge writes (`roles.0`, `tenures.0`): perm reads them.
pub(crate) fn edge_ak(ak: &str) -> bool {
    matches!(ak, "roles.0" | "tenures.0")
}

/// Whether `ak`'s writes reach perm instead of a state: edge writes and creation records.
pub(crate) fn perm_ak(ak: &str) -> bool {
    edge_ak(ak) || ak == "created.0"
}

/// Entries of a `roles.0` (map) fragment: (dot, key, fragment).
fn entries(f: &Fragment) -> Vec<(Dot, Option<Value>, Option<Fragment>)> {
    let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = f.slot(osis_crdt::Encoding::Map) else { return Vec::new() };
    m.entries().map(|(d, _, k, f)| (d.clone(), k.cloned(), f.cloned())).collect()
}

/// A `roles.0` entry as perm's adaptation reads it: dot, the holder its key names (`None`: a
/// key that is no tid), and the edge its fragment reads (`None`: no fragment, an entry reset; a
/// fragment reading no edge is bad input, `check_holders_parts`).
pub(crate) type Entry = (Dot, Option<Tid>, Option<Edge>);

/// One held `roles.0` or `tenures.0` part of a role commit as perm's adaptation reads it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EdgePart {
    Holders(Vec<Entry>),
    /// The tenure set's elements.
    Tenures(Vec<Value>),
}

/// What perm's adaptation reads of a role commit's held parts, by aspect index: a function
/// of the commit record, persisted per commit in the index (`engine::index`, `EDGES`) so an open
/// decodes no role body.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct EdgeParts(pub Vec<(usize, EdgePart)>);

impl EdgeParts {
    pub(crate) fn of(h: &Header, parts: &[(usize, usize, Decoded)]) -> EdgeParts {
        let mut out = Vec::new();
        for (ai, _, d) in parts {
            let f = d.fragment();
            match h.aspects.get(*ai).map(|a| a.ak.as_str()) {
                Some("roles.0") => out.push((
                    *ai,
                    EdgePart::Holders(
                        entries(f)
                            .into_iter()
                            // a removal record keyed by no tid acts on no holder's entry
                            // (spec/crdt.md §5.6)
                            .filter(|(_, k, x)| x.is_some() || k.as_ref().is_none_or(|k| matches!(k, Value::Tid(_))))
                            .filter_map(|(d, k, x)| {
                                let m = match k {
                                    Some(Value::Tid(m)) => Some(m),
                                    _ => None,
                                };
                                let edge = match x {
                                    Some(x) => Some(x.read().as_ref().and_then(edge_of)?),
                                    None => None,
                                };
                                Some((d, m, edge))
                            })
                            .collect(),
                    ),
                )),
                Some("tenures.0") => out.push((*ai, EdgePart::Tenures(match f.read() {
                    Some(Value::Set(s)) => s.into_iter().collect(),
                    _ => Vec::new(),
                }))),
                _ => {}
            }
        }
        EdgeParts(out)
    }

    fn holders(&self) -> impl Iterator<Item = (usize, &[Entry])> {
        self.0.iter().filter_map(|(ai, p)| match p {
            EdgePart::Holders(e) => Some((*ai, e.as_slice())),
            EdgePart::Tenures(_) => None,
        })
    }

    fn tenures(&self) -> impl Iterator<Item = (usize, Vec<ct::Tenure>)> + '_ {
        self.0.iter().filter_map(|(ai, p)| match p {
            EdgePart::Tenures(t) => Some((*ai, tenures_of(t))),
            EdgePart::Holders(_) => None,
        })
    }
}

/// Records the holder of every `roles.0` entry these deltas create: (target, entry dot) ->
/// holder. Only the delta owning the entry's dot (`own`) creates it (a nested write into
/// another's entry is bad input, `check_holders_parts`).
fn note_keys(core: &mut Core, target: &Tid, es: &[Entry], own: Option<&Owned>) -> bool {
    let mut new = false;
    for (d, k, _) in es {
        if let Some(m) = k
            && own.is_some_and(|o| o.owns(d.owner()))
            && core.ix.holder_keys.get(&(*target, d.clone())).is_none()
        {
            core.ix.holder_keys.insert((*target, d.clone()), *m);
            new = true;
        }
    }
    new
}

/// The edge writes of one `roles.0` delta of a role commit, per holder: an entry the
/// delta creates sets the edge it reads; an entry reset removes the edge its entry's creation
/// keyed, when the reset carries that key or none (a record acts only on the entry of its key,
/// spec/crdt.md §5.6; an edge change is remove + put, spec/permissions.md §2). With whether
/// every reset's entry is known here: a reset of an entry whose creation is not held names no
/// holder yet.
fn edge_ops(core: &Core, target: &Tid, es: &[Entry], own: Option<&Owned>) -> (Vec<EdgeOp>, bool) {
    let mut known = true;
    let mut per: BTreeMap<Tid, Option<Edge>> = BTreeMap::new();
    let mut set: BTreeSet<Tid> = BTreeSet::new();
    for (d, k, v) in es {
        let created = own.is_some_and(|o| o.owns(d.owner()));
        match (k, v) {
            (Some(m), Some(e)) if created => {
                per.insert(*m, Some(*e));
                set.insert(*m);
            }
            // a nested write into another's entry is no edge write (bad input on receipt)
            (_, Some(_)) => {}
            (_, None) => match core.ix.holder_keys.get(&(*target, d.clone())) {
                Some(m) if k.is_some_and(|k| k != *m) => {}
                Some(m) if !set.contains(m) => {
                    per.insert(*m, None);
                }
                Some(_) => {}
                None => known = false,
            },
        }
    }
    (per.into_iter().map(|(holder, edge)| EdgeOp { target: *target, holder, edge }).collect(), known)
}

/// Holders whose edge on `target` a `roles.0` delta writes: an entry it creates names its key,
/// an entry reset the holder its creation keyed (known here or not named).
pub(crate) fn edge_holders(core: &Core, target: &Tid, f: &Fragment) -> Vec<Tid> {
    entries(f)
        .into_iter()
        .filter_map(|(d, k, v)| match (k, v) {
            (Some(Value::Tid(m)), Some(_)) => Some(m),
            (k, None) => core.ix.holder_keys.get(&(*target, d)).copied().filter(|m| k.as_ref().is_none_or(|k| *k == Value::Tid(*m))),
            _ => None,
        })
        .collect()
}

/// Holders a roster snapshot's `roles.0` or `tenures.0` delta names (its edges or ledger
/// entries): what a certificate copy of it is projected by (spec/permissions.md §6).
pub(crate) fn named_holders(ak: &str, f: &Fragment) -> Vec<Tid> {
    match ak {
        "roles.0" => entries(f)
            .into_iter()
            .filter_map(|(_, k, _)| match k {
                Some(Value::Tid(m)) => Some(m),
                _ => None,
            })
            .collect(),
        "tenures.0" => tenures(f).into_iter().map(|t| t.holder).collect(),
        _ => Vec::new(),
    }
}

/// The tenures a `tenures.0` delta writes, each typed as a set element (a linked frontier inside
/// it reads as its link); malformed ones are skipped.
fn tenures(f: &Fragment) -> Vec<ct::Tenure> {
    let Some(Value::Set(s)) = f.read() else { return Vec::new() };
    tenures_of(&s.into_iter().collect::<Vec<_>>())
}

fn tenures_of(s: &[Value]) -> Vec<ct::Tenure> {
    s.iter().filter_map(|t| osis_schema::AspectKey::decode(&ct::TENURES, &Value::Set([t.clone()].into())).ok()).flat_map(|x| x.0).collect()
}

/// A roster snapshot's parts on one thing: roster, ledger, `roles.0` dots.
type RosterParts = (BTreeMap<Tid, Edge>, Vec<Tenure>);

/// The things on which a roster snapshot's held `roles.0` deltas name one holder twice
/// (spec/permissions.md §6): which one counts would depend on the deltas a node holds. Deltas are
/// fine alone, so this is judged over those held, and an earlier one may have applied: the snapshot
/// stays out of the walk on those things (`add_role_commit`).
pub(crate) fn names_twice(v: &View, parts: &EdgeParts) -> BTreeSet<Tid> {
    let mut seen: BTreeSet<(Tid, Tid)> = BTreeSet::new();
    let mut out = BTreeSet::new();
    for (ai, es) in parts.holders() {
        let Some(a) = v.aspects.get(ai) else { continue };
        for m in es.iter().filter_map(|e| e.1) {
            if !seen.insert((a.tid, m)) {
                out.insert(a.tid);
            }
        }
    }
    out
}

/// A `roles.0` delta writing inside an entry it did not create is bad input (an edge change is
/// remove + put, spec/permissions.md §2), and so is one, of a role commit or a roster snapshot,
/// holding a value that is no well-formed edge (§2): judged from the delta and its header alone,
/// the one judgment of an edge's shape; perm never sees another.
pub(crate) fn check_holders_parts(h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "roles.0" {
            continue;
        }
        let es = entries(d.fragment());
        if es.iter().any(|(_, _, f)| f.as_ref().is_some_and(|f| f.read().as_ref().and_then(edge_of).is_none())) {
            return Err(Error::BadInput("a roles.0 value that is no well-formed edge"));
        }
        if h.kind.has_own_writes() {
            let own = Owned::of(h, id, *ai);
            if es.iter().any(|(dot, _, f)| f.is_some() && !own.as_ref().is_some_and(|o| o.owns(dot.owner()))) {
                return Err(Error::BadInput("a roles.0 write inside an entry the delta did not create"));
            }
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
            let b = match osis_label::LargeReader::new(*link, &dedup, &mut r, osis_label::LargeParams::FORMAT, *budget).read_all() {
                Ok(b) => b,
                Err(osis_label::Error::Missing) => return Ok(None),
                Err(osis_label::Error::TooLarge(_)) => return Err(Error::BadInput("linked frontiers above MAX_LINKED_FRONTIERS")),
                Err(_) => return Err(Error::BadInput("a linked frontier does not read")),
            };
            // by shape, before anything is decoded: a whole-value decode pays for any bytes
            osis_commit::frontier_value(&b).map_err(|_| Error::BadInput("a linked frontier is not a frontier"))?;
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

/// Resolves the linked frontiers of a roster snapshot's `tenures.0` parts (spec/permissions.md
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

/// Adds a role commit's edge writes (or a roster snapshot) to perm's held set. `parts`: its applied
/// edge parts and any `tenures.0` part waiting for a linked frontier (`validity::away_parts`).
///
/// Invariant (spec/permissions.md §6, spec/commits.md §4): whether a snapshot of a thing takes part in
/// the walk is a function of its parts held and the blobs held, read here each time, never of their
/// order. It stays out while a held `tenures.0` part on the thing links a frontier not held (waiting,
/// or an applied commit whose tree went: store loss, a partial import: never audited by an empty
/// frontier, and `roster_snapshot` refuses it, `Indexes::frontier_unknown`), while its linked frontiers
/// are over the bound, or while its deltas name a holder twice. Its applied parts stay in state and
/// its holders named, so what applies never reads this. Authority so does not depend on which part
/// came first: one with the frontier away and one with both parts reads the same roster as one
/// that holds neither.
///
/// Reads the commit's `View` (`v`); its header (`h`, else decoded from `Core::commits`) only
/// for a roster snapshot whose tenures link their frontiers (the chunk list), so an open adapts
/// without decoding headers.
pub(crate) fn add_role_commit(tx: &mut Tx<'_>, v: &View, h: Option<&Header>, id: &CommitId, parts: &EdgeParts) -> Result<()> {
    tx.core.stale_commits.insert(*id);
    let links = v.kind == Kind::RosterSnapshot && parts.tenures().any(|(_, ts)| ts.iter().any(|t| matches!(t.frontier, Some(osis_schema::Chunked::Link(_)))));
    let found = if links && h.is_none() { tx.core.ix.commits.get(id).map(|m| m.header.arc()) } else { None };
    let linked = match h.or(found.as_deref()) {
        Some(h) if links => linked_frontiers(tx, h, parts),
        _ => Ok(Linked::default()),
    };
    let things: BTreeSet<Tid> = if v.kind == Kind::RosterSnapshot { parts.0.iter().filter_map(|(ai, _)| v.aspects.get(*ai)).map(|a| a.tid).collect() } else { BTreeSet::new() };
    let mut linked = match linked {
        Ok(l) => l,
        Err(_) if tx.core.skip_writer_rules && v.author == tx.core.id.tid() => Linked::default(),
        // over the bound together, each part fine alone (`judge_part`)
        Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::BadInput => Linked { frontiers: BTreeMap::new(), waiting: things.clone() },
        Err(e) => return Err(e),
    };
    if !linked.waiting.is_empty() {
        let now = tx.now();
        tx.core.events.diagnostic(crate::Diagnostic { kind: crate::DiagnosticKind::BadInput, tids: linked.waiting.iter().copied().collect(), commit: Some(*id), peer: None, detail: "a roster snapshot's linked frontier is not held: kept out of the timeline".into() }, now);
    }
    for t in &things {
        if linked.waiting.contains(t) {
            tx.core.ix.frontier_unknown.insert(*t, *id);
        } else {
            tx.core.ix.frontier_unknown.remove(t, id);
        }
    }
    if v.kind == Kind::RosterSnapshot && !(tx.core.skip_writer_rules && v.author == tx.core.id.tid()) {
        linked.waiting.extend(names_twice(v, parts));
    }
    add_role_commit_in(tx.core, v, id, parts, &linked);
    Ok(())
}

/// The `tenures.0` parts among `parts` of roster snapshot `id` (waiting alone: checked or not, their
/// hash holds or they are junk that `examine` drops) that link a frontier not held: what keeps the
/// snapshot out of the walk beside its applied parts.
pub(crate) fn away_parts(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &[osis_commit::Part]) -> Vec<(usize, usize, Decoded)> {
    let mut out = Vec::new();
    if h.kind != Kind::RosterSnapshot {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in parts {
        let Some(a) = h.aspects.get(p.ai).filter(|a| a.ak.as_str() == "tenures.0") else { continue };
        let Some(dedup) = tx.core.dedup(&a.tid) else { continue };
        let mut blobs = crate::engine::blobs::TxBlobs::new(&mut tx.txn);
        let mut reader = osis_label::BlobReader::new(&dedup, &mut blobs);
        let Ok(d) = osis_commit::verify_part(h, id, p, &dedup, &mut interner, Some(&mut reader)) else { continue };
        let part = (p.ai, p.di, d);
        if linked_frontiers(tx, h, &EdgeParts::of(h, std::slice::from_ref(&part))).is_ok_and(|l| !l.waiting.is_empty()) {
            out.push(part);
        }
    }
    out
}

fn add_role_commit_in(core: &mut Core, h: &View, id: &CommitId, parts: &EdgeParts, linked: &Linked) {
    for (ai, es) in parts.holders() {
        if let Some(a) = h.aspects.get(ai) {
            note_keys(core, &a.tid, es, Owned::of_view(h, id, ai).as_ref());
        }
    }
    match h.kind {
        Kind::Role => {
            // the writes whose holder is known go to perm now; a commit resetting an entry of
            // unknown key stays in `unresolved` and is derived again when keys arrive
            let mut ops = Vec::new();
            let mut known = true;
            for (ai, es) in parts.holders() {
                let Some(a) = h.aspects.get(ai) else { continue };
                // nothing written on a thing too deep applies (spec/permissions.md §1); its owner
                // chain is held whole at apply (`examine`), so this never changes later
                if too_deep(core, &a.tid) {
                    continue;
                }
                let (v, k) = edge_ops(core, &a.tid, es, Owned::of_view(h, id, ai).as_ref());
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
                core.ix.held.add_commit(RoleCommit { id: *id, ts: h.ts, author: h.author, actor: h.actor, frontier: h.frontier.clone(), ops });
            }
        }
        Kind::RosterSnapshot => {
            let mut by_thing: BTreeMap<Tid, RosterParts> = BTreeMap::new();
            for (ai, p) in &parts.0 {
                let Some(a) = h.aspects.get(*ai) else { continue };
                let e = by_thing.entry(a.tid).or_default();
                match p {
                    EdgePart::Holders(es) => {
                        for (_, k, v) in es {
                            if let (Some(m), Some(edge)) = (k, v) {
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
                            e.1.push(Tenure { holder: t.holder, role: t.role, since: t.since.map(point_of), until: point_of(t.until), frontier });
                        }
                    }
                }
            }
            for (thing, (roster, ledger)) in by_thing {
                if too_deep(core, &thing) {
                    continue;
                }
                let s = RosterSnapshot { id: *id, ts: h.ts, author: h.author, actor: h.actor, thing, roster, ledger };
                if linked.waiting.contains(&thing) {
                    core.ix.held.add_withheld(s);
                } else {
                    core.ix.held.add_snapshot(s);
                }
            }
        }
        _ => {}
    }
}

/// Does a path of held edge writes and owner links lead from `author` to a thing on `chain`?
/// (The author's chain certificates, spec/permissions.md §1, §4: a path climbs role
/// grants and owner links, as perm's effective role counts them.) Searched backward from
/// `chain`, as perm's `roles_to_any`: from a thing to its owner and to the holders named on
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
        for y in owner.into_iter().chain(held.holders_of(&t)) {
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

/// The role a `keys.0` or `secrets.0` delta needs (spec/permissions.md §3). `keys.0`: a writer
/// rotates read and write, only an admin the admin role; at least write. A delta that is not a
/// plain struct (a write or reset of the whole value) replaces every field: admin.
fn rotation_required(ak: &str, f: &Fragment) -> Option<Role> {
    match ak {
        "secrets.0" => return Some(secrets_role(f)),
        "keys.0" => {}
        _ => return None,
    }
    if !f.is_plain_struct() {
        return Some(Role::Admin);
    }
    // the admin keyset, a key actor's KEM key, the inbox and the deposit seed need admin
    // (spec/crypto.md §3: inbox and deposit seed by an admin); read and write keysets their
    // rotator
    let admin = match f.slot(osis_crdt::Encoding::Struct) {
        Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) => (2..=5).any(|id| st.field(id).is_some()),
        _ => false,
    };
    Some(if admin { Role::Admin } else { Role::Write })
}

/// The role a `secrets.0` delta needs (spec/permissions.md §3, spec/crypto.md §4): at least
/// write, and for each entry record (a put, a write into an entry, a removal) the role its key
/// names; a record acts only on the entry of its key (spec/crdt.md §5.6), so this is judged
/// from the delta alone. A key-erased record, a key that is no box or history key, or a write
/// or reset of the whole value or of a field: admin.
pub(super) fn secrets_role(f: &Fragment) -> Role {
    let Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct).filter(|_| f.is_plain_struct()) else { return Role::Admin };
    let mut top = Role::Write;
    for id in [0, 1] {
        let Some(field) = st.field(id) else { continue };
        let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map).filter(|_| !field.has_reset()) else { return Role::Admin };
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

/// Records the roles `secrets.0` and `keys.0` deltas of a commit need, and the `secrets.0` parts
/// of a role commit that write beyond its grantees' boxes. `parts`: every held part of the
/// commit (a late `secrets.0` part is judged with the `roles.0` part held before it).
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    core.stale_commits.insert(*id);
    for (ai, _, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(r) = rotation_required(a.ak.as_str(), d.fragment())
        {
            core.ix.rotation_role.upsert((*id, *ai), || r, |e| *e = (*e).max(r));
        }
    }
    if h.kind != Kind::Role {
        return;
    }
    // the edges this commit puts, per target: what an invite grant may box
    let mut granted: BTreeMap<(Tid, Tid), Role> = BTreeMap::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "roles.0" {
            for (_, k, frag) in entries(d.fragment()) {
                if let (Some(Value::Tid(m)), Some(e)) = (k, frag.and_then(|f| f.read()).as_ref().and_then(edge_of)) {
                    granted.insert((a.tid, m), e.role);
                }
            }
        }
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "secrets.0" {
            if crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, d.fragment(), &granted, &own)) {
                core.ix.grant_overreach.remove(&(*id, *ai));
            } else {
                core.ix.grant_overreach.insert((*id, *ai));
            }
        }
    }
    // one delta per `secrets.0` aspect, known from the signed header: a node that never holds a
    // part (dropped by expiry or purge) judges the others as one that held it does
    for (ai, a) in h.aspects.iter().enumerate() {
        if a.ak.as_str() == "secrets.0" && a.hashes.len() != 1 {
            core.ix.grant_overreach.insert((*id, ai));
        }
    }
}

/// Whether a `secrets.0` delta writes only the boxes of the holders `granted` puts on `actor`, at
/// or below each one's role, and history boxes at or below the highest granted role, as puts
/// only: entries this delta creates (`own` dots), no reset of the value, a field, a map or any
/// entry (spec/permissions.md §2). Judged from
/// the delta alone, so every node judges it alike whatever it holds.
pub(super) fn grantee_boxes_only(actor: &Tid, f: &Fragment, granted: &BTreeMap<(Tid, Tid), Role>, own: &crate::engine::Owned) -> bool {
    // a write or reset of the whole value removes every box
    if !f.is_plain_struct() {
        return false;
    }
    let Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct) else { return false };
    let top = granted.iter().filter(|((t, _), _)| t == actor).map(|(_, r)| *r).max();
    let fits = |k: &ct::BoxKey| granted.get(&(*actor, k.holder)).is_some_and(|r| k.role <= *r);
    for id in [0, 1] {
        let Some(field) = st.field(id) else { continue };
        // every entry new: created by this delta (its own dots), never a write into another's
        if !field.is_put_only_map(&|d| own.owns(d)) {
            return false;
        }
        let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map) else { return false };
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

/// Notes what the held `required.0^` deltas among `parts` say (spec/commits.md §5), each judged
/// from the delta alone. Deltas on the thing are judged again if it stands: a fallen one changes
/// nothing, so a writer's costs nobody the walk; if it rises its thing is judged again anyway.
pub(crate) fn note_required_rules(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)]) {
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai).filter(|a| a.ak.as_str() == osis_commit::retention::REQUIRED) else { continue };
        let rules = d.fragment().read().map(|v| ct::required_rules(&v)).unwrap_or_default();
        let p = Point { ts: h.ts, node: h.author, commit: *id };
        let put = |l: &mut Vec<(Point, Arc<ct::RequiredRules>)>| {
            if let Err(i) = l.binary_search_by(|x| x.0.cmp(&p)) {
                l.insert(i, (p, Arc::new(rules.clone())));
            }
        };
        core.ix.required.upsert(a.tid, || {
            let mut l = Vec::new();
            put(&mut l);
            l
        }, put);
        if core.ix.commits.get(id).is_none_or(|m| m.valid_at(*ai)) {
            core.stale_things.insert(a.tid);
        }
        // a pending commit's missing delta may count as held now (`breaks_a_held_setting`)
        core.waits.wake_thing(&a.tid);
    }
}

/// Whether a delta of this kind and AK answers to its thing's required retention: not a
/// compaction snapshot's or an aspect of fixed retention's. An ephemeral commit's is judged
/// elsewhere (`eph_part_valid`) and carries none.
pub(super) fn under_required(h: &Header, ak: &Ak) -> bool {
    // a non-durable aspect answers to no rule (spec/commits.md §5)
    !h.kind.is_compaction() && osis_commit::retention::fixed_retention(ak.as_str()).is_none() && ak.lifetime() == osis_schema::Lifetime::Durable
}

/// Re-derives the edge writes of commits whose removed keys were unknown.
pub(crate) fn resolve_unresolved(tx: &mut Tx<'_>) -> Result<bool> {
    let ids: Vec<CommitId> = tx.core.ix.unresolved.iter().copied().collect();
    let mut any = false;
    for id in ids {
        let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        let parts = super::edge_parts(tx, &id)?;
        let before = tx.core.ix.held.edge_commit(&id).map(|c| c.ops.clone());
        add_role_commit(tx, &v, None, &id, &parts)?;
        any |= tx.core.ix.held.edge_commit(&id).map(|c| &c.ops) != before.as_ref();
    }
    Ok(any)
}

/// Whether `t`'s owner chain is not known to end at a key actor or an ownerless thing within `MAX_OWNER_DEPTH`
/// owner links (spec/permissions.md §1): deeper, or a creation record on it is not held (unknown
/// counts as invalid, so forgetting a record never makes a deep delta valid). O(`MAX_OWNER_DEPTH`).
pub(crate) fn too_deep(core: &Core, t: &Tid) -> bool {
    !matches!(core.owner_chain(t).end(), ChainStep::Key(_) | ChainStep::Ownerless { .. })
}

/// Is aspect `ai` of a held commit valid (spec/permissions.md §5.2)?
pub(crate) fn part_valid(core: &Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    Judge::new(core).part(h, id, ai)
}

/// Whether the author of commit `id` could act for its header's actor (spec/permissions.md
/// §5.2): it is the actor, or its write on the actor at the commit's key is valid as a delta on
/// the actor needing write would be (same timeline, demotions and frontiers). A commit failing
/// this is invalid whole. Role commits and roster snapshots name their author (bad input
/// otherwise, spec/wire.md §4), so the timeline never depends on this.
///
/// Invariant (arrival-order independence): a function of the actor's timeline alone, so it
/// changes only when that timeline does; `rejudge_once` re-judges the commits acting for a
/// thing whose timeline changed (`by_actor`).
pub(crate) fn acts_for(core: &Core, h: &Header, id: &CommitId) -> bool {
    h.author == h.actor || acts_on(core.timelines.get(&h.actor), h, id)
}

fn acts_on(tl: Option<&osis_perm::Timeline>, h: &Header, id: &CommitId) -> bool {
    let Some(tl) = tl else { return false };
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    tl.delta_valid(point, &h.actor, Role::Write) == Validity::Valid
}

/// The newest `required.0^` delta on `tid` valid and ordered before `at`: (its key, the entry
/// governing `ak`) (spec/commits.md §5). A function of the held deltas and the timeline.
fn in_force(judge: &mut Judge<'_>, tid: &Tid, ak: &str, at: &Point) -> Option<(Point, Option<ct::Required>)> {
    let valid = judge.settings(tid);
    let (p, rules) = valid.get(valid.partition_point(|x| x.0 < *at).checked_sub(1)?)?;
    Some((*p, ct::required_for(rules, ak).copied()))
}

/// Whether a removal from `tid` at key `at` keeps by default: the `keep` of the setting in force
/// (spec/permissions.md §3; none: it erases).
pub(crate) fn keep_in_force(core: &Core, tid: &Tid, at: &Point) -> bool {
    let valid = Judge::new(core).settings(tid);
    valid.partition_point(|x| x.0 < *at).checked_sub(1).and_then(|i| valid.get(i)).is_some_and(|x| x.1.keep)
}

/// `keep_in_force` for a write this node makes now: after every setting it holds.
pub(crate) fn keep_now(core: &Core, tid: &Tid) -> bool {
    keep_in_force(core, tid, &Point { ts: core.hlc.peek(), node: core.id.tid(), commit: CommitId([0xff; 32]) })
}

/// The requirement in force for a write of `ak` on `tid` by `node` at `ts` (the writer's side).
pub(crate) fn required_now(core: &Core, tid: &Tid, ak: &Ak, node: Tid, ts: osis_base::Ts) -> Option<ct::Required> {
    in_force(&mut Judge::new(core), tid, ak.as_str(), &Point { ts, node, commit: CommitId([0; 32]) })?.1
}

/// The key of the `required.0^` delta that aspect `ai` of held commit `id` breaks, if any
/// (`Judge::broken`).
pub(crate) fn broken_by(core: &Core, h: &Header, id: &CommitId, ai: usize) -> Option<Point> {
    Judge::new(core).broken(h, id, h.aspects.get(ai)?)
}

/// Whether `required.0^` part `a` of a commit with header `h` is signed by one not a possible admin
/// of the thing: it binds nothing and costs every node a body, so it goes without a right
/// (spec/permissions.md §8). A delta is judged by its author's standing, so the actor it names
/// saves nothing. A setting by a possible admin stays, fallen or not: it may stand again.
pub(crate) fn never_could_set(core: &Core, h: &Header, a: &osis_commit::AspectEntry) -> bool {
    a.ak.as_str() == osis_commit::retention::REQUIRED && !core.ix.held.ever_admins(&a.tid).contains(&h.author)
}

/// Whether a delta carries exactly the retention and expiry `q` requires.
pub(super) fn meets(q: &ct::Required, h: &Header, a: &osis_commit::AspectEntry) -> bool {
    a.retention == q.retention() && q.expires_at(h.ts.wall_ms().0) == Some(a.expires)
}

/// `part_valid` over many parts: what is per thing (owner depth, timeline) looked up once per
/// run of parts on one thing.
pub(crate) struct Judge<'a> {
    core: &'a Core,
    last: Option<(Tid, bool, Option<&'a osis_perm::Timeline>)>,
    /// On the last thing: per (author, required role), from where its deltas are valid
    /// whatever else (`Timeline::valid_from`).
    from: BTreeMap<(Tid, Role), Option<Option<Point>>>,
    /// Per (author, actor), from where the author acts for the actor whatever the commit.
    acts: BTreeMap<(Tid, Tid), Option<Option<Point>>>,
    /// On the last thing: its valid `required.0^` deltas, in key order, found once.
    settings: Option<Arc<Settings>>,
}

/// A thing's `required.0^` deltas: each one's key and what it says.
type Settings = Vec<(Point, Arc<ct::RequiredRules>)>;

impl<'a> Judge<'a> {
    pub(crate) fn new(core: &'a Core) -> Judge<'a> {
        Judge { core, last: None, from: BTreeMap::new(), acts: BTreeMap::new(), settings: None }
    }

    /// (too deep, timeline) of `t`.
    fn thing(&mut self, t: &Tid) -> (bool, Option<&'a osis_perm::Timeline>) {
        match self.last {
            Some((x, d, tl)) if x == *t => (d, tl),
            _ => {
                let v = (too_deep(self.core, t), self.core.timelines.get(t));
                self.last = Some((*t, v.0, v.1));
                self.from.clear();
                self.settings = None;
                v
            }
        }
    }

    /// The key of the `required.0^` delta in force that delta `a` of commit `id` breaks
    /// (spec/commits.md §5). Its commit's other deltas stand, its own thing's and others': a member
    /// of another thing alone never holds this setting and must read as the rest do.
    fn broken(&mut self, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry) -> Option<Point> {
        if !under_required(h, &a.ak) || !self.core.ix.required.contains_key(&a.tid) {
            return None;
        }
        let (p, q) = in_force(self, &a.tid, a.ak.as_str(), &Point { ts: h.ts, node: h.author, commit: *id })?;
        q.filter(|q| !meets(q, h, a)).map(|_| p)
    }

    /// The valid `required.0^` deltas on `t` (`Settings`), each judged once per thing.
    fn settings(&mut self, t: &Tid) -> Arc<Settings> {
        self.thing(t);
        if let Some(s) = &self.settings {
            return s.clone();
        }
        let core = self.core;
        let mut valid = Settings::new();
        for x in core.ix.required.get(t).into_iter().flatten() {
            let Some(m) = core.ix.commits.get(&x.0.commit) else { continue };
            let ai = m.header.aspects.iter().position(|a| a.tid == *t && a.ak.as_str() == osis_commit::retention::REQUIRED);
            if ai.is_some_and(|ai| self.part(&m.header, &x.0.commit, ai)) {
                debug_assert!(core.ix.held.ever_admins(t).contains(&x.0.node), "a valid setting's author is a possible admin");
                valid.push(x.clone());
            }
        }
        let s = Arc::new(valid);
        self.settings = Some(s.clone());
        s
    }

    /// `acts_for`, its tenure bound found once per (author, actor).
    fn acts(&mut self, h: &Header, id: &CommitId) -> bool {
        if h.author == h.actor {
            return true;
        }
        let tl = self.core.timelines.get(&h.actor);
        let from = *self.acts.entry((h.author, h.actor)).or_insert_with(|| tl.and_then(|tl| tl.valid_from(&h.author, &h.actor, Role::Write)));
        let point = Point { ts: h.ts, node: h.author, commit: *id };
        if from.is_some_and(|b| b.is_none_or(|b| b <= point)) {
            return true;
        }
        acts_on(tl, h, id)
    }

    pub(crate) fn part(&mut self, h: &Header, id: &CommitId, ai: usize) -> bool {
        let core = self.core;
        if core.ix.void.contains(id) {
            return false;
        }
        let Some(a) = h.aspects.get(ai) else { return false };
        let ak = a.ak.as_str();
        // `created.0` hashes to its tid, whoever acts; edge writes are layer 1 (reads go through
        // the timeline); a compaction snapshot is judged as its author's write (below), which
        // vouches for every write it carries (spec/permissions.md §5.2)
        if ak == "created.0" {
            return true;
        }
        if !self.acts(h, id) {
            return false;
        }
        // a delta breaking a required retention at its key (spec/commits.md §5); a `required.0^`
        // delta answers to none, so this ends
        if self.broken(h, id, a).is_some() {
            return false;
        }
        // a thing more than `MAX_OWNER_DEPTH` owner links below its key actor: nothing written on
        // it applies (spec/permissions.md §1); judged per delta from creation records alone
        let (deep, tl) = self.thing(&a.tid);
        if deep {
            return false;
        }
        if ak == "roles.0" || ak == "tenures.0" {
            return true;
        }
        let Some(tl) = tl else { return false };
        // a compaction snapshot: valid iff its author could write the aspect at the snapshot,
        // judged by commit ID (a demotion's frontier lists it), needing the strictest role a
        // write it carries could need (`snapshot_role`: admin for `keys.0` and `secrets.0`)
        if h.kind.is_compaction() {
            let required = crate::engine::write::snapshot_role(ak);
            let point = Point { ts: h.ts, node: h.author, commit: *id };
            return tl.delta_valid(point, &a.tid, required) == Validity::Valid;
        }
        // the author's deltas from its standing tenure on are valid, found once per author
        if !core.ix.rotation_role.contains_key(&(*id, ai)) && ak != "secrets.0" {
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
    if ak == "secrets.0"
        && let Some(c) = tl.role_commit(id)
        && !core.ix.grant_overreach.contains(&(*id, ai))
    {
        let grant = |i: usize| matches!(tl.applied().get(&WriteId::Op(*id, i as u32)), Some(x) if matches!(x.attr, osis_perm::Attr::By(osis_perm::Class::Invite(_))));
        let mut puts = c.ops.iter().enumerate().filter(|(_, o)| o.target == a.tid && o.edge.is_some()).peekable();
        if puts.peek().is_some() && puts.all(|(i, _)| grant(i)) {
            return true;
        }
    }
    let required = core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| required_role(ak));
    tl.delta_valid(point, &a.tid, required) == Validity::Valid
}

/// Re-judges the held deltas whose validity may have changed since the last call: those on the
/// things whose timeline changed (`Core::stale_things`, filled by `update_timelines`: the things
/// of components evaluated anew, and below what a continued walk touched), the commits whose
/// other inputs changed (`stale_commits`: void, required roles, overreach), every one after a
/// rebuild at open (`stale_all`); so the cost follows the change, not the held set. Rebuilds
/// aspects whose validity flipped; returns them. Again while a rebuild left some stale (a part
/// `retention::uncover` made missing loses what its body judged). Ends: only `uncover` marks
/// stale here, and it turns parts dropped as covered missing, never back.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    let _s = crate::costs::span("rejudge");
    let mut out: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    loop {
        out.extend(rejudge_once(tx, rebuild)?);
        if !tx.core.stale() {
            return Ok(out.into_iter().collect());
        }
    }
}

/// One pass of `rejudge_all`.
fn rejudge_once(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    if resolve_unresolved(tx)? {
        tx.core.update_timelines();
    }
    let mut flipped: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // aspects where something became valid again: re-merging needs the held bodies
    let mut rose: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    // per aspect, the parts that went invalid (their bodies say which pages to un-merge)
    let mut fell: BTreeMap<(Tid, Ak), Vec<(CommitId, usize)>> = BTreeMap::new();
    let mut secrets_flips: Vec<(CommitId, usize, bool)> = Vec::new();
    let mut keyset_flips: BTreeSet<Tid> = BTreeSet::new();
    let mut things = std::mem::take(&mut tx.core.stale_things);
    let authors = std::mem::take(&mut tx.core.stale_authors);
    let under = std::mem::take(&mut tx.core.stale_under);
    let explicit = std::mem::take(&mut tx.core.stale_commits);
    let all = std::mem::take(&mut tx.core.stale_all);
    // the commits whose author's role may have moved on a thing they write
    let (on, acting) = tx.core.authored_under(&under, &authors);
    let authored: BTreeSet<CommitId> = on.collect();
    let acting: BTreeSet<CommitId> = acting.collect();
    // re-judged whole: those named, and those acting for a thing whose timeline changed
    // (`acts_for`); deltas on a thing answer to its `required.0^` deltas (`in_force`), so where
    // one of those is judged again they are too
    let mut whole = explicit;
    whole.extend(things.iter().flat_map(|t| tx.core.acting_for(t)));
    whole.extend(acting);
    for id in whole.iter().chain(&authored) {
        let Some(m) = tx.core.ix.commits.get(id) else { continue };
        things.extend(m.view.aspects.iter().filter(|a| a.ak.as_str() == osis_commit::retention::REQUIRED).map(|a| a.tid));
    }
    let judge = crate::costs::span("rejudge: judge");
    // verdicts first (the core read only), each held commit once: by thing, a commit under the
    // first re-judged thing among its aspects; then the commits re-judged whole
    let mut news: Vec<(CommitId, Vec<bool>)> = Vec::new();
    {
        let core: &Core = tx.core;
        let mut judge = Judge::new(core);
        let mut one = |id: &CommitId, m: &Meta, whole: bool| {
            drop(crate::costs::span("rejudge: a commit"));
            let mut now: Option<Vec<bool>> = None;
            for (ai, a) in m.header.aspects.iter().enumerate() {
                // parts on things not re-judged keep their flag
                if !(whole || things.contains(&a.tid) || under.contains(&a.tid) && authors.contains(&m.view.author)) {
                    continue;
                }
                let v = judge.part(&m.header, id, ai);
                let old = m.valid_at(ai);
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
                for id in core.on_thing(t) {
                    let Some(m) = core.ix.commits.get(&id) else { continue };
                    if !whole.contains(&id) && met.insert(id) {
                        one(&id, m, false);
                    }
                }
            }
            for id in &authored {
                let Some(m) = core.ix.commits.get(id) else { continue };
                if !whole.contains(id) && met.insert(*id) {
                    one(id, m, false);
                }
            }
            for id in whole.iter() {
                if let Some(m) = core.ix.commits.get(id) {
                    one(id, m, true);
                }
            }
        }
    }
    let me = tx.core.id.tid();
    let mut own_fell: Vec<(CommitId, Vec<Tid>)> = Vec::new();
    let mut fresh = false;
    let current = [tx.core.session.nonce, tx.core.expiring.nonce];
    for (id, now) in news {
        let Some(m) = tx.core.ix.commits.get_mut(&id) else { continue };
        let h = m.header.clone();
        if h.author == me && h.kind.has_own_writes() && m.valid.iter().zip(&now).any(|(a, b)| *a && !*b) {
            own_fell.push((id, h.aspects.iter().map(|a| a.tid).collect::<BTreeSet<_>>().into_iter().collect()));
            fresh |= matches!(h.form, osis_commit::Form::Session(n) if current.contains(&n));
        }
        for (ai, (a, b)) in m.valid.iter().zip(&now).enumerate() {
            if a != b
                && let Some(x) = h.aspects.get(ai)
            {
                flipped.insert((x.tid, x.ak.clone()));
                if m.view.memory {
                    tx.core.memory.dirty.insert((x.tid, x.ak.clone()));
                    // the bodies it covered were forgotten: the lane brings their copies back
                    if *a && m.view.kind.is_compaction() {
                        tx.core.memory.invalidated.insert((x.tid, x.ak.clone()));
                    }
                }
                if *b {
                    rose.insert((x.tid, x.ak.clone()));
                } else {
                    fell.entry((x.tid, x.ak.clone())).or_default().push((id, ai));
                }
                if x.ak.as_str() == "secrets.0" {
                    secrets_flips.push((id, ai, *b));
                }
                if x.ak.as_str() == "keys.0" {
                    keyset_flips.insert(x.tid);
                }
            }
        }
        m.valid = now;
        tx.core.index_validity(&id);
        tx.core.mark_changed(id);
    }
    drop(judge);
    // an own write of the current sessions fell: later writes go under fresh ones, past the hole
    // (`Core::fresh_session`)
    if fresh {
        tx.core.fresh_session();
    }
    let at = tx.now();
    for (id, tids) in own_fell {
        tx.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OwnWriteInvalid, tids, commit: Some(id), peer: None, detail: "a write of this node turned invalid".into() }, at);
    }
    // a body dropped for breaking the rule that no longer does: never received from here on
    for (tid, ak) in &rose {
        crate::retention::unbreak(tx, tid, ak)?;
    }
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
            // a memory aspect's rebuild is memory work, whatever transaction re-judges it
            let memory = tx.txn.is_memory_aspect(tid, ak);
            tx.in_class(memory, |tx| {
                let k = (*tid, ak.clone());
                // a snapshot turned invalid gives nothing: what it gave goes (its writer no longer
                // vouches for it, spec/permissions.md §5.2; other valid carriers give theirs back),
                // and with it its vouching
                let snaps: Vec<CommitId> = fell.get(&k).into_iter().flatten().filter(|(c, _)| tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction())).map(|x| x.0).collect();
                if rose.contains(&k) || !snaps.is_empty() {
                    let _s = crate::costs::span("rejudge: rebuild");
                    let mut gone: Vec<Owned> = Vec::new();
                    for s in &snaps {
                        gone.extend(super::copies::given_by(tx, tid, ak, s)?);
                    }
                    // parts dropped under its cover alone are missing again, their writes gone
                    if !snaps.is_empty() {
                        gone.extend(crate::retention::uncover(tx, tid, ak)?);
                    }
                    super::atomic::rebuild_without(tx, tid, ak, &gone)?;
                } else {
                    let _s = crate::costs::span("rejudge: unmerge");
                    super::atomic::unmerge_fallen(tx, tid, ak, fell.get(&k).map(Vec::as_slice).unwrap_or_default())?;
                }
                // a write fell where a body dropped for its keep bounds may have died for it:
                // its value may be live again here, gone with the body (spec/commits.md §5)
                if fell.contains_key(&k) {
                    let dropped = crate::retention::suspect::keep_dropped(tx.core, tid, ak);
                    crate::retention::suspect::raise(tx, tid, ak, crate::retention::suspect::Why::Flip, &dropped)?;
                }
                crate::retention::mark_deaths_due(tx, tid, ak)
            })?;
        }
        // memory parts turned valid may supersede held ones (spec/sync.md §9)
        let memory: BTreeSet<(Tid, Ak)> = rose.iter().filter(|(t, a)| tx.txn.is_memory_aspect(t, a)).cloned().collect();
        if !memory.is_empty() {
            let gone = tx.in_class(true, |tx| {
                let gone = crate::retention::memory::drop_superseded(tx, &memory, None, None)?;
                // and snapshots turned valid cover held bodies
                crate::retention::memory::drop_covered(tx, &memory, None)?;
                Ok(gone)
            })?;
            flipped.extend(gone);
        }
    }
    super::keys::rebuild_keysets(tx, &keyset_flips)?;
    super::keys::refresh_own_keys(tx, &keyset_flips, true)?;
    for (c, ai, now_valid) in secrets_flips {
        if now_valid {
            super::keys::revalidated(tx, &c, ai)?;
        } else {
            super::keys::invalidated(tx, &c, ai)?;
        }
    }
    // a request's right rests on the same timelines (spec/permissions.md §8)
    if rebuild {
        let things: BTreeSet<Tid> = things.union(&under).copied().collect();
        for (tid, ak) in crate::retention::purged_aspects(tx, &things, &whole)? {
            crate::retention::rejudge_purges(tx, &tid, &ak, &mut flipped)?;
        }
    }
    Ok(flipped.into_iter().collect())
}

/// Whether `author` lowering `holder`'s edge on `target` at `ts` is a self-removal
/// (spec/permissions.md §2): its own edge, or its authority on the target comes only through the
/// holder (admin on the holder, and no admin on the target without the holder's edge).
pub(crate) fn self_removal(core: &Core, author: &Tid, target: &Tid, holder: &Tid, ts: osis_base::Ts) -> bool {
    if author == holder {
        return true;
    }
    let Some(tl) = core.timelines.get(target) else { return false };
    if tl.role(author, holder, At::now(ts)) != Some(Role::Admin) {
        return false;
    }
    let edges = tl.edges_at(None);
    let view = osis_perm::graph::View::at(tl.owners(), &edges, Some(ts)).patched(*holder, *target, None);
    view.roles_from(author).get(target).copied() != Some(Role::Admin)
}

/// Rules of a role commit that need its deltas
/// (spec/commits.md §2, spec/wire.md §4 position 13, spec/permissions.md §3).
pub(crate) fn check_content_rules(core: &Core, h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    if h.kind != Kind::Role {
        return Ok(());
    }
    let mut changed: Vec<(Tid, Tid, Option<Edge>)> = Vec::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "roles.0" {
            continue;
        }
        for (dot, k, frag) in entries(d.fragment()) {
            match k {
                Some(Value::Tid(m)) => changed.push((a.tid, m, frag.and_then(|f| f.read()).as_ref().and_then(edge_of))),
                _ => {
                    if let Some(m) = core.ix.holder_keys.get(&(a.tid, dot)) {
                        changed.push((a.tid, *m, None));
                    }
                }
            }
        }
    }
    // a change is remove + put of one entry: the put is the holder's new edge
    let mut net: BTreeMap<(Tid, Tid), Option<Edge>> = BTreeMap::new();
    for (t, m, e) in changed {
        let slot = net.entry((t, m)).or_insert(None);
        if e.is_some() {
            *slot = e;
        }
    }
    let changed: Vec<(Tid, Tid, Option<Edge>)> = net.into_iter().map(|((t, m), e)| (t, m, e)).collect();
    let mut holders: Vec<(Tid, Tid)> = changed.iter().map(|c| (c.0, c.1)).collect();
    holders.sort();
    holders.dedup();
    if holders.len() > 1 {
        // the one exception for edge writes in a plain role commit: a single-use
        // redemption (a grant plus the author key's own self-removal, both on K,
        // spec/permissions.md §9, spec/commits.md §2)
        let redemption = holders.len() == 2 && holders.first().map(|m| m.0) == holders.last().map(|m| m.0) && changed.iter().any(|c| c.1 == h.author && c.2.is_none()) && changed.iter().any(|c| c.1 != h.author && c.2.is_some());
        // or an explicit removal of several others' edges on one target (a link joiner with
        // the link key), under one frontier and one rotation: no edge of it a self-removal, each
        // gone or saying keep
        let first = holders.first().map(|m| m.0);
        let removal = h.frontier.is_some() && changed.iter().all(|c| Some(c.0) == first && c.1 != h.author && c.2.is_none_or(|e| e.says_keep()) && !self_removal(core, &h.author, &c.0, &c.1, h.ts));
        if !redemption && !removal {
            return Err(Error::BadInput("a role commit changes more than one edge"));
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
            (Some(o), Some(n)) => n.role < o.role || n.says_keep(),
            _ => false,
        };
        // a self-removal carries no rotation: the next node that may rotate does it
        // (spec/permissions.md §3)
        if demotes && !self_removal(core, &h.author, target, m, h.ts) && core.ix.own_keys.contains(target) {
            let has = |ak: &str| h.aspects.iter().any(|a| a.tid == *target && a.ak.as_str() == ak);
            if !has("secrets.0") || !has("keys.0") {
                return Err(Error::BadInput("a removal without the rotation it requires"));
            }
        }
    }
    Ok(())
}
