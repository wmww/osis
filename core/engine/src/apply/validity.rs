//! Validity through osis-perm (spec/permissions.md §5): role commits become perm's edge-write
//! records (the node's `HeldSet` is perm's `MemoryHeldSet`,
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
use osis_perm::{Addendum, AddendumEntry, At, Edge, EdgeOp, Frontier, Point, RoleCommit, Validity, Vouching, WriteId};
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
    Some(Edge { role: e.role, until: e.until, invite: e.invite, tied: e.tied.map(crate::flows::tied::tie_perm) })
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

/// Whether `ak` holds edge writes (`roles.0`): perm reads them.
pub(crate) fn edge_ak(ak: &str) -> bool {
    ak == "roles.0"
}

/// Whether `ak`'s writes reach perm instead of a state: edge writes and creation records.
pub(crate) fn perm_ak(ak: &str) -> bool {
    edge_ak(ak) || ak == "created.0"
}

/// Whether a part of commit `h` on aspect `a` is plain content, what an addendum may vouch for
/// (spec/permissions.md §5.2, Addenda): a content commit (no compaction snapshot) carrying no
/// purge request, on no role-class, admin-only or addenda aspect.
fn plain_part(h: &Header, a: &osis_commit::AspectEntry) -> bool {
    let ak = a.ak.as_str();
    plain_commit(h) && !ct::is_role_class(ak) && !a.ak.admin_only() && !ct::is_addenda(ak) && ak != "created.0"
}

/// Whether commit `h` may be vouched for at all (`plain_part`).
fn plain_commit(h: &Header) -> bool {
    h.kind == Kind::Content && h.purge.is_empty()
}

/// What a commit's `addenda.0` deltas say (`Indexes::addenda`), per thing: the removals the
/// entries name and the commit IDs each lists, none for a delta whose body is not held.
/// Persisted beside the record (`index::ADDENDA`), so an open decodes no body.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AddendaParts(pub Vec<(Tid, Vec<AddendumEntry>)>);

impl AddendaParts {
    /// The parts of commit `id` as the index holds them (`addenda_of`).
    pub(crate) fn from_index(core: &Core, id: &CommitId, aspects: &[crate::engine::AspectView]) -> AddendaParts {
        let mut out = Vec::new();
        for a in aspects.iter().filter(|a| ct::is_addenda(a.ak.as_str())) {
            if let Some(v) = core.ix.addenda.get(&(a.tid, *id)) {
                out.push((a.tid, v.entries.clone()));
            }
        }
        AddendaParts(out)
    }
}

/// The entries an `addenda.0` delta (part `ai` of commit `id`) creates: per entry, the removal
/// its key names and the commit IDs its `frontier` value lists. An entry keyed by no 32-byte
/// commit ID or reading no `frontier` says nothing.
fn entries_of(h: &Header, id: &CommitId, ai: usize, d: &Decoded) -> Vec<AddendumEntry> {
    let own = Owned::of(h, id, ai);
    let mut es = Vec::new();
    for (dot, k, f) in entries(d.fragment()) {
        if !own.as_ref().is_some_and(|o| o.owns(dot.origin())) {
            continue;
        }
        let Some(Value::Bytes(r)) = k else { continue };
        let Ok(r) = <[u8; 32]>::try_from(r.as_slice()) else { continue };
        let Some(lists) = f.and_then(|f| f.read()).and_then(|v| typed(&v, "frontier")).and_then(|v| ct::Frontier::from_value(&v).ok()) else { continue };
        es.push((CommitId(r), Arc::new(lists.commits)));
    }
    es
}

/// Indexes what commit `id` (at `point`) says as an addendum (`Indexes::addenda`); its things
/// get judged again.
pub(crate) fn index_addenda(core: &mut Core, point: Point, parts: &AddendaParts) {
    for (t, es) in &parts.0 {
        core.ix.addenda.insert((*t, point.commit), Arc::new(Addendum { point, entries: es.clone() }));
        core.stale_things.insert(*t);
    }
}

/// Indexes commit `id`'s addendum deltas (spec/permissions.md §5.2, Addenda): every `addenda.0`
/// delta its header names is its author's write, whether its body is held or not; `parts`, the
/// bodies just held, say its entries. A delta acting for another actor, or of a commit other
/// than a content one, is no addendum.
pub(crate) fn note_addenda(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) {
    if h.kind != Kind::Content || h.author != h.actor {
        return;
    }
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    let mut out = Vec::new();
    for (ai, a) in h.aspects.iter().enumerate().filter(|(_, a)| ct::is_addenda(a.ak.as_str())) {
        match parts.iter().find(|(x, _)| *x == ai) {
            Some((_, d)) => out.push((a.tid, entries_of(h, id, ai, d))),
            None if !core.ix.addenda.contains_key(&(a.tid, *id)) => out.push((a.tid, Vec::new())),
            None => {}
        }
    }
    index_addenda(core, point, &AddendaParts(out));
}

/// Forgets what addendum part `ai` of commit `id` says, its body dropped: it stays its author's
/// write, listing nothing (spec/permissions.md §5.2, Addenda).
pub(crate) fn forget_addendum_body(core: &mut Core, id: &CommitId, tid: &Tid) {
    if let Some(a) = core.ix.addenda.get(&(*tid, *id)).filter(|a| !a.entries.is_empty()) {
        let point = a.point;
        core.ix.addenda.insert((*tid, *id), Arc::new(Addendum { point, entries: Vec::new() }));
        core.stale_things.insert(*tid);
    }
}

/// Forgets what commit `id` said as an addendum (`unindex_commit`).
pub(crate) fn forget_addenda(core: &mut Core, id: &CommitId, aspects: &[crate::engine::AspectView]) {
    for a in aspects.iter().filter(|a| ct::is_addenda(a.ak.as_str())) {
        if core.ix.addenda.remove(&(a.tid, *id)).is_some() {
            core.stale_things.insert(a.tid);
        }
    }
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

/// What perm's adaptation reads of a role commit's held `roles.0` parts, by aspect index: a
/// function of the commit record, persisted per commit in the index (`engine::index`, `EDGES`)
/// so an open decodes no role body.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct EdgeParts(pub Vec<(usize, Vec<Entry>)>);

impl EdgeParts {
    pub(crate) fn of(h: &Header, parts: &[(usize, Decoded)]) -> EdgeParts {
        let mut out = Vec::new();
        for (ai, d) in parts {
            if h.aspects.get(*ai).is_none_or(|a| !edge_ak(a.ak.as_str())) {
                continue;
            }
            let es = entries(d.fragment())
                .into_iter()
                // a removal record keyed by no tid acts on no holder's entry (spec/crdt.md §5.6)
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
                .collect();
            out.push((*ai, es));
        }
        EdgeParts(out)
    }
}

/// Records the holder of every `roles.0` entry these deltas create: (target, entry dot) ->
/// holder. Only the delta carrying the entry's dot (`own`) creates it (a nested write into
/// another's entry is bad input, `check_holders_parts`).
fn note_keys(core: &mut Core, target: &Tid, es: &[Entry], own: Option<&Owned>) -> bool {
    let mut new = false;
    for (d, k, _) in es {
        if let Some(m) = k
            && own.is_some_and(|o| o.owns(d.origin()))
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
/// spec/crdt.md §5.6; an edge change is remove + put, spec/permissions.md §2). With whether the
/// delta is resolved here: a removal (no edge left for keys: none, or `until` 0) names the writes
/// it ends by the entries it resets, so each such reset's creation must be held; if not, the
/// commit applies nothing yet (`add_role_commit_in`). A reset beside a put of a live edge for its
/// key decides nothing: the put sets the edge whatever it replaces.
fn edge_ops(core: &Core, target: &Tid, es: &[Entry], own: Option<&Owned>) -> (Vec<EdgeOp>, bool) {
    let mut per: BTreeMap<Tid, Option<Edge>> = BTreeMap::new();
    for (d, k, v) in es {
        if let (Some(m), Some(e)) = (k, v)
            && own.is_some_and(|o| o.owns(d.origin()))
        {
            per.insert(*m, Some(*e));
        }
    }
    let live_put = |m: &Tid| per.get(m).is_some_and(|e| e.is_some_and(|e| !e.says_retain()));
    let mut known = true;
    let mut removed: BTreeSet<Tid> = BTreeSet::new();
    for (d, k, v) in es {
        // a nested write into another's entry is no edge write (bad input on receipt)
        if v.is_some() {
            continue;
        }
        match core.ix.holder_keys.get(&(*target, d.clone())) {
            Some(m) if k.is_some_and(|k| k != *m) => {}
            Some(m) => {
                removed.insert(*m);
            }
            None => known &= k.as_ref().is_some_and(live_put),
        }
    }
    for m in removed {
        per.entry(m).or_insert(None);
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

/// A `roles.0` delta writing inside an entry it did not create is bad input (an edge change is
/// remove + put, spec/permissions.md §2), and so is one holding a value that is no well-formed
/// edge (§2): judged from the delta and its header alone,
/// the one judgment of an edge's shape; perm never sees another.
pub(crate) fn check_holders_parts(h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) -> Result<()> {
    for (ai, d) in parts {
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
            if es.iter().any(|(dot, _, f)| f.is_some() && !own.as_ref().is_some_and(|o| o.owns(dot.origin()))) {
                return Err(Error::BadInput("a roles.0 write inside an entry the delta did not create"));
            }
        }
    }
    Ok(())
}

/// Adds a role commit's edge writes to perm's held set. A commit's edge writes apply together or
/// not at all (spec/permissions.md §2): one whose removal resets an entry of unknown creation
/// names a write this node lacks, so it applies none of them and stays in `unresolved` until keys
/// arrive. Invariant: an applied commit is the whole departure its author applied, which a name of
/// it stands for (spec/crypto.md §4 Met): a finalize held without the write it ends removes nobody
/// here, and one partly applied would let its name cover a holder it left in place.
pub(crate) fn add_role_commit(core: &mut Core, h: &View, id: &CommitId, parts: &EdgeParts) {
    core.stale_commits.insert(*id);
    for (ai, es) in &parts.0 {
        if let Some(a) = h.aspects.get(*ai) {
            note_keys(core, &a.tid, es, Owned::of_view(h, id, *ai).as_ref());
        }
    }
    let mut ops = Vec::new();
    let mut known = true;
    for (ai, es) in &parts.0 {
        let Some(a) = h.aspects.get(*ai) else { continue };
        // nothing written on a thing too deep applies (spec/permissions.md §1); its record chain is
        // held whole at apply (`examine`), so this never changes later
        if too_deep(core, &a.tid) {
            continue;
        }
        let (v, k) = edge_ops(core, &a.tid, es, Owned::of_view(h, id, *ai).as_ref());
        ops.extend(v);
        known &= k;
    }
    if known {
        core.ix.unresolved.remove(id);
    } else {
        core.ix.unresolved.insert(*id);
        ops.clear();
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

/// Does a path of held edge writes and record links lead from `author` to a thing on `chain`?
/// (The author's chain certificates, spec/permissions.md §1, §4: a path climbs role
/// grants and record links, as perm's effective role counts them.) Searched backward from
/// `chain`, as perm's `roles_to_any`: from a thing to its first admin and to the holders named on
/// it, so the search stays within what has authority over the chain.
pub(crate) fn reaches(core: &Core, author: &Tid, chain: &[Tid]) -> bool {
    let held = &core.ix.held;
    let mut stack: Vec<Tid> = chain.to_vec();
    let mut seen: BTreeSet<Tid> = chain.iter().copied().collect();
    while let Some(t) = stack.pop() {
        let first = match held.created(&t) {
            Some(CreationRecord::Thing { admin, .. }) => Some(admin),
            _ => None,
        };
        for y in first.into_iter().chain(held.holders_of(&t)) {
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
    let Some(maps) = entry_maps(f) else { return Role::Admin };
    // a delta putting history boxes only (a history add, spec/crypto.md §4) needs the role its
    // keys name: any holder of the epoch may add; anything else needs at least write
    let history_only = maps.iter().all(|(id, m)| m.entries().all(|(_, r, _, f)| *id == 1 && r.is_none() && f.is_some()));
    let mut top = if history_only { Role::Read } else { Role::Write };
    for (id, m) in maps {
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

/// The box and history maps of a `secrets.0` delta (field 0, 1) that writes entries only: a
/// plain struct, no reset of the value or of a field. `None` otherwise.
fn entry_maps(f: &Fragment) -> Option<Vec<(u64, &osis_crdt::Map)>> {
    let Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct).filter(|_| f.is_plain_struct()) else { return None };
    let mut out = Vec::new();
    for id in [0, 1] {
        let Some(field) = st.field(id) else { continue };
        let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map).filter(|_| !field.has_reset()) else { return None };
        out.push((id, m));
    }
    Some(out)
}

/// What a role commit's `secrets.0` delta on `actor` shows for possession (spec/crypto.md §4):
/// whether it writes more than entries (`rotates`), the boxes it removes, and each box's keyset
/// and signature.
fn showing_of(actor: &Tid, f: &Fragment) -> crate::engine::Showing {
    let w = super::keys::secrets_write(f);
    let rotates = entry_maps(f).is_none();
    let removed = w.removed.iter().map(|k| (k.holder, k.role)).collect();
    let shown = w.boxes.iter().filter_map(|(k, b)| osis_keys::possession::Shown::of(actor, k, b)).collect();
    crate::engine::Showing { rotates, top: None, removed, shown }
}

/// What a role commit's `keys.0` delta on `actor` shows for possession (spec/crypto.md §4):
/// whether it writes a keyset (a rotation), the highest role it writes one of, and the proofs its
/// keysets carry.
fn proofs_of(actor: &Tid, f: &Fragment) -> crate::engine::Showing {
    let w = super::keys::keys_write(f);
    let shown = w.keysets.iter().flat_map(|(r, ks)| osis_keys::possession::Shown::of_keyset(actor, *r, ks)).collect();
    crate::engine::Showing { rotates: !w.keysets.is_empty(), top: w.keysets.keys().max().copied(), removed: Vec::new(), shown }
}

/// Notes what part `ai` of `id` shows for possession (`Indexes::shown`).
pub(crate) fn note_shown(core: &mut Core, id: &CommitId, ai: usize, x: Arc<crate::engine::Showing>) {
    core.ix.shown.insert((*id, ai), x);
}

/// Records the roles `secrets.0` and `keys.0` deltas of a commit need, and the `secrets.0` parts
/// of a role commit that write beyond its grantees' boxes. `parts`: every held part of the
/// commit (a late `secrets.0` part is judged with the `roles.0` part held before it).
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) {
    core.stale_commits.insert(*id);
    for (ai, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(r) = rotation_required(a.ak.as_str(), d.fragment())
        {
            core.ix.rotation_role.upsert((*id, *ai), || r, |e| *e = (*e).max(r));
        }
    }
    if h.kind != Kind::Role {
        return;
    }
    // a part's deltas (pages of one rotation) show together
    let mut showing: BTreeMap<usize, crate::engine::Showing> = BTreeMap::new();
    for (ai, d) in parts {
        let (Some(a), Decoded::Delta(d)) = (h.aspects.get(*ai), d) else { continue };
        let x = match a.ak.as_str() {
            "secrets.0" => showing_of(&a.tid, &d.fragment),
            "keys.0" => proofs_of(&a.tid, &d.fragment),
            _ => continue,
        };
        let e = showing.entry(*ai).or_insert_with(|| core.ix.shown.get(&(*id, *ai)).map(|x| (**x).clone()).unwrap_or_default());
        e.rotates |= x.rotates;
        e.top = e.top.max(x.top);
        e.removed.extend(x.removed);
        e.shown.extend(x.shown);
    }
    for (ai, mut x) in showing {
        x.shown.sort();
        x.shown.dedup();
        x.removed.sort();
        x.removed.dedup();
        note_shown(core, id, ai, Arc::new(x));
    }
    // the edges this commit puts, per target: what an invite grant may box
    let mut granted: BTreeMap<(Tid, Tid), Role> = BTreeMap::new();
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "roles.0" {
            for (_, k, frag) in entries(d.fragment()) {
                if let (Some(Value::Tid(m)), Some(e)) = (k, frag.and_then(|f| f.read()).as_ref().and_then(edge_of)) {
                    granted.insert((a.tid, m), e.role);
                }
            }
        }
    }
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() == "secrets.0" {
            if crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, d.fragment(), &granted, &own)) {
                core.ix.grant_overreach.remove(&(*id, *ai));
            } else {
                core.ix.grant_overreach.insert((*id, *ai));
            }
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

/// Notes what the held `required^.0` deltas among `parts` say (spec/commits.md §5), each judged
/// from the delta alone. Deltas on the thing are judged again if it stands: a fallen one changes
/// nothing, so a writer's costs nobody the walk; if it rises its thing is judged again anyway.
pub(crate) fn note_required_rules(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) {
    for (ai, d) in parts {
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
    }
}

/// Whether a delta of this kind and AK answers to its thing's required retention: not a
/// compaction snapshot's or an aspect of fixed retention's. An ephemeral commit's is judged
/// elsewhere (`eph_part_valid`) and carries none.
pub(super) fn under_required(h: &Header, ak: &Ak) -> bool {
    // an ephemeral aspect answers to no rule (spec/commits.md §5)
    !h.kind.is_compaction() && osis_commit::retention::fixed_retention(ak.as_str()).is_none() && !ak.ephemeral()
}

/// Re-derives the edge writes of commits whose removed keys were unknown.
pub(crate) fn resolve_unresolved(tx: &mut Tx<'_>) -> Result<bool> {
    let ids: Vec<CommitId> = tx.core.ix.unresolved.iter().copied().collect();
    let mut any = false;
    for id in ids {
        let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        let parts = super::edge_parts(tx, &id)?;
        let before = tx.core.ix.held.edge_commit(&id).map(|c| c.ops.clone());
        add_role_commit(tx.core, &v, &id, &parts);
        any |= tx.core.ix.held.edge_commit(&id).map(|c| &c.ops) != before.as_ref();
    }
    Ok(any)
}

/// Whether `t`'s record chain is not known to end at a key actor within `MAX_CHAIN_DEPTH` links,
/// first-admin links counted (spec/permissions.md §1): deeper, or a creation record on it is not
/// held (unknown counts as invalid, so forgetting a record never makes a deep delta valid).
/// O(`MAX_CHAIN_DEPTH`).
pub(crate) fn too_deep(core: &Core, t: &Tid) -> bool {
    !matches!(core.record_chain(t).end(), ChainStep::Key(_))
}

/// Is aspect `ai` of a held commit valid (spec/permissions.md §5.2)?
pub(crate) fn part_valid(core: &Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    Judge::new(core).part(h, id, ai)
}

/// Whether the author of commit `id` could act for its header's actor (spec/permissions.md
/// §5.2): it is the actor, or its write on the actor at the commit's key is valid as a delta on
/// the actor needing write would be (same timeline, demotions and frontiers). A commit failing
/// this is invalid whole. Role commits name their author (bad input
/// otherwise, spec/wire.md §4), so the timeline never depends on this.
///
/// Invariant (arrival-order independence): a function of the actor's timeline alone, so it
/// changes only when that timeline does; `rejudge_once` re-judges the commits acting for a
/// thing whose timeline changed (`by_actor`).
pub(crate) fn acts_for(core: &Core, h: &Header, id: &CommitId) -> bool {
    Judge::new(core).acts(h, id)
}

fn acts_on(tl: Option<&osis_perm::Timeline>, h: &Header, id: &CommitId) -> bool {
    let Some(tl) = tl else { return false };
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    tl.delta_valid(point, &h.actor, Role::Write) == Validity::Valid
}

/// The newest `required^.0` delta on `tid` valid and ordered before `at`: (its key, the entry
/// governing `ak`) (spec/commits.md §5). A function of the held deltas and the timeline.
fn in_force(judge: &mut Judge<'_>, tid: &Tid, ak: &Ak, at: &Point) -> Option<(Point, Option<ct::Required>)> {
    let valid = judge.settings(tid);
    let (p, rules) = valid.get(valid.partition_point(|x| x.0 < *at).checked_sub(1)?)?;
    Some((*p, ct::required_for(rules, ak).copied()))
}

/// Whether a removal from `tid` at key `at` retains by default: the `retain` of the setting in force
/// (spec/permissions.md §3; none: it erases).
pub(crate) fn retain_in_force(core: &Core, tid: &Tid, at: &Point) -> bool {
    let valid = Judge::new(core).settings(tid);
    valid.partition_point(|x| x.0 < *at).checked_sub(1).and_then(|i| valid.get(i)).is_some_and(|x| x.1.retain)
}

/// `retain_in_force` for a write this node makes now: after every setting it holds.
pub(crate) fn retain_now(core: &Core, tid: &Tid) -> bool {
    retain_in_force(core, tid, &Point { ts: core.hlc.peek(), node: core.id.tid(), commit: CommitId([0xff; 32]) })
}

/// The requirement in force for a write of `ak` on `tid` by `node` at `ts` (the writer's side).
pub(crate) fn required_now(core: &Core, tid: &Tid, ak: &Ak, node: Tid, ts: osis_base::Ts) -> Option<ct::Required> {
    in_force(&mut Judge::new(core), tid, ak, &Point { ts, node, commit: CommitId([0; 32]) })?.1
}

/// The key of the `required^.0` delta that aspect `ai` of held commit `id` breaks, if any
/// (`Judge::broken`).
pub(crate) fn broken_by(core: &Core, h: &Header, id: &CommitId, ai: usize) -> Option<Point> {
    Judge::new(core).broken(h, id, h.aspects.get(ai)?)
}

/// Whether a delta carries exactly the retention and expiry `q` requires.
pub(super) fn meets(q: &ct::Required, h: &Header, a: &osis_commit::AspectEntry) -> bool {
    a.retention == q.retention().canonical() && q.expires_at(h.ts.wall_ms().0) == Some(h.expires)
}

/// `part_valid` over many parts: what is per thing (chain depth, timeline) looked up once per
/// run of parts on one thing.
pub(crate) struct Judge<'a> {
    core: &'a Core,
    last: Option<(Tid, bool, Option<&'a osis_perm::Timeline>)>,
    /// On the last thing: per (author, required role), from where its deltas are valid
    /// whatever else (`Timeline::valid_from`).
    from: BTreeMap<(Tid, Role), Option<Option<Point>>>,
    /// Per (author, actor), from where the author acts for the actor whatever the commit.
    acts: BTreeMap<(Tid, Tid), Option<Option<Point>>>,
    /// On the last thing: its valid `required^.0` deltas, in key order, found once.
    settings: Option<Arc<Settings>>,
    /// Per thing, the addenda on it that count (`Timeline::vouching`), found once; `None` for a
    /// thing with no timeline.
    vouchings: BTreeMap<Tid, Option<Arc<Vouching>>>,
}

/// A thing's `required^.0` deltas: each one's key and what it says.
type Settings = Vec<(Point, Arc<ct::RequiredRules>)>;

impl<'a> Judge<'a> {
    pub(crate) fn new(core: &'a Core) -> Judge<'a> {
        Judge { core, last: None, from: BTreeMap::new(), acts: BTreeMap::new(), settings: None, vouchings: BTreeMap::new() }
    }

    /// The addenda on `t` that count (spec/permissions.md §5.2, Addenda): every held `addenda.0`
    /// delta of a content commit of its author (`Indexes::addenda`), listing what its body says
    /// while held and nothing otherwise (a dropped or missing one is still a write of its author
    /// at its key, which a later addendum may vouch for; it is fetched again when it turns
    /// valid), none of a void commit; the least fixpoint over them is perm's.
    fn vouching(&mut self, t: &Tid) -> Option<Arc<Vouching>> {
        if let Some(v) = self.vouchings.get(t) {
            return v.clone();
        }
        let core = self.core;
        let v = core.timelines.get(t).map(|tl| {
            let mut all: Vec<Addendum> = Vec::new();
            for ((_, c), list) in core.ix.addenda.range((*t, CommitId([0; 32]))..=(*t, CommitId([0xff; 32]))) {
                let Some(m) = core.ix.commits.get(c) else { continue };
                if core.ix.void.contains(c) || m.view.memory {
                    continue;
                }
                all.push((**list).clone());
            }
            Arc::new(tl.vouching(t, &all))
        });
        self.vouchings.insert(*t, v.clone());
        v
    }

    /// Whether a counting addendum on `thing` vouches for the part of the commit at `point`
    /// there: a witness with write on the thing at the addendum's key (spec/permissions.md
    /// §5.2, Addenda). The Acting check of a commit is a part on its header actor, vouched for
    /// on that actor by a writer of it (`acts`).
    fn vouched(&mut self, thing: &Tid, point: Point) -> bool {
        let core = self.core;
        let Some(v) = self.vouching(thing) else { return false };
        if v.is_empty() {
            return false;
        }
        let Some(tl) = core.timelines.get(thing) else { return false };
        v.witnesses(tl, point).next().is_some()
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

    /// The key of the `required^.0` delta in force that delta `a` of commit `id` breaks
    /// (spec/commits.md §5). Its commit's other deltas stand, its own thing's and others': a member
    /// of another thing alone never holds this setting and must read as the rest do.
    fn broken(&mut self, h: &Header, id: &CommitId, a: &osis_commit::AspectEntry) -> Option<Point> {
        if !under_required(h, &a.ak) || !self.core.ix.required.contains_key(&a.tid) {
            return None;
        }
        let (p, q) = in_force(self, &a.tid, &a.ak, &Point { ts: h.ts, node: h.author, commit: *id })?;
        q.filter(|q| !meets(q, h, a)).map(|_| p)
    }

    /// The valid `required^.0` deltas on `t` (`Settings`), each judged once per thing.
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

    /// `acts_for`, its `valid_from` bound found once per (author, actor); else an addendum on
    /// the actor vouching for the commit (spec/permissions.md §5.2, Acting).
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
        acts_on(tl, h, id) || plain_commit(h) && self.vouched(&h.actor, point)
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
        // a delta breaking a required retention at its key (spec/commits.md §5); a `required^.0`
        // delta answers to none, so this ends
        if self.broken(h, id, a).is_some() {
            return false;
        }
        // a thing more than `MAX_CHAIN_DEPTH` record links below its key actor: nothing written on
        // it applies (spec/permissions.md §1); judged per delta from creation records alone
        let (deep, tl) = self.thing(&a.tid);
        if deep {
            return false;
        }
        if ak == "roles.0" {
            return true;
        }
        let Some(tl) = tl else { return false };
        // an addendum: valid as its author's plain delta, by the timeline or by a counting
        // addendum (the fixpoint, `vouching`)
        if ct::is_addenda(ak) {
            return self.vouching(&a.tid).is_some_and(|v| v.valid(id));
        }
        // a compaction snapshot: valid iff its author could write the aspect at the snapshot,
        // judged by commit ID (a demotion's frontier lists it; addenda list content commits
        // only), needing the strictest role a write it carries could need (`snapshot_role`:
        // admin for `keys.0` and `secrets.0`)
        if h.kind.is_compaction() {
            let required = crate::engine::write::snapshot_role(ak);
            let point = Point { ts: h.ts, node: h.author, commit: *id };
            return tl.delta_valid(point, &a.tid, required) == Validity::Valid;
        }
        // the author's deltas from the first point it held the role on are valid (re-grant),
        // found once per author
        if !core.ix.rotation_role.contains_key(&(*id, ai)) && ak != "secrets.0" {
            let required = required_role(ak);
            let from = *self.from.entry((h.author, required)).or_insert_with(|| tl.valid_from(&h.author, &a.tid, required));
            let point = Point { ts: h.ts, node: h.author, commit: *id };
            if from.is_some_and(|b| b.is_none_or(|b| b <= point)) {
                debug_assert!(self.valid_on(tl, h, id, ai, a), "valid_from disagrees with delta_valid");
                return true;
            }
        }
        self.valid_on(tl, h, id, ai, a)
    }

    /// `part_valid` of a content part on its thing's timeline `tl`: by the timeline, else, for
    /// plain content, by an addendum on the thing (spec/permissions.md §5.2, Addenda).
    fn valid_on(&mut self, tl: &osis_perm::Timeline, h: &Header, id: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> bool {
        let core = self.core;
        let ak = a.ak.as_str();
        let point = Point { ts: h.ts, node: h.author, commit: *id };
        if matches!(ak, "secrets.0" | "keys.0") && h.kind == Kind::Role && !possessed(core, tl, h, id, ai, a) {
            return false;
        }
        // an applied invite grant carries the grantee's boxes (spec/permissions.md §1, §2): every
        // put on the thing applied as an invite grant (`grant_overreach` checked the boxes against
        // all of them), so a self-removal beside a failing put exempts nothing
        if ak == "secrets.0"
            && let Some(c) = tl.role_commit(id)
            && !core.ix.grant_overreach.contains(&(*id, ai))
        {
            let grant = |i: usize| matches!(tl.applied().get(&WriteId(*id, i as u32)), Some(x) if matches!(x.attr, osis_perm::Attr::By(osis_perm::Class::Invite(_))));
            let mut puts = c.ops.iter().enumerate().filter(|(_, o)| o.target == a.tid && o.edge.is_some()).peekable();
            if puts.peek().is_some() && puts.all(|(i, _)| grant(i)) {
                return true;
            }
        }
        let required = core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| required_role(ak));
        if tl.delta_valid(point, &a.tid, required) == Validity::Valid {
            return true;
        }
        required == Role::Write && plain_part(h, a) && self.vouched(&a.tid, point)
    }
}

/// What possession is judged by (`osis_keys::possession::View`): the roles and the held valid
/// keysets just before a role commit's key on the actor's timeline (a keyset counts by a body
/// ordered before it: validity follows the key order, so it has one result).
struct Possession<'a> {
    core: &'a Core,
    tl: &'a osis_perm::Timeline,
    at: At,
    point: Point,
    actor: Tid,
    author: Tid,
    /// The author's roles on paths not through the actor.
    roles: BTreeMap<Tid, Role>,
}

impl osis_keys::possession::View for Possession<'_> {
    fn key_actor(&self, t: &Tid) -> bool {
        self.core.is_key_actor(t) && !self.core.is_account(t)
    }
    fn author_on(&self, t: &Tid) -> Option<Role> {
        self.roles.get(t).copied()
    }
    fn holder_actors(&self) -> BTreeSet<Tid> {
        let held = |m: &Tid| self.core.is_account(m) || self.core.keysets_of(m).any(|(_, _, x)| x.held_before(&self.point));
        self.tl.roster(&self.actor, self.at).into_keys().filter(|m| *m != self.author && !self.key_actor(m) && held(m)).collect()
    }
    fn role_on_actor(&self, avoid: &BTreeSet<Tid>) -> Option<Role> {
        self.tl.roles_avoiding(&self.author, self.at, avoid).get(&self.actor).copied()
    }
    fn keys(&self, m: &Tid, r: Role, k: &osis_crypto::Epoch) -> Option<Vec<osis_crypto::VerifyingKey>> {
        if self.core.is_account(m) {
            return self.core.account_view(m)?.possession_key(k, &self.point).map(|pk| vec![pk]);
        }
        let x = self.core.ix.keysets.get(&(*m, r, *k)).filter(|x| x.held_before(&self.point))?;
        Some(x.possession.iter().filter(|(_, p)| **p < self.point).filter_map(|(pk, _)| osis_crypto::VerifyingKey::from_bytes(pk).ok()).collect())
    }
}

/// Whether part `ai` (`secrets.0` or `keys.0` on `a`) of role commit `id` passes possession
/// (spec/crypto.md §4, Holder actors, Authority), from what its bodies showed (`Indexes::shown`).
/// A rotation (its `keys.0` part on `a` writes a keyset) is judged whole by the proofs its
/// keysets carry: its `secrets.0` part shares the verdict, so a node holding the keysets alone
/// (certificates) judges it alike. A `secrets.0` body held beside a `keys.0` part whose body
/// never was is judged showing nothing; with neither body held there is nothing to judge. Any
/// other `secrets.0` part is judged by its boxes when it removes a box or writes more than
/// entries; anything else is not judged (a box alone never is).
///
/// Invariant (arrival-order independence): a function of `a`'s timeline (`stale_things` when it
/// changes) and of the held valid keysets of the holders it boxes or proves and of `a`'s holders
/// (`stale_commits` when they change, `apply::keys::keyset_changed`), read before its key.
fn possessed(core: &Core, tl: &osis_perm::Timeline, h: &Header, id: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> bool {
    let ki = h.aspects.iter().position(|b| b.tid == a.tid && b.ak.as_str() == "keys.0");
    let keys = ki.map(|ki| (ki, core.ix.shown.get(&(*id, ki))));
    let own = || core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or(Role::Write);
    // a rotation needs the right to rotate its highest rotated role (at least write)
    let (x, rotation, needed) = match (a.ak.as_str(), keys) {
        (_, Some((_, Some(k)))) if k.rotates => (k.clone(), true, k.top.map_or(Role::Write, |r| r.max(Role::Write))),
        ("keys.0", _) => return true,
        (_, Some((_, None))) if core.ix.shown.contains_key(&(*id, ai)) => (Arc::new(crate::engine::Showing::default()), true, own()),
        (_, Some((_, None))) => return true,
        _ => match core.ix.shown.get(&(*id, ai)) {
            Some(x) => (x.clone(), x.rotates, own()),
            None => return true,
        },
    };
    if x.removed.is_empty() && !rotation {
        return true;
    }
    let point = Point { ts: h.ts, node: h.author, commit: *id };
    let at = At::before(point);
    // the author's roles on holder actors not through `a` (a role on M through `a` is a cycle,
    // read through a keyless grant: no secret of M to show)
    let roles = tl.roles_avoiding(&h.author, at, &BTreeSet::from([a.tid]));
    let v = Possession { core, tl, at, point, actor: a.tid, author: h.author, roles };
    osis_keys::possession::holds(&x.shown, &x.removed, rotation, needed, &v)
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

/// The first held commit whose flags differ from what judging it now gives (decodes every
/// header). Debug builds check it after each re-judge; tests after an open from the persisted
/// index (`Engine::misjudged`: every input of a judgment that comes from a body is persisted with
/// the flag, `index::meta_row`).
pub(crate) fn misjudged(core: &Core) -> Option<String> {
    for (id, m) in core.ix.commits.iter() {
        let h = &m.header;
        let now: Vec<bool> = (0..h.aspects.len()).map(|ai| part_valid(core, h, id, ai)).collect();
        if now != m.valid {
            let parts: Vec<_> = h.aspects.iter().zip(m.valid.iter().zip(&now)).filter(|(_, (a, b))| a != b).map(|(x, (a, _))| (x.tid, x.ak.as_str(), *a)).collect();
            return Some(format!("validity of {id:?} ({:?} by {}): {parts:?}", h.kind, h.author));
        }
    }
    None
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
    // an addendum's validity may change with its author's role or its commit's void flag, and
    // with it every part it vouches for: such a thing is judged whole
    let has_addenda = |t: &Tid| tx.core.ix.addenda.range((*t, CommitId([0; 32]))..=(*t, CommitId([0xff; 32]))).next().is_some();
    things.extend(under.iter().filter(|t| has_addenda(t)).copied());
    things.extend(explicit.iter().filter_map(|c| tx.core.ix.commits.get(c)).flat_map(|m| m.view.aspects.iter().filter(|a| ct::is_addenda(a.ak.as_str())).map(|a| a.tid)));
    // the commits whose author's role may have moved on a thing they write
    let (on, acting) = tx.core.authored_under(&under, &authors);
    let authored: BTreeSet<CommitId> = on.collect();
    let acting: BTreeSet<CommitId> = acting.collect();
    // re-judged whole: those named, and those acting for a thing whose timeline changed
    // (`acts_for`); deltas on a thing answer to its `required^.0` deltas (`in_force`), so where
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
    // parts dropped while invalid that turn valid: missing again, fetched
    let mut back: Vec<(CommitId, usize)> = Vec::new();
    let mut fresh = false;
    let current = tx.core.current_sessions();
    let accounts: BTreeSet<Tid> = tx.core.accounts.keys().copied().collect();
    for (id, now) in news {
        let Some(m) = tx.core.ix.commits.get_mut(&id) else { continue };
        let h = m.header.clone();
        if (h.author == me || accounts.contains(&h.author)) && h.kind.has_own_writes() && m.valid.iter().zip(&now).any(|(a, b)| *a && !*b) {
            // an account's commit may be a sibling's: told apart by the session, ours or not
            if h.author == me {
                own_fell.push((id, h.aspects.iter().map(|a| a.tid).collect::<BTreeSet<_>>().into_iter().collect()));
            }
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
                    if m.dropped_invalid(ai) {
                        back.push((id, ai));
                    }
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
    // what was not re-judged has not changed (debug builds: decodes every header)
    #[cfg(debug_assertions)]
    {
        let d = misjudged(tx.core);
        debug_assert!(d.is_none(), "{} changed outside the re-judged set", d.unwrap_or_default());
    }
    // what its body judged goes with it (`reopen`): judged again by the next pass
    crate::retention::valid_again(tx, &back)?;
    for (tid, ak) in &flipped {
        tx.core.mark_aspect_changed(tid, ak);
    }
    if rebuild {
        for (tid, ak) in &flipped {
            // a memory aspect's rebuild is memory work, whatever transaction re-judges it
            let memory = tx.txn.is_memory_aspect(tid, ak);
            tx.in_class(memory, |tx| {
                let k = (*tid, ak.clone());
                // a snapshot turned invalid gives nothing (its writer no longer vouches for it,
                // spec/permissions.md §5.2): parts dropped under its cover alone are missing again
                let snaps = fell.get(&k).into_iter().flatten().any(|(c, _)| tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction()));
                let _s = crate::costs::span("rejudge: rebuild");
                if snaps {
                    crate::retention::uncover(tx, tid, ak)?;
                }
                // the one path (issues/drop-rejoin-robust.md item 1): the aspect rebuilt from
                // what is held
                super::atomic::rebuild(tx, tid, ak)
            })?;
        }
        // memory parts turned valid may supersede held ones (spec/sync.md §9)
        let memory: BTreeSet<(Tid, Ak)> = rose.iter().filter(|(t, a)| tx.txn.is_memory_aspect(t, a)).cloned().collect();
        if !memory.is_empty() {
            let gone = tx.in_class(true, |tx| {
                let gone = crate::retention::memory::drop_superseded(tx, &memory)?;
                // and snapshots turned valid cover held bodies
                crate::retention::memory::drop_covered(tx, &memory, None, None)?;
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
    // a request's right rests on the same timelines (spec/permissions.md §6)
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
    let view = osis_perm::graph::View::at(&edges, Some(ts)).patched(*holder, *target, None);
    view.roles_from(author).get(target).copied() != Some(Role::Admin)
}

/// Rules of a role commit that need its deltas
/// (spec/commits.md §2, spec/wire.md §4 position 13).
pub(crate) fn check_content_rules(core: &Core, h: &Header, parts: &[(usize, Decoded)]) -> Result<()> {
    if h.kind != Kind::Role {
        return Ok(());
    }
    let mut changed: Vec<(Tid, Tid, Option<Edge>)> = Vec::new();
    for (ai, d) in parts {
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
        // spec/permissions.md §7, spec/commits.md §2)
        let redemption = holders.len() == 2 && holders.first().map(|m| m.0) == holders.last().map(|m| m.0) && changed.iter().any(|c| c.1 == h.author && c.2.is_none()) && changed.iter().any(|c| c.1 != h.author && c.2.is_some());
        // or a removal of several others' edges on one target under one rotation (a link joiner
        // with the link key, under one frontier; a finalize of several ended edges): no edge of
        // it a self-removal, each gone or saying retain
        let first = holders.first().map(|m| m.0);
        let removal = changed.iter().all(|c| Some(c.0) == first && c.1 != h.author && c.2.is_none_or(|e| e.says_retain()) && !self_removal(core, &h.author, &c.0, &c.1, h.ts));
        if !redemption && !removal {
            return Err(Error::BadInput("a role commit changes more than one edge"));
        }
    }
    // a frontier rides on an explicit write that audits (spec/permissions.md §5.1 step 4): one
    // below the edge as restored, a removal (of an absent edge too, §2) included
    let audits = changed.iter().any(|(target, m, new)| new.is_none() || core.timelines.get(target).is_some_and(|tl| tl.audits(m, target, *new, h.ts)));
    if h.frontier.is_some() && !audits && !changed.is_empty() {
        return Err(Error::BadInput("a frontier on a commit that audits nothing"));
    }
    // a removal of another's edge with no frontier is a finalize (spec/permissions.md §2): of
    // an edge not past its `until` it would apply nothing, so a revoke written so would cut off
    // nobody. Any other explicit write that audits carries one: without, every write of the
    // holder's it puts in question drops, received or not
    if h.frontier.is_none() {
        for (target, m, new) in &changed {
            let Some(tl) = core.timelines.get(target) else { continue };
            let old = tl.edges_at(None).get(m, target).copied();
            let selfr = self_removal(core, &h.author, target, m, h.ts);
            let removes = *m != h.author && new.as_ref().is_none_or(|e| e.says_retain()) && !selfr;
            if removes && old.is_some_and(|o| o.until.is_none() || o.alive_at(Some(h.ts))) {
                return Err(Error::BadInput("a removal with no frontier of an edge not past its until"));
            }
            let explicit = !selfr && tl.role(&h.author, target, At::now(h.ts)) == Some(Role::Admin);
            if explicit && new.is_some_and(|e| !e.says_retain()) && tl.audits(m, target, *new, h.ts) {
                return Err(Error::BadInput("an explicit write that audits with no frontier"));
            }
        }
    }
    Ok(())
}
