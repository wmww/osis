//! Validity through osis-perm (spec/permissions.md §5): each held commit is given to the walk as
//! its reading (`reading`: edge writes, deltas along their stated paths), each delta is judged by
//! a point query (layer 2), and a change of the walk re-judges the deltas it reaches; an aspect with a flip is rebuilt from its held bodies
//! (un-merge or re-merge, spec/crdt.md §4.6). Also the role-commit content rules
//! osis-commit cannot see (spec/commits.md §2).

use crate::engine::write::required_role;
use crate::engine::{Core, Meta, Owned, Tx, View};
use crate::error::{Error, Result};
use osis_commit::{Decoded, Header, Kind};
use osis_base::{Ak, CommitId, CreationRecord, Holder, Role, SignKey, Tid, Value};
use osis_crdt::{Dot, Fragment};
use osis_perm::paths::{Content, Delta, DeltaClass, Part, PartKind, Way};
use osis_perm::{At, Edge, EdgeOp, Frontier, Point, RoleCommit, WriteId};
use osis_schema::core_types as ct;
use osis_schema::{Codec, Type, typed_read};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

/// The edge a `roles.0` value reads as: `None` when it is not one, which makes the delta bad by
/// itself (`check_holders_parts`).
pub(crate) fn edge_of(v: &Value) -> Option<Edge> {
    Some(perm_edge(&ct::Edge::from_value(&typed(v, "edge")?).ok()?))
}

/// A grant's value as the walk reads it.
pub(crate) fn perm_edge(e: &ct::Edge) -> Edge {
    Edge { role: e.role, until: e.until, may_grant: e.may_grant, retain: e.retain, floor: e.floor }
}

/// The value a walk's edge reads back as (`perm_edge`).
pub(crate) fn schema_edge(e: &Edge) -> ct::Edge {
    ct::Edge { role: e.role, until: e.until, may_grant: e.may_grant, retain: e.retain, floor: e.floor }
}

/// The header's frontier (inline, or resolved from its link), sharing its IDs.
pub(crate) fn header_frontier(h: &Header) -> Option<Arc<Frontier>> {
    h.frontier.clone().map(|ids| Arc::new(Frontier::of_sorted(ids)))
}

/// Whether `ak` holds edge writes (`roles.0` of things, `signers.0` of keys): perm reads them.
pub(crate) fn edge_ak(ak: &str) -> bool {
    Grants::of(ak).is_some()
}

/// Which grants an edge aspect holds: things' (`roles.0`, keyed by a weak) or keys' (`signers.0`,
/// keyed by a `signing_key` value). Its entries' dots are its own: a commit's two edge aspects on
/// a thing may use the same counters, so an entry is named by its aspect too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grants {
    Things,
    Keys,
}

impl Grants {
    pub(crate) fn of(ak: &str) -> Option<Grants> {
        match ak {
            "roles.0" => Some(Grants::Things),
            "signers.0" => Some(Grants::Keys),
            _ => None,
        }
    }
    /// The aspect holding `h`'s grants.
    pub(crate) fn of_holder(h: &Holder) -> Grants {
        match h {
            Holder::Thing(_) => Grants::Things,
            Holder::Key(_) => Grants::Keys,
        }
    }
    pub(crate) fn ak(self) -> &'static str {
        match self {
            Grants::Things => "roles.0",
            Grants::Keys => "signers.0",
        }
    }
    /// The holder an entry key names here; `None`: no holder (bad input as a created entry's key).
    pub(crate) fn holder(self, k: &Value) -> Option<Holder> {
        match (self, k) {
            (Grants::Things, Value::Weak(m)) => Some(Holder::Thing(*m)),
            (Grants::Keys, k) => SignKey::from_value(k).map(Holder::Key),
            _ => None,
        }
    }
    /// The entry key naming `h` here.
    pub(crate) fn key(h: &Holder) -> Value {
        match h {
            Holder::Thing(m) => Value::Weak(*m),
            Holder::Key(k) => k.to_value(),
        }
    }
    /// Whether `e` is a grant this aspect may hold: a key's carries no `retain` and no `floor`, and
    /// is no `until` 0 removal (spec/data-model.md §9 `signers.0`).
    fn fits(self, e: &Edge) -> bool {
        self == Grants::Things || !e.retain && e.floor.is_none() && e.until != Some(osis_base::WallMs(0))
    }
}

/// Whether `ak`'s writes reach perm instead of a state: edge writes and creation records.
pub(crate) fn perm_ak(ak: &str) -> bool {
    edge_ak(ak) || ak == "created.0"
}

/// What a held `addenda.0` delta says (`Indexes::addenda`): its commit's key and the entries it
/// creates.
#[derive(Clone, Debug, PartialEq)]
pub struct Addendum {
    pub point: Point,
    pub entries: Vec<AddendumEntry>,
}

/// An addendum entry: the removal (or rotation) its key names and the commits it lists.
pub(crate) type AddendumEntry = (CommitId, Arc<BTreeSet<CommitId>>);

/// What a commit's `addenda.0` deltas say (`Indexes::addenda`), per thing: the removals the
/// entries name and the commit IDs each lists, none for a delta whose body is not held.
/// Persisted beside the record (`index::ADDENDA`), so an open decodes no body.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AddendaParts(pub Vec<(Tid, Vec<AddendumEntry>)>);

impl AddendaParts {
    /// The parts of commit `id` as the index holds them.
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
        set_addendum(core, *t, point.commit, Some(Addendum { point, entries: es.clone() }));
        core.stale_things.insert(*t);
    }
}

/// Indexes commit `id`'s addendum deltas (spec/permissions.md §5.2, Addenda): every `addenda.0`
/// delta its header names is its signer's write, whether its body is held or not; `parts`, the
/// bodies just held, say its entries. A delta of a commit other than a content one is no
/// addendum.
pub(crate) fn note_addenda(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) {
    if h.kind != Kind::Content {
        return;
    }
    let point = Point { ts: h.ts, node: h.signer, commit: *id };
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
        set_addendum(core, *tid, *id, Some(Addendum { point, entries: Vec::new() }));
        core.stale_things.insert(*tid);
    }
}

/// Forgets what commit `id` said as an addendum (`unindex_commit`). One listing nothing (its
/// body not held, as for every forgettable commit) vouches for nothing: its thing's validity
/// stays as judged.
pub(crate) fn forget_addenda(core: &mut Core, id: &CommitId, aspects: &[crate::engine::AspectView]) {
    for a in aspects.iter().filter(|a| ct::is_addenda(a.ak.as_str())) {
        if set_addendum(core, a.tid, *id, None).is_some_and(|x| !x.entries.is_empty()) {
            core.stale_things.insert(a.tid);
        }
    }
}

/// Sets (or, `None`, removes) what commit `id` says as an addendum on `t`, with its entries'
/// keys (`Indexes::addenda_keyed`); returns what it said before.
fn set_addendum(core: &mut Core, t: Tid, id: CommitId, a: Option<Addendum>) -> Option<Arc<Addendum>> {
    core.ix.held.touch_commit(id);
    let was = match a {
        Some(a) => {
            for (r, _) in &a.entries {
                core.ix.addenda_keyed.insert(*r, (t, id));
            }
            core.ix.addenda.insert((t, id), Arc::new(a))
        }
        None => core.ix.addenda.remove(&(t, id)),
    };
    let now = core.ix.addenda.get(&(t, id)).cloned();
    for (r, _) in was.iter().flat_map(|w| w.entries.iter()) {
        if !now.as_ref().is_some_and(|n| n.entries.iter().any(|(x, _)| x == r)) {
            core.ix.addenda_keyed.remove(r, &(t, id));
        }
    }
    // what it lists reads it against a rotation (`Judge::counts`)
    for c in was.iter().chain(&now).flat_map(|x| x.entries.iter().flat_map(|(_, l)| l.iter())) {
        if core.ix.commits.contains_key(c) {
            core.ix.held.touch_commit(*c);
        }
    }
    core.update_timelines();
    was
}

/// Entries of a `roles.0` (map) fragment: (dot, key, fragment).
fn entries(f: &Fragment) -> Vec<(Dot, Option<Value>, Option<Fragment>)> {
    let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = f.slot(osis_crdt::Encoding::Map) else { return Vec::new() };
    m.entries().map(|(d, _, k, f)| (d.clone(), k.cloned(), f.cloned())).collect()
}

/// An edge aspect's entry as perm's adaptation reads it: dot, the holder its key names (`None`:
/// a key naming no holder), and the edge its fragment reads (`None`: no fragment, an entry
/// reset; a fragment reading no edge is bad input, `check_holders_parts`).
pub(crate) type Entry = (Dot, Option<Holder>, Option<Edge>);

/// What perm's adaptation reads of a role commit's held `roles.0` parts, by aspect index: a
/// function of the commit record, persisted per commit in the index (`engine::index`,
/// `PERM_PARTS`) so an open decodes no role body.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct PermParts {
    pub edges: Vec<(usize, Vec<Entry>)>,
}

impl PermParts {
    pub(crate) fn of(h: &Header, parts: &[(usize, Decoded)]) -> PermParts {
        let mut out = PermParts::default();
        for (ai, d) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            let Some(g) = Grants::of(a.ak.as_str()) else { continue };
            let es = entries(d.fragment())
                .into_iter()
                // a removal record keyed by no holder acts on no holder's entry (spec/crdt.md §5.6)
                .filter(|(_, k, x)| x.is_some() || k.as_ref().is_none_or(|k| g.holder(k).is_some()))
                .filter_map(|(d, k, x)| {
                    let m = k.as_ref().and_then(|k| g.holder(k));
                    let edge = match x {
                        Some(x) => Some(x.read().as_ref().and_then(edge_of)?),
                        None => None,
                    };
                    Some((d, m, edge))
                })
                .collect();
            out.edges.push((*ai, es));
        }
        // by aspect, as the record holds them, whatever order the parts came in
        out.edges.sort_by_key(|x| x.0);
        out
    }
}

/// Records the holder of every edge entry these deltas of aspect `g` create: (target, `g`, entry
/// dot) -> holder. Only the delta carrying the entry's dot (`own`) creates it (a nested write
/// into another's entry is bad input, `check_holders_parts`).
fn note_keys(core: &mut Core, target: &Tid, g: Grants, es: &[Entry], own: Option<&Owned>) -> bool {
    let mut new = false;
    for (d, k, _) in es {
        if let Some(m) = k
            && own.is_some_and(|o| o.owns(d.origin()))
            && core.ix.holder_keys.get(&(*target, g, d.clone())).is_none()
        {
            core.ix.holder_keys.insert((*target, g, d.clone()), *m);
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
/// commit applies nothing yet (`add_role_commit`). A reset beside a put of a live edge for its
/// key decides nothing: the put sets the edge whatever it replaces.
fn edge_ops(core: &Core, target: &Tid, g: Grants, es: &[Entry], own: Option<&Owned>) -> (Vec<EdgeOp>, bool) {
    let mut per: BTreeMap<Holder, Option<Edge>> = BTreeMap::new();
    for (d, k, v) in es {
        if let (Some(m), Some(e)) = (k, v)
            && own.is_some_and(|o| o.owns(d.origin()))
        {
            per.insert(*m, Some(*e));
        }
    }
    let live_put = |m: &Holder| per.get(m).is_some_and(|e| e.is_some_and(|e| !e.says_retain()));
    let mut known = true;
    let mut removed: BTreeSet<Holder> = BTreeSet::new();
    for (d, k, v) in es {
        // a nested write into another's entry is no edge write (bad input on receipt)
        if v.is_some() {
            continue;
        }
        // the entry's creation: one held, else this delta's own (`note_keys` records it so once
        // the commit is held)
        let own_key = || es.iter().find(|(x, m, _)| x == d && m.is_some() && own.is_some_and(|o| o.owns(x.origin()))).and_then(|x| x.1);
        match core.ix.holder_keys.get(&(*target, g, d.clone())).copied().or_else(own_key) {
            Some(m) if k.is_some_and(|k| k != m) => {}
            Some(m) => {
                removed.insert(m);
            }
            None => known &= k.as_ref().is_some_and(live_put),
        }
    }
    for m in removed {
        per.entry(m).or_insert(None);
    }
    (per.into_iter().map(|(holder, edge)| EdgeOp { target: *target, holder, edge }).collect(), known)
}

/// Holders whose edge on `target` a delta of edge aspect `g` writes: an entry it creates names
/// its key, an entry reset the holder its creation keyed (known here or not named).
pub(crate) fn edge_holders(core: &Core, target: &Tid, g: Grants, f: &Fragment) -> Vec<Holder> {
    entries(f)
        .into_iter()
        .filter_map(|(d, k, v)| match (k, v) {
            (Some(k), Some(_)) => g.holder(&k),
            (k, None) => core.ix.holder_keys.get(&(*target, g, d)).copied().filter(|m| k.as_ref().is_none_or(|k| *k == Grants::key(m))),
            _ => None,
        })
        .collect()
}

/// An edge aspect's delta (`roles.0`, `signers.0`) writing inside an entry it did not create is
/// bad input (an edge change is remove + put, spec/permissions.md §2), and so is one holding a
/// value that is no well-formed grant for it, or a `signers.0` entry it creates keyed by no
/// `signing_key` value (spec/data-model.md §9): judged from the delta and its header alone, the
/// one judgment of an edge's shape; perm never sees another.
pub(crate) fn check_holders_parts(h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) -> Result<()> {
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        let Some(g) = Grants::of(a.ak.as_str()) else { continue };
        let es = entries(d.fragment());
        if es.iter().any(|(_, _, f)| f.as_ref().is_some_and(|f| f.read().as_ref().and_then(edge_of).is_none_or(|e| !g.fits(&e)))) {
            return Err(Error::BadInput("an edge aspect's value that is no well-formed grant for it"));
        }
        if es.iter().any(|(_, k, f)| f.is_some() && k.as_ref().is_none_or(|k| g.holder(k).is_none())) {
            return Err(Error::BadInput("an edge aspect's entry keyed by no holder"));
        }
        if h.kind.has_own_writes() {
            let own = Owned::of(h, id, *ai);
            if es.iter().any(|(dot, _, f)| f.is_some() && !own.as_ref().is_some_and(|o| o.owns(dot.origin()))) {
                return Err(Error::BadInput("an edge aspect's write inside an entry the delta did not create"));
            }
        }
    }
    Ok(())
}

/// Sets what perm's held set reads of a held role commit (its edge writes) from
/// `parts`, its held role-class parts, replacing whatever it read of the commit before: a late part, a drop or a forget calls it again with what stays
/// held, so it is a function of the parts held. A commit's edge writes apply together or
/// not at all (spec/permissions.md §2): one whose removal resets an entry of unknown creation
/// names a write this node lacks, so it applies none of them and stays in `unresolved` until keys
/// arrive. Invariant: an applied commit is the whole departure its author applied, which a name of
/// it stands for (spec/crypto.md §4 Met): a finalize held without the write it ends removes nobody
/// here, and one partly applied would let its name cover a holder it left in place.
pub(crate) fn add_role_commit(core: &mut Core, h: &View, path: &osis_commit::Paths, id: &CommitId, parts: &PermParts) {
    hold_role_commit(core, h, path, id, parts);
    core.update_timelines();
}

/// `add_role_commit` short of giving it to the walk: a batch's, which gives its changes at its end.
pub(crate) fn hold_role_commit(core: &mut Core, h: &View, path: &osis_commit::Paths, id: &CommitId, parts: &PermParts) {
    core.stale_commits.insert(*id);
    for (ai, es) in &parts.edges {
        if let Some(a) = h.aspects.get(*ai)
            && let Some(g) = Grants::of(a.ak.as_str())
        {
            note_keys(core, &a.tid, g, es, Owned::of_view(h, id, *ai).as_ref());
        }
    }
    let mut ops = Vec::new();
    let mut known = true;
    for (ai, es) in &parts.edges {
        let Some(a) = h.aspects.get(*ai) else { continue };
        // nothing written on a thing too deep applies (spec/permissions.md §1); its record chain is
        // held whole at apply (`apply::thing_wait`) and a record goes only with every part on its
        // thing, once nothing held needs it, a thing it minted included (`retention::needed`), so
        // this never changes while the part is held
        if too_deep(core, &a.tid) {
            continue;
        }
        // nor do the edge writes of a commit listing a wrong delete key for the thing
        // (spec/crypto.md §7 Checked keys; `Core::rekey` reads them again where that moves)
        if core.miskeyed(id, &a.tid) {
            continue;
        }
        let Some(g) = Grants::of(a.ak.as_str()) else { continue };
        let (v, k) = edge_ops(core, &a.tid, g, es, Owned::of_view(h, id, *ai).as_ref());
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
        // a role commit states one path (spec/wire.md §4); a split one's edge writes rest on none
        let (listed, direct) = match path {
            osis_commit::Paths::One(p) => (p.things.clone(), p.direct),
            osis_commit::Paths::Split(_) => return core.ix.held.remove(id),
        };
        core.ix.held.add_commit(RoleCommit { id: *id, ts: h.ts, signer: h.signer, key: signing_key(core, h), listed, direct, frontier: h.frontier.clone(), ops });
    }
}

/// Notes commit `id` (header `h`, parts judged `valid`) for taking (`Indexes::fires_due`) when a
/// valid part of it is a `grant@~0` fire (spec/sync-inbox.md §5 Carried commits).
pub(crate) fn note_grant_fire(core: &mut Core, id: &CommitId, h: &Header, valid: &[bool]) {
    if h.aspects.iter().zip(valid).any(|(a, v)| *v && crate::flows::inbox::carries(a.ak.as_str())) {
        core.ix.fires_due.insert(*id);
    }
}

/// Where a part sits in the order its path wait reads (spec/permissions.md §5.1 step 1, §5.2
/// Position).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Place {
    /// Content: the start of its `ts`, before every edge write there.
    Start(osis_base::Ts),
    /// An edge write: its commit's point, then its place among that commit's edge writes
    /// (`write_place`); `None`: after every one of them, the least a part of the commit can wait.
    Write(Point, Option<WritePlace>),
}

/// An edge write's place among its commit's (spec/permissions.md §5.1 step 1): on an edge of a
/// path the commit states or not, then thing, then holder.
pub(crate) type WritePlace = (bool, Tid, Holder);

/// The key that signed held commit `h` (spec/wire.md §4 field 1): the one its header names, else
/// its signer's record's: what `apply::commit_key` verified its signature with (its invariant).
/// A commit is held only once that check passed; where the record is not held the zero key
/// stands in, which no record holds and no grant names.
pub(crate) fn signing_key(core: &Core, h: &View) -> SignKey {
    h.key.or_else(|| core.created(&h.signer).and_then(CreationRecord::key)).unwrap_or(SignKey([0; 32]))
}

impl Place {
    /// Whether an edge write of the commit at `at` is ordered before it, `place` its place in
    /// that commit.
    fn after(&self, at: &Point, place: impl FnOnce() -> WritePlace) -> bool {
        match self {
            Place::Start(ts) => at.ts < *ts,
            Place::Write(p, mine) => at < p || at == p && mine.is_none_or(|m| place() < m),
        }
    }
}

/// The place of the edge write on `holder`'s edge on `target` in a commit signed by `key` as
/// `signer` stating `along` (marks `direct`) for `target`, `mint` holding the record chains it
/// reads. Interim
/// (issues/stated-path-wait-order.md): an edge on another thing's path counts as stated only
/// where it is on `target`'s, so a write on a record edge down to a thing the commit writes other
/// than by edge writes may sit apart from the walk's place for it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_place(mint: &BTreeMap<Tid, Holder>, key: SignKey, signer: Tid, along: &[Tid], direct: osis_base::format::PathMarks, target: Tid, holder: Holder) -> WritePlace {
    let stated = osis_perm::paths::hops(mint, key, signer, along, direct, target, None, true).contains(&(holder, target));
    (stated, target, holder)
}

/// Whether an edge of the path a part states has not arrived (spec/commits.md §4 Unjudgeable):
/// one that is no record edge and that no held edge write (a grant or a removal, of any validity)
/// not itself unjudgeable is ordered before the part, `at`. The part is by `signer` on `t` along
/// `along`, its hops `direct` marked; `edge_class` for a `roles.0` part, `leaves` for one read as
/// a self-removal, whose path ends at its holder, the last thing listed or the signer
/// (spec/permissions.md §1 Path). A path stating no edges (a thing named twice, a bad mark) is
/// judged as it is. `record`: the records held, or carried by the commit. No other path is read:
/// one that would also lead to `t` judges nothing (§1).
#[allow(clippy::too_many_arguments)]
pub(crate) fn unreached(core: &Core, signer: Tid, key: Option<SignKey>, along: &[Tid], direct: osis_base::format::PathMarks, t: &Tid, edge_class: bool, leaves: bool, at: Place, record: &dyn Fn(&Tid) -> Option<CreationRecord>) -> bool {
    let holder = leaves.then(|| Holder::Thing(along.last().copied().unwrap_or(signer)));
    // the key its signature verified with (`apply::commit_key`)
    let key = key.or_else(|| record(&signer).and_then(|r| r.key())).unwrap_or(SignKey([0; 32]));
    Reach::new(core, record).unreached(key, signer, along, direct, *t, edge_class, holder, at)
}

/// The path wait over the held edge writes. Each edge's writes are judged in order, each once, up
/// to the first not itself unjudgeable (`first`): a part's wait reads each held write at most once.
/// A write's judgment reads only writes ordered strictly before it, so it ends, and never reads an
/// edge past where that edge's judging stands.
struct Reach<'a> {
    core: &'a Core,
    record: &'a dyn Fn(&Tid) -> Option<CreationRecord>,
    /// Edge (holder, thing) -> its writes judged: the first not itself unjudgeable (`Ok`), or the
    /// last of those before it judged so far (`Err`), all unjudgeable.
    first: BTreeMap<(Holder, Tid), std::result::Result<Point, Point>>,
}

/// The record chains of `members` (`record` the records read), each record's holder: what a
/// path's descents and record edges read, a record's key included.
fn chains(members: impl IntoIterator<Item = Tid>, record: &dyn Fn(&Tid) -> Option<CreationRecord>) -> BTreeMap<Tid, Holder> {
    let mut mint: BTreeMap<Tid, Holder> = BTreeMap::new();
    for start in members {
        let mut x = start;
        for _ in 0..=osis_base::format::MAX_CHAIN_DEPTH {
            let Some(up) = record(&x).and_then(|r| r.holder()) else { break };
            if mint.insert(x, up).is_some() {
                break;
            }
            let Holder::Thing(up) = up else { break };
            x = up;
        }
    }
    mint
}

impl<'a> Reach<'a> {
    fn new(core: &'a Core, record: &'a dyn Fn(&Tid) -> Option<CreationRecord>) -> Self {
        Reach { core, record, first: BTreeMap::new() }
    }

    fn mint(&self, members: impl IntoIterator<Item = Tid>) -> BTreeMap<Tid, Holder> {
        chains(members, self.record)
    }

    /// Whether an edge of the path stated by `key`'s commit as `signer` has not arrived: one that
    /// is no record edge with no held edge write before `at`, the key hop among them (a key
    /// granted on `signer` waits for its grant as any holder does).
    #[allow(clippy::too_many_arguments)]
    fn unreached(&mut self, key: SignKey, signer: Tid, along: &[Tid], direct: osis_base::format::PathMarks, t: Tid, edge_class: bool, holder: Option<Holder>, at: Place) -> bool {
        let mint = self.mint([signer, t].into_iter().chain(along.iter().copied()));
        let hops = osis_perm::paths::hops(&mint, key, signer, along, direct, t, holder, edge_class);
        hops.into_iter().any(|(p, q)| mint.get(&q) != Some(&p) && !self.arrived(p, q, at))
    }

    /// Whether a held edge write on `p`'s edge on `q`, not itself unjudgeable, is ordered before
    /// `at`: whether the first such is.
    fn arrived(&mut self, p: Holder, q: Tid, at: Place) -> bool {
        let core: &'a Core = self.core;
        loop {
            let after = match self.first.get(&(p, q)) {
                Some(Ok(w)) => return self.before(core.ix.held.edge_commit(&w.commit), w, p, q, at),
                Some(Err(w)) => Some(*w),
                None => None,
            };
            let Some(&w) = core.ix.held.writes_on(p, &q, after.as_ref()).next() else { return false };
            let c = core.ix.held.edge_commit(&w.commit);
            // ascending: none past one not before `at` is before it
            if !self.before(c, &w, p, q, at) {
                return false;
            }
            osis_base::costs::count("path wait: write read", 1);
            // its judgment reads this edge only before `w`: judged, as `first` says
            let judgeable = c.is_some_and(|c| !self.write_unreached(c, p, q));
            self.first.insert((p, q), if judgeable { Ok(w) } else { Err(w) });
            if judgeable {
                return true;
            }
        }
    }

    /// Whether the write of `c` (held, at `w`) on `p`'s edge on `q` is ordered before `at`.
    fn before(&self, c: Option<&RoleCommit>, w: &Point, p: Holder, q: Tid, at: Place) -> bool {
        at.after(w, || {
            let Some(c) = c else { return (true, q, p) };
            let along = c.path_to(&q);
            write_place(&self.mint([c.signer, q].into_iter().chain(along.iter().copied())), c.key, c.signer, along, c.direct, q, p)
        })
    }

    /// Whether the held edge write of `c` on `holder`'s edge on `target` is itself unjudgeable.
    fn write_unreached(&mut self, c: &RoleCommit, holder: Holder, target: Tid) -> bool {
        let along = c.path_to(&target);
        let end = along.last().copied().unwrap_or(c.signer);
        let mint = self.mint([c.signer, target].into_iter().chain(along.iter().copied()));
        let at = Place::Write(c.point(), Some(write_place(&mint, c.key, c.signer, along, c.direct, target, holder)));
        self.unreached(c.key, c.signer, along, c.direct, target, true, Self::leaving(c.key, c.signer, &end, along, &holder), at)
    }

    /// The holder whose grant an edge write of `key`'s commit as `signer` on `holder`'s edge
    /// leaves (its path ending at it, spec/permissions.md §2 Self-removal): a thing at the path's
    /// end, or the signing key itself on the signer along the empty path (stating no hop).
    fn leaving(key: SignKey, signer: Tid, end: &Tid, along: &[Tid], holder: &Holder) -> Option<Holder> {
        match holder {
            Holder::Thing(h) => (h == end).then_some(*holder),
            Holder::Key(k) => (*k == key && along.is_empty() && *end == signer).then_some(*holder),
        }
    }
}

/// Whether every edge write the `roles.0` part of aspect `ai` of commit `id` makes is unjudgeable
/// (spec/commits.md §4): an edge of its path (to its holder, for a self-removal: the last thing
/// listed or the signer) has no held edge write ordered before it (`unreached`). `es` its
/// entries, `known`: every edge part held of the commit resolved (`resolved`). A part making no
/// write yet (a reset whose creation is not held, or not all known) is read as one write after
/// every edge write of its commit, along the whole path.
pub(crate) fn writes_unreached(core: &Core, h: &Header, id: &CommitId, ai: usize, es: &[Entry], known: bool, record: &dyn Fn(&Tid) -> Option<CreationRecord>) -> bool {
    let (Some(a), osis_commit::Paths::One(p)) = (h.aspects.get(ai), &h.path) else { return false };
    let along = p.to(&a.tid);
    let end = along.last().copied().unwrap_or(h.signer);
    let point = Point { ts: h.ts, node: h.signer, commit: *id };
    let g = Grants::of(a.ak.as_str());
    let ops = match g.filter(|_| known && !too_deep(core, &a.tid)) {
        Some(g) => edge_ops(core, &a.tid, g, es, Owned::of(h, id, ai).as_ref()).0,
        None => Vec::new(),
    };
    // the key its signature verified with (`apply::commit_key`)
    let key = h.key.or_else(|| record(&h.signer).and_then(|r| r.key())).unwrap_or(SignKey([0; 32]));
    let mut reach = Reach::new(core, record);
    if ops.is_empty() {
        return reach.unreached(key, h.signer, along, p.direct, a.tid, true, None, Place::Write(point, None));
    }
    let mint = chains([h.signer, a.tid].into_iter().chain(along.iter().copied()), record);
    ops.iter().all(|o| {
        let at = Place::Write(point, Some(write_place(&mint, key, h.signer, along, p.direct, a.tid, o.holder)));
        reach.unreached(key, h.signer, along, p.direct, a.tid, true, Reach::leaving(key, h.signer, &end, along, &o.holder), at)
    })
}

/// Whether every reset of the `roles.0` entries `es` of aspect `ai` of commit `id` names a write
/// held here (`edge_ops`).
pub(crate) fn resolved(core: &Core, h: &Header, id: &CommitId, ai: usize, es: &[Entry]) -> bool {
    h.aspects.get(ai).is_none_or(|a| too_deep(core, &a.tid) || Grants::of(a.ak.as_str()).is_none_or(|g| edge_ops(core, &a.tid, g, es, Owned::of(h, id, ai).as_ref()).1))
}

/// The role a `keys.0` or `secrets.0` delta needs (spec/permissions.md §3). `keys.0`: a writer
/// rotates sync, read and write, only an admin the admin role; a box record needs the role its
/// key names, as its box does; at least write. A delta that is not a plain struct (a write or
/// reset of the whole value) replaces every field: admin.
fn rotation_required(ak: &str, f: &Fragment) -> Option<Role> {
    match ak {
        "secrets.0" => return Some(secrets_role(f)),
        "keys.0" => {}
        _ => return None,
    }
    if !f.is_plain_struct() {
        return Some(Role::Admin);
    }
    let Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct) else { return Some(Role::Write) };
    // the admin keyset, a key actor's KEM key, the inbox, the deposit seed and the sync ID need
    // admin (spec/crypto.md §3: by an admin); sync, read and write keysets their rotator
    if (2..=5).chain([9]).any(|id| st.field(id).is_some()) {
        return Some(Role::Admin);
    }
    let Some(field) = st.field(crate::flows::SEALED) else { return Some(Role::Write) };
    let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map).filter(|_| !field.has_reset()) else { return Some(Role::Admin) };
    let mut top = Role::Write;
    for (_, _, k, _) in m.entries() {
        let role = k.and_then(|k| typed(k, "box_key")).and_then(|k| ct::BoxKey::from_value(&k).ok()).map(|k| k.role);
        top = top.max(role.unwrap_or(Role::Admin));
    }
    Some(top)
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
    let mut top = if history_only { Role::Sync } else { Role::Write };
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

/// Records the roles `secrets.0` and `keys.0` deltas of a commit need, and the `secrets.0` parts
/// of a role commit that write beyond its grantees' boxes. `read`: every held part of the
/// commit (a late `secrets.0` part is judged with the `roles.0` part held before it). The
/// commit's reading moves with them (`reading`): touched, the caller giving it to the walk.
pub(crate) fn note_required(core: &mut Core, h: &Header, id: &CommitId, read: &super::PartsRead<'_>) {
    let parts = read.all();
    core.stale_commits.insert(*id);
    core.ix.held.touch_commit(*id);
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
    // the edges this commit puts, per target: what a may-grant grant may box
    let mut granted: BTreeMap<(Tid, Tid), Role> = BTreeMap::new();
    for (ai, es) in &read.perm().edges {
        let Some(a) = h.aspects.get(*ai) else { continue };
        for (_, m, e) in es {
            // a key's grant boxes nothing (spec/permissions.md §2 Key grants)
            if let (Some(Holder::Thing(m)), Some(e)) = (m, e) {
                granted.insert((a.tid, *m), e.role);
            }
        }
    }
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if matches!(a.ak.as_str(), "secrets.0" | "keys.0") {
            if crate::engine::Owned::of(h, id, *ai).is_some_and(|own| grantee_boxes_only(&a.tid, a.ak.as_str(), d.fragment(), &granted, &own)) {
                core.ix.grant_overreach.remove(&(*id, *ai));
            } else {
                core.ix.grant_overreach.insert((*id, *ai));
            }
        }
    }
}

/// Whether a `secrets.0` delta writes only the boxes of the holders `granted` puts on `actor`, at
/// or below each one's role, and history boxes at or below the highest granted role, or a
/// `keys.0` delta only those boxes' records (field `SEALED`), as puts only: entries this delta
/// creates (`own` dots), no reset of the value, a field, a map or any entry (spec/permissions.md
/// §2). Judged from the delta alone, so every node judges it alike whatever it holds.
pub(super) fn grantee_boxes_only(actor: &Tid, ak: &str, f: &Fragment, granted: &BTreeMap<(Tid, Tid), Role>, own: &crate::engine::Owned) -> bool {
    // a write or reset of the whole value removes every box
    if !f.is_plain_struct() {
        return false;
    }
    let Some(osis_crdt::SlotRef::Frag(Fragment::Struct(st))) = f.slot(osis_crdt::Encoding::Struct) else { return false };
    let top = granted.iter().filter(|((t, _), _)| t == actor).map(|(_, r)| *r).max();
    let fits = |k: &ct::BoxKey| granted.get(&(*actor, k.holder.0)).is_some_and(|r| k.role <= *r);
    let fields: &[u64] = if ak == "keys.0" { &[crate::flows::SEALED] } else { &[0, 1] };
    if ak == "keys.0" && st.field_ids().any(|id| id != crate::flows::SEALED) {
        return false;
    }
    for &id in fields {
        let Some(field) = st.field(id) else { continue };
        // every entry new: created by this delta (its own dots), never a write into another's
        if !field.is_put_only_map(&|d| own.owns(d)) {
            return false;
        }
        let Some(osis_crdt::SlotRef::Frag(Fragment::Map(m))) = field.slot(osis_crdt::Encoding::Map) else { return false };
        for (_, _, k, _) in m.entries() {
            let Some(k) = k else { return false };
            let ok = match id {
                1 => typed(k, "history_key").and_then(|k| ct::HistoryKey::from_value(&k).ok()).is_some_and(|k| top.is_some_and(|t| k.role <= t)),
                _ => typed(k, "box_key").and_then(|k| ct::BoxKey::from_value(&k).ok()).is_some_and(|k| fits(&k)),
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

/// Notes the held `retention^.0` bodies among `parts` (spec/commits.md §5 The setting), each read
/// alone: one not reading as a setting is none. Each is ordered by the setting write it carries:
/// a delta by its own key, a snapshot by its newest write's stamp, so the last is the one whose
/// write the state holds; what rests on the thing's current setting is judged again
/// (`setting_moved`).
pub(crate) fn note_settings(core: &mut Core, h: &Header, id: &CommitId, parts: &[(usize, Decoded)]) {
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai).filter(|a| a.ak.as_str() == osis_commit::retention::RETENTION) else { continue };
        let before = enabled(core, &a.tid);
        let Some(setting) = d.fragment().read().and_then(|v| ct::retention_setting(&v)) else {
            setting_moved(core, &a.tid, Some(before));
            continue;
        };
        let f = d.fragment();
        let ts = if h.kind.is_compaction() { f.winners().iter().map(|w| w.stamp.ts).max().unwrap_or(h.ts) } else { h.ts };
        let p = Point { ts, node: h.signer, commit: *id };
        let put = |l: &mut Vec<(Point, Arc<ct::RetentionSetting>)>| {
            if let Err(i) = l.binary_search_by(|x| x.0.cmp(&p)) {
                l.insert(i, (p, Arc::new(setting.clone())));
            }
        };
        core.ix.retention.upsert(a.tid, || {
            let mut l = Vec::new();
            put(&mut l);
            l
        }, put);
        setting_moved(core, &a.tid, Some(before));
    }
}

/// A `retention^.0` part of commit `id` on `t` no longer held (dropped, forgotten, unindexed):
/// a setting not held is in force nowhere (spec/commits.md §5 In force).
pub(crate) fn forget_setting(core: &mut Core, t: &Tid, id: &CommitId) {
    let Some(mut settings) = core.ix.retention.get(t).cloned() else { return };
    let before = enabled(core, t);
    settings.retain(|x| x.0.commit != *id);
    if settings.is_empty() {
        core.ix.retention.remove(t);
    } else {
        core.ix.retention.insert(*t, settings);
    }
    setting_moved(core, t, Some(before));
}

/// The external signals `t`'s current setting enables (`RetentionSetting::enables`).
pub(crate) fn enabled(core: &Core, t: &Tid) -> BTreeSet<Ak> {
    setting_now(core, t).map(|s| s.rules.keys().filter(|a| a.external()).cloned().collect()).unwrap_or_default()
}

/// `t`'s held valid settings moved (one held, dropped, purged or turning valid or invalid), so
/// its current setting may have (spec/commits.md §5 In force): what its history judges is judged
/// again (`retention::settings_changed`), and so are the external fires held on `t` whose validity
/// may rest on that setting (spec/permissions.md §5.2 External fires), by the one re-judging path
/// (`stale_commits`). `before`: the signals enabled before a move of the held settings, so only
/// the fires of signals that changed are (a fire's verdict reads the setting by `enables` alone;
/// a setting dropped or covered at a transaction's end moves none); `None`: a setting's validity
/// flipped while the pass judging it is under way, so every one is. O(those fires).
pub(crate) fn setting_moved(core: &mut Core, t: &Tid, before: Option<BTreeSet<Ak>>) {
    core.settings_due.insert(*t);
    core.kept_things_due.insert(*t);
    let moved = |a: &Ak| a.external() && before.as_ref().is_none_or(|b| b.contains(a) != setting_now(core, t).is_some_and(|s| s.enables(a)));
    let fires: Vec<CommitId> = core.aspects_of(t).filter(|((_, a), _)| moved(a)).flat_map(|(_, s)| s.iter().map(|x| x.1)).collect();
    core.stale_commits.extend(fires);
}

/// Re-derives the edge writes of commits whose removed keys were unknown, and of those whose
/// things with a wrong delete key moved (`Indexes::rekeyed`).
pub(crate) fn resolve_unresolved(tx: &mut Tx<'_>) -> Result<()> {
    let rekeyed: Vec<CommitId> = tx.core.ix.rekeyed.iter().copied().collect();
    for id in &rekeyed {
        tx.core.ix.rekeyed.remove(id);
    }
    let ids: BTreeSet<CommitId> = tx.core.ix.unresolved.iter().copied().chain(rekeyed).collect();
    for id in ids {
        let Some(v) = tx.core.ix.commits.get(&id).map(|m| m.view.clone()) else { continue };
        let parts = super::perm_parts(tx, &id)?;
        let Some(path) = tx.core.ix.commits.get(&id).map(|m| m.header.path.clone()) else { continue };
        add_role_commit(tx.core, &v, &path, &id, &parts);
    }
    Ok(())
}

/// Whether `t`'s record chain is not known to end at a key actor within `MAX_CHAIN_DEPTH` links,
/// mint-admin links counted (spec/permissions.md §1): deeper, or a creation record on it is not
/// held (unknown counts as invalid, so forgetting a record never makes a deep delta valid).
/// O(`MAX_CHAIN_DEPTH`).
pub(crate) fn too_deep(core: &Core, t: &Tid) -> bool {
    !core.ix.held.chain_held(t)
}

/// Is aspect `ai` of a held commit whose view is `view` (its purge author, the paths known here)
/// valid (spec/permissions.md §5.2)?
pub(crate) fn part_valid(core: &Core, h: &Header, view: &crate::engine::View, id: &CommitId, ai: usize) -> bool {
    Judge::new(core).part(h, view, id, ai)
}

/// `part_valid` of every aspect of commit `id`, judged by one `Judge` (the commit's reading
/// found once, not once per part).
pub(crate) fn parts_valid(core: &Core, h: &Header, view: &crate::engine::View, id: &CommitId) -> Vec<bool> {
    let mut judge = Judge::new(core);
    (0..h.aspects.len()).map(|ai| judge.part(h, view, id, ai)).collect()
}

/// Whether a removal from `tid` retains by default: the `retain` of its current setting
/// (spec/permissions.md §3; none: it erases).
pub(crate) fn retain_default(core: &Core, tid: &Tid) -> bool {
    setting_now(core, tid).is_some_and(|s| s.retain)
}

/// The valid `retention^.0` bodies held on `tid`, ordered by the setting write each carries (a
/// snapshot's by its own: `note_settings`); the last is the current setting (spec/commits.md §5
/// In force; `retention::history`).
/// Judged by the parts' validity flags (`Meta::valid`, set by every re-judge), from the views
/// alone: no header is decoded.
pub(crate) fn settings(core: &Core, tid: &Tid) -> Arc<Settings> {
    let Some(all) = core.ix.retention.get(tid) else { return Arc::default() };
    let valid = |p: &Point| core.ix.commits.get(&p.commit).is_some_and(|m| m.view.aspect(tid, osis_commit::retention::RETENTION).is_some_and(|ai| m.valid_at(ai) && !m.own_gone(ai)));
    Arc::new(all.iter().filter(|x| valid(&x.0)).cloned().collect())
}

/// The current setting of `tid`: the newest held valid one (spec/commits.md §5 In force), what
/// history keeps and what this node writes under (the writer fills expiry and refuses a replace
/// by it).
pub(crate) fn setting_now(core: &Core, tid: &Tid) -> Option<Arc<ct::RetentionSetting>> {
    settings(core, tid).last().map(|x| x.1.clone())
}

/// The path commit `h` (view `view`) states for thing `t`: the things it writes `t` along, the
/// hops marked direct, and its purge author as an index into [signer, the things, `t`]. `None`
/// where a split commit's entry for `t` is bad or opens nowhere here.
pub(crate) fn stated(h: &Header, view: &View, t: &Tid) -> Option<(Vec<Tid>, osis_base::format::PathMarks, u32)> {
    let known;
    let p = match &h.path {
        osis_commit::Paths::One(p) => p,
        osis_commit::Paths::Split(_) => {
            known = view.paths.as_ref()?.get(t)?.clone()?;
            &known
        }
    };
    let along = p.to(t);
    let author = match p.purge.checked_sub(1).and_then(|j| p.things.get(j)) {
        None => 0,
        Some(x) => along.iter().position(|y| y == x).unwrap_or(along.len()) + 1,
    };
    Some((along.to_vec(), p.direct, u32::try_from(author).ok()?))
}

/// Held commit `id` as the walk reads it (`osis_perm::HeldSet::commit`), a function of the index:
/// part `ai` is aspect `ai`'s delta along the path the commit states for its thing, needing the
/// role its aspect does, or nothing where the walk reads none of it (an edge write's aspect,
/// `created.0`, a listing, a part whose path is not known, a void commit's, one that does not
/// pass the epoch rule); then one part per purge item (`retention::purge::item_names`); its edge
/// writes are its `RoleCommit`'s where it counts.
pub(crate) fn reading(core: &Core, id: &CommitId) -> Option<osis_perm::Held> {
    let m = core.ix.commits.get(id)?;
    Some(reading_of(core, id, &m.header, &m.view))
}

/// `reading` of a commit by its header and view, held or about to be.
pub(crate) fn reading_of(core: &Core, id: &CommitId, h: &Header, view: &View) -> osis_perm::Held {
    read(core, id, h, view, true)
}

/// `reading_of`; without `carries`, what a snapshot carries and what carries the commit are left
/// out: judging the commit's own deltas reads neither (`Judge::by_path`), and listing them
/// costs O(the commits carried).
fn read(core: &Core, id: &CommitId, h: &Header, view: &View, carries: bool) -> osis_perm::Held {
    let void = core.ix.void.contains(id);
    let none = |a: &osis_commit::AspectEntry| Part { on: a.tid, path: Vec::new(), direct: 0, kind: PartKind::None };
    let mut parts = Vec::with_capacity(h.aspects.len());
    for (ai, a) in h.aspects.iter().enumerate() {
        let ak = a.ak.as_str();
        let read = !void && !perm_ak(ak) && !too_deep(core, &a.tid);
        let Some((path, direct, purge_author)) = stated(h, view, &a.tid).filter(|_| read) else {
            parts.push(none(a));
            continue;
        };
        let class = if h.kind.is_compaction() {
            // a list naming it names the held commits it carries (spec/permissions.md §5.2
            // Copies); what it states of them is not read here
            let carries = if carries { Frontier::new(crate::retention::snapshot::carried(core, id, &a.tid, &a.ak)) } else { Frontier::default() };
            DeltaClass::Snapshot { carries, stated: BTreeMap::new(), own: h.own_cover }
        } else if ct::is_addenda(ak) && h.kind == Kind::Content {
            // one entry is read (a node writes one per thing and removal, spec/permissions.md
            // §5.2 Writing); without its body it lists nothing
            match core.ix.addenda.get(&(a.tid, *id)).and_then(|x| x.entries.first().cloned()) {
                Some((removal, list)) => DeltaClass::Addendum { removal, list: Frontier::new(list.iter().copied()) },
                None => DeltaClass::Addendum { removal: CommitId([0; 32]), list: Frontier::default() },
            }
        } else if ct::is_role_class(ak) {
            DeltaClass::RoleClass
        } else {
            DeltaClass::Plain
        };
        let needs = if h.kind.is_compaction() { crate::engine::write::snapshot_role(ak) } else { core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| required_role(ak)) };
        parts.push(Part { on: a.tid, path, direct, kind: PartKind::Delta(Delta { aspect: a.ak.clone(), needs, purge_author, purge_by: a.purge_by, class }) });
    }
    if !void {
        for item in &h.purge {
            let (t, ak, names) = crate::retention::purge::item_names(item);
            let kind = match stated(h, view, t) {
                Some((_, _, purge_author)) => PartKind::Delta(Delta { aspect: ak.clone(), needs: Role::Write, purge_author, purge_by: osis_base::PurgeBy::Admin, class: DeltaClass::Purge { names } }),
                None => PartKind::None,
            };
            let (path, direct) = stated(h, view, t).map(|x| (x.0, x.1)).unwrap_or_default();
            parts.push(Part { on: *t, path, direct, kind });
        }
    }
    let carriers = if void || !carries { Vec::new() } else { crate::retention::snapshot::carriers(core, id, view) };
    osis_perm::Held { id: *id, ts: h.ts, signer: h.signer, key: signing_key(core, view), parts, role: core.ix.held.held_commit(id), carriers }
}

/// [signer, the things `t` is written along] of the path commit `h` states for `t` (`stated`).
pub(crate) fn chain(h: &Header, view: &View, t: &Tid) -> Option<Vec<Tid>> {
    stated(h, view, t).map(|(along, _, _)| std::iter::once(h.signer).chain(along).collect())
}

/// The walk's index of purge item `j` of a commit with header `h` (`reading`).
pub(crate) fn request_part(h: &Header, j: usize) -> u32 {
    (h.aspects.len() + j) as u32
}

impl osis_perm::HeldSet for Core {
    fn created(&self, thing: &Tid) -> Option<CreationRecord> {
        self.ix.held.created(thing).cloned()
    }
    fn commit(&self, id: &CommitId) -> Option<osis_perm::Held> {
        reading(self, id)
    }
    /// O(the held commits): a key actor's record goes only with what is signed as it
    /// (`retention::needed`), so this finds none but for a record forgotten out of turn.
    fn signed_as(&self, signer: &Tid) -> Vec<CommitId> {
        self.ix.commits.iter().filter(|(_, m)| m.view.signer == *signer).map(|(id, _)| *id).collect()
    }
}

/// `part_valid` over many parts: what is per commit or thing looked up once.
pub(crate) struct Judge<'a> {
    core: &'a Core,
    /// Per thing, its current setting (`setting_now`), found once.
    settings: BTreeMap<Tid, Option<Arc<ct::RetentionSetting>>>,
    /// Per commit, its deltas as the walk reads them (`reading_of`), found once.
    readings: BTreeMap<CommitId, osis_perm::paths::Commit>,
}

/// A thing's `retention^.0` deltas: each one's key and what it says.
pub(crate) type Settings = Vec<(Point, Arc<ct::RetentionSetting>)>;

impl<'a> Judge<'a> {
    pub(crate) fn new(core: &'a Core) -> Judge<'a> {
        Judge { core, settings: BTreeMap::new(), readings: BTreeMap::new() }
    }

    pub(crate) fn part(&mut self, h: &Header, view: &crate::engine::View, id: &CommitId, ai: usize) -> bool {
        let core = self.core;
        if core.ix.void.contains(id) {
            return false;
        }
        let Some(a) = h.aspects.get(ai) else { return false };
        let ak = a.ak.as_str();
        // `created.0` hashes to its tid, whoever writes it
        if ak == "created.0" {
            return true;
        }
        // a commit's deltas on a thing for which it lists a level-1 or level-3 delete key no step
        // places before it are invalid (spec/crypto.md §7 Checked keys, spec/commits.md §4;
        // `Core::rekey` keeps the set, and names the commit stale wherever it moves)
        if core.miskeyed(id, &a.tid) {
            return false;
        }
        // a split commit's part whose thing's path is not known here (or opened bad) is judged
        // invalid until it opens (spec/wire.md §4 `Split`, `apply::paths`)
        if !view.path_known(&a.tid) {
            return false;
        }
        // an external fire (spec/permissions.md §5.2 External fires): valid by its path (a
        // writer's fire, whatever the setting), else iff the thing's current setting enables its
        // signal. Invariant: the setting is admin-only (its own validity reads no fire), and the
        // current one is a function of the held valid settings alone; every move of it re-judges
        // the thing's external fires (`setting_moved`).
        if a.ak.external() {
            return self.by_path(h, view, id, ai, a) || self.settings.entry(a.tid).or_insert_with(|| setting_now(core, &a.tid)).as_ref().is_some_and(|s| s.enables(&a.ak));
        }
        self.by_path(h, view, id, ai, a)
    }

    /// `part` of a part past the epoch rule: valid along the path its commit states for its
    /// thing (spec/permissions.md §5.2), as the walk judges it.
    fn by_path(&mut self, h: &Header, view: &View, id: &CommitId, ai: usize, a: &osis_commit::AspectEntry) -> bool {
        let core = self.core;
        let ak = a.ak.as_str();
        // a thing more than `MAX_CHAIN_DEPTH` record links below its key actor: nothing written on
        // it applies (spec/permissions.md §1); judged per delta from creation records alone
        if too_deep(core, &a.tid) {
            return false;
        }
        // an edge write is judged by the timeline
        if edge_ak(ak) {
            return true;
        }
        // an applied may-grant grant carries the grantee's boxes (spec/permissions.md §2): every
        // put on the thing applied as a may-grant grant (`grant_overreach` checked the boxes
        // against all of them), so a self-removal beside a failing put exempts nothing
        if matches!(ak, "secrets.0" | "keys.0")
            && !core.ix.grant_overreach.contains(&(*id, ai))
            && let Some(c) = core.timelines().role_commit(id)
        {
            let grant = |i: usize| core.timelines().way(&WriteId(*id, i as u32)) == Some(Way::MayGrant);
            let mut puts = c.ops.iter().enumerate().filter(|(_, o)| o.target == a.tid && o.edge.is_some()).peekable();
            if puts.peek().is_some() && puts.all(|(i, _)| grant(i)) {
                return true;
            }
        }
        // a point query over what is held, the commit itself held yet or not: a commit is judged
        // as it applies, before the walk takes it
        let c = self.readings.entry(*id).or_insert_with(|| read(core, id, h, view, false).deltas());
        matches!(core.timelines().judge(c, ai as u32), Some(Content::Valid(_)))
    }
}

/// Re-judges the held deltas whose validity may have changed since the last call: those on the
/// things whose timeline changed (`Core::stale_things`, filled by `update_timelines`: the things
/// of components evaluated anew, and below what a continued walk touched), the commits whose
/// other inputs changed (`stale_commits`: void, required roles, overreach), every one after a
/// rebuild at open (`stale_all`); so the cost follows the change, not the held set. Rebuilds
/// aspects whose validity flipped; returns them. Again while a rebuild left some stale (a part
/// `retention::uncover` made missing loses what its body judged, the role it required among
/// them: perm's timelines read it anew). Ends: only `uncover` marks stale here, and it turns
/// parts dropped as covered missing, never back.
pub(crate) fn rejudge_all(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    let _s = osis_base::costs::span("rejudge");
    let mut out: BTreeSet<(Tid, Ak)> = BTreeSet::new();
    loop {
        super::paths::refresh(tx);
        out.extend(rejudge_once(tx, rebuild)?);
        if !tx.core.stale() {
            return Ok(out.into_iter().collect());
        }
    }
}

/// The first held commit whose flags differ from what judging it now gives (decodes every
/// header): what was not re-judged has not changed. Debug builds check it at the end of an
/// engine's history (`Engine::checked_verdicts`) and after an open from the persisted index
/// (every input of a judgment that comes from a body is persisted with the flag,
/// `index::meta_row`).
pub(crate) fn misjudged(core: &Core) -> Option<String> {
    core.ix.commits.iter().find_map(|(id, m)| misjudged_one(core, id, m))
}

/// `misjudged` of the commits with a part on `things` alone (debug builds, after each re-judge:
/// those on the things whose inputs it took, so a verdict wrong only for a while is caught at the
/// transaction it went wrong in, at the cost of the re-judge itself).
#[cfg(debug_assertions)]
fn misjudged_on<'a>(core: &Core, things: impl Iterator<Item = &'a Tid>) -> Option<String> {
    // a commit marked stale since (`setting_moved`) is judged by the next pass
    let ids: BTreeSet<CommitId> = things.flat_map(|t| core.on_thing(t)).filter(|c| !core.stale_commits.contains(c)).collect();
    ids.iter().find_map(|id| core.ix.commits.get(id).and_then(|m| misjudged_one(core, id, m)))
}

fn misjudged_one(core: &Core, id: &CommitId, m: &Meta) -> Option<String> {
    let h = &m.header;
    // the stored key verdict is what judging the header now gives (`Core::rekey`)
    let wrong = core.wrong_keys(h);
    if let Some(a) = h.aspects.iter().find(|a| core.ix.miskeyed.contains(&(*id, a.tid)) != wrong.contains(&a.tid)) {
        return Some(format!("delete keys of {id:?} ({:?} by {}) on {}: held as {}, {}", h.kind, h.signer, a.tid, if wrong.contains(&a.tid) { "right" } else { "wrong" }, core.explain_keys(h)));
    }
    let now = parts_valid(core, h, &m.view, id);
    (now != m.valid()).then(|| {
        let parts: Vec<_> = h.aspects.iter().zip(m.valid().iter().zip(&now)).filter(|(_, (a, b))| a != b).map(|(x, (a, _))| (x.tid, x.ak.as_str(), *a)).collect();
        format!("validity of {id:?} ({:?} by {}): {parts:?}", h.kind, h.signer)
    })
}

/// One pass of `rejudge_all`.
fn rejudge_once(tx: &mut Tx<'_>, rebuild: bool) -> Result<Vec<(Tid, Ak)>> {
    // the keys held as wrong are checked again where what the check reads may have moved besides
    // the steps (`Core::steps_recorded`): a record on a chain (the things judged again); every key
    // on a thing whose chain became known (`Indexes::keys_due`)
    let due: Vec<Tid> = tx.core.ix.keys_due.iter().copied().collect();
    for t in &due {
        tx.core.ix.keys_due.remove(t);
    }
    let rekey: BTreeSet<CommitId> = tx.core.ix.miskeyed.iter().filter(|(_, t)| tx.core.stale_things.contains(t)).map(|(c, _)| *c).chain(due.iter().flat_map(|t| tx.core.on_thing(t))).collect();
    for c in rekey {
        tx.core.rekey(&c);
    }
    resolve_unresolved(tx)?;
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
    // every commit whose judged inputs moved is read by the walk as now: each input of `reading`
    // touches where it moves (debug builds; once per pass, so the check costs what moved)
    #[cfg(debug_assertions)]
    {
        let behind = tx.core.walk_behind(tx.core.stale_commits.iter());
        debug_assert!(behind.is_none(), "the walk reads behind an input of {behind:?}");
    }
    let explicit = std::mem::take(&mut tx.core.stale_commits);
    let all = std::mem::take(&mut tx.core.stale_all);
    // an addendum's validity may change with its author's role or its commit's void flag, and
    // with it every part it vouches for: such a thing is judged whole
    let has_addenda = |t: &Tid| tx.core.ix.addenda.range((*t, CommitId([0; 32]))..=(*t, CommitId([0xff; 32]))).next().is_some();
    things.extend(under.iter().filter(|t| has_addenda(t)).copied());
    things.extend(explicit.iter().filter_map(|c| tx.core.ix.commits.get(c)).flat_map(|m| m.view.aspects.iter().filter(|a| ct::is_addenda(a.ak.as_str())).map(|a| a.tid)));
    // the commits whose author's role may have moved on a thing they write
    let authored: BTreeSet<CommitId> = tx.core.authored_under(&under, &authors).collect();
    // re-judged whole: those named
    let whole = explicit;
    let judge = osis_base::costs::span("rejudge: judge");
    // verdicts first (the core read only), each held commit once: by thing, a commit under the
    // first re-judged thing among its aspects; then the commits re-judged whole
    let mut news: Vec<(CommitId, Vec<bool>)> = Vec::new();
    // a missing part judged again and still invalid may be judgeable now (a record come): it
    // drops if judged invalid (`retention::drop_invalid`)
    let mut missing_due: Vec<CommitId> = Vec::new();
    {
        let core: &Core = tx.core;
        let mut judge = Judge::new(core);
        let mut one = |id: &CommitId, m: &Meta, whole: bool| {
            drop(osis_base::costs::span("rejudge: a commit"));
            let mut now: Option<Vec<bool>> = None;
            for (ai, a) in m.header.aspects.iter().enumerate() {
                // parts on things not re-judged keep their flag
                if !(whole || things.contains(&a.tid) || under.contains(&a.tid) && authors.contains(&m.view.signer)) {
                    continue;
                }
                let v = judge.part(&m.header, &m.view, id, ai);
                let old = m.valid_at(ai);
                if !v && !old && m.missing(ai) {
                    missing_due.push(*id);
                }
                if v != old {
                    let n = now.get_or_insert_with(|| m.valid().to_vec());
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
    let me = tx.core.me();
    let mut own_fell: Vec<(CommitId, Vec<Tid>)> = Vec::new();
    // parts dropped while invalid that turn valid: missing again, fetched
    let mut back: Vec<(CommitId, usize)> = Vec::new();
    let mut fresh = false;
    let current = tx.core.current_sessions();
    let mut falls: Vec<(Tid, Ak)> = Vec::new();
    for (id, now) in news {
        let Some(m) = tx.core.ix.commits.get(&id) else { continue };
        let h = m.header.clone();
        if h.signer == me && h.kind.has_own_writes() && m.valid().iter().zip(&now).any(|(a, b)| *a && !*b) {
            own_fell.push((id, h.aspects.iter().map(|a| a.tid).collect::<BTreeSet<_>>().into_iter().collect()));
            fresh |= matches!(h.form, osis_commit::Form::Session(n) if current.contains(&n));
        }
        for (ai, (a, b)) in m.valid().iter().zip(&now).enumerate() {
            if a != b
                && let Some(x) = h.aspects.get(ai)
            {
                flipped.insert((x.tid, x.ak.clone()));
                tx.core.compaction.weigh((x.tid, x.ak.clone()));
                // a memory snapshot's covered bodies were forgotten: a fresh one is written
                // (`memory::resnapshot_fallen`)
                if *a && m.view.kind.is_compaction() && m.view.memory {
                    tx.core.fallen.insert((x.tid, x.ak.clone()));
                }
                if *b {
                    rose.insert((x.tid, x.ak.clone()));
                    if crate::flows::inbox::carries(x.ak.as_str()) {
                        tx.core.ix.fires_due.insert(id);
                    }
                    if m.dropped_invalid(ai) {
                        back.push((id, ai));
                    }
                } else {
                    fell.entry((x.tid, x.ak.clone())).or_default().push((id, ai));
                    // a held part's fall: one missing here (a release's) marks nothing
                    if m.holds(ai) {
                        falls.push((x.tid, x.ak.clone()));
                    }
                }
                if x.ak.as_str() == "secrets.0" {
                    secrets_flips.push((id, ai, *b));
                }
                if x.ak.as_str() == "keys.0" {
                    keyset_flips.insert(x.tid);
                }
            }
        }
        tx.core.ix.commits.update(&id, |m| m.set_valid(now));
        tx.core.index_validity(&id);
    }
    drop(judge);
    tx.core.drop_due.extend(missing_due);
    for (t, ak) in falls {
        crate::sync::falls::fell(tx, &t, &ak)?;
    }
    // an own write of the current sessions fell: later writes go under fresh ones, past the hole
    // (`Core::fresh_session`)
    if fresh {
        tx.core.fresh_session();
    }
    for (id, tids) in own_fell {
        tx.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::OwnWriteInvalid, tids, commit: Some(id), peer: None, detail: "a write of this node turned invalid".into() }, tx.core.hlc.mono());
    }
    // on the things whose inputs moved, what was not re-judged has not changed (the whole held
    // set: at the end of the history)
    #[cfg(debug_assertions)]
    {
        let d = misjudged_on(tx.core, things.iter().chain(&under));
        debug_assert!(d.is_none(), "{} changed outside the re-judged set", d.unwrap_or_default());
    }
    // what its body judged goes with it (`reopen`): judged again by the next pass
    crate::retention::valid_again(tx, &back)?;
    // each aspect rebuilt once, after its flips and every purge request's verdict on it (a
    // requester's flip moves all its requests: one rebuild per request read the aspect's bodies
    // once each). Nothing in it reads a state (`run_batched`): what does runs after.
    super::run_batched(tx, |tx| {
        if rebuild {
            for (tid, ak) in &flipped {
                // a memory aspect's rebuild is memory work, whatever transaction re-judges it
                let memory = ak.ephemeral();
                tx.in_class(memory, |tx| {
                    let k = (*tid, ak.clone());
                    // a snapshot turned invalid gives nothing (its writer no longer vouches for it,
                    // spec/permissions.md §5.2): parts dropped under its cover alone are missing again
                    // (an own replace likewise, spec/commits.md §5 Own replaces)
                    let snaps = fell.get(&k).into_iter().flatten().any(|(c, _)| tx.core.ix.commits.get(c).is_some_and(|m| m.view.kind.is_compaction() || (0..m.parts()).any(|ai| m.whole(ai))));
                    let _s = osis_base::costs::span("rejudge: rebuild");
                    if snaps {
                        crate::retention::uncover(tx, tid, ak)?;
                    }
                    // the one path (issues/drop-rejoin-robust.md item 1): the aspect rebuilt from
                    // what is held
                    super::atomic::rebuild(tx, tid, ak)
                })?;
            }
            // a request's right rests on its signers' roles as a write's validity does
            // (spec/permissions.md §6): the requests among the commits re-judged
            for (tid, ak) in crate::retention::purged_aspects(tx, &things, authored.iter().chain(&whole))? {
                crate::retention::rejudge_purges(tx, &tid, &ak, &mut flipped)?;
            }
        }
        Ok(())
    })?;
    // memory parts turned valid may supersede held ones (spec/sync-compaction.md §2): after the rebuilds,
    // as a cover's keep bound reads the state (`bounds::part_keep`)
    let memory: BTreeSet<(Tid, Ak)> = if rebuild { rose.iter().filter(|(_, a)| a.ephemeral()).cloned().collect() } else { BTreeSet::new() };
    if !memory.is_empty() {
        let gone = tx.in_class(true, |tx| {
            let gone = crate::retention::memory::drop_superseded(tx, &memory)?;
            // and snapshots turned valid cover held bodies
            crate::retention::memory::drop_covered(tx, &memory, None, None)?;
            Ok(gone)
        })?;
        flipped.extend(gone);
    }
    // after the rebuilds: a keyset or secrets flip reads its aspect's state
    super::keys::rebuild_keysets(tx, &keyset_flips)?;
    super::keys::refresh_independent(tx, &keyset_flips, true)?;
    for (c, ai, now_valid) in secrets_flips {
        if now_valid {
            super::keys::revalidated(tx, &c, ai)?;
        } else {
            super::keys::invalidated(tx, &c, ai)?;
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
    let Some(tl) = core.timelines().get(target) else { return false };
    if tl.role(author, holder, At::now(ts)) != Some(Role::Admin) {
        return false;
    }
    let edges = tl.edges_at(None);
    let view = osis_perm::graph::View::at(&edges, Some(ts)).patched(*holder, *target, None);
    view.roles_from(author).get(target).copied() != Some(Role::Admin)
}

/// The edge writes of a role commit's parts `(thing, ak, fragment)`, each `(target, holder, new
/// edge)` once (`None`: removed): a change is a reset and a put of one entry, the put the
/// holder's new edge.
pub(crate) fn edge_writes<'f>(core: &Core, parts: impl IntoIterator<Item = (Tid, &'f Ak, &'f Fragment)>) -> Vec<(Tid, Holder, Option<Edge>)> {
    let mut changed: Vec<(Tid, Holder, Option<Edge>)> = Vec::new();
    for (t, ak, f) in parts {
        let Some(g) = Grants::of(ak.as_str()) else { continue };
        for (dot, k, frag) in entries(f) {
            match k.as_ref().and_then(|k| g.holder(k)) {
                Some(m) => changed.push((t, m, frag.and_then(|f| f.read()).as_ref().and_then(edge_of))),
                None => {
                    if let Some(m) = core.ix.holder_keys.get(&(t, g, dot)) {
                        changed.push((t, *m, None));
                    }
                }
            }
        }
    }
    // a change is remove + put of one entry: the put is the holder's new edge
    let mut net: BTreeMap<(Tid, Holder), Option<Edge>> = BTreeMap::new();
    for (t, m, e) in changed {
        let slot = net.entry((t, m)).or_insert(None);
        if e.is_some() {
            *slot = e;
        }
    }
    net.into_iter().map(|((t, m), e)| (t, m, e)).collect()
}

/// Whether edge writes `writes` (holder, new edge) on `t` would leave it, holding a standing
/// admin now, with none (spec/permissions.md §1, The last admin): a standing admin is an admin
/// edge on `t` with no `until`, its record edge included while it stands, as this node's walk
/// has them. Reads `t`'s own edges alone: an audit a write makes drops none of the writes its
/// writer holds (its frontier lists them, `Engine::demotion_frontier`), so it leaves no other
/// thing so at the writer.
pub(crate) fn leaves_no_admin(core: &Core, t: &Tid, writes: &[(Holder, Option<Edge>)]) -> bool {
    let standing = |e: &Edge| e.role == Role::Admin && e.until.is_none();
    // the things' grants and the keys' (a key's grant is a standing admin as any: §1)
    let mut now: Vec<(Holder, Edge)> = match core.timelines().on(t) {
        Some(on) => on.holders().into_iter().map(|(m, e)| (Holder::Thing(m), e)).collect(),
        None => core.mint_admin(t).map(|a| (Holder::Thing(a), Edge::new(Role::Admin))).into_iter().collect(),
    };
    now.extend(core.timelines().key_grants(t, None).into_iter().map(|(k, e)| (Holder::Key(k), e)));
    let lowered = |m: &Holder| writes.iter().find(|(x, _)| x == m).map(|(_, e)| *e);
    let after = now.iter().filter_map(|(m, e)| lowered(m).unwrap_or(Some(*e))).chain(writes.iter().filter_map(|(_, e)| *e));
    now.iter().any(|(_, e)| standing(e)) && !after.into_iter().any(|e| standing(&e))
}

/// The first thing edge writes `changed` leave with no standing admin (`leaves_no_admin`).
fn left_adminless(core: &Core, changed: &[(Tid, Holder, Option<Edge>)]) -> Option<Tid> {
    let targets: BTreeSet<Tid> = changed.iter().map(|c| c.0).collect();
    targets.into_iter().find(|t| {
        let writes: Vec<(Holder, Option<Edge>)> = changed.iter().filter(|c| c.0 == *t).map(|c| (c.1, c.2)).collect();
        leaves_no_admin(core, t, &writes)
    })
}

/// Whether a role commit with parts `parts` would leave a thing with no standing admin: the
/// commit the adminless mark goes on (`Engine::leaving_adminless`), and no other.
pub(crate) fn needs_adminless_mark<'f>(core: &Core, parts: impl IntoIterator<Item = (Tid, &'f Ak, &'f Fragment)>) -> bool {
    left_adminless(core, &edge_writes(core, parts)).is_some()
}

/// Rules of a role commit that need its deltas
/// (spec/commits.md §2, spec/wire.md §4 position 12).
pub(crate) fn check_content_rules(core: &Core, h: &Header, parts: &[(usize, Decoded)]) -> Result<()> {
    if h.kind != Kind::Role {
        return Ok(());
    }
    let changed = edge_writes(core, parts.iter().filter_map(|(ai, d)| h.aspects.get(*ai).map(|a| (a.tid, &a.ak, d.fragment()))));
    // the last admin (spec/permissions.md §1): the adminless mark says it is meant
    if !h.adminless && let Some(t) = left_adminless(core, &changed) {
        return Err(Error::LeavesNoAdmin(t));
    }
    // the key it is signed by (`apply::commit_key`): a write on that key's grant on its signer is
    // the key's self-removal
    let key = h.key.or_else(|| core.created(&h.signer).and_then(CreationRecord::key));
    let me = Holder::Thing(h.signer);
    let selfr = |target: &Tid, m: &Holder| match m {
        Holder::Thing(m) => self_removal(core, &h.signer, target, m, h.ts),
        Holder::Key(k) => Some(*k) == key && *target == h.signer,
    };
    let mut holders: Vec<(Tid, Holder)> = changed.iter().map(|c| (c.0, c.1)).collect();
    holders.sort();
    holders.dedup();
    if holders.len() > 1 {
        // the one exception for edge writes in a plain role commit: a single-use
        // redemption (a grant plus the author key's own self-removal, both on K,
        // spec/permissions.md §7, spec/commits.md §2)
        let redemption = holders.len() == 2 && holders.first().map(|m| m.0) == holders.last().map(|m| m.0) && changed.iter().any(|c| c.1 == me && c.2.is_none()) && changed.iter().any(|c| c.1 != me && c.2.is_some());
        // or a removal of several others' edges on one target under one rotation (a link joiner
        // with the link key, under one frontier; a finalize of several ended edges): no edge of
        // it a self-removal, each gone or saying retain
        let first = holders.first().map(|m| m.0);
        let removal = changed.iter().all(|c| Some(c.0) == first && c.1 != me && c.2.is_none_or(|e| e.says_retain()) && !selfr(&c.0, &c.1));
        if !redemption && !removal {
            return Err(Error::BadInput("a role commit changes more than one edge"));
        }
    }
    // a frontier rides on an explicit write that audits (spec/permissions.md §5.1 step 4): one
    // below the edge as restored, a removal (of an absent edge too, §2) included
    let audits = changed.iter().any(|(target, m, new)| new.is_none() || core.timelines().get(target).is_some_and(|tl| tl.audits(m, target, *new, h.ts)));
    if h.frontier.is_some() && !audits && !changed.is_empty() {
        return Err(Error::BadInput("a frontier on a commit that audits nothing"));
    }
    // a removal of another's edge with no frontier is a finalize (spec/permissions.md §2): of
    // an edge not past its `until` it would apply nothing, so a revoke written so would cut off
    // nobody. Any other explicit write that audits carries one: without, every write of the
    // holder's it puts in question drops, received or not
    if h.frontier.is_none() {
        for (target, m, new) in &changed {
            let Some(tl) = core.timelines().get(target) else { continue };
            let old = match m {
                Holder::Thing(m) => tl.edges_at(None).get(m, target).copied(),
                Holder::Key(k) => tl.key_grant(k, target),
            };
            let selfr = selfr(target, m);
            let removes = *m != me && new.as_ref().is_none_or(|e| e.says_retain()) && !selfr;
            if removes && old.is_some_and(|o| o.until.is_none() || o.alive_at(Some(h.ts))) {
                return Err(Error::BadInput("a removal with no frontier of an edge not past its until"));
            }
            let explicit = !selfr && tl.role(&h.signer, target, At::now(h.ts)) == Some(Role::Admin);
            if explicit && new.is_some_and(|e| !e.says_retain()) && tl.audits(m, target, *new, h.ts) {
                return Err(Error::BadInput("an explicit write that audits with no frontier"));
            }
        }
    }
    Ok(())
}
