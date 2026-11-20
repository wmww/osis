//! Held commits as the walk's input (`osis_perm::paths::Commit`): one definition, read off what
//! the engine holds of a commit (its header, which parts are held, perm's held reading of its
//! edge writes and vouches), so a live apply, late parts (`join_late`), a dropped or forgotten
//! part, a released or lost thing and an open all give the walk the same input for the same held
//! commit. The walk is told a commit's input changed by `Paths::update` (`forget` where it has
//! none left, `add` where it is new).
//!
//! Parts, in this order (a part's index is its `WriteId` index):
//! - a role commit's edge writes, as perm's held set reads them (`Held::edge_commit`: an op's
//!   index in the commit's `RoleCommit` is its index here, so today's walk and the new one name an
//!   edge write by the same `WriteId`), each along the path its commit states for the target;
//! - its vouch entries (`Held::vouches_of`: entries its delta creates), along the path to the
//!   vouch's thing;
//! - every other held part (`Meta::holds`) as a delta: a role commit's other role-class parts
//!   (`RoleClass`, needing the role their aspect requires: `rotation_role`, else
//!   `write::required_role`), a content commit's parts (`Plain`), an `addenda.0` part one
//!   `Addendum` per entry its body creates (`Indexes::addenda`; held or not, its body dropped it
//!   lists nothing: `Plain`).
//!
//! Not given to the walk (notes/perm-paths.md, The switch, who judges each): `created.0` (always
//! valid), a commit that does not count by the epoch rule (`Core::standing`: judged by nothing
//! below it), a thing of a split commit whose path has not opened here (no parts until
//! it opens: `View::paths`), compaction snapshots and purge requests (their classes are owed:
//! notes/perm-paths.md, The switch).

use crate::engine::Core;
use osis_base::{CommitId, PurgeBy, Tid};
use osis_commit::{Header, Kind, Paths as Stated, ThingPath};
use osis_perm::paths::{Commit, Delta, DeltaClass, EdgeWrite, Part, PartKind};
use osis_perm::WriteId;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// What a part of an adapted commit is, in the engine's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// An edge write: its op's index in perm's held `RoleCommit` (today's `WriteId` index).
    Edge(u32),
    /// A vouch entry on its thing.
    Vouch,
    /// A delta: its aspect index in the header.
    Delta(usize),
}

/// A held commit as the walk reads it.
#[derive(Clone, Debug)]
pub struct Input {
    pub commit: Commit,
    /// Per part, what it is.
    pub origins: Vec<Origin>,
}

impl Input {
    /// Whether `self` and `o` give the walk the same input (`Paths::update` only where not).
    pub fn same(&self, o: &Input) -> bool {
        let (a, b) = (&self.commit, &o.commit);
        self.origins == o.origins && a.id == b.id && a.ts == b.ts && a.signer == b.signer && a.parts.len() == b.parts.len() && a.parts.iter().zip(&b.parts).all(|(x, y)| same_part(x, y))
    }
}

fn same_part(x: &Part, y: &Part) -> bool {
    x.on == y.on
        && x.path == y.path
        && x.direct == y.direct
        && match (&x.kind, &y.kind) {
            (PartKind::Edge(a), PartKind::Edge(b)) => a.holder == b.holder && a.value == b.value && a.frontier == b.frontier && a.remains == b.remains && a.adminless == b.adminless,
            (PartKind::Vouch { removal: r, list: l }, PartKind::Vouch { removal: s, list: m }) => r == s && l == m,
            (PartKind::Delta(a), PartKind::Delta(b)) => {
                a.aspect == b.aspect
                    && a.needs == b.needs
                    && a.purge_author == b.purge_author
                    && a.retention == b.retention
                    && match (&a.class, &b.class) {
                        (DeltaClass::Plain, DeltaClass::Plain) | (DeltaClass::RoleClass, DeltaClass::RoleClass) => true,
                        (DeltaClass::Addendum { removal: r, list: l }, DeltaClass::Addendum { removal: s, list: m }) => r == s && l == m,
                        _ => false,
                    }
            }
            _ => false,
        }
}

/// The path commit `h` states for thing `t` ([A1..Ak]), its purge author's index into
/// [signer, A1..Ak] (past the path where the author is not on it: the walk judges such a part
/// invalid) and the hops it marks direct (a clear path's marks on every thing's part, a split
/// entry's own). `None` where the path is not known here: a split commit's entry not opened, or
/// bad.
pub(crate) fn path_of(core: &Core, h: &Header, decided: Option<&BTreeMap<Tid, bool>>, t: &Tid) -> Option<(Vec<Tid>, u32, osis_base::format::PathMarks)> {
    let (listed, author, direct) = match &h.path {
        Stated::One(p) => (p.to(t).to_vec(), p.purge_author(h.signer), p.direct),
        Stated::Split(_) => {
            if decided.and_then(|d| d.get(t)) != Some(&true) {
                return None;
            }
            let i = h.things().iter().position(|x| x == t)?;
            let ThingPath::Known(p) = crate::apply::paths::open(core, h, None, i, t)? else { return None };
            (p.to(t).to_vec(), h.purge_author(), p.direct)
        }
    };
    let index = std::iter::once(h.signer).chain(listed.iter().copied()).position(|x| x == author).unwrap_or(listed.len() + 1);
    Some((listed, u32::try_from(index).unwrap_or(u32::MAX), direct))
}

/// Held commit `id` as the walk reads it; `None` where the walk reads nothing of it.
pub fn commit(core: &Core, id: &CommitId) -> Option<Input> {
    let m = core.ix.commits.get(id)?;
    let v = m.view.clone();
    // the epoch rule filters before the walk (spec/permissions.md §5.5): an account's commit
    // that does not count is judged by nothing below it
    if !matches!(v.kind, Kind::Role | Kind::Content) || core.ix.held.is_uncounted(id) || core.standing(id, &v) != osis_perm::EpochStanding::Counts {
        return None;
    }
    let h = m.header.decoded()?;
    let decided = v.paths.as_deref();
    let mut paths: BTreeMap<Tid, Option<(Vec<Tid>, u32, osis_base::format::PathMarks)>> = BTreeMap::new();
    let mut path = |t: &Tid| paths.entry(*t).or_insert_with(|| path_of(core, &h, decided, t)).clone();
    let mut parts = Vec::new();
    let mut origins = Vec::new();
    if v.kind == Kind::Role {
        if let Some(rc) = core.ix.held.edge_commit(id) {
            for (i, op) in (0u32..).zip(&rc.ops) {
                // a role commit states one path in the clear: every op has one
                let (p, _, direct) = path(&op.target)?;
                parts.push(Part { on: op.target, path: p, direct, kind: PartKind::Edge(EdgeWrite { holder: op.holder, value: op.edge, frontier: rc.frontier.clone(), remains: h.remains, adminless: h.adminless }) });
                origins.push(Origin::Edge(i));
            }
        }
        for vouch in core.ix.held.vouches_of(id) {
            let Some((p, _, direct)) = path(&vouch.thing) else { continue };
            for (r, list) in &vouch.entries {
                parts.push(Part { on: vouch.thing, path: p.clone(), direct, kind: PartKind::Vouch { removal: *r, list: (**list).clone() } });
                origins.push(Origin::Vouch);
            }
        }
    }
    for (ai, a) in v.aspects.iter().enumerate() {
        let ak = a.ak.as_str();
        if ak == "created.0" || ak == "roles.0" || ak == ct::VOUCHES_AK {
            continue;
        }
        // an addendum is its signer's write whether its body is held or not; its entries are those
        // its held body creates (`Indexes::addenda`)
        let addendum = (v.kind == Kind::Content && ct::is_addenda(ak)).then(|| core.ix.addenda.get(&(a.tid, *id)).cloned()).flatten();
        if addendum.is_none() && !m.holds(ai) {
            continue;
        }
        let Some((p, purge_author, direct)) = path(&a.tid) else { continue };
        if let Some(ad) = addendum.filter(|ad| !ad.entries.is_empty()) {
            for (r, list) in &ad.entries {
                let class = DeltaClass::Addendum { removal: *r, list: osis_perm::Frontier::new(list.iter().copied()) };
                parts.push(Part { on: a.tid, path: p.clone(), direct, kind: PartKind::Delta(Delta { aspect: a.ak.clone(), needs: crate::engine::write::required_role(ak), purge_author, retention: PurgeBy::Admin, class }) });
                origins.push(Origin::Delta(ai));
            }
            continue;
        }
        let role = v.kind == Kind::Role && ct::is_role_class(ak);
        let needs = if role { core.ix.rotation_role.get(&(*id, ai)).copied().unwrap_or_else(|| crate::engine::write::required_role(ak)) } else { crate::engine::write::required_role(ak) };
        let class = if role { DeltaClass::RoleClass } else { DeltaClass::Plain };
        parts.push(Part { on: a.tid, path: p, direct, kind: PartKind::Delta(Delta { aspect: a.ak.clone(), needs, purge_author, retention: PurgeBy::Admin, class }) });
        origins.push(Origin::Delta(ai));
    }
    if parts.is_empty() {
        return None;
    }
    Some(Input { commit: Commit { id: *id, ts: v.ts, signer: v.signer, parts }, origins })
}

/// Every held commit the walk reads, by ID.
pub fn all(core: &Core) -> BTreeMap<CommitId, Input> {
    core.ix.commits.keys().filter_map(|id| Some((*id, commit(core, id)?))).collect()
}

/// The records the walk reads (thing to mint admin): every held creation record naming one.
pub fn records(core: &Core) -> BTreeMap<Tid, Tid> {
    core.ix.held.things().filter_map(|t| Some((*t, core.ix.held.created(t)?.mint_admin()?))).collect()
}

/// The trust set as the draft allows it (notes/a1-spec/permissions.md §5.1 Trust set): of the
/// edge writes this node sides with (`sides`), those carrying a frontier and setting the edge of
/// a holder other than their signer and their target, as the walk names them (`inputs`).
pub fn trust(core: &Core, inputs: &BTreeMap<CommitId, Input>) -> BTreeSet<WriteId> {
    let mut out = BTreeSet::new();
    for w in core.sides.trust().ops {
        let Some(input) = inputs.get(&w.0) else { continue };
        let Some(ix) = input.origins.iter().position(|o| *o == Origin::Edge(w.1)) else { continue };
        let Some(part) = input.commit.parts.get(ix) else { continue };
        if let PartKind::Edge(e) = &part.kind
            && e.frontier.is_some()
            && e.holder != input.commit.signer
            && e.holder != part.on
        {
            out.insert(WriteId(w.0, u32::try_from(ix).unwrap_or(u32::MAX)));
        }
    }
    out
}

