//! Writes (notes/api.md Writes): a `Write` batch becomes one atomic commit over every touched
//! thing, of any size. `set` makes a value equal (structural diff, spec/crdt.md §9), `edit`
//! writes only what changed between what the app showed and what the user produced, `replace`
//! resets then writes, path ops change one position. Rights are checked locally before signing.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::read::ak_of;
use osis_commit::PurgeItem;
use osis_base::{CommitId, Tid, Ts, Value, WallMs};
use osis_crdt::{AnyView, Op, PathOp, PathSeg, diff_values};
use osis_node::Mutation;
use osis_schema::core_types::{GROUP, is_membership_class};
use osis_schema::{AspectKey, CaseId, Codec, Path, Retention, Step, type_at, validate_write};
use std::collections::BTreeMap;
use std::ops::Range;
use std::time::Duration;

/// Where a new thing syncs (notes/api.md: explicit, no default).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// An item of this group.
    In(Tid),
    /// An item of each of these groups.
    InAll(Vec<Tid>),
    /// Device-local, or a group that will be synced itself.
    Unsynced,
}

/// A committed write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    pub commit: CommitId,
    pub ts: Ts,
}

/// A batch of writes that becomes one commit. Reads see committed state only.
#[must_use = "a Write does nothing until commit()"]
pub struct Write<'d> {
    db: &'d Osis,
    m: Mutation,
    actor: Tid,
    created: Vec<Tid>,
    /// Things placed into groups by this batch (the `NotSynced` check).
    placed: Vec<Tid>,
    /// Per group whose `/group` this batch writes through the group calls: the expiry those
    /// writes asked for. Expiry is per aspect write, so one batch cannot mix them.
    group_exp: BTreeMap<Tid, Option<Duration>>,
}

impl Osis {
    /// A new write batch acting as `me()`.
    pub fn write(&self) -> Write<'_> {
        Write { db: self, m: Mutation::new(), actor: self.me(), created: Vec::new(), placed: Vec::new(), group_exp: BTreeMap::new() }
    }

    /// Runs `f` on a new batch and commits it if `f` succeeds; returns what `f` returned (the
    /// commit itself: `write()` and `commit()`).
    pub fn write_with<R>(&self, f: impl FnOnce(&mut Write<'_>) -> Result<R>) -> Result<R> {
        let mut w = self.write();
        let r = f(&mut w)?;
        w.commit()?;
        Ok(r)
    }
}

/// Synthetic aspects and `/created`: never written by ops.
fn read_only(ak: &str) -> bool {
    matches!(ak, "/tid" | "/aspects" | "/groups" | "/created")
}

pub(crate) fn segs(p: &Path) -> Result<Vec<PathSeg>> {
    p.0.iter()
        .map(|s| match s {
            Step::Field(id) => Ok(PathSeg::Field(*id)),
            Step::Case(id) => Ok(PathSeg::Case(*id)),
            Step::Key(k) => Ok(PathSeg::Key(k.clone())),
            Step::Index(i) => Ok(PathSeg::Index(*i)),
            Step::Elem(_) => Err(Error::Invalid("a set element is atomic: no path into it".into())),
        })
        .collect()
}

fn group_op(items: bool, member: Tid, add: bool) -> PathOp {
    let v = Value::Tid(member);
    let f = if items { crate::core::group::ITEMS } else { crate::core::group::SUBGROUPS };
    PathOp { path: vec![PathSeg::Field(f.0)], op: if add { Op::Add(v) } else { Op::Remove(v) } }
}

/// The wall time `d` from now; `Invalid` for a zero duration (an expiry must be in the future).
fn expiry_in(db: &Osis, d: Duration) -> Result<WallMs> {
    let ms = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    if ms == 0 {
        return Err(Error::Invalid("expiry 0 ms is not in the future".into()));
    }
    Ok(WallMs(db.now().0.saturating_add(ms)))
}

impl<'d> Write<'d> {
    /// Acts for `actor` instead of `me()` (header actor; this node needs its rights).
    pub fn act_as(&mut self, actor: Tid) -> &mut Self {
        self.actor = actor;
        self
    }

    fn resolve(&self, t: Tid) -> Tid {
        if self.created.contains(&t) { t } else { self.db.read(|r| r.resolve(t)) }
    }

    fn known(&self, t: Tid) -> Result<Tid> {
        let t = self.resolve(t);
        if self.created.contains(&t) || self.db.knows(t) { Ok(t) } else { Err(Error::UnknownThing { tid: t }) }
    }

    /// A new thing owned by `owner` (fixed forever; needs write on it), placed per `place`.
    pub fn create(&mut self, owner: Tid, place: Place) -> Result<Tid> {
        self.create_expiring(owner, place, None)
    }

    /// `create` whose placements expire after `expires` (spec/commits.md §6; `None`: never), as
    /// `place_expiring` does: a disappearing item leaves its groups by itself.
    pub fn create_expiring(&mut self, owner: Tid, place: Place, expires: Option<Duration>) -> Result<Tid> {
        if let Some(d) = expires {
            expiry_in(self.db, d)?;
        }
        let owner = self.known(owner)?;
        let groups = match &place {
            Place::In(g) => vec![*g],
            Place::InAll(gs) => gs.clone(),
            Place::Unsynced => Vec::new(),
        };
        let groups = groups.into_iter().map(|g| self.known(g)).collect::<Result<Vec<_>>>()?;
        let m = &mut self.m;
        let t = self.db.engine(|e| e.new_thing(m, owner));
        self.created.push(t);
        for g in groups {
            self.place_expiring(t, g, expires)?;
        }
        Ok(t)
    }

    /// Gives `tid` an empty `/group` if it has none (a group thing).
    pub fn make_group(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        if !self.created.contains(&t) && self.db.get(t, GROUP)?.is_some() {
            return Ok(());
        }
        self.group_expiry(t, None)?;
        self.m.set(t, &GROUP, &osis_schema::core_types::Group::default())?;
        Ok(())
    }

    /// Records that this batch writes `g`'s `/group` with expiry `d`; `Invalid` when another
    /// write of it in this batch asked for a different one.
    fn group_expiry(&mut self, g: Tid, d: Option<Duration>) -> Result<()> {
        match self.group_exp.get(&g) {
            Some(x) if *x == d => return Ok(()),
            Some(_) => return Err(Error::Invalid(format!("this batch writes the groups of {g} with different expiries (expiry is per aspect write): use one batch each"))),
            None => {}
        }
        if let Some(d) = d {
            let t = expiry_in(self.db, d)?;
            self.m.expires(g, &GROUP, t)?;
        }
        self.group_exp.insert(g, d);
        Ok(())
    }

    fn group(&mut self, g: Tid, items: bool, member: Tid, add: bool, exp: Option<Duration>) -> Result<()> {
        let g = self.known(g)?;
        let member = self.resolve(member);
        self.group_expiry(g, exp)?;
        self.m.op(g, &GROUP, group_op(items, member, add))?;
        Ok(())
    }

    /// Adds `tid` to the items of group `g`. A thing whose groups then include no synced one
    /// gets a `NotSynced` diagnostic after commit.
    pub fn place(&mut self, tid: Tid, g: Tid) -> Result<()> {
        self.place_expiring(tid, g, None)
    }
    /// `place` whose placement expires after `expires` (`None`: never). Expiry is per aspect
    /// write, so every group call on `g` in this batch must ask for the same expiry (else
    /// `Invalid`).
    pub fn place_expiring(&mut self, tid: Tid, g: Tid, expires: Option<Duration>) -> Result<()> {
        let t = self.resolve(tid);
        self.group(g, true, tid, true, expires)?;
        self.placed.push(t);
        Ok(())
    }
    pub fn unplace(&mut self, tid: Tid, g: Tid) -> Result<()> {
        self.group(g, true, tid, false, None)
    }
    pub fn add_subgroup(&mut self, g: Tid, sub: Tid) -> Result<()> {
        self.group(g, false, sub, true, None)
    }
    pub fn remove_subgroup(&mut self, g: Tid, sub: Tid) -> Result<()> {
        self.group(g, false, sub, false, None)
    }

    /// Removes every aspect the node knows of `tid` and every known placement of it. The tid
    /// stays valid; a later write recreates the thing.
    pub fn delete(&mut self, tid: Tid) -> Result<()> {
        let t = self.known(tid)?;
        let aks = self.db.aspects(t)?;
        for ak in aks.iter().filter(|a| !read_only(a.as_str()) && !is_membership_class(a.as_str())) {
            self.m.remove_aspect(t, ak)?;
        }
        for g in self.db.groups_of(t) {
            if self.db.get(g, GROUP)?.is_some_and(|x| x.items.contains(&t)) {
                self.unplace(t, g)?;
            }
        }
        Ok(())
    }

    /// A raw path op through `key` (text sessions).
    pub(crate) fn raw_op(&mut self, tid: Tid, key: &crate::Key, op: PathOp) -> Result<()> {
        let t = self.known(tid)?;
        self.m.op(t, key, op)?;
        Ok(())
    }

    /// One aspect of a thing, for whole-value and path ops.
    pub fn at<K: AspectKey>(&mut self, tid: Tid, key: K) -> AspectWrite<'_, 'd, K> {
        let bad = match ak_of(&key) {
            Err(e) => Some(e),
            Ok(ak) if read_only(ak.as_str()) || is_membership_class(ak.as_str()) => Some(Error::Invalid(format!("{ak} is written only by the engine or the sharing calls"))),
            Ok(_) => None,
        };
        let tid = self.resolve(tid);
        AspectWrite { w: self, tid, key, bad }
    }

    /// Commits every op as one atomic commit; `None` when nothing changes. Fails before
    /// signing with `Permission` or `UnknownThing`.
    pub fn commit(mut self) -> Result<Option<Committed>> {
        self.m.act_as(self.actor);
        let m = std::mem::take(&mut self.m);
        let placed = std::mem::take(&mut self.placed);
        self.db.engine(|e| match e.commit(m)? {
            Some(id) => {
                not_synced(e, &placed);
                Ok(Some(Committed { commit: id, ts: e.header(&id).map(|h| h.ts).unwrap_or_default() }))
            }
            None => Ok(None),
        })
    }
}

/// Reports things placed only where no synced group holds them (spec/requirements.md, Offline
/// and network).
fn not_synced(e: &mut osis_node::Engine, placed: &[Tid]) {
    if placed.is_empty() {
        return;
    }
    let labeled = e.labeled_groups();
    for t in placed {
        if labeled.contains(t) || e.groups_of(t).iter().any(|g| labeled.contains(g)) {
            continue;
        }
        e.report(osis_node::Diagnostic { kind: osis_node::DiagnosticKind::NotSynced, tids: vec![*t], commit: None, peer: None, detail: "placed only in groups no synced group holds: it stays on this device".into() });
    }
}

/// Ops on one aspect inside a `Write`.
pub struct AspectWrite<'w, 'd, K> {
    w: &'w mut Write<'d>,
    tid: Tid,
    key: K,
    bad: Option<Error>,
}

impl<'w, 'd, K: AspectKey> AspectWrite<'w, 'd, K> {
    fn ok(&self) -> Result<()> {
        match &self.bad {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn op(&mut self, op: PathOp) -> Result<()> {
        self.ok()?;
        self.w.m.op(self.tid, &self.key, op)?;
        Ok(())
    }

    /// Makes the aspect read `v` (structural diff against the current state: a concurrent
    /// edit inside the value survives, but a field the app did not touch is written back if
    /// it differs from the current state). For "must be exactly this"; interactive edits use
    /// `edit`.
    pub fn set(&mut self, v: &K::T) -> Result<()> {
        self.ok()?;
        self.w.m.set(self.tid, &self.key, v)?;
        Ok(())
    }

    /// Writes only what differs between `base` (what the app showed) and `new` (what the user
    /// produced), as path ops against the current state: a remote change made meanwhile to
    /// anything the user did not touch is kept.
    pub fn edit(&mut self, base: &K::T, new: &K::T) -> Result<()> {
        self.ok()?;
        let (b, n) = (self.key.encode(base), self.key.encode(new));
        self.key.validate(&n)?;
        let ak = ak_of(&self.key)?;
        let ops = match self.key.schema().and_then(|s| s.view(ak.as_str())) {
            Some(v) => diff_values(Some(&b), &n, &v),
            None => diff_values(Some(&b), &n, &AnyView),
        }
        .map_err(|e| Error::Invalid(e.to_string()))?;
        for op in ops {
            self.op(op)?;
        }
        Ok(())
    }

    /// Resets the aspect, then writes `v` (discards concurrent edits inside it).
    pub fn replace(&mut self, v: &K::T) -> Result<()> {
        self.ok()?;
        self.w.m.replace(self.tid, &self.key, v)?;
        Ok(())
    }

    /// Removes the aspect.
    pub fn remove(&mut self) -> Result<()> {
        self.ok()?;
        self.w.m.remove_aspect(self.tid, &self.key)?;
        Ok(())
    }

    /// Counter increment (or max/min observation) at the root.
    pub fn inc<U: Codec>(&mut self, n: &U) -> Result<()> {
        self.path(Path::root()).inc(n)
    }

    /// Drops the aspect's whole history wherever the author may purge it (spec/commits.md §5,
    /// spec/permissions.md §8) and removes the aspect, in this commit.
    pub fn purge(&mut self) -> Result<()> {
        self.remove()?;
        let ak = ak_of(&self.key)?;
        self.w.m.purge(PurgeItem::Aspect { tid: self.tid, ak });
        Ok(())
    }

    /// This write's delta expires at `t` (spec/commits.md §6); default from the key.
    /// Fails the following op with `Invalid` when `t` is not in the future.
    pub fn expires_at(mut self, t: WallMs) -> Self {
        if self.bad.is_none() && t <= self.w.db.now() {
            self.bad = Some(Error::Invalid(format!("expiry {} ms is not in the future", t.0)));
        } else if self.bad.is_none()
            && let Err(e) = self.w.m.expires(self.tid, &self.key, t)
        {
            self.bad = Some(e.into());
        }
        self
    }

    /// This write's delta expires `d` from now.
    pub fn expires_in(self, d: Duration) -> Self {
        self.expires(Some(d))
    }

    /// `expires_in(d)` for `Some(d)`; `None` keeps the key's default.
    pub fn expires(mut self, d: Option<Duration>) -> Self {
        match d.map(|d| expiry_in(self.w.db, d)) {
            None => self,
            Some(Ok(t)) => self.expires_at(t),
            Some(Err(e)) => {
                self.bad.get_or_insert(e);
                self
            }
        }
    }

    /// Retention of this write's delta instead of the key's default (spec/commits.md §5);
    /// checked at commit (`Invalid`).
    pub fn retention(mut self, r: Retention) -> Self {
        if self.bad.is_none()
            && let Err(e) = self.w.m.retention(self.tid, &self.key, r)
        {
            self.bad = Some(e.into());
        }
        self
    }

    /// A position inside the value, for path ops. Index paths resolve at commit time.
    pub fn path(&mut self, p: Path) -> PathWrite<'_, 'w, 'd, K> {
        PathWrite { a: self, path: p }
    }
}

/// Ops at one position inside an aspect.
pub struct PathWrite<'a, 'w, 'd, K> {
    a: &'a mut AspectWrite<'w, 'd, K>,
    path: Path,
}

impl<K: AspectKey> PathWrite<'_, '_, '_, K> {
    fn at(&mut self, extra: Option<PathSeg>, op: Op) -> Result<()> {
        let mut path = segs(&self.path)?;
        path.extend(extra);
        self.a.op(PathOp { path, op })
    }

    /// Validates `v` against the writer's schema at the path (plus one step).
    fn check(&self, extra: Option<Step>, v: &Value) -> Result<()> {
        let (Some(s), Some(ty)) = (self.a.key.schema(), self.a.key.ty()) else { return Ok(()) };
        let mut p = self.path.clone();
        p.0.extend(extra);
        let (t, _) = type_at(s, ty, &p)?;
        validate_write(s, v, &t)?;
        Ok(())
    }

    fn checked<U: Codec>(&self, extra: Option<Step>, v: &U) -> Result<Value> {
        let v = v.to_value();
        self.check(extra, &v)?;
        Ok(v)
    }

    /// The key's schema type at this position (`None`: untyped).
    pub(crate) fn position_type(&self) -> Result<Option<osis_schema::Type>> {
        crate::large::type_of(&self.a.key, &self.path)
    }

    /// `set` of an untyped value, checked against the schema.
    pub(crate) fn set_value(&mut self, v: Value) -> Result<()> {
        self.check(None, &v)?;
        self.at(None, Op::Set(v))
    }

    /// Makes the position read `v` (structural diff).
    pub fn set<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Set(v))
    }

    /// Resets the position, then writes `v`.
    pub fn replace<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = self.checked(None, v)?;
        self.at(None, Op::Replace(v))
    }

    /// Removes the position: a map entry, a set element or a list element.
    pub fn remove(&mut self) -> Result<()> {
        let mut parent = self.path.clone();
        let last = parent.0.pop();
        let op = match last {
            Some(Step::Key(k)) => Op::Remove(k),
            Some(Step::Elem(e)) => Op::Remove(e),
            Some(Step::Index(i)) => Op::Delete { at: i, len: 1 },
            _ => return Err(Error::Invalid("only a map entry, set element or list element can be removed (remove() the aspect, or set the field)".into())),
        };
        PathWrite { a: &mut *self.a, path: parent }.at(None, op)
    }

    /// Sets an enum position to `case` with an optional payload.
    pub fn set_case(&mut self, case: CaseId, payload: Option<Value>) -> Result<()> {
        let v = Value::Enum(case.0, payload.map(Box::new));
        self.check(None, &v)?;
        self.at(None, Op::Set(v))
    }

    /// List: inserts `items` before visible index `at`.
    pub fn insert<U: Codec>(&mut self, at: usize, items: &[U]) -> Result<()> {
        let items = items.iter().map(|x| self.checked(Some(Step::Index(0)), x)).collect::<Result<Vec<_>>>()?;
        self.at(None, Op::Insert { at, items })
    }

    /// List or text: deletes the visible range.
    pub fn delete(&mut self, r: Range<usize>) -> Result<()> {
        self.at(None, Op::Delete { at: r.start, len: r.len() })
    }

    /// List or text: moves the range so it starts at index `to` of the sequence without it.
    pub fn move_range(&mut self, r: Range<usize>, to: usize) -> Result<()> {
        self.at(None, Op::Move { at: r.start, len: r.len(), to })
    }

    /// Text: replaces the range with `s`.
    pub fn splice(&mut self, r: Range<usize>, s: &str) -> Result<()> {
        if !r.is_empty() {
            self.delete(r.clone())?;
        }
        if s.is_empty() {
            return Ok(());
        }
        self.at(None, Op::Insert { at: r.start, items: vec![Value::Str(s.into())] })
    }

    /// Set: adds `v`.
    pub fn add<U: Codec>(&mut self, v: &U) -> Result<()> {
        let v = v.to_value();
        self.check(Some(Step::Elem(v.clone())), &v)?;
        self.at(None, Op::Add(v))
    }

    /// Set: removes `v`.
    pub fn remove_elem<U: Codec>(&mut self, v: &U) -> Result<()> {
        self.at(None, Op::Remove(v.to_value()))
    }

    /// Map: makes entry `k` read `v`.
    pub fn put<Kk: Codec, U: Codec>(&mut self, k: &Kk, v: &U) -> Result<()> {
        let k = k.to_value();
        let v = self.checked(Some(Step::Key(k.clone())), v)?;
        self.at(Some(PathSeg::Key(k)), Op::Set(v))
    }

    /// Map: removes entry `k`.
    pub fn remove_key<Kk: Codec>(&mut self, k: &Kk) -> Result<()> {
        self.at(None, Op::Remove(k.to_value()))
    }

    /// Counter: adds `n` (int or float).
    pub fn inc<U: Codec>(&mut self, n: &U) -> Result<()> {
        self.at(None, Op::Inc(n.to_value()))
    }

    /// Max/min: observes `v`.
    pub fn observe<U: Codec>(&mut self, v: &U) -> Result<()> {
        self.at(None, Op::Inc(v.to_value()))
    }
}
