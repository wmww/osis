//! Reads and watches (notes/api.md Reads, Watching): synchronous reads of local state, every
//! tid resolved through moves, large values materialized up to the bound, typed reads failing
//! with the path; watches and callbacks over the dispatcher.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::port::method as m;
use crate::watch::{Callback, Change, Delivery, Filter, Msg, Source, Subscription, Watch, WatchState};
use osis_base::{Ak, CommitId, Role, Tid, Ts, Value, WallMs};
use osis_node::{Diagnostic, Engine};
use osis_schema::{AspectKey, Codec, Path, PathError, Step, type_at, typed_read, value_at};
use std::collections::BTreeMap;
use std::sync::Arc;

/// An edge of a roster (spec/permissions.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    pub role: Role,
    /// The edge counts as removed from this wall time on.
    pub until: Option<WallMs>,
    /// The role this holder may grant others (invite grants).
    pub invite: Option<Role>,
    /// Tied to the placement of the thing in this holder, a group (`Osis::share_into`): removed
    /// once the placement is gone (spec/permissions.md §2).
    pub tied: bool,
}

/// A thing's time (`Osis::created`, `Osis::changed`): the commit, its author and when.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    /// The commit (never a compaction snapshot); `None` for an ephemeral thing's creation
    /// (`ts`, `node`, `actor` then from the creating batch).
    pub commit: Option<CommitId>,
    /// Its `ts`: the author's clock, the same on every node.
    pub ts: Ts,
    /// The authoring node and the actor it wrote for.
    pub node: Tid,
    pub actor: Tid,
    /// When this node received it (per node).
    pub received: WallMs,
}

impl Stamp {
    /// The time to show and sort by: `min(ts, received)` (an author's clock may run ahead;
    /// one more than `MAX_DRIFT` ahead is not applied until it is no longer, spec/crdt.md §2.2).
    pub fn shown(&self) -> WallMs {
        self.ts.wall_ms().min(self.received)
    }
}

fn stamp(c: osis_node::Creation) -> Stamp {
    Stamp { commit: c.commit, ts: c.ts, node: c.node, actor: c.actor, received: c.received }
}

/// The groups a thing is in (`Osis::groups_of`), each list in tid order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupsOf {
    /// Groups whose `group.0` lists it as an item.
    pub item_of: Vec<Tid>,
    /// Groups whose `group.0` lists it as a subgroup (its items count as theirs).
    pub subgroup_of: Vec<Tid>,
    /// Every group holding it as an item, directly or through subgroup lists (`groups.0`,
    /// spec/data-model.md §8): what sync follows for its own aspects. Not the groups it is
    /// only a subgroup of.
    pub within: Vec<Tid>,
}

/// The role timeline's roster of a thing: holder actor → edge.
pub type Roster = BTreeMap<Tid, Edge>;

pub(crate) fn ak_of<K: AspectKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Invalid(format!("bad AK {:?}", key.ak())))
}

fn materialize_in(e: &mut Engine, tid: &Tid, v: Value, limit: usize, budget: &mut usize) -> Result<Value> {
    let too_large = Error::TooLarge { limit };
    Ok(match v {
        Value::Link(l) => {
            let x = e.read_large_max(tid, &l, *budget).map_err(|err| match err {
                osis_node::Error::Label(osis_label::Error::TooLarge(_)) => too_large.clone(),
                other => other.into(),
            })?;
            let n = osis_base::cbor::encode(&x).len();
            *budget = budget.checked_sub(n).ok_or(too_large)?;
            x
        }
        Value::List(l) => Value::List(l.into_iter().map(|x| materialize_in(e, tid, x, limit, budget)).collect::<Result<_>>()?),
        Value::Set(s) => Value::Set(s.into_iter().map(|x| materialize_in(e, tid, x, limit, budget)).collect::<Result<_>>()?),
        Value::Map(m) => Value::Map(m.into_iter().map(|(k, x)| Ok((materialize_in(e, tid, k, limit, budget)?, materialize_in(e, tid, x, limit, budget)?))).collect::<Result<_>>()?),
        Value::Enum(c, Some(p)) => Value::Enum(c, Some(Box::new(materialize_in(e, tid, *p, limit, budget)?))),
        v => v,
    })
}

/// Replaces every link by its value; fails `TooLarge` past `limit` canonical bytes.
fn materialize(e: &mut Engine, tid: &Tid, v: Value, limit: usize) -> Result<Value> {
    let mut budget = limit;
    let v = materialize_in(e, tid, v, limit, &mut budget)?;
    if osis_base::cbor::encode(&v).len() > limit {
        return Err(Error::TooLarge { limit });
    }
    Ok(v)
}

/// The diagnostic for a stored value of `tid`'s `ak` that a typed read could not decode.
pub(crate) fn mismatch(tid: Tid, ak: &Ak, e: &PathError) -> Diagnostic {
    Diagnostic { kind: osis_node::DiagnosticKind::Mismatch, tids: vec![tid], commit: None, peer: None, detail: format!("{ak}: type error at {}: {}", e.path, e.kind) }
}

/// A typed decode of stored data (notes/api.md Typed reads): a value that does not match the
/// reader's type reads as absent and reports a `Mismatch` diagnostic. Stored data is others'
/// input; a caller cannot act on an error (the untyped read shows the value).
pub(crate) fn lenient<T>(tid: Tid, ak: &Ak, r: std::result::Result<T, PathError>, report: impl FnOnce(Diagnostic)) -> Option<T> {
    r.map_err(|e| report(mismatch(tid, ak, &e))).ok()
}

/// A consistent view for several reads (`Osis::read`); also what every single read uses.
pub struct Reader<'a> {
    pub(crate) e: &'a mut Engine,
    pub(crate) limit: usize,
    /// Reads as this actor (`Osis::act_as`): a thing it may not read answers exactly as a thing
    /// this node does not know, through every method below.
    pub(crate) actor: Option<Tid>,
}

/// `Reader::knows` on an engine already locked (a check inside a commit).
pub(crate) fn knows_in(e: &mut Engine, tid: Tid) -> bool {
    Reader { e, limit: 0, actor: None }.knows(tid)
}

impl Reader<'_> {
    /// The tid that `t` continues as (spec/permissions.md §7). Acting as an actor: `t` itself
    /// unless it may read both ends.
    pub fn resolve(&self, t: Tid) -> Tid {
        let r = self.e.resolve(&t, &t);
        if self.hidden(t) || self.hidden(r) { t } else { r }
    }

    /// Whether the acting actor may not read `t` (never without one).
    pub(crate) fn hidden(&self, t: Tid) -> bool {
        self.actor.is_some_and(|a| !self.e.readable_by(&a, &t))
    }

    /// The stored value of `tid` resolved (returned too), large values still links.
    pub(crate) fn raw(&mut self, tid: Tid, ak: &Ak) -> Result<(Tid, Option<Value>)> {
        let tid = self.resolve(tid);
        if self.hidden(tid) {
            return Ok((tid, None));
        }
        let v = self.e.get(&tid, ak)?;
        // `groups.0`: the local index, shown as `groups_of` shows it
        if let (Some(_), "groups.0", Some(Value::Set(s))) = (self.actor, ak.as_str(), &v) {
            return Ok((tid, Some(Value::Set(s.iter().filter(|g| !matches!(g, Value::Tid(t) if self.hidden(*t))).cloned().collect()))));
        }
        Ok((tid, v))
    }

    fn materialize(&mut self, tid: &Tid, v: Value) -> Result<Value> {
        materialize(self.e, tid, v, self.limit)
    }

    /// The whole value of an aspect, untyped, materialized up to the bound.
    pub fn value(&mut self, tid: Tid, ak: &Ak) -> Result<Option<Value>> {
        let (tid, v) = self.raw(tid, ak)?;
        v.map(|v| self.materialize(&tid, v)).transpose()
    }

    /// A typed read (spec/versioning.md §5): `None` when absent, and when the stored value
    /// does not match the key's type (a `Mismatch` diagnostic).
    pub fn get<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<Option<K::T>> {
        let ak = ak_of(key)?;
        let Some(v) = self.value(tid, &ak)? else { return Ok(None) };
        let t = self.resolve(tid);
        Ok(lenient(t, &ak, key.decode(&v), |d| self.e.report(d)))
    }

    /// `v` if it decodes through `key`, else `None` with a `Mismatch` diagnostic.
    pub(crate) fn checked<K: AspectKey>(&mut self, tid: Tid, ak: &Ak, key: &K, v: Result<Option<Value>>) -> Result<Option<Value>> {
        Ok(v?.filter(|x| lenient(tid, ak, key.decode(x), |d| self.e.report(d)).is_some()))
    }

    /// The value at `path` inside an aspect (typed projection through the key's schema when it
    /// has one); `None` when the path leads nowhere or the value there does not match the
    /// schema (a `Mismatch` diagnostic). A path the schema does not have fails `Type`. Only
    /// that position is materialized.
    pub fn get_path<K: AspectKey>(&mut self, tid: Tid, key: &K, path: &Path) -> Result<Option<Value>> {
        let ak = ak_of(key)?;
        let (tid, Some(raw)) = self.raw(tid, &ak)? else { return Ok(None) };
        let (Some(s), Some(ty)) = (key.schema(), key.ty()) else {
            let Some(sub) = value_at(&raw, path) else { return Ok(None) };
            return Ok(Some(self.materialize(&tid, sub.clone())?));
        };
        let t = type_at(s, ty, path)?.0;
        if let Some(sub) = value_at(&raw, path) {
            let sub = self.materialize(&tid, sub.clone())?;
            return Ok(lenient(tid, &ak, typed_read(s, &sub, &t), |d| self.e.report(d)));
        }
        // an absent struct field reads as its default (spec/versioning.md §5): project the parent
        let Some((Step::Field(id), parent)) = path.0.split_last() else { return Ok(None) };
        let parent = Path(parent.to_vec());
        let Some(sub) = value_at(&raw, &parent) else { return Ok(None) };
        let sub = self.materialize(&tid, sub.clone())?;
        let pt = type_at(s, ty, &parent)?.0;
        let Some(projected) = lenient(tid, &ak, typed_read(s, &sub, &pt), |d| self.e.report(d)) else { return Ok(None) };
        Ok(value_at(&projected, &Path(vec![Step::Field(*id)])).cloned())
    }

    /// AKs present on the thing.
    pub fn aspects(&mut self, tid: Tid) -> Result<Vec<Ak>> {
        let tid = self.resolve(tid);
        if self.hidden(tid) {
            return Ok(Vec::new());
        }
        Ok(self.e.aspects(&tid)?)
    }

    /// The groups the thing is in: those listing it as an item or as a subgroup, and every
    /// group holding it transitively. `group.0` and `placed.0~`, local indexes only.
    pub fn groups_of(&self, tid: Tid) -> GroupsOf {
        let t = self.resolve(tid);
        if self.hidden(t) {
            return GroupsOf::default();
        }
        let (items, subs) = self.e.listed_in(&t);
        let seen = |s: std::collections::BTreeSet<Tid>| s.into_iter().filter(|g| !self.hidden(*g)).collect();
        GroupsOf { item_of: seen(items), subgroup_of: seen(subs), within: seen(self.e.groups_of(&t)) }
    }

    /// The role timeline's roster of `thing` (spec/permissions.md §2).
    pub fn roster(&self, thing: Tid) -> Roster {
        if self.hidden(self.resolve(thing)) {
            return Roster::new();
        }
        self.e.roster(&self.resolve(thing)).into_iter().map(|(m, e)| (self.resolve(m), Edge { role: e.role, until: e.until, invite: e.invite, tied: e.tied.is_some() })).collect()
    }

    /// This node's effective role on `tid` now (`None`: no access); the acting actor's when
    /// there is one.
    pub fn role_on(&self, tid: Tid) -> Option<Role> {
        let t = self.resolve(tid);
        match self.actor {
            Some(a) => self.e.actor_role(&a, &t).filter(|_| !self.hidden(t)),
            None => self.e.role_on(&t),
        }
    }

    /// Whether the thing is here: its creation is held and it has content, some aspect a
    /// `Write` sets, or it is ephemeral or a draft again (its save undone) here (content or
    /// not, unless an undo of its creation deleted it). `false` for an unknown thing and for a deleted one, which `created` still
    /// reports; an actor carrying only role data (a link key, a contact before any
    /// data) reads `false` too.
    pub fn knows(&mut self, tid: Tid) -> bool {
        let t = self.resolve(tid);
        if self.hidden(t) {
            return false;
        }
        self.e.ephemeral_thing(&t).is_some_and(|x| !x.deleted) || self.e.is_draft_again(&t) || (self.e.knows(&t) && self.e.has_content(&t).unwrap_or(true))
    }

    /// Whether the thing's creation is held or it is ephemeral here, deleted or not: what a
    /// write, grant or move needs.
    pub(crate) fn holds(&self, tid: Tid) -> bool {
        let t = self.resolve(tid);
        !self.hidden(t) && self.e.knows(&t)
    }

    /// The thing's owner (`None`: unknown, or a key actor).
    pub fn owner_of(&self, tid: Tid) -> Option<Tid> {
        let t = self.resolve(tid);
        if self.hidden(t) {
            return None;
        }
        self.e.owner(&t).map(|o| self.resolve(o))
    }

    /// When the thing was created: the oldest valid commit carrying its `created.0` that is no
    /// snapshot (an ephemeral thing's batch, `commit: None`); `None` while it is unknown or
    /// only a snapshot carrying its `created.0` is here. Follows moves: a moved thing reports
    /// its copy's creation, the move.
    pub fn created(&self, tid: Tid) -> Option<Stamp> {
        let t = self.resolve(tid);
        if self.hidden(t) {
            return None;
        }
        self.e.creation(&t).map(stamp)
    }

    /// When the thing's content last changed: of the held changes, reverts and imports
    /// writing its aspects (not `created.0`, `group.0` or role-class ones: placement and
    /// sharing are no content change; not ephemeral writes), the one with the latest
    /// `shown()`, else its creation. A delete is a change. A change known here only from a
    /// snapshot is not seen (notes/api.md Attribution). Follows moves.
    pub fn changed(&self, tid: Tid) -> Option<Stamp> {
        let t = self.resolve(tid);
        if self.hidden(t) {
            return None;
        }
        self.e.changed(&t).map(stamp)
    }
}

impl Osis {
    /// Runs `f` with a consistent view across several reads. `Unsupported` on a handle attached
    /// to a node (`Osis::attach`): the port carries no read transaction.
    ///
    /// `Unsupported` too while this node routes a group elsewhere (`group_source`): the closure
    /// reads this engine alone, where a routed group's things are stale, and a transaction cannot
    /// span two sources.
    pub fn read<R>(&self, f: impl FnOnce(&mut Reader<'_>) -> R) -> Result<R> {
        self.local_only("read")?;
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            if !l.routes.is_empty() {
                return Err(Error::Unsupported("read on a handle routing a group to another node".into()));
            }
            Ok(f(&mut Reader { e: l.engine(), limit, actor }))
        })
    }

    /// `read` on this process's engine (callers route first).
    pub(crate) fn read_local<R>(&self, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.engine(|e| f(&mut Reader { e, limit, actor }))
    }

    /// A typed read: `None` when absent or the thing is unknown.
    pub fn get<K: AspectKey>(&self, tid: Tid, key: K) -> Result<Option<K::T>> {
        self.at(tid, key).get()
    }

    /// An aspect, for reads at paths, watches and callbacks.
    pub fn at<K: AspectKey>(&self, tid: Tid, key: K) -> AspectRef<'_, K> {
        AspectRef { db: self, tid, key }
    }

    pub fn aspects(&self, tid: Tid) -> Result<Vec<Ak>> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            let v = r.call(m::ASPECTS, vec![Value::Tid(tid)])?;
            return crate::port::codec::Args::of(vec![v]).list()?.iter().map(crate::port::codec::ak).collect();
        }
        self.read_local(|r| r.aspects(tid))
    }

    /// `Reader::groups_of`. Attached to a node that cannot be reached: empty (a diagnostic).
    pub fn groups_of(&self, tid: Tid) -> GroupsOf {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.infallible(r.call(m::GROUPS_OF, vec![Value::Tid(tid)]).and_then(crate::port::codec::groups));
        }
        self.read_local(|r| r.groups_of(tid))
    }

    pub fn roster(&self, thing: Tid) -> Roster {
        if let crate::sources::Source::Remote(r) = self.route(thing) {
            return self.infallible(r.call(m::ROSTER, vec![Value::Tid(thing)]).and_then(crate::port::codec::roster));
        }
        self.read_local(|r| r.roster(thing))
    }

    pub fn role_on(&self, tid: Tid) -> Option<Role> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.infallible(r.call(m::ROLE_ON, vec![Value::Tid(tid)]).and_then(|v| crate::port::codec::Args::of(vec![v]).opt()?.map(|r| crate::port::codec::role(&r)).transpose()));
        }
        self.read_local(|r| r.role_on(tid))
    }

    /// `Reader::knows`: the thing is here, not unknown or deleted.
    pub fn knows(&self, tid: Tid) -> bool {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.infallible(r.call(m::KNOWS, vec![Value::Tid(tid)]).and_then(|v| crate::port::codec::Args::of(vec![v]).bool()));
        }
        self.read_local(|r| r.knows(tid))
    }

    /// A remote result of a call whose signature cannot fail: the default when the node could
    /// not answer, reported as a diagnostic.
    pub(crate) fn infallible<T: Default>(&self, r: Result<T>) -> T {
        r.unwrap_or_else(|e| {
            self.engine(|x| x.report(Diagnostic { kind: osis_node::DiagnosticKind::Storage, tids: Vec::new(), commit: None, peer: None, detail: format!("attached node: {e}") }));
            T::default()
        })
    }

    pub(crate) fn holds(&self, tid: Tid) -> bool {
        self.read_local(|r| r.holds(tid))
    }

    /// The thing's owner, fixed at creation (`None`: unknown, or a key actor).
    pub fn owner_of(&self, tid: Tid) -> Option<Tid> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.infallible(r.call(m::OWNER_OF, vec![Value::Tid(tid)]).and_then(|v| crate::port::codec::Args::of(vec![v]).opt()?.map(|t| crate::port::codec::tid(&t)).transpose()));
        }
        self.read_local(|r| r.owner_of(tid))
    }

    fn remote_stamp(&self, r: &crate::port::client::Remote, m: u64, tid: Tid) -> Option<Stamp> {
        self.infallible(r.call(m, vec![Value::Tid(tid)]).and_then(|v| crate::port::codec::Args::of(vec![v]).opt()?.map(crate::port::codec::stamp).transpose()))
    }

    /// When the thing was created (`Reader::created`).
    pub fn created(&self, tid: Tid) -> Option<Stamp> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.remote_stamp(&r, m::CREATED, tid);
        }
        self.read_local(|r| r.created(tid))
    }

    /// When the thing's content last changed (`Reader::changed`).
    pub fn changed(&self, tid: Tid) -> Option<Stamp> {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.remote_stamp(&r, m::CHANGED, tid);
        }
        self.read_local(|r| r.changed(tid))
    }

    /// The corrected wall clock (spec/sync.md §6): the time the database stamps commits with,
    /// for app timestamps.
    pub fn now(&self) -> WallMs {
        if self.is_attached()
            && let Ok(Some(n)) = self.rcall(m::NOW, vec![]).map(|v| v.as_uint())
        {
            return WallMs(n);
        }
        self.engine(|e| e.now())
    }

    /// Whether two tids name the same thing across moves (spec/permissions.md §7): the only
    /// explicit resolution call; `Tid` equality is plain bits.
    pub fn same_thing(&self, a: Tid, b: Tid) -> bool {
        if let crate::sources::Source::Remote(r) = self.route(a) {
            return self.infallible(r.call(m::SAME_THING, vec![Value::Tid(a), Value::Tid(b)]).and_then(|v| crate::port::codec::Args::of(vec![v]).bool()));
        }
        self.read_local(|r| r.resolve(a) == r.resolve(b))
    }

    /// Reads an aspect and runs `also` under the same engine lock (the dispatcher queues the
    /// events whose effect the read shows).
    pub(crate) fn value_with(&self, tid: Tid, ak: &Ak, also: impl FnOnce()) -> Result<Option<Value>> {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            let v = Reader { e: l.engine(), limit, actor }.value(tid, ak);
            also();
            v
        })
    }

    /// Registers a callback built by `make` under the engine lock (so whatever `make` reads is
    /// atomic with the registration: nothing committed after it is missed or seen twice);
    /// `initial` queues one `Delivery::Initial` call through the dispatcher.
    pub(crate) fn subscribe(&self, filter: Filter, initial: bool, make: impl FnOnce(&mut Reader<'_>) -> Callback) -> Subscription {
        let (limit, actor) = (self.inner.limit, self.acting);
        self.locked(|l| {
            let cb = make(&mut Reader { e: l.engine(), limit, actor });
            let d = &self.inner.dispatch;
            // the route was decided before this lock: a move since ends it at once
            let on = match &filter {
                Filter::Aspect(t, _) | Filter::Thing(t) | Filter::Roster(t) => Some(*t),
                _ => None,
            };
            let gone = on.is_some_and(|t| actor.is_none() && !self.local_in(l, t));
            let sub = d.register(l.seq + 1, filter, cb);
            if initial && let Some(id) = sub.id() {
                l.seq += 1;
                d.send(l.seq, Msg::Initial(id));
            }
            if gone && let Some(id) = sub.id() {
                l.seq += 1;
                d.send(l.seq, Msg::Moved(id));
            }
            sub
        })
    }

    /// Calls `f` with every change of any aspect of `tid` (and of what it moves to), first
    /// once per present aspect (`Source::Initial`, through the dispatcher). Like every
    /// callback, `f` gets the database handle, so it need not capture one (a captured clone in
    /// a detached callback keeps the database open; capture `Osis::downgrade()` instead).
    pub fn watch_thing(&self, tid: Tid, mut f: impl FnMut(&Osis, Change<Value>) + Send + 'static) -> Subscription {
        if let crate::sources::Source::Remote(r) = self.route(tid) {
            return self.remote_watch_thing(&r, tid, Box::new(f));
        }
        let tid = self.read_local(|r| r.resolve(tid));
        self.subscribe(Filter::Thing(tid), true, move |r| {
            let mut last: BTreeMap<Ak, Result<Option<Value>>> = BTreeMap::new();
            for ak in r.aspects(tid).unwrap_or_default() {
                let v = r.value(tid, &ak);
                last.insert(ak, v);
            }
            let mut first = Some(last.clone());
            Box::new(move |db, d| match d {
                Delivery::Initial => {
                    for (ak, v) in first.take().unwrap_or_default() {
                        f(db, Change { tid, ak, value: v, source: Source::Initial });
                    }
                }
                Delivery::Aspect { tid, ak, source, value } if value.is_err() || last.get(&ak) != Some(&value) => {
                    last.insert(ak.clone(), value.clone());
                    f(db, Change { tid, ak, value, source });
                }
                Delivery::Fired { tid, ak, source, value } => f(db, Change { tid, ak, value: Ok(Some(value)), source }),
                Delivery::Moved => {
                    if let Ok(ak) = Ak::new("tid.0") {
                        f(db, Change { tid, ak, value: Err(crate::sources::moved()), source: Source::Initial });
                    }
                }
                _ => {}
            })
        })
    }

    /// Calls `f` with the roster of `actor` now (through the dispatcher) and on every change.
    pub fn watch_roster(&self, actor: Tid, mut f: impl FnMut(&Osis, Roster) + Send + 'static) -> Subscription {
        if let crate::sources::Source::Remote(r) = self.route(actor) {
            return self.remote_watch_roster(&r, actor, Box::new(f));
        }
        let actor = self.read_local(|r| r.resolve(actor));
        self.subscribe(Filter::Roster(actor), true, move |r| {
            let mut last = r.roster(actor);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, last.clone()),
                Delivery::Roster => {
                    let r = db.roster(actor);
                    if r != last {
                        last = r.clone();
                        f(db, r);
                    }
                }
                _ => {}
            })
        })
    }

    /// Calls `f` with every diagnostic (structured, deduped and rate-limited by the engine).
    pub fn on_diagnostic(&self, mut f: impl FnMut(&Osis, Diagnostic) + Send + 'static) -> Subscription {
        if self.is_attached() {
            return self.remote_on_diagnostic(Box::new(f));
        }
        self.subscribe(Filter::Diagnostics, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Diagnostic(x) = d {
                    f(db, x)
                }
            })
        })
    }
}

/// An aspect of a thing: reads, path reads, watches.
pub struct AspectRef<'d, K> {
    db: &'d Osis,
    tid: Tid,
    key: K,
}

impl<'d, K: AspectKey> AspectRef<'d, K> {
    pub fn get(&self) -> Result<Option<K::T>> {
        if let crate::sources::Source::Remote(r) = self.db.route(self.tid) {
            let ak = ak_of(&self.key)?;
            let Some(v) = self.db.remote_get(&r, self.tid, &ak, &Path::root())? else { return Ok(None) };
            let db = self.db;
            return Ok(lenient(self.tid, &ak, self.key.decode(&v), |d| db.engine(|e| e.report(d))));
        }
        self.db.read_local(|r| r.get(self.tid, &self.key))
    }

    /// The whole value, untyped.
    pub fn get_value(&self) -> Result<Option<Value>> {
        let ak = ak_of(&self.key)?;
        if let crate::sources::Source::Remote(r) = self.db.route(self.tid) {
            return self.db.remote_get(&r, self.tid, &ak, &Path::root());
        }
        self.db.read_local(|r| r.value(self.tid, &ak))
    }

    /// A position inside the value.
    pub fn path(&self, path: Path) -> PathRef<'_, 'd, K> {
        PathRef { a: self, path }
    }
}

impl<K: AspectKey + Clone + Send + 'static> AspectRef<'_, K> {
    /// A watch taken atomically with the current value: no change after it is missed. It
    /// follows moves of the thing.
    pub fn watch(&self) -> Result<Watch<K::T>>
    where
        K: Sync,
    {
        let ak = ak_of(&self.key)?;
        if let crate::sources::Source::Remote(r) = self.db.route(self.tid) {
            let key = self.key.clone();
            let (st, sub) = self.db.remote_watch(&r, self.tid, ak, Box::new(move |v: &Value| key.decode(v).is_ok()))?;
            let key = self.key.clone();
            return Ok(Watch::new(st, Arc::new(move |v: &Value| key.decode(v).ok()), sub));
        }
        let tid = self.db.read_local(|r| r.resolve(self.tid));
        let mut state = None;
        let key = self.key.clone();
        let sub = self.db.subscribe(Filter::Aspect(tid, ak.clone()), false, |r| {
            let v = r.value(tid, &ak);
            let st = WatchState::new(r.checked(tid, &ak, &key, v));
            state = Some(st.clone());
            let key = key.clone();
            Box::new(move |db, d| match d {
                Delivery::Aspect { value, .. } => st.update(db.read_local(|r| r.checked(tid, &ak, &key, value))),
                Delivery::Moved => st.update(Err(crate::sources::moved())),
                _ => {}
            })
        });
        let state = state.ok_or(Error::Closed)?;
        // the held value decoded when stored: a mismatch was reported and stored as absent
        Ok(Watch::new(state, Arc::new(move |v: &Value| key.decode(v).ok()), sub))
    }

    /// Calls `f` once with the value at registration (`Source::Initial`, through the
    /// dispatcher like every later call), then on every change; `f` gets the database handle.
    /// Calls coalesce: one call may show several commits' effect and carries the newest one's
    /// source; an unchanged value is not repeated, an error always is. Follows moves.
    pub fn on_change(&self, mut f: impl FnMut(&Osis, Change<K::T>) + Send + 'static) -> Result<Subscription> {
        let ak = ak_of(&self.key)?;
        if let crate::sources::Source::Remote(r) = self.db.route(self.tid) {
            let key = self.key.clone();
            let ak2 = ak.clone();
            let tid = self.tid;
            let decode = move |db: &Osis, v: Result<Option<Value>>| -> Result<Option<K::T>> { Ok(v?.and_then(|x| lenient(tid, &ak2, key.decode(&x), |d| db.engine(|e| e.report(d))))) };
            return self.db.remote_on_change(&r, self.tid, ak, Box::new(move |db, ch: Change<Value>| f(db, Change { tid: ch.tid, ak: ch.ak, value: decode(db, ch.value), source: ch.source })));
        }
        let tid = self.db.read_local(|r| r.resolve(self.tid));
        let key = self.key.clone();
        let ak2 = ak.clone();
        let decode = move |db: &Osis, v: Result<Option<Value>>| Ok(v?.and_then(|x| lenient(tid, &ak2, key.decode(&x), |d| db.engine(|e| e.report(d)))));
        Ok(self.db.subscribe(Filter::Aspect(tid, ak.clone()), true, move |r| {
            let mut last = r.value(tid, &ak);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(db, Change { tid, ak: ak.clone(), value: decode(db, last.clone()), source: Source::Initial }),
                Delivery::Aspect { tid, source, value, .. } if value.is_err() || value != last => {
                    last = value.clone();
                    f(db, Change { tid, ak: ak.clone(), value: decode(db, value), source });
                }
                Delivery::Fired { tid, source, value, .. } => f(db, Change { tid, ak: ak.clone(), value: decode(db, Ok(Some(value))), source }),
                Delivery::Moved => f(db, Change { tid, ak: ak.clone(), value: Err(crate::sources::moved()), source: Source::Initial }),
                _ => {}
            })
        }))
    }
}

/// A position inside an aspect's value.
pub struct PathRef<'a, 'd, K> {
    a: &'a AspectRef<'d, K>,
    path: Path,
}

impl<'d, K: AspectKey> PathRef<'_, 'd, K> {
    pub(crate) fn parts(&self) -> (&'d Osis, Tid, &K, &Path) {
        (self.a.db, self.a.tid, &self.a.key, &self.path)
    }

    /// The untyped value at the path (typed projection when the key has a schema).
    pub fn get_value(&self) -> Result<Option<Value>> {
        if let crate::sources::Source::Remote(r) = self.a.db.route(self.a.tid) {
            return self.a.db.remote_get(&r, self.a.tid, &ak_of(&self.a.key)?, &self.path);
        }
        self.a.db.read_local(|r| r.get_path(self.a.tid, &self.a.key, &self.path))
    }

    /// The value at the path as `U`; one bad element of a large collection reads as absent
    /// alone (a `Mismatch` diagnostic).
    pub fn get<U: Codec>(&self) -> Result<Option<U>> {
        let Some(v) = self.get_value()? else { return Ok(None) };
        let db = self.a.db;
        let tid = if db.is_local(self.a.tid) { db.read_local(|r| r.resolve(self.a.tid)) } else { self.a.tid };
        let ak = ak_of(&self.a.key)?;
        Ok(lenient(tid, &ak, U::from_value(&v), |d| db.engine(|e| e.report(d))))
    }
}
