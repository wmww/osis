//! Reads and watches (notes/api.md Reads, Watching): synchronous reads of local state, every
//! tid resolved through moves, large values materialized up to the bound, typed reads failing
//! with the path; watches and callbacks over the dispatcher.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{Callback, Change, Delivery, Filter, Msg, Source, Subscription, Watch, WatchState};
use osis_core::{Ak, Role, Tid, Value, WallMs};
use osis_node::{Diagnostic, Engine};
use osis_schema::{AspectKey, Codec, Path, type_at, typed_read, value_at};
use std::collections::BTreeMap;
use std::sync::Arc;

/// An edge of a roster (spec/permissions.md §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    pub role: Role,
    /// The edge counts as removed from this wall time on.
    pub until: Option<WallMs>,
    /// The role this member may grant others (invite grants).
    pub invite: Option<Role>,
}

/// The membership timeline's roster of a thing: member actor → edge.
pub type Roster = BTreeMap<Tid, Edge>;

pub(crate) fn ak_of<K: AspectKey>(key: &K) -> Result<Ak> {
    Ak::new(key.ak()).map_err(|_| Error::Invalid(format!("bad AK {:?}", key.ak())))
}

fn materialize_in(e: &mut Engine, tid: &Tid, v: Value, limit: usize, budget: &mut usize) -> Result<Value> {
    let too_large = Error::TooLarge { limit };
    Ok(match v {
        Value::Link(l) => {
            let x = e.read_large_max(tid, &l, *budget).map_err(|err| match Error::from(err) {
                Error::TooLarge { .. } => too_large.clone(),
                other => other,
            })?;
            let n = osis_core::cbor::encode(&x).len();
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
    if osis_core::cbor::encode(&v).len() > limit {
        return Err(Error::TooLarge { limit });
    }
    Ok(v)
}

/// A consistent view for several reads (`Osis::read`); also what every single read uses.
pub struct Reader<'a> {
    e: &'a mut Engine,
    limit: usize,
}

impl Reader<'_> {
    /// The tid that `t` continues as (spec/permissions.md §7).
    pub fn resolve(&self, t: Tid) -> Tid {
        self.e.resolve(&t, &t)
    }

    /// The raw stored value: tids resolved, large values still links.
    fn raw(&mut self, tid: Tid, ak: &Ak) -> Result<Option<Value>> {
        let tid = self.resolve(tid);
        Ok(self.e.get(&tid, ak)?)
    }

    /// The whole value of an aspect, untyped, materialized up to the bound.
    pub fn value(&mut self, tid: Tid, ak: &Ak) -> Result<Option<Value>> {
        let tid = self.resolve(tid);
        match self.e.get(&tid, ak)? {
            Some(v) => Ok(Some(materialize(self.e, &tid, v, self.limit)?)),
            None => Ok(None),
        }
    }

    /// A typed read (spec/versioning.md §5): `None` when absent.
    pub fn get<K: AspectKey>(&mut self, tid: Tid, key: &K) -> Result<Option<K::T>> {
        match self.value(tid, &ak_of(key)?)? {
            Some(v) => Ok(Some(key.decode(&v)?)),
            None => Ok(None),
        }
    }

    /// The value at `path` inside an aspect (typed projection through the key's schema when it
    /// has one); `None` when the path leads nowhere. Only that position is materialized.
    pub fn get_path<K: AspectKey>(&mut self, tid: Tid, key: &K, path: &Path) -> Result<Option<Value>> {
        let Some(raw) = self.raw(tid, &ak_of(key)?)? else { return Ok(None) };
        let ty = match (key.schema(), key.ty()) {
            (Some(s), Some(t)) => Some((s, type_at(s, t, path)?.0)),
            _ => None,
        };
        let Some(sub) = value_at(&raw, path) else { return Ok(None) };
        let sub = materialize(self.e, &self.resolve(tid), sub.clone(), self.limit)?;
        match ty {
            Some((s, t)) => Ok(Some(typed_read(s, &sub, &t)?)),
            None => Ok(Some(sub)),
        }
    }

    /// AKs present on the thing.
    pub fn aspects(&mut self, tid: Tid) -> Result<Vec<Ak>> {
        let tid = self.resolve(tid);
        Ok(self.e.aspects(&tid)?)
    }

    /// Groups containing the thing, transitively.
    pub fn groups_of(&self, tid: Tid) -> Vec<Tid> {
        self.e.groups_of(&self.resolve(tid)).into_iter().collect()
    }

    /// The membership timeline's roster of `thing` (spec/permissions.md §2).
    pub fn roster(&self, thing: Tid) -> Roster {
        self.e.roster(&self.resolve(thing)).into_iter().map(|(m, e)| (self.resolve(m), Edge { role: e.role, until: e.until, invite: e.invite })).collect()
    }

    /// This node's effective role on `tid` now (`None`: no access).
    pub fn role_on(&self, tid: Tid) -> Option<Role> {
        self.e.role_on(&self.resolve(tid))
    }

    /// Whether the thing's `/created` is held.
    pub fn knows(&self, tid: Tid) -> bool {
        self.e.knows(&self.resolve(tid))
    }
}

impl Osis {
    /// Runs `f` with a consistent view across several reads.
    pub fn read<R>(&self, f: impl FnOnce(&mut Reader<'_>) -> R) -> R {
        let limit = self.inner.limit;
        self.engine(|e| f(&mut Reader { e, limit }))
    }

    /// A typed read: `None` when absent or the thing is unknown.
    pub fn get<K: AspectKey>(&self, tid: Tid, key: K) -> Result<Option<K::T>> {
        self.read(|r| r.get(tid, &key))
    }

    /// An aspect, for reads at paths, watches and callbacks.
    pub fn at<K: AspectKey>(&self, tid: Tid, key: K) -> AspectRef<'_, K> {
        AspectRef { db: self, tid, key }
    }

    pub fn aspects(&self, tid: Tid) -> Result<Vec<Ak>> {
        self.read(|r| r.aspects(tid))
    }

    pub fn groups_of(&self, tid: Tid) -> Vec<Tid> {
        self.read(|r| r.groups_of(tid))
    }

    pub fn roster(&self, thing: Tid) -> Roster {
        self.read(|r| r.roster(thing))
    }

    pub fn role_on(&self, tid: Tid) -> Option<Role> {
        self.read(|r| r.role_on(tid))
    }

    pub fn knows(&self, tid: Tid) -> bool {
        self.read(|r| r.knows(tid))
    }

    /// Whether two tids name the same thing across moves (spec/permissions.md §7): the only
    /// explicit resolution call; `Tid` equality is plain bits.
    pub fn same_thing(&self, a: Tid, b: Tid) -> bool {
        self.read(|r| r.resolve(a) == r.resolve(b))
    }


    /// Registers a callback built by `make` under the engine lock (so whatever `make` reads is
    /// atomic with the registration: nothing committed after it is missed or seen twice);
    /// `initial` queues one `Delivery::Initial` call through the dispatcher.
    pub(crate) fn subscribe(&self, filter: Filter, initial: bool, make: impl FnOnce(&mut Reader<'_>) -> Callback) -> Subscription {
        let limit = self.inner.limit;
        self.locked(|l| {
            let cb = make(&mut Reader { e: &mut l.engine, limit });
            let d = &self.inner.dispatch;
            let sub = d.register(l.seq + 1, filter, cb);
            if initial && let Some(id) = sub.id() {
                l.seq += 1;
                d.send(l.seq, Msg::Initial(id));
            }
            sub
        })
    }

    /// Calls `f` with every change of any aspect of `tid`, first once per present aspect
    /// (`Source::Initial`, through the dispatcher).
    pub fn watch_thing(&self, tid: Tid, mut f: impl FnMut(Change<Value>) + Send + 'static) -> Subscription {
        let tid = self.read(|r| r.resolve(tid));
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
                        f(Change { tid, ak, value: v, source: Source::Initial });
                    }
                }
                Delivery::Aspect { ak, source } => {
                    let v = db.read(|r| r.value(tid, &ak));
                    if last.get(&ak) != Some(&v) {
                        last.insert(ak.clone(), v.clone());
                        f(Change { tid, ak, value: v, source });
                    }
                }
                _ => {}
            })
        })
    }

    /// Calls `f` with the roster of `actor` now (through the dispatcher) and on every change.
    pub fn watch_roster(&self, actor: Tid, mut f: impl FnMut(Roster) + Send + 'static) -> Subscription {
        let actor = self.read(|r| r.resolve(actor));
        self.subscribe(Filter::Roster(actor), true, move |r| {
            let mut last = r.roster(actor);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(last.clone()),
                Delivery::Roster => {
                    let r = db.roster(actor);
                    if r != last {
                        last = r.clone();
                        f(r);
                    }
                }
                _ => {}
            })
        })
    }

    /// Calls `f` with every diagnostic (structured, deduped and rate-limited by the engine).
    pub fn on_diagnostic(&self, mut f: impl FnMut(Diagnostic) + Send + 'static) -> Subscription {
        self.subscribe(Filter::Diagnostics, false, |_| {
            Box::new(move |_, d| {
                if let Delivery::Diagnostic(x) = d {
                    f(x)
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
        self.db.read(|r| r.get(self.tid, &self.key))
    }

    /// The whole value, untyped.
    pub fn get_value(&self) -> Result<Option<Value>> {
        let ak = ak_of(&self.key)?;
        self.db.read(|r| r.value(self.tid, &ak))
    }

    /// A position inside the value.
    pub fn path(&self, path: Path) -> PathRef<'_, 'd, K> {
        PathRef { a: self, path }
    }
}

impl<K: AspectKey + Clone + Send + 'static> AspectRef<'_, K> {
    /// A watch taken atomically with the current value: no change after it is missed.
    pub fn watch(&self) -> Result<Watch<K::T>>
    where
        K: Sync,
    {
        let ak = ak_of(&self.key)?;
        let tid = self.db.read(|r| r.resolve(self.tid));
        let mut state = None;
        let sub = self.db.subscribe(Filter::Aspect(tid, ak.clone()), false, |r| {
            let st = WatchState::new(r.value(tid, &ak));
            state = Some(st.clone());
            Box::new(move |db, d| {
                if matches!(d, Delivery::Aspect { .. }) {
                    st.update(db.read(|r| r.value(tid, &ak)));
                }
            })
        });
        let state = state.ok_or(Error::Closed)?;
        let key = self.key.clone();
        Ok(Watch::new(state, Arc::new(move |v: &Value| Ok(key.decode(v)?)), sub))
    }

    /// Calls `f` once with the value at registration (`Source::Initial`, through the
    /// dispatcher like every later call), then on every change.
    pub fn on_change(&self, mut f: impl FnMut(Change<K::T>) + Send + 'static) -> Result<Subscription> {
        let ak = ak_of(&self.key)?;
        let tid = self.db.read(|r| r.resolve(self.tid));
        let key = self.key.clone();
        let decode = move |v: Result<Option<Value>>| v.and_then(|o| o.map(|x| key.decode(&x).map_err(Error::from)).transpose());
        Ok(self.db.subscribe(Filter::Aspect(tid, ak.clone()), true, move |r| {
            let mut last = r.value(tid, &ak);
            Box::new(move |db, d| match d {
                Delivery::Initial => f(Change { tid, ak: ak.clone(), value: decode(last.clone()), source: Source::Initial }),
                Delivery::Aspect { source, .. } => {
                    let v = db.read(|r| r.value(tid, &ak));
                    if v != last {
                        last = v.clone();
                        f(Change { tid, ak: ak.clone(), value: decode(v), source });
                    }
                }
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

impl<K: AspectKey> PathRef<'_, '_, K> {
    /// The untyped value at the path (typed projection when the key has a schema).
    pub fn get_value(&self) -> Result<Option<Value>> {
        self.a.db.read(|r| r.get_path(self.a.tid, &self.a.key, &self.path))
    }

    /// The value at the path as `U`; one bad element of a large collection fails alone.
    pub fn get<U: Codec>(&self) -> Result<Option<U>> {
        match self.get_value()? {
            Some(v) => Ok(Some(U::from_value(&v)?)),
            None => Ok(None),
        }
    }
}
