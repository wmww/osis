//! `Db`: the read side of `osis` that a render holds. It has no write, no listener and no session,
//! so a write during render does not compile. On a render's handle each address is one node of the
//! graph (one read, one listener however many memos ask); elsewhere it is a plain read.

use crate::view::graph::{Graph, Scope};
use osis::{Ak, Address, Commit, CommitPage, CommitQuery, DynamicAspectKey, Grants, GroupsOf, Member, Osis, Path, Result, Role, SignalKey, Status, ThingStamp, Tid, Time, ValueKey};
use std::any::{Any, TypeId};
use std::fmt::Debug;
use std::hash::Hash;

/// The read half of an `Osis` handle (a tracking one in a render).
#[derive(Clone)]
pub struct Db {
    pub(crate) inner: Osis,
    pub(crate) scope: Option<Scope>,
}

impl Db {
    /// An untracked `Db` over `inner`.
    pub fn new(inner: Osis) -> Db {
        Db { inner, scope: None }
    }

    /// `f` reads `key`'s address: remembered in the graph for this pass and until it changes.
    fn leaf<K, V>(&self, key: K, f: impl Fn(&Osis) -> Result<V> + 'static) -> Result<V>
    where
        K: Any + Debug + Hash + Eq,
        V: Clone + PartialEq + 'static,
    {
        match &self.scope {
            None => f(&self.inner),
            Some(s) => Ok((*Graph::get(&s.graph, s, key, move |r| f(&r.db.inner))?).clone()),
        }
    }

    pub fn at<K: Clone>(&self, tid: Tid, key: K) -> At<'_, K> {
        At { db: self, tid, key }
    }

    pub fn me(&self) -> Tid {
        self.inner.me()
    }
    pub fn node(&self) -> Tid {
        self.inner.node()
    }
    pub fn now(&self) -> Result<Time> {
        self.inner.now()
    }
    pub fn aspect_key(&self, ak: &str) -> Result<DynamicAspectKey> {
        self.inner.aspect_key(ak)
    }
    pub fn profile(&self) -> Result<Tid> {
        self.inner.profile()
    }
    pub fn members(&self, t: Tid) -> Result<Vec<Member>> {
        self.leaf(("db.members", t), move |db| db.members(t))
    }
    pub fn aspects(&self, t: Tid) -> Result<Vec<Ak>> {
        self.leaf(("db.aspects", t), move |db| db.aspects(t))
    }
    pub fn status(&self) -> Result<Status> {
        self.leaf(("db.status", ()), move |db| db.status())
    }
    pub fn groups_of(&self, t: Tid) -> Result<GroupsOf> {
        self.leaf(("db.groups_of", t), move |db| db.groups_of(t))
    }
    pub fn profile_of(&self, t: Tid) -> Result<Option<Tid>> {
        self.leaf(("db.profile_of", t), move |db| db.profile_of(t))
    }
    pub fn saved_peers(&self) -> Result<Vec<Address>> {
        self.leaf(("db.saved_peers", ()), move |db| db.saved_peers())
    }
    pub fn changed(&self, t: Tid) -> Result<Option<ThingStamp>> {
        self.leaf(("db.changed", t), move |db| db.changed(t))
    }
    pub fn created(&self, t: Tid) -> Result<Option<ThingStamp>> {
        self.leaf(("db.created", t), move |db| db.created(t))
    }
    pub fn role_on(&self, t: Tid) -> Result<Option<Role>> {
        self.leaf(("db.role_on", t), move |db| db.role_on(t))
    }
    pub fn grants(&self, t: Tid) -> Result<Grants> {
        self.leaf(("db.grants", t), move |db| db.grants(t))
    }
    pub fn has_content(&self, t: Tid) -> Result<bool> {
        self.leaf(("db.has_content", t), move |db| db.has_content(t))
    }
    /// What `undo` of this scope would do (`writes` and `fired` read as listings, not addresses).
    pub fn undo_target(&self, s: &osis::Scope) -> Result<Option<Commit>> {
        self.inner.undo_target(s)
    }
}

/// An aspect of a thing, as `db.at(t, k)` is on `Osis`.
pub struct At<'d, K> {
    db: &'d Db,
    tid: Tid,
    key: K,
}

impl<K: ValueKey + Clone + 'static> At<'_, K>
where
    K::T: Clone + PartialEq + 'static,
{
    pub fn get(&self) -> Result<Option<K::T>> {
        let (tid, key) = (self.tid, self.key.clone());
        self.db.leaf(("db.at", tid, key.ak().to_string(), TypeId::of::<K::T>()), move |db| db.at(tid, key.clone()).get())
    }
}

impl<'d, K: ValueKey + Clone + Send + 'static> At<'d, K> {
    pub fn path(&self, p: Path) -> AtPath<'_, 'd, K> {
        AtPath { at: self, p }
    }
}

impl<K: ValueKey + Clone> At<'_, K> {
    pub fn writes(&self, q: &CommitQuery) -> Result<CommitPage> {
        self.db.inner.at(self.tid, self.key.clone()).writes(q)
    }
}

impl<K: SignalKey + Clone> At<'_, K> {
    pub fn fired(&self, q: &CommitQuery) -> Result<CommitPage> {
        self.db.inner.at(self.tid, self.key.clone()).fired(q)
    }
}

/// A position inside an aspect.
pub struct AtPath<'a, 'd, K> {
    at: &'a At<'d, K>,
    p: Path,
}

impl<K: ValueKey + Clone + Send + 'static> AtPath<'_, '_, K> {
    pub fn get<U: osis::Codec + Clone + PartialEq + 'static>(&self) -> Result<Option<U>> {
        let (tid, key, p) = (self.at.tid, self.at.key.clone(), self.p.clone());
        self.at.db.leaf(("db.path", tid, key.ak().to_string(), format!("{p:?}"), TypeId::of::<U>()), move |db| db.at(tid, key.clone()).path(p.clone()).get::<U>())
    }
}

