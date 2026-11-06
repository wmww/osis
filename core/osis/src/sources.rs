//! Sources per group (notes/client-port.md §1, §6): a process's calls go to its own engine or to a
//! node it is connected to, group by group.
//!
//! **Routing invariant.** Each call goes to exactly one source, decided once, under the one lock
//! that also orders every change of the table (`eng`), and never falls back to another source: an
//! unreachable source is that call's `Network`, not another source's answer. No route, result or
//! membership is cached outside that table; a thing's groups are read from the engine's own index
//! at each decision. The rule (`decide_in`), for a thing `t` and S = `t` and the groups holding it
//! here:
//! 1. a process with no store: its connections;
//! 2. a routed group in S: the node of the route, connected or not, whatever else holds `t`;
//! 3. `t` known here: this engine;
//! 4. else the connections, in order: the first that holds `t`, the first unreachable one stopping
//!    the search (a later one must not answer for it); none: this engine, which says unknown.
//!
//! A local write is decided twice for one reason: a route decided Local before a move may run
//! after it, so the commit checks again under its own lock (`guard_local`) and fails rather than
//! land in a group that no longer syncs here. A read decided before a move is ordered before it.
//! `group_source` writes a route before it stops the local sync and drops one only after local
//! sync caught up, so a crash or failure between leaves "routed and synced", which reads remote:
//! there is no moment when this engine's copy answers while behind. A remote copy can: a move away
//! waits for this node's writes to reach a saved peer, not for that node to pull them.
//!
//! **No write is acknowledged and silently never sent.** A write through a route goes out under what
//! that node syncs, so a thing split between a route and a group that carries it here (`split_in`:
//! that group syncs here, or routes to another node) refuses writes (`route_write`): its other
//! holders would miss them with no sign. Reads stay on the route: this engine's copy, fed by the
//! other group alone, never answers. A split cannot always be refused where it starts (a holder of
//! the other group may add the thing to it at any time), so it is a state with one rule, not a
//! refused step: the next write says so, `Status::two_sources` lists it, and moving either group ends it.
//!
//! The port worker (`port::serve`) serves every client of its node one call at a time, so it never
//! waits on another node: a socket client's call that routes there fails `Unsupported`.

use crate::error::{Error, Result};
use crate::handle::{Locked, Osis};
use crate::port::client::Remote;
use crate::port::method;
use crate::share::{Address, Status, SyncScope};
use crate::watch::{Msg, PortEvent};
use osis_base::{Tid, Value};
use osis_node::{ChangeId, Engine};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// The local record of `routes`: a line `tid url#key` per routed group.
const SOURCES: &str = "sources";

/// How to log in to a node (`Osis::connect`, `Osis::connect_node`): where it is and what proves
/// who this client is there. The node says which actor that makes it (`Osis::me`).
#[derive(Clone, Debug)]
pub struct NodeLogin {
    /// Where it is.
    pub addr: Address,
    /// What proves who this client is.
    pub secret: crate::ClientSecret,
}

/// A node this process is a client of, or that a group's source names, and whether the connection
/// is up now (`Status::node_connections`).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct NodeConnection {
    pub address: Address,
    pub connected: bool,
}

/// Where a group's calls go (`Osis::group_source`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupSource {
    /// This node: it syncs the group.
    Local,
    /// The node at this address, which must be connected (`Osis::connect_node`).
    Node(Address),
}

/// Where an API call on a thing or group goes. Every call addressed by a tid or group checks it.
#[derive(Clone)]
pub(crate) enum Route {
    /// This process's engine.
    Local,
    /// The node at this connection.
    Remote(Arc<Remote>),
}

/// A decision made under the lock: `Ask` needs the network, off the lock.
enum Decided {
    Local,
    Remote(Arc<Remote>),
    Ask(Arc<Remote>, Vec<Arc<Remote>>),
}

/// What a watch whose group moved gets (`Delivery::Moved`).
pub(crate) fn moved() -> Error {
    Error::Network("the group's source moved: watch it again".into())
}

/// Whether the group has a live label here.
pub(crate) fn labeled(l: &mut Locked, g: &Tid) -> bool {
    l.sync.engine_mut().labels_of(g).iter().any(|x| !x.replaced)
}

/// The group syncs here: a live label, not held for receipts only.
fn syncs_here(l: &mut Locked, g: &Tid) -> bool {
    !l.sync.receipts_only().contains(g) && labeled(l, g)
}

/// The things commit `id` touched, when this engine holds it.
fn touched_by(e: &Engine, id: ChangeId) -> Option<Vec<Tid>> {
    match id {
        ChangeId::Commit(c) => e.header(&c).map(|h| h.aspects.iter().map(|a| a.tid).collect()),
        ChangeId::Ephemeral(_) => {
            let hit: Vec<Tid> = e.ephemeral_log().iter().filter(|x| x.id == id).flat_map(|x| x.aspects.iter().map(|(t, _)| *t)).collect();
            (!hit.is_empty()).then_some(hit)
        }
    }
}

/// S of the module comment.
fn scope_of(e: &Engine, t: Tid) -> BTreeSet<Tid> {
    let mut s = e.groups_of(&t);
    s.insert(t);
    s
}

fn remote_named(l: &Locked, addr: &Address) -> Arc<Remote> {
    l.remotes.iter().find(|r| r.addr == *addr).cloned().unwrap_or_else(|| Remote::absent(addr))
}

/// The module comment's rule.
fn decide_in(l: &mut Locked, client: bool, tid: Tid) -> Decided {
    if !client {
        let s = scope_of(l.sync.engine(), tid);
        if let Some(addr) = s.iter().find_map(|g| l.routes.get(g)) {
            return Decided::Remote(remote_named(l, addr));
        }
        if l.sync.engine().knows(&tid) {
            return Decided::Local;
        }
    }
    match l.remotes.as_slice() {
        [] => Decided::Local,
        [r] => Decided::Remote(r.clone()),
        rs @ [r, ..] => Decided::Ask(r.clone(), rs.to_vec()),
    }
}

/// The module comment's split: `t` reads at a route, and a group that carries it (its actor may read
/// `t`, spec/sync.md §3) goes elsewhere: it syncs here, or routes to another node. Returns (the
/// routed group, that group). A plain placement carries nothing: no holder of it misses a write.
fn split_in(l: &mut Locked, tid: Tid) -> Option<(Tid, Tid)> {
    let s = scope_of(l.sync.engine(), tid);
    let (routed, addr) = s.iter().find_map(|g| l.routes.get(g).map(|a| (*g, a.clone())))?;
    let other = s.into_iter().find(|g| {
        let elsewhere = match l.routes.get(g) {
            Some(a) => *a != addr,
            None => syncs_here(l, g),
        };
        let e = l.sync.engine();
        elsewhere && e.entitled(&e.group_actor(g), &tid)
    })?;
    Some((routed, other))
}

/// Every split thing: they are all in the closure of a route.
fn split_things(l: &mut Locked) -> BTreeSet<Tid> {
    let inside: BTreeSet<Tid> = l.routes.keys().flat_map(|g| l.sync.engine().closure_placed(g)).collect();
    inside.into_iter().filter(|t| split_in(l, *t).is_some()).collect()
}

/// The connection that answers for a thing known here to none (rule 4).
fn ask(first: &Arc<Remote>, rs: &[Arc<Remote>], tid: Tid) -> Arc<Remote> {
    for r in rs {
        match r.call(method::HOLDS, vec![Value::Tid(tid)]) {
            Ok(Value::Bool(false)) => {}
            // it knows, or cannot say: this call goes there, and fails `Network` if down
            _ => return r.clone(),
        }
    }
    first.clone()
}

impl Osis {
    fn decide(&self, tid: Tid) -> Decided {
        let client = !self.has_store();
        let mut g = crate::watch::lock(&self.inner.eng);
        decide_in(&mut g, client, tid)
    }

    /// `r`, unless this thread must not wait on another node.
    fn reachable(&self, r: Arc<Remote>) -> Arc<Remote> {
        if crate::port::serve::on_worker() {
            return Remote::failing(&r.addr, Error::Unsupported("through this node's daemon, of a thing it does not hold or reads at another node: ask that node".into()));
        }
        r
    }

    /// Whether this thread may wait on another node for something that can do without it: not a
    /// port worker, nor the dispatcher, which runs every callback of this process.
    pub(crate) fn may_wait(&self) -> bool {
        !crate::port::serve::on_worker() && !self.inner.dispatch.shared.on_dispatcher()
    }

    /// Whether routing applies: an acting handle (the port worker's, for a client of this node)
    /// is never routed on: reading through this node's connection would run as this node's
    /// actor there, and it reads only what this engine syncs (`Engine::readable_by`).
    #[inline]
    fn routed(&self) -> bool {
        self.acting.is_none() && self.routing()
    }

    /// Any connection or route exists.
    #[inline]
    pub(crate) fn routing(&self) -> bool {
        self.inner.routing.load(Ordering::Acquire)
    }

    /// The source of calls on `tid`, a thing or a group (the module's invariant).
    #[inline]
    pub(crate) fn route(&self, tid: Tid) -> Route {
        if !self.routed() {
            return Route::Local;
        }
        match self.decide(tid) {
            Decided::Local => Route::Local,
            Decided::Remote(r) => Route::Remote(self.reachable(r)),
            Decided::Ask(first, _) if crate::port::serve::on_worker() => Route::Remote(self.reachable(first)),
            Decided::Ask(first, rs) => Route::Remote(ask(&first, &rs, tid)),
        }
    }

    /// `route` for a call that writes: `Invalid` on a split thing (the module's invariant). The check
    /// comes after the route: a move in between fails it instead of passing a route it never saw.
    pub(crate) fn route_write(&self, tid: Tid) -> Result<Route> {
        let s = self.route(tid);
        self.after_route();
        self.check_split(&[tid])?;
        Ok(s)
    }

    /// `route_all` for a call that writes.
    pub(crate) fn route_write_all(&self, things: &[Tid]) -> Result<Route> {
        let s = self.route_all(things)?;
        self.after_route();
        self.check_split(things)?;
        Ok(s)
    }

    /// `route_scope` for a call that writes. Over a group: whichever of its things the write turns
    /// out to touch, which only the source knows.
    pub(crate) fn route_write_scope(&self, scope: &crate::commits::Scope) -> Result<Route> {
        let s = self.route_scope(Some(scope))?;
        self.after_route();
        match scope {
            crate::commits::Scope::Thing(t) => self.check_split(&[*t])?,
            crate::commits::Scope::Group(g) if self.routed() => {
                let things: Vec<Tid> = self.locked(|l| {
                    let e = l.sync.engine();
                    e.closure_placed(g).into_iter().collect()
                });
                self.check_split(&things)?;
            }
            crate::commits::Scope::Group(_) => {}
            crate::commits::Scope::Aspects(a) => self.check_split(&a.iter().map(|(t, _)| *t).collect::<Vec<_>>())?,
        }
        Ok(s)
    }

    /// `route_commit` for a call that writes. A commit not held here says nothing of what it touched
    /// (a write through a route never comes here): `Invalid` while anything is split.
    pub(crate) fn route_write_commit(&self, id: ChangeId) -> Result<Route> {
        let s = self.route_commit(id)?;
        self.after_route();
        if self.routed() && self.has_store() {
            match self.locked(|l| touched_by(l.engine(), id)) {
                Some(touched) => self.check_split(&touched)?,
                None => {
                    if let Some(t) = self.locked(split_things).first() {
                        return Err(Error::Invalid(format!("a commit this node does not hold may touch {t}, which is split: see `status`")));
                    }
                }
            }
        }
        Ok(s)
    }

    fn check_split(&self, things: &[Tid]) -> Result<()> {
        if !self.routed() || !self.has_store() {
            return Ok(());
        }
        let mut l = crate::watch::lock(&self.inner.eng);
        for t in things {
            if let Some((g, h)) = split_in(&mut l, *t) {
                return Err(Error::Invalid(format!("{t} reads at another node through group {g} and is also in group {h}, whose other holders this write would miss: move {g} home, or {h} to the same node")));
            }
        }
        Ok(())
    }

    /// Whether calls on `t` run on this engine, as far as the lock can say (no network).
    pub(crate) fn is_local(&self, t: Tid) -> bool {
        !self.routed() || matches!(self.decide(t), Decided::Local)
    }

    /// `is_local` under the lock.
    pub(crate) fn local_in(&self, l: &mut Locked, t: Tid) -> bool {
        !self.routed() || matches!(decide_in(l, !self.has_store(), t), Decided::Local)
    }

    /// The one source of calls on all of `things`; `Invalid` when they resolve to two. None: as
    /// a call on no thing (`route_scope(None)`).
    pub(crate) fn route_all(&self, things: &[Tid]) -> Result<Route> {
        let mut out: Option<Route> = None;
        for t in things.iter().collect::<BTreeSet<_>>() {
            let s = self.route(*t);
            match (&out, &s) {
                (None, _) | (Some(Route::Local), Route::Local) => {}
                (Some(Route::Remote(a)), Route::Remote(b)) if Arc::ptr_eq(a, b) => {}
                _ => return Err(Error::Invalid("a call on things at two sources: one call, one source".into())),
            }
            out = Some(s);
        }
        match out {
            Some(s) => Ok(s),
            None => self.route_scope(None),
        }
    }

    /// The source of calls over `scope` (`None`: every held commit; for a process with a store,
    /// its own).
    pub(crate) fn route_scope(&self, scope: Option<&crate::commits::Scope>) -> Result<Route> {
        Ok(match scope {
            Some(crate::commits::Scope::Thing(t) | crate::commits::Scope::Group(t)) => self.route(*t),
            Some(crate::commits::Scope::Aspects(a)) => return self.route_all(&a.iter().map(|(t, _)| *t).collect::<Vec<_>>()),
            None => match self.inner.client.get() {
                Some(t) if self.acting.is_none() => Route::Remote(t.primary.clone()),
                _ => Route::Local,
            },
        })
    }

    /// The source holding commit `id`: of what it touched when this engine holds it; else an
    /// only connection. `Invalid` among several: a commit id does not say whose it is.
    pub(crate) fn route_commit(&self, id: ChangeId) -> Result<Route> {
        if !self.routed() {
            return Ok(Route::Local);
        }
        let client = !self.has_store();
        let (known, remotes) = self.locked(|l| (if client { None } else { touched_by(l.engine(), id) }, l.remotes.clone()));
        match (known, remotes.as_slice()) {
            (Some(ts), _) => self.route_all(&ts),
            (None, []) => Ok(Route::Local),
            (None, [r]) => Ok(Route::Remote(self.reachable(r.clone()))),
            (None, _) => Err(Error::Invalid("a commit this node does not hold, with several nodes connected: revert it through a handle with one".into())),
        }
    }

    /// Under the commit's lock: every thing of a local write is still this engine's.
    pub(crate) fn guard_local(&self, l: &mut Locked, things: &[Tid]) -> Result<()> {
        if !self.routing() {
            return Ok(());
        }
        let client = !self.has_store();
        for t in things {
            if !matches!(decide_in(l, client, *t), Decided::Local) {
                // a client of this node, or a write that lost a race with a move: nothing written
                return Err(if self.acting.is_some() { Error::UnknownThing { tid: *t } } else { moved() });
            }
        }
        Ok(())
    }

    /// Runs a sharing flow's engine step under the lock, its things still this engine's: a step
    /// decided Local before a move fails rather than sit unsent (a revocation the caller believes
    /// happened).
    pub(crate) fn guarded<R>(&self, things: &[Tid], f: impl FnOnce(&mut Engine) -> Result<R>) -> Result<R> {
        self.after_route();
        self.locked(|l| {
            self.guard_local(l, things)?;
            f(l.engine())
        })
    }

    /// A test's way into the gap between a route and its lock (`Internals::after_route`).
    pub(crate) fn after_route(&self) {
        if self.routing()
            && let Some(f) = crate::watch::lock(&self.inner.port.after_route).as_ref()
        {
            f();
        }
    }

    /// `guard_local` for a revert: what the commit touched.
    pub(crate) fn guard_commit(&self, l: &mut Locked, id: ChangeId) -> Result<()> {
        if !self.routing() {
            return Ok(());
        }
        let things = touched_by(l.engine(), id).unwrap_or_default();
        self.guard_local(l, &things)
    }

    /// A status of this engine `local`, with what the connections add: each connected and routed
    /// node with whether it is up, the groups a connected one reports where this node does not
    /// sync them. A disconnected node takes nothing away and adds no group.
    pub(crate) fn merged_status(&self, mut local: Status) -> Result<Status> {
        if !self.routing() {
            return Ok(local);
        }
        let client = !self.has_store();
        let (remotes, routes, split) = self.locked(|l| {
            let mut all = l.remotes.clone();
            for a in l.routes.values() {
                if !all.iter().any(|r| r.addr == *a) {
                    all.push(Remote::absent(a));
                }
            }
            let split = if client { BTreeSet::new() } else { split_things(l) };
            (all, l.routes.clone(), split)
        });
        if client {
            local = Status::default();
        }
        local.two_sources = split;
        for r in remotes {
            local.node_connections.push(NodeConnection { address: r.addr.clone(), connected: r.connected() });
            if !self.may_wait() {
                continue;
            }
            let Ok(v) = r.call(method::STATUS, vec![]) else { continue };
            let Ok(there) = crate::port::codec::status(v) else { continue };
            local.connected = local.connected.saturating_add(there.connected);
            local.two_sources.extend(there.two_sources);
            for (g, s) in there.groups {
                let mine = routes.get(&g).is_some_and(|a| *a == r.addr);
                if mine || !local.groups.contains_key(&g) {
                    local.groups.insert(g, s);
                }
            }
        }
        Ok(local)
    }

    /// Mirrors a schema's source to the connected nodes (notes/client-port.md §1), now and on each
    /// reconnect. A secret client's node takes none from it (`Unsupported`, issues/cli-proxy.md):
    /// that is the caller's error on a process with no store, nothing on a node's own handle,
    /// whose schema stays local for what it reads.
    pub(crate) fn mirror_schema(&self, file: &str, src: &str) -> Result<()> {
        if !self.routing() || crate::port::serve::on_worker() {
            return Ok(());
        }
        let client = !self.has_store();
        for r in self.locked(|l| l.remotes.clone()) {
            match r.call(method::REGISTER_SCHEMA, vec![Value::Str(file.into()), Value::Str(src.into())]) {
                Err(e) if client => return Err(e),
                Err(Error::Unsupported(_)) => {}
                // down: registered when it is up again
                _ => r.remember_schema(file, src),
            }
        }
        Ok(())
    }

    /// Ends the watch of every subscription whose source this table change changed: `change` runs
    /// between looking at each before and after, all under this one lock.
    fn moving<R>(&self, l: &mut Locked, change: impl FnOnce(&mut Locked) -> Result<R>) -> Result<R> {
        let client = !self.has_store();
        let key = |d: Decided| match d {
            Decided::Local => "local".to_string(),
            Decided::Remote(r) => r.addr.to_string(),
            Decided::Ask(..) => "ask".to_string(),
        };
        let subs = self.inner.dispatch.subs_on();
        let before: Vec<String> = subs.iter().map(|(_, _, t)| key(decide_in(l, client, *t))).collect();
        let r = change(l)?;
        for ((id, token, t), was) in subs.iter().zip(before) {
            if key(decide_in(l, client, *t)) == was {
                continue;
            }
            l.seq += 1;
            if *token {
                self.inner.dispatch.send(l.seq, Msg::Port(*id, PortEvent::Closed));
                for x in &l.remotes {
                    x.unsub(*id);
                }
            } else {
                self.inner.dispatch.send(l.seq, Msg::Moved(*id));
            }
        }
        Ok(r)
    }

    /// Moves where `group` is read and written, between this node and a node it is connected to,
    /// never losing a write.
    ///
    /// To `Node(addr)`: the connection must be up and the node know the group (else `Network` or
    /// `UnknownThing`, nothing changed); waits for this node's writes in it to reach a saved peer
    /// (`wait_synced`'s outcomes; failed or dropped, nothing changed); then this
    /// node stops syncing it, for itself alone (`SyncMode::LogOnly`, not `unsync`, which
    /// stops it for every holder), and calls go there. `Invalid`: the account's home group, or a
    /// group still synced here through a parent (its things would have two sources: move the parent). A write made
    /// during the wait fails the move `Unsynced` rather than strand it: call it again.
    ///
    /// To `Local`: this node must hold the group (a program with no store has no keys: `Unsupported`; a node
    /// without it: `Invalid`). It syncs the group again and, until the node's writes reached a saved peer
    /// and this node caught up (`wait_synced`'s outcomes; failed or dropped, syncing goes on and
    /// calling this again finishes the move), calls keep going to the node, so nothing reads this
    /// node's old copy. Works with the node gone (what only it held arrives if it returns).
    /// `Unsynced` here means this node lost the group's keys (`status`: `Stranded`): calls stay at the
    /// node, nothing is lost, and calling again helps once another holder gives the keys again.
    ///
    /// A thing also in a group that syncs here reads at the node like the rest of this one, and
    /// refuses writes (`Invalid`, `Status::two_sources`) until this group comes home or the other moves to
    /// the same node: they would miss the other group's holders.
    ///
    /// Every watch whose source this changes gets one last `Err(Network)` and ends: watch again.
    /// Where it goes survives a restart; a process with no store has none.
    pub async fn group_source(&self, group: Tid, to: GroupSource) -> Result<()> {
        self.local_only("group_source")?;
        match to {
            GroupSource::Node(addr) => self.source_remote(group, addr).await,
            GroupSource::Local => self.source_local(group).await,
        }
    }

    async fn source_remote(&self, group: Tid, addr: Address) -> Result<()> {
        if group == self.me() {
            return Err(Error::Invalid("the home group stays on this node".into()));
        }
        let Some(r) = self.locked(|l| l.remotes.iter().find(|r| r.addr == addr).cloned()) else { return Err(Error::Invalid(format!("not connected to {addr}"))) };
        r.first().await?;
        // Value::Bool(false): the node does not hold it, or the client's actor may not read it
        if r.call_pending(method::HOLDS, vec![Value::Tid(group)]).await? != Value::Bool(true) {
            return Err(Error::UnknownThing { tid: group });
        }
        let (held, live) = self.locked(|l| {
            let held = l.engine().knows(&group);
            (held, syncs_here(l, &group))
        });
        if live {
            self.wait_synced_pending(SyncScope::Thing(group)).await?;
        }
        self.locked(|l| {
            let parents: Vec<Tid> = l.engine().groups_of(&group).into_iter().filter(|p| *p != group && !l.routes.contains_key(p)).collect();
            if parents.iter().any(|p| syncs_here(l, p)) {
                // every write in it would be refused (the module's split)
                return Err(Error::Invalid("this group stays synced here through a group holding it: move that one".into()));
            }
            // written since the wait: never strand it
            if syncs_here(l, &group) && crate::share::synced_now(l, group) != Some(Ok(())) {
                return Err(Error::Unsynced { groups: vec![group] });
            }
            self.moving(l, |l| {
                l.routes.insert(group, addr.clone());
                save_routes(l)?;
                self.inner.routing.store(true, Ordering::Release);
                if held && !l.sync.receipts_only().contains(&group) {
                    let acts = l.sync.set_receipts_only(group, true);
                    self.inner.apply(acts);
                }
                Ok(())
            })
        })
    }

    async fn source_local(&self, group: Tid) -> Result<()> {
        let (held, role, stopped, has_label, route) = self.locked(|l| {
            let held = l.engine().knows(&group);
            let limit = self.inner.limit;
            let role = crate::read::Reader { e: l.engine(), limit, actor: None }.role_on(group);
            let stopped = l.sync.receipts_only().contains(&group);
            (held, role, stopped, labeled(l, &group), l.routes.get(&group).cloned())
        });
        if route.is_none() && !stopped {
            return Ok(());
        }
        if !held || role.is_none() {
            return Err(Error::Invalid("this node does not hold the group: its keys are not here".into()));
        }
        if !has_label {
            // its first label here: needs admin, as `sync`
            self.sync_here(group, &[], true)?;
        }
        if stopped {
            self.act(|l| l.sync.set_receipts_only(group, false));
        }
        // what was written at the node reaches a saved peer first, else this engine would catch up
        // without it; not asked of a node that is gone
        if let Some(r) = route.as_ref().map(|a| self.locked(|l| remote_named(l, a))) {
            self.node_uploaded(&r, group).await?;
        }
        self.wait_synced_pending(SyncScope::Thing(group)).await?;
        self.locked(|l| {
            self.moving(l, |l| {
                l.routes.remove(&group);
                save_routes(l)
            })
        })
    }

    /// Ends the connection to the node at `addr`, and with it what waits on that node there. A group
    /// whose source it is stays so, and fails `Network` until it is connected again or the group moves. `false`: no such connection. `Unsupported` on a
    /// handle with no store of its own.
    pub fn disconnect_node(&self, addr: &Address) -> Result<bool> {
        self.local_only("disconnect_node")?;
        Ok(self.locked(|l| {
            let (gone, kept) = std::mem::take(&mut l.remotes).into_iter().partition::<Vec<_>, _>(|r| r.addr == *addr);
            l.remotes = kept;
            // a call or wait in flight holds it too: it ends now, and they hear so
            gone.iter().for_each(|r| r.end());
            !gone.is_empty()
        }))
    }

    /// The groups whose source is another node, with its address (`group_source`). This process's own
    /// table, so it cannot fail; a handle with no store has none.
    pub fn group_sources(&self) -> BTreeMap<Tid, Address> {
        self.locked(|l| l.routes.clone())
    }
}

fn save_routes(l: &mut Locked) -> Result<()> {
    l.show_routes();
    let text: Vec<String> = l.routes.iter().map(|(g, a)| format!("{} {a}", g.to_uri())).collect();
    l.engine().set_app_record(SOURCES, text.join("\n").as_bytes())?;
    Ok(())
}

impl Locked {
    /// Tells the engine which groups are routed (`Engine::readable_by`).
    pub(crate) fn show_routes(&mut self) {
        let routed = self.routes.keys().copied().collect();
        self.engine().core.routed_away = routed;
    }
}

/// The `sources` record.
pub(crate) fn load_routes(e: &mut Engine) -> Result<BTreeMap<Tid, Address>> {
    let bad = || Error::Storage("sources record".into());
    let Some(b) = e.app_record(SOURCES)? else { return Ok(BTreeMap::new()) };
    let s = String::from_utf8(b).map_err(|_| bad())?;
    s.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (g, a) = l.split_once(' ').ok_or_else(bad)?;
            Ok((Tid::parse(g).map_err(|_| bad())?, a.parse().map_err(|_| bad())?))
        })
        .collect()
}

