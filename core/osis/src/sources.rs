//! Sources per group (notes/client-port.md §1, §6): a process's calls go to its own engine or to a
//! node it is connected to, group by group.
//!
//! **Source invariant.** Each call goes to exactly one source, decided once, under the one lock
//! that also orders every change of the table (`eng`), and never falls back to another source: an
//! unreachable source is that call's `Network`, not another source's answer. No source, result or
//! membership is cached outside that table; a thing's groups are read from the engine's own index
//! at each decision. The rule (`decide_in`), for a thing `t` and S = `t` and the groups holding it
//! here:
//! 1. a process with no store: its connections;
//! 2. a group in S with a source node: that node, connected or not, whatever else holds `t`;
//! 3. `t` known here: this engine;
//! 4. else the connections, in order: the first that holds `t`, the first unreachable one stopping
//!    the search (a later one must not answer for it); none: this engine, which says unknown.
//!
//! A local write is decided twice for one reason: a source decided Local before a move may run
//! after it, so the commit checks again under its own lock (`guard_local`) and fails rather than
//! land in a group that no longer syncs here. A read decided before a move is ordered before it.
//! `group_source` writes a group source before it stops the local sync and drops one only after local
//! sync caught up, so a crash or failure between leaves "sourced at the node and synced", which reads at the node:
//! there is no moment when this engine's copy answers while behind. The node's copy can: a move away
//! waits for this node's writes to reach a saved peer, not for that node to pull them.
//!
//! **No write is acknowledged and silently never sent.** A write through a node goes out under what
//! that node syncs, so a thing split between a source node and a group that carries it here (`split_in`:
//! that group syncs here, or goes to another node) refuses writes (`source_write`): its other
//! holders would miss them with no sign. Reads stay at the node: this engine's copy, fed by the
//! other group alone, never answers. A split cannot always be refused where it starts (a holder of
//! the other group may add the thing to it at any time), so it is a state with one rule, not a
//! refused step: the next write says so, `Status::two_sources` lists it, and moving either group ends it.
//!
//! The port worker (`port::serve`) serves every client of its node one call at a time, so it never
//! waits on another node: a socket client's call that goes there fails `Unsupported`.

use crate::error::{Error, Result};
use crate::handle::{Locked, Osis, ReadOnly};
use crate::port::client::Connection;
use crate::port::method;
use crate::share::{Address, Status, SyncScope};
use crate::watch::{Msg, PortEvent};
use osis_base::{CommitId as RawCommitId, Tid, Value};
use osis_node::Engine;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// The local record of `group_sources`: a line `tid url#key` per group with a source node.
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
pub(crate) enum Source {
    /// This process's engine.
    Local,
    /// The node at this connection.
    Node(Arc<Connection>),
}

/// A decision made under the lock: `Ask` needs the network, off the lock.
enum Decided {
    Local,
    Node(Arc<Connection>),
    Ask(Arc<Connection>, Vec<Arc<Connection>>),
}

/// What a watch whose group moved gets (`Delivery::Moved`).
pub(crate) fn moved() -> Error {
    Error::Network("the group's source moved: watch it again".into())
}

/// Whether the group has a live label here.
pub(crate) fn labeled(l: &mut Locked, g: &Tid) -> bool {
    l.sync.engine_mut().labels_of(g).iter().any(|x| !x.replaced)
}

/// The group syncs here: a live label, not handed off.
fn syncs_here(l: &mut Locked, g: &Tid) -> bool {
    !l.sync.handed_off().contains(g) && labeled(l, g)
}

/// The things commit `id` touched, when this engine holds it.
fn touched_by(e: &Engine, id: RawCommitId) -> Option<Vec<Tid>> {
    e.header(&id).map(|h| h.aspects.iter().map(|a| a.tid).collect())
}

/// S of the module comment.
fn scope_of(e: &Engine, t: Tid) -> BTreeSet<Tid> {
    let mut s = e.groups_of(&t);
    s.insert(t);
    s
}

fn node_named(l: &Locked, addr: &Address) -> Arc<Connection> {
    l.connections.iter().find(|r| r.addr == *addr).cloned().unwrap_or_else(|| Connection::absent(addr))
}

/// The module comment's rule.
fn decide_in(l: &mut Locked, client: bool, tid: Tid) -> Decided {
    if !client {
        let s = scope_of(l.sync.engine(), tid);
        if let Some(addr) = s.iter().find_map(|g| l.group_sources.get(g)) {
            return Decided::Node(node_named(l, addr));
        }
        if l.sync.engine().knows(&tid) {
            return Decided::Local;
        }
    }
    match l.connections.as_slice() {
        [] => Decided::Local,
        [r] => Decided::Node(r.clone()),
        rs @ [r, ..] => Decided::Ask(r.clone(), rs.to_vec()),
    }
}

/// The module comment's split: `t` reads at a source node, and a group that carries it (its actor may read
/// `t`, spec/sync.md §3) goes elsewhere: it syncs here, or goes to another node. Returns (the
/// group with the source node, that group). A membership in a group that does not sync carries nothing: no holder of it misses a write.
fn split_in(l: &mut Locked, tid: Tid) -> Option<(Tid, Tid)> {
    let s = scope_of(l.sync.engine(), tid);
    let (sourced, addr) = s.iter().find_map(|g| l.group_sources.get(g).map(|a| (*g, a.clone())))?;
    // `t`'s own sync ID is no other source: the sourced group's node, a holder of `t`, syncs it too
    let other = s.into_iter().filter(|g| *g != tid).find(|g| {
        let elsewhere = match l.group_sources.get(g) {
            Some(a) => *a != addr,
            None => syncs_here(l, g),
        };
        let e = l.sync.engine();
        elsewhere && e.entitled(&e.group_actor(g), &tid)
    })?;
    Some((sourced, other))
}

/// Every split thing: they are all in the closure of a group with a source node.
fn split_things(l: &mut Locked) -> BTreeSet<Tid> {
    let inside: BTreeSet<Tid> = l.group_sources.keys().flat_map(|g| l.sync.engine().closure(g).iter().copied().collect::<Vec<_>>()).collect();
    inside.into_iter().filter(|t| split_in(l, *t).is_some()).collect()
}

/// The connection that answers for a thing known here to none (rule 4).
fn ask(first: &Arc<Connection>, rs: &[Arc<Connection>], tid: Tid) -> Arc<Connection> {
    for r in rs {
        match r.call(method::HOLDS, vec![Value::Tid(tid)]) {
            Ok(Value::Bool(false)) => {}
            // it knows, or cannot say: this call goes there, and fails `Network` if down
            _ => return r.clone(),
        }
    }
    first.clone()
}

impl ReadOnly {
    fn decide(&self, tid: Tid) -> Decided {
        let client = !self.has_store();
        let mut g = crate::watch::lock(&self.inner.eng);
        decide_in(&mut g, client, tid)
    }

    /// `r`, unless this thread must not wait on another node.
    fn reachable(&self, r: Arc<Connection>) -> Arc<Connection> {
        if crate::port::serve::on_worker() {
            return Connection::failing(&r.addr, Error::Unsupported("through this node's daemon, of a thing it does not hold or reads at another node: ask that node".into()));
        }
        r
    }

    /// Whether this thread may wait on another node for something that can do without it: not a
    /// port worker, nor the dispatcher, which runs every callback of this process.
    pub(crate) fn may_wait(&self) -> bool {
        !crate::port::serve::on_worker() && !self.inner.dispatch.shared.on_dispatcher()
    }

    /// Whether sources apply: an acting handle (the port worker's, for a client of this node)
    /// always reads here: reading through this node's connection would run as this node's
    /// actor there, and it reads only what this engine syncs (`Engine::readable_by`).
    #[inline]
    fn sources_apply(&self) -> bool {
        self.acting.is_none() && self.has_sources()
    }

    /// Any connection or group source exists.
    #[inline]
    pub(crate) fn has_sources(&self) -> bool {
        self.inner.has_sources.load(Ordering::Acquire)
    }

    /// The source of calls on `tid`, a thing or a group (the module's invariant).
    #[inline]
    pub(crate) fn source(&self, tid: Tid) -> Source {
        if !self.sources_apply() {
            return Source::Local;
        }
        match self.decide(tid) {
            Decided::Local => Source::Local,
            Decided::Node(r) => Source::Node(self.reachable(r)),
            Decided::Ask(first, _) if crate::port::serve::on_worker() => Source::Node(self.reachable(first)),
            Decided::Ask(first, rs) => Source::Node(ask(&first, &rs, tid)),
        }
    }

    /// `source` for a call that writes: `Invalid` on a split thing (the module's invariant). The check
    /// comes after the source: a move in between fails it instead of passing a source it never saw.
    pub(crate) fn source_write(&self, tid: Tid) -> Result<Source> {
        let s = self.source(tid);
        self.after_source();
        self.check_split(&[tid])?;
        Ok(s)
    }

    /// `source_all` for a call that writes.
    pub(crate) fn source_write_all(&self, things: &[Tid]) -> Result<Source> {
        let s = self.source_all(things)?;
        self.after_source();
        self.check_split(things)?;
        Ok(s)
    }

    /// `source_scope` for a call that writes. Over a group: whichever of its things the write turns
    /// out to touch, which only the source knows.
    pub(crate) fn source_write_scope(&self, scope: &crate::commits::Scope) -> Result<Source> {
        let s = self.source_scope(Some(scope))?;
        self.after_source();
        match scope {
            crate::commits::Scope::Thing(t) => self.check_split(&[*t])?,
            crate::commits::Scope::Group(g) if self.sources_apply() => {
                let things: Vec<Tid> = self.locked(|l| {
                    let e = l.sync.engine();
                    e.closure(g).iter().copied().collect()
                });
                self.check_split(&things)?;
            }
            crate::commits::Scope::Group(_) => {}
            crate::commits::Scope::Aspects(a) => self.check_split(&a.iter().map(|(t, _)| *t).collect::<Vec<_>>())?,
        }
        Ok(s)
    }

    /// `source_commit` for a call that writes. A commit not held here says nothing of what it touched
    /// (a write through a node never comes here): `Invalid` while anything is split.
    pub(crate) fn source_write_commit(&self, id: RawCommitId) -> Result<Source> {
        let s = self.source_commit(id)?;
        self.after_source();
        if self.sources_apply() && self.has_store() {
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
        if !self.sources_apply() || !self.has_store() {
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
        !self.sources_apply() || matches!(self.decide(t), Decided::Local)
    }

    /// `is_local` under the lock.
    pub(crate) fn local_in(&self, l: &mut Locked, t: Tid) -> bool {
        !self.sources_apply() || matches!(decide_in(l, !self.has_store(), t), Decided::Local)
    }

    /// The one source of calls on all of `things`; `Invalid` when they resolve to two. None: as
    /// a call on no thing (`source_scope(None)`).
    pub(crate) fn source_all(&self, things: &[Tid]) -> Result<Source> {
        let mut out: Option<Source> = None;
        for t in things.iter().collect::<BTreeSet<_>>() {
            let s = self.source(*t);
            match (&out, &s) {
                (None, _) | (Some(Source::Local), Source::Local) => {}
                (Some(Source::Node(a)), Source::Node(b)) if Arc::ptr_eq(a, b) => {}
                _ => return Err(Error::Invalid("a call on things at two sources: one call, one source".into())),
            }
            out = Some(s);
        }
        match out {
            Some(s) => Ok(s),
            None => self.source_scope(None),
        }
    }

    /// The source of calls over `scope` (`None`: every held commit; for a process with a store,
    /// its own).
    pub(crate) fn source_scope(&self, scope: Option<&crate::commits::Scope>) -> Result<Source> {
        Ok(match scope {
            Some(crate::commits::Scope::Thing(t) | crate::commits::Scope::Group(t)) => self.source(*t),
            Some(crate::commits::Scope::Aspects(a)) => return self.source_all(&a.iter().map(|(t, _)| *t).collect::<Vec<_>>()),
            None => match self.inner.client.get() {
                Some(t) if self.acting.is_none() => Source::Node(t.primary.clone()),
                _ => Source::Local,
            },
        })
    }

    /// The source holding commit `id`: of what it touched when this engine holds it; else an
    /// only connection. `Invalid` among several: a commit id does not say whose it is.
    pub(crate) fn source_commit(&self, id: RawCommitId) -> Result<Source> {
        if !self.sources_apply() {
            return Ok(Source::Local);
        }
        let client = !self.has_store();
        let (known, connections) = self.locked(|l| (if client { None } else { touched_by(l.engine(), id) }, l.connections.clone()));
        match (known, connections.as_slice()) {
            (Some(ts), _) => self.source_all(&ts),
            (None, []) => Ok(Source::Local),
            (None, [r]) => Ok(Source::Node(self.reachable(r.clone()))),
            (None, _) => Err(Error::Invalid("a commit this node does not hold, with several nodes connected: revert it through a handle with one".into())),
        }
    }

    /// Under the commit's lock: every thing of a local write is still this engine's.
    pub(crate) fn guard_local(&self, l: &mut Locked, things: &[Tid]) -> Result<()> {
        if !self.has_sources() {
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
        self.after_source();
        self.locked(|l| {
            self.guard_local(l, things)?;
            f(l.engine())
        })
    }

    /// A test's way into the gap between a source decision and its lock (`Internals::after_source`).
    pub(crate) fn after_source(&self) {
        if self.has_sources()
            && let Some(f) = crate::watch::lock(&self.inner.port.after_source).as_ref()
        {
            f();
        }
    }

    /// `guard_local` for a revert: what the commit touched.
    pub(crate) fn guard_commit(&self, l: &mut Locked, id: RawCommitId) -> Result<()> {
        if !self.has_sources() {
            return Ok(());
        }
        let things = touched_by(l.engine(), id).unwrap_or_default();
        self.guard_local(l, &things)
    }

    /// A status of this engine `local`, with what the connections add: each connected or source
    /// node with whether it is up, the groups a connected one reports where this node does not
    /// sync them. A group with a source node shows only what that node reports: never this
    /// engine's copy, which is behind or catching up.
    pub(crate) fn merged_status(&self, mut local: Status) -> Result<Status> {
        if !self.has_sources() {
            return Ok(local);
        }
        let client = !self.has_store();
        let (connections, group_sources, split) = self.locked(|l| {
            let mut all = l.connections.clone();
            for a in l.group_sources.values() {
                if !all.iter().any(|r| r.addr == *a) {
                    all.push(Connection::absent(a));
                }
            }
            let split = if client { BTreeSet::new() } else { split_things(l) };
            (all, l.group_sources.clone(), split)
        });
        if client {
            local = Status::default();
        }
        local.groups.retain(|g, _| !group_sources.contains_key(g));
        local.two_sources = split;
        for r in connections {
            local.node_connections.push(NodeConnection { address: r.addr.clone(), connected: r.connected() });
            if !self.may_wait() {
                continue;
            }
            let Ok(v) = r.call(method::STATUS, vec![]) else { continue };
            let Ok(there) = crate::port::codec::status(v) else { continue };
            local.connected = local.connected.saturating_add(there.connected);
            local.two_sources.extend(there.two_sources);
            for (g, s) in there.groups {
                // a group with a source node: that node's word alone, never another connection's
                let mine = group_sources.get(&g).map(|a| *a == r.addr);
                if mine.unwrap_or(!local.groups.contains_key(&g)) {
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
        if !self.has_sources() || crate::port::serve::on_worker() {
            return Ok(());
        }
        let client = !self.has_store();
        for r in self.locked(|l| l.connections.clone()) {
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
            Decided::Node(r) => r.addr.to_string(),
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
                for x in &l.connections {
                    x.unsub(*id);
                }
            } else {
                self.inner.dispatch.send(l.seq, Msg::Moved(*id));
            }
        }
        Ok(r)
    }

}

impl Osis {
    /// Moves where `group` is read and written, between this node and a node it is connected to,
    /// never losing a write.
    ///
    /// To `Node(addr)`: the connection must be up and the node know the group (else `Network` or
    /// `UnknownThing`, nothing changed); waits for this node's writes in it to reach a saved peer
    /// (`wait_synced`'s outcomes; failed or dropped, nothing changed; what is written or arrives meanwhile
    /// is waited for too); then this
    /// node stops syncing it, for itself alone, and calls go there. `Invalid`: the account's home group, or a
    /// group still synced here through a parent (its things would have two sources: move the parent).
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
    /// `status` shows the group as its source node does. Where it goes survives a restart and reads
    /// back with `group_sources`; a process with no store has none.
    pub async fn group_source(&self, group: Tid, to: GroupSource) -> Result<()> {
        self.local_only("group_source")?;
        match to {
            GroupSource::Node(addr) => self.source_node(group, addr).await,
            GroupSource::Local => self.source_local(group).await,
        }
    }

    async fn source_node(&self, group: Tid, addr: Address) -> Result<()> {
        if group == self.home() {
            return Err(Error::Invalid("the home group stays on this node".into()));
        }
        let Some(r) = self.locked(|l| l.connections.iter().find(|r| r.addr == addr).cloned()) else { return Err(Error::Invalid(format!("not connected to {addr}"))) };
        r.first().await?;
        // Value::Bool(false): the node does not hold it, or the client's actor may not read it
        if r.call_pending(method::HOLDS, vec![Value::Tid(group)]).await? != Value::Bool(true) {
            return Err(Error::UnknownThing { tid: group });
        }
        loop {
            if self.locked(|l| syncs_here(l, &group)) {
                self.wait_synced_pending(SyncScope::Thing(group)).await?;
            }
            let moved = self.locked(|l| {
                let parents: Vec<Tid> = l.engine().groups_of(&group).into_iter().filter(|p| *p != group && !l.group_sources.contains_key(p)).collect();
                if parents.iter().any(|p| syncs_here(l, p)) {
                    // every write in it would be refused (the module's split)
                    return Err(Error::Invalid("this group stays synced here through a group holding it: move that one".into()));
                }
                // the group arrived, or something was written, since the wait: wait again, never strand it
                if syncs_here(l, &group) {
                    match crate::share::synced_now(l, group) {
                        Some(Ok(())) => {}
                        Some(Err(e)) => return Err(e),
                        None => return Ok(false),
                    }
                }
                self.moving(l, |l| {
                    l.group_sources.insert(group, addr.clone());
                    save_sources(l)?;
                    self.inner.has_sources.store(true, Ordering::Release);
                    if !l.sync.handed_off().contains(&group) {
                        let acts = l.sync.set_handed_off(group, true);
                        self.inner.apply(acts);
                    }
                    Ok(())
                })?;
                Ok(true)
            })?;
            if moved {
                return Ok(());
            }
        }
    }

    async fn source_local(&self, group: Tid) -> Result<()> {
        let (held, role, away, has_label, at) = self.locked(|l| {
            let held = l.engine().knows(&group);
            let limit = self.inner.limit;
            let role = crate::read::Reader { e: l.engine(), limit, actor: None }.role_on(group);
            let away = l.sync.handed_off().contains(&group);
            (held, role, away, labeled(l, &group), l.group_sources.get(&group).cloned())
        });
        if at.is_none() && !away {
            return Ok(());
        }
        if !held || role?.is_none() {
            return Err(Error::Invalid("this node does not hold the group: its keys are not here".into()));
        }
        if !has_label {
            // its first label here: needs admin, as `sync`
            self.sync_here(group, &[], true)?;
        }
        if away {
            self.act(|l| l.sync.set_handed_off(group, false));
        }
        // what was written at the node reaches a saved peer first, else this engine would catch up
        // without it; not asked of a node that is gone
        if let Some(r) = at.as_ref().map(|a| self.locked(|l| node_named(l, a))) {
            self.node_uploaded(&r, group).await?;
        }
        self.wait_synced_pending(SyncScope::Thing(group)).await?;
        self.locked(|l| {
            self.moving(l, |l| {
                l.group_sources.remove(&group);
                save_sources(l)
            })
        })
    }

    /// Ends the connection to the node at `addr`, and with it what waits on that node there. A group
    /// whose source it is stays so, and fails `Network` until it is connected again or the group moves. `false`: no such connection. `Unsupported` on a
    /// handle with no store of its own.
    pub fn disconnect_node(&self, addr: &Address) -> Result<bool> {
        self.local_only("disconnect_node")?;
        Ok(self.locked(|l| {
            let (gone, kept) = std::mem::take(&mut l.connections).into_iter().partition::<Vec<_>, _>(|r| r.addr == *addr);
            l.connections = kept;
            // a call or wait in flight holds it too: it ends now, and they hear so
            gone.iter().for_each(|r| r.end());
            !gone.is_empty()
        }))
    }

    /// The groups whose source is another node, with its address (`group_source`). This process's own
    /// table, so it cannot fail; a handle with no store has none.
    pub fn group_sources(&self) -> BTreeMap<Tid, Address> {
        self.locked(|l| l.group_sources.clone())
    }
}

fn save_sources(l: &mut Locked) -> Result<()> {
    l.show_sources();
    let text: Vec<String> = l.group_sources.iter().map(|(g, a)| format!("{} {a}", g.to_uri())).collect();
    l.engine().set_app_record(SOURCES, text.join("\n").as_bytes())?;
    Ok(())
}

impl Locked {
    /// Tells the engine which groups are sourced at another node (`Engine::readable_by`).
    pub(crate) fn show_sources(&mut self) {
        let sourced = self.group_sources.keys().copied().collect();
        self.engine().core.sourced_elsewhere = sourced;
    }
}

/// The `sources` record.
pub(crate) fn load_sources(e: &mut Engine) -> Result<BTreeMap<Tid, Address>> {
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

