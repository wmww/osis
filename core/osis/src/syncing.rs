//! How sync stands and waiting for it (notes/api.md Sync configuration and status;
//! spec/sync-status.md §3): `status` reads sync's status per sync ID, as of its last step, and
//! shows it per thing; `on_status_change` hears it after each step; `wait_synced` and every
//! other call that waits for another node is a future polled again after each step.

use crate::error::{Error, Result};
use crate::handle::{Locked, Osis, ReadOnly, WeakOsis};
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::Tid;
use osis_sync::status::SyncStatus;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// How a thing's sync stands here (`UnitSync::state`), best first. A thing syncing under
/// several sync IDs shows the worst of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SyncState {
    /// A node is connected with it open, each such node caught up both ways, and every commit
    /// of this node's on it held elsewhere.
    Synced,
    /// A node is connected with it open, and something is still on its way.
    Syncing,
    /// No node is connected with it open: what is written here stays here for now.
    NotConnected,
    /// This node holds no key to read what its peers hold now (lost, or not given yet), and can
    /// read nothing new until another holder gives them again.
    Stranded,
}

/// How one thing syncs here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitSync {
    /// Where its sync has got to.
    pub state: SyncState,
    /// Connected nodes with it open that take no more of it for now: full, or refusing what
    /// this node sends. Informational: they are not waited for.
    pub not_taking: usize,
}

/// How sync stands: connections and each thing this node syncs, read or kept unread.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Sync connections up now, whichever side dialed.
    pub connected: usize,
    /// How each thing with a sync ID here stands.
    pub units: BTreeMap<Tid, UnitSync>,
}

/// What `Osis::wait_synced` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    /// Everything this node syncs.
    All,
    /// What this thing travels under: every sync ID carrying it, each with a node connected and
    /// caught up and this node's own changes held there (spec/sync-status.md §3). Runs to the
    /// caller's timeout while one of them has no node connected, or this node does not hold
    /// the thing.
    Thing(Tid),
}

/// A thing's state from its sync IDs' (worst first).
fn state_of(s: &SyncStatus) -> SyncState {
    if s.stranded {
        SyncState::Stranded
    } else if s.sources.is_empty() {
        SyncState::NotConnected
    } else if s.synced() {
        SyncState::Synced
    } else {
        SyncState::Syncing
    }
}

/// How sync stands, as `actor` may see it (notes/client-port.md §3 Status): the things it may
/// read, and the connections with one of them open; everything without one.
pub(crate) fn status_in(l: &mut Locked, actor: Option<Tid>) -> Result<Status> {
    let per_id = l.node.status();
    let mut connected = l.node.connections();
    let mut units: BTreeMap<Tid, UnitSync> = BTreeMap::new();
    if per_id.is_empty() {
        return Ok(Status { connected: if actor.is_some() { 0 } else { connected }, units });
    }
    // what this node syncs: the sync set, and each sync ID that left it while it waits to stop
    let syncs = l.node.store().syncs();
    let e = l.engine();
    let mut seen = std::collections::BTreeSet::new();
    for (s, st) in per_id {
        let Some((things, _)) = syncs.get(&s) else { continue };
        // how S stands is how each of its things stands under it
        for t in things {
            if actor.is_some_and(|a| !e.readable_by(&a, t)) {
                continue;
            }
            seen.extend(st.sources.keys().copied());
            let g = UnitSync { state: state_of(&st), not_taking: st.sources.values().filter(|x| !x.waited()).count() };
            merge(&mut units, *t, g);
        }
    }
    if actor.is_some() {
        connected = seen.len();
    }
    Ok(Status { connected, units })
}

/// Adds `g`, how `t` stands under one sync ID or at one node, to `units`: the worst state.
pub(crate) fn merge(units: &mut BTreeMap<Tid, UnitSync>, t: Tid, g: UnitSync) {
    units
        .entry(t)
        .and_modify(|x| {
            x.state = x.state.max(g.state);
            x.not_taking += g.not_taking;
        })
        .or_insert(g);
}

impl ReadOnly {
    /// How sync stands now. On a thin client, at its nodes: the things its actor may read
    /// there, and their connections with one of them open.
    pub fn status(&self) -> Result<Status> {
        if !self.has_store() {
            return self.remote_status();
        }
        self.locked(|l| status_in(l, self.acting))
    }
}

impl Osis {
    /// Calls `f` with the status now and on every change.
    pub fn on_status_change(&self, mut f: impl FnMut(&Osis, Status) + Send + 'static) -> Result<Subscription> {
        if !self.has_store() {
            return self.remote_status_watch(f);
        }
        let mut last = self.status()?;
        let first = last.clone();
        let mut told = false;
        Ok(self.subscribe(Filter::Status, true, move |_| {
            Box::new(move |db, d| match d {
                Delivery::Initial if !told => {
                    told = true;
                    f(db, first.clone());
                }
                Delivery::Due => {
                    if let Ok(s) = db.status()
                        && s != last
                    {
                        last = s.clone();
                        f(db, s);
                    }
                }
                _ => {}
            })
        }))
    }

    /// Resolves once everything in `scope` is synced: each sync ID carrying it heard out (every
    /// connected node with it open caught up both ways, none of them full or refusing it left
    /// waited for) and each commit of this node's on it held elsewhere. A sync ID no other node
    /// may hold (no other account has a role on its thing, no other node of this account) holds
    /// nothing up; it never
    /// resolves while one some other node may hold is unconnected.
    /// It fails `Stranded` while a sync ID in scope is stranded here (naming its things); with no
    /// network (`Runtime::None`) one not done at once fails `Network`.
    pub async fn wait_synced(&self, scope: SyncScope) -> Result<()> {
        if let Some(at) = self.process_at("wait_synced")? {
            return self.remote_wait(&at, crate::port::method::WAIT_SYNCED, (scope,))?.await;
        }
        self.syncing(scope).await
    }

    /// `wait_synced` here, as a future holding nothing of the node (the port runs it for a main
    /// session).
    pub(crate) fn syncing(&self, scope: SyncScope) -> impl Future<Output = Result<()>> + Send + 'static {
        let s = match scope {
            SyncScope::All => osis_sync::types::Scope::All,
            SyncScope::Thing(t) => osis_sync::types::Scope::Thing(t),
        };
        self.waiting(move |db| match db.locked(|l| l.node.wait(s)) {
            osis_sync::types::Waiting::Done => Some(Ok(())),
            osis_sync::types::Waiting::Pending => None,
            // a stranded sync ID fails the wait (notes/api-design.md), naming the things whose
            // sync IDs are stranded
            osis_sync::types::Waiting::Stranded(ids) => Some(db.locked(|l| {
                let mut things = Vec::new();
                for s in &ids {
                    things.extend(l.engine().sync_owners(s)?);
                }
                things.sort();
                things.dedup();
                Err(Error::Stranded { things })
            })),
            // spec/sync-status.md §3 has no wait sure never to end: sync's `Never` here is a part
            // of it not built yet, never an answer about the thing
            osis_sync::types::Waiting::Never(_) => Some(Err(Error::NotBuilt)),
        })
    }

    /// A future that asks `check` now and after each sync step until it answers. With no
    /// network anything but success fails `Network` at once: nothing will ever step the node.
    pub(crate) fn waiting<R, F: FnMut(&Osis) -> Option<Result<R>> + Send + Unpin>(&self, check: F) -> Waiting<F> {
        Waiting { db: self.downgrade(), check, online: self.inner.net.online() }
    }
}

/// A wait on sync (`Osis::waiting`): runtime-agnostic, polled again after each sync step;
/// dropping it leaves nothing behind.
pub(crate) struct Waiting<F> {
    db: WeakOsis,
    check: F,
    online: bool,
}

impl<R, F: FnMut(&Osis) -> Option<Result<R>> + Unpin> Future for Waiting<F> {
    type Output = Result<R>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<R>> {
        let Some(db) = self.db.hold() else { return Poll::Ready(Err(Error::Closed)) };
        // registered before asking: a step between the two wakes it
        {
            let mut w = lock(&db.inner.waiters);
            if !w.iter().any(|x| x.will_wake(cx.waker())) {
                w.push(cx.waker().clone());
            }
        }
        match (self.check)(&db) {
            Some(Ok(r)) => Poll::Ready(Ok(r)),
            _ if !self.online => Poll::Ready(Err(Error::Network("no network: nothing would ever sync (Config.runtime)".into()))),
            Some(Err(e)) => Poll::Ready(Err(e)),
            None => Poll::Pending,
        }
    }
}
