//! How sync stands and waiting for it (notes/api.md Sync configuration and status;
//! spec/sync-status.md §3): `status` reads sync's status per sync ID, as of its last step, and
//! shows it per thing; `on_status_change` hears it after each step; `wait_synced` and every
//! other call that waits for another node is a future polled again after each step.

use crate::error::{Error, Result};
use crate::handle::{Osis, ReadOnly, WeakOsis};
use crate::watch::{Delivery, Filter, Subscription, lock};
use osis_base::Tid;
use osis_sync::status::SyncStatus;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// How a thing's sync stands here (`GroupSync::state`), best first. A thing syncing under
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
pub struct GroupSync {
    /// Where its sync has got to.
    pub state: SyncState,
    /// Connected nodes with it open that take no more of it for now: full, or refusing what
    /// this node sends. Informational: they are not waited for.
    pub not_taking: usize,
    /// It is no longer synced here, and a connected node still has it open with this node.
    pub leaving: bool,
}

/// How sync stands: connections and each thing this node syncs, read or kept unread.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// Sync connections up now, whichever side dialed.
    pub connected: usize,
    /// How each thing with a sync ID here stands (any thing is a group of itself).
    pub groups: BTreeMap<Tid, GroupSync>,
}

/// What `Osis::wait_synced` waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncScope {
    /// Everything this node syncs and every delivery it owes.
    All,
    /// What this thing travels under: every sync ID carrying it, each with a node connected and
    /// caught up and this node's own changes held there (spec/sync-status.md §3). Runs to the
    /// caller's timeout while one of them has no node connected, or this node does not hold
    /// the thing.
    Thing(Tid),
    /// This node's pending deliveries (grants and other inbox items), nothing else.
    Deliveries,
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

impl ReadOnly {
    /// How sync stands now.
    pub fn status(&self) -> Result<Status> {
        self.locked(|l| {
            let connected = l.node.connections();
            let per_id = l.node.status();
            let mut groups: BTreeMap<Tid, GroupSync> = BTreeMap::new();
            if per_id.is_empty() {
                return Ok(Status { connected, groups });
            }
            let set = l.engine().sync_set()?;
            for (s, st) in per_id {
                let Some((t, _)) = set.ids.get(&s).copied() else { continue };
                let g = GroupSync { state: state_of(&st), not_taking: st.sources.values().filter(|x| !x.waited()).count(), leaving: st.holding.is_none() };
                groups
                    .entry(t)
                    .and_modify(|x| {
                        x.state = x.state.max(g.state);
                        x.not_taking += g.not_taking;
                        x.leaving &= g.leaving;
                    })
                    .or_insert(g);
            }
            Ok(Status { connected, groups })
        })
    }
}

impl Osis {
    /// Calls `f` with the status now and on every change.
    pub fn on_status_change(&self, mut f: impl FnMut(&Osis, Status) + Send + 'static) -> Result<Subscription> {
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
    /// waited for) and each commit of this node's on it held elsewhere, and in `All` and
    /// `Deliveries` every delivery taken. It never resolves while nobody is connected; with no
    /// network (`Runtime::None`) it fails `Network`; `Unsynced` when it can never be done.
    pub async fn wait_synced(&self, scope: SyncScope) -> Result<()> {
        let s = match scope {
            SyncScope::All => osis_sync::types::Scope::All,
            SyncScope::Thing(t) => osis_sync::types::Scope::Thing(t),
            SyncScope::Deliveries => osis_sync::types::Scope::Deliveries,
        };
        self.waiting(move |db| match db.locked(|l| l.node.wait(s)) {
            osis_sync::types::Waiting::Done => Some(Ok(())),
            osis_sync::types::Waiting::Pending => None,
            osis_sync::types::Waiting::Never(_) => Some(Err(Error::Unsynced { groups: match scope {
                SyncScope::Thing(t) => vec![t],
                _ => Vec::new(),
            } })),
        })
        .await
    }

    /// A future that asks `check` now and after each sync step until it answers. With no
    /// network an unanswered first ask fails `Network`: nothing will ever step the node.
    pub(crate) fn waiting<R>(&self, check: impl FnMut(&Osis) -> Option<Result<R>> + Send + Unpin) -> Waiting<impl FnMut(&Osis) -> Option<Result<R>> + Send + Unpin> {
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
        if let Some(r) = (self.check)(&db) {
            return Poll::Ready(r);
        }
        if !self.online {
            return Poll::Ready(Err(Error::Network("no network: nothing would ever sync (Config.runtime)".into())));
        }
        Poll::Pending
    }
}
