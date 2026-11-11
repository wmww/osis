//! Test hooks for world copies (notes/testing.md, Copied worlds), reached through
//! `ManualNet::test_copy`: never in a product, where a copy is the same
//! node twice (one identity, session and rng stream, so the two would reuse nonces, counters and
//! commit IDs).

use crate::error::{Error, Result};
use crate::handle::{Inner, LifeGuard, Locked, Osis, WeakOsis};
use crate::net::{ManualNet, Net, Runtime};
use crate::watch::{Dispatch, Dispatcher, lock};
use osis_base::Clock;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

impl Osis {
    /// An exact copy of this node as it stands, on `clock`, driven by `runtime` (`None` or a
    /// `Manual` registry the copy joins, as the original's; `ManualNet::test_copy`): its sync engine
    /// (`SyncEngine::test_copy`), status, offers, schemas, group sources, the network actions not
    /// yet taken, the dispatcher's sequence. Fresh: the dispatcher (callbacks queued so far run on
    /// the original first; the copy has no subscriptions, so the engine has no commit listener),
    /// user handles. Refused (`Invalid`) where a part cannot be copied: a thin client, a store in
    /// a directory, in-process transport, `Dispatcher::Pump`, a runtime other than `None` or
    /// `Manual`, a call still waiting for another node, a connection to another node, a client
    /// port that ran. Inside a world copy (`osis_base::copying`) with the nodes beside it.
    pub(crate) fn test_copy(&self, clock: Arc<dyn Clock>, runtime: &Runtime) -> Result<Osis> {
        let i = &self.inner;
        let refuse = |why: &str| Err(Error::Invalid(format!("test_copy: {why}")));
        if i.client.get().is_some() || i.store_dir.is_some() || i.transport.is_some() {
            return refuse("a thin client, a store in a directory or in-process transport");
        }
        if i.dispatch.pumps() {
            return refuse("Dispatcher::Pump");
        }
        if !i.port.idle() {
            return refuse("a client port that ran");
        }
        let net = match (&i.net, runtime) {
            (Net::Off, Runtime::None) => Net::Off,
            (Net::Manual(q), Runtime::Manual(_)) => Net::Manual(Mutex::new(lock(q).clone())),
            _ => return refuse("a runtime other than None or Manual, or another than the original's"),
        };
        i.dispatch.settle(Arc::downgrade(i));
        let mut l = lock(&i.eng);
        if !l.waiters.is_empty() || !l.connections.is_empty() {
            return refuse("a call waiting for another node, or a connection to one");
        }
        let (sync, events) = osis_base::copying::copying(|| -> Result<_> {
            let mut sync = l.sync.test_copy(clock.clone())?;
            // the events the handle had not drained, readable on both
            let pending: Vec<osis_node::Event> = l.events.try_iter().collect();
            l.events = l.sync.engine_mut().test_subscribe_with(pending.clone(), false);
            let events = sync.engine_mut().test_subscribe_with(pending, false);
            Ok((sync, events))
        })?;
        let locked = Locked { sync, events, seq: l.seq, waiters: Vec::new(), status: l.status.clone(), offers: l.offers.clone(), connections: Vec::new(), group_sources: l.group_sources.clone(), status_failed: l.status_failed };
        drop(l);
        let port = crate::port::serve::Port::new();
        port.panic_next.store(i.port.panic_next.load(Ordering::Acquire), Ordering::Release);
        port.panic_after_call.store(i.port.panic_after_call.load(Ordering::Acquire), Ordering::Release);
        port.pad_pair_reply.store(i.port.pad_pair_reply.load(Ordering::Acquire), Ordering::Release);
        let inner = Arc::new(Inner {
            eng: Mutex::new(locked),
            dispatch: Dispatch::new(&Dispatcher::Thread),
            node: i.node,
            me: i.me,
            home: i.home,
            limit: i.limit,
            idle_commit: i.idle_commit,
            text_save: i.text_save.clone(),
            transport: None,
            store_dir: None,
            dials_peers: i.dials_peers,
            connection_wait: i.connection_wait,
            clock,
            schemas: Mutex::new(lock(&i.schemas).clone()),
            undo: Mutex::new(()),
            net,
            port,
            client: std::sync::OnceLock::new(),
            has_sources: i.has_sources.load(Ordering::Acquire).into(),
            life: LifeGuard(Arc::default()),
        });
        inner.dispatch.start(Arc::downgrade(&inner))?;
        let db = Osis::user(inner);
        if let Runtime::Manual(m) = runtime {
            m.register(db.downgrade());
        }
        Ok(db)
    }
}

impl ManualNet {
    /// Tests only: a registry of exact copies (`Osis::test_copy`) of every node this one
    /// drives, in start order, a closed node closed in it too; each copy on the clock
    /// `clock_of` maps its original's clock to. With the copies, by start order (`None`: closed):
    /// a copy is open while a handle to it is held. Inside a world copy (`osis_base::copying`).
    #[doc(hidden)]
    pub fn test_copy(&self, clock_of: impl Fn(&Arc<dyn Clock>) -> Arc<dyn Clock>) -> Result<(ManualNet, Vec<Option<Osis>>)> {
        osis_base::copying::copying(|| {
            let net = ManualNet::new();
            let mut dbs = Vec::new();
            for db in self.dbs() {
                match db {
                    Some(db) => dbs.push(Some(db.test_copy(clock_of(&db.inner.clock), &Runtime::Manual(net.clone()))?)),
                    None => {
                        lock(&net.0).push(WeakOsis(std::sync::Weak::<Inner>::new()));
                        dbs.push(None);
                    }
                }
            }
            Ok((net, dbs))
        })
    }
}
