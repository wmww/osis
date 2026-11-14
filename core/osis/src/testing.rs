//! Test hooks for world copies (notes/test-harnesses.md, Copied worlds): never in a product, where
//! a copy is the same node twice (one identity, session and rng stream, so the two would reuse
//! nonces, counters and commit IDs).

use crate::error::{Error, Result};
use crate::handle::{Inner, LifeGuard, Locked, Osis};
use crate::watch::{Dispatch, Dispatcher, lock};
use osis_base::Clock;
use std::sync::{Arc, Mutex};

impl Osis {
    /// Tests only: an exact copy of this node as it stands, on `clock`: its engine
    /// (`Engine::test_copy`), offers, schemas, the dispatcher's sequence. Fresh: the dispatcher
    /// (callbacks queued so far run on the original first; the copy has no subscriptions, so the
    /// engine has no commit listener), user handles. Refused (`Invalid`) where a part cannot be
    /// copied: a store the engine cannot copy (a directory), a `text_save` hook,
    /// `Dispatcher::Pump`, a runtime (its timers). Inside a world copy (`osis_base::copying`)
    /// with the nodes beside it.
    #[doc(hidden)]
    pub fn test_copy(&self, clock: Arc<dyn Clock>) -> Result<Osis> {
        let i = &self.inner;
        let refuse = |why: &str| Err(Error::Invalid(format!("test_copy: {why}")));
        if i.text_save.is_some() {
            // a closure the two would share
            return refuse("a text_save hook");
        }
        if i.dispatch.pumps() {
            return refuse("Dispatcher::Pump");
        }
        if i.timers {
            return refuse("a runtime");
        }
        i.dispatch.settle(Arc::downgrade(i));
        let mut l = lock(&i.eng);
        let (engine, events) = osis_base::copying::copying(|| -> Result<_> {
            let mut engine = l.engine.test_copy(clock.clone())?;
            // the events the handle had not drained, readable on both
            let pending: Vec<osis_engine::Event> = l.events.try_iter().collect();
            l.events = l.engine.test_subscribe_with(pending.clone(), false);
            let events = engine.test_subscribe_with(pending, false);
            Ok((engine, events))
        })?;
        let locked = Locked { engine, events, seq: l.seq, offers: l.offers.clone() };
        drop(l);
        let inner = Arc::new(Inner {
            eng: Mutex::new(locked),
            dispatch: Dispatch::new(&Dispatcher::Thread),
            node: i.node,
            me: i.me,
            home: i.home,
            limit: i.limit,
            idle_commit: i.idle_commit,
            text_save: None,
            clock,
            schemas: Mutex::new(lock(&i.schemas).clone()),
            undo: Mutex::new(()),
            timers: false,
            life: LifeGuard(Arc::default()),
        });
        inner.dispatch.start(Arc::downgrade(&inner))?;
        Ok(Osis::user(inner))
    }
}
