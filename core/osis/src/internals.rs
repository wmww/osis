//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_node::sync::{Action, Event, SyncEngine};
use osis_node::Engine;

pub use crate::net::ManualNet;
pub use osis_node as node;

/// The hooks on `Osis` (`use osis::internals::Internals;`).
pub trait Internals {
    /// Runs `f` on the engine under the database lock, then queues its events for the
    /// dispatcher.
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R;
    /// Runs `f` on the sync engine; its actions are carried out.
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R;
    /// Calls waiting for another node right now (a dropped future leaves none).
    fn waiting(&self) -> usize;
    /// With `Runtime::Manual`: the network actions queued so far (the harness carries them).
    fn take_actions(&self) -> Vec<Action>;
    /// With `Runtime::Manual`: feeds a network event.
    fn feed(&self, ev: Event);
}

impl Internals for Osis {
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        Osis::engine(self, f)
    }
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R {
        self.locked(|l| f(&mut l.sync))
    }
    fn waiting(&self) -> usize {
        self.locked(|l| l.waiters.len())
    }
    fn take_actions(&self) -> Vec<Action> {
        self.inner.net.take()
    }
    fn feed(&self, ev: Event) {
        self.handled(|l| l.sync.handle(ev));
    }
}
