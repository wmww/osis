//! Engine access for the CLI's `inspect`, the simulator and test harnesses: not app API, so the
//! whole module is hidden from the docs and `Osis`'s own documentation stays app-only.

use crate::Osis;
use osis_node::sync::{Action, Event, SyncEngine};
use osis_node::Engine;

pub use crate::net::ManualNet;
pub use osis_node as node;

/// The hooks on `Osis` (`use osis::internals::Internals;`). Each panics on a handle attached to a
/// node (`Osis::attach`): its engine is a stand-in, never the node's.
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
    /// Live dispatcher registrations: this process's watches and the client port's
    /// subscriptions it serves.
    fn watches(&self) -> usize;
}

impl Internals for Osis {
    fn engine<R>(&self, f: impl FnOnce(&mut Engine) -> R) -> R {
        here(self);
        Osis::engine(self, f)
    }
    fn sync_engine<R>(&self, f: impl FnOnce(&mut SyncEngine) -> R) -> R {
        here(self);
        self.locked(|l| f(&mut l.sync))
    }
    fn waiting(&self) -> usize {
        here(self);
        self.locked(|l| l.waiters.len())
    }
    fn take_actions(&self) -> Vec<Action> {
        here(self);
        self.inner.net.take()
    }
    fn feed(&self, ev: Event) {
        here(self);
        self.handled(|l| l.sync.handle(ev));
    }
    fn watches(&self) -> usize {
        here(self);
        self.inner.dispatch.registrations()
    }
}

/// Panics on an attached handle (`Internals` reads this process's engine).
fn here(db: &Osis) {
    assert!(!db.is_attached(), "Internals on a handle attached to a node: Unsupported (its engine is a stand-in)");
}
