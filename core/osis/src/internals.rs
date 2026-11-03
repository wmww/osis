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
    /// A handle acting as `actor`, as the client port serves a thin client's session.
    fn acting_as(&self, actor: osis_base::Tid) -> Osis;
    /// The port worker's next job panics: before running (`false`), or after a Call ran and
    /// before its reply (`true`, the reply is lost).
    fn port_panic_next(&self, after_call: bool);
    /// Pads the next pairing reply the port sends by `n` bytes.
    fn port_pad_pair_reply(&self, n: usize);
    /// Runs `f` between each local write's route and its lock.
    fn after_route(&self, f: Box<dyn Fn() + Send>);
    /// Sets a route with nothing else `group_source` does.
    fn set_route(&self, group: osis_base::Tid, to: Option<String>);
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
    fn acting_as(&self, actor: osis_base::Tid) -> Osis {
        here(self);
        self.act_as(actor)
    }
    fn port_pad_pair_reply(&self, n: usize) {
        self.inner.port.pad_pair_reply.store(n, std::sync::atomic::Ordering::Release);
    }

    fn port_panic_next(&self, after_call: bool) {
        let p = &self.inner.port;
        (if after_call { &p.panic_after_call } else { &p.panic_next }).store(true, std::sync::atomic::Ordering::Release);
    }
    fn after_route(&self, f: Box<dyn Fn() + Send>) {
        *crate::watch::lock(&self.inner.port.after_route) = Some(f);
    }
    fn set_route(&self, group: osis_base::Tid, to: Option<String>) {
        self.inner.routing.store(true, std::sync::atomic::Ordering::Release);
        self.locked(|l| match to {
            Some(a) => l.routes.insert(group, a),
            None => l.routes.remove(&group),
        });
        self.locked(|l| l.show_routes());
    }
}

/// Panics on an attached handle (`Internals` reads this process's engine).
fn here(db: &Osis) {
    assert!(!db.is_attached(), "Internals on a handle attached to a node: Unsupported (its engine is a stand-in)");
}
