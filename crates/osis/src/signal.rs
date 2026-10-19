//! Signals (notes/api.md Signals, spec/sync.md §9): never stored; local listeners fire on the
//! same node, including the sender's own. Delivery to other nodes comes with node-sync (plans/
//! api.md second half): until then `send_signal` reaches local listeners only.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::keys::SignalKey;
use crate::watch::{Delivery, Filter, Msg, SignalMsg, Subscription};
use osis_core::{Role, Tid, WallMs};

/// Who a signal is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    All,
    Node(Tid),
}

/// A received signal.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalEvent<T> {
    pub value: Result<T>,
    pub actor: Tid,
    pub node: Tid,
    pub ts: WallMs,
}

impl Osis {
    /// Sends a signal about `tid` (needs write on it).
    pub fn send_signal<S: SignalKey>(&self, tid: Tid, key: &S, value: &S::T, target: Target) -> Result<()> {
        let v = key.encode(value);
        key.validate(&v)?;
        let tid = self.read(|r| r.resolve(tid));
        if !self.knows(tid) {
            return Err(Error::UnknownThing { tid });
        }
        if self.role_on(tid) < Some(Role::Write) {
            return Err(Error::Permission { tid, needs: Role::Write });
        }
        if target == Target::All || target == Target::Node(self.node()) {
            let (me, node, kind) = (self.me(), self.node(), key.kind().to_string());
            self.locked(|l| {
                l.seq += 1;
                let ts = l.engine.now();
                self.inner.dispatch.send(l.seq, Msg::Signal(SignalMsg { tid, kind, value: v, actor: me, node, ts }));
            });
        }
        Ok(())
    }

    /// Calls `f` with every signal of kind `key` about `tid`.
    pub fn on_signal<S: SignalKey + Send + 'static>(&self, tid: Tid, key: S, mut f: impl FnMut(SignalEvent<S::T>) + Send + 'static) -> Subscription {
        let tid = self.read(|r| r.resolve(tid));
        let kind = key.kind().to_string();
        self.subscribe(Filter::Signal(tid, kind), false, |_| {
            Box::new(move |_, d| {
                if let Delivery::Signal(s) = d {
                    f(SignalEvent { value: key.decode(&s.value).map_err(Error::from), actor: s.actor, node: s.node, ts: s.ts });
                }
            })
        })
    }
}
