//! Signals (notes/api.md Signals, spec/sync.md §9): never stored; local listeners fire on the
//! same node, including the sender's own; connected nodes reading the thing under an open label
//! receive them best effort.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::keys::SignalKey;
use crate::watch::{Delivery, Filter, Subscription};
use osis_core::{Ak, Role, Tid, WallMs};

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
        let kind = Ak::new(key.kind()).map_err(|_| Error::Invalid(format!("bad signal kind {:?}", key.kind())))?;
        let target = match target {
            Target::All => None,
            Target::Node(n) => Some(n),
        };
        let me = self.me();
        self.locked(|l| -> Result<()> {
            let acts = l.sync.signal_as(&tid, me, kind, v, target)?;
            self.inner.net.apply(acts);
            Ok(())
        })
    }

    /// Calls `f` with every signal of kind `key` about `tid`.
    pub fn on_signal<S: SignalKey + Send + 'static>(&self, tid: Tid, key: S, mut f: impl FnMut(&Osis, SignalEvent<S::T>) + Send + 'static) -> Subscription {
        let tid = self.read(|r| r.resolve(tid));
        let kind = key.kind().to_string();
        self.subscribe(Filter::Signal(tid, kind), false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Signal(s) = d {
                    f(db, SignalEvent { value: key.decode(&s.value).map_err(Error::from), actor: s.actor, node: s.node, ts: s.ts });
                }
            })
        })
    }
}
