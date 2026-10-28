//! Signals (notes/api.md Signals, spec/sync.md §9): never stored; local listeners fire on the
//! same node, including the sender's own; connected nodes reading the thing under an open label
//! receive them best effort.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::watch::{Delivery, Filter, Subscription};
use osis_base::{Ak, Role, Tid, WallMs};
use osis_schema::SignalKey;

/// Who a signal is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    All,
    Node(Tid),
}

/// A received signal.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalEvent<T> {
    /// The thing the signal is about.
    pub tid: Tid,
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
        self.try_act(|l| Ok(l.sync.signal_as(&tid, me, kind, v, target)?))
    }

    /// Calls `f` with every signal of kind `key` about `tid`.
    pub fn on_signal<S: SignalKey + Send + 'static>(&self, tid: Tid, key: S, f: impl FnMut(&Osis, SignalEvent<S::T>) + Send + 'static) -> Subscription {
        let tid = self.read(|r| r.resolve(tid));
        let kind = key.kind().to_string();
        self.signal_sub(Filter::Signal(tid, kind), key, f)
    }

    /// Calls `f` with every signal of kind `key` about `group` or anything in its closure when
    /// the signal arrives (things placed later included); `SignalEvent::tid` names the thing.
    pub fn on_signal_in<S: SignalKey + Send + 'static>(&self, group: Tid, key: S, f: impl FnMut(&Osis, SignalEvent<S::T>) + Send + 'static) -> Subscription {
        let g = self.read(|r| r.resolve(group));
        let kind = key.kind().to_string();
        self.signal_sub(Filter::SignalIn(g, kind), key, f)
    }

    fn signal_sub<S: SignalKey + Send + 'static>(&self, filter: Filter, key: S, mut f: impl FnMut(&Osis, SignalEvent<S::T>) + Send + 'static) -> Subscription {
        self.subscribe(filter, false, |_| {
            Box::new(move |db, d| {
                if let Delivery::Signal(s) = d {
                    f(db, SignalEvent { tid: s.tid, value: key.decode(&s.value).map_err(Error::from), actor: s.actor, node: s.node, ts: s.ts });
                }
            })
        })
    }
}
