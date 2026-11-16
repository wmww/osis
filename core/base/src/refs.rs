//! References (spec/data-model.md §8): a strong makes its target part of the closure of the thing
//! holding it, a weak only points, a ticket is a weak that also carries what syncing its target
//! needs. Each is a value of its own (spec/data-model.md §5: tags STRONG, WEAK, TICKET); none is
//! a bare tid. Filled by lane (a) of issues/reference-graph.md.

use crate::{Role, SyncId, Tid, Value};

/// A strong reference to a thing (spec/data-model.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Strong(pub Tid);

/// A weak reference to a thing (spec/data-model.md §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Weak(pub Tid);

/// A strong or a weak, the writer's choice per value (spec/data-model.md §3 `ref`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ref {
    Strong(Strong),
    Weak(Weak),
}

/// A ticket: `[target, sync_id, role, epoch, box, holder, profile]` (spec/data-model.md §8
/// Tickets). `epoch` as `(n, nonce)`; `boxed` the encoded `box` value (spec/data-model.md §9).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket {
    pub target: Tid,
    pub sync_id: SyncId,
    pub role: Role,
    pub epoch: (u64, [u8; 32]),
    pub boxed: Value,
    pub holder: Tid,
    pub profile: Tid,
}

impl From<Tid> for Strong {
    fn from(t: Tid) -> Strong {
        Strong(t)
    }
}

impl From<Tid> for Weak {
    fn from(t: Tid) -> Weak {
        Weak(t)
    }
}

impl From<Strong> for Tid {
    fn from(s: Strong) -> Tid {
        s.0
    }
}

impl From<Weak> for Tid {
    fn from(w: Weak) -> Tid {
        w.0
    }
}

impl Ref {
    /// The target's tid.
    pub fn tid(self) -> Tid {
        match self {
            Ref::Strong(s) => s.0,
            Ref::Weak(w) => w.0,
        }
    }
}

impl Ticket {
    /// The ticket's content as a value (spec/data-model.md §8 Tickets), without its tag.
    pub fn to_value(&self) -> Value {
        todo!("refgraph: (a) ticket encoding")
    }

    /// A ticket from its tag content; `None` on any other shape or role (spec/data-model.md §8).
    pub fn from_value(v: &Value) -> Option<Ticket> {
        let _ = v;
        todo!("refgraph: (a) ticket decoding")
    }
}
