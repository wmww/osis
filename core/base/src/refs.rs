//! References (spec/data-model.md §8): a strong makes its target part of the closure of the thing
//! holding it, a weak only points. Each is a value of its own (spec/data-model.md §5: tags STRONG,
//! WEAK); none is a bare tid.

use crate::{Tid, Value};

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

/// Which kind of reference a value is: its byte in a structure (spec/wire.md §11.2, the port's backlinks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    Strong = 0,
    Weak = 1,
}

impl RefKind {
    pub const ALL: [RefKind; 2] = [RefKind::Strong, RefKind::Weak];
    pub fn id(self) -> u8 {
        self as u8
    }
    pub fn from_id(id: u64) -> Option<RefKind> {
        RefKind::ALL.into_iter().find(|k| u64::from(k.id()) == id)
    }
    /// The kind and target of a reference value; `None` for any other value.
    pub fn of(v: &Value) -> Option<(RefKind, Tid)> {
        match v {
            Value::Strong(t) => Some((RefKind::Strong, *t)),
            Value::Weak(t) => Some((RefKind::Weak, *t)),
            _ => None,
        }
    }
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
