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

/// Which kind of reference a value is: its byte in a structure (spec/wire.md §11.2, the port's backlinks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    Strong = 0,
    Weak = 1,
    Ticket = 2,
}

impl RefKind {
    pub const ALL: [RefKind; 3] = [RefKind::Strong, RefKind::Weak, RefKind::Ticket];
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
            Value::Ticket(t) => Some((RefKind::Ticket, t.target)),
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

impl Ticket {
    /// The ticket's content as a value (spec/data-model.md §8 Tickets), without its tag.
    pub fn to_value(&self) -> Value {
        Value::List(vec![
            Value::bytes(self.target.as_bytes()),
            Value::bytes(&self.sync_id.0),
            Value::uint(u64::from(self.role.id())),
            Value::List(vec![Value::uint(self.epoch.0), Value::bytes(&self.epoch.1)]),
            self.boxed.clone(),
            Value::bytes(self.holder.as_bytes()),
            Value::bytes(self.profile.as_bytes()),
        ])
    }

    /// A ticket from its tag content; `None` on any other shape or role (spec/data-model.md §8).
    pub fn from_value(v: &Value) -> Option<Ticket> {
        let [target, sync_id, role, epoch, boxed, holder, profile] = v.as_list()? else { return None };
        let tid = |v: &Value| v.as_array().map(Tid::from_bytes);
        let role = Role::from_id(role.as_uint()?).filter(|r| matches!(r, Role::Read | Role::Sync))?;
        let [n, nonce] = epoch.as_list()? else { return None };
        // a `box` value: an enum with a payload, holding no large value (spec/data-model.md §9)
        if !matches!(boxed, Value::Enum(_, Some(_))) || crate::cbor::has_link(boxed) {
            return None;
        }
        Some(Ticket {
            target: tid(target)?,
            sync_id: SyncId(sync_id.as_array()?),
            role,
            epoch: (n.as_uint()?, nonce.as_array()?),
            boxed: boxed.clone(),
            holder: tid(holder)?,
            profile: tid(profile)?,
        })
    }

    /// As a weak to its target (spec/data-model.md §8: a ticket is a weak).
    pub fn weak(&self) -> Weak {
        Weak(self.target)
    }
}
