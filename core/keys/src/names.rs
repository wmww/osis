//! A rotation's names (spec/crypto.md §4): the departures from the actor its rotator held, read
//! from its own role timeline and carried in every history box the rotation writes. An epoch
//! whose secret a node holds is established there only once some history entry of it has its
//! names met, so a node never uses an epoch while it lacks a departure the epoch's rotator held.

use osis_base::{CommitId, Tid, Value};
use std::collections::BTreeSet;

/// A commit's key (spec/permissions.md §5.1): its position in the role timeline's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub ts: u64,
    pub node: Tid,
    pub commit: CommitId,
}

/// One named departure: the thing whose `roles.0` part of the commit is met, and its commit's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    pub thing: Tid,
    pub key: Key,
}

/// The rotation commit itself, when it departs a holder of the actor (it cannot name its own
/// ID): its `ts` and author node, unique to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Own {
    pub ts: u64,
    pub node: Tid,
}

/// What one history entry names: the commits, and the rotation commit itself when it departs a
/// holder.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Names {
    pub list: BTreeSet<Name>,
    pub departs: Option<Own>,
}

impl Names {
    /// `[[name*], Opt([ts, node])]`, each name `[thing, ts, node, commit]`, ascending
    /// (spec/wire.md §7).
    pub fn to_value(&self) -> Value {
        let list = self
            .list
            .iter()
            .map(|n| Value::List(vec![Value::bytes(n.thing.as_bytes()), Value::uint(n.key.ts), Value::bytes(n.key.node.as_bytes()), Value::bytes(&n.key.commit.0)]))
            .collect();
        let own = self.departs.iter().map(|o| Value::List(vec![Value::uint(o.ts), Value::bytes(o.node.as_bytes())])).collect();
        Value::List(vec![Value::List(list), Value::List(own)])
    }

    /// The names of `v`; `None` unless it is exactly the encoding `to_value` writes (ascending,
    /// distinct).
    pub fn from_value(v: &Value) -> Option<Names> {
        let Value::List(f) = v else { return None };
        let [Value::List(items), Value::List(own)] = f.as_slice() else { return None };
        let departs = match own.as_slice() {
            [] => None,
            [Value::List(o)] => match o.as_slice() {
                [Value::Int(ts), Value::Bytes(node)] => Some(Own { ts: u64::try_from(*ts).ok()?, node: Tid::from_bytes(node.as_slice().try_into().ok()?) }),
                _ => return None,
            },
            _ => return None,
        };
        let mut list = BTreeSet::new();
        let mut last: Option<Name> = None;
        for it in items {
            let Value::List(x) = it else { return None };
            let [Value::Bytes(thing), Value::Int(ts), Value::Bytes(node), Value::Bytes(commit)] = x.as_slice() else { return None };
            let n = Name {
                thing: Tid::from_bytes(thing.as_slice().try_into().ok()?),
                key: Key { ts: u64::try_from(*ts).ok()?, node: Tid::from_bytes(node.as_slice().try_into().ok()?), commit: CommitId(commit.as_slice().try_into().ok()?) },
            };
            if last.is_some_and(|l| l >= n) {
                return None;
            }
            last = Some(n);
            list.insert(n);
        }
        Some(Names { list, departs })
    }
}

impl Names {
    /// Every name and the departs mark met under `held` (spec/crypto.md §4).
    pub fn met(&self, held: &dyn Held) -> bool {
        self.list.iter().all(|x| held.met(x)) && self.departs.is_none_or(|o| held.departed(&o))
    }
}

/// What a node holds for judging names (spec/crypto.md §4), for one actor.
pub trait Held {
    /// `n`'s commit is applied here with its part on `n.thing`, every entry its edge writes reset
    /// known.
    fn met(&self, n: &Name) -> bool;
    /// The commit `own` names (by `ts` and author) is applied here with its edge writes on the
    /// actor, every entry they reset known; it writes a keyset of the actor (a rotation commit)
    /// and makes no self-removal on it (spec/crypto.md §4).
    fn departed(&self, own: &Own) -> bool;
}

/// Every name met (a node holding everything: tests, and the views whose names were checked when
/// they were made).
pub struct AllHeld;

impl Held for AllHeld {
    fn met(&self, _: &Name) -> bool {
        true
    }
    fn departed(&self, _: &Own) -> bool {
        true
    }
}
