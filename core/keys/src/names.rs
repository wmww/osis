//! A rotation's names (spec/crypto.md §4): the departures from the actor and the things below it
//! its rotator held, read from its own role timeline and carried in every history box the
//! rotation writes. An epoch
//! whose secret a node holds is established there only once some history entry of it has its
//! names met, so a node never uses an epoch while it lacks a departure the epoch's rotator held.

use osis_base::{CommitId, Role, Tid, Value};
use osis_crypto::Epoch;
use std::collections::BTreeSet;

/// A commit's key (spec/permissions.md §6): its position in the role timeline's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub ts: u64,
    pub node: Tid,
    pub commit: CommitId,
}

/// The commit ID of an expiry's key (`Key::expiry`): no commit has it.
pub const EXPIRY: CommitId = CommitId([0; 32]);

impl Key {
    /// The key a departure by `holder`'s edge passing its `until` (at `ts`, the first `ts` at
    /// `until`) is named by (spec/crypto.md §4): the holder in place of the node, no commit.
    pub fn expiry(ts: u64, holder: Tid) -> Key {
        Key { ts, node: holder, commit: EXPIRY }
    }
}

/// One named departure: the thing whose epoch start can stand in for it, and its commit's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name {
    pub thing: Tid,
    pub key: Key,
}

/// A holder actor's keyset epoch a rotation's box to it names: a departure inside that actor
/// rides in the rotation that made the epoch, and a node boxing the actor at an older keyset
/// would hand the new epoch to the departed holder. Met by any valid keyset body writing or
/// listing it: the departures from the actor are named too (`Names::list`), so a departed admin's
/// later keysets are invalid wherever the names are met.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeysetName {
    pub thing: Tid,
    pub role: Role,
    pub epoch: Epoch,
}

/// The rotation commit itself, when it departs a holder of the actor (it cannot name its own
/// ID): its `ts` and author node, unique to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Own {
    pub ts: u64,
    pub node: Tid,
}

/// What one history entry names: the commits, the holder actors' keyset epochs, and the
/// rotation commit itself when it departs a holder.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Names {
    pub list: BTreeSet<Name>,
    pub keysets: BTreeSet<KeysetName>,
    pub departs: Option<Own>,
}

fn role_byte(r: Role) -> u64 {
    match r {
        Role::Read => 0,
        Role::Write => 1,
        Role::Admin => 2,
    }
}

impl Names {
    /// `[[name*], [keyset name*], Opt([ts, node])]`, each name `[thing, ts, node, commit]`, each
    /// keyset name `[thing, role, n, nonce]`, ascending (spec/wire.md §7).
    pub fn to_value(&self) -> Value {
        let list = self
            .list
            .iter()
            .map(|n| Value::List(vec![Value::bytes(n.thing.as_bytes()), Value::uint(n.key.ts), Value::bytes(n.key.node.as_bytes()), Value::bytes(&n.key.commit.0)]))
            .collect();
        let keysets = self
            .keysets
            .iter()
            .map(|k| Value::List(vec![Value::bytes(k.thing.as_bytes()), Value::uint(role_byte(k.role)), Value::uint(k.epoch.n()), Value::bytes(k.epoch.nonce())]))
            .collect();
        let own = self.departs.iter().map(|o| Value::List(vec![Value::uint(o.ts), Value::bytes(o.node.as_bytes())])).collect();
        Value::List(vec![Value::List(list), Value::List(keysets), Value::List(own)])
    }

    /// The names of `v`; `None` unless it is exactly the encoding `to_value` writes (ascending,
    /// distinct).
    pub fn from_value(v: &Value) -> Option<Names> {
        let Value::List(f) = v else { return None };
        let [Value::List(items), Value::List(ks), Value::List(own)] = f.as_slice() else { return None };
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
        let mut keysets = BTreeSet::new();
        let mut last: Option<KeysetName> = None;
        for it in ks {
            let Value::List(x) = it else { return None };
            let [Value::Bytes(thing), Value::Int(role), Value::Int(n), Value::Bytes(nonce)] = x.as_slice() else { return None };
            let role = [Role::Read, Role::Write, Role::Admin].get(usize::try_from(*role).ok()?).copied()?;
            let k = KeysetName { thing: Tid::from_bytes(thing.as_slice().try_into().ok()?), role, epoch: Epoch::new(u64::try_from(*n).ok()?, nonce.as_slice().try_into().ok()?).ok()? };
            if last.is_some_and(|l| l >= k) {
                return None;
            }
            last = Some(k);
            keysets.insert(k);
        }
        Some(Names { list, keysets, departs })
    }
}

impl Names {
    /// Every name, keyset name and the departs mark met under `held` (spec/crypto.md §4).
    pub fn met(&self, held: &dyn Held) -> bool {
        self.list.iter().all(|x| held.met(x)) && self.keysets.iter().all(|k| held.keyset(k)) && self.departs.is_none_or(|o| held.departed(&o))
    }
}

/// What a node holds for judging names (spec/crypto.md §4), for one actor.
pub trait Held {
    /// `n`'s commit is applied here, or its key is ordered before this node's epoch start of
    /// `n.thing`.
    fn met(&self, n: &Name) -> bool;
    /// A held valid `keys.0` body of `k.thing` writes `k.epoch` as its keyset of `k.role` or
    /// lists it as superseded by one (no epoch start stands in: a roster snapshot carries no
    /// keyset).
    fn keyset(&self, k: &KeysetName) -> bool;
    /// The commit `own` names (by `ts` and author) is applied here with its edge write on the
    /// actor, or lies before this node's epoch start of the actor.
    fn departed(&self, own: &Own) -> bool;
}

/// Every name met (a node holding everything: tests, and the views whose names were checked when
/// they were made).
pub struct AllHeld;

impl Held for AllHeld {
    fn met(&self, _: &Name) -> bool {
        true
    }
    fn keyset(&self, _: &KeysetName) -> bool {
        true
    }
    fn departed(&self, _: &Own) -> bool {
        true
    }
}
