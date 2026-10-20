//! The fragment model (spec/crdt.md §1, §3.1, §5): one state shape per merge encoding. States and
//! deltas share it; a state holds every stamp in full. Sequences live in `seq`.

use crate::seq::Seq;
use crate::stamp::{Dot, Stamp};
use osis_core::Value;
use std::collections::BTreeMap;

/// Merge encoding IDs (§3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    Register = 0,
    Counter = 1,
    Max = 2,
    Min = 3,
    Struct = 4,
    Enum = 5,
    Set = 6,
    Map = 7,
    List = 8,
    Text = 9,
    /// Several encodings at one position (§7); never a schema encoding.
    Slots = 10,
}

impl Encoding {
    pub fn id(self) -> u8 {
        self as u8
    }
    /// `None` for an ID this build does not know (parks the delta, §3.1).
    pub fn from_id(id: u64) -> Option<Encoding> {
        Some(match id {
            0 => Encoding::Register,
            1 => Encoding::Counter,
            2 => Encoding::Max,
            3 => Encoding::Min,
            4 => Encoding::Struct,
            5 => Encoding::Enum,
            6 => Encoding::Set,
            7 => Encoding::Map,
            8 => Encoding::List,
            9 => Encoding::Text,
            10 => Encoding::Slots,
            _ => return None,
        })
    }
    /// The encoding an `any` position writes `v` with: the value's kind (§3.1).
    pub fn of_value(v: &Value) -> Encoding {
        match v {
            Value::Map(_) => Encoding::Map,
            Value::List(_) => Encoding::List,
            Value::Set(_) => Encoding::Set,
            Value::Enum(..) => Encoding::Enum,
            _ => Encoding::Register,
        }
    }
    pub fn bag_kind(self) -> Option<BagKind> {
        match self {
            Encoding::Counter => Some(BagKind::Counter),
            Encoding::Max => Some(BagKind::Max),
            Encoding::Min => Some(BagKind::Min),
            _ => None,
        }
    }
}

/// The three bag encodings (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BagKind {
    Counter,
    Max,
    Min,
}

impl BagKind {
    pub fn encoding(self) -> Encoding {
        match self {
            BagKind::Counter => Encoding::Counter,
            BagKind::Max => Encoding::Max,
            BagKind::Min => Encoding::Min,
        }
    }
}

/// Reset and explicit presence write of a composite (§4.2, §4.3). The presence stamp `written`
/// is computed from the surviving writes; only `W` is stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub(crate) reset: Option<Stamp>,
    pub(crate) w: Option<Stamp>,
}

/// A register write; `value` is `None` for a value-less write (§4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegWrite {
    pub(crate) stamp: Stamp,
    pub(crate) value: Option<Value>,
}

/// §5.1. Only an aspect root or a `Slots` member carries a reset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Register {
    pub(crate) reset: Option<Stamp>,
    pub(crate) write: Option<RegWrite>,
}

/// A set or bag element: its reset and its value register (§5.2, §5.5). A record with a reset and
/// no content is a tombstone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Elem {
    pub(crate) reset: Option<Stamp>,
    pub(crate) frag: Option<Box<Fragment>>,
}

/// A map entry (§5.6). `key` is `None` for tombstones and value-less creations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub(crate) reset: Option<Stamp>,
    pub(crate) key: Option<Value>,
    pub(crate) frag: Option<Box<Fragment>>,
}

/// Counter, max, min (§5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bag {
    pub(crate) kind: BagKind,
    pub(crate) meta: Meta,
    pub(crate) elems: BTreeMap<Dot, Elem>,
}

/// §5.3. Field IDs are the schema's wire IDs; unknown ones are kept.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Struct {
    pub(crate) meta: Meta,
    pub(crate) fields: BTreeMap<u64, Fragment>,
}

/// The case register of an enum; `case` is `None` for a value-less write (§4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseWrite {
    pub(crate) stamp: Stamp,
    pub(crate) case: Option<u64>,
}

/// §5.4. Payload writes are filed under the case they were made for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enum {
    pub(crate) meta: Meta,
    pub(crate) case: Option<CaseWrite>,
    pub(crate) payloads: BTreeMap<u64, Fragment>,
}

/// §5.5.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Set {
    pub(crate) meta: Meta,
    pub(crate) elems: BTreeMap<Dot, Elem>,
}

/// §5.6.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    pub(crate) meta: Meta,
    pub(crate) entries: BTreeMap<Dot, Entry>,
}

/// A position that has seen several encodings (§7): the register slot and one slot per other
/// encoding, every slot holding the register's embedding. At least two members; never in a
/// writer's delta.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Slots {
    pub(crate) reg: Option<Register>,
    pub(crate) members: BTreeMap<Encoding, Fragment>,
}

/// A fragment of an aspect state or delta (§3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fragment {
    Register(Register),
    Bag(Bag),
    Struct(Struct),
    Enum(Enum),
    Set(Set),
    Map(Map),
    /// List or text (§5.7).
    Seq(Seq),
    Slots(Slots),
}

impl Fragment {
    pub fn encoding(&self) -> Encoding {
        match self {
            Fragment::Register(_) => Encoding::Register,
            Fragment::Bag(b) => b.kind.encoding(),
            Fragment::Struct(_) => Encoding::Struct,
            Fragment::Enum(_) => Encoding::Enum,
            Fragment::Set(_) => Encoding::Set,
            Fragment::Map(_) => Encoding::Map,
            Fragment::Seq(s) => s.encoding(),
            Fragment::Slots(_) => Encoding::Slots,
        }
    }

    /// The empty fragment of `enc`; `Slots` has none (it is formed by join).
    pub fn empty(enc: Encoding) -> Option<Fragment> {
        Some(match enc {
            Encoding::Register => Fragment::Register(Register::default()),
            Encoding::Counter | Encoding::Max | Encoding::Min => {
                let kind = enc.bag_kind()?;
                Fragment::Bag(Bag { kind, meta: Meta::default(), elems: BTreeMap::new() })
            }
            Encoding::Struct => Fragment::Struct(Struct::default()),
            Encoding::Enum => Fragment::Enum(Enum::default()),
            Encoding::Set => Fragment::Set(Set::default()),
            Encoding::Map => Fragment::Map(Map::default()),
            Encoding::List => Fragment::Seq(Seq::empty(false)),
            Encoding::Text => Fragment::Seq(Seq::empty(true)),
            Encoding::Slots => return None,
        })
    }
}
