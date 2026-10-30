//! The fragment model (spec/crdt.md §1, §3.1, §5): one state shape per merge encoding. States and
//! deltas share it; a state holds every stamp in full. Sequences live in `seq`.

use crate::seq::Seq;
use crate::stamp::{Dot, Stamp};
use osis_base::Value;
use std::collections::{BTreeMap, BTreeSet};

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

impl Elem {
    /// A tombstone: reset `r`, no content.
    pub(crate) fn tomb(r: &Stamp) -> Elem {
        Elem { reset: Some(r.clone()), frag: None }
    }
}

/// A map key as an entry's identity: compared by canonical encoding, bytewise (§3.3 rule 2;
/// `Value` compares links by content hash alone).
#[derive(Clone, Debug)]
pub struct Key(pub Value);

impl Ord for Key {
    fn cmp(&self, o: &Key) -> std::cmp::Ordering {
        crate::state::opt_value_cmp(Some(&self.0), Some(&o.0))
    }
}
impl PartialOrd for Key {
    fn partial_cmp(&self, o: &Key) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl PartialEq for Key {
    fn eq(&self, o: &Key) -> bool {
        self.cmp(o) == std::cmp::Ordering::Equal
    }
}
impl Eq for Key {}
impl std::hash::Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        self.0.hash(h);
    }
}

/// A map entry record's identity (§5.6): the entry's dot and key; `None` for the dot's
/// key-erased record (§4.7). Ordered by dot, the key-erased record first, then by key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eid {
    pub dot: Dot,
    pub key: Option<Key>,
}

impl Eid {
    pub fn new(dot: Dot, key: Option<Value>) -> Eid {
        Eid { dot, key: key.map(Key) }
    }
    /// The key-erased record of `dot`, the lowest of its records.
    pub fn erased(dot: Dot) -> Eid {
        Eid { dot, key: None }
    }
    pub fn key(&self) -> Option<&Value> {
        self.key.as_ref().map(|k| &k.0)
    }
}

/// A map entry record (§5.6): its reset, its content, and its creation write's stamp (the
/// creation's dot is the entry's), kept while it survives pruning and the record holds content.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub(crate) reset: Option<Stamp>,
    pub(crate) frag: Option<Box<Fragment>>,
    pub(crate) created: Option<Stamp>,
}

impl Entry {
    /// A tombstone: reset `r`, no content.
    pub(crate) fn tomb(r: &Stamp) -> Entry {
        Entry { reset: Some(r.clone()), ..Entry::default() }
    }
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
#[derive(Clone, Default)]
pub struct Map {
    pub(crate) meta: Meta,
    pub(crate) entries: BTreeMap<Eid, Entry>,
    /// Local index, not part of the lattice: key -> the keyed records carrying it (by `Value`
    /// equality, so links by content hash). A superset (a record gone may linger), so lookups
    /// check the record.
    pub(crate) keys: BTreeMap<Value, BTreeSet<Eid>>,
}

impl PartialEq for Map {
    fn eq(&self, o: &Map) -> bool {
        self.meta == o.meta && self.entries == o.entries
    }
}
impl Eq for Map {}

impl std::fmt::Debug for Map {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Map").field("meta", &self.meta).field("entries", &self.entries).finish()
    }
}

impl Map {
    pub(crate) fn new(meta: Meta, entries: BTreeMap<Eid, Entry>) -> Map {
        let mut m = Map { meta, entries, keys: BTreeMap::new() };
        m.reindex();
        m
    }
    /// Rebuilds the key index exactly.
    pub(crate) fn reindex(&mut self) {
        self.keys.clear();
        for id in self.entries.keys() {
            if let Some(k) = id.key() {
                self.keys.entry(k.clone()).or_default().insert(id.clone());
            }
        }
    }
    /// Lists keyed record `id` in the index.
    pub(crate) fn index_id(&mut self, id: &Eid) {
        if let Some(k) = id.key()
            && !self.keys.get(k).is_some_and(|s| s.contains(id))
        {
            self.keys.entry(k.clone()).or_default().insert(id.clone());
        }
    }
    /// The records of `dot`, the key-erased one first.
    pub(crate) fn of_dot(&self, dot: &Dot) -> impl Iterator<Item = (&Eid, &Entry)> + '_ {
        let d = dot.clone();
        self.entries.range(Eid::erased(dot.clone())..).take_while(move |(id, _)| id.dot == d)
    }
    /// Whether `dot`'s greatest creation is held only by its key-erased record: then none of
    /// its records is live (§5.6, §4.7).
    pub(crate) fn hidden(&self, dot: &Dot) -> bool {
        let mut it = self.of_dot(dot);
        let Some((id, e)) = it.next() else { return false };
        let Some(c) = e.created.as_ref().filter(|_| id.key.is_none()) else { return false };
        !it.any(|(_, x)| x.created.as_ref().is_some_and(|y| y >= c))
    }
    /// Whether keyed record `id` is live: its fragment present and its dot not hidden (§5.6).
    pub(crate) fn is_live(&self, id: &Eid) -> bool {
        id.key.is_some() && self.entries.get(id).and_then(|e| e.frag.as_deref()).is_some_and(|f| f.present()) && !self.hidden(&id.dot)
    }
    /// What record `id` reads as: its fragment, a keyed record's joined with its dot's
    /// key-erased record's (§5.6).
    pub(crate) fn record_frag(&self, id: &Eid) -> Option<std::borrow::Cow<'_, Fragment>> {
        let f = self.entries.get(id)?.frag.as_deref()?;
        match self.entries.get(&Eid::erased(id.dot.clone())).and_then(|e| e.frag.as_deref()) {
            Some(x) if id.key.is_some() => {
                let mut j = f.clone();
                j.join_into(x.clone(), None, &mut crate::changes::Changes::new());
                Some(std::borrow::Cow::Owned(j))
            }
            _ => Some(std::borrow::Cow::Borrowed(f)),
        }
    }
    /// Moves the records of the dots `pred` accepts to their key-erased record (§4.7), each
    /// joined in without pruning (the caller joins or prunes).
    pub(crate) fn erase_keys(&mut self, pred: &dyn Fn(&Dot) -> bool) {
        let ids: Vec<Eid> = self.entries.keys().filter(|id| id.key.is_some() && pred(&id.dot)).cloned().collect();
        if ids.is_empty() {
            return;
        }
        for id in ids {
            let Some(e) = self.entries.remove(&id) else { continue };
            let slot = self.entries.entry(Eid::erased(id.dot)).or_default();
            slot.reset = crate::stamp::max_opt(slot.reset.take(), e.reset);
            slot.created = crate::stamp::max_opt(slot.created.take(), e.created);
            match (&mut slot.frag, e.frag) {
                (Some(a), Some(b)) => a.join_into(*b, None, &mut crate::changes::Changes::new()),
                (a @ None, b) => *a = b,
                (_, None) => {}
            }
        }
        self.reindex();
    }
    /// Live records of `k`, ascending (§5.6): O(log n + records of k).
    pub(crate) fn live_ids(&self, k: &Value) -> Vec<&Eid> {
        let Some(ids) = self.keys.get(k) else { return Vec::new() };
        ids.iter().filter(|id| self.is_live(id)).collect()
    }
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

    /// Splits a root map or set delta into a delta carrying the root's reset and presence write
    /// alone, then one delta per entry or element carrying them too (spec/commits.md §2: several
    /// deltas of one aspect share the commit-level stamp); their join is `self`. Anything else,
    /// or an empty collection: `self` alone.
    pub fn split_entries(self) -> Vec<Fragment> {
        match self {
            Fragment::Map(m) if !m.entries.is_empty() => {
                let Map { meta, entries, .. } = m;
                let mut out = vec![Fragment::Map(Map::new(meta.clone(), BTreeMap::new()))];
                out.extend(entries.into_iter().map(|(d, e)| Fragment::Map(Map::new(meta.clone(), BTreeMap::from([(d, e)])))));
                out
            }
            Fragment::Set(s) if !s.elems.is_empty() => {
                let Set { meta, elems } = s;
                let mut out = vec![Fragment::Set(Set { meta: meta.clone(), elems: BTreeMap::new() })];
                out.extend(elems.into_iter().map(|(d, e)| Fragment::Set(Set { meta: meta.clone(), elems: BTreeMap::from([(d, e)]) })));
                out
            }
            f => vec![f],
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
