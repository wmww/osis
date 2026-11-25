//! Read-only views into fragments for the node (perm adapts `roles.0` entries into edge
//! writes, spec/permissions.md §5.1): map entries with their keys and fragments.

use crate::fragment::{Eid, Fragment, Map};
use crate::state::SlotRef;
use crate::stamp::{Dot, Stamp};
use osis_base::Value;

impl Map {
    /// Entry records by dot, then key: (dot, reset, key (`None`: the key-erased record),
    /// fragment if carried).
    pub fn entries(&self) -> impl Iterator<Item = (&Dot, Option<&Stamp>, Option<&Value>, Option<&Fragment>)> {
        self.entries.iter().map(|(id, e)| (&id.dot, e.reset.as_ref(), id.key(), e.frag.as_deref()))
    }

    /// The live records of key `k` (O(log n + their number)), with their own fragments.
    pub fn live(&self, k: &Value) -> Vec<(&Eid, &Fragment)> {
        self.live_ids(k).into_iter().filter_map(|id| Some((id, self.entries.get(id)?.frag.as_deref()?))).collect()
    }
}

impl crate::fragment::Struct {
    /// A field's fragment.
    pub fn field(&self, id: u64) -> Option<&Fragment> {
        self.fields.get(&id)
    }

    /// The ids of the fields it carries.
    pub fn field_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.fields.keys().copied()
    }
}

use std::collections::BTreeMap;

impl Fragment {
    /// This struct fragment split by the keyed records of its map field `field`: `piece_of`
    /// names a key's piece (`None`: the rest). Each piece is a struct holding at `field` only
    /// those records (no struct or map meta); the rest holds everything else: the other fields,
    /// both metas, the key-erased records, the records of keys no piece takes. Joined, they are
    /// this fragment. Anything but a struct is all rest.
    pub fn split_by_key<K: Ord>(&self, field: u64, piece_of: impl Fn(&Value) -> Option<K>) -> (BTreeMap<K, Fragment>, Fragment) {
        let Fragment::Struct(s) = self else { return (BTreeMap::new(), self.clone()) };
        let Some(Fragment::Map(m)) = s.fields.get(&field) else { return (BTreeMap::new(), self.clone()) };
        let mut pieces: BTreeMap<K, BTreeMap<Eid, crate::fragment::Entry>> = BTreeMap::new();
        let mut rest_entries = BTreeMap::new();
        for (id, e) in &m.entries {
            match id.key().and_then(&piece_of) {
                Some(k) => {
                    pieces.entry(k).or_default().insert(id.clone(), e.clone());
                }
                None => {
                    rest_entries.insert(id.clone(), e.clone());
                }
            }
        }
        let wrap = |fields: BTreeMap<u64, Fragment>, meta: crate::fragment::Meta| Fragment::Struct(crate::fragment::Struct { meta, fields });
        let out = pieces.into_iter().map(|(k, es)| (k, wrap(BTreeMap::from([(field, Fragment::Map(Map::new(Default::default(), es)))]), Default::default()))).collect();
        let mut fields = s.fields.clone();
        let rest_map = Map::new(m.meta.clone(), rest_entries);
        if rest_map.entries.is_empty() && rest_map.meta == Default::default() {
            fields.remove(&field);
        } else {
            fields.insert(field, Fragment::Map(rest_map));
        }
        (out, wrap(fields, s.meta.clone()))
    }

    /// The keys of the keyed records of this struct's map field `field` (none for anything else).
    pub fn field_keys(&self, field: u64) -> Vec<&Value> {
        let Fragment::Struct(s) = self else { return Vec::new() };
        let Some(Fragment::Map(m)) = s.fields.get(&field) else { return Vec::new() };
        m.entries.keys().filter_map(Eid::key).collect()
    }

    /// Whether this struct holds nothing but keyed records of its map field `field`: no other
    /// field, no struct or map meta, no key-erased record.
    pub fn only_keyed_in(&self, field: u64) -> bool {
        let Fragment::Struct(s) = self else { return false };
        if s.meta != Default::default() || s.fields.keys().any(|f| *f != field) {
            return false;
        }
        match s.fields.get(&field) {
            None => true,
            Some(Fragment::Map(m)) => m.meta == Default::default() && m.entries.keys().all(|id| id.key().is_some()),
            Some(_) => false,
        }
    }
    /// Calls `f` on every value the fragment holds: register values, map keys, at any depth,
    /// in records live or not (a write into another's entry carries no creation and reads as
    /// nothing alone, §5.6 Live; its values are still its).
    pub fn values(&self, f: &mut dyn FnMut(&Value)) {
        self.values_with(crate::state::Values::All, f);
    }

    /// The stamp of a register's write (`None`: no register, or none written).
    pub fn write_stamp(&self) -> Option<&Stamp> {
        match self {
            Fragment::Register(r) => r.write.as_ref().map(|w| &w.stamp),
            _ => None,
        }
    }

    /// The position at `path` as a read sees it: a struct field, the current case's payload, what
    /// a map key reads as (its live entries joined, §5.6), a list element by index. Only that
    /// position is copied; a key costs O(log n).
    pub fn at(&self, path: &[crate::ops::PathSeg]) -> Option<Fragment> {
        use crate::ops::PathSeg;
        let Some((seg, rest)) = path.split_first() else { return Some(self.clone()) };
        let SlotRef::Frag(f) = self.chosen_slot() else { return None };
        match (seg, f) {
            (PathSeg::Field(id), Fragment::Struct(s)) => s.fields.get(id)?.at(rest),
            (PathSeg::Case(id), Fragment::Enum(e)) if e.case.as_ref().map(|c| c.case) == Some(*id) => e.payloads.get(id)?.at(rest),
            (PathSeg::Key(k), Fragment::Map(m)) => match m.live_ids(k).as_slice() {
                // one live record: read in place
                [id] => m.record_frag(id)?.at(rest),
                ids => crate::ops::key_state(m, ids)?.at(rest),
            },
            (PathSeg::Index(i), Fragment::Seq(s)) => crate::seq::element_at(s, *i)?.1?.at(rest),
            _ => None,
        }
    }

    /// What `read` shows at `path`, reading only that position: as `at` then `read`, and inside
    /// a register's value (one written whole) the value at the rest of the path.
    pub fn read_at(&self, path: &[crate::ops::PathSeg]) -> Option<Value> {
        use crate::ops::PathSeg;
        let Some((seg, rest)) = path.split_first() else { return self.read() };
        let f = match self.chosen_slot() {
            SlotRef::Reg(r) => return value_at(&r.write.as_ref()?.value, path).cloned(),
            SlotRef::Frag(f) => f,
        };
        // a struct reads as a map by field id: a field step and an integer key step are one
        let field = |k: &Value| if let Value::Int(i) = k { u64::try_from(*i).ok() } else { None };
        let int = |id: &u64| i64::try_from(*id).ok().map(Value::Int);
        match (seg, f) {
            (PathSeg::Field(id), Fragment::Struct(s)) => s.fields.get(id)?.read_at(rest),
            (PathSeg::Key(k), Fragment::Struct(s)) => s.fields.get(&field(k)?)?.read_at(rest),
            (PathSeg::Case(id), Fragment::Enum(e)) if e.case.as_ref().map(|c| c.case) == Some(*id) => e.payloads.get(id)?.read_at(rest),
            (PathSeg::Field(id), Fragment::Map(_)) => f.read_at(&[&[PathSeg::Key(int(id)?)], rest].concat()),
            (PathSeg::Key(k), Fragment::Map(m)) => match m.live_ids(k).as_slice() {
                [id] => m.record_frag(id)?.read_at(rest),
                ids => crate::ops::key_state(m, ids)?.read_at(rest),
            },
            (PathSeg::Index(i), Fragment::Seq(s)) => crate::seq::element_at(s, *i)?.1?.read_at(rest),
            _ => None,
        }
    }
}

/// The part of read value `v` at `path` (a field step reads a map's integer key, as a struct
/// reads as a map by field id).
pub fn value_at<'a>(v: &'a Value, path: &[crate::ops::PathSeg]) -> Option<&'a Value> {
    use crate::ops::PathSeg;
    let mut cur = v;
    for seg in path {
        cur = match (seg, cur) {
            (PathSeg::Field(id), Value::Map(m)) => m.get(&Value::Int(i64::try_from(*id).ok()?))?,
            (PathSeg::Key(k), Value::Map(m)) => m.get(k)?,
            (PathSeg::Index(i), Value::List(l)) => l.get(*i)?,
            (PathSeg::Case(id), Value::Enum(c, Some(p))) if c == id => p,
            _ => return None,
        };
    }
    Some(cur)
}

/// Rough bytes per stamp held inline beyond its slot (a source's heap part, if any).
const STAMP: usize = 40;

fn opt_stamp(s: &Option<Stamp>) -> usize {
    if s.is_some() { STAMP } else { 0 }
}

fn meta_bytes(m: &crate::fragment::Meta) -> usize {
    opt_stamp(&m.reset) + opt_stamp(&m.w)
}

/// Heap of a `BTreeMap`'s nodes: a node holds up to 11 entries inline and trees fill them about
/// two thirds, so a small map costs a whole node (most fragments are small maps).
pub(crate) const fn nodes(len: usize, slot: usize) -> usize {
    if len == 0 { 0 } else { (1 + len / 8) * (11 * slot + 16) }
}

fn tree<K, V>(m: &BTreeMap<K, V>) -> usize {
    nodes(m.len(), size_of::<K>() + size_of::<V>())
}

fn boxed(f: &Option<Box<Fragment>>) -> usize {
    f.as_deref().map_or(0, |f| size_of::<Fragment>() + f.approx_bytes())
}

fn value_bytes(v: &Value) -> usize {
    match v {
        Value::Str(s) => s.len(),
        Value::Bytes(b) => b.len(),
        Value::Map(m) => 2 * m.len() * size_of::<Value>() + m.iter().map(|(k, x)| value_bytes(k) + value_bytes(x)).sum::<usize>(),
        Value::List(l) => l.len() * size_of::<Value>() + l.iter().map(value_bytes).sum::<usize>(),
        Value::Set(s) => s.len() * size_of::<Value>() + s.iter().map(value_bytes).sum::<usize>(),
        Value::Enum(_, p) => p.as_deref().map_or(0, |p| size_of::<Value>() + value_bytes(p)),
        Value::Link(_) => size_of::<osis_base::Link>(),
        Value::Unknown(u) => size_of::<osis_base::Unknown>() + u.content().as_bytes().len(),
        Value::Int(_) | Value::Float(_) | Value::Bool(_) | Value::Strong(_) | Value::Weak(_) => 0,
    }
}

impl Fragment {
    /// A rough size in bytes of what the fragment owns on the heap (tree nodes, boxes, stamps'
    /// and values' contents; not its own `size_of`), for memory bounds: O(fragment), far cheaper
    /// than encoding it, and within a small factor of the allocations.
    pub fn approx_bytes(&self) -> usize {
        use crate::fragment::{Bag, Enum, Slots, Struct};
        let reg = |r: &crate::fragment::Register| opt_stamp(&r.reset) + r.write.as_ref().map_or(0, |w| STAMP + value_bytes(&w.value));
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { meta, elems, .. }) => meta_bytes(meta) + tree(elems) + elems.values().map(|e| opt_stamp(&e.reset) + boxed(&e.frag)).sum::<usize>(),
            Fragment::Set(s) => meta_bytes(&s.meta) + tree(&s.elems) + s.elems.values().map(|e| opt_stamp(&e.reset) + boxed(&e.frag) + e.gone.as_ref().map_or(0, |g| STAMP + value_bytes(&g.value) + g.seen.len() * STAMP)).sum::<usize>(),
            Fragment::Struct(Struct { meta, fields }) => meta_bytes(meta) + tree(fields) + fields.values().map(Fragment::approx_bytes).sum::<usize>(),
            Fragment::Enum(Enum { meta, case, payloads }) => meta_bytes(meta) + case.as_ref().map_or(0, |_| STAMP) + tree(payloads) + payloads.values().map(Fragment::approx_bytes).sum::<usize>(),
            Fragment::Map(m) => {
                let index = tree(&m.keys) + m.keys.iter().map(|(k, ds)| value_bytes(k) + nodes(ds.len(), size_of::<Eid>()) + ds.iter().filter_map(Eid::key).map(value_bytes).sum::<usize>()).sum::<usize>();
                meta_bytes(&m.meta) + tree(&m.entries) + index + m.entries.iter().map(|(id, e)| opt_stamp(&e.reset) + opt_stamp(&e.created) + id.key().map_or(0, value_bytes) + boxed(&e.frag)).sum::<usize>()
            }
            Fragment::Seq(s) => {
                meta_bytes(&s.meta)
                    + tree(s.elems())
                    + s.elems()
                        .values()
                        .map(|e| {
                            let content = match &e.content {
                                crate::seq::SeqContent::None => 0,
                                crate::seq::SeqContent::Char(_) => 4 * usize::try_from(e.span).unwrap_or(usize::MAX),
                                crate::seq::SeqContent::Frag(f) => size_of::<Fragment>() + f.approx_bytes(),
                            };
                            // a range's creation `ts` and anchors per element
                            let n = usize::try_from(e.span).unwrap_or(usize::MAX);
                            let each = e.each.as_ref().map_or(0, |x| size_of::<crate::seq::Each>() + x.ts.as_ref().map_or(0, |_| size_of::<osis_base::Ts>() * n) + x.at.as_ref().map_or(0, |_| size_of::<Option<crate::seq::Anchor>>() * n));
                            e.created.as_ref().map_or(0, |_| 2 * STAMP) + (2 * STAMP + 24) * e.pos.len() + e.deleted.as_ref().map_or(0, |_| STAMP) + content + each
                        })
                        .fold(0usize, usize::saturating_add)
            }
            Fragment::Slots(Slots { reg: r, slots }) => r.as_ref().map_or(0, reg) + tree(slots) + slots.values().map(Fragment::approx_bytes).sum::<usize>(),
        }
    }
}
