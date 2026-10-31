//! Read-only views into fragments for the node (perm adapts `/members` entries into edge
//! writes, spec/permissions.md §5.1): map entries with their keys and fragments.

use crate::fragment::{Eid, Fragment, Map};
use crate::state::MemberRef;
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
}

use std::collections::BTreeMap;

/// What a state holds of one set element (`Fragment::set_elem`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Held {
    Live,
    /// A tombstone, a record without a live value, or pruned: absent under an effective reset
    /// above its creation stamp (§4.2).
    Dead,
    /// Absent and not pruned: its creation has not arrived.
    Unknown,
}

impl Fragment {
    /// The set at field `field` of this struct state (or of its struct slot), with the effective
    /// reset above its elements (§4.2); `None` when the state is no struct.
    fn struct_set(&self, field: u64) -> Option<(Option<&crate::fragment::Set>, Option<Stamp>)> {
        let (s, e) = match self {
            Fragment::Struct(s) => (s, None),
            Fragment::Slots(sl) => match sl.members.get(&crate::fragment::Encoding::Struct) {
                Some(Fragment::Struct(s)) => (s, self.reset()),
                _ => return None,
            },
            _ => return None,
        };
        let e = crate::stamp::max_opt(e, s.meta.reset.clone());
        match s.fields.get(&field) {
            Some(Fragment::Set(set)) => Some((Some(set), crate::stamp::max_opt(e, set.meta.reset.clone()))),
            None => Some((None, e)),
            Some(_) => None,
        }
    }

    /// The set element created at `at` in the set at struct field `field` of this state (§4.2,
    /// §5.5): live, dead (also once a reset above `at` pruned it), or not held. `Unknown` when the
    /// state has no such struct of sets.
    pub fn set_elem(&self, field: u64, at: &Stamp) -> Held {
        let Some((set, e)) = self.struct_set(field) else { return Held::Unknown };
        match set.and_then(|s| s.elems.get(&at.dot)) {
            Some(el) if el.frag.as_deref().and_then(Fragment::read).is_some() => Held::Live,
            Some(_) => Held::Dead,
            None if e.is_some_and(|e| e > *at) => Held::Dead,
            None => Held::Unknown,
        }
    }

    /// The greatest creation stamp of a live element of value `v` in the set at struct field
    /// `field` of this state (§5.5).
    pub fn set_live_elem(&self, field: u64, v: &Value) -> Option<Stamp> {
        let (set, _) = self.struct_set(field)?;
        set?.elems
            .values()
            .filter_map(|el| match el.frag.as_deref()? {
                Fragment::Register(r) => r.write.as_ref().filter(|w| w.value.as_ref() == Some(v)).map(|w| w.stamp.clone()),
                _ => None,
            })
            .max()
    }
    /// The position at `path` as a read sees it: a struct field, the current case's payload, what
    /// a map key reads as (its live entries joined, §5.6), a list element by index. Only that
    /// position is copied; a key costs O(log n).
    pub fn at(&self, path: &[crate::ops::PathSeg]) -> Option<Fragment> {
        self.walk(path, false)
    }

    /// `at`, with `any_case` also through a case that is not current (undo's `before`).
    pub(crate) fn walk(&self, path: &[crate::ops::PathSeg], any_case: bool) -> Option<Fragment> {
        use crate::ops::PathSeg;
        let Some((seg, rest)) = path.split_first() else { return Some(self.clone()) };
        let MemberRef::Frag(f) = self.chosen_member() else { return None };
        match (seg, f) {
            (PathSeg::Field(id), Fragment::Struct(s)) => s.fields.get(id)?.walk(rest, any_case),
            (PathSeg::Case(id), Fragment::Enum(e)) if any_case || e.case.as_ref().and_then(|c| c.case) == Some(*id) => e.payloads.get(id)?.walk(rest, any_case),
            (PathSeg::Key(k), Fragment::Map(m)) => match m.live_ids(k).as_slice() {
                // one live record: read in place
                [id] => m.record_frag(id)?.walk(rest, any_case),
                ids => crate::ops::key_state(m, ids)?.walk(rest, any_case),
            },
            (PathSeg::Index(i), Fragment::Seq(s)) => crate::seq::element_at(s, *i)?.1?.walk(rest, any_case),
            _ => None,
        }
    }
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
        Value::Map(m) => tree(m) + m.iter().map(|(k, x)| value_bytes(k) + value_bytes(x)).sum::<usize>(),
        Value::List(l) => l.len() * size_of::<Value>() + l.iter().map(value_bytes).sum::<usize>(),
        Value::Set(s) => nodes(s.len(), size_of::<Value>()) + s.iter().map(value_bytes).sum::<usize>(),
        Value::Enum(_, p) => p.as_deref().map_or(0, |p| size_of::<Value>() + value_bytes(p)),
        _ => 0,
    }
}

impl Fragment {
    /// A rough size in bytes of what the fragment owns on the heap (tree nodes, boxes, stamps'
    /// and values' contents; not its own `size_of`), for memory bounds: O(fragment), far cheaper
    /// than encoding it, and within a small factor of the allocations.
    pub fn approx_bytes(&self) -> usize {
        use crate::fragment::{Bag, Enum, Set, Slots, Struct};
        let reg = |r: &crate::fragment::Register| opt_stamp(&r.reset) + r.write.as_ref().map_or(0, |w| STAMP + w.value.as_ref().map_or(0, value_bytes));
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Bag(Bag { meta, elems, .. }) | Fragment::Set(Set { meta, elems }) => meta_bytes(meta) + tree(elems) + elems.values().map(|e| opt_stamp(&e.reset) + boxed(&e.frag)).sum::<usize>(),
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
                            e.created.as_ref().map_or(0, |_| 2 * STAMP) + (2 * STAMP + 24) * e.pos.len() + e.deleted.as_ref().map_or(0, |_| STAMP) + content
                        })
                        .fold(0usize, usize::saturating_add)
            }
            Fragment::Slots(Slots { reg: r, members }) => r.as_ref().map_or(0, reg) + tree(members) + members.values().map(Fragment::approx_bytes).sum::<usize>(),
        }
    }
}
