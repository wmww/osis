//! The writer's view for the structural diff (spec/crdt.md §9). osis-schema implements `View`;
//! `AnyView` is the identity view of untyped writes and `any` positions.

use crate::fragment::Encoding;
use osis_base::Value;
use std::borrow::Cow;

/// The writer's schema at one position. Children are views too (`Self`), so an implementation
/// can be a cheap handle into a schema.
pub trait View: Sized {
    /// The encoding writes at this position use; `None` for `any`: the value's kind decides,
    /// recursively (§3.1).
    fn encoding(&self) -> Option<Encoding>;
    /// `v` (a read at this position) projected onto what the writer's type can type; `None` if
    /// it cannot (unknown enum case, type mismatch): the element is opaque (§9).
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>>;
    /// View of struct field `id`; `None` if the writer's schema does not declare it.
    fn field(&self, id: u64) -> Option<Self>;
    /// Declared constant default of struct field `id` (never materialized, §9).
    fn field_default(&self, id: u64) -> Option<Value>;
    /// Payload view of enum case `id`; `None` if the case has no payload or is unknown.
    fn case(&self, id: u64) -> Option<Self>;
    /// Element view of a set or list, value view of a map, contribution view of a bag.
    fn element(&self) -> Option<Self>;
    /// Key view of a map.
    fn key(&self) -> Option<Self>;
}

/// Identity view: every value projects to itself, every child is `any`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AnyView;

impl View for AnyView {
    fn encoding(&self) -> Option<Encoding> {
        None
    }
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
        Some(Cow::Borrowed(v))
    }
    fn field(&self, _: u64) -> Option<AnyView> {
        Some(AnyView)
    }
    fn field_default(&self, _: u64) -> Option<Value> {
        None
    }
    fn case(&self, _: u64) -> Option<AnyView> {
        Some(AnyView)
    }
    fn element(&self) -> Option<AnyView> {
        Some(AnyView)
    }
    fn key(&self) -> Option<AnyView> {
        Some(AnyView)
    }
}

/// A value (a register's write) holding, unchunked, what must be chunked: a blob or string, a set
/// element or a map key above `CHUNK_THRESHOLD` (spec/data-model.md §6). A value's struct fields
/// are map entries under int keys, which never pass it.
fn holds_large(v: &Value) -> bool {
    match v {
        Value::Str(_) | Value::Bytes(_) => v.above_chunk_threshold(),
        Value::List(items) => items.iter().any(holds_large),
        Value::Set(items) => items.iter().any(Value::above_chunk_threshold),
        Value::Map(m) => m.iter().any(|(k, x)| k.above_chunk_threshold() || holds_large(x)),
        Value::Enum(_, Some(p)) => holds_large(p),
        _ => false,
    }
}

impl crate::fragment::Fragment {
    /// Whether this fragment holds, unchunked, a value that must be chunked (spec/data-model.md
    /// §6): `holds_large` in any register, or a map key, or (`whole_elements`) a set or bag
    /// element's whole value above `CHUNK_THRESHOLD`. Text characters merge as sequences and never
    /// chunk.
    pub fn holds_unchunked(&self, whole_elements: bool) -> bool {
        use crate::fragment::{Bag, Fragment, Register, Set, Slots};
        let reg = |r: &Register| r.write.as_ref().and_then(|w| w.value.as_ref()).is_some_and(holds_large);
        let on = |f: &Fragment| f.holds_unchunked(whole_elements);
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(Slots { reg: r, slots }) => r.as_ref().is_some_and(reg) || slots.values().any(on),
            Fragment::Bag(Bag { elems, .. }) | Fragment::Set(Set { elems, .. }) => elems.values().filter_map(|e| e.frag.as_deref()).any(|f| {
                let whole = |r: &Register| r.write.as_ref().and_then(|w| w.value.as_ref()).is_some_and(Value::above_chunk_threshold);
                on(f) || (whole_elements && matches!(f, Fragment::Register(r) if whole(r)))
            }),
            Fragment::Struct(s) => s.fields.values().any(on),
            Fragment::Enum(e) => e.payloads.values().any(on),
            Fragment::Map(m) => m.entries.iter().any(|(id, e)| id.key().is_some_and(Value::above_chunk_threshold) || e.frag.as_deref().is_some_and(on)),
            Fragment::Seq(s) => s.elems().values().any(|el| matches!(&el.content, crate::seq::SeqContent::Frag(f) if on(f))),
        }
    }

    /// Whether every position this fragment carries fits `view`: each non-register fragment has
    /// the view's encoding (a register may stand anywhere: its value is judged), each value (a
    /// register's write, a map key) projects at its position, and each enum case write names a
    /// case the view declares. Positions the view does not declare (unknown struct fields,
    /// payloads of undeclared cases) are not looked into.
    pub fn fits<V: View>(&self, view: &V) -> bool {
        use crate::fragment::{Bag, Fragment, Register, Set, Slots};
        let value = |v: &Value| view.project(v).is_some();
        let reg = |r: &Register| r.write.as_ref().and_then(|w| w.value.as_ref()).is_none_or(value);
        let elems = |es: &mut dyn Iterator<Item = &Fragment>| match view.element() {
            Some(e) => Iterator::all(&mut &mut *es, |f| f.fits(&e)),
            None => true,
        };
        if !matches!(self, Fragment::Register(_) | Fragment::Slots(_)) && view.encoding().is_some_and(|e| e != self.encoding()) {
            return false;
        }
        match self {
            Fragment::Register(r) => reg(r),
            Fragment::Slots(Slots { reg: r, slots }) => r.as_ref().is_none_or(reg) && slots.values().all(|f| f.fits(view)),
            Fragment::Bag(Bag { elems: es, .. }) | Fragment::Set(Set { elems: es, .. }) => elems(&mut es.values().filter_map(|e| e.frag.as_deref())),
            Fragment::Struct(s) => s.fields.iter().all(|(id, f)| view.field(*id).is_none_or(|v| f.fits(&v))),
            Fragment::Enum(e) => {
                // a payload-less case is declared iff its bare value projects
                let declared = |c: u64| view.case(c).is_some() || value(&Value::Enum(c, None));
                e.case.as_ref().and_then(|w| w.case).is_none_or(declared) && e.payloads.iter().all(|(id, f)| view.case(*id).is_none_or(|v| f.fits(&v)))
            }
            Fragment::Map(m) => {
                let key = view.key();
                m.entries.keys().all(|id| id.key().zip(key.as_ref()).is_none_or(|(k, kv)| kv.project(k).is_some()))
                    && elems(&mut m.entries.values().filter_map(|e| e.frag.as_deref()))
            }
            Fragment::Seq(s) => elems(&mut s.elems().values().filter_map(|el| match &el.content {
                crate::seq::SeqContent::Frag(f) => Some(&**f),
                _ => None,
            })),
        }
    }
}
