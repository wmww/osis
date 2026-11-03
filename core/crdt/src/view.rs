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

impl crate::fragment::Fragment {
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
