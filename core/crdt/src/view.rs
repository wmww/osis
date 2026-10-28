//! The writer's view for the structural diff (spec/crdt.md §9). osis-schema implements `View`;
//! `AnyView` is the identity view of untyped writes and `any` positions.

use crate::fragment::Encoding;
use osis_core::Value;
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
