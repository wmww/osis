//! `Key`: an aspect key typed by a schema registered at run time (CLIs, tools; `Osis::key`), and
//! the core keys. Typed `Aspect<T>` come from codegen (osis-schema).

use osis_base::{Ak, Value};
use osis_schema::{AspectKey, Codec, PathError, Schema, typed_read};
use std::sync::Arc;

/// An aspect key whose schema is known only at run time. Reads are typed reads projected back
/// to `Value` (reader defaults, failures with the path); writes are validated.
#[derive(Clone, Debug)]
pub struct Key {
    pub(crate) ak: Ak,
    pub(crate) schema: Option<Arc<Schema>>,
}

impl Key {
    /// A key typed by `schema` if it declares `ak`, else untyped.
    pub fn new(ak: Ak, schema: Option<Arc<Schema>>) -> Key {
        let schema = schema.filter(|s| s.aspects.contains_key(ak.as_str()));
        Key { ak, schema }
    }
    pub fn ak(&self) -> &Ak {
        &self.ak
    }
    pub fn schema(&self) -> Option<&Arc<Schema>> {
        self.schema.as_ref()
    }
}

impl AspectKey for Key {
    type T = Value;
    fn ak(&self) -> &str {
        self.ak.as_str()
    }
    fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }
    fn decode(&self, v: &Value) -> Result<Value, PathError> {
        // `/created` is typed by its exclusivity rule, not the missing-field rule
        // (spec/data-model.md §9).
        if self.schema.as_deref().is_some_and(Schema::is_core) && self.ak.as_str() == "/created" {
            return <osis_base::CreationRecord as Codec>::from_value(v).map(|_| v.clone());
        }
        match (self.schema.as_deref(), AspectKey::ty(self)) {
            (Some(s), Some(t)) => typed_read(s, v, t),
            _ => Ok(v.clone()),
        }
    }
    fn encode(&self, t: &Value) -> Value {
        t.clone()
    }
}

/// Typed keys of the core aspects (spec/data-model.md §9). Membership-class aspects are read
/// here and written only through the sharing calls.
pub mod core {
    pub use osis_schema::core_types::{ASPECTS, BODY, CREATED, GROUP, GROUPS, Group, KEYS, LABEL, MEMBERS, MOVED, NAME, NODE, REACH, SECRETS, SEEN, TAG, TENURES, TID, Tag, WAS};

    /// Field ids of `/group` (spec/data-model.md §8), for path ops on it.
    pub mod group {
        use osis_schema::FieldId;
        /// `set<tid>`: the group's items.
        pub const ITEMS: FieldId = FieldId(0);
        /// `set<tid>`: its subgroups.
        pub const SUBGROUPS: FieldId = FieldId(1);
    }
}
