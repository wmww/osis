//! `Key`: an aspect key by name, typed by a schema registered at run time (`Osis::key`), and the
//! core keys. Typed `Aspect<T>` come from codegen (osis-schema).

use osis_base::{Ak, Value};
use osis_schema::{AspectKey, Codec, PathError, Schema, typed_read};
use std::sync::Arc;

/// An aspect key by name (`Osis::key`), its values plain `Value`s. Under a registered schema reads
/// are typed reads projected back to `Value` (reader defaults, failures with the path) and writes
/// are validated.
#[derive(Clone, Debug)]
pub struct Key {
    pub(crate) ak: Ak,
    pub(crate) schema: Option<Arc<Schema>>,
}

/// The core schema, one shared copy.
pub(crate) fn core_schema() -> Arc<Schema> {
    static CORE: std::sync::OnceLock<Arc<Schema>> = std::sync::OnceLock::new();
    CORE.get_or_init(|| Arc::new(osis_schema::core_schema().clone())).clone()
}

impl Key {
    /// The key named `ak` with no schema, even where one is registered: any stored value as it is.
    pub fn untyped(ak: Ak) -> Key {
        Key { ak, schema: None }
    }

    /// Its name.
    pub fn name(&self) -> &Ak {
        &self.ak
    }
}

impl osis_schema::ApiKey for Key {}

impl AspectKey for Key {
    type T = Value;
    fn ak(&self) -> &str {
        self.ak.as_str()
    }
    fn schema(&self) -> Option<&Schema> {
        self.schema.as_deref()
    }
    fn shared_schema(&self) -> Option<Arc<Schema>> {
        self.schema.clone()
    }
    fn decode(&self, v: &Value) -> Result<Value, PathError> {
        // `created.0` is typed by its exclusivity rule, not the missing-field rule
        // (spec/data-model.md §9).
        if self.schema.is_some() && self.ak.as_str() == osis_schema::core_types::CREATED.ak() {
            return <osis_base::CreationRecord as Codec>::from_value(v).map(|_| v.clone());
        }
        match (self.schema.as_deref(), self.ty()) {
            (Some(s), Some(t)) => typed_read(s, v, t),
            _ => Ok(v.clone()),
        }
    }
    fn encode(&self, t: &Value) -> Value {
        t.clone()
    }
}

/// Typed keys of the core aspects (spec/data-model.md §9). Role-class aspects are read here and
/// written only through the sharing calls, `GROUP` only through the group calls of `Write`.
pub mod core {
    pub use osis_schema::core_types::{ASPECTS, BODY, CREATED, GROUP, GROUPS, Group, KEYS, LABEL, ROLES, NAME, NODE, PLACED, REACH, REQUIRED, Required, RequiredRules, SECRETS, SEEN, TAG, TENURES, TID, Tag};

    /// Field ids of `group.0` (spec/data-model.md §8), for path reads of it.
    pub mod group {
        use osis_schema::FieldId;
        /// `set<tid>`: the group's items.
        pub const ITEMS: FieldId = FieldId(0);
        /// `set<tid>`: its subgroups.
        pub const SUBGROUPS: FieldId = FieldId(1);
    }
}
