//! `DynamicAspectKey`: an aspect key by name, typed by a schema registered at run time (`Osis::aspect_key`), and the
//! core keys apps write. Typed `Aspect<T>` come from codegen (osis-schema).

use osis_base::{Ak, Value};
use osis_schema::{RawKey, Codec, PathError, Schema, typed_read};
use std::sync::Arc;

/// An aspect key made at run time (`Osis::aspect_key`), its values plain `Value`s. Under a registered
/// schema its reads are typed and its writes validated.
#[derive(Clone, Debug)]
pub struct DynamicAspectKey {
    pub(crate) ak: Ak,
    pub(crate) schema: Option<Arc<Schema>>,
}

/// The core schema, one shared copy.
pub(crate) fn core_schema() -> Arc<Schema> {
    static CORE: std::sync::OnceLock<Arc<Schema>> = std::sync::OnceLock::new();
    CORE.get_or_init(|| Arc::new(osis_schema::core_schema().clone())).clone()
}

impl DynamicAspectKey {
    /// The key named `ak` with no schema, even where one is registered: any stored value as it is.
    pub fn untyped(ak: Ak) -> DynamicAspectKey {
        DynamicAspectKey { ak, schema: None }
    }

    /// Its name.
    pub fn name(&self) -> &Ak {
        &self.ak
    }

    /// The type of its values, as its schema declares it (`None`: no schema declares it): `get()`
    /// its shape, `name()` its declared name.
    pub fn value_type(&self) -> Option<crate::NestedType> {
        let s = self.schema.clone()?;
        let ty = s.aspects.get(self.ak.as_str())?.ty.clone();
        Some(crate::value_type::nested(s, ty))
    }

    /// Who may purge a write through this key and how long it is held, unless it says otherwise (`AspectWrite::retention`).
    pub fn default_retention(&self) -> crate::Retention {
        self.defaults().retention.into()
    }
}

impl osis_schema::AspectKey for DynamicAspectKey {}

impl RawKey for DynamicAspectKey {
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

/// Aspects every app shares the meaning of, and the rule of what may be written to a thing.
pub mod core {
    /// What a thing is called.
    pub use osis_schema::core_types::NAME;
    /// A thing's main text.
    pub use osis_schema::core_types::BODY;
    /// Marks a thing as a tag.
    pub use osis_schema::core_types::TAG;
    pub use osis_schema::core_types::Tag;
    pub use crate::retention::{Required, RequiredRules};
    /// What every write to a thing must keep to, by aspect: how long it is held, when it
    /// expires. An admin sets it; a write that breaks it is refused.
    pub const REQUIRED: osis_schema::Aspect<RequiredRules> = osis_schema::Aspect::new("required.0^", &osis_schema::CORE);
}
