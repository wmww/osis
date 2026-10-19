//! Typed aspect and signal keys (notes/api.md Keys). `Aspect<T>` and `Signal<T>` are constants
//! (generated per declared AK and signal kind, or the core ones in `core_types`); `Ak` is the
//! untyped key with `T = Value`.

use crate::codec::Codec;
use crate::path::{Path, PathError, PathErrorKind};
use crate::schema::{AspectDefaults, Schema};
use crate::statics::StaticSchema;
use crate::typed::{typed_read, validate_write};
use crate::types::Type;
use osis_core::{Ak, SchemaId, Value};
use std::marker::PhantomData;

pub trait AspectKey {
    type T;
    fn ak(&self) -> &str;
    /// The writer's schema; `None` for an untyped write (no schema index, untyped defaults).
    fn schema(&self) -> Option<&Schema>;
    /// Typed read (reader defaults, open structs), then into `T`.
    fn decode(&self, v: &Value) -> Result<Self::T, PathError>;
    fn encode(&self, t: &Self::T) -> Value;

    /// The aspect's type in its schema.
    fn ty(&self) -> Option<&Type> {
        self.schema()?.aspects.get(self.ak()).map(|a| &a.ty)
    }
    /// (schema ID, revision) for the commit's schema table.
    fn schema_ref(&self) -> Option<(SchemaId, u64)> {
        self.schema().map(|s| (s.id, s.revision))
    }
    /// Retention and expiry a write puts into its delta (untyped: `author`, no bounds, no expiry).
    fn defaults(&self) -> AspectDefaults {
        self.schema().and_then(|s| s.defaults(self.ak())).unwrap_or_default()
    }
    /// Validates a write against the writer's schema (spec/versioning.md §5); untyped writes
    /// always pass.
    fn validate(&self, v: &Value) -> Result<(), PathError> {
        match self.schema() {
            None => Ok(()),
            Some(s) => validate_write(s, v, self.ty().ok_or_else(|| undeclared(self.ak()))?),
        }
    }
}

fn undeclared(ak: &str) -> PathError {
    PathError::new(Path::root(), PathErrorKind::Schema(format!("{ak} is not declared by its schema")))
}

impl AspectKey for Ak {
    type T = Value;
    fn ak(&self) -> &str {
        self.as_str()
    }
    fn schema(&self) -> Option<&Schema> {
        None
    }
    fn decode(&self, v: &Value) -> Result<Value, PathError> {
        Ok(v.clone())
    }
    fn encode(&self, t: &Value) -> Value {
        t.clone()
    }
}

/// A typed aspect key: AK, schema, Rust type.
pub struct Aspect<T> {
    ak: &'static str,
    schema: &'static StaticSchema,
    _t: PhantomData<fn() -> T>,
}

impl<T> Aspect<T> {
    pub const fn new(ak: &'static str, schema: &'static StaticSchema) -> Aspect<T> {
        Aspect { ak, schema, _t: PhantomData }
    }
}

impl<T> Clone for Aspect<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Aspect<T> {}
impl<T> std::fmt::Debug for Aspect<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aspect({})", self.ak)
    }
}

impl<T: Codec> AspectKey for Aspect<T> {
    type T = T;
    fn ak(&self) -> &str {
        self.ak
    }
    fn schema(&self) -> Option<&Schema> {
        Some(self.schema.get())
    }
    fn decode(&self, v: &Value) -> Result<T, PathError> {
        if T::CHECKS_ITSELF {
            return T::from_value(v);
        }
        let ty = self.ty().ok_or_else(|| undeclared(self.ak))?;
        T::from_value(&typed_read(self.schema.get(), v, ty)?)
    }
    fn encode(&self, t: &T) -> Value {
        t.to_value()
    }
    fn validate(&self, v: &Value) -> Result<(), PathError> {
        if T::CHECKS_ITSELF {
            return T::from_value(v).map(|_| ());
        }
        validate_write(self.schema.get(), v, self.ty().ok_or_else(|| undeclared(self.ak))?)
    }
}

/// A typed signal kind (spec/data-model.md §2; never stored).
pub struct Signal<T> {
    kind: &'static str,
    schema: &'static StaticSchema,
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for Signal<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Signal<T> {}
impl<T> std::fmt::Debug for Signal<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signal({})", self.kind)
    }
}

impl<T: Codec> Signal<T> {
    pub const fn new(kind: &'static str, schema: &'static StaticSchema) -> Signal<T> {
        Signal { kind, schema, _t: PhantomData }
    }
    pub fn kind(&self) -> &str {
        self.kind
    }
    pub fn schema(&self) -> &Schema {
        self.schema.get()
    }
    pub fn ty(&self) -> Option<&Type> {
        self.schema.get().signals.get(self.kind).map(|s| &s.ty)
    }
    pub fn decode(&self, v: &Value) -> Result<T, PathError> {
        let ty = self.ty().ok_or_else(|| undeclared(self.kind))?;
        T::from_value(&typed_read(self.schema.get(), v, ty)?)
    }
    pub fn encode(&self, t: &T) -> Value {
        t.to_value()
    }
    pub fn validate(&self, v: &Value) -> Result<(), PathError> {
        validate_write(self.schema.get(), v, self.ty().ok_or_else(|| undeclared(self.kind))?)
    }
}
