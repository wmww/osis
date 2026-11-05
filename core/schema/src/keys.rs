//! Typed aspect keys (notes/api.md Keys). `Aspect<T>` are constants
//! (generated per declared AK, or the core ones in `core_types`); `Ak` is the
//! untyped key with `T = Value`, for the engine: an app's key is an `AspectKey`, a `RawKey` too.

use crate::codec::Codec;
use crate::path::{Path, PathError, PathErrorKind};
use crate::schema::{AspectDefaults, Lifetime, Schema};
use crate::statics::StaticSchema;
use crate::typed::{typed_read, validate_write};
use crate::types::Type;
use osis_base::{Ak, Value};
use std::marker::PhantomData;

#[doc(hidden)]
pub trait RawKey {
    /// The Rust type its values read as.
    type T;
    #[doc(hidden)]
    fn ak(&self) -> &str;
    #[doc(hidden)]
    /// The writer's schema; `None` for an untyped write (untyped defaults).
    fn schema(&self) -> Option<&Schema>;
    #[doc(hidden)]
    /// `schema` as a shared copy (a key holding an `Arc` shares it instead of copying).
    fn shared_schema(&self) -> Option<std::sync::Arc<Schema>> {
        self.schema().map(|s| std::sync::Arc::new(s.clone()))
    }
    #[doc(hidden)]
    /// Typed read (reader defaults, open structs), then into `T`.
    fn decode(&self, v: &Value) -> Result<Self::T, PathError>;
    #[doc(hidden)]
    fn encode(&self, t: &Self::T) -> Value;

    #[doc(hidden)]
    /// The aspect's type in its schema.
    fn ty(&self) -> Option<&Type> {
        self.schema()?.aspects.get(self.ak()).map(|a| &a.ty)
    }
    #[doc(hidden)]
    /// Retention and expiry a write puts into its delta (untyped: `author`, no bounds, no expiry).
    fn defaults(&self) -> AspectDefaults {
        self.schema().and_then(|s| s.defaults(self.ak())).unwrap_or_default()
    }
    #[doc(hidden)]
    /// Where its writes go: the AK's lifetime marker (spec/data-model.md §2), typed or not.
    fn lifetime(&self) -> Lifetime {
        Ak::markers_of(self.ak()).1
    }
    #[doc(hidden)]
    /// Validates a write against the writer's schema (spec/versioning.md §5); untyped writes
    /// always pass.
    fn validate(&self, v: &Value) -> Result<(), PathError> {
        match self.schema() {
            None => Ok(()),
            Some(s) => validate_write(s, v, self.ty().ok_or_else(|| undeclared(self.ak()))?),
        }
    }
}

/// What a call of the `osis` API takes as an aspect's key: generated keys and `osis::Key`, not a
/// bare name.
pub trait AspectKey: RawKey {}

impl<T: Codec> AspectKey for Aspect<T> {}

fn undeclared(ak: &str) -> PathError {
    PathError::new(Path::root(), PathErrorKind::Schema(format!("{ak} is not declared by its schema")))
}

impl RawKey for Ak {
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

/// A typed aspect key, as generated from a schema: its name and the Rust type its values read as.
pub struct Aspect<T> {
    ak: &'static str,
    schema: &'static StaticSchema,
    _t: PhantomData<fn() -> T>,
}

impl<T> Aspect<T> {
    /// Fails the build, in a `const` item, unless `ak` parses as an AK: every generated key
    /// constant is checked so (`Ak::check`).
    pub const fn new(ak: &'static str, schema: &'static StaticSchema) -> Aspect<T> {
        Aspect { ak: Ak::check(ak), schema, _t: PhantomData }
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

impl<T: Codec> RawKey for Aspect<T> {
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

