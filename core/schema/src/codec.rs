//! Rust types to and from values (notes/api.md Keys): `Codec`, its impls for standard types, the
//! `codec_struct!` macro used by the core types and generated code, `Chunked<T>`.
//!
//! `from_value` takes a typed-read value (reader defaults filled, spec/versioning.md §5), so a
//! missing field is an error here; typed keys run the typed read first.

use crate::path::{PathError, PathErrorKind, Step};
use osis_base::{BlobId, CommitId, Float, LabelId, Link, Role, SchemaId, Tid, Ts, Value, WallMs};
use std::collections::{BTreeMap, BTreeSet};

pub trait Codec: Sized {
    /// `from_value` validates the raw value completely, so typed keys skip the schema's typed
    /// read (the creation record: its fields 0 and 1 are exclusive, which the type system cannot
    /// say; spec/data-model.md §9).
    const CHECKS_ITSELF: bool = false;
    fn to_value(&self) -> Value;
    fn from_value(v: &Value) -> Result<Self, PathError>;
}

fn mismatch(expected: &'static str) -> PathError {
    PathError::new(crate::Path::root(), PathErrorKind::Mismatch { expected })
}

impl Codec for Value {
    fn to_value(&self) -> Value {
        self.clone()
    }
    fn from_value(v: &Value) -> Result<Value, PathError> {
        Ok(v.clone())
    }
}

macro_rules! scalar {
    ($t:ty, $variant:ident, $name:literal) => {
        impl Codec for $t {
            fn to_value(&self) -> Value {
                Value::$variant(self.clone())
            }
            fn from_value(v: &Value) -> Result<$t, PathError> {
                match v {
                    Value::$variant(x) => Ok(x.clone()),
                    _ => Err(mismatch($name)),
                }
            }
        }
    };
}
scalar!(String, Str, "string");
scalar!(bool, Bool, "bool");
scalar!(i64, Int, "int");
scalar!(Tid, Tid, "tid");
scalar!(Float, Float, "float");

impl Codec for f64 {
    fn to_value(&self) -> Value {
        Value::float(*self)
    }
    fn from_value(v: &Value) -> Result<f64, PathError> {
        Float::from_value(v).map(Float::get)
    }
}

impl Codec for u64 {
    fn to_value(&self) -> Value {
        Value::Int(i64::try_from(*self).unwrap_or(i64::MAX))
    }
    fn from_value(v: &Value) -> Result<u64, PathError> {
        match v {
            Value::Int(i) if *i >= 0 => Ok(i.unsigned_abs()),
            _ => Err(mismatch("non-negative int")),
        }
    }
}

impl Codec for WallMs {
    fn to_value(&self) -> Value {
        self.0.to_value()
    }
    fn from_value(v: &Value) -> Result<WallMs, PathError> {
        u64::from_value(v).map(WallMs)
    }
}

impl Codec for Ts {
    fn to_value(&self) -> Value {
        self.to_u64().to_value()
    }
    fn from_value(v: &Value) -> Result<Ts, PathError> {
        Ts::from_u64(u64::from_value(v)?).ok_or_else(|| mismatch("ts"))
    }
}

/// `blob` of any length (`u8` is not `Codec`, so this does not overlap `Vec<T>`).
impl Codec for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
    fn from_value(v: &Value) -> Result<Vec<u8>, PathError> {
        match v {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(mismatch("blob")),
        }
    }
}

impl<const N: usize> Codec for [u8; N] {
    fn to_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
    fn from_value(v: &Value) -> Result<[u8; N], PathError> {
        match v {
            Value::Bytes(b) => b.as_slice().try_into().map_err(|_| mismatch("blob of the declared length")),
            _ => Err(mismatch("blob")),
        }
    }
}

macro_rules! byte_id {
    ($t:ident) => {
        impl Codec for $t {
            fn to_value(&self) -> Value {
                self.0.to_value()
            }
            fn from_value(v: &Value) -> Result<$t, PathError> {
                Codec::from_value(v).map($t)
            }
        }
    };
}
byte_id!(LabelId);
byte_id!(SchemaId);
byte_id!(CommitId);
byte_id!(BlobId);

/// `role = enum { 0 read, 1 write, 2 admin }` (spec/data-model.md §9).
impl Codec for Role {
    fn to_value(&self) -> Value {
        Value::Enum(
            match self {
                Role::Read => 0,
                Role::Write => 1,
                Role::Admin => 2,
            },
            None,
        )
    }
    fn from_value(v: &Value) -> Result<Role, PathError> {
        match v {
            Value::Enum(0, None) => Ok(Role::Read),
            Value::Enum(1, None) => Ok(Role::Write),
            Value::Enum(2, None) => Ok(Role::Admin),
            Value::Enum(c, _) => Err(PathError::new(crate::Path::root(), PathErrorKind::UnknownCase(*c))),
            _ => Err(mismatch("enum")),
        }
    }
}

/// `option<T>`.
impl<T: Codec> Codec for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            None => Value::Enum(0, None),
            Some(t) => Value::Enum(1, Some(Box::new(t.to_value()))),
        }
    }
    fn from_value(v: &Value) -> Result<Option<T>, PathError> {
        match v {
            Value::Enum(0, None) => Ok(None),
            Value::Enum(1, Some(p)) => T::from_value(p).map(Some).map_err(|e| e.within(Step::Case(1))),
            _ => Err(mismatch("option")),
        }
    }
}

impl<T: Codec> Codec for Vec<T> {
    fn to_value(&self) -> Value {
        Value::List(self.iter().map(Codec::to_value).collect())
    }
    fn from_value(v: &Value) -> Result<Vec<T>, PathError> {
        match v {
            Value::List(l) => l.iter().enumerate().map(|(i, x)| T::from_value(x).map_err(|e| e.within(Step::Index(i)))).collect(),
            _ => Err(mismatch("list")),
        }
    }
}

impl<T: Codec + Ord> Codec for BTreeSet<T> {
    fn to_value(&self) -> Value {
        Value::Set(self.iter().map(Codec::to_value).collect())
    }
    fn from_value(v: &Value) -> Result<BTreeSet<T>, PathError> {
        match v {
            Value::Set(s) => s.iter().map(|x| T::from_value(x).map_err(|e| e.within(Step::Elem(x.clone())))).collect(),
            _ => Err(mismatch("set")),
        }
    }
}

impl<K: Codec + Ord, V: Codec> Codec for BTreeMap<K, V> {
    fn to_value(&self) -> Value {
        Value::Map(self.iter().map(|(k, v)| (k.to_value(), v.to_value())).collect())
    }
    fn from_value(v: &Value) -> Result<BTreeMap<K, V>, PathError> {
        match v {
            Value::Map(m) => m
                .iter()
                .map(|(k, x)| {
                    let at = |e: PathError| e.within(Step::Key(k.clone()));
                    Ok((K::from_value(k).map_err(at)?, V::from_value(x).map_err(at)?))
                })
                .collect(),
            _ => Err(mismatch("map")),
        }
    }
}

impl<T: Codec> Codec for Box<T> {
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
    fn from_value(v: &Value) -> Result<Box<T>, PathError> {
        T::from_value(v).map(Box::new)
    }
}

/// A large atomic value: inline, or the root link of its chunk tree (spec/data-model.md §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chunked<T> {
    Inline(T),
    Link(Link),
}

impl<T: Codec> Codec for Chunked<T> {
    fn to_value(&self) -> Value {
        match self {
            Chunked::Inline(t) => t.to_value(),
            Chunked::Link(l) => Value::Link(*l),
        }
    }
    fn from_value(v: &Value) -> Result<Chunked<T>, PathError> {
        match v {
            Value::Link(l) => Ok(Chunked::Link(*l)),
            _ => T::from_value(v).map(Chunked::Inline),
        }
    }
}

/// Helpers for `codec_struct!` and generated code. Not a stable API.
#[doc(hidden)]
pub mod rt {
    pub use osis_base::Value;
    use super::*;

    pub fn struct_value(fields: Vec<(u64, Value)>) -> Value {
        Value::Map(fields.into_iter().map(|(id, v)| (id.to_value(), v)).collect())
    }
    pub fn struct_map(v: &Value) -> Result<&BTreeMap<Value, Value>, PathError> {
        match v {
            Value::Map(m) => Ok(m),
            _ => Err(mismatch("struct")),
        }
    }
    pub fn field<T: Codec>(m: &BTreeMap<Value, Value>, id: u64) -> Result<T, PathError> {
        let x = m.get(&id.to_value()).ok_or_else(|| PathError::new(crate::Path::root(), PathErrorKind::MissingField(id)))?;
        T::from_value(x).map_err(|e| e.within(Step::Field(id)))
    }
    pub fn payload<T: Codec>(case: u64, p: &Option<Box<Value>>) -> Result<T, PathError> {
        match p {
            Some(x) => T::from_value(x).map_err(|e| e.within(Step::Case(case))),
            None => Err(PathError::new(crate::Path::root(), PathErrorKind::MissingPayload(case))),
        }
    }
    pub fn enum_value(case: u64, payload: Option<Value>) -> Value {
        Value::Enum(case, payload.map(Box::new))
    }
    pub fn unknown_case(v: &Value) -> PathError {
        match v {
            Value::Enum(c, _) => PathError::new(crate::Path::root(), PathErrorKind::UnknownCase(*c)),
            _ => mismatch("enum"),
        }
    }
}

/// A struct with field IDs and its `Codec`: `codec_struct! { pub struct Seen { 0 ts: WallMs, 1 stranded: bool } }`.
/// Type parameters must be `Codec`.
#[macro_export]
macro_rules! codec_struct {
    ($(#[$m:meta])* $vis:vis struct $name:ident $(<$($g:ident),*>)? { $($(#[$fm:meta])* $id:literal $f:ident : $t:ty),* $(,)? }) => {
        $(#[$m])*
        $vis struct $name $(<$($g),*>)? { $($(#[$fm])* pub $f: $t),* }
        impl $(<$($g: $crate::Codec),*>)? $crate::Codec for $name $(<$($g),*>)? {
            fn to_value(&self) -> $crate::codec::rt::Value {
                $crate::codec::rt::struct_value(vec![$(($id, $crate::Codec::to_value(&self.$f))),*])
            }
            #[allow(unused_variables)]
            fn from_value(v: &$crate::codec::rt::Value) -> Result<Self, $crate::PathError> {
                let m = $crate::codec::rt::struct_map(v)?;
                Ok($name { $($f: $crate::codec::rt::field(m, $id)?),* })
            }
        }
    };
}

/// An enum with case IDs and its `Codec`: `codec_enum! { pub enum Priority { 0 Low, 3 Custom(x: i64) } }`
/// (a payload case names a binding for its value). Type parameters must be `Codec`.
#[macro_export]
macro_rules! codec_enum {
    (@pat $n:ident $c:ident) => { $n::$c };
    (@pat $n:ident $c:ident $x:ident) => { $n::$c($x) };
    (@to $id:literal) => { $crate::codec::rt::enum_value($id, None) };
    (@to $id:literal $x:ident) => { $crate::codec::rt::enum_value($id, Some($crate::Codec::to_value($x))) };
    (@from $v:ident $p:ident $id:literal $n:ident $c:ident) => {
        if $p.is_none() { Ok($n::$c) } else { Err($crate::codec::rt::unknown_case($v)) }
    };
    (@from $v:ident $p:ident $id:literal $n:ident $c:ident $x:ident) => { $crate::codec::rt::payload($id, $p).map($n::$c) };
    ($(#[$m:meta])* $vis:vis enum $name:ident $(<$($g:ident),*>)? { $($(#[$cm:meta])* $id:literal $c:ident $(($x:ident : $t:ty))?),* $(,)? }) => {
        $(#[$m])*
        $vis enum $name $(<$($g),*>)? { $($(#[$cm])* $c $(($t))?),* }
        impl $(<$($g: $crate::Codec),*>)? $crate::Codec for $name $(<$($g),*>)? {
            fn to_value(&self) -> $crate::codec::rt::Value {
                match self {
                    $($crate::codec_enum!(@pat $name $c $($x)?) => $crate::codec_enum!(@to $id $($x)?),)*
                }
            }
            fn from_value(v: &$crate::codec::rt::Value) -> Result<Self, $crate::PathError> {
                match v {
                    $($crate::codec::rt::Value::Enum($id, p) => $crate::codec_enum!(@from v p $id $name $c $($x)?),)*
                    _ => Err($crate::codec::rt::unknown_case(v)),
                }
            }
        }
    };
}

/// A module of field or case ID constants, for generated code:
/// `ids! { pub mod task: FieldId { TITLE = 1, DONE = 2 } }`.
#[macro_export]
macro_rules! ids {
    ($(#[$m:meta])* $vis:vis mod $name:ident : $ty:ident { $($c:ident = $id:literal),* $(,)? }) => {
        $(#[$m])*
        $vis mod $name {
            $(pub const $c: $crate::$ty = $crate::$ty($id);)*
        }
    };
}

/// `TryFrom<&Value>` through a schema's typed read of its type `name` (reader defaults, open
/// structs), and `From<&T> for Value`: for generated types.
#[macro_export]
macro_rules! named_type {
    ($t:ident, $name:literal, $schema:path) => {
        impl TryFrom<&$crate::osis_base::Value> for $t {
            type Error = $crate::PathError;
            fn try_from(v: &$crate::osis_base::Value) -> Result<$t, $crate::PathError> {
                let n = $crate::typed_read($schema.get(), v, &$crate::Type::named($name))?;
                $crate::Codec::from_value(&n)
            }
        }
        impl From<&$t> for $crate::osis_base::Value {
            fn from(t: &$t) -> $crate::osis_base::Value {
                $crate::Codec::to_value(t)
            }
        }
    };
}
