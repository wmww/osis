//! `ValueType`: what a registered schema says an aspect's values look like, for code that handles
//! aspects it was not generated for (a form, a command line). Types may be recursive, so what is
//! nested in one is expanded when asked for.

use osis_base::Value;
use osis_schema::{Schema, Type};
use std::sync::Arc;

/// The shape of a value (`Key::value_type`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValueType {
    /// A string, replaced whole (`Value::Str`).
    String,
    /// Text that merges by character (`Value::Str`): what `edit_text` edits.
    Text,
    /// `Value::Bytes`.
    Bytes,
    /// `Value::Bool`.
    Bool,
    /// `Value::Int`.
    Int,
    /// `Value::Float`.
    Float,
    /// A thing's id (`Value::Tid`).
    Thing,
    /// A moment, in milliseconds (`Value::Int`).
    Time,
    /// A length of time, in milliseconds (`Value::Int`).
    Duration,
    /// Anything.
    Any,
    /// A value or nothing: `Value::Enum(0, None)`, or `Value::Enum(1, Some(value))`.
    Optional(NestedType),
    /// One of several cases, maybe each with a value of its own (`Value::Enum(id, value)`).
    Cases(Vec<TypeCase>),
    /// Named fields (`Value::Map`, by `Value::Int(id)`).
    Record(Vec<RecordField>),
    /// `Value::List`.
    List(NestedType),
    /// `Value::Set`.
    Set(NestedType),
    /// `Value::Map`: keys, values.
    Map(NestedType, NestedType),
    /// A number that adds what each writer contributes (`PathWrite::contribute`).
    Counter(NestedType),
    /// The largest value contributed.
    Max(NestedType),
    /// The smallest value contributed.
    Min(NestedType),
}

/// A case of `ValueType::Cases`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeCase {
    /// Its id: `Value::Enum(id, ..)`, `Step::Case(id)`.
    pub id: u64,
    pub name: String,
    pub value: Option<NestedType>,
}

/// A field of `ValueType::Record`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordField {
    /// Its id: `Value::Int(id)`, `Step::Field(id)`.
    pub id: u64,
    pub name: String,
    pub ty: NestedType,
    /// What it reads as when absent.
    pub default: Option<Value>,
}

/// A type inside another.
#[derive(Clone, Debug)]
pub struct NestedType {
    schema: Arc<Schema>,
    ty: Type,
}

impl PartialEq for NestedType {
    fn eq(&self, o: &NestedType) -> bool {
        self.ty == o.ty && (Arc::ptr_eq(&self.schema, &o.schema) || self.schema == o.schema)
    }
}

impl Eq for NestedType {}

impl NestedType {
    /// Its shape.
    pub fn get(&self) -> ValueType {
        describe(&self.schema, &self.ty)
    }

    /// The name it was declared by, short (`string`, `date`, `option<string>`).
    pub fn name(&self) -> String {
        type_name(&self.ty)
    }
}

/// The description of `ty` in `schema`.
pub fn of_schema(schema: Arc<Schema>, ty: Type) -> ValueType {
    describe(&schema, &ty)
}

/// A type's declared name.
pub(crate) fn declared_name(ty: &Type) -> String {
    type_name(ty)
}

fn type_name(t: &Type) -> String {
    match t {
        Type::String => "string".into(),
        Type::Blob => "blob".into(),
        Type::Bool => "bool".into(),
        Type::Int => "int".into(),
        Type::Float => "float".into(),
        Type::Tid => "tid".into(),
        Type::Any => "any".into(),
        Type::Text => "text".into(),
        Type::List(e) => format!("list<{}>", type_name(e)),
        Type::Set(e) => format!("set<{}>", type_name(e)),
        Type::Map(k, v) => format!("map<{}, {}>", type_name(k), type_name(v)),
        Type::Struct(_) => "struct".into(),
        Type::Enum(_) => "enum".into(),
        Type::Counter(e) => format!("counter<{}>", type_name(e)),
        Type::Max(e) => format!("max<{}>", type_name(e)),
        Type::Min(e) => format!("min<{}>", type_name(e)),
        Type::Named(n, args) if args.is_empty() => n.clone(),
        Type::Named(n, args) => format!("{n}<{}>", args.iter().map(type_name).collect::<Vec<_>>().join(", ")),
        Type::Param(p) => p.clone(),
    }
}

/// Follows names until a shape shows; what cannot be followed (an alias chain past the schema's
/// bound, an unknown name) describes as `Any`, as it would read.
fn describe(s: &Arc<Schema>, t: &Type) -> ValueType {
    let nested = |ty: &Type| NestedType { schema: s.clone(), ty: ty.clone() };
    if let Type::Named(n, _) = t {
        match n.as_str() {
            "timestamp" => return ValueType::Time,
            "duration" => return ValueType::Duration,
            _ => {}
        }
    }
    if s.is_option(t) {
        return match s.expand(t).as_deref() {
            Ok(Type::Enum(e)) => e.cases.get(&1).and_then(|c| c.payload.as_ref()).map_or(ValueType::Any, |p| ValueType::Optional(nested(p))),
            _ => ValueType::Any,
        };
    }
    // one name at a time would see `timestamp` behind an alias; expand first only past those
    if let Type::Named(n, args) = t
        && let Some(d) = s.types.get(n)
    {
        return describe(s, &d.body.subst(&d.params, args));
    }
    let Ok(ty) = s.expand(t) else { return ValueType::Any };
    match ty.as_ref() {
        Type::String => ValueType::String,
        Type::Text => ValueType::Text,
        Type::Blob => ValueType::Bytes,
        Type::Bool => ValueType::Bool,
        Type::Int => ValueType::Int,
        Type::Float => ValueType::Float,
        Type::Tid => ValueType::Thing,
        Type::Any | Type::Named(..) | Type::Param(_) => ValueType::Any,
        Type::List(e) => ValueType::List(nested(e)),
        Type::Set(e) => ValueType::Set(nested(e)),
        Type::Map(k, v) => ValueType::Map(nested(k), nested(v)),
        Type::Counter(e) => ValueType::Counter(nested(e)),
        Type::Max(e) => ValueType::Max(nested(e)),
        Type::Min(e) => ValueType::Min(nested(e)),
        Type::Struct(st) => ValueType::Record(st.fields.iter().map(|(id, f)| RecordField { id: *id, name: f.name.clone(), ty: nested(&f.ty), default: s.default_of(f) }).collect()),
        Type::Enum(e) => ValueType::Cases(e.cases.iter().map(|(id, c)| TypeCase { id: *id, name: c.name.clone(), value: c.payload.as_ref().map(nested) }).collect()),
    }
}
