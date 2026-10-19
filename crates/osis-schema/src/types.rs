//! Type model (spec/data-model.md §3), shaped like the schema-as-data `type_expr` (§10).

use osis_core::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A type expression. `Named` covers schema types and the standard named types (`option`,
/// `markdown`, `timestamp`, `duration`); `Param` is a parameter of the enclosing type definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Type {
    String,
    Blob,
    Bool,
    Int,
    Float,
    Tid,
    Any,
    Text,
    List(Box<Type>),
    Set(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Struct(StructType),
    Enum(EnumType),
    Counter(Box<Type>),
    Max(Box<Type>),
    Min(Box<Type>),
    Named(String, Vec<Type>),
    Param(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StructType {
    pub fields: BTreeMap<u64, Field>,
    pub reserved: BTreeSet<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    /// Declared constant default. An `option` field without one defaults to `none`
    /// (`Schema::default_of`).
    pub default: Option<Value>,
    pub succeeds: BTreeSet<u64>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnumType {
    pub cases: BTreeMap<u64, Case>,
    pub reserved: BTreeSet<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub name: String,
    pub payload: Option<Type>,
    pub succeeds: BTreeSet<u64>,
    pub doc: Option<String>,
}

/// Standard named types (spec/data-model.md §3) with their parameter count.
pub const STANDARD: &[(&str, usize)] = &[("option", 1), ("markdown", 0), ("timestamp", 0), ("duration", 0)];

/// Names a schema type may not take: builtins, standard named types, DSL keywords.
pub fn is_reserved_name(n: &str) -> bool {
    STANDARD.iter().any(|(s, _)| *s == n)
        || matches!(
            n,
            "string" | "blob" | "bool" | "int" | "float" | "tid" | "any" | "text" | "list" | "set" | "map" | "struct"
                | "enum" | "counter" | "max" | "min" | "type" | "aspect" | "signal" | "schema" | "revision"
                | "reserved" | "succeeds" | "true" | "false"
        )
}

impl Type {
    pub fn named(n: &str) -> Type {
        Type::Named(n.to_string(), Vec::new())
    }
    pub fn option(t: Type) -> Type {
        Type::Named("option".into(), vec![t])
    }
    /// `option<T>` = `enum { 0 none, 1 some(T) }`.
    pub fn option_body(t: Type) -> Type {
        let mut cases = BTreeMap::new();
        cases.insert(0, Case { name: "none".into(), payload: None, succeeds: BTreeSet::new(), doc: None });
        cases.insert(1, Case { name: "some".into(), payload: Some(t), succeeds: BTreeSet::new(), doc: None });
        Type::Enum(EnumType { cases, reserved: BTreeSet::new() })
    }
    /// Encoding wrapper (counter, max, min, text); `markdown` is one too once expanded.
    pub fn is_wrapper(&self) -> bool {
        matches!(self, Type::Counter(_) | Type::Max(_) | Type::Min(_) | Type::Text)
    }
    /// Replaces `Param(p)` with the matching argument, without expanding named types (so
    /// recursive types stay finite).
    pub fn subst(&self, params: &[String], args: &[Type]) -> Type {
        let s = |t: &Type| Box::new(t.subst(params, args));
        match self {
            Type::Param(p) => match params.iter().position(|q| q == p).and_then(|i| args.get(i)) {
                Some(a) => a.clone(),
                None => self.clone(),
            },
            Type::List(t) => Type::List(s(t)),
            Type::Set(t) => Type::Set(s(t)),
            Type::Map(k, v) => Type::Map(s(k), s(v)),
            Type::Counter(t) => Type::Counter(s(t)),
            Type::Max(t) => Type::Max(s(t)),
            Type::Min(t) => Type::Min(s(t)),
            Type::Named(n, a) => Type::Named(n.clone(), a.iter().map(|t| t.subst(params, args)).collect()),
            Type::Struct(st) => Type::Struct(StructType {
                fields: st.fields.iter().map(|(id, f)| (*id, Field { ty: f.ty.subst(params, args), ..f.clone() })).collect(),
                reserved: st.reserved.clone(),
            }),
            Type::Enum(en) => Type::Enum(EnumType {
                cases: en
                    .cases
                    .iter()
                    .map(|(id, c)| (*id, Case { payload: c.payload.as_ref().map(|p| p.subst(params, args)), ..c.clone() }))
                    .collect(),
                reserved: en.reserved.clone(),
            }),
            Type::String | Type::Blob | Type::Bool | Type::Int | Type::Float | Type::Tid | Type::Any | Type::Text => {
                self.clone()
            }
        }
    }
}
