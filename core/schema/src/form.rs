//! Schema as an osis value (spec/data-model.md §10): `to_value`, `from_value`, canonical bytes
//! and hash. A typed write carries every declared field, so the canonical form spells out every
//! field (`none` included).

use crate::codec::Codec;
use crate::error::Error;
use crate::schema::{AspectDef, Flag, Retention, Schema, TypeDef};
use crate::statics::StaticSchema;
use crate::typed::typed_read;
use crate::types::{Case, EnumType, Field, StructType, Type};
use osis_base::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Source of the schema of schemas (spec/data-model.md §10).
pub const META_SRC: &str = include_str!("../../../schema/meta.osis");
static META: StaticSchema = StaticSchema::new("meta.osis", META_SRC);

/// The schema of schemas: its `schema` type types every schema value.
pub fn meta_schema() -> &'static Schema {
    META.get()
}

fn st(fields: Vec<Value>) -> Value {
    Value::Map(fields.into_iter().enumerate().map(|(i, v)| (Value::uint(i as u64), v)).collect())
}
fn case(id: u64, payload: Value) -> Value {
    Value::Enum(id, Some(Box::new(payload)))
}
/// `type_expr` value of a type.
fn type_value(t: &Type) -> Value {
    let b = |t: &Type| type_value(t);
    match t {
        Type::String => Value::Enum(0, None),
        Type::Blob => Value::Enum(1, None),
        Type::Bool => Value::Enum(2, None),
        Type::Int => Value::Enum(3, None),
        Type::Float => Value::Enum(4, None),
        Type::Tid => Value::Enum(5, None),
        Type::Any => Value::Enum(6, None),
        Type::Text => Value::Enum(7, None),
        Type::List(e) => case(8, b(e)),
        Type::Set(e) => case(9, b(e)),
        Type::Map(k, v) => case(10, st(vec![b(k), b(v)])),
        Type::Struct(s) => {
            let fields = s.fields.iter().map(|(id, f)| {
                (id.to_value(), st(vec![f.name.to_value(), b(&f.ty), f.default.to_value(), f.succeeds.to_value(), f.doc.to_value()]))
            });
            case(11, st(vec![Value::Map(fields.collect()), s.reserved.to_value()]))
        }
        Type::Enum(e) => {
            let cases = e.cases.iter().map(|(id, c)| {
                (id.to_value(), st(vec![c.name.to_value(), c.payload.as_ref().map(b).to_value(), c.succeeds.to_value(), c.doc.to_value()]))
            });
            case(12, st(vec![Value::Map(cases.collect()), e.reserved.to_value()]))
        }
        Type::Counter(e) => case(13, b(e)),
        Type::Max(e) => case(14, b(e)),
        Type::Min(e) => case(15, b(e)),
        Type::Named(n, args) => case(16, st(vec![n.to_value(), Value::List(args.iter().map(b).collect())])),
        Type::Param(p) => case(17, p.to_value()),
    }
}

impl Schema {
    /// The schema's value (type `schema` of spec/data-model.md §10).
    pub fn to_value(&self) -> Value {
        let types = self.types.iter().map(|(n, d)| (n.to_value(), st(vec![d.params.to_value(), type_value(&d.body), d.doc.to_value()])));
        let aspects = self.aspects.iter().map(|(ak, a)| {
            let flags = Value::Set(a.flags.iter().map(|f| Value::Enum(*f as u64, None)).collect());
            let retention = st(vec![a.retention.by.to_value()]);
            (ak.to_value(), st(vec![type_value(&a.ty), retention, a.expires.to_value(), flags, a.succeeds.to_value(), a.doc.to_value()]))
        });
        st(vec![self.revision.to_value(), Value::Map(types.collect()), Value::Map(aspects.collect()), self.doc.to_value()])
    }

    /// Canonical form: the canonical encoding of `to_value`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        osis_base::encode(&self.to_value())
    }

    /// Reads a schema value: typed against the schema of schemas, then validated.
    pub fn from_value(v: &Value) -> Result<Schema, Error> {
        let v = typed_read(meta_schema(), v, &Type::named("schema")).map_err(|e| Error::Form(e.to_string()))?;
        let f = Fields::of(&v)?;
        let mut s = Schema::new(f.get(0)?);
        for (n, d) in f.get::<BTreeMap<String, Value>>(1)? {
            let d = Fields::of(&d)?;
            s.types.insert(n, TypeDef { params: d.get(0)?, body: read_type(d.val(1)?)?, doc: d.get(2)? });
        }
        for (ak, a) in f.get::<BTreeMap<String, Value>>(2)? {
            let a = Fields::of(&a)?;
            let flags = a
                .get::<BTreeSet<Value>>(3)?
                .into_iter()
                .map(|f| match f {
                    Value::Enum(c, None) => Flag::from_id(c).ok_or_else(|| Error::Form("flag case".into())),
                    _ => Err(Error::Form("flag".into())),
                })
                .collect::<Result<_, _>>()?;
            let retention = Retention { by: Fields::of(a.val(1)?)?.get(0)? };
            let def = AspectDef { ty: read_type(a.val(0)?)?, retention, expires: a.get(2)?, flags, succeeds: a.get(4)?, doc: a.get(5)? };
            s.aspects.insert(ak, def);
        }
        s.doc = f.get(3)?;
        if let Some(inv) = s.validate().into_iter().next() {
            return Err(Error::Form(format!("{}: {}", inv.item, inv.msg)));
        }
        Ok(s)
    }
}

/// Struct fields of a typed-read (so complete) struct value.
struct Fields<'a>(&'a osis_base::ValueMap);

fn form<T>(m: &str) -> Result<T, Error> {
    Err(Error::Form(m.into()))
}

impl<'a> Fields<'a> {
    fn of(v: &'a Value) -> Result<Fields<'a>, Error> {
        match v {
            Value::Map(m) => Ok(Fields(m)),
            _ => form("expected struct"),
        }
    }
    fn val(&self, id: i64) -> Result<&'a Value, Error> {
        self.0.get(&Value::Int(id)).ok_or_else(|| Error::Form(format!("missing field {id}")))
    }
    fn get<T: Codec>(&self, id: i64) -> Result<T, Error> {
        T::from_value(self.val(id)?).map_err(|e| Error::Form(format!("field {id}: {e}")))
    }
}

/// A `type_expr` value (already typed by the schema of schemas).
fn read_type(v: &Value) -> Result<Type, Error> {
    let Value::Enum(c, p) = v else { return form("expected type_expr") };
    let Some(p) = p.as_deref() else {
        return Ok(match c {
            0 => Type::String,
            1 => Type::Blob,
            2 => Type::Bool,
            3 => Type::Int,
            4 => Type::Float,
            5 => Type::Tid,
            6 => Type::Any,
            7 => Type::Text,
            _ => return form("type_expr payload"),
        });
    };
    let inner = || read_type(p).map(Box::new);
    let f = || Fields::of(p);
    Ok(match c {
        8 => Type::List(inner()?),
        9 => Type::Set(inner()?),
        10 => Type::Map(Box::new(read_type(f()?.val(0)?)?), Box::new(read_type(f()?.val(1)?)?)),
        11 => {
            let f = f()?;
            let mut fields = BTreeMap::new();
            for (id, fd) in f.get::<BTreeMap<u64, Value>>(0)? {
                let fd = Fields::of(&fd)?;
                let field = Field { name: fd.get(0)?, ty: read_type(fd.val(1)?)?, default: fd.get(2)?, succeeds: fd.get(3)?, doc: fd.get(4)? };
                fields.insert(id, field);
            }
            Type::Struct(StructType { fields, reserved: f.get(1)? })
        }
        12 => {
            let f = f()?;
            let mut cases = BTreeMap::new();
            for (id, cd) in f.get::<BTreeMap<u64, Value>>(0)? {
                let cd = Fields::of(&cd)?;
                let payload = cd.get::<Option<Value>>(1)?.as_ref().map(read_type).transpose()?;
                cases.insert(id, Case { name: cd.get(0)?, payload, succeeds: cd.get(2)?, doc: cd.get(3)? });
            }
            Type::Enum(EnumType { cases, reserved: f.get(1)? })
        }
        13 => Type::Counter(inner()?),
        14 => Type::Max(inner()?),
        15 => Type::Min(inner()?),
        16 => {
            let f = f()?;
            Type::Named(f.get(0)?, f.get::<Vec<Value>>(1)?.iter().map(read_type).collect::<Result<_, _>>()?)
        }
        17 => Type::Param(String::from_value(p).map_err(|e| Error::Form(e.to_string()))?),
        _ => return form("unknown type_expr case"),
    })
}
