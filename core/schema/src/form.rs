//! Schema as an osis value (spec/data-model.md §10): `to_value`, `from_value`, canonical bytes
//! and hash. A typed write carries every declared field, so the canonical form spells out every
//! field (`none` included).

use crate::error::Error;
use crate::schema::{AspectDef, Bound, Flag, PurgeBy, Retention, Schema, TypeDef};
use crate::statics::StaticSchema;
use crate::typed::typed_read;
use crate::types::{Case, EnumType, Field, StructType, Type};
use osis_base::{SchemaId, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Source of the schema of schemas (spec/data-model.md §10).
pub const META_SRC: &str = include_str!("../schemas/meta.osis");
static META: StaticSchema = StaticSchema::new("meta.osis", META_SRC);

/// The schema of schemas: its `schema` type types every schema value.
pub fn meta_schema() -> &'static Schema {
    META.get()
}

fn st(fields: Vec<Value>) -> Value {
    Value::Map(fields.into_iter().enumerate().map(|(i, v)| (Value::uint(i as u64), v)).collect())
}
/// A struct value with the given field ids (a retired id stays unused).
fn st_fields(fields: Vec<(u64, Value)>) -> Value {
    Value::Map(fields.into_iter().map(|(i, v)| (Value::uint(i), v)).collect())
}
fn opt(v: Option<Value>) -> Value {
    match v {
        None => Value::Enum(0, None),
        Some(v) => Value::Enum(1, Some(Box::new(v))),
    }
}
fn doc(d: &Option<String>) -> Value {
    opt(d.clone().map(Value::Str))
}
fn ids(s: &BTreeSet<u64>) -> Value {
    Value::Set(s.iter().map(|i| Value::uint(*i)).collect())
}
fn case(id: u64, payload: Value) -> Value {
    Value::Enum(id, Some(Box::new(payload)))
}
fn bound(b: &Bound) -> Value {
    st(vec![opt(b.abs.map(Value::uint)), opt(b.rel.map(Value::uint))])
}

/// `type_expr` value of a type.
pub fn type_value(t: &Type) -> Value {
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
        Type::Struct(s) => case(
            11,
            st(vec![
                Value::Map(
                    s.fields
                        .iter()
                        .map(|(id, f)| {
                            (Value::uint(*id), st(vec![Value::Str(f.name.clone()), b(&f.ty), opt(f.default.clone()), ids(&f.succeeds), doc(&f.doc)]))
                        })
                        .collect(),
                ),
                ids(&s.reserved),
            ]),
        ),
        Type::Enum(e) => case(
            12,
            st(vec![
                Value::Map(
                    e.cases
                        .iter()
                        .map(|(id, c)| {
                            (Value::uint(*id), st(vec![Value::Str(c.name.clone()), opt(c.payload.as_ref().map(b)), ids(&c.succeeds), doc(&c.doc)]))
                        })
                        .collect(),
                ),
                ids(&e.reserved),
            ]),
        ),
        Type::Counter(e) => case(13, b(e)),
        Type::Max(e) => case(14, b(e)),
        Type::Min(e) => case(15, b(e)),
        Type::Named(n, args) => case(16, st(vec![Value::Str(n.clone()), Value::List(args.iter().map(b).collect())])),
        Type::Param(p) => case(17, Value::Str(p.clone())),
    }
}

impl Schema {
    /// The schema's value (type `schema` of spec/data-model.md §10).
    pub fn to_value(&self) -> Value {
        let types = self
            .types
            .iter()
            .map(|(n, d)| {
                (Value::Str(n.clone()), st(vec![Value::List(d.params.iter().cloned().map(Value::Str).collect()), type_value(&d.body), doc(&d.doc)]))
            })
            .collect();
        let aspects = self
            .aspects
            .iter()
            .map(|(ak, a)| {
                let r = &a.retention;
                let retention = st(vec![Value::Enum(r.by as u64, None), bound(&r.at_least), bound(&r.at_most)]);
                let flags = Value::Set(a.flags.iter().map(|f| Value::Enum(*f as u64, None)).collect());
                let succ = Value::Set(a.succeeds.iter().cloned().map(Value::Str).collect());
                (Value::Str(ak.clone()), st(vec![type_value(&a.ty), retention, opt(a.expires.map(Value::uint)), flags, succ, doc(&a.doc)]))
            })
            .collect();
        st_fields(vec![(0, Value::bytes(&self.id.0)), (1, Value::uint(self.revision)), (2, Value::Map(types)), (3, Value::Map(aspects)), (5, doc(&self.doc))])
    }

    /// Canonical form: the canonical encoding of `to_value`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        osis_base::encode(&self.to_value())
    }

    /// Unkeyed BLAKE3 of the canonical form (lock files).
    pub fn hash(&self) -> [u8; 32] {
        osis_base::hash::hash(&self.canonical_bytes())
    }

    /// Reads a schema value: typed against the schema of schemas, then validated.
    pub fn from_value(v: &Value) -> Result<Schema, Error> {
        let v = typed_read(meta_schema(), v, &Type::named("schema")).map_err(|e| Error::Form(e.to_string()))?;
        let f = Fields::of(&v)?;
        let id: [u8; 16] = f.bytes(0)?.try_into().map_err(|_| Error::Form("schema ID must be 16 bytes".into()))?;
        let mut s = Schema::new(SchemaId(id), f.uint(1)?);
        for (n, d) in f.map(2)? {
            let d = Fields::of(d)?;
            let params = d.list(0)?.iter().map(as_str).collect::<Result<_, _>>()?;
            s.types.insert(as_str(n)?, TypeDef { params, body: read_type(d.get(1)?)?, doc: d.doc(2)? });
        }
        for (ak, a) in f.map(3)? {
            let a = Fields::of(a)?;
            let r = Fields::of(a.get(1)?)?;
            let by = PurgeBy::from_id(r.case(0)?).ok_or_else(|| Error::Form("purgeable-by case".into()))?;
            let retention = Retention { by, at_least: read_bound(r.get(1)?)?, at_most: read_bound(r.get(2)?)? };
            let flags = a
                .set(3)?
                .iter()
                .map(|f| match f {
                    Value::Enum(c, None) => Flag::from_id(*c).ok_or_else(|| Error::Form("flag case".into())),
                    _ => Err(Error::Form("flag".into())),
                })
                .collect::<Result<_, _>>()?;
            let succeeds = a.set(4)?.iter().map(as_str).collect::<Result<_, _>>()?;
            let expires = a.opt(2)?.map(as_uint).transpose()?;
            s.aspects.insert(as_str(ak)?, AspectDef { ty: read_type(a.get(0)?)?, retention, expires, flags, succeeds, doc: a.doc(5)? });
        }
        s.doc = f.doc(5)?;
        if let Some(inv) = s.validate().into_iter().next() {
            return Err(Error::Form(format!("{}: {}", inv.item, inv.msg)));
        }
        Ok(s)
    }
}

/// Struct fields of a typed-read (so complete) struct value.
struct Fields<'a>(&'a BTreeMap<Value, Value>);

fn form<T>(m: &str) -> Result<T, Error> {
    Err(Error::Form(m.into()))
}
fn as_str(v: &Value) -> Result<String, Error> {
    match v {
        Value::Str(s) => Ok(s.clone()),
        _ => form("expected string"),
    }
}
fn as_uint(v: &Value) -> Result<u64, Error> {
    v.as_uint().ok_or_else(|| Error::Form("expected a non-negative int".into()))
}

impl<'a> Fields<'a> {
    fn of(v: &'a Value) -> Result<Fields<'a>, Error> {
        match v {
            Value::Map(m) => Ok(Fields(m)),
            _ => form("expected struct"),
        }
    }
    fn get(&self, id: i64) -> Result<&'a Value, Error> {
        self.0.get(&Value::Int(id)).ok_or_else(|| Error::Form(format!("missing field {id}")))
    }
    fn uint(&self, id: i64) -> Result<u64, Error> {
        as_uint(self.get(id)?)
    }
    fn bytes(&self, id: i64) -> Result<Vec<u8>, Error> {
        self.get(id)?.as_bytes().map(<[u8]>::to_vec).ok_or_else(|| Error::Form("expected blob".into()))
    }
    fn map(&self, id: i64) -> Result<&'a BTreeMap<Value, Value>, Error> {
        match self.get(id)? {
            Value::Map(m) => Ok(m),
            _ => form("expected map"),
        }
    }
    fn list(&self, id: i64) -> Result<&'a Vec<Value>, Error> {
        match self.get(id)? {
            Value::List(l) => Ok(l),
            _ => form("expected list"),
        }
    }
    fn set(&self, id: i64) -> Result<&'a BTreeSet<Value>, Error> {
        match self.get(id)? {
            Value::Set(s) => Ok(s),
            _ => form("expected set"),
        }
    }
    fn case(&self, id: i64) -> Result<u64, Error> {
        match self.get(id)? {
            Value::Enum(c, _) => Ok(*c),
            _ => form("expected enum"),
        }
    }
    fn opt(&self, id: i64) -> Result<Option<&'a Value>, Error> {
        match self.get(id)? {
            Value::Enum(0, None) => Ok(None),
            Value::Enum(1, Some(v)) => Ok(Some(v)),
            _ => form("expected option"),
        }
    }
    fn doc(&self, id: i64) -> Result<Option<String>, Error> {
        self.opt(id)?.map(as_str).transpose()
    }
    fn ids(&self, id: i64) -> Result<BTreeSet<u64>, Error> {
        self.set(id)?.iter().map(as_uint).collect()
    }
}

fn read_bound(v: &Value) -> Result<Bound, Error> {
    let b = Fields::of(v)?;
    Ok(Bound { abs: b.opt(0)?.map(as_uint).transpose()?, rel: b.opt(1)?.map(as_uint).transpose()? })
}

/// A `type_expr` value (already typed by the schema of schemas).
pub fn read_type(v: &Value) -> Result<Type, Error> {
    let Value::Enum(c, p) = v else { return form("expected type_expr") };
    let p = p.as_deref();
    let inner = || match p {
        Some(x) => read_type(x).map(Box::new),
        None => form("type_expr payload"),
    };
    let fields = || match p {
        Some(x) => Fields::of(x),
        None => form("type_expr payload"),
    };
    Ok(match c {
        0 => Type::String,
        1 => Type::Blob,
        2 => Type::Bool,
        3 => Type::Int,
        4 => Type::Float,
        5 => Type::Tid,
        6 => Type::Any,
        7 => Type::Text,
        8 => Type::List(inner()?),
        9 => Type::Set(inner()?),
        10 => {
            let f = fields()?;
            Type::Map(Box::new(read_type(f.get(0)?)?), Box::new(read_type(f.get(1)?)?))
        }
        11 => {
            let f = fields()?;
            let mut s = StructType { fields: BTreeMap::new(), reserved: f.ids(1)? };
            for (id, fd) in f.map(0)? {
                let fd = Fields::of(fd)?;
                let field = Field {
                    name: as_str(fd.get(0)?)?,
                    ty: read_type(fd.get(1)?)?,
                    default: fd.opt(2)?.cloned(),
                    succeeds: fd.ids(3)?,
                    doc: fd.doc(4)?,
                };
                s.fields.insert(as_uint(id)?, field);
            }
            Type::Struct(s)
        }
        12 => {
            let f = fields()?;
            let mut e = EnumType { cases: BTreeMap::new(), reserved: f.ids(1)? };
            for (id, cd) in f.map(0)? {
                let cd = Fields::of(cd)?;
                let case = Case {
                    name: as_str(cd.get(0)?)?,
                    payload: cd.opt(1)?.map(read_type).transpose()?,
                    succeeds: cd.ids(2)?,
                    doc: cd.doc(3)?,
                };
                e.cases.insert(as_uint(id)?, case);
            }
            Type::Enum(e)
        }
        13 => Type::Counter(inner()?),
        14 => Type::Max(inner()?),
        15 => Type::Min(inner()?),
        16 => {
            let f = fields()?;
            Type::Named(as_str(f.get(0)?)?, f.list(1)?.iter().map(read_type).collect::<Result<_, _>>()?)
        }
        17 => match p {
            Some(x) => Type::Param(as_str(x)?),
            None => return form("type_expr payload"),
        },
        _ => return form("unknown type_expr case"),
    })
}
