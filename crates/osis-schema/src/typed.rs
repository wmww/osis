//! Typed reads and write validation (spec/versioning.md §5): a read projects a value onto a type
//! (known fields only, reader defaults filled), failing with the path on an unknown enum case, a
//! type mismatch or a missing field without default. A write must carry every declared field and
//! no undeclared one.

use crate::path::{Path, PathError, PathErrorKind as K, Step};
use crate::schema::Schema;
use crate::types::Type;
use osis_core::Value;
use osis_core::format::MAX_VALUE_DEPTH;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Read,
    Write,
}

/// Typed read of `v` as `ty`: the projection (unknown field IDs dropped, absent defaulted fields
/// filled). Large atomic values may be links (spec/data-model.md §6) and pass as they are.
pub fn typed_read(schema: &Schema, v: &Value, ty: &Type) -> Result<Value, PathError> {
    Walk { schema, mode: Mode::Read, path: Vec::new() }.walk(v, ty, false)
}

/// Validates a write of `v` as `ty` against the writer's schema.
pub fn validate_write(schema: &Schema, v: &Value, ty: &Type) -> Result<(), PathError> {
    if v.depth() > MAX_VALUE_DEPTH {
        return Err(PathError::new(Path::root(), K::TooDeep));
    }
    Walk { schema, mode: Mode::Write, path: Vec::new() }.walk(v, ty, false).map(|_| ())
}

/// The type at `path` under `ty`, with whether that position is atomic (inside a set element or
/// map key). Index and key steps need no value: they name the element type.
pub fn type_at(schema: &Schema, ty: &Type, path: &Path) -> Result<(Type, bool), PathError> {
    let mut cur = ty.clone();
    let mut atomic = false;
    for (i, s) in path.0.iter().enumerate() {
        let err = |k| PathError::new(Path(path.0.get(..=i).map(<[Step]>::to_vec).unwrap_or_default()), k);
        let t = schema.expand(&cur).map_err(|e| err(K::Schema(e)))?.into_owned();
        cur = match (s, t) {
            (Step::Field(id), Type::Struct(st)) => st.fields.get(id).map(|f| f.ty.clone()).ok_or_else(|| err(K::NotFound))?,
            (Step::Case(id), Type::Enum(en)) => {
                en.cases.get(id).and_then(|c| c.payload.clone()).ok_or_else(|| err(K::NotFound))?
            }
            (Step::Index(_), Type::List(e)) => *e,
            (Step::Elem(_), Type::Set(e)) => {
                atomic = true;
                *e
            }
            (Step::Key(_), Type::Map(_, v)) => *v,
            (_, Type::Any) => Type::Any,
            _ => return Err(err(K::NotFound)),
        };
    }
    Ok((cur, atomic))
}

/// The sub-value of `v` at `path` (untyped; always works on any data).
pub fn value_at<'a>(v: &'a Value, path: &Path) -> Option<&'a Value> {
    let mut cur = v;
    for s in &path.0 {
        cur = match (s, cur) {
            (Step::Field(id), Value::Map(m)) => m.get(&Value::Int(i64::try_from(*id).ok()?))?,
            (Step::Case(id), Value::Enum(c, Some(p))) if c == id => p,
            (Step::Key(k), Value::Map(m)) => m.get(k)?,
            (Step::Index(i), Value::List(l)) => l.get(*i)?,
            (Step::Elem(e), Value::Set(s)) => s.get(e)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Typed read of the part of `v` at `path` (lets an app skip one bad element).
pub fn read_path(schema: &Schema, v: &Value, ty: &Type, path: &Path) -> Result<Value, PathError> {
    let (t, atomic) = type_at(schema, ty, path)?;
    let sub = value_at(v, path).ok_or_else(|| PathError::new(path.clone(), K::NotFound))?;
    Walk { schema, mode: Mode::Read, path: path.0.clone() }.walk(sub, &t, atomic)
}

struct Walk<'s> {
    schema: &'s Schema,
    mode: Mode,
    path: Vec<Step>,
}

fn kind_name(t: &Type) -> &'static str {
    match t {
        Type::String | Type::Text => "string",
        Type::Blob => "blob",
        Type::Bool => "bool",
        Type::Int => "int",
        Type::Float => "float",
        Type::Tid => "tid",
        Type::List(_) => "list",
        Type::Set(_) => "set",
        Type::Map(..) => "map",
        Type::Struct(_) => "struct",
        Type::Enum(_) => "enum",
        _ => "value",
    }
}

impl Walk<'_> {
    fn err(&self, k: K) -> PathError {
        PathError::new(Path(self.path.clone()), k)
    }

    fn nested(&mut self, s: Step, v: &Value, ty: &Type, atomic: bool) -> Result<Value, PathError> {
        self.path.push(s);
        let r = self.walk(v, ty, atomic);
        self.path.pop();
        r
    }

    fn walk(&mut self, v: &Value, ty: &Type, atomic: bool) -> Result<Value, PathError> {
        let t = self.schema.expand(ty).map_err(|e| self.err(K::Schema(e)))?;
        let t = t.as_ref();
        match (t, v) {
            (Type::Any, _) => return Ok(v.clone()),
            (Type::Counter(i) | Type::Max(i) | Type::Min(i), _) => return self.walk(v, i, atomic),
            (_, Value::Unknown(u)) => return Err(self.err(K::UnknownTag(u.tag()))),
            (Type::String | Type::Blob, Value::Link(_)) => return Ok(v.clone()),
            (_, Value::Link(_)) if atomic => return Ok(v.clone()),
            _ => {}
        }
        match (t, v) {
            (Type::String | Type::Text, Value::Str(_))
            | (Type::Blob, Value::Bytes(_))
            | (Type::Bool, Value::Bool(_))
            | (Type::Int, Value::Int(_))
            | (Type::Float, Value::Float(_))
            | (Type::Tid, Value::Tid(_)) => Ok(v.clone()),
            (Type::List(e), Value::List(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, x) in items.iter().enumerate() {
                    out.push(self.nested(Step::Index(i), x, e, atomic)?);
                }
                Ok(Value::List(out))
            }
            (Type::Set(e), Value::Set(items)) => {
                let mut out = BTreeSet::new();
                for x in items {
                    out.insert(self.nested(Step::Elem(x.clone()), x, e, true)?);
                }
                Ok(Value::Set(out))
            }
            (Type::Map(kt, vt), Value::Map(m)) => {
                let mut out = BTreeMap::new();
                for (k, x) in m {
                    let k2 = self.nested(Step::Key(k.clone()), k, kt, true)?;
                    let x2 = self.nested(Step::Key(k.clone()), x, vt, atomic)?;
                    out.insert(k2, x2);
                }
                Ok(Value::Map(out))
            }
            (Type::Struct(st), Value::Map(m)) => {
                let mut out = BTreeMap::new();
                for k in m.keys() {
                    match k {
                        Value::Int(id) if *id >= 0 => {
                            if self.mode == Mode::Write && !st.fields.contains_key(&id.unsigned_abs()) {
                                return Err(self.err(K::UndeclaredField(id.unsigned_abs())));
                            }
                        }
                        _ => return Err(self.err(K::Mismatch { expected: "struct (int keys)" })),
                    }
                }
                for (id, f) in &st.fields {
                    let key = Value::Int(i64::try_from(*id).map_err(|_| self.err(K::Schema("field ID out of range".into())))?);
                    let x = match m.get(&key) {
                        Some(x) => self.nested(Step::Field(*id), x, &f.ty, atomic)?,
                        None if self.mode == Mode::Read => match self.schema.default_of(f) {
                            Some(d) => d,
                            None => return Err(self.err(K::MissingField(*id))),
                        },
                        None => return Err(self.err(K::MissingField(*id))),
                    };
                    out.insert(key, x);
                }
                Ok(Value::Map(out))
            }
            (Type::Enum(en), Value::Enum(c, p)) => {
                let case = en.cases.get(c).ok_or_else(|| self.err(K::UnknownCase(*c)))?;
                match (&case.payload, p) {
                    (None, None) => Ok(v.clone()),
                    (Some(pt), Some(x)) => Ok(Value::Enum(*c, Some(Box::new(self.nested(Step::Case(*c), x, pt, atomic)?)))),
                    (Some(_), None) => Err(self.err(K::MissingPayload(*c))),
                    (None, Some(_)) => Err(self.err(K::UnexpectedPayload(*c))),
                }
            }
            _ => Err(self.err(K::Mismatch { expected: kind_name(t) })),
        }
    }
}
