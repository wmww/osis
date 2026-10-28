//! `--json` output (notes/cli.md, JSON mapping): a small JSON tree and writer, and the value
//! mapping (named with a schema, else ids).

use crate::text::{Kind, Ty, float_text, kind_of, quote};
use osis::{Tid, Value};
use osis_schema::osis_base::base64url;

#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    /// A number already in JSON form.
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn obj<const N: usize>(fields: [(&str, J); N]) -> J {
        J::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }
    pub fn tid(t: Tid) -> J {
        J::Str(t.to_uri())
    }
    pub fn int(i: impl Into<i128>) -> J {
        J::Num(i.into().to_string())
    }
    pub fn opt(o: Option<J>) -> J {
        o.unwrap_or(J::Null)
    }

    pub fn write(&self, o: &mut String) {
        match self {
            J::Null => o.push_str("null"),
            J::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
            J::Num(n) => o.push_str(n),
            J::Str(s) => quote(o, s),
            J::Arr(a) => {
                o.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    x.write(o);
                }
                o.push(']');
            }
            J::Obj(m) => {
                o.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        o.push(',');
                    }
                    quote(o, k);
                    o.push(':');
                    v.write(o);
                }
                o.push('}');
            }
        }
    }

    pub fn text(&self) -> String {
        let mut o = String::new();
        self.write(&mut o);
        o
    }
}

/// Keys of the marker objects (`{"$set": …}`).
pub const MARKERS: [&str; 7] = ["$blob", "$set", "$case", "$payload", "$map", "$tag", "$bytes"];

fn b64(b: &[u8]) -> J {
    J::Str(base64url::encode(b))
}

/// The JSON form of a value. Timestamps and durations stay ms ints.
pub fn value(v: &Value, ty: Ty<'_>) -> J {
    let s = ty.map(|(s, _)| s);
    let kind = kind_of(ty);
    let elem = match &kind {
        Kind::List(e) | Kind::Set(e) => Some(e),
        _ => None,
    };
    match v {
        Value::Int(i) => J::int(*i),
        Value::Float(f) => {
            let f = f.get();
            if f.is_finite() { J::Num(float_text(f)) } else { J::Str(float_text(f)) }
        }
        Value::Bool(b) => J::Bool(*b),
        Value::Str(x) => J::str(x.clone()),
        Value::Bytes(b) => J::obj([("$blob", b64(b))]),
        Value::Tid(t) => J::tid(*t),
        Value::Enum(c, p) => {
            let case = match &kind {
                Kind::Enum(e) => e.cases.get(c),
                _ => None,
            };
            let mut f = vec![("$case".to_string(), case.map_or_else(|| J::int(*c), |c| J::str(c.name.clone())))];
            if let Some(p) = p {
                f.push(("$payload".into(), value(p, s.zip(case.and_then(|c| c.payload.as_ref())))));
            }
            J::Obj(f)
        }
        Value::List(l) => J::Arr(l.iter().map(|x| value(x, s.zip(elem))).collect()),
        Value::Set(x) => J::obj([("$set", J::Arr(x.iter().map(|x| value(x, s.zip(elem))).collect()))]),
        Value::Map(m) => {
            let (st, kt, vt) = match &kind {
                Kind::Struct(st) => (Some(st), None, None),
                Kind::Map(k, v) => (None, Some(k), Some(v)),
                _ => (None, None, None),
            };
            let field = |k: &Value| match (st, k) {
                (Some(st), Value::Int(i)) => u64::try_from(*i).ok().and_then(|id| st.fields.get(&id)),
                _ => None,
            };
            let vty = |k: &Value| s.zip(if st.is_some() { field(k).map(|f| &f.ty) } else { vt });
            // A typed struct is an object by field name; a map is an object only when every key
            // is a string and none is a marker, so an object never reads as a marker form.
            let is_struct = st.is_some() && m.keys().all(|k| matches!(k, Value::Int(i) if *i >= 0));
            let strs = m.keys().all(|k| matches!(k, Value::Str(x) if !MARKERS.contains(&x.as_str())));
            if is_struct || strs {
                J::Obj(
                    m.iter()
                        .map(|(k, v)| {
                            let name = match k {
                                Value::Str(x) => x.clone(),
                                Value::Int(i) if st.is_some() => field(k).map_or_else(|| i.to_string(), |f| f.name.clone()),
                                k => crate::text::print(k, None),
                            };
                            (name, value(v, vty(k)))
                        })
                        .collect(),
                )
            } else {
                J::obj([("$map", J::Arr(m.iter().map(|(k, v)| J::Arr(vec![value(k, s.zip(kt)), value(v, vty(k))])).collect()))])
            }
        }
        Value::Link(_) => J::Null,
        Value::Unknown(u) => J::obj([("$tag", J::int(u.tag())), ("$bytes", b64(u.content().as_bytes()))]),
    }
}
