//! The writer's view for the structural diff (spec/crdt.md §9), and the positions of a value
//! that must be chunked (spec/data-model.md §6).

use crate::path::{Path, Step};
use crate::schema::Schema;
use crate::typed::typed_read_at;
use crate::types::Type;
use osis_base::Value;
use osis_base::format::CHUNK_THRESHOLD;
use osis_crdt::{Encoding, View};
use std::borrow::Cow;

/// A position in the writer's schema: projects reads onto what the type can type (known fields,
/// reader defaults filled); a read the type cannot type is opaque (`project` is `None`).
#[derive(Clone, Debug)]
pub struct SchemaView<'s> {
    schema: &'s Schema,
    ty: Type,
    /// Inside a set element or map key: large values there are links.
    atomic: bool,
}

impl<'s> SchemaView<'s> {
    pub fn new(schema: &'s Schema, ty: Type) -> SchemaView<'s> {
        SchemaView { schema, ty, atomic: false }
    }
    pub fn ty(&self) -> &Type {
        &self.ty
    }
    fn child(&self, ty: Type, atomic: bool) -> SchemaView<'s> {
        SchemaView { schema: self.schema, ty, atomic: self.atomic || atomic }
    }
    fn expanded(&self) -> Option<Cow<'_, Type>> {
        self.schema.expand(&self.ty).ok()
    }
}

impl Schema {
    /// The view of an aspect this schema declares.
    pub fn view(&self, ak: &str) -> Option<SchemaView<'_>> {
        self.aspects.get(ak).map(|a| SchemaView::new(self, a.ty.clone()))
    }
}

impl View for SchemaView<'_> {
    fn encoding(&self) -> Option<Encoding> {
        self.schema.encoding(&self.ty)
    }
    fn project<'a>(&self, v: &'a Value) -> Option<Cow<'a, Value>> {
        let p = typed_read_at(self.schema, v, &self.ty, self.atomic).ok()?;
        Some(if p == *v { Cow::Borrowed(v) } else { Cow::Owned(p) })
    }
    fn field(&self, id: u64) -> Option<Self> {
        match self.expanded()?.as_ref() {
            Type::Struct(st) => st.fields.get(&id).map(|f| self.child(f.ty.clone(), false)),
            Type::Any => Some(self.child(Type::Any, false)),
            _ => None,
        }
    }
    fn field_default(&self, id: u64) -> Option<Value> {
        match self.expanded()?.as_ref() {
            Type::Struct(st) => st.fields.get(&id).and_then(|f| self.schema.default_of(f)),
            _ => None,
        }
    }
    fn case(&self, id: u64) -> Option<Self> {
        match self.expanded()?.as_ref() {
            Type::Enum(en) => en.cases.get(&id).and_then(|c| c.payload.clone()).map(|p| self.child(p, false)),
            Type::Any => Some(self.child(Type::Any, false)),
            _ => None,
        }
    }
    fn element(&self) -> Option<Self> {
        match self.expanded()?.as_ref() {
            Type::List(e) => Some(self.child((**e).clone(), false)),
            Type::Set(e) => Some(self.child((**e).clone(), true)),
            Type::Map(_, v) => Some(self.child((**v).clone(), false)),
            Type::Counter(i) | Type::Max(i) | Type::Min(i) => Some(self.child((**i).clone(), false)),
            Type::Any => Some(self.child(Type::Any, false)),
            _ => None,
        }
    }
    fn key(&self) -> Option<Self> {
        match self.expanded()?.as_ref() {
            Type::Map(k, _) => Some(self.child((**k).clone(), true)),
            Type::Any => Some(self.child(Type::Any, true)),
            _ => None,
        }
    }
}

/// A position that must be chunked. `map_key` tells a map key from the value at that key
/// (both have the path ending in `Step::Key`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Large {
    pub path: Path,
    pub map_key: bool,
}

/// Positions of `v` (written as `ty`) that MUST be chunked (spec/data-model.md §6): blobs,
/// register-encoded strings, set elements and map keys whose canonical encoding exceeds
/// `CHUNK_THRESHOLD`. Text-typed strings merge as sequences and never chunk. Positions the type
/// does not describe are classified by the value's kind (as `any`).
pub fn large_positions(schema: &Schema, v: &Value, ty: &Type) -> Vec<Large> {
    let mut out = Vec::new();
    let mut path = Vec::new();
    large(schema, v, Some(ty), &mut path, &mut out, false);
    out
}

/// The positions of a read value `v` of type `ty` that hold a link (a chunked large value),
/// typed like `large_positions`.
pub fn link_positions(schema: &Schema, v: &Value, ty: &Type) -> Vec<Large> {
    let mut out = Vec::new();
    let mut path = Vec::new();
    large(schema, v, Some(ty), &mut path, &mut out, true);
    out
}

fn too_big(v: &Value) -> bool {
    let quick = match v {
        Value::Str(s) => Some(s.len()),
        Value::Bytes(b) => Some(b.len()),
        _ => None,
    };
    match quick {
        Some(n) if n + 9 <= CHUNK_THRESHOLD => false,
        _ => osis_base::encode(v).len() > CHUNK_THRESHOLD,
    }
}

/// `links`: find positions holding a link instead of raw values above the threshold.
fn large(schema: &Schema, v: &Value, ty: Option<&Type>, path: &mut Vec<Step>, out: &mut Vec<Large>, links: bool) {
    let too_big = |v: &Value| if links { matches!(v, Value::Link(_)) } else { too_big(v) };
    let t = ty.and_then(|t| schema.expand(t).ok());
    let t = t.as_deref();
    let at = |s: Step, x: &Value, ty: Option<&Type>, path: &mut Vec<Step>, out: &mut Vec<Large>| {
        path.push(s);
        large(schema, x, ty, path, out, links);
        path.pop();
    };
    let field_ty = |id: i64| match t {
        Some(Type::Struct(st)) => u64::try_from(id).ok().and_then(|id| st.fields.get(&id)).map(|f| &f.ty),
        _ => None,
    };
    match v {
        Value::Str(_) if matches!(t, Some(Type::Text)) => {}
        Value::Str(_) | Value::Bytes(_) | Value::Link(_) => {
            if too_big(v) {
                out.push(Large { path: Path(path.clone()), map_key: false });
            }
        }
        Value::List(items) => {
            let e = match t {
                Some(Type::List(e)) => Some(&**e),
                _ => None,
            };
            for (i, x) in items.iter().enumerate() {
                at(Step::Index(i), x, e, path, out);
            }
        }
        Value::Set(items) => {
            for x in items {
                if too_big(x) {
                    path.push(Step::Elem(x.clone()));
                    out.push(Large { path: Path(path.clone()), map_key: false });
                    path.pop();
                }
            }
        }
        Value::Map(m) => {
            let struct_like = matches!(t, Some(Type::Struct(_)));
            let vt = match t {
                Some(Type::Map(_, v)) => Some(&**v),
                _ => None,
            };
            for (k, x) in m {
                match (struct_like, k) {
                    (true, Value::Int(id)) if *id >= 0 => at(Step::Field(id.unsigned_abs()), x, field_ty(*id), path, out),
                    _ => {
                        if too_big(k) {
                            path.push(Step::Key(k.clone()));
                            out.push(Large { path: Path(path.clone()), map_key: true });
                            path.pop();
                        }
                        at(Step::Key(k.clone()), x, vt, path, out);
                    }
                }
            }
        }
        Value::Enum(c, Some(p)) => {
            let pt = match t {
                Some(Type::Enum(en)) => en.cases.get(c).and_then(|c| c.payload.as_ref()),
                _ => None,
            };
            at(Step::Case(*c), p, pt, path, out);
        }
        _ => {}
    }
}
