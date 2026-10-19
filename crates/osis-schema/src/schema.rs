//! A parsed schema (spec/data-model.md §2, §10): types, aspects with retention, expiry and flags,
//! signal kinds; expansion of named types; validation.

use crate::types::{Case, EnumType, Field, StructType, Type, is_reserved_name};
use osis_core::format::CORE_SCHEMA_ID;
use osis_core::{Ak, SchemaId, Value};
use osis_crdt::Encoding;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

/// Most named-type expansions before a type must reach a structure (catches `type a = a;`).
const MAX_EXPAND: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub id: SchemaId,
    pub revision: u64,
    pub types: BTreeMap<String, TypeDef>,
    /// By AK.
    pub aspects: BTreeMap<String, AspectDef>,
    /// By signal kind.
    pub signals: BTreeMap<String, SignalDef>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeDef {
    pub params: Vec<String>,
    pub body: Type,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AspectDef {
    pub ty: Type,
    pub retention: Retention,
    /// Default expiry, ms after the write (spec/commits.md §6).
    pub expires: Option<u64>,
    pub flags: BTreeSet<Flag>,
    pub succeeds: BTreeSet<String>,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalDef {
    pub ty: Type,
    pub doc: Option<String>,
}

/// Local aspect flags (spec/data-model.md §2); nothing on the wire enforces them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Ro = 0,
    Synthetic = 1,
    Guaranteed = 2,
    Indexed = 3,
}

impl Flag {
    pub const ALL: [Flag; 4] = [Flag::Ro, Flag::Synthetic, Flag::Guaranteed, Flag::Indexed];
    pub fn name(self) -> &'static str {
        match self {
            Flag::Ro => "ro",
            Flag::Synthetic => "synthetic",
            Flag::Guaranteed => "guaranteed",
            Flag::Indexed => "indexed",
        }
    }
    pub fn from_id(id: u64) -> Option<Flag> {
        Flag::ALL.into_iter().find(|f| *f as u64 == id)
    }
}

/// Purgeable-by class (spec/commits.md §5; wire uint per spec/wire.md §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PurgeBy {
    Nobody = 0,
    Admin = 1,
    #[default]
    Author = 2,
    Writer = 3,
}

impl PurgeBy {
    pub const ALL: [PurgeBy; 4] = [PurgeBy::Nobody, PurgeBy::Admin, PurgeBy::Author, PurgeBy::Writer];
    pub fn name(self) -> &'static str {
        match self {
            PurgeBy::Nobody => "nobody",
            PurgeBy::Admin => "admin",
            PurgeBy::Author => "author",
            PurgeBy::Writer => "writer",
        }
    }
    pub fn from_id(id: u64) -> Option<PurgeBy> {
        PurgeBy::ALL.into_iter().find(|p| *p as u64 == id)
    }
}

/// A keep bound: absolute wall ms, a duration after the body is replaced, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Bound {
    pub abs: Option<u64>,
    pub rel: Option<u64>,
}

impl Bound {
    pub fn is_none(&self) -> bool {
        self.abs.is_none() && self.rel.is_none()
    }
}

/// Retention a writer puts into every delta (spec/commits.md §5). `Default` is the untyped
/// default: `author`, no keep bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct Retention {
    pub by: PurgeBy,
    pub at_least: Bound,
    pub at_most: Bound,
}

/// Per-AK write defaults (notes/api.md Keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct AspectDefaults {
    pub retention: Retention,
    pub expires: Option<u64>,
}

/// A validation failure: the item (`type NAME`, `aspect AK`, `signal KIND`, `schema`) and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid {
    pub item: String,
    pub msg: String,
}

impl Schema {
    pub fn new(id: SchemaId, revision: u64) -> Schema {
        Schema { id, revision, types: BTreeMap::new(), aspects: BTreeMap::new(), signals: BTreeMap::new(), doc: None }
    }

    pub fn is_core(&self) -> bool {
        self.id == CORE_SCHEMA_ID
    }

    /// Write defaults for an AK this schema declares.
    pub fn defaults(&self, ak: &str) -> Option<AspectDefaults> {
        self.aspects.get(ak).map(|a| AspectDefaults { retention: a.retention, expires: a.expires })
    }

    /// One expansion step of a named type; `Ok(None)` for a structure.
    fn instantiate(&self, n: &str, args: &[Type]) -> Result<Type, String> {
        let arity = |k: usize| if args.len() == k { Ok(()) } else { Err(format!("{n} takes {k} type argument(s)")) };
        match n {
            "option" => {
                arity(1)?;
                Ok(Type::option_body(args.first().cloned().unwrap_or(Type::Any)))
            }
            "markdown" => arity(0).map(|_| Type::Text),
            "timestamp" | "duration" => arity(0).map(|_| Type::Int),
            _ => {
                let def = self.types.get(n).ok_or_else(|| format!("unknown type {n}"))?;
                arity(def.params.len())?;
                Ok(def.body.subst(&def.params, args))
            }
        }
    }

    /// Expands named types at the head until a structure. Fails on an unknown name, a wrong
    /// argument count, an unbound parameter or non-productive recursion.
    pub fn expand<'a>(&self, ty: &'a Type) -> Result<Cow<'a, Type>, String> {
        let mut cur = Cow::Borrowed(ty);
        for _ in 0..MAX_EXPAND {
            let next = match cur.as_ref() {
                Type::Named(n, args) => self.instantiate(n, args)?,
                Type::Param(p) => return Err(format!("unbound type parameter {p}")),
                _ => return Ok(cur),
            };
            cur = Cow::Owned(next);
        }
        Err("type never expands to a structure".into())
    }

    /// Whether the type is `option<T>` (possibly through aliases).
    pub fn is_option(&self, ty: &Type) -> bool {
        let mut cur = Cow::Borrowed(ty);
        for _ in 0..MAX_EXPAND {
            let Type::Named(n, args) = cur.as_ref() else { return false };
            if n == "option" {
                return true;
            }
            match self.instantiate(n, args) {
                Ok(t) => cur = Cow::Owned(t),
                Err(_) => return false,
            }
        }
        false
    }

    /// Reader default of a field: the declared constant, else `none` for an `option` field.
    pub fn default_of(&self, f: &Field) -> Option<Value> {
        match &f.default {
            Some(d) => Some(d.clone()),
            None if self.is_option(&f.ty) => Some(Value::Enum(0, None)),
            None => None,
        }
    }

    /// Merge encoding writes at this type use (spec/crdt.md §3.1); `None` for `any`.
    pub fn encoding(&self, ty: &Type) -> Option<Encoding> {
        Some(match self.expand(ty).ok()?.as_ref() {
            Type::String | Type::Blob | Type::Bool | Type::Int | Type::Float | Type::Tid => Encoding::Register,
            Type::Any => return None,
            Type::Text => Encoding::Text,
            Type::List(_) => Encoding::List,
            Type::Set(_) => Encoding::Set,
            Type::Map(..) => Encoding::Map,
            Type::Struct(_) => Encoding::Struct,
            Type::Enum(_) => Encoding::Enum,
            Type::Counter(_) => Encoding::Counter,
            Type::Max(_) => Encoding::Max,
            Type::Min(_) => Encoding::Min,
            Type::Named(..) | Type::Param(_) => Encoding::Register,
        })
    }

    /// Every validation rule; empty when valid.
    pub fn validate(&self) -> Vec<Invalid> {
        let mut out = Vec::new();
        let mut bad = |item: &str, msg: String| out.push(Invalid { item: item.to_string(), msg });
        for (name, def) in &self.types {
            let item = format!("type {name}");
            if is_reserved_name(name) || !is_ident(name) {
                bad(&item, format!("invalid type name {name}"));
            }
            let mut seen = BTreeSet::new();
            for p in &def.params {
                if !seen.insert(p) || is_reserved_name(p) || self.types.contains_key(p) || !is_ident(p) {
                    bad(&item, format!("invalid or duplicate parameter {p}"));
                }
            }
            self.check_syntax(&def.body, &def.params, &mut |m| bad(&item, m));
            if def.params.is_empty() {
                self.check_semantics(&def.body, false, &mut BTreeSet::new(), &mut |m| bad(&item, m));
            }
        }
        for (ak, def) in &self.aspects {
            let item = format!("aspect {ak}");
            match Ak::new(ak.as_str()) {
                Ok(a) if a.is_core() != self.is_core() => {
                    bad(&item, "core AKs have one segment and belong to the core schema; app AKs have two or more".into())
                }
                Ok(_) => {}
                Err(_) => bad(&item, "invalid AK".into()),
            }
            self.check_syntax(&def.ty, &[], &mut |m| bad(&item, m));
            self.check_semantics(&def.ty, false, &mut BTreeSet::new(), &mut |m| bad(&item, m));
            if def.retention.at_most.rel.is_some() && def.retention.by != PurgeBy::Writer {
                bad(&item, "a relative keep_at_most needs by: writer (spec/commits.md §5)".into());
            }
            if def.expires == Some(0) {
                bad(&item, "expires must be positive".into());
            }
            for s in &def.succeeds {
                if s == ak || Ak::new(s.as_str()).is_err() {
                    bad(&item, format!("invalid succeeds {s}"));
                }
            }
        }
        for (kind, def) in &self.signals {
            let item = format!("signal {kind}");
            if Ak::new(kind.as_str()).is_err() {
                bad(&item, "invalid signal kind".into());
            }
            self.check_syntax(&def.ty, &[], &mut |m| bad(&item, m));
            self.check_semantics(&def.ty, false, &mut BTreeSet::new(), &mut |m| bad(&item, m));
        }
        out
    }

    /// Names resolve, argument counts match, parameters are in scope, IDs are consistent.
    fn check_syntax(&self, ty: &Type, params: &[String], bad: &mut dyn FnMut(String)) {
        match ty {
            Type::Named(n, args) => {
                let want = crate::types::STANDARD
                    .iter()
                    .find(|(s, _)| s == n)
                    .map(|(_, k)| *k)
                    .or_else(|| self.types.get(n).map(|d| d.params.len()));
                match want {
                    None => bad(format!("unknown type {n}")),
                    Some(k) if k != args.len() => bad(format!("{n} takes {k} type argument(s), got {}", args.len())),
                    Some(_) => {}
                }
                for a in args {
                    self.check_syntax(a, params, bad);
                }
            }
            Type::Param(p) => {
                if !params.contains(p) {
                    bad(format!("unbound type parameter {p}"));
                }
            }
            Type::List(t) | Type::Set(t) | Type::Counter(t) | Type::Max(t) | Type::Min(t) => self.check_syntax(t, params, bad),
            Type::Map(k, v) => {
                self.check_syntax(k, params, bad);
                self.check_syntax(v, params, bad);
            }
            Type::Struct(StructType { fields, reserved }) => {
                check_ids("field", fields.keys().copied(), reserved, fields.values().map(|f| (&f.name, &f.succeeds)), bad);
                for f in fields.values() {
                    self.check_syntax(&f.ty, params, bad);
                }
            }
            Type::Enum(EnumType { cases, reserved }) => {
                check_ids("case", cases.keys().copied(), reserved, cases.values().map(|c| (&c.name, &c.succeeds)), bad);
                for c in cases.values() {
                    if let Some(p) = &c.payload {
                        self.check_syntax(p, params, bad);
                    }
                }
            }
            Type::String | Type::Blob | Type::Bool | Type::Int | Type::Float | Type::Tid | Type::Any | Type::Text => {}
        }
    }

    /// Wrapper rules and termination, walking named types once per (instance, atomic context).
    fn check_semantics(&self, ty: &Type, atomic: bool, seen: &mut BTreeSet<(String, bool)>, bad: &mut dyn FnMut(String)) {
        let ty = match ty {
            Type::Named(..) => {
                if !seen.insert((format!("{ty:?}"), atomic)) {
                    return;
                }
                match self.expand(ty) {
                    Ok(t) => t,
                    Err(e) => return bad(e),
                }
            }
            _ => Cow::Borrowed(ty),
        };
        match ty.as_ref() {
            Type::Counter(t) | Type::Max(t) | Type::Min(t) => {
                if atomic {
                    bad("encoding wrappers are not allowed in set elements or map keys".into());
                }
                match self.expand(t).as_deref() {
                    Ok(Type::Int | Type::Float) => {}
                    Ok(_) => bad("counter, max and min take int or float".into()),
                    Err(e) => bad(e.clone()),
                }
            }
            Type::Text if atomic => bad("text is not allowed in set elements or map keys".into()),
            Type::List(t) => self.check_semantics(t, atomic, seen, bad),
            Type::Set(t) => self.check_semantics(t, true, seen, bad),
            Type::Map(k, v) => {
                self.check_semantics(k, true, seen, bad);
                self.check_semantics(v, atomic, seen, bad);
            }
            Type::Struct(st) => {
                for f in st.fields.values() {
                    self.check_semantics(&f.ty, atomic, seen, bad);
                    if let Some(Err(e)) = f.default.as_ref().map(|d| crate::typed::typed_read(self, d, &f.ty)) {
                        bad(format!("default of field {} does not fit its type: {e}", f.name));
                    }
                }
            }
            Type::Enum(en) => {
                for c in en.cases.values() {
                    if let Some(p) = &c.payload {
                        self.check_semantics(p, atomic, seen, bad);
                    }
                }
            }
            Type::Param(p) => bad(format!("unbound type parameter {p}")),
            _ => {}
        }
    }
}

fn check_ids<'a>(
    what: &str,
    ids: impl Iterator<Item = u64>,
    reserved: &BTreeSet<u64>,
    items: impl Iterator<Item = (&'a String, &'a BTreeSet<u64>)>,
    bad: &mut dyn FnMut(String),
) {
    let ids: BTreeSet<u64> = ids.collect();
    for id in &ids {
        if reserved.contains(id) {
            bad(format!("{what} ID {id} is both declared and reserved"));
        }
        if i64::try_from(*id).is_err() {
            bad(format!("{what} ID {id} out of range"));
        }
    }
    let mut names = BTreeSet::new();
    for ((name, succeeds), id) in items.zip(ids.iter()) {
        if !names.insert(name) || !is_ident(name) {
            bad(format!("invalid or duplicate {what} name {name}"));
        }
        for s in succeeds {
            if s == id || !(ids.contains(s) || reserved.contains(s)) {
                bad(format!("{what} {name} succeeds unknown {what} {s}"));
            }
        }
    }
}

pub(crate) fn is_ident(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_') && c.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// Keeps `Case` and `Field` constructors short in parser and value form.
impl Field {
    pub fn new(name: &str, ty: Type) -> Field {
        Field { name: name.into(), ty, default: None, succeeds: BTreeSet::new(), doc: None }
    }
}

impl Case {
    pub fn new(name: &str, payload: Option<Type>) -> Case {
        Case { name: name.into(), payload, succeeds: BTreeSet::new(), doc: None }
    }
}
