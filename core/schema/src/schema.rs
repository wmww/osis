//! A parsed schema (spec/data-model.md §2, §10): types, aspects with retention, expiry and flags;
//! expansion of named types; validation.

use crate::types::{Case, EnumType, Field, StructType, Type, is_reserved_name};
use osis_base::format::CORE_SCHEMA_ID;
use osis_base::{Ak, SchemaId, Value};
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

impl AspectDef {
    /// The lifetime its flags declare (validation allows at most one lifetime flag).
    pub fn lifetime(&self) -> Lifetime {
        if self.flags.contains(&Flag::Signal) {
            Lifetime::Signal
        } else if self.flags.contains(&Flag::Presence) {
            Lifetime::Presence
        } else if self.flags.contains(&Flag::Ephemeral) {
            Lifetime::Ephemeral
        } else {
            Lifetime::Durable
        }
    }
}


/// Aspect flags (spec/data-model.md §2). `ephemeral`, `presence` and `signal` decide where a
/// write goes (its lifetime); nothing on the wire enforces the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    Ro = 0,
    Synthetic = 1,
    Guaranteed = 2,
    Indexed = 3,
    Ephemeral = 4,
    Presence = 5,
    Signal = 6,
}

impl Flag {
    pub const ALL: [Flag; 7] = [Flag::Ro, Flag::Synthetic, Flag::Guaranteed, Flag::Indexed, Flag::Ephemeral, Flag::Presence, Flag::Signal];
    pub fn name(self) -> &'static str {
        match self {
            Flag::Ro => "ro",
            Flag::Synthetic => "synthetic",
            Flag::Guaranteed => "guaranteed",
            Flag::Indexed => "indexed",
            Flag::Ephemeral => "ephemeral",
            Flag::Presence => "presence",
            Flag::Signal => "signal",
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
    /// Before this bound a body leaves only by purge request, never by compaction. Who wrote a
    /// change and when is reported only while its signed original is held (notes/api.md
    /// Attribution): `abs` forever keeps every change's authorship provable.
    pub at_least: Bound,
    pub at_most: Bound,
}

/// Where an aspect's writes live (notes/ephemeral.md Model): durable commits, or in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Lifetime {
    #[default]
    Durable,
    /// A value held in memory.
    Ephemeral,
    /// An ephemeral value tied to its author's presence (acts as `Ephemeral` for now).
    Presence,
    /// A write with no lasting value: delivered to callbacks, never in state.
    Signal,
}

impl Lifetime {
    pub fn is_durable(self) -> bool {
        self == Lifetime::Durable
    }
}

/// Per-AK write defaults (notes/api.md Keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Hash)]
pub struct AspectDefaults {
    pub retention: Retention,
    pub expires: Option<u64>,
    pub lifetime: Lifetime,
}

/// A validation failure: the item (`type NAME`, `aspect AK`, `schema`) and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid {
    pub item: String,
    pub msg: String,
}

impl Schema {
    pub fn new(id: SchemaId, revision: u64) -> Schema {
        Schema { id, revision, types: BTreeMap::new(), aspects: BTreeMap::new(), doc: None }
    }

    pub fn is_core(&self) -> bool {
        self.id == CORE_SCHEMA_ID
    }

    /// Write defaults for an AK this schema declares.
    pub fn defaults(&self, ak: &str) -> Option<AspectDefaults> {
        self.aspects.get(ak).map(|a| AspectDefaults { retention: a.retention, expires: a.expires, lifetime: a.lifetime() })
    }

    /// One expansion step of a named type (standard or declared).
    fn instantiate(&self, n: &str, args: &[Type]) -> Result<Type, String> {
        let arity = |k: usize| if args.len() == k { Ok(()) } else { Err(format!("{n} takes {k} type argument(s)")) };
        match n {
            "option" => {
                arity(1)?;
                Ok(Type::option_body(args.first().cloned().unwrap_or(Type::Any)))
            }
            "markdown" => arity(0).map(|_| Type::Text),
            "timestamp" | "duration" | "date" | "localtime" => arity(0).map(|_| Type::Int),
            _ => {
                let def = self.types.get(n).ok_or_else(|| format!("unknown type {n}"))?;
                arity(def.params.len())?;
                Ok(def.body.subst(&def.params, args))
            }
        }
    }

    /// Expands named types at the head until a structure (or a parameter of an enclosing
    /// definition). Fails on an unknown name, a wrong argument count or non-productive recursion.
    pub fn expand<'a>(&self, ty: &'a Type) -> Result<Cow<'a, Type>, String> {
        let mut cur = Cow::Borrowed(ty);
        for _ in 0..MAX_EXPAND {
            let next = match cur.as_ref() {
                Type::Named(n, args) => self.instantiate(n, args)?,
                _ => return Ok(cur),
            };
            cur = Cow::Owned(next);
        }
        Err(format!("named type does not reach a structure within {MAX_EXPAND} expansions (alias chain too long, or recursion through aliases only)"))
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
        let big = |n: Option<u64>| n.is_some_and(|n| i64::try_from(n).is_err());
        if big(Some(self.revision)) {
            bad("schema", "revision out of range".into());
        }
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
        }
        for (name, msg) in self.irregular_recursion() {
            bad(&format!("type {name}"), msg);
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
            if def.retention.at_most.rel.is_some() && def.retention.by != PurgeBy::Writer {
                bad(&item, "a relative keep_at_most needs by: writer (spec/commits.md §5)".into());
            }
            let r = &def.retention;
            if [def.expires, r.at_least.abs, r.at_least.rel, r.at_most.abs, r.at_most.rel].into_iter().any(big) {
                bad(&item, "time out of range".into());
            }
            if def.expires == Some(0) {
                bad(&item, "expires must be positive".into());
            }
            let lifetimes = def.flags.iter().filter(|f| matches!(f, Flag::Ephemeral | Flag::Presence | Flag::Signal)).count();
            if lifetimes > 1 {
                bad(&item, "at most one of ephemeral, presence, signal".into());
            }
            // `/placed`, the ephemeral placements (spec/data-model.md §8), is the one core aspect
            // that is not durable
            if self.is_core() && (def.lifetime() != Lifetime::Durable) != (ak.as_str() == "/placed") {
                bad(&item, "core aspects are durable, /placed ephemeral".into());
            }
            if lifetimes > 0 && def.retention != Retention::default() {
                bad(&item, "retention applies to durable aspects only".into());
            }
            if def.lifetime() == Lifetime::Signal && def.expires.is_some() {
                bad(&item, "a signal has no value to expire".into());
            }
            if def.lifetime() == Lifetime::Presence && def.expires.is_some() {
                bad(&item, "a presence value lives while its author is connected: no expiry".into());
            }
            for s in &def.succeeds {
                if s == ak || Ak::new(s.as_str()).is_err() {
                    bad(&item, format!("invalid succeeds {s}"));
                }
            }
        }
        // Semantic rules only on a syntactically sound schema with regular recursion (so the set
        // of named instances is finite); one walk shared by every root, memoized per instance.
        if !out.is_empty() {
            return out;
        }
        let mut sem = Sem { schema: self, heights: BTreeMap::new(), active: BTreeSet::new(), work: 0, stopped: false };
        let roots = self
            .types
            .iter()
            .filter(|(_, d)| d.params.is_empty())
            .map(|(n, _)| (format!("type {n}"), Type::named(n)))
            .chain(self.aspects.iter().map(|(ak, d)| (format!("aspect {ak}"), d.ty.clone())));
        for (item, ty) in roots {
            let mut msgs = Vec::new();
            sem.walk(&ty, false, 0, &mut |m| msgs.push(m));
            out.extend(msgs.into_iter().map(|msg| Invalid { item: item.clone(), msg }));
            if sem.stopped {
                break;
            }
        }
        out
    }

    /// A reference to a type of its own recursive group must pass the referencing definition's
    /// parameters unchanged (regular recursion); otherwise expansion never repeats an instance.
    fn irregular_recursion(&self) -> Vec<(String, String)> {
        let edges: BTreeMap<&str, Vec<&str>> = self
            .types
            .iter()
            .map(|(n, d)| {
                let mut refs = Vec::new();
                named_refs(&d.body, &mut |r, _| {
                    if self.types.contains_key(r) {
                        refs.push(r.to_string());
                    }
                });
                (n.as_str(), refs.into_iter().filter_map(|r| self.types.get_key_value(&r).map(|(k, _)| k.as_str())).collect())
            })
            .collect();
        let comp = sccs(&edges);
        let mut out = Vec::new();
        for (n, d) in &self.types {
            let own: Vec<Type> = d.params.iter().cloned().map(Type::Param).collect();
            named_refs(&d.body, &mut |r, args| {
                if comp.get(r).is_some_and(|c| Some(c) == comp.get(n.as_str())) && args != own.as_slice() {
                    out.push((n.clone(), format!("recursive reference {r}<..> must pass the parameters of {n} unchanged")));
                }
            });
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
}

/// Deepest nesting of a type, counted in structures (beyond it no value fits the depth limit).
pub(crate) const MAX_TYPE_DEPTH: usize = 256;
/// Most named-type instances a validation expands (parametric types can multiply).
const MAX_INSTANCES: usize = 10_000;

/// Wrapper rules, termination and nesting depth; named instances walked once per atomic context.
struct Sem<'s> {
    schema: &'s Schema,
    /// Height (structure levels below) per walked (instance, atomic).
    heights: BTreeMap<(String, bool), usize>,
    /// Instances on the current path: a repeat is a recursive reference (height 0 there).
    active: BTreeSet<(String, bool)>,
    work: usize,
    /// Too deep or too large: reported once, the walk stops.
    stopped: bool,
}

impl Sem<'_> {
    fn stop(&mut self, msg: &str, bad: &mut dyn FnMut(String)) -> usize {
        if !self.stopped {
            self.stopped = true;
            bad(msg.into());
        }
        0
    }

    /// Returns the type's height.
    fn walk(&mut self, ty: &Type, atomic: bool, depth: usize, bad: &mut dyn FnMut(String)) -> usize {
        if self.stopped {
            return 0;
        }
        if depth > MAX_TYPE_DEPTH {
            return self.stop("type nests too deeply", bad);
        }
        if let Type::Named(..) = ty {
            let key = (format!("{ty:?}"), atomic);
            if let Some(h) = self.heights.get(&key) {
                let h = *h;
                if depth + h > MAX_TYPE_DEPTH {
                    return self.stop("type nests too deeply", bad);
                }
                return h;
            }
            if self.active.contains(&key) {
                return 0;
            }
            self.work += 1;
            if self.work > MAX_INSTANCES {
                return self.stop("schema expands too many type instances", bad);
            }
            let t = match self.schema.expand(ty) {
                Ok(t) => t.into_owned(),
                Err(e) => {
                    bad(e);
                    return 0;
                }
            };
            self.active.insert(key.clone());
            let h = self.walk(&t, atomic, depth, bad);
            self.active.remove(&key);
            self.heights.insert(key, h);
            return h;
        }
        let d = depth + 1;
        let schema = self.schema;
        1 + match ty {
            Type::Counter(t) | Type::Max(t) | Type::Min(t) => {
                if atomic {
                    bad("encoding wrappers are not allowed in set elements or map keys".into());
                }
                match schema.expand(t).as_deref() {
                    Ok(Type::Int | Type::Float) => {}
                    Ok(_) => bad("counter, max and min take int or float".into()),
                    Err(e) => bad(e.clone()),
                }
                0
            }
            Type::Text if atomic => {
                bad("text is not allowed in set elements or map keys".into());
                0
            }
            Type::List(t) => self.walk(t, atomic, d, bad),
            Type::Set(t) => self.walk(t, true, d, bad),
            Type::Map(k, v) => self.walk(k, true, d, bad).max(self.walk(v, atomic, d, bad)),
            Type::Struct(st) => {
                let mut h = 0;
                for f in st.fields.values() {
                    h = h.max(self.walk(&f.ty, atomic, d, bad));
                    if self.stopped {
                        return 0;
                    }
                    if let Some(Err(e)) = f.default.as_ref().map(|v| crate::typed::typed_read(schema, v, &f.ty)) {
                        bad(format!("default of field {} does not fit its type: {e}", f.name));
                    }
                }
                h
            }
            Type::Enum(en) => {
                let mut h = 0;
                for p in en.cases.values().filter_map(|c| c.payload.as_ref()) {
                    h = h.max(self.walk(p, atomic, d, bad));
                }
                h
            }
            Type::Param(p) => {
                bad(format!("unbound type parameter {p}"));
                0
            }
            _ => 0,
        }
    }
}

/// Every `Named(name, args)` inside a type (arguments included).
fn named_refs(t: &Type, f: &mut dyn FnMut(&str, &[Type])) {
    if let Type::Named(n, a) = t {
        f(n, a);
    }
    t.children().into_iter().for_each(|c| named_refs(c, f));
}

/// Strongly connected components (iterative Tarjan): component number per node. A node alone
/// without a self-edge gets its own component like any other; callers compare components.
fn sccs<'a>(edges: &BTreeMap<&'a str, Vec<&'a str>>) -> BTreeMap<&'a str, usize> {
    let (mut index, mut low, mut comp) = (BTreeMap::new(), BTreeMap::<&str, usize>::new(), BTreeMap::new());
    let (mut stack, mut on) = (Vec::new(), BTreeSet::new());
    let (mut counter, mut ncomp) = (0usize, 0usize);
    let none: Vec<&str> = Vec::new();
    for &s in edges.keys() {
        if index.contains_key(s) {
            continue;
        }
        index.insert(s, counter);
        low.insert(s, counter);
        counter += 1;
        stack.push(s);
        on.insert(s);
        let mut call: Vec<(&str, usize)> = vec![(s, 0)];
        while let Some((v, i)) = call.last().copied() {
            if let Some(&w) = edges.get(v).unwrap_or(&none).get(i) {
                if let Some(top) = call.last_mut() {
                    top.1 += 1;
                }
                if !index.contains_key(w) {
                    index.insert(w, counter);
                    low.insert(w, counter);
                    counter += 1;
                    stack.push(w);
                    on.insert(w);
                    call.push((w, 0));
                } else if on.contains(w) {
                    let iw = index.get(w).copied().unwrap_or(0);
                    low.entry(v).and_modify(|l| *l = (*l).min(iw));
                }
            } else {
                call.pop();
                let lv = low.get(v).copied().unwrap_or(0);
                if let Some(&(u, _)) = call.last() {
                    low.entry(u).and_modify(|l| *l = (*l).min(lv));
                }
                if Some(&lv) == index.get(v) {
                    while let Some(w) = stack.pop() {
                        on.remove(w);
                        comp.insert(w, ncomp);
                        if w == v {
                            break;
                        }
                    }
                    ncomp += 1;
                }
            }
        }
    }
    comp
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
