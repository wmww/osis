//! The additive checker (spec/versioning.md §4): a new revision against the last published one.
//! Types are compared structurally after expanding named types, so renaming a type or a field
//! is free; recursive types are compared coinductively.

use crate::schema::Schema;
use crate::types::{EnumType, StructType, Type};
use std::collections::BTreeSet;
use std::fmt;

/// One rule of spec/versioning.md §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// A field or case ID the old revision reserved is declared again.
    IdReused,
    /// A field was removed without reserving its ID.
    RemovedNotReserved,
    /// A reserved ID is no longer reserved.
    ReservedDropped,
    /// An enum case was removed (cases are never removed, reserved or not).
    CaseRemoved,
    /// An existing ID (or aspect, or signal kind) changed type, other than along a register
    /// embedding edge (`T` to `counter<T>`/`max<T>`/`min<T>`, `string` to `text`).
    TypeChanged,
    /// A field without default was added to an existing struct.
    FieldWithoutDefault,
    /// A default was changed or removed.
    DefaultChanged,
    /// A default was added to a formerly required field (allowed only when explicitly marked).
    DefaultAdded,
    /// The schema ID changed.
    SchemaIdChanged,
    /// The schema changed without a greater revision.
    RevisionNotBumped,
    /// An aspect was removed (its wire type never changes; a different type is a new AK).
    AspectRemoved,
    /// A signal kind was removed.
    SignalRemoved,
    /// The comparison exceeded its depth or size bound (not provably additive).
    TooLarge,
    /// A revision does not validate (`Schema::validate`), so it is not compared.
    Invalid,
}

/// Deepest comparison path (two validated schemas stay well within it).
const MAX_CHECK_DEPTH: usize = 2 * crate::schema::MAX_TYPE_DEPTH;
/// Most type-pair comparisons per check.
const MAX_CHECK_WORK: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub rule: Rule,
    /// Where: `type task.7`, `aspect /note/tasks[].3`, `schema`.
    pub at: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} at {}", self.rule, self.at)
    }
}

/// Every violation of `new` against the last published `old`; empty when additive.
pub fn check(old: &Schema, new: &Schema) -> Vec<Violation> {
    // Only validated schemas are walked: regular recursion keeps the instances finite.
    let invalid: Vec<Violation> = [("old", old), ("new", new)]
        .into_iter()
        .filter(|(_, s)| !s.validate().is_empty())
        .map(|(w, _)| Violation { rule: Rule::Invalid, at: format!("{w} schema") })
        .collect();
    if !invalid.is_empty() {
        return invalid;
    }
    let mut c = Checker { old, new, out: Vec::new(), seen: BTreeSet::new(), depth: 0, work: 0, stopped: false };
    if old.id != new.id {
        c.v(Rule::SchemaIdChanged, "schema".into());
    }
    let changed = {
        let mut o = old.clone();
        o.revision = new.revision;
        o != *new
    };
    if new.revision < old.revision || (changed && new.revision == old.revision) {
        c.v(Rule::RevisionNotBumped, "schema".into());
    }
    for (name, od) in &old.types {
        if let Some(nd) = new.types.get(name) {
            let at = format!("type {name}");
            if od.params.len() != nd.params.len() {
                c.v(Rule::TypeChanged, at);
            } else {
                // As named instances with positional parameters, so aspects reaching them skip them.
                let args: Vec<Type> = (0..od.params.len()).map(|i| Type::Param(format!("${i}"))).collect();
                let t = Type::Named(name.clone(), args);
                c.ty(&t, &t, &at);
            }
        }
    }
    for (ak, oa) in &old.aspects {
        match new.aspects.get(ak) {
            Some(na) => c.ty(&oa.ty, &na.ty, &format!("aspect {ak}")),
            None => c.v(Rule::AspectRemoved, format!("aspect {ak}")),
        }
    }
    for (k, os) in &old.signals {
        match new.signals.get(k) {
            Some(ns) => c.ty(&os.ty, &ns.ty, &format!("signal {k}")),
            None => c.v(Rule::SignalRemoved, format!("signal {k}")),
        }
    }
    c.out
}

struct Checker<'a> {
    old: &'a Schema,
    new: &'a Schema,
    out: Vec<Violation>,
    /// Named-type pairs already compared (coinduction for recursive types).
    seen: BTreeSet<(String, String)>,
    depth: usize,
    work: usize,
    stopped: bool,
}

impl Checker<'_> {
    fn v(&mut self, rule: Rule, at: String) {
        self.out.push(Violation { rule, at });
    }

    fn ty(&mut self, o: &Type, n: &Type, at: &str) {
        if self.stopped {
            return;
        }
        if self.depth >= MAX_CHECK_DEPTH || self.work >= MAX_CHECK_WORK {
            self.stopped = true;
            return self.v(Rule::TooLarge, at.into());
        }
        self.depth += 1;
        self.work += 1;
        self.ty_inner(o, n, at);
        self.depth -= 1;
    }

    fn ty_inner(&mut self, o: &Type, n: &Type, at: &str) {
        let named = matches!(o, Type::Named(..)) || matches!(n, Type::Named(..));
        if named && !self.seen.insert((format!("{o:?}"), format!("{n:?}"))) {
            return;
        }
        let (Ok(o), Ok(n)) = (self.old.expand(o), self.new.expand(n)) else {
            return self.v(Rule::TypeChanged, at.into());
        };
        match (o.as_ref(), n.as_ref()) {
            (Type::String, Type::String | Type::Text)
            | (Type::Blob, Type::Blob)
            | (Type::Bool, Type::Bool)
            | (Type::Int, Type::Int)
            | (Type::Float, Type::Float)
            | (Type::Tid, Type::Tid)
            | (Type::Any, Type::Any)
            | (Type::Text, Type::Text) => {}
            (Type::Param(a), Type::Param(b)) if a == b => {}
            (Type::Int | Type::Float, Type::Counter(i) | Type::Max(i) | Type::Min(i)) => self.ty(&o, i, at),
            (Type::Counter(a), Type::Counter(b)) | (Type::Max(a), Type::Max(b)) | (Type::Min(a), Type::Min(b)) => {
                self.ty(a, b, at)
            }
            (Type::List(a), Type::List(b)) => self.ty(a, b, &format!("{at}[]")),
            (Type::Set(a), Type::Set(b)) => self.ty(a, b, &format!("{at}{{}}")),
            (Type::Map(ka, va), Type::Map(kb, vb)) => {
                self.ty(ka, kb, &format!("{at}[key]"));
                self.ty(va, vb, &format!("{at}[]"));
            }
            (Type::Struct(a), Type::Struct(b)) => self.structs(a, b, at),
            (Type::Enum(a), Type::Enum(b)) => self.enums(a, b, at),
            _ => self.v(Rule::TypeChanged, at.into()),
        }
    }

    fn structs(&mut self, o: &StructType, n: &StructType, at: &str) {
        for (id, of) in &o.fields {
            let fat = format!("{at}.{id}");
            match n.fields.get(id) {
                Some(nf) => {
                    self.ty(&of.ty, &nf.ty, &fat);
                    match (self.old.default_of(of), self.new.default_of(nf)) {
                        (Some(a), Some(b)) if a != b => self.v(Rule::DefaultChanged, fat),
                        (Some(_), None) => self.v(Rule::DefaultChanged, fat),
                        (None, Some(_)) => self.v(Rule::DefaultAdded, fat),
                        _ => {}
                    }
                }
                None if n.reserved.contains(id) => {}
                None => self.v(Rule::RemovedNotReserved, fat),
            }
        }
        for (id, nf) in &n.fields {
            if o.fields.contains_key(id) {
                continue;
            }
            if o.reserved.contains(id) {
                self.v(Rule::IdReused, format!("{at}.{id}"));
            } else if self.new.default_of(nf).is_none() {
                self.v(Rule::FieldWithoutDefault, format!("{at}.{id}"));
            }
        }
        self.reserved(&o.reserved, &n.reserved, |id| n.fields.contains_key(&id), at);
    }

    fn enums(&mut self, o: &EnumType, n: &EnumType, at: &str) {
        for (id, oc) in &o.cases {
            let cat = format!("{at}#{id}");
            match (n.cases.get(id), &oc.payload) {
                (None, _) => self.v(Rule::CaseRemoved, cat),
                (Some(nc), Some(op)) => match &nc.payload {
                    Some(np) => self.ty(op, np, &cat),
                    None => self.v(Rule::TypeChanged, cat),
                },
                (Some(nc), None) => {
                    if nc.payload.is_some() {
                        self.v(Rule::TypeChanged, cat);
                    }
                }
            }
        }
        for id in n.cases.keys() {
            if !o.cases.contains_key(id) && o.reserved.contains(id) {
                self.v(Rule::IdReused, format!("{at}#{id}"));
            }
        }
        self.reserved(&o.reserved, &n.reserved, |id| n.cases.contains_key(&id), at);
    }

    /// Reserved IDs stay reserved (one declared again is `IdReused`, reported by the caller).
    fn reserved(&mut self, o: &BTreeSet<u64>, n: &BTreeSet<u64>, declared: impl Fn(u64) -> bool, at: &str) {
        for id in o {
            if !n.contains(id) && !declared(*id) {
                self.v(Rule::ReservedDropped, format!("{at}.{id}"));
            }
        }
    }
}
