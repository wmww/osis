//! Recursive-descent parser for `*.osis` files (notes/data-model.md, Schema DSL). Two passes over
//! the tokens: the first collects every item, the second converts field defaults against the
//! now-known types. Errors carry file, line and column.
//!
//! ```text
//! file    := innerdoc* "revision" INT ";" item*
//! item    := doc* ( "type" IDENT ("<" IDENT,+ ">")? "=" type ";"
//!                 | mod* "ephemeral"? "admin"? ("aspect" | "signal") AK ":" type succeeds? ";" )
//! mod     := "synthetic" | "guaranteed"
//!          | "purgeable_by" "(" IDENT ("," IDENT)? ")" | "expires" "(" DUR ")"
//! type    := IDENT ("<" type,+ ">")? | "struct" "{" field,* "}" | "enum" "{" case,* "}"
//! field   := doc* (IDENT INT ":" type ("=" lit)? succeeds? | "reserved" ids)
//! case    := doc* (IDENT INT ("(" type ")")? succeeds? | "reserved" ids)
//! ids     := INT | "(" INT,+ ")"          succeeds := "succeeds" (ids | AK | "(" AK,+ ")")
//! lit     := "-"? INT | "-"? FLOAT | STR | HEX | "true" | "false" | IDENT ("(" lit ")")?
//!          | "[" lit,* "]" | "{" (lit ":" lit),* "}"
//! ```
//! Lists marked `,*`/`,+` allow a trailing comma. The keywords before `aspect`/`signal` agree
//! with the AK's markers; versions of one name ascend in file order.

use crate::error::ParseError;
use crate::lex::{Tok, Token, lex};
use crate::schema::{AspectDef, Flag, PurgeBy, Retention, Schema, TypeDef};
use crate::types::{Case, EnumType, Field, StructType, Type};
use osis_base::{Ak, Tid, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Deepest nesting of types and literals in a source file.
const MAX_NEST: usize = 64;

/// Parses and validates a schema source. `file` names it in errors.
pub fn parse(file: &str, src: &str) -> Result<Schema, ParseError> {
    let toks = lex(file, src)?;
    let valid = |(s, locs): (Schema, Locs)| match s.validate().into_iter().next() {
        None => Ok(s),
        Some(inv) => {
            let (line, col) = locs.get(&inv.item).copied().unwrap_or((1, 1));
            Err(ParseError { file: file.into(), line, col, msg: format!("{}: {}", inv.item, inv.msg) })
        }
    };
    // Types must be sound before pass 2 types defaults against them.
    let first = valid(Parser::new(file, &toks, None).file()?)?;
    valid(Parser::new(file, &toks, Some(&first)).file()?)
}

enum Lit {
    Int(i128),
    Float(f64),
    Str(String),
    Hex(Vec<u8>),
    Bool(bool),
    Ident(String, Option<Box<Lit>>),
    List(Vec<Lit>),
    Map(Vec<(Lit, Lit)>),
}

struct Parser<'a> {
    file: &'a str,
    toks: &'a [Token],
    pos: usize,
    /// Pass 2: the pass-1 schema, for typing defaults.
    known: Option<&'a Schema>,
    /// Parameters of the type definition being parsed.
    params: Vec<String>,
    depth: usize,
}

type Locs = BTreeMap<String, (u32, u32)>;

impl<'a> Parser<'a> {
    fn new(file: &'a str, toks: &'a [Token], known: Option<&'a Schema>) -> Parser<'a> {
        Parser { file, toks, pos: 0, known, params: Vec::new(), depth: 0 }
    }

    fn tok(&self) -> &Tok {
        self.toks.get(self.pos).map(|t| &t.tok).unwrap_or(&Tok::Eof)
    }
    fn here(&self) -> (u32, u32) {
        self.toks.get(self.pos).or(self.toks.last()).map(|t| (t.line, t.col)).unwrap_or((1, 1))
    }
    fn err_at<T>(&self, at: (u32, u32), msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError { file: self.file.into(), line: at.0, col: at.1, msg: msg.into() })
    }
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        self.err_at(self.here(), msg)
    }
    fn next(&mut self) -> Tok {
        let t = self.tok().clone();
        if self.pos < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn is(&self, c: char) -> bool {
        *self.tok() == Tok::Punct(c)
    }
    fn eat(&mut self, c: char) -> bool {
        let y = self.is(c);
        if y {
            self.pos += 1;
        }
        y
    }
    fn expect(&mut self, c: char) -> Result<(), ParseError> {
        if self.eat(c) { Ok(()) } else { self.err(format!("expected `{c}`")) }
    }
    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.tok(), Tok::Ident(s) if s == kw)
    }
    /// The current token as `f` reads it, consumed; else an error naming `what`, at it.
    fn want<T>(&mut self, what: &str, f: impl FnOnce(&Tok) -> Option<T>) -> Result<T, ParseError> {
        match f(self.tok()) {
            Some(x) => {
                self.pos += 1;
                Ok(x)
            }
            None => self.err(format!("expected {what}")),
        }
    }
    fn ident(&mut self, what: &str) -> Result<String, ParseError> {
        self.want(what, |t| if let Tok::Ident(s) = t { Some(s.clone()) } else { None })
    }
    fn int(&mut self, what: &str) -> Result<u64, ParseError> {
        self.want(what, |t| if let Tok::Int(n) = t { Some(*n) } else { None })
    }
    /// Items up to `close`, comma-separated, a trailing comma allowed.
    fn list<T>(&mut self, close: char, mut item: impl FnMut(&mut Self) -> Result<T, ParseError>) -> Result<Vec<T>, ParseError> {
        let mut out = Vec::new();
        while !self.eat(close) {
            out.push(item(self)?);
            if !self.eat(',') {
                self.expect(close)?;
                break;
            }
        }
        Ok(out)
    }
    fn docs(&mut self) -> Option<String> {
        let mut lines = Vec::new();
        while let Tok::Doc(d) = self.tok() {
            lines.push(d.clone());
            self.pos += 1;
        }
        if lines.is_empty() { None } else { Some(lines.join("\n")) }
    }
    fn nest(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_NEST { self.err("nested too deeply") } else { Ok(()) }
    }

    fn file(&mut self) -> Result<(Schema, Locs), ParseError> {
        let mut doc = Vec::new();
        while let Tok::InnerDoc(d) = self.tok() {
            doc.push(d.clone());
            self.pos += 1;
        }
        let mut s = Schema::new(0);
        let mut locs = Locs::new();
        let at = self.here();
        if !self.is_kw("revision") {
            return self.err("expected `revision <n>;` first");
        }
        self.pos += 1;
        s.revision = self.int("a revision number")?;
        self.expect(';')?;
        locs.insert("schema".into(), at);
        // the last version declared per name (the AK up to its markers)
        let mut versions: BTreeMap<String, (u64, String)> = BTreeMap::new();
        loop {
            let item_doc = self.docs();
            let at = self.here();
            match self.tok().clone() {
                Tok::Eof => break,
                Tok::Ident(k) if k == "type" => {
                    self.pos += 1;
                    let name = self.ident("a type name")?;
                    let params = if self.eat('<') { self.list('>', |p| p.ident("a type parameter"))? } else { Vec::new() };
                    self.expect('=')?;
                    self.params = params.clone();
                    let body = self.ty()?;
                    self.params.clear();
                    let key = format!("type {name}");
                    if s.types.insert(name, TypeDef { params, body, doc: item_doc }).is_some() {
                        return self.err_at(at, format!("duplicate {key}"));
                    }
                    locs.insert(key, at);
                }
                Tok::Ident(k) if k == "revision" => return self.err_at(at, "duplicate revision"),
                Tok::Ident(_) => {
                    let mut def = AspectDef { ty: Type::Any, retention: Retention::default(), expires: None, flags: BTreeSet::new(), succeeds: BTreeSet::new(), doc: item_doc };
                    self.modifiers(&mut def)?;
                    let (ephemeral, admin) = (self.eat_kw("ephemeral"), self.eat_kw("admin"));
                    let kat = self.here();
                    let signal = match self.next() {
                        Tok::Ident(k) if k == "aspect" => false,
                        Tok::Ident(k) if k == "signal" => true,
                        _ => return self.err_at(kat, "expected `aspect` or `signal` (after any modifiers, `ephemeral` and `admin`)"),
                    };
                    let kat = self.here();
                    let Tok::Ak(ak) = self.next() else { return self.err_at(kat, "expected an AK (a:b.0)") };
                    let (name, version) = match Ak::new(ak.as_str()) {
                        Ok(a) => (unmarked(&ak), a.version()),
                        Err(_) => return self.err_at(kat, format!("invalid AK {ak}")),
                    };
                    let want = respell(&name, ephemeral, admin, signal, version);
                    if want != ak {
                        let kws: Vec<&str> = [(ephemeral, "ephemeral"), (admin, "admin"), (true, if signal { "signal" } else { "aspect" })].into_iter().filter(|(y, _)| *y).map(|(_, k)| k).collect();
                        return self.err_at(kat, format!("`{}` needs `{want}`", kws.join(" ")));
                    }
                    if let Some((v, other)) = versions.get(&name)
                        && *v > version
                    {
                        return self.err_at(kat, format!("{ak} after {other}: versions of one name are declared in ascending order"));
                    }
                    versions.insert(name, (version, ak.clone()));
                    self.expect(':')?;
                    def.ty = self.ty()?;
                    if self.eat_kw("succeeds") {
                        def.succeeds = self.succeeds_aks()?;
                    }
                    let key = format!("aspect {ak}");
                    if s.aspects.insert(ak, def).is_some() {
                        return self.err_at(at, format!("duplicate {key}"));
                    }
                    locs.insert(key, at);
                }
                Tok::InnerDoc(_) => return self.err_at(at, "`//!` docs belong at the top of the file"),
                _ => return self.err_at(at, "expected an item (type, aspect, signal)"),
            }
            self.expect(';')?;
        }
        s.doc = if doc.is_empty() { None } else { Some(doc.join("\n")) };
        Ok((s, locs))
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        let y = self.is_kw(kw);
        if y {
            self.pos += 1;
        }
        y
    }

    /// The modifiers before an aspect's keywords, each at most once.
    fn modifiers(&mut self, def: &mut AspectDef) -> Result<(), ParseError> {
        let mut seen = BTreeSet::new();
        loop {
            let at = self.here();
            let Tok::Ident(name) = self.tok().clone() else { return Ok(()) };
            if !matches!(name.as_str(), "synthetic" | "guaranteed" | "purgeable_by" | "expires") {
                return Ok(());
            }
            self.pos += 1;
            if !seen.insert(name.clone()) {
                return self.err_at(at, format!("duplicate {name}"));
            }
            match name.as_str() {
                "synthetic" => {
                    def.flags.insert(Flag::Synthetic);
                }
                "guaranteed" => {
                    def.flags.insert(Flag::Guaranteed);
                }
                "purgeable_by" => {
                    self.expect('(')?;
                    let mut who = vec![self.ident("writer, or author, admin")?];
                    if self.eat(',') && !self.is(')') {
                        who.push(self.ident("admin or author")?);
                        self.eat(',');
                    }
                    self.expect(')')?;
                    let who: Vec<&str> = who.iter().map(String::as_str).collect();
                    def.retention.by = match who.as_slice() {
                        // the default is unnamed: admins alone
                        ["admin"] => return self.err_at(at, "admins alone may purge by default: leave purgeable_by out"),
                        ["writer"] => PurgeBy::Writer,
                        ["author", "admin"] | ["admin", "author"] => PurgeBy::AuthorOrAdmin,
                        _ => return self.err_at(at, "purgeable_by takes writer, or author, admin"),
                    };
                }
                _ => {
                    self.expect('(')?;
                    let kat = self.here();
                    match self.next() {
                        Tok::Dur(ms) => def.expires = Some(ms),
                        _ => return self.err_at(kat, "expected a duration (30d, 12h, 5m, 10s, 250ms)"),
                    }
                    self.expect(')')?;
                }
            }
        }
    }

    /// At `reserved` IDs, not a field named `reserved` (`reserved 3: int`). No case is named
    /// `reserved`.
    fn reserved_ids(&self, field: bool) -> bool {
        let after = |i: usize| self.toks.get(self.pos + i).map(|t| &t.tok);
        self.is_kw("reserved") && !(field && matches!(after(1), Some(Tok::Int(_))) && after(2) == Some(&Tok::Punct(':')))
    }

    fn ids(&mut self) -> Result<BTreeSet<u64>, ParseError> {
        Ok(if self.eat('(') { self.list(')', |p| p.int("an ID"))?.into_iter().collect() } else { BTreeSet::from([self.int("an ID")?]) })
    }

    fn succeeds_aks(&mut self) -> Result<BTreeSet<String>, ParseError> {
        let ak = |p: &mut Self| p.want("an AK", |t| if let Tok::Ak(a) = t { Some(a.clone()) } else { None });
        // One AK, or a parenthesized list of at least one (an empty one fails at its `)`).
        if !self.eat('(') || self.is(')') {
            return Ok(BTreeSet::from([ak(self)?]));
        }
        Ok(self.list(')', ak)?.into_iter().collect())
    }

    fn ty(&mut self) -> Result<Type, ParseError> {
        self.nest()?;
        let at = self.here();
        let name = self.ident("a type")?;
        let t = match name.as_str() {
            "struct" => Type::Struct(self.struct_body()?),
            "enum" => Type::Enum(self.enum_body()?),
            _ => {
                let args = if self.eat('<') { self.list('>', Self::ty)? } else { Vec::new() };
                let one = |p: &Self, args: Vec<Type>| -> Result<Box<Type>, ParseError> {
                    let mut it = args.into_iter();
                    match (it.next(), it.next()) {
                        (Some(t), None) => Ok(Box::new(t)),
                        _ => p.err_at(at, format!("{name} takes one type argument")),
                    }
                };
                let none = |p: &Self, args: &[Type], t: Type| {
                    if args.is_empty() { Ok(t) } else { p.err_at(at, format!("{name} takes no type arguments")) }
                };
                match name.as_str() {
                    "string" => none(self, &args, Type::String)?,
                    "blob" => none(self, &args, Type::Blob)?,
                    "bool" => none(self, &args, Type::Bool)?,
                    "int" => none(self, &args, Type::Int)?,
                    "float" => none(self, &args, Type::Float)?,
                    "tid" => none(self, &args, Type::Tid)?,
                    "any" => none(self, &args, Type::Any)?,
                    "text" => none(self, &args, Type::Text)?,
                    "list" => Type::List(one(self, args)?),
                    "set" => Type::Set(one(self, args)?),
                    "counter" => Type::Counter(one(self, args)?),
                    "max" => Type::Max(one(self, args)?),
                    "min" => Type::Min(one(self, args)?),
                    "map" => {
                        let mut it = args.into_iter();
                        match (it.next(), it.next(), it.next()) {
                            (Some(k), Some(v), None) => Type::Map(Box::new(k), Box::new(v)),
                            _ => return self.err_at(at, "map takes two type arguments"),
                        }
                    }
                    _ if self.params.contains(&name) => none(self, &args, Type::Param(name.clone()))?,
                    _ => Type::Named(name, args),
                }
            }
        };
        self.depth -= 1;
        Ok(t)
    }

    /// A struct or enum body: members by ID (`what`: `field` or `case`) and reserved IDs.
    fn body<T>(
        &mut self,
        what: &str,
        mut member: impl FnMut(&mut Self, Option<String>) -> Result<(u64, T), ParseError>,
    ) -> Result<(BTreeMap<u64, T>, BTreeSet<u64>), ParseError> {
        self.expect('{')?;
        let (mut items, mut reserved) = (BTreeMap::new(), BTreeSet::new());
        self.list('}', |p| {
            let doc = p.docs();
            let at = p.here();
            if p.is('}') {
                // docs before the closing brace
            } else if p.reserved_ids(what == "field") {
                p.pos += 1;
                reserved.extend(p.ids()?);
            } else {
                let (id, m) = member(p, doc)?;
                if items.insert(id, m).is_some() {
                    return p.err_at(at, format!("duplicate {what} ID {id}"));
                }
            }
            Ok(())
        })?;
        Ok((items, reserved))
    }

    fn succeeds_ids(&mut self) -> Result<BTreeSet<u64>, ParseError> {
        if self.eat_kw("succeeds") { self.ids() } else { Ok(BTreeSet::new()) }
    }

    fn struct_body(&mut self) -> Result<StructType, ParseError> {
        let (fields, reserved) = self.body("field", |p, doc| {
            let name = p.ident("a field name or `reserved`")?;
            let id = p.int("the field's number")?;
            p.expect(':')?;
            let ty = p.ty()?;
            let mut default = None;
            if p.eat('=') {
                let lat = p.here();
                let lit = p.lit()?;
                if let Some(known) = p.known {
                    match lit_value(known, &lit, &ty) {
                        Ok(v) => default = Some(v),
                        Err(m) => return p.err_at(lat, format!("default of {name}: {m}")),
                    }
                }
            }
            Ok((id, Field { name, ty, default, succeeds: p.succeeds_ids()?, doc }))
        })?;
        Ok(StructType { fields, reserved })
    }

    fn enum_body(&mut self) -> Result<EnumType, ParseError> {
        let (cases, reserved) = self.body("case", |p, doc| {
            let name = p.ident("a case name or `reserved`")?;
            let id = p.int("the case's number")?;
            let payload = if p.eat('(') {
                let t = p.ty()?;
                p.expect(')')?;
                Some(t)
            } else {
                None
            };
            Ok((id, Case { name, payload, succeeds: p.succeeds_ids()?, doc }))
        })?;
        Ok(EnumType { cases, reserved })
    }

    fn lit(&mut self) -> Result<Lit, ParseError> {
        self.nest()?;
        let neg = self.eat('-');
        let l = match self.next() {
            Tok::Int(n) => Lit::Int(if neg { -i128::from(n) } else { i128::from(n) }),
            Tok::Float(f) => Lit::Float(if neg { -f } else { f }),
            _ if neg => {
                self.pos = self.pos.saturating_sub(1);
                return self.err("expected a number after `-`");
            }
            Tok::Str(s) => Lit::Str(s),
            Tok::Hex(b) => Lit::Hex(b),
            Tok::Ident(s) if s == "true" => Lit::Bool(true),
            Tok::Ident(s) if s == "false" => Lit::Bool(false),
            Tok::Ident(s) => {
                let payload = if self.eat('(') {
                    let p = self.lit()?;
                    self.expect(')')?;
                    Some(Box::new(p))
                } else {
                    None
                };
                Lit::Ident(s, payload)
            }
            Tok::Punct('[') => Lit::List(self.list(']', Self::lit)?),
            Tok::Punct('{') => Lit::Map(self.list('}', |p| {
                let k = p.lit()?;
                p.expect(':')?;
                Ok((k, p.lit()?))
            })?),
            _ => {
                self.pos = self.pos.saturating_sub(1);
                return self.err("expected a literal");
            }
        };
        self.depth -= 1;
        Ok(l)
    }
}

/// A default literal as a value of `ty`.
fn lit_value(s: &Schema, lit: &Lit, ty: &Type) -> Result<Value, String> {
    let t = s.expand(ty).map_err(|e| format!("cannot type a default here ({e})"))?;
    let int = |n: &i128| i64::try_from(*n).map_err(|_| "integer out of range".to_string());
    Ok(match (t.as_ref(), lit) {
        (Type::Param(p), _) => return Err(format!("cannot type a default of parameter type {p}")),
        // Only int or float inside (never re-enter: `type a = counter<a>` must not loop).
        (Type::Counter(i) | Type::Max(i) | Type::Min(i), _) => match s.expand(i).as_deref() {
            Ok(n @ (Type::Int | Type::Float)) => return lit_value(s, lit, n),
            _ => return Err("counter, max and min take int or float".into()),
        },
        (Type::Any, _) => any_value(lit)?,
        (Type::Int, Lit::Int(n)) => Value::Int(int(n)?),
        (Type::Float, Lit::Float(f)) => Value::float(*f),
        #[allow(clippy::cast_precision_loss)]
        (Type::Float, Lit::Int(n)) => Value::float(int(n)? as f64),
        (Type::String | Type::Text, Lit::Str(x)) => Value::Str(x.clone()),
        (Type::Blob, Lit::Hex(b)) => Value::Bytes(b.clone()),
        (Type::Bool, Lit::Bool(b)) => Value::Bool(*b),
        (Type::Tid, Lit::Str(x)) => Value::Tid(Tid::parse(x).map_err(|_| "bad tid".to_string())?),
        (Type::List(e), Lit::List(items)) => Value::List(items.iter().map(|l| lit_value(s, l, e)).collect::<Result<_, _>>()?),
        (Type::Set(e), Lit::List(items)) => Value::Set(items.iter().map(|l| lit_value(s, l, e)).collect::<Result<_, _>>()?),
        (Type::Map(k, v), Lit::Map(items)) => {
            Value::Map(items.iter().map(|(a, b)| Ok((lit_value(s, a, k)?, lit_value(s, b, v)?))).collect::<Result<_, String>>()?)
        }
        (Type::Struct(st), Lit::Map(items)) => {
            let mut m = BTreeMap::new();
            for (k, v) in items {
                let (id, f) = match k {
                    Lit::Ident(n, None) => st.fields.iter().find(|(_, f)| &f.name == n),
                    Lit::Int(n) => u64::try_from(*n).ok().and_then(|id| st.fields.get_key_value(&id)),
                    _ => None,
                }
                .ok_or("unknown field in struct literal")?;
                m.insert(Value::Int(i64::try_from(*id).map_err(|_| "field ID out of range")?), lit_value(s, v, &f.ty)?);
            }
            for (id, f) in &st.fields {
                let key = Value::Int(i64::try_from(*id).map_err(|_| "field ID out of range")?);
                if let std::collections::btree_map::Entry::Vacant(e) = m.entry(key) {
                    e.insert(s.default_of(f).ok_or_else(|| format!("struct literal lacks field {}", f.name))?);
                }
            }
            Value::Map(m.into_iter().collect())
        }
        (Type::Enum(en), Lit::Ident(n, p)) => {
            let (id, c) = en.cases.iter().find(|(_, c)| &c.name == n).ok_or_else(|| format!("unknown case {n}"))?;
            match (&c.payload, p) {
                (None, None) => Value::Enum(*id, None),
                (Some(pt), Some(pl)) => Value::Enum(*id, Some(Box::new(lit_value(s, pl, pt)?))),
                _ => return Err(format!("case {n} payload does not match")),
            }
        }
        _ => return Err("literal does not fit the type".into()),
    })
}

/// A literal in an `any` position: kinds as written; struct literals are int-keyed maps.
fn any_value(lit: &Lit) -> Result<Value, String> {
    Ok(match lit {
        Lit::Int(n) => Value::Int(i64::try_from(*n).map_err(|_| "integer out of range")?),
        Lit::Float(f) => Value::float(*f),
        Lit::Str(x) => Value::Str(x.clone()),
        Lit::Hex(b) => Value::Bytes(b.clone()),
        Lit::Bool(b) => Value::Bool(*b),
        Lit::List(items) => Value::List(items.iter().map(any_value).collect::<Result<_, _>>()?),
        Lit::Map(items) => Value::Map(items.iter().map(|(a, b)| Ok((any_value(a)?, any_value(b)?))).collect::<Result<_, String>>()?),
        Lit::Ident(..) => return Err("case names need an enum type".into()),
    })
}

/// An AK up to its markers: its tid and name segments (`a:b+^.1` → `a:b`).
pub(crate) fn unmarked(ak: &str) -> String {
    let body = ak.trim_end_matches(|c: char| c.is_ascii_digit());
    let body = body.strip_suffix(['.', '~']).unwrap_or(body);
    let body = body.strip_suffix('^').unwrap_or(body);
    body.strip_suffix('+').unwrap_or(body).to_string()
}

/// The AK of `name` and `version` with the markers the keywords give.
fn respell(name: &str, ephemeral: bool, admin: bool, signal: bool, version: u64) -> String {
    format!("{name}{}{}{}{version}", if ephemeral { "+" } else { "" }, if admin { "^" } else { "" }, if signal { '~' } else { '.' })
}
