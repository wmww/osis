//! The text forms (notes/cli.md, Value syntax): values, paths, durations, timestamps. One
//! printed form per value; the parser reads back everything the printer writes, numbered or
//! named (a schema type guides both).

use osis::{Schema, Step, Tid, Value};
use osis_schema::osis_core::{CanonicalBytes, Unknown, base64url, hex};
use osis_schema::{EnumType, StructType, Type};
use std::collections::{BTreeMap, BTreeSet};

/// A type in a schema, or nothing (numbered forms).
pub type Ty<'a> = Option<(&'a Schema, &'a Type)>;

/// What a type means for the text form.
enum Kind {
    Timestamp,
    Duration,
    Struct(StructType),
    Enum(EnumType),
    List(Type),
    Set(Type),
    Map(Type, Type),
    /// Scalars, text, `any`: printed and read as untyped values.
    Plain,
}

/// Expands named types one step at a time so `timestamp` and `duration` stay visible.
fn kind(s: &Schema, t: &Type) -> Kind {
    let mut cur = t.clone();
    for _ in 0..64 {
        cur = match cur {
            Type::Named(n, _) if n == "timestamp" => return Kind::Timestamp,
            Type::Named(n, _) if n == "duration" => return Kind::Duration,
            Type::Named(n, args) => match n.as_str() {
                "option" => Type::option_body(args.first().cloned().unwrap_or(Type::Any)),
                "markdown" => Type::Text,
                _ => match s.types.get(&n) {
                    Some(d) => d.body.subst(&d.params, &args),
                    None => return Kind::Plain,
                },
            },
            Type::Counter(t) | Type::Max(t) | Type::Min(t) => *t,
            Type::Struct(st) => return Kind::Struct(st),
            Type::Enum(e) => return Kind::Enum(e),
            Type::List(t) => return Kind::List(*t),
            Type::Set(t) => return Kind::Set(*t),
            Type::Map(k, v) => return Kind::Map(*k, *v),
            _ => return Kind::Plain,
        };
    }
    Kind::Plain
}

fn kind_of(ty: Ty<'_>) -> Kind {
    match ty {
        Some((s, t)) => kind(s, t),
        None => Kind::Plain,
    }
}

// ---- printing

/// The text form of `v`, named where `ty` covers it.
pub fn print(v: &Value, ty: Ty<'_>) -> String {
    let mut o = String::new();
    pv(&mut o, v, ty);
    o
}

fn pv(o: &mut String, v: &Value, ty: Ty<'_>) {
    let s = ty.map(|(s, _)| s);
    match (kind_of(ty), v, s) {
        (Kind::Timestamp, Value::Int(i), _) => match rfc3339(*i) {
            Some(t) => o.push_str(&t),
            None => o.push_str(&i.to_string()),
        },
        (Kind::Duration, Value::Int(i), _) => o.push_str(&duration_text(*i)),
        (Kind::Struct(st), Value::Map(m), Some(s)) if m.keys().all(|k| matches!(k, Value::Int(i) if *i >= 0)) => {
            seq(o, "{", "}", m.iter(), |o, (k, v)| {
                let f = match k {
                    Value::Int(i) => u64::try_from(*i).ok().and_then(|id| st.fields.get(&id)),
                    _ => None,
                };
                match f {
                    Some(f) => {
                        o.push_str(&f.name);
                        o.push_str(": ");
                        pv(o, v, Some((s, &f.ty)));
                    }
                    None => {
                        pv(o, k, None);
                        o.push_str(": ");
                        pv(o, v, None);
                    }
                }
            })
        }
        (Kind::Enum(e), Value::Enum(c, p), Some(s)) if e.cases.contains_key(c) => {
            let case = e.cases.get(c);
            o.push('#');
            o.push_str(case.map(|c| c.name.as_str()).unwrap_or(""));
            if let Some(p) = p {
                o.push('(');
                pv(o, p, case.and_then(|c| c.payload.as_ref()).map(|t| (s, t)));
                o.push(')');
            }
        }
        (Kind::List(t), Value::List(l), Some(s)) => seq(o, "[", "]", l.iter(), |o, x| pv(o, x, Some((s, &t)))),
        (Kind::Set(t), Value::Set(l), Some(s)) => seq(o, "#{", "}", l.iter(), |o, x| pv(o, x, Some((s, &t)))),
        (Kind::Map(kt, vt), Value::Map(m), Some(s)) => seq(o, "{", "}", m.iter(), |o, (k, v)| {
            pv(o, k, Some((s, &kt)));
            o.push_str(": ");
            pv(o, v, Some((s, &vt)));
        }),
        _ => plain(o, v),
    }
}

fn seq<I: Iterator>(o: &mut String, open: &str, close: &str, it: I, mut f: impl FnMut(&mut String, I::Item)) {
    o.push_str(open);
    for (i, x) in it.enumerate() {
        if i > 0 {
            o.push_str(", ");
        }
        f(o, x);
    }
    o.push_str(close);
}

fn plain(o: &mut String, v: &Value) {
    match v {
        Value::Int(i) => o.push_str(&i.to_string()),
        Value::Float(f) => o.push_str(&float_text(f.get())),
        Value::Bool(b) => o.push_str(if *b { "true" } else { "false" }),
        Value::Str(s) => quote(o, s),
        Value::Bytes(b) => {
            o.push_str("h'");
            o.push_str(&hex::encode(b));
            o.push('\'');
        }
        Value::Tid(t) => o.push_str(&t.to_uri()),
        Value::Enum(c, p) => {
            o.push('#');
            o.push_str(&c.to_string());
            if let Some(p) = p {
                o.push('(');
                plain(o, p);
                o.push(')');
            }
        }
        Value::Map(m) => seq(o, "{", "}", m.iter(), |o, (k, v)| {
            plain(o, k);
            o.push_str(": ");
            plain(o, v);
        }),
        Value::List(l) => seq(o, "[", "]", l.iter(), plain),
        Value::Set(s) => seq(o, "#{", "}", s.iter(), plain),
        // The API materializes links or fails TooLarge; never printed.
        Value::Link(_) => o.push_str("<link>"),
        Value::Unknown(u) => {
            o.push_str(&format!("tag({}, ", u.tag()));
            match u.content().to_value() {
                Ok(c) => plain(o, &c),
                // Not expected (the content was parsed canonical); raw bytes keep it readable.
                Err(_) => {
                    o.push_str("h'");
                    o.push_str(&hex::encode(u.content().as_bytes()));
                    o.push('\'');
                }
            }
            o.push(')');
        }
    }
}

/// Shortest decimal that reads back to the same bits, always with `.` or an exponent.
pub fn float_text(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 { "Infinity".into() } else { "-Infinity".into() }
    } else {
        let s = format!("{f:?}");
        if s.contains(['.', 'e', 'E']) { s } else { format!("{s}.0") }
    }
}

/// A JSON string literal.
pub fn quote(o: &mut String, s: &str) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
}

// ---- time

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// RFC 3339 UTC with milliseconds when nonzero; `None` outside years 0..=9999.
pub fn rfc3339(ms: i64) -> Option<String> {
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, mo, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return None;
    }
    let (h, mi, s, f) = (rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000);
    let frac = if f == 0 { String::new() } else { format!(".{f:03}") };
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}{frac}Z"))
}

/// Parses RFC 3339 (`2026-10-19T12:00:00.5+02:00`, or a bare date as UTC midnight) to ms.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        if t.bytes().all(|c| c.is_ascii_digit()) { t.parse().ok() } else { None }
    };
    if b.len() < 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > days[(mo - 1) as usize] {
        return None;
    }
    let mut ms = days_from_civil(y, mo, d) * 86_400_000;
    if b.len() == 10 {
        return Some(ms);
    }
    if !matches!(b.get(10), Some(b'T' | b't' | b' ')) || b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    ms += h * 3_600_000 + mi * 60_000 + sec * 1000;
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let digits = s.get(start..i)?;
        if digits.is_empty() {
            return None;
        }
        let three: String = digits.chars().chain("00".chars()).take(3).collect();
        ms += three.parse::<i64>().ok()?;
    }
    match s.get(i..)? {
        "Z" | "z" => Some(ms),
        off if off.len() == 6 && (off.starts_with('+') || off.starts_with('-')) && off.get(3..4) == Some(":") => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            let o = (oh * 60 + om) * 60_000;
            Some(if off.starts_with('+') { ms - o } else { ms + o })
        }
        _ => None,
    }
}

/// Length of the RFC 3339 timestamp at the start of `r` as the printer writes it (date, then
/// optionally `T` time, fraction, `Z` or offset); stops before a following `:` separator.
fn ts_len(r: &str) -> usize {
    let b = r.as_bytes();
    let at = |i: usize, f: fn(u8) -> bool| b.get(i).copied().is_some_and(f);
    let dig = |i: usize, n: usize| (i..i + n).all(|j| at(j, |c| c.is_ascii_digit()));
    if !(dig(0, 4) && at(4, |c| c == b'-') && dig(5, 2) && at(7, |c| c == b'-') && dig(8, 2)) {
        return 0;
    }
    if !(at(10, |c| c == b'T' || c == b't') && dig(11, 2) && at(13, |c| c == b':') && dig(14, 2) && at(16, |c| c == b':') && dig(17, 2)) {
        return 10;
    }
    let mut i = 19;
    if at(i, |c| c == b'.') {
        i += 1;
        while at(i, |c| c.is_ascii_digit()) {
            i += 1;
        }
    }
    if at(i, |c| c == b'Z' || c == b'z') {
        i + 1
    } else if at(i, |c| c == b'+' || c == b'-') && dig(i + 1, 2) && at(i + 3, |c| c == b':') && dig(i + 4, 2) {
        i + 6
    } else {
        i
    }
}

const UNITS: [(&str, i64); 5] = [("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000), ("ms", 1)];

/// `1d2h30m5s500ms`; `0s` for zero; a leading `-` when negative.
pub fn duration_text(ms: i64) -> String {
    if ms == 0 {
        return "0s".into();
    }
    let mut o = String::from(if ms < 0 { "-" } else { "" });
    let mut r = ms.unsigned_abs();
    for (u, n) in UNITS {
        let n = n.unsigned_abs();
        if r >= n {
            o.push_str(&format!("{}{u}", r / n));
            r %= n;
        }
    }
    o
}

/// Parses `duration_text` forms (units d, h, m, s, ms, any combination) to ms.
pub fn parse_duration(s: &str) -> Option<i64> {
    let (neg, mut rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    if rest.is_empty() {
        return None;
    }
    let mut total: i128 = 0;
    while !rest.is_empty() {
        let n = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let num: i128 = rest.get(..n)?.parse().ok()?;
        rest = rest.get(n..)?;
        let (unit, len) = if rest.starts_with("ms") { (1, 2) } else { (UNITS.iter().find(|(u, _)| rest.starts_with(u))?.1, 1) };
        rest = rest.get(len..)?;
        total = total.checked_add(num.checked_mul(i128::from(unit))?)?;
    }
    i64::try_from(if neg { -total } else { total }).ok()
}

// ---- parsing

/// Resolves `me`, `node`, `home` and script variables (`$name`) to tids.
pub type Aliases<'a> = &'a dyn Fn(&str) -> Option<Tid>;

pub fn no_aliases(_: &str) -> Option<Tid> {
    None
}

/// Parses a whole value.
pub fn parse(s: &str, ty: Ty<'_>, aliases: Aliases<'_>) -> Result<Value, String> {
    let mut p = Parser { s, pos: 0, aliases, depth: 0 };
    let v = p.value(ty)?;
    p.ws();
    if p.pos < s.len() {
        return Err(p.err("unexpected text after the value"));
    }
    Ok(v)
}

/// A path step whose meaning needs the current value: `[n]` on an untyped position (a list
/// index if the position holds a list, else a map key).
#[derive(Clone, Debug, PartialEq)]
pub enum PStep {
    Step(Step),
    IndexOrKey(i64),
}

/// Parses a path (`.title[2]#some{"x"}`); empty is the whole aspect.
pub fn parse_path(s: &str, ty: Ty<'_>, aliases: Aliases<'_>) -> Result<Vec<PStep>, String> {
    let mut p = Parser { s, pos: 0, aliases, depth: 0 };
    let mut out = Vec::new();
    let mut cur: Option<(&Schema, Type)> = ty.map(|(s, t)| (s, t.clone()));
    loop {
        p.ws();
        let Some(c) = p.peek() else { break };
        let k = match &cur {
            Some((s, t)) => kind(s, t),
            None => Kind::Plain,
        };
        let sch = cur.as_ref().map(|(s, _)| *s);
        let (step, next): (PStep, Option<Type>) = match c {
            '.' => {
                p.pos += 1;
                let w = p.word();
                let st = match &k {
                    Kind::Struct(st) => Some(st),
                    _ => None,
                };
                let (id, ft) = match w.parse::<u64>() {
                    Ok(id) => (id, st.and_then(|st| st.fields.get(&id)).map(|f| f.ty.clone())),
                    Err(_) => {
                        let (id, f) = st.and_then(|st| st.fields.iter().find(|(_, f)| f.name == w)).ok_or_else(|| p.err(&format!("unknown field {w:?}")))?;
                        (*id, Some(f.ty.clone()))
                    }
                };
                (PStep::Step(Step::Field(id)), ft)
            }
            '#' => {
                p.pos += 1;
                let w = p.word();
                let en = match &k {
                    Kind::Enum(e) => Some(e),
                    _ => None,
                };
                let (id, pt) = match w.parse::<u64>() {
                    Ok(id) => (id, en.and_then(|e| e.cases.get(&id)).and_then(|c| c.payload.clone())),
                    Err(_) => {
                        let (id, c) = en.and_then(|e| e.cases.iter().find(|(_, c)| c.name == w)).ok_or_else(|| p.err(&format!("unknown case {w:?}")))?;
                        (*id, c.payload.clone())
                    }
                };
                (PStep::Step(Step::Case(id)), pt)
            }
            '[' => {
                p.pos += 1;
                let r = match &k {
                    Kind::List(t) => {
                        let v = p.value(None)?;
                        let i = match v {
                            Value::Int(i) => usize::try_from(i).map_err(|_| p.err("negative index"))?,
                            _ => return Err(p.err("list index must be an int")),
                        };
                        (PStep::Step(Step::Index(i)), Some(t.clone()))
                    }
                    Kind::Map(kt, vt) => {
                        let v = p.value(sch.map(|s| (s, kt)))?;
                        (PStep::Step(Step::Key(v)), Some(vt.clone()))
                    }
                    _ => match p.value(None)? {
                        Value::Int(i) if i >= 0 => (PStep::IndexOrKey(i), None),
                        v => (PStep::Step(Step::Key(v)), None),
                    },
                };
                p.expect(']')?;
                r
            }
            '{' => {
                p.pos += 1;
                let et = match &k {
                    Kind::Set(t) => Some(t.clone()),
                    _ => None,
                };
                let v = p.value(match (&et, sch) {
                    (Some(t), Some(s)) => Some((s, t)),
                    _ => None,
                })?;
                p.expect('}')?;
                (PStep::Step(Step::Elem(v)), et)
            }
            _ => return Err(p.err("expected a path step (.field, #case, [index or key], {element})")),
        };
        out.push(step);
        cur = match (sch, next) {
            (Some(s), Some(t)) => Some((s, t)),
            _ => None,
        };
    }
    Ok(out)
}

/// The type at a path (for parsing the value written there), if the schema knows it.
pub fn type_at_path(s: &Schema, root: &Type, path: &[Step]) -> Option<Type> {
    let mut cur = root.clone();
    for st in path {
        cur = match (kind(s, &cur), st) {
            (Kind::Struct(t), Step::Field(id)) => t.fields.get(id)?.ty.clone(),
            (Kind::Enum(e), Step::Case(id)) => e.cases.get(id)?.payload.clone()?,
            (Kind::List(t), Step::Index(_)) => t,
            (Kind::Map(_, v), Step::Key(_)) => v,
            (Kind::Set(t), Step::Elem(_)) => t,
            _ => return None,
        };
    }
    Some(cur)
}

/// The element, key and value types inside a collection type (for op arguments).
pub fn inner_types(s: &Schema, t: &Type) -> (Option<Type>, Option<Type>) {
    match kind(s, t) {
        Kind::List(e) | Kind::Set(e) => (Some(e), None),
        Kind::Map(k, v) => (Some(k), Some(v)),
        _ => (None, None),
    }
}

/// An enum case id by name or number at a type.
pub fn case_id(s: Option<&Schema>, t: Option<&Type>, w: &str) -> Result<(u64, Option<Type>), String> {
    let en = match (s, t) {
        (Some(s), Some(t)) => match kind(s, t) {
            Kind::Enum(e) => Some(e),
            _ => None,
        },
        _ => None,
    };
    let w = w.strip_prefix('#').unwrap_or(w);
    match w.parse::<u64>() {
        Ok(id) => Ok((id, en.and_then(|e| e.cases.get(&id).and_then(|c| c.payload.clone())))),
        Err(_) => en
            .and_then(|e| e.cases.iter().find(|(_, c)| c.name == w).map(|(id, c)| (*id, c.payload.clone())))
            .ok_or_else(|| format!("unknown case {w:?}")),
    }
}

fn typed<'x>(s: Option<&'x Schema>, t: &'x Type) -> Ty<'x> {
    s.map(|s| (s, t))
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
    aliases: Aliases<'a>,
    depth: usize,
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

impl<'a> Parser<'a> {
    fn err(&self, m: &str) -> String {
        format!("{m} at column {}", self.s.get(..self.pos).map_or(0, |p| p.chars().count()) + 1)
    }
    fn rest(&self) -> &'a str {
        self.s.get(self.pos..).unwrap_or("")
    }
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }
    fn ws(&mut self) {
        let r = self.rest();
        self.pos += r.len() - r.trim_start().len();
    }
    fn eat(&mut self, c: char) -> bool {
        self.ws();
        if self.peek() == Some(c) {
            self.pos += c.len_utf8();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.eat(c) { Ok(()) } else { Err(self.err(&format!("expected `{c}`"))) }
    }
    /// A run of word characters.
    fn word(&mut self) -> &'a str {
        let r = self.rest();
        let n = r.find(|c: char| !is_word(c)).unwrap_or(r.len());
        let w = r.get(..n).unwrap_or("");
        self.pos += n;
        w
    }
    /// A run of characters that may form a bare duration (`-1h30m`).
    fn bare(&mut self) -> &'a str {
        let r = self.rest();
        let n = r.char_indices().find(|&(i, c)| !(c.is_ascii_alphanumeric() || (i == 0 && c == '-'))).map_or(r.len(), |(i, _)| i);
        let w = r.get(..n).unwrap_or("");
        self.pos += n;
        w
    }

    fn value(&mut self, ty: Ty<'_>) -> Result<Value, String> {
        self.depth += 1;
        if self.depth > 200 {
            return Err(self.err("value nests too deep"));
        }
        let v = self.value_inner(ty);
        self.depth -= 1;
        v
    }

    fn value_inner(&mut self, ty: Ty<'_>) -> Result<Value, String> {
        self.ws();
        let k = kind_of(ty);
        let s = ty.map(|(s, _)| s);
        let r = self.rest();
        let Some(c) = self.peek() else { return Err(self.err("expected a value")) };
        if matches!(k, Kind::Timestamp) && (c.is_ascii_digit() || c == '-') && !r.starts_with("-Infinity") {
            let n = ts_len(r);
            if n > 0 {
                let w = r.get(..n).unwrap_or("");
                let v = parse_rfc3339(w).map(Value::Int).ok_or_else(|| self.err("bad RFC 3339 timestamp"))?;
                self.pos += n;
                return Ok(v);
            }
        }
        if matches!(k, Kind::Duration) && (c.is_ascii_digit() || c == '-') {
            let start = self.pos;
            let w = self.bare().to_string();
            if w.ends_with(|c: char| c.is_ascii_alphabetic()) {
                let end = self.pos;
                self.pos = start;
                let v = parse_duration(&w).map(Value::Int).ok_or_else(|| self.err("bad duration"))?;
                self.pos = end;
                return Ok(v);
            }
            self.pos = start;
        }
        if c == '"' {
            return self.string().map(Value::Str);
        }
        if r.starts_with("h'") {
            self.pos += 2;
            let b = self.until_quote()?;
            return hex::decode(&b).map(Value::Bytes).ok_or_else(|| self.err("bad hex"));
        }
        if r.starts_with("b64'") {
            self.pos += 4;
            let b = self.until_quote()?;
            let norm: String = b.chars().filter(|c| !c.is_whitespace() && *c != '=').map(|c| match c {
                '+' => '-',
                '/' => '_',
                c => c,
            }).collect();
            return base64url::decode(&norm).map(Value::Bytes).ok_or_else(|| self.err("bad base64"));
        }
        if r.starts_with("osis://") {
            self.pos += 7;
            let w = self.tid_chars();
            return Tid::parse(&w).map(Value::Tid).map_err(|_| self.err("bad tid"));
        }
        if r.starts_with("tag(") {
            self.pos += 4;
            self.ws();
            let n: u64 = self.word().parse().map_err(|_| self.err("tag number: a u64"))?;
            self.expect(',')?;
            let c = self.value(None)?;
            self.expect(')')?;
            return Unknown::new(n, CanonicalBytes::from_value(&c)).map(Value::Unknown).ok_or_else(|| self.err("tag known to this build: use its own form"));
        }
        match c {
            '[' => {
                self.pos += 1;
                let et = match &k {
                    Kind::List(t) => typed(s, t),
                    _ => None,
                };
                let items = self.items(']', |p| p.value(et))?;
                Ok(Value::List(items))
            }
            '{' => {
                self.pos += 1;
                match &k {
                    Kind::Struct(st) => {
                        let m = self.items('}', |p| {
                            p.ws();
                            let (id, ft) = p.field_key(st)?;
                            p.expect(':')?;
                            let v = p.value(ft.as_ref().and_then(|t| typed(s, t)))?;
                            Ok((Value::Int(i64::try_from(id).map_err(|_| p.err("field id out of range"))?), v))
                        })?;
                        self.unique(m)
                    }
                    Kind::Map(kt, vt) => {
                        let m = self.items('}', |p| {
                            let kk = p.value(typed(s, kt))?;
                            p.expect(':')?;
                            Ok((kk, p.value(typed(s, vt))?))
                        })?;
                        self.unique(m)
                    }
                    _ => {
                        let m = self.items('}', |p| {
                            let kk = p.value(None)?;
                            p.expect(':')?;
                            Ok((kk, p.value(None)?))
                        })?;
                        self.unique(m)
                    }
                }
            }
            '#' => {
                self.pos += 1;
                if self.peek() == Some('{') {
                    self.pos += 1;
                    let et = match &k {
                        Kind::Set(t) => typed(s, t),
                        _ => None,
                    };
                    let items = self.items('}', |p| p.value(et))?;
                    let n = items.len();
                    let set: BTreeSet<Value> = items.into_iter().collect();
                    if set.len() != n {
                        return Err(self.err("duplicate set element"));
                    }
                    return Ok(Value::Set(set));
                }
                let w = self.word().to_string();
                let en = match &k {
                    Kind::Enum(e) => Some(e),
                    _ => None,
                };
                let (id, pt) = match w.parse::<u64>() {
                    Ok(id) => (id, en.and_then(|e| e.cases.get(&id)).and_then(|c| c.payload.clone())),
                    Err(_) => {
                        let (id, c) = en.and_then(|e| e.cases.iter().find(|(_, c)| c.name == w)).ok_or_else(|| self.err(&format!("unknown case {w:?}")))?;
                        (*id, c.payload.clone())
                    }
                };
                let payload = if self.peek() == Some('(') {
                    self.pos += 1;
                    let v = self.value(pt.as_ref().and_then(|t| typed(s, t)))?;
                    self.expect(')')?;
                    Some(Box::new(v))
                } else {
                    None
                };
                Ok(Value::Enum(id, payload))
            }
            c if c == '-' || c.is_ascii_digit() => self.number(),
            c if is_word(c) => {
                let start = self.pos;
                let w = self.word().to_string();
                match w.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    "NaN" => Ok(Value::float(f64::NAN)),
                    "Infinity" => Ok(Value::float(f64::INFINITY)),
                    _ => match (self.aliases)(&w) {
                        Some(t) => Ok(Value::Tid(t)),
                        None => {
                            self.pos = start;
                            Err(self.err(&format!("unknown word {w:?} (strings need quotes, tids osis://)")))
                        }
                    },
                }
            }
            _ => Err(self.err("expected a value")),
        }
    }

    fn unique(&self, m: Vec<(Value, Value)>) -> Result<Value, String> {
        let n = m.len();
        let map: BTreeMap<Value, Value> = m.into_iter().collect();
        if map.len() != n {
            return Err(self.err("duplicate map key"));
        }
        Ok(Value::Map(map))
    }

    /// A struct key: field name (bare or quoted) or id.
    fn field_key(&mut self, st: &StructType) -> Result<(u64, Option<Type>), String> {
        let name = if self.peek() == Some('"') {
            self.string()?
        } else {
            self.word().to_string()
        };
        if let Ok(id) = name.parse::<u64>() {
            return Ok((id, st.fields.get(&id).map(|f| f.ty.clone())));
        }
        st.fields.iter().find(|(_, f)| f.name == name).map(|(id, f)| (*id, Some(f.ty.clone()))).ok_or_else(|| self.err(&format!("unknown field {name:?}")))
    }

    /// Comma-separated items up to `close` (trailing comma allowed).
    fn items<T>(&mut self, close: char, mut f: impl FnMut(&mut Self) -> Result<T, String>) -> Result<Vec<T>, String> {
        let mut out = Vec::new();
        loop {
            if self.eat(close) {
                return Ok(out);
            }
            out.push(f(self)?);
            if !self.eat(',') {
                self.expect(close)?;
                return Ok(out);
            }
        }
    }

    fn tid_chars(&mut self) -> String {
        let r = self.rest();
        let n = r.find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_')).unwrap_or(r.len());
        self.pos += n;
        r.get(..n).unwrap_or("").to_string()
    }

    fn until_quote(&mut self) -> Result<String, String> {
        let r = self.rest();
        let n = r.find('\'').ok_or_else(|| self.err("unterminated '...'"))?;
        let out = r.get(..n).unwrap_or("").to_string();
        self.pos += n + 1;
        Ok(out)
    }

    fn number(&mut self) -> Result<Value, String> {
        if self.rest().starts_with("-Infinity") {
            self.pos += 9;
            return Ok(Value::float(f64::NEG_INFINITY));
        }
        let r = self.rest();
        let b = r.as_bytes();
        let mut i = usize::from(b.first() == Some(&b'-'));
        let digits = |i: &mut usize| {
            let s = *i;
            while b.get(*i).is_some_and(u8::is_ascii_digit) {
                *i += 1;
            }
            *i > s
        };
        let int_start = i;
        if !digits(&mut i) {
            return Err(self.err("expected a number"));
        }
        if i - int_start > 1 && b.get(int_start) == Some(&b'0') {
            return Err(self.err("leading zero"));
        }
        let mut float = false;
        if b.get(i) == Some(&b'.') {
            i += 1;
            float = true;
            if !digits(&mut i) {
                return Err(self.err("expected digits after `.`"));
            }
        }
        if matches!(b.get(i), Some(b'e' | b'E')) {
            i += 1;
            float = true;
            if matches!(b.get(i), Some(b'+' | b'-')) {
                i += 1;
            }
            if !digits(&mut i) {
                return Err(self.err("expected exponent digits"));
            }
        }
        let t = r.get(..i).unwrap_or("");
        let v = if float {
            t.parse::<f64>().map(Value::float).map_err(|_| self.err("bad float"))?
        } else {
            t.parse::<i64>().map(Value::Int).map_err(|_| self.err("int out of range (i64)"))?
        };
        self.pos += i;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        let mut it = self.rest().char_indices();
        loop {
            let Some((i, c)) = it.next() else { return Err(self.err("unterminated string")) };
            match c {
                '"' => {
                    self.pos += i + 1;
                    return Ok(out);
                }
                '\\' => {
                    let Some((_, e)) = it.next() else { return Err(self.err("unterminated string")) };
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'u' => {
                            let hex4 = |it: &mut std::str::CharIndices<'_>| -> Option<u32> {
                                let h: String = it.by_ref().take(4).map(|(_, c)| c).collect();
                                if h.len() == 4 && h.chars().all(|c| c.is_ascii_hexdigit()) { u32::from_str_radix(&h, 16).ok() } else { None }
                            };
                            let hi = hex4(&mut it).ok_or_else(|| self.err("bad \\u escape"))?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                let ok = matches!((it.next(), it.next()), (Some((_, '\\')), Some((_, 'u'))));
                                let lo = if ok { hex4(&mut it) } else { None }.filter(|lo| (0xdc00..0xe000).contains(lo)).ok_or_else(|| self.err("lone surrogate"))?;
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).ok_or_else(|| self.err("bad \\u escape"))?);
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                c => out.push(c),
            }
        }
    }
}
