//! Write commands (notes/cli.md Command table, Things and aspects): each applies to a `Write` batch, so a
//! single command and a `write` script line share one implementation.

use crate::args::{CreateArgs, OpArgs, PlaceArgs, RmArgs, ScriptCmd, ScriptLine, SetArgs, SubCmd, WriteFlags};
use crate::text::{self, PStep};
use crate::{Ctx, parse_dur, parse_ts, usage};
use clap::Parser;
use osis::{AspectKey, AspectWrite, CaseId, Error, Key, Path, Place, Retention, Step, Tid, Value, WallMs};
use osis_schema::{Bound, PurgeBy, Type};
use std::ops::Range;

/// What a write command produced.
#[derive(Default)]
pub struct Did {
    /// Tids bound by `create` (name, tid); the unnamed one of a single command is "".
    pub created: Vec<(String, Tid)>,
}

pub fn place(ctx: &Ctx<'_>, p: &PlaceArgs) -> anyhow::Result<Place> {
    let n = usize::from(p.in_.is_some()) + usize::from(!p.in_all.is_empty()) + usize::from(p.unsynced);
    if n != 1 {
        return Err(usage("give exactly one of --in G, --in-all G,G, --unsynced"));
    }
    Ok(match (&p.in_, p.unsynced) {
        (Some(g), _) => Place::In(ctx.tid(g)?),
        (None, true) => Place::Unsynced,
        (None, false) => Place::InAll(p.in_all.iter().map(|g| ctx.tid(g)).collect::<anyhow::Result<_>>()?),
    })
}

/// The schema type of an aspect key, owned.
fn root_type(key: &Key) -> Option<Type> {
    key.ty().cloned()
}

/// Parses a path. `[n]` on an untyped position: for a read, a list index if the saved value
/// there is a list, else a map key; for a write (`write: true`), a map key, and an error when
/// the saved value there is a list (untyped lists take no index writes) or when this batch
/// already wrote the aspect (its pending state is invisible, so the saved one cannot decide).
pub fn path(ctx: &mut Ctx<'_>, t: Tid, key: &Key, s: &str, write: bool) -> anyhow::Result<Path> {
    let rt = root_type(key);
    let ty = key.schema().zip(rt.as_ref()).map(|(s, t)| (&**s, t));
    let al = |w: &str| ctx.alias(w);
    let steps = text::parse_path(s, ty, &al).map_err(|e| usage(format!("bad path {s:?}: {e}")))?;
    let mut out = Vec::new();
    let mut cur: Option<Option<Value>> = None;
    for st in steps {
        let step = match st {
            PStep::Step(s) => s,
            PStep::IndexOrKey(i) => {
                if write && (ctx.pending.contains(&(t, key.ak().as_str().to_string())) || ctx.pending.contains(&(t, String::new()))) {
                    return Err(usage(format!("[{i}] on untyped {} written earlier in this batch: list index or map key is unknown (register a schema, or write in a separate step)", key.ak().as_str())));
                }
                if cur.is_none() {
                    let untyped = Key::new(key.ak().clone(), None);
                    cur = Some(ctx.db.get(t, untyped).ok().flatten());
                }
                let here = cur.as_ref().and_then(|v| v.as_ref()).and_then(|v| osis_schema::value_at(v, &Path(out.clone())));
                match here {
                    Some(Value::List(_)) if write => return Err(usage(format!("[{i}]: {} is an untyped list; index writes need a schema (--schema)", key.ak().as_str()))),
                    Some(Value::List(_)) => Step::Index(usize::try_from(i).map_err(|_| usage("bad index"))?),
                    _ => Step::Key(Value::Int(i)),
                }
            }
        };
        out.push(step);
    }
    Ok(Path(out))
}

/// The schema type at a path, for parsing what is written there.
fn type_at(key: &Key, p: &Path) -> Option<Type> {
    let s = key.schema()?;
    text::type_at_path(s, key.ty()?, &p.0)
}

fn with_flags<'w, 'd>(a: AspectWrite<'w, 'd, Key>, f: &WriteFlags, ctx: &Ctx<'_>, key: &Key) -> anyhow::Result<AspectWrite<'w, 'd, Key>> {
    let mut a = a;
    if let Some(d) = &f.expires_in {
        a = a.expires_in(parse_dur(d)?);
    }
    if let Some(t) = &f.expires_at {
        a = a.expires_at(WallMs(parse_ts(t)?));
    }
    if let Some(r) = &f.retention {
        let base = key.schema().and_then(|s| s.defaults(key.ak().as_str())).map(|d| d.retention).unwrap_or_default();
        a = a.retention(retention(r, base)?);
    }
    let _ = ctx;
    Ok(a)
}

/// `by=NAME,at_least=DUR,at_least_abs=TS,at_most=DUR,at_most_abs=TS` over the key's default.
pub fn retention(s: &str, mut r: Retention) -> anyhow::Result<Retention> {
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').ok_or_else(|| usage(format!("bad retention item {part:?}")))?;
        let dur = || parse_dur(v).map(|d| d.as_millis() as u64);
        let b = |r: &mut Bound, abs: bool| -> anyhow::Result<()> {
            if abs { r.abs = Some(parse_ts(v)?) } else { r.rel = Some(dur()?) }
            Ok(())
        };
        match k {
            "by" => r.by = PurgeBy::ALL.into_iter().find(|p| p.name() == v).ok_or_else(|| usage(format!("by: one of nobody, admin, author, writer (got {v:?})")))?,
            "at_least" => b(&mut r.at_least, false)?,
            "at_least_abs" => b(&mut r.at_least, true)?,
            "at_most" => b(&mut r.at_most, false)?,
            "at_most_abs" => b(&mut r.at_most, true)?,
            _ => return Err(usage(format!("unknown retention item {k:?}"))),
        }
    }
    Ok(r)
}

fn range(s: &str) -> anyhow::Result<Range<usize>> {
    let (a, b) = s.split_once("..").ok_or_else(|| usage(format!("expected a range A..B, got {s:?}")))?;
    let n = |x: &str| x.parse::<usize>().map_err(|_| usage(format!("bad range {s:?}")));
    let (a, b) = (n(a)?, n(b)?);
    if b < a {
        return Err(usage(format!("bad range {s:?}")));
    }
    Ok(a..b)
}

fn index(s: &str) -> anyhow::Result<usize> {
    s.parse().map_err(|_| usage(format!("bad index {s:?}")))
}

pub fn create(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &CreateArgs, did: &mut Did) -> anyhow::Result<()> {
    let owner = ctx.tid(&a.owner)?;
    let place = place(ctx, &a.place)?;
    if !a.pairs.len().is_multiple_of(2) {
        return Err(usage("create takes AK VALUE pairs"));
    }
    let t = w.create(owner, place)?;
    if a.group {
        w.make_group(t)?;
    }
    for pair in a.pairs.chunks(2) {
        let key = ctx.key(&pair[0])?;
        let rt = root_type(&key);
        let v = ctx.value(&pair[1], key.schema().zip(rt.as_ref()).map(|(s, t)| (&**s, t)))?;
        w.at(t, key).set(&v)?;
    }
    if let Some(n) = &a.as_ {
        ctx.vars.insert(n.clone(), t);
    }
    did.created.push((a.as_.clone().unwrap_or_default(), t));
    Ok(())
}

fn set(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &SetArgs, replace: bool) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.key(&a.ak)?;
    if a.stream {
        let p = match a.rest.as_slice() {
            [] => Path::root(),
            [p] => path(ctx, t, &key, p, true)?,
            _ => return Err(usage("--stream takes [PATH] and the value on stdin")),
        };
        let mut aw = with_flags(w.at(t, key.clone()), &a.w, ctx, &key)?;
        aw.path(p).set_stream(&mut *ctx.stdin)?;
        return Ok(());
    }
    let (p, val) = match a.rest.as_slice() {
        [v] => (Path::root(), v),
        [p, v] => (path(ctx, t, &key, p, true)?, v),
        _ => return Err(usage("expected [PATH] VALUE")),
    };
    let pt = type_at(&key, &p);
    let v = ctx.value(val, key.schema().zip(pt.as_ref()).map(|(s, t)| (&**s, t)))?;
    let mut aw = with_flags(w.at(t, key.clone()), &a.w, ctx, &key)?;
    match (p.0.is_empty(), replace) {
        (true, false) => aw.set(&v)?,
        (true, true) => aw.replace(&v)?,
        (false, false) => aw.path(p).set(&v)?,
        (false, true) => aw.path(p).replace(&v)?,
    }
    Ok(())
}

fn rm(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &RmArgs) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.key(&a.ak)?;
    match a.path.as_deref() {
        None | Some("") => w.at(t, key).remove()?,
        Some(s) => {
            let p = path(ctx, t, &key, s, true)?;
            w.at(t, key).path(p).remove()?
        }
    }
    Ok(())
}

fn op(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &OpArgs) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.key(&a.ak)?;
    let p = path(ctx, t, &key, &a.path, true)?;
    let pt = type_at(&key, &p);
    let sch = key.schema().cloned();
    let (et, vt) = match (&sch, &pt) {
        (Some(s), Some(t)) => text::inner_types(s, t),
        _ => (None, None),
    };
    let (ety, vty) = (sch.as_deref().zip(et.as_ref()), sch.as_deref().zip(vt.as_ref()));
    let args = &a.args;
    let n = |k: usize| -> anyhow::Result<()> {
        if args.len() == k { Ok(()) } else { Err(usage(format!("{} takes {k} argument(s)", a.op))) }
    };
    // Parse every argument before borrowing the batch.
    enum O {
        Insert(usize, Vec<Value>),
        Delete(Range<usize>),
        Move(Range<usize>, usize),
        Splice(Range<usize>, String),
        Add(Value),
        RemoveElem(Value),
        Put(Value, Value),
        RemoveKey(Value),
        Inc(Value),
        Observe(Value),
        SetCase(u64, Option<Value>),
    }
    let o = match a.op.as_str() {
        "insert" => {
            if args.len() < 2 {
                return Err(usage("insert I V..."));
            }
            let i = index(&args[0])?;
            let vs = args[1..].iter().map(|v| ctx.value(v, ety)).collect::<anyhow::Result<Vec<_>>>()?;
            O::Insert(i, vs)
        }
        "delete" => {
            n(1)?;
            O::Delete(range(&args[0])?)
        }
        "move" => {
            n(2)?;
            O::Move(range(&args[0])?, index(&args[1])?)
        }
        "splice" => {
            n(2)?;
            let s = ctx.arg_text(&args[1])?;
            let s = if s.starts_with('"') {
                match text::parse(&s, None, &text::no_aliases) {
                    Ok(Value::Str(s)) => s,
                    _ => return Err(usage("splice text: a string")),
                }
            } else {
                s
            };
            O::Splice(range(&args[0])?, s)
        }
        "undelete" => return Err(Error::Unsupported("undelete (issues/api-deferred.md)").into()),
        "add" => {
            n(1)?;
            O::Add(ctx.value(&args[0], ety)?)
        }
        "remove-elem" => {
            n(1)?;
            O::RemoveElem(ctx.value(&args[0], ety)?)
        }
        "put" => {
            n(2)?;
            O::Put(ctx.value(&args[0], ety)?, ctx.value(&args[1], vty)?)
        }
        "remove-key" => {
            n(1)?;
            O::RemoveKey(ctx.value(&args[0], ety)?)
        }
        "inc" => {
            n(1)?;
            O::Inc(ctx.value(&args[0], None)?)
        }
        "observe" => {
            n(1)?;
            O::Observe(ctx.value(&args[0], None)?)
        }
        "set-case" => {
            if args.is_empty() || args.len() > 2 {
                return Err(usage("set-case ID [V]"));
            }
            let (id, payload_ty) = text::case_id(sch.as_deref(), pt.as_ref(), &args[0]).map_err(usage)?;
            let pl = match args.get(1) {
                Some(v) => Some(ctx.value(v, sch.as_deref().zip(payload_ty.as_ref()))?),
                None => None,
            };
            O::SetCase(id, pl)
        }
        other => return Err(usage(format!("unknown op {other:?}"))),
    };
    let mut aw = with_flags(w.at(t, key.clone()), &a.w, ctx, &key)?;
    let mut pw = aw.path(p);
    match o {
        O::Insert(i, vs) => pw.insert(i, &vs)?,
        O::Delete(r) => pw.delete(r)?,
        O::Move(r, to) => pw.move_range(r, to)?,
        O::Splice(r, s) => pw.splice(r, &s)?,
        O::Add(v) => pw.add(&v)?,
        O::RemoveElem(v) => pw.remove_elem(&v)?,
        O::Put(k, v) => pw.put(&k, &v)?,
        O::RemoveKey(k) => pw.remove_key(&k)?,
        O::Inc(v) => pw.inc(&v)?,
        O::Observe(v) => pw.observe(&v)?,
        O::SetCase(id, pl) => pw.set_case(CaseId(id), pl)?,
    }
    Ok(())
}

/// Applies one write command to the batch.
pub fn apply(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, c: &ScriptCmd, did: &mut Did) -> anyhow::Result<()> {
    apply_one(ctx, w, c, did)?;
    // Record what this batch wrote (path resolution must not trust the saved state there).
    let touched: Vec<(String, String)> = match c {
        ScriptCmd::Set(a) | ScriptCmd::Replace(a) => vec![(a.t.clone(), a.ak.clone())],
        ScriptCmd::Rm(a) => vec![(a.t.clone(), a.ak.clone())],
        ScriptCmd::Op(a) => vec![(a.t.clone(), a.ak.clone())],
        ScriptCmd::Delete { t } => vec![(t.clone(), String::new())],
        ScriptCmd::Create(_) => {
            let t = did.created.last().map(|(_, t)| t.to_uri()).unwrap_or_default();
            vec![(t, String::new())]
        }
        _ => Vec::new(),
    };
    for (t, ak) in touched {
        let t = ctx.tid(&t)?;
        ctx.pending.insert((t, ak));
    }
    Ok(())
}

fn apply_one(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, c: &ScriptCmd, did: &mut Did) -> anyhow::Result<()> {
    match c {
        ScriptCmd::Create(a) => create(ctx, w, a, did),
        ScriptCmd::Set(a) => set(ctx, w, a, false),
        ScriptCmd::Replace(a) => set(ctx, w, a, true),
        ScriptCmd::Rm(a) => rm(ctx, w, a),
        ScriptCmd::Op(a) => op(ctx, w, a),
        ScriptCmd::Place { t, g } => Ok(w.place(ctx.tid(t)?, ctx.tid(g)?)?),
        ScriptCmd::Unplace { t, g } => Ok(w.unplace(ctx.tid(t)?, ctx.tid(g)?)?),
        ScriptCmd::Sub(SubCmd::Add { g, sub }) => Ok(w.add_subgroup(ctx.tid(g)?, ctx.tid(sub)?)?),
        ScriptCmd::Sub(SubCmd::Rm { g, sub }) => Ok(w.remove_subgroup(ctx.tid(g)?, ctx.tid(sub)?)?),
        ScriptCmd::Delete { t } => Ok(w.delete(ctx.tid(t)?)?),
    }
}

/// Splits a script line into arguments: whitespace separates, except inside quotes and
/// brackets, so a value is one argument with its quotes kept (`set $a /x/y {a: "b c"}`). A
/// token wholly in single quotes loses them (`''` is the empty path).
pub fn split_line(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut in_str, mut esc, mut in_single, mut started) = (0usize, false, false, false, false);
    for c in line.chars() {
        if in_str {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if in_single {
            cur.push(c);
            if c == '\'' {
                in_single = false;
            }
            continue;
        }
        match c {
            c if c.is_whitespace() && depth == 0 => {
                if started {
                    out.push(unquote_single(std::mem::take(&mut cur)));
                    started = false;
                }
                continue;
            }
            '"' => in_str = true,
            '\'' => in_single = true,
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        cur.push(c);
        started = true;
    }
    if in_str || in_single || depth > 0 {
        return Err("unbalanced quotes or brackets".into());
    }
    if started {
        out.push(unquote_single(cur));
    }
    Ok(out)
}

fn unquote_single(s: String) -> String {
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') && s.matches('\'').count() == 2 { s[1..s.len() - 1].to_string() } else { s }
}

/// Parses a `write` script: one command per line, `#` comments, blank lines skipped.
pub fn script(text: &str) -> anyhow::Result<Vec<(usize, ScriptCmd)>> {
    let mut out = Vec::new();
    for (i, l) in text.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let words = split_line(l).map_err(|e| usage(format!("line {}: {e}", i + 1)))?;
        let parsed = ScriptLine::try_parse_from(words).map_err(|e| usage(format!("line {}: {}", i + 1, e.render().to_string().lines().next().unwrap_or("").trim_start_matches("error: "))))?;
        out.push((i + 1, parsed.cmd));
    }
    Ok(out)
}
