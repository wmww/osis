//! Write commands (notes/cli.md Command table, Things and aspects): each applies to a `Write`, so a
//! single command and a `write` script line share one implementation.

use crate::args::{CreateArgs, FireArgs, MemberCmd, OpArgs, GroupsArgs, RmArgs, ScriptCmd, ScriptLine, SetArgs, WriteFlags};
use crate::text::{self, PStep};
use crate::{Ctx, parse_dur, parse_ts, usage};
use clap::Parser;
use osis::{AspectWrite, DynamicAspectKey, Expiry, Member, Path, PurgeBy, Retention, Step, Tid, Time, Value, ValueType};
use std::ops::Range;

/// What a write command produced.
#[derive(Default)]
pub struct Did {
    /// Tids bound by `create` (name, tid); the unnamed one of a single command is "".
    pub created: Vec<(String, Tid)>,
    /// The expiry asked for so far.
    pub expires: Option<Expiry>,
}

/// The groups a new thing goes into (none: added later, or on this node alone).
pub fn groups(ctx: &Ctx<'_>, p: &GroupsArgs) -> anyhow::Result<Vec<Tid>> {
    if p.in_.is_some() && !p.in_all.is_empty() {
        return Err(usage("give at most one of --in G, --in-all G,G"));
    }
    p.in_.iter().chain(&p.in_all).map(|g| ctx.tid(g)).collect()
}

/// Parses a path. `[n]` on an untyped position: for a read, a list index if the saved value
/// there is a list, else a map key; for a write (`write: true`), a map key, and an error when
/// the saved value there is a list (untyped lists take no index writes) or when this script
/// already wrote the aspect (its pending state is invisible, so the saved one cannot decide).
pub fn path(ctx: &mut Ctx<'_>, t: Tid, key: &DynamicAspectKey, s: &str, write: bool) -> anyhow::Result<Path> {
    let al = |w: &str| ctx.alias(w);
    let ty = key.value_type().map(|t| t.get());
    let steps = text::parse_path(s, ty.as_ref(), &al).map_err(|e| usage(format!("bad path {s:?}: {e}")))?;
    let mut out = Vec::new();
    let mut cur: Option<Option<Value>> = None;
    for st in steps {
        let step = match st {
            PStep::Step(s) => s,
            PStep::IndexOrKey(i) => {
                if write && (ctx.pending.contains(&(t, key.name().as_str().to_string())) || ctx.pending.contains(&(t, String::new()))) {
                    return Err(usage(format!("[{i}] on untyped {} written earlier in this script: list index or map key is unknown (register a schema, or write in a separate step)", key.name().as_str())));
                }
                if cur.is_none() {
                    let untyped = DynamicAspectKey::untyped(key.name());
                    cur = Some(ctx.db.at(t, untyped).get()?);
                }
                let here = cur.as_ref().and_then(|v| v.as_ref()).and_then(|v| osis_schema::value_at(v, &Path(out.clone())));
                match here {
                    Some(Value::List(_)) if write => return Err(usage(format!("[{i}]: {} is an untyped list; index writes need a schema (--schema)", key.name().as_str()))),
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
fn type_at(key: &DynamicAspectKey, p: &Path) -> Option<ValueType> {
    text::type_at_path(key.value_type()?.get(), &p.0)
}

fn expiry(within: &Option<String>, at: &Option<String>) -> anyhow::Result<Option<Expiry>> {
    Ok(match (within, at) {
        (Some(d), _) => Some(Expiry::In(parse_dur(d)?)),
        (_, Some(t)) => Some(Expiry::At(Time(parse_ts(t)?))),
        _ => None,
    })
}

/// A line's expiry is its commit's: lines of one script asking for different ones are refused.
fn commit_expiry(w: &mut osis::Write<'_>, did: &mut Did, e: Option<Expiry>) -> anyhow::Result<()> {
    let Some(e) = e else { return Ok(()) };
    if did.expires.is_some_and(|x| x != e) {
        return Err(usage("a commit has one expiry: this script asks for two, so run them as separate commands"));
    }
    did.expires = Some(e);
    w.expires(e);
    Ok(())
}

fn with_flags<'w, 'd>(mut a: AspectWrite<'w, 'd, DynamicAspectKey>, f: &WriteFlags, key: &DynamicAspectKey) -> anyhow::Result<AspectWrite<'w, 'd, DynamicAspectKey>> {
    if let Some(r) = &f.retention {
        a = a.retention(retention(r, key.default_retention())?);
    }
    Ok(a)
}

/// `by=NAME` over the key's default (what history keeps is the thing's setting, `retention^.0`).
pub fn retention(s: &str, mut r: Retention) -> anyhow::Result<Retention> {
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').ok_or_else(|| usage(format!("bad retention item {part:?}")))?;
        match k {
            "by" => r.by = [PurgeBy::Admin, PurgeBy::AuthorOrAdmin, PurgeBy::Writer].into_iter().find(|p| p.name() == v).ok_or_else(|| usage(format!("by: one of admin, author_or_admin, writer (got {v:?})")))?,
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
    let admin = a.admin.as_deref().map(|o| ctx.tid(o)).transpose()?;
    let groups = groups(ctx, &a.groups)?;
    if !a.pairs.len().is_multiple_of(2) {
        return Err(usage("create takes AK VALUE pairs"));
    }
    let t = match admin {
        Some(a) => w.create_with_admin(a)?,
        None => w.create()?,
    };
    for g in groups {
        w.group(g).add(Member::Item(t))?;
    }
    for pair in a.pairs.chunks(2) {
        let key = ctx.aspect_key(&pair[0])?;
        let v = ctx.value(&pair[1], key.value_type().map(|t| t.get()).as_ref())?;
        w.at(t, key).set(&v)?;
    }
    if let Some(n) = &a.as_ {
        ctx.vars.insert(n.clone(), t);
    }
    did.created.push((a.as_.clone().unwrap_or_default(), t));
    Ok(())
}

fn set(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &SetArgs, overwrite: bool) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.aspect_key(&a.ak)?;
    if a.stream {
        let p = match a.rest.as_slice() {
            [] => Path::root(),
            [p] => path(ctx, t, &key, p, true)?,
            _ => return Err(usage("--stream takes [PATH] and the value on stdin")),
        };
        with_flags(w.at(t, key.clone()), &a.w, &key)?.path(p).set_stream(&mut *ctx.stdin)?;
        return Ok(());
    }
    let (p, val) = match a.rest.as_slice() {
        [v] => (Path::root(), v),
        [p, v] => (path(ctx, t, &key, p, true)?, v),
        _ => return Err(usage("expected [PATH] VALUE")),
    };
    let pt = type_at(&key, &p);
    let v = ctx.value(val, pt.as_ref())?;
    let mut aw = with_flags(w.at(t, key.clone()), &a.w, &key)?;
    let mut pw = aw.path(p);
    if overwrite { pw.overwrite(&v)? } else { pw.set(&v)? }
    Ok(())
}

fn fire(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &FireArgs) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.aspect_key(&a.ak)?;
    let v = ctx.value(&a.value, key.value_type().map(|t| t.get()).as_ref())?;
    let mut at = with_flags(w.at(t, key.clone()), &a.w, &key)?;
    match &a.replaces {
        Some(c) => at.replace(c.parse().map_err(|_| crate::usage(format!("not a commit id: {c}")))?, &v)?,
        None => at.fire(&v)?,
    }
    Ok(())
}

fn rm(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &RmArgs) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.aspect_key(&a.ak)?;
    let p = match a.path.as_deref() {
        None | Some("") => Path::root(),
        Some(s) => path(ctx, t, &key, s, true)?,
    };
    w.at(t, key).path(p).remove()?;
    Ok(())
}

fn op(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, a: &OpArgs) -> anyhow::Result<()> {
    let t = ctx.tid(&a.t)?;
    let key = ctx.aspect_key(&a.ak)?;
    let p = path(ctx, t, &key, &a.path, true)?;
    let pt = type_at(&key, &p);
    let et = pt.as_ref().and_then(text::element_type);
    let ety = et.as_ref();
    let args = &a.args;
    let n = |k: usize| -> anyhow::Result<()> {
        if args.len() == k { Ok(()) } else { Err(usage(format!("{} takes {k} argument(s)", a.op))) }
    };
    let mut aw = with_flags(w.at(t, key.clone()), &a.w, &key)?;
    let mut pw = aw.path(p);
    match a.op.as_str() {
        "move" => {
            n(2)?;
            pw.move_range(range(&args[0])?, index(&args[1])?)?
        }
        "splice" => {
            if args.is_empty() {
                return Err(usage("splice A..B [V...]"));
            }
            let r = range(&args[0])?;
            if args.len() == 1 {
                pw.splice(r, ())?
            } else if matches!(pt, Some(ValueType::Text)) {
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
                pw.splice(r, s.as_str())?
            } else {
                let vs = args[1..].iter().map(|v| ctx.value(v, ety)).collect::<anyhow::Result<Vec<_>>>()?;
                pw.splice(r, &vs)?
            }
        }
        "undelete" => return Err(crate::cmd::not_built("undelete")),
        "add" => {
            n(1)?;
            pw.add(&ctx.value(&args[0], ety)?)?
        }
        "contribute" => {
            n(1)?;
            pw.contribute(&ctx.value(&args[0], None)?)?
        }
        other => return Err(usage(format!("unknown op {other:?}"))),
    }
    Ok(())
}

/// Applies one write command to the `Write`.
pub fn apply(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, c: &ScriptCmd, did: &mut Did) -> anyhow::Result<()> {
    apply_one(ctx, w, c, did)?;
    // Record what this script wrote (path resolution must not trust the saved state there).
    let touched = match c {
        ScriptCmd::Set(SetArgs { t, ak, .. }) | ScriptCmd::Overwrite(SetArgs { t, ak, .. }) | ScriptCmd::Rm(RmArgs { t, ak, .. }) | ScriptCmd::Op(OpArgs { t, ak, .. }) => {
            Some((ctx.tid(t)?, ak.clone()))
        }
        ScriptCmd::Delete { t } => Some((ctx.tid(t)?, String::new())),
        ScriptCmd::Create(_) => did.created.last().map(|(_, t)| (*t, String::new())),
        _ => None,
    };
    ctx.pending.extend(touched);
    Ok(())
}

fn member(t: osis::Tid, subgroup: bool) -> Member {
    if subgroup { Member::Subgroup(t) } else { Member::Item(t) }
}

fn apply_one(ctx: &mut Ctx<'_>, w: &mut osis::Write<'_>, c: &ScriptCmd, did: &mut Did) -> anyhow::Result<()> {
    if let ScriptCmd::Set(SetArgs { w: f, .. }) | ScriptCmd::Overwrite(SetArgs { w: f, .. }) | ScriptCmd::Fire(FireArgs { w: f, .. }) | ScriptCmd::Op(OpArgs { w: f, .. }) = c {
        commit_expiry(w, did, expiry(&f.expires_in, &f.expires_at)?)?;
    }
    match c {
        ScriptCmd::Create(a) => create(ctx, w, a, did),
        ScriptCmd::Set(a) => set(ctx, w, a, false),
        ScriptCmd::Overwrite(a) => set(ctx, w, a, true),
        ScriptCmd::Fire(a) => fire(ctx, w, a),
        ScriptCmd::Rm(a) => rm(ctx, w, a),
        ScriptCmd::Op(a) => op(ctx, w, a),
        ScriptCmd::Group(MemberCmd::Add { g, t, subgroup, expires_in, expires_at }) => {
            let (g, m) = (ctx.tid(g)?, member(ctx.tid(t)?, *subgroup));
            commit_expiry(w, did, expiry(expires_in, expires_at)?)?;
            Ok(w.group(g).add(m)?)
        }
        ScriptCmd::Group(MemberCmd::Rm { g, t, subgroup }) => Ok(w.group(ctx.tid(g)?).remove(member(ctx.tid(t)?, *subgroup))?),
        ScriptCmd::Delete { t } => Ok(w.delete(ctx.tid(t)?)?),
    }
}

/// Splits a script line into arguments: whitespace separates, except inside quotes and
/// brackets, so a value is one argument with its quotes kept (`set $a x:y.0 {a: "b c"}`). A
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
