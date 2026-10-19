//! Command bodies (plans/cli.md §4): each a thin wrapper over one API call, plus printing.

use crate::args::*;
use crate::json::{self, J};
use crate::text::{self, Ty};
use crate::write::{self, Did};
use crate::{Ctx, StoreSel, exit, open, parse_dur, parse_ts, usage};
use anyhow::{Context as _, anyhow};
use osis::{
    AspectKey, Change, CommitId, Demotion, EdgeOpts, EntryState, Error, HistoryQuery, Key, LinkOpts, Lower, Osis, Role, Schema, Source, SyncScope, Target, Tid, Ts, UndoScope,
    Value, WaitForSync, WallMs,
};
use std::future::Future;
use std::io::BufRead;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

pub fn role_text(r: Role) -> &'static str {
    match r {
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
    }
}

fn parse_role(s: &str) -> anyhow::Result<Role> {
    match s {
        "read" => Ok(Role::Read),
        "write" => Ok(Role::Write),
        "admin" => Ok(Role::Admin),
        _ => Err(usage(format!("role: read, write or admin (got {s:?})"))),
    }
}

pub fn commit_text(c: &CommitId) -> String {
    osis_schema::osis_core::hex::encode(&c.0)
}

fn parse_commit(s: &str) -> anyhow::Result<CommitId> {
    osis_schema::osis_core::hex::decode(s).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(CommitId).ok_or_else(|| usage(format!("not a commit id (64 hex digits): {s}")))
}

fn ts_text(raw: bool, ms: u64) -> String {
    if raw { ms.to_string() } else { i64::try_from(ms).ok().and_then(text::rfc3339).unwrap_or_else(|| ms.to_string()) }
}

fn ts_of(t: Ts) -> u64 {
    t.wall_ms().0
}

// ---- futures without a runtime: the API's futures are runtime-agnostic (notes/api.md).

struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// `now + d`; `None` (no deadline) for no timeout or one too far to represent.
fn deadline(d: Option<Duration>) -> Option<Instant> {
    d.and_then(|d| Instant::now().checked_add(d))
}

/// What the API's `Duration`-taking waits get for "no timeout" (`--timeout 0`): the CLI's own
/// deadline (none) ends the wait first.
const FOREVER: Duration = Duration::from_secs(100 * 365 * 86_400);

/// Polls `f` on this thread until it is ready or `timeout` passes (`None`: timed out).
fn block_on<F: Future>(f: F, timeout: Option<Duration>) -> Option<F::Output> {
    let mut f = std::pin::pin!(f);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let end = deadline(timeout);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        match end {
            None => std::thread::park(),
            Some(e) => {
                let now = Instant::now();
                if now >= e {
                    return None;
                }
                std::thread::park_timeout(e - now);
            }
        }
    }
}

fn wait<T>(ctx: &Ctx<'_>, f: impl Future<Output = osis::Result<T>>) -> anyhow::Result<T> {
    match block_on(f, ctx.timeout()?) {
        Some(r) => Ok(r?),
        None => Err(exit(6, "timed out")),
    }
}

fn demotion(d: &DemoteFlags, ctx: &Ctx<'_>) -> anyhow::Result<Demotion> {
    let sync = match d.sync.as_deref() {
        None | Some("required") => WaitForSync::Required,
        Some("try") => WaitForSync::Try(ctx.timeout()?.unwrap_or(Duration::from_secs(30))),
        Some("skip") => WaitForSync::Skip,
        Some(o) => return Err(usage(format!("--sync: required, try or skip (got {o:?})"))),
    };
    let backdate = d.backdate.as_deref().map(parse_ts).transpose()?.map(WallMs);
    Ok(Demotion { sync, backdate })
}

fn scope(ctx: &Ctx<'_>, s: &Scope) -> anyhow::Result<UndoScope> {
    match (&s.thing, s.aspect.is_empty(), &s.group) {
        (Some(t), true, None) => Ok(UndoScope::Thing(ctx.tid(t)?)),
        (None, false, None) => Ok(UndoScope::Aspects(
            s.aspect.chunks(2).map(|p| Ok((ctx.tid(&p[0])?, osis::Ak::new(&p[1]).map_err(|_| usage(format!("bad AK {:?}", p[1])))?))).collect::<anyhow::Result<_>>()?,
        )),
        (None, true, Some(g)) => Ok(UndoScope::Group(ctx.tid(g)?)),
        _ => Err(usage("give exactly one scope: --thing T, --aspect T AK..., --group G")),
    }
}

fn servers(ctx: &mut Ctx<'_>, list: &[String]) -> anyhow::Result<Vec<osis::ServerAddr>> {
    list.iter().map(|s| Ok(ctx.arg_text(s)?.parse::<osis::ServerAddr>()?)).collect()
}

fn ty_of(key: &Key) -> Ty<'_> {
    key.schema().zip(key.ty()).map(|(s, t)| (&**s, t))
}

/// A value as text or JSON at a key's type (`--raw`: numbered).
fn show_value(ctx: &Ctx<'_>, v: &Value, ty: Ty<'_>) -> (String, J) {
    let ty = if ctx.g.raw { None } else { ty };
    (text::print(v, ty), json::value(v, ty))
}

fn truncate(s: String, width: usize) -> String {
    if width == 0 || s.chars().count() <= width { s } else { s.chars().take(width.saturating_sub(1)).collect::<String>() + "…" }
}

fn not_supported(what: &'static str) -> anyhow::Error {
    Error::Unsupported(what).into()
}

/// Runs one parsed command.
pub fn dispatch(cli: Cli, store: Option<StoreSel>, stdin: &mut dyn BufRead, out: &mut dyn std::io::Write, tty: bool) -> anyhow::Result<()> {
    let g = cli.g.clone();
    let sel = crate::store_sel(&g, store)?;
    // Commands that do not open a store.
    match &cli.cmd {
        Cmd::Serve { config, listen, data, key } => return serve(&g, config, listen, data, key, out),
        Cmd::Schema(SchemaCmd::Check { file }) => return schema_check(&g, file, out),
        Cmd::Schema(SchemaCmd::Gen { file, o }) => return schema_gen(file, o, out),
        Cmd::Schema(SchemaCmd::Add { file }) => return schema_reg(&sel, file, true),
        Cmd::Schema(SchemaCmd::Rm { file }) => return schema_reg(&sel, file, false),
        Cmd::Schema(SchemaCmd::Ls) => {
            let StoreSel::Dir(d) = &sel else { return Err(usage("schemas register with a store directory")) };
            let list = crate::registered(d)?;
            let lines: Vec<String> = list.iter().map(|p| p.display().to_string()).collect();
            let j = J::Arr(lines.iter().map(|l| J::str(l.clone())).collect());
            return if g.json { writeln!(out, "{}", j.text()).map_err(Into::into) } else { lines.iter().try_for_each(|l| writeln!(out, "{l}")).map_err(Into::into) };
        }
        _ => {}
    }
    let db = match &cli.cmd {
        Cmd::Init { .. } => crate::create(&sel, &g)?,
        Cmd::Restore { card, server } => {
            let cfg = crate::config(&sel, &g);
            let _ = server; // seed servers go in Config once the API takes them
            let card: osis::RecoveryCard = card.parse()?;
            let t = Ctx::timeout_flag(&g)?;
            match block_on(Osis::restore(cfg, &card), t) {
                Some(r) => r?,
                None => return Err(exit(6, "timed out")),
            }
        }
        Cmd::Pair(PairCmd::Join { offer, server }) => {
            let cfg = crate::config(&sel, &g);
            let _ = server;
            let offer: osis::PairOffer = offer.parse()?;
            match block_on(Osis::pair(cfg, &offer), Ctx::timeout_flag(&g)?) {
                Some(r) => r?,
                None => return Err(exit(6, "timed out")),
            }
        }
        _ => open(&sel, &g)?,
    };
    let mut ctx = Ctx::new(g, db, sel, out, stdin, tty)?;
    let r = run(&mut ctx, cli.cmd);
    ctx.db.settle();
    r
}

impl Ctx<'_> {
    fn timeout_flag(g: &crate::args::Global) -> anyhow::Result<Option<Duration>> {
        match &g.timeout {
            None => Ok(Some(Duration::from_secs(30))),
            Some(s) => Ok(Some(parse_dur(s)?).filter(|d| !d.is_zero())),
        }
    }
}

/// Runs one write command as its own commit; prints the commit id (and a created tid).
fn one_write(ctx: &mut Ctx<'_>, c: ScriptCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut w = db.write();
    let mut did = Did::default();
    write::apply(ctx, &mut w, &c, &mut did)?;
    let done = w.commit()?;
    let commit = done.map(|c| c.commit);
    let created = did.created.first().map(|(_, t)| *t);
    let mut lines = Vec::new();
    if let Some(t) = created {
        lines.push(t.to_uri());
    } else if let Some(c) = &commit {
        lines.push(commit_text(c));
    }
    let mut f = vec![("commit".to_string(), J::opt(commit.as_ref().map(|c| J::str(commit_text(c)))))];
    if let Some(t) = created {
        f.push(("tid".into(), J::tid(t)));
    }
    ctx.emit(&lines, J::Obj(f))
}

fn run(ctx: &mut Ctx<'_>, cmd: Cmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match cmd {
        Cmd::Init { server } | Cmd::Restore { server, .. } | Cmd::Pair(PairCmd::Join { server, .. }) => {
            for s in servers(ctx, &server)? {
                db.add_server(&s)?;
            }
            whoami(ctx)
        }
        Cmd::Whoami => whoami(ctx),
        Cmd::Pair(PairCmd::Offer) => {
            let o = db.pair_offer()?;
            ctx.emit(&[o.to_string()], J::obj([("offer", J::str(o.to_string()))]))
        }
        Cmd::Device(DeviceCmd::Ls) => {
            let ds = db.devices()?;
            ctx.emit(&ds.iter().map(|d| d.node.to_uri()).collect::<Vec<_>>(), J::Arr(ds.iter().map(|d| J::obj([("node", J::tid(d.node))])).collect()))
        }
        Cmd::Device(DeviceCmd::Rm { node, d }) => {
            let n = ctx.tid(&node)?;
            let d = demotion(&d, ctx)?;
            wait(ctx, db.remove_device(n, d))
        }
        Cmd::Server(ServerCmd::Ls) => {
            let s = db.servers()?;
            ctx.emit(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>(), J::Arr(s.iter().map(|s| J::str(s.to_string())).collect()))
        }
        Cmd::Server(ServerCmd::Add { addr }) => Ok(db.add_server(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Server(ServerCmd::Rm { addr }) => Ok(db.remove_server(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Serve { .. } | Cmd::Schema(_) => unreachable!("handled before opening"),
        Cmd::Create(a) => one_write(ctx, ScriptCmd::Create(a)),
        Cmd::Set(a) => one_write(ctx, ScriptCmd::Set(a)),
        Cmd::Replace(a) => one_write(ctx, ScriptCmd::Replace(a)),
        Cmd::Rm(a) => one_write(ctx, ScriptCmd::Rm(a)),
        Cmd::Op(a) => one_write(ctx, ScriptCmd::Op(a)),
        Cmd::Place { t, g } => one_write(ctx, ScriptCmd::Place { t, g }),
        Cmd::Unplace { t, g } => one_write(ctx, ScriptCmd::Unplace { t, g }),
        Cmd::Sub(s) => one_write(ctx, ScriptCmd::Sub(s)),
        Cmd::Delete { t } => one_write(ctx, ScriptCmd::Delete { t }),
        Cmd::Get { t, ak, path, stream, len } => get(ctx, &t, &ak, path.as_deref(), stream, len),
        Cmd::Edit { t, ak, path, base } => edit(ctx, &t, &ak, path.as_deref(), base),
        Cmd::Write => write_script(ctx),
        Cmd::Show { t, width } => show(ctx, &t, width),
        Cmd::Aspects { t } => {
            let a = db.aspects(ctx.tid(&t)?)?;
            ctx.emit(&a.iter().map(|a| a.as_str().to_string()).collect::<Vec<_>>(), J::Arr(a.iter().map(|a| J::str(a.as_str())).collect()))
        }
        Cmd::Ls { .. } => Err(not_supported("query (plans/api.md second half)")),
        Cmd::Backlinks { .. } => Err(not_supported("backlinks (plans/api.md second half)")),
        Cmd::Watch { t, ak, count } => watch(ctx, &t, ak.as_deref(), count),
        Cmd::Signal(SignalCmd::Send { t, kind, value, to }) => {
            let t = ctx.tid(&t)?;
            let k = osis::Ak::new(&kind).map_err(|_| usage(format!("bad signal kind {kind:?}")))?;
            let st = signal_type(ctx, &kind);
            let v = ctx.value(&value, st.as_ref().map(|(s, t)| (&**s, t)))?;
            let target = match to {
                Some(n) => Target::Node(ctx.tid(&n)?),
                None => Target::All,
            };
            Ok(db.send_signal(t, &k, &v, target)?)
        }
        Cmd::Signal(SignalCmd::Listen { t, kind, count }) => listen(ctx, &t, &kind, count),
        Cmd::History { scope: s, max, before } => history(ctx, &s, max, before),
        Cmd::Undo { scope: s } => undo(ctx, &s, false),
        Cmd::Redo { scope: s } => undo(ctx, &s, true),
        Cmd::UndoCommit { id } => {
            let c = db.undo_commit(parse_commit(&id)?)?;
            ctx.emit(&[commit_text(&c.commit)], J::obj([("commit", J::str(commit_text(&c.commit)))]))
        }
        Cmd::Groups { t } => {
            let gs = db.groups_of(ctx.tid(&t)?);
            ctx.emit(&gs.iter().map(Tid::to_uri).collect::<Vec<_>>(), J::Arr(gs.iter().map(|g| J::tid(*g)).collect()))
        }
        Cmd::Roster { t, watch: false, .. } => roster(ctx, &t),
        Cmd::Roster { t, watch: true, count } => {
            let t = ctx.tid(&t)?;
            let (raw, json_out) = (ctx.g.raw, ctx.g.json);
            let (tx, rx) = mpsc::channel::<String>();
            let _sub = db.watch_roster(t, move |_, r| {
                let l = if json_out {
                    roster_json(&r).text()
                } else {
                    roster_lines(&r, raw).join(", ")
                };
                let _ = tx.send(l);
            });
            let timeout = ctx.timeout_or(None)?;
            stream_lines(ctx, &rx, count, timeout)
        }
        Cmd::Role { t } => {
            let r = db.role_on(ctx.tid(&t)?);
            ctx.emit(&[r.map_or("none", role_text).to_string()], J::obj([("role", J::opt(r.map(|r| J::str(role_text(r)))))]))
        }
        Cmd::Grant { t, member, role, until, invite } => {
            let opts = EdgeOpts { until: until.as_deref().map(parse_ts).transpose()?.map(WallMs), invite: invite.as_deref().map(parse_role).transpose()? };
            Ok(db.grant(ctx.tid(&t)?, ctx.tid(&member)?, parse_role(&role)?, opts)?)
        }
        Cmd::Edge { t, member, role, until, invite } => {
            let (t, m) = (ctx.tid(&t)?, ctx.tid(&member)?);
            let role = match role {
                Some(r) => parse_role(&r)?,
                None => db.roster(t).get(&m).map(|e| e.role).ok_or_else(|| exit(3, "no such edge"))?,
            };
            let opts = EdgeOpts { until: until.as_deref().map(parse_ts).transpose()?.map(WallMs), invite: invite.as_deref().map(parse_role).transpose()? };
            Ok(db.change_edge(t, m, role, opts)?)
        }
        Cmd::Demote { t, member, role, d } => {
            let to = if role == "remove" { Lower::Remove } else { Lower::To(parse_role(&role)?) };
            let (t, m, d) = (ctx.tid(&t)?, ctx.tid(&member)?, demotion(&d, ctx)?);
            wait(ctx, db.demote(t, m, to, d))
        }
        Cmd::Leave { t } => Ok(db.leave(ctx.tid(&t)?)?),
        Cmd::Link(LinkCmd::Make { t, role, until, single_use }) => {
            let l = db.make_link(ctx.tid(&t)?, parse_role(&role)?, LinkOpts { until: until.as_deref().map(parse_ts).transpose()?.map(WallMs), single_use })?;
            ctx.emit(&[l.to_string()], J::obj([("link", J::str(l.to_string()))]))
        }
        Cmd::Link(LinkCmd::Redeem { link }) => {
            let l: osis::ShareLink = ctx.arg_text(&link)?.parse()?;
            let t = wait(ctx, db.redeem(&l))?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        Cmd::Link(LinkCmd::Ls { .. }) => Err(not_supported("links (plans/api.md second half)")),
        Cmd::Link(LinkCmd::Revoke { .. }) => Err(not_supported("revoke_link (plans/api.md second half)")),
        Cmd::Card(CardCmd::Show) => {
            let c = db.contact_card()?;
            ctx.emit(&[c.to_string()], J::obj([("card", J::str(c.to_string()))]))
        }
        Cmd::Card(CardCmd::Import { card }) => {
            let c: osis::ContactCard = ctx.arg_text(&card)?.parse()?;
            let a = db.import_contact(&c)?;
            ctx.emit(&[a.to_uri()], J::obj([("actor", J::tid(a))]))
        }
        Cmd::Move { t, owner, place } => {
            let p = write::place(ctx, &place)?;
            let n = db.move_thing(ctx.tid(&t)?, ctx.tid(&owner)?, p)?;
            ctx.emit(&[n.to_uri()], J::obj([("tid", J::tid(n))]))
        }
        Cmd::Same { a, b } => {
            let s = db.same_thing(ctx.tid(&a)?, ctx.tid(&b)?);
            ctx.emit(&[s.to_string()], J::obj([("same", J::Bool(s))]))?;
            if s { Ok(()) } else { Err(exit(3, "")) }
        }
        Cmd::Status { watch } => {
            if watch {
                return Err(not_supported("watch_status (plans/api.md second half)"));
            }
            status(ctx)
        }
        Cmd::Sync { group } => {
            let s = match group {
                Some(g) => SyncScope::Group(ctx.tid(&g)?),
                None => SyncScope::All,
            };
            db.sync_now()?;
            let t = ctx.timeout()?.unwrap_or(FOREVER);
            wait(ctx, db.wait_synced(s, t))
        }
        Cmd::Wait { group } => {
            let s = match group {
                Some(g) => SyncScope::Group(ctx.tid(&g)?),
                None => SyncScope::All,
            };
            let t = ctx.timeout()?.unwrap_or(FOREVER);
            wait(ctx, db.wait_synced(s, t))
        }
        Cmd::Group(GroupCmd::Sync { g, server }) => {
            let g = ctx.tid(&g)?;
            let s = if server.is_empty() { db.servers()? } else { servers(ctx, &server)? };
            Ok(db.sync(g, &s)?)
        }
        Cmd::Group(GroupCmd::Unsync { g }) => Ok(db.unsync(ctx.tid(&g)?)?),
        Cmd::Group(GroupCmd::Policy { .. }) => Err(not_supported("sync_policy (plans/api.md second half)")),
        Cmd::Bundle(_) => Err(not_supported("bundles (plans/api.md second half)")),
        Cmd::Inspect(i) => inspect(ctx, i),
        Cmd::Diag { follow } => {
            diag(ctx, if follow { ctx.timeout_or(None)? } else { Some(Duration::ZERO) })
        }
        Cmd::Daemon => {
            let t = ctx.timeout_or(None)?;
            diag(ctx, t)
        }
    }
}

fn whoami(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let store = match &ctx.sel {
        StoreSel::Dir(d) => d.display().to_string(),
        StoreSel::Memory(_) => "(memory)".into(),
    };
    let servers = db.servers().ok();
    let sw = format!("osis {}", env!("CARGO_PKG_VERSION"));
    let mut lines = vec![format!("me\t{}", db.me().to_uri()), format!("node\t{}", db.node().to_uri()), format!("home\t{}", db.home().to_uri())];
    if let Some(s) = &servers {
        lines.extend(s.iter().map(|s| format!("server\t{s}")));
    }
    lines.push(format!("store\t{store}"));
    lines.push(format!("software\t{sw}"));
    let j = J::obj([
        ("me", J::tid(db.me())),
        ("node", J::tid(db.node())),
        ("home", J::tid(db.home())),
        ("servers", J::opt(servers.map(|s| J::Arr(s.iter().map(|s| J::str(s.to_string())).collect())))),
        ("store", J::str(store)),
        ("software", J::str(sw)),
    ]);
    ctx.emit(&lines, j)
}

fn get(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, stream: bool, len: bool) -> anyhow::Result<()> {
    if stream {
        return Err(not_supported("stream (plans/api.md second half)"));
    }
    if len {
        return Err(not_supported("len (plans/api.md second half)"));
    }
    let t = ctx.tid(t)?;
    let key = ctx.key(ak)?;
    let db = ctx.db.clone();
    let (v, pty) = match path {
        None | Some("") => (db.get(t, key.clone())?, key.ty().cloned()),
        Some(p) => {
            let p = write::path(ctx, t, &key, p, false)?;
            let pty = key.schema().and_then(|s| text::type_at_path(s, key.ty()?, &p.0));
            (db.at(t, key.clone()).path(p).get_value()?, pty)
        }
    };
    let Some(v) = v else { return Err(exit(3, "")) };
    let (s, j) = show_value(ctx, &v, key.schema().zip(pty.as_ref()).map(|(s, t)| (&**s, t)));
    ctx.emit(&[s], j)
}

fn edit(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, base: Option<String>) -> anyhow::Result<()> {
    if path.is_some_and(|p| !p.is_empty()) {
        return Err(usage("edit takes the whole aspect (the API edits aspects; use op or set for a path)"));
    }
    let t = ctx.tid(t)?;
    let key = ctx.key(ak)?;
    let db = ctx.db.clone();
    let ty = ty_of(&key);
    let (base, new) = match base {
        Some(b) => {
            let base = ctx.value(&b, ty)?;
            let new = ctx.value("-", ty)?;
            (base, new)
        }
        None if ctx.tty => {
            let cur = db.get(t, key.clone())?.ok_or_else(|| exit(3, "absent: nothing to edit (use set)"))?;
            let shown = text::print(&cur, if ctx.g.raw { None } else { ty });
            let f = edit_file(&format!("{shown}\n"))?;
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let st = std::process::Command::new(&editor).arg(&f).status().map_err(|e| anyhow!("{editor}: {e}"))?;
            let edited = std::fs::read_to_string(&f)?;
            let _ = std::fs::remove_file(&f);
            if !st.success() {
                return Err(anyhow!("{editor} failed"));
            }
            let al = |w: &str| ctx.alias(w);
            let new = text::parse(edited.trim(), ty, &al).map_err(|e| usage(format!("bad value: {e}")))?;
            (cur, new)
        }
        None => return Err(usage("off a terminal, edit needs --base VALUE and the new value on stdin")),
    };
    let done = db.write_with(|w| w.at(t, key.clone()).edit(&base, &new))?;
    let commit = done.map(|c| commit_text(&c.commit));
    ctx.emit(&commit.iter().cloned().collect::<Vec<_>>(), J::obj([("commit", J::opt(commit.map(J::str)))]))
}

/// A new temp file (`create_new`, random name, owner-only) holding `text`.
fn edit_file(text: &str) -> anyhow::Result<std::path::PathBuf> {
    use std::hash::{BuildHasher, Hasher};
    for _ in 0..16 {
        let r = std::collections::hash_map::RandomState::new().build_hasher().finish();
        let f = std::env::temp_dir().join(format!("osis-edit-{r:016x}.txt"));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&f) {
            Ok(mut h) => {
                std::io::Write::write_all(&mut h, text.as_bytes())?;
                return Ok(f);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(anyhow!("{}: {e}", f.display())),
        }
    }
    Err(anyhow!("cannot create a temp file"))
}

fn write_script(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let mut src = String::new();
    ctx.stdin.read_to_string(&mut src)?;
    let lines = write::script(&src)?;
    let db = ctx.db.clone();
    let mut w = db.write();
    let mut did = Did::default();
    for (n, c) in &lines {
        write::apply(ctx, &mut w, c, &mut did).with_context(|| format!("line {n}"))?;
    }
    let done = w.commit()?;
    let commit = done.map(|c| commit_text(&c.commit));
    let mut text = vec![commit.clone().unwrap_or_else(|| "-".into())];
    let mut vars = Vec::new();
    for (name, t) in &did.created {
        if !name.is_empty() {
            text.push(format!("{name}\t{}", t.to_uri()));
            vars.push((name.clone(), J::tid(*t)));
        }
    }
    ctx.emit(&text, J::obj([("commit", J::opt(commit.map(J::str))), ("tids", J::Obj(vars))]))
}

fn show(ctx: &mut Ctx<'_>, t: &str, width: usize) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let t = ctx.tid(t)?;
    let aks = db.aspects(t)?;
    if aks.is_empty() && !db.knows(t) {
        return Err(Error::UnknownThing { tid: t }.into());
    }
    let mut lines = vec![format!("tid\t{}", t.to_uri())];
    let mut fields = Vec::new();
    for ak in &aks {
        let key = ctx.key(ak.as_str())?;
        let (s, j) = match db.get(t, key.clone()) {
            Ok(Some(v)) => show_value(ctx, &v, ty_of(&key)),
            Ok(None) => ("(absent)".to_string(), J::Null),
            Err(e) => (format!("(error: {e})"), J::obj([("error", J::str(e.to_string()))])),
        };
        lines.push(format!("{}\t{}", ak.as_str(), truncate(s, width)));
        fields.push((ak.as_str().to_string(), j));
    }
    let groups = db.groups_of(t);
    let role = db.role_on(t);
    lines.push(format!("groups\t{}", groups.iter().map(Tid::to_uri).collect::<Vec<_>>().join(" ")));
    lines.push(format!("role\t{}", role.map_or("none", role_text)));
    let j = J::obj([
        ("tid", J::tid(t)),
        ("aspects", J::Obj(fields)),
        ("groups", J::Arr(groups.iter().map(|g| J::tid(*g)).collect())),
        ("role", J::opt(role.map(|r| J::str(role_text(r))))),
    ]);
    ctx.emit(&lines, j)
}

fn change_line(ctx: &Ctx<'_>, c: &Change<Value>) -> String {
    let key = ctx.key(c.ak.as_str()).ok();
    let ty = key.as_ref().and_then(ty_of);
    let (src, info) = match &c.source {
        Source::Initial => ("initial", None),
        Source::Local(i) => ("local", Some(i)),
        Source::Remote(i) => ("remote", Some(i)),
        Source::Derived(_) => ("derived", None),
    };
    let (vt, vj) = match &c.value {
        Ok(Some(v)) => show_value(ctx, v, ty),
        Ok(None) => ("(absent)".into(), J::Null),
        Err(e) => (format!("(error: {e})"), J::obj([("error", J::str(e.to_string()))])),
    };
    if ctx.g.json {
        J::obj([
            ("tid", J::tid(c.tid)),
            ("ak", J::str(c.ak.as_str())),
            ("source", J::str(src)),
            ("commit", J::opt(info.map(|i| J::str(commit_text(&i.id))))),
            ("actor", J::opt(info.map(|i| J::tid(i.actor)))),
            ("node", J::opt(info.map(|i| J::tid(i.node)))),
            ("ts", J::opt(info.map(|i| J::int(ts_of(i.ts))))),
            ("value", vj),
        ])
        .text()
    } else {
        let d = |o: Option<String>| o.unwrap_or_else(|| "-".into());
        format!(
            "{src} {} {} {} {} {vt}",
            d(info.map(|i| i.actor.to_uri())),
            d(info.map(|i| i.node.to_uri())),
            d(info.map(|i| ts_text(ctx.g.raw, ts_of(i.ts)))),
            c.ak.as_str()
        )
    }
}

/// Prints lines from `rx` until `count` lines, the timeout, or the senders are gone.
fn stream_lines(ctx: &mut Ctx<'_>, rx: &mpsc::Receiver<String>, count: Option<usize>, timeout: Option<Duration>) -> anyhow::Result<()> {
    let end = deadline(timeout);
    let mut n = 0;
    while count.is_none_or(|c| n < c) {
        let r = match end {
            None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            Some(e) => rx.recv_timeout(e.saturating_duration_since(Instant::now())),
        };
        match r {
            Ok(l) => {
                ctx.line(&l)?;
                ctx.out.flush()?;
                n += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) if count.is_some() => return Err(exit(6, format!("timed out after {n} line(s)"))),
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

fn watch(ctx: &mut Ctx<'_>, t: &str, ak: Option<&str>, count: Option<usize>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let t = ctx.tid(t)?;
    let (tx, rx) = mpsc::channel::<Change<Value>>();
    let _sub = match ak {
        Some(ak) => {
            let key = Key::new(osis::Ak::new(ak).map_err(|_| usage(format!("bad AK {ak:?}")))?, None);
            db.at(t, key).on_change(move |_, c| {
                let _ = tx.send(c);
            })?
        }
        None => db.watch_thing(t, move |_, c| {
            let _ = tx.send(c);
        }),
    };
    let end = deadline(ctx.timeout_or(None)?);
    let mut n = 0;
    while count.is_none_or(|c| n < c) {
        let r = match end {
            None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            Some(e) => rx.recv_timeout(e.saturating_duration_since(Instant::now())),
        };
        match r {
            Ok(c) => {
                let l = change_line(ctx, &c);
                ctx.line(&l)?;
                ctx.out.flush()?;
                n += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) if count.is_some() => return Err(exit(6, format!("timed out after {n} change(s)"))),
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// The schema type of a signal kind, if a registered schema declares it.
fn signal_type(ctx: &Ctx<'_>, kind: &str) -> Option<(Arc<Schema>, osis_schema::Type)> {
    if ctx.g.raw {
        return None;
    }
    ctx.schemas.iter().find_map(|s| s.signals.get(kind).map(|d| (s.clone(), d.ty.clone())))
}

fn listen(ctx: &mut Ctx<'_>, t: &str, kind: &str, count: Option<usize>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let t = ctx.tid(t)?;
    let k = osis::Ak::new(kind).map_err(|_| usage(format!("bad signal kind {kind:?}")))?;
    let st = signal_type(ctx, kind);
    let (raw, json_out) = (ctx.g.raw, ctx.g.json);
    let (tx, rx) = mpsc::channel::<String>();
    let _sub = db.on_signal(t, k, move |_, e| {
        let ty = st.as_ref().map(|(s, t)| (&**s, t));
        let (vt, vj) = match &e.value {
            Ok(v) => (text::print(v, if raw { None } else { ty }), json::value(v, if raw { None } else { ty })),
            Err(e) => (format!("(error: {e})"), J::Null),
        };
        let l = if json_out {
            J::obj([("actor", J::tid(e.actor)), ("node", J::tid(e.node)), ("ts", J::int(e.ts.0)), ("value", vj)]).text()
        } else {
            format!("{} {} {} {vt}", e.actor.to_uri(), e.node.to_uri(), ts_text(raw, e.ts.0))
        };
        let _ = tx.send(l);
    });
    let timeout = ctx.timeout_or(None)?;
    stream_lines(ctx, &rx, count, timeout)
}

fn state_text(s: EntryState) -> &'static str {
    match s {
        EntryState::Undoable => "undoable",
        EntryState::Undone => "undone",
        EntryState::Dropped(osis::DropReason::Compacted) => "dropped-compacted",
        EntryState::Dropped(osis::DropReason::Superseded) => "dropped-superseded",
    }
}

fn history(ctx: &mut Ctx<'_>, s: &Scope, max: usize, before: Option<String>) -> anyhow::Result<()> {
    let sc = scope(ctx, s)?;
    let before = before.as_deref().map(parse_ts).transpose()?.and_then(|ms| Ts::make(WallMs(ms), 0));
    let hs = ctx.db.history(&sc, HistoryQuery { limit: max, before })?;
    let raw = ctx.g.raw;
    let lines = hs
        .iter()
        .map(|h| {
            let aks: Vec<String> = h.aspects.iter().map(|(t, a)| format!("{}{}", t.to_uri(), a.as_str())).collect();
            format!("{} {} {} {} {} {}", commit_text(&h.commit), ts_text(raw, ts_of(h.ts)), h.actor.to_uri(), h.node.to_uri(), state_text(h.state), aks.join(","))
        })
        .collect::<Vec<_>>();
    let j = J::Arr(
        hs.iter()
            .map(|h| {
                J::obj([
                    ("commit", J::str(commit_text(&h.commit))),
                    ("ts", J::int(ts_of(h.ts))),
                    ("actor", J::tid(h.actor)),
                    ("node", J::tid(h.node)),
                    ("state", J::str(state_text(h.state))),
                    ("undoes", J::opt(h.undoes.as_ref().map(|c| J::str(commit_text(c))))),
                    ("aspects", J::Arr(h.aspects.iter().map(|(t, a)| J::Arr(vec![J::tid(*t), J::str(a.as_str())])).collect())),
                ])
            })
            .collect(),
    );
    ctx.emit(&lines, j)
}

fn undo(ctx: &mut Ctx<'_>, s: &Scope, redo: bool) -> anyhow::Result<()> {
    let sc = scope(ctx, s)?;
    let r = if redo { ctx.db.redo(&sc)? } else { ctx.db.undo(&sc)? };
    match r {
        Some(c) => ctx.emit(&[commit_text(&c.commit)], J::obj([("commit", J::str(commit_text(&c.commit)))])),
        None => Err(exit(3, if redo { "nothing to redo" } else { "nothing to undo" })),
    }
}

fn roster_lines(r: &osis::Roster, raw: bool) -> Vec<String> {
    r.iter()
        .map(|(m, e)| {
            let until = e.until.map_or("-".into(), |u| ts_text(raw, u.0));
            format!("{} {} {} {}", m.to_uri(), role_text(e.role), until, e.invite.map_or("-", role_text))
        })
        .collect()
}

fn roster_json(r: &osis::Roster) -> J {
    J::Arr(
        r.iter()
            .map(|(m, e)| J::obj([("actor", J::tid(*m)), ("role", J::str(role_text(e.role))), ("until", J::opt(e.until.map(|u| J::int(u.0)))), ("invite", J::opt(e.invite.map(|r| J::str(role_text(r)))))]))
            .collect(),
    )
}

fn roster(ctx: &mut Ctx<'_>, t: &str) -> anyhow::Result<()> {
    let r = ctx.db.roster(ctx.tid(t)?);
    let lines = roster_lines(&r, ctx.g.raw);
    ctx.emit(&lines, roster_json(&r))
}

fn status(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let s = ctx.db.status()?;
    let raw = ctx.g.raw;
    let lines = s
        .groups
        .iter()
        .map(|(g, x)| format!("{} {:?} {} {}", g.to_uri(), x.state, x.pending_uploads, x.last_sync.map_or("-".into(), |t| ts_text(raw, t.0))))
        .collect::<Vec<_>>();
    let j = J::Arr(
        s.groups
            .iter()
            .map(|(g, x)| J::obj([("group", J::tid(*g)), ("state", J::str(format!("{:?}", x.state))), ("pending_uploads", J::int(x.pending_uploads as u64)), ("last_sync", J::opt(x.last_sync.map(|t| J::int(t.0))))]))
            .collect(),
    );
    ctx.emit(&lines, j)
}

fn diag(ctx: &mut Ctx<'_>, timeout: Option<Duration>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let json_out = ctx.g.json;
    let (tx, rx) = mpsc::channel::<String>();
    let _sub = db.on_diagnostic(move |_, d| {
        let l = if json_out {
            J::obj([
                ("kind", J::str(format!("{:?}", d.kind))),
                ("tids", J::Arr(d.tids.iter().map(|t| J::tid(*t)).collect())),
                ("commit", J::opt(d.commit.as_ref().map(|c| J::str(commit_text(c))))),
                ("peer", J::opt(d.peer.map(J::tid))),
                ("detail", J::str(d.detail.clone())),
            ])
            .text()
        } else {
            let tids: Vec<String> = d.tids.iter().map(Tid::to_uri).collect();
            format!("{:?} {} {}", d.kind, tids.join(","), d.detail)
        };
        let _ = tx.send(l);
    });
    db.settle();
    if timeout == Some(Duration::ZERO) {
        while let Ok(l) = rx.try_recv() {
            ctx.line(&l)?;
        }
        return Ok(());
    }
    stream_lines(ctx, &rx, None, timeout)
}

fn inspect(ctx: &mut Ctx<'_>, i: InspectCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut lines = Vec::new();
    match i {
        InspectCmd::Thing { t } => {
            let t = ctx.tid(&t)?;
            let t = db.read(|r| r.resolve(t));
            lines.push(format!("tid {} known={} role={}", t.to_uri(), db.knows(t), db.role_on(t).map_or("none", role_text)));
            let aks = db.aspects(t)?;
            for ak in aks {
                let (changes, size, frag) = db.engine(|e| {
                    let ch = e.changes(&[(t, ak.clone())]);
                    let size = e.get(&t, &ak).ok().flatten().map(|v| osis_schema::osis_core::encode(&v).len());
                    let frag = e.state(&t, &ak).ok().flatten().map(|f| format!("{f:?}"));
                    (ch, size, frag)
                });
                lines.push(format!("aspect {} commits={} stored_size={}", ak.as_str(), changes.len(), size.map_or("-".into(), |s| s.to_string())));
                for (id, node, actor, ts, undoes) in changes {
                    lines.push(format!("  commit {} ts={} actor={} node={}{}", commit_text(&id), ts_of(ts), actor.to_uri(), node.to_uri(), undoes.map_or(String::new(), |u| format!(" undoes={}", commit_text(&u)))));
                }
                if let Some(f) = frag {
                    lines.push(format!("  state {f}"));
                }
            }
            for g in db.groups_of(t) {
                lines.push(format!("group {}", g.to_uri()));
            }
            for (m, e) in db.roster(t) {
                lines.push(format!("member {} {:?}", m.to_uri(), e));
            }
        }
        InspectCmd::Group { g } => {
            let g = ctx.tid(&g)?;
            let all = db.engine(|e| e.all_aspects())?;
            let mut things: Vec<Tid> = all.into_iter().map(|(t, _)| t).collect();
            things.dedup();
            for t in things {
                if db.groups_of(t).contains(&g) {
                    lines.push(format!("item {}", t.to_uri()));
                }
            }
            for (id, reason) in db.engine(|e| e.pending()) {
                lines.push(format!("pending {} {reason:?}", commit_text(&id)));
            }
        }
        InspectCmd::Actor { a } => {
            let a = ctx.tid(&a)?;
            let ep = db.engine(|e| e.epochs(&a));
            lines.push(format!("actor {} epochs {ep:?}", a.to_uri()));
            for (m, e) in db.roster(a) {
                lines.push(format!("member {} {:?}", m.to_uri(), e));
            }
        }
        InspectCmd::Commit { id } => {
            let id = parse_commit(&id)?;
            let h = db.engine(|e| e.header(&id)).ok_or_else(|| exit(3, "commit not held"))?;
            lines.push(format!("{h:#?}"));
            for (p, reason) in db.engine(|e| e.pending()) {
                if p == id {
                    lines.push(format!("pending {reason:?}"));
                }
            }
        }
    }
    let j = J::Arr(lines.iter().map(|l| J::str(l.clone())).collect());
    ctx.emit(&lines, j)
}

fn serve(g: &crate::args::Global, config: &Option<std::path::PathBuf>, listen: &Option<String>, data: &Option<std::path::PathBuf>, key: &Option<std::path::PathBuf>, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let mut cfg = match config {
        Some(f) => {
            let text = std::fs::read_to_string(f).map_err(|e| usage(format!("{}: {e}", f.display())))?;
            osis_server::config::parse(&text).map_err(|e| usage(format!("{}: {e}", f.display())))?
        }
        None => {
            let data = data.clone().unwrap_or_else(|| osis_server::config::DEFAULT_DATA.into());
            osis_server::Config { listen: "quic://127.0.0.1:0".into(), key: data.join("server.key"), data, peers: Vec::new(), policy: osis_server::Policy::default() }
        }
    };
    if let Some(l) = listen {
        cfg.listen = l.clone();
    }
    if let Some(d) = data {
        cfg.data = d.clone();
    }
    if let Some(k) = key {
        cfg.key = k.clone();
    }
    if config.is_none() && key.is_none() {
        cfg.key = cfg.data.join("server.key");
    }
    std::fs::create_dir_all(&cfg.data).map_err(|e| anyhow!("{}: {e}", cfg.data.display()))?;
    let quiet = g.quiet;
    let log: osis_server::Log = Arc::new(move |m: &str| {
        if !quiet {
            eprintln!("osis serve: {m}");
        }
    });
    let out = Mutex::new(out);
    osis_server::serve::run(cfg, log, |a| {
        let mut o = out.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(o, "{a}");
        let _ = o.flush();
    })
    .map_err(|e| anyhow!(e))
}

fn schema_check(g: &crate::args::Global, file: &std::path::Path, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let src = std::fs::read_to_string(file).map_err(|e| usage(format!("{}: {e}", file.display())))?;
    let name = file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let s = osis_schema::parse(&name, &src).map_err(|e| exit(7, e.to_string()))?;
    let lock = file.with_file_name(format!("{name}.lock"));
    let status = match std::fs::read_to_string(&lock) {
        Ok(t) => {
            let l = osis_schema::Lock::parse(&t).map_err(|e| exit(7, format!("{}: {e}", lock.display())))?;
            match osis_schema::check_lock(&s, &l, &[]).map_err(|e| exit(7, e.to_string()))? {
                osis_schema::LockStatus::Published => "published",
                osis_schema::LockStatus::Unpublished => "unpublished",
            }
        }
        Err(_) => "no lock",
    };
    let line = format!("ok revision {} {status}", s.revision);
    if g.json {
        writeln!(out, "{}", J::obj([("revision", J::int(s.revision)), ("status", J::str(status))]).text())?;
    } else {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn schema_gen(file: &std::path::Path, dir: &std::path::Path, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let g = osis_schema::generate_file(file).map_err(|e| exit(7, e.to_string()))?;
    let stem = file.file_stem().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| "schema".into());
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{stem}.rs"));
    std::fs::write(&path, &g.code).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    for w in &g.warnings {
        eprintln!("warning: {w}");
    }
    writeln!(out, "{}", path.display())?;
    Ok(())
}

fn schema_reg(sel: &StoreSel, file: &std::path::Path, add: bool) -> anyhow::Result<()> {
    let StoreSel::Dir(d) = sel else { return Err(usage("schemas register with a store directory")) };
    if !d.join("db.redb").exists() {
        return Err(exit(8, format!("no store at {} (run osis init)", d.display())));
    }
    let abs = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    let mut list = crate::registered(d)?;
    if add {
        let src = std::fs::read_to_string(&abs).map_err(|e| usage(format!("{}: {e}", abs.display())))?;
        let name = abs.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        osis_schema::parse(&name, &src).map_err(|e| exit(7, e.to_string()))?;
        if !list.contains(&abs) {
            list.push(abs);
        }
    } else {
        let n = list.len();
        list.retain(|p| *p != abs && p != file);
        if list.len() == n {
            return Err(exit(3, format!("{} is not registered", file.display())));
        }
    }
    crate::save_registered(d, &list)
}

#[cfg(test)]
mod tests {
    // notes/cli.md Design: `edit`'s temp file is new (`create_new`), randomly named, owner-only.
    #[test]
    fn edit_file_is_new_and_private_notes_cli() {
        let a = super::edit_file("x").unwrap();
        let b = super::edit_file("y").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "x");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&a).unwrap().permissions()) & 0o077, 0);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    // plans/cli.md §2: `--timeout 0` (no deadline) and huge timeouts do not overflow.
    #[test]
    fn deadline_never_overflows_plan_cli_2() {
        assert_eq!(super::deadline(None), None);
        assert_eq!(super::deadline(Some(std::time::Duration::MAX)), None);
        assert!(super::deadline(Some(super::FOREVER)).is_some());
    }
}
