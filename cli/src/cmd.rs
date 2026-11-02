//! Command bodies (notes/cli.md Command table): each a thin wrapper over one API call, plus printing.
//! Tests: spec: none (client surface).

use crate::args::*;
use crate::json::{self, J};
use crate::text::{self, Ty};
use crate::write::{self, Did};
use crate::{Ctx, StoreSel, exit, key_ty, open, opt_ts, parse_ak, ty_in, usage};
use anyhow::{Context as _, anyhow};
use osis::internals::Internals as _;
use osis::{
    AspectKey, Change, CommitId, CommitKind, CommitQuery, Demotion, EdgeOpts, Error, Key, LinkOpts, Lower, Osis, Role, Schema, Source, SyncScope, SyncState, Tid, Ts,
    Value, WaitForSync,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io::BufRead;
use std::sync::mpsc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

pub fn role_text(r: Role) -> &'static str {
    match r {
        Role::Read => "read",
        Role::Write => "write",
        Role::Admin => "admin",
    }
}

fn edge_opts(until: &Option<String>, invite: &Option<String>) -> anyhow::Result<EdgeOpts> {
    Ok(EdgeOpts { until: opt_ts(until)?, invite: invite.as_deref().map(parse_role).transpose()? })
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
    osis_schema::osis_base::hex::encode(&c.0)
}

/// A change: its commit id, or `ephemeral:<session prefix>:<n>` for an ephemeral batch.
pub fn change_text(c: &osis::ChangeId) -> String {
    match c {
        osis::ChangeId::Commit(c) => commit_text(c),
        osis::ChangeId::Ephemeral(e) => format!("ephemeral:{}:{}", osis_schema::osis_base::hex::encode(&e.session[..8]), e.n),
    }
}

/// Prints a commit id (nothing when nothing changed).
fn emit_commit(ctx: &mut Ctx<'_>, c: Option<CommitId>) -> anyhow::Result<()> {
    let c = c.map(|c| commit_text(&c));
    ctx.emit(&c.iter().cloned().collect::<Vec<_>>(), J::obj([("commit", J::opt(c.map(J::str)))]))
}

fn parse_commit(s: &str) -> anyhow::Result<CommitId> {
    osis_schema::osis_base::hex::decode(s).and_then(|b| <[u8; 32]>::try_from(b).ok()).map(CommitId).ok_or_else(|| usage(format!("not a commit id (64 hex digits): {s}")))
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

/// `wait_synced` on its own deadline `t` (a label a host does not admit fails it `Unsynced`
/// then, saying which host).
fn wait_sync(ctx: &Ctx<'_>, s: SyncScope, t: Duration) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match block_on(db.wait_synced(s, t), None) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(not_admitted(&db, e)),
        None => Err(exit(6, "timed out")),
    }
}

/// `e` with the hosts that do not admit the groups it names (state `Refused`), if any.
fn not_admitted(db: &Osis, e: Error) -> anyhow::Error {
    let (Error::Unsynced { groups }, Ok(st)) = (&e, db.status()) else { return e.into() };
    let hint: Vec<String> = groups
        .iter()
        .filter_map(|g| st.groups.get(g).filter(|x| x.state == SyncState::Refused).map(|x| (g, x)))
        .flat_map(|(g, x)| x.not_admitted.iter().map(move |h| format!("host {h} does not admit group {} (yet)", g.to_uri())))
        .collect();
    if hint.is_empty() { e.into() } else { anyhow::Error::from(e).context(hint.join("; ")) }
}

fn demotion(d: &DemoteFlags, ctx: &Ctx<'_>) -> anyhow::Result<Demotion> {
    let sync = match d.sync.as_deref() {
        None | Some("required") => WaitForSync::Required,
        Some("try") => WaitForSync::Try(ctx.timeout()?.unwrap_or(crate::DEFAULT_WAIT)),
        Some("skip") => WaitForSync::Skip,
        Some(o) => return Err(usage(format!("--sync: required, try or skip (got {o:?})"))),
    };
    let backdate = opt_ts(&d.backdate)?;
    Ok(Demotion { sync, backdate, repudiate: d.repudiate })
}

fn scope(ctx: &Ctx<'_>, s: &Scope) -> anyhow::Result<osis::Scope> {
    opt_scope(ctx, s)?.ok_or_else(|| usage("give exactly one scope: --thing T, --aspect T AK..., --group G"))
}

/// At most one scope.
fn opt_scope(ctx: &Ctx<'_>, s: &Scope) -> anyhow::Result<Option<osis::Scope>> {
    match (&s.thing, s.aspect.is_empty(), &s.group) {
        (None, true, None) => Ok(None),
        (Some(t), true, None) => Ok(Some(osis::Scope::Thing(ctx.tid(t)?))),
        (None, false, None) => Ok(Some(osis::Scope::Aspects(
            s.aspect.chunks(2).map(|p| Ok((ctx.tid(&p[0])?, parse_ak(&p[1], "AK")?))).collect::<anyhow::Result<_>>()?,
        ))),
        (None, true, Some(g)) => Ok(Some(osis::Scope::Group(ctx.tid(g)?))),
        _ => Err(usage("give at most one scope: --thing T, --aspect T AK..., --group G")),
    }
}

fn hosts(ctx: &mut Ctx<'_>, list: &[String]) -> anyhow::Result<Vec<osis::HostAddr>> {
    list.iter().map(|s| Ok(ctx.arg_text(s)?.parse::<osis::HostAddr>()?)).collect()
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
    Error::Unsupported(what.into()).into()
}

/// Commands that wait for or talk to other nodes: the store opens with sync running. Others stay
/// local (their writes go out with the next networked command, `sync` or `serve`).
fn needs_net(c: &Cmd) -> bool {
    matches!(
        c,
        Cmd::Pair(_)
            | Cmd::Device(DeviceCmd::Rm { .. })
            | Cmd::Demote { .. }
            | Cmd::Link(LinkCmd::Redeem { .. } | LinkCmd::Revoke { .. })
            | Cmd::Card(CardCmd::Import { .. })
            | Cmd::Status { .. }
            | Cmd::Sync { .. }
            | Cmd::Wait { .. }
            | Cmd::Serve { .. }
            | Cmd::Group(GroupCmd::Source { .. })
            | Cmd::Clients(ClientsCmd::RotateKey)
            | Cmd::Watch { .. }
            | Cmd::Roster { watch: true, .. }
            | Cmd::Diag { follow: true }
    ) || delivers(c)
}

/// Commands whose API call hands other nodes something the engine keeps only in memory until
/// sent (inbox grants, a new label's first commits):
/// they run with sync on and wait until it is at the hosts before the process exits.
fn delivers(c: &Cmd) -> bool {
    matches!(c, Cmd::Grant { .. } | Cmd::Edge { .. } | Cmd::Leave { .. } | Cmd::ShareInto { .. } | Cmd::RemoveEdgeOf { .. } | Cmd::Link(LinkCmd::Make { .. }) | Cmd::Card(CardCmd::Show) | Cmd::Group(GroupCmd::Sync { .. }))
}

/// The thing a sharing command shares (a `delivers` command its holders fetch).
fn shared(c: &Cmd) -> Option<String> {
    match c {
        Cmd::Grant { t, .. } | Cmd::Edge { t, .. } | Cmd::ShareInto { t, .. } | Cmd::Link(LinkCmd::Make { t, .. }) => Some(t.clone()),
        _ => None,
    }
}

/// Sends what a `delivers` command queued (within `--timeout`): `wait_synced` on the shared
/// thing's groups (a hostless one fails: its holders can never fetch it), then on `All`.
fn deliver(ctx: &mut Ctx<'_>, shared: Option<String>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    db.sync_now()?;
    let t = ctx.timeout()?.unwrap_or(FOREVER);
    let end = std::time::Instant::now() + t;
    let mut scopes = vec![SyncScope::All];
    if let Some(x) = shared {
        scopes.insert(0, SyncScope::Group(ctx.tid(&x)?));
    }
    for s in scopes {
        let left = end.saturating_duration_since(std::time::Instant::now());
        wait_sync(ctx, s, left).map_err(|e| exit(6, format!("done locally, not yet at the hosts: {e:#}")))?;
    }
    Ok(())
}

/// Runs one parsed command.
pub fn dispatch(cli: Cli, store: Option<StoreSel>, stdin: &mut dyn BufRead, out: &mut dyn std::io::Write, err: &mut (dyn std::io::Write + Send), tty: bool) -> anyhow::Result<()> {
    let g = cli.g.clone();
    let sel = crate::store_sel(&g, store)?;
    // Commands that do not open a store.
    match &cli.cmd {
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
    let seed = |list: &[String]| list.iter().map(|s| s.parse::<osis::HostAddr>().map_err(anyhow::Error::from)).collect::<anyhow::Result<Vec<_>>>();
    let mut card = None;
    let db = match &cli.cmd {
        Cmd::Init { host } => {
            let (db, c) = crate::create(&sel, &g, seed(host)?)?;
            card = c;
            db
        }
        Cmd::Restore { card, host } => {
            let mut cfg = crate::config(&sel, &g, true);
            cfg.hosts = seed(host)?;
            let card: osis::RecoveryCard = crate::arg_text(&mut *stdin, card)?.parse()?;
            let t = crate::timeout_of(&g, Some(crate::DEFAULT_WAIT))?;
            match block_on(Osis::restore(cfg, &card), t) {
                Some(r) => r?,
                None => return Err(exit(6, "timed out")),
            }
        }
        Cmd::Pair(PairCmd::Join { offer, host }) => {
            // the app carries two messages: print the request, read the reply
            let mut cfg = crate::config(&sel, &g, true);
            cfg.hosts = seed(host)?;
            let offer: osis::PairOffer = offer.parse()?;
            let join = Osis::pair(cfg, &offer)?;
            writeln!(out, "{}", join.request())?;
            out.flush()?;
            let mut line = String::new();
            stdin.read_line(&mut line)?;
            join.finish(&line.parse()?)?
        }
        c => open(&sel, &g, needs_net(c), !matches!(c, Cmd::Inspect(_) | Cmd::Serve { .. }))?,
    };
    if let Some(c) = card {
        writeln!(out, "{c}")?;
    }
    // -v on a command that syncs: diagnostics to stderr while it runs, best effort (not for
    // those that already print them on stdout)
    let streams = matches!(cli.cmd, Cmd::Serve { .. } | Cmd::Diag { follow: true });
    let verbose = (g.verbose > 0 && needs_net(&cli.cmd) && !streams).then(|| Verbose::start(&db, g.json));
    std::thread::scope(|s| {
        let verbose = verbose.map(|(v, rx)| {
            s.spawn(move || {
                for l in rx {
                    let _ = writeln!(err, "{l}").and_then(|()| err.flush());
                }
            });
            v
        });
        let mut ctx = Ctx::new(g, db, sel, out, stdin, tty)?;
        let (flush, shared) = (delivers(&cli.cmd), shared(&cli.cmd));
        let mut r = run(&mut ctx, cli.cmd);
        if r.is_ok() && flush && !ctx.db.hosts().is_empty() {
            r = deliver(&mut ctx, shared);
        }
        ctx.db.settle();
        drop(verbose);
        let db = ctx.db.clone();
        drop(ctx);
        let closed = db.close();
        r.and(closed.map_err(Into::into))
    })
}

/// Runs one write command as its own commit; prints the commit id (and a created tid).
fn one_write(ctx: &mut Ctx<'_>, c: ScriptCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut w = db.write();
    let mut did = Did::default();
    write::apply(ctx, &mut w, &c, &mut did)?;
    let done = w.commit()?;
    let commit = done.and_then(|c| c.id.commit());
    let created = did.created.first().map(|(_, t)| *t);
    // a new thing with no durable data lives in this process's memory only
    if created.is_some_and(|t| db.created(t).is_some_and(|c| c.commit.is_none())) {
        return Err(usage("a new thing with no durable data is gone when this command exits: give AK V (or use `write`)"));
    }
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
        Cmd::Init { host } | Cmd::Restore { host, .. } | Cmd::Pair(PairCmd::Join { host, .. }) => {
            for s in hosts(ctx, &host)? {
                db.add_host(&s)?;
            }
            whoami(ctx)
        }
        Cmd::Whoami => whoami(ctx),
        Cmd::Pair(PairCmd::Offer) => {
            // print the offer, read the new device's request, print the reply and its node
            let o = db.pair_offer()?;
            ctx.emit(&[o.to_string()], J::obj([("offer", J::str(o.to_string()))]))?;
            let mut line = String::new();
            ctx.stdin.read_line(&mut line)?;
            let (node, reply) = db.pair_accept(&line.parse()?)?;
            ctx.emit(&[reply.to_string(), node.to_uri()], J::obj([("reply", J::str(reply.to_string())), ("node", J::tid(node))]))
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
        Cmd::Hosts(HostsCmd::Ls) => {
            let s = db.hosts();
            ctx.emit(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>(), J::Arr(s.iter().map(|s| J::str(s.to_string())).collect()))
        }
        Cmd::Hosts(HostsCmd::Add { addr }) => Ok(db.add_host(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Hosts(HostsCmd::Rm { addr }) => Ok(db.remove_host(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Hosting(HostingCmd::Show) => hosting_show(ctx),
        Cmd::Hosting(HostingCmd::Set(f)) => set_hosting(ctx, f),
        Cmd::Hosting(HostingCmd::Off) => Ok(db.set_hosting(None)?),
        Cmd::Clients(c) => clients(ctx, &c),
        Cmd::Serve { host, client_listen } => serve(ctx, host, &client_listen),
        Cmd::Schema(_) => unreachable!("handled before opening"),
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
        Cmd::Ls { .. } => Err(not_supported("query (issues/api-deferred.md)")),
        Cmd::Backlinks { .. } => Err(not_supported("backlinks (issues/api-deferred.md)")),
        Cmd::Watch { t, ak, count } => watch(ctx, &t, ak.as_deref(), count),
        Cmd::Commits { scope: s, actor, kind, reverts, reverted_by, in_effect, since, until, after, max, next } => {
            let mut q = CommitQuery { scope: opt_scope(ctx, &s)?, in_effect, limit: max, ..CommitQuery::default() };
            q.actors = actor.iter().map(|a| ctx.tid(a)).collect::<anyhow::Result<_>>()?;
            q.kinds = kind.iter().map(|k| kind_of(k)).collect::<anyhow::Result<_>>()?;
            q.reverts = reverts.as_deref().map(parse_commit).transpose()?.map(osis::ChangeId::Commit);
            q.reverted_by = reverted_by.as_deref().map(parse_commit).transpose()?.map(osis::ChangeId::Commit);
            q.after = after.as_deref().map(parse_commit).transpose()?.map(osis::ChangeId::Commit);
            q.since = opt_ts(&since)?.and_then(|ms| Ts::make(ms, 0));
            q.until = opt_ts(&until)?.and_then(|ms| Ts::make(ms, 0));
            q.next = match next.as_deref() {
                None => None,
                Some("undo") => Some(osis::Next::Undo),
                Some("redo") => Some(osis::Next::Redo),
                Some(x) => return Err(usage(format!("--next takes undo or redo, not {x:?}"))),
            };
            commits(ctx, &q)
        }
        Cmd::Undo { scope: s } => undo(ctx, &s, false),
        Cmd::Redo { scope: s } => undo(ctx, &s, true),
        Cmd::Revert { id } => {
            let c = db.revert(osis::ChangeId::Commit(parse_commit(&id)?))?;
            emit_commit(ctx, c.id.commit())
        }
        Cmd::Groups { t } => {
            let gs = db.groups_of(ctx.tid(&t)?);
            let rel = [("item", &gs.item_of), ("subgroup", &gs.subgroup_of), ("within", &gs.within)];
            let lines = rel.iter().flat_map(|(n, v)| v.iter().map(move |g| format!("{n}\t{}", g.to_uri()))).collect::<Vec<_>>();
            let arr = |v: &[Tid]| J::Arr(v.iter().map(|g| J::tid(*g)).collect());
            ctx.emit(&lines, J::obj([("item_of", arr(&gs.item_of)), ("subgroup_of", arr(&gs.subgroup_of)), ("within", arr(&gs.within))]))
        }
        Cmd::Roster { t, watch: false, .. } => roster(ctx, &t),
        Cmd::Roster { t, watch: true, count } => {
            let t = ctx.tid(&t)?;
            let (raw, json_out) = (ctx.g.raw, ctx.g.json);
            let (tx, rx) = mpsc::channel::<(String, bool)>();
            // the first call is the roster now: printed, not counted
            let mut initial = true;
            let _sub = db.watch_roster(t, move |_, r| {
                let l = if json_out {
                    roster_json(&r).text()
                } else {
                    roster_lines(&r, raw).join(", ")
                };
                let _ = tx.send((l, !std::mem::take(&mut initial)));
            });
            let timeout = ctx.timeout_or(None)?;
            stream(ctx, &rx, count, timeout, "change", false, |_, (l, counts)| (l, counts))
        }
        Cmd::Via { t, holder } => {
            let p = db.holder_path(ctx.tid(&t)?, ctx.tid(&holder)?);
            if p.is_empty() {
                return Err(exit(3, "no such holder"));
            }
            ctx.emit(&p.iter().map(|(a, b)| format!("{} {}", a.to_uri(), b.to_uri())).collect::<Vec<_>>(), J::Arr(p.iter().map(|(a, b)| J::Arr(vec![J::tid(*a), J::tid(*b)])).collect()))
        }
        Cmd::Now => {
            let n = db.now().0;
            ctx.emit(&[ts_text(ctx.g.raw, n)], J::obj([("now", J::int(n))]))
        }
        Cmd::Role { t } => {
            let r = db.role_on(ctx.tid(&t)?);
            ctx.emit(&[r.map_or("none", role_text).to_string()], J::obj([("role", J::opt(r.map(|r| J::str(role_text(r)))))]))
        }
        Cmd::Grant { t, holder, role, until, invite } => Ok(db.grant(ctx.tid(&t)?, ctx.tid(&holder)?, parse_role(&role)?, edge_opts(&until, &invite)?)?),
        Cmd::Edge { t, holder, role, until, invite } => {
            let (t, m) = (ctx.tid(&t)?, ctx.tid(&holder)?);
            let role = match role {
                Some(r) => parse_role(&r)?,
                None => db.roster(t).get(&m).map(|e| e.role).ok_or_else(|| exit(3, "no such edge"))?,
            };
            Ok(db.change_edge(t, m, role, edge_opts(&until, &invite)?)?)
        }
        Cmd::Demote { t, holder, role, d } => {
            let to = if role == "remove" { Lower::Remove } else { Lower::To(parse_role(&role)?) };
            let (t, m, d) = (ctx.tid(&t)?, ctx.tid(&holder)?, demotion(&d, ctx)?);
            wait(ctx, db.demote(t, m, to, d))
        }
        Cmd::Leave { t } => Ok(db.leave(ctx.tid(&t)?)?),
        Cmd::ShareInto { t, g, role, subgroup, place_anyway } => {
            let s = db.share_into(ctx.tid(&t)?, ctx.tid(&g)?, parse_role(&role)?, osis::ShareOpts { subgroup, place_anyway })?;
            ctx.emit(&[share_text(s)], J::str(share_text(s)))
        }
        Cmd::RemoveEdgeOf { g, t } => Ok(db.remove_edge_of(ctx.tid(&g)?, ctx.tid(&t)?)?),
        Cmd::Reach { t } => {
            let r = db.reach(ctx.tid(&t)?);
            let lines: Vec<String> = r.iter().map(|x| format!("{} {} {}", x.group.to_uri(), if x.placed { "placed" } else { "unplaced" }, share_text(x.share))).collect();
            let j = J::Arr(r.iter().map(|x| J::obj([("group", J::tid(x.group)), ("placed", J::Bool(x.placed)), ("share", J::str(share_text(x.share)))])).collect());
            ctx.emit(&lines, j)
        }
        Cmd::Link(LinkCmd::Make { t, role, until, single_use }) => {
            let l = db.make_link(ctx.tid(&t)?, parse_role(&role)?, LinkOpts { until: opt_ts(&until)?, single_use, direct: false })?;
            ctx.emit(&[l.to_string()], J::obj([("link", J::str(l.to_string()))]))
        }
        Cmd::Link(LinkCmd::Redeem { link }) => {
            let l: osis::ShareLink = ctx.arg_text(&link)?.parse()?;
            let t = wait(ctx, db.redeem(&l))?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        Cmd::Link(LinkCmd::Ls { t }) => {
            let ls = db.links(ctx.tid(&t)?);
            let lines: Vec<String> = ls.iter().map(|l| format!("{} {} {}", l.id.to_uri(), role_text(l.role), if l.single_use { "single-use" } else { "-" })).collect();
            let j = J::Arr(ls.iter().map(|l| J::obj([("id", J::tid(l.id)), ("role", J::str(role_text(l.role).to_string())), ("single_use", J::Bool(l.single_use))])).collect());
            ctx.emit(&lines, j)
        }
        Cmd::Link(LinkCmd::Revoke { id, joiner, d }) => {
            let id = ctx.tid(&id)?;
            let d = demotion(&d, ctx)?;
            match joiner {
                Some(j) => {
                    let j = ctx.tid(&j)?;
                    wait(ctx, db.revoke_joiner(id, j, d))
                }
                None => wait(ctx, db.revoke_link(id, d)),
            }
        }
        Cmd::Card(CardCmd::Show) => {
            let c = db.contact_card()?;
            ctx.emit(&[c.to_string()], J::obj([("card", J::str(c.to_string()))]))
        }
        Cmd::Card(CardCmd::Profile { person }) => {
            let p = match person {
                Some(a) => db.profile_of(ctx.tid(&a)?)?,
                None => Some(db.profile()?),
            };
            match p {
                Some(p) => ctx.emit(&[p.to_uri()], J::obj([("profile", J::tid(p))])),
                None => Err(exit(3, "no profile known for that person")),
            }
        }
        Cmd::Card(CardCmd::Import { card }) => {
            let c: osis::ContactCard = ctx.arg_text(&card)?.parse()?;
            let a = wait(ctx, db.import_contact(&c))?;
            ctx.emit(&[a.to_uri()], J::obj([("actor", J::tid(a))]))
        }
        Cmd::Move { t, owner, place } => {
            let p = write::place(ctx, &place)?;
            let n = db.move_thing(ctx.tid(&t)?, ctx.tid(&owner)?, &p)?;
            ctx.emit(&[n.to_uri()], J::obj([("tid", J::tid(n))]))
        }
        Cmd::Ownerless { admin } => {
            let t = db.create_ownerless(ctx.tid(&admin)?)?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        Cmd::Same { a, b } => {
            let s = db.same_thing(ctx.tid(&a)?, ctx.tid(&b)?);
            ctx.emit(&[s.to_string()], J::obj([("same", J::Bool(s))]))?;
            if s { Ok(()) } else { Err(exit(3, "")) }
        }
        Cmd::Status { watch: false } => status(ctx),
        Cmd::Status { watch: true } => {
            let (tx, rx) = mpsc::channel::<String>();
            let _sub = db.watch_status(move |_, st| {
                let l = st.groups.iter().map(|(g, x)| format!("{} {:?}", g.to_uri(), x.state)).chain(st.split.iter().map(|t| format!("{} split", t.to_uri()))).collect::<Vec<_>>().join(", ");
                let _ = tx.send(format!("connected {} {l}", st.connected));
            });
            let timeout = ctx.timeout_or(None)?;
            stream_lines(ctx, &rx, None, timeout)
        }
        // `wait_synced` asks the hosts to sync first: `sync` and `wait` are one call
        Cmd::Sync { group } | Cmd::Wait { group } => {
            let s = match group {
                Some(g) => SyncScope::Group(ctx.tid(&g)?),
                None => SyncScope::All,
            };
            let t = ctx.timeout()?.unwrap_or(FOREVER);
            wait_sync(ctx, s, t)
        }
        Cmd::Group(GroupCmd::Sync { g, host }) => {
            let g = ctx.tid(&g)?;
            let s = if host.is_empty() { db.hosts() } else { hosts(ctx, &host)? };
            Ok(db.sync(g, &s)?)
        }
        Cmd::Group(GroupCmd::Unsync { g }) => Ok(db.unsync(ctx.tid(&g)?)?),
        Cmd::Group(GroupCmd::Source { g, to }) => {
            let g = ctx.tid(&g)?;
            let to = if to == "local" { osis::GroupSource::Local } else { osis::GroupSource::Remote(to.parse()?) };
            match block_on(db.group_source(g, to), ctx.timeout()?) {
                Some(r) => Ok(r?),
                None => Err(exit(6, "timed out: where it was, unless the move finished")),
            }
        }
        Cmd::Group(GroupCmd::Policy { .. }) => Err(not_supported("sync_policy (issues/api-deferred.md)")),
        Cmd::Bundle(BundleCmd::Export { groups }) => {
            let gs = groups.iter().map(|g| ctx.tid(g)).collect::<anyhow::Result<Vec<_>>>()?;
            db.export_bundle(&gs, &mut *ctx.out)?;
            Ok(())
        }
        Cmd::Bundle(BundleCmd::Import) => Ok(db.import_bundle(&mut *ctx.stdin)?),
        Cmd::Inspect(i) => inspect(ctx, i),
        Cmd::Diag { follow } => {
            diag(ctx, if follow { ctx.timeout_or(None)? } else { Some(Duration::ZERO) }, false)
        }
    }
}

fn whoami(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let store = match &ctx.sel {
        StoreSel::Dir(d) => d.display().to_string(),
        StoreSel::Memory(_) => "(memory)".into(),
    };
    let hosts = db.hosts();
    let sw = format!("osis {}", env!("CARGO_PKG_VERSION"));
    let mut lines = vec![format!("me\t{}", db.me().to_uri()), format!("node\t{}", db.node().to_uri()), format!("home\t{}", db.home().to_uri())];
    lines.extend(hosts.iter().map(|s| format!("host\t{s}")));
    lines.push(format!("store\t{store}"));
    lines.push(format!("software\t{sw}"));
    let j = J::obj([
        ("me", J::tid(db.me())),
        ("node", J::tid(db.node())),
        ("home", J::tid(db.home())),
        ("hosts", J::Arr(hosts.iter().map(|s| J::str(s.to_string())).collect())),
        ("store", J::str(store)),
        ("software", J::str(sw)),
    ]);
    ctx.emit(&lines, j)
}

fn get(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, stream: bool, len: bool) -> anyhow::Result<()> {
    let t = ctx.tid(t)?;
    let key = ctx.key(ak)?;
    let db = ctx.db.clone();
    if stream || len {
        let at = db.at(t, key.clone());
        let s = match path {
            None | Some("") => at.stream()?,
            Some(p) => {
                let p = write::path(ctx, t, &key, p, false)?;
                at.path(p).stream()?
            }
        };
        let Some(mut s) = s else { return Err(exit(3, "")) };
        if len {
            let n = s.len();
            return ctx.emit(&[n.to_string()], J::obj([("len", J::int(n))]));
        }
        std::io::copy(&mut s, &mut *ctx.out)?;
        return Ok(());
    }
    let (v, pty) = match path {
        None | Some("") => (db.get(t, key.clone())?, key.ty().cloned()),
        Some(p) => {
            let p = write::path(ctx, t, &key, p, false)?;
            let pty = key.schema().and_then(|s| text::type_at_path(s, key.ty()?, &p.0));
            (db.at(t, key.clone()).path(p).get_value()?, pty)
        }
    };
    let Some(v) = v else { return Err(exit(3, "")) };
    let (s, j) = show_value(ctx, &v, ty_in(&key, pty.as_ref()));
    ctx.emit(&[s], j)
}

fn edit(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, base: Option<String>) -> anyhow::Result<()> {
    if path.is_some_and(|p| !p.is_empty()) {
        return Err(usage("edit takes the whole aspect (the API edits aspects; use op or set for a path)"));
    }
    let t = ctx.tid(t)?;
    let key = ctx.key(ak)?;
    let db = ctx.db.clone();
    let ty = key_ty(&key);
    let (base, new) = match base {
        Some(b) => {
            let base = ctx.value(&b, ty)?;
            let new = ctx.value("-", ty)?;
            (base, new)
        }
        None if ctx.tty => {
            let cur = db.get(t, key.clone())?.ok_or_else(|| exit(3, "absent: nothing to edit (use set)"))?;
            let shown = text::print(&cur, if ctx.g.raw { None } else { ty });
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let edited = edit_in(&edit_dir(), &editor, &format!("{shown}\n"))?;
            let al = |w: &str| ctx.alias(w);
            let new = text::parse(edited.trim(), ty, &al).map_err(|e| usage(format!("bad value: {e}")))?;
            (cur, new)
        }
        None => return Err(usage("off a terminal, edit needs --base VALUE and the new value on stdin")),
    };
    let mut w = db.write();
    w.at(t, key.clone()).edit(&base, &new)?;
    let done = w.commit()?;
    emit_commit(ctx, done.and_then(|c| c.id.commit()))
}

/// Where `edit`'s temp file goes: the per-user runtime directory (owner-only, usually in
/// memory) when there is one, else the temp directory.
fn edit_dir() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()).map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

/// Runs `editor` on a temp file holding `text`; returns what it saved. The file (plaintext of
/// the value) is removed whatever happens.
fn edit_in(dir: &std::path::Path, editor: &str, text: &str) -> anyhow::Result<String> {
    let f = edit_file(dir, text)?;
    let st = std::process::Command::new(editor).arg(&f).status();
    let edited = std::fs::read_to_string(&f);
    let _ = std::fs::remove_file(&f);
    if !st.map_err(|e| anyhow!("{editor}: {e}"))?.success() {
        return Err(anyhow!("{editor} failed"));
    }
    Ok(edited?)
}

/// A new temp file (`create_new`, random name, owner-only) holding `text`.
fn edit_file(dir: &std::path::Path, text: &str) -> anyhow::Result<std::path::PathBuf> {
    use std::hash::{BuildHasher, Hasher};
    for _ in 0..16 {
        let r = std::collections::hash_map::RandomState::new().build_hasher().finish();
        let f = dir.join(format!("osis-edit-{r:016x}.txt"));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&f) {
            Ok(mut h) => {
                if let Err(e) = std::io::Write::write_all(&mut h, text.as_bytes()) {
                    let _ = std::fs::remove_file(&f);
                    return Err(e.into());
                }
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
    let commit = done.map(|c| change_text(&c.id));
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
    let known = db.knows(t);
    let created = db.created(t);
    if aks.is_empty() && !known && created.is_none() {
        return Err(Error::UnknownThing { tid: t }.into());
    }
    let mut lines = vec![format!("tid\t{}", t.to_uri())];
    let mut fields = Vec::new();
    for ak in &aks {
        let key = ctx.key(ak.as_str())?;
        let (s, j) = match db.get(t, key.clone()) {
            Ok(Some(v)) => show_value(ctx, &v, key_ty(&key)),
            // a value its schema does not read (a `Mismatch` diagnostic): shown untyped
            Ok(None) => match db.get(t, ak.clone()) {
                Ok(Some(v)) => show_value(ctx, &v, None),
                _ => ("(absent)".to_string(), J::Null),
            },
            Err(e) => (format!("(error: {e})"), J::obj([("error", J::str(e.to_string()))])),
        };
        lines.push(format!("{}\t{}", ak.as_str(), truncate(s, width)));
        fields.push((ak.as_str().to_string(), j));
    }
    let groups = db.groups_of(t);
    let role = db.role_on(t);
    let owner = db.owner_of(t);
    let uris = |v: &[Tid]| v.iter().map(Tid::to_uri).collect::<Vec<_>>().join(" ");
    lines.push(format!("state\t{}", if known { "present" } else { "deleted" }));
    lines.push(format!("groups\t{}", uris(&groups.within)));
    lines.push(format!("subgroup_of\t{}", uris(&groups.subgroup_of)));
    lines.push(format!("role\t{}", role.map_or("none", role_text)));
    lines.push(format!("owner\t{}", owner.map_or("none".into(), |o| o.to_uri())));
    let changed = db.changed(t);
    let stamp = |c: Option<osis::Stamp>| c.map_or("unknown".into(), |c| format!("{} by {}", ts_text(ctx.g.raw, ts_of(c.ts)), c.node.to_uri()));
    lines.push(format!("created\t{}", stamp(created)));
    lines.push(format!("changed\t{}", stamp(changed)));
    let j = J::obj([
        ("tid", J::tid(t)),
        ("aspects", J::Obj(fields)),
        ("deleted", J::Bool(!known)),
        ("groups", J::Arr(groups.within.iter().map(|g| J::tid(*g)).collect())),
        ("subgroup_of", J::Arr(groups.subgroup_of.iter().map(|g| J::tid(*g)).collect())),
        ("role", J::opt(role.map(|r| J::str(role_text(r))))),
        ("owner", J::opt(owner.map(J::tid))),
        ("created", J::opt(created.map(stamp_json))),
        ("changed", J::opt(changed.map(stamp_json))),
    ]);
    ctx.emit(&lines, j)
}

fn stamp_json(c: osis::Stamp) -> J {
    J::obj([("commit", J::opt(c.commit.map(|x| J::str(commit_text(&x))))), ("node", J::tid(c.node)), ("ts", J::int(ts_of(c.ts)))])
}

fn change_line(ctx: &Ctx<'_>, c: &Change<Value>) -> String {
    let key = ctx.key(c.ak.as_str()).ok();
    let ty = key.as_ref().and_then(key_ty);
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
            ("commit", J::opt(info.map(|i| J::str(change_text(&i.id))))),
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
    stream(ctx, rx, count, timeout, "line", false, |_, l| (l, true))
}

/// `stream_lines` over items printed by `line`, which also says whether the item counts
/// toward `count` (an initial value does not). `best_effort`: write errors are ignored (the
/// lines are diagnostics, not what the command is run for).
fn stream<T>(ctx: &mut Ctx<'_>, rx: &mpsc::Receiver<T>, count: Option<usize>, timeout: Option<Duration>, what: &str, best_effort: bool, line: impl Fn(&Ctx<'_>, T) -> (String, bool)) -> anyhow::Result<()> {
    let end = deadline(timeout);
    let mut n = 0;
    while count.is_none_or(|c| n < c) {
        let r = match end {
            None => rx.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            Some(e) => rx.recv_timeout(e.saturating_duration_since(Instant::now())),
        };
        match r {
            Ok(x) => {
                let (l, counts) = line(ctx, x);
                let w = ctx.line(&l).and_then(|()| Ok(ctx.out.flush()?));
                if !best_effort {
                    w?;
                }
                n += usize::from(counts);
            }
            Err(mpsc::RecvTimeoutError::Timeout) if count.is_some() => return Err(exit(6, format!("timed out after {n} {what}(s)"))),
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
            let key = Key::new(parse_ak(ak, "AK")?, None);
            db.at(t, key).on_change(move |_, c| {
                let _ = tx.send(c);
            })?
        }
        None => db.watch_thing(t, move |_, c| {
            let _ = tx.send(c);
        }),
    };
    let timeout = ctx.timeout_or(None)?;
    stream(ctx, &rx, count, timeout, "change", false, |ctx, c| (change_line(ctx, &c), !matches!(c.source, Source::Initial)))
}

const KINDS: [(&str, CommitKind); 6] =
    [("change", CommitKind::Change), ("revert", CommitKind::Revert), ("role", CommitKind::Role), ("snapshot", CommitKind::Snapshot), ("import", CommitKind::Import), ("ephemeral", CommitKind::Ephemeral)];

fn kind_of(s: &str) -> anyhow::Result<CommitKind> {
    KINDS.iter().find(|k| k.0 == s).map(|k| k.1).ok_or_else(|| usage(format!("unknown commit kind {s:?}: change, revert, role, snapshot or import")))
}

fn kind_text(k: CommitKind) -> &'static str {
    KINDS.iter().find(|x| x.1 == k).map_or("?", |x| x.0)
}

/// One line per commit: id, ts, actor, node, kind, in-effect or reverted, flags, aspects.
fn commits(ctx: &mut Ctx<'_>, q: &CommitQuery) -> anyhow::Result<()> {
    let cs = ctx.db.commits(q)?;
    let raw = ctx.g.raw;
    let lines = cs
        .iter()
        .map(|c| {
            let aks: Vec<String> = c.aspects.iter().map(|(t, a)| format!("{}{}", t.to_uri(), a.as_str())).collect();
            let i = &c.commit;
            let mut l = format!("{} {} {} {} {} {}", change_text(&i.id), ts_text(raw, ts_of(i.ts)), i.actor.to_uri(), i.node.to_uri(), kind_text(c.kind), if c.in_effect { "in-effect" } else { "reverted" });
            if let Some(r) = &c.reverts {
                l += &format!(" reverts={}", change_text(r));
            }
            if c.dropped {
                l += " dropped";
            }
            l + " " + &aks.join(",")
        })
        .collect::<Vec<_>>();
    let j = J::Arr(
        cs.iter()
            .map(|c| {
                J::obj([
                    ("commit", J::str(change_text(&c.commit.id))),
                    ("ts", J::int(ts_of(c.commit.ts))),
                    ("actor", J::tid(c.commit.actor)),
                    ("node", J::tid(c.commit.node)),
                    ("kind", J::str(kind_text(c.kind))),
                    ("in_effect", J::Bool(c.in_effect)),
                    ("reverts", J::opt(c.reverts.as_ref().map(|r| J::str(change_text(r))))),
                    ("reverted_by", J::Arr(c.reverted_by.iter().map(|r| J::str(change_text(r))).collect())),
                    ("dropped", J::Bool(c.dropped)),
                    ("aspects", J::Arr(c.aspects.iter().map(|(t, a)| J::Arr(vec![J::tid(*t), J::str(a.as_str())])).collect())),
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
        Some(c) => emit_commit(ctx, c.id.commit()),
        None => Err(exit(3, if redo { "nothing to redo" } else { "nothing to undo" })),
    }
}

fn share_text(s: osis::Share) -> String {
    match s {
        osis::Share::Tied(r) => format!("tied {}", role_text(r)),
        osis::Share::Untied(r) => format!("untied {}", role_text(r)),
        osis::Share::Excluded => "excluded".into(),
    }
}

fn roster_lines(r: &osis::Roster, raw: bool) -> Vec<String> {
    r.iter()
        .map(|(m, e)| {
            let until = e.until.map_or("-".into(), |u| ts_text(raw, u.0));
            format!("{} {} {} {}{}", m.to_uri(), role_text(e.role), until, e.invite.map_or("-", role_text), if e.tied { " tied" } else { "" })
        })
        .collect()
}

fn roster_json(r: &osis::Roster) -> J {
    J::Arr(
        r.iter()
            .map(|(m, e)| J::obj([("actor", J::tid(*m)), ("role", J::str(role_text(e.role))), ("until", J::opt(e.until.map(|u| J::int(u.0)))), ("invite", J::opt(e.invite.map(|r| J::str(role_text(r))))), ("tied", J::Bool(e.tied))]))
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
    let lines = status_lines(&s, ctx.g.raw);
    ctx.emit(&lines, status_json(&s))
}

fn status_lines(s: &osis::Status, raw: bool) -> Vec<String> {
    let groups = s.groups.iter().map(|(g, x)| format!("{} {:?} {} {}", g.to_uri(), x.state, x.last_sync.map_or("-".into(), |t| ts_text(raw, t.0)), if x.labels.is_empty() { "-".into() } else { x.labels.iter().map(|l| osis_schema::osis_base::hex::encode(&l.0)).collect::<Vec<_>>().join(",") }));
    // writes on these are refused until a group moves (Osis::group_source)
    groups.chain(s.split.iter().map(|t| format!("{} split: writes refused", t.to_uri()))).collect()
}

fn status_json(s: &osis::Status) -> J {
    let groups = s.groups.iter().map(|(g, x)| J::obj([("group", J::tid(*g)), ("state", J::str(format!("{:?}", x.state))), ("last_sync", J::opt(x.last_sync.map(|t| J::int(t.0)))), ("labels", J::Arr(x.labels.iter().map(|l| J::str(osis_schema::osis_base::hex::encode(&l.0))).collect()))]));
    J::obj([("groups", J::Arr(groups.collect())), ("split", J::Arr(s.split.iter().map(|t| J::tid(*t)).collect()))])
}

/// One diagnostic as `diag` prints it (text or a JSON line).
fn diag_line(d: &osis::Diagnostic, json: bool) -> String {
    if json {
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
    }
}

/// Prints diagnostics until `timeout` (`Some(0)`: those so far). `best_effort` (`serve`): a
/// failed write (a closed stdout) is ignored, the command goes on.
fn diag(ctx: &mut Ctx<'_>, timeout: Option<Duration>, best_effort: bool) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let json_out = ctx.g.json;
    let (tx, rx) = mpsc::channel::<String>();
    let _sub = db.on_diagnostic(move |_, d| {
        let _ = tx.send(diag_line(&d, json_out));
    });
    db.settle();
    if timeout == Some(Duration::ZERO) {
        while let Ok(l) = rx.try_recv() {
            ctx.line(&l)?;
        }
        return Ok(());
    }
    stream(ctx, &rx, None, timeout, "line", best_effort, |_, l| (l, true))
}

/// Copies diagnostics to `err` while it lives (`-v` on a command that syncs): best effort.
struct Verbose {
    tx: Arc<std::sync::Mutex<Option<mpsc::Sender<String>>>>,
    _sub: osis::Subscription,
}

impl Verbose {
    /// Subscribes; the lines go to the receiver, drained by the caller's thread.
    fn start(db: &Osis, json: bool) -> (Verbose, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let t = tx.clone();
        let sub = db.on_diagnostic(move |_, d| {
            if let Some(tx) = t.lock().ok().as_ref().and_then(|g| g.as_ref()) {
                let _ = tx.send(diag_line(&d, json));
            }
        });
        (Verbose { tx, _sub: sub }, rx)
    }
}

impl Drop for Verbose {
    /// Ends the receiver's stream (the subscription may outlive this in the dispatcher).
    fn drop(&mut self) {
        if let Ok(mut g) = self.tx.lock() {
            g.take();
        }
    }
}

fn inspect(ctx: &mut Ctx<'_>, i: InspectCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut lines = Vec::new();
    match i {
        InspectCmd::Thing { t } => {
            let t = ctx.tid(&t)?;
            let t = db.read(|r| r.resolve(t))?;
            lines.push(format!("tid {} known={} role={}", t.to_uri(), db.knows(t), db.role_on(t).map_or("none", role_text)));
            let aks = db.aspects(t)?;
            for ak in aks {
                let (changes, size, frag) = db.engine(|e| {
                    let ch = e.held_commits(Some(&[(t, ak.clone())]));
                    let size = e.get(&t, &ak).ok().flatten().map(|v| osis_schema::osis_base::encode(&v).len());
                    let frag = e.state(&t, &ak).ok().flatten().map(|f| format!("{f:?}"));
                    (ch, size, frag)
                });
                lines.push(format!("aspect {} commits={} stored_size={}", ak.as_str(), changes.len(), size.map_or("-".into(), |s| s.to_string())));
                for c in changes {
                    let h = &c.header;
                    lines.push(format!("  commit {} kind={:?} ts={} actor={} node={}{}", commit_text(&c.id), h.kind, ts_of(h.ts), h.actor.to_uri(), h.author.to_uri(), h.undoes.map_or(String::new(), |u| format!(" undoes={}", commit_text(&u)))));
                }
                if let Some(f) = frag {
                    lines.push(format!("  state {f}"));
                }
            }
            for g in db.groups_of(t).within {
                lines.push(format!("group {}", g.to_uri()));
            }
            for (m, e) in db.roster(t) {
                lines.push(format!("holder {} {:?}", m.to_uri(), e));
            }
        }
        InspectCmd::Group { g } => {
            let g = ctx.tid(&g)?;
            let all = db.engine(|e| e.all_aspects())?;
            let mut things: Vec<Tid> = all.into_iter().map(|(t, _)| t).collect();
            things.dedup();
            for t in things {
                if db.groups_of(t).within.contains(&g) {
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
                lines.push(format!("holder {} {:?}", m.to_uri(), e));
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

/// How long `serve` waits for its host to listen. Listening is local (milliseconds); at 0 a
/// host never prints its address, at infinity a stuck listen hangs the command silently.
const HOST_START_WAIT: Duration = Duration::from_secs(30);

/// What `serve` listens on when hosting with no listen URL (osis's default port, spec/sync.md §10).
const DEFAULT_LISTEN: &str = "quic://0.0.0.0:4040";

fn serve(ctx: &mut Ctx<'_>, host: HostFlags, client_listen: &[String]) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    // other invocations on this store become its clients (notes/cli.md Design)
    let _sock = crate::listen(&ctx.sel, &db)?;
    if host.any() {
        set_hosting(ctx, host)?;
    }
    if let Some(mut h) = db.hosting() {
        if h.listen.is_empty() {
            h.listen = vec![DEFAULT_LISTEN.into()];
            db.set_hosting(Some(h))?;
        }
        let until = std::time::Instant::now() + HOST_START_WAIT;
        let a = loop {
            if let Some(a) = db.host_address().map_err(|e| exit(6, format!("hosting: {e}")))? {
                break a;
            }
            if std::time::Instant::now() >= until {
                return Err(exit(6, "hosting: the host did not start listening"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        ctx.emit(&[a.to_string()], J::obj([("host", J::str(a.to_string()))]))?;
        ctx.out.flush()?;
    }
    if !client_listen.is_empty() {
        for a in db.client_listen(client_listen)? {
            let a = a.to_string();
            ctx.emit(&[format!("client {a}")], J::obj([("client", J::str(a.clone()))]))?;
        }
        ctx.out.flush()?;
    }
    // the address line above is a hard failure; the diagnostics after it are best effort (a
    // caller that read only the address and closed the pipe does not end the host)
    let t = ctx.timeout_or(None)?;
    diag(ctx, t, true)
}

/// Writes `host.0^`: each flag given replaces its field (one `''` clears it), the rest kept;
/// starts hosting (`own`, no listener) when it was off.
fn set_hosting(ctx: &mut Ctx<'_>, f: HostFlags) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut h = db.hosting().unwrap_or_default();
    // a flag given once as '' clears its field; otherwise its values replace it
    let given = |v: &[String]| (!v.is_empty()).then(|| v.iter().filter(|x| !(v.len() == 1 && x.is_empty())).cloned().collect::<Vec<_>>());
    if let Some(v) = given(&f.listen) {
        h.listen = v;
    }
    if let Some(a) = f.admit {
        h.admit = match a {
            AdmitArg::Own => osis::Admit::Own,
            AdmitArg::Open => osis::Admit::Open,
        };
    }
    if let Some(v) = given(&f.label) {
        h.labels = BTreeSet::new();
        for l in v {
            h.labels.extend(labels_of(ctx, &l)?);
        }
    }
    if let Some(v) = given(&f.replicate) {
        h.replicate = hosts(ctx, &v)?;
    }
    if let Some(v) = given(&f.policy) {
        h.policy = BTreeMap::new();
        for p in v {
            let (k, n) = p.split_once('=').ok_or_else(|| usage(format!("not NAME=N: {p}")))?;
            h.policy.insert(k.to_string(), n.parse().map_err(|_| usage(format!("not NAME=N: {p}")))?);
        }
    }
    if let Some(v) = given(&f.cap) {
        h.caps = BTreeMap::new();
        for c in v {
            let bad = || usage(format!("not GROUP|ID=ENTRIES,BYTES: {c}"));
            let (l, n) = c.rsplit_once('=').ok_or_else(bad)?;
            let (e, b) = n.split_once(',').ok_or_else(bad)?;
            let caps = osis::HostCaps { entries: e.parse().map_err(|_| bad())?, bytes: b.parse().map_err(|_| bad())? };
            for id in labels_of(ctx, l)? {
                h.caps.insert(id, caps);
            }
        }
    }
    Ok(db.set_hosting(Some(h))?)
}

/// `clients add|ls|rm|rotate` (notes/cli.md): `clients.0^` of this node.
fn clients(ctx: &mut Ctx<'_>, c: &ClientsCmd) -> anyhow::Result<()> {
    use osis_schema::osis_base::hex;
    match c {
        ClientsCmd::Add { until } => {
            let (actor, secret) = ctx.db.add_client(opt_ts(until)?)?;
            let s = hex::encode(secret.expose());
            ctx.emit(&[format!("{} {s}", actor.to_uri())], J::obj([("actor", J::tid(actor)), ("secret", J::str(s.clone()))]))
        }
        ClientsCmd::Ls => {
            let cs = ctx.db.clients()?;
            let lines = cs.iter().map(|c| format!("{} {}", c.actor.to_uri(), c.until.map_or("-".to_string(), |u| u.0.to_string()))).collect::<Vec<_>>();
            let j = J::Arr(cs.iter().map(|c| J::obj([("actor", J::tid(c.actor)), ("until", c.until.map_or(J::Null, |u| J::int(u.0)))])).collect());
            ctx.emit(&lines, j)
        }
        ClientsCmd::Rm { actor } => {
            let a = ctx.tid(actor)?;
            if ctx.db.remove_client(a)? { Ok(()) } else { Err(exit(3, "no such client")) }
        }
        ClientsCmd::RotateKey => {
            let a: Vec<String> = ctx.db.rotate_client_key()?.iter().map(ToString::to_string).collect();
            let j = J::Arr(a.iter().map(|x| J::str(x.clone())).collect());
            ctx.emit(&a, j)
        }
        ClientsCmd::Rotate { actor } => {
            let a = ctx.tid(actor)?;
            let s = hex::encode(ctx.db.rotate_client_secret(a)?.expose());
            ctx.emit(std::slice::from_ref(&s), J::str(s.clone()))
        }
    }
}

/// `host.0^` as lines (`listen URL`, `address URL#KEY` per listen URL but a port 0, `admit own|open`, `label ID`, `replicate ADDR`,
/// `policy NAME N`, `cap ID ENTRIES BYTES`) or one JSON object; exit 3 when not hosting.
fn hosting_show(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let h = ctx.db.hosting().ok_or_else(|| exit(3, "not hosting"))?;
    let admit = match h.admit {
        osis::Admit::Own => "own",
        osis::Admit::Open => "open",
    };
    let hex = |l: &osis::LabelId| osis_schema::osis_base::hex::encode(&l.0);
    // the address each listen URL will have; none for a port 0 (picked only when it listens)
    let addrs: Vec<String> = match ctx.db.host_key() {
        Some(k) => h.listen.iter().map(|u| osis::HostAddr::new(u, k).to_string()).filter(|a| !a.split('#').next().is_some_and(|u| u.ends_with(":0"))).collect(),
        None => vec![],
    };
    let mut lines: Vec<String> = h.listen.iter().map(|u| format!("listen {u}")).collect();
    lines.extend(addrs.iter().map(|a| format!("address {a}")));
    lines.push(format!("admit {admit}"));
    lines.extend(h.labels.iter().map(|l| format!("label {}", hex(l))));
    lines.extend(h.replicate.iter().map(|a| format!("replicate {a}")));
    lines.extend(h.policy.iter().map(|(k, n)| format!("policy {k} {n}")));
    lines.extend(h.caps.iter().map(|(l, c)| format!("cap {} {} {}", hex(l), c.entries, c.bytes)));
    let j = J::obj([
        ("listen", J::Arr(h.listen.iter().map(|u| J::str(u.clone())).collect())),
        ("addresses", J::Arr(addrs.iter().map(|a| J::str(a.clone())).collect())),
        ("admit", J::str(admit)),
        ("labels", J::Arr(h.labels.iter().map(|l| J::str(hex(l))).collect())),
        ("replicate", J::Arr(h.replicate.iter().map(|a| J::str(a.to_string())).collect())),
        ("policy", J::Obj(h.policy.iter().map(|(k, n)| (k.clone(), J::int(*n))).collect())),
        ("caps", J::Obj(h.caps.iter().map(|(l, c)| (hex(l), J::obj([("entries", J::int(c.entries)), ("bytes", J::int(c.bytes))]))).collect())),
    ]);
    ctx.emit(&lines, j)
}

/// A label ID (32 hex digits), or a group synced here: its labels (`status` lists them).
fn labels_of(ctx: &mut Ctx<'_>, s: &str) -> anyhow::Result<Vec<osis::LabelId>> {
    if let Some(b) = osis_schema::osis_base::hex::decode(s)
        && let Ok(id) = <[u8; 16]>::try_from(b)
    {
        return Ok(vec![osis::LabelId(id)]);
    }
    let g = ctx.tid(s).map_err(|_| usage(format!("not a group or a label ID (32 hex digits): {s}")))?;
    let ls = ctx.db.status()?.groups.remove(&g).map(|x| x.labels).unwrap_or_default();
    if ls.is_empty() {
        return Err(exit(3, format!("{s} is not synced here: give its label ID (`osis status` on a device that reads it)")));
    }
    Ok(ls)
}

/// Reads and parses a schema file (exit 7 when it does not parse); returns its file name too.
fn read_schema(file: &std::path::Path) -> anyhow::Result<(String, Schema)> {
    let src = std::fs::read_to_string(file).map_err(|e| usage(format!("{}: {e}", file.display())))?;
    let name = file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let s = osis_schema::parse(&name, &src).map_err(|e| exit(7, e.to_string()))?;
    Ok((name, s))
}

fn schema_check(g: &crate::args::Global, file: &std::path::Path, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let (name, s) = read_schema(file)?;
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
    if g.json {
        writeln!(out, "{}", J::obj([("version", J::int(s.version)), ("status", J::str(status))]).text())?;
    } else {
        writeln!(out, "ok version {} {status}", s.version)?;
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
        read_schema(&abs)?;
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
    // notes/cli.md Command table: `status` shows split things apart from groups, in both forms.
    #[test]
    fn status_lists_split_things_apart_notes_cli() {
        let t = osis::Tid::from_bytes([7; 15]);
        let mut s = osis::Status::default();
        s.split.insert(t);
        assert_eq!(super::status_lines(&s, true), vec![format!("{} split: writes refused", t.to_uri())]);
        assert_eq!(super::status_json(&s).text(), format!("{{\"groups\":[],\"split\":[\"{}\"]}}", t.to_uri()));
    }

    // notes/cli.md Design: `edit`'s temp file is new (`create_new`), randomly named, owner-only.
    #[test]
    fn edit_file_is_new_and_private_notes_cli() {
        let a = super::edit_file(&std::env::temp_dir(), "x").unwrap();
        let b = super::edit_file(&std::env::temp_dir(), "y").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "x");
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&a).unwrap().permissions()) & 0o077, 0);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    // notes/cli.md Design: `edit`'s temp file holds the value's plaintext; it is removed
    // whether the editor succeeds, fails or cannot start.
    #[cfg(unix)]
    #[test]
    fn edit_file_removed_notes_cli() {
        let d = std::env::temp_dir().join(format!("osis-cli-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(super::edit_in(&d, "true", "v").unwrap(), "v");
        assert!(super::edit_in(&d, "false", "v").is_err());
        assert!(super::edit_in(&d, "/nonexistent/editor", "v").is_err());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "temp file left behind");
        let _ = std::fs::remove_dir_all(&d);
    }

    // notes/cli.md Design: `--timeout 0` (no deadline) and huge timeouts do not overflow.
    #[test]
    fn deadline_never_overflows_plan_cli_2() {
        assert_eq!(super::deadline(None), None);
        assert_eq!(super::deadline(Some(std::time::Duration::MAX)), None);
        assert!(super::deadline(Some(super::FOREVER)).is_some());
    }
}
