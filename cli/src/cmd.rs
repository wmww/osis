//! Command bodies (notes/cli.md Command table): each one API call, plus printing.
//! Tests: spec: none (client surface).

use crate::args::*;
use crate::json::{self, J};
use crate::text::{self, Ty};
use crate::write::{self, Did};
use crate::{Ctx, StoreSel, exit, open, opt_ts, parse_ak, usage};
use anyhow::{Context as _, anyhow};
use osis::internals::Internals as _;
use osis::{
    Change, CommitId, CommitKind, CommitQuery, DynamicAspectKey, Error, GrantOpts, LinkOpts, Member, Origin, Osis, Role, SetRoleOpts, SyncScope, SyncState, Tid, Value,
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

fn grant_opts(until: &Option<String>, may_grant: &Option<String>) -> anyhow::Result<GrantOpts> {
    Ok(GrantOpts { until: opt_ts(until)?, may_grant: may_grant.as_deref().map(parse_role).transpose()? })
}

pub(crate) fn parse_role(s: &str) -> anyhow::Result<Role> {
    match s {
        "read" => Ok(Role::Read),
        "write" => Ok(Role::Write),
        "admin" => Ok(Role::Admin),
        _ => Err(usage(format!("role: read, write or admin (got {s:?})"))),
    }
}

/// A commit id, as `inspect` prints it.
pub fn commit_text(c: &osis::internals::RawCommitId) -> String {
    CommitId::from(*c).to_string()
}

/// Prints a commit id (nothing when nothing changed).
fn emit_commit(ctx: &mut Ctx<'_>, c: Option<CommitId>) -> anyhow::Result<()> {
    let c = c.map(|c| c.to_string());
    ctx.emit(&c.iter().cloned().collect::<Vec<_>>(), J::obj([("commit", J::opt(c.map(J::str)))]))
}

fn parse_id(s: &str) -> anyhow::Result<CommitId> {
    s.parse().map_err(|_| usage(format!("not a commit id: {s}")))
}

/// The commit behind a commit id, as `inspect` asks.
fn parse_commit(s: &str) -> anyhow::Result<osis::internals::RawCommitId> {
    Ok(osis::internals::CommitRaw::raw(&parse_id(s)?))
}

fn ts_text(raw: bool, ms: u64) -> String {
    if raw { ms.to_string() } else { i64::try_from(ms).ok().and_then(text::rfc3339).unwrap_or_else(|| ms.to_string()) }
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

/// Polls `f` on this thread until it is ready, or past `limit` drops it: `None`.
fn race<F: Future>(limit: Option<Duration>, f: F) -> Option<F::Output> {
    let end = deadline(limit);
    let mut f = std::pin::pin!(f);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
        match end {
            None => std::thread::park(),
            Some(e) => {
                let left = e.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return None;
                }
                std::thread::park_timeout(left);
            }
        }
    }
}

/// A call that waits, within `limit` (`None`: for as long as it takes): past it `Network`, exit 6.
pub(crate) fn within<T>(limit: Option<Duration>, f: impl Future<Output = osis::Result<T>>) -> osis::Result<T> {
    race(limit, f).unwrap_or_else(|| Err(Error::Network("timed out".into())))
}

/// A call that waits, within `--timeout`.
pub(crate) fn wait<T>(ctx: &Ctx<'_>, f: impl Future<Output = osis::Result<T>>) -> anyhow::Result<T> {
    Ok(within(ctx.timeout()?, f)?)
}

/// `wait` of a call judging a link or card: nothing says it never will, so past `--timeout` it says
/// what is known, and that nothing was left half done.
pub(crate) fn confirm<T>(ctx: &Ctx<'_>, f: impl Future<Output = osis::Result<T>>) -> anyhow::Result<T> {
    race(ctx.timeout()?, f).unwrap_or_else(|| Err(Error::Network("could not confirm this link yet; trying again is safe".into()))).map_err(Into::into)
}

/// `wait_synced` within `limit`; past it `Network`, or the serving nodes that do not admit a group (state
/// `Refused`) when there are any.
fn wait_sync(ctx: &Ctx<'_>, s: SyncScope, limit: Option<Duration>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match race(limit, db.wait_synced(s)) {
        Some(r) => r.map_err(|e| not_admitted(&db, e)),
        None => {
            let refused = db.status().map(|st| st.groups.iter().filter(|(_, x)| x.state == SyncState::Refused).map(|(g, _)| *g).collect::<Vec<_>>()).unwrap_or_default();
            Err(if refused.is_empty() { Error::Network("timed out".into()).into() } else { not_admitted(&db, Error::Unsynced { groups: refused }) })
        }
    }
}

/// `e` with the serving nodes that do not admit the groups it names (state `Refused`), if any.
fn not_admitted(db: &Osis, e: Error) -> anyhow::Error {
    let (Error::Unsynced { groups }, Ok(st)) = (&e, db.status()) else { return e.into() };
    let hint: Vec<String> = groups
        .iter()
        .filter_map(|g| st.groups.get(g).filter(|x| x.state == SyncState::Refused).map(|x| (g, x)))
        .flat_map(|(g, x)| x.refused_by.iter().map(move |h| format!("{h} does not admit group {} (yet)", g.to_uri())))
        .collect();
    if hint.is_empty() { e.into() } else { anyhow::Error::from(e).context(hint.join("; ")) }
}

fn links_j(ls: &[osis::LinkInfo]) -> J {
    J::Arr(ls.iter().map(|l| J::obj([("id", J::str(l.id.to_string())), ("target", J::tid(l.target)), ("role", J::str(role_text(l.role).to_string())), ("single_use", J::Bool(l.single_use))])).collect())
}

fn set_role_opts(d: &SetRoleFlags) -> SetRoleOpts {
    SetRoleOpts { retain_copy: d.retain_copy }
}

/// A role, or `none`.
fn opt_role(s: &str) -> anyhow::Result<Option<Role>> {
    if s == "none" { Ok(None) } else { parse_role(s).map(Some) }
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

fn peers(ctx: &mut Ctx<'_>, list: &[String]) -> anyhow::Result<Vec<osis::Address>> {
    list.iter().map(|s| Ok(ctx.arg_text(s)?.parse::<osis::Address>()?)).collect()
}

/// A value as text or JSON at a key's type (`--raw`: numbered).
fn show_value(ctx: &Ctx<'_>, v: &Value, ty: Ty<'_>) -> (String, J) {
    let ty = if ctx.g.raw { None } else { ty };
    (text::print(v, ty), json::value(v, ty))
}

fn truncate(s: String, width: usize) -> String {
    if width == 0 || s.chars().count() <= width { s } else { s.chars().take(width.saturating_sub(1)).collect::<String>() + "…" }
}

/// A command over an API piece that does not exist yet.
pub(crate) fn not_built(what: &'static str) -> anyhow::Error {
    exit(1, format!("not built yet: {what}"))
}

/// Commands that wait for or talk to other nodes: the store opens with sync running. Others stay
/// local (their writes go out with the next networked command, `sync` or `serve`).
fn needs_net(c: &Cmd) -> bool {
    matches!(
        c,
        Cmd::Pair(_)
            | Cmd::Node(NodeCmd::Rm { .. })
            | Cmd::SetRole { .. }
            | Cmd::Link(LinkCmd::Redeem { .. } | LinkCmd::Revoke { .. })
            | Cmd::Card(CardCmd::Import { .. })
            | Cmd::Chat(_)
            | Cmd::Status { .. }
            | Cmd::Sync { .. }
            | Cmd::Wait { .. }
            | Cmd::Serve { .. }
            | Cmd::Group(GroupCmd::Source { to: Some(_), .. })
            | Cmd::Clients(ClientsCmd::RotateAddress)
            | Cmd::Watch { .. }
            | Cmd::Writes { list: ListArgs { follow: true, .. }, .. }
            | Cmd::Fired { list: ListArgs { follow: true, .. }, .. }
            | Cmd::Grants { watch: true, .. }
            | Cmd::Diag { follow: true }
    ) || delivers(c)
}

/// Commands that stay up until stopped, so they are on the local network (unless `--no-lan`).
fn stays_up(c: &Cmd) -> bool {
    matches!(
        c,
        Cmd::Serve { .. }
            | Cmd::Pair(_)
            | Cmd::Watch { .. }
            | Cmd::Status { watch: true }
            | Cmd::Writes { list: ListArgs { follow: true, .. }, .. }
            | Cmd::Fired { list: ListArgs { follow: true, .. }, .. }
            | Cmd::Grants { watch: true, .. }
            | Cmd::Diag { follow: true }
    )
}

/// What a command uses of the network: one that stays up is on the local network; the others that
/// sync are gone too soon to be worth announcing.
fn network(c: &Cmd) -> crate::Network {
    match c {
        c if stays_up(c) => crate::Network::Node,
        c if needs_net(c) => crate::Network::Sync,
        _ => crate::Network::None,
    }
}

/// Commands whose API call hands other nodes something the engine keeps only in memory until
/// sent (inbox grants, the first commits under a new sync ID):
/// they run with sync on and wait until it reached a peer before the process exits.
fn delivers(c: &Cmd) -> bool {
    // a role that stays may have been granted or raised, which goes to the holder's inbox
    matches!(c, Cmd::SetRole { role, .. } if role != "none") || matches!(c, Cmd::Grant { .. } | Cmd::Leave { .. } | Cmd::AddWithGrant { .. } | Cmd::Link(LinkCmd::Make { .. }) | Cmd::Card(CardCmd::Show) | Cmd::Group(GroupCmd::Sync { .. }))
}

/// What a delivering command waits on before exit.
pub(crate) enum Delivers {
    /// The thing its holders fetch, or the one a removal is about.
    Thing(String),
    /// This account's profile: a contact card is a read link to it.
    Profile,
    /// Only the inbox items it queued: the role is recorded, and `status` shows how its sync stands.
    Deliveries,
    All,
}

fn delivery_of(c: &Cmd) -> Delivers {
    match c {
        Cmd::AddWithGrant { t, .. } | Cmd::Link(LinkCmd::Make { t, .. }) | Cmd::Leave { t, .. } => Delivers::Thing(t.clone()),
        Cmd::Card(CardCmd::Show) => Delivers::Profile,
        Cmd::Group(GroupCmd::Sync { g, .. }) => Delivers::Thing(g.clone()),
        Cmd::Grant { .. } | Cmd::SetRole { .. } => Delivers::Deliveries,
        _ => Delivers::All,
    }
}

/// The peers this process delivers to: a thin client has none, its node delivers.
fn own_peers(db: &Osis) -> osis::Result<Vec<osis::Address>> {
    match db.saved_peers() {
        Err(Error::Unsupported(_)) => Ok(Vec::new()),
        h => h,
    }
}

/// Sends what a `delivers` command queued (within `--timeout`): `wait_synced` on what it delivers.
pub(crate) fn deliver(ctx: &mut Ctx<'_>, what: Delivers) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    db.nudge_sync()?;
    let end = deadline(ctx.timeout()?);
    let s = match what {
        Delivers::Thing(x) => SyncScope::Thing(ctx.tid(&x)?),
        Delivers::Profile => SyncScope::Thing(db.profile()?),
        Delivers::Deliveries => SyncScope::Deliveries,
        Delivers::All => SyncScope::All,
    };
    let left = end.map(|e| e.saturating_duration_since(Instant::now()));
    wait_sync(ctx, s, left).map_err(|e| exit(6, format!("done locally, not yet at its peers: {e:#}")))?;
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
    let seed = |list: &[String]| list.iter().map(|s| s.parse::<osis::Address>().map_err(anyhow::Error::from)).collect::<anyhow::Result<Vec<_>>>();
    let db = match &cli.cmd {
        Cmd::Init { peer } => crate::create(&sel, &g, seed(peer)?)?,
        Cmd::Pair(PairCmd::Join { offer, peer }) => {
            // the app carries two messages: print the request, read the reply
            let cfg = crate::config(&g, crate::Network::Node);
            let offer: osis::PairOffer = offer.parse()?;
            let join = Osis::pair(crate::store_of(&sel), &seed(peer)?, &offer, cfg)?;
            writeln!(out, "{}", join.request())?;
            out.flush()?;
            let mut line = String::new();
            stdin.read_line(&mut line)?;
            join.finish(&line.parse()?)?
        }
        c => open(&sel, &g, network(c), !matches!(c, Cmd::Inspect(_) | Cmd::Serve { .. }))?,
    };
    // -v on a command that syncs: diagnostics to stderr while it runs, best effort (not for
    // those that already print them on stdout)
    let streams = matches!(cli.cmd, Cmd::Serve { .. } | Cmd::Diag { follow: true });
    let verbose = (g.verbose > 0 && needs_net(&cli.cmd) && !streams).then(|| Verbose::start(&db, g.json)).transpose()?;
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
        let (flush, what) = (delivers(&cli.cmd), delivery_of(&cli.cmd));
        let mut r = run(&mut ctx, cli.cmd);
        if r.is_ok() && flush {
            r = match own_peers(&ctx.db) {
                Ok(h) if h.is_empty() => Ok(()),
                Ok(_) => deliver(&mut ctx, what),
                Err(e) => Err(e.into()),
            };
        }
        ctx.db.settle();
        drop(verbose);
        let db = ctx.db.clone();
        drop(ctx);
        // other handles left open change nothing: every commit is durable and this process ends
        let closed = db.close();
        r.and(closed.map(drop).map_err(Into::into))
    })
}

/// Runs one write command as its own commit; prints the commit id (and a created tid).
fn one_write(ctx: &mut Ctx<'_>, c: ScriptCmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut w = db.write();
    let mut did = Did::default();
    write::apply(ctx, &mut w, &c, &mut did)?;
    let done = w.commit()?;
    let commit = done.map(|c| c.stamp.id);
    let created = did.created.first().map(|(_, t)| *t);
    let mut lines = Vec::new();
    if let Some(t) = created {
        lines.push(t.to_uri());
    } else if let Some(c) = &commit {
        lines.push(c.to_string());
    }
    let mut f = vec![("commit".to_string(), J::opt(commit.as_ref().map(|c| J::str(c.to_string()))))];
    if let Some(t) = created {
        f.push(("tid".into(), J::tid(t)));
    }
    ctx.emit(&lines, J::Obj(f))
}

fn run(ctx: &mut Ctx<'_>, cmd: Cmd) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    match cmd {
        Cmd::Init { peer } | Cmd::Pair(PairCmd::Join { peer, .. }) => {
            for s in peers(ctx, &peer)? {
                db.add_peer(&s)?;
            }
            whoami(ctx)
        }
        Cmd::Whoami => whoami(ctx),
        Cmd::Pair(PairCmd::Offer) => {
            // print the offer, read the new node's request, print the reply and its node
            let o = db.pair_offer()?;
            ctx.emit(&[o.to_string()], J::obj([("offer", J::str(o.to_string()))]))?;
            let mut line = String::new();
            ctx.stdin.read_line(&mut line)?;
            let (node, reply) = db.pair_accept(&line.parse()?)?;
            ctx.emit(&[reply.to_string(), node.to_uri()], J::obj([("reply", J::str(reply.to_string())), ("node", J::tid(node))]))
        }
        Cmd::Node(NodeCmd::Ls) => {
            let ds = db.nodes()?;
            ctx.emit(&ds.iter().map(|d| d.node.to_uri()).collect::<Vec<_>>(), J::Arr(ds.iter().map(|d| J::obj([("node", J::tid(d.node))])).collect()))
        }
        Cmd::Node(NodeCmd::Rm { node, d, end_links }) => {
            let n = ctx.tid(&node)?;
            let o = set_role_opts(&d);
            let open = db.remove_node(n, o)?;
            if end_links {
                for l in &open {
                    db.revoke_link(l.id)?;
                }
            }
            let say = |l: &osis::LinkInfo| {
                if end_links {
                    format!("ended link {} to {}", l.id, l.target.to_uri())
                } else {
                    format!("link {} to {} still works for whoever holds that node: osis link revoke {}", l.id, l.target.to_uri(), l.id)
                }
            };
            ctx.emit(&open.iter().map(say).collect::<Vec<_>>(), J::obj([("links", links_j(&open)), ("ended", J::Bool(end_links))]))
        }
        Cmd::Peers(PeersCmd::Ls { group }) => {
            let s = match group {
                Some(g) => db.peers(ctx.tid(&g)?)?,
                None => db.saved_peers()?,
            };
            ctx.emit(&s.iter().map(|s| s.to_string()).collect::<Vec<_>>(), J::Arr(s.iter().map(|s| J::str(s.to_string())).collect()))
        }
        Cmd::Peers(PeersCmd::Add { addr }) => Ok(db.add_peer(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Peers(PeersCmd::Rm { addr }) => Ok(db.remove_peer(&ctx.arg_text(&addr)?.parse()?)?),
        Cmd::Serving(ServingCmd::Show) => serving_show(ctx),
        Cmd::Serving(ServingCmd::Set(f)) => set_serving(ctx, f),
        Cmd::Serving(ServingCmd::Off) => Ok(db.set_serving(None)?),
        Cmd::Serving(ServingCmd::Ids { g }) => {
            let t = ctx.tid(&g)?;
            let t = if t == db.me() { db.home() } else { t };
            let ids: Vec<String> = db.sync_ids(t)?.iter().map(ToString::to_string).collect();
            let j = J::Arr(ids.iter().map(|x| J::str(x.clone())).collect());
            ctx.emit(&ids, j)
        }
        Cmd::Clients(c) => clients(ctx, &c),
        Cmd::Serve { serving, client_listen, .. } => serve(ctx, serving, &client_listen),
        Cmd::Schema(_) => unreachable!("handled before opening"),
        Cmd::Create(a) => one_write(ctx, ScriptCmd::Create(a)),
        Cmd::Set(a) => one_write(ctx, ScriptCmd::Set(a)),
        Cmd::Overwrite(a) => one_write(ctx, ScriptCmd::Overwrite(a)),
        Cmd::Fire(a) => one_write(ctx, ScriptCmd::Fire(a)),
        Cmd::Rm(a) => one_write(ctx, ScriptCmd::Rm(a)),
        Cmd::Op(a) => one_write(ctx, ScriptCmd::Op(a)),
        Cmd::Group(GroupCmd::Member(m)) => one_write(ctx, ScriptCmd::Group(m)),
        Cmd::Delete { t } => one_write(ctx, ScriptCmd::Delete { t }),
        Cmd::Get { t, ak, path, stream, len } => get(ctx, &t, &ak, path.as_deref(), stream, len),
        Cmd::Edit { t, ak, path, base } => edit(ctx, &t, &ak, path.as_deref(), base),
        Cmd::Write => write_script(ctx),
        Cmd::Show { t, width } => show(ctx, &t, width),
        Cmd::Aspects { t } => {
            let a = db.aspects(ctx.tid(&t)?)?;
            ctx.emit(&a.iter().map(|a| a.as_str().to_string()).collect::<Vec<_>>(), J::Arr(a.iter().map(|a| J::str(a.as_str())).collect()))
        }
        Cmd::Ls { .. } => Err(not_built("query")),
        Cmd::Backlinks { .. } => Err(not_built("backlinks")),
        Cmd::Watch { t, ak, path, count } => watch(ctx, &t, ak.as_deref(), path.as_deref(), count),
        Cmd::Writes { t, ak, scope: s, list, next } => {
            let sc = match (t, ak) {
                (Some(t), Some(ak)) if opt_scope(ctx, &s)?.is_none() => osis::Scope::Aspects(vec![(ctx.tid(&t)?, parse_ak(&ak, "AK")?)]),
                (None, None) => scope(ctx, &s)?,
                _ => return Err(usage("give T AK or one scope: --thing T, --aspect T AK..., --group G")),
            };
            // the one commit undo or redo would revert: a question of its own, about a scope
            if let Some(n) = next {
                let c = match n.as_str() {
                    "undo" => db.undo_target(&sc)?,
                    "redo" => db.redo_target(&sc)?,
                    x => return Err(usage(format!("--next takes undo or redo, not {x:?}"))),
                };
                let lines: Vec<String> = c.iter().map(|c| commit_line(ctx, c)).collect();
                return ctx.emit(&lines, J::Arr(c.iter().map(commit_j).collect()));
            }
            let at = Listed::Writes(sc);
            listing(ctx, &at, &list)
        }
        Cmd::Fired { t, ak, list, versions_of } => {
            let (t, ak) = (ctx.tid(&t)?, parse_ak(&ak, "AK")?);
            let at = match versions_of {
                Some(c) => Listed::Versions(t, ak, parse_id(&c)?),
                None => Listed::Fired(t, ak),
            };
            listing(ctx, &at, &list)
        }
        Cmd::Purge { t, ak, commit, author } => {
            let tid = ctx.tid(&t)?;
            let key = ctx.aspect_key(&ak)?;
            let commit = commit.as_deref().map(parse_id).transpose()?;
            let author = author.as_deref().map(|a| ctx.tid(a)).transpose()?;
            let mut w = db.write();
            let mut at = w.at(tid, key);
            match (commit, author) {
                (Some(c), _) => at.purge(osis::Purge::Commit(c))?,
                (_, Some(a)) => at.purge(osis::Purge::Author(a))?,
                _ => at.purge(osis::Purge::All)?,
            }
            let done = w.commit()?;
            emit_commit(ctx, done.map(|d| d.stamp.id))
        }
        Cmd::Undo { scope: s } => undo(ctx, &s, false),
        Cmd::Redo { scope: s } => undo(ctx, &s, true),
        Cmd::Revert { id } => {
            let c = db.revert(parse_id(&id)?)?;
            emit_commit(ctx, Some(c.stamp.id))
        }
        Cmd::Groups { t } => {
            let gs = db.groups_of(ctx.tid(&t)?)?;
            let rel = [("item", &gs.item_of), ("subgroup", &gs.subgroup_of), ("within", &gs.within)];
            let lines = rel.iter().flat_map(|(n, v)| v.iter().map(move |g| format!("{n}\t{}", g.to_uri()))).collect::<Vec<_>>();
            let arr = |v: &[Tid]| J::Arr(v.iter().map(|g| J::tid(*g)).collect());
            ctx.emit(&lines, J::obj([("item_of", arr(&gs.item_of)), ("subgroup_of", arr(&gs.subgroup_of)), ("within", arr(&gs.within))]))
        }
        Cmd::Members { g } => {
            let g = ctx.tid(&g)?;
            let members = db.members(g)?;
            let of = |want: fn(Member) -> Option<Tid>| members.iter().copied().filter_map(want).collect::<Vec<_>>();
            let (items, subs) = (of(|m| if let Member::Item(t) = m { Some(t) } else { None }), of(|m| if let Member::Subgroup(t) = m { Some(t) } else { None }));
            let rel = [("item", &items), ("subgroup", &subs)];
            let lines = rel.iter().flat_map(|(n, v)| v.iter().map(move |t| format!("{n}\t{}", t.to_uri()))).collect::<Vec<_>>();
            let arr = |v: &[Tid]| J::Arr(v.iter().map(|t| J::tid(*t)).collect());
            ctx.emit(&lines, J::obj([("items", arr(&items)), ("subgroups", arr(&subs))]))
        }
        Cmd::Grants { t, watch: false, .. } => grants(ctx, &t),
        Cmd::Grants { t, watch: true, count } => {
            let t = ctx.tid(&t)?;
            let (raw, json_out) = (ctx.g.raw, ctx.g.json);
            let (tx, rx) = mpsc::channel::<(String, bool)>();
            // the first call is the grants now: printed, not counted
            let mut initial = true;
            let _sub = db.on_grants_change(t, move |_, r| {
                let l = match (r, json_out) {
                    (Ok(r), true) => grants_json(&r).text(),
                    (Ok(r), false) => grants_lines(&r, raw).join(", "),
                    (Err(e), true) => J::obj([("error", J::str(e.to_string()))]).text(),
                    (Err(e), false) => format!("(error: {e})"),
                };
                let _ = tx.send((l, !std::mem::take(&mut initial)));
            })?;
            let timeout = ctx.timeout_or(None)?;
            stream(ctx, &rx, count, timeout, "change", false, |_, (l, counts)| (l, counts))
        }
        Cmd::Holders { t } => {
            let hs = db.holders(ctx.tid(&t)?)?;
            let raw = ctx.g.raw;
            let lines: Vec<String> = hs.iter().map(|h| {
                let via = if h.through.is_empty() { String::new() } else { format!(" via {}", h.through.iter().map(|t| t.to_uri()).collect::<Vec<_>>().join(",")) };
                format!("{} {:?} {} {}{via}", h.actor.to_uri(), h.kind, role_text(h.role), h.until.map_or("-".into(), |u| ts_text(raw, u.0)))
            }).collect();
            let j = J::Arr(hs.iter().map(|h| J::obj([("actor", J::tid(h.actor)), ("kind", J::str(format!("{:?}", h.kind))), ("role", J::str(role_text(h.role))), ("until", J::opt(h.until.map(|u| J::int(u.0)))), ("through", J::Arr(h.through.iter().map(|t| J::tid(*t)).collect()))])).collect());
            ctx.emit(&lines, j)
        }
        Cmd::Now => {
            let n = db.now()?.0;
            ctx.emit(&[ts_text(ctx.g.raw, n)], J::obj([("now", J::int(n))]))
        }
        Cmd::Role { t } => {
            let r = db.role_on(ctx.tid(&t)?)?;
            ctx.emit(&[r.map_or("none", role_text).to_string()], J::obj([("role", J::opt(r.map(|r| J::str(role_text(r)))))]))
        }
        Cmd::Grant { t, holder, role, until, may_grant } => {
            let (t, m) = (ctx.tid(&t)?, ctx.tid(&holder)?);
            let role = match role {
                Some(r) => parse_role(&r)?,
                None => db.grants(t)?.get(&m).map(|e| e.role).ok_or_else(|| exit(3, "no such grant"))?,
            };
            Ok(db.grant(t, m, role, grant_opts(&until, &may_grant)?)?)
        }
        Cmd::SetRole { t, holder, role, d } => {
            let (t, m, role, o) = (ctx.tid(&t)?, ctx.tid(&holder)?, opt_role(&role)?, set_role_opts(&d));
            Ok(db.set_role(t, m, role, o)?)
        }
        Cmd::Leave { t, holder } => {
            let holder = holder.map_or(Ok(db.me()), |h| ctx.tid(&h))?;
            Ok(db.leave(holder, ctx.tid(&t)?)?)
        }
        Cmd::Retained { drop: Some(a) } => Ok(db.drop_retained_copy(ctx.tid(&a)?)?),
        Cmd::Retained { drop: None } => {
            for a in db.retained_copies()? {
                println!("{}", a.to_uri());
            }
            Ok(())
        }
        Cmd::AddWithGrant { t, g, role, subgroup } => {
            let t = ctx.tid(&t)?;
            let member = if subgroup { Member::Subgroup(t) } else { Member::Item(t) };
            Ok(db.add_with_grant(member, ctx.tid(&g)?, parse_role(&role)?)?)
        }
        Cmd::Chat(c) => crate::chat::run(ctx, c),
        Cmd::Link(LinkCmd::Make { t, role, until, single_use }) => {
            let l = db.make_link(ctx.tid(&t)?, parse_role(&role)?, LinkOpts { until: opt_ts(&until)?, single_use, direct: false })?;
            ctx.emit(&[l.to_string()], J::obj([("link", J::str(l.to_string()))]))
        }
        Cmd::Link(LinkCmd::Redeem { link }) => {
            let l: osis::ShareLink = ctx.arg_text(&link)?.parse()?;
            let t = confirm(ctx, db.redeem(&l))?;
            ctx.emit(&[t.to_uri()], J::obj([("tid", J::tid(t))]))
        }
        Cmd::Link(LinkCmd::Ls { t }) => {
            let mut ls = db.links()?;
            if let Some(t) = t {
                let t = ctx.tid(&t)?;
                ls.retain(|l| l.target == t);
            }
            let lines: Vec<String> = ls.iter().map(|l| format!("{} {} {} {}", l.id, role_text(l.role), if l.single_use { "single-use" } else { "-" }, l.target.to_uri())).collect();
            ctx.emit(&lines, links_j(&ls))
        }
        Cmd::Link(LinkCmd::Revoke { id }) => {
            let id: osis::LinkId = id.parse()?;
            Ok(db.revoke_link(id)?)
        }
        Cmd::Card(CardCmd::Show) => {
            let c = db.contact_card()?;
            ctx.emit(&[c.to_string()], J::obj([("card", J::str(c.to_string()))]))
        }
        Cmd::Card(CardCmd::Profile { account }) => {
            let p = match account {
                Some(a) => db.profile_of(ctx.tid(&a)?)?,
                None => Some(db.profile()?),
            };
            match p {
                Some(p) => ctx.emit(&[p.to_uri()], J::obj([("profile", J::tid(p))])),
                None => Err(exit(3, "no profile known for that account")),
            }
        }
        Cmd::Card(CardCmd::Import { card }) => {
            let c: osis::ContactCard = ctx.arg_text(&card)?.parse()?;
            let a = confirm(ctx, db.import_contact(&c))?;
            ctx.emit(&[a.to_uri()], J::obj([("actor", J::tid(a))]))
        }
        Cmd::Disputes(DisputeCmd::Ls) => {
            let (ds, left) = db.disputes()?;
            let side = |s: osis::Side| if s == osis::Side::Author { "author" } else { "holder" };
            let mut lines: Vec<String> = ds.iter().map(|d| format!("{} {} {} {} {}{}", d.id, d.target.to_uri(), d.author.to_uri(), d.holder.to_uri(), side(d.side), if d.chosen { " chosen" } else { "" })).collect();
            if left > 0 {
                lines.push(format!("{left} not examined"));
            }
            let j = J::obj([("disputes", J::Arr(ds.iter().map(|d| J::obj([("id", J::str(d.id.to_string())), ("target", J::tid(d.target)), ("author", J::tid(d.author)), ("holder", J::tid(d.holder)), ("side", J::str(side(d.side))), ("chosen", J::str(if d.chosen { "true" } else { "false" }))])).collect())), ("unexamined", J::int(left as i64))]);
            ctx.emit(&lines, j)
        }
        Cmd::Disputes(DisputeCmd::Choose { id, side }) => {
            let side = match side.as_str() {
                "author" => osis::Side::Author,
                "holder" => osis::Side::Holder,
                _ => return Err(exit(2, "side: author or holder")),
            };
            Ok(db.choose_side(id.parse()?, side)?)
        }
        Cmd::Status { watch: false } => status(ctx),
        Cmd::Status { watch: true } => {
            let (tx, rx) = mpsc::channel::<String>();
            let _sub = db.on_status_change(move |_, st| {
                let st = match st {
                    Ok(st) => st,
                    Err(e) => {
                        let _ = tx.send(format!("error {e}"));
                        return;
                    }
                };
                let l = st.groups.iter().map(|(g, x)| format!("{} {:?}", g.to_uri(), x.state)).chain(st.two_sources.iter().map(|t| format!("{} two sources", t.to_uri()))).collect::<Vec<_>>().join(", ");
                let _ = tx.send(format!("connected {} {l}", st.connected));
            })?;
            let timeout = ctx.timeout_or(None)?;
            stream_lines(ctx, &rx, None, timeout)
        }
        // `wait_synced` asks its peers to sync first: `sync` and `wait` are one call
        Cmd::Sync { group } | Cmd::Wait { group } => {
            let s = match group {
                Some(g) => SyncScope::Thing(ctx.tid(&g)?),
                None => SyncScope::All,
            };
            let t = ctx.timeout()?;
            wait_sync(ctx, s, t)
        }
        Cmd::Group(GroupCmd::Sync { g, peer }) => {
            let g = ctx.tid(&g)?;
            let s = peers(ctx, &peer)?;
            Ok(db.sync(g, &s)?)
        }
        Cmd::Group(GroupCmd::Source { g, to }) => {
            // the source's connection and its secret are in the process that holds the store
            if !db.has_store() {
                return Err(exit(1, "group source needs the store itself: stop `osis serve` on this store, run it with --connect, start `serve` again"));
            }
            let g = ctx.tid(&g)?;
            let Some(to) = to else {
                let at = db.group_sources().get(&g).map_or("local".to_string(), |a| a.to_string());
                return ctx.emit(&[at.clone()], J::obj([("source", J::str(at))]));
            };
            let to = if to == "local" { osis::GroupSource::Local } else { osis::GroupSource::Node(to.parse()?) };
            wait(ctx, db.group_source(g, to))
        }
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
    let peers = own_peers(&db)?;
    let sw = format!("osis {}", env!("CARGO_PKG_VERSION"));
    let mut lines = vec![format!("me\t{}", db.me().to_uri()), format!("node\t{}", db.node().to_uri())];
    lines.extend(peers.iter().map(|s| format!("peer\t{s}")));
    lines.push(format!("store\t{store}"));
    lines.push(format!("software\t{sw}"));
    let j = J::obj([
        ("me", J::tid(db.me())),
        ("node", J::tid(db.node())),
        ("peers", J::Arr(peers.iter().map(|s| J::str(s.to_string())).collect())),
        ("store", J::str(store)),
        ("software", J::str(sw)),
    ]);
    ctx.emit(&lines, j)
}

fn get(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, stream: bool, len: bool) -> anyhow::Result<()> {
    let t = ctx.tid(t)?;
    let key = ctx.aspect_key(ak)?;
    let db = ctx.db.clone();
    if stream || len {
        let p = match path {
            None | Some("") => osis::Path::root(),
            Some(p) => write::path(ctx, t, &key, p, false)?,
        };
        let s = db.at(t, key.clone()).path(p).stream()?;
        let Some(mut s) = s else { return Err(absent(t, ak)) };
        if len {
            let n = s.len();
            return ctx.emit(&[n.to_string()], J::obj([("len", J::int(n))]));
        }
        std::io::copy(&mut s, &mut *ctx.out)?;
        return Ok(());
    }
    let (v, pty) = match path {
        None | Some("") => (db.at(t, key.clone()).get()?, key.value_type().map(|t| t.get())),
        Some(p) => {
            let p = write::path(ctx, t, &key, p, false)?;
            let pty = key.value_type().map(|t| t.get()).and_then(|t| text::type_at_path(t, &p.0));
            (db.at(t, key.clone()).path(p).get::<osis::Value>()?, pty)
        }
    };
    let Some(v) = v else { return Err(absent(t, ak)) };
    let (s, j) = show_value(ctx, &v, pty.as_ref());
    ctx.emit(&[s], j)
}

/// `get` of what reads as absent here: exit 3, saying so.
fn absent(t: Tid, ak: &str) -> anyhow::Error {
    exit(3, format!("absent: {ak} of {}", t.to_uri()))
}

fn edit(ctx: &mut Ctx<'_>, t: &str, ak: &str, path: Option<&str>, base: Option<String>) -> anyhow::Result<()> {
    if path.is_some_and(|p| !p.is_empty()) {
        return Err(usage("edit takes the whole aspect (the API edits aspects; use op or set for a path)"));
    }
    let t = ctx.tid(t)?;
    let key = ctx.aspect_key(ak)?;
    let db = ctx.db.clone();
    let ty = key.value_type().map(|t| t.get());
    let ty = ty.as_ref();
    let (base, new) = match base {
        Some(b) => {
            let base = ctx.value(&b, ty)?;
            let new = ctx.value("-", ty)?;
            (base, new)
        }
        None if ctx.tty => {
            let cur = db.at(t, key.clone()).get()?.ok_or_else(|| exit(3, "absent: nothing to edit (use set)"))?;
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
    emit_commit(ctx, done.map(|c| c.stamp.id))
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
    let commit = done.map(|c| c.stamp.id.to_string());
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
    let known = db.has_content(t)?;
    let created = db.created(t)?;
    if aks.is_empty() && !known && created.is_none() {
        return Err(Error::UnknownThing { tid: t }.into());
    }
    let mut lines = vec![format!("tid\t{}", t.to_uri())];
    let mut fields = Vec::new();
    for ak in &aks {
        let key = ctx.aspect_key(ak.as_str())?;
        let (s, j) = match db.at(t, key.clone()).get() {
            Ok(Some(v)) => show_value(ctx, &v, key.value_type().map(|t| t.get()).as_ref()),
            // a value its schema does not read (a `Mismatch` diagnostic): shown untyped
            Ok(None) => match db.at(t, DynamicAspectKey::untyped(ak.clone())).get() {
                Ok(Some(v)) => show_value(ctx, &v, None),
                _ => ("(absent)".to_string(), J::Null),
            },
            Err(e) => (format!("(error: {e})"), J::obj([("error", J::str(e.to_string()))])),
        };
        lines.push(format!("{}\t{}", ak.as_str(), truncate(s, width)));
        fields.push((ak.as_str().to_string(), j));
    }
    let groups = db.groups_of(t)?;
    let role = db.role_on(t)?;
    let uris = |v: &[Tid]| v.iter().map(Tid::to_uri).collect::<Vec<_>>().join(" ");
    lines.push(format!("state\t{}", if known { "present" } else { "empty" }));
    lines.push(format!("groups\t{}", uris(&groups.within)));
    lines.push(format!("subgroup_of\t{}", uris(&groups.subgroup_of)));
    lines.push(format!("role\t{}", role.map_or("none", role_text)));
    let changed = db.changed(t)?;
    let stamp = |c: Option<osis::ThingStamp>| c.map_or("unknown".into(), |c| format!("{} by {}", ts_text(ctx.g.raw, c.written.0), c.actor.to_uri()));
    lines.push(format!("created\t{}", stamp(created)));
    lines.push(format!("changed\t{}", stamp(changed)));
    let j = J::obj([
        ("tid", J::tid(t)),
        ("aspects", J::Obj(fields)),
        ("empty", J::Bool(!known)),
        ("groups", J::Arr(groups.within.iter().map(|g| J::tid(*g)).collect())),
        ("subgroup_of", J::Arr(groups.subgroup_of.iter().map(|g| J::tid(*g)).collect())),
        ("role", J::opt(role.map(|r| J::str(role_text(r))))),
        ("created", J::opt(created.map(stamp_json))),
        ("changed", J::opt(changed.map(stamp_json))),
    ]);
    ctx.emit(&lines, j)
}

fn stamp_json(c: osis::ThingStamp) -> J {
    J::obj([("commit", J::str(c.id.to_string())), ("actor", J::tid(c.actor)), ("ts", J::int(c.written.0))])
}

/// A change's line; its value printed by type `ty`, else by its aspect's.
fn change_line(ctx: &Ctx<'_>, c: &Change<Value>, ty: Ty<'_>) -> String {
    let key = ctx.aspect_key(c.ak.as_str()).ok();
    let own = key.as_ref().and_then(DynamicAspectKey::value_type).map(|t| t.get());
    let ty = ty.or(own.as_ref());
    let (src, info) = match &c.origin {
        Origin::Initial => ("initial", None),
        Origin::Local(i) => ("local", Some(i)),
        Origin::Remote(i) => ("remote", Some(i)),
        Origin::Derived(_) => ("derived", None),
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
            ("origin", J::str(src)),
            ("commit", J::opt(info.map(|i| J::str(i.id.to_string())))),
            ("actor", J::opt(info.map(|i| J::tid(i.actor)))),
            ("ts", J::opt(info.map(|i| J::int(i.written.0)))),
            ("value", vj),
        ])
        .text()
    } else {
        let d = |o: Option<String>| o.unwrap_or_else(|| "-".into());
        format!(
            "{src} {} {} {} {vt}",
            d(info.map(|i| i.actor.to_uri())),
            d(info.map(|i| ts_text(ctx.g.raw, i.written.0))),
            c.ak.as_str()
        )
    }
}

/// Prints lines from `rx` until `count` lines, the timeout, or the senders are gone.
pub(crate) fn stream_lines(ctx: &mut Ctx<'_>, rx: &mpsc::Receiver<String>, count: Option<usize>, timeout: Option<Duration>) -> anyhow::Result<()> {
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

fn watch(ctx: &mut Ctx<'_>, t: &str, ak: Option<&str>, path: Option<&str>, count: Option<usize>) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let t = ctx.tid(t)?;
    let (tx, rx) = mpsc::channel::<Change<Value>>();
    let f = move |_: &Osis, c| {
        let _ = tx.send(c);
    };
    // the type the values print by: the aspect's, or the one at the path
    let mut pty = None;
    let _sub = match ak {
        Some(ak) => {
            let a = parse_ak(ak, "AK")?;
            if a.signal() {
                return Err(usage(format!("{ak} is a signal: it has no value to watch; `fired T AK --follow` prints its fires")));
            }
            let key = ctx.aspect_key(ak)?;
            match path {
                None | Some("") => {
                    pty = key.value_type().map(|t| t.get());
                    db.at(t, DynamicAspectKey::untyped(a)).on_change(f)?
                }
                Some(p) => {
                    let p = write::path(ctx, t, &key, p, false)?;
                    pty = key.value_type().map(|t| t.get()).and_then(|t| text::type_at_path(t, &p.0));
                    db.at(t, key).path(p).on_change::<Value>(f)?
                }
            }
        }
        None => db.on_thing_change(t, f)?,
    };
    let timeout = ctx.timeout_or(None)?;
    stream(ctx, &rx, count, timeout, "change", false, |ctx, c| (change_line(ctx, &c, pty.as_ref()), !matches!(c.origin, Origin::Initial)))
}

const KINDS: [(&str, CommitKind); 4] =
    [("content", CommitKind::Content), ("revert", CommitKind::Revert), ("role", CommitKind::Role), ("snapshot", CommitKind::Snapshot)];

fn kind_of(s: &str) -> anyhow::Result<CommitKind> {
    KINDS.iter().find(|k| k.0 == s).map(|k| k.1).ok_or_else(|| usage(format!("unknown commit kind {s:?}: content, revert, role or snapshot")))
}

fn kind_text(k: CommitKind) -> &'static str {
    KINDS.iter().find(|x| x.1 == k).map_or("?", |x| x.0)
}

/// A place printed by `writes` or `fired`.
fn parse_pos(s: &str) -> anyhow::Result<osis::CommitPos> {
    s.parse().map_err(|_| usage(format!("not a place printed by writes or fired: {s:?}")))
}

/// Where `writes` and `fired` list.
enum Listed {
    Writes(osis::Scope),
    Fired(Tid, osis::Ak),
    /// A fire's versions (`fired --versions-of`).
    Versions(Tid, osis::Ak, CommitId),
}

/// A page of the commits at `at`, or with `--follow` each that reads otherwise from now on.
fn listing(ctx: &mut Ctx<'_>, at: &Listed, l: &ListArgs) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    if l.follow {
        let (tx, rx) = mpsc::channel::<osis::CommitEvent>();
        let f = move |_: &Osis, e| {
            let _ = tx.send(e);
        };
        let _sub = match at {
            Listed::Writes(s) => db.on_write(s, f)?,
            Listed::Fired(t, ak) | Listed::Versions(t, ak, _) => db.at(*t, DynamicAspectKey::untyped(ak.clone())).on_fire(f)?,
        };
        let timeout = ctx.timeout_or(None)?;
        return stream(ctx, &rx, l.count, timeout, "commit", false, |ctx, e| match e {
            osis::CommitEvent::Commit { commit: Some(c), .. } => (commit_line(ctx, &c), true),
            osis::CommitEvent::Commit { id, commit: None } => (format!("{id} not-listed"), true),
            osis::CommitEvent::Reread => ("reread".to_string(), false),
            osis::CommitEvent::Ended(e) => (format!("ended: {e}"), false),
        });
    }
    let from = match (&l.before, &l.after) {
        (Some(p), _) => osis::CommitFrom::Before(parse_pos(p)?),
        (_, Some(p)) => osis::CommitFrom::After(parse_pos(p)?),
        _ if l.oldest => osis::CommitFrom::Oldest,
        _ => osis::CommitFrom::Newest,
    };
    let q = CommitQuery {
        from,
        limit: Some(l.max),
        actors: l.actor.iter().map(|a| ctx.tid(a)).collect::<anyhow::Result<_>>()?,
        kinds: l.kind.iter().map(|k| kind_of(k)).collect::<anyhow::Result<_>>()?,
        reverts: l.reverts.as_deref().map(parse_id).transpose()?,
        reverted_by: l.reverted_by.as_deref().map(parse_id).transpose()?,
        in_effect: l.in_effect,
    };
    let page = match at {
        Listed::Writes(s) => db.writes(s, &q)?,
        Listed::Fired(t, ak) => db.at(*t, DynamicAspectKey::untyped(ak.clone())).fired(&q)?,
        Listed::Versions(t, ak, c) => db.at(*t, DynamicAspectKey::untyped(ak.clone())).versions(*c, &q)?,
    };
    let lines: Vec<String> = page.commits.iter().map(|c| commit_line(ctx, c)).collect();
    let commits = J::Arr(page.commits.iter().map(commit_j).collect());
    ctx.emit(&lines, J::obj([("commits", commits), ("more", J::Bool(page.more)), ("complete", J::Bool(page.complete))]))
}

fn body_text(b: &osis::Body<Value>) -> String {
    match b {
        osis::Body::Held(Some(v)) => format!("{v:?}"),
        osis::Body::Held(None) => "held-empty".to_string(),
        osis::Body::TooLarge { .. } => "too-large".to_string(),
        osis::Body::Purged { by, actor } => format!("purged={} by={}", by, actor.map_or_else(|| "?".to_string(), |a| a.to_uri())),
        osis::Body::NotFetched => "not-fetched".to_string(),
    }
}

/// One line per commit: place, ts, actor, node, kind, in effect or reverted, what it reverts, then
/// each part `T/AK valid|invalid body`.
fn commit_line(ctx: &Ctx<'_>, c: &osis::Commit) -> String {
    let i = &c.stamp;
    let mut l = format!("{} {} {} {} {}", c.pos(), ts_text(ctx.g.raw, i.written.0), i.actor.to_uri(), kind_text(c.kind), if c.in_effect { "in-effect" } else { "reverted" });
    if let Some(r) = &c.reverts {
        l += &format!(" reverts={r}");
    }
    for (t, ak, p) in c.parts() {
        l += &format!(" | {}{} {} {}", t.to_uri(), ak.as_str(), if p.valid { "valid" } else { "invalid" }, body_text(&p.body));
        if let Some(e) = &p.edited {
            l += &format!(" edited={e}");
        }
    }
    l
}

fn commit_j(c: &osis::Commit) -> J {
    let i = &c.stamp;
    let parts = c.parts().map(|(t, ak, p)| J::obj([("thing", J::tid(t)), ("ak", J::str(ak.as_str())), ("valid", J::Bool(p.valid)), ("body", J::str(body_text(&p.body))), ("edited", p.edited.map_or(J::Null, |e| J::str(e.to_string())))])).collect();
    J::obj([
        ("pos", J::str(c.pos().to_string())),
        ("commit", J::str(i.id.to_string())),
        ("ts", J::int(i.written.0)),
        ("received", J::int(i.received.0)),
        ("actor", J::tid(i.actor)),
        ("kind", J::str(kind_text(c.kind))),
        ("in_effect", J::Bool(c.in_effect)),
        ("reverts", J::opt(c.reverts.as_ref().map(|r| J::str(r.to_string())))),
        ("reverted_by", J::Arr(c.reverted_by.iter().map(|r| J::str(r.to_string())).collect())),
        ("parts", J::Arr(parts)),
    ])
}

fn undo(ctx: &mut Ctx<'_>, s: &Scope, redo: bool) -> anyhow::Result<()> {
    let sc = scope(ctx, s)?;
    let r = if redo { ctx.db.redo(&sc)? } else { ctx.db.undo(&sc)? };
    match r {
        Some(c) => emit_commit(ctx, Some(c.stamp.id)),
        None => Err(exit(3, if redo { "nothing to redo" } else { "nothing to undo" })),
    }
}

fn grants_lines(r: &osis::Grants, raw: bool) -> Vec<String> {
    r.iter()
        .map(|(m, e)| {
            let until = e.until.map_or("-".into(), |u| ts_text(raw, u.0));
            format!("{} {} {} {}{}", m.to_uri(), role_text(e.role), until, e.may_grant.map_or("-", role_text), if e.with_membership { " with-membership" } else { "" })
        })
        .collect()
}

fn grants_json(r: &osis::Grants) -> J {
    J::Arr(
        r.iter()
            .map(|(m, e)| J::obj([("actor", J::tid(*m)), ("role", J::str(role_text(e.role))), ("until", J::opt(e.until.map(|u| J::int(u.0)))), ("may_grant", J::opt(e.may_grant.map(|r| J::str(role_text(r))))), ("with_membership", J::Bool(e.with_membership))]))
            .collect(),
    )
}

fn grants(ctx: &mut Ctx<'_>, t: &str) -> anyhow::Result<()> {
    let r = ctx.db.grants(ctx.tid(t)?)?;
    let lines = grants_lines(&r, ctx.g.raw);
    ctx.emit(&lines, grants_json(&r))
}

fn status(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let s = ctx.db.status()?;
    let lines = status_lines(&s, ctx.g.raw);
    ctx.emit(&lines, status_json(&s))
}

fn status_lines(s: &osis::Status, raw: bool) -> Vec<String> {
    let groups = s.groups.iter().map(|(g, x)| {
        format!("{} {:?} {}", g.to_uri(), x.state, x.last_sync.map_or("-".into(), |t| ts_text(raw, t.0)))
    });
    // writes on these are refused until a group moves (Osis::group_source)
    std::iter::once(format!("connected {}", s.connected)).chain(groups).chain(s.two_sources.iter().map(|t| format!("{} two sources: writes refused", t.to_uri()))).collect()
}

fn status_json(s: &osis::Status) -> J {
    let groups = s.groups.iter().map(|(g, x)| J::obj([("group", J::tid(*g)), ("state", J::str(format!("{:?}", x.state))), ("last_sync", J::opt(x.last_sync.map(|t| J::int(t.0))))]));
    J::obj([("groups", J::Arr(groups.collect())), ("connected", J::int(s.connected as u64)), ("two_sources", J::Arr(s.two_sources.iter().map(|t| J::tid(*t)).collect()))])
}

/// One diagnostic as `diag` prints it (text or a JSON line): its kind, what it names, its detail.
fn diag_line(d: &osis::Diagnostic, json: bool) -> String {
    use osis::Diagnostic as D;
    let (kind, tids, commit, peer, detail): (&str, Vec<Tid>, Option<osis::CommitId>, Option<Tid>, &str) = match d {
        D::NotSynced { thing, group, detail } => ("NotSynced", std::iter::once(*thing).chain(*group).collect(), None, None, detail),
        D::Uncommitted { thing, detail } => ("Uncommitted", vec![*thing], None, None, detail),
        D::OwnWriteInvalid { commit, things, detail } => ("OwnWriteInvalid", things.clone(), Some(*commit), None, detail),
        D::Mismatch { thing, detail } => ("Mismatch", vec![*thing], None, None, detail),
        D::Unreadable { thing, detail } => ("Unreadable", vec![*thing], None, None, detail),
        D::LostAccess { actor, detail } => ("LostAccess", vec![*actor], None, None, detail),
        D::Stranded { group, detail } => ("Stranded", vec![*group], None, None, detail),
        D::EphemeralRefused { things, detail } => ("EphemeralRefused", things.clone(), None, None, detail),
        D::Storage { detail } => ("Storage", vec![], None, None, detail),
        D::Callback { detail } => ("Callback", vec![], None, None, detail),
        D::SyncStopped { detail } => ("SyncStopped", vec![], None, None, detail),
        D::Parked { things, commit, peer, detail } => ("Parked", things.clone(), *commit, *peer, detail),
        D::Handled { things, commit, peer, detail } => ("Handled", things.clone(), *commit, *peer, detail),
        other => ("Other", vec![], None, None, Box::leak(other.to_string().into_boxed_str())),
    };
    if json {
        J::obj([
            ("kind", J::str(kind)),
            ("tids", J::Arr(tids.iter().map(|t| J::tid(*t)).collect())),
            ("commit", J::opt(commit.as_ref().map(|c| J::str(c.to_string())))),
            ("peer", J::opt(peer.map(J::tid))),
            ("detail", J::str(detail)),
        ])
        .text()
    } else {
        let tids: Vec<String> = tids.iter().map(Tid::to_uri).collect();
        format!("{kind} {} {detail}", tids.join(","))
    }
}

/// Prints diagnostics until `timeout` (`Some(0)`: those so far). `best_effort` (`serve`): a
/// failed write (a closed stdout) is ignored, the command goes on.
fn diag(ctx: &mut Ctx<'_>, timeout: Option<Duration>, best_effort: bool) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let json_out = ctx.g.json;
    let (tx, rx) = mpsc::channel::<String>();
    // a dead sync driver ends the stream (after its line) and the command fails
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let st = stopped.clone();
    let mut tx = Some(tx);
    let _sub = db.on_diagnostic(move |_, d| {
        if let Some(t) = &tx {
            let _ = t.send(diag_line(&d, json_out));
        }
        if matches!(d, osis::Diagnostic::SyncStopped { .. }) {
            st.store(true, std::sync::atomic::Ordering::Release);
            tx = None;
        }
    })?;
    db.settle();
    if timeout == Some(Duration::ZERO) {
        while let Ok(l) = rx.try_recv() {
            ctx.line(&l)?;
        }
        return Ok(());
    }
    stream(ctx, &rx, None, timeout, "line", best_effort, |_, l| (l, true))?;
    if stopped.load(std::sync::atomic::Ordering::Acquire) {
        return Err(exit(6, "sync stopped"));
    }
    Ok(())
}

/// Copies diagnostics to `err` while it lives (`-v` on a command that syncs): best effort.
struct Verbose {
    tx: Arc<std::sync::Mutex<Option<mpsc::Sender<String>>>>,
    _sub: osis::Subscription,
}

impl Verbose {
    /// Subscribes; the lines go to the receiver, drained by the caller's thread.
    fn start(db: &Osis, json: bool) -> anyhow::Result<(Verbose, mpsc::Receiver<String>)> {
        let (tx, rx) = mpsc::channel();
        let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
        let t = tx.clone();
        let sub = db.on_diagnostic(move |_, d| {
            if let Some(tx) = t.lock().ok().as_ref().and_then(|g| g.as_ref()) {
                let _ = tx.send(diag_line(&d, json));
            }
        })?;
        Ok((Verbose { tx, _sub: sub }, rx))
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
            lines.push(format!("tid {} known={} role={}", t.to_uri(), db.has_content(t)?, db.role_on(t)?.map_or("none", role_text)));
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
                    lines.push(format!("  commit {} kind={:?} ts={} actor={} node={}{}", commit_text(&c.id), h.kind, h.ts.wall_ms().0, h.actor.to_uri(), h.author.to_uri(), h.undoes.map_or(String::new(), |u| format!(" undoes={}", commit_text(&u)))));
                }
                if let Some(f) = frag {
                    lines.push(format!("  state {f}"));
                }
            }
            for g in db.groups_of(t)?.within {
                lines.push(format!("group {}", g.to_uri()));
            }
            for (m, e) in db.grants(t)? {
                lines.push(format!("holder {} {:?}", m.to_uri(), e));
            }
        }
        InspectCmd::Group { g } => {
            let g = ctx.tid(&g)?;
            let all = db.engine(|e| e.all_aspects())?;
            let mut things: Vec<Tid> = all.into_iter().map(|(t, _)| t).collect();
            things.dedup();
            for t in things {
                if db.groups_of(t)?.within.contains(&g) {
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
            for (m, e) in db.grants(a)? {
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

/// How long `serve` waits to start listening. Listening is local (milliseconds); at 0 it
/// never prints its address, at infinity a stuck listen hangs the command silently.
const SERVING_START_WAIT: Duration = Duration::from_secs(30);

/// What `serve` listens on when serving with no listen URL (osis's default port, spec/sync.md §10).
const DEFAULT_LISTEN: &str = "quic://0.0.0.0:4040";

fn serve(ctx: &mut Ctx<'_>, serving: ServingFlags, client_listen: &[String]) -> anyhow::Result<()> {
    let client_listen = client_listen.iter().map(|u| u.parse()).collect::<osis::Result<Vec<osis::Url>>>()?;
    let db = ctx.db.clone();
    // other invocations on this store become its clients (notes/cli.md Design)
    crate::listen(&ctx.sel, &db)?;
    if serving.any() {
        set_serving(ctx, serving)?;
    }
    if let Some(mut h) = db.serving()? {
        if h.listen.is_empty() {
            h.listen = vec![DEFAULT_LISTEN.parse()?];
            db.set_serving(Some(h))?;
        }
        let until = std::time::Instant::now() + SERVING_START_WAIT;
        let a = loop {
            if let Some(a) = db.serving_address().map_err(|e| exit(6, format!("serving: {e}")))? {
                break a;
            }
            if std::time::Instant::now() >= until {
                return Err(exit(6, "serving: did not start listening"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        ctx.emit(&[a.to_string()], J::obj([("address", J::str(a.to_string()))]))?;
        ctx.out.flush()?;
    }
    if !client_listen.is_empty() {
        for a in db.client_listen(&client_listen)? {
            let a = a.to_string();
            ctx.emit(&[format!("client {a}")], J::obj([("client", J::str(a.clone()))]))?;
        }
        ctx.out.flush()?;
    }
    // the address line above is a hard failure; the diagnostics after it are best effort (a
    // caller that read only the address and closed the pipe does not end it)
    let t = ctx.timeout_or(None)?;
    diag(ctx, t, true)
}

/// Sets the terms of serving: each flag given replaces its field (one `''` clears it), the rest kept;
/// starts serving (`own`, no listener) when it was off.
fn set_serving(ctx: &mut Ctx<'_>, f: ServingFlags) -> anyhow::Result<()> {
    let db = ctx.db.clone();
    let mut h = db.serving()?.unwrap_or_default();
    // a flag given once as '' clears its field; otherwise its values replace it
    let given = |v: &[String]| (!v.is_empty()).then(|| v.iter().filter(|x| !(v.len() == 1 && x.is_empty())).cloned().collect::<Vec<_>>());
    if let Some(v) = given(&f.listen) {
        h.listen = v.iter().map(|u| u.parse()).collect::<osis::Result<_>>()?;
    }
    if let Some(a) = f.admit {
        h.admit = match a {
            AdmitArg::Own => osis::Admit::Own,
            AdmitArg::Open => osis::Admit::Open,
        };
    }
    if let Some(v) = given(&f.admitted) {
        h.admitted = BTreeSet::new();
        for l in v {
            h.admitted.extend(sync_ids(ctx, &l)?);
        }
    }
    if let Some(v) = given(&f.replicate) {
        h.replicate = peers(ctx, &v)?;
    }
    if let Some(v) = given(&f.policy) {
        h.policy = osis::ServingPolicy::default();
        for p in v {
            let (k, n) = p.split_once('=').ok_or_else(|| usage(format!("not NAME=N: {p}")))?;
            osis::internals::host_limit(&mut h.policy, k, n.parse().map_err(|_| usage(format!("not NAME=N: {p}")))?).map_err(Error::Invalid)?;
        }
    }
    if let Some(v) = given(&f.cap) {
        h.caps = BTreeMap::new();
        for c in v {
            let bad = || usage(format!("not GROUP|ID=ENTRIES,BYTES: {c}"));
            let (l, n) = c.rsplit_once('=').ok_or_else(bad)?;
            let (e, b) = n.split_once(',').ok_or_else(bad)?;
            let caps = osis::ServingCaps { entries: e.parse().map_err(|_| bad())?, bytes: b.parse().map_err(|_| bad())? };
            for id in sync_ids(ctx, l)? {
                h.caps.insert(id, caps);
            }
        }
    }
    Ok(db.set_serving(Some(h))?)
}

/// `clients add|ls|rm|rotate` (notes/cli.md): `clients^.0` of this node.
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
        ClientsCmd::RotateAddress => {
            let a: Vec<String> = ctx.db.rotate_client_address()?.iter().map(ToString::to_string).collect();
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

/// The terms of serving as lines (`listen URL`, `address URL#KEY` per listen URL but a port 0, `admit own|open`, `admitted ID`, `replicate ADDR`,
/// `policy NAME N`, `cap ID ENTRIES BYTES`) or one JSON object; exit 3 when not serving.
fn serving_show(ctx: &mut Ctx<'_>) -> anyhow::Result<()> {
    let h = ctx.db.serving()?.ok_or_else(|| exit(3, "not serving"))?;
    let admit = match h.admit {
        osis::Admit::Own => "own",
        osis::Admit::Open => "open",
    };
    // the address each listen URL will have; none for a port 0 (picked only when it listens)
    let addrs: Vec<String> = match ctx.db.serving_key()? {
        Some(k) => h.listen.iter().map(|u| osis::Address::new(u, k).to_string()).filter(|a| !a.split('#').next().is_some_and(|u| u.ends_with(":0"))).collect(),
        None => vec![],
    };
    let mut lines: Vec<String> = h.listen.iter().map(|u| format!("listen {u}")).collect();
    lines.extend(addrs.iter().map(|a| format!("address {a}")));
    lines.push(format!("admit {admit}"));
    lines.extend(h.admitted.iter().map(|l| format!("admitted {l}")));
    lines.extend(h.replicate.iter().map(|a| format!("replicate {a}")));
    let knobs = policy_lines(&h.policy);
    lines.extend(knobs.iter().map(|(k, n)| format!("policy {k} {n}")));
    lines.extend(h.caps.iter().map(|(l, c)| format!("cap {l} {} {}", c.entries, c.bytes)));
    let j = J::obj([
        ("listen", J::Arr(h.listen.iter().map(|u| J::str(u.to_string())).collect())),
        ("addresses", J::Arr(addrs.iter().map(|a| J::str(a.clone())).collect())),
        ("admit", J::str(admit)),
        ("admitted", J::Arr(h.admitted.iter().map(|l| J::str(l.to_string())).collect())),
        ("replicate", J::Arr(h.replicate.iter().map(|a| J::str(a.to_string())).collect())),
        ("policy", J::Obj(knobs.iter().map(|(k, n)| (k.clone(), J::int(*n))).collect())),
        ("caps", J::Obj(h.caps.iter().map(|(l, c)| (l.to_string(), J::obj([("entries", J::int(c.entries)), ("bytes", J::int(c.bytes))]))).collect())),
    ]);
    ctx.emit(&lines, j)
}

/// The limits set apart from the defaults, by name.
fn policy_lines(p: &osis::ServingPolicy) -> BTreeMap<String, u64> {
    let d = osis::ServingPolicy::default();
    let plain = [("group_entries", p.group_entries, d.group_entries), ("group_bytes", p.group_bytes, d.group_bytes), ("groups", p.groups, d.groups), ("entries", p.entries, d.entries), ("bytes", p.bytes, d.bytes), ("connections", p.connections as u64, d.connections as u64)];
    plain.into_iter().filter(|(_, v, def)| v != def).map(|(k, v, _)| (k.to_string(), v)).chain(osis::internals::host_limits_unshown(p)).collect()
}

/// A sync ID, or a group synced here: its IDs.
fn sync_ids(ctx: &mut Ctx<'_>, s: &str) -> anyhow::Result<Vec<osis::SyncId>> {
    if let Ok(id) = s.parse() {
        return Ok(vec![id]);
    }
    let g = ctx.tid(s).map_err(|_| usage(format!("not a group or a sync ID (32 hex digits): {s}")))?;
    // an account syncs under its home group
    let g = if g == ctx.db.me() { ctx.db.home() } else { g };
    let ls = ctx.db.sync_ids(g)?;
    if ls.is_empty() {
        return Err(exit(3, format!("{s} is not synced here: give its sync ID (`osis serving ids` on a node that reads it)")));
    }
    Ok(ls)
}

/// Reads and parses a schema file (exit 7 when it does not parse); returns its file name too.
fn read_schema(file: &std::path::Path) -> anyhow::Result<(String, osis_schema::Schema)> {
    let src = std::fs::read_to_string(file).map_err(|e| usage(format!("{}: {e}", file.display())))?;
    let name = file.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let s = osis_schema::parse(&name, &src).map_err(|e| exit(7, e.to_string()))?;
    Ok((name, s))
}

fn schema_check(g: &crate::args::Global, file: &std::path::Path, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    let (_, s) = read_schema(file)?;
    if g.json {
        writeln!(out, "{}", J::obj([("revision", J::int(s.revision))]).text())?;
    } else {
        writeln!(out, "ok revision {}", s.revision)?;
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
    // notes/api.md Sync configuration and status: `leave` and `card show` wait on the thing they touch, so an unrelated
    // group with nobody connected does not end them in exit 6.
    #[test]
    fn leave_and_card_show_wait_on_what_they_touch() {
        use super::{CardCmd, Cmd, Delivers, delivery_of};
        assert!(matches!(delivery_of(&Cmd::Leave { t: "x".into(), holder: None }), Delivers::Thing(t) if t == "x"));
        assert!(matches!(delivery_of(&Cmd::Card(CardCmd::Show)), Delivers::Profile));
    }

    // notes/cli.md Network: only a command that stays up is on the LAN; a short one never announces.
    #[test]
    fn only_commands_that_stay_up_announce_notes_cli() {
        use crate::Network::{Node, None, Sync};
        use clap::Parser;
        for (args, want) in [
            (&["osis", "serve"][..], Node),
            (&["osis", "pair", "join", "x"], Node),
            (&["osis", "diag", "--follow"], Node),
            (&["osis", "status", "--watch"], Node),
            (&["osis", "status"], Sync),
            (&["osis", "diag"], None),
            (&["osis", "link", "make", "t", "read"], Sync),
            (&["osis", "sync"], Sync),
            (&["osis", "get", "t", "a:b.0"], None),
        ] {
            let cli = crate::args::Cli::try_parse_from(args).unwrap();
            assert!(super::network(&cli.cmd) == want, "{args:?}");
        }
    }

    // notes/cli.md Network: `--no-lan`, on any command that stays up, keeps it off the LAN.
    #[test]
    fn no_lan_keeps_a_node_off_the_lan_notes_cli() {
        use clap::Parser;
        for args in [&["osis", "--no-lan", "watch", "t", "a:b.0"][..], &["osis", "serve", "--no-lan"], &["osis", "--no-lan", "pair", "join", "x"]] {
            let cli = crate::args::Cli::try_parse_from(args).unwrap();
            assert!(matches!(crate::config(&cli.g, super::network(&cli.cmd)).lan, osis::Lan::Off), "{args:?}");
        }
        let cli = crate::args::Cli::try_parse_from(["osis", "serve"]).unwrap();
        assert!(matches!(crate::config(&cli.g, super::network(&cli.cmd)).lan, osis::Lan::On { .. }));
    }

    // notes/cli.md Command table: `status` shows split things apart from groups, in both forms.
    #[test]
    fn status_lists_things_with_two_sources_apart_notes_cli() {
        let t = osis::Tid::from_bytes([7; 15]);
        let mut s = osis::Status::default();
        s.two_sources.insert(t);
        assert_eq!(super::status_lines(&s, true), vec!["connected 0".to_string(), format!("{} two sources: writes refused", t.to_uri())]);
        assert_eq!(super::status_json(&s).text(), format!("{{\"groups\":[],\"connected\":0,\"two_sources\":[\"{}\"]}}", t.to_uri()));
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
    }
}
