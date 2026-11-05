//! osis-cli: the command-line tool `osis` over the `osis` API, for scripts, debugging and agents.
//! One invocation opens the store, acts, closes. Text forms that read back what they print,
//! `--json` for machines, exit codes by error category. Design: notes/cli.md.
//! Layer 9 (notes/architecture.md).
#![forbid(unsafe_code)]
// The binary's crate: panics on programmer errors are allowed (notes/architecture.md §3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod args;
mod chat;
mod cmd;
pub mod json;
pub mod text;
mod write;

use anyhow::anyhow;
use args::{Cli, Global};
use clap::Parser;
use json::J;
use osis::{AppConfig, Config, Error, Key, MemStore, Osis, Store, Tid};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A failure with its exit code (notes/cli.md Exit codes); an empty message prints nothing.
#[derive(Debug)]
pub struct Exit(pub i32, pub String);

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.1)
    }
}
impl std::error::Error for Exit {}

pub(crate) fn exit(code: i32, m: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Exit(code, m.into()))
}
pub(crate) fn usage(m: impl Into<String>) -> anyhow::Error {
    exit(2, m)
}

/// Exit code and kind of an API error (notes/cli.md Exit codes).
pub fn category(e: &Error) -> (i32, &'static str) {
    match e {
        Error::UnknownThing { .. } => (3, "UnknownThing"),
        Error::UnknownActor { .. } => (3, "UnknownActor"),
        Error::Permission { .. } => (4, "Permission"),
        Error::Refused(_) => (4, "Refused"),
        Error::TooLarge { .. } => (5, "TooLarge"),
        Error::Type { .. } => (5, "Type"),
        Error::Network(_) => (6, "Network"),
        Error::Unsynced { .. } => (6, "Unsynced"),
        Error::OutcomeUnknown => (6, "OutcomeUnknown"),
        Error::Invalid(_) => (7, "Invalid"),
        Error::NotUndoable { .. } => (1, "NotUndoable"),
        Error::Storage(_) => (1, "Storage"),
        Error::Unsupported(_) => (1, "Unsupported"),
        Error::Closed => (1, "Closed"),
    }
}

/// Where the store lives: a directory, or (tests) a memory store.
#[derive(Clone, Debug)]
pub enum StoreSel {
    Dir(PathBuf),
    Memory(MemStore),
}

/// Standard streams of one invocation.
pub struct Io<'a> {
    pub stdin: &'a mut dyn BufRead,
    pub stdout: &'a mut dyn Write,
    /// Sent to the thread that prints `-v` diagnostics.
    pub stderr: &'a mut (dyn Write + Send),
    /// stdin is a terminal (`edit` opens `$EDITOR`).
    pub tty: bool,
}

/// Runs one invocation (args include the binary name); returns the exit code.
pub fn main_with<I, T>(args: I, stdin: &mut dyn BufRead, stdout: &mut dyn Write, stderr: &mut (dyn Write + Send)) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run(args, None, Io { stdin, stdout, stderr, tty: false })
}

/// `main_with` with an explicit store (a memory store in tests) and terminal flag.
pub fn run<I, T>(args: I, store: Option<StoreSel>, io: Io<'_>) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { 2 } else { 0 };
            let s = e.render().to_string();
            let _ = if code == 0 { io.stdout.write_all(s.as_bytes()) } else { io.stderr.write_all(s.as_bytes()) };
            return code;
        }
    };
    let json = cli.g.json;
    let Io { stdin, stdout, stderr, tty } = io;
    let r = cmd::dispatch(cli, store, stdin, stdout, &mut *stderr, tty);
    let _ = stdout.flush();
    match r {
        Ok(()) => 0,
        Err(e) => report(&e, json, stderr),
    }
}

fn report(e: &anyhow::Error, json: bool, err: &mut dyn Write) -> i32 {
    let (code, kind, msg, tid, needs) = if let Some(x) = e.downcast_ref::<Exit>() {
        (x.0, if x.0 == 2 { "Usage" } else { "Cli" }, if x.1.is_empty() { String::new() } else { format!("{e:#}") }, None, None)
    } else if let Some(a) = e.downcast_ref::<Error>() {
        let (c, k) = category(a);
        let (tid, needs) = match a {
            Error::UnknownThing { tid } | Error::UnknownActor { tid } => (Some(*tid), None),
            Error::Permission { tid, needs } => (Some(*tid), Some(cmd::role_text(*needs))),
            _ => (None, None),
        };
        (c, k, format!("{e:#}"), tid, needs)
    } else {
        (1, "Other", format!("{e:#}"), None, None)
    };
    if msg.is_empty() {
        return code;
    }
    let line = if json {
        J::obj([("error", J::obj([("kind", J::str(kind)), ("message", J::str(msg)), ("tid", J::opt(tid.map(J::tid))), ("needs", J::opt(needs.map(J::str)))]))]).text()
    } else {
        format!("error: {msg}")
    };
    let _ = writeln!(err, "{line}");
    code
}

/// The default store: `$XDG_DATA_HOME/osis/default` (or `~/.local/share/osis/default`).
fn default_store() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_DATA_HOME") {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var_os("HOME").ok_or_else(|| usage("no --store and no $HOME"))?).join(".local/share"),
    };
    Ok(base.join("osis/default"))
}

fn store_sel(g: &Global, given: Option<StoreSel>) -> anyhow::Result<StoreSel> {
    match (given, &g.store) {
        (Some(s), _) => Ok(s),
        (None, Some(d)) => Ok(StoreSel::Dir(d.clone())),
        (None, None) => Ok(StoreSel::Dir(default_store()?)),
    }
}

/// The store selected.
pub(crate) fn store_of(sel: &StoreSel) -> Store {
    match sel {
        StoreSel::Dir(d) => Store::Dir(d.clone()),
        StoreSel::Memory(m) => Store::Memory(m.clone()),
    }
}

/// The config of a command holding a store; `net`: sync runs (`Runtime::Own` over QUIC) while the
/// command runs, else the command stays local (`Runtime::None`).
fn config(g: &Global, net: bool) -> Config {
    let mut c = Config { app: app_config(g), ..Config::default() };
    if net {
        c.runtime = osis::Runtime::Own;
    }
    c
}

/// The config of a command using a node out of process.
fn app_config(g: &Global) -> AppConfig {
    let mut c = AppConfig::default();
    if let Some(l) = g.limit {
        c.read_limit = l;
    }
    c
}

/// How long connecting to a node waits, by `--timeout`.
fn connect_wait(g: &Global) -> anyhow::Result<Option<Duration>> {
    timeout_of(g, Some(DEFAULT_WAIT))
}

/// The connection `--remote ADDR --remote-secret FILE` asks for.
fn remote_flags(g: &Global) -> anyhow::Result<Option<osis::NodeLogin>> {
    let (Some(addr), Some(file)) = (&g.remote, &g.remote_secret) else { return Ok(None) };
    Ok(Some(osis::NodeLogin { addr: addr.parse()?, secret: read_secret(file)? }))
}

/// A client's secret file: 64 hex digits.
fn read_secret(file: &Path) -> anyhow::Result<osis::ClientSecret> {
    let text = std::fs::read_to_string(file).map_err(|e| exit(8, format!("{}: {e}", file.display())))?;
    let bytes = osis_schema::osis_base::hex::decode(text.trim()).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| usage(format!("{}: not 64 hex digits", file.display())))?;
    Ok(osis::ClientSecret::from_bytes(bytes))
}

const PID_FILE: &str = "pid";
const SCHEMAS_FILE: &str = "cli.toml";

/// Maps the store's lock failure to exit 8 with the holder's pid.
fn lock_err(dir: &Path, e: Error) -> anyhow::Error {
    match &e {
        Error::Storage(m) if m.contains("already open") => {
            let pid = std::fs::read_to_string(dir.join(PID_FILE)).map(|p| p.trim().to_string()).unwrap_or_else(|_| "?".into());
            exit(8, format!("store in use by pid {pid}"))
        }
        _ => e.into(),
    }
}

/// Opens an existing store (exit 8 when missing or locked). Locked by a daemon (`osis serve`)
/// whose socket answers, the invocation is that daemon's client instead (`use_daemon`, unless the
/// command must hold the store itself: `inspect`).
fn open(sel: &StoreSel, g: &Global, net: bool, use_daemon: bool) -> anyhow::Result<Osis> {
    if g.node.is_some() {
        return if use_daemon { client_of_node(g) } else { Err(usage("this command holds a store: not with --node")) };
    }
    match sel {
        StoreSel::Dir(d) => {
            if !d.join("db.redb").exists() {
                return Err(exit(8, format!("no store at {} (run osis init)", d.display())));
            }
            let login = remote_flags(g)?;
            let db = match Osis::open(store_of(sel), config(g, net)) {
                Ok(db) => db,
                Err(Error::Storage(m)) if use_daemon && m.contains("already open") => match daemon(d, g) {
                    Some(db) => return Ok(db),
                    None => return Err(lock_err(d, Error::Storage(m))),
                },
                Err(e) => return Err(lock_err(d, e)),
            };
            let _ = std::fs::write(d.join(PID_FILE), std::process::id().to_string());
            if let Some(l) = login {
                match crate::cmd::within(connect_wait(g)?, db.connect_node(&l)) {
                    // a node down fails what goes there, as `Network`; the rest of the store works
                    Err(Error::Network(_)) | Ok(()) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Ok(db)
        }
        StoreSel::Memory(_) => Osis::open(store_of(sel), config(g, net)).map_err(|e| match e {
            Error::Storage(m) if m.contains("not an osis database") => exit(8, "no store (run osis init)"),
            e => e.into(),
        }),
    }
}

/// The daemon serving the store at `d`, as a client acting as the node's account
/// (notes/client-port.md §5). None when there is no live one.
fn daemon(d: &Path, g: &Global) -> Option<Osis> {
    crate::cmd::within(connect_wait(g).ok()?, Osis::connect_socket(d, app_config(g))).ok()
}

/// The node named by `--node`, as the client `--client-secret` stands for (notes/client-port.md
/// §3). No store is opened.
fn client_of_node(g: &Global) -> anyhow::Result<Osis> {
    let (Some(addr), Some(file)) = (&g.node, &g.client_secret) else { return Err(usage("--node needs --client-secret")) };
    let secret = read_secret(file)?;
    let login = osis::NodeLogin { addr: addr.parse()?, secret };
    Ok(crate::cmd::within(connect_wait(g)?, Osis::connect(&[login], app_config(g)))?)
}

/// Serves the client port while `serve` runs, on the store's socket. A memory store has none.
pub(crate) fn listen(sel: &StoreSel, db: &Osis) -> anyhow::Result<()> {
    let StoreSel::Dir(_) = sel else { return Ok(()) };
    match db.listen_socket() {
        // a socket directory another user made first (no XDG_RUNTIME_DIR, `/tmp/osis-<uid>`) costs
        // the clients, never the daemon
        Err(Error::Storage(e)) => eprintln!("warning: serving without a client socket: {e}"),
        r => r?,
    }
    Ok(())
}

/// Creates a store with its home group on `hosts`; refuses a non-empty directory. Returns the
/// recovery card (none without hosts).
fn create(sel: &StoreSel, g: &Global, hosts: Vec<osis::HostAddr>) -> anyhow::Result<(Osis, Option<osis::RecoveryCard>)> {
    if let StoreSel::Dir(d) = sel
        && d.read_dir().is_ok_and(|mut r| r.next().is_some())
    {
        return Err(exit(8, format!("{} is not empty", d.display())));
    }
    let net = !hosts.is_empty();
    let db = Osis::create(store_of(sel), &hosts, config(g, net)).map_err(|e| match sel {
        StoreSel::Dir(d) => lock_err(d, e),
        _ => e.into(),
    })?;
    if let StoreSel::Dir(d) = sel {
        let _ = std::fs::write(d.join(PID_FILE), std::process::id().to_string());
    }
    Ok(db)
}

/// Schema paths registered in `<store>/cli.toml`: `schemas = [ "path", ... ]`, one per line.
fn registered(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let text = match std::fs::read_to_string(dir.join(SCHEMAS_FILE)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow!("{}: {e}", dir.join(SCHEMAS_FILE).display())),
    };
    let mut out = Vec::new();
    for l in text.lines() {
        let l = l.trim().trim_end_matches(',');
        if l.starts_with('"') {
            match text::parse(l, None, &text::no_aliases) {
                Ok(osis::Value::Str(s)) => out.push(PathBuf::from(s)),
                _ => return Err(anyhow!("{}: bad line {l}", SCHEMAS_FILE)),
            }
        }
    }
    Ok(out)
}

fn save_registered(dir: &Path, paths: &[PathBuf]) -> anyhow::Result<()> {
    let mut s = String::from("# schemas registered by `osis schema add`\nschemas = [\n");
    for p in paths {
        s.push_str("  ");
        text::quote(&mut s, &p.to_string_lossy());
        s.push_str(",\n");
    }
    s.push_str("]\n");
    std::fs::write(dir.join(SCHEMAS_FILE), s).map_err(|e| anyhow!("{}: {e}", dir.join(SCHEMAS_FILE).display()))
}

/// Reads an argument: a literal, `@FILE`, or `-` (stdin): a secret (a recovery card, a link)
/// need not appear in the process list or shell history.
pub(crate) fn arg_text(stdin: &mut dyn BufRead, s: &str) -> anyhow::Result<String> {
    if s == "-" {
        let mut b = String::new();
        stdin.read_to_string(&mut b)?;
        Ok(b.trim_end_matches('\n').to_string())
    } else if let Some(f) = s.strip_prefix('@') {
        Ok(std::fs::read_to_string(f).map_err(|e| usage(format!("{f}: {e}")))?.trim_end_matches('\n').to_string())
    } else {
        Ok(s.to_string())
    }
}

/// One invocation's state: the open database, flags, output, script variables.
pub(crate) struct Ctx<'a> {
    pub g: Global,
    pub db: Osis,
    pub out: &'a mut dyn Write,
    pub stdin: &'a mut dyn BufRead,
    pub tty: bool,
    pub sel: StoreSel,
    pub vars: BTreeMap<String, Tid>,
    /// (tid, AK) this script wrote; AK "" for the whole thing (created or deleted).
    pub pending: std::collections::BTreeSet<(Tid, String)>,
}

impl Ctx<'_> {
    fn new<'a>(g: Global, db: Osis, sel: StoreSel, out: &'a mut dyn Write, stdin: &'a mut dyn BufRead, tty: bool) -> anyhow::Result<Ctx<'a>> {
        let mut paths = match &sel {
            // a thin client has no store, so no registered schemas
            StoreSel::Dir(_) if g.node.is_some() => Vec::new(),
            StoreSel::Dir(d) => registered(d)?,
            StoreSel::Memory(_) => Vec::new(),
        };
        paths.extend(g.schemas.iter().cloned());
        for p in paths {
            let fail = |e: &dyn std::fmt::Display| exit(7, format!("schema {}: {e}", p.display()));
            let src = std::fs::read_to_string(&p).map_err(|e| fail(&e))?;
            let name = p.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
            db.register_schema(&name, &src).map_err(|e| fail(&e))?;
        }
        Ok(Ctx { g, db, out, stdin, tty, sel, vars: BTreeMap::new(), pending: Default::default() })
    }

    pub fn line(&mut self, s: &str) -> anyhow::Result<()> {
        writeln!(self.out, "{s}")?;
        Ok(())
    }

    pub fn json(&mut self, j: &J) -> anyhow::Result<()> {
        self.line(&j.text())
    }

    /// Emits `text` lines or the JSON document.
    pub fn emit(&mut self, text: &[String], j: J) -> anyhow::Result<()> {
        if self.g.json {
            self.json(&j)
        } else {
            for l in text {
                self.line(l)?;
            }
            Ok(())
        }
    }

    /// What a call that waits on other nodes gets: the `--timeout` bound (default 30 s; `0`: none).
    pub fn wait_for(&self) -> anyhow::Result<Duration> {
        Ok(self.timeout()?.unwrap_or(Duration::MAX))
    }

    /// The `--timeout` bound (default 30 s; `0`: none).
    pub fn timeout(&self) -> anyhow::Result<Option<Duration>> {
        timeout_of(&self.g, Some(DEFAULT_WAIT))
    }

    pub fn timeout_or(&self, default: Option<Duration>) -> anyhow::Result<Option<Duration>> {
        timeout_of(&self.g, default)
    }

    /// Resolves a tid argument: `osis://…`, bare, `me`, `node`, `$var`.
    pub fn tid(&self, s: &str) -> anyhow::Result<Tid> {
        self.alias(s).or_else(|| Tid::parse(s).ok()).ok_or_else(|| usage(format!("not a tid: {s}")))
    }

    pub fn alias(&self, s: &str) -> Option<Tid> {
        match s {
            "me" => Some(self.db.me()),
            "node" => Some(self.db.node()),
            _ => s.strip_prefix('$').and_then(|v| self.vars.get(v).copied()),
        }
    }

    /// The key for an AK: typed by a registered schema unless `--raw`.
    pub fn key(&self, ak: &str) -> anyhow::Result<Key> {
        if self.g.raw {
            Ok(Key::untyped(parse_ak(ak, "AK")?))
        } else {
            self.db.key(ak).map_err(|_| usage(format!("bad AK {ak:?}")))
        }
    }

    /// Reads an argument: a literal, `@FILE`, or `-` (stdin).
    pub fn arg_text(&mut self, s: &str) -> anyhow::Result<String> {
        arg_text(&mut *self.stdin, s)
    }

    /// Parses a value argument at a type.
    pub fn value(&mut self, s: &str, ty: text::Ty<'_>) -> anyhow::Result<osis::Value> {
        let src = self.arg_text(s)?;
        let al = |w: &str| self.alias(w);
        text::parse(&src, ty, &al).map_err(|e| usage(format!("bad value {src:?}: {e}")))
    }
}

/// Waits for other nodes without `--timeout`.
pub(crate) const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// The `--timeout` bound (`0`: none), else `default`.
pub(crate) fn timeout_of(g: &Global, default: Option<Duration>) -> anyhow::Result<Option<Duration>> {
    match &g.timeout {
        None => Ok(default),
        Some(s) => Ok(Some(parse_dur(s)?).filter(|d| !d.is_zero())),
    }
}

/// An AK argument.
pub(crate) fn parse_ak(s: &str, what: &str) -> anyhow::Result<osis::Ak> {
    osis::Ak::new(s).map_err(|_| usage(format!("bad {what} {s:?}")))
}

/// An optional timestamp flag.
pub(crate) fn opt_ts(s: &Option<String>) -> anyhow::Result<Option<osis::Time>> {
    Ok(s.as_deref().map(parse_ts).transpose()?.map(osis::Time))
}

/// A duration flag: `30s`, `5m`, `1h30m`, or `0`.
pub(crate) fn parse_dur(s: &str) -> anyhow::Result<Duration> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    match text::parse_duration(s) {
        Some(ms) if ms >= 0 => Ok(Duration::from_millis(ms as u64)),
        _ => Err(usage(format!("bad duration {s:?} (e.g. 30s, 5m, 1h30m)"))),
    }
}

/// A timestamp flag: RFC 3339 or ms since the epoch.
pub(crate) fn parse_ts(s: &str) -> anyhow::Result<u64> {
    s.parse::<u64>().ok().or_else(|| text::parse_rfc3339(s).and_then(|m| u64::try_from(m).ok())).ok_or_else(|| usage(format!("bad timestamp {s:?} (RFC 3339 or ms)")))
}
