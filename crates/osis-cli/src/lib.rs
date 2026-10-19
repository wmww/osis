//! osis-cli: the command-line tool `osis` over the `osis` API, for scripts, debugging and agents.
//! One invocation opens the store, acts, closes. Text forms that read back what they print,
//! `--json` for machines, exit codes by error category. Design: notes/cli.md.
//! Layer 9 (notes/architecture.md). Plan: plans/cli.md.
#![forbid(unsafe_code)]
// The binary's crate: panics on programmer errors are allowed (notes/architecture.md §3).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

pub mod args;
mod cmd;
pub mod json;
pub mod text;
mod write;

use anyhow::anyhow;
use args::{Cli, Global};
use clap::Parser;
use json::J;
use osis::{Config, Error, Key, MemStore, Osis, Schema, StoreAt, Tid};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// A failure with its exit code (plans/cli.md §6); an empty message prints nothing.
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

/// Exit code and kind of an API error (plans/cli.md §6).
pub fn category(e: &Error) -> (i32, &'static str) {
    match e {
        Error::UnknownThing { .. } => (3, "UnknownThing"),
        Error::UnknownActor { .. } => (3, "UnknownActor"),
        Error::Permission { .. } => (4, "Permission"),
        Error::TooLarge { .. } => (5, "TooLarge"),
        Error::Type { .. } => (5, "Type"),
        Error::Network(_) => (6, "Network"),
        Error::Unsynced { .. } => (6, "Unsynced"),
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
    pub stderr: &'a mut dyn Write,
    /// stdin is a terminal (`edit` opens `$EDITOR`).
    pub tty: bool,
}

/// Runs one invocation (args include the binary name); returns the exit code.
pub fn main_with<I, T>(args: I, stdin: &mut dyn BufRead, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32
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
    let r = cmd::dispatch(cli, store, stdin, stdout, tty);
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

fn config(sel: &StoreSel, g: &Global) -> Config {
    let mut c = match sel {
        StoreSel::Dir(d) => Config::dir(d),
        StoreSel::Memory(m) => Config::at(StoreAt::Memory(m.clone())),
    };
    if let Some(l) = g.limit {
        c.materialize_limit = l;
    }
    // background sync on a runtime of osis's own, servers over QUIC
    c.runtime = osis::Runtime::Own;
    c.transport = Some(osis::Transport::Quic);
    c
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

/// Opens an existing store (exit 8 when missing or locked).
fn open(sel: &StoreSel, g: &Global) -> anyhow::Result<Osis> {
    match sel {
        StoreSel::Dir(d) => {
            if !d.join("db.redb").exists() {
                return Err(exit(8, format!("no store at {} (run osis init)", d.display())));
            }
            let db = Osis::open(config(sel, g)).map_err(|e| lock_err(d, e))?;
            let _ = std::fs::write(d.join(PID_FILE), std::process::id().to_string());
            Ok(db)
        }
        StoreSel::Memory(_) => Osis::open(config(sel, g)).map_err(|e| match e {
            Error::Storage(m) if m.contains("not an osis database") => exit(8, "no store (run osis init)"),
            e => e.into(),
        }),
    }
}

/// Creates a store with its home group on `servers`; refuses a non-empty directory. Returns the
/// recovery card (none without servers).
fn create(sel: &StoreSel, g: &Global, servers: Vec<osis::ServerAddr>) -> anyhow::Result<(Osis, Option<osis::RecoveryCard>)> {
    if let StoreSel::Dir(d) = sel
        && d.read_dir().is_ok_and(|mut r| r.next().is_some())
    {
        return Err(exit(8, format!("{} is not empty", d.display())));
    }
    let mut cfg = config(sel, g);
    cfg.servers = servers;
    let db = Osis::create(cfg).map_err(|e| match sel {
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

/// One invocation's state: the open database, flags, output, script variables.
pub(crate) struct Ctx<'a> {
    pub g: Global,
    pub db: Osis,
    pub out: &'a mut dyn Write,
    pub stdin: &'a mut dyn BufRead,
    pub tty: bool,
    pub sel: StoreSel,
    pub schemas: Vec<Arc<Schema>>,
    pub vars: BTreeMap<String, Tid>,
    /// (tid, AK) this batch wrote; AK "" for the whole thing (created or deleted).
    pub pending: std::collections::BTreeSet<(Tid, String)>,
}

impl Ctx<'_> {
    fn new<'a>(g: Global, db: Osis, sel: StoreSel, out: &'a mut dyn Write, stdin: &'a mut dyn BufRead, tty: bool) -> anyhow::Result<Ctx<'a>> {
        let mut paths = match &sel {
            StoreSel::Dir(d) => registered(d)?,
            StoreSel::Memory(_) => Vec::new(),
        };
        paths.extend(g.schemas.iter().cloned());
        let mut schemas = Vec::new();
        for p in paths {
            schemas.push(db.register_schema_file(&p).map_err(|e| exit(7, format!("schema {}: {e}", p.display())))?);
        }
        Ok(Ctx { g, db, out, stdin, tty, sel, schemas, vars: BTreeMap::new(), pending: Default::default() })
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

    /// The `--timeout` bound (default 30 s; `0`: none).
    pub fn timeout(&self) -> anyhow::Result<Option<Duration>> {
        self.timeout_or(Some(Duration::from_secs(30)))
    }

    pub fn timeout_or(&self, default: Option<Duration>) -> anyhow::Result<Option<Duration>> {
        match &self.g.timeout {
            None => Ok(default),
            Some(s) => Ok(match parse_dur(s)? {
                d if d.is_zero() => None,
                d => Some(d),
            }),
        }
    }

    /// Resolves a tid argument: `osis://…`, bare, `me`, `node`, `home`, `$var`.
    pub fn tid(&self, s: &str) -> anyhow::Result<Tid> {
        self.alias(s).or_else(|| Tid::parse(s).ok()).ok_or_else(|| usage(format!("not a tid: {s}")))
    }

    pub fn alias(&self, s: &str) -> Option<Tid> {
        match s {
            "me" => Some(self.db.me()),
            "node" => Some(self.db.node()),
            "home" => Some(self.db.home()),
            _ => s.strip_prefix('$').and_then(|v| self.vars.get(v).copied()),
        }
    }

    /// The key for an AK: typed by a registered schema unless `--raw`.
    pub fn key(&self, ak: &str) -> anyhow::Result<Key> {
        if self.g.raw {
            let a = osis::Ak::new(ak).map_err(|_| usage(format!("bad AK {ak:?}")))?;
            Ok(Key::new(a, None))
        } else {
            self.db.key(ak).map_err(|_| usage(format!("bad AK {ak:?}")))
        }
    }

    /// Reads an argument: a literal, `@FILE`, or `-` (stdin).
    pub fn arg_text(&mut self, s: &str) -> anyhow::Result<String> {
        if s == "-" {
            let mut b = String::new();
            self.stdin.read_to_string(&mut b)?;
            Ok(b.trim_end_matches('\n').to_string())
        } else if let Some(f) = s.strip_prefix('@') {
            Ok(std::fs::read_to_string(f).map_err(|e| usage(format!("{f}: {e}")))?.trim_end_matches('\n').to_string())
        } else {
            Ok(s.to_string())
        }
    }

    /// Parses a value argument at a type.
    pub fn value(&mut self, s: &str, ty: text::Ty<'_>) -> anyhow::Result<osis::Value> {
        let src = self.arg_text(s)?;
        let al = |w: &str| self.alias(w);
        text::parse(&src, ty, &al).map_err(|e| usage(format!("bad value {src:?}: {e}")))
    }
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
