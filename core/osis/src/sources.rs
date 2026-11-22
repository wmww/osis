//! Sources (notes/client-port.md §1, §6, §8; spec/sync-set.md §5): a call on a thing goes to
//! this process's engine or to a node this process is a client of (`port::client`), decided per
//! call, never cached and never falling back to another source: an unreachable source is that
//! call's `Network`.
//!
//! **The rule** (`decide`), for a thing `t`: on a thin client, its node (the first of several
//! that holds `t`, an unreachable one stopping the search); else a sync unit in S = `t` and the
//! sync units holding it here that is sourced at another node: that node, connected or not;
//! else this engine. A write goes to one source and is refused while the thing is split
//! (`split`): carried also by a sync unit that syncs here or is sourced at a second node.
//!
//! Sync unit sources persist as the app record `sources` (a line `tid url#key` per sync unit), holding
//! no secret: `connect_node` brings the connection after each open.
//!
//! **Hand-off** (spec/sync-set.md §5): the engine's sync set leaves a sync unit sourced at another
//! node (`Engine::set_sourced`), so its sync IDs stop by spec/sync-set.md §3, once this node's
//! own commits there are held elsewhere: the move away waits for nothing itself. Moving back, the
//! sync unit syncs here again while still read at its node (`Locked::moving_back`), and the move answers
//! once it caught up (`Engine::caught_up`: history complete, spec/sync-status.md §3, so a source
//! gone ends it by `PASS_WAIT_MS`); only then is it recorded as read here. A client of this node reads
//! nothing of it until then.

use crate::error::{Error, Result};
use crate::handle::{AppConfig, Locked, Osis, ReadOnly};
use crate::share::Address;
use osis_base::Tid;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::Ordering;

/// How to log in to a node (`Osis::connect`, `Osis::connect_node`): where it is and what proves
/// who this client is there. The node says which actor that makes it (`Osis::me`).
#[derive(Clone, Debug)]
pub struct NodeLogin {
    /// Where it is.
    pub addr: Address,
    /// What proves who this client is.
    pub secret: crate::ClientSecret,
}

/// Where a sync unit's calls go (`Osis::unit_source`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitSource {
    /// This node: it syncs the sync unit.
    Local,
    /// The node at this address, which must be connected (`Osis::connect_node`).
    Node(Address),
}

/// Where a call on a thing goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// This process's engine.
    Local,
    /// The node at this address.
    Node(Address),
}

/// The app record of the sync unit sources.
const SOURCES: &str = "sources";

/// A decision made under the lock: `Ask` needs the nodes' answers, off it.
enum Decided {
    At(Source),
    Ask(Vec<Address>),
}

/// The rule, under the lock.
fn decide(db: &ReadOnly, l: &mut Locked, t: Tid) -> Decided {
    if db.inner.thin.get().is_some() {
        return match l.remotes.as_slice() {
            [one] => Decided::At(Source::Node(one.addr.clone())),
            all => Decided::Ask(all.iter().map(|r| r.addr.clone()).collect()),
        };
    }
    Decided::At(sourced_in(l, t).map_or(Source::Local, Source::Node))
}

/// The node `t` is read at through a sync unit sourced there, under the lock (a node's own
/// handle; a thin client's every thing is at its node).
pub(crate) fn sourced_in(l: &mut Locked, t: Tid) -> Option<Address> {
    if l.unit_sources.is_empty() {
        return None;
    }
    let mut s = l.engine().units_holding(&t);
    s.insert(t);
    s.iter().find_map(|g| l.unit_sources.get(g)).cloned()
}

/// `t` is split (spec/sync-set.md §5): sourced at `at`, and carried by a sync unit that syncs here
/// (under a sync ID of its own in the sync set, spec/sync-judgement.md §1) or is sourced at
/// another node.
fn split(l: &mut Locked, t: Tid, at: &Address) -> Result<Option<Tid>> {
    let mut s = l.engine().units_holding(&t);
    s.insert(t);
    for g in s {
        let elsewhere = match l.unit_sources.get(&g) {
            Some(a) => a != at,
            None => l.engine().syncs_here(&g)?,
        };
        if elsewhere {
            return Ok(Some(g));
        }
    }
    Ok(None)
}

impl ReadOnly {
    /// Whether this handle has a store of its own: `false` on a thin client (`connect`,
    /// `connect_socket`).
    pub fn has_store(&self) -> bool {
        self.inner.thin.get().is_none()
    }

    /// Where a call on `t` goes. Free while nothing is connected or sourced elsewhere.
    pub(crate) fn source(&self, t: Tid) -> Result<Source> {
        if !self.inner.has_sources.load(Ordering::Acquire) {
            return Ok(Source::Local);
        }
        let d = self.locked(|l| decide(self, l, t));
        let ask = match d {
            Decided::At(s) => return Ok(s),
            Decided::Ask(all) => all,
        };
        // the first node holding it answers; an unreachable one stops the search, so a later
        // one never answers for it
        for a in &ask {
            if self.forward(a, crate::port::method::HAS_RECORD, (t,))? {
                return Ok(Source::Node(a.clone()));
            }
        }
        Ok(ask.into_iter().next().map_or(Source::Local, Source::Node))
    }

    /// Where a write on `things` goes: one source; `Invalid` when they resolve to two, or a
    /// thing at another node is split (spec/sync-set.md §5).
    pub(crate) fn source_of_all(&self, things: &[Tid]) -> Result<Source> {
        let mut at = None;
        for t in things {
            let s = self.source(*t)?;
            if at.as_ref().is_some_and(|a| *a != s) {
                return Err(Error::Invalid("a write goes to one source: its things are at two nodes, or here and at a node".into()));
            }
            at = Some(s);
        }
        let at = match at {
            Some(a) => a,
            None if self.has_store() => Source::Local,
            None => self.locked(|l| l.remotes.first().map(|r| Source::Node(r.addr.clone()))).unwrap_or(Source::Local),
        };
        if let Source::Node(a) = &at
            && self.has_store()
        {
            for t in things {
                if let Some(g) = self.locked(|l| split(l, *t, a))? {
                    return Err(Error::Invalid(format!("{t} is read at {a} and also carried by {g}, which syncs elsewhere: move one of the sync units so the write reaches every holder")));
                }
            }
        }
        Ok(at)
    }

    /// Where a process-wide call (`what`) goes: `None` here, in the process holding the store; on
    /// a thin client its node, which answers it for a main session alone (a client actor's is
    /// `Unsupported` there). A thin client of several nodes has no one node to ask: `Unsupported`.
    pub(crate) fn process_at(&self, what: &str) -> Result<Option<Address>> {
        if self.has_store() {
            return Ok(None);
        }
        match self.remote_addrs().as_slice() {
            [one] => Ok(Some(one.clone())),
            _ => Err(Error::Unsupported(format!("{what} through several nodes"))),
        }
    }

    /// Where a read over `things` goes when not here: the one node they are all read at
    /// (`Invalid` when at two sources). A handle acting for a client of this node always reads
    /// here (notes/client-port.md §8 Catching up); a tracked read at another node is
    /// `Unsupported`, named `what`.
    pub(crate) fn remote_of(&self, things: &[Tid], what: &str) -> Result<Option<Address>> {
        if self.acting.is_some() {
            return Ok(None);
        }
        let mut at: Option<Option<Address>> = None;
        for t in things {
            let s = self.remote(*t, what)?;
            if at.as_ref().is_some_and(|a| *a != s) {
                return Err(Error::Invalid(format!("{what}: its things are read at two sources")));
            }
            at = Some(s);
        }
        Ok(at.flatten())
    }

    /// `Unsupported` on a thin client: `what` needs this process to be the node.
    pub(crate) fn local(&self, what: &str) -> Result<()> {
        if self.has_store() { Ok(()) } else { Err(Error::Unsupported(format!("{what}: not through a connection to a node"))) }
    }

    /// `Unsupported` when `t` is at another node: `what` is not built through a connection.
    pub(crate) fn local_at(&self, t: Tid, what: &str) -> Result<()> {
        match self.source(t)? {
            Source::Local => Ok(()),
            Source::Node(a) => Err(Error::Unsupported(format!("{what} of a thing at {a}: not through a connection"))),
        }
    }
}

/// The engine's copy of the source table (`Engine::set_sourced`): the sync set leaves a sync unit
/// read elsewhere unless it is moving back, and a client of this node reads nothing of it, its
/// copy here maybe behind (`readable_by`).
fn mirror(l: &mut Locked) -> Result<()> {
    let g = l.unit_sources.keys().copied().collect();
    let moving_back = l.moving_back.clone();
    Ok(l.engine().set_sourced(g, &moving_back)?)
}

/// Writes the source table to its app record and the engine (`mirror`).
fn record(db: &ReadOnly, l: &mut Locked) -> Result<()> {
    let text: String = l.unit_sources.iter().map(|(g, a)| format!("{g} {a}\n")).collect();
    l.engine().set_app_record(SOURCES, text.as_bytes())?;
    mirror(l)?;
    db.inner.has_sources.store(!l.remotes.is_empty() || !l.unit_sources.is_empty(), Ordering::Release);
    Ok(())
}

/// The scratch node a thin client stands on: in memory, dialing nothing, listening nowhere.
fn scratch(mut cfg: AppConfig) -> Result<Osis> {
    cfg.internals.thin = true;
    let runtime = if cfg.internals.net.is_some() {
        crate::Runtime::None
    } else {
        match tokio::runtime::Handle::try_current() {
            Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => crate::Runtime::Tokio(h),
            _ => crate::Runtime::Own,
        }
    };
    let mut c = crate::Config { app: cfg, runtime, dial: Vec::new(), lan: crate::Lan::Off };
    c.app.internals.no_listen = true;
    Osis::create(crate::Store::Memory(crate::MemStore::new()), c)
}

impl Osis {
    /// Makes a thin client of the node running on the store at `store_dir`, over its unix socket
    /// (`Osis::listen_socket`), acting as the node's main actor.
    pub async fn connect_socket(store_dir: &Path, cfg: AppConfig) -> Result<Osis> {
        let url = osis_transport::unix::url_of(&socket_path(store_dir)?);
        let uid = osis_transport::unix::own_uid().map_err(|e| Error::Network(e.to_string()))?;
        let addr = Address(osis_blob::Address { url, key: osis_transport::unix::uid_key(uid) });
        Osis::thin(&[(addr, None)], cfg).await
    }

    /// Makes a thin client of the nodes it logs in to, each dialed at its address, which pins the
    /// node's key: every call goes to them, as the actor a login makes this program (`me()`).
    /// Several logins must make it one actor (`Invalid` otherwise); a thing goes to the first
    /// node holding it.
    pub async fn connect(logins: &[NodeLogin], cfg: AppConfig) -> Result<Osis> {
        if logins.is_empty() {
            return Err(Error::Invalid("connect needs a node to log in to".into()));
        }
        if let Some(l) = logins.iter().find(|l| l.addr.0.url.starts_with("unix://")) {
            return Err(Error::Invalid(format!("{}: a socket takes no secret (connect_socket)", l.addr)));
        }
        let all: Vec<_> = logins.iter().map(|l| (l.addr.clone(), Some(l.secret.clone()))).collect();
        Osis::thin(&all, cfg).await
    }

    async fn thin(logins: &[(Address, Option<crate::ClientSecret>)], cfg: AppConfig) -> Result<Osis> {
        let db = scratch(cfg)?;
        let mut who = None;
        for (a, s) in logins {
            let w = db.add_remote(a.clone(), s.clone()).await?;
            if who.is_some_and(|x: crate::port::client::Thin| x.me != w.me) {
                return Err(Error::Invalid(format!("{a} makes this client another actor than the nodes before it")));
            }
            who.get_or_insert(w);
        }
        if let Some(w) = who {
            let _ = db.inner.thin.set(w);
        }
        Ok(db)
    }

    /// Makes this node a client of the node at `login`'s address, beside its own store:
    /// `unit_source` can then make it the source of sync units. Lasts until `disconnect_node` or
    /// this handle closes; a connection lost is dialed again.
    pub async fn connect_node(&self, login: &NodeLogin) -> Result<()> {
        self.local("connect_node")?;
        self.add_remote(login.addr.clone(), Some(login.secret.clone())).await.map(drop)
    }

    /// Moves where `sync unit` is read and written, between this node and a node it is connected to
    /// (`connect_node`). At a node, the sync unit's things are read there and written there, and a
    /// write on one also carried by a sync unit that syncs here or at a third node fails `Invalid`;
    /// this node keeps the copy it had and stops syncing the sync unit once its own writes there
    /// reached another holder. Moving back here answers once this node's copy caught up (a complete
    /// pass of each sync ID carrying the sync unit: at most `PASS_WAIT_MS` past a holder away); until
    /// then the sync unit stays read at its node, and a call dropped before it answers leaves it so,
    /// syncing here too until a restart (moving it again ends that). `Invalid` for a node not connected, for
    /// the account root (it always syncs here), or when the sync unit moved away again before it caught up.
    pub async fn unit_source(&self, unit: Tid, to: UnitSource) -> Result<()> {
        self.local("unit_source")?;
        let moving_back = self.locked(|l| -> Result<bool> {
            match &to {
                UnitSource::Node(a) if !l.remotes.iter().any(|r| r.addr == *a) => Err(Error::Invalid(format!("not connected to {a} (connect_node)"))),
                // the node's own records live on the account root: it always syncs here
                UnitSource::Node(_) if unit == self.account_root() => Err(Error::Invalid("the account root is never sourced at another node".into())),
                UnitSource::Node(a) => {
                    l.unit_sources.insert(unit, a.clone());
                    l.moving_back.remove(&unit);
                    record(self, l)?;
                    // the sync set moved: sync steps now, as moving back does
                    l.handle(osis_sync::Input::Wrote);
                    Ok(false)
                }
                UnitSource::Local if !l.unit_sources.contains_key(&unit) => Ok(false),
                UnitSource::Local => {
                    // syncing here again, read at its node until it caught up
                    if l.moving_back.insert(unit) {
                        mirror(l)?;
                        l.handle(osis_sync::Input::Wrote);
                    }
                    Ok(true)
                }
            }
        })?;
        if !moving_back {
            return Ok(());
        }
        self.waiting(move |db| {
            db.locked(|l| -> Option<Result<()>> {
                if !l.unit_sources.contains_key(&unit) {
                    return Some(Ok(()));
                }
                if !l.moving_back.contains(&unit) {
                    return Some(Err(Error::Invalid(format!("{unit} moved away again before it caught up"))));
                }
                match l.engine().caught_up(&unit) {
                    Ok(false) => None,
                    Ok(true) => {
                        l.unit_sources.remove(&unit);
                        l.moving_back.remove(&unit);
                        Some(record(db, l))
                    }
                    Err(e) => Some(Err(e.into())),
                }
            })
        })
        .await
    }

    /// Ends the connection to the node at `addr`. `false`: no such connection.
    pub fn disconnect_node(&self, addr: &Address) -> Result<bool> {
        Ok(self.drop_remote(addr))
    }

    /// The sync units whose source is another node, with its address (`unit_source`).
    pub fn unit_sources(&self) -> BTreeMap<Tid, Address> {
        self.locked(|l| l.unit_sources.clone())
    }

    /// Reads the sync unit sources this store keeps (`Osis::start`).
    pub(crate) fn load_sources(&self) -> Result<()> {
        let rec = self.engine(|e| e.app_record(SOURCES))?;
        let Some(b) = rec else { return Ok(()) };
        let text = String::from_utf8(b).map_err(|_| Error::Storage("sources record".into()))?;
        let mut m = BTreeMap::new();
        for line in text.lines() {
            let (g, a) = line.split_once(' ').ok_or_else(|| Error::Storage("sources record".into()))?;
            let g = Tid::parse(g).map_err(|_| Error::Storage("sources record".into()))?;
            m.insert(g, a.parse::<Address>().map_err(|_| Error::Storage("sources record".into()))?);
        }
        let any = !m.is_empty();
        self.locked(|l| {
            l.unit_sources = m;
            mirror(l)
        })?;
        self.inner.has_sources.store(any, Ordering::Release);
        Ok(())
    }
}

/// The path of the client socket of the store at `store` (`Osis::listen_socket`,
/// `Osis::connect_socket`): under `$XDG_RUNTIME_DIR/osis/`, else `/tmp/osis-<uid>/` (made 0700 and
/// checked), named by a hash of the store's path.
pub fn socket_path(store: &Path) -> Result<std::path::PathBuf> {
    socket_path_under(std::env::var_os("XDG_RUNTIME_DIR").as_deref().map(Path::new), store)
}

/// `socket_path` under `runtime_dir` (`None`: `/tmp/osis-<uid>/`).
pub fn socket_path_under(runtime_dir: Option<&Path>, store: &Path) -> Result<std::path::PathBuf> {
    let uid = osis_transport::unix::own_uid().map_err(|e| Error::Storage(e.to_string()))?;
    let dir = match runtime_dir.filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => d.join("osis"),
        None => std::path::PathBuf::from(format!("/tmp/osis-{uid}")),
    };
    socket_dir(&dir, uid)?;
    let abs = std::fs::canonicalize(store).or_else(|_| std::path::absolute(store)).map_err(|e| Error::Storage(e.to_string()))?;
    let h = osis_base::hash::hash(abs.as_os_str().as_encoded_bytes());
    let name: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    let sock = dir.join(format!("{name}.sock"));
    if sock.as_os_str().len() > osis_transport::unix::MAX_PATH {
        return Err(Error::Storage(format!("{}: too long a path for a socket", sock.display())));
    }
    Ok(sock)
}

/// Makes `dir` 0700 if missing, then checks it is a directory of `uid`'s, mode 0700, not a
/// symlink; refuses it otherwise (another user's or a planted directory).
pub fn socket_dir(dir: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let mut b = std::fs::DirBuilder::new();
    b.mode(0o700);
    match b.create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::Storage(format!("{}: {e}", dir.display()))),
    }
    let m = std::fs::symlink_metadata(dir).map_err(|e| Error::Storage(format!("{}: {e}", dir.display())))?;
    if m.file_type().is_symlink() || !m.is_dir() || m.uid() != uid || m.mode() & 0o777 != 0o700 {
        return Err(Error::Storage(format!("{}: not a directory of this user's with mode 0700", dir.display())));
    }
    Ok(())
}
