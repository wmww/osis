//! Sources (notes/client-port.md §1, §6, §8; spec/sync-set.md §5): a call on a thing goes to
//! this process's engine or to a node this process is a client of (`port::client`), decided per
//! call, never cached and never falling back to another source: an unreachable source is that
//! call's `Network`.
//!
//! **The rule** (`decide`), for a thing `t`: on a thin client, its node (the first of several
//! that holds `t`, an unreachable one stopping the search); else a group in S = `t` and the
//! groups holding it here that is sourced at another node: that node, connected or not;
//! else this engine. A write goes to one source and is refused while the thing is split
//! (`split`): carried also by a group that syncs here or is sourced at a second node.
//!
//! Group sources persist as the app record `sources` (a line `tid url#key` per group), holding
//! no secret: `connect_node` brings the connection after each open.
//!
//! Not built: hand-off. The engine's sync set does not leave a group sourced elsewhere yet, so
//! such a group still syncs here (its copy updates and never answers): moving a group needs no
//! wait for it to be synced, and moving it home finds it current (issues/group-source-hand-off.md).

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

/// Where a group's calls go (`Osis::group_source`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupSource {
    /// This node: it syncs the group.
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

/// The app record of the group sources.
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

/// The node `t` is read at through a group sourced there, under the lock (a node's own
/// handle; a thin client's every thing is at its node).
pub(crate) fn sourced_in(l: &mut Locked, t: Tid) -> Option<Address> {
    if l.group_sources.is_empty() {
        return None;
    }
    let mut s = l.engine().enclosing(&t);
    s.insert(t);
    s.iter().find_map(|g| l.group_sources.get(g)).cloned()
}

/// `t` is split (spec/sync-set.md §5): sourced at `at`, and carried by a group that syncs here
/// or is sourced at another node.
fn split(l: &mut Locked, t: Tid, at: &Address) -> Option<Tid> {
    let synced: std::collections::BTreeSet<Tid> = l.engine().labeled_groups().into_iter().collect();
    let mut s = l.engine().enclosing(&t);
    s.insert(t);
    s.into_iter().find(|g| match l.group_sources.get(g) {
        Some(a) => a != at,
        None => synced.contains(g),
    })
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
            if self.remote_call(a, crate::port::method::HOLDS, vec![osis_base::Value::Tid(t)], crate::port::SMALL_REPLY)? == osis_base::Value::Bool(true) {
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
                if let Some(g) = self.locked(|l| split(l, *t, a)) {
                    return Err(Error::Invalid(format!("{t} is read at {a} and also carried by {g}, which syncs elsewhere: move one of the groups so the write reaches every holder")));
                }
            }
        }
        Ok(at)
    }

    /// `Unsupported` on a thin client: `what` needs this process to be the node.
    pub(crate) fn local(&self, what: &str) -> Result<()> {
        if self.has_store() { Ok(()) } else { Err(Error::Unsupported(format!("{what}: not through a connection to a node"))) }
    }

    /// `local_at` for each of `things`.
    pub(crate) fn local_things(&self, things: &[Tid], what: &str) -> Result<()> {
        self.local(what)?;
        things.iter().try_for_each(|t| self.local_at(*t, what))
    }

    /// `Unsupported` when `t` is at another node: `what` is not built through a connection.
    pub(crate) fn local_at(&self, t: Tid, what: &str) -> Result<()> {
        match self.source(t)? {
            Source::Local => Ok(()),
            Source::Node(a) => Err(Error::Unsupported(format!("{what} of a thing at {a}: not through a connection"))),
        }
    }
}

/// The engine's copy of the source table (`Core::sourced_elsewhere`): a client of this node
/// reads nothing of a group read elsewhere, whose copy here may be behind (`readable_by`).
fn mirror(l: &mut Locked) {
    let g = l.group_sources.keys().copied().collect();
    l.engine().core.sourced_elsewhere = g;
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
    let c = crate::Config { app: cfg, runtime, dial: Vec::new(), direct_sync: false, relays: Vec::new(), lan: crate::Lan::Off };
    Osis::create(crate::Store::Memory(crate::MemStore::new()), c)
}

impl Osis {
    /// Makes a thin client of the node running on the store at `store_dir`, over its unix socket
    /// (`Osis::listen_socket`), acting as the node's main actor.
    pub async fn connect_socket(store_dir: &Path, cfg: AppConfig) -> Result<Osis> {
        let url = osis_transport::unix::url_of(&socket_path(store_dir)?);
        let uid = osis_transport::unix::own_uid().map_err(|e| Error::Network(e.to_string()))?;
        let addr = Address(osis_label::Address { url, key: osis_transport::unix::uid_key(uid) });
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
    /// `group_source` can then make it the source of groups. Lasts until `disconnect_node` or
    /// this handle closes; a connection lost is dialed again.
    pub async fn connect_node(&self, login: &NodeLogin) -> Result<()> {
        self.local("connect_node")?;
        self.add_remote(login.addr.clone(), Some(login.secret.clone())).await.map(drop)
    }

    /// Moves where `group` is read and written, between this node and a node it is connected to
    /// (`connect_node`). At a node, the group's things are read there and written there, and a
    /// write on one also carried by a group that syncs here or at a third node fails `Invalid`;
    /// this node keeps the copy it had. `Invalid` for a node not connected.
    pub async fn group_source(&self, group: Tid, to: GroupSource) -> Result<()> {
        self.local("group_source")?;
        self.locked(|l| -> Result<()> {
            match &to {
                GroupSource::Node(a) if !l.remotes.iter().any(|r| r.addr == *a) => return Err(Error::Invalid(format!("not connected to {a} (connect_node)"))),
                GroupSource::Node(a) => {
                    l.group_sources.insert(group, a.clone());
                }
                GroupSource::Local => {
                    l.group_sources.remove(&group);
                }
            }
            let text: String = l.group_sources.iter().map(|(g, a)| format!("{g} {a}\n")).collect();
            l.engine().set_app_record(SOURCES, text.as_bytes())?;
            mirror(l);
            self.inner.has_sources.store(!l.remotes.is_empty() || !l.group_sources.is_empty(), Ordering::Release);
            Ok(())
        })
    }

    /// Ends the connection to the node at `addr`. `false`: no such connection.
    pub fn disconnect_node(&self, addr: &Address) -> Result<bool> {
        Ok(self.drop_remote(addr))
    }

    /// The groups whose source is another node, with its address (`group_source`).
    pub fn group_sources(&self) -> BTreeMap<Tid, Address> {
        self.locked(|l| l.group_sources.clone())
    }

    /// Reads the group sources this store keeps (`Osis::start`).
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
            l.group_sources = m;
            mirror(l);
        });
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
