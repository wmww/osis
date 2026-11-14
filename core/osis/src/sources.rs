//! Using a node from another process (thin clients) and reading a group at another node (group
//! sources), over the client port (spec/wire.md §11.2). The node side of the port is built
//! (`port`); the client side is not: these fail `NotBuilt`.

use crate::error::{Error, Result};
use crate::handle::{AppConfig, Osis, ReadOnly};
use crate::share::Address;
use osis_base::Tid;
use std::collections::BTreeMap;
use std::path::Path;

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

impl Osis {
    /// Makes a thin client of the node running on the store at `store_dir`, over its unix socket
    /// (`Osis::listen_socket`), acting as the node's main actor. `NotBuilt`.
    pub async fn connect_socket(_store_dir: &Path, _cfg: AppConfig) -> Result<Osis> {
        Err(Error::NotBuilt)
    }

    /// Makes a thin client of the nodes it logs in to, each dialed at its address, which pins the
    /// node's key: every call goes to them, as the actor a login makes this program (`me()`).
    /// `NotBuilt`.
    pub async fn connect(_logins: &[NodeLogin], _cfg: AppConfig) -> Result<Osis> {
        Err(Error::NotBuilt)
    }

    /// Makes this node a client of the node at `login`'s address, beside its own store:
    /// `group_source` can then make it the source of groups. `NotBuilt`.
    pub async fn connect_node(&self, _login: &NodeLogin) -> Result<()> {
        Err(Error::NotBuilt)
    }

    /// Moves where `group` is read and written, between this node and a node it is connected to,
    /// never losing a write. `NotBuilt`.
    pub async fn group_source(&self, _group: Tid, _to: GroupSource) -> Result<()> {
        Err(Error::NotBuilt)
    }

    /// Ends the connection to the node at `addr`. `false`: no such connection.
    pub fn disconnect_node(&self, _addr: &Address) -> Result<bool> {
        Ok(false)
    }

    /// The groups whose source is another node, with its address (`group_source`).
    pub fn group_sources(&self) -> BTreeMap<Tid, Address> {
        BTreeMap::new()
    }
}

impl ReadOnly {
    /// Whether this handle has a store of its own: `false` on a thin client (`connect`,
    /// `connect_socket`).
    #[inline]
    pub fn has_store(&self) -> bool {
        true
    }
}

/// The path of the client socket of the store at `store` (`Osis::listen_socket`,
/// `Osis::connect_socket`): under `$XDG_RUNTIME_DIR/osis/`, else `/tmp/osis-<uid>/` (made 0700 and
/// checked), named by a hash of the store's path.
pub(crate) fn socket_path(store: &Path) -> Result<std::path::PathBuf> {
    socket_path_under(std::env::var_os("XDG_RUNTIME_DIR").as_deref().map(Path::new), store)
}

fn socket_path_under(runtime_dir: Option<&Path>, store: &Path) -> Result<std::path::PathBuf> {
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
fn socket_dir(dir: &Path, uid: u32) -> Result<()> {
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
