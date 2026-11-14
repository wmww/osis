//! Where background sync runs (`Runtime`, `Lan`) and the calls that put this node on the network;
//! sync is not built yet, so those fail `NotBuilt`.

/// Where background sync runs.
#[derive(Clone, Debug, Default)]
pub enum Runtime {
    /// No network: everything works locally; calls that wait for another node fail `Network`.
    #[default]
    None,
    /// The app's tokio runtime (multi-thread recommended: osis's work blocks its thread for a moment).
    Tokio(tokio::runtime::Handle),
    /// A small tokio runtime of osis's own.
    Own,
}

/// Whether a node with direct sync on (`Config::direct_sync`) finds other nodes on its local
/// network and is found by them, by a small UDP datagram it broadcasts there every so often.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lan {
    /// Announce on the local network.
    On {
        /// Further addresses to announce to, ones a broadcast does not reach, such as nodes of a
        /// routed mesh (each `<ip>:47380` unless it listens elsewhere).
        also_announce_to: Vec<std::net::SocketAddr>,
    },
    /// Stay quiet on the local network.
    Off,
}

impl Default for Lan {
    fn default() -> Lan {
        Lan::On { also_announce_to: Vec::new() }
    }
}

/// Runs `f`, which blocks; inside a multi-thread runtime in place, so that worker's tasks move
/// to others meanwhile.
pub(crate) fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

impl crate::Osis {
    /// Serves clients on this store's own unix socket: processes of this uid that connect
    /// (`Osis::connect_socket` with this store's directory) act as this node's main actor.
    /// `NotBuilt`.
    pub fn listen_socket(&self) -> crate::Result<()> {
        Err(crate::Error::NotBuilt)
    }

    /// Listens at `urls` (`quic://example.org:4040`) under this node's one key: other nodes sync
    /// with it there and clients use it, by default only as actors they authenticate for
    /// (`add_client`). Returns each address (with its real port) to hand out. `NotBuilt`.
    pub fn listen(&self, _urls: &[crate::Url]) -> crate::Result<Vec<crate::Address>> {
        Err(crate::Error::NotBuilt)
    }

    /// Gives this node a new key, so a new address other nodes dial it directly at
    /// (`Config::direct_sync`) and new `listen` addresses. `NotBuilt`.
    pub fn rotate_peer_address(&self) -> crate::Result<()> {
        Err(crate::Error::NotBuilt)
    }
}
