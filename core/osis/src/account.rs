//! The account across nodes (spec/permissions.md §8; notes/api.md Handle and lifecycle): pairing
//! a new node. Pairing is transport-agnostic: the app carries two messages between the nodes
//! (QR, clipboard, a local socket): the new node's request and the existing node's reply.
//!
//! Interim (notes/accounts-switch-brief.md): pairing is not built; each call says so.

use crate::error::{Error, Result};
use crate::handle::Osis;
use crate::{Config, Store};
use osis_base::Tid;

const OFFER: &str = "osis://pair/";
const REQUEST: &str = "osis://pair-request/";
const REPLY: &str = "osis://pair-reply/";

crate::share::secret_text!(
    /// A short-lived offer to pair a new node, made on an existing one (holds a one-time
    /// secret: show it only to the new node).
    PairOffer, (), |s| unpack(s, OFFER)
);
crate::share::secret_text!(
    /// The new node's answer to an offer, for `Osis::pair_accept` on the offering node.
    PairRequest, (), |s| unpack(s, REQUEST)
);
crate::share::secret_text!(
    /// The offering node's answer to a request, for `Joining::finish` on the new node.
    PairReply, (), |s| unpack(s, REPLY)
);

fn unpack(s: &str, prefix: &str) -> Result<()> {
    s.strip_prefix(prefix).map(drop).ok_or_else(|| Error::Invalid("malformed pairing message".into()))
}

/// Pairing is not built yet (notes/accounts-switch-brief.md).
fn not_built() -> Error {
    Error::Unsupported("pairing a node: not built yet".into())
}

/// Whether `a` equals `b`, compared in constant time.
pub(crate) fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A new node waiting for the offering node's reply.
pub struct Joining {
    request: PairRequest,
}

impl std::fmt::Debug for Joining {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Joining({:?})", self.request)
    }
}

impl Joining {
    /// The request to carry to the offering node.
    pub fn request(&self) -> &PairRequest {
        &self.request
    }

    /// Takes the offering node's reply and returns the node, now a node of the account.
    pub fn finish(self, _reply: &PairReply) -> Result<Osis> {
        Err(not_built())
    }
}

impl Osis {
    /// An offer to pair a new node, good once: the new node runs `Osis::pair` with it and the
    /// app carries the request back to `pair_accept`.
    pub fn pair_offer(&self) -> Result<PairOffer> {
        self.local("pair_offer")?;
        Err(not_built())
    }

    /// Accepts a new node's request to an offer of this node: makes it a node of the account
    /// and returns its node tid with the reply to carry back.
    pub fn pair_accept(&self, _req: &PairRequest) -> Result<(Tid, PairReply)> {
        self.local("pair_accept")?;
        Err(not_built())
    }

    /// Starts pairing this fresh store as a new node of the account that made `offer`: returns
    /// the request to carry to the offering node and, with its reply, `Joining::finish`.
    pub fn pair(_store: Store, _offer: &PairOffer, cfg: Config) -> Result<Joining> {
        cfg.check()?;
        Err(not_built())
    }
}
