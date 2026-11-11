//! A connection's proof exchange (spec/sync.md §10, Connection proofs): what this node proves on
//! a connection and what a peer's proofs show. The signature's check is osis-proto's; whether an
//! account's key is open is `Engine::account_key_open`. `SyncEngine::proven` is the only reader:
//! everything later reads a connection's actors from there, none from group data.

use super::{ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use osis_proto::{ActorProof, MAX_PROOFS, Prover};
use std::collections::BTreeSet;

/// This node's proofs: its own key only to a node of its own account (`own`), then its account
/// at its open epoch when it holds the seed, then the key actors it holds (a link key) by their
/// signing keys, in tid order, up to `MAX_PROOFS` (spec/wire.md §11.2): any more are not proved
/// on this connection.
pub(super) fn provers(engine: &mut Engine, own: bool) -> Result<Vec<Prover>> {
    let id = engine.core.id.clone();
    let mut out = Vec::new();
    if own {
        out.push(Prover { key: id.keys().signing.clone(), record: id.record().clone() });
    }
    out.extend(engine.account_prover()?.map(|(key, record)| Prover { key, record }));
    let room = MAX_PROOFS.saturating_sub(out.len());
    out.extend(engine.core.key_actors.values().take(room).map(|k| Prover { key: k.keys().signing.clone(), record: k.record().clone() }));
    Ok(out)
}

/// What a connection proved (spec/sync.md §10), by how.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proven {
    /// Key actors proved by their own signing key over this connection.
    pub key_actors: BTreeSet<Tid>,
    /// Each of those key actors' signing key (from its proof: a static entry is checked against
    /// it, known here or not).
    pub signing: std::collections::BTreeMap<Tid, [u8; 32]>,
    /// The first proof's actor when it is a node of this node's own account (`Core::own_node`):
    /// a node proves its node key to its own account's nodes only (spec/sync.md §10).
    pub node: Option<Tid>,
    /// Accounts proved at an epoch open here: a closed epoch proves nothing (spec/sync.md §10).
    pub accounts: BTreeSet<Tid>,
}

impl Proven {
    /// Every actor proved, however.
    pub fn all(&self) -> BTreeSet<Tid> {
        self.key_actors.union(&self.accounts).copied().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.key_actors.is_empty() && self.accounts.is_empty()
    }

    /// Whom the peer counts as here (budgets, repair): its node when it is one of this node's
    /// account, else the first account it proved that is known here (`Judge::known`). A node of
    /// another account proves no node key here, so its account stands for all of its nodes; an
    /// account known by nothing is one anyone can make per connection, so it bounds nothing.
    pub fn source(&self, core: &crate::engine::Core) -> Option<Tid> {
        self.node.or_else(|| self.accounts.iter().copied().find(|t| core.judge([*t]).known()))
    }
}

/// What `proofs` show: each proof's actor (its signature is checked by osis-proto); an account
/// only at an epoch open here; the first proof as the peer's node only when it is a node of this
/// node's account.
pub(super) fn proven_actors(engine: &mut Engine, proofs: &[ActorProof]) -> Result<Proven> {
    let is_account = |p: &ActorProof| matches!(p.record, osis_base::CreationRecord::KeyActor { account: true, .. });
    let (accounts, key_actors): (Vec<&ActorProof>, Vec<&ActorProof>) = proofs.iter().partition(|p| is_account(p));
    let node = proofs.first().filter(|p| !is_account(p)).map(ActorProof::actor).filter(|t| engine.core.own_node(t));
    Ok(Proven { key_actors: key_actors.iter().map(|p| p.actor()).collect(), signing: key_actors.iter().map(|p| (p.actor(), p.key)).collect(), node, accounts: accounts.iter().filter(|p| engine.account_key_open(&p.record, &p.key)).map(|p| p.actor()).collect() })
}

/// Whether a peer that proved `proven` gets this node's node key: it proved this node's account
/// at an open epoch, or its own node key as a node of it (spec/sync.md §10).
pub(super) fn own_peer(engine: &Engine, proven: &Proven) -> bool {
    proven.node.is_some() || engine.core.account.get().is_some_and(|p| proven.accounts.contains(&p))
}

impl SyncEngine {
    /// This node's own connection proofs, its node key among them only for a node of its own
    /// account (`own`).
    pub fn provers(&mut self, own: bool) -> Result<Vec<Prover>> {
        provers(&mut self.engine, own)
    }

    /// Every connection's proven actors (diagnostics, tests).
    pub fn proven_connections(&self) -> Vec<(ConnId, BTreeSet<Tid>)> {
        self.conns.iter().map(|(c, x)| (*c, x.proven.all())).chain(self.served_proven_all()).collect()
    }

    /// The actors `conn` proved on its own proof exchange (spec/sync.md §10), whoever dialed;
    /// `None` for a connection this engine does not have. Empty until the exchange finished,
    /// and for a connection that proved nothing.
    pub fn proven(&self, conn: ConnId) -> Option<BTreeSet<Tid>> {
        self.connection_proven(conn).map(Proven::all)
    }

    /// The actors this node proved on `conn` (its Prove as the dialer, its Proved as the
    /// listener): what a connection's peer may judge it by, never what it could prove now.
    pub(super) fn proved(&self, conn: ConnId) -> Option<&BTreeSet<Tid>> {
        self.conns.get(&conn).map(|c| &c.proved).or_else(|| self.served_proved(conn))
    }

    /// `proven`, by how each actor was proved.
    pub(super) fn connection_proven(&self, conn: ConnId) -> Option<&Proven> {
        self.conns.get(&conn).map(|c| &c.proven).or_else(|| self.served_proven(conn))
    }
}
