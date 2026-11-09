//! A connection's proof exchange (spec/sync.md §10, Connection proofs): what this node proves on
//! a connection and what a peer's proofs show. The signature's check is osis-proto's; a chain's
//! judgment is `Engine::accounts_proven`. `SyncEngine::proven` is the only reader: everything
//! later reads a connection's actors from there, none from group data.

use super::{ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use osis_base::format::MAX_MESSAGE;
use osis_proto::{ActorProof, Prover};
use std::collections::BTreeSet;

/// The local record naming this node's account (`Engine::app_record`).
pub const ACCOUNT_RECORD: &str = "account";

/// Past this many chain bytes a node sends no chain and proves its key alone. Resource bound by
/// the message cap: any margin under `MAX_MESSAGE` that leaves room for the signatures works; 0
/// sends no chain and so proves no account, infinity sends a frame the peer rejects.
pub const MAX_CHAIN_BYTES: usize = MAX_MESSAGE / 2;

/// This node's proofs: its own key with the chain to its account, and each key actor it holds
/// (a link key, a recovery key) by its signing key.
pub(super) fn provers(engine: &mut Engine) -> Result<Vec<Prover>> {
    let id = engine.core.id.clone();
    let mut accounts = Vec::new();
    let mut chain = Vec::new();
    if let Some(b) = engine.app_record(ACCOUNT_RECORD)?
        && let Ok(a) = <[u8; osis_base::format::TID_LEN]>::try_from(b.as_slice())
    {
        let account = Tid::from_bytes(a);
        let links = engine.account_chain(&account)?;
        if links.iter().map(Vec::len).sum::<usize>() <= MAX_CHAIN_BYTES {
            accounts.push(account);
            chain = links;
        }
    }
    let mut out = vec![Prover { key: id.keys().signing.clone(), record: id.record().clone(), accounts, chain }];
    out.extend(engine.core.key_actors.values().map(|k| Prover { key: k.keys().signing.clone(), record: k.record().clone(), accounts: Vec::new(), chain: Vec::new() }));
    Ok(out)
}

/// The actors `proofs` show: each proof's actor (its signature is checked), and each account its
/// chain shows for it. A proof's chain speaks for itself; this node's data only closes one.
pub(super) fn proven_actors(engine: &mut Engine, proofs: &[ActorProof]) -> Result<BTreeSet<Tid>> {
    let mut proven: BTreeSet<Tid> = proofs.iter().map(ActorProof::actor).collect();
    let claims: Vec<(Tid, Tid)> = proofs.iter().flat_map(|p| p.accounts.iter().map(move |a| (p.actor(), *a))).collect();
    let chain: Vec<Vec<u8>> = proofs.iter().flat_map(|p| p.chain.iter().cloned()).collect();
    proven.extend(engine.accounts_proven(&claims, &chain)?.into_iter().map(|(_, account)| account));
    Ok(proven)
}

impl SyncEngine {
    /// This node's own connection proofs.
    pub fn provers(&mut self) -> Result<Vec<Prover>> {
        provers(&mut self.engine)
    }

    /// Every connection's proven actors (diagnostics, tests).
    pub fn proven_connections(&self) -> Vec<(ConnId, BTreeSet<Tid>)> {
        self.conns.iter().map(|(c, x)| (*c, x.proven.clone())).chain(self.served_proven_all()).collect()
    }

    /// The actors `conn` proved on its own proof exchange (spec/sync.md §10), whoever dialed;
    /// `None` for a connection this engine does not have. Empty until the exchange finished,
    /// and for a connection that proved nothing.
    pub fn proven(&self, conn: ConnId) -> Option<&BTreeSet<Tid>> {
        self.conns.get(&conn).map(|c| &c.proven).or_else(|| self.served_proven(conn))
    }
}
