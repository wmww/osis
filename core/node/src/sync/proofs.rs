//! A connection's proof exchange (spec/sync.md §10, Connection proofs): what this node proves on
//! a connection and what a peer's proofs show. The signature's check is osis-proto's; a chain's
//! judgment is `Engine::accounts_proven`. `SyncEngine::proven` is the only reader: everything
//! later reads a connection's actors from there, none from group data.

use super::{ConnId, SyncEngine};
use crate::engine::Engine;
use crate::error::Result;
use osis_base::Tid;
use osis_proto::{ActorProof, MAX_CHAIN_BYTES, MAX_PROOFS, Prover};
use std::collections::BTreeSet;

/// The local record naming this node's account (`Engine::app_record`).
pub const ACCOUNT_RECORD: &str = "account";

/// This node's proofs: its own key with the chain to its account, then the key actors it holds
/// (a link key, a recovery key) by their signing keys, in tid order, up to `MAX_PROOFS`
/// (spec/wire.md §11.2): any more are not proved on this connection.
pub(super) fn provers(engine: &mut Engine) -> Result<Vec<Prover>> {
    let id = engine.core.id.clone();
    let mut accounts = Vec::new();
    let mut chain = Vec::new();
    if let Some(b) = engine.app_record(ACCOUNT_RECORD)?
        && let Ok(a) = <[u8; osis_base::format::TID_LEN]>::try_from(b.as_slice())
    {
        let account = Tid::from_bytes(a);
        let links = engine.account_chain(&account)?;
        (accounts, chain) = claim_within_cap(account, links);
    }
    let mut out = vec![Prover { key: id.keys().signing.clone(), record: id.record().clone(), accounts, chain }];
    out.extend(engine.core.key_actors.values().take(MAX_PROOFS - 1).map(|k| Prover { key: k.keys().signing.clone(), record: k.record().clone(), accounts: Vec::new(), chain: Vec::new() }));
    Ok(out)
}

/// A node's account claim and chain, or neither when the chain passes `MAX_CHAIN_BYTES`: it then
/// proves its key alone.
fn claim_within_cap(account: Tid, links: Vec<Vec<u8>>) -> (Vec<Tid>, Vec<Vec<u8>>) {
    if links.iter().map(Vec::len).sum::<usize>() <= MAX_CHAIN_BYTES { (vec![account], links) } else { (Vec::new(), Vec::new()) }
}

/// What a connection proved (spec/sync.md §10), by how: the split is the access rule until accounts
/// sign (issues/account-signing.md step 6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proven {
    /// Key actors proved by their own signing key over this connection: all J counts.
    pub key_actors: BTreeSet<Tid>,
    /// The first proof's actor: the prover's own node key (spec/wire.md §11.2 Prove).
    pub node: Option<Tid>,
    /// Accounts: a chain's claim, or a proof by an account's key. Reported, never counted by J:
    /// the chain is judged alone (a removal it omits leaves the claim standing, even at a node
    /// holding the removal, and a removed node keeps an account's first-epoch key), so a J
    /// counting these would give a removed node access. Invariant, enforced where `Judge` is made.
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
}

/// What `proofs` show: each proof's actor (its signature is checked), and each account its chain
/// shows for it, judged from that chain alone.
pub(super) fn proven_actors(engine: &mut Engine, proofs: &[ActorProof]) -> Result<Proven> {
    let (accounts, key_actors): (Vec<&ActorProof>, Vec<&ActorProof>) = proofs.iter().partition(|p| matches!(p.record, osis_base::CreationRecord::KeyActor { account: true, .. }));
    let node = proofs.first().map(|p| p.actor());
    let mut proven = Proven { key_actors: key_actors.iter().map(|p| p.actor()).collect(), node, accounts: accounts.iter().map(|p| p.actor()).collect() };
    let claims: Vec<(Tid, Tid)> = proofs.iter().flat_map(|p| p.accounts.iter().map(move |a| (p.actor(), *a))).collect();
    let chain: Vec<Vec<u8>> = proofs.iter().flat_map(|p| p.chain.iter().cloned()).collect();
    proven.accounts.extend(engine.accounts_proven(&claims, &chain)?.into_iter().map(|(_, account)| account));
    Ok(proven)
}

impl SyncEngine {
    /// This node's own connection proofs.
    pub fn provers(&mut self) -> Result<Vec<Prover>> {
        provers(&mut self.engine)
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

    /// `proven`, by how each actor was proved.
    pub(super) fn connection_proven(&self, conn: ConnId) -> Option<&Proven> {
        self.conns.get(&conn).map(|c| &c.proven).or_else(|| self.served_proven(conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/wire.md §11.2 (MAX_CHAIN_BYTES): certificates past the cap are not sent and no account
    // is claimed, so the node proves its key alone
    #[test]
    fn chain_past_its_cap_claims_no_account_spec_wire_11_2() {
        let account = Tid::from_bytes([1; 15]);
        assert_eq!(claim_within_cap(account, vec![vec![0; MAX_CHAIN_BYTES]]).0, vec![account]);
        assert_eq!(claim_within_cap(account, vec![vec![0; MAX_CHAIN_BYTES], vec![0]]), (Vec::new(), Vec::new()));
    }
}
