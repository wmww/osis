//! What a connection's proof exchange shows about accounts (spec/sync.md §10, Connection proofs;
//! until issues/account-signing.md step 6). Judged in a scratch engine holding only the proof's
//! chain, never this node's group data: what it holds can close a proof (a removal), never make one.

use crate::engine::{Config, Engine};
use crate::error::Result;
use osis_base::{Role, Tid};
use osis_crypto::SeededRng;
use osis_perm::At;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::BTreeSet;

impl Engine {
    /// `actor` is a node of `account` in the chain this node holds as canonical commit blobs,
    /// projected to the chain's parts: what a connection proof carries.
    pub fn account_chain(&mut self, account: &Tid) -> Result<Vec<Vec<u8>>> {
        let me = self.tid();
        let certs = self.chain_to(&me, account);
        let mut parts = std::collections::BTreeMap::new();
        self.cert_parts(&certs, &mut parts);
        let mut out = Vec::with_capacity(parts.len());
        for (c, keep) in parts {
            let Some(mut blob) = self.run(|tx| tx.get_commit(&c))? else { continue };
            blob.parts.retain(|p| keep.contains(&p.ai));
            out.push(blob.encode());
        }
        Ok(out)
    }

    /// The (actor, account) claims a proof's chain shows: the actor holds admin on the account
    /// (`until` disregarded, spec/crypto.md §4 Holders for keys) by the chain alone, and no removal
    /// this node holds closes it. Invariant: a claim counts only if it holds in the scratch engine
    /// given `chain` and nothing of this node's: `self` is read only to refuse.
    pub fn accounts_proven(&mut self, claims: &[(Tid, Tid)], chain: &[Vec<u8>]) -> Result<BTreeSet<(Tid, Tid)>> {
        if claims.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut seed = [0u8; 32];
        self.rng.fill_bytes(&mut seed);
        let mut scratch = Engine::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Config::default(), self.clock.clone(), Box::new(SeededRng::from_seed(seed)))?;
        // the order a chain's commits arrive in does not matter: each waits for what it names
        for bytes in chain {
            let _ = scratch.ingest(bytes, Vec::new());
        }
        Ok(claims.iter().copied().filter(|(actor, account)| scratch.node_of(actor, account) && !self.removed_from(actor, account)).collect())
    }

    /// Whether `node` holds admin on `account` here, as keys see it.
    fn node_of(&self, node: &Tid, account: &Tid) -> bool {
        match self.core.timelines.get(account) {
            Some(tl) => tl.role(node, account, At::KEYS) >= Some(Role::Admin),
            None => self.core.created(account).is_some_and(|r| r.first_admin() == Some(*node)),
        }
    }

    /// Whether this node holds an edge write on `node`'s grant on `account` and judges it no
    /// holder there: the removal it holds closes a proof made without it. An edge this node has
    /// never seen says nothing.
    fn removed_from(&self, node: &Tid, account: &Tid) -> bool {
        let seen = self.core.ix.held.commits_on(account).iter().any(|c| c.ops.iter().any(|o| o.holder == *node && o.target == *account));
        seen && !self.node_of(node, account)
    }
}
