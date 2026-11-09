//! What a connection's proof exchange shows about accounts (spec/sync.md §10, Connection proofs;
//! until issues/account-signing.md step 6). Judged in a scratch engine holding only the proof's
//! chain, never this node's data.

use crate::engine::{Config, Engine};
use crate::error::Result;
use osis_base::{Role, Tid};
use osis_crypto::SeededRng;
use osis_perm::At;
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet};

impl Engine {
    /// This node's chain to `account` as canonical commit blobs projected to the chain's parts:
    /// what a connection proof carries.
    pub fn account_chain(&mut self, account: &Tid) -> Result<Vec<Vec<u8>>> {
        let me = self.tid();
        let certs = self.chain_to(&me, account);
        let mut parts = BTreeMap::new();
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
    /// (`until` disregarded, spec/crypto.md §4 Holders for keys) by the chain alone. Invariant:
    /// nothing this node holds is read, so it neither makes a claim nor closes one.
    pub fn accounts_proven(&mut self, claims: &[(Tid, Tid)], chain: &[Vec<u8>]) -> Result<BTreeSet<(Tid, Tid)>> {
        if claims.is_empty() {
            return Ok(BTreeSet::new());
        }
        let mut seed = [0u8; 32];
        self.rng.fill_bytes(&mut seed);
        let mut scratch = Engine::create(Box::new(MemoryBackend::new()), Box::new(MemoryRoot::new()), Config::default(), self.clock.clone(), Box::new(SeededRng::from_seed(seed)))?;
        // the order a chain's commits arrive in does not matter: creations first, then by `ts`, as
        // a batch is judged; what is still unjudgeable (nothing is kept of it, spec/commits.md §4)
        // is judged again while anything applied: a linear chain lands in one round
        let mut order: Vec<(bool, osis_base::Ts, &Vec<u8>)> = chain.iter().map(|b| match osis_commit::CommitBlob::decode(b) {
            Ok(c) => (!c.header.aspects.iter().any(|a| a.ak.as_str() == "created.0"), c.header.ts, b),
            Err(_) => (true, osis_base::Ts::default(), b),
        }).collect();
        order.sort();
        let mut waiting: Vec<&Vec<u8>> = order.into_iter().map(|(_, _, b)| b).collect();
        while !waiting.is_empty() {
            let before = waiting.len();
            waiting.retain(|b| matches!(scratch.ingest(b, Vec::new()), Ok(crate::Ingested::Awaits(..))));
            if waiting.len() == before {
                break;
            }
        }
        Ok(claims.iter().copied().filter(|(actor, account)| scratch.node_of(actor, account)).collect())
    }

    /// Whether `node` holds admin on `account` here, as keys see it.
    fn node_of(&self, node: &Tid, account: &Tid) -> bool {
        match self.core.timelines.get(account) {
            Some(tl) => tl.role(node, account, At::KEYS) >= Some(Role::Admin),
            None => self.core.created(account).is_some_and(|r| r.first_admin() == Some(*node)),
        }
    }
}
