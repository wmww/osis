//! What a connection's proof exchange shows about accounts (spec/sync.md §10, Connection proofs;
//! until issues/account-signing.md step 6). Judged in a scratch engine holding only the proof's
//! chain, never this node's group data: what it holds can close a proof (a removal), never make one.

use crate::engine::{Config, Engine};
use crate::error::Result;
use super::certs::Parts;
use osis_base::{BlobId, CommitId, Role, Tid};
use osis_crypto::SeededRng;
use osis_perm::{At, WriteId};
use osis_store::{MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet};

/// Blobs a commit links, sent with it.
type LinkedBlobs = Vec<(BlobId, Vec<u8>)>;

impl Engine {
    /// This node's chain to `account` as canonical commit blobs projected to the chain's parts:
    /// what a connection proof carries.
    pub fn account_chain(&mut self, account: &Tid) -> Result<Vec<Vec<u8>>> {
        let me = self.tid();
        let certs = self.chain_to(&me, account);
        let mut parts = BTreeMap::new();
        self.cert_parts(&certs, &mut parts);
        Ok(self.projected(parts)?.into_iter().map(|(_, bytes)| bytes).collect())
    }

    /// The (actor, account) claims a proof's chain shows: the actor holds admin on the account
    /// (`until` disregarded, spec/crypto.md §4 Holders for keys) by the chain alone, and still does
    /// once this node's own edge writes on the chain's paths are added to it, judged by the same
    /// rule. Invariant: a claim counts only if the scratch engine shows it from `chain` and nothing
    /// of this node's; what this node holds can close a claim (a removal anywhere on its paths),
    /// never make one.
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
        let shown: BTreeSet<(Tid, Tid)> = claims.iter().copied().filter(|(actor, account)| scratch.node_of(actor, account)).collect();
        if shown.is_empty() {
            return Ok(shown);
        }
        for (bytes, blobs) in self.edge_writes_on(&scratch, &shown)? {
            let _ = scratch.ingest(&bytes, blobs);
        }
        Ok(shown.into_iter().filter(|(actor, account)| scratch.node_of(actor, account)).collect())
    }

    /// This node's applied edge writes between the things on the paths `scratch` shows for `shown`,
    /// with what judges them, as commit blobs and their linked blobs.
    fn edge_writes_on(&mut self, scratch: &Engine, shown: &BTreeSet<(Tid, Tid)>) -> Result<Vec<(Vec<u8>, LinkedBlobs)>> {
        let things: BTreeSet<Tid> = shown.iter().flat_map(|(actor, account)| scratch.chain_to(actor, account).created).collect();
        let mut found = Vec::new();
        for t in &things {
            let Some(tl) = self.core.timelines.get(t) else { continue };
            for c in self.core.ix.held.commits_on(t) {
                for (i, _) in c.ops.iter().enumerate().filter(|(_, o)| o.target == *t && things.contains(&o.holder)) {
                    let id = WriteId(c.id, u32::try_from(i).unwrap_or(u32::MAX));
                    if tl.is_applied(&id) {
                        found.extend(tl.write_certificates(&id));
                    }
                }
            }
        }
        let mut parts = BTreeMap::new();
        for certs in &found {
            self.cert_parts(certs, &mut parts);
        }
        let mut out = Vec::new();
        for (c, bytes) in self.projected(parts.clone())? {
            let linked = parts.get(&c).map(|p| self.linked_blobs(&c, p)).transpose()?.unwrap_or_default();
            let blobs = self.run(|tx| linked.iter().filter_map(|b| tx.txn.get_blob(b).transpose().map(|r| r.map(|v| (*b, v)))).collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into))?;
            out.push((bytes, blobs));
        }
        Ok(out)
    }

    /// The canonical blobs of `parts`' commits, each projected to its parts.
    fn projected(&mut self, parts: BTreeMap<CommitId, Parts>) -> Result<Vec<(CommitId, Vec<u8>)>> {
        let mut out = Vec::with_capacity(parts.len());
        for (c, keep) in parts {
            let Some(mut blob) = self.run(|tx| tx.get_commit(&c))? else { continue };
            blob.parts.retain(|p| keep.contains(&p.ai));
            out.push((c, blob.encode()));
        }
        Ok(out)
    }

    /// Whether `node` holds admin on `account` here, as keys see it.
    fn node_of(&self, node: &Tid, account: &Tid) -> bool {
        match self.core.timelines.get(account) {
            Some(tl) => tl.role(node, account, At::KEYS) >= Some(Role::Admin),
            None => self.core.created(account).is_some_and(|r| r.first_admin() == Some(*node)),
        }
    }
}
