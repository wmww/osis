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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::{Role, Tid, Value, WallMs};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;

    fn set_edge(lp: &mut LocalPeer, by: usize, thing: Tid, holder: Tid, role: Role) {
        let mut m = Mutation::new();
        let e = ct::Edge { role, until: None, invite: None, tied: None };
        m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
        m.op(thing, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(osis_schema::Codec::to_value(&e)) }).unwrap();
        if lp.peers[by].engine.needs_frontier(&thing, &holder, Some(&e)) {
            lp.peers[by].engine.write_addenda(false);
            m.frontier(osis_schema::Codec::to_value(&ct::Frontier::default()));
        }
        lp.peers[by].commit(m).unwrap();
    }

    /// Held writes a verifier feeds its scratch engine for a stranger's claim on its own thing `x`;
    /// the stranger's chain only names the verifier's `g` and `m` (`m` holds `g` at the verifier,
    /// `h` rewrites of that edge); no path runs through them. Returns how many writes were added.
    fn off_path_writes(h: usize) -> u64 {
        let mut lp = LocalPeer::new(2, 0x77 + h as u64, WallMs(1_700_000_000_000)).unwrap();
        let (a, b) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let mut m0 = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m0, a);
        m0.set(g, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        let m = lp.peers[0].engine.new_thing(&mut m0, a);
        m0.set(m, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m0).unwrap();
        for i in 0..h {
            set_edge(&mut lp, 0, g, m, if i % 2 == 0 { Role::Read } else { Role::Write });
            lp.advance(1);
        }
        let mut m1 = Mutation::new();
        let x = lp.peers[1].engine.new_thing(&mut m1, b);
        m1.set(x, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[1].commit(m1).unwrap();
        // all valid, on the stranger's own thing: a grant to its own y, then one removal naming y,
        // g and m (one removal of several others' edges is a single valid commit; removing an absent
        // edge is allowed); certificates follow a commit's every op
        let mut m2 = Mutation::new();
        let y = lp.peers[1].engine.new_thing(&mut m2, b);
        m2.set(y, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[1].commit(m2).unwrap();
        set_edge(&mut lp, 1, x, y, Role::Admin);
        set_edge(&mut lp, 1, x, g, Role::Read);
        set_edge(&mut lp, 1, x, m, Role::Read);
        lp.advance(1);
        lp.peers[1].engine.write_addenda(false);
        let mut m3 = Mutation::new();
        for holder in [y, g, m] {
            m3.op(x, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) }).unwrap();
        }
        m3.frontier(osis_schema::Codec::to_value(&ct::Frontier::default()));
        lp.peers[1].commit(m3).unwrap();
        // a stranger's own commits, all valid: the chain is whatever it sends
        let chain: Vec<Vec<u8>> = lp.packages(1).unwrap().into_iter().map(|p| p.bytes).collect();
        assert!(chain.iter().map(Vec::len).sum::<usize>() < 16 * 1024, "a chain of a few commits");
        let mut scratch = crate::engine::Engine::create(Box::new(osis_store::MemoryBackend::new()), Box::new(osis_store::MemoryRoot::new()), crate::engine::Config::default(), lp.peers[0].engine.clock.clone(), Box::new(osis_crypto::SeededRng::from_seed([1; 32]))).unwrap();
        for bytes in &chain {
            let _ = scratch.ingest(bytes, Vec::new());
        }
        let shown = std::collections::BTreeSet::from([(b, x)]);
        assert!(scratch.node_of(&b, &x), "the chain shows the claim");
        assert!(scratch.chain_to(&b, &x).created.contains(&g), "the chain's commits name g");
        lp.peers[0].engine.edge_writes_on(&scratch, &shown).unwrap().len() as u64
    }

    // spec/sync.md §10 (a held removal closes a proof "on any edge of the certificates' paths from
    // the key to the account"): edges the verifier holds between things a stranger's chain only
    // names, with no valid path of its own through them, are not read: the work is bounded by the
    // chain's paths, not by the verifier's other data.
    #[test]
    #[ignore]
    fn repro_held_edges_a_stranger_names_are_not_read() {
        let (small, big) = (off_path_writes(30), off_path_writes(300));
        println!("held writes fed to the scratch engine: {small} at h=30, {big} at h=300");
        assert!(big <= 2 * small + 2, "grows with held writes off the paths: {small} at 30, {big} at 300");
    }
}
