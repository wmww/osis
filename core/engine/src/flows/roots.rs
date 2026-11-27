//! The node root (spec/sync-set.md §1): the one local thing per node whose closure the node
//! holds.

use crate::engine::{records, Engine, Mutation, Tx};
use crate::error::{Error, Result};
use osis_base::{Strong, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_schema::core_types as ct;
use osis_store::Shred;

impl Engine {
    /// This node's node root (spec/sync-set.md §1): local, no sync ID, referenced by nothing.
    pub fn node_root(&self) -> Option<Tid> {
        self.core.node_root
    }

    /// Adds `s` to the node root's `holds.0` (spec/data-model.md §8, spec/sync-set.md §1).
    pub fn hold(&mut self, s: Strong) -> Result<()> {
        self.run(|tx| hold_in(tx, s.0))
    }

    /// Removes `s` from the node root's `holds.0`: what only it held leaves the node closure
    /// (spec/sync-set.md §3).
    pub fn unhold(&mut self, s: Strong) -> Result<()> {
        let root = self.core.node_root.ok_or(Error::Misuse("no node root"))?;
        let mut m = Mutation::new();
        m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Remove(Value::Strong(s.0)) })?;
        self.commit(m).map(|_| ())
    }
}

/// The node's first start (spec/sync-set.md §1, §2 Making a thing), in `tx`: its node thing N
/// minted with its key, independent at its minting (its keysets, sync ID and deposit seed, its
/// secrets this node's alone), and its node root, minted with admin N, a dependent of N, holding a
/// strong to N. Both made in one transaction, so each is in the node closure at its end.
pub(crate) fn first_start(tx: &mut Tx<'_>) -> Result<()> {
    let node = tx.core.id.record().clone();
    let n = node.tid();
    let mut done = crate::flows::Done::default();
    crate::rotation::own_secrets_new(tx, node, None, Vec::new(), &mut done)?;
    let rec = crate::identity::thing_record(n, None, &mut *tx.rng);
    let root = rec.tid();
    tx.core.node_root = Some(root);
    tx.txn.put_local(records::NODE_ROOT, root.as_bytes(), Shred::No)?;
    let mut m = Mutation::new();
    m.create(rec);
    m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(n)) })?;
    crate::engine::write::commit_in(tx, m).map(|_| ())
}

/// Writes a strong from the node root's `holds.0` to `t`, in `tx`.
pub(crate) fn hold_in(tx: &mut Tx<'_>, t: Tid) -> Result<()> {
    let root = tx.core.node_root.ok_or(Error::Misuse("no node root"))?;
    let mut m = Mutation::new();
    m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) })?;
    crate::engine::write::commit_in(tx, m).map(|_| ())
}
