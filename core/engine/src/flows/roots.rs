//! The node root and the account root (spec/sync-set.md §1): the one local thing per node whose
//! closure the node holds, and the private thing beside the account its nodes read.

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

    /// This node's account root (spec/sync-set.md §1), strongly referenced from the node root.
    pub fn account_root(&self) -> Option<Tid> {
        self.core.account_devices().map(|(_, d)| d)
    }

    /// Adds `s` to the node root's `holds.0` (spec/data-model.md §8, spec/sync-set.md §1).
    pub fn hold(&mut self, s: Strong) -> Result<()> {
        self.run(|tx| hold_in(tx, s.0))
    }

    /// Removes `s` from the node root's `holds.0`: what only it held leaves the node closure
    /// (spec/sync-set.md §3). The strong to the account root stays (`Invalid`).
    pub fn unhold(&mut self, s: Strong) -> Result<()> {
        if Some(s.0) == self.account_root() {
            return Err(Error::Misuse("the node root's strong to the account root stays"));
        }
        let root = self.core.node_root.ok_or(Error::Misuse("no node root"))?;
        let mut m = Mutation::new();
        m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Remove(Value::Strong(s.0)) })?;
        self.commit(m).map(|_| ())
    }

    /// The node root, made at the node's first start (`bootstrap`): a thing whose first admin
    /// is the node, its commits the node's own.
    pub(crate) fn make_node_root(&mut self) -> Result<()> {
        let node = self.tid();
        self.run(|tx| {
            let rec = crate::identity::thing_record(node, &mut *tx.rng);
            let root = rec.tid();
            tx.core.node_root = Some(root);
            tx.txn.put_local(records::NODE_ROOT, root.as_bytes(), Shred::No)?;
            let mut m = Mutation::new();
            m.create(rec);
            crate::engine::write::commit_in(tx, m)?;
            Ok(())
        })
    }
}

/// Writes a strong from the node root's `holds.0` to `t`, in `tx`.
pub(crate) fn hold_in(tx: &mut Tx<'_>, t: Tid) -> Result<()> {
    let root = tx.core.node_root.ok_or(Error::Misuse("no node root"))?;
    let mut m = Mutation::new();
    m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) })?;
    crate::engine::write::commit_in(tx, m).map(|_| ())
}
