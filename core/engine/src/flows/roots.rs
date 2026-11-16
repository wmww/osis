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
    /// (spec/sync-set.md §3). The strong to the account root stays (`keeps_root_strongs`).
    pub fn unhold(&mut self, s: Strong) -> Result<()> {
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

/// Refuses a local write removing a strong the node's roots keep (spec/sync-set.md §1): the node
/// root's to the account root, the account root's to the profile and the inbox. A write
/// replacing or resetting such a `holds.0` whole keeps them only by naming them again.
pub(crate) fn keeps_root_strongs(tx: &mut Tx<'_>, m: &Mutation) -> Result<()> {
    let holds = osis_base::Ak::new("holds.0").map_err(|_| Error::Misuse("ak"))?;
    let mut kept: Vec<(Tid, Tid)> = Vec::new();
    if let (Some(root), Some((p, d))) = (tx.core.node_root, tx.core.account_devices()) {
        kept.push((root, d));
        let inbox = super::inbox::inbox_in(tx, &p)?;
        kept.extend(tx.core.profile_of(&p, inbox).map(|x| (d, x)));
        kept.extend(inbox.map(|i| (d, i)));
    }
    for (from, to) in kept {
        let removes = |v: &Value| matches!(v, Value::Strong(t) if *t == to);
        let names = |v: &Value| matches!(v, Value::Set(s) if s.iter().any(|x| matches!(x, Value::Strong(t) if *t == to)));
        let key = (from, holds.clone());
        let reset = m.dead_resets.contains_key(&key) || m.fresh_resets.contains_key(&key) || m.sweeps.contains(&key) || m.purge.iter().any(|p| *p.tid() == from && *p.ak() == holds);
        let cut = m.aspects.get(&key).is_some_and(|w| {
            w.ops.iter().any(|o| match &o.op {
                Op::Remove(v) => o.path.is_empty() && removes(v),
                Op::Set(v) | Op::Replace(v) => o.path.is_empty() && !names(v),
                _ => false,
            })
        });
        if reset || cut {
            return Err(Error::Misuse("the node root's strong to the account root, and the account root's to the profile and the inbox, stay"));
        }
    }
    Ok(())
}
