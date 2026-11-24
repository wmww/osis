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
    crate::rotation::own_secrets_new(tx, node, &[], None, &mut done)?;
    let rec = crate::identity::thing_record(n, None, &mut *tx.rng);
    let root = rec.tid();
    tx.core.node_root = Some(root);
    tx.txn.put_local(records::NODE_ROOT, root.as_bytes(), Shred::No)?;
    let mut m = Mutation::new();
    m.create(rec);
    m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(n)) })?;
    crate::engine::write::commit_in(tx, m).map(|_| ())
}

/// An account as a library makes it (spec/permissions.md §8): no rule of core reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    /// A: minted with the node thing as mint admin, independent at its minting.
    pub thing: Tid,
    /// A's inbox (spec/sync-inbox.md §1): minted with admin A, independent, named by A's `keys.0`.
    pub inbox: Tid,
    /// A's profile (spec/sync-inbox.md §5 Contact card): minted with admin A, independent.
    pub profile: Tid,
}

impl Engine {
    /// Makes an account (spec/permissions.md §8 Making), in one transaction: A minted with the
    /// node thing as mint admin and made independent in its minting; its inbox and profile
    /// minted with admin A, each made independent, held by strongs from A's `holds.0`; A's
    /// `keys.0` naming the inbox, whose setting enables both inbox signals for `INBOX_LIFETIME`
    /// (spec/sync-inbox.md §1); and a strong to A in the node root's `holds.0`. The node enters A
    /// by its node thing's edge piece on it (its record edge, spec/permissions.md §4 Key part),
    /// the inbox and profile in A's sync unit.
    pub fn make_account(&mut self) -> Result<(Account, crate::flows::Done)> {
        self.run(|tx| {
            let mut done = crate::flows::Done::default();
            let me = tx.core.me();
            let arec = crate::identity::thing_record(me, None, &mut *tx.rng);
            let a = crate::rotation::own_secrets_new(tx, arec, &[], None, &mut done)?;
            let irec = crate::identity::thing_record(a, None, &mut *tx.rng);
            let inbox = crate::rotation::own_secrets_new(tx, irec, &[], None, &mut done)?;
            let prec = crate::identity::thing_record(a, None, &mut *tx.rng);
            let profile = crate::rotation::own_secrets_new(tx, prec, &[], None, &mut done)?;
            let mut m = Mutation::new();
            for t in [inbox, profile] {
                m.op(a, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(t)) })?;
            }
            done.add(crate::engine::write::commit_in(tx, m)?);
            let mut m = Mutation::new();
            let mut setting = ct::RetentionSetting::default();
            setting.take_inbox_signals();
            m.set(inbox, &ct::RETENTION, &setting)?;
            done.add(crate::engine::write::commit_in(tx, m)?);
            // `keys.0` is role-class: a role commit of its own
            let mut m = Mutation::new();
            m.op(a, &ct::KEYS, PathOp { path: vec![osis_crdt::PathSeg::Field(4)], op: Op::Set(osis_schema::Codec::to_value(&Some(osis_base::Weak(inbox)))) })?;
            done.add(crate::engine::write::commit_in(tx, m)?);
            // the node root's strong in a commit of its own: the root is local, its commits go
            // under no sync ID (spec/sync-set.md §1)
            let root = tx.core.node_root.ok_or(Error::Misuse("no node root"))?;
            let mut m = Mutation::new();
            m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(a)) })?;
            done.add(crate::engine::write::commit_in(tx, m)?);
            Ok((Account { thing: a, inbox, profile }, done))
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
