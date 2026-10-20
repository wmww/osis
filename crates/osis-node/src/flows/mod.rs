//! Membership flows (spec/permissions.md; notes/permissions.md Implementation): person actors under a
//! recovery key, pairing, grants and inbox delivery, changes and removals with their rotation,
//! demotions with the pre-sync and the receipt-record frontier, invite grants and self-removal,
//! re-seal, registration steps, links, recovery cards, lost-access cleanup. Rotations, the
//! cascade and departures live in `crate::rotation`.
//!
//! Flows build membership commits with `Mutation` (`sign_as` for a held recovery or link key,
//! `frontier`, `unchecked` where perm's invite and self-removal rules decide authority) and
//! return what must travel as `Delivery` values: node-sync places them (inbox blobs, direct
//! sends, placement before any other upload). Where a decision needs sync state (a complete pass
//! of an actor's labels) node-sync implements `SyncState`.

pub(crate) mod edges;
pub(crate) mod labels;
pub(crate) mod links;
pub(crate) mod person;
pub(crate) mod roster;
mod moving;

pub use roster::ROSTER_SNAPSHOT_AFTER;

pub use edges::{Demotion, PreSync};
pub use links::{LINK_SEED, LinkSpec};
pub use person::Person;

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::Mutation;
use osis_core::{Ak, CommitId, CreationRecord, LabelId, Role, Tid, Value, WallMs};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_keys::{KeysWrite, MemberKeys, Recipient, SecretsWrite};
use osis_label::Address;
use osis_perm::At;
use osis_schema::core_types::{self as ct, Inbox, Keys, Secrets};
use osis_schema::{AspectKey, Codec};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Something a flow produced that must travel (node-sync carries it out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// An inbox blob for actor `to` (spec/sync.md §3): placed under `inbox.label` by deposit, or
    /// by upload when the sender holds that label's write key.
    Inbox { to: Tid, inbox: Inbox, blob: Vec<u8> },
    /// Commits for node `to` over a direct connection (pairing; a node has no inbox).
    Direct { to: Tid, commits: Vec<CommitId> },
    /// Commits to place, in the same sync and before any other upload, under every label the
    /// node tracks of the things listed (a removal and the affected actors' new `/keys`,
    /// spec/permissions.md §3), stamped or by deposit.
    First { commits: Vec<CommitId>, under: Vec<Tid> },
    /// A certificate copy to place under the home label of `under` (spec/sync.md §3: a grantee
    /// device accepting a grant; deposit unless writer).
    Certificate { commits: Vec<CommitId>, under: Tid },
    /// A commit to place under the label of `under`, by deposit (a non-writer of that label: an
    /// invite grant or self-removal, spec/sync.md §5).
    Deposit { commit: CommitId, under: Tid },
}

/// What node-sync knows that flows need (notes/node.md, hooks).
pub trait SyncState {
    /// A complete pass of `actor`'s labels (the log of every server and peer it syncs them with
    /// read to its end) since the last membership commit of the actor applied from elsewhere
    /// (spec/permissions.md §3).
    fn complete_pass(&self, actor: &Tid) -> bool;
}

/// A flow's result: the commits written and what must travel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Done {
    pub commits: Vec<CommitId>,
    pub deliveries: Vec<Delivery>,
    /// Commits never uploaded under labels: re-seals travel by inbox only (spec/permissions.md
    /// §3); node-sync honours it.
    pub inbox_only: Vec<CommitId>,
    /// A self-removal: drop the secrets this node lost (`Engine::drop_lost_secrets`) once the
    /// commit is placed (node-sync's `carry_out` does).
    pub drop_lost: bool,
    /// Things a key actor signing these commits removed itself from (a single-use redemption
    /// removes L from K): placing these commits under them ignores that departure, as a node's
    /// own self-removal does (the next node that may rotate does).
    pub departed: Vec<Tid>,
}

impl Done {
    pub(crate) fn add(&mut self, c: Option<CommitId>) {
        self.commits.extend(c);
    }
    pub(crate) fn extend(&mut self, o: Done) {
        self.commits.extend(o.commits);
        self.deliveries.extend(o.deliveries);
        self.inbox_only.extend(o.inbox_only);
        self.drop_lost |= o.drop_lost;
        self.departed.extend(o.departed);
    }
}

pub(crate) fn ak(s: &str) -> Result<Ak> {
    Ak::new(s).map_err(|_| Error::Misuse("ak"))
}

/// Writes a `/secrets` write into `m` (removed boxes reset; boxes and history boxes as remove +
/// put, so a re-seal or grant re-writing an entry the member does not hold is a new entry there,
/// not a write into one it never got, spec/crypto.md §4).
pub(crate) fn put_secrets(m: &mut Mutation, actor: Tid, w: &SecretsWrite) -> Result<()> {
    for (k, b) in &w.boxes {
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) })?;
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0), PathSeg::Key(k.to_value())], op: Op::Set(b.to_value()) })?;
    }
    for k in &w.removed {
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) })?;
    }
    for (k, h) in &w.history {
        // remove + put: a put of an unchanged value writes nothing
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1)], op: Op::Remove(k.to_value()) })?;
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Set(Value::Bytes(h.clone())) })?;
    }
    Ok(())
}

/// Writes the rotated roles' keysets into `m` (whole keysets: the field is replaced).
pub(crate) fn put_keysets(m: &mut Mutation, actor: Tid, w: &KeysWrite) -> Result<()> {
    for (role, ks) in &w.keysets {
        let f = match role {
            Role::Read => 0,
            Role::Write => 1,
            Role::Admin => 2,
        };
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) })?;
    }
    Ok(())
}

/// An edge put (a change is remove + put, notes/node.md).
pub(crate) fn put_edge(m: &mut Mutation, target: Tid, member: Tid, e: &ct::Edge) -> Result<()> {
    m.op(target, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(e.to_value()) })?;
    Ok(())
}

pub(crate) fn remove_edge(m: &mut Mutation, target: Tid, member: Tid) -> Result<()> {
    m.op(target, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) })?;
    Ok(())
}

pub(crate) fn now_ts(core: &Core) -> osis_core::Ts {
    osis_core::Ts::make(core.now(), 0).unwrap_or_default()
}

impl Core {
    /// The typed state of `/keys` of `tid`.
    pub(crate) fn keys_in(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<Keys>> {
        Ok(tx.state(tid, &ak("/keys")?)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()))
    }

    /// Effective role of `node` on `tid` now.
    pub(crate) fn role_now(&self, node: &Tid, tid: &Tid) -> Option<Role> {
        crate::engine::write::role_of(self, node, tid, now_ts(self))
    }

    /// The owner of `tid` (none for a key actor or an unknown thing).
    pub(crate) fn owner(&self, tid: &Tid) -> Option<Tid> {
        match self.created(tid)? {
            CreationRecord::Thing { owner, .. } => Some(*owner),
            CreationRecord::KeyActor { .. } => None,
        }
    }

    pub(crate) fn is_key_actor(&self, tid: &Tid) -> bool {
        matches!(self.created(tid), Some(CreationRecord::KeyActor { .. }))
    }

    /// Current members of `actor` with their role and `until` (alive edges), owner first as
    /// admin.
    pub(crate) fn current_members(&self, actor: &Tid) -> Vec<(Tid, Role, Option<WallMs>)> {
        let mut out = Vec::new();
        if let Some(o) = self.owner(actor) {
            out.push((o, Role::Admin, None));
        }
        let ts = now_ts(self);
        if let Some(tl) = self.timelines.get(actor) {
            for (m, e) in tl.roster(actor, At::now(ts)) {
                if Some(m) != self.owner(actor) {
                    out.push((m, e.role, e.until));
                }
            }
        }
        out
    }

    /// The actor whose role secrets a label of `group` derives from: the group if it has
    /// secrets of its own, else its owner (spec/sync.md §3).
    pub(crate) fn has_own_secrets(&self, tid: &Tid) -> bool {
        self.own_keys.contains(tid)
    }
}

/// A recipient for boxes of `actor` to `member` at `role`, from the member's held `/keys`.
pub(crate) fn recipient(tx: &mut Tx<'_>, member: Tid, role: Role) -> Result<Recipient> {
    let keys = Core::keys_in(tx, &member)?;
    let keys = match (tx.core.is_key_actor(&member), keys) {
        (true, Some(k)) => MemberKeys::from_keys(&Keys { read: None, write: None, admin: None, ..k })?,
        (true, None) if member == tx.core.id.tid() => MemberKeys::KeyActor { kem: tx.core.id.keys().kem.public().clone(), seed: None },
        (true, None) => match tx.core.key_actors.get(&member) {
            Some(k) => MemberKeys::KeyActor { kem: k.keys().kem.public().clone(), seed: None },
            None => return Err(Error::Misuse("no /keys held for the member")),
        },
        (false, Some(k)) => {
            let mk = MemberKeys::from_keys(&k)?;
            match tx.core.secrets.get(&member) {
                Some(e) => mk.with_own(e),
                None => mk,
            }
        }
        (false, None) => return Err(Error::Misuse("the member has no secrets of its own")),
    };
    Ok(Recipient { member, role, keys })
}

/// The inbox a membership write about `member` goes to (spec/sync.md §2): its own, else the
/// nearest actor's above it. `None` for a key actor (direct delivery only).
pub(crate) fn inbox_of(tx: &mut Tx<'_>, member: &Tid) -> Result<Option<(Tid, Inbox)>> {
    let mut cur = *member;
    for _ in 0..64 {
        if tx.core.is_key_actor(&cur) {
            return Ok(None);
        }
        if let Some(i) = Core::keys_in(tx, &cur)?.and_then(|k| k.inbox) {
            return Ok(Some((cur, i)));
        }
        match tx.core.owner(&cur) {
            Some(o) => cur = o,
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// The newest label of `tid` (not replaced), with its servers.
pub(crate) fn own_label(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<(LabelId, Vec<Address>)>> {
    let labels = tx.state(tid, &ak("/label")?)?.and_then(Fragment::read).and_then(|v| ct::LABEL.decode(&v).ok()).unwrap_or_default();
    Ok(labels.into_iter().filter(|(_, l)| !l.replaced).max_by_key(|(_, l)| l.index).map(|(id, l)| (id, l.servers)))
}

/// A label a member can reach `tid` under: its own, a group's containing it, or the home label
/// of the nearest actor above it.
pub(crate) fn label_for(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<(LabelId, Vec<Address>)>> {
    if let Some(l) = own_label(tx, tid)? {
        return Ok(Some(l));
    }
    let groups: Vec<Tid> = tx.core.groups.get(tid).into_iter().flatten().copied().collect();
    for g in groups {
        if let Some(l) = own_label(tx, &g)? {
            return Ok(Some(l));
        }
    }
    let mut cur = *tid;
    for _ in 0..64 {
        match tx.core.owner(&cur) {
            Some(o) => {
                if let Some(l) = own_label(tx, &o)? {
                    return Ok(Some(l));
                }
                cur = o;
            }
            None => return Ok(None),
        }
    }
    Ok(None)
}

/// Whether key actor `t` is a node (it has a `/node` card), not a recovery or link key.
pub(crate) fn is_node(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    Ok(*t == tx.core.id.tid() || tx.core.by_aspect.contains_key(&(*t, ak("/node")?)))
}

/// The deposit seed in `/keys` of `actor`.
pub(crate) fn deposit_of(tx: &mut Tx<'_>, actor: &Tid) -> Result<[u8; 32]> {
    Core::keys_in(tx, actor)?.and_then(|k| k.deposit_seed).ok_or(Error::Misuse("no deposit seed in /keys"))
}

pub(crate) fn secrets_in(tx: &mut Tx<'_>, actor: &Tid) -> Result<Secrets> {
    Ok(tx.state(actor, &ak("/secrets")?)?.and_then(Fragment::read).and_then(|v| crate::engine::secrets::secrets_value(&v)).unwrap_or_default())
}

/// Persists the epochs held for `actor` (the `k/` record node-core loads).
pub(crate) fn save_epochs(tx: &mut Tx<'_>, actor: &Tid) -> Result<()> {
    if let Some(e) = tx.core.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
    }
    Ok(())
}

/// Re-opens the `/secrets` of every actor that boxes to `learned` after this node learned
/// secrets of `learned` (an actor's boxes open only once its member's epochs are held), to a
/// fixpoint. Called by node-core's state observation (engine hook).
pub(crate) fn reopen_dependents(tx: &mut Tx<'_>, learned: Tid) -> Result<()> {
    let mut work = vec![learned];
    let mut steps = 0usize;
    while let Some(m) = work.pop() {
        steps += 1;
        if steps > 4096 {
            break;
        }
        // the actors holding a box for `m`: from the index of keyed `/secrets` entries
        let actors: BTreeSet<Tid> = tx
            .core
            .box_keys
            .iter()
            .filter(|((a, _), v)| *a != m && osis_schema::core_types::BoxKey::from_value(v).is_ok_and(|k| k.member == m))
            .map(|((a, _), _)| *a)
            .collect();
        for a in actors {
            let s = secrets_in(tx, &a)?;
            tx.core.touch();
            if tx.core.ingest_secrets(&a, &s) {
                save_epochs(tx, &a)?;
                work.push(a);
            }
        }
    }
    Ok(())
}

/// Re-opens every held `/secrets` (after a key actor was taken up).
fn reopen_all(tx: &mut Tx<'_>) -> Result<()> {
    let secrets_ak = ak("/secrets")?;
    let actors: BTreeSet<Tid> = tx.core.by_aspect.keys().filter(|(_, a)| *a == secrets_ak).map(|(t, _)| *t).collect();
    for _ in 0..8 {
        let mut any = false;
        for a in &actors {
            let s = secrets_in(tx, a)?;
            tx.core.touch();
            if tx.core.ingest_secrets(a, &s) {
                save_epochs(tx, a)?;
                any = true;
            }
        }
        if !any {
            break;
        }
    }
    Ok(())
}

impl Engine {
    /// Takes up a key actor from its seed (a recovery key from a card, a link key from a link)
    /// for this session: it can sign (`Mutation::sign_as`) and its boxes open. Returns its tid.
    pub fn hold_key_actor(&mut self, seed: Secret32) -> Result<Tid> {
        let id = Identity::from_seed(seed);
        let t = id.tid();
        self.core.key_actors.insert(t, Arc::new(id));
        self.run(reopen_all)?;
        Ok(t)
    }

    /// How many key actors this node holds now (tests: a redeemer forgets the seed).
    pub fn held_key_actors(&self) -> usize {
        self.core.key_actors.len()
    }

    /// Forgets a held key actor (a redeemer discards the seed, spec/permissions.md §9).
    pub fn drop_key_actor(&mut self, tid: &Tid) {
        self.core.key_actors.remove(tid);
    }

    /// Commits `m` in a running transaction.
    pub(crate) fn commit_tx(tx: &mut Tx<'_>, m: Mutation) -> Result<Option<CommitId>> {
        crate::engine::write::commit_in(tx, m)
    }
}
