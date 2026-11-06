//! Role flows (spec/permissions.md; notes/permissions.md Implementation): person actors under a
//! recovery key, pairing, grants and inbox delivery, changes and removals with their rotation,
//! demotions with the pre-sync and the receipt-record frontier, invite grants and self-removal,
//! re-seal, registration steps, links, recovery cards, lost-access cleanup. Rotations, the
//! cascade and departures live in `crate::rotation`.
//!
//! Flows build role commits with `Mutation` (`sign_as` for a held recovery or link key,
//! `frontier`, `unchecked` where perm's invite and self-removal rules decide authority) and
//! return what must travel as `Delivery` values: node-sync places them (inbox blobs, direct
//! sends, placement before any other upload). Where a decision needs sync state (a complete pass
//! of an actor's labels) node-sync implements `SyncState`.

pub mod edges;
pub(crate) mod labels;
pub(crate) mod links;
mod create;
pub(crate) mod person;
pub mod tied;


pub use edges::{Demotion, PreSync};
pub use links::{HeldLink, LINK_SEED, LinkSpec};
pub use person::Person;
pub use tied::Untie;

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::Mutation;
use osis_base::{Ak, CommitId, CreationRecord, LabelId, Role, Tid, Value, WallMs};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_keys::{KeysWrite, HolderKeys, Recipient, SecretsWrite};
use osis_label::Address;
use osis_perm::At;
use osis_schema::core_types::{self as ct, Inbox, Keys, Secrets};
use osis_schema::{RawKey, Codec};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Something a flow produced that must travel (node-sync carries it out).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// An inbox blob for actor `to` (spec/sync.md §3): placed under `inbox.label` by deposit, or
    /// by upload when the sender holds that label's write key; `resend` seals it again.
    Inbox { to: Tid, inbox: Inbox, blob: Vec<u8>, resend: Resend },
    /// Commits for node `to` over a direct connection (pairing; a node has no inbox).
    Direct { to: Tid, commits: Vec<CommitId> },
    /// Commits to place, in the same sync and before any other upload, under every label the
    /// node tracks of the things listed (a removal and the affected actors' new `keys.0`,
    /// spec/permissions.md §3), stamped or by deposit.
    First { commits: Vec<CommitId>, under: Vec<Tid> },
    /// A certificate copy to place under the home label of `under` (spec/sync.md §3: a grantee
    /// node accepting a grant; deposit unless writer).
    Certificate { commits: Vec<CommitId>, under: Tid },
    /// A commit to place under the label of `under`, by deposit (a non-writer of that label: an
    /// invite grant, spec/sync.md §5).
    Deposit { commit: CommitId, under: Tid },
    /// A removal or lowering of actor `under`'s edge, placed under every label holding `under`
    /// as a certificate copy without its `secrets.0` and `keys.0` deltas (spec/permissions.md §2:
    /// those are for the target's remaining holders; a refreshed deposit seed is not the
    /// departed's to read).
    Removal { commit: CommitId, under: Tid },
}

/// What seals an inbox delivery again (spec/sync.md §3: re-sent after `INBOX_LIFETIME` while
/// the holder has not acted): the holder, the commit, the things named, whether only its
/// `roles.0` parts went (a removal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resend {
    pub holder: Tid,
    pub commit: CommitId,
    pub things: Vec<Tid>,
    pub edge_only: bool,
}

/// What node-sync knows that flows need (notes/engine-roles.md, Flows hooks).
pub trait SyncState {
    /// A complete pass of `actor`'s labels (the log of every host and peer it syncs them with
    /// read to its end) since the last role commit of the actor applied from elsewhere
    /// (spec/permissions.md §3).
    fn complete_pass(&self, actor: &Tid) -> bool;
}

/// A flow's result: the commits written and what must travel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Done {
    pub commits: Vec<CommitId>,
    pub deliveries: Vec<Delivery>,
    /// A self-removal: drop the secrets this node lost once the commit is placed (node-sync's
    /// `carry_out` arms that; the lost-access trigger leaves such losses, an app driving the
    /// engine alone calls `Engine::drop_lost_secrets`).
    pub drop_lost: bool,
}

/// Records `d` with node-sync in the running transaction, the one whose commit owes it
/// (`SyncRecords::owe`), and returns it: every delivery but an inbox blob (recorded by
/// `SyncRecords::note_unsent`) is made through here.
pub(crate) fn owe(tx: &mut Tx<'_>, d: Delivery) -> Result<Delivery> {
    if let Some(r) = tx.core.sync_records {
        r.owe(tx, &d, true)?;
    }
    Ok(d)
}

/// Drops the records of `ds` (`owe`): a flow that replaces what an inner transaction owed.
pub(crate) fn unowe(tx: &mut Tx<'_>, ds: &[Delivery]) -> Result<()> {
    if let Some(r) = tx.core.sync_records {
        for d in ds {
            r.owe(tx, d, false)?;
        }
    }
    Ok(())
}

impl Done {
    pub(crate) fn add(&mut self, c: Option<CommitId>) {
        self.commits.extend(c);
    }
    pub(crate) fn extend(&mut self, o: Done) {
        self.commits.extend(o.commits);
        self.deliveries.extend(o.deliveries);
        self.drop_lost |= o.drop_lost;
    }
}

pub(crate) fn ak(s: &str) -> Result<Ak> {
    Ak::new(s).map_err(|_| Error::Misuse("ak"))
}

/// Writes a `secrets.0` write into `m`: removed boxes reset; boxes and history boxes as remove +
/// put, so a re-seal or grant re-writing an entry is a new entry there, not a write into one the
/// holder never got or nothing for an unchanged value (spec/crypto.md §4), and one live entry
/// per key stays. `invite`: an invite grant, which may reset nothing (spec/permissions.md §2):
/// fresh puts only (`Op::Put`), a second live entry where the key is live.
pub(crate) fn put_secrets(m: &mut Mutation, actor: Tid, w: &SecretsWrite, invite: bool) -> Result<()> {
    let put = |m: &mut Mutation, field: u64, k: Value, v: Value| -> Result<()> {
        if invite {
            m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(field), PathSeg::Key(k)], op: Op::Put(v) })?;
        } else {
            m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(field)], op: Op::Remove(k.clone()) })?;
            m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(field), PathSeg::Key(k)], op: Op::Set(v) })?;
        }
        Ok(())
    };
    for (k, b) in &w.boxes {
        put(m, 0, k.to_value(), b.to_value())?;
    }
    for k in &w.removed {
        m.op(actor, &ct::SECRETS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Remove(k.to_value()) })?;
    }
    for (k, h) in &w.history {
        put(m, 1, k.to_value(), Value::Bytes(h.clone()))?;
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

/// An edge put (a change is remove + put, notes/engine-roles.md).
/// Writes `holder`'s edge on `target` as remove + put (spec/permissions.md §2): whatever entry
/// the state holds for it, valid or one the timeline dropped, is reset, never written into.
pub(crate) fn put_edge(m: &mut Mutation, target: Tid, holder: Tid, e: &ct::Edge) -> Result<()> {
    remove_edge(m, target, holder)?;
    m.op(target, &ct::ROLES, PathOp { path: vec![PathSeg::Key(Value::Tid(holder))], op: Op::Set(e.to_value()) })?;
    Ok(())
}

pub(crate) fn remove_edge(m: &mut Mutation, target: Tid, holder: Tid) -> Result<()> {
    m.op(target, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(holder)) })?;
    Ok(())
}

pub(crate) fn now_ts(core: &Core) -> osis_base::Ts {
    osis_base::Ts::make(core.now(), 0).unwrap_or_default()
}

impl Core {
    /// The typed state of `keys.0` of `tid`.
    pub(crate) fn keys_in(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<Keys>> {
        Ok(tx.state(tid, &ak("keys.0")?)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()))
    }

    /// Effective role of `node` on `tid` now.
    pub fn role_now(&self, node: &Tid, tid: &Tid) -> Option<Role> {
        crate::engine::write::role_of(self, node, tid, now_ts(self))
    }

    /// The first admin of `tid` (spec/permissions.md §1): the next actor up its record chain,
    /// whose secrets a plain `tid` derives from (spec/crypto.md §3). None for a key actor or an
    /// unknown thing.
    pub(crate) fn first_admin(&self, tid: &Tid) -> Option<Tid> {
        self.created(tid)?.first_admin()
    }

    pub fn is_key_actor(&self, tid: &Tid) -> bool {
        matches!(self.created(tid), Some(CreationRecord::KeyActor { .. }))
    }

    /// The things whose inbox `a` may use (spec/sync.md §2): `a`, then its first admin while
    /// `a`'s record edge stands here, and so on up its record chain (key actors have none).
    pub(crate) fn inbox_chain(&self, a: &Tid) -> Vec<Tid> {
        let mut out = Vec::new();
        for step in self.owner_chain(a) {
            let osis_base::ChainStep::Up { thing, admin } = step else { break };
            out.push(thing);
            if !self.key_holders(&thing).iter().any(|(m, _)| *m == admin) {
                break;
            }
        }
        out
    }

    /// Current holders of `actor` with their role and `until` (alive edges), its record edge
    /// included while it stands (with no timeline here, nothing wrote it: the first admin alone).
    pub fn current_holders(&self, actor: &Tid) -> Vec<(Tid, Role, Option<WallMs>)> {
        let ts = now_ts(self);
        match self.timelines.get(actor) {
            Some(tl) => tl.roster(actor, At::now(ts)).into_iter().map(|(m, e)| (m, e.role, e.until)).collect(),
            None => self.first_admin(actor).map(|a| (a, Role::Admin, None)).into_iter().collect(),
        }
    }

    /// The holders of `actor` for keys (spec/crypto.md §4): every holder of an edge on it by
    /// `rotation::key_role` (its record edge included while it stands), every held applied
    /// write in effect and `until` disregarded: keys read no clock, so an edge past its `until`
    /// stays until it is finalized (spec/permissions.md §2).
    pub fn key_holders(&self, actor: &Tid) -> Vec<(Tid, Role)> {
        match self.timelines.get(actor) {
            Some(tl) => tl.edges_at(None).holders(actor).filter_map(|(m, e)| Some((*m, crate::rotation::key_role(Some(e))?))).collect(),
            None => self.first_admin(actor).map(|a| (a, Role::Admin)).into_iter().collect(),
        }
    }

    /// Whether `tid` has role secrets of its own (else a plain thing derives them from its first
    /// admin's, spec/crypto.md §3).
    pub(crate) fn has_own_secrets(&self, tid: &Tid) -> bool {
        self.ix.own_keys.contains(tid)
    }
}

/// A recipient for boxes of `actor` to `holder` at `role`, from the holder's held `keys.0`.
pub(crate) fn recipient(tx: &mut Tx<'_>, holder: Tid, role: Role) -> Result<Recipient> {
    let keys = Core::keys_in(tx, &holder)?;
    let keys = match (tx.core.is_key_actor(&holder), keys) {
        (true, Some(k)) => HolderKeys::from_keys(&Keys { read: None, write: None, admin: None, ..k })?,
        (true, None) if holder == tx.core.id.tid() => HolderKeys::KeyActor { kem: tx.core.id.keys().kem.public().clone(), seed: None },
        (true, None) => match tx.core.key_actors.get(&holder) {
            Some(k) => HolderKeys::KeyActor { kem: k.keys().kem.public().clone(), seed: None },
            None => return Err(Error::Misuse("no keys.0 held for the holder")),
        },
        // a key-actor KEM key on an actor's `keys.0` is never sealed to (only key actors have one)
        (false, Some(k)) => {
            let mk = HolderKeys::from_keys(&Keys { key: None, ..k })?;
            match tx.core.own_epochs(&holder) {
                Some(e) => mk.with_own(&e),
                None => mk,
            }
        }
        (false, None) => return Err(Error::Misuse("the holder has no secrets of its own")),
    };
    Ok(Recipient { holder, role, keys })
}

/// The inbox a role write about `holder` goes to (spec/sync.md §2): the one its `keys.0`
/// names, else its own live label; else its first admin's, the same way, while its record edge
/// stands here, and so on up (`Core::inbox_chain`). `None` for a key actor (direct delivery
/// only) and when none is known here. The readers of the thing try every label a blob about it
/// may come under (`Engine::inbox_candidates`): a sender that holds the thing's label uses it,
/// one that knows the thing by its `keys.0` alone goes up the chain.
pub(crate) fn inbox_of(tx: &mut Tx<'_>, holder: &Tid) -> Result<Option<(Tid, Inbox)>> {
    if tx.core.is_key_actor(holder) {
        return Ok(None);
    }
    for t in tx.core.inbox_chain(holder) {
        if let Some(i) = Core::keys_in(tx, &t)?.and_then(|k| k.inbox) {
            return Ok(Some((t, i)));
        }
        if let Some((label, _, hosts)) = own_label(tx, &t)? {
            return Ok(Some((t, Inbox { label, hosts })));
        }
    }
    Ok(None)
}

/// The newest unreplaced label of `tid`: ID, index, hosts.
pub(crate) fn own_label(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<(LabelId, u64, Vec<Address>)>> {
    let labels = tx.state(tid, &ak("label.0")?)?.and_then(Fragment::read).and_then(|v| ct::LABEL.decode(&v).ok()).unwrap_or_default();
    Ok(labels.into_iter().filter(|(_, l)| !l.replaced).max_by_key(|(_, l)| l.index).map(|(id, l)| (id, l.index, l.hosts)))
}

/// Whether key actor `t` is a node (it has a `node.0` card), not a recovery or link key.
pub(crate) fn is_node(tx: &mut Tx<'_>, t: &Tid) -> Result<bool> {
    Ok(*t == tx.core.id.tid() || tx.has_state(t, &ak("node.0")?)?)
}

/// The deposit seed in `keys.0` of `actor`.
pub(crate) fn deposit_of(tx: &mut Tx<'_>, actor: &Tid) -> Result<[u8; 32]> {
    Core::keys_in(tx, actor)?.and_then(|k| k.deposit_seed).ok_or(Error::Misuse("no deposit seed in keys.0"))
}

/// `secrets.0` of `actor`, decoded, held until its state changes (`Core::secrets_read`).
pub(crate) fn secrets_in(tx: &mut Tx<'_>, actor: &Tid) -> Result<Arc<Secrets>> {
    if let Some(s) = tx.core.secrets_read.get(actor).cloned() {
        #[cfg(debug_assertions)]
        assert_eq!(*s, secrets_decoded(tx, actor)?, "secrets_read of {actor:?} went stale");
        return Ok(s);
    }
    let _s = crate::costs::span("secrets: decode");
    let s = Arc::new(secrets_decoded(tx, actor)?);
    tx.core.secrets_read.insert(*actor, s.clone());
    Ok(s)
}

fn secrets_decoded(tx: &mut Tx<'_>, actor: &Tid) -> Result<Secrets> {
    Ok(tx.state(actor, &ak("secrets.0")?)?.and_then(Fragment::read).and_then(|v| crate::engine::secrets::secrets_value(&v)).unwrap_or_default())
}

/// `crate::engine::secrets::history_alts` of `actor`'s `secrets.0` state.
pub(crate) fn secrets_alts(tx: &mut Tx<'_>, actor: &Tid) -> Result<osis_keys::HistoryAlts> {
    Ok(tx.state(actor, &ak("secrets.0")?)?.map(crate::engine::secrets::history_alts).unwrap_or_default())
}

/// Persists the epochs held for `actor` (the `k/` record node-core loads).
pub(crate) fn save_epochs(tx: &mut Tx<'_>, actor: &Tid) -> Result<()> {
    tx.core.role_changed();
    tx.core.waits.secrets_changed(actor);
    if let Some(e) = tx.core.ix.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
    }
    Ok(())
}

/// Re-opens the `secrets.0` of every actor that boxes to `learned` after this node learned
/// secrets of `learned` (an actor's boxes open only once its holder's epochs are held), to a
/// fixpoint. Called by node-core's state observation (engine hook). Terminates without a step
/// cap: an actor is pushed only when its held epochs grew, and they only grow, bounded by the
/// boxes held (a cap would leave secrets of deep holder chains unopened).
pub(crate) fn reopen_dependents(tx: &mut Tx<'_>, learned: Tid) -> Result<()> {
    let mut work = vec![learned];
    while let Some(m) = work.pop() {
        // the boxes keyed to `m`, per actor: from the index of keyed `secrets.0` entries
        let mut per: std::collections::BTreeMap<Tid, Vec<osis_base::Value>> = std::collections::BTreeMap::new();
        for (a, k) in tx.core.ix.boxes_to.get(&m).into_iter().flatten() {
            if *a != m {
                per.entry(*a).or_default().push(k.clone());
            }
        }
        for (a, keys) in per {
            if crate::apply::ingest_secrets_keys(tx, &a, &keys, &[])? {
                save_epochs(tx, &a)?;
                work.push(a);
            }
        }
    }
    Ok(())
}

/// Re-opens every held `secrets.0` (after a key actor was taken up), to a fixpoint: what an
/// actor learns reopens its dependents at once (`reopen_dependents`, so a holder-actor chain
/// opens in one sweep whatever its tid order); sweeps repeat until one learns nothing (held
/// epochs only grow, so no round cap is needed; a cap left deep chains unopened).
fn reopen_all(tx: &mut Tx<'_>) -> Result<()> {
    let secrets_ak = ak("secrets.0")?;
    let actors: BTreeSet<Tid> = tx.core.ix.by_aspect.keys().filter(|(_, a)| *a == secrets_ak).map(|(t, _)| *t).collect();
    loop {
        let mut any = false;
        for a in &actors {
            let s = secrets_in(tx, a)?;
            let alts = secrets_alts(tx, a)?;
            tx.core.touch();
            if tx.core.ingest_secrets(a, &s, None, &alts) {
                save_epochs(tx, a)?;
                reopen_dependents(tx, *a)?;
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
    /// The inbox a role write about `holder` goes to (`inbox_of`): the actor whose inbox it is,
    /// and the inbox.
    pub fn inbox_of_actor(&mut self, holder: &Tid) -> Result<Option<(Tid, Inbox)>> {
        let h = *holder;
        self.run(|tx| inbox_of(tx, &h))
    }

    pub fn hold_key_actor(&mut self, seed: Secret32) -> Result<Tid> {
        let id = Identity::from_seed(seed);
        let t = id.tid();
        self.core.key_actors.insert(t, Arc::new(id));
        self.core.role_changed();
        // boxes of pending commits may open to it
        self.core.waits.clear();
        self.run(reopen_all)?;
        Ok(t)
    }

    /// Whether key actor `t` is a node (`is_node`): it has a `node.0` card here.
    pub fn is_node(&mut self, t: &Tid) -> Result<bool> {
        let t = *t;
        self.run(|tx| is_node(tx, &t))
    }

    /// How many key actors this node holds now (tests: a redeemer forgets the seed).
    pub fn held_key_actors(&self) -> usize {
        self.core.key_actors.len()
    }

    /// Forgets a held key actor (a redeemer discards the seed, spec/permissions.md §7).
    pub fn drop_key_actor(&mut self, tid: &Tid) {
        self.core.key_actors.remove(tid);
        self.core.role_changed();
    }

    /// Commits `m` in a running transaction.
    pub(crate) fn commit_tx(tx: &mut Tx<'_>, m: Mutation) -> Result<Option<CommitId>> {
        crate::engine::write::commit_in(tx, m)
    }
}
