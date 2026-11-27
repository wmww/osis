//! Role flows (spec/permissions.md; notes/engine-roles.md, Role flows): accounts, pairing,
//! grants and inbox delivery, changes and removals with their rotation,
//! demotions with their frontier, may-grant grants and self-removal,
//! re-seal, registration steps, links, lost-access cleanup. Rotations, the
//! cascade and departures live in `crate::rotation`.
//!
//! Flows build role commits with `Mutation` (`sign_as` for a held link key,
//! `frontier`, `unchecked` where perm's may-grant and self-removal rules decide authority) and
//! return the commits written; an inbox delivery a commit owes is recorded in its transaction
//! (`sync::deliveries::owe`). Where a decision needs sync state (a complete pass of an actor's
//! sync IDs) it reads what sync noted (`Engine::note_complete_pass`).

pub(crate) mod addenda;
pub mod cards;
pub mod edges;
pub(crate) mod sync_ids;
pub(crate) mod links;
mod create;
pub(crate) mod inbox;
pub(crate) mod roots;


pub use edges::{Demotion, Removal};
pub use links::{HeldLink, LINK_SEED, LinkSpec};

use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::Mutation;
use osis_base::{Ak, CommitId, SyncId, Role, Tid, Value, WallMs};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::Secret32;
use osis_keys::{KeysWrite, HolderKeys, Recipient, SecretsWrite};
use osis_perm::At;
use osis_schema::core_types::{self as ct, Keys, Secrets};
use osis_schema::{RawKey, Codec};
use std::collections::BTreeSet;
use std::sync::Arc;

/// A flow's result: the commits written. What travels is derived from them: inbox deliveries
/// owed in their transactions (`sync::deliveries`), bodies by the sync judgement.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Done {
    pub commits: Vec<CommitId>,
}

impl Done {
    pub(crate) fn add(&mut self, c: Option<CommitId>) {
        self.commits.extend(c);
    }
    pub(crate) fn extend(&mut self, o: Done) {
        self.commits.extend(o.commits);
    }
}

pub(crate) fn ak(s: &str) -> Result<Ak> {
    Ak::new(s).map_err(|_| Error::Misuse("ak"))
}

/// Writes a `secrets.0` write into `m`: removed boxes reset; boxes and history boxes as remove +
/// put, so a re-seal or grant re-writing an entry is a new entry there, not a write into one the
/// holder never got or nothing for an unchanged value (spec/crypto.md §4), and one live entry
/// per key stays. `new_only`: fresh puts only (`Op::Put`), resetting nothing, a second live entry
/// where the key is live (a may-grant grant's shape, spec/permissions.md §2; a history add,
/// spec/crypto.md §4).
pub(crate) fn put_secrets(m: &mut Mutation, actor: Tid, w: &SecretsWrite, new_only: bool) -> Result<()> {
    let put = |m: &mut Mutation, field: u64, k: Value, v: Value| -> Result<()> {
        if new_only {
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

/// `keys.0`'s field of box records (spec/crypto.md §4 Box records; spec/wire.md §7).
pub(crate) const SEALED: u64 = 8;

/// Removes from `m` every record of `actor`'s `keys.0` state at the roles `roles` a rotation
/// rotates: its records replace them, as its keysets replace theirs (spec/crypto.md §4 Box
/// records).
pub(crate) fn unseal(tx: &mut Tx<'_>, m: &mut Mutation, actor: Tid, roles: &BTreeSet<osis_base::Role>) -> Result<()> {
    let held = Core::keys_in(tx, &actor)?.map(|k| k.sealed).unwrap_or_default();
    for k in held.keys().filter(|k| roles.contains(&k.role)) {
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED)], op: Op::Remove(k.to_value()) })?;
    }
    Ok(())
}

/// Writes the rotated roles' keysets into `m` (whole keysets: the field is replaced) and the
/// records of the rotation's boxes, each as remove + put (spec/crypto.md §4 Box records).
pub(crate) fn put_keysets(m: &mut Mutation, actor: Tid, w: &KeysWrite) -> Result<()> {
    for (role, ks) in &w.keysets {
        let f = osis_keys::aspects::keyset_field(*role);
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) })?;
    }
    for (k, ks) in &w.sealed {
        let v = ks.iter().map(osis_keys::aspects::to_schema).collect::<BTreeSet<ct::Epoch>>().to_value();
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED)], op: Op::Remove(k.to_value()) })?;
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED), PathSeg::Key(k.to_value())], op: Op::Set(v) })?;
    }
    Ok(())
}

/// A new entry holding `holder`'s whole edge on `target` (spec/crdt.md §5.6 `put_new`): never
/// written into a held entry. The reset of the holder's current entry is the caller's
/// (`edges::reset_current`, spec/permissions.md §2).
pub(crate) fn put_edge(m: &mut Mutation, target: Tid, holder: impl Into<osis_base::Holder>, e: &ct::Edge) -> Result<()> {
    let holder = holder.into();
    let path = vec![PathSeg::Key(crate::apply::validity::Grants::key(&holder))];
    match holder {
        osis_base::Holder::Thing(_) => m.op(target, &ct::ROLES, PathOp { path, op: Op::Put(e.to_value()) })?,
        osis_base::Holder::Key(_) => m.op(target, &ct::SIGNERS, PathOp { path, op: Op::Put(e.to_value()) })?,
    };
    Ok(())
}

pub(crate) fn now_ts(core: &Core) -> osis_base::Ts {
    ts_at(core.now().0)
}

/// Wall ms `now` as a `ts`.
pub(crate) fn ts_at(now: u64) -> osis_base::Ts {
    osis_base::Ts::make(WallMs(now), 0).unwrap_or_default()
}

impl Core {
    /// The typed state of `keys.0` of `tid`.
    pub(crate) fn keys_in(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<Keys>> {
        Ok(tx.state(tid, &ak("keys.0")?)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()))
    }

    /// Effective role of `node` on `tid` now: read on the memo clock up to the first `until` the
    /// answer depends on (`Timeline::roles_on_now`), so a memo reading it (the thing lists a sync
    /// ID carries, access) moves when that passes, with a wake then (`Engine::clock_next`).
    pub fn role_now(&self, node: &Tid, tid: &Tid) -> Option<Role> {
        self.time.at(|now| {
            let (role, until) = self.timelines().role_now(node, tid, ts_at(now));
            (role, until.map(|u| u.0))
        })
    }

    /// The mint admin of `tid` (spec/permissions.md §1): the next thing up its record chain,
    /// whose secrets a dependent `tid` derives from (spec/crypto.md §3). None for a thing minted
    /// with a key or an unknown thing.
    pub(crate) fn mint_admin(&self, tid: &Tid) -> Option<Tid> {
        self.created(tid)?.mint_admin()
    }

    /// Current holders of `actor` with their role and `until` (alive edges), its record edge
    /// included while it stands (with no timeline here, nothing wrote it: the mint admin alone).
    pub fn current_holders(&self, actor: &Tid) -> Vec<(Tid, Role, Option<WallMs>)> {
        let ts = now_ts(self);
        match self.timelines().on(actor) {
            Some(on) => on.roster(At::now(ts)).into_iter().map(|(m, e)| (m, e.role, e.until)).collect(),
            None => self.mint_admin(actor).map(|a| (a, Role::Admin, None)).into_iter().collect(),
        }
    }

    /// The holders of `actor` for keys (spec/crypto.md §4): every holder of an edge on it by
    /// `rotation::key_role` (its record edge included while it stands), every held applied
    /// write in effect and `until` disregarded: keys read no clock, so an edge past its `until`
    /// stays until it is finalized (spec/permissions.md §2). A destroyed thing is none: it holds
    /// no keys and nobody stands in for it (spec/crypto.md §4, Holder actors, Destroyed).
    pub fn key_holders(&self, actor: &Tid) -> Vec<(Tid, Role)> {
        self.edge_holders(actor).into_iter().filter(|(m, _)| !self.destroyed(m)).collect()
    }

    /// The direct holders of `actor` for keys with destroyed things among them (`key_holders`
    /// keeps them out): every edge on it by `rotation::key_role`, its record edge included while
    /// it stands.
    pub(crate) fn edge_holders(&self, actor: &Tid) -> Vec<(Tid, Role)> {
        match self.timelines().on(actor) {
            Some(on) => on.holders().into_iter().filter_map(|(m, e)| Some((m, crate::rotation::key_role(Some(&e))?))).collect(),
            None => self.mint_admin(actor).map(|a| (a, Role::Admin)).into_iter().collect(),
        }
    }

    /// Whether `tid` is independent (else a dependent thing derives its role secrets from its mint
    /// admin's, spec/crypto.md §3).
    pub(crate) fn is_independent(&self, tid: &Tid) -> bool {
        self.ix.independent.contains(tid)
    }
}

/// A recipient for boxes of `actor` to `holder` at `role`, from the holder's held `keys.0`.
pub(crate) fn recipient(tx: &mut Tx<'_>, holder: Tid, role: Role) -> Result<Recipient> {
    let Some(k) = Core::keys_in(tx, &holder)? else { return Err(Error::Misuse("the holder is not independent")) };
    let mk = HolderKeys::from_keys(&k)?;
    // a holder whose secrets this node holds (its own things, a held link key) is boxed
    // symmetrically
    let keys = match tx.core.link_key_epochs(&holder).map(std::sync::Arc::new).or_else(|| tx.core.own_epochs(&holder)) {
        Some(e) => mk.with_own(&e),
        None => mk,
    };
    Ok(Recipient { holder, role, keys, floor: 0 })
}

/// The sync ID of `tid` by its seed or its `keys.0` (spec/sync-ids.md §4 Owner,
/// `sync_ids::actors::owner_sync_id`), a hint included.
pub(crate) fn sync_id_of(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<SyncId>> {
    Ok(crate::sync_ids::actors::owner_sync_id(tx, tid)?.map(|o| o.id))
}

/// `secrets.0` of `actor`, decoded (`Core::secrets_read`).
pub(crate) fn secrets_in(tx: &mut Tx<'_>, actor: &Tid) -> Result<Arc<Secrets>> {
    osis_base::memo::Memo::get_in(tx, |tx| &tx.core.secrets_read, actor, |tx| secrets_decoded(tx, actor).map(Arc::new))
}

fn secrets_decoded(tx: &mut Tx<'_>, actor: &Tid) -> Result<Secrets> {
    Ok(tx.state(actor, &ak("secrets.0")?)?.and_then(Fragment::read).and_then(|v| crate::engine::secrets::secrets_value(&v)).unwrap_or_default())
}

/// `crate::engine::secrets::history_alts` of `actor`'s `secrets.0` state.
pub(crate) fn secrets_alts(tx: &mut Tx<'_>, actor: &Tid) -> Result<osis_keys::HistoryAlts> {
    Ok(tx.state(actor, &ak("secrets.0")?)?.map(crate::engine::secrets::history_alts).unwrap_or_default())
}

/// What `actor`'s whole `secrets.0` state gives under the secrets held now (`SecretsRead::State`),
/// then what that opens in turn (`reopen_dependents`). Whether anything was learned. The read of
/// an actor whose state moved (`apply::observe_state`), of one whose roles came to give what they
/// kept out (`retake`), and of every actor at a load (`reopen_all`), live and rebuilt alike.
pub(crate) fn observe_secrets(tx: &mut Tx<'_>, actor: &Tid) -> Result<bool> {
    let s = secrets_in(tx, actor)?;
    let alts = secrets_alts(tx, actor)?;
    tx.core.touch();
    let learned = tx.core.ingest_secrets(actor, &s, crate::engine::secrets::SecretsRead::State, &alts);
    if learned {
        reopen_dependents(tx, *actor)?;
    }
    Ok(learned)
}

/// After this node learned secrets of `learned`, reads again everything they may open, to a
/// fixpoint: of `learned` itself and of every actor with a box keyed to an actor that learned,
/// `reread`. So what an actor holds is what reading its state and invalid commits whole after
/// gives (a rebuild: `reopen_all`), whichever input brought the secrets (a state, an invalid or
/// pending commit's boxes, a take-up). Terminates without a step cap: an actor is pushed only
/// when its held epochs grew, and they only grow, bounded by the boxes held (a cap would leave
/// secrets of deep holder chains unopened).
pub(crate) fn reopen_dependents(tx: &mut Tx<'_>, learned: Tid) -> Result<()> {
    let mut work = vec![learned];
    while let Some(m) = work.pop() {
        // what `m`'s secrets open of its own `secrets.0`
        while reread(tx, &m, &[])? {}
        // the boxes keyed to `m`, per actor: from the index of keyed `secrets.0` entries
        let mut per: std::collections::BTreeMap<Tid, Vec<osis_base::Value>> = std::collections::BTreeMap::new();
        for (a, k) in tx.core.ix.boxes_to.get(&m).into_iter().flatten() {
            if *a != m {
                per.entry(*a).or_default().push(k.clone());
            }
        }
        for (a, keys) in per {
            if reread(tx, &a, &keys)? {
                work.push(a);
            }
        }
    }
    Ok(())
}

/// What `actor`'s held `secrets.0` gives under the secrets held now, its whole state aside: the
/// applied boxes keyed `boxes`, the history box of every epoch whose secret is held, repeatedly
/// (`apply::ingest_secrets_keys`), and its invalid commits' deltas, for reading (a box proves
/// itself by what it opens: `keys::reread_invalid`). O(those boxes + held epochs + the commits
/// invalid there). Whether anything was learned.
fn reread(tx: &mut Tx<'_>, actor: &Tid, boxes: &[osis_base::Value]) -> Result<bool> {
    let learned = crate::apply::ingest_secrets_keys(tx, actor, boxes, &[])?;
    Ok(crate::apply::keys::reread_invalid(tx, actor)? | learned)
}

/// Re-opens the `secrets.0` of every actor whose applied boxes gave secrets `rotation::may_take_role`
/// kept out (`Waits::untaken`) where the node's roles now give them: a box applied before the
/// grant that makes it the node's (a rotation by another admin, a re-seal) is taken once the grant
/// applies. Called wherever roles may have grown (`apply::rejudged`).
/// Invariant: nothing opens here that `ingest_view` would not take now (each box is judged by
/// `may_take_role` again as it opens; the list only says which actors to try), and the work is one
/// `may_take_role` per listed actor and role kept out, never per held actor (`retake: judged`).
/// Whether any was due.
pub(crate) fn retake(tx: &mut Tx<'_>) -> Result<bool> {
    let core = &*tx.core;
    osis_base::costs::count("retake: calls", 1);
    let due = core.waits.untaken_due(|a, r| {
        osis_base::costs::count("retake: judged", 1);
        crate::rotation::may_take_role(core, a, r)
    });
    let any = !due.is_empty();
    for a in due {
        tx.core.waits.retaken(&a);
        observe_secrets(tx, &a)?;
    }
    Ok(any)
}

/// Opener `h` taken up (a link key): the boxes keyed to it open, and what they
/// give opens the boxes keyed to that in turn (`reopen_dependents`); boxes the node's roles kept out are taken where the
/// roles as `h` give them (`retake`). O(what `h` opens), never the held actors or the node
/// closure.
fn take_up_opener(tx: &mut Tx<'_>, h: Tid) -> Result<()> {
    reopen_dependents(tx, h)?;
    retake(tx).map(drop)
}

/// The open's sweep (`Engine::load`), O(the held actors) as an open is: re-opens every
/// held `secrets.0` to a fixpoint, listing again the boxes the node's roles keep out
/// (`Waits::untaken`, in memory). What an actor learns reopens its dependents at once
/// (`reopen_dependents`, so a holder-actor chain opens in one sweep whatever its tid order);
/// sweeps repeat until one learns nothing (held epochs only grow, so no round cap is needed).
pub(crate) fn reopen_all(tx: &mut Tx<'_>) -> Result<()> {
    let secrets_ak = ak("secrets.0")?;
    let actors: BTreeSet<Tid> = tx.core.ix.aspect_things.get(&secrets_ak).cloned().unwrap_or_default();
    loop {
        let mut any = false;
        for a in &actors {
            osis_base::costs::count("reopen: actors", 1);
            any |= observe_secrets(tx, a)?;
        }
        if !any {
            break;
        }
    }
    Ok(())
}

impl Engine {
    /// Takes up the link key of `seed` on link's thing `k` until `drop_link_key`: it can sign
    /// (`Mutation::sign_as`) and its boxes open by its seed's secrets. Returns its tid.
    pub fn hold_link_key(&mut self, seed: Secret32, k: Tid) -> Result<Tid> {
        let id = Arc::new(Identity::link_key(seed, k));
        let t = id.tid();
        self.core.held_link_keys.insert(t, id);
        self.settle_link_key(&t);
        self.reopen_held(t)?;
        Ok(t)
    }

    /// Follows a link being redeemed (spec/sync-set.md §2, spec/sync-inbox.md §6): holds its key
    /// L while a followed link names it and keeps K's sync ID from the link text in the sync set,
    /// read, until `unfollow_link`. Returns L.
    pub fn follow_link(&mut self, link: &osis_blob::ShareLink) -> Result<Tid> {
        let id = Arc::new(Identity::link_key(link.seed.clone(), link.k));
        let l = id.tid();
        let old = self.core.followed_links.insert(link.k, link.k_sync_id, Some(id));
        self.settle_link_key(&l);
        if let Some(o) = old {
            self.settle_link_key(&o);
        }
        self.reopen_held(l)?;
        Ok(l)
    }

    /// Follows a locator being redeemed (spec/sync-set.md §4, §5): keeps the sync ID of its
    /// target's independent (`Locator::followed`) from the link text in the sync set, read,
    /// until `unfollow_link` of that thing. The
    /// link text is untrusted: its sync ID counts only where nothing held records another's
    /// (`sync_ids::actors::followed`).
    pub fn follow_public(&mut self, link: &osis_blob::Locator) {
        self.core.followed_links.insert(link.followed(), link.sync_id, None);
    }

    /// Stops following link K (its join is held elsewhere), or a locator's target; a share
    /// link's key goes with the last link naming it (spec/permissions.md §7).
    pub fn unfollow_link(&mut self, k: &Tid) {
        if let Some(l) = self.core.followed_links.remove(k) {
            self.settle_link_key(&l);
        }
    }

    /// A recipient for boxes to `holder` at `role` as this node writes them (`recipient`), for
    /// tests building boxes by hand.
    #[doc(hidden)]
    pub fn recipient_for(&mut self, holder: &Tid, role: Role) -> Result<Recipient> {
        let holder = *holder;
        self.read(|tx| recipient(tx, holder, role))
    }

    /// The KEM key of the node thing's newest read epoch held: its claim key's X25519 half
    /// (spec/crypto.md §3), for tests.
    #[doc(hidden)]
    pub fn node_read_kem(&self) -> Option<osis_crypto::KemSecret> {
        let e = self.core.epochs(&self.core.tid())?;
        e.read.newest_held().map(|(_, s)| s.kem().clone())
    }


    /// Lets go of a link key held by `hold_link_key`; a followed link naming it still holds it.
    pub fn drop_link_key(&mut self, tid: &Tid) {
        self.core.held_link_keys.remove(tid);
        self.settle_link_key(tid);
    }

    /// Holds link key `t` exactly while `hold_link_key` or a followed link names it.
    fn settle_link_key(&mut self, t: &Tid) {
        let want = self.core.held_link_keys.get(t).or_else(|| self.core.followed_links.key(t)).cloned();
        match want {
            Some(id) if !self.core.link_keys.contains_key(t) => drop(self.core.link_keys.replace(*t, id)),
            None if self.core.link_keys.contains_key(t) => drop(self.core.link_keys.remove(t)),
            _ => {}
        }
    }

    /// Opens what link key `t`, taken up, may open now (`take_up_opener`).
    fn reopen_held(&mut self, t: Tid) -> Result<()> {
        if let Some(ch) = &mut self.core.wakes {
            ch.reopen_awaits = true;
        }
        self.run(|tx| take_up_opener(tx, t))
    }

    /// Commits `m` in a running transaction.
    pub(crate) fn commit_tx(tx: &mut Tx<'_>, m: Mutation) -> Result<Option<CommitId>> {
        crate::engine::write::commit_in(tx, m)
    }
}

#[cfg(test)]
mod tests_signals;
