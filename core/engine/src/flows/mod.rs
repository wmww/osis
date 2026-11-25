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
pub mod edges;
pub(crate) mod sync_ids;
pub(crate) mod links;
mod create;
pub(crate) mod inbox;
pub(crate) mod roots;
pub mod pairing;


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
use std::collections::{BTreeMap, BTreeSet};
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
    // each box's record (spec/crypto.md §4, Stale), written as the box is
    for (k, ks) in &w.sealed {
        let v = ks.iter().map(osis_keys::aspects::to_schema).collect::<BTreeSet<ct::Epoch>>().to_value();
        if new_only {
            m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED), PathSeg::Key(k.to_value())], op: Op::Put(v) })?;
        } else {
            m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED)], op: Op::Remove(k.to_value()) })?;
            m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED), PathSeg::Key(k.to_value())], op: Op::Set(v) })?;
        }
    }
    Ok(())
}

/// `keys.0`'s field of box records (spec/crypto.md §4, Stale; spec/wire.md §7).
pub(crate) const SEALED: u64 = 8;

/// Removes from `m` the records of `actor`'s boxes `removed` that its `keys.0` state holds: a
/// record goes with its box (a rotation removing the boxes at the epochs it supersedes).
pub(crate) fn unseal(tx: &mut Tx<'_>, m: &mut Mutation, actor: Tid, removed: &BTreeSet<ct::BoxKey>) -> Result<()> {
    if removed.is_empty() {
        return Ok(());
    }
    let held = Core::keys_in(tx, &actor)?.map(|k| k.sealed).unwrap_or_default();
    for k in removed.iter().filter(|k| held.contains_key(k)) {
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(SEALED)], op: Op::Remove(k.to_value()) })?;
    }
    Ok(())
}

/// Writes the rotated roles' keysets into `m` (whole keysets: the field is replaced).
pub(crate) fn put_keysets(m: &mut Mutation, actor: Tid, w: &KeysWrite) -> Result<()> {
    for (role, ks) in &w.keysets {
        let f = osis_keys::aspects::keyset_field(*role);
        m.op(actor, &ct::KEYS, PathOp { path: vec![PathSeg::Field(f)], op: Op::Replace(Some(ks.clone()).to_value()) })?;
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
    /// stays until it is finalized (spec/permissions.md §2).
    /// A destroyed actor holds no keys: in its place come its frozen holders (its edges as they
    /// stood at its destruction: nobody writes it after), each at the lesser of its role there and
    /// the destroyed actor's here, and so on through destroyed actors among them, a holder reached
    /// more than one way at the greatest (spec/crypto.md §4, Holder actors, Destroyed); `actor`
    /// itself never.
    pub fn key_holders(&self, actor: &Tid) -> Vec<(Tid, Role)> {
        expand_destroyed(actor, |t| self.edge_holders(t), |m| self.destroyed_actor(m))
    }

    /// The holders of `actor` for keys with key access to it, each at its role so (spec/crypto.md
    /// §4, Key access, Destroyed), `keyless` the keyless grants (`rotation::members::key_access`):
    /// `key_holders` walked over grants with key access only, so a destroyed actor's frozen holder
    /// has it only when every grant on some path to it does, at the greatest role over such paths.
    pub(crate) fn keyed_holders(&self, actor: &Tid, keyless: &BTreeSet<(Tid, Tid)>) -> BTreeMap<Tid, Role> {
        let edges = |t: &Tid| self.edge_holders(t).into_iter().filter(|(m, _)| !keyless.contains(&(*t, *m))).collect();
        expand_destroyed(actor, edges, |m| self.destroyed_actor(m)).into_iter().collect()
    }

    /// The direct holders of `actor` for keys (`key_holders` without the destroyed actors' frozen
    /// holders in their place): every edge on it by `rotation::key_role`, its record edge
    /// included while it stands.
    pub(crate) fn edge_holders(&self, actor: &Tid) -> Vec<(Tid, Role)> {
        match self.timelines().on(actor) {
            Some(on) => on.holders().into_iter().filter_map(|(m, e)| Some((m, crate::rotation::key_role(Some(&e))?))).collect(),
            None => self.mint_admin(actor).map(|a| (a, Role::Admin)).into_iter().collect(),
        }
    }

    /// Whether `m` is a destroyed thing (spec/crypto.md §4 Destroyed: it holds no keys).
    pub(crate) fn destroyed_actor(&self, m: &Tid) -> bool {
        self.destroyed(m)
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

/// The sync ID of `tid`: the greatest of those it owns (two admins giving it secrets at once made
/// two) (`sync_ids::owned_in`).
pub(crate) fn sync_id_of(tx: &mut Tx<'_>, tid: &Tid) -> Result<Option<SyncId>> {
    Ok(sync_ids::owned_in(tx, tid)?.into_keys().next_back())
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

/// Re-opens the `secrets.0` of every actor that boxes to `learned` after this node learned
/// secrets of `learned` (an actor's boxes open only once its holder's epochs are held), to a
/// fixpoint. Called by node-core's state observation (engine hook) and by a
/// take-up (`take_up_opener`). Terminates without a step cap: an actor is pushed only when its
/// held epochs grew, and they only grow, bounded by the boxes held (a cap would leave secrets of
/// deep holder chains unopened).
pub(crate) fn reopen_dependents(tx: &mut Tx<'_>, learned: Tid) -> Result<()> {
    let mut work = vec![learned];
    while let Some(m) = work.pop() {
        // `m`'s own invalid commits: their history boxes open with what it learned
        if crate::apply::keys::reread_invalid(tx, &m)? {
            work.push(m);
        }
        // the boxes keyed to `m`, per actor: from the index of keyed `secrets.0` entries
        let mut per: std::collections::BTreeMap<Tid, Vec<osis_base::Value>> = std::collections::BTreeMap::new();
        for (a, k) in tx.core.ix.boxes_to.get(&m).into_iter().flatten() {
            if *a != m {
                per.entry(*a).or_default().push(k.clone());
            }
        }
        for (a, keys) in per {
            let learned = crate::apply::ingest_secrets_keys(tx, &a, &keys, &[])?;
            // boxes of commits invalid here open for reading too (custody follows holding)
            if crate::apply::keys::reread_invalid(tx, &a)? | learned {
                work.push(a);
            }
        }
    }
    Ok(())
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
        let s = secrets_in(tx, &a)?;
        let alts = secrets_alts(tx, &a)?;
        tx.core.touch();
        if tx.core.ingest_secrets(&a, &s, crate::engine::secrets::SecretsRead::State, &alts) {
            reopen_dependents(tx, a)?;
        }
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
            let s = secrets_in(tx, a)?;
            let alts = secrets_alts(tx, a)?;
            tx.core.touch();
            if tx.core.ingest_secrets(a, &s, crate::engine::secrets::SecretsRead::State, &alts) {
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
        let old = self.core.followed_links.insert(link.k, link.k_sync_id, id);
        self.settle_link_key(&l);
        if let Some(o) = old {
            self.settle_link_key(&o);
        }
        self.reopen_held(l)?;
        Ok(l)
    }

    /// Stops following link K (its join is held elsewhere); its key goes with the last link naming
    /// it (spec/permissions.md §7).
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
        let e = self.core.epochs(&self.core.me())?;
        e.read.newest_held().map(|(_, s)| osis_crypto::role_kem(s))
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

/// `key_holders`' walk over `edges` (an actor's direct holders for keys) with `destroyed` actors
/// replaced by their own holders, each at the lesser role along the way and the greatest over
/// the ways: a destroyed actor is entered again only at a greater role than before, so each at
/// most once per role.
fn expand_destroyed(actor: &Tid, edges: impl Fn(&Tid) -> Vec<(Tid, Role)>, destroyed: impl Fn(&Tid) -> bool) -> Vec<(Tid, Role)> {
    let mut out: BTreeMap<Tid, Role> = BTreeMap::new();
    let mut entered: BTreeMap<Tid, Role> = BTreeMap::from([(*actor, Role::Admin)]);
    let mut work = vec![(*actor, Role::Admin)];
    while let Some((t, cap)) = work.pop() {
        for (m, r) in edges(&t) {
            let r = r.min(cap);
            if m == *actor {
                continue;
            }
            let into = if destroyed(&m) { &mut entered } else { &mut out };
            if into.get(&m).is_some_and(|x| *x >= r) {
                continue;
            }
            into.insert(m, r);
            if destroyed(&m) {
                work.push((m, r));
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u8) -> Tid {
        Tid::from_bytes([n; 15])
    }

    // spec/crypto.md §4 (Holders for keys; Destroyed): a destroyed actor reached at a lesser role first
    // and at a greater one later puts its holders at the greater, whatever the walk's order
    #[test]
    fn destroyed_holder_reached_two_ways_takes_the_greater_role_spec_crypto_4() {
        let (a, t, u, v, m) = (tid(1), tid(2), tid(3), tid(4), tid(5));
        for (lo, hi) in [(t, u), (u, t)] {
            // a: lo (destroyed, read), hi (destroyed, admin); lo and hi: v (destroyed, admin); v: m (admin)
            let edges = |x: &Tid| -> Vec<(Tid, Role)> {
                let mut e = if *x == a {
                    vec![(lo, Role::Read), (hi, Role::Admin)]
                } else if *x == lo || *x == hi {
                    vec![(v, Role::Admin)]
                } else if *x == v {
                    vec![(m, Role::Admin), (a, Role::Admin)]
                } else {
                    vec![]
                };
                e.sort();
                e
            };
            let destroyed = |x: &Tid| [t, u, v].contains(x);
            assert_eq!(expand_destroyed(&a, edges, destroyed), vec![(m, Role::Admin)], "lo {lo:?}");
        }
    }
}
