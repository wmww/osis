//! Sync IDs as role writes (spec/sync-ids.md §2-§4, §6 Steps): a thing's genesis step and `sync.0`
//! record, the steps an admin issues after rotations (registered at a node keeping the sync ID
//! unread once it holds the role commits they register: sync orders that), the claim set's
//! readers, the deposit seed's refresh.

use super::{Done, ak, sync_id_of};
use crate::rotation;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{SyncId, Role, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KemPublicKey, RoleKey, Secret32, VerifyingKey, role_key};
use osis_keys::{ActorEpochs, registration_epochs};
use osis_blob::{ClaimSet, Parent, Reader, Step, StepId, StepKeys, genesis_sync_id, sync_steps, register_with, step_record};
use osis_schema::core_types::{self as ct, KemKey};
use osis_schema::{RawKey, Codec};

/// A reader of a thing's read epoch as the registrar lists it.
#[derive(Clone)]
pub(crate) enum ReaderKey {
    /// A node or an actor: the X25519 half of its (read-role) KEM key.
    Dh([u8; 32]),
    /// A link key: static entry with an entry box sealed to its KEM key.
    Static(VerifyingKey, KemPublicKey),
}

fn kem_of(k: &KemKey) -> Result<KemPublicKey> {
    let KemKey::X25519MlKem768(b) = k;
    Ok(KemPublicKey::from_slice(b)?)
}

/// The readers of `t`'s read epoch `e` (spec/sync-ids.md §3): holders of read boxes at `e`, its
/// first admin included while its record edge stands; a node by its KEM key, another key actor
/// by static entry, an actor by its newest read keyset.
pub(crate) fn readers(tx: &mut Tx<'_>, t: &Tid, e: &Epoch) -> Result<Vec<ReaderKey>> {
    let mut holders: Vec<Tid> = Vec::new();
    if let Some(o) = tx.core.first_admin(t).filter(|a| tx.core.key_holders(t).iter().any(|(m, _)| m == a)) {
        holders.push(o);
    }
    let secrets = super::secrets_in(tx, t)?;
    for k in secrets.boxes.keys() {
        if k.role == Role::Read && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|ke| ke == *e) {
            holders.push(k.holder.0);
        }
    }
    holders.sort();
    holders.dedup();
    let mut out = Vec::new();
    for m in holders {
        out.extend(reader_key(tx, &m)?);
    }
    Ok(out)
}

pub(crate) fn reader_key(tx: &mut Tx<'_>, m: &Tid) -> Result<Option<ReaderKey>> {
    if tx.core.is_account(m) {
        return super::account::reader_key(tx, m);
    }
    let keys = Core::keys_in(tx, m)?;
    if tx.core.is_key_actor(m) {
        let kem = match (keys.as_ref().and_then(|k| k.key.as_ref()), tx.core.key_actors.get(m)) {
            (Some(k), _) => kem_of(k)?,
            (None, Some(id)) => id.keys().kem.public().clone(),
            (None, None) if *m == tx.core.id.tid() => tx.core.id.keys().kem.public().clone(),
            _ => return Ok(None),
        };
        if super::is_node(tx, m)? {
            return Ok(Some(ReaderKey::Dh(kem.x25519())));
        }
        let Some(osis_base::CreationRecord::KeyActor { public_key, .. }) = tx.core.created(m) else { return Ok(None) };
        let vk = VerifyingKey::from_slice(public_key)?;
        return Ok(Some(ReaderKey::Static(vk, kem)));
    }
    Ok(match keys.and_then(|k| k.read) {
        Some(ks) => Some(ReaderKey::Dh(kem_of(&ks.kem_key)?.x25519())),
        None => None,
    })
}

/// The deposit seed `t`'s sync IDs derive from (spec/sync-ids.md §2): its secret actor's
/// `keys.0`. The one derivation (`Engine::deposit_seed`,
/// `step_due`). None while a valid part of that `keys.0` is still to fetch (a rotation taken
/// header-only): lacking it is waiting, so no step is issued from an older seed, which a node
/// holding the newer one would step past again, and so on.
pub(crate) fn deposit_seed_of(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<Secret32>> {
    let actor = tx.core.reader_of(t);
    let keys = ak("keys.0")?;
    let lacking = tx.core.ix.by_aspect.get(&(actor, keys.clone())).into_iter().flatten().any(|(_, c)| tx.core.ix.commits.get(c).is_some_and(|m| m.aspect(&actor, &keys).is_some_and(|ai| m.valid_at(ai) && m.missing(ai))));
    if lacking {
        return Ok(None);
    }
    Ok(Core::keys_in(tx, &actor)?.and_then(|k| k.deposit_seed).map(Secret32::from_bytes))
}


/// Issues a step of `t` at the newest established epochs: a genesis step of a new sync ID
/// when `parent` is none, else a child of the parent step (signed by the parent's delete key,
/// from the admin secret of the epoch it registers).
pub(crate) fn issue(tx: &mut Tx<'_>, t: &Tid, epochs: &ActorEpochs, parent: Option<(&Step, &Secret32)>, readers: &[ReaderKey], deposit: &Secret32) -> Result<(Step, ClaimSet)> {
    let [(se, ss), (re, rs), (_, ws), (_, adm)] = registration_epochs(epochs).ok_or(Error::Misuse("an admin registers: every role's newest secret is needed"))?;
    let sync_id = parent.map_or_else(|| genesis_sync_id(adm), |(p, _)| p.sync_id);
    let keys = StepKeys::derive(ss, ws, adm, deposit, &sync_id);
    let rk: Vec<Reader> = readers
        .iter()
        .map(|r| match r {
            ReaderKey::Dh(x) => Reader::Dh(*x),
            ReaderKey::Static(vk, kem) => Reader::Static { signing: *vk, kem },
        })
        .collect();
    let del = role_key(RoleKey::Delete, parent.map_or(adm, |(_, a)| a));
    let p = match parent {
        None => Parent::Genesis(&del),
        Some((step, _)) => Parent::Child { step, delete: &del },
    };
    Ok(register_with(p, keys, &rk, (t, re, rs), (se, ss), epochs.read.wrapped_under([&re], |s| epochs.read.secret(s).is_some()).and_then(|s| epochs.read.secret(&s).map(|x| (s, x))), &mut *tx.rng)?)
}

/// `sync.0` write: a new sync ID of `t` with its genesis step (`genesis`), or a step added.
pub(crate) fn put_step(m: &mut Mutation, t: Tid, sync_id: SyncId, step: &Step, set: &ClaimSet, genesis: bool) -> Result<()> {
    match genesis {
        true => {
            let l = ct::SyncEntry { steps: [(step.id().0, step_record(step, Some(set)))].into_iter().collect() };
            m.op(t, &ct::SYNC, PathOp { path: vec![PathSeg::Key(sync_id.to_value())], op: Op::Set(l.to_value()) })?;
        }
        false => {
            let path = vec![PathSeg::Key(sync_id.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(step.id().0.to_vec()))];
            m.op(t, &ct::SYNC, PathOp { path, op: Op::Set(step_record(step, Some(set)).to_value()) })?;
        }
    }
    Ok(())
}

/// Drops, in `m`, the claim sets (with their entry boxes) of `t`'s steps superseded for
/// `ROLE_KEEP` (spec/sync-ids.md §4: an admin may): a step is superseded when the record of its
/// first child was written, by that write's stamp. Folded into every `sync.0` write an admin
/// makes, so a thing's records hold the sets of its recent steps only.
pub(crate) fn drop_old_claims(tx: &mut Tx<'_>, m: &mut Mutation, t: Tid) -> Result<()> {
    let now = tx.core.now().0;
    let Some(state) = tx.state(&t, &ak("sync.0")?)?.cloned() else { return Ok(()) };
    let ids = state.read().and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    for (sync_id, rec) in &ids {
        let Ok(steps) = sync_steps(rec) else { continue };
        // when each step's record was written
        let written = |id: &StepId| {
            let path = [PathSeg::Key(sync_id.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(id.0.to_vec())), PathSeg::Field(0)];
            state.at(&path).and_then(|f| f.write_stamp().map(|s| s.ts.wall_ms().0))
        };
        for (id, (_, claims)) in &steps {
            if claims.is_none() {
                continue;
            }
            let superseded = steps.iter().filter(|(_, (c, _))| c.prev == Some(*id)).filter_map(|(c, _)| written(c)).min();
            if superseded.is_some_and(|w| w.saturating_add(osis_base::format::ROLE_KEEP_MS) <= now) {
                let path = vec![PathSeg::Key(sync_id.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(id.0.to_vec())), PathSeg::Field(1)];
                m.op(t, &ct::SYNC, PathOp { path, op: Op::Replace(None::<Vec<u8>>.to_value()) })?;
            }
        }
    }
    Ok(())
}

/// A new sync ID of `t`, a thing with own keys (spec/sync-ids.md §2): genesis step at its newest epochs,
/// written to `sync.0` in `m`. Returns the sync ID.
pub(crate) fn new_sync_id(tx: &mut Tx<'_>, m: &mut Mutation, t: Tid, epochs: &ActorEpochs, readers: &[ReaderKey], deposit: &Secret32) -> Result<SyncId> {
    let (step, set) = issue(tx, &t, epochs, None, readers, deposit)?;
    put_step(m, t, step.sync_id, &step, &set, true)?;
    // named in its `keys.0` too: the public key record a sender fires by (spec/crypto.md §3)
    m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(9)], op: Op::Set(Some(step.sync_id).to_value()) })?;
    drop_old_claims(tx, m, t)?;
    Ok(step.sync_id)
}

/// The sync IDs `t`'s `sync.0` records that it owns (`sync_ids::actors::owns`).
pub(crate) fn owned_in(tx: &mut Tx<'_>, t: &Tid) -> Result<ct::SyncIds> {
    let mut sync_ids = tx.state(t, &ak("sync.0")?)?.and_then(Fragment::read).and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    sync_ids.retain(|id, l| sync_steps(l).is_ok_and(|s| tx.core.owns_sync_id(t, id, &s)));
    Ok(sync_ids)
}

/// The sync IDs this node holds for `t` (`sync_ids::actors::held_sync_ids`): those its `sync.0`
/// records that it owns, else a followed link's or its held tickets' hints.
pub(crate) fn held_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<SyncId>> {
    let m = tx.state(t, &ak("sync.0")?)?.and_then(Fragment::read).and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    Ok(crate::sync_ids::actors::held_sync_ids(tx.core, t, &m).into_iter().map(|o| o.id).collect())
}

/// Whether a child of recorded head `head` is due at an admin holding `epochs`, its actor's
/// deposit seed `deposit` (spec/sync-ids.md §6 Steps): the head's admin epoch, held and
/// established here, when it holds a sync, write or admin epoch newer than the head registers,
/// the seed derives another deposit key than the head's, or `fresh`; never while it lacks the
/// newest secret of a role (it could not sign the step).
pub(crate) fn due_at(epochs: &ActorEpochs, head: &Step, deposit: &Secret32, fresh: bool) -> Option<Epoch> {
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(epochs, r, head.keys.get(r)));
    let head_admin = at[2].filter(|e| epochs.role(Role::Admin).is_established(e))?;
    registration_epochs(epochs)?;
    let deposit_key = osis_crypto::deposit_key(deposit, &head.sync_id).verifying_key();
    (fresh || osis_keys::newer_than_head(epochs, at) || head.keys.deposit != deposit_key).then_some(head_admin)
}

/// What a due step of `g`'s sync ID `l` is issued from (`step_due`).
pub(crate) struct Due {
    head: Step,
    admin: Secret32,
    deposit: Secret32,
    pub(crate) epochs: std::sync::Arc<ActorEpochs>,
    /// Due by a new deposit key alone, no role newer than the head registers.
    pub(crate) deposit_only: bool,
}

/// Whether this node issues a step of `g`'s sync ID `l` now (spec/sync-ids.md §6 Steps,
/// spec/permissions.md §3 next-step triggers): it is an admin of `g` holding its recorded head's
/// epochs, the head's admin epoch established, and it holds a sync, write or admin epoch newer
/// than the head registers, or its actor's deposit seed derives another deposit key than the
/// head's (or `fresh`). The step is a child of the recorded head, never of a step it has not
/// recorded.
pub(crate) fn step_due(tx: &mut Tx<'_>, g: &Tid, l: &SyncId, fresh: bool) -> Result<Option<Due>> {
    let Ok(me) = tx.core.writer() else { return Ok(None) };
    if tx.core.role_now(&me, g) != Some(Role::Admin) {
        return Ok(None);
    }
    let owned = owned_in(tx, g)?;
    let Some(rec) = owned.get(l) else { return Ok(None) };
    let steps = sync_steps(rec)?;
    let Some((head, _)) = crate::sync_ids::actors::head_of(&steps).and_then(|h| steps.get(&h).cloned()) else { return Ok(None) };
    let Some(epochs) = tx.core.epochs(g) else { return Ok(None) };
    let Some(deposit) = deposit_seed_of(tx, g)? else { return Ok(None) };
    let Some(head_admin) = due_at(&epochs, &head, &deposit, fresh) else { return Ok(None) };
    // a deposit-only step waits for a newer seed held but not applied (spec/permissions.md §3):
    // stepping to this one would register a key a departed party may know
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(&epochs, r, head.keys.get(r)));
    let deposit_only = !fresh && !osis_keys::newer_than_head(&epochs, at);
    if deposit_only && crate::rotation::keys_write_unapplied(tx, g)? {
        return Ok(None);
    }
    let admin = epochs.role(Role::Admin).secret(&head_admin).cloned().ok_or(Error::Misuse("head admin secret"))?;
    Ok(Some(Due { head, admin, deposit, epochs, deposit_only }))
}

/// The step due of `g`'s sync ID `l` (`step_due`), put into `m`: a child of its recorded head at
/// the newest epochs with the current readers.
fn step_into(tx: &mut Tx<'_>, m: &mut Mutation, g: Tid, l: SyncId, fresh: bool) -> Result<Option<(Step, ClaimSet)>> {
    let Some(due) = step_due(tx, &g, &l, fresh)? else { return Ok(None) };
    let [_, (re, _), _, _] = registration_epochs(&due.epochs).ok_or(Error::Misuse("an admin registers: every role's newest secret is needed"))?;
    let rs = readers(tx, &g, &re)?;
    let (step, set) = issue(tx, &g, &due.epochs, Some((&due.head, &due.admin)), &rs, &due.deposit)?;
    put_step(m, g, l, &step, &set, false)?;
    Ok(Some((step, set)))
}

impl Engine {
    /// Refreshes `actor`'s deposit seed (spec/crypto.md §3, a MAY: a departed holder can then no
    /// longer deposit under its sync IDs, nor can a holder that has not read the new `keys.0`).
    pub fn refresh_deposit_seed(&mut self, actor: &Tid) -> Result<Done> {
        let a = *actor;
        let mut done = Done::default();
        let c = self.run(|tx| {
            let mut m = Mutation::new();
            rotation::fresh_deposit_seed(tx, &mut m, a)?;
            Engine::commit_tx(tx, m)
        })?;
        done.add(c);
        Ok(done)
    }

    /// Issues the step of `t`'s sync ID `sync_id` (spec/sync-ids.md §6 Steps): the step due
    /// (`step_due`), or with `fresh` one without a rotation (a MAY: to list readers granted since
    /// its parent). `None` when none is due or a role is blocked here (the step comes with the
    /// rotation that is made). Sync calls it once the rotations it registers are logged
    /// (`Engine::due_step`).
    pub fn issue_step(&mut self, t: &Tid, sync_id: &SyncId, fresh: bool) -> Result<Option<(Step, ClaimSet)>> {
        let (g, l) = (*t, *sync_id);
        self.run(|tx| {
            let Ok(me) = tx.core.writer() else { return Ok(None) };
            if !rotation::blocked_roles(tx, &me, &g)?.is_empty() {
                return Ok(None);
            }
            let mut m = Mutation::new();
            let Some(out) = step_into(tx, &mut m, g, l, fresh)? else { return Ok(None) };
            drop_old_claims(tx, &mut m, g)?;
            Engine::commit_tx(tx, m)?;
            Ok(Some(out))
        })
    }

    /// `drop_old_claims` into `m`, a `sync.0` write of `t` by this admin.
    pub fn drop_old_claims(&mut self, m: &mut Mutation, t: &Tid) -> Result<()> {
        let g = *t;
        self.run(|tx| drop_old_claims(tx, m, g))
    }

    /// The sync ID of `t`: the greatest it owns (`flows::sync_id_of`).
    pub fn sync_id_of(&mut self, t: &Tid) -> Result<Option<SyncId>> {
        let g = *t;
        self.read(|tx| sync_id_of(tx, &g))
    }
}

/// The sync IDs `sync.0` of `g` records, owned or not, inside a transaction (unparsable: none).
pub(crate) fn recorded_in(tx: &mut Tx<'_>, g: &Tid) -> Result<Vec<SyncId>> {
    let Some(v) = tx.state(g, &ak("sync.0")?)?.and_then(Fragment::read) else { return Ok(Vec::new()) };
    Ok(ct::SYNC.decode(&v).map(|m| m.into_keys().collect()).unwrap_or_default())
}
