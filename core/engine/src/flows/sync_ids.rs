//! Sync IDs as role writes (spec/sync-ids.md §2-§4, §6 Steps): a thing's genesis step and `sync.0`
//! record, the steps an admin issues after rotations (registered at a node keeping the sync ID
//! unread once it holds the role commits they register: sync orders that), the deposit seed's
//! refresh.

use super::{Done, ak, sync_id_of};
use crate::rotation;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{SyncId, Role, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::{Epoch, RoleKey, Secret32, role_key};
use osis_keys::{ActorEpochs, registration_epochs};
use osis_blob::{Step, StepKeys, sync_steps, register, step_record};
use osis_schema::core_types::{self as ct, KemKey};
use osis_schema::{RawKey, Codec};

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


/// A step issued (`issue`): with the read key its issuer publishes beside it (spec/crypto.md §3).
pub(crate) struct Issued {
    pub(crate) step: Step,
    pub(crate) read: Option<ct::ReadKey>,
}

/// Issues a step of `t` at the newest established epochs: a child of the parent step, signed by
/// the parent's delete key from the secret given with it (the admin secret of the epoch it
/// registers; the genesis step's: the genesis seed).
///
/// Invariant: the read key is the epoch of the read keyset `t`'s `keys.0` holds here, written only
/// where this node vouches for it (`vouched`), with the KEM key derived here from its secret,
/// never copied from the keyset: what a party outside `t` seals to is an admin's derivation for
/// an epoch it holds current, so no writer's junk keyset can make an outside fire open nowhere,
/// and no keyset the issuer holds only part of, or holds superseded, puts an older epoch in force
/// (spec/crypto.md §3, Read key in force).
///
/// `keyset`: the read keyset `t`'s `keys.0` holds once the step's commit is applied (one the same
/// commit writes, where it writes one); `claim`: the claim epoch of the sync epoch it registers,
/// where that commit writes its keyset (else read from the keyset held, `Core::keyset`). Its step
/// key is the public half of that sync epoch's claim key (spec/sync-ids.md §3).
pub(crate) fn issue(tx: &mut Tx<'_>, t: &Tid, epochs: &ActorEpochs, parent: (&Step, &Secret32), deposit: &Secret32, keyset: Option<&ct::Keyset>, claim: Option<Epoch>) -> Result<Issued> {
    let [(se, ss), _, (_, ws), (_, adm)] = registration_epochs(epochs).ok_or(Error::Misuse("an admin registers: every role's newest secret is needed"))?;
    let claim = claim.or_else(|| tx.core.keyset(t, Role::Sync, &se).and_then(|k| k.claim)).ok_or(Error::Misuse("the sync epoch's claim epoch is not held"))?;
    let roles = epochs.read.checked_roles(&claim).ok_or(Error::Misuse("the claim epoch's roles secret is not held"))?;
    let step_key = osis_crypto::step_secret(ss, &roles).public();
    let keys = StepKeys::derive(ss, ws, adm, deposit, &parent.0.sync_id);
    let del = role_key(RoleKey::Delete, parent.1);
    // its KEM key only beside a read keyset carrying one (spec/crypto.md §3, Published KEM keys)
    let kem = keyset.is_some_and(|k| k.kem_key.is_some());
    let read = vouched(epochs, keyset).map(|(e, s)| ct::ReadKey { epoch: osis_keys::aspects::to_schema(&e), kem_key: kem.then(|| KemKey::X25519MlKem768(s.kem().public().as_bytes().to_vec())) });
    let step = register(parent.0, &del, keys, step_key)?;
    Ok(Issued { step, read })
}

/// `sync.0` write: a step of `t`'s sync ID `sync_id` recorded; and the step's keys published in
/// `t`'s `keys.0` in the same commit (spec/crypto.md §3, §7 Header list).
///
/// Invariant: the keys `keys.0` publishes are those of a step recorded by the same commit, so at
/// the same stamp: a writer listing them (one holding no `sync.0` of `t`, a fire from outside)
/// lists keys a step recorded before its commit places, never a rotation's before its step; and
/// its read key, naming the read keyset this node holds, is in force again (`read_key_in_force`).
pub(crate) fn put_step(m: &mut Mutation, t: Tid, sync_id: SyncId, issued: &Issued) -> Result<()> {
    publish_keys(m, t, issued)?;
    let path = vec![PathSeg::Key(sync_id.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(issued.step.id().0.to_vec()))];
    m.op(t, &ct::SYNC, PathOp { path, op: Op::Set(step_record(&issued.step).to_value()) })?;
    Ok(())
}

/// `keys.0` write: the step keys of `issued` (`put_step`).
fn publish_keys(m: &mut Mutation, t: Tid, issued: &Issued) -> Result<()> {
    let Issued { step, read, .. } = issued;
    let published = ct::StepKeys { delete: ct::SigningKey::Ed25519(step.keys.delete.to_bytes().to_vec()), write: ct::SigningKey::Ed25519(step.keys.write.to_bytes().to_vec()), read: read.clone() };
    m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(STEP)], op: Op::Set(Some(published).to_value()) })?;
    Ok(())
}

/// `sync.0` write: `steps` of `t`'s sync ID `sync_id`, as a new entry of its key whatever is live
/// there (a put, spec/crdt.md §5.6 `put_new`): it reads as the join with what other writes
/// record, so concurrent writes of steps of one sync ID all stand.
pub(crate) fn put_steps(m: &mut Mutation, t: Tid, sync_id: SyncId, steps: &[&Step]) -> Result<()> {
    let l = ct::SyncEntry { steps: steps.iter().map(|s| (s.id().0, step_record(s))).collect() };
    m.op(t, &ct::SYNC, PathOp { path: vec![PathSeg::Key(sync_id.to_value())], op: Op::Put(l.to_value()) })?;
    Ok(())
}

/// What making `t` independent writes in `sync.0` (spec/sync-ids.md §2), in `m`: the genesis
/// step of its sync ID, from its genesis seed `g` (the same bytes at every node making it
/// independent), and a child of it at its new epochs `epochs`. Returns the sync ID.
pub(crate) fn independent_steps(tx: &mut Tx<'_>, m: &mut Mutation, t: Tid, g: &Secret32, epochs: &ActorEpochs, deposit: &Secret32, keysets: &osis_keys::KeysWrite) -> Result<SyncId> {
    let genesis = osis_blob::genesis(g);
    let sync_id = genesis.sync_id;
    let claim = keysets.keysets.get(&Role::Sync).and_then(|k| k.claim.as_ref()).and_then(|e| osis_keys::aspects::from_schema(e).ok());
    let issued = issue(tx, &t, epochs, (&genesis, g), deposit, keysets.keysets.get(&Role::Read), claim)?;
    publish_keys(m, t, &issued)?;
    put_steps(m, t, sync_id, &[&genesis, &issued.step])?;
    // named in its `keys.0` too: the public key record a sender fires by (spec/crypto.md §3)
    m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(9)], op: Op::Set(Some(sync_id).to_value()) })?;
    Ok(sync_id)
}

/// The sync IDs this node holds for `t` (`sync_ids::actors::held_sync_ids`).
pub(crate) fn held_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<SyncId>> {
    Ok(crate::sync_ids::actors::held_sync_ids(tx, t)?.into_iter().map(|o| o.id).collect())
}

/// `t`'s sync IDs (`held_in`) are pulled anew from every source (spec/sync-judgement.md §3
/// Dropped bodies): what was forgotten of what they carry is fetched again. Durable before the
/// transaction commits; a test peer's fetch stand-in reads it (`Wakes::pulled_anew`).
pub(crate) fn pull_anew(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    for s in held_in(tx, t)? {
        osis_base::costs::count("sync IDs pulled anew", 1);
        tx.blobs.refetch(&s);
        if let Some(w) = &mut tx.core.wakes {
            w.pulled_anew.insert(s);
        }
    }
    Ok(())
}

/// Whether a child of recorded head `head` is due at an admin holding `epochs`, its actor's
/// deposit seed `deposit` (spec/sync-ids.md §6 Steps): the head's admin epoch, held and
/// established here, when it holds a sync, write or admin epoch newer than the head registers,
/// its `keys.0` has no read key in force (`read_moved`, `read_key_in_force`), or the seed derives
/// another deposit key than the head's; never while it lacks the newest secret of a role (it
/// could not sign the step).
pub(crate) fn due_at(epochs: &ActorEpochs, head: &Step, deposit: &Secret32, read_moved: bool) -> Option<Epoch> {
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(epochs, r, head.keys.get(r)));
    let head_admin = at[2].filter(|e| epochs.role(Role::Admin).is_established(e))?;
    registration_epochs(epochs)?;
    let deposit_key = osis_crypto::deposit_key(deposit, &head.sync_id).verifying_key();
    (read_moved || osis_keys::newer_than_head(epochs, at) || head.keys.deposit != deposit_key).then_some(head_admin)
}

/// `t`'s read key in force (spec/crypto.md §3): its `keys.0` step keys' read key while the read
/// keyset there is of its epoch. `None` while another is, or no read key is held (a step is then
/// due wherever an admin vouches for the keyset's epoch, `step_due`).
///
/// Invariant: what a party outside `t` seals to (`Engine::fire_keys`) is admin-written (the step
/// keys need admin, `validity::rotation_required`), derived from a read secret its issuer holds
/// current (`issue`), and the epoch of the keyset every writer's rotation writes: a writer's keyset
/// written since makes the fire wait and never chooses the key. A junk KEM key in a writer's
/// keyset would leave every outside fire opened by nobody while its sender saw it delivered; a
/// step's key for another epoch than the keyset's would be read by a party a rotation since left
/// out. A writer rewriting the keyset at the read key's epoch changes nothing (an epoch names its
/// secret, spec/crypto.md §4). Every node reads it from its own `keys.0` state, a function of the
/// valid writes it holds: no held secret decides it.
pub(crate) fn read_key_in_force(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<ct::ReadKey>> {
    let Some(k) = Core::keys_in(tx, t)? else { return Ok(None) };
    let Some(current) = k.read.map(|ks| ks.epoch) else { return Ok(None) };
    Ok(k.step.and_then(|s| s.read).filter(|r| r.epoch == current))
}

/// The epoch of read keyset `keyset` with its secret, where an issuer holding `epochs` vouches for
/// it (spec/crypto.md §3, Read key): it holds the epoch current (established, not superseded) with
/// its secret. None for a keyset it holds only part of, holds superseded, or never received the
/// secret of (junk, a lockout): outside fires then wait for a rotation or a removal.
fn vouched<'a>(epochs: &'a ActorEpochs, keyset: Option<&ct::Keyset>) -> Option<(Epoch, &'a osis_crypto::RoleSecret)> {
    let e = osis_keys::aspects::from_schema(&keyset?.epoch).ok()?;
    let read = epochs.role(Role::Read);
    read.is_current(&e).then(|| read.secret(&e).map(|s| (e, s))).flatten()
}

/// `keys.0` field `step` (schema/core.osis).
const STEP: u64 = 10;

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
/// than the head registers, `g`'s `keys.0` has no read key in force, or its actor's deposit seed
/// derives another deposit key than the head's. The step is a child of the recorded head, never
/// of a step it has not recorded.
pub(crate) fn step_due(tx: &mut Tx<'_>, g: &Tid, l: &SyncId) -> Result<Option<Due>> {
    let me = tx.core.tid();
    if tx.core.role_now(&me, g) != Some(Role::Admin) || sync_id_of(tx, g)? != Some(*l) {
        return Ok(None);
    }
    let Some(rec) = tx.state(g, &ak("sync.0")?)?.and_then(Fragment::read).and_then(|v| ct::SYNC.decode(&v).ok()).and_then(|m| m.get(l).cloned()) else { return Ok(None) };
    let steps = sync_steps(&rec)?;
    let Some(head) = crate::sync_ids::actors::head_of(&steps).and_then(|h| steps.get(&h).cloned()) else { return Ok(None) };
    let Some(epochs) = tx.core.epochs(g) else { return Ok(None) };
    let Some(deposit) = deposit_seed_of(tx, g)? else { return Ok(None) };
    // no read key in force for a read keyset this admin vouches for: outside fires wait for this
    // step, so it is due (spec/permissions.md §3), whoever wrote the keyset
    let keyset = Core::keys_in(tx, g)?.and_then(|k| k.read);
    let read_moved = read_key_in_force(tx, g)?.is_none() && vouched(&epochs, keyset.as_ref()).is_some();
    let Some(head_admin) = due_at(&epochs, &head, &deposit, read_moved) else { return Ok(None) };
    // a deposit-only step waits for a newer seed held but not applied (spec/permissions.md §3):
    // stepping to this one would register a key a departed party may know
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(&epochs, r, head.keys.get(r)));
    let deposit_only = !read_moved && !osis_keys::newer_than_head(&epochs, at);
    if deposit_only && crate::rotation::keys_write_unapplied(tx, g)? {
        return Ok(None);
    }
    let admin = epochs.role(Role::Admin).secret(&head_admin).map(|s| s.secret().clone()).ok_or(Error::Misuse("head admin secret"))?;
    Ok(Some(Due { head, admin, deposit, epochs, deposit_only }))
}

/// The step due of `g`'s sync ID `l` (`step_due`), put into `m`: a child of its recorded head at
/// the newest epochs.
fn step_into(tx: &mut Tx<'_>, m: &mut Mutation, g: Tid, l: SyncId) -> Result<Option<Step>> {
    let Some(due) = step_due(tx, &g, &l)? else { return Ok(None) };
    let keyset = Core::keys_in(tx, &g)?.and_then(|k| k.read);
    let issued = issue(tx, &g, &due.epochs, (&due.head, &due.admin), &due.deposit, keyset.as_ref(), None)?;
    put_step(m, g, l, &issued)?;
    Ok(Some(issued.step))
}

/// The endorsements this node owes S's recorded head, as signing keys (spec/sync-ids.md §6
/// Steps): those of `endorsements_owed` whose admin secret it holds, while it is an admin of `g`.
pub(crate) fn endorsers(tx: &mut Tx<'_>, g: &Tid, o: &crate::sync::OwnedSyncId) -> Result<Vec<osis_crypto::SigningSecret>> {
    let owed = crate::sync_ids::actors::endorsements_owed(o);
    if owed.is_empty() {
        return Ok(Vec::new());
    }
    let me = tx.core.tid();
    if tx.core.role_now(&me, g) != Some(Role::Admin) {
        return Ok(Vec::new());
    }
    let Some(epochs) = tx.core.epochs(g) else { return Ok(Vec::new()) };
    Ok(epochs.admin.held_newest_first().into_iter().map(|(_, s)| role_key(RoleKey::Delete, s)).filter(|k| owed.contains(&k.verifying_key().to_bytes())).collect())
}

/// `sync.0` write: endorsements of `g`'s sync ID `l`'s step `step` by `keys`.
fn put_endorsements(m: &mut Mutation, g: Tid, l: SyncId, step: &Step, keys: &[osis_crypto::SigningSecret]) -> Result<()> {
    for k in keys {
        let path = vec![PathSeg::Key(l.to_value()), PathSeg::Field(0), PathSeg::Key(Value::Bytes(step.id().0.to_vec())), PathSeg::Field(2), PathSeg::Key(Value::Bytes(k.verifying_key().to_bytes().to_vec()))];
        m.op(g, &ct::SYNC, PathOp { path, op: Op::Set(Value::Bytes(step.endorse(k).0.to_vec())) })?;
    }
    Ok(())
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
    /// (`step_due`). `None` when none is due or a role is blocked here (the step comes with the
    /// rotation that is made). Sync calls it once the rotations it registers are logged
    /// (`Engine::due_step`).
    pub fn issue_step(&mut self, t: &Tid, sync_id: &SyncId) -> Result<Option<Step>> {
        let (g, l) = (*t, *sync_id);
        self.run(|tx| {
            let me = tx.core.tid();
            if !rotation::blocked_roles(tx, &me, &g)?.is_empty() {
                return Ok(None);
            }
            let mut m = Mutation::new();
            let Some(out) = step_into(tx, &mut m, g, l)? else { return Ok(None) };
            Engine::commit_tx(tx, m)?;
            // a store takes the step by Register
            Ok(Some(out))
        })
    }

    /// Writes the endorsements this node owes `sync_id`'s recorded head (`endorsers`, spec/sync-ids.md
    /// §6 Steps): whether it wrote any.
    pub fn endorse_due(&mut self, sync_id: &SyncId) -> Result<bool> {
        let Some((g, o)) = self.recorded_owner(sync_id)? else { return Ok(false) };
        let Some(head) = o.path.steps.last().cloned() else { return Ok(false) };
        self.run(|tx| {
            let keys = endorsers(tx, &g, &o)?;
            if keys.is_empty() {
                return Ok(false);
            }
            let mut m = Mutation::new();
            put_endorsements(&mut m, g, o.id, &head, &keys)?;
            Engine::commit_tx(tx, m)?;
            Ok(true)
        })
    }

    /// Whether this node owes `sync_id`'s recorded head an endorsement it can sign (`endorse_due`).
    pub fn endorsement_due(&mut self, sync_id: &SyncId) -> Result<bool> {
        let Some((g, o)) = self.recorded_owner(sync_id)? else { return Ok(false) };
        self.read(|tx| Ok(!endorsers(tx, &g, &o)?.is_empty()))
    }

    /// The sync ID of `t` (`flows::sync_id_of`).
    pub fn sync_id_of(&mut self, t: &Tid) -> Result<Option<SyncId>> {
        let g = *t;
        self.read(|tx| sync_id_of(tx, &g))
    }
}

