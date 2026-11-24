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
    /// A thing: the X25519 half of its read-role KEM key.
    Dh([u8; 32]),
    /// A link key of the sync ID's thing: its static entry, by its signing key, with an entry
    /// box sealed to its read KEM key (spec/sync-ids.md §3).
    Static(VerifyingKey, KemPublicKey),
}

fn kem_of(k: &KemKey) -> Result<KemPublicKey> {
    let KemKey::X25519MlKem768(b) = k;
    Ok(KemPublicKey::from_slice(b)?)
}

/// The readers of `t`'s read epoch `e` (spec/sync-ids.md §3): holders of read boxes at `e`, its
/// mint admin included while its record edge stands; each by its newest read keyset, a link key
/// of `t` by its static entry.
pub(crate) fn readers(tx: &mut Tx<'_>, t: &Tid, e: &Epoch) -> Result<Vec<ReaderKey>> {
    let mut holders: Vec<Tid> = Vec::new();
    if let Some(o) = tx.core.mint_admin(t).filter(|a| tx.core.key_holders(t).iter().any(|(m, _)| m == a)) {
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
        out.extend(reader_key(tx, t, &m)?);
    }
    Ok(out)
}

/// Reader `m` of `t`'s sync ID as the registrar lists it (`readers`): by its newest read keyset
/// held here; a link key of `t` (its record names `t` as its K) by its static entry, the one
/// reader so listed (spec/sync-ids.md §3: a bearer secret opens `t` from a store with nothing
/// else). None while no keyset of it is held.
pub(crate) fn reader_key(tx: &mut Tx<'_>, t: &Tid, m: &Tid) -> Result<Option<ReaderKey>> {
    let Some(ks) = Core::keys_in(tx, m)?.and_then(|k| k.read) else { return Ok(None) };
    let kem = kem_of(&ks.kem_key)?;
    Ok(Some(match tx.core.created(m).filter(|r| r.link_key_of() == Some(*t)).and_then(osis_base::CreationRecord::key) {
        Some(k) => ReaderKey::Static(VerifyingKey::from_bytes(&k.0)?, kem),
        None => ReaderKey::Dh(kem.x25519()),
    }))
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


/// A step issued (`issue`): with the read key its issuer publishes beside it (spec/crypto.md §3).
pub(crate) struct Issued {
    pub(crate) step: Step,
    pub(crate) set: ClaimSet,
    pub(crate) read: ct::ReadKey,
}

/// Issues a step of `t` at the newest established epochs: a genesis step of a new sync ID
/// when `parent` is none, else a child of the parent step (signed by the parent's delete key,
/// from the admin secret of the epoch it registers).
///
/// Invariant: the read key is the read epoch the step registers with the KEM key derived here
/// from that epoch's secret, never copied from a keyset: what a party outside `t` seals to is
/// an admin's derivation, so no writer's junk keyset can make an outside fire open nowhere
/// (spec/crypto.md §3, Read key in force). It names the read keyset this node's `keys.0` holds
/// (`seen`): the key is in force only while that keyset is current, so no rotation the issuer
/// had not received is passed over.
///
/// `keyset`: the read keyset `t`'s `keys.0` holds once the step's commit is applied (one the same
/// commit writes, where it writes one).
pub(crate) fn issue(tx: &mut Tx<'_>, t: &Tid, epochs: &ActorEpochs, parent: Option<(&Step, &Secret32)>, readers: &[ReaderKey], deposit: &Secret32, keyset: Option<&ct::Keyset>) -> Result<Issued> {
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
    let seen = keyset.map(keyset_digest);
    let read = ct::ReadKey { epoch: osis_keys::aspects::to_schema(&re), kem_key: KemKey::X25519MlKem768(osis_crypto::role_kem(rs).public().as_bytes().to_vec()), seen };
    let (step, set) = register_with(p, keys, &rk, (t, re, rs), (se, ss), epochs.read.wrapped_under([&re], |s| epochs.read.secret(s).is_some()).and_then(|s| epochs.read.secret(&s).map(|x| (s, x))), &mut *tx.rng)?;
    Ok(Issued { step, set, read })
}

/// `sync.0` write: a new sync ID of `t` with its genesis step (`genesis`), or a step added; and
/// the step's keys published in `t`'s `keys.0` in the same commit (spec/crypto.md §3, §7 Header
/// list).
///
/// Invariant: the keys `keys.0` publishes are those of a step recorded by the same commit, so at
/// the same stamp: a writer listing them (one holding no `sync.0` of `t`, a fire from outside)
/// lists keys a step recorded before its commit places, never a rotation's before its step; and
/// its read key, naming the read keyset this node holds, is in force again (`read_key_in_force`).
pub(crate) fn put_step(m: &mut Mutation, t: Tid, sync_id: SyncId, issued: &Issued, genesis: bool) -> Result<()> {
    let Issued { step, set, read } = issued;
    let published = ct::StepKeys { delete: ct::SigningKey::Ed25519(step.keys.delete.to_bytes().to_vec()), write: ct::SigningKey::Ed25519(step.keys.write.to_bytes().to_vec()), read: read.clone() };
    m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(STEP)], op: Op::Set(Some(published).to_value()) })?;
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

/// A new sync ID of `t`, an independent thing (spec/sync-ids.md §2): genesis step at its newest epochs,
/// written to `sync.0` in `m`. Returns the sync ID.
pub(crate) fn new_sync_id(tx: &mut Tx<'_>, m: &mut Mutation, t: Tid, epochs: &ActorEpochs, readers: &[ReaderKey], deposit: &Secret32, keyset: Option<&ct::Keyset>) -> Result<SyncId> {
    let issued = issue(tx, &t, epochs, None, readers, deposit, keyset)?;
    let sync_id = issued.step.sync_id;
    put_step(m, t, sync_id, &issued, true)?;
    // named in its `keys.0` too: the public key record a sender fires by (spec/crypto.md §3)
    m.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(9)], op: Op::Set(Some(sync_id).to_value()) })?;
    drop_old_claims(tx, m, t)?;
    Ok(sync_id)
}

/// The sync IDs `t`'s `sync.0` records that it owns (`sync_ids::actors::owns`).
pub(crate) fn owned_in(tx: &mut Tx<'_>, t: &Tid) -> Result<ct::SyncIds> {
    let mut sync_ids = tx.state(t, &ak("sync.0")?)?.and_then(Fragment::read).and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    sync_ids.retain(|id, l| sync_steps(l).is_ok_and(|s| tx.core.owns_sync_id(t, id, &s)));
    Ok(sync_ids)
}

/// The sync IDs this node holds for `t` (`sync_ids::actors::held_sync_ids`): those its `sync.0`
/// records that it owns, else a followed link's hint.
pub(crate) fn held_in(tx: &mut Tx<'_>, t: &Tid) -> Result<Vec<SyncId>> {
    let m = tx.state(t, &ak("sync.0")?)?.and_then(Fragment::read).and_then(|v| ct::SYNC.decode(&v).ok()).unwrap_or_default();
    Ok(crate::sync_ids::actors::held_sync_ids(tx.core, t, &m).into_iter().map(|o| o.id).collect())
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
/// its `keys.0` has no read key in force (`read_moved`, `read_key_in_force`), the seed derives
/// another deposit key than the head's, or `fresh`; never while it lacks the newest secret of a
/// role (it could not sign the step).
pub(crate) fn due_at(epochs: &ActorEpochs, head: &Step, deposit: &Secret32, read_moved: bool, fresh: bool) -> Option<Epoch> {
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(epochs, r, head.keys.get(r)));
    let head_admin = at[2].filter(|e| epochs.role(Role::Admin).is_established(e))?;
    registration_epochs(epochs)?;
    let deposit_key = osis_crypto::deposit_key(deposit, &head.sync_id).verifying_key();
    (fresh || read_moved || osis_keys::newer_than_head(epochs, at) || head.keys.deposit != deposit_key).then_some(head_admin)
}

/// `t`'s read key in force (spec/crypto.md §3): its `keys.0` step keys' read key while the read
/// keyset there is the one it names (`seen`). `None` while another is (a step is then due,
/// `step_due`) or no step keys are held.
///
/// Invariant: what a party outside `t` seals to (`Engine::fire_keys`) is admin-written (the step
/// keys need admin, `validity::rotation_required`) and derived from a read secret its issuer
/// holds (`issue`); a writer's keyset written since makes the fire wait for the next step and never
/// chooses the key. A junk KEM key in a writer's keyset would leave every outside fire opened by
/// nobody while its sender saw it delivered; a step's key from before a writer's rotation (one its
/// issuer had not received) would be read by the party that rotation left out. Every node reads it
/// from its own `keys.0` state, a function of the valid writes it holds: no held secret decides it.
pub(crate) fn read_key_in_force(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<ct::ReadKey>> {
    let Some(k) = Core::keys_in(tx, t)? else { return Ok(None) };
    let current = k.read.as_ref().map(keyset_digest);
    Ok(k.step.map(|s| s.read).filter(|r| r.seen == current))
}

/// The digest a read key names a read keyset by (`ct::ReadKey::seen`, spec/wire.md §7): BLAKE3
/// of the canonical bytes of `[epoch, kem_key]`, what a sender would otherwise seal to.
fn keyset_digest(ks: &ct::Keyset) -> [u8; 32] {
    osis_base::hash::hash(&osis_base::encode(&Value::List(vec![ks.epoch.to_value(), ks.kem_key.to_value()])))
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
/// derives another deposit key than the head's (or `fresh`). The step is a child of the recorded head, never of a step it has not
/// recorded.
pub(crate) fn step_due(tx: &mut Tx<'_>, g: &Tid, l: &SyncId, fresh: bool) -> Result<Option<Due>> {
    let me = tx.core.me();
    if tx.core.role_now(&me, g) != Some(Role::Admin) {
        return Ok(None);
    }
    let owned = owned_in(tx, g)?;
    let Some(rec) = owned.get(l) else { return Ok(None) };
    let steps = sync_steps(rec)?;
    let Some((head, _)) = crate::sync_ids::actors::head_of(&steps).and_then(|h| steps.get(&h).cloned()) else { return Ok(None) };
    let Some(epochs) = tx.core.epochs(g) else { return Ok(None) };
    let Some(deposit) = deposit_seed_of(tx, g)? else { return Ok(None) };
    // a read keyset other than the one the step keys name leaves no read key in force: outside
    // fires wait for this step, so it is due (spec/permissions.md §3), whoever wrote the keyset
    let read_moved = read_key_in_force(tx, g)?.is_none();
    let Some(head_admin) = due_at(&epochs, &head, &deposit, read_moved, fresh) else { return Ok(None) };
    // a deposit-only step waits for a newer seed held but not applied (spec/permissions.md §3):
    // stepping to this one would register a key a departed party may know
    let at = RoleKey::ALL.map(|r| osis_keys::registered_epoch(&epochs, r, head.keys.get(r)));
    let deposit_only = !fresh && !read_moved && !osis_keys::newer_than_head(&epochs, at);
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
    let keyset = Core::keys_in(tx, &g)?.and_then(|k| k.read);
    let issued = issue(tx, &g, &due.epochs, Some((&due.head, &due.admin)), &rs, &due.deposit, keyset.as_ref())?;
    put_step(m, g, l, &issued, false)?;
    Ok(Some((issued.step, issued.set)))
}

/// The endorsements this node owes S's recorded head, as signing keys (spec/sync-ids.md §6
/// Steps): those of `endorsements_owed` whose admin secret it holds, while it is an admin of `g`.
pub(crate) fn endorsers(tx: &mut Tx<'_>, g: &Tid, o: &crate::sync::OwnedSyncId) -> Result<Vec<osis_crypto::SigningSecret>> {
    let owed = crate::sync_ids::actors::endorsements_owed(o);
    if owed.is_empty() {
        return Ok(Vec::new());
    }
    let me = tx.core.me();
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
    /// (`step_due`), or with `fresh` one without a rotation (a MAY: to list readers granted since
    /// its parent). `None` when none is due or a role is blocked here (the step comes with the
    /// rotation that is made). Sync calls it once the rotations it registers are logged
    /// (`Engine::due_step`).
    pub fn issue_step(&mut self, t: &Tid, sync_id: &SyncId, fresh: bool) -> Result<Option<(Step, ClaimSet)>> {
        let (g, l) = (*t, *sync_id);
        self.run(|tx| {
            let me = tx.core.me();
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

    /// Writes the endorsements this node owes `sync_id`'s recorded head (`endorsers`, spec/sync-ids.md
    /// §6 Steps): whether it wrote any.
    pub fn endorse_due(&mut self, sync_id: &SyncId) -> Result<bool> {
        let Some((g, o)) = self.recorded_owner(sync_id)? else { return Ok(false) };
        let Some((head, _)) = o.path.steps.last().cloned() else { return Ok(false) };
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

    /// The sync ID of `t`: the greatest it owns (`flows::sync_id_of`).
    pub fn sync_id_of(&mut self, t: &Tid) -> Result<Option<SyncId>> {
        let g = *t;
        self.read(|tx| sync_id_of(tx, &g))
    }
}

