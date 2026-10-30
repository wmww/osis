//! Labels as membership writes (spec/sync.md §2, §5): a group's genesis step and `/label`
//! record, registration steps an admin issues after rotations (at each server when it next
//! syncs there, after uploading the membership commits it registers: node-sync orders that),
//! the claim set's readers.

use super::{Done, ak, own_label};
use crate::rotation;
use osis_keys::ROLES;
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{LabelId, Role, Tid, Value};
use osis_crdt::{Fragment, Op, PathOp, PathSeg};
use osis_crypto::{Epoch, KemPublicKey, LabelRole, Secret32, VerifyingKey, label_role_key};
use osis_keys::{ActorEpochs, registration_epochs};
use osis_label::{Address, ClaimSet, EntryTo, Parent, Reader, Step, StepId, StepKeys, genesis_label, label_steps, register, step_record};
use osis_schema::core_types::{self as ct, KemKey};
use osis_schema::{AspectKey, Codec};

/// A reader of a group's read epoch as the registrar lists it.
pub(crate) enum ReaderKey {
    /// A node or an actor: the X25519 half of its (read-role) KEM key.
    Dh([u8; 32]),
    /// A recovery or link key: static entry with an entry box sealed to its KEM key.
    Static(VerifyingKey, KemPublicKey),
}

fn kem_of(k: &KemKey) -> Result<KemPublicKey> {
    let KemKey::X25519MlKem768(b) = k;
    Ok(KemPublicKey::from_slice(b)?)
}

/// The readers of `group`'s read epoch `e` (spec/sync.md §2): holders of read boxes at `e`
/// (and key actors boxed at a higher role, whose box carries read), the owner included; a node
/// by its KEM key, another key actor by static entry, an actor by its newest read keyset.
pub(crate) fn readers(tx: &mut Tx<'_>, group: &Tid, e: &Epoch) -> Result<Vec<ReaderKey>> {
    let mut members: Vec<Tid> = Vec::new();
    if let Some(o) = tx.core.owner(group) {
        members.push(o);
    }
    let secrets = super::secrets_in(tx, group)?;
    let epochs = tx.core.epochs(group).unwrap_or_default();
    for k in secrets.boxes.keys() {
        let Ok(ke) = osis_keys::aspects::from_schema(&k.epoch) else { continue };
        let read_at_e = k.role == Role::Read && ke == *e;
        let carried = k.role > Role::Read && epochs.role(k.role).is_current(&ke) && tx.core.is_key_actor(&k.member);
        if read_at_e || carried {
            members.push(k.member);
        }
    }
    members.sort();
    members.dedup();
    let mut out = Vec::new();
    for m in members {
        out.extend(reader_key(tx, &m)?);
    }
    Ok(out)
}

fn reader_key(tx: &mut Tx<'_>, m: &Tid) -> Result<Option<ReaderKey>> {
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

/// The deposit seed of the actor `group`'s labels derive from (spec/sync.md §2).
fn deposit_seed(tx: &mut Tx<'_>, group: &Tid) -> Result<Secret32> {
    let actor = if tx.core.has_own_secrets(group) { *group } else { tx.core.owner(group).ok_or(Error::UnknownThing(*group))? };
    let k = Core::keys_in(tx, &actor)?.and_then(|k| k.deposit_seed).ok_or(Error::Misuse("no deposit seed in /keys"))?;
    Ok(Secret32::from_bytes(k))
}

/// Issues a step at the newest established epochs: a genesis step of a new label at `index`
/// when `parent` is none, else a child of the parent step (signed by the parent's delete key,
/// from the admin secret of the epoch it registers).
pub(crate) fn issue(tx: &mut Tx<'_>, epochs: &ActorEpochs, index: u64, parent: Option<(&Step, &Secret32)>, readers: &[ReaderKey], deposit: &Secret32) -> Result<(Step, ClaimSet)> {
    let [(re, rs), (_, ws), (_, adm)] = registration_epochs(epochs).ok_or(Error::Misuse("an admin registers: every role's newest secret is needed"))?;
    let label = parent.map_or_else(|| genesis_label(adm, index), |(p, _)| p.label);
    let keys = StepKeys::derive(rs, ws, adm, index, deposit, &label);
    let rk: Vec<Reader> = readers
        .iter()
        .map(|r| match r {
            ReaderKey::Dh(x) => Reader::Dh(*x),
            ReaderKey::Static(vk, kem) => Reader::Static { signing: *vk, entry: EntryTo::Sealed(kem) },
        })
        .collect();
    let del = label_role_key(LabelRole::Delete, parent.map_or(adm, |(_, a)| a), index);
    let p = match parent {
        None => Parent::Genesis(&del),
        Some((step, _)) => Parent::Child { step, delete: &del },
    };
    Ok(register(p, keys, &rk, (re, rs), &mut *tx.rng)?)
}

/// `/label` write: a new label of `group` with its genesis step, or a step added.
pub(crate) fn put_label(m: &mut Mutation, group: Tid, label: LabelId, index: u64, step: &Step, set: &ClaimSet, servers: Option<&[Address]>) -> Result<()> {
    match servers {
        Some(servers) => {
            let l = ct::Label { index, steps: [(step.id().0, step_record(step, Some(set)))].into_iter().collect(), servers: servers.to_vec(), replaced: false };
            m.op(group, &ct::LABEL, PathOp { path: vec![PathSeg::Key(label.to_value())], op: Op::Set(l.to_value()) })?;
        }
        None => {
            let path = vec![PathSeg::Key(label.to_value()), PathSeg::Field(1), PathSeg::Key(Value::Bytes(step.id().0.to_vec()))];
            m.op(group, &ct::LABEL, PathOp { path, op: Op::Set(step_record(step, Some(set)).to_value()) })?;
        }
    }
    Ok(())
}

/// A new label of `group` (its home label when `group` is an actor): genesis step at its
/// newest epochs, written to `/label` in `m`. Returns the label ID.
pub(crate) fn new_label(tx: &mut Tx<'_>, m: &mut Mutation, group: Tid, epochs: &ActorEpochs, readers: &[ReaderKey], deposit: &Secret32, servers: &[Address]) -> Result<LabelId> {
    let index = labels_of(tx, &group)?.values().map(|l| l.index.saturating_add(1)).max().unwrap_or(0);
    let (step, set) = issue(tx, epochs, index, None, readers, deposit)?;
    put_label(m, group, step.label, index, &step, &set, Some(servers))?;
    Ok(step.label)
}

/// Whether `group`'s newest admin epoch is one a step of `label` registers (its delete key).
fn admin_registered(tx: &mut Tx<'_>, group: &Tid, label: &ct::Label) -> Result<bool> {
    let Some(epochs) = tx.core.epochs(group) else { return Ok(false) };
    let Some((newest, _)) = epochs.role(Role::Admin).newest_held() else { return Ok(false) };
    for (step, _) in label_steps(label)?.values() {
        let key = step.keys.get(osis_keys::label_role(Role::Admin));
        if osis_keys::registered_epoch(epochs.role(Role::Admin), Role::Admin, label.index, key) == Some(newest) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn labels_of(tx: &mut Tx<'_>, group: &Tid) -> Result<ct::Labels> {
    Ok(tx.state(group, &ak("/label")?)?.and_then(Fragment::read).and_then(|v| ct::LABEL.decode(&v).ok()).unwrap_or_default())
}

impl Engine {
    /// Gives `group` a label (its home label, for an actor) on `servers`: genesis step at its
    /// newest epochs, recorded in `/label` (spec/sync.md §2). node-sync registers it.
    pub fn create_label(&mut self, group: &Tid, servers: &[Address]) -> Result<(LabelId, Done)> {
        let g = *group;
        self.run(|tx| {
            // signing the step and sealing entry boxes encrypt under the group's epochs
            let mut done = Done::default();
            let me = tx.core.id.tid();
            rotation::require_covered(tx, me, g, &ROLES.into_iter().collect(), &mut done)?;
            let epochs = tx.core.epochs(&g).ok_or(Error::Misuse("no secrets held for the group"))?;
            let deposit = deposit_seed(tx, &g)?;
            let (re, _) = epochs.role(Role::Read).newest_held().ok_or(Error::Misuse("no read secret"))?;
            let rs = readers(tx, &g, &re)?;
            let mut m = Mutation::new();
            let id = new_label(tx, &mut m, g, &epochs, &rs, &deposit, servers)?;
            done.add(Engine::commit_tx(tx, m)?);
            Ok((id, done))
        })
    }

    /// The step an admin issues at a server whose head is `head` of `group`'s label `label`
    /// (spec/sync.md §5): when it holds the head's epochs and an established epoch newer than
    /// the head's, or the head's deposit key is not the one the actor's deposit seed derives
    /// (refreshed), a child at its newest epochs with the current readers, recorded in `/label`
    /// (a membership commit; node-sync uploads the rotation commits first, then registers, then
    /// the rest). `None` when nothing is newer, or when it does not hold the head's epochs (it
    /// walks first). `fresh`: issue a step without a rotation (to list readers granted since).
    pub fn issue_step(&mut self, group: &Tid, label: &LabelId, head: &StepId, fresh: bool) -> Result<(Option<(Step, ClaimSet)>, Done)> {
        let (g, l, h) = (*group, *label, *head);
        let mut done = Done::default();
        let step = self.run(|tx| {
            let me = tx.core.id.tid();
            if tx.core.role_now(&me, &g) != Some(Role::Admin) {
                return Ok(None);
            }
            // signing a step and sealing entry boxes encrypt under the group's epochs
            rotation::require_covered(tx, me, g, &ROLES.into_iter().collect(), &mut done)?;
            let labels = labels_of(tx, &g)?;
            let rec = labels.get(&l).ok_or(Error::Misuse("unknown label"))?;
            let steps = label_steps(rec)?;
            let (head, _) = steps.get(&h).ok_or(Error::Misuse("unknown head step"))?.clone();
            let epochs = tx.core.epochs(&g).ok_or(Error::Misuse("no secrets held for the group"))?;
            // the head's epochs per role, where held
            let mut at = [None, None, None];
            for (i, r) in [Role::Read, Role::Write, Role::Admin].into_iter().enumerate() {
                let key = head.keys.get(osis_keys::label_role(r));
                if let Some(slot) = at.get_mut(i) {
                    *slot = osis_keys::registered_epoch(epochs.role(r), r, rec.index, key);
                }
            }
            let [_, _, Some(head_admin)] = at else { return Ok(None) };
            let deposit = deposit_seed(tx, &g)?;
            let deposit_key = osis_crypto::deposit_key(&deposit, &head.label).verifying_key();
            if !fresh && !osis_keys::newer_than_head(&epochs, at) && head.keys.deposit == deposit_key {
                return Ok(None);
            }
            if !epochs.role(Role::Admin).is_established(&head_admin) {
                return Ok(None);
            }
            let admin_secret = epochs.role(Role::Admin).secret(&head_admin).cloned().ok_or(Error::Misuse("head admin secret"))?;
            let [(re, _), (we, _), (ae, _)] = registration_epochs(&epochs).ok_or(Error::Misuse("an admin registers: every role's newest secret is needed"))?;
            // a child of the head already recorded at these epochs (another admin's, or this
            // node's own for another server): reused, so one rotation gives one step
            if !fresh {
                let current = |c: &Step| c.keys.deposit == deposit_key && [(Role::Read, re), (Role::Write, we), (Role::Admin, ae)].into_iter().all(|(r, e)| osis_keys::registered_epoch(epochs.role(r), r, rec.index, c.keys.get(osis_keys::label_role(r))) == Some(e));
                if let Some((c, Some(set))) = steps.values().filter(|(c, _)| c.prev == Some(h) && current(c)).min_by_key(|(c, _)| c.id()) {
                    return Ok(Some((c.clone(), set.clone())));
                }
            }
            let rs = readers(tx, &g, &re)?;
            let (step, set) = issue(tx, &epochs, rec.index, Some((&head, &admin_secret)), &rs, &deposit)?;
            let mut m = Mutation::new();
            put_label(&mut m, g, l, rec.index, &step, &set, None)?;
            done.add(Engine::commit_tx(tx, m)?);
            Ok(Some((step, set)))
        })?;
        Ok((step, done))
    }

    /// Replaces label `old` of `group` (spec/sync.md §2; an admin), in one transaction: rotates
    /// the admin secret first when the newest admin epoch is one a step of the old label
    /// registers (whoever took the label may hold it; a plain group gets secrets of its own),
    /// then writes a new label one index above the highest at the old label's servers and marks
    /// the old one replaced, in one commit. node-sync uploads the live blobs under the new label
    /// and deletes the old label's content entries.
    pub fn replace_label(&mut self, group: &Tid, old: &LabelId) -> Result<(LabelId, Done)> {
        let (g, o) = (*group, *old);
        self.run(|tx| {
            let me = tx.core.id.tid();
            if tx.core.role_now(&me, &g) != Some(Role::Admin) {
                return Err(Error::Permission { tid: g });
            }
            let rec = labels_of(tx, &g)?.get(&o).cloned().ok_or(Error::Misuse("no such label"))?;
            let mut done = Done::default();
            rotation::require_covered(tx, me, g, &ROLES.into_iter().collect(), &mut done)?;
            if admin_registered(tx, &g, &rec)? {
                if tx.core.has_own_secrets(&g) {
                    done.extend(rotation::rotate_now(tx, me, g, &[Role::Admin].into_iter().collect())?);
                } else {
                    rotation::own_secrets(tx, g, &mut done)?;
                }
            }
            let epochs = tx.core.epochs(&g).ok_or(Error::Misuse("no secrets held for the group"))?;
            let deposit = deposit_seed(tx, &g)?;
            let (re, _) = epochs.role(Role::Read).newest_held().ok_or(Error::Misuse("no read secret"))?;
            let rs = readers(tx, &g, &re)?;
            let mut m = Mutation::new();
            let id = new_label(tx, &mut m, g, &epochs, &rs, &deposit, &rec.servers)?;
            let path = vec![PathSeg::Key(o.to_value()), PathSeg::Field(3)];
            m.op(g, &ct::LABEL, PathOp { path, op: Op::Set(Value::Bool(true)) })?;
            done.add(Engine::commit_tx(tx, m)?);
            Ok((id, done))
        })
    }

    /// The newest label of `group` with its servers.
    pub fn label_of(&mut self, group: &Tid) -> Result<Option<(LabelId, Vec<Address>)>> {
        let g = *group;
        Ok(self.run(|tx| own_label(tx, &g))?.map(|(id, _, servers)| (id, servers)))
    }
}

/// The label IDs `/label` of `g` records, inside a transaction (unparsable: none).
pub(crate) fn labels_in(tx: &mut Tx<'_>, g: &Tid) -> Result<Vec<LabelId>> {
    let Some(v) = tx.state(g, &ak("/label")?)?.and_then(Fragment::read) else { return Ok(Vec::new()) };
    Ok(ct::LABEL.decode(&v).map(|m| m.into_keys().collect()).unwrap_or_default())
}
