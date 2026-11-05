//! Box production: rotations, grants and re-seals (spec/crypto.md §4, spec/permissions.md §3).
//! Boxing an epoch's secret is encrypting under it: callers check the covers rule first
//! (`covers`), except for the epochs a rotation creates.

use crate::aspects::{KeysWrite, SecretsWrite, box_key, from_schema, history_key, keyset, keyset_of, to_schema};
use crate::epoch::{ActorEpochs, Provenance, ROLES, SUITE, is_newer, newest_of};
use crate::names::Names;
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{
    BoxItem, BoxSlot, CryptoRngCore, Epoch, KemPublicKey, Secret32, key_actor_role_secret, seal_box, seal_history, wrap_symmetric_box,
};
use osis_schema::core_types::{BoxKey, KemKey, Keys, Sealed, SealedBox, SecretBox, Secrets, Signature, SymmetricBox};
use std::collections::{BTreeMap, BTreeSet};

/// What the writer knows of a holder's keys.
#[derive(Clone, Debug)]
pub enum HolderKeys {
    /// One KEM key; `seed` when the writer holds it (symmetric boxes under its role secrets).
    KeyActor { kem: KemPublicKey, seed: Option<Secret32> },
    /// The holder's newest keysets per role the writer holds, and its newest role secrets the
    /// writer holds (symmetric boxes, e.g. a thing's owner).
    Actor { keysets: BTreeMap<Role, (Epoch, KemPublicKey)>, own: BTreeMap<Role, (Epoch, Secret32)> },
}

impl HolderKeys {
    /// From the holder's `keys.0`: its key-actor KEM key, else its keysets.
    pub fn from_keys(k: &Keys) -> Result<HolderKeys, Error> {
        if let Some(KemKey::X25519MlKem768(b)) = &k.key {
            return Ok(HolderKeys::KeyActor { kem: KemPublicKey::from_slice(b)?, seed: None });
        }
        let mut keysets = BTreeMap::new();
        for r in ROLES {
            if let Some(ks) = keyset_of(k, r) {
                if ks.suite != SUITE {
                    return Err(Error::UnknownSuite(ks.suite));
                }
                let KemKey::X25519MlKem768(b) = &ks.kem_key;
                keysets.insert(r, (from_schema(&ks.epoch)?, KemPublicKey::from_slice(b)?));
            }
        }
        Ok(HolderKeys::Actor { keysets, own: BTreeMap::new() })
    }

    /// Adds the holder's newest held secrets (writer holds the holder's epochs).
    pub fn with_own(mut self, holder: &ActorEpochs) -> HolderKeys {
        if let HolderKeys::Actor { own, .. } = &mut self {
            for r in ROLES {
                if let Some((e, s)) = holder.role(r).newest_held() {
                    own.insert(r, (e, s.clone()));
                }
            }
        }
        self
    }
}

/// A holder to box: its tid, its role on the actor (an owner holds admin), its keys.
#[derive(Clone, Debug)]
pub struct Recipient {
    pub holder: Tid,
    pub role: Role,
    pub keys: HolderKeys,
}

/// One role secret to box.
struct Item<'a> {
    role: Role,
    epoch: Epoch,
    secret: &'a Secret32,
}

/// Writes `rcpt`'s boxes for `items` into `out`, one per (role, epoch), keyed with it. `None`
/// when a needed keyset is unknown.
fn box_items(actor: &Tid, rcpt: &Recipient, items: &[Item], rng: &mut dyn CryptoRngCore, out: &mut SecretsWrite) -> Result<Option<()>, Error> {
    let holder = rcpt.holder;
    for i in items {
        let slot = BoxSlot::Secrets { actor: *actor, holder, role: i.role, epoch: i.epoch };
        let b = match &rcpt.keys {
            HolderKeys::KeyActor { kem, seed: None } => sealed(kem, &slot, None, i, rng)?,
            HolderKeys::KeyActor { seed: Some(seed), .. } => symmetric(&slot, i, &key_actor_role_secret(seed, i.role), Epoch::ZERO, false)?,
            HolderKeys::Actor { keysets, own } => {
                let ks = keysets.get(&i.role);
                match own.get(&i.role) {
                    Some((es, s)) if symmetric_box(es, ks.map(|(ek, _)| ek)) => symmetric(&slot, i, s, *es, true)?,
                    _ => {
                        let Some((ek, pk)) = ks else { return Ok(None) };
                        sealed(pk, &slot, Some(*ek), i, rng)?
                    }
                }
            }
        };
        out.boxes.insert(box_key(holder, i.role, &i.epoch), b);
    }
    Ok(Some(()))
}

/// Whether a box to an actor holder is symmetric under its secret at `own` (the holder's newest
/// the writer holds) rather than sealed to its `keyset` epoch (the newest the writer holds):
/// unless that keyset is newer.
pub fn symmetric_box(own: &Epoch, keyset: Option<&Epoch>) -> bool {
    keyset.is_none_or(|ek| !is_newer(ek, own))
}

fn sealed(pk: &KemPublicKey, slot: &BoxSlot, keyset: Option<Epoch>, i: &Item, rng: &mut dyn CryptoRngCore) -> Result<SecretBox, Error> {
    let item = BoxItem { role: i.role, epoch: i.epoch, secret: i.secret.clone() };
    let sealed = seal_box(pk, slot, keyset, &item, rng)?;
    Ok(SecretBox::Sealed(SealedBox { keyset: keyset.as_ref().map(to_schema), suite: SUITE, sealed: Sealed::X25519MlKem768(sealed) }))
}

/// A symmetric box under the holder's secret `s` of `epoch_s`; to a holder actor (`signed`) with
/// its possession signature (spec/crypto.md §4, spec/wire.md §7).
fn symmetric(slot: &BoxSlot, i: &Item, s: &Secret32, epoch_s: Epoch, signed: bool) -> Result<SecretBox, Error> {
    let wrap = wrap_symmetric_box(s, slot, epoch_s, i.secret)?;
    let possession = if signed { Some(Signature::Ed25519(crate::possession::sign(s, slot, epoch_s, &wrap)?.0.to_vec())) } else { None };
    Ok(SecretBox::Symmetric(SymmetricBox { epoch: to_schema(&epoch_s), wrap: wrap.to_vec(), possession }))
}

/// A role's new epoch made by a rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotated {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
    /// The epochs it supersedes, as a node holding its secret reads them from its commit: those
    /// its keyset lists (`SecretsWrite::rotation_commit`) and those its history box lists.
    pub supersedes: BTreeSet<Epoch>,
}

/// A rotation's writes (spec/crypto.md §4): one role commit carries them.
#[derive(Clone, Debug)]
pub struct Rotation {
    pub rotated: Vec<Rotated>,
    pub secrets: SecretsWrite,
    pub keys: KeysWrite,
    /// Holders with no keyset known for a role they hold: left unboxed (re-seal later).
    pub unboxed: Vec<Tid>,
    /// The names every history box it writes carries (spec/crypto.md §4).
    pub names: Names,
    wrap: Option<Epoch>,
}

impl Rotation {
    /// Records the new epochs, secrets and names in the rotator's own view. Their establishment
    /// comes from the rotation commit, applied (spec/crypto.md §4); the names are the rotator's
    /// own, held here.
    pub fn record(&self, epochs: &mut ActorEpochs) {
        for r in &self.rotated {
            let re = epochs.role_mut(r.role);
            re.rotation(r.epoch, r.supersedes.iter().copied());
            re.set_secret(r.epoch, r.secret.clone());
            re.add_names(r.epoch, self.names.clone());
        }
    }

    /// `held` (an established view) as the rotation commit being made sees it, before it has an
    /// ID: the rotation recorded and its epochs established, as that commit, applied, establishes
    /// them (its rotations recorded under a placeholder ID; a scratch view, never kept). What the
    /// commit itself writes under them (spec/crypto.md §4: the rotation commit's own writes).
    pub fn preview(&self, held: &ActorEpochs) -> Result<ActorEpochs, Error> {
        let mut a = held.clone();
        self.record(&mut a);
        for (r, e, sup) in self.secrets.rotation_commit(&self.keys)? {
            let re = a.role_mut(r);
            re.set_rotation(e, osis_base::CommitId([0; 32]), sup);
            re.set_established(e, Provenance::Rotated);
        }
        Ok(a)
    }

    /// The newest read epoch it supersedes whose secret the rotator holds: what the rotation
    /// commit is wrapped under (spec/crypto.md §5). None when read is not rotated.
    pub fn wrap_epoch(&self) -> Option<Epoch> {
        self.wrap
    }
}

/// The boxes a rotation of `roles` removes: those keyed with a rotated role at one of its
/// current epochs.
fn removals(roles: &BTreeSet<Role>, held: &ActorEpochs, held_secrets: &Secrets) -> Result<BTreeSet<BoxKey>, Error> {
    let mut out = BTreeSet::new();
    for k in held_secrets.boxes.keys().filter(|k| roles.contains(&k.role)) {
        if held.role(k.role).is_current(&from_schema(&k.epoch)?) {
            out.insert(k.clone());
        }
    }
    Ok(out)
}

/// Rotates `roles` of `actor` (spec/crypto.md §4, spec/permissions.md §3): per role a fresh
/// secret at n+1 (n = greatest n of its current epochs; epochs merely seen, unestablished, never
/// count), boxes for every holder holding the role (owner included, as a recipient with admin),
/// the history box of every distinct earlier established secret held with `names` (spec/crypto.md
/// §4: the departures from `actor` the rotator holds), the keyset, and the removal of the role's
/// boxes held at its current epochs. `held` is the rotator's established view of the actor (a
/// plain thing's derived epochs for the switch to secrets of its own); `held_secrets` the
/// actor's `secrets.0`.
pub fn rotate(actor: &Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, held_secrets: &Secrets, holders: &[Recipient], names: &Names, rng: &mut dyn CryptoRngCore) -> Result<Rotation, Error> {
    let removed = removals(roles, held, held_secrets)?;
    let mut rotated = Vec::new();
    let mut secrets = SecretsWrite { removed, ..SecretsWrite::default() };
    let mut keys = KeysWrite::default();
    let mut wrap = None;
    for &r in roles {
        let re = held.role(r);
        let current = re.current();
        // no epoch of any role at all: an ownerless thing's first (spec/crypto.md §3), n counted
        // as 0; an actor with epochs of other roles but none current of this one cannot rotate it
        let n = match current.iter().map(Epoch::n).max() {
            Some(n) => n,
            None if ROLES.iter().all(|q| held.role(*q).epochs().next().is_none()) => 0,
            None => return Err(Error::NoEpoch(r)),
        };
        let secret = Secret32::random(rng);
        let epoch = Epoch::derive(actor, r, n + 1, &secret)?;
        if r == Role::Read {
            // by n, not order n (spec/crypto.md §5): uploaders judge from the thing's own epochs,
            // where derived ones keep no order n
            wrap = newest_of(current.iter().filter(|e| re.secret(e).is_some()));
        }
        let earlier: Vec<(Epoch, Secret32)> = re.held_established().map(|(e, s)| (e, s.clone())).collect();
        secrets.history.insert(history_key(r, &epoch), seal_history(&secret, actor, r, &epoch, &earlier, &names.to_value())?);
        // the keyset lists its current epochs but derived ones (held only where the owner's
        // secret is: superseded through the history box)
        let listed: BTreeSet<Epoch> = current.iter().filter(|e| re.provenance(e) != Some(Provenance::Derived)).copied().collect();
        keys.keysets.insert(r, keyset(&epoch, &secret, &listed));
        let supersedes = listed.iter().copied().chain(earlier.iter().map(|(e, _)| *e)).collect();
        rotated.push(Rotated { role: r, epoch, secret, supersedes });
    }
    let mut unboxed = Vec::new();
    for m in holders {
        let items: Vec<Item> = rotated.iter().filter(|x| x.role <= m.role).map(|x| Item { role: x.role, epoch: x.epoch, secret: &x.secret }).collect();
        if !items.is_empty() && box_items(actor, m, &items, rng, &mut secrets)?.is_none() {
            unboxed.push(m.holder);
        }
    }
    Ok(Rotation { rotated, secrets, keys, unboxed, names: names.clone(), wrap })
}

/// A grant or re-seal (spec/crypto.md §4, spec/permissions.md §3): `rcpt`'s boxes for `roles`
/// (those at or below its role) at each of their current (established) epochs whose secret is
/// held, with the history boxes of those epochs re-written unchanged. `Ok(None)` when a needed
/// keyset is unknown; `Error::NoSecret` when a role has no such epoch held.
pub fn box_holder(
    actor: &Tid,
    held: &ActorEpochs,
    held_secrets: &Secrets,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    let mut items = Vec::new();
    for &r in roles.iter().filter(|r| **r <= rcpt.role) {
        let re = held.role(r);
        let mut any = false;
        for e in re.current() {
            if let Some(s) = re.secret(&e) {
                items.push(Item { role: r, epoch: e, secret: s });
                any = true;
            }
        }
        if !any {
            return Err(Error::NoSecret(r));
        }
    }
    let mut out = SecretsWrite::default();
    if box_items(actor, rcpt, &items, rng, &mut out)?.is_none() {
        return Ok(None);
    }
    for i in &items {
        if let Some(h) = held_secrets.history.get(&history_key(i.role, &i.epoch)) {
            out.history.insert(history_key(i.role, &i.epoch), h.clone());
        }
    }
    Ok(Some(out))
}

/// The epoch of its holder box `b` names (a sealed box's recipient keyset epoch, a symmetric
/// one's epoch of s): none for a key actor's sealed box.
pub fn box_epoch(b: &SecretBox) -> Option<Epoch> {
    match b {
        SecretBox::Sealed(x) => x.keyset.as_ref().and_then(|e| from_schema(e).ok()),
        SecretBox::Symmetric(x) => from_schema(&x.epoch).ok(),
    }
}

/// The roles a grant of `role` boxes: every role at or below it.
pub fn roles_up_to(role: Role) -> BTreeSet<Role> {
    ROLES.into_iter().filter(|r| *r <= role).collect()
}
