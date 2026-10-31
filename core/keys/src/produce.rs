//! Box production: rotations, grants and re-seals (spec/crypto.md §4, spec/permissions.md §3).
//! Boxing an epoch's secret is encrypting under it: callers check the covers rule first
//! (`covers`), except for the epochs a rotation creates.

use crate::aspects::{KeysWrite, SecretsWrite, box_key, from_schema, history_key, keyset, keyset_of, to_schema};
use crate::epoch::{ActorEpochs, Provenance, ROLES, SUITE, is_newer, newest_of};
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{
    BoxItem, BoxSlot, CryptoRngCore, Epoch, KemPublicKey, Secret32, key_actor_role_secret, seal_box, seal_history, wrap_symmetric_box,
};
use osis_schema::core_types::{BoxKey, KemKey, Keys, Sealed, SealedBox, SecretBox, Secrets, SymmetricBox};
use std::collections::{BTreeMap, BTreeSet};

/// What the writer knows of a member's keys.
#[derive(Clone, Debug)]
pub enum MemberKeys {
    /// One KEM key; `seed` when the writer holds it (symmetric boxes under its role secrets).
    KeyActor { kem: KemPublicKey, seed: Option<Secret32> },
    /// The member's newest keysets per role the writer holds, and its newest role secrets the
    /// writer holds (symmetric boxes, e.g. a thing's owner).
    Actor { keysets: BTreeMap<Role, (Epoch, KemPublicKey)>, own: BTreeMap<Role, (Epoch, Secret32)> },
}

impl MemberKeys {
    /// From the member's `/keys`: its key-actor KEM key, else its keysets.
    pub fn from_keys(k: &Keys) -> Result<MemberKeys, Error> {
        if let Some(KemKey::X25519MlKem768(b)) = &k.key {
            return Ok(MemberKeys::KeyActor { kem: KemPublicKey::from_slice(b)?, seed: None });
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
        Ok(MemberKeys::Actor { keysets, own: BTreeMap::new() })
    }

    /// Adds the member's newest held secrets (writer holds the member's epochs).
    pub fn with_own(mut self, member: &ActorEpochs) -> MemberKeys {
        if let MemberKeys::Actor { own, .. } = &mut self {
            for r in ROLES {
                if let Some((e, s)) = member.role(r).newest_held() {
                    own.insert(r, (e, s.clone()));
                }
            }
        }
        self
    }
}

/// A member to box: its tid, its role on the actor (an owner holds admin), its keys.
#[derive(Clone, Debug)]
pub struct Recipient {
    pub member: Tid,
    pub role: Role,
    pub keys: MemberKeys,
}

/// One role secret to box.
struct Item<'a> {
    role: Role,
    epoch: Epoch,
    secret: &'a Secret32,
}

/// Writes `rcpt`'s boxes for `items` (one per (role, epoch)) into `out`; returns the (role,
/// epoch) pairs they carry. A key-actor member without its seed gets one sealed box keyed at the
/// highest role, carrying one secret per role (the newest epoch given for each). `None` when a
/// needed keyset is unknown.
fn box_items(actor: &Tid, rcpt: &Recipient, items: &[Item], rng: &mut dyn CryptoRngCore, out: &mut SecretsWrite) -> Result<Option<Vec<(Role, Epoch)>>, Error> {
    let member = rcpt.member;
    match &rcpt.keys {
        MemberKeys::KeyActor { kem, seed: None } => {
            let mut per_role: BTreeMap<Role, &Item> = BTreeMap::new();
            for i in items {
                let newest = per_role.entry(i.role).or_insert(i);
                if is_newer(&i.epoch, &newest.epoch) {
                    *newest = i;
                }
            }
            let Some((top_role, top)) = per_role.iter().next_back() else { return Ok(Some(Vec::new())) };
            let slot = BoxSlot::Secrets { actor: *actor, member, role: *top_role, epoch: top.epoch };
            let payload: Vec<BoxItem> = per_role.values().map(|i| BoxItem { role: i.role, epoch: i.epoch, secret: i.secret.clone() }).collect();
            let sealed = seal_box(kem, &slot, None, &payload, rng)?;
            let b = SecretBox::Sealed(SealedBox { keyset: None, suite: SUITE, sealed: Sealed::X25519MlKem768(sealed) });
            out.boxes.insert(box_key(member, *top_role, &top.epoch), b);
            return Ok(Some(per_role.values().map(|i| (i.role, i.epoch)).collect()));
        }
        MemberKeys::KeyActor { seed: Some(seed), .. } => {
            for i in items {
                let s = key_actor_role_secret(seed, i.role);
                let b = symmetric(actor, member, i, &s, Epoch::ZERO)?;
                out.boxes.insert(box_key(member, i.role, &i.epoch), b);
            }
        }
        MemberKeys::Actor { keysets, own } => {
            for i in items {
                let ks = keysets.get(&i.role);
                let b = match own.get(&i.role) {
                    Some((es, s)) if symmetric_box(es, ks.map(|(ek, _)| ek)) => symmetric(actor, member, i, s, *es)?,
                    _ => {
                        let Some((ek, pk)) = ks else { return Ok(None) };
                        let slot = BoxSlot::Secrets { actor: *actor, member, role: i.role, epoch: i.epoch };
                        let payload = [BoxItem { role: i.role, epoch: i.epoch, secret: i.secret.clone() }];
                        let sealed = seal_box(pk, &slot, Some(*ek), &payload, rng)?;
                        SecretBox::Sealed(SealedBox { keyset: Some(to_schema(ek)), suite: SUITE, sealed: Sealed::X25519MlKem768(sealed) })
                    }
                };
                out.boxes.insert(box_key(member, i.role, &i.epoch), b);
            }
        }
    }
    Ok(Some(items.iter().map(|i| (i.role, i.epoch)).collect()))
}

/// Whether a box to an actor member is symmetric under its secret at `own` (the member's newest
/// the writer holds) rather than sealed to its `keyset` epoch (the newest the writer holds):
/// unless that keyset is newer.
pub fn symmetric_box(own: &Epoch, keyset: Option<&Epoch>) -> bool {
    keyset.is_none_or(|ek| !is_newer(ek, own))
}

fn symmetric(actor: &Tid, member: Tid, i: &Item, s: &Secret32, epoch_s: Epoch) -> Result<SecretBox, Error> {
    let slot = BoxSlot::Secrets { actor: *actor, member, role: i.role, epoch: i.epoch };
    let wrap = wrap_symmetric_box(s, &slot, epoch_s, i.secret)?;
    Ok(SecretBox::Symmetric(SymmetricBox { epoch: to_schema(&epoch_s), wrap: wrap.to_vec() }))
}

/// A role's new epoch made by a rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotated {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
    /// The current epochs it supersedes (as the rotator held them).
    pub supersedes: BTreeSet<Epoch>,
}

/// A rotation's writes (spec/crypto.md §4): one membership commit carries them.
#[derive(Clone, Debug)]
pub struct Rotation {
    pub rotated: Vec<Rotated>,
    pub secrets: SecretsWrite,
    pub keys: KeysWrite,
    /// Members with no keyset known for a role they hold: left unboxed (re-seal later).
    pub unboxed: Vec<Tid>,
    wrap: Option<Epoch>,
}

impl Rotation {
    /// Records the new epochs and secrets in the rotator's own view.
    pub fn record(&self, epochs: &mut ActorEpochs) {
        for r in &self.rotated {
            let re = epochs.role_mut(r.role);
            re.rotation(r.epoch, r.supersedes.iter().copied());
            re.set_secret(r.epoch, r.secret.clone());
            re.set_established(r.epoch, Provenance::Own);
        }
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

/// The roles a key-actor member's box carries besides the rotated ones (spec/crypto.md §4):
/// below its top written role; or, when the rotation writes it nothing but removes its box,
/// every role it holds.
fn carried(m: &Recipient, roles: &BTreeSet<Role>, removed: &BTreeSet<BoxKey>) -> Vec<Role> {
    if !matches!(m.keys, MemberKeys::KeyActor { seed: None, .. }) {
        return Vec::new();
    }
    let held = ROLES.into_iter().filter(|r| *r <= m.role && !roles.contains(r));
    match roles.iter().filter(|r| **r <= m.role).max() {
        Some(top) => held.filter(|r| r < top).collect(),
        None if removed.iter().any(|k| k.member == m.member) => held.collect(),
        None => Vec::new(),
    }
}

/// Rotates `roles` of `actor` (spec/crypto.md §4, spec/permissions.md §3): per role a fresh
/// secret at n+1 (n = greatest n of the current epochs it supersedes; epochs
/// merely seen, unestablished, never count), boxes for
/// every member holding the role (owner included, as a recipient with admin), the history box of
/// every distinct earlier established secret held (spec/crypto.md §4: never one got by re-seal
/// before its rotation commit), the keyset, and the removal of the role's boxes held at the
/// epochs it supersedes. `held` is the rotator's view of the actor (a plain thing's derived
/// epochs for the switch to secrets of its own); `held_secrets` the actor's `/secrets`.
/// Secrets of other roles carried to key-actor members are encrypting under their epochs: a
/// carried role whose newest epoch `may_carry` refuses (the covers rule) is rotated too.
pub fn rotate(
    actor: &Tid,
    roles: &BTreeSet<Role>,
    held: &ActorEpochs,
    held_secrets: &Secrets,
    members: &[Recipient],
    may_carry: &dyn Fn(Role, &Epoch) -> bool,
    rng: &mut dyn CryptoRngCore,
) -> Result<Rotation, Error> {
    let mut roles = roles.clone();
    let removed = loop {
        let removed = removals(&roles, held, held_secrets)?;
        let mut more = BTreeSet::new();
        for m in members {
            for r in carried(m, &roles, &removed) {
                let (e, _) = held.role(r).newest_held().ok_or(Error::NoSecret(r))?;
                if !may_carry(r, &e) {
                    more.insert(r);
                }
            }
        }
        if more.is_empty() {
            break removed;
        }
        roles.extend(more);
    };
    let mut rotated = Vec::new();
    let mut secrets = SecretsWrite { removed, ..SecretsWrite::default() };
    let mut keys = KeysWrite::default();
    let mut wrap = None;
    for &r in &roles {
        let re = held.role(r);
        let supersedes: BTreeSet<Epoch> = re.current().into_iter().collect();
        let n = supersedes.iter().map(Epoch::n).max().ok_or(Error::NoEpoch(r))?;
        let secret = Secret32::random(rng);
        let epoch = Epoch::derive(actor, r, n + 1, &secret)?;
        if r == Role::Read {
            // by n, not order n (spec/crypto.md §5): uploaders judge from the thing's own epochs,
            // where derived ones keep no order n
            wrap = newest_of(supersedes.iter().filter(|e| re.secret(e).is_some()));
        }
        let earlier: Vec<(Epoch, Secret32)> = re.held_established().map(|(e, s)| (e, s.clone())).collect();
        secrets.history.insert(history_key(r, &epoch), seal_history(&secret, actor, r, &epoch, &earlier)?);
        keys.keysets.insert(r, keyset(&epoch, &secret));
        rotated.push(Rotated { role: r, epoch, secret, supersedes });
    }
    let mut unboxed = Vec::new();
    for m in members {
        let mut items: Vec<Item> = rotated.iter().filter(|x| x.role <= m.role).map(|x| Item { role: x.role, epoch: x.epoch, secret: &x.secret }).collect();
        for r in carried(m, &roles, &secrets.removed) {
            let (epoch, secret) = held.role(r).newest_held().ok_or(Error::NoSecret(r))?;
            items.push(Item { role: r, epoch, secret });
        }
        if !items.is_empty() && box_items(actor, m, &items, rng, &mut secrets)?.is_none() {
            unboxed.push(m.member);
        }
    }
    Ok(Rotation { rotated, secrets, keys, unboxed, wrap })
}

/// A grant or re-seal (spec/crypto.md §4, spec/permissions.md §3): `rcpt`'s boxes for `roles`
/// (those at or below its role) at each of their current (established) epochs whose secret is
/// held, with the history boxes of those epochs re-written unchanged. A key-actor member without
/// its seed held gets one box carrying each role's newest. `Ok(None)` when a needed keyset is
/// unknown. A re-seal uses `reseal_member`.
pub fn box_member(
    actor: &Tid,
    held: &ActorEpochs,
    held_secrets: &Secrets,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    box_at(actor, held, held_secrets, rcpt, roles, &|_| true, rng)
}

/// A re-seal (spec/permissions.md §3): `box_member` at the current epochs established through
/// their rotation commits (`Provenance::reseals`) only, never at one established by a snapshot
/// alone. `Error::NoSecret` when a role has no such epoch held.
pub fn reseal_member(
    actor: &Tid,
    held: &ActorEpochs,
    held_secrets: &Secrets,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    box_at(actor, held, held_secrets, rcpt, roles, &Provenance::reseals, rng)
}

fn box_at(
    actor: &Tid,
    held: &ActorEpochs,
    held_secrets: &Secrets,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    at: &dyn Fn(Provenance) -> bool,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    let mut items = Vec::new();
    for &r in roles.iter().filter(|r| **r <= rcpt.role) {
        let re = held.role(r);
        let mut any = false;
        for e in re.current().into_iter().filter(|e| re.provenance(e).is_some_and(at)) {
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
    let Some(boxed) = box_items(actor, rcpt, &items, rng, &mut out)? else { return Ok(None) };
    for (r, e) in boxed {
        if let Some(h) = held_secrets.history.get(&history_key(r, &e)) {
            out.history.insert(history_key(r, &e), h.clone());
        }
    }
    Ok(Some(out))
}

/// The roles a grant of `role` boxes: every role at or below it.
pub fn roles_up_to(role: Role) -> BTreeSet<Role> {
    ROLES.into_iter().filter(|r| *r <= role).collect()
}
