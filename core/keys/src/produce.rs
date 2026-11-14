//! Box production: rotations, grants and re-seals (spec/crypto.md §4, spec/permissions.md §3).
//! Boxing an epoch's secret is encrypting under it: callers check the covers rule first
//! (`covers`), except for the epochs a rotation creates.

use crate::aspects::{KeysWrite, SecretsWrite, box_key, from_schema, history_key, keyset, keyset_of, to_schema};
use crate::epoch::{ActorEpochs, Provenance, ROLES, SUITE, is_newer, newest_of};
use crate::names::{Held, Names};
use crate::open::HistoryAlts;
use crate::Error;
use osis_base::{Role, Tid};
use osis_crypto::{
    AccountEpochKeys, BoxItem, BoxSlot, CryptoRngCore, Epoch, KemPublicKey, Secret32, key_actor_role_secret, open_history, seal_box, seal_history, HistoryEntry, seal_joint_box, wrap_symmetric_box,
};
use osis_schema::core_types::{BoxKey, JointBox, KemKey, Keys, Sealed, SealedBox, SecretBox, Secrets, SymmetricBox};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What the writer knows of a holder's keys.
#[derive(Clone, Debug)]
pub enum HolderKeys {
    /// One KEM key; `seed` when the writer holds it (symmetric boxes under its role secrets).
    KeyActor { kem: KemPublicKey, seed: Option<Secret32> },
    /// The holder's keysets per role to seal to, each with its KEM key (one; several ascending:
    /// a joint box, spec/crypto.md §4 Seal), and role secrets of the holder the writer holds
    /// (symmetric boxes, e.g. a thing's base actor).
    Actor { keysets: BTreeMap<Role, Vec<(Epoch, KemPublicKey)>>, own: BTreeMap<Role, (Epoch, Secret32)> },
    /// An account at its epoch (spec/crypto.md §3): the epoch's name and KEM key, and its keys
    /// when the writer holds it (symmetric boxes).
    Account { epoch: Epoch, kem: KemPublicKey, keys: Option<Arc<AccountEpochKeys>> },
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
                keysets.insert(r, vec![(from_schema(&ks.epoch)?, KemPublicKey::from_slice(b)?)]);
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

/// A holder to box: its tid, its role on the actor, its keys, and its floor on the actor (spec/crypto.md
/// §4, Floors: boxed only at read epochs whose floor is at least it).
#[derive(Clone, Debug)]
pub struct Recipient {
    pub holder: Tid,
    pub role: Role,
    pub keys: HolderKeys,
    pub floor: u64,
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
            HolderKeys::KeyActor { seed: Some(seed), .. } => symmetric(&slot, i, &key_actor_role_secret(seed, i.role), Epoch::ZERO)?,
            HolderKeys::Account { epoch, keys: Some(k), .. } => symmetric(&slot, i, &key_actor_role_secret(k.seed(), i.role), *epoch)?,
            HolderKeys::Account { epoch, kem, keys: None } => sealed(kem, &slot, Some(*epoch), i, rng)?,
            HolderKeys::Actor { keysets, own } => match keysets.get(&i.role).map(Vec::as_slice) {
                Some(joint @ [_, _, ..]) => self::joint(joint, &slot, i, rng)?,
                ks => match own.get(&i.role) {
                    Some((es, s)) if symmetric_box(es, ks.and_then(|k| k.first()).map(|(ek, _)| ek)) => symmetric(&slot, i, s, *es)?,
                    _ => {
                        let Some([(ek, pk)]) = ks else { return Ok(None) };
                        sealed(pk, &slot, Some(*ek), i, rng)?
                    }
                },
            },
        };
        let key = box_key(holder, i.role, &i.epoch);
        // a holder actor's keysets the box names, recorded beside it in `keys.0` where every
        // node holding the actor's keysets reads them (spec/crypto.md §4, Stale): a node holding
        // none of the actor's boxes judges its epochs stale by them
        if !matches!(rcpt.keys, HolderKeys::KeyActor { .. }) {
            out.sealed.insert(key.clone(), box_keysets(&b).iter().copied().collect());
        }
        out.boxes.insert(key, b);
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

/// A joint box to the holder's keysets `ks` (ascending, at least two) (spec/crypto.md §4, Seal).
fn joint(ks: &[(Epoch, KemPublicKey)], slot: &BoxSlot, i: &Item, rng: &mut dyn CryptoRngCore) -> Result<SecretBox, Error> {
    let item = BoxItem { role: i.role, epoch: i.epoch, secret: i.secret.clone() };
    let to: Vec<(Epoch, &KemPublicKey)> = ks.iter().map(|(e, pk)| (*e, pk)).collect();
    let sealed = seal_joint_box(&to, slot, &item, rng)?;
    Ok(SecretBox::Joint(JointBox { keysets: ks.iter().map(|(e, _)| to_schema(e)).collect(), suite: SUITE, sealed: Sealed::X25519MlKem768(sealed) }))
}

/// A symmetric box under the holder's secret `s` of `epoch_s` (spec/crypto.md §4, spec/wire.md
/// §7).
fn symmetric(slot: &BoxSlot, i: &Item, s: &Secret32, epoch_s: Epoch) -> Result<SecretBox, Error> {
    let wrap = wrap_symmetric_box(s, slot, epoch_s, i.secret)?;
    Ok(SecretBox::Symmetric(SymmetricBox { epoch: to_schema(&epoch_s), wrap: wrap.to_vec() }))
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
    /// The floor its history box writes (spec/crypto.md §4, Floors; 0 but at read).
    pub floor: u64,
}

/// The demotions every keyset of a rotation carries (spec/crypto.md §4, Carried demotions): the
/// commits demoting a writer or admin of the actor or of an actor below it that the rotator
/// holds in effect (`demotions`), and whether the rotation's own commit is one (`demotes`: a
/// keyset cannot name its own commit). A node holds the keyset only once it holds them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Carried {
    pub demotions: BTreeSet<osis_base::CommitId>,
    pub demotes: bool,
}

/// Per rotated role, the holder actors a rotation leaves out of it, each with the keysets of it
/// of that role its keyset records (spec/crypto.md §4, Left out): Seal at every node then seals
/// that holder only at a keyset descending from each.
pub type LeftOut = BTreeMap<Role, BTreeMap<Tid, BTreeSet<Epoch>>>;

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
    /// What it rotated of role `r`.
    pub fn role(&self, r: Role) -> Option<&Rotated> {
        self.rotated.iter().find(|x| x.role == r)
    }

    /// Records the new epochs, secrets and names in the rotator's own view. Their establishment
    /// comes from the rotation commit, applied (spec/crypto.md §4); the names are the rotator's
    /// own, held here.
    pub fn record(&self, epochs: &mut ActorEpochs) {
        for r in &self.rotated {
            let re = epochs.role_mut(r.role);
            re.set_history(r.epoch, [self.names.clone()].into(), r.supersedes.iter().copied(), Some(r.floor));
            re.set_secret(r.epoch, r.secret.clone());
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

    /// The read epoch it supersedes whose secret the rotator holds with the greatest n: what the
    /// rotation commit is wrapped under (spec/crypto.md §5). None when read is not rotated.
    pub fn wrap_epoch(&self) -> Option<Epoch> {
        self.wrap
    }
}

/// The boxes a rotation removes (spec/crypto.md §4): those keyed with a rotated role at an epoch
/// whose secret its history box carries (`carried`). A box at an epoch it cannot open, does not
/// hold established or may not carry (below a cut, spec/crypto.md §4 Floors) stands: it still
/// opens for its holder (which then adds that secret to the history where the carry rule lets
/// it, `history_adds`), and anchors and staleness read current epochs only.
fn removals(carried: &BTreeMap<Role, BTreeSet<Epoch>>, held_secrets: &Secrets) -> Result<BTreeSet<BoxKey>, Error> {
    let mut out = BTreeSet::new();
    for k in held_secrets.boxes.keys() {
        if carried.get(&k.role).is_some_and(|c| from_schema(&k.epoch).is_ok_and(|e| c.contains(&e))) {
            out.insert(k.clone());
        }
    }
    Ok(out)
}

/// Rotates `roles` of `actor` (spec/crypto.md §4, spec/permissions.md §3): per role a fresh
/// secret at n+1 (n = greatest n of its current and unsuperseded epochs, held or not; epochs merely
/// seen, with no valid rotation commit or snapshot, never count), boxes for every holder holding
/// the role (first admin included while its record edge stands), the history box of every
/// distinct earlier established secret held with `names` (spec/crypto.md §4: the departures from
/// `actor` the rotator holds), the keyset listing every current and unsuperseded epoch, and the removal of the role's boxes at the epochs whose
/// secret is held. No current secret is needed: an epoch the rotator cannot open is superseded
/// unread, and a holder of its secret adds it to the new epoch's history (`history_adds`).
/// `held` is the rotator's established view of the actor (a plain thing's derived epochs for the
/// switch to secrets of its own); `held_secrets` the actor's `secrets.0`. Records no holder actor
/// left out (`rotate_leaving_out`).
pub fn rotate(actor: &Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, held_secrets: &Secrets, holders: &[Recipient], names: &Names, rng: &mut dyn CryptoRngCore) -> Result<Rotation, Error> {
    rotate_leaving_out(actor, roles, held, held_secrets, holders, &LeftOut::new(), &Carried::default(), names, false, rng)
}

/// `rotate`, each rotated role's keyset recording `left_out` (the holder actors the rotation
/// leaves out of it, with the keysets of each it was left out at: `LeftOut`) and carrying
/// `carried` (`Carried`). `cut`: a grant without history (spec/crypto.md §4, Floors): the read
/// floor is its own n and its history box carries no earlier secret, so it removes no box.
#[allow(clippy::too_many_arguments)]
pub fn rotate_leaving_out(actor: &Tid, roles: &BTreeSet<Role>, held: &ActorEpochs, held_secrets: &Secrets, holders: &[Recipient], left_out: &LeftOut, carried: &Carried, names: &Names, cut: bool, rng: &mut dyn CryptoRngCore) -> Result<Rotation, Error> {
    let mut rotated = Vec::new();
    let mut secrets = SecretsWrite::default();
    let mut keys = KeysWrite::default();
    let mut wrap = None;
    let mut in_history: BTreeMap<Role, BTreeSet<Epoch>> = BTreeMap::new();
    let mut floors: BTreeMap<Role, u64> = BTreeMap::new();
    for &r in roles {
        let re = held.role(r);
        // current and unsuperseded: an epoch whose names this node does not meet is current
        // wherever its secret is not held, so it counts for n and is listed
        let current: BTreeSet<Epoch> = re.current().into_iter().chain(re.unsuperseded()).collect();
        // no epoch of any role at all: a plain thing's first (spec/crypto.md §3), n counted
        // as 0; an actor with epochs of other roles but none current of this one cannot rotate it
        let n = match current.iter().map(Epoch::n).max() {
            Some(n) => n,
            None if ROLES.iter().all(|q| held.role(*q).epochs().next().is_none()) => 0,
            None => return Err(Error::NoEpoch(r)),
        };
        let secret = Secret32::random(rng);
        let epoch = Epoch::derive(actor, r, n + 1, &secret)?;
        // the floor (spec/crypto.md §4, Floors): a cut's own n; else the greatest floor among
        // its maker and the holders it boxes (each boxed, none handed what lies below its own)
        let cut = cut && r == Role::Read;
        let floor = match (cut, re.has_floors()) {
            (true, _) => n + 1,
            (false, true) => holders.iter().filter(|m| m.role >= r).map(|m| m.floor).max().unwrap_or(0).max(re.own_floor()).min(n + 1),
            (false, false) => 0,
        };
        let established: Vec<(Epoch, Secret32)> = re.held_established().filter(|(e, _)| e.n() <= n).map(|(e, s)| (e, s.clone())).collect();
        if r == Role::Read {
            // the greatest n it supersedes whose secret is held: one exists whenever any read
            // secret is held (the rotator may hold no current one). By n, not order n
            // (spec/crypto.md §5): uploaders judge from the thing's own epochs, where derived
            // ones keep no order n
            wrap = newest_of(established.iter().map(|(e, _)| e));
        }
        // the carry rule (spec/crypto.md §4): what its floor lets in (its maker's is at most it);
        // a cut's floor, its own n, none
        let earlier: Vec<(Epoch, Secret32)> = established.into_iter().filter(|(e, _)| !cut && re.carries_into(floor, e)).collect();
        in_history.insert(r, earlier.iter().map(|(e, _)| *e).collect());
        floors.insert(r, floor);
        // every earlier roles secret held, the carry rule aside (spec/crypto.md §4, Roles secrets)
        let roles = re.held_roles().into_iter().filter(|(e, _)| e.n() <= n).collect();
        let entry = HistoryEntry { earlier: earlier.clone(), names: names.to_value(), floor, roles };
        secrets.history.insert(history_key(r, &epoch), seal_history(&secret, actor, r, &epoch, &entry)?);
        // the keyset lists its current epochs but derived ones (held only where the base actor's
        // secret is: superseded through the history box)
        let listed: BTreeSet<Epoch> = current.iter().filter(|e| re.provenance(e) != Some(Provenance::Derived)).copied().collect();
        let mut ks = keyset(&epoch, &secret, &listed, names);
        for (m, out) in left_out.get(&r).into_iter().flatten() {
            ks.left_out.insert(*m, out.iter().map(to_schema).collect());
        }
        ks.demotions = carried.demotions.clone();
        ks.demotes = carried.demotes;
        keys.keysets.insert(r, ks);
        let supersedes = listed.iter().copied().chain(earlier.iter().map(|(e, _)| *e)).collect();
        rotated.push(Rotated { role: r, epoch, secret, supersedes, floor });
    }
    secrets.removed = removals(&in_history, held_secrets)?;
    let mut unboxed = Vec::new();
    for m in holders {
        // the boxing rule (spec/crypto.md §4): at a read epoch of floor at least the holder's
        let allowed = |x: &&Rotated| !held.role(x.role).has_floors() || floors.get(&x.role).is_some_and(|f| *f >= m.floor);
        let items: Vec<Item> = rotated.iter().filter(|x| x.role <= m.role).filter(allowed).map(|x| Item { role: x.role, epoch: x.epoch, secret: &x.secret }).collect();
        if !items.is_empty() && box_items(actor, m, &items, rng, &mut secrets)?.is_none() {
            unboxed.push(m.holder);
        }
    }
    Ok(Rotation { rotated, secrets, keys, unboxed, names: names.clone(), wrap })
}

/// What a node writes as the history box of one current epoch (spec/crypto.md §4, History box):
/// the earlier secrets the live entries it opens list and every earlier superseded established
/// secret it holds (a current fork's travels by box and by the rotation listing it, never by history: what an epoch
/// supersedes is read alike by every node, its keyset listing every fork its rotator knew),
/// with the epoch's names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryBox {
    /// Every earlier secret the entry carries, by epoch.
    pub earlier: BTreeMap<Epoch, Secret32>,
    /// The epochs the live entries of the key list (what holders of the epoch read already).
    pub listed: BTreeSet<Epoch>,
    /// The epoch's names, copied from a met entry (a bound one first).
    pub names: Names,
    /// The epoch's floor as this node reads it (spec/crypto.md §4, Floors), written again.
    pub floor: u64,
    /// Every earlier roles secret the entry carries apart from `earlier` (spec/crypto.md §4,
    /// Roles secrets): those the live entries list and every one held.
    pub roles: BTreeMap<Epoch, Secret32>,
    /// The epochs whose roles secret the live entries list.
    pub roles_listed: BTreeSet<Epoch>,
}

impl HistoryBox {
    /// The entry it writes at its epoch.
    fn entry(&self) -> HistoryEntry {
        HistoryEntry {
            earlier: self.earlier.iter().map(|(x, sx)| (*x, sx.clone())).collect(),
            names: self.names.to_value(),
            floor: self.floor,
            roles: self.roles.iter().map(|(x, rx)| (*x, rx.clone())).collect(),
        }
    }
}

/// Per (role, current epoch) whose secret is held established: its history box as this node
/// writes it.
pub type HistoryBoxes = BTreeMap<(Role, Epoch), HistoryBox>;

/// The history boxes this node writes for the current established epochs of `actor` whose secret
/// it holds (spec/crypto.md §4): each opened live entry's secrets (`alts`: the live entries of
/// keys holding several), plus every earlier established secret held, and the names of a met
/// entry (`names_held`). An epoch no met entry names is left out: nothing is written under it.
pub fn history_boxes(actor: &Tid, held: &ActorEpochs, secrets: &Secrets, alts: &HistoryAlts, names_held: &dyn Held) -> HistoryBoxes {
    let mut out = HistoryBoxes::new();
    for r in ROLES {
        let re = held.role(r);
        for e in re.current() {
            let Some(s) = re.get(&e).and_then(|i| i.checked()) else { continue };
            let Some(names) = re.history_names(r, &e, names_held) else { continue };
            let k = history_key(r, &e);
            let mut earlier: BTreeMap<Epoch, Secret32> = BTreeMap::new();
            let mut listed = BTreeSet::new();
            let mut roles: BTreeMap<Epoch, Secret32> = BTreeMap::new();
            let mut roles_listed = BTreeSet::new();
            for ct in secrets.history.get(&k).into_iter().chain(alts.get(&k).into_iter().flatten()) {
                let Ok(h) = open_history(s, actor, r, &e, ct) else { continue };
                for (x, sx) in h.earlier {
                    listed.insert(x);
                    earlier.insert(x, sx);
                }
                for (x, rx) in h.roles {
                    roles_listed.insert(x);
                    roles.insert(x, rx);
                }
            }
            // every earlier roles secret held, the carry rule aside (spec/crypto.md §4, Roles
            // secrets)
            for (x, rx) in re.held_roles().into_iter().filter(|(x, _)| x.n() < e.n()) {
                roles.entry(x).or_insert(rx);
            }
            // the carry rule (spec/crypto.md §4): what the live entries list goes again as it is
            // (every holder of e reads it already); what this node adds, only as e's floor and
            // its maker's let in
            for (x, sx) in re.held_established().filter(|(x, _)| x.n() < e.n() && !re.is_current(x) && re.carries(&e, x)) {
                earlier.entry(x).or_insert_with(|| sx.clone());
            }
            roles.retain(|x, _| !earlier.contains_key(x));
            out.insert((r, e), HistoryBox { earlier, listed, names, floor: re.floor(&e), roles, roles_listed });
        }
    }
    out
}

/// A **history add** (spec/crypto.md §4): the history boxes of `hist` (this node's, for the
/// epochs it may encrypt under) carrying an earlier secret or roles secret no live entry lists,
/// each written whole beside the entries there (a put of a new entry, resetting nothing: any
/// holder of the epoch may add one). Empty when every one held is listed already.
pub fn history_adds(actor: &Tid, held: &ActorEpochs, hist: &HistoryBoxes) -> Result<SecretsWrite, Error> {
    let mut out = SecretsWrite::default();
    for ((r, e), h) in hist {
        if !h.adds() {
            continue;
        }
        let Some(s) = held.role(*r).get(e).and_then(|i| i.checked()) else { continue };
        out.history.insert(history_key(*r, e), seal_history(s, actor, *r, e, &h.entry())?);
    }
    Ok(out)
}

impl HistoryBox {
    /// It carries a secret or roles secret no live entry lists (a history add is due).
    pub fn adds(&self) -> bool {
        self.earlier.keys().any(|x| !self.listed.contains(x)) || self.roles.keys().any(|x| !self.roles_listed.contains(x) && !self.listed.contains(x))
    }
}

/// A grant or a re-share (spec/crypto.md §4, spec/permissions.md §3): `rcpt`'s boxes for `roles`
/// (those at or below its role) at each of their current (established) epochs whose secret is
/// held, with those epochs' history boxes written again from `hist` (`history_boxes`: what the
/// live entries list and what this node holds). `Ok(None)` when a needed keyset is unknown;
/// `Error::NoSecret` when a role has no such epoch held.
pub fn box_holder(
    actor: &Tid,
    held: &ActorEpochs,
    hist: &HistoryBoxes,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    let mut out = box_at(actor, held, hist, rcpt, roles, &|_, _| true, rng)?;
    // a grant with history also boxes each dropped epoch held that the holder's floor allows: no
    // history entry carries it on (spec/crypto.md §4, Floors)
    if let Some(w) = &mut out {
        let re = held.role(Role::Read);
        let items: Vec<Item> = re.dropped().into_iter().filter(|_| roles.contains(&Role::Read) && rcpt.role >= Role::Read).filter(|f| re.allows(f, rcpt.floor)).filter_map(|f| re.secret(&f).map(|s| Item { role: Role::Read, epoch: f, secret: s })).collect();
        if box_items(actor, rcpt, &items, rng, w)?.is_none() {
            return Ok(None);
        }
    }
    Ok(out)
}

/// The **tip add** (spec/crypto.md §4, Floors): boxes of the dropped epochs `epochs` (secrets
/// held) to `rcpt`, each that its floor allows. `Ok(None)` when a needed keyset is unknown.
pub fn box_dropped(actor: &Tid, held: &ActorEpochs, rcpt: &Recipient, epochs: &BTreeSet<Epoch>, rng: &mut dyn CryptoRngCore) -> Result<Option<SecretsWrite>, Error> {
    let re = held.role(Role::Read);
    let items: Vec<Item> = epochs.iter().filter(|f| re.allows(f, rcpt.floor)).filter_map(|f| re.secret(f).map(|s| Item { role: Role::Read, epoch: *f, secret: s })).collect();
    let mut out = SecretsWrite::default();
    Ok(box_items(actor, rcpt, &items, rng, &mut out)?.map(|_| out))
}

/// The re-seal the trigger asks for (`reseal_needed`): `box_holder` at only the current epochs
/// `rcpt` has no box at in `boxed` (`reseal_missing`), so it puts boxes and replaces none;
/// `Error::NoSecret` when a role
/// has no such epoch held.
pub fn reseal_holder(
    actor: &Tid,
    held: &ActorEpochs,
    boxed: &Secrets,
    hist: &HistoryBoxes,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    box_at(actor, held, hist, rcpt, roles, &|r, e| !boxed.boxes.contains_key(&box_key(rcpt.holder, r, e)), rng)
}

/// `box_holder` at the current epochs `want` names.
fn box_at(
    actor: &Tid,
    held: &ActorEpochs,
    hist: &HistoryBoxes,
    rcpt: &Recipient,
    roles: &BTreeSet<Role>,
    want: &dyn Fn(Role, &Epoch) -> bool,
    rng: &mut dyn CryptoRngCore,
) -> Result<Option<SecretsWrite>, Error> {
    let mut items = Vec::new();
    for &r in roles.iter().filter(|r| **r <= rcpt.role) {
        let re = held.role(r);
        let mut any = false;
        for e in re.current().into_iter().filter(|e| want(r, e) && re.allows(e, rcpt.floor)) {
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
        if let Some(h) = hist.get(&(i.role, i.epoch)) {
            out.history.insert(history_key(i.role, &i.epoch), seal_history(i.secret, actor, i.role, &i.epoch, &h.entry())?);
        }
    }
    Ok(Some(out))
}

/// The keysets of its holder its box `b` names (a sealed box's recipient keyset epoch, a
/// symmetric one's epoch of s, a joint one's keysets): none for a key actor's sealed box.
pub fn box_keysets(b: &SecretBox) -> Vec<Epoch> {
    match b {
        SecretBox::Sealed(x) => x.keyset.iter().filter_map(|e| from_schema(e).ok()).collect(),
        SecretBox::Symmetric(x) => from_schema(&x.epoch).into_iter().collect(),
        SecretBox::Joint(x) => x.keysets.iter().filter_map(|e| from_schema(e).ok()).collect(),
    }
}

/// The roles a grant of `role` boxes: every role at or below it.
pub fn roles_up_to(role: Role) -> BTreeSet<Role> {
    ROLES.into_iter().filter(|r| *r <= role).collect()
}
