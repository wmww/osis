//! `secrets.0` boxes, entry boxes and history boxes (spec/crypto.md §4, spec/wire.md §7).
//! The `box` value itself (spec/data-model.md §9) is osis-keys'; this module builds the AD
//! tuples and seals, wraps and opens the payloads.

use crate::aead::{self, SUITE_KEY_LEN, ZERO_NONCE};
use crate::kdf::{self, kdf};
use crate::{Error, KemPublicKey, KemSecret, SUITE_1, Secret32, open_sealed, seal};
use osis_base::cbor::{Limits, decode, encode};
use osis_base::{LabelId, Role, Tid, Value};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

/// A role secret's epoch `(n, nonce)`; ordered by n, then nonce (the canonical order of
/// `[n, nonce]`). n is within the int range.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Epoch {
    n: i64,
    nonce: [u8; 32],
}

impl Epoch {
    /// `(0, 32 zero bytes)`: the fixed epoch of a key actor's role secrets, the one exception to
    /// the nonce rule (spec/crypto.md §3).
    pub const ZERO: Epoch = Epoch { n: 0, nonce: [0; 32] };

    /// `TooLarge` above `i64::MAX`.
    pub fn new(n: u64, nonce: [u8; 32]) -> Result<Epoch, Error> {
        Ok(Epoch { n: i64::try_from(n).map_err(|_| Error::TooLarge)?, nonce })
    }

    /// The epoch secret `s` of `actor`'s `role` names at `n` (spec/crypto.md §4, the nonce
    /// rule): the one its roles secret names (`derive_roles`).
    pub fn derive(actor: &Tid, role: Role, n: u64, s: &Secret32) -> Result<Epoch, Error> {
        Epoch::derive_roles(actor, role, n, &roles_secret(s))
    }

    /// The epoch roles secret `r` of `actor`'s `role` names at `n` (the nonce rule): nonce
    /// `kdf("epoch", r, actor tid || role byte || le64(n))`.
    pub fn derive_roles(actor: &Tid, role: Role, n: u64, r: &Secret32) -> Result<Epoch, Error> {
        let n = i64::try_from(n).map_err(|_| Error::TooLarge)?;
        let input = [actor.as_bytes().as_slice(), &[role_byte(role)], &n.to_le_bytes()].concat();
        Ok(Epoch { n, nonce: *kdf(kdf::EPOCH, r.expose(), &input).expose() })
    }

    /// Whether `s` is the secret of this epoch of `actor`'s `role` (the nonce rule).
    pub fn names(&self, actor: &Tid, role: Role, s: &Secret32) -> bool {
        Epoch::derive(actor, role, self.n(), s).is_ok_and(|e| e == *self)
    }

    /// Whether `r` is the roles secret of this epoch of `actor`'s `role` (the nonce rule).
    pub fn names_roles(&self, actor: &Tid, role: Role, r: &Secret32) -> bool {
        Epoch::derive_roles(actor, role, self.n(), r).is_ok_and(|e| e == *self)
    }

    pub fn n(&self) -> u64 {
        self.n.unsigned_abs()
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    /// `[n, nonce]` (spec/wire.md §1).
    pub fn to_wire(&self) -> Value {
        Value::List(vec![Value::Int(self.n), Value::Bytes(self.nonce.to_vec())])
    }
    pub fn from_wire(v: &Value) -> Result<Epoch, Error> {
        match v {
            Value::List(items) => match items.as_slice() {
                [n, nonce] => Epoch::new(get_uint(n)?, get_array(nonce)?),
                _ => Err(Error::Malformed("epoch")),
            },
            _ => Err(Error::Malformed("epoch")),
        }
    }
}

/// Form fields of a box, as they enter its AD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoxForm<'a> {
    /// To the holder's KEM key of the keyset `keyset` (none for a key actor), under `suite`.
    Sealed { keyset: Option<Epoch>, suite: u64 },
    /// Wrap under `kdf("box", s)`, s the holder's own secret of epoch `epoch_s`.
    Symmetric { epoch_s: Epoch },
    /// Sealed to the KEM key of each of the holder's keysets `keysets` (ascending, at least two)
    /// in turn, the first outermost, under `suite`: opens only for a holder of each.
    Joint { keysets: &'a [Epoch], suite: u64 },
}

impl BoxForm<'_> {
    fn to_wire(self) -> Result<Value, Error> {
        Ok(match self {
            BoxForm::Sealed { keyset, suite } => {
                Value::List(vec![Value::Int(0), Value::List(keyset.iter().map(Epoch::to_wire).collect()), uint(suite)?])
            }
            BoxForm::Symmetric { epoch_s } => Value::List(vec![Value::Int(1), epoch_s.to_wire()]),
            BoxForm::Joint { keysets, suite } => Value::List(vec![Value::Int(2), Value::List(keysets.iter().map(Epoch::to_wire).collect()), uint(suite)?]),
        })
    }
}

/// Where a box sits: the AD fields before the form (spec/wire.md §7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoxSlot {
    /// A `secrets.0` box of `actor` to `holder` for (role, epoch).
    Secrets { actor: Tid, holder: Tid, role: Role, epoch: Epoch },
    /// An entry box of a label step; `group`, the label's group thing, is the actor whose epoch
    /// the payload names (not in the AD).
    Entry { label: LabelId, step_key: [u8; 32], group: Tid },
}

impl BoxSlot {
    /// The actor whose epochs the box carries.
    pub fn actor(&self) -> &Tid {
        match self {
            BoxSlot::Secrets { actor, .. } => actor,
            BoxSlot::Entry { group, .. } => group,
        }
    }

    /// The (role, epoch) of a `secrets.0` box's key: what its payload must name.
    fn key(&self) -> Option<(Role, Epoch)> {
        match self {
            BoxSlot::Secrets { role, epoch, .. } => Some((*role, *epoch)),
            BoxSlot::Entry { .. } => None,
        }
    }

    /// AD `[actor, holder, role, n, nonce, form]` or `[label_id, step_key, form]`.
    pub fn ad(&self, form: BoxForm) -> Result<Vec<u8>, Error> {
        Ok(encode(&Value::List(self.ad_items(form)?)))
    }

    fn ad_items(&self, form: BoxForm) -> Result<Vec<Value>, Error> {
        let form = form.to_wire()?;
        Ok(match self {
            BoxSlot::Secrets { actor, holder, role, epoch } => {
                vec![tid(actor), tid(holder), role_value(*role), Value::Int(epoch.n), Value::Bytes(epoch.nonce.to_vec()), form]
            }
            BoxSlot::Entry { label, step_key, .. } => vec![Value::Bytes(label.0.to_vec()), Value::Bytes(step_key.to_vec()), form],
        })
    }
}

/// The role secret a sealed box carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoxItem {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
}

/// Sealed form, payload `[role, n, secret]`, to `recipient` (the KEM key of keyset `keyset`,
/// none for a key actor) under suite 1. Returns the raw sealed box. The item's epoch must be the
/// one its secret names (spec/crypto.md §4); at a `secrets.0` slot, its key's (role, epoch).
pub fn seal_box(recipient: &KemPublicKey, slot: &BoxSlot, keyset: Option<Epoch>, item: &BoxItem, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let payload = box_payload(slot, item)?;
    let ad = slot.ad(BoxForm::Sealed { keyset, suite: u64::from(SUITE_1) })?;
    seal(recipient, &ad, &payload, rng)
}

/// What an entry box carries (spec/sync-ids.md §3): the read secret of the epoch its step registers
/// and, when that epoch supersedes one, the earlier secret its rotation commit is wrapped under;
/// and the sync secret whose label key the step registers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EntryItem {
    pub epoch: Epoch,
    pub secret: Secret32,
    pub earlier: Option<(Epoch, Secret32)>,
    pub sync: (Epoch, Secret32),
}

/// An entry box at `slot`: payload `[role, n, secret, earlier, sync]`, `earlier` `[n, secret]` or
/// `[]`, `sync` `[n, secret]` (spec/wire.md §7). Each secret must name its epoch of the slot's
/// group.
pub fn seal_entry(recipient: &KemPublicKey, slot: &BoxSlot, item: &EntryItem, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let group = slot.actor();
    let named = |e: &Epoch, s: &Secret32| e.names(group, Role::Read, s);
    if slot.key().is_some() || !named(&item.epoch, &item.secret) || item.earlier.as_ref().is_some_and(|(e, s)| !named(e, s)) || !item.sync.0.names(group, Role::Sync, &item.sync.1) {
        return Err(Error::Malformed("entry box item"));
    }
    let ad = slot.ad(BoxForm::Sealed { keyset: None, suite: u64::from(SUITE_1) })?;
    let earlier = item.earlier.iter().flat_map(|(e, s)| [Value::Int(e.n), Value::Bytes(s.expose().to_vec())]).collect();
    let sync = vec![Value::Int(item.sync.0.n), Value::Bytes(item.sync.1.expose().to_vec())];
    let value = Value::List(vec![role_value(Role::Read), Value::Int(item.epoch.n), Value::Bytes(item.secret.expose().to_vec()), Value::List(earlier), Value::List(sync)]);
    let payload = Zeroizing::new(encode(&value));
    wipe_value(value);
    seal(recipient, &ad, &payload, rng)
}

/// Opens an entry box at `slot`. Each epoch is the one its secret names under the slot's group.
pub fn open_entry(kem: &KemSecret, slot: &BoxSlot, form: BoxForm, sealed: &[u8]) -> Result<EntryItem, Error> {
    if slot.key().is_some() {
        return Err(Error::Malformed("not an entry box slot"));
    }
    match form {
        BoxForm::Sealed { keyset: None, suite, .. } if suite != u64::from(SUITE_1) => return Err(Error::UnknownSuite(suite)),
        BoxForm::Symmetric { .. } | BoxForm::Joint { .. } => return Err(Error::Malformed("entry box form")),
        BoxForm::Sealed { .. } => {}
    }
    let payload = open_sealed(kem, &slot.ad(form)?, sealed)?;
    let value = decode(&payload, &Limits::DEFAULT).map_err(|_| Error::Malformed("box payload"))?;
    let out = parse_entry_item(&value, slot.actor());
    wipe_value(value);
    out
}

fn parse_entry_item(v: &Value, group: &Tid) -> Result<EntryItem, Error> {
    let Value::List(f) = v else { return Err(Error::Malformed("box payload")) };
    let [role, n, secret, Value::List(earlier), Value::List(sync)] = f.as_slice() else { return Err(Error::Malformed("box payload")) };
    if get_role(role)? != Role::Read {
        return Err(Error::Malformed("entry box carries other than the read secret"));
    }
    let at = |r: Role, n: &Value, s: &Value| -> Result<(Epoch, Secret32), Error> {
        let s = Secret32::from_bytes(get_array(s)?);
        Ok((Epoch::derive(group, r, get_uint(n)?, &s)?, s))
    };
    let (epoch, secret) = at(Role::Read, n, secret)?;
    let earlier = match earlier.as_slice() {
        [] => None,
        [n, s] => Some(at(Role::Read, n, s)?),
        _ => return Err(Error::Malformed("box payload")),
    };
    let [n, s] = sync.as_slice() else { return Err(Error::Malformed("box payload")) };
    let sync = at(Role::Sync, n, s)?;
    Ok(EntryItem { epoch, secret, earlier, sync })
}

/// Opens a sealed-form box at `slot` with the form fields read beside it. The AD is built here,
/// so a box opens only under its own slot and form. An unknown suite parks before decryption.
/// The item's epoch is the one its secret names (spec/crypto.md §4); a `secrets.0` box whose
/// item is not its key's (role, epoch) is `Malformed`.
pub fn open_box(kem: &KemSecret, slot: &BoxSlot, form: BoxForm, sealed: &[u8]) -> Result<BoxItem, Error> {
    if slot.key().is_none() {
        return Err(Error::Malformed("an entry box is opened by open_entry"));
    }
    match form {
        BoxForm::Sealed { keyset: None, suite, .. } if suite != u64::from(SUITE_1) => return Err(Error::UnknownSuite(suite)),
        BoxForm::Symmetric { .. } | BoxForm::Joint { .. } => return Err(Error::Malformed("not the sealed form")),
        BoxForm::Sealed { .. } => {}
    }
    let payload = open_sealed(kem, &slot.ad(form)?, sealed)?;
    box_item(slot, &payload)
}

/// Joint form (spec/crypto.md §4, Seal): the sealed payload sealed to `recipients[last]`, that
/// sealed to the one before, and so on: the outermost to `recipients[0]`, all under one AD
/// naming every keyset. `recipients` are the holder's keysets ascending, at least two, each with
/// its KEM key.
pub fn seal_joint_box(recipients: &[(Epoch, &KemPublicKey)], slot: &BoxSlot, item: &BoxItem, rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let keysets: Vec<Epoch> = recipients.iter().map(|(e, _)| *e).collect();
    if !joint_keysets(&keysets) {
        return Err(Error::Malformed("joint box keysets"));
    }
    let ad = slot.ad(BoxForm::Joint { keysets: &keysets, suite: u64::from(SUITE_1) })?;
    let mut out = box_payload(slot, item)?;
    for (_, pk) in recipients.iter().rev() {
        out = Zeroizing::new(seal(pk, &ad, &out, rng)?);
    }
    Ok(out.to_vec())
}

/// Opens a joint-form box with the KEM secret of each keyset its form names, in order.
pub fn open_joint_box(kems: &[&KemSecret], slot: &BoxSlot, keysets: &[Epoch], suite: u64, sealed: &[u8]) -> Result<BoxItem, Error> {
    if suite != u64::from(SUITE_1) {
        return Err(Error::UnknownSuite(suite));
    }
    if kems.len() != keysets.len() || !joint_keysets(keysets) || slot.key().is_none() {
        return Err(Error::Malformed("joint box keysets"));
    }
    let ad = slot.ad(BoxForm::Joint { keysets, suite })?;
    let mut payload = Zeroizing::new(sealed.to_vec());
    for kem in kems {
        payload = open_sealed(kem, &ad, &payload)?;
    }
    box_item(slot, &payload)
}

/// Whether `keysets` fit a joint box: at least two, ascending.
fn joint_keysets(keysets: &[Epoch]) -> bool {
    keysets.len() >= 2 && keysets.iter().zip(keysets.iter().skip(1)).all(|(a, b)| a < b)
}

/// The sealed payload `[role, n, secret]` of `item`, checked against `slot`.
fn box_payload(slot: &BoxSlot, item: &BoxItem) -> Result<Zeroizing<Vec<u8>>, Error> {
    if slot.key().is_none() {
        return Err(Error::Malformed("an entry box is sealed by seal_entry"));
    }
    if !item.epoch.names(slot.actor(), item.role, &item.secret) {
        return Err(Error::Malformed("box item epoch"));
    }
    if slot.key().is_some_and(|k| k != (item.role, item.epoch)) {
        return Err(Error::Malformed("box carries no secret of its key"));
    }
    let value = Value::List(vec![role_value(item.role), Value::Int(item.epoch.n), Value::Bytes(item.secret.expose().to_vec())]);
    let payload = Zeroizing::new(encode(&value));
    wipe_value(value);
    Ok(payload)
}

/// The item of a `secrets.0` box's opened payload, which must name `slot`'s (role, epoch).
fn box_item(slot: &BoxSlot, payload: &[u8]) -> Result<BoxItem, Error> {
    let value = decode(payload, &Limits::DEFAULT).map_err(|_| Error::Malformed("box payload"))?;
    let out = parse_box_item(&value, slot.actor());
    wipe_value(value);
    let out = out?;
    if slot.key().is_some_and(|k| k != (out.role, out.epoch)) {
        return Err(Error::Malformed("box item does not name its key's epoch"));
    }
    Ok(out)
}

fn parse_box_item(v: &Value, actor: &Tid) -> Result<BoxItem, Error> {
    let Value::List(f) = v else { return Err(Error::Malformed("box payload")) };
    let [role, n, secret] = f.as_slice() else { return Err(Error::Malformed("box payload")) };
    let role = get_role(role)?;
    let secret = Secret32::from_bytes(get_array(secret)?);
    let epoch = Epoch::derive(actor, role, get_uint(n)?, &secret)?;
    Ok(BoxItem { role, epoch, secret })
}

/// Symmetric form at `slot`: wrap of `secret` under `kdf("box", s)`, s of epoch `epoch_s`;
/// nonce = BLAKE3(AD)[..24]. At a `secrets.0` slot, `secret` must name the key's epoch.
pub fn wrap_symmetric_box(s: &Secret32, slot: &BoxSlot, epoch_s: Epoch, secret: &Secret32) -> Result<[u8; SUITE_KEY_LEN], Error> {
    check_names(slot, secret)?;
    let ad = slot.ad(BoxForm::Symmetric { epoch_s })?;
    aead::seal_suite_key(kdf(kdf::BOX, s.expose(), b"").expose(), &ad_nonce(&ad), &ad, secret)
}

/// Opens a symmetric box; at a `secrets.0` slot a secret that does not name the key's epoch is
/// `Malformed` (spec/crypto.md §4).
pub fn open_symmetric_box(s: &Secret32, slot: &BoxSlot, epoch_s: Epoch, wrap: &[u8]) -> Result<Secret32, Error> {
    let ad = slot.ad(BoxForm::Symmetric { epoch_s })?;
    let secret = aead::open_suite_key(kdf(kdf::BOX, s.expose(), b"").expose(), &ad_nonce(&ad), &ad, wrap)?;
    check_names(slot, &secret)?;
    Ok(secret)
}

fn check_names(slot: &BoxSlot, secret: &Secret32) -> Result<(), Error> {
    match slot.key() {
        Some((r, e)) if !e.names(slot.actor(), r, secret) => Err(Error::Malformed("box secret does not name its key's epoch")),
        _ => Ok(()),
    }
}

fn ad_nonce(ad: &[u8]) -> [u8; 24] {
    let mut n = [0u8; 24];
    n.copy_from_slice(blake3::hash(ad).as_bytes().get(..24).unwrap_or(&[0; 24]));
    n
}

/// A read epoch's roles secret: `kdf("roles", s)` (spec/crypto.md §4, Roles secrets). It opens the
/// `roles.0` sections and wraps sealed under the epoch, and names the epoch as its secret does.
pub fn roles_secret(s: &Secret32) -> Secret32 {
    kdf(kdf::ROLES, s.expose(), b"")
}

/// What one history box entry holds (spec/crypto.md §4): the earlier secrets it carries, the
/// rotation's names value (osis-keys encodes it), the epoch's floor (0 at every role but read) and
/// the roles secrets of earlier epochs it carries apart from their secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub earlier: Vec<(Epoch, Secret32)>,
    pub names: Value,
    pub floor: u64,
    pub roles: Vec<(Epoch, Secret32)>,
}

/// History box (role, epoch) of `actor`: AEAD under `kdf("history", secret)`, nonce zero,
/// AD `[actor, role, n, nonce]`, plaintext `[[[n, secret]*], names, floor, [[n, roles secret]*]]`,
/// each list ascending by the epochs it names (spec/crypto.md §4, spec/wire.md §7). Repeated
/// pairs collapse, as does a roles secret of an epoch whose secret the entry carries; an epoch its
/// secret does not name, or whose n is not below `epoch`'s, is `Malformed`.
pub fn seal_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, entry: &HistoryEntry) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&(Epoch, Secret32)> = entry.earlier.iter().collect();
    sorted.sort_by_key(|(e, _)| *e);
    sorted.dedup();
    let mut roles: Vec<&(Epoch, Secret32)> = entry.roles.iter().filter(|(e, _)| !sorted.iter().any(|(x, _)| x == e)).collect();
    roles.sort_by_key(|(e, _)| *e);
    roles.dedup();
    if sorted.iter().any(|(e, s)| !e.names(actor, role, s)) || roles.iter().any(|(e, r)| !e.names_roles(actor, role, r)) {
        return Err(Error::Malformed("history epoch"));
    }
    if sorted.iter().chain(roles.iter()).any(|(e, _)| e.n >= epoch.n) {
        return Err(Error::Malformed("history epoch not earlier"));
    }
    let list = |v: &[&(Epoch, Secret32)]| Value::List(v.iter().map(|(e, s)| Value::List(vec![Value::Int(e.n), Value::Bytes(s.expose().to_vec())])).collect());
    let floor = Value::Int(i64::try_from(entry.floor).map_err(|_| Error::Malformed("history floor"))?);
    let value = Value::List(vec![list(&sorted), entry.names.clone(), floor, list(&roles)]);
    let pt = Zeroizing::new(encode(&value));
    wipe_value(value);
    aead::seal(kdf(kdf::HISTORY, secret.expose(), b"").expose(), &ZERO_NONCE, &history_ad(actor, role, epoch), &pt)
}

/// Opens a history box: each secret at the epoch it names (spec/crypto.md §4), the names value as
/// written, the floor and the roles secrets; an entry out of order, or whose n is not below
/// `epoch`'s, is `Malformed`.
pub fn open_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, ct: &[u8]) -> Result<HistoryEntry, Error> {
    let pt = Zeroizing::new(aead::open(kdf(kdf::HISTORY, secret.expose(), b"").expose(), &ZERO_NONCE, &history_ad(actor, role, epoch), ct)?);
    let value = decode(&pt, &Limits::DEFAULT).map_err(|_| Error::Malformed("history"))?;
    let Value::List(mut parts) = value else { return Err(Error::Malformed("history")) };
    let (Some(roles), Some(floor), Some(names), Some(pairs), None) = (parts.pop(), parts.pop(), parts.pop(), parts.pop(), parts.pop()) else {
        parts.into_iter().for_each(wipe_value);
        return Err(Error::Malformed("history"));
    };
    let earlier = parse_history(&pairs, actor, role, epoch, Epoch::derive);
    let roles_out = parse_history(&roles, actor, role, epoch, Epoch::derive_roles);
    wipe_value(pairs);
    wipe_value(roles);
    Ok(HistoryEntry { earlier: earlier?, names, floor: get_uint(&floor)?, roles: roles_out? })
}

/// A list of `[n, secret]` pairs, each naming its epoch by `derive`.
fn parse_history(v: &Value, actor: &Tid, role: Role, epoch: &Epoch, derive: fn(&Tid, Role, u64, &Secret32) -> Result<Epoch, Error>) -> Result<Vec<(Epoch, Secret32)>, Error> {
    let Value::List(items) = v else { return Err(Error::Malformed("history")) };
    let mut out: Vec<(Epoch, Secret32)> = Vec::with_capacity(items.len());
    for item in items {
        let Value::List(f) = item else { return Err(Error::Malformed("history item")) };
        let [n, s] = f.as_slice() else { return Err(Error::Malformed("history item")) };
        let s = Secret32::from_bytes(get_array(s)?);
        let e = derive(actor, role, get_uint(n)?, &s)?;
        if out.last().is_some_and(|(prev, _)| *prev >= e) {
            return Err(Error::Malformed("history order"));
        }
        if e.n >= epoch.n {
            return Err(Error::Malformed("history epoch not earlier"));
        }
        out.push((e, s));
    }
    Ok(out)
}

fn history_ad(actor: &Tid, role: Role, epoch: &Epoch) -> Vec<u8> {
    encode(&Value::List(vec![tid(actor), role_value(role), Value::Int(epoch.n), Value::Bytes(epoch.nonce.to_vec())]))
}

/// Wipes the byte strings of a box or history payload value.
fn wipe_value(v: Value) {
    match v {
        Value::Bytes(b) => drop(Zeroizing::new(b)),
        Value::List(items) => items.into_iter().for_each(wipe_value),
        _ => {}
    }
}

// Structure encodings (spec/wire.md §1).
fn tid(t: &Tid) -> Value {
    Value::bytes(t.as_bytes())
}

/// `TooLarge` above `i64::MAX` (the int range).
fn uint(n: u64) -> Result<Value, Error> {
    Value::try_uint(n).ok_or(Error::TooLarge)
}

pub(crate) fn role_value(r: Role) -> Value {
    Value::Int(i64::from(role_byte(r)))
}

fn role_byte(r: Role) -> u8 {
    r.id()
}

fn get_role(v: &Value) -> Result<Role, Error> {
    v.as_uint().and_then(Role::from_id).ok_or(Error::Malformed("role"))
}

fn get_uint(v: &Value) -> Result<u64, Error> {
    v.as_uint().ok_or(Error::Malformed("not a uint"))
}

fn get_array<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    v.as_array().ok_or(Error::Malformed("not a byte string of its length"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeededRng;

    fn actor(b: u8) -> Tid {
        Tid::from_bytes([b; 15])
    }

    fn sec(b: u8) -> Secret32 {
        Secret32::from_bytes([b; 32])
    }

    /// Epoch n of actor 1's `role` with secret `sec(b)`.
    fn ep(role: Role, n: u64, b: u8) -> Epoch {
        Epoch::derive(&actor(1), role, n, &sec(b)).unwrap()
    }

    fn slot(a: u8, holder: u8, role: Role, epoch: Epoch) -> BoxSlot {
        BoxSlot::Secrets { actor: actor(a), holder: actor(holder), role, epoch }
    }

    // spec/crypto.md §4: the nonce rule binds the secret (through its roles secret), actor, role
    // and n.
    #[test]
    fn nonce_rule() {
        let e = ep(Role::Read, 3, 1);
        assert_eq!(e.n(), 3);
        let mut input = actor(1).as_bytes().to_vec();
        input.push(0);
        input.extend(3u64.to_le_bytes());
        let roles = kdf(kdf::ROLES, sec(1).expose(), b"");
        assert_eq!(roles, roles_secret(&sec(1)));
        assert_eq!(e.nonce(), kdf(kdf::EPOCH, roles.expose(), &input).expose());
        assert!(e.names_roles(&actor(1), Role::Read, &roles));
        assert!(e.names(&actor(1), Role::Read, &sec(1)));
        for other in [ep(Role::Read, 3, 2), ep(Role::Write, 3, 1), ep(Role::Read, 4, 1), Epoch::derive(&actor(2), Role::Read, 3, &sec(1)).unwrap()] {
            assert_ne!(other.nonce(), e.nonce());
        }
        assert!(!e.names(&actor(1), Role::Read, &sec(2)));
        assert_eq!(Epoch::derive(&actor(1), Role::Read, u64::MAX, &sec(1)), Err(Error::TooLarge));
    }

    // spec/crypto.md §4 (Seal), spec/wire.md §7: a joint box opens only with the KEM secret of
    // every keyset it names, in order; its AD binds the keysets.
    #[test]
    fn joint_box() {
        let mut rng = SeededRng::from_u64(0);
        let (k1, k2) = (KemSecret::derive(&sec(0x31)), KemSecret::derive(&sec(0x32)));
        let (e1, e2) = (ep(Role::Read, 3, 0x31), ep(Role::Read, 3, 0x32));
        let (e1, e2, k1, k2) = if e1 < e2 { (e1, e2, k1, k2) } else { (e2, e1, k2, k1) };
        let ew = ep(Role::Write, 4, 9);
        let at = slot(1, 2, Role::Write, ew);
        let item = BoxItem { role: Role::Write, epoch: ew, secret: sec(9) };
        let b = seal_joint_box(&[(e1, k1.public()), (e2, k2.public())], &at, &item, &mut rng).unwrap();
        assert_eq!(open_joint_box(&[&k1, &k2], &at, &[e1, e2], 1, &b).unwrap(), item);
        assert!(open_joint_box(&[&k2, &k1], &at, &[e1, e2], 1, &b).is_err(), "out of order");
        assert!(open_joint_box(&[&k1, &k1], &at, &[e1, e2], 1, &b).is_err(), "one keyset's secret only");
        assert!(open_joint_box(&[&k1], &at, &[e1], 1, &b).is_err());
        assert!(open_box(&k1, &at, BoxForm::Sealed { keyset: Some(e1), suite: 1 }, &b).is_err(), "not a sealed box to one keyset");
        assert!(seal_joint_box(&[(e2, k2.public()), (e1, k1.public())], &at, &item, &mut rng).is_err(), "keysets ascending");
        assert!(seal_joint_box(&[(e1, k1.public())], &at, &item, &mut rng).is_err(), "at least two");
    }

    // spec/wire.md §7: sealed secrets.0 box round trip; AD binds actor, holder, role, epoch, form;
    // the item names its key's epoch.
    #[test]
    fn sealed_box() {
        let mut rng = SeededRng::from_u64(0);
        let kem = KemSecret::derive(&sec(0x31));
        let ew = ep(Role::Write, 4, 9);
        let at = slot(1, 2, Role::Write, ew);
        let ks = ep(Role::Read, 3, 0x30);
        let form = BoxForm::Sealed { keyset: Some(ks), suite: 1 };
        let item = BoxItem { role: Role::Write, epoch: ew, secret: sec(9) };
        let b = seal_box(kem.public(), &at, Some(ks), &item, &mut rng).unwrap();
        assert_eq!(open_box(&kem, &at, form, &b).unwrap(), item);
        for other in [slot(2, 2, Role::Write, ew), slot(1, 1, Role::Write, ew), slot(1, 2, Role::Admin, ew), slot(1, 2, Role::Write, ep(Role::Write, 5, 9))] {
            assert_eq!(open_box(&kem, &other, form, &b), Err(Error::Decrypt));
        }
        // A mismatched form cannot authenticate: the AD is built from the form given.
        for wrong in [BoxForm::Sealed { keyset: None, suite: 1 }, BoxForm::Sealed { keyset: Some(ep(Role::Read, 2, 0x30)), suite: 1 }] {
            assert_eq!(open_box(&kem, &at, wrong, &b), Err(Error::Decrypt));
        }
        assert!(open_box(&kem, &at, BoxForm::Symmetric { epoch_s: ks }, &b).is_err());
        let parked = BoxForm::Sealed { keyset: None, suite: 2 };
        assert_eq!(open_box(&kem, &at, parked, &b), Err(Error::UnknownSuite(2)));
        // An item at an epoch its secret does not name, or other than the box's key, is not
        // sealed.
        let lie = BoxItem { role: Role::Write, epoch: ew, secret: sec(7) };
        assert_eq!(seal_box(kem.public(), &at, None, &lie, &mut rng), Err(Error::Malformed("box item epoch")));
        let other = BoxItem { role: Role::Read, epoch: ep(Role::Read, 2, 8), secret: sec(8) };
        assert_eq!(seal_box(kem.public(), &at, None, &other, &mut rng), Err(Error::Malformed("box carries no secret of its key")));
    }

    // spec/crypto.md §4: a box whose item names another epoch than its key's is refused on
    // open (built by hand: the payload names n, the reader recomputes the epoch).
    #[test]
    fn lying_box_refused() {
        let mut rng = SeededRng::from_u64(0);
        let kem = KemSecret::derive(&sec(0x31));
        let at = slot(1, 2, Role::Read, ep(Role::Read, 4, 9));
        let ad = at.ad(BoxForm::Sealed { keyset: None, suite: 1 }).unwrap();
        let payload = encode(&Value::List(vec![Value::Int(0), Value::Int(4), Value::Bytes(vec![7; 32])]));
        let b = seal(kem.public(), &ad, &payload, &mut rng).unwrap();
        assert_eq!(open_box(&kem, &at, BoxForm::Sealed { keyset: None, suite: 1 }, &b), Err(Error::Malformed("box item does not name its key's epoch")));
    }

    // spec/wire.md §7, spec/sync-ids.md §3: an entry box names epochs of the group, with or without the earlier secret; a box of the wrong payload or slot, a write secret, or a secret its epoch does not name, stays shut
    #[test]
    fn entry_box_round_trip() {
        let mut rng = SeededRng::from_u64(0);
        let kem = KemSecret::derive(&sec(0x31));
        let g = actor(5);
        let entry = BoxSlot::Entry { label: LabelId([3; 16]), step_key: [5; 32], group: g };
        let form = BoxForm::Sealed { keyset: None, suite: 1 };
        let read = |n, s: u8| Epoch::derive(&g, Role::Read, n, &sec(s)).unwrap();
        let sync = (Epoch::derive(&g, Role::Sync, 4, &sec(6)).unwrap(), sec(6));
        let bare = EntryItem { epoch: read(4, 7), secret: sec(7), earlier: None, sync: sync.clone() };
        let both = EntryItem { earlier: Some((read(3, 8), sec(8))), ..bare.clone() };
        for i in [&bare, &both] {
            let b = seal_entry(kem.public(), &entry, i, &mut rng).unwrap();
            assert_eq!(&open_entry(&kem, &entry, form, &b).unwrap(), i);
            assert!(open_box(&kem, &entry, form, &b).is_err());
        }
        let lying = EntryItem { earlier: Some((read(3, 8), sec(9))), ..bare.clone() };
        assert_eq!(seal_entry(kem.public(), &entry, &lying, &mut rng), Err(Error::Malformed("entry box item")));
        let read_as_sync = EntryItem { sync: (read(4, 7), sec(7)), ..bare.clone() };
        assert_eq!(seal_entry(kem.public(), &entry, &read_as_sync, &mut rng), Err(Error::Malformed("entry box item")), "the sync secret names a sync epoch");
        assert!(seal_entry(kem.public(), &slot(1, 2, Role::Read, read(4, 7)), &bare, &mut rng).is_err());
        let ad = entry.ad(form).unwrap();
        let s = || Value::List(vec![Value::Int(4), Value::Bytes(vec![6; 32])]);
        for v in [vec![Value::Int(0), Value::Int(4), Value::Bytes(vec![7; 32]), Value::List(vec![])], vec![Value::Int(1), Value::Int(4), Value::Bytes(vec![7; 32]), Value::List(vec![]), s()], vec![Value::Int(0), Value::Int(4), Value::Bytes(vec![7; 32]), Value::List(vec![Value::Int(3)]), s()]] {
            let b = seal(kem.public(), &ad, &encode(&Value::List(v)), &mut rng).unwrap();
            assert!(open_entry(&kem, &entry, form, &b).is_err());
        }
    }

    // spec/wire.md §7: AD layout `[actor, holder, role, n, nonce, [0, Opt(epoch), suite]]`;
    // spec/wire.md §1: ints beyond i64 are not encodable.
    #[test]
    fn ad_layout() {
        let e = Epoch::new(4, [4; 32]).unwrap();
        let ad = slot(1, 2, Role::Admin, e).ad(BoxForm::Sealed { keyset: None, suite: 1 }).unwrap();
        let mut expect = vec![0x86, 0x4f];
        expect.extend([1; 15]);
        expect.push(0x4f);
        expect.extend([2; 15]);
        expect.extend([0x02, 0x04, 0x58, 0x20]);
        expect.extend([4; 32]);
        expect.extend([0x83, 0x00, 0x80, 0x01]);
        assert_eq!(ad, expect);
        let entry = BoxSlot::Entry { label: LabelId([3; 16]), step_key: [5; 32], group: actor(9) };
        let sym = entry.ad(BoxForm::Symmetric { epoch_s: Epoch::new(1, [1; 32]).unwrap() }).unwrap();
        assert_eq!(sym[..2], [0x83, 0x50]);
        assert_eq!(sym[sym.len() - 38..sym.len() - 33], [0x82, 0x01, 0x82, 0x01, 0x58]);
        assert_eq!(entry.ad(BoxForm::Sealed { keyset: None, suite: u64::MAX }), Err(Error::TooLarge));
    }

    // spec/wire.md §7: symmetric form is deterministic, binds its slot and epoch of s, fails
    // under another s, and its secret names the key's epoch.
    #[test]
    fn symmetric_box() {
        let s = sec(4);
        let at = slot(1, 2, Role::Read, ep(Role::Read, 1, 6));
        let es = Epoch::new(7, [7; 32]).unwrap();
        let w = wrap_symmetric_box(&s, &at, es, &sec(6)).unwrap();
        assert_eq!(w, wrap_symmetric_box(&s, &at, es, &sec(6)).unwrap());
        assert_eq!(open_symmetric_box(&s, &at, es, &w), Ok(sec(6)));
        assert_eq!(open_symmetric_box(&sec(5), &at, es, &w), Err(Error::Decrypt));
        assert_eq!(open_symmetric_box(&s, &slot(1, 2, Role::Write, ep(Role::Read, 1, 6)), es, &w), Err(Error::Decrypt));
        assert_eq!(open_symmetric_box(&s, &at, Epoch::new(6, [7; 32]).unwrap(), &w), Err(Error::Decrypt));
        assert!(open_symmetric_box(&s, &at, es, &w[..48]).is_err());
        assert!(wrap_symmetric_box(&s, &at, es, &sec(7)).is_err());
        // a wrap of another secret under this key (built by hand) is refused
        let ad = at.ad(BoxForm::Symmetric { epoch_s: es }).unwrap();
        let lie = aead::seal_suite_key(kdf(kdf::BOX, s.expose(), b"").expose(), &ad_nonce(&ad), &ad, &sec(7)).unwrap();
        assert!(matches!(open_symmetric_box(&s, &at, es, &lie), Err(Error::Malformed(_))));
    }

    /// A names value (osis-keys encodes them; opaque here).
    fn names() -> Value {
        Value::List(vec![Value::List(vec![]), Value::Bool(true)])
    }

    fn entry(earlier: &[(Epoch, Secret32)]) -> HistoryEntry {
        HistoryEntry { earlier: earlier.to_vec(), names: names(), floor: 0, roles: Vec::new() }
    }

    // spec/crypto.md §4: a history box under the new secret opens every distinct earlier one,
    // sorted, each at the epoch it names, and the roles secrets it carries apart; another role or
    // epoch does not open it.
    #[test]
    fn history_box() {
        let s = sec(1);
        let a = actor(1);
        let e3 = ep(Role::Read, 3, 1);
        let earlier = vec![(ep(Role::Read, 2, 2), sec(2)), (ep(Role::Read, 1, 3), sec(3)), (ep(Role::Read, 2, 2), sec(2))];
        let ct = seal_history(&s, &a, Role::Read, &e3, &entry(&earlier)).unwrap();
        let got = open_history(&s, &a, Role::Read, &e3, &ct).unwrap();
        assert_eq!(got, entry(&[earlier[1].clone(), earlier[0].clone()]));
        assert_eq!(open_history(&s, &a, Role::Write, &e3, &ct), Err(Error::Decrypt));
        assert_eq!(open_history(&s, &a, Role::Read, &ep(Role::Read, 4, 1), &ct), Err(Error::Decrypt));
        let e1 = ep(Role::Read, 1, 1);
        let empty = seal_history(&s, &a, Role::Read, &e1, &entry(&[])).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &e1, &empty), Ok(entry(&[])));
        // Forks: one n, two secrets, both kept.
        let fork = [(ep(Role::Read, 2, 2), sec(2)), (ep(Role::Read, 2, 4), sec(4))];
        let ct = seal_history(&s, &a, Role::Read, &e3, &entry(&fork)).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &e3, &ct).unwrap().earlier.len(), 2);
        // roles secrets name their epochs alike; one of an epoch whose secret it carries collapses
        let (e2, e1b) = (ep(Role::Read, 2, 2), ep(Role::Read, 1, 3));
        let roles = vec![(e2, roles_secret(&sec(2))), (e1b, roles_secret(&sec(3)))];
        let ct = seal_history(&s, &a, Role::Read, &e3, &HistoryEntry { roles: roles.clone(), ..entry(&[(e2, sec(2))]) }).unwrap();
        let got = open_history(&s, &a, Role::Read, &e3, &ct).unwrap();
        assert_eq!((got.earlier, got.roles), (vec![(e2, sec(2))], vec![roles[1].clone()]));
        assert!(e2.names_roles(&a, Role::Read, &roles_secret(&sec(2))) && !e2.names_roles(&a, Role::Read, &sec(2)));
    }

    // spec/crypto.md §4: a history box lists only earlier epochs, each the one its secret names.
    #[test]
    fn history_rejections() {
        let s = sec(1);
        let a = actor(1);
        let e3 = ep(Role::Read, 3, 1);
        let lie = [(ep(Role::Read, 1, 2), sec(3))];
        assert_eq!(seal_history(&s, &a, Role::Read, &e3, &entry(&lie)), Err(Error::Malformed("history epoch")));
        let lie_roles = HistoryEntry { roles: vec![(ep(Role::Read, 1, 2), sec(2))], ..entry(&[]) };
        assert_eq!(seal_history(&s, &a, Role::Read, &e3, &lie_roles), Err(Error::Malformed("history epoch")));
        for late in [ep(Role::Read, 3, 2), ep(Role::Read, 4, 2)] {
            assert!(seal_history(&s, &a, Role::Read, &e3, &entry(&[(late, sec(2))])).is_err());
        }
        // A box listing its own n (built by hand) is rejected on open; so is one out of order.
        let key = kdf(kdf::HISTORY, s.expose(), b"");
        let item = |n: i64, b: u8| Value::List(vec![Value::Int(n), Value::Bytes(vec![b; 32])]);
        let none = Value::List(vec![]);
        let pt = encode(&Value::List(vec![Value::List(vec![item(3, 2)]), names(), Value::Int(0), none.clone()]));
        let ct = aead::seal(key.expose(), &ZERO_NONCE, &history_ad(&a, Role::Read, &e3), &pt).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &e3, &ct), Err(Error::Malformed("history epoch not earlier")));
        let pt = encode(&Value::List(vec![Value::List(vec![item(2, 2), item(1, 3)]), names(), Value::Int(0), none.clone()]));
        let ct = aead::seal(key.expose(), &ZERO_NONCE, &history_ad(&a, Role::Read, &e3), &pt).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &e3, &ct), Err(Error::Malformed("history order")));
        let pt = encode(&Value::List(vec![none.clone(), names(), Value::Int(0), Value::List(vec![item(3, 2)])]));
        let ct = aead::seal(key.expose(), &ZERO_NONCE, &history_ad(&a, Role::Read, &e3), &pt).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &e3, &ct), Err(Error::Malformed("history epoch not earlier")));
        // the plaintext is exactly [pairs, names, floor, roles]
        for pt in [Value::List(vec![item(1, 3)]), Value::List(vec![none.clone(), names(), Value::Int(0)])] {
            let ct = aead::seal(key.expose(), &ZERO_NONCE, &history_ad(&a, Role::Read, &e3), &encode(&pt)).unwrap();
            assert_eq!(open_history(&s, &a, Role::Read, &e3, &ct), Err(Error::Malformed("history")));
        }
    }

    // spec/wire.md §1: epochs are `[n, nonce]` with n in the int range and a 32-byte nonce.
    #[test]
    fn epoch_wire() {
        let e = ep(Role::Read, 9, 1);
        assert_eq!(Epoch::from_wire(&e.to_wire()), Ok(e));
        assert_eq!(Epoch::new(u64::MAX, [0; 32]), Err(Error::TooLarge));
        assert_eq!(Epoch::new(i64::MAX as u64, [0; 32]).unwrap().n(), i64::MAX as u64);
        assert!(Epoch::from_wire(&Value::List(vec![Value::Int(-1), Value::Bytes(vec![0; 32])])).is_err());
        assert!(Epoch::from_wire(&Value::List(vec![Value::Int(1), Value::Bytes(vec![0; 16])])).is_err());
        assert!(Epoch::new(1, [9; 32]).unwrap() < Epoch::new(2, [0; 32]).unwrap() && Epoch::new(1, [0; 32]).unwrap() < Epoch::new(1, [1; 32]).unwrap());
    }
}
