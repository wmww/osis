//! `/secrets` boxes, entry boxes and history boxes (spec/crypto.md §4, spec/wire.md §7).
//! The `box` value itself (spec/data-model.md §9) is osis-keys'; this module builds the AD
//! tuples and seals, wraps and opens the payloads.

use crate::aead::{self, WRAP_LEN, ZERO_NONCE};
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
    nonce: [u8; 16],
}

impl Epoch {
    /// `(0, 16 zero bytes)`: the fixed epoch of a key actor's role secrets (spec/crypto.md §3).
    pub const ZERO: Epoch = Epoch { n: 0, nonce: [0; 16] };

    /// `TooLarge` above `i64::MAX`.
    pub fn new(n: u64, nonce: [u8; 16]) -> Result<Epoch, Error> {
        Ok(Epoch { n: i64::try_from(n).map_err(|_| Error::TooLarge)?, nonce })
    }
    pub fn n(&self) -> u64 {
        self.n.unsigned_abs()
    }
    pub fn nonce(&self) -> &[u8; 16] {
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
pub enum BoxForm {
    /// To the member's KEM key of the keyset `keyset` (none for a key actor), under `suite`.
    Sealed { keyset: Option<Epoch>, suite: u64 },
    /// Wrap under `kdf("box", s)`, s the member's own secret of epoch `epoch_s`.
    Symmetric { epoch_s: Epoch },
}

impl BoxForm {
    fn to_wire(self) -> Result<Value, Error> {
        Ok(match self {
            BoxForm::Sealed { keyset, suite } => {
                Value::List(vec![Value::Int(0), Value::List(keyset.iter().map(Epoch::to_wire).collect()), uint(suite)?])
            }
            BoxForm::Symmetric { epoch_s } => Value::List(vec![Value::Int(1), epoch_s.to_wire()]),
        })
    }
}

/// Where a box sits: the AD fields before the form (spec/wire.md §7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoxSlot {
    /// A `/secrets` box of `actor` to `member` for (role, epoch).
    Secrets { actor: Tid, member: Tid, role: Role, epoch: Epoch },
    /// An entry box of a label step.
    Entry { label: LabelId, step_key: [u8; 32] },
}

impl BoxSlot {
    /// AD `[actor, member, role, n, nonce, form]` or `[label_id, step_key, form]`.
    pub fn ad(&self, form: BoxForm) -> Result<Vec<u8>, Error> {
        let form = form.to_wire()?;
        Ok(encode(&Value::List(match self {
            BoxSlot::Secrets { actor, member, role, epoch } => {
                vec![tid(actor), tid(member), role_value(*role), Value::Int(epoch.n), Value::Bytes(epoch.nonce.to_vec()), form]
            }
            BoxSlot::Entry { label, step_key } => vec![Value::Bytes(label.0.to_vec()), Value::Bytes(step_key.to_vec()), form],
        })))
    }
}

/// One role secret carried by a box.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoxItem {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
}

/// Sealed form `[[role, n, nonce, secret]+]` ascending by role, to `recipient` (the KEM key of
/// keyset `keyset`, none for a key actor) under suite 1. Returns the raw sealed box.
pub fn seal_box(recipient: &KemPublicKey, slot: &BoxSlot, keyset: Option<Epoch>, items: &[BoxItem], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&BoxItem> = items.iter().collect();
    sorted.sort_by_key(|i| i.role);
    if sorted.is_empty() || sorted.windows(2).any(|w| w.first().map(|a| a.role) == w.get(1).map(|b| b.role)) {
        return Err(Error::Malformed("box items"));
    }
    let ad = slot.ad(BoxForm::Sealed { keyset, suite: u64::from(SUITE_1) })?;
    let value = Value::List(
        sorted
            .iter()
            .map(|i| {
                Value::List(vec![role_value(i.role), Value::Int(i.epoch.n), Value::Bytes(i.epoch.nonce.to_vec()), Value::Bytes(i.secret.expose().to_vec())])
            })
            .collect(),
    );
    let payload = Zeroizing::new(encode(&value));
    wipe_value(value);
    seal(recipient, &ad, &payload, rng)
}

/// Opens a sealed-form box at `slot` with the form fields read beside it. The AD is built here,
/// so a box opens only under its own slot and form. An unknown suite parks before decryption.
pub fn open_box(kem: &KemSecret, slot: &BoxSlot, form: BoxForm, sealed: &[u8]) -> Result<Vec<BoxItem>, Error> {
    match form {
        BoxForm::Sealed { suite, .. } if suite != u64::from(SUITE_1) => return Err(Error::UnknownSuite(suite)),
        BoxForm::Symmetric { .. } => return Err(Error::Malformed("symmetric form is not sealed")),
        BoxForm::Sealed { .. } => {}
    }
    let payload = open_sealed(kem, &slot.ad(form)?, sealed)?;
    let value = decode(&payload, &Limits::DEFAULT).map_err(|_| Error::Malformed("box payload"))?;
    let out = parse_box_items(&value);
    wipe_value(value);
    out
}

fn parse_box_items(v: &Value) -> Result<Vec<BoxItem>, Error> {
    let Value::List(items) = v else { return Err(Error::Malformed("box payload")) };
    let mut out: Vec<BoxItem> = Vec::with_capacity(items.len());
    for item in items {
        let Value::List(f) = item else { return Err(Error::Malformed("box item")) };
        let [role, n, nonce, secret] = f.as_slice() else { return Err(Error::Malformed("box item")) };
        let role = get_role(role)?;
        if out.last().is_some_and(|prev| prev.role >= role) {
            return Err(Error::Malformed("box item order"));
        }
        let epoch = Epoch::new(get_uint(n)?, get_array(nonce)?)?;
        out.push(BoxItem { role, epoch, secret: Secret32::from_bytes(get_array(secret)?) });
    }
    if out.is_empty() {
        return Err(Error::Malformed("empty box"));
    }
    Ok(out)
}

/// Symmetric form at `slot`: wrap of `secret` under `kdf("box", s)`, s of epoch `epoch_s`;
/// nonce = BLAKE3(AD)[..24].
pub fn wrap_symmetric_box(s: &Secret32, slot: &BoxSlot, epoch_s: Epoch, secret: &Secret32) -> Result<[u8; WRAP_LEN], Error> {
    let ad = slot.ad(BoxForm::Symmetric { epoch_s })?;
    aead::seal_suite_key(kdf(kdf::BOX, s.expose(), b"").expose(), &ad_nonce(&ad), &ad, secret)
}

pub fn open_symmetric_box(s: &Secret32, slot: &BoxSlot, epoch_s: Epoch, wrap: &[u8]) -> Result<Secret32, Error> {
    let ad = slot.ad(BoxForm::Symmetric { epoch_s })?;
    aead::open_suite_key(kdf(kdf::BOX, s.expose(), b"").expose(), &ad_nonce(&ad), &ad, wrap)
}

fn ad_nonce(ad: &[u8]) -> [u8; 24] {
    let mut n = [0u8; 24];
    n.copy_from_slice(blake3::hash(ad).as_bytes().get(..24).unwrap_or(&[0; 24]));
    n
}

/// History box (role, epoch) of `actor`: AEAD under `kdf("history", secret)`, nonce zero,
/// AD `[actor, role, n, nonce]`, plaintext `[[n, nonce, secret]*]` ascending by epoch. Repeated
/// pairs collapse; two secrets at one epoch, or an epoch whose n is not below `epoch`'s, are
/// `Malformed`.
pub fn seal_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, earlier: &[(Epoch, Secret32)]) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&(Epoch, Secret32)> = earlier.iter().collect();
    sorted.sort_by_key(|(e, _)| *e);
    sorted.dedup();
    if sorted.windows(2).any(|w| w.first().map(|p| p.0) == w.get(1).map(|p| p.0)) {
        return Err(Error::Malformed("two secrets at one epoch"));
    }
    if sorted.iter().any(|(e, _)| e.n >= epoch.n) {
        return Err(Error::Malformed("history epoch not earlier"));
    }
    let value = Value::List(
        sorted.iter().map(|(e, s)| Value::List(vec![Value::Int(e.n), Value::Bytes(e.nonce.to_vec()), Value::Bytes(s.expose().to_vec())])).collect(),
    );
    let pt = Zeroizing::new(encode(&value));
    wipe_value(value);
    aead::seal(kdf(kdf::HISTORY, secret.expose(), b"").expose(), &ZERO_NONCE, &history_ad(actor, role, epoch), &pt)
}

/// Opens a history box; an entry out of order, or whose n is not below `epoch`'s, is `Malformed`.
pub fn open_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, ct: &[u8]) -> Result<Vec<(Epoch, Secret32)>, Error> {
    let pt = Zeroizing::new(aead::open(kdf(kdf::HISTORY, secret.expose(), b"").expose(), &ZERO_NONCE, &history_ad(actor, role, epoch), ct)?);
    let value = decode(&pt, &Limits::DEFAULT).map_err(|_| Error::Malformed("history"))?;
    let out = parse_history(&value, epoch);
    wipe_value(value);
    out
}

fn parse_history(v: &Value, epoch: &Epoch) -> Result<Vec<(Epoch, Secret32)>, Error> {
    let Value::List(items) = v else { return Err(Error::Malformed("history")) };
    let mut out: Vec<(Epoch, Secret32)> = Vec::with_capacity(items.len());
    for item in items {
        let Value::List(f) = item else { return Err(Error::Malformed("history item")) };
        let [n, nonce, s] = f.as_slice() else { return Err(Error::Malformed("history item")) };
        let e = Epoch::new(get_uint(n)?, get_array(nonce)?)?;
        if out.last().is_some_and(|(prev, _)| *prev >= e) {
            return Err(Error::Malformed("history order"));
        }
        if e.n >= epoch.n {
            return Err(Error::Malformed("history epoch not earlier"));
        }
        out.push((e, Secret32::from_bytes(get_array(s)?)));
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
    Value::Bytes(t.as_bytes().to_vec())
}

/// `TooLarge` above `i64::MAX` (the int range).
fn uint(n: u64) -> Result<Value, Error> {
    Ok(Value::Int(i64::try_from(n).map_err(|_| Error::TooLarge)?))
}

pub(crate) fn role_value(r: Role) -> Value {
    Value::Int(match r {
        Role::Read => 0,
        Role::Write => 1,
        Role::Admin => 2,
    })
}

fn get_role(v: &Value) -> Result<Role, Error> {
    match v {
        Value::Int(0) => Ok(Role::Read),
        Value::Int(1) => Ok(Role::Write),
        Value::Int(2) => Ok(Role::Admin),
        _ => Err(Error::Malformed("role")),
    }
}

fn get_uint(v: &Value) -> Result<u64, Error> {
    match v {
        Value::Int(n) => u64::try_from(*n).map_err(|_| Error::Malformed("negative int")),
        _ => Err(Error::Malformed("not an int")),
    }
}

fn get_array<const N: usize>(v: &Value) -> Result<[u8; N], Error> {
    match v {
        Value::Bytes(b) => b.as_slice().try_into().map_err(|_| Error::Malformed("byte string length")),
        _ => Err(Error::Malformed("not a byte string")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeededRng;

    fn epoch(n: u64) -> Epoch {
        Epoch::new(n, [n as u8; 16]).unwrap()
    }

    fn slot(actor: u8, member: u8, role: Role, n: u64) -> BoxSlot {
        BoxSlot::Secrets { actor: Tid::from_bytes([actor; 15]), member: Tid::from_bytes([member; 15]), role, epoch: epoch(n) }
    }

    // spec/wire.md §7: sealed /secrets box round trip; AD binds actor, member, role, epoch, form.
    #[test]
    fn sealed_box() {
        let mut rng = SeededRng::from_u64(2);
        let kem = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let at = slot(1, 2, Role::Write, 4);
        let form = BoxForm::Sealed { keyset: Some(epoch(3)), suite: 1 };
        let items = vec![
            BoxItem { role: Role::Write, epoch: epoch(4), secret: Secret32::from_bytes([9; 32]) },
            BoxItem { role: Role::Read, epoch: epoch(2), secret: Secret32::from_bytes([8; 32]) },
        ];
        let b = seal_box(kem.public(), &at, Some(epoch(3)), &items, &mut rng).unwrap();
        assert_eq!(open_box(&kem, &at, form, &b).unwrap(), vec![items[1].clone(), items[0].clone()]);
        for other in [slot(2, 2, Role::Write, 4), slot(1, 1, Role::Write, 4), slot(1, 2, Role::Admin, 4), slot(1, 2, Role::Write, 5)] {
            assert_eq!(open_box(&kem, &other, form, &b), Err(Error::Decrypt));
        }
        // A mismatched form cannot authenticate: the AD is built from the form given.
        for wrong in [BoxForm::Sealed { keyset: None, suite: 1 }, BoxForm::Sealed { keyset: Some(epoch(2)), suite: 1 }] {
            assert_eq!(open_box(&kem, &at, wrong, &b), Err(Error::Decrypt));
        }
        assert!(open_box(&kem, &at, BoxForm::Symmetric { epoch_s: epoch(3) }, &b).is_err());
        let parked = BoxForm::Sealed { keyset: None, suite: 2 };
        assert_eq!(open_box(&kem, &at, parked, &b), Err(Error::UnknownSuite(2)));
        let dup = vec![items[0].clone(), items[0].clone()];
        assert!(seal_box(kem.public(), &at, None, &dup, &mut rng).is_err());
        assert!(seal_box(kem.public(), &at, None, &[], &mut rng).is_err());
    }

    // spec/wire.md §7: AD layout `[actor, member, role, n, nonce, [0, Opt(epoch), suite]]`;
    // spec/wire.md §1: ints beyond i64 are not encodable.
    #[test]
    fn ad_layout() {
        let ad = slot(1, 2, Role::Admin, 4).ad(BoxForm::Sealed { keyset: None, suite: 1 }).unwrap();
        let mut expect = vec![0x86, 0x4f];
        expect.extend([1; 15]);
        expect.push(0x4f);
        expect.extend([2; 15]);
        expect.extend([0x02, 0x04, 0x50]);
        expect.extend([4; 16]);
        expect.extend([0x83, 0x00, 0x80, 0x01]);
        assert_eq!(ad, expect);
        let entry = BoxSlot::Entry { label: LabelId([3; 16]), step_key: [5; 32] };
        let sym = entry.ad(BoxForm::Symmetric { epoch_s: epoch(1) }).unwrap();
        assert_eq!(sym[..2], [0x83, 0x50]);
        assert_eq!(sym[sym.len() - 21..sym.len() - 17], [0x82, 0x01, 0x82, 0x01]);
        assert_eq!(entry.ad(BoxForm::Sealed { keyset: None, suite: u64::MAX }), Err(Error::TooLarge));
    }

    // spec/wire.md §7: symmetric form is deterministic, binds its slot and epoch of s, and fails
    // under another s.
    #[test]
    fn symmetric_box() {
        let s = Secret32::from_bytes([4; 32]);
        let at = slot(1, 2, Role::Read, 1);
        let secret = Secret32::from_bytes([6; 32]);
        let w = wrap_symmetric_box(&s, &at, epoch(7), &secret).unwrap();
        assert_eq!(w, wrap_symmetric_box(&s, &at, epoch(7), &secret).unwrap());
        assert_eq!(open_symmetric_box(&s, &at, epoch(7), &w), Ok(secret));
        assert_eq!(open_symmetric_box(&Secret32::from_bytes([5; 32]), &at, epoch(7), &w), Err(Error::Decrypt));
        assert_eq!(open_symmetric_box(&s, &slot(1, 2, Role::Write, 1), epoch(7), &w), Err(Error::Decrypt));
        assert_eq!(open_symmetric_box(&s, &at, epoch(6), &w), Err(Error::Decrypt));
        assert!(open_symmetric_box(&s, &at, epoch(7), &w[..48]).is_err());
    }

    // spec/crypto.md §4: a history box under the new secret opens every distinct earlier one,
    // sorted; another role or epoch does not open it.
    #[test]
    fn history_box() {
        let s = Secret32::from_bytes([1; 32]);
        let a = Tid::from_bytes([1; 15]);
        let earlier = vec![(epoch(2), Secret32::from_bytes([2; 32])), (epoch(1), Secret32::from_bytes([3; 32])), (epoch(2), Secret32::from_bytes([2; 32]))];
        let ct = seal_history(&s, &a, Role::Read, &epoch(3), &earlier).unwrap();
        let got = open_history(&s, &a, Role::Read, &epoch(3), &ct).unwrap();
        assert_eq!(got, vec![earlier[1].clone(), earlier[0].clone()]);
        assert_eq!(open_history(&s, &a, Role::Write, &epoch(3), &ct), Err(Error::Decrypt));
        assert_eq!(open_history(&s, &a, Role::Read, &epoch(4), &ct), Err(Error::Decrypt));
        let empty = seal_history(&s, &a, Role::Read, &epoch(1), &[]).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &epoch(1), &empty), Ok(vec![]));
        // Forks: one n, two nonces, both kept.
        let fork = [(epoch(2), Secret32::from_bytes([2; 32])), (Epoch::new(2, [9; 16]).unwrap(), Secret32::from_bytes([4; 32]))];
        let ct = seal_history(&s, &a, Role::Read, &epoch(3), &fork).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &epoch(3), &ct).unwrap().len(), 2);
    }

    // spec/crypto.md §4: a history box holds one secret per earlier epoch, and only earlier ones.
    #[test]
    fn history_rejections() {
        let s = Secret32::from_bytes([1; 32]);
        let a = Tid::from_bytes([1; 15]);
        let two = [(epoch(1), Secret32::from_bytes([2; 32])), (epoch(1), Secret32::from_bytes([3; 32]))];
        assert!(seal_history(&s, &a, Role::Read, &epoch(3), &two).is_err());
        for late in [epoch(3), epoch(4), Epoch::new(3, [0; 16]).unwrap()] {
            assert!(seal_history(&s, &a, Role::Read, &epoch(3), &[(late, Secret32::from_bytes([2; 32]))]).is_err());
        }
        // A box listing its own epoch (built by hand) is rejected on open.
        let key = kdf(kdf::HISTORY, s.expose(), b"");
        let pt = encode(&Value::List(vec![Value::List(vec![Value::Int(3), Value::Bytes(vec![3; 16]), Value::Bytes(vec![2; 32])])]));
        let ct = aead::seal(key.expose(), &ZERO_NONCE, &history_ad(&a, Role::Read, &epoch(3)), &pt).unwrap();
        assert_eq!(open_history(&s, &a, Role::Read, &epoch(3), &ct), Err(Error::Malformed("history epoch not earlier")));
    }

    // spec/wire.md §1: epochs are `[n, nonce]` with n in the int range.
    #[test]
    fn epoch_wire() {
        assert_eq!(Epoch::from_wire(&epoch(9).to_wire()), Ok(epoch(9)));
        assert_eq!(Epoch::new(u64::MAX, [0; 16]), Err(Error::TooLarge));
        assert_eq!(Epoch::new(i64::MAX as u64, [0; 16]).unwrap().n(), i64::MAX as u64);
        assert!(Epoch::from_wire(&Value::List(vec![Value::Int(-1), Value::Bytes(vec![0; 16])])).is_err());
        assert!(epoch(1) < epoch(2) && Epoch::new(1, [0; 16]).unwrap() < Epoch::new(1, [1; 16]).unwrap());
    }
}
