//! `/secrets` boxes, entry boxes and history boxes (spec/crypto.md §4, spec/wire.md §7).
//! The `box` value itself (spec/data-model.md §9) is osis-keys'; this module builds the AD
//! tuples and seals, wraps and opens the payloads.

use crate::aead::{self, WRAP_LEN, ZERO_NONCE};
use crate::kdf::{self, kdf};
use crate::{Error, KemPublicKey, KemSecret, SUITE_1, Secret32, open_sealed, seal};
use osis_core::cbor::{Limits, decode, encode};
use osis_core::{LabelId, Role, Tid, Value};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

/// A role secret's epoch `(n, nonce)`; ordered by n, then nonce (the canonical order of
/// `[n, nonce]`). n is at most `i64::MAX` (the int range).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Epoch {
    n: u64,
    nonce: [u8; 16],
}

impl Epoch {
    pub fn new(n: u64, nonce: [u8; 16]) -> Result<Epoch, Error> {
        if i64::try_from(n).is_err() {
            return Err(Error::TooLarge);
        }
        Ok(Epoch { n, nonce })
    }
    pub fn n(&self) -> u64 {
        self.n
    }
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    /// `[n, nonce]` (spec/wire.md §1).
    pub fn to_wire(&self) -> Value {
        Value::List(vec![uint(self.n), Value::Bytes(self.nonce.to_vec())])
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
    fn to_wire(self) -> Value {
        match self {
            BoxForm::Sealed { keyset, suite } => {
                Value::List(vec![uint(0), Value::List(keyset.iter().map(Epoch::to_wire).collect()), uint(suite)])
            }
            BoxForm::Symmetric { epoch_s } => Value::List(vec![uint(1), epoch_s.to_wire()]),
        }
    }
    /// Unknown suites park before any decryption.
    fn check_suite(self) -> Result<(), Error> {
        match self {
            BoxForm::Sealed { suite, .. } if suite != u64::from(SUITE_1) => Err(Error::UnknownSuite(suite)),
            _ => Ok(()),
        }
    }
}

/// AD of a `/secrets` box: `[actor, member, role, n, nonce, form]`.
pub fn secrets_box_ad(actor: &Tid, member: &Tid, role: Role, epoch: &Epoch, form: BoxForm) -> Vec<u8> {
    encode(&Value::List(vec![
        tid(actor),
        tid(member),
        role_value(role),
        uint(epoch.n),
        Value::Bytes(epoch.nonce.to_vec()),
        form.to_wire(),
    ]))
}

/// AD of an entry box: `[label_id, step_key, form]` (spec/wire.md §7).
pub fn entry_box_ad(label: &LabelId, step_key: &[u8; 32], form: BoxForm) -> Vec<u8> {
    encode(&Value::List(vec![Value::Bytes(label.0.to_vec()), Value::Bytes(step_key.to_vec()), form.to_wire()]))
}

/// One role secret carried by a box.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BoxItem {
    pub role: Role,
    pub epoch: Epoch,
    pub secret: Secret32,
}

/// Sealed form: `[[role, n, nonce, secret]+]` ascending by role, sealed to `recipient` under
/// `ad` (built with `BoxForm::Sealed`). Returns the raw sealed box.
pub fn seal_box(recipient: &KemPublicKey, ad: &[u8], items: &[BoxItem], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&BoxItem> = items.iter().collect();
    sorted.sort_by_key(|i| i.role);
    if sorted.is_empty() || sorted.windows(2).any(|w| w.first().map(|a| a.role) == w.get(1).map(|b| b.role)) {
        return Err(Error::Malformed("box items"));
    }
    let payload = Zeroizing::new(encode(&Value::List(
        sorted
            .iter()
            .map(|i| {
                Value::List(vec![
                    role_value(i.role),
                    uint(i.epoch.n),
                    Value::Bytes(i.epoch.nonce.to_vec()),
                    Value::Bytes(i.secret.expose().to_vec()),
                ])
            })
            .collect(),
    )));
    seal(recipient, ad, &payload, rng)
}

/// Opens a sealed-form box. `form` must be the box's own form fields (its suite is checked).
pub fn open_box(kem: &KemSecret, ad: &[u8], form: BoxForm, sealed: &[u8]) -> Result<Vec<BoxItem>, Error> {
    form.check_suite()?;
    let payload = open_sealed(kem, ad, sealed)?;
    let Value::List(items) = decode(&payload, &Limits::DEFAULT).map_err(|_| Error::Malformed("box payload"))? else {
        return Err(Error::Malformed("box payload"));
    };
    let mut out: Vec<BoxItem> = Vec::with_capacity(items.len());
    for item in &items {
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

/// Symmetric form: wrap of `secret` under `kdf("box", s)`, nonce = BLAKE3(AD)[..24].
pub fn wrap_symmetric_box(s: &Secret32, ad: &[u8], secret: &Secret32) -> [u8; WRAP_LEN] {
    aead::seal_suite_key(&kdf(kdf::BOX, s.expose(), b""), &ad_nonce(ad), ad, secret)
}

pub fn open_symmetric_box(s: &Secret32, ad: &[u8], wrap: &[u8]) -> Result<Secret32, Error> {
    aead::open_suite_key(&kdf(kdf::BOX, s.expose(), b""), &ad_nonce(ad), ad, wrap)
}

fn ad_nonce(ad: &[u8]) -> [u8; 24] {
    let mut n = [0u8; 24];
    n.copy_from_slice(blake3::hash(ad).as_bytes().get(..24).unwrap_or(&[0; 24]));
    n
}

/// History box (role, epoch) of `actor`: AEAD under `kdf("history", secret)`, nonce zero,
/// AD `[actor, role, n, nonce]`, plaintext `[[n, nonce, secret]*]` ascending by epoch.
pub fn seal_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, earlier: &[(Epoch, Secret32)]) -> Result<Vec<u8>, Error> {
    let mut sorted: Vec<&(Epoch, Secret32)> = earlier.iter().collect();
    sorted.sort_by_key(|(e, _)| *e);
    sorted.dedup_by_key(|(e, _)| *e);
    let pt = Zeroizing::new(encode(&Value::List(
        sorted
            .iter()
            .map(|(e, s)| Value::List(vec![uint(e.n), Value::Bytes(e.nonce.to_vec()), Value::Bytes(s.expose().to_vec())]))
            .collect(),
    )));
    aead::seal(&kdf(kdf::HISTORY, secret.expose(), b""), &ZERO_NONCE, &history_ad(actor, role, epoch), &pt)
}

pub fn open_history(secret: &Secret32, actor: &Tid, role: Role, epoch: &Epoch, ct: &[u8]) -> Result<Vec<(Epoch, Secret32)>, Error> {
    let pt = Zeroizing::new(aead::open(&kdf(kdf::HISTORY, secret.expose(), b""), &ZERO_NONCE, &history_ad(actor, role, epoch), ct)?);
    let Value::List(items) = decode(&pt, &Limits::DEFAULT).map_err(|_| Error::Malformed("history"))? else {
        return Err(Error::Malformed("history"));
    };
    let mut out: Vec<(Epoch, Secret32)> = Vec::with_capacity(items.len());
    for item in &items {
        let Value::List(f) = item else { return Err(Error::Malformed("history item")) };
        let [n, nonce, s] = f.as_slice() else { return Err(Error::Malformed("history item")) };
        let e = Epoch::new(get_uint(n)?, get_array(nonce)?)?;
        if out.last().is_some_and(|(prev, _)| *prev >= e) {
            return Err(Error::Malformed("history order"));
        }
        out.push((e, Secret32::from_bytes(get_array(s)?)));
    }
    Ok(out)
}

fn history_ad(actor: &Tid, role: Role, epoch: &Epoch) -> Vec<u8> {
    encode(&Value::List(vec![tid(actor), role_value(role), uint(epoch.n), Value::Bytes(epoch.nonce.to_vec())]))
}

// Structure encodings (spec/wire.md §1).
fn tid(t: &Tid) -> Value {
    Value::Bytes(t.as_bytes().to_vec())
}

/// Callers keep n within the int range (`Epoch::new`); suites and roles are small.
fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
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

    // spec/wire.md §7: sealed /secrets box round trip; AD binds actor, member, role, epoch, form.
    #[test]
    fn sealed_box() {
        let mut rng = SeededRng::from_u64(2);
        let kem = KemSecret::derive(&Secret32::from_bytes([1; 32]));
        let (a, m) = (Tid::from_bytes([1; 15]), Tid::from_bytes([2; 15]));
        let form = BoxForm::Sealed { keyset: Some(epoch(3)), suite: 1 };
        let ad = secrets_box_ad(&a, &m, Role::Write, &epoch(4), form);
        let items = vec![
            BoxItem { role: Role::Write, epoch: epoch(4), secret: Secret32::from_bytes([9; 32]) },
            BoxItem { role: Role::Read, epoch: epoch(2), secret: Secret32::from_bytes([8; 32]) },
        ];
        let b = seal_box(kem.public(), &ad, &items, &mut rng).unwrap();
        let got = open_box(&kem, &ad, form, &b).unwrap();
        assert_eq!(got, vec![items[1].clone(), items[0].clone()]);
        for other in [
            secrets_box_ad(&m, &m, Role::Write, &epoch(4), form),
            secrets_box_ad(&a, &a, Role::Write, &epoch(4), form),
            secrets_box_ad(&a, &m, Role::Admin, &epoch(4), form),
            secrets_box_ad(&a, &m, Role::Write, &epoch(5), form),
            secrets_box_ad(&a, &m, Role::Write, &epoch(4), BoxForm::Sealed { keyset: None, suite: 1 }),
        ] {
            assert_eq!(open_box(&kem, &other, form, &b), Err(Error::Decrypt));
        }
        let parked = BoxForm::Sealed { keyset: None, suite: 2 };
        assert_eq!(open_box(&kem, &ad, parked, &b), Err(Error::UnknownSuite(2)));
        let dup = vec![items[0].clone(), items[0].clone()];
        assert!(seal_box(kem.public(), &ad, &dup, &mut rng).is_err());
        assert!(seal_box(kem.public(), &ad, &[], &mut rng).is_err());
    }

    // spec/wire.md §7: AD layout `[actor, member, role, n, nonce, [0, Opt(epoch), suite]]`.
    #[test]
    fn ad_layout() {
        let (a, m) = (Tid::from_bytes([1; 15]), Tid::from_bytes([2; 15]));
        let ad = secrets_box_ad(&a, &m, Role::Admin, &epoch(4), BoxForm::Sealed { keyset: None, suite: 1 });
        let mut expect = vec![0x86, 0x4f];
        expect.extend([1; 15]);
        expect.push(0x4f);
        expect.extend([2; 15]);
        expect.extend([0x02, 0x04, 0x50]);
        expect.extend([4; 16]);
        expect.extend([0x83, 0x00, 0x80, 0x01]);
        assert_eq!(ad, expect);
        let sym = entry_box_ad(&LabelId([3; 16]), &[5; 32], BoxForm::Symmetric { epoch_s: epoch(1) });
        assert_eq!(sym[..2], [0x83, 0x50]);
        assert_eq!(sym[sym.len() - 21..sym.len() - 17], [0x82, 0x01, 0x82, 0x01]);
    }

    // spec/wire.md §7: symmetric form is deterministic, binds its AD, and fails under another s.
    #[test]
    fn symmetric_box() {
        let s = Secret32::from_bytes([4; 32]);
        let ad = secrets_box_ad(&Tid::from_bytes([1; 15]), &Tid::from_bytes([2; 15]), Role::Read, &epoch(1), BoxForm::Symmetric { epoch_s: epoch(7) });
        let secret = Secret32::from_bytes([6; 32]);
        let w = wrap_symmetric_box(&s, &ad, &secret);
        assert_eq!(w, wrap_symmetric_box(&s, &ad, &secret));
        assert_eq!(open_symmetric_box(&s, &ad, &w), Ok(secret));
        assert_eq!(open_symmetric_box(&Secret32::from_bytes([5; 32]), &ad, &w), Err(Error::Decrypt));
        assert_eq!(open_symmetric_box(&s, b"other", &w), Err(Error::Decrypt));
        assert!(open_symmetric_box(&s, &ad, &w[..48]).is_err());
    }

    // spec/crypto.md §4: a history box under the new secret opens every earlier one, sorted,
    // deduplicated; another role or epoch does not open it.
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
    }

    // spec/wire.md §1: epochs are `[n, nonce]` with n in the int range.
    #[test]
    fn epoch_wire() {
        assert_eq!(Epoch::from_wire(&epoch(9).to_wire()), Ok(epoch(9)));
        assert!(Epoch::new(u64::MAX, [0; 16]).is_err());
        assert!(Epoch::from_wire(&Value::List(vec![Value::Int(-1), Value::Bytes(vec![0; 16])])).is_err());
        assert!(epoch(1) < epoch(2) && Epoch::new(1, [0; 16]).unwrap() < Epoch::new(1, [1; 16]).unwrap());
    }
}
