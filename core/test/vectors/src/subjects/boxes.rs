//! `box/`: hybrid sealed boxes, `secrets.0` boxes in both forms, entry boxes, history boxes, box names and the
//! inbox sealed box (spec/crypto.md §1, §4, spec/wire.md §7, §9). Generated. Randomness a box
//! draws is listed in draw order: `ephemeral` (X25519 private key), then `mlkem-m`.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{LabelId, Role, Tid, Value, encode};
use osis_crypto::*;

const EPH: [u8; 32] = [0x0c; 32];
const M: [u8; 32] = [0x0d; 32];

/// A nonce standing for an epoch nothing checks (a keyset or epoch of s).
fn epoch(n: u64) -> Epoch {
    Epoch::new(n, [n as u8; 32]).unwrap()
}

/// The epoch secret `s` of `actor`'s `role` names at `n` (spec/crypto.md §4).
fn named(actor: &Tid, role: Role, n: u64, s: &Secret32) -> Epoch {
    Epoch::derive(actor, role, n, s).unwrap()
}

fn role_int(r: Role) -> i64 {
    match r {
        Role::Read => 0,
        Role::Write => 1,
        Role::Admin => 2,
    }
}

/// Box payload `[role, n, secret]`, encoded here independently of osis-crypto.
fn payload(i: &BoxItem) -> Vec<u8> {
    encode(&Value::List(vec![Value::Int(role_int(i.role)), Value::Int(i.epoch.n() as i64), Value::Bytes(i.secret.expose().to_vec())]))
}

fn randomness(r: Record) -> Record {
    r.with("ephemeral", hex(&EPH)).with("mlkem-m", hex(&M))
}

fn secrets_slot(r: Record, actor: &Tid, holder: &Tid, role: Role, e: &Epoch) -> Record {
    r.with("actor", hex(actor.as_bytes()))
        .with("holder", hex(holder.as_bytes()))
        .with("role", role_int(role).to_string())
        .with("n", e.n().to_string())
        .with("nonce", hex(e.nonce()))
}

fn epoch_fields(r: Record, prefix: &str, e: Option<&Epoch>) -> Record {
    match e {
        Some(e) => r.with(&format!("{prefix}-n"), e.n().to_string()).with(&format!("{prefix}-nonce"), hex(e.nonce())),
        None => r.with(prefix, "none"),
    }
}

pub fn boxes() -> VecFile {
    let kem_seed = s32(0x05);
    let recipient = KemSecret::derive(&kem_seed);
    let (actor, holder) = (Tid::from_bytes([0x01; 15]), Tid::from_bytes([0x02; 15]));
    let mut cases = Vec::new();

    // The nonce rule: kdf("epoch", s, actor || role byte || le64(n)).
    let e = named(&actor, Role::Write, 4, &s32(0x09));
    let mut input = actor.as_bytes().to_vec();
    input.push(1);
    input.extend(4u64.to_le_bytes());
    assert_eq!(e.nonce(), kdf::kdf(kdf::EPOCH, s32(0x09).expose(), &input).expose());
    cases.push(case("epoch nonce", "spec/crypto.md §4").with("actor", hex(actor.as_bytes())).with("role", "1").with("n", "4").with("secret", hex(s32(0x09).expose())).with("nonce", hex(e.nonce())));

    let sealed = seal_with(recipient.public(), b"ad", b"payload", &Secret32::from_bytes(EPH), &M).unwrap();
    cases.push(
        randomness(case("hybrid sealed box", "spec/crypto.md §1").with("recipient-kem-seed", hex(kem_seed.expose())).with("recipient-public", hex(recipient.public().as_bytes())))
            .with("ad", hex(b"ad"))
            .with("payload", hex(b"payload"))
            .with("sealed", hex(&sealed))
            .with("sealed-value", hex(&encode(&sealed_to_value(&sealed)))),
    );
    let mut t = sealed.clone();
    *t.last_mut().unwrap() ^= 1;
    assert_eq!(open_sealed(&recipient, b"ad", &t), Err(Error::Decrypt));
    cases.push(case("hybrid sealed box tampered", "spec/crypto.md §1").with("recipient-kem-seed", hex(kem_seed.expose())).with("ad", hex(b"ad")).with("sealed", hex(&t)).with("reject", "decrypt"));
    assert_eq!(open_sealed(&recipient, b"ae", &sealed), Err(Error::Decrypt));
    cases.push(case("hybrid sealed box wrong ad", "spec/crypto.md §1").with("recipient-kem-seed", hex(kem_seed.expose())).with("ad", hex(b"ae")).with("sealed", hex(&sealed)).with("reject", "decrypt"));

    // Sealed secrets.0 boxes: to an actor holder (keyset named), to a key-actor holder (none).
    let ew = named(&actor, Role::Write, 4, &s32(0x09));
    let item = BoxItem { role: Role::Write, epoch: ew, secret: s32(0x09) };
    for (name, keyset) in [("secrets box sealed, actor holder", Some(epoch(3))), ("secrets box sealed, key-actor holder", None)] {
        let slot = BoxSlot::Secrets { actor, holder, role: Role::Write, epoch: ew };
        let form = BoxForm::Sealed { keyset, suite: 1 };
        let ad = slot.ad(form).unwrap();
        let b = seal_box(recipient.public(), &slot, keyset, &item, &mut FixedRng::new(&[&EPH, &M])).unwrap();
        assert_eq!(open_box(&recipient, &slot, form, &b).unwrap(), item);
        assert_eq!(&open_sealed(&recipient, &ad, &b).unwrap()[..], &payload(&item)[..]);
        let r = secrets_slot(case(name, "spec/wire.md §7").with("recipient-kem-seed", hex(kem_seed.expose())), &actor, &holder, Role::Write, &ew);
        let r = epoch_fields(r, "keyset", keyset.as_ref()).with("suite", "1").with("ad", hex(&ad));
        cases.push(randomness(r).with("payload", hex(&payload(&item))).with("sealed", hex(&b)));
    }

    // A box whose item names another epoch than its key's is refused.
    let slot = BoxSlot::Secrets { actor, holder, role: Role::Write, epoch: ew };
    let form = BoxForm::Sealed { keyset: Some(epoch(3)), suite: 1 };
    let ad = slot.ad(form).unwrap();
    let lie = encode(&Value::List(vec![Value::Int(1), Value::Int(4), Value::Bytes(s32(0x0a).expose().to_vec())]));
    let b = seal_with(recipient.public(), &ad, &lie, &Secret32::from_bytes(EPH), &M).unwrap();
    assert!(matches!(open_box(&recipient, &slot, form, &b), Err(Error::Malformed(_))));
    let r = secrets_slot(case("secrets box naming another epoch", "spec/crypto.md §4").with("recipient-kem-seed", hex(kem_seed.expose())), &actor, &holder, Role::Write, &ew);
    cases.push(epoch_fields(r, "keyset", Some(&epoch(3))).with("suite", "1").with("ad", hex(&ad)).with("payload", hex(&lie)).with("sealed", hex(&b)).with("reject", "malformed"));

    // Symmetric form.
    let e1 = named(&actor, Role::Read, 1, &s32(0x09));
    let slot = BoxSlot::Secrets { actor, holder, role: Role::Read, epoch: e1 };
    let ad = slot.ad(BoxForm::Symmetric { epoch_s: epoch(7) }).unwrap();
    let w = wrap_symmetric_box(&s32(0x0b), &slot, epoch(7), &s32(0x09)).unwrap();
    assert_eq!(open_symmetric_box(&s32(0x0b), &slot, epoch(7), &w), Ok(s32(0x09)));
    let r = epoch_fields(secrets_slot(case("secrets box symmetric", "spec/wire.md §7"), &actor, &holder, Role::Read, &e1), "s-epoch", Some(&epoch(7)));
    cases.push(r.with("ad", hex(&ad)).with("s", hex(s32(0x0b).expose())).with("secret", hex(s32(0x09).expose())).with("wrap", hex(&w)));
    assert_eq!(open_symmetric_box(&s32(0x0c), &slot, epoch(7), &w), Err(Error::Decrypt));
    cases.push(case("secrets box symmetric wrong s", "spec/wire.md §7").with("ad", hex(&ad)).with("s", hex(s32(0x0c).expose())).with("wrap", hex(&w)).with("reject", "decrypt"));

    // Entry box.
    let label = LabelId([0x0a; 16]);
    let step_key = X25519Secret::from_secret(&s32(0x06)).public();
    let group = Tid::from_bytes([0x07; 15]);
    let slot = BoxSlot::Entry { label, step_key, group };
    let form = BoxForm::Sealed { keyset: None, suite: 1 };
    let ad = slot.ad(form).unwrap();
    let item = EntryItem { epoch: named(&group, Role::Read, 2, &s32(0x08)), secret: s32(0x08), earlier: Some((named(&group, Role::Read, 1, &s32(0x0b)), s32(0x0b))) };
    let b = seal_entry(recipient.public(), &slot, &item, &mut FixedRng::new(&[&EPH, &M])).unwrap();
    assert_eq!(open_entry(&recipient, &slot, form, &b).unwrap(), item);
    let entry_payload = encode(&Value::List(vec![Value::Int(role_int(Role::Read)), Value::Int(2), Value::Bytes(item.secret.expose().to_vec()), Value::List(vec![Value::Int(1), Value::Bytes(s32(0x0b).expose().to_vec())])]));
    let r = case("entry box", "spec/wire.md §7").with("recipient-kem-seed", hex(kem_seed.expose())).with("label-id", hex(&label.0)).with("step-key", hex(&step_key)).with("group", hex(group.as_bytes()));
    cases.push(randomness(r.with("keyset", "none").with("suite", "1").with("ad", hex(&ad))).with("payload", hex(&entry_payload)).with("sealed", hex(&b)));

    // History box.
    let e3 = named(&actor, Role::Read, 3, &s32(0x09));
    let mut earlier = vec![(named(&actor, Role::Read, 1, &s32(0x21)), s32(0x21)), (named(&actor, Role::Read, 2, &s32(0x22)), s32(0x22))];
    earlier.sort_by_key(|(e, _)| *e);
    // names (spec/wire.md §7): one name [thing, ts, node, commit], one keyset name [thing, role, n,
    // nonce], the departs mark [ts, node]
    let name = Value::List(vec![Value::Bytes(actor.as_bytes().to_vec()), Value::Int(1_700_000_000_000 << 16), Value::Bytes(vec![0x31; 15]), Value::Bytes(vec![0x32; 32])]);
    let ks_name = Value::List(vec![Value::Bytes(vec![0x02; 15]), Value::Int(0), Value::Int(5), Value::Bytes(vec![0x05; 32])]);
    let departs = Value::List(vec![Value::Int(1_700_000_000_001 << 16), Value::Bytes(vec![0x31; 15])]);
    let names = Value::List(vec![Value::List(vec![name.clone()]), Value::List(vec![ks_name.clone()]), Value::List(vec![departs])]);
    let h = seal_history(&s32(0x09), &actor, Role::Read, &e3, &earlier, &names).unwrap();
    assert_eq!(open_history(&s32(0x09), &actor, Role::Read, &e3, &h).unwrap(), (earlier.clone(), names.clone()));
    let pairs = Value::List(earlier.iter().map(|(e, s)| Value::List(vec![Value::Int(e.n() as i64), Value::Bytes(s.expose().to_vec())])).collect());
    let pt = encode(&Value::List(vec![pairs, names]));
    let ad = encode(&Value::List(vec![Value::Bytes(actor.as_bytes().to_vec()), Value::Int(0), Value::Int(3), Value::Bytes(e3.nonce().to_vec())]));
    cases.push(
        case("history box", "spec/wire.md §7")
            .with("secret", hex(s32(0x09).expose()))
            .with("actor", hex(actor.as_bytes()))
            .with("role", "0")
            .with("n", "3")
            .with("nonce", hex(e3.nonce()))
            .with("ad", hex(&ad))
            .with("plaintext", hex(&pt))
            .with("box", hex(&h)),
    );
    assert_eq!(open_history(&s32(0x09), &actor, Role::Write, &e3, &h), Err(Error::Decrypt));
    cases.push(case("history box wrong role", "spec/wire.md §7").with("secret", hex(s32(0x09).expose())).with("actor", hex(actor.as_bytes())).with("role", "1").with("n", "3").with("nonce", hex(e3.nonce())).with("box", hex(&h)).with("reject", "decrypt"));

    // A grant's box names: random nonce || AEAD under the history key, AD [actor, holder, role, n,
    // nonce], the names with no departs mark.
    let holder = Tid::from_bytes([0x02; 15]);
    let bn = Value::List(vec![Value::List(vec![name]), Value::List(vec![ks_name]), Value::List(vec![])]);
    let nn = [0x0e; 24];
    let sealed = seal_box_names(&s32(0x09), &actor, &holder, Role::Read, &e3, &bn, &mut FixedRng::new(&[&nn])).unwrap();
    assert_eq!(sealed.get(..24), Some(&nn[..]));
    assert_eq!(open_box_names(&s32(0x09), &actor, &holder, Role::Read, &e3, &sealed).unwrap(), bn);
    let ad = encode(&Value::List(vec![Value::Bytes(actor.as_bytes().to_vec()), Value::Bytes(holder.as_bytes().to_vec()), Value::Int(0), Value::Int(3), Value::Bytes(e3.nonce().to_vec())]));
    let r = case("box names", "spec/wire.md §7").with("secret", hex(s32(0x09).expose())).with("actor", hex(actor.as_bytes())).with("holder", hex(holder.as_bytes()));
    let r = r.with("role", "0").with("n", "3").with("nonce", hex(e3.nonce()));
    cases.push(r.with("ad", hex(&ad)).with("names-nonce", hex(&nn)).with("plaintext", hex(&encode(&bn))).with("names", hex(&sealed)));
    let other = Tid::from_bytes([0x04; 15]);
    assert_eq!(open_box_names(&s32(0x09), &actor, &other, Role::Read, &e3, &sealed), Err(Error::Decrypt));
    let r = case("box names wrong holder", "spec/wire.md §7").with("secret", hex(s32(0x09).expose())).with("actor", hex(actor.as_bytes())).with("holder", hex(other.as_bytes()));
    cases.push(r.with("role", "0").with("n", "3").with("nonce", hex(e3.nonce())).with("names", hex(&sealed)).with("reject", "decrypt"));

    // Inbox sealed box over an opaque prefix (the prefix layout is osis-label's, inbox/).
    let prefix = super::PREFIX;
    let r_tid = Tid::from_bytes([0x03; 15]);
    let ib = seal_inbox(&prefix, &r_tid, recipient.public(), b"role commit", &mut FixedRng::new(&[&EPH, &M])).unwrap();
    assert_eq!(open_inbox(&ib, prefix.len(), &r_tid, &recipient).unwrap(), b"role commit");
    let ad = encode(&Value::List(vec![Value::Bytes(r_tid.as_bytes().to_vec()), Value::Str("inbox".into()), Value::Bytes(prefix.to_vec())]));
    let r = case("inbox sealed box", "spec/wire.md §9").with("recipient-kem-seed", hex(kem_seed.expose())).with("recipient", hex(r_tid.as_bytes())).with("prefix", hex(&prefix));
    cases.push(randomness(r.with("ad", hex(&ad))).with("payload", hex(b"role commit")).with("padded", hex(&pad(b"role commit"))).with("blob", hex(&ib)));
    VecFile { header: generated_header("box", "spec/wire.md §7"), cases }
}
