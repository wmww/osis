//! `box/`: hybrid sealed boxes, `/secrets` boxes in both forms, entry boxes, history boxes and the
//! inbox sealed box (spec/crypto.md §1, §4, spec/wire.md §7, §9). Generated. Randomness a box
//! draws is listed in draw order: `ephemeral` (X25519 private key), then `mlkem-m`.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_core::{LabelId, Role, Tid, Value, encode};
use osis_crypto::*;

const EPH: [u8; 32] = [0x0c; 32];
const M: [u8; 32] = [0x0d; 32];

fn epoch(n: u64) -> Epoch {
    Epoch::new(n, [n as u8; 16]).unwrap()
}

fn role_int(r: Role) -> i64 {
    match r {
        Role::Read => 0,
        Role::Write => 1,
        Role::Admin => 2,
    }
}

/// Box payload `[[role, n, nonce, secret]+]`, encoded here independently of osis-crypto.
fn payload(items: &[BoxItem]) -> Vec<u8> {
    encode(&Value::List(
        items
            .iter()
            .map(|i| {
                Value::List(vec![
                    Value::Int(role_int(i.role)),
                    Value::Int(i.epoch.n() as i64),
                    Value::Bytes(i.epoch.nonce().to_vec()),
                    Value::Bytes(i.secret.expose().to_vec()),
                ])
            })
            .collect(),
    ))
}

fn randomness(r: Record) -> Record {
    r.with("ephemeral", hex(&EPH)).with("mlkem-m", hex(&M))
}

fn secrets_slot(r: Record, actor: &Tid, member: &Tid, role: Role, e: &Epoch) -> Record {
    r.with("actor", hex(actor.as_bytes()))
        .with("member", hex(member.as_bytes()))
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
    let (actor, member) = (Tid::from_bytes([0x01; 15]), Tid::from_bytes([0x02; 15]));
    let mut cases = Vec::new();

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

    // Sealed /secrets boxes: to an actor member (one item, keyset named), to a key-actor member
    // (no keyset, every written role).
    let cases_sealed: [(&str, Option<Epoch>, Vec<BoxItem>); 2] = [
        ("secrets box sealed, actor member", Some(epoch(3)), vec![BoxItem { role: Role::Write, epoch: epoch(4), secret: s32(0x09) }]),
        (
            "secrets box sealed, key-actor member",
            None,
            vec![BoxItem { role: Role::Read, epoch: epoch(2), secret: s32(0x08) }, BoxItem { role: Role::Write, epoch: epoch(4), secret: s32(0x09) }],
        ),
    ];
    for (name, keyset, items) in cases_sealed {
        let slot = BoxSlot::Secrets { actor, member, role: Role::Write, epoch: epoch(4) };
        let form = BoxForm::Sealed { keyset, suite: 1 };
        let ad = slot.ad(form).unwrap();
        let b = seal_box(recipient.public(), &slot, keyset, &items, &mut FixedRng::new(&[&EPH, &M])).unwrap();
        assert_eq!(open_box(&recipient, &slot, form, &b).unwrap(), items);
        assert_eq!(&open_sealed(&recipient, &ad, &b).unwrap()[..], &payload(&items)[..]);
        let r = secrets_slot(case(name, "spec/wire.md §7").with("recipient-kem-seed", hex(kem_seed.expose())), &actor, &member, Role::Write, &epoch(4));
        let r = epoch_fields(r, "keyset", keyset.as_ref()).with("suite", "1").with("ad", hex(&ad));
        cases.push(randomness(r).with("payload", hex(&payload(&items))).with("sealed", hex(&b)));
    }

    // Symmetric form.
    let slot = BoxSlot::Secrets { actor, member, role: Role::Read, epoch: epoch(1) };
    let ad = slot.ad(BoxForm::Symmetric { epoch_s: epoch(7) }).unwrap();
    let w = wrap_symmetric_box(&s32(0x0b), &slot, epoch(7), &s32(0x09)).unwrap();
    assert_eq!(open_symmetric_box(&s32(0x0b), &slot, epoch(7), &w), Ok(s32(0x09)));
    let r = epoch_fields(secrets_slot(case("secrets box symmetric", "spec/wire.md §7"), &actor, &member, Role::Read, &epoch(1)), "s-epoch", Some(&epoch(7)));
    cases.push(r.with("ad", hex(&ad)).with("s", hex(s32(0x0b).expose())).with("secret", hex(s32(0x09).expose())).with("wrap", hex(&w)));
    assert_eq!(open_symmetric_box(&s32(0x0c), &slot, epoch(7), &w), Err(Error::Decrypt));
    cases.push(case("secrets box symmetric wrong s", "spec/wire.md §7").with("ad", hex(&ad)).with("s", hex(s32(0x0c).expose())).with("wrap", hex(&w)).with("reject", "decrypt"));

    // Entry box.
    let label = LabelId([0x0a; 16]);
    let step_key = X25519Secret::from_secret(&s32(0x06)).public();
    let slot = BoxSlot::Entry { label, step_key };
    let form = BoxForm::Sealed { keyset: None, suite: 1 };
    let ad = slot.ad(form).unwrap();
    let items = [BoxItem { role: Role::Read, epoch: epoch(2), secret: s32(0x08) }];
    let b = seal_box(recipient.public(), &slot, None, &items, &mut FixedRng::new(&[&EPH, &M])).unwrap();
    assert_eq!(open_box(&recipient, &slot, form, &b).unwrap(), items);
    let r = case("entry box", "spec/wire.md §7").with("recipient-kem-seed", hex(kem_seed.expose())).with("label-id", hex(&label.0)).with("step-key", hex(&step_key));
    cases.push(randomness(r.with("keyset", "none").with("suite", "1").with("ad", hex(&ad))).with("payload", hex(&payload(&items))).with("sealed", hex(&b)));

    // History box.
    let earlier = [(epoch(1), s32(0x21)), (epoch(2), s32(0x22))];
    let h = seal_history(&s32(0x09), &actor, Role::Read, &epoch(3), &earlier).unwrap();
    assert_eq!(open_history(&s32(0x09), &actor, Role::Read, &epoch(3), &h).unwrap(), earlier);
    let pt = encode(&Value::List(
        earlier.iter().map(|(e, s)| Value::List(vec![Value::Int(e.n() as i64), Value::Bytes(e.nonce().to_vec()), Value::Bytes(s.expose().to_vec())])).collect(),
    ));
    let ad = encode(&Value::List(vec![Value::Bytes(actor.as_bytes().to_vec()), Value::Int(0), Value::Int(3), Value::Bytes(vec![3; 16])]));
    cases.push(
        case("history box", "spec/wire.md §7")
            .with("secret", hex(s32(0x09).expose()))
            .with("actor", hex(actor.as_bytes()))
            .with("role", "0")
            .with("n", "3")
            .with("nonce", hex(&[3; 16]))
            .with("ad", hex(&ad))
            .with("plaintext", hex(&pt))
            .with("box", hex(&h)),
    );
    assert_eq!(open_history(&s32(0x09), &actor, Role::Write, &epoch(3), &h), Err(Error::Decrypt));
    cases.push(case("history box wrong role", "spec/wire.md §7").with("secret", hex(s32(0x09).expose())).with("actor", hex(actor.as_bytes())).with("role", "1").with("n", "3").with("nonce", hex(&[3; 16])).with("box", hex(&h)).with("reject", "decrypt"));

    // Inbox sealed box over an opaque prefix (the prefix layout is osis-label's, inbox/).
    let prefix = super::PREFIX;
    let r_tid = Tid::from_bytes([0x03; 15]);
    let ib = seal_inbox(&prefix, &r_tid, recipient.public(), b"membership commit", &mut FixedRng::new(&[&EPH, &M])).unwrap();
    assert_eq!(open_inbox(&ib, prefix.len(), &r_tid, &recipient).unwrap(), b"membership commit");
    let ad = encode(&Value::List(vec![Value::Bytes(r_tid.as_bytes().to_vec()), Value::Str("inbox".into()), Value::Bytes(prefix.to_vec())]));
    let r = case("inbox sealed box", "spec/wire.md §9").with("recipient-kem-seed", hex(kem_seed.expose())).with("recipient", hex(r_tid.as_bytes())).with("prefix", hex(&prefix));
    cases.push(randomness(r.with("ad", hex(&ad))).with("payload", hex(b"membership commit")).with("padded", hex(&pad(b"membership commit"))).with("blob", hex(&ib)));
    VecFile { header: generated_header("box", "spec/wire.md §7"), cases }
}
