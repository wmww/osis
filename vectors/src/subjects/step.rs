//! `step/`: registration steps and claim sets (spec/wire.md §8, spec/sync.md §2). Generated.
//! Group secrets: read `0a`, write `0b`, admin `09`, deposit seed `0c`, index 0, read epoch
//! `[0, 0d*16]`. Randomness in draw order (`osis_label::register`): `step-secret`, per sealed
//! entry box `ephemeral` then `mlkem-m`, 32 bytes per `padding` key, 8 bytes per `shuffle` swap.

use super::{FixedRng, case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_core::{LabelId, Value, encode};
use osis_crypto::{Epoch, KeyActorKeys, LabelRole, X25519Secret, label_role_key, static_entry};
use osis_label::{ClaimSet, EntryKey, EntryTo, Parent, Reader, Step, StepKeys, genesis_label, open_entry_box, register};
use osis_schema::Codec;

const SPEC: &str = "spec/wire.md §8";

fn claims_field(c: &ClaimSet) -> String {
    c.claims.iter().map(|k| hex(k)).collect::<Vec<_>>().join(",")
}

fn step_fields(r: Record, s: &Step, c: &ClaimSet) -> Record {
    r.with("label-id", hex(&s.label.0))
        .with("sync-pk", hex(&s.keys.sync.to_bytes()))
        .with("write-pk", hex(&s.keys.write.to_bytes()))
        .with("delete-pk", hex(&s.keys.delete.to_bytes()))
        .with("deposit-pk", hex(&s.keys.deposit.to_bytes()))
        .with("step-key", hex(&s.step_key))
        .with("claims", claims_field(c))
        .with("claim-set", hex(&c.to_bytes()))
        .with("claims-hash", hex(&c.hash()))
        .with("signed-digest", hex(&s.digest()))
        .with("step", hex(&s.to_bytes()))
        .with("step-id", hex(&s.id().0))
}

pub fn steps() -> VecFile {
    let (read, write, admin, deposit) = (s32(0x0a), s32(0x0b), s32(0x09), s32(0x0c));
    let label = genesis_label(&admin, 0);
    let keys = StepKeys::derive(&read, &write, &admin, 0, &deposit, &label);
    let epoch = Epoch::new(0, [0x0d; 16]).unwrap();
    let (m1, m2, card) = (KeyActorKeys::from_seed(&s32(0x05)), KeyActorKeys::from_seed(&s32(0x06)), KeyActorKeys::from_seed(&s32(0x04)));
    let readers = [
        Reader::Dh(m1.kem.public().x25519()),
        Reader::Dh(m2.kem.public().x25519()),
        Reader::Static { signing: card.signing.verifying_key(), entry: EntryTo::Sealed(card.kem.public()) },
    ];
    let (sk, eph, m, pad, shuf) = ([0x31u8; 32], [0x32u8; 32], [0x33u8; 32], [0x34u8; 32], [0x35u8; 24]);
    let delete0 = label_role_key(LabelRole::Delete, &admin, 0);
    let mut rng = FixedRng::new(&[&sk, &eph, &m, &pad, &shuf]);
    let (s0, c0) = register(Parent::Genesis(&delete0), keys, &readers, (epoch, &read), &mut rng).unwrap();
    drop(rng);
    s0.verify_genesis().unwrap();
    assert_eq!(s0.step_key, X25519Secret::from_secret(&osis_crypto::Secret32::from_bytes(sk)).public());
    let k1 = s0.claim_key(m1.kem.x25519()).unwrap().verifying_key().to_bytes();
    let k2 = s0.claim_key(m2.kem.x25519()).unwrap().verifying_key().to_bytes();
    let entry = static_entry(&s0.label, &card.signing.verifying_key());
    assert!(c0.contains(&k1) && c0.contains(&k2) && c0.contains(&entry));
    let b = c0.entries.get(&entry).unwrap();
    assert_eq!(open_entry_box(b, &s0, EntryKey::Kem(&card.kem)).unwrap(), (Some(epoch), read.clone()));
    let mut cases = vec![step_fields(
        case("genesis step with two DH readers and one static entry", SPEC)
            .with("read-secret", hex(read.expose()))
            .with("write-secret", hex(write.expose()))
            .with("admin-secret", hex(admin.expose()))
            .with("deposit-seed", hex(deposit.expose()))
            .with("index", "0")
            .with("read-epoch-n", "0")
            .with("read-epoch-nonce", hex(epoch.nonce()))
            .with("reader-1-seed", hex(&[0x05; 32]))
            .with("reader-2-seed", hex(&[0x06; 32]))
            .with("static-reader-seed", hex(&[0x04; 32]))
            .with("step-secret", hex(&sk))
            .with("ephemeral", hex(&eph))
            .with("mlkem-m", hex(&m))
            .with("padding", hex(&pad))
            .with("shuffle", hex(&shuf))
            .with("claim-key-1", hex(&k1))
            .with("claim-key-2", hex(&k2))
            .with("static-entry", hex(&entry))
            .with("entry-box", hex(&encode(&b.to_value()))),
        &s0,
        &c0,
    )];

    // Child step: a rotation of every role (secrets 1a, 1b, 19), signed by the genesis delete key.
    let (r1, w1, a1) = (s32(0x1a), s32(0x1b), s32(0x19));
    let keys1 = StepKeys::derive(&r1, &w1, &a1, 0, &deposit, &label);
    let sk1 = [0x41u8; 32];
    let mut rng = FixedRng::new(&[&sk1]);
    let (s1, c1) = register(Parent::Child { step: &s0, delete: &delete0 }, keys1, &[Reader::Dh(m1.kem.public().x25519())], (Epoch::new(1, [0x0e; 16]).unwrap(), &r1), &mut rng).unwrap();
    drop(rng);
    s1.verify_child(&s0).unwrap();
    cases.push(step_fields(
        case("child step, one DH reader", SPEC)
            .with("parent-step-id", hex(&s0.id().0))
            .with("read-secret", hex(r1.expose()))
            .with("write-secret", hex(w1.expose()))
            .with("admin-secret", hex(a1.expose()))
            .with("deposit-seed", hex(deposit.expose()))
            .with("reader-1-seed", hex(&[0x05; 32]))
            .with("step-secret", hex(&sk1)),
        &s1,
        &c1,
    ));

    // Rejections.
    let mut t = s1.clone();
    t.sig = s0.sig;
    assert!(t.verify_child(&s0).is_err());
    cases.push(case("child step with a wrong signature", SPEC).with("parent", hex(&s0.to_bytes())).with("step", hex(&t.to_bytes())).with("reject", "step-signature"));
    let mut g = s0.clone();
    g.label = LabelId([0; 16]);
    assert!(g.verify_genesis().is_err());
    cases.push(case("genesis step of another label ID", SPEC).with("step", hex(&g.to_bytes())).with("reject", "label-id"));
    let three = encode(&Value::List(vec![Value::List((0..3u8).map(|i| Value::Bytes(vec![i; 32])).collect()), Value::Map(Default::default())]));
    assert!(ClaimSet::parse(&three).is_err());
    cases.push(case("claim set of three", SPEC).with("claim-set", hex(&three)).with("reject", "claim-count"));
    VecFile { header: generated_header("step", SPEC), cases }
}
