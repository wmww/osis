//! `inbox/`: an inbox blob (spec/wire.md §9, spec/crypto.md §5). Generated. The commit is a
//! stand-in `CommitBlobPlaintext` value until osis-commit lands. Randomness in draw order: the
//! prefix `salt`, then the sealed box's `ephemeral` and `mlkem-m`.

use super::{FixedRng, case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::{LabelId, Tid, Value, WallMs, encode};
use osis_crypto::KemSecret;
use osis_label::{Address, InboxPayload, InboxThing, open_inbox_blob, seal_inbox_blob};

const SPEC: &str = "spec/wire.md §9";

pub fn inbox() -> VecFile {
    let kem_seed = s32(0x05);
    let kem = KemSecret::derive(&kem_seed);
    let recipient = Tid::from_bytes([0x02; 15]);
    let payload = InboxPayload {
        commit: Value::List(vec![Value::List(vec![]), Value::Bytes(vec![0; 64]), Value::List(vec![])]),
        things: vec![InboxThing { tid: Tid::from_bytes([0x03; 15]), label: LabelId([0x04; 16]), servers: vec![Address { url: "quic://server.example:4433".into(), key: [0x06; 32] }], delete_keys: Some((osis_crypto::DeleteSecret::derive(&s32(0x07)).verifying_key(), osis_crypto::DeleteSecret::derive(&s32(0x08)).verifying_key())) }],
    };
    let (salt, eph, m) = ([0x36u8; 16], [0x37u8; 32], [0x38u8; 32]);
    let now = WallMs(1_700_000_000_000);
    let blob = seal_inbox_blob(&recipient, kem.public(), &payload, now, &mut FixedRng::new(&[&salt, &eph, &m])).unwrap();
    let (prefix, got) = open_inbox_blob(&blob, &recipient, &kem).unwrap();
    assert_eq!(got, payload);
    let mut cases = vec![
        case("inbox blob", SPEC)
            .with("recipient", hex(recipient.as_bytes()))
            .with("recipient-kem-seed", hex(kem_seed.expose()))
            .with("now", now.0.to_string())
            .with("salt", hex(&salt))
            .with("ephemeral", hex(&eph))
            .with("mlkem-m", hex(&m))
            .with("prefix", hex(&prefix.to_bytes()))
            .with("payload", hex(&encode(&payload.to_value())))
            .with("blob", hex(&blob))
            .with("blob-id", hex(&osis_label::blob_id(&blob).0)),
    ];
    assert!(open_inbox_blob(&blob, &Tid::from_bytes([0x09; 15]), &kem).is_err());
    cases.push(case("inbox blob for another recipient", SPEC).with("recipient", hex(&[0x09; 15])).with("recipient-kem-seed", hex(kem_seed.expose())).with("blob", hex(&blob)).with("reject", "decrypt"));
    VecFile { header: generated_header("inbox", SPEC), cases }
}
