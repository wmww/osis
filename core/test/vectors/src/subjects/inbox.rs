//! `inbox/`: an inbox blob (spec/wire.md §9, spec/crypto.md §5). Generated. The commit is a
//! stand-in `CommitBlobPlaintext` value until osis-commit lands. Randomness in draw order: the
//! prefix `salt`, then the sealed box's `ephemeral` and `mlkem-m`.

use super::{FixedRng, case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::{CommitId, Role, SyncId, Tid, Value, WallMs, encode};
use osis_crypto::{KemSecret, SigningSecret};
use osis_label::{BoxedThing, BoxesPayload, DialHint, Inbox, InboxPayload, InboxThing, open_inbox_blob, open_inbox_item, seal_boxes_payload, seal_inbox_blob};
use osis_schema::core_types::{Epoch, SecretBox, SymmetricBox};

const SPEC: &str = "spec/wire.md §9";

pub fn inbox() -> VecFile {
    let kem_seed = s32(0x05);
    let kem = KemSecret::derive(&kem_seed);
    let recipient = Tid::from_bytes([0x02; 15]);
    let payload = InboxPayload {
        chain: Vec::new(), records: Vec::new(),
        commit: Value::List(vec![Value::List(vec![]), Value::Bytes(vec![0; 64]), Value::List(vec![])]),
        things: vec![InboxThing { tid: Tid::from_bytes([0x03; 15]), sync_id: Some(SyncId([0x04; 16])), delete_keys: Some((osis_crypto::DeleteSecret::derive(&s32(0x07)).verifying_key(), osis_crypto::DeleteSecret::derive(&s32(0x08)).verifying_key())) }],
        dial: Some(DialHint { dialable: [0x06; 32], urls: vec!["quic://peer.example:4433".into()] }),
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
    // a boxes payload: the recipient's boxes of a role commit, signed by its author
    let signing_seed = s32(0x0a);
    let signer = SigningSecret::from_seed(&signing_seed);
    let e = Epoch { n: 1, nonce: [0x0b; 32] };
    let b = SecretBox::Symmetric(SymmetricBox { epoch: Epoch { n: 0, nonce: [0x0c; 32] }, wrap: vec![0x0d; 49] });
    let things = vec![BoxedThing::new(Tid::from_bytes([0x03; 15]), Some(SyncId([0x04; 16])), vec![(Role::Sync, e, b)])];
    let record = osis_base::CreationRecord::KeyActor { alg: osis_base::SIGNING_KEY_ED25519, public_key: signer.verifying_key().to_bytes().to_vec(), nonce: [0x0f; 32], account: false };
    let boxes = BoxesPayload::signed(&recipient, CommitId([0x0e; 32]), osis_label::AuthorProof { record, rotations: Vec::new() }, None, things, None, &signer);
    let blob = seal_boxes_payload(&recipient, kem.public(), &boxes, now, &mut FixedRng::new(&[&salt, &eph, &m])).unwrap();
    assert_eq!(open_inbox_item(&blob, &recipient, &kem).unwrap().1, Inbox::Boxes(boxes.clone()));
    assert!(boxes.verified(&recipient));
    cases.push(
        case("boxes payload", SPEC)
            .with("recipient", hex(recipient.as_bytes()))
            .with("recipient-kem-seed", hex(kem_seed.expose()))
            .with("signing-seed", hex(signing_seed.expose()))
            .with("now", now.0.to_string())
            .with("salt", hex(&salt))
            .with("ephemeral", hex(&eph))
            .with("mlkem-m", hex(&m))
            .with("payload", hex(&encode(&boxes.to_value())))
            .with("blob", hex(&blob)),
    );
    VecFile { header: generated_header("inbox", SPEC), cases }
}
