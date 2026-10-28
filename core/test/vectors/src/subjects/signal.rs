//! `signal/`: a signal envelope with its wrap and publish authorization (spec/wire.md §9,
//! spec/sync.md §9). Generated. Sender node seed `08`; label secrets read `0a`, write `0b`,
//! index 0. Randomness in draw order: the prefix `salt`, then the `blob-key`.

use super::{FixedRng, case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_core::{Ak, LabelId, SchemaId, Tid, Ts, Value, encode};
use osis_crypto::{KeyActorKeys, LabelRole, label_role_key, wrap};
use osis_label::{PublishAuth, PublishKey, SignalBody, open_signal, seal_signal};

const SPEC: &str = "spec/wire.md §9";

pub fn signal() -> VecFile {
    let node = KeyActorKeys::from_seed(&s32(0x08));
    let body = SignalBody {
        node: Tid::from_bytes([0x01; 15]),
        actor: Tid::from_bytes([0x02; 15]),
        ts: Ts::from_u64(1_700_000_000_000 << 16).unwrap(),
        tid: Tid::from_bytes([0x03; 15]),
        kind: Ak::new("/chat/typing").unwrap(),
        target: None,
        schema: Some((SchemaId([0x04; 16]), 1)),
        value: Value::Bool(true),
    };
    let (salt, key) = ([0x39u8; 16], [0x3au8; 32]);
    let (k, blob) = seal_signal(&body, &node.signing, &mut FixedRng::new(&[&salt, &key])).unwrap();
    let (got, sig) = open_signal(&blob, &k).unwrap();
    assert_eq!(got, body);
    got.verify(&node.signing.verifying_key(), &sig).unwrap();
    let id = osis_label::blob_id(&blob);
    let read = s32(0x0a);
    let w = wrap(&read, &id, &k).unwrap();
    let label = LabelId([0x05; 16]);
    let auth = PublishAuth::sign(PublishKey::Write, &label_role_key(LabelRole::Write, &s32(0x0b), 0), &label, &id, &w);
    let cases = vec![
        case("signal envelope", SPEC)
            .with("node-seed", hex(&[0x08; 32]))
            .with("body", hex(&encode(&body.to_value().unwrap())))
            .with("digest", hex(&body.digest().unwrap()))
            .with("signature", hex(&sig.0))
            .with("salt", hex(&salt))
            .with("blob-key", hex(&key))
            .with("blob", hex(&blob))
            .with("blob-id", hex(&id.0))
            .with("read-secret", hex(read.expose()))
            .with("wrap", hex(&w))
            .with("label-id", hex(&label.0))
            .with("write-secret", hex(&[0x0b; 32]))
            .with("index", "0")
            .with("publish-auth", hex(&encode(&auth.to_value()))),
    ];
    VecFile { header: generated_header("signal", SPEC), cases }
}
