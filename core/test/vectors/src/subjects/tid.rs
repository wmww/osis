//! `tid/`: creation records and tids (spec/wire.md §3, spec/data-model.md §1). Generated.

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{CreationRecord, Tid, Value, encode};
use std::collections::BTreeMap;

const SPEC: &str = "spec/wire.md §3";

/// Ordinary-thing records and the both/neither-field rejections. Key-actor records need
/// osis-crypto (`tid/key-actor.vec`).
pub fn thing() -> VecFile {
    let owner = Tid::from_bytes([1; 15]);
    let nonce = [2u8; 32];
    let rec = CreationRecord::Thing { owner, nonce };
    let bytes = encode(&rec.to_value());
    let tid = rec.tid();
    assert_eq!(osis_base::hash::hash(&bytes)[..15], tid.as_bytes()[..], "tid is BLAKE3 of the record");
    let mut cases = vec![
        Record::new()
            .with("case", "ordinary thing")
            .with("spec", SPEC)
            .with("owner", hex(owner.as_bytes()))
            .with("nonce", hex(&nonce))
            .with("record", hex(&bytes))
            .with("tid", hex(tid.as_bytes()))
            .with("text", tid.to_string())
            .with("uri", tid.to_uri()),
    ];
    // Field numbers of spec/wire.md §3: 0 owner, 1 key, 2 nonce.
    let key = Value::Enum(1, Some(Box::new(Value::Bytes(vec![3; 32]))));
    let both = BTreeMap::from([
        (Value::Int(0), Value::Tid(owner)),
        (Value::Int(1), key),
        (Value::Int(2), Value::Bytes(nonce.to_vec())),
    ]);
    let neither = BTreeMap::from([(Value::Int(2), Value::Bytes(nonce.to_vec()))]);
    for (name, m) in [("both owner and key", both), ("neither owner nor key", neither)] {
        let v = Value::Map(m);
        assert!(CreationRecord::from_value(&v).is_none(), "{name} must be rejected");
        cases.push(Record::new().with("case", name).with("spec", SPEC).with("record", hex(&encode(&v))).with("reject", "creation-fields"));
    }
    VecFile { header: generated_header("tid", SPEC), cases }
}

/// Key-actor records: a node (signing key from seed 03 via `kdf("sign", seed)`, random nonce
/// 04*32) and a link key (same seed, nonce `kdf("creation nonce", seed, "")`).
pub fn key_actor() -> VecFile {
    let seed = osis_crypto::Secret32::from_bytes([3; 32]);
    let key = osis_crypto::KeyActorKeys::from_seed(&seed).signing.verifying_key();
    let mut cases = Vec::new();
    for (name, nonce) in [("node", [4u8; 32]), ("link key", osis_crypto::creation_nonce(&seed))] {
        // alg 1: `signing_key` case ed25519 (spec/wire.md §3).
        let rec = CreationRecord::KeyActor { alg: 1, public_key: key.to_bytes().to_vec(), nonce };
        let bytes = encode(&rec.to_value());
        let tid = rec.tid();
        assert_eq!(CreationRecord::from_value(&rec.to_value()), Some(rec.clone()));
        cases.push(
            Record::new()
                .with("case", name)
                .with("spec", SPEC)
                .with("seed", hex(seed.expose()))
                .with("signing-key", hex(&key.to_bytes()))
                .with("nonce", hex(&nonce))
                .with("record", hex(&bytes))
                .with("tid", hex(tid.as_bytes()))
                .with("text", tid.to_string())
                .with("uri", tid.to_uri()),
        );
    }
    VecFile { header: generated_header("tid", SPEC), cases }
}
