//! Box and wrap openers (spec/wire.md §7, spec/crypto.md §4–§6) on attacker bytes under fixed
//! keys, plus the `/secrets` and `/keys` value decoders: never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use osis_core::{BlobId, Limits, Role, Tid, decode};
use osis_crypto::{BoxForm, BoxSlot, Epoch, KeyActorKeys, Secret32, decrypt_blob, open_box, open_history, open_sealed, open_symmetric_box, sealed_from_value, unpad, unwrap};
use osis_schema::core_types as ct;
use osis_schema::{AspectKey, Codec};

fuzz_target!(|data: &[u8]| {
    let kem = KeyActorKeys::from_seed(&Secret32::from_bytes([1; 32])).kem;
    let s = Secret32::from_bytes([2; 32]);
    let actor = Tid::from_bytes([3; 15]);
    let slot = BoxSlot::Secrets { actor, member: Tid::from_bytes([4; 15]), role: Role::Read, epoch: Epoch::ZERO };
    let _ = open_box(&kem, &slot, BoxForm::Sealed { keyset: None, suite: 1 }, data);
    let _ = open_box(&kem, &slot, BoxForm::Sealed { keyset: Some(Epoch::ZERO), suite: 1 }, data);
    let _ = open_sealed(&kem, b"ad", data);
    let _ = open_symmetric_box(&s, &slot, Epoch::ZERO, data);
    let _ = open_history(&s, &actor, Role::Write, &Epoch::ZERO, data);
    let _ = unwrap(&s, &BlobId([5; 32]), data);
    let prefix = data.first().map_or(0, |b| usize::from(*b));
    let _ = decrypt_blob(data, prefix, &s);
    let _ = unpad(data);
    if let Ok(v) = decode(data, &Limits::DEFAULT) {
        let _ = sealed_from_value(&v);
        let _ = ct::SECRETS.decode(&v);
        let _ = ct::KEYS.decode(&v);
    }
});
