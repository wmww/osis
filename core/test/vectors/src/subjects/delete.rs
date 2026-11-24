//! `delete/`: delete keys, blinded prefix commitments and delete signatures (spec/crypto.md §7).
//! Generated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::{BlobId, SyncId};
use osis_crypto::*;

const SPEC: &str = "spec/crypto.md §7";

pub fn keys() -> VecFile {
    let mut cases = Vec::new();
    let hb = [0x12u8; 16];
    let (sync_id, blob) = (SyncId([0x17; 16]), BlobId([0x18; 32]));
    // per level, two prefix salts: the same key commits differently and each signature verifies
    // only under its own commitment
    for (level, secret) in [(1u8, 0x14u8), (2, 0x15), (3, 0x16)] {
        let d = DeleteSecret::at_level(level, &s32(secret));
        // a level's key is the step key of its role secret (spec/sync-ids.md §2)
        let role = if level == 1 { RoleKey::Delete } else { RoleKey::Write };
        let vk = d.verifying_key();
        assert_eq!(vk, role_key(role, &s32(secret)).verifying_key());
        let digest = osis_blob::auth::delete_digest(&sync_id, &blob, &[level]);
        let mut seen = Vec::new();
        for salt in [[0x13u8; 16], [0x19; 16]] {
            let c = commitment(level, &vk, &salt, &hb).unwrap();
            let sig = d.sign(&salt, &hb, &digest);
            let blinded: [u8; 32] = c[1..].try_into().unwrap();
            verify_delete(&blinded, &digest, &sig).unwrap();
            assert!(verify_delete(&vk.to_bytes(), &digest, &sig).is_err());
            assert!(seen.iter().all(|(b, s): &([u8; 32], Signature)| verify_delete(b, &digest, &sig).is_err() && verify_delete(&blinded, &digest, s).is_err()));
            seen.push((blinded, sig));
            cases.push(
                case(&format!("delete key level {level}, salt {:02x}", salt[0]), SPEC)
                    .with("secret", hex(s32(secret).expose()))
                    .with("seed", hex(role_key_seed(role, &s32(secret)).expose()))
                    .with("key", hex(&vk.to_bytes()))
                    .with("level", level.to_string())
                    .with("salt", hex(&salt))
                    .with("header-blind", hex(&hb))
                    .with("commitment", hex(&c))
                    .with("sync-id", hex(&sync_id.0))
                    .with("blob-id", hex(&blob.0))
                    .with("digest", hex(&digest))
                    .with("signature", hex(&sig.0)),
            );
        }
    }
    // the unblinded key's signature is refused under the commitment
    let d = DeleteSecret::admin(&s32(0x14));
    let salt = [0x13u8; 16];
    let c = commitment(1, &d.verifying_key(), &salt, &hb).unwrap();
    let digest = osis_blob::auth::delete_digest(&sync_id, &blob, &[1]);
    let plain = role_key(RoleKey::Delete, &s32(0x14)).sign(Domain::Delete, &digest);
    assert!(verify_delete(&c[1..].try_into().unwrap(), &digest, &plain).is_err());
    cases.push(case("unblinded signature", SPEC).with("commitment", hex(&c)).with("digest", hex(&digest)).with("signature", hex(&plain.0)).with("reject", "signature"));
    VecFile { header: generated_header("delete", SPEC), cases }
}
