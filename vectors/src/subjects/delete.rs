//! `delete/`: delete keys, blinded prefix commitments and delete signatures (spec/crypto.md §7).
//! Generated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_core::{BlobId, LabelId, WallMs};
use osis_crypto::*;

const SPEC: &str = "spec/crypto.md §7";

pub fn keys() -> VecFile {
    let mut cases = Vec::new();
    let salt = [0x13u8; 16];
    let (label, blob) = (LabelId([0x17; 16]), BlobId([0x18; 32]));
    for (level, secret) in [(1u8, 0x14u8), (2, 0x15), (3, 0x16)] {
        let d = DeleteSecret::derive(&s32(secret));
        let vk = d.verifying_key();
        let c = commitment(level, &vk, &salt).unwrap();
        let at = (level == 2).then_some(WallMs(1_700_000_000_000));
        let digest = osis_label::auth::delete_digest(&label, &blob, at, Some(level)).unwrap();
        let sig = d.sign(&salt, &digest);
        let blinded: [u8; 32] = c[1..].try_into().unwrap();
        verify_delete(&blinded, &digest, &sig).unwrap();
        assert!(verify_delete(&vk.to_bytes(), &digest, &sig).is_err());
        cases.push(
            case(&format!("delete key level {level}"), SPEC)
                .with("secret", hex(s32(secret).expose()))
                .with("seed", hex(kdf::kdf(kdf::DELETE_KEY, s32(secret).expose(), b"").expose()))
                .with("key", hex(&vk.to_bytes()))
                .with("level", level.to_string())
                .with("salt", hex(&salt))
                .with("commitment", hex(&c))
                .with("label-id", hex(&label.0))
                .with("blob-id", hex(&blob.0))
                .with("at", at.map_or("none".to_string(), |t| t.0.to_string()))
                .with("digest", hex(&digest))
                .with("signature", hex(&sig.0)),
        );
    }
    // the unblinded key's signature is refused under the commitment
    let d = DeleteSecret::derive(&s32(0x14));
    let c = commitment(1, &d.verifying_key(), &salt).unwrap();
    let digest = osis_label::auth::delete_digest(&label, &blob, None, Some(1)).unwrap();
    let plain = SigningSecret::from_seed(&kdf::kdf(kdf::DELETE_KEY, s32(0x14).expose(), b"")).sign(Domain::Delete, &digest);
    assert!(verify_delete(&c[1..].try_into().unwrap(), &digest, &plain).is_err());
    cases.push(case("unblinded signature", SPEC).with("commitment", hex(&c)).with("digest", hex(&digest)).with("signature", hex(&plain.0)).with("reject", "signature"));
    VecFile { header: generated_header("delete", SPEC), cases }
}
