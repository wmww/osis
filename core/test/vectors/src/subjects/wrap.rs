//! `wrap/`: wraps and blob encryption over an opaque clear prefix (spec/crypto.md §5,
//! spec/wire.md §5). Generated. Prefix layouts and full blobs are osis-label's (`blob/`).

use super::{FixedRng, case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::BlobId;
use osis_crypto::*;

const SPEC: &str = "spec/crypto.md §5";

pub fn wrap() -> VecFile {
    let mut cases = Vec::new();
    let (rs, bk, bid) = (s32(0x0f), s32(0x10), BlobId([0x0e; 32]));
    let w = osis_crypto::wrap(&rs, &bid, &bk).unwrap();
    assert_eq!(unwrap(&rs, &bid, &w), Ok(bk.clone()));
    cases.push(case("wrap", SPEC).with("read-secret", hex(rs.expose())).with("blob-id", hex(&bid.0)).with("blob-key", hex(bk.expose())).with("wrap", hex(&w)));
    assert_eq!(unwrap(&rs, &BlobId([0x0d; 32]), &w), Err(Error::Decrypt));
    cases.push(case("wrap under another blob id", SPEC).with("read-secret", hex(rs.expose())).with("blob-id", hex(&[0x0d; 32])).with("wrap", hex(&w)).with("reject", "decrypt"));

    // The rng supplies the blob key.
    let prefix = super::PREFIX;
    let key = [0x10u8; 32];
    let (k, blob) = encrypt_blob(&prefix, b"osis", &mut FixedRng::new(&[&key])).unwrap();
    assert_eq!(k.expose(), &key);
    let id = blob_id(&blob);
    let w = osis_crypto::wrap(&rs, &id, &k).unwrap();
    cases.push(
        case("blob and its wrap", SPEC)
            .with("prefix", hex(&prefix))
            .with("plaintext", hex(b"osis"))
            .with("padded", hex(&pad(b"osis")))
            .with("blob-key", hex(&key))
            .with("blob", hex(&blob))
            .with("blob-id", hex(&id.0))
            .with("read-secret", hex(rs.expose()))
            .with("wrap", hex(&w)),
    );
    let mut t = blob.clone();
    t[1] ^= 1;
    assert_eq!(decrypt_blob(&t, prefix.len(), &k), Err(Error::Decrypt));
    cases.push(case("blob prefix tampered", SPEC).with("prefix-len", prefix.len().to_string()).with("blob-key", hex(&key)).with("blob", hex(&t)).with("reject", "decrypt"));
    VecFile { header: generated_header("wrap", SPEC), cases }
}
