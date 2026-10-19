//! osis-crypto benches: sealed box seal/open and KEM keygen (spec/crypto.md §1, §3), blob
//! encryption (spec/crypto.md §5), Ed25519 sign/verify (spec/crypto.md §2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_bench::bench;
use osis_crypto::{Domain, KemSecret, Secret32, SeededRng, SigningSecret, decrypt_blob, encrypt_blob, open_sealed, seal};

fn main() {
    let mut rng = SeededRng::from_u64(1);
    let k = KemSecret::derive(&Secret32::from_bytes([1; 32]));
    let payload = [7u8; 64];
    bench("crypto/sealed_box_seal", None, || seal(k.public(), b"ad", &payload, &mut rng).unwrap());
    let sealed = seal(k.public(), b"ad", &payload, &mut rng).unwrap();
    bench("crypto/sealed_box_open", None, || open_sealed(&k, b"ad", &sealed).unwrap());
    bench("crypto/kem_keygen", None, || KemSecret::derive(&Secret32::from_bytes([2; 32])));

    let data = vec![5u8; 1 << 20];
    let prefix = [1u8; 26];
    bench("crypto/blob_encrypt_1MiB", Some(data.len()), || encrypt_blob(&prefix, &data, &mut rng).unwrap());
    let (key, blob) = encrypt_blob(&prefix, &data, &mut rng).unwrap();
    bench("crypto/blob_decrypt_1MiB", Some(data.len()), || decrypt_blob(&blob, 26, &key).unwrap());

    let sk = SigningSecret::from_seed(&Secret32::from_bytes([3; 32]));
    let pk = sk.verifying_key();
    let sig = sk.sign(Domain::Commit, &[9; 32]);
    bench("crypto/ed25519_sign", None, || sk.sign(Domain::Commit, &[9; 32]));
    bench("crypto/ed25519_verify", None, || pk.verify(Domain::Commit, &[9; 32], &sig).unwrap());
}
