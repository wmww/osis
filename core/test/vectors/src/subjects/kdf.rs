//! `kdf/`: every kdf purpose, the XOF form and the dedup derive_key (spec/crypto.md §1, §3).
//! Generated.

use super::{case, generated_header};
use crate::file::VecFile;
use crate::hex;
use osis_crypto::kdf::{self, kdf, kdf_xof};

const SPEC: &str = "spec/crypto.md §1";

pub fn purposes() -> VecFile {
    let secret = [0x11u8; 32];
    let input = b"osis test input";
    let mut cases = Vec::new();
    for p in kdf::PURPOSES {
        cases.push(case(p, SPEC).with("purpose", p).with("secret", hex(&secret)).with("input", hex(input)).with("out", hex(kdf(p, &secret, input).expose())));
    }
    let mut xof = [0u8; 96];
    kdf_xof(kdf::KEM, &secret, b"", &mut xof);
    assert_eq!(xof[..32], kdf(kdf::KEM, &secret, b"").expose()[..], "XOF extends kdf");
    cases.push(case("kem xof 96", SPEC).with("purpose", kdf::KEM).with("secret", hex(&secret)).with("input", "").with("out", hex(&xof)));
    let dedup = osis_crypto::dedup_secret(&secret);
    cases.push(
        case("dedup", "spec/crypto.md §3").with("derive-key-context", kdf::DEDUP).with("material", hex(&secret)).with("out", hex(dedup.expose())),
    );
    VecFile { header: generated_header("kdf", SPEC), cases }
}
