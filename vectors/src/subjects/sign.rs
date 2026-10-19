//! `sign/`: Ed25519 signatures over `domain || digest` for every signature domain, and the label
//! open signature (spec/crypto.md §2, spec/wire.md §11.2). Generated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_core::LabelId;
use osis_crypto::*;

const SPEC: &str = "spec/crypto.md §2";

pub fn signatures() -> VecFile {
    let mut cases = Vec::new();
    let sk = SigningSecret::from_seed(&s32(0x08));
    let pk = sk.verifying_key();
    let digest = [0x17u8; 32];
    for d in Domain::ALL {
        let sig = sk.sign(d, &digest);
        assert_eq!(pk.verify(d, &digest, &sig), Ok(()));
        cases.push(
            case(d.as_str(), SPEC)
                .with("domain", d.as_str())
                .with("seed", hex(s32(0x08).expose()))
                .with("public", hex(&pk.to_bytes()))
                .with("digest", hex(&digest))
                .with("signature", hex(&sig.0)),
        );
    }
    let (l, c, s) = (LabelId([0x0a; 16]), [0x18u8; 32], [0x19u8; 32]);
    cases.push(
        case("label open", "spec/wire.md §11.2")
            .with("seed", hex(s32(0x08).expose()))
            .with("label-id", hex(&l.0))
            .with("challenge", hex(&c))
            .with("static-key", hex(&s))
            .with("digest", hex(&open_digest(&l, &c, &s)))
            .with("signature", hex(&sign_open(&sk, &l, &c, &s).0)),
    );
    VecFile { header: generated_header("sign", SPEC), cases }
}
