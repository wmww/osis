//! `token/`: delete tokens, token hashes and prefix commitments (spec/crypto.md §7). Generated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_crypto::*;

const SPEC: &str = "spec/crypto.md §7";

pub fn tokens() -> VecFile {
    let mut cases = Vec::new();
    let (salt, prefix_salt) = ([0x12u8; 16], [0x13u8; 16]);
    for (level, secret) in [(1u8, 0x14u8), (2, 0x15), (3, 0x16)] {
        let t = delete_token(&s32(secret), &salt);
        let th = token_hash(t.expose());
        let c = commitment(level, &th, &prefix_salt).unwrap();
        assert!(verify_presented_token(t.expose(), &c, &prefix_salt));
        cases.push(
            case(&format!("delete token level {level}"), SPEC)
                .with("secret", hex(s32(secret).expose()))
                .with("salt", hex(&salt))
                .with("token", hex(t.expose()))
                .with("token-hash", hex(&th))
                .with("level", level.to_string())
                .with("prefix-salt", hex(&prefix_salt))
                .with("commitment", hex(&c)),
        );
    }
    VecFile { header: generated_header("token", SPEC), cases }
}
