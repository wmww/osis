//! `keys/`: keys derived from seeds and secrets (spec/crypto.md §3, §6, spec/sync.md §2, §10,
//! spec/wire.md §6, §8). Generated. Ed25519 keys are RFC 8032 keys from the 32-byte seed shown
//! or derived as stated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_core::{LabelId, Role, Tid, encode};
use osis_crypto::*;

pub fn seed() -> VecFile {
    let seed = s32(0x05);
    let k = KeyActorKeys::from_seed(&seed);
    let mut cases = Vec::new();
    let mut c = case("key actor from seed", "spec/crypto.md §3")
        .with("seed", hex(seed.expose()))
        .with("ed25519-public", hex(&k.signing.verifying_key().to_bytes()))
        .with("signing-key-value", hex(&encode(&k.signing.verifying_key().to_value())))
        .with("kem-public", hex(k.kem.public().as_bytes()))
        .with("kem-key-value", hex(&encode(&k.kem.public().to_value())))
        .with("x25519-public", hex(&k.kem.public().x25519()))
        .with("creation-nonce", hex(&creation_nonce(&seed)));
    for (n, r) in [("read", Role::Read), ("write", Role::Write), ("admin", Role::Admin)] {
        c = c.with(&format!("role-secret-{n}"), hex(key_actor_role_secret(&seed, r).expose()));
    }
    cases.push(c);

    let tid = Tid::from_bytes([0x01; 15]);
    let mut c = case("plain thing secrets", "spec/crypto.md §3").with("owner-secret", hex(seed.expose())).with("tid", hex(tid.as_bytes()));
    for (n, r) in [("read", Role::Read), ("write", Role::Write), ("admin", Role::Admin)] {
        c = c.with(&format!("thing-secret-{n}"), hex(thing_role_secret(&seed, r, &tid).expose()));
    }
    c = c.with("read-kem-public", hex(role_kem(&thing_role_secret(&seed, Role::Read, &tid)).public().as_bytes()));
    cases.push(c);

    let label = LabelId([0x0a; 16]);
    let step = X25519Secret::from_secret(&s32(0x06));
    let claim = claim_key(&step, &k.kem.public().x25519(), &label, &step.public()).unwrap();
    let by_member = claim_key(k.kem.x25519(), &step.public(), &label, &step.public()).unwrap();
    assert_eq!(claim.verifying_key(), by_member.verifying_key(), "both sides derive one claim key");
    cases.push(
        case("claim key", "spec/sync.md §2")
            .with("member-seed", hex(seed.expose()))
            .with("step-private", hex(s32(0x06).expose()))
            .with("step-key", hex(&step.public()))
            .with("label-id", hex(&label.0))
            .with("claim-public", hex(&claim.verifying_key().to_bytes())),
    );
    cases.push(
        case("static entry", "spec/wire.md §8")
            .with("label-id", hex(&label.0))
            .with("signing-key", hex(&k.signing.verifying_key().to_bytes()))
            .with("entry", hex(&static_entry(&label, &k.signing.verifying_key()))),
    );
    for i in [0u64, 1] {
        let mut c = case(&format!("label keys index {i}"), "spec/sync.md §2").with("secret", hex(seed.expose())).with("index", i.to_string());
        for (n, r) in [("sync", LabelRole::Sync), ("write", LabelRole::Write), ("delete", LabelRole::Delete)] {
            c = c.with(&format!("{n}-public"), hex(&label_role_key(r, &seed, i).verifying_key().to_bytes()));
        }
        let id = label_id(&label_role_key(LabelRole::Delete, &seed, i).verifying_key());
        c = c.with("label-id-from-delete", hex(&id.0)).with("deposit-seed", hex(seed.expose())).with("deposit-public", hex(&deposit_key(&seed, &id).verifying_key().to_bytes()));
        cases.push(c);
    }

    let d = s32(0x07);
    let (a, b) = (link_hash(&d, b"chunk a"), link_hash(&d, b"chunk b"));
    cases.push(case("delta hash", "spec/crypto.md §6").with("dedup", hex(d.expose())).with("delta", hex(b"delta")).with("hash", hex(&delta_hash(&d, b"delta"))));
    cases.push(
        case("link hashes", "spec/wire.md §6")
            .with("dedup", hex(d.expose()))
            .with("chunk-a", hex(b"chunk a"))
            .with("chunk-b", hex(b"chunk b"))
            .with("link-a", hex(&a))
            .with("link-b", hex(&b))
            .with("tree-level", "1")
            .with("tree-lens", "7,7")
            .with("tree-ab", hex(&link_tree_hash(&d, 1, &[(a, 7), (b, 7)]))),
    );
    cases.push(case("lan tag", "spec/sync.md §10").with("lan-secret", hex(d.expose())).with("unix-ms", "1234567890123").with("tag", hex(&lan_tag(&d, 1_234_567_890_123))));
    VecFile { header: generated_header("keys", "spec/crypto.md §3"), cases }
}
