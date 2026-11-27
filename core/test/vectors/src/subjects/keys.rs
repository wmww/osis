//! `keys/`: keys derived from seeds and secrets (spec/crypto.md §3, §6, spec/sync-ids.md §2, spec/sync-transport.md §4,
//! spec/wire.md §6, §8). Generated. Ed25519 keys are RFC 8032 keys from the 32-byte seed shown
//! or derived as stated.

use super::{case, generated_header, s32};
use crate::file::VecFile;
use crate::hex;
use osis_base::{SyncId, Role, Tid, encode};
use osis_crypto::*;

pub fn seed() -> VecFile {
    let seed = s32(0x05);
    let signing = signing_key(&seed);
    let mut cases = Vec::new();
    let mut c = case("signing key and link key from seed", "spec/crypto.md §3")
        .with("seed", hex(seed.expose()))
        .with("ed25519-public", hex(&signing.verifying_key().to_bytes()))
        .with("signing-key-value", hex(&encode(&signing.verifying_key().to_value())))
        .with("creation-nonce", hex(&creation_nonce(&seed)));
    for (n, r) in [("read", Role::Read), ("write", Role::Write), ("admin", Role::Admin)] {
        c = c.with(&format!("link-role-secret-{n}"), hex(link_key_role_secret(&seed, r).expose()));
    }
    let kem = role_kem(&link_key_role_secret(&seed, Role::Read));
    c = c.with("link-read-kem-public", hex(kem.public().as_bytes())).with("kem-key-value", hex(&encode(&kem.public().to_value()))).with("x25519-public", hex(&kem.public().x25519()));
    cases.push(c);

    let tid = Tid::from_bytes([0x01; 15]);
    let mut c = case("dependent thing secrets", "spec/crypto.md §3").with("base-secret", hex(seed.expose())).with("tid", hex(tid.as_bytes()));
    for (n, r) in [("read", Role::Read), ("write", Role::Write), ("admin", Role::Admin)] {
        c = c.with(&format!("thing-secret-{n}"), hex(thing_role_secret(&seed, r, &tid).expose()));
    }
    c = c.with("read-kem-public", hex(role_kem(&thing_role_secret(&seed, Role::Read, &tid)).public().as_bytes()));
    cases.push(c);

    let sync_id = SyncId([0x0a; 16]);
    let (sync_secret, roles) = (s32(0x06), roles_secret(&s32(0x08)));
    let ck = osis_crypto::claim_key(&sync_secret, &roles);
    let step_key = ck.public();
    let holder = claim(&ck, &kem.public().x25519(), &sync_id, &step_key).unwrap();
    let by_holder = claim(kem.x25519(), &step_key, &sync_id, &step_key).unwrap();
    assert_eq!(holder.verifying_key(), by_holder.verifying_key(), "both sides derive one claim");
    cases.push(
        case("claim key and claim", "spec/wire.md §8")
            .with("holder-read-secret", hex(link_key_role_secret(&seed, Role::Read).expose()))
            .with("sync-secret", hex(sync_secret.expose()))
            .with("roles-secret", hex(roles.expose()))
            .with("step-key", hex(&step_key))
            .with("sync-id", hex(&sync_id.0))
            .with("claim-public", hex(&holder.verifying_key().to_bytes()))
            .with("public-claim", hex(&public_claim(&sync_id, &step_key).verifying_key().to_bytes())),
    );
    {
        let mut c = case("role keys", "spec/sync-ids.md §2").with("secret", hex(seed.expose()));
        for (n, r) in [("sync", RoleKey::Sync), ("write", RoleKey::Write), ("delete", RoleKey::Delete)] {
            c = c.with(&format!("{n}-public"), hex(&role_key(r, &seed).verifying_key().to_bytes()));
        }
        c = c.with("sync-proof", hex(&osis_crypto::kdf::sync_proof(&osis_crypto::role_key_seed(RoleKey::Sync, &seed))));
        let id = osis_crypto::sync_id(&role_key(RoleKey::Delete, &seed).verifying_key());
        c = c.with("sync-id-from-delete", hex(&id.0)).with("deposit-seed", hex(seed.expose())).with("deposit-public", hex(&deposit_key(&seed, &id).verifying_key().to_bytes()));
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
    VecFile { header: generated_header("keys", "spec/crypto.md §3"), cases }
}
