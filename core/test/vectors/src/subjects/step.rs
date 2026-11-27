//! `step/`: registration steps (spec/wire.md §8, spec/sync-ids.md §3). Generated.
//! Secrets: write `0b`, admin `09` (also the genesis seed), deposit seed `0c`, sync `0d`; a child's
//! step key is an input.

use super::{case, generated_header, s32};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::SyncId;
use osis_crypto::{RoleKey, X25519Secret, role_key};
use osis_blob::{Step, StepKeys, genesis, genesis_sync_id, register};

const SPEC: &str = "spec/wire.md §8";

fn step_fields(r: Record, s: &Step) -> Record {
    r.with("sync-id", hex(&s.sync_id.0))
        .with("sync-pk", hex(&s.keys.sync.to_bytes()))
        .with("write-pk", hex(&s.keys.write.to_bytes()))
        .with("delete-pk", hex(&s.keys.delete.to_bytes()))
        .with("deposit-pk", hex(&s.keys.deposit.to_bytes()))
        .with("step-key", hex(&s.step_key))
        .with("signed-digest", hex(&s.digest()))
        .with("step", hex(&s.to_bytes()))
        .with("step-id", hex(&s.id().0))
}

pub fn steps() -> VecFile {
    let (write, admin, deposit, sync) = (s32(0x0b), s32(0x09), s32(0x0c), s32(0x0d));
    let sync_id = genesis_sync_id(&admin);
    let keys = StepKeys::derive(&sync, &write, &admin, &deposit, &sync_id);
    let delete0 = role_key(RoleKey::Delete, &admin);
    // the genesis step: deterministic from its genesis seed (spec/wire.md §8)
    let g0 = genesis(&admin);
    g0.verify_genesis().unwrap();
    assert_eq!(g0.sync_id, sync_id);
    let mut cases = vec![step_fields(case("genesis step", SPEC).with("genesis-seed", hex(admin.expose())), &g0)];
    let sk = X25519Secret::from_secret(&s32(0x31)).public();
    let s0 = register(&g0, &delete0, keys, sk).unwrap();
    s0.verify_child(&g0).unwrap();
    cases.push(step_fields(
        case("first step", SPEC)
            .with("parent-step-id", hex(&g0.id().0))
            .with("signer-admin-secret", hex(admin.expose()))
            .with("sync-secret", hex(sync.expose()))
            .with("write-secret", hex(write.expose()))
            .with("admin-secret", hex(admin.expose()))
            .with("deposit-seed", hex(deposit.expose())),
        &s0,
    ));

    // Child step: a rotation of every role (secrets 1b, 19, sync 1d), signed by the first step's
    // delete key.
    let (w1, a1, y1) = (s32(0x1b), s32(0x19), s32(0x1d));
    let keys1 = StepKeys::derive(&y1, &w1, &a1, &deposit, &sync_id);
    let sk1 = X25519Secret::from_secret(&s32(0x41)).public();
    let s1 = register(&s0, &delete0, keys1, sk1).unwrap();
    s1.verify_child(&s0).unwrap();
    cases.push(step_fields(
        case("child step", SPEC)
            .with("parent-step-id", hex(&s0.id().0))
            .with("signer-admin-secret", hex(admin.expose()))
            .with("sync-secret", hex(y1.expose()))
            .with("write-secret", hex(w1.expose()))
            .with("admin-secret", hex(a1.expose()))
            .with("deposit-seed", hex(deposit.expose())),
        &s1,
    ));

    // Rejections.
    let mut t = s1.clone();
    t.sig = s0.sig;
    assert!(t.verify_child(&s0).is_err());
    cases.push(case("child step with a wrong signature", SPEC).with("parent", hex(&s0.to_bytes())).with("step", hex(&t.to_bytes())).with("reject", "step-signature"));
    let mut g = g0.clone();
    g.sync_id = SyncId([0; 16]);
    assert!(g.verify_genesis().is_err());
    cases.push(case("genesis step of another sync ID", SPEC).with("step", hex(&g.to_bytes())).with("reject", "sync-id"));
    VecFile { header: generated_header("step", SPEC), cases }
}
