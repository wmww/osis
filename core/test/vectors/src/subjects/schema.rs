//! `schema/`: canonical encodings of core aspect values written through their typed keys
//! (spec/data-model.md §9). Generated; each sample is checked against the core schema as it goes.

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{CommitId, CreationRecord, Limits, SyncId, Role, Tid, Value, Time, decode, encode};
use osis_schema::core_types::*;
use osis_schema::{RawKey, Schema, Type, core_schema, validate_write};
use std::collections::{BTreeMap, BTreeSet};

const SPEC: &str = "spec/data-model.md §9";

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}
fn epoch(n: u64) -> Epoch {
    Epoch { n, nonce: [8; 32] }
}
/// (case, AK, value) per core aspect a commit writes; inputs are repeated bytes.
fn samples() -> Vec<(&'static str, &'static str, Value)> {
    let holders: Holders = BTreeMap::from([
        (tid(5).into(), Grant { role: Role::Write, until: Some(Time(1_700_000_000_000)), may_grant: true, retain: false, floor: None }),
        (tid(7).into(), Grant { role: Role::Admin, until: None, may_grant: false, retain: false, floor: None }),
    ]);
    let keys = Keys {
        read: Some(Keyset { epoch: epoch(1), kem_key: Some(KemKey::X25519MlKem768(vec![9; 1216])), suite: 1, supersedes: BTreeSet::from([epoch(0)]), names: [6; 32], left_out: BTreeMap::from([(tid(11).into(), BTreeMap::from([(epoch(2), BTreeSet::from([CommitId([14; 32])]))]))]), demotions: BTreeSet::from([CommitId([7; 32])]), demotes: true, claim: None }),
        deposit_seed: Some([12; 32]),
        sealed: BTreeMap::from([(BoxKey { holder: tid(12).into(), role: Role::Read, epoch: epoch(1) }, BTreeSet::from([epoch(3)]))]),
        step: Some(StepKeys { delete: SigningKey::Ed25519(vec![8; 32]), write: SigningKey::Ed25519(vec![17; 32]), read: Some(ReadKey { epoch: epoch(1), kem_key: Some(KemKey::X25519MlKem768(vec![18; 1216])) }) }),
        ..Keys::default()
    };
    let secrets = Secrets {
        boxes: BTreeMap::from([
            (
                BoxKey { holder: tid(13).into(), role: Role::Read, epoch: epoch(2) },
                SecretBox::Sealed(SealedBox { keyset: Some(epoch(1)), suite: 1, sealed: Sealed::X25519MlKem768(vec![15; 40]) }),
            ),
            (BoxKey { holder: tid(13).into(), role: Role::Write, epoch: epoch(2) }, SecretBox::Symmetric(SymmetricBox { epoch: epoch(1), wrap: vec![16; 48] })),
        ]),
        history: BTreeMap::from([(HistoryKey { role: Role::Read, epoch: epoch(1) }, vec![17; 64])]),
    };
    let sync_ids: SyncIds = BTreeMap::from([(SyncId([22; 16]), SyncEntry { steps: BTreeMap::from([([23; 32], StepRecord { step: vec![24; 10], endorsements: BTreeMap::new() })]) })]);
    vec![
        ("created thing", "created.0", CREATED.encode(&CreationRecord::with_admin(tid(1), [2; 32]))),
        ("created with a key", "created.0", CREATED.encode(&CreationRecord::with_key(osis_base::SignKey([3; 32]), [4; 32]))),
        ("holders", "roles.0", ROLES.encode(&holders)),
        ("keys", "keys.0", KEYS.encode(&keys)),
        ("secrets", "secrets.0", SECRETS.encode(&secrets)),
        ("sync", "sync.0", SYNC.encode(&sync_ids)),
        ("name", "name.0", NAME.encode(&"Trip".to_string())),
        ("body", "body.0", BODY.encode(&"# Plan\n".to_string())),
        ("tag", "tag.0", TAG.encode(&Tag { color: Some("#ff8800".into()) })),
        ("dial", "dial.0", DIAL.encode(&BTreeMap::from([(tid(36).into(), Dial { key: vec![36; 32], urls: vec!["peer://203.0.113.7:4040".to_string()] })]))),
        ("settings", "settings^.0", SETTINGS.encode(&tid(37).into())),
        ("caps", "caps^.0", CAPS.encode(&BTreeMap::from([(tid(38).into(), Caps { policy: BTreeMap::from([("cap_bytes".to_string(), 1000)]), things: BTreeMap::from([(tid(33).into(), ThingCaps { entries: 5, bytes: 6 })]) })]))),
        ("clients", "clients^.0", CLIENTS.encode(&BTreeMap::from([(tid(34).into(), Client { secret_hash: [35; 32], until: Some(Time(1_700_000_000_000)) })]))),
    ]
}

/// `v` decoded and re-encoded through the typed key of `ak`.
fn through_key(ak: &str, v: &Value) -> Value {
    match ak {
        "created.0" => CREATED.encode(&CREATED.decode(v).unwrap()),
        "roles.0" => ROLES.encode(&ROLES.decode(v).unwrap()),
        "keys.0" => KEYS.encode(&KEYS.decode(v).unwrap()),
        "secrets.0" => SECRETS.encode(&SECRETS.decode(v).unwrap()),
        "sync.0" => SYNC.encode(&SYNC.decode(v).unwrap()),
        "name.0" => NAME.encode(&NAME.decode(v).unwrap()),
        "body.0" => BODY.encode(&BODY.decode(v).unwrap()),
        "tag.0" => TAG.encode(&TAG.decode(v).unwrap()),
        "dial.0" => DIAL.encode(&DIAL.decode(v).unwrap()),
        "settings^.0" => SETTINGS.encode(&SETTINGS.decode(v).unwrap()),
        "caps^.0" => CAPS.encode(&CAPS.decode(v).unwrap()),
        "clients^.0" => CLIENTS.encode(&CLIENTS.decode(v).unwrap()),
        _ => panic!("{ak}: no typed key here"),
    }
}

/// Every struct in `v` (a Rust type's encoding, which writes every field) has exactly the field
/// IDs its schema type `ty` declares: schema/core.osis and core_types are written apart, so a
/// field one lacks fails here.
fn same_fields(sc: &Schema, v: &Value, ty: &Type, name: &str) {
    match (sc.expand(ty).unwrap().as_ref(), v) {
        (Type::Struct(st), Value::Map(m)) => {
            let ids: BTreeSet<Value> = st.fields.keys().map(|i| Value::Int(*i as i64)).collect();
            assert_eq!(m.keys().cloned().collect::<BTreeSet<_>>(), ids, "{name}: struct fields");
            for (i, f) in &st.fields {
                same_fields(sc, m.get(&Value::Int(*i as i64)).unwrap(), &f.ty, name);
            }
        }
        (Type::Map(_, t), Value::Map(m)) => m.values().for_each(|x| same_fields(sc, x, t, name)),
        (Type::List(t), Value::List(l)) => l.iter().for_each(|x| same_fields(sc, x, t, name)),
        (Type::Set(t), Value::Set(l)) => l.iter().for_each(|x| same_fields(sc, x, t, name)),
        _ => {}
    }
}

/// One case per core aspect sample.
pub fn core() -> VecFile {
    let s = core_schema();
    let mut cases = Vec::new();
    for (name, ak, v) in samples() {
        // a valid write of its aspect's type, with exactly its struct fields...
        if ak != "created.0" {
            let t = &s.aspects[ak].ty;
            validate_write(s, &v, t).unwrap_or_else(|e| panic!("{name}: {e}"));
            same_fields(s, &v, t, name);
        }
        // ...that survives the canonical round trip and its typed key
        assert_eq!(decode(&encode(&v), &Limits::DEFAULT).unwrap(), v, "{name}");
        assert_eq!(through_key(ak, &v), v, "{name}");
        cases.push(Record::new().with("case", name).with("spec", SPEC).with("ak", ak).with("value", hex(&encode(&v))));
    }
    VecFile { header: generated_header("schema", SPEC), cases }
}
