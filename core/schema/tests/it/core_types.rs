#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Core aspect Rust types and typed keys (spec/data-model.md §9, spec/wire.md §3). Canonical
//! encodings are the `schema/core` generator of osis-vectors.

use osis_base::{Ak, Classified, CommitId, CreationRecord, ErrorClass, LabelId, Limits, Role, Tid, Ts, Value, WallMs};
use osis_schema::core_types::*;
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}
fn epoch(n: u64) -> Epoch {
    Epoch { n, nonce: [8; 32] }
}

/// (vector name, AK, encoded sample) per core aspect a commit can write.
fn samples() -> Vec<(&'static str, &'static str, Value)> {
    let holders: Holders = BTreeMap::from([
        (tid(5), Edge { role: Role::Write, until: Some(WallMs(1_700_000_000_000)), invite: Some(Role::Read), tied: Some(Tie { ts: Ts::make(WallMs(1_700_000_000_000), 3).unwrap(), source: Source::Commit(CommitId([7; 32])), ctr: 2, subgroup: false }) }),
        (tid(7), Edge { role: Role::Admin, until: None, invite: None, tied: None }),
    ]);
    let keys = Keys {
        read: Some(Keyset { epoch: epoch(1), kem_key: KemKey::X25519MlKem768(vec![9; 1216]), suite: 1, delete_key: SigningKey::Ed25519(vec![8; 32]), supersedes: BTreeSet::from([epoch(0)]), possession_key: SigningKey::Ed25519(vec![7; 32]), names: [6; 32] }),
        inbox: Some(Inbox { label: LabelId([10; 16]), hosts: vec![Address { url: "quic://s.example:4433".into(), key: [11; 32] }] }),
        deposit_seed: Some([12; 32]),
        ..Keys::default()
    };
    let secrets = Secrets {
        boxes: BTreeMap::from([
            (
                BoxKey { holder: tid(13), role: Role::Read, epoch: epoch(2) },
                SecretBox::Sealed(SealedBox { keyset: Some(epoch(1)), suite: 1, sealed: Sealed::X25519MlKem768(vec![15; 40]) }),
            ),
            (BoxKey { holder: tid(13), role: Role::Write, epoch: epoch(2) }, SecretBox::Symmetric(SymmetricBox { epoch: epoch(1), wrap: vec![16; 48], possession: Some(Signature::Ed25519(vec![17; 64])) })),
        ]),
        history: BTreeMap::from([(HistoryKey { role: Role::Read, epoch: epoch(1) }, vec![17; 64])]),
    };
    let labels: Labels = BTreeMap::from([(
        LabelId([22; 16]),
        Label { index: 0, steps: BTreeMap::from([([23; 32], StepRecord { step: vec![24; 10], claims: None })]), hosts: vec![], replaced: false },
    )]);
    vec![
        ("created thing", "created.0", CREATED.encode(&CreationRecord::Thing { admin: tid(1), nonce: [2; 32] })),
        ("created key actor", "created.0", CREATED.encode(&CreationRecord::KeyActor { alg: 1, public_key: vec![3; 32], nonce: [4; 32] })),
        ("holders", "roles.0", ROLES.encode(&holders)),
        ("keys", "keys.0", KEYS.encode(&keys)),
        ("secrets", "secrets.0", SECRETS.encode(&secrets)),
        ("label", "label.0", LABEL.encode(&labels)),
        ("node", "node.0", NODE.encode(&NodeInfo { software: "osis 0.1.0".into() })),
        ("reach", "reach.0", REACH.encode(&Reach { dialable: [27; 32], items: vec!["https://relay.example".into()], lan_secret: [28; 32] })),
        ("seen", "seen.0", SEEN.encode(&Seen { ts: WallMs(1_700_000_000_000), stranded: false, suspect: Default::default() })),
        ("host", "host.0^", HOST.encode(&Host {
            listen: vec!["quic://0.0.0.0:7400".into()],
            admit: Admit::Open,
            labels: BTreeSet::from([LabelId([31; 16])]),
            replicate: vec![Address { url: "quic://b:7400".into(), key: [32; 32] }],
            policy: BTreeMap::from([("cap_bytes".to_string(), 1000)]),
            caps: BTreeMap::from([(LabelId([33; 16]), HostCaps { entries: 5, bytes: 6 })]),
        })),
        ("clients", "clients.0^", CLIENTS.encode(&BTreeMap::from([(tid(34), Client { secret_hash: [35; 32], until: Some(WallMs(1_700_000_000_000)) })]))),
        ("group", "group.0", GROUP.encode(&Group { items: BTreeSet::from([tid(29)]), subgroups: BTreeSet::from([tid(30)]) })),
    ]
}

#[test]
fn core_aspects_round_trip_spec_data_model_9() {
    let sc = core_schema();
    for (name, ak, v) in samples() {
        // Every sample is a valid write of its aspect's schema type...
        if ak != "created.0" {
            validate_write(sc, &v, &sc.aspects[ak].ty).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        // ...and survives the canonical round trip through its typed key.
        let bytes = osis_base::encode(&v);
        let back = osis_base::decode(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(back, v);
    }
    let samples = samples();
    let decoded = |ak: &str, v: &Value| -> Value {
        match ak {
            "created.0" => CREATED.encode(&CREATED.decode(v).unwrap()),
            "roles.0" => ROLES.encode(&ROLES.decode(v).unwrap()),
            "keys.0" => KEYS.encode(&KEYS.decode(v).unwrap()),
            "secrets.0" => SECRETS.encode(&SECRETS.decode(v).unwrap()),
            "label.0" => LABEL.encode(&LABEL.decode(v).unwrap()),
            "node.0" => NODE.encode(&NODE.decode(v).unwrap()),
            "reach.0" => REACH.encode(&REACH.decode(v).unwrap()),
            "seen.0" => SEEN.encode(&SEEN.decode(v).unwrap()),
            "host.0^" => HOST.encode(&HOST.decode(v).unwrap()),
            "clients.0^" => CLIENTS.encode(&CLIENTS.decode(v).unwrap()),
            "group.0" => GROUP.encode(&GROUP.decode(v).unwrap()),
            _ => panic!("{ak}"),
        }
    };
    for (_, ak, v) in &samples {
        assert_eq!(&decoded(ak, v), v, "{ak}");
    }
}

#[test]
fn fixed_lengths_and_unknown_cases_spec_wire_3() {
    // A KEM key of the wrong length is malformed.
    let short = Value::Enum(1, Some(Box::new(Value::Bytes(vec![0; 10]))));
    let e = KemKey::from_value(&short).unwrap_err();
    assert_eq!(e.class(), ErrorClass::BadInput);
    // An unknown agility case is newer data: parked.
    let e = KemKey::from_value(&Value::Enum(2, Some(Box::new(Value::Bytes(vec![]))))).unwrap_err();
    assert_eq!((e.kind.clone(), e.class()), (PathErrorKind::UnknownCase(2), ErrorClass::Parked));
    // An unknown role case in a holder edge: parked, with the path.
    let mut m = ROLES.encode(&BTreeMap::from([(tid(1), Edge { role: Role::Read, until: None, invite: None, tied: None })]));
    if let Value::Map(mm) = &mut m {
        let e = mm.get_mut(&Value::Tid(tid(1))).unwrap();
        if let Value::Map(f) = e {
            f.insert(Value::Int(0), Value::Enum(9, None));
        }
    }
    let e = ROLES.decode(&m).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::UnknownCase(9));
    assert_eq!(e.path, p![tid(1), FieldId(0)]);
    // created.0: an unknown signing key case parks; both admin and key is bad input.
    let rec = CreationRecord::KeyActor { alg: 1, public_key: vec![3; 32], nonce: [4; 32] }.to_value();
    let Value::Map(mut f) = rec else { panic!() };
    f.insert(Value::Int(1), Value::Enum(7, Some(Box::new(Value::Bytes(vec![0; 40])))));
    assert_eq!(CREATED.decode(&Value::Map(f.clone())).unwrap_err().class(), ErrorClass::Parked);
    f.insert(Value::Int(1), Value::Enum(1, Some(Box::new(Value::Bytes(vec![3; 32])))));
    f.insert(Value::Int(0), Value::Tid(tid(1)));
    assert_eq!(CREATED.decode(&Value::Map(f)).unwrap_err().class(), ErrorClass::BadInput);
    // Reader defaults: an keys.0 written with only some fields reads with none for the rest.
    let k = KEYS.decode(&Value::Map(osis_base::ValueMap::new())).unwrap();
    assert_eq!(k, Keys::default());
}

#[test]
fn key_defaults_and_identity_spec_commits_5() {
    let m = ROLES.defaults();
    assert_eq!((m.retention.by, m.retention.history, m.expires), (PurgeBy::Admin, None, None));
    for ak in ROLE_CLASS {
        let a = &core_schema().aspects[ak];
        assert_eq!((a.retention.by, a.retention.history), (PurgeBy::Admin, None), "{ak}");
        assert!(is_role_class(ak));
    }
    assert!(!is_role_class("group.0"));
    assert_eq!(CREATED.defaults().retention, osis_schema::Retention { by: PurgeBy::Nobody, history: Some(osis_schema::History::FOREVER) });
    assert_eq!(SEEN.defaults(), AspectDefaults::default());
    assert!(GROUP.schema().is_some_and(Schema::declares_core));
    let untyped = Ak::new("x:y.0").unwrap();
    assert!(untyped.schema().is_none());
    assert_eq!(untyped.defaults(), AspectDefaults::default());
    assert_eq!(RawKey::decode(&untyped, &Value::Int(3)).unwrap(), Value::Int(3));
    assert!(core_schema().aspects["tid.0"].flags.contains(&Flag::Synthetic));
    assert!(core_schema().aspects["created.0"].flags.contains(&Flag::Guaranteed));
}
