#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Core aspect Rust types and typed keys (spec/data-model.md §9, spec/wire.md §3). Canonical
//! encodings are vectors/schema/core.vec (osis-vectors).

use osis_core::format::{CORE_SCHEMA_ID, CORE_SCHEMA_REVISION, MEMBERSHIP_KEEP_MS};
use osis_core::{Ak, Classified, CommitId, CreationRecord, ErrorClass, LabelId, Limits, Link, BlobId, Role, SchemaId, Tid, Ts, Value, WallMs};
use osis_schema::core_types::*;
use osis_schema::*;
use std::collections::{BTreeMap, BTreeSet};

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}
fn epoch(n: u64) -> Epoch {
    Epoch { n, nonce: [8; 16] }
}
fn edge_key() -> EdgeKey {
    EdgeKey { ts: Ts::make(WallMs(1_700_000_000_000), 3).unwrap(), node: tid(6) }
}

/// (vector name, AK, encoded sample) per core aspect a commit can write.
fn samples() -> Vec<(&'static str, &'static str, Value)> {
    let members: Members = BTreeMap::from([
        (tid(5), Edge { role: Role::Write, until: Some(WallMs(1_700_000_000_000)), invite: Some(Role::Read), since: Some(edge_key()) }),
        (tid(7), Edge { role: Role::Admin, until: None, invite: None, since: None }),
    ]);
    let keys = Keys {
        read: Some(Keyset { epoch: epoch(1), kem_key: KemKey::X25519MlKem768(vec![9; 1216]), suite: 1 }),
        inbox: Some(Inbox { label: LabelId([10; 16]), servers: vec![Address { url: "quic://s.example:4433".into(), key: [11; 32] }] }),
        deposit_seed: Some([12; 32]),
        ..Keys::default()
    };
    let secrets = Secrets {
        boxes: BTreeMap::from([
            (
                BoxKey { member: tid(13), role: Role::Read, epoch: epoch(2) },
                SecretBox::Sealed(SealedBox { keyset: Some(epoch(1)), suite: 1, sealed: Sealed::X25519MlKem768(vec![15; 40]) }),
            ),
            (BoxKey { member: tid(13), role: Role::Write, epoch: epoch(2) }, SecretBox::Symmetric(SymmetricBox { epoch: epoch(1), wrap: vec![16; 48] })),
        ]),
        history: BTreeMap::from([(HistoryKey { role: Role::Read, epoch: epoch(1) }, vec![17; 64])]),
    };
    let frontier = Frontier {
        writes: BTreeMap::from([(tid(19), BTreeMap::from([("/note/body".to_string(), BTreeMap::from([(tid(20), 3)]))]))]),
        commits: BTreeSet::from([CommitId([21; 32])]),
    };
    let tenures = Tenures(vec![Tenure { member: tid(18), role: Role::Write, since: None, until: edge_key(), frontier: Some(Chunked::Inline(frontier)) }]);
    let labels: Labels = BTreeMap::from([(
        LabelId([22; 16]),
        Label { index: 0, steps: BTreeMap::from([([23; 32], StepRecord { step: vec![24; 10], claims: None })]), servers: vec![], replaced: false },
    )]);
    vec![
        ("created thing", "/created", CREATED.encode(&CreationRecord::Thing { owner: tid(1), nonce: [2; 32] })),
        ("created key actor", "/created", CREATED.encode(&CreationRecord::KeyActor { alg: 1, public_key: vec![3; 32], nonce: [4; 32] })),
        ("members", "/members", MEMBERS.encode(&members)),
        ("keys", "/keys", KEYS.encode(&keys)),
        ("secrets", "/secrets", SECRETS.encode(&secrets)),
        ("tenures", "/tenures", TENURES.encode(&tenures)),
        ("label", "/label", LABEL.encode(&labels)),
        ("moved", "/moved", MOVED.encode(&tid(25))),
        ("was", "/was", WAS.encode(&tid(26))),
        ("node", "/node", NODE.encode(&NodeInfo { software: "osis 0.1.0".into(), schemas: BTreeMap::from([(SchemaId([0; 16]), 1)]) })),
        ("reach", "/reach", REACH.encode(&Reach { dialable: [27; 32], relays: vec!["https://relay.example".into()], lan_secret: [28; 32] })),
        ("seen", "/seen", SEEN.encode(&Seen { ts: WallMs(1_700_000_000_000), stranded: false })),
        ("group", "/group", GROUP.encode(&Group { items: BTreeSet::from([tid(29)]), subgroups: BTreeSet::from([tid(30)]) })),
    ]
}

#[test]
fn core_aspects_round_trip_spec_data_model_9() {
    let sc = core_schema();
    for (name, ak, v) in samples() {
        // Every sample is a valid write of its aspect's schema type...
        if ak != "/created" {
            validate_write(sc, &v, &sc.aspects[ak].ty).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        // ...and survives the canonical round trip through its typed key.
        let bytes = osis_core::encode(&v);
        let back = osis_core::decode(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(back, v);
    }
    let samples = samples();
    let decoded = |ak: &str, v: &Value| -> Value {
        match ak {
            "/created" => CREATED.encode(&CREATED.decode(v).unwrap()),
            "/members" => MEMBERS.encode(&MEMBERS.decode(v).unwrap()),
            "/keys" => KEYS.encode(&KEYS.decode(v).unwrap()),
            "/secrets" => SECRETS.encode(&SECRETS.decode(v).unwrap()),
            "/tenures" => TENURES.encode(&TENURES.decode(v).unwrap()),
            "/label" => LABEL.encode(&LABEL.decode(v).unwrap()),
            "/moved" => MOVED.encode(&MOVED.decode(v).unwrap()),
            "/was" => WAS.encode(&WAS.decode(v).unwrap()),
            "/node" => NODE.encode(&NODE.decode(v).unwrap()),
            "/reach" => REACH.encode(&REACH.decode(v).unwrap()),
            "/seen" => SEEN.encode(&SEEN.decode(v).unwrap()),
            "/group" => GROUP.encode(&GROUP.decode(v).unwrap()),
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
    // An unknown role case in a member edge: parked, with the path.
    let mut m = MEMBERS.encode(&BTreeMap::from([(tid(1), Edge { role: Role::Read, until: None, invite: None, since: None })]));
    if let Value::Map(mm) = &mut m {
        let e = mm.get_mut(&Value::Tid(tid(1))).unwrap();
        if let Value::Map(f) = e {
            f.insert(Value::Int(0), Value::Enum(9, None));
        }
    }
    let e = MEMBERS.decode(&m).unwrap_err();
    assert_eq!(e.kind, PathErrorKind::UnknownCase(9));
    assert_eq!(e.path, p![tid(1), FieldId(0)]);
    // /created: an unknown signing key case parks; both owner and key is bad input.
    let rec = CreationRecord::KeyActor { alg: 1, public_key: vec![3; 32], nonce: [4; 32] }.to_value();
    let Value::Map(mut f) = rec else { panic!() };
    f.insert(Value::Int(1), Value::Enum(7, Some(Box::new(Value::Bytes(vec![0; 40])))));
    assert_eq!(CREATED.decode(&Value::Map(f.clone())).unwrap_err().class(), ErrorClass::Parked);
    f.insert(Value::Int(1), Value::Enum(1, Some(Box::new(Value::Bytes(vec![3; 32])))));
    f.insert(Value::Int(0), Value::Tid(tid(1)));
    assert_eq!(CREATED.decode(&Value::Map(f)).unwrap_err().class(), ErrorClass::BadInput);
    // Reader defaults: an /keys written with only some fields reads with none for the rest.
    let k = KEYS.decode(&Value::Map(BTreeMap::new())).unwrap();
    assert_eq!(k, Keys::default());
}

#[test]
fn tenure_frontier_may_be_a_link_spec_data_model_6() {
    let link = Link { hash: [1; 32], blob: BlobId([2; 32]), suite: 1, key: [3; 32] };
    let t = Tenures(vec![Tenure { member: tid(1), role: Role::Admin, since: Some(edge_key()), until: edge_key(), frontier: Some(Chunked::Link(link)) }]);
    let v = TENURES.encode(&t);
    TENURES.validate(&v).unwrap();
    assert_eq!(TENURES.decode(&v).unwrap(), t);
}

#[test]
fn key_defaults_and_identity_spec_commits_5() {
    let m = MEMBERS.defaults();
    assert_eq!((m.retention.by, m.retention.at_least.rel, m.expires), (PurgeBy::Admin, Some(MEMBERSHIP_KEEP_MS), None));
    for ak in MEMBERSHIP_CLASS {
        let a = &core_schema().aspects[ak];
        assert_eq!((a.retention.by, a.retention.at_least.rel), (PurgeBy::Admin, Some(MEMBERSHIP_KEEP_MS)), "{ak}");
        assert!(is_membership_class(ak));
    }
    assert!(!is_membership_class("/group"));
    assert_eq!(CREATED.defaults().retention.by, PurgeBy::Nobody);
    assert_eq!(SEEN.defaults(), AspectDefaults::default());
    assert_eq!(GROUP.schema_ref(), Some((CORE_SCHEMA_ID, CORE_SCHEMA_REVISION)));
    let untyped = Ak::new("/x/y").unwrap();
    assert_eq!((untyped.schema_ref(), untyped.defaults()), (None, AspectDefaults::default()));
    assert_eq!(untyped.decode(&Value::Int(3)).unwrap(), Value::Int(3));
    assert!(core_schema().aspects["/tid"].flags.contains(&Flag::Synthetic));
    assert!(core_schema().aspects["/created"].flags.contains(&Flag::Guaranteed));
}
