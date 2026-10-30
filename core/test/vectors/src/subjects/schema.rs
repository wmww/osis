//! `schema/`: the core schema as a `schema` value (spec/data-model.md §9, §10) and canonical
//! encodings of core aspect values written through their typed keys. Generated.

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{CommitId, CreationRecord, LabelId, Role, SchemaId, Tid, Ts, Value, WallMs, encode};
use osis_schema::core_types::*;
use osis_schema::{AspectKey, Chunked, core_schema};
use std::collections::{BTreeMap, BTreeSet};

const SPEC: &str = "spec/data-model.md §9";

fn tid(n: u8) -> Tid {
    Tid::from_bytes([n; 15])
}
fn epoch(n: u64) -> Epoch {
    Epoch { n, nonce: [8; 32] }
}
fn edge_key() -> EdgeKey {
    let ts = match Ts::make(WallMs(1_700_000_000_000), 3) {
        Some(t) => t,
        None => unreachable!("fixed input in range"),
    };
    EdgeKey { ts, node: tid(6), commit: CommitId([7; 32]) }
}

/// (case, AK, value) per core aspect a commit writes; inputs are repeated bytes.
fn samples() -> Vec<(&'static str, &'static str, Value)> {
    let members: Members = BTreeMap::from([
        (tid(5), Edge { role: Role::Write, until: Some(WallMs(1_700_000_000_000)), invite: Some(Role::Read), since: Some(edge_key()) }),
        (tid(7), Edge { role: Role::Admin, until: None, invite: None, since: None }),
    ]);
    let keys = Keys {
        read: Some(Keyset { epoch: epoch(1), kem_key: KemKey::X25519MlKem768(vec![9; 1216]), suite: 1, delete_key: SigningKey::Ed25519(vec![8; 32]) }),
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
        ("created thing", "/created", CREATED.encode(&CreationRecord::Thing { owner: tid(1), nonce: [2; 32], creator: None })),
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
        ("name", "/name", NAME.encode(&"Trip".to_string())),
        ("body", "/body", BODY.encode(&"# Plan\n".to_string())),
        ("tag", "/tag", TAG.encode(&Tag { color: Some("#ff8800".into()) })),
    ]
}

/// The core schema value and one case per core aspect sample.
pub fn core() -> VecFile {
    let s = core_schema();
    let mut cases = vec![
        Record::new()
            .with("case", "core schema")
            .with("spec", "spec/data-model.md §10")
            .with("id", hex(&s.id.0))
            .with("revision", s.revision.to_string())
            .with("value", hex(&s.canonical_bytes()))
            .with("hash", hex(&s.hash())),
    ];
    for (name, ak, v) in samples() {
        let typ = s.aspects.get(ak).map(|a| &a.ty);
        assert!(ak == "/created" || typ.is_some_and(|t| osis_schema::validate_write(s, &v, t).is_ok()), "{name}: not a valid write");
        cases.push(Record::new().with("case", name).with("spec", SPEC).with("ak", ak).with("value", hex(&encode(&v))));
    }
    VecFile { header: generated_header("schema", SPEC), cases }
}
