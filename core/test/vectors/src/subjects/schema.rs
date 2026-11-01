//! `schema/`: the core schema as a `schema` value (spec/data-model.md §9, §10) and canonical
//! encodings of core aspect values written through their typed keys. Generated.

use super::generated_header;
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{CommitId, CreationRecord, LabelId, Role, Tid, Ts, Value, WallMs, encode};
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
    let holders: Holders = BTreeMap::from([
        (tid(5), Edge { role: Role::Write, until: Some(WallMs(1_700_000_000_000)), invite: Some(Role::Read), since: Some(edge_key()), tied: Some(Tie { ts: edge_key().ts, source: Source::Commit(CommitId([7; 32])), ctr: 2, subgroup: false }) }),
        (tid(7), Edge { role: Role::Admin, until: None, invite: None, since: None, tied: None }),
    ]);
    let keys = Keys {
        read: Some(Keyset { epoch: epoch(1), kem_key: KemKey::X25519MlKem768(vec![9; 1216]), suite: 1, delete_key: SigningKey::Ed25519(vec![8; 32]), supersedes: BTreeSet::from([epoch(0)]) }),
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
            (BoxKey { holder: tid(13), role: Role::Write, epoch: epoch(2) }, SecretBox::Symmetric(SymmetricBox { epoch: epoch(1), wrap: vec![16; 48] })),
        ]),
        history: BTreeMap::from([(HistoryKey { role: Role::Read, epoch: epoch(1) }, vec![17; 64])]),
    };
    let frontier = Frontier {
        writes: BTreeMap::from([(tid(19), BTreeMap::from([("note:body.0".to_string(), BTreeMap::from([(tid(20), 3)]))]))]),
        commits: BTreeSet::from([CommitId([21; 32])]),
    };
    let tenures = Tenures(vec![Tenure { holder: tid(18), role: Role::Write, since: None, until: edge_key(), frontier: Some(Chunked::Inline(frontier)) }]);
    let labels: Labels = BTreeMap::from([(
        LabelId([22; 16]),
        Label { index: 0, steps: BTreeMap::from([([23; 32], StepRecord { step: vec![24; 10], claims: None })]), hosts: vec![], replaced: false },
    )]);
    vec![
        ("created thing", "created.0", CREATED.encode(&CreationRecord::Thing { owner: tid(1), nonce: [2; 32], creator: None })),
        ("created key actor", "created.0", CREATED.encode(&CreationRecord::KeyActor { alg: 1, public_key: vec![3; 32], nonce: [4; 32] })),
        ("holders", "roles.0", ROLES.encode(&holders)),
        ("keys", "keys.0", KEYS.encode(&keys)),
        ("secrets", "secrets.0", SECRETS.encode(&secrets)),
        ("tenures", "tenures.0", TENURES.encode(&tenures)),
        ("label", "label.0", LABEL.encode(&labels)),
        ("moved", "moved.0", MOVED.encode(&tid(25))),
        ("was", "was.0", WAS.encode(&tid(26))),
        ("node", "node.0", NODE.encode(&NodeInfo { software: "osis 0.1.0".into() })),
        ("reach", "reach.0", REACH.encode(&Reach { dialable: [27; 32], relays: vec!["https://relay.example".into()], lan_secret: [28; 32] })),
        ("seen", "seen.0", SEEN.encode(&Seen { ts: WallMs(1_700_000_000_000), stranded: false })),
        ("group", "group.0", GROUP.encode(&Group { items: BTreeSet::from([tid(29)]), subgroups: BTreeSet::from([tid(30)]) })),
        ("name", "name.0", NAME.encode(&"Trip".to_string())),
        ("body", "body.0", BODY.encode(&"# Plan\n".to_string())),
        ("tag", "tag.0", TAG.encode(&Tag { color: Some("#ff8800".into()) })),
    ]
}

/// The core schema value and one case per core aspect sample.
pub fn core() -> VecFile {
    let s = core_schema();
    let mut cases = vec![
        Record::new()
            .with("case", "core schema")
            .with("spec", "spec/data-model.md §10")
            .with("version", s.version.to_string())
            .with("value", hex(&s.canonical_bytes()))
            .with("hash", hex(&s.hash())),
    ];
    for (name, ak, v) in samples() {
        let typ = s.aspects.get(ak).map(|a| &a.ty);
        assert!(ak == "created.0" || typ.is_some_and(|t| osis_schema::validate_write(s, &v, t).is_ok()), "{name}: not a valid write");
        cases.push(Record::new().with("case", name).with("spec", SPEC).with("ak", ak).with("value", hex(&encode(&v))));
    }
    VecFile { header: generated_header("schema", SPEC), cases }
}
