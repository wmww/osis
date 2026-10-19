//! `proto/`: frames, Hello, one message of every kind and rejections (spec/wire.md §11.1, §11.2);
//! range reconciliation (§11.3). Generated.

use super::{case, generated_header};
use crate::file::VecFile;
use crate::hex;
use osis_core::{BlobId, LabelId, Value, cbor};
use osis_proto::{Hello, Message, encode_frame, examples};

const SPEC: &str = "spec/wire.md §11.2";

pub fn messages() -> VecFile {
    let mut cases = Vec::new();
    let ping = Message::Ping { id: 3, wall_ms: 1_700_000_000_000 }.encode();
    cases.push(case("frame", "spec/wire.md §11.1").with("body", hex(&ping)).with("frame", hex(&encode_frame(&ping))));
    let hello = Hello { versions: vec![1, 2], wall_ms: 1_700_000_000_000, challenge: [0x0c; 32] };
    assert_eq!(Hello::decode(&hello.encode()), Ok(hello.clone()));
    cases.push(
        case("hello", "spec/wire.md §11.1")
            .with("versions", "1,2")
            .with("wall-ms", "1700000000000")
            .with("challenge", hex(&hello.challenge))
            .with("hex", hex(&hello.encode())),
    );
    for (name, m) in examples::messages() {
        let enc = m.encode();
        assert_eq!(Message::decode(&enc), Ok(m.clone()));
        cases.push(case(name, SPEC).with("kind", m.kind().to_string()).with("hex", hex(&enc)));
    }
    // Rejections: `reject` names the broken rule, `answer` the Error code sent back.
    let int = |n: i64| Value::Int(n);
    let rejects: Vec<(&str, &str, Value, &str)> = vec![
        ("unknown kind", "unknown-kind", Value::List(vec![int(99), int(7)]), "11"),
        ("id at 2^32", "head", Value::List(vec![int(2), int(1 << 32), int(0)]), "2"),
        ("push with an id", "id", Value::List(vec![int(23), int(5), Value::Bytes(vec![0; 16]), Value::List(vec![Value::List(vec![int(1), Value::Bytes(vec![0; 32])])]), Value::List(vec![Value::Bytes(vec![0; 16]), int(0)])]), "2"),
        ("wrap of 48 bytes", "size", Value::List(vec![int(12), int(1), Value::Bytes(vec![0; 16]), Value::Bytes(vec![1]), Value::Bytes(vec![0; 48]), Value::Bytes(vec![0; 64])]), "2"),
        (
            "mode 1 over 32 ids",
            "cap",
            Value::List(vec![
                int(17),
                int(1),
                Value::Bytes(vec![0; 16]),
                Value::List(vec![Value::List(vec![Value::Bytes(vec![]), Value::Bytes(vec![]), Value::List(vec![int(1), Value::List((0..33u8).map(|i| Value::Bytes(vec![i; 32])).collect())])])]),
            ]),
            "2",
        ),
        ("empty upload", "count", Value::List(vec![int(10), int(1), Value::Bytes(vec![0; 16]), Value::List(vec![])]), "2"),
        (
            "overlapping ranges",
            "ranges",
            Value::List(vec![
                int(17),
                int(1),
                Value::Bytes(vec![0; 16]),
                Value::List(vec![
                    Value::List(vec![Value::Bytes(vec![1]), Value::Bytes(vec![3]), Value::List(vec![int(0), Value::Bytes(vec![0; 16])])]),
                    Value::List(vec![Value::Bytes(vec![2]), Value::Bytes(vec![4]), Value::List(vec![int(0), Value::Bytes(vec![0; 16])])]),
                ]),
            ]),
            "2",
        ),
    ];
    for (name, rule, v, answer) in rejects {
        let enc = cbor::encode(&v);
        let r = Message::decode(&enc).expect_err(name);
        assert_eq!(r.code().0.to_string(), answer, "{name}");
        cases.push(case(name, SPEC).with("hex", hex(&enc)).with("reject", rule).with("answer", answer));
    }
    cases.push(case("zero-length frame", "spec/wire.md §11.1").with("frame", "00000000").with("reject", "frame-length").with("answer", "2"));
    VecFile { header: generated_header("proto", SPEC), cases }
}

/// The fixed reconciliation universe: 32-byte slices of `xof("osis proto reconcile", 32 n)`.
fn universe(n: usize) -> Vec<BlobId> {
    crate::xof("osis proto reconcile", 32 * n).chunks_exact(32).map(|c| BlobId(c.try_into().unwrap())).collect()
}

fn hash_ids(ids: &[BlobId]) -> String {
    hex(&osis_core::hash::hash(&ids.iter().flat_map(|i| i.0).collect::<Vec<u8>>()))
}

fn ranges_of(m: &Message) -> &[osis_proto::Range] {
    match m {
        Message::Reconcile { ranges, .. } | Message::ReconcileReply { ranges, .. } => ranges,
        _ => unreachable!(),
    }
}

pub fn reconcile() -> VecFile {
    use osis_proto::rbsr::{Reconciler, fingerprint, respond};
    const SPEC3: &str = "spec/wire.md §11.3";
    let mut cases = Vec::new();
    let u = universe(10_100);
    let mut first = u[..100].to_vec();
    first.sort();
    cases.push(case("fingerprint of 100 ids", SPEC3).with("ids", "the first 100 ids of the universe below").with("fingerprint", hex(&fingerprint(&first))));
    cases.push(case("fingerprint of the empty set", SPEC3).with("fingerprint", hex(&fingerprint(&[]))));
    let mut one = [0u8; 32];
    one[0] = 1;
    cases.push(
        case("fingerprint sum wraps mod 2^256", SPEC3)
            .with("ids", format!("{},{}", hex(&one), hex(&[0xff; 32])))
            .with("fingerprint", hex(&fingerprint(&[BlobId(one), BlobId([0xff; 32])]))),
    );
    // Requester A and responder B: 9900 common IDs, then 100 only A holds, then 100 only B holds.
    let mut a: Vec<_> = u[..10_000].to_vec();
    let mut b: Vec<_> = u[..9_900].iter().chain(&u[10_000..]).copied().collect();
    a.sort();
    b.sort();
    let mut r = Reconciler::new(&a);
    let (mut step, mut round) = (0, 0u32);
    while r.has_queued() {
        round += 1;
        let mut replies = Vec::new();
        while let Some(batch) = r.next_batch() {
            let req = Message::Reconcile { id: round, label: LabelId([0x0a; 16]), ranges: batch };
            let reply = Message::ReconcileReply { id: round, ranges: respond(&b, ranges_of(&req)).unwrap() };
            for (dir, m) in [("request", &req), ("reply", &reply)] {
                step += 1;
                let enc = m.encode();
                let mut c = case(&format!("transcript {step}"), SPEC3)
                    .with("round", round.to_string())
                    .with("direction", dir)
                    .with("ranges", ranges_of(m).len().to_string())
                    .with("body-blake3", hex(&osis_core::hash::hash(&enc)));
                if step <= 2 {
                    c = c.with("hex", hex(&enc));
                }
                cases.push(c);
            }
            replies.push(ranges_of(&reply).to_vec());
        }
        for rep in replies {
            r.on_reply(&a, &rep);
        }
    }
    let need: Vec<_> = r.need.iter().copied().collect();
    let have: Vec<_> = r.have.iter().copied().collect();
    let mut want_need = u[10_000..].to_vec();
    let mut want_have = u[9_900..10_000].to_vec();
    want_need.sort();
    want_have.sort();
    assert_eq!((&need, &have), (&want_need, &want_have));
    cases.push(
        case("transcript result", SPEC3)
            .with("sets", "universe = xof(\"osis proto reconcile\", 323200) as 10100 ids; A = ids 0..10000, B = ids 0..9900 and 10000..10100; A requests")
            .with("split", "16 subranges of near-equal own counts (subrange i holds own ids i*n/16..(i+1)*n/16), bounds the first own id of each (full 32 bytes); requests batch the queued ranges sorted by lower bound, 256 per message; replies are applied after the round")
            .with("rounds", round.to_string())
            .with("need", format!("{} ids, blake3 of the sorted concatenation {}", need.len(), hash_ids(&need)))
            .with("have", format!("{} ids, blake3 of the sorted concatenation {}", have.len(), hash_ids(&have))),
    );
    VecFile { header: generated_header("proto", SPEC3), cases }
}
