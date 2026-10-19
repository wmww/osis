//! `proto/`: frames, Hello, one message of every kind and rejections (spec/wire.md §11.1, §11.2);
//! range reconciliation (§11.3). Generated.

use super::{case, generated_header};
use crate::file::VecFile;
use crate::hex;
use osis_core::{Value, cbor};
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
