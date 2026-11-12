//! `proto/`: frames, Hello, one message of every kind on a fixed label, and rejections (spec/wire.md
//! §11.1, §11.2, §13). Generated.

use super::{case, generated_header};
use crate::file::{Record, VecFile};
use crate::hex;
use osis_base::{Value, cbor};
use osis_proto::examples::{CHALLENGE, Fixture, STATIC_KEY};
use osis_proto::{Hello, Message, encode_frame, examples};

const SPEC: &str = "spec/wire.md §11.2";

fn int(n: i64) -> Value {
    Value::Int(n)
}

fn bytes(n: usize, b: u8) -> Value {
    Value::Bytes(vec![b; n])
}

/// A rejected body written as `head || item × count || tail` (core/test/vectors/README.md, proto).
fn repeated(name: &str, rule: &str, full: Value, item: Value, count: usize, tail: &[Value]) -> Record {
    let full = cbor::encode(&full);
    let item = cbor::encode(&item);
    let tail: Vec<u8> = tail.iter().flat_map(cbor::encode).collect();
    let head_len = full.len() - tail.len() - count * item.len();
    let head = &full[..head_len];
    assert_eq!([head.to_vec(), item.repeat(count), tail.clone()].concat(), full, "{name}");
    let r = Message::decode(&full).expect_err(name);
    assert!(matches!(r.error, osis_proto::Error::Cap(_)), "{name}: {:?}", r.error);
    case(name, SPEC).with("head", hex(head)).with("item", hex(&item)).with("count", count.to_string()).with("tail", hex(&tail)).with("reject", rule).with("answer", r.code().0.to_string())
}

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
    let f = Fixture::new(0x10);
    cases.push(
        case("fixture", "spec/wire.md §8, §11.2")
            .with("about", "the label of the messages below: osis-proto examples::Fixture::new(0x10) (group secrets 10..13 repeated, reader X25519 14.., key actor 15.., entry box sealed to the KEM key derived from 16.., group thing tid 10.., registration rng seed 17..); opens are signed for the challenge and static key below")
            .with("label-id", hex(&f.label.0))
            .with("genesis", hex(&f.genesis.to_bytes()))
            .with("genesis-claim-set", hex(&f.genesis_claims.to_bytes()))
            .with("child", hex(&f.child.to_bytes()))
            .with("challenge", hex(&CHALLENGE))
            .with("static-key", hex(&STATIC_KEY)),
    );
    for (name, m) in examples::messages() {
        let enc = m.encode();
        assert_eq!(Message::decode(&enc), Ok(m.clone()));
        cases.push(case(name, SPEC).with("kind", m.kind().to_string()).with("hex", hex(&enc)));
    }
    // Rejections: `reject` names the broken rule, `answer` the Error code sent back.
    let label = bytes(16, 0x0a);
    let id = bytes(32, 0x01);
    let item = Value::List(vec![bytes(32, 1), Value::List(vec![]), Value::List(vec![]), bytes(64, 3)]);
    let list = |v: &Value, n: usize| Value::List(vec![v.clone(); n]);
    let step = Value::Bytes(f.genesis.to_bytes());
    let fetched = Value::List(vec![id.clone(), Value::List(vec![])]);
    let empty = Value::List(vec![]);
    let caps: Vec<(&str, Value, Value, usize, Vec<Value>)> = vec![
        ("delete of 1025 items", Value::List(vec![int(14), int(1), label.clone(), list(&item, 1025)]), item.clone(), 1025, vec![]),
        ("fetch of 1025 ids", Value::List(vec![int(19), int(1), label.clone(), int(16_384), list(&id, 1025)]), id.clone(), 1025, vec![]),
        ("fetch reply of 1025 items", Value::List(vec![int(20), int(1), list(&fetched, 1025)]), fetched.clone(), 1025, vec![]),
        ("path reply of 1025 steps", Value::List(vec![int(9), int(1), list(&step, 1025), Value::Bool(false)]), step.clone(), 1025, vec![Value::Bool(false)]),
    ];
    for (name, full, item, n, tail) in caps {
        cases.push(repeated(name, "cap", full, item, n, &tail));
    }
    let rejects: Vec<(&str, &str, Vec<u8>)> = vec![
        ("unknown kind", "unknown-kind", cbor::encode(&Value::List(vec![int(99), int(7)]))),
        ("id at 2^32", "head", cbor::encode(&Value::List(vec![int(2), int(1 << 32), int(0)]))),
        ("request with id 0", "id", cbor::encode(&Value::List(vec![int(2), int(0), int(0)]))),
        ("reply with id 0", "id", cbor::encode(&Value::List(vec![int(1), int(0)]))),
        ("stream with an id", "id", cbor::encode(&Value::List(vec![int(43), int(5), Value::List(vec![Value::List(vec![label.clone(), Value::List(vec![int(1), id.clone()])])]), Value::List(vec![]), Value::Bool(false)]))),
        ("non-canonical id", "cbor", vec![0x82, 0x01, 0x18, 0x01]),
        ("trailing byte", "cbor", vec![0x82, 0x01, 0x01, 0x00]),
        ("indefinite array", "cbor", vec![0x9f, 0x01, 0x01, 0xff]),
        ("deposit wrap of 48 bytes", "size", cbor::encode(&Value::List(vec![int(37), int(1), Value::List(vec![Value::List(vec![int(2), label.clone(), bytes(1, 1), bytes(48, 0), bytes(64, 0)])])]))),
        ("step that does not parse", "step", cbor::encode(&Value::List(vec![int(6), int(1), bytes(300, 0)]))),
        ("empty delete", "count", cbor::encode(&Value::List(vec![int(14), int(1), label.clone(), empty.clone()]))),
    ];
    for (name, rule, enc) in rejects {
        let r = Message::decode(&enc).expect_err(name);
        cases.push(case(name, SPEC).with("hex", hex(&enc)).with("reject", rule).with("answer", r.code().0.to_string()));
    }
    // retired kinds are unknown
    for kind in [10, 12, 13, 15, 16, 17, 18, 21, 22, 23] {
        let enc = cbor::encode(&Value::List(vec![int(kind), int(7), label.clone()]));
        let r = Message::decode(&enc).expect_err("retired kind");
        assert_eq!(r.error, osis_proto::Error::UnknownKind(kind as u64));
        cases.push(case(&format!("retired kind {kind}"), SPEC).with("hex", hex(&enc)).with("reject", "unknown-kind").with("answer", r.code().0.to_string()));
    }
    let h17 = Value::List(vec![Value::Str("osis".into()), Value::List((1..=17).map(int).collect()), int(0), bytes(32, 0)]);
    assert!(Hello::decode(&cbor::encode(&h17)).is_err());
    cases.push(case("hello with 17 versions", "spec/wire.md §11.1").with("hex", hex(&cbor::encode(&h17))).with("reject", "cap"));
    cases.push(case("zero-length frame", "spec/wire.md §11.1").with("frame", "00000000").with("reject", "frame-length").with("answer", "2"));
    let over = u32::try_from(osis_base::format::MAX_MESSAGE + 1).unwrap().to_be_bytes();
    cases.push(case("frame of MAX_MESSAGE + 1", "spec/wire.md §11.1").with("frame", hex(&over)).with("reject", "frame-length").with("answer", "2"));
    VecFile { header: generated_header("proto", SPEC), cases }
}
