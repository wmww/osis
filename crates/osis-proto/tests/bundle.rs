//! Bundle import as a peer with no cursor (spec/sync.md §11, spec/wire.md §12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{LabelId, Value, cbor, hash::hash};
use osis_crypto::{Domain, Secret32, SigningSecret};
use osis_proto::bundle::{BundleImport, MAGIC};
use osis_proto::label::{ClaimSet, NewStep, entry_digest, sign};
use osis_proto::msg::Event;
use osis_proto::{ClientEvent, encode_frame};

fn key(b: u8) -> SigningSecret {
    SigningSecret::from_seed(&Secret32::from_bytes([b; 32]))
}

fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn int(n: u64) -> Value {
    Value::Int(n as i64)
}

fn rec(items: Vec<Value>) -> Vec<u8> {
    encode_frame(&cbor::encode(&Value::List(items)))
}

struct Fixture {
    label: LabelId,
    steps: Vec<Vec<u8>>,
    cs: Vec<u8>,
    write: SigningSecret,
}

fn fixture() -> Fixture {
    let (d0, d1) = (key(1), key(2));
    let label = osis_crypto::label_id(&d0.verifying_key());
    let cs = ClaimSet { claims: vec![[7; 32]], boxes: Default::default() }.to_bytes().unwrap();
    let p = |k: &SigningSecret| k.verifying_key().to_bytes();
    let g = NewStep { label, prev: None, sync: [3; 32], write: p(&key(4)), delete: p(&d0), deposit: [5; 32], step_key: [6; 32], claims_hash: hash(&cs), signer: &d0 }.sign();
    let c = NewStep { label, prev: Some(hash(&g)), sync: [3; 32], write: p(&key(8)), delete: p(&d1), deposit: [5; 32], step_key: [6; 32], claims_hash: hash(&cs), signer: &d0 }.sign();
    Fixture { label, steps: vec![g, c], cs, write: key(8) }
}

fn entry(f: &Fixture, blob: &[u8], signer: Option<&SigningSecret>) -> Vec<u8> {
    let id = osis_crypto::blob_id(blob);
    let wrap = [9u8; 49];
    let stamp = signer.map(|k| sign(k, Domain::Upload, &entry_digest(&f.label, &id, &wrap)));
    rec(vec![int(3), bytes(&f.label.0), bytes(&id.0), bytes(&wrap), Value::List(stamp.iter().map(|s| bytes(s)).collect())])
}

// spec/wire.md §12, spec/sync.md §11: records replay as log events with no cursor; paths and stamps verified, unknown kinds skipped
#[test]
fn import_replays_records() {
    let f = fixture();
    let (b1, b2) = (vec![1u8, 2, 3], vec![4u8, 5]);
    let (id1, id2) = (osis_crypto::blob_id(&b1), osis_crypto::blob_id(&b2));
    let path = Value::List(f.steps.iter().map(|s| Value::List(vec![bytes(s), Value::List(vec![bytes(&f.cs)])])).collect());
    let mut file = MAGIC.to_vec();
    file.extend(rec(vec![int(0), int(1)]));
    file.extend(rec(vec![int(1), bytes(&f.label.0), path]));
    file.extend(rec(vec![int(2), bytes(&b1)]));
    file.extend(rec(vec![int(2), bytes(&b2)]));
    file.extend(entry(&f, &b1, Some(&f.write)));
    file.extend(entry(&f, &b2, None));
    file.extend(entry(&f, &b2, Some(&key(99))));
    file.extend(rec(vec![int(9), int(1)]));
    file.extend(rec(vec![int(5), bytes(&f.label.0), bytes(&id2.0), int(77)]));
    file.extend(rec(vec![int(4), bytes(&f.label.0), bytes(&id1.0)]));
    let mut imp = BundleImport::new();
    let ev = imp.push(&file).unwrap();
    imp.finish().unwrap();
    // byte by byte: the same events, split differently
    let flat = |ev: &[ClientEvent]| ev.iter().flat_map(|e| match e { ClientEvent::Events { events, .. } => events.clone(), _ => vec![] }).collect::<Vec<_>>();
    let mut imp = BundleImport::new();
    let mut chunked = Vec::new();
    for chunk in file.chunks(5) {
        chunked.extend(imp.push(chunk).unwrap());
    }
    imp.finish().unwrap();
    assert_eq!(flat(&chunked), flat(&ev));
    assert_eq!(ev[0], ClientEvent::PathSteps { label: f.label, steps: f.steps.clone(), more: false });
    let stamp = sign(&f.write, Domain::Upload, &entry_digest(&f.label, &id1, &[9; 49]));
    assert_eq!(ev[1], ClientEvent::Events { label: f.label, events: vec![Event::Added { blob_id: id1, blob: Some(b1), wrap: [9; 49], stamp: Some(stamp) }, Event::Added { blob_id: id2, blob: Some(b2), wrap: [9; 49], stamp: None }], cursor: None });
    assert!(matches!(ev[2], ClientEvent::PeerError(_)));
    assert_eq!(ev[3], ClientEvent::Events { label: f.label, events: vec![Event::Pending { blob_id: id2, at: 77 }, Event::Deleted(id1)], cursor: None });
    assert_eq!(ev.len(), 4);
}

// spec/wire.md §12: magic, header record, whole frames; a forged path is refused
#[test]
fn import_rejects() {
    assert!(BundleImport::new().push(b"osisbndX").is_err());
    let mut imp = BundleImport::new();
    imp.push(MAGIC).unwrap();
    assert!(imp.push(&rec(vec![int(0), int(2)])).is_err());
    let mut imp = BundleImport::new();
    imp.push(MAGIC).unwrap();
    imp.push(&rec(vec![int(0), int(1)])).unwrap();
    imp.push(&[0, 0]).unwrap();
    assert!(imp.finish().is_err());
    let f = fixture();
    let mut imp = BundleImport::new();
    imp.push(MAGIC).unwrap();
    imp.push(&rec(vec![int(0), int(1)])).unwrap();
    // the child without its genesis does not verify
    let ev = imp.push(&rec(vec![int(1), bytes(&f.label.0), Value::List(vec![Value::List(vec![bytes(&f.steps[1]), Value::List(vec![])])])])).unwrap();
    assert!(matches!(&ev[..], [ClientEvent::PeerError(_)]));
    // an entry before its path
    let ev = imp.push(&entry(&f, &[1], Some(&f.write))).unwrap();
    assert!(matches!(&ev[..], [ClientEvent::PeerError(_)]));
}
