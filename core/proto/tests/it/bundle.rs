//! Bundle import as a peer with no cursor (spec/sync.md §11, spec/wire.md §12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_base::{Value, WallMs, cbor};
use osis_crypto::{Secret32, SigningSecret};
use osis_label::{BundleWriter, Record, sign_stamp};
use osis_proto::bundle::BundleImport;
use osis_proto::examples::Fixture;
use osis_proto::{ClientEvent, Event, encode_frame};

fn import(file: &[u8]) -> Vec<ClientEvent> {
    let mut imp = BundleImport::new(file).unwrap();
    let mut out = vec![];
    while let Some(ev) = imp.next_events().unwrap() {
        out.extend(ev);
    }
    out
}

// spec/wire.md §12, spec/sync.md §11: records replay as log events with no cursor; paths and stamps verified, unknown kinds skipped
#[test]
fn import_replays_records() {
    let f = Fixture::new(0x20);
    let (b1, b2) = (Fixture::blob(1), Fixture::blob(2));
    let (id1, id2) = (osis_label::blob_id(&b1), osis_label::blob_id(&b2));
    let wrap = [9u8; 49];
    let stamp = sign_stamp(&f.write, &f.label, &id1, &wrap);
    let forged = sign_stamp(&SigningSecret::from_seed(&Secret32::from_bytes([99; 32])), &f.label, &id2, &wrap);
    let mut w = BundleWriter::new(Vec::new()).unwrap();
    let l = f.label;
    for r in [
        Record::Path { label: l, steps: vec![(f.genesis.clone(), Some(f.genesis_claims.clone())), (f.child.clone(), None)] },
        Record::Blob(b1.clone()),
        Record::Blob(b2.clone()),
        Record::Entry { label: l, blob: id1, wrap, stamp: Some(stamp) },
        Record::Entry { label: l, blob: id2, wrap, stamp: None },
        Record::Entry { label: l, blob: id2, wrap, stamp: Some(forged) },
        Record::TimedDelete { label: l, blob: id2, at: WallMs(77) },
        Record::Delete { label: l, blob: id1 },
    ] {
        w.record(&r).unwrap();
    }
    let mut file = w.finish().unwrap();
    file.extend(encode_frame(&cbor::encode(&Value::List(vec![Value::Int(9), Value::Int(1)]))));
    let ev = import(&file);
    assert_eq!(ev[0], ClientEvent::PathSteps { label: l, steps: vec![f.genesis.clone(), f.child.clone()], more: false });
    let one = |e| ClientEvent::Events { label: l, events: vec![e], cursor: None };
    assert_eq!(ev[1], one(Event::Added { blob_id: id1, blob: Some(b1), wrap, stamp: Some(stamp) }));
    assert_eq!(ev[2], one(Event::Added { blob_id: id2, blob: Some(b2), wrap, stamp: None }));
    assert!(matches!(ev[3], ClientEvent::PeerError(_)));
    assert_eq!(ev[4], one(Event::Pending { blob_id: id2, at: 77 }));
    assert_eq!(ev[5], one(Event::Deleted(id1)));
    assert_eq!(ev.len(), 6);
}

// spec/wire.md §12: magic and format record; a path that does not extend the head is refused
#[test]
fn import_rejects() {
    assert!(BundleImport::new(&b"osisbndX"[..]).is_err());
    let f = Fixture::new(0x20);
    let mut w = BundleWriter::new(Vec::new()).unwrap();
    w.record(&Record::Path { label: f.label, steps: vec![(f.genesis.clone(), None), (f.child.clone(), None)] }).unwrap();
    w.record(&Record::Path { label: f.label, steps: vec![(f.genesis.clone(), None)] }).unwrap();
    let ev = import(&w.finish().unwrap());
    assert!(matches!(&ev[..], [ClientEvent::PathSteps { .. }, ClientEvent::PeerError(_)]), "{ev:?}");
}
