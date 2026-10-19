//! One fixed message of every kind (spec/wire.md §11.2), shared by tests, conformance vectors
//! and fuzz seeds. Field bytes are repeated constants, not valid signatures.

use crate::msg::*;
use crate::rbsr::Bound;
use osis_core::{BlobId, LabelId};

const L: LabelId = LabelId([0x0a; 16]);

fn id(b: u8) -> BlobId {
    BlobId([b; 32])
}

/// A 323-byte stand-in for a step (opaque at this layer).
pub fn step() -> Vec<u8> {
    vec![0x5e; MAX_STEP_BYTES]
}

/// `(name, message)` for every kind, in kind order, plus variants of the sum types.
pub fn messages() -> Vec<(&'static str, Message)> {
    let cursor = Cursor { log_id: [0x1c; 16], seq: 42 };
    let entry = Entry { blob: vec![1, 2, 3], wrap: [0x77; 49], stamp: [0x55; 64] };
    let added = Event::Added { blob_id: id(0xb1), blob: Some(vec![9; 5]), wrap: [0x77; 49], stamp: Some([0x55; 64]) };
    vec![
        ("error", Message::Error { id: 1, code: Code::NOT_OPENED }),
        ("ok", Message::Ok { id: 2 }),
        ("ping", Message::Ping { id: 3, wall_ms: 1_700_000_000_000 }),
        ("pong", Message::Pong { id: 3, wall_ms: 1_700_000_000_123 }),
        ("open sync key", Message::Open { id: 4, label: L, proof: Proof::Sync { pk: [0x31; 32], sig: [0x32; 64] } }),
        ("open claim key", Message::Open { id: 5, label: L, proof: Proof::Claim { step_id: [0x33; 32], pk: [0x34; 32], sig: [0x35; 64] } }),
        ("open static entry", Message::Open { id: 6, label: L, proof: Proof::Static { pk: [0x36; 32], sig: [0x37; 64] } }),
        ("opened", Message::Opened { id: 4, head: step(), entry_box: None }),
        ("opened with entry box", Message::Opened { id: 6, head: step(), entry_box: Some(vec![0xe0; 49]) }),
        ("step", Message::Step { id: 4, step: step() }),
        ("register", Message::Register { id: 7, label: L, step: step(), claim_set: Some(vec![0xc5; 40]) }),
        ("path", Message::Path { id: 8, label: L, after: Some([0x38; 32]) }),
        ("path reply", Message::PathReply { id: 8, steps: vec![step(), step()], more: false }),
        ("upload", Message::Upload { id: 10, label: L, entries: vec![entry.clone()] }),
        ("status", Message::Status { id: 10, codes: vec![Code::OK, Code::NOT_HEAD], head: Some(step()) }),
        ("deposit", Message::Deposit { id: 12, label: L, blob: vec![4, 5], wrap: [0x78; 49], sig: [0x56; 64] }),
        ("budget", Message::Budget { id: 12, code: Code::OK, entries_left: 63, bytes_left: 2_064_384, head: None }),
        (
            "delete",
            Message::Delete {
                id: 14,
                label: L,
                items: vec![
                    DeleteItem { blob_id: id(0xd1), at: None, token: None, sig: [0x57; 64] },
                    DeleteItem { blob_id: id(0xd2), at: Some(1_700_000_100_000), token: Some([0x7a; 32]), sig: [0x58; 64] },
                ],
            },
        ),
        ("cursor sync", Message::Sync { id: 15, label: L, cursor: Some(cursor), inline_limit: 65_536, entries: vec![entry], gained: vec![id(0xa1), id(0xa2)] }),
        ("sync without cursor", Message::Sync { id: 16, label: L, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] }),
        (
            "sync reply",
            Message::SyncReply {
                id: 15,
                events: vec![
                    added.clone(),
                    Event::Added { blob_id: id(0xb2), blob: None, wrap: [0x79; 49], stamp: None },
                    Event::Deleted(id(0xb3)),
                    Event::Pending { blob_id: id(0xb4), at: 1_700_000_200_000 },
                    Event::Head(step()),
                ],
                want: vec![id(0xa2)],
                codes: vec![Code::OK],
                cursor: Cursor { log_id: [0x1c; 16], seq: 47 },
                more: false,
            },
        ),
        (
            "reconcile",
            Message::Reconcile {
                id: 17,
                label: L,
                ranges: vec![
                    Range { lower: Bound::empty(), upper: Bound::of(&id(0x40)), mode: Mode::Fingerprint([0xf1; 16]) },
                    Range { lower: Bound::of(&id(0x40)), upper: Bound::new(vec![0x80]).unwrap_or_default(), mode: Mode::Ids(vec![id(0x41), id(0x42)]) },
                ],
            },
        ),
        (
            "reconcile reply",
            Message::ReconcileReply {
                id: 17,
                ranges: vec![Range { lower: Bound::of(&id(0x40)), upper: Bound::new(vec![0x80]).unwrap_or_default(), mode: Mode::Diff { theirs: vec![id(0x43)], lacking: vec![id(0x42)] } }],
            },
        ),
        ("fetch", Message::Fetch { id: 19, label: L, ids: vec![id(0xb2), id(0xb5)] }),
        (
            "fetch reply",
            Message::FetchReply {
                id: 19,
                items: vec![Fetched { blob_id: id(0xb2), entry: Some((vec![6; 4], [0x79; 49], None)) }, Fetched { blob_id: id(0xb5), entry: None }],
            },
        ),
        ("subscribe", Message::Subscribe { id: 21, labels: vec![L, LabelId([0x0b; 16])] }),
        ("unsubscribe", Message::Unsubscribe { id: 22, labels: vec![L] }),
        ("push", Message::Push { label: L, events: vec![added], cursor: Cursor { log_id: [0x1c; 16], seq: 48 } }),
        ("signal", Message::Signal { label: L, blob: vec![0x5a; 8], wrap: [0x7b; 49], auth: SignalAuth { deposit: true, sig: [0x59; 64] } }),
    ]
}
