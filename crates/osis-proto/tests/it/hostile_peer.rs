//! A misbehaving peer against a `ClientSession` (spec/requirements.md: "Peer input never causes
//! unbounded allocation, work, storage or diagnostics"): replies scripted frame by frame.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use osis_core::{BlobId, LabelId};
use osis_proto::rbsr::Bound;
use osis_proto::*;

const T0: u64 = 1_700_000_000_000;
const L: LabelId = LabelId([7; 16]);

fn ready() -> ClientSession {
    let mut c = ClientSession::new(ClientConfig { peer_static_key: [1; 32], challenge: [2; 32] });
    c.handle(T0, ClientInput::Start);
    c.handle(T0, ClientInput::Bytes(encode_frame(&Hello::new(T0, [3; 32]).encode())));
    c
}

fn sent(out: &[ClientOutput]) -> Vec<Message> {
    out.iter().filter_map(|o| if let ClientOutput::Send(f) = o { Message::decode(&f[4..]).ok() } else { None }).collect()
}

fn reply(c: &mut ClientSession, m: Message) -> Vec<ClientOutput> {
    c.handle(T0, ClientInput::Bytes(encode_frame(&m.encode())))
}

fn id(n: u64) -> BlobId {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    BlobId(b)
}

// spec/wire.md §11.2 (Sync: `more` pages), spec/requirements.md (no unbounded work): pages with
// fresh cursors and no events end the exchange after `MAX_EMPTY_PAGES`
#[test]
fn empty_pages_end_the_sync_spec_wire_11_2() {
    let mut c = ready();
    let out = c.handle(T0, ClientInput::Command(Command::Sync { label: L, cursor: None, inline_limit: 0, entries: vec![], gained: vec![] }));
    let mut next = sent(&out).into_iter().find_map(|m| if let Message::Sync { id, .. } = m { Some(id) } else { None });
    let mut pages = 0;
    while let Some(rid) = next {
        pages += 1;
        assert!(pages <= client::MAX_EMPTY_PAGES as usize, "followed past the cap");
        let out = reply(&mut c, Message::SyncReply { id: rid, events: vec![], want: vec![], codes: vec![], cursor: Cursor { log_id: [1; 16], seq: pages as u64 }, more: true });
        next = sent(&out).into_iter().find_map(|m| if let Message::Sync { id, .. } = m { Some(id) } else { None });
        if next.is_none() {
            assert!(out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::PeerError(_)))));
        }
    }
    assert_eq!(pages, client::MAX_EMPTY_PAGES as usize);
}

// spec/wire.md §11.2 (SyncReply `want`: "gained IDs the peer lacks"): a Want names only IDs the
// Sync listed as gained; others are dropped (no upload amplification)
#[test]
fn want_only_names_gained_ids_spec_wire_11_2() {
    let mut c = ready();
    let out = c.handle(T0, ClientInput::Command(Command::Sync { label: L, cursor: None, inline_limit: 0, entries: vec![], gained: vec![id(1)] }));
    let rid = sent(&out).into_iter().find_map(|m| if let Message::Sync { id, .. } = m { Some(id) } else { None }).unwrap();
    let out = reply(&mut c, Message::SyncReply { id: rid, events: vec![], want: vec![id(1), id(2), id(3)], codes: vec![], cursor: Cursor { log_id: [1; 16], seq: 1 }, more: false });
    let wants: Vec<&Vec<BlobId>> = out.iter().filter_map(|o| if let ClientOutput::Event(ClientEvent::Want { ids, .. }) = o { Some(ids) } else { None }).collect();
    assert_eq!(wants, vec![&vec![id(1)]]);
}

// spec/wire.md §11.2 (Path `more`), spec/requirements.md (no unbounded work): a Path exchange the
// node stopped is not followed
#[test]
fn stopped_path_not_followed_spec_wire_11_2() {
    let mut c = ready();
    let out = c.handle(T0, ClientInput::Command(Command::Path { label: L, after: None }));
    let rid = sent(&out).into_iter().find_map(|m| if let Message::Path { id, .. } = m { Some(id) } else { None }).unwrap();
    c.handle(T0, ClientInput::Command(Command::StopPath { label: L }));
    let step = examples::Fixture::new(1).genesis.clone();
    let out = reply(&mut c, Message::PathReply { id: rid, steps: vec![step], more: true });
    assert!(sent(&out).is_empty(), "no next page asked");
    assert!(!out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::PathSteps { .. }))));
}

// spec/wire.md §11.3, spec/requirements.md (no unbounded allocation): a responder answering every
// range with full difference lists is abandoned once the differences pass
// `MAX_RECONCILE_IDS`, long before `MAX_RECONCILE_MESSAGES`
#[test]
#[ignore = "tier 2: about 2M IDs"]
fn reconcile_differences_capped_spec_wire_11_3() {
    let mut c = ready();
    let out = c.handle(T0, ClientInput::Command(Command::Reconcile { label: L, ids: vec![] }));
    let mut asked: Vec<(u32, Vec<Range>)> = sent(&out).into_iter().filter_map(|m| if let Message::Reconcile { id, ranges, .. } = m { Some((id, ranges)) } else { None }).collect();
    // first answer: 4096 fingerprint ranges, split by the top 12 bits
    let (rid, _) = asked.remove(0);
    let bound = |i: u16| Bound::new((i << 4).to_be_bytes().to_vec()).unwrap();
    let ranges: Vec<Range> = (0..4096u16).map(|i| Range { lower: bound(i), upper: if i == 4095 { Bound::empty() } else { bound(i + 1) }, mode: Mode::Fingerprint([9; 16]) }).collect();
    let out = reply(&mut c, Message::ReconcileReply { id: rid, ranges });
    asked.extend(sent(&out).into_iter().filter_map(|m| if let Message::Reconcile { id, ranges, .. } = m { Some((id, ranges)) } else { None }));
    // then each mode 1 range answered by 1024 made-up IDs inside it
    let mut n = 0u64;
    let mut abandoned = false;
    let mut replies = 0;
    while let Some((rid, ranges)) = asked.pop() {
        let mut out_ranges = Vec::new();
        for r in ranges {
            let top = u16::from_be_bytes([r.lower.as_bytes().first().copied().unwrap_or(0), r.lower.as_bytes().get(1).copied().unwrap_or(0)]);
            let theirs: Vec<BlobId> = (0..1024u64)
                .map(|_| {
                    n += 1;
                    let mut b = id(n).0;
                    b[..2].copy_from_slice(&top.to_be_bytes());
                    BlobId(b)
                })
                .collect();
            out_ranges.push(Range { lower: r.lower, upper: r.upper, mode: Mode::Diff { theirs, lacking: vec![] } });
        }
        let out = reply(&mut c, Message::ReconcileReply { id: rid, ranges: out_ranges });
        replies += 1;
        if out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::Refused { kind: 17, .. }))) {
            abandoned = true;
            break;
        }
        assert!(!out.iter().any(|o| matches!(o, ClientOutput::Event(ClientEvent::Reconciled { .. }))), "never completes with this much");
    }
    assert!(abandoned, "abandoned after {replies} replies");
    assert!(replies <= client::MAX_RECONCILE_IDS / (256 * 1024) + 1);
}
