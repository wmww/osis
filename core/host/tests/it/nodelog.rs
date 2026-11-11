//! spec: none (the node log in the host's store: issues/net-one-peer.md build 3e, issues/net-reconnect.md
//! One node log). The hub's store logs every entry and head it holds, beside its per-label logs.

use crate::common::*;
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, LabelId, ManualClock, WallMs};
use osis_crypto::{SeededRng, Signature};
use osis_host::{HostPolicy, HostStore};
use osis_proto::examples::Fixture;
use osis_proto::msg::WRAP_LEN;
use osis_proto::*;
use osis_store::{LogRead, MemoryBackend, MemoryRoot, NodeEvent, Store, StoreConfig};
use std::collections::BTreeSet;
use std::sync::Arc;

struct Host {
    s: HostStore,
    backend: MemoryBackend,
    root: MemoryRoot,
    clock: Arc<ManualClock>,
}

fn policy() -> HostPolicy {
    HostPolicy { deposit_factor: 1 << 20, ..HostPolicy::unlimited() }
}

fn open(backend: MemoryBackend, root: MemoryRoot, seed: u8) -> Host {
    let store = Store::open_or_create(Box::new(backend.clone()), Box::new(root.clone()), StoreConfig::default(), &mut SeededRng::from_seed([seed; 32])).unwrap();
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let s = HostStore::open(store, clock.clone(), policy(), Box::new(SeededRng::from_seed([seed ^ 0x55; 32]))).unwrap();
    Host { s, backend, root, clock }
}

fn host() -> Host {
    open(MemoryBackend::new(), MemoryRoot::new(), 1)
}

fn put(s: &mut HostStore, l: &LabelId, n: u64, stamped: bool, expiry: Option<u64>, replaces: &[BlobId]) -> BlobId {
    let b = blob(n);
    let id = osis_label::blob_id(&b);
    let stamp = stamped.then_some(Signature([n as u8; 64]));
    let p = Put { blob_id: id, blob: &b, wrap: [n as u8; WRAP_LEN], stamp, expiry, ephemeral: false, replaces, now: T0 };
    assert_eq!(s.put(l, p).unwrap(), Code::OK);
    id
}

fn read(s: &mut HostStore, cursor: Option<&[u8]>) -> LogRead {
    s.store_mut().unwrap().transaction(&mut SeededRng::from_seed([9; 32])).unwrap().log_read(cursor, usize::MAX - 1).unwrap()
}

fn listing(s: &mut HostStore) -> Vec<NodeEvent> {
    let r = read(s, None);
    assert!(r.whole && !r.more);
    r.events.into_iter().map(|e| e.event).collect()
}

fn sweep(h: &mut Host, now: u64) {
    h.clock.set(WallMs(now));
    while h.s.sweep(now, 1024).unwrap().more {}
    h.s.commit().unwrap();
}

#[test]
fn a_listing_from_the_start_is_the_live_set_plus_retained_deletions() {
    let mut h = host();
    let (f1, f2) = (Fixture::new(0x10), Fixture::new(0x20));
    let (l1, l2) = (f1.label, f2.label);
    h.s.push_step(&l1, f1.genesis.clone(), Some(f1.genesis_claims.clone())).unwrap();
    h.s.push_step(&l2, f2.genesis.clone(), Some(f2.genesis_claims.clone())).unwrap();
    // the head moves: its earlier event goes
    h.s.push_step(&l1, f1.child.clone(), Some(f1.child_claims.clone())).unwrap();
    let mut live: Vec<(LabelId, BlobId)> = (0..6).map(|n| (l1, put(&mut h.s, &l1, n, true, None, &[]))).collect();
    live.extend((10..14).map(|n| (l2, put(&mut h.s, &l2, n, n != 13, (n == 12).then_some(T0 + 1_000), &[]))));
    // a delete, a replacement and an expiry: each leaves a deletion event
    let (deleted, replaced, expired) = (live.remove(0), live.remove(6), live.remove(6));
    h.s.delete(&l1, &deleted.1, T0).unwrap();
    live.push((l2, put(&mut h.s, &l2, 20, true, None, &[replaced.1])));
    // an ephemeral entry is never logged
    let eb = blob(30);
    let p = Put { blob_id: osis_label::blob_id(&eb), blob: &eb, wrap: [30; WRAP_LEN], stamp: Some(Signature([30; 64])), expiry: None, ephemeral: true, replaces: &[], now: T0 };
    assert_eq!(h.s.put(&l1, p).unwrap(), Code::OK);
    sweep(&mut h, T0 + 1_000);
    assert_eq!(h.s.entry(&l2, &expired.1).unwrap(), None);
    let heads = |e: &[NodeEvent]| e.iter().filter_map(|e| if let NodeEvent::Head(l) = e { Some(*l) } else { None }).collect::<Vec<_>>();
    let added = |e: &[NodeEvent]| e.iter().filter_map(|e| if let NodeEvent::Added(l, b) = e { Some((*l, *b)) } else { None }).collect::<BTreeSet<_>>();
    let gone = |e: &[NodeEvent]| e.iter().filter_map(|e| if let NodeEvent::Deleted { label, blob, .. } = e { Some((*label, *blob)) } else { None }).collect::<BTreeSet<_>>();
    let e = listing(&mut h.s);
    assert_eq!(e.len(), live.len() + 3 + 2, "one event per subject: {e:?}");
    assert_eq!(added(&e), live.iter().copied().collect(), "every held entry, of every sync ID");
    assert!(live.iter().all(|(l, b)| h.s.entry(l, b).unwrap().is_some()));
    assert_eq!(gone(&e), [deleted, replaced, expired].into_iter().collect());
    assert_eq!(heads(&e).into_iter().collect::<BTreeSet<_>>(), [l1, l2].into_iter().collect());
    // deletions are retained for their lifetime, then the listing is the live set alone
    let due = h.s.next_due().unwrap().unwrap();
    assert!(due <= T0 + 1_000 + TOMBSTONE_LIFETIME_MS, "the log's sweep is due");
    sweep(&mut h, T0 + 1_000 + TOMBSTONE_LIFETIME_MS);
    let e = listing(&mut h.s);
    assert!(gone(&e).is_empty(), "{e:?}");
    assert_eq!(added(&e), live.iter().copied().collect());
    assert_eq!(heads(&e).len(), 2);
}

/// Deposits promoted: two events per entry written, one held. Counted at n and 10n: the log
/// grows with what the store holds, not with what was written.
#[test]
fn an_entrys_earlier_events_compact_away() {
    for n in [20u64, 200] {
        let mut h = host();
        let f = Fixture::new(0x30);
        h.s.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        for i in 0..n {
            put(&mut h.s, &f.label, i, false, None, &[]);
        }
        let before = read(&mut h.s, None).cursor.unwrap();
        for i in 0..n {
            put(&mut h.s, &f.label, i, true, None, &[]);
        }
        let e = listing(&mut h.s);
        assert_eq!(e.len() as u64, n + 1, "one event per entry and the head");
        let mut rng = SeededRng::from_seed([9; 32]);
        let mut t = h.s.store_mut().unwrap().transaction(&mut rng).unwrap();
        assert_eq!(t.log_end().unwrap(), 2 * n + 1, "each write appended once");
        // a cursor from before the promotions reads each promotion once
        let r = t.log_read(Some(&before), usize::MAX - 1).unwrap();
        assert!(!r.whole);
        assert_eq!(r.events.len() as u64, n);
    }
}

#[test]
fn a_restored_store_issues_no_cursor() {
    let mut h = host();
    let f = Fixture::new(0x40);
    h.s.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    put(&mut h.s, &f.label, 1, true, None, &[]);
    let early = read(&mut h.s, None).cursor.unwrap();
    h.s.store_mut().unwrap();
    let (backup, backup_root) = (h.backend.copy(), h.root.copy());
    put(&mut h.s, &f.label, 2, true, None, &[]);
    let late = read(&mut h.s, None).cursor.unwrap();
    // the restored store takes a write: what the lost store issued past the backup is no cursor
    let mut r = open(backup, backup_root, 2);
    put(&mut r.s, &f.label, 3, true, None, &[]);
    let from_late = read(&mut r.s, Some(&late));
    assert!(from_late.whole, "a cursor past the restore point reads from the start");
    assert_eq!(from_late.events.len(), 3);
    let from_early = read(&mut r.s, Some(&early));
    assert!(!from_early.whole, "a cursor the restored history holds is honoured");
    assert_eq!(from_early.events.iter().map(|e| e.event).collect::<Vec<_>>(), [NodeEvent::Added(f.label, osis_label::blob_id(&blob(3)))]);
}

// issues/net-one-peer.md step 4 (`host^.0` going drops the sync IDs kept for others, not the
// store): a dropped label leaves no row, no event and no blob only it held; the others stay whole
#[test]
fn dropping_a_label_leaves_nothing_of_it() {
    let mut h = host();
    let (f1, f2) = (Fixture::new(0x50), Fixture::new(0x60));
    let (l1, l2) = (f1.label, f2.label);
    let base = h.s.all_rows().unwrap().len();
    h.s.push_step(&l1, f1.genesis.clone(), Some(f1.genesis_claims.clone())).unwrap();
    h.s.push_step(&l2, f2.genesis.clone(), Some(f2.genesis_claims.clone())).unwrap();
    let only1: Vec<BlobId> = (0..4).map(|n| put(&mut h.s, &l1, n, n != 3, None, &[])).collect();
    // one blob under both labels: it stays with the label kept
    let shared = put(&mut h.s, &l1, 9, true, None, &[]);
    put(&mut h.s, &l2, 9, true, None, &[]);
    h.s.delete(&l1, &only1[0], T0).unwrap();
    let kept_rows: Vec<_> = {
        let before = h.s.all_rows().unwrap();
        before.into_iter().filter(|(k, _)| !k.windows(16).any(|w| w == l1.0)).collect()
    };
    let gone = h.s.drop_labels(&|l| *l == l1).unwrap();
    assert_eq!(gone, [l1]);
    assert_eq!(h.s.labels_after(None, 10).unwrap(), [l2]);
    assert!(only1.iter().all(|b| h.s.blob(b).unwrap().is_none()), "its blobs go");
    assert!(h.s.blob(&shared).unwrap().is_some(), "a blob another label holds stays");
    let rows = h.s.all_rows().unwrap();
    assert!(!rows.iter().any(|(k, _)| k.starts_with(b"L") && k.get(1..17) == Some(l1.0.as_slice())), "no meta");
    assert!(rows.len() >= base, "{} rows", rows.len());
    // what stays is what named only the other label, the totals and its sweep rows
    for (k, v) in &kept_rows {
        if !k.starts_with(b"N") && !k.starts_with(b"R") && !k.starts_with(b"Y") {
            assert!(rows.iter().any(|(k2, v2)| k2 == k && v2 == v), "row {k:?} of the label kept stays");
        }
    }
    let t = h.s.totals().unwrap();
    assert_eq!((t.labels, t.entries), (1, 1));
    let e = listing(&mut h.s);
    assert!(e.iter().all(|e| match e {
        NodeEvent::Added(l, _) | NodeEvent::Head(l) => *l == l2,
        NodeEvent::Deleted { label, .. } => *label == l2,
    }), "no event of the dropped label: {e:?}");
}
