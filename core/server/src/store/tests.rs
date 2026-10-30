//! BackendStore rules (spec/sync.md §4, §5): the state a blind node keeps, the policy it applies,
//! durability, and agreement with osis-proto's reference `MemoryLabelStore`.

use super::*;
use osis_base::{ManualClock, WallMs};
use osis_crypto::SeededRng;
use osis_proto::MemoryLabelStore;
use osis_proto::examples::Fixture;
use osis_store::MemoryBackend;
use proptest::prelude::*;

const T0: u64 = 1_700_000_000_000;
const DAY_MS: u64 = 86_400_000;

struct Env {
    clock: Arc<ManualClock>,
    store: BackendStore<MemoryBackend>,
    backend: MemoryBackend,
    f: Fixture,
}

fn env(policy: Policy) -> Env {
    let clock = Arc::new(ManualClock::new(WallMs(T0)));
    let backend = MemoryBackend::new();
    let mut store = BackendStore::open(backend.clone(), clock.clone(), policy, &mut SeededRng::from_seed([1; 32])).unwrap();
    let f = Fixture::new(0x10);
    store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
    Env { clock, store, backend, f }
}

fn blob(n: u8) -> Vec<u8> {
    let mut b = vec![n; 30 + n as usize];
    b[0] = 1;
    b
}

fn put(b: &[u8], stamped: bool, expiry: Option<u64>) -> Put<'_> {
    Put { blob_id: osis_label::blob_id(b), blob: b, wrap: [b.len() as u8; WRAP_LEN], stamp: stamped.then_some(Signature([b.len() as u8; 64])), expiry, ephemeral: false, presence: false, tie: 0, replaces: &[], now: 0 }
}

fn id(n: u8) -> BlobId {
    osis_label::blob_id(&blob(n))
}

// spec/sync.md §4: entries, log with sequence numbers, the head and its claim set; durable across reopen with the same log ID
#[test]
fn state_survives_reopen() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    assert_eq!(e.store.put(&l, put(&blob(1), true, None)).unwrap(), Code::OK);
    assert_eq!(e.store.put(&l, put(&blob(2), false, Some(T0 + 10))).unwrap(), Code::OK);
    e.store.push_step(&l, e.f.child.clone(), None).unwrap();
    let before = (e.store.log_head(&l).unwrap(), e.store.live_by_id(&l, None, 100).unwrap(), e.store.log_after(&l, 0, 100).unwrap());
    let again = BackendStore::open(e.backend.clone(), e.clock.clone(), Policy::default(), &mut SeededRng::from_seed([2; 32])).unwrap();
    let after = (again.log_head(&l).unwrap(), again.live_by_id(&l, None, 100).unwrap(), again.log_after(&l, 0, 100).unwrap());
    assert_eq!(before, after);
    assert_eq!(again.head(&l).unwrap(), Some(e.f.child.id()));
    assert_eq!(again.path(&l).unwrap(), vec![e.f.genesis.clone(), e.f.child.clone()]);
    assert_eq!(again.claim_set(&l, &e.f.genesis.id()).unwrap().as_deref(), Some(&e.f.genesis_claims));
    assert_eq!(again.claim_set(&l, &e.f.child.id()).unwrap(), None);
    assert_eq!(again.blob(&id(1)).unwrap(), Some(blob(1)));
    // a fresh instance names its logs differently: old cursors are invalid there
    let mut fresh = BackendStore::open(MemoryBackend::new(), e.clock.clone(), Policy::default(), &mut SeededRng::from_seed([3; 32])).unwrap();
    fresh.push_step(&l, e.f.genesis.clone(), None).unwrap();
    assert_ne!(fresh.log_head(&l).unwrap().0, before.0.0);
}

// spec/sync.md §4: blob bytes are stored once per node and deleted when no label references them
#[test]
fn blob_bytes_once_per_node() {
    let mut e = env(Policy::default());
    let g = Fixture::new(0x20);
    e.store.push_step(&g.label, g.genesis.clone(), None).unwrap();
    let b = blob(7);
    e.store.put(&e.f.label, put(&b, true, None)).unwrap();
    e.store.put(&g.label, put(&b, true, None)).unwrap();
    e.store.delete(&e.f.label, &id(7), T0).unwrap();
    assert_eq!(e.store.blob(&id(7)).unwrap(), Some(b.clone()));
    // the prefix bytes a delete by level checks live in the reference row, not the blob
    let big = vec![1u8; 4096];
    e.store.put(&e.f.label, put(&big, true, None)).unwrap();
    assert_eq!(e.store.blob_prefix(&osis_label::blob_id(&big)).unwrap(), Some(big[..osis_label::MAX_PREFIX_LEN].to_vec()));
    assert_eq!(e.store.blob_prefix(&id(7)).unwrap(), Some(b));
    e.store.delete(&e.f.label, &osis_label::blob_id(&big), T0).unwrap();
    e.store.delete(&g.label, &id(7), T0).unwrap();
    assert_eq!(e.store.blob(&id(7)).unwrap(), None);
    assert_eq!(e.store.blob_prefix(&id(7)).unwrap(), None);
    assert!(e.backend.scan_prefix(b"R", 10).unwrap().is_empty());
}

// spec/sync.md §5: an upload of a held blob replaces wrap and stamp and clears the deposited flag; a deposit of a held blob changes nothing
#[test]
fn replace_and_deposited_flag() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    let b = blob(3);
    e.store.put(&l, put(&b, false, None)).unwrap();
    assert_eq!(e.store.entry(&l, &id(3)).unwrap().unwrap().stamp, None);
    let seq = e.store.log_head(&l).unwrap().1;
    e.store.put(&l, put(&b, false, None)).unwrap();
    assert_eq!(e.store.log_head(&l).unwrap().1, seq);
    let mut p = put(&b, true, None);
    p.wrap = [9; WRAP_LEN];
    e.store.put(&l, p).unwrap();
    let m = e.store.entry(&l, &id(3)).unwrap().unwrap();
    assert_eq!((m.wrap, m.stamp.is_some(), m.add_seq), ([9; WRAP_LEN], true, seq + 1));
    // identical re-upload: nothing logged
    e.store.put(&l, p).unwrap();
    assert_eq!(e.store.log_head(&l).unwrap().1, seq + 1);
}

// spec/sync.md §5: deposit budget 64 + 4 x claim slots entries and x 32 KiB bytes; freed on stamp, delete, expiry
#[test]
fn deposit_budget() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    let max = 64 + 4 * e.f.genesis_claims.claims.len() as u64;
    assert_eq!(e.store.budget(&l).unwrap(), Budget { entries_left: max, bytes_left: max * DEPOSIT_ENTRY_BYTES });
    let blobs: Vec<Vec<u8>> = (0..max).map(|n| [&n.to_be_bytes()[..], &[0; 24]].concat()).collect();
    for (i, b) in blobs.iter().enumerate() {
        let expiry = (i == 0).then_some(T0 + 5);
        assert_eq!(e.store.put(&l, put(b, false, expiry)).unwrap(), Code::OK);
    }
    let extra = vec![0xee; 40];
    assert_eq!(e.store.put(&l, put(&extra, false, None)).unwrap(), Code::BUDGET_FULL);
    assert_eq!(e.store.budget(&l).unwrap().entries_left, 0);
    // stamped: out of the budget
    e.store.put(&l, put(&blobs[1], true, None)).unwrap();
    assert_eq!(e.store.budget(&l).unwrap().entries_left, 1);
    e.store.delete(&l, &osis_label::blob_id(&blobs[2]), T0).unwrap();
    assert_eq!(e.store.budget(&l).unwrap().entries_left, 2);
    e.store.sweep(T0 + 5, 1024).unwrap();
    assert_eq!(e.store.budget(&l).unwrap().entries_left, 3);
    // bytes: an entry larger than what remains
    let left = e.store.budget(&l).unwrap().bytes_left;
    let big = vec![0xbb; left as usize + 1];
    assert_eq!(e.store.put(&l, put(&big, false, None)).unwrap(), Code::BUDGET_FULL);
    // a new head with a bigger claim set raises the budget; a head without its set gives the floor
    e.store.push_step(&l, e.f.child.clone(), None).unwrap();
    assert_eq!(e.store.budget(&l).unwrap().entries_left, 64u64.saturating_sub(max - 3));
}

// spec/sync.md §5: servers cap storage per label (code 12); replacing a held entry is not capped
#[test]
fn storage_cap() {
    let mut e = env(Policy { cap_entries: 2, cap_bytes: 1000, ..Policy::default() });
    let l = e.f.label;
    assert_eq!(e.store.put(&l, put(&blob(1), true, None)).unwrap(), Code::OK);
    assert_eq!(e.store.put(&l, put(&vec![5; 1000], true, None)).unwrap(), Code::STORAGE_CAP);
    assert_eq!(e.store.put(&l, put(&blob(2), true, None)).unwrap(), Code::OK);
    assert_eq!(e.store.put(&l, put(&blob(3), true, None)).unwrap(), Code::STORAGE_CAP);
    let b2 = blob(2);
    let mut p = put(&b2, true, None);
    p.wrap = [1; WRAP_LEN];
    assert_eq!(e.store.put(&l, p).unwrap(), Code::OK);
    e.store.delete(&l, &id(1), T0).unwrap();
    assert_eq!(e.store.put(&l, put(&blob(3), true, None)).unwrap(), Code::OK);
}

// spec/sync.md §5: rate limits per label on deletes, wrap replacements (also per entry) and deposits (code 4); a new window resets them
#[test]
fn rate_limits() {
    let mut e = env(Policy { deletes: 2, replacements: 3, entry_replacements: 2, deposits: 1, ..Policy::default() });
    let l = e.f.label;
    for n in 0..5 {
        e.store.put(&l, put(&blob(n), true, None)).unwrap();
    }
    assert_eq!(e.store.delete(&l, &id(0), T0).unwrap(), Code::OK);
    assert_eq!(e.store.schedule_delete(&l, &id(1), T0 + 100).unwrap(), Code::OK);
    assert_eq!(e.store.delete(&l, &id(2), T0).unwrap(), Code::RATE_LIMITED);
    let replace = |s: &mut BackendStore<MemoryBackend>, n: u8, w: u8| {
        let b = blob(n);
        let mut p = put(&b, true, None);
        p.wrap = [w; WRAP_LEN];
        s.put(&l, p).unwrap()
    };
    assert_eq!(replace(&mut e.store, 3, 1), Code::OK);
    assert_eq!(replace(&mut e.store, 3, 2), Code::OK);
    assert_eq!(replace(&mut e.store, 3, 3), Code::RATE_LIMITED);
    assert_eq!(replace(&mut e.store, 4, 1), Code::OK);
    assert_eq!(replace(&mut e.store, 4, 2), Code::RATE_LIMITED);
    assert_eq!(e.store.put(&l, put(&blob(20), false, None)).unwrap(), Code::OK);
    assert_eq!(e.store.put(&l, put(&blob(21), false, None)).unwrap(), Code::RATE_LIMITED);
    e.clock.advance(60_000);
    assert_eq!(e.store.delete(&l, &id(2), T0).unwrap(), Code::OK);
    assert_eq!(replace(&mut e.store, 3, 3), Code::OK);
}

// spec/sync.md §5: timed deletes (earliest wins) execute at their time with a tombstone and a log event; expiry removes outright, no tombstone, no event; tombstones last TOMBSTONE_LIFETIME
#[test]
fn timed_deletes_expiry_tombstones() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    e.store.put(&l, put(&blob(1), true, None)).unwrap();
    e.store.put(&l, put(&blob(2), true, Some(T0 + 50))).unwrap();
    e.store.schedule_delete(&l, &id(1), T0 + 100).unwrap();
    let seq = e.store.log_head(&l).unwrap().1;
    e.store.schedule_delete(&l, &id(1), T0 + 200).unwrap();
    assert_eq!(e.store.log_head(&l).unwrap().1, seq);
    e.store.schedule_delete(&l, &id(1), T0 + 80).unwrap();
    assert_eq!(e.store.entry(&l, &id(1)).unwrap().unwrap().pending_delete, Some(T0 + 80));
    assert_eq!(e.store.next_due().unwrap(), Some(T0 + 50));
    assert!(e.store.sweep(T0 + 50, 1024).unwrap().grew.is_empty());
    assert_eq!(e.store.entry(&l, &id(2)).unwrap(), None);
    assert!(!e.store.tombstoned(&l, &id(2)).unwrap());
    assert_eq!(e.store.blob(&id(2)).unwrap(), None);
    assert_eq!(e.store.sweep(T0 + 80, 1024).unwrap().grew, BTreeSet::from([l]));
    assert!(e.store.tombstoned(&l, &id(1)).unwrap());
    let recs = e.store.log_after(&l, seq, 10).unwrap().unwrap();
    assert_eq!(recs.iter().map(|r| r.1.clone()).collect::<Vec<_>>(), vec![LogRecord::Pending(id(1), T0 + 80), LogRecord::Deleted(id(1))]);
    e.store.sweep(T0 + 80 + TOMBSTONE_LIFETIME_MS - 1, 1024).unwrap();
    assert!(e.store.tombstoned(&l, &id(1)).unwrap());
    e.store.sweep(T0 + 80 + TOMBSTONE_LIFETIME_MS, 1024).unwrap();
    assert!(!e.store.tombstoned(&l, &id(1)).unwrap());
    assert_eq!(e.store.next_due().unwrap(), None);
}

// spec/sync.md §4: a claim set is kept until its step has been superseded for MEMBERSHIP_KEEP
#[test]
fn claim_sets_dropped_after_membership_keep() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    e.store.push_step(&l, e.f.child.clone(), Some(e.f.child_claims.clone())).unwrap();
    let g = e.f.genesis.id();
    e.store.sweep(T0 + MEMBERSHIP_KEEP_MS - 1, 1024).unwrap();
    assert!(e.store.claim_set(&l, &g).unwrap().is_some());
    e.store.sweep(T0 + MEMBERSHIP_KEEP_MS, 1024).unwrap();
    assert!(e.store.claim_set(&l, &g).unwrap().is_none());
    assert!(e.store.claim_set(&l, &e.f.child.id()).unwrap().is_some());
    assert!(e.store.step(&l, &g).unwrap().is_some());
}

// spec/wire.md §11.2 Sync: the log keeps a horizon; cursors below it are refused (reconciliation fallback)
#[test]
fn log_horizon() {
    let mut e = env(Policy { log_keep: 8, ..Policy::default() });
    let l = e.f.label;
    for n in 0..20 {
        e.store.put(&l, put(&blob(n), true, None)).unwrap();
    }
    let (_, head) = e.store.log_head(&l).unwrap();
    assert_eq!(head, 21);
    assert_eq!(e.store.log_after(&l, 0, 100).unwrap(), None);
    let tail = e.store.log_after(&l, head - 8, 100).unwrap().unwrap();
    assert_eq!(tail.len(), 8);
    assert_eq!(e.store.log_after(&l, head + 1, 100).unwrap(), None);
    assert_eq!(e.store.live_ids(&l).unwrap().len(), 20);
}

fn eph_put(b: &[u8], expiry: Option<u64>) -> Put<'_> {
    Put { ephemeral: true, ..put(b, true, expiry) }
}

fn eph_blob(n: u32, len: usize) -> Vec<u8> {
    let mut b = vec![0u8; len.max(8)];
    b[0] = 1;
    b[1..5].copy_from_slice(&n.to_le_bytes());
    b
}

// ephemeral security review H2: a stranger looping upload and delete of ephemeral entries on its
// own label grows no memory without bound: tombstones and log records are charged to the label's
// cap, deletes are rate-limited, tombstones go after `EPH_TOMBSTONE_MS`, and the due-time index
// empties
#[test]
fn ephemeral_churn_memory_bounded() {
    let cap = 64 << 10;
    let mut e = env(Policy { ephemeral_bytes: cap, deletes: 200, ..Policy::default() });
    let l = e.f.label;
    let mut codes = BTreeMap::new();
    for n in 0..5_000u32 {
        let b = eph_blob(n, 40);
        let c = e.store.put(&l, eph_put(&b, None)).unwrap();
        *codes.entry(("put", c.0)).or_insert(0) += 1;
        let c = e.store.delete(&l, &osis_label::blob_id(&b), T0).unwrap();
        *codes.entry(("delete", c.0)).or_insert(0) += 1;
        assert!(e.store.ephemeral_bytes(&l) <= cap, "charged within the cap");
    }
    assert!(codes.contains_key(&("delete", Code::RATE_LIMITED.0)), "{codes:?}");
    assert!(codes.contains_key(&("put", Code::STORAGE_CAP.0)), "full of live entries: {codes:?}");
    e.clock.advance(EPH_TOMBSTONE_MS + 61_000);
    let now = e.clock.now_wall_ms().0;
    e.store.sweep(now, usize::MAX).unwrap();
    let left = e.store.ephemeral_bytes(&l);
    let live = e.store.eph.labels.get(&l).map_or(0, |x| x.entries.len()) as u64;
    assert!(e.store.eph.labels.get(&l).is_none_or(|x| x.tombstones.is_empty()), "tombstones dropped");
    assert!(left <= live * (48 + ENTRY_OVERHEAD) + EPH_LOG_KEEP as u64 * REC_OVERHEAD, "{left}");
    assert!(e.store.eph.due.len() as u64 <= live, "due index holds only live entries' times");
    // a deleted entry stays refused for the tombstone's lifetime only
    let mut e = env(Policy::default());
    let l = e.f.label;
    let now = e.clock.now_wall_ms().0;
    let b = eph_blob(99_999, 40);
    e.store.put(&l, eph_put(&b, None)).unwrap();
    e.store.delete(&l, &osis_label::blob_id(&b), now).unwrap();
    assert!(e.store.tombstoned(&l, &osis_label::blob_id(&b)).unwrap());
    e.clock.advance(EPH_TOMBSTONE_MS);
    e.store.sweep(e.clock.now_wall_ms().0, usize::MAX).unwrap();
    assert!(!e.store.tombstoned(&l, &osis_label::blob_id(&b)).unwrap());
}

// ephemeral security review M4: a stranger filling the node-wide ephemeral cap with its own
// labels does not lock another label out: the label charged most gives way (oldest first)
#[test]
fn ephemeral_total_evicts_largest_label() {
    let per = 32 << 10;
    let mut e = env(Policy { ephemeral_bytes: per, ephemeral_total: 4 * per, ..Policy::default() });
    let mut strangers = Vec::new();
    for i in 0..6u8 {
        let f = Fixture::new(0x20 + 6 * i);
        e.store.push_step(&f.label, f.genesis.clone(), Some(f.genesis_claims.clone())).unwrap();
        strangers.push(f.label);
    }
    let mut n = 0u32;
    for l in &strangers {
        for _ in 0..40 {
            n += 1;
            e.store.put(l, eph_put(&eph_blob(n, 1_000), None)).unwrap();
        }
    }
    assert!(e.store.ephemeral_total() <= 4 * per);
    let honest = e.f.label;
    for k in 0..10u32 {
        assert_eq!(e.store.put(&honest, eph_put(&eph_blob(1_000_000 + k, 500), None)).unwrap(), Code::OK, "the honest label gets in");
    }
    assert!(e.store.ephemeral_total() <= 4 * per);
    assert_eq!(e.store.eph.labels.get(&honest).map_or(0, |x| x.entries.len()), 10);
}

// ephemeral security review M7: ephemeral churn takes sequence numbers from the label's log but
// neither trims durable records nor sends a durable cursor back to reconciliation
#[test]
fn ephemeral_churn_keeps_durable_cursors() {
    let mut e = env(Policy { log_keep: 8, deletes: u32::MAX, ..Policy::default() });
    let l = e.f.label;
    for n in 0..4 {
        e.store.put(&l, put(&blob(n), true, None)).unwrap();
    }
    let (_, cursor) = e.store.log_head(&l).unwrap();
    for n in 0..(EPH_LOG_KEEP as u32) {
        let b = eph_blob(n, 40);
        e.store.put(&l, eph_put(&b, None)).unwrap();
        e.store.delete(&l, &osis_label::blob_id(&b), T0).unwrap();
    }
    e.store.put(&l, put(&blob(9), true, None)).unwrap();
    let recs = e.store.log_after(&l, cursor, usize::MAX).unwrap().expect("the cursor still reaches");
    assert!(recs.iter().any(|(_, r)| *r == LogRecord::Added(id(9))));
    assert!(e.store.log_after(&l, 0, usize::MAX).unwrap().is_some(), "4 durable records + head: under log_keep");
    // a live ephemeral entry whose add record was trimmed still reaches an old cursor
    let live = eph_blob(7_777_777, 40);
    e.store.put(&l, eph_put(&live, None)).unwrap();
    for n in 0..(EPH_LOG_KEEP as u32) {
        let b = eph_blob(8_000_000 + n, 40);
        e.store.put(&l, eph_put(&b, None)).unwrap();
        e.store.delete(&l, &osis_label::blob_id(&b), T0).unwrap();
    }
    let recs = e.store.log_after(&l, cursor, usize::MAX).unwrap().unwrap();
    assert!(recs.iter().any(|(_, r)| *r == LogRecord::Added(osis_label::blob_id(&live))));
}

// ENTRY_OVERHEAD, TOMB_OVERHEAD, REC_OVERHEAD count what the in-memory structures cost (each
// map entry with about half again for B-tree slack or hash load)
#[test]
fn overheads_cover_the_structures() {
    use std::mem::size_of;
    let slack = |n: usize| (n * 3 / 2) as u64;
    let entry = slack(size_of::<(BlobId, EphEntry)>())
        + slack(size_of::<(BlobId, (Vec<u8>, usize))>() + 1)
        + slack(size_of::<(u64, BlobId)>())
        + 2 * slack(size_of::<(u64, LabelId, BlobId)>())
        + slack(size_of::<((LabelId, BlobId), [u8; 32])>() + 1)
        + 32;
    assert!(entry <= ENTRY_OVERHEAD, "{entry}");
    let tomb = slack(size_of::<(BlobId, u64)>()) + slack(size_of::<(u64, LabelId, BlobId)>());
    assert!(tomb <= TOMB_OVERHEAD, "{tomb}");
    assert!(slack(size_of::<(u64, EphRec)>()) <= REC_OVERHEAD, "{}", size_of::<(u64, EphRec)>());
}

// spec/sync.md §4: `live_by_id` pages ascending from after a given ID
#[test]
fn live_by_id_pages() {
    let mut e = env(Policy::default());
    let l = e.f.label;
    for n in 0..10 {
        e.store.put(&l, put(&blob(n), true, None)).unwrap();
    }
    let mut all: Vec<BlobId> = (0..10).map(id).collect();
    all.sort();
    assert_eq!(e.store.live_ids(&l).unwrap(), all);
    let page = e.store.live_by_id(&l, Some(&all[3]), 4).unwrap();
    assert_eq!(page.iter().map(|p| p.0).collect::<Vec<_>>(), all[4..8]);
    assert!(e.store.live_ids(&LabelId([0xee; 16])).unwrap().is_empty());
    assert_eq!(e.store.live_ids_in(&l, &all[2], Some(&all[7])).unwrap(), all[2..7]);
    assert_eq!(e.store.live_ids_in(&l, &all[7], None).unwrap(), all[7..]);
    assert!(e.store.live_ids_in(&l, &all[7], Some(&all[2])).unwrap().is_empty());
}

#[derive(Clone, Debug)]
enum Op {
    Put { n: u8, stamped: bool, wrap: u8, label: bool },
    Delete { n: u8, label: bool },
    Schedule { n: u8, after: u64 },
    Step,
    Sweep { advance: u64 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..12, any::<bool>(), 0u8..3, any::<bool>()).prop_map(|(n, stamped, wrap, label)| Op::Put { n, stamped, wrap, label }),
        2 => (0u8..12, any::<bool>()).prop_map(|(n, label)| Op::Delete { n, label }),
        1 => (0u8..12, 0u64..20).prop_map(|(n, after)| Op::Schedule { n, after: after * DAY_MS / 4 }),
        1 => Just(Op::Step),
        1 => (0u64..20).prop_map(|a| Op::Sweep { advance: a * DAY_MS }),
    ]
}

/// Expiry of blob `n` (fixed per blob, as a prefix fixes it).
fn expiry_of(n: u8) -> Option<u64> {
    n.is_multiple_of(4).then_some(T0 + u64::from(n) * DAY_MS)
}

proptest! {
    // spec/sync.md §4, §5: BackendStore answers exactly as the reference MemoryLabelStore (no policy limits), and its log replays to its state
    #[test]
    fn agrees_with_reference_and_replays(ops in prop::collection::vec(op(), 1..40)) {
        let mut e = env(Policy::unlimited());
        let g = Fixture::new(0x20);
        e.store.push_step(&g.label, g.genesis.clone(), None).unwrap();
        let mut r = MemoryLabelStore::new([0; 32]);
        r.push_step(&e.f.label, e.f.genesis.clone(), Some(e.f.genesis_claims.clone())).unwrap();
        r.push_step(&g.label, g.genesis.clone(), None).unwrap();
        let mut now = T0;
        let mut stepped = false;
        let mut expired = false;
        for o in &ops {
            let pick = |second: bool| if second { g.label } else { e.f.label };
            match o.clone() {
                Op::Put { n, stamped, wrap, label } => {
                    let b = blob(n);
                    let mut p = put(&b, stamped, expiry_of(n));
                    p.wrap = [wrap; WRAP_LEN];
                    if p.expiry.is_some_and(|t| t <= now) {
                        continue; // the engine refuses an expired prefix
                    }
                    let l = pick(label);
                    if r.tombstoned(&l, &p.blob_id).unwrap() {
                        continue; // the engine refuses a tombstoned ID
                    }
                    prop_assert_eq!(e.store.put(&l, p).unwrap(), r.put(&l, p).unwrap());
                }
                Op::Delete { n, label } => {
                    let l = pick(label);
                    prop_assert_eq!(e.store.delete(&l, &id(n), now).unwrap(), r.delete(&l, &id(n), now).unwrap());
                }
                Op::Schedule { n, after } => {
                    let l = e.f.label;
                    prop_assert_eq!(e.store.schedule_delete(&l, &id(n), now + after + 1).unwrap(), r.schedule_delete(&l, &id(n), now + after + 1).unwrap());
                }
                Op::Step => {
                    if !stepped {
                        stepped = true;
                        e.store.push_step(&e.f.label, e.f.child.clone(), Some(e.f.child_claims.clone())).unwrap();
                        r.push_step(&e.f.label, e.f.child.clone(), Some(e.f.child_claims.clone())).unwrap();
                    }
                }
                Op::Sweep { advance } => {
                    now += advance;
                    e.clock.set(WallMs(now));
                    expired |= (0..12).any(|n| expiry_of(n).is_some_and(|t| t <= now));
                    e.store.sweep(now, usize::MAX).unwrap();
                    r.sweep(now);
                }
            }
            for l in [e.f.label, g.label] {
                prop_assert_eq!(e.store.live_by_id(&l, None, 100).unwrap(), r.live_by_id(&l, None, 100).unwrap());
                for (lo, hi) in [(0u8, None), (3, Some(9)), (9, Some(3)), (6, None)] {
                    let (lo, hi) = (id(lo), hi.map(id));
                    prop_assert_eq!(e.store.live_ids_in(&l, &lo, hi.as_ref()).unwrap(), r.live_ids_in(&l, &lo, hi.as_ref()).unwrap());
                }
                prop_assert_eq!(e.store.budget(&l).unwrap(), r.budget(&l).unwrap());
                prop_assert_eq!(e.store.log_head(&l).unwrap().1, r.log_head(&l).unwrap().1);
                // the same records; a sweep executes due deletes by time, the reference by ID
                let recs = |v: Vec<(u64, LogRecord)>| { let mut v: Vec<String> = v.into_iter().map(|r| format!("{:?}", r.1)).collect(); v.sort(); v };
                prop_assert_eq!(recs(e.store.log_after(&l, 0, 1000).unwrap().unwrap()), recs(r.log_after(&l, 0, 1000).unwrap().unwrap()));
                prop_assert_eq!(e.store.head(&l).unwrap(), r.head(&l).unwrap());
                prop_assert_eq!(e.store.head_keys(&l).unwrap(), osis_proto::HeadKeys::of_path(&e.store.path(&l).unwrap()));
                for s in [None, Some(e.f.genesis.id()), Some(e.f.child.id())] {
                    prop_assert_eq!(e.store.child(&l, s.as_ref()).unwrap(), r.child(&l, s.as_ref()).unwrap());
                }
                let sync = e.f.genesis.keys.sync;
                prop_assert_eq!(e.store.step_with_sync(&l, &sync).unwrap(), r.step_with_sync(&l, &sync).unwrap());
                for n in 0..12 {
                    prop_assert_eq!(e.store.tombstoned(&l, &id(n)).unwrap(), r.tombstoned(&l, &id(n)).unwrap());
                    prop_assert_eq!(e.store.blob(&id(n)).unwrap(), r.blob(&id(n)).unwrap());
                }
            }
        }
        // replay: adds and deletes of the log give the live set (expiry logs nothing, so only without it)
        if !expired {
            for l in [e.f.label, g.label] {
                let mut live = BTreeSet::new();
                let mut head = None;
                for (_, rec) in e.store.log_after(&l, 0, 10_000).unwrap().unwrap() {
                    match rec {
                        LogRecord::Added(b) => { live.insert(b); }
                        LogRecord::Deleted(b) => { live.remove(&b); }
                        LogRecord::Pending(..) => {}
                        LogRecord::Head(s) => head = Some(s.id()),
                    }
                }
                prop_assert_eq!(live.into_iter().collect::<Vec<_>>(), e.store.live_ids(&l).unwrap());
                prop_assert_eq!(head, e.store.head(&l).unwrap());
            }
        }
    }
}

// spec/sync.md §5 (servers may rate-limit deletes; a presence entry's leaves no tombstone):
// deletes of presence entries are not counted against the label's delete rate (an author
// replaces its presence entry per update), other ephemeral deletes still are
#[test]
fn presence_deletes_not_rate_limited() {
    let mut e = env(Policy { deletes: 2, ..Policy::default() });
    let l = e.f.label;
    let blobs: Vec<Vec<u8>> = (0..10).map(|n| eph_blob(n, 64)).collect();
    for b in &blobs[..6] {
        assert_eq!(e.store.put(&l, Put { presence: true, ..eph_put(b, None) }).unwrap(), Code::OK);
    }
    for b in &blobs[6..] {
        assert_eq!(e.store.put(&l, eph_put(b, None)).unwrap(), Code::OK);
    }
    for b in &blobs[..6] {
        assert_eq!(e.store.delete(&l, &osis_label::blob_id(b), T0).unwrap(), Code::OK);
    }
    assert_eq!(e.store.delete(&l, &osis_label::blob_id(&blobs[6]), T0).unwrap(), Code::OK);
    assert_eq!(e.store.delete(&l, &osis_label::blob_id(&blobs[7]), T0).unwrap(), Code::OK);
    assert_eq!(e.store.delete(&l, &osis_label::blob_id(&blobs[8]), T0).unwrap(), Code::RATE_LIMITED);
}

// spec/sync.md §5 (ephemeral memory capped per label, log records counted): the log records of
// deletions (a presence entry replaced per update, a covered entry deleted) stay within the
// label's cap: older records are trimmed (sim `ephemeral` seed 13: a label 58 B over its cap)
#[test]
fn deletion_records_within_cap() {
    let cap = 8 << 10;
    let mut e = env(Policy { ephemeral_bytes: cap, deletes: 1_000, ..Policy::default() });
    let l = e.f.label;
    let mut n = 0u32;
    // plain entries up to the cap
    while e.store.put(&l, eph_put(&eph_blob(n, 64), None)).unwrap() == Code::OK {
        n += 1;
    }
    let plain = n;
    for k in 0..200u32 {
        let b = eph_blob(1_000_000 + k, 64);
        assert_eq!(e.store.put(&l, Put { presence: true, ..eph_put(&b, None) }).unwrap(), Code::OK);
        assert_eq!(e.store.delete(&l, &osis_label::blob_id(&b), T0).unwrap(), Code::OK);
        assert!(e.store.ephemeral_bytes(&l) <= cap, "presence deletes: {} B over {cap}", e.store.ephemeral_bytes(&l));
    }
    for k in 0..plain {
        e.store.delete(&l, &osis_label::blob_id(&eph_blob(k, 64)), T0).unwrap();
        assert!(e.store.ephemeral_bytes(&l) <= cap, "deletes: {} B over {cap}", e.store.ephemeral_bytes(&l));
    }
}

/// The path indexes (`V`, `W` rows) against the whole path: each step's child is the next one,
/// the genesis the child of none, none past the head; each key of `pool` names the newest step
/// registering it as sync key.
fn check_indexes(store: &BackendStore<MemoryBackend>, l: &LabelId, path: &[Step], pool: &[osis_crypto::VerifyingKey]) -> Result<(), String> {
    let ids: Vec<StepId> = path.iter().map(|s| s.id()).collect();
    let mut want = vec![(None, ids.first().copied())];
    want.extend(ids.iter().enumerate().map(|(i, id)| (Some(*id), ids.get(i + 1).copied())));
    want.push((Some(StepId([0xee; 32])), None));
    for (at, child) in want {
        let got = store.child(l, at.as_ref()).map_err(|e| e.to_string())?;
        if got != child {
            return Err(format!("child of {at:?}: {got:?}, want {child:?}"));
        }
    }
    for pk in pool {
        let newest = path.iter().rev().find(|s| s.keys.sync == *pk).map(|s| s.id());
        let got = store.step_with_sync(l, pk).map_err(|e| e.to_string())?;
        if got != newest {
            return Err(format!("sync key {pk:?}: {got:?}, want {newest:?}"));
        }
    }
    Ok(())
}

// spec/sync.md §5 (code 9, Open, Path): what the store keeps step by step (the `K` head keys,
// the `V` sync-key and `W` child indexes) agrees with the whole path (`HeadKeys::of_path`, a
// scan), across reopens, on long paths whose keys repeat and run past `OLDER_KEYS` distinct ones
#[test]
fn path_records_follow_path_across_reopen() {
    let key = |n: u8| osis_crypto::SigningSecret::from_seed(&osis_crypto::Secret32::from_bytes([n; 32])).verifying_key();
    for seed in 0..8u8 {
        let mut e = env(Policy::unlimited());
        let l = e.f.label;
        let mut prev = e.f.genesis.clone();
        for i in 0..40u32 {
            let h = osis_base::hash::hash(&[seed.to_le_bytes().as_slice(), &i.to_le_bytes()].concat());
            let pool = 2 + seed * 4;
            let mut s = e.f.genesis.clone();
            s.prev = Some(prev.id());
            s.keys.sync = key(1 + h[0] % pool);
            s.keys.write = key(1 + h[1] % pool);
            s.keys.delete = key(1 + h[2] % 3);
            s.keys.deposit = key(1 + h[3] % pool);
            e.store.push_step(&l, s.clone(), None).unwrap();
            prev = s;
            if h[4].is_multiple_of(7) {
                e.store = BackendStore::open(e.backend.clone(), e.clock.clone(), Policy::unlimited(), &mut SeededRng::from_seed([h[5]; 32])).unwrap();
            }
            let path = e.store.path(&l).unwrap();
            assert_eq!(e.store.head_keys(&l).unwrap(), osis_proto::HeadKeys::of_path(&path), "seed {seed} step {i}");
            let pool: Vec<_> = (1..=pool).map(key).collect();
            if let Err(m) = check_indexes(&e.store, &l, &path, &pool) {
                panic!("seed {seed} step {i}: {m}");
            }
        }
    }
}
