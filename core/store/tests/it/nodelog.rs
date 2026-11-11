#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! spec: none (the node log's layout is the store's own; issues/net-reconnect.md, One node log,
//! and core/test/tla/net/README.md `SN_inc`, `SN_copies`, `SN_history` state its properties).

use crate::common;

use common::*;
use osis_base::format::TOMBSTONE_LIFETIME_MS;
use osis_base::{BlobId, LabelId};
use osis_crypto::SeededRng;
use osis_store::{Fault, INCARNATIONS_KEPT, MemoryBackend, MemoryRoot, NodeEvent, Shred, Store, StoreConfig};

fn l(n: u8) -> LabelId {
    LabelId([n; 16])
}

fn b(n: u32) -> BlobId {
    let mut id = [0; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    BlobId(id)
}

fn big() -> StoreConfig {
    StoreConfig::default()
}

struct Dev {
    backend: MemoryBackend,
    root: MemoryRoot,
}

impl Dev {
    fn new() -> (Dev, Store, SeededRng) {
        let mut rng = SeededRng::from_u64(7);
        let d = MemDevice::new();
        let s = Store::create(d.backend(), d.root(), cfg(), &mut rng).unwrap();
        (Dev { backend: d.backend, root: d.root }, s, rng)
    }
    fn open(&self) -> Store {
        Store::open(Box::new(self.backend.clone()), Box::new(self.root.clone()), cfg()).unwrap()
    }
    /// The device as it stands: a backup, or a copy to run beside it.
    fn copy(&self) -> Dev {
        Dev { backend: self.backend.copy(), root: self.root.copy() }
    }
}

fn add(s: &mut Store, rng: &mut SeededRng, n: u32) {
    let mut t = s.transaction(rng).unwrap();
    t.log_added(l(1), b(n)).unwrap();
    t.commit().unwrap();
}

/// A cursor at the log's end.
fn at_end(s: &mut Store, rng: &mut SeededRng) -> Vec<u8> {
    let mut t = s.transaction(rng).unwrap();
    let end = t.log_end().unwrap();
    t.log_cursor(end).unwrap().unwrap()
}

fn position(s: &mut Store, rng: &mut SeededRng, c: &[u8]) -> Option<u64> {
    s.transaction(rng).unwrap().log_position(c).unwrap()
}

fn events(s: &mut Store, rng: &mut SeededRng) -> Vec<NodeEvent> {
    s.transaction(rng).unwrap().log_read(None, usize::MAX - 1).unwrap().events.into_iter().map(|e| e.event).collect()
}

#[test]
fn read_pages_in_order_and_resumes_from_its_cursor() {
    let (_d, mut s, mut rng) = Dev::new();
    for n in 1..=5 {
        add(&mut s, &mut rng, n);
    }
    let mut t = s.transaction(&mut rng).unwrap();
    let r = t.log_read(None, 2).unwrap();
    assert!(r.whole && r.more);
    assert_eq!(r.events.iter().map(|e| e.pos).collect::<Vec<_>>(), [1, 2]);
    let r = t.log_read(r.cursor.as_deref(), 2).unwrap();
    assert!(!r.whole && r.more);
    assert_eq!(r.events.iter().map(|e| e.pos).collect::<Vec<_>>(), [3, 4]);
    let r = t.log_read(r.cursor.as_deref(), 2).unwrap();
    assert!(!r.whole && !r.more);
    assert_eq!(r.events.iter().map(|e| e.pos).collect::<Vec<_>>(), [5]);
    let again = t.log_read(r.cursor.as_deref(), 2).unwrap();
    assert!(!again.whole && !again.more && again.events.is_empty(), "a cursor at the end has nothing after it");
}

#[test]
fn empty_log_has_no_cursor() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    let r = t.log_read(None, 10).unwrap();
    assert!(r.whole && r.events.is_empty() && r.cursor.is_none());
    assert_eq!(t.log_cursor(0).unwrap(), None);
}

// the model's assumption: the log and the record are one atomic unit
#[test]
fn crash_at_any_write_keeps_event_and_effect_together() {
    let mut writes = 0;
    let (d, mut s, mut rng) = Dev::new();
    let base = d.backend.faults().writes();
    let mut t = s.transaction(&mut rng).unwrap();
    t.put_local(b"effect", b"1", Shred::Yes).unwrap();
    t.log_added(l(1), b(1)).unwrap();
    t.commit().unwrap();
    writes += d.backend.faults().writes() - base;
    assert!(writes > 0);
    let (mut seen_before, mut seen_after) = (false, false);
    for k in 0..=writes + 2 {
        let (d, mut s, mut rng) = Dev::new();
        d.backend.faults().at(k, Fault::Crash);
        let mut t = s.transaction(&mut rng).unwrap();
        t.put_local(b"effect", b"1", Shred::Yes).unwrap();
        t.log_added(l(1), b(1)).unwrap();
        let _ = t.commit();
        drop(s);
        d.backend.faults().revive();
        let mut s = d.open();
        let mut t = s.transaction(&mut rng).unwrap();
        let effect = t.get_local(b"effect").unwrap().is_some();
        let logged = !t.log_read(None, 10).unwrap().events.is_empty();
        assert_eq!(effect, logged, "crash at write {k}: the entry and its event split");
        seen_before |= !effect;
        seen_after |= effect;
    }
    assert!(seen_before && seen_after, "the crash points reach both outcomes");
}

#[test]
fn a_rolled_back_append_leaves_the_draw_for_the_next() {
    let (d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    let c = at_end(&mut s, &mut rng);
    drop(s);
    let mut s = d.open();
    {
        let mut t = s.transaction(&mut rng).unwrap();
        t.log_added(l(1), b(2)).unwrap();
    }
    add(&mut s, &mut rng, 2);
    assert_eq!(position(&mut s, &mut rng, &c), Some(1), "the incarnation before is recorded by the append that committed");
}

// SN_history: the first append after a start records the incarnation before it, so a restart honours earlier cursors
#[test]
fn restart_with_appends_honours_earlier_cursors() {
    let (d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    let c1 = at_end(&mut s, &mut rng);
    add(&mut s, &mut rng, 2);
    let c2 = at_end(&mut s, &mut rng);
    drop(s);
    let mut s = d.open();
    add(&mut s, &mut rng, 3);
    assert_eq!(position(&mut s, &mut rng, &c1), Some(1));
    assert_eq!(position(&mut s, &mut rng, &c2), Some(2));
    let c3 = at_end(&mut s, &mut rng);
    assert_eq!(c3.len(), osis_store::CURSOR_LEN);
    drop(s);
    let mut s = d.open();
    add(&mut s, &mut rng, 4);
    let r = s.transaction(&mut rng).unwrap().log_read(Some(&c2), 10).unwrap();
    assert!(!r.whole, "two restarts later a cursor still resumes");
    assert_eq!(r.events.iter().map(|e| e.pos).collect::<Vec<_>>(), [3, 4]);
}

// a start that appends nothing costs nothing, and the cursor it issues names the incarnation still current
#[test]
fn restart_without_appends_writes_nothing() {
    let (d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    let c = at_end(&mut s, &mut rng);
    drop(s);
    let before = d.backend.dump();
    let mut s = d.open();
    let c2 = at_end(&mut s, &mut rng);
    assert_eq!(position(&mut s, &mut rng, &c), Some(1));
    let mut t = s.transaction(&mut rng).unwrap();
    t.log_read(Some(&c2), 10).unwrap();
    let end = t.log_end().unwrap();
    t.log_cursor(end).unwrap().unwrap();
    t.log_position(&c).unwrap().unwrap();
    t.commit().unwrap();
    drop(s);
    assert_eq!(d.backend.dump(), before, "a start and a read draw no incarnation");
    let mut s = d.open();
    add(&mut s, &mut rng, 2);
    assert_eq!(position(&mut s, &mut rng, &c2), Some(1), "a cursor issued by an appendless start names the incarnation that ended at 1");
}

// SN_inc: a cursor is honoured only on this store's own history. The restored store's positions pass its lost
// sibling's: only the ended incarnation's recorded end tells the lost cursor from one it holds.
#[test]
fn restored_store_refuses_cursors_from_the_lost_history() {
    let (d, mut s, mut rng) = Dev::new();
    for n in 1..=3 {
        add(&mut s, &mut rng, n);
    }
    let held = at_end(&mut s, &mut rng);
    let backup = d.copy();
    for n in 4..=9 {
        add(&mut s, &mut rng, n);
    }
    let lost = at_end(&mut s, &mut rng);
    drop(s);
    let mut r = backup.open();
    assert_eq!(position(&mut r, &mut rng, &lost), None, "past the restored end");
    for n in 10..=20 {
        add(&mut r, &mut rng, n);
    }
    assert_eq!(position(&mut r, &mut rng, &held), Some(3), "a cursor the restored history holds names what it covers");
    assert_eq!(position(&mut r, &mut rng, &lost), None, "position 9 of the lost history is not this store's 9");
    let rd = r.transaction(&mut rng).unwrap().log_read(Some(&lost), 100).unwrap();
    assert!(rd.whole, "no cursor reads from the start");
}

// SN_copies: a copy running beside the original
#[test]
fn live_copy_cursors_are_no_cursor_at_the_other() {
    let (d, mut orig, mut rng) = Dev::new();
    for n in 1..=3 {
        add(&mut orig, &mut rng, n);
    }
    let shared = at_end(&mut orig, &mut rng);
    let mut copy = d.copy().open();
    for n in 4..=8 {
        add(&mut orig, &mut rng, n);
    }
    let of_orig = at_end(&mut orig, &mut rng);
    for n in 100..=110 {
        add(&mut copy, &mut rng, n);
    }
    let of_copy = at_end(&mut copy, &mut rng);
    for n in 9..=30 {
        add(&mut orig, &mut rng, n);
    }
    assert_eq!(position(&mut orig, &mut rng, &of_copy), None, "the copy's incarnation is unknown to the original");
    assert_eq!(position(&mut copy, &mut rng, &of_orig), None, "the original's cursor is past the end the copy recorded for it");
    assert_eq!(position(&mut orig, &mut rng, &shared), Some(3));
    assert_eq!(position(&mut copy, &mut rng, &shared), Some(3), "a position of the shared history names the same events on both");
}

#[test]
fn garbage_and_foreign_cursors_are_no_cursor() {
    let (_d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    let mut c = at_end(&mut s, &mut rng);
    let (_d2, mut other, _) = Dev::new();
    let mut rng2 = SeededRng::from_u64(8);
    add(&mut other, &mut rng2, 1);
    let foreign = at_end(&mut other, &mut rng2);
    assert_eq!(position(&mut s, &mut rng, &foreign), None, "another store's key");
    assert_eq!(position(&mut s, &mut rng, b""), None);
    assert_eq!(position(&mut s, &mut rng, &c[..10]), None);
    c[30] ^= 1;
    assert_eq!(position(&mut s, &mut rng, &c), None, "a cursor is authenticated");
}

#[test]
fn incarnation_list_is_capped_oldest_first() {
    let (_d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 0);
    let mut cursors = vec![at_end(&mut s, &mut rng)];
    for n in 1..=INCARNATIONS_KEPT as u32 + 1 {
        s.reopen().unwrap();
        add(&mut s, &mut rng, n);
        cursors.push(at_end(&mut s, &mut rng));
    }
    // the list holds the KEPT incarnations before the current: the oldest, and only it, fell out
    assert_eq!(position(&mut s, &mut rng, &cursors[0]), None, "evicted");
    assert_eq!(position(&mut s, &mut rng, &cursors[1]), Some(2), "the oldest kept");
    assert_eq!(position(&mut s, &mut rng, cursors.last().unwrap()), Some(INCARNATIONS_KEPT as u64 + 2));
}

#[test]
fn an_entry_keeps_one_event_and_a_listing_is_the_live_set() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    for _ in 0..5 {
        t.log_added(l(1), b(1)).unwrap();
    }
    t.log_added(l(1), b(2)).unwrap();
    t.log_deleted(l(1), b(2), 50).unwrap();
    t.commit().unwrap();
    assert_eq!(events(&mut s, &mut rng), [NodeEvent::Added(l(1), b(1)), NodeEvent::Deleted { label: l(1), blob: b(2), at: 50 }]);
}

// compaction drops an earlier event but a cursor before the drop still gets the later one
#[test]
fn compaction_never_hides_the_later_event_from_a_cursor() {
    let (_d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    add(&mut s, &mut rng, 2);
    let c = at_end(&mut s, &mut rng);
    add(&mut s, &mut rng, 1);
    let r = s.transaction(&mut rng).unwrap().log_read(Some(&c), 10).unwrap();
    assert_eq!(r.events.iter().map(|e| e.event).collect::<Vec<_>>(), [NodeEvent::Added(l(1), b(1))]);
}

#[test]
fn deletion_events_last_the_tombstone_lifetime() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    t.log_deleted(l(1), b(1), 100).unwrap();
    t.log_deleted(l(1), b(2), 200).unwrap();
    t.log_added(l(1), b(3)).unwrap();
    assert!(!t.log_sweep(100 + TOMBSTONE_LIFETIME_MS - 1).unwrap());
    assert_eq!(t.log_read(None, 10).unwrap().events.len(), 3);
    assert!(!t.log_sweep(100 + TOMBSTONE_LIFETIME_MS).unwrap());
    let left: Vec<_> = t.log_read(None, 10).unwrap().events.into_iter().map(|e| e.event).collect();
    assert_eq!(left, [NodeEvent::Deleted { label: l(1), blob: b(2), at: 200 }, NodeEvent::Added(l(1), b(3))]);
    t.log_deleted(l(1), b(1), 300).unwrap();
    t.commit().unwrap();
    assert_eq!(events(&mut s, &mut rng).len(), 3, "the swept entry's slot went with its event, so a later deletion logs");
}

#[test]
fn a_readded_entry_is_not_swept_as_its_old_deletion() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    t.log_deleted(l(1), b(1), 100).unwrap();
    t.log_added(l(1), b(1)).unwrap();
    t.log_sweep(u64::MAX / 2).unwrap();
    assert_eq!(t.log_read(None, 10).unwrap().events.iter().map(|e| e.event).collect::<Vec<_>>(), [NodeEvent::Added(l(1), b(1))]);
}

// bounded by what the node holds: a swept deletion leaves nothing behind (a stale slot would
// cost about 60 B per entry ever deleted)
#[test]
fn swept_entries_leave_no_rows() {
    let (d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 0);
    let baseline = d.backend.held_bytes();
    let n = 400;
    let mut t = s.transaction(&mut rng).unwrap();
    for i in 1..=n {
        t.log_added(l(1), b(i)).unwrap();
        t.log_deleted(l(1), b(i), 1).unwrap();
    }
    while t.log_sweep(1 + TOMBSTONE_LIFETIME_MS).unwrap() {}
    t.commit().unwrap();
    let grown = d.backend.held_bytes().saturating_sub(baseline);
    assert!(grown < u64::from(n) * 20, "{grown} B left behind by {n} swept entries");
}

#[test]
fn sweep_pages_until_done() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    for n in 0..600 {
        t.log_deleted(l(1), b(n), 1).unwrap();
    }
    let mut rounds = 0;
    while t.log_sweep(1 + TOMBSTONE_LIFETIME_MS).unwrap() {
        rounds += 1;
    }
    assert_eq!(rounds, 2, "two full pages, then a short one");
    assert!(t.log_read(None, 10).unwrap().events.is_empty());
}

#[test]
fn forgetting_a_label_logs_no_deletion_and_keeps_others() {
    let (_d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    for n in 0..600 {
        t.log_added(l(1), b(n)).unwrap();
    }
    t.log_deleted(l(1), b(999), 7).unwrap();
    t.log_head(l(1), &[1; 32]).unwrap();
    t.log_added(l(2), b(1)).unwrap();
    t.log_forget(l(1)).unwrap();
    assert_eq!(t.log_read(None, 10_000).unwrap().events.iter().map(|e| e.event).collect::<Vec<_>>(), [NodeEvent::Added(l(2), b(1))]);
    assert!(t.log_heads().unwrap().is_empty());
    assert!(!t.log_sweep(u64::MAX / 2).unwrap());
}

#[test]
fn a_head_is_logged_only_when_it_moves_and_keeps_one_event() {
    let (d, mut s, mut rng) = Dev::new();
    let mut t = s.transaction(&mut rng).unwrap();
    assert!(t.log_head(l(1), &[1; 32]).unwrap());
    assert!(!t.log_head(l(1), &[1; 32]).unwrap());
    assert!(t.log_head(l(1), &[2; 32]).unwrap());
    t.commit().unwrap();
    assert_eq!(events(&mut s, &mut rng), [NodeEvent::Head(l(1))]);
    drop(s);
    let mut s = d.open();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.log_heads().unwrap(), [(l(1), [2; 32])]);
    assert!(!t.log_head(l(1), &[2; 32]).unwrap(), "an unchanged head after a restart logs nothing");
}

// `changed_at` of issues/net-reconnect.md, Changes: a sequence of its own, never given twice,
// moving only when a fingerprint differs, sharing nothing with the log's positions
#[test]
fn changed_at_has_its_own_sequence() {
    let (d, mut s, mut rng) = Dev::new();
    add(&mut s, &mut rng, 1);
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.changed_note(l(1), &[1; 32]).unwrap(), Some(1));
    assert_eq!(t.changed_note(l(1), &[1; 32]).unwrap(), None, "an unchanged fingerprint moves nothing");
    assert_eq!(t.changed_note(l(1), &[2; 32]).unwrap(), Some(2));
    assert_eq!(t.log_end().unwrap(), 1, "the log does not move");
    t.commit().unwrap();
    drop(s);
    let mut s = d.open();
    let mut t = s.transaction(&mut rng).unwrap();
    assert_eq!(t.changed_note(l(2), &[1; 32]).unwrap(), Some(3), "a position is never given twice");
    assert_eq!(t.changed_after(1, 10).unwrap(), [(2, l(1)), (3, l(2))]);
    assert_eq!(t.changed_at(&l(1)).unwrap(), Some(2));
}

fn filled(n: u32) -> (Dev, Vec<u8>) {
    let mut rng = SeededRng::from_u64(3);
    let d = MemDevice::new();
    let mut s = Store::create(d.backend(), d.root(), big(), &mut rng).unwrap();
    let mut t = s.transaction(&mut rng).unwrap();
    for i in 0..n {
        t.log_added(l(1), b(i)).unwrap();
    }
    t.commit().unwrap();
    let c = {
        let mut t = s.transaction(&mut rng).unwrap();
        t.log_cursor(u64::from(n) - 5).unwrap().unwrap()
    };
    drop(s);
    (Dev { backend: d.backend, root: d.root }, c)
}

// a reader's cost is what comes after its cursor, whatever the log holds
#[test]
fn reading_from_a_cursor_costs_what_is_after_it() {
    let read_cost = |n: u32| {
        let (d, c) = filled(n);
        let mut s = Store::open(Box::new(d.backend.clone()), Box::new(d.root.clone()), big()).unwrap();
        let before = d.backend.io();
        let mut rng = SeededRng::from_u64(5);
        let r = s.transaction(&mut rng).unwrap().log_read(Some(&c), 100).unwrap();
        assert_eq!(r.events.len(), 5);
        (d.backend.io() - before).reads
    };
    let (small, large) = (read_cost(2_000), read_cost(20_000));
    assert!(large <= small + 8, "reads {small} at n, {large} at 10n");
}

// a whole log's listing is the live set; its write path is a few rows per event
#[test]
fn an_event_costs_a_few_rows() {
    let count = |n: u32| {
        let (d, _) = filled(n);
        d.backend.held_bytes()
    };
    let (a, b) = (count(2_000), count(12_000));
    let per = (b - a) / 10_000;
    assert!(per <= 200, "{per} stored bytes per event");
}
