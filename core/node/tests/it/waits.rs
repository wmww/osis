#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Re-examination of pending commits (`apply/waits.rs`): what `reexamine` leaves out must wait
//! for the same reason as a full examination would say (spec/commits.md §4).

use crate::common;
use common::*;
use osis_commit::CommitBlob;
use osis_base::{Tid, Value, WallMs};
use osis_node::{Ingested, Mutation, Reason};

fn only(bytes: &[u8], h: &osis_commit::Header, keep: impl Fn(Tid, &str) -> bool) -> Vec<u8> {
    let mut b = CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(h.aspects[p.ai].tid, h.aspects[p.ai].ak.as_str()));
    b.encode()
}

// spec/commits.md §4: a commit waiting for deltas, then a thing of it whose `/created` is
// unknown starts syncing: it waits for that record now (examined in full, not only its
// missing deltas).
#[test]
fn syncing_on_reexamines_in_full_spec_commits_4() {
    let mut lp = net(2, 26);
    let t = new_thing(&mut lp, 0);
    let u = new_thing(&mut lp, 0);
    let pks = packages(&mut lp, 0);
    for p in &pks[..3] {
        lp.deliver(1, p).unwrap();
    }
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    m.set(u, &REG, &s("u")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let partial = only(&pk.bytes, &h, |x, a| x == t && a == "/t/reg");
    let r = lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[1].engine.set_syncing(u, true).unwrap();
    // another reexamine: the debug check examines the skipped commit
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(id, Reason::UnknownCreated(u))]);
}

// spec/commits.md §4; spec/crdt.md §2.2: a delta wait examined at a later clock than
// `reexamine` last looked; the clock goes back: the commit is more than MAX_DRIFT ahead again.
#[test]
fn clock_back_after_ingest_reexamines_spec_commits_4() {
    let mut lp = net(2, 27);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    lp.peers[1].engine.set_syncing(t, true).unwrap();
    let t0 = lp.peers[1].engine.now().0;
    lp.peers[0].clock.advance(2 * 3_600_000);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("r")).unwrap();
    m.set(t, &TAGS, &Value::Set([s("a")].into_iter().collect())).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&id).unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    let partial = only(&pk.bytes, &h, |_, a| a == "/t/reg");
    lp.peers[1].clock.advance(2 * 3_600_000);
    let r = lp.peers[1].engine.ingest(&partial, Vec::new()).unwrap();
    assert!(matches!(r, Ingested::Pending(_, Reason::WaitDeltas)), "{r:?}");
    lp.peers[1].clock.set(WallMs(t0 + 1_800_000));
    lp.peers[1].engine.tick().unwrap();
    assert_eq!(lp.peers[1].engine.pending(), vec![(id, Reason::Drift)]);
}

// spec/commits.md §4; spec/requirements.md, Scale (peer input never causes unbounded
// allocation): 1000 unsigned junk commits naming unknown authors pend, and what re-examination
// keeps of them stays small and bounded.
#[test]
fn junk_pending_waits_bounded_spec_commits_4() {
    let mut lp = net(2, 29);
    let t = new_thing(&mut lp, 0);
    sync(&mut lp, 0, 1);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("x")).unwrap();
    let id = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = packages(&mut lp, 0).into_iter().find(|p| p.id == id).unwrap();
    for i in 0..1000u32 {
        let mut b = CommitBlob::decode(&pk.bytes).unwrap();
        let mut a = [0u8; 15];
        a[..4].copy_from_slice(&i.to_be_bytes());
        a[4] = 0xee;
        b.header.author = Tid::from_bytes(a);
        let r = lp.peers[1].engine.ingest(&b.encode(), Vec::new()).unwrap();
        assert!(matches!(r, Ingested::Pending(_, Reason::MissingChain(_))), "{r:?}");
    }
    assert_eq!(lp.peers[1].engine.pending().len(), 1000);
    let bytes = lp.peers[1].engine.waits_bytes();
    assert!(bytes <= 1000 * 512, "{bytes} B kept for 1000 junk commits");
}
