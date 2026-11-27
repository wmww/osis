//! What carries a pending commit (spec/commits.md §4 Pending storage): a commit pends, and a thing
//! it awaits is held for itself (spec/commits.md §5 What a held thing needs), only while an entry,
//! a fire or a report carries it. Fires here: peer 0's sealed `NOTE` fires on peer 1's inbox, kept
//! an hour; what a fire carries is taken as `Engine::take_fire` takes a carried commit
//! (`ingest_valid` from the fire). Reports: rotation::tests_stranded.

use crate::common::{ak, pass_end, set_setting, REG};
use osis_base::{CommitId, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::local_peer::LocalPeer;
use osis_engine::{Carrier, Engine, Mutation};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

const NOTE: &str = "x:note@~0";
const HOUR_MS: u64 = 3_600_000;

/// Peer 0 makes X and grants peer 1 read; peer 1 holds X and keeps `NOTE` fires on its inbox an
/// hour. (lp, X, peer 1's inbox)
fn base() -> (LocalPeer, Tid, Tid) {
    let (mut lp, ps) = crate::flows::accounts(2);
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let x = e0.new_thing(&mut m, ps[0]);
    e0.commit(m).unwrap();
    e0.grant(&x, &ps[1], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    let d1 = lp.peers[1].engine.node_root().unwrap();
    let mut m = Mutation::new();
    m.op(d1, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(x)) }).unwrap();
    lp.peers[1].engine.commit(m).unwrap();
    let all = lp.peers[0].engine.commit_ids();
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    crate::flows::send_carried(&mut lp, 0, 1, &all);
    let inbox = lp.peers[1].engine.inbox_of(&ps[1]).unwrap().unwrap();
    let mut s = lp.peers[1].engine.get_typed(&inbox, &ct::RETENTION).unwrap().unwrap();
    s.rules.insert(ak(NOTE), ct::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    set_setting(&mut lp, 1, inbox, &s);
    pass_end(&mut lp.peers[1].engine);
    assert!(lp.peers[1].engine.closure_holds(&x));
    (lp, x, inbox)
}

/// Peer 0's sealed `NOTE` fire on `inbox`, opened by peer 1: the fire's commit.
fn fire(lp: &mut LocalPeer, inbox: Tid, v: &str) -> CommitId {
    let e = &mut lp.peers[0].engine;
    let before: BTreeSet<_> = e.fires_owed().into_iter().collect();
    e.fire_open(&inbox, NOTE, Value::Str(v.into())).unwrap();
    let id = e.fires_owed().into_iter().find(|x| !before.contains(x)).expect("owed sealed");
    let out = e.sealed_fire(&id).unwrap().expect("sealed");
    e.fire_taken(&id).unwrap();
    let b = osis_blob::blob_id(&out.blob);
    match lp.peers[1].engine.open_entry(&out.sync_id, &b, &[0; 57], &out.blob, &[], u64::MAX).unwrap() {
        osis_engine::sync::Opened::Commit(c, _) => c,
        o => panic!("not opened: {o:?}"),
    }
}

/// Peer 1's fires leave history (their hour passes) and node-sync forgets them.
fn fires_go(lp: &mut LocalPeer, fires: &[CommitId]) {
    lp.advance(HOUR_MS + 1_000);
    lp.peers[1].tick().unwrap();
    let e = &mut lp.peers[1].engine;
    let gone: Vec<_> = fires.iter().copied().filter(|c| e.forgettable(c).unwrap()).collect();
    let kept: Vec<_> = fires.iter().filter(|c| !gone.contains(c)).map(|c| (fires.iter().position(|x| x == c), e.header(c).map(|h| h.ts), e.pends(c), e.pending_carriers(c))).collect();
    assert_eq!(gone.len(), fires.len(), "every fire out of history may be forgotten: {kept:?}");
    e.forget_commits(&gone).unwrap();
    pass_end(e);
}

/// Peer 0 mints W with admin X and X's strong to it (C) and writes W's `REG` again (D): (W, C,
/// D's bytes, D).
fn minted(lp: &mut LocalPeer, x: Tid, v: &str) -> (Tid, CommitId, Vec<u8>, CommitId) {
    minted_with(lp, x, &[(&REG, v)])
}

/// `minted`, D writing `writes` on W.
fn minted_with(lp: &mut LocalPeer, x: Tid, writes: &[(&osis_schema::Aspect<Value>, &str)]) -> (Tid, CommitId, Vec<u8>, CommitId) {
    let e0 = &mut lp.peers[0].engine;
    let (w, c) = crate::common::mint_from(e0, x, x, &[]);
    let mut m = Mutation::new();
    for (a, v) in writes {
        m.set(w, *a, &crate::common::s(v)).unwrap();
    }
    let d = e0.commit(m).unwrap().unwrap();
    (w, c, e0.package(&d).unwrap().unwrap().bytes, d)
}

/// Whether something pending at `e` awaits `w`'s record (W held for itself, `Root::Awaited`).
fn awaited(e: &Engine, w: &Tid) -> bool {
    e.core.ix.pend_on.contains_key(&osis_engine::apply::Wake::Record(*w))
}

/// Peer 1's `pc/` rows (`apply::carriers`).
fn carrier_rows(lp: &mut LocalPeer) -> usize {
    lp.peers[1].engine.local_census().unwrap().get("pc/").map_or(0, |r| r.0)
}

// spec/commits.md §4 Pending storage (taken from no carrier, never received at the end of its
// transaction), §5 What a held thing needs: D on W, whose record peer 1 lacks, taken with no
// carrier (`ingest_valid(_, None)`) neither pends nor roots W, across pass ends and a restart.
#[test]
fn a_commit_taken_from_no_carrier_is_not_kept_spec_commits_4() {
    let (mut lp, x, _) = base();
    let (w, _, d_bytes, d) = minted(&mut lp, x, "d");
    let e1 = &mut lp.peers[1].engine;
    e1.ingest_valid(&d_bytes, None).unwrap();
    assert!(!e1.pends(&d) && e1.header(&d).is_none(), "nothing of D kept");
    assert!(!awaited(e1, &w));
    pass_end(e1);
    lp.peers[1].restart(0).unwrap();
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&d) && e1.core.created(&w).is_none(), "{}", e1.why_kept(&w));
    assert_eq!(carrier_rows(&mut lp), 0);
}

// spec/commits.md §4 Pending storage (a fire carries what it carries while its commit is held),
// §5 What a held thing needs: D1 and D2 on things whose records peer 1 lacks, each carried by fire
// F; D2 also by an entry. Across a restart both pend and root their things; once F leaves history
// and is forgotten, D1 goes and its W1 with it, while D2 stays for its entry, until the entry goes.
#[test]
fn a_fire_letting_go_forgets_what_only_it_carries_spec_commits_4() {
    let (mut lp, x, inbox) = base();
    let f = fire(&mut lp, inbox, "f");
    let (w1, _, b1, d1) = minted(&mut lp, x, "d1");
    let (w2, _, b2, d2) = minted(&mut lp, x, "d2");
    let e1 = &mut lp.peers[1].engine;
    e1.ingest_valid(&b1, Some(Carrier::Fire(f))).unwrap();
    e1.ingest_valid(&b2, Some(Carrier::Fire(f))).unwrap();
    lp.peers[1].receive(&b2, Vec::new()).unwrap();
    assert_eq!(lp.peers[1].engine.pending_carriers(&d2), vec![Carrier::Entry, Carrier::Fire(f)]);
    pass_end(&mut lp.peers[1].engine);
    lp.peers[1].restart(0).unwrap();
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.pends(&d1) && e1.pends(&d2) && awaited(e1, &w1) && awaited(e1, &w2), "carried across a restart");
    fires_go(&mut lp, &[f]);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&d1) && !awaited(e1, &w1), "D1 goes with its fire: {}", e1.why_kept(&w1));
    assert!(e1.pends(&d2) && awaited(e1, &w2), "D2 kept by its entry");
    assert!(e1.release_entry(&d2).unwrap(), "D2 goes with its entry");
    pass_end(e1);
    assert!(!awaited(e1, &w2));
    assert_eq!(carrier_rows(&mut lp), 0);
}

// spec/commits.md §4 Pending storage, Outside the node closure: D, carried by a fire, waits for
// W's record and its entry into the node closure; C brings both, and D applies once: W reads D's
// value, nothing of D pends or keeps a carrier, and the fire leaving changes nothing.
#[test]
fn a_fire_carried_commit_applies_once_its_ground_comes_spec_commits_4() {
    let (mut lp, x, inbox) = base();
    let f = fire(&mut lp, inbox, "f");
    let (w, c, b, d) = minted(&mut lp, x, "d");
    lp.peers[1].engine.ingest_valid(&b, Some(Carrier::Fire(f))).unwrap();
    assert!(lp.peers[1].engine.pends(&d));
    crate::flows::send_carried(&mut lp, 0, 1, &[c]);
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&d) && e1.pending_carriers(&d).is_empty());
    assert_eq!(e1.get(&w, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("d".into())));
    assert_eq!(carrier_rows(&mut lp), 0);
    fires_go(&mut lp, &[f]);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.closure_holds(&w) && e1.header(&d).is_some());
    assert_eq!(e1.get(&w, &crate::common::ak("t:reg.0")).unwrap(), Some(Value::Str("d".into())), "D applied once, kept");
}

// spec/commits.md §4 Pending storage, spec/sync-inbox.md §2: a sender's flood of fires, each
// carrying a commit on a thing peer 1 holds that awaits a record never sent: what pends and the
// carrier rows are one per fire held (bounded by what bounds the fires), and nothing is left once
// the fires go.
#[test]
fn a_flood_of_fires_carries_no_more_than_the_fires_held_spec_commits_4() {
    let k = 6;
    let (mut lp, x, inbox) = base();
    let before = lp.peers[1].engine.pending().len();
    let mut fires = Vec::new();
    let mut ws = Vec::new();
    for i in 0..k {
        let f = fire(&mut lp, inbox, &format!("f{i}"));
        let (w, _, b, _) = minted(&mut lp, x, &format!("d{i}"));
        lp.peers[1].engine.ingest_valid(&b, Some(Carrier::Fire(f))).unwrap();
        fires.push(f);
        ws.push(w);
    }
    pass_end(&mut lp.peers[1].engine);
    assert_eq!(lp.peers[1].engine.pending().len() - before, k, "one pending per fire");
    assert_eq!(carrier_rows(&mut lp), k);
    fires_go(&mut lp, &fires);
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.pending().len(), before, "nothing pends past the fires");
    assert!(ws.iter().all(|w| !awaited(e1, w) && e1.core.created(w).is_none()));
    assert_eq!(carrier_rows(&mut lp), 0);
}

// spec/commits.md §4 Pending storage (with none left it counts as never received, until a carrier
// brings it again): D1 is carried by fire F and an entry, D2 by an entry alone. Their entries go:
// D1 stays for F, D2 is gone with what it rooted. An entry brings both again: each pends as before,
// D1 carried by both again; once F goes, both stay for their entries, and go with them.
#[test]
fn a_commit_let_go_and_brought_again_pends_by_its_carriers_spec_commits_4() {
    let (mut lp, x, inbox) = base();
    let f = fire(&mut lp, inbox, "f");
    let (w1, _, b1, d1) = minted(&mut lp, x, "d1");
    let (w2, _, b2, d2) = minted(&mut lp, x, "d2");
    lp.peers[1].engine.ingest_valid(&b1, Some(Carrier::Fire(f))).unwrap();
    lp.peers[1].receive(&b1, Vec::new()).unwrap();
    lp.peers[1].receive(&b2, Vec::new()).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.release_entry(&d1).unwrap(), "D1 kept by F");
    assert!(e1.release_entry(&d2).unwrap(), "D2 had its entry alone");
    pass_end(e1);
    assert_eq!(e1.pending_carriers(&d1), vec![Carrier::Fire(f)]);
    assert!(e1.pends(&d1) && awaited(e1, &w1));
    assert!(!e1.pends(&d2) && !awaited(e1, &w2) && e1.pending_carriers(&d2).is_empty());
    lp.peers[1].receive(&b1, Vec::new()).unwrap();
    lp.peers[1].receive(&b2, Vec::new()).unwrap();
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.pending_carriers(&d1), vec![Carrier::Entry, Carrier::Fire(f)]);
    assert_eq!(e1.pending_carriers(&d2), vec![Carrier::Entry]);
    assert!(awaited(e1, &w1) && awaited(e1, &w2), "brought again, each roots its thing");
    fires_go(&mut lp, &[f]);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.pends(&d1) && e1.pends(&d2) && awaited(e1, &w1), "kept by their entries");
    assert!(e1.release_entry(&d1).unwrap() && e1.release_entry(&d2).unwrap());
    pass_end(e1);
    assert!(!awaited(e1, &w1) && !awaited(e1, &w2));
    assert_eq!(carrier_rows(&mut lp), 0);
}

// spec/commits.md §4 Pending storage, spec/permissions.md §5.1 Received: D, carried by an entry,
// pends for W's record a while; once C brings it D applies, received when it first came: a
// frontier as of a time between its arrival and its apply lists it, one before its arrival does not.
#[test]
fn a_commit_that_waited_for_its_record_was_received_when_it_came_spec_commits_4() {
    let (mut lp, x, _) = base();
    let (w, c, b, d) = minted(&mut lp, x, "d");
    let before = lp.peers[1].engine.now();
    lp.advance(1_000);
    lp.peers[1].receive(&b, Vec::new()).unwrap();
    assert!(lp.peers[1].engine.pends(&d));
    lp.advance(10_000);
    let between = lp.peers[1].engine.now();
    lp.advance(10_000);
    crate::flows::send_carried(&mut lp, 0, 1, &[c]);
    pass_end(&mut lp.peers[1].engine);
    let author = lp.peers[0].engine.tid();
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&d) && e1.header(&d).is_some(), "D applied");
    let scope = osis_engine::DemotionScope { roles: std::collections::BTreeMap::from([(author, BTreeSet::from([w]))]), content: std::collections::BTreeMap::from([(author, BTreeSet::from([w]))]) };
    assert!(e1.frontier(&scope, between).unwrap().commits.contains(&d), "received when it came");
    assert!(!e1.frontier(&scope, before).unwrap().commits.contains(&d));
}

/// `bytes` (a commit) with its parts `keep` picks, the rest left out.
fn parts_of(bytes: &[u8], keep: impl Fn(usize) -> bool) -> Vec<u8> {
    let mut b = osis_commit::CommitBlob::decode(bytes).unwrap();
    b.parts.retain(|p| keep(p.ai));
    b.encode()
}

/// The work of `f` by counter: examinations, signature checks, store rows written and read.
fn work(f: impl FnOnce()) -> [u64; 4] {
    osis_base::costs::take();
    f();
    let c = osis_base::costs::take();
    let n = |k: &str| c.iter().filter(|x| x.0 == k).map(|x| x.2).sum::<u64>();
    [n("examine"), n("examine: signature"), n("store rows written"), n("store rows read")]
}

// spec/commits.md §4 Pending storage, spec/permissions.md §5.1 Received: D (two parts) pends for
// W's record, first carried by fire F with one part. Handed again as it is, each arrival costs a
// lookup, the same at 1 and 10 arrivals: no examination, no signature check, no row written. A
// copy forging that part (same ID, other bytes) is judged, the stored copy kept; one bringing the
// other part is judged and takes it, its entry recorded as a carrier, after which the whole copy
// handed again costs a lookup too. F goes and D stays for its entry; once C comes, D applies with
// both parts, received when it first came.
#[test]
fn a_pending_commit_handed_again_costs_a_lookup_unless_it_brings_something_spec_commits_4() {
    let (mut lp, x, inbox) = base();
    let f = fire(&mut lp, inbox, "f");
    let (w, c, b, d) = minted_with(&mut lp, x, &[(&REG, "d"), (&crate::common::GONE, "g")]);
    let first = osis_commit::CommitBlob::decode(&b).unwrap().parts[0].ai;
    let half = parts_of(&b, |ai| ai == first);
    let before = lp.peers[1].engine.now();
    lp.advance(1_000);
    assert!(lp.peers[1].engine.ingest_valid(&half, Some(Carrier::Fire(f))).unwrap().is_some());
    assert!(lp.peers[1].engine.pends(&d));
    lp.advance(10_000);
    let between = lp.peers[1].engine.now();
    lp.advance(10_000);
    let again = |lp: &mut LocalPeer, bytes: &[u8], n: usize| {
        work(|| {
            for _ in 0..n {
                let out = lp.peers[1].engine.ingest_valid(bytes, Some(Carrier::Fire(f))).unwrap();
                assert!(matches!(out, Some(osis_engine::Ingested::Pending(..))), "{out:?}");
            }
        })
    };
    let (one, ten) = (again(&mut lp, &half, 1), again(&mut lp, &half, 10));
    assert_eq!(one[..3], [0, 0, 0], "a copy bringing nothing is not examined, checked or written: {one:?}");
    assert_eq!(ten.map(|x| x / 10), one, "per arrival, flat: {one:?} {ten:?}");
    assert_eq!(ten.map(|x| x % 10), [0; 4]);

    // a forged part: same ID, other bytes
    let mut forged = osis_commit::CommitBlob::decode(&half).unwrap();
    let last = forged.parts[0].delta.len() - 1;
    forged.parts[0].delta[last] ^= 1;
    let forged = forged.encode();
    let judged = work(|| {
        let _ = lp.peers[1].engine.ingest_valid(&forged, Some(Carrier::Fire(f)));
    });
    assert!(judged[0] > 0, "a forged copy is judged: {judged:?}");
    assert!(lp.peers[1].engine.pends(&d));

    // the other part, by an entry
    let judged = work(|| {
        lp.peers[1].receive(&b, Vec::new()).unwrap();
    });
    assert!(judged[0] > 0, "a copy bringing a part is judged: {judged:?}");
    assert_eq!(lp.peers[1].engine.pending_carriers(&d), vec![Carrier::Entry, Carrier::Fire(f)]);
    let whole = |lp: &mut LocalPeer, n: usize| {
        work(|| {
            for _ in 0..n {
                lp.peers[1].receive(&b, Vec::new()).unwrap();
            }
        })
    };
    let (one, ten) = (whole(&mut lp, 1), whole(&mut lp, 10));
    assert_eq!(one[..3], [0, 0, 0], "{one:?}");
    assert_eq!(ten.map(|x| x / 10), one, "{one:?} {ten:?}");

    fires_go(&mut lp, &[f]);
    assert!(lp.peers[1].engine.pends(&d), "kept by its entry");
    crate::flows::send_carried(&mut lp, 0, 1, &[c]);
    pass_end(&mut lp.peers[1].engine);
    let author = lp.peers[0].engine.tid();
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.pends(&d) && e1.header(&d).is_some(), "D applied");
    assert_eq!(e1.get(&w, &ak("t:reg.0")).unwrap(), Some(Value::Str("d".into())), "the stored part, not the forged one");
    assert_eq!(e1.get(&w, &ak("t:gone.0")).unwrap(), Some(Value::Str("g".into())), "the part a later copy brought");
    let scope = osis_engine::DemotionScope { roles: std::collections::BTreeMap::from([(author, BTreeSet::from([w]))]), content: std::collections::BTreeMap::from([(author, BTreeSet::from([w]))]) };
    assert!(e1.frontier(&scope, between).unwrap().commits.contains(&d), "received when it first came");
    assert!(!e1.frontier(&scope, before).unwrap().commits.contains(&d));
}

// spec/crdt.md §2.2, spec/commits.md §4: D, written more than MAX_DRIFT ahead of peer 1's clock,
// pends for drift; once peer 1's clock reaches it, D handed again before any tick applies, as an
// examination would apply it: a copy bringing nothing is a lookup only while nothing of its wait
// is due.
#[test]
fn a_pending_commit_handed_again_once_its_drift_passed_applies_spec_commits_4() {
    let (mut lp, x, _) = base();
    let ahead = 3 * osis_base::format::MAX_DRIFT_MS;
    lp.peers[0].clock.advance(ahead);
    let mut m = Mutation::new();
    m.set(x, &REG, &Value::Str("ahead".into())).unwrap();
    let d = lp.peers[0].engine.commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(matches!(e1.ingest(&pk.bytes, pk.blobs.clone()).unwrap(), osis_engine::Ingested::Pending(_, osis_engine::Reason::Drift)));
    lp.peers[1].clock.advance(ahead);
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.ingest(&pk.bytes, Vec::new()).unwrap(), osis_engine::Ingested::Applied(d), "examined, not a lookup");
    assert_eq!(e1.get(&x, &ak("t:reg.0")).unwrap(), Some(Value::Str("ahead".into())));
}
