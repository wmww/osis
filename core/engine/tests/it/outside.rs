//! Content of a thing outside the node closure (spec/commits.md §4 Outside the node closure,
//! Pending storage): what waits, what is carried, what is fetched again, and what it stores.

use crate::flows::people;
use osis_base::{CommitId, Tid, Value};
use osis_crdt::{Op, PathOp};
use osis_engine::local_peer::LocalPeer;
use osis_engine::{Engine, Mutation};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

fn strong_m(m: &mut Mutation, from: Tid, to: Tid) {
    m.op(from, &ct::HOLDS, PathOp { path: vec![], op: Op::Add(Value::Strong(to)) }).unwrap();
}

fn pass_end(e: &mut Engine) {
    let left: BTreeSet<Tid> = e.left_closure().into_keys().collect();
    e.released(&left).unwrap();
    e.settle_needs().unwrap();
    e.check_index();
}

/// Peer 0's commit `c`, whole.
fn give(lp: &mut LocalPeer, c: &CommitId) {
    let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
    lp.deliver(1, &pk).unwrap();
}

/// Peer 0's commit `c` holding only its parts `keep` picks (by thing).
fn give_parts(lp: &mut LocalPeer, c: &CommitId, keep: impl Fn(Tid) -> bool) {
    let pk = lp.peers[0].engine.package(c).unwrap().unwrap();
    let h = lp.peers[0].engine.header(c).unwrap();
    let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
    let bytes = osis_commit::rewrite(&b, |ai| !keep(h.aspects[ai].tid)).encode();
    lp.peers[1].receive(&bytes, pk.blobs.clone()).unwrap();
}

/// Peer 0 makes X and grants peer 1 read on it; peer 1 holds X by its account root.
fn base() -> (LocalPeer, Tid) {
    base_n(2).0
}

fn base_n(n: usize) -> ((LocalPeer, Tid), Vec<Tid>) {
    let (mut lp, ps) = people(n);
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let x = e0.new_thing(&mut m, ps[0]);
    e0.commit(m).unwrap();
    e0.grant(&x, &ps[1], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    let d1 = lp.peers[1].engine.account_root().unwrap();
    let mut m = Mutation::new();
    strong_m(&mut m, d1, x);
    lp.peers[1].engine.commit(m).unwrap();
    for _ in 0..2 {
        for c in lp.peers[0].engine.commit_ids() {
            give(&mut lp, &c);
        }
    }
    pass_end(&mut lp.peers[1].engine);
    assert!(lp.peers[1].engine.closure_holds(&x));
    ((lp, x), ps)
}

/// Every commit of peer 0's sent whole again where peer 1 pulled anew (what node-sync fetches).
fn pull(lp: &mut LocalPeer) -> bool {
    lp.peers[1].reexamine().unwrap();
    let pulled = !std::mem::take(&mut lp.peers[1].pulled_anew).is_empty();
    if pulled {
        for c in lp.peers[0].engine.commit_ids() {
            give(lp, &c);
        }
    }
    pulled
}

// spec/commits.md §4 Outside the node closure (carried while the node cannot judge the thing's
// sync units), spec/sync-judgement.md §3: writer peer 2 (granted write on X by peer 0)
// makes M (mints W under X with X's strong to it, content on W) and D (more content on W). Peer 1
// takes M and D before peer 2's chain and grant: both pend whole (W's record unknown), kept across
// a pass end, and apply whole once the grant comes.
#[test]
fn a_minting_before_its_authors_grant_waits_whole_across_a_pass_end_spec_commits_4() {
    let reg = crate::common::ak("t:reg.0");
    let tags = crate::common::ak("t:tags.0");
    let tagv = Value::Set([Value::Str("d".into())].into_iter().collect());
    for same_pass in [false, true] {
        let ((mut lp, x), ps) = base_n(3);
        let before: BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
        lp.peers[0].engine.grant(&x, &ps[2], &crate::flows::edge_of(osis_base::Role::Write)).unwrap();
        let grant: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
        lp.hold_at(2, x);
        lp.sync(0, 2).unwrap();
        let e2 = &mut lp.peers[2].engine;
        assert!(e2.closure_holds(&x));
        let rec = e2.thing_record(x, None);
        let mut m = Mutation::new();
        let w = m.create(rec);
        m.set(w, &reg, &Value::Str("w".into())).unwrap();
        strong_m(&mut m, x, w);
        let mc = e2.commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.set(w, &tags, &tagv).unwrap();
        let d = lp.peers[2].engine.commit(m).unwrap().unwrap();
        for c in [mc, d] {
            let pk = lp.peers[2].engine.package(&c).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        assert!(lp.peers[1].engine.pends(&mc) && lp.peers[1].engine.pends(&d), "both wait");
        if !same_pass {
            pass_end(&mut lp.peers[1].engine);
            let e1 = &mut lp.peers[1].engine;
            assert!(e1.pends(&mc) && e1.pends(&d), "W's minting not held: carried, they stay");
        }
        lp.peers[1].pulled_anew.clear();
        for c in &grant {
            give(&mut lp, c);
        }
        let pulled = pull(&mut lp);
        pass_end(&mut lp.peers[1].engine);
        let e1 = &mut lp.peers[1].engine;
        assert!(e1.closure_holds(&w), "same pass {same_pass} (pulled {pulled}): W entered");
        assert_eq!(e1.get(&w, &reg).unwrap(), Some(Value::Str("w".into())), "same pass {same_pass}: M's content");
        assert_eq!(e1.get(&w, &tags).unwrap(), Some(tagv.clone()), "same pass {same_pass}: D's content");
        assert!(e1.pending().is_empty(), "{:?}", e1.pending());
    }
}

// spec/commits.md §4 Outside the node closure, spec/sync-judgement.md §3 Dropped bodies: M mints W
// with X's strong to it and content; D writes W. Peer 1 takes M without its part on X and D: W
// stays outside, and with M held it judges W in no unit it syncs, so at the pass end both
// contents count as never received. M's missing part keeps its header and W's record, so M
// coming whole (its part fetched) brings W in with its record held: pulled anew, D comes back.
#[test]
fn content_dropped_as_not_carried_comes_back_when_the_minting_strong_does_spec_sync_judgement_3() {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, x) = base();
    let e0 = &mut lp.peers[0].engine;
    let rec = e0.thing_record(x, None);
    let mut m = Mutation::new();
    let w = m.create(rec);
    m.set(w, &reg, &Value::Str("w".into())).unwrap();
    strong_m(&mut m, x, w);
    let mc = e0.commit(m).unwrap().unwrap();
    lp.peers[0].clock.advance(5);
    let mut m = Mutation::new();
    m.set(w, &crate::common::ak("t:tags.0"), &Value::Set([Value::Str("d".into())].into_iter().collect())).unwrap();
    let d = lp.peers[0].engine.commit(m).unwrap().unwrap();
    give_parts(&mut lp, &mc, |t| t != x);
    give(&mut lp, &d);
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.core.created(&w).is_some() && e1.header(&d).is_none() && e1.get(&w, &reg).unwrap().is_none(), "not carried: never received, W's record kept");
    lp.peers[1].pulled_anew.clear();
    give(&mut lp, &mc);
    assert!(lp.peers[1].engine.closure_holds(&w), "W entered");
    assert!(pull(&mut lp), "W's record held when it entered: pulled anew");
    pass_end(&mut lp.peers[1].engine);
    let e1 = &mut lp.peers[1].engine;
    assert_eq!(e1.get(&w, &reg).unwrap(), Some(Value::Str("w".into())), "M's content");
    assert_eq!(e1.get(&w, &crate::common::ak("t:tags.0")).unwrap(), Some(Value::Set([Value::Str("d".into())].into_iter().collect())), "D's content");
}

// spec/commits.md §4 Examined again (the thing a part waits on entering): a grant making a strong
// valid wakes content waiting on the thing it brings in. Peer 0
// makes W (its own, content) and grants peer 1 read on it; writer peer 2 (granted on X by peer 0)
// writes S, X's strong to W. Peer 1 takes W's commits and S before peer 2's grant (S waits for a
// reach, W's content for W to enter), then the grant in the same pass.
#[test]
fn a_grant_making_a_strong_valid_wakes_what_waits_on_its_target_spec_commits_4() {
    let reg = crate::common::ak("t:reg.0");
    let ((mut lp, x), ps) = base_n(3);
    let e0 = &mut lp.peers[0].engine;
    let mut m = Mutation::new();
    let w = e0.new_thing(&mut m, ps[0]);
    m.set(w, &reg, &Value::Str("w".into())).unwrap();
    e0.commit(m).unwrap();
    e0.grant(&w, &ps[1], &crate::flows::edge_of(osis_base::Role::Read)).unwrap();
    let mut wc: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| lp.peers[0].engine.header(c).is_some_and(|h| h.aspects.iter().any(|a| a.tid == w))).collect();
    let before: BTreeSet<CommitId> = lp.peers[0].engine.commit_ids().into_iter().collect();
    lp.peers[0].engine.grant(&x, &ps[2], &crate::flows::edge_of(osis_base::Role::Write)).unwrap();
    let grant: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|c| !before.contains(c)).collect();
    lp.hold_at(2, x);
    lp.hold_at(2, w);
    lp.sync(0, 2).unwrap();
    let mut m = Mutation::new();
    strong_m(&mut m, x, w);
    let s = lp.peers[2].engine.commit(m).unwrap().unwrap();
    wc.sort();
    for c in &wc {
        give(&mut lp, c);
    }
    let pk = lp.peers[2].engine.package(&s).unwrap().unwrap();
    lp.deliver(1, &pk).unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(!e1.closure_holds(&w));
    assert!(e1.pending().iter().any(|(_, r)| *r == osis_engine::Reason::Outside(w)), "W's content waits");
    for c in &grant {
        give(&mut lp, c);
    }
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.closure_holds(&w), "W entered with the grant");
    assert_eq!(e1.get(&w, &reg).unwrap(), Some(Value::Str("w".into())), "W's content joined as W entered");
}

/// Store rows grown, by family.
type Rows = Vec<(String, i64)>;

/// What peer 1 stores for `n` writes on W, outside its node closure (it holds X, not
/// the strong to W) while X's sync ID carries them at their source: (rows after the writes and
/// the pass end with W's minting commit held, rows after `n` writes awaiting W's record and their
/// carriers gone), each less the rows before.
fn outside_rows(n: usize) -> (Rows, Rows) {
    let reg = crate::common::ak("t:reg.0");
    let (mut lp, x) = base();
    let e0 = &mut lp.peers[0].engine;
    let rec = e0.thing_record(x, None);
    let mut m = Mutation::new();
    let w = m.create(rec);
    strong_m(&mut m, x, w);
    let mc = e0.commit(m).unwrap().unwrap();
    let mut ds = Vec::new();
    for i in 0..n {
        lp.peers[0].clock.advance(1);
        let mut m = Mutation::new();
        m.set(w, &reg, &Value::Int(i as i64)).unwrap();
        ds.push(lp.peers[0].engine.commit(m).unwrap().unwrap());
    }
    let diff = |a: &std::collections::BTreeMap<String, (usize, usize)>, b: &std::collections::BTreeMap<String, (usize, usize)>| -> Rows {
        a.keys().chain(b.keys()).collect::<BTreeSet<_>>().into_iter().map(|k| (k.clone(), b.get(k).map_or(0, |v| v.0) as i64 - a.get(k).map_or(0, |v| v.0) as i64)).filter(|x| x.1 != 0).collect()
    };
    // minted here: the writes wait, then go at the pass end
    pass_end(&mut lp.peers[1].engine);
    let mut a = lp.copy().unwrap();
    let before = a.peers[1].engine.census().unwrap();
    give_parts(&mut a, &mc, |t| t != x);
    for d in &ds {
        let pk = a.peers[0].engine.package(d).unwrap().unwrap();
        a.deliver(1, &pk).unwrap();
    }
    pass_end(&mut a.peers[1].engine);
    let minted = diff(&before, &a.peers[1].engine.census().unwrap());
    // not minted here: they wait while carried; their carriers go
    let mut b = lp.copy().unwrap();
    let before = b.peers[1].engine.census().unwrap();
    for d in &ds {
        let pk = b.peers[0].engine.package(d).unwrap().unwrap();
        b.deliver(1, &pk).unwrap();
    }
    pass_end(&mut b.peers[1].engine);
    assert_eq!(b.peers[1].engine.pending().len(), n, "they wait while carried");
    for d in &ds {
        b.peers[1].engine.release_entry(d).unwrap();
    }
    pass_end(&mut b.peers[1].engine);
    let carried = diff(&before, &b.peers[1].engine.census().unwrap());
    (minted, carried)
}

// spec/commits.md §4 Pending storage, Outside the node closure, spec/requirements.md Scale: writes
// on a thing outside the node closure leave nothing once not carried (minting commit held) or once
// their carriers go, the same rows at n and 10n.
#[test]
fn writes_outside_the_node_closure_store_nothing_once_not_carried_spec_commits_4() {
    let (s, l) = (outside_rows(3), outside_rows(30));
    assert_eq!(s, l, "the same rows at n and 10n");
    assert!(s.1.is_empty(), "nothing left once their carriers go: {:?}", s.1);
}
