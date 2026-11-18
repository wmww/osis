//! Stranded reports at the receiver (spec/permissions.md §4 Stranded, §3 Re-seal): the holder
//! keys a report brings are taken along the holder's authority chain alone, and the re-seal it
//! asks for writes only what differs.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, granted, with_own_keys, synced};
use super::Reseal;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeSet;

/// Peer 2's team T holds read on G, a thing of peer 0's with own keys; everyone synced. (lp, G, T)
fn team_on_g() -> (LocalPeer, Tid, Tid) {
    let (lp, (g, t)) = LocalPeer::cached("rotation::tests_stranded::team_on_g", || {
        let mut lp = synced(3);
        let t = with_own_keys(&mut lp, 2);
        lp.sync_all().unwrap();
        let g = with_own_keys(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &t, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        (lp, (g, t))
    });
    (lp, g, t)
}

fn held(lp: &LocalPeer, i: usize, ids: &[CommitId]) -> usize {
    ids.iter().filter(|c| lp.peers[i].engine.header(c).is_some()).count()
}

fn ids_of(keys: &osis_blob::HolderKeys) -> Vec<CommitId> {
    keys.commits.iter().map(|v| osis_commit::CommitBlob::decode(&osis_base::encode(v)).unwrap().id()).collect()
}

// spec/permissions.md §4 (stranded), spec/crypto.md §4 (Reported): the receiver takes the holder
// keys as chain certificates; a node gone from the holder learns its keyset only so. T rotates
// unseen by peer 0; the holder keys of T from peer 2 bring T's new keyset to peer 0.
#[test]
fn holder_keys_bring_the_holders_new_keyset_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let k = lp.peers[2].engine.rotate_leaving_out(&t, &[Role::Read], &[]).unwrap().unwrap();
    assert!(lp.peers[0].engine.header(&k).is_none(), "peer 0 lacks T's new keyset");
    let keys = lp.peers[2].engine.holder_keys(&t).unwrap();
    assert!(ids_of(&keys).contains(&k));
    assert!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap() > 0);
    assert!(lp.peers[0].engine.current_keys(&t).contains(&k), "T's new keyset taken");
}

// spec/permissions.md §4 (stranded): nothing off the holder's authority chain is taken (peer
// input never causes unbounded storage, spec/requirements.md). A report naming T that
// carries the role commits and record of X, a thing of peer 2's with own keys peer 0 never saw, leaves peer 0
// none of them; X's keys named under X itself are taken only as a holder's (X holds nothing).
#[test]
fn holder_keys_take_nothing_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = with_own_keys(&mut lp, 2);
    let keys = lp.peers[2].engine.holder_keys(&x).unwrap();
    let mut ids = ids_of(&keys);
    ids.retain(|c| lp.peers[0].engine.header(c).is_none());
    assert!(!ids.is_empty() && !lp.peers[0].engine.knows(&x));
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap(), 0);
    assert_eq!(held(&lp, 0, &ids), 0, "X's commits not kept");
    assert!(!lp.peers[0].engine.knows(&x), "X's record not kept");
}

// spec/permissions.md §3 (Re-seal), §4 (stranded): a re-seal a stranded notice asks for writes
// the holder's boxes at every current epoch held, unless each is as Seal gives it: the asked re-seal writes only where a box is missing or
// differs from the one Seal gives now, so asking again changes nothing once met.
#[test]
fn an_asked_reseal_writes_only_what_differs_spec_permissions_3() {
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    let m = tids[1];
    let ask = |lp: &mut LocalPeer| lp.peers[0].engine.run(|tx| super::reseal_one(tx, g, m, &BTreeSet::from([Role::Read]), Reseal::Asked)).unwrap().commits.len();
    assert_eq!(ask(&mut lp), 0, "boxed as Seal gives: nothing");
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Read], &[m]).unwrap().unwrap();
    assert_eq!(ask(&mut lp), 1, "left out: re-sealed");
    assert_eq!(ask(&mut lp), 0, "met: nothing more");
}

// spec/permissions.md §4 (stranded): no edge write of anything off the chain. Peer 0 knows X, a
// thing of peer 2's with own keys on no path to T; a report naming T that carries a later grant on X leaves
// peer 0 without it.
#[test]
fn holder_keys_take_no_edge_write_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = with_own_keys(&mut lp, 2);
    lp.sync_all().unwrap();
    let p1 = lp.peers[1].engine.me();
    let c = lp.peers[2].engine.grant(&x, &p1, &edge(Role::Read)).unwrap().commits[0];
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let v = osis_base::decode(&lp.peers[2].engine.run(|tx| tx.get_commit(&c)).unwrap().unwrap().encode(), &limits).unwrap();
    let keys = osis_blob::HolderKeys { commits: vec![v], records: Vec::new() };
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys).unwrap(), 0);
    assert!(lp.peers[0].engine.header(&c).is_none(), "the grant on X not kept");
}

/// Peer 0's asks on `g`: (holder, met).
fn asks(lp: &mut LocalPeer, g: Tid) -> Vec<(Tid, bool)> {
    lp.peers[0].engine.core.ix.reseal_asks.iter().filter(|((a, _), _)| *a == g).map(|((_, m), k)| (*m, k.met)).collect()
}

/// Peer 0 takes a report from holder `m` on `g` (no keys) and runs a pass end's re-seals.
fn report_and_pass(lp: &mut LocalPeer, g: Tid, m: Tid) {
    let s = lp.peers[0].engine.sync_ids(&g).unwrap()[0].id;
    assert!(lp.peers[0].engine.take_stranded(&s, &m, &osis_blob::HolderKeys::default()).unwrap(), "asked");
    lp.peers[0].engine.reseal_run(&g).unwrap();
}

// spec/permissions.md §3 (Re-seal: none to a holder whose grant it may finalize), §4 (stranded):
// an ask of a holder whose grant ended goes with the finalize the pass end writes, unmet.
#[test]
fn an_ended_holders_ask_goes_with_its_finalize_spec_permissions_4() {
    let (mut lp, tids) = synced_tids(2);
    let g = with_own_keys(&mut lp, 0);
    let until = lp.peers[0].engine.now().0 + 1_000;
    lp.peers[0].engine.grant(&g, &tids[1], &osis_schema::core_types::Edge { until: Some(osis_base::WallMs(until)), ..edge(Role::Read) }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].clock.advance(2_000);
    report_and_pass(&mut lp, g, tids[1]);
    assert!(!lp.peers[0].engine.core.key_holders(&g).iter().any(|x| x.0 == tids[1]), "finalized");
    assert_eq!(asks(&mut lp, g), Vec::new(), "its ask gone");
}

// spec/permissions.md §4 (stranded): an ask met is kept while its holder is current (the same
// report asks nothing more), and goes once the holder is removed: asks are bounded by the current
// holders, not by every holder there was.
#[test]
fn a_met_ask_goes_with_its_holder_spec_permissions_4() {
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    report_and_pass(&mut lp, g, tids[1]);
    assert_eq!(asks(&mut lp, g), vec![(tids[1], true)], "met");
    lp.peers[0].engine.demote(&g, &crate::flows::Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    lp.peers[0].engine.reseal_run(&g).unwrap();
    assert_eq!(asks(&mut lp, g), Vec::new(), "gone with the holder");
}

fn synced_tids(n: usize) -> (LocalPeer, Vec<Tid>) {
    let lp = super::tests::synced(n);
    let tids = (0..n).map(|i| lp.peers[i].engine.me()).collect();
    (lp, tids)
}

// spec/crypto.md §4 (Encrypting under: a grant past its `until` that this node may finalize is
// finalized before its next commit encrypting under the actor): whether a body can be wrapped for
// S reads the clock with a wake at the grant's `until`, so a reader following it is due then with
// nothing else moving, and judges it unwrappable until the finalize is written.
#[test]
fn whether_a_body_wraps_moves_at_a_grants_until_spec_crypto_4() {
    let (mut lp, tids) = synced_tids(2);
    let g = with_own_keys(&mut lp, 0);
    let until = lp.peers[0].engine.now().0 + 1_000;
    lp.peers[0].engine.grant(&g, &tids[1], &osis_schema::core_types::Edge { until: Some(osis_base::WallMs(until)), ..edge(Role::Read) }).unwrap();
    lp.sync_all().unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_base::Ak::new("x:m.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let s = lp.peers[0].engine.sync_ids(&g).unwrap()[0].id;
    let e = &mut lp.peers[0].engine;
    let mut fx: osis_base::memo::Effects<(), bool> = osis_base::memo::Effects::new("wraps");
    fx.want(());
    assert_eq!(fx.settle(&(), || { let held = e.commit_blobs(&c).unwrap(); e.may_log(&s, &c, &held).unwrap() }), Some((None, true)), "wraps before the until");
    assert!(fx.due().is_empty());
    lp.peers[0].clock.advance(2_000);
    let e = &mut lp.peers[0].engine;
    let now = e.now();
    e.set_now(now);
    // as sync's driver does before each module's `due` (`Engine::follow`)
    e.follow().unwrap();
    assert_eq!(fx.due(), vec![()], "due at the until");
    assert_eq!(fx.settle(&(), || { let held = e.commit_blobs(&c).unwrap(); e.may_log(&s, &c, &held).unwrap() }), Some((Some(true), false)), "the finalize is owed first");
}

// spec/sync-inbox.md §5 (Stranded notice: a writer of the thing acts on it when its node takes
// it), spec/permissions.md §4 (Stranded): peer 0 rotates g's read leaving out reader m (peer 1),
// who takes the rotation and cannot read the new epoch; with no writer connected it fires a
// stranded notice, sealed to the new keyset. Peer 0, taking the fire, asks m's re-seal, and the
// pass end's re-seal boxes m the new epoch. Fails if a stranded node fires as a reader (it
// holds the old epoch's secret) or a writer ignores the notice.
#[test]
fn a_writer_taking_a_stranded_notice_reseals_its_holder_spec_sync_inbox_5() {
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    let m = tids[1];
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Read], &[m]).unwrap().unwrap();
    let e = super::tests::newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let s = lp.peers[1].engine.sync_ids(&g).unwrap()[0].id;
    assert!(lp.peers[1].engine.stranded(&s).unwrap().is_some(), "m is stranded");
    lp.peers[1].engine.fire_stranded(&s, &m).unwrap();
    let id = *lp.peers[1].engine.fires_owed().first().expect("a stranded notice owed");
    let out = lp.peers[1].engine.sealed_fire(&id).unwrap().expect("sealed");
    let opened = lp.peers[0].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the writer takes the notice: {opened:?}");
    assert_eq!(asks(&mut lp, g), vec![(m, false)], "m's re-seal asked");
    lp.peers[0].engine.reseal_run(&g).unwrap();
    assert_eq!(asks(&mut lp, g), vec![(m, true)], "met");
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.epochs(&g).unwrap().read.secret(&e).is_some(), "m holds the new epoch");
}

// spec/sync-inbox.md §4 (A sealed fire: one holding any delta but one fire of an open signal of
// S's thing is not promoted): peer 1, holding g's public record and no secret of it, seals fires
// to g's keyset; peer 0, a writer of g, takes the one holding one fire of an open signal of g and
// refuses as bad one with a second fire beside it, one with a fire on another thing beside it,
// one holding a fire of another thing alone, and one holding a write of g's that is no signal.
#[test]
fn a_sealed_fire_is_one_fire_of_its_thing_spec_sync_inbox_4() {
    use crate::flows::inbox::{Fire, OwedFire, save};
    use osis_base::{Ak, Value};
    use osis_crdt::{Op, PathOp};
    let (mut lp, g, _) = granted(2, &[]);
    let other = with_own_keys(&mut lp, 0);
    let (f, f2, plain) = (Ak::new("x:f@~0").unwrap(), Ak::new("x:h@~0").unwrap(), Ak::new("x:v.0").unwrap());
    let keep = osis_schema::core_types::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() };
    for t in [g, other] {
        let mut m = crate::Mutation::new();
        m.set(t, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::from(std::collections::BTreeMap::from([(f.clone(), keep), (f2.clone(), keep)]))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    lp.sync_all().unwrap();
    type Row<'a> = (&'a str, Vec<(Tid, &'a Ak)>, bool);
    let rows: [Row; 5] = [
        ("one fire of g", vec![(g, &f)], true),
        ("two fires of g", vec![(g, &f), (g, &f2)], false),
        ("a fire of another thing beside", vec![(g, &f), (other, &f)], false),
        ("a fire of another thing alone", vec![(other, &f)], false),
        ("a write that is no signal", vec![(g, &plain)], false),
    ];
    for (n, (row, ops, taken)) in rows.into_iter().enumerate() {
        let e1 = &mut lp.peers[1].engine;
        let before = e1.fires_owed();
        e1.run(|tx| {
            let mut m = crate::Mutation::new();
            for (t, ak) in &ops {
                m.op(*t, *ak, PathOp { path: Vec::new(), op: Op::Set(Value::Int(n as i64)) })?;
            }
            // built as a hostile sender would, its author's rights unchecked
            m.sealed = true;
            m.commit_form().unchecked();
            let b = crate::engine::write::commit_or_build(tx, m)?.and_then(|x| x.1).expect("built");
            save(tx, OwedFire { thing: g, ak: f.clone(), what: Fire::Value(Value::Int(n as i64)), to: BTreeSet::new(), commit: Some(std::sync::Arc::new(b.encode())) })
        })
        .unwrap();
        let id = *e1.fires_owed().iter().find(|x| !before.contains(x)).expect("owed");
        let out = e1.sealed_fire(&id).unwrap().expect("sealed");
        let opened = lp.peers[0].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
        assert_eq!(matches!(opened, crate::sync::Opened::Commit(..)), taken, "{row}: {opened:?}");
        if !taken {
            assert!(matches!(opened, crate::sync::Opened::Bad), "{row}: bad, {opened:?}");
        }
    }
}
