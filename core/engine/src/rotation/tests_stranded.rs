//! Stranded reports at the receiver (spec/permissions.md §4 Stranded, §3 Re-seal): the holder
//! keys a report brings are taken along the holder's authority chain alone, and the re-seal it
//! asks for writes only what differs.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, granted, independent_thing, synced};
use super::Reseal;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeSet;

/// Peer 2's team T holds read on G, an independent thing of peer 0's; everyone synced. (lp, G, T)
fn team_on_g() -> (LocalPeer, Tid, Tid) {
    let (lp, (g, t)) = LocalPeer::cached("rotation::tests_stranded::team_on_g", || {
        let mut lp = synced(3);
        let t = independent_thing(&mut lp, 2);
        lp.sync_all().unwrap();
        let g = independent_thing(&mut lp, 0);
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
    assert!(lp.peers[0].engine.take_holder_keys(&t, &keys, None).unwrap() > 0);
    assert!(lp.peers[0].engine.current_keys(&t).contains(&k), "T's new keyset taken");
}

// spec/permissions.md §4 (stranded): nothing off the holder's authority chain is taken (peer
// input never causes unbounded storage, spec/requirements.md). A report naming T that
// carries the role commits and record of X, an independent thing of peer 2's peer 0 never saw, leaves peer 0
// none of them; X's keys named under X itself are taken only as a holder's (X holds nothing).
#[test]
fn holder_keys_take_nothing_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = independent_thing(&mut lp, 2);
    let keys = lp.peers[2].engine.holder_keys(&x).unwrap();
    let mut ids = ids_of(&keys);
    ids.retain(|c| lp.peers[0].engine.header(c).is_none());
    assert!(!ids.is_empty() && !lp.peers[0].engine.knows(&x));
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys, None).unwrap(), 0);
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
// independent thing of peer 2's on no path to T; a report naming T that carries a later grant on X leaves
// peer 0 without it.
#[test]
fn holder_keys_take_no_edge_write_off_the_chain_spec_permissions_4() {
    let (mut lp, _, t) = team_on_g();
    let x = independent_thing(&mut lp, 2);
    lp.sync_all().unwrap();
    let p1 = lp.peers[1].engine.me();
    let c = lp.peers[2].engine.grant(&x, &p1, &edge(Role::Read)).unwrap().commits[0];
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let v = osis_base::decode(&lp.peers[2].engine.run(|tx| tx.get_commit(&c)).unwrap().unwrap().encode(), &limits).unwrap();
    let keys = osis_blob::HolderKeys { commits: vec![v], records: Vec::new() };
    assert_eq!(lp.peers[0].engine.take_holder_keys(&t, &keys, None).unwrap(), 0);
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
    let g = independent_thing(&mut lp, 0);
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
    let g = independent_thing(&mut lp, 0);
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
// pass end's re-seal boxes m the new epoch, once g enables stranded notices (refused before,
// spec/permissions.md §5.2 External fires: m stays stranded, its status saying so). Fails if a stranded node fires as a reader (it holds
// the old epoch's secret) or a writer ignores the notice.
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
    assert!(matches!(opened, crate::sync::Opened::Bad), "g does not enable stranded notices: refused, {opened:?}");
    assert_eq!(asks(&mut lp, g), vec![], "nothing asked");
    assert!(lp.peers[1].engine.stranded(&s).unwrap().is_some(), "not enabled: m stays stranded, and says so");
    // g takes stranded notices from its readers once its admin enables them (spec/sync-inbox.md
    // §1), here with no history: a sealed fire is taken all the same
    let mut x = crate::Mutation::new();
    let stranded = osis_base::Ak::new(crate::flows::inbox::STRANDED_FIRE).unwrap();
    x.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::from(std::collections::BTreeMap::from([(stranded, osis_schema::core_types::RetentionEntry::default())]))).unwrap();
    lp.peers[0].commit(x).unwrap();
    let opened = lp.peers[0].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the writer takes the notice: {opened:?}");
    assert_eq!(asks(&mut lp, g), vec![(m, false)], "m's re-seal asked");
    lp.peers[0].engine.reseal_run(&g).unwrap();
    assert_eq!(asks(&mut lp, g), vec![(m, true)], "met");
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.epochs(&g).unwrap().read.secret(&e).is_some(), "m holds the new epoch");
}

// spec/sync-inbox.md §4 (A sealed fire: one holding any delta but one fire of an external signal of
// S's thing is not promoted): peer 1, holding g's public record and no secret of it, seals fires
// to g's keyset; peer 0, a writer of g, takes the one holding one fire of an external signal of g and
// refuses as bad one with a second fire beside it, one with a fire on another thing beside it,
// one holding a fire of another thing alone, and one holding a write of g's that is no signal.
#[test]
fn a_sealed_fire_is_one_fire_of_its_thing_spec_sync_inbox_4() {
    use crate::flows::inbox::{Fire, OwedFire, save};
    use osis_base::{Ak, Value};
    use osis_crdt::{Op, PathOp};
    let (mut lp, g, _) = granted(2, &[]);
    let other = independent_thing(&mut lp, 0);
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

// spec/sync-inbox.md §5 (Carried commits: a removal notice's commit is taken as an arriving
// commit, each part only where judged valid): peer 2, a reader of g and no admin, forges Bob's
// (peer 1's) removal from g, built as a hostile sender would, and fires its notice sealed on
// Bob's inbox. Bob, taking it, checks it against the roster he holds: he still reads g, and holds
// nothing of the forged commit.
#[test]
fn a_forged_removal_notice_changes_nothing_spec_sync_inbox_5() {
    let (mut lp, g, tids) = granted(3, &[(1, Role::Read), (2, Role::Read)]);
    let bob = tids[1];
    let reg = osis_base::Ak::new("t:reg.0").unwrap();
    let mut m = crate::Mutation::new();
    m.set(g, &reg, &osis_base::Value::Str("before".into())).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[1].engine.get(&g, &reg).unwrap().is_some(), "Bob reads g");
    let e2 = &mut lp.peers[2].engine;
    let before = e2.fires_owed();
    let c = e2
        .run(|tx| {
            let mut m = crate::Mutation::new();
            crate::flows::put_edge(&mut m, g, bob, &edge(Role::Sync))?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            let c = c?.expect("built");
            crate::flows::inbox::fire_removal(tx, bob, c, g)?;
            Ok(c)
        })
        .unwrap();
    let id = *e2.fires_owed().iter().find(|x| !before.contains(x)).expect("owed");
    let out = e2.sealed_fire(&id).unwrap().expect("sealed");
    let e1 = &mut lp.peers[1].engine;
    let opened = e1.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the notice itself is a fire like any: {opened:?}");
    e1.take_carried().unwrap();
    e1.role_duties().unwrap();
    e1.settle_needs().unwrap();
    assert_eq!(e1.role_on(&g), Some(Role::Read), "Bob's role stands");
    assert_eq!(e1.get(&g, &reg).unwrap(), Some(osis_base::Value::Str("before".into())), "he reads g as before");
    assert!(e1.header(&c).is_none(), "nothing of the forged commit is held");
}

/// Peer 1 writes again an independent thing W it makes, unknown to peer 0 (D): (W, D, D's
/// bytes). D pends at peer 0 for W's record.
fn on_unknown(lp: &mut LocalPeer, v: &str) -> (Tid, CommitId, Vec<u8>) {
    let w = independent_thing(lp, 1);
    let mut m = crate::Mutation::new();
    m.set(w, &osis_base::Ak::new("x:a.0").unwrap(), &osis_base::Value::Str(v.into())).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let d = e1.commit(m).unwrap().unwrap();
    (w, d, e1.package(&d).unwrap().unwrap().bytes)
}

fn awaited(lp: &LocalPeer, w: &Tid) -> bool {
    lp.peers[0].engine.core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*w))
}

// spec/commits.md §4 Pending storage (a stranded report carries while it is the newest on its
// sync ID and its holder is current), §5 What a held thing needs: D1, D2 and D3 pend at peer 0
// for their things' records, carried by holder M's report on G; D2 also by an entry. A newer
// report on G's sync ID carrying none of them forgets D1 and un-roots its W1, D2 staying for its
// entry; D3, carried again by the newer report, goes once M is no holder of G.
#[test]
fn a_report_letting_go_forgets_what_only_it_carries_spec_commits_4() {
    use crate::apply::carriers::Carrier;
    let (mut lp, g, tids) = granted(2, &[(1, Role::Read)]);
    let m = tids[1];
    let s = lp.peers[0].engine.sync_ids(&g).unwrap()[0].id;
    let k = Carrier::Report { actor: g, sync_id: s, holder: m };
    let (w1, d1, b1) = on_unknown(&mut lp, "1");
    let (w2, d2, b2) = on_unknown(&mut lp, "2");
    let (w3, d3, b3) = on_unknown(&mut lp, "3");
    for b in [&b1, &b2] {
        lp.peers[0].engine.ingest_valid(b, Some(k)).unwrap();
    }
    lp.peers[0].receive(&b2, Vec::new()).unwrap();
    assert!([d1, d2].iter().all(|d| lp.peers[0].engine.pends(d)) && awaited(&lp, &w1));
    let mut keys = osis_blob::HolderKeys::default();
    keys.commits.push(osis_base::decode(&b3, &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB)).unwrap());
    // the newer report: D3 rides it alone (off M's chain, so it is not taken from it)
    lp.peers[0].engine.take_stranded(&s, &m, &keys).unwrap();
    lp.peers[0].engine.ingest_valid(&b3, Some(k)).unwrap();
    lp.peers[0].engine.settle_needs().unwrap();
    let e0 = &mut lp.peers[0].engine;
    assert!(!e0.pends(&d1) && !awaited(&lp, &w1), "D1 goes with the report replaced");
    let e0 = &mut lp.peers[0].engine;
    assert_eq!(e0.pending_carriers(&d2), vec![Carrier::Entry], "D2 kept by its entry");
    assert_eq!(e0.pending_carriers(&d3), vec![k], "D3 carried by the newer report");
    e0.demote(&g, &crate::flows::Demotion { holder: m, new: None, retain: None }).unwrap();
    e0.reseal_run(&g).unwrap();
    e0.settle_needs().unwrap();
    assert!(!lp.peers[0].engine.pends(&d3) && !awaited(&lp, &w3), "D3 goes with its holder");
    assert!(lp.peers[0].engine.pends(&d2) && awaited(&lp, &w2));
}

// spec/commits.md §4 Pending storage (a fire carries while its commit is held), spec/sync-inbox.md
// §5 Carried commits, §5 What a held thing needs: peer 2, a reader of g, fires Bob (peer 1) a
// removal notice carrying its own role commit on g and on W, a thing it mints and never sends,
// projected to its part on W. Bob takes it from the notice (`take_fire`): it pends for W's record,
// carried by the notice alone, rooting W. Once the notice leaves Bob's inbox history and is
// forgotten, nothing of the commit or W is left, across a restart.
#[test]
fn a_removal_notice_carries_what_it_brings_until_it_goes_spec_commits_4() {
    use crate::apply::carriers::Carrier;
    use crate::flows::inbox::{save, Fire, OwedFire, REMOVAL_FIRE};
    const HOUR_MS: u64 = 3_600_000;
    let (mut lp, g, tids) = granted(3, &[(1, Role::Read), (2, Role::Read)]);
    let bob = tids[1];
    let removal = osis_base::Ak::new(REMOVAL_FIRE).unwrap();
    // Bob keeps removal notices on his inbox an hour
    let e1 = &mut lp.peers[1].engine;
    let inbox = e1.inbox_thing(&bob).unwrap();
    let mut s = e1.get_typed(&inbox, &osis_schema::core_types::RETENTION).unwrap().unwrap_or_default();
    s.rules.insert(removal.clone(), osis_schema::core_types::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    let mut m = crate::Mutation::new();
    m.set(inbox, &osis_schema::core_types::RETENTION, &s).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let e2 = &mut lp.peers[2].engine;
    let me2 = e2.me();
    let mut m = crate::Mutation::new();
    let w = e2.new_thing(&mut m, me2);
    e2.commit(m).unwrap().unwrap();
    let before = e2.fires_owed();
    let c = e2
        .run(|tx| {
            let mut m = crate::Mutation::new();
            crate::flows::put_edge(&mut m, g, bob, &edge(Role::Sync))?;
            crate::flows::put_edge(&mut m, w, bob, &edge(Role::Read))?;
            m.unchecked();
            tx.core.skip_writer_rules = true;
            let c = crate::engine::Engine::commit_tx(tx, m);
            tx.core.skip_writer_rules = false;
            let c = c?.expect("built");
            let full = tx.get_commit(&c)?.expect("held");
            let on_w = osis_commit::rewrite(&full, |ai| full.header.aspects.get(ai).is_none_or(|a| a.tid != w));
            let v = osis_schema::codec::rt::struct_value(vec![(0, osis_base::Value::Bytes(on_w.encode())), (1, osis_base::Value::List(Vec::new())), (2, osis_base::Value::List(Vec::new()))]);
            save(tx, OwedFire { thing: inbox, ak: removal.clone(), what: Fire::Value(v), to: BTreeSet::new(), commit: None })?;
            Ok(c)
        })
        .unwrap();
    let id = *e2.fires_owed().iter().find(|x| !before.contains(x)).expect("owed");
    let out = e2.sealed_fire(&id).unwrap().expect("sealed");
    let e1 = &mut lp.peers[1].engine;
    let f = match e1.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap() {
        crate::sync::Opened::Commit(f, _) => f,
        o => panic!("the notice is a fire like any: {o:?}"),
    };
    e1.take_carried().unwrap();
    e1.settle_needs().unwrap();
    assert!(e1.pends(&c) && awaited_at(e1, &w), "taken from the notice, pending for W's record");
    assert_eq!(e1.pending_carriers(&c), vec![Carrier::Fire(f)]);
    lp.peers[1].restart(0).unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert!(lp.peers[1].engine.pends(&c) && awaited_at(&lp.peers[1].engine, &w), "carried across a restart");
    lp.advance(HOUR_MS + 1_000);
    lp.peers[1].tick().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.forgettable(&f).unwrap(), "the notice is out of history");
    e1.forget_commits(&[f]).unwrap();
    e1.settle_needs().unwrap();
    assert!(!e1.pends(&c) && !awaited_at(e1, &w) && e1.core.created(&w).is_none(), "gone with its notice: {}", e1.why_kept(&w));
    lp.peers[1].restart(0).unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert!(!lp.peers[1].engine.pends(&c) && lp.peers[1].engine.pending_carriers(&c).is_empty());
}

fn awaited_at(e: &crate::Engine, w: &Tid) -> bool {
    e.core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*w))
}

// spec/commits.md §4 Pending storage (a fire carries a chain commit it carries while its commit is
// held), spec/sync-inbox.md §4 A sealed fire: peer 2 seals Bob (peer 1) a fire whose chain carries,
// beside its own, a write on W, a thing it mints and never sends. Bob takes the fire whole: the
// write pends for W's record, carried by the fire alone, rooting W; once the fire leaves Bob's
// inbox history and is forgotten, nothing of the write or W is left.
#[test]
fn a_sealed_fire_carries_its_chain_until_it_goes_spec_commits_4() {
    use crate::apply::carriers::Carrier;
    use crate::flows::inbox::REMOVAL_FIRE;
    use osis_base::Value;
    const HOUR_MS: u64 = 3_600_000;
    let (mut lp, _, tids) = granted(3, &[]);
    let bob = tids[1];
    let removal = osis_base::Ak::new(REMOVAL_FIRE).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let inbox = e1.inbox_thing(&bob).unwrap();
    let mut s = e1.get_typed(&inbox, &osis_schema::core_types::RETENTION).unwrap().unwrap_or_default();
    s.rules.insert(removal.clone(), osis_schema::core_types::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    let mut m = crate::Mutation::new();
    m.set(inbox, &osis_schema::core_types::RETENTION, &s).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let e2 = &mut lp.peers[2].engine;
    let me2 = e2.me();
    let mut m = crate::Mutation::new();
    let w = e2.new_thing(&mut m, me2);
    e2.commit(m).unwrap().unwrap();
    let mut m = crate::Mutation::new();
    m.set(w, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Str("d".into())).unwrap();
    let d = e2.commit(m).unwrap().unwrap();
    let d_bytes = e2.package(&d).unwrap().unwrap().bytes;
    // `Engine::sealed_fire`, its chain carrying D too
    let fire = e2
        .run(|tx| {
            let mut m = crate::Mutation::new();
            m.op(inbox, &removal, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Set(Value::Int(0)) })?;
            m.commit_form();
            crate::engine::write::sealed_commit(tx, m)
        })
        .unwrap();
    let h = fire.header.clone();
    let mut certs = crate::sync_ids::Certs::default();
    e2.account_chain(&h.author, &mut certs);
    let (mut chain, records) = e2.certs_values(&certs).unwrap();
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    chain.push(osis_base::decode(&d_bytes, &limits).unwrap());
    let (epoch, kem, sync_id) = e2.fire_keys(&inbox).unwrap().unwrap();
    let ais: Vec<usize> = (0..h.aspects.len()).collect();
    let groups = osis_commit::prefix_groups(&h, ais.iter().copied()).unwrap();
    let mut rng = osis_crypto::SeededRng::from_seed([7; 32]);
    let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(&h, &ais).map(osis_base::WallMs), &groups).unwrap();
    let commit = osis_base::decode(&fire.encode(), &limits).unwrap();
    let blob = osis_blob::seal_fire(&prefix, &inbox, &epoch, &kem, &osis_blob::SealedFire { commit, chain, records }, &mut rng).unwrap();
    let e1 = &mut lp.peers[1].engine;
    let f = match e1.open_entry(&sync_id, &osis_blob::blob_id(&blob), &[0; 57], &blob, u64::MAX).unwrap() {
        crate::sync::Opened::Commit(f, _) => f,
        o => panic!("taken whole: {o:?}"),
    };
    e1.settle_needs().unwrap();
    assert!(e1.pends(&d) && awaited_at(e1, &w), "D pends for W's record");
    assert_eq!(e1.pending_carriers(&d), vec![Carrier::Fire(f)]);
    lp.advance(HOUR_MS + 1_000);
    lp.peers[1].tick().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.forgettable(&f).unwrap(), "the fire is out of history");
    e1.forget_commits(&[f]).unwrap();
    e1.settle_needs().unwrap();
    assert!(!e1.pends(&d) && !awaited_at(e1, &w) && e1.core.created(&w).is_none(), "gone with its fire: {}", e1.why_kept(&w));
}
