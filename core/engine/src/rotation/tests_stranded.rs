//! Stranded reports at the receiver (spec/permissions.md §4 Stranded, §3 Re-seal): the holder
//! keys a report brings are taken along the holder's authority chain alone, and the re-seal it
//! asks for writes only what differs.

#![allow(clippy::unwrap_used)]
use super::tests::{edge, granted, independent_thing, synced};
use super::Reseal;
use crate::local_peer::LocalPeer;
use osis_base::{CommitId, Role, Tid};
use std::collections::BTreeSet;

/// Peer 2's holder T holds read on G, an independent thing of peer 0's; everyone synced. (lp, G, T)
fn holder_on_g() -> (LocalPeer, Tid, Tid) {
    let (lp, (g, t)) = LocalPeer::cached("rotation::tests_stranded::holder_on_g", || {
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
// keys as evidence; a node gone from the holder learns its keyset only so. T rotates
// unseen by peer 0; the holder keys of T from peer 2 bring T's new keyset to peer 0.
#[test]
fn holder_keys_bring_the_holders_new_keyset_spec_permissions_4() {
    let (mut lp, _, t) = holder_on_g();
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
    let (mut lp, _, t) = holder_on_g();
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
    let (mut lp, _, t) = holder_on_g();
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
    let (mut lp, g, tids) = until_granted();
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

/// G, an independent thing of peer 0's, granting peer 1 read until a second on; synced.
fn until_granted() -> (LocalPeer, Tid, Vec<Tid>) {
    let (lp, (g, tids)) = LocalPeer::cached("rotation::tests_stranded::until_granted", || {
        let mut lp = synced(2);
        let tids: Vec<Tid> = (0..2).map(|i| lp.peers[i].engine.me()).collect();
        let g = independent_thing(&mut lp, 0);
        let until = lp.peers[0].engine.now().0 + 1_000;
        lp.peers[0].engine.grant(&g, &tids[1], &osis_schema::core_types::Edge { until: Some(osis_base::WallMs(until)), ..edge(Role::Read) }).unwrap();
        lp.sync_all().unwrap();
        (lp, (g, tids))
    });
    (lp, g, tids)
}

// spec/crypto.md §4 (Encrypting under: a grant past its `until` that this node may finalize is
// finalized before its next commit encrypting under the actor): whether a body can be wrapped for
// S reads the clock with a wake at the grant's `until`, so a reader following it is due then with
// nothing else moving, and judges it unwrappable until the finalize is written.
#[test]
fn whether_a_body_wraps_moves_at_a_grants_until_spec_crypto_4() {
    let (mut lp, g, _) = until_granted();
    let mut m = crate::Mutation::new();
    m.set(g, &osis_base::Ak::new("x:m.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
    let c = lp.peers[0].commit(m).unwrap().unwrap();
    let s = lp.peers[0].engine.sync_ids(&g).unwrap()[0].id;
    let e = &mut lp.peers[0].engine;
    let mut fx: osis_base::memo::Effects<(), bool> = osis_base::memo::Effects::new("wraps");
    fx.want(());
    assert_eq!(fx.settle(&(), || { let held = e.commit_blobs(&c).unwrap(); e.may_log(&s, &crate::sync::BodyId::unit(c), &held).unwrap() }), Some((None, true)), "wraps before the until");
    assert!(fx.due().is_empty());
    lp.peers[0].clock.advance(2_000);
    let e = &mut lp.peers[0].engine;
    let now = e.now();
    e.set_now(now);
    // as sync's driver does before each module's `due` (`Engine::follow`)
    e.follow().unwrap();
    assert_eq!(fx.due(), vec![()], "due at the until");
    assert_eq!(fx.settle(&(), || { let held = e.commit_blobs(&c).unwrap(); e.may_log(&s, &crate::sync::BodyId::unit(c), &held).unwrap() }), Some((Some(true), false)), "the finalize is owed first");
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
    // g's admin enables no external signal
    let mut x = crate::Mutation::new();
    x.set(g, &osis_schema::core_types::RETENTION, &osis_schema::core_types::RetentionSetting::default()).unwrap();
    lp.peers[0].commit(x).unwrap();
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

// spec/crypto.md §7 (Header list; Checked keys), spec/sync-inbox.md §2, spec/sync-ids.md §6
// Steps: a fire from outside lists the step keys g's `keys.0` publishes, written in the commit
// recording that step. Peer 0, g's admin, rotates g's admin role; peer 1, holding g's public key
// record and no secret of g, takes the rotation's keysets before the step registering them is
// issued, and fires on g: its fire lists the recorded step's delete key, not the rotation's, and
// the admin, issuing the step after it, takes it. Fails if the fire lists the rotation's key (no
// step recorded before the fire bears it: unjudgeable for good, the fire refused) or the step
// leaves `keys.0` as it was (the published key then never moves on).
#[test]
fn a_fire_sent_between_a_rotation_and_its_step_is_taken_spec_crypto_7() {
    use osis_base::{Ak, Value};
    use osis_schema::core_types as ct;
    let (mut lp, g, _) = granted(2, &[]);
    let f = Ak::new("x:f@~0").unwrap();
    let keep = ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() };
    let mut m = crate::Mutation::new();
    m.set(g, &ct::RETENTION, &ct::RetentionSetting::from(std::collections::BTreeMap::from([(f.clone(), keep)]))).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let published = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get_typed(&g, &ct::KEYS).unwrap().and_then(|k| k.step).map(|s| s.delete);
    let head = lp.peers[0].engine.core.listed_step(&g).unwrap();
    let head_key = ct::SigningKey::Ed25519(head.delete.to_vec());
    assert_eq!(published(&mut lp, 1), Some(head_key.clone()), "g's keys.0 publishes its head's keys");
    lp.peers[0].engine.rotate_leaving_out(&g, &[Role::Admin], &[]).unwrap().expect("rotated");
    let admin = lp.peers[0].engine.epochs(&g).unwrap().admin.newest_held().unwrap().1.clone();
    let rotated = osis_crypto::DeleteSecret::admin(&admin).verifying_key().to_bytes();
    assert_ne!(rotated, head.delete);
    assert_eq!(lp.peers[0].engine.core.listed_step(&g), Some(head.clone()), "no step yet");
    lp.sync(0, 1).unwrap();
    let held = lp.peers[1].engine.get_typed(&g, &ct::KEYS).unwrap().unwrap();
    let new_epoch = osis_keys::aspects::to_schema(&lp.peers[0].engine.epochs(&g).unwrap().admin.newest_held().unwrap().0);
    assert_eq!(held.admin.map(|k| k.epoch), Some(new_epoch), "peer 1 holds the rotation's keysets");
    assert_eq!(held.step.map(|s| s.delete), Some(head_key.clone()), "and the recorded step's keys");
    let s = &mut lp.peers[1].engine;
    s.fire_open(&g, f.as_str(), Value::Int(5)).unwrap();
    let id = *s.fires_owed().first().expect("a sealed fire owed");
    let out = s.sealed_fire(&id).unwrap().expect("sealed");
    let fire = osis_commit::CommitBlob::decode(s.core.ix.fires.get(&id).unwrap().commit.as_ref().unwrap()).unwrap();
    let listed: Vec<[u8; 32]> = fire.header.keys.iter().filter(|k| k.level == osis_base::format::DELETE_ADMIN).map(|k| k.key).collect();
    assert_eq!(listed, vec![head.delete], "the fire lists the recorded step's key");
    lp.advance(1_000);
    let sync_id = head.sync_id;
    lp.peers[0].engine.issue_step(&g, &sync_id, false).unwrap().expect("the step is due");
    assert_eq!(lp.peers[0].engine.core.listed_step(&g).map(|s| s.delete), Some(rotated), "the step registers the rotation");
    assert_eq!(published(&mut lp, 0), Some(ct::SigningKey::Ed25519(rotated.to_vec())), "published with the step");
    let opened = lp.peers[0].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the admin takes the fire: {opened:?}");
}

// spec/permissions.md §3 (Who rotates), spec/crypto.md §7 (Header list): a `keys.0` delta touching
// a field other than the keysets a writer rotates and box records needs admin, so a writer of g
// writing junk step keys in g's `keys.0` changes nothing: its write is invalid, peer 2 (outside g) still lists
// the recorded step's key in its fire, and the admin takes it. Fails if `step` needs only write
// (every outside fire would then list keys no step places and apply nowhere, silently).
#[test]
fn a_writers_junk_step_keys_change_no_outside_fire_spec_permissions_3() {
    use osis_base::{Ak, Value};
    use osis_crdt::{Op, PathOp, PathSeg};
    use osis_schema::core_types as ct;
    use osis_schema::Codec;
    let (mut lp, g, _) = granted(3, &[(1, Role::Write)]);
    let f = Ak::new("x:f@~0").unwrap();
    let keep = ct::RetentionEntry { history: Some(osis_schema::History::FOREVER), ..Default::default() };
    let mut m = crate::Mutation::new();
    m.set(g, &ct::RETENTION, &ct::RetentionSetting::from(std::collections::BTreeMap::from([(f.clone(), keep)]))).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let head = lp.peers[0].engine.core.listed_step(&g).unwrap();
    let junk = ct::StepKeys { delete: ct::SigningKey::Ed25519(vec![0x66; 32]), write: ct::SigningKey::Ed25519(vec![0x67; 32]) };
    let mut m = crate::Mutation::new();
    m.op(g, &ct::KEYS, PathOp { path: vec![PathSeg::Field(10)], op: Op::Set(Some(junk).to_value()) }).unwrap();
    m.unchecked();
    lp.peers[1].engine.core.skip_writer_rules = true;
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.peers[1].engine.core.skip_writer_rules = false;
    lp.sync_all().unwrap();
    for i in [0, 2] {
        let step = lp.peers[i].engine.get_typed(&g, &ct::KEYS).unwrap().and_then(|k| k.step).map(|s| s.delete);
        assert_eq!(step, Some(ct::SigningKey::Ed25519(head.delete.to_vec())), "peer {i} keeps the step's keys");
    }
    let s = &mut lp.peers[2].engine;
    s.fire_open(&g, f.as_str(), Value::Int(5)).unwrap();
    let id = *s.fires_owed().first().expect("a sealed fire owed");
    let out = s.sealed_fire(&id).unwrap().expect("sealed");
    let opened = lp.peers[0].engine.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the admin takes the fire: {opened:?}");
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
            save(tx, OwedFire { thing: g, ak: f.clone(), what: Fire::Value(Value::Int(n as i64)), to: BTreeSet::new(), commit: Some(std::sync::Arc::new(b.encode())), pages: Default::default() })
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

// spec/sync-inbox.md §5 (Carried commits: a grant fire's commit is taken as an arriving
// commit, each part only where judged valid): peer 2, a reader of g and no admin, forges Bob's
// (peer 1's) demotion on g, built as a hostile sender would, and fires it as a grant fire sealed
// on Bob's inbox. Bob, taking it, checks it against the roster he holds: he still reads g, and holds
// nothing of the forged commit.
#[test]
#[ignore = "accounts: making an account"]
fn a_forged_grant_fire_changes_nothing_spec_sync_inbox_5() {
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
            crate::flows::inbox::fire_copy(tx, bob, c, g)?;
            Ok(c)
        })
        .unwrap();
    let id = *e2.fires_owed().iter().find(|x| !before.contains(x)).expect("owed");
    let out = e2.sealed_fire(&id).unwrap().expect("sealed");
    let e1 = &mut lp.peers[1].engine;
    let opened = e1.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap();
    assert!(matches!(opened, crate::sync::Opened::Commit(..)), "the grant fire is a fire like any: {opened:?}");
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
    assert!([d1, d2].iter().all(|d| lp.peers[0].engine.pends(d)) && awaited_at(&lp.peers[0].engine, &w1));
    let mut keys = osis_blob::HolderKeys::default();
    keys.commits.push(osis_base::decode(&b3, &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB)).unwrap());
    // the newer report: D3 rides it alone (off M's chain, so it is not taken from it)
    lp.peers[0].engine.take_stranded(&s, &m, &keys).unwrap();
    lp.peers[0].engine.ingest_valid(&b3, Some(k)).unwrap();
    lp.peers[0].engine.settle_needs().unwrap();
    let e0 = &mut lp.peers[0].engine;
    assert!(!e0.pends(&d1) && !awaited_at(&lp.peers[0].engine, &w1), "D1 goes with the report replaced");
    let e0 = &mut lp.peers[0].engine;
    assert_eq!(e0.pending_carriers(&d2), vec![Carrier::Entry], "D2 kept by its entry");
    assert_eq!(e0.pending_carriers(&d3), vec![k], "D3 carried by the newer report");
    e0.demote(&g, &crate::flows::Demotion { holder: m, new: None, retain: None }).unwrap();
    e0.reseal_run(&g).unwrap();
    e0.settle_needs().unwrap();
    assert!(!lp.peers[0].engine.pends(&d3) && !awaited_at(&lp.peers[0].engine, &w3), "D3 goes with its holder");
    assert!(lp.peers[0].engine.pends(&d2) && awaited_at(&lp.peers[0].engine, &w2));
}

// spec/commits.md §4 Pending storage (a fire carries while its commit is held), spec/sync-inbox.md
// §5 Carried commits, §5 What a held thing needs: peer 2, a reader of g, fires Bob (peer 1) a
// grant fire carrying its own role commit on g and on W, a thing it mints and never sends,
// projected to its part on W. Bob takes it from the fire (`take_fire`): it pends for W's record,
// carried by the fire alone, rooting W. Once the fire leaves Bob's inbox history and is
// forgotten, nothing of the commit or W is left, across a restart.
#[test]
fn a_grant_fire_carries_what_it_brings_until_it_goes_spec_commits_4() {
    use crate::apply::carriers::Carrier;
    use crate::flows::inbox::{save, Fire, OwedFire, GRANT_FIRE};
    let (mut lp, g, tids) = granted(3, &[(1, Role::Read), (2, Role::Read)]);
    let bob = tids[1];
    let grant = osis_base::Ak::new(GRANT_FIRE).unwrap();
    let (inbox, w) = keeps_fires_an_hour(&mut lp, &grant);
    let e2 = &mut lp.peers[2].engine;
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
            save(tx, OwedFire { thing: inbox, ak: grant.clone(), what: Fire::Value(v), to: BTreeSet::new(), commit: None, pages: Default::default() })?;
            Ok(c)
        })
        .unwrap();
    let id = *e2.fires_owed().iter().find(|x| !before.contains(x)).expect("owed");
    let out = e2.sealed_fire(&id).unwrap().expect("sealed");
    let e1 = &mut lp.peers[1].engine;
    let f = match e1.open_entry(&out.sync_id, &osis_blob::blob_id(&out.blob), &[0; 57], &out.blob, u64::MAX).unwrap() {
        crate::sync::Opened::Commit(f, _) => f,
        o => panic!("the grant fire is a fire like any: {o:?}"),
    };
    e1.take_carried().unwrap();
    e1.settle_needs().unwrap();
    assert!(e1.pends(&c) && awaited_at(e1, &w), "taken from the fire, pending for W's record");
    assert_eq!(e1.pending_carriers(&c), vec![Carrier::Fire(f)]);
    lp.peers[1].restart(0).unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert!(lp.peers[1].engine.pends(&c) && awaited_at(&lp.peers[1].engine, &w), "carried across a restart");
    lp.advance(HOUR_MS + 1_000);
    lp.peers[1].tick().unwrap();
    let e1 = &mut lp.peers[1].engine;
    assert!(e1.forgettable(&f).unwrap(), "the fire is out of history");
    e1.forget_commits(&[f]).unwrap();
    e1.settle_needs().unwrap();
    assert!(!e1.pends(&c) && !awaited_at(e1, &w) && e1.core.created(&w).is_none(), "gone with its fire: {}", e1.why_kept(&w));
    lp.peers[1].restart(0).unwrap();
    lp.peers[1].engine.settle_needs().unwrap();
    assert!(!lp.peers[1].engine.pends(&c) && lp.peers[1].engine.pending_carriers(&c).is_empty());
}

fn awaited_at(e: &crate::Engine, w: &Tid) -> bool {
    e.core.ix.pend_on.contains_key(&crate::apply::Wake::Record(*w))
}

const HOUR_MS: u64 = 3_600_000;

/// Bob (peer 1) keeps `fire` signals on his inbox an hour, synced; peer 2 then mints W, which
/// it never sends. (Bob's inbox, W)
fn keeps_fires_an_hour(lp: &mut LocalPeer, fire: &osis_base::Ak) -> (Tid, Tid) {
    let bob = lp.peers[1].engine.me();
    let e1 = &mut lp.peers[1].engine;
    let inbox = e1.inbox_thing(&bob).unwrap();
    let mut s = e1.get_typed(&inbox, &osis_schema::core_types::RETENTION).unwrap().unwrap_or_default();
    s.rules.insert(fire.clone(), osis_schema::core_types::RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(HOUR_MS) }), ..Default::default() });
    let mut m = crate::Mutation::new();
    m.set(inbox, &osis_schema::core_types::RETENTION, &s).unwrap();
    lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let e2 = &mut lp.peers[2].engine;
    let me2 = e2.me();
    let mut m = crate::Mutation::new();
    let w = e2.new_thing(&mut m, me2);
    e2.commit(m).unwrap().unwrap();
    (inbox, w)
}

// spec/commits.md §4 Pending storage (a fire carries a chain commit it carries while its commit is
// held), spec/sync-inbox.md §4 A sealed fire: peer 2 seals Bob (peer 1) a fire whose chain carries,
// beside its own, a write on W, a thing it mints and never sends. Bob takes the fire whole: the
// write pends for W's record, carried by the fire alone, rooting W; once the fire leaves Bob's
// inbox history and is forgotten, nothing of the write or W is left.
#[test]
fn a_sealed_fire_carries_its_chain_until_it_goes_spec_commits_4() {
    use crate::apply::carriers::Carrier;
    use crate::flows::inbox::GRANT_FIRE;
    use osis_base::Value;
    let (mut lp, _, _) = granted(3, &[]);
    let grant = osis_base::Ak::new(GRANT_FIRE).unwrap();
    let (inbox, w) = keeps_fires_an_hour(&mut lp, &grant);
    let e2 = &mut lp.peers[2].engine;
    let mut m = crate::Mutation::new();
    m.set(w, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Str("d".into())).unwrap();
    let d = e2.commit(m).unwrap().unwrap();
    let d_bytes = e2.package(&d).unwrap().unwrap().bytes;
    // `Engine::sealed_fire`, its chain carrying D too
    let fire = e2
        .run(|tx| {
            let mut m = crate::Mutation::new();
            m.op(inbox, &grant, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Set(Value::Int(0)) })?;
            m.commit_form();
            crate::engine::write::sealed_commit(tx, m)
        })
        .unwrap();
    let h = fire.header.clone();
    let mut certs = crate::sync_ids::Certs::default();
    certs.records.insert(h.signer);
    let (mut chain, records) = e2.certs_values(&certs).unwrap();
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    chain.push(osis_base::decode(&d_bytes, &limits).unwrap());
    let (epoch, kem, sync_id) = e2.fire_keys(&inbox).unwrap().unwrap();
    let ais: Vec<usize> = (0..h.aspects.len()).collect();
    let groups = osis_commit::prefix_groups(&h, ais.iter().copied()).unwrap();
    let mut rng = osis_crypto::SeededRng::from_seed([7; 32]);
    let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(&h, &ais).map(osis_base::WallMs), &groups).unwrap();
    let commit = osis_base::decode(&fire.encode(), &limits).unwrap();
    let blob = osis_blob::seal_fire(&prefix, &inbox, &epoch, &kem, &osis_blob::SealedFire { copy: false, commit, evidence: chain, records, pages: Vec::new() }, &mut rng).unwrap();
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

// spec/permissions.md §4 Delivering an edge piece: an edge write goes as a `grant@~0` fire only
// where its writer may not write the holder. Alice grants her own G a role on her X: G's key
// part, logged under G's sync ID, so nothing is fired. She grants Bob's account, which she does
// not write: a fire is owed. Bob's H hangs under his A, on which Alice holds admin by a grant:
// she writes H through A, and nothing is fired.
#[test]
fn an_edge_write_fires_only_where_its_writer_may_not_write_the_holder_spec_permissions_4() {
    let mut lp = synced(2);
    let (alice, bob) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
    let a = independent_thing(&mut lp, 1);
    let mut m = crate::Mutation::new();
    let h = lp.peers[1].engine.new_thing(&mut m, a);
    lp.peers[1].commit(m).unwrap();
    lp.hold(h);
    lp.peers[1].engine.grant(&a, &alice, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let g = independent_thing(&mut lp, 0);
    let x = independent_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    let e0 = &mut lp.peers[0].engine;
    let fired = |e0: &crate::Engine, c: CommitId| e0.core.ix.fires.values().any(|o| matches!(o.what, crate::flows::inbox::Fire::Grant { commit, .. } if commit == c));
    let grant = |e0: &mut crate::Engine, holder: Tid| {
        e0.grant(&x, &holder, &edge(Role::Read)).unwrap();
        e0.core.timelines().in_force(&osis_base::Holder::Thing(holder), &x).expect("the grant applied")
    };
    let c = grant(e0, g);
    assert!(!fired(e0, c), "a grant by the holder's writer is fired nowhere");
    let c = grant(e0, bob);
    assert!(fired(e0, c), "a grant from outside is fired");
    let c = grant(e0, h);
    assert!(!fired(e0, c), "Alice writes H through A: fired nowhere");
}
