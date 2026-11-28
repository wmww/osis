//! Grant signals (spec/sync-inbox.md §5 Grant signal): who follows one, and under which sync IDs.

#![allow(clippy::unwrap_used)]
use crate::local_peer::LocalPeer;
use crate::rotation::tests::{grant, synced};
use crate::Mutation;
use osis_base::{Ak, Role, SyncId, Tid, Value};
use osis_schema::RawKey;
use osis_schema::core_types as ct;

/// An independent thing peer `i` makes and holds alone, enabling the inbox signals when `inbox`.
fn own_thing(lp: &mut LocalPeer, i: usize, inbox: bool) -> Tid {
    let me = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    let t = lp.peers[i].engine.new_thing(&mut m, me);
    if inbox {
        let mut setting = ct::RetentionSetting::default();
        setting.take_inbox_signals();
        m.set(t, &ct::RETENTION, &setting).unwrap();
    }
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.make_independent(&t).unwrap();
    lp.hold_at(i, t);
    t
}

/// Peer `i` fires a grant signal on `inbox` naming `x` under `s`, telling `holder` (as anyone
/// holding the inbox's card may, the values its own), and takes it.
fn signal(lp: &mut LocalPeer, i: usize, inbox: Tid, x: Tid, s: SyncId, holder: Tid) {
    let v = osis_schema::codec::rt::struct_value(vec![(0, Value::Weak(x)), (1, Value::Bytes(s.0.to_vec())), (2, Value::List(vec![])), (3, Value::Bytes(holder.as_bytes().to_vec()))]);
    let mut m = Mutation::new();
    m.op(inbox, &Ak::new(super::inbox::GRANT_FIRE).unwrap(), osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.take_carried().unwrap();
}

/// The things peer `i` syncs under `s` (none: `s` is not in its sync set).
fn synced_under(lp: &mut LocalPeer, i: usize, s: &SyncId) -> Option<std::collections::BTreeSet<Tid>> {
    lp.peers[i].engine.sync_holder(s).unwrap().map(|(ts, _)| ts)
}

// spec/sync-inbox.md §5 (Grant signal), spec/sync-hostile.md (a forged signal names a sync ID that
// gives nothing), spec/sync-ids.md §4 (Owner): peer 1 holds two signals naming X, one by X's own
// sync ID, one by another (a forger's: anyone holding the holder's card fires one), in either
// order. X is followed under both, before and after a restart. A third naming X by the sync ID of
// a thing peer 1 owns (its inbox), and a `sync.0` of another thing of peer 1's recording X's
// sync ID, change nothing: the inbox's sync ID stays its own alone, and X's stays followed. Fails
// with the newest signal's sync ID displacing the other, or with a sync ID any other thing
// records counted as that thing's.
#[test]
fn a_signals_sync_id_is_never_displaced_spec_sync_inbox_5() {
    for forged_last in [false, true] {
        let mut lp = synced(2);
        let n = lp.peers[1].engine.tid();
        let x = own_thing(&mut lp, 0, false);
        let own = lp.peers[0].engine.sync_id_of(&x).unwrap().expect("X's sync ID");
        let forged = SyncId([7; 16]);
        let inbox = own_thing(&mut lp, 1, true);
        let order = if forged_last { [own, forged] } else { [forged, own] };
        for s in order {
            signal(&mut lp, 1, inbox, x, s, n);
        }
        let inbox_s = lp.peers[1].engine.sync_id_of(&inbox).unwrap().expect("the inbox's sync ID");
        signal(&mut lp, 1, inbox, x, inbox_s, n);
        // a thing of peer 1's whose `sync.0` records X's sync ID (its admins' word, judged by
        // the owner rule: no step of it bears a key of that thing's)
        let z = own_thing(&mut lp, 1, false);
        let sync_ak = Ak::new("sync.0").unwrap();
        let read = |lp: &mut LocalPeer, i: usize, t: &Tid| ct::SYNC.decode(&lp.peers[i].engine.get(t, &sync_ak).unwrap().expect("a sync.0")).unwrap();
        let mut zs = read(&mut lp, 1, &z);
        zs.extend(read(&mut lp, 0, &x));
        let mut m = Mutation::new();
        m.set(z, &ct::SYNC, &zs).unwrap();
        lp.peers[1].commit(m).unwrap();
        for restart in [false, true] {
            if restart {
                lp.peers[1].restart(5).unwrap();
                lp.peers[1].engine.take_carried().unwrap();
            }
            let at = format!("forged last {forged_last}, restart {restart}");
            assert_eq!(synced_under(&mut lp, 1, &own), Some([x].into()), "{at}: X followed under its own sync ID");
            assert_eq!(synced_under(&mut lp, 1, &forged), Some([x].into()), "{at}: and the forged one");
            assert_eq!(synced_under(&mut lp, 1, &inbox_s), Some([inbox].into()), "{at}: the inbox's sync ID its own alone");
        }
    }
}

// spec/sync-inbox.md §5 (Grant signal: followed by a node reading its holder): peer 1 holds a
// signal on its inbox telling G, a thing peer 0 makes, of X. Reading the inbox but not G, peer 1
// follows nothing for it; once granted read on G and holding it, it follows X; removed from G, it
// lets X go. Fails with every node reading the inbox following its signals.
#[test]
fn a_signal_is_followed_where_its_holder_is_read_spec_sync_inbox_5() {
    let mut lp = synced(2);
    let n = lp.peers[1].engine.tid();
    let x = own_thing(&mut lp, 0, false);
    let g = own_thing(&mut lp, 0, false);
    let s = lp.peers[0].engine.sync_id_of(&x).unwrap().expect("X's sync ID");
    let inbox = own_thing(&mut lp, 1, true);
    signal(&mut lp, 1, inbox, x, s, g);
    assert_eq!(synced_under(&mut lp, 1, &s), None, "G not read: X not followed");
    lp.peers[0].engine.grant(&g, &n, &grant(Role::Read)).unwrap();
    lp.hold_at(1, g);
    lp.sync_all().unwrap();
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&g), Some(Role::Read), "peer 1 reads G");
    assert_eq!(synced_under(&mut lp, 1, &s), Some([x].into()), "G read: X followed");
    lp.peers[0].engine.demote(&g, &super::Demotion { holder: n, new: None, retain: None }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[1].engine.take_carried().unwrap();
    assert_eq!(lp.peers[1].engine.role_on(&g), None, "peer 1 reads G no more");
    assert_eq!(synced_under(&mut lp, 1, &s), None, "X let go");
}
