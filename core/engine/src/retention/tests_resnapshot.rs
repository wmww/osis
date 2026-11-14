//! The re-snapshot a writer owes after a purge (spec/commits.md §5 Purge) is written whatever
//! happens between the purge and the write: a stop, or delete keys that come only later.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use crate::Mutation;
use crate::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_schema::Retention;
use osis_schema::core_types as ct;

const T0: osis_base::WallMs = osis_base::WallMs(1_700_000_000_000);

fn reg() -> Ak {
    Ak::new("x:a.0").unwrap()
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
}

/// Admin 0 and writer 1 on a thing of 0. With `keys`, 1 holds every commit of 0; without, all but
/// those carrying the thing's `keys.0` (its delete keys), returned for later.
fn world(keys: bool) -> (LocalPeer, Tid, Vec<crate::local_peer::Package>) {
    let key = if keys { "retention::tests_resnapshot::keys" } else { "retention::tests_resnapshot::no_keys" };
    let (lp, (t, rest)) = LocalPeer::cached(key, || {
        let mut lp = LocalPeer::fresh(2, T0);
        lp.sync_all().unwrap();
        let (a, w) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        // the writer's role by a raw edge write, so it holds the role without the grant's keys
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(w))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&edge(Role::Write))) }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        let pks = lp.packages(0).unwrap();
        let carries = |lp: &LocalPeer, id: &CommitId| lp.peers[0].engine.writes_keyset(&t, id);
        let (held, rest): (Vec<_>, Vec<_>) = pks.into_iter().partition(|pk| keys || !carries(&lp, &pk.id));
        for pk in &held {
            lp.deliver(1, pk).unwrap();
        }
        assert_eq!(lp.peers[1].engine.holds_delete_keys(&t).unwrap(), keys);
        lp.advance(60_000);
        (lp, (t, rest))
    });
    (lp, t, rest)
}

/// Admin 0 writes over an older value with a secret on `t`, 1 applying each; 0 purges the secret
/// and 1 applies the request (node-sync, which would write the re-snapshot at once, does not run).
fn purged(lp: &mut LocalPeer, t: Tid) {
    let send = |lp: &mut LocalPeer, id: CommitId| {
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    };
    let mut c = None;
    for v in ["old", "SECRET"] {
        let mut m = Mutation::new();
        m.retention(t, &reg(), Retention { by: PurgeBy::Writer }).unwrap();
        m.set(t, &reg(), &Value::Str(v.into())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        send(lp, id);
        c = Some(id);
        lp.advance(1_000);
    }
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(lp.peers[0].engine.purge_item(&c.unwrap(), t, reg()).unwrap());
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    send(lp, p);
    assert_eq!(lp.peers[1].engine.get(&t, &reg()).unwrap(), None, "the purge applied");
}

/// The snapshots of `(t, reg)` writer 1 wrote.
fn own_snapshots(lp: &LocalPeer, t: Tid) -> usize {
    let e = &lp.peers[1].engine;
    let me = e.me();
    e.core.ix.snapshots.get(&(t, reg())).into_iter().flatten().filter(|x| e.header(&x.1).is_some_and(|h| h.author == me)).count()
}

// spec/commits.md §5 Purge: a writer that stops after applying a purge request, before writing the
// re-snapshot it owes, writes it once open again, once only
#[test]
fn owed_resnapshot_survives_a_stop_spec_commits_5() {
    let (mut lp, t, _) = world(true);
    purged(&mut lp, t);
    assert_eq!(own_snapshots(&lp, t), 0, "not written yet");
    lp.peers[1].restart(1).unwrap();
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1, "written after the stop");
    lp.peers[1].engine.purge_resnapshots().unwrap();
    lp.peers[1].restart(2).unwrap();
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1, "owed no more");
}

// spec/commits.md §5 Purge, spec/crypto.md §7: a writer that may not write the re-snapshot yet
// (the thing's delete keys are not here) writes it once they come
#[test]
fn owed_resnapshot_waits_for_delete_keys_spec_commits_5() {
    let (mut lp, t, keys) = world(false);
    purged(&mut lp, t);
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 0, "the keys are not here");
    for pk in &keys {
        lp.deliver(1, pk).unwrap();
    }
    assert!(lp.peers[1].engine.holds_delete_keys(&t).unwrap());
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1, "written once the keys came");
}
