//! The re-snapshot a writer owes after a purge (spec/commits.md §5 Purge) is written whatever
//! comes between the purge and the write, a stop included.

use osis_engine::Mutation;
use osis_engine::local_peer::LocalPeer;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Value};
use osis_schema::core_types as ct;
use crate::common::{T0, edge};

fn reg() -> Ak {
    Ak::new("x:a.0").unwrap()
}

/// Admin 0 and writer 1 on a thing of 0, 1 holding every commit of 0.
fn world() -> (LocalPeer, Tid) {
    LocalPeer::cached("retention::tests_resnapshot::world", || {
        let mut lp = LocalPeer::fresh(2, T0);
        lp.sync_all().unwrap();
        let (a, w) = (lp.peers[0].engine.me(), lp.peers[1].engine.me());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
        for pk in &lp.packages_for(0, 1).unwrap() {
            lp.deliver(1, pk).unwrap();
        }
        lp.advance(60_000);
        (lp, t)
    })
}

/// How the secret reaches 1 (`purged`).
#[derive(Clone, Copy, Debug)]
enum Secret {
    /// Before the request.
    First,
    /// After the request, whole: a copy taken before 0 purged it.
    LateBody,
    /// After the request, as 0 holds it then: the header without the purged body.
    LateHeader,
}

/// Admin 0 writes over an older value with a secret on `t`, 1 applying each; 0 purges the secret
/// and 1 applies the request (node-sync, which would write the re-snapshot at once, does not run).
/// Where 1 got the secret's body it reads the older value again, whichever came first
/// (spec/commits.md §5 Purge, spec/crdt.md §4.7: a gone write has no effect on the read).
fn purged(lp: &mut LocalPeer, t: Tid, secret: Secret) {
    let send = |lp: &mut LocalPeer, id: CommitId| {
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
    };
    let mut c = None;
    let mut early = None;
    let mut old = None;
    for v in ["old", "SECRET"] {
        let mut m = Mutation::new();
        m.purge_by(t, &reg(), PurgeBy::Writer).unwrap();
        m.set(t, &reg(), &Value::Str(v.into())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        if v == "old" || matches!(secret, Secret::First) {
            send(lp, id);
        } else {
            early = lp.peers[0].engine.package(&id).unwrap();
        }
        c = Some(id);
        lp.advance(1_000);
        if v == "old" {
            // what the secret replaces, as this writer reads it (nothing without the delete keys)
            old = lp.peers[1].engine.get(&t, &reg()).unwrap();
        }
    }
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(lp.peers[0].engine.purge_item(&c.unwrap(), t, reg()).unwrap());
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    send(lp, p);
    match secret {
        Secret::First => {}
        Secret::LateBody => {
            lp.deliver(1, &early.unwrap()).unwrap();
        }
        Secret::LateHeader => send(lp, c.unwrap()),
    }
    if !matches!(secret, Secret::LateHeader) {
        assert_eq!(lp.peers[1].engine.get(&t, &reg()).unwrap(), old, "the purge applied, {secret:?}");
    }
}

/// The snapshots of `(t, reg)` writer 1 wrote.
fn own_snapshots(lp: &LocalPeer, t: Tid) -> usize {
    let e = &lp.peers[1].engine;
    let me = e.me();
    e.core.ix.snapshots.get(&(t, reg())).into_iter().flatten().filter(|x| e.header(&x.1).is_some_and(|h| h.signer == me)).count()
}

// spec/commits.md §5 Purge: a writer that stops after applying a purge request, before writing the
// re-snapshot it owes, writes it once open again, once only
#[test]
fn owed_resnapshot_survives_a_stop_spec_commits_5() {
    let (mut lp, t) = world();
    purged(&mut lp, t, Secret::First);
    assert_eq!(own_snapshots(&lp, t), 0, "not written yet");
    lp.peers[1].restart(1).unwrap();
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1, "written after the stop");
    lp.peers[1].engine.purge_resnapshots().unwrap();
    lp.peers[1].restart(2).unwrap();
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1, "owed no more");
}

// spec/commits.md §5 Purge, §4 Order independence: a writer owes the re-snapshot whichever of the
// request and the delta it names came first: the request dropped something here either way
#[test]
fn owed_resnapshot_whichever_comes_first_spec_commits_5() {
    for secret in [Secret::First, Secret::LateBody, Secret::LateHeader] {
        let (mut lp, t) = world();
        purged(&mut lp, t, secret);
        lp.peers[1].engine.purge_resnapshots().unwrap();
        assert_eq!(own_snapshots(&lp, t), 1, "{secret:?}");
    }
}

// spec/commits.md §5 Purge, spec/crdt.md §4.7, spec/requirements.md Convergence: admin and writer
// read the value the purged secret replaced, whichever of it and the request reached the writer
// first (a writer given only the secret's header reads as one that held and removed it), also
// after exchanging their re-snapshots
#[test]
fn purged_secret_reads_what_it_replaced_whatever_reaches_first_spec_commits_5() {
    for secret in [Secret::First, Secret::LateBody, Secret::LateHeader] {
        let (mut lp, t) = world();
        purged(&mut lp, t, secret);
        for i in [0, 1] {
            lp.peers[i].engine.purge_resnapshots().unwrap();
        }
        lp.sync(1, 0).unwrap();
        lp.sync(0, 1).unwrap();
        for i in [0, 1] {
            assert_eq!(lp.peers[i].engine.get(&t, &reg()).unwrap(), Some(Value::Str("old".into())), "peer {i}, {secret:?}");
        }
    }
}

// spec/commits.md §5 Purge (what the re-snapshot is for), spec/requirements.md Convergence: a
// node that compacted the value a purged write replaced (no history kept: dropped as covered under
// a snapshot carrying the purged write) cannot read it again from bodies, which it takes no copy
// of, even from a writer holding them; it reads it again once that writer re-snapshots
#[test]
fn a_compacted_node_reads_what_a_purge_brought_back_once_a_writer_resnapshots_spec_commits_5() {
    let (mut lp, t) = world();
    let mut ids = Vec::new();
    for v in ["old", "SECRET"] {
        let mut m = Mutation::new();
        m.purge_by(t, &reg(), PurgeBy::Writer).unwrap();
        m.set(t, &reg(), &Value::Str(v.into())).unwrap();
        let id = lp.peers[0].commit(m).unwrap().unwrap();
        let pk = lp.peers[0].engine.package(&id).unwrap().unwrap();
        lp.deliver(1, &pk).unwrap();
        ids.push(id);
        lp.advance(1_000);
    }
    let e = &mut lp.peers[0].engine;
    e.snapshot(&t, &reg()).unwrap().unwrap();
    for c in &ids {
        e.drop_body(c, &t, &reg()).unwrap();
    }
    let mut m = Mutation::new();
    m.set(t, &ct::PURGE, &lp.peers[0].engine.now()).unwrap();
    m.purge(lp.peers[0].engine.purge_item(&ids[1], t, reg()).unwrap());
    let p = lp.peers[0].commit(m).unwrap().unwrap();
    let pk = lp.peers[0].engine.package(&p).unwrap().unwrap();
    lp.deliver(1, &pk).unwrap();
    let old = Some(Value::Str("old".into()));
    assert_eq!(lp.peers[1].engine.get(&t, &reg()).unwrap(), old, "the writer holding the old body reads it");
    assert_eq!(lp.peers[0].engine.get(&t, &reg()).unwrap(), None, "the compacted node does not");
    lp.sync(1, 0).unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &reg()).unwrap(), None, "nor once it holds what the writer logs, but its re-snapshot");
    lp.peers[1].engine.purge_resnapshots().unwrap();
    assert_eq!(own_snapshots(&lp, t), 1);
    lp.sync(1, 0).unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &reg()).unwrap(), old, "the re-snapshot carries it");
}
