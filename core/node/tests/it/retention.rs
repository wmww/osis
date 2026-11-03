#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Retention, expiry, purge, compaction snapshots and undo (spec/commits.md §5–§7).

use crate::common;
use common::*;
use osis_commit::{Kind, PurgeItem};
use osis_base::{Role, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_node::local_peer::LocalPeer;
use osis_node::{Cause, Event, Mutation};
use osis_schema::Codec;

fn set(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, k: &osis_schema::Aspect<Value>, v: &str) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.set(t, k, &s(v)).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/commits.md §5, spec/crdt.md §4.8: a write dies when superseded, at the superseding
// `ts`; per body the first and last death are kept; keep at least counts from the last.
#[test]
fn deaths_and_bounds_spec_commits_5() {
    let mut lp = net(1, 51);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &KEPT, "one");
    lp.advance(10);
    let c2 = set(&mut lp, 0, t, &KEPT, "two");
    let ts2 = lp.peers[0].engine.header(&c2).unwrap().ts;
    let e = &mut lp.peers[0].engine;
    assert_eq!(e.deaths(&c1, &t, &ak("t:kept.0")).unwrap(), Some((ts2, ts2)));
    assert_eq!(e.deaths(&c2, &t, &ak("t:kept.0")).unwrap(), None);
    let k = e.body_keep(&c1, &t, &ak("t:kept.0")).unwrap();
    assert_eq!(k.at_least, ts2.wall_ms().0 + 86_400_000);
    assert_eq!(k.at_most, None);
    assert!(e.body_not_dropped(&c1, &t, &ak("t:kept.0")));
}

// spec/commits.md §5: keep at most 0 after replaced: the replacing node drops the body in the
// transaction that applies the kill (live state unchanged);
// a dropped body cannot be undone (§7).
// spec/commits.md §5 (keep at most)
#[test]
fn keep_at_most_zero_spec_commits_5() {
    let mut lp = net(2, 52);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &GONE, "draft");
    sync(&mut lp, 0, 1);
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    let e = &mut lp.peers[0].engine;
    assert!(!e.body_not_dropped(&c1, &t, &ak("t:gone.0")));
    assert_eq!(e.get(&t, &ak("t:gone.0")).unwrap(), Some(s("final")));
    assert_eq!(e.revert(&c1).unwrap(), None);
    // every node drops it by the bound, here when it applies the kill
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.body_not_dropped(&c1, &t, &ak("t:gone.0")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:gone.0")).unwrap(), Some(s("final")));
}

// spec/commits.md §6, spec/crdt.md §4.7: at T the delta's values go value-less everywhere and
// its body is dropped; a copy arriving after T is stripped on arrival.
#[test]
fn expiry_spec_commits_6() {
    let mut lp = net(3, 53);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let c = set(&mut lp, 0, t, &BRIEF, "soon gone");
    let h = lp.peers[0].engine.header(&c).unwrap();
    let a = h.aspects.iter().find(|a| a.ak.as_str() == "t:brief.0").unwrap();
    assert_eq!(a.expires, Some(h.ts.wall_ms().0 + 3_600_000));
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:brief.0")).unwrap(), Some(s("soon gone")));
    lp.advance(3_600_001);
    for i in 0..2 {
        lp.peers[i].drain_events();
        lp.peers[i].engine.tick().unwrap();
        assert_eq!(lp.peers[i].engine.get(&t, &ak("t:brief.0")).unwrap(), None, "node {i}");
        assert!(!lp.peers[i].engine.body_not_dropped(&c, &t, &ak("t:brief.0")));
        assert!(lp.peers[i].drain_events().iter().any(|e| matches!(e, Event::Changed { cause: Cause::Expiry, .. })));
    }
    // a late copy (from a relay that still had it) is stripped on arrival
    let pk = osis_node::local_peer::Package { id: c, bytes: lp.peers[1].engine.commit_bytes(&c).unwrap().unwrap(), blobs: Vec::new() };
    sync(&mut lp, 0, 2);
    let _ = lp.deliver(2, &pk);
    assert_eq!(lp.peers[2].engine.get(&t, &ak("t:brief.0")).unwrap(), None);
    // an explicit T on any aspect
    let mut m = Mutation::new();
    let now = lp.peers[0].engine.now();
    m.set(t, &REG, &s("x")).unwrap();
    m.expires(t, &REG, WallMs(now.0 + 1000)).unwrap();
    lp.peers[0].commit(m).unwrap();
    lp.advance(1000);
    lp.peers[0].engine.tick().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), None);
}

// spec/commits.md §5, spec/permissions.md §8: rights are judged per delta in any arrival order:
// a request by the admin arriving before an `author` delta leaves it whole, the author's arriving
// before it drops it on arrival; `nobody` keeps it from both.
#[test]
fn purge_sets_any_order_spec_perm_8() {
    use osis_schema::{PurgeBy, Retention};
    for (by, by_admin, by_author) in [(PurgeBy::Author, false, true), (PurgeBy::Admin, true, false), (PurgeBy::AuthorOrAdmin, true, true), (PurgeBy::Nobody, false, false), (PurgeBy::Writer, true, true)] {
        for (who, dropped) in [(0, by_admin), (1, by_author)] {
            let mut lp = net(3, 55);
            lp.sync_all().unwrap();
            let t = new_thing(&mut lp, 0);
            let b = lp.peers[1].engine.tid();
            set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
            sync(&mut lp, 0, 1);
            lp.advance(5);
            let mut m = Mutation::new();
            m.retention(t, &REG, Retention { by, ..Default::default() }).unwrap();
            m.set(t, &REG, &s("v")).unwrap();
            let c = lp.peers[1].commit(m).unwrap().unwrap();
            let full = lp.peers[1].engine.package(&c).unwrap().unwrap();
            sync(&mut lp, 1, 0);
            lp.advance(5);
            let mut m = Mutation::new();
            m.set(t, &REG, &s("later")).unwrap();
            m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
            let pc = lp.peers[who].commit(m).unwrap().unwrap();
            sync(&mut lp, who, 1 - who);
            let holds = |lp: &mut osis_node::local_peer::LocalPeer, n: usize| lp.peers[n].engine.body_not_dropped(&c, &t, &ak("t:reg.0"));
            assert_eq!((holds(&mut lp, 0), holds(&mut lp, 1)), (!dropped, !dropped), "{by:?} by peer {who}");
            // node 2: the request first, the delta last
            let pks = lp.packages(1).unwrap();
            let pp = pks.iter().find(|p| p.id == pc).unwrap().clone();
            for p in pks.iter().filter(|p| p.id != c && p.id != pc) {
                let _ = lp.deliver(2, p);
            }
            let _ = lp.deliver(2, &pp);
            let _ = lp.deliver(2, &full);
            assert_eq!(holds(&mut lp, 2), !dropped, "{by:?} by peer {who}, request first");
        }
    }
}

// spec/permissions.md §8: rights hold in every arrival order: among the delta, the request and a
// demotion the requester had not heard of. Dropped iff the set holds the requester at the
// request's time; with the demotion last a stale drop falls, the part missing until a copy comes.
#[test]
fn purge_rights_any_arrival_order_spec_perm_8() {
    use osis_schema::{PurgeBy, Retention};
    for by in PurgeBy::ALL {
        // requester: 0 the admin, 1 the author, 2 another writer; demoted: lost write before it asks
        for (who, demoted) in [(0, false), (1, false), (2, false), (1, true), (2, true)] {
            let want = match (who, demoted) {
                (0, _) => by.admin(),
                (1, false) => by.author(),
                (2, false) => by.writer(),
                _ => false,
            };
            const ORDERS: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
            let mut lp = net(3 + ORDERS.len(), 0x51 + by as u64);
            lp.sync_all().unwrap();
            let t = new_thing(&mut lp, 0);
            for i in [1, 2] {
                let n = lp.peers[i].engine.tid();
                set_edge(&mut lp.peers[0].engine, t, n, Some(edge(Role::Write)), None);
            }
            lp.sync_all().unwrap();
            lp.advance(5);
            let mut m = Mutation::new();
            m.retention(t, &REG, Retention { by, ..Default::default() }).unwrap();
            m.set(t, &REG, &s("v")).unwrap();
            let c = lp.peers[1].commit(m).unwrap().unwrap();
            sync(&mut lp, 1, 2);
            sync(&mut lp, 1, 0);
            lp.advance(5);
            let base: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
            let mut late = vec![lp.peers[1].engine.package(&c).unwrap().unwrap()];
            if demoted {
                let n = lp.peers[who].engine.tid();
                let d = set_edge(&mut lp.peers[0].engine, t, n, Some(edge(Role::Read)), None);
                late.push(lp.peers[0].engine.package(&d).unwrap().unwrap());
                lp.advance(5);
            }
            let mut m = Mutation::new();
            m.set(t, &REG, &s("later")).unwrap();
            m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
            let pc = lp.peers[who].commit(m).unwrap().unwrap();
            late.push(lp.peers[who].engine.package(&pc).unwrap().unwrap());
            let pks = lp.packages(0).unwrap();
            for (k, order) in ORDERS.iter().enumerate() {
                let r = 3 + k;
                for p in pks.iter().filter(|p| base.contains(&p.id) && p.id != c) {
                    let _ = lp.deliver(r, p);
                }
                for i in order.iter().filter(|i| **i < late.len()) {
                    let _ = lp.deliver(r, &late[*i]);
                }
                assert_eq!(lp.peers[r].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), !want, "{by:?} by peer {who} demoted {demoted}, order {order:?}");
                // given again it is held by every order alike
                let _ = lp.deliver(r, &late[0]);
                assert!(lp.peers[r].engine.core.ix.commits.get(&c).unwrap().missing.is_empty(), "{by:?} by peer {who} demoted {demoted}, order {order:?}");
            }
        }
    }
}

/// Peers 0 (owner) and the admin or writer `x` (1) and `w` (2) of a new thing, a fresh node 3; `w`'s
/// message `c` and `x`'s request `p` naming it, stamped before 0's demotion of `x`, whose frontier
/// lacks `p`.
struct Backdated {
    lp: LocalPeer,
    t: osis_base::Tid,
    c: osis_base::CommitId,
    p: osis_base::CommitId,
    d: osis_base::CommitId,
}

fn backdated(seed: u64) -> Backdated {
    let mut lp = net(4, seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("kept")).unwrap();
    let c = lp.peers[2].commit(m).unwrap().unwrap();
    sync(&mut lp, 2, 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(5);
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    Backdated { lp, t, c, p, d }
}

impl Backdated {
    /// The commits up to the demotion's, the setup first, to node 3 in `order` (0: `c`, 1: `p`, 2: `d`).
    fn give(&mut self, order: &[usize]) {
        let (c, p, d) = (self.c, self.p, self.d);
        let pks = self.lp.packages(0).unwrap();
        for pk in pks.iter().filter(|pk| ![c, p, d].contains(&pk.id)) {
            let _ = self.lp.deliver(3, pk);
        }
        for i in order {
            let id = [c, p, d][*i];
            // the author first: the requester dropped what it purged
            let pk = [2, 1, 0].iter().find_map(|n| self.lp.peers[*n].engine.package(&id).unwrap()).unwrap();
            let _ = self.lp.deliver(3, &pk);
        }
    }
}

// spec/permissions.md §8: a request a demotion's frontier leaves out, however early its `ts`, holds
// no right: a node holding the demotion drops nothing and shows no purge.
#[test]
fn request_outside_the_frontier_drops_nothing_spec_perm_8() {
    let mut b = backdated(0x61);
    b.give(&[2, 0, 1]);
    let (t, c) = (b.t, b.c);
    let e = &mut b.lp.peers[3].engine;
    assert!(e.body_not_dropped(&c, &t, &ak("t:reg.0")));
    assert_eq!(e.get(&t, &ak("t:reg.0")).unwrap(), Some(s("kept")));
    assert!(e.purged_on(&t, &ak("t:reg.0")).unwrap().is_empty());
}

// spec/commits.md §5: a purge request naming role-class deltas is refused on arrival, signed or not;
// the purge judgments (`retention::purge`) rely on never seeing one.
#[test]
fn forged_role_class_purge_refused_spec_commits_5() {
    let mut lp = net(2, 0x63);
    let t = new_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    let c = set(&mut lp, 0, t, &KEPT, "one");
    lp.advance(1);
    let ts = lp.peers[0].engine.header(&c).unwrap().ts;
    let key = ak("t:kept.0");
    let forged = |lp: &mut LocalPeer, on: &str| {
        let bytes = forge_snapshot(lp, 1, t, &key, ts, osis_crdt::Fragment::default());
        let mut blob = osis_commit::CommitBlob::decode(&bytes).unwrap();
        blob.header.purge = vec![PurgeItem::Aspect { tid: t, ak: ak(on) }];
        blob.signature = blob.header.sign(&lp.peers[1].engine.identity().keys().signing);
        blob.encode()
    };
    let role = forged(&mut lp, "roles.0");
    let err = lp.peers[0].engine.ingest(&role, Vec::new()).unwrap_err();
    assert!(err.to_string().contains("role-class"), "{err}");
    let content = forged(&mut lp, "t:kept.0");
    lp.peers[0].engine.ingest(&content, Vec::new()).unwrap();
}

// spec/permissions.md §8: a node that dropped the body before it heard of the demotion: the purge
// falls, the part counts as never received, and a copy brings the value back; as the order that had
// the demotion first reads.
#[test]
fn fallen_purge_comes_back_spec_perm_8() {
    let mut b = backdated(0x62);
    b.give(&[0, 1]);
    let (t, c, d) = (b.t, b.c, b.d);
    let k = ak("t:reg.0");
    assert!(!b.lp.peers[3].engine.body_not_dropped(&c, &t, &k), "the right holds as far as it knows");
    assert_eq!(b.lp.peers[3].engine.purged_on(&t, &k).unwrap().len(), 1);
    let demote = b.lp.peers[0].engine.package(&d).unwrap().unwrap();
    let _ = b.lp.deliver(3, &demote);
    let e = &mut b.lp.peers[3].engine;
    assert!(e.body_not_dropped(&c, &t, &k));
    assert_eq!(e.core.ix.commits.get(&c).unwrap().missing.len(), 1, "missing until a copy comes");
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("new")), "reads as a node that never received it");
    assert!(e.purged_on(&t, &k).unwrap().is_empty());
    let pk = b.lp.peers[2].engine.package(&c).unwrap().unwrap();
    let _ = b.lp.deliver(3, &pk);
    let e = &mut b.lp.peers[3].engine;
    assert!(e.core.ix.commits.get(&c).unwrap().missing.is_empty());
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("kept")));
    // and it survives an index rebuild
    e.rebuild_index().unwrap();
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("kept")));
}

// spec/permissions.md §8: a demotion that itself falls gives the request its right back: the body
// drops, in either order.
#[test]
fn purge_stands_again_when_its_demotion_falls_spec_perm_8() {
    for fall_last in [true, false] {
        let mut lp = net(5, 0x63 + u64::from(fall_last));
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let (m1, x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
        set_edge(&mut lp.peers[0].engine, t, m1, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("v")).unwrap();
        let c = lp.peers[3].commit(m).unwrap().unwrap();
        sync(&mut lp, 3, 2);
        lp.advance(5);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
        let p = lp.peers[2].commit(m).unwrap().unwrap();
        lp.advance(5);
        // 1 demotes x, unseen by 0, whose demotion of 1 leaves it out of its frontier
        let dx = set_edge(&mut lp.peers[1].engine, t, x, None, None);
        lp.advance(5);
        let dm = set_edge(&mut lp.peers[0].engine, t, m1, None, None);
        let pks = lp.packages(0).unwrap();
        for pk in pks.iter().filter(|pk| pk.id != dm) {
            let _ = lp.deliver(4, pk);
        }
        let by = |lp: &mut LocalPeer, id, n: usize| lp.peers[n].engine.package(id).unwrap().unwrap();
        let (pc, pp, pdx, pdm) = (by(&mut lp, &c, 3), by(&mut lp, &p, 2), by(&mut lp, &dx, 1), by(&mut lp, &dm, 0));
        let order = if fall_last { [pc, pdx, pp, pdm] } else { [pdm, pdx, pc, pp] };
        for (i, pk) in order.iter().enumerate() {
            let _ = lp.deliver(4, pk);
            if fall_last && i == 2 {
                assert!(lp.peers[4].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "x is demoted as far as it knows");
            }
        }
        assert!(!lp.peers[4].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "fall_last {fall_last}");
        assert_eq!(lp.peers[4].engine.purged_on(&t, &ak("t:reg.0")).unwrap().len(), 1);
    }
}

// spec/commits.md §5, spec/permissions.md §8: a snapshot dropped for carrying the purged value comes
// back with the fall, and given again gives the value; the delta itself need not return.
#[test]
fn snapshot_dropped_for_a_fallen_purge_comes_back_spec_perm_8() {
    let mut lp = net(4, 0x66);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let k = ak("t:reg.0");
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("kept")).unwrap();
    let c = lp.peers[2].commit(m).unwrap().unwrap();
    lp.advance(5);
    let snap = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    let (pc, ps) = (lp.peers[2].engine.package(&c).unwrap().unwrap(), lp.peers[2].engine.package(&snap).unwrap().unwrap());
    sync(&mut lp, 2, 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    let pp = lp.peers[1].engine.package(&p).unwrap().unwrap();
    lp.advance(5);
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    let pd = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    for pk in pks.iter().filter(|pk| ![c, snap, p, d].contains(&pk.id)) {
        let _ = lp.deliver(3, pk);
    }
    for pk in [&pc, &ps, &pp] {
        lp.deliver(3, pk).unwrap();
    }
    let e = &mut lp.peers[3].engine;
    assert!(!e.body_not_dropped(&snap, &t, &k) && !e.body_not_dropped(&c, &t, &k));
    lp.deliver(3, &pd).unwrap();
    let e = &mut lp.peers[3].engine;
    let missing = |e: &osis_node::Engine, id| e.core.ix.commits.get(id).unwrap().missing.len();
    assert_eq!((missing(e, &snap), missing(e, &c)), (1, 1));
    lp.deliver(3, &ps).unwrap();
    let e = &mut lp.peers[3].engine;
    assert_eq!(missing(e, &snap), 0);
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("kept")), "the snapshot carries it");
}

// spec/commits.md §5, spec/permissions.md §8: a part held value-less while its commit waits, whose
// request's right falls before it applies: it applies and comes back as any fallen drop.
#[test]
fn stripped_part_of_a_fallen_purge_comes_back_spec_perm_8() {
    let mut lp = net(4, 0x67);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (k, list) = (ak("t:reg.0"), ak("t:list.0"));
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("kept")).unwrap();
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let c = lp.peers[2].commit(m).unwrap().unwrap();
    let pc = lp.peers[2].engine.package(&c).unwrap().unwrap();
    // `c`'s parts as two copies: with the first alone it waits for the second
    let part = |ak: &osis_base::Ak| {
        let mut pk = pc.clone();
        let mut blob = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let ai = blob.header.aspects.iter().position(|a| a.ak == *ak).unwrap();
        blob.parts.retain(|x| x.ai == ai);
        pk.bytes = blob.encode();
        pk
    };
    let (reg_part, list_part) = (part(&k), part(&list));
    sync(&mut lp, 2, 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    m.set(t, &KEPT, &s("beside")).unwrap();
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    let pp = lp.peers[1].engine.package(&p).unwrap().unwrap();
    lp.advance(5);
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    let pd = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let pks = lp.packages(0).unwrap();
    for pk in pks.iter().filter(|pk| ![c, p, d].contains(&pk.id)) {
        let _ = lp.deliver(3, pk);
    }
    lp.peers[3].engine.set_syncing(t, true).unwrap();
    lp.deliver(3, &reg_part).unwrap();
    lp.deliver(3, &pp).unwrap();
    lp.peers[3].engine.reexamine().unwrap();
    assert!(lp.peers[3].engine.pending().iter().any(|x| x.0 == c), "it waits: {:?}", lp.peers[3].engine.pending());
    assert_eq!(lp.peers[3].engine.stripped_count(&c).unwrap(), 1, "held value-less");
    lp.deliver(3, &pd).unwrap();
    lp.deliver(3, &list_part).unwrap();
    lp.peers[3].engine.reexamine().unwrap();
    let e = &mut lp.peers[3].engine;
    assert!(e.pending().is_empty(), "{:?}", e.pending());
    assert!(e.purged_on(&t, &k).unwrap().is_empty());
    assert_eq!(e.core.ix.commits.get(&c).unwrap().missing.len(), 1, "as never received");
    lp.deliver(3, &reg_part).unwrap();
    let e = &mut lp.peers[3].engine;
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("kept")));
}

// spec/commits.md §4: a held request names a missing delta and its right is judged later: the commit
// stops waiting on the signer's standing as a possible holder, not on the right, so the demotion's
// place in the order decides nothing.
#[test]
fn missing_delta_counts_alike_however_the_right_ends_spec_commits_4() {
    use std::collections::BTreeSet;
    let mut applied = BTreeSet::new();
    for demotion_first in [false, true] {
        let mut lp = net(4, 0x65);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let u = new_thing(&mut lp, 0);
        let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        for th in [t, u] {
            set_edge(&mut lp.peers[0].engine, th, x, Some(edge(Role::Admin)), None);
            set_edge(&mut lp.peers[0].engine, th, w, Some(edge(Role::Write)), None);
        }
        lp.sync_all().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.set(t, &REG, &s("a")).unwrap();
        m.set(u, &REG, &s("b")).unwrap();
        let c = lp.peers[2].commit(m).unwrap().unwrap();
        sync(&mut lp, 2, 1);
        lp.advance(5);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
        let p = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(5);
        let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
        let pks = lp.packages(0).unwrap();
        for pk in pks.iter().filter(|pk| ![c, p, d].contains(&pk.id)) {
            let _ = lp.deliver(3, pk);
        }
        lp.peers[3].engine.set_syncing(t, true).unwrap();
        lp.peers[3].engine.set_syncing(u, true).unwrap();
        let (pd, pp) = (lp.peers[0].engine.package(&d).unwrap().unwrap(), lp.peers[1].engine.package(&p).unwrap().unwrap());
        // `c` with only its part on `u`
        let mut only = lp.peers[2].engine.package(&c).unwrap().unwrap();
        let mut blob = osis_commit::CommitBlob::decode(&only.bytes).unwrap();
        blob.parts.retain(|x| blob.header.aspects[x.ai].tid == u);
        only.bytes = blob.encode();
        for pk in if demotion_first { [&pd, &pp, &only] } else { [&only, &pp, &pd] } {
            let _ = lp.deliver(3, pk);
        }
        applied.insert(lp.peers[3].engine.commit_ids().contains(&c));
    }
    assert_eq!(applied, BTreeSet::from([true]), "the commit applies in both orders");
}

// spec/commits.md §5: whether a snapshot may drop a covered body is judged from held data: in every
// arrival order of the body, the snapshot and a demotion of the snapshot's author (admin to
// write before it), every node ends with the same verdict, and the demoted admin no longer has it.
#[test]
fn snapshot_right_any_arrival_order_spec_commits_5() {
    use osis_schema::{PurgeBy, Retention};
    for (by, demoted, want) in [(PurgeBy::AuthorOrAdmin, false, true), (PurgeBy::AuthorOrAdmin, true, false), (PurgeBy::Admin, true, false), (PurgeBy::Writer, true, true), (PurgeBy::Author, false, false), (PurgeBy::Nobody, false, false)] {
        const ORDERS: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        let mut lp = net(3 + ORDERS.len(), 0x71 + by as u64);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        let base: std::collections::BTreeSet<_> = lp.packages(0).unwrap().iter().map(|p| p.id).collect();
        let mut m = Mutation::new();
        m.retention(t, &REG, Retention { by, ..Default::default() }).unwrap();
        m.set(t, &REG, &s("w's")).unwrap();
        let c = lp.peers[2].commit(m).unwrap().unwrap();
        sync(&mut lp, 2, 1);
        lp.advance(5);
        let mut late = vec![lp.peers[2].engine.package(&c).unwrap().unwrap()];
        if demoted {
            let d = set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Write)), None);
            late.push(lp.peers[0].engine.package(&d).unwrap().unwrap());
            lp.advance(5);
        }
        let snap = lp.peers[1].engine.snapshot(&t, &ak("t:reg.0")).unwrap().unwrap();
        late.push(lp.peers[1].engine.package(&snap).unwrap().unwrap());
        let pks = lp.packages(0).unwrap();
        for (k, order) in ORDERS.iter().enumerate() {
            let r = 3 + k;
            for p in pks.iter().filter(|p| base.contains(&p.id)) {
                let _ = lp.deliver(r, p);
            }
            for i in order.iter().filter(|i| **i < late.len()) {
                let _ = lp.deliver(r, &late[*i]);
            }
            let e = &mut lp.peers[r].engine;
            assert_eq!(e.snapshot_right(&snap, &c, &t, &ak("t:reg.0")), want, "{by:?} demoted {demoted}, order {order:?}");
            assert_eq!(e.covered(&snap, &c, &t, &ak("t:reg.0")).unwrap(), Some(true), "{by:?} demoted {demoted}, order {order:?}");
            assert!(e.body_not_dropped(&c, &t, &ak("t:reg.0")));
        }
    }
}

// spec/permissions.md §8: a purge acting for an actor drops only what that actor holds the right
// to, also a delta its node holds later: of an `author` delta of node 1, node 0 (which has write on
// node 1) acting for client C, an admin, drops nothing; acting for itself it drops it.
#[test]
fn purge_for_an_actor_reaches_no_unsynced_delta_spec_perm_8() {
    use osis_schema::{PurgeBy, Retention};
    for (confined, dropped) in [(true, false), (false, true)] {
        let mut lp = net(2, 0x8a);
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let d1 = lp.peers[1].engine.tid();
        let t = new_thing(&mut lp, 0);
        let mut m = Mutation::new();
        let client = lp.peers[0].engine.new_thing(&mut m, me);
        lp.peers[0].commit(m).unwrap();
        set_edge(&mut lp.peers[0].engine, t, d1, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[0].engine, t, client, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[1].engine, d1, me, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        // node 1 writes; node 0 has not heard of it when the request is made
        let mut m = Mutation::new();
        m.retention(t, &REG, Retention { by: PurgeBy::Author, ..Default::default() }).unwrap();
        m.set(t, &REG, &s("node 1's")).unwrap();
        let c = lp.peers[1].commit(m).unwrap().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        if confined {
            m.confine(client);
        }
        m.set(t, &REG, &s("later")).unwrap();
        m.purge(PurgeItem::Aspect { tid: t, ak: ak("t:reg.0") });
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        for n in [0, 1] {
            assert_eq!(lp.peers[n].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), !dropped, "peer {n}, confined {confined}");
        }
    }
}

// spec/commits.md §5, spec/permissions.md §8: a purge request drops the named deltas its author
// may purge, everywhere it applies, and later copies arrive value-less; a writer without the
// right purges nothing.
#[test]
fn purge_spec_commits_5() {
    let mut lp = net(3, 54);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let secret = set(&mut lp, 0, t, &REG, "secret");
    let full = lp.peers[0].engine.package(&secret).unwrap().unwrap();
    sync(&mut lp, 0, 1);
    // b (author retention: only a's chain or an admin may purge a's delta) tries and fails
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("b's")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    lp.peers[1].commit(m).unwrap();
    assert!(lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    // a purges it
    lp.advance(5);
    let mut m = Mutation::new();
    m.set(t, &REG, &s("public")).unwrap();
    m.purge(PurgeItem::Commit { commit: secret, tid: t, ak: ak("t:reg.0") });
    let pc = lp.peers[0].commit(m).unwrap().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    sync(&mut lp, 0, 1);
    assert!(!lp.peers[1].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    // node 2 gets the purge before the purged delta: the delta arrives purged
    let pks = lp.packages(1).unwrap();
    let purge_pk = pks.iter().find(|p| p.id == pc).unwrap().clone();
    for p in pks.iter().filter(|p| p.id != pc && p.id != secret) {
        let _ = lp.deliver(2, p);
    }
    lp.deliver(2, &purge_pk).unwrap();
    // a relay still holding the old full blob
    lp.deliver(2, &full).unwrap();
    assert!(lp.peers[2].engine.commit_ids().contains(&secret));
    assert!(!lp.peers[2].engine.body_not_dropped(&secret, &t, &ak("t:reg.0")));
    for i in 0..3 {
        assert_eq!(lp.peers[i].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("public")), "node {i}");
    }
}

// spec/commits.md §2, §5; spec/crdt.md §8: a compaction snapshot of a node's whole state covers
// every body it applied; a node holding only the snapshot reads the same (a kept set: deaths
// are kept under a relative bound only).
#[test]
fn compaction_snapshot_spec_commits_5() {
    let mut lp = net(2, 55);
    let t = new_thing(&mut lp, 0);
    let mut bodies = Vec::new();
    for i in 0..4 {
        let mut m = Mutation::new();
        m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Add(s(&format!("t{i}"))) }).unwrap();
        bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    }
    let mut m = Mutation::new();
    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Remove(s("t0")) }).unwrap();
    bodies.push(lp.peers[0].commit(m).unwrap().unwrap());
    let snap = lp.peers[0].engine.snapshot(&t, &ak("t:keptset.0")).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&snap).unwrap();
    assert_eq!(h.kind, Kind::ContentSnapshot);
    assert_eq!((h.aspects[0].lo, h.aspects[0].hi), (0, 0));
    assert_eq!(h.aspects[0].retention.by, osis_schema::PurgeBy::Writer);
    for c in &bodies {
        assert_eq!(lp.peers[0].engine.covered(&snap, c, &t, &ak("t:keptset.0")).unwrap(), Some(true));
    }
    // the receiver gets the creation and the snapshot only
    let me0 = lp.peers[0].engine.tid();
    for p in lp.packages(0).unwrap() {
        let h = lp.peers[0].engine.header(&p.id).unwrap();
        let only_tags = h.aspects.iter().all(|a| a.ak.as_str() == "t:keptset.0");
        if !only_tags || p.id == snap || h.author != me0 {
            lp.deliver(1, &p).unwrap();
        }
    }
    let want = lp.peers[0].engine.get(&t, &ak("t:keptset.0")).unwrap();
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:keptset.0")).unwrap(), want);
    // spec/commits.md §5 (deaths per body): a write dying later dies in every body carrying
    // it, the snapshot's included, also where its own body was never held
    lp.advance(10);
    let mut m = Mutation::new();
    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: Op::Remove(s("t1")) }).unwrap();
    let kill = lp.peers[0].commit(m).unwrap().unwrap();
    let ts = lp.peers[0].engine.header(&kill).unwrap().ts;
    for p in lp.packages(0).unwrap() {
        if p.id == kill {
            lp.deliver(1, &p).unwrap();
        }
    }
    for i in 0..2 {
        assert_eq!(lp.peers[i].engine.deaths(&snap, &t, &ak("t:keptset.0")).unwrap(), Some((ts, ts)), "node {i}");
    }
    assert_eq!(lp.peers[0].engine.deaths(&bodies[1], &t, &ak("t:keptset.0")).unwrap(), Some((ts, ts)));
}

// spec/commits.md §7, spec/crdt.md §4.6: revert, redo as a revert of the revert; the held
// commits list them; an admin reverts another's change.
#[test]
fn undo_redo_spec_commits_7() {
    let mut lp = net(2, 56);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    set(&mut lp, 0, t, &REG, "a");
    let c2 = set(&mut lp, 0, t, &REG, "b");
    let mut m = Mutation::new();
    m.op(t, &TAGS, PathOp { path: Vec::new(), op: Op::Add(s("x")) }).unwrap();
    let c3 = lp.peers[0].commit(m).unwrap().unwrap();
    let scope = [(t, ak("t:reg.0")), (t, ak("t:tags.0"))];
    assert_eq!(lp.peers[0].engine.held_commits(Some(&scope))[0].id, c3);
    let u3 = lp.peers[0].engine.revert(&c3).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:tags.0")).unwrap(), None, "exact: the set was absent before");
    let u2 = lp.peers[0].engine.revert(&c2).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("a")));
    let held: Vec<_> = lp.peers[0].engine.held_commits(Some(&scope)).into_iter().map(|c| (c.id, c.header.undoes)).collect();
    assert_eq!(held[..2], [(u2, Some(c2)), (u3, Some(c3))]);
    // redo = undo of the undo commit
    lp.peers[0].engine.revert(&u2).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("b")));
    // undo replicates like any commit
    sync(&mut lp, 0, 1);
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("b")));
    assert_eq!(lp.peers[1].engine.get(&t, &ak("t:tags.0")).unwrap(), None);
    // an admin undoes another's change
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    lp.advance(5);
    let cb = set(&mut lp, 1, t, &REG, "vandal");
    sync(&mut lp, 1, 0);
    assert!(lp.peers[0].engine.held_commits(Some(&scope)).iter().any(|c| c.id == cb && c.header.author == b));
    lp.peers[0].engine.revert(&cb).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("b")));
}

fn big(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid) -> Option<Value> {
    lp.peers[i].engine.tick().unwrap();
    lp.peers[i].engine.get(&t, &ak("t:big.0")).unwrap().filter(|v| *v != Value::Map(Default::default()))
}

/// Node 0 puts `k` into `t:big.0` expiring at `at`, then removes it: the removal.
fn put_removed(lp: &mut osis_node::local_peer::LocalPeer, t: osis_base::Tid, k: &str, at: u64) -> osis_base::CommitId {
    let mut m = Mutation::new();
    m.op(t, &BIG, PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: Op::Put(s("v")) }).unwrap();
    m.expires(t, &BIG, WallMs(at)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let mut m = Mutation::new();
    m.op(t, &BIG, PathOp { path: vec![], op: Op::Remove(s(k)) }).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.6, §4.7 (an undo never extends a value's lifetime past its original expiry):
// undoing the removal of an expiring map entry re-adds it with the entry's expiry, at both
// nodes
#[test]
fn undo_of_removal_keeps_expiry_spec_crdt_4_6() {
    let mut lp = net(2, 57);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let at = lp.peers[0].engine.now().0 + 5_000;
    let rm = put_removed(&mut lp, t, "k", at);
    lp.advance(1_000);
    let u = lp.peers[0].engine.revert(&rm).unwrap().unwrap();
    let h = lp.peers[0].engine.header(&u).unwrap();
    assert_eq!(h.aspects.iter().find(|a| a.ak.as_str() == "t:big.0").and_then(|a| a.expires), Some(at), "the entry's expiry");
    sync(&mut lp, 0, 1);
    let v = Some(Value::Map([(s("k"), s("v"))].into()));
    assert_eq!((big(&mut lp, 0, t), big(&mut lp, 1, t)), (v.clone(), v), "back at both");
    lp.advance(5_000);
    assert_eq!((big(&mut lp, 0, t), big(&mut lp, 1, t)), (None, None), "gone at its expiry");
}

// spec/crdt.md §4.6, §4.7: past the entry's expiry, undoing its removal re-adds nothing
#[test]
fn undo_of_removal_past_expiry_restores_nothing_spec_crdt_4_6() {
    let mut lp = net(2, 58);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let at = lp.peers[0].engine.now().0 + 5_000;
    let rm = put_removed(&mut lp, t, "j", at);
    lp.advance(6_000);
    let _ = lp.peers[0].engine.revert(&rm).unwrap();
    sync(&mut lp, 0, 1);
    assert_eq!((big(&mut lp, 0, t), big(&mut lp, 1, t)), (None, None), "nothing came back");
}

// spec/commits.md §7, spec/crdt.md §4.6 over a paged state (notes/node.md, Paged state): in a new
// session, which loads only the pages it touches, undoing an edit of a key of a large map, an
// edit inside an entry's nested map and a removal restores what a whole state would, and a
// session loading everything reads the same.
#[test]
fn undo_in_lazily_loaded_pages_spec_commits_7() {
    let mut lp = net(1, 58);
    let t = new_thing(&mut lp, 0);
    let fill: std::collections::BTreeMap<Value, Value> = (0..300).map(|i| (s(&format!("k{i:03}")), s(&"v".repeat(300)))).collect();
    let mut m = Mutation::new();
    m.set(t, &BIG, &Value::Map(fill)).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    let key = |k: &str| osis_crdt::PathSeg::Key(s(k));
    let edit = |lp: &mut osis_node::local_peer::LocalPeer, op: PathOp| {
        let mut m = Mutation::new();
        m.op(t, &BIG, op).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    lp.advance(5);
    let c1 = edit(&mut lp, PathOp { path: vec![key("k100")], op: Op::Set(s("changed")) });
    lp.advance(5);
    let c2 = edit(&mut lp, PathOp { path: Vec::new(), op: Op::Remove(s("k200")) });
    lp.advance(5);
    let c3 = edit(&mut lp, PathOp { path: vec![key("new")], op: Op::Set(s("added")) });
    let before = lp.peers[0].engine.get(&t, &ak("t:big.0")).unwrap();
    for (c, k, want) in [(c3, "new", None), (c2, "k200", Some(s(&"v".repeat(300)))), (c1, "k100", Some(s(&"v".repeat(300))))] {
        lp.peers[0].restart(58).unwrap();
        lp.advance(5);
        lp.peers[0].engine.revert(&c).unwrap().unwrap();
        assert_eq!(lp.peers[0].engine.get_at(&t, &ak("t:big.0"), &[key(k)]).unwrap(), want, "undo of {k}");
    }
    // a whole read after the three undos: the fill again
    lp.peers[0].restart(59).unwrap();
    let Some(Value::Map(after)) = lp.peers[0].engine.get(&t, &ak("t:big.0")).unwrap() else { panic!() };
    assert_eq!(after.len(), 300);
    assert!(after.values().all(|v| *v == s(&"v".repeat(300))));
    assert_ne!(Some(Value::Map(after)), before);
}

// spec/commits.md §7, spec/crdt.md §4.6 over a paged state: node 0 edits inside key "n" of a
// large map while node 1 concurrently writes its own entry for "n", which lands on another page.
// In a new session, undoing the edit reads the join of every entry of "n" (the undo replaces
// both), exactly as with the whole state loaded.
#[test]
fn undo_nested_edit_reads_every_entry_of_its_key_spec_commits_7() {
    use std::collections::BTreeMap;
    let run = |whole: bool| {
        let mut lp = net(2, 61);
        let t = new_thing(&mut lp, 0);
        let b = lp.peers[1].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
        let big = ak("x:big.0");
        let key = |k: &str| osis_crdt::PathSeg::Key(s(k));
        let put = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, path: Vec<osis_crdt::PathSeg>, v: Value| {
            let mut m = Mutation::new();
            m.op(t, &big, PathOp { path, op: Op::Set(v) }).unwrap();
            lp.peers[i].commit(m).unwrap().unwrap()
        };
        let mut m = Mutation::new();
        m.set(t, &big, &Value::Map(BTreeMap::new())).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        put(&mut lp, 1, vec![key("n")], Value::Map(BTreeMap::from([(s("b"), s("1"))])));
        let fill = |lp: &mut osis_node::local_peer::LocalPeer, r: std::ops::Range<usize>| {
            let mut m = Mutation::new();
            for i in r {
                m.op(t, &big, PathOp { path: vec![key(&format!("k{i:03}"))], op: Op::Set(s(&"v".repeat(300))) }).unwrap();
            }
            lp.peers[0].commit(m).unwrap().unwrap();
        };
        fill(&mut lp, 0..150);
        put(&mut lp, 0, vec![key("n")], Value::Map(BTreeMap::from([(s("a"), s("0"))])));
        fill(&mut lp, 150..300);
        lp.advance(5);
        let e = put(&mut lp, 0, vec![key("n"), key("a")], s("5"));
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[0].engine.get_at(&t, &big, &[key("n")]).unwrap(), Some(Value::Map(BTreeMap::from([(s("a"), s("5")), (s("b"), s("1"))]))));
        lp.peers[0].restart(61).unwrap();
        if whole {
            lp.peers[0].engine.get(&t, &big).unwrap();
        }
        lp.advance(5);
        lp.peers[0].engine.revert(&e).unwrap().unwrap();
        let n = lp.peers[0].engine.get_at(&t, &big, &[key("n")]).unwrap();
        assert_eq!(n, Some(Value::Map(BTreeMap::from([(s("a"), s("0")), (s("b"), s("1"))]))));
        lp.peers[0].restart(62).unwrap();
        lp.peers[0].engine.state(&t, &big).unwrap()
    };
    assert!(run(false) == run(true), "the undo in a lazily loaded session equals the whole state's");
}

// spec/crdt.md §4.8: two snapshots carry K's write on a kept register; Z kills it, Z2 then Z,
// and the second snapshot, taken after Z2 by a writer that saw neither, carries it again. With
// K's body dropped a recompute meets the write in both snapshots; the second copy is not dated
// again at Z2 (was: the first snapshot's last death at Z2).
#[test]
fn deaths_alike_after_carried_write_dropped_spec_crdt_4_8() {
    let mut lp = net(4, 79);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    let k = ak("t:kept.0");
    lp.advance(10);
    let kc = set(&mut lp, 0, t, &KEPT, "k");
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let z = set(&mut lp, 1, t, &KEPT, "z");
    sync(&mut lp, 1, 0);
    lp.advance(10);
    set(&mut lp, 0, t, &KEPT, "z2");
    lp.advance(10);
    let s2 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    assert!(lp.peers[2].engine.header(&s2).unwrap().aspects[0].retention.at_least.rel.is_some());
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id));
    all.sort_by_key(|p| lp.peers[0].engine.header(&p.id).or_else(|| lp.peers[2].engine.header(&p.id)).unwrap().ts);
    for p in &all {
        lp.deliver(3, p).unwrap();
    }
    let tz = lp.peers[0].engine.header(&z).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tz, tz)));
    e.drop_body(&kc, &t, &k).unwrap();
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tz, tz)));
}

fn map_op(lp: &mut osis_node::local_peer::LocalPeer, i: usize, t: osis_base::Tid, path: Vec<osis_crdt::PathSeg>, v: Value) -> osis_base::CommitId {
    use osis_schema::{Bound, PurgeBy, Retention};
    let mut m = Mutation::new();
    m.retention(t, &MAP, Retention { by: PurgeBy::Writer, at_least: Bound { abs: None, rel: Some(3_600_000) }, at_most: Bound::default() }).unwrap();
    m.op(t, &MAP, PathOp { path, op: Op::Set(v) }).unwrap();
    lp.peers[i].commit(m).unwrap().unwrap()
}

// spec/crdt.md §4.8: on a kept map, B (another writer) and then C write inside A's entry. In
// order, A's field dies at B and B's at C; a replay of every body agrees (was: a replay
// stripped B's and C's writes as copies of A's entry, so B had no death and A's died at C).
#[test]
fn deaths_alike_nested_in_others_entry_spec_crdt_4_8() {
    use osis_crdt::PathSeg;
    let mut lp = net(2, 80);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    lp.advance(10);
    let a = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k"))], item("x", 1));
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let b = map_op(&mut lp, 1, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(2));
    sync(&mut lp, 1, 0);
    lp.advance(10);
    let c = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(3));
    let k = ak("t:map.0");
    let e = &mut lp.peers[0].engine;
    let (tb, tc) = (e.header(&b).unwrap().ts, e.header(&c).unwrap().ts);
    let want = (e.deaths(&a, &t, &k).unwrap(), e.deaths(&b, &t, &k).unwrap());
    assert_eq!(want, (Some((tb, tb)), Some((tc, tc))));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!((e.deaths(&a, &t, &k).unwrap(), e.deaths(&b, &t, &k).unwrap()), want);
}

// spec/crdt.md §4.8, §8: a snapshot's copy of a write nested in an entry another held commit
// created (a put into the key's live entry) supersedes that commit's write there; delivered the
// snapshot first, the late creator dies on arrival at the carried write, as in a recompute (was:
// a window dropped the entry's content with the creator's copies, order seed 7233).
#[test]
fn late_entry_creator_dies_at_carried_nested_write_spec_crdt_4_8() {
    let mut lp = net(2, 84);
    let t = new_thing(&mut lp, 0);
    let k = ak("t:gonemap.0");
    let put = |lp: &mut osis_node::local_peer::LocalPeer, v: &str| {
        let mut m = Mutation::new();
        m.op(t, &GONEMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s("a"))], op: Op::Set(s(v)) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    };
    let a = put(&mut lp, "one");
    lp.advance(10);
    let b = put(&mut lp, "two");
    let tb = lp.peers[0].engine.header(&b).unwrap().ts;
    lp.advance(10);
    lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    assert_eq!(lp.peers[0].engine.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
    for p in packages(&mut lp, 0).iter().filter(|p| p.id != a && p.id != b) {
        lp.deliver(1, p).unwrap();
    }
    let pa = packages(&mut lp, 0).into_iter().find(|p| p.id == a).unwrap();
    lp.deliver(1, &pa).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.body_not_dropped(&a, &t, &k));
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tb, tb)));
}

// spec/crdt.md §4.8, §8: on a kept map X (never held here) writes inside A's entry and a
// snapshot carries it; Y, later, writes there too. A's field dies at X in a replay of every body
// (was: the replay dropped X's copy with A's entry and dated it at Y; the state at the end no
// longer holds X's write).
#[test]
fn replay_dates_at_carried_write_in_held_entry_spec_crdt_4_8() {
    use osis_crdt::PathSeg;
    let mut lp = net(4, 87);
    let t = new_thing(&mut lp, 0);
    for i in [1, 2] {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    sync(&mut lp, 0, 2);
    let k = ak("t:map.0");
    lp.advance(10);
    let a = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k"))], item("a", 1));
    sync(&mut lp, 0, 2);
    lp.advance(10);
    let x = map_op(&mut lp, 2, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(2));
    lp.advance(10);
    let s1 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let y = map_op(&mut lp, 0, t, vec![PathSeg::Key(s("k")), PathSeg::Field(1)], Value::Int(3));
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id) && p.id != x);
    for p in &all {
        lp.deliver(3, p).unwrap();
    }
    let tx = lp.peers[2].engine.header(&x).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    assert!(e.header(&x).is_none() && e.body_not_dropped(&s1, &t, &k) && e.body_not_dropped(&y, &t, &k));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&a, &t, &k).unwrap(), Some((tx, tx)));
}

// spec/commits.md §5, spec/crdt.md §4.8 (deaths dated per node): X < Y < Z on a kept register and
// on a keep-at-most-10m one. In order X dies at Y; delivered Z first, X dies at Z (the first
// superseder this node held) and stays so when Y comes, never earlier than Y, the earliest:
// keep at least counts from Z there, and keep at most too, so within D of learning of Z. A node
// learning of them past Z's bound drops the dead bodies on arrival.
#[test]
fn deaths_dated_from_first_superseder_held_spec_commits_5() {
    for (k, name) in [(&KEPT, "t:kept.0"), (&SHORT, "t:short.0")] {
        let kept = name == "t:kept.0";
        let mut lp = net(4, 54);
        let t = new_thing(&mut lp, 0);
        let mut ids = Vec::new();
        for v in ["one", "two", "three"] {
            ids.push(set(&mut lp, 0, t, k, v));
            lp.advance(10);
        }
        let ts: Vec<_> = ids.iter().map(|c| lp.peers[0].engine.header(c).unwrap().ts).collect();
        let a = ak(name);
        assert_eq!(lp.peers[0].engine.deaths(&ids[0], &t, &a).unwrap(), Some((ts[1], ts[1])));
        let pks = packages(&mut lp, 0);
        let pk = |c: &osis_base::CommitId| pks.iter().find(|p| p.id == *c).unwrap().clone();
        let rest: Vec<_> = pks.iter().filter(|p| !ids.contains(&p.id)).cloned().collect();
        for (to, order) in [(1, [0, 2, 1]), (2, [2, 1, 0])] {
            for p in &rest {
                lp.deliver(to, p).unwrap();
            }
            for i in order {
                lp.deliver(to, &pk(&ids[i])).unwrap();
            }
            let e = &mut lp.peers[to].engine;
            for x in &ids[..2] {
                assert_eq!(e.deaths(x, &t, &a).unwrap(), Some((ts[2], ts[2])), "node {to} {name}");
                let keep = e.body_keep(x, &t, &a).unwrap();
                if kept {
                    assert_eq!(keep.at_least, ts[2].wall_ms().0 + 86_400_000, "node {to}");
                } else {
                    assert_eq!(keep.at_most, Some(ts[2].wall_ms().0 + 600_000), "node {to}");
                    assert!(keep.at_most.unwrap() <= e.now().0 + 600_000, "within D of learning");
                }
            }
            assert_eq!(e.deaths(&ids[2], &t, &a).unwrap(), None);
        }
        lp.advance(3_600_000);
        for p in &pks {
            lp.deliver(3, p).unwrap();
        }
        let e = &mut lp.peers[3].engine;
        for x in &ids[..2] {
            assert_eq!(e.body_not_dropped(x, &t, &a), kept, "node 3 {name}");
        }
        assert_eq!(e.get(&t, &a).unwrap(), Some(s("three")));
    }
}

// spec/commits.md §5 (keep at most 0): a write arriving after the write that replaced it dies on
// arrival, and its body drops in the transaction applying it.
#[test]
fn keep_at_most_zero_late_body_dropped_on_arrival_spec_commits_5() {
    let mut lp = net(2, 56);
    let t = new_thing(&mut lp, 0);
    let c1 = set(&mut lp, 0, t, &GONE, "draft");
    let p1 = packages(&mut lp, 0).into_iter().find(|p| p.id == c1).unwrap();
    lp.advance(5);
    set(&mut lp, 0, t, &GONE, "final");
    for p in packages(&mut lp, 0).iter().filter(|p| p.id != c1) {
        lp.deliver(1, p).unwrap();
    }
    lp.deliver(1, &p1).unwrap();
    let e = &mut lp.peers[1].engine;
    assert!(e.header(&c1).is_some() && !e.body_not_dropped(&c1, &t, &ak("t:gone.0")));
    assert_eq!(e.get(&t, &ak("t:gone.0")).unwrap(), Some(s("final")));
}

// spec/commits.md §5 (keep at most: a tombstone is no live write): a compaction snapshot carrying a
// keep-at-most map entry, then the entry removed. The tombstone left is keyed by the entry's dot
// but holds the remover's reset, so the snapshot has no live write: under at most 0 it drops with
// the removal; under 10m, held, it is due at the removal plus 10m with no grace; dropped live
// before the removal, it is live no more.
#[test]
fn snapshot_of_removed_entry_no_live_write_spec_commits_5() {
    use osis_crdt::PathSeg;
    for (k, name, zero, dropped) in [(&GONEMAP, "t:gonemap.0", true, false), (&SHORTMAP, "t:shortmap.0", false, false), (&SHORTMAP, "t:shortmap.0", false, true)] {
        let mut lp = net(1, 57);
        let t = new_thing(&mut lp, 0);
        let a = ak(name);
        let mut m = Mutation::new();
        m.op(t, k, PathOp { path: vec![PathSeg::Key(s("k1"))], op: Op::Set(s("v")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.advance(5);
        let snap = lp.peers[0].engine.snapshot(&t, &a).unwrap().unwrap();
        lp.advance(5);
        let e = &mut lp.peers[0].engine;
        assert!(e.body_live(&snap, &t, &a).unwrap(), "carries the entry");
        if dropped {
            e.drop_body(&snap, &t, &a).unwrap();
            assert!(!e.body_not_dropped(&snap, &t, &a) && e.body_live(&snap, &t, &a).unwrap(), "dropped live");
        }
        let mut m = Mutation::new();
        m.op(t, k, PathOp { path: Vec::new(), op: Op::Remove(s("k1")) }).unwrap();
        let rm = lp.peers[0].commit(m).unwrap().unwrap();
        let e = &mut lp.peers[0].engine;
        if zero {
            assert!(!e.body_not_dropped(&snap, &t, &a), "dropped with the removal");
        } else if dropped {
            assert!(!e.body_live(&snap, &t, &a).unwrap(), "dropped live, live no more");
        } else {
            assert!(e.body_not_dropped(&snap, &t, &a) && !e.body_live(&snap, &t, &a).unwrap(), "held, no live write");
            let ts = e.header(&rm).unwrap().ts;
            assert_eq!(e.body_keep(&snap, &t, &a).unwrap().at_most, Some(ts.wall_ms().0 + 600_000), "no grace");
        }
    }
}

// spec/commits.md §5, spec/crdt.md §4.8 (deaths dated per node, never early): random histories
// on a kept register, a kept set, a kept map and a keep-at-most-10m register by four writers
// with compaction snapshots (peer 3's writes reach node 4 only as snapshot copies, some others'
// never), delivered to node 4 in a random order with snapshots and writes dropped as they come
// and recomputes batched. Node 5 takes the same commits keeping every body (`keep_bodies`) and
// recomputes: each write's earliest superseder. Every body node 4 holds is dated no earlier:
// a body with writes of its own dies iff node 5's does, first and last no earlier; a snapshot's
// last death no earlier. Seeds 0..24; more in `_large`.
#[test]
fn deaths_never_early_random_spec_commits_5() {
    let seeds: Vec<u64> = (0..24).collect();
    osis_base::testenv::run_seeds("retention::deaths_never_early_random_spec_commits_5", &seeds, false, dating_replay, dating_history);
}

/// Seeds: OSIS_STRAYS_START, OSIS_STRAYS_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn deaths_never_early_random_large() {
    osis_base::testenv::Seeds::from_env("OSIS_STRAYS_START", "OSIS_STRAYS_SEEDS", 0..200).run("retention::deaths_never_early_random_large", dating_replay, dating_history);
}

fn dating_replay(s: u64) -> String {
    format!("OSIS_STRAYS_START={s} OSIS_STRAYS_SEEDS=1 cargo test --workspace --test it retention::deaths_never_early_random_large -- --ignored --exact")
}

/// One history of `deaths_never_early_random_*`.
fn dating_history(seed: u64) {
    use osis_crdt::PathSeg;
    let mut r = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    let mut lp = net(6, 1000 + seed);
    lp.peers[5].engine.keep_bodies(true);
    let t = new_thing(&mut lp, 0);
    for i in 1..4 {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    for i in 1..5 {
        sync(&mut lp, 0, i);
    }
    let aks = [ak("t:kept.0"), ak("t:keptset.0"), ak("t:map.0"), ak("t:short.0")];
    let (mut writes, mut snaps) = (Vec::new(), Vec::new());
    for _ in 0..28 {
        let x = below(100);
        let i = below(4) as usize;
        if x < 55 {
            let v = format!("v{}", below(3));
            let mut m = Mutation::new();
            match below(4) {
                0 => {
                    m.set(t, &KEPT, &s(&v)).unwrap();
                }
                1 => {
                    m.op(t, &KEPTSET, PathOp { path: Vec::new(), op: if below(3) == 0 { Op::Remove(s(&v)) } else { Op::Add(s(&v)) } }).unwrap();
                }
                2 => {
                    let keep = osis_schema::Retention { by: osis_schema::PurgeBy::Writer, at_least: osis_schema::Bound { abs: None, rel: Some(3_600_000) }, at_most: osis_schema::Bound::default() };
                    m.retention(t, &MAP, keep).unwrap();
                    m.op(t, &MAP, PathOp { path: vec![PathSeg::Key(s(&v))], op: Op::Set(item("e", below(9) as i64)) }).unwrap();
                }
                _ => {
                    m.set(t, &SHORT, &s(&v)).unwrap();
                }
            }
            // a remove of nothing writes no commit
            if let Some(c) = lp.peers[i].commit(m).unwrap() {
                writes.push((i, c));
            }
        } else if x < 72 {
            let j = below(4) as usize;
            if j != i {
                sync(&mut lp, i, j);
            }
        } else if x < 88 {
            let a = below(aks.len() as u64) as usize;
            if let Some(c) = lp.peers[i].engine.snapshot(&t, &aks[a]).unwrap() {
                snaps.push((c, a));
            }
        }
        lp.advance(1 + below(12));
    }
    let mut all = Vec::new();
    for i in 0..4 {
        all.extend(packages(&mut lp, i));
    }
    let mut seen = std::collections::BTreeSet::new();
    let withheld: std::collections::BTreeSet<osis_base::CommitId> = writes.iter().filter(|(i, _)| *i == 3 || below(7) == 0).map(|x| x.1).collect();
    let held: Vec<_> = all.iter().filter(|p| seen.insert(p.id) && !withheld.contains(&p.id)).cloned().collect();
    for p in &held {
        let _ = lp.deliver(5, p);
    }
    // a recompute plays a carried write whose own commit is not held at its snapshot: node 5
    // takes those commits too (each writes one aspect), so it plays every write at its own `ts`
    let carried: std::collections::BTreeSet<(osis_base::Tid, osis_base::Ak, osis_crdt::Dot)> = aks.iter().flat_map(|a| lp.peers[5].engine.carried_dots(&t, a).into_iter().map(|d| (t, a.clone(), d))).collect();
    let header = |lp: &osis_node::local_peer::LocalPeer, c: &osis_base::CommitId| (0..4).find_map(|i| lp.peers[i].engine.header(c));
    let extra: Vec<_> = all.iter().filter(|p| withheld.contains(&p.id) && header(&lp, &p.id).is_some_and(|h| crate::common::owns_carried(&h, &p.id, &carried))).cloned().collect();
    for p in &extra {
        let _ = lp.deliver(5, p);
    }
    let mut all = held;
    all.retain(|p| lp.peers[4].engine.header(&p.id).is_none());
    let mode = below(3);
    if mode != 1 {
        for i in (1..all.len()).rev() {
            all.swap(i, below(i as u64 + 1) as usize);
        }
        if mode == 2 {
            // snapshots first: they drop before any body older than them arrives
            all.sort_by_key(|p| !snaps.iter().any(|x| x.0 == p.id));
        }
    } else {
        // newest first, roughly: superseders drop before older bodies arrive
        let ts = |lp: &osis_node::local_peer::LocalPeer, c: &osis_base::CommitId| (0..4).find_map(|i| lp.peers[i].engine.header(c)).map(|h| h.ts);
        all.sort_by_key(|p| std::cmp::Reverse(ts(&lp, &p.id)));
        let n = all.len();
        for _ in 0..n / 3 {
            let i = below(n as u64) as usize;
            all.swap(i, (i + 1).min(n - 1));
        }
    }
    let mut deferred = false;
    for p in &all {
        if below(4) == 0 {
            deferred = !deferred;
            lp.peers[4].engine.defer_deaths(deferred).unwrap();
        }
        let _ = lp.deliver(4, p);
        let e = &mut lp.peers[4].engine;
        if let Some(&(c, a)) = snaps.iter().find(|x| x.0 == p.id)
            && below(3) == 0
            && e.body_not_dropped(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(5) == 0
            && let Some(&(c, a)) = snaps.get(below(snaps.len().max(1) as u64) as usize)
            && e.body_not_dropped(&c, &t, &aks[a])
        {
            e.drop_body(&c, &t, &aks[a]).unwrap();
        }
        if below(12) == 0
            && let Some(&(_, c)) = writes.get(below(writes.len() as u64) as usize)
        {
            for a in &aks {
                if e.body_not_dropped(&c, &t, a) {
                    e.drop_body(&c, &t, a).unwrap();
                }
            }
        }
    }
    lp.peers[4].engine.defer_deaths(false).unwrap();
    for a in &aks {
        lp.peers[5].engine.replay_deaths(&t, a).unwrap();
    }
    let ids: Vec<(osis_base::CommitId, bool)> = writes.iter().map(|x| (x.1, false)).chain(snaps.iter().map(|x| (x.0, true))).filter(|(c, _)| lp.peers[4].engine.header(c).is_some()).collect();
    for a in &aks {
        for (c, snap) in &ids {
            if !lp.peers[4].engine.body_not_dropped(c, &t, a) {
                continue;
            }
            let x = lp.peers[4].engine.deaths(c, &t, a).unwrap();
            let y = lp.peers[5].engine.deaths(c, &t, a).unwrap();
            // a snapshot's writes die for it no earlier than its `ts` (a write already dead when
            // it was taken, its superseder unseen by its author, at its `ts`)
            let after = |x: (osis_base::Ts, osis_base::Ts)| lp.peers[4].engine.header(c).is_some_and(|h| x.0 >= h.ts);
            let ok = match (x, y, snap) {
                (Some(x), Some(y), false) => x.0 >= y.0 && x.1 >= y.1,
                (None, None, _) => true,
                (Some(x), Some(y), true) => after(x) && x.1 >= y.1,
                _ => false,
            };
            assert!(ok, "seed {seed} {a:?} {c:?} (snapshot {snap}): here {x:?}, earliest superseders {y:?}");
        }
    }
}

// spec/commits.md §5 (deaths of carried writes): a commit-form write and an import's write (dot
// `Commit(origin)`) on a kept register, each carried by a later snapshot, die at their superseder
// for their own body and the snapshot alike, by joins and in a recompute (was: neither the
// import's body nor the snapshot got a death, so both were past keep at least).
#[test]
fn commit_form_and_import_deaths_dated_spec_commits_5() {
    let mut lp = net(1, 91);
    let t = new_thing(&mut lp, 0);
    let me = lp.peers[0].engine.tid();
    let k = ak("t:kept.0");
    let mut m = Mutation::new();
    m.commit_form();
    m.set(t, &KEPT, &s("one")).unwrap();
    let w = lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, me).unwrap();
    let imp = *imports.iter().find(|i| lp.peers[0].engine.header(i).is_some_and(|h| h.aspects.iter().any(|a| a.ak == k))).unwrap();
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let s2 = lp.peers[0].engine.snapshot(&copy, &k).unwrap().unwrap();
    lp.advance(10);
    let w2 = set(&mut lp, 0, t, &KEPT, "two");
    let c2 = set(&mut lp, 0, copy, &KEPT, "two");
    let e = &mut lp.peers[0].engine;
    let (t2, tc) = (e.header(&w2).unwrap().ts, e.header(&c2).unwrap().ts);
    let want = [Some((t2, t2)), Some((t2, t2)), Some((tc, tc)), Some((tc, tc))];
    let got = |e: &mut osis_node::Engine| [e.deaths(&w, &t, &k).unwrap(), e.deaths(&s1, &t, &k).unwrap(), e.deaths(&imp, &copy, &k).unwrap(), e.deaths(&s2, &copy, &k).unwrap()];
    assert_eq!(got(e), want);
    e.replay_deaths(&t, &k).unwrap();
    e.replay_deaths(&copy, &k).unwrap();
    assert_eq!(got(e), want, "recompute");
}

// spec/commits.md §5 (a snapshot's writes die for it no earlier than its `ts`): S, taken after K
// but without it, carries W; K kills W; S2 carries K; K2 beats K. K's own body dropped, the
// recompute finds the kill of W by K in S2 (its frontier holds K) and dates S at its `ts` (was:
// the state names K2 as W's killer, so S got no death).
#[test]
fn snapshot_dated_through_superseders_snapshot_spec_commits_5() {
    let mut lp = net(3, 92);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let k = ak("t:kept.0");
    let w = set(&mut lp, 0, t, &KEPT, "w");
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let kk = set(&mut lp, 1, t, &KEPT, "k");
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let s2 = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set(&mut lp, 1, t, &KEPT, "k2");
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id));
    for p in &all {
        lp.deliver(2, p).unwrap();
    }
    let ts1 = lp.peers[0].engine.header(&s1).unwrap().ts;
    let e = &mut lp.peers[2].engine;
    assert!(e.body_not_dropped(&w, &t, &k) && e.body_not_dropped(&s2, &t, &k));
    e.drop_body(&kk, &t, &k).unwrap();
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((ts1, ts1)));
}

// spec/commits.md §5 (a snapshot's writes die for it no earlier than its `ts`): as above with K
// commit-form, so S2 holds it through `Absorbed`, not its frontier. K's own body dropped, the
// recompute finds the kill of W by K in S2 and dates S at its `ts` (was: only a frontier counted
// as holding K, so the state named K2 and S got no death).
#[test]
fn snapshot_dated_through_commit_form_superseder_spec_commits_5() {
    let mut lp = net(3, 93);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let k = ak("t:kept.0");
    let w = set(&mut lp, 0, t, &KEPT, "w");
    sync(&mut lp, 0, 1);
    lp.advance(10);
    let mut m = Mutation::new();
    m.commit_form();
    m.set(t, &KEPT, &s("k")).unwrap();
    let kk = lp.peers[1].commit(m).unwrap().unwrap();
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let s2 = lp.peers[1].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    set(&mut lp, 1, t, &KEPT, "k2");
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 1));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| seen.insert(p.id));
    for p in &all {
        lp.deliver(2, p).unwrap();
    }
    let ts1 = lp.peers[0].engine.header(&s1).unwrap().ts;
    let e = &mut lp.peers[2].engine;
    assert!(e.body_not_dropped(&w, &t, &k) && e.body_not_dropped(&s2, &t, &k));
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((ts1, ts1)));
    e.drop_body(&kk, &t, &k).unwrap();
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((ts1, ts1)), "recompute");
}

// spec/commits.md §5 (deaths of carried writes): a snapshot S of a moved thing carries an
// import's write (dot `Commit(origin)`) and lists the import in `Absorbed`; a node holding S but
// not the import's header still dates S at the write's superseder, by joins and in a recompute
// (was: the import could not be mapped to its origin, so S got no death).
#[test]
fn snapshot_of_unheld_import_dated_spec_commits_5() {
    let mut lp = net(2, 94);
    let t = new_thing(&mut lp, 0);
    let me = lp.peers[0].engine.tid();
    let k = ak("t:kept.0");
    let mut m = Mutation::new();
    m.commit_form();
    m.set(t, &KEPT, &s("one")).unwrap();
    lp.peers[0].commit(m).unwrap().unwrap();
    lp.advance(10);
    let (copy, imports) = lp.peers[0].engine.move_thing(&t, me).unwrap();
    let imp = *imports.iter().find(|i| lp.peers[0].engine.header(i).is_some_and(|h| h.aspects.iter().any(|a| a.ak == k))).unwrap();
    lp.advance(10);
    let s2 = lp.peers[0].engine.snapshot(&copy, &k).unwrap().unwrap();
    lp.advance(10);
    let c2 = set(&mut lp, 0, copy, &KEPT, "two");
    let all = packages(&mut lp, 0);
    for p in all.iter().filter(|p| p.id != imp) {
        let _ = lp.deliver(1, p);
    }
    let tc = lp.peers[0].engine.header(&c2).unwrap().ts;
    let e = &mut lp.peers[1].engine;
    assert!(e.header(&imp).is_none() && e.body_not_dropped(&s2, &copy, &k));
    assert_eq!(e.deaths(&s2, &copy, &k).unwrap(), Some((tc, tc)));
    e.replay_deaths(&copy, &k).unwrap();
    assert_eq!(e.deaths(&s2, &copy, &k).unwrap(), Some((tc, tc)), "recompute");
}

// spec/commits.md §5 (deaths of carried writes): a snapshot S whose author applied W while an
// earlier write X of W's author on the aspect never arrived (a late part) carries W past its
// frontier; K kills W at a node holding S but not W's commit, and S dies at K, by joins and in a
// recompute (was: only the frontier counted, so S got no death).
#[test]
fn snapshot_carrying_write_past_frontier_dated_spec_commits_5() {
    let mut lp = net(4, 95);
    let t = new_thing(&mut lp, 0);
    for i in 1..3 {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    lp.sync_all().unwrap();
    let k = ak("t:kept.0");
    let mut m = Mutation::new();
    m.set(t, &KEPT, &s("x")).unwrap();
    m.set(t, &REG, &s("r")).unwrap();
    let x = lp.peers[1].commit(m).unwrap().unwrap();
    let h = lp.peers[1].engine.header(&x).unwrap();
    let mut b = osis_commit::CommitBlob::decode(&lp.peers[1].engine.package(&x).unwrap().unwrap().bytes).unwrap();
    b.parts.retain(|p| h.aspects[p.ai].ak != k);
    lp.peers[0].engine.set_syncing(t, true).unwrap();
    lp.peers[0].engine.ingest(&b.encode(), Vec::new()).unwrap();
    lp.advance(3_600_001);
    lp.peers[0].engine.tick().unwrap();
    let w = set(&mut lp, 1, t, &KEPT, "w");
    let wp = lp.peers[1].engine.package(&w).unwrap().unwrap();
    lp.deliver(0, &wp).unwrap();
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), Some(s("w")));
    lp.deliver(2, &wp).unwrap();
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    lp.advance(10);
    let kk = set(&mut lp, 2, t, &KEPT, "k");
    let mut all = packages(&mut lp, 0);
    all.extend(packages(&mut lp, 2));
    let mut seen = std::collections::BTreeSet::new();
    all.retain(|p| p.id != w && p.id != x && seen.insert(p.id));
    for p in &all {
        let _ = lp.deliver(3, p);
    }
    let tk = lp.peers[2].engine.header(&kk).unwrap().ts;
    let e = &mut lp.peers[3].engine;
    assert!(e.header(&w).is_none() && e.body_not_dropped(&s1, &t, &k));
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tk, tk)));
    e.replay_deaths(&t, &k).unwrap();
    assert_eq!(e.deaths(&s1, &t, &k).unwrap(), Some((tk, tk)), "recompute");
}

// spec/crdt.md §4.6 Expiry, §4.7 (an undo never extends a value's lifetime past its original
// expiry): random histories of three writers on a map, a set, a list, a text, a register and
// a map of structs (puts, removes, nested edits, inserts, deletes; most with a random expiry),
// undos and redos of any held commit by any node (its own from the undo buffer, others' from
// held bodies), syncs and time passing. Every written value is unique; after each step no node
// reads one past the expiry of the write that first wrote it. Seeds 0..24; more in `_large`.
#[test]
fn undo_never_outlives_expiry_random_spec_crdt_4_6() {
    let seeds: Vec<u64> = (0..24).collect();
    osis_base::testenv::run_seeds("retention::undo_never_outlives_expiry_random_spec_crdt_4_6", &seeds, false, undo_replay, undo_expiry_history);
}

/// Seeds: OSIS_UNDOEXP_START, OSIS_UNDOEXP_SEEDS (default 0..200).
#[test]
#[ignore = "tier 2"]
fn undo_never_outlives_expiry_random_large() {
    osis_base::testenv::Seeds::from_env("OSIS_UNDOEXP_START", "OSIS_UNDOEXP_SEEDS", 0..200).run("retention::undo_never_outlives_expiry_random_large", undo_replay, undo_expiry_history);
}

fn undo_replay(s: u64) -> String {
    format!("OSIS_UNDOEXP_START={s} OSIS_UNDOEXP_SEEDS=1 cargo test --workspace --test it retention::undo_never_outlives_expiry_random_large -- --ignored --exact")
}

/// One history of `undo_never_outlives_expiry_random_*`.
fn undo_expiry_history(seed: u64) {
    use osis_crdt::PathSeg;
    use std::collections::BTreeMap;
    let mut r = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut below = |n: u64| {
        r ^= r << 13;
        r ^= r >> 7;
        r ^= r << 17;
        r % n
    };
    let mut lp = net(3, 2000 + seed);
    let t = new_thing(&mut lp, 0);
    for i in 1..3 {
        let p = lp.peers[i].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
    }
    for i in 1..3 {
        sync(&mut lp, 0, i);
    }
    let aks = [ak("t:big.0"), ak("t:tags.0"), ak("t:list.0"), ak("t:text.0"), ak("t:reg.0"), ak("t:map.0")];
    // each value written (`m<n>`, a text's char `<n>`) and its write's expiry
    let mut expiry: BTreeMap<String, Option<u64>> = BTreeMap::new();
    let mut commits = Vec::new();
    let mut n = 0u32;
    // the tracked values a read shows
    fn values(v: &Value, text: bool, out: &mut Vec<String>) {
        match v {
            Value::Str(x) if text => out.extend(x.chars().map(String::from)),
            Value::Str(x) => out.push(x.clone()),
            Value::Map(m) => m.values().for_each(|v| values(v, text, out)),
            Value::List(l) => l.iter().for_each(|v| values(v, text, out)),
            Value::Set(s) => s.iter().for_each(|v| values(v, text, out)),
            _ => {}
        }
    }
    let mut log = Vec::new();
    for step in 0..100 {
        let x = below(100);
        let i = below(3) as usize;
        if x < 50 {
            let now = lp.peers[i].engine.now().0;
            let exp = (below(10) < 6).then(|| now + 1 + below(8_000));
            n += 1;
            let a = below(aks.len() as u64) as usize;
            let mark = if a == 3 { char::from_u32(0x4e00 + n).unwrap().to_string() } else { format!("m{n}") };
            let cur = lp.peers[i].engine.get(&t, &aks[a]).unwrap();
            let len = match &cur {
                Some(Value::List(l)) => l.len(),
                Some(Value::Str(x)) => x.chars().count(),
                _ => 0,
            };
            let key = s(&format!("k{}", below(3)));
            let rm = below(3) == 0;
            let op = |path: Vec<PathSeg>, op: Op| PathOp { path, op };
            let (k, po) = match a {
                0 if rm => (&BIG, op(vec![], Op::Remove(key))),
                0 => (&BIG, op(vec![PathSeg::Key(key)], Op::Put(s(&mark)))),
                1 if rm => {
                    let mut vs = Vec::new();
                    if let Some(v) = &cur {
                        values(v, false, &mut vs);
                    }
                    let Some(v) = vs.get(below(vs.len().max(1) as u64) as usize) else { continue };
                    (&TAGS, op(vec![], Op::Remove(s(v))))
                }
                1 => (&TAGS, op(vec![], Op::Add(s(&mark)))),
                2 | 3 if rm && len > 0 => (if a == 2 { &LIST } else { &TEXT }, op(vec![], Op::Delete { at: below(len as u64) as usize, len: 1 })),
                2 => (&LIST, op(vec![], Op::Insert { at: below(len as u64 + 1) as usize, items: vec![s(&mark)] })),
                3 => (&TEXT, op(vec![], Op::Insert { at: below(len as u64 + 1) as usize, items: vec![s(&mark)] })),
                4 => (&REG, op(vec![], Op::Set(s(&mark)))),
                _ if rm => (&MAP, op(vec![], Op::Remove(key))),
                _ if below(2) == 0 && matches!(&cur, Some(Value::Map(m)) if m.contains_key(&key)) => (&MAP, op(vec![PathSeg::Key(key), PathSeg::Field(0)], Op::Set(s(&mark)))),
                _ => (&MAP, op(vec![PathSeg::Key(key)], Op::Put(item(&mark, 0)))),
            };
            let mut m = Mutation::new();
            m.op(t, k, po.clone()).unwrap();
            if let Some(e) = exp {
                m.expires(t, k, WallMs(e)).unwrap();
            }
            expiry.insert(mark.clone(), exp);
            if let Ok(Some(c)) = lp.peers[i].commit(m) {
                log.push(format!("{step}: node {i} {po:?} expires {exp:?} at {now}: {c:?}"));
                commits.push(c);
            }
        } else if x < 70 {
            let Some(&c) = commits.get(below(commits.len().max(1) as u64) as usize) else { continue };
            if let Ok(Some(u)) = lp.peers[i].engine.revert(&c) {
                log.push(format!("{step}: node {i} undoes {c:?} at {}: {u:?}", lp.peers[i].engine.now().0));
                commits.push(u);
            }
        } else if x < 85 {
            let j = below(3) as usize;
            if j != i {
                sync(&mut lp, i, j);
            }
        } else {
            lp.advance(below(3_000));
        }
        for p in 0..3 {
            let e = &mut lp.peers[p].engine;
            e.tick().unwrap();
            let now = e.now().0;
            for (ai, a) in aks.iter().enumerate() {
                let mut vs = Vec::new();
                if let Some(v) = e.get(&t, a).unwrap() {
                    values(&v, ai == 3, &mut vs);
                }
                for v in vs {
                    if let Some(Some(at)) = expiry.get(&v) {
                        assert!(now < *at, "seed {seed} step {step}: node {p} reads {v} in {a:?} at {now}, past its expiry {at}\n{}", log.join("\n"));
                    }
                }
            }
        }
    }
}

// spec/commits.md §5, spec/crdt.md §4.8: two writers delete the same char of a kept text; the
// older delete arriving after the newer one supersedes nothing new (the insert died at the newer
// delete, a superseder arriving later does not move it), so it is no reason to date the aspect's
// deaths again from every body (an O(history) replay per concurrent delete).
#[test]
fn older_duplicate_text_delete_dates_in_place_spec_commits_5() {
    use osis_schema::{Bound, PurgeBy, Retention};
    let r = Retention { by: PurgeBy::AuthorOrAdmin, at_least: Bound { abs: None, rel: Some(1_800_000) }, at_most: Bound::default() };
    let mut lp = net(2, 0x5e9);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let b = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, b, Some(edge(Role::Write)), None);
    let op = |lp: &mut osis_node::local_peer::LocalPeer, i: usize, op: Op| {
        let mut m = Mutation::new();
        m.op(t, &TEXT, PathOp { path: vec![], op }).unwrap();
        m.retention(t, &TEXT, r).unwrap();
        lp.peers[i].commit(m).unwrap().unwrap()
    };
    let ins = op(&mut lp, 0, Op::Insert { at: 0, items: vec![s("ab")] });
    lp.sync_all().unwrap();
    lp.advance(10);
    let older = op(&mut lp, 1, Op::Delete { at: 0, len: 1 });
    lp.advance(10);
    let newer = op(&mut lp, 0, Op::Delete { at: 0, len: 1 });
    let ts = lp.peers[0].engine.header(&newer).unwrap().ts;
    let pk = lp.packages(1).unwrap().into_iter().find(|p| p.id == older).unwrap();
    osis_node::costs::take();
    lp.deliver(0, &pk).unwrap();
    lp.peers[0].engine.settle_deaths().unwrap();
    let recomputes = osis_node::costs::take().iter().find(|x| x.0 == "deaths: recompute").map_or(0, |x| x.2);
    assert_eq!(recomputes, 0, "no recompute of the aspect's deaths");
    assert_eq!(lp.peers[0].engine.deaths(&ins, &t, &ak("t:text.0")).unwrap(), Some((ts, ts)));
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:text.0")).unwrap(), Some(s("b")));
}

// spec/commits.md §5 (deaths dated from the bodies only where the state cannot date them): an
// expiring put into a keep-at-most map, overwritten by a kept put, expires; the expiry moves the
// entry's records to its key-erased record with nothing beaten across them, so the aspect's
// deaths are not recomputed (each such expiry recomputing cost O(bodies) per tick).
#[test]
fn expiry_merging_records_without_death_recomputes_nothing_spec_commits_5() {
    let mut lp = net(1, 57);
    let t = new_thing(&mut lp, 0);
    let now = lp.peers[0].engine.now();
    for (i, k) in ["a", "b"].into_iter().enumerate() {
        let mut m = Mutation::new();
        m.op(t, &SHORTMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: Op::Set(s("old")) }).unwrap();
        m.expires(t, &SHORTMAP, WallMs(now.0 + 1000 + 100 * i as u64)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        m.op(t, &SHORTMAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s(k))], op: Op::Set(s("new")) }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }
    osis_node::costs::take();
    for _ in 0..2 {
        lp.advance(1000);
        lp.peers[0].engine.tick().unwrap();
    }
    let recomputes = osis_node::costs::take().iter().find(|x| x.0 == "deaths: recompute").map_or(0, |x| x.2);
    assert_eq!(recomputes, 0);
    // the entries' creations expired: value-less, they hide the entries (spec/crdt.md §5.6)
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:shortmap.0")).unwrap(), Some(Value::Map(Default::default())));
}

// `any_bounded` reads a count (`Indexes::bounded_held`): exact as bounded parts arrive and drop,
// and across a restart; none on an unbounded aspect (debug builds compare it with a walk).
#[test]
fn bounded_held_count_exact_spec_commits_5() {
    let mut lp = net(1, 91);
    let t = new_thing(&mut lp, 0);
    let count = |lp: &LocalPeer, a: &str| lp.peers[0].engine.core.ix.bounded_held.get(&(t, ak(a))).copied();
    set(&mut lp, 0, t, &REG, "one");
    assert_eq!(count(&lp, "t:reg.0"), None);
    let c1 = set(&mut lp, 0, t, &KEPT, "one");
    assert_eq!(count(&lp, "t:kept.0"), Some(1));
    lp.advance(10);
    let c2 = set(&mut lp, 0, t, &KEPT, "two");
    assert_eq!(count(&lp, "t:kept.0"), Some(2));
    lp.peers[0].engine.drop_body(&c1, &t, &ak("t:kept.0")).unwrap();
    assert_eq!(count(&lp, "t:kept.0"), Some(1));
    lp.peers[0].restart(92).unwrap();
    assert_eq!(count(&lp, "t:kept.0"), Some(1));
    lp.peers[0].engine.drop_body(&c2, &t, &ak("t:kept.0")).unwrap();
    assert_eq!(count(&lp, "t:kept.0"), None);
    // keep at most 0 after replaced: the first body drops as the second applies
    set(&mut lp, 0, t, &GONE, "one");
    lp.advance(10);
    set(&mut lp, 0, t, &GONE, "two");
    assert_eq!(count(&lp, "t:gone.0"), Some(1));
    lp.peers[0].restart(93).unwrap();
    assert_eq!(count(&lp, "t:gone.0"), Some(1));
}

// spec/crdt.md §4.6: a register's rise and its winner's fall read the bodies down to the new
// winner only, and give what reading all of them gives (debug builds join the rest to check).
#[test]
fn register_rebuild_stops_at_the_winner_spec_crdt_4_6() {
    let mut lp = net(2, 94);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    for i in 0..100 {
        lp.advance(10);
        set(&mut lp, 0, t, &REG, &format!("{i}"));
    }
    lp.advance(10);
    set(&mut lp, 1, t, &REG, "winner");
    sync(&mut lp, 1, 0);
    let read = |lp: &mut LocalPeer| lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap();
    assert_eq!(read(&mut lp), Some(s("winner")));
    let bodies = || osis_node::costs::take().iter().find(|x| x.0 == "rebuild: body").map_or(0, |x| x.2);
    bodies();
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, p1, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    let n = bodies();
    assert_eq!(read(&mut lp), Some(s("99")));
    assert!((1..=4).contains(&n), "{n} bodies read for the fall");
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    let n = bodies();
    assert_eq!(read(&mut lp), Some(s("winner")));
    assert!(n <= 4, "{n} bodies read for the rise");
}

// spec/crdt.md §4.6: many deltas falling at once un-merge an unpaged state in one pass.
#[test]
fn fall_of_many_one_pass_spec_crdt_4_6() {
    let mut lp = net(2, 95);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    for i in 0..50 {
        lp.advance(10);
        set(&mut lp, 1, t, &REG, &format!("{i}"));
    }
    sync(&mut lp, 1, 0);
    lp.advance(10);
    set(&mut lp, 0, t, &REG, "winner");
    let passes = || osis_node::costs::take().iter().find(|x| x.0 == "unmerge: pass").map_or(0, |x| x.2);
    passes();
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, p1, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    let n = passes();
    assert_eq!(lp.peers[0].engine.invalid_writes(&t, &ak("t:reg.0")).len(), 50);
    assert_eq!(lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap(), Some(s("winner")));
    assert_eq!(n, 1, "un-merge passes");
}

// spec/crdt.md §2.2, §4.6: writes tied on `ts`: a rebuild reads every tied body, so whichever
// holder's write has the higher dot, a re-add gives the same winner as before the fall.
#[test]
fn register_rebuild_reads_tied_writes_spec_crdt_4_6() {
    let mut lp = net(3, 96);
    let t = new_thing(&mut lp, 0);
    let (p1, p2) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, p2, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    lp.advance(10);
    set(&mut lp, 0, t, &REG, "old");
    sync(&mut lp, 0, 1);
    sync(&mut lp, 0, 2);
    lp.advance(10);
    set(&mut lp, 1, t, &REG, "one");
    set(&mut lp, 2, t, &REG, "two");
    sync(&mut lp, 1, 0);
    sync(&mut lp, 2, 0);
    let e = |lp: &mut LocalPeer| lp.peers[0].engine.body_page(&t, &ak("t:reg.0"), true, 0, 2).unwrap();
    let page = e(&mut lp);
    assert_eq!(page[0].ts, page[1].ts, "not tied");
    let read = |lp: &mut LocalPeer| lp.peers[0].engine.get(&t, &ak("t:reg.0")).unwrap();
    let won = read(&mut lp);
    for (p, other) in [(p1, "two"), (p2, "one")] {
        lp.advance(10);
        set_edge(&mut lp.peers[0].engine, t, p, None, Some(osis_schema::core_types::Frontier::default().to_value()));
        assert_eq!(read(&mut lp), Some(s(other)));
        lp.advance(10);
        set_edge(&mut lp.peers[0].engine, t, p, Some(edge(Role::Write)), None);
        assert_eq!(read(&mut lp), won);
    }
    // both fall: the older write, which sits below the two tied ones
    for p in [p1, p2] {
        lp.advance(10);
        set_edge(&mut lp.peers[0].engine, t, p, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    }
    assert_eq!(read(&mut lp), Some(s("old")));
}

// spec/crdt.md §4.6: over random flips, ties and writes from members without the role, a register
// reads the winner of the valid held bodies, at every node: what a rebuild stopping early must
// keep (debug builds also compare each stop with reading every body). Holds in release too.
#[test]
fn register_rebuild_random_winner_of_valid_bodies_spec_crdt_4_6() {
    for seed in 0..6u64 {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        let mut next = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as usize % n
        };
        let mut lp = net(3, 970 + seed);
        let t = new_thing(&mut lp, 0);
        let holders = [lp.peers[1].engine.tid(), lp.peers[2].engine.tid()];
        for h in holders {
            set_edge(&mut lp.peers[0].engine, t, h, Some(edge(Role::Write)), None);
        }
        sync(&mut lp, 0, 1);
        sync(&mut lp, 0, 2);
        let aspects = ["t:reg.0", "t:kept.0"];
        let mut writer = [true; 2];
        for step in 0..40 {
            if next(2) == 0 {
                lp.advance(10);
            }
            let k = aspects[next(2)];
            match next(5) {
                0..=2 => {
                    let i = next(3);
                    let mut m = Mutation::new();
                    m.set(t, &ak(k), &s(&format!("{seed}.{step}"))).unwrap();
                    // past the writer's rules: a member without the role still writes
                    lp.peers[i].engine.commit_hostile(m).unwrap();
                }
                3 => {
                    let (a, b) = (next(3), next(3));
                    if a != b {
                        sync(&mut lp, a, b);
                    }
                }
                _ => {
                    let w = next(2);
                    lp.advance(10);
                    let e = if writer[w] { None } else { Some(edge(Role::Write)) };
                    let frontier = writer[w].then(|| osis_schema::core_types::Frontier::default().to_value());
                    set_edge(&mut lp.peers[0].engine, t, holders[w], e, frontier);
                    writer[w] = !writer[w];
                }
            }
        }
        for _ in 0..2 {
            for (a, b) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (2, 1)] {
                sync(&mut lp, a, b);
            }
        }
        for name in aspects {
            let a = ak(name);
            let reads: Vec<_> = (0..3).map(|i| lp.peers[i].engine.get(&t, &a).unwrap()).collect();
            assert_eq!(reads[0], reads[1], "seed {seed} {name}");
            assert_eq!(reads[0], reads[2], "seed {seed} {name}");
            for (i, read) in reads.iter().enumerate() {
                let e = &mut lp.peers[i].engine;
                let n = e.held_bodies(&t, &a);
                let page = e.body_page(&t, &a, true, 0, n).unwrap();
                let mut valid = page.iter().filter(|b| b.valid);
                let Some(top) = valid.next() else {
                    assert_eq!(*read, None, "seed {seed} {name}: nothing valid");
                    continue;
                };
                let tied: Vec<_> = std::iter::once(top).chain(valid.take_while(|b| b.ts == top.ts)).map(|b| b.value.clone()).collect();
                assert!(tied.contains(read), "seed {seed} {name} peer {i}: {read:?} of {tied:?}");
            }
        }
    }
}

// spec/commits.md §5, §4.6 of spec/crdt.md: a write superseded only once its superseder rises: a
// body kept at most 0 after replaced goes with the rise (`rejudge_deaths`, a bound being held).
#[test]
fn keep_at_most_rejudged_on_rise_spec_commits_5() {
    let mut lp = net(2, 98);
    let t = new_thing(&mut lp, 0);
    let p1 = lp.peers[1].engine.tid();
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    sync(&mut lp, 0, 1);
    lp.advance(10);
    set(&mut lp, 0, t, &GONE, "kept");
    sync(&mut lp, 0, 1);
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, p1, None, Some(osis_schema::core_types::Frontier::default().to_value()));
    lp.advance(10);
    set(&mut lp, 1, t, &GONE, "late");
    sync(&mut lp, 1, 0);
    let a = ak("t:gone.0");
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(s("kept")));
    assert_eq!(lp.peers[0].engine.invalid_writes(&t, &a).len(), 1);
    let held = |lp: &mut LocalPeer| lp.peers[0].engine.held_bodies(&t, &a);
    assert_eq!(held(&mut lp), 2);
    lp.advance(10);
    set_edge(&mut lp.peers[0].engine, t, p1, Some(edge(Role::Write)), None);
    assert_eq!(lp.peers[0].engine.get(&t, &a).unwrap(), Some(s("late")));
    assert_eq!(held(&mut lp), 1, "the replaced body, its bound passed");
}

/// Peers 0 (owner), `x` (1, admin) and `w` (2, writer) of a new thing; `w`'s message `c` and `x`'s
/// request naming it, its own delta on another aspect if `beside`, all synced.
fn rightful(seed: u64, beside: bool) -> (LocalPeer, osis_base::Tid, osis_base::CommitId, osis_base::CommitId) {
    let mut lp = net(3, seed);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let c = set(&mut lp, 2, t, &REG, "kept");
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    if beside {
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    } else {
        m.set(t, &REG, &s("after")).unwrap();
    }
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:reg.0")));
    (lp, t, c, p)
}

fn stays_purged(lp: &mut LocalPeer, t: osis_base::Tid, c: osis_base::CommitId) {
    for i in [0, 2] {
        let e = &mut lp.peers[i].engine;
        assert!(!e.body_not_dropped(&c, &t, &ak("t:reg.0")), "peer {i}: the demotion brought it back");
        assert_eq!(e.purged_on(&t, &ak("t:reg.0")).unwrap().len(), 1, "peer {i}");
    }
}

// spec/permissions.md §5.1, §8: a demotion lists the requests its author received, so a demotion
// by one that held them leaves every rightful purge standing: to a writer (whose frontier holds no
// content commit otherwise), and out altogether, whatever aspect the request's own delta is on.
#[test]
fn honest_demotion_keeps_rightful_purges_spec_perm_8() {
    for (seed, new, beside) in [(0x71, Some(Role::Write), false), (0x72, None, false), (0x73, Some(Role::Write), true), (0x74, None, true)] {
        let (mut lp, t, c, p) = rightful(seed, beside);
        let x = lp.peers[1].engine.tid();
        let d = osis_node::flows::Demotion { holder: x, new: new.map(edge), presync: osis_node::flows::PreSync::Synced, keep: None };
        let done = lp.peers[0].engine.demote(&t, &d).unwrap();
        lp.sync_all().unwrap();
        stays_purged(&mut lp, t, c);
        assert!(frontier_lists(&lp.peers[0].engine, &done, &p), "{new:?}");
    }
}

// spec/permissions.md §5.1: a request's body dropped as covered is no reason to leave it out, as it is
// for a write.
#[test]
fn request_dropped_as_covered_stays_listed_spec_perm_5_1() {
    let (mut lp, t, c, p) = rightful(0x75, false);
    let k = ak("t:reg.0");
    lp.advance(100 * 86_400_000);
    lp.peers[0].engine.compaction_snapshot(&t, &k).unwrap().unwrap();
    lp.peers[0].engine.drop_body(&p, &t, &k).unwrap();
    let x = lp.peers[1].engine.tid();
    let d = osis_node::flows::Demotion { holder: x, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
    let done = lp.peers[0].engine.demote(&t, &d).unwrap();
    assert!(frontier_lists(&lp.peers[0].engine, &done, &p));
    assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &k));
}

fn frontier_lists(e: &osis_node::Engine, done: &osis_node::flows::Done, p: &osis_base::CommitId) -> bool {
    done.commits.iter().filter_map(|c| e.header(c)).filter_map(|h| h.frontier.clone()).any(|f| osis_schema::core_types::Frontier::from_value(&f).unwrap().commits.contains(p))
}

// spec/permissions.md §5.1: a request read by header alone (a receipts-only read) lists too.
#[test]
fn request_read_by_header_alone_is_listed_spec_perm_5_1() {
    let mut lp = net(2, 0x76);
    lp.sync_all().unwrap();
    let x = lp.peers[1].engine.tid();
    let t = new_thing(&mut lp, 1);
    let c = set(&mut lp, 1, t, &REG, "kept");
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    let pk = lp.peers[1].engine.package(&p).unwrap().unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.record_header(&osis_commit::CommitBlob::decode(&pk.bytes).unwrap()).unwrap());
    let mut scope = osis_perm::DemotionScope::default();
    scope.roles.entry(x).or_default().insert(t);
    let now = e.now();
    assert!(e.frontier(&scope, now).unwrap().commits.contains(&p));
}

// spec/sync.md §6: a request no signer could ever hold the right for explains no delete: a plain
// writer's aspect-wide request leaves the keep-out rule alone.
#[test]
fn a_writers_request_explains_no_delete_spec_sync_6() {
    let (mut lp, t, _, _) = rightful(0x78, false);
    let k = ak("t:reg.0");
    let c2 = set(&mut lp, 0, t, &REG, "owner's");
    lp.sync_all().unwrap();
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Aspect { tid: t, ak: k.clone() });
    m.set(t, &REG, &s("w's")).unwrap();
    lp.peers[2].commit(m).unwrap().unwrap();
    lp.sync_all().unwrap();
    let e = &mut lp.peers[0].engine;
    assert!(e.body_not_dropped(&c2, &t, &k), "no right over another's delta");
    assert!(!e.named_by_a_fallen_purge(&c2, &[(0, 0)]).unwrap());
}

// spec/permissions.md §8: a snapshot dropped for carrying two purged deltas, one purge falling: it
// is fetched again, and goes on arrival as it carries the other's value, which stays gone; given
// the bodies again it all reads alike with a node that never saw the fallen purge stand.
#[test]
fn snapshot_of_two_purges_one_falls_spec_perm_8() {
    let mut lp = net(5, 0x79);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let k = ak("t:map.0");
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut ids = Vec::new();
    for key in ["one", "two", "live"] {
        lp.advance(5);
        let mut m = Mutation::new();
        m.op(t, &MAP, PathOp { path: vec![osis_crdt::PathSeg::Key(s(key))], op: Op::Set(item(key, 1)) }).unwrap();
        ids.push(lp.peers[2].commit(m).unwrap().unwrap());
    }
    lp.advance(5);
    let snap = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    let pks: Vec<_> = ids.iter().chain([&snap]).map(|c| lp.peers[2].engine.package(c).unwrap().unwrap()).collect();
    lp.advance(5);
    let purge = |lp: &mut LocalPeer, i: usize, c: osis_base::CommitId| {
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:map.0") });
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
        let p = lp.peers[i].commit(m).unwrap().unwrap();
        lp.peers[i].engine.package(&p).unwrap().unwrap()
    };
    let p1 = purge(&mut lp, 1, ids[0]);
    let p2 = purge(&mut lp, 0, ids[1]);
    lp.advance(5);
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    let pd = lp.peers[0].engine.package(&d).unwrap().unwrap();
    let all = lp.packages(0).unwrap();
    let skip = [ids[0], ids[1], ids[2], snap, p1.id, p2.id, d];
    let read = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.get(&t, &k).unwrap();
    for n in [3, 4] {
        for pk in all.iter().filter(|pk| !skip.contains(&pk.id)) {
            let _ = lp.deliver(n, pk);
        }
        for pk in &pks {
            lp.deliver(n, pk).unwrap();
        }
        lp.peers[n].engine.drop_body(&ids[2], &t, &k).unwrap();
    }
    // 3 sees p1 stand, then fall; 4 has the demotion first
    for pk in [&p1, &p2, &pd] {
        lp.deliver(3, pk).unwrap();
    }
    for pk in [&pd, &p1, &p2] {
        lp.deliver(4, pk).unwrap();
    }
    assert!(!lp.peers[3].engine.body_not_dropped(&ids[1], &t, &k), "the other purge stands");
    assert_eq!(lp.peers[3].engine.core.ix.commits.get(&snap).unwrap().missing.len(), 1);
    lp.deliver(3, &pks[3]).unwrap();
    assert!(!lp.peers[3].engine.body_not_dropped(&snap, &t, &k), "it carries the other's value");
    assert!(!lp.peers[3].engine.body_not_dropped(&ids[1], &t, &k));
    for pk in [&pks[0], &pks[2]] {
        lp.deliver(3, pk).unwrap();
    }
    assert_eq!(read(&mut lp, 3), read(&mut lp, 4));
    let two = lp.peers[3].engine.get(&t, &k).unwrap().unwrap();
    assert!(!format!("{two:?}").contains("two"), "{two:?}");
}

// spec/permissions.md §8: the right held through another actor: `x` is admin of the thing only through
// `via`, on which it holds admin, and the demotion of `via` or of `x` on it leaves the purge standing.
#[test]
fn honest_demotion_of_a_path_keeps_rightful_purges_spec_perm_8() {
    for on_via in [false, true] {
        let mut lp = net(3, 0x7a);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let via = new_thing(&mut lp, 0);
        let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, via, x, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, via, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        let c = set(&mut lp, 2, t, &REG, "kept");
        lp.sync_all().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        m.set(t, &REG, &s("after")).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "the right holds through the path");
        lp.advance(5);
        let (on, holder) = if on_via { (via, x) } else { (t, via) };
        let d = osis_node::flows::Demotion { holder, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
        lp.peers[0].engine.demote(&on, &d).unwrap();
        lp.sync_all().unwrap();
        stays_purged(&mut lp, t, c);
    }
}

// spec/permissions.md §5.1, §8: a hostile current admin's frontier lists the demoted admin's message
// and leaves its delete out: the delete is undone. Nodes that dropped the body read it as never
// received; a node that still holds it keeps it and its copy brings the message back everywhere.
// Left out too, the message itself stays invalid.
#[test]
fn demotion_lists_the_message_omits_the_delete_spec_perm_8() {
    for listed in [true, false] {
        let mut lp = net(4, 0x7b);
        lp.sync_all().unwrap();
        let (t, k) = (new_thing(&mut lp, 0), ak("t:reg.0"));
        let x = lp.peers[1].engine.tid();
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        let c = set(&mut lp, 1, t, &REG, "kept");
        lp.sync_all().unwrap();
        lp.advance(5);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
        let p = lp.peers[1].commit(m).unwrap().unwrap();
        let pp = lp.peers[1].engine.package(&p).unwrap().unwrap();
        // 3 is behind: it still holds the body
        for i in [0, 2] {
            lp.deliver(i, &pp).unwrap();
            assert!(!lp.peers[i].engine.body_not_dropped(&c, &t, &k));
        }
        let copy = lp.peers[3].engine.package(&c).unwrap().unwrap();
        lp.advance(5);
        let commits = if listed { std::collections::BTreeSet::from([c]) } else { Default::default() };
        let d = set_edge(&mut lp.peers[0].engine, t, x, None, Some(osis_schema::core_types::Frontier { commits }.to_value()));
        let pd = lp.peers[0].engine.package(&d).unwrap().unwrap();
        for (i, pk) in [(2, &pd), (3, &pd), (3, &pp)] {
            lp.deliver(i, pk).unwrap();
        }
        for i in [0, 2, 3] {
            assert!(lp.peers[i].engine.purged_on(&t, &k).unwrap().is_empty(), "peer {i}: no purge shown");
        }
        // what the thing's creation wrote, below the message
        let (before, want) = (Some(s("new")), Some(s(if listed { "kept" } else { "new" })));
        assert_eq!(lp.peers[3].engine.get(&t, &k).unwrap(), want, "the holder");
        assert!(lp.peers[3].engine.body_not_dropped(&c, &t, &k), "the holder keeps the body either way");
        for i in [0, 2] {
            assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), before, "peer {i}: as never received");
            assert_eq!(lp.peers[i].engine.core.ix.commits.get(&c).unwrap().missing.len(), 1, "peer {i}");
            lp.deliver(i, &copy).unwrap();
            assert!(lp.peers[i].engine.body_not_dropped(&c, &t, &k), "peer {i}: the copy joins");
            assert_eq!(lp.peers[i].engine.get(&t, &k).unwrap(), want, "peer {i}");
        }
        assert_eq!(lp.peers[0].engine.get(&t, &ak("t:list.0")).unwrap(), None, "the request's own write falls with it");
    }
}

// spec/permissions.md §8, spec/sync.md §6: a waiting commit's part stripped for a purge that falls
// before the commit applies: the part counts as never received once it applies, and the change
// names the commit, which is what makes node-sync fetch it again (`reopen_undropped`).
#[test]
fn stripped_while_waiting_purge_falls_is_fetched_again_spec_perm_8() {
    let mut lp = net(4, 0x7c);
    let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    for (a, b) in [(0, 1), (1, 0), (0, 2), (2, 0), (1, 2), (2, 1)] {
        sync(&mut lp, a, b);
    }
    let (t, k) = (new_thing(&mut lp, 0), ak("t:reg.0"));
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    for (a, b) in [(0, 1), (0, 2)] {
        sync(&mut lp, a, b);
    }
    lp.advance(5);
    let c = set(&mut lp, 2, t, &REG, "kept");
    sync(&mut lp, 2, 1);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let p = lp.peers[1].commit(m).unwrap().unwrap();
    // 3 lacks `w`'s creation record: `c` waits
    let is_w = |pk: &osis_node::local_peer::Package| osis_commit::CommitBlob::decode(&pk.bytes).unwrap().header.author == w;
    let all = lp.packages(0).unwrap();
    for pk in all.iter().filter(|pk| !is_w(pk)) {
        let _ = lp.deliver(3, pk);
    }
    let withheld: Vec<_> = all.into_iter().filter(|pk| is_w(pk)).collect();
    let pc = lp.peers[2].engine.package(&c).unwrap().unwrap();
    let pp = lp.peers[1].engine.package(&p).unwrap().unwrap();
    lp.deliver(3, &pc).unwrap();
    lp.deliver(3, &pp).unwrap();
    assert!(!lp.peers[3].engine.core.ix.commits.contains_key(&c), "it waits");
    lp.peers[3].engine.reexamine().unwrap();
    assert_eq!(lp.peers[3].engine.stripped_count(&c).unwrap(), 1, "stripped for the request");
    lp.advance(5);
    let d = set_edge(&mut lp.peers[0].engine, t, x, None, None);
    let pd = lp.peers[0].engine.package(&d).unwrap().unwrap();
    lp.deliver(3, &pd).unwrap();
    lp.peers[3].engine.take_changed();
    for pk in withheld.iter().filter(|pk| pk.id != c) {
        let _ = lp.deliver(3, pk);
    }
    lp.peers[3].engine.reexamine().unwrap();
    let e = &mut lp.peers[3].engine;
    assert_eq!(e.core.ix.commits.get(&c).unwrap().missing.len(), 1, "applied, its part never received");
    assert!(e.take_changed().undropped.contains(&c), "node-sync is told to fetch it");
    assert_eq!(e.get(&t, &k).unwrap(), Some(s("new")));
    lp.deliver(3, &pc).unwrap();
    assert_eq!(lp.peers[3].engine.get(&t, &k).unwrap(), Some(s("kept")));
}

// spec/permissions.md §5.1, §8: a request resting on the author class through a person: its signer
// keeps a direct write edge on the thing, so its class falls only on the person (`on_person`), or the
// person falls and the signer stays on it. An honest demotion lists the request either way.
#[test]
fn honest_demotion_keeps_a_request_resting_on_the_person_spec_perm_8() {
    for on_person in [true, false] {
        let mut lp = net(3, 0x7c + u64::from(on_person));
        let (who, _) = lp.peers[0].engine.create_person(&crate::flows::hosts()).unwrap();
        let person = who.person;
        let (x, o) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        crate::flows::spread(&mut lp);
        let paired = lp.peers[0].engine.pair(&person, &x).unwrap();
        crate::flows::spread(&mut lp);
        lp.peers[1].engine.paired(&person, paired.commits.last().unwrap()).unwrap();
        let t = crate::flows::thing_of(&mut lp, 2, o);
        set_edge(&mut lp.peers[2].engine, t, person, Some(edge(Role::Write)), None);
        set_edge(&mut lp.peers[2].engine, t, x, Some(edge(Role::Write)), None);
        crate::flows::spread(&mut lp);
        lp.advance(5);
        let mut m = Mutation::new();
        m.act_as(person);
        m.set(t, &REG, &s("kept")).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        crate::flows::spread(&mut lp);
        lp.advance(5);
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: ak("t:reg.0") });
        m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        crate::flows::spread(&mut lp);
        assert!(!lp.peers[0].engine.body_not_dropped(&c, &t, &ak("t:reg.0")), "the right holds through the person");
        lp.advance(5);
        let (by, on, holder) = if on_person { (0, person, x) } else { (2, t, person) };
        let d = osis_node::flows::Demotion { holder, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
        lp.peers[by].engine.demote(&on, &d).unwrap();
        crate::flows::spread(&mut lp);
        for i in [0, 2] {
            let e = &mut lp.peers[i].engine;
            assert!(!e.body_not_dropped(&c, &t, &ak("t:reg.0")), "on_person {on_person}, peer {i}: the demotion brought it back");
            assert_eq!(e.purged_on(&t, &ak("t:reg.0")).unwrap().len(), 1, "on_person {on_person}, peer {i}");
        }
    }
}

// spec/permissions.md §8: a purge standing, falling and rising over a part dropped as covered, with
// no copy left: it leaves what it left, as at a node that never saw the fall.
#[test]
fn covered_part_purged_fallen_and_purged_again_reads_alike_spec_perm_8() {
    let mut lp = net(6, 0x7e);
    lp.sync_all().unwrap();
    let t = new_thing(&mut lp, 0);
    let k = ak("t:reg.0");
    let (m1, x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    set_edge(&mut lp.peers[0].engine, t, m1, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
    set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    lp.advance(5);
    let older = set(&mut lp, 3, t, &REG, "older");
    lp.advance(5);
    let c = set(&mut lp, 3, t, &REG, "kept");
    lp.advance(5);
    let snap = lp.peers[3].engine.snapshot(&t, &k).unwrap().unwrap();
    sync(&mut lp, 3, 2);
    lp.advance(5);
    let mut m = Mutation::new();
    m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
    m.set(t, &LIST, &Value::List(vec![s("beside")])).unwrap();
    let p = lp.peers[2].commit(m).unwrap().unwrap();
    lp.advance(5);
    // 1 demotes x, unseen by 0, whose demotion of 1 leaves it out of its frontier
    let dx = set_edge(&mut lp.peers[1].engine, t, x, None, None);
    lp.advance(5);
    let dm = set_edge(&mut lp.peers[0].engine, t, m1, None, None);
    let by = |lp: &mut LocalPeer, id, n: usize| lp.peers[n].engine.package(id).unwrap().unwrap();
    let (po, pc, ps, pp, pdx, pdm) = (by(&mut lp, &older, 3), by(&mut lp, &c, 3), by(&mut lp, &snap, 3), by(&mut lp, &p, 2), by(&mut lp, &dx, 1), by(&mut lp, &dm, 0));
    let base = lp.packages(0).unwrap();
    for pk in base.iter().filter(|pk| ![dm, older, c, snap, p, dx].contains(&pk.id)) {
        let _ = lp.deliver(4, pk);
        let _ = lp.deliver(5, pk);
    }
    // 4 drops `c` as covered, sees the purge stand, fall, and rise
    for pk in [&po, &pc, &ps] {
        lp.deliver(4, pk).unwrap();
    }
    lp.peers[4].engine.drop_body(&c, &t, &k).unwrap();
    for pk in [&pp, &pdx] {
        lp.deliver(4, pk).unwrap();
    }
    // what it left outlives a restart
    lp.peers[4].restart(0x7f).unwrap();
    lp.deliver(4, &pdm).unwrap();
    // 5 never sees it fall
    for pk in [&po, &pc, &ps, &pp, &pdm, &pdx] {
        lp.deliver(5, pk).unwrap();
    }
    assert!(lp.peers[5].engine.purged_on(&t, &k).unwrap().contains_key(&c));
    assert_eq!(lp.peers[4].engine.get(&t, &k).unwrap(), lp.peers[5].engine.get(&t, &k).unwrap(), "reads alike");
    assert_eq!(lp.peers[5].engine.get(&t, &k).unwrap(), None, "the delete stands");
}

// spec/permissions.md §5.1, §8: at the list bound a demotion goes through and leaves out the requests
// its author received last, as few as fit: each of those falls, rightful or not.
#[test]
fn frontier_at_the_bound_leaves_out_the_last_requests_spec_perm_5_1() {
    let k = ak("t:reg.0");
    let run = |bound: usize| {
        let mut lp = net(3, 0x80);
        lp.sync_all().unwrap();
        let t = new_thing(&mut lp, 0);
        let (x, w) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        set_edge(&mut lp.peers[0].engine, t, x, Some(edge(Role::Admin)), None);
        set_edge(&mut lp.peers[0].engine, t, w, Some(edge(Role::Write)), None);
        lp.sync_all().unwrap();
        lp.advance(5);
        let msgs: Vec<_> = (0..3).map(|i| set(&mut lp, 2, t, &REG, &format!("m{i}"))).collect();
        lp.sync_all().unwrap();
        for (i, c) in msgs.iter().enumerate() {
            lp.advance(5);
            let mut m = Mutation::new();
            m.purge(PurgeItem::Commit { commit: *c, tid: t, ak: k.clone() });
            m.set(t, &LIST, &Value::List(vec![s(&format!("b{i}"))])).unwrap();
            lp.peers[1].commit(m).unwrap().unwrap();
            sync(&mut lp, 1, 0);
        }
        lp.sync_all().unwrap();
        lp.advance(5);
        lp.peers[0].engine.list_bound(bound);
        let d = osis_node::flows::Demotion { holder: x, new: None, presync: osis_node::flows::PreSync::Synced, keep: None };
        let done = lp.peers[0].engine.demote(&t, &d).unwrap();
        let size = done.commits.iter().filter_map(|c| lp.peers[0].engine.header(c)).filter_map(|h| h.frontier.clone()).map(|f| osis_base::encode(&f).len()).max().unwrap();
        lp.sync_all().unwrap();
        let stands: Vec<Vec<bool>> = [0, 2].iter().map(|i| msgs.iter().map(|c| !lp.peers[*i].engine.body_not_dropped(c, &t, &k)).collect()).collect();
        assert_eq!(stands[0], stands[1], "nodes judge alike");
        assert!(!lp.peers[2].engine.roster(&t).contains_key(&x), "the demotion applied");
        (size, stands[0].clone())
    };
    let (full, all) = run(usize::MAX);
    assert_eq!(all, [true, true, true]);
    assert_eq!(run(full - 1).1, [true, true, false], "one left out, the one received last");
    assert_eq!(run(0).1, [false, false, false], "none fits: the demotion still goes through");
}

// spec/crdt.md §4.7, spec/commits.md §5: a second request on a delta dropped as covered keeps the
// residue the first took from its coverers, when a coverer not carrying it is left (was: replaced
// by nothing, so the older write came back once a later write fell, where a node that held the body
// read as ever).
#[test]
fn second_request_keeps_covered_residue_spec_crdt_4_7() {
    use std::collections::{BTreeMap, BTreeSet};
    let mut lp = net(3, 0x77);
    lp.sync_all().unwrap();
    let ids: Vec<_> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let t = new_thing(&mut lp, 0);
    set_edge(&mut lp.peers[0].engine, t, ids[1], Some(edge(Role::Write)), None);
    set_edge(&mut lp.peers[0].engine, t, ids[2], Some(edge(Role::Write)), None);
    lp.sync_all().unwrap();
    let mut packs: Vec<_> = lp.peers[0].engine.commit_ids().into_iter().map(|id| lp.peers[0].engine.package(&id).unwrap().unwrap()).collect();
    let k = ak("t:reg.0");
    let pack = |lp: &mut LocalPeer, i: usize, id: &osis_base::CommitId| lp.peers[i].engine.package(id).unwrap().unwrap();
    // an older write no snapshot covers, kept from 0 for now
    let old = set(&mut lp, 1, t, &REG, "old");
    let old = pack(&mut lp, 1, &old);
    lp.advance(10);
    let c = set(&mut lp, 0, t, &REG, "secret");
    let cp = pack(&mut lp, 0, &c);
    lp.advance(10);
    let s1 = lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
    let s1 = pack(&mut lp, 0, &s1);
    lp.deliver(2, &cp).unwrap();
    lp.deliver(2, &s1).unwrap();
    lp.advance(10);
    // 2's later write, and its snapshot: covers c, carries none of it
    let x = set(&mut lp, 2, t, &REG, "later");
    let xp = pack(&mut lp, 2, &x);
    lp.advance(10);
    let s2 = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    let s2 = pack(&mut lp, 2, &s2);
    lp.deliver(0, &xp).unwrap();
    lp.deliver(0, &s2).unwrap();
    lp.advance(10);
    lp.peers[0].engine.drop_body(&c, &t, &k).unwrap();
    packs.extend([old.clone(), cp, s1, xp, s2]);
    for v in ["one", "two"] {
        let mut m = Mutation::new();
        m.purge(PurgeItem::Commit { commit: c, tid: t, ak: k.clone() });
        m.set(t, &KEPT, &s(v)).unwrap();
        let p = lp.peers[0].commit(m).unwrap().unwrap();
        packs.push(pack(&mut lp, 0, &p));
        lp.advance(10);
    }
    lp.deliver(0, &old).unwrap();
    // 2 demoted as of before its write: both fall
    let scope = osis_perm::DemotionScope { roles: BTreeMap::from([(ids[2], BTreeSet::from([t]))]), content: BTreeMap::from([(ids[2], BTreeSet::from([t]))]) };
    let before = WallMs(lp.peers[2].engine.header(&x).unwrap().ts.wall_ms().0 - 1);
    let f = lp.peers[0].engine.frontier(&scope, before).unwrap();
    let mut m = Mutation::new();
    m.op(t, &osis_schema::core_types::ROLES, PathOp { path: vec![], op: Op::Remove(Value::Tid(ids[2])) }).unwrap();
    m.frontier(f.to_value());
    let d = lp.peers[0].commit(m).unwrap().unwrap();
    packs.push(pack(&mut lp, 0, &d));
    let now = lp.peers[0].engine.now();
    let mut fresh = osis_node::local_peer::Peer::new(0x9999, now).unwrap();
    for pk in &packs {
        fresh.engine.ingest(&pk.bytes, pk.blobs.clone()).unwrap();
    }
    assert_eq!(lp.peers[0].engine.get(&t, &k).unwrap(), fresh.engine.get(&t, &k).unwrap(), "the older write stays superseded");
    assert_eq!(lp.peers[0].engine.state_digest(&t, &k).unwrap(), fresh.engine.state_digest(&t, &k).unwrap());
}
