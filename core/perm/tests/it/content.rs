//! Layer 2 (spec/permissions.md §5.2, §6 ledger; spec/commits.md §4 overlap): scenarios of
//! core/test/membership-model `content` and `snapshot` records.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::Role::{Admin, Write};
use osis_base::{Role, Tid};
use osis_perm::{overlapping, Dots, Edge, Point, Range, Timeline, Validity};
use std::collections::BTreeSet;

const DOC: &str = "/doc";

fn valid(tl: &Timeline, p: Point, thing: Tid, required: Role) -> bool {
    tl.delta_valid(p, &thing, DOC, Dots::Commit, required) == Validity::Valid
}

/// Owner O (node 0) owns N; A (node 1) admin, X (node 2) writer.
fn doc() -> (World, Vec<Tid>, Tid) {
    let mut w = World::new();
    let n = w.nodes(4);
    let d = w.thing(n[0]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], d, n[1], edge(Admin), 0, &all);
    w.set(n[0], d, n[2], edge(Write), 0, &all);
    (w, n, d)
}

/// §5.2 reference scenario: X's edit at t=3 unseen by A, who revokes at t=4; X's edit at t=5.
/// Both invalid; seen by A, the first stands; re-granted, both stand.
#[test]
fn frontier_decides_pre_revoke_edits() {
    for (seen, regrant, expect) in [(false, false, (false, false)), (true, false, (true, false)), (true, true, (true, true)), (false, true, (true, true))] {
        let (mut w, n, d) = doc();
        let (a, x) = (n[1], n[2]);
        let recv: Vec<(Tid, u64)> = if seen { vec![(a, 3)] } else { vec![] };
        let e1 = w.content(x, 3, &recv);
        let e2 = w.content(x, 5, &[]);
        let r = w.set(a, d, x, None, 4, &[]);
        if regrant {
            w.set(a, d, x, edge(Write), 8, &[]);
        }
        let tl = Timeline::evaluate(&w.held());
        assert_eq!((valid(&tl, e1, d, Write), valid(&tl, e2, d, Write)), expect, "seen {seen} regrant {regrant}");
        if !seen && !regrant {
            let by = tl.delta_valid(e1, &d, DOC, Dots::Commit, Write);
            assert_eq!(by, Validity::Invalid { by: Some(Point { ts: ts(4), node: a, commit: r }) });
        }
    }
}

/// §5.2: `until` audits nothing: edits inside the edge's life stand, later ones do not; the
/// next explicit demotion audits as if the member still held write.
#[test]
fn until_audits_nothing_until_explicit_demotion() {
    let (mut w, n, d) = doc();
    let (a, x) = (n[1], n[2]);
    w.set(n[0], d, x, edge_inv(Write, None, Some(4)), 1, &[]);
    let e1 = w.content(x, 3, &[]);
    let e2 = w.content(x, 5, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!((valid(&tl, e1, d, Write), valid(&tl, e2, d, Write)), (true, false));
    w.set(a, d, x, None, 9, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!((valid(&tl, e1, d, Write), valid(&tl, e2, d, Write)), (false, false));
}

/// §5.2: validity is per delta: X's commit touches N0 and N1; revoked on N0 only.
#[test]
fn per_delta_validity() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (d0, d1) = (w.thing(n[0]), w.thing(n[0]));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], d0, n[2], edge(Write), 0, &all);
    w.set(n[0], d1, n[2], edge(Write), 0, &all);
    let e = w.content(n[2], 3, &[]);
    w.set(n[0], d0, n[2], None, 4, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!((valid(&tl, e, d0, Write), valid(&tl, e, d1, Write)), (false, true));
}

/// §5.2 through the owner chain: a device removed from P by a node that had not received its
/// write on G (owned by P) loses it; one it had received stands.
#[test]
fn device_removal_reaches_owned_things() {
    for seen in [false, true] {
        let mut w = World::new();
        let n = w.nodes(3);
        let (d1, d2) = (n[1], n[2]);
        let p = w.thing(n[0]);
        let g = w.thing(p);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(n[0], p, d1, edge(Admin), 0, &all);
        w.set(n[0], p, d2, edge(Admin), 0, &all);
        let recv: Vec<(Tid, u64)> = if seen { vec![(d2, 6)] } else { vec![] };
        let e = w.content(d1, 5, &recv);
        w.set(d2, p, d1, None, 7, &[]);
        let tl = Timeline::evaluate(&w.held());
        assert_eq!(valid(&tl, e, g, Write), seen);
        assert_eq!(valid(&tl, e, g, Admin), seen, "records need admin (§5.1: judged like content)");
    }
}

/// §6 ledger, layer 2: the key actor re-snapshots P after D2 removed D1; the tenure carries
/// the removal's frontier, so D1's record D2 had received stays valid and one it had not
/// stays invalid, compacted or not. Without the ledger both would be disowned.
#[test]
fn p_resnapshot_keeps_former_device_records() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, d1, d2) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    let g1 = w.set(k, p, d1, edge(Admin), 0, &all);
    let g2 = w.set(k, p, d2, edge(Admin), 0, &all);
    let seen = w.content(d1, 3, &[(d2, 3)]);
    let unseen = w.content(d1, 4, &[]);
    let rm = w.set(d2, p, d1, None, 5, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!((valid(&tl, seen, g, Admin), valid(&tl, unseen, g, Admin)), (true, false));
    let mut with = w.clone();
    with.snapshot_l(k, p, &[(d2, Edge::new(Admin))], &[(d1, Admin, None, (5, d2, None), true)], 7, &[]);
    let compacted = with.held_without(&[g1, g2, rm].into_iter().collect());
    for held in [with.held(), compacted] {
        let tl = Timeline::evaluate(&held);
        assert_eq!((valid(&tl, seen, g, Admin), valid(&tl, unseen, g, Admin)), (true, false));
    }
    let mut bare = w.clone();
    bare.snapshot(k, p, &[(d2, Edge::new(Admin))], 7, &[]);
    let tl = Timeline::evaluate(&bare.held());
    assert_eq!((valid(&tl, seen, g, Admin), valid(&tl, unseen, g, Admin)), (false, false));
}

/// §5.2: a re-grant validates a write made in the gap; a later removal judges it by its own
/// frontier (the snapshot model's record rule, "admin at its point", is not §5.2's).
#[test]
fn regrant_validates_gap_until_next_removal() {
    for k_removes in [false, true] {
        let mut w = World::new();
        let n = w.nodes(3);
        let (k, d1, d2) = (n[0], n[1], n[2]);
        let p = w.thing(k);
        let g = w.thing(p);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(k, p, d1, edge(Admin), 0, &all);
        w.set(k, p, d2, edge(Admin), 0, &all);
        w.set(d2, p, d1, None, 2, &[]);
        let gap = w.content(d1, 3, &[(d2, 3)]);
        assert!(!valid(&Timeline::evaluate(&w.held()), gap, g, Admin));
        w.set(d2, p, d1, edge(Admin), 4, &[]);
        assert!(valid(&Timeline::evaluate(&w.held()), gap, g, Admin));
        w.set(if k_removes { k } else { d2 }, p, d1, None, 6, &[]);
        assert_eq!(valid(&Timeline::evaluate(&w.held()), gap, g, Admin), !k_removes, "k removes {k_removes}");
    }
}

/// spec/commits.md §4: overlapping node-form ranges from one node on one aspect void both
/// commits; adjacent ranges, other nodes and other aspects do not.
// spec/permissions.md §5.2 (dot reuse)
#[test]
fn node_form_overlap_voids_both() {
    let mut w = World::new();
    let n = w.nodes(2);
    let t = w.thing(n[0]);
    let r = |c: u32, node: Tid, ak: &str, lo: u64, hi: u64| Range { commit: cid(c), node, tid: t, ak: ak.into(), lo, hi };
    let v = overlapping([r(1, n[0], DOC, 1, 3), r(2, n[0], DOC, 3, 5), r(3, n[0], DOC, 4, 6), r(4, n[1], DOC, 1, 9), r(5, n[0], "/x", 1, 9), r(1, n[0], DOC, 1, 3)]);
    assert_eq!(v, BTreeSet::from([cid(2), cid(3)]));
}

/// spec/commits.md §4 in layer 1: two edge commits by one node with overlapping `/members`
/// ranges are both ignored.
#[test]
fn overlapping_membership_commits_ignored() {
    let (w, n, d) = doc();
    let mut held = w.held();
    let z = w.created.keys().copied().find(|t| !n.contains(t) && *t != d).unwrap_or(n[3]);
    for (id, lo, hi, member) in [(cid(1), 1, 3, n[3]), (cid(2), 2, 4, z)] {
        held.add_commit(osis_perm::MembershipCommit {
            id,
            ts: ts(5),
            author: n[1],
            actor: n[1],
            frontier: None,
            ops: vec![osis_perm::EdgeOp { target: d, member, edge: edge(Write), dots: Dots::Node { lo, hi } }],
        });
    }
    let tl = Timeline::evaluate(&held);
    assert!(!tl.roster(&d, osis_perm::At::END).contains_key(&n[3]));
}

/// §5.2 re-grant makes writes valid *again*: a write before X's first tenure stays invalid
/// after X is granted (review finding), one inside a later gap is restored.
#[test]
fn pre_grant_write() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (a, x) = (n[0], n[1]);
    let t = w.thing(a);
    let pre = w.content(x, 3, &[]);
    w.set(a, t, x, edge(Write), 10, &[]);
    w.set(a, t, x, None, 12, &[]);
    let gap = w.content(x, 13, &[]);
    w.set(a, t, x, edge(Write), 14, &[]);
    let tl = Timeline::evaluate(&w.held());
    assert!(!valid(&tl, pre, t, Write));
    assert!(valid(&tl, gap, t, Write));
}

/// §5.2 with §5.1 "as if the member still held the role" (deliberate): a write after `until`
/// is invalid until the next explicit demotion, whose frontier then decides it.
#[test]
fn until_gap_write_finalized_by_frontier() {
    for seen in [false, true] {
        let mut w = World::new();
        let n = w.nodes(2);
        let (a, x) = (n[0], n[1]);
        let t = w.thing(a);
        w.set(a, t, x, edge_inv(Write, None, Some(5)), 1, &[]);
        let recv: Vec<(Tid, u64)> = if seen { vec![(a, 8)] } else { vec![] };
        let p = w.content(x, 7, &recv);
        assert!(!valid(&Timeline::evaluate(&w.held()), p, t, Write));
        w.set(a, t, x, None, 10, &[]);
        assert_eq!(valid(&Timeline::evaluate(&w.held()), p, t, Write), seen);
    }
}

/// Re-grant's first tenure (`first_held`, a replay of the node's roles over the history) is
/// what a search at every change finds: random owner trees, actors as members, edges with
/// `until` and invites, most writes by the target's key actor. Debug builds compare the two at
/// every call.
#[cfg(debug_assertions)]
#[test]
fn regrant_replay_equals_search() {
    use osis_base::Role::Read;
    let mut rng = membership_model::Rng(0x5eed_0501);
    for _ in 0..3000 {
        let mut w = World::new();
        let n = w.nodes(3);
        let mut ents = n.clone();
        let mut top: std::collections::BTreeMap<Tid, Tid> = n.iter().map(|x| (*x, *x)).collect();
        for _ in 0..4 {
            let o = ents[rng.below(ents.len())];
            let t = w.thing(o);
            top.insert(t, top[&o]);
            ents.push(t);
        }
        for k in 0..rng.below(40) as u64 {
            let (target, member) = (ents[3 + rng.below(4)], ents[rng.below(ents.len())]);
            let author = if rng.below(4) == 0 { n[rng.below(3)] } else { top[&target] };
            let role = [Read, Write, Admin][rng.below(3)];
            let invite = [None, Some(Read), Some(Write), Some(Admin)][rng.below(4)].map(|i: Role| i.min(role));
            let until = (rng.below(3) == 0).then(|| osis_base::WallMs(k + rng.below(10) as u64));
            let e = (rng.below(4) != 0).then_some(Edge { role, until, invite, since: None });
            if member != target {
                w.set(author, target, member, e, 1 + k, &[]);
            }
        }
        let tl = Timeline::evaluate(&w.held());
        for x in &n {
            for t in &ents[3..] {
                for r in [Read, Write, Admin] {
                    let _ = valid(&tl, Point { ts: ts(0), node: *x, commit: cid(1) }, *t, r);
                }
            }
        }
    }
}
