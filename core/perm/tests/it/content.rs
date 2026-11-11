//! Layer 2 (spec/permissions.md §5.2; spec/commits.md §4 overlap): scenarios of
//! core/test/roles-model `content`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use osis_base::Role::{Admin, Write};
use osis_base::{Role, Tid};
use osis_perm::{Edge, Point, Timeline, Validity};

fn valid(tl: &Timeline, p: Point, thing: Tid, required: Role) -> bool {
    tl.delta_valid(p, &thing, required) == Validity::Valid
}

/// O (node 0) is first admin of N; A (node 1) admin, X (node 2) writer.
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
            let by = tl.delta_valid(e1, &d, Write);
            assert_eq!(by, Validity::Invalid { by: Some(Point { ts: ts(4), node: a, commit: r }) });
        }
    }
}

/// §5.2: `until` audits nothing: edits inside the edge's life stand, later ones do not; the
/// next explicit demotion audits as if the holder still held write.
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

/// §5.2 through the record chain: a node removed from P by a node that had not received its
/// write on G (first admin P) loses it; one it had received stands.
#[test]
fn node_removal_reaches_things_below() {
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

/// §5.2: a re-grant validates a write made in the gap; a later removal judges it by its own
/// frontier.
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

/// §5.2: a frontier saves what it lists whatever the order: X's write stamped after A's
/// removal R2 (received by a header read, which does not advance A's clock) stands though a
/// later removal by O, who never received it, follows; unlisted, it falls.
#[test]
fn earlier_removal_lists_write_stamped_after_it_spec_permissions_5_2() {
    for seen in [false, true] {
        let (mut w, n, d) = doc();
        let (o, a, x) = (n[0], n[1], n[2]);
        w.set(a, d, x, None, 2, &[]);
        w.set(a, d, x, edge(Write), 4, &[]);
        let recv: Vec<(Tid, u64)> = if seen { vec![(a, 5)] } else { vec![] };
        let late = w.content(x, 9, &recv);
        w.set(a, d, x, None, 6, &[]);
        w.set(a, d, x, edge(Write), 10, &[]);
        w.set(o, d, x, None, 12, &[]);
        assert_eq!(valid(&Timeline::evaluate(&w.held()), late, d, Write), seen, "seen {seen}");
    }
}

/// §5.2 re-grant makes writes valid *again*: a write before X first held the role stays
/// invalid after X is granted (review finding), one inside a later gap is restored.
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

/// §5.2 with §5.1 "as if the holder still held the role" (deliberate): a write after `until`
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

/// Where a node first held a role (`first_held`, a replay of the node's roles over the history) is
/// what a search at every change finds: random record trees, actors as holders, edges with
/// `until` and invites, most writes by the target's key actor. Debug builds compare the two at
/// every call.
#[cfg(debug_assertions)]
#[test]
fn regrant_replay_equals_search() {
    use osis_base::Role::Read;
    let mut rng = roles_model::Rng(0);
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
            let (target, holder) = (ents[3 + rng.below(4)], ents[rng.below(ents.len())]);
            let author = if rng.below(4) == 0 { n[rng.below(3)] } else { top[&target] };
            let role = [Read, Write, Admin][rng.below(3)];
            let invite = [None, Some(Read), Some(Write), Some(Admin)][rng.below(4)].map(|i: Role| i.min(role));
            let until = (rng.below(3) == 0).then(|| osis_base::WallMs(k + rng.below(10) as u64));
            let e = (rng.below(4) != 0).then_some(Edge { role, until, invite, tied: crate::common::tie_if(until.is_some() != invite.is_some()) });
            if holder != target {
                w.set(author, target, holder, e, 1 + k, &[]);
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

/// §5.2 Addenda, §5.5: the addenda fixpoint runs through every account's epochs. X's addendum
/// (at an epoch rotation r1 closed) saves Y's write (at an epoch r2 closed) only once A's
/// addendum against r1 saves X's; without it, or saving itself, X's addendum is invalid.
#[test]
fn addenda_fixpoint_runs_through_closed_epochs_spec_permissions_5_5() {
    use osis_perm::{Addendum, EpochStanding};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    let (mut w, n, d) = doc();
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(n[0], d, n[3], edge(Write), 0, &all);
    let (a, x, y) = (n[1], n[2], n[3]);
    let (r1, r2) = (cid(9001), cid(9002));
    let wy = w.content(y, 3, &[]);
    let ax = w.content(x, 5, &[]);
    let aa = w.content(a, 6, &[]);
    let tl = Timeline::evaluate(&w.held());
    let names = |r, c: osis_base::CommitId| (r, Arc::new(BTreeSet::from([c])));
    let by_x = Addendum { point: ax, entries: vec![names(r2, wy.commit), names(r1, ax.commit)] };
    let by_a = Addendum { point: aa, entries: vec![names(r1, ax.commit)] };
    let standing = |c: &osis_base::CommitId| match *c {
        c if c == ax.commit => EpochStanding::Closed(BTreeSet::from([r1])),
        c if c == wy.commit => EpochStanding::Closed(BTreeSet::from([r2])),
        _ => EpochStanding::Counts,
    };
    let v = tl.vouching(&d, &[by_x.clone(), by_a], standing);
    assert!(v.valid(&ax.commit) && v.valid(&aa.commit));
    assert!(v.saves(&wy.commit, &BTreeSet::from([r2])), "X's saved addendum saves Y's write");
    assert!(!v.saves(&wy.commit, &BTreeSet::from([r1])), "only against a closer of its epoch");
    let alone = tl.vouching(&d, &[by_x], standing);
    assert!(!alone.valid(&ax.commit), "an addendum at a closed epoch does not save itself");
    assert!(!alone.saves(&wy.commit, &BTreeSet::from([r2])));
}
