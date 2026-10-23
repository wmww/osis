//! Roster snapshot production (spec/permissions.md §6): a roster snapshot carrying the roster
//! and ledger the timeline computes changes nothing, before or after compaction (the model's
//! `resnapshot_neutral`, generalized to every thing of random joint, edges and snapshot
//! histories, layer 2 included).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use common::*;
use membership_model::{edges, joint, snapshot, Rng};
use osis_core::Role::{Admin, Write};
use osis_core::{CommitId, Role, Tid};
use osis_perm::{At, Dots, Edge, MemoryHeldSet, Point, Timeline, WriteId};
use std::collections::{BTreeMap, BTreeSet};

const END_T: u64 = 50_000;

/// Everything a held set's timeline answers that a snapshot must not change.
#[derive(PartialEq, Debug)]
struct Answers {
    rosters: BTreeMap<Tid, BTreeMap<Tid, Edge>>,
    applied: BTreeSet<WriteId>,
    valid: Vec<bool>,
}

fn answers(held: &MemoryHeldSet, things: &[Tid], probes: &[Point], keep: &dyn Fn(&WriteId) -> bool) -> Answers {
    let tl = Timeline::evaluate(held);
    let strip = |r: BTreeMap<Tid, Edge>| r.into_iter().map(|(m, e)| (m, Edge { since: None, ..e })).collect();
    Answers {
        rosters: things.iter().map(|t| (*t, strip(tl.roster(t, At::END)))).collect(),
        applied: tl.applied().keys().filter(|w| keep(w)).copied().collect(),
        valid: probes
            .iter()
            .flat_map(|p| things.iter().flat_map(move |t| [Role::Write, Role::Admin].map(|r| (*t, r))).map(move |(t, r)| (*p, t, r)))
            .map(|(p, t, r)| tl.delta_valid(p, &t, "/doc", Dots::Commit, r) == osis_perm::Validity::Valid)
            .collect(),
    }
}

/// `author` (owner chain of `thing`) snapshots it at the end; nothing changes, and a node that
/// compacted `thing` at the snapshot answers the same, later audits and a demoter's own
/// demotions included.
static RESIDUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn neutral(w: &World, thing: Tid, author: Tid, things: &[Tid], probes: &[Point]) -> Option<String> {
    let tl = Timeline::evaluate(&w.held());
    let residue = common::residue(&tl);
    let state = tl.roster_state(&thing);
    let mut w2 = w.clone();
    let ledger = state.ledger.clone();
    let s = w2.snapshot_state(author, thing, state, END_T);
    // The thing's own earlier writes are replaced by the snapshot: compare everything else.
    let mut mine: BTreeSet<CommitId> = w.commits.iter().filter(|c| c.ops.iter().any(|o| o.0 == thing)).map(|c| c.id).collect();
    mine.extend(w.snaps.iter().filter(|x| x.thing == thing).map(|x| x.id));
    mine.insert(s);
    let keep = |x: &WriteId| !mine.contains(&x.commit());
    let before = answers(&w.held(), things, probes, &keep);
    let after = answers(&w2.held(), things, probes, &keep);
    let compacted = answers(&w2.compacted(thing, s), things, probes, &keep);
    if before == after && before == compacted {
        return None;
    }
    // a snapshot may repair sticky residue (models/tla/membership MC_sticky_snap): it only
    // undoes drops, never adds them, and only residue drops
    let undone: BTreeSet<WriteId> = after.applied.iter().chain(&compacted.applied).filter(|w| !before.applied.contains(w)).copied().collect();
    if !undone.is_empty() && before.applied.is_subset(&after.applied) && before.applied.is_subset(&compacted.applied) && undone.is_subset(&residue) {
        RESIDUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return None;
    }
    Some(format!("snapshot of {thing:?} changed\nbefore {before:?}\nafter  {after:?}\ncompacted {compacted:?}\nledger {ledger:#?}\ndropped {:?}\nnodes {:?}", tl.dropped(), w.commits.iter().map(|c| (c.id, c.author, c.t, c.ops.clone())).collect::<Vec<_>>()))
}

/// Content probes by every node at a few times, with random receipts.
fn probes(w: &mut World, nodes: &[Tid], rng: &mut Rng) -> Vec<Point> {
    let mut out = Vec::new();
    for &x in nodes {
        for _ in 0..2 {
            // HLC ts are unique per node: never at the ts of one of its own writes.
            let t = 1 + rng.below(9) as u64;
            if w.commits.iter().any(|c| c.author == x && c.t == t) || w.snaps.iter().any(|c| c.author == x && c.t == t) {
                continue;
            }
            let recv: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, if rng.below(2) == 0 { LATE } else { t + rng.below(4) as u64 })).collect();
            out.push(w.content(x, t, &recv));
        }
    }
    out
}

fn run_joint(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let h = joint::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.nodes);
        let (mut actors, mut top) = (Vec::new(), Vec::new());
        for o in &h.owners {
            let (owner, tp) = match *o {
                joint::Owner::Node(n) => (nodes[n], nodes[n]),
                joint::Owner::Actor(y) => (actors[y], top[y]),
            };
            actors.push(w.thing(owner));
            top.push(tp);
        }
        let ent = |e: usize| if e < h.nodes { nodes[e] } else { actors[e - h.nodes] };
        let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
        for (m, row) in h.genesis.iter().enumerate() {
            for (x, &r) in row.iter().enumerate() {
                if r != membership_model::Role::None {
                    let role = if r == membership_model::Role::Admin { Admin } else { Write };
                    w.set(top[x], actors[x], ent(m), edge(role), 0, &all0);
                }
            }
        }
        for (i, jw) in h.writes.iter().enumerate() {
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, t)| (*t, h.recv[i][n] as u64)).collect();
            let e = match jw.role {
                membership_model::Role::None => None,
                membership_model::Role::Admin => edge(Admin),
                _ => edge(Write),
            };
            w.commit_id(cid(jw.id), nodes[jw.author], jw.t as u64, &[(actors[jw.target], ent(jw.member), e)], &recv);
        }
        let ps = probes(&mut w, &nodes, &mut rng);
        for x in 0..actors.len() {
            if let Some(d) = neutral(&w, actors[x], top[x], &actors, &ps) {
                panic!("seed {seed:#x} sample {s}: {d}\n{h:?}");
            }
        }
    }
    eprintln!("{samples} histories; sticky-residue snapshots that repaired drops so far (all runs): {}", RESIDUE.load(std::sync::atomic::Ordering::Relaxed));
}

/// §6: re-snapshotting any actor of a random joint history (mutual membership, owner chains)
/// is neutral, compacted or not.
#[test]
fn joint_resnapshot_neutral() {
    run_joint(60, 0x5eed_0101);
}

#[test]
#[ignore = "tier 2"]
fn joint_resnapshot_neutral_large() {
    run_joint(20_000, 0x5eed_0102);
}

fn run_edges(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let h = edges::random_hist(&mut rng);
        let mut w = World::new();
        let nodes = w.nodes(h.n());
        let t = w.thing(nodes[0]);
        let me = |e: Option<edges::Edge>| {
            e.map(|e| Edge {
                role: match e.role {
                    membership_model::Role::Admin => Admin,
                    membership_model::Role::Write => Write,
                    _ => Role::Read,
                },
                until: (e.until != edges::NEVER).then_some(osis_core::WallMs(e.until as u64)),
                invite: match e.invite {
                    membership_model::Role::None => None,
                    membership_model::Role::Read => Some(Role::Read),
                    membership_model::Role::Write => Some(Write),
                    membership_model::Role::Admin => Some(Admin),
                },
                since: None,
            })
        };
        let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
        for (x, e) in h.genesis.iter().enumerate().skip(1) {
            if e.is_some() {
                w.set(nodes[0], t, nodes[x], me(*e), 0, &all0);
            }
        }
        for (i, ew) in h.writes.iter().enumerate() {
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
            let ops: Vec<(Tid, Tid, Option<Edge>)> = ew.ops.iter().map(|&(x, e)| (t, nodes[x], me(e))).collect();
            w.commit_id(cid(ew.id), nodes[ew.author], ew.t as u64, &ops, &recv);
        }
        let ps = probes(&mut w, &nodes, &mut rng);
        if let Some(d) = neutral(&w, t, nodes[0], &[t], &ps) {
            panic!("seed {seed:#x} sample {s}: {d}\n{h:?}");
        }
    }
    eprintln!("{samples} histories; sticky-residue snapshots that repaired drops so far (all runs): {}", RESIDUE.load(std::sync::atomic::Ordering::Relaxed));
}

/// §6: re-snapshotting a thing with `until`, invites, links and self-removals is neutral.
#[test]
fn edges_resnapshot_neutral() {
    run_edges(100, 0x5eed_0103);
}

#[test]
#[ignore = "tier 2"]
fn edges_resnapshot_neutral_large() {
    run_edges(30_000, 0x5eed_0104);
}

fn run_snapshot(samples: u64, seed: u64) {
    let seed = seeded(seed);
    let mut rng = Rng(seed);
    for s in 0..samples {
        let mut h = snapshot::random_hist(&mut rng);
        // Only ledgers perm produced are well formed; drop the model's random ones and its
        // records (probes stand in for them).
        for wr in &mut h.writes {
            wr.ledger.clear();
        }
        let keep: Vec<usize> = (0..h.writes.len()).filter(|&i| !h.writes[i].rec && (h.writes[i].snap.is_some() || h.writes[i].target != 0)).collect();
        h.writes = keep.iter().map(|&i| h.writes[i].clone()).collect();
        h.recv = keep.iter().map(|&i| h.recv[i].clone()).collect();
        let mut w = World::new();
        let nodes = w.nodes(h.n());
        let k = nodes[0];
        let p = w.thing(k);
        let g = w.thing(p);
        let all0: Vec<(Tid, u64)> = nodes.iter().map(|n| (*n, 0)).collect();
        let mr = |r: membership_model::Role| match r {
            membership_model::Role::Admin => Some(Admin),
            membership_model::Role::Write => Some(Write),
            membership_model::Role::Read => Some(Role::Read),
            membership_model::Role::None => None,
        };
        for (thing, roles) in [(p, &h.gp), (g, &h.gg)] {
            for (x, &r) in roles.iter().enumerate().skip(1) {
                if let Some(r) = mr(r) {
                    w.set(k, thing, nodes[x], edge(r), 0, &all0);
                }
            }
        }
        for (i, sw) in h.writes.iter().enumerate() {
            let thing = if sw.thing == snapshot::Thing::P { p } else { g };
            let recv: Vec<(Tid, u64)> = nodes.iter().enumerate().map(|(n, tn)| (*tn, h.recv[i][n] as u64)).collect();
            match &sw.snap {
                None => {
                    w.set(nodes[sw.author], thing, nodes[sw.target], mr(sw.role).map(Edge::new), sw.t as u64, &recv);
                }
                Some(roster) => {
                    let r: Vec<(Tid, Edge)> = roster.iter().enumerate().skip(1).filter_map(|(x, &rl)| mr(rl).map(|rl| (nodes[x], Edge::new(rl)))).collect();
                    w.snapshot(nodes[sw.author], thing, &r, sw.t as u64, &recv);
                }
            }
        }
        let ps = probes(&mut w, &nodes, &mut rng);
        for thing in [p, g] {
            if let Some(d) = neutral(&w, thing, k, &[p, g], &ps) {
                panic!("seed {seed:#x} sample {s}: {d}\n{h:?}");
            }
        }
    }
    eprintln!("{samples} histories; sticky-residue snapshots that repaired drops so far (all runs): {}", RESIDUE.load(std::sync::atomic::Ordering::Relaxed));
}

/// §6: re-snapshotting P (owning G) or G after churn, demotions and earlier snapshots is
/// neutral for G's writes and for content on both (the ledger keeps former devices' writes).
#[test]
fn snapshot_resnapshot_neutral() {
    run_snapshot(100, 0x5eed_0105);
}

#[test]
#[ignore = "tier 2"]
fn snapshot_resnapshot_neutral_large() {
    run_snapshot(30_000, 0x5eed_0106);
}

/// §6 ledger carried forward whole: a second snapshot keeps the first one's entries verbatim.
#[test]
fn ledger_carried_forward() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, d1, d2, d3) = (n[0], n[1], n[2], n[3]);
    let p = w.thing(k);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    let g1 = w.set(k, p, d1, edge(Admin), 0, &all);
    w.set(k, p, d2, edge(Admin), 0, &all);
    w.set(d2, p, d1, None, 5, &[]);
    let s1 = Timeline::evaluate(&w.held()).roster_state(&p);
    assert_eq!(s1.ledger.len(), 1);
    assert_eq!((s1.ledger[0].member, s1.ledger[0].role, s1.ledger[0].since), (d1, Admin, Some(Point { ts: ts(0), node: k, commit: g1 })));
    assert!(s1.ledger[0].frontier.is_some());
    w.snapshot_state(k, p, s1.clone(), 10);
    w.set(k, p, d3, edge(Write), 11, &[]);
    w.set(k, p, d2, edge(Write), 12, &[]);
    let s2 = Timeline::evaluate(&w.held()).roster_state(&p);
    assert_eq!(s2.ledger[0], s1.ledger[0]);
    assert_eq!(s2.ledger.len(), 2, "d2's admin tenure ended by the demotion to write");
    assert_eq!(s2.roster.get(&d2).map(|e| (e.role, e.since.map(|k| k.ts))), Some((Write, Some(ts(12)))));
    assert_eq!(s2.roster.get(&d3).map(|e| e.since.map(|k| k.ts)), Some(Some(ts(11))));
}

/// §6, §5.1: a tenure ended by self-removal and audited later by an explicit demotion of its
/// edge is an entry without a frontier plus an audit-only entry at the demotion's key, so the
/// replay audits where the walk did (after d1 also left the group it reached P through).
#[test]
fn later_audit_is_an_entry_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, d1) = (n[0], n[1]);
    let (p, a) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    let g = w.set(k, p, d1, edge(Admin), 0, &all);
    w.set(k, a, d1, edge(Admin), 0, &all);
    w.set(k, p, a, edge(Admin), 0, &all);
    let x = w.content(d1, 1, &[]);
    let leave = w.set(d1, p, d1, None, 2, &all);
    w.set(d1, a, d1, None, 3, &all);
    let rm = w.set(k, p, d1, None, 5, &all);
    let tl = Timeline::evaluate(&w.held());
    assert!(matches!(tl.delta_valid(x, &p, "/doc", Dots::Commit, Write), osis_perm::Validity::Invalid { .. }));
    let ledger = tl.roster_state(&p).ledger;
    let key = |t, node, commit| Point { ts: ts(t), node, commit };
    let shape: Vec<_> = ledger.iter().filter(|t| t.member == d1).map(|t| (t.role, t.since, t.until, t.frontier.is_some())).collect();
    assert_eq!(shape, vec![(Admin, Some(key(0, k, g)), key(2, d1, leave), false), (Admin, Some(key(5, k, rm)), key(5, k, rm), true)]);
    assert_eq!(neutral(&w, p, k, &[p, a], &[x]), None);
}

/// §6, §5.1: a demoter that reaches the member it demoted keeps its standing until the next
/// explicit write on that edge; the ledger entry's key node is that demoter, and the next
/// write's audit is an entry of its own.
#[test]
fn own_demotion_replayed_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, d2) = (n[0], n[1]);
    let (p, a) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, a, edge(Admin), 0, &all);
    w.set(k, a, d2, edge(Admin), 0, &all);
    w.set(k, p, d2, edge(Admin), 0, &all);
    let x = w.content(d2, 1, &[]);
    // explicit (d2 also holds edge admin on P), d2 exempt as the demoter
    w.set(d2, p, a, None, 2, &all);
    w.set(d2, p, d2, None, 3, &all);
    w.set(k, p, a, None, 5, &all);
    let tl = Timeline::evaluate(&w.held());
    assert!(matches!(tl.delta_valid(x, &p, "/doc", Dots::Commit, Write), osis_perm::Validity::Invalid { .. }));
    let ledger = tl.roster_state(&p).ledger;
    assert!(ledger.iter().any(|t| t.member == a && t.since.is_some_and(|s| s == t.until) && t.until.node == k && t.frontier.is_some()), "{ledger:?}");
    assert_eq!(neutral(&w, p, k, &[p, a], &[x]), None);
}

/// §6: two commits of one node at one ts (a shared key used from two devices) that demote a
/// member and re-grant it are told apart by the commit ID in ledger keys: the replay audits at
/// the demotion, so the member's dropped edge write below the thing stays dropped after a
/// re-snapshot, compacted or not.
#[test]
fn same_ts_demote_regrant_replayed_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, m, z) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let q = w.thing(p);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, m, edge(Admin), 0, &all);
    w.set(m, q, z, edge(Write), 1, &[]);
    // C1 then C2 (IDs ascending): one key actor, one ts
    let c1 = w.set(k, p, m, None, 5, &all);
    let c2 = w.set(k, p, m, edge(Admin), 5, &all);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!(tl.role(&z, &q, At::END), None, "the walk drops m's grant");
    let state = tl.roster_state(&p);
    assert!(state.ledger.iter().any(|t| t.member == m && t.until.commit == c1 && t.frontier.is_some()), "{:?}", state.ledger);
    assert_eq!(state.roster.get(&m).and_then(|e| e.since).map(|k| k.commit), Some(c2));
    let mut w2 = w.clone();
    let s = w2.snapshot_state(k, p, state, END_T);
    for held in [w2.held(), w2.compacted(p, s)] {
        let after = Timeline::evaluate(&held);
        assert_eq!(after.role(&z, &q, At::END), None);
        assert_eq!(after.role(&m, &p, At::END), Some(Admin));
    }
    assert_eq!(neutral(&w, p, k, &[p, q], &[]), None);
}

/// §6 epoch start: n1 removes n2 from P at 4, but K's removal of n1 at 18 drops that removal,
/// so n2's snapshot of G at 6 is G's epoch start, as without the dropped write (it used to be
/// rejected for good when found inapplicable before the drop), and a re-snapshot of P keeps it.
#[test]
fn start_after_dropped_write_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(4);
    let (k, n1, n2, n3) = (n[0], n[1], n[2], n[3]);
    let p = w.thing(k);
    let g = w.thing(p);
    let all0: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, n1, edge(Admin), 0, &all0);
    w.set(k, p, n2, edge(Admin), 0, &all0);
    let r = |v: [u64; 4]| -> Vec<(Tid, u64)> { n.iter().zip(v).map(|(a, b)| (*a, b)).collect() };
    w.set(k, p, n1, None, 18, &r([18, LATE, LATE, LATE]));
    let s = w.snapshot(n2, g, &[(n1, Edge::new(Admin)), (n2, Edge::new(Admin)), (n3, Edge::new(Write))], 6, &r([5, LATE, 5, 5]));
    let rm = w.set(n1, p, n2, None, 4, &r([LATE, 4, LATE, LATE]));
    let tl = Timeline::evaluate(&w.held());
    assert!(dropped_commits(&tl).contains(&rm));
    assert_eq!(tl.epoch_start(&g), Some(s));
    assert_eq!(Timeline::evaluate(&w.held_without(&[rm].into_iter().collect())).epoch_start(&g), Some(s));
    let mut w2 = w.clone();
    w2.snapshot_state(k, p, tl.roster_state(&p), END_T);
    assert_eq!(Timeline::evaluate(&w2.held()).epoch_start(&g), Some(s));
    assert_eq!(neutral(&w, p, k, &[p, g], &[]), None);
    assert_eq!(neutral(&w, g, k, &[p, g], &[]), None);
}

/// §6 epoch start through mutual membership: B (owned by A) is an admin of A, so n2, admin
/// of B, has owner-chain authority on B through B itself. Its snapshot of B at 5 leaving n2
/// out applies only while it is not B's start, so the rounds do not settle and it is
/// excluded: with no other snapshot B has no start; with an older one keeping n2 (at 3), that
/// one is the start. A snapshot keeping n2 is the start at once.
#[test]
fn self_withdrawing_start_excluded_spec_permissions_6() {
    for (newest_keeps, older) in [(false, false), (false, true), (true, false)] {
        let mut w = World::new();
        let n = w.nodes(3);
        let (k, n2, n3) = (n[0], n[1], n[2]);
        let a = w.thing(k);
        let b = w.thing(a);
        let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
        w.set(k, a, b, edge(Admin), 0, &all);
        w.set(k, b, n2, edge(Admin), 0, &all);
        let keeping = [(n3, Edge::new(Write)), (n2, Edge::new(Admin))];
        let s0 = older.then(|| w.snapshot(n2, b, &keeping, 3, &all));
        let s1 = w.snapshot(n2, b, if newest_keeps { &keeping } else { &keeping[..1] }, 5, &all);
        let tl = Timeline::evaluate(&w.held());
        let want = if newest_keeps { Some(s1) } else { s0 };
        assert_eq!(tl.epoch_start(&b), want, "newest keeps n2: {newest_keeps}, older: {older}");
        assert_eq!(tl.role(&n2, &b, At::END), Some(Admin));
    }
}

/// §6: a ledger entry replays just after the commit its key names: A's self-removal from N
/// and grant of X on M in one commit (A admin of M through N) keeps X's grant after a
/// re-snapshot of N, as in the full history.
#[test]
fn ledger_entry_after_its_commit_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, a, x) = (n[0], n[1], n[2]);
    let (tn, tm) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|y| (*y, 0)).collect();
    w.set(k, tn, a, edge(Admin), 0, &all);
    w.set(k, tm, tn, edge(Admin), 0, &all);
    w.commit(a, 2, &[(tn, a, None), (tm, x, edge(Write))], &all);
    let tl = Timeline::evaluate(&w.held());
    assert_eq!(tl.role(&x, &tm, At::END), Some(Write));
    assert_eq!(neutral(&w, tn, k, &[tn, tm], &[]), None);
}

/// §6: an expiry by `until` is keyed before every write at its ts: an explicit demotion at
/// that ts by a node whose tid sorts below the member's replays as the walk ordered it.
#[test]
fn expiry_before_same_ts_write_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, d, m) = (n[0], n[1], n[2]);
    assert!(d < m);
    let p = w.thing(k);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, d, edge(Admin), 0, &all);
    w.set(k, p, m, edge_inv(Write, None, Some(5)), 0, &all);
    let x = w.content(m, 1, &[]);
    let y = w.content(m, 2, &[(d, 3)]);
    w.set(d, p, m, None, 5, &all);
    let tl = Timeline::evaluate(&w.held());
    let valid = |pt| tl.delta_valid(pt, &p, "/doc", Dots::Commit, Write) == osis_perm::Validity::Valid;
    assert_eq!((valid(x), valid(y)), (false, true), "d's removal audits the expired edge");
    assert_eq!(neutral(&w, p, k, &[p], &[x, y]), None);
}

/// §6: a demoter's kept admin standing (it reaches the member it lowered to write) is audited
/// by another node's write→write on that edge, which splits the write tenure in force.
#[test]
fn kept_standing_split_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(2);
    let (k, d2) = (n[0], n[1]);
    let (p, a) = (w.thing(k), w.thing(k));
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, a, edge(Admin), 0, &all);
    w.set(k, a, d2, edge(Admin), 0, &all);
    w.set(k, p, d2, edge(Admin), 0, &all);
    let x = w.content(d2, 1, &[]);
    w.set(d2, p, a, edge(Write), 2, &all);
    w.set(d2, p, d2, None, 3, &all);
    w.set(k, p, a, edge(Write), 5, &all);
    let tl = Timeline::evaluate(&w.held());
    let ledger = tl.roster_state(&p).ledger;
    assert!(ledger.iter().any(|t| t.member == a && t.until.node == k && t.until.ts == ts(5) && t.frontier.is_some()), "{ledger:?}");
    assert_eq!(neutral(&w, p, k, &[p, a], &[x]), None);
}

/// §6 bad ledgers: a frontier entry keyed to the member itself, a zero-tid key, `since` after
/// `until`, an audit-only entry: evaluated without panic, granting no role after the start.
#[test]
fn adversarial_ledger_grants_nothing_spec_permissions_6() {
    let mut w = World::new();
    let n = w.nodes(3);
    let (k, m, z) = (n[0], n[1], n[2]);
    let p = w.thing(k);
    let zero = Tid::from_bytes([0; 15]);
    let all: Vec<(Tid, u64)> = n.iter().map(|x| (*x, 0)).collect();
    w.set(k, p, m, edge(Admin), 0, &all);
    w.set(m, p, z, edge(Write), 1, &[]);
    let ledger = vec![
        (m, Admin, Some((0, k, None)), (3, m, None), true),
        (m, Write, Some((4, k, None)), (4, zero, None), true),
        (z, Admin, Some((7, k, None)), (2, k, None), true),
        (z, Write, Some((6, k, None)), (6, k, None), true),
        (m, Admin, None, (8, zero, None), false),
    ];
    w.snapshot_l(k, p, &[], &ledger, 10, &all);
    let tl = Timeline::evaluate(&w.held());
    for x in [m, z] {
        assert_eq!(tl.role(&x, &p, At::END), None);
    }
    let _ = tl.roster_state(&p);
}
