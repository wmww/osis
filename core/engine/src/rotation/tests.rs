//! Rotation tests (spec/permissions.md §3, spec/crypto.md §4).

#![allow(clippy::unwrap_used)]
use crate::Mutation;
use crate::flows::{Demotion, PreSync};
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid, WallMs};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Delivers every commit of peer `from` to peer `to` without the `secrets.0` deltas of `x`
/// (what a node that does not read `x` gets of them: certificates).
pub(super) fn deliver_without_secrets(lp: &mut LocalPeer, from: usize, to: usize, x: Tid) {
    for pk in lp.packages(from).unwrap() {
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai, _| b.header.aspects.get(ai).is_some_and(|a| a.tid == x && a.ak.as_str() == "secrets.0"));
        let _ = lp.peers[to].engine.ingest(&cut.encode(), pk.blobs.clone());
    }
}

/// Peers: 0 = the owner of group `t`, 1 = W (a writer, then removed: rotation R1 of read
/// and write), 2 = P (an admin), 3 = N (an admin when `n_first`, else granted later by the
/// caller). Returns R1's commits.
fn removed_writer(seed: u64, n_first: bool) -> (LocalPeer, Tid, Vec<osis_base::CommitId>) {
    let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let t = group(&mut lp, 0);
    let (w, p, n) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&t, &p, &edge(Role::Admin)).unwrap();
    if n_first {
        lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let r1 = lp.peers[0].engine.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Synced, keep: None }).unwrap().commits;
    (lp, t, r1)
}

/// The roles of `t` peer `i` may not encrypt under now (no rotation first).
pub(super) fn blocked_at(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<Role> {
    lp.peers[i].engine.run(|tx| super::blocked_roles(tx, &tx.core.id.tid(), &t)).unwrap()
}

/// Whether every holder of each of `actors` with key access, at peer `i`, holds a box at each
/// current epoch of its roles (holders without key access are boxed nothing).
pub(super) fn all_boxed(lp: &mut LocalPeer, i: usize, actors: &[Tid]) -> bool {
    actors.iter().all(|t| {
        let e = lp.peers[i].engine.epochs(t).unwrap();
        let s = lp.peers[i].engine.get_typed(t, &ct::SECRETS).unwrap().unwrap();
        let core = &mut lp.peers[i].engine.core;
        let ms: Vec<osis_keys::Holder> = core.key_holders(t).into_iter().filter(|(h, _)| super::members::keyed(core, t, h)).map(|(holder, role)| osis_keys::Holder { holder, role }).collect();
        osis_keys::reseal_needed(&s, &e, &ms).is_empty()
    })
}

fn keys_secrets() -> [osis_base::Ak; 2] {
    ["keys.0", "secrets.0"].map(|k| osis_base::Ak::new(k).unwrap())
}

// spec/crypto.md §4 (covers by names, carried in the history box): N, granted admin after the
// owner compacted and dropped R1's bodies (R1 removed writer W), holds the read epoch's history
// box from the `secrets.0` snapshot, so the epoch covers W's departure there: no rotation, as
// when N holds R1.
#[test]
fn compacted_rotation_covers_its_names_spec_crypto_4() {
    for compact in [true, false] {
        let (mut lp, t, r1) = removed_writer(941, false);
        if compact {
            for k in keys_secrets() {
                lp.peers[0].engine.snapshot(&t, &k).unwrap().unwrap();
                for c in &r1 {
                    if lp.peers[0].engine.body_not_dropped(c, &t, &k) {
                        lp.peers[0].engine.drop_body(c, &t, &k).unwrap();
                    }
                }
            }
        }
        let n = lp.peers[3].engine.tid();
        lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
        lp.sync(0, 3).unwrap();
        let before = newest_read(&lp, 3, t);
        assert!(before.is_some(), "N holds the read epoch");
        assert!(lp.peers[3].engine.departures(&t).unwrap().iter().any(|d| d.holder == lp.peers[1].engine.tid()), "N knows W left");
        assert!(blocked_at(&mut lp, 3, t).is_empty(), "covered (compacted {compact})");
        assert!(lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "no extra rotation");
        assert!(blocked_at(&mut lp, 0, t).is_empty());
    }
}

// spec/crypto.md §4, spec/permissions.md §5.2: N drops R1's `keys.0` body under admin P's
// compaction snapshot S; the owner then demotes P with a frontier not listing S, so S turns
// invalid and that body is missing again at N (R1's `secrets.0` still held): the read epoch
// still covers what its names name (W's departure); P's demotion rotates read anyway.
#[test]
fn rotation_missing_again_covers_its_names_spec_crypto_4() {
    let (mut lp, t, r1) = removed_writer(942, true);
    lp.sync_all().unwrap();
    let p = lp.peers[2].engine.tid();
    let k = osis_base::Ak::new("keys.0").unwrap();
    let s = lp.peers[2].engine.snapshot(&t, &k).unwrap().unwrap();
    let pk = lp.peers[2].engine.package(&s).unwrap().unwrap();
    lp.deliver(3, &pk).unwrap();
    for c in &r1 {
        let e = &mut lp.peers[3].engine;
        if e.body_not_dropped(c, &t, &k) && e.covered(&s, c, &t, &k).unwrap() == Some(true) {
            e.drop_body(c, &t, &k).unwrap();
        }
    }
    assert!(r1.iter().any(|c| !lp.peers[3].engine.body_not_dropped(c, &t, &k)), "R1's keys.0 dropped at N");
    assert!(blocked_at(&mut lp, 3, t).is_empty(), "the dropped rotation stays known");
    lp.peers[0].engine.demote(&t, &Demotion { holder: p, new: Some(edge(Role::Read)), presync: PreSync::Synced, keep: None }).unwrap();
    lp.sync(0, 3).unwrap();
    assert!(!lp.peers[3].engine.core.ix.commits.get(&s).unwrap().valid.iter().any(|v| *v), "S invalid at N");
    assert!(blocked_at(&mut lp, 3, t).is_empty(), "R1 missing again: still covered by names");
    assert!(lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "no extra rotation");
}

/// A thing of peer `i`'s with secrets of its own.
pub(super) fn group(lp: &mut LocalPeer, i: usize) -> Tid {
    let me = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    let g = lp.peers[i].engine.new_thing(&mut m, me);
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.give_own_secrets(&g).unwrap();
    g
}

pub(super) fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None, tied: None }
}

pub(super) fn newest_read(lp: &LocalPeer, i: usize, t: Tid) -> Option<osis_crypto::Epoch> {
    lp.peers[i].engine.epochs(&t).and_then(|e| e.read.newest_held().map(|x| x.0))
}

pub(super) struct Rng(pub(super) u64);
impl Rng {
    pub(super) fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// Every (actor, role, epoch) of `actors` a party holding `known` opens from the `secrets.0`
/// peer `i` holds of them: a box to `party` itself, or to a holder at a keyset (sealed) or
/// secret (symmetric) epoch known, transitively. What a departed party that kept its secrets
/// can read, whatever its own node does.
pub(super) fn openable(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, mut known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
    use osis_keys::aspects::from_schema;
    let all: Vec<(Tid, ct::Secrets)> = actors.iter().filter_map(|a| lp.peers[i].engine.get_typed(a, &ct::SECRETS).unwrap().map(|s| (*a, s))).collect();
    // boxes to the party itself (a key actor)
    if let Some(p) = lp.peers.iter().find(|p| p.engine.tid() == party) {
        let seed = p.engine.core.id.seed().clone();
        for (a, s) in &all {
            for o in osis_keys::open_boxes(a, s, &osis_keys::Opener::KeyActor { holder: party, seed: &seed }).0 {
                known.insert((*a, o.role, o.epoch));
            }
        }
    }
    loop {
        let n = known.len();
        for (a, s) in &all {
            for (k, b) in &s.boxes {
                let Ok(e) = from_schema(&k.epoch) else { continue };
                let via = match b {
                    ct::SecretBox::Sealed(sb) => sb.keyset.as_ref().and_then(|x| from_schema(x).ok()),
                    ct::SecretBox::Symmetric(sb) => from_schema(&sb.epoch).ok(),
                };
                if k.holder == party || via.is_some_and(|x| known.contains(&(k.holder, k.role, x))) {
                    known.insert((*a, k.role, e));
                }
            }
        }
        if known.len() == n {
            return known;
        }
    }
}

/// The epochs of `actors` whose secrets peer `i` holds.
pub(super) fn held_by(lp: &LocalPeer, i: usize, actors: &[Tid]) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
    let mut out = BTreeSet::new();
    for a in actors {
        if let Some(e) = lp.peers[i].engine.epochs(a) {
            for r in osis_keys::ROLES {
                out.extend(e.role(r).held().map(|(ep, _)| (*a, r, ep)));
            }
        }
    }
    out
}

/// Peer `i`'s newest read epoch of each of `actors` that `party` opens from `known`.
pub(super) fn leaked(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> Vec<Tid> {
    let o = openable(lp, i, actors, party, known);
    actors.iter().filter(|t| newest_read(lp, i, **t).is_some_and(|e| o.contains(&(**t, Role::Read, e)))).copied().collect()
}

/// A complete pass of every actor's labels (re-seal decisions in tests).
pub(super) struct Pass;
impl crate::flows::SyncState for Pass {
    fn complete_pass(&self, _: &Tid) -> bool {
        true
    }
}

/// Rounds of every peer of `admins` acting alone on every actor of `actors` (the cascade,
/// then the re-seal trigger), synced after each, until nothing changes; the rounds taken.
pub(super) fn settle(lp: &mut LocalPeer, admins: &[usize], actors: &[Tid]) -> usize {
    for round in 0..8 {
        let mut n = 0;
        for &p in admins {
            for x in actors {
                n += lp.peers[p].engine.ensure_rotated(x).unwrap().0.commits.len();
                n += lp.peers[p].engine.reseal_due(x, &Pass).unwrap().commits.len();
            }
            lp.sync_all().unwrap();
        }
        if n == 0 {
            return round;
        }
    }
    panic!("no fixpoint in 8 rounds");
}

/// Peer `i` rotates `roles` of `a` as a malicious writer would: boxing every current holder,
/// itself only at `keep` (the role it is about to keep), so the box rule finds no box for it
/// at the roles it leaves, while it holds the new secrets.
fn rotate_unboxed(lp: &mut LocalPeer, i: usize, a: Tid, roles: &[Role], keep: Option<Role>) {
    let me = lp.peers[i].engine.tid();
    let roles: BTreeSet<Role> = roles.iter().copied().collect();
    lp.peers[i]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let holders = super::recipients(tx, &tx.core.id.tid(), &a, &[(me, keep)])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let rot = super::rotation_into(tx, &mut m, a, &roles, &held, &holders, &[])?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, a, &rot)
        })
        .unwrap();
}

// spec/crypto.md §4 (covers by names): Alice's thing N, her tag T shared with Bob; T a writer
// of N, then removed, then granted read again: her removal's rotation names T's departure, so
// it covers it and the re-grant goes through without another rotation.
#[test]
fn regrant_after_tag_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 944, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let bob = lp.peers[1].engine.tid();
    let tag = group(&mut lp, 0);
    let n = group(&mut lp, 0);
    lp.peers[0].engine.grant(&tag, &bob, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.demote(&n, &Demotion { holder: tag, new: None, presync: PreSync::Synced, keep: None }).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Read)).unwrap();
    assert!(lp.peers[0].engine.ensure_rotated(&n).unwrap().1.is_empty(), "covered");
}

// spec/permissions.md §3 (re-seal fixpoint), spec/crypto.md §4 (forks, merge) (churn seeds
// 140170 and 140188 shrunk: a node re-sealed itself on every pass): A and D rotate G's write
// concurrently, D's rotation leaving writer B out, so B lacks a box and the secret at D's fork.
// B, holding only A's fork, writes no re-seal of itself (before: one boxing A's fork alone on
// every pass); A, holding both, re-seals B once, a box at each fork, or, as the fork's merger
// (rule 3: re-sealing encrypts under G), merges it, boxing B.
#[test]
fn forked_role_reseal_reaches_fixpoint_spec_permissions_3() {
    let mut lp = LocalPeer::new(3, 1141, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (b, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    rotate_unboxed(&mut lp, 0, g, &[Role::Write], Some(Role::Write));
    lp.peers[2]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let holders = super::recipients(tx, &tx.core.id.tid(), &g, &[(b, Some(Role::Read))])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let rot = super::rotation_into(tx, &mut m, g, &[Role::Write].into(), &held, &holders, &[])?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, g, &rot)
        })
        .unwrap();
    lp.sync_all().unwrap();
    let e = lp.peers[1].engine.epochs(&g).unwrap();
    assert_eq!(e.write.current().len(), 2, "write forked");
    assert_eq!(e.write.current().iter().filter(|x| e.write.secret(x).is_some()).count(), 1, "B holds one fork");
    for pass in 0..3 {
        assert!(lp.peers[1].engine.reseal_due(&g, &Pass).unwrap().commits.is_empty(), "B re-sealed itself on pass {pass}");
        lp.sync_all().unwrap();
    }
    assert_eq!(lp.peers[0].engine.reseal_due(&g, &Pass).unwrap().commits.len(), 1, "A re-seals B");
    lp.sync_all().unwrap();
    for p in 0..3 {
        assert!(lp.peers[p].engine.reseal_due(&g, &Pass).unwrap().commits.is_empty(), "peer {p}: fixpoint");
        assert!(all_boxed(&mut lp, p, &[g]), "peer {p}: every holder boxed");
    }
    let e = lp.peers[1].engine.epochs(&g).unwrap();
    assert!(e.write.current().iter().all(|x| e.write.secret(x).is_some()), "B holds every current secret");
}

// spec/permissions.md §3 (re-seal: a node holding one fork re-seals at it): B and D, writers of
// G, rotate its write concurrently, each leaving the other out, so each holds only its own
// fork; A, the one node holding both, never re-seals. B and D re-seal each other at the fork
// each holds and reach a fixpoint with both forks held (requiring every fork's secret of a
// re-sealer stranded them until A).
#[test]
fn forked_role_resealed_without_a_node_holding_every_fork_spec_permissions_3() {
    let mut lp = LocalPeer::new(3, 1142, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (b, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    for (i, other) in [(1, d), (2, b)] {
        lp.peers[i]
            .engine
            .run(|tx| {
                let held = tx.core.epochs(&g).unwrap();
                let holders = super::recipients(tx, &tx.core.id.tid(), &g, &[(other, Some(Role::Read))])?.ok_or(super::SEAL_WAITS)?;
                let mut m = Mutation::new();
                let rot = super::rotation_into(tx, &mut m, g, &[Role::Write].into(), &held, &holders, &[])?;
                crate::engine::Engine::commit_tx(tx, m)?;
                super::record(tx, g, &rot)
            })
            .unwrap();
    }
    lp.sync_all().unwrap();
    for p in [1, 2] {
        let e = lp.peers[p].engine.epochs(&g).unwrap();
        assert_eq!(e.write.current().len(), 2, "write forked");
        assert_eq!(e.write.current().iter().filter(|x| e.write.secret(x).is_some()).count(), 1, "peer {p} holds one fork");
    }
    for _ in 0..3 {
        for p in [1, 2] {
            lp.peers[p].engine.reseal_due(&g, &Pass).unwrap();
        }
        lp.sync_all().unwrap();
    }
    for p in [1, 2] {
        assert!(lp.peers[p].engine.reseal_due(&g, &Pass).unwrap().commits.is_empty(), "peer {p}: fixpoint");
        let e = lp.peers[p].engine.epochs(&g).unwrap();
        assert!(e.write.current().iter().all(|x| e.write.secret(x).is_some()), "peer {p} holds both forks");
    }
    for p in 0..3 {
        assert!(all_boxed(&mut lp, p, &[g]), "peer {p}: every holder boxed at both forks");
    }
}

// spec/permissions.md §3 (re-seal), spec/crypto.md §4 (forks; supersession read from the
// commits): random concurrent rotations of G by random holders, each leaving out a random
// subset of the others, give random fork shapes and random subsets of secrets per node; rounds
// of every node's re-seal trigger (all on one state, or synced after each node) then reach a
// fixpoint within a bound (main before reseal-livelock: no fixpoint at 62 of 300 seeds), where
// the re-seal invariant holds (`reseal_candidates`): every node counts the same current epochs,
// and every holder of a role holds every current epoch of it that any node holds.
#[test]
fn forked_reseals_settle_spec_permissions_3() {
    forked_stats(osis_base::testenv::run_seeds("rotation::tests::forked_reseals_settle_spec_permissions_3", &[0, 1, 2], false, forked_replay, forked_reseals));
}

// Seed 3: peer 0 rotates admin while peer 2 rotates read leaving peer 0 out, so peer 0 is
// re-sealed at read's new epoch. Seed 75: peer 0 rotates admin unaware of peer 3's concurrent
// admin fork, which stays current at every node and is re-sealed to peer 0.
#[test]
fn forked_reseals_settle_issue_seeds_spec_permissions_3() {
    forked_reseals(3);
    forked_reseals(75);
}

/// Seeds: OSIS_FORKS_START, OSIS_FORKS_SEEDS (default 0..100).
#[test]
#[ignore = "tier 2"]
fn forked_reseals_settle_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORKS_START", "OSIS_FORKS_SEEDS", osis_base::testenv::large(0..100));
    forked_stats(s.run("rotation::tests::forked_reseals_settle_large", forked_replay, forked_reseals));
}

fn forked_replay(s: u64) -> String {
    format!("OSIS_FORKS_START={s} OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::forked_reseals_settle_large -- --ignored --exact")
}

fn forked_stats(runs: Vec<(bool, usize)>) {
    let forked = runs.iter().filter(|r| r.0).count();
    let rounds = runs.iter().map(|r| r.1).max().unwrap_or(0);
    eprintln!("forked re-seals: {forked} runs forked, at most {} rounds to settle", rounds + 1);
}

/// One seed of `forked_reseals_settle_*`: whether it forked, and the re-seal rounds to settle.
fn forked_reseals(seed: u64) -> (bool, usize) {
    const N: usize = 4;
    let roles = [Role::Read, Role::Write, Role::Admin];
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(N, 2_000 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    let mut role = [Role::Admin; N];
    for i in 1..N {
        role[i] = roles[rng.next(3) as usize];
        lp.peers[0].engine.grant(&g, &tids[i], &edge(role[i])).unwrap();
    }
    lp.sync_all().unwrap();
    for _ in 0..2 + rng.next(4) {
        // a few rotators act on the same state: their rotations fork
        for (i, &ri) in role.iter().enumerate() {
            if ri < Role::Write || rng.next(2) == 0 {
                continue;
            }
            let rot: BTreeSet<Role> = roles.into_iter().filter(|r| *r <= ri && rng.next(2) == 0).collect();
            if rot.is_empty() {
                continue;
            }
            let skip: Vec<(Tid, Option<Role>)> = (0..N).filter(|j| *j != i && rng.next(3) == 0).map(|j| (tids[j], None)).collect();
            // refused (a rotated role's secret not held) changes nothing
            let _ = lp.peers[i].engine.run(|tx| {
                let held = tx.core.epochs(&g).unwrap();
                let holders = super::recipients(tx, &tx.core.id.tid(), &g, &skip)?.ok_or(super::SEAL_WAITS)?;
                let mut m = Mutation::new();
                let r = super::rotation_into(tx, &mut m, g, &rot, &held, &holders, &[])?;
                crate::engine::Engine::commit_tx(tx, m)?;
                super::record(tx, g, &r)
            });
        }
        if rng.next(2) == 0 {
            lp.sync_all().unwrap();
        } else {
            for _ in 0..3 {
                let (a, b) = (rng.next(N as u64) as usize, rng.next(N as u64) as usize);
                if a != b {
                    lp.sync(a, b).unwrap();
                }
            }
        }
    }
    lp.sync_all().unwrap();
    let e0 = lp.peers[0].engine.epochs(&g).unwrap();
    let forked = roles.iter().any(|r| e0.role(*r).current().len() > 1);
    let mut settled = None;
    for round in 0..12 {
        let mut n = 0;
        let concurrent = rng.next(2) == 0;
        for p in 0..N {
            n += lp.peers[p].engine.reseal_due(&g, &Pass).unwrap().commits.len();
            if !concurrent {
                lp.sync_all().unwrap();
            }
        }
        lp.sync_all().unwrap();
        if n == 0 {
            settled = Some(round);
            break;
        }
    }
    let Some(rounds) = settled else { panic!("seed {seed}: no re-seal fixpoint in 12 rounds") };
    for r in roles {
        let current: Vec<Vec<osis_crypto::Epoch>> = (0..N).map(|p| lp.peers[p].engine.epochs(&g).unwrap().role(r).current()).collect();
        assert!(current.iter().all(|c| *c == current[0]), "seed {seed}: {r:?}: nodes count different current epochs: {current:?}");
        for e in &current[0] {
            let any = (0..N).any(|p| lp.peers[p].engine.epochs(&g).unwrap().role(r).secret(e).is_some());
            let lacking: Vec<usize> = (0..N).filter(|h| role[*h] >= r && lp.peers[*h].engine.epochs(&g).unwrap().role(r).secret(e).is_none()).collect();
            assert!(!any || lacking.is_empty(), "seed {seed}: {r:?} holders {lacking:?} lack current epoch {e:?} another node holds");
        }
    }
    (forked, rounds)
}

// spec/permissions.md §3 (re-seal, removal), spec/crypto.md §4 (supersession, history boxes,
// covers): as `forked_reseals`, with five peers, rotations that box nobody (the rotator leaving
// every holder out, itself included: an epoch with no box, which no later commit removes a box
// of) and removals and demotions to read of random holders by random admins, concurrent with
// the rotations; then
// rounds of every remaining node's re-seals and rotations until nothing is written. Then the
// invariant: every remaining node agrees on the current and newest epochs, every holder holds
// every current epoch a node that may rotate holds, and no departed holder holds an epoch a
// remaining holder encrypts or signs under.
// Seed 1: an admin epoch that boxed nobody, superseded through the next one's keyset list.
#[test]
fn forks_with_departures_settle_spec_permissions_3() {
    forks_with_departures(1, false);
}

// spec/crypto.md §4 (established by its own valid rotation commit, whatever came before):
// rotation commits turned invalid, their rotator demoted concurrently. Seeds 23, 25: a demoted
// admin's own rotation falls at it too (at 25 it stayed current there, an epoch no other node
// established). Seeds 51, 243, 336: a valid rotation superseding an invalid one is established
// (once a chain through the superseded epochs was required, it stayed unestablished but at its
// author, and so every one after it: at 51 the older epoch stayed current with its boxes gone).
#[test]
fn invalid_own_rotation_falls_spec_crypto_4() {
    forks_with_departures(23, false);
}

#[test]
fn invalid_own_rotation_falls_25_spec_crypto_4() {
    forks_with_departures(25, false);
}

#[test]
fn rotation_after_invalid_one_51_spec_crypto_4() {
    forks_with_departures(51, false);
}

#[test]
fn rotation_after_invalid_one_243_spec_crypto_4() {
    forks_with_departures(243, false);
}

#[test]
fn rotation_after_invalid_one_336_spec_crypto_4() {
    forks_with_departures(336, false);
}

// spec/crypto.md §4 (established by its own valid rotation commit): peer 1's rotation G of read
// (epoch s, boxing peers 2 and 4 only) falls invalid, peer 0 demoting 1 to read concurrently;
// peer 4's rotation of read is a valid fork beside it. Unaware of the demotion, 2 and 4 re-grant
// each other (re-writing every box G made at s), then 2 removes reader 3: its rotation C removes
// the boxes at s and at 4's fork. C must be established wherever it is held, else 4's fork stays
// current with its boxes gone, covering 3 by the box rule, and is encrypted under while 3 holds
// it. (Seed 3918: at 3917 4's fork lost the order, so 4, the fork's merger, merged it in its
// grant and the shape was gone.)
#[test]
fn rotation_after_invalid_one_through_regrants_spec_crypto_4() {
    let mut lp = LocalPeer::new(5, 3_918, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    let was = [Some(Role::Admin), Some(Role::Admin), Some(Role::Admin), Some(Role::Read), Some(Role::Admin)];
    for i in 1..5 {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(was[i].unwrap())).unwrap();
    }
    lp.sync_all().unwrap();
    let others = |lp: &mut LocalPeer| {
        for a in 1..5 {
            for b in 1..5 {
                if a != b {
                    lp.sync(a, b).unwrap();
                }
            }
        }
    };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(edge(Role::Read)), presync: PreSync::Synced, keep: None }).unwrap();
    let read = BTreeSet::from([Role::Read]);
    rotate_leaving_out(&mut lp, 4, g, &read, &[]);
    rotate_leaving_out(&mut lp, 1, g, &read, &[0, 1, 3]);
    others(&mut lp);
    lp.peers[2].engine.grant(&g, &tids[4], &edge(Role::Admin)).unwrap();
    lp.peers[4].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    others(&mut lp);
    let before = lp.peers[2].engine.epochs(&g).unwrap().read.current();
    assert_eq!(before.len(), 2, "G's epoch and 4's fork current at 2: {before:?}");
    lp.peers[2].engine.demote(&g, &Demotion { holder: tids[3], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    departures_settle(&mut lp, g, 0, &mut Rng(1), was);
}

/// Peer `w`, holding read epoch `s` of `g`, signs F, a forged rotation commit of `s`: `s`'s
/// keyset (listing nothing), history box and `holder`'s box at `s` written again. Returns F's ID.
fn forge_rotation(lp: &mut LocalPeer, w: usize, g: Tid, s: osis_crypto::Epoch, holder: Tid) -> osis_base::CommitId {
    let ids = |lp: &mut LocalPeer| -> BTreeSet<osis_base::CommitId> { lp.packages(w).unwrap().into_iter().map(|p| p.id).collect() };
    let before = ids(lp);
    lp.peers[w]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let ks = osis_keys::keyset(&s, held.read.secret(&s).unwrap(), &Default::default());
            let state = crate::flows::secrets_in(tx, &g)?;
            let at = ct::Epoch { n: s.n(), nonce: *s.nonce() };
            let key = ct::HistoryKey { role: Role::Read, epoch: at.clone() };
            let bk = ct::BoxKey { holder, role: Role::Read, epoch: at };
            let w = osis_keys::SecretsWrite { history: [(key.clone(), state.history[&key].clone())].into(), boxes: [(bk.clone(), state.boxes[&bk].clone())].into(), ..Default::default() };
            let mut m = Mutation::new();
            crate::flows::put_keysets(&mut m, g, &osis_keys::KeysWrite { keysets: [(Role::Read, ks)].into() })?;
            crate::flows::put_secrets(&mut m, g, &w, false)?;
            crate::engine::Engine::commit_tx(tx, m).map(|_| ())
        })
        .unwrap();
    *ids(lp).difference(&before).next().unwrap()
}

// spec/crypto.md §4 (names): owner A (peer 0) removes reader M (2), rotating read to s (R_s).
// Admin G (1) signs F, a forged rotation commit of s (s's keyset, history box and X's box
// written again), then re-grants admin X (3), whose box record it replaces at s (C). A, holding C
// but not F, removes G, rotating to e (naming R_s); so F is invalid (G demoted concurrently). X
// holds every commit but R_s: e must not be established there (else X, still seeing M as a
// reader, re-seals e to it). Once R_s arrives, e is.
#[test]
fn forged_rotation_withheld_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Admin), (2, Role::Read), (3, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let ids = |lp: &mut LocalPeer, i: usize| -> BTreeSet<osis_base::CommitId> { lp.packages(i).unwrap().into_iter().map(|p| p.id).collect() };
    let before = ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let r_s: BTreeSet<_> = ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let f = forge_rotation(&mut lp, 1, g, s, tids[3]);
    let before = ids(&mut lp, 1);
    lp.peers[1].engine.grant(&g, &tids[3], &edge(Role::Admin)).unwrap();
    for pk in lp.packages(1).unwrap().into_iter().filter(|p| !before.contains(&p.id)) {
        lp.peers[0].engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_s.contains(&p.id)) {
        let _ = lp.peers[3].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let at_x = lp.peers[3].engine.epochs(&g).unwrap();
    let rotations = |x: &osis_keys::ActorEpochs, ep: &osis_crypto::Epoch| x.read.get(ep).map(|i| i.rotations.keys().copied().collect::<Vec<_>>()).unwrap_or_default();
    assert!(lp.peers[3].engine.core.ix.commits.contains_key(&f) && rotations(&at_x, &s).is_empty(), "F held, invalid; R_s withheld");
    assert!(!rotations(&at_x, &e).is_empty(), "e's rotation commit applied, valid");
    assert!(at_x.read.secret(&e).is_some());
    assert!(!at_x.read.is_established(&e), "e established at X without R_s, which it names");
    withheld_arrives(&mut lp, 3, g, e, &all, &r_s);
}

/// The commits `withheld` of `all` reach peer `x`: `e` is then current there (names met).
fn withheld_arrives(lp: &mut LocalPeer, x: usize, g: Tid, e: osis_crypto::Epoch, all: &[crate::local_peer::Package], withheld: &BTreeSet<osis_base::CommitId>) {
    for pk in all.iter().filter(|p| withheld.contains(&p.id)) {
        let _ = lp.peers[x].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert!(lp.peers[x].engine.epochs(&g).unwrap().read.is_current(&e), "e current once the withheld commits arrive");
}

// spec/crypto.md §4 (names): owner A (peer 0) removes reader M (2), rotating read to s (R_s).
// Writer W (1, may rotate read) signs F, a forged rotation commit of s, valid. A applies F, then
// removes W, rotating to e (naming R_s). X (3) holds every commit but R_s: e must not be
// established (else X, still seeing M as a reader, re-seals e to it, though both M and W departed
// before e). Once R_s arrives, e is.
#[test]
fn valid_forged_rotation_withheld_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Write), (2, Role::Read), (3, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let ids = |lp: &mut LocalPeer, i: usize| -> BTreeSet<osis_base::CommitId> { lp.packages(i).unwrap().into_iter().map(|p| p.id).collect() };
    let before = ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let r_s: BTreeSet<_> = ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let f = forge_rotation(&mut lp, 1, g, s, tids[3]);
    for pk in lp.packages(1).unwrap() {
        let _ = lp.peers[0].engine.ingest(&pk.bytes, pk.blobs);
    }
    assert!(lp.peers[0].engine.epochs(&g).unwrap().read.get(&s).unwrap().rotations.contains_key(&f), "F valid at A");
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_s.contains(&p.id)) {
        let _ = lp.peers[3].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let at_x = lp.peers[3].engine.epochs(&g).unwrap();
    let rotations = |x: &osis_keys::ActorEpochs, ep: &osis_crypto::Epoch| x.read.get(ep).map(|i| i.rotations.keys().copied().collect::<Vec<_>>()).unwrap_or_default();
    assert_eq!(rotations(&at_x, &s), vec![f], "F held, valid; R_s withheld");
    assert!(!rotations(&at_x, &e).is_empty(), "e's rotation commit applied, valid");
    assert!(!at_x.read.is_established(&e), "e established at X without R_s, which it names");
    // nor s: its history box (F's copy of R_s's) names R_s as its departing commit
    assert!(!at_x.read.is_established(&s));
    withheld_arrives(&mut lp, 3, g, e, &all, &r_s);
}

/// Peers 0 (owner A of `g`), 1 (W, a writer), 2 (M, a reader), 3 (X, an admin), all synced; A
/// then removes M (R_s, rotating read to s). Returns `g`, the tids, R_s's commits and s.
fn removed_reader(lp: &mut LocalPeer, extra_admin: bool) -> (Tid, Vec<Tid>, BTreeSet<osis_base::CommitId>, osis_crypto::Epoch) {
    let n = lp.peers.len();
    let tids: Vec<Tid> = (0..n).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(lp, 0);
    let mut grants = vec![(1, Role::Write), (2, Role::Read), (3, Role::Admin)];
    if extra_admin {
        grants.push((4, Role::Admin));
    }
    for (i, r) in grants {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let before = commit_ids(lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let r_s: BTreeSet<_> = commit_ids(lp, 0).difference(&before).copied().collect();
    let s = newest_read(lp, 0, g).unwrap();
    (g, tids, r_s, s)
}

pub(super) fn commit_ids(lp: &mut LocalPeer, i: usize) -> BTreeSet<osis_base::CommitId> {
    lp.packages(i).unwrap().into_iter().map(|p| p.id).collect()
}

/// Delivers `all` but `withheld` to peer `x`; asserts `e` is not established there (it names a
/// withheld commit), then delivers the rest and asserts it is current.
fn withheld_then_arrives(lp: &mut LocalPeer, x: usize, g: Tid, e: osis_crypto::Epoch, all: &[crate::local_peer::Package], withheld: &BTreeSet<osis_base::CommitId>) {
    for pk in all.iter().filter(|p| !withheld.contains(&p.id)) {
        let _ = lp.peers[x].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let at_x = lp.peers[x].engine.epochs(&g).unwrap();
    let cands = lp.peers[x].engine.run(|tx| super::reseal_candidates(tx, &g)).unwrap();
    assert!(at_x.read.secret(&e).is_some(), "X holds e's secret");
    assert!(!at_x.read.is_established(&e), "e established at X without R_s; re-seal candidates there: {cands:?}");
    withheld_arrives(lp, x, g, e, all, withheld);
}

// spec/crypto.md §4 (names come from the rotator's own timeline, never from another's word):
// writer W (1) saw R_s (M's removal) and rotates read to e1 itself, its history box naming
// nothing and its keyset listing nothing (`list_s`: listing s, with a forged rotation commit F of
// s beside it). At owner A e1 is current; A removes W, rotating to e (naming R_s). X (3), withheld
// R_s, must not establish e (it would re-seal e to M, departed before e).
fn writer_rotation_skips(list_s: bool) {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (g, tids, r_s, s) = removed_reader(&mut lp, false);
    lp.sync(0, 1).unwrap();
    if list_s {
        forge_rotation(&mut lp, 1, g, s, tids[3]);
    }
    lp.peers[1]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let holders = super::recipients(tx, &tx.core.id.tid(), &g, &[])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let secrets = crate::flows::secrets_in(tx, &g)?;
            let mut rot = osis_keys::rotate(&g, &[Role::Read].into(), &held, &secrets, &holders, &osis_keys::Names::default(), &mut *tx.rng).unwrap();
            let r = &rot.rotated[0];
            let list: BTreeSet<osis_crypto::Epoch> = if list_s { [s].into() } else { BTreeSet::new() };
            rot.keys.keysets.insert(Role::Read, osis_keys::keyset(&r.epoch, &r.secret, &list));
            crate::flows::put_secrets(&mut m, g, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut m, g, &rot.keys)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, g, &rot)
        })
        .unwrap();
    for pk in lp.packages(1).unwrap() {
        let _ = lp.peers[0].engine.ingest(&pk.bytes, pk.blobs);
    }
    let e1 = newest_read(&lp, 0, g).unwrap();
    assert!(e1.n() > s.n(), "W's rotation current at A");
    assert_eq!(lp.peers[0].engine.epochs(&g).unwrap().read.current(), vec![e1]);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > e1.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    withheld_then_arrives(&mut lp, 3, g, e, &all, &r_s);
}

#[test]
fn writer_rotation_naming_nothing_spec_crypto_4() {
    writer_rotation_skips(false);
}

#[test]
fn writer_rotation_listing_forged_spec_crypto_4() {
    writer_rotation_skips(true);
}

// spec/crypto.md §4 (names; an epoch held by snapshot alone): owner A (0) removes M (2) by R_s,
// compacts `secrets.0` (a snapshot keying s), then removes W, rotating to e (naming R_s). X (3)
// gets everything but R_s: e must not be established (X sees M as a reader).
#[test]
fn snapshot_keyed_without_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (g, tids, r_s, s) = removed_reader(&mut lp, false);
    let snap = lp.peers[0].engine.compaction_snapshot(&g, &osis_base::Ak::new("secrets.0").unwrap()).unwrap();
    assert!(snap.is_some());
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let all = lp.packages(0).unwrap();
    withheld_then_arrives(&mut lp, 3, g, e, &all, &r_s);
}

// spec/crypto.md §4 (names): A (0) rotates read (R_p), then removes M (2) by R_s. Writer W (1)
// forges F of s. Admin B (4) gets everything but R_p and removes W, rotating to e: it names R_s
// from its own timeline, whatever F says. X (3) gets everything but R_s: e not established.
#[test]
fn rotator_beside_forged_rotation_spec_crypto_4() {
    let mut lp = LocalPeer::new(5, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Write), (2, Role::Read), (3, Role::Admin), (4, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 0);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let r_p: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let r_s: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    forge_rotation(&mut lp, 1, g, s, tids[3]);
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_p.contains(&p.id)) {
        let _ = lp.peers[4].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert_eq!(lp.peers[4].engine.epochs(&g).unwrap().read.current(), vec![s], "s current at B");
    lp.peers[4].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    let e = newest_read(&lp, 4, g).unwrap();
    assert!(e.n() > s.n());
    all.extend(lp.packages(4).unwrap());
    withheld_then_arrives(&mut lp, 3, g, e, &all, &r_s);
}

/// Seeds: OSIS_DEPART_START, OSIS_DEPART_SEEDS (default 0..100, as `forks_with_departures_settle_large`).
#[test]
#[ignore = "tier 2"]
fn regrants_after_invalid_rotation_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_DEPART_START", "OSIS_DEPART_SEEDS", osis_base::testenv::large(0..100));
    let replay = |s: u64| format!("OSIS_DEPART_START={s} OSIS_DEPART_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::regrants_after_invalid_rotation_large -- --ignored --exact");
    s.run("rotation::tests::regrants_after_invalid_rotation_large", replay, regrants_after_invalid_rotation);
}

/// Random variations of `rotation_after_invalid_one_through_regrants_spec_crypto_4`: an
/// admin demoted by the owner rotates read unaware (invalid) beside a valid fork; the other
/// admins, cut off from the owner, re-grant each other (re-writing the invalid rotation's boxes),
/// then one removes the reader.
fn regrants_after_invalid_rotation(seed: u64) {
    const N: usize = 5;
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(N, 5_000 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    // peers 1, x and y admins, v a reader
    let v = 2 + rng.next(3) as usize;
    let (x, y) = match v {
        2 => (3, 4),
        3 => (2, 4),
        _ => (2, 3),
    };
    let mut was = [Some(Role::Admin); N];
    was[v] = Some(Role::Read);
    for i in 1..N {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(was[i].unwrap())).unwrap();
    }
    lp.sync_all().unwrap();
    let others = |lp: &mut LocalPeer| {
        for a in 1..N {
            for b in (1..N).filter(|b| *b != a) {
                lp.sync(a, b).unwrap();
            }
        }
    };
    let read = BTreeSet::from([Role::Read]);
    let pick = |rng: &mut Rng| if rng.next(2) == 0 { x } else { y };
    // peer 1 demoted, unaware
    let new = (rng.next(2) == 0).then_some(edge(Role::Read));
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new, presync: PreSync::Synced, keep: None }).unwrap();
    // a valid fork boxing v; 1's invalid rotation leaving v out
    let f = pick(&mut rng);
    let skip: Vec<usize> = (0..N).filter(|j| *j != f && *j != v && rng.next(4) == 0).collect();
    rotate_leaving_out(&mut lp, f, g, &read, &skip);
    let skip: Vec<usize> = (0..N).filter(|j| *j == 0 || *j == 1 || *j == v || rng.next(4) == 0).collect();
    rotate_leaving_out(&mut lp, 1, g, &read, &skip);
    others(&mut lp);
    // x and y re-grant each other, sometimes 1 too
    for (i, j) in [(x, y), (y, x), (x, 1), (y, 1)] {
        if j != 1 || rng.next(2) == 0 {
            // refused (a fork that left the granter out: a read secret not held), nothing
            let r = lp.peers[i].engine.core.role_now(&tids[j], &g).unwrap();
            let _ = lp.peers[i].engine.grant(&g, &tids[j], &edge(r));
        }
    }
    others(&mut lp);
    let a = pick(&mut rng);
    let _ = lp.peers[a].engine.demote(&g, &Demotion { holder: tids[v], new: None, presync: PreSync::Synced, keep: None });
    departures_settle(&mut lp, g, seed, &mut rng, was);
}

/// Seeds: OSIS_DEPART_START, OSIS_DEPART_SEEDS (default 0..100).
#[test]
#[ignore = "tier 2"]
fn forks_with_departures_settle_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_DEPART_START", "OSIS_DEPART_SEEDS", osis_base::testenv::large(0..100));
    let replay = |s: u64| format!("OSIS_DEPART_START={s} OSIS_DEPART_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::forks_with_departures_settle_large -- --ignored --exact");
    s.run("rotation::tests::forks_with_departures_settle_large", replay, |seed| forks_with_departures(seed, true));
}

/// Rotates `rot` of `g` at peer `i`, leaving out the peers `skip` (all of them, the rotator
/// included: an epoch with no box); refused (a rotated role's secret not held), nothing.
pub(super) fn rotate_leaving_out(lp: &mut LocalPeer, i: usize, g: Tid, rot: &BTreeSet<Role>, skip: &[usize]) {
    let skip: Vec<(Tid, Option<Role>)> = skip.iter().map(|j| (lp.peers[*j].engine.tid(), None)).collect();
    let _ = lp.peers[i].engine.run(|tx| {
        let held = tx.core.epochs(&g).unwrap();
        let holders = super::recipients(tx, &tx.core.id.tid(), &g, &skip)?.ok_or(super::SEAL_WAITS)?;
        let mut m = Mutation::new();
        let r = super::rotation_into(tx, &mut m, g, rot, &held, &holders, &[])?;
        crate::engine::Engine::commit_tx(tx, m)?;
        super::record(tx, g, &r)
    });
}

/// `regrant`: admins also re-grant holders their edge as they see it (re-writing their boxes
/// at the current epochs, spec/crypto.md §4), drawn from a second generator so the first one's
/// shapes stay as they were without.
fn forks_with_departures(seed: u64, regrant: bool) {
    const N: usize = 5;
    let roles = [Role::Read, Role::Write, Role::Admin];
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut rng2 = Rng(seed.wrapping_mul(0xC2B2_AE3D_27D4_EB4F) | 1);
    let mut lp = LocalPeer::new(N, 3_000 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    let mut role = [Some(Role::Admin); N];
    for i in 1..N {
        let r = roles[rng.next(3) as usize];
        role[i] = Some(r);
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    // the highest role each peer held
    let was = role;
    for _ in 0..2 + rng.next(4) {
        // a peer acts on the role it held when the round began: one demoted in it does not
        // know yet, and its rotation there is invalid at the others
        let acting = role;
        for (i, ri) in acting.into_iter().enumerate() {
            let Some(ri) = ri else { continue };
            if regrant && ri == Role::Admin {
                // sometimes every holder it sees, sometimes one
                let how = rng2.next(4);
                let one = 1 + rng2.next(N as u64 - 1) as usize;
                for j in (1..N).filter(|j| *j != i && (how == 0 || how == 1 && *j == one)) {
                    if let Some(r) = lp.peers[i].engine.core.role_now(&tids[j], &g) {
                        let _ = lp.peers[i].engine.grant(&g, &tids[j], &edge(r));
                    }
                }
            }
            if ri < Role::Write || rng.next(2) == 0 {
                continue;
            }
            let pick = rng.next(6);
            if pick == 0 && ri == Role::Admin {
                let j = 1 + rng.next(N as u64 - 1) as usize;
                let new = (rng.next(2) == 0).then_some(Role::Read);
                if j == i || role[j] <= new {
                    continue;
                }
                // refused (a rotated role's secret not held) changes nothing
                if lp.peers[i].engine.demote(&g, &Demotion { holder: tids[j], new: new.map(edge), presync: PreSync::Synced, keep: None }).is_ok() {
                    role[j] = new;
                }
                continue;
            }
            let rot: BTreeSet<Role> = roles.into_iter().filter(|r| *r <= ri && rng.next(2) == 0).collect();
            if rot.is_empty() {
                continue;
            }
            let skip: Vec<usize> = (0..N).filter(|j| pick == 1 || *j != i && rng.next(3) == 0).collect();
            rotate_leaving_out(&mut lp, i, g, &rot, &skip);
        }
        if rng.next(2) == 0 {
            lp.sync_all().unwrap();
        } else {
            for _ in 0..4 {
                let (a, b) = (rng.next(N as u64) as usize, rng.next(N as u64) as usize);
                if a != b {
                    lp.sync(a, b).unwrap();
                }
            }
        }
    }
    departures_settle(&mut lp, g, seed, &mut rng, was);
}

/// Syncs everything, then runs rounds of every remaining node's re-seals and rotations until
/// nothing is written, and checks the invariant of `forks_with_departures` (`was`: the highest
/// role each peer held; peer 0 is `g`'s owner).
fn departures_settle(lp: &mut LocalPeer, g: Tid, seed: u64, rng: &mut Rng, was: [Option<Role>; 5]) {
    const N: usize = 5;
    let roles = [Role::Read, Role::Write, Role::Admin];
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    lp.sync_all().unwrap();
    // what the demotions came to: one by an admin demoted concurrently is invalid
    let mut role = [Some(Role::Admin); N];
    let now: BTreeMap<Tid, Role> = lp.peers[0].engine.core.current_holders(&g).into_iter().map(|(h, r, _)| (h, r)).collect();
    for p in 1..N {
        role[p] = now.get(&tids[p]).copied();
    }
    let stay: Vec<usize> = (0..N).filter(|p| role[*p].is_some()).collect();
    let mut settled = false;
    for _ in 0..16 {
        let mut n = 0;
        let concurrent = rng.next(2) == 0;
        for &p in &stay {
            n += lp.peers[p].engine.reseal_due(&g, &Pass).unwrap().commits.len();
            n += lp.peers[p].engine.ensure_rotated(&g).unwrap().0.commits.len();
            if !concurrent {
                lp.sync_all().unwrap();
            }
        }
        lp.sync_all().unwrap();
        if n == 0 {
            settled = true;
            break;
        }
    }
    assert!(settled, "seed {seed}: no fixpoint in 16 rounds");
    for r in roles {
        let ep = |p: usize| lp.peers[p].engine.epochs(&g).unwrap().role(r).clone();
        // peer 0, G's owner, holds every role and is never demoted
        let at0 = ep(0).current();
        for &p in &stay {
            let e = ep(p);
            let c = e.current();
            // peer 0's rotations are all valid: an epoch current elsewhere and unestablished
            // there is an invalid rotation's (a demoted admin's own, made unaware)
            assert!(c.iter().all(|x| ep(0).is_established(x)), "seed {seed}: {r:?}: peer {p} counts current {c:?}, peer 0 establishes not all");
            assert_eq!(c, at0, "seed {seed}: {r:?}: peers 0 and {p} count different current epochs (roles {role:?})");
        }
        for e in &at0 {
            // re-sealed by a node that may rotate `r` (one that may not, as a writer demoted
            // after a rotation that boxed only itself, cannot: issues/fork-held-by-non-rotators.md)
            let any = stay.iter().any(|&p| role[p] >= Some(r.max(Role::Write)) && ep(p).secret(e).is_some());
            let lacking: Vec<usize> = stay.iter().copied().filter(|h| role[*h] >= Some(r) && ep(*h).secret(e).is_none()).collect();
            assert!(!any || lacking.is_empty(), "seed {seed}: {r:?} holders {lacking:?} lack current epoch {e:?} another node holds");
        }
        // what the remaining holders encrypt under: a fork boxed to a departed peer by a
        // rotation unaware of its departure may stay current beside it, never newest
        for h in stay.iter().copied().filter(|h| role[*h] >= Some(r)) {
            let Some(e) = ep(h).newest_held().map(|x| x.0) else { continue };
            for d in (0..N).filter(|d| was[*d] >= Some(r) && role[*d] < Some(r)) {
                assert!(ep(d).reading_secret(&e).is_none(), "seed {seed}: peer {d}, {:?} now, holds {r:?} epoch {e:?} peer {h} encrypts under", role[d]);
            }
        }
    }
}

/// Seeds: OSIS_WITHHELD_START, OSIS_WITHHELD_SEEDS (default 0..100).
#[test]
#[ignore = "tier 2"]
fn withheld_departures_leak_nothing_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_WITHHELD_START", "OSIS_WITHHELD_SEEDS", osis_base::testenv::large(0..100));
    let replay = |s: u64| format!("OSIS_WITHHELD_START={s} OSIS_WITHHELD_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::withheld_departures_leak_nothing_large -- --ignored --exact");
    s.run("rotation::tests::withheld_departures_leak_nothing_large", replay, |seed| {
        withheld_departures(seed, false);
        withheld_departures(seed, true);
    });
}

// spec/crypto.md §4 (names; a node uses an epoch only once it holds every departure its rotator
// held): random removals, demotions, self-removals, rotations (forks, ones boxing nobody),
// `secrets.0` compactions and partial syncs on a group of five peers; then an admin X gets
// everything but some departing commits (and a few others), re-seals and rotates. No departed
// peer opens, from the boxes held at the end, an epoch whose rotator held its departure (the last
// write on its edge) and saw it below the epoch's role, for keys (an ended edge departs by its
// finalize). Seeds 59 and 69 leak with names ignored.
#[test]
fn withheld_departures_leak_nothing() {
    for seed in [59, 69] {
        withheld_departures(seed, false);
    }
}

// As `withheld_departures_leak_nothing`, `more` also: grants by admins, an `until` soon set on a
// holder's edge at its role, and the clock moving on (ended edges finalized by whoever next
// encrypts, spec/permissions.md §2). (The audit names matter only for a demotion on another thing, an owner chain's:
// `audit_dropped_grant_named_spec_crypto_4`.)
#[test]
fn withheld_departures_audits_and_expiries_leak_nothing() {
    for seed in WITHHELD_MORE {
        withheld_departures(seed, true);
    }
}

const WITHHELD_MORE: [u64; 1] = [3];

// As `withheld_departures_audits_and_expiries_leak_nothing`, seeds 9490002 and 9490147: an admin
// removed (or past its `until`) unknown to itself re-grants a departed peer d, boxing it epochs it
// holds (9490002: with their history boxes); in 9490147 X, lacking that admin's removal, takes the
// re-grant as valid and rotates boxing d, whose history box lists an epoch made knowing d's
// departure. That admin shares what it holds, as it could anyway; nobody encrypts under those
// epochs.
#[test]
fn withheld_regrant_by_unaware_admin_spec_crypto_4() {
    for seed in [9_490_002, 9_490_147] {
        withheld_departures(seed, true);
    }
}

// As `withheld_departures_audits_and_expiries_leak_nothing`, seed 282407 (periodic run 13):
// admin P removes holder M (rotating to e), its own edge passes an `until` set by another admin,
// then P re-grants M at e. M takes e from that grant while it looks valid; it is invalid once
// the `until` is known. M keeps e's secret (nothing unlearns it): no leak as long as no node
// encrypts under e, which the harness checks at the owner after `ensure_rotated` (e, written by
// the since-departed P, does not cover P's departure).
#[test]
fn withheld_regrant_past_own_until_spec_crypto_4() {
    withheld_departures(282_407, true);
}

fn withheld_departures(seed: u64, more: bool) {
    const N: usize = 5;
    let roles = [Role::Read, Role::Write, Role::Admin];
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(N, 7_000 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for t in &tids[1..] {
        lp.peers[0].engine.grant(&g, t, &edge(roles[rng.next(3) as usize])).unwrap();
    }
    lp.sync_all().unwrap();
    // (role, epoch) -> the commits its rotator held when it made it (those it held before the
    // action, and the rotation commit itself: a cascade rotation comes before a removal's), and
    // the peers below the role in its view then
    type Made = BTreeMap<(Role, osis_crypto::Epoch), (BTreeSet<osis_base::CommitId>, BTreeSet<usize>)>;
    let mut made: Made = BTreeMap::new();
    type Before = (BTreeSet<(Role, osis_crypto::Epoch)>, BTreeSet<osis_base::CommitId>);
    // departures are for keys (spec/crypto.md §4): an edge past its `until` departs by its
    // finalize, never by a clock
    let key_role = |lp: &LocalPeer, i: usize, d: &usize| lp.peers[i].engine.core.key_holders(&g).into_iter().find(|h| h.0 == tids[*d]).map(|h| h.1);
    let seen = |lp: &LocalPeer, i: usize| -> Before {
        let epochs = (0..N).flat_map(|i| lp.peers[i].engine.epochs(&g).into_iter().flat_map(move |e| roles.into_iter().flat_map(move |r| e.role(r).epochs().map(move |(x, _)| (r, *x)).collect::<Vec<_>>()))).collect();
        (epochs, lp.peers[i].engine.core.ix.commits.keys().copied().collect())
    };
    let record = |made: &mut Made, lp: &LocalPeer, i: usize, (before, held): &Before| {
        let Some(e) = lp.peers[i].engine.epochs(&g) else { return };
        for r in roles {
            let below: BTreeSet<usize> = (0..N).filter(|d| key_role(lp, i, d) < Some(r)).collect();
            for (x, info) in e.role(r).epochs() {
                if info.checked().is_some() && !before.contains(&(r, *x)) {
                    let own = lp.peers[i].engine.core.ix.epoch_intro.get(&(g, r, *x)).map(|v| v.1);
                    made.insert((r, *x), (held.iter().copied().chain(own).collect(), below.clone()));
                }
            }
        }
    };
    // the commits that lower an edge (removals, demotions, self-removals)
    let mut departing: BTreeSet<osis_base::CommitId> = BTreeSet::new();
    for _ in 0..3 + rng.next(4) {
        for i in 0..N {
            let Some(ri) = lp.peers[i].engine.core.role_now(&tids[i], &g) else { continue };
            if ri < Role::Write || rng.next(2) == 0 {
                continue;
            }
            let before = seen(&lp, i);
            let kind = if more { rng.next(7) } else { rng.next(5) };
            match kind {
                5 if ri == Role::Admin => {
                    // a grant (raise)
                    let j = 1 + rng.next(N as u64 - 1) as usize;
                    let r = roles[rng.next(3) as usize];
                    if j != i && lp.peers[i].engine.core.role_now(&tids[j], &g) < Some(r) {
                        let _ = lp.peers[i].engine.grant(&g, &tids[j], &edge(r));
                    }
                }
                6 if ri == Role::Admin => {
                    // an `until` soon on a holder's edge, at its role now
                    let j = 1 + rng.next(N as u64 - 1) as usize;
                    let until = WallMs(lp.peers[i].engine.core.now().0 + 1 + rng.next(500));
                    if j != i
                        && let Some(r) = lp.peers[i].engine.core.role_now(&tids[j], &g)
                    {
                        let e = ct::Edge { role: r, until: Some(until), invite: None, since: None, tied: None };
                        if let Ok(d) = lp.peers[i].engine.demote(&g, &Demotion { holder: tids[j], new: Some(e), presync: PreSync::Synced, keep: None }) {
                            departing.extend(d.commits);
                        }
                    }
                }
                0 | 1 if ri == Role::Admin => {
                    let j = 1 + rng.next(N as u64 - 1) as usize;
                    let new = (rng.next(2) == 0).then_some(Role::Read);
                    if j != i
                        && lp.peers[i].engine.core.role_now(&tids[j], &g) > new
                        && let Ok(d) = lp.peers[i].engine.demote(&g, &Demotion { holder: tids[j], new: new.map(edge), presync: PreSync::Synced, keep: None })
                    {
                        departing.extend(d.commits);
                    }
                }
                2 if i != 0 => {
                    if let Ok(d) = lp.peers[i].engine.demote(&g, &Demotion { holder: tids[i], new: None, presync: PreSync::Synced, keep: None }) {
                        departing.extend(d.commits);
                    }
                }
                3 if ri == Role::Admin => {
                    let _ = lp.peers[i].engine.compaction_snapshot(&g, &osis_base::Ak::new("secrets.0").unwrap());
                }
                _ => {
                    let rot: BTreeSet<Role> = roles.into_iter().filter(|r| *r <= ri && rng.next(2) == 0).collect();
                    if !rot.is_empty() {
                        let skip: Vec<usize> = (0..N).filter(|j| *j != i && rng.next(4) == 0).collect();
                        rotate_leaving_out(&mut lp, i, g, &rot, &skip);
                    }
                }
            }
            record(&mut made, &lp, i, &before);
        }
        for _ in 0..3 {
            let (a, b) = (rng.next(N as u64) as usize, rng.next(N as u64) as usize);
            if a != b {
                lp.sync(a, b).unwrap();
            }
        }
        if more {
            lp.advance(rng.next(2_000));
        }
    }
    // X: an admin that stays one at peer 0 (the owner never departs), given everything but
    // some departing commits (and, rarely, others), re-seals and rotates
    let x = (1..N).find(|p| lp.peers[0].engine.core.role_now(&tids[*p], &g) == Some(Role::Admin)).unwrap_or(0);
    let mut all = Vec::new();
    for p in (0..N).filter(|p| *p != x) {
        all.extend(lp.packages(p).unwrap());
    }
    let mut withheld: BTreeSet<osis_base::CommitId> = departing.iter().copied().filter(|_| rng.next(2) == 0).collect();
    withheld.extend(all.iter().map(|p| p.id).filter(|_| rng.next(8) == 0));
    for pk in all.iter().filter(|p| !withheld.contains(&p.id)) {
        let _ = lp.peers[x].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    for _ in 0..2 {
        let before = seen(&lp, x);
        let _ = lp.peers[x].engine.reseal_due(&g, &Pass);
        // a finalize X may write but cannot (it lacks a secret its rotation needs) holds back
        // every encrypting under `g` (spec/permissions.md §2)
        if let Ok((_, blocked)) = lp.peers[x].engine.ensure_rotated(&g) {
            let due = lp.peers[x].engine.run(|tx| Ok(crate::flows::edges::finalizable(tx.core, &tx.core.id.tid(), &g))).unwrap();
            assert!(due.is_empty() || blocked.len() == roles.len(), "seed {seed}: X has a finalize due, encrypts under {:?}", roles.iter().filter(|r| !blocked.contains(r)).collect::<Vec<_>>());
        }
        if rng.next(2) == 0 {
            let rot: BTreeSet<Role> = roles.into_iter().filter(|_| rng.next(2) == 0).collect();
            rotate_leaving_out(&mut lp, x, g, &rot, &[]);
        }
        record(&mut made, &lp, x, &before);
    }
    lp.sync_all().unwrap();
    // each departed peer's departure, in the converged timeline: the last applied write on its
    // edge, or a later demotion whose audit dropped a write on it
    let tl = lp.peers[0].engine.core.timelines.get(&g).unwrap();
    let on_edge = |c: &osis_base::CommitId, d: &Tid| tl.role_commit(c).is_some_and(|mc| mc.ops.iter().any(|op| op.target == g && op.holder == *d));
    let last_write: Vec<Option<osis_base::CommitId>> = tids
        .iter()
        .map(|d| {
            let applied = tl.applied().values().filter(|a| a.target == g && on_edge(&a.point.commit, d)).map(|a| a.point);
            let dropped = tl.dropped().iter().filter(|(w, _)| matches!(w, osis_perm::WriteId::Op(c, _) if on_edge(c, d))).map(|(_, p)| *p);
            applied.chain(dropped).max().map(|p| p.commit)
        })
        .collect();
    // per peer, the held edge writes on it that do not apply in the converged timeline
    let applied: BTreeSet<osis_base::CommitId> = tl.applied().values().map(|a| a.point.commit).collect();
    let rotators_held: BTreeSet<osis_base::CommitId> = made.values().flat_map(|(h, _)| h.iter().copied()).collect();
    let unapplied: Vec<BTreeSet<osis_base::CommitId>> = tids.iter().map(|d| rotators_held.iter().copied().filter(|c| on_edge(c, d) && !applied.contains(c)).collect()).collect();
    let state = lp.peers[0].engine.run(|tx| crate::flows::secrets_in(tx, &g)).unwrap();
    for d in 0..N {
        let Some(gone) = last_write[d] else { continue };
        // what d holds, and opens of the converged state with its key
        let seed_d = lp.peers[d].engine.core.id.seed().clone();
        let mut got = lp.peers[d].engine.epochs(&g).unwrap_or_default();
        let _ = osis_keys::ingest(&g, &state, &osis_keys::Opener::KeyActor { holder: tids[d], seed: &seed_d }, &mut got, None);
        let now_d = key_role(&lp, 0, &d);
        // what d opens from boxes of epochs whose rotator held its departure yet saw it a holder,
        // by a later edge write on it that does not apply here (a re-grant by an admin removed
        // unknown to itself and to the rotator): that admin shares what it holds, as it could
        // anyway
        let invalid_raise = |c: &osis_base::CommitId| unapplied[d].contains(c);
        let via: BTreeSet<ct::BoxKey> = made
            .iter()
            .filter(|(_, (held, below))| held.contains(&gone) && !below.contains(&d) && held.iter().any(invalid_raise))
            .map(|((r, f), _)| ct::BoxKey { holder: tids[d], role: *r, epoch: osis_keys::aspects::to_schema(f) })
            .collect();
        let boxes = state.boxes.iter().filter(|(k, _)| via.contains(k)).map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut regranted = osis_keys::ActorEpochs::default();
        let _ = osis_keys::ingest(&g, &ct::Secrets { boxes, history: state.history.clone() }, &osis_keys::Opener::KeyActor { holder: tids[d], seed: &seed_d }, &mut regranted, None);
        let (invalid, invalid_authors) = opened_by_invalid(&mut lp, 0, g, tids[d], &seed_d, &state);
        // who wrote those invalid writes (the raises, the boxes): what d so opens is only what
        // one of them opens itself, so shares as it could anyway
        let raisers = unapplied[d].iter().filter_map(|c| lp.peers[0].engine.core.ix.commits.get(c).map(|m| m.view.author));
        let sharers: Vec<osis_keys::ActorEpochs> = raisers
            .chain(invalid_authors)
            .collect::<BTreeSet<Tid>>()
            .into_iter()
            .filter_map(|a| tids.iter().position(|t| *t == a))
            .map(|p| {
                let seed_p = lp.peers[p].engine.core.id.seed().clone();
                let mut o = lp.peers[p].engine.epochs(&g).unwrap_or_default();
                let _ = osis_keys::ingest(&g, &state, &osis_keys::Opener::KeyActor { holder: tids[p], seed: &seed_p }, &mut o, None);
                o
            })
            .collect();
        for r in roles.into_iter().filter(|r| now_d < Some(*r)) {
            for (e, _) in got.role(r).held_newest_first() {
                let knew = made.get(&(r, e)).is_some_and(|(held, below)| held.contains(&gone) && below.contains(&d));
                // a box to d in a commit valid when d took it, invalid now (its author departed
                // after: a regrant past its own `until`, say), or an epoch its history box lists,
                // or one d opens by `regranted`: d keeps the secret, so the epoch must not cover
                // the author's departure, and nobody encrypts under it
                if knew && (invalid.role(r).secret(&e).is_some() || regranted.role(r).secret(&e).is_some()) {
                    assert!(sharers.iter().any(|o| o.role(r).secret(&e).is_some()), "seed {seed}: departed peer {d} opens {r:?} epoch {e:?} through an invalid write whose author does not hold it");
                    let _ = lp.peers[0].engine.ensure_rotated(&g);
                    let now = lp.peers[0].engine.epochs(&g).unwrap();
                    assert!(now.role(r).newest() != Some(e), "seed {seed}: owner encrypts under {r:?} epoch {e:?}, which departed peer {d} opens from an invalid box");
                    continue;
                }
                assert!(!knew, "seed {seed}: departed peer {d} opens {r:?} epoch {e:?} made by a rotator that saw it depart");
            }
        }
    }
}


/// The epochs of `g` that `holder` (its device `seed`) opens from the boxes to it in the invalid
/// `secrets.0` deltas peer `i` holds, and from there by the history boxes of `state`; with those
/// deltas' authors.
fn opened_by_invalid(lp: &mut LocalPeer, i: usize, g: Tid, holder: Tid, seed: &osis_crypto::Secret32, state: &ct::Secrets) -> (osis_keys::ActorEpochs, BTreeSet<Tid>) {
    let ak = osis_base::Ak::new("secrets.0").unwrap();
    let (boxes, authors) = lp.peers[i]
        .engine
        .run(|tx| {
            let mut boxes = BTreeMap::new();
            let mut authors = BTreeSet::new();
            let ids: Vec<osis_base::CommitId> = tx.core.ix.by_aspect.get(&(g, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
            for id in ids {
                let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
                let Some(ai) = m.aspect(&g, &ak) else { continue };
                if m.valid_at(ai) {
                    continue;
                }
                for d in crate::apply::held_parts(tx, &id, ai)? {
                    if let osis_commit::Decoded::Delta(d) = d {
                        let to: Vec<_> = crate::apply::keys::secrets_write(&d.fragment).boxes.into_iter().filter(|(k, _)| k.holder == holder).collect();
                        if !to.is_empty() {
                            authors.insert(m.view.author);
                        }
                        boxes.extend(to);
                    }
                }
            }
            Ok((boxes, authors))
        })
        .unwrap();
    let mut out = osis_keys::ActorEpochs::default();
    let _ = osis_keys::ingest(&g, &ct::Secrets { boxes, history: state.history.clone() }, &osis_keys::Opener::KeyActor { holder, seed }, &mut out, None);
    (out, authors)
}

// spec/permissions.md §2 (finalize before encrypting; lacking a secret, wait): owner A (0)
// rotates write leaving out admin X (2), then sets an `until` on writer D's (1) edge. Past it, X
// may finalize D but cannot (no current write secret for the rotation): it encrypts nothing under
// G, re-seals included, until it can.
#[test]
fn finalize_due_without_secret_blocks_spec_permissions_2() {
    let mut lp = LocalPeer::new(3, 3_996, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Write]), &[2]);
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    let timed = ct::Edge { until: Some(until), ..edge(Role::Write) };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(timed), presync: PreSync::Synced, keep: None }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    assert!(lp.peers[2].engine.epochs(&g).unwrap().write.newest_held().is_none(), "X lacks write");
    let me = tids[2];
    assert!(!lp.peers[2].engine.run(|tx| Ok(crate::flows::edges::finalizable(tx.core, &me, &g))).unwrap().is_empty(), "X may finalize D");
    let (done, blocked) = lp.peers[2].engine.ensure_rotated(&g).unwrap();
    assert!(done.commits.is_empty(), "X wrote {:?}", done.commits);
    assert_eq!(blocked, BTreeSet::from([Role::Read, Role::Write, Role::Admin]), "X may encrypt under G with D's finalize due");
    assert!(lp.peers[2].engine.reseal_due(&g, &Pass).unwrap().commits.is_empty(), "X re-sealed with D's finalize due");
}

// spec/crypto.md §4 (a name is met when its commit is applied with every entry it resets known),
// spec/permissions.md §2: owner A (0) sets an `until` on writer D's (1) edge (U); past it, A
// finalizes D, rotating to e (its departs mark). X (2, an admin) holds the finalize but not U, the
// write it ends: there the finalize applies nothing and D is still a writer, so e must not be
// established, nor re-sealed to D. Once U arrives, e is.
#[test]
fn finalize_without_its_until_unmet_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 3_995, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    let timed = ct::Edge { until: Some(until), ..edge(Role::Write) };
    let u: BTreeSet<_> = lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(timed), presync: PreSync::Synced, keep: None }).unwrap().commits.into_iter().collect();
    lp.peers[0].clock.advance(1_000);
    lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(lp.peers[0].engine.core.key_holders(&g).iter().all(|h| h.0 != tids[1]), "D finalized at A");
    let e = newest_read(&lp, 0, g).unwrap();
    let all = lp.packages(0).unwrap();
    for pk in all.iter().filter(|p| !u.contains(&p.id)) {
        let _ = lp.peers[2].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert!(lp.peers[2].engine.core.key_holders(&g).iter().any(|h| h.0 == tids[1]), "D still a writer at X");
    let at_x = lp.peers[2].engine.epochs(&g).unwrap();
    assert!(at_x.read.secret(&e).is_some(), "X holds e's secret");
    assert!(!at_x.read.is_established(&e), "e established at X, where its finalize applies nothing");
    lp.peers[2].engine.reseal_due(&g, &Pass).unwrap();
    let to_d = ct::BoxKey { holder: tids[1], role: Role::Read, epoch: osis_keys::aspects::to_schema(&e) };
    let at_x = lp.peers[2].engine.run(|tx| crate::flows::secrets_in(tx, &g)).unwrap();
    assert!(!at_x.boxes.contains_key(&to_d), "X re-sealed e to D");
    withheld_arrives(&mut lp, 2, g, e, &all, &u);
    assert!(lp.peers[2].engine.core.key_holders(&g).iter().all(|h| h.0 != tids[1]), "D finalized at X");
}

// spec/permissions.md §2 (a commit's edge writes apply together), spec/crypto.md §4 (a name
// covers its commit's departures): owner A (0) sets an `until` on writers D1 (3) and D2 (4); past
// it, admin B (1) finalizes both in one commit F. Admin X (2) holds F and D2's `until` but not
// D1's. Were F's write on D2 to apply alone there, X's rotation would name F while boxing D1, and
// A, holding everything, would take that epoch as covering D1's departure.
#[test]
fn finalize_applies_whole_or_not_spec_permissions_2() {
    let mut lp = LocalPeer::new(5, 3_989, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    for (p, r) in [(1, Role::Admin), (2, Role::Admin), (3, Role::Write), (4, Role::Write)] {
        lp.peers[0].engine.grant(&g, &tids[p], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    let mut u1 = BTreeSet::new();
    for d in [3, 4] {
        let c = lp.peers[0].engine.demote(&g, &Demotion { holder: tids[d], new: Some(timed.clone()), presync: PreSync::Synced, keep: None }).unwrap().commits;
        if d == 3 {
            u1.extend(c);
        }
    }
    lp.sync(0, 1).unwrap();
    lp.peers[1].clock.advance(1_000);
    lp.peers[1].engine.ensure_rotated(&g).unwrap();
    assert!(lp.peers[1].engine.core.key_holders(&g).iter().all(|h| h.0 != tids[3] && h.0 != tids[4]), "D1, D2 finalized at B");
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !u1.contains(&p.id)) {
        let _ = lp.peers[2].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let _ = lp.peers[2].engine.ensure_rotated(&g);
    lp.sync_all().unwrap();
    let _ = lp.peers[0].engine.ensure_rotated(&g);
    let state = lp.peers[0].engine.run(|tx| crate::flows::secrets_in(tx, &g)).unwrap();
    let seed_d = lp.peers[3].engine.core.id.seed().clone();
    let mut got = lp.peers[3].engine.epochs(&g).unwrap_or_default();
    let _ = osis_keys::ingest(&g, &state, &osis_keys::Opener::KeyActor { holder: tids[3], seed: &seed_d }, &mut got, None);
    for e in lp.peers[0].engine.epochs(&g).unwrap().read.current() {
        assert!(got.read.reading_secret(&e).is_none(), "D1 opens read epoch {e:?}, current at A");
    }
}

// spec/crypto.md §4 (a name is met when its commit is applied: its edge write on the name's
// thing held): owner A (0) removes reader M (2) (R_s), then rotates read to e (naming R_s). X
// (3, an admin) holds R_s without its `roles.0` delta on G (a copy of some parts: a certificate copy or
// another label's parts), so it still sees M as a reader: e must not be established there.
// Once R_s arrives whole, e is.
#[test]
fn named_commit_without_its_edge_write_unmet_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_961, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (g, tids, r_s, _) = removed_reader(&mut lp, false);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(&lp, 0, g).unwrap();
    let all = lp.packages(0).unwrap();
    for pk in all.clone() {
        let bytes = if r_s.contains(&pk.id) {
            let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
            osis_commit::rewrite(&b, |ai, _| b.header.aspects.get(ai).is_some_and(|a| a.tid == g && a.ak.as_str() == "roles.0")).encode()
        } else {
            pk.bytes.clone()
        };
        let _ = lp.peers[3].engine.ingest(&bytes, pk.blobs.clone());
    }
    assert!(r_s.iter().all(|c| lp.peers[3].engine.core.ix.commits.contains_key(c)), "R_s held");
    assert!(lp.peers[3].engine.core.role_now(&tids[2], &g).is_some(), "M still a reader at X");
    let at_x = lp.peers[3].engine.epochs(&g).unwrap();
    let cands = lp.peers[3].engine.run(|tx| super::reseal_candidates(tx, &g)).unwrap();
    assert!(at_x.read.secret(&e).is_some(), "X holds e's secret");
    assert!(!at_x.read.is_established(&e), "e established at X, which sees M a reader; re-seal candidates: {cands:?}");
    withheld_arrives(&mut lp, 3, g, e, &all, &r_s);
}

// spec/crypto.md §4 (names: every commit whose demotion's audit dropped an edge write on the
// actor, named by the thing the demotion is on): G is owned by actor O (peer 0's); W (1) an
// admin of O grants D (2) read on G through the owner chain (C). Owner A demotes W to write on
// O, not having received C (its frontier misses it), so C is audited away; A then gets C and
// rotates G's read to e: no edge write on G departs anyone, and O's read keyset is unchanged, so
// only the audit names W's demotion. X (3, G's admin) holds C but not the demotion: e must not
// be established there (X sees D a reader and would re-seal e to it). Once it arrives, e is.
#[test]
fn audit_dropped_grant_named_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_981, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let o = group(&mut lp, 0);
    lp.peers[0].engine.grant(&o, &tids[1], &edge(Role::Admin)).unwrap();
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, o);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&g).unwrap();
    lp.peers[0].engine.grant(&g, &tids[3], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 1);
    lp.peers[1].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    let c: BTreeSet<_> = commit_ids(&mut lp, 1).difference(&before).copied().collect();
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&o, &Demotion { holder: tids[1], new: Some(edge(Role::Write)), presync: PreSync::Synced, keep: None }).unwrap();
    let dem: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.sync(1, 0).unwrap();
    assert!(lp.peers[0].engine.core.role_now(&tids[2], &g).is_none(), "C audited away at A");
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(&lp, 0, g).unwrap();
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !dem.contains(&p.id)) {
        let _ = lp.peers[3].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert!(c.iter().all(|x| lp.peers[3].engine.core.ix.commits.contains_key(x)));
    assert!(lp.peers[3].engine.core.role_now(&tids[2], &g).is_some(), "X sees D a reader");
    withheld_then_arrives(&mut lp, 3, g, e, &all, &dem);
}

// spec/crypto.md §4 (a node attributes a departure to the name of the newest of its events,
// by key, whatever thing names it): A removes D from G (rotation e1 names that removal on G);
// W, an admin of G's owner O, grants D read on G again, boxing it at e1; A demotes W on O
// without that grant, so the audit drops it (named on O). D's newest departure is the drop,
// which e1 does not name: A must rotate before encrypting under e1, which D holds.
#[test]
fn newest_event_names_departure_spec_crypto_4() {
    for seed in [3_990, 3_991, 3_992, 3_993] {
        let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
        let o = group(&mut lp, 0);
        lp.peers[0].engine.grant(&o, &tids[1], &edge(Role::Admin)).unwrap();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, o);
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
        lp.sync_all().unwrap();
        let e1 = newest_read(&lp, 0, g).unwrap();
        lp.peers[1].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
        lp.sync(1, 2).unwrap();
        assert!(lp.peers[2].engine.epochs(&g).is_some_and(|x| x.read.secret(&e1).is_some()), "seed {seed}: D holds e1");
        // ordered after the re-grant, whose author it has not seen: audited, not plain invalid
        lp.peers[0].clock.advance(5_000);
        lp.peers[0].engine.demote(&o, &Demotion { holder: tids[1], new: Some(edge(Role::Write)), presync: PreSync::Synced, keep: None }).unwrap();
        lp.sync(1, 0).unwrap();
        assert!(lp.peers[0].engine.core.role_now(&tids[2], &g).is_none(), "seed {seed}: the re-grant audited away at A");
        assert_eq!(newest_read(&lp, 0, g), Some(e1), "seed {seed}");
        let _ = lp.peers[0].engine.ensure_rotated(&g).unwrap();
        assert_ne!(newest_read(&lp, 0, g), Some(e1), "seed {seed}: e1 names only the earlier removal");
    }
}

/// Delivers every package of peer `from` to peer `to` but those in `skip`.
pub(super) fn send_skipping(lp: &mut LocalPeer, from: usize, to: usize, skip: &BTreeSet<osis_base::CommitId>) {
    for pk in lp.packages(from).unwrap().iter().filter(|p| !skip.contains(&p.id)) {
        let _ = lp.peers[to].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
}

/// What a party holding `epochs` of holder actor `m` opens of `a`'s epochs from peer `i`'s
/// `secrets.0` state of `a`: its boxes to `m`, then the history boxes they open.
pub(super) fn opens_through(lp: &mut LocalPeer, i: usize, a: Tid, m: Tid, epochs: &osis_keys::ActorEpochs) -> osis_keys::ActorEpochs {
    let state = lp.peers[i].engine.run(|tx| crate::flows::secrets_in(tx, &a)).unwrap();
    let mut got = osis_keys::ActorEpochs::default();
    osis_keys::ingest(&a, &state, &osis_keys::Opener::Actor { holder: m, epochs }, &mut got, None).unwrap();
    got
}

// spec/crypto.md §4 (covers by names; study C2, fork-sibling re-seal): a1 grants D read; a2
// rotates A to e1 before reading the grant (no box for D); a1, not holding e1, removes D (its own
// rotation e2 forks e1). Where a1 takes e1 as newest, e1 holds no box for D but its rotator never
// knew of the removal, so it covers nothing: a1 rotates before encrypting. a2 then reads the grant
// but not the removal and re-seals D at e1: D opens e1, never the epoch a1 encrypts under.
#[test]
fn fork_sibling_reseal_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut hit = 0;
    for seed in 4_100..4_116 {
        let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
        let a = group(&mut lp, 0);
        lp.peers[0].engine.grant(&a, &tids[1], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &tids[2], &edge(Role::Read)).unwrap();
        rotate_leaving_out(&mut lp, 1, a, &read, &[]);
        let e1 = newest_read(&lp, 1, a).unwrap();
        send_skipping(&mut lp, 0, 2, &BTreeSet::new());
        let start = held_by(&lp, 2, &[a]);
        let before = commit_ids(&mut lp, 0);
        lp.peers[0].engine.demote(&a, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced, keep: None }).unwrap();
        let removal: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
        send_skipping(&mut lp, 1, 0, &BTreeSet::new());
        if newest_read(&lp, 0, a) != Some(e1) {
            continue;
        }
        hit += 1;
        assert!(blocked_at(&mut lp, 0, a).contains(&Role::Read), "e1 does not name the removal");
        let _ = lp.peers[0].engine.ensure_rotated(&a).unwrap();
        let w = newest_read(&lp, 0, a).unwrap();
        assert_ne!(w, e1, "a1 rotated");
        send_skipping(&mut lp, 0, 1, &removal);
        lp.peers[1].engine.reseal_due(&a, &Pass).unwrap();
        assert!(openable(&mut lp, 1, &[a], tids[2], start.clone()).contains(&(a, Role::Read, e1)), "a2 re-sealed D at e1");
        assert!(!openable(&mut lp, 1, &[a], tids[2], start).contains(&(a, Role::Read, w)), "D opens the epoch a1 writes under");
    }
    assert!(hit > 0, "no seed took e1 as newest");
}

/// Peers: 0 a hostile admin of G, 1 an honest admin, 2 a writer who stays, 3 a reader removed by 0's
/// rotation, whose parts on `bad` do not decode, or never come (`leave_out`). What each then holds, and
/// what the honest admin's own rotation gives.
fn removal_with(seed: u64, bad: &[&str], leave_out: bool) -> Vec<String> {
    let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let ids: Vec<Tid> = lp.peers.iter().map(|p| p.engine.tid()).collect();
    let edge = |role| ct::Edge { role, until: None, invite: None, since: None, tied: None };
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, ids[0]);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&g).unwrap();
    lp.peers[0].engine.grant(&g, &ids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &ids[2], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &ids[3], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let before: BTreeSet<_> = lp.peers[0].engine.commit_ids().into_iter().collect();
    lp.advance(1000);
    lp.peers[0].engine.core.skip_writer_rules = true;
    lp.peers[0].engine.core.forge_bad = bad.iter().map(|a| (g, osis_base::Ak::new(*a).unwrap())).collect();
    lp.peers[0].engine.demote(&g, &Demotion { holder: ids[3], new: None, presync: PreSync::Synced, keep: None }).unwrap();
    lp.peers[0].engine.core.forge_bad = Default::default();
    lp.peers[0].engine.core.skip_writer_rules = false;
    let forged = lp.peers[0].engine.core.forged.take().unwrap();
    let forged_id = osis_commit::CommitBlob::decode(&forged).unwrap().id();
    for pk in lp.packages(0).unwrap() {
        if before.contains(&pk.id) {
            continue;
        }
        let b = osis_commit::CommitBlob::decode(&forged).unwrap();
        let bytes = match (pk.id == forged_id, leave_out) {
            (true, true) => osis_commit::rewrite(&b, |ai, _| bad.contains(&b.header.aspects[ai].ak.as_str())).encode(),
            (true, false) => forged.clone(),
            _ => pk.bytes.clone(),
        };
        for i in [1, 2, 3] {
            assert!(matches!(lp.peers[i].engine.ingest(&bytes, pk.blobs.clone()).unwrap(), crate::Ingested::Applied(_)));
        }
    }
    let mut out = Vec::new();
    for i in [1, 2, 3] {
        assert!(lp.peers[i].engine.pending().is_empty(), "{i}");
        assert!(!lp.peers[i].engine.roster(&g).contains_key(&ids[3]), "{i}: the removal stands");
        out.push(format!("{i}: {} secrets", lp.peers[i].engine.read_secrets(&g).len()));
    }
    lp.advance(1000);
    assert!(lp.peers[1].engine.ensure_rotated(&g).unwrap().1.is_empty());
    for pk in lp.packages(1).unwrap() {
        for i in [2, 3] {
            let _ = lp.peers[i].engine.ingest(&pk.bytes, pk.blobs.clone());
        }
    }
    let fresh = newest_read(&lp, 1, g);
    assert_eq!(newest_read(&lp, 2, g), fresh, "the writer is boxed again");
    assert_ne!(newest_read(&lp, 3, g), fresh, "the removed reader is left out");
    out
}

// spec/commits.md §4, spec/permissions.md §3: a part of a role commit that hashes and does not decode
// is as one that never came: the removal in it stands, nothing is stuck, and any other admin's rotation
// gives what the hostile one's did not.
#[test]
fn bad_rotation_parts_read_as_missing_spec_commits_4() {
    for bad in [&["secrets.0"][..], &["keys.0"], &["secrets.0", "keys.0"]] {
        assert_eq!(removal_with(9931, bad, false), removal_with(9931, bad, true), "{bad:?}");
    }
}

// spec/permissions.md §4, spec/crypto.md §5: an owner's holder with K's keyset and none of K's secrets has K's derived read epochs, to open its label and nothing more: it wraps nothing, rotates and boxes nothing; a node not holding the owner has none; K's real box then replaces them
#[test]
fn keyset_before_box_reads_only_spec_permissions_4() {
    let mut lp = LocalPeer::new(3, 3_391, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (a, b, c) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let admin = ct::Edge { role: Role::Admin, until: None, invite: None, since: None, tied: None };
    let mut m = Mutation::new();
    let o = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&o).unwrap();
    lp.peers[0].engine.grant(&o, &b, &admin).unwrap();
    lp.sync(0, 1).unwrap();
    let mut m = Mutation::new();
    let k = lp.peers[0].engine.new_thing(&mut m, o);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&k).unwrap();
    deliver_without_secrets(&mut lp, 0, 1, k);
    deliver_without_secrets(&mut lp, 0, 2, k);

    let e = &mut lp.peers[1].engine;
    assert!(e.core.ix.own_keys.contains(&k) && e.core.ix.secrets.get(&k).is_none(), "the keyset and no box");
    let held = e.epochs(&k).unwrap();
    assert!(held.read.holds_any() && held.read.current().is_empty(), "read epochs, none established");
    assert!(!held.write.holds_any() && !held.admin.holds_any());
    assert!(e.read_secrets(&k).iter().any(|s| held.read.held().any(|(_, x)| x.expose() == s.expose())));
    assert!(e.wrap_secret(&k, None).unwrap().is_none() && e.stranded_secret(&k).is_none(), "wraps nothing");
    let before = e.core.ix.commits.len();
    assert!(e.ensure_rotated(&k).unwrap().1.is_empty());
    assert!(e.grant(&k, &c, &admin).is_err(), "boxes nothing");
    assert!(e.run(|tx| super::rotate_now(tx, b, k, &BTreeSet::from([Role::Read]))).is_err(), "rotates nothing");
    assert_eq!(e.core.ix.commits.len(), before, "wrote nothing");
    assert!(lp.peers[2].engine.core.epochs(&k).is_none_or(|e| !e.holds_any()), "not the owner's holder");

    lp.sync(0, 1).unwrap();
    let e = &lp.peers[1].engine;
    let real = e.epochs(&k).unwrap();
    assert!(e.core.ix.secrets.get(&k).is_some() && real.read.newest_held().is_some() && real.admin.newest_held().is_some(), "the box replaces them");
}

// spec/crypto.md §4 Met, spec/permissions.md §2 (a finalize names the writes it ends): owner A (0)
// sets an `until` on writers D1 (2) and D2 (3), then renews D2 before it; admin B (1), not holding
// the renewal, finalizes both past it, rotating to e. Where the renewal is held, the finalize's
// write on D2 ends a write already superseded and applies nothing, yet the finalize is held whole,
// so its name is met: e is established everywhere and nobody stays blocked under G.
#[test]
fn finalize_beside_renewal_settles_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_993, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    for d in [2, 3] {
        lp.peers[0].engine.grant(&g, &tids[d], &edge(Role::Write)).unwrap();
    }
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    for d in [2, 3] {
        lp.peers[0].engine.demote(&g, &Demotion { holder: tids[d], new: Some(timed.clone()), presync: PreSync::Synced, keep: None }).unwrap();
    }
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &tids[3], &edge(Role::Write)).unwrap();
    lp.peers[1].clock.advance(1_000);
    lp.peers[1].engine.ensure_rotated(&g).unwrap();
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for i in 0..4 {
            lp.peers[i].clock.advance(1_000);
            let _ = lp.peers[i].engine.ensure_rotated(&g);
            let _ = lp.peers[i].engine.reseal_due(&g, &Pass);
        }
    }
    lp.sync_all().unwrap();
    for i in [0, 1] {
        assert!(blocked_at(&mut lp, i, g).is_empty(), "peer {i} blocked under G");
    }
}

// As `finalize_beside_renewal_settles_spec_crypto_4` with D2 alone: e, established everywhere,
// leaves out D2, which A sees renewed and re-seals, so D2 holds a current secret of G.
#[test]
fn renewed_holder_resealed_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 3_991, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.tid()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: Some(timed), presync: PreSync::Synced, keep: None }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    lp.peers[1].clock.advance(1_000);
    lp.peers[1].engine.ensure_rotated(&g).unwrap();
    for _ in 0..3 {
        lp.sync_all().unwrap();
        for i in 0..3 {
            lp.peers[i].clock.advance(1_000);
            let _ = lp.peers[i].engine.ensure_rotated(&g);
            let _ = lp.peers[i].engine.reseal_due(&g, &Pass);
        }
    }
    lp.sync_all().unwrap();
    assert!(lp.peers[2].engine.core.key_holders(&g).iter().any(|h| h.0 == tids[2]), "D2 renewed");
    let at_d = lp.peers[2].engine.epochs(&g).unwrap();
    assert!(at_d.read.newest_held().is_some() && at_d.write.newest_held().is_some(), "D2 holds no current secret of G");
}
