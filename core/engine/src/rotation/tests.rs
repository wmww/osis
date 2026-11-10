//! Rotation tests (spec/permissions.md §3, spec/crypto.md §4).

#![allow(clippy::unwrap_used)]
use crate::Mutation;
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use osis_base::{Role, Tid, WallMs};
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Delivers every commit of peer `from` to peer `to` without the `secrets.0` deltas of `x`
/// (what a node that does not read `x` gets of them: certificates).
pub(super) fn deliver_without_secrets(lp: &mut LocalPeer, from: usize, to: usize, x: Tid) {
    for pk in lp.packages(from).unwrap() {
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai| b.header.aspects.get(ai).is_some_and(|a| a.tid == x && a.ak.as_str() == "secrets.0"));
        let _ = lp.peers[to].receive(&cut.encode(), pk.blobs.clone());
    }
}

/// Peers: 0 = the first admin of group `t`, 1 = W (a writer, then removed: rotation R1 of read
/// and write), 2 = P (an admin), 3 = N (an admin when `n_first`, else granted later by the
/// caller). Returns R1's commits.
fn removed_writer(seed: u64, n_first: bool) -> (LocalPeer, Tid, Vec<osis_base::CommitId>) {
    let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let t = group(&mut lp, 0);
    let (w, p, n) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[3].engine.me());
    lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&t, &p, &edge(Role::Admin)).unwrap();
    if n_first {
        lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
    }
    lp.sync_all().unwrap();
    let r1 = lp.peers[0].engine.demote(&t, &Demotion { holder: w, new: None, retain: None }).unwrap().commits;
    (lp, t, r1)
}

/// The roles of `t` peer `i` may not encrypt under now (no rotation first).
pub(super) fn blocked_at(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<Role> {
    lp.peers[i].engine.run(|tx| super::blocked_roles(tx, &tx.core.writer().unwrap(), &t)).unwrap()
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
// first admin compacted and dropped R1's bodies (R1 removed writer W), holds the read epoch's history
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
        let n = lp.peers[3].engine.me();
        lp.peers[0].engine.grant(&t, &n, &edge(Role::Admin)).unwrap();
        lp.sync(0, 3).unwrap();
        let before = newest_read(&lp, 3, t);
        assert!(before.is_some(), "N holds the read epoch");
        assert!(lp.peers[3].engine.departures(&t).unwrap().iter().any(|d| d.holder == lp.peers[1].engine.me()), "N knows W left");
        assert!(blocked_at(&mut lp, 3, t).is_empty(), "covered (compacted {compact})");
        assert!(lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "no extra rotation");
        assert!(blocked_at(&mut lp, 0, t).is_empty());
    }
}

// spec/crypto.md §4 (names: an entry is bound to a held valid keyset body), spec/permissions.md
// §5.2: N drops R1's `keys.0` body under admin P's compaction snapshot S; the first admin then demotes
// P with a frontier not listing S, so S turns invalid and that body is missing again at N (R1's
// `secrets.0` still held). No held valid keyset binds the read epoch's entry any more, so it
// covers nothing: N rotates read once (an extra rotation, no lockout) and is covered by its own.
#[test]
fn rotation_missing_again_binds_nothing_spec_crypto_4() {
    let (mut lp, t, r1) = removed_writer(942, true);
    lp.sync_all().unwrap();
    let p = lp.peers[2].engine.me();
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
    lp.peers[0].engine.demote(&t, &Demotion { holder: p, new: Some(edge(Role::Read)), retain: None }).unwrap();
    lp.sync(0, 3).unwrap();
    assert!(!lp.peers[3].engine.core.ix.commits.get(&s).unwrap().valid.iter().any(|v| *v), "S invalid at N");
    assert_eq!(blocked_at(&mut lp, 3, t), BTreeSet::from([Role::Read]), "R1's keyset missing again: its entry binds to nothing");
    assert!(!lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "N rotates read");
    assert!(blocked_at(&mut lp, 3, t).is_empty(), "covered by its own rotation");
}

/// A thing of peer `i`'s with secrets of its own.
pub(super) fn group(lp: &mut LocalPeer, i: usize) -> Tid {
    let me = lp.peers[i].engine.me();
    let mut m = Mutation::new();
    let g = lp.peers[i].engine.new_thing(&mut m, me);
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.give_own_secrets(&g).unwrap();
    g
}

pub(super) fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, tied: None }
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
pub(super) fn openable(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
    openable_but(lp, i, actors, party, known, &BTreeSet::new())
}

/// `openable` with the boxes in `skip` (actor, role, epoch, holder) left aside.
pub(super) fn openable_but(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, mut known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>, skip: &BTreeSet<(Tid, Role, osis_crypto::Epoch, Tid)>) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
    use osis_keys::aspects::from_schema;
    let all: Vec<(Tid, ct::Secrets)> = actors.iter().filter_map(|a| lp.peers[i].engine.get_typed(a, &ct::SECRETS).unwrap().map(|s| (*a, s))).collect();
    // boxes to the party itself (a key actor)
    if let Some(p) = lp.peers.iter().find(|p| p.engine.me() == party) {
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
                if skip.contains(&(*a, k.role, e, k.holder)) {
                    continue;
                }
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
    let me = lp.peers[i].engine.me();
    let roles: BTreeSet<Role> = roles.iter().copied().collect();
    lp.peers[i]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&a).unwrap();
            let holders = super::recipients(tx, &tx.core.writer().unwrap(), &a, &[(me, keep)])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let rot = super::rotation_into(tx, &mut m, a, &roles, &held, &holders, false)?;
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
    let bob = lp.peers[1].engine.me();
    let tag = group(&mut lp, 0);
    let n = group(&mut lp, 0);
    lp.peers[0].engine.grant(&tag, &bob, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.demote(&n, &Demotion { holder: tag, new: None, retain: None }).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Read)).unwrap();
    assert!(lp.peers[0].engine.ensure_rotated(&n).unwrap().1.is_empty(), "covered");
}

// spec/permissions.md §3 (re-seal fixpoint), spec/crypto.md §4 (forks, merge) (churn seeds
// 140170 and 140188 shrunk: a node re-sealed itself on every pass): A and D rotate G's write
// concurrently, D's rotation leaving writer B out, so B lacks a box and the secret at D's fork.
// B, holding only A's fork, writes no re-seal of itself (before: one boxing A's fork alone on
// every pass); A, holding both, re-seals B once, a box at each fork, or, as the fork's merger
// (rule 3: a re-seal makes the rotations due first), merges it, boxing B.
#[test]
fn forked_role_reseal_reaches_fixpoint_spec_permissions_3() {
    let mut lp = LocalPeer::new(3, 1141, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (b, d) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    rotate_unboxed(&mut lp, 0, g, &[Role::Write], Some(Role::Write));
    lp.peers[2]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &[(b, Some(Role::Read))])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let rot = super::rotation_into(tx, &mut m, g, &[Role::Write].into(), &held, &holders, false)?;
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
    let (b, d) = (lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    for (i, other) in [(1, d), (2, b)] {
        lp.peers[i]
            .engine
            .run(|tx| {
                let held = tx.core.epochs(&g).unwrap();
                let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &[(other, Some(Role::Read))])?.ok_or(super::SEAL_WAITS)?;
                let mut m = Mutation::new();
                let rot = super::rotation_into(tx, &mut m, g, &[Role::Write].into(), &held, &holders, false)?;
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
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(edge(Role::Read)), retain: None }).unwrap();
    let read = BTreeSet::from([Role::Read]);
    rotate_leaving_out(&mut lp, 4, g, &read, &[]);
    rotate_leaving_out(&mut lp, 1, g, &read, &[0, 1, 3]);
    others(&mut lp);
    lp.peers[2].engine.grant(&g, &tids[4], &edge(Role::Admin)).unwrap();
    lp.peers[4].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    others(&mut lp);
    let before = lp.peers[2].engine.epochs(&g).unwrap().read.current();
    assert_eq!(before.len(), 2, "G's epoch and 4's fork current at 2: {before:?}");
    lp.peers[2].engine.demote(&g, &Demotion { holder: tids[3], new: None, retain: None }).unwrap();
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
            let ks = osis_keys::keyset(&s, held.read.secret(&s).unwrap(), &Default::default(), &Default::default());
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

// spec/crypto.md §4 (names): first admin A (peer 0) removes reader M (2), rotating read to s (R_s).
// Admin G (1) signs F, a forged rotation commit of s (s's keyset, history box and X's box
// written again), then re-grants admin X (3), whose box record it replaces at s (C). A, holding C
// but not F, removes G, rotating to e (naming R_s); so F is invalid (G demoted concurrently). X
// holds every commit but R_s: e must not be established there (else X, still seeing M as a
// reader, re-seals e to it). Once R_s arrives, e is.
#[test]
fn forged_rotation_withheld_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Admin), (2, Role::Read), (3, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let ids = |lp: &mut LocalPeer, i: usize| -> BTreeSet<osis_base::CommitId> { lp.packages(i).unwrap().into_iter().map(|p| p.id).collect() };
    let before = ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let r_s: BTreeSet<_> = ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let f = forge_rotation(&mut lp, 1, g, s, tids[3]);
    let before = ids(&mut lp, 1);
    lp.peers[1].engine.grant(&g, &tids[3], &edge(Role::Admin)).unwrap();
    for pk in lp.packages(1).unwrap().into_iter().filter(|p| !before.contains(&p.id)) {
        lp.peers[0].receive(&pk.bytes, pk.blobs).unwrap();
    }
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_s.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
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
        let _ = lp.peers[x].receive(&pk.bytes, pk.blobs.clone());
    }
    assert!(lp.peers[x].engine.epochs(&g).unwrap().read.is_current(&e), "e current once the withheld commits arrive");
}

// spec/crypto.md §4 (names): first admin A (peer 0) removes reader M (2), rotating read to s (R_s).
// Writer W (1, may rotate read) signs F, a forged rotation commit of s, valid. A applies F, then
// removes W, rotating to e (naming R_s). X (3) holds every commit but R_s: e must not be
// established (else X, still seeing M as a reader, re-seals e to it, though both M and W departed
// before e). Once R_s arrives, e is.
#[test]
fn valid_forged_rotation_withheld_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Write), (2, Role::Read), (3, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let ids = |lp: &mut LocalPeer, i: usize| -> BTreeSet<osis_base::CommitId> { lp.packages(i).unwrap().into_iter().map(|p| p.id).collect() };
    let before = ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let r_s: BTreeSet<_> = ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let f = forge_rotation(&mut lp, 1, g, s, tids[3]);
    for pk in lp.packages(1).unwrap() {
        let _ = lp.peers[0].receive(&pk.bytes, pk.blobs);
    }
    assert!(lp.peers[0].engine.epochs(&g).unwrap().read.get(&s).unwrap().rotations.contains_key(&f), "F valid at A");
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_s.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
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

/// Peers 0 (first admin A of `g`), 1 (W, a writer), 2 (M, a reader), 3 (X, an admin), all synced; A
/// then removes M (R_s, rotating read to s). Returns `g`, the tids, R_s's commits and s.
fn removed_reader(lp: &mut LocalPeer, extra_admin: bool) -> (Tid, Vec<Tid>, BTreeSet<osis_base::CommitId>, osis_crypto::Epoch) {
    let n = lp.peers.len();
    let tids: Vec<Tid> = (0..n).map(|i| lp.peers[i].engine.me()).collect();
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
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
        let _ = lp.peers[x].receive(&pk.bytes, pk.blobs.clone());
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
// s beside it). At first admin A e1 is current; A removes W, rotating to e (naming R_s). X (3), withheld
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
            let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &[])?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let secrets = crate::flows::secrets_in(tx, &g)?;
            let mut rot = osis_keys::rotate(&g, &[Role::Read].into(), &held, &secrets, &holders, &osis_keys::Names::default(), &mut *tx.rng).unwrap();
            let r = &rot.rotated[0];
            let list: BTreeSet<osis_crypto::Epoch> = if list_s { [s].into() } else { BTreeSet::new() };
            rot.keys.keysets.insert(Role::Read, osis_keys::keyset(&r.epoch, &r.secret, &list, &rot.names));
            crate::flows::put_secrets(&mut m, g, &rot.secrets, false)?;
            crate::flows::put_keysets(&mut m, g, &rot.keys)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, g, &rot)
        })
        .unwrap();
    for pk in lp.packages(1).unwrap() {
        let _ = lp.peers[0].receive(&pk.bytes, pk.blobs);
    }
    let e1 = newest_read(&lp, 0, g).unwrap();
    assert!(e1.n() > s.n(), "W's rotation current at A");
    assert_eq!(lp.peers[0].engine.epochs(&g).unwrap().read.current(), vec![e1]);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
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

// spec/crypto.md §4 (names; an epoch held by snapshot alone): first admin A (0) removes M (2) by R_s,
// compacts `secrets.0` (a snapshot keying s), then removes W, rotating to e (naming R_s). X (3)
// gets everything but R_s: e must not be established (X sees M as a reader).
#[test]
fn snapshot_keyed_without_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (g, tids, r_s, s) = removed_reader(&mut lp, false);
    let snap = lp.peers[0].engine.snapshot(&g, &osis_base::Ak::new("secrets.0").unwrap()).unwrap();
    assert!(snap.is_some());
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let all = lp.packages(0).unwrap();
    withheld_then_arrives(&mut lp, 3, g, e, &all, &r_s);
}

// spec/crypto.md §4 (Established: a held valid rotation commit or compaction snapshot keying e):
// admin B (1), removed by A (0) unaware, removes reader C (2), rotating to e, and compacts
// `secrets.0`. Both turn invalid once A's removal arrives; e was established at B by them alone,
// so it is not any more, as at a rebuild (one valid base gone takes its keying with it).
#[test]
fn invalid_snapshot_keys_nothing_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 3_932, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    lp.advance(1_000);
    lp.peers[1].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let e = newest_read(&lp, 1, g).unwrap();
    assert!(lp.peers[1].engine.snapshot(&g, &osis_base::Ak::new("secrets.0").unwrap()).unwrap().is_some());
    lp.sync(0, 1).unwrap();
    let est = |lp: &LocalPeer| lp.peers[1].engine.epochs(&g).unwrap().read.is_established(&e);
    assert!(!est(&lp), "e established at B by its invalid rotation and snapshot");
    lp.peers[1].engine.rebuild_index().unwrap();
    assert!(!est(&lp), "after a rebuild");
}

// spec/crypto.md §4 (names): A (0) rotates read (R_p), then removes M (2) by R_s. Writer W (1)
// forges F of s. Admin B (4) gets everything but R_p and removes W, rotating to e: it names R_s
// from its own timeline, whatever F says. X (3) gets everything but R_s: e not established.
#[test]
fn rotator_beside_forged_rotation_spec_crypto_4() {
    let mut lp = LocalPeer::new(5, 3_931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    for (i, r) in [(1, Role::Write), (2, Role::Read), (3, Role::Admin), (4, Role::Admin)] {
        lp.peers[0].engine.grant(&g, &tids[i], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let before = commit_ids(&mut lp, 0);
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let r_p: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let r_s: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    forge_rotation(&mut lp, 1, g, s, tids[3]);
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_p.contains(&p.id)) {
        let _ = lp.peers[4].receive(&pk.bytes, pk.blobs.clone());
    }
    assert_eq!(lp.peers[4].engine.epochs(&g).unwrap().read.current(), vec![s], "s current at B");
    lp.peers[4].engine.demote(&g, &Demotion { holder: tids[1], new: None, retain: None }).unwrap();
    let e = newest_read(&lp, 4, g).unwrap();
    assert!(e.n() > s.n());
    all.extend(lp.packages(4).unwrap());
    withheld_then_arrives(&mut lp, 3, g, e, &all, &r_s);
}

/// Rotates `rot` of `g` at peer `i`, leaving out the peers `skip` (all of them, the rotator
/// included: an epoch with no box); refused (a rotated role's secret not held), nothing.
pub(super) fn rotate_leaving_out(lp: &mut LocalPeer, i: usize, g: Tid, rot: &BTreeSet<Role>, skip: &[usize]) {
    let skip: Vec<(Tid, Option<Role>)> = skip.iter().map(|j| (lp.peers[*j].engine.me(), None)).collect();
    let _ = lp.peers[i].engine.run(|tx| {
        let held = tx.core.epochs(&g).unwrap();
        let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &skip)?.ok_or(super::SEAL_WAITS)?;
        let mut m = Mutation::new();
        let r = super::rotation_into(tx, &mut m, g, rot, &held, &holders, false)?;
        crate::engine::Engine::commit_tx(tx, m)?;
        super::record(tx, g, &r)
    });
}

/// Syncs everything, then runs rounds of every remaining node's re-seals and rotations until
/// nothing is written, and checks the re-seal invariant (`reseal_candidates`), history adds and
/// that no departed peer holds an epoch a remaining holder encrypts under (`was`: the highest
/// role each peer held; peer 0 is `g`'s first admin).
fn departures_settle(lp: &mut LocalPeer, g: Tid, seed: u64, rng: &mut Rng, was: [Option<Role>; 5]) {
    const N: usize = 5;
    let roles = [Role::Read, Role::Write, Role::Admin];
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.me()).collect();
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
        // peer 0, G's first admin, holds every role and is never demoted
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
            // re-sealed by a node that may rotate `r`; an epoch only non-rotators hold is a fork
            // the merge supersedes, or the lockout a removal ends (notes/crypto.md, Lockouts)
            let any = stay.iter().any(|&p| role[p] >= Some(r.max(Role::Write)) && ep(p).secret(e).is_some());
            let lacking: Vec<usize> = stay.iter().copied().filter(|h| role[*h] >= Some(r) && ep(*h).secret(e).is_none()).collect();
            assert!(!any || lacking.is_empty(), "seed {seed}: {r:?} holders {lacking:?} lack current epoch {e:?} another node holds");
            // history adds: every holder of `e` holds every earlier superseded established
            // secret any holder of `e` holds (spec/crypto.md §4, History add)
            let at_e: Vec<usize> = stay.iter().copied().filter(|h| role[*h] >= Some(r) && ep(*h).secret(e).is_some()).collect();
            for &p in &at_e {
                let ex = ep(p);
                for (x, _) in ex.held_established().filter(|(x, _)| x.n() < e.n() && !ex.is_current(x)) {
                    let missing: Vec<usize> = at_e.iter().copied().filter(|h| ep(*h).secret(&x).is_none()).collect();
                    assert!(missing.is_empty(), "seed {seed}: {r:?} holders {missing:?} of current {e:?} lack earlier {x:?} peer {p} holds");
                }
            }
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


// spec/permissions.md §2 (finalize before encrypting), spec/crypto.md §4 (rotating needs no
// secret; History box): first admin A (0) rotates write leaving out admin X (2), then sets an
// `until` on writer D's (1) edge. Past it, X finalizes D with the rotation although it lacks the
// current write secret: that epoch is superseded unread, and A, holding it, adds it to X's
// epoch's history, so X reads what went under it.
#[test]
fn finalize_without_secret_rotates_history_added_spec_permissions_2() {
    let mut lp = LocalPeer::new(3, 3_996, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Write]), &[2]);
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    let timed = ct::Edge { until: Some(until), ..edge(Role::Write) };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(timed), retain: None }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].clock.advance(1_000);
    let lacked = {
        let e = lp.peers[2].engine.epochs(&g).unwrap();
        assert!(e.write.newest_held().is_none(), "X lacks write");
        e.write.current()[0]
    };
    let me = tids[2];
    assert!(!lp.peers[2].engine.run(|tx| Ok(crate::flows::edges::finalizable(tx.core, &me, &g))).unwrap().is_empty(), "X may finalize D");
    let (done, blocked) = lp.peers[2].engine.ensure_rotated(&g).unwrap();
    assert_eq!(done.commits.len(), 1, "X finalized D with the rotation: {:?}", done.commits);
    assert!(blocked.is_empty(), "{blocked:?}");
    let e = lp.peers[2].engine.epochs(&g).unwrap();
    assert!(e.write.newest_held().is_some() && !e.write.is_current(&lacked), "the lacked epoch is superseded");
    assert!(e.write.secret(&lacked).is_none());
    lp.sync(2, 0).unwrap();
    assert!(!lp.peers[0].engine.reseal_due(&g, &Pass).unwrap().commits.is_empty(), "A adds the superseded secret to X's history");
    lp.sync(0, 2).unwrap();
    assert!(lp.peers[2].engine.epochs(&g).unwrap().write.secret(&lacked).is_some(), "X holds it by history");
}

// spec/crypto.md §4 (a name is met when its commit is applied with every entry it resets known),
// spec/permissions.md §2: first admin A (0) sets an `until` on writer D's (1) edge (U); past it, A
// finalizes D, rotating to e (its departs mark). X (2, an admin) holds the finalize but not U, the
// write it ends: there the finalize applies nothing and D is still a writer, so e must not be
// established, nor re-sealed to D. Once U arrives, e is.
#[test]
fn finalize_without_its_until_unmet_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 3_995, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    let timed = ct::Edge { until: Some(until), ..edge(Role::Write) };
    let u: BTreeSet<_> = lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(timed), retain: None }).unwrap().commits.into_iter().collect();
    lp.peers[0].clock.advance(1_000);
    lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(lp.peers[0].engine.core.key_holders(&g).iter().all(|h| h.0 != tids[1]), "D finalized at A");
    let e = newest_read(&lp, 0, g).unwrap();
    let all = lp.packages(0).unwrap();
    for pk in all.iter().filter(|p| !u.contains(&p.id)) {
        let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
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
// covers its commit's departures): first admin A (0) sets an `until` on writers D1 (3) and D2 (4); past
// it, admin B (1) finalizes both in one commit F. Admin X (2) holds F and D2's `until` but not
// D1's. Were F's write on D2 to apply alone there, X's rotation would name F while boxing D1, and
// A, holding everything, would take that epoch as covering D1's departure.
#[test]
fn finalize_applies_whole_or_not_spec_permissions_2() {
    let mut lp = LocalPeer::new(5, 3_989, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..5).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    for (p, r) in [(1, Role::Admin), (2, Role::Admin), (3, Role::Write), (4, Role::Write)] {
        lp.peers[0].engine.grant(&g, &tids[p], &edge(r)).unwrap();
    }
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    let mut u1 = BTreeSet::new();
    for d in [3, 4] {
        let c = lp.peers[0].engine.demote(&g, &Demotion { holder: tids[d], new: Some(timed.clone()), retain: None }).unwrap().commits;
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
        let _ = lp.peers[2].receive(&pk.bytes, pk.blobs.clone());
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
// thing held): first admin A (0) removes reader M (2) (R_s), then rotates read to e (naming R_s). X
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
            osis_commit::rewrite(&b, |ai| b.header.aspects.get(ai).is_some_and(|a| a.tid == g && a.ak.as_str() == "roles.0")).encode()
        } else {
            pk.bytes.clone()
        };
        let _ = lp.peers[3].receive(&bytes, pk.blobs.clone());
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
// actor, named by the thing the demotion is on): G's first admin is actor O (peer 0's); W (1) an
// admin of O grants D (2) read on G through the record chain (C). First admin A demotes W to write on
// O, not having received C (its frontier misses it), so C is audited away; A then gets C and
// rotates G's read to e: no edge write on G departs anyone, and O's read keyset is unchanged, so
// only the audit names W's demotion. X (3, G's admin) holds C but not the demotion: e must not
// be established there (X sees D a reader and would re-seal e to it). Once it arrives, e is.
#[test]
fn audit_dropped_grant_named_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_981, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
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
    lp.advance(1_000);
    let before = commit_ids(&mut lp, 0);
    lp.peers[0].engine.demote(&o, &Demotion { holder: tids[1], new: Some(edge(Role::Write)), retain: None }).unwrap();
    let dem: BTreeSet<_> = commit_ids(&mut lp, 0).difference(&before).copied().collect();
    lp.sync(1, 0).unwrap();
    assert!(lp.peers[0].engine.core.role_now(&tids[2], &g).is_none(), "C audited away at A");
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[]);
    let e = newest_read(&lp, 0, g).unwrap();
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !dem.contains(&p.id)) {
        let _ = lp.peers[3].receive(&pk.bytes, pk.blobs.clone());
    }
    assert!(c.iter().all(|x| lp.peers[3].engine.core.ix.commits.contains_key(x)));
    assert!(lp.peers[3].engine.core.role_now(&tids[2], &g).is_some(), "X sees D a reader");
    withheld_then_arrives(&mut lp, 3, g, e, &all, &dem);
}

// spec/crypto.md §4 (a node attributes a departure to the name of the newest of its events,
// by key, whatever thing names it): A removes D from G (rotation e1 names that removal on G);
// W, an admin of G's first admin O, grants D read on G again, boxing it at e1; A demotes W on O
// without that grant, so the audit drops it (named on O). D's newest departure is the drop,
// which e1 does not name: A must rotate before encrypting under e1, which D holds.
#[test]
fn newest_event_names_departure_spec_crypto_4() {
    for seed in [3_990, 3_991, 3_992, 3_993] {
        let mut lp = LocalPeer::new(3, seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let o = group(&mut lp, 0);
        lp.peers[0].engine.grant(&o, &tids[1], &edge(Role::Admin)).unwrap();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, o);
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        let e1 = newest_read(&lp, 0, g).unwrap();
        lp.peers[1].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
        lp.sync(1, 2).unwrap();
        assert!(lp.peers[2].engine.epochs(&g).is_some_and(|x| x.read.secret(&e1).is_some()), "seed {seed}: D holds e1");
        // ordered after the re-grant, whose author it has not seen: audited, not plain invalid
        lp.peers[0].clock.advance(5_000);
        lp.peers[0].engine.demote(&o, &Demotion { holder: tids[1], new: Some(edge(Role::Write)), retain: None }).unwrap();
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
        let _ = lp.peers[to].receive(&pk.bytes, pk.blobs.clone());
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
        let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
        let a = group(&mut lp, 0);
        lp.peers[0].engine.grant(&a, &tids[1], &edge(Role::Admin)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&a, &tids[2], &edge(Role::Read)).unwrap();
        rotate_leaving_out(&mut lp, 1, a, &read, &[]);
        let e1 = newest_read(&lp, 1, a).unwrap();
        send_skipping(&mut lp, 0, 2, &BTreeSet::new());
        let start = held_by(&lp, 2, &[a]);
        let before = commit_ids(&mut lp, 0);
        lp.peers[0].engine.demote(&a, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
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
    let ids: Vec<Tid> = lp.peers.iter().map(|p| p.engine.me()).collect();
    let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: ids[3], new: None, retain: None }).unwrap();
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
            (true, true) => osis_commit::rewrite(&b, |ai| bad.contains(&b.header.aspects[ai].ak.as_str())).encode(),
            (true, false) => forged.clone(),
            _ => pk.bytes.clone(),
        };
        for i in [1, 2, 3] {
            assert!(matches!(lp.peers[i].receive(&bytes, pk.blobs.clone()).unwrap(), crate::Ingested::Applied(_)));
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
            let _ = lp.peers[i].receive(&pk.bytes, pk.blobs.clone());
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

// spec/permissions.md §4, spec/crypto.md §5: a first admin's holder with K's keyset and none of K's secrets has K's derived read epochs, to open its label and nothing more: it wraps nothing, rotates and boxes nothing; a node not holding the first admin has none; K's real box then replaces them
#[test]
fn keyset_before_box_reads_only_spec_permissions_4() {
    let mut lp = LocalPeer::new(3, 3_391, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (a, b, c) = (lp.peers[0].engine.me(), lp.peers[1].engine.me(), lp.peers[2].engine.me());
    let admin = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
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
    assert!(e.wrap_secret(&k, None).unwrap().is_none(), "wraps nothing");
    let before = e.core.ix.commits.len();
    assert!(e.ensure_rotated(&k).unwrap().1.is_empty());
    assert!(e.grant(&k, &c, &admin).is_err(), "boxes nothing");
    assert!(e.run(|tx| super::rotate_now(tx, b, k, &BTreeSet::from([Role::Read]))).is_err(), "rotates nothing");
    assert_eq!(e.core.ix.commits.len(), before, "wrote nothing");
    assert!(lp.peers[2].engine.core.epochs(&k).is_none_or(|e| !e.holds_any()), "not the first admin's holder");

    lp.sync(0, 1).unwrap();
    let e = &lp.peers[1].engine;
    let real = e.epochs(&k).unwrap();
    assert!(e.core.ix.secrets.get(&k).is_some() && real.read.newest_held().is_some() && real.admin.newest_held().is_some(), "the box replaces them");
}

// spec/crypto.md §4 Met, spec/permissions.md §2 (a finalize names the writes it ends): first admin A (0)
// sets an `until` on writers D1 (2) and D2 (3), then renews D2 before it; admin B (1), not holding
// the renewal, finalizes both past it, rotating to e. Where the renewal is held, the finalize's
// write on D2 ends a write already superseded and applies nothing, yet the finalize is held whole,
// so its name is met: e is established everywhere and nobody stays blocked under G.
#[test]
fn finalize_beside_renewal_settles_spec_crypto_4() {
    let mut lp = LocalPeer::new(4, 3_993, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    for d in [2, 3] {
        lp.peers[0].engine.grant(&g, &tids[d], &edge(Role::Write)).unwrap();
    }
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    for d in [2, 3] {
        lp.peers[0].engine.demote(&g, &Demotion { holder: tids[d], new: Some(timed.clone()), retain: None }).unwrap();
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
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    let timed = ct::Edge { until: Some(WallMs(lp.peers[0].engine.core.now().0 + 100)), ..edge(Role::Write) };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: Some(timed), retain: None }).unwrap();
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

// spec/crypto.md §4 (rotating needs no secret; merge; History box): B and D, writers granted
// concurrently, each rotate read leaving the other out (each lacks the other's fork), and A
// removes reader X, then is gone. Each knowing the removal merges at once, lacking the other's
// fork; the merges fork and settle by their merger, and each ends holding every fork's secret
// (the merges' history boxes, and history adds for what they lacked). X is boxed at none of it.
#[test]
fn forks_unboxed_with_departure_merge_lacking_secrets_spec_crypto_4() {
    let mut found = false;
    for seed in 0..12u64 {
        let mut lp = LocalPeer::new(4, 7100 + seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (b, d, x) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[3].engine.me());
        let g = group(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&g, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let mut forks = Vec::new();
        for (i, other) in [(1, d), (2, b)] {
            forks.push(lp.peers[i]
                .engine
                .run(|tx| {
                    let held = tx.core.epochs(&g).unwrap();
                    let holders = super::recipients(tx, &tx.core.writer().unwrap(), &g, &[(other, None)])?.ok_or(super::SEAL_WAITS)?;
                    let mut m = Mutation::new();
                    let rot = super::rotation_into(tx, &mut m, g, &[Role::Read].into(), &held, &holders, false)?;
                    crate::engine::Engine::commit_tx(tx, m)?;
                    super::record(tx, g, &rot)?;
                    Ok(rot.rotated[0].epoch)
                })
                .unwrap());
        }
        lp.peers[0].engine.demote(&g, &Demotion { holder: x, new: None, retain: None }).unwrap();
        // A is gone: only B and D exchange
        lp.sync(0, 1).unwrap();
        lp.sync(0, 2).unwrap();
        lp.sync(1, 2).unwrap();
        lp.sync(2, 1).unwrap();
        if blocked_at(&mut lp, 1, g).is_empty() || blocked_at(&mut lp, 2, g).is_empty() {
            continue;
        }
        found = true;
        for p in [1, 2] {
            let (done, still) = lp.peers[p].engine.ensure_rotated(&g).unwrap();
            assert!(!done.commits.is_empty(), "peer {p} did not merge lacking a fork");
            assert!(still.is_empty(), "peer {p} still blocked: {still:?}");
        }
        for _ in 0..4 {
            for p in [1, 2] {
                let _ = lp.peers[p].engine.ensure_rotated(&g);
                let _ = lp.peers[p].engine.reseal_due(&g, &Pass);
            }
            lp.sync(1, 2).unwrap();
            lp.sync(2, 1).unwrap();
        }
        for p in [1, 2] {
            assert!(blocked_at(&mut lp, p, g).is_empty(), "peer {p} still blocked under G");
            let e = lp.peers[p].engine.epochs(&g).unwrap();
            assert_eq!(e.read.current().len(), 1, "peer {p}: forks merged");
            assert!(e.read.holds_current(), "peer {p} holds the merge");
            assert!(forks.iter().all(|f| e.read.secret(f).is_some()), "peer {p} lacks a fork's secret");
        }
        let (e, _) = lp.peers[1].engine.epochs(&g).unwrap().read.newest_held().unwrap();
        let s = lp.peers[1].engine.get_typed(&g, &ct::SECRETS).unwrap().unwrap();
        assert!(!s.boxes.contains_key(&osis_keys::aspects::box_key(x, Role::Read, &e)), "X boxed at the merge");
        break;
    }
    assert!(found, "no seed reached both blocked");
}

// spec/permissions.md §3 (a `secrets.0` delta putting history boxes only needs the role its
// keys name), spec/crypto.md §4 (History add: any holder may add): reader R's put of a history
// entry at G's current read epoch is valid at G's admin; its put of a box is not (at least
// write).
#[test]
fn reader_history_add_valid_box_put_not_spec_permissions_3() {
    let mut lp = LocalPeer::new(2, 7_400, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let r = lp.peers[1].engine.me();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &r, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let (e, secret) = {
        let ep = lp.peers[1].engine.epochs(&g).unwrap();
        let (e, s) = ep.read.newest_held().expect("R holds G's read");
        (e, s.clone())
    };
    let names = lp.peers[1].engine.run(|tx| Ok(tx.core.epochs(&g).unwrap().read.history_names(Role::Read, &e, &tx.core.names_held(&g)).unwrap())).unwrap();
    let ct = osis_crypto::seal_history(&secret, &g, Role::Read, &e, &[], &names.to_value()).unwrap();
    let mut m = Mutation::new();
    let history = [(osis_keys::aspects::history_key(Role::Read, &e), ct)].into_iter().collect();
    crate::flows::put_secrets(&mut m, g, &osis_keys::SecretsWrite { history, ..Default::default() }, true).unwrap();
    let add = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    let rcpt = osis_keys::Recipient { holder: r, role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem: lp.peers[1].engine.identity().keys().kem.public().clone(), seed: None } };
    let w = lp.peers[1]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            Ok(osis_keys::box_holder(&g, &held, &osis_keys::HistoryBoxes::new(), &rcpt, &[Role::Read].into(), &mut *tx.rng)?.unwrap())
        })
        .unwrap();
    let mut m = Mutation::new();
    crate::flows::put_secrets(&mut m, g, &w, true).unwrap();
    let boxed = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
    lp.sync(1, 0).unwrap();
    assert_eq!(lp.peers[0].engine.body_valid(&add, &g, &osis_base::Ak::new("secrets.0").unwrap()), Some(true), "a reader's history add");
    assert_eq!(lp.peers[0].engine.body_valid(&boxed, &g, &osis_base::Ak::new("secrets.0").unwrap()), Some(false), "a reader's box");
}

/// The box keys of `x`'s boxes in `t`'s `secrets.0` at peer `i`.
fn boxes_of(lp: &mut LocalPeer, i: usize, t: Tid, x: Tid) -> BTreeSet<ct::BoxKey> {
    let s = lp.peers[i].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
    s.boxes.keys().filter(|k| k.holder == x).cloned().collect()
}

// spec/permissions.md §3 (a grant boxes the holder at the current epochs held, after the
// rotations the node may make), spec/crypto.md §4: as
// `forks_unboxed_with_departure_merge_lacking_secrets_*`, B and D admins, both blocked by A's
// removal of X. B grants fresh Z read: B merges first (lacking D's fork), Z gets B's merge
// epoch, and the removed X gets no box.
#[test]
fn grant_merges_first_boxes_grantee_only_spec_crypto_4() {
    let mut found = false;
    for seed in 0..24u64 {
        let mut lp = LocalPeer::new(5, 7300 + seed, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (b, d, x, z) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[3].engine.me(), lp.peers[4].engine.me());
        let g = group(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &b, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&g, &d, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&g, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from([Role::Read]), &[2]);
        rotate_leaving_out(&mut lp, 2, g, &BTreeSet::from([Role::Read]), &[1]);
        lp.peers[0].engine.demote(&g, &Demotion { holder: x, new: None, retain: None }).unwrap();
        lp.sync(0, 1).unwrap();
        lp.sync(0, 2).unwrap();
        lp.sync(1, 2).unwrap();
        lp.sync(2, 1).unwrap();
        if blocked_at(&mut lp, 1, g).is_empty() || blocked_at(&mut lp, 2, g).is_empty() {
            continue;
        }
        found = true;
        let before = boxes_of(&mut lp, 1, g, x);
        let done = lp.peers[1].engine.grant(&g, &z, &edge(Role::Read)).unwrap();
        assert_eq!(done.commits.len(), 2, "B merged, then granted: {:?}", done.commits);
        assert!(blocked_at(&mut lp, 1, g).is_empty(), "B still blocked after its merge");
        assert!(boxes_of(&mut lp, 1, g, x).is_subset(&before), "X boxed by the grant");
        let e = lp.peers[1].engine.epochs(&g).unwrap();
        assert_eq!(e.read.current().len(), 1, "B's merge alone is current at B");
        let (m, _) = e.read.newest_held().unwrap();
        assert!(boxes_of(&mut lp, 1, g, z).contains(&osis_keys::aspects::box_key(z, Role::Read, &m)), "Z not boxed at the merge");
        lp.sync(1, 4).unwrap();
        assert!(lp.peers[4].engine.epochs(&g).unwrap().read.secret(&m).is_some(), "Z holds no secret of the merge");
        break;
    }
    assert!(found, "no seed reached both blocked");
}

// spec/permissions.md §2 (finalize), §3 (re-seal a current holder): admin X (2) lacks write
// (rotated leaving it out), so it may finalize writer D's (1) ended edge but cannot; A then
// rotated read leaving D out. X boxes D nothing (a re-seal or re-share of an ended grant it
// must finalize is no box to a current holder), so D never reads the new read epoch.
#[test]
fn ended_holder_not_resealed_spec_permissions_2() {
    let mut lp = LocalPeer::new(3, 3_997, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Write]), &[2]);
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    let timed = ct::Edge { until: Some(until), ..edge(Role::Write) };
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(timed), retain: None }).unwrap();
    rotate_leaving_out(&mut lp, 0, g, &BTreeSet::from([Role::Read]), &[1]);
    lp.sync(0, 2).unwrap();
    lp.peers[2].clock.advance(1_000);
    let me = tids[2];
    assert!(!lp.peers[2].engine.run(|tx| Ok(crate::flows::edges::finalizable(tx.core, &me, &g))).unwrap().is_empty(), "X may finalize D");
    let (e, _) = lp.peers[2].engine.epochs(&g).unwrap().read.newest_held().unwrap();
    let _ = lp.peers[2].engine.reseal_due(&g, &Pass);
    let _ = lp.peers[2].engine.reshare(&g, &tids[1]);
    let d = tids[1];
    let _ = lp.peers[2].engine.run(|tx| super::reseal_one(tx, g, d, &BTreeSet::from([Role::Read])));
    assert!(!boxes_of(&mut lp, 2, g, tids[1]).contains(&osis_keys::aspects::box_key(tids[1], Role::Read, &e)), "X boxed ended D at the new read epoch");
}

// spec/permissions.md §2 (finalize; lacking a secret, wait for a re-seal), §3 (re-seal):
// writers B and D, granted concurrently, each rotate G's read leaving the other out; reader X's
// edge ends by `until` and first admin A is gone. Each may finalize X but lacks the other's
// fork (made by a writer); each re-seals the other at its own fork (X, ended, boxed nothing),
// then finalizes, and the forks merge.
#[test]
fn forks_with_ended_edge_finalize_after_reseal_spec_permissions_2() {
    let mut lp = LocalPeer::new(4, 7_400, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (b, d, x) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[3].engine.me());
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &b, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Write)).unwrap();
    let until = WallMs(lp.peers[0].engine.core.now().0 + 100);
    lp.peers[0].engine.grant(&g, &x, &ct::Edge { until: Some(until), ..edge(Role::Read) }).unwrap();
    lp.sync_all().unwrap();
    rotate_leaving_out(&mut lp, 1, g, &BTreeSet::from([Role::Read]), &[2]);
    rotate_leaving_out(&mut lp, 2, g, &BTreeSet::from([Role::Read]), &[1]);
    lp.sync(1, 2).unwrap();
    lp.sync(2, 1).unwrap();
    for p in [1, 2] {
        lp.peers[p].clock.advance(1_000);
        assert!(!lp.peers[p].engine.epochs(&g).unwrap().read.holds_current(), "peer {p} holds both forks");
    }
    for _ in 0..4 {
        for p in [1, 2] {
            let _ = lp.peers[p].engine.reseal_due(&g, &Pass);
            let _ = lp.peers[p].engine.ensure_rotated(&g);
        }
        lp.sync(1, 2).unwrap();
        lp.sync(2, 1).unwrap();
    }
    for p in [1, 2] {
        assert!(lp.peers[p].engine.core.key_holders(&g).iter().all(|h| h.0 != x), "peer {p}: X not finalized");
        assert!(blocked_at(&mut lp, p, g).is_empty(), "peer {p} still blocked under G");
        let e = lp.peers[p].engine.epochs(&g).unwrap();
        assert!(e.read.holds_current(), "peer {p} lacks a current read epoch");
        let (n, _) = e.read.newest_held().unwrap();
        assert!(!boxes_of(&mut lp, p, g, x).contains(&osis_keys::aspects::box_key(x, Role::Read, &n)), "X boxed at the newest read epoch");
    }
}

// spec/crypto.md §4 (History box; Encrypting under: a history entry is encrypted under its
// epoch): A removes reader P (f) and rotates again (g1); B, unaware, rotates twice (e1, e2),
// boxing P. At A, e2 is current beside g1 and does not cover P's removal: the history box A
// would write at e2 (a grant or re-seal made while blocked) copies what e2's entries list and
// adds nothing, so P, holding e2, never gets f; at g1 it carries f.
#[test]
fn blocked_epoch_history_carries_nothing_new_spec_crypto_4() {
    let read = BTreeSet::from([Role::Read]);
    let mut lp = LocalPeer::new(3, 4_201, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..3).map(|i| lp.peers[i].engine.me()).collect();
    let g = group(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &tids[1], &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &tids[2], &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, retain: None }).unwrap();
    let f = newest_read(&lp, 0, g).unwrap();
    rotate_leaving_out(&mut lp, 0, g, &read, &[]);
    let g1 = newest_read(&lp, 0, g).unwrap();
    rotate_leaving_out(&mut lp, 1, g, &read, &[]);
    rotate_leaving_out(&mut lp, 1, g, &read, &[]);
    let e2 = newest_read(&lp, 1, g).unwrap();
    send_skipping(&mut lp, 1, 0, &BTreeSet::new());
    let me = tids[0];
    let (cur, hist, blocked) = lp.peers[0]
        .engine
        .run(|tx| {
            let deps = super::departures(tx, &g)?;
            let blocked = super::blocked_epoch(tx, &me, &g, Role::Read, &e2, &deps, super::Walk::Encrypt)?;
            Ok((tx.core.epochs(&g).unwrap().read.current(), super::history_boxes(tx, &me, &g)?, blocked))
        })
        .unwrap();
    assert_eq!(BTreeSet::from_iter(cur), BTreeSet::from([g1, e2]), "g1 and e2 current at A");
    assert!(f.n() < e2.n() && blocked, "e2 does not cover P's removal");
    assert!(!hist[&(Role::Read, e2)].earlier.contains_key(&f), "A's history at e2 hands P f");
    assert!(hist[&(Role::Read, g1)].earlier.contains_key(&f), "A's history at g1 lacks f");
}

// spec: none (internal: notes/engine.md, Derived values). A thing's epochs are derived when
// something they are read from changed, not per ask and not per commit held.
#[test]
fn epochs_are_derived_once_per_change_of_what_they_read() {
    let mut lp = LocalPeer::new(2, 31, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (t, other) = (group(&mut lp, 0), group(&mut lp, 0));
    let w = lp.peers[1].engine.me();
    let derived = |lp: &mut LocalPeer| {
        crate::costs::take();
        assert!(lp.peers[0].engine.core.epochs(&t).is_some());
        crate::costs::take().iter().filter(|x| x.0 == "epochs").map(|x| x.2).sum::<u64>()
    };
    derived(&mut lp);
    assert_eq!(derived(&mut lp), 0, "asked again");
    let ak = osis_base::Ak::new("x:a.0").unwrap();
    for i in 0..5 {
        for on in [t, other] {
            let mut m = Mutation::new();
            m.set(on, &ak, &osis_base::Value::Int(i)).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
    }
    assert_eq!(derived(&mut lp), 0, "content commits, on it and elsewhere");
    lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
    assert!(derived(&mut lp) > 0, "a grant on it");
}
