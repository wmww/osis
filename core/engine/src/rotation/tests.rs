//! Rotation tests (spec/permissions.md §3, spec/crypto.md §4).

#![allow(clippy::unwrap_used)]
use crate::Mutation;
use crate::flows::{Demotion, PreSync};
use crate::local_peer::LocalPeer;
use crate::engine::Tx;
use osis_base::{Role, Tid, WallMs};
use osis_keys::Departure;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Delivers every commit of peer `from` to peer `to` without the `secrets.0` deltas of `x`
/// (what a node that does not read `x` gets of them: certificates).
fn deliver_without_secrets(lp: &mut LocalPeer, from: usize, to: usize, x: Tid) {
    for pk in lp.packages(from).unwrap() {
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai, _| b.header.aspects.get(ai).is_some_and(|a| a.tid == x && a.ak.as_str() == "secrets.0"));
        let _ = lp.peers[to].engine.ingest(&cut.encode(), pk.blobs.clone());
    }
}

/// Peers: 0 = a (G's admin), 1 = b (X's admin), 2 = W, 3 = Z (holders of X); X a writer
/// of G. Every commit reaches a without X's `secrets.0` deltas when `strip`.
fn team(seed: u64) -> (LocalPeer, Tid, Tid, Tid, Tid) {
    let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (a, b, w, z) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, b);
    lp.peers[1].commit(m).unwrap();
    lp.peers[1].engine.give_own_secrets(&x).unwrap();
    lp.peers[1].engine.grant(&x, &w, &write).unwrap();
    lp.peers[1].engine.grant(&x, &z, &write).unwrap();
    lp.sync(1, 2).unwrap();
    lp.sync(1, 3).unwrap();
    deliver_without_secrets(&mut lp, 1, 0, x);
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&g).unwrap();
    lp.peers[0].engine.grant(&g, &x, &write).unwrap();
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "covered before");
    (lp, x, g, w, z)
}

// spec/crypto.md §4 (times are the authors' word: only the departure's own commit setting
// M's keyset, or a held rotation delta without the leaver's box, shows it unboxed): W leaves
// X by itself with a `ts` before a rotation of X that, made unaware of it (b removes Z),
// still boxed W; G's admin, holding none of X's `secrets.0`, keeps G's epoch uncovered.
#[test]
fn backdated_self_removal_uncovered_spec_crypto_4() {
    let (mut lp, x, g, w, z) = team(932);
    // b's clock runs ahead of W's: its rotation's ts is later than W's departure
    lp.peers[1].clock.advance(120_000);
    lp.peers[1].engine.demote(&x, &Demotion { holder: z, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[2].engine.demote(&x, &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap();
    deliver_without_secrets(&mut lp, 1, 0, x);
    deliver_without_secrets(&mut lp, 2, 0, x);
    assert_eq!(lp.peers[0].engine.roster(&x).get(&w), None, "a sees W gone");
    let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(still.contains(&Role::Read), "W's departure is not covered by the later-stamped rotation: {still:?}");
}

// spec/crypto.md §4: the same unaware rotation, its `secrets.0` delta held by G's admin: the
// delta boxes W, so the departure stays uncovered; after a rotation of X by an admin that
// saw W leave (its delta boxes no W), G's admin rotates G and covers it.
#[test]
fn unaware_rotation_uncovered_aware_covers_spec_crypto_4() {
    let (mut lp, x, g, w, z) = team(933);
    lp.peers[1].clock.advance(120_000);
    lp.peers[1].engine.demote(&x, &Demotion { holder: z, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[2].engine.demote(&x, &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync(1, 0).unwrap();
    lp.sync(2, 0).unwrap();
    let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(still.contains(&Role::Read), "the unaware rotation boxed W: {still:?}");
    // b learns of W's departure and rotates X again
    lp.sync(2, 1).unwrap();
    lp.peers[1].engine.rotate_eagerly().unwrap();
    lp.sync(1, 0).unwrap();
    let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(still.is_empty(), "an aware rotation of X lets G's admin rotate G and cover W: {still:?}");
}

// spec/permissions.md §4 (exception: under an uncovered epoch a non-rotator places only the
// revokes of the departures that leave it uncovered now): Z's removal from X, which G's
// admin already covered by rotating G, is not among them; W's later self-removal is.
#[test]
fn only_uncovering_revokes_placed_spec_permissions_4() {
    let (mut lp, x, g, w, z) = team(934);
    let rz = *lp.peers[1].engine.demote(&x, &Demotion { holder: z, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
    lp.sync(1, 0).unwrap();
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "G's admin rotated G past Z's removal");
    lp.sync(1, 2).unwrap();
    let rw = *lp.peers[2].engine.demote(&x, &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
    lp.sync(2, 0).unwrap();
    let revokes = lp.peers[0].engine.inside_holder_revokes(&g, &Default::default());
    assert!(revokes.contains_key(&rw), "W's self-removal leaves G uncovered");
    // Z's removal may ride along as chain material (edges), never as a whole write
    let h = lp.peers[0].engine.header(&rz).unwrap();
    let si = h.aspects.iter().position(|a| a.tid == x && a.ak.as_str() == "secrets.0").unwrap();
    assert!(revokes.get(&rz).is_none_or(|p| p.iter().all(|(ai, _)| *ai != si)), "Z's removal is covered: not placed whole");
}

// spec/permissions.md §4 (the revoke of a departure inside a holder is the write lowering
// the departed holder's edge on the actor it left, the last on its chain): G <- X1 <- ... <-
// Xk, W a writer of Xk leaves it by itself; G's admin finds W's removal on Xk at every depth.
#[test]
fn nested_departure_revoke_is_the_leavers_write_spec_permissions_4() {
    for k in 1..=4 {
        let mut lp = LocalPeer::new(3, 935 + k as u64, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let w = lp.peers[2].engine.tid();
        let xs: Vec<Tid> = (0..k).map(|_| group(&mut lp, 1)).collect();
        lp.peers[1].engine.grant(&xs[k - 1], &w, &edge(Role::Write)).unwrap();
        for i in (1..k).rev() {
            lp.peers[1].engine.grant(&xs[i - 1], &xs[i], &edge(Role::Write)).unwrap();
        }
        let g = group(&mut lp, 0);
        lp.sync_all().unwrap();
        lp.peers[0].engine.grant(&g, &xs[0], &edge(Role::Write)).unwrap();
        assert!(lp.peers[0].engine.inside_holder_revokes(&g, &Default::default()).is_empty(), "k={k}: nothing departed yet");
        let rw = *lp.peers[2].engine.demote(&xs[k - 1], &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap().commits.first().unwrap();
        lp.sync(2, 0).unwrap();
        assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.contains(&Role::Read), "k={k}: W's departure leaves G uncovered");
        let revokes = lp.peers[0].engine.inside_holder_revokes(&g, &Default::default());
        assert!(revokes.contains_key(&rw), "k={k}: W's removal from X{k} is placed");
    }
}

// spec/crypto.md §4 (a node holding no secret of holder M judges by M's keyset and the
// boxes of M it holds; holding none, a departure from M that M's keyset predates is not
// covered): W leaves team X by self-removal (nothing rotates X); G's admin, who holds no
// secret and no `secrets.0` of X, must not count G's epoch as covering W's departure inside
// X (W still reads through X's old epoch), and cannot fix it by rotating G.
#[test]
fn departure_inside_unheld_actor_uncovered_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 931, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (a, b, w) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let write = ct::Edge { role: Role::Write, until: None, invite: None, since: None, tied: None };
    // X: b's team with W
    let mut m = Mutation::new();
    let x = lp.peers[1].engine.new_thing(&mut m, b);
    lp.peers[1].commit(m).unwrap();
    lp.peers[1].engine.give_own_secrets(&x).unwrap();
    lp.peers[1].engine.grant(&x, &w, &write).unwrap();
    lp.sync(1, 2).unwrap();
    deliver_without_secrets(&mut lp, 1, 0, x);
    // G: a's group, X a writer of it
    let mut m = Mutation::new();
    let g = lp.peers[0].engine.new_thing(&mut m, a);
    lp.peers[0].commit(m).unwrap();
    lp.peers[0].engine.give_own_secrets(&g).unwrap();
    lp.peers[0].engine.grant(&g, &x, &write).unwrap();
    assert!(lp.peers[0].engine.get_typed(&x, &ct::SECRETS).unwrap().is_none_or(|s| s.boxes.is_empty()), "a holds nothing of X's secrets.0");
    assert!(lp.peers[0].engine.ensure_rotated(&g).unwrap().1.is_empty(), "covered before");
    // W leaves X by itself: no rotation of X
    lp.peers[2].engine.demote(&x, &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap();
    deliver_without_secrets(&mut lp, 2, 0, x);
    assert_eq!(lp.peers[0].engine.roster(&x).get(&w), None, "a sees W gone");
    let (_, still) = lp.peers[0].engine.ensure_rotated(&g).unwrap();
    assert!(still.contains(&Role::Read), "W's departure inside X is not covered: {still:?}");
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
    let r1 = lp.peers[0].engine.demote(&t, &Demotion { holder: w, new: None, presync: PreSync::Synced }).unwrap().commits;
    (lp, t, r1)
}

fn uncovered_at(lp: &mut LocalPeer, i: usize, t: Tid) -> BTreeSet<Role> {
    lp.peers[i].engine.run(|tx| super::uncovered_roles(tx, &t)).unwrap()
}

fn keys_secrets() -> [osis_base::Ak; 2] {
    ["keys.0", "secrets.0"].map(|k| osis_base::Ak::new(k).unwrap())
}

// spec/crypto.md §4 (an epoch whose rotation commit a rotator does not hold counts as
// written by any departed party that could have rotated it): N, granted admin after the
// owner compacted and dropped R1's bodies, does not know who wrote the read epoch, and W (a
// writer) is gone: it rotates read before encrypting under it. Holding R1 it does not.
#[test]
fn unheld_rotation_counts_as_departed_partys_spec_crypto_4() {
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
        if !compact {
            assert!(uncovered_at(&mut lp, 3, t).is_empty(), "R1 held: covered");
            assert!(lp.peers[3].engine.ensure_rotated(&t).unwrap().0.commits.is_empty(), "no extra rotation");
            continue;
        }
        assert!(uncovered_at(&mut lp, 3, t).contains(&Role::Read), "introducer unknown, a writer gone");
        let (done, still) = lp.peers[3].engine.ensure_rotated(&t).unwrap();
        assert!(!done.commits.is_empty() && still.is_empty(), "{still:?}");
        assert_ne!(newest_read(&lp, 3, t), before, "rotated");
        assert!(uncovered_at(&mut lp, 3, t).is_empty(), "its own rotation is known");
        // the owner, holding R1's record, needs no rotation
        assert!(uncovered_at(&mut lp, 0, t).is_empty());
    }
}

// spec/crypto.md §4, spec/permissions.md §5.2: N drops R1's `keys.0` body under admin P's
// compaction snapshot S; the owner then demotes P with a frontier not listing S, so S turns
// invalid and that body is missing again at N (R1's `secrets.0` still held): the read epoch's
// introducer is unknown there and N rotates read.
#[test]
fn rotation_missing_again_counts_as_departed_partys_spec_crypto_4() {
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
    assert!(uncovered_at(&mut lp, 3, t).is_empty(), "the dropped rotation stays known");
    lp.peers[0].engine.demote(&t, &Demotion { holder: p, new: Some(edge(Role::Read)), presync: PreSync::Synced }).unwrap();
    lp.sync(0, 3).unwrap();
    assert!(!lp.peers[3].engine.core.ix.commits.get(&s).unwrap().valid.iter().any(|v| *v), "S invalid at N");
    assert!(uncovered_at(&mut lp, 3, t).contains(&Role::Read), "R1 missing again: introducer unknown");
    let (done, still) = lp.peers[3].engine.ensure_rotated(&t).unwrap();
    assert!(!done.commits.is_empty() && still.is_empty(), "{still:?}");
}

/// A thing of peer `i`'s with secrets of its own.
fn group(lp: &mut LocalPeer, i: usize) -> Tid {
    let me = lp.peers[i].engine.tid();
    let mut m = Mutation::new();
    let g = lp.peers[i].engine.new_thing(&mut m, me);
    lp.peers[i].commit(m).unwrap();
    lp.peers[i].engine.give_own_secrets(&g).unwrap();
    g
}

fn edge(role: Role) -> ct::Edge {
    ct::Edge { role, until: None, invite: None, since: None, tied: None }
}

fn newest_read(lp: &LocalPeer, i: usize, t: Tid) -> Option<osis_crypto::Epoch> {
    lp.peers[i].engine.epochs(&t).and_then(|e| e.read.newest_held().map(|x| x.0))
}

/// Every chain of at most `depth` actors below `a` (revisits allowed, never through the
/// departed holder), one departure each: the oracle of `walk_matches_path_walk` and
/// `walk_with_cycles_keeps_every_bounded_chain`.
fn path_walk(tx: &mut Tx<'_>, a: &Tid, depth: usize, out: &mut BTreeSet<Departure>) -> crate::error::Result<()> {
    let mut mine = super::departures::direct_departures(tx, a, &mut None)?;
    if depth > 0 {
        for (x, _, _) in tx.core.current_holders(a) {
            if x == *a || !tx.core.has_own_secrets(&x) {
                continue;
            }
            let mut inner = BTreeSet::new();
            path_walk(tx, &x, depth - 1, &mut inner)?;
            for d in inner {
                if d.holder != *a {
                    mine.insert(Departure::inside(x, &d));
                }
            }
        }
    }
    out.extend(mine);
    Ok(())
}

type Key = (Option<Tid>, Option<Tid>, Tid, Tid, Role);
type Decisions = (BTreeSet<(Key, [bool; 3])>, Vec<BTreeSet<Key>>, BTreeSet<Role>);

/// What the rotation decisions read of departures `deps` of `a`: each class (first and
/// second actor, actor left, holder, role) with the first actor's verdicts, the uncovered
/// classes per role at `a`'s newest held epoch, and the uncovered roles.
fn decisions(tx: &mut Tx<'_>, a: &Tid, deps: Vec<Departure>) -> Decisions {
    let held = super::held_actors(tx).unwrap();
    let secrets = crate::flows::secrets_in(tx, a).unwrap();
    let held = super::Judge::new(tx.core, &held);
    let key = |d: &Departure| (d.via.first().copied(), d.via.get(1).copied(), d.via.last().copied().unwrap_or(*a), d.holder, d.from);
    let classes = deps
        .iter()
        .map(|d| match d.via.split_first() {
            Some((m, rest)) => (key(d), super::departures::verdicts(&held, m, &Departure { via: rest.clone(), holder: d.holder, from: d.from })),
            None => (key(d), super::departures::verdicts(&held, a, d)),
        })
        .collect();
    let mut per_role = Vec::new();
    if let Some(epochs) = tx.core.epochs(a) {
        for r in osis_keys::ROLES {
            let un = epochs.role(r).newest_held().map(|(e, _)| osis_keys::uncovered(a, &secrets, r, &e, &deps, &held).into_iter().map(key).collect()).unwrap_or_default();
            per_role.push(un);
        }
    }
    let roles = super::uncovered_roles_of(tx, a, deps).unwrap();
    (classes, per_role, roles)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// Random holder graphs of 7 actors (with back edges: cycles, when `cyclic`), three leaf
/// nodes, random removals, demotions and partial cascades; compares, for every actor, the
/// rotation decisions from `departures` with those from the path walk.
fn differential(seed: u64, cyclic: bool) -> (usize, usize) {
    const N: usize = 7;
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(4, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let leaves = [1, 2, 3].map(|i| lp.peers[i].engine.tid());
    let gs: Vec<Tid> = (0..N).map(|_| group(&mut lp, 0)).collect();
    let roles = [Role::Read, Role::Write, Role::Admin];
    let mut edges: Vec<(Tid, Tid)> = Vec::new();
    for i in 0..N {
        for j in 0..N {
            let p = if i < j { 50 } else if cyclic && i > j { 12 } else { 0 };
            if rng.next(100) < p && lp.peers[0].engine.grant(&gs[i], &gs[j], &edge(roles[rng.next(3) as usize])).is_ok() {
                edges.push((gs[i], gs[j]));
            }
        }
    }
    let mut leaf_edges: Vec<(Tid, Tid)> = Vec::new();
    for l in leaves {
        for _ in 0..3 {
            let g = gs[N / 2 + rng.next((N - N / 2) as u64) as usize];
            if lp.peers[0].engine.grant(&g, &l, &edge(roles[rng.next(3) as usize])).is_ok() {
                leaf_edges.push((g, l));
            }
        }
    }
    for _ in 0..8 {
        let pick = rng.next(10);
        let pool = if pick < 7 { &leaf_edges } else { &edges };
        if pick < 9 && !pool.is_empty() {
            let (t, m) = pool[rng.next(pool.len() as u64) as usize];
            let new = [None, Some(edge(Role::Read)), Some(edge(Role::Write))][rng.next(3) as usize].clone();
            let _ = lp.peers[0].engine.demote(&t, &Demotion { holder: m, new, presync: PreSync::Synced });
        } else {
            let _ = lp.peers[0].engine.ensure_rotated(&gs[rng.next(N as u64) as usize]);
        }
    }
    let (mut same, mut all) = (0, 0);
    for a in &gs {
        let a = *a;
        let (old, new) = lp.peers[0]
            .engine
            .run(|tx| {
                let mut out = BTreeSet::new();
                path_walk(tx, &a, 8, &mut out)?;
                let old = decisions(tx, &a, out.into_iter().collect());
                let deps = super::departures(tx, &a)?;
                let new = decisions(tx, &a, deps);
                Ok((old, new))
            })
            .unwrap();
        all += 1;
        if old == new {
            same += 1;
        } else {
            // with cycles, a chain longer than the bounded walk's could add a class
            assert!(cyclic, "seed {seed}: {a:?}\nold {old:?}\nnew {new:?}");
            assert!(old.0.is_subset(&new.0) && old.2.is_subset(&new.2), "seed {seed}: every bounded chain's class is kept");
        }
    }
    (same, all)
}

// spec/crypto.md §4: on acyclic holder graphs (depth under the old cap), one departure per
// class gives exactly the path walk's rotation decisions.
#[test]
fn walk_matches_path_walk() {
    for seed in 0..6 {
        differential(7_100 + seed, false);
    }
}

// spec/crypto.md §4: with cycles, the walk's classes and decisions are those of every
// chain up to 8 actors, revisits included (the merge is exact; on these seeds no longer
// chain adds a class).
#[test]
fn walk_with_cycles_keeps_every_bounded_chain() {
    let (mut same, mut all) = (0, 0);
    for seed in 0..6 {
        let (s, n) = differential(7_200 + seed, true);
        same += s;
        all += n;
    }
    assert_eq!(same, all, "{same} of {all} alike");
}

/// The walk over a chain G0 (the walked actor) <- G1 <- ... <- GL, departures from the
/// levels in `departed`: (kept departures, distinct chain hops they hold, chain actors they
/// would hold unshared).
fn chain_walk(l: usize, departed: impl Fn(usize) -> bool) -> (usize, usize, usize) {
    let t = |i: usize| Tid::from_bytes({
        let mut b = [0u8; 15];
        b[..8].copy_from_slice(&(i as u64).to_be_bytes());
        b
    });
    let leaf = |i: usize| t(i + 1_000_000);
    let parents: BTreeMap<Tid, Vec<Tid>> = (1..=l).map(|i| (t(i), vec![t(i - 1)])).collect();
    let direct = (1..=l).map(|i| (t(i), if departed(i) { BTreeSet::from([Departure::holder(leaf(i), Role::Read)]) } else { BTreeSet::new() })).collect();
    let held = osis_keys::MemoryHeldActors::default();
    let found = super::departures::walk(&parents, direct, |v, d| super::departures::class_of(&held, v, d));
    let deps: Vec<&Departure> = found.iter().filter(|(v, _)| **v != t(0)).flat_map(|(_, f)| f.values()).collect();
    let hops: std::collections::HashSet<usize> = deps.iter().flat_map(|d| d.via.hop_ids()).collect();
    (deps.len(), hops.len(), deps.iter().map(|d| d.via.len()).sum())
}

// issues/rotation-chain-cost.md: the walk's memory is linear in the departures it keeps
// (one hop each, tails shared), not in the sum of their chain lengths.
#[test]
fn walk_memory_linear_in_chain_depth() {
    for l in [100, 1000] {
        let (kept, hops, unshared) = chain_walk(l, |i| i == l);
        assert_eq!((kept, hops, unshared), (l, l - 1, l * (l - 1) / 2), "L = {l}");
    }
    // a departure at every level: kept departures grow with L^2, each holding one hop
    for l in [100, 200] {
        let (kept, hops, _) = chain_walk(l, |_| true);
        assert_eq!((kept, hops), (l * (l + 1) / 2, l * (l - 1) / 2), "L = {l}");
    }
}

// spec/crypto.md §4 (no depth bound): a node removed 12 actors below G0 (G11 in G10 ... in
// G0): the cascade rotates every level, top-down, and the removed node holds none of it.
#[test]
fn removal_twelve_deep_rotates_every_level_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 941, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let gs: Vec<Tid> = (0..12).map(|_| group(&mut lp, 0)).collect();
    for w in gs.windows(2) {
        lp.peers[0].engine.grant(&w[0], &w[1], &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&gs[11], &d, &edge(Role::Write)).unwrap();
    lp.sync(0, 1).unwrap();
    assert!(newest_read(&lp, 1, gs[0]).is_some(), "d reads G0 through 11 actors");
    let before: Vec<_> = gs.iter().map(|g| newest_read(&lp, 0, *g)).collect();
    lp.peers[0].engine.demote(&gs[11], &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let deps = lp.peers[0].engine.departures(&gs[0]).unwrap();
    assert!(deps.iter().any(|x| x.holder == d && x.via == gs[1..].to_vec()), "{deps:?}");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 11, "G10 up to G0");
    for (i, g) in gs.iter().enumerate() {
        assert_ne!(newest_read(&lp, 0, *g), before[i], "G{i} rotated");
    }
    assert!(lp.peers[0].engine.ensure_rotated(&gs[0]).unwrap().0.commits.is_empty(), "covered");
    lp.sync(0, 1).unwrap();
    let top = newest_read(&lp, 0, gs[0]).unwrap();
    assert!(lp.peers[1].engine.epochs(&gs[0]).unwrap().read.secret(&top).is_none(), "d does not hold G0's new secret");
}

// spec/crypto.md §4, spec/permissions.md §3: a diamond (A over X and Y, both over Z) and a
// cycle (A over P, P and Q holders of each other): a removal from Z, and from Q, rotates
// each intermediate once, and a second cascade finds nothing to do.
#[test]
fn diamond_and_cycle_rotate_once_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 942, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let [a, x, y, z] = [0; 4].map(|_| group(&mut lp, 0));
    for (t, m) in [(a, x), (a, y), (x, z), (y, z)] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&z, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let (done, still) = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 3, "X, Y, then A");
    assert!(lp.peers[0].engine.ensure_rotated(&a).unwrap().0.commits.is_empty());
    let [b, p, q] = [0; 3].map(|_| group(&mut lp, 0));
    for (t, m) in [(b, p), (p, q), (q, p)] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
    }
    lp.peers[0].engine.grant(&q, &d, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&q, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let (done, still) = lp.peers[0].engine.ensure_rotated(&b).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "P, then B (the removal rotated Q, leaving P out)");
    assert_eq!(lp.peers[0].engine.reseal_due(&q, &Pass).unwrap().commits.len(), 1, "P re-sealed on Q");
    assert!(lp.peers[0].engine.ensure_rotated(&b).unwrap().0.commits.is_empty(), "no churn around the cycle");
    assert!(lp.peers[0].engine.reseal_due(&q, &Pass).unwrap().commits.is_empty());
}

/// Every (actor, role, epoch) of `actors` a party holding `known` opens from the `secrets.0`
/// peer `i` holds of them: a box to `party` itself, or to a holder at a keyset (sealed) or
/// secret (symmetric) epoch known, transitively. What a departed party that kept its secrets
/// can read, whatever its own node does.
fn openable(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, mut known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
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
fn held_by(lp: &LocalPeer, i: usize, actors: &[Tid]) -> BTreeSet<(Tid, Role, osis_crypto::Epoch)> {
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
fn leaked(lp: &mut LocalPeer, i: usize, actors: &[Tid], party: Tid, known: BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> Vec<Tid> {
    let o = openable(lp, i, actors, party, known);
    actors.iter().filter(|t| newest_read(lp, i, **t).is_some_and(|e| o.contains(&(**t, Role::Read, e)))).copied().collect()
}

/// A complete pass of every actor's labels (re-seal decisions in tests).
struct Pass;
impl crate::flows::SyncState for Pass {
    fn complete_pass(&self, _: &Tid) -> bool {
        true
    }
}

/// Rounds of every peer of `admins` acting alone on every actor of `actors` (the cascade,
/// then the re-seal trigger), synced after each, until nothing changes; the rounds taken.
fn settle(lp: &mut LocalPeer, admins: &[usize], actors: &[Tid]) -> usize {
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

/// Whether every current holder of each of `actors`, at peer `i`, holds a box at each
/// current epoch of its roles (left-out holders re-sealed).
fn all_boxed(lp: &mut LocalPeer, i: usize, actors: &[Tid]) -> bool {
    actors.iter().all(|t| {
        let e = lp.peers[i].engine.epochs(t).unwrap();
        let s = lp.peers[i].engine.get_typed(t, &ct::SECRETS).unwrap().unwrap();
        let core = &lp.peers[i].engine.core;
        let ms: Vec<osis_keys::Holder> = core.current_holders(t).into_iter().map(|(holder, role, until)| osis_keys::Holder { holder, role, until }).collect();
        osis_keys::reseal_needed(&s, &e, &ms, core.now()).is_empty()
    })
}

// spec/crypto.md §4, spec/permissions.md §3 (left out): X and Y readers of each
// other, D a reader of X (2-cycle), or X <- Y <- Z <- X (3-cycle). D's removal from X
// rotates X, leaving out its holder actor whose epoch D opens; D, keeping its old secrets,
// opens no epoch judged covered after the removal, and no new epoch after the cascade and
// re-seals, after which every holder is boxed again and a remaining holder of X reads the
// whole cycle.
#[test]
fn removal_in_cycle_leaves_out_spec_crypto_4() {
    for len in [2, 3] {
        let mut lp = LocalPeer::new(3, 950 + len as u64, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (d, n) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let cyc: Vec<Tid> = (0..len).map(|_| group(&mut lp, 0)).collect();
        for i in 0..len {
            lp.peers[0].engine.grant(&cyc[i], &cyc[(i + 1) % len], &edge(Role::Read)).unwrap();
        }
        lp.peers[0].engine.grant(&cyc[0], &d, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&cyc[0], &n, &edge(Role::Read)).unwrap();
        lp.sync(0, 1).unwrap();
        let start = held_by(&lp, 1, &cyc);
        assert!(cyc.iter().all(|t| start.contains(&(*t, Role::Read, newest_read(&lp, 0, *t).unwrap()))), "len {len}: D reads the whole cycle");
        lp.peers[0].engine.demote(&cyc[0], &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
        let gs: Vec<(Tid, usize)> = cyc.iter().map(|t| (*t, 0)).collect();
        assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "len {len}: after the removal");
        assert!(!all_boxed(&mut lp, 0, &cyc), "len {len}: the holder actor is left out");
        settle(&mut lp, &[0], &cyc);
        for t in &cyc {
            assert!(uncovered_at(&mut lp, 0, *t).is_empty(), "len {len}");
        }
        assert!(all_boxed(&mut lp, 0, &cyc), "len {len}: re-sealed");
        assert_eq!(leaked(&mut lp, 0, &cyc, d, start), Vec::<Tid>::new(), "len {len}: after the cascade");
        lp.sync(0, 2).unwrap();
        for t in &cyc {
            assert_eq!(newest_read(&lp, 2, *t), newest_read(&lp, 0, *t), "len {len}: N reads the cycle");
        }
    }
}

// spec/crypto.md §4, spec/permissions.md §3: X and Y readers of each other, Z a reader of
// X, D a reader of Z. D's removal from Z leaves X uncovered also through Y (X <- Y <- X <-
// Z); the cascade rotates Y (leaving X out), then X, a re-seal boxes X on Y again, and D
// opens no new epoch.
#[test]
fn departure_below_cycle_leaves_out_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 953, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let [x, y, z] = [0; 3].map(|_| group(&mut lp, 0));
    for (t, m) in [(x, y), (y, x), (x, z)] {
        lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
    }
    lp.peers[0].engine.grant(&z, &d, &edge(Role::Read)).unwrap();
    lp.sync(0, 1).unwrap();
    let all = [x, y, z];
    let start = held_by(&lp, 1, &all);
    lp.peers[0].engine.demote(&z, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let deps = lp.peers[0].engine.departures(&x).unwrap();
    assert!(deps.iter().any(|q| q.holder == d && q.via == vec![y, x, z]), "{deps:?}");
    let (done, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 2, "Y (leaving X out), then X");
    assert_eq!(leaked(&mut lp, 0, &all, d, start.clone()), Vec::<Tid>::new());
    assert!(lp.peers[0].engine.ensure_rotated(&y).unwrap().0.commits.is_empty(), "Y covered too");
    assert_eq!(lp.peers[0].engine.reseal_due(&y, &Pass).unwrap().commits.len(), 1, "X re-sealed on Y");
    assert!(all_boxed(&mut lp, 0, &all));
    assert_eq!(leaked(&mut lp, 0, &all, d, start), Vec::<Tid>::new());
    assert_eq!(settle(&mut lp, &[0], &all), 0, "settled");
}

// spec/permissions.md §3 (Role cycles; each admin acts alone): X (peer 0's) and Y
// (peer 2's) readers of each other, no common admin (two people's shared tags), D a reader
// of X. Peer 0 removes D: X rotates leaving Y out (Y's epoch boxes X's old one, which D
// holds), so peer 0 may encrypt under X at once. Peer 2's cascade rotates Y, boxing X's new
// epoch; peer 0's re-seal trigger then boxes X to Y's new one. D opens neither.
#[test]
fn cycle_with_disjoint_admins_converges_spec_permissions_3() {
    let mut lp = LocalPeer::new(3, 955, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let x = group(&mut lp, 0);
    let y = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&x, &y, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&x, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&y, &x, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let start = held_by(&lp, 1, &[x, y]);
    assert!(start.contains(&(y, Role::Read, newest_read(&lp, 1, y).unwrap())), "D reads Y through X");
    lp.peers[0].engine.demote(&x, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let (_, still) = lp.peers[0].engine.ensure_rotated(&x).unwrap();
    assert!(still.is_empty(), "peer 0 not stranded on X: {still:?}");
    assert!(lp.peers[0].engine.reseal_due(&x, &Pass).unwrap().commits.is_empty(), "Y not re-sealed before it rotates");
    lp.sync(0, 2).unwrap();
    let (done, still) = lp.peers[2].engine.ensure_rotated(&y).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 1, "Y");
    lp.sync(2, 0).unwrap();
    assert_eq!(lp.peers[0].engine.reseal_due(&x, &Pass).unwrap().commits.len(), 1, "Y re-sealed on X");
    lp.sync_all().unwrap();
    for i in [0, 2] {
        assert!(all_boxed(&mut lp, i, &[x, y]));
        assert_eq!(leaked(&mut lp, i, &[x, y], d, start.clone()), Vec::<Tid>::new());
    }
    assert_eq!(settle(&mut lp, &[0, 2], &[x, y]), 0, "settled");
}

// spec/permissions.md §3 (left out), §2 (invite grants): D leaves M by itself (no rotation
// of M yet). A grant of M on T by a node that may not rotate M (a reader of M; T's admin,
// or an invite holder on T whose grant then carries no box and stays valid) would box T's
// epoch to M's newest, which D holds, so it leaves M out; M is re-sealed on T once M's admin
// rotates it. A granter that may rotate M rotates it first and boxes M at once
// (spec/crypto.md §4: boxing to M is encrypting under M's epoch).
#[test]
fn grant_to_stale_holder_leaves_out_spec_permissions_3() {
    // granter: 0 T's admin reading M, 2 M's admin owning T, 0 by invite on T owned by 3
    for (g, owner) in [(0, 0), (2, 2), (0, 3)] {
        let mut lp = LocalPeer::new(4, 957, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let d = lp.peers[1].engine.tid();
        let p0 = lp.peers[0].engine.tid();
        let m = group(&mut lp, 2);
        lp.peers[2].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
        lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
        let t = group(&mut lp, owner);
        if owner != g {
            lp.peers[owner].engine.grant(&t, &p0, &ct::Edge { invite: Some(Role::Write), ..edge(Role::Write) }).unwrap();
        }
        lp.sync_all().unwrap();
        let start = held_by(&lp, 1, &[m]);
        lp.peers[1].engine.demote(&m, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
        lp.sync_all().unwrap();
        assert!(uncovered_at(&mut lp, 0, m).contains(&Role::Read), "M stale");
        lp.peers[g].engine.grant(&t, &m, &edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        assert_eq!(lp.peers[owner].engine.roster(&t).get(&m).map(|e| e.role), Some(Role::Write), "a valid grant");
        assert!(!leaked(&mut lp, owner, &[m, t], d, start.clone()).contains(&t), "after the grant");
        assert_eq!(all_boxed(&mut lp, owner, &[t]), g == 2, "M left out unless its admin granted");
        settle(&mut lp, &[2, owner], &[m, t]);
        assert!(all_boxed(&mut lp, owner, &[m, t]), "re-sealed");
        assert_eq!(leaked(&mut lp, owner, &[m, t], d, start), Vec::<Tid>::new());
    }
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
            let holders = super::recipients(tx, &a, &[(me, keep)])?;
            let mut m = Mutation::new();
            let rot = super::rotation_into(tx, &mut m, a, &roles, &held, &holders, &[])?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, a, &rot)
        })
        .unwrap();
}

// spec/crypto.md §4 (written by a departed party, along a chain): D, a writer of M, rotates
// M's read and write without boxing itself, then
// leaves M. M reads A; A's admin reads M (so holds M's `secrets.0`) but may not rotate it.
// M's newest epoch has no box for D but D wrote it, so it does not cover D's departure: A's
// admin waits for M (or leaves it out) instead of boxing A's new epoch to an epoch D holds;
// once M's admin rotates M, everything is boxed again and D opens nothing new.
#[test]
fn holder_epoch_written_by_departed_spec_crypto_4() {
    let mut lp = LocalPeer::new(3, 959, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    let p0 = lp.peers[0].engine.tid();
    lp.peers[2].engine.grant(&m, &d, &edge(Role::Write)).unwrap();
    lp.peers[2].engine.grant(&m, &p0, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    rotate_unboxed(&mut lp, 1, m, &[Role::Read, Role::Write], None);
    lp.sync_all().unwrap();
    let start = held_by(&lp, 1, &[m, a]);
    assert!(start.contains(&(m, Role::Read, newest_read(&lp, 2, m).unwrap())), "D holds M's newest");
    lp.peers[1].engine.demote(&m, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    assert!(lp.peers[0].engine.departures(&a).unwrap().iter().any(|q| q.holder == d && q.via == vec![m]), "A sees D leave M");
    let before = newest_read(&lp, 0, a);
    let _ = lp.peers[0].engine.ensure_rotated(&a).unwrap();
    let _ = lp.peers[0].engine.reseal_due(&a, &Pass).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(leaks_judged_covered(&mut lp, &[(m, 2), (a, 0)], d, &start), vec![], "before M rotates");
    let rotated = newest_read(&lp, 0, a) != before;
    assert!(!rotated || !leaked(&mut lp, 0, &[m, a], d, start.clone()).contains(&a), "A's new epoch not boxed to D's");
    settle(&mut lp, &[0, 2], &[m, a]);
    assert!(all_boxed(&mut lp, 0, &[a]) && all_boxed(&mut lp, 2, &[m]), "re-sealed");
    assert_eq!(leaked(&mut lp, 0, &[m, a], d, start), Vec::<Tid>::new());
}

/// Pairs (actor, role) whose newest epoch at the owner peer `owner(t)` is judged covered there
/// but that `d` opens from its old secrets `start` beyond what boxes to `d` itself give it.
fn leaks_judged_covered(lp: &mut LocalPeer, gs: &[(Tid, usize)], d: Tid, start: &BTreeSet<(Tid, Role, osis_crypto::Epoch)>) -> Vec<(Tid, Role)> {
    let actors: Vec<Tid> = gs.iter().map(|g| g.0).collect();
    let mut out = Vec::new();
    for &(t, i) in gs {
        let legit = openable(lp, i, &actors, d, BTreeSet::new());
        let all = openable(lp, i, &actors, d, start.clone());
        let un = uncovered_at(lp, i, t);
        let Some(e) = lp.peers[i].engine.epochs(&t) else { continue };
        for r in osis_keys::ROLES {
            if let Some((n, _)) = e.role(r).newest_held()
                && !un.contains(&r)
                && all.contains(&(t, r, n))
                && !legit.contains(&(t, r, n))
            {
                out.push((t, r));
            }
        }
    }
    out
}

// spec/crypto.md §4, spec/permissions.md §3 (Role cycles): random role graphs of 2-4
// actors through a forced cycle, owned by one or two peers (sometimes with a common admin),
// a party D on one or two of them; D is removed or demoted on one, or leaves by itself (a
// writer having first rotated it without boxing itself). After the removal, and
// after each admin acting alone (cascade and re-seal trigger) until nothing changes, D's old
// secrets open no newest epoch its owner judges covered beyond what D's remaining boxes give
// it; then nothing stays uncovered and every holder holds a box at the newest epoch.
#[test]
fn cycle_removals_leak_nothing_random() {
    cycle_stats(osis_base::testenv::run_seeds("rotation::tests::cycle_removals_leak_nothing_random", &[0, 1, 2, 3, 4, 5], false, cycle_replay, cycle_removals));
}

/// Seeds: OSIS_CYCLE_START, OSIS_CYCLE_SEEDS (default 1000..1200).
#[test]
#[ignore = "tier 2"]
fn cycle_removals_leak_nothing_random_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_CYCLE_START", "OSIS_CYCLE_SEEDS", 1_000..1_200);
    cycle_stats(s.run("rotation::tests::cycle_removals_leak_nothing_random_large", cycle_replay, cycle_removals));
}

fn cycle_replay(s: u64) -> String {
    format!("OSIS_CYCLE_START={s} OSIS_CYCLE_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::cycle_removals_leak_nothing_random_large -- --ignored --exact")
}

fn cycle_stats(runs: Vec<(usize, bool, bool)>) {
    let rounds = runs.iter().map(|r| r.0).max().unwrap_or(0);
    let lonely = runs.iter().filter(|r| r.1).count();
    let wrote = runs.iter().filter(|r| r.2).count();
    eprintln!("cycle removals: {} runs, {lonely} with disjoint admins, {wrote} written by D, at most {rounds} rounds to settle", runs.len());
}

/// One seed of `cycle_removals_leak_nothing_random*`: rounds to settle, whether its admins were
/// disjoint, whether D wrote; peers: 0 and 2 admins, 1 the party D.
fn cycle_removals(seed: u64) -> (usize, bool, bool) {
    let roles = [Role::Read, Role::Write, Role::Admin];
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(3, 1_300 + seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let [d, c] = [1, 2].map(|i| lp.peers[i].engine.tid());
    let two = rng.next(2) == 0;
    let common = two && rng.next(2) == 0;
    let k = 2 + rng.next(3) as usize;
    let gs: Vec<(Tid, usize)> = (0..k)
        .map(|_| {
            let o = if two && rng.next(2) == 0 { 2 } else { 0 };
            (group(&mut lp, o), o)
        })
        .collect();
    lp.sync_all().unwrap();
    if common {
        // peer 2 an admin of every actor of peer 0's
        for &(t, o) in &gs {
            if o == 0 {
                lp.peers[0].engine.grant(&t, &c, &edge(Role::Admin)).unwrap();
            }
        }
    }
    for i in 0..k {
        for j in 0..k {
            if i != j && (j == (i + 1) % k || rng.next(3) == 0) {
                let (t, o) = gs[i];
                let _ = lp.peers[o].engine.grant(&t, &gs[j].0, &edge(roles[rng.next(3) as usize]));
            }
        }
    }
    let mut held_by_d = Vec::new();
    for _ in 0..1 + rng.next(2) {
        let (t, o) = gs[rng.next(k as u64) as usize];
        let r = roles[rng.next(3) as usize];
        if lp.peers[o].engine.grant(&t, &d, &edge(r)).is_ok() {
            held_by_d.push((t, o, r));
        }
    }
    lp.sync_all().unwrap();
    let all: Vec<Tid> = gs.iter().map(|g| g.0).collect();
    let (t, o, r) = held_by_d[rng.next(held_by_d.len() as u64) as usize];
    let new = match (r, rng.next(2)) {
        (Role::Admin, 0) => Some(edge(Role::Write)),
        (Role::Admin | Role::Write, 1) => Some(edge(Role::Read)),
        _ => None,
    };
    // sometimes D, before leaving by itself, rotates the roles of `t` it leaves without
    // boxing itself at them (spec/crypto.md §4: written by a departed party)
    let by_d = rng.next(2) == 0;
    let keep = new.as_ref().map(|e| e.role);
    let wrote = by_d && r >= Role::Write;
    if wrote {
        let rot: Vec<Role> = roles.into_iter().filter(|x| Some(*x) > keep && *x <= r).collect();
        rotate_unboxed(&mut lp, 1, t, &rot, keep);
        lp.sync_all().unwrap();
    }
    let start = held_by(&lp, 1, &all);
    lp.peers[if by_d { 1 } else { o }].engine.demote(&t, &Demotion { holder: d, new, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "seed {seed}: after the removal");
    let admins: &[usize] = if two { &[0, 2] } else { &[0] };
    let rounds = settle(&mut lp, admins, &all);
    assert_eq!(leaks_judged_covered(&mut lp, &gs, d, &start), vec![], "seed {seed}: after the cascade and re-seals");
    for &(x, i) in &gs {
        assert!(uncovered_at(&mut lp, i, x).is_empty(), "seed {seed}: each admin alone covers every cycle");
    }
    assert!(gs.iter().all(|&(x, i)| all_boxed(&mut lp, i, &[x])), "seed {seed}: every holder re-sealed");
    let lonely = two && !common && gs.iter().any(|g| g.1 == 0) && gs.iter().any(|g| g.1 == 2);
    (rounds, lonely, wrote)
}

// A lattice 4 wide and 10 deep, each actor a holder of all 4 above it (4^9 chains from the
// top to one bottom actor): departures stay one per class, polynomial in the graph.
#[test]
fn wide_lattice_departures_bounded() {
    let mut lp = LocalPeer::new(2, 943, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let d = lp.peers[1].engine.tid();
    let top = group(&mut lp, 0);
    let mut layer = vec![top];
    for _ in 0..9 {
        let next: Vec<Tid> = (0..4).map(|_| group(&mut lp, 0)).collect();
        for t in &layer {
            for m in &next {
                lp.peers[0].engine.grant(t, m, &edge(Role::Write)).unwrap();
            }
        }
        layer = next;
    }
    lp.peers[0].engine.grant(&layer[0], &d, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.demote(&layer[0], &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    let deps = lp.peers[0].engine.departures(&top).unwrap();
    // first and second actor (4 x 4), 8 verdict vectors at most
    assert!(!deps.is_empty() && deps.len() <= 4 * 4 * 8, "{}", deps.len());
    let (done, still) = lp.peers[0].engine.ensure_rotated(&top).unwrap();
    assert!(still.is_empty(), "{still:?}");
    assert_eq!(done.commits.len(), 8 * 4 + 1, "every actor above the bottom one once");
}

// spec/crypto.md §4 (an epoch does not cover a departure when its rotation commit's author
// reaches the actor at that role only through the departed party): Alice's thing N, her
// tag T shared with Bob; T a writer of N, then removed, then granted read again. Alice's
// node reaches T as its owner but N by its own chain, so her removal's rotation covers T's
// departure and the re-grant goes through. Bob, who reaches N's write only through T,
// counts as T (also with a read edge of his own on N), not at read, and again once he
// holds nothing on N.
#[test]
fn regrant_after_tag_removal_spec_crypto_4() {
    let mut lp = LocalPeer::new(2, 944, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let (alice, bob) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
    let tag = group(&mut lp, 0);
    let n = group(&mut lp, 0);
    lp.peers[0].engine.grant(&tag, &bob, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.demote(&n, &Demotion { holder: tag, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[0].engine.grant(&n, &tag, &edge(Role::Read)).unwrap();
    assert!(lp.peers[0].engine.ensure_rotated(&n).unwrap().1.is_empty(), "covered");
    let core = &lp.peers[0].engine.core;
    let by = |who: &Tid, r: Role| super::departures::written_by(core, &n, r, who, who, &tag);
    assert!(!by(&alice, Role::Write) && !by(&alice, Role::Admin), "Alice's node reaches N by its own chain");
    assert!(by(&bob, Role::Write), "Bob reaches N only through T");
    assert!(by(&tag, Role::Read), "T itself");
    lp.peers[0].engine.grant(&n, &bob, &edge(Role::Read)).unwrap();
    let core = &lp.peers[0].engine.core;
    let by = |who: &Tid, r: Role| super::departures::written_by(core, &n, r, who, who, &tag);
    assert!(by(&bob, Role::Write), "Bob's own read edge gives no write");
    assert!(!by(&bob, Role::Read), "Bob reads N on his own");
    // judged now: once Bob has left both T and N, an epoch he wrote while reading N on his
    // own no longer covers T's departure (he still knows its secret)
    lp.peers[0].engine.demote(&n, &Demotion { holder: bob, new: None, presync: PreSync::Synced }).unwrap();
    lp.peers[0].engine.demote(&tag, &Demotion { holder: bob, new: None, presync: PreSync::Synced }).unwrap();
    let core = &lp.peers[0].engine.core;
    assert!(super::departures::written_by(core, &n, Role::Read, &bob, &bob, &tag), "Bob holds nothing on N now");
}

// spec/permissions.md §3 (left out), spec/crypto.md §4 (one box per role and epoch): P writes A
// only through holder actor M (owned by peer 2). D leaves M by itself, so M's epoch is stale;
// A's owner then removes D (also a reader of A) and its read rotation leaves M out, so P holds
// A's write but no current read. E, a writer of A, leaves by itself. P rotates A's write, which
// needs no other role's secret; its heartbeat reports it stranded on read until M rotates and
// A's owner, rotating A, boxes M again.
#[test]
fn rotator_lacking_read_rotates_write_spec_permissions_3() {
    let mut lp = LocalPeer::new(5, 961, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let [p, d, e] = [1, 3, 4].map(|i| lp.peers[i].engine.tid());
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&m, &p, &edge(Role::Write)).unwrap();
    lp.peers[2].engine.grant(&m, &d, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &d, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&a, &e, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    assert!(newest_read(&lp, 1, a).is_some(), "P reads A through M");
    lp.peers[3].engine.demote(&m, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&a, &Demotion { holder: d, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    assert!(newest_read(&lp, 1, a).is_none(), "M left out of A's read");
    assert!(lp.peers[1].engine.epochs(&a).unwrap().write.newest_held().is_some(), "P still holds A's write");
    lp.peers[4].engine.demote(&a, &Demotion { holder: e, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    let write = |lp: &LocalPeer| lp.peers[1].engine.epochs(&a).unwrap().write.newest_held().map(|x| x.0);
    let before = write(&lp);
    // P may rotate M's read (D left it) first: that is fine
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert_ne!(write(&lp), before, "A's write rotated");
    assert!(still.is_empty(), "{still:?}");
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(matches!(osis_keys::wrap_epoch(&e.read), osis_keys::WrapEpoch::Stranded(_)), "P's heartbeat reports it stranded on A");
    settle(&mut lp, &[1, 2, 0], &[m, a]);
    assert!(newest_read(&lp, 1, a).is_some(), "P re-sealed on A through M");
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "{still:?}");
}

/// The write-lacking shape of `rotator_lacking_read_rotates_write_spec_permissions_3`:
/// P is A's admin only through holder actor M (owned by peer 2); D, a writer of M, demotes
/// itself to reader (no rotation), and A's owner demotes writer E to reader, so A's write
/// rotation leaves M out of write only. P holds A's read and admin but no current write; F is
/// an admin of A. Returns the peers and A, M.
fn lacking_write(seed: u64) -> (LocalPeer, Tid, Tid) {
    let mut lp = LocalPeer::new(6, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let [p, d, e, f] = [1, 3, 4, 5].map(|i| lp.peers[i].engine.tid());
    let a = group(&mut lp, 0);
    let m = group(&mut lp, 2);
    lp.sync_all().unwrap();
    lp.peers[2].engine.grant(&m, &p, &edge(Role::Admin)).unwrap();
    lp.peers[2].engine.grant(&m, &d, &edge(Role::Write)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&a, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&a, &e, &edge(Role::Write)).unwrap();
    lp.peers[0].engine.grant(&a, &f, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    lp.peers[3].engine.demote(&m, &Demotion { holder: d, new: Some(edge(Role::Read)), presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    lp.peers[0].engine.demote(&a, &Demotion { holder: e, new: Some(edge(Role::Read)), presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    let ep = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(ep.write.newest_held().is_none(), "M left out of A's write");
    assert!(ep.read.newest_held().is_some() && ep.admin.newest_held().is_some(), "P holds A's read and admin");
    (lp, a, m)
}

// spec/permissions.md §3 (left out, re-seal trigger, forks): F, an admin of A, leaves by
// itself. P, lacking A's current write, rotates A's read and admin and leaves write to a node
// holding it. Its read is current, so no heartbeat reports it stranded: the re-seal trigger of A's
// owner (M lacks a box at A's current write) re-seals M once M rotates. P's own cascade rotates
// M's write unsynced, so M's owner's rotation of it forks: A's owner, holding no secret of M,
// names one fork (its `keys.0` keyset) and M's owner the other (its newest), each judging the
// other's box to M uncovered, so A's write was rotated back and forth for good (at about a
// third of seeds) until the fork was rotated away first.
#[test]
fn rotator_lacking_write_resealed_spec_permissions_3() {
    // a seed that forks so (which seeds do moves with unrelated byte changes: recheck with
    // `fork_named` off; each run costs seconds, six peers, so one seed here, the range in `_large`)
    lacking_write_resealed(960);
}

/// Seeds: OSIS_LACKING_START, OSIS_LACKING_SEEDS (default 955..975).
#[test]
#[ignore = "tier 2"]
fn rotator_lacking_write_resealed_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_LACKING_START", "OSIS_LACKING_SEEDS", 955..975);
    let replay = |s: u64| format!("OSIS_LACKING_START={s} OSIS_LACKING_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::rotator_lacking_write_resealed_large -- --ignored --exact");
    s.run("rotation::tests::rotator_lacking_write_resealed_large", replay, lacking_write_resealed);
}

fn lacking_write_resealed(seed: u64) {
    let (mut lp, a, m) = lacking_write(seed);
    let f = lp.peers[5].engine.tid();
    lp.peers[5].engine.demote(&a, &Demotion { holder: f, new: None, presync: PreSync::Synced }).unwrap();
    lp.sync_all().unwrap();
    let admin = |lp: &LocalPeer| lp.peers[1].engine.epochs(&a).unwrap().admin.newest_held().map(|x| x.0);
    let before = admin(&lp);
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "seed {seed}: {still:?}");
    assert_ne!(admin(&lp), before, "seed {seed}: A's admin rotated");
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(e.write.newest_held().is_none(), "seed {seed}: still lacking A's write");
    assert!(matches!(osis_keys::wrap_epoch(&e.read), osis_keys::WrapEpoch::Current(_)), "seed {seed}: P's read is current: no heartbeat");
    settle(&mut lp, &[2, 0], &[m, a]);
    let e = lp.peers[1].engine.epochs(&a).unwrap();
    assert!(e.write.newest_held().is_some() && e.admin.newest_held().is_some(), "seed {seed}: P re-sealed on A's write through M");
    let (_, still) = lp.peers[1].engine.ensure_rotated(&a).unwrap();
    assert!(still.is_empty(), "seed {seed}: {still:?}");
}

// A removal P makes itself in that shape: it must rotate A's write, whose current secret P
// lacks, so it is refused with an error saying it waits for a re-seal, and changes nothing.
#[test]
fn removal_lacking_rotated_secret_refused_spec_permissions_3() {
    let (mut lp, a, _) = lacking_write(963);
    let f = lp.peers[5].engine.tid();
    let before = lp.peers[1].engine.core.current_holders(&a).len();
    let err = lp.peers[1].engine.demote(&a, &Demotion { holder: f, new: None, presync: PreSync::Synced }).unwrap_err();
    assert!(format!("{err}").contains("re-seal"), "{err}");
    assert_eq!(lp.peers[1].engine.core.current_holders(&a).len(), before);
}

// spec/permissions.md §3 (re-seal fixpoint), spec/crypto.md §4 (forks) (churn seeds 140170
// and 140188 shrunk: a node re-sealed itself on every pass): A and D rotate G's write
// concurrently, D's rotation leaving writer B out, so B lacks a box and the secret at D's fork.
// B, holding only A's fork, writes no re-seal of itself (before: one boxing A's fork alone on
// every pass); A, holding both, re-seals B once, a box at each fork.
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
            let holders = super::recipients(tx, &g, &[(b, Some(Role::Read))])?;
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
        assert!(all_boxed(&mut lp, p, &[g]), "peer {p}: every holder boxed at both forks");
    }
    let e = lp.peers[1].engine.epochs(&g).unwrap();
    assert!(e.write.current().iter().all(|x| e.write.secret(x).is_some()), "B holds both forks' secrets");
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
                let holders = super::recipients(tx, &g, &[(other, Some(Role::Read))])?;
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
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORKS_START", "OSIS_FORKS_SEEDS", 0..100);
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
                let holders = super::recipients(tx, &g, &skip)?;
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

// spec/crypto.md §4 (settled rotation commits): rotation commits turned invalid, their rotator
// demoted concurrently. Seeds 23, 25: a demoted admin's own rotation falls at it too (at 25 it
// stayed current there, an epoch no other node established). Seeds 51, 243, 336: a valid
// rotation superseding one stayed unestablished but at its author, and so every one after it (at
// 51 the older epoch stayed current with its boxes gone, an admin signing under it while a demoted
// writer held it); 336 settles only by passing through the invalid one.
#[test]
fn invalid_own_rotation_falls_spec_crypto_4() {
    forks_with_departures(23, false);
}

#[test]
fn invalid_own_rotation_falls_25_spec_crypto_4() {
    forks_with_departures(25, false);
}

#[test]
fn chain_passes_invalid_rotation_51_spec_crypto_4() {
    forks_with_departures(51, false);
}

#[test]
fn chain_passes_invalid_rotation_243_spec_crypto_4() {
    forks_with_departures(243, false);
}

#[test]
fn chain_passes_invalid_rotation_336_spec_crypto_4() {
    forks_with_departures(336, false);
}

// spec/crypto.md §4 (settled: passing through re-written boxes): peer 1's rotation G of read
// (epoch s, boxing peers 2 and 4 only) falls invalid, peer 0 demoting 1 to read concurrently;
// peer 4's rotation of read is a valid fork beside it. Unaware of the demotion, 2 and 4 re-grant
// each other (re-writing every box G made at s), then 2 removes reader 3: its rotation C removes
// the boxes at s and at 4's fork, its removal at s naming only the grants. Before: C never
// settled, so 4's fork stayed current with its boxes gone, covering 3 by the box rule, and was
// encrypted under while 3 held it.
#[test]
fn chain_passes_invalid_rotation_through_regrants_spec_crypto_4() {
    let mut lp = LocalPeer::new(5, 3_917, WallMs(1_700_000_000_000)).unwrap();
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: Some(edge(Role::Read)), presync: PreSync::Synced }).unwrap();
    let read = BTreeSet::from([Role::Read]);
    rotate_leaving_out(&mut lp, 4, g, &read, &[]);
    rotate_leaving_out(&mut lp, 1, g, &read, &[0, 1, 3]);
    others(&mut lp);
    lp.peers[2].engine.grant(&g, &tids[4], &edge(Role::Admin)).unwrap();
    lp.peers[4].engine.grant(&g, &tids[2], &edge(Role::Admin)).unwrap();
    others(&mut lp);
    let before = lp.peers[2].engine.epochs(&g).unwrap().read.current();
    assert_eq!(before.len(), 2, "G's epoch and 4's fork current at 2: {before:?}");
    lp.peers[2].engine.demote(&g, &Demotion { holder: tids[3], new: None, presync: PreSync::Synced }).unwrap();
    departures_settle(&mut lp, g, 0, &mut Rng(1), was);
}

// spec/crypto.md §4 (only the commits a rotation's keyset lists pass an epoch through): owner A
// (peer 0) removes reader M (2), rotating read to s (R_s). Admin G (1) signs F, a forged
// rotation commit of s (s's keyset, history box and X's box written again; it lists nothing, so
// it is settled), then re-grants admin X (3), whose box record it replaces at s (C). A, holding C
// but not F, removes G, rotating to e (listing R_s; its removals at s name R_s and C, C's names
// F); so F is invalid (G demoted concurrently). X holds every commit but R_s: e must not be
// established there (else X, still seeing M as a reader, re-seals e to it). Once R_s arrives, e
// is.
#[test]
fn forged_claim_withheld_rotation_spec_crypto_4() {
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[2], new: None, presync: PreSync::Synced }).unwrap();
    let r_s: BTreeSet<_> = ids(&mut lp, 0).difference(&before).copied().collect();
    let s = newest_read(&lp, 0, g).unwrap();
    lp.sync(0, 1).unwrap();
    let before = ids(&mut lp, 1);
    lp.peers[1]
        .engine
        .run(|tx| {
            let held = tx.core.epochs(&g).unwrap();
            let ks = osis_keys::keyset(&s, held.read.secret(&s).unwrap(), &Default::default());
            let state = crate::flows::secrets_in(tx, &g)?;
            let at = ct::Epoch { n: s.n(), nonce: *s.nonce() };
            let key = ct::HistoryKey { role: Role::Read, epoch: at.clone() };
            let bk = ct::BoxKey { holder: tids[3], role: Role::Read, epoch: at };
            let w = osis_keys::SecretsWrite { history: [(key.clone(), state.history[&key].clone())].into(), boxes: [(bk.clone(), state.boxes[&bk].clone())].into(), ..Default::default() };
            let mut m = Mutation::new();
            crate::flows::put_keysets(&mut m, g, &osis_keys::KeysWrite { keysets: [(Role::Read, ks)].into() })?;
            crate::flows::put_secrets(&mut m, g, &w, false)?;
            crate::engine::Engine::commit_tx(tx, m).map(|_| ())
        })
        .unwrap();
    let f = *ids(&mut lp, 1).difference(&before).next().unwrap();
    let before = ids(&mut lp, 1);
    lp.peers[1].engine.grant(&g, &tids[3], &edge(Role::Admin)).unwrap();
    for pk in lp.packages(1).unwrap().into_iter().filter(|p| !before.contains(&p.id)) {
        lp.peers[0].engine.ingest(&pk.bytes, pk.blobs).unwrap();
    }
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new: None, presync: PreSync::Synced }).unwrap();
    let e = newest_read(&lp, 0, g).unwrap();
    assert!(e.n() > s.n());
    let mut all = lp.packages(0).unwrap();
    all.extend(lp.packages(1).unwrap());
    for pk in all.iter().filter(|p| !r_s.contains(&p.id)) {
        let _ = lp.peers[3].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    let at_x = lp.peers[3].engine.epochs(&g).unwrap();
    let claims = |x: &osis_keys::ActorEpochs, ep: &osis_crypto::Epoch| x.read.get(ep).map(|i| i.claims.iter().map(|(c, cl)| (*c, cl.valid)).collect::<Vec<_>>()).unwrap_or_default();
    assert_eq!(claims(&at_x, &s), vec![(f, false)], "F held, invalid; R_s withheld");
    assert!(claims(&at_x, &e).iter().any(|c| c.1), "e's rotation commit applied, valid");
    assert!(!at_x.read.is_established(&e), "e established through a forged claim of s");
    for pk in all.iter().filter(|p| r_s.contains(&p.id)) {
        let _ = lp.peers[3].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    assert!(lp.peers[3].engine.epochs(&g).unwrap().read.is_current(&e));
}

/// Seeds: OSIS_DEPART_START, OSIS_DEPART_SEEDS (default 0..100, as `forks_with_departures_settle_large`).
#[test]
#[ignore = "tier 2"]
fn regrants_pass_through_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_DEPART_START", "OSIS_DEPART_SEEDS", 0..100);
    let replay = |s: u64| format!("OSIS_DEPART_START={s} OSIS_DEPART_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::regrants_pass_through_large -- --ignored --exact");
    s.run("rotation::tests::regrants_pass_through_large", replay, regrants_pass_through);
}

/// Random variations of `chain_passes_invalid_rotation_through_regrants_spec_crypto_4`: an
/// admin demoted by the owner rotates read unaware (invalid) beside a valid fork; the other
/// admins, cut off from the owner, re-grant each other (re-writing the invalid rotation's boxes),
/// then one removes the reader. Naming the chain by removal dots instead of the keyset list,
/// about 1 seed in 10 leaks.
fn regrants_pass_through(seed: u64) {
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
    lp.peers[0].engine.demote(&g, &Demotion { holder: tids[1], new, presync: PreSync::Synced }).unwrap();
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
    let _ = lp.peers[a].engine.demote(&g, &Demotion { holder: tids[v], new: None, presync: PreSync::Synced });
    departures_settle(&mut lp, g, seed, &mut rng, was);
}

/// Seeds: OSIS_DEPART_START, OSIS_DEPART_SEEDS (default 0..100).
#[test]
#[ignore = "tier 2"]
fn forks_with_departures_settle_large() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_DEPART_START", "OSIS_DEPART_SEEDS", 0..100);
    let replay = |s: u64| format!("OSIS_DEPART_START={s} OSIS_DEPART_SEEDS=1 cargo test -p osis-engine --lib rotation::tests::forks_with_departures_settle_large -- --ignored --exact");
    s.run("rotation::tests::forks_with_departures_settle_large", replay, |seed| forks_with_departures(seed, true));
}

/// Rotates `rot` of `g` at peer `i`, leaving out the peers `skip` (all of them, the rotator
/// included: an epoch with no box); refused (a rotated role's secret not held), nothing.
fn rotate_leaving_out(lp: &mut LocalPeer, i: usize, g: Tid, rot: &BTreeSet<Role>, skip: &[usize]) {
    let skip: Vec<(Tid, Option<Role>)> = skip.iter().map(|j| (lp.peers[*j].engine.tid(), None)).collect();
    let _ = lp.peers[i].engine.run(|tx| {
        let held = tx.core.epochs(&g).unwrap();
        let holders = super::recipients(tx, &g, &skip)?;
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
                if lp.peers[i].engine.demote(&g, &Demotion { holder: tids[j], new: new.map(edge), presync: PreSync::Synced }).is_ok() {
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
