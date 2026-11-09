//! The rotation property (spec/crypto.md §4, spec/permissions.md §2-§3), on one generator: no
//! departed holder reads later content, and every holder ends reading everything. A history
//! mixes forks (rotations on stale states, leaving holders out), departures (removals,
//! demotions, `until`s finalized, self-removals forging what a writer can), vandals (a rotation
//! boxing nobody), re-grants, invalid rotations (a rotator demoted unaware), compactions, holder
//! actors in cycles, a rotator lacking a role's secret, and an admin acting while some departures
//! are withheld from it. Forgers and vandals are hostile: their nodes act no more, and an honest
//! admin removes them (and the actors they are first admin of) before settling, the recovery
//! from their lockouts. Every node settles under the walk's side of each admin dispute. The
//! seed picks an emphasis (seed mod 4: forks, departures, forgeries, cycles); every feature stays
//! on its own draws.

#![allow(clippy::unwrap_used)]
use super::tests::{Pass, Rng, edge, group, openable};
use super::tests_departs::{Forge, leave};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{CommitId, Role, Tid, WallMs};
use osis_crypto::Epoch;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

const N: usize = 5;
const ROLES: [Role; 3] = osis_keys::ROLES;

/// What a seed reached, for the run's coverage tally.
#[derive(Clone, Copy, Default, Debug)]
struct Reached {
    forked: bool,
    departed: bool,
    forged: bool,
    cycle: bool,
    withheld: bool,
    invalid: bool,
}

/// (actor, role, epoch): a secret.
type Key = (Tid, Role, Epoch);

/// A rotator's view when it made an epoch: the commits it held (the rotation commit included),
/// and the peers below the epoch's role in its view, for keys.
type Made = BTreeMap<Key, (BTreeSet<CommitId>, BTreeSet<usize>)>;

struct Run {
    lp: LocalPeer,
    tids: Vec<Tid>,
    /// Each actor with the peer that made it (its first admin, never lowered).
    actors: Vec<(Tid, usize)>,
    /// Every secret each peer held or made at any point: what a departed peer keeps.
    ever: Vec<BTreeSet<Key>>,
    made: Made,
    rng: Rng,
    /// Peers that forged: their nodes no longer act, and nothing is checked of them.
    hostile: BTreeSet<usize>,
    /// The history's steps, for a failure's message.
    log: Vec<String>,
    /// When each peer first held each secret (an index into `log`).
    first: BTreeMap<(usize, Key), usize>,
}

impl Drop for Run {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("the failing history: {:#?}", self.log);
        }
    }
}

impl Run {
    fn all(&self) -> Vec<Tid> {
        self.actors.iter().map(|a| a.0).collect()
    }

    fn held(&self, p: usize) -> BTreeSet<Key> {
        let mut out = BTreeSet::new();
        for t in self.all() {
            if let Some(e) = self.lp.peers[p].engine.epochs(&t) {
                for r in ROLES {
                    out.extend(e.role(r).epochs().filter(|(_, x)| x.secret.is_some()).map(|(x, _)| (t, r, *x)));
                }
            }
        }
        out
    }

    fn note(&mut self) {
        for p in 0..N {
            let h = self.held(p);
            for k in &h {
                self.first.entry((p, *k)).or_insert(self.log.len());
            }
            self.ever[p].extend(h);
        }
    }

    fn key_role(&self, at: usize, t: &Tid, d: usize) -> Option<Role> {
        self.lp.peers[at].engine.core.key_holders(t).into_iter().find(|h| h.0 == self.tids[d]).map(|h| h.1)
    }

    /// Every epoch of any actor known anywhere, and the commits peer `i` holds.
    fn before(&mut self, i: usize) -> (BTreeSet<Key>, BTreeSet<CommitId>) {
        let mut known = BTreeSet::new();
        for p in 0..N {
            for t in self.all() {
                if let Some(e) = self.lp.peers[p].engine.epochs(&t) {
                    for r in ROLES {
                        known.extend(e.role(r).epochs().map(|(x, _)| (t, r, *x)));
                    }
                }
            }
        }
        (known, super::tests::commit_ids(&mut self.lp, i))
    }

    /// Records the epochs peer `i` made since `before`.
    fn record(&mut self, i: usize, (known, held): &(BTreeSet<Key>, BTreeSet<CommitId>)) {
        for t in self.all() {
            let Some(e) = self.lp.peers[i].engine.epochs(&t) else { continue };
            // with a holder actor on `t`, a departure may run through it: recorded for the
            // check of direct departures only where every holder is a peer
            if self.lp.peers[i].engine.core.key_holders(&t).iter().any(|h| !self.tids.contains(&h.0)) {
                continue;
            }
            for r in ROLES {
                let below: BTreeSet<usize> = (0..N).filter(|d| !access(self, i, *d, t, r)).collect();
                for (x, info) in e.role(r).epochs() {
                    if info.checked().is_some() && !known.contains(&(t, r, *x)) {
                        let own = self.lp.peers[i].engine.core.ix.epoch_intro.get(&(t, r, *x)).map(|v| v.1);
                        // nor where its rotation boxed a holder actor (one the step then removed:
                        // the step's cascade rotates before the removal's own rotation)
                        if own.is_some_and(|c| self.boxed_actor(i, &c)) {
                            continue;
                        }
                        self.log.push(format!("  made actor {} {r:?} n{} {:?} at peer {i}, below {below:?}", self.actors.iter().position(|a| a.0 == t).unwrap(), x.n(), &x.nonce()[..2]));
                        self.made.insert((t, r, *x), (held.iter().copied().chain(own).collect(), below.clone()));
                    }
                }
            }
        }
    }

    /// Whether commit `c` at peer `i` writes a box to a holder that is no peer (an actor).
    fn boxed_actor(&self, i: usize, c: &CommitId) -> bool {
        let core = &self.lp.peers[i].engine.core;
        let Some(m) = core.ix.commits.get(c) else { return false };
        (0..m.view.aspects.len()).filter_map(|ai| core.ix.shown.get(&(*c, ai))).any(|x| x.shown.iter().any(|s| !self.tids.contains(&s.holder)))
    }

    /// Peer `i` rotates `rot` of `t`, leaving out each other member (peer or actor) at random, or
    /// everyone (`nobody`: an epoch with no box, a vandal's); refused, nothing. Whether it was made.
    fn rotate(&mut self, i: usize, t: Tid, rot: &BTreeSet<Role>, nobody: bool) -> bool {
        let mut skip: Vec<(Tid, Option<Role>)> = Vec::new();
        let members: Vec<Tid> = self.tids.iter().copied().chain(self.all()).filter(|m| *m != t).collect();
        for m in members {
            if nobody || (m != self.tids[i] && self.rng.next(4) == 0) {
                skip.push((m, None));
            }
        }
        // refused (a rotated role's secret not held, Seal waiting) changes nothing
        self.lp.peers[i].engine.run(|tx| {
            let held = tx.core.epochs(&t).unwrap_or_default();
            let holders = super::recipients(tx, &tx.core.id.tid(), &t, &skip)?.ok_or(super::SEAL_WAITS)?;
            let mut m = Mutation::new();
            let r = super::rotation_into(tx, &mut m, t, rot, &held, &holders, false)?;
            crate::engine::Engine::commit_tx(tx, m)?;
            super::record(tx, t, &r)
        })
        .is_ok()
    }

    fn sync_some(&mut self, all: bool) {
        if all {
            self.lp.sync_all().unwrap();
        } else {
            for _ in 0..4 {
                let (a, b) = (self.rng.next(N as u64) as usize, self.rng.next(N as u64) as usize);
                if a != b {
                    self.lp.sync(a, b).unwrap();
                }
            }
        }
        self.note();
    }
}

/// One seed: generates a history, settles it, and checks the property. Panics with what failed.
fn rotation_history(seed: u64) -> Reached {
    let mut reached = Reached::default();
    let emphasis = seed % 4;
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut lp = LocalPeer::new(N, seed, WallMs(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    // actors: G (peer 0's); with holder actors, one or two more, some of peer 2's, granted
    // roles on each other around a cycle
    let mut actors = vec![(group(&mut lp, 0), 0)];
    let cycle = emphasis == 3 || rng.next(6) == 0;
    if cycle {
        let two = rng.next(2) == 0;
        for _ in 0..1 + rng.next(2) {
            let o = if two && rng.next(2) == 0 { 2 } else { 0 };
            actors.push((group(&mut lp, o), o));
        }
    }
    lp.sync_all().unwrap();
    let k = actors.len();
    // holders granted before others' grants are held (half the seeds), or each synced at once
    let hidden = rng.next(2) == 0;
    if cycle {
        for i in 0..k {
            for j in (0..k).filter(|j| *j != i) {
                if j == (i + 1) % k || rng.next(3) == 0 {
                    let (t, o) = actors[i];
                    let _ = lp.peers[o].engine.grant(&t, &actors[j].0, &edge(ROLES[rng.next(3) as usize]));
                    if !hidden {
                        lp.sync_all().unwrap();
                    }
                }
            }
        }
    }
    for &(t, o) in &actors {
        for p in (1..N).filter(|p| *p != o) {
            if t == actors[0].0 || rng.next(3) == 0 {
                let _ = lp.peers[o].engine.grant(&t, &tids[p], &edge(ROLES[rng.next(3) as usize]));
                if !hidden {
                    lp.sync_all().unwrap();
                }
            }
        }
    }
    lp.sync_all().unwrap();
    let mut run = Run { lp, tids, actors, ever: vec![BTreeSet::new(); N], made: BTreeMap::new(), rng, hostile: BTreeSet::new(), log: Vec::new(), first: BTreeMap::new() };
    run.log.push(format!("actors {:?} (owners), peers {:?}", run.actors, run.tids));
    run.note();
    reached.cycle = k > 1;
    // the commits lowering an edge: what the withheld admin may miss
    let mut departing: BTreeSet<CommitId> = BTreeSet::new();
    let rounds = 3 + run.rng.next(4);
    for _ in 0..rounds {
        for i in 0..N {
            let (t, o) = run.actors[run.rng.next(k as u64) as usize];
            let Some(ri) = run.lp.peers[i].engine.core.role_now(&run.tids[i], &t) else { continue };
            if run.rng.next(2) == 0 || run.hostile.contains(&i) {
                continue;
            }
            let before = run.before(i);
            let j = 1 + run.rng.next(N as u64 - 1) as usize;
            let kind = match emphasis {
                0 => [7, 7, 7, 6, 3][run.rng.next(5) as usize],
                1 => [0, 0, 1, 4, 5, 6, 3, 7][run.rng.next(8) as usize],
                2 => [2, 2, 2, 0, 7][run.rng.next(5) as usize],
                _ => [0, 1, 2, 4, 7][run.rng.next(5) as usize],
            };
            // whether the action lowered an edge (a departure, or an `until` that ends one)
            let mut lowered = false;
            match kind {
                // a removal or a demotion to read
                0 | 1 if ri == Role::Admin && j != o && j != i => {
                    let new = (kind == 1 || run.rng.next(2) == 0).then_some(Role::Read);
                    lowered = run.lp.peers[i].engine.core.role_now(&run.tids[j], &t) > new && run.lp.peers[i].engine.demote(&t, &Demotion { holder: run.tids[j], new: new.map(edge), retain: None }).is_ok();
                }
                // a self-removal, a writer forging as it can
                2 if i != o => {
                    let how = if ri >= Role::Write { [Forge::None, Forge::Mark, Forge::Listed, Forge::Rotating, Forge::Backdated][run.rng.next(5) as usize] } else { Forge::None };
                    if let Forge::None = how {
                        lowered = run.lp.peers[i].engine.demote(&t, &Demotion { holder: run.tids[i], new: None, retain: None }).is_ok();
                    } else if let Ok(made) = leave(&mut run.lp, i, t, how) {
                        // a forger is hostile from here on: its node acts no more
                        run.hostile.insert(i);
                        lowered = true;
                        reached.forged = true;
                        run.ever[i].extend(made.into_iter().map(|(r, e)| (t, r, e)));
                    }
                }
                3 if ri == Role::Admin => {
                    let _ = run.lp.peers[i].engine.snapshot(&t, &osis_base::Ak::new("secrets.0").unwrap());
                }
                // a grant (raise)
                4 if ri == Role::Admin && j != o && j != i => {
                    let r = ROLES[run.rng.next(3) as usize];
                    if run.lp.peers[i].engine.core.role_now(&run.tids[j], &t) < Some(r) {
                        let _ = run.lp.peers[i].engine.grant(&t, &run.tids[j], &edge(r));
                    }
                }
                // an `until` soon on a holder's edge, at its role now
                5 if ri == Role::Admin && j != o && j != i => {
                    let until = WallMs(run.lp.peers[i].engine.core.now().0 + 1 + run.rng.next(500));
                    if let Some(r) = run.lp.peers[i].engine.core.role_now(&run.tids[j], &t) {
                        lowered = run.lp.peers[i].engine.demote(&t, &Demotion { holder: run.tids[j], new: Some(ct::Edge { role: r, until: Some(until), invite: None, tied: None }), retain: None }).is_ok();
                    }
                }
                // re-grants of every holder it sees, or one, at its role (re-writing their boxes)
                6 if ri == Role::Admin => {
                    let every = run.rng.next(2) == 0;
                    for p in (1..N).filter(|p| *p != i && *p != o && (every || *p == j)) {
                        if let Some(r) = run.lp.peers[i].engine.core.role_now(&run.tids[p], &t) {
                            let _ = run.lp.peers[i].engine.grant(&t, &run.tids[p], &edge(r));
                        }
                    }
                }
                _ if ri >= Role::Write => {
                    let rot: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= ri && run.rng.next(2) == 0).collect();
                    if !rot.is_empty() {
                        // boxing nobody, itself included, is no honest node's rotation: a
                        // vandal's lockout (notes/crypto.md, Lockouts), so its node is hostile
                        // from here on, and never the actor's first admin (whom nobody removes)
                        let nobody = run.rng.next(8) == 0 && i != o;
                        if run.rotate(i, t, &rot, nobody) && nobody {
                            run.hostile.insert(i);
                            run.log.push(format!("  peer {i} boxed nobody: hostile"));
                        }
                    }
                }
                _ => {}
            }
            if lowered {
                reached.departed = true;
                let now = super::tests::commit_ids(&mut run.lp, i);
                departing.extend(now.difference(&before.1).copied());
            }
            let ti = run.actors.iter().position(|a| a.0 == t).unwrap();
            run.log.push(format!("peer {i} ({ri:?}) on actor {ti}: kind {kind}, j {j}"));
            run.record(i, &before);
            run.note();
        }
        let all = run.rng.next(3) == 0;
        run.log.push(format!("sync (all: {all})"));
        run.sync_some(all);
        run.lp.advance(run.rng.next(2_000));
    }
    // X: an admin of G that stays one at peer 0, given everything but some departing commits
    // (and, rarely, others), re-seals and rotates
    let g = run.actors[0].0;
    let x = (1..N).find(|p| !run.hostile.contains(p) && run.lp.peers[0].engine.core.role_now(&run.tids[*p], &g) == Some(Role::Admin)).unwrap_or(0);
    let mut all = Vec::new();
    for p in (0..N).filter(|p| *p != x) {
        all.extend(run.lp.packages(p).unwrap());
    }
    let mut withheld: BTreeSet<CommitId> = departing.iter().copied().filter(|_| run.rng.next(2) == 0).collect();
    withheld.extend(all.iter().map(|p| p.id).filter(|_| run.rng.next(8) == 0));
    for pk in all.iter().filter(|p| !withheld.contains(&p.id)) {
        let _ = run.lp.peers[x].engine.ingest(&pk.bytes, pk.blobs.clone());
    }
    reached.withheld = !withheld.is_empty();
    run.log.push(format!("withheld at {x}: {}", withheld.len()));
    for _ in 0..2 {
        let before = run.before(x);
        for t in run.all() {
            let _ = run.lp.peers[x].engine.reseal_due(&t, &Pass);
            let _ = run.lp.peers[x].engine.ensure_rotated(&t);
            if run.rng.next(2) == 0 {
                let rot: BTreeSet<Role> = ROLES.into_iter().filter(|_| run.rng.next(2) == 0).collect();
                let _ = run.rotate(x, t, &rot, false);
            }
        }
        run.record(x, &before);
        run.note();
    }
    // the recovery from a hostile node's lockout (notes/crypto.md, Lockouts): an honest admin
    // removes each hostile peer still holding an edge on an actor, and each holder actor whose
    // first admin is hostile (no keyset of it may ever know a departure from it)
    run.lp.sync_all().unwrap();
    for (t, o) in run.actors.clone() {
        let Some(a) = (0..N).find(|p| !run.hostile.contains(p) && run.lp.peers[*p].engine.core.role_now(&run.tids[*p], &t) == Some(Role::Admin)) else { continue };
        let peers = run.hostile.iter().filter(|h| **h != o).map(|h| (format!("peer {h}"), run.tids[*h]));
        let groups = run.actors.iter().filter(|(m, mo)| *m != t && run.hostile.contains(mo)).map(|(m, _)| (format!("actor {m:?}"), *m));
        let gone: Vec<(String, Tid)> = peers.chain(groups).collect();
        for (h, ht) in gone {
            let before = run.before(a);
            if run.lp.peers[a].engine.demote(&t, &Demotion { holder: ht, new: None, retain: None }).is_ok() {
                let now = super::tests::commit_ids(&mut run.lp, a);
                departing.extend(now.difference(&before.1).copied());
                reached.departed = true;
                let ti = run.actors.iter().position(|x| x.0 == t).unwrap();
                run.log.push(format!("peer {a} removes hostile {h} from actor {ti}"));
                run.record(a, &before);
            }
        }
        run.lp.sync_all().unwrap();
        run.note();
    }
    // without departures, re-seals alone reach a fixpoint where every holder reads everything
    // (nobody writing, nobody rotates); then the due rotations too
    if departing.is_empty() {
        settle(&mut run, seed, false);
        check(&mut run, seed, false);
    }
    settle(&mut run, seed, true);
    reached.forked = run.made.keys().any(|(t, r, e)| run.made.keys().any(|(t2, r2, e2)| t == t2 && r == r2 && e != e2 && e.n() == e2.n()));
    reached.invalid = invalid_rotations(&run);
    check(&mut run, seed, true);
    reached
}

/// Whether some rotation commit of the history is invalid (its rotator demoted unaware).
fn invalid_rotations(run: &Run) -> bool {
    let core = &run.lp.peers[0].engine.core;
    let ak = osis_base::Ak::new("secrets.0").unwrap();
    run.all().iter().any(|t| core.ix.by_aspect.get(&(*t, ak.clone())).into_iter().flatten().any(|x| core.ix.commits.get(&x.1).is_some_and(|m| m.aspect(t, &ak).is_some_and(|ai| !m.valid_at(ai)))))
}

/// Syncs everything, then rounds of every node's re-seals (and, with `rotate`, due rotations) on
/// every actor until nothing is written.
fn settle(run: &mut Run, seed: u64, rotate: bool) {
    run.lp.sync_all().unwrap();
    for _ in 0..16 {
        let mut n = walk_sides(run);
        let concurrent = run.rng.next(2) == 0;
        for p in 0..N {
            for t in run.all() {
                if run.hostile.contains(&p) || run.lp.peers[p].engine.core.role_now(&run.tids[p], &t).is_none() {
                    continue;
                }
                let a = run.lp.peers[p].engine.reseal_due(&t, &Pass).unwrap().commits.len();
                let b = if !rotate { 0 } else { run.lp.peers[p].engine.ensure_rotated(&t).unwrap_or_else(|e| panic!("seed {seed}: peer {p} ensure_rotated {t:?}: {e:?}")).0.commits.len() };
                n += a + b;
                if a + b > 0 {
                    let ti = run.actors.iter().position(|x| x.0 == t).unwrap();
                    run.log.push(format!("settle: peer {p} on actor {ti}: {a} re-seals, {b} rotations"));
                }
            }
            if !concurrent {
                run.lp.sync_all().unwrap();
                run.note();
            }
        }
        run.lp.sync_all().unwrap();
        run.note();
        if n == 0 {
            return;
        }
    }
    panic!("seed {seed}: no fixpoint in 16 rounds");
}

/// Every peer takes the walk's side in each admin dispute it holds, as its user choosing it
/// would: a default side is the first received (a party sides with its own removal), and only
/// nodes under one trust set must read alike (spec/permissions.md §5.1); forks are permanent, so
/// the property is checked within the walk's side. How many sides changed.
fn walk_sides(run: &mut Run) -> usize {
    let mut n = 0;
    for p in 0..N {
        let (ds, _) = run.lp.peers[p].engine.disputes(usize::MAX);
        for d in ds.iter().filter(|d| d.side.is_some_and(|s| s.trust)) {
            run.lp.peers[p].engine.choose(d.commit, d.op, d.holder, false).unwrap();
            n += 1;
        }
    }
    n
}

/// Whether peer `d` may read role `r` of actor `t` in peer `at`'s rosters: a holder of it for
/// keys, itself or through a holder actor it may read at `r`.
fn access(run: &Run, at: usize, d: usize, t: Tid, r: Role) -> bool {
    let mut reach: BTreeSet<Tid> = BTreeSet::new();
    loop {
        let n = reach.len();
        for a in run.all() {
            let holders = run.lp.peers[at].engine.core.key_holders(&a);
            if holders.iter().any(|(m, mr)| *mr >= r && (*m == run.tids[d] || reach.contains(m))) {
                reach.insert(a);
            }
        }
        if reach.len() == n {
            return reach.contains(&t);
        }
    }
}

/// The property, on the settled history; with `rotated`, after the due rotations too: nothing
/// blocked, every holder boxed, and nothing leaked.
fn check(run: &mut Run, seed: u64, rotated: bool) {
    let all = run.all();
    for (t, o) in run.actors.clone() {
        let direct: Vec<(usize, Role)> = (0..N).filter(|p| !run.hostile.contains(p)).filter_map(|p| run.key_role(o, &t, p).map(|r| (p, r))).collect();
        let role = |p: usize| direct.iter().find(|x| x.0 == p).map(|x| x.1);
        // a hostile first admin is never removed and acts no more: nothing recovers its lockouts
        // (notes/crypto.md, Lockouts), so the actor need not settle
        if rotated && !run.hostile.contains(&o) {
            let blocked = super::tests::blocked_at(&mut run.lp, o, t);
            assert!(blocked.is_empty(), "seed {seed}: the first admin of {t:?} settles with {blocked:?} blocked");
            assert!(super::tests::all_boxed(&mut run.lp, o, &[t]), "seed {seed}: a holder of {t:?} with key access lacks a box");
        }
        for r in ROLES {
            let ep = |p: usize| run.lp.peers[p].engine.epochs(&t).unwrap_or_default().role(r).clone();
            let at_o = ep(o).current();
            // every holder agrees on the current epochs, each established by the first admin
            for &(p, _) in &direct {
                assert!(at_o.iter().all(|x| ep(o).is_established(x)), "seed {seed}: {t:?} {r:?}: the first admin counts current {at_o:?}, not all established there");
                assert_eq!(ep(p).current(), at_o, "seed {seed}: {t:?} {r:?}: peers {o} and {p} count different current epochs (rotated: {rotated})");
            }
            // every holder ends reading everything: it holds each current epoch a holder that
            // may rotate holds, and every earlier superseded secret a holder of it holds
            for e in &at_o {
                let any = direct.iter().any(|&(p, pr)| pr >= r.max(Role::Write) && ep(p).secret(e).is_some());
                let lacking: Vec<usize> = direct.iter().filter(|&&(p, pr)| pr >= r && ep(p).secret(e).is_none()).map(|x| x.0).collect();
                assert!(!any || lacking.is_empty(), "seed {seed}: {t:?} {r:?} holders {lacking:?} lack current epoch {e:?} another holds (rotated: {rotated})");
                let at_e: Vec<usize> = direct.iter().filter(|&&(p, pr)| pr >= r && ep(p).secret(e).is_some()).map(|x| x.0).collect();
                for &p in &at_e {
                    let ex = ep(p);
                    for (x, _) in ex.held_established().filter(|(x, _)| x.n() < e.n() && !ex.is_current(x)) {
                        let missing: Vec<usize> = at_e.iter().copied().filter(|h| ep(*h).secret(&x).is_none()).collect();
                        assert!(missing.is_empty(), "seed {seed}: {t:?} {r:?} holders {missing:?} of current {e:?} lack earlier {x:?} peer {p} holds");
                    }
                }
            }
            if !rotated {
                continue;
            }
            // no departed holder reads later content: what a holder that may write encrypts
            // under, and every epoch made by a rotator that saw the peer depart, opens to no
            // peer without access, from all it ever held or made and every box
            let gone: Vec<usize> = (0..N).filter(|d| !access(run, o, *d, t, r)).collect();
            for &d in &gone {
                let opens = openable(&mut run.lp, o, &all, run.tids[d], run.ever[d].clone());
                for &(h, hr) in direct.iter().filter(|x| x.1 >= r.max(Role::Write)) {
                    if super::tests::blocked_at(&mut run.lp, h, t).contains(&r) {
                        continue;
                    }
                    if let Some((e, _)) = run.lp.peers[h].engine.epochs(&t).unwrap_or_default().role(r).newest_held() {
                        assert!(!opens.contains(&(t, r, e)), "seed {seed}: peer {d} (now {:?}) opens {t:?} {r:?} epoch {e:?} peer {h} ({hr:?}) encrypts under", role(d));
                    }
                }
                let last = departure(run, o, t, d);
                for ((mt, mr, e), (held, below)) in &run.made {
                    if *mt == t && *mr == r && below.contains(&d) && last.is_some_and(|c| held.contains(&c)) {
                        assert!(!opens.contains(&(t, r, *e)), "seed {seed}: peer {d} (now {:?}) opens {t:?} {r:?} epoch {e:?}, made by a rotator that saw it depart (first held at step {:?})", role(d), run.first.get(&(d, (t, r, *e))));
                    }
                }
            }
        }
    }
}

/// Peer `d`'s departure from `t` in the settled timeline: the last applied write on its edge,
/// or a later demotion whose audit dropped a write on it.
fn departure(run: &Run, o: usize, t: Tid, d: usize) -> Option<CommitId> {
    let tl = run.lp.peers[o].engine.core.timelines.get(&t)?;
    let on_edge = |c: &CommitId| tl.role_commit(c).is_some_and(|mc| mc.ops.iter().any(|op| op.target == t && op.holder == run.tids[d]));
    let applied = tl.applied().values().filter(|a| a.target == t && on_edge(&a.point.commit)).map(|a| a.point);
    let dropped = tl.dropped().iter().filter(|(w, _)| matches!(w, osis_perm::WriteId(c, _) if on_edge(c))).map(|(_, p)| *p);
    applied.chain(dropped).max().map(|p| p.commit)
}

/// The runs' coverage: with at least eight seeds (every emphasis twice), each shape is reached.
fn tally(runs: &[Reached]) {
    let count = |f: fn(&Reached) -> bool| runs.iter().filter(|r| f(r)).count();
    let line = format!(
        "rotation: {} runs; forked {}, departed {}, forged {}, cycle {}, withheld {}, invalid rotation {}",
        runs.len(),
        count(|r| r.forked),
        count(|r| r.departed),
        count(|r| r.forged),
        count(|r| r.cycle),
        count(|r| r.withheld),
        count(|r| r.invalid)
    );
    eprintln!("{line}");
    if runs.len() >= 8 {
        for (name, f) in [("forked", (|r: &Reached| r.forked) as fn(&Reached) -> bool), ("departed", |r| r.departed), ("forged", |r| r.forged), ("cycle", |r| r.cycle), ("withheld", |r| r.withheld), ("invalid", |r| r.invalid)] {
            assert!(count(f) > 0, "no run reached {name}: {line}");
        }
    }
}

fn replay(s: u64) -> String {
    format!("OSIS_ROTATION_START={s} OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_tier2_spec_crypto_4")
}

// spec/crypto.md §4, spec/permissions.md §2-§3: no departed holder reads later content, every
// holder ends reading everything (module doc). Quick size: fixed seeds, no environment.
#[test]
fn rotation_holds_spec_crypto_4() {
    tally(&osis_base::testenv::run_seeds("rotation::tests_property::rotation_holds_spec_crypto_4", &(8..16).collect::<Vec<u64>>(), false, replay, rotation_history));
}

/// Plain size (a tenth of full) or full under `OSIS_FULL=1`; seeds: OSIS_ROTATION_START,
/// OSIS_ROTATION_SEEDS.
#[test]
#[ignore = "tier 2"]
fn rotation_holds_tier2_spec_crypto_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_ROTATION_START", "OSIS_ROTATION_SEEDS", osis_base::testenv::large(0..1_000));
    tally(&s.run("rotation::tests_property::rotation_holds_tier2_spec_crypto_4", replay, rotation_history));
}

