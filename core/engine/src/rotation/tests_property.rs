//! The rotation property (spec/crypto.md §4, spec/permissions.md §2-§3), on one generator: no
//! departed holder reads later content, and every holder ends reading everything. A history
//! mixes forks (rotations on stale states, leaving holders out), departures (removals,
//! demotions, `until`s finalized, self-removals forging what a writer can), vandals (a rotation
//! boxing nobody), re-grants, invalid rotations (a rotator demoted unaware), compactions, holder
//! actors in cycles (a peer reading G only through them leaves the last), a rotator lacking a
//! role's secret, and an admin acting while some departures are withheld from it. Forgers and
//! vandals are hostile: their nodes act no more, and an honest admin removes them (and the
//! actors they are mint admin of) before settling, the re-key from their lockouts. Every node
//! settles under the walk's side of each admin dispute. The seed picks an emphasis (seed mod 4:
//! forks, departures, forgeries, cycles); every feature stays on its own draws.

#![allow(clippy::unwrap_used)]
use super::tests::{Key, Rng, Via, edge, independent_thing, openable, opens_by, opens_from, opens_in, self_opened, synced};
use super::tests_departs::{Forge, leave};
use crate::flows::Demotion;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{CommitId, Role, Tid, Time};
use osis_crypto::Epoch;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

const N: usize = 5;
const ROLES: [Role; 4] = osis_keys::ROLES;

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


/// A box: (actor, role, epoch, holder).
type BoxAt = (Tid, Role, Epoch, Tid);

/// A rotator's view when it made an epoch.
#[derive(Clone)]
struct Made {
    /// The commits it held, the rotation commit included.
    held: BTreeSet<CommitId>,
    /// The peers below the epoch's role in its view, for keys.
    below: BTreeSet<usize>,
    /// The holder actors the epoch boxes at a keyset whose secret the rotator lacked, each with
    /// that keyset.
    blind: BTreeSet<(Tid, Epoch)>,
    /// The earlier established secrets of the role it held: what its history box carries.
    carried: BTreeSet<Epoch>,
}

/// A grant that handed a peer a secret (`Run::handed`).
#[derive(Clone, Debug)]
struct Handed {
    /// Its index into `log`.
    step: usize,
    /// Its author.
    author: usize,
    /// Its target.
    on: Tid,
    /// The commits its author wrote for it (rotations first, then the grant).
    commits: BTreeSet<CommitId>,
}

struct Run {
    lp: LocalPeer,
    tids: Vec<Tid>,
    /// Each actor with the peer that made it (its mint admin, never lowered).
    actors: Vec<(Tid, usize)>,
    /// Every secret each peer held or made at any point: what a departed peer keeps.
    ever: Vec<BTreeSet<Key>>,
    /// The secrets each peer was handed by a grant, each with the grant (`Handed`): the
    /// epochs the grant boxed it that its granter held before it, and the earlier secrets of
    /// their roles the granter held (its history boxes), and what those open through boxes to
    /// the granted thing as a holder actor, none the grantee held yet. Any holder
    /// of a key may hand it on (spec/requirements.md Permissions), and a grant judged invalid
    /// (its author lowered concurrently) still opens (spec/crypto.md §4, Boxes).
    handed: Vec<BTreeMap<Key, Handed>>,
    made: BTreeMap<Key, Made>,
    /// Boxes a re-seal wrote to a holder actor at a keyset whose secret its writer lacked: the
    /// box (actor, role, epoch, holder actor), the keyset, and the commits the writer held.
    resealed: Vec<(BoxAt, Epoch, BTreeSet<CommitId>)>,
    /// The holder actors (no peers) each rotation commit boxes, per role, each with the keyset
    /// its box names, as its rotator's state read just after it (`record`).
    boxed: BTreeMap<(CommitId, Role), BTreeSet<(Tid, Epoch)>>,
    rng: Rng,
    /// Peers that forged: their nodes no longer act, and nothing is checked of them.
    hostile: BTreeSet<usize>,
    /// The history's steps, for a failure's message.
    log: Vec<String>,
    /// Every `secrets.0` state of an actor any node held after each write, and every secret any
    /// node held: what a departed party that kept every state it met opens (`opens_in`). Noted
    /// after each write, not each step: a rotation removes the boxes at the epochs it supersedes,
    /// so a box another write of the same step replaced is in no later state.
    states: Vec<(Tid, ct::Secrets)>,
    /// The step (index into `log`) each of `states` was first met at.
    state_step: Vec<usize>,
    /// The boxes to a holder actor at a keyset the first node holding them held superseded (a
    /// stale box, spec/crypto.md §4 Stale): no honest node writes one, so none is a hand-on.
    stale: BTreeSet<BoxAt>,
    secrets: BTreeMap<Key, osis_crypto::Secret32>,
    /// When each peer first held each secret (an index into `log`).
    first: BTreeMap<(usize, Key), usize>,
    /// Whether an actor holding a role on another rotated: the epochs boxing or proving its
    /// old keyset go stale, which only a rotation clears (spec/crypto.md §4, Stale).
    holder_rotated: bool,
    /// Per actors of a peer, what it holds of them (`holds`), kept while what it read stands.
    holds: crate::engine::Kept<Vec<Tid>, Holds>,
    /// Each peer's `holds` at its last `note`: noted again only once it moved.
    noted: Vec<Option<Holds>>,
}

/// What a peer holds of the actors: the keys it holds secrets of, and its `secrets.0` state of each.
type Holds = (BTreeSet<Key>, Vec<(Tid, Option<ct::Secrets>)>);

/// `Holds` of engine `e` over actors `all`.
fn holds(e: &mut crate::Engine, all: &[Tid]) -> crate::Result<Holds> {
    let mut states = Vec::new();
    for a in all {
        states.push((*a, e.get_typed(a, &ct::SECRETS)?));
    }
    Ok((held_keys(e, all), states))
}

/// The keys engine `e` holds secrets of, of actors `all`.
fn held_keys(e: &crate::Engine, all: &[Tid]) -> BTreeSet<Key> {
    let mut out = BTreeSet::new();
    for t in all {
        if let Some(e) = e.epochs(t) {
            for r in ROLES {
                out.extend(e.role(r).epochs().filter(|(_, x)| x.secret.is_some()).map(|(x, _)| (*t, r, *x)));
            }
        }
    }
    out
}

impl Drop for Run {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("the failing history: {:#?}", self.log);
            return;
        }
        // the engines' drop checks (the index, a missed addenda trigger) run after `Run` is gone:
        // run them here, so their failure prints the history too
        let peers = std::mem::take(&mut self.lp.peers);
        if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(peers))) {
            eprintln!("the failing history (an engine's drop check failed): {:#?}", self.log);
            std::panic::resume_unwind(p);
        }
    }
}

impl Run {
    fn new(lp: LocalPeer, actors: Vec<(Tid, usize)>, rng: Rng) -> Run {
        let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
        let mut run = Run { lp, tids, actors, ever: vec![BTreeSet::new(); N], handed: vec![BTreeMap::new(); N], made: BTreeMap::new(), resealed: Vec::new(), boxed: BTreeMap::new(), states: Vec::new(), state_step: Vec::new(), stale: BTreeSet::new(), secrets: BTreeMap::new(), rng, hostile: BTreeSet::new(), log: Vec::new(), first: BTreeMap::new(), holder_rotated: false, holds: crate::engine::Kept::new("rotation property: holds"), noted: vec![None; N] };
        run.log.push(format!("actors {:?} (owners), peers {:?}", run.actors, run.tids));
        run.note();
        run
    }

    /// A copy, its world copied (notes/test-harnesses.md, Copied worlds).
    fn copy(&mut self) -> Run {
        Run {
            lp: self.lp.copy().unwrap(),
            tids: self.tids.clone(),
            actors: self.actors.clone(),
            ever: self.ever.clone(),
            handed: self.handed.clone(),
            made: self.made.clone(),
            resealed: self.resealed.clone(),
            boxed: self.boxed.clone(),
            rng: self.rng.clone(),
            hostile: self.hostile.clone(),
            log: self.log.clone(),
            states: self.states.clone(),
            state_step: self.state_step.clone(),
            stale: self.stale.clone(),
            secrets: self.secrets.clone(),
            first: self.first.clone(),
            holder_rotated: self.holder_rotated,
            holds: crate::engine::Kept::new("rotation property: holds"),
            noted: self.noted.clone(),
        }
    }

    fn all(&self) -> Vec<Tid> {
        self.actors.iter().map(|a| a.0).collect()
    }

    fn held(&self, p: usize) -> BTreeSet<Key> {
        held_keys(&self.lp.peers[p].engine, &self.all())
    }

    /// Notes what each peer holds: its secrets (`ever`, `first`, `secrets`) and its `secrets.0`
    /// state of each actor.
    fn note(&mut self) {
        let all = self.all();
        for p in 0..N {
            let seen = self.lp.peers[p].engine.memo(&self.holds, &all, |e| holds(e, &all)).unwrap();
            if self.noted[p].as_ref() == Some(&seen) {
                continue;
            }
            self.noted[p] = Some(seen.clone());
            let (h, states) = seen;
            for k in &h {
                self.first.entry((p, *k)).or_insert(self.log.len());
            }
            self.ever[p].extend(h);
            self.secrets.extend(super::tests::held_secrets(&self.lp.peers[p], &all));
            for (a, s) in states {
                if let Some(s) = s
                    && !self.states.iter().any(|x| x.0 == a && x.1 == s)
                {
                    self.stale.extend(self.stale_boxes(p, a, &s));
                    self.states.push((a, s));
                    self.state_step.push(self.log.len());
                }
            }
        }
    }

    /// The boxes new in state `s` of actor `a` (in no state of it met before) to a holder actor
    /// at a keyset peer `p`, the first node holding them, holds superseded.
    fn stale_boxes(&self, p: usize, a: Tid, s: &ct::Secrets) -> Vec<BoxAt> {
        use osis_keys::aspects::from_schema;
        let core = &self.lp.peers[p].engine.core;
        let new = |k, b| !self.states.iter().any(|x| x.0 == a && x.1.boxes.get(k) == Some(b));
        // a joint box is stale where any keyset it names is
        let sealed = s.boxes.iter().filter(|(k, b)| !self.tids.contains(&k.holder.0) && new(*k, *b)).flat_map(|(k, b)| {
            let e = from_schema(&k.epoch).ok();
            osis_keys::box_keysets(b).into_iter().filter_map(move |via| Some((k, e?, via)))
        });
        let superseded = |m: &Tid, r: Role, k: &Epoch| core.epochs(m).is_some_and(|ep| ep.role(r).epochs().any(|(_, info)| info.rotations.iter().any(|(_, list)| list.contains(k))));
        sealed.filter(|(k, _, via)| superseded(&k.holder.0, k.role, via)).map(|(k, e, _)| (a, k.role, e, k.holder.0)).collect()
    }

    /// Peer `i` granted peer `j` role `r` on `t`: notes what that handed `j` (`handed`), on `t`
    /// and, through boxes to `t` as a holder actor, on the actors `t` holds a role on. A grant's
    /// box carries what its author held when writing it (spec/crypto.md §4, Boxes), so the
    /// epochs a rotation the grant made first count too.
    fn grant(&mut self, i: usize, j: usize, t: Tid, r: Role) {
        // the actors `i` may read
        let all: Vec<Tid> = self.all().into_iter().filter(|a| self.lp.peers[i].engine.get_typed(a, &ct::SECRETS).is_ok()).collect();
        let before = openable(&mut self.lp, i, &all, self.tids[j], BTreeSet::new());
        let ids = super::tests::commit_ids(&mut self.lp, i);
        if self.lp.peers[i].engine.grant(&t, &self.tids[j], &edge(r)).is_ok() {
            let commits: BTreeSet<CommitId> = super::tests::commit_ids(&mut self.lp, i).difference(&ids).copied().collect();
            let handed = Handed { step: self.log.len(), author: i, on: t, commits };
            let had: BTreeSet<Key> = self.held(i).into_iter().filter(|k| k.0 == t).collect();
            let after = openable(&mut self.lp, i, &all, self.tids[j], BTreeSet::new());
            let boxed: BTreeSet<Key> = after.difference(&before).filter(|k| had.contains(k)).copied().collect();
            let carried = had.iter().filter(|k| boxed.iter().any(|b| b.1 == k.1 && k.2.n() < b.2.n()));
            let carried: BTreeSet<Key> = carried.copied().collect();
            // a handed secret of `t` opens every box to `t` at it written so far, at any node,
            // not only those its author had received: the author holds the secret, so it opens
            // them too (a secret once shared cannot be un-shared); a stale box is a leak, not a
            // hand-on
            let nobody = Tid::from_bytes([0; osis_base::format::TID_LEN]);
            let reach = opens_in(&self.lp, &self.states, &self.secrets, nobody, boxed.union(&carried).copied().collect(), &self.stale);
            let above = after.difference(&before).chain(&reach).filter(|k| k.0 != t);
            for k in boxed.iter().chain(&carried).chain(above).filter(|k| !self.ever[j].contains(k)) {
                self.handed[j].entry(*k).or_insert_with(|| handed.clone());
            }
        }
    }

    /// Peer `p` re-seals what is due on `t`, noting the boxes it seals blind (`resealed`). How
    /// many commits it wrote.
    fn reseal(&mut self, p: usize, t: Tid) -> crate::Result<usize> {
        let before = self.lp.peers[p].engine.get_typed(&t, &ct::SECRETS).ok().flatten().unwrap_or_default();
        let n = self.lp.peers[p].engine.reseal_after_pass(&t)?.commits.len();
        let after = self.lp.peers[p].engine.get_typed(&t, &ct::SECRETS).ok().flatten().unwrap_or_default();
        let held = super::tests::commit_ids(&mut self.lp, p);
        use osis_keys::aspects::from_schema;
        for (k, b) in after.boxes.iter().filter(|(k, b)| before.boxes.get(k) != Some(b) && !self.tids.contains(&k.holder.0)) {
            for via in osis_keys::box_keysets(b) {
                if let Ok(e) = from_schema(&k.epoch)
                    && !self.ever[p].contains(&(k.holder.0, k.role, via))
                {
                    self.resealed.push(((t, k.role, e, k.holder.0), via, held.clone()));
                }
            }
        }
        Ok(n)
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

    /// Records the epochs peer `i` made since `before`, each with the peers below its role as
    /// the history stood just after its rotation commit (`access_at`): a step may remove a peer
    /// from a holder actor after its cascade rotated an actor boxing that holder, when the peer
    /// still read through it.
    fn record(&mut self, i: usize, (known, held): &(BTreeSet<Key>, BTreeSet<CommitId>)) {
        for t in self.all() {
            let Some(e) = self.lp.peers[i].engine.epochs(&t) else { continue };
            for r in ROLES {
                for (x, info) in e.role(r).epochs() {
                    if info.checked().is_some() && !known.contains(&(t, r, *x)) {
                        let own = self.lp.peers[i].engine.core.ix.epoch_intro.get(&(t, r, *x)).map(|v| v.1);
                        let after = own.and_then(|c| self.after(i, &c));
                        // a peer reading a holder actor the epoch boxes reads it rightly
                        let via = self.boxed_actors(i, t, r, x);
                        if let Some(c) = own {
                            self.boxed.insert((c, r), via.clone());
                        }
                        // its rotator holds what it made (a leaver rotating in its own
                        // self-removal): rule 1 judges who encrypts under it after
                        let below: BTreeSet<usize> = (0..N).filter(|d| *d != i && !access_at(self, i, *d, t, r, after) && !via.iter().any(|(m, _)| access_at(self, i, *d, *m, r, after))).collect();
                        // a rotator lacking the secret of the keyset it seals a boxed actor at
                        // judges it by order alone (spec/crypto.md §4, the limit for an epoch whose
                        // secret the node lacks): a departed peer may open the epoch by that box
                        // where order allows it (`excused`)
                        let blind: BTreeSet<(Tid, Epoch)> = via.iter().copied().filter(|(m, k)| !self.ever[i].contains(&(*m, r, *k))).collect();
                        self.log.push(format!("  made actor {} {r:?} n{} {:?} at peer {i}, below {below:?}, blind {}", self.actors.iter().position(|a| a.0 == t).unwrap(), x.n(), &x.nonce()[..2], blind.len()));
                        let carried = e.role(r).held_established().map(|(y, _)| y).filter(|y| y.n() < x.n()).collect();
                        self.made.insert((t, r, *x), Made { held: held.iter().copied().chain(own).collect(), below, blind, carried });
                    }
                }
            }
        }
    }

    /// The point just after commit `c` in the key order, as peer `i` holds it: its own edge
    /// writes applied.
    fn after(&self, i: usize, c: &CommitId) -> Option<osis_perm::Point> {
        let h = &self.lp.peers[i].engine.core.ix.commits.get(c)?.header;
        Some(osis_perm::Point { ts: h.ts, node: h.signer, commit: CommitId([0xff; 32]) })
    }

    /// The holder actors (no peers) epoch `e` of role `r` of actor `a` boxes in peer `i`'s
    /// `secrets.0` state, each with the keyset its box names (each, for a joint box).
    fn boxed_actors(&mut self, i: usize, a: Tid, r: Role, e: &Epoch) -> BTreeSet<(Tid, Epoch)> {
        let s = self.lp.peers[i].engine.get_typed(&a, &ct::SECRETS).ok().flatten().unwrap_or_default();
        let at = |k: &ct::BoxKey| k.role == r && osis_keys::aspects::from_schema(&k.epoch).is_ok_and(|x| x == *e);
        s.boxes.iter().filter(|(k, _)| at(k) && !self.tids.contains(&k.holder.0)).flat_map(|(k, b)| osis_keys::box_keysets(b).into_iter().map(move |x| (k.holder.0, x))).collect()
    }

    /// Whether keyset `k` of role `r` of holder actor `m` is superseded where the commits `held`
    /// are: the supersedes list of a keyset of `m` written by a held rotation commit, valid as
    /// peer `o` judges it settled, names it (spec/crypto.md §4, Stale).
    fn superseded(&self, o: usize, held: &BTreeSet<CommitId>, m: Tid, r: Role, k: &Epoch) -> bool {
        let Some(ep) = self.lp.peers[o].engine.core.epochs(&m) else { return false };
        ep.role(r).epochs().any(|(_, info)| info.rotations.iter().any(|(c, list)| held.contains(c) && list.contains(k)))
    }

    /// Whether a box to holder actor `m` at keyset `k` of role `r`, sealed by a rotator lacking
    /// `k`'s secret and holding the commits `held`, is within the stated limits for departed
    /// peer `d` (spec/crypto.md §4), read from the history at `o`. Seal leaves `m` out where `k`'s
    /// rotation boxes a keyset of a holder actor of `m` that a keyset the rotator held
    /// supersedes (Stale), so a departure below `m` reaches the box only until such a keyset
    /// does (the limit for a departure from a holder actor of M). A departure from `m` itself is
    /// judged by order alone (the limit for an epoch whose secret the node lacks): within it
    /// unless the rotator held `d`'s departure from `m` (`tail_departure_point`: the write a covering epoch must name)
    /// and `k`'s rotation is ordered before it. Boxes a later grant or re-seal of `m` writes at
    /// `k`, keysets held invalid or tainted (Stale too) and superseding keysets held only by a
    /// compaction snapshot are not read: wider than Seal there.
    fn excused(&self, o: usize, held: &BTreeSet<CommitId>, m: Tid, r: Role, k: &Epoch, d: usize) -> bool {
        let core = &self.lp.peers[o].engine.core;
        let Some((_, c)) = core.ix.epoch_intro.get(&(m, r, *k)) else { return true };
        if held.contains(c) && self.boxed.get(&(*c, r)).into_iter().flatten().any(|(m2, k2)| self.superseded(o, held, *m2, r, k2)) {
            return false;
        }
        let Some(om) = self.actors.iter().find(|x| x.0 == m).map(|x| x.1) else { return true };
        let Some(dep) = tail_departure_point(self, om, m, d, r) else { return true };
        let Some(h) = core.ix.commits.get(c).map(|x| &x.header) else { return true };
        let made = osis_perm::Point { ts: h.ts, node: h.signer, commit: *c };
        !(held.contains(&dep.commit) && made < dep)
    }

    /// Peer `i` rotates `rot` of `t`, leaving out each other member (peer or actor) at random, or
    /// everyone (`nobody`: an epoch with no box, a vandal's); refused, nothing. Whether it was made.
    fn rotate(&mut self, i: usize, t: Tid, rot: &BTreeSet<Role>, nobody: bool) -> bool {
        let made = self.rotate_at(i, t, rot, nobody);
        self.rotated(i, t, made);
        made
    }

    /// Notes that peer `i` rotated `t` (`made`), for `holder_rotated`.
    fn rotated(&mut self, i: usize, t: Tid, made: bool) {
        let holder = self.all().iter().any(|a| *a != t && self.lp.peers[i].engine.core.key_holders(a).iter().any(|h| h.0 == t));
        self.holder_rotated |= made && holder;
    }

    /// `rotate`, unnoted.
    fn rotate_at(&mut self, i: usize, t: Tid, rot: &BTreeSet<Role>, nobody: bool) -> bool {
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
            let holders = super::recipients(tx, &tx.core.tid(), &t, &skip)?;
            let mut m = Mutation::new();
            let r = super::rotation_into(tx, &mut m, t, rot, &held, &holders, crate::rotation::Departs::No)?;
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
    let mut lp = LocalPeer::new(N, seed, Time(1_700_000_000_000)).unwrap();
    lp.sync_all().unwrap();
    let tids: Vec<Tid> = (0..N).map(|i| lp.peers[i].engine.tid()).collect();
    // actors: G (peer 0's); with holder actors, one or two more, some of peer 2's, granted
    // roles on each other around a cycle
    let mut actors = vec![(independent_thing(&mut lp, 0), 0)];
    let cycle = emphasis == 3 || rng.next(6) == 0;
    if cycle {
        let two = rng.next(2) == 0;
        for _ in 0..1 + rng.next(2) {
            let o = if two && rng.next(2) == 0 { 2 } else { 0 };
            actors.push((independent_thing(&mut lp, o), o));
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
                    let _ = lp.peers[o].engine.grant(&t, &actors[j].0, &edge(ROLES[rng.next(ROLES.len() as u64) as usize]));
                    if !hidden {
                        lp.sync_all().unwrap();
                    }
                }
            }
        }
    }
    // every peer on G, and some on each other actor; with holder actors, in half the seeds a
    // deep peer instead on the last actor alone: it reads G only through the chain of holder
    // actors, so departs below G
    let deep = (cycle && rng.next(2) == 0).then(|| 1 + rng.next(N as u64 - 1) as usize).filter(|p| actors.iter().all(|a| a.1 != *p));
    for (ai, &(t, o)) in actors.iter().enumerate() {
        for p in (1..N).filter(|p| *p != o) {
            let granted = if deep == Some(p) { ai == k - 1 } else { ai == 0 || rng.next(3) == 0 };
            if granted {
                let _ = lp.peers[o].engine.grant(&t, &tids[p], &edge(ROLES[rng.next(ROLES.len() as u64) as usize]));
                if !hidden {
                    lp.sync_all().unwrap();
                }
            }
        }
    }
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, actors, rng);
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
                        run.log.push(format!("  peer {i} forges {how:?}: {:?}", made.iter().map(|(r, e)| (r, e.n(), e.nonce()[0])).collect::<Vec<_>>()));
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
                    let r = ROLES[run.rng.next(ROLES.len() as u64) as usize];
                    if run.lp.peers[i].engine.core.role_now(&run.tids[j], &t) < Some(r) {
                        run.grant(i, j, t, r);
                    }
                }
                // an `until` soon on a holder's edge, at its role now
                5 if ri == Role::Admin && j != o && j != i => {
                    let until = Time(run.lp.peers[i].engine.core.now().0 + 1 + run.rng.next(500));
                    if let Some(r) = run.lp.peers[i].engine.core.role_now(&run.tids[j], &t) {
                        lowered = run.lp.peers[i].engine.demote(&t, &Demotion { holder: run.tids[j], new: Some(ct::Edge { role: r, until: Some(until), may_grant: false, retain: false, floor: None }), retain: None }).is_ok();
                    }
                }
                // re-grants of every holder it sees, or one, at its role (re-writing their boxes)
                6 if ri == Role::Admin => {
                    let every = run.rng.next(2) == 0;
                    for p in (1..N).filter(|p| *p != i && *p != o && (every || *p == j)) {
                        if let Some(r) = run.lp.peers[i].engine.core.role_now(&run.tids[p], &t) {
                            run.grant(i, p, t, r);
                        }
                    }
                }
                _ if ri >= Role::Write => {
                    let rot: BTreeSet<Role> = ROLES.into_iter().filter(|r| *r <= ri && run.rng.next(2) == 0).collect();
                    if !rot.is_empty() {
                        // boxing nobody, itself included, is no honest node's rotation: a
                        // vandal's lockout (notes/keys.md, Lockouts), so its node is hostile
                        // from here on, and never the actor's mint admin (whom nobody removes)
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
    // the deep peer leaves the last actor (its mint admin removes it, half the time synced to
    // everyone before X acts), so a blind sealer of G meets a stale box below what it seals
    if let Some(d) = deep.filter(|d| !run.hostile.contains(d)) {
        let (t, o) = run.actors[k - 1];
        let before = run.before(o);
        if run.lp.peers[o].engine.demote(&t, &Demotion { holder: run.tids[d], new: None, retain: None }).is_ok() {
            reached.departed = true;
            let now = super::tests::commit_ids(&mut run.lp, o);
            departing.extend(now.difference(&before.1).copied());
            run.log.push(format!("peer {o} removes deep peer {d} from actor {}", k - 1));
            run.record(o, &before);
            run.note();
            if run.rng.next(2) == 0 {
                run.lp.sync_all().unwrap();
                run.note();
            }
        }
    }
    // X: an honest admin of G that stays one at peer 0, given everything but some departing
    // commits (and, rarely, others), re-seals and rotates
    let g = run.actors[0].0;
    // a hostile node acts no more (a hostile admin of a holder actor boxing a departed peer is
    // no rule's to stop): with no honest admin of G (its mint admin a forger), no X
    if let Some(x) = (1..N).chain([0]).find(|p| !run.hostile.contains(p) && run.lp.peers[0].engine.core.role_now(&run.tids[*p], &g) == Some(Role::Admin)) {
        let mut all = Vec::new();
        for p in (0..N).filter(|p| *p != x) {
            all.extend(run.lp.packages_for(p, x).unwrap());
        }
        // drawn in history order (ts, signer), not by commit ID: an ID hashes the path a role commit
        // states, so the role-paths property's two runs of a seed withhold the same writes
        let order = |c: &CommitId| (0..N).find_map(|p| run.lp.peers[p].engine.core.ix.commits.get(c).map(|m| (m.header.ts, m.header.signer)));
        let mut lowering: Vec<CommitId> = departing.iter().copied().collect();
        lowering.sort_by_key(&order);
        all.sort_by_key(|p| order(&p.id));
        let mut withheld: BTreeSet<CommitId> = lowering.into_iter().filter(|_| run.rng.next(2) == 0).collect();
        withheld.extend(all.iter().map(|p| p.id).filter(|_| run.rng.next(8) == 0));
        for pk in all.iter().filter(|p| !withheld.contains(&p.id)) {
            let _ = run.lp.peers[x].receive(&pk.bytes, pk.blobs.clone());
        }
        reached.withheld = !withheld.is_empty();
        run.log.push(format!("withheld at {x}: {}", withheld.len()));
        for _ in 0..2 {
            let before = run.before(x);
            for t in run.all() {
                let _ = run.reseal(x, t);
                run.note();
                let made = run.lp.peers[x].engine.ensure_rotated(&t).is_ok_and(|d| !d.0.commits.is_empty());
                run.rotated(x, t, made);
                run.note();
                if run.rng.next(2) == 0 {
                    let rot: BTreeSet<Role> = ROLES.into_iter().filter(|_| run.rng.next(2) == 0).collect();
                    let _ = run.rotate(x, t, &rot, false);
                }
                run.note();
            }
            run.record(x, &before);
            run.note();
        }
    }
    // the re-key after a hostile node's lockout (notes/keys.md, Lockouts): an honest admin
    // removes each hostile peer still holding an edge on an actor, and each holder actor whose
    // mint admin is hostile (no keyset of it may ever know a departure from it)
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
                run.note();
            }
        }
        run.lp.sync_all().unwrap();
        run.note();
    }
    // without departures, re-seals alone reach a fixpoint where every holder reads everything
    // (nobody writing, nobody rotates), unless a holder actor rotated: an epoch boxing or proving
    // its old keyset is stale, so blocked, and takes no history add until its due rotation;
    // then the due rotations too
    if departing.is_empty() && !run.holder_rotated {
        settle(&mut run, seed, false);
        check(&mut run, seed, false);
    }
    settle(&mut run, seed, true);
    reached.forked = run.made.keys().any(|(t, r, e)| run.made.keys().any(|(t2, r2, e2)| t == t2 && r == r2 && e != e2 && e.n() == e2.n()));
    reached.invalid = invalid_rotations(&run);
    check(&mut run, seed, true);
    // `OSIS_ROTATION_DUMP`: the run's steps
    if osis_base::testenv::u64_var("OSIS_ROTATION_DUMP").is_some() {
        run.log.iter().for_each(|l| eprintln!("{l}"));
    }
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
                let a = run.reseal(p, t).unwrap();
                if a > 0 {
                    run.note();
                }
                let b = if !rotate { 0 } else { run.lp.peers[p].engine.ensure_rotated(&t).unwrap_or_else(|e| panic!("seed {seed}: peer {p} ensure_rotated {t:?}: {e:?}")).0.commits.len() };
                if b > 0 {
                    run.note();
                }
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
    (0..N).map(|p| run.lp.peers[p].engine.take_walk_sides()).sum()
}

/// Whether peer `d` may read role `r` of actor `t` in peer `at`'s rosters: a holder of it for
/// keys, itself or through a holder actor it may read at `r` whose grant has key access there (a
/// keyless grant, closing a cycle, gives no read access through it: spec/requirements.md
/// Permissions, spec/crypto.md §4 Key access).
fn access(run: &Run, at: usize, d: usize, t: Tid, r: Role) -> bool {
    access_at(run, at, d, t, r, None)
}

/// `access` as the rosters stood just before `point` (`None`: now), key access judged over the
/// actor grants standing there (a grant keyless then, its cycle's earlier grant standing, reads
/// nothing then, whatever a later removal gave it).
fn access_at(run: &Run, at: usize, d: usize, t: Tid, r: Role, point: Option<osis_perm::Point>) -> bool {
    let core = &run.lp.peers[at].engine.core;
    let holders_of = |a: &Tid| -> Vec<(Tid, Role)> {
        match (point, core.timelines().get(a)) {
            (Some(p), Some(tl)) => tl.edges_at(Some(p)).holders(a).filter_map(|(m, e)| Some((*m, super::key_role(Some(e))?))).collect(),
            _ => core.key_holders(a),
        }
    };
    let keyless: BTreeSet<(Tid, Tid)> = match point {
        Some(p) => run.all().iter().filter_map(|a| core.timelines().get(a)).flat_map(|tl| super::members::keyless_before(tl, p)).collect(),
        None => (*super::members::key_access(core)).clone(),
    };
    let mut reach: BTreeSet<Tid> = BTreeSet::new();
    loop {
        let n = reach.len();
        for a in run.all() {
            let holders = holders_of(&a);
            if holders.iter().any(|(m, mr)| *mr >= r && (*m == run.tids[d] || reach.contains(m) && !keyless.contains(&(a, *m)))) {
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
    // what each party's own node opens of the states met (`self_opened`): the check reads it for
    // every actor and role
    let mut own_opened: BTreeMap<usize, Vec<(Key, Via)>> = BTreeMap::new();
    for (t, o) in run.actors.clone() {
        let direct: Vec<(usize, Role)> = (0..N).filter(|p| !run.hostile.contains(p)).filter_map(|p| run.key_role(o, &t, p).map(|r| (p, r))).collect();
        let role = |p: usize| direct.iter().find(|x| x.0 == p).map(|x| x.1);
        // a hostile mint admin is never removed and acts no more: nothing recovers its lockouts
        // (notes/keys.md, Lockouts), so the actor need not settle
        if rotated && !run.hostile.contains(&o) {
            let blocked = super::tests::blocked_at(&mut run.lp, o, t);
            assert!(blocked.is_empty(), "seed {seed}: the mint admin of {t:?} settles with {blocked:?} blocked");
            assert!(super::tests::all_boxed(&mut run.lp, o, &[t]), "seed {seed}: a holder of {t:?} with key access lacks a box");
        }
        for r in ROLES {
            let ep = |p: usize| run.lp.peers[p].engine.epochs(&t).unwrap_or_default().role(r).clone();
            let at_o = ep(o).current();
            // every holder at r agrees on the current epochs, each established by the mint admin;
            // a node holding none of r's secrets reads supersession from keysets alone, without
            // the history boxes (spec/crypto.md §4, Supersedes), so may count more
            // a holder of only sync reads nothing, so holds no secret (spec/permissions.md §3)
            let holds = r.max(Role::Read);
            for &(p, _) in direct.iter().filter(|x| x.1 >= holds) {
                assert!(at_o.iter().all(|x| ep(o).is_established(x)), "seed {seed}: {t:?} {r:?}: the mint admin counts current {at_o:?}, not all established there");
                assert_eq!(ep(p).current(), at_o, "seed {seed}: {t:?} {r:?}: peers {o} and {p} count different current epochs (rotated: {rotated})");
            }
            // every holder ends reading everything: it holds each current epoch a holder that
            // may rotate holds, and every earlier superseded secret a holder of it holds
            for e in &at_o {
                let any = direct.iter().any(|&(p, pr)| pr >= r.max(Role::Write) && ep(p).secret(e).is_some());
                let lacking: Vec<usize> = direct.iter().filter(|&&(p, pr)| pr >= holds && ep(p).secret(e).is_none()).map(|x| x.0).collect();
                assert!(!any || lacking.is_empty(), "seed {seed}: {t:?} {r:?} holders {lacking:?} lack current epoch {e:?} another holds (rotated: {rotated})");
                let at_e: Vec<usize> = direct.iter().filter(|&&(p, pr)| pr >= holds && ep(p).secret(e).is_some()).map(|x| x.0).collect();
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
            // under opens to no peer without access, from all it ever held or made and every box
            // (but a secret a grant left it reading: `left_reading`);
            // nor does any epoch made by a rotator that saw the peer lose access (it held the
            // commit that cost the peer the thing, directly or below, and the peer reads it in
            // none of the rotator's rosters, nor in the settled ones while it was current: `holder_at`),
            // unless a grant (on the thing or on a holder actor of it) handed it on (its author's
            // own departure, or the grant counting, then rotates the role, so the first holds), the
            // history of a later epoch the peer held as a holder (in its rotator's view or the
            // settled one) carried it (access regained, here or through a holder actor, reads earlier
            // content), or it opens only through boxes within the limits (`excused`)
            let gone: Vec<usize> = (0..N).filter(|d| !access(run, o, *d, t, r)).collect();
            for &d in &gone {
                let kept: BTreeSet<Key> = run.ever[d].iter().filter(|k| !left_reading(run, o, d, k)).copied().collect();
                let opens = openable(&mut run.lp, o, &all, run.tids[d], kept);
                // a secret of `t` first held since a grant handed it, not before
                let own: BTreeSet<Key> = run.ever[d].iter().filter(|k| k.0 != t || run.handed[d].get(k).is_none_or(|g| run.first.get(&(d, **k)).is_some_and(|f| *f <= g.step))).copied().collect();
                for &(h, hr) in direct.iter().filter(|x| x.1 >= r.max(Role::Write)) {
                    if super::tests::blocked_at(&mut run.lp, h, t).contains(&r) {
                        continue;
                    }
                    if let Some((e, _)) = run.lp.peers[h].engine.epochs(&t).unwrap_or_default().role(r).newest_held() {
                        assert!(!opens.contains(&(t, r, e)), "seed {seed}: peer {d} (now {:?}) opens {t:?} {r:?} epoch {e:?} peer {h} ({hr:?}) encrypts under", role(d));
                    }
                }
                // the commits that cost it `r` of `t`: its departure from `r` on `t` itself, and
                // the one that cut its last path to `t` (through holder actors too)
                let lost: Vec<CommitId> = departure(run, o, t, d, r).into_iter().chain(path_loss(run, o, d, t, r)).collect();
                // the epochs it held access to `r` of `t` at while current in the settled order
                // (`held_while_current`): a current holder is entitled to every current epoch and to
                // the history its holders have (notes/keys.md, the three promises: 2; spec/crypto.md
                // §4 Boxes: a re-seal boxes every current holder at every current epoch, a grant with
                // history carries what lies below), and the requirement ends its reading only at a
                // rotation knowing a removal after that (spec/requirements.md Permissions); a holder
                // then by a grant concurrent with the rotation, here or on a holder actor the epoch
                // boxes, its rotator unaware, is one. Every grant drawn here goes with history: a
                // cut's floor would bar the epoch (spec/crypto.md §4 Floors)
                let holder_at: BTreeSet<Epoch> = run.made.keys().filter(|(t2, r2, e2)| *t2 == t && *r2 == r && held_while_current(run, o, d, t, r, e2)).map(|k| k.2).collect();
                let regained = |e: &Epoch| run.made.iter().any(|((t2, r2, e2), m)| *t2 == t && *r2 == r && (!m.below.contains(&d) || holder_at.contains(e2)) && m.carried.contains(e) && run.ever[d].contains(&(t, r, *e2)));
                // the boxes within the limit for `d` (`excused`), in any epoch of the history: a
                // cascade seals a holder actor blind in an epoch of an actor `t`'s epoch boxes
                let made = run.made.iter().flat_map(|((t2, r2, e2), m)| m.blind.iter().map(move |(bm, k)| ((*t2, *r2, *e2, *bm), *k, &m.held)));
                let resealed = run.resealed.iter().map(|(b, k, held)| (*b, *k, held));
                let limit: BTreeSet<BoxAt> = made.chain(resealed).filter(|(b, k, held)| run.excused(o, held, b.3, b.1, k, d)).map(|x| x.0).collect();
                // from the secrets the peer held rightly (none of an epoch made with it below): what
                // the settled boxes open to it without those within the limit, and what every
                // state met opens with and without them
                let base: BTreeSet<Key> = own.iter().filter(|k| !run.made.get(k).is_some_and(|m| m.below.contains(&d))).copied().collect();
                let settled = super::tests::openable_but(&mut run.lp, o, &all, run.tids[d], base.clone(), &limit);
                let mine = own_opened.entry(d).or_insert_with(|| self_opened(&run.lp, &run.states, run.tids[d]));
                let met: BTreeSet<Key> = opens_from(&run.states, &run.secrets, run.tids[d], base.clone(), mine, &BTreeSet::new()).into_keys().collect();
                let met_unlimited: BTreeSet<Key> = opens_from(&run.states, &run.secrets, run.tids[d], base, mine, &limit).into_keys().collect();
                let leaks = run.made.iter().filter(|((mt, mr, e), Made { held, below, .. })| *mt == t && *mr == r && below.contains(&d) && !holder_at.contains(e) && lost.iter().any(|c| held.contains(c)) && !regained(e));
                // excused only when boxes within the limit were its one way to it: a leak if the
                // settled boxes open it without them, or it holds it and no state met opens it,
                // or one opens it without them
                let leak = leaks.map(|x| *x.0).find(|k| settled.contains(k) || own.contains(k) && (met_unlimited.contains(k) || !met.contains(k)));
                if let Some(k) = leak {
                    if osis_base::testenv::u64_var("OSIS_ROTATION_DUMP").is_some() {
                        dump(run, o, d, k, &own, &limit, &lost);
                    }
                    panic!("seed {seed}: peer {d} (now {:?}) opens {t:?} {r:?} epoch {:?}, made by a rotator that saw it depart (first held at step {:?})", role(d), k.2, run.first.get(&(d, k)));
                }
            }
        }
    }
}

/// Whether peer `d` held access to role `r` of `t` (`access_at`) at some point while epoch `e`
/// was current in peer `o`'s settled order: just after `e`'s rotation commit, or just after an
/// applied edge write ordered after it and before the first held rotation commit whose keyset
/// lists `e` (spec/crypto.md §4 Supersedes).
fn held_while_current(run: &Run, o: usize, d: usize, t: Tid, r: Role, e: &Epoch) -> bool {
    let core = &run.lp.peers[o].engine.core;
    let point = |c: &CommitId| core.ix.commits.get(c).map(|m| osis_perm::Point { ts: m.header.ts, node: m.header.signer, commit: *c });
    let Some(start) = core.ix.epoch_intro.get(&(t, r, *e)).and_then(|(_, c)| point(c)) else { return false };
    let just_after = |p: osis_perm::Point| osis_perm::Point { commit: CommitId([0xff; 32]), ..p };
    let ep = core.epochs(&t).unwrap_or_default();
    let end = ep.role(r).epochs().flat_map(|(_, info)| info.rotations.iter().filter(|(_, list)| list.contains(e)).filter_map(|(c, _)| point(c))).min();
    let before_end = |p: &osis_perm::Point| end.is_none_or(|x| *p < x);
    let writes = run.all().iter().filter_map(|a| core.timelines().get(a)).flat_map(|tl| tl.applied_writes().into_values()).filter(|p| *p > start).collect::<BTreeSet<_>>();
    std::iter::once(start).chain(writes).map(just_after).filter(before_end).any(|p| access_at(run, o, d, t, r, Some(p)))
}

/// Whether peer `d` was first handed secret `k` by a grant that leaves it reading (spec/crypto.md
/// §4, Boxes: an admin demoted to reader while granting X read leaves X reading, until that
/// role's next rotation): the grant's write applies nothing and does not count in peer `o`'s
/// settled timeline of its target (its author held no write there just before it), its author
/// still holds `k`'s role on `k`'s thing, so could hand `k` on anyway (a secret once shared cannot
/// be un-shared), and that role has not moved past `k`: nobody departed it after the grant (the
/// author's own departure, regained or not, included) and no later epoch of it was made. A grant
/// that counts is named void, and a departure rotates the role: neither is excused. Read from the
/// history (the grant's commits, the timelines the rosters come from, the epochs made), not from
/// any key decision.
fn left_reading(run: &Run, o: usize, d: usize, k: &Key) -> bool {
    let Some(h) = run.handed[d].get(k) else { return false };
    if run.first.get(&(d, *k)).is_none_or(|f| *f <= h.step) {
        return false;
    }
    let Some(tl) = run.lp.peers[o].engine.core.timelines().get(&h.on) else { return false };
    let write = h.commits.iter().filter_map(|c| tl.role_commit(c)).find_map(|mc| mc.ops.iter().position(|op| op.target == h.on && op.holder == osis_base::Holder::Thing(run.tids[d])).map(|ix| (mc, ix)));
    let Some((mc, ix)) = write else { return false };
    let applies = tl.is_applied(&osis_perm::WriteId(mc.id, ix as u32));
    let counts = tl.role(&mc.signer, &h.on, osis_perm::At::before(mc.point())) >= Some(Role::Write);
    let after = |p: Option<osis_perm::Point>| p.is_some_and(|p| p > mc.point());
    let departed = (0..N).any(|p| after(departure_point(run, o, k.0, p, k.1)) || after(path_loss_point(run, o, p, k.0, k.1)));
    let moved = run.made.keys().any(|m| m.0 == k.0 && m.1 == k.1 && m.2.n() > k.2.n());
    !applies && !counts && !departed && !moved && access(run, o, h.author, k.0, k.1)
}

/// `OSIS_ROTATION_DUMP`: on a leak of epoch `k` to peer `d`, prints a legend, how `k` was made,
/// how `d` opens it (the settled boxes at peer `o` without the boxes within the limit, and every
/// state met with and without them), each box on the way with the step its state was first met at, and what it
/// held rightly (`own`), was handed, and lost (`lost`).
fn dump(run: &mut Run, o: usize, d: usize, k: Key, own: &BTreeSet<Key>, limit: &BTreeSet<BoxAt>, lost: &[CommitId]) {
    let name = |run: &Run, t: &Tid| run.tids.iter().position(|x| x == t).map(|p| format!("peer {p}")).or_else(|| run.actors.iter().position(|a| a.0 == *t).map(|a| format!("actor {a}"))).unwrap_or_else(|| format!("{t:?}"));
    let ep = |e: &Epoch| format!("n{} {:?}", e.n(), &e.nonce()[..2]);
    let key = |run: &Run, k: &Key| format!("{} {:?} {}", name(run, &k.0), k.1, ep(&k.2));
    let mut out = vec![format!("== dump: peer {d} opens {}", key(run, &k))];
    for (i, t) in run.tids.iter().enumerate() {
        out.push(format!("peer {i}: {t:?}{}", if run.hostile.contains(&i) { " (hostile)" } else { "" }));
    }
    for (i, (t, ow)) in run.actors.iter().enumerate() {
        out.push(format!("actor {i}: {t:?}, mint admin peer {ow}"));
    }
    if let Some(m) = run.made.get(&k) {
        let rotator = run.lp.peers[o].engine.core.ix.epoch_intro.get(&k).and_then(|(_, c)| run.lp.peers[o].engine.core.ix.commits.get(c)).map(|c| name(run, &c.header.signer));
        let blind: Vec<String> = m.blind.iter().map(|(t, e)| format!("{} at {}", name(run, t), ep(e))).collect();
        let carried: Vec<String> = m.carried.iter().map(ep).collect();
        out.push(format!("made by {rotator:?}: below {:?}, blind {blind:?}, carried {carried:?}, held the lost commits {:?}", m.below, lost.iter().map(|c| m.held.contains(c)).collect::<Vec<_>>()));
    }
    out.push(format!("lost: {lost:?}"));
    let all = run.all();
    let states: Vec<(Tid, ct::Secrets)> = all.iter().filter_map(|a| run.lp.peers[o].engine.get_typed(a, &ct::SECRETS).unwrap().map(|s| (*a, s))).collect();
    let mut secrets = BTreeMap::new();
    for p in &run.lp.peers {
        secrets.extend(super::tests::held_secrets(p, &all));
    }
    let base: BTreeSet<Key> = own.iter().filter(|k| !run.made.get(k).is_some_and(|m| m.below.contains(&d))).copied().collect();
    let none = BTreeSet::new();
    for (what, by) in [("settled, without the limit's boxes", opens_by(&run.lp, &states, &secrets, run.tids[d], base.clone(), limit)), ("met", opens_by(&run.lp, &run.states, &run.secrets, run.tids[d], base.clone(), &none)), ("met, without the limit's boxes", opens_by(&run.lp, &run.states, &run.secrets, run.tids[d], base, limit))] {
        out.push(format!("-- {what}:"));
        let mut at = Some(k);
        while let Some(x) = at.take() {
            let line = match by.get(&x) {
                None => "not opened".to_string(),
                Some(Via::Known) => format!("held rightly (first at step {:?}, handed at {:?})", run.first.get(&(d, x)), run.handed[d].get(&x).map(|h| h.step)),
                Some(Via::History(h)) => {
                    at = Some(*h);
                    format!("listed by the history box of {}", key(run, h))
                }
                Some(Via::Box(a, r, e, h, ks)) => {
                    at = ks.first().map(|ks| (*h, *r, *ks)).filter(|_| *h != run.tids[d]);
                    let b = (*a, *r, *e, *h);
                    let step = run.states.iter().zip(&run.state_step).find(|((t, s), _)| t == a && s.boxes.iter().any(|(bk, _)| bk.holder == osis_base::Weak(*h) && bk.role == *r && osis_keys::aspects::from_schema(&bk.epoch).ok() == Some(*e))).map(|x| *x.1);
                    format!("box to {} at keyset {:?} (first met at step {step:?}, stale {}, within the limit {})", name(run, h), ks.iter().map(ep).collect::<Vec<_>>(), run.stale.contains(&b), limit.contains(&b))
                }
            };
            out.push(format!("  {}: {line}", key(run, &x)));
        }
    }
    eprintln!("{}", out.join("\n"));
}

/// Peer `d`'s departure from role `r` of `t` in the settled timeline: the last applied write
/// taking its edge from `r` or more to below it (for keys, `key_role`), or a later demotion whose
/// audit dropped a write giving it `r` or more. A write that never gave `r` (a sync grant, for
/// read) departs nothing at `r`.
fn departure(run: &Run, o: usize, t: Tid, d: usize, r: Role) -> Option<CommitId> {
    departure_point(run, o, t, d, r).map(|p| p.commit)
}

/// The edge write (on any actor) at which peer `d` last lost role `r` of `t` by every path in
/// peer `o`'s settled timelines (`access_at`): the newest applied write with `d` reading `t` just
/// before it and not just after.
fn path_loss(run: &Run, o: usize, d: usize, t: Tid, r: Role) -> Option<CommitId> {
    path_loss_point(run, o, d, t, r).map(|p| p.commit)
}

/// `path_loss`, at its point in the key order.
fn path_loss_point(run: &Run, o: usize, d: usize, t: Tid, r: Role) -> Option<osis_perm::Point> {
    let core = &run.lp.peers[o].engine.core;
    let points: BTreeSet<osis_perm::Point> = run.all().iter().filter_map(|a| core.timelines().get(a)).flat_map(|tl| tl.applied_writes().into_values()).collect();
    let last = points.last().map(|p| osis_perm::Point { commit: CommitId([0xff; 32]), ..*p });
    // whether `d` reads `t` just before each point, then just after the last
    let reads: Vec<bool> = points.iter().copied().chain(last).map(|p| access_at(run, o, d, t, r, Some(p))).collect();
    points.iter().zip(reads.windows(2)).filter(|(_, w)| w[0] && !w[1]).map(|(p, _)| *p).next_back()
}

/// Where peer `d`'s departure from role `r` of holder actor `m` is ordered for a keyset of `m`
/// whose secret a sealer lacks, in peer `o`'s settled timeline (spec/crypto.md §4, Encrypting
/// under: the newest write a covering epoch must name, `Departure::newest_needed` over the edge
/// writes as `o` holds them: the earliest tail write taking it below `r`, when one is needed, and
/// every tail write giving `r` or more that counts); else `departure_point`.
fn tail_departure_point(run: &Run, o: usize, m: Tid, d: usize, r: Role) -> Option<osis_perm::Point> {
    let core = &run.lp.peers[o].engine.core;
    let on = core.timelines().on(&m)?;
    let log = super::departures::edge_logs(core, &on, &m).remove(&run.tids[d]);
    let key = log.and_then(|l| osis_keys::Departure::holder(run.tids[d], r).edge(l).newest_needed(r));
    let point = key.and_then(|k| Some(osis_perm::Point { ts: osis_base::Ts::from_u64(k.ts)?, node: k.node, commit: k.commit }));
    point.or_else(|| departure_point(run, o, m, d, r))
}

/// `departure`, at its point in the key order.
fn departure_point(run: &Run, o: usize, t: Tid, d: usize, r: Role) -> Option<osis_perm::Point> {
    let tl = run.lp.peers[o].engine.core.timelines().get(&t)?;
    let h = run.tids[d];
    // the edge value write `w` sets on `d`'s edge into `t`, if it is one
    let on_edge = |w: &osis_perm::WriteId| tl.role_commit(&w.0).and_then(|mc| mc.ops.get(w.1 as usize)).filter(|op| op.target == t && op.holder == osis_base::Holder::Thing(h)).map(|op| op.edge.as_ref());
    let gives = |e: Option<&osis_perm::Edge>| super::key_role(e) >= Some(r);
    let applied = tl.applied_writes().into_iter().filter(|(w, p)| on_edge(w).is_some_and(|e| !gives(e)) && gives(tl.edges_at(Some(*p)).get(&h, &t))).map(|(_, p)| p);
    let dropped = tl.dropped_writes().into_iter().filter(|(w, _)| on_edge(w).is_some_and(gives)).map(|(_, p)| p);
    applied.chain(dropped).max()
}

/// The shapes a run may reach, each with the rate the seeds reach it at (`reach_floor`: per, over
/// seeds) set well under what offset ranges show: a cycle in every emphasis-3 seed and some others,
/// an invalid rotation (a race, drawn by no emphasis) in about 1 run in 10.
/// A shape: its name, whether a run reached it, its rate (per, over seeds).
type Shape = (&'static str, fn(&Reached) -> bool, usize, usize);

const SHAPES: [Shape; 6] = [
    ("forked", |r| r.forked, 1, 8),
    ("departed", |r| r.departed, 1, 4),
    ("forged", |r| r.forged, 1, 8),
    ("cycle", |r| r.cycle, 1, 8),
    ("withheld", |r| r.withheld, 1, 2),
    ("invalid rotation", |r| r.invalid, 1, 40),
];

/// The runs' coverage over any range: each shape at its rate.
fn tally(runs: &[Reached]) {
    for (name, f, per, over) in SHAPES {
        osis_base::testenv::reach_floor(&format!("rotation runs {name}"), runs.iter().map(|r| usize::from(f(r))), per, over);
    }
}

fn replay(s: u64) -> String {
    format!("OSIS_ROTATION_START={s} OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4")
}

// spec/crypto.md §4, spec/permissions.md §2-§3: no departed holder reads later content, every
// holder ends reading everything (module doc). The quick size (a property): seeds 0..8 (every emphasis twice), no
// environment, a covering set (every shape).
#[test]
#[ignore = "property"]
fn rotation_holds_plain_spec_crypto_4() {
    let runs = osis_base::testenv::run_seeds("rotation::tests_property::rotation_holds_plain_spec_crypto_4", &(0..8).collect::<Vec<u64>>(), false, replay, rotation_history);
    // a covering set: its fixed seeds reach every shape
    for (name, f, ..) in SHAPES {
        assert!(runs.iter().any(f), "no run of the covering seeds reached {name}");
    }
}

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_ROTATION_START,
/// OSIS_ROTATION_SEEDS.
#[test]
#[ignore = "property"]
fn rotation_holds_large_spec_crypto_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_ROTATION_START", "OSIS_ROTATION_SEEDS", osis_base::testenv::large(0..1_000));
    tally(&s.run("rotation::tests_property::rotation_holds_large_spec_crypto_4", replay, rotation_history));
}

/// Peer `i` acts (`f`), logged, its new epochs recorded and the states noted, as a generated step
/// is (the log line first: a secret first held after a grant's step counts as handed by it).
fn step(run: &mut Run, i: usize, f: impl FnOnce(&mut Run)) {
    let before = run.before(i);
    f(run);
    run.log.push(format!("peer {i} acts"));
    run.record(i, &before);
    run.note();
}

// The checker's hand-on through a holder actor (spec/crypto.md §4, Boxes; seed 636429853021):
// M admin of G, A (peer 1) admin of M, D (peer 2) admin of G. The owner demotes D to reader,
// rotating G's admin to e1 boxed to M at keyset k, and removes A from M. A, having received
// neither, grants D admin of M, boxing k; D, not yet holding A's removal, opens e1 through the
// box to M at k. The grant settles invalid. A holds k, so opens that box though its node never
// received it: e1 is handed on, not leaked (`Run::grant` counts every box at a handed keyset).
#[test]
fn handed_keyset_opens_boxes_its_author_never_received_spec_crypto_4() {
    let mut lp = synced(N);
    let (a, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&m, &a, &edge(Role::Admin)).unwrap();
    lp.peers[0].engine.grant(&g, &d, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, vec![(g, 0), (m, 0)], Rng(1));
    let admin = |run: &Run| run.lp.peers[0].engine.epochs(&g).and_then(|e| e.role(Role::Admin).newest_held().map(|x| x.0)).unwrap();
    step(&mut run, 0, |run| {
        run.lp.peers[0].clock.advance(1_000);
        run.lp.peers[0].engine.demote(&g, &Demotion { holder: d, new: Some(edge(Role::Read)), retain: None }).unwrap();
    });
    let e1 = admin(&run);
    run.lp.sync(0, 2).unwrap();
    run.note();
    step(&mut run, 0, |run| {
        run.lp.peers[0].clock.advance(2_000);
        run.lp.peers[0].engine.demote(&m, &Demotion { holder: a, new: None, retain: None }).unwrap();
        run.lp.peers[0].engine.ensure_rotated(&g).unwrap();
    });
    step(&mut run, 1, |run| {
        run.lp.peers[1].clock.advance(3_000);
        run.grant(1, 2, m, Role::Admin);
    });
    assert!(!run.ever[1].contains(&(g, Role::Admin, e1)), "A never held e1");
    run.lp.sync(1, 2).unwrap();
    run.note();
    assert!(run.ever[2].contains(&(g, Role::Admin, e1)), "D opens e1 through the box to M at k");
    settle(&mut run, 1, true);
    assert_eq!(run.key_role(0, &m, 2), None, "the grant is invalid");
    check(&mut run, 1, true);
}

/// Peer 0 removes `holder` from `g` `at` ms on: one new `role` epoch of `g` (the removal's
/// rotation alone), which peer `d`, given what peer 0 holds, does not open.
fn removal_rotates_once(run: &mut Run, g: Tid, role: Role, holder: Tid, at: u64, d: usize) {
    let made = |run: &Run| run.made.keys().filter(|k| k.0 == g && k.1 == role).map(|k| k.2).collect::<BTreeSet<Epoch>>();
    let before = made(run);
    step(run, 0, |run| {
        run.lp.peers[0].clock.advance(at);
        run.lp.peers[0].engine.demote(&g, &Demotion { holder, new: None, retain: None }).unwrap();
    });
    let new: Vec<Epoch> = made(run).difference(&before).copied().collect();
    assert_eq!(new.len(), 1, "the removal's rotation alone");
    run.lp.sync(0, d).unwrap();
    run.note();
    assert!(!run.ever[d].contains(&(g, role, new[0])), "peer {d} opens an epoch of G the removal made");
}

// A removal's cascade rotates none of the target's roles the removal rotates (seed
// 750502401262): M (peer 1's) a sync holder of G (peer 0's), D (peer 2) a sync holder of M, A
// (peer 3) an admin of M. A removes D from M; M's admin, unaware, rotates M to k, boxing D. Peer
// 0, not in M, holding everything, removes M from G, whose box to M is stale: one rotation of G's
// sync, leaving M out. A cascade rotation first would seal M at k, then the removal's rotation
// drop that box, D opening the cascade's epoch by it.
#[test]
fn a_removal_boxes_none_it_removes_spec_permissions_3() {
    let mut lp = synced(N);
    let (d, a) = (lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 1);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Sync)).unwrap();
    lp.peers[1].engine.grant(&m, &d, &edge(Role::Sync)).unwrap();
    lp.peers[1].engine.grant(&m, &a, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, vec![(g, 0), (m, 1)], Rng(1));
    step(&mut run, 3, |run| {
        run.lp.peers[3].clock.advance(1_000);
        run.lp.peers[3].engine.demote(&m, &Demotion { holder: d, new: None, retain: None }).unwrap();
    });
    step(&mut run, 1, |run| {
        run.lp.peers[1].clock.advance(2_000);
        // twice: k, the newest keyset of M, is what G seals M at
        assert!(run.rotate(1, m, &[Role::Sync].into(), false));
        assert!(run.rotate(1, m, &[Role::Sync].into(), false));
    });
    for (from, to) in [(1, 2), (3, 0), (1, 0)] {
        run.lp.sync(from, to).unwrap();
    }
    run.note();
    removal_rotates_once(&mut run, g, Role::Sync, m, 3_000, 2);
    settle(&mut run, 1, true);
    check(&mut run, 1, true);
}

// A removal's cascade rotates none of the target's roles the removal rotates by any path, the
// upward one included: H (peer 0's) a read holder of G and of Y (peer 0's), G a read holder of Y,
// H's self-removed member X (peer 2) uncovered, M (peer 3) a read holder of G. Peer 0 removes M
// from G: the cascade rotates H, making G's and Y's boxes to H stale; following that upward,
// directly or through Y's cascade below, must not rotate G's read before the removal (boxing M).
#[test]
fn a_removal_boxes_none_it_removes_through_the_upward_cascade_spec_permissions_3() {
    let mut lp = synced(N);
    let (x, m) = (lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let h = independent_thing(&mut lp, 0);
    let y = independent_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&h, &x, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &h, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&y, &h, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&y, &g, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, vec![(g, 0), (h, 0), (y, 0)], Rng(1));
    step(&mut run, 2, |run| {
        run.lp.peers[2].clock.advance(1_000);
        run.lp.peers[2].engine.demote(&h, &Demotion { holder: x, new: None, retain: None }).unwrap();
    });
    run.lp.sync(2, 0).unwrap();
    run.note();
    removal_rotates_once(&mut run, g, Role::Read, m, 2_000, 3);
    settle(&mut run, 1, true);
    check(&mut run, 1, true);
}

// The same through a finalize the cascade makes first: E (peer 2) a read holder of G past its
// `until`, M (peer 3) a read holder. Peer 0 removes M: the finalize of E goes without a rotation
// of read, which the removal's rotation makes next (naming E's departure), so M opens no epoch of
// G the act made.
#[test]
fn a_removal_boxes_none_it_removes_through_a_finalize_first_spec_permissions_3() {
    let mut lp = synced(N);
    let (e, m) = (lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
    let g = independent_thing(&mut lp, 0);
    lp.sync_all().unwrap();
    lp.peers[0].engine.grant(&g, &e, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    let until = Time(lp.peers[0].engine.core.now().0 + 100);
    lp.peers[0].engine.demote(&g, &Demotion { holder: e, new: Some(ct::Edge { until: Some(until), ..edge(Role::Read) }), retain: None }).unwrap();
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, vec![(g, 0)], Rng(1));
    removal_rotates_once(&mut run, g, Role::Read, m, 2_000, 3);
    assert!(run.lp.peers[0].engine.ensure_rotated(&g).unwrap().0.commits.is_empty(), "it covers E's departure too");
    settle(&mut run, 1, true);
    check(&mut run, 1, true);
}

// A grant concurrent with a rotation entitles its grantee to the epoch (seed 611521595787): M
// (peer 0's) a read holder of G (peer 0's), D (peer 2) a reader of G, W (peer 1) a writer of G
// and a reader of M (so its box to M is no blind one within the limit). Peer 0 removes D from
// G, then grants D read of M; W, holding the removal but not the grant, rotates G's read to e2,
// boxing M, D below e2 in its view. In the settled rosters D holds G through M while e2 is
// current, so it opens e2 through M rightly (`holder_at`), and keeps it once peer 0 removes it
// from M; with `after`, the grant is ordered after e2's rotation commit.
#[test]
fn a_grant_concurrent_with_a_rotation_entitles_its_grantee_spec_crypto_4() {
    for after in [false, true] {
        let mut lp = synced(N);
        let (w, d) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let g = independent_thing(&mut lp, 0);
        let m = independent_thing(&mut lp, 0);
        lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &w, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&m, &w, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &d, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let mut run = Run::new(lp, vec![(g, 0), (m, 0)], Rng(1));
        step(&mut run, 0, |run| {
            run.lp.peers[0].clock.advance(1_000);
            run.lp.peers[0].engine.demote(&g, &Demotion { holder: d, new: None, retain: None }).unwrap();
        });
        run.lp.sync(0, 1).unwrap();
        run.note();
        let made = |run: &Run| run.made.keys().filter(|k| k.0 == g && k.1 == Role::Read).map(|k| k.2).collect::<BTreeSet<Epoch>>();
        let before = made(&run);
        step(&mut run, 0, |run| {
            run.lp.peers[0].clock.advance(2_000);
            run.grant(0, 2, m, Role::Read);
        });
        step(&mut run, 1, |run| {
            run.lp.peers[1].clock.advance(if after { 2_000 } else { 4_000 });
            run.lp.peers[1].engine.rotate_leaving_out(&g, &[Role::Read], &[]).unwrap();
        });
        let e2: Vec<Epoch> = made(&run).difference(&before).copied().collect();
        assert_eq!(e2.len(), 1, "after {after}: W's rotation alone");
        let e2 = e2[0];
        let made_e2 = &run.made[&(g, Role::Read, e2)];
        assert!(made_e2.below.contains(&2) && made_e2.blind.is_empty(), "after {after}: D is below e2 in W's view, M boxed knowingly");
        run.lp.sync_all().unwrap();
        run.note();
        assert!(run.ever[2].contains(&(g, Role::Read, e2)), "after {after}: D opens e2 through M");
        step(&mut run, 0, |run| {
            run.lp.peers[0].clock.advance(3_000);
            run.lp.peers[0].engine.demote(&m, &Demotion { holder: d, new: None, retain: None }).unwrap();
        });
        settle(&mut run, 1, true);
        assert!(!access(&run, 0, 2, g, Role::Read), "after {after}: D has left G");
        check(&mut run, 1, true);
    }
}

// A grant that leaves its grantee reading (spec/crypto.md §4, Boxes; seed 874943289279): M
// (peer 0's) a read holder of G (peer 0's), A (peer 1) admin of M. Peer 0 demotes A to reader of
// M; A, unaware, grants X (peer 2) read of M after it, boxing M's read epoch. The grant applies
// nothing and does not count, and A still reads M: nothing rotates M's read, so X reads M and,
// through G's box to M, G's read epoch peer 0 encrypts under. That is the stated limit, not a
// leak (`left_reading`).
#[test]
fn a_grant_by_a_demoted_admin_leaves_its_grantee_reading_spec_crypto_4() {
    let (mut run, g, m, x) = demoted_granter(false);
    let read = |run: &Run, t: Tid| run.lp.peers[0].engine.epochs(&t).and_then(|e| e.role(Role::Read).newest_held().map(|x| x.0)).unwrap();
    assert_eq!(run.key_role(0, &m, 1), Some(Role::Read), "A still reads M");
    assert!(run.ever[2].contains(&(m, Role::Read, read(&run, m))), "X holds M's read epoch");
    assert!(openable(&mut run.lp, 0, &[g, m], x, run.ever[2].clone()).contains(&(g, Role::Read, read(&run, g))), "X opens G's read epoch through M");
    check(&mut run, 1, true);
}

// The same with A's grant ordered before its demotion, which audits it: the grant counts, so is
// named void, and M's read rotates; X opens no epoch of G peer 0 encrypts under.
#[test]
fn a_grant_audited_by_its_authors_demotion_rotates_spec_crypto_4() {
    let (mut run, g, m, x) = demoted_granter(true);
    let read = |run: &Run, t: Tid| run.lp.peers[0].engine.epochs(&t).and_then(|e| e.role(Role::Read).newest_held().map(|x| x.0)).unwrap();
    assert!(!run.ever[2].contains(&(m, Role::Read, read(&run, m))), "M's read rotated past X");
    assert!(!openable(&mut run.lp, 0, &[g, m], x, run.ever[2].clone()).contains(&(g, Role::Read, read(&run, g))));
    check(&mut run, 1, true);
}

/// `a_grant_by_a_demoted_admin_leaves_its_grantee_reading_spec_crypto_4`'s history, A's grant
/// before its demotion (`first`) or after, settled: the run, G, M and X.
/// Built once per order, a copy each call.
fn demoted_granter(first: bool) -> (Run, Tid, Tid, Tid) {
    LocalPeer::cached_world(&format!("rotation::tests_property::demoted_granter/{first}"), || demoted_granter_built(first), |(run, g, m, x)| (run.copy(), *g, *m, *x))
}

fn demoted_granter_built(first: bool) -> (Run, Tid, Tid, Tid) {
    let mut lp = synced(N);
    let (a, x) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
    let g = independent_thing(&mut lp, 0);
    let m = independent_thing(&mut lp, 0);
    lp.peers[0].engine.grant(&g, &m, &edge(Role::Read)).unwrap();
    lp.peers[0].engine.grant(&m, &a, &edge(Role::Admin)).unwrap();
    lp.sync_all().unwrap();
    let mut run = Run::new(lp, vec![(g, 0), (m, 0)], Rng(1));
    let (demote_at, grant_at) = if first { (2_000, 1_000) } else { (1_000, 2_000) };
    step(&mut run, 0, |run| {
        run.lp.peers[0].clock.advance(demote_at);
        run.lp.peers[0].engine.demote(&m, &Demotion { holder: a, new: Some(edge(Role::Read)), retain: None }).unwrap();
    });
    step(&mut run, 1, |run| {
        run.lp.peers[1].clock.advance(grant_at);
        run.grant(1, 2, m, Role::Read);
    });
    assert!(run.handed[2].keys().any(|k| k.0 == m && k.1 == Role::Read), "the grant boxed X");
    settle(&mut run, 0, true);
    assert_eq!(run.key_role(0, &m, 2), None, "the grant is invalid");
    (run, g, m, x)
}

// The same, then peer 0 removes A from M, re-adding it as a reader of M (`readd`) or not: A's
// departure rotates M's read and, through M, G's, so X opens no epoch of G peer 0 encrypts under;
// the excuse ends with the role's rotation, the author's departure counted even once it reads
// again (else a missing rotation there would read as the limit).
#[test]
fn the_demoted_granters_removal_shuts_its_grantee_out_spec_crypto_4() {
    for readd in [false, true] {
        let (mut run, g, m, x) = demoted_granter(false);
        let a = run.tids[1];
        let read = |run: &Run, t: Tid| run.lp.peers[0].engine.epochs(&t).and_then(|e| e.role(Role::Read).newest_held().map(|x| x.0)).unwrap();
        let k = (m, Role::Read, read(&run, m));
        assert!(left_reading(&run, 0, 2, &k), "X reads M by the void grant");
        step(&mut run, 0, |run| {
            run.lp.peers[0].clock.advance(3_000);
            run.lp.peers[0].engine.demote(&m, &Demotion { holder: a, new: None, retain: None }).unwrap();
            if readd {
                run.lp.peers[0].clock.advance(1_000);
                run.lp.peers[0].engine.grant(&m, &a, &edge(Role::Read)).unwrap();
            }
        });
        settle(&mut run, 1, true);
        assert_eq!(access(&run, 0, 1, m, Role::Read), readd);
        assert!(!left_reading(&run, 0, 2, &k), "readd {readd}: the excuse outlives A's departure");
        assert!(!openable(&mut run.lp, 0, &[g, m], x, run.ever[2].clone()).contains(&(g, Role::Read, read(&run, g))), "readd {readd}");
        check(&mut run, 1, true);
    }
}
