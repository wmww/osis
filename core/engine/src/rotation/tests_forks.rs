#![allow(clippy::unwrap_used, clippy::panic)]
//! The engine's account nodes against core/test/roles-model `forks` (spec/permissions.md
//! §5.4-§5.5): real engines driven through random fork worlds, the model judging the same
//! commits. Peers are the model's parties (A, B, X, T: account P's nodes; R1, R2: readers with
//! accounts of their own; peer 6 stands in for Z, a key actor X makes up). A removes X at tick 1;
//! X, never told, forks from epochs whose keys it holds (plainly, naming another fork, claiming to
//! take a revocation, one it withholds, sealed as itself or as Z), revokes A or B, writes at any
//! epoch it holds; B may be offline and write, rotate and remove T unaware; R2's user switches; the settle delivers everything and the
//! honest nodes act in turn, users on X's side switching as in the model.
//!
//! Every commit an engine makes that the model knows (rotations, D grants, content) becomes an
//! item of a mirror `forks::World` with the receipt ticks the engines saw (one tick's in item
//! order, as the model places them). After each tick, at each observer: which rotations it holds
//! with their chain, which count, its heads, preferred head and warning, and at P's nodes the
//! revocations taken and D's roster, against `forks::judge`; a write the model counts counts in the
//! engine, and outside P where A's removal counts no write X made after it counts but one an honest
//! node of P held before it held the removal (an unaware sibling's word: spec/permissions.md §5.5,
//! Limit). Before each honest node acts, `forks::act` on the mirror says whether it rotates and
//! what the rotation is signed at, supersedes, names and takes; the engine's `signing_due` (or its
//! removal) must agree. Settled, the honest-side nodes share one head and count every honest write,
//! and none rotates in the last round.
//!
//! What the mirror takes from the engines as input: receipts (when each node held each item, in
//! milliseconds, a pending commit once it applied; one millisecond's by commit ID, as
//! `World::commit_ids`), whom an honest rotation boxes (its maker's D roster; checked against the
//! model's roster), and thing lists and listings (the model has none; checked only by the write
//! rules above). The switching variant has P's nodes on X's side switch back in the settle. Not
//! generated: D edits apart from rotations (the model's grants of D: a membership change is a
//! rotation's, which the custody model reads), each target revoked by X once.

use crate::flows::Demotion;
use crate::local_peer::{LocalPeer, Package};
use osis_base::{Ak, CommitId, Tid, Value, WallMs};
use osis_commit::{CommitBlob, FIRST_EPOCH};
use osis_crypto::{AccountEpochKeys, Secret32};
use roles_model::forks::{self, Kind as MK, A, B, N, NEVER, OWN, R1, R2, T, X, Z};
use roles_model::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const SETTLE: u32 = 12;
/// Milliseconds per tick: room for every delivery and action of one, each a millisecond apart.
const TICK_MS: u64 = 10_000;

fn x() -> Ak {
    Ak::new("x:a.0").unwrap()
}

/// Peers 0..7 as the model's parties; P created on A, B, X and T paired, R1 and R2 accounts of
/// their own, Z bare; A makes thing `t`. Everything synced.
fn setup() -> (LocalPeer, (Tid, Tid, Tid)) {
    LocalPeer::cached("rotation::tests_forks::setup", || {
        let mut lp = LocalPeer::new_bare(N, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[A].engine.create_account().unwrap();
        for i in [B, X, T] {
            let node = lp.peers[i].engine.tid();
            for id in lp.peers[i].engine.commit_ids() {
                let pk = lp.peers[i].engine.package(&id).unwrap().unwrap();
                lp.deliver(A, &pk).unwrap();
            }
            let (_, all) = lp.peers[A].engine.pair(&node).unwrap();
            for c in &all {
                let pk = lp.peers[A].engine.package(c).unwrap().unwrap();
                lp.deliver(i, &pk).unwrap();
            }
            lp.peers[i].engine.paired(&a.account).unwrap();
        }
        for i in [R1, R2] {
            lp.peers[i].engine.create_account().unwrap();
        }
        lp.sync_all().unwrap();
        let mut m = crate::Mutation::new();
        let t = lp.peers[A].engine.new_thing(&mut m, a.account);
        m.set(t, &x(), &Value::Str("p".into())).unwrap();
        lp.peers[A].commit(m).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        (lp, (a.account, a.devices, t))
    })
}

/// A commit an engine made beside the mirror's items: to P's nodes only (it is on D alone), or
/// to every observer.
#[derive(Clone)]
struct Side {
    pk: Package,
    d_only: bool,
}

#[derive(Default, Debug, Clone, Copy)]
pub(super) struct Reached {
    forked: bool,
    revoked: bool,
    as_z: bool,
    claims: bool,
    withheld: bool,
    b_unaware: bool,
    b_left: bool,
    merges: bool,
    answers: bool,
    warned: bool,
    child_first: bool,
    switched: bool,
}

struct Run {
    /// The epoch the setup's pairings leave (the mirror's first epoch) and its line.
    base_epoch: CommitId,
    setup_chain: BTreeSet<CommitId>,
    lp: LocalPeer,
    p: Tid,
    d: Tid,
    t: Tid,
    tids: [Tid; N],
    w: forks::World,
    /// Mirror item ID - 1 to the engine's commit ID, and back.
    eid: Vec<CommitId>,
    mid: BTreeMap<CommitId, u32>,
    pk: BTreeMap<u32, Package>,
    /// When each item is to reach each peer, in ticks (`NEVER`: until the settle). The mirror's
    /// receipts are what the engines report (`sync_recv`), in milliseconds.
    sched: BTreeMap<u32, [u32; N]>,
    /// Commits made in the action that made an item, delivered just before it.
    comp: BTreeMap<u32, Vec<Side>>,
    /// Commits honest node k made on receipt (listings): each goes with k's next item to a peer.
    extras: [Vec<Side>; N],
    /// How many of `extras[k]` existed when item i was made.
    extras_at: BTreeMap<u32, usize>,
    sent: [[usize; N]; N],
    seen: BTreeSet<CommitId>,
    /// Keys of epochs X forged (by mirror ID).
    keys: BTreeMap<u32, Arc<AccountEpochKeys>>,
    next_seed: u8,
    tick: u32,
    base: WallMs,
    floor: [u32; N],
    /// Engine nodes of P that left the account (a counting removal of them).
    left: [bool; N],
    revoked: BTreeSet<usize>,
    t_removed: bool,
    log: Vec<String>,
    rng: Rng,
    reached: Reached,
    /// Users of P's nodes on X's side switch to A's removal in the settle, as the model's do.
    p_switch: bool,
    /// The seeds each node of P held at the last compare (custody only grows but for a leave).
    seeds: [BTreeSet<[u8; 32]>; N],
    /// The rotation each node's user chose last (`switch`).
    chosen: [Option<u32>; N],
}

impl Run {
    fn new(seed: u64) -> Run {
        let (lp, (p, d, t)) = setup();
        let tids: [Tid; N] = std::array::from_fn(|i| lp.peers[i].engine.tid());
        let base = WallMs(lp.peers[A].engine.now().0 + 1);
        let seen = (0..N).flat_map(|i| lp.peers[i].engine.commit_ids()).collect();
        let va = lp.peers[A].engine.core.account_view(&p).unwrap();
        let base_epoch = va.preferred();
        let setup_chain = va.line(&base_epoch).unwrap_or_default();
        Run {
            base_epoch,
            setup_chain,
            lp,
            p,
            d,
            t,
            tids,
            w: forks::World::default(),
            eid: Vec::new(),
            mid: BTreeMap::new(),
            pk: BTreeMap::new(),
            sched: BTreeMap::new(),
            comp: BTreeMap::new(),
            extras: Default::default(),
            extras_at: BTreeMap::new(),
            sent: [[0; N]; N],
            seen,
            keys: BTreeMap::new(),
            next_seed: 1,
            tick: 0,
            base,
            floor: [0; N],
            left: [false; N],
            revoked: BTreeSet::new(),
            t_removed: false,
            log: Vec::new(),
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            reached: Reached::default(),
            p_switch: false,
            seeds: Default::default(),
            chosen: [None; N],
        }
    }

    fn e(&self, id: u32) -> CommitId {
        if id == 0 { self.base_epoch } else { self.eid[id as usize - 1] }
    }

    fn m(&self, c: &CommitId) -> u32 {
        // the setup's chain (the first epoch and its pairings' rotations) is the mirror's first epoch
        if *c == FIRST_EPOCH || self.setup_chain.contains(c) {
            return 0;
        }
        *self.mid.get(c).unwrap_or_else(|| self.fail(&format!("commit {c:?} is no mirror item")))
    }

    fn ms(&self, cs: &[CommitId]) -> Vec<u32> {
        let mut v: Vec<u32> = cs.iter().map(|c| self.m(c)).collect();
        v.sort();
        v.dedup();
        v
    }

    fn fail(&self, what: &str) -> ! {
        let mut s = format!("{what}\nlog:\n");
        for l in &self.log {
            s.push_str(&format!("  {l}\n"));
        }
        s.push_str("mirror:\n");
        for i in &self.w.items {
            let recv: Vec<String> = i.recv.iter().map(|r| if *r == NEVER { "-".into() } else { r.to_string() }).collect();
            s.push_str(&format!("  #{} {:?} by {} as {} at e{} t{} recv [{}]{}\n", i.id, i.kind, i.author, i.signer, i.epoch, i.t, recv.join(" "), if self.w.hostile(i.id) { " hostile" } else { "" }));
        }
        for (n, t, c) in &self.w.switches {
            s.push_str(&format!("  switch {n} at {t} to {c}\n"));
        }
        let name = |c: &CommitId| self.mid.get(c).map_or_else(|| format!("{:.6}", format!("{c:?}")), |m| format!("#{m}"));
        let who = |t: &Tid| self.tids.iter().position(|x| x == t).map_or("?".to_string(), |i| i.to_string());
        for v in [A, B, T] {
            let Some(d) = self.lp.peers[v].engine.core.account_view(&self.p).and_then(|w| w.devices.clone()) else { continue };
            let minter: Vec<String> = d.minter.iter().map(|(r, m)| format!("{}:{}", name(r), who(m))).collect();
            let removes: Vec<String> = d.removes.iter().map(|(r, ms)| format!("{}:{:?}", name(r), ms.iter().map(who).collect::<Vec<_>>())).collect();
            let adds: Vec<String> = d.adds.iter().map(|(r, ms)| format!("{}:{:?}", name(r), ms.iter().map(who).collect::<Vec<_>>())).collect();
            s.push_str(&format!("devices at {v}: minter {minter:?} removes {removes:?} adds {adds:?}\n"));
        }
        panic!("{s}");
    }

    /// Milliseconds since the run began: the mirror's time.
    fn now(&self) -> u32 {
        (self.lp.peers[A].engine.now().0 - self.base.0 + 1) as u32
    }

    /// The mirror's receipts are the engines': when each held the item (a pending commit is held
    /// once it applies, as the engine places it), in milliseconds; the author's own at creation.
    fn sync_recv(&mut self) {
        for k in 0..self.w.items.len() {
            let (author, c) = (self.w.items[k].author, self.eid[k]);
            for v in [A, B, X, T, R1, R2] {
                if v == author {
                    continue;
                }
                let r = self.lp.peers[v].engine.core.ix.commits.get(&c).map_or(NEVER, |m| (m.received.0 - self.base.0 + 1) as u32);
                self.w.items[k].recv[v] = r;
            }
        }
    }

    /// `forks::judge` of node v now, receipts synced.
    fn judge(&mut self, v: usize) -> forks::View {
        self.sync_recv();
        forks::judge(&self.w, v, self.now())
    }

    /// Clocks to the start of tick `t`.
    fn goto(&mut self, t: u32) {
        self.tick = t;
        let at = self.base.0 + u64::from(t) * TICK_MS;
        let now = self.lp.peers[A].engine.now().0;
        assert!(now < at, "tick {t} overran its milliseconds");
        self.lp.advance(at - now);
    }

    /// The commits peer k holds that no one held before (made there): every commit but a
    /// rotation, then a rotation.
    fn fresh(&mut self, k: usize) -> Vec<CommitId> {
        let ids = self.lp.peers[k].engine.commit_ids();
        let mut new: Vec<CommitId> = ids.into_iter().filter(|c| self.seen.insert(*c)).collect();
        new.sort_by_key(|c| self.lp.peers[k].engine.header(c).is_some_and(|h| h.rotation.is_some()));
        new
    }

    fn side(&mut self, k: usize, c: &CommitId) -> Side {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let d_only = h.actor == self.d || !h.aspects.is_empty() && h.aspects.iter().all(|a| a.tid == self.d);
        Side { pk: self.lp.peers[k].engine.package(c).unwrap().unwrap(), d_only }
    }

    /// After peer k received something: what it made goes out with its next item (honest nodes
    /// of P), or nowhere.
    fn note_extras(&mut self, k: usize) {
        let new = self.fresh(k);
        if [A, B, T].contains(&k) {
            for c in new {
                let s = self.side(k, &c);
                self.extras[k].push(s);
            }
        }
    }

    /// Adds item `kind` made by `author` (sealed as `signer`) at tick now, engine commit `c`.
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, kind: MK, author: usize, signer: usize, epoch: u32, c: CommitId, pk: Package, boxed: [bool; N]) -> u32 {
        let now = self.now();
        let id = self.w.add_as(kind, author, signer, epoch, now, boxed);
        let mut sched = [NEVER; N];
        sched[author] = self.tick;
        self.sched.insert(id, sched);
        self.w.commit_ids.push(u64::from_be_bytes(c.0[..8].try_into().unwrap()));
        self.eid.push(c);
        self.mid.insert(c, id);
        self.seen.insert(c);
        self.pk.insert(id, pk);
        self.extras_at.insert(id, self.extras[author].len());
        id
    }

    /// Receipts of `ids` at every peer but the author, as the model's `deliver`: a tick 1-5 on or
    /// never (until the settle), never before a peer's floor; D's commits to P's nodes only.
    fn schedule(&mut self, ids: &[u32]) {
        for id in ids {
            let i = &self.w.items[*id as usize - 1];
            let (author, t) = (i.author, self.tick);
            let d = matches!(i.kind, MK::Grant { .. } | MK::Creation { .. });
            let off = if author == B { self.floor[B] } else { 0 };
            for m in 0..N {
                if m == author || m == Z || d && m >= OWN {
                    continue;
                }
                let r = match self.rng.below(6) {
                    0 => NEVER,
                    k => (t + k as u32).max(self.floor[m]).max(off),
                };
                self.sched.get_mut(id).unwrap()[m] = r;
            }
        }
    }

    fn deliver(&mut self, to: usize, pk: &Package, what: &str) {
        self.lp.advance(1);
        if let Err(e) = self.lp.deliver(to, pk) {
            if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local {
                self.fail(&format!("delivering {what} to {to}: {e}"));
            }
            self.log.push(format!("t{} {what} refused at {to}: {e}", self.tick));
        }
    }

    /// Item `id` to peer `to`, after its companions and the extras its author made before it.
    fn send(&mut self, id: u32, to: usize) {
        let author = self.w.items[id as usize - 1].author;
        for s in self.comp.get(&id).cloned().unwrap_or_default() {
            if !s.d_only || to < OWN {
                self.deliver(to, &s.pk, "companion");
            }
        }
        let upto = self.extras_at[&id];
        self.send_extras(author, to, upto);
        let pk = self.pk[&id].clone();
        self.deliver(to, &pk, &format!("#{id}"));
        self.note_extras(to);
    }

    fn send_extras(&mut self, author: usize, to: usize, upto: usize) {
        while self.sent[author][to] < upto.min(self.extras[author].len()) {
            let s = self.extras[author][self.sent[author][to]].clone();
            self.sent[author][to] += 1;
            if !s.d_only || to < OWN {
                self.deliver(to, &s.pk, "extra");
            }
        }
    }

    /// Everything due at this tick, in item order (the model's one-tick order).
    fn arrivals(&mut self) {
        let t = self.tick;
        for id in 1..=self.w.items.len() as u32 {
            for to in 0..N {
                let i = &self.w.items[id as usize - 1];
                if to != Z && self.sched[&id][to] == t && i.author != to {
                    self.child_first(id, to);
                    self.send(id, to);
                }
            }
        }
    }

    /// Counts a rotation arriving before the rotation it is signed at.
    fn child_first(&mut self, id: u32, to: usize) {
        if let MK::Rot { at, .. } = self.w.items[id as usize - 1].kind
            && at != 0
            && self.sched[&at][to] > self.tick
        {
            self.reached.child_first = true;
        }
    }

    fn view(&self, k: usize) -> Arc<crate::flows::account::AccountView> {
        self.lp.peers[k].engine.core.account_view(&self.p).unwrap_or_else(|| self.fail(&format!("no view of P at {k}")))
    }

    /// Node n judges what it holds, as its signing pass at the end of every pass of D's sync IDs
    /// does (`rotations_due`), without rotating.
    fn take_up(&mut self, n: usize) {
        if self.left[n] || !self.lp.peers[n].engine.core.accounts.contains_key(&self.p) {
            return;
        }
        self.lp.peers[n].engine.run(|tx| crate::apply::rejudged(tx, false).map(drop)).unwrap();
        self.note_extras(n);
    }

    /// Whether engine node k holds the seed of mirror rotation r.
    fn has_seed(&self, k: usize, r: u32) -> bool {
        let e = &self.lp.peers[k].engine;
        let (Some(held), Some(v)) = (e.core.accounts.get(&self.p), e.core.account_view(&self.p)) else { return false };
        v.keys_of(&self.e(r), held).is_some()
    }

    /// The keys of epoch `e` X holds: from its engine, or of a rotation it forged.
    fn x_keys(&self, e: u32) -> Option<Arc<AccountEpochKeys>> {
        if let Some(k) = self.keys.get(&e) {
            return Some(k.clone());
        }
        let eng = &self.lp.peers[X].engine;
        let held = eng.core.accounts.get(&self.p)?;
        if e == 0 {
            return held.keys.get(&held.first).cloned();
        }
        eng.core.account_view(&self.p)?.keys_of(&self.e(e), held)
    }

    /// Whom node k's rotation made now boxes: D's roster there, but the node it removes (the
    /// engine's boxing; the roster check holds it to the model's).
    fn boxed_by(&self, k: usize, removes: Option<usize>) -> [bool; N] {
        let roster = self.lp.peers[k].engine.roster(&self.d);
        std::array::from_fn(|m| Some(m) != removes && roster.contains_key(&self.tids[m]))
    }

    /// When node n came to hold rotation r with what it needs (its epoch's rotation, the forks it
    /// names, the rotations it takes, and theirs): the latest receipt among them.
    fn held_at(&self, n: usize, r: u32) -> u32 {
        if r == 0 {
            return 0;
        }
        let i = &self.w.items[r as usize - 1];
        let MK::Rot { at, names, takes, .. } = &i.kind else { return i.recv[n] };
        std::iter::once(at).chain(names).chain(takes).map(|q| self.held_at(n, *q)).fold(i.recv[n], u32::max)
    }

    fn rots(&self) -> Vec<u32> {
        self.w.items.iter().filter(|i| matches!(i.kind, MK::Rot { .. })).map(|i| i.id).collect()
    }

    fn rot_fields(&self, k: usize, c: &CommitId) -> (u32, Vec<u32>, Vec<u32>, Vec<u32>) {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let r = h.rotation.clone().unwrap();
        (self.m(&h.epoch.unwrap()), self.ms(&r.supersedes), self.ms(&r.names), self.ms(&r.takes))
    }

    /// Honest node n acts: the model's `act` on the mirror says what it owes; the engine's
    /// signing pass (or its removal of `removes`) must make the same rotation. Then a write.
    fn act(&mut self, n: usize, removes: Option<usize>, write: bool) -> Option<u32> {
        self.check_left();
        if self.left[n] {
            return None;
        }
        self.take_up(n);
        let t = self.tick;
        self.sync_recv();
        let mut wc = self.w.clone();
        let made = forks::act(&mut wc, n, self.now(), removes, false);
        let model = made.first().map(|id| wc.items[*id as usize - 1].clone()).filter(|i| matches!(i.kind, MK::Rot { .. }));
        self.lp.advance(1);
        let done = match removes {
            Some(y) => {
                let holder = self.tids[y];
                self.lp.peers[n].engine.demote(&self.d, &Demotion { holder, new: None, retain: None })
            }
            None => self.lp.peers[n].engine.signing_due(),
        };
        if let Err(e) = done {
            self.fail(&format!("t{t}: node {n} acting (removes {removes:?}): {e}"));
        }
        let new = self.fresh(n);
        let rot = new.iter().copied().find(|c| self.lp.peers[n].engine.header(c).is_some_and(|h| h.rotation.is_some()));
        self.log.push(format!("t{t} node {n} acts (removes {removes:?}): model {:?}, engine rotates {}", model.as_ref().map(|i| &i.kind), rot.is_some()));
        let item = match (&model, rot) {
            (None, None) => None,
            (Some(mi), Some(c)) => {
                let MK::Rot { at, names, sup, takes, .. } = &mi.kind else { unreachable!() };
                let (eat, mut esup, enames, etakes) = self.rot_fields(n, &c);
                let (mut msup, mut mnames, mut mtakes) = (sup.clone(), names.clone(), takes.clone());
                msup.sort();
                msup.dedup();
                mnames.sort();
                mtakes.sort();
                esup.dedup();
                if (eat, &esup, &enames, &etakes) != (*at, &msup, &mnames, &mtakes) {
                    self.fail(&format!("t{t} node {n}: engine rotation at {eat} sup {esup:?} names {enames:?} takes {etakes:?}; model at {at} sup {msup:?} names {mnames:?} takes {mtakes:?}"));
                }
                if !names.is_empty() {
                    self.reached.merges = true;
                }
                if sup.iter().any(|s| s != at && !names.contains(s)) {
                    self.reached.answers = true;
                }
                let pk = self.lp.peers[n].engine.package(&c).unwrap().unwrap();
                let boxed = self.boxed_by(n, removes);
                let id = self.add(mi.kind.clone(), n, n, *at, c, pk, boxed);
                let comp: Vec<Side> = new.iter().filter(|x| **x != c).map(|x| self.side(n, x)).collect();
                self.comp.insert(id, comp);
                Some(id)
            }
            (m, e) => self.fail(&format!("t{t} node {n}: model rotates {:?}, engine {:?}", m.as_ref().map(|i| &i.kind), e.map(|c| self.rot_fields(n, &c)))),
        };
        if item.is_none() {
            for c in new {
                let s = self.side(n, &c);
                self.extras[n].push(s);
            }
        }
        if let Some(id) = item {
            self.schedule(&[id]);
        }
        if write {
            self.write(n);
        }
        self.check_left();
        item
    }

    /// Node n writes at its open epoch.
    fn write(&mut self, n: usize) -> Option<u32> {
        self.check_left();
        if self.left[n] {
            return None;
        }
        self.lp.advance(1);
        let mut m = crate::Mutation::new();
        m.set(self.t, &x(), &Value::Str(format!("{n} #{}", self.w.items.len()))).unwrap();
        let c = match self.lp.peers[n].commit(m) {
            Ok(Some(c)) => c,
            Ok(None) => self.fail(&format!("t{} node {n} wrote nothing", self.tick)),
            // its open epoch's seed is not held (a head on another side, boxed away from it)
            Err(e) => {
                self.log.push(format!("t{} node {n} cannot write: {e}", self.tick));
                return None;
            }
        };
        let mut new = self.fresh(n);
        new.retain(|x| *x != c);
        let e = self.lp.peers[n].engine.header(&c).unwrap().epoch.unwrap();
        let e = self.m(&e);
        let pk = self.lp.peers[n].engine.package(&c).unwrap().unwrap();
        let id = self.add(MK::Content, n, n, e, c, pk, [false; N]);
        let comp: Vec<Side> = new.iter().map(|x| self.side(n, x)).collect();
        self.comp.insert(id, comp);
        self.schedule(&[id]);
        Some(id)
    }

    fn check_left(&mut self) {
        for k in [A, B, T] {
            if !self.left[k] && !self.lp.peers[k].engine.core.accounts.contains_key(&self.p) {
                self.left[k] = true;
                self.log.push(format!("t{} node {k} left the account", self.tick));
                if k == B {
                    self.reached.b_left = true;
                }
            }
        }
    }

    /// A plain rotation node n makes now (the model's manual ones: an unaware sibling's, or a
    /// pre-removal one), expected signed at, superseding and taking `expect`.
    fn rotate(&mut self, n: usize, expect: Option<(u32, Vec<u32>, Vec<u32>)>) -> u32 {
        self.lp.advance(1);
        let p = self.p;
        let c = self.lp.peers[n].engine.run(|tx| crate::flows::signing::rotate_in(tx, p, &[], &mut crate::flows::Done::default())).unwrap().unwrap();
        let new: Vec<CommitId> = self.fresh(n).into_iter().filter(|x| *x != c).collect();
        let (at, sup, names, takes) = self.rot_fields(n, &c);
        if let Some((eat, esup, etakes)) = &expect
            && (at, &sup, &takes) != (*eat, esup, etakes)
        {
            self.fail(&format!("t{} node {n} rotating plainly: engine at {at} sup {sup:?} takes {takes:?}, model at {eat} sup {esup:?} takes {etakes:?}", self.tick));
        }
        let pk = self.lp.peers[n].engine.package(&c).unwrap().unwrap();
        let boxed = self.boxed_by(n, None);
        let id = self.add(MK::Rot { at, names, sup, removes: None, covers: vec![], takes }, n, n, at, c, pk, boxed);
        let comp: Vec<Side> = new.iter().map(|x| self.side(n, x)).collect();
        self.comp.insert(id, comp);
        self.log.push(format!("t{} node {n} rotates plainly: #{id}", self.tick));
        id
    }

    /// `bytes` with its inner signature sealed as `signer` by epoch keys `k` (its header kept;
    /// `epoch` given: signed at that epoch instead, a new commit ID).
    fn seal(&self, bytes: &[u8], epoch: Option<u32>, k: &AccountEpochKeys, signer: usize) -> (CommitId, Vec<u8>) {
        let mut b = CommitBlob::decode(bytes).unwrap();
        if let Some(e) = epoch {
            b.header.epoch = Some(self.e(e));
        }
        let id = b.header.id();
        let who = &self.lp.peers[signer].engine.core.id;
        let inner = osis_crypto::seal_inner(&k.inner, &id.0, &who.tid(), &who.keys().signing);
        b.sigs = osis_commit::Sigs::signed(&id, &k.signing, Some(inner), b.sigs.merge.clone());
        (id, b.encode())
    }

    /// X's commit `c` (made by its engine at its open epoch, never sent) signed at epoch `e` as
    /// `signer`: a new commit only the mirror's item carries.
    fn x_resign(&mut self, c: &CommitId, e: u32, signer: usize) -> Option<(CommitId, Package)> {
        let k = self.x_keys(e)?;
        let mut pk = self.lp.peers[X].engine.package(c).unwrap()?;
        let (id, bytes) = self.seal(&pk.bytes, Some(e), &k, signer);
        self.seen.insert(id);
        pk.id = id;
        pk.bytes = bytes;
        pk.lists.clear();
        Some((id, pk))
    }

    /// The epochs X holds the keys of (0 the first).
    fn x_held(&self) -> Vec<u32> {
        std::iter::once(0).chain(self.rots().into_iter().filter(|r| !self.w.withheld.contains(r) && self.w.items[*r as usize - 1].recv[X] <= self.now() && self.x_keys(*r).is_some())).collect()
    }

    fn signer(&mut self) -> usize {
        if self.rng.below(2) == 0 || self.w.z_paired() { X } else { Z }
    }

    /// X forks: a revocation by its engine at its open epoch, or a rotation it forges at an epoch
    /// it holds, naming another or not, claiming to take a revocation or not.
    fn x_fork(&mut self) -> Option<u32> {
        let held = self.x_held();
        let e = held[self.rng.below(held.len())];
        let removes = [None, Some(A), Some(B)][self.rng.below(3)].filter(|y| !self.revoked.contains(y));
        let signer = self.signer();
        let t = self.tick;
        // a revocation: the removal sealed in the rotation's devices field (spec/crypto.md §9)
        if let Some(y) = removes {
            self.revoked.insert(y);
        }
        let names: Vec<u32> = if self.rng.below(4) == 0 { held.iter().copied().filter(|x| *x != e && *x != 0).take(1).collect() } else { vec![] };
        let now = self.now();
        let revs: Vec<u32> = self.rots().into_iter().filter(|r| self.w.items[*r as usize - 1].recv[X] <= now && matches!(self.w.items[*r as usize - 1].kind, MK::Rot { removes: Some(_), .. })).chain([self.w.removal]).collect();
        let takes: Vec<u32> = match self.rng.below(6) {
            0 | 1 => {
                self.reached.claims = true;
                vec![revs[self.rng.below(revs.len())]]
            }
            2 => {
                // a revocation of A it keeps to itself for good
                let mut boxed = [false; N];
                boxed[X] = true;
                let fake = CommitId(osis_base::hash::hash(&[&[0xee], &self.w.items.len().to_le_bytes()[..]].concat()));
                let pk = Package { id: fake, bytes: Vec::new(), blobs: Vec::new(), lists: Vec::new() };
                let k = self.add(MK::Rot { at: e, names: vec![], sup: vec![e], removes: Some(A), covers: vec![], takes: vec![] }, X, X, e, fake, pk, boxed);
                self.w.withheld.insert(k);
                self.reached.withheld = true;
                vec![k]
            }
            _ => vec![],
        };
        let at_keys = self.x_keys(e)?;
        let fork_keys: Vec<(u32, Arc<AccountEpochKeys>)> = names.iter().map(|n| Some((*n, self.x_keys(*n)?))).collect::<Option<_>>()?;
        let seed = self.next_seed;
        self.next_seed += 1;
        let next = Arc::new(AccountEpochKeys::from_seed(&Secret32::from_bytes([seed; 32])));
        let mut sup_e: Vec<CommitId> = std::iter::once(e).chain(names.iter().copied()).map(|x| self.e(x)).collect();
        sup_e.sort();
        let mut names_e: Vec<(CommitId, Arc<AccountEpochKeys>)> = fork_keys.iter().map(|(n, k)| (self.e(*n), k.clone())).collect();
        names_e.sort_by_key(|x| x.0);
        let mut takes_e: Vec<CommitId> = takes.iter().map(|x| self.e(*x)).collect();
        takes_e.sort();
        let devices = removes.map(|y| osis_crypto::seal_devices(&at_keys.inner, &next.signing.verifying_key(), &[], &[self.tids[y]])).unwrap_or_default();
        let header = osis_commit::RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: sup_e, names: names_e.iter().map(|x| x.0).collect(), takes: takes_e, revokes: removes.is_some(), devices, list_root: [0; 32], seeds: Vec::new() };
        let rec = self.lp.peers[X].engine.core.created(&self.p).unwrap().clone();
        self.lp.advance(1);
        let ts = osis_base::Ts::make(self.lp.peers[X].engine.now(), 0).unwrap();
        let fks: Vec<&AccountEpochKeys> = names_e.iter().map(|x| &*x.1).collect();
        let bytes = super::tests_account::rotation_at(rec, (self.e(e), &at_keys), &fks, &next, header, ts);
        let (c, bytes) = self.seal(&bytes, None, &at_keys, signer);
        let pk = Package { id: c, bytes, blobs: Vec::new(), lists: Vec::new() };
        let mut boxed = [false; N];
        boxed[X] = true;
        let mut sup = vec![e];
        sup.extend(names.iter().copied());
        let id = self.add(MK::Rot { at: e, names, sup, removes, covers: vec![], takes }, X, signer, e, c, pk, boxed);
        self.keys.insert(id, next);
        self.reached.forked = true;
        self.reached.revoked |= removes.is_some();
        self.reached.as_z |= signer == Z;
        self.log.push(format!("t{t} X forges #{id} at {e} as {signer}, removing {removes:?}"));
        Some(id)
    }

    /// X writes (by its engine), signed at epoch `e`.
    fn x_write(&mut self, e: u32) -> Option<u32> {
        self.lp.advance(1);
        let mut m = crate::Mutation::new();
        m.set(self.t, &x(), &Value::Str(format!("X #{}", self.w.items.len()))).unwrap();
        let c = self.lp.peers[X].commit(m).ok()??;
        self.fresh(X);
        let (id, pk) = self.x_resign(&c, e, X)?;
        let item = self.add(MK::Content, X, X, e, id, pk, [false; N]);
        self.log.push(format!("t{} X writes #{item} at {e}", self.tick));
        Some(item)
    }

    /// At every observer: the engine's judgment against the model's, at tick now.
    fn compare(&mut self) {
        for n in [A, B, T] {
            self.take_up(n);
        }
        self.check_left();
        self.custody();
        self.sync_recv();
        let t = self.tick;
        let now = self.now();
        let rots = self.rots();
        let removal = self.w.removal;
        let mut warned = false;
        for v in [A, B, T, R1, R2] {
            if self.left[v] {
                continue;
            }
            let j = forks::judge(&self.w, v, now);
            let view = self.view(v);
            let at = |what: &str, e: String, m: String| self.fail(&format!("t{t} node {v}: {what}: engine {e}, model {m}"));
            let held: BTreeSet<u32> = rots.iter().copied().filter(|r| !self.w.withheld.contains(r) && view.holds(&self.e(*r))).collect();
            if held != j.chain {
                at("held with chain", format!("{held:?}"), format!("{:?}", j.chain));
            }
            let counting: BTreeSet<u32> = held.iter().copied().filter(|r| view.rotation_counts(&self.e(*r))).collect();
            if counting != j.counting {
                let order: Vec<String> = view.received().iter().map(|c| self.mid.get(c).map_or("?".to_string(), |m| m.to_string())).collect();
                let rec: Vec<String> = view.received().iter().map(|c| format!("{}", self.lp.peers[v].engine.core.ix.commits.get(c).map_or(0, |m| (m.received.0 + 1).saturating_sub(self.base.0)))).collect();
                at("counting", format!("{counting:?} (receipt order {order:?} at {rec:?})"), format!("{:?} taken {:?}", j.counting, j.taken));
            }
            if counting != j.counting {
                at("counting", format!("{counting:?}"), format!("{:?}", j.counting));
            }
            let heads: BTreeSet<u32> = view.heads().iter().map(|h| self.m(h)).collect();
            if heads != j.heads {
                at("heads", format!("{heads:?}"), format!("{:?}", j.heads));
            }
            let pref = self.m(&view.preferred());
            if pref != j.preferred {
                at("preferred", format!("{pref}"), format!("{}", j.preferred));
            }
            let warn = view.doubt().is_some();
            if warn != j.warning {
                at("warning", format!("{warn}"), format!("{}", j.warning));
            }
            warned |= warn;
            if v < OWN {
                // seeds: on the honest side, the engine holds an honest node's counting
                // rotation's seed iff the model boxed it to v (a seed travels by its rotation's
                // word on D, counting only where the rotation does, and a removed node's by its
                // word on D, which is not the model's: only its own inner signatures read it)
                let honest_side = j.counting.contains(&removal) && !j.removed_node(v);
                for &r in j.counting.iter().filter(|r| honest_side && [A, B, T].contains(&self.w.items[**r as usize - 1].author)) {
                    let (e, m) = (self.has_seed(v, r), self.w.items[r as usize - 1].boxed[v]);
                    if e != m {
                        at(&format!("seed of #{r}"), format!("{e}"), format!("{m}"));
                    }
                }
                let taken: Vec<u32> = view.taken().iter().map(|c| self.m(c)).collect();
                if taken != j.taken {
                    at("taken", format!("{taken:?}"), format!("{:?}", j.taken));
                }
                let roster: BTreeSet<usize> = self.lp.peers[v].engine.roster(&self.d).keys().filter_map(|m| self.tids.iter().position(|x| x == m)).collect();
                if roster != j.roster {
                    at("D's roster", format!("{roster:?}"), format!("{:?}", j.roster));
                }
            }
            // writes: what the model counts counts; outside P where the removal counts, no write X
            // made after it counts but one an honest node of P held before the removal
            let excused = |c: u32| {
                let i = &self.w.items[c as usize - 1];
                [A, B, T].iter().any(|n| i.recv[*n] != NEVER && i.recv[*n] < self.held_at(*n, removal))
            };
            for i in self.w.items.iter().filter(|i| matches!(i.kind, MK::Content) && i.recv[v] <= now) {
                let c = self.e(i.id);
                let e = &self.lp.peers[v].engine;
                let Some(meta) = e.core.ix.commits.get(&c) else { continue };
                let counts = e.core.standing(&c, &meta.view) == osis_perm::EpochStanding::Counts;
                if j.valid.contains(&i.id) && !counts {
                    at(&format!("write #{}", i.id), "invalid".into(), "valid".into());
                }
                if v >= OWN && counts && j.counting.contains(&removal) && self.w.hostile(i.id) && !excused(i.id) {
                    let by = self.lp.peers[v].engine.read(|tx| crate::flows::lists::names_of(tx, &c)).unwrap_or_default();
                    let by: Vec<String> = by.iter().map(|(_, s)| {
                        let k = (0..N).find(|k| self.extras[*k].iter().any(|x| x.pk.id == *s));
                        let h = k.and_then(|k| self.lp.peers[k].engine.header(s)).map(|h| (h.epoch.map(|e| self.mid.get(&e).copied().unwrap_or(999)), h.rotation.is_some()));
                        self.mid.get(s).map_or_else(|| format!("extra by {k:?} {h:?}"), |m| format!("#{m}"))
                    }).collect();
                    self.fail(&format!("t{t} node {v}: X's write #{} counts beside its removal (named by {by:?})", i.id));
                }
            }
        }
        self.reached.warned |= warned;
    }

    /// The model's `random_world` played on the engines.
    fn generate(&mut self) {
        self.w.b_switch = [None, Some(0), Some(1), Some(3)][self.rng.below(4)];
        if self.rng.below(3) > 0 {
            self.floor[B] = 3 + self.rng.below(6) as u32;
        }
        self.goto(0);
        if self.rng.below(4) == 0 {
            let id = self.rotate(X, None);
            self.schedule(&[id]);
        }
        if self.rng.below(3) == 0 {
            let id = self.rotate(A, None);
            self.schedule(&[id]);
        }
        self.act(A, None, true);
        self.compare();
        self.goto(1);
        self.arrivals();
        let w = self.rng.below(2) == 0;
        let r = self.act(A, Some(X), w).unwrap_or_else(|| self.fail("A's removal of X made no rotation"));
        self.w.removal = r;
        // X never receives the removal or what A made with it
        let at1: Vec<u32> = self.w.items.iter().filter(|i| i.author == A && self.sched[&i.id][A] == 1).map(|i| i.id).collect();
        for id in at1 {
            self.sched.get_mut(&id).unwrap()[X] = NEVER;
        }
        self.compare();
        let steps = 4 + self.rng.below(6) as u32;
        for t in 2..SETTLE {
            self.goto(t);
            self.arrivals();
            if t - 2 >= steps {
                self.compare();
                continue;
            }
            match self.rng.below(5) {
                0 | 1 => self.x_move(),
                2 => {
                    let w = self.rng.below(2) == 0;
                    self.act(A, None, w);
                }
                _ => self.b_move(),
            }
            if self.rng.below(6) == 0 {
                let j = self.judge(R2);
                if let Some(c) = j.chain.iter().nth(self.rng.below(j.chain.len().max(1))).copied() {
                    self.switch(R2, c);
                }
            }
            self.compare();
        }
    }

    /// Custody is monotone (notes/account-forks-design.md, Properties): the seeds a node of P holds
    /// only grow, but for its own leave. A switch takes: a node whose user chose a held rotation on
    /// a line it is a node of follows it, its preferred head on that rotation's line, and signs
    /// there.
    fn custody(&mut self) {
        for n in [A, B, T] {
            let now: BTreeSet<[u8; 32]> = self.lp.peers[n].engine.held_seeds(&self.p).iter().map(|s| *s.expose()).collect();
            if !self.left[n] && !self.seeds[n].is_subset(&now) {
                self.fail(&format!("t{} node {n}: held seeds shrank {} -> {}", self.tick, self.seeds[n].len(), now.len()));
            }
            self.seeds[n] = now;
            let Some(c) = self.chosen[n] else { continue };
            let e = self.e(c);
            if self.left[n] || !self.view(n).holds(&e) || self.judge(n).removed_node(n) {
                continue;
            }
            let v = self.view(n);
            let pref = v.preferred();
            if pref != e && !v.on_line(&e, &pref) {
                self.fail(&format!("t{} node {n}: chose #{c}, preferred head {:?} is not on its line", self.tick, self.mid.get(&pref)));
            }
            if self.lp.peers[n].engine.core.account_signing(&self.p).ok().flatten().is_none() {
                self.fail(&format!("t{} node {n}: chose #{c}, signs nowhere", self.tick));
            }
        }
    }

    fn switch(&mut self, n: usize, c: u32) {
        let t = self.tick;
        self.lp.advance(1);
        let now = self.now();
        self.w.switches.push((n, now, c));
        let e = self.e(c);
        let _ = self.lp.peers[n].engine.choose_line(self.p, e);
        self.chosen[n] = Some(c);
        self.reached.switched = true;
        self.log.push(format!("t{t} {n} chooses #{c}"));
    }

    fn x_move(&mut self) {
        let held = self.x_held();
        let e = held[self.rng.below(held.len())];
        let made: Vec<u32> = match self.rng.below(6) {
            0..=3 => {
                let f = self.x_fork();
                let w = f.filter(|_| self.rng.below(2) == 0).and_then(|f| self.x_write(f));
                f.into_iter().chain(w).collect()
            }
            _ => self.x_write(e).into_iter().collect(),
        };
        let made: Vec<u32> = made.into_iter().filter(|id| !self.w.withheld.contains(id)).collect();
        self.schedule(&made);
    }

    fn b_move(&mut self) {
        let t = self.tick;
        let removes = (t < self.floor[B] && !self.t_removed && self.rng.below(3) == 0).then_some(T);
        if removes.is_some() {
            self.t_removed = true;
        }
        let r = self.act(B, removes, true);
        if t < self.floor[B] {
            self.reached.b_unaware = true;
        }
        if t < self.floor[B] && r.is_none() && !self.left[B] && self.rng.below(3) == 0 {
            let j = self.judge(B);
            let h = j.preferred;
            let takes = forks::takes_of(&j, h, &[]);
            let id = self.rotate(B, Some((h, vec![h], takes)));
            self.schedule(&[id]);
            self.write(B);
        }
    }

    /// Everything delivered (but what X withholds), then the honest nodes act in turn as in the
    /// model's `settle`; users on X's side switch to A's removal.
    fn settle(&mut self) {
        // (X is no longer watched: it gets nothing more)
        for i in self.w.items.iter().filter(|i| !self.w.withheld.contains(&i.id)) {
            let d = matches!(i.kind, MK::Grant { .. } | MK::Creation { .. });
            let sched = self.sched.get_mut(&i.id).unwrap();
            for (m, r) in sched.iter_mut().enumerate() {
                if m != Z && m != X && m != i.author && !(d && m >= OWN) {
                    *r = (*r).min(SETTLE);
                }
            }
        }
        self.goto(SETTLE);
        self.arrivals();
        self.flush();
        self.compare();
        let mut t = SETTLE;
        for round in 0..forks::ROUNDS {
            for n in [A, B, T] {
                t += 1;
                self.goto(t);
                self.flush();
                let j = self.judge(n);
                let switches = if n == B { self.w.b_switch.is_some_and(|k| round >= k) } else { true };
                if self.p_switch && !self.left[n] && !j.counting.contains(&self.w.removal) && switches {
                    let r = self.w.removal;
                    self.switch(n, r);
                }
                if n != T
                    && let Some(id) = self.act(n, None, false)
                {
                    if round + 1 == forks::ROUNDS {
                        self.fail(&format!("node {n} still rotates in the last settle round (#{id})"));
                    }
                    for m in 0..N {
                        if m != n && m != Z && m != X {
                            self.sched.get_mut(&id).unwrap()[m] = t;
                        }
                    }
                    for m in [A, B, T, R1, R2] {
                        if m != n {
                            self.send(id, m);
                        }
                    }
                }
                self.compare();
            }
        }
        self.flush();
        self.compare();
    }

    /// Every extra the honest nodes made, to every observer, until none is new.
    fn flush(&mut self) {
        loop {
            let before: usize = self.extras.iter().map(|e| e.len()).sum();
            for k in [A, B, T] {
                for to in [A, B, T, R1, R2] {
                    if to != k {
                        let n = self.extras[k].len();
                        self.send_extras(k, to, n);
                        self.note_extras(to);
                    }
                }
            }
            let after: usize = self.extras.iter().map(|e| e.len()).sum();
            if after == before {
                return;
            }
        }
    }

    /// Settled: honest-side nodes (A's removal counting) share one head and count every honest
    /// write (by A, and by B or T while a node on that side).
    fn settled(&mut self) {
        let removal = self.w.removal;
        let mut heads = BTreeSet::new();
        let side = |r: &Run, n: usize| !r.left[n] && r.view(n).rotation_counts(&r.e(removal));
        for v in [A, B, T, R1, R2] {
            if self.left[v] || !side(self, v) {
                continue;
            }
            // a node of P removed in its own view (T where B's removal of it counts) is no node:
            // nothing is promised it (the model's settled check)
            if v < forks::OWN && self.judge(v).removed_node(v) {
                continue;
            }
            let hs = self.view(v).heads();
            if hs.len() != 1 {
                self.fail(&format!("node {v} settled with heads {hs:?}"));
            }
            heads.insert(hs);
            for i in self.w.items.iter().filter(|i| matches!(i.kind, MK::Content) && (i.author == A || [B, T].contains(&i.author) && side(self, i.author))) {
                let c = self.e(i.id);
                let e = &self.lp.peers[v].engine;
                let counts = e.core.ix.commits.get(&c).is_some_and(|m| e.core.standing(&c, &m.view) == osis_perm::EpochStanding::Counts);
                if !counts {
                    let mut why = String::new();
                    for k in [A, B, T] {
                        for x in &self.extras[k] {
                            let held = self.lp.peers[v].engine.core.ix.commits.get(&x.pk.id).map(|m| self.lp.peers[v].engine.core.standing(&x.pk.id, &m.view));
                            let h = self.lp.peers[k].engine.header(&x.pk.id).map(|h| (h.epoch.map(|e| self.mid.get(&e).copied().unwrap_or(999)), h.aspects.iter().map(|a| a.ak.as_str().to_string()).collect::<Vec<_>>()));
                            why.push_str(&format!("  extra by {k}: {h:?} at {v}: {held:?}\n"));
                        }
                    }
                    let at_author = { let e = &self.lp.peers[i.author].engine; e.core.ix.commits.get(&c).map(|m| e.core.standing(&c, &m.view)) };
                    self.fail(&format!("node {v} settled without honest write #{} (at its author: {at_author:?}; at {v}: {:?})\n{why}", i.id, e.core.ix.commits.get(&c).map(|m| e.core.standing(&c, &m.view))));
                }
            }
        }
        if heads.len() > 1 {
            self.fail(&format!("honest-side nodes settled on different heads {heads:?}"));
        }
    }
}

/// One world from `seed`, played and checked; what it reached.
pub(super) fn forks_world(seed: u64) -> Reached {
    play(seed, false)
}

fn play(seed: u64, p_switch: bool) -> Reached {
    let mut r = Run::new(seed);
    r.p_switch = p_switch;
    r.generate();
    r.settle();
    r.settled();
    r.reached
}

fn tally(runs: &[Reached]) {
    let count = |f: fn(&Reached) -> bool| runs.iter().filter(|r| f(r)).count();
    eprintln!(
        "forks: {} worlds; X forged {}, revoked {}, as Z {}, claimed {}, withheld {}; B unaware {}, B left {}; merges {}, answers {}, warned {}, child first {}, switched {}",
        runs.len(),
        count(|r| r.forked),
        count(|r| r.revoked),
        count(|r| r.as_z),
        count(|r| r.claims),
        count(|r| r.withheld),
        count(|r| r.b_unaware),
        count(|r| r.b_left),
        count(|r| r.merges),
        count(|r| r.answers),
        count(|r| r.warned),
        count(|r| r.child_first),
        count(|r| r.switched),
    );
}

fn replay(s: u64) -> String {
    format!("OSIS_FORKS_START={s} OSIS_FORKS_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4")
}

// spec/permissions.md §5.4-§5.5: the account's nodes and readers judge a forked signing chain and
// owe rotations as roles-model `forks` says (module doc). Quick size: seeds 0..6, no environment.
#[test]
fn engine_agrees_with_forks_model_spec_permissions_5_4() {
    tally(&osis_base::testenv::run_seeds("rotation::tests_forks::engine_agrees_with_forks_model_spec_permissions_5_4", &(0..6).collect::<Vec<u64>>(), false, replay, forks_world));
}

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_FORKS_START,
/// OSIS_FORKS_SEEDS.
#[test]
#[ignore = "property"]
fn engine_agrees_with_forks_model_large_spec_permissions_5_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORKS_START", "OSIS_FORKS_SEEDS", osis_base::testenv::large(0..2_000));
    tally(&s.run("rotation::tests_forks::engine_agrees_with_forks_model_large_spec_permissions_5_4", replay, forks_world));
}


/// As the property, with the users of P's nodes left on X's side switching to A's removal in the
/// settle (the model's settle). A switch takes (custody: the honest line's boxes open whatever
/// counts), and a head a switched node made while on X's side, boxing no device X revoked, is
/// re-sealed to them (seed re-seals), so they merge the heads.
#[test]
fn engine_agrees_with_forks_model_switching_back_spec_permissions_5_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_FORKS_START", "OSIS_FORKS_SEEDS", osis_base::testenv::large(0..2_000));
    tally(&s.run("rotation::tests_forks::engine_agrees_with_forks_model_switching_back_spec_permissions_5_4", replay, |seed| play(seed, true)));
}
