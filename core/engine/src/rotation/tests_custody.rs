#![allow(clippy::unwrap_used, clippy::panic)]
//! The engine's account nodes against core/test/roles-model `custody` (spec/permissions.md
//! §5.4-§5.5, spec/crypto.md §9; notes/account-forks-design.md): real engines play the model's
//! custody worlds, the model judging the same commits. Peers are the model's parties: A, B, C,
//! X and T account P's nodes, R1 and R2 readers with accounts of their own (R1 a writer of P's
//! thing t, so t keeps epochs of its own), Z a bare peer whose keys X uses as a key actor it made
//! up. P's plain thing u carries the writes the model makes at P epochs.
//!
//! Every commit an engine makes that the model knows becomes an item of a mirror
//! `custody::World`: plain rotations and merge certificates (their lines read from the engine's
//! headers), seed boxes (a rotation's, a certificate's and every seed a box carries besides the
//! first, a re-seal's), t's rotations and writes. The mirror's receipts are the engines'. After
//! every tick, at every observer: rotations held with their chain, merges held, the epochs
//! counting, heads, preferred head and warning, and at P's nodes the revocations taken, D's
//! roster and the seeds held (and what they derive), against `custody::judge`; a write the model
//! counts counts in the engine (the engine counts more: its thing lists and listings name what
//! the mirror leaves out). Before an honest node acts, `custody::act` on a copy of the mirror says
//! what it owes: the engine's plain rotation (signed at, removes, takes, answers, boxed) and
//! certificate (the line it joins, boxed) must be the model's, a re-seal the model makes the
//! engine makes, t is re-keyed iff the model re-keys it, writes go at the model's head.
//!
//! X holds every header and every key boxed to X or Z (its engine is never sent anything: the
//! harness opens the boxes), forks from any epoch whose seed it holds (removing A, B or C, adding
//! Z or itself, signed as X or Z, taking a revocation or one it withholds, answering), writes,
//! certifies merges of epochs it holds and re-seals its seeds to honest nodes, as the model's
//! `x_step` (random worlds). Settled, at every node on the honest side: one head, the same, whose
//! seed X lacks; every honest write counts (on t too, at P's nodes and R1); X's do not; no honest
//! node rotates in the last round.
//!
//! Not mirrored: listings and thing lists (the engine's names; checked by the write rules), X's
//! writes on t.

use crate::local_peer::{LocalPeer, Package};
use osis_base::{Ak, CommitId, Role, Tid, Value, WallMs};
use osis_commit::{CommitBlob, FIRST_EPOCH, SeedBox};
use osis_crypto::{AccountEpochKeys, Secret32};
use roles_model::Rng;
use roles_model::custody::{self as cm, A, B, C, Kind as MK, Line, N, NEVER, OWN, R1, R2, T, X, Z};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Milliseconds per tick: room for every delivery and action of one, each a millisecond apart.
const TICK_MS: u64 = 10_000;

fn x() -> Ak {
    Ak::new("x:a.0").unwrap()
}

/// The setup's actors: account P, its devices actor D, thing t (R1 writes it), plain thing u.
#[derive(Clone, Copy)]
struct Ids {
    p: Tid,
    d: Tid,
    t: Tid,
    u: Tid,
}

/// Peers 0..8 as the model's parties: P created on A with B, C, X and T paired; R1 and R2
/// accounts of their own; Z bare. A makes thing u and thing t, and grants R1 write on t.
fn setup() -> (LocalPeer, Ids) {
    LocalPeer::cached("rotation::tests_custody::setup", || {
        let mut lp = LocalPeer::new_bare(N, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[A].engine.create_account().unwrap();
        for i in [B, C, X, T] {
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
        let u = lp.peers[A].engine.new_thing(&mut m, a.account);
        m.set(u, &x(), &Value::Str("u".into())).unwrap();
        let t = lp.peers[A].engine.new_thing(&mut m, a.account);
        m.set(t, &x(), &Value::Str("t".into())).unwrap();
        lp.peers[A].commit(m).unwrap();
        let o = lp.peers[R1].engine.me();
        lp.peers[A].engine.grant(&t, &o, &super::tests::edge(Role::Write)).unwrap();
        lp.sync_all().unwrap();
        lp.advance(1000);
        (lp, Ids { p: a.account, d: a.devices, t, u })
    })
}

/// The epoch answer `q` names: a plain rotation's line, a certificate's merge.
fn answered(w: &cm::World, q: u32) -> Line {
    if matches!(w.item(q).kind, MK::Cert { .. }) { w.mints(q) } else { w.line(q) }
}

/// A commit an engine made beside the mirror's items, and whom it reaches.
#[derive(Clone)]
struct Side {
    pk: Package,
    reach: [bool; N],
}

#[derive(Default, Debug, Clone, Copy)]
pub(super) struct Reached {
    lockstep: bool,
    x_side: bool,
    own_removal: bool,
    switched: bool,
    certs: bool,
    twin_certs: bool,
    x_certs: bool,
    x_reseals: bool,
    t_rekeyed: bool,
    cycle: bool,
    withheld: bool,
    as_z: bool,
    left: bool,
    warned: bool,
}

/// What the model's `act` made, read off the mirror copy.
#[derive(Debug, Default)]
struct Policy {
    /// Signed at, removes, takes, answers (each a line: a merge's for a certificate), boxed.
    plain: Option<(Line, BTreeSet<usize>, BTreeSet<u32>, BTreeSet<Line>, BTreeSet<usize>)>,
    cert: Option<(Line, BTreeSet<usize>)>,
    reseals: BTreeSet<(Line, usize)>,
    trot: bool,
    writes: Vec<(Line, bool)>,
}

struct Run {
    ids: Ids,
    lp: LocalPeer,
    tids: [Tid; N],
    /// The setup's chain (the mirror's first epoch) and its preferred head.
    base_epoch: CommitId,
    setup_chain: BTreeSet<CommitId>,
    w: cm::World,
    /// Per mirror item: its engine commit (a re-seal's or newcomer box's extra seeds are items of
    /// the commit carrying them), and its package when it is the commit's first item.
    eid: Vec<CommitId>,
    mid: BTreeMap<CommitId, u32>,
    pk: BTreeMap<u32, Package>,
    reach: BTreeMap<u32, [bool; N]>,
    /// Merge epochs by ID and by line (the first certificate's).
    merge_line: BTreeMap<CommitId, Line>,
    line_merge: BTreeMap<Line, CommitId>,
    /// Epoch lines by signing key (the setup's: the first epoch).
    key_line: BTreeMap<[u8; 32], Line>,
    /// Signing keys by engine epoch.
    epoch_key: BTreeMap<CommitId, [u8; 32]>,
    /// When each item reaches each peer, in ticks (`NEVER`: not before the settle).
    sched: BTreeMap<u32, [u32; N]>,
    /// Commits made with an item, delivered just before it.
    comp: BTreeMap<u32, Vec<Side>>,
    /// Commits peer k made on receipt: each goes with k's next item to a peer.
    extras: [Vec<Side>; N],
    extras_at: BTreeMap<u32, usize>,
    sent: [[usize; N]; N],
    seen: BTreeSet<CommitId>,
    /// Every seed X holds (boxed to X or Z, or forged), by signing key.
    xseeds: BTreeMap<[u8; 32], Secret32>,
    /// X's receipts, in milliseconds.
    xrecv: BTreeMap<u32, u32>,
    tick: u32,
    base: WallMs,
    floor: [u32; N],
    left: [bool; N],
    log: Vec<String>,
    rng: Rng,
    reached: Reached,
    /// What each node held at the last compare: seeds (lines), t's read epochs.
    seeds: [BTreeSet<Line>; N],
    tkeys: [BTreeSet<osis_crypto::Epoch>; N],
    /// Taken revocations (P) or followed rotations (outside) at the last compare.
    taken: [Vec<u32>; N],
    switched_at: [bool; N],
}

impl Run {
    fn new(seed: u64) -> Run {
        let (lp, ids) = setup();
        let tids: [Tid; N] = std::array::from_fn(|i| lp.peers[i].engine.tid());
        let base = WallMs(lp.peers[A].engine.now().0 + 1);
        let seen = (0..N).flat_map(|i| lp.peers[i].engine.commit_ids()).collect();
        let va = lp.peers[A].engine.core.account_view(&ids.p).unwrap();
        let base_epoch = va.preferred();
        let setup_chain = va.line(&base_epoch).unwrap_or_default();
        let key_line = setup_chain.iter().chain([&FIRST_EPOCH]).filter_map(|e| va.signing_key(e)).map(|k| (k.to_bytes(), Line::new())).collect();
        let epoch_key = [(base_epoch, va.signing_key(&base_epoch).unwrap().to_bytes())].into();
        let mut xseeds = BTreeMap::new();
        for s in lp.peers[X].engine.held_seeds(&ids.p) {
            xseeds.insert(AccountEpochKeys::from_seed(&s).signing.verifying_key().to_bytes(), s);
        }
        Run {
            ids,
            lp,
            tids,
            base_epoch,
            setup_chain,
            w: cm::World::default(),
            eid: Vec::new(),
            mid: BTreeMap::new(),
            pk: BTreeMap::new(),
            reach: BTreeMap::new(),
            merge_line: BTreeMap::new(),
            line_merge: BTreeMap::new(),
            key_line,
            epoch_key,
            sched: BTreeMap::new(),
            comp: BTreeMap::new(),
            extras: Default::default(),
            extras_at: BTreeMap::new(),
            sent: [[0; N]; N],
            seen,
            xseeds,
            xrecv: BTreeMap::new(),
            tick: 0,
            base,
            floor: [0; N],
            left: [false; N],
            log: Vec::new(),
            rng: Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
            reached: Reached::default(),
            seeds: Default::default(),
            tkeys: Default::default(),
            taken: Default::default(),
            switched_at: [false; N],
        }
    }

    fn fail(&self, what: &str) -> ! {
        let mut s = format!("{what}\nlog:\n");
        for l in &self.log {
            s.push_str(&format!("  {l}\n"));
        }
        s.push_str(&format!("mirror ({:?}, b_switch {:?}, removal #{}, withheld {:?}):\n", self.w.sched, self.w.b_switch, self.w.removal, self.w.withheld));
        for i in &self.w.items {
            let recv: Vec<String> = i.recv.iter().map(|r| if *r == NEVER { "-".into() } else { r.to_string() }).collect();
            let bx: Vec<&str> = (0..N).filter(|m| i.boxed[*m]).map(|m| cm::NAMES[m]).collect();
            s.push_str(&format!("  #{} {:?} by {} as {} at {:?}{} t{} recv [{}] boxed {bx:?}{}\n", i.id, i.kind, cm::NAMES[i.author], cm::NAMES[i.signer], i.epoch, i.on_t.map(|t| format!(" on t@{t}")).unwrap_or_default(), i.t, recv.join(" "), if self.w.hostile(i.id) { " hostile" } else { "" }));
        }
        for (n, t, c) in &self.w.switches {
            s.push_str(&format!("  switch {} at {t} to #{c}\n", cm::NAMES[*n]));
        }
        panic!("{s}");
    }

    /// Logs `l` (printed at once under `CUSTODY_TRACE`, for a panic inside an engine).
    fn note(&mut self, l: String) {
        if std::env::var_os("CUSTODY_TRACE").is_some() {
            eprintln!("{l}");
        }
        self.log.push(l);
    }

    /// Milliseconds since the run began: the mirror's time.
    fn now(&self) -> u32 {
        (self.lp.peers[A].engine.now().0 - self.base.0 + 1) as u32
    }

    fn goto(&mut self, t: u32) {
        self.tick = t;
        let at = self.base.0 + u64::from(t) * TICK_MS;
        let now = self.lp.peers[A].engine.now().0;
        assert!(now < at, "tick {t} overran its milliseconds");
        self.lp.advance(at - now);
    }

    // ---- epochs: engine IDs and mirror lines

    fn m(&self, c: &CommitId) -> u32 {
        *self.mid.get(c).unwrap_or_else(|| self.fail(&format!("commit {c:?} is no mirror item")))
    }

    /// The mirror line of engine epoch `e` (a plain rotation's, a merge's, the setup's).
    fn line_of(&self, e: &CommitId) -> Line {
        if *e == FIRST_EPOCH || self.setup_chain.contains(e) {
            return Line::new();
        }
        if let Some(l) = self.merge_line.get(e) {
            return l.clone();
        }
        self.w.line(self.m(e))
    }

    /// The engine epoch of mirror line `l`, when one is held anywhere.
    fn epoch_of(&self, l: &Line) -> Option<CommitId> {
        if l.is_empty() {
            return Some(self.base_epoch);
        }
        let tips = self.w.tips(l);
        if tips.len() == 1 {
            return Some(self.eid[tips[0] as usize - 1]);
        }
        self.line_merge.get(l).copied()
    }

    fn party(&self, t: &Tid) -> Option<usize> {
        self.tids.iter().position(|x| x == t)
    }

    // ---- the mirror

    /// Item `kind` by `author` (sealed as `signer`) at epoch `epoch`, made now, engine commit
    /// `c` (`pk`: its package when the commit is delivered as this item).
    #[allow(clippy::too_many_arguments)]
    fn add(&mut self, kind: MK, author: usize, signer: usize, epoch: Line, on_t: Option<u32>, c: CommitId, pk: Option<Package>, boxed: [bool; N], reach: [bool; N]) -> u32 {
        let now = self.now();
        let id = self.w.add(kind, author, signer, epoch, on_t, now, boxed);
        // rotations held at once are placed by commit ID
        self.w.tie.push(u64::from_be_bytes(c.0[..8].try_into().unwrap()));
        let mut sched = [NEVER; N];
        sched[author] = self.tick;
        self.sched.insert(id, sched);
        self.eid.push(c);
        self.mid.entry(c).or_insert(id);
        self.seen.insert(c);
        if let Some(pk) = pk {
            self.pk.insert(id, pk);
        }
        self.reach.insert(id, reach);
        self.extras_at.insert(id, self.extras[author].len());
        if author == X {
            self.xrecv.insert(id, now);
        }
        if std::env::var_os("CUSTODY_TRACE").is_some() {
            let i = self.w.item(id);
            eprintln!("  #{id} {:.12} {:?} by {} as {} at {:?} on {:?} boxed {:?}", format!("{c:?}"), i.kind, cm::NAMES[author], cm::NAMES[i.signer], i.epoch, i.on_t, (0..N).filter(|m| i.boxed[*m]).map(|m| cm::NAMES[m]).collect::<Vec<_>>());
        }
        id
    }

    /// Who commit `c` (made at peer k) reaches: P's nodes only (on D alone), P's nodes and R1
    /// (on thing t), or every observer; never Z.
    fn reach_of(&self, k: usize, c: &CommitId) -> [bool; N] {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let tids: BTreeSet<Tid> = h.aspects.iter().map(|a| a.tid).collect();
        let d_only = !tids.is_empty() && tids.iter().all(|t| *t == self.ids.d);
        let on_t = tids.contains(&self.ids.t);
        std::array::from_fn(|m| m != Z && (m < OWN || !d_only && (!on_t || m == R1)))
    }

    fn side(&mut self, k: usize, c: &CommitId) -> Side {
        let reach = self.reach_of(k, c);
        Side { pk: self.lp.peers[k].engine.package(c).unwrap().unwrap(), reach }
    }

    /// The commits peer k holds that no one held before (made there).
    fn fresh(&mut self, k: usize) -> Vec<CommitId> {
        let ids = self.lp.peers[k].engine.commit_ids();
        ids.into_iter().filter(|c| self.seen.insert(*c)).collect()
    }

    /// After peer k received something: what it made goes out with its next item.
    fn note_extras(&mut self, k: usize) {
        if k == X || k == Z {
            return;
        }
        for c in self.fresh(k) {
            let s = self.side(k, &c);
            self.extras[k].push(s);
        }
    }

    /// The mirror's receipts are the engines' (a pending commit once it applies), X's when its
    /// schedule reached it.
    fn sync_recv(&mut self) {
        for k in 0..self.w.items.len() {
            let (author, c) = (self.w.items[k].author, self.eid[k]);
            for v in [A, B, C, T, R1, R2] {
                if v == author {
                    continue;
                }
                let r = self.lp.peers[v].engine.core.ix.commits.get(&c).map_or(NEVER, |m| (m.received.0 - self.base.0 + 1) as u32);
                self.w.items[k].recv[v] = r;
            }
            if author != X {
                self.w.items[k].recv[X] = self.xrecv.get(&(k as u32 + 1)).copied().unwrap_or(NEVER);
            }
        }
    }

    fn judge(&mut self, v: usize) -> cm::View {
        self.sync_recv();
        cm::judge(&self.w, v, self.now())
    }

    // ---- delivery

    /// Receipts of `ids` as the model's `deliver`: honest items in lockstep next tick, else a
    /// tick 1-5 on or not before the settle; X's to everyone next tick, to B, C and R1 only, or
    /// to no one before the settle. Never before a peer's floor or its offline author's.
    fn schedule(&mut self, ids: &[u32]) {
        let pattern = self.rng.below(3);
        for id in ids {
            let (author, t) = (self.w.item(*id).author, self.tick);
            if self.w.withheld.contains(id) {
                continue;
            }
            for m in 0..N {
                if m == author || m == Z || !self.reach[id][m] {
                    continue;
                }
                let at = if author == X {
                    match pattern {
                        0 => t + 1,
                        1 if m == B || m == C || m == R1 => t + 1,
                        _ => NEVER,
                    }
                } else if self.w.sched == cm::Sched::Lockstep {
                    t + 1
                } else {
                    match self.rng.below(6) {
                        0 => NEVER,
                        k => t + k as u32,
                    }
                };
                self.sched.get_mut(id).unwrap()[m] = if at == NEVER { NEVER } else { at.max(self.floor[m]).max(self.floor[author]) };
            }
        }
    }

    fn deliver(&mut self, to: usize, pk: &Package, what: &str) {
        self.lp.advance(1);
        match self.lp.deliver(to, pk) {
            Err(e) => {
                if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local {
                    self.fail(&format!("delivering {what} to {to}: {e}"));
                }
                self.note(format!("t{} {what} refused at {}: {e}", self.tick, cm::NAMES[to]));
            }
            Ok(crate::apply::Ingested::Pending(_, why)) => self.note(format!("t{} {what} pending at {}: {why:?}", self.tick, cm::NAMES[to])),
            Ok(_) => {}
        }
        if std::env::var_os("CUSTODY_PROBE").is_some() {
            eprintln!("t{} probe {what} ({:.12}) at {}", self.tick, format!("{:?}", pk.id), cm::NAMES[to]);
            if let Some(v) = self.lp.peers[to].engine.core.account_view(&self.ids.p) {
                let e = &self.lp.peers[to].engine;
                let st: Vec<String> = self.w.items.iter().filter(|i| matches!(i.kind, MK::TRot | MK::Plain { .. } | MK::Cert { .. })).map(|i| {
                    let c = self.eid[i.id as usize - 1];
                    let s = e.core.ix.commits.get(&c).map(|m| format!("{:?}", e.core.standing(&c, &m.view)).chars().take(6).collect::<String>());
                    format!("#{}:{}:{:?}", i.id, v.rotation_counts(&c), s)
                }).collect();
                eprintln!("   heads {:?} taken {:?} {st:?}", v.heads().iter().map(|h| self.line_of(h)).collect::<Vec<_>>(), v.taken().iter().map(|c| self.mid.get(c)).collect::<Vec<_>>());
                let names: Vec<String> = e.core.account_keys_by_name(&self.ids.p).keys().map(|n| format!("{n:?}").chars().take(40).collect()).collect();
                eprintln!("   names {names:?}");
            }
            self.lp.peers[to].engine.check_index();
        }
    }

    /// Item `id` to peer `to`, after its companions and the extras its author made before it;
    /// to X: its receipt noted, and every box to X or Z in it opened.
    fn send(&mut self, id: u32, to: usize) {
        if to == X {
            if !self.xrecv.contains_key(&id) {
                self.lp.advance(1);
                let now = self.now();
                self.xrecv.insert(id, now);
                self.x_open(id);
            }
            return;
        }
        let Some(pk) = self.pk.get(&id).cloned() else { return };
        let author = self.w.item(id).author;
        for s in self.comp.get(&id).cloned().unwrap_or_default() {
            if s.reach[to] {
                self.deliver(to, &s.pk, "companion");
            }
        }
        let upto = self.extras_at[&id];
        self.send_extras(author, to, upto);
        if self.lp.peers[to].engine.core.ix.commits.contains_key(&pk.id) {
            return;
        }
        self.deliver(to, &pk, &format!("#{id}"));
        self.note_extras(to);
    }

    fn send_extras(&mut self, author: usize, to: usize, upto: usize) {
        while self.sent[author][to] < upto.min(self.extras[author].len()) {
            let s = self.extras[author][self.sent[author][to]].clone();
            self.sent[author][to] += 1;
            if s.reach[to] && to != X {
                self.deliver(to, &s.pk, "extra");
            }
        }
    }

    /// Everything due at this tick, in item order.
    fn arrivals(&mut self) {
        let t = self.tick;
        for id in 1..=self.w.items.len() as u32 {
            for to in 0..N {
                if to != Z && self.sched[&id][to] == t && self.w.item(id).author != to {
                    self.send(id, to);
                }
            }
        }
    }

    /// Every extra the honest nodes made, to every observer it reaches, until none is new.
    fn flush(&mut self) {
        loop {
            let before: usize = self.extras.iter().map(|e| e.len()).sum();
            for k in [A, B, C, T, R1, R2] {
                for to in [A, B, C, T, R1, R2] {
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

    // ---- X's keys

    /// Opens every seed box in item `id`'s commit addressed to X or Z.
    fn x_open(&mut self, id: u32) {
        let c = self.eid[id as usize - 1];
        let Some(pk) = self.pk.get(&self.m(&c)).cloned() else { return };
        let Ok(b) = CommitBlob::decode(&pk.bytes) else { return };
        let Some((key, boxes)) = crate::flows::custody::seed_boxes_of(&b.header) else { return };
        let (key, boxes) = (*key, boxes.to_vec());
        for k in [X, Z] {
            let kem = self.lp.peers[k].engine.core.id.keys().kem.clone();
            for bx in &boxes {
                for s in osis_crypto::open_seeds(&kem, &self.ids.p, &key, &bx.sealed).unwrap_or_default() {
                    self.xseeds.insert(AccountEpochKeys::from_seed(&s).signing.verifying_key().to_bytes(), s);
                }
            }
        }
    }

    /// The seed of line `l` X holds: boxed, or a merge's derived from every tip's.
    fn x_seed(&self, l: &Line) -> Option<Secret32> {
        let key = self.epoch_of(l).and_then(|e| self.epoch_key.get(&e).copied());
        if let Some(s) = key.and_then(|k| self.xseeds.get(&k)) {
            return Some(s.clone());
        }
        if l.is_empty() || self.w.single(l) {
            return None;
        }
        let mut tips = self.w.tips(l);
        tips.sort_by_key(|t| self.eid[*t as usize - 1]);
        let seeds: Vec<Secret32> = tips.iter().map(|t| self.x_seed(&self.w.line(*t))).collect::<Option<_>>()?;
        Some(osis_crypto::merge_seed(&seeds.iter().collect::<Vec<_>>()))
    }

    // ---- honest nodes

    fn view(&self, k: usize) -> Arc<crate::flows::account::AccountView> {
        self.lp.peers[k].engine.core.account_view(&self.ids.p).unwrap_or_else(|| self.fail(&format!("no view of P at {}", cm::NAMES[k])))
    }

    fn check_left(&mut self) {
        for k in [A, B, C, T] {
            if !self.left[k] && !self.lp.peers[k].engine.core.accounts.contains_key(&self.ids.p) {
                self.left[k] = true;
                self.reached.left = true;
                self.note(format!("t{} {} left the account", self.tick, cm::NAMES[k]));
                // leaving is a node's own removal: no held line keeps it a node
                let j = self.judge(k);
                if !j.out(k) {
                    self.fail(&format!("t{}: {} left the account while on its roster in the model ({:?})", self.tick, cm::NAMES[k], j.roster));
                }
            }
        }
    }

    /// Node n judges what it holds, as its signing pass does.
    fn take_up(&mut self, n: usize) {
        if self.left[n] {
            return;
        }
        self.lp.peers[n].engine.run(|tx| crate::apply::rejudged(tx, false).map(drop)).unwrap();
        self.note_extras(n);
    }

    /// The keys node k (honest, holding P) holds of engine epoch `e`.
    fn keys_at(&self, k: usize, e: &CommitId) -> Option<Arc<AccountEpochKeys>> {
        let eng = &self.lp.peers[k].engine;
        let held = eng.core.accounts.get(&self.ids.p)?;
        eng.core.account_view(&self.ids.p)?.keys_of(e, held)
    }

    /// The parties boxed `seed` by `boxes` (their tags).
    fn boxed_by(&self, seed: &Secret32, boxes: &[SeedBox]) -> [bool; N] {
        std::array::from_fn(|m| boxes.iter().any(|b| b.tag == osis_crypto::seed_tag(seed, &self.tids[m])))
    }

    /// The lines of the seeds node k holds (setup's: the first epoch).
    fn held_lines(&self, k: usize) -> BTreeSet<Line> {
        self.lp.peers[k].engine.held_seeds(&self.ids.p).iter().filter_map(|s| self.key_line.get(&AccountEpochKeys::from_seed(s).signing.verifying_key().to_bytes()).cloned()).collect()
    }

    /// The model's act of node n on a copy of the mirror.
    fn policy(&mut self, n: usize, removes: Option<usize>, write: bool) -> Policy {
        self.sync_recv();
        let mut wc = self.w.clone();
        let before = wc.items.len();
        let made = cm::act(&mut wc, n, self.now(), removes, write);
        let mut p = Policy::default();
        for id in made {
            let i = wc.item(id).clone();
            let bx: BTreeSet<usize> = (0..N).filter(|m| i.boxed[*m] && *m != n).collect();
            match &i.kind {
                MK::Plain { at, removes, takes, answers, .. } => p.plain = Some((at.clone(), removes.iter().copied().collect(), takes.iter().copied().collect(), answers.iter().map(|q| answered(&wc, *q)).collect(), bx)),
                MK::Cert { .. } => p.cert = Some((wc.mints(id), bx)),
                MK::Reseal { e } => {
                    for d in bx {
                        p.reseals.insert((e.clone(), d));
                    }
                }
                MK::TRot => p.trot = true,
                MK::Content => p.writes.push((i.epoch.clone(), i.on_t.is_some())),
                MK::Listing { .. } => {}
            }
        }
        // writes on t name the t epoch the model encrypts under
        let _ = before;
        p
    }

    /// The model's t epoch node n writes on t under, now.
    fn t_epoch(&mut self, n: usize) -> Option<u32> {
        let j = self.judge(n);
        cm::t_epoch(&self.w, &j, n)
    }

    /// Honest node n acts: removes `removes` (a plain rotation), then what it owes at the end of a
    /// pass (`signing_due`, then t's re-key), then writes on u and t. Each must be the model's.
    fn act(&mut self, n: usize, removes: Option<usize>, write: bool) -> Vec<u32> {
        self.check_left();
        if self.left[n] {
            return Vec::new();
        }
        self.take_up(n);
        let t = self.tick;
        let model = self.policy(n, removes, write);
        if std::env::var_os("CUSTODY_TRACE").is_some() {
            let j = self.judge(n);
            eprintln!("t{t} {} to act: model {model:?}; taken {:?} heads {:?} pref {:?} roster {:?}", cm::NAMES[n], j.taken, j.heads, j.preferred, j.roster);
        }
        let te = self.t_epoch(n);
        self.lp.advance(1);
        if let Some(y) = removes {
            let node = self.tids[y];
            if let Err(e) = self.lp.peers[n].engine.remove_device(&node) {
                self.fail(&format!("t{t}: {} removing {}: {e}", cm::NAMES[n], cm::NAMES[y]));
            }
        }
        if let Err(e) = self.lp.peers[n].engine.signing_due() {
            self.fail(&format!("t{t}: {} signing: {e}", cm::NAMES[n]));
        }
        let t_id = self.ids.t;
        if self.lp.peers[n].engine.core.ix.secrets.contains_key(&t_id)
            && let Err(e) = self.lp.peers[n].engine.reseal_after_pass(&t_id)
        {
            self.fail(&format!("t{t}: {} re-keying t: {e}", cm::NAMES[n]));
        }
        let new = self.fresh(n);
        let mut made = Vec::new();
        let mut rest = Vec::new();
        let (mut plain, mut cert, mut trot) = (None, None, false);
        let mut reseals: BTreeSet<(Line, usize)> = BTreeSet::new();
        for c in new {
            let h = self.lp.peers[n].engine.header(&c).unwrap();
            if h.author == self.ids.p && let Some(r) = &h.rotation {
                let id = if r.is_merge() { self.add_cert(n, &c) } else { self.add_plain(n, &c, false) };
                if r.is_merge() {
                    cert = Some(id);
                    // the seeds its boxes carry besides the merge's (`add_cert`)
                    for x in self.w.items[id as usize..].iter().filter(|x| self.eid[x.id as usize - 1] == c) {
                        if let MK::Reseal { e } = &x.kind {
                            reseals.extend((0..N).filter(|d| x.boxed[*d]).map(|d| (e.clone(), d)));
                        }
                    }
                } else {
                    plain = Some(id);
                }
                made.push(id);
            } else if h.author == self.ids.p && h.reseal.is_some() {
                let ids = self.add_reseal(n, &c);
                for id in &ids {
                    if let MK::Reseal { e } = &self.w.item(*id).kind {
                        for d in (0..N).filter(|d| self.w.item(*id).boxed[*d]) {
                            reseals.insert((e.clone(), d));
                        }
                    }
                }
                made.extend(ids.first());
            } else if self.is_t_rotation(n, &c) {
                let e = self.line_of(&h.epoch.unwrap());
                let mut bx = [false; N];
                bx[R1] = true;
                let reach = self.reach_of(n, &c);
                let pk = self.lp.peers[n].engine.package(&c).unwrap();
                made.push(self.add(MK::TRot, n, n, e, te, c, pk, bx, reach));
                trot = true;
                self.reached.t_rekeyed = true;
            } else {
                rest.push(c);
            }
        }
        // the plain rotation and the certificate: the model's
        let got = plain.map(|id| self.plain_of(id));
        if got != model.plain {
            self.fail(&format!("t{t} {} acting (removes {removes:?}): plain rotation engine {got:?}, model {:?}", cm::NAMES[n], model.plain));
        }
        let got = cert.map(|id| (self.w.mints(id), (0..N).filter(|m| self.w.item(id).boxed[*m] && *m != n).collect::<BTreeSet<usize>>()));
        if got != model.cert {
            self.fail(&format!("t{t} {} acting: certificate engine {got:?}, model {:?}", cm::NAMES[n], model.cert));
        }
        if let Some((e, d)) = model.reseals.iter().find(|x| !reseals.contains(x)) {
            self.fail(&format!("t{t} {} acting: the model re-seals {e:?} to {}, the engine not (engine {reseals:?})", cm::NAMES[n], cm::NAMES[*d]));
        }
        // the model's t has no forks of its own (each t epoch follows one): the engine also
        // re-keys t where two of t's epochs are current (siblings re-keyed it apart), so only the
        // model's re-key is required
        if model.trot && !trot {
            let what: Vec<String> = made.iter().chain(&[]).map(|id| format!("#{id} {:?}", self.w.item(*id).kind)).collect();
            let hs: Vec<String> = rest.iter().map(|c| { let h = self.lp.peers[n].engine.header(c).unwrap(); format!("{:?} {:?}", h.kind, h.aspects.iter().map(|a| format!("{}:{}", if a.tid == self.ids.t { "t" } else if a.tid == self.ids.d { "D" } else if a.tid == self.ids.p { "P" } else { "?" }, a.ak.as_str())).collect::<Vec<_>>()) }).collect();
            self.fail(&format!("t{t} {} acting: engine re-keys t {trot}, model {} (made {what:?}; besides {hs:?})", cm::NAMES[n], model.trot));
        }
        // what else it made goes with its first item, or with its next one
        let sides: Vec<Side> = rest.iter().map(|c| self.side(n, c)).collect();
        match made.first() {
            Some(id) => {
                self.comp.insert(*id, sides);
            }
            None => self.extras[n].extend(sides),
        }
        self.note(format!("t{t} {} acts (removes {removes:?}): made {made:?}", cm::NAMES[n]));
        if write {
            let mut writes = Vec::new();
            for (thing, on_t) in [(self.ids.u, false), (self.ids.t, true)] {
                if let Some(id) = self.write(n, thing, if on_t { te } else { None }) {
                    writes.push((self.w.item(id).epoch.clone(), on_t));
                    made.push(id);
                }
            }
            if writes != model.writes {
                self.fail(&format!("t{t} {} writes: engine {writes:?}, model {:?}", cm::NAMES[n], model.writes));
            }
        }
        self.schedule(&made);
        self.check_left();
        made
    }

    /// Whether commit c made at peer k is a rotation of thing t (it writes t's keysets).
    fn is_t_rotation(&self, k: usize, c: &CommitId) -> bool {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        h.kind == osis_commit::Kind::Role && h.aspects.iter().any(|a| a.tid == self.ids.t && a.ak.as_str() == "keys.0")
    }

    /// Plain rotation item `id` as the policy compares it: signed at, removes, takes, answers,
    /// boxed (but its maker).
    fn plain_of(&self, id: u32) -> (Line, BTreeSet<usize>, BTreeSet<u32>, BTreeSet<Line>, BTreeSet<usize>) {
        let i = self.w.item(id);
        let MK::Plain { at, removes, takes, answers, .. } = &i.kind else { unreachable!() };
        (at.clone(), removes.iter().copied().collect(), takes.iter().copied().collect(), answers.iter().map(|q| answered(&self.w, *q)).collect(), (0..N).filter(|m| i.boxed[*m] && *m != i.author).collect())
    }

    /// Engine plain rotation `c` made by k (honest), mirrored.
    fn add_plain(&mut self, k: usize, c: &CommitId, script: bool) -> u32 {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let r = h.rotation.clone().unwrap();
        let at_e = h.epoch.unwrap();
        let at = self.line_of(&at_e);
        let v = self.view(k);
        let to_parties = |s: BTreeSet<Tid>| -> Vec<usize> { s.iter().filter_map(|t| self.party(t)).collect() };
        let removes = to_parties(v.removes(c));
        let adds = to_parties(v.devices.as_ref().and_then(|d| d.adds.get(c)).cloned().unwrap_or_default());
        let takes: Vec<u32> = r.takes.iter().map(|x| self.m(x)).collect();
        // a merge answered is named by a certificate of it
        let answers: Vec<u32> = r.supersedes.iter().filter(|s| **s != at_e).map(|s| match self.merge_line.get(s) {
            Some(l) => self.w.items.iter().find(|i| matches!(i.kind, MK::Cert { .. }) && self.w.mints(i.id) == *l).map(|i| i.id).unwrap_or_else(|| self.fail("an answer to a merge no certificate mirrors")),
            None => self.m(s),
        }).collect();
        let seed = self.keys_at(k, c).unwrap_or_else(|| self.fail("a rotation's maker lacks its seed")).seed().clone();
        let boxed = self.boxed_by(&seed, &r.seeds);
        let reach = self.reach_of(k, c);
        let pk = self.lp.peers[k].engine.package(c).unwrap();
        let id = self.add(MK::Plain { at: at.clone(), removes, adds, takes, answers }, k, k, at, None, *c, pk, boxed, reach);
        self.w.items[id as usize - 1].script = script;
        self.key_line.insert(r.signing_key.to_bytes(), self.w.line(id));
        self.epoch_key.insert(*c, r.signing_key.to_bytes());
        id
    }

    /// Records certificate commit `c`'s merge epoch: its line from its tips.
    fn note_merge(&mut self, c: &CommitId, r: &osis_commit::RotationHeader) -> (Line, Vec<Line>) {
        let tips: Vec<Line> = r.supersedes.iter().map(|t| self.w.line(self.m(t))).collect();
        let line: Line = tips.iter().flatten().copied().collect();
        let e = r.mints(c);
        self.w.merge_tie.insert(line.clone(), u64::from_be_bytes(e.0[..8].try_into().unwrap()));
        self.merge_line.insert(e, line.clone());
        self.line_merge.entry(line.clone()).or_insert(e);
        self.key_line.insert(r.signing_key.to_bytes(), line.clone());
        self.epoch_key.insert(e, r.signing_key.to_bytes());
        (line, tips)
    }

    /// Engine certificate `c` made by k (honest), mirrored, and the maker's other seeds it boxes
    /// (to a device that cannot derive the merge's: every seed held, spec/crypto.md §9).
    fn add_cert(&mut self, k: usize, c: &CommitId) -> u32 {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let r = h.rotation.clone().unwrap();
        let (line, tips) = self.note_merge(c, &r);
        let seed = self.keys_at(k, &r.mints(c)).unwrap_or_else(|| self.fail("a certificate's maker lacks its seed")).seed().clone();
        let boxed = self.boxed_by(&seed, &r.seeds);
        let reach = self.reach_of(k, c);
        let pk = self.lp.peers[k].engine.package(c).unwrap();
        let at = tips[0].clone();
        let id = self.add(MK::Cert { joined: tips, takes: vec![], answers: vec![] }, k, k, at.clone(), None, *c, pk, boxed, reach);
        // the seeds riding along count as the certificate does: items at its own epoch
        let newcomers: Vec<usize> = (0..N).filter(|m| boxed[*m] && *m != k).collect();
        if !newcomers.is_empty() {
            let bx: [bool; N] = std::array::from_fn(|m| newcomers.contains(&m));
            let extra: Vec<Line> = self.held_lines(k).into_iter().filter(|e| *e != line && !e.is_empty() && e.is_subset(&line) && self.w.single(e)).collect();
            for e in extra {
                self.add(MK::Reseal { e }, k, k, line.clone(), None, *c, None, bx, reach);
            }
        }
        self.reached.certs = true;
        id
    }

    /// Engine re-seal `c` made by k: an item per seed it carries (its head's, then its line's
    /// held there), each boxed to the devices its boxes are tagged for.
    fn add_reseal(&mut self, k: usize, c: &CommitId) -> Vec<u32> {
        let h = self.lp.peers[k].engine.header(c).unwrap();
        let rs = h.reseal.clone().unwrap();
        let head = self.key_line.get(&rs.signing_key.to_bytes()).cloned().unwrap_or_else(|| self.fail("a re-seal of an unknown epoch"));
        let he = self.epoch_of(&head).unwrap();
        let seed = self.keys_at(k, &he).unwrap().seed().clone();
        let boxed = self.boxed_by(&seed, &rs.seeds);
        let reach = self.reach_of(k, c);
        let at = self.line_of(&h.epoch.unwrap());
        let pk = self.lp.peers[k].engine.package(c).unwrap();
        let v = self.view(k);
        let mut lines: Vec<Line> = vec![head.clone()];
        for r in v.line(&he).into_iter().flatten().filter(|r| *r != he) {
            if self.keys_at(k, &r).is_some() {
                let l = self.line_of(&r);
                if !l.is_empty() && !lines.contains(&l) {
                    lines.push(l);
                }
            }
        }
        let mut out = vec![self.add(MK::Reseal { e: head }, k, k, at.clone(), None, *c, pk, boxed, reach)];
        for e in lines.into_iter().skip(1) {
            out.push(self.add(MK::Reseal { e }, k, k, at.clone(), None, *c, None, boxed, reach));
        }
        out
    }

    /// Node n writes on `thing` at its open epoch (`on_t`: the t epoch the model says).
    fn write(&mut self, n: usize, thing: Tid, on_t: Option<u32>) -> Option<u32> {
        self.lp.advance(1);
        let mut m = crate::Mutation::new();
        m.set(thing, &x(), &Value::Str(format!("{} #{}", cm::NAMES[n], self.w.items.len()))).unwrap();
        let c = match self.lp.peers[n].commit(m) {
            Ok(Some(c)) => c,
            Ok(None) => self.fail(&format!("t{} {} wrote nothing", self.tick, cm::NAMES[n])),
            Err(e) => {
                self.note(format!("t{} {} cannot write: {e}", self.tick, cm::NAMES[n]));
                return None;
            }
        };
        let others: Vec<CommitId> = self.fresh(n).into_iter().filter(|x| *x != c).collect();
        let e = self.line_of(&self.lp.peers[n].engine.header(&c).unwrap().epoch.unwrap());
        let reach = self.reach_of(n, &c);
        let pk = self.lp.peers[n].engine.package(&c).unwrap();
        let on_t = if thing == self.ids.t { Some(on_t.unwrap_or(0)) } else { None };
        let id = self.add(MK::Content, n, n, e, on_t, c, pk, [false; N], reach);
        let comp: Vec<Side> = others.iter().map(|x| self.side(n, x)).collect();
        self.comp.insert(id, comp);
        Some(id)
    }

    /// B's or A's plain rotation of the world's script (no policy event), its seed boxed to its
    /// roster.
    fn script_rotation(&mut self, n: usize) -> Option<u32> {
        self.lp.advance(1);
        let p = self.ids.p;
        let c = self.lp.peers[n].engine.run(|tx| crate::flows::signing::rotate_in(tx, p, &[], &mut crate::flows::Done::default())).unwrap()?;
        let others: Vec<CommitId> = self.fresh(n).into_iter().filter(|x| *x != c).collect();
        let id = self.add_plain(n, &c, true);
        let comp: Vec<Side> = others.iter().map(|x| self.side(n, x)).collect();
        self.comp.insert(id, comp);
        self.note(format!("t{} {} rotates plainly: #{id}", self.tick, cm::NAMES[n]));
        Some(id)
    }

    fn switch(&mut self, n: usize, c: u32) {
        self.lp.advance(1);
        let now = self.now();
        self.w.switches.push((n, now, c));
        let e = self.eid[c as usize - 1];
        let _ = self.lp.peers[n].engine.choose_line(self.ids.p, e);
        self.switched_at[n] = true;
        self.note(format!("t{} {} chooses #{c}", self.tick, cm::NAMES[n]));
    }

    // ---- X

    /// `bytes` with its inner signature sealed as `signer` under epoch keys `k` and a rotation's
    /// again under `more` (`epoch`: signed at that epoch instead, a new commit ID).
    fn seal(&self, bytes: &[u8], epoch: Option<CommitId>, k: &AccountEpochKeys, signer: usize, more: &[&Secret32]) -> (CommitId, Vec<u8>) {
        let mut b = CommitBlob::decode(bytes).unwrap();
        if let Some(e) = epoch {
            b.header.epoch = Some(e);
        }
        let who = &self.lp.peers[signer].engine.core.id;
        super::tests_account::seal_inner_as(&mut b, k, more, &who.tid(), &who.keys().signing);
        (b.header.id(), b.encode())
    }

    /// Seed boxes of `seed` (epoch key `key`) to `to`.
    fn boxes(&mut self, seed: &Secret32, to: &[bool; N]) -> Vec<SeedBox> {
        let key = AccountEpochKeys::from_seed(seed).signing.verifying_key();
        let mut rng = osis_crypto::SeededRng::from_u64(self.rng.next());
        let mut out: Vec<SeedBox> = (0..N).filter(|m| to[*m]).map(|m| {
            let kem = self.lp.peers[m].engine.core.id.keys().kem.public().clone();
            SeedBox { tag: osis_crypto::seed_tag(seed, &self.tids[m]), sealed: osis_crypto::seal_seeds(&kem, &self.ids.p, &key, &[seed], &mut rng).unwrap() }
        }).collect();
        out.sort_by_key(|b| b.tag);
        out
    }

    fn everyone() -> [bool; N] {
        std::array::from_fn(|m| m != Z)
    }

    /// A rotation X forges: signed at line `e` (whose seed it holds), as `signer`, with a fresh
    /// seed boxed to `boxed`, carrying `removes`, `adds`, `takes` and `answers`. Withheld: never
    /// delivered.
    #[allow(clippy::too_many_arguments)]
    fn x_rotation(&mut self, e: &Line, removes: Vec<usize>, adds: Vec<usize>, signer: usize, takes: Vec<u32>, answers: Vec<u32>, boxed: [bool; N], withheld: bool) -> Option<u32> {
        let at_seed = self.x_seed(e)?;
        let at_keys = AccountEpochKeys::from_seed(&at_seed);
        let at_e = self.epoch_of(e)?;
        let mut b = [0u8; 32];
        for x in b.iter_mut() {
            *x = self.rng.next() as u8;
        }
        let seed = Secret32::from_bytes(b);
        let next = AccountEpochKeys::from_seed(&seed);
        let tid = |m: &usize| self.tids[*m];
        let mut sup: Vec<CommitId> = std::iter::once(at_e).chain(answers.iter().map(|q| self.eid[*q as usize - 1])).collect();
        sup.sort();
        sup.dedup();
        let mut takes_e: Vec<CommitId> = takes.iter().map(|q| self.eid[*q as usize - 1]).collect();
        takes_e.sort();
        let devices = if adds.is_empty() && removes.is_empty() { Vec::new() } else { osis_crypto::seal_devices(&at_keys.inner, &next.signing.verifying_key(), &adds.iter().map(tid).collect::<Vec<_>>(), &removes.iter().map(tid).collect::<Vec<_>>()) };
        let seeds = self.boxes(&seed, &boxed);
        let header = osis_commit::RotationHeader { signing_key: next.signing.verifying_key(), kem_key: next.kem.public().clone(), supersedes: sup, names: Vec::new(), takes: takes_e, revokes: !removes.is_empty(), devices, list_root: [0; 32], seeds };
        let rec = self.lp.peers[A].engine.core.created(&self.ids.p).unwrap().clone();
        self.lp.advance(1);
        let ts = osis_base::Ts::make(self.lp.peers[X].engine.now(), 0).unwrap();
        let bytes = super::tests_account::rotation_at(rec, (at_e, &at_keys), &[], &next, header, ts);
        let (c, bytes) = self.seal(&bytes, None, &at_keys, signer, &[&next.inner]);
        let pk = Package { id: c, bytes, blobs: Vec::new(), lists: Vec::new() };
        let id = self.add(MK::Plain { at: e.clone(), removes, adds, takes, answers }, X, signer, e.clone(), None, c, Some(pk), boxed, Self::everyone());
        self.xseeds.insert(next.signing.verifying_key().to_bytes(), seed);
        self.key_line.insert(next.signing.verifying_key().to_bytes(), self.w.line(id));
        self.epoch_key.insert(c, next.signing.verifying_key().to_bytes());
        if withheld {
            self.w.withheld.insert(id);
            self.reached.withheld = true;
        }
        self.reached.as_z |= signer == Z;
        self.note(format!("t{} X forges #{id} at {e:?} as {}", self.tick, cm::NAMES[signer]));
        Some(id)
    }

    /// A certificate X forges of the merge of `a` and `b` (every tip's seed held), as `signer`,
    /// boxed to P's devices.
    fn x_cert(&mut self, a: &Line, b: &Line, signer: usize) -> Option<u32> {
        let line: Line = a.union(b).copied().collect();
        let mut tips: Vec<CommitId> = self.w.tips(&line).iter().map(|t| self.eid[*t as usize - 1]).collect();
        tips.sort();
        let tip_seeds: Vec<Secret32> = tips.iter().map(|t| self.x_seed(&self.w.line(self.m(t)))).collect::<Option<_>>()?;
        let seed = osis_crypto::merge_seed(&tip_seeds.iter().collect::<Vec<_>>());
        let keys = AccountEpochKeys::from_seed(&seed);
        let tip_keys: Vec<AccountEpochKeys> = tip_seeds.iter().map(AccountEpochKeys::from_seed).collect();
        let boxed: [bool; N] = std::array::from_fn(|m| m < OWN);
        let seeds = self.boxes(&seed, &boxed);
        let header = osis_commit::RotationHeader { signing_key: keys.signing.verifying_key(), kem_key: keys.kem.public().clone(), supersedes: tips.clone(), names: tips[1..].to_vec(), takes: Vec::new(), revokes: false, devices: Vec::new(), list_root: [0; 32], seeds };
        let rec = self.lp.peers[A].engine.core.created(&self.ids.p).unwrap().clone();
        self.lp.advance(1);
        let ts = osis_base::Ts::make(self.lp.peers[X].engine.now(), 0).unwrap();
        let forks: Vec<&AccountEpochKeys> = tip_keys[1..].iter().collect();
        let bytes = super::tests_account::rotation_at(rec, (tips[0], &tip_keys[0]), &forks, &keys, header.clone(), ts);
        let more: Vec<&Secret32> = tip_keys[1..].iter().map(|k| &k.inner).chain([&keys.inner]).collect();
        let (c, bytes) = self.seal(&bytes, None, &tip_keys[0], signer, &more);
        let pk = Package { id: c, bytes, blobs: Vec::new(), lists: Vec::new() };
        let (_, tlines) = self.note_merge(&c, &header);
        let at = tlines[0].clone();
        let id = self.add(MK::Cert { joined: tlines, takes: vec![], answers: vec![] }, X, signer, at, None, c, Some(pk), boxed, Self::everyone());
        self.reached.x_certs = true;
        self.reached.as_z |= signer == Z;
        self.note(format!("t{} X certifies #{id}: {line:?} as {}", self.tick, cm::NAMES[signer]));
        Some(id)
    }

    /// X's commit `c` (made by its engine at its setup epoch, never sent) signed at line `e`.
    fn x_resign(&mut self, c: &CommitId, e: &Line) -> Option<Package> {
        let k = AccountEpochKeys::from_seed(&self.x_seed(e)?);
        let at = self.epoch_of(e)?;
        let mut pk = self.lp.peers[X].engine.package(c).unwrap()?;
        let (id, bytes) = self.seal(&pk.bytes, Some(at), &k, X, &[]);
        self.seen.insert(id);
        pk.id = id;
        pk.bytes = bytes;
        pk.lists.clear();
        Some(pk)
    }

    /// X writes on u at line `e`.
    fn x_write(&mut self, e: &Line) -> Option<u32> {
        self.lp.advance(1);
        let mut m = crate::Mutation::new();
        m.set(self.ids.u, &x(), &Value::Str(format!("X #{}", self.w.items.len()))).unwrap();
        let c = self.lp.peers[X].commit(m).ok()??;
        self.fresh(X);
        let pk = self.x_resign(&c, e)?;
        let id = pk.id;
        let item = self.add(MK::Content, X, X, e.clone(), None, id, Some(pk), [false; N], Self::everyone());
        self.note(format!("t{} X writes #{item} at {e:?}", self.tick));
        Some(item)
    }

    /// X re-seals the seed of line `e` to honest node `to`: a carrier on D signed at `e`.
    fn x_reseal(&mut self, e: &Line, to: usize) -> Option<u32> {
        let seed = self.x_seed(e)?;
        let key = AccountEpochKeys::from_seed(&seed).signing.verifying_key();
        let mut bx = [false; N];
        bx[to] = true;
        let seeds = self.boxes(&seed, &bx);
        let (p, d) = (self.ids.p, self.ids.d);
        self.lp.advance(1);
        let mut m = crate::Mutation::new();
        m.sign_as(p);
        m.op(d, &osis_schema::core_types::ACCOUNT, osis_crdt::PathOp { path: vec![], op: osis_crdt::Op::Add(Value::bytes(&key.to_bytes())) }).unwrap();
        m.reseal = Some(osis_commit::SeedReseal { signing_key: key, seeds });
        let c = self.lp.peers[X].commit(m).ok()??;
        self.fresh(X);
        let pk = self.x_resign(&c, e)?;
        let id = pk.id;
        let reach: [bool; N] = std::array::from_fn(|m| m < OWN);
        let item = self.add(MK::Reseal { e: e.clone() }, X, X, e.clone(), None, id, Some(pk), bx, reach);
        self.reached.x_reseals = true;
        self.note(format!("t{} X re-seals {e:?} to {}: #{item}", self.tick, cm::NAMES[to]));
        Some(item)
    }

    /// X's move, as the model's `x_step` in random worlds.
    fn x_move(&mut self) {
        let j = self.judge(X);
        let mut eps: Vec<Line> = std::iter::once(Line::new()).chain(j.chain.iter().map(|x| self.w.line(*x))).chain(j.merges.iter().cloned()).filter(|e| j.keys.holds(&self.w, e)).collect();
        eps.dedup();
        for e in &eps {
            if self.x_seed(e).is_none() {
                self.fail(&format!("t{}: X holds {e:?} in the model, not in the engines' boxes", self.tick));
            }
        }
        let e = eps[self.rng.below(eps.len())].clone();
        let mut made = Vec::new();
        match self.rng.below(4) {
            0 => {
                let removes = [vec![], vec![A], vec![B], vec![C]][self.rng.below(4)].clone();
                let signer = [X, Z][self.rng.below(2)];
                let adds = [vec![], vec![Z], vec![X]][self.rng.below(3)].clone();
                let revs: Vec<u32> = j.chain.iter().copied().filter(|q| !self.w.removes(*q).is_empty()).collect();
                let takes = match self.rng.below(4) {
                    0 if !revs.is_empty() => vec![revs[self.rng.below(revs.len())]],
                    1 => vec![self.w.removal],
                    2 => {
                        let only_x: [bool; N] = std::array::from_fn(|m| m == X);
                        self.x_rotation(&e, vec![A], vec![], X, vec![], vec![], only_x, true).into_iter().collect()
                    }
                    _ => vec![],
                };
                let honest: Vec<u32> = j.chain.iter().copied().filter(|q| self.w.item(*q).author != X && !e.contains(q)).collect();
                let answers = if self.rng.below(3) == 0 { honest.last().into_iter().copied().collect() } else { vec![] };
                let only = |ms: &[usize]| -> [bool; N] { std::array::from_fn(|m| ms.contains(&m)) };
                let boxed = [only(&[A, B, C, X, T]), only(&[X]), only(&[X, B]), only(&[X, A, C])][self.rng.below(4)];
                if let Some(r) = self.x_rotation(&e, removes, adds, signer, takes, answers, boxed, false) {
                    made.push(r);
                    if self.rng.below(2) == 0 {
                        let l = self.w.line(r);
                        made.extend(self.x_write(&l));
                    }
                }
            }
            1 => made.extend(self.x_write(&e)),
            2 => {
                let pairs: Vec<(Line, Line)> = eps.iter().flat_map(|a| eps.iter().map(move |b| (a.clone(), b.clone()))).filter(|(a, b)| a < b && !a.is_subset(b) && !b.is_subset(a)).collect();
                if !pairs.is_empty() {
                    let (a, b) = pairs[self.rng.below(pairs.len())].clone();
                    let signer = [X, Z][self.rng.below(2)];
                    made.extend(self.x_cert(&a, &b, signer));
                }
            }
            _ => {
                let to = [A, B, C, T][self.rng.below(4)];
                if !e.is_empty() {
                    made.extend(self.x_reseal(&e, to));
                }
            }
        }
        self.schedule(&made);
    }

    // ---- compare

    /// At every observer: the engine's judgment against the model's, now.
    fn compare(&mut self) {
        for n in [A, B, C, T, R1, R2] {
            self.take_up(n);
            if std::env::var_os("CUSTODY_PROBE").is_some() {
                eprintln!("t{} probe {}", self.tick, cm::NAMES[n]);
                self.lp.peers[n].engine.check_index();
            }
        }
        self.check_left();
        self.sync_recv();
        let t = self.tick;
        let now = self.now();
        let plain: Vec<u32> = self.w.items.iter().filter(|i| matches!(i.kind, MK::Plain { .. }) && !self.w.withheld.contains(&i.id)).map(|i| i.id).collect();
        for v in [A, B, C, T, R1, R2] {
            if self.left[v] {
                continue;
            }
            let j = cm::judge(&self.w, v, now);
            let view = self.view(v);
            let at = |what: &str, e: String, m: String| format!("t{t} node {}: {what}: engine {e}, model {m}", cm::NAMES[v]);
            let chain: BTreeSet<u32> = plain.iter().copied().filter(|r| view.holds(&self.eid[*r as usize - 1])).collect();
            if chain != j.chain {
                self.fail(&at("held with chain", format!("{chain:?}"), format!("{:?}", j.chain)));
            }
            let merges: BTreeSet<Line> = self.merge_line.iter().filter(|(e, _)| view.holds(e)).map(|(_, l)| l.clone()).collect();
            if merges != j.merges {
                self.fail(&at("merges held", format!("{merges:?}"), format!("{:?}", j.merges)));
            }
            let mut counting: BTreeSet<Line> = [Line::new()].into();
            counting.extend(chain.iter().filter(|r| view.rotation_counts(&self.eid[**r as usize - 1])).map(|r| self.w.line(*r)));
            counting.extend(self.merge_line.iter().filter(|(e, _)| view.holds(e) && view.rotation_counts(e)).map(|(_, l)| l.clone()));
            if counting != j.counting {
                self.fail(&at("counting", format!("{counting:?}"), format!("{:?} taken {:?}", j.counting, j.taken)));
            }
            let heads: BTreeSet<Line> = view.heads().iter().map(|h| self.line_of(h)).collect();
            if heads != j.heads {
                self.fail(&at("heads", format!("{heads:?}"), format!("{:?}", j.heads)));
            }
            let pref = self.line_of(&view.preferred());
            if pref != j.preferred {
                self.fail(&at("preferred", format!("{pref:?}"), format!("{:?}", j.preferred)));
            }
            let warn = view.doubt().is_some();
            if warn != j.warning {
                let rej: Vec<u32> = chain.iter().copied().filter(|r| view.rejected(&self.eid[*r as usize - 1])).collect();
                let answers: Vec<(u32, Vec<u32>)> = self.w.items.iter().filter(|i| !self.w.answers(i.id).is_empty()).map(|i| (i.id, self.w.answers(i.id).to_vec())).collect();
                self.fail(&at("warning", format!("{warn} (rejected {rej:?}, contested {:?})", view.contested().iter().map(|c| self.line_of(c)).collect::<Vec<_>>()), format!("{} (rejected {:?}; answers {answers:?})", j.warning, j.rejected)));
            }
            self.reached.warned |= warn;
            if v < OWN {
                let taken: Vec<u32> = view.taken().iter().map(|c| self.m(c)).collect();
                if taken != j.taken {
                    self.fail(&at("taken", format!("{taken:?}"), format!("{:?}", j.taken)));
                }
                if !self.switched_at[v] && !self.taken[v].iter().all(|r| taken.contains(r)) {
                    self.fail(&format!("t{t} node {}: dropped a taken revocation {:?} -> {taken:?}", cm::NAMES[v], self.taken[v]));
                }
                self.taken[v] = taken;
                let roster: BTreeSet<usize> = view.roster().iter().filter_map(|m| self.party(m)).collect();
                if roster != j.roster {
                    self.fail(&at("D's roster", format!("{roster:?}"), format!("{:?}", j.roster)));
                }
                // custody: the seeds held (and the merges they derive), as the model's
                let mut seeds = self.held_lines(v);
                let derivable: Vec<Line> = self.w.items.iter().filter(|i| self.w.is_rot(i.id)).map(|i| self.w.mints(i.id)).filter(|e| !self.w.single(e) && self.w.tips(e).iter().all(|m| seeds.contains(&self.w.line(*m)))).collect();
                seeds.extend(derivable);
                let model = cm::secrets(&self.w, &j).0;
                if seeds != model {
                    self.fail(&at("seeds held", format!("{seeds:?}"), format!("{model:?}")));
                }
                if !self.seeds[v].is_subset(&seeds) {
                    self.fail(&format!("t{t} node {}: custody shrank {:?} -> {seeds:?}", cm::NAMES[v], self.seeds[v]));
                }
                self.seeds[v] = seeds;
                if j.taken.iter().any(|r| self.w.item(*r).author == X) && !j.taken.contains(&self.w.removal) {
                    self.reached.x_side = true;
                }
                if j.out(v) {
                    self.reached.own_removal = true;
                }
            } else {
                let fol: Vec<u32> = j.followed.iter().copied().collect();
                if !self.switched_at[v] && !self.taken[v].iter().all(|r| fol.contains(r)) {
                    self.fail(&format!("t{t} node {}: followed shrank", cm::NAMES[v]));
                }
                self.taken[v] = fol;
            }
            // the secrets of t's own read epochs only grow (reading-only ones included: opened
            // whatever counts; t's epochs derived from P's come and go with P's current epochs)
            if v < OWN || v == R1 {
                let tk: BTreeSet<osis_crypto::Epoch> = self.lp.peers[v].engine.core.ix.secrets.get(&self.ids.t).map(|e| e.read.epochs().filter(|(x, _)| e.read.secret(x).is_some()).map(|(x, _)| *x).collect()).unwrap_or_default();
                if !self.tkeys[v].is_subset(&tk) {
                    let lost: Vec<u64> = self.tkeys[v].difference(&tk).map(|e| e.n()).collect();
                    self.fail(&format!("t{t} node {}: t's read epochs shrank {} -> {} (lost n {lost:?})", cm::NAMES[v], self.tkeys[v].len(), tk.len()));
                }
                self.tkeys[v] = tk;
            }
            // a switch takes
            if let Some(c) = j.chosen {
                let e = self.eid[c as usize - 1];
                let node = v >= OWN || j.roster.contains(&v) || !j.out(v);
                if node && view.holds(&e) && (!view.rotation_counts(&e) || !view.on_line(&e, &view.preferred()) && view.preferred() != e) {
                    self.fail(&format!("t{t} node {}: chose #{c}, does not follow it", cm::NAMES[v]));
                }
                if v < OWN && c == self.w.removal {
                    self.reached.switched = true;
                }
            }
            // writes the model counts count
            for i in self.w.items.iter().filter(|i| matches!(i.kind, MK::Content) && i.recv[v] <= now) {
                let c = self.eid[i.id as usize - 1];
                let e = &self.lp.peers[v].engine;
                let Some(meta) = e.core.ix.commits.get(&c) else { continue };
                let counts = e.core.standing(&c, &meta.view) == osis_perm::EpochStanding::Counts;
                if j.valid.contains(&i.id) && !counts {
                    self.fail(&at(&format!("write #{}", i.id), "invalid".into(), "valid".into()));
                }
            }
        }
        for v in 0..N {
            self.switched_at[v] = false;
        }
    }

    /// Why commit `c` stands as it does at peer v: its standing, and each word naming it there.
    fn why(&mut self, v: usize, c: &CommitId) -> String {
        let names = self.lp.peers[v].engine.read(|tx| crate::flows::lists::names_of(tx, c)).unwrap_or_default();
        let others: Vec<(usize, Vec<(Tid, CommitId)>)> = [A, B, C, T].iter().map(|k| (*k, self.lp.peers[*k].engine.read(|tx| crate::flows::lists::names_of(tx, c)).unwrap_or_default())).collect();
        let e = &self.lp.peers[v].engine;
        let Some(m) = e.core.ix.commits.get(c) else { return "not held".into() };
        let st = e.core.standing(c, &m.view);
        let ns: Vec<String> = names.iter().map(|(_, s)| {
            let what = self.mid.get(s).map_or_else(|| format!("{:.8}", format!("{s:?}")), |m| format!("#{m}"));
            let st = e.core.ix.commits.get(s).map(|m| format!("{:?} at {:?}", e.core.standing(s, &m.view), m.view.epoch.map(|x| self.line_of(&x))));
            format!("{what}: {st:?}")
        }).collect();
        let mut elsewhere = Vec::new();
        for (k, ns) in others {
            for (_, s) in ns {
                let here = self.lp.peers[v].engine.core.ix.commits.get(&s).map(|m| format!("{:?}", self.lp.peers[v].engine.core.standing(&s, &m.view)));
                let pend = format!("{:?}", self.lp.peers[v].engine.core.ix.pending.get(&s));
                elsewhere.push(format!("{} named by {:.8} (here {here:?}, pending {pend:?})", cm::NAMES[k], format!("{s:?}")));
            }
        }
        format!("{st:?} at {:?}; named by {ns:?}; elsewhere {elsewhere:?}", m.view.epoch.map(|x| self.line_of(&x)))
    }

    // ---- the world

    fn generate(&mut self) {
        self.w.sched = [cm::Sched::Random, cm::Sched::Lockstep][self.rng.below(2)];
        self.reached.lockstep = self.w.sched == cm::Sched::Lockstep;
        self.w.b_switch = [None, Some(0), Some(1), Some(3)][self.rng.below(4)];
        if self.rng.below(2) == 1 {
            self.floor[B] = 3 + self.rng.below(5) as u32;
        }
        let c_mode = self.rng.below(3);
        if c_mode > 0 {
            self.floor[C] = 3 + self.rng.below(5) as u32;
        }
        self.floor[T] = cm::SETTLE;
        let (x0, a0) = (self.rng.below(2) == 1, self.rng.below(2) == 1);
        let steps = 3 + self.rng.below(5) as u32;
        self.goto(0);
        if x0 {
            let all_p: [bool; N] = std::array::from_fn(|m| m < OWN);
            if let Some(id) = self.x_rotation(&Line::new(), vec![], vec![], X, vec![], vec![], all_p, false) {
                self.w.items[id as usize - 1].script = true;
                self.schedule(&[id]);
            }
        }
        if a0 && let Some(id) = self.script_rotation(A) {
            self.schedule(&[id]);
        }
        self.act(A, None, true);
        self.compare();
        self.goto(1);
        self.arrivals();
        let made = self.act(A, Some(X), true);
        self.w.removal = *made.first().unwrap_or_else(|| self.fail("A's removal of X made nothing"));
        if self.rng.below(2) == 1 {
            for id in &made {
                for m in [B, C] {
                    self.sched.get_mut(id).unwrap()[m] = NEVER;
                }
            }
        }
        if c_mode == 1 {
            self.act(C, Some(T), true);
        }
        self.compare();
        for t in 2..2 + steps {
            self.goto(t);
            self.arrivals();
            let x_acts = match self.w.sched {
                cm::Sched::Random => self.rng.below(5) < 2,
                cm::Sched::Lockstep => self.rng.below(2) == 0,
            };
            if x_acts {
                self.x_move();
            }
            let actors: Vec<usize> = match self.w.sched {
                cm::Sched::Lockstep => vec![A, B, C],
                cm::Sched::Random if x_acts => vec![],
                cm::Sched::Random => vec![[A, B, C][self.rng.below(3)]],
            };
            for n in actors {
                self.act(n, None, true);
                // B, unaware of X's removal, may rotate plainly (boxing X)
                if n == B && self.rng.below(2) == 0 && !self.left[B] {
                    let j = self.judge(B);
                    if !j.taken.contains(&self.w.removal) && !j.out(B) && j.keys.holds(&self.w, &j.preferred)
                        && let Some(r) = self.script_rotation(B)
                    {
                        let mut ids = vec![r];
                        ids.extend(self.write(B, self.ids.u, None));
                        self.schedule(&ids);
                    }
                }
            }
            if self.rng.below(6) == 0 {
                let j = self.judge(R2);
                if !j.chain.is_empty() {
                    let c = *j.chain.iter().nth(self.rng.below(j.chain.len())).unwrap();
                    self.switch(R2, c);
                }
            }
            self.compare();
        }
        for t in 2 + steps..cm::SETTLE {
            self.goto(t);
            self.arrivals();
            self.compare();
        }
    }

    /// Everything but what X withholds delivered; P's users on X's side switch to A's removal
    /// (A, C, T at once, B in round `b_switch` or never); the honest nodes act `ROUNDS` rounds,
    /// in turn (random) or on the same deliveries (lockstep).
    fn settle(&mut self) {
        for i in 0..self.w.items.len() {
            let id = i as u32 + 1;
            if self.w.withheld.contains(&id) {
                continue;
            }
            let (author, reach) = (self.w.item(id).author, self.reach[&id]);
            let s = self.sched.get_mut(&id).unwrap();
            for m in 0..N {
                if m != author && reach[m] {
                    s[m] = s[m].min(cm::SETTLE);
                }
            }
        }
        self.goto(cm::SETTLE);
        self.arrivals();
        self.flush();
        self.compare();
        let mut t = cm::SETTLE;
        let removal = self.w.removal;
        for round in 0..cm::ROUNDS {
            let mut made: Vec<u32> = Vec::new();
            let switch = |r: &mut Run, n: usize| {
                if r.left[n] {
                    return;
                }
                let j = r.judge(n);
                let user = if n == B { r.w.b_switch.is_some_and(|k| round >= k) } else { true };
                if user && !j.taken.contains(&removal) && j.chosen != Some(removal) {
                    r.switch(n, removal);
                }
            };
            match self.w.sched {
                cm::Sched::Random => {
                    for n in [A, B, C, T] {
                        t += 1;
                        self.goto(t);
                        self.flush();
                        switch(self, n);
                        if n != T {
                            let ids = self.act(n, None, false);
                            for id in &ids {
                                let reach = self.reach[id];
                                for m in 0..N {
                                    if m != n && reach[m] {
                                        self.sched.get_mut(id).unwrap()[m] = t;
                                        self.send(*id, m);
                                    }
                                }
                            }
                            made.extend(ids);
                        }
                        self.compare();
                    }
                }
                cm::Sched::Lockstep => {
                    t += 1;
                    self.goto(t);
                    self.flush();
                    for n in [A, B, C, T] {
                        switch(self, n);
                    }
                    for n in [A, B, C] {
                        made.extend(self.act(n, None, false));
                    }
                    t += 1;
                    self.goto(t);
                    for id in made.clone() {
                        let (author, reach) = (self.w.item(id).author, self.reach[&id]);
                        for m in 0..N {
                            if m != author && reach[m] {
                                self.sched.get_mut(&id).unwrap()[m] = t;
                                self.send(id, m);
                            }
                        }
                    }
                    self.compare();
                }
            }
            if round + 1 == cm::ROUNDS && made.iter().any(|id| self.w.is_rot(*id) || matches!(self.w.item(*id).kind, MK::TRot)) {
                self.fail(&format!("restless: an honest node still rotates in the last settle round ({made:?})"));
            }
        }
        t += 1;
        self.goto(t);
        self.flush();
        self.compare();
    }

    /// The model's properties on what the engines settled at (roles-model `custody::check`):
    /// bounded rotations, one roster source, secrecy, warned, settled.
    fn settled(&mut self) {
        let w = &self.w;
        let removal = w.removal;
        // bounded: one event per node per plain rotation, none empty
        for n in [A, B, C] {
            let mut seen: BTreeSet<(u8, u32)> = BTreeSet::new();
            for i in w.items.iter().filter(|i| i.author == n && matches!(i.kind, MK::Plain { .. }) && !i.script) {
                let evs: Vec<(u8, u32)> = w.removes(i.id).iter().map(|y| (0, *y as u32)).chain(w.takes(i.id).iter().map(|r| (1, *r))).chain(w.answers(i.id).iter().map(|q| (2, *q))).collect();
                if evs.is_empty() {
                    self.fail(&format!("bounded: {}'s rotation #{} carries no event", cm::NAMES[n], i.id));
                }
                for e in evs {
                    if !seen.insert(e) {
                        self.fail(&format!("bounded: {} carries event {e:?} twice (#{})", cm::NAMES[n], i.id));
                    }
                }
            }
        }
        // one epoch per tip set: twin certificates of one line mint one epoch
        let mut by_line: BTreeMap<Line, BTreeSet<CommitId>> = BTreeMap::new();
        for (e, l) in &self.merge_line {
            by_line.entry(l.clone()).or_default().insert(*e);
        }
        if let Some((l, es)) = by_line.iter().find(|(_, es)| es.len() > 1) {
            self.fail(&format!("merges: the tips of {l:?} make {} epochs", es.len()));
        }
        let mut certs: BTreeMap<Line, usize> = BTreeMap::new();
        for i in w.items.iter().filter(|i| matches!(i.kind, MK::Cert { .. }) && i.author != X) {
            *certs.entry(w.mints(i.id)).or_default() += 1;
        }
        self.reached.twin_certs |= certs.values().any(|n| *n > 1);
        // secrecy: X holds no seed of an epoch an honest node minted where X's removal is taken
        let end = self.now();
        for i in w.items.iter().filter(|i| [A, B, C].contains(&i.author) && w.is_rot(i.id)) {
            let j = cm::judge(w, i.author, i.t);
            if j.taken.contains(&removal) && self.x_seed(&w.mints(i.id)).is_some() {
                self.fail(&format!("secrecy: X holds the seed of #{} by {}, made where X's removal is taken", i.id, cm::NAMES[i.author]));
            }
        }
        let honest_side = |r: &Run, v: usize| if v < OWN { r.view(v).taken().contains(&r.eid[removal as usize - 1]) } else { r.view(v).rotation_counts(&r.eid[removal as usize - 1]) };
        let mut heads: BTreeSet<Vec<CommitId>> = BTreeSet::new();
        for v in [A, B, C, T, R1, R2] {
            if self.left[v] {
                continue;
            }
            let j = cm::judge(&self.w, v, end);
            if v < OWN && j.out(v) {
                continue;
            }
            let view = self.view(v);
            if j.chain.iter().any(|r| self.w.hostile(*r)) && view.doubt().is_none() {
                self.fail(&format!("warned: {} settled holding X's rotation without the warning", cm::NAMES[v]));
            }
            if !honest_side(self, v) {
                continue;
            }
            let hs = view.heads();
            if hs.len() != 1 {
                self.fail(&format!("settled: {} with heads {hs:?}", cm::NAMES[v]));
            }
            if hs.iter().any(|h| self.x_seed(&self.line_of(h)).is_some() && !self.line_of(h).is_empty()) {
                self.fail(&format!("secrecy: {} settled at a head whose seed X holds", cm::NAMES[v]));
            }
            heads.insert(hs);
            let reads_t = v < OWN || v == R1;
            let contents: Vec<cm::Item> = self.w.items.iter().filter(|i| matches!(i.kind, MK::Content)).cloned().collect();
            for i in &contents {
                let c = self.eid[i.id as usize - 1];
                let e = &self.lp.peers[v].engine;
                let counts = e.core.ix.commits.get(&c).is_some_and(|m| e.core.standing(&c, &m.view) == osis_perm::EpochStanding::Counts);
                // an honest node of P holding X's write before X's removal may name it (its
                // cutoff: spec/permissions.md §5.5, Limit), which counts wherever its word does
                let removal_at = |n: usize| self.w.item(removal).recv[n];
                let excused = [A, B, C, T].iter().any(|n| i.recv[*n] < removal_at(*n));
                if self.w.hostile(i.id) && counts && !excused {
                    let why = self.why(v, &c);
                    self.fail(&format!("settled: {} counts X's write #{} ({why})", cm::NAMES[v], i.id));
                }
                if i.author == X || !reads_t && i.on_t.is_some() || self.left[i.author] {
                    continue;
                }
                let ja = cm::judge(&self.w, i.author, end);
                if ja.out(i.author) || !honest_side(self, i.author) {
                    continue;
                }
                if !counts {
                    let why = self.why(v, &c);
                    self.fail(&format!("writes: {} settled without {}'s write #{}{} ({why})", cm::NAMES[v], cm::NAMES[i.author], i.id, if i.on_t.is_some() { " on t" } else { "" }));
                }
                if i.author == C && i.on_t.is_some() && v == A {
                    self.reached.cycle = true;
                }
            }
        }
        if heads.len() > 1 {
            self.fail(&format!("agree: honest-side nodes settled on different heads {heads:?}"));
        }
    }
}

/// One world from `seed`, played and checked; what it reached.
pub(super) fn custody_world(seed: u64) -> Reached {
    let mut r = Run::new(seed);
    r.generate();
    r.settle();
    r.settled();
    r.reached
}

fn tally(runs: &[Reached]) {
    let count = |f: fn(&Reached) -> bool| runs.iter().filter(|r| f(r)).count();
    eprintln!(
        "custody: {} worlds; lockstep {}, X's side taken first {}, own removal {}, switched back {}, certificates {} (twins {}), X certifies {}, X re-seals {}, t re-keyed {}, listing cycle {}, withheld {}, as Z {}, left {}, warned {}",
        runs.len(),
        count(|r| r.lockstep),
        count(|r| r.x_side),
        count(|r| r.own_removal),
        count(|r| r.switched),
        count(|r| r.certs),
        count(|r| r.twin_certs),
        count(|r| r.x_certs),
        count(|r| r.x_reseals),
        count(|r| r.t_rekeyed),
        count(|r| r.cycle),
        count(|r| r.withheld),
        count(|r| r.as_z),
        count(|r| r.left),
        count(|r| r.warned),
    );
}

fn replay(s: u64) -> String {
    format!("OSIS_CUSTODY_START={s} OSIS_CUSTODY_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4")
}

// spec/permissions.md §5.4-§5.5, spec/crypto.md §9: the account's nodes and readers judge a
// forked chain, hold seeds and owe rotations as roles-model `custody` says (module doc). Quick
// size: a few worlds.
#[test]
fn engine_agrees_with_custody_model_spec_permissions_5_4() {
    tally(&osis_base::testenv::run_seeds("rotation::tests_custody::engine_agrees_with_custody_model_spec_permissions_5_4", &(0..4).collect::<Vec<u64>>(), false, replay, custody_world));
}

/// Small size (a tenth of large) or large under `OSIS_FULL=1`; seeds: OSIS_CUSTODY_START,
/// OSIS_CUSTODY_SEEDS.
#[test]
#[ignore = "property"]
fn engine_agrees_with_custody_model_large_spec_permissions_5_4() {
    let s = osis_base::testenv::Seeds::from_env("OSIS_CUSTODY_START", "OSIS_CUSTODY_SEEDS", osis_base::testenv::large(0..2_000));
    tally(&s.run("rotation::tests_custody::engine_agrees_with_custody_model_large_spec_permissions_5_4", replay, custody_world));
}
