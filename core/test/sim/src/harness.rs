//! The harness: nodes (real engines over `MemoryBackend`s with a shared fault plan), virtual
//! time, per-node clocks, an in-flight message queue, and a seeded scheduler choosing the next
//! event. Everything is driven from one `Dice`, so (scenario, seed) replays exactly.

use crate::check::{self, Checker};
use crate::dice::Dice;
use crate::workload;
use osis_base::{Classified, Clock, CommitId, ErrorClass, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::SeededRng;
use osis_node::local_peer::{Package, Peer};
use osis_node::{Engine, Ingested, Mutation};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

/// Wall time at the start of every run.
pub const T0: u64 = 1_700_000_000_000;
const TRACE: usize = 40;

/// A failed invariant (or a panic, or an engine error on honest input), with what replays it.
#[derive(Clone, Debug)]
pub struct Failure {
    pub scenario: String,
    pub seed: u64,
    pub step: u64,
    pub what: String,
    pub trace: Vec<String>,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "sim failure in scenario `{}`, seed {}, step {}: {}", self.scenario, self.seed, self.step, self.what)?;
        writeln!(f, "replay: osis_sim::replay(\"{}\", {})", self.scenario, self.seed)?;
        for t in &self.trace {
            writeln!(f, "  {t}")?;
        }
        Ok(())
    }
}

pub type Res<T> = std::result::Result<T, Failure>;

/// A node's clock: `wall = T0 + elapsed + skew + elapsed * drift_ppm / 10^6`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClockSpec {
    pub skew_ms: i64,
    pub drift_ppm: i64,
}

/// Message faults, applied per package sent.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetFaults {
    pub drop_pct: u32,
    pub dup_pct: u32,
    pub max_delay_ms: u64,
    /// Deliver any due message, not the earliest.
    pub reorder: bool,
}

/// Relative weights of the scheduler's events (0 disables one).
#[derive(Clone, Copy, Debug)]
pub struct Weights {
    pub write: u32,
    pub gossip: u32,
    pub deliver: u32,
    pub tick: u32,
    pub crash: u32,
    pub restart: u32,
}

impl Default for Weights {
    fn default() -> Weights {
        Weights { write: 4, gossip: 2, deliver: 6, tick: 2, crash: 0, restart: 0 }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub nodes: usize,
    /// Per node; missing entries are a perfect clock.
    pub clocks: Vec<ClockSpec>,
    pub net: NetFaults,
    pub weights: Weights,
    /// A tick advances virtual time by 1..=this.
    pub max_tick_ms: u64,
    /// Check convergence after every step (else at quiescence only).
    pub check_every_step: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config { nodes: 2, clocks: Vec::new(), net: NetFaults::default(), weights: Weights::default(), max_tick_ms: 5_000, check_every_step: true }
    }
}

/// One simulated device.
pub struct Node {
    pub peer: Peer,
    pub faults: Faults,
    pub clock: ClockSpec,
    pub up: bool,
}

struct Msg {
    to: usize,
    at: u64,
    pkg: Package,
}

/// Counters of what a run did (and a digest for determinism checks).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub steps: u64,
    pub writes: u64,
    pub sent: u64,
    pub dropped: u64,
    pub delivered: u64,
    pub parked: u64,
    pub crashes: u64,
    pub restarts: u64,
    /// Phase B: messages duplicated, server crashes, partitions, engine and hub diagnostics.
    pub duplicated: u64,
    pub server_crashes: u64,
    pub partitions: u64,
    pub diagnostics: u64,
    /// Must-hold bodies found at servers by the quiescent label check.
    pub held_checked: u64,
    /// Phase C: messages an evil server dropped, held back or replayed; requests an adversary's
    /// hand-driven session sent and those the server refused.
    pub evil: u64,
    pub rogue_sent: u64,
    pub rogue_refused: u64,
    pub commits: usize,
    /// BLAKE3 of every node's final held commits and reads.
    pub digest: [u8; 32],
}

pub struct Sim {
    pub scenario: String,
    pub seed: u64,
    pub dice: Dice,
    /// Virtual time elapsed since T0 (ms).
    pub elapsed: u64,
    pub nodes: Vec<Node>,
    /// Things random writes go to.
    pub things: Vec<Tid>,
    pub cfg: Config,
    pub report: Report,
    /// Random writes and crashes are off (quiescence).
    calm: bool,
    queue: Vec<Msg>,
    trace: VecDeque<String>,
    check: Checker,
}

fn boot(seed: u64, t: WallMs) -> osis_node::Result<(Peer, Faults)> {
    let faults = Faults::new();
    let clock = Arc::new(ManualClock::new(t));
    let backend = MemoryBackend::with_faults(faults.clone());
    let root = MemoryRoot::with_faults(faults.clone());
    let c: Arc<dyn Clock> = clock.clone();
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_node::Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
    let events = engine.subscribe();
    Ok((Peer { engine, clock, backend, root, events }, faults))
}

impl Sim {
    pub fn new(scenario: &str, seed: u64, cfg: Config) -> Res<Sim> {
        let mut s = Sim {
            scenario: scenario.into(),
            seed,
            dice: Dice::new(seed),
            elapsed: 0,
            nodes: Vec::new(),
            things: Vec::new(),
            cfg,
            report: Report::default(),
            calm: false,
            queue: Vec::new(),
            trace: VecDeque::new(),
            check: Checker::default(),
        };
        for i in 0..s.cfg.nodes {
            let clock = s.cfg.clocks.get(i).copied().unwrap_or_default();
            let (peer, faults) = boot(s.dice.u64(), WallMs(wall_of(clock, 0))).map_err(|e| s.fail(format!("node {i} create: {e}")))?;
            s.nodes.push(Node { peer, faults, clock, up: true });
        }
        Ok(s)
    }

    pub fn fail(&self, what: impl Into<String>) -> Failure {
        Failure { scenario: self.scenario.clone(), seed: self.seed, step: self.report.steps, what: what.into(), trace: self.trace.iter().cloned().collect() }
    }

    fn note(&mut self, s: String) {
        if self.trace.len() == TRACE {
            self.trace.pop_front();
        }
        self.trace.push_back(format!("[{} t+{}ms] {s}", self.report.steps, self.elapsed));
    }

    fn node(&mut self, i: usize) -> Res<&mut Node> {
        let f = self.fail(format!("no node {i}"));
        self.nodes.get_mut(i).ok_or(f)
    }

    pub fn engine(&mut self, i: usize) -> Res<&mut Engine> {
        Ok(&mut self.node(i)?.peer.engine)
    }

    /// Node `i`'s read of `ak` on `t`.
    pub fn read(&mut self, i: usize, t: Tid, ak: &str) -> Res<Option<Value>> {
        let ak = osis_base::Ak::new(ak).map_err(|e| self.fail(e.to_string()))?;
        let r = self.engine(i)?.get(&t, &ak);
        r.map_err(|e| self.fail(format!("node {i} read: {e}")))
    }

    pub fn tid(&mut self, i: usize) -> Res<Tid> {
        Ok(self.engine(i)?.tid())
    }

    /// An engine error on node `i`: a crash takes it down; anything else fails the run.
    fn engine_err(&mut self, i: usize, what: &str, e: osis_node::Error) -> Res<()> {
        let n = self.node(i)?;
        if n.faults.crashed() {
            n.up = false;
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {i} crashed during {what}"));
            return Ok(());
        }
        Err(self.fail(format!("node {i} {what}: {e} ({:?})", e.class())))
    }

    /// Feeds node `i`'s engine events to the checker.
    fn drain(&mut self, i: usize) -> Res<()> {
        let Some(n) = self.nodes.get(i) else { return Ok(()) };
        let evs = n.peer.drain_events();
        for ev in evs {
            let r = match self.nodes.get(i) {
                Some(n) => self.check.event(i, &n.peer.engine, &ev),
                None => Ok(()),
            };
            r.map_err(|w| self.fail(w))?;
        }
        Ok(())
    }

    fn drain_all(&mut self) -> Res<()> {
        for i in 0..self.nodes.len() {
            self.drain(i)?;
        }
        Ok(())
    }

    // ---- setup helpers (scenarios)

    /// Node `i` commits `m` (errors fail the run).
    pub fn commit(&mut self, i: usize, m: Mutation) -> Res<Option<CommitId>> {
        let r = self.engine(i)?.commit(m);
        let r = r.map_err(|e| self.fail(format!("node {i} commit: {e}")))?;
        self.drain(i)?;
        Ok(r)
    }

    /// Node `i` creates a thing owned by `owner` (default: itself) and adds it to the write
    /// targets.
    pub fn create_thing(&mut self, i: usize, owner: Option<Tid>) -> Res<Tid> {
        let me = self.tid(i)?;
        let mut m = Mutation::new();
        let t = self.engine(i)?.new_thing(&mut m, owner.unwrap_or(me));
        m.set(t, &workload::REG, &Value::Str("new".into())).map_err(|e| self.fail(e.to_string()))?;
        self.commit(i, m)?;
        self.things.push(t);
        Ok(t)
    }

    /// Node `i` writes node `j`'s edge on `thing` (spec/permissions.md §2).
    pub fn grant(&mut self, i: usize, thing: Tid, j: usize, role: Role) -> Res<CommitId> {
        let member = self.tid(j)?;
        let edge = ct::Edge { role, until: None, invite: None, since: None };
        let mut m = Mutation::new();
        m.op(thing, &ct::MEMBERS, PathOp { path: vec![PathSeg::Key(Value::Tid(member))], op: Op::Set(edge.to_value()) }).map_err(|e| self.fail(e.to_string()))?;
        let id = self.commit(i, m)?;
        id.ok_or_else(|| self.fail("grant changed nothing"))
    }

    /// Node `i` removes node `j`'s edge on `thing` (spec/permissions.md §5).
    pub fn revoke(&mut self, i: usize, thing: Tid, j: usize) -> Res<CommitId> {
        let member = self.tid(j)?;
        let mut m = Mutation::new();
        m.op(thing, &ct::MEMBERS, PathOp { path: Vec::new(), op: Op::Remove(Value::Tid(member)) }).map_err(|e| self.fail(e.to_string()))?;
        let id = self.commit(i, m)?;
        id.ok_or_else(|| self.fail("removal changed nothing"))
    }

    /// Moves virtual time on by `ms`, sets every clock, and ticks every node that is up.
    pub fn advance(&mut self, ms: u64) -> Res<()> {
        self.elapsed = self.elapsed.saturating_add(ms);
        for n in &self.nodes {
            n.peer.clock.set(WallMs(wall_of(n.clock, self.elapsed)));
        }
        for i in 0..self.nodes.len() {
            if !self.node(i)?.up {
                continue;
            }
            let r = self.engine(i)?.tick();
            if let Err(e) = r {
                self.engine_err(i, "tick", e)?;
            }
        }
        self.drain_all()
    }

    /// Changes node `i`'s clock (a jump, then the new skew and drift).
    pub fn set_clock(&mut self, i: usize, c: ClockSpec) -> Res<()> {
        self.node(i)?.clock = c;
        self.advance(0)
    }

    /// Delivers one package to node `i` now, with no faults.
    pub fn deliver(&mut self, i: usize, pkg: &Package) -> Res<Option<Ingested>> {
        if !self.node(i)?.up {
            return Ok(None);
        }
        let r = self.engine(i)?.ingest(&pkg.bytes, pkg.blobs.clone());
        let out = match r {
            Ok(x) => {
                if matches!(x, Ingested::Pending(..) | Ingested::Parked(..)) {
                    self.report.parked = self.report.parked.saturating_add(1);
                }
                self.note(format!("node {i} ingest {:?}", x));
                Some(x)
            }
            Err(e) if e.class() == ErrorClass::BadInput => return Err(self.fail(format!("node {i}: honest commit {:?} rejected as bad input: {e}", pkg.id))),
            Err(e) => {
                self.engine_err(i, "ingest", e)?;
                None
            }
        };
        self.report.delivered = self.report.delivered.saturating_add(1);
        self.drain(i)?;
        Ok(out)
    }

    /// Packages of the commits node `from` holds that `to` does not (anti-entropy oracle; the
    /// sync protocol's reconciliation replaces it in phase B).
    fn missing(&mut self, from: usize, to: usize) -> Res<Vec<Package>> {
        let theirs = check::held(&self.node(to)?.peer.engine);
        let ids: Vec<CommitId> = self.engine(from)?.commit_ids().into_iter().filter(|c| !theirs.contains(c)).collect();
        let mut out = Vec::new();
        for id in ids {
            match self.engine(from)?.package(&id) {
                Ok(Some(p)) => out.push(p),
                Ok(None) => {}
                Err(e) => {
                    self.engine_err(from, "package", e)?;
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    /// Exchanges every missing commit between every pair of up nodes, without faults, until
    /// nothing moves.
    pub fn sync_all(&mut self) -> Res<()> {
        for _ in 0..=self.nodes.len() {
            let mut moved = false;
            for a in 0..self.nodes.len() {
                for b in 0..self.nodes.len() {
                    if a == b || !self.node(a)?.up || !self.node(b)?.up {
                        continue;
                    }
                    for p in self.missing(a, b)? {
                        if let Some(Ingested::Applied(_)) = self.deliver(b, &p)? {
                            moved = true;
                        }
                    }
                }
            }
            if !moved {
                break;
            }
        }
        Ok(())
    }

    // ---- the scheduler

    /// One scheduler event.
    pub fn step(&mut self) -> Res<()> {
        self.report.steps = self.report.steps.saturating_add(1);
        let w = self.cfg.weights;
        let any_up = self.nodes.iter().any(|n| n.up);
        let any_down = self.nodes.iter().any(|n| !n.up);
        let calm = self.calm;
        let options: [(u32, u8); 6] = [
            (if any_up && !calm { w.write } else { 0 }, 0),
            (if any_up && self.nodes.len() > 1 { w.gossip } else { 0 }, 1),
            (if self.queue.is_empty() { 0 } else { w.deliver }, 2),
            (w.tick.max(1), 3),
            (if any_up && !calm { w.crash } else { 0 }, 4),
            (if any_down { w.restart.max(u32::from(calm)) } else { 0 }, 5),
        ];
        let total: u64 = options.iter().map(|o| u64::from(o.0)).sum();
        let mut r = self.dice.below(total);
        let mut pick = 3;
        for (wt, a) in options {
            if r < u64::from(wt) {
                pick = a;
                break;
            }
            r -= u64::from(wt);
        }
        match pick {
            0 => self.random_write()?,
            1 => self.gossip()?,
            2 => self.deliver_next()?,
            4 => self.crash()?,
            5 => self.restart_one()?,
            _ => {
                let dt = 1 + self.dice.below(self.cfg.max_tick_ms.max(1));
                self.advance(dt)?;
            }
        }
        if self.cfg.check_every_step {
            self.check_convergence()?;
        }
        Ok(())
    }

    /// `n` scheduler events.
    pub fn run(&mut self, n: u64) -> Res<()> {
        for _ in 0..n {
            self.step()?;
        }
        Ok(())
    }

    fn up_nodes(&self) -> Vec<usize> {
        (0..self.nodes.len()).filter(|i| self.nodes.get(*i).is_some_and(|n| n.up)).collect()
    }

    /// A random up node writes 1..=3 random ops on things it may write.
    fn random_write(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        let Some(&i) = self.dice.pick(&ups) else { return Ok(()) };
        let things = self.things.clone();
        let e = self.engine(i)?;
        let writable: Vec<Tid> = things.into_iter().filter(|t| e.role_on(t).is_some_and(|r| r >= Role::Write)).collect();
        if writable.is_empty() {
            return Ok(());
        }
        let mut m = Mutation::new();
        for _ in 0..1 + self.dice.below(3) {
            let Some(&t) = self.dice.pick(&writable) else { continue };
            workload::random_op(&mut self.dice, &mut m, t).map_err(|e| self.fail(format!("building op: {e}")))?;
        }
        let r = self.engine(i)?.commit(m);
        match r {
            Ok(id) => {
                self.report.writes = self.report.writes.saturating_add(1);
                self.note(format!("node {i} write {id:?}"));
            }
            Err(e) => self.engine_err(i, "write", e)?,
        }
        self.drain(i)
    }

    /// A random up node sends a random other node what it lacks, through the faults.
    fn gossip(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        let Some(&from) = self.dice.pick(&ups) else { return Ok(()) };
        let others: Vec<usize> = (0..self.nodes.len()).filter(|j| *j != from).collect();
        let Some(&to) = self.dice.pick(&others) else { return Ok(()) };
        let pkgs = self.missing(from, to)?;
        self.note(format!("node {from} -> {to}: {} packages", pkgs.len()));
        let net = self.cfg.net;
        for p in pkgs {
            self.report.sent = self.report.sent.saturating_add(1);
            if self.dice.pct(net.drop_pct) {
                self.report.dropped = self.report.dropped.saturating_add(1);
                continue;
            }
            let copies = if self.dice.pct(net.dup_pct) { 2 } else { 1 };
            for _ in 0..copies {
                let at = self.elapsed.saturating_add(self.dice.below(net.max_delay_ms.saturating_add(1)));
                self.queue.push(Msg { to, at, pkg: p.clone() });
            }
        }
        Ok(())
    }

    /// Delivers a due message (the earliest, or any due one under reorder); waits for the
    /// earliest when none is due.
    fn deliver_next(&mut self) -> Res<()> {
        let Some(first) = self.queue.iter().map(|m| m.at).min() else { return Ok(()) };
        if first > self.elapsed {
            self.advance(first - self.elapsed)?;
        }
        let due: Vec<usize> = (0..self.queue.len()).filter(|k| self.queue.get(*k).is_some_and(|m| m.at <= self.elapsed)).collect();
        let k = if self.cfg.net.reorder { self.dice.pick(&due).copied() } else { due.first().copied() };
        let Some(k) = k else { return Ok(()) };
        let m = self.queue.remove(k);
        self.deliver(m.to, &m.pkg)?;
        Ok(())
    }

    /// Crashes a random up node: now, or at one of its next few durable writes (mid-write).
    fn crash(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        if ups.len() < 2 {
            return Ok(());
        }
        let Some(&i) = self.dice.pick(&ups) else { return Ok(()) };
        let at = self.dice.below(4);
        let now = self.dice.pct(50);
        let n = self.node(i)?;
        if now {
            n.up = false;
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {i} crashed"));
        } else {
            n.faults.at(at, Fault::Crash);
            self.note(format!("node {i} will crash at its write {at}"));
        }
        Ok(())
    }

    fn restart_one(&mut self) -> Res<()> {
        let down: Vec<usize> = (0..self.nodes.len()).filter(|i| self.nodes.get(*i).is_some_and(|n| !n.up)).collect();
        let Some(&i) = self.dice.pick(&down) else { return Ok(()) };
        self.restart(i)
    }

    /// Powers node `i` up again over its durable state (spec: storage recovers from a crash).
    pub fn restart(&mut self, i: usize) -> Res<()> {
        let seed = self.dice.u64();
        let n = self.node(i)?;
        n.faults.revive();
        let r = n.peer.restart(seed);
        r.map_err(|e| self.fail(format!("node {i} restart: {e}")))?;
        self.node(i)?.up = true;
        self.report.restarts = self.report.restarts.saturating_add(1);
        self.note(format!("node {i} restarted"));
        self.drain(i)
    }

    // ---- invariants

    /// spec/requirements.md (convergence) over the nodes that are up.
    pub fn check_convergence(&mut self) -> Res<()> {
        let mut es: Vec<(usize, &mut Engine)> = self.nodes.iter_mut().enumerate().filter(|(_, n)| n.up).map(|(i, n)| (i, &mut n.peer.engine)).collect();
        let r = check::convergence(&mut es);
        r.map_err(|w| self.fail(w))
    }

    /// Stops writes and crashes, brings every node up, delivers everything and syncs every pair
    /// without faults, letting time pass for parked commits, until nothing moves and nothing
    /// pends; then checks the quiescent invariants. Fails if that takes more than `max_rounds`.
    pub fn run_until_quiescent(&mut self, max_rounds: u64) -> Res<()> {
        self.calm = true;
        for i in 0..self.nodes.len() {
            self.node(i)?.faults.revive();
            if !self.node(i)?.up {
                self.restart(i)?;
            }
        }
        for round in 0..max_rounds {
            while !self.queue.is_empty() {
                self.deliver_next()?;
            }
            let before = self.fingerprint();
            self.sync_all()?;
            if self.fingerprint() == before && self.queue.is_empty() {
                let pending = self.nodes.iter().any(|n| !n.peer.engine.pending().is_empty());
                if !pending {
                    self.note(format!("quiescent after {round} rounds"));
                    self.check_quiescent()?;
                    self.calm = false;
                    return Ok(());
                }
                // parked commits wait for local time (spec/crdt.md §2.2)
                self.advance(10 * 60_000)?;
            }
        }
        let p: Vec<usize> = self.nodes.iter().map(|n| n.peer.engine.pending().len()).collect();
        Err(self.fail(format!("not quiescent after {max_rounds} rounds; pending per node {p:?}")))
    }

    fn fingerprint(&self) -> Vec<(usize, usize)> {
        self.nodes.iter().map(|n| (n.peer.engine.commit_ids().len(), n.peer.engine.pending().len())).collect()
    }

    /// Quiescent invariants: same commits everywhere, nothing pending, reads converge.
    pub fn check_quiescent(&mut self) -> Res<()> {
        let es: Vec<(usize, &Engine)> = self.nodes.iter().enumerate().map(|(i, n)| (i, &n.peer.engine)).collect();
        let r = check::quiescent(&es);
        r.map_err(|w| self.fail(w))?;
        self.check_convergence()?;
        self.finish_report()
    }

    fn finish_report(&mut self) -> Res<()> {
        let mut h = osis_base::hash::Hasher::new();
        let mut commits = BTreeSet::new();
        for i in 0..self.nodes.len() {
            let e = self.engine(i)?;
            for c in e.commit_ids() {
                h.update(&c.0);
                commits.insert(c);
            }
            let r = check::reads(e).map_err(|x| self.fail(format!("read: {x}")))?;
            h.update(format!("{r:?}").as_bytes());
        }
        self.report.commits = commits.len();
        self.report.digest = h.finalize();
        Ok(())
    }
}

/// A clock's wall time after `elapsed` ms of virtual time.
pub fn wall_of(c: ClockSpec, elapsed: u64) -> u64 {
    let e = i128::from(elapsed);
    let w = i128::from(T0) + e + i128::from(c.skew_ms) + e * i128::from(c.drift_ppm) / 1_000_000;
    u64::try_from(w.max(0)).unwrap_or(0)
}
