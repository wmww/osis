//! The harness: nodes (real engines over `MemoryBackend`s with a shared fault plan), virtual
//! time, per-node clocks, an in-flight message queue, and a seeded scheduler choosing the next
//! event. Everything is driven from one `Dice`, so (scenario, seed) replays exactly.

use crate::check::{self, Checker};
use crate::dice::Dice;
use crate::workload;
use osis_base::{Classified, Clock, CommitId, ErrorClass, ManualClock, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp};
use osis_crypto::SeededRng;
use osis_engine::local_peer::{Package, Peer};
use osis_engine::{Engine, Ingested, Mutation};
use osis_schema::core_types as ct;
use osis_store::{Fault, Faults, MemoryBackend, MemoryRoot};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::Arc;

/// Wall time at the start of every run.
pub const T0: u64 = 1_700_000_000_000;
const TRACE: usize = 40;

/// A failed invariant (or a panic, or an engine error on honest input), with the seed that
/// replays it.
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
}

impl Default for Config {
    fn default() -> Config {
        Config { nodes: 2, clocks: Vec::new(), net: NetFaults::default(), weights: Weights::default(), max_tick_ms: 5_000 }
    }
}

/// One simulated node.
pub struct Node {
    pub peer: Peer,
    /// The account it acts for (spec/permissions.md §8), made at its start.
    pub account: Tid,
    /// Its account's profile, holding the account's card (its keys, its inbox among them,
    /// spec/sync-inbox.md §1).
    pub profile: Tid,
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
    /// Planned one-off failed writes that happened (`Fault::Fail`: the device stays up).
    pub failed_writes: u64,
    /// (node, write, thing) triples the history check found held at quiet (`Sim::check_history`).
    pub history_checked: u64,
    pub commits: usize,
    /// BLAKE3 of every node's final held commits and reads: replays alike to the bit.
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
    /// Each node's held set and reads at its last convergence check.
    views: check::Views,
    /// What the run played: the oracle of what each node holds at quiet (`check_history`).
    history: History,
}

/// What a run played, as the harness played it: things made, roles given and taken, content
/// written. What each node must hold at quiet is computed from it (`Sim::check_history`), apart
/// from what any node sends.
#[derive(Clone, Debug, Default)]
pub struct History {
    /// Thing -> (maker node, its mint admin, if any).
    made: BTreeMap<Tid, (usize, Option<Tid>)>,
    /// (thing, node) -> the role given it last (`grant`), `None` once removed (`revoke`).
    roles: BTreeMap<(Tid, usize), Option<Role>>,
    /// (thing, node) once removed: its writes there are judged by the removal's frontier, which
    /// the history does not hold, so none is expected.
    removed: BTreeSet<(Tid, usize)>,
    /// Content commits played: (writer node, commit, things written).
    writes: Vec<(usize, CommitId, BTreeSet<Tid>)>,
}

impl History {
    /// Node `n`'s role on `t` by the history: its maker's admin, a role given it, or its role on
    /// `t`'s mint admin (spec/permissions.md §1, the record chain).
    fn role(&self, n: usize, t: &Tid) -> Option<Role> {
        let mut best = self.roles.get(&(*t, n)).copied().flatten();
        let mut at = *t;
        for _ in 0..=self.made.len() {
            let Some((maker, under)) = self.made.get(&at) else { break };
            if *maker == n && under.is_none() {
                return Some(Role::Admin);
            }
            let Some(u) = under else { break };
            best = best.max(self.roles.get(&(*u, n)).copied().flatten());
            at = *u;
        }
        best
    }

    /// Whether `n`'s writes on `t` can be judged from the history: never removed there nor above.
    fn kept(&self, n: usize, t: &Tid) -> bool {
        let mut at = Some(*t);
        while let Some(x) = at {
            if self.removed.contains(&(x, n)) {
                return false;
            }
            at = self.made.get(&x).and_then(|m| m.1);
        }
        true
    }
}

fn boot(seed: u64, t: WallMs) -> osis_engine::Result<(Peer, Faults)> {
    let faults = Faults::new();
    let clock = Arc::new(ManualClock::new(t));
    let backend = MemoryBackend::with_faults(faults.clone());
    let root = MemoryRoot::with_faults(faults.clone());
    let c: Arc<dyn Clock> = clock.clone();
    let blob_disk = (MemoryBackend::with_faults(faults.clone()), MemoryRoot::with_faults(faults.clone()));
    let mut engine = Engine::create(Box::new(backend.clone()), Box::new(root.clone()), osis_engine::local_peer::blob_area(&blob_disk, seed)?, osis_engine::Config::default(), c, Box::new(SeededRng::from_u64(seed)))?;
    engine.take_wakes();
    let events = engine.subscribe();
    Ok((Peer { engine, clock, backend, root, blob_disk, events, restarts: 0, discarded: Vec::new(), discards: 0, redelivered: 0, pulled_anew: Default::default(), given: Default::default(), offers: Default::default(), entries: Default::default() }, faults))
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
            views: check::Views::default(),
            history: History::default(),
        };
        for i in 0..s.cfg.nodes {
            let clock = s.cfg.clocks.get(i).copied().unwrap_or_default();
            let (mut peer, faults) = boot(s.dice.u64(), WallMs(wall_of(clock, 0))).map_err(|e| s.fail(format!("node {i} create: {e}")))?;
            let (made, _) = osis_engine::local_peer::make_account(&mut peer.engine).map_err(|e| s.fail(format!("node {i} account: {e}")))?;
            s.nodes.push(Node { peer, account: made.thing, profile: made.profile, faults, clock, up: true });
        }
        // each account is every other's contact (spec/sync-inbox.md §5): its profile is public and
        // its contact card a locator of it, which each other node follows until the profile
        // is here, then redeems (a strong from its account, spec/sync-set.md §4); the profile
        // carries the account's card, so a fire reaches the inbox its keys name
        let mut links = Vec::new();
        for i in 0..s.nodes.len() {
            let profile = s.node(i)?.profile;
            let l = s.engine(i)?.locator(&profile, Vec::new());
            links.push(l.map_err(|e| s.fail(format!("node {i} contact card: {e}")))?.ok_or_else(|| s.fail(format!("node {i}'s profile is not public")))?);
        }
        let pairs: Vec<(usize, usize, osis_blob::Locator)> = (0..links.len()).flat_map(|j| links.iter().enumerate().filter(move |(i, _)| *i != j).map(move |(i, l)| (j, i, l.clone()))).collect();
        for (j, _, l) in &pairs {
            s.engine(*j)?.follow_public(l);
        }
        s.sync_all()?;
        for (j, i, l) in &pairs {
            let a = s.account(*j)?;
            let e = s.engine(*j)?;
            let r = e.redeem_public(l, &a).and_then(|_| e.take_carried());
            r.map_err(|e| s.fail(format!("node {j} imports node {i}'s contact card: {e}")))?;
            s.engine(*j)?.unfollow_link(&l.target);
            s.drain(*j)?;
        }
        s.sync_all()?;
        Ok(s)
    }

    pub fn fail(&self, what: impl Into<String>) -> Failure {
        Failure { scenario: self.scenario.clone(), seed: self.seed, step: self.report.steps, what: what.into(), trace: self.trace.iter().cloned().collect() }
    }

    /// Keeps the last `TRACE` lines for a failure's report; with `OSIS_SIM_TRACE=1` prints every
    /// line as it happens too (a wait that began earlier than the kept tail shows).
    fn note(&mut self, s: String) {
        static ALL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if self.trace.len() == TRACE {
            self.trace.pop_front();
        }
        let line = format!("[{} t+{}ms] {s}", self.report.steps, self.elapsed);
        if *ALL.get_or_init(|| osis_base::testenv::u64_var("OSIS_SIM_TRACE").is_some_and(|n| n != 0)) {
            eprintln!("{} {line}", self.scenario);
        }
        self.trace.push_back(line);
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

    /// The account node `i` acts for: what it grants, is granted and makes things in.
    pub fn account(&mut self, i: usize) -> Res<Tid> {
        Ok(self.node(i)?.account)
    }

    /// An engine error on node `i`: a crash takes it down; a planned failed write this step
    /// failed the call, the node stays up; anything else fails the run.
    fn engine_err(&mut self, i: usize, what: &str, e: osis_engine::Error) -> Res<()> {
        let n = self.node(i)?;
        if n.faults.crashed() {
            n.up = false;
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {i} crashed during {what}"));
            return Ok(());
        }
        if n.faults.take_failed() {
            self.report.failed_writes = self.report.failed_writes.saturating_add(1);
            self.note(format!("node {i}: a write failed during {what}: {e}"));
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
        if let Some(id) = r {
            self.wrote(i, id)?;
        }
        Ok(r)
    }

    /// Notes node `i`'s commit `id` in the history, as a write on the things its content parts name.
    fn wrote(&mut self, i: usize, id: CommitId) -> Res<()> {
        let Some(h) = self.engine(i)?.header(&id) else { return Ok(()) };
        // the sim schema's aspects: what `workload` and scenarios write
        let things: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str().starts_with("s:")).map(|a| a.tid).collect();
        if !things.is_empty() {
            self.history.writes.push((i, id, things));
        }
        Ok(())
    }

    /// Node `i` creates a thing whose mint admin is `admin` (default: its account) and adds it to
    /// the write targets.
    pub fn create_thing(&mut self, i: usize, admin: Option<Tid>) -> Res<Tid> {
        let me = self.account(i)?;
        let mut m = Mutation::new();
        let t = self.engine(i)?.new_thing(&mut m, admin.unwrap_or(me));
        m.set(t, &workload::REG, &Value::Str("new".into())).map_err(|e| self.fail(e.to_string()))?;
        self.history.made.insert(t, (i, admin));
        self.commit(i, m)?;
        self.things.push(t);
        Ok(t)
    }

    /// Node `i` writes the edge of node `j`'s account on `thing` (spec/permissions.md §2), signalling
    /// it; node `j` holds `thing` from its node root, as a node keeps and writes only what it holds
    /// (spec/sync-set.md §2).
    pub fn grant(&mut self, i: usize, thing: Tid, j: usize, role: Role) -> Res<CommitId> {
        let holder = self.account(j)?;
        let edge = ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        // the grant and its signal to the holder, as the `osis` library's grant (spec/sync-set.md
        // §2 First entry: a grant reaches its holder by a signal or a reference)
        let e = self.engine(i)?;
        let r = e.grant(&thing, &holder, &edge).and_then(|d| e.signal_grant(&thing, &holder, &[]).map(|()| d));
        let done = r.map_err(|e| self.fail(format!("node {i} grant: {e}")))?;
        self.drain(i)?;
        self.history.roles.insert((thing, j), Some(role));
        if !self.engine(j)?.closure_holds(&thing) {
            let r = self.engine(j)?.hold(osis_base::Strong(thing));
            r.map_err(|e| self.fail(format!("node {j} hold: {e}")))?;
            self.drain(j)?;
        }
        done.commits.last().copied().ok_or_else(|| self.fail("grant changed nothing"))
    }

    /// Node `i` removes the edge of node `j`'s account on `thing` (spec/permissions.md §5).
    pub fn revoke(&mut self, i: usize, thing: Tid, j: usize) -> Res<CommitId> {
        let holder = self.account(j)?;
        let mut m = Mutation::new();
        m.op(thing, &ct::ROLES, PathOp { path: Vec::new(), op: Op::Remove(Value::Weak(holder)) }).map_err(|e| self.fail(e.to_string()))?;
        // an explicit removal: with no frontier it would be a finalize (spec/permissions.md §2)
        m.frontier(osis_engine::Frontier::default());
        self.history.roles.insert((thing, j), None);
        self.history.removed.insert((thing, j));
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

    /// Node `from` offers node `to` each sealed fire it owes that account (spec/sync-inbox.md §3
    /// Sending, as a sync's fire step does, apart from its commits), and owes one no more once
    /// taken. A fire refused fails the run: every fire offered here is on an
    /// account's inbox.
    pub fn fires(&mut self, from: usize, to: usize) -> Res<()> {
        if !self.node(from)?.up || !self.node(to)?.up {
            return Ok(());
        }
        let account = self.account(to)?;
        for id in self.engine(from)?.fires_owed() {
            let out = match self.engine(from)?.sealed_fire(&id) {
                Ok(out) => out,
                // an injected fault or crash: the fire stays owed
                Err(e) => return self.engine_err(from, "seal a fire", e),
            };
            let Some(out) = out.filter(|o| o.to.contains(&account)) else { continue };
            match self.engine(to)?.offer_fire(&out) {
                Ok(osis_engine::sync::Opened::Commit(..)) => {
                    self.note(format!("node {to} takes a fire of node {from}"));
                    if let Err(e) = self.engine(from)?.fire_taken(&id) {
                        return self.engine_err(from, "fire taken", e);
                    }
                }
                Ok(osis_engine::sync::Opened::NotOpen) => {}
                Ok(r) => return Err(self.fail(format!("node {to} refuses a fire of node {from}: {r:?}"))),
                Err(e) => return self.engine_err(to, "take a fire", e),
            }
        }
        if let Err(e) = self.engine(to)?.take_carried() {
            return self.engine_err(to, "take what its fires carry", e);
        }
        self.drain(from)?;
        self.drain(to)
    }

    /// Packages of the commits node `from` holds that `to` lacks, wholly or by a part `from`
    /// holds, each holding what the sync IDs `to` syncs carry as `from` sees them and its
    /// certificate parts (`Engine::sent_parts`, as a sync sends: anti-entropy oracle; phase B's
    /// nodes fetch entries by blob, so parts come the same way there).
    fn missing(&mut self, from: usize, to: usize) -> Res<Vec<Package>> {
        let theirs = check::held(&self.node(to)?.peer.engine);
        let ours = check::held(self.engine(from)?);
        let lacks = |c: &CommitId| theirs.get(c).is_none_or(|gaps| ours.get(c).is_some_and(|mine| gaps.difference(mine).next().is_some()));
        let ids: Vec<CommitId> = self.engine(from)?.commit_ids().into_iter().filter(lacks).collect();
        let synced: BTreeSet<osis_base::SyncId> = match self.engine(to)?.sync_set() {
            Ok(s) => s.ids.keys().copied().collect(),
            Err(e) => {
                self.engine_err(to, "sync set", e)?;
                return Ok(Vec::new());
            }
        };
        let mut out = Vec::new();
        for id in ids {
            let e = self.engine(from)?;
            let r = e.sent_parts(&id, &synced).and_then(|parts| match parts {
                Some(parts) => e.package_of_parts(&id, &parts),
                None => Ok(None),
            });
            match r {
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
                    self.fires(a, b)?;
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
        osis_base::testenv::checkpoint();
        self.report.steps = self.report.steps.saturating_add(1);
        // a failed write excuses an error of the step it happened in only; one nothing excused
        // (a commit that landed) is counted here
        for n in &self.nodes {
            self.report.failed_writes = self.report.failed_writes.saturating_add(u64::from(n.faults.take_failed()));
        }
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
        self.check_convergence()
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

    /// A random up node writes 1..=3 random ops on things it holds and may write (a node writes
    /// only what it holds, spec/sync-set.md §2 Writing). One its offer gave a role on before its
    /// minting arrived is refused (`UnknownThing`), as the API refuses it.
    fn random_write(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        let Some(&i) = self.dice.pick(&ups) else { return Ok(()) };
        let things = self.things.clone();
        let e = self.engine(i)?;
        let writable: Vec<Tid> = things.into_iter().filter(|t| e.closure_holds(t) && e.role_on(t).is_some_and(|r| r >= Role::Write)).collect();
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
                if let Some(id) = id {
                    self.wrote(i, id)?;
                }
            }
            Err(osis_engine::Error::UnknownThing(t)) => self.note(format!("node {i} write refused: {t} not arrived")),
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
        // the fire step of the same sync, lost whole as any message is
        if !self.dice.pct(self.cfg.net.drop_pct) {
            self.fires(from, to)?;
        }
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

    /// Crashes a random up node: now, or at one of its next few durable writes (mid-write); or
    /// fails one of those writes alone (the node stays up and its next calls must work).
    fn crash(&mut self) -> Res<()> {
        let ups = self.up_nodes();
        if ups.len() < 2 {
            return Ok(());
        }
        let Some(&i) = self.dice.pick(&ups) else { return Ok(()) };
        let at = self.dice.below(4);
        let now = self.dice.pct(50);
        let crash = now || self.dice.pct(50);
        let n = self.node(i)?;
        if now {
            n.up = false;
            self.report.crashes = self.report.crashes.saturating_add(1);
            self.note(format!("node {i} crashed"));
        } else if crash {
            n.faults.at(at, Fault::Crash);
            self.note(format!("node {i} will crash at its write {at}"));
        } else {
            n.faults.at(at, Fault::Fail);
            self.note(format!("node {i} will fail its write {at}"));
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
        let r = check::convergence(&mut es, &self.views);
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

    fn fingerprint(&self) -> Vec<(check::Held, usize)> {
        self.nodes.iter().map(|n| (check::held(&n.peer.engine), n.peer.engine.pending().len())).collect()
    }

    /// Quiescent invariants: nothing pending; every node holds each part another node sends it
    /// (`missing`: what the sync IDs it syncs carry as the sender sees them, and certificates);
    /// reads converge.
    pub fn check_quiescent(&mut self) -> Res<()> {
        let es: Vec<(usize, &Engine)> = self.nodes.iter().enumerate().map(|(i, n)| (i, &n.peer.engine)).collect();
        let r = check::quiescent(&es);
        r.map_err(|w| self.fail(w))?;
        for a in 0..self.nodes.len() {
            for b in (0..self.nodes.len()).filter(|b| *b != a) {
                let theirs = check::held(&self.node(b)?.peer.engine);
                for p in self.missing(a, b)? {
                    let parts: BTreeSet<usize> = osis_commit::CommitBlob::decode(&p.bytes).map(|x| x.parts.iter().map(|q| q.ai).collect()).unwrap_or_default();
                    let lacks = theirs.get(&p.id).is_none_or(|gaps| parts.iter().any(|ai| gaps.contains(ai)));
                    if lacks {
                        return Err(self.fail(format!("at quiescence node {b} lacks what node {a} sends it of {:?} (parts {parts:?}; holds it: {})", p.id, theirs.contains_key(&p.id))));
                    }
                }
            }
        }
        self.check_history()?;
        // read every node afresh: the per-step views trust what their reads recorded, this does not
        self.views = check::Views::default();
        self.check_convergence()?;
        self.finish_report()
    }

    /// At quiet, what each node holds by the history alone (`History`), whatever any node sends:
    /// each thing node `n` reads by it (made or given read or above, or reached through its mint
    /// admin: spec/sync-set.md §1-§2, as `grant` and `create_thing` hold it), and on each
    /// such thing every content commit the history played whose writer may write there and was
    /// never removed there (`History::kept`): `n` holds the commit, no part of it on that thing
    /// missing (spec/commits.md §4: every node is up and synced at quiet). The sender-defined
    /// check above cannot see a sender that never carries some content; this one can.
    fn check_history(&mut self) -> Res<()> {
        let h = self.history.clone();
        for n in 0..self.nodes.len() {
            let held = check::held(self.engine(n)?);
            for (w, c, things) in &h.writes {
                for t in things.iter().filter(|t| h.role(n, t).is_some_and(|r| r >= Role::Read) && h.role(*w, t).is_some_and(|r| r >= Role::Write) && h.kept(*w, t)) {
                    let header = self.engine(n)?.header(c);
                    let gaps = held.get(c);
                    let lacks = match (header, gaps) {
                        (Some(hd), Some(g)) => hd.aspects.iter().enumerate().any(|(ai, a)| a.tid == *t && g.contains(&ai)),
                        _ => true,
                    };
                    if lacks {
                        return Err(self.fail(format!("at quiescence node {n} lacks node {w}'s write {c:?} on {t}, which it reads by the history (holds the commit: {})", gaps.is_some())));
                    }
                    self.report.history_checked = self.report.history_checked.saturating_add(1);
                }
            }
        }
        Ok(())
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
