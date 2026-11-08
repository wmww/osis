//! Synced ephemeral data in the simulator (notes/ephemeral.md, spec/sync.md §9): random
//! ephemeral (expiring ones included) and signal writes on items of labeled groups (windows
//! among them, made amid the faults), and their invariants at quiescence (`check`):
//! - convergence among holders (spec/requirements.md Ephemeral data), within what a host cap
//!   lets through (spec/sync.md §5: a host whose cap keeps out an entry an up node holds,
//!   checked against the host's own accounting, is no path): reader nodes connected through
//!   the other hosts read the same ephemeral state of an item; expired writes (typing flags,
//!   cursors) read absent everywhere.
//! - own compaction (spec/sync.md §9): each up node's own held plain commits without expiry
//!   cost at most twice their cover plus one commit in flight.
//! - ephemeral signals (spec/sync.md §9 Relay-only commits): delivered at most once per node over the run
//!   (checked as events arrive).
//! - bounded host memory (spec/sync.md §5): every label's ephemeral charge within its cap,
//!   the total within the host's.
//!
//! Scenario helpers check two more after quiescence: `author_leaves` (a cursor its author keeps
//! refreshing stays up at every connected reader; once the author goes away it goes everywhere
//! by its last write's expiry) and `signal_reaches` (an ephemeral signal reaches each connected reader
//! once).

use super::scenarios::{clock, persons, shared_group, sim};
use super::{NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use osis_host::HostPolicy;
use osis_base::{Ak, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::Event;
use osis_proto::LabelStore;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// `map<string, string>`, ephemeral.
pub const NOTES: &str = "e:notes+.0";
/// A string, ephemeral.
pub const STATE: &str = "e:state+.0";
/// A bool written with an expiry 5-30 s out (a typing indicator).
pub const TYPING: &str = "e:typing+.0";
/// A map from the author's node index to its cursor, each write a fresh entry at the author's
/// key expiring `CURSOR_MS` out, refreshed by its author while there (as `osis::KeepAlive`
/// does).
pub const CURSOR: &str = "e:cursor+.0";
/// A cursor write's expiry, from the write.
pub const CURSOR_MS: u64 = 30_000;
/// Signal: a unique string per write.
pub const RING: &str = "e:ring+~0";


#[derive(Clone, Debug, Default)]
pub struct Track {
    /// Things (with their group) whose ephemeral aspects random writes touch.
    pub things: Vec<(Tid, Tid)>,
    /// Signal deliveries per (node, value).
    pub delivered: BTreeMap<(usize, String), u32>,
    /// Restarts per node and host.
    pub boots: BTreeMap<Party, u64>,
    /// Values written so far (unique values).
    pub next: u64,
}

impl NetSim {
    fn eph_ak(&self, ak: &str) -> Res<Ak> {
        Ak::new(ak).map_err(|e| self.fail(e.to_string()))
    }

    /// Node `n` makes a window under and added to `g`, then sets its state, and tracks it; none
    /// when the node crashed making it.
    pub fn window(&mut self, n: usize, g: Tid) -> Res<Option<Tid>> {
        let state = self.eph_ak(STATE)?;
        let e = self.engine(n)?;
        let mut m = Mutation::new();
        let w = e.new_thing(&mut m, g);
        let add = PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) };
        m.op(g, &ct::GROUP, add).map_err(|e| self.fail(e.to_string()))?;
        // a crash in the write, or in the sync step after it (the window then stays untracked)
        if self.write(n, m)?.is_empty() || !self.is_up(n) {
            return Ok(None);
        }
        self.note(format!("node {n} makes window {w}"));
        let mut m = Mutation::new();
        m.set(w, &state, &Value::Str("w".into())).map_err(|e| self.fail(e.to_string()))?;
        self.eph_write(n, m, format!("sets window {w}"))?;
        self.eph.things.push((w, g));
        Ok(Some(w))
    }

    /// A random up node of `ns` makes a window in `g` (none if all are down).
    pub fn window_by_any(&mut self, ns: &[usize], g: Tid) -> Res<()> {
        let ups: Vec<usize> = ns.iter().copied().filter(|n| self.is_up(*n)).collect();
        if let Some(&n) = self.dice.pick(&ups) {
            self.window(n, g)?;
        }
        Ok(())
    }

    /// Random ephemeral writes also touch durable thing `t` of group `g`.
    pub fn track_ephemeral(&mut self, t: Tid, g: Tid) {
        self.eph.things.push((t, g));
    }

    /// Node `n` writes `m`, then its sync engine looks.
    pub fn eph_write(&mut self, n: usize, m: Mutation, what: String) -> Res<()> {
        let r = self.engine(n)?.write(m);
        r.map_err(|e| self.fail(format!("node {n} ephemeral write ({what}): {e}")))?;
        self.report.writes = self.report.writes.saturating_add(1);
        self.note(format!("node {n} {what}"));
        self.feed(n, Event::Local)
    }

    /// Targets node `n` may write ephemerally: tracked things it holds and writes.
    fn eph_targets(&mut self, n: usize) -> Res<Vec<Tid>> {
        let things = self.eph.things.clone();
        let e = self.engine(n)?;
        Ok(things.into_iter().map(|x| x.0).filter(|t| e.knows(t) && e.role_on(t).is_some_and(|r| r >= Role::Write)).collect())
    }

    /// A random up node writes one ephemeral op on a target it may write: a note set or
    /// removed, the state, an expiring typing flag, its expiring cursor or a signal.
    pub(super) fn random_ephemeral(&mut self) -> Res<()> {
        let ups: Vec<usize> = (0..self.nodes.len()).filter(|i| self.is_up(*i)).collect();
        let Some(&n) = self.dice.pick(&ups) else { return Ok(()) };
        let targets = self.eph_targets(n)?;
        let Some(&t) = self.dice.pick(&targets) else { return Ok(()) };
        self.eph.next += 1;
        let k = self.eph.next;
        let mut m = Mutation::new();
        let what = match self.dice.below(12) {
            4 if matches!(self.eph_read(n, &t, NOTES)?, Some(Value::Map(_))) => {
                let key = format!("k{}", self.dice.below(5));
                let op = PathOp { path: Vec::new(), op: Op::Remove(Value::Str(key.clone())) };
                m.op(t, &self.eph_ak(NOTES)?, op).map_err(|e| self.fail(e.to_string()))?;
                format!("notes {t} remove {key}")
            }
            0..=4 => {
                let key = format!("k{}", self.dice.below(5));
                let op = PathOp { path: vec![PathSeg::Key(Value::Str(key.clone()))], op: Op::Set(Value::Str(format!("v{k}"))) };
                m.op(t, &self.eph_ak(NOTES)?, op).map_err(|e| self.fail(e.to_string()))?;
                format!("notes {t} {key}=v{k}")
            }
            5 => {
                m.set(t, &self.eph_ak(STATE)?, &Value::Str(format!("s{k}"))).map_err(|e| self.fail(e.to_string()))?;
                format!("state {t} s{k}")
            }
            6 => {
                let key = self.eph_ak(TYPING)?;
                let at = self.engine(n)?.now().0.saturating_add(5_000 + self.dice.below(25_000));
                m.set(t, &key, &Value::Bool(true)).map_err(|e| self.fail(e.to_string()))?;
                m.expires(t, &key, WallMs(at)).map_err(|e| self.fail(e.to_string()))?;
                format!("typing {t} until {at}")
            }
            7..=9 => {
                let v = format!("c{k}");
                self.cursor_op(n, t, &v, &mut m)?;
                format!("cursor {t} {v}")
            }
            _ => {
                m.set(t, &self.eph_ak(RING)?, &Value::Str(format!("sig{k}"))).map_err(|e| self.fail(e.to_string()))?;
                format!("signal {t} sig{k}")
            }
        };
        self.eph_write(n, m, what)
    }

    /// Signal parts fired at node `n` (history entries nobody holds): each value at most once per
    /// node.
    pub(super) fn eph_signals(&mut self, n: usize, changes: &[osis_node::HistoryChange]) -> Res<()> {
        for ch in changes {
            let (t, Some(row)) = (ch.tid, &ch.fired) else { continue };
            let osis_node::engine::history::RowBody::Held(Some(Value::Str(v))) = &row.body else { continue };
            if ch.ak.as_str() != RING {
                continue;
            }
            let c = self.eph.delivered.entry((n, v.clone())).or_default();
            *c += 1;
            let c = *c;
            if c > 1 {
                return Err(self.fail(format!("node {n}: signal {v} on {t} delivered {c} times")));
            }
        }
        Ok(())
    }

    /// Whether node `n` reaches host `s` for group `g`'s label (one of its hosts, not cut
    /// off).
    fn label_reaches(&mut self, n: usize, s: usize, g: &Tid) -> bool {
        let Some(key) = self.hosts.get(s).filter(|x| x.up).map(|x| x.key) else { return false };
        if self.is_blocked(Party::N(n), Party::S(s)) {
            return false;
        }
        let Some(sync) = self.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { return false };
        sync.labels().into_iter().any(|(x, l)| x == *g && l.hosts.iter().any(|a| a.key == key))
    }

    fn share_host(&mut self, a: usize, b: usize, g: &Tid) -> bool {
        (0..self.hosts.len()).any(|s| self.label_reaches(a, s, g) && self.label_reaches(b, s, g))
    }

    /// Up nodes (not excused) reading group `g`.
    fn readers(&mut self, g: &Tid) -> Res<Vec<usize>> {
        let mut out = Vec::new();
        for n in 0..self.nodes.len() {
            if self.excused.contains(&n) || !self.is_up(n) {
                continue;
            }
            if self.engine(n)?.role_on(g).is_some_and(|r| r >= Role::Read) {
                out.push(n);
            }
        }
        Ok(out)
    }

    /// Node `n`'s read of ephemeral aspect `ak` of `t`, printed.
    fn eph_read(&mut self, n: usize, t: &Tid, ak: &str) -> Res<Option<Value>> {
        let a = self.eph_ak(ak)?;
        let r = self.engine(n)?.get(t, &a);
        r.map_err(|e| self.fail(format!("node {n} reads {ak} of {t}: {e}")))
    }

    /// Node `n`'s cursor write on `t` into `m`: a fresh entry at its key, expiring `CURSOR_MS`
    /// out.
    fn cursor_op(&mut self, n: usize, t: Tid, v: &str, m: &mut Mutation) -> Res<()> {
        let key = self.eph_ak(CURSOR)?;
        let at = self.engine(n)?.now().0.saturating_add(CURSOR_MS);
        let op = PathOp { path: vec![PathSeg::Key(Value::Str(n.to_string()))], op: Op::Put(Value::Str(v.into())) };
        m.op(t, &key, op).map_err(|e| self.fail(e.to_string()))?;
        m.expires(t, &key, WallMs(at)).map_err(|e| self.fail(e.to_string()))?;
        Ok(())
    }

    /// Node `o`'s read of node `a`'s cursor on `t`.
    fn cursor_of(&mut self, o: usize, t: &Tid, a: usize) -> Res<Option<String>> {
        Ok(str_map(self.eph_read(o, t, CURSOR)?).remove(&a.to_string()))
    }

    /// After quiescence: a random writer of a tracked durable thing sets its cursor there and
    /// refreshes it every half expiry; each reader a path through hosts that keep nothing
    /// out joins to it reads it just before every refresh. Then the writer goes down (nobody sees it leave) and once its last
    /// write expired nobody reads its cursor. Then it comes back.
    pub fn author_leaves(&mut self) -> Res<()> {
        let Some(&(t, g)) = self.eph.things.first() else { return Ok(()) };
        let ms = self.readers(&g)?;
        let mut writers = Vec::new();
        for n in &ms {
            if self.engine(*n)?.role_on(&t).is_some_and(|r| r >= Role::Write) {
                writers.push(*n);
            }
        }
        let Some(&a) = self.dice.pick(&writers) else { return Ok(()) };
        self.eph.next += 1;
        let v = format!("c{}", self.eph.next);
        for round in 0..4 {
            let mut m = Mutation::new();
            self.cursor_op(a, t, &v, &mut m)?;
            self.eph_write(a, m, format!("cursor {t} {v} (refresh {round})"))?;
            self.settle()?;
            // just before the next refresh: a second's slack for the nodes' corrected clocks
            self.advance(CURSOR_MS / 2 - 1_000)?;
            self.settle()?;
            // the readers a path through hosts that keep nothing out joins to the writer
            let lossy = self.lossy_hosts();
            let readers = self.eph_components(&g, &ms, &lossy).into_iter().find(|c| c.contains(&a)).unwrap_or_default();
            for o in &readers {
                if self.cursor_of(*o, &t, a)?.as_deref() != Some(v.as_str()) {
                    return Err(self.fail(format!("node {o} does not read node {a}'s refreshed cursor {v} on {t} (refresh {round})")));
                }
            }
            self.advance(1_000)?;
        }
        self.note(format!("author {a} leaves"));
        self.node_down(a)?;
        self.drain_queue()?;
        self.advance(CURSOR_MS)?;
        self.settle()?;
        for o in ms.into_iter().filter(|o| *o != a) {
            if let Some(c) = self.cursor_of(o, &t, a)? {
                return Err(self.fail(format!("node {o} still reads departed author {a}'s cursor {c} on {t} past its expiry")));
            }
        }
        self.restart_node(a)?;
        self.quiet(40)
    }

    /// After quiescence: a random writer signals on a tracked durable thing; each reader
    /// sharing a host with it gets it exactly once, the writer once (its own event).
    pub fn signal_reaches(&mut self) -> Res<()> {
        let Some(&(t, g)) = self.eph.things.first() else { return Ok(()) };
        let ms = self.readers(&g)?;
        let mut writers = Vec::new();
        for n in &ms {
            if self.engine(*n)?.role_on(&t).is_some_and(|r| r >= Role::Write) {
                writers.push(*n);
            }
        }
        let Some(&n) = self.dice.pick(&writers) else { return Ok(()) };
        self.eph.next += 1;
        let v = format!("sig{}", self.eph.next);
        let mut m = Mutation::new();
        m.set(t, &self.eph_ak(RING)?, &Value::Str(v.clone())).map_err(|e| self.fail(e.to_string()))?;
        self.eph_write(n, m, format!("final signal {t} {v}"))?;
        self.settle()?;
        for o in ms {
            let got = self.eph.delivered.get(&(o, v.clone())).copied().unwrap_or(0);
            if (o == n || self.share_host(n, o, &g)) && got != 1 {
                return Err(self.fail(format!("node {o} got signal {v} from node {n} {got} times, connected through a shared host")));
            }
        }
        Ok(())
    }

    /// Per tracked thing: its group and the readers holding it.
    fn holders(&mut self) -> Res<BTreeMap<Tid, (Tid, Vec<usize>)>> {
        let mut out = BTreeMap::new();
        for (t, g) in self.eph.things.clone() {
            let mut hs = Vec::new();
            for n in self.readers(&g)? {
                if self.engine(n)?.knows(&t) {
                    hs.push(n);
                }
            }
            out.insert(t, (g, hs));
        }
        Ok(out)
    }
}

impl NetSim {
    /// Up hosts whose ephemeral cap keeps out a plain entry some up node holds under a label
    /// they carry, by their own accounting (spec/sync.md §5, the defined outcome past a cap).
    fn lossy_hosts(&self) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        for s in 0..self.hosts.len() {
            let Some(hub) = self.hub(s) else { continue };
            let st = hub.store();
            for l in st.labels_after(None, 4096).unwrap_or_default() {
                let live: BTreeSet<osis_base::BlobId> = st.live_ids(&l).unwrap_or_default().into_iter().collect();
                let mut held = BTreeSet::new();
                let mut keeps_out = false;
                for n in (0..self.nodes.len()).filter(|n| self.is_up(*n)) {
                    let Some(sync) = self.nodes.get(n).and_then(|x| x.sync.as_ref()) else { continue };
                    for (b, size) in sync.ephemeral_held_entries(&l) {
                        keeps_out |= !live.contains(&b) && !st.ephemeral_fits(&l, size as u64);
                        held.insert(b);
                    }
                }
                // not genuine while it keeps a plain entry no up node holds (absorbed everywhere,
                // its deletion never sent): that room is what the refused entry lacks
                let plain = |b: &osis_base::BlobId| st.blob(b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Ephemeral);
                if keeps_out && !live.iter().any(|b| plain(b) && !held.contains(b)) {
                    out.insert(s);
                }
            }
        }
        out
    }

    /// The nodes of `ns` grouped by what connects them for `g`'s label through hosts not in
    /// `lossy`: a host they reach, hosts replicating to each other.
    fn eph_components(&mut self, g: &Tid, ns: &[usize], lossy: &BTreeSet<usize>) -> Vec<Vec<usize>> {
        let mut edges: BTreeMap<Party, BTreeSet<Party>> = BTreeMap::new();
        let mut link = |a: Party, b: Party| {
            edges.entry(a).or_default().insert(b);
            edges.entry(b).or_default().insert(a);
        };
        let paths: Vec<usize> = (0..self.hosts.len()).filter(|s| !lossy.contains(s) && self.hub(*s).is_some()).collect();
        for s in paths {
            for n in ns {
                if self.label_reaches(*n, s, g) {
                    link(Party::N(*n), Party::S(s));
                }
            }
            let peers = self.hosts.get(s).map(|x| x.peers.clone()).unwrap_or_default();
            for p in peers.into_iter().filter(|p| !lossy.contains(p) && self.hub(*p).is_some()) {
                link(Party::S(s), Party::S(p));
            }
        }
        let mut seen: BTreeSet<Party> = BTreeSet::new();
        let mut out = Vec::new();
        for n in ns {
            if seen.contains(&Party::N(*n)) {
                continue;
            }
            let mut comp = Vec::new();
            let mut stack = vec![Party::N(*n)];
            while let Some(x) = stack.pop() {
                if !seen.insert(x) {
                    continue;
                }
                if let Party::N(m) = x {
                    comp.push(m);
                }
                stack.extend(edges.get(&x).into_iter().flatten().copied());
            }
            out.push(comp);
        }
        out
    }

    /// The ephemeral commits nodes `ns` hold touching `t` (failure detail): id, author node,
    /// own, aspects of `t`.
    fn held_detail(&self, ns: &[usize], t: &Tid) -> Vec<String> {
        let author = |a: &Tid| self.nodes.iter().position(|x| x.tid == *a).map_or_else(|| a.to_string(), |i| format!("n{i}"));
        let mut out = Vec::new();
        for n in ns {
            let Some(e) = self.nodes.get(*n).and_then(|x| x.sync.as_ref()).map(|s| s.engine()) else { continue };
            for (id, bytes, own) in e.memory_commits() {
                let Some(h) = e.header(&id) else { continue };
                let aks: Vec<&str> = h.aspects.iter().filter(|a| a.tid == *t).map(|a| a.ak.as_str()).collect();
                if aks.is_empty() {
                    continue;
                }
                let sync = self.nodes.get(*n).and_then(|x| x.sync.as_ref());
                let ents: Vec<String> = sync.map(|s| s.ephemeral_entries_of(&id)).unwrap_or_default().into_iter().map(|(l, b, present)| {
                    let at: Vec<usize> = (0..self.hosts.len()).filter(|s| self.hub(*s).is_some_and(|h| h.store().live_ids(&l).unwrap_or_default().contains(&b))).collect();
                    let counted: Vec<usize> = present.iter().filter_map(|k| self.hosts.iter().position(|x| x.key == *k)).collect();
                    format!("{b:?} live at {at:?} counted at {counted:?}")
                }).collect();
                out.push(format!("node {n}: {:?} by {} own {own} {bytes} B ts {:?} {aks:?} entries {ents:?}", id, author(&h.author), h.ts));
            }
        }
        out
    }
}

/// A `map<string, string>` value as a map (absent: empty).
fn str_map(v: Option<Value>) -> BTreeMap<String, String> {
    match v {
        Some(Value::Map(m)) => m
            .into_iter()
            .filter_map(|(k, v)| match (k, v) {
                (Value::Str(k), Value::Str(v)) => Some((k, v)),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// The ephemeral invariants at quiescence (module doc); nothing to do without tracked targets.
pub fn check(sim: &mut NetSim) -> Res<()> {
    if sim.eph.things.is_empty() {
        return Ok(());
    }
    // bounded host memory, first (its trace lines help read a divergence)
    let mut lines = Vec::new();
    for s in 0..sim.hosts.len() {
        let Some(host) = sim.hosts.get(s) else { continue };
        let (cap, total) = (host.policy.ephemeral_bytes, host.policy.ephemeral_total);
        let Some(hub) = sim.hub(s) else { continue };
        let st = hub.store();
        if st.ephemeral_total() > total {
            return Err(sim.fail(format!("host {s} charges {} B of ephemeral memory, over its total {total}", st.ephemeral_total())));
        }
        for l in st.labels_after(None, 4096).unwrap_or_default() {
            let b = st.ephemeral_bytes(&l);
            if b > cap {
                return Err(sim.fail(format!("host {s} charges {b} B of ephemeral memory under {l:?}, over its cap {cap}")));
            }
            if b > 0 {
                lines.push(format!("host {s} charges {b} B of ephemeral memory under {l:?} (cap {cap})"));
            }
        }
    }
    for l in lines {
        sim.note(l);
    }
    // compaction keeps the bodies held of an aspect within `FACTOR` times its snapshot
    let ups: Vec<usize> = (0..sim.nodes.len()).filter(|n| sim.is_up(*n)).collect();
    for n in ups {
        for x in sim.engine(n)?.memory_load().map_err(|e| sim.fail(e.to_string()))? {
            if x.held > osis_node::ephemeral::FACTOR * x.snapshot + x.largest {
                return Err(sim.fail(format!("node {n} holds {} B of {} on {}, more than `FACTOR` times its {} B snapshot and one {} B commit", x.held, x.ak, x.tid, x.snapshot, x.largest)));
            }
        }
    }
    let lossy = sim.lossy_hosts();
    if !lossy.is_empty() {
        sim.note(format!("hosts {lossy:?} keep out an entry that does not fit their ephemeral cap"));
    }
    let holders = sim.holders()?;
    for (t, (g, hs)) in &holders {
        for comp in sim.eph_components(g, hs, &lossy) {
            eph_alike(sim, t, &comp)?;
        }
        // whatever connects them: holders of the same plain commits read alike (a node's state
        // is its own commits and the valid ones it received; checks past a lossy host too)
        let mut by: BTreeMap<BTreeSet<osis_base::CommitId>, Vec<usize>> = BTreeMap::new();
        for n in hs {
            let e = sim.engine(*n)?;
            let held: BTreeSet<osis_base::CommitId> = e.memory_commits().into_iter().map(|x| x.0).collect();
            by.entry(held).or_default().push(*n);
        }
        for same in by.into_values().filter(|x| x.len() > 1) {
            eph_alike(sim, t, &same)?;
        }
    }
    Ok(())
}

/// Nodes `hs` read the same ephemeral state of `t`, and no expired typing flag or cursor.
fn eph_alike(sim: &mut NetSim, t: &Tid, hs: &[usize]) -> Res<()> {
    {
        let mut first: Option<(usize, Vec<String>)> = None;
        for n in hs {
            let mut reads = Vec::new();
            for ak in [NOTES, STATE, TYPING, CURSOR] {
                reads.push(format!("{ak} {:?}", sim.eph_read(*n, t, ak)?));
            }
            // quiescence moves time past every expiry (an emptied map stays present)
            for ak in [TYPING, CURSOR] {
                if let Some(v) = sim.eph_read(*n, t, ak)?.filter(|v| *v != Value::Map(Default::default())) {
                    return Err(sim.fail(format!("node {n} still reads an expired {ak} {v:?} on {t}")));
                }
            }
            match &first {
                None => first = Some((*n, reads)),
                Some((m, f)) if *f != reads => {
                    let (m, f) = (*m, f.clone());
                    let held = sim.held_detail(&[m, *n], t);
                    return Err(sim.fail(format!("ephemeral divergence on {t}: node {m} reads {f:?}, node {n} reads {reads:?}; held: {held:?}")));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// A random host ephemeral cap for the capped scenarios: nothing fits, below one cover, about
/// the writers' covers, about twice them (what spec/sync.md §5 says always fits), plenty.
fn random_cap(d: &mut Dice) -> u64 {
    d.pick(&[0, 1_500, 4_000, 8_000, 16_000, 64_000]).copied().unwrap_or(0)
}

/// Shared ephemeral data under faults (notes/ephemeral.md): A (admin) and B (writer) reach both
/// replicating hosts, C (writer) only s0, D (reader) only s1; odd seeds give s0 a random
/// ephemeral cap (0 and below one cover included). A window added to the group and a durable item get random
/// ephemeral (expiring ones included) and signal writes amid durable writes, lossy links, node
/// and host crashes (mid-write too), partitions and slow hosts; then the quiescent
/// invariants, an author refreshing its cursor and leaving, and a signal to everyone connected.
pub fn ephemeral(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xe9);
    let w = NetWeights { write: 1, ephemeral: 5, crash: 1, restart: 2, host_crash: 1, host_restart: 2, partition: 1, heal: 2, slow: 1, ..NetWeights::default() };
    let mut sim = sim("ephemeral", seed, w);
    let cap = if seed % 2 == 1 { HostPolicy { ephemeral_bytes: random_cap(&mut d), ..sim.cfg.policy.clone() } } else { sim.cfg.policy.clone() };
    let s0 = sim.add_host_with(cap)?;
    let s1 = sim.add_host()?;
    sim.replicate(s0, s1)?;
    let a = sim.add_node(&[s0, s1], clock(&mut d))?;
    let b = sim.add_node(&[s0, s1], clock(&mut d))?;
    let c = sim.add_node(&[s0], clock(&mut d))?;
    let e = sim.add_node(&[s1], clock(&mut d))?;
    sim.sever(Party::N(c), Party::S(s1));
    sim.sever(Party::N(e), Party::S(s0));
    let [pa, pb, pc, pe] = persons(&mut sim, [a, b, c, e], [s0, s0, s0, s1])?;
    let g = shared_group(&mut sim, a, pa, &[s0, s1], &[(pb, Role::Write), (pc, Role::Write), (pe, Role::Read)])?;
    let t = sim.item(a, g)?;
    sim.track_ephemeral(t, g);
    sim.quiet(40)?;
    sim.window(a, g)?;
    sim.quiet(40)?;
    sim.run(150)?;
    // a second window made amid the faults (the first may be lost by then)
    sim.window_by_any(&[a, b, c], g)?;
    sim.run(150)?;
    sim.run_until_quiescent(60)?;
    sim.author_leaves()?;
    sim.signal_reaches()?;
    sim.finish()
}

/// One host with a random ephemeral cap (0 and below one cover included) holds all that
/// writers exchange (no other path): three
/// writers write a window and a durable item ephemerally under link faults, node crashes and
/// host restarts (which lose every ephemeral entry), with the host at times slow.
pub fn ephemeral_capped(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xec);
    let w = NetWeights { write: 1, ephemeral: 6, crash: 1, restart: 2, host_crash: 1, host_restart: 2, partition: 1, heal: 2, slow: 1, ..NetWeights::default() };
    let mut sim = sim("ephemeral_capped", seed, w);
    let cap = random_cap(&mut d);
    let s = sim.add_host_with(HostPolicy { ephemeral_bytes: cap, ..sim.cfg.policy.clone() })?;
    let a = sim.add_node(&[s], clock(&mut d))?;
    let b = sim.add_node(&[s], clock(&mut d))?;
    let c = sim.add_node(&[s], clock(&mut d))?;
    let [pa, pb, pc] = persons(&mut sim, [a, b, c], [s, s, s])?;
    let g = shared_group(&mut sim, a, pa, &[s], &[(pb, Role::Write), (pc, Role::Write)])?;
    let t = sim.item(a, g)?;
    sim.track_ephemeral(t, g);
    sim.quiet(40)?;
    sim.window(b, g)?;
    sim.quiet(40)?;
    sim.run(150)?;
    sim.window_by_any(&[a, b, c], g)?;
    sim.run(150)?;
    sim.run_until_quiescent(60)?;
    sim.author_leaves()?;
    sim.signal_reaches()?;
    sim.finish()
}
