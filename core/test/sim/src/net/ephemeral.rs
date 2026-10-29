//! Synced ephemeral data in the simulator (notes/ephemeral.md, spec/sync.md §9): random
//! ephemeral, presence and signal writes on ephemeral windows placed in labeled groups and on
//! durable items of them, and their invariants at quiescence (`check`):
//! - convergence among holders (spec/requirements.md Ephemeral data): every member node of the
//!   group reads the same ephemeral state of a durable item; a window is held by every member
//!   node or by none (lost only when every member node and every server restarted since it was
//!   made), and its holders read the same state; expired writes read absent everywhere.
//! - presence (spec/sync.md §9 Presence commits): a holder reads exactly the live cursors of the
//!   authors it shares a server with (its own included); a server keeps at most one presence
//!   entry per live author it serves.
//! - signals (spec/sync.md §9 Relay-only commits): delivered at most once per node over the run
//!   (checked as events arrive).
//! - bounded server memory (spec/sync.md §5): every label's ephemeral charge within its cap,
//!   the total within the server's.
//!
//! Scenario helpers check two more after quiescence: `author_leaves` (an author's cursors go
//! everywhere once its connections close) and `signal_reaches` (a signal reaches each connected
//! member once).

use super::scenarios::{clock, persons, shared_group, sim};
use super::{NetSim, NetWeights, Party};
use crate::dice::Dice;
use crate::harness::{Report, Res};
use osis_server::Policy;
use osis_base::{Ak, Role, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_node::Mutation;
use osis_node::sync::Event;
use osis_proto::LabelStore;
use osis_schema::core_types as ct;
use osis_schema::{Lifetime, Untyped};
use std::collections::{BTreeMap, BTreeSet};

/// `map<string, string>`, ephemeral.
pub const NOTES: &str = "/e/notes";
/// A string, ephemeral.
pub const STATE: &str = "/e/state";
/// A bool written with an expiry 5-30 s out (a typing indicator).
pub const TYPING: &str = "/e/typing";
/// Presence: a map from the author's node index to its cursor.
pub const CURSOR: &str = "/e/cursor";
/// Signal: a unique string per write.
pub const RING: &str = "/e/ring";

/// Whether `ak` is one of the simulator's ephemeral aspects (the durable checks skip them).
pub fn is_ephemeral(ak: &Ak) -> bool {
    ak.as_str().starts_with("/e/")
}

/// An ephemeral window and who held it.
#[derive(Clone, Debug)]
pub struct Window {
    pub w: Tid,
    pub g: Tid,
    /// Per node that held it (seen after a step or on an event naming it): its boot then.
    pub held: BTreeMap<usize, u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Track {
    pub windows: Vec<Window>,
    /// Durable things (with their group) whose ephemeral aspects random writes touch.
    pub things: Vec<(Tid, Tid)>,
    /// Live presence per (target, author node): its last cursor since the author's boot.
    pub cursors: BTreeMap<(Tid, usize), String>,
    /// Signal deliveries per (node, value).
    pub delivered: BTreeMap<(usize, String), u32>,
    /// Restarts per node and server.
    pub boots: BTreeMap<Party, u64>,
    /// Values written so far (unique values).
    pub next: u64,
}

impl NetSim {
    fn ukey(&self, ak: &str, l: Lifetime) -> Res<Untyped> {
        let a = Ak::new(ak).map_err(|e| self.fail(e.to_string()))?;
        Ok(Untyped::new(a, l))
    }

    fn eph_ak(&self, ak: &str) -> Res<Ak> {
        Ak::new(ak).map_err(|e| self.fail(e.to_string()))
    }

    /// Node `n` makes an ephemeral window owned by and placed in `g` (the ephemeral side of its
    /// `/group`) and tracks it.
    pub fn window(&mut self, n: usize, g: Tid) -> Res<Tid> {
        let state = self.ukey(STATE, Lifetime::Ephemeral)?;
        let e = self.engine(n)?;
        let mut m = Mutation::new();
        let w = e.new_thing(&mut m, g);
        let place = PathOp { path: vec![PathSeg::Field(0)], op: Op::Add(Value::Tid(w)) };
        m.op(g, &ct::GROUP, place).map_err(|e| self.fail(e.to_string()))?;
        m.set(w, &state, &Value::Str("w".into())).map_err(|e| self.fail(e.to_string()))?;
        self.eph_write(n, m, format!("makes window {w}"))?;
        if self.engine(n)?.ephemeral_thing(&w).is_none() {
            return Err(self.fail("the window did not stay ephemeral"));
        }
        let boot = self.boots_of(n);
        self.eph.windows.push(Window { w, g, held: BTreeMap::from([(n, boot)]) });
        Ok(w)
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

    fn boots_of(&self, n: usize) -> u64 {
        self.eph.boots.get(&Party::N(n)).copied().unwrap_or(0)
    }

    /// Records which up nodes hold each window (after every step).
    pub(super) fn eph_holding(&mut self) {
        for i in 0..self.eph.windows.len() {
            let Some(w) = self.eph.windows.get(i).map(|x| x.w) else { continue };
            for n in 0..self.nodes.len() {
                let holds = self.nodes.get(n).and_then(|x| x.sync.as_ref()).is_some_and(|s| s.engine().ephemeral_thing(&w).is_some());
                if holds {
                    let b = self.boots_of(n);
                    if let Some(x) = self.eph.windows.get_mut(i) {
                        x.held.insert(n, b);
                    }
                }
            }
        }
    }

    /// Node `n` writes `m` (an ephemeral batch), then its sync engine looks.
    pub fn eph_write(&mut self, n: usize, m: Mutation, what: String) -> Res<()> {
        let r = self.engine(n)?.write(m);
        r.map_err(|e| self.fail(format!("node {n} ephemeral write ({what}): {e}")))?;
        self.report.writes = self.report.writes.saturating_add(1);
        self.note(format!("node {n} {what}"));
        self.feed(n, Event::Local)
    }

    /// Targets node `n` may write ephemerally: windows it holds in groups it writes, tracked
    /// durable things it writes.
    fn eph_targets(&mut self, n: usize) -> Res<Vec<Tid>> {
        let wins: Vec<(Tid, Tid)> = self.eph.windows.iter().map(|x| (x.w, x.g)).collect();
        let things = self.eph.things.clone();
        let e = self.engine(n)?;
        let mut out = Vec::new();
        for (w, g) in wins {
            if e.ephemeral_thing(&w).is_some() && e.role_on(&g).is_some_and(|r| r >= Role::Write) {
                out.push(w);
            }
        }
        for (t, _) in things {
            if e.role_on(&t).is_some_and(|r| r >= Role::Write) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// A random up node writes one ephemeral op on a target it may write: a note set or
    /// removed, the state, an expiring typing flag, its cursor (presence) or a signal.
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
                m.op(t, &self.ukey(NOTES, Lifetime::Ephemeral)?, op).map_err(|e| self.fail(e.to_string()))?;
                format!("notes {t} remove {key}")
            }
            0..=4 => {
                let key = format!("k{}", self.dice.below(5));
                let op = PathOp { path: vec![PathSeg::Key(Value::Str(key.clone()))], op: Op::Set(Value::Str(format!("v{k}"))) };
                m.op(t, &self.ukey(NOTES, Lifetime::Ephemeral)?, op).map_err(|e| self.fail(e.to_string()))?;
                format!("notes {t} {key}=v{k}")
            }
            5 => {
                m.set(t, &self.ukey(STATE, Lifetime::Ephemeral)?, &Value::Str(format!("s{k}"))).map_err(|e| self.fail(e.to_string()))?;
                format!("state {t} s{k}")
            }
            6 => {
                let key = self.ukey(TYPING, Lifetime::Ephemeral)?;
                let at = self.engine(n)?.now().0.saturating_add(5_000 + self.dice.below(25_000));
                m.set(t, &key, &Value::Bool(true)).map_err(|e| self.fail(e.to_string()))?;
                m.expires(t, &key, WallMs(at)).map_err(|e| self.fail(e.to_string()))?;
                format!("typing {t} until {at}")
            }
            7..=9 => {
                let v = format!("c{k}");
                let op = PathOp { path: vec![PathSeg::Key(Value::Str(n.to_string()))], op: Op::Set(Value::Str(v.clone())) };
                m.op(t, &self.ukey(CURSOR, Lifetime::Presence)?, op).map_err(|e| self.fail(e.to_string()))?;
                self.eph.cursors.insert((t, n), v.clone());
                format!("cursor {t} {v}")
            }
            _ => {
                m.set(t, &self.ukey(RING, Lifetime::Signal)?, &Value::Str(format!("sig{k}"))).map_err(|e| self.fail(e.to_string()))?;
                format!("signal {t} sig{k}")
            }
        };
        self.eph_write(n, m, what)
    }

    /// Signal parts delivered to node `n`'s callbacks: each value at most once per node.
    pub(super) fn eph_signals(&mut self, n: usize, signals: &[(Tid, Ak, Value)]) -> Res<()> {
        for (t, ak, v) in signals {
            let Value::Str(v) = v else { continue };
            if ak.as_str() != RING {
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

    /// Whether node `n` reaches server `s` for group `g`'s label (one of its servers, not cut
    /// off).
    fn label_reaches(&mut self, n: usize, s: usize, g: &Tid) -> bool {
        let Some(key) = self.servers.get(s).filter(|x| x.up).map(|x| x.key) else { return false };
        if self.is_blocked(Party::N(n), Party::S(s)) {
            return false;
        }
        let Some(sync) = self.nodes.get_mut(n).and_then(|x| x.sync.as_mut()) else { return false };
        sync.labels().into_iter().any(|(x, l)| x == *g && l.servers.iter().any(|a| a.key == key))
    }

    fn share_server(&mut self, a: usize, b: usize, g: &Tid) -> bool {
        (0..self.servers.len()).any(|s| self.label_reaches(a, s, g) && self.label_reaches(b, s, g))
    }

    /// Up nodes (not excused) reading group `g`.
    fn members(&mut self, g: &Tid) -> Res<Vec<usize>> {
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

    /// The cursors node `n` reads on `t`.
    fn cursors_at(&mut self, n: usize, t: &Tid) -> Res<BTreeMap<String, String>> {
        Ok(str_map(self.eph_read(n, t, CURSOR)?))
    }

    /// The cursors node `o` must read on target `t` of group `g`: those of live authors it
    /// shares a server with, its own included.
    fn cursors_expected(&mut self, o: usize, t: &Tid, g: &Tid) -> BTreeMap<String, String> {
        let live: Vec<(usize, String)> = self.eph.cursors.iter().filter(|(k, _)| k.0 == *t).map(|(k, v)| (k.1, v.clone())).collect();
        let mut out = BTreeMap::new();
        for (a, v) in live {
            if a == o || self.share_server(a, o, g) {
                out.insert(a.to_string(), v);
            }
        }
        out
    }

    /// Presence-class live entries per (server, label).
    fn presence_entries(&self) -> BTreeMap<(usize, osis_base::LabelId), usize> {
        let mut out = BTreeMap::new();
        for s in 0..self.servers.len() {
            let Some(hub) = self.hub(s) else { continue };
            let st = hub.store();
            for l in st.labels_after(None, 4096).unwrap_or_default() {
                let ids = st.live_ids(&l).unwrap_or_default();
                let p = ids.iter().filter(|b| st.blob(b).ok().flatten().and_then(|x| osis_label::Prefix::parse(&x).ok()).is_some_and(|p| p.class() == osis_label::Class::Presence)).count();
                if p > 0 {
                    out.insert((s, l), p);
                }
            }
        }
        out
    }

    /// Authors with a live cursor whose presence server `s` serves (for any tracked group).
    fn live_authors_at(&mut self, s: usize) -> usize {
        let groups: BTreeMap<Tid, Tid> = self.eph.windows.iter().map(|x| (x.w, x.g)).chain(self.eph.things.iter().copied()).collect();
        let keys: Vec<(Tid, usize)> = self.eph.cursors.keys().copied().collect();
        let mut authors = BTreeSet::new();
        for (t, a) in keys {
            if let Some(g) = groups.get(&t)
                && self.label_reaches(a, s, g)
            {
                authors.insert(a);
            }
        }
        authors.len()
    }

    /// The presence invariants: every holder of each target reads exactly the expected
    /// cursors; servers keep at most one presence entry per live author they serve.
    fn presence_ok(&mut self, holders: &BTreeMap<Tid, (Tid, Vec<usize>)>) -> Res<()> {
        for (t, (g, hs)) in holders {
            for o in hs {
                let got = self.cursors_at(*o, t)?;
                let want = self.cursors_expected(*o, t, g);
                if got != want {
                    return Err(self.fail(format!("node {o} reads cursors {got:?} on {t}, expected {want:?} (live: {:?})", self.eph.cursors)));
                }
            }
        }
        for ((s, l), p) in self.presence_entries() {
            let live = self.live_authors_at(s);
            if p > live {
                return Err(self.fail(format!("server {s} holds {p} presence entries under {l:?} for {live} live authors (live: {:?})", self.eph.cursors)));
            }
        }
        Ok(())
    }

    /// After quiescence: a random author with a live cursor goes down; once its connections'
    /// close is delivered (no clock advance beyond the messages), nobody reads its cursors and
    /// no server keeps more presence entries than live authors. Then it comes back.
    pub fn author_leaves(&mut self) -> Res<()> {
        let authors: Vec<usize> = self.eph.cursors.keys().map(|k| k.1).collect::<BTreeSet<_>>().into_iter().collect();
        let Some(&a) = self.dice.pick(&authors) else { return Ok(()) };
        self.note(format!("author {a} leaves"));
        self.node_down(a)?;
        self.drain_queue()?;
        let holders = self.holders()?;
        self.presence_ok(&holders)?;
        for (t, (_, hs)) in &holders {
            for o in hs {
                if self.cursors_at(*o, t)?.contains_key(&a.to_string()) {
                    return Err(self.fail(format!("node {o} still reads departed author {a}'s cursor on {t}")));
                }
            }
        }
        self.restart_node(a)?;
        self.quiet(40)
    }

    /// After quiescence: a random writer signals on a tracked durable thing; each member
    /// sharing a server with it gets it exactly once, the writer once (its own event).
    pub fn signal_reaches(&mut self) -> Res<()> {
        let Some(&(t, g)) = self.eph.things.first() else { return Ok(()) };
        let ms = self.members(&g)?;
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
        m.set(t, &self.ukey(RING, Lifetime::Signal)?, &Value::Str(v.clone())).map_err(|e| self.fail(e.to_string()))?;
        self.eph_write(n, m, format!("final signal {t} {v}"))?;
        self.settle()?;
        for o in ms {
            let got = self.eph.delivered.get(&(o, v.clone())).copied().unwrap_or(0);
            if (o == n || self.share_server(n, o, &g)) && got != 1 {
                return Err(self.fail(format!("node {o} got signal {v} from node {n} {got} times, connected through a shared server")));
            }
        }
        Ok(())
    }

    /// Per tracked target: its group and the nodes holding it (members for a durable thing,
    /// members holding the record for a window).
    fn holders(&mut self) -> Res<BTreeMap<Tid, (Tid, Vec<usize>)>> {
        let mut out = BTreeMap::new();
        for (t, g) in self.eph.things.clone() {
            let ms = self.members(&g)?;
            out.insert(t, (g, ms));
        }
        for win in self.eph.windows.clone() {
            let ms = self.members(&win.g)?;
            let mut hs = Vec::new();
            for n in ms {
                if self.engine(n)?.ephemeral_thing(&win.w).is_some() {
                    hs.push(n);
                }
            }
            out.insert(win.w, (win.g, hs));
        }
        Ok(out)
    }
}

impl NetSim {
    /// The ephemeral commits nodes `ns` hold touching `t` (failure detail): id, author node,
    /// own, cover, aspects of `t`.
    fn held_detail(&self, ns: &[usize], t: &Tid) -> Vec<String> {
        let author = |a: &Tid| self.nodes.iter().position(|x| x.tid == *a).map_or_else(|| a.to_string(), |i| format!("n{i}"));
        let mut out = Vec::new();
        for n in ns {
            let Some(e) = self.nodes.get(*n).and_then(|x| x.sync.as_ref()).map(|s| s.engine()) else { continue };
            for (id, bytes, own) in e.held_ephemeral() {
                let Some(h) = e.ephemeral_header(&id) else { continue };
                let aks: Vec<&str> = h.aspects.iter().filter(|a| a.tid == *t).map(|a| a.ak.as_str()).collect();
                if aks.is_empty() {
                    continue;
                }
                let sync = self.nodes.get(*n).and_then(|x| x.sync.as_ref());
                let ents: Vec<String> = sync.map(|s| s.ephemeral_entries_of(&id)).unwrap_or_default().into_iter().map(|(l, b, present)| {
                    let at: Vec<usize> = (0..self.servers.len()).filter(|s| self.hub(*s).is_some_and(|h| h.store().live_ids(&l).unwrap_or_default().contains(&b))).collect();
                    let counted: Vec<usize> = present.iter().filter_map(|k| self.servers.iter().position(|x| x.key == *k)).collect();
                    format!("{b:?} live at {at:?} counted at {counted:?}")
                }).collect();
                out.push(format!("node {n}: {:?} by {} own {own} cover {} {bytes} B ts {:?} {aks:?} entries {ents:?}", id, author(&h.author), e.ephemeral_is_cover(&id), h.ts));
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
    if sim.eph.windows.is_empty() && sim.eph.things.is_empty() {
        return Ok(());
    }
    // bounded server memory, first (its trace lines help read a divergence)
    let mut lines = Vec::new();
    for s in 0..sim.servers.len() {
        let Some(sv) = sim.servers.get(s) else { continue };
        let (cap, total) = (sv.policy.ephemeral_bytes, sv.policy.ephemeral_total);
        let Some(hub) = sim.hub(s) else { continue };
        let st = hub.store();
        if st.ephemeral_total() > total {
            return Err(sim.fail(format!("server {s} charges {} B of ephemeral memory, over its total {total}", st.ephemeral_total())));
        }
        for l in st.labels_after(None, 4096).unwrap_or_default() {
            let b = st.ephemeral_bytes(&l);
            if b > cap {
                return Err(sim.fail(format!("server {s} charges {b} B of ephemeral memory under {l:?}, over its cap {cap}")));
            }
            if b > 0 {
                lines.push(format!("server {s} charges {b} B of ephemeral memory under {l:?} (cap {cap})"));
            }
        }
    }
    for l in lines {
        sim.note(l);
    }
    let holders = sim.holders()?;
    for win in sim.eph.windows.clone() {
        let ms = sim.members(&win.g)?;
        let hs = holders.get(&win.w).map(|x| x.1.clone()).unwrap_or_default();
        if hs.is_empty() {
            // lost only when no node holds it: every node that held it restarted since (a
            // server still holding it would have handed it back to the members)
            let kept: Vec<usize> = win.held.iter().filter(|(n, b)| sim.boots_of(**n) == **b).map(|x| *x.0).collect();
            if !kept.is_empty() {
                return Err(sim.fail(format!("window {} held by no member, though nodes {kept:?} held it and never restarted since", win.w)));
            }
            sim.note(format!("window {} lost: every node that held it restarted", win.w));
        } else if hs.len() != ms.len() {
            return Err(sim.fail(format!("window {} held by nodes {hs:?} of members {ms:?} at quiescence", win.w)));
        }
    }
    for (t, (_, hs)) in &holders {
        let mut first: Option<(usize, Vec<String>)> = None;
        for n in hs {
            let mut reads = Vec::new();
            for ak in [NOTES, STATE, TYPING] {
                reads.push(format!("{ak} {:?}", sim.eph_read(*n, t, ak)?));
            }
            if sim.eph_read(*n, t, TYPING)?.is_some() {
                return Err(sim.fail(format!("node {n} still reads an expired typing flag on {t}")));
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
    sim.presence_ok(&holders)?;
    Ok(())
}

/// The small server cap of the capped scenarios: above a compacted state of the scenario's
/// things (a few KB per writer's cover), below what uncompacted writes pile up to, so writers
/// hit it and compact (a cap below the compacted state stops the label syncing by design:
/// notes/ephemeral.md Bounds).
const CAP: u64 = 16_000;

/// Shared ephemeral data under faults (notes/ephemeral.md): A (admin) and B (writer) reach both
/// replicating servers, C (writer) only s0, D (reader) only s1; odd seeds give s0 a small
/// ephemeral cap (writers compact). A window placed in the group and a durable item get random
/// ephemeral, presence and signal writes amid durable writes, lossy links, node and server
/// crashes (mid-write too), partitions and slow servers; then the quiescent invariants, an
/// author leaving, and a signal to everyone connected.
pub fn ephemeral(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xe9);
    let w = NetWeights { write: 1, ephemeral: 5, crash: 1, restart: 2, server_crash: 1, server_restart: 2, partition: 1, heal: 2, slow: 1, ..NetWeights::default() };
    let mut sim = sim("ephemeral", seed, w);
    let cap = if seed % 2 == 1 { Policy { ephemeral_bytes: CAP, ..sim.cfg.policy.clone() } } else { sim.cfg.policy.clone() };
    let s0 = sim.add_server_with(cap)?;
    let s1 = sim.add_server()?;
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

/// One server with a small ephemeral cap holds all that writers exchange (no other path): three
/// writers write a window and a durable item ephemerally under link faults, node crashes and
/// server restarts (which lose every ephemeral entry), with the server at times slow.
pub fn ephemeral_capped(seed: u64) -> Res<Report> {
    let mut d = Dice::new(seed ^ 0xec);
    let w = NetWeights { write: 1, ephemeral: 6, crash: 1, restart: 2, server_crash: 1, server_restart: 2, partition: 1, heal: 2, slow: 1, ..NetWeights::default() };
    let mut sim = sim("ephemeral_capped", seed, w);
    let s = sim.add_server_with(Policy { ephemeral_bytes: CAP, ..sim.cfg.policy.clone() })?;
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
