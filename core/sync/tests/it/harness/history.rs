//! The reference-model differential (notes/sync-test-harness.md, Layers): random histories of
//! writes, grants of read and sync, removals, rotations, restarts and faults over a few nodes;
//! at quiet every reader reads alike and as the reference, a single engine handed every commit
//! directly (sync's property is perfect delivery; the engine's own read rules are held-model's
//! and the order harness's), and no needed body is deleted everywhere.
//!
//! A history's writes are `Step`s (`New`, `Write`, `Grant`, `Remove`, `Rotate`) played through
//! the product's engine flows at one node, which sync then carries. Each commit a step writes is
//! handed to the reference as it is written (a commit deleted everywhere later still counts);
//! what sync itself writes (rotations it makes due, addenda) is handed at the check, from
//! every node.

use super::{DiskFault, Loss, Step, World};
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_crypto::{RngCore, SeededRng};
use osis_engine::flows::edges::Demotion;
use osis_engine::local_peer::{Package, Peer};
use osis_engine::{Engine, Ingested, Mutation};
use osis_schema::core_types::Edge;
use std::collections::{BTreeMap, BTreeSet};

/// The role a history grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Gives {
    /// Sync: the holder's nodes keep the thing's sync ID unread.
    Syncs,
    Reads,
    Writes,
}

impl Gives {
    pub fn role(self) -> Role {
        match self {
            Gives::Syncs => Role::Sync,
            Gives::Reads => Role::Read,
            Gives::Writes => Role::Write,
        }
    }

    /// The next role down (shrinking).
    pub fn lesser(self) -> Option<Gives> {
        match self {
            Gives::Writes => Some(Gives::Reads),
            Gives::Reads => Some(Gives::Syncs),
            Gives::Syncs => None,
        }
    }
}

/// The one aspect a history writes.
pub fn value_ak() -> Ak {
    Ak::new("u:v.0").expect("aspect key")
}

/// What a history made, carried with the world (copied with it).
#[derive(Clone, Default)]
pub struct Made {
    /// Things made (`Step::New`), by index, with the node that made them.
    pub things: Vec<(Tid, usize)>,
    /// Each value written, with the commit that wrote it (values are unique).
    pub values: BTreeMap<String, CommitId>,
    /// Commits handed to the reference, in the order seen.
    pub handed: Vec<Package>,
    handed_ids: BTreeSet<CommitId>,
    written: u64,
    /// Hand commits to the reference (`World::differential`); off, a step only writes.
    pub harvest: bool,
}

impl Made {
    fn value(&mut self) -> String {
        self.written += 1;
        format!("v{}", self.written)
    }
}

/// Hands the reference every commit node `i` holds that it has not been handed.
pub fn harvest(w: &mut World, i: usize) {
    if !w.history.harvest || !w.online(i) {
        return;
    }
    let e = w.engine(i);
    let ids = e.commit_ids();
    let mut new = Vec::new();
    for id in ids {
        if !w.history.handed_ids.contains(&id) {
            new.extend(w.engine(i).package(&id).ok().flatten());
        }
    }
    for pk in new {
        w.history.handed_ids.insert(pk.id);
        w.history.handed.push(pk);
    }
}

/// Plays one history write; a note of what came of it.
pub fn step(w: &mut World, s: &Step) -> String {
    let i = match s {
        Step::New(i) | Step::Write(i, _) | Step::Grant(i, ..) | Step::Remove(i, ..) | Step::Rotate(i, _) => *i,
        _ => return String::new(),
    };
    if i >= w.len() || !w.online(i) {
        return "skipped: no such node, or off".into();
    }
    let thing = |w: &World, k: &usize| w.history.things.get(*k).map(|x| x.0);
    let account = |w: &World, j: &usize| (*j < w.len()).then(|| w.node(*j).account).flatten();
    let r: Result<String, String> = match s {
        Step::New(_) => {
            let Some(admin) = account(w, &i) else { return "skipped: no account".into() };
            let v = w.history.value();
            let ak = value_ak();
            match w.write(i, |e| -> osis_engine::Result<_> {
                let mut m = Mutation::new();
                let t = e.new_thing(&mut m, admin);
                m.set(t, &ak, &Value::Str(v.clone()))?;
                Ok((t, e.commit(m)?))
            }) {
                Ok((t, c)) => {
                    w.history.things.push((t, i));
                    w.history.values.extend(c.map(|c| (v, c)));
                    Ok(format!("thing {}", w.history.things.len() - 1))
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Step::Write(_, k) => {
            let Some(t) = thing(w, k) else { return "skipped: no such thing".into() };
            let v = w.history.value();
            let ak = value_ak();
            match w.write(i, |e| -> osis_engine::Result<_> {
                let mut m = Mutation::new();
                m.set(t, &ak, &Value::Str(v.clone()))?;
                e.commit(m)
            }) {
                Ok(c) => {
                    w.history.values.extend(c.map(|c| (v.clone(), c)));
                    Ok(v)
                }
                Err(e) => Err(e.to_string()),
            }
        }
        Step::Grant(_, k, j, g) => {
            let (Some(t), Some(holder)) = (thing(w, k), account(w, j)) else { return "skipped: no such thing or holder".into() };
            let edge = Edge { role: g.role(), until: None, invite: None, tied: None };
            w.write(i, |e| e.grant(&t, &holder, &edge)).map(|_| String::new()).map_err(|e| e.to_string())
        }
        Step::Remove(_, k, j) => {
            let (Some(t), Some(holder)) = (thing(w, k), account(w, j)) else { return "skipped: no such thing or holder".into() };
            w.write(i, |e| e.demote(&t, &Demotion { holder, new: None, retain: None })).map(|_| String::new()).map_err(|e| e.to_string())
        }
        Step::Rotate(_, k) => {
            let Some(t) = thing(w, k) else { return "skipped: no such thing".into() };
            w.write(i, |e| e.give_own_secrets_again(&t)).map(|_| String::new()).map_err(|e| e.to_string())
        }
        _ => return String::new(),
    };
    match r {
        Ok(note) => {
            harvest(w, i);
            note
        }
        Err(e) => format!("refused: {e}"),
    }
}

/// What a node reads of a thing: the history's value and the roster's roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reads {
    pub value: Option<Value>,
    pub roles: Vec<(Tid, Role)>,
}

pub fn reads(e: &mut Engine, t: &Tid) -> Reads {
    let value = e.get(t, &value_ak()).ok().flatten();
    let roles = e.roster(t).into_iter().map(|(h, edge)| (h, edge.role)).collect();
    Reads { value, roles }
}

/// A world of `n` nodes, each with an account of its own, each account known to every node,
/// quiet, handing its commits to the reference from now on. Fresh per seed (drawn IDs, keys and
/// tie-breaks), never a fixture copy.
pub fn world(seed: u64, n: usize) -> World {
    let mut w = World::new(seed);
    for _ in 0..n {
        w.add_node();
    }
    introduce(&mut w);
    w.run();
    w.history.harvest = true;
    w
}

/// Every node learns every other node's account: each one's commits handed to every other's
/// engine directly. A stand-in for the contact exchange (a link redeemed through the inbox),
/// made before any history so no content travels this way.
pub fn introduce(w: &mut World) {
    let n = w.len();
    let mut all: Vec<Vec<Package>> = Vec::new();
    for i in 0..n {
        let e = w.engine(i);
        let pks = e.commit_ids().iter().filter_map(|id| e.package(id).ok().flatten()).collect();
        all.push(pks);
    }
    for (i, pks) in all.iter().enumerate() {
        for j in (0..n).filter(|j| *j != i) {
            w.write(j, |e| {
                for pk in pks {
                    let _ = e.ingest_with_lists(&pk.bytes, pk.blobs.clone(), None, &pk.lists);
                }
            });
        }
    }
}

/// The reference: a single engine handed every commit any node wrote, again while one
/// applies. Every commit any node holds now is handed too (what sync wrote).
pub fn reference(w: &mut World) -> Peer {
    for i in 0..w.len() {
        harvest(w, i);
    }
    let mut r = Peer::new_bare(0x005e_ed0f_5eed, w.now()).expect("reference");
    let handed = w.history.handed.clone();
    for _ in 0..=handed.len() {
        let mut moved = false;
        for pk in &handed {
            moved |= matches!(r.receive_with(&pk.bytes, pk.blobs.clone(), &pk.lists), Ok(x) if !matches!(x, Ingested::Duplicate(_)));
        }
        if !moved {
            break;
        }
    }
    r.clock.set(w.now());
    let _ = r.tick();
    r
}

/// The nodes that read thing `k` per the reference's `want`: its maker's and each whose account
/// holds read or above.
pub fn readers(w: &World, k: usize, want: &Reads) -> BTreeSet<usize> {
    let maker = w.history.things.get(k).map(|x| x.1);
    (0..w.len()).filter(|i| Some(*i) == maker || want.roles.iter().any(|(h, role)| Some(*h) == w.node(*i).account && *role >= Role::Read)).collect()
}

/// Node `i` reads thing `k` as the reference.
pub fn reads_as(w: &mut World, r: &mut Peer, k: usize, i: usize) {
    let Some((t, _)) = w.history.things.get(k).copied() else { panic!("no thing {k}") };
    let want = reads(&mut r.engine, &t);
    let got = reads(w.engine(i), &t);
    assert_eq!(got, want, "node {i} reads thing {k} unlike the reference");
}

/// The checks at quiet: for each thing, every node that reads it per the reference reads as the
/// reference (each must be on), and the commit of the value the reference reads is held by some
/// node.
pub fn check(w: &mut World) {
    let mut r = reference(w);
    let things = w.history.things.clone();
    for (k, (t, _)) in things.iter().enumerate() {
        let want = reads(&mut r.engine, t);
        for i in readers(w, k, &want) {
            assert!(w.online(i), "node {i}, a reader of thing {k}, is off at the check");
            reads_as(w, &mut r, k, i);
        }
        if let Some(Value::Str(v)) = &want.value
            && let Some(c) = w.history.values.get(v).copied()
        {
            let held = (0..w.len()).any(|i| w.engine(i).commit_bytes(&c).ok().flatten().is_some());
            assert!(held, "thing {k}: the body of its value {v} (commit {c:?}) is deleted everywhere");
        }
    }
}

/// A random history over `n` nodes of `len` steps (writes, grants, removals, rotations, runs and
/// faults, mostly ones that apply), ending healed, every node on, faults off, run to quiet.
/// `faults`: whether the history loses power, partitions, loses messages and fails disks.
pub fn history(seed: u64, n: usize, len: usize, faults: bool) -> Vec<Step> {
    let mut rng = SeededRng::from_u64(seed ^ 0x6869_7374);
    let mut pick = |m: usize| (rng.next_u64() % m.max(1) as u64) as usize;
    // a sketch of what applies: each thing's maker and the roles it gave
    let mut things: Vec<(usize, BTreeMap<usize, Gives>)> = Vec::new();
    let mut off: BTreeSet<usize> = BTreeSet::new();
    let mut out = Vec::new();
    while out.len() < len {
        let roll = pick(100);
        let k = pick(things.len());
        let on: Vec<usize> = (0..n).filter(|i| !off.contains(i)).collect();
        let node = on[pick(on.len())];
        let maker_on = things.get(k).is_some_and(|t| !off.contains(&t.0));
        let s = match roll {
            _ if things.is_empty() || (roll < 12 && things.len() < 4) => {
                things.push((node, BTreeMap::new()));
                Step::New(node)
            }
            0..=39 => {
                let (maker, given) = &things[k];
                let writers: Vec<usize> = std::iter::once(*maker).chain(given.iter().filter(|(_, g)| **g == Gives::Writes).map(|(j, _)| *j)).filter(|i| !off.contains(i)).collect();
                // now and then a node that may not write
                let i = if pick(10) == 0 || writers.is_empty() { node } else { writers[pick(writers.len())] };
                Step::Write(i, k)
            }
            40..=54 if n > 1 && maker_on => {
                let maker = things[k].0;
                let j = (maker + 1 + pick(n - 1)) % n;
                let g = [Gives::Syncs, Gives::Reads, Gives::Writes][pick(3)];
                things[k].1.insert(j, g);
                Step::Grant(maker, k, j, g)
            }
            55..=61 if maker_on && !things[k].1.is_empty() => {
                let maker = things[k].0;
                let held: Vec<usize> = things[k].1.keys().copied().collect();
                let j = held[pick(held.len())];
                things[k].1.remove(&j);
                Step::Remove(maker, k, j)
            }
            62..=65 if maker_on => Step::Rotate(things[k].0, k),
            76..=99 if faults => match pick(7) {
                0 if on.len() > 1 => {
                    off.insert(node);
                    Step::PowerOff(node)
                }
                1 if !off.is_empty() => {
                    let j = off.iter().copied().nth(pick(off.len())).unwrap_or(0);
                    off.remove(&j);
                    Step::PowerOn(j)
                }
                2 if n > 1 => Step::Partition(node, (node + 1 + pick(n - 1)) % n),
                3 => Step::Heal,
                4 => Step::Lossy(Loss { drop: [0, 20, 100][pick(3)], dup: [0, 50][pick(2)], delay: [0, 200][pick(2)], delay_ms: 5_000 }),
                5 => Step::Disk(node, pick(30) as u64, [DiskFault::Fail, DiskFault::Unsynced, DiskFault::Crash][pick(3)]),
                _ => Step::Skew(node, [-90_000i64, 0, 90_000][pick(3)]),
            },
            _ => Step::Run,
        };
        out.push(s);
    }
    out.push(Step::Lossy(Loss::NONE));
    out.push(Step::Heal);
    out.extend((0..n).map(Step::PowerOn));
    out.push(Step::Run);
    out
}
