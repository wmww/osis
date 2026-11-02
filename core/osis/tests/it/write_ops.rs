//! The `Write` recorder (notes/client-port.md §1, §8 (a)): a batch of API ops commits to the
//! same state as the same ops committed one batch each, for random op lists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::*;
use osis::{Osis, Tid, Value, core, p};
use std::collections::BTreeMap;
use std::time::Duration;

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::schema as osis_schema;
    include!("../../../schema/tests/gen/notes.rs");
}

/// Untyped durable and ephemeral scalars, an untyped map (whole-value writes: the scalars).
const AKS: [&str; 3] = ["app:a.0", "app:e.0~", "app:m.0"];
const HOUR: Duration = Duration::from_secs(3600);

/// One API call of a batch; things by index into the case's things (setup ones first, then
/// the case's creates), groups by index into its two groups (`g0`: plain placements, `g1`:
/// placements expiring in an hour; one expiry per group and batch).
#[derive(Clone, Debug)]
enum Call {
    Set(usize, usize, i64),
    SetExpiring(usize, usize, i64),
    Replace(usize, usize, i64),
    Remove(usize, usize),
    Put(usize, i64, i64),
    RemoveKey(usize, i64),
    Edit(usize, Vec<(i64, i64)>, Vec<(i64, i64)>),
    Title(usize, String),
    Views(usize, i64),
    Opened(usize, i64),
    Place(usize, usize),
    Unplace(usize),
    AddSubgroup(usize),
    RemoveSubgroup(usize),
    MakeGroup(usize),
    Delete(usize),
}

impl Call {
    /// The things the call names (its group aside).
    fn things(&self) -> Vec<usize> {
        match self {
            Call::Set(t, ..) | Call::SetExpiring(t, ..) | Call::Replace(t, ..) | Call::Remove(t, _) | Call::Put(t, ..) | Call::RemoveKey(t, _) | Call::Edit(t, ..) => vec![*t],
            Call::Title(t, _) | Call::Views(t, _) | Call::Opened(t, _) | Call::Place(t, _) | Call::Unplace(t) | Call::AddSubgroup(t) | Call::RemoveSubgroup(t) | Call::MakeGroup(t) | Call::Delete(t) => vec![*t],
        }
    }
}

/// splitmix64.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
    fn small(&mut self) -> i64 {
        i64::try_from(self.next() % 5).unwrap()
    }
    fn map(&mut self) -> Vec<(i64, i64)> {
        (0..self.below(3)).map(|_| (self.small(), self.small())).collect()
    }
}

/// Setup things: four durable things with an empty map (`app:m.0`, the only map: map ops need
/// one), `t0` placed in `g0`.
const SETUP: usize = 4;

/// A case: how many things it creates (first in the batch: they draw the same tids either
/// way), then its calls. Lists that would read differently batched and unbatched are
/// normalized away (a batch's `delete` removes what is held when the batch commits, not what
/// the batch wrote before it): a thing has no call before its delete, and a created thing is
/// not deleted.
fn case(seed: u64) -> (usize, Vec<Call>) {
    let mut r = Rng(seed);
    let creates = r.below(3);
    let n = SETUP + creates;
    let mut calls = Vec::new();
    for _ in 0..1 + r.below(12) {
        let t = r.below(n);
        calls.push(match r.below(16) {
            0 => Call::Set(t, r.below(2), r.small()),
            1 => Call::SetExpiring(t, r.below(2), r.small()),
            2 => Call::Replace(t, r.below(2), r.small()),
            3 => Call::Remove(t, r.below(2)),
            4 => Call::Put(r.below(SETUP), r.small(), r.small()),
            5 => Call::RemoveKey(r.below(SETUP), r.small()),
            6 => Call::Edit(r.below(SETUP), r.map(), r.map()),
            7 => Call::Title(t, format!("t{}", r.small())),
            8 => Call::Views(t, r.small()),
            9 => Call::Opened(t, r.small()),
            10 => Call::Place(t, r.below(2)),
            11 => Call::Unplace(t),
            12 => Call::AddSubgroup(t),
            13 => Call::RemoveSubgroup(t),
            14 => Call::MakeGroup(t),
            _ => Call::Delete(r.below(SETUP)),
        });
    }
    // the first delete of each thing; a call on it before that, and a second delete, go
    let first_delete = |t: usize| calls.iter().position(|c| matches!(c, Call::Delete(d) if *d == t));
    let keep: Vec<bool> = calls
        .iter()
        .enumerate()
        .map(|(i, c)| match c {
            Call::Delete(t) => first_delete(*t) == Some(i),
            c => !c.things().iter().any(|t| first_delete(*t).is_some_and(|d| i < d)),
        })
        .collect();
    let calls = calls.into_iter().zip(keep).filter_map(|(c, k)| k.then_some(c)).collect();
    (creates, calls)
}

struct World {
    db: Osis,
    things: Vec<Tid>,
    groups: [Tid; 2],
}

fn world() -> World {
    let db = db(7);
    let (things, groups) = db
        .write_with(|w| {
            let things: Vec<Tid> = (0..SETUP).map(|_| w.create_durable(db.me())).collect::<osis::Result<_>>()?;
            for t in &things {
                w.at(*t, ak(AKS[2])).set(&Value::Map(BTreeMap::new()))?;
            }
            let g0 = w.create_durable(db.me())?;
            let g1 = w.create_durable(db.me())?;
            w.make_group(g0)?;
            w.make_group(g1)?;
            w.place(things[0], g0)?;
            Ok((things, [g0, g1]))
        })
        .unwrap();
    World { db, things, groups }
}

fn apply(w: &mut osis::Write<'_>, wd: &World, things: &[Tid], c: &Call) -> osis::Result<()> {
    let key = |k: usize| ak(AKS[k]);
    let m = |v: &[(i64, i64)]| Value::Map(v.iter().map(|(k, x)| (Value::Int(*k), Value::Int(*x))).collect::<BTreeMap<_, _>>());
    let [g0, g1] = wd.groups;
    match c {
        Call::Set(t, k, v) => w.at(things[*t], key(*k)).set(&Value::Int(*v)),
        Call::SetExpiring(t, k, v) => w.at(things[*t], key(*k)).expires_in(HOUR).set(&Value::Int(*v)),
        Call::Replace(t, k, v) => w.at(things[*t], key(*k)).replace(&Value::Int(*v)),
        Call::Remove(t, k) => w.at(things[*t], key(*k)).remove(),
        Call::Put(t, k, v) => w.at(things[*t], key(2)).path(p!()).put(&Value::Int(*k), &Value::Int(*v)),
        Call::RemoveKey(t, k) => w.at(things[*t], key(2)).path(p!()).remove_key(&Value::Int(*k)),
        Call::Edit(t, b, n) => w.at(things[*t], key(2)).edit(&m(b), &m(n)),
        Call::Title(t, s) => w.at(things[*t], notes::TITLE).set(s),
        Call::Views(t, n) => w.at(things[*t], notes::VIEWS).inc(n),
        Call::Opened(t, v) => w.at(things[*t], notes::LAST_OPENED).set(v),
        Call::Place(t, 0) => w.place(things[*t], g0),
        Call::Place(t, _) => w.place_expiring(things[*t], g1, Some(HOUR)),
        Call::Unplace(t) => w.unplace(things[*t], g0),
        Call::AddSubgroup(t) => w.add_subgroup(g0, things[*t]),
        Call::RemoveSubgroup(t) => w.remove_subgroup(g0, things[*t]),
        Call::MakeGroup(t) => w.make_group(things[*t]),
        Call::Delete(t) => w.delete(things[*t]),
    }
}

/// Runs the case batched (one `Write`) or one call per batch; the things and the batched
/// commit's ID.
fn run(creates: usize, calls: &[Call], batched: bool) -> (World, Vec<Tid>, Option<osis::ChangeId>) {
    let wd = world();
    let db = wd.db.clone();
    let mut things = wd.things.clone();
    let mut id = None;
    if batched {
        let mut w = db.write();
        for _ in 0..creates {
            things.push(w.create(db.me()).unwrap());
        }
        for c in calls {
            apply(&mut w, &wd, &things, c).unwrap_or_else(|e| panic!("{c:?}: {e}"));
        }
        id = w.commit().unwrap().map(|c| c.id);
    } else {
        for _ in 0..creates {
            things.push(db.write_with(|w| w.create(db.me())).unwrap());
        }
        for c in calls {
            db.write_with(|w| apply(w, &wd, &things, c)).unwrap_or_else(|e| panic!("{c:?}: {e}"));
        }
    }
    (wd, things, id)
}

/// Every aspect value, placement and existence of the case's things and groups.
fn state(wd: &World, things: &[Tid]) -> Vec<String> {
    let db = &wd.db;
    let mut out = Vec::new();
    for t in things.iter().chain(&wd.groups) {
        let mut vals = Vec::new();
        for a in db.aspects(*t).unwrap() {
            // `placed.0~`: an ephemeral thing's placements, left empty where it persisted
            // (unbatched: placed while ephemeral); `groups_of` compares what they mean
            if a.as_str() == "created.0" || a.as_str() == "placed.0~" {
                continue;
            }
            vals.push(format!("{a}={:?}", db.get(*t, a.clone()).unwrap()));
        }
        out.push(format!("{t} knows={} group={:?} in={:?} {}", db.knows(*t), db.get(*t, core::GROUP).unwrap(), db.groups_of(*t), vals.join(" ")));
    }
    out
}

/// Cases in tier 1 (`case` seeds 0..CASES): about 1 s per 32; 64 includes a write after a
/// `delete` of the same thing (seed 48), which fails when `commit` reorders path ops.
const CASES: u64 = 64;

// notes/client-port.md §8 (a): a `Write` records API ops and builds the engine mutation at
// commit; a random op list (sets, edits, path ops, typed writes with schema defaults, expiry,
// group ops, `make_group`, `delete`, creates) commits to the state its ops reach one batch each.
// spec: none (API surface, notes/api.md Writes)
#[test]
fn batch_equals_single_op_batches() {
    for seed in 0..CASES {
        let (creates, calls) = case(seed);
        let (a, ta, id) = run(creates, &calls, true);
        let (b, tb, _) = run(creates, &calls, false);
        assert_eq!(ta, tb, "seed {seed}: creates draw the same tids");
        assert_eq!(state(&a, &ta), state(&b, &tb), "seed {seed}: {calls:?}");
        // the batched commit's ID: equal before and after a refactor of the write path (run
        // with --nocapture and compare)
        eprintln!("write_ops seed {seed}: {id:?}");
    }
}
