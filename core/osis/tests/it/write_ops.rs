//! The `Write` recorder (notes/client-port.md §1): a commit of API ops commits to the
//! same state as the same ops committed one commit each, for random op lists.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use crate::common::TestWrites as _;
use crate::common::*;
use osis::{Osis, Tid, Value, p};
use std::collections::BTreeMap;
use std::time::Duration;

#[allow(clippy::all, dead_code)]
mod notes {
    use osis::internals::schema as osis_schema;
    include!("../../../schema/tests/gen/notes.rs");
}

/// Untyped durable and ephemeral scalars, an untyped map (whole-value writes: the scalars).
const AKS: [&str; 3] = ["app:a.0", "app:e.0~", "app:m.0"];
const HOUR: Duration = Duration::from_secs(3600);

/// One API call of a commit; things by index into the case's things (setup ones first, then
/// the case's creates), groups by index into its two groups (`g0`: plain placements, `g1`:
/// placements expiring in an hour; one expiry per group and commit).
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
    Delete(usize),
}

impl Call {
    /// The things the call names (its group aside).
    fn things(&self) -> Vec<usize> {
        match self {
            Call::Set(t, ..) | Call::SetExpiring(t, ..) | Call::Replace(t, ..) | Call::Remove(t, _) | Call::Put(t, ..) | Call::RemoveKey(t, _) | Call::Edit(t, ..) => vec![*t],
            Call::Title(t, _) | Call::Views(t, _) | Call::Opened(t, _) | Call::Place(t, _) | Call::Unplace(t) | Call::AddSubgroup(t) | Call::RemoveSubgroup(t) | Call::Delete(t) => vec![*t],
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

/// A case: how many things it creates (first in the commit: they draw the same tids either
/// way), then its calls. Lists that would read differently batched and unbatched are
/// normalized away (a commit's `delete` removes what is held when it commits, not what
/// was written before it in it): a thing has no call before its delete, and a created thing is
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
    // a thing's first durable write does not expire: what expires goes on the things already kept
    let calls = calls
        .into_iter()
        .zip(keep)
        .filter_map(|(c, k)| k.then_some(c))
        .map(|c| match c {
            Call::SetExpiring(t, k, v) if t >= SETUP => Call::Set(t, k, v),
            Call::Opened(t, _) if t >= SETUP => Call::Views(t, 1),
            Call::Place(t, 1) if t >= SETUP => Call::Place(t, 0),
            c => c,
        })
        .collect();
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
        .commit_with(|w| {
            let things: Vec<Tid> = (0..SETUP).map(|_| w.create_durable(db.me())).collect::<osis::Result<_>>()?;
            for t in &things {
                w.at(*t, osis::DynamicAspectKey::untyped(ak(AKS[2]))).set(&Value::Map(osis_base::ValueMap::new()))?;
            }
            let g0 = w.create_durable(db.me())?;
            let g1 = w.create_durable(db.me())?;
            w.group(g0).add(osis::Member::Item(things[0]))?;
            Ok((things, [g0, g1]))
        })
        .unwrap();
    World { db, things, groups }
}

fn apply(w: &mut osis::Write<'_>, wd: &World, things: &[Tid], c: &Call) -> osis::Result<()> {
    let key = |k: usize| ak(AKS[k]);
    let m = |v: &[(i64, i64)]| Value::Map(v.iter().map(|(k, x)| (Value::Int(*k), Value::Int(*x))).collect::<BTreeMap<_, _>>().into_iter().collect());
    let [g0, g1] = wd.groups;
    match c {
        Call::Set(t, k, v) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(*k))).set(&Value::Int(*v)),
        Call::SetExpiring(t, k, v) => {
            w.expires(osis::Expiry::In(HOUR));
            w.at(things[*t], osis::DynamicAspectKey::untyped(key(*k))).set(&Value::Int(*v))
        }
        Call::Replace(t, k, v) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(*k))).overwrite(&Value::Int(*v)),
        Call::Remove(t, k) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(*k))).remove(),
        Call::Put(t, k, v) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(2))).path(p!(Value::Int(*k))).set(&Value::Int(*v)),
        Call::RemoveKey(t, k) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(2))).path(p!(Value::Int(*k))).remove(),
        Call::Edit(t, b, n) => w.at(things[*t], osis::DynamicAspectKey::untyped(key(2))).edit(&m(b), &m(n)),
        Call::Title(t, s) => w.at(things[*t], notes::TITLE).set(s),
        Call::Views(t, n) => w.at(things[*t], notes::VIEWS).path(osis::Path::root()).contribute(n),
        Call::Opened(t, v) => w.at(things[*t], notes::LAST_OPENED).set(v),
        Call::Place(t, 0) => w.group(g0).add(osis::Member::Item(things[*t])),
        Call::Place(t, _) => {
            w.expires(osis::Expiry::In(HOUR));
            w.group(g1).add(osis::Member::Item(things[*t]))
        }
        Call::Unplace(t) => w.group(g0).remove(osis::Member::Item(things[*t])),
        Call::AddSubgroup(t) => w.group(g0).add(osis::Member::Subgroup(things[*t])),
        Call::RemoveSubgroup(t) => w.group(g0).remove(osis::Member::Subgroup(things[*t])),
        Call::Delete(t) => w.delete(things[*t]),
    }
}

/// Which calls may share a commit: by expiry (none, an hour, the key's default) and by what they
/// write (`app:e.0~` is ephemeral).
fn commit_class(c: &Call) -> (u8, bool) {
    let eph = matches!(c, Call::Set(_, 1, _) | Call::SetExpiring(_, 1, _) | Call::Replace(_, 1, _) | Call::Remove(_, 1));
    match c {
        Call::SetExpiring(..) | Call::Place(_, 1) => (1, eph),
        Call::Opened(..) => (2, eph),
        _ => (0, eph),
    }
}

static REFUSED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static WHOLE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Runs the case batched (a `Write` per run of calls of one class; one the node refuses to hold as
/// one commit, one call per commit, counted in `REFUSED`) or one call per commit; the things and the last batched
/// commit's ID.
fn run(creates: usize, calls: &[Call], batched: bool) -> (World, Vec<Tid>, Option<osis::CommitId>) {
    let wd = world();
    let db = wd.db.clone();
    let mut things = wd.things.clone();
    let mut id = None;
    let mut fresh = creates;
    let runs: Vec<&[Call]> = if batched { calls.chunk_by(|a, b| commit_class(a) == commit_class(b)).collect() } else { calls.chunks(1).collect() };
    if !batched || calls.is_empty() {
        for _ in 0..std::mem::take(&mut fresh) {
            things.push(db.commit_with(|w| w.create()).unwrap());
        }
    }
    for run in runs {
        let mut w = db.write();
        let mut all = things.clone();
        for _ in 0..fresh {
            all.push(w.create().unwrap());
        }
        for c in run {
            apply(&mut w, &wd, &all, c).unwrap_or_else(|e| panic!("{c:?}: {e}"));
        }
        match w.commit() {
            Ok(c) => {
                if run.len() > 1 {
                    WHOLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                things = all;
                fresh = 0;
                id = c.map(|c| c.id).or(id);
            }
            Err(osis::Error::Invalid(_)) if batched && run.len() > 1 => {
                REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                for _ in 0..std::mem::take(&mut fresh) {
                    things.push(db.commit_with(|w| w.create()).unwrap());
                }
                for c in run {
                    db.commit_with(|w| apply(w, &wd, &things, c)).unwrap_or_else(|e| panic!("{c:?}: {e}"));
                }
            }
            Err(e) => panic!("{run:?}: {e}"),
        }
    }
    (wd, things, id)
}

/// Every aspect value, placement and existence of the case's things and groups.
fn state(wd: &World, things: &[Tid]) -> Vec<String> {
    let db = &wd.db;
    // created things are named by position: a creation-only commit is a commit (its blind drawn
    // from the engine's rng), so the tids drawn after one differ between the modes
    let name = |s: String| things.iter().enumerate().fold(s, |s, (i, t)| s.replace(&t.to_string(), &format!("T{i}")));
    let mut out = Vec::new();
    for t in things.iter().chain(&wd.groups) {
        let mut vals = Vec::new();
        for a in db.aspects(*t).unwrap() {
            // `placed.0~`: an ephemeral thing's placements, left empty where it persisted
            // (unbatched: placed while ephemeral); `groups_of` compares what they mean
            if a.as_str() == "created.0" || a.as_str() == "placed.0~" {
                continue;
            }
            vals.push(format!("{a}={:?}", db.at(*t, osis::DynamicAspectKey::untyped(a.clone())).get().unwrap()));
        }
        out.push(name(format!("{t} knows={} group={:?} in={:?} {}", db.has_content(*t).unwrap(), db.at(*t, osis::internals::core_types::GROUP).get().unwrap(), db.groups_of(*t).unwrap(), vals.join(" "))));
    }
    out
}

/// Cases in tier 1 (`case` seeds 0..CASES): about 1 s per 32; 64 includes a write after a
/// `delete` of the same thing (seed 48), which fails when `commit` reorders path ops.
const CASES: u64 = 64;

// notes/client-port.md §1: a `Write` records API ops and builds the engine mutation at
// commit; a random op list (sets, edits, path ops, typed writes with schema defaults, expiry,
// group ops, `delete`, creates) commits to the state its ops reach one commit each.
// spec: none (API surface, notes/api.md Writes)
#[test]
fn commit_equals_single_op_commits() {
    for seed in 0..CASES {
        let (creates, calls) = case(seed);
        let (a, ta, id) = run(creates, &calls, true);
        let (b, tb, _) = run(creates, &calls, false);
        assert_eq!(state(&a, &ta), state(&b, &tb), "seed {seed}: {calls:?}");
        // the batched commit's ID: equal before and after a refactor of the write path (run
        // with --nocapture and compare)
        eprintln!("write_ops seed {seed}: {id:?}");
    }
    // the point is commits: most runs of several calls must commit whole
    let (whole, refused) = (WHOLE.load(std::sync::atomic::Ordering::Relaxed), REFUSED.load(std::sync::atomic::Ordering::Relaxed));
    eprintln!("write_ops: {whole} batches whole, {refused} refused");
    assert!(whole > refused, "{whole} batches whole, {refused} refused");
}

// spec: none (notes/api.md Keys): an app's generic helper names `osis::AspectKey` alone, with or without a value type, and takes generated keys and `osis::DynamicAspectKey`
#[test]
fn a_generic_helper_names_aspect_key() {
    fn set_and_read<K: osis::AspectKey + Clone>(db: &Osis, t: Tid, k: K, v: &K::T) -> osis::Result<Option<K::T>> {
        let mut w = db.write();
        w.at(t, k.clone()).set(v)?;
        w.commit()?;
        db.at(t, k).get()
    }
    fn title_of<K: osis::AspectKey<T = String>>(db: &Osis, t: Tid, k: K) -> osis::Result<String> {
        Ok(db.at(t, k).get()?.unwrap_or_default())
    }
    let db = db(1);
    let mut w = db.write();
    let t = w.create().unwrap();
    w.commit().unwrap();
    let key = db.aspect_key("app:h.0").unwrap();
    assert_eq!(set_and_read(&db, t, key, &Value::Int(1)).unwrap(), Some(Value::Int(1)));
    assert_eq!(set_and_read(&db, t, notes::TITLE, &"x".to_string()).unwrap().as_deref(), Some("x"));
    assert_eq!(title_of(&db, t, notes::TITLE).unwrap(), "x");
}

// spec: none (notes/api.md Writes): a backward range moves nothing and says so
#[test]
fn a_backward_move_range_is_invalid() {
    let db = db(1);
    let k = ak("app:m.0");
    let mut w = db.write();
    let t = w.create().unwrap();
    #[allow(clippy::reversed_empty_ranges)]
    let back = 2..1;
    assert!(matches!(w.at(t, osis::DynamicAspectKey::untyped(k)).path(p![]).move_range(back, 0), Err(osis::Error::Invalid(_))));
}

// spec/commits.md §6, notes/api.md Writes: what clashes is judged on what the ops ask, not on what they
// turn out to write, so the same calls clash whatever the state: a `set` of the value already there
// counts, and a key's default names itself in the error.
#[test]
fn a_clash_is_judged_on_what_is_asked() {
    let db = db(2);
    db.register_schema("rv.osis", "version 1;\naspect app:d.0: int [expires: 30d];\naspect app:p.0: int;").unwrap();
    let t = db.commit_with(|w| {
        let t = w.create()?;
        w.at(t, osis::DynamicAspectKey::untyped(ak("app:a.0"))).set(&Value::Int(0))?;
        Ok(t)
    })
    .unwrap();
    let (d, plain) = (db.aspect_key("app:d.0").unwrap(), db.aspect_key("app:p.0").unwrap());
    db.commit_set(t, d.clone(), &Value::Int(1)).unwrap();
    let mut w = db.write();
    w.at(t, d.clone()).set(&Value::Int(1)).unwrap();
    w.at(t, plain.clone()).set(&Value::Int(1)).unwrap();
    assert!(matches!(w.commit(), Err(osis::Error::Invalid(m)) if m.contains("app:d.0") && m.contains("app:p.0")));
    assert_eq!(db.at(t, plain).get().unwrap(), None);
}
