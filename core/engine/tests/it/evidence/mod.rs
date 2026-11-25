//! The evidence derivation (`osis_engine::evidence`, notes/evidence-derivation.md;
//! spec/permissions.md §4) against held-model `evidence` (`World::req` under `Rule::fixed`: every
//! edge write on a stated path's edges, keys-open travel on), the oracle: at every step of a
//! world, for every node's held set and every sync ID's held entries, under every sync ID, the
//! copies the derivation keeps incrementally and computes from scratch equal the model's required
//! copies. Hand worlds per model test naming a rule or finding (keys-open travel's in
//! `travel.rs`); the derivation's own (a waiting path entry, delete-key steps); count tests.
use held_model::evidence::{self as hm, Rule, Shape, World};
use osis_engine::evidence::{Config, CopyId, Evidence, Kind, Part, Write};
use roles_model::paths::{self, Id, Key, Rules, Set, Thing, Things};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

mod counts;
mod engine;
mod hand;
mod steps;
mod travel;
mod walk;

type Ev = Evidence<Id, Thing, Key>;
type Copies = BTreeSet<CopyId<Id, Thing>>;
/// Held copies with their parts as the derivation takes them.
type HeldCopies = BTreeMap<CopyId<Id, Thing>, Vec<Part<Thing, Key>>>;

/// The model's rule as the derivation is built: no carried-demotion seed, and S's key part only
/// on an edge giving S read (the rest is cut as sync copies outside the derivation:
/// `Rule::key_part_whole`).
// Interim (issues/engine-evidence-trails-model.md): `keysets` goes when the derivation builds the keyset seed
fn derived() -> Rule {
    Rule { keysets: false, key_part_whole: false, ..Rule::fixed() }
}

/// `w` set to the spec's rule (`Rule::fixed`, as the derivation is built).
fn e1(w: &mut World) -> Rule {
    w.rules = Rules::fixed();
    derived()
}

/// Part `i` of the model's world as the derivation's input, `reads` the writes giving read that
/// the node holding it judges valid (`World::reads_valid`), as the engine feeds it.
fn part(w: &World, i: Id, reads: &Set) -> Part<Thing, Key> {
    let pw = &w.w;
    let kind = match &pw.commits[i].kind {
        paths::Kind::Edge { holder, role, .. } => Kind::Write(Write { holder: *holder, gives_read: *role >= Role::Read && !pw.leave(i) && reads.contains(&i) }),
        _ => Kind::Content,
    };
    Part::new(kind, Some(pw.hops(i).to_vec()))
}

/// The held copies of `h` with their held parts in id order.
fn copies_of(w: &World, h: &Set) -> BTreeMap<CopyId<Id, Thing>, Vec<Id>> {
    let mut out: BTreeMap<CopyId<Id, Thing>, Vec<Id>> = BTreeMap::new();
    for &i in h {
        out.entry((w.w.cid(i), w.on(i))).or_default().push(i);
    }
    out
}

/// `h` holds some parts of a commit on a thing and not others. The model writes each part of a
/// commit as an event of its own; no node holds such a set: a commit's edge writes on a thing are
/// one `roles.0` delta (spec/crdt.md §2: one delta per tid and aspect), and a copy is held whole or
/// not at all (spec/permissions.md §4 Copies). Not compared.
fn splits_a_copy(w: &World, h: &Set) -> bool {
    copies_of(w, h).iter().any(|(c, held)| w.w.part_ids(c.0).filter(|&p| w.on(p) == c.1).count() != held.len())
}

/// One node's derivation, fed the model's held set and units step by step.
struct Driver {
    ev: Ev,
    held: HeldCopies,
    units: BTreeMap<Thing, Things>,
}

impl Driver {
    fn new(w: &World, keys_open: bool) -> Driver {
        Driver::with(w, Config { keys_open })
    }

    fn with(w: &World, cfg: Config) -> Driver {
        let mut ev = Ev::new(cfg);
        for &e in &w.w.records {
            ev.add_record(e);
        }
        for &s in &w.sids {
            ev.add_sid(s, s);
        }
        Driver { ev, held: BTreeMap::new(), units: w.sids.iter().map(|&s| (s, Things::new())).collect() }
    }

    /// Moves the derivation to held set `h` and units `units`: new copies, forgotten copies,
    /// retags.
    fn step(&mut self, w: &World, h: &Set, units: &BTreeMap<Thing, Things>) {
        let reads = w.reads_valid(h);
        let now: HeldCopies = copies_of(w, h).into_iter().map(|(c, ids)| (c, ids.iter().map(|&i| part(w, i, &reads)).collect())).collect();
        for (c, parts) in &now {
            // other parts held (the model's per-part events): taken again
            if self.held.get(c) != Some(parts) {
                self.ev.add(*c, parts.clone());
            }
        }
        // forgotten together, as a compaction drops its bodies
        self.ev.forget_all(self.held.keys().filter(|c| !now.contains_key(c)).copied());
        self.held = now;
        for (s, unit) in units {
            let old = self.units.get(s).cloned().unwrap_or_default();
            for &t in unit.difference(&old) {
                self.ev.join(s, t);
            }
            for &t in old.difference(unit) {
                self.ev.leave(s, t);
            }
        }
        self.units = units.clone();
    }

    fn required(&self, s: Thing) -> Copies {
        self.ev.required(&s).map(|m| m.keys().copied().collect()).unwrap_or_default()
    }
}

/// The model's required copies of `s` over `h`: its required parts on things outside the unit,
/// by (commit, thing).
fn model_copies(w: &World, rule: &Rule, s: Thing, units: &BTreeMap<Thing, Things>, h: &Set) -> Copies {
    w.req(rule, s, units, h).into_iter().filter(|&i| !units[&s].contains(&w.on(i))).map(|i| (w.w.cid(i), w.on(i))).collect()
}

/// What a run compared: disagreements, comparisons where the model required some copy; held sets
/// splitting a copy (not compared).
#[derive(Default)]
struct Run {
    differ: Vec<String>,
    copies: usize,
    split: usize,
}

impl Run {
    fn add(&mut self, r: Run) {
        self.differ.extend(r.differ);
        self.copies += r.copies;
        self.split += r.split;
    }
}

/// Every disagreement over the run of `w` under the spec's rule: per step, per node (its held set) and
/// per sync ID's reader (its entries), for every sync ID, the derivation's copies against the
/// model's.
fn differ(w: &World) -> Run {
    let mut out = Run::default();
    let mut w = w.clone();
    let rule = e1(&mut w);
    let w = &w;
    let mut nodes: Vec<Driver> = (0..w.nodes.len()).map(|_| Driver::new(w, true)).collect();
    let mut readers: BTreeMap<Thing, Driver> = w.sids.iter().map(|&s| (s, Driver::new(w, true))).collect();
    w.run(&rule, |st| {
        let mut held: Vec<(String, &Set, &mut Driver)> = vec![];
        for (n, d) in nodes.iter_mut().enumerate() {
            held.push((format!("node {n}"), &st.held[n], d));
        }
        for (s, d) in readers.iter_mut() {
            held.push((format!("reader of {s}"), &st.entries[s], d));
        }
        for (who, h, d) in held {
            let split = splits_a_copy(w, h);
            out.split += usize::from(split);
            d.step(w, h, &st.units);
            // incremental = from scratch, the reverse indexes current
            if let Err(e) = d.ev.check() {
                out.differ.push(format!("step {} {who}: {e}", st.step));
            }
            if split {
                continue;
            }
            for &s in &w.sids {
                let model = model_copies(w, &rule, s, &st.units, h);
                let inc = d.required(s);
                out.copies += usize::from(!model.is_empty());
                if inc != model {
                    out.differ.push(format!("step {} {who} sid {s}: model {model:?} derivation {inc:?}", st.step));
                }
            }
        }
    });
    out
}

/// Asserts `w` agrees; the comparisons where the model required a copy.
fn assert_agrees(name: &str, w: &World) -> usize {
    assert_agrees_run(name, w).copies
}

/// Asserts `w` agrees; what was compared.
fn assert_agrees_run(name: &str, w: &World) -> Run {
    let r = differ(w);
    assert!(r.differ.is_empty(), "{name}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
    r
}

// ---- the family, story and random worlds ----

/// The quick check (a property): every 291st family world (the model's default slice: 106 worlds
/// over the three `Shape::mint` values), then roles-model's story world of seed 0 under each of the
/// six unit crossings.
#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_plain_spec_permissions_4() {
    let mut r = Run::default();
    for i in (0..hm::FAMILY).step_by(97 * 3) {
        r.add(assert_agrees_run(&format!("{:?}", Shape::nth(i)), &hm::family(Shape::nth(i))));
    }
    eprintln!("copies {}", r.copies);
    assert!(r.copies > 1000, "copies {}", r.copies);
    for u in 0..hm::STORY_UNITS {
        let sim = paths::random_world(0, &Rules::fixed());
        let w = hm::story_world(&sim, u);
        let r = differ(&w);
        assert!(r.differ.is_empty(), "story units {u}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
        eprintln!("story units {u}: {} comparisons with copies", r.copies);
    }
}

// Interim (issues/engine-evidence-trails-model.md): the engine reads no key hop until A4; a story
// world with an edge write on a key hop or a commit signed by a key other than its signer's own (moves 54, 55) is
// the model's alone
fn other_keys(sim: &paths::Sim) -> bool {
    (0..sim.w.commits.len()).any(|j| sim.w.key_write(j) || sim.w.commits[j].key != paths::own_key(sim.w.commits[j].signer))
}

/// Random worlds (junk, hostile paths, two-holder removals, retags), story worlds under the six
/// crossings, a family slice: `n` random seeds and `story` story seeds from `OSIS_HELD_START`, a
/// thread per core.
fn search(family_step: usize, random_worlds: u64, story: u64) {
    let start = std::env::var("OSIS_HELD_START").ok().filter(|v| !v.is_empty()).map_or(0, |v| v.parse::<u64>().expect("OSIS_HELD_START is a decimal u64"));
    eprintln!("evidence derivation: random seeds {start}..{}, story seeds {start}..{}", start + random_worlds, start + story);
    type Job = Box<dyn Fn() -> (String, Run) + Sync>;
    let mut jobs: Vec<Job> = vec![];
    for i in (0..hm::FAMILY).step_by(family_step) {
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), differ(&hm::family(Shape::nth(i))))));
    }
    for seed in start..start + random_worlds {
        jobs.push(Box::new(move || (format!("random seed {seed}"), differ(&hm::random(seed, 14)))));
    }
    for seed in start..start + story {
        for u in 0..hm::STORY_UNITS {
            jobs.push(Box::new(move || {
                let sim = paths::random_world(seed, &Rules::fixed());
                if other_keys(&sim) {
                    return (format!("story seed {seed} units {u}"), Run::default());
                }
                (format!("story seed {seed} units {u}"), differ(&hm::story_world(&sim, u)))
            }));
        }
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let total = std::sync::Mutex::new(Run::default());
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, mut r) = j();
                let d = std::mem::take(&mut r.differ);
                total.lock().unwrap().add(r);
                if !d.is_empty() {
                    bad.lock().unwrap().push(format!("{name}: {} disagreements, first: {}", d.len(), d[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} worlds disagree, first: {}", bad.len(), bad[0]);
    let r = total.into_inner().unwrap();
    eprintln!("{} worlds agree; comparisons with copies {}; {} held sets splitting a copy not compared", jobs.len(), r.copies, r.split);
    assert!(r.copies > jobs.len(), "copies {}", r.copies);
}

/// Full size (`OSIS_FULL=1`): every 17th family world, 1500 random and 60 story seeds; the
/// gate's a tenth of the seeds and every 97th family world.
#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_large_spec_permissions_4() {
    let full = osis_base::testenv::u64_var("OSIS_FULL") == Some(1);
    search(if full { 17 } else { 97 }, osis_base::testenv::large_n(1500), osis_base::testenv::large_n(60));
}

