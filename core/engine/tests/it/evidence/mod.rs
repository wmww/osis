//! The evidence derivation (`osis_engine::evidence`, notes/evidence-derivation.md; spec/permissions.md
//! §4, as notes/a2-spec/permissions.md and notes/a3-spec/permissions.md draft it) against
//! held-model `evidence` (`World::req` under OPEN 10's (iv), `Open10::Granted`, entry creations
//! on, keys-open travel on: `Stage::A2`), the oracle: at every step of a world, for every node's
//! held set and every sync ID's held entries, under every sync ID, the copies the derivation keeps
//! incrementally and computes from scratch equal the model's required copies with A3's leaves
//! (`Rule::listed`: leaves, addenda leaving) and without (`Rule::fixed`);
//! with leaves, the leaves equal `World::req_leaves` and each held part waits for a leaf exactly
//! where `World::pend_leaf` says. Hand worlds per model test naming a rule or finding (keys-open
//! travel's in `travel.rs`, A3's in `a3.rs`); the derivation's own (a waiting path entry); count
//! tests.
use held_model::evidence::{self as hm, Chained, Join, LeafKeep, Leafs, Open10, Rule, Shape, Stage, State, World};
use osis_engine::evidence::{Config, CopyId, Evidence, Gives, Hop, Kind, Need, Part, Write};
use roles_model::paths::{self, Id, Key, Rules, Set, Thing, Things};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

mod a3;
mod counts;
mod hand;
mod travel;
mod walk;

type Ev = Evidence<Id, Thing, Key>;
type Copies = BTreeSet<CopyId<Id, Thing>>;
/// Held copies with their parts as the derivation takes them.
type HeldCopies = BTreeMap<CopyId<Id, Thing>, Vec<Part<Id, Thing, Key>>>;

/// `w` set to (iv) with entry creations.
fn granted(w: &mut World) -> Rule {
    w.rules = Rules::fixed();
    Open10::Granted.set(w, Rule::fixed())
}

/// `w` set to A2's rule (`Stage::A2` over `Rule::fixed`: (iv), keys-open travel, no leaves).
fn a2(w: &mut World) -> Rule {
    w.rules = Rules::fixed();
    Stage::A2.set(w, Rule::fixed())
}

/// `w` set to A3's rule (`Stage::A2` over `Rule::listed`: (iv), keys-open travel, leaves read
/// where they cut and far leaves kept at home, addenda leaving).
fn a3(w: &mut World) -> Rule {
    w.rules = Rules::fixed();
    Stage::A2.set(w, Rule::listed())
}

/// The delivery a world runs under: A3's (leaves) or A2's. Each run compares both derivations
/// (A3's, A2's) at every held set.
fn delivery(w: &mut World, leaves: bool) -> Rule {
    if leaves { a3(w) } else { a2(w) }
}

/// The rules a held set is compared under: A3's and A2's.
fn compared(w: &World) -> [Rule; 2] {
    let mut w = w.clone();
    [a3(&mut w), a2(&mut w)]
}

/// Part `i` of the model's world as the derivation's input, over held set `h` whose chained
/// writes are `ch`.
fn part(w: &World, ch: &Set, i: Id) -> Part<Id, Thing, Key> {
    let pw = &w.w;
    let c = &pw.commits[i];
    let kind = match &c.kind {
        paths::Kind::Edge { holder, role, invite, .. } => Kind::Write(Write {
            holder: *holder,
            grant: w.grant(i).then(|| Gives { role: level(*role), invite: (*role == Role::Admin || *invite > Role::None).then(|| level(if *role == Role::Admin { Role::Admin } else { (*invite).min(*role) })) }),
            removal: w.removes(i).is_some(),
            gives_write: *role >= Role::Write,
            gives_read: *role >= Role::Read && !pw.leave(i),
            // Interim (issues/last-admin-rule-in-perm-engine.md): the model names no remaining
            // admin; the field goes with the engine's rule
            relies: None,
            creation: w.creation(i).map(|j| (pw.cid(j), pw.commits[j].on)),
            leaves: w.leaves_of(i).into_iter().map(|(_, t)| t).collect(),
        }),
        paths::Kind::Addendum { removal, list } => Kind::Addendum { edge: pw.sets(*removal).expect("an addendum against an edge write"), lists: list.iter().map(|&j| (pw.cid(j), pw.commits[j].on)).collect() },
        _ => Kind::Content,
    };
    let hops = pw.hops(i).iter().map(|&edge| Hop { edge, record: pw.records.contains(&edge), need: need(w, i, edge) }).collect();
    let pos = if pw.edge_class(i) { pw.key(i) } else { pw.pos(i) };
    Part { kind, hops: Some(hops), pos, chained: ch.contains(&i) }
}

/// The engine's role for a model role above none.
fn level(r: Role) -> osis_base::Role {
    match r {
        Role::None => panic!("no grant gives none"),
        Role::Read => osis_base::Role::Read,
        Role::Write => osis_base::Role::Write,
        Role::Admin => osis_base::Role::Admin,
    }
}

/// What part `i` needs of hop `e` as the model's `Join` reads it: under `Join::Needed` its least
/// need (`World::need`), else any grant (every grant gives read).
fn need(w: &World, i: Id, e: paths::Edge) -> Need {
    if w.join != Join::Needed {
        return Need::Role(osis_base::Role::Read);
    }
    match w.need(i, e) {
        (r, true) => Need::Invite(level(r)),
        (r, false) => Need::Role(level(r)),
    }
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
/// not at all (notes/a2-spec/permissions.md §4 Copies). Not compared.
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
        Driver::with(w, Config { keys_open, leaves: false })
    }

    /// A3's derivation: keys-open travel and leaves.
    fn a3(w: &World) -> Driver {
        Driver::with(w, A3)
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

    /// Moves the derivation to held set `h` and units `units`: new copies, chained flips,
    /// forgotten copies, retags.
    fn step(&mut self, w: &World, h: &Set, units: &BTreeMap<Thing, Things>) {
        let ch = w.chained(h);
        let now: HeldCopies = copies_of(w, h).into_iter().map(|(c, ids)| (c, ids.iter().map(|&i| part(w, &ch, i)).collect())).collect();
        for (c, parts) in &now {
            match self.held.get(c) {
                None => self.ev.add(*c, parts.clone()),
                // other parts held (the model's per-part events): taken again
                Some(old) if old.len() != parts.len() || old.iter().zip(parts).any(|(a, b)| a.kind != b.kind || a.hops != b.hops || a.pos != b.pos) => self.ev.add(*c, parts.clone()),
                Some(old) => {
                    for (i, (a, b)) in old.iter().zip(parts).enumerate() {
                        if a.chained != b.chained {
                            self.ev.set_chained(c, i, b.chained);
                        }
                    }
                }
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

/// A3's configuration: keys-open travel (Role changes travel whole, finding 31) and leaves.
const A3: Config = Config { keys_open: true, leaves: true };

/// The model's required leaves of `s` over `h` under `rule`, as (lowering commit, thing).
fn model_leaves(w: &World, rule: &Rule, s: Thing, units: &BTreeMap<Thing, Things>, h: &Set) -> BTreeSet<(Id, Thing)> {
    w.req_leaves(rule, s, units, h).into_iter().map(|(r, t)| (w.w.cid(r), t)).collect()
}

/// Every content-class part of `h` whose wait for a leaf (`World::pend_leaf`, holding leaves `l`)
/// the derivation's `waits` does not match: (part, model, derivation).
fn leaf_waits(w: &World, d: &mut Driver, h: &Set, l: &Leafs) -> (Vec<(Id, bool, bool)>, usize) {
    let ch = Chained::new();
    let held: BTreeSet<(Id, Thing)> = l.iter().map(|&(r, t)| (w.w.cid(r), t)).collect();
    let mut bad = vec![];
    let mut waiting = 0;
    for &i in h.iter().filter(|&&i| !w.w.edge_class(i)) {
        let model = w.pend_leaf(LeafKeep::Cuts, h, &ch, l, i);
        let ours = d.ev.waits(&(w.w.cid(i), w.on(i)), |x| held.contains(x)).is_some();
        waiting += usize::from(model);
        if model != ours {
            bad.push((i, model, ours));
        }
    }
    (bad, waiting)
}

/// What a run compared: disagreements, comparisons where the model required some copy, some leaf,
/// a part waiting on a leaf; held sets splitting a copy (not compared).
#[derive(Default)]
struct Run {
    differ: Vec<String>,
    copies: usize,
    leaves: usize,
    waits: usize,
    split: usize,
}

impl Run {
    fn add(&mut self, r: Run) {
        self.differ.extend(r.differ);
        self.copies += r.copies;
        self.leaves += r.leaves;
        self.waits += r.waits;
        self.split += r.split;
    }
}

/// Every disagreement over the run of `w` under `rule` (its delivery): per step, per node (its
/// held set) and per sync ID's reader (its entries), for every sync ID, A3's derivation against
/// the model under A3's rule (copies, leaves, waits on a leaf) and A2's against A2's rule (copies).
fn differ(w: &World, rule: &Rule) -> Run {
    let mut out = Run::default();
    let [ra3, ra2] = compared(w);
    let mut nodes: Vec<[Driver; 2]> = (0..w.nodes.len()).map(|_| [Driver::a3(w), Driver::new(w, true)]).collect();
    let mut readers: BTreeMap<Thing, [Driver; 2]> = w.sids.iter().map(|&s| (s, [Driver::a3(w), Driver::new(w, true)])).collect();
    w.run(rule, |st| {
        // (who, its held set and leaves, its derivations)
        let mut held: Vec<(String, &Set, Leafs, &mut [Driver; 2])> = vec![];
        for (n, d) in nodes.iter_mut().enumerate() {
            held.push((format!("node {n}"), &st.held[n], st.held_leaves[n].clone(), d));
        }
        for (s, d) in readers.iter_mut() {
            let h = &st.entries[s];
            held.push((format!("reader of {s}"), h, st.leaves[s].iter().copied().filter(|l| h.contains(&l.0)).collect(), d));
        }
        for (who, h, l, [da3, da2]) in held {
            let split = splits_a_copy(w, h);
            out.split += usize::from(split);
            for (d, rule, name) in [(&mut *da3, &ra3, "a3"), (&mut *da2, &ra2, "a2")] {
                d.step(w, h, &st.units);
                // incremental = from scratch, the reverse indexes current
                if let Err(e) = d.ev.check() {
                    out.differ.push(format!("step {} {who} {name}: {e}", st.step));
                }
                if split {
                    continue;
                }
                for &s in &w.sids {
                    let model = model_copies(w, rule, s, &st.units, h);
                    let inc = d.required(s);
                    out.copies += usize::from(!model.is_empty());
                    if inc != model {
                        out.differ.push(format!("step {} {who} {name} sid {s}: model {model:?} derivation {inc:?}", st.step));
                    }
                }
            }
            if split {
                continue;
            }
            out.add(a3_checks(w, &ra3, st, &who, h, &l, da3));
        }
    });
    out
}

/// A3's leaf checks over held set `h` (holding leaves `l`): per sync ID the required leaves
/// (incremental and from scratch) against `World::req_leaves`, and per held part its wait on a
/// leaf against `World::pend_leaf`.
fn a3_checks(w: &World, rule: &Rule, st: &State, who: &str, h: &Set, l: &Leafs, d: &mut Driver) -> Run {
    let mut out = Run::default();
    for &s in &w.sids {
        let model = model_leaves(w, rule, s, &st.units, h);
        let inc: BTreeSet<(Id, Thing)> = d.ev.leaves(&s).unwrap_or_default().into_keys().collect();
        let scratch: BTreeSet<(Id, Thing)> = d.ev.leaves_from_scratch(&s).unwrap_or_default().into_keys().collect();
        out.leaves += usize::from(!model.is_empty());
        if inc != model || scratch != model {
            out.differ.push(format!("step {} {who} sid {s} leaves: model {model:?} derivation {inc:?} from scratch {scratch:?}", st.step));
        }
    }
    let (bad, waiting) = leaf_waits(w, d, h, l);
    out.waits += waiting;
    if !bad.is_empty() {
        out.differ.push(format!("step {} {who} waits (part, model, derivation): {bad:?}", st.step));
    }
    out
}

/// `differ` under (iv), with A3's leaves and without.
fn differ_both(w: &World) -> Run {
    let mut out = Run::default();
    for leaves in [true, false] {
        let mut w = w.clone();
        let rule = delivery(&mut w, leaves);
        let r = differ(&w, &rule);
        out.add(Run { differ: r.differ.into_iter().map(|d| format!("leaves {leaves}: {d}")).collect(), ..r });
    }
    out
}

/// Asserts `w` agrees; the comparisons where the model required a copy.
fn assert_agrees(name: &str, w: &World) -> usize {
    assert_agrees_run(name, w).copies
}

/// Asserts `w` agrees; what was compared.
fn assert_agrees_run(name: &str, w: &World) -> Run {
    let r = differ_both(w);
    assert!(r.differ.is_empty(), "{name}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
    r
}

// ---- the family, story and random worlds ----

/// The quick check (a property): every 291st family world (the model's default slice: 106 worlds
/// over the three `Shape::mint` values), then roles-model's story world of seed 0 under each of the
/// six unit crossings, A3's leaves on every other one.
#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_plain_spec_permissions_4() {
    let mut r = Run::default();
    for i in (0..hm::FAMILY).step_by(97 * 3) {
        r.add(assert_agrees_run(&format!("{:?}", Shape::nth(i)), &hm::family(Shape::nth(i))));
    }
    eprintln!("copies {}, leaves {}, waits {}", r.copies, r.leaves, r.waits);
    assert!(r.copies > 1000 && r.leaves > 0 && r.waits > 0, "copies {}, leaves {}, waits {}", r.copies, r.leaves, r.waits);
    for u in 0..hm::STORY_UNITS {
        let leaves = u % 2 == 0;
        let sim = paths::random_world(0, &Rules::fixed());
        let mut w = hm::story_world(&sim, u);
        let rule = delivery(&mut w, leaves);
        let r = differ(&w, &rule);
        assert!(r.differ.is_empty(), "story units {u} leaves {leaves}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
        eprintln!("story units {u} leaves {leaves}: {} comparisons with copies", r.copies);
    }
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
        jobs.push(Box::new(move || (format!("{:?}", Shape::nth(i)), differ_both(&hm::family(Shape::nth(i))))));
    }
    for seed in start..start + random_worlds {
        jobs.push(Box::new(move || (format!("random seed {seed}"), differ_both(&hm::random(seed, 14)))));
    }
    for seed in start..start + story {
        for leaves in [true, false] {
            for u in 0..hm::STORY_UNITS {
                jobs.push(Box::new(move || {
                    let sim = paths::random_world(seed, &Rules::fixed());
                    let mut w = hm::story_world(&sim, u);
                    let rule = delivery(&mut w, leaves);
                    let r = differ(&w, &rule);
                    (format!("story seed {seed} units {u} leaves {leaves}"), Run { differ: r.differ.into_iter().map(|d| format!("leaves {leaves}: {d}")).collect(), ..r })
                }));
            }
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
    eprintln!("{} worlds agree; comparisons with copies {}, with leaves {}, parts waiting on a leaf {}; {} held sets splitting a copy not compared", jobs.len(), r.copies, r.leaves, r.waits, r.split);
    assert!(r.copies > jobs.len() && r.leaves > 0 && r.waits > 0, "copies {}, leaves {}, waits {}", r.copies, r.leaves, r.waits);
}

/// Full size (`OSIS_FULL=1`): every 17th family world, 1500 random and 60 story seeds; the
/// gate's a tenth of the seeds and every 97th family world.
#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_large_spec_permissions_4() {
    let full = osis_base::testenv::u64_var("OSIS_FULL") == Some(1);
    search(if full { 17 } else { 97 }, osis_base::testenv::large_n(1500), osis_base::testenv::large_n(60));
}

