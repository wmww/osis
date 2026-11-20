//! The evidence derivation (`osis_engine::evidence`, notes/evidence-derivation.md; spec/permissions.md
//! §4, as notes/a2-spec/permissions.md drafts it) against
//! held-model `evidence` (`World::req` under OPEN 10's (iv), `Open10::Granted`, entry creations
//! on, reach on), the oracle: at every step of a world, for every node's held set and every sync
//! ID's held entries, under every sync ID, the copies the derivation keeps incrementally and
//! computes from scratch equal the model's required copies, with keys-open travel off (A3's rule,
//! `Rule::fixed`) and on (brief 3's, `Stage::ReachNoErrand`: notes/a2-spec/README.md OPEN 14),
//! vouches counting and not. Hand worlds per model test naming a rule or finding (reach's in
//! `reach.rs`); the derivation's own (a waiting path entry); count tests.
use held_model::evidence::{self as hm, Open10, Rule, Shape, Stage, World};
use osis_engine::evidence::{Config, CopyId, Evidence, Hop, Kind, Part, Write};
use roles_model::paths::{self, Id, Key, Rules, Set, Thing, Things, Vouch};
use roles_model::Role;
use std::collections::{BTreeMap, BTreeSet};

mod counts;
mod hand;
mod reach;
mod walk;

type Ev = Evidence<Id, Thing, Key>;
type Copies = BTreeSet<CopyId<Id, Thing>>;
/// Held copies with their parts as the derivation takes them.
type HeldCopies = BTreeMap<CopyId<Id, Thing>, Vec<Part<Id, Thing, Key>>>;

/// The rules a world is judged by, vouches counting or not (as held-model's story tests).
fn rules(vouches: bool) -> Rules {
    Rules { vouch: if vouches { Vouch::BaseWalk } else { Vouch::Off }, ..Rules::fixed() }
}

/// `w` set to (iv) with entry creations, vouch evidence on or off.
fn granted(w: &mut World, vouches: bool) -> Rule {
    w.rules = rules(vouches);
    let mut rule = Open10::Granted.set(w, Rule::fixed());
    rule.closure.vouches = vouches;
    rule
}

/// `w` set to brief 3's rule (`Stage::ReachNoErrand`: (iv), reach, keys-open travel, no errand),
/// vouch evidence on or off.
fn brief3(w: &mut World, vouches: bool) -> Rule {
    w.rules = rules(vouches);
    let mut rule = Stage::ReachNoErrand.set(w, Rule::fixed());
    rule.closure.vouches = vouches;
    rule
}

/// The delivery a world runs under for `vouches`: A3's (the errand) with vouches counting, brief
/// 3's without. Each run compares both derivations (keys-open travel off and on) at every held set.
fn delivery(w: &mut World, vouches: bool) -> Rule {
    if vouches { granted(w, vouches) } else { brief3(w, vouches) }
}

/// Part `i` of the model's world as the derivation's input, over held set `h` whose chained
/// writes are `ch`.
fn part(w: &World, ch: &Set, i: Id) -> Part<Id, Thing, Key> {
    let pw = &w.w;
    let c = &pw.commits[i];
    let kind = match &c.kind {
        paths::Kind::Edge { holder, role, relies, .. } => Kind::Write(Write {
            holder: *holder,
            grant: w.grant(i),
            removal: w.removes(i).is_some(),
            gives_write: *role >= Role::Write,
            gives_read: *role >= Role::Read && !pw.leave(i),
            relies: *relies,
            creation: w.creation(i).map(|j| (pw.cid(j), pw.commits[j].on)),
        }),
        paths::Kind::Vouch { removal, .. } => Kind::Vouch { keyed: (pw.cid(*removal), pw.commits[*removal].on) },
        _ => Kind::Content,
    };
    let hops = pw.hops(i).iter().map(|&edge| Hop { edge, record: pw.records.contains(&edge) }).collect();
    let pos = if pw.edge_class(i) { pw.key(i) } else { pw.pos(i) };
    Part { kind, hops: Some(hops), pos, chained: ch.contains(&i) }
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
    fn new(w: &World, vouches: bool, keys_open: bool) -> Driver {
        Driver::with(w, Config { vouches, reach: true, keys_open })
    }

    fn with(w: &World, cfg: Config) -> Driver {
        let mut ev = Ev::new(cfg);
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

/// What a run compared: disagreements, comparisons where the model required some copy, held
/// sets splitting a copy (not compared).
#[derive(Default)]
struct Run {
    differ: Vec<String>,
    copies: usize,
    split: usize,
}

/// Every disagreement over the run of `w` under `rule` (its delivery): per step, per node (its
/// held set) and per sync ID's reader (its entries), for every sync ID, with keys-open travel off
/// and on: the derivation's copies (incremental and from scratch) against the model's
/// (`World::req` with `keys_open` alike).
fn differ(w: &World, rule: &Rule, vouches: bool) -> Run {
    let mut out = Run::default();
    let keys = [false, true];
    let mut nodes: Vec<[Driver; 2]> = (0..w.nodes.len()).map(|_| keys.map(|k| Driver::new(w, vouches, k))).collect();
    let mut readers: BTreeMap<Thing, [Driver; 2]> = w.sids.iter().map(|&s| (s, keys.map(|k| Driver::new(w, vouches, k)))).collect();
    let rules = keys.map(|keys_open| Rule { keys_open, ..*rule });
    w.run(rule, |st| {
        let mut held: Vec<(String, &Set, &mut [Driver; 2])> = vec![];
        for (n, d) in nodes.iter_mut().enumerate() {
            held.push((format!("node {n}"), &st.held[n], d));
        }
        for (s, d) in readers.iter_mut() {
            held.push((format!("reader of {s}"), &st.entries[s], d));
        }
        for (who, h, ds) in held {
            let split = splits_a_copy(w, h);
            out.split += usize::from(split);
            for (d, rule) in ds.iter_mut().zip(&rules) {
                d.step(w, h, &st.units);
                // incremental = from scratch, the reverse indexes current
                if let Err(e) = d.ev.check() {
                    out.differ.push(format!("step {} {who} keys-open {}: {e}", st.step, rule.keys_open));
                }
                if split {
                    continue;
                }
                for &s in &w.sids {
                    let model = model_copies(w, rule, s, &st.units, h);
                    let inc = d.required(s);
                    out.copies += usize::from(!model.is_empty());
                    if inc != model {
                        out.differ.push(format!("step {} {who} keys-open {} sid {s}: model {model:?} derivation {inc:?}", st.step, rule.keys_open));
                    }
                }
            }
        }
    });
    out
}

/// `differ` under (iv), vouches counting and not.
fn differ_both(w: &World) -> Run {
    let mut out = Run::default();
    for vouches in [true, false] {
        let mut w = w.clone();
        let rule = delivery(&mut w, vouches);
        let r = differ(&w, &rule, vouches);
        out.copies += r.copies;
        out.split += r.split;
        out.differ.extend(r.differ.into_iter().map(|d| format!("vouches {vouches}: {d}")));
    }
    out
}

/// Asserts `w` agrees; the comparisons where the model required a copy.
fn assert_agrees(name: &str, w: &World) -> usize {
    let r = differ_both(w);
    assert!(r.differ.is_empty(), "{name}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
    r.copies
}

// ---- the family, story and random worlds ----

/// Every 97th family world (the model's default slice).
#[test]
fn the_derivation_agrees_with_the_model_on_a_family_slice_spec_permissions_4() {
    let mut copies = 0;
    for i in (0..hm::FAMILY).step_by(97) {
        copies += assert_agrees(&format!("{:?}", Shape::nth(i)), &hm::family(Shape::nth(i)));
    }
    assert!(copies > 1000, "{copies}");
}

/// roles-model's story world of seed 0 under each of the six unit crossings, vouches counting on
/// every other one.
#[test]
fn the_derivation_agrees_with_the_model_on_story_worlds_spec_permissions_4() {
    for u in 0..hm::STORY_UNITS {
        let vouches = u % 2 == 0;
        let sim = paths::random_world(0, &rules(vouches));
        {
            let mut w = hm::story_world(&sim, u);
            let rule = delivery(&mut w, vouches);
            let r = differ(&w, &rule, vouches);
            assert!(r.differ.is_empty(), "story units {u} vouches {vouches}: {} disagreements, first: {}", r.differ.len(), r.differ[0]);
            eprintln!("story units {u} vouches {vouches}: {} comparisons with copies", r.copies);
        }
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
        for vouches in [true, false] {
            for u in 0..hm::STORY_UNITS {
                jobs.push(Box::new(move || {
                    let sim = paths::random_world(seed, &rules(vouches));
                    let mut w = hm::story_world(&sim, u);
                    let rule = delivery(&mut w, vouches);
                    let r = differ(&w, &rule, vouches);
                    (format!("story seed {seed} units {u} vouches {vouches}"), Run { differ: r.differ.into_iter().map(|d| format!("vouches {vouches}: {d}")).collect(), copies: r.copies, split: r.split })
                }));
            }
        }
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let bad = std::sync::Mutex::new(vec![]);
    let copies = std::sync::atomic::AtomicUsize::new(0);
    let split = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let Some(j) = jobs.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) else { return };
                let (name, r) = j();
                copies.fetch_add(r.copies, std::sync::atomic::Ordering::Relaxed);
                split.fetch_add(r.split, std::sync::atomic::Ordering::Relaxed);
                let d = r.differ;
                if !d.is_empty() {
                    bad.lock().unwrap().push(format!("{name}: {} disagreements, first: {}", d.len(), d[0]));
                }
            });
        }
    });
    let bad = bad.into_inner().unwrap();
    assert!(bad.is_empty(), "{} worlds disagree, first: {}", bad.len(), bad[0]);
    let copies = copies.into_inner();
    eprintln!("{} worlds agree, {copies} comparisons with copies, {} held sets splitting a copy not compared", jobs.len(), split.into_inner());
    assert!(copies > jobs.len(), "{copies}");
}

#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_plain_spec_permissions_4() {
    search(97, 20, 2);
}

/// Full size (`OSIS_FULL=1`): every 17th family world, 1500 random and 60 story seeds; the
/// gate's a tenth of the seeds and every 97th family world.
#[test]
#[ignore = "property"]
fn the_derivation_agrees_with_the_model_large_spec_permissions_4() {
    let full = osis_base::testenv::u64_var("OSIS_FULL") == Some(1);
    search(if full { 17 } else { 97 }, osis_base::testenv::large_n(1500), osis_base::testenv::large_n(60));
}

