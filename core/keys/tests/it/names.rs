#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Establishment by names (spec/crypto.md §4): random rotation histories of one role (forks,
//! departures in plain commits and in the rotation commits themselves, keyset lists, rotators
//! each holding a random part of what came before, writers' forged history entries, invalid
//! rotation commits, snapshots), observed by a node holding a random part of it
//! (withheld commits, secrets held or reading-only, verdicts flipping on the way, any order).
//! Checked: the established set and current epochs equal a direct reading of the rule over the
//! final held set, and the invariant: a node uses (holds the secret of an established epoch) no
//! epoch made by an honest rotator unless it holds every departure that rotator held; a departed
//! holder thus never gets a later epoch from it.

use osis_base::{CommitId, Tid};
use osis_crypto::{Epoch, Secret32};
use osis_base::Role;
use osis_keys::{Held, Key, Name, Names, Own, Provenance, RoleEpochs, Unchecked};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn ep(n: u64, k: u8) -> Epoch {
    Epoch::new(n, [k; 32]).unwrap()
}

fn cid(i: usize) -> CommitId {
    CommitId([i as u8 + 1; 32])
}

/// Commit `i`'s key: its index orders it.
fn key(i: usize) -> Key {
    Key { ts: i as u64 + 1, node: Tid::from_bytes([7; 15]), commit: cid(i) }
}

const THING: Tid = Tid::from_bytes([3; 15]);


#[derive(Clone, Debug)]
enum Kind {
    /// A departure written alone (a self-removal).
    Departure,
    /// A rotation to `epoch`, its keyset listing `list`; `departs`: it writes a departure itself.
    Rotation { epoch: Epoch, list: BTreeSet<Epoch>, departs: bool },
}

#[derive(Clone, Debug)]
struct Commit {
    kind: Kind,
    /// Valid at the observer (an invalid rotation counts for nothing).
    valid: bool,
    /// The departures its rotator held (indices of earlier departing commits): its names.
    knew: BTreeSet<usize>,
    /// A writer holding its epoch forged a second history entry naming only these.
    forged: Option<BTreeSet<usize>>,
}

#[derive(Clone, Debug)]
struct History {
    commits: Vec<Commit>,
    /// What the observer holds: commit indices.
    held: BTreeSet<usize>,
    /// Epochs whose secret it holds (checked), and reading-only.
    secrets: BTreeSet<Epoch>,
    reading: BTreeSet<Epoch>,
    /// Epochs a held `secrets.0` snapshot keys.
    snapshots: BTreeSet<Epoch>,
}

impl History {
    fn departs(&self, i: usize) -> bool {
        matches!(self.commits[i].kind, Kind::Departure | Kind::Rotation { departs: true, .. })
    }

    fn rotations_of(&self, e: Epoch) -> impl Iterator<Item = (usize, &Commit)> {
        self.commits.iter().enumerate().filter(move |(_, c)| matches!(&c.kind, Kind::Rotation { epoch, .. } if *epoch == e))
    }

    /// The names commit `i`'s history entries carry: honest, and the forger's.
    fn entries(&self, i: usize) -> Vec<Names> {
        let c = &self.commits[i];
        let Kind::Rotation { departs, .. } = c.kind else { return Vec::new() };
        let own = departs.then_some(Own { ts: key(i).ts, node: key(i).node });
        let names = |ks: &BTreeSet<usize>| Names { list: ks.iter().map(|k| Name { thing: THING, key: key(*k) }).collect(), departs: own };
        std::iter::once(names(&c.knew)).chain(c.forged.iter().map(|f| Names { departs: None, ..names(f) })).collect()
    }

    fn met(&self, k: usize) -> bool {
        self.held.contains(&k)
    }

    fn entry_met(&self, n: &Names) -> bool {
        n.list.iter().all(|x| self.met(x.key.ts as usize - 1)) && n.departs.is_none_or(|o| self.met(o.ts as usize - 1))
    }
}

struct Observer<'a>(&'a History);

impl Held for Observer<'_> {
    fn met(&self, n: &Name) -> bool {
        self.0.met(n.key.ts as usize - 1)
    }
    fn holds(&self, _: &Tid, _: Role) -> bool {
        true
    }
    fn departed(&self, own: &Own) -> bool {
        self.0.met(own.ts as usize - 1)
    }
    fn publishes(&self, _: Role, _: &Epoch, _: &osis_keys::NamesDigest) -> bool {
        true
    }
}

const LEVELS: u64 = 4;

fn history() -> impl Strategy<Value = History> {
    let commit = (any::<bool>(), 1..=LEVELS, 0u8..2, proptest::collection::btree_set((0..LEVELS, 0u8..2), 0..3), any::<bool>(), proptest::bool::weighted(0.85), proptest::collection::btree_set(0usize..12, 0..12), proptest::option::weighted(0.2, proptest::collection::btree_set(0usize..12, 0..3)));
    let rest = (proptest::collection::btree_set(0usize..12, 0..12), proptest::collection::btree_set((0..=LEVELS, 0u8..2), 0..6), proptest::collection::btree_set((0..=LEVELS, 0u8..2), 0..2), proptest::collection::btree_set((0..=LEVELS, 0u8..2), 0..2));
    (proptest::collection::vec(commit, 1..12), rest).prop_map(|(cs, (held, secrets, reading, snaps))| {
        let mut commits: Vec<Commit> = Vec::new();
        for (i, (rot, n, k, list, departs, valid, knew, forged)) in cs.into_iter().enumerate() {
            let departing: Vec<usize> = (0..i).filter(|j| matches!(commits[*j].kind, Kind::Departure | Kind::Rotation { departs: true, .. })).collect();
            // a rotator holds some of the earlier departures (an honest one names all it holds)
            let knew: BTreeSet<usize> = departing.iter().copied().filter(|j| knew.contains(j)).collect();
            let forged = forged.map(|f| f.into_iter().filter(|j| departing.contains(j)).collect());
            let kind = if rot { Kind::Rotation { epoch: ep(n, k), list: list.into_iter().filter(|(m, _)| *m < n).map(|(m, x)| ep(m, x)).collect(), departs } } else { Kind::Departure };
            commits.push(Commit { kind, valid, knew, forged });
        }
        let len = commits.len();
        History {
            commits,
            held: held.into_iter().filter(|i| *i < len).collect(),
            secrets: secrets.iter().map(|(n, k)| ep(*n, *k)).collect(),
            reading: reading.iter().map(|(n, k)| ep(*n, *k)).filter(|e| !secrets.contains(&(e.n(), e.nonce()[0]))).collect(),
            snapshots: snaps.into_iter().map(|(n, k)| ep(n, k)).collect(),
        }
    })
}

/// The epoch-0 fork 0 is the actor's fixed epoch.
fn fixed() -> Epoch {
    ep(0, 0)
}

/// spec/crypto.md §4 read directly over the final held set.
fn reference(h: &History, flips: &[bool]) -> (BTreeSet<Epoch>, Vec<Epoch>) {
    // a history entry is in the state while its commit applied valid (an invalid one's deltas are
    // stripped; names recorded while it was valid stay), or a snapshot keys it
    let carried = |i: usize, e: &Epoch| h.held.contains(&i) && (h.commits[i].valid || flips[i % 16]) || h.snapshots.contains(e);
    let epochs: BTreeSet<Epoch> = h.commits.iter().filter_map(|c| if let Kind::Rotation { epoch, .. } = c.kind { Some(epoch) } else { None }).chain(h.snapshots.iter().copied()).chain(h.secrets.iter().copied()).chain(h.reading.iter().copied()).chain([fixed()]).collect();
    let mut est = BTreeSet::from([fixed()]);
    for e in &epochs {
        let rotation = h.rotations_of(*e).any(|(i, c)| h.held.contains(&i) && c.valid);
        if !(rotation || h.snapshots.contains(e)) {
            continue;
        }
        let entries: Vec<Names> = h.rotations_of(*e).filter(|(i, _)| carried(*i, e)).flat_map(|(i, _)| h.entries(i)).collect();
        let checked = h.secrets.contains(e);
        let ok = !checked || entries.iter().any(|n| h.entry_met(n));
        if ok {
            est.insert(*e);
        }
    }
    // supersession: valid held rotation commits' lists, and history lists where the secret is
    // held (a history box lists the established epochs its rotator held: here its list)
    let sup = |f: &Epoch| -> BTreeSet<Epoch> {
        h.rotations_of(*f)
            .filter(|(i, c)| h.held.contains(i) && c.valid)
            .flat_map(|(_, c)| if let Kind::Rotation { list, .. } = &c.kind { list.clone() } else { BTreeSet::new() })
            .chain(if h.secrets.contains(f) { h.rotations_of(*f).filter(|(i, _)| carried(*i, f)).flat_map(|(_, c)| if let Kind::Rotation { list, .. } = &c.kind { list.clone() } else { BTreeSet::new() }).collect() } else { BTreeSet::new() })
            .filter(|s| s.n() < f.n())
            .collect()
    };
    let current = est.iter().filter(|e| !est.iter().any(|f| sup(f).contains(e))).copied().collect();
    (est, current)
}

/// One input to the observer's epochs.
#[derive(Clone, Debug)]
enum Step {
    /// Held rotation commit `i`: recorded valid first when `flip`, then its verdict.
    Commit(usize, bool),
    Snapshot(Epoch),
    Secret(Epoch),
}

fn apply(h: &History, steps: &[Step]) -> RoleEpochs {
    let mut r = RoleEpochs::default();
    r.set_established(fixed(), Provenance::Fixed);
    let source = Unchecked { author: Tid::from_bytes([9; 15]), commit: CommitId([0xee; 32]) };
    for s in steps {
        match s {
            Step::Commit(i, flip) => {
                let c = &h.commits[*i];
                let Kind::Rotation { epoch, list, .. } = &c.kind else { continue };
                if c.valid || *flip {
                    r.set_rotation(*epoch, cid(*i), list.clone());
                }
                if !c.valid {
                    r.invalidate(&cid(*i));
                }
            }
            Step::Snapshot(e) => {
                r.set_snapshot(*e);
            }
            Step::Secret(e) => {
                if h.secrets.contains(e) {
                    r.set_secret(*e, Secret32::from_bytes([e.n() as u8 * 2 + e.nonce()[0]; 32]));
                } else {
                    r.set_reading_secret(*e, Secret32::from_bytes([e.n() as u8 * 2 + e.nonce()[0]; 32]), source);
                }
            }
        }
        // what opening its history entries records, once its secret is held and they are
        let opened: Vec<(Epoch, Vec<Names>, BTreeSet<Epoch>)> = r
            .epochs()
            .filter(|(e, i)| i.secret.is_some() && **e != fixed())
            .map(|(e, _)| (*e, h.rotations_of(*e).filter(|(i, c)| seen(steps, s, *i, c) || snapshot_seen(steps, s, e)).flat_map(|(i, _)| h.entries(i)).collect(), history_seen(h, steps, s, e)))
            .collect();
        for (e, names, list) in opened {
            for n in names {
                if !r.is_reading_only(&e) {
                    r.add_names(e, n);
                }
            }
            if !r.is_reading_only(&e) {
                r.rotation(e, list);
            }
        }
        r.establish(&Observer(h));
    }
    r
}

/// Whether commit `i` is among the steps up to `upto`, applied valid at some point (its history
/// entries were in the state).
fn seen(steps: &[Step], upto: &Step, i: usize, c: &Commit) -> bool {
    for s in steps {
        if let Step::Commit(j, flip) = s
            && *j == i
        {
            return c.valid || *flip;
        }
        if std::ptr::eq(s, upto) {
            break;
        }
    }
    false
}

fn snapshot_seen(steps: &[Step], upto: &Step, e: &Epoch) -> bool {
    for s in steps {
        if let Step::Snapshot(x) = s
            && x == e
        {
            return true;
        }
        if std::ptr::eq(s, upto) {
            break;
        }
    }
    false
}

fn history_seen(h: &History, steps: &[Step], upto: &Step, f: &Epoch) -> BTreeSet<Epoch> {
    h.rotations_of(*f).filter(|(i, c)| seen(steps, upto, *i, c) || snapshot_seen(steps, upto, f)).flat_map(|(_, c)| if let Kind::Rotation { list, .. } = &c.kind { list.clone() } else { BTreeSet::new() }).collect()
}

fn established(r: &RoleEpochs) -> BTreeSet<Epoch> {
    r.epochs().filter(|(_, i)| i.established.is_some()).map(|(e, _)| *e).collect()
}

proptest! {
    // spec/crypto.md §4: establishment is a function of the held set (rotation commits and their
    // verdicts, snapshots, secrets, the names met), whatever order it arrived in.
    #[test]
    fn names_establish_by_the_held_set(h in history(), order in Just(()).prop_perturb(|_, mut rng| {
        let keys: Vec<u32> = (0..64).map(|_| rng.next_u32()).collect();
        let flips: Vec<bool> = (0..16).map(|_| rng.next_u32() % 3 == 0).collect();
        (keys, flips)
    })) {
        let (keys, flips) = order;
        let mut steps: Vec<(u32, Step)> = Vec::new();
        for (n, i) in h.held.iter().enumerate() {
            steps.push((keys[n], Step::Commit(*i, flips[*i % 16])));
        }
        for (n, e) in h.snapshots.iter().enumerate() {
            steps.push((keys[20 + n], Step::Snapshot(*e)));
        }
        for (n, e) in h.secrets.iter().chain(&h.reading).enumerate() {
            steps.push((keys[30 + n], Step::Secret(*e)));
        }
        steps.sort_by_key(|x| x.0);
        let steps: Vec<Step> = steps.into_iter().map(|x| x.1).collect();
        let r = apply(&h, &steps);
        let (est, current) = reference(&h, &flips);
        prop_assert_eq!(established(&r), est.clone(), "established");
        prop_assert_eq!(r.current(), current, "current");
        // the invariant: an epoch used here (established, secret held) whose entries are all
        // honest has, among its rotations whose entries are here, one whose rotator's departures
        // (its own included) are all met here
        let carried = |i: usize, e: &Epoch| h.held.contains(&i) && (h.commits[i].valid || flips[i % 16]) || h.snapshots.contains(e);
        for e in est.iter().filter(|e| h.secrets.contains(e) && **e != fixed()) {
            if h.rotations_of(*e).any(|(_, c)| c.forged.is_some()) {
                continue;
            }
            let ok = h.rotations_of(*e).filter(|(i, _)| carried(*i, e)).any(|(i, c)| c.knew.iter().all(|k| h.met(*k)) && (!h.departs(i) || h.met(i)));
            prop_assert!(ok, "epoch {e:?} used without a departure its rotator held");
        }
    }
}

// spec/crypto.md §4 (names): a writer's forged history entry with fewer names establishes the
// epoch where the genuine one does not: accepted, the writer held the epoch and could leak it.
#[test]
fn forged_entry_by_a_holder_is_accepted() {
    let e = ep(2, 0);
    let mut r = RoleEpochs::default();
    r.set_rotation(e, cid(1), BTreeSet::new());
    r.set_secret(e, Secret32::from_bytes([1; 32]));
    let h = History { commits: Vec::new(), held: BTreeSet::new(), secrets: BTreeSet::new(), reading: BTreeSet::new(), snapshots: BTreeSet::new() };
    r.add_names(e, Names { list: [Name { thing: THING, key: key(0) }].into(), departs: None });
    r.establish(&Observer(&h));
    assert!(!r.is_established(&e));
    r.add_names(e, Names::default());
    r.establish(&Observer(&h));
    assert!(r.is_established(&e));
}
