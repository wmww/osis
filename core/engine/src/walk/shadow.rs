//! Debug builds: the shadow walk. Beside today's walk, which decides, the engine keeps the walk
//! along stated paths (`osis_perm::paths::Paths`) over the same held commits, fed through the
//! adapter (`walk::input`), and compares the two at the end of every durable transaction and at
//! the engine's drop: every difference must fall in a designed class (`walk::classes`), else the
//! check fails the test. At the drop it also checks the incremental walk against one from scratch
//! over the adapter's whole input.
//!
//! Feeding: what moved since the last sync, by one diff of the adapter's input against what the
//! shadow was given (`fed`), over the commits reported moved (`Held::take_walk_moved`: perm's
//! held reading of a role commit, a commit's record or rotation role changed by a transaction,
//! committed or rolled back): O(what moved). A changed input is an `update`, a new one an
//! `add`, one gone a `forget`; a record moved or the trust set changed builds the walk anew
//! (`Paths` takes its records at construction) or `set_trust`. A rolled-back transaction needs
//! nothing: the shadow syncs only after durable transactions, and what a rollback restores is
//! reported moved, so the next diff gives the walk the restored input.

use super::classes::{self, World};
use super::input::{self, Input};
use crate::engine::Core;
use osis_base::{CommitId, Tid};
use super::store::EngineStore;
use osis_perm::paths::Paths;
use osis_perm::WriteId;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Shadow {
    paths: Paths<EngineStore>,
    fed: BTreeMap<CommitId, Input>,
    records: BTreeMap<Tid, Tid>,
    trust: BTreeSet<WriteId>,
    /// Commits adapted by syncs since built (count tests).
    pub(crate) adapted: u64,
}

impl Shadow {
    /// The walk over everything `core` holds (an open, a rebuild, a record moved).
    fn build(core: &Core) -> Shadow {
        let fed = input::all(core);
        for (id, i) in &fed {
            assert!(classes::as_written(core, i), "the walk's input of {id:?} states other than its header: {i:?}");
        }
        let records = input::records(core);
        let trust = input::trust(core, &fed);
        let commits: Vec<_> = fed.values().map(|i| i.commit.clone()).collect();
        let mut paths = Paths::with_store(&records, trust.clone(), EngineStore::default());
        paths.add(&commits);
        Shadow { paths, fed, records, trust, adapted: 0 }
    }

    /// Brings the walk to what `core` holds now.
    fn sync(&mut self, core: &mut Core) {
        let moved = core.ix.held.take_walk_moved();
        if moved.epochs || (moved.records && input::records(core) != self.records) {
            let adapted = self.adapted;
            *self = Shadow::build(core);
            self.adapted = adapted;
            return;
        }
        let ids: BTreeSet<CommitId> = moved.commits;
        let (mut add, mut upd, mut gone) = (Vec::new(), Vec::new(), Vec::new());
        for id in ids {
            self.adapted += 1;
            let now = if core.ix.commits.contains_key(&id) { input::commit(core, &id) } else { None };
            if let Some(n) = &now {
                assert!(classes::as_written(core, n), "the walk's input of {id:?} states other than its header: {n:?}");
            }
            match (self.fed.get(&id), now) {
                (None, None) => {}
                (Some(_), None) => {
                    self.fed.remove(&id);
                    gone.push(id);
                }
                (None, Some(n)) => {
                    add.push(n.commit.clone());
                    self.fed.insert(id, n);
                }
                (Some(was), Some(n)) if !was.same(&n) => {
                    upd.push(n.commit.clone());
                    self.fed.insert(id, n);
                }
                _ => {}
            }
        }
        self.paths.forget(&gone);
        self.paths.add(&add);
        self.paths.update(&upd);
        let trust = input::trust(core, &self.fed);
        if trust != self.trust {
            self.paths.set_trust(trust.clone());
            self.trust = trust;
        }
    }
}

/// Debug builds, at the end of a durable transaction: the shadow walk brought up to date and
/// compared with today's (`Shadow`).
pub(crate) fn after_transaction(shadow: &mut Option<Shadow>, core: &mut Core, when: &str) {
    match shadow {
        Some(s) => s.sync(core),
        None => *shadow = Some(Shadow::build(core)),
    }
    if let Some(s) = shadow {
        check(s, core, when);
    }
}

/// Debug builds, at the engine's drop: as `after_transaction`, and the incremental walk read as
/// one from scratch.
pub(crate) fn at_drop(shadow: &mut Option<Shadow>, core: &mut Core) {
    after_transaction(shadow, core, "end of history");
    let Some(s) = shadow else { return };
    let fresh = Shadow::build(core);
    assert_eq!(fresh.fed.keys().collect::<Vec<_>>(), s.fed.keys().collect::<Vec<_>>(), "the shadow walk's input: fed incrementally, not as held");
    for (id, i) in &fresh.fed {
        assert!(s.fed.get(id).is_some_and(|x| x.same(i)), "the shadow walk's input of {id:?}: fed incrementally {:?}, held {i:?}", s.fed.get(id));
    }
    assert_eq!(s.trust, fresh.trust, "the shadow walk's trust set");
    assert_eq!(s.paths.statuses(), fresh.paths.statuses(), "the shadow walk: incremental statuses, not from scratch");
    assert_eq!(s.paths.finals(), fresh.paths.finals(), "the shadow walk: incremental final roles, not from scratch");
    assert_eq!(s.paths.contents(), fresh.paths.contents(), "the shadow walk: incremental content verdicts, not from scratch");
}

/// Fails the test on a difference no designed class takes. `OSIS_SHADOW_LOG=FILE` (a measure)
/// appends every difference with its class and the test's name (worker threads carry their
/// test's name: `testenv::spawn_named`), one line each: the class counts of notes/perm-paths.md,
/// The switch.
fn check(s: &Shadow, core: &Core, when: &str) {
    let w = World { core, inputs: &s.fed, paths: &s.paths };
    let all = classes::differences(core, &s.fed, &s.paths);
    let classed: Vec<_> = all.iter().zip(classes::classify_all(&w, &all)).collect();
    if let Ok(f) = std::env::var("OSIS_SHADOW_LOG") {
        let name = std::thread::current().name().unwrap_or("?").to_string();
        let out: String = classed.iter().map(|(d, c)| format!("{name}\t{}\t{when}\t{d:?}\n", c.map_or("UNCLASSED", |c| c.name))).collect();
        use std::io::Write;
        if let Ok(mut fh) = std::fs::OpenOptions::new().create(true).append(true).open(f) {
            let _ = fh.write_all(out.as_bytes());
        }
    }
    let bad: Vec<_> = classed.into_iter().filter(|(_, c)| c.is_none()).map(|(d, _)| d).collect();
    assert!(bad.is_empty(), "{when}: the walk along stated paths differs from today's outside every designed class (notes/perm-paths.md, The switch): {bad:#?}");
}
