//! The certificates of the things this node reads (`Engine::sync_certificates`), indexed per
//! commit (`Certified`): `sync_bodies` reads one commit's row, the record module one thing's
//! records.
//!
//! Each read thing's certificates are followed by what deriving them read (`memo::Effects`: the
//! kept evidence derivation's rows, `evidence::kept`, and the engine's indexes), so a follow
//! derives those of the things whose inputs moved since the last and writes the rows that
//! changed. It runs whenever the engine's state moved since the last follow (`Core::generation`).

use super::ThingSync;
use crate::Engine;
use crate::error::Result;
use crate::evidence::held::Ev;
use crate::sync_ids::{Certs, Parts};
use osis_base::memo::{Effects, Feed, Stamped, StampedSet, Unrecorded};
use osis_base::{CommitId, Tid};
use std::collections::BTreeSet;
use std::sync::Arc;

/// What one thing's certificates name of a commit: parts to carry, whether its header goes alone
/// (`Certs::headers`), and the things it is a held minting of whose records go
/// (`Certs::mintings`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Named {
    pub parts: Parts,
    pub header: bool,
    pub mints: BTreeSet<Tid>,
}

impl Named {
    fn of(certs: &Certs, c: &CommitId) -> Option<Named> {
        let parts = certs.commits.get(c).cloned().unwrap_or_default();
        let header = certs.headers.contains(c);
        let mints = certs.mintings.get(c).cloned().unwrap_or_default();
        (header || !parts.is_empty() || !mints.is_empty()).then_some(Named { parts, header, mints })
    }
}

/// The commits `certs` names anything of.
fn named(certs: &Certs) -> BTreeSet<CommitId> {
    certs.commits.keys().chain(&certs.headers).chain(certs.mintings.keys()).copied().collect()
}

/// Each read thing's certificates as last derived (`None`: read no more), followed by what
/// deriving them read.
#[derive(Clone)]
struct Follow {
    certs: Effects<Tid, Option<Arc<Certs>>>,
    /// The things read from the first follow on (`SyncRows::read`'s feed).
    read: Option<Feed<Tid>>,
    /// Follows that derived anything, for the debug comparison's schedule.
    #[cfg(debug_assertions)]
    follows: u64,
}

impl Default for Follow {
    fn default() -> Self {
        Follow {
            certs: Effects::new("certified: certificates"),
            read: None,
            #[cfg(debug_assertions)]
            follows: 0,
        }
    }
}

/// The certificates of the things this node reads, indexed by commit and by read thing.
#[derive(Clone, Default)]
pub(crate) struct Certified {
    /// `Core::generation` and `memory_generation` at the last follow that succeeded.
    at: Option<(u64, u64)>,
    follow: Follow,
    /// Read things whose certificates were derived so far: what a count test reads.
    pub(crate) derived: u64,
    /// The read things.
    pub(crate) read: StampedSet<Tid>,
    /// Per (commit, read thing) whose certificates name it, what they name.
    of: Stamped<(CommitId, Tid), Named>,
    /// Per commit, the read things whose certificates name it.
    naming: Stamped<CommitId, Arc<BTreeSet<Tid>>>,
    /// Per read thing, the records its certificates name.
    records: Stamped<Tid, Arc<BTreeSet<Tid>>>,
    /// Per record, the read things whose certificates name it (`records` the other way).
    pub(crate) namers: Stamped<Tid, Arc<BTreeSet<Tid>>>,
}

/// Adds `t` to the set at `k` (`add`) or takes it out, an emptied set leaving; `fed`: a key new
/// to the map goes to its feed.
fn member<K: Ord + Clone + std::hash::Hash + Send + Sync + 'static>(m: &mut Stamped<K, Arc<BTreeSet<Tid>>>, k: &K, t: &Tid, add: bool, fed: bool) {
    let f = |v: Option<Arc<BTreeSet<Tid>>>| {
        let mut v = v.unwrap_or_default();
        let s = Arc::make_mut(&mut v);
        if add {
            s.insert(*t);
        } else {
            s.remove(t);
        }
        (!v.is_empty()).then_some(v)
    };
    match fed {
        true => m.update_fed(k.clone(), f),
        false => m.update(k.clone(), f),
    }
}

impl Certified {
    /// Read thing `g`'s certificates moved from `was` to `now` (`None`: not read): its rows
    /// written where they differ.
    fn put(&mut self, g: &Tid, was: Option<&Certs>, now: Option<&Certs>) {
        match now {
            Some(_) => self.read.insert(*g),
            None => self.read.remove(g),
        };
        let none = Certs::default();
        let (was, now) = (was.unwrap_or(&none), now.unwrap_or(&none));
        // per (commit, thing), and per commit
        for id in named(was).union(&named(now)) {
            let (a, b) = (Named::of(was, id), Named::of(now, id));
            if a == b {
                continue;
            }
            if a.is_some() != b.is_some() {
                member(&mut self.naming, id, g, b.is_some(), false);
            }
            self.of.update((*id, *g), |_| b);
        }
        // its records, and per record its namers
        if was.records != now.records {
            let v = (!now.records.is_empty()).then(|| Arc::new(now.records.clone()));
            self.records.update(*g, |_| v);
        }
        for r in was.records.difference(&now.records) {
            member(&mut self.namers, r, g, false, true);
        }
        for r in now.records.difference(&was.records) {
            member(&mut self.namers, r, g, true, true);
        }
    }
}

impl Engine {
    /// The things whose certificates `Certified` keeps: those holding a read sync ID
    /// (`SyncRows::read`), whole: for tests.
    #[cfg(test)]
    pub(crate) fn read_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_rows()?;
        Ok(Arc::new((*self.core.sync_rows.read).clone()))
    }

    /// Brings `Certified` up to date. Read by no caller: what a caller reads is the rows
    /// (`certified`, `certified_records`). Whether a row moved.
    pub(crate) fn follow_certificates(&mut self) -> Result<bool> {
        if self.certificates_quiet()? {
            return Ok(false);
        }
        osis_base::costs::count("certified: follows", 1);
        let _u = Unrecorded::start();
        let at = self.generations();
        let r = self.follow_due();
        self.core.certified.at = r.is_ok().then_some(at);
        r
    }

    /// Whether `follow_certificates` would do nothing: neither the engine's state nor the read
    /// things (`SyncRows::read`, which a link followed or a holding moving changes with no
    /// transaction) moved since the last.
    pub(crate) fn certificates_quiet(&mut self) -> Result<bool> {
        self.follow_rows()?;
        // the follow's own check: what reads the rows follows them, not this
        let _u = Unrecorded::start();
        Ok(self.core.certified.at == Some(self.generations()) && self.core.certified.read.iter().eq(self.core.sync_rows.read.iter()))
    }

    fn generations(&self) -> (u64, u64) {
        (self.core.generation, self.core.memory_generation)
    }

    /// The certificates of each read thing whose inputs moved since the last follow derived
    /// anew, the rows written where they moved. Whether any did.
    fn follow_due(&mut self) -> Result<bool> {
        self.follow_rows()?;
        let ev = self.kept_evidence()?;
        let mut f = std::mem::take(&mut self.core.certified.follow);
        let came: Vec<Tid> = match f.read.as_mut() {
            Some(feed) => feed.added(),
            None => {
                f.read = Some(self.core.sync_rows.read.feed());
                self.core.sync_rows.read.iter().copied().collect()
            }
        };
        for g in came {
            f.certs.want(g);
        }
        let mut moved = false;
        let due = f.certs.due();
        #[cfg(debug_assertions)]
        let compare = !due.is_empty() && {
            f.follows += 1;
            f.follows.is_power_of_two()
        };
        for g in due {
            if !f.certs.checking(&g) {
                self.core.certified.derived += 1;
            }
            let Some((was, now)) = f.certs.settle(&g, || self.certificates_read(&ev, &g)) else { continue };
            self.core.certified.put(&g, was.flatten().as_deref(), now.as_deref());
            moved = true;
            if now.is_none() {
                f.certs.unwant(&g);
            }
        }
        #[cfg(debug_assertions)]
        if compare {
            let differs = osis_base::costs::paused(|| self.certified_differs(&ev, &f));
            debug_assert_eq!(differs, None, "the followed certificates differ from those derived anew");
        }
        self.core.certified.follow = f;
        Ok(moved)
    }

    /// `g`'s certificates while it is a read thing.
    fn certificates_read(&mut self, ev: &Ev, g: &Tid) -> Option<Arc<Certs>> {
        self.core.sync_rows.read.contains(g).then(|| Arc::new(self.sync_certificates(ev, g)))
    }

    /// The first difference between what `f` and the rows keep and every read thing's
    /// certificates derived anew (tests, debug builds).
    fn certified_differs(&mut self, ev: &Ev, f: &Follow) -> Option<String> {
        let read: Vec<Tid> = self.core.sync_rows.read.iter().copied().collect();
        let mut anew = Certified::default();
        for g in &read {
            let now = self.sync_certificates(ev, g);
            if f.certs.current(g).flatten().as_deref() != Some(&now) {
                return Some(format!("read thing {g:?}: followed {:?}, derived anew {now:?}", f.certs.current(g)));
            }
            anew.put(g, None, Some(&now));
        }
        let c = &self.core.certified;
        if !c.read.iter().eq(read.iter()) {
            return Some(format!("the rows' read things {:?}, read {read:?}", c.read.iter().collect::<Vec<_>>()));
        }
        (!c.of.iter().eq(anew.of.iter()) || !c.naming.iter().eq(anew.naming.iter()) || !c.records.iter().eq(anew.records.iter()) || !c.namers.iter().eq(anew.namers.iter())).then(|| "a certificate row is not the one written from nothing".to_string())
    }

    /// `certified_differs` of the state as followed (tests: `check_evidence`).
    pub(crate) fn check_certified(&mut self) -> Result<Option<String>> {
        self.follow_certificates()?;
        let ev = self.kept_evidence()?;
        let f = std::mem::take(&mut self.core.certified.follow);
        let out = osis_base::costs::paused(|| self.certified_differs(&ev, &f));
        self.core.certified.follow = f;
        Ok(out)
    }

    /// Per thing read here whose certificates name commit `c`, what they name of it, and the
    /// thing's read sync IDs (spec/permissions.md §4): a read of `c`'s rows alone.
    pub(crate) fn certified(&mut self, c: &CommitId) -> Result<Vec<(Tid, Named, Vec<osis_base::SyncId>)>> {
        self.follow_certificates()?;
        let things = self.core.certified.naming.get(c).cloned().unwrap_or_default();
        let mut out = Vec::new();
        for t in things.iter() {
            let Some(n) = self.core.certified.of.get(&(*c, *t)).cloned() else { continue };
            if let ThingSync::Read(ids) = self.thing_sync(t)? {
                out.push((*t, n, ids));
            }
        }
        Ok(out)
    }

    /// What read thing `t`'s certificates name of commit `c`: a read of that pair alone.
    pub(crate) fn certified_of(&mut self, c: &CommitId, t: &Tid) -> Result<Option<Named>> {
        self.follow_certificates()?;
        Ok(self.core.certified.of.get(&(*c, *t)).cloned())
    }

    /// The records read thing `t`'s certificates name (`Certs::records`), a read of `t`'s entry
    /// alone: for tests (`Certified::namers` is what the follows read).
    #[cfg(test)]
    pub(crate) fn certified_records(&mut self, t: &Tid) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_certificates()?;
        Ok(self.core.certified.records.get(t).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Engine;
    use crate::Mutation;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    /// The rows `follow_cert_records` keeps equal those derived whole from the certificates.
    fn check(e: &mut Engine, step: &str) {
        e.follow_certificates().unwrap();
        let things = e.read_things().unwrap();
        e.follow_cert_records().unwrap();
        assert!(e.core.cert_records.rows.keys().all(|t| things.contains(t)), "{step}: a certificate record row of a thing not read");
        for t in things.iter() {
            let got = e.core.cert_records.rows.get(t).map(|x| (**x).clone()).unwrap_or_default();
            assert_eq!(got, e.cert_records_whole(t).unwrap(), "{step}: certificate records of {t:?}");
        }
    }

    // spec/permissions.md §4 Evidence of a sync ID: a thing granted across three accounts and
    // written by each; at every step every node's list and record rows equal their derivation
    // whole, and a reader holds what its write rests on.
    #[test]
    fn rows_follow_the_certificates_spec_permissions_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &ak, &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
        lp.hold(t);
        let edge = |role| ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &edge(Role::Write)).unwrap();
        lp.peers[0].engine.grant(&t, &c, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        for p in &mut lp.peers {
            check(&mut p.engine, "granted");
        }
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(2)).unwrap();
        lp.peers[1].commit(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        for p in &mut lp.peers {
            check(&mut p.engine, "written");
        }
        assert_eq!(lp.peers[2].engine.get(&t, &ak).unwrap(), Some(Value::Int(2)), "the reader holds the writer's write");
    }
}
