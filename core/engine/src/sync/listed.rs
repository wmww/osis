//! The thing lists each read thing's sync IDs carry (spec/sync-judgement.md §1 List blobs),
//! kept per (read thing, rotation) (`Listed`): `certificate_lists(s, r)` reads one row. A read
//! thing carries the lists of the things of its closure its actor reads as chain certificates
//! place (`Engine::cert_reads_in`: a thing list is a chain certificate) and of the things whose
//! records its certificates name (`Engine::certified_records`); which things it carries is
//! followed per read thing (`Effects`), the read things are `sync::certified`'s (its set's feed,
//! so the sync set is followed once), and the lists held come from `Indexes::lists_on`'s feed, so
//! a commit that moves neither re-derives nothing, and a rotation's lists cost the rows of the
//! things they name.

use crate::Engine;
use crate::error::Result;
use osis_base::memo::{Effects, Feed, Quiet, Stamped, Stamps, Unrecorded};
use osis_base::{CommitId, SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The keys followed, taken out of `Listed` while they settle (their functions read the engine
/// whole).
#[derive(Clone)]
struct Followers {
    /// The read things `sync::certified` adds from the first follow on (`Certified::read`).
    read: Option<Feed<Tid>>,
    /// Per read thing, the things whose lists it carries.
    carried: Effects<Tid, Arc<BTreeSet<Tid>>>,
    /// The (thing, rotation) lists held from the first follow on (`Indexes::lists_on`).
    lists: Option<Feed<(Tid, CommitId)>>,
    /// The follow's fixed point (`certified`'s inside it).
    quiet: Quiet,
}

impl Default for Followers {
    fn default() -> Self {
        Followers { read: None, carried: Effects::new("sync: listed carried"), lists: None, quiet: Quiet::default() }
    }
}

/// Per (read thing, rotation), the things whose list of the rotation the thing's sync IDs carry.
/// Bounded by what is held: a row per read thing and rotation listing a thing it carries.
#[derive(Clone)]
pub(crate) struct Listed {
    followers: Followers,
    /// Each read thing's carried things, as placed.
    carried: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    /// Per carried thing, the read things carrying it.
    carriers: BTreeMap<Tid, BTreeSet<Tid>>,
    rows: Stamped<(Tid, CommitId), Arc<BTreeSet<Tid>>>,
    /// Each row as it comes (`Engine::lists_feed`).
    added: Stamps,
    /// Whether a row moved since the running follow began.
    wrote: bool,
}

impl Default for Listed {
    fn default() -> Self {
        Listed { followers: Followers::default(), carried: BTreeMap::new(), carriers: BTreeMap::new(), rows: Stamped::default(), added: Stamps::named("sync: list rows"), wrote: false }
    }
}

/// The range of `lists_on` or the rows holding `t` first.
fn of(t: Tid) -> std::ops::RangeInclusive<(Tid, CommitId)> {
    (t, CommitId([0; 32]))..=(t, CommitId([0xff; 32]))
}

impl Listed {
    /// `x`'s list of rotation `r` goes under read thing `t` (`add`) or leaves it.
    fn set(&mut self, t: Tid, r: CommitId, x: Tid, add: bool) {
        osis_base::costs::count("sync: list rows touched", 1);
        let k = (t, r);
        let mut row = self.rows.get(&k).cloned().unwrap_or_default();
        let changed = match add {
            true => Arc::make_mut(&mut row).insert(x),
            false => Arc::make_mut(&mut row).remove(&x),
        };
        if !changed {
            return;
        }
        self.wrote = true;
        match (row.is_empty(), add) {
            (true, _) => {
                self.rows.remove(&k);
            }
            (false, true) if row.len() == 1 => {
                self.rows.insert(k, row);
                self.added.wrote_added(&k, true, true);
            }
            (false, _) => {
                self.rows.insert(k, row);
            }
        }
    }
}

impl Engine {
    /// The things whose lists read thing `t`'s sync IDs carry (spec/sync-judgement.md §1 List
    /// blobs): its closure's things whose lists go there (`closure_lists`), and the things whose
    /// records its certificates name; none once `t` is read no more.
    fn carried_lists(&mut self, t: &Tid) -> Result<Arc<BTreeSet<Tid>>> {
        let records = self.certified_records(t)?;
        if !self.core.certified.read.contains(t) {
            return Ok(Arc::default());
        }
        let mut out = self.closure_lists(t);
        out.extend(records.iter().copied());
        Ok(Arc::new(out))
    }

    /// The things of `t`'s closure whose lists its sync IDs carry: those its actor may read as it
    /// places chain certificates (a thing list is one: `cert_reads_in`, a role at now on the memo
    /// clock), so they are the same at every node.
    pub(crate) fn closure_lists(&self, t: &Tid) -> BTreeSet<Tid> {
        self.sync_unit(t).iter().filter(|x| self.cert_reads_in(t, x)).copied().collect()
    }

    /// The rotations whose held lists name `x` (`Indexes::lists_on`, read whole: only while
    /// placing, never inside a settle).
    fn rotations_listing(&self, x: Tid) -> Vec<CommitId> {
        self.core.ix.lists_on.range(of(x)).map(|(_, r)| *r).collect()
    }

    /// Brings `Certified` and then `Listed` up to date with what moved since the last call: the
    /// read things whose carried things moved, and the lists held since. Called by the facade's readers of the
    /// rows and `Engine::follow`; never inside a transaction, by its type: a `Tx` holds the
    /// `Core` alone, and following reads the engine whole. Whether a row of either moved.
    pub(crate) fn follow_lists(&mut self) -> Result<bool> {
        let f = &self.core.listed.followers;
        // `certified`'s follow runs inside: at its fixed point too
        if f.quiet.holds(f.carried.idle()) && self.certificates_quiet() {
            return Ok(false);
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        // the read things, as `certified` follows them
        let moved = self.follow_certificates()?;
        self.core.listed.wrote = false;
        let mut f = std::mem::take(&mut self.core.listed.followers);
        let r = self.follow_lists_with(&mut f);
        f.quiet.ended(from, r.is_ok());
        self.core.listed.followers = f;
        r.map(|()| self.core.listed.wrote | moved)
    }

    fn follow_lists_with(&mut self, f: &mut Followers) -> Result<()> {
        if f.lists.is_none() {
            // the lists held before are found as their things are placed
            f.lists = Some(self.core.ix.lists_on.feed());
        }
        let came: Vec<Tid> = match f.read.as_mut() {
            Some(feed) => feed.added(),
            None => {
                f.read = Some(self.core.certified.read.feed());
                self.core.certified.read.iter().copied().collect()
            }
        };
        for t in came {
            f.carried.want(t);
        }
        // a thing read no more settles to nothing (`carried_lists`) and is followed no more
        for t in f.carried.due() {
            let Some((_, now)) = f.carried.try_settle(&t, || self.carried_lists(&t))? else { continue };
            self.place_lists(t, &now);
            if now.is_empty() && !self.core.certified.read.contains(&t) {
                f.carried.unwant(&t);
            }
        }
        let added = f.lists.as_mut().map(Feed::added).unwrap_or_default();
        for (x, r) in added {
            // one added and undone since is reported too: absent now
            if !self.core.ix.lists_on.contains(&(x, r)) {
                continue;
            }
            let under: Vec<Tid> = self.core.listed.carriers.get(&x).into_iter().flatten().copied().collect();
            for t in under {
                self.core.listed.set(t, r, x, true);
            }
        }
        Ok(())
    }

    /// Read thing `t` carries the lists of `now`: the rows of the things that came or went.
    fn place_lists(&mut self, t: Tid, now: &BTreeSet<Tid>) {
        let was = match now.is_empty() {
            true => self.core.listed.carried.remove(&t),
            false => self.core.listed.carried.insert(t, Arc::new(now.clone())),
        }
        .unwrap_or_default();
        for x in now.difference(&was) {
            self.core.listed.carriers.entry(*x).or_default().insert(t);
            for r in self.rotations_listing(*x) {
                self.core.listed.set(t, r, *x, true);
            }
        }
        for x in was.difference(now) {
            if let Some(c) = self.core.listed.carriers.get_mut(x) {
                c.remove(&t);
                if c.is_empty() {
                    self.core.listed.carriers.remove(x);
                }
            }
            for r in self.rotations_listing(*x) {
                self.core.listed.set(t, r, *x, false);
            }
        }
    }

    /// The things whose held list of rotation `r` sync ID `s` carries (spec/sync-judgement.md §1
    /// List blobs): a read of that row alone.
    pub fn certificate_lists(&mut self, s: &SyncId, r: &CommitId) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_lists()?;
        let mut out = BTreeSet::new();
        for t in self.read_things_of(s)? {
            out.extend(self.core.listed.rows.get(&(t, *r)).into_iter().flat_map(|x| x.iter().copied()));
        }
        Ok(Arc::new(out))
    }

    /// The things whose held list of rotation `r` read thing `t`'s sync IDs carry.
    pub(crate) fn thing_lists(&mut self, t: &Tid, r: &CommitId) -> Arc<BTreeSet<Tid>> {
        self.core.listed.rows.get(&(*t, *r)).cloned().unwrap_or_default()
    }

    /// The rotations with a list `s` carries (read whole: where a reader starts following `s`).
    pub fn list_rotations(&mut self, s: &SyncId) -> Result<Vec<CommitId>> {
        self.follow_lists()?;
        let mut out = BTreeSet::new();
        for t in self.read_things_of(s)? {
            out.extend(self.core.listed.rows.range(of(t)).map(|((_, r), _)| *r));
        }
        Ok(out.into_iter().collect())
    }

    /// A cursor over the (read thing, rotation) rows that come from now on (`memo::Feed`): a new
    /// rotation listing a carried thing, or a thing carried anew.
    pub fn lists_feed(&self) -> Feed<(Tid, CommitId)> {
        self.core.listed.added.feed()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    
    
    use crate::Engine;
    use osis_base::{CommitId, SyncId, Tid};
    use std::collections::{BTreeMap, BTreeSet};
    

    type Rows = BTreeMap<(SyncId, CommitId), BTreeSet<Tid>>;

    /// The rows `e` keeps equal those derived whole (`sync::certified`'s random histories call
    /// this after each step).
    pub(crate) fn check(e: &mut Engine, step: &str) {
        let (kept, whole) = rows_of(e);
        assert_eq!(kept, whole, "{step}: list rows");
    }

    fn rows_of(e: &mut Engine) -> (Rows, Rows) {
        let ids: Vec<SyncId> = e.sync_set().unwrap().ids.keys().copied().collect();
        let (mut kept, mut whole) = (BTreeMap::new(), BTreeMap::new());
        for s in ids {
            for r in e.list_rotations(&s).unwrap() {
                kept.insert((s, r), (*e.certificate_lists(&s, &r).unwrap()).clone());
            }
            for t in e.read_things_of(&s).unwrap() {
                for x in e.carried_lists(&t).unwrap().iter() {
                    for r in e.rotations_listing(*x) {
                        whole.entry((s, r)).or_insert_with(BTreeSet::new).insert(*x);
                    }
                }
            }
        }
        (kept, whole)
    }

}
