//! The thing lists each read thing's sync IDs carry (spec/sync-judgement.md §1 List blobs),
//! kept per (read thing, rotation) (`Listed`): `certificate_lists(s, r)` reads one row. A read
//! thing carries the lists of the things of its closure its actor reads as chain certificates
//! place (`Engine::cert_reads_in`: a thing list is a chain certificate) and of the things whose
//! records its certificates name (`Certified::namers`). Which read things carry a thing's lists
//! is followed per thing (`Effects`; candidates from the closure's members, the read things and
//! the records named, each by its feed), so a thing entering a sync unit judges itself alone,
//! never the unit's other members, and the lists held come from `Indexes::lists_on`'s feed: a
//! commit that moves neither re-derives nothing, and a rotation's lists cost the rows of the
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
    /// The closure's members added from the first follow on.
    members: Option<Feed<(crate::sync::units::Ctx, Tid)>>,
    /// The records named from the first follow on (`Certified::namers`).
    named: Option<Feed<Tid>>,
    /// Per thing, the read things carrying its lists.
    carriers: Effects<Tid, Arc<BTreeSet<Tid>>>,
    /// The (thing, rotation) lists held from the first follow on (`Indexes::lists_on`).
    lists: Option<Feed<(Tid, CommitId)>>,
    /// The follow's fixed point (`certified`'s inside it).
    quiet: Quiet,
}

impl Default for Followers {
    fn default() -> Self {
        Followers { read: None, members: None, named: None, carriers: Effects::new("sync: listed carriers"), lists: None, quiet: Quiet::default() }
    }
}

/// Per (read thing, rotation), the things whose list of the rotation the thing's sync IDs carry.
/// Bounded by what is held: a row per read thing and rotation listing a thing it carries.
#[derive(Clone)]
pub(crate) struct Listed {
    followers: Followers,
    /// Per carried thing, the read things carrying it, as placed.
    carriers: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    rows: Stamped<(Tid, CommitId), Arc<BTreeSet<Tid>>>,
    /// Each row as it comes (`Engine::lists_feed`).
    added: Stamps,
    /// Whether a row moved since the running follow began.
    wrote: bool,
}

impl Default for Listed {
    fn default() -> Self {
        Listed { followers: Followers::default(), carriers: BTreeMap::new(), rows: Stamped::default(), added: Stamps::named("sync: list rows"), wrote: false }
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
    /// The read things whose sync IDs carry thing `x`'s lists (spec/sync-judgement.md §1 List
    /// blobs): those whose sync unit holds it and whose actor may read it as it places chain
    /// certificates (`cert_reads_in`, a role at now on the memo clock, so they are the same at
    /// every node), and those whose certificates name its record. Reads per (read thing, `x`).
    fn carriers_of(&mut self, x: &Tid) -> Arc<BTreeSet<Tid>> {
        let read = |e: &Engine, t: &Tid| e.core.certified.read.contains(t);
        let mut out: BTreeSet<Tid> = self.core.certified.namers.get(x).into_iter().flat_map(|n| n.iter()).filter(|t| read(self, t)).copied().collect();
        let mut under = self.units_holding(x);
        under.insert(*x);
        for t in under {
            if read(self, &t) && self.core.ix.closure.unit_holds(&t, x) && self.cert_reads_in(&t, x) {
                out.insert(t);
            }
        }
        Arc::new(out)
    }

    /// The things whose lists read thing `t`'s sync IDs carry, derived whole (`carriers_of` the
    /// other way): its closure's things its actor reads as chain certificates place, and the
    /// things whose records its certificates name; none once `t` is read no more.
    #[cfg(test)]
    fn carried_lists(&mut self, t: &Tid) -> Result<Arc<BTreeSet<Tid>>> {
        let records = self.certified_records(t)?;
        if !self.core.certified.read.contains(t) {
            return Ok(Arc::default());
        }
        let mut out: BTreeSet<Tid> = self.sync_unit(t).iter().filter(|x| self.cert_reads_in(t, x)).copied().collect();
        out.extend(records.iter().copied());
        Ok(Arc::new(out))
    }

    /// The rotations whose held lists name `x` (`Indexes::lists_on`, read whole: only while
    /// placing, never inside a settle).
    fn rotations_listing(&self, x: Tid) -> Vec<CommitId> {
        self.core.ix.lists_on.range(of(x)).map(|(_, r)| *r).collect()
    }

    /// Brings `Certified` and then `Listed` up to date with what moved since the last call: the
    /// things whose carriers moved, and the lists held since. Called by the facade's readers of the
    /// rows and `Engine::follow`; never inside a transaction, by its type: a `Tx` holds the
    /// `Core` alone, and following reads the engine whole. Whether a row of either moved.
    pub(crate) fn follow_lists(&mut self) -> Result<bool> {
        let f = &self.core.listed.followers;
        // `certified`'s follow runs inside: at its fixed point too
        if f.quiet.holds(f.carriers.idle()) && self.certificates_quiet()? {
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
        // the candidates: what is there at the first follow, then as each comes
        let mut came: Vec<Tid> = Vec::new();
        match f.members.as_mut() {
            Some(feed) => came.extend(feed.added().into_iter().map(|(_, x)| x)),
            None => {
                f.members = Some(self.core.ix.closure.member_feed());
                came.extend(self.core.ix.closure.things().copied());
            }
        }
        match f.read.as_mut() {
            Some(feed) => came.extend(feed.added()),
            None => {
                f.read = Some(self.core.certified.read.feed());
                came.extend(self.core.certified.read.iter().copied());
            }
        }
        match f.named.as_mut() {
            Some(feed) => came.extend(feed.added()),
            None => {
                f.named = Some(self.core.certified.namers.feed());
                came.extend(self.core.certified.namers.keys().copied());
            }
        }
        for x in came {
            f.carriers.want(x);
        }
        // followed while it may come to be carried: held in the closure, read or named; once
        // none, again as a feed gives it
        for x in f.carriers.due() {
            let Some((_, now)) = f.carriers.try_settle(&x, || Ok::<_, crate::error::Error>(self.carriers_of(&x)))? else { continue };
            self.place_carriers(x, &now);
            if now.is_empty() && !self.core.ix.closure.holds(&x) && !self.core.certified.read.contains(&x) && self.core.certified.namers.get(&x).is_none() {
                f.carriers.unwant(&x);
            }
        }
        let added = f.lists.as_mut().map(Feed::added).unwrap_or_default();
        for (x, r) in added {
            // one added and undone since is reported too: absent now
            if !self.core.ix.lists_on.contains(&(x, r)) {
                continue;
            }
            let under: Vec<Tid> = self.core.listed.carriers.get(&x).into_iter().flat_map(|c| c.iter()).copied().collect();
            for t in under {
                self.core.listed.set(t, r, x, true);
            }
        }
        Ok(())
    }

    /// Thing `x`'s lists go under the read things of `now`: the rows of those that came or went.
    fn place_carriers(&mut self, x: Tid, now: &Arc<BTreeSet<Tid>>) {
        let was = match now.is_empty() {
            true => self.core.listed.carriers.remove(&x),
            false => self.core.listed.carriers.insert(x, now.clone()),
        }
        .unwrap_or_default();
        let rotations = self.rotations_listing(x);
        for t in now.difference(&was) {
            for r in &rotations {
                self.core.listed.set(*t, *r, x, true);
            }
        }
        for t in was.difference(now) {
            for r in &rotations {
                self.core.listed.set(*t, *r, x, false);
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
