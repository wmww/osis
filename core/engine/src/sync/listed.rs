//! The thing lists each read thing's sync IDs carry (spec/sync-judgement.md §1 List blobs),
//! kept per (read thing, rotation) (`Listed`): `certificate_lists(s, r)` reads one row. A read
//! thing carries the lists of the things of its closure its actor reads and of the things whose
//! records its certificates name (`Engine::certified_records`); which things it carries is
//! followed per read thing (`Effects`), the read things are `sync::certified`'s (its set's feed,
//! so the sync set is followed once), and the lists held come from `Indexes::lists_on`'s feed, so
//! a commit that moves neither re-derives nothing, and a rotation's lists cost the rows of the
//! things they name.

use crate::Engine;
use crate::error::Result;
use osis_base::memo::{Effects, Feed, Stamped, Stamps, Unrecorded};
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
}

impl Default for Followers {
    fn default() -> Self {
        Followers { read: None, carried: Effects::new("sync: listed carried"), lists: None }
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
    /// blobs): its closure's things its actor may read (`reads_in`, a role at now on the memo
    /// clock), and the things whose records its certificates name; none once `t` is read no more.
    fn carried_lists(&mut self, t: &Tid) -> Result<Arc<BTreeSet<Tid>>> {
        let records = self.certified_records(t)?;
        if !self.core.certified.read.contains(t) {
            return Ok(Arc::default());
        }
        let closure = self.core.ix.groups.closure_of(t);
        let mut out: BTreeSet<Tid> = closure.iter().filter(|x| self.reads_in(t, x)).copied().collect();
        out.extend(records.iter().copied());
        Ok(Arc::new(out))
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
        let _u = Unrecorded::start();
        // the read things, as `certified` follows them
        let moved = self.follow_certificates()?;
        self.core.listed.wrote = false;
        let mut f = std::mem::take(&mut self.core.listed.followers);
        let r = self.follow_lists_with(&mut f);
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
    pub(crate) fn certificate_lists_now(&mut self, s: &SyncId, r: &CommitId) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_lists()?;
        let Some(t) = self.read_thing(s)? else { return Ok(Arc::default()) };
        Ok(self.core.listed.rows.get(&(t, *r)).cloned().unwrap_or_default())
    }

    /// The rotations with a list `s` carries (read whole: where a reader starts following `s`).
    pub(crate) fn list_rotations_now(&mut self, s: &SyncId) -> Result<Vec<CommitId>> {
        self.follow_lists()?;
        let Some(t) = self.read_thing(s)? else { return Ok(Vec::new()) };
        Ok(self.core.listed.rows.range(of(t)).map(|((_, r), _)| *r).collect())
    }

    /// A cursor over the (read thing, rotation) rows that come from now on (`memo::Feed`): a new
    /// rotation listing a carried thing, or a thing carried anew.
    pub(crate) fn lists_feed_now(&self) -> Feed<(Tid, CommitId)> {
        self.core.listed.added.feed()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::flows::Done;
    use crate::local_peer::LocalPeer;
    use crate::{Engine, Mutation};
    use osis_base::{Ak, CommitId, SyncId, Tid, Value, WallMs};
    use std::collections::{BTreeMap, BTreeSet};
    use osis_schema::core_types as ct;

    /// One node of account P whose synced group `g` it wrote at each of `n` epochs, rotating
    /// after each: each rotation lists `g`, a thing the home sync ID carries.
    fn rotated(n: usize) -> (LocalPeer, osis_base::Tid, osis_base::Tid) {
        let mut lp = LocalPeer::new_bare(1, 0, WallMs(1_700_000_000_000)).unwrap();
        let (a, _) = lp.peers[0].engine.create_account().unwrap();
        let me = lp.peers[0].engine.tid();
        let g = *lp.peers[0].engine.get_typed(&a.devices, &ct::SYNCED).unwrap().unwrap().get(&me).unwrap();
        for i in 0..n {
            let c = write(&mut lp, g, i);
            rotate(&mut lp, a.account, c);
        }
        (lp, a.account, g)
    }

    fn write(lp: &mut LocalPeer, g: osis_base::Tid, i: usize) -> CommitId {
        let mut m = Mutation::new();
        m.set(g, &Ak::new("x:a.0").unwrap(), &Value::Str(format!("v{i}"))).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap()
    }

    /// A rotation of P listing `c` (and what else it names).
    fn rotate(lp: &mut LocalPeer, p: osis_base::Tid, c: CommitId) -> CommitId {
        lp.peers[0].engine.run(|tx| crate::flows::signing::rotate_in(tx, p, &[c], &mut Done::default())).unwrap().unwrap()
    }

    type Rows = BTreeMap<(SyncId, CommitId), BTreeSet<Tid>>;

    /// Per (sync ID, rotation), the things whose list S carries: as the rows hold them, and
    /// derived whole (every carried thing's lists).
    fn rows(lp: &mut LocalPeer) -> (Rows, Rows) {
        rows_of(&mut lp.peers[0].engine)
    }

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
            for r in e.list_rotations_now(&s).unwrap() {
                kept.insert((s, r), (*e.certificate_lists_now(&s, &r).unwrap()).clone());
            }
            let Some(t) = e.read_thing(&s).unwrap() else { continue };
            for x in e.carried_lists(&t).unwrap().iter() {
                for r in e.rotations_listing(*x) {
                    whole.entry((s, r)).or_insert_with(BTreeSet::new).insert(*x);
                }
            }
        }
        (kept, whole)
    }

    /// The list rows touched and the read things' carried things settled by `change`, followed.
    fn touched(lp: &mut LocalPeer, change: impl FnOnce(&mut LocalPeer)) -> (u64, u64) {
        lp.peers[0].engine.follow_lists().unwrap();
        change(lp);
        osis_base::costs::take();
        lp.peers[0].engine.follow_lists().unwrap();
        let taken = osis_base::costs::take();
        let n = |name: &str| taken.iter().filter(|x| x.0 == name).map(|x| x.2).sum::<u64>();
        (n("sync: list rows touched"), n("sync: listed carried"))
    }

    // spec/sync-judgement.md §1 (List blobs: under a sync ID, the thing lists of things in its
    // closure or whose records its certificates name), spec/sync.md §2 (work in proportion to
    // change): after n and 10n rotations whose lists the home sync ID carries, a plain commit
    // touches no list row and a rotation touches the rows of the carried things it lists; the
    // rows equal the whole derivation.
    #[test]
    fn a_rotation_touches_the_lists_it_names_spec_sync_judgement_1() {
        let counts = |n: usize| {
            let (mut lp, p, g) = rotated(n);
            let (kept, whole) = rows(&mut lp);
            assert_eq!(kept, whole);
            assert!(kept.len() >= n, "a row per rotation: {}", kept.len());
            let plain = touched(&mut lp, |lp| {
                write(lp, g, 1000);
            });
            let rotation = touched(&mut lp, |lp| {
                let c = write(lp, g, 1001);
                rotate(lp, p, c);
            });
            let (kept, whole) = rows(&mut lp);
            assert_eq!(kept, whole);
            (plain, rotation)
        };
        let (a, b) = (counts(3), counts(30));
        assert_eq!(a, b, "work grows with the rotations held");
        assert_eq!(a.0, (0, 0), "a plain commit touches no row, settles no carried things");
        assert_eq!(a.1.0, 1, "the rotation's own row");
    }

    /// Files `x` in group `g`'s items (`add`) or takes it out.
    fn file(lp: &mut LocalPeer, g: Tid, x: Tid, add: bool) {
        let v = osis_base::Value::Tid(x);
        let op = if add { osis_crdt::Op::Add(v) } else { osis_crdt::Op::Remove(v) };
        let mut m = Mutation::new();
        m.op(g, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(crate::engine::groups::ITEMS)], op }).unwrap();
        lp.peers[0].commit(m).unwrap().unwrap();
    }

    /// Whether some row holds `x`.
    fn listed(lp: &mut LocalPeer, x: Tid) -> bool {
        let (kept, whole) = rows(lp);
        assert_eq!(kept, whole);
        kept.values().any(|row| row.contains(&x))
    }

    // spec/sync-judgement.md §1 (List blobs: the thing lists of things in the sync ID's closure):
    // a thing filed in D (the one read thing), written and listed by a rotation, has its list
    // carried; taken out of D, its list leaves every row, and filed again it comes back.
    #[test]
    fn a_thing_leaving_the_closure_leaves_its_rows_spec_sync_judgement_1() {
        let (mut lp, p, _) = rotated(1);
        let read = lp.peers[0].engine.read_things().unwrap();
        assert_eq!(read.len(), 1);
        let g = *read.first().unwrap();
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, p);
        m.set(x, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        file(&mut lp, g, x, true);
        rotate(&mut lp, p, c);
        assert!(listed(&mut lp, x), "x's list carried");
        file(&mut lp, g, x, false);
        assert!(!listed(&mut lp, x), "x's list left");
        file(&mut lp, g, x, true);
        assert!(listed(&mut lp, x), "x's list carried again");
    }

    // spec/sync-judgement.md §1 (List blobs: the thing lists of closure things S's actor may
    // read), spec/requirements.md Confidentiality between readers (a reader learns only what it may read): G, a group
    // with secrets of its own filed in D, holds X, which G's actor does not read; a rotation
    // listing a write on X never puts X's list under G's sync IDs (its readers would learn which
    // commits the account made on X). Fails with the reads condition dropped.
    #[test]
    fn a_closure_thing_its_actor_does_not_read_has_no_list_carried_spec_sync_judgement_1() {
        let (mut lp, p, d) = rotated(0);
        let ak = Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, p);
        m.set(x, &ak, &Value::Int(1)).unwrap();
        let c = lp.peers[0].commit(m).unwrap().unwrap();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, p);
        m.set(g, &ct::GROUP, &ct::Group { items: [x].into(), ..Default::default() }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        file(&mut lp, d, g, true);
        let e = &mut lp.peers[0].engine;
        assert!(e.read_things().unwrap().contains(&g), "G is read here");
        assert!(!e.reads_in(&g, &x), "G's actor does not read X");
        rotate(&mut lp, p, c);
        let (kept, whole) = rows(&mut lp);
        assert_eq!(kept, whole);
        let e = &mut lp.peers[0].engine;
        let under = |e: &mut Engine, t: Tid| kept.iter().filter(|((s, _), _)| e.read_thing(s).unwrap() == Some(t)).any(|(_, row)| row.contains(&x));
        assert!(!under(e, g), "X's list never under G's: {kept:?}");
    }

    // spec/permissions.md §4 (Suspect list: things in L's closure L's actor may read): G, with
    // secrets of its own, holds X, which G's actor does not read; G's sync ID carries X yet names
    // none of X's aspects in a suspect list, nor is asked to repair one. Fails with the reads
    // condition dropped from `suspect_under`.
    #[test]
    fn a_closure_thing_its_actor_does_not_read_is_in_no_suspect_list_spec_permissions_4() {
        let (mut lp, p, d) = rotated(0);
        let mut m = Mutation::new();
        let x = lp.peers[0].engine.new_thing(&mut m, p);
        m.set(x, &Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let mut m = Mutation::new();
        let g = lp.peers[0].engine.new_thing(&mut m, p);
        m.set(g, &ct::GROUP, &ct::Group { items: [x].into(), ..Default::default() }).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.give_own_secrets(&g).unwrap();
        file(&mut lp, d, g, true);
        let e = &mut lp.peers[0].engine;
        let s = *e.sync_ids(&g).unwrap().first().map(|o| &o.id).unwrap();
        assert!(e.carrying(&x).unwrap().contains(&s), "G's sync ID carries X");
        assert!(e.suspect_under(&s, &g).unwrap(), "G itself is named under its own sync ID");
        assert!(!e.suspect_under(&s, &x).unwrap(), "X is not");
        assert!(!e.may_repair(&s, &x, &Ak::new("x:a.0").unwrap()).unwrap(), "nor repaired for its readers");
    }
}
