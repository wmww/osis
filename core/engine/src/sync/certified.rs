//! The certificates of the things this node reads (`Engine::sync_certificates`), kept per piece
//! and indexed per commit (`Certified`): `sync_bodies` reads one commit's row, the record module
//! one thing's records. A thing's certificates are the union of pieces (`Piece`), each one
//! derivation read by what it is made of, shared by every read thing it goes under: a change
//! re-derives the pieces whose reads it moved and rewrites the rows of the commits whose naming
//! changed, so an account named on n things pays for the copy that changed, not for n.
//!
//! Which pieces go under which read thing is followed the same way, per key: the read things
//! (from the sync set), each one's inbox actors, and each thing with authors (its authors and the
//! read things whose closure holds it). New keys come from feeds (`Indexes::authors_on` gaining a
//! thing, `Held` naming a holder on a thing), never from a walk of everything; a key whose input
//! went away settles to nothing and is dropped.

use super::ThingSync;
use crate::Engine;
use crate::error::Result;
use crate::labeling::{Certs, Parts};
use osis_base::memo::{Effects, Feed, Stamped, StampedSet, Unrecorded};
use osis_base::{CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What one thing's certificates name of a commit: parts to carry, and whether its header goes
/// alone (a minting or request, `Certs::headers`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Named {
    pub parts: Parts,
    pub header: bool,
}

impl Named {
    fn of(certs: &Certs, c: &CommitId) -> Option<Named> {
        let parts = certs.commits.get(c).cloned().unwrap_or_default();
        let header = certs.headers.contains(c);
        (header || !parts.is_empty()).then_some(Named { parts, header })
    }
}

/// One derivation of certificates, going under each read thing it is placed under
/// (`Engine::sync_certificates`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Piece {
    /// A read thing's own (`Engine::own_piece`), under it alone.
    Own(Tid),
    /// Author `a`'s chain to `x` (`Engine::chain_piece`), under each read thing whose closure
    /// holds `x` and whose actor reads it.
    Chain(Tid, Tid),
    /// Actor `a`'s grant copy for `x` (`Engine::grant_copy`), under each read thing owning `a`'s
    /// inbox.
    Grant(Tid, Tid),
}

/// What a thing with authors gives (`Followers::authored`): its authors that are no node, and the
/// read things whose closure holds it and whose actor reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Authored {
    authors: BTreeSet<Tid>,
    under: BTreeSet<Tid>,
}

/// The keys followed, taken out of `Certified` while they settle (their functions read the
/// engine whole).
#[derive(Clone)]
struct Followers {
    /// The things read here (a read sync ID of the sync set).
    read: Effects<(), Arc<BTreeSet<Tid>>>,
    /// Per read thing, the actors whose inbox it owns.
    inboxes: Effects<Tid, Arc<BTreeSet<Tid>>>,
    /// Per thing with authors (`Indexes::authors_on`), what it gives.
    authored: Effects<Tid, Arc<Authored>>,
    /// Per piece placed somewhere, its certificates; `None` for a grant copy of a pair no longer
    /// named (the piece goes).
    pieces: Effects<Piece, Option<Arc<Certs>>>,
    /// New things with authors, new (holder, thing) pairs; `None` until the first follow.
    feeds: Option<Feeds>,
}

/// `Followers::feeds`.
type Feeds = (Feed<Tid>, Feed<(Tid, Tid)>);

impl Default for Followers {
    fn default() -> Self {
        Followers { read: Effects::new("sync: certified things"), inboxes: Effects::new("sync: certified inboxes"), authored: Effects::new("sync: certified authored"), pieces: Effects::new("sync: certified pieces"), feeds: None }
    }
}

/// A piece where it is placed: the read things it goes under, and its certificates as indexed.
#[derive(Clone, Default)]
struct Placed {
    under: BTreeSet<Tid>,
    certs: Arc<Certs>,
}

/// An inbox actor of some read thing: the read things owning its inbox, and the things it is
/// named on (each a `Piece::Grant`).
#[derive(Clone, Default)]
struct Inbox {
    owners: BTreeSet<Tid>,
    on: BTreeSet<Tid>,
}

/// The certificates of the things this node reads, per piece, and indexed by commit and by read
/// thing. Every map is bounded by what is held: a piece per read thing, per (author, thing written
/// on) under a read closure and per (inbox actor, thing named on); the rows by the commits and
/// records those name.
#[derive(Clone, Default)]
pub(crate) struct Certified {
    followers: Followers,
    /// The read things, per key (what `Authored` reads).
    read: StampedSet<Tid>,
    /// Each read thing's inbox actors, as placed.
    inboxes_of: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    inboxes: BTreeMap<Tid, Inbox>,
    /// Each followed thing with authors, as placed.
    authored: BTreeMap<Tid, Arc<Authored>>,
    placed: BTreeMap<Piece, Placed>,
    /// Per (commit, read thing), what each piece under the thing names of the commit.
    named: BTreeMap<(CommitId, Tid), BTreeMap<Piece, Named>>,
    /// Per read thing, each record its pieces name, with how many name it.
    record_counts: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Per (commit, read thing) whose certificates name it, what they name (the union of the
    /// thing's pieces'), read per pair.
    of: Stamped<(CommitId, Tid), Named>,
    /// Per commit, the read things whose certificates name it (moved as one comes or goes).
    naming: Stamped<CommitId, Arc<BTreeSet<Tid>>>,
    /// Per read thing, the records its certificates name.
    records: Stamped<Tid, Arc<BTreeSet<Tid>>>,
    /// Whether a row of `of` or `records` was written since the running follow began.
    wrote: bool,
}

impl Certified {
    /// Places piece `p` under `t`: whether it is newly followed.
    fn place(&mut self, p: Piece, t: Tid) -> bool {
        let fresh = !self.placed.contains_key(&p);
        let placed = self.placed.entry(p).or_default();
        if placed.under.insert(t) {
            let certs = placed.certs.clone();
            self.apply(t, p, &Certs::default(), &certs);
        }
        fresh
    }

    /// Takes piece `p` from under `t`: whether it is placed nowhere now (to unfollow).
    fn unplace(&mut self, p: Piece, t: Tid) -> bool {
        let Some(placed) = self.placed.get_mut(&p) else { return false };
        if placed.under.remove(&t) {
            let certs = placed.certs.clone();
            self.apply(t, p, &certs, &Certs::default());
        }
        let gone = self.placed.get(&p).is_some_and(|x| x.under.is_empty());
        if gone {
            self.placed.remove(&p);
        }
        gone
    }

    /// Piece `p`'s certificates are `now`.
    fn reset(&mut self, p: Piece, now: Arc<Certs>) {
        let Some(placed) = self.placed.get_mut(&p) else { return };
        let was = std::mem::replace(&mut placed.certs, now.clone());
        let under: Vec<Tid> = placed.under.iter().copied().collect();
        for t in under {
            self.apply(t, p, &was, &now);
        }
    }

    /// Piece `p` under `t` moved from `was` to `now`: the rows of the commits and the records
    /// either names.
    fn apply(&mut self, t: Tid, p: Piece, was: &Certs, now: &Certs) {
        let commits: BTreeSet<&CommitId> = was.commits.keys().chain(&was.headers).chain(now.commits.keys()).chain(&now.headers).collect();
        for c in commits {
            let n = Named::of(now, c);
            if Named::of(was, c) == n {
                continue;
            }
            let k = (*c, t);
            let by = self.named.entry(k).or_default();
            match n {
                Some(n) => by.insert(p, n),
                None => by.remove(&p),
            };
            let union = (!by.is_empty()).then(|| {
                by.values().fold(Named::default(), |mut u, n| {
                    u.parts.extend(n.parts.iter().copied());
                    u.header |= n.header;
                    u
                })
            });
            if by.is_empty() {
                self.named.remove(&k);
            }
            let was = self.of.get(&k).cloned();
            if was == union {
                continue;
            }
            self.wrote = true;
            if was.is_some() != union.is_some() {
                let mut naming = self.naming.remove(c).unwrap_or_default();
                let set = Arc::make_mut(&mut naming);
                match union.is_some() {
                    true => set.insert(t),
                    false => set.remove(&t),
                };
                if !set.is_empty() {
                    self.naming.insert(*c, naming);
                }
            }
            match union {
                Some(u) => self.of.insert(k, u),
                None => self.of.remove(&k),
            };
        }
        if was.records == now.records {
            return;
        }
        let counts = self.record_counts.entry(t).or_default();
        let mut moved = false;
        for r in was.records.difference(&now.records) {
            if let Some(n) = counts.get_mut(r) {
                *n -= 1;
                if *n == 0 {
                    counts.remove(r);
                    moved = true;
                }
            }
        }
        for r in now.records.difference(&was.records) {
            let n = counts.entry(*r).or_default();
            *n += 1;
            moved |= *n == 1;
        }
        if !moved {
            return;
        }
        self.wrote = true;
        if counts.is_empty() {
            self.record_counts.remove(&t);
            self.records.remove(&t);
        } else {
            let set: BTreeSet<Tid> = counts.keys().copied().collect();
            self.records.insert(t, Arc::new(set));
        }
    }
}

impl Engine {
    /// The things whose certificates `Certified` keeps: those holding a read sync ID.
    fn read_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        let set = self.sync_set()?;
        Ok(Arc::new(set.ids.values().filter(|(_, h)| *h == super::Holding::Read).map(|(t, _)| *t).collect()))
    }

    /// What thing `x` gives the read things (`Authored`): its authors that are no node, and the
    /// read things whose closure holds it (`Groups::enclosing`) and whose actor reads it, each
    /// read per key.
    fn authored(&mut self, x: &Tid) -> Arc<Authored> {
        let authors: Vec<Tid> = self.core.ix.authors_on.get(x).into_iter().flatten().copied().collect();
        let authors: BTreeSet<Tid> = authors.into_iter().filter(|a| !self.is_node(a).unwrap_or(false)).collect();
        if authors.is_empty() {
            return Arc::default();
        }
        let under = self.core.ix.groups.enclosing(x).into_iter().filter(|t| self.core.certified.read.contains(t) && self.reads_in(t, x)).collect();
        Arc::new(Authored { authors, under })
    }

    /// Piece `p`'s certificates; `None` for a grant copy whose actor is no longer named on the
    /// thing (`Held::is_named`, read per pair so the piece goes when the pair does).
    fn piece(&mut self, p: &Piece) -> Option<Arc<Certs>> {
        Some(Arc::new(match p {
            Piece::Own(t) => self.own_piece(t),
            Piece::Chain(a, x) => self.chain_piece(a, x),
            Piece::Grant(a, x) if !self.core.ix.held.is_named(a, x) => return None,
            Piece::Grant(a, x) => self.grant_copy(a, x),
        }))
    }

    /// Brings `Certified` up to date with what moved since the last call: work in proportion to
    /// the keys whose reads moved and the pieces they place. Read by no caller: what a caller
    /// reads is the rows (`certified`, `certified_records`). Whether a row moved.
    pub(crate) fn follow_certificates(&mut self) -> Result<bool> {
        let _u = Unrecorded::start();
        let mut f = std::mem::take(&mut self.core.certified.followers);
        let r = self.follow_with(&mut f);
        self.core.certified.followers = f;
        r
    }

    fn follow_with(&mut self, f: &mut Followers) -> Result<bool> {
        self.core.certified.wrote = false;
        // the entries the inbox keys read, before they are asked whether they are due
        self.refresh_inboxes();
        if f.feeds.is_none() {
            f.feeds = Some((self.core.ix.authors_on.feed(), self.core.ix.held.pairs_feed()));
            let all: Vec<Tid> = self.core.ix.authors_on.keys().copied().collect();
            for x in all {
                f.authored.want(x);
            }
        }
        if !f.read.wants(&()) {
            f.read.want(());
        }
        // the read things: each its own piece and inbox actors
        for k in f.read.due() {
            let Some((was, now)) = f.read.try_settle(&k, || self.read_things())? else { continue };
            let was = was.unwrap_or_default();
            for t in now.difference(&was) {
                self.core.certified.read.insert(*t);
                if self.core.certified.place(Piece::Own(*t), *t) {
                    f.pieces.want(Piece::Own(*t));
                }
                f.inboxes.want(*t);
            }
            for t in was.difference(&now) {
                self.core.certified.read.remove(t);
                if self.core.certified.unplace(Piece::Own(*t), *t) {
                    f.pieces.unwant(&Piece::Own(*t));
                }
                f.inboxes.unwant(t);
                let had = self.core.certified.inboxes_of.remove(t).unwrap_or_default();
                self.set_inboxes(f, t, &had, &BTreeSet::new());
            }
        }
        let (authors, pairs) = f.feeds.as_mut().map(|(a, p)| (a.added(), p.added())).unwrap_or_default();
        for x in authors {
            f.authored.want(x);
        }
        for (a, x) in pairs {
            if x != a && self.core.certified.inboxes.contains_key(&a) {
                self.add_grant(f, a, x);
            }
        }
        for t in f.inboxes.due() {
            let Some((_, now)) = f.inboxes.settle(&t, || Arc::new(self.inbox_actors_of(&t).into_iter().collect())) else { continue };
            let had = self.core.certified.inboxes_of.insert(t, now.clone()).unwrap_or_default();
            self.set_inboxes(f, &t, &had, &now);
        }
        for x in f.authored.due() {
            let Some((_, now)) = f.authored.settle(&x, || self.authored(&x)) else { continue };
            let had = match now.authors.is_empty() {
                true => {
                    // followed while it has any author (one that is no node may come); with none,
                    // again once one comes (the feed)
                    if self.core.ix.authors_on.get(&x).is_none() {
                        f.authored.unwant(&x);
                    }
                    self.core.certified.authored.remove(&x)
                }
                false => self.core.certified.authored.insert(x, now.clone()),
            }
            .unwrap_or_default();
            let pairs = |a: &Authored| -> BTreeSet<(Tid, Tid)> { a.authors.iter().flat_map(|au| a.under.iter().map(move |t| (*au, *t))).collect() };
            let (old, new) = (pairs(&had), pairs(&now));
            for (a, t) in old.difference(&new) {
                if self.core.certified.unplace(Piece::Chain(*a, x), *t) {
                    f.pieces.unwant(&Piece::Chain(*a, x));
                }
            }
            for (a, t) in new.difference(&old) {
                if self.core.certified.place(Piece::Chain(*a, x), *t) {
                    f.pieces.want(Piece::Chain(*a, x));
                }
            }
        }
        for p in f.pieces.due() {
            osis_base::costs::count("sync: certificate pieces derived", 1);
            let Some((_, now)) = f.pieces.settle(&p, || self.piece(&p)) else { continue };
            match (p, now) {
                (_, Some(now)) => self.core.certified.reset(p, now),
                // a grant copy of a pair no longer named: gone until the feed names it again
                (Piece::Grant(a, x), None) => self.drop_grant(f, a, x),
                (_, None) => {}
            }
        }
        Ok(self.core.certified.wrote)
    }

    /// Read thing `t`'s inbox actors moved from `had` to `now`: the grant pieces of each go under
    /// it or leave.
    fn set_inboxes(&mut self, f: &mut Followers, t: &Tid, had: &BTreeSet<Tid>, now: &BTreeSet<Tid>) {
        for a in had.difference(now) {
            let Some(ib) = self.core.certified.inboxes.get_mut(a) else { continue };
            ib.owners.remove(t);
            let on: Vec<Tid> = ib.on.iter().copied().collect();
            if ib.owners.is_empty() {
                self.core.certified.inboxes.remove(a);
            }
            for x in on {
                if self.core.certified.unplace(Piece::Grant(*a, x), *t) {
                    f.pieces.unwant(&Piece::Grant(*a, x));
                }
            }
        }
        for a in now.difference(had) {
            if !self.core.certified.inboxes.contains_key(a) {
                // the things it is named on, once: later ones come from the feed
                let on: BTreeSet<Tid> = self.core.ix.held.named_on(a).filter(|x| *x != a).copied().collect();
                self.core.certified.inboxes.insert(*a, Inbox { owners: BTreeSet::new(), on });
            }
            let Some(ib) = self.core.certified.inboxes.get_mut(a) else { continue };
            ib.owners.insert(*t);
            let on: Vec<Tid> = ib.on.iter().copied().collect();
            for x in on {
                if self.core.certified.place(Piece::Grant(*a, x), *t) {
                    f.pieces.want(Piece::Grant(*a, x));
                }
            }
        }
    }

    /// Inbox actor `a` is named on `x`: its grant copy goes under each owner of its inbox.
    fn add_grant(&mut self, f: &mut Followers, a: Tid, x: Tid) {
        let Some(ib) = self.core.certified.inboxes.get_mut(&a) else { return };
        ib.on.insert(x);
        let owners: Vec<Tid> = ib.owners.iter().copied().collect();
        for t in owners {
            if self.core.certified.place(Piece::Grant(a, x), t) {
                f.pieces.want(Piece::Grant(a, x));
            }
        }
    }

    fn drop_grant(&mut self, f: &mut Followers, a: Tid, x: Tid) {
        let owners: Vec<Tid> = self.core.certified.inboxes.get_mut(&a).map(|ib| {
            ib.on.remove(&x);
            ib.owners.iter().copied().collect()
        }).unwrap_or_default();
        self.core.certified.reset(Piece::Grant(a, x), Arc::default());
        for t in owners {
            self.core.certified.unplace(Piece::Grant(a, x), t);
        }
        f.pieces.unwant(&Piece::Grant(a, x));
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
    /// alone.
    pub(crate) fn certified_records(&mut self, t: &Tid) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_certificates()?;
        Ok(self.core.certified.records.get(t).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Mutation;
    use crate::flows::Demotion;
    use crate::local_peer::LocalPeer;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    /// Every read thing's rows and records, as `follow` keeps them, equal its certificates derived
    /// whole (`sync_certificates`), and no other thing has a row.
    fn check(e: &mut Engine, step: &str) {
        e.follow_certificates().unwrap();
        let things = e.read_things().unwrap();
        let mut rows: BTreeMap<Tid, Certs> = BTreeMap::new();
        for ((c, t), n) in e.core.certified.of.iter() {
            let got = rows.entry(*t).or_default();
            if !n.parts.is_empty() {
                got.commits.insert(*c, n.parts.clone());
            }
            if n.header {
                got.headers.insert(*c);
            }
        }
        for (t, r) in e.core.certified.records.iter() {
            rows.entry(*t).or_default().records = (**r).clone();
        }
        assert!(rows.keys().all(|t| things.contains(t)), "{step}: a row of a thing not read");
        for t in things.iter() {
            let want = e.sync_certificates(t);
            let got = rows.remove(t).unwrap_or_default();
            assert_eq!(got, want, "{step}: certificates of {t:?}");
        }
    }

    // spec/permissions.md §4, spec/sync-inbox.md §5, spec/sync-judgement.md §2 (required set:
    // certificates): through grants, a group filing, secrets of a thing's own, a lowering, a
    // removal and syncing both ways, each read thing's certificates kept per piece are those
    // derived whole.
    #[test]
    fn pieces_keep_what_the_whole_derivation_gives_spec_permissions_4() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        let a0 = lp.peers[0].engine.create_account().unwrap().0;
        let a1 = lp.peers[1].engine.create_account().unwrap().0;
        lp.sync_all().unwrap();
        let ak = Ak::new("x:a.0").unwrap();
        let mut things = Vec::new();
        for i in 0..3 {
            let e = &mut lp.peers[0].engine;
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0.account);
            m.set(t, &ak, &Value::Int(i)).unwrap();
            e.commit(m).unwrap();
            things.push(t);
        }
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        // a link's K, written first by the sharer node and then by L (an author that is no node)
        let link: std::cell::RefCell<Option<osis_label::ShareLink>> = Default::default();
        let k = || link.borrow().as_ref().unwrap().k;
        type Step<'a> = (&'a str, Box<dyn Fn(&mut LocalPeer) + 'a>);
        let steps: Vec<Step> = vec![
            ("grant read", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&things[0], &a1.account, &edge(Role::Read)).unwrap()))),
            ("own secrets", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.give_own_secrets(&things[1]).unwrap()))),
            ("grant write", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&things[1], &a1.account, &edge(Role::Write)).unwrap()))),
            ("link made", Box::new(|lp: &mut LocalPeer| {
                let spec = crate::flows::LinkSpec { target: things[2], role: Role::Read, until: None, hosts: Vec::new(), peers: Vec::new(), single_use: false };
                *link.borrow_mut() = Some(lp.peers[0].engine.create_link(&a0.account, &spec).unwrap().0);
                lp.sync_all().unwrap();
            })),
            ("link redeemed", Box::new(|lp: &mut LocalPeer| {
                let l = link.borrow().clone().unwrap();
                lp.peers[1].engine.redeem(&l, &a1.account, false).unwrap();
                lp.sync_all().unwrap();
            })),
            ("filed in a group", Box::new(|lp: &mut LocalPeer| {
                let e = &mut lp.peers[0].engine;
                let mut m = Mutation::new();
                m.set(things[1], &ct::GROUP, &ct::Group { items: [things[2], k()].into(), ..Default::default() }).unwrap();
                e.commit(m).unwrap();
            })),
            ("synced", Box::new(|lp: &mut LocalPeer| lp.sync_all().unwrap())),
            ("written by the grantee", Box::new(|lp: &mut LocalPeer| {
                let mut m = Mutation::new();
                m.set(things[1], &ak, &Value::Int(9)).unwrap();
                lp.peers[1].commit(m).unwrap();
                lp.sync_all().unwrap();
            })),
            ("unfiled", Box::new(|lp: &mut LocalPeer| {
                let e = &mut lp.peers[0].engine;
                let mut m = Mutation::new();
                m.set(things[1], &ct::GROUP, &ct::Group::default()).unwrap();
                e.commit(m).unwrap();
            })),
            ("link's K taken out of D", Box::new(|lp: &mut LocalPeer| {
                let e = &mut lp.peers[0].engine;
                let mut m = Mutation::new();
                m.op(a0.devices, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(crate::engine::groups::ITEMS)], op: osis_crdt::Op::Remove(Value::Tid(k())) }).unwrap();
                e.commit(m).unwrap();
            })),
            ("lowered", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.demote(&things[0], &Demotion { holder: a1.account, new: Some(edge(Role::Sync)), retain: None }).unwrap()))),
            ("removed", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.demote(&things[1], &Demotion { holder: a1.account, new: None, retain: None }).unwrap()))),
            ("synced again", Box::new(|lp: &mut LocalPeer| lp.sync_all().unwrap())),
        ];
        check(&mut lp.peers[0].engine, "start");
        check(&mut lp.peers[1].engine, "start");
        // the authors' chains to K (L's among them) come under D and K, and leave D with K
        let chains = |e: &Engine| -> BTreeSet<(Piece, Tid)> { e.core.certified.placed.iter().filter(|(p, _)| matches!(p, Piece::Chain(..))).flat_map(|(p, x)| x.under.iter().map(|t| (*p, *t))).collect() };
        let (mut came, mut went) = (false, false);
        for (name, f) in &steps {
            let was = chains(&lp.peers[0].engine);
            f(&mut lp);
            check(&mut lp.peers[0].engine, name);
            check(&mut lp.peers[1].engine, name);
            let now = chains(&lp.peers[0].engine);
            came |= now.difference(&was).next().is_some();
            went |= was.difference(&now).next().is_some();
        }
        assert!(came && went, "chain pieces placed and taken away");
    }

    // spec/permissions.md §4, as above: random histories of grants, lowerings, removals, group
    // filings, own secrets, links, grantee writes and syncs; after each step every read thing's
    // pieces on both peers equal the whole derivation.
    #[test]
    fn pieces_keep_the_whole_derivation_through_random_histories_spec_permissions_4() {
        for seed in 1..=2u64 {
            let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let mut next = |n: usize| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                (rng % n as u64) as usize
            };
            let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
            let a0 = lp.peers[0].engine.create_account().unwrap().0;
            let a1 = lp.peers[1].engine.create_account().unwrap().0;
            lp.sync_all().unwrap();
            let ak = Ak::new("x:a.0").unwrap();
            let mut things = Vec::new();
            for i in 0..4 {
                let e = &mut lp.peers[0].engine;
                let mut m = Mutation::new();
                let t = e.new_thing(&mut m, a0.account);
                m.set(t, &ak, &Value::Int(i)).unwrap();
                e.commit(m).unwrap();
                things.push(t);
            }
            let roles = [Role::Sync, Role::Read, Role::Write, Role::Admin];
            for step in 0..14 {
                let t = things[next(things.len())];
                let op = next(8);
                let r = match op {
                    0 => lp.peers[0].engine.grant(&t, &a1.account, &ct::Edge { role: roles[next(4)], until: None, invite: None, tied: None }).map(drop),
                    1 => lp.peers[0].engine.demote(&t, &Demotion { holder: a1.account, new: None, retain: None }).map(drop),
                    2 => lp.peers[0].engine.give_own_secrets(&t).map(drop),
                    3 => {
                        // file a random set of the others (and D, at times) in t
                        let mut items: BTreeSet<Tid> = things.iter().copied().filter(|x| *x != t && next(2) == 0).collect();
                        if next(3) == 0 {
                            items.insert(a0.devices);
                        }
                        let mut m = Mutation::new();
                        m.set(t, &ct::GROUP, &ct::Group { items, ..Default::default() }).unwrap();
                        lp.peers[0].engine.commit(m).map(drop)
                    }
                    4 => {
                        let mut m = Mutation::new();
                        m.set(t, &ak, &Value::Int(step)).unwrap();
                        lp.peers[1].commit(m).map(drop)
                    }
                    5 => {
                        let spec = crate::flows::LinkSpec { target: t, role: Role::Read, until: None, hosts: Vec::new(), peers: Vec::new(), single_use: next(2) == 0 };
                        lp.peers[0].engine.create_link(&a0.account, &spec).map(|(l, _, _)| l).and_then(|l| {
                            lp.sync_all()?;
                            lp.peers[1].engine.redeem(&l, &a1.account, l.single_use).map(drop)
                        })
                    }
                    _ => lp.sync_all(),
                };
                let name = format!("seed {seed} step {step} op {op}: {}", if r.is_ok() { "done" } else { "refused" });
                check(&mut lp.peers[0].engine, &name);
                check(&mut lp.peers[1].engine, &name);
            }
        }
    }
}
