//! The certificates of the things this node reads (`Engine::sync_certificates`), kept per piece
//! and indexed per commit (`Certified`): `sync_bodies` reads one commit's row, the record module
//! one thing's records. A thing's certificates are the union of pieces (`Piece`), each one
//! derivation read by what it is made of, shared by every read thing it goes under: a change
//! re-derives the pieces whose reads it moved and rewrites the rows of the commits whose naming
//! changed, so an account named on n things pays for the copy that changed, not for n.
//!
//! Which pieces go under which read thing is followed the same way, per key: the read things
//! (from the sync set), each one's inbox actors, and each thing with authors (the chains its
//! commits' authors' chains are made of, and the read things whose closure holds it). New keys
//! come from feeds (`Indexes::chains_on` gaining a thing, `Held` naming a holder on a thing),
//! never from a walk of everything; a key whose input went away settles to nothing and is
//! dropped.

use super::ThingSync;
use crate::Engine;
use crate::error::Result;
use crate::sync_ids::{Certs, Parts};
use osis_base::memo::{Effects, Feed, Quiet, Stamped, StampedSet, Unrecorded};
use osis_base::{CommitId, Tid};
use std::collections::{BTreeMap, BTreeSet};
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

/// One derivation of certificates, going under each read thing it is placed under
/// (`Engine::sync_certificates`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Piece {
    /// A read thing's own (`Engine::own_piece`), under it alone.
    Own(Tid),
    /// Author `a`'s chain to `x` (`Engine::chain_piece`), under each read thing whose closure
    /// holds, and whose actor reads, a thing with a held commit of `a` writing `x` or acting for
    /// it (`Indexes::chains_on`): one piece per chain, however many things need it.
    Chain(Tid, Tid),
    /// Actor `a`'s grant copy for `x` (`Engine::kept_grant_copy`), under each read thing owning `a`'s
    /// inbox.
    Grant(Tid, Tid),
    /// Account `p`'s signing chain (`Engine::account_piece`), under each read thing one of whose
    /// pieces names `p` (`Certs::accounts`): a rotation re-derives this piece alone, not every
    /// piece naming the account.
    Account(Tid),
}

/// `Followers::pieces`.
type Pieces = Effects<Piece, Option<Arc<Certs>>>;

/// What a thing with authors gives (`Followers::authored`): the chains of its commits' authors
/// that are no node (`Indexes::chains_on`), and the read things whose closure holds it and whose
/// actor reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Authored {
    chains: BTreeSet<(Tid, Tid)>,
    under: BTreeSet<Tid>,
}

/// The keys followed, taken out of `Certified` while they settle (their functions read the
/// engine whole).
#[derive(Clone)]
struct Followers {
    /// Per thing that came to hold a read sync ID (`SyncRows::read`'s feed), whether it holds one.
    read: Effects<Tid, bool>,
    /// The things coming to hold a read sync ID; `None` until the first follow.
    read_feed: Option<Feed<Tid>>,
    /// Per read thing, the actors whose inbox it owns.
    inboxes: Effects<Tid, Arc<BTreeSet<Tid>>>,
    /// Per thing with authors (`Indexes::chains_on`), what it gives.
    authored: Effects<Tid, Arc<Authored>>,
    /// Per piece placed somewhere, its certificates; `None` for a grant copy of a pair no longer
    /// named (the piece goes).
    pieces: Pieces,
    /// New things with authors, new (holder, thing) pairs; `None` until the first follow.
    feeds: Option<Feeds>,
    /// The follow's fixed point.
    quiet: Quiet,
}

/// `Followers::feeds`.
type Feeds = (Feed<Tid>, Feed<(Tid, Tid)>);

impl Default for Followers {
    fn default() -> Self {
        Followers { read: Effects::new("sync: certified things"), read_feed: None, inboxes: Effects::new("sync: certified inboxes"), authored: Effects::new("sync: certified authored"), pieces: Effects::new("sync: certified pieces"), feeds: None, quiet: Quiet::default() }
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
/// thing. Every map is bounded by what is held: a piece per read thing, per chain of an author
/// writing under a read closure (to a thing it wrote on, to an actor it acted for there) and per
/// (inbox actor, thing named on); the rows by the commits and records those name.
#[derive(Clone, Default)]
pub(crate) struct Certified {
    followers: Followers,
    /// The read things, per key (what `Authored` and `sync::listed` read; `listed` follows its
    /// feed).
    pub(crate) read: StampedSet<Tid>,
    /// Each read thing's inbox actors, as placed.
    inboxes_of: BTreeMap<Tid, Arc<BTreeSet<Tid>>>,
    inboxes: BTreeMap<Tid, Inbox>,
    /// Each followed thing with authors, as placed.
    authored: BTreeMap<Tid, Arc<Authored>>,
    /// Per (chain piece, read thing), the things with authors that place it there: it goes under
    /// the read thing while any does.
    chain_by: BTreeMap<(Piece, Tid), BTreeSet<Tid>>,
    placed: BTreeMap<Piece, Placed>,
    /// Per (commit, read thing), what each piece under the thing names of the commit.
    named: BTreeMap<(CommitId, Tid), BTreeMap<Piece, Named>>,
    /// Per read thing, each record its pieces name, with how many name it.
    record_counts: BTreeMap<Tid, BTreeMap<Tid, usize>>,
    /// Per (read thing, account), the pieces under the thing that name the account
    /// (`Certs::accounts`): its `Piece::Account` goes under the thing while any does.
    account_naming: BTreeMap<(Tid, Tid), BTreeSet<Piece>>,
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
    /// Places piece `p` under `t`, following it if it is new.
    fn place(&mut self, p: Piece, t: Tid, pieces: &mut Pieces) {
        if !self.placed.contains_key(&p) {
            pieces.want(p);
        }
        let placed = self.placed.entry(p).or_default();
        if placed.under.insert(t) {
            let certs = placed.certs.clone();
            self.apply(t, p, &Certs::default(), &certs, pieces);
        }
    }

    /// Thing `x` places chain piece `p` under `t`.
    fn place_chain(&mut self, p: Piece, t: Tid, x: Tid, pieces: &mut Pieces) {
        let by = self.chain_by.entry((p, t)).or_default();
        if by.insert(x) && by.len() == 1 {
            self.place(p, t, pieces);
        }
    }

    /// Thing `x` places chain piece `p` under `t` no more.
    fn unplace_chain(&mut self, p: Piece, t: Tid, x: Tid, pieces: &mut Pieces) {
        let k = (p, t);
        let Some(by) = self.chain_by.get_mut(&k) else { return };
        if by.remove(&x) && by.is_empty() {
            self.chain_by.remove(&k);
            self.unplace(p, t, pieces);
        }
    }

    /// Takes piece `p` from under `t`, unfollowing it once it is placed nowhere.
    fn unplace(&mut self, p: Piece, t: Tid, pieces: &mut Pieces) {
        let Some(placed) = self.placed.get_mut(&p) else { return };
        if placed.under.remove(&t) {
            let certs = placed.certs.clone();
            self.apply(t, p, &certs, &Certs::default(), pieces);
        }
        if self.placed.get(&p).is_some_and(|x| x.under.is_empty()) {
            self.placed.remove(&p);
            pieces.unwant(&p);
        }
    }

    /// Piece `p`'s certificates are `now`.
    fn reset(&mut self, p: Piece, now: Arc<Certs>, pieces: &mut Pieces) {
        let Some(placed) = self.placed.get_mut(&p) else { return };
        let was = std::mem::replace(&mut placed.certs, now.clone());
        let under: Vec<Tid> = placed.under.iter().copied().collect();
        for t in under {
            self.apply(t, p, &was, &now, pieces);
        }
    }

    /// Piece `p` under `t` moved from `was` to `now`: the rows of the commits and the records
    /// either names, and the account pieces under `t` (an account piece names no account).
    fn apply(&mut self, t: Tid, p: Piece, was: &Certs, now: &Certs, pieces: &mut Pieces) {
        let none = BTreeSet::new();
        let (had, has) = (was.accounts.as_ref().unwrap_or(&none), now.accounts.as_ref().unwrap_or(&none));
        for a in had.difference(has) {
            let k = (t, *a);
            let Some(by) = self.account_naming.get_mut(&k) else { continue };
            if by.remove(&p) && by.is_empty() {
                self.account_naming.remove(&k);
                self.unplace(Piece::Account(*a), t, pieces);
            }
        }
        for a in has.difference(had) {
            let by = self.account_naming.entry((t, *a)).or_default();
            if by.insert(p) && by.len() == 1 {
                self.place(Piece::Account(*a), t, pieces);
            }
        }
        let commits: BTreeSet<&CommitId> = was.commits.keys().chain(&was.headers).chain(was.mintings.keys()).chain(now.commits.keys()).chain(&now.headers).chain(now.mintings.keys()).collect();
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
                    u.mints.extend(n.mints.iter().copied());
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
    /// The things whose certificates `Certified` keeps: those holding a read sync ID
    /// (`SyncRows::read`), whole: for tests.
    #[cfg(test)]
    pub(crate) fn read_things(&mut self) -> Result<Arc<BTreeSet<Tid>>> {
        self.follow_rows()?;
        Ok(Arc::new((*self.core.sync_rows.read).clone()))
    }

    /// What thing `x` gives the read things (`Authored`): its chains (`Indexes::chains_on`) of
    /// authors that are no node, and the read things whose closure holds it
    /// (`Groups::enclosing`) and whose actor reads it (`cert_reads_in`), each read per key.
    fn authored(&mut self, x: &Tid) -> Arc<Authored> {
        let chains: Vec<(Tid, Tid)> = self.core.ix.chains_on.get(x).into_iter().flatten().copied().collect();
        let chains: BTreeSet<(Tid, Tid)> = chains.into_iter().filter(|(a, _)| !self.is_node(a).unwrap_or(false)).collect();
        if chains.is_empty() {
            return Arc::default();
        }
        let under = self.core.ix.groups.enclosing(x).into_iter().filter(|t| self.core.certified.read.contains(t) && self.cert_reads_in(t, x)).collect();
        Arc::new(Authored { chains, under })
    }

    /// Piece `p`'s certificates; `None` for a grant copy whose actor is no longer named on the
    /// thing (`Held::is_named`, read per pair so the piece goes when the pair does).
    fn piece(&mut self, p: &Piece) -> Option<Arc<Certs>> {
        Some(Arc::new(match p {
            Piece::Own(t) => self.own_piece(t),
            Piece::Chain(a, x) => self.chain_piece(a, x),
            Piece::Grant(a, x) if !self.core.ix.held.is_named(a, x) => return None,
            Piece::Grant(a, x) => self.kept_grant_copy(a, x),
            Piece::Account(p) => self.account_piece(p),
        }))
    }

    /// Brings `Certified` up to date with what moved since the last call: work in proportion to
    /// the keys whose reads moved and the pieces they place. Read by no caller: what a caller
    /// reads is the rows (`certified`, `certified_records`). Whether a row moved.
    pub(crate) fn follow_certificates(&mut self) -> Result<bool> {
        if self.certificates_quiet() {
            return Ok(false);
        }
        osis_base::costs::count("certified: follows", 1);
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let mut f = std::mem::take(&mut self.core.certified.followers);
        let r = self.follow_with(&mut f);
        f.quiet.ended(from, r.is_ok());
        self.core.certified.followers = f;
        r
    }

    /// Whether `follow_certificates` is at its fixed point (`Quiet`), the rows it follows inside
    /// included: a follow would do nothing.
    pub(crate) fn certificates_quiet(&self) -> bool {
        let f = &self.core.certified.followers;
        f.quiet.holds(f.read.idle() && f.inboxes.idle() && f.authored.idle() && f.pieces.idle()) && self.rows_quiet()
    }

    fn follow_with(&mut self, f: &mut Followers) -> Result<bool> {
        self.core.certified.wrote = false;
        // the entries the inbox keys read, before they are asked whether they are due
        self.refresh_inboxes();
        if f.feeds.is_none() {
            f.feeds = Some((self.core.ix.chains_on.feed(), self.core.ix.held.pairs_feed()));
            let all: Vec<Tid> = self.core.ix.chains_on.keys().copied().collect();
            for x in all {
                f.authored.want(x);
            }
        }
        // the read things, per thing: each its own piece and inbox actors
        self.follow_rows()?;
        let came: Vec<Tid> = match f.read_feed.as_mut() {
            Some(feed) => feed.added(),
            None => {
                f.read_feed = Some(self.core.sync_rows.read.feed());
                self.core.sync_rows.read.iter().copied().collect()
            }
        };
        for t in came {
            f.read.want(t);
        }
        for t in f.read.due() {
            let Some((was, now)) = f.read.settle(&t, || self.core.sync_rows.read.contains(&t)) else { continue };
            if now {
                self.core.certified.read.insert(t);
                self.core.certified.place(Piece::Own(t), t, &mut f.pieces);
                f.inboxes.want(t);
                continue;
            }
            f.read.unwant(&t);
            if was == Some(true) {
                self.core.certified.read.remove(&t);
                self.core.certified.unplace(Piece::Own(t), t, &mut f.pieces);
                f.inboxes.unwant(&t);
                let had = self.core.certified.inboxes_of.remove(&t).unwrap_or_default();
                self.set_inboxes(f, &t, &had, &BTreeSet::new());
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
            let had = match now.chains.is_empty() {
                true => {
                    // followed while it has any author (one that is no node may come); with none,
                    // again once one comes (the feed)
                    if self.core.ix.chains_on.get(&x).is_none() {
                        f.authored.unwant(&x);
                    }
                    self.core.certified.authored.remove(&x)
                }
                false => self.core.certified.authored.insert(x, now.clone()),
            }
            .unwrap_or_default();
            let pairs = |a: &Authored| -> BTreeSet<(Piece, Tid)> { a.chains.iter().flat_map(|(au, to)| a.under.iter().map(move |t| (Piece::Chain(*au, *to), *t))).collect() };
            let (old, new) = (pairs(&had), pairs(&now));
            for (p, t) in old.difference(&new) {
                self.core.certified.unplace_chain(*p, *t, x, &mut f.pieces);
            }
            for (p, t) in new.difference(&old) {
                self.core.certified.place_chain(*p, *t, x, &mut f.pieces);
            }
        }
        // a piece settling may place account pieces (`Certs::accounts`): a second round settles
        // them (an account piece names no account)
        for _ in 0..2 {
            for p in f.pieces.due() {
                osis_base::costs::count("sync: certificate pieces derived", 1);
                let Some((_, now)) = f.pieces.settle(&p, || self.piece(&p)) else { continue };
                match (p, now) {
                    (_, Some(now)) => self.core.certified.reset(p, now, &mut f.pieces),
                    // a grant copy of a pair no longer named: gone until the feed names it again
                    (Piece::Grant(a, x), None) => self.drop_grant(f, a, x),
                    (_, None) => {}
                }
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
                self.core.certified.unplace(Piece::Grant(*a, x), *t, &mut f.pieces);
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
                self.core.certified.place(Piece::Grant(*a, x), *t, &mut f.pieces);
            }
        }
    }

    /// Inbox actor `a` is named on `x`: its grant copy goes under each owner of its inbox.
    fn add_grant(&mut self, f: &mut Followers, a: Tid, x: Tid) {
        let Some(ib) = self.core.certified.inboxes.get_mut(&a) else { return };
        ib.on.insert(x);
        let owners: Vec<Tid> = ib.owners.iter().copied().collect();
        for t in owners {
            self.core.certified.place(Piece::Grant(a, x), t, &mut f.pieces);
        }
    }

    fn drop_grant(&mut self, f: &mut Followers, a: Tid, x: Tid) {
        let owners: Vec<Tid> = self.core.certified.inboxes.get_mut(&a).map(|ib| {
            ib.on.remove(&x);
            ib.owners.iter().copied().collect()
        }).unwrap_or_default();
        self.core.certified.reset(Piece::Grant(a, x), Arc::default(), &mut f.pieces);
        for t in owners {
            self.core.certified.unplace(Piece::Grant(a, x), t, &mut f.pieces);
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
            if !n.mints.is_empty() {
                got.mintings.insert(*c, n.mints.clone());
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
        super::super::listed::tests::check(e, step);
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
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None, floor: None };
        // a link's K, written first by the sharer node and then by L (an author that is no node)
        let link: std::cell::RefCell<Option<osis_blob::ShareLink>> = Default::default();
        let k = || link.borrow().as_ref().unwrap().k;
        type Step<'a> = (&'a str, Box<dyn Fn(&mut LocalPeer) + 'a>);
        let steps: Vec<Step> = vec![
            ("grant read", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&things[0], &a1.account, &edge(Role::Read)).unwrap()))),
            ("own secrets", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.give_own_secrets(&things[1]).unwrap()))),
            ("grant write", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&things[1], &a1.account, &edge(Role::Write)).unwrap()))),
            ("link made", Box::new(|lp: &mut LocalPeer| {
                let spec = crate::flows::LinkSpec { target: things[2], role: Role::Read, until: None, peers: Vec::new(), single_use: false };
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

    // spec/sync-judgement.md §1 (Entitlement: placing chain certificates by what S's actor may
    // read), spec/sync-inbox.md §5 (Grant copy: while the actor reads the thing),
    // spec/permissions.md §2 (`until`): G, a group with secrets of its own filed in D, holds X and
    // reads it by a grant with an `until`; the account's chain to X and G's grant copy go under
    // G, and the clock passing the `until` (no commit) moves both, as the whole derivation does,
    // with a wake set at it.
    #[test]
    fn an_until_passing_moves_chain_and_grant_pieces_spec_sync_judgement_1() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a0 = lp.peers[0].engine.create_account().unwrap().0;
        let ak = Ak::new("x:a.0").unwrap();
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let x = e.new_thing(&mut m, a0.account);
        m.set(x, &ak, &Value::Int(1)).unwrap();
        e.commit(m).unwrap();
        e.give_own_secrets(&x).unwrap();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, a0.account);
        m.set(g, &ct::GROUP, &ct::Group { items: [x].into(), ..Default::default() }).unwrap();
        e.commit(m).unwrap();
        e.give_own_secrets(&g).unwrap();
        let until = WallMs(e.now().0 + 10_000);
        e.grant(&x, &g, &ct::Edge { role: Role::Read, until: Some(until), invite: None, tied: None, floor: None }).unwrap();
        let mut m = Mutation::new();
        m.op(a0.devices, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(crate::engine::groups::ITEMS)], op: osis_crdt::Op::Add(Value::Tid(g)) }).unwrap();
        e.commit(m).unwrap();
        let under_g = |e: &Engine| e.core.certified.placed.get(&Piece::Chain(a0.account, x)).is_some_and(|p| p.under.contains(&g));
        check(e, "granted");
        assert!(e.read_things().unwrap().contains(&g), "G is read here");
        assert!(e.reads_in(&g, &x) && under_g(e), "the chain to X goes under G");
        assert_eq!(e.clock_next(), Some(until), "a wake at the until");
        lp.advance(20_000);
        let e = &mut lp.peers[0].engine;
        let now = e.now();
        e.set_now(now);
        check(e, "until passed");
        assert!(!e.reads_in(&g, &x) && !under_g(e), "the chain to X left G");
    }

    /// Thing `t`'s certificates as `e`'s rows keep them.
    fn rows_of(e: &mut Engine, t: &Tid) -> Certs {
        e.follow_certificates().unwrap();
        let mut got = Certs::default();
        for ((c, x), n) in e.core.certified.of.iter() {
            if x != t {
                continue;
            }
            if !n.parts.is_empty() {
                got.commits.insert(*c, n.parts.clone());
            }
            if n.header {
                got.headers.insert(*c);
            }
            if !n.mints.is_empty() {
                got.mintings.insert(*c, n.mints.clone());
            }
        }
        got.records = (*e.core.certified.records.get(t).cloned().unwrap_or_default()).clone();
        got
    }

    // spec/sync-judgement.md §2 (required set: a certificate blob is in it by the chain
    // certificates it carries, the same at every node), spec/permissions.md §4 (Chain
    // certificates: an account's signing chain, every line, old lines as headers alone): writers
    // of two accounts on T, through account rotations of both, a role change and T filed in a group and out again, name the
    // same certificates of T at both nodes, each account's own (its every rotation line among
    // them) included at the other; a chain certificate of a writer that is none of T's (its edge
    // on an unrelated group) is named at neither.
    #[test]
    fn two_nodes_name_the_same_certificates_whoever_logs_them_spec_sync_judgement_2() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        let a0 = lp.peers[0].engine.create_account().unwrap().0;
        let a1 = lp.peers[1].engine.create_account().unwrap().0;
        lp.sync_all().unwrap();
        let ak = Ak::new("x:a.0").unwrap();
        let mut made = Vec::new();
        for i in 0..3 {
            let e = &mut lp.peers[0].engine;
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0.account);
            m.set(t, &ak, &Value::Int(i)).unwrap();
            e.commit(m).unwrap();
            made.push(t);
        }
        let (t, g, y) = (made[0], made[1], made[2]);
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None, floor: None };
        let rotate = |lp: &mut LocalPeer, i: usize, p: Tid| {
            let e = &mut lp.peers[i].engine;
            e.run(|tx| crate::flows::signing::rotate_in(tx, p, &[], &mut crate::flows::Done::default())).unwrap().unwrap();
        };
        let write = |lp: &mut LocalPeer, i: usize, v: i64| {
            let mut m = Mutation::new();
            m.set(t, &ak, &Value::Int(v)).unwrap();
            lp.peers[i].commit(m).unwrap();
        };
        type Step<'a> = (&'a str, Box<dyn Fn(&mut LocalPeer) + 'a>);
        let steps: Vec<Step> = vec![
            // shared no more at node 0: T syncs at both only once filed in each D
            ("grant write", Box::new(|lp: &mut LocalPeer| {
                lp.peers[0].engine.grant(&t, &a1.account, &edge(Role::Write)).unwrap();
                lp.peers[0].engine.unshare(&t).unwrap();
            })),
            ("filed in each D", Box::new(|lp: &mut LocalPeer| {
                lp.sync_all().unwrap();
                for (i, d, items) in [(0, a0.devices, vec![t, g]), (1, a1.devices, vec![t])] {
                    let mut m = Mutation::new();
                    m.set(d, &ct::GROUP, &ct::Group { items: items.into_iter().collect(), ..Default::default() }).unwrap();
                    lp.peers[i].commit(m).unwrap();
                }
            })),
            ("both write", Box::new(|lp: &mut LocalPeer| {
                lp.sync_all().unwrap();
                write(lp, 0, 1);
                write(lp, 1, 2);
            })),
            ("an unrelated group", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&y, &a1.account, &edge(Role::Write)).unwrap()))),
            ("a1 rotates", Box::new(|lp: &mut LocalPeer| rotate(lp, 1, a1.account))),
            ("a1 rotates again and writes", Box::new(|lp: &mut LocalPeer| {
                rotate(lp, 1, a1.account);
                write(lp, 1, 3);
            })),
            ("a0 rotates twice", Box::new(|lp: &mut LocalPeer| {
                rotate(lp, 0, a0.account);
                rotate(lp, 0, a0.account);
            })),
            ("lowered", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.demote(&t, &Demotion { holder: a1.account, new: Some(edge(Role::Read)), retain: None }).unwrap()))),
            ("raised", Box::new(|lp: &mut LocalPeer| drop(lp.peers[0].engine.grant(&t, &a1.account, &edge(Role::Write)).unwrap()))),
            ("filed in a group", Box::new(|lp: &mut LocalPeer| {
                let mut m = Mutation::new();
                m.set(g, &ct::GROUP, &ct::Group { items: [t].into(), ..Default::default() }).unwrap();
                lp.peers[0].engine.commit(m).unwrap();
            })),
            ("a1 writes again", Box::new(|lp: &mut LocalPeer| write(lp, 1, 4))),
            ("unfiled", Box::new(|lp: &mut LocalPeer| {
                let mut m = Mutation::new();
                m.set(g, &ct::GROUP, &ct::Group::default()).unwrap();
                lp.peers[0].engine.commit(m).unwrap();
            })),
        ];
        let lines = |e: &Engine, p: &Tid| e.account_rotations(p);
        for (k, (name, f)) in steps.iter().enumerate() {
            f(&mut lp);
            lp.sync_all().unwrap();
            if k > 0 {
                assert!(lp.peers.iter_mut().all(|p| p.engine.read_things().unwrap().contains(&t)), "{name}: T read at both");
            }
            let r0 = rows_of(&mut lp.peers[0].engine, &t);
            let r1 = rows_of(&mut lp.peers[1].engine, &t);
            assert_eq!(r0, r1, "{name}: T's certificates differ between the nodes");
            check(&mut lp.peers[0].engine, name);
            check(&mut lp.peers[1].engine, name);
            // y's edge naming a1: a chain certificate of a1, but none of T's
            let on_y = |e: &Engine| e.core.ix.by_aspect.get(&(y, Ak::new("roles.0").unwrap())).into_iter().flatten().map(|x| x.1).collect::<Vec<_>>();
            for c in on_y(&lp.peers[0].engine) {
                assert!(!r0.commits.contains_key(&c), "{name}: an edge on an unrelated group named");
            }
        }
        // every line named, the current rotation with its `keys.0` part, every other as a header
        // alone (no old epoch's deposit seed, spec/permissions.md §4)
        let r0 = rows_of(&mut lp.peers[0].engine, &t);
        for p in [a0.account, a1.account] {
            let ls = lines(&lp.peers[0].engine, &p);
            let current = lp.peers[0].engine.current_keys(&p);
            assert!(ls.len() >= 2, "rotations made");
            for c in ls {
                match current.contains(&c) {
                    true => assert!(r0.commits.contains_key(&c), "the current rotation named with its part"),
                    false => assert!(r0.headers.contains(&c) && !r0.commits.contains_key(&c), "an old line named as a header alone"),
                }
            }
        }
    }

    // spec/sync-judgement.md §2 (required set: certificates the same at every node), counted at n
    // and 10n lines of a writer's signing chain and at m and 10m things it wrote on: after its
    // rotation, and after a plain write by it, the reader derives the same number of pieces at
    // every size (the chain is one piece, `Piece::Account`, not part of each piece naming it).
    #[test]
    fn another_accounts_rotation_derives_pieces_in_proportion_to_change_spec_sync_judgement_2() {
        let derived = |n: usize, m: usize| -> (u64, u64) {
            let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
            let a0 = lp.peers[0].engine.create_account().unwrap().0;
            let a1 = lp.peers[1].engine.create_account().unwrap().0;
            lp.sync_all().unwrap();
            let ak = Ak::new("x:a.0").unwrap();
            let e = &mut lp.peers[0].engine;
            let mut m_ = Mutation::new();
            let ts: Vec<Tid> = (0..m).map(|_| e.new_thing(&mut m_, a0.account)).collect();
            for t in &ts {
                m_.set(*t, &ak, &Value::Int(0)).unwrap();
            }
            m_.set(a0.devices, &ct::GROUP, &ct::Group { items: ts.iter().copied().collect(), ..Default::default() }).unwrap();
            e.commit(m_).unwrap();
            for t in &ts {
                e.grant(t, &a1.account, &ct::Edge { role: Role::Write, until: None, invite: None, tied: None, floor: None }).unwrap();
            }
            lp.sync_all().unwrap();
            let write = |lp: &mut LocalPeer, on: &[Tid], v: i64| {
                let mut m = Mutation::new();
                for t in on {
                    m.set(*t, &ak, &Value::Int(v)).unwrap();
                }
                lp.peers[1].commit(m).unwrap();
                lp.sync_all().unwrap();
            };
            let rotate = |lp: &mut LocalPeer| {
                lp.peers[1].engine.run(|tx| crate::flows::signing::rotate_in(tx, a1.account, &[], &mut crate::flows::Done::default())).unwrap().unwrap();
                lp.sync_all().unwrap();
            };
            write(&mut lp, &ts, 1);
            for _ in 0..n {
                rotate(&mut lp);
            }
            lp.peers[0].engine.follow_certificates().unwrap();
            let pieces = || osis_base::costs::take().iter().filter(|x| x.0 == "sync: certificate pieces derived").map(|x| x.2).sum::<u64>();
            osis_base::costs::take();
            rotate(&mut lp);
            lp.peers[0].engine.follow_certificates().unwrap();
            let rotated = pieces();
            write(&mut lp, &ts[..1], 2);
            osis_base::costs::take();
            lp.peers[0].engine.follow_certificates().unwrap();
            (rotated, pieces())
        };
        let small = derived(2, 1);
        assert!(small.0 > 0, "the rotation re-derives the account's piece");
        assert_eq!(small, derived(20, 1), "pieces derived (after the rotation, after the write) at n and 10n lines");
        assert_eq!(small, derived(2, 10), "pieces derived (after the rotation, after the write) at m and 10m things written on");
    }

    /// Node 2's Y grants node 1's account X write; node 0's T1 and T2 (read at node 0) grant X
    /// write, Y holding no role on either: (world, X, Y, [T1, T2]).
    fn acting_world() -> (LocalPeer, Tid, Tid, [Tid; 2]) {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        let a0 = lp.peers[0].engine.create_account().unwrap().0;
        let a1 = lp.peers[1].engine.create_account().unwrap().0;
        let a2 = lp.peers[2].engine.create_account().unwrap().0;
        lp.sync_all().unwrap();
        let edge = ct::Edge { role: Role::Write, until: None, invite: None, tied: None, floor: None };
        let new = |lp: &mut LocalPeer, i: usize, a: Tid| {
            let e = &mut lp.peers[i].engine;
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            m.set(t, &acting_ak(), &Value::Int(0)).unwrap();
            e.commit(m).unwrap();
            t
        };
        let y = new(&mut lp, 2, a2.account);
        lp.peers[2].engine.grant(&y, &a1.account, &edge).unwrap();
        let ts = [new(&mut lp, 0, a0.account), new(&mut lp, 0, a0.account)];
        for t in &ts {
            lp.peers[0].engine.grant(t, &a1.account, &edge).unwrap();
        }
        lp.sync_all().unwrap();
        (lp, a1.account, y, ts)
    }

    fn acting_ak() -> Ak {
        Ak::new("x:a.0").unwrap()
    }

    /// X (node 1) writes `v` on `t`, acting for `y` if given.
    fn acting_write(lp: &mut LocalPeer, t: Tid, v: i64, y: Option<Tid>) -> CommitId {
        let mut m = Mutation::new();
        m.set(t, &acting_ak(), &Value::Int(v)).unwrap();
        if let Some(y) = y {
            m.act_as(y);
        }
        lp.peers[1].commit(m).unwrap().unwrap()
    }

    /// Where X's chain to Y is placed: the read things under each such piece.
    fn chain_under(e: &Engine, x: Tid, y: Tid) -> Vec<BTreeSet<Tid>> {
        e.core.certified.placed.iter().filter(|(p, _)| **p == Piece::Chain(x, y)).map(|(_, p)| p.under.clone()).collect()
    }

    // spec/permissions.md §4 (a commit's author's chain: to its actor too), spec/sync-judgement.md
    // §2: X writes T1 and T2 (each read here) acting for Y, which holds no role on either: X's
    // chain to Y is one piece, under each read thing whose closure holds such a write, however
    // many writes there are; it leaves a read thing with the thing (unshared); the rows equal the
    // whole derivation throughout.
    #[test]
    fn a_chain_to_an_acted_for_actor_is_one_piece_per_read_thing_spec_permissions_4() {
        let (mut lp, x, y, ts) = acting_world();
        for v in 1..=6 {
            acting_write(&mut lp, ts[(v % 2) as usize], v, Some(y));
            lp.sync_all().unwrap();
            check(&mut lp.peers[0].engine, &format!("write {v}"));
        }
        let e = &mut lp.peers[0].engine;
        assert!(e.read_things().unwrap().is_superset(&ts.into_iter().collect()), "T1 and T2 read here");
        assert_eq!(chain_under(e, x, y), vec![ts.into_iter().collect::<BTreeSet<Tid>>()], "one piece of X's chain to Y, under T1 and T2");
        e.unshare(&ts[1]).unwrap();
        check(e, "T2 unshared");
        assert_eq!(chain_under(e, x, y), vec![BTreeSet::from([ts[0]])], "X's chain to Y leaves T2 with it");
        e.unshare(&ts[0]).unwrap();
        check(e, "T1 unshared");
        assert!(chain_under(e, x, y).is_empty(), "and goes once no read thing needs it");
    }

    // spec/permissions.md §4, spec/sync-judgement.md §2, spec/commits.md §5 (Forgetting): X writes
    // T1 acting for Y twice, unseen by Y's admin, who removes X meanwhile, and once as itself: the
    // writes for Y are invalid, and node 0 forgets them while it still reads T1 and holds X's own
    // write there: X's chain to Y (holding the removal) stays while they are held and leaves T1
    // with the last of them; X's chain to T1 stays.
    #[test]
    fn a_chain_to_an_acted_for_actor_leaves_with_the_last_write_acting_for_it_spec_permissions_4() {
        let (mut lp, x, y, ts) = acting_world();
        let acting = [acting_write(&mut lp, ts[0], 1, Some(y)), acting_write(&mut lp, ts[0], 2, Some(y))];
        let own = acting_write(&mut lp, ts[0], 3, None);
        lp.peers[2].engine.demote(&y, &Demotion { holder: x, new: None, retain: None }).unwrap();
        lp.sync_all().unwrap();
        let e = &mut lp.peers[0].engine;
        assert!(acting.iter().all(|c| e.kept_invalid(c)), "X's writes for Y are invalid at node 0");
        check(e, "synced");
        assert_eq!(chain_under(e, x, y), vec![BTreeSet::from([ts[0]])], "the chain holding the removal stays while they are held");
        let due: Vec<CommitId> = e.commit_ids().into_iter().filter(|c| e.forgettable(c).unwrap()).collect();
        assert!(acting.iter().all(|c| due.contains(c)) && !due.contains(&own), "the writes for Y are forgettable, X's own is not");
        e.forget_commits(&due).unwrap();
        check(e, "forgotten");
        assert!(e.read_things().unwrap().contains(&ts[0]), "T1 still read");
        assert!(chain_under(e, x, y).is_empty(), "X's chain to Y leaves with the last write acting for Y");
        assert!(e.core.certified.placed.get(&Piece::Chain(x, ts[0])).is_some_and(|p| p.under.contains(&ts[0])), "X's chain to T1 stays, by its own write");
    }

    /// Node 0's account A makes T (read here) and Y, a private actor: C (node 2's account) holds
    /// read on Y, W (node 1's account) write on T. Y holds no role on T: (world, W, Y, T, the
    /// commits granting C on Y).
    fn private_world() -> (LocalPeer, Tid, Tid, Tid, Vec<CommitId>) {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.create_account().unwrap().0;
        let w = lp.peers[1].engine.create_account().unwrap().0;
        let c = lp.peers[2].engine.create_account().unwrap().0;
        lp.sync_all().unwrap();
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None, floor: None };
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a.account);
        let y = e.new_thing(&mut m, a.account);
        m.set(t, &acting_ak(), &Value::Int(0)).unwrap();
        m.set(y, &acting_ak(), &Value::Int(0)).unwrap();
        e.commit(m).unwrap();
        e.grant(&t, &w.account, &edge(Role::Write)).unwrap();
        let on_y = e.grant(&y, &c.account, &edge(Role::Read)).unwrap().commits;
        lp.sync_all().unwrap();
        (lp, w.account, y, t, on_y)
    }

    /// What T's certificates at node 0 carry of Y: Y's record, or a commit on Y's roster.
    fn of_y(lp: &mut LocalPeer, t: Tid, y: Tid, on_y: &[CommitId]) -> (bool, bool) {
        let e = &mut lp.peers[0].engine;
        check(e, "synced");
        let r = rows_of(e, &t);
        (r.records.contains(&y), on_y.iter().any(|c| r.commits.contains_key(c) || r.headers.contains(c)))
    }

    // spec/permissions.md §4 (Chained writes; Chain certificates), spec/requirements.md (readers
    // learn the rosters of actors holding a role, never the entries of other rosters): W, a writer
    // of T and no admin, grants private Y read on T. The grant never applies; node 0, holding Y's
    // roster, logs nothing of Y under T.
    #[test]
    fn a_writers_grant_of_a_private_actor_logs_nothing_of_it_spec_permissions_4() {
        let (mut lp, _, y, t, on_y) = private_world();
        let mut m = Mutation::new();
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Tid(y))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&ct::Edge { role: Role::Read, until: None, invite: None, tied: None, floor: None })) }).unwrap();
        lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        assert!(!lp.peers[0].engine.roster(&t).contains_key(&y), "the grant applies nowhere");
        assert_eq!(of_y(&mut lp, t, y, &on_y), (false, false), "Y's record or roster under T");
    }

    // spec/permissions.md §4 (Chain certificates), as above: W writes T acting for Y, holding no
    // role on Y: its chain to Y carries nothing of Y (the commit is invalid without it).
    #[test]
    fn acting_for_an_actor_one_holds_no_role_on_logs_nothing_of_it_spec_permissions_4() {
        let (mut lp, _, y, t, on_y) = private_world();
        let mut m = Mutation::new();
        m.set(t, &acting_ak(), &Value::Int(1)).unwrap();
        m.act_as(y);
        let c = lp.peers[1].engine.commit_hostile(m).unwrap().unwrap();
        lp.sync_all().unwrap();
        assert!(lp.peers[0].engine.kept_invalid(&c), "the write for Y is invalid at node 0");
        assert_eq!(of_y(&mut lp, t, y, &on_y), (false, false), "Y's record or roster under T");
    }

    // spec/permissions.md §4, spec/sync-judgement.md §1 (List blobs), as above: random histories
    // of grants, lowerings, removals, group filings, own secrets, links, grantee writes, account
    // rotations listing a write and syncs;
    // after each step every read thing's pieces and list rows on both peers equal the whole
    // derivation.
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
                let op = next(9);
                let r = match op {
                    0 => lp.peers[0].engine.grant(&t, &a1.account, &ct::Edge { role: roles[next(4)], until: None, invite: None, tied: None, floor: None }).map(drop),
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
                        let spec = crate::flows::LinkSpec { target: t, role: Role::Read, until: None, peers: Vec::new(), single_use: next(2) == 0 };
                        lp.peers[0].engine.create_link(&a0.account, &spec).map(|(l, _, _)| l).and_then(|l| {
                            lp.sync_all()?;
                            lp.peers[1].engine.redeem(&l, &a1.account, l.single_use).map(drop)
                        })
                    }
                    7 => {
                        // a write on t, and a rotation of the account listing it (its thing lists)
                        let mut m = Mutation::new();
                        m.set(t, &ak, &Value::Int(step)).unwrap();
                        let e = &mut lp.peers[0].engine;
                        e.commit(m).and_then(|c| e.run(|tx| crate::flows::signing::rotate_in(tx, a0.account, &c.into_iter().collect::<Vec<_>>(), &mut crate::flows::Done::default())).map(drop))
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
