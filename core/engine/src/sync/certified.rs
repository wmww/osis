//! The certificates of the things this node reads (`Engine::sync_certificates`), kept per piece
//! and indexed per commit (`Certified`): `sync_bodies` reads one commit's row, the record module
//! one thing's records. A thing's certificates are the union of pieces (`Piece`), each one
//! derivation read by what it is made of, shared by every read thing it goes under: a change
//! re-derives the pieces whose reads it moved and rewrites the rows of the commits whose naming
//! changed, so an account named on n things pays for the copy that changed, not for n.
//!
//! Which pieces go under which read thing is followed the same way, per key: the read things
//! (from the sync set) and each thing with authors (the chains its commits' authors' chains are
//! made of, and the read things whose sync unit holds it). New keys come from a feed
//! (`Indexes::chains_on` gaining a thing), never from a walk of everything; a key whose input went away settles to nothing and is
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
    /// The parts, header and mintings named.
    fn size(&self) -> usize {
        self.parts.len() + usize::from(self.header) + self.mints.len()
    }

    fn of(certs: &Certs, c: &CommitId) -> Option<Named> {
        let parts = certs.commits.get(c).cloned().unwrap_or_default();
        let header = certs.headers.contains(c);
        let mints = certs.mintings.get(c).cloned().unwrap_or_default();
        (header || !parts.is_empty() || !mints.is_empty()).then_some(Named { parts, header, mints })
    }
}

/// What the pieces under a read thing name of one commit, each part, header and minting with
/// how many name it: the union (`Certified::of`'s row) moves only where a count leaves or
/// reaches 0, so a piece coming or going costs what it names, not the pieces beside it.
#[derive(Clone, Debug, Default)]
struct Counted {
    parts: BTreeMap<usize, usize>,
    header: usize,
    mints: BTreeMap<Tid, usize>,
}

/// The union's moves from one piece's change (`Counted::add`, `Counted::sub`).
#[derive(Default)]
struct Moved {
    came: Named,
    gone: Named,
    /// The header went from named to not, or back.
    header: bool,
}

impl Moved {
    fn is_empty(&self) -> bool {
        !self.header && self.came == Named::default() && self.gone == Named::default()
    }
}

impl Counted {
    fn is_empty(&self) -> bool {
        self.parts.is_empty() && self.header == 0 && self.mints.is_empty()
    }

    fn add(&mut self, n: &Named, m: &mut Moved) {
        for ai in &n.parts {
            let c = self.parts.entry(*ai).or_default();
            *c += 1;
            if *c == 1 {
                m.came.parts.insert(*ai);
            }
        }
        for x in &n.mints {
            let c = self.mints.entry(*x).or_default();
            *c += 1;
            if *c == 1 {
                m.came.mints.insert(*x);
            }
        }
        if n.header {
            self.header += 1;
            m.header ^= self.header == 1;
        }
    }

    fn sub(&mut self, n: &Named, m: &mut Moved) {
        for ai in &n.parts {
            if let Some(c) = self.parts.get_mut(ai) {
                *c -= 1;
                if *c == 0 {
                    self.parts.remove(ai);
                    m.gone.parts.insert(*ai);
                }
            }
        }
        for x in &n.mints {
            if let Some(c) = self.mints.get_mut(x) {
                *c -= 1;
                if *c == 0 {
                    self.mints.remove(x);
                    m.gone.mints.insert(*x);
                }
            }
        }
        if n.header && self.header > 0 {
            self.header -= 1;
            m.header ^= self.header == 0;
        }
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
    /// Holder `t`'s chain to `x` with `x`'s boxes to `t` and sync record
    /// (`Engine::holder_piece`), under `t`'s home for each `x` an edge write names it holder on
    /// (`Engine::holder_home_on`: role changes travel): `t` itself when read, an account's root
    /// for a thing the root reaches by strongs.
    Holder(Tid, Tid),
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
    /// Per thing with authors (`Indexes::chains_on`), what it gives.
    authored: Effects<Tid, Arc<Authored>>,
    /// Per (holder, thing), the read thing its piece goes under while an edge write names the
    /// holder on the thing (`holder_home_on`), followed for each pair named while the holder has
    /// a home.
    held_on: Effects<(Tid, Tid), Option<Tid>>,
    /// The (holder, thing) pairs named since the last follow (`Held::pairs_feed`); `None` until
    /// the first follow.
    pairs_feed: Option<Feed<(Tid, Tid)>>,
    /// Per piece placed somewhere, its certificates.
    pieces: Pieces,
    /// New things with authors; `None` until the first follow.
    feeds: Option<Feed<Tid>>,
    /// The follow's fixed point.
    quiet: Quiet,
}

impl Default for Followers {
    fn default() -> Self {
        Followers { read: Effects::new("sync: certified things"), read_feed: None, authored: Effects::new("sync: certified authored"), held_on: Effects::new("sync: certified held on"), pairs_feed: None, pieces: Effects::new("sync: certified pieces"), feeds: None, quiet: Quiet::default() }
    }
}

/// A piece where it is placed: the read things it goes under, and its certificates as indexed.
#[derive(Clone, Default)]
struct Placed {
    under: BTreeSet<Tid>,
    certs: Arc<Certs>,
}

/// The certificates of the things this node reads, per piece, and indexed by commit and by read
/// thing. Every map is bounded by what is held: a piece per read thing, per chain of an author
/// writing under a read sync unit (to a thing it wrote on, to an actor it acted for there); the rows by the commits and records those name.
#[derive(Clone, Default)]
pub(crate) struct Certified {
    followers: Followers,
    /// The read things, per key (what `Authored` and `sync::listed` read; `listed` follows its
    /// feed).
    pub(crate) read: StampedSet<Tid>,
    /// Each followed thing with authors, as placed.
    authored: BTreeMap<Tid, Arc<Authored>>,
    /// Per holder, the things it is named holder on, as placed (`holder_home_on`).
    held_on: BTreeMap<Tid, BTreeSet<Tid>>,
    /// Per (chain piece, read thing), the things with authors that place it there: it goes under
    /// the read thing while any does.
    chain_by: BTreeMap<(Piece, Tid), BTreeSet<Tid>>,
    placed: BTreeMap<Piece, Placed>,
    /// Per (commit, read thing), what the pieces under the thing name of the commit, counted.
    named: BTreeMap<(CommitId, Tid), Counted>,
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
    /// Per record, the read things whose certificates name it (`records` the other way; new
    /// keys by its feed, `sync::listed`).
    pub(crate) namers: Stamped<Tid, Arc<BTreeSet<Tid>>>,
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
            let (a, b) = (Named::of(was, c), Named::of(now, c));
            if a == b {
                continue;
            }
            let k = (*c, t);
            // counted: tests read what a piece's change costs the rows of the commits it names
            osis_base::costs::count("certified: names counted", (a.as_ref().map_or(0, Named::size) + b.as_ref().map_or(0, Named::size)) as u64);
            let counted = self.named.entry(k).or_default();
            // `b` first: a part both name keeps its count above 0, so `came` and `gone` are
            // disjoint
            let mut m = Moved::default();
            if let Some(b) = &b {
                counted.add(b, &mut m);
            }
            if let Some(a) = &a {
                counted.sub(a, &mut m);
            }
            let named = !counted.is_empty();
            if !named {
                self.named.remove(&k);
            }
            if m.is_empty() {
                continue;
            }
            self.wrote = true;
            let had = self.of.contains_key(&k);
            self.of.update(k, |u| {
                let mut u = u.unwrap_or_default();
                u.parts.extend(m.came.parts.iter().copied());
                u.mints.extend(m.came.mints.iter().copied());
                for ai in &m.gone.parts {
                    u.parts.remove(ai);
                }
                for x in &m.gone.mints {
                    u.mints.remove(x);
                }
                u.header ^= m.header;
                named.then_some(u)
            });
            if had != named {
                self.naming.update(*c, |naming| {
                    let mut naming = naming.unwrap_or_default();
                    let set = Arc::make_mut(&mut naming);
                    match named {
                        true => set.insert(t),
                        false => set.remove(&t),
                    };
                    (!set.is_empty()).then_some(naming)
                });
            }
        }
        if was.records == now.records {
            return;
        }
        let counts = self.record_counts.entry(t).or_default();
        let (mut came, mut gone) = (Vec::new(), Vec::new());
        for r in was.records.difference(&now.records) {
            if let Some(n) = counts.get_mut(r) {
                *n -= 1;
                if *n == 0 {
                    counts.remove(r);
                    gone.push(*r);
                }
            }
        }
        for r in now.records.difference(&was.records) {
            let n = counts.entry(*r).or_default();
            *n += 1;
            if *n == 1 {
                came.push(*r);
            }
        }
        if came.is_empty() && gone.is_empty() {
            return;
        }
        self.wrote = true;
        if counts.is_empty() {
            self.record_counts.remove(&t);
        }
        for r in &gone {
            self.namers.update_fed(*r, |set| {
                let mut set = set.unwrap_or_default();
                Arc::make_mut(&mut set).remove(&t);
                (!set.is_empty()).then_some(set)
            });
        }
        for r in &came {
            self.namers.update_fed(*r, |set| {
                let mut set = set.unwrap_or_default();
                Arc::make_mut(&mut set).insert(t);
                Some(set)
            });
        }
        // edited in place: a record coming or going costs itself, not the thing's every record
        self.records.update(t, |set| {
            let mut set = set.unwrap_or_default();
            let edit = Arc::make_mut(&mut set);
            for r in &gone {
                edit.remove(r);
            }
            edit.extend(came);
            (!edit.is_empty()).then_some(set)
        });
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
    /// authors that are no node, and the read things whose sync unit holds it
    /// (`units_holding`) and whose actor reads it (`cert_reads_in`), each read per key.
    fn authored(&mut self, x: &Tid) -> Arc<Authored> {
        let chains: Vec<(Tid, Tid)> = self.core.ix.chains_on.get(x).into_iter().flatten().copied().collect();
        let chains: BTreeSet<(Tid, Tid)> = chains.into_iter().filter(|(a, _)| !self.is_node(a).unwrap_or(false)).collect();
        if chains.is_empty() {
            return Arc::default();
        }
        let under = self.units_holding(x).into_iter().filter(|t| self.core.certified.read.contains(t) && self.cert_reads_in(t, x)).collect();
        Arc::new(Authored { chains, under })
    }

    /// The read thing holder `t`'s piece for `x` goes under (`Piece::Holder(t, x)`), while an
    /// edge write names `t` holder on `x`, its own things aside (a first admin's edge is its
    /// record's, which no edge write lowers): spec/permissions.md §4 Role changes travel, a role
    /// commit with an edge write naming holder `t` goes under `t`'s own sync ID with `x`'s boxes
    /// to `t` and sync record, the piece holding every edge write on its paths, a removal
    /// included, which the target's bodies no longer carry there once `t` reads it no more. `t`'s
    /// home is `t` when read here; for this node's account, its root read here, for an `x` the
    /// root reaches by strongs (the account root reads as its account: a node paired later holds
    /// `x`'s boxes to the account from it, as its siblings do from the fires). A read of the pair
    /// and the home alone.
    fn holder_home_on(&self, t: &Tid, x: &Tid) -> Option<Tid> {
        osis_base::costs::count("certified: held on examined", 1);
        let home = self.holder_home(t)?;
        let named = x != t && self.core.ix.held.is_named(t, x) && self.core.first_admin(x) != Some(*t);
        (named && (home == *t || self.core.ix.closure.reaches_from(&home, x))).then_some(home)
    }

    /// Where holder `t`'s pieces go (`holder_home_on`): `t` when read here, else the account
    /// root of `t` when `t` is an account held here and its root is read here.
    fn holder_home(&self, t: &Tid) -> Option<Tid> {
        let read = &self.core.certified.read;
        if read.contains(t) {
            return Some(*t);
        }
        let d = self.core.accounts.get(t)?.root;
        (read.contains(&d) && self.core.account_of_root(&d) == Some(*t)).then_some(d)
    }

    /// Piece `p`'s certificates.
    fn piece(&mut self, p: &Piece) -> Option<Arc<Certs>> {
        Some(Arc::new(match p {
            Piece::Own(t) => self.own_piece(t),
            Piece::Chain(a, x) => self.chain_piece(a, x),
            Piece::Holder(t, x) => self.holder_piece(t, x),
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
        f.quiet.holds(f.read.idle() && f.authored.idle() && f.held_on.idle() && f.pieces.idle()) && self.rows_quiet()
    }

    fn follow_with(&mut self, f: &mut Followers) -> Result<bool> {
        self.core.certified.wrote = false;
        if f.feeds.is_none() {
            f.feeds = Some(self.core.ix.chains_on.feed());
            let all: Vec<Tid> = self.core.ix.chains_on.keys().copied().collect();
            for x in all {
                f.authored.want(x);
            }
        }
        // the pairs named from here on; the read things' pairs before, as each comes to be read
        let named = match f.pairs_feed.as_mut() {
            Some(feed) => feed.added(),
            None => {
                f.pairs_feed = Some(self.core.ix.held.pairs_feed());
                Vec::new()
            }
        };
        // the read things, per thing: each its own piece
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
                // its own pairs, and an account root's its account's
                let holders = std::iter::once(t).chain(self.core.account_of_root(&t));
                let pairs: Vec<(Tid, Tid)> = holders.flat_map(|h| self.core.ix.held.named_on(&h).map(move |x| (h, *x)).collect::<Vec<_>>()).collect();
                for k in pairs {
                    f.held_on.want(k);
                }
                continue;
            }
            f.read.unwant(&t);
            if was == Some(true) {
                // its pairs move with it (`holds_on` reads it) and go below
                self.core.certified.read.remove(&t);
                self.core.certified.unplace(Piece::Own(t), t, &mut f.pieces);
            }
        }
        for (t, x) in named {
            if self.holder_home(&t).is_some() {
                f.held_on.want((t, x));
            }
        }
        // the role changes naming each holder with a home (`holder_home_on`), per pair: its chain
        // to the target, with the target's boxes to it and sync record, under its home; a pair
        // that holds no more is followed again once named again (the feed)
        for (t, x) in f.held_on.due() {
            let Some((was, now)) = f.held_on.settle(&(t, x), || self.holder_home_on(&t, &x)) else { continue };
            if now.is_none() {
                f.held_on.unwant(&(t, x));
            }
            let on = self.core.certified.held_on.entry(t).or_default();
            if let Some(h) = was.flatten() {
                on.remove(&x);
                self.core.certified.unplace_chain(Piece::Holder(t, x), h, h, &mut f.pieces);
            }
            let on = self.core.certified.held_on.entry(t).or_default();
            if let Some(h) = now {
                on.insert(x);
                self.core.certified.place_chain(Piece::Holder(t, x), h, h, &mut f.pieces);
            }
            if self.core.certified.held_on.get(&t).is_some_and(|on| on.is_empty()) {
                self.core.certified.held_on.remove(&t);
            }
        }
        let authors = f.feeds.as_mut().map(|a| a.added()).unwrap_or_default();
        for x in authors {
            f.authored.want(x);
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
                if let Some(now) = now {
                    self.core.certified.reset(p, now, &mut f.pieces);
                }
            }
        }
        Ok(self.core.certified.wrote)
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
        // the records each read thing's sync IDs carry as certificates, as followed per record
        e.follow_cert_records().unwrap();
        assert!(e.core.cert_records.rows.keys().all(|t| things.contains(t)), "{step}: a certificate record row of a thing not read");
        for t in things.iter() {
            let got = e.core.cert_records.rows.get(t).map(|x| (**x).clone()).unwrap_or_default();
            assert_eq!(got, e.cert_records_whole(t).unwrap(), "{step}: certificate records of {t:?}");
        }
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

    /// Node 2's Y grants node 1's account X write; node 0's T1 and T2 (read at node 0) grant X
    /// write, Y holding no role on either: (world, X, Y, [T1, T2]).
    fn acting_world() -> (LocalPeer, Tid, Tid, [Tid; 2]) {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        let a0 = lp.peers[0].engine.create_account().unwrap().0;
        let a1 = lp.peers[1].engine.create_account().unwrap().0;
        let a2 = lp.peers[2].engine.create_account().unwrap().0;
        lp.sync_all().unwrap();
        let edge = ct::Edge { role: Role::Write, until: None, invite: None, floor: None };
        let new = |lp: &mut LocalPeer, i: usize, a: Tid| {
            let e = &mut lp.peers[i].engine;
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a);
            m.set(t, &acting_ak(), &Value::Int(0)).unwrap();
            e.commit(m).unwrap();
            lp.hold(t);
            t
        };
        let y = new(&mut lp, 2, a2.account);
        lp.peers[2].engine.grant(&y, &a1.account, &edge).unwrap();
        let ts = [new(&mut lp, 0, a0.account), new(&mut lp, 0, a0.account)];
        for t in &ts {
            // read at node 0: held by its node root
            lp.peers[0].engine.hold(osis_base::Strong(*t)).unwrap();
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
        let edge = |role| ct::Edge { role, until: None, invite: None, floor: None };
        let e = &mut lp.peers[0].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, a.account);
        let y = e.new_thing(&mut m, a.account);
        m.set(t, &acting_ak(), &Value::Int(0)).unwrap();
        m.set(y, &acting_ak(), &Value::Int(0)).unwrap();
        e.commit(m).unwrap();
        e.grant(&t, &w.account, &edge(Role::Write)).unwrap();
        let on_y = e.grant(&y, &c.account, &edge(Role::Read)).unwrap().commits;
        lp.hold(t);
        lp.hold(y);
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
        m.op(t, &ct::ROLES, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Key(Value::Weak(y))], op: osis_crdt::Op::Set(osis_schema::Codec::to_value(&ct::Edge { role: Role::Read, until: None, invite: None, floor: None })) }).unwrap();
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

    // spec/permissions.md §4 (Role changes travel), spec/sync-set.md §2 Cost: granting read team
    // actor X on one more thing places X's chain to it alone: the `held on` work of the last of n
    // grants is the same at n and 10n (X's chains as placed checked whole after).
    #[test]
    fn a_grant_to_a_read_actor_costs_one_chain_spec_permissions_4() {
        let work = |n: usize| {
            let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
            let a = lp.peers[0].engine.create_account().unwrap().0.account;
            let e = &mut lp.peers[0].engine;
            let edge = ct::Edge { role: Role::Read, until: None, invite: None, floor: None };
            let new = |e: &mut Engine| {
                let mut m = Mutation::new();
                let t = e.new_thing(&mut m, a);
                m.set(t, &acting_ak(), &Value::Int(0)).unwrap();
                e.commit(m).unwrap();
                t
            };
            let x = new(e);
            e.follow_certificates().unwrap();
            let ts: Vec<Tid> = (0..n).map(|_| new(e)).collect();
            let mut costs = (0, 0);
            for (i, t) in ts.iter().enumerate() {
                osis_base::costs::take();
                e.grant(t, &x, &edge).unwrap();
                e.follow_certificates().unwrap();
                let c: u64 = osis_base::costs::take().into_iter().filter(|(k, _, _)| k.starts_with("certified: held on")).map(|(_, _, c)| c).sum();
                costs.0 += c;
                if i + 1 == n {
                    costs.1 = c;
                }
            }
            assert_eq!(e.core.certified.held_on.get(&x).cloned().unwrap_or_default(), ts.iter().copied().collect::<BTreeSet<Tid>>(), "X's chains as placed");
            check(e, "granted");
            costs
        };
        let (small, large) = (work(4), work(40));
        eprintln!("held-on work over n grants and of the last, at n and 10n: {small:?} {large:?}");
        assert_eq!(small.1, large.1, "the last grant's work");
    }
}
