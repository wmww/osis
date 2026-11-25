//! This node's own commits per read sync ID (spec/sync-status.md §2, `Engine::own_commits`),
//! kept as rows moved by what changed: each (sync ID, commit) candidate is followed alone
//! (`Effects`), new candidates come from the commits added and from things entering the sync
//! ID's sync unit (`Feed`s), so a pass costs what moved, never every own commit again. The rows
//! are (sync ID, commit) pairs with a feed of those that come and go (`Engine::own_feed`), so a
//! reader follows one more own commit as one pair, never the sync ID's set handed over whole.

use crate::Engine;
use crate::error::Result;
use osis_base::memo::{Effects, Feed, Quiet, Removals, StampedSet, Unrecorded};
use osis_base::{CommitId, SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What decides a sync ID's candidates: its read things (whose sync units' members come by
/// `Closure::member_feed`) and the authors written as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope {
    things: BTreeSet<Tid>,
    authors: BTreeSet<Tid>,
}

/// Cursors over the (sync ID, own commit) pairs that come (`Feed`) and go (`Removals`).
pub type OwnFeed = (Feed<(SyncId, CommitId)>, Removals<(SyncId, CommitId)>);

/// The commits held, the self-removals waiting and the sync unit members, each from now on.
type Feeds = (Feed<CommitId>, Feed<CommitId>, Feed<(crate::sync::units::Ctx, Tid)>);

/// The own commits of each sync ID asked (`own_commits`). Bounded by the candidates: an own
/// commit on a thing of a followed sync ID's sync unit, or a self-removal waiting; a sync ID read
/// here no more takes its rows with it.
#[derive(Clone)]
pub(crate) struct OwnCommits {
    /// Per followed sync ID, its scope (`None`: not read here).
    scope: Effects<SyncId, Option<Scope>>,
    /// Per candidate, whether it is an own commit with a body under the sync ID.
    pairs: Effects<(SyncId, CommitId), bool>,
    /// The candidates of each followed sync ID, and the scope they were found in.
    candidates: BTreeMap<SyncId, (Option<Scope>, BTreeSet<CommitId>)>,
    /// Commits held, self-removals waiting and sync unit members from now on; `None` until the
    /// first follow.
    feeds: Option<Feeds>,
    /// The rows: each followed sync ID with each of its own commits.
    rows: StampedSet<(SyncId, CommitId)>,
    /// The follow's fixed point.
    quiet: Quiet,
}

impl Default for OwnCommits {
    fn default() -> Self {
        OwnCommits { scope: Effects::new("own: scope"), pairs: Effects::new("own: commits"), candidates: BTreeMap::new(), feeds: None, rows: StampedSet::default(), quiet: Quiet::default() }
    }
}

impl OwnCommits {
    fn want(&mut self, s: SyncId, c: CommitId) {
        if let Some((_, cs)) = self.candidates.get_mut(&s)
            && cs.insert(c)
        {
            self.pairs.want((s, c));
        }
    }

    fn set(&mut self, s: &SyncId, c: &CommitId, own: bool) {
        let _u = Unrecorded::start();
        if own {
            self.rows.insert((*s, *c));
        } else {
            self.rows.remove(&(*s, *c));
        }
    }

    /// Stops following `s` (read here no more, `Engine::forget_read`): nothing of it stays.
    pub(crate) fn unfollow(&mut self, s: &SyncId) {
        self.drop_sync_id(s);
        self.scope.unwant(s);
    }

    /// Stops following `s`'s candidates: they and its row go.
    fn drop_sync_id(&mut self, s: &SyncId) {
        for c in self.candidates.remove(s).map(|x| x.1).unwrap_or_default() {
            self.pairs.unwant(&(*s, c));
            self.rows.remove(&(*s, c));
        }
    }

}

impl Engine {

    /// `s`'s scope: the sync units of the things reading it and the authors this node writes as
    /// (its account, itself, the link key of a link it follows: a join, spec/permissions.md §7).
    fn own_scope(&mut self, s: &SyncId) -> Result<Option<Scope>> {
        let things = self.read_things_of(s)?;
        if things.is_empty() {
            return Ok(None);
        }
        let links = self.core.followed_links.all().values().filter_map(|(_, l)| *l);
        let authors = std::iter::once(self.core.me()).chain(links).collect();
        Ok(Some(Scope { things: things.into_iter().collect(), authors }))
    }

    /// Whether `c` is an own commit with a body under `s` (spec/sync-status.md §2): written here
    /// on a thing of `s`'s sync unit by one of its authors, or a self-removal sync waits on
    /// (`waiting_removals`, a sibling's among them), and with a body under `s`.
    fn own_under(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        let waits = self.core.ix.held_wait.contains(c);
        for t in self.read_things_of(s)? {
            let ctx = self.body_ctx(&t);
            // an author asked per key: one link followed or let go moves only its key's commits
            let own = waits || {
                let core = &self.core;
                core.ix.commits.get(c).is_some_and(|m| {
                    let a = &m.view.signer;
                    m.origin == crate::events::Origin::Local && (core.me() == *a || core.followed_links.is_key(a)) && m.view.aspects.iter().any(|x| ctx.holds(core, &x.tid))
                })
            };
            if own && !self.commit_bodies_under(&ctx, c)?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The commits on `x` by `authors`.
    fn authored_on(&self, x: &Tid, authors: &BTreeSet<Tid>) -> Vec<CommitId> {
        authors.iter().flat_map(|a| self.core.ix.by_thing.get(&(*x, *a)).into_iter().flatten().copied()).collect()
    }

    /// Brings the own commits of each followed sync ID up to date: work in proportion to the
    /// commits added, the things entering a sync unit and the candidates whose reads moved.
    pub fn follow_own(&mut self) -> Result<()> {
        let o = &self.core.own_commits;
        if o.quiet.holds(o.scope.idle() && o.pairs.idle()) {
            return Ok(());
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let mut o = std::mem::take(&mut self.core.own_commits);
        let r = self.follow_own_in(&mut o);
        o.quiet.ended(from, r.is_ok());
        self.core.own_commits = o;
        r
    }

    fn follow_own_in(&mut self, o: &mut OwnCommits) -> Result<()> {
        // things entering a sync unit since: their commits by the authors of each sync ID of it
        // (before the scopes: a scope settled now finds its unit whole)
        let entered = o.feeds.as_mut().map(|f| f.2.added()).unwrap_or_default();
        for (ctx, x) in entered {
            let crate::sync::units::Ctx::Read(u) = ctx else { continue };
            let ids: Vec<(SyncId, BTreeSet<Tid>)> = o.candidates.iter().filter_map(|(s, (sc, _))| sc.as_ref().filter(|sc| sc.things.contains(&u)).map(|sc| (*s, sc.authors.clone()))).collect();
            for (s, authors) in ids {
                for c in self.authored_on(&x, &authors) {
                    o.want(s, c);
                }
            }
        }
        // scopes: a sync ID followed afresh, or written as other authors, finds its candidates
        // in its sync unit whole
        for s in o.scope.due() {
            let Some((_, now)) = o.scope.try_settle(&s, || self.own_scope(&s))? else { continue };
            let Some(now) = now else {
                // read here no more: nothing of it is kept
                o.unfollow(&s);
                continue;
            };
            let was = o.candidates.get(&s).and_then(|x| x.0.clone());
            let mut found: Vec<CommitId> = Vec::new();
            if was.as_ref() != Some(&now) {
                for t in &now.things {
                    for x in self.sync_unit(t).iter() {
                        found.extend(self.authored_on(x, &now.authors));
                    }
                }
            }
            if was.is_none() {
                found.extend(self.core.ix.held_wait.iter().copied());
            }
            o.candidates.entry(s).or_default().0 = Some(now);
            for c in found {
                o.want(s, c);
            }
        }
        // commits held and removals waiting since: candidates of each sync ID whose sync unit
        // holds one of their things
        let (held, waits) = o.feeds.as_mut().map(|(h, w, _)| (h.added(), w.added())).unwrap_or_default();
        if !held.is_empty() || !waits.is_empty() {
            let ids: Vec<(SyncId, BTreeSet<Tid>)> = o.candidates.iter().filter_map(|(s, (sc, _))| sc.as_ref().map(|sc| (*s, sc.things.clone()))).collect();
            for c in held {
                let things: Vec<Tid> = self.core.ix.commits.get(&c).map(|m| m.view.aspects.iter().map(|a| a.tid).collect()).unwrap_or_default();
                for (s, us) in &ids {
                    if things.iter().any(|x| us.iter().any(|u| self.core.ix.closure.unit_holds(u, x))) {
                        o.want(*s, c);
                    }
                }
            }
            for c in waits {
                for (s, _) in &ids {
                    o.want(*s, c);
                }
            }
        }
        for (s, c) in o.pairs.due() {
            let Some((was, now)) = o.pairs.try_settle(&(s, c), || self.own_under(&s, &c))? else { continue };
            if now || was.is_some() {
                o.set(&s, &c, now);
            }
            // gone: a copy held again comes through the feed
            if !now && !self.core.ix.commits.contains_key(&c) && !self.core.ix.held_wait.contains(&c) {
                o.pairs.unwant(&(s, c));
                if let Some((_, cs)) = o.candidates.get_mut(&s) {
                    cs.remove(&c);
                }
            }
        }
        Ok(())
    }

    /// This node's commits and the own self-removals sync waits on with a body under `s`
    /// (spec/sync-status.md §2, `own_under`): its pairs, followed from its first ask, moved by
    /// `follow_own` (here and at `Engine::follow`).
    pub fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        {
            let o = &mut self.core.own_commits;
            if o.feeds.is_none() {
                o.feeds = Some((self.core.ix.commits.feed(), self.core.ix.held_wait.feed(), self.core.ix.closure.member_feed()));
            }
            if !o.candidates.contains_key(s) {
                o.candidates.insert(*s, (None, BTreeSet::new()));
                o.scope.want(*s);
            }
        }
        self.follow_own()?;
        let lo = (*s, CommitId([0; 32]));
        Ok(Arc::new(self.core.own_commits.rows.range(lo..=(*s, CommitId([0xff; 32]))).map(|x| x.1).collect()))
    }

    /// Whether `c` is among `own_commits(s)` as last followed: a read of that pair alone.
    pub fn own_has(&self, s: &SyncId, c: &CommitId) -> bool {
        self.core.own_commits.rows.contains(&(*s, *c))
    }

    /// Cursors over the (sync ID, own commit) pairs that come and go from now on (`own_commits`'
    /// rows, moved by `follow_own`): a reader follows each own commit by itself.
    pub fn own_feed(&self) -> OwnFeed {
        let r = &self.core.own_commits.rows;
        (r.feed(), r.removals())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    
    
    
    

}
