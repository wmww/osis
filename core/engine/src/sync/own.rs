//! This node's own commits per read sync ID (spec/sync-status.md §2, `Engine::own_commits`),
//! kept as rows moved by what changed: each (sync ID, commit) candidate is followed alone
//! (`Effects`), new candidates come from the commits added (`Feed`) and from things entering the
//! sync ID's closure, so a pass costs what moved, never every own commit again.

use crate::Engine;
use crate::error::Result;
use osis_base::memo::{Effects, Feed, Quiet, Stamped, Unrecorded};
use osis_base::{CommitId, SyncId, Tid};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What decides a sync ID's candidates: its read thing's closure and the authors written as.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Scope {
    closure: Arc<BTreeSet<Tid>>,
    authors: BTreeSet<Tid>,
}

/// The own commits of each sync ID asked (`own_commits`). Bounded by the candidates: an own
/// commit on a thing of a followed sync ID's closure, or a self-removal waiting; a sync ID read
/// here no more takes its rows with it.
#[derive(Clone)]
pub(crate) struct OwnCommits {
    /// Per followed sync ID, its scope (`None`: not read here).
    scope: Effects<SyncId, Option<Scope>>,
    /// Per candidate, whether it is an own commit with a body under the sync ID.
    pairs: Effects<(SyncId, CommitId), bool>,
    /// The candidates of each followed sync ID, and the scope they were found in.
    candidates: BTreeMap<SyncId, (Option<Scope>, BTreeSet<CommitId>)>,
    /// Commits held and self-removals waiting from now on; `None` until the first follow.
    feeds: Option<(Feed<CommitId>, Feed<CommitId>)>,
    /// The rows: per followed sync ID, its own commits (read whole).
    rows: Stamped<SyncId, Arc<BTreeSet<CommitId>>>,
    /// The follow's fixed point.
    quiet: Quiet,
}

impl Default for OwnCommits {
    fn default() -> Self {
        OwnCommits { scope: Effects::new("own: scope"), pairs: Effects::new("own: commits"), candidates: BTreeMap::new(), feeds: None, rows: Stamped::default(), quiet: Quiet::default() }
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
        let mut row = self.rows.get(s).cloned().unwrap_or_default();
        let moved = if own { Arc::make_mut(&mut row).insert(*c) } else { Arc::make_mut(&mut row).remove(c) };
        if moved {
            self.rows.insert(*s, row);
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
        }
        self.rows.remove(s);
    }

}

impl Engine {
    /// What is kept per sync ID asked (tests: what unsyncing leaves): sync IDs whose own
    /// commits are kept, own-commit candidates followed, sync IDs whose pass want is kept.
    #[doc(hidden)]
    pub fn kept_per_sync_id(&self) -> (usize, usize, usize) {
        let o = &self.core.own_commits;
        (o.candidates.len(), o.candidates.values().map(|x| x.1.len()).sum(), self.core.pass_wanted.len())
    }

    /// `s`'s scope: its read thing's closure and the authors this node writes as (its account,
    /// itself, the link key of a link it follows: a join, spec/permissions.md §7).
    fn own_scope(&mut self, s: &SyncId) -> Result<Option<Scope>> {
        let Some(t) = self.read_thing(s)? else { return Ok(None) };
        let links = self.core.followed_links.all().values().map(|(_, l)| *l);
        let authors = self.core.me().into_iter().chain([self.core.id.tid()]).chain(links).collect();
        Ok(Some(Scope { closure: self.closure(&t), authors }))
    }

    /// Whether `c` is an own commit with a body under `s` (spec/sync-status.md §2): written here
    /// on a thing of `s`'s closure by one of its authors, or a self-removal sync waits on
    /// (`waiting_removals`, a sibling's among them), and with a body under `s`.
    fn own_under(&mut self, s: &SyncId, c: &CommitId) -> Result<bool> {
        let Some(t) = self.read_thing(s)? else { return Ok(false) };
        let ctx = self.body_ctx(&t);
        let waits = self.core.ix.held_wait.contains(c);
        // an author asked per key: one link followed or let go moves only its key's commits
        let own = waits || {
            let core = &self.core;
            core.ix.commits.get(c).is_some_and(|m| {
                let a = &m.view.author;
                m.origin == crate::events::Origin::Local && (core.me() == Some(*a) || core.id.tid() == *a || core.followed_links.is_key(a)) && m.view.aspects.iter().any(|x| ctx.closure.contains(&x.tid))
            })
        };
        Ok(own && !self.commit_bodies_under(&ctx, c)?.is_empty())
    }

    /// Brings the own commits of each followed sync ID up to date: work in proportion to the
    /// commits added, the things entering a closure and the candidates whose reads moved.
    pub(crate) fn follow_own(&mut self) -> Result<()> {
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
        // scopes first: a thing entering a closure brings its own commits
        for s in o.scope.due() {
            let Some((_, now)) = o.scope.try_settle(&s, || self.own_scope(&s))? else { continue };
            let Some(now) = now else {
                // read here no more: nothing of it is kept
                o.unfollow(&s);
                continue;
            };
            let was = o.candidates.get(&s).and_then(|x| x.0.clone()).filter(|w| w.authors == now.authors);
            let new: Vec<Tid> = now.closure.iter().filter(|x| !was.as_ref().is_some_and(|w| w.closure.contains(*x))).copied().collect();
            let ix = &self.core.ix;
            let found: Vec<CommitId> = new.iter().flat_map(|x| now.authors.iter().flat_map(move |a| ix.by_thing.get(&(*x, *a)).into_iter().flatten().copied())).chain(was.is_none().then(|| ix.held_wait.iter().copied()).into_iter().flatten()).collect();
            o.candidates.entry(s).or_default().0 = Some(now);
            for c in found {
                o.want(s, c);
            }
        }
        // commits held and removals waiting since: candidates of each sync ID whose closure
        // holds one of their things
        let (held, waits) = o.feeds.as_mut().map(|(h, w)| (h.added(), w.added())).unwrap_or_default();
        if !held.is_empty() || !waits.is_empty() {
            let ids: Vec<(SyncId, Arc<BTreeSet<Tid>>)> = o.candidates.iter().filter_map(|(s, (sc, _))| sc.as_ref().map(|sc| (*s, sc.closure.clone()))).collect();
            for c in held {
                let things: Vec<Tid> = self.core.ix.commits.get(&c).map(|m| m.view.aspects.iter().map(|a| a.tid).collect()).unwrap_or_default();
                for (s, closure) in &ids {
                    if things.iter().any(|x| closure.contains(x)) {
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
    /// (spec/sync-status.md §2, `own_under`): a row per sync ID, from its first ask, moved by
    /// `follow_own` (here and at `Engine::follow`).
    pub fn own_commits(&mut self, s: &SyncId) -> Result<Arc<BTreeSet<CommitId>>> {
        {
            let o = &mut self.core.own_commits;
            if o.feeds.is_none() {
                o.feeds = Some((self.core.ix.commits.feed(), self.core.ix.held_wait.feed()));
            }
            if !o.candidates.contains_key(s) {
                o.candidates.insert(*s, (None, BTreeSet::new()));
                o.scope.want(*s);
            }
        }
        self.follow_own()?;
        Ok(self.core.own_commits.rows.get(s).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{Ak, Role, Value, WallMs};
    use osis_schema::core_types as ct;

    // spec/sync-status.md §2 (Held elsewhere: a commit a node made, or by a key actor it holds,
    // a followed link's key among them): following a link and letting it go judges again only the commits its key
    // could have written, not every own commit, counted at n and 10n own commits under home.
    #[test]
    fn a_link_followed_and_let_go_judges_no_other_own_commit_spec_sync_status_2() {
        let judged = |n: i64| -> u64 {
            let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
            let a0 = lp.peers[0].engine.create_account().unwrap().0;
            let a1 = lp.peers[1].engine.create_account().unwrap().0;
            let e = &mut lp.peers[0].engine;
            let home = e.home_sync_id(&a0.devices).unwrap().unwrap();
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, a0.devices);
            m.op(a0.devices, &ct::GROUP, osis_crdt::PathOp { path: vec![osis_crdt::PathSeg::Field(0)], op: osis_crdt::Op::Add(Value::Tid(t)) }).unwrap();
            e.commit(m).unwrap();
            for i in 0..n {
                let mut m = Mutation::new();
                m.set(t, &Ak::new("x:a.0").unwrap(), &Value::Int(i)).unwrap();
                e.commit(m).unwrap();
            }
            assert!(e.own_commits(&home).unwrap().len() as i64 > n, "the writes are own commits under home");
            let e1 = &mut lp.peers[1].engine;
            let mut m = Mutation::new();
            let x = e1.new_thing(&mut m, a1.account);
            e1.commit(m).unwrap();
            let spec = crate::flows::LinkSpec { target: x, role: Role::Read, until: None, peers: Vec::new(), single_use: false };
            let link = e1.create_link(&a1.account, &spec).unwrap().0;
            let e = &mut lp.peers[0].engine;
            e.follow().unwrap();
            osis_base::costs::take();
            e.follow_link(&link).unwrap();
            e.follow().unwrap();
            e.unfollow_link(&link.k);
            e.follow().unwrap();
            osis_base::costs::take().iter().filter(|x| x.0 == "own: commits").map(|x| x.2).sum()
        };
        assert_eq!(judged(3), judged(30), "own commits judged again at n and 10n own commits");
    }
}
