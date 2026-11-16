//! The things with a sync ID each actor's home sync ID publishes (spec/sync-ids.md §4, `published_under`),
//! kept per thing with a sync ID (`Published`): each one's publisher is followed alone, so a thing
//! coming to be published moves its own row and the actor's whole set, never another thing's.
//! A body judgement asks per thing (`PublishedView::contains`); the walk of what a sync ID carries
//! reads the actor's set whole (`PublishedView::iter`).

use crate::Engine;
use osis_base::Tid;
use osis_base::memo::{Effects, Feed, Quiet, Reader, Stamped, StampedSet, Unrecorded};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The publisher of each thing with a sync ID, followed, with the sets per actor it makes. Bounded by the
/// things with a sync ID held: one key and at most one row each.
#[derive(Clone)]
pub(crate) struct Published {
    /// Per thing with a sync ID (`Indexes::sync_recorded`), the actor publishing it.
    by: Effects<Tid, Option<Tid>>,
    /// Things given a sync ID from now on; `None` until the first follow.
    feed: Option<Feed<Tid>>,
    /// Each followed thing's publisher, as placed.
    placed: BTreeMap<Tid, Tid>,
    /// Per actor, what it publishes (read whole).
    under: Stamped<Tid, Arc<BTreeSet<Tid>>>,
    /// (actor, thing) for each thing published, read per pair.
    pairs: StampedSet<(Tid, Tid)>,
    /// The follow's fixed point.
    quiet: Quiet,
}

impl Default for Published {
    fn default() -> Self {
        Published { by: Effects::new("published"), feed: None, placed: BTreeMap::new(), under: Stamped::default(), pairs: StampedSet::default(), quiet: Quiet::default() }
    }
}

/// What an actor's home sync ID publishes, as a body judgement reads it (`BodyCtx::published`): per
/// thing asked (`contains`), whole when walked (`iter`).
pub struct PublishedView {
    actor: Tid,
    set: Arc<BTreeSet<Tid>>,
    pairs: Reader,
    under: Reader,
}

impl PublishedView {
    pub fn contains(&self, t: &Tid) -> bool {
        self.pairs.read(&(self.actor, *t));
        self.set.contains(t)
    }
    pub fn iter(&self) -> impl Iterator<Item = &Tid> {
        self.under.read(&self.actor);
        self.set.iter()
    }
}

impl Engine {
    /// The actor whose home sync ID publishes thing with a sync ID `h` (spec/sync-ids.md §2, §4): the
    /// nearest actor with a sync ID with secrets of its own up `h`'s record chain whose record edges up
    /// to it stand here (`Core::standing_chain`); an account has no sync ID, so what is under it
    /// publishes under its devices actor's. `None` for a thing without a sync ID.
    pub(crate) fn publisher(&self, h: &Tid) -> Option<Tid> {
        let core = &self.core;
        if !core.ix.sync_recorded.contains(h) {
            return None;
        }
        let up = core.standing_chain(h).into_iter().skip(1).map(|a| core.accounts.get(&a).map_or(a, |x| x.devices)).find(|a| core.ix.sync_recorded.contains(a) && core.ix.own_keys.contains(a));
        up.filter(|a| a != h)
    }

    /// Brings `Published` up to date with what moved since the last call: work in proportion to
    /// the things with a sync ID whose publisher's reads moved. Whether a set moved.
    pub(crate) fn follow_published(&mut self) -> bool {
        let p = &self.core.published;
        if p.quiet.holds(p.by.idle()) {
            return false;
        }
        let _u = Unrecorded::start();
        let from = Quiet::begin();
        let mut p = std::mem::take(&mut self.core.published);
        if p.feed.is_none() {
            p.feed = Some(self.core.ix.sync_recorded.feed());
            for h in self.core.ix.sync_recorded.iter() {
                p.by.want(*h);
            }
        }
        for h in p.feed.as_mut().map(Feed::added).unwrap_or_default() {
            p.by.want(h);
        }
        let mut moved = false;
        for h in p.by.due() {
            let Some((_, now)) = p.by.settle(&h, || self.publisher(&h)) else { continue };
            if !self.core.ix.sync_recorded.contains(&h) {
                // given a sync ID again: the feed gives it
                p.by.unwant(&h);
            }
            moved = true;
            if let Some(a) = p.placed.remove(&h) {
                p.pairs.remove(&(a, h));
                p.under.update(a, |set| {
                    let mut set = set.unwrap_or_default();
                    Arc::make_mut(&mut set).remove(&h);
                    (!set.is_empty()).then_some(set)
                });
            }
            if let Some(a) = now {
                p.placed.insert(h, a);
                p.pairs.insert((a, h));
                p.under.update(a, |set| {
                    let mut set = set.unwrap_or_default();
                    Arc::make_mut(&mut set).insert(h);
                    Some(set)
                });
            }
        }
        p.quiet.ended(from, true);
        self.core.published = p;
        moved
    }

    /// Groups with a sync ID whose nearest record-chain actor with a sync ID is `g` (its home sync ID publishes
    /// their `sync.0`, spec/sync-ids.md §4). Empty unless `g` is an actor with secrets of its
    /// own. A read of `g`'s whole set.
    pub fn published_under(&mut self, g: &Tid) -> Arc<BTreeSet<Tid>> {
        self.follow_published();
        self.core.published.under.get(g).cloned().unwrap_or_default()
    }

    /// `published_under` as a body judgement reads it (`PublishedView`).
    pub(crate) fn published_view(&mut self, g: &Tid) -> PublishedView {
        self.follow_published();
        let p = &self.core.published;
        // the view reads per thing or whole as it is used
        let set = {
            let _u = Unrecorded::start();
            p.under.get(g).cloned().unwrap_or_default()
        };
        PublishedView { actor: *g, set, pairs: p.pairs.reader(), under: p.under.reader() }
    }
}
