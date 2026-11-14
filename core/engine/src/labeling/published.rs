//! The labeled things each actor's home label publishes (spec/sync-ids.md §4, `published_under`),
//! kept per labeled thing (`Published`): each one's publisher is followed alone, so a thing
//! coming to be published moves its own row and the actor's whole set, never another thing's.
//! A body judgement asks per thing (`PublishedView::contains`); the walk of what a label carries
//! reads the actor's set whole (`PublishedView::iter`).

use crate::Engine;
use osis_base::Tid;
use osis_base::memo::{Effects, Feed, Reader, Stamped, StampedSet, Unrecorded};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Each labeled thing's publisher, followed, with the sets per actor it makes. Bounded by the
/// labeled things held: one key and at most one row each.
#[derive(Clone)]
pub(crate) struct Published {
    /// Per labeled thing (`Indexes::sync_recorded`), the actor publishing it.
    by: Effects<Tid, Option<Tid>>,
    /// Things labeled from now on; `None` until the first follow.
    feed: Option<Feed<Tid>>,
    /// Each followed thing's publisher, as placed.
    placed: BTreeMap<Tid, Tid>,
    /// Per actor, what it publishes (read whole).
    under: Stamped<Tid, Arc<BTreeSet<Tid>>>,
    /// (actor, thing) for each thing published, read per pair.
    pairs: StampedSet<(Tid, Tid)>,
}

impl Default for Published {
    fn default() -> Self {
        Published { by: Effects::new("published"), feed: None, placed: BTreeMap::new(), under: Stamped::default(), pairs: StampedSet::default() }
    }
}

/// What an actor's home label publishes, as a body judgement reads it (`BodyCtx::published`): per
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
    /// The actor whose home label publishes labeled thing `h` (spec/sync-ids.md §2, §4): the
    /// nearest labeled actor with secrets of its own up `h`'s record chain whose record edges up
    /// to it stand here (`Core::standing_chain`); an account has no label, so what is under it
    /// publishes under its devices actor's. `None` for a thing not labeled.
    pub(crate) fn publisher(&self, h: &Tid) -> Option<Tid> {
        let core = &self.core;
        if !core.ix.sync_recorded.contains(h) {
            return None;
        }
        let up = core.standing_chain(h).into_iter().skip(1).map(|a| core.accounts.get(&a).map_or(a, |x| x.devices)).find(|a| core.ix.sync_recorded.contains(a) && core.ix.own_keys.contains(a));
        up.filter(|a| a != h)
    }

    /// Brings `Published` up to date with what moved since the last call: work in proportion to
    /// the labeled things whose publisher's reads moved. Whether a set moved.
    pub(crate) fn follow_published(&mut self) -> bool {
        let _u = Unrecorded::start();
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
                // labeled again: the feed gives it
                p.by.unwant(&h);
            }
            moved = true;
            if let Some(a) = p.placed.remove(&h) {
                p.pairs.remove(&(a, h));
                let mut set = p.under.remove(&a).unwrap_or_default();
                Arc::make_mut(&mut set).remove(&h);
                if !set.is_empty() {
                    p.under.insert(a, set);
                }
            }
            if let Some(a) = now {
                p.placed.insert(h, a);
                p.pairs.insert((a, h));
                let mut set = p.under.remove(&a).unwrap_or_default();
                Arc::make_mut(&mut set).insert(h);
                p.under.insert(a, set);
            }
        }
        self.core.published = p;
        moved
    }

    /// Labeled groups whose nearest labeled record-chain actor is `g` (its home label publishes
    /// their `label.0`, spec/sync-ids.md §4). Empty unless `g` is an actor with secrets of its
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
