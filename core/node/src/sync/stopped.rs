//! Groups this node does not sync (`set_stopped`): held, their labels left alone. What is stored
//! of them stays, no longer updated.

use super::{Action, SyncEngine};
use osis_base::{LabelId, Tid};
use std::collections::BTreeSet;

impl SyncEngine {
    /// Stops syncing `group` here (`on`), or syncs it again: a stopped group's labels are not
    /// synced (no download, no pass, nothing placed there). What is already stored stays, no
    /// longer updated.
    pub fn set_stopped(&mut self, group: Tid, on: bool) -> Vec<Action> {
        self.state.set_stopped(group, on);
        self.synced.key.0 = u64::MAX;
        self.engine.core.stopped = self.state.stopped.clone();
        self.served_cache = None;
        if on {
            // its labels' sessions stop here: nothing more runs on them
            let labels: BTreeSet<LabelId> = self.engine.labels_of(&group).iter().map(|l| l.id).collect();
            for (id, c) in self.conns.iter_mut() {
                for l in c.labels.keys().filter(|l| labels.contains(l)) {
                    self.unsubscribe.insert((*id, *l));
                }
                c.labels.retain(|l, _| !labels.contains(l));
            }
        }
        self.handle(super::Event::Local)
    }

    /// Groups this node does not sync (`set_stopped`).
    pub fn stopped(&self) -> &BTreeSet<Tid> {
        &self.state.stopped
    }

    /// The stopped groups holding any of `things` as far as this node knows: the group itself,
    /// or a thing its known closure holds (the rest of its closure is not here).
    pub fn stopped_groups(&mut self, things: &BTreeSet<Tid>) -> Vec<Tid> {
        let gs: Vec<Tid> = self.state.stopped.iter().copied().collect();
        gs.into_iter().filter(|g| things.contains(g) || self.engine.closure(g).iter().any(|t| things.contains(t))).collect()
    }
}
