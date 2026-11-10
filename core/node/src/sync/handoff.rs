//! Groups handed off to another node (`set_handed_off`): their calls go there (osis
//! `group_source`), so this node holds them without syncing them. What is stored of them stays,
//! no longer updated.

use super::{Action, SyncEngine};
use osis_base::{LabelId, Tid};
use std::collections::BTreeSet;

impl SyncEngine {
    /// Hands `group` off (`on`), or takes it back: a handed-off group's labels are not synced
    /// here (no download, no pass, nothing placed there).
    pub fn set_handed_off(&mut self, group: Tid, on: bool) -> Vec<Action> {
        self.state.set_handed_off(group, on);
        self.synced.key.0 = u64::MAX;
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

    /// The groups handed off (`set_handed_off`).
    pub fn handed_off(&self) -> &BTreeSet<Tid> {
        &self.state.handed_off
    }

    /// The handed-off groups holding any of `things` as far as this node knows: the group itself,
    /// or a thing its known closure holds (the rest of its closure is not here).
    pub fn handed_off_groups(&mut self, things: &BTreeSet<Tid>) -> Vec<Tid> {
        let gs: Vec<Tid> = self.state.handed_off.iter().copied().collect();
        gs.into_iter().filter(|g| things.contains(g) || self.engine.closure(g).iter().any(|t| things.contains(t))).collect()
    }
}
