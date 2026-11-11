//! The lifetime judgment's trigger (issues/thing-lifetimes.md, The release, When;
//! notes/engine-lifetimes.md): a thing is judged once every label this node syncs whose closure
//! holds a thing its walk read is heard out (`heard`); a thing under no label at once. Offline,
//! a hosted label is not heard out, so nothing under it is released.

use super::SyncEngine;
use osis_base::Tid;
use std::collections::{BTreeMap, BTreeSet};

impl SyncEngine {
    /// Judges thing lifetimes (`Engine::judge_lifetimes`) when work is queued, and the held
    /// things again once a label is newly heard out since the last judgment; the engine writes
    /// the release request as the node's account. Nothing due: two store seeks. Returns whether a
    /// request was written (it goes up with the next step's passes).
    pub(crate) fn judge_lifetimes(&mut self) -> bool {
        match self.judge_lifetimes_due() {
            Ok(wrote) => wrote,
            Err(e) => {
                self.diag(format!("lifetimes: {e}"));
                false
            }
        }
    }

    fn judge_lifetimes_due(&mut self) -> crate::error::Result<bool> {
        let (due, held) = self.engine.lifetimes_due()?;
        if !due && !held {
            return Ok(false);
        }
        // per group, whether every label of it is heard out; a hostless label has nothing to hear
        let mut groups: BTreeMap<Tid, bool> = BTreeMap::new();
        let mut heard = BTreeSet::new();
        for (g, gl) in self.labels() {
            if gl.replaced {
                continue;
            }
            let out = super::peers::hostless(&gl.hosts) || self.heard(&gl.id);
            if out {
                heard.insert(gl.id);
            }
            *groups.entry(g).or_insert(true) &= out;
        }
        let again = held && self.lifetimes_heard.as_ref().is_none_or(|last| !heard.is_subset(last));
        if !due && !again {
            return Ok(false);
        }
        let judged = self.engine.judge_lifetimes(&|g| groups.get(g).copied().unwrap_or(true), again)?;
        self.lifetimes_heard = Some(heard);
        Ok(judged.request.is_some())
    }
}
