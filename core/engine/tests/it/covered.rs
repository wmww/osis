//! Covered drops over the engine alone (spec/sync-compaction.md §1, spec/commits.md §5): every
//! durable aspect's held content snapshots judge each body of it, its own replaces their
//! author's older commits. The order harness runs it where a node would drop.

use osis_engine::Result;
use osis_base::{Ak, CommitId, Tid};
use osis_commit::Kind;
use std::collections::BTreeSet;

/// Drops every body of `e` a held cover lets it drop now; returns them. A body not judged
/// droppable yet (not established covered, before its keep bound) is judged again at the next
/// call.
pub fn drop_all_covered(e: &mut osis_engine::Engine) -> Result<Vec<CommitId>> {
    let aspects: Vec<(Tid, Ak)> = e.core.ix.by_aspect.keys().filter(|k| !k.1.ephemeral()).cloned().collect();
    let mut pass = CoverPass { engine: e, covered_judged: BTreeSet::new(), dropped: Vec::new() };
    for (t, a) in aspects {
        let covers: Vec<(CommitId, bool)> = pass.engine.core.durable_on(&(t, a.clone())).filter_map(|s| {
            let snapshot = pass.engine.core.ix.commits.get(&s).is_some_and(|m| m.header.kind == Kind::ContentSnapshot);
            (snapshot || pass.engine.own_replace(&s, &t, &a)).then_some((s, snapshot))
        }).collect();
        for (s, snapshot) in covers {
            let only = (!snapshot).then(|| pass.engine.own_held_before(&s, &t, &a));
            if only.as_ref().is_some_and(|o| o.is_empty()) {
                continue;
            }
            pass.drop_covered(&t, &a, &s, only.as_deref())?;
        }
    }
    Ok(pass.dropped)
}

fn is_snapshot(k: Kind) -> bool {
    matches!(k, Kind::ContentSnapshot | Kind::RoleSnapshot)
}

struct CoverPass<'a> {
    engine: &'a mut osis_engine::Engine,
    /// Settled pairs: (snapshot, body, thing, aspect) judged kept while both are held.
    covered_judged: BTreeSet<(CommitId, CommitId, Tid, Ak)>,
    dropped: Vec<CommitId>,
}

impl CoverPass<'_> {
    /// Drops the bodies of `(t, ak)` that snapshot or own replace `s` covers whose keep-at-least
    /// bound has passed (only those `only` names, when given).
    fn drop_covered(&mut self, t: &Tid, ak: &Ak, s: &CommitId, only: Option<&[CommitId]>) -> Result<()> {
        let s = *s;
        let now = self.engine.now();
        let held: Vec<CommitId> = match only {
            Some(o) => o.to_vec(),
            None => self.engine.core.durable_on(&(*t, ak.clone())).collect(),
        };
        for c in held {
            if c == s {
                continue;
            }
            // a settled judgment holds while both bodies are held
            let k = (s, c, *t, ak.clone());
            let both = self.engine.body_not_dropped(&s, t, ak) && self.engine.droppable_if_covered(&c, t, ak);
            if self.covered_judged.contains(&k) {
                if both {
                    continue;
                }
                self.covered_judged.remove(&k);
            }
            if !self.engine.droppable_if_covered(&c, t, ak) {
                continue;
            }
            let Some(h) = self.engine.header(&c) else { continue };
            // a live delta this node wrote drops only under its own covers (spec/sync-compaction.md
            // §1 own bodies)
            if self.engine.own_kept_under(&s, &c, t, ak)? {
                continue;
            }
            let own = self.engine.own_replace(&s, t, ak);
            if own && self.engine.covered(&s, &c, t, ak)? != Some(true) {
                continue;
            }
            // out of history any held valid writer's cover drops it (spec/commits.md §5)
            let due = self.engine.drop_from(&c, t, ak)?;
            // kept for good while live (spec/commits.md §5 Kept while live)
            if due >= osis_commit::FOREVER {
                self.engine.settle_kept(&c, t, ak);
                continue;
            }
            if due > now.0 {
                continue;
            }
            // spec/commits.md §5 Own replaces: a commit goes only whole
            if own && !self.own_covers_every_part(&c, &h)?.is_some_and(|due| due <= now.0) {
                continue;
            }
            match self.engine.covered(&s, &c, t, ak)? {
                None => continue,
                Some(false) => {
                    if (h.expires.is_none() || !self.engine.body_not_dropped(&c, t, ak)) && self.engine.header(&s).is_some_and(|x| is_snapshot(x.kind)) {
                        self.covered_judged.insert(k);
                    }
                    continue;
                }
                Some(true) => {}
            }
            // covered-equal snapshots (equal `ts`): only the higher commit ID goes
            if is_snapshot(h.kind) && c < s && self.engine.covered(&c, &s, t, ak)? == Some(true) {
                self.covered_judged.insert(k);
                continue;
            }
            self.engine.drop_body(&c, t, ak)?;
            self.dropped.push(c);
        }
        Ok(())
    }

    /// Whether every part of `c` still held may drop under own replaces (spec/commits.md §5):
    /// covered by its author's own replaces. `Some`: from when all of them may.
    fn own_covers_every_part(&mut self, c: &CommitId, h: &osis_commit::Header) -> Result<Option<u64>> {
        let mut due = 0;
        for (ai, a) in h.aspects.iter().enumerate() {
            if !self.engine.part_held(c, ai) {
                continue;
            }
            let covers = self.engine.own_covers(c, &a.tid, &a.ak);
            let mut covered = false;
            for q in &covers {
                covered |= self.engine.covered(q, c, &a.tid, &a.ak)? == Some(true);
            }
            if !covered {
                return Ok(None);
            }
            due = due.max(self.engine.drop_from(c, &a.tid, &a.ak)?);
        }
        Ok(Some(due))
    }
}
