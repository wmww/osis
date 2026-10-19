//! Carrying out what membership flows produce (`flows::Done`, `flows::Delivery`) and the sync
//! state flows ask about (`flows::SyncState`): inbox blobs deposited at the inbox's servers,
//! direct commits handed to the app's pairing channel, placements before any other upload,
//! certificate copies under a home label, deposits; commits that travel by inbox only are never
//! placed under a label (spec/permissions.md §3, re-seal).

use super::local::Outgoing;
use super::{Action, SyncEngine};
use crate::error::Result;
use crate::flows::{Delivery, Done, SyncState};
use crate::local_peer::Package;
use osis_core::{CommitId, LabelId, Tid};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

impl SyncEngine {
    /// Carries out a flow's result (call it with every `Done` a flow returns).
    pub fn carry_out(&mut self, done: Done) -> Result<Vec<Action>> {
        if done.drop_lost {
            for d in &done.deliveries {
                if let Delivery::First { under, .. } = d {
                    self.leaving.extend(under.iter().copied());
                }
            }
            if self.leaving.is_empty() {
                self.engine.drop_lost_secrets()?;
            }
        }
        self.take_done(done)?;
        // placements wait for a pass
        for c in self.conns.values_mut() {
            for l in c.labels.values_mut() {
                l.dirty = true;
            }
        }
        Ok(self.handle(super::Event::Local))
    }

    /// Records a flow's deliveries; the next step sends them.
    pub(crate) fn take_done(&mut self, done: Done) -> Result<()> {
        for c in done.inbox_only {
            self.state.set_inbox_only(c);
        }
        for d in done.deliveries {
            match d {
                Delivery::Inbox { to, inbox, blob } => {
                    let owner = self.inbox_owner(&to, &inbox.label)?.unwrap_or(to);
                    for server in inbox.servers {
                        self.queue_inbox(Outgoing { label: inbox.label, server, blob: blob.clone(), owner, after: 0, tries: 0 });
                    }
                }
                Delivery::Direct { to, commits } => {
                    let mut pks = Vec::new();
                    for c in commits {
                        if let Some(p) = self.engine.package(&c)? {
                            pks.push(p);
                        }
                    }
                    self.direct.push((to, pks));
                }
                Delivery::First { commits, under } => {
                    for c in &commits {
                        self.first.insert(*c);
                    }
                    for t in under {
                        for g in self.groups_holding(&t) {
                            for c in &commits {
                                self.place_all(&g, c)?;
                            }
                        }
                    }
                }
                Delivery::Certificate { commits, under } => {
                    for c in &commits {
                        self.place_all(&under, c)?;
                    }
                }
                Delivery::Deposit { commit, under } => {
                    for g in self.groups_holding(&under) {
                        self.place_all(&g, &commit)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Places every aspect of `c` as a certificate copy under the labels of `g`.
    fn place_all(&mut self, g: &Tid, c: &CommitId) -> Result<()> {
        let Some(h) = self.engine.header(c) else { return Ok(()) };
        let all: BTreeSet<usize> = (0..h.aspects.len()).collect();
        self.place_certificate_in(g, c, &all)
    }

    /// Groups with a label whose closure holds `t` (the thing itself when labeled).
    fn groups_holding(&mut self, t: &Tid) -> Vec<Tid> {
        let mut out: Vec<Tid> = self.engine.labeled_groups().into_iter().filter(|g| g == t || self.engine.groups_of(t).contains(g)).collect();
        out.dedup();
        out
    }

    /// The actor up `to`'s owner chain whose `/keys` names `label` as its inbox (its deposit
    /// seed signs the deposit).
    fn inbox_owner(&mut self, to: &Tid, label: &LabelId) -> Result<Option<Tid>> {
        let mut cur = *to;
        for _ in 0..64 {
            if self.engine.get_typed(&cur, &ct::KEYS)?.and_then(|k| k.inbox).is_some_and(|i| i.label == *label) {
                return Ok(Some(cur));
            }
            match self.engine.core.created(&cur) {
                Some(osis_core::CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => return Ok(None),
            }
        }
        Ok(None)
    }

    /// Commits for nodes over a direct connection (pairing): the app carries them, the
    /// receiving node `Engine::ingest`s them.
    pub fn take_direct(&mut self) -> Vec<(Tid, Vec<Package>)> {
        std::mem::take(&mut self.direct)
    }

    /// The packages for node `to` only; those for other nodes stay.
    pub fn take_direct_for(&mut self, to: &Tid) -> Vec<Package> {
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.direct).into_iter().partition(|(t, _)| t == to);
        self.direct = rest;
        mine.into_iter().flat_map(|(_, p)| p).collect()
    }
}

impl SyncState for SyncEngine {
    fn complete_pass(&self, actor: &Tid) -> bool {
        let since = self.membership_seen.get(actor).copied().unwrap_or(0);
        let mut any = false;
        for (l, (a, servers)) in &self.label_actors {
            if a != actor {
                continue;
            }
            for s in servers {
                any = true;
                if self.passes.get(&(*s, *l)).is_none_or(|p| *p <= since) {
                    return false;
                }
            }
        }
        any
    }
}
