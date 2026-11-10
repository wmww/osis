//! What a node reports about itself to others (spec/permissions.md §4): that it is stranded on a
//! label (a Stranded message to a connected peer that may re-seal it, else a stranded notice
//! under the label's admins' inboxes), and the aspects it flags suspect (Suspect messages to the
//! peers it shares the label with). Both are judged by their receiver: a re-seal of a current
//! holder at the end of a complete pass (`pass::reseal`), a repair snapshot (spec/sync.md §7).

use super::{Action, ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{Ak, LabelId, Role, Tid};
use osis_proto::Message;
use osis_proto::msg::SuspectEntry;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Whom a stranded report went to: a connection's peer, or an admin's inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum To {
    Peer(ConnId),
    Inbox(Tid),
}

impl SyncEngine {
    /// This node is stranded on `l` of `g` (spec/permissions.md §4: no key it holds opens the
    /// label's current epoch, wherever its walk at `conn`'s host stopped). It sends a Stranded
    /// message to each connected peer that proved an account holding write or above on the
    /// label's actor; with none, a stranded notice to the inbox of each admin of the actor. Each
    /// once per sync key of the newest step reached and recipient.
    pub(crate) fn stranded(&mut self, conn: ConnId, g: Tid, l: LabelId, out: &mut Vec<Action>) -> Result<()> {
        self.stranded_on.insert(l);
        let Some(a) = self.engine.core.secret_actor(&g) else { return Ok(()) };
        let step = self.reached_key(conn, &g, &l);
        let peers: Vec<ConnId> = self
            .records
            .shared
            .keys()
            .copied()
            .filter(|c| self.connection_proven(*c).is_some_and(|p| p.accounts.iter().any(|x| self.engine.core.role_now(x, &a) >= Some(Role::Write))))
            .collect();
        if !peers.is_empty() {
            for c in peers {
                if self.stranded_sent.insert((l, step, To::Peer(c))) {
                    self.shared_request(c, |id| Message::Stranded { id, label: l }, out)?;
                }
            }
            return Ok(());
        }
        let holder = self.own_holder(&a);
        let admins: Vec<Tid> = self.engine.core.key_holders(&a).into_iter().filter(|x| x.1 == Role::Admin).map(|x| x.0).collect();
        for admin in admins {
            if !self.stranded_sent.insert((l, step, To::Inbox(admin))) {
                continue;
            }
            let (Some(kem), Some((inbox_actor, inbox))) = (self.engine.inbox_kem(&admin)?, self.engine.inbox_of_actor(&admin)?) else {
                self.diag(format!("stranded on {l:?}: no inbox of admin {admin}"));
                continue;
            };
            let notice = osis_label::StrandedNotice { label: l, holder };
            let blob = osis_label::seal_stranded_notice(&admin, &kem, &notice, self.engine.now(), &mut *self.rng)?;
            self.queue_inbox(&inbox_actor, inbox.label, &inbox.hosts, blob, None)?;
        }
        self.send_outbox(out)
    }

    /// The sync key of the newest step this node reached of `l` at `conn`'s host: the head, else
    /// where its walk stopped, else the head last known there, else the newest step `label.0`
    /// records; all zeros knowing none.
    fn reached_key(&mut self, conn: ConnId, g: &Tid, l: &LabelId) -> [u8; 32] {
        let host = self.conns.get(&conn).map(|c| c.host);
        let known = self.lc(conn, l).and_then(|x| x.head.clone().or_else(|| x.walk.clone()).or_else(|| x.path.last().cloned())).or_else(|| host.and_then(|h| self.state.heads.get(&(h, *l)).cloned()));
        let step = match known {
            Some(s) => Some(s),
            None => self.engine.labels_of(g).into_iter().find(|x| x.id == *l).and_then(|x| x.tips().first().and_then(|t| x.steps.get(t)).map(|s| s.0.clone())),
        };
        step.map_or([0; 32], |s| s.keys.sync.to_bytes())
    }

    /// The holder of `a` this node reads through, as it judges it: its account, or an actor
    /// holding `a` that its account holds a role on (a team); its account when it judges none (a
    /// grant it has not received). Never a key actor it holds: a link key reads by its static
    /// entry and has no inbox.
    fn own_holder(&self, a: &Tid) -> Tid {
        let me = self.engine.account_tid().unwrap_or_else(|| self.engine.tid());
        let holders: Vec<Tid> = self.engine.core.key_holders(a).into_iter().map(|x| x.0).collect();
        if holders.contains(&me) {
            return me;
        }
        holders.into_iter().find(|h| !self.engine.core.is_key_actor(h) && self.engine.core.role_now(&me, h).is_some()).unwrap_or(me)
    }

    /// A Stranded message from `conn`'s peer: the holder of `l`'s actor among the actors the
    /// connection proved (or up their record chains) waits for the end of a complete pass of the
    /// actor's labels to be re-sealed (`reseal`).
    pub(super) fn stranded_message(&mut self, conn: ConnId, l: LabelId) {
        let Some(g) = self.labels().into_iter().find(|(_, x)| x.id == l).map(|x| x.0) else { return };
        let Some(a) = self.engine.core.secret_actor(&g) else { return };
        let Some(p) = self.connection_proven(conn) else { return };
        let actors: Vec<Tid> = p.all().into_iter().collect();
        let holders: BTreeSet<Tid> = self.engine.core.key_holders(&a).into_iter().map(|x| x.0).collect();
        let holder = actors.iter().find_map(|x| self.engine.record_chain(x).find(|t| holders.contains(t)));
        if let Some(h) = holder {
            self.stranded_ask(a, h, l);
        }
    }

    /// A stranded notice opened from an inbox: `holder` is re-sealed on `l`'s actor at the end
    /// of a complete pass of its labels, if a current holder this node may re-seal.
    pub(super) fn stranded_notice(&mut self, n: osis_label::StrandedNotice) {
        let Some(g) = self.labels().into_iter().find(|(_, x)| x.id == n.label).map(|x| x.0) else { return };
        let Some(a) = self.engine.core.secret_actor(&g) else { return };
        self.stranded_ask(a, n.holder, n.label);
    }

    fn stranded_ask(&mut self, a: Tid, holder: Tid, l: LabelId) {
        self.stranded_asks.entry(a).or_default().insert(holder);
        let labels: Vec<LabelId> = self.labels().into_iter().filter(|(g, _)| self.engine.core.secret_actor(g) == Some(a)).map(|x| x.1.id).chain([l]).collect();
        self.mark_labels(&labels);
    }

    /// Suspect lists to the peers this node shares labels with (spec/permissions.md §4): per
    /// (connection, member L), the flagged, not dormant aspects of things in L's closure with
    /// their state digests, the most recently flagged first, whenever that list changes (a
    /// member joining included). Taken again only after an engine change or a member joining.
    pub(super) fn send_suspects(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let generation = self.engine.core.generation;
        if !std::mem::take(&mut self.suspects_due) && self.suspects_gen == Some(generation) {
            return Ok(());
        }
        self.suspects_gen = Some(generation);
        let members: Vec<(ConnId, LabelId)> = self.records.shared.iter().flat_map(|(c, s)| s.member_ids().map(move |l| (*c, l))).collect();
        let keep: BTreeSet<(ConnId, LabelId)> = members.iter().copied().collect();
        self.suspects_sent.retain(|k, _| keep.contains(k));
        let flags = self.engine.suspects()?;
        if flags.is_empty() && self.suspects_sent.values().all(Vec::is_empty) {
            return Ok(());
        }
        let groups: BTreeMap<LabelId, Tid> = self.labels().into_iter().map(|(g, x)| (x.id, g)).collect();
        let mut lists: BTreeMap<LabelId, Vec<SuspectEntry>> = BTreeMap::new();
        for (c, l) in members {
            let Some(g) = groups.get(&l) else { continue };
            let list = match lists.get(&l) {
                Some(x) => x.clone(),
                None => {
                    let x = self.suspects_under(&flags, g)?;
                    lists.insert(l, x.clone());
                    x
                }
            };
            if self.suspects_sent.get(&(c, l)) == Some(&list) || !self.suspects_sent.contains_key(&(c, l)) && list.is_empty() {
                continue;
            }
            self.suspects_sent.insert((c, l), list.clone());
            // as many as fit a message, each message on its own
            let room = osis_base::format::MAX_MESSAGE - 1024;
            let mut chunk: Vec<SuspectEntry> = Vec::new();
            let mut size = 0;
            for e in list {
                if size + e.size() > room && !chunk.is_empty() {
                    let entries = std::mem::take(&mut chunk);
                    self.shared_request(c, |id| Message::Suspect { id, label: l, entries }, out)?;
                    size = 0;
                }
                size += e.size();
                chunk.push(e);
            }
            if !chunk.is_empty() {
                self.shared_request(c, |id| Message::Suspect { id, label: l, entries: chunk }, out)?;
            }
        }
        Ok(())
    }

    /// The aspects of things in `g`'s closure among `flags` with their keyed state digests
    /// (spec/permissions.md §4), the most recently flagged first; an aspect with no digest here
    /// (no creation record) waits until it has one. Only the label's things: its readers learn
    /// nothing of others.
    fn suspects_under(&mut self, flags: &[(Tid, Ak, u64, u8)], g: &Tid) -> Result<Vec<SuspectEntry>> {
        let closure = self.engine.closure(g);
        let mut flagged: Vec<&(Tid, Ak, u64, u8)> = flags.iter().filter(|x| closure.contains(&x.0)).collect();
        flagged.sort_by_key(|x| (std::cmp::Reverse(x.2), x.0, x.1.clone()));
        let mut out = Vec::new();
        for (thing, ak, _, _) in flagged {
            if let Some(digest) = self.engine.state_digest(thing, ak)? {
                out.push(SuspectEntry { thing: *thing, ak: ak.clone(), digest });
            }
        }
        Ok(out)
    }

    /// Repair (spec/sync.md §7): a Suspect message from `conn`'s peer for `l`, a member of the
    /// connection's shared set. For each entry of a thing in `l`'s closure this node may write,
    /// past its first sync of `l`, whose state digest here differs: a snapshot of it from this
    /// node's whole state, an ordinary compaction snapshot (it joins with the others', never
    /// resurrects expired or purged values). Once per entry of each list, and once per state per
    /// reporting peer (`repair_state`). Every entry acted on is a diagnostic, so silent repairs
    /// hide nothing.
    pub(super) fn suspect_message(&mut self, conn: ConnId, l: LabelId, entries: Vec<SuspectEntry>) -> Result<()> {
        if !self.shared_member(conn, &l) || self.filling(&l) {
            return Ok(());
        }
        let Some(g) = self.labels().into_iter().find(|(_, x)| x.id == l).map(|x| x.0) else { return Ok(()) };
        // per source: a node of this account by its node, any other by its known account (its
        // node key is not proved here), else its first known actor
        let core = &self.engine.core;
        let Some(peer) = self.connection_proven(conn).and_then(|p| p.source(core).or_else(|| p.all().into_iter().find(|t| core.judge([*t]).known()))) else { return Ok(()) };
        let closure = self.engine.closure(&g);
        for s in entries {
            let ak = s.ak;
            if !closure.contains(&s.thing) || ct::is_role_class(ak.as_str()) || ak.as_str() == "created.0" {
                continue;
            }
            if self.engine.role_on(&s.thing) < Some(Role::Write) {
                continue;
            }
            let mine = self.engine.state_digest(&s.thing, &ak)?;
            if mine.is_none() || mine == Some(s.digest) {
                self.repair_diag(peer, s.thing, None, format!("suspect {} {} reported by {peer}: same state here", s.thing, ak));
                continue;
            }
            // a report no snapshot can settle: another from this same state repairs nothing more
            // for this peer; another node may have dropped that snapshot before its own flip
            if self.repair_state.get(&(peer, s.thing, ak.clone())) == mine.as_ref() {
                self.repair_diag(peer, s.thing, None, format!("suspect {} {} reported by {peer}: already snapshotted from this state", s.thing, ak));
                continue;
            }
            match self.engine.snapshot(&s.thing, &ak) {
                // holding no state, this writer has nothing to snapshot
                Ok(None) => self.repair_diag(peer, s.thing, None, format!("suspect {} {} reported by {peer}: no state here", s.thing, ak)),
                Ok(snap) => {
                    if let Some(d) = self.engine.state_digest(&s.thing, &ak)? {
                        self.repair_state.insert((peer, s.thing, ak.clone()), d);
                    }
                    self.repair_diag(peer, s.thing, snap, format!("suspect {} {} reported by {peer}: re-snapshotted", s.thing, ak));
                }
                Err(e) => self.diag(format!("repair of {} {}: {e}", s.thing, ak)),
            }
        }
        Ok(())
    }

    fn repair_diag(&mut self, peer: Tid, thing: Tid, commit: Option<osis_base::CommitId>, detail: String) {
        let now = self.engine.now();
        self.engine.core.events.diagnostic(crate::events::Diagnostic { kind: crate::events::DiagnosticKind::Repair, tids: vec![peer, thing], commit, peer: Some(peer), detail }, now);
    }
}
