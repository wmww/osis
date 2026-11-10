//! Requests of the app and of role flows: compaction
//! (spec/sync.md §7), certificate placement under a group's labels (spec/permissions.md §3, §4:
//! the grantee's `keys.0`, a removal's new `keys.0`), inbox delivery (spec/sync.md §3), label
//! creation.

use super::state::{Entry, Kind, HostKey};
use super::{Action, ConnId, Phase, SyncEngine};
use crate::error::{Error, Result};
use osis_base::{Ak, BlobId, CommitId, LabelId, Role, Tid, Ts};
use osis_label::{Address, InboxLabel, InboxPayload, InboxThing};
use osis_perm::At;
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Longest wait between sends of a queued deposit refused for now (`retry_ms` doubling per
/// refusal up to this). Minor consequence: at 0 a refused deposit is resent on every tick, at
/// infinity it lands that much later after the refusal clears (a recipient back online).
pub(crate) const DEPOSIT_RETRY_CAP_MS: u64 = 3_600_000;

/// Re-sends of an inbox delivery whose holder never acts (local policy; one per
/// `INBOX_LIFETIME`).
const MAX_INBOX_RESENDS: u32 = 3;

/// Where a queued deposit (`State::outbox`, `SyncEngine::queue_deposit`) stands, in memory: a
/// restart sends every one again.
#[derive(Clone, Copy, Default)]
pub(crate) struct Outgoing {
    /// Not sent before this raw wall ms (a refused deposit backs off from `retry_ms`).
    pub after: u64,
    /// Refusals so far (the back-off doubles per refusal).
    pub tries: u32,
    /// Sent on this connection and not answered yet.
    pub sent: Option<ConnId>,
}

impl SyncEngine {
    /// Creates a label for group `g` at `hosts` (an admin; spec/sync.md §2) and connects.
    pub fn create_label(&mut self, g: &Tid, hosts: Vec<Address>) -> Result<(LabelId, Vec<Action>)> {
        let (l, done) = self.engine.create_label(g, &hosts)?;
        self.take_done(done)?;
        Ok((l, self.handle(super::Event::Local)))
    }

    /// Replaces label `old` of `g` (spec/sync.md §2; an admin, `Engine::replace_label`: the
    /// admin rotation if the loss calls for it, a new label at the same hosts, the old one
    /// marked replaced); passes then upload the live blobs under the new label, and under the
    /// old one (an admin keeps syncing it until done there, `labels`) only role-class
    /// commits, the replacement's `label.0` among them, deleting its content entries;
    /// certificates stay.
    pub fn replace_label(&mut self, g: &Tid, old: &LabelId) -> Result<(LabelId, Vec<Action>)> {
        let (new, done) = self.engine.replace_label(g, old)?;
        self.take_done(done)?;
        Ok((new, self.handle(super::Event::Local)))
    }

    /// Compacts `(t, ak)` (spec/sync.md §7): writes a snapshot from this node's state, then
    /// drops the bodies it covers that this node may purge and whose keep-at-least bound is
    /// `MAX_DRIFT` past; the next pass uploads the snapshot and deletes the dropped bodies at hosts once
    /// the snapshot is there.
    pub fn compact(&mut self, t: &Tid, ak: &Ak) -> Result<Vec<Action>> {
        let Some(s) = self.engine.snapshot(t, ak)? else { return Ok(Vec::new()) };
        let dropped: BTreeSet<CommitId> = self.drop_covered(t, ak, &s, None, &mut super::work::Left::default())?.into_iter().collect();
        // a dropped body's key and ciphertext go with it (spec/commits.md §5)
        self.forget_dropped(Some(&dropped))?;
        Ok(self.handle(super::Event::Local))
    }

    /// Drops the bodies of `(t, ak)` that snapshot `s` covers, that this node may purge and
    /// whose keep-at-least bound is `MAX_DRIFT` past (spec/sync.md §7: the compactor, and every other
    /// right holder as it holds the snapshot); `s` carries them. A body is judged against `s`
    /// again until it is dropped or settled kept (established uncovered, or the lower of two
    /// covered-equal snapshots: `covered_judged`), so what a node drops follows what it holds,
    /// not when the snapshot or the body arrived. Only the bodies `only` names when given (a
    /// pass's work set: the others were judged before and nothing changed for them); what is
    /// judged again later goes into `left` (not established yet: next pass; keep-at-least: at
    /// its bound). Returns the bodies dropped.
    pub(crate) fn drop_covered(&mut self, t: &Tid, ak: &Ak, s: &CommitId, only: Option<&[CommitId]>, left: &mut super::work::Left) -> Result<Vec<CommitId>> {
        let s = *s;
        let now = self.engine.now();
        let held: Vec<CommitId> = match only {
            Some(o) => o.to_vec(),
            None => self.engine.core.durable_on(&(*t, ak.clone())).collect(),
        };
        let mut dropped = Vec::new();
        for c in held {
            if c == s {
                continue;
            }
            // a settled judgment holds while both bodies are held (a pair goes once either is
            // dropped: a drop is a trigger, so the pair is looked at then)
            let k = (s, c, *t, ak.clone());
            let both = self.engine.body_not_dropped(&s, t, ak) && self.engine.droppable_if_covered(&c, t, ak);
            if self.covered_judged.contains(&k) {
                if both {
                    continue;
                }
                self.covered_judged.remove(&k);
            }
            if !self.engine.droppable_if_covered(&c, t, ak) {
                // a leftover drops as covered once past its expiry: judged again then
                if let Some(h) = self.engine.header(&c)
                    && let Some(x) = h.expires
                    && x > now.0
                    && h.aspects.iter().position(|a| a.tid == *t && a.ak == *ak).is_some_and(|ai| self.engine.part_held(&c, ai))
                {
                    left.at(x, super::state::Touch::Commit(c));
                }
                continue;
            }
            let Some(h) = self.engine.header(&c) else { continue };
            // the snapshot's right, this node's and the keep-at-least bound, as a demotion's
            // frontier judges them
            if !self.engine.snapshot_right(&s, &c, t, ak) {
                continue;
            }
            // an own whole replace is judged before its body's keep bound: most plain commits
            // cover nothing, and the bound reads every part of the body
            let own = self.engine.own_replace(&s, t, ak);
            if own {
                match self.engine.covered(&s, &c, t, ak)? {
                    Some(true) => {}
                    // not established yet: judged again
                    None => {
                        left.commits.insert(c);
                        continue;
                    }
                    // judged again once the aspect changes (a write's liveness, `cannot_keep`)
                    Some(false) => {
                        left.wait(*t, ak.clone(), c);
                        continue;
                    }
                }
            }
            let due = if own {
                self.engine.own_drop_from(&c, t, ak)?
            } else {
                let Some(due) = self.engine.drop_from(&c, t, ak)? else { continue };
                due
            };
            if due > now.0 {
                left.at(due, super::state::Touch::Commit(c));
                continue;
            }
            // spec/commits.md §5 Own replaces: a commit goes only whole, or a node that may not
            // rewrite its blob (a reader) could no longer relay what its other parts carry
            if own {
                match self.own_covers_every_part(&c, &h)? {
                    None => {
                        for a in &h.aspects {
                            left.wait(a.tid, a.ak.clone(), c);
                        }
                        continue;
                    }
                    Some(due) if due > now.0 => {
                        left.at(due, super::state::Touch::Commit(c));
                        continue;
                    }
                    Some(_) => {}
                }
            }
            match self.engine.covered(&s, &c, t, ak)? {
                // not established yet: judged again
                None => {
                    left.commits.insert(c);
                    continue;
                }
                Some(false) => {
                    // a body with an expiry, held with its values, is judged anew once it is
                    // its leftover (spec/commits.md §5): not settled
                    if (h.expires.is_none() || !self.engine.body_not_dropped(&c, t, ak)) && self.engine.header(&s).is_some_and(|x| super::pass::is_snapshot(x.kind)) {
                        self.covered_judged.insert(k);
                    }
                    continue;
                }
                Some(true) => {}
            }
            // covered-equal snapshots (equal `ts`): only the higher commit ID goes (spec/sync.md
            // §7), as in the must-hold judgment, or this node drops the one a co-writer keeps
            // uploading
            if super::pass::is_snapshot(h.kind) && c < s && self.engine.covered(&c, &s, t, ak)? == Some(true) {
                self.covered_judged.insert(k);
                continue;
            }
            self.engine.drop_body(&c, t, ak)?;
            self.state.forget_due.insert(c);
            self.state.set_carrier(c, s);
            self.touched.commits.insert(c);
            dropped.push(c);
        }
        Ok(dropped)
    }

    /// Whether every part of `c` still held may drop under own replaces (spec/commits.md §5):
    /// covered by one whose author holds the right over it. `Some`: from when all of them may
    /// (the latest keep bound), so none drops alone for good.
    fn own_covers_every_part(&mut self, c: &CommitId, h: &osis_commit::Header) -> Result<Option<u64>> {
        let mut due = 0;
        for (ai, a) in h.aspects.iter().enumerate() {
            if !self.engine.part_held(c, ai) {
                continue;
            }
            let covers = self.engine.own_covers(c, &a.tid, &a.ak);
            let mut covered = false;
            for q in &covers {
                covered |= self.engine.snapshot_right(q, c, &a.tid, &a.ak) && self.engine.covered(q, c, &a.tid, &a.ak)? == Some(true);
            }
            if !covered {
                return Ok(None);
            }
            due = due.max(self.engine.own_drop_from(c, &a.tid, &a.ak)?);
        }
        Ok(Some(due))
    }

    /// Places commit `c`'s deltas on `aspects` as a certificate copy under every label of `g`
    /// (spec/permissions.md §3, §4): a fresh encryption per label, uploaded or deposited at the
    /// label's next pass.
    pub fn place_certificate(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        self.place_certificate_in(g, c, aspects, None)?;
        Ok(self.handle(super::Event::Local))
    }

    /// `place_certificate`. A copy of this node's own write under a label it does not write
    /// (its invite grant, self-removal, chain) is also queued as a deposit (`queue_deposit`),
    /// so it reaches the label even when this node loses the label before a host answers:
    /// other nodes may hold parts of the commit from elsewhere and wait for the rest. `owed`:
    /// the flow's delivery it carries out (`take_done`), kept while the copy waits.
    pub(crate) fn place_certificate_in(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>, owed: Option<[u8; 32]>) -> Result<()> {
        let labels: Vec<(LabelId, Vec<Address>)> = self.engine.group_labels(g)?.into_iter().filter(|l| !l.replaced).map(|l| (l.id, l.hosts)).collect();
        if labels.is_empty() {
            return Ok(());
        }
        // placing never rotates (a rotation's own copies placed here recursed into rotations):
        // under an epoch that does not cover a known departure it waits for the next pass,
        // which rotates first
        if self.uncovered(g, false)?.place.contains(&Role::Read) {
            self.deferred.push((*g, *c, aspects.clone(), owed));
            return Ok(());
        }
        let own = self.engine.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local);
        let seed = if own && self.engine.role_on(&self.engine.group_actor(g)) < Some(Role::Write) { self.engine.deposit_seed(g)? } else { None };
        let want = self.engine.header(c).map(|h| super::pass::parts_of(&h, |i| aspects.contains(&i))).unwrap_or_default();
        let mut unwrapped = false;
        for (l, hosts) in labels {
            // by part: a chain may have copied this commit's edge here, and a later copy wants its
            // boxes. A copy placed and gone since is not placed again
            let mine: BTreeSet<usize> = self.state.entries_of(&l, c).filter(|(_, e)| e.cert).filter_map(|(_, e)| if let Kind::Commit { parts, .. } = &e.kind { Some(parts.clone()) } else { None }).flatten().collect();
            if self.state.certs.contains(&(l, *c)) && (mine.is_empty() || want.is_subset(&mine)) {
                continue;
            }
            let parts: BTreeSet<usize> = want.difference(&mine).copied().collect();
            let deposit = seed.as_ref().map(|s| osis_crypto::deposit_key(s, &l));
            // nothing to place once its parts are dropped here (`State::sweep_certs`)
            let Some(b) = self.engine.part_body(c, &parts)? else { continue };
            // a rotation-carrying copy is wrapped like the body (spec/crypto.md §5): other
            // holders take it as the body's entry
            let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else {
                unwrapped = true;
                continue;
            };
            let Some(s) = self.engine.seal_to(&b, osis_label::Class::Durable, &secret, &mut *self.rng)? else {
                unwrapped = true;
                continue;
            };
            let wrap = osis_crypto::wrap(&secret, &s.id, &s.key, b.order)?;
            if let Some(d) = &deposit {
                self.queue_deposit(l, &hosts, d, s.blob.clone(), wrap, None);
            }
            self.engine.put_blobs(vec![(s.id, s.blob)])?;
            self.state.add_blob(s.id, super::state::BlobRec { commit: b.commit, parts: b.parts.clone(), ais: s.ais.clone(), key: s.key.clone(), cert: true, memory: false });
            self.state.set_entry(l, s.id, Entry { wrap, stamp: None, cert: true, salt: Some(s.salt), kind: Kind::Commit { commit: b.commit, parts: b.parts.clone(), ais: s.ais }, memory: false });
            self.place_linked(l, c, &parts)?;
            if let Some(d) = &deposit {
                for id in self.engine.linked_blobs(c, &parts)? {
                    let wrap = self.state.entries.get(&(l, id)).map(|e| e.wrap);
                    if let (Some(wrap), Some(blob)) = (wrap, self.engine.blob(&id)?) {
                        self.queue_deposit(l, &hosts, d, blob, wrap, None);
                    }
                }
            }
            self.state.add_cert(l, *c);
        }
        // nothing wrapped part of it (no current read secret): it waits like an uncovered epoch,
        // for a re-seal; a node that does not read the group (another's, its removal's copy) gets
        // none, so that copy is not this node's to place
        if unwrapped && self.engine.account_tid().is_some_and(|m| self.engine.core.may_read(&m, &self.engine.group_actor(g))) {
            self.deferred.push((*g, *c, aspects.clone(), owed));
        }
        Ok(())
    }

    /// After a settled pass of replaced label `l` of `g` at `host` that had nothing left to
    /// upload (`quiet`): done there when no content entry is present any more (spec/sync.md §2:
    /// role-class commits, the replacement's `label.0` among them, and certificates stay);
    /// once done at every host of the label (or no key opens it there), this admin stops
    /// syncing it for good; `labels` retires it after `ROLE_KEEP` whatever.
    pub(crate) fn retire_at(&mut self, host: super::state::HostKey, g: &Tid, l: LabelId) -> Result<()> {
        // content commits' chunks and pages go too
        if !self.replaced_leftovers(&host, &l).is_empty() {
            return Ok(());
        }
        for b in self.state.present_at(&host, &l) {
            let Some(Kind::Commit { commit, parts, .. }) = self.state.entries.get(&(l, b)).map(|e| &e.kind) else { continue };
            let Some(h) = self.engine.header(commit) else { return Ok(()) };
            if parts.iter().filter_map(|ai| h.aspects.get(*ai)).any(|a| !super::pass::kept_when_replaced(a.ak.as_str())) {
                return Ok(());
            }
        }
        self.retired_at.insert((host, l));
        let hosts: Vec<_> = self.engine.group_labels(g)?.into_iter().find(|x| x.id == l).map(|x| x.hosts).unwrap_or_default();
        // a host where no key opens the label (taken by whoever replaced it) counts as done
        let failed = |k: &super::state::HostKey| self.conns.values().any(|c| c.host == *k && c.labels.get(&l).is_some_and(|x| x.phase == Phase::Failed));
        if hosts.iter().all(|a| self.retired_at.contains(&(a.key, l)) || failed(&a.key)) {
            self.state.retire(l);
        }
        Ok(())
    }

    /// The blobs a certificate copy of `parts` of `c` links (header lists, linked frontiers) as
    /// certificate entries under `l` (spec/sync.md §3), so a verifier that syncs nothing else
    /// under the label resolves them.
    pub(crate) fn place_linked(&mut self, l: LabelId, c: &CommitId, parts: &BTreeSet<usize>) -> Result<()> {
        for b in self.engine.linked_blobs(c, parts)? {
            if !self.state.entries.contains_key(&(l, b)) {
                let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                self.state.set_entry(l, b, Entry { wrap, stamp: None, cert: true, salt: None, kind: Kind::Unknown, memory: false });
            }
        }
        Ok(())
    }

    /// Delivers commit `c`'s deltas on `aspects` to actor `recipient` as an inbox blob
    /// (spec/sync.md §3; spec/crypto.md §5): sealed to its read keyset's KEM key, with the label
    /// IDs and hosts of the things the commit names, deposited under its inbox
    /// (`Engine::inbox_of_actor`).
    pub fn deliver_inbox(&mut self, recipient: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        let id = *c;
        let blob = self.engine.run(|tx| tx.get_commit(&id))?.ok_or(Error::UnknownCommit(id))?;
        let cut = osis_commit::rewrite(&blob, |ai| !aspects.contains(&ai));
        let kem = self.engine.inbox_kem(recipient)?.ok_or(Error::Misuse("recipient has no KEM key"))?;
        let (inbox_actor, inbox) = self.engine.inbox_of_actor(recipient)?.ok_or(Error::Misuse("recipient has no inbox"))?;
        let mut things: Vec<InboxThing> = Vec::new();
        let tids: BTreeSet<Tid> = cut.header.aspects.iter().map(|a| a.tid).collect();
        for t in tids {
            let label = self.engine.group_labels(&t)?.into_iter().find(|gl| !gl.replaced).map(|gl| InboxLabel { id: gl.id, index: gl.index, hosts: gl.hosts });
            let delete_keys = self.engine.own_delete_keys(&t)?;
            things.push(InboxThing { tid: t, label, delete_keys });
        }
        let commit = osis_base::decode(&cut.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_MESSAGE })
            .map_err(|_| Error::Corrupt("commit blob"))?;
        let payload = InboxPayload { commit, things, chain: Vec::new(), records: Vec::new() };
        let blob = osis_label::seal_inbox_blob(recipient, &kem, &payload, self.engine.now(), &mut *self.rng)?;
        self.queue_inbox(&inbox_actor, inbox.label, &inbox.hosts, blob, None)?;
        Ok(self.handle(super::Event::Local))
    }

    /// Inbox deliveries from their records (spec/sync.md §3, §5): one not sent yet (`at` 0) is
    /// sealed and sent at once; one `INBOX_LIFETIME` old whose holder has not acted is sealed
    /// again (to its newest keyset) and sent again, at most `MAX_INBOX_RESENDS` times; one whose
    /// commit is gone, or whose holder acted or (for a grant or re-seal) left, is forgotten.
    pub(crate) fn send_inbox(&mut self) -> Result<()> {
        let now = self.now();
        let due: Vec<super::state::SentInbox> = self.state.sent_inbox.values().filter(|s| s.at == 0 || s.at.saturating_add(osis_base::format::INBOX_LIFETIME_MS) <= now).cloned().collect();
        for s in due {
            let first = s.at == 0;
            let ts = self.engine.header(&s.commit).map(|h| h.ts);
            let gone = match ts {
                None => true,
                // a seal waiting for the inbox's nodes stays until one takes it
                Some(ts) => !first && ((s.tries >= MAX_INBOX_RESENDS && !self.waits_for_nodes(&(s.holder, s.commit))) || self.acted(&s.holder, ts, &s.things)),
            };
            if gone || !s.edge_only && !self.still_holder(&s.holder, &s.commit) {
                self.forget_delivery(&s.holder, &s.commit);
                continue;
            }
            let parts = if s.edge_only { crate::flows::edges::Parts::Edge } else { crate::flows::edges::Parts::All };
            // a re-sent removal notice names no label: a removed holder must not learn the
            // target's current one
            let things = if s.edge_only && !first { Vec::new() } else { s.things.clone() };
            // with the author's chain for what it carries when a named thing has no label (the
            // holder has nothing to read the chain from, so it would hold the grant pending and
            // show no state; a labeled thing's label carries it, as before); a chain that does
            // not fit the blob goes without (the holder then waits for the thing's label)
            let unlabeled = things.iter().any(|t| !self.engine.labeled(t));
            let carried = self.engine.header(&s.commit).map(|h| super::pass::parts_of(&h, |ai| !s.edge_only || h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == "roles.0"))).unwrap_or_default();
            // a grant's or re-seal's recipient reads the thing: its `keys.0` goes along (a
            // removal's does not: the fresh deposit seed is not for the departed)
            let keys_of: Vec<Tid> = if s.edge_only { Vec::new() } else { s.things.clone() };
            let (chain, records) = if unlabeled { self.inbox_chain(&s.commit, &carried, &keys_of)? } else { Default::default() };
            let mut r = self.engine.run(|tx| crate::flows::edges::deliver_parts(tx, s.holder, s.commit, &things, parts, chain, records));
            if r.is_err() {
                r = self.engine.run(|tx| crate::flows::edges::deliver_parts(tx, s.holder, s.commit, &things, parts, Vec::new(), Vec::new()));
            }
            // a new seal replaces the earlier one still queued
            self.drop_delivery_out(&s.holder, &s.commit);
            let mut sent = false;
            for d in r.unwrap_or_default() {
                if let crate::flows::Delivery::Inbox { to, inbox, blob, .. } = d {
                    let inbox_actor = self.inbox_actor(&to, &inbox.label)?.unwrap_or(to);
                    self.queue_inbox(&inbox_actor, inbox.label, &inbox.hosts, blob, Some((s.holder, s.commit)))?;
                    sent = true;
                }
            }
            if sent {
                self.state.note_sent(s.holder, s.commit, s.things.clone(), s.edge_only, now);
            } else {
                // no inbox or keys for the holder any more
                self.forget_delivery(&s.holder, &s.commit);
            }
        }
        Ok(())
    }

    /// Whether a seal of inbox delivery `d` waits for its inbox's nodes (`Dest::Nodes`).
    fn waits_for_nodes(&self, d: &(Tid, CommitId)) -> bool {
        self.state.outbox.values().any(|o| o.delivery.as_ref() == Some(d) && matches!(o.to, super::state::Dest::Nodes(_)))
    }

    /// Forgets inbox delivery `(holder, c)` and its seals still queued.
    fn forget_delivery(&mut self, holder: &Tid, c: &CommitId) {
        self.state.remove_sent(holder, c);
        self.drop_delivery_out(holder, c);
    }

    /// Drops the queued seals of inbox delivery `(holder, c)`.
    fn drop_delivery_out(&mut self, holder: &Tid, c: &CommitId) {
        let k = Some((*holder, *c));
        let ks: Vec<(HostKey, LabelId, BlobId)> = self.state.outbox.iter().filter(|(_, o)| o.delivery == k).map(|(x, _)| *x).collect();
        for (s, l, b) in ks {
            self.outbox.remove(&(s, l, b));
            self.state.remove_out(&s, &l, &b);
        }
    }

    /// How long a queued deposit refused for now `tries` times waits: `retry_ms`, doubling per
    /// refusal, at most `DEPOSIT_RETRY_CAP_MS`.
    pub(crate) fn deposit_back_off(&self, tries: u32) -> u64 {
        self.cfg.retry_ms.saturating_mul(1u64 << tries.saturating_sub(1).min(20)).min(DEPOSIT_RETRY_CAP_MS)
    }

    /// Whether a queued deposit refused for now (`SyncEngine::budget`) is moot, so it is dropped
    /// rather than sent again: an inbox seal whose delivery is gone, or a deposit under a label
    /// this node sees replaced (spec/sync.md §2: no new step is issued for it, and what still
    /// matters goes under the new label). Anything else waits for its label to take it.
    pub(crate) fn deposit_moot(&mut self, host: &HostKey, l: &LabelId, b: &BlobId) -> bool {
        let Some(o) = self.state.outbox.get(&(*host, *l, *b)) else { return true };
        if let Some(k) = o.delivery {
            return !self.state.sent_inbox.contains_key(&k);
        }
        self.group_of(l, None).is_some_and(|g| self.is_replaced(&g, l))
    }

    /// Signs queued deposit `(host, l, b)` again with the label's current deposit key (an
    /// inbox's from its actor's `keys.0`), after its host found it signed by an earlier one;
    /// false when this node holds no other key, so it can never be taken.
    pub(crate) fn resign_deposit(&mut self, host: &HostKey, l: &LabelId, b: &BlobId) -> Result<bool> {
        let Some(o) = self.state.outbox.get(&(*host, *l, *b)).cloned() else { return Ok(false) };
        let seed = match o.delivery {
            Some((holder, _)) => {
                let inbox_actor = self.inbox_actor(&holder, l)?.unwrap_or(holder);
                self.engine.get_typed(&inbox_actor, &ct::KEYS)?.and_then(|k| k.deposit_seed).map(osis_crypto::Secret32::from_bytes)
            }
            None => match self.group_of(l, None) {
                Some(g) => self.engine.deposit_seed(&g)?,
                None => None,
            },
        };
        let Some(seed) = seed else { return Ok(false) };
        let sig = osis_label::sign_deposit(&osis_crypto::deposit_key(&seed, l), l, b, &o.wrap);
        if sig == o.sig {
            return Ok(false);
        }
        self.state.add_out(super::state::OutRec { sig, ..o });
        Ok(true)
    }

    /// The author's chain certificates for `parts` of `c` (`chain_under`: without any `keys.0`
    /// but the author's own) and the current `keys.0` commits of each of `keys_of` (the things a grant
    /// boxes the recipient on: it reads them, and judges them by their keyset) as plaintext commit
    /// values, each projected to those deltas, and the chain's raw records: an inbox payload's
    /// `chain` and `records` (spec/wire.md §9). Empty for a commit not applied here.
    fn inbox_chain(&mut self, c: &CommitId, parts: &BTreeSet<usize>, keys_of: &[Tid]) -> Result<(Vec<osis_base::Value>, Vec<osis_base::CreationRecord>)> {
        let mut chain = self.chain_under(c, parts).unwrap_or_default();
        for t in keys_of {
            for x in self.engine.current_keys(t) {
                let Some(h) = self.engine.header(&x) else { continue };
                chain.commits.entry(x).or_default().extend(super::pass::parts_of(&h, |i| h.aspects.get(i).is_some_and(|a| a.tid == *t && a.ak.as_str() == "keys.0")));
            }
        }
        self.chain_values(chain)
    }

    /// `h`'s current `keys.0` commits, each projected to that delta, with their authors' chains
    /// for them (`chain_under`), and the chain's raw records: a stranded report's holder keys
    /// (spec/wire.md §9), from which a reader of the label's actor gone from `h` seals `h` and
    /// deposits under its inbox.
    pub(super) fn holder_keys(&mut self, h: &Tid) -> Result<osis_label::HolderKeys> {
        let mut chain = crate::labeling::Certs::default();
        for x in self.engine.current_keys(h) {
            let Some(hd) = self.engine.header(&x) else { continue };
            let parts = super::pass::parts_of(&hd, |i| hd.aspects.get(i).is_some_and(|a| a.tid == *h && a.ak.as_str() == "keys.0"));
            if let Some(c) = self.chain_under(&x, &parts) {
                for (y, q) in c.commits {
                    chain.commits.entry(y).or_default().extend(q);
                }
                chain.records.extend(c.records);
            }
            chain.commits.entry(x).or_default().extend(parts);
        }
        let (commits, records) = self.chain_values(chain)?;
        Ok(osis_label::HolderKeys { commits, records })
    }

    /// The commits of `chain`, each projected to its parts there, as plaintext commit values, and
    /// its raw records (the ones held).
    fn chain_values(&mut self, chain: crate::labeling::Certs) -> Result<(Vec<osis_base::Value>, Vec<osis_base::CreationRecord>)> {
        let mut out = Vec::new();
        for (x, q) in chain.commits {
            let Some(mut blob) = self.engine.run(|tx| tx.get_commit(&x))?.map(std::sync::Arc::unwrap_or_clone) else { continue };
            blob.parts.retain(|p| q.contains(&p.ai));
            if blob.parts.is_empty() {
                continue;
            }
            let limits = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB };
            out.push(osis_base::decode(&blob.encode(), &limits).map_err(|_| Error::Corrupt("commit blob"))?);
        }
        let records = chain.records.iter().filter_map(|t| self.engine.core.created(t).cloned()).collect();
        Ok((out, records))
    }

    /// Whether `holder` is still a current holder of a thing whose edges, secrets or labels
    /// commit `c` writes (a grant, re-seal or new label is re-sent only while the holder holds
    /// what it gave; a removal since then must not hand it the target's current label).
    fn still_holder(&self, holder: &Tid, c: &CommitId) -> bool {
        let Some(h) = self.engine.header(c) else { return false };
        let targets: BTreeSet<Tid> = h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "roles.0" | "secrets.0" | "label.0")).map(|a| a.tid).collect();
        targets.iter().any(|t| self.engine.core.current_holders(t).iter().any(|(m, _, _)| m == holder))
    }

    /// Whether `holder` acted on a delivery naming `things` after `since` as this node sees it:
    /// a held commit newer than that, by the holder, for it, or by a node with a role on it (its
    /// nodes), writing one of `things` or a thing whose record chain reaches one of them. Acting elsewhere says nothing of
    /// this delivery (its blob may have been cleared, spec/sync.md §5), so it is sent again.
    /// The record chain as created, not `Core::standing_chain`: this reads evidence of receipt,
    /// not standing (a write below a named thing is one whatever edges stood since), and a
    /// mismatch costs only a re-send more or less.
    fn acted(&self, holder: &Tid, since: Ts, things: &[Tid]) -> bool {
        let tl = self.engine.core.timelines.get(holder);
        // the views: O(commits) without decoding headers
        self.engine.core.ix.commits.values().any(|m| {
            let h = &m.view;
            h.ts > since
                && (h.author == *holder || h.actor == *holder || tl.is_some_and(|tl| tl.role(&h.author, holder, At::now(h.ts)).is_some()))
                && h.aspects.iter().any(|a| self.engine.record_chain(&a.tid).any(|t| things.contains(&t)))
        })
    }

    /// Queues inbox blob `blob` for the inbox `label` of `actor` (its deposit seed signs, with
    /// a filler wrap), a seal of inbox delivery `delivery` when given.
    pub(crate) fn queue_inbox(&mut self, actor: &Tid, label: LabelId, hosts: &[Address], blob: Vec<u8>, delivery: Option<(Tid, CommitId)>) -> Result<()> {
        let Some(seed) = self.engine.get_typed(actor, &ct::KEYS)?.and_then(|k| k.deposit_seed) else {
            self.diag(format!("inbox blob for {actor}: no deposit seed held for the inbox"));
            return Ok(());
        };
        let d = osis_crypto::deposit_key(&osis_crypto::Secret32::from_bytes(seed), &label);
        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
        if !super::peers::hostless(hosts) {
            self.queue_deposit(label, hosts, &d, blob, wrap, delivery);
        } else if self.labels().iter().any(|(_, x)| x.id == label) {
            // an inbox this node reads and no host serves: deposited here, its other nodes get it
            // by their streams
            self.local_inbox.push((label, blob, wrap));
        } else {
            // one no host serves: a Deposit item to whichever of its nodes is connected first
            let sig = osis_label::sign_deposit(&d, &label, &osis_label::blob_id(&blob), &wrap);
            self.queue_out(label, super::state::Dest::Nodes(*actor), blob, wrap, sig, delivery);
        }
        Ok(())
    }

    /// Queues a deposit under `label`, signed now: kept durably until each of its hosts takes
    /// it, refuses it for good, or it is moot (`deposit_moot`); a crash, a cut or forgetting the
    /// label does not recall it.
    pub(crate) fn queue_deposit(&mut self, label: LabelId, hosts: &[Address], deposit: &osis_crypto::SigningSecret, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], delivery: Option<(Tid, CommitId)>) {
        let sig = osis_label::sign_deposit(deposit, &label, &osis_label::blob_id(&blob), &wrap);
        for host in hosts {
            self.queue_out(label, super::state::Dest::Host(host.clone()), blob.clone(), wrap, sig, delivery);
        }
    }

    /// Queues one signed deposit for `to`.
    fn queue_out(&mut self, label: LabelId, to: super::state::Dest, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], sig: osis_crypto::Signature, delivery: Option<(Tid, CommitId)>) {
        let k = (to.key(), label, osis_label::blob_id(&blob));
        self.state.add_out(super::state::OutRec { label, to, blob, wrap, sig, delivery });
        self.outbox.entry(k).or_default();
    }

    /// Whether inbox delivery `d` names a label this node is still opening (so maybe registering)
    /// at a connected host, and has at no other: its recipient would look for the label before it
    /// is there, and try again only after a back-off (a new chat's first invite). Ends with the
    /// reply on a live connection (a host silent to it while alive holds only what it alone could
    /// serve), and no connection holds nothing back: spec/sync.md §3.
    fn names_label_opening(&mut self, d: &(Tid, CommitId)) -> bool {
        let Some(things) = self.state.sent_inbox.get(d).map(|s| s.things.clone()) else { return false };
        let labels = self.labels();
        labels.iter().filter(|(g, l)| things.contains(g) && !l.replaced).any(|(_, l)| {
            let phases = || self.conns.values().filter(|c| c.session.is_ready() && l.hosts.iter().any(|a| a.key == c.host)).map(|c| c.labels.get(&l.id).map(|x| &x.phase));
            phases().any(|p| p.is_none_or(|x| matches!(x, Phase::Opening | Phase::Registering))) && !phases().any(|p| matches!(p, Some(Phase::Open | Phase::Verifying)))
        })
    }

    /// Sends queued deposits on connections to their hosts (no open needed), and logs those
    /// for labels synced with nobody here.
    pub(crate) fn send_outbox(&mut self, out: &mut Vec<Action>) -> Result<()> {
        for (l, blob, wrap) in std::mem::take(&mut self.local_inbox) {
            let blob_id = osis_label::blob_id(&blob);
            self.log_events(None, l, vec![osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None }], None, out)?;
        }
        let ready: Vec<(ConnId, [u8; 32])> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.host)).collect();
        let now = self.raw_now();
        let due: Vec<((HostKey, LabelId, BlobId), ConnId)> = self
            .outbox
            .iter()
            .filter(|(k, o)| k.0 != super::state::INBOX_NODES && o.sent.is_none() && o.after <= now)
            .filter_map(|(k, _)| ready.iter().find(|(_, s)| *s == k.0).map(|(c, _)| (*k, *c)))
            .collect();
        // what the host last said fits (`deposit_room`, unknown: all), with one unanswered at any
        // time to find out when a full budget frees: a deposit is its whole body, and a refused
        // one costs that again. A host lying low only slows its own label to one per round trip.
        let mut unanswered: BTreeMap<(HostKey, LabelId), u64> = BTreeMap::new();
        for k in self.outbox.iter().filter(|(_, o)| o.sent.is_some()).map(|(k, _)| k) {
            *unanswered.entry((k.0, k.1)).or_default() += 1;
        }
        for (k, conn) in due {
            let Some(o) = self.state.outbox.get(&k) else { continue };
            if o.delivery.is_some_and(|d| self.names_label_opening(&d)) {
                continue;
            }
            let at = (k.0, k.1);
            let n = unanswered.entry(at).or_default();
            if *n > 0 && *n >= self.deposit_room.get(&at).copied().unwrap_or(u64::MAX) {
                continue;
            }
            *n += 1;
            let Some(o) = self.state.outbox.get(&k) else { continue };
            let cmd = Command::Deposit { label: o.label, blob: o.blob.clone(), wrap: o.wrap, sig: o.sig };
            if let Some(m) = self.outbox.get_mut(&k) {
                m.sent = Some(conn);
            }
            self.command(conn, cmd, out)?;
        }
        // those for an inbox's nodes go as Deposit items on the shared sets
        self.shared_deposits(out)
    }
}
