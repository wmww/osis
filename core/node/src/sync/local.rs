//! Requests of the app and of membership flows: compaction
//! (spec/sync.md §7), certificate placement under a group's labels (spec/permissions.md §3, §4:
//! the grantee's `/keys`, a removal's new `/keys`), inbox delivery (spec/sync.md §3), label
//! creation.

use super::state::{Entry, Kind, ServerKey};
use super::{Action, ConnId, Phase, SyncEngine};
use crate::error::{Error, Result};
use crate::labeling::seal_body;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, BlobId, CommitId, LabelId, Role, Tid, Ts};
use osis_label::{Address, InboxPayload, InboxThing};
use osis_perm::{At, PurgeBy};
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Longest wait between sends of a queued deposit refused for now (`retry_ms` doubling per
/// refusal up to this). Minor consequence: at 0 a refused deposit is resent on every tick, at
/// infinity it lands that much later after the refusal clears (a recipient back online).
pub(crate) const DEPOSIT_RETRY_CAP_MS: u64 = 3_600_000;

/// Re-sends of an inbox delivery whose member never acts (local policy; one per
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
    /// Creates a label for group `g` at `servers` (an admin; spec/sync.md §2) and connects.
    pub fn create_label(&mut self, g: &Tid, servers: Vec<Address>) -> Result<(LabelId, Vec<Action>)> {
        let (l, done) = self.engine.create_label(g, &servers)?;
        self.take_done(done)?;
        Ok((l, self.handle(super::Event::Local)))
    }

    /// Replaces label `old` of `g` (spec/sync.md §2; an admin, `Engine::replace_label`: the
    /// admin rotation if the loss calls for it, a new label at the same servers, the old one
    /// marked replaced); passes then upload the live blobs under the new label, and under the
    /// old one (an admin keeps syncing it until done there, `labels`) only membership-class
    /// commits, the replacement's `/label` among them, deleting its content entries;
    /// certificates stay.
    pub fn replace_label(&mut self, g: &Tid, old: &LabelId) -> Result<(LabelId, Vec<Action>)> {
        let (new, done) = self.engine.replace_label(g, old)?;
        self.take_done(done)?;
        Ok((new, self.handle(super::Event::Local)))
    }

    /// Compacts `(t, ak)` (spec/sync.md §7): writes a snapshot from this node's state, then
    /// drops the bodies it covers that this node may purge and whose keep-at-least bound is
    /// `MAX_DRIFT` past; the next pass uploads the snapshot and deletes the dropped bodies at servers once
    /// the snapshot is there. Nothing when the snapshot would be a carrier only (spec/commits.md §5).
    pub fn compact(&mut self, t: &Tid, ak: &Ak) -> Result<Vec<Action>> {
        let Some(s) = self.engine.compaction_snapshot(t, ak)? else { return Ok(Vec::new()) };
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
        // a carrier-only snapshot drops nothing (spec/commits.md §5)
        if self.engine.carrier_only(&s, t, ak) {
            return Ok(Vec::new());
        }
        let me = self.engine.tid();
        let now = self.engine.now();
        let held: Vec<CommitId> = match only {
            Some(o) => o.to_vec(),
            None => self.engine.core.ix.by_aspect.get(&(*t, ak.clone())).map(|x| x.iter().map(|(_, c)| *c).collect()).unwrap_or_default(),
        };
        let mut dropped = Vec::new();
        for c in held {
            if c == s {
                continue;
            }
            // a settled judgment holds while both bodies are held (a pair goes once either is
            // dropped: a drop is a trigger, so the pair is looked at then)
            let k = (s, c, *t, ak.clone());
            let both = self.engine.body_not_dropped(&s, t, ak) && self.engine.body_not_dropped(&c, t, ak);
            if self.covered_judged.contains(&k) {
                if both {
                    continue;
                }
                self.covered_judged.remove(&k);
            }
            if !self.engine.body_not_dropped(&c, t, ak) {
                continue;
            }
            let Some(h) = self.engine.header(&c) else { continue };
            let Some(a) = h.aspects.iter().find(|x| x.tid == *t && x.ak == *ak) else { continue };
            let by = PurgeBy::from_code(a.retention.by as u64).unwrap_or(PurgeBy::Nobody);
            let ts = Ts::make(now, 0).unwrap_or_default();
            let may = match self.engine.core.timelines.get(t) {
                Some(tl) => tl.may_purge(&me, t, by, &h.actor, At::now(ts)),
                None => by != PurgeBy::Nobody && self.engine.role_on(t) >= Some(Role::Admin),
            };
            if !may {
                continue;
            }
            // MAX_DRIFT past the bound: a node whose clock lags by up to that still holds the
            // body must-hold and would place it again
            let due = self.engine.body_keep(&c, t, ak)?.at_least.saturating_add(MAX_DRIFT_MS);
            if due > now.0 {
                left.at(due, c);
                continue;
            }
            match self.engine.covered(&s, &c, t, ak)? {
                // not established yet: judged again
                None => {
                    left.commits.insert(c);
                    continue;
                }
                Some(false) => {
                    self.covered_judged.insert((s, c, *t, ak.clone()));
                    continue;
                }
                Some(true) => {}
            }
            // covered-equal snapshots: only the higher commit ID goes (spec/sync.md §7), as in
            // the must-hold judgment, or this node drops the one a co-writer keeps uploading
            if super::pass::is_snapshot(h.kind) && c < s && self.engine.covered(&c, &s, t, ak)? == Some(true) {
                self.covered_judged.insert((s, c, *t, ak.clone()));
                continue;
            }
            self.engine.drop_body(&c, t, ak)?;
            self.state.set_carrier(c, s);
            self.touched.commits.insert(c);
            dropped.push(c);
        }
        Ok(dropped)
    }

    /// Places commit `c`'s deltas on `aspects` as a certificate copy under every label of `g`
    /// (spec/permissions.md §3, §4): a fresh encryption per label, uploaded or deposited at the
    /// label's next pass.
    pub fn place_certificate(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        self.place_certificate_in(g, c, aspects)?;
        Ok(self.handle(super::Event::Local))
    }

    /// `place_certificate`. A copy of this node's own write under a label it does not write
    /// (its invite grant, self-removal, chain) is also queued as a deposit (`queue_deposit`),
    /// so it reaches the label even when this node loses the label before a server answers:
    /// other nodes may hold parts of the commit from elsewhere and wait for the rest.
    pub(crate) fn place_certificate_in(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<()> {
        let labels: Vec<(LabelId, Vec<Address>)> = self.engine.group_labels(g)?.into_iter().filter(|l| !l.replaced).map(|l| (l.id, l.servers)).collect();
        if labels.is_empty() {
            return Ok(());
        }
        // placing never rotates (a rotation's own copies placed here recursed into rotations):
        // under an epoch that does not cover a known departure it waits for the next pass,
        // which rotates first
        if self.uncovered_now(g)?.contains(&Role::Read) {
            self.deferred.push((*g, *c, aspects.clone()));
            return Ok(());
        }
        let own = self.engine.core.ix.commits.get(c).is_some_and(|m| m.origin == crate::events::Origin::Local);
        let seed = if own && self.engine.role_on(&self.engine.group_actor(g)) < Some(Role::Write) { self.engine.deposit_seed(g)? } else { None };
        for (l, servers) in labels {
            if self.state.certs.contains(&(l, *c)) {
                continue;
            }
            let deposit = seed.as_ref().map(|s| osis_crypto::deposit_key(s, &l));
            for b in self.engine.partial_bodies(c, aspects)? {
                // a rotation-carrying copy is wrapped like the body (spec/crypto.md §5): other
                // members take it as the body's entry
                let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { continue };
                let s = seal_body(&b, &mut *self.rng)?;
                let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
                if let Some(d) = &deposit {
                    self.queue_deposit(l, &servers, d, s.blob.clone(), wrap, None);
                }
                self.engine.put_blobs(vec![(s.id, s.blob)])?;
                self.state.add_blob(s.id, super::state::BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert: true });
                self.state.set_entry(l, s.id, Entry { wrap, stamp: None, cert: true, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone(), salt: s.salt } });
            }
            let parts = self.engine.header(c).map(|h| super::pass::parts_of(&h, |i| aspects.contains(&i))).unwrap_or_default();
            self.place_linked(l, c, &parts)?;
            if let Some(d) = &deposit {
                for id in self.engine.linked_blobs(c, &parts)? {
                    let wrap = self.state.entries.get(&(l, id)).map(|e| e.wrap);
                    if let (Some(wrap), Some(blob)) = (wrap, self.engine.blob(&id)?) {
                        self.queue_deposit(l, &servers, d, blob, wrap, None);
                    }
                }
            }
            self.state.add_cert(l, *c);
        }
        Ok(())
    }

    /// After a settled pass of replaced label `l` of `g` at `server` that had nothing left to
    /// upload (`quiet`): done there when no content entry is present any more (spec/sync.md §2:
    /// membership-class commits, the replacement's `/label` among them, and certificates stay);
    /// once done at every server of the label (or no key opens it there), this admin stops
    /// syncing it for good; `labels` retires it after `MEMBERSHIP_KEEP` whatever.
    pub(crate) fn retire_at(&mut self, server: super::state::ServerKey, g: &Tid, l: LabelId) -> Result<()> {
        // content commits' chunks and pages go too
        if !self.replaced_leftovers(&server, &l).is_empty() {
            return Ok(());
        }
        for b in self.state.present_at(&server, &l) {
            let Some(Kind::Commit { commit, parts, .. }) = self.state.entries.get(&(l, b)).map(|e| &e.kind) else { continue };
            let Some(h) = self.engine.header(commit) else { return Ok(()) };
            if parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| !super::pass::kept_when_replaced(a.ak.as_str())) {
                return Ok(());
            }
        }
        self.retired_at.insert((server, l));
        let servers: Vec<_> = self.engine.group_labels(g)?.into_iter().find(|x| x.id == l).map(|x| x.servers).unwrap_or_default();
        // a server where no key opens the label (taken by whoever replaced it) counts as done
        let failed = |k: &super::state::ServerKey| self.conns.values().any(|c| c.server == *k && c.labels.get(&l).is_some_and(|x| x.phase == Phase::Failed));
        if servers.iter().all(|a| self.retired_at.contains(&(a.key, l)) || failed(&a.key)) {
            self.state.retire(l);
        }
        Ok(())
    }

    /// The blobs a certificate copy of `parts` of `c` links (header lists, linked frontiers) as
    /// certificate entries under `l` (spec/sync.md §3), so a verifier that syncs nothing else
    /// under the label resolves them.
    pub(crate) fn place_linked(&mut self, l: LabelId, c: &CommitId, parts: &BTreeSet<(usize, usize)>) -> Result<()> {
        for b in self.engine.linked_blobs(c, parts)? {
            if !self.state.entries.contains_key(&(l, b)) {
                let wrap = osis_crypto::filler_wrap(&mut *self.rng);
                self.state.set_entry(l, b, Entry { wrap, stamp: None, cert: true, kind: Kind::Unknown });
            }
        }
        Ok(())
    }

    /// Delivers commit `c`'s deltas on `aspects` to actor `recipient` as an inbox blob
    /// (spec/sync.md §3; spec/crypto.md §5): sealed to its read keyset's KEM key, with the label
    /// IDs and servers of the things the commit names, deposited under its inbox (its `/keys`,
    /// else the nearest owner-chain actor's).
    pub fn deliver_inbox(&mut self, recipient: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        let id = *c;
        let blob = self.engine.run(|tx| tx.get_commit(&id))?.ok_or(Error::UnknownCommit(id))?;
        let cut = osis_commit::rewrite(&blob, |ai, _| !aspects.contains(&ai));
        let keys = self.engine.get_typed(recipient, &ct::KEYS)?.ok_or(Error::UnknownThing(*recipient))?;
        let ks = keys.read.as_ref().ok_or(Error::Misuse("recipient has no read keyset"))?;
        let ct::KemKey::X25519MlKem768(kb) = &ks.kem_key;
        let kem = osis_crypto::KemPublicKey::from_slice(kb)?;
        let mut inbox = keys.inbox.clone().map(|i| (i, *recipient));
        let chain: Vec<Tid> = self.engine.owner_chain(recipient).skip(1).collect();
        for t in chain {
            if inbox.is_some() {
                break;
            }
            inbox = self.engine.get_typed(&t, &ct::KEYS)?.and_then(|k| k.inbox).map(|i| (i, t));
        }
        let (inbox, owner) = inbox.ok_or(Error::Misuse("recipient has no inbox"))?;
        let mut things: Vec<InboxThing> = Vec::new();
        let tids: BTreeSet<Tid> = cut.header.aspects.iter().map(|a| a.tid).collect();
        for t in tids {
            for gl in self.engine.group_labels(&t)? {
                if !gl.replaced {
                    let delete_keys = self.engine.own_delete_keys(&t)?;
                    things.push(InboxThing { tid: t, label: gl.id, index: gl.index, servers: gl.servers, delete_keys });
                    break;
                }
            }
        }
        let commit = osis_base::decode(&cut.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_MESSAGE })
            .map_err(|_| Error::Corrupt("commit blob"))?;
        let payload = InboxPayload { commit, things };
        let blob = osis_label::seal_inbox_blob(recipient, &kem, &payload, self.engine.now(), &mut *self.rng)?;
        self.queue_inbox(&owner, inbox.label, &inbox.servers, blob, None)?;
        Ok(self.handle(super::Event::Local))
    }

    /// Inbox deliveries from their records (spec/sync.md §3, §5): one not sent yet (`at` 0) is
    /// sealed and sent at once; one `INBOX_LIFETIME` old whose member
    /// has not acted is sealed again (to its newest keyset) and sent again, at most
    /// `MAX_INBOX_RESENDS` times; one whose commit is gone, or whose member acted or (for a grant
    /// or re-seal) left, is forgotten.
    pub(crate) fn send_inbox(&mut self) -> Result<()> {
        let now = self.now();
        let due: Vec<super::state::SentInbox> = self.state.sent_inbox.values().filter(|s| s.at == 0 || s.at.saturating_add(osis_base::format::INBOX_LIFETIME_MS) <= now).cloned().collect();
        for s in due {
            let first = s.at == 0;
            let ts = self.engine.header(&s.commit).map(|h| h.ts);
            let gone = match ts {
                None => true,
                Some(ts) => !first && (s.tries >= MAX_INBOX_RESENDS || self.acted(&s.member, ts)),
            };
            if gone || !s.edge_only && !self.still_member(&s.member, &s.commit) {
                self.forget_delivery(&s.member, &s.commit);
                continue;
            }
            let parts = if s.edge_only { crate::flows::edges::Parts::Edge } else { crate::flows::edges::Parts::All };
            // a re-sent removal notice names no label: a removed member must not learn the
            // target's current one
            let things = if s.edge_only && !first { Vec::new() } else { s.things.clone() };
            let r = self.engine.run(|tx| crate::flows::edges::deliver_parts(tx, s.member, s.commit, &things, parts));
            // a new seal replaces the earlier one still queued
            self.drop_delivery_out(&s.member, &s.commit);
            let mut sent = false;
            for d in r.unwrap_or_default() {
                if let crate::flows::Delivery::Inbox { to, inbox, blob, .. } = d {
                    let owner = self.inbox_owner(&to, &inbox.label)?.unwrap_or(to);
                    self.queue_inbox(&owner, inbox.label, &inbox.servers, blob, Some((s.member, s.commit)))?;
                    sent = true;
                }
            }
            if sent {
                self.state.note_sent(s.member, s.commit, s.things.clone(), s.edge_only, now);
            } else {
                // no inbox or keys for the member any more
                self.forget_delivery(&s.member, &s.commit);
            }
        }
        Ok(())
    }

    /// Forgets inbox delivery `(member, c)` and its seals still queued.
    fn forget_delivery(&mut self, member: &Tid, c: &CommitId) {
        self.state.remove_sent(member, c);
        self.drop_delivery_out(member, c);
    }

    /// Drops the queued seals of inbox delivery `(member, c)`.
    fn drop_delivery_out(&mut self, member: &Tid, c: &CommitId) {
        let k = Some((*member, *c));
        let ks: Vec<(ServerKey, LabelId, BlobId)> = self.state.outbox.iter().filter(|(_, o)| o.delivery == k).map(|(x, _)| *x).collect();
        for (s, l, b) in ks {
            self.outbox.remove(&(s, l, b));
            self.state.remove_out(&s, &l, &b);
        }
    }

    /// Whether a queued deposit refused for now (`SyncEngine::budget`) is moot, so it is dropped
    /// rather than sent again: an inbox seal whose delivery is gone, or a deposit under a label
    /// this node sees replaced (spec/sync.md §2: no new step is issued for it, and what still
    /// matters goes under the new label). Anything else waits for its label to take it.
    pub(crate) fn deposit_moot(&mut self, server: &ServerKey, l: &LabelId, b: &BlobId) -> bool {
        let Some(o) = self.state.outbox.get(&(*server, *l, *b)) else { return true };
        if let Some(k) = o.delivery {
            return !self.state.sent_inbox.contains_key(&k);
        }
        self.group_of(l).is_some_and(|g| self.is_replaced(&g, l))
    }

    /// Signs queued deposit `(server, l, b)` again with the label's current deposit key (an
    /// inbox's from its owner's `/keys`), after its server found it signed by an earlier one;
    /// false when this node holds no other key, so it can never be taken.
    pub(crate) fn resign_deposit(&mut self, server: &ServerKey, l: &LabelId, b: &BlobId) -> Result<bool> {
        let Some(o) = self.state.outbox.get(&(*server, *l, *b)).cloned() else { return Ok(false) };
        let seed = match o.delivery {
            Some((member, _)) => {
                let owner = self.inbox_owner(&member, l)?.unwrap_or(member);
                self.engine.get_typed(&owner, &ct::KEYS)?.and_then(|k| k.deposit_seed).map(osis_crypto::Secret32::from_bytes)
            }
            None => match self.group_of(l) {
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

    /// Whether `member` is still a current member of a thing whose edges or secrets commit `c`
    /// writes (a grant or re-seal is re-sent only while the member holds what it gave; a removal
    /// since then must not hand it the target's current label).
    fn still_member(&self, member: &Tid, c: &CommitId) -> bool {
        let Some(h) = self.engine.header(c) else { return false };
        let targets: BTreeSet<Tid> = h.aspects.iter().filter(|a| matches!(a.ak.as_str(), "/members" | "/secrets")).map(|a| a.tid).collect();
        targets.iter().any(|t| self.engine.core.current_members(t).iter().any(|(m, _, _)| m == member))
    }

    /// Whether `member` acted after `since` as this node sees it: a held commit newer than that
    /// by the member, for it, or by a node with a role on it (its devices).
    fn acted(&self, member: &Tid, since: Ts) -> bool {
        let tl = self.engine.core.timelines.get(member);
        // the views: O(commits) without decoding headers
        self.engine.core.ix.commits.values().any(|m| {
            let h = &m.view;
            h.ts > since && (h.author == *member || h.actor == *member || tl.is_some_and(|tl| tl.role(&h.author, member, At::now(h.ts)).is_some()))
        })
    }

    /// Queues inbox blob `blob` for the inbox `label` of `owner` (its deposit seed signs, with
    /// a filler wrap), a seal of inbox delivery `delivery` when given.
    pub(crate) fn queue_inbox(&mut self, owner: &Tid, label: LabelId, servers: &[Address], blob: Vec<u8>, delivery: Option<(Tid, CommitId)>) -> Result<()> {
        let Some(seed) = self.engine.get_typed(owner, &ct::KEYS)?.and_then(|k| k.deposit_seed) else {
            self.diag(format!("inbox blob for {owner}: no deposit seed held for the inbox"));
            return Ok(());
        };
        let d = osis_crypto::deposit_key(&osis_crypto::Secret32::from_bytes(seed), &label);
        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
        // an inbox this node serves to nobody else's server: deposited here
        if servers.iter().all(super::peers::is_peer) && self.labels().iter().any(|(_, x)| x.id == label) {
            self.local_inbox.push((label, blob.clone(), wrap));
        }
        self.queue_deposit(label, servers, &d, blob, wrap, delivery);
        Ok(())
    }

    /// Queues a deposit under `label`, signed now: kept durably until each of its servers takes
    /// it, refuses it for good, or it is moot (`deposit_moot`); a crash, a cut or forgetting the
    /// label does not recall it.
    pub(crate) fn queue_deposit(&mut self, label: LabelId, servers: &[Address], deposit: &osis_crypto::SigningSecret, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN], delivery: Option<(Tid, CommitId)>) {
        let sig = osis_label::sign_deposit(deposit, &label, &osis_label::blob_id(&blob), &wrap);
        let id = osis_label::blob_id(&blob);
        for server in servers {
            self.state.add_out(super::state::OutRec { label, server: server.clone(), blob: blob.clone(), wrap, sig, delivery });
            self.outbox.entry((server.key, label, id)).or_default();
        }
    }

    /// Sends queued deposits on connections to their servers (no open needed), and logs those
    /// for labels synced with nobody here.
    pub(crate) fn send_outbox(&mut self, out: &mut Vec<Action>) -> Result<()> {
        for (l, blob, wrap) in std::mem::take(&mut self.local_inbox) {
            let blob_id = osis_label::blob_id(&blob);
            self.log_events(None, l, vec![osis_proto::Event::Added { blob_id, blob: Some(blob), wrap, stamp: None }], None, out)?;
        }
        let ready: Vec<(ConnId, [u8; 32])> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.server)).collect();
        let now = self.raw_now();
        let due: Vec<((ServerKey, LabelId, BlobId), ConnId)> = self
            .outbox
            .iter()
            .filter(|(_, o)| o.sent.is_none() && o.after <= now)
            .filter_map(|(k, _)| ready.iter().find(|(_, s)| *s == k.0).map(|(c, _)| (*k, *c)))
            .collect();
        for (k, conn) in due {
            let Some(o) = self.state.outbox.get(&k) else { continue };
            let cmd = Command::Deposit { label: o.label, blob: o.blob.clone(), wrap: o.wrap, sig: o.sig };
            if let Some(m) = self.outbox.get_mut(&k) {
                m.sent = Some(conn);
            }
            self.command(conn, cmd, out)?;
        }
        Ok(())
    }
}
