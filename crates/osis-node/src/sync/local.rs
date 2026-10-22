//! Requests of the app and of membership flows: signals (spec/sync.md §9), compaction
//! (spec/sync.md §7), certificate placement under a group's labels (spec/permissions.md §3, §4:
//! the grantee's `/keys`, a removal's new `/keys`), inbox delivery (spec/sync.md §3), label
//! creation.

use super::state::{Entry, Kind};
use super::{Action, ConnId, Phase, SyncEngine};
use crate::error::{Error, Result};
use crate::labeling::seal_body;
use osis_core::{Ak, CommitId, LabelId, Role, Tid, Ts, Value};
use osis_label::{Address, InboxPayload, InboxThing, PublishAuth, PublishKey, SignalBody};
use osis_perm::{At, PurgeBy};
use osis_proto::Command;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Refusals of one queued deposit before it is dropped (label not registered, rate limit, full
/// budget, stale head).
pub(crate) const MAX_INBOX_TRIES: u32 = 8;

/// Re-sends of an inbox delivery whose member never acts (local policy; one per
/// `INBOX_LIFETIME`).
const MAX_INBOX_RESENDS: u32 = 3;

/// A deposit waiting for its server (`SyncEngine::queue_deposit`).
#[derive(Clone)]
pub(crate) struct Outgoing {
    pub label: LabelId,
    pub server: Address,
    pub blob: Vec<u8>,
    pub wrap: [u8; osis_crypto::WRAP_LEN],
    pub sig: osis_crypto::Signature,
    /// Not sent before this raw wall ms (a refused deposit backs off from `retry_ms`).
    pub after: u64,
    /// Refusals so far (`MAX_INBOX_TRIES` then dropped with a diagnostic).
    pub tries: u32,
}

impl SyncEngine {
    /// Open connections and labels whose group's closure holds `t`.
    fn labels_holding(&mut self, t: &Tid) -> Vec<(ConnId, LabelId, Tid)> {
        let mut out = Vec::new();
        let opened: Vec<(ConnId, LabelId, Tid)> = self.conns.iter().flat_map(|(id, c)| c.labels.iter().filter(|(_, l)| l.phase == Phase::Open).map(move |(lid, l)| (*id, *lid, l.group))).collect();
        for (c, l, g) in opened {
            if self.engine.closure(&g).contains(t) {
                out.push((c, l, g));
            }
        }
        out
    }

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

    /// Sends a signal about `t` under every open label holding it (spec/sync.md §9): under the
    /// write key when this node writes the label, else the deposit key; also fires this node's
    /// own listeners.
    pub fn signal(&mut self, t: &Tid, kind: Ak, value: Value, target: Option<Tid>) -> Result<Vec<Action>> {
        let me = self.engine.tid();
        self.signal_as(t, me, kind, value, target)
    }

    /// `signal` for `actor` (an actor this node writes for: the receivers check it).
    pub fn signal_as(&mut self, t: &Tid, actor: Tid, kind: Ak, value: Value, target: Option<Tid>) -> Result<Vec<Action>> {
        if self.engine.role_on(t) < Some(Role::Write) {
            return Err(Error::Permission { tid: *t });
        }
        let me = self.engine.tid();
        if actor != me && self.engine.role_on(&actor) < Some(Role::Write) {
            return Err(Error::Permission { tid: actor });
        }
        let ts = Ts::make(self.engine.now(), 0).ok_or(Error::Misuse("clock out of range"))?;
        let body = SignalBody { node: me, actor, ts, tid: *t, kind: kind.clone(), target, schema: None, value: value.clone() };
        let mut out = Vec::new();
        let mut sent = BTreeSet::new();
        for (conn, l, g) in self.labels_holding(t) {
            if self.uncovered(&g)?.contains(&Role::Read) {
                continue;
            }
            let Some(secret) = self.engine.wrap_secret(&g, None)? else { continue };
            let Some(keys) = self.conns.get(&conn).and_then(|c| c.labels.get(&l)).map(|x| x.keys.clone()) else { continue };
            let (key, blob) = osis_label::seal_signal(&body, &self.engine.identity().keys().signing, &mut *self.rng)?;
            let id = osis_label::blob_id(&blob);
            let wrap = osis_crypto::wrap(&secret, &id, &key)?;
            let auth = match (&keys.write, &keys.deposit) {
                (Some(w), _) => PublishAuth::sign(PublishKey::Write, w, &l, &id, &wrap),
                (None, Some(d)) => PublishAuth::sign(PublishKey::Deposit, d, &l, &id, &wrap),
                _ => continue,
            };
            sent.insert(l);
            self.command(conn, Command::Signal { label: l, blob, wrap, auth }, &mut out)?;
        }
        self.engine.core.events.queue(crate::Event::Signal { tid: *t, kind, from: me, actor, ts, target, value });
        self.engine.core.events.flush();
        self.signals.push(body);
        self.state.flush(&mut self.engine)?;
        Ok(out)
    }

    /// Compacts `(t, ak)` (spec/sync.md §7): writes a snapshot from this node's state, then
    /// drops the bodies it covers that this node may purge and whose keep-at-least bound has
    /// passed; the next pass uploads the snapshot and deletes the dropped bodies at servers once
    /// the snapshot is there.
    pub fn compact(&mut self, t: &Tid, ak: &Ak) -> Result<Vec<Action>> {
        let Some(s) = self.engine.snapshot(t, ak)? else { return Ok(Vec::new()) };
        self.drop_covered(t, ak, &s)?;
        Ok(self.handle(super::Event::Local))
    }

    /// Drops the bodies of `(t, ak)` that snapshot `s` covers, that this node may purge and
    /// whose keep-at-least bound has passed (spec/sync.md §7: the compactor, and every other
    /// right holder as it sees the snapshot); `s` carries them. Returns whether a body may still
    /// go later (its keep-at-least bound ahead, or not established covered or uncovered yet):
    /// the snapshot is judged again, so what a node drops depends on what it holds, not on when
    /// it first saw the snapshot.
    pub(crate) fn drop_covered(&mut self, t: &Tid, ak: &Ak, s: &CommitId) -> Result<bool> {
        let s = *s;
        let me = self.engine.tid();
        let now = self.engine.now();
        let mut later = false;
        let held: Vec<CommitId> = self.engine.core.by_aspect.get(&(*t, ak.clone())).map(|x| x.iter().map(|(_, c)| *c).collect()).unwrap_or_default();
        for c in held {
            if c == s || !self.engine.holds_body(&c, t, ak) {
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
            let covered = self.engine.covered(&s, &c, t, ak)?;
            if covered.is_none() || covered == Some(true) && self.engine.body_keep(&c, t, ak)?.at_least > now.0 {
                later = true;
                continue;
            }
            if covered != Some(true) {
                continue;
            }
            // covered-equal snapshots: only the higher commit ID goes (spec/sync.md §7), as in
            // the must-hold judgment, or this node drops the one a co-writer keeps uploading
            let snapshot = matches!(h.kind, osis_commit::Kind::ContentSnapshot | osis_commit::Kind::MembershipSnapshot);
            if snapshot && c < s && self.engine.covered(&c, &s, t, ak)? == Some(true) {
                continue;
            }
            self.engine.drop_body(&c, t, ak)?;
            self.state.set_carrier(c, s);
        }
        Ok(later)
    }

    /// Places commit `c`'s deltas on `aspects` as a certificate copy under every label of `g`
    /// (spec/permissions.md §3, §4): a fresh encryption per label, uploaded or deposited at the
    /// label's next pass.
    pub fn place_certificate(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        self.place_certificate_in(g, c, aspects)?;
        Ok(self.handle(super::Event::Local))
    }

    pub(crate) fn place_certificate_in(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<()> {
        let labels: Vec<LabelId> = self.engine.group_labels(g)?.into_iter().filter(|l| !l.replaced).map(|l| l.id).collect();
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
        for l in labels {
            if self.state.certs.contains(&(l, *c)) {
                continue;
            }
            for b in self.engine.partial_bodies(c, aspects)? {
                // a rotation-carrying copy is wrapped like the body (spec/crypto.md §5): other
                // members take it as the body's entry
                let Some(secret) = self.engine.wrap_secret(g, Some((&b.commit, &b.parts)))? else { continue };
                let s = seal_body(&b, &mut *self.rng)?;
                self.engine.put_blobs(vec![(s.id, s.blob)])?;
                self.state.add_blob(s.id, super::state::BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert: true });
                let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
                self.state.set_entry(l, s.id, Entry { wrap, stamp: None, cert: true, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone() } });
            }
            let parts = self.engine.header(c).map(|h| h.aspects.iter().enumerate().filter(|(i, _)| aspects.contains(i)).flat_map(|(i, a)| (0..a.hashes.len()).map(move |d| (i, d))).collect()).unwrap_or_default();
            self.place_linked(l, c, &parts)?;
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
        let kept = |ak: &str| ct::is_membership_class(ak) || matches!(ak, "/created" | "/node" | "/reach" | "/seen");
        // content commits' chunks and pages go too
        if !self.replaced_leftovers(&server, &l).is_empty() {
            return Ok(());
        }
        for b in self.state.present_at(&server, &l) {
            let Some(Kind::Commit { commit, parts }) = self.state.entries.get(&(l, b)).map(|e| &e.kind) else { continue };
            let Some(h) = self.engine.header(commit) else { return Ok(()) };
            if parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| !kept(a.ak.as_str())) {
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
        let mut inbox = keys.inbox.clone();
        let mut cur = *recipient;
        let mut owner = *recipient;
        for _ in 0..64 {
            if inbox.is_some() {
                break;
            }
            let Some(osis_core::CreationRecord::Thing { owner: up, .. }) = self.engine.core.created(&cur).cloned() else { break };
            cur = up;
            inbox = self.engine.get_typed(&cur, &ct::KEYS)?.and_then(|k| k.inbox);
            owner = cur;
        }
        let inbox = inbox.ok_or(Error::Misuse("recipient has no inbox"))?;
        let mut things: Vec<InboxThing> = Vec::new();
        let tids: BTreeSet<Tid> = cut.header.aspects.iter().map(|a| a.tid).collect();
        for t in tids {
            for gl in self.engine.group_labels(&t)? {
                if !gl.replaced {
                    things.push(InboxThing { tid: t, label: gl.id, servers: gl.servers });
                    break;
                }
            }
        }
        let commit = osis_core::decode(&cut.encode(), &osis_core::Limits { max_depth: osis_core::format::MAX_OBJECT_DEPTH, max_bytes: osis_core::format::MAX_MESSAGE })
            .map_err(|_| Error::Corrupt("commit blob"))?;
        let payload = InboxPayload { commit, things };
        let blob = osis_label::seal_inbox_blob(recipient, &kem, &payload, self.engine.now(), &mut *self.rng)?;
        self.queue_inbox(&owner, inbox.label, &inbox.servers, blob)?;
        Ok(self.handle(super::Event::Local))
    }

    /// Inbox deliveries `INBOX_LIFETIME` old whose member has not acted are sealed again (to its
    /// newest keyset) and sent again (spec/sync.md §3), at most `MAX_INBOX_RESENDS` times; one
    /// whose commit is gone, or whose member acted, is forgotten.
    pub(crate) fn resend_inbox(&mut self) -> Result<()> {
        let now = self.now();
        let due: Vec<super::state::SentInbox> = self.state.sent_inbox.values().filter(|s| s.at.saturating_add(osis_core::format::INBOX_LIFETIME_MS) <= now).cloned().collect();
        for s in due {
            let ts = self.engine.header(&s.commit).map(|h| h.ts);
            if !ts.is_some_and(|ts| s.tries < MAX_INBOX_RESENDS && !self.acted(&s.member, ts)) || !s.edge_only && !self.still_member(&s.member, &s.commit) {
                self.state.remove_sent(&s.member, &s.commit);
                continue;
            }
            let parts = if s.edge_only { crate::flows::edges::Parts::Edge } else { crate::flows::edges::Parts::All };
            // a removal notice names no label: a removed member must not learn the target's
            // current one
            let things = if s.edge_only { Vec::new() } else { s.things.clone() };
            let r = self.engine.run(|tx| crate::flows::edges::deliver_parts(tx, s.member, s.commit, &things, parts));
            match r {
                Ok(deliveries) if !deliveries.is_empty() => self.take_done(crate::flows::Done { deliveries, ..Default::default() })?,
                // no inbox or keys for the member any more
                _ => self.state.remove_sent(&s.member, &s.commit),
            }
        }
        Ok(())
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
        self.engine.core.commits.values().any(|m| {
            let h = &m.header;
            h.ts > since && (h.author == *member || h.actor == *member || tl.is_some_and(|tl| tl.role(&h.author, member, At::now(h.ts)).is_some()))
        })
    }

    /// Queues inbox blob `blob` for the inbox `label` of `owner` (its deposit seed signs, with
    /// a filler wrap).
    pub(crate) fn queue_inbox(&mut self, owner: &Tid, label: LabelId, servers: &[Address], blob: Vec<u8>) -> Result<()> {
        let Some(seed) = self.engine.get_typed(owner, &ct::KEYS)?.and_then(|k| k.deposit_seed) else {
            self.diag(format!("inbox blob for {owner}: no deposit seed held for the inbox"));
            return Ok(());
        };
        let d = osis_crypto::deposit_key(&osis_crypto::Secret32::from_bytes(seed), &label);
        let wrap = osis_crypto::filler_wrap(&mut *self.rng);
        self.queue_deposit(label, servers, &d, blob, wrap);
        Ok(())
    }

    /// Queues a deposit under `label`, signed now: kept durably until each of its servers answers
    /// (a crash, a cut or forgetting the label does not recall it), and logged here when this
    /// node serves the label to nobody else's server.
    pub(crate) fn queue_deposit(&mut self, label: LabelId, servers: &[Address], deposit: &osis_crypto::SigningSecret, blob: Vec<u8>, wrap: [u8; osis_crypto::WRAP_LEN]) {
        let sig = osis_label::sign_deposit(deposit, &label, &osis_label::blob_id(&blob), &wrap);
        if servers.iter().all(super::peers::is_peer) && self.labels().iter().any(|(_, x)| x.id == label) {
            self.local_inbox.push((label, blob.clone(), wrap));
        }
        for server in servers {
            let o = Outgoing { label, server: server.clone(), blob: blob.clone(), wrap, sig, after: 0, tries: 0 };
            self.state.add_out(super::state::OutRec { label, server: o.server.clone(), blob: o.blob.clone(), wrap, sig });
            self.outbox.push(o);
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
        let mut keep = Vec::new();
        for o in std::mem::take(&mut self.outbox) {
            let Some((conn, _)) = ready.iter().find(|(_, k)| *k == o.server.key).filter(|_| o.after <= now) else {
                keep.push(o);
                continue;
            };
            let id = osis_label::blob_id(&o.blob);
            self.inbox_sent.insert((o.server.key, id), (*conn, o.clone()));
            self.command(*conn, Command::Deposit { label: o.label, blob: o.blob, wrap: o.wrap, sig: o.sig }, out)?;
        }
        self.outbox = keep;
        Ok(())
    }
}
