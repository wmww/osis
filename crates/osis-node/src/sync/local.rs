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

/// An inbox blob waiting to be deposited at a server.
#[derive(Clone)]
pub(crate) struct Outgoing {
    pub label: LabelId,
    pub server: Address,
    pub blob: Vec<u8>,
    /// The actor whose `/keys` named the inbox (its deposit seed signs).
    pub owner: Tid,
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
        let l = self.engine.create_label(g, servers, &mut *self.rng)?;
        Ok((l, self.handle(super::Event::Local)))
    }

    /// Sends a signal about `t` under every open label holding it (spec/sync.md §9): under the
    /// write key when this node writes the label, else the deposit key; also fires this node's
    /// own listeners.
    pub fn signal(&mut self, t: &Tid, kind: Ak, value: Value, target: Option<Tid>) -> Result<Vec<Action>> {
        if self.engine.role_on(t) < Some(Role::Write) {
            return Err(Error::Permission { tid: *t });
        }
        let me = self.engine.tid();
        let ts = Ts::make(self.engine.now(), 0).ok_or(Error::Misuse("clock out of range"))?;
        let body = SignalBody { node: me, actor: me, ts, tid: *t, kind: kind.clone(), target, schema: None, value: value.clone() };
        let mut out = Vec::new();
        let mut sent = BTreeSet::new();
        for (conn, l, g) in self.labels_holding(t) {
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
        self.engine.core.events.queue(crate::Event::Signal { kind, from: me, value });
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
        let me = self.engine.tid();
        let now = self.engine.now();
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
            if std::env::var_os("OSIS_SYNC_TRACE").is_some() {
                eprintln!("compact {c:?}: may {may} keep {:?} covered {:?}", self.engine.body_keep(&c, t, ak)?.at_least, self.engine.covered(&s, &c, t, ak)?);
            }
            if !may || self.engine.body_keep(&c, t, ak)?.at_least > now.0 || self.engine.covered(&s, &c, t, ak)? != Some(true) {
                continue;
            }
            self.engine.drop_body(&c, t, ak)?;
        }
        Ok(self.handle(super::Event::Local))
    }

    /// Places commit `c`'s deltas on `aspects` as a certificate copy under every label of `g`
    /// (spec/permissions.md §3, §4): a fresh encryption per label, uploaded or deposited at the
    /// label's next pass.
    pub fn place_certificate(&mut self, g: &Tid, c: &CommitId, aspects: &BTreeSet<usize>) -> Result<Vec<Action>> {
        let labels: Vec<LabelId> = self.engine.group_labels(g)?.into_iter().filter(|l| !l.replaced).map(|l| l.id).collect();
        for l in labels {
            if self.state.certs.contains(&(l, *c)) {
                continue;
            }
            let Some(secret) = self.engine.wrap_secret(g, None)? else { continue };
            for b in self.engine.partial_bodies(c, aspects)? {
                let s = seal_body(&b, &mut *self.rng)?;
                self.engine.put_blobs(vec![(s.id, s.blob)])?;
                self.state.add_blob(s.id, super::state::BlobRec { commit: b.commit, parts: b.parts.clone(), key: s.key.clone(), cert: true });
                let wrap = osis_crypto::wrap(&secret, &s.id, &s.key)?;
                self.state.set_entry(l, s.id, Entry { wrap, stamp: None, cert: true, kind: Kind::Commit { commit: b.commit, parts: b.parts.clone() } });
            }
            self.state.add_cert(l, *c);
        }
        Ok(self.handle(super::Event::Local))
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
        for server in inbox.servers {
            self.outbox.push(Outgoing { label: inbox.label, server, blob: blob.clone(), owner });
        }
        Ok(self.handle(super::Event::Local))
    }

    /// Deposits waiting inbox blobs on connections to their servers (no open needed).
    pub(crate) fn send_outbox(&mut self, out: &mut Vec<Action>) -> Result<()> {
        let ready: Vec<(ConnId, [u8; 32])> = self.conns.iter().filter(|(_, c)| c.session.is_ready()).map(|(id, c)| (*id, c.server)).collect();
        let mut keep = Vec::new();
        for o in std::mem::take(&mut self.outbox) {
            let Some((conn, _)) = ready.iter().find(|(_, k)| *k == o.server.key) else {
                keep.push(o);
                continue;
            };
            let seed = self.engine.get_typed(&o.owner, &ct::KEYS)?.and_then(|k| k.deposit_seed);
            let Some(seed) = seed else { continue };
            let d = osis_crypto::deposit_key(&osis_crypto::Secret32::from_bytes(seed), &o.label);
            let wrap = osis_crypto::filler_wrap(&mut *self.rng);
            let sig = osis_label::sign_deposit(&d, &o.label, &osis_label::blob_id(&o.blob), &wrap);
            self.command(*conn, Command::Deposit { label: o.label, blob: o.blob, wrap, sig }, out)?;
        }
        self.outbox = keep;
        Ok(())
    }
}
