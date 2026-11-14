//! Taking inbox blobs (spec/sync-inbox.md §2) and the invitations they leave
//! (spec/sync-set.md §4): an inbox blob opens under an actor whose `keys.0` names its sync ID as
//! its inbox; its removal signatures are kept whatever else happens to it (`records`); its
//! commit applies only once taken (held already, its sender connected, or the user accepted).
//! A taken blob boxing the recipient read applies as any commit; one boxing it sync alone writes a
//! sync record and applies nothing (spec/sync-judgement.md §6: no engine state of what S carries).
//! An untaken one waits, listed as an invitation, until judged again.

use super::{InboxOpened, Invitation, RemovalNotice, Taken};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, Value, WallMs};
use osis_commit::CommitBlob;
use osis_crypto::KemSecret;
use osis_keys::Opener;
use osis_label::{Inbox, InboxPayload, InboxRest, open_inbox_item};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `iw/` + blob ID: an inbox blob not taken (an invite request), with what it offers.
pub(crate) const WAITING: &[u8] = b"iw/";

/// An inbox blob held untaken: its commit, the things its boxes give the recipient with the role
/// each gives, its author, its expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitingBlob {
    pub sync_id: SyncId,
    pub commit: CommitId,
    pub things: Vec<(Tid, Role)>,
    pub from: Tid,
    pub expires: WallMs,
}

fn waiting_value(w: &WaitingBlob) -> Value {
    Value::List(vec![
        Value::Bytes(w.sync_id.0.to_vec()),
        Value::Bytes(w.commit.0.to_vec()),
        Value::List(w.things.iter().map(|(t, r)| Value::List(vec![Value::Tid(*t), Value::Int(i64::from(r.id()))])).collect()),
        Value::Tid(w.from),
        Value::Int(w.expires.0 as i64),
    ])
}

fn waiting_of(b: &[u8]) -> Result<WaitingBlob> {
    let bad = || Error::Corrupt("waiting inbox blob");
    let v = osis_base::decode(b, &osis_base::Limits { max_depth: 6, max_bytes: b.len() }).map_err(|_| bad())?;
    let Value::List(f) = v else { return Err(bad()) };
    let [Value::Bytes(s), Value::Bytes(c), Value::List(ts), Value::Tid(from), Value::Int(e)] = f.as_slice() else { return Err(bad()) };
    let mut things = Vec::new();
    for t in ts {
        let Value::List(p) = t else { return Err(bad()) };
        let [Value::Tid(t), Value::Int(r)] = p.as_slice() else { return Err(bad()) };
        things.push((*t, Role::from_id(u64::try_from(*r).map_err(|_| bad())?).ok_or_else(bad)?));
    }
    Ok(WaitingBlob {
        sync_id: SyncId(s.as_slice().try_into().map_err(|_| bad())?),
        commit: CommitId(c.as_slice().try_into().map_err(|_| bad())?),
        things,
        from: *from,
        expires: WallMs(u64::try_from(*e).map_err(|_| bad())?),
    })
}

/// `ih/` + thing: the sync ID a taken inbox blob named for a thing no applied `sync.0` gives one
/// it owns, and the blob's prefix expiry (spec/sync-inbox.md §2 Following a payload sync ID:
/// followed only while the blob is unexpired). Goes with the thing (`forget`).
pub(crate) const HINTS: &[u8] = b"ih/";

/// Keeps `s` as `t`'s hinted sync ID until `expires` (`None`: drops it). Keeping the hint held
/// writes nothing (an inbox blob taken again moves nothing that read the hints).
pub(crate) fn set_hint(tx: &mut Tx<'_>, t: &Tid, s: Option<(SyncId, WallMs)>) -> Result<()> {
    let k = [HINTS, t.as_bytes()].concat();
    match s {
        Some(h) if tx.core.ix.inbox_hints.get(t) == Some(&h) => {}
        Some((s, expires)) => {
            tx.txn.put_local(&k, &[&s.0[..], &expires.0.to_be_bytes()].concat(), Shred::No)?;
            tx.core.ix.inbox_hints.insert(*t, (s, expires));
        }
        None => {
            if tx.core.ix.inbox_hints.remove(t).is_some() {
                tx.txn.remove_local(&k, Shred::No)?;
            }
        }
    }
    Ok(())
}

/// Whether an applied `sync.0` records `s` (a payload naming it is no hint, spec/sync-inbox.md §2).
pub(crate) fn recorded(e: &Engine, s: &SyncId) -> bool {
    e.core.ix.sync_recorders.get(s).is_some_and(|x| !x.is_empty())
}

/// Loads the waiting inbox blobs and the hinted sync IDs (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut hints = Vec::new();
    tx.scan(HINTS, |k, v| {
        let bad = || Error::Corrupt("inbox hint");
        let (s, e) = (v.get(..16).ok_or_else(bad)?, v.get(16..).ok_or_else(bad)?);
        let hint = (SyncId(s.try_into().map_err(|_| bad())?), WallMs(u64::from_be_bytes(e.try_into().map_err(|_| bad())?)));
        hints.push((Tid::from_bytes(k.try_into().map_err(|_| bad())?), hint));
        Ok(())
    })?;
    for (t, s) in hints {
        tx.core.ix.inbox_hints.insert(t, s);
    }
    let mut rows = Vec::new();
    tx.scan(WAITING, |k, v| {
        rows.push((BlobId(k.try_into().map_err(|_| Error::Corrupt("waiting inbox blob"))?), waiting_of(&v)?));
        Ok(())
    })?;
    for (b, w) in rows {
        tx.core.ix.waiting_inbox.insert(b, Arc::new(w));
    }
    Ok(())
}

fn set_waiting(tx: &mut Tx<'_>, blob: &BlobId, w: Option<WaitingBlob>) -> Result<()> {
    let k = [WAITING, &blob.0].concat();
    match w {
        Some(w) => {
            tx.txn.put_local(&k, &osis_base::encode(&waiting_value(&w)), Shred::No)?;
            tx.core.ix.waiting_inbox.insert(*blob, Arc::new(w));
        }
        None => {
            if tx.core.ix.waiting_inbox.remove(blob).is_some() {
                tx.txn.remove_local(&k, Shred::No)?;
            }
        }
    }
    Ok(())
}

/// Drops the waiting rows whose blob expired by `now` (`retention::tick`).
pub(crate) fn expire_waiting(tx: &mut Tx<'_>, now: WallMs) -> Result<()> {
    let gone: Vec<BlobId> = tx.core.ix.waiting_inbox.iter().filter(|(_, w)| w.expires <= now).map(|(b, _)| *b).collect();
    for b in gone {
        set_waiting(tx, &b, None)?;
    }
    Ok(())
}

/// What an inbox blob's boxes give its recipient: per thing, the secrets of each role that open.
struct Boxed {
    things: BTreeMap<Tid, Vec<osis_keys::Opened>>,
}

impl Boxed {
    /// The highest role a box of `t` gives (Admin > Write > Read > Sync).
    fn role(&self, t: &Tid) -> Option<Role> {
        self.things.get(t)?.iter().map(|o| o.role).max()
    }
    fn reads(&self) -> bool {
        self.things.keys().any(|t| self.role(t) >= Some(Role::Read))
    }
}

impl Engine {
    /// The inbox blob `bytes` under inbox sync ID `s`, opened by an actor whose inbox `s` is
    /// (spec/sync-inbox.md §1: a blob is tried under each): the recipient, the blob's expiry, what
    /// it carries. `None`: none opens it.
    fn open_inbox_bytes(&mut self, s: &SyncId, bytes: &[u8]) -> Option<(Tid, WallMs, Inbox)> {
        // a blob whose prefix no inbox blob has (a commit's, under the inbox's own sync ID) is
        // opened by no key: told from its bytes alone, so it reads nothing that moves
        if !osis_label::Prefix::parse(bytes).is_ok_and(|p| p.inbox_shaped()) {
            return None;
        }
        let actors = self.inbox_actors().get(s).cloned().unwrap_or_default();
        for a in actors {
            let kems: Vec<KemSecret> = match self.core.accounts.contains_key(&a) {
                true => self.account_kems(&a),
                false => self.core.epochs(&a).map(|e| e.role(Role::Read).held_newest_first().into_iter().map(|(_, s)| osis_crypto::role_kem(s)).collect()).unwrap_or_default(),
            };
            for kem in &kems {
                osis_base::costs::count("inbox: open tried", 1);
                if let Ok((p, inbox)) = open_inbox_item(bytes, &a, kem) {
                    return Some((a, p.expiry().unwrap_or(WallMs(0)), inbox));
                }
            }
        }
        None
    }

    /// The secrets the boxes of commit `c` (`blob`) give recipient `a`, per thing.
    fn boxed_to(&self, a: &Tid, blob: &CommitBlob, c: &CommitId) -> Boxed {
        let keys = self.core.account_keys_by_name(a);
        let epochs = self.core.epochs(a);
        let mut things: BTreeMap<Tid, Vec<osis_keys::Opened>> = BTreeMap::new();
        for (t, w) in crate::apply::keys::pending_secrets_writes(blob, c) {
            let mut s = osis_schema::core_types::Secrets::default();
            w.apply(&mut s);
            let opener = match (self.core.accounts.contains_key(a), epochs.as_deref()) {
                (true, _) => Opener::Account { holder: *a, keys: &keys },
                (false, Some(e)) => Opener::Actor { holder: *a, epochs: e },
                (false, None) => continue,
            };
            let (opened, _) = osis_keys::open_boxes(&t, &s, &opener);
            if !opened.is_empty() {
                things.entry(t).or_default().extend(opened);
            }
        }
        Boxed { things }
    }

    /// Whether the sender of commit `blob` (`id`) is connected (spec/sync-inbox.md §2 Taking): its
    /// author a key actor whose record is held, under whose key the commit's signature verifies
    /// here (a sync-alone blob is never ingested: the header's author is the sender's word until
    /// then), with an effective role now on a thing in the sync set or up such a thing's record
    /// chain. Limit: an account whose contact card was imported is not counted (contact cards are
    /// not built).
    fn sender_connected(&mut self, blob: &CommitBlob, id: &CommitId) -> Result<bool> {
        let author = blob.header.author;
        let record = self.core.created(&author).cloned();
        if !matches!(record, Some(osis_base::CreationRecord::KeyActor { .. })) || crate::apply::signed_by_author(&self.core, blob, id, record.as_ref()) != Some(true) {
            return Ok(false);
        }
        let set = self.sync_set_now()?;
        let mut things: BTreeSet<Tid> = BTreeSet::new();
        for (t, _) in set.ids.values() {
            things.extend(self.core.record_chain(t).filter_map(|s| s.thing()));
        }
        Ok(things.iter().any(|t| self.core.role_now(&author, t).is_some()))
    }

    /// Takes the inbox blob `bytes` (ID `blob`) held under `s`: see the module doc. `accepted`:
    /// the user accepted it (spec/sync-set.md §4).
    pub(crate) fn take_inbox_bytes(&mut self, s: &SyncId, blob: &BlobId, bytes: &[u8], accepted: bool) -> Result<Option<InboxOpened>> {
        let Some((a, expires, inbox)) = self.open_inbox_bytes(s, bytes) else { return Ok(None) };
        // a stranded notice asks for a re-seal the recipient judges itself (spec/permissions.md
        // §4): not a role commit to take
        let Inbox::Payload(p) = inbox else { return Ok(Some(InboxOpened { commit: None, taken: Taken::Refused, hints: Vec::new(), dial: None })) };
        let (plain, rest) = InboxPayload::split(p);
        let InboxRest { things, chain, records, dial, removals } = rest;
        let cb = CommitBlob::decode(&plain)?;
        let id = cb.id();
        let notices: Vec<RemovalNotice> = removals.into_iter().map(|(sync_id, epoch, sig)| RemovalNotice { sync_id, epoch, sig, recipient: a, commit: id }).collect();
        let b = *blob;
        self.run(|tx| super::records::note_removals(tx, &b, expires, notices))?;
        let boxed = self.boxed_to(&a, &cb, &id);
        let held = self.core.ix.commits.contains_key(&id);
        let taken = held || accepted || self.sender_connected(&cb, &id)?;
        if !taken {
            let w = WaitingBlob { sync_id: *s, commit: id, things: boxed.things.keys().filter_map(|t| Some((*t, boxed.role(t)?))).collect(), from: cb.header.author, expires };
            self.run(|tx| set_waiting(tx, &b, Some(w)))?;
            return Ok(Some(InboxOpened { commit: Some(id), taken: Taken::Waiting, hints: Vec::new(), dial: None }));
        }
        self.run(|tx| set_waiting(tx, &b, None))?;
        let payload_ids: BTreeMap<Tid, SyncId> = things.iter().filter_map(|t| Some((t.tid, t.sync_id?))).collect();
        // sync alone: the sync record, nothing applied (spec/sync-judgement.md §6)
        if !boxed.reads() {
            let mut any = false;
            for (t, opened) in &boxed.things {
                let secrets: Vec<_> = opened.iter().filter(|o| o.role == Role::Sync).map(|o| (o.epoch, o.secret.clone())).collect();
                let ids: Vec<SyncId> = payload_ids.get(t).copied().into_iter().collect();
                let t = *t;
                any |= self.run(|tx| super::records::note_sync_secrets(tx, &t, &ids, secrets))?;
            }
            let taken = if any || held { Taken::Applied } else { Taken::Refused };
            return Ok(Some(InboxOpened { commit: Some(id), taken, hints: Vec::new(), dial }));
        }
        self.learn_records(records)?;
        // the author's chain first: a chain commit is judged alone, its refusal refuses nothing else
        for (c, _) in crate::flows::inbox_chain(chain) {
            if let Err(e) = self.ingest(&c, Vec::new()) && osis_base::Classified::class(&e) == osis_base::ErrorClass::Local {
                return Err(e);
            }
        }
        let taken = match self.ingest(&plain, Vec::new()) {
            Ok(_) => Taken::Applied,
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => return Err(e),
            Err(_) => Taken::Refused,
        };
        self.note_delete_hints(id, &things)?;
        // hints (spec/sync-inbox.md §2 Following a payload sync ID): for a thing whose read or
        // sync box opened and that it knows no sync ID of, a sync ID no applied `sync.0` records;
        // at most one per blob, while the blob is unexpired
        let mut hints = Vec::new();
        if taken == Taken::Applied {
            for (t, sid) in &payload_ids {
                if boxed.role(t).is_some() && !self.owned_sync_ids(t)?.iter().any(|o| !o.hint) && !recorded(self, sid) {
                    hints.push((*t, *sid));
                    let (t, sid) = (*t, *sid);
                    self.run(|tx| set_hint(tx, &t, Some((sid, expires))))?;
                    break;
                }
            }
        }
        Ok(Some(InboxOpened { commit: Some(id), taken, hints, dial }))
    }

    /// Takes inbox blob `bytes` under whichever inbox here opens it (tests: an inbox blob carried
    /// by hand, as sync would take it).
    #[doc(hidden)]
    pub fn take_inbox_blob(&mut self, bytes: &[u8], accepted: bool) -> Result<Option<InboxOpened>> {
        let b = osis_label::blob_id(bytes);
        let ids: Vec<SyncId> = self.inbox_actors().keys().copied().collect();
        for s in ids {
            if let Some(o) = self.take_inbox_bytes(&s, &b, bytes, accepted)? {
                return Ok(Some(o));
            }
        }
        Ok(None)
    }

    /// The invitations (spec/sync-set.md §4): the things a held inbox blob boxes this node's
    /// account or actors on, untaken, and the things the node holds a role on (secrets or a sync
    /// record) that no node's synced group closure holds, taken. The granting account of a taken
    /// one is the thing's first admin's account as this node knows it.
    pub(crate) fn invitations_now(&mut self) -> Result<Arc<Vec<Invitation>>> {
        let now = WallMs(self.core.time.get());
        let mut out: BTreeMap<Tid, Invitation> = BTreeMap::new();
        let next = self.core.ix.waiting_inbox.values().map(|w| w.expires.0).filter(|e| *e > now.0).min();
        self.core.time.until(next);
        for w in self.core.ix.waiting_inbox.values().filter(|w| w.expires > now) {
            for (t, role) in &w.things {
                out.entry(*t).or_insert(Invitation { thing: *t, role: *role, from: w.from, taken: false });
            }
        }
        let listed = self.synced_closures()?;
        let mut held: Vec<(Tid, Role)> = self.core.ix.sync_records.keys().map(|t| (*t, Role::Sync)).collect();
        let me = self.core.me();
        for t in self.core.ix.secrets.keys().copied().collect::<Vec<_>>() {
            if self.core.is_key_actor(&t) || self.core.accounts.get(&t).is_some() || self.core.of_devices(&t) {
                continue;
            }
            if let Some(r) = me.and_then(|m| self.core.role_now(&m, &t)) {
                held.push((t, r));
            }
        }
        for (t, role) in held {
            if listed.contains(&t) {
                continue;
            }
            let from = self.core.first_admin(&t).map(|a| self.core.home_owner(&a)).unwrap_or(t);
            out.entry(t).or_insert(Invitation { thing: t, role, from, taken: true });
        }
        Ok(Arc::new(out.into_values().collect()))
    }
}
