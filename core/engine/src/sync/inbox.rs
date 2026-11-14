//! Taking inbox blobs (spec/sync-inbox.md §2) and the invitations they leave
//! (spec/sync-set.md §4): an inbox blob opens under an actor whose `keys.0` names its sync ID as
//! its inbox; its commit applies only once taken (held already, its sender connected, or the user accepted).
//! A taken blob boxing the recipient read applies as any commit; one boxing it sync alone writes a
//! sync record and applies nothing (spec/sync-judgement.md §6: no engine state of what S carries).
//! An untaken one waits, listed as an invitation, until judged again.

use super::{InboxOpened, Invitation, Taken};
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, CommitId, Role, SyncId, Tid, Value, WallMs};
use osis_commit::CommitBlob;
use osis_crypto::KemSecret;
use osis_keys::Opener;
use osis_label::{BoxesPayload, Inbox, InboxPayload, InboxRest, open_inbox_item};
use osis_schema::core_types as ct;
use osis_schema::RawKey;
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
        Some(w) if tx.core.ix.waiting_inbox.get(blob).is_some_and(|x| **x == w) => {}
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
        self.open_boxes_of(a, crate::apply::keys::pending_secrets_writes(blob, c).into_iter().map(|(t, w)| {
            let mut s = osis_schema::core_types::Secrets::default();
            w.apply(&mut s);
            (t, s)
        }))
    }

    /// The secrets a boxes payload's boxes give its recipient `a`, per thing: each box opened
    /// with the AD rebuilt from its thing, `a`, its role and epoch (spec/wire.md §9).
    fn boxes_payload_to(&self, a: &Tid, p: &BoxesPayload) -> Boxed {
        self.open_boxes_of(a, p.things.iter().map(|t| {
            let boxes = t.boxes.iter().map(|(r, e, b)| (osis_schema::core_types::BoxKey { holder: *a, role: *r, epoch: e.clone() }, b.clone())).collect();
            (t.tid, osis_schema::core_types::Secrets { boxes, history: BTreeMap::new() })
        }))
    }

    fn open_boxes_of(&self, a: &Tid, per_thing: impl Iterator<Item = (Tid, osis_schema::core_types::Secrets)>) -> Boxed {
        let keys = self.core.account_keys_by_name(a);
        let epochs = self.core.epochs(a);
        let mut things: BTreeMap<Tid, Vec<osis_keys::Opened>> = BTreeMap::new();
        for (t, s) in per_thing {
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
        // a held commit's signature was checked once here, its verdict kept with it
        let known = self.core.ix.commits.get(id).map(|m| m.signed);
        if !matches!(record, Some(osis_base::CreationRecord::KeyActor { .. })) || crate::apply::signed_by_author(&self.core, blob, id, record.as_ref(), known) != Some(true) {
            return Ok(false);
        }
        self.author_connected(&author)
    }

    /// Whether `author` has an effective role now on a thing in the sync set or up such a thing's
    /// record chain (spec/sync-inbox.md §2 Taking, connected).
    fn author_connected(&mut self, author: &Tid) -> Result<bool> {
        let set = self.sync_set_now()?;
        let mut things: BTreeSet<Tid> = BTreeSet::new();
        for (t, _) in set.ids.values() {
            things.extend(self.core.record_chain(t).filter_map(|s| s.thing()));
        }
        Ok(things.iter().any(|t| self.core.role_now(author, t).is_some()))
    }

    /// Takes boxes payload `p` to `a` (spec/sync-inbox.md §2 Taking): refused when its signature
    /// fails under its author's key held here; taken whole when the user accepted it or its
    /// signature verifies under a connected author's key, else for the things it boxes `a` on
    /// that a synced group's closure lists; the sync secrets of the boxes taken that open go into
    /// their things' sync records with its sync IDs and dial hint (spec/sync-judgement.md §6),
    /// and nothing else.
    fn take_boxes(&mut self, s: &SyncId, blob: &BlobId, a: &Tid, expires: WallMs, p: BoxesPayload, accepted: bool) -> Result<Option<InboxOpened>> {
        let id = p.commit;
        let refused = |dial| Ok(Some(InboxOpened { commit: Some(id), taken: Taken::Refused, hints: Vec::new(), dial }));
        let verified = match crate::apply::signing_key_at(&self.core, &p.author, p.epoch) {
            Ok(Some(k)) if p.verifies(a, &k) => true,
            Ok(None) => false,
            _ => return refused(None),
        };
        let boxed = self.boxes_payload_to(a, &p);
        // accepted or by a connected author: every thing; else only those a synced group's
        // closure lists (the signature unchecked, a box there gives nothing else)
        let whole = accepted || (verified && self.author_connected(&p.author)?);
        let listed = if whole { BTreeSet::new() } else { self.synced_closures()? };
        let take: Vec<&osis_label::BoxedThing> = p.things.iter().filter(|x| whole || listed.contains(&x.tid)).collect();
        let b = *blob;
        // the things not taken stay an invite request
        let rest: Vec<(Tid, Role)> = boxed.things.keys().filter(|t| !take.iter().any(|x| x.tid == **t)).filter_map(|t| Some((*t, boxed.role(t)?))).collect();
        let w = (!rest.is_empty()).then_some(WaitingBlob { sync_id: *s, commit: id, things: rest, from: p.author, expires });
        self.run(|tx| set_waiting(tx, &b, w))?;
        if take.is_empty() {
            return Ok(Some(InboxOpened { commit: Some(id), taken: Taken::Waiting, hints: Vec::new(), dial: None }));
        }
        let mut any = false;
        for t in take {
            let secrets: Vec<_> = boxed.things.get(&t.tid).into_iter().flatten().filter(|o| o.role == Role::Sync && o.epoch.names(&t.tid, Role::Sync, &o.secret)).map(|o| (o.epoch, o.secret.clone())).collect();
            if secrets.is_empty() {
                continue;
            }
            any = true;
            let (tid, ids) = (t.tid, t.sync_id.into_iter().collect::<Vec<_>>());
            self.run(|tx| super::records::note_sync_secrets(tx, &tid, &ids, secrets, p.dial.as_ref()))?;
        }
        if !any {
            return refused(p.dial);
        }
        Ok(Some(InboxOpened { commit: Some(id), taken: Taken::Applied, hints: Vec::new(), dial: p.dial }))
    }

    /// Takes the inbox blob `bytes` (ID `blob`) held under `s`: see the module doc. `accepted`:
    /// the user accepted it (spec/sync-set.md §4).
    pub(crate) fn take_inbox_bytes(&mut self, s: &SyncId, blob: &BlobId, bytes: &[u8], accepted: bool) -> Result<Option<InboxOpened>> {
        let Some((a, expires, inbox)) = self.open_inbox_bytes(s, bytes) else { return Ok(None) };
        // a stranded notice asks for a re-seal the recipient judges itself (spec/permissions.md
        // §4): not a role commit to take
        let p = match inbox {
            Inbox::Payload(p) => p,
            Inbox::Boxes(p) => return self.take_boxes(s, blob, &a, expires, p, accepted),
            Inbox::Stranded(_) => return Ok(Some(InboxOpened { commit: None, taken: Taken::Refused, hints: Vec::new(), dial: None })),
        };
        let (plain, rest) = InboxPayload::split(p);
        let InboxRest { things, chain, records, dial } = rest;
        let cb = CommitBlob::decode(&plain)?;
        let id = cb.id();
        let b = *blob;
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
        // boxes giving sync alone: the sync record, nothing applied (spec/sync-judgement.md §6);
        // a payload boxing nothing (a removal's edges) is applied
        if !boxed.things.is_empty() && !boxed.reads() {
            let mut any = false;
            for (t, opened) in &boxed.things {
                let secrets: Vec<_> = opened.iter().filter(|o| o.role == Role::Sync).map(|o| (o.epoch, o.secret.clone())).collect();
                let ids: Vec<SyncId> = payload_ids.get(t).copied().into_iter().collect();
                let t = *t;
                any |= self.run(|tx| super::records::note_sync_secrets(tx, &t, &ids, secrets, dial.as_ref()))?;
            }
            let taken = if any || held { Taken::Applied } else { Taken::Refused };
            return Ok(Some(InboxOpened { commit: Some(id), taken, hints: Vec::new(), dial }));
        }
        let chain: Vec<Vec<u8>> = crate::flows::inbox_chain(chain).into_iter().map(|(c, _)| c).collect();
        let mut taken = self.take_payload(&chain, &plain)?;
        // its records learned only where what it brought awaits them (with their record chains),
        // then taken again: a part thrown out for one joins (spec/commits.md §4 Pending storage)
        let batch: BTreeMap<Tid, osis_base::CreationRecord> = records.into_iter().map(|r| (r.tid(), r)).filter(|(t, _)| self.core.created(t).is_none()).collect();
        let seeds: Vec<Tid> = batch.keys().filter(|t| crate::apply::awaits_record(&self.core, t)).copied().collect();
        let learn = super::with_chains(&self.core, seeds, &batch);
        if self.learn_records(learn)? > 0 {
            taken = self.take_payload(&chain, &plain)?;
        }
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

    /// Ingests an inbox payload's chain commits, then its commit: a chain commit is judged alone,
    /// its refusal refuses nothing else.
    fn take_payload(&mut self, chain: &[Vec<u8>], plain: &[u8]) -> Result<Taken> {
        for c in chain {
            if let Err(e) = self.ingest(c, Vec::new()) && osis_base::Classified::class(&e) == osis_base::ErrorClass::Local {
                return Err(e);
            }
        }
        match self.ingest(plain, Vec::new()) {
            Ok(_) => Ok(Taken::Applied),
            Err(e) if osis_base::Classified::class(&e) == osis_base::ErrorClass::Local => Err(e),
            Err(_) => Ok(Taken::Refused),
        }
    }

    /// Opens inbox blob `bytes` under whichever inbox here opens it, taking nothing (tests: what
    /// a recipient learns from it).
    #[doc(hidden)]
    pub fn open_inbox_blob(&mut self, bytes: &[u8]) -> Option<Inbox> {
        let ids: Vec<SyncId> = self.inbox_actors().keys().copied().collect();
        ids.iter().find_map(|s| self.open_inbox_bytes(s, bytes)).map(|(_, _, i)| i)
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

    /// The invitations (spec/sync-set.md §4): the things no node's synced group closure holds
    /// that a held inbox blob boxes this node's account or actors on (untaken) or that this node
    /// holds a role on (`Core::held_role`, taken); each acted on while `acted^.0` on D lists it.
    /// The granting account of a taken one is the thing's first admin's account as known here.
    pub(crate) fn invitations_now(&mut self) -> Result<Arc<Vec<Invitation>>> {
        let now = WallMs(self.core.time.get());
        let acted = match self.core.account_devices() {
            Some((_, d)) => self.get_typed(&d, &ct::ACTED)?.unwrap_or_default(),
            None => BTreeSet::new(),
        };
        let mut out: BTreeMap<Tid, Invitation> = BTreeMap::new();
        let next = self.core.ix.waiting_inbox.values().map(|w| w.expires.0).filter(|e| *e > now.0).min();
        self.core.time.until(next);
        let listed = self.synced_closures()?;
        for w in self.core.ix.waiting_inbox.values().filter(|w| w.expires > now) {
            for (t, role) in w.things.iter().filter(|(t, _)| !listed.contains(t)) {
                out.entry(*t).or_insert(Invitation { thing: *t, role: *role, from: w.from, taken: false, acted: acted.contains(t) });
            }
        }
        let held: BTreeSet<Tid> = self.core.ix.sync_records.keys().chain(self.core.ix.secrets.keys()).copied().collect();
        for t in held {
            if listed.contains(&t) || out.contains_key(&t) {
                continue;
            }
            let Some(role) = self.core.held_role(&t) else { continue };
            let from = self.core.first_admin(&t).map(|a| self.core.home_owner(&a)).unwrap_or(t);
            out.insert(t, Invitation { thing: t, role, from, taken: true, acted: acted.contains(&t) });
        }
        Ok(Arc::new(out.into_values().collect()))
    }
}

impl crate::engine::Core {
    /// The role an invitation of `t` gives (spec/sync-set.md §4), whether or not a synced group
    /// lists it: sync while this node holds a sync record of it; else the account's role on it,
    /// when `t` has secrets held here and is no key actor, account or thing of D.
    pub(crate) fn held_role(&self, t: &Tid) -> Option<Role> {
        if self.ix.sync_records.contains_key(t) {
            return Some(Role::Sync);
        }
        if !self.ix.secrets.contains_key(t) || self.is_key_actor(t) || self.accounts.get(t).is_some() || self.of_devices(t) {
            return None;
        }
        self.role_now(&self.me()?, t)
    }
}

/// Marks what local write `tx` acted on as invitations (spec/sync-set.md §4 Acted): each thing a
/// held inbox blob offers or `held_role` gives a role (none the write created: a content commit
/// gives no secrets) that was in no synced group's closure when the write began and is listed by
/// it in a group (an accept, or filing it elsewhere), or that was in one and is in none after it
/// (an unsync). Each is added to `acted^.0` on D, in a commit of its own in the same transaction.
/// Costs nothing without a listing change; else a walk up from each thing listed and the
/// subtrees cut (spec/sync-set.md §2 Cost).
pub(crate) fn mark_acted(tx: &mut Tx<'_>) -> Result<()> {
    let changed = tx.core.ix.groups.changed();
    if changed.is_empty() {
        return Ok(());
    }
    let Some((_, d)) = tx.core.account_devices() else { return Ok(()) };
    let synced = tx.state(&d, &ct::SYNCED.name())?.and_then(osis_crdt::Fragment::read).and_then(|v| ct::SYNCED.decode(&v).ok());
    let roots: BTreeSet<Tid> = match synced {
        Some(m) if !m.is_empty() => m.into_values().collect(),
        _ => [d].into(),
    };
    let groups = &tx.core.ix.groups;
    let (mut listed, mut subs, mut items) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (_, f, t, now) in changed {
        if now {
            listed.insert(t);
        } else if f == crate::engine::groups::SUBGROUPS {
            subs.insert(t);
        } else {
            items.insert(t);
        }
    }
    // a cut subgroup takes its closure with it; a cut item only itself
    let mut left = groups.closures_at_start(&subs);
    left.extend(items);
    let was_synced = groups.under_at_start(&listed.union(&left).copied().collect(), &roots);
    let mut acted: BTreeSet<Tid> = listed.difference(&was_synced).copied().collect();
    acted.extend(left.intersection(&was_synced).filter(|t| !groups.under(t, &roots)));
    if acted.is_empty() {
        return Ok(());
    }
    let waiting: BTreeSet<Tid> = tx.core.ix.waiting_inbox.values().flat_map(|w| w.things.iter().map(|(t, _)| *t)).collect();
    acted.retain(|t| waiting.contains(t) || tx.core.held_role(t).is_some());
    if acted.is_empty() {
        return Ok(());
    }
    // a thing marked already adds nothing: such a commit changes nothing and is not written
    let mut m = crate::Mutation::new();
    for t in acted {
        m.op(d, &ct::ACTED, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Tid(t)) })?;
    }
    crate::engine::write::commit_in(tx, m)?;
    Ok(())
}
