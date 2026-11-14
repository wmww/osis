//! Inbox deliveries (spec/sync-inbox.md §2): the role commits this node wrote that carry
//! something about an actor, owed to it by inbox blob (to a node: the commit itself, over a
//! connection) until the node sees it taken. The flow that writes the commit names the recipient
//! in the commit's own transaction (`owe`: which holders a rotation reaches depends on the boxes
//! they held before it, which the commit alone does not show); everything else is derived from
//! the commit when the blob is sealed: its parts, the things it names with their sync IDs and
//! delete keys, the author's chain and this node's dial hint. Re-sends,
//! back-offs and the per-connection state are sync's (`inbox`).

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{CommitId, Role, Tid, Value};
use osis_commit::CommitBlob;
use osis_crypto::NodeRng;
use osis_label::{DialHint, InboxPayload, InboxThing, seal_inbox_blob};
use osis_store::Shred;
use std::collections::BTreeSet;
use std::sync::Arc;

/// `ow/` + commit ID + holder: an inbox delivery owed.
pub(crate) const OWED: &[u8] = b"ow/";

/// What a delivery of a commit to one holder carries: the things the blob names, and whether only
/// its `roles.0` parts go (a lowering or removal: the rotation's boxes are not about the holder).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owed {
    pub things: Vec<Tid>,
    pub edge_only: bool,
}

fn owed_value(o: &Owed) -> Value {
    Value::List(vec![Value::List(o.things.iter().map(|t| Value::Tid(*t)).collect()), Value::Bool(o.edge_only)])
}

fn owed_of(b: &[u8]) -> Result<Owed> {
    let bad = || Error::Corrupt("owed delivery");
    let v = osis_base::decode(b, &osis_base::Limits { max_depth: 4, max_bytes: b.len() }).map_err(|_| bad())?;
    let Value::List(f) = v else { return Err(bad()) };
    let [Value::List(ts), Value::Bool(edge_only)] = f.as_slice() else { return Err(bad()) };
    let things = ts.iter().map(|t| if let Value::Tid(t) = t { Ok(*t) } else { Err(bad()) }).collect::<Result<_>>()?;
    Ok(Owed { things, edge_only: *edge_only })
}

/// Loads the owed deliveries (an open or reload).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(OWED, |k, v| {
        let bad = || Error::Corrupt("owed delivery");
        let c = CommitId(k.get(..32).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let h = Tid::from_bytes(k.get(32..).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        rows.push(((c, h), owed_of(&v)?));
        Ok(())
    })?;
    for (k, o) in rows {
        tx.core.ix.owed_inbox.insert(k, Arc::new(o));
    }
    Ok(())
}

/// Owes `holder` an inbox delivery of commit `c` naming `things`, in `c`'s own transaction (so a
/// crash loses nothing). A key actor that is neither a node nor an account (a link key) reads
/// its sync ID by static entry and is owed nothing.
pub(crate) fn owe(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid], edge_only: bool) -> Result<()> {
    if tx.core.is_key_actor(&holder) && !tx.core.is_account(&holder) && !crate::flows::is_node(tx, &holder)? {
        return Ok(());
    }
    let mut o = tx.core.ix.owed_inbox.get(&(c, holder)).map(|o| (**o).clone()).unwrap_or(Owed { things: Vec::new(), edge_only });
    for t in things {
        if !o.things.contains(t) {
            o.things.push(*t);
        }
    }
    o.edge_only &= edge_only;
    tx.txn.put_local(&[OWED, &c.0, h_bytes(&holder)].concat(), &osis_base::encode(&owed_value(&o)), Shred::No)?;
    tx.core.ix.owed_inbox.insert((c, holder), Arc::new(o));
    Ok(())
}

/// Drops delivery (`c`, `holder`) (`Engine::delivered`).
pub(crate) fn drop_owed(tx: &mut Tx<'_>, c: &CommitId, holder: &Tid) -> Result<()> {
    if tx.core.ix.owed_inbox.remove(&(*c, *holder)).is_some() {
        tx.txn.remove_local(&[OWED, &c.0, h_bytes(holder)].concat(), Shred::No)?;
    }
    Ok(())
}

/// Commit `c` is forgotten (`apply::unindex_commit`): nothing of it is owed any more.
pub(crate) fn forget(tx: &mut Tx<'_>, c: &CommitId) -> Result<()> {
    let holders: Vec<Tid> = tx.core.ix.owed_inbox.range((*c, Tid::from_bytes([0; 15]))..=(*c, Tid::from_bytes([0xff; 15]))).map(|((_, h), _)| *h).collect();
    for h in holders {
        drop_owed(tx, c, &h)?;
    }
    Ok(())
}

fn h_bytes(t: &Tid) -> &[u8] {
    t.as_bytes()
}

impl Engine {
    /// Whether this node has seen `holder` take its delivery of `c` (spec/sync-inbox.md §2
    /// Re-send): a held commit by the holder writing a thing the delivery names, stamped after
    /// `c` and opened here under a current read epoch of that thing (a secret only a grant at
    /// that epoch gives: a commit sealed under an older one may have been written before the
    /// holder took `c`, and shows nothing); or `c` is no longer held (forgotten: nothing to
    /// deliver). The other sign, an open by the holder of a sync ID the blob names, is sync's to
    /// see. Reads the delivery's keys and those commits' openings.
    pub(crate) fn delivery_taken_now(&mut self, c: &CommitId, holder: &Tid) -> Result<bool> {
        let Some(o) = self.core.ix.owed_inbox.get(&(*c, *holder)).cloned() else { return Ok(true) };
        let Some(ts) = self.core.ix.commits.get(c).map(|m| m.view.ts) else { return Ok(true) };
        for t in o.things.iter().copied() {
            let later: Vec<CommitId> = self.core.ix.by_thing.get(&(t, *holder)).map(|cs| cs.iter().filter(|x| *x != c && self.core.ix.commits.get(x).is_some_and(|m| m.view.ts > ts)).copied().collect()).unwrap_or_default();
            if later.is_empty() {
                continue;
            }
            let current: Vec<osis_crypto::Epoch> = self.current_read_secrets(&t).into_iter().map(|(e, _)| e).collect();
            for x in later {
                if self.read(|tx| crate::labeling::opened::opened_epochs(tx, &x, &t))?.iter().any(|e| current.contains(e)) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// The deliveries owed and not seen taken, whole (`delivery_feed` follows additions).
    pub(crate) fn deliveries_now(&mut self) -> Result<Arc<BTreeSet<(CommitId, Tid)>>> {
        let owed: Vec<(CommitId, Tid)> = self.core.ix.owed_inbox.keys().copied().collect();
        let mut out = BTreeSet::new();
        for (c, h) in owed {
            if !self.delivery_taken_now(&c, &h)? {
                out.insert((c, h));
            }
        }
        Ok(Arc::new(out))
    }

    /// The inbox blob of delivery (`c`, `holder`), sealed now to the holder's current KEM key
    /// (spec/wire.md §9): `None` for a holder with no inbox (a node is sent `c` itself), one whose
    /// keys are not known here, or a commit no longer held.
    pub(crate) fn inbox_blob_now(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>> {
        self.inbox_blob_with(c, holder, true, rng)
    }

    /// `inbox_blob` with no chain whatever the recipient reads (tests: the chain arriving apart).
    #[doc(hidden)]
    pub fn inbox_blob_without_chain(&mut self, c: &CommitId, holder: &Tid, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>> {
        self.inbox_blob_with(c, holder, false, rng)
    }

    fn inbox_blob_with(&mut self, c: &CommitId, holder: &Tid, with_chain: bool, rng: &mut dyn NodeRng) -> Result<Option<Vec<u8>>> {
        let Some(o) = self.core.ix.owed_inbox.get(&(*c, *holder)).cloned() else { return Ok(None) };
        if self.core.is_key_actor(holder) && !self.core.is_account(holder) {
            return Ok(None);
        }
        let (h, id) = (*holder, *c);
        // a holder of sync alone gets the boxes' part only (spec/sync-inbox.md §2): no edge,
        // keyset, step or record (the part's keys still name each holder boxed:
        // issues/sync-holder-roster.md)
        let sync_alone = !o.things.is_empty() && o.things.iter().all(|t| self.core.role_now(holder, t) == Some(Role::Sync));
        let Some((blob, things)) = self.read(|tx| {
            if crate::flows::edges::inbox_kem(tx, &h)?.is_none() {
                return Ok(None);
            }
            let Some(full) = tx.get_commit(&id)? else { return Ok(None) };
            let mut blob = Arc::unwrap_or_clone(full);
            if o.edge_only || sync_alone {
                let ak = if o.edge_only { "roles.0" } else { "secrets.0" };
                let keep: BTreeSet<usize> = blob.header.aspects.iter().enumerate().filter(|(_, a)| a.ak.as_str() == ak).map(|(i, _)| i).collect();
                blob.parts.retain(|p| keep.contains(&p.ai));
            }
            let mut things = Vec::new();
            for t in &o.things {
                let sync_id = crate::flows::home_sync_id(tx, t)?;
                let delete_keys = crate::engine::secrets::own_delete_keys(tx, t)?;
                things.push(InboxThing { tid: *t, sync_id, delete_keys });
            }
            things.sort_by_key(|t| t.tid);
            things.dedup_by_key(|t| t.tid);
            Ok(Some((blob, things)))
        })?
        else {
            return Ok(None);
        };
        let reads = o.things.iter().any(|t| self.core.role_now(holder, t) >= Some(Role::Read));
        // a recipient below read on every thing gets the boxes and sync IDs only (spec/wire.md §9
        // positions 2-3): no chain, no `keys.0`
        let (chain, records) = if reads && with_chain { self.chain_values(&id, &blob, holder)? } else { (Vec::new(), Vec::new()) };
        let commit = osis_base::decode(&blob.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).map_err(|_| Error::Corrupt("commit blob"))?;
        let payload = InboxPayload { commit, things, chain, records, dial: self.dial_hint()? };
        let now = self.now();
        let kem = self.read(|tx| crate::flows::edges::inbox_kem(tx, &h))?.ok_or(Error::Misuse("the holder's inbox key"))?;
        Ok(Some(seal_inbox_blob(holder, &kem, &payload, now, rng)?))
    }

    /// The commits logged with role commit `c` under the sync IDs it goes under (spec/crypto.md
    /// §4 Carried, names): the held rotation commits of the keysets its boxes to holder actors
    /// name, and of those its keysets record holder actors were left out at; and, for a rotation,
    /// the held commits its names point to (each epoch it introduces, as its history entries
    /// opened here name them).
    pub(crate) fn logged_with_now(&mut self, c: &CommitId) -> Result<Vec<CommitId>> {
        let Some(h) = self.header(c) else { return Ok(Vec::new()) };
        let id = *c;
        let mut out = Vec::new();
        for a in h.aspects.iter().filter(|a| a.ak.as_str() == "keys.0").map(|a| a.tid).collect::<BTreeSet<Tid>>() {
            let Some(ep) = self.epochs(&a) else { continue };
            for r in osis_keys::ROLES {
                for (e, info) in ep.role(r).epochs() {
                    if self.core.ix.epoch_intro.get(&(a, r, *e)).is_some_and(|x| x.1 == id) {
                        out.extend(info.names.iter().flat_map(|n| n.list.iter().map(|x| x.key.commit)).filter(|x| self.core.ix.commits.contains_key(x)));
                    }
                }
            }
        }
        let actors: BTreeSet<Tid> = h.aspects.iter().filter(|a| a.ak.as_str() == "secrets.0").map(|a| a.tid).collect();
        for a in actors {
            let (Some(si), ki) = (h.aspect_index(&a, "secrets.0"), h.aspect_index(&a, "keys.0")) else { continue };
            let (w, k) = self.read(|tx| {
                let w = crate::apply::held_fragment(tx, &id, si)?.map(|f| crate::apply::keys::secrets_write(&f));
                let k = match ki {
                    Some(ki) => crate::apply::held_fragment(tx, &id, ki)?.map(|f| crate::apply::keys::keys_write(&f)),
                    None => None,
                };
                Ok((w, k))
            })?;
            if let Some(w) = w {
                out.extend(crate::rotation::members::carried(&self.core, &w, k.as_ref()));
            }
        }
        out.sort();
        out.dedup();
        out.retain(|x| x != c);
        Ok(out)
    }

    /// The author's chain certificates for the parts `blob` carries (spec/permissions.md §4), each
    /// commit projected to its chain parts, as `CommitBlobPlaintext` values, without any `keys.0`
    /// but the author's own; and their creation records.
    /// When the commit boxes the recipient, also the current `keys.0` commit of each thing it boxes
    /// it on, projected to that delta (spec/wire.md §9 position 2).
    fn chain_values(&mut self, c: &CommitId, blob: &CommitBlob, holder: &Tid) -> Result<(Vec<Value>, Vec<osis_base::CreationRecord>)> {
        let parts: crate::labeling::Parts = blob.parts.iter().map(|p| p.ai).collect();
        let Some(mut certs) = self.author_chain(c, &parts) else { return Ok((Vec::new(), Vec::new())) };
        let boxed: BTreeSet<Tid> = crate::apply::keys::pending_secrets_writes(blob, c).into_iter().filter(|(_, w)| w.boxes.keys().any(|k| k.holder == *holder)).map(|(t, _)| t).collect();
        let mut boxed_keys: BTreeSet<(CommitId, usize)> = BTreeSet::new();
        for t in boxed {
            for k in self.current_keys(&t) {
                if let Some(ai) = self.header(&k).and_then(|h| h.aspect_index(&t, "keys.0")) {
                    certs.commits.entry(k).or_default().insert(ai);
                    boxed_keys.insert((k, ai));
                }
                certs.records.insert(t);
            }
        }
        let author = blob.header.author;
        let mut out = Vec::new();
        for (x, ps) in &certs.commits {
            let id = *x;
            let Some(full) = self.read(|tx| tx.get_commit(&id))? else { continue };
            let mut b = Arc::unwrap_or_clone(full);
            let keep: BTreeSet<usize> = ps.iter().copied().filter(|ai| b.header.aspects.get(*ai).is_some_and(|a| a.ak.as_str() != "keys.0" || a.tid == author || boxed_keys.contains(&(id, *ai)))).collect();
            b.parts.retain(|p| keep.contains(&p.ai));
            if b.parts.is_empty() {
                continue;
            }
            out.extend(osis_base::decode(&b.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).ok());
        }
        let records = certs.records.iter().filter_map(|t| self.core.created(t).cloned()).collect();
        Ok((out, records))
    }

    /// This node's dial hint (spec/wire.md §9 position 4): its `reach.0` dialable key and URL, as
    /// in its `dial^.0` entry (`Engine::publish_reach`).
    fn dial_hint(&mut self) -> Result<Option<DialHint>> {
        let me = self.core.id.tid();
        Ok(self.get_typed(&me, &osis_schema::core_types::REACH)?.map(|r| DialHint { dialable: r.dialable, urls: super::dial::urls_of(&r.items) }))
    }

}
