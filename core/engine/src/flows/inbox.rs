//! The inbox thing and its open signals (spec/sync-inbox.md §1, §2, §5): `ticket@~0`,
//! `removal@~0` and `stranded@~0`, fired sealed by anyone holding the inbox's public key record,
//! promoted by a writer. Filled by lane (c) of issues/reference-graph.md.

use super::Done;
use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_crdt::{Op, PathOp};
use osis_store::Shred;
use std::sync::Arc;
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{Ak, CommitId, Tid, Ticket, Value};
use osis_schema::core_types::{self as ct, RetentionEntry, RetentionSetting};
use std::collections::BTreeMap;

/// Arriving tickets (spec/sync-inbox.md §1).
pub const TICKET_FIRE: &str = Ak::check("ticket@~0", true);
/// Removal notices.
pub const REMOVAL_FIRE: &str = Ak::check("removal@~0", true);
/// Stranded notices.
pub const STRANDED_FIRE: &str = Ak::check("stranded@~0", true);

/// Gives the account's new inbox `i` own keys and its history setting: each of its three signals
/// kept `INBOX_LIFETIME` (spec/sync-inbox.md §1), in the account's creation.
pub(crate) fn make_inbox(tx: &mut Tx<'_>, i: Tid, done: &mut Done) -> Result<()> {
    crate::rotation::own_secrets(tx, i, done)?;
    let keep = RetentionEntry { history: Some(osis_schema::History::Keep { until: None, after: Some(INBOX_LIFETIME_MS) }), ..RetentionEntry::default() };
    let mut rules = BTreeMap::new();
    for k in [TICKET_FIRE, REMOVAL_FIRE, STRANDED_FIRE] {
        rules.insert(super::ak(k)?, keep);
    }
    let mut m = Mutation::new();
    m.set(i, &ct::RETENTION, &RetentionSetting::from(rules))?;
    done.add(Engine::commit_tx(tx, m)?);
    Ok(())
}

/// Fires on `holder`'s inbox the ticket role commit `c` owes it about `things` (spec/sync-inbox.md
/// §5): a grant's, a key change's or a re-seal's.
pub(crate) fn fire_ticket(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid]) -> Result<()> {
    let _ = (tx, holder, c, things);
    // refgraph: (c) fire the ticket
    Ok(())
}

/// Fires on `holder`'s inbox the removal notice of role commit `c` lowering its edge on `target`
/// below read (spec/sync-inbox.md §5).
pub(crate) fn fire_removal(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let _ = (tx, holder, c, target);
    // refgraph: (c) fire the removal notice
    Ok(())
}

impl Engine {
    /// Account `a`'s inbox thing, as its `keys.0` names it (spec/sync-inbox.md §1); an actor with
    /// own keys that is no account is its own inbox.
    pub fn inbox_thing(&mut self, a: &Tid) -> Option<Tid> {
        if self.core.is_account(a) {
            return self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(Tid::from);
        }
        self.core.has_own_secrets(a).then_some(*a)
    }

    /// The held ticket for `t` this node can open (spec/data-model.md §8 Tickets, spec/sync-set.md §2):
    /// found among the known references by `t`'s tid.
    pub fn ticket_for(&mut self, t: &Tid) -> Result<Option<Ticket>> {
        let _ = t;
        todo!("refgraph: (c) ticket lookup")
    }

    /// Acts on a removal notice fired on this account's inbox (spec/sync-inbox.md §5): checked
    /// against the member list held for its thing, then the thing released or a copy retained.
    pub fn take_removal_notice(&mut self, fire: &CommitId) -> Result<()> {
        let _ = fire;
        todo!("refgraph: (c) removal notices")
    }

    /// Fires a stranded notice on the thing of sync ID `s` (spec/sync-inbox.md §5), naming
    /// `holder` for its writers to re-seal.
    pub fn fire_stranded(&mut self, s: &osis_base::SyncId, holder: &Tid) -> Result<()> {
        let _ = (s, holder);
        todo!("refgraph: (c) stranded notices")
    }
}

/// A sealed fire's ID: BLAKE3 of `[thing, ak, value]`, so the same fire is owed once.
pub type FireId = [u8; 32];

/// `node/fires/` + fire ID: a sealed fire owed (`OwedFire`).
pub(crate) const FIRES: &[u8] = b"node/fires/";

/// A fire of open signal `ak` on `thing` this node owes by sealed fire until a peer takes it
/// (spec/sync-inbox.md §2): offered to peers where `to` (an account holding a role on the thing)
/// is proven; its commit built once (`commit`, a `CommitBlob`'s bytes), sealed again whenever
/// the thing's read keyset moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedFire {
    pub thing: Tid,
    pub ak: Ak,
    pub value: Value,
    pub to: Option<Tid>,
    pub commit: Option<Arc<Vec<u8>>>,
}

impl OwedFire {
    fn id(&self) -> FireId {
        let v = Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), Value::Str(self.ak.as_str().into()), self.value.clone()]);
        osis_base::hash::hash(&osis_base::encode(&v))
    }
    fn encode(&self) -> Vec<u8> {
        let opt = |b: Option<Vec<u8>>| Value::List(b.into_iter().map(Value::Bytes).collect());
        osis_base::encode(&Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), Value::Str(self.ak.as_str().into()), self.value.clone(), opt(self.to.map(|t| t.as_bytes().to_vec())), opt(self.commit.as_ref().map(|c| c.to_vec()))]))
    }
    fn decode(b: &[u8]) -> Result<OwedFire> {
        let bad = || Error::Corrupt("owed fire");
        let v = osis_base::decode(b, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: b.len() }).map_err(|_| bad())?;
        let Value::List(f) = v else { return Err(bad()) };
        let [Value::Bytes(t), Value::Str(ak), value, Value::List(to), Value::List(c)] = f.as_slice() else { return Err(bad()) };
        let tid = |b: &[u8]| -> Result<Tid> { Ok(Tid::from_bytes(b.try_into().map_err(|_| bad())?)) };
        let to = match to.as_slice() {
            [] => None,
            [Value::Bytes(b)] => Some(tid(b)?),
            _ => return Err(bad()),
        };
        let commit = match c.as_slice() {
            [] => None,
            [Value::Bytes(b)] => Some(Arc::new(b.clone())),
            _ => return Err(bad()),
        };
        Ok(OwedFire { thing: tid(t)?, ak: Ak::new(ak.as_str()).map_err(|_| bad())?, value: value.clone(), to, commit })
    }
}

/// Loads the owed fires (an open).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(FIRES, |_, v| {
        rows.push(OwedFire::decode(&v)?);
        Ok(())
    })?;
    for o in rows {
        tx.core.ix.fires.insert(o.id(), Arc::new(o));
    }
    Ok(())
}

fn save(tx: &mut Tx<'_>, o: OwedFire) -> Result<()> {
    let id = o.id();
    tx.txn.put_local(&[FIRES, &id].concat(), &o.encode(), Shred::No)?;
    tx.core.ix.fires.insert(id, Arc::new(o));
    Ok(())
}

/// Fires open signal `ak` on `thing` with `value` (spec/sync-inbox.md §2): a node reading the
/// thing fires as it writes (a non-writer's commit is deposited as any); any other owes a sealed
/// fire, offered to peers where `to` is proven, kept until one takes it.
pub(crate) fn fire(tx: &mut Tx<'_>, thing: Tid, ak: &str, value: Value, to: Option<Tid>) -> Result<()> {
    let ak = super::ak(ak)?;
    if tx.core.epochs(&thing).is_some_and(|e| e.role(osis_base::Role::Read).holds_any()) {
        let mut m = Mutation::new();
        m.op(thing, &ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
        Engine::commit_tx(tx, m)?;
        return Ok(());
    }
    save(tx, OwedFire { thing, ak, value, to, commit: None })
}

/// A sealed fire ready to go (`Engine::sealed_fire`): its Deposit item's sync ID and blob, the
/// thing whose deposit seed signs it, and the account to offer it where proven.
#[derive(Clone, Debug)]
pub struct SealedFireOut {
    pub sync_id: osis_base::SyncId,
    pub thing: Tid,
    pub to: Option<Tid>,
    pub blob: Vec<u8>,
}

impl Engine {
    /// The sealed fires owed (spec/sync-inbox.md §2), whole; `fires_feed` follows additions.
    pub fn fires_owed(&self) -> Vec<FireId> {
        self.core.ix.fires.keys().copied().collect()
    }

    /// A cursor over the sealed fires owed from now on.
    pub fn fires_feed(&self) -> osis_base::memo::Feed<FireId> {
        self.core.ix.fires.feed()
    }

    /// The read epoch fire `id` seals to now: the newest read keyset of its thing held here
    /// (its `keys.0`). Sealed again when this moves.
    pub fn fire_epoch(&mut self, id: &FireId) -> Result<Option<osis_crypto::Epoch>> {
        let Some(o) = self.core.ix.fires.get(id).cloned() else { return Ok(None) };
        Ok(self.fire_keys(&o.thing)?.map(|(e, _, _)| e))
    }

    fn fire_keys(&mut self, t: &Tid) -> Result<Option<(osis_crypto::Epoch, osis_crypto::KemPublicKey, osis_base::SyncId)>> {
        let Some(k) = self.get_typed(t, &ct::KEYS)? else { return Ok(None) };
        let (Some(rk), Some(s)) = (k.read.as_ref(), k.sync_id) else { return Ok(None) };
        let ct::KemKey::X25519MlKem768(b) = &rk.kem_key;
        let (Ok(e), Ok(kem)) = (osis_keys::aspects::from_schema(&rk.epoch), osis_crypto::KemPublicKey::from_slice(b)) else { return Ok(None) };
        Ok(Some((e, kem, s)))
    }

    /// Fire `id` sealed now (spec/sync-inbox.md §2, spec/wire.md §9): its commit (built once, by
    /// this node's account, one delta: the fire) with its author's chain to its actor, behind the
    /// commit's prefix, sealed to its thing's newest read keyset held. `None`: not owed, or the
    /// thing's public key record is not held.
    pub fn sealed_fire(&mut self, id: &FireId) -> Result<Option<SealedFireOut>> {
        let Some(o) = self.core.ix.fires.get(id).cloned() else { return Ok(None) };
        let Some((epoch, kem, sync_id)) = self.fire_keys(&o.thing)? else { return Ok(None) };
        let blob = match &o.commit {
            Some(b) => osis_commit::CommitBlob::decode(b)?,
            None => {
                let o = (*o).clone();
                self.run(|tx| {
                    let mut m = Mutation::new();
                    m.op(o.thing, &o.ak, PathOp { path: Vec::new(), op: Op::Set(o.value.clone()) })?;
                    m.commit_form();
                    let b = crate::engine::write::sealed_commit(tx, m)?;
                    save(tx, OwedFire { commit: Some(Arc::new(b.encode())), ..o })?;
                    Ok(b)
                })?
            }
        };
        let h = &blob.header;
        let mut certs = crate::sync_ids::Certs::default();
        self.account_chain(&h.author, &mut certs);
        let (chain, records) = self.certs_values(&certs)?;
        let ais: Vec<usize> = (0..h.aspects.len()).collect();
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        let seed = self.run(|tx| Ok(osis_crypto::Secret32::random(&mut *tx.rng)))?;
        let mut rng = osis_crypto::SeededRng::from_seed(*seed.expose());
        let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &groups)?;
        let commit = osis_base::decode(&blob.encode(), &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB }).map_err(|_| Error::Corrupt("commit blob"))?;
        let fire = osis_blob::SealedFire { commit, chain, records };
        let sealed = osis_blob::seal_fire(&prefix, &o.thing, &epoch, &kem, &fire, &mut rng)?;
        Ok(Some(SealedFireOut { sync_id, thing: o.thing, to: o.to, blob: sealed }))
    }

    /// A peer took fire `id` (answer 0, spec/sync-inbox.md §3): its delivery ends.
    pub fn fire_taken(&mut self, id: &FireId) -> Result<()> {
        let id = *id;
        self.run(|tx| {
            if tx.core.ix.fires.remove(&id).is_some() {
                tx.txn.remove_local(&[FIRES, &id].concat(), Shred::No)?;
            }
            Ok(())
        })
    }
}
