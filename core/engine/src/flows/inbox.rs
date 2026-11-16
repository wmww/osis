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
use osis_base::{Ak, CommitId, Role, Tid, Ticket, Value};
use osis_schema::core_types::{self as ct, RetentionEntry, RetentionSetting};
use std::collections::{BTreeMap, BTreeSet};

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

/// Fires on `holder`'s inbox a ticket for each of `things` (spec/sync-inbox.md §5), after role
/// commit `c` (a grant's, a key change's or a re-seal's): of the read secret where the holder
/// holds read or above there, else of the sync secret. A sealed fire also carries `c`'s role parts
/// on the thing with their author's chain (`Fire::Ticket`): the commit giving the holder its
/// epochs is wrapped under one it supersedes, which the holder lacks (spec/crypto.md §5 Who
/// wraps under what), so it takes it from the fire. A holder with no inbox here (a key actor
/// other than an account: a node or a link key) is fired nothing.
pub(crate) fn fire_ticket(tx: &mut Tx<'_>, holder: Tid, c: CommitId, things: &[Tid]) -> Result<()> {
    let Some(inbox) = inbox_in(tx, &holder)? else { return Ok(()) };
    let to = tx.core.is_account(&holder).then_some(holder);
    for t in things {
        let role = if tx.core.role_now(&holder, t) >= Some(Role::Read) { Role::Read } else { Role::Sync };
        let Some(ticket) = make_ticket(tx, *t, role, holder)? else { continue };
        let v = Value::Ticket(Box::new(ticket));
        if tx.core.epochs(&inbox).is_some_and(|e| e.role(Role::Read).holds_any()) {
            fire(tx, inbox, TICKET_FIRE, osis_schema::codec::rt::struct_value(vec![(0, v)]), to)?;
        } else {
            save(tx, OwedFire { thing: inbox, ak: super::ak(TICKET_FIRE)?, what: Fire::Ticket { ticket: v, commit: c, target: *t }, to, commit: None })?;
        }
    }
    Ok(())
}

/// A ticket for `target` of `role` (read or sync) boxed to `holder` (spec/data-model.md §8
/// Tickets): the secret of the newest current epoch of that role held here, boxed as a
/// `secrets.0` box to the holder is, naming the target's sync ID and this node's account's
/// profile. `None` when no such secret, sync ID or keyset of the holder is held.
pub(crate) fn make_ticket(tx: &mut Tx<'_>, target: Tid, role: Role, holder: Tid) -> Result<Option<Ticket>> {
    let Some(epochs) = tx.core.epochs(&target) else { return Ok(None) };
    let Some(e) = epochs.role(role).current().into_iter().filter(|e| epochs.role(role).secret(e).is_some()).max_by_key(|e| (e.n(), *e.nonce())) else { return Ok(None) };
    let Some(sync_id) = super::home_sync_id(tx, &target)? else { return Ok(None) };
    let Ok(rcpt) = super::recipient(tx, holder, role) else { return Ok(None) };
    let Some(w) = osis_keys::box_holder(&target, &epochs, &Default::default(), &rcpt, &BTreeSet::from([role]), &mut *tx.rng)? else { return Ok(None) };
    let key = ct::BoxKey { holder: holder.into(), role, epoch: osis_keys::aspects::to_schema(&e) };
    let Some(b) = w.boxes.get(&key) else { return Ok(None) };
    let me = tx.core.account.get();
    let profile = match me {
        Some(p) => {
            let i = inbox_in(tx, &p)?;
            tx.core.profile_of(&p, i)
        }
        None => None,
    };
    let Some(profile) = profile else { return Ok(None) };
    Ok(Some(Ticket { target, sync_id, role, epoch: (e.n(), *e.nonce()), boxed: osis_schema::Codec::to_value(b), holder, profile }))
}

/// Fires on `holder`'s inbox the removal notice of role commit `c` lowering its edge on `target`
/// below read (spec/sync-inbox.md §5): its value, the commit's `roles.0` parts on `target` with
/// their author's chain, is made when the fire is first sealed, `c` applied by then.
pub(crate) fn fire_removal(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let Some(inbox) = inbox_in(tx, &holder)? else { return Ok(()) };
    let to = tx.core.is_account(&holder).then_some(holder);
    save(tx, OwedFire { thing: inbox, ak: super::ak(REMOVAL_FIRE)?, what: Fire::Removal { commit: c, target }, to, commit: None })
}

/// `Engine::inbox_thing` in a transaction.
pub(crate) fn inbox_in(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<Tid>> {
    if tx.core.is_account(a) {
        return Ok(crate::engine::Core::keys_in(tx, a)?.and_then(|k| k.inbox).map(Tid::from));
    }
    Ok(tx.core.has_own_secrets(a).then_some(*a))
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

    /// Acts on removal notice `fire` held here (spec/sync-inbox.md §5): only while this node reads
    /// its thing T and holds T's roster, it learns the notice's records and takes its chain and
    /// then its role commit, each only where judged valid (`ingest_valid`): an edit write taking
    /// this node below read then applies like any, and lost access releases T or keeps the
    /// retained copy it says (spec/permissions.md §3). Any other notice changes nothing.
    pub fn take_removal_notice(&mut self, fire: &CommitId) -> Result<()> {
        let id = *fire;
        let Some(v) = self.read(|tx| fire_value(tx, &id, REMOVAL_FIRE))? else { return Ok(()) };
        self.take_role_parts(&v, &["roles.0"], true)
    }

    /// Takes the role parts a ticket fire held here carries (`Fire::Ticket`), once the walk took
    /// its ticket at a strong (spec/sync-inbox.md §5 Nothing before the strong): its records, its
    /// chain and then its commit, each only where judged valid (`ingest_valid`).
    pub(crate) fn take_ticket_fire(&mut self, fire: &CommitId) -> Result<()> {
        let id = *fire;
        let Some(Value::Map(m)) = self.read(|tx| fire_value(tx, &id, TICKET_FIRE))? else { return Ok(()) };
        let Some(v) = m.get(&Value::Int(2)).cloned() else { return Ok(()) };
        self.take_role_parts(&v, &["roles.0", "keys.0", "secrets.0"], false)
    }

    /// Takes role commit parts `v` (`role_parts_value`): every part of one of `aks`; `read` the
    /// things they are on read here, with their roster held.
    fn take_role_parts(&mut self, v: &Value, aks: &[&str], read: bool) -> Result<()> {
        let Value::Map(m) = v else { return Ok(()) };
        let bytes = |k: i64| match m.get(&Value::Int(k)) {
            Some(Value::Bytes(b)) => vec![b.clone()],
            Some(Value::List(l)) => l.iter().filter_map(|x| if let Value::Bytes(b) = x { Some(b.clone()) } else { None }).collect(),
            _ => Vec::new(),
        };
        let Some(commit) = bytes(0).into_iter().next() else { return Ok(()) };
        let Ok(blob) = osis_commit::CommitBlob::decode(&commit) else { return Ok(()) };
        let things: BTreeSet<Tid> = blob.parts.iter().filter_map(|p| blob.header.aspects.get(p.ai)).map(|a| a.tid).collect();
        let ours = |e: &Engine, t: &Tid| e.core.epochs(t).is_some_and(|x| x.role(Role::Read).holds_any()) && e.core.timelines.get(t).is_some();
        if blob.parts.iter().any(|p| blob.header.aspects.get(p.ai).is_none_or(|a| !aks.contains(&a.ak.as_str()))) || things.is_empty() || (read && !things.iter().all(|t| ours(self, t))) {
            return Ok(());
        }
        let limits = osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: osis_base::format::MAX_BLOB };
        let records: Vec<osis_base::CreationRecord> = bytes(2).iter().filter_map(|b| osis_base::decode(b, &limits).ok()).filter_map(|v| osis_base::CreationRecord::from_value(&v)).filter(|r| self.core.created(&r.tid()).is_none()).collect();
        if !records.is_empty() {
            self.learn_records(records)?;
        }
        for c in bytes(1) {
            self.ingest_valid(&c)?;
        }
        self.ingest_valid(&commit)?;
        Ok(())
    }

    /// Fires a stranded notice on the thing of sync ID `s` (spec/sync-inbox.md §5), naming
    /// `holder` for its writers to re-seal.
    pub fn fire_stranded(&mut self, s: &osis_base::SyncId, holder: &Tid) -> Result<()> {
        let Some(t) = self.sync_owner_of(s)? else { return Ok(()) };
        let keys = self.holder_keys(holder)?;
        let blobs = |v: &[Value]| Value::List(v.iter().map(|x| Value::Bytes(osis_base::encode(x))).collect());
        let records = Value::List(keys.records.iter().map(|r| Value::Bytes(osis_base::encode(&r.to_value()))).collect());
        let v = osis_schema::codec::rt::struct_value(vec![(0, Value::Bytes(s.0.to_vec())), (1, Value::Weak(*holder)), (2, blobs(&keys.commits)), (3, records)]);
        let expires = self.now().0.saturating_add(INBOX_LIFETIME_MS);
        let ak = super::ak(STRANDED_FIRE)?;
        self.run(|tx| save(tx, OwedFire { thing: t, ak, what: Fire::Expiring(v, expires), to: None, commit: None }))
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
    pub what: Fire,
    pub to: Option<Tid>,
    pub commit: Option<Arc<Vec<u8>>>,
}

/// What a fire carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fire {
    Value(Value),
    /// A value whose commit expires at wall ms `expires` (a stranded notice).
    Expiring(Value, u64),
    /// A removal notice of role commit `commit` on `target` (`fire_removal`).
    Removal { commit: CommitId, target: Tid },
    /// A ticket for `target` after role commit `commit`, which the sealed fire carries
    /// (`fire_ticket`).
    Ticket { ticket: Value, commit: CommitId, target: Tid },
}

impl Fire {
    fn to_value(&self) -> Value {
        match self {
            Fire::Value(v) => Value::List(vec![Value::Int(0), v.clone()]),
            Fire::Expiring(v, t) => Value::List(vec![Value::Int(2), v.clone(), Value::Int(i64::try_from(*t).unwrap_or(i64::MAX))]),
            Fire::Removal { commit, target } => Value::List(vec![Value::Int(1), Value::Bytes(commit.0.to_vec()), Value::Bytes(target.as_bytes().to_vec())]),
            Fire::Ticket { ticket, commit, target } => Value::List(vec![Value::Int(3), ticket.clone(), Value::Bytes(commit.0.to_vec()), Value::Bytes(target.as_bytes().to_vec())]),
        }
    }
    fn from_value(v: &Value) -> Option<Fire> {
        let Value::List(f) = v else { return None };
        match f.as_slice() {
            [Value::Int(0), v] => Some(Fire::Value(v.clone())),
            [Value::Int(2), v, Value::Int(t)] => Some(Fire::Expiring(v.clone(), u64::try_from(*t).ok()?)),
            [Value::Int(1), Value::Bytes(c), Value::Bytes(t)] => Some(Fire::Removal { commit: CommitId(c.as_slice().try_into().ok()?), target: Tid::from_bytes(t.as_slice().try_into().ok()?) }),
            [Value::Int(3), k, Value::Bytes(c), Value::Bytes(t)] => Some(Fire::Ticket { ticket: k.clone(), commit: CommitId(c.as_slice().try_into().ok()?), target: Tid::from_bytes(t.as_slice().try_into().ok()?) }),
            _ => None,
        }
    }
}

impl OwedFire {
    fn id(&self) -> FireId {
        let v = Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), Value::Str(self.ak.as_str().into()), self.what.to_value()]);
        osis_base::hash::hash(&osis_base::encode(&v))
    }
    fn encode(&self) -> Vec<u8> {
        let opt = |b: Option<Vec<u8>>| Value::List(b.into_iter().map(Value::Bytes).collect());
        osis_base::encode(&Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), Value::Str(self.ak.as_str().into()), self.what.to_value(), opt(self.to.map(|t| t.as_bytes().to_vec())), opt(self.commit.as_ref().map(|c| c.to_vec()))]))
    }
    fn decode(b: &[u8]) -> Result<OwedFire> {
        let bad = || Error::Corrupt("owed fire");
        let v = osis_base::decode(b, &osis_base::Limits { max_depth: osis_base::format::MAX_OBJECT_DEPTH, max_bytes: b.len() }).map_err(|_| bad())?;
        let Value::List(f) = v else { return Err(bad()) };
        let [Value::Bytes(t), Value::Str(ak), what, Value::List(to), Value::List(c)] = f.as_slice() else { return Err(bad()) };
        let what = Fire::from_value(what).ok_or_else(bad)?;
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
        Ok(OwedFire { thing: tid(t)?, ak: Ak::new(ak.as_str()).map_err(|_| bad())?, what, to, commit })
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

fn drop_fire(tx: &mut Tx<'_>, id: &FireId) -> Result<()> {
    if tx.core.ix.fires.remove(id).is_some() {
        tx.txn.remove_local(&[FIRES, id].concat(), Shred::No)?;
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
        // a fire the thing's setting would not keep is in no history: none is written (an actor
        // that is no account takes the fires its own setting keeps, spec/sync-inbox.md §1)
        let wall = tx.core.hlc.peek().wall_ms().0;
        if crate::retention::history::of(tx.core, &thing, &ak).leaves_at(Some(wall)) <= wall {
            return Ok(());
        }
        let mut m = Mutation::new();
        m.op(thing, &ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
        Engine::commit_tx(tx, m)?;
        return Ok(());
    }
    save(tx, OwedFire { thing, ak, what: Fire::Value(value), to, commit: None })
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
        // a stranded notice past its expiry is owed no more: no receiver would keep it
        if let Fire::Expiring(_, t) = &o.what
            && self.now().0 >= *t
        {
            let id = *id;
            self.run(|tx| drop_fire(tx, &id))?;
            return Ok(None);
        }
        let Some((epoch, kem, sync_id)) = self.fire_keys(&o.thing)? else { return Ok(None) };
        let blob = match &o.commit {
            Some(b) => osis_commit::CommitBlob::decode(b)?,
            None => {
                let (value, expires) = match &o.what {
                    Fire::Value(v) => (v.clone(), None),
                    Fire::Expiring(v, t) => (v.clone(), Some(osis_base::WallMs(*t))),
                    Fire::Removal { commit, target } => match self.role_parts_value(commit, target, &["roles.0"])? {
                        Some(v) => (v, None),
                        None => return Ok(None),
                    },
                    Fire::Ticket { ticket, commit, target } => match self.role_parts_value(commit, target, &["roles.0", "keys.0", "secrets.0"])? {
                        Some(v) => (osis_schema::codec::rt::struct_value(vec![(0, ticket.clone()), (2, v)]), None),
                        None => return Ok(None),
                    },
                };
                let o = (*o).clone();
                let reads = self.core.epochs(&o.thing).is_some_and(|e| e.role(osis_base::Role::Read).holds_any());
                let made = self.run(|tx| {
                    let mut m = Mutation::new();
                    m.op(o.thing, &o.ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
                    if let Some(t) = expires {
                        m.expires(o.thing, &o.ak, t)?;
                    }
                    // a node reading the thing fires as it writes (spec/sync-inbox.md §2)
                    if reads {
                        let wall = tx.core.hlc.peek().wall_ms().0;
                        if crate::retention::history::of(tx.core, &o.thing, &o.ak).leaves_at(Some(wall)) > wall {
                            Engine::commit_tx(tx, m)?;
                        }
                        drop_fire(tx, &o.id())?;
                        return Ok(None);
                    }
                    m.commit_form();
                    let b = crate::engine::write::sealed_commit(tx, m)?;
                    save(tx, OwedFire { commit: Some(Arc::new(b.encode())), ..o })?;
                    Ok(Some(b))
                })?;
                match made {
                    Some(b) => b,
                    None => return Ok(None),
                }
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
        self.run(|tx| drop_fire(tx, &id))
    }

    /// Role commit `c` as a removal notice or a ticket fire carries it (spec/sync-inbox.md §5,
    /// spec/data-model.md §9): `c` projected to its parts on `target` of `aks`, its author's chain
    /// certificates for them (each projected to its chain deltas, no `keys.0` but the author's
    /// own), and their creation records. `None` while `c` is not applied here.
    fn role_parts_value(&mut self, c: &CommitId, target: &Tid, aks: &[&str]) -> Result<Option<Value>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let parts: crate::sync_ids::Parts = full.header.aspects.iter().enumerate().filter(|(_, a)| a.tid == *target && aks.contains(&a.ak.as_str())).map(|(i, _)| i).collect();
        let Some(mut chain) = self.author_chain(c, &parts) else { return Ok(None) };
        for (x, ps) in chain.commits.iter_mut() {
            let Some(hx) = self.header(x) else { continue };
            ps.retain(|i| hx.aspects.get(*i).is_some_and(|a| a.ak.as_str() != "keys.0" || a.tid == hx.author));
        }
        chain.commits.retain(|_, p| !p.is_empty());
        let (chain, records) = self.certs_values(&chain)?;
        let commit = osis_commit::rewrite(&full, |ai| !parts.contains(&ai));
        let blobs = |v: Vec<Value>| Value::List(v.iter().map(|x| Value::Bytes(osis_base::encode(x))).collect());
        let records = Value::List(records.iter().map(|r| Value::Bytes(osis_base::encode(&r.to_value()))).collect());
        Ok(Some(osis_schema::codec::rt::struct_value(vec![(0, Value::Bytes(commit.encode())), (1, blobs(chain)), (2, records)])))
    }
}

impl Engine {
    /// Opens entry `b` (`bytes`) of thing `t`'s sync ID as a sealed fire (spec/sync-inbox.md §4
    /// A sealed fire): with the read secret of each keyset of `t` held, newest first; takes the
    /// commit, which holds one delta: a fire of an open signal of `t` whose hash and prefix agree
    /// with its header, with the author's records and its chain's commits it carries as
    /// certificates, all or nothing: `Bad` unless the fire applies valid. `NotOpen` when no held
    /// key opens it.
    pub(crate) fn open_sealed_fire(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8]) -> Result<crate::sync::Opened> {
        use crate::sync::Opened;
        let mut found = None;
        for (e, secret) in self.read_epochs(t, &[]).into_iter().rev() {
            if let Ok(x) = osis_blob::open_fire(bytes, t, &e, &osis_crypto::role_kem(&secret)) {
                found = Some(x);
                break;
            }
        }
        let Some((prefix, fire)) = found else { return Ok(Opened::NotOpen) };
        let Ok(commit) = osis_commit::CommitBlob::decode(&osis_base::encode(&fire.commit)) else { return Ok(Opened::Bad) };
        let h = &commit.header;
        let one = matches!(commit.parts.as_slice(), [p] if h.aspects.get(p.ai).is_some_and(|a| a.tid == *t && a.ak.open()));
        if !one || !h.is_resolved() {
            return Ok(Opened::Bad);
        }
        let ais: Vec<usize> = (0..h.aspects.len()).collect();
        let removal: Vec<bool> = h.aspects.iter().map(|a| a.ak.as_str() == REMOVAL_FIRE).collect();
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        if !prefix.agrees(osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &h.blind, &groups, osis_blob::Class::of_marker(h.ephemeral)) {
            return Ok(Opened::Bad);
        }
        if let (Some(r), Some(p)) = (self.core.created(t), commit.parts.first())
            && h.aspects.get(p.ai).is_some_and(|a| osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) != a.hash)
        {
            return Ok(Opened::Bad);
        }
        // the author's records and chain to its actor with the fire, kept only if the fire applies
        // valid (`ingest_sealed_fire`)
        let records: Vec<osis_base::CreationRecord> = fire.records.into_iter().filter(|r| self.core.created(&r.tid()).is_none()).collect();
        let chain: Vec<Vec<u8>> = fire.chain.iter().map(osis_base::encode).collect();
        let id = commit.id();
        let parts: Vec<usize> = commit.parts.iter().map(|p| p.ai).collect();
        let Some(ingested) = self.ingest_sealed_fire(records, &chain, commit)? else { return Ok(Opened::Bad) };
        // a removal notice is acted on as it is taken
        if parts.iter().any(|ai| removal.get(*ai) == Some(&true)) {
            self.take_removal_notice(&id)?;
        }
        let row = crate::sync::BlobOf { commit: id, parts: parts.into_iter().collect(), sealed: Default::default(), copy: false, unchecked: false, salt: *prefix.salt(), ais: ais.into_iter().collect() };
        let b = *b;
        self.run(|tx| crate::sync::bodies::note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }
}

/// The account's tickets (spec/sync-set.md §1): D's tickets for `t` this node owes now. `Some`
/// while the walk enters `t` at a strong outside the local part at role `r` (read, or sync kept
/// unread) and D's `tickets.0` holds no ticket for `t` of that role, to the account, at a current
/// epoch of that role held here.
pub(crate) fn account_ticket_due(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<Role>> {
    let (Some((p, d)), Some(r)) = (tx.core.account_devices(), tx.core.ix.closure.entered_outside(t)) else { return Ok(None) };
    let Some(epochs) = tx.core.epochs(t) else { return Ok(None) };
    let current: BTreeSet<(u64, [u8; 32])> = epochs.role(r).current().into_iter().filter(|e| epochs.role(r).secret(e).is_some()).map(|e| (e.n(), *e.nonce())).collect();
    if current.is_empty() {
        return Ok(None);
    }
    let held = account_tickets(tx, &d)?;
    let has = held.iter().any(|k| k.target == *t && k.role == r && k.holder == p && current.contains(&k.epoch));
    Ok((!has).then_some(r))
}

/// D's `tickets.0` as held.
fn account_tickets(tx: &mut Tx<'_>, d: &Tid) -> Result<BTreeSet<Ticket>> {
    let ak = super::ak("tickets.0")?;
    let Some(v) = tx.state(d, &ak)?.and_then(osis_crdt::Fragment::read) else { return Ok(BTreeSet::new()) };
    Ok(match v {
        Value::Set(s) => s.iter().filter_map(|x| if let Value::Ticket(k) = x { Some((**k).clone()) } else { None }).collect(),
        _ => BTreeSet::new(),
    })
}

/// Writes D's ticket for `t` this node owes (`account_ticket_due`): a fresh one sealed to the
/// account (a node's ticket for its own account, spec/data-model.md §8), removing in the same
/// commit D's tickets for `t` of that role at older epochs.
pub(crate) fn write_account_ticket(tx: &mut Tx<'_>, t: &Tid) -> Result<Option<CommitId>> {
    let Some(r) = account_ticket_due(tx, t)? else { return Ok(None) };
    let Some((p, d)) = tx.core.account_devices() else { return Ok(None) };
    let Some(k) = make_ticket(tx, *t, r, p)? else { return Ok(None) };
    // older epochs only: a sibling's ticket at a newer epoch, or at a concurrent one of the same
    // n (a fork's other side), stays, so two nodes never undo each other
    let old: Vec<Ticket> = account_tickets(tx, &d)?.into_iter().filter(|x| x.target == *t && x.role == r && x.epoch.0 < k.epoch.0).collect();
    let mut m = Mutation::new();
    for o in old {
        m.op(d, &ct::TICKETS, PathOp { path: vec![], op: Op::Remove(Value::Ticket(Box::new(o))) })?;
    }
    m.op(d, &ct::TICKETS, PathOp { path: vec![], op: Op::Add(Value::Ticket(Box::new(k))) })?;
    Engine::commit_tx(tx, m)
}

/// In the transaction releasing `ts`: D's tickets for each go (spec/sync-set.md §1, §3).
pub(crate) fn drop_account_tickets(tx: &mut Tx<'_>, ts: &BTreeSet<Tid>) -> Result<()> {
    let Some((_, d)) = tx.core.account_devices() else { return Ok(()) };
    if ts.contains(&d) {
        return Ok(());
    }
    let gone: Vec<Ticket> = account_tickets(tx, &d)?.into_iter().filter(|k| ts.contains(&k.target)).collect();
    if gone.is_empty() {
        return Ok(());
    }
    let mut m = Mutation::new();
    for k in gone {
        m.op(d, &ct::TICKETS, PathOp { path: vec![], op: Op::Remove(Value::Ticket(Box::new(k))) })?;
    }
    Engine::commit_tx(tx, m)?;
    Ok(())
}

impl Engine {
    /// A cursor over the things that enter the node closure from now on.
    pub fn closure_feed(&self) -> osis_base::memo::Feed<Tid> {
        self.core.ix.closure.feed()
    }

    /// See `account_ticket_due`.
    pub fn account_ticket_due(&mut self, t: &Tid) -> Result<Option<Role>> {
        let t = *t;
        self.read(|tx| account_ticket_due(tx, &t))
    }

    /// See `write_account_ticket`.
    pub fn write_account_ticket(&mut self, t: &Tid) -> Result<Option<CommitId>> {
        let t = *t;
        self.run(|tx| write_account_ticket(tx, &t))
    }
}

/// The value fire commit `c` holds on open signal `ak`, as held here.
fn fire_value(tx: &mut Tx<'_>, c: &CommitId, ak: &str) -> Result<Option<Value>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.header.aspects.iter().position(|a| a.ak.as_str() == ak) else { return Ok(None) };
    let mut out = None;
    crate::apply::each_held_piece(tx, c, ai, &mut |_, f| {
        out = out.take().or_else(|| f.read());
        Ok(())
    })?;
    Ok(out)
}
