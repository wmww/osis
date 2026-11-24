//! The inbox thing and its external signals (spec/sync-inbox.md §1, §2, §5): `grant@~0` and
//! `stranded@~0`, fired sealed by anyone holding the inbox's public key record,
//! promoted by a writer.

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::Mutation;
use osis_crdt::{Op, PathOp};
use osis_store::Shred;
use std::sync::Arc;
use osis_base::format::INBOX_LIFETIME_MS;
use osis_base::{Ak, CommitId, Role, Tid, Value};
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// Grants from outside (spec/sync-inbox.md §1, §5).
pub const GRANT_FIRE: &str = ct::INBOX_SIGNALS[0];
/// Stranded notices.
pub const STRANDED_FIRE: &str = ct::INBOX_SIGNALS[1];

/// Role commit `c` of `target` naming or boxing `holder`, as the holder's readers learn of it
/// (spec/permissions.md §4 Delivering an edge piece): a holder this node may write has it in
/// its key part, logged under its own sync ID; any other is offered it by a `grant@~0` fire
/// (`fire_copy`; spec/sync-inbox.md §5 Grant from outside).
pub(crate) fn deliver_copy(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let me = tx.core.me();
    if tx.core.role_now(&me, &holder) >= Some(Role::Write) {
        return Ok(());
    }
    fire_copy(tx, holder, c, target)
}

/// Fires `grant@~0` on `holder`'s inbox carrying role commit `c`'s copy on `target`: the fire's
/// value, the copy with its evidence and their records (`Engine::grant_value`), is made when the
/// fire is first sealed, `c` applied by then. One already owed stays as it is. A holder with no
/// inbox here (not independent here) is fired nothing.
pub(crate) fn fire_copy(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let Some(inbox) = inbox_in(tx, &holder)? else { return Ok(()) };
    let to = fire_to(tx, &holder);
    let o = OwedFire { thing: inbox, ak: super::ak(GRANT_FIRE)?, what: Fire::Grant { commit: c, target }, to, commit: None, pages: Default::default() };
    if tx.core.ix.fires.contains_key(&o.id()) {
        return Ok(());
    }
    save(tx, o)
}

/// Whom a fire on `holder`'s inbox is offered to where proven (spec/sync-inbox.md §3 Sending: a
/// peer that proved a thing holding a role on it, as this node judges it): the holder and the
/// things holding a role on it, directly or through the things holding it. Not cut to the things
/// whose records say a key signs as them: the sender may hold an account's record (from its
/// profile) and not its node things', which the proof brings.
fn fire_to(tx: &mut Tx<'_>, holder: &Tid) -> BTreeSet<Tid> {
    let mut out = BTreeSet::from([*holder]);
    let mut todo = vec![*holder];
    while let Some(x) = todo.pop() {
        for (m, _) in tx.core.key_holders(&x) {
            if out.insert(m) {
                todo.push(m);
            }
        }
    }
    out
}

/// `Engine::inbox_thing` in a transaction.
pub(crate) fn inbox_in(tx: &mut Tx<'_>, a: &Tid) -> Result<Option<Tid>> {
    let named = crate::engine::Core::keys_in(tx, a)?.and_then(|k| k.inbox).map(Tid::from);
    Ok(named.or_else(|| tx.core.is_independent(a).then_some(*a)))
}

impl Engine {
    /// `a`'s inbox thing (spec/sync-inbox.md §1): the thing its `keys.0` names, else `a` itself
    /// where independent.
    pub fn inbox_thing(&mut self, a: &Tid) -> Option<Tid> {
        let named = self.get_typed(a, &ct::KEYS).ok().flatten().and_then(|k| k.inbox).map(Tid::from);
        named.or_else(|| self.core.is_independent(a).then_some(*a))
    }

    /// What each `grant@~0` fire held valid here carries (`Carried`).
    pub fn grant_fires_held(&self) -> Vec<Carried> {
        self.core.ix.grant_fires.iter().filter(|(f, _)| held_valid(&self.core, f, GRANT_FIRE)).map(|(_, c)| *c).collect()
    }

    /// Takes what each due fire carries (`Indexes::fires_due`, `take_fire`): whether any was
    /// due.
    pub fn take_carried(&mut self) -> Result<bool> {
        let due: Vec<CommitId> = self.core.ix.fires_due.iter().copied().collect();
        if due.is_empty() {
            return Ok(false);
        }
        self.bringing(|e| e.take_due(&due))
    }

    /// Runs `f`, what arrives in it brought by a sealed fire (`Core::fire_brings`).
    fn bringing<T>(&mut self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        let was = std::mem::replace(&mut self.core.fire_brings, true);
        let r = f(self);
        self.core.fire_brings = was;
        r
    }

    fn take_due(&mut self, due: &[CommitId]) -> Result<bool> {
        self.run(|tx| {
            for c in due {
                tx.core.ix.fires_due.remove(c);
            }
            Ok(())
        })?;
        for c in due {
            self.take_fire(c)?;
        }
        Ok(true)
    }

    /// Takes what fire `fire` carries while it is held valid here (spec/sync-inbox.md §5): a
    /// `grant@~0` fire's commit as an arriving role commit of its target (its records, its
    /// evidence and then the copy, each only where judged valid, `ingest_valid`, pending on what
    /// it lacks); a stranded notice's report.
    pub(crate) fn take_fire(&mut self, fire: &CommitId) -> Result<()> {
        let id = *fire;
        // a stranded notice that applied after it was opened (one ahead of the clock): acted on
        // as one taken at its opening is
        if self.read(|tx| Ok(held_valid(tx.core, &id, STRANDED_FIRE)))?
            && let Some(v) = self.read(|tx| fire_value(tx, &id, STRANDED_FIRE))?
            && let Some((s, holder, keys)) = notice_of(&v)
        {
            self.take_stranded_from(&s, &holder, &keys, crate::apply::carriers::Carrier::Fire(id))?;
        }
        if !self.read(|tx| Ok(held_valid(tx.core, &id, GRANT_FIRE)))? {
            return Ok(());
        }
        let Some(v) = self.read(|tx| fire_value(tx, &id, GRANT_FIRE))? else { return Ok(()) };
        self.take_role_parts(&v, GRANT_PARTS, id)?;
        // a fire turned valid takes the grant it carries: boxes kept out for want of the role
        // open now
        self.run(|tx| crate::flows::retake(tx).map(drop))
    }

    /// The holder whose inbox held `grant@~0` fire `fire` is on: an account up the fire's thing's
    /// record chain whose `keys.0` names that thing its inbox, else the thing itself
    /// (`inbox_thing`).
    fn fired_at(&mut self, fire: &CommitId) -> Option<Tid> {
        let on = self.core.ix.commits.get(fire)?.header.aspects.iter().find(|a| a.ak.as_str() == GRANT_FIRE)?.tid;
        let up: Vec<Tid> = self.core.record_chain(&on).filter_map(|s| s.thing()).filter(|h| *h != on).chain([on]).collect();
        up.into_iter().find(|h| self.inbox_thing(h) == Some(on))
    }

    /// Takes role commit parts `v` (`grant_value`) that fire `fire` carries, every part one
    /// of `aks`: what pends of them, the fire carries (spec/commits.md §4 Pending storage).
    fn take_role_parts(&mut self, v: &Value, aks: &[&str], fire: CommitId) -> Result<()> {
        let from = Some(crate::apply::carriers::Carrier::Fire(fire));
        let Value::Map(m) = v else { return Ok(()) };
        let bytes = |k: i64| match m.get(&Value::Int(k)) {
            Some(Value::Bytes(b)) => vec![b.clone()],
            Some(Value::List(l)) => l.iter().filter_map(|x| if let Value::Bytes(b) = x { Some(b.clone()) } else { None }).collect(),
            _ => Vec::new(),
        };
        let Some(commit) = bytes(0).into_iter().next() else { return Ok(()) };
        let Ok(blob) = osis_commit::CommitBlob::decode(&commit) else { return Ok(()) };
        if blob.parts.is_empty() || blob.parts.iter().any(|p| blob.header.aspects.get(p.ai).is_none_or(|a| !aks.contains(&a.ak.as_str()))) {
            return Ok(());
        }
        // the copy's parts are on one thing, its target (`grant_value`)
        let target = blob.parts.first().and_then(|p| blob.header.aspects.get(p.ai)).map(|a| a.tid);
        if let (Some(holder), Some(target)) = (self.fired_at(&fire), target) {
            let carried = blob.id();
            self.run(|tx| note_carried(tx, fire, Carried { commit: carried, holder, target }))?;
        }
        let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
        let records: Vec<osis_base::CreationRecord> = bytes(2).iter().filter_map(|b| osis_base::decode(b, &limits).ok()).filter_map(|v| osis_base::CreationRecord::from_value(&v)).filter(|r| self.core.created(&r.tid()).is_none()).collect();
        if !records.is_empty() {
            self.learn_records(records)?;
        }
        for c in bytes(1) {
            self.ingest_valid(&c, from)?;
        }
        self.ingest_valid(&commit, from)?;
        Ok(())
    }

    /// Fires a stranded notice on the thing of sync ID `s` (spec/sync-inbox.md §5), naming
    /// `holder` for its writers to re-seal.
    pub fn fire_stranded(&mut self, s: &osis_base::SyncId, holder: &Tid) -> Result<()> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(()) };
        let keys = self.holder_keys(holder)?;
        let blobs = |v: &[Value]| Value::List(v.iter().map(|x| Value::Bytes(osis_base::encode(x))).collect());
        let records = Value::List(keys.records.iter().map(|r| Value::Bytes(osis_base::encode(&r.to_value()))).collect());
        let v = osis_schema::codec::rt::struct_value(vec![(0, Value::Bytes(s.0.to_vec())), (1, Value::Weak(*holder)), (2, blobs(&keys.commits)), (3, records)]);
        let expires = self.now().0.saturating_add(INBOX_LIFETIME_MS);
        let ak = super::ak(STRANDED_FIRE)?;
        self.run(|tx| save(tx, OwedFire { thing: t, ak, what: Fire::Expiring(v, expires), to: BTreeSet::new(), commit: None, pages: Default::default() }))
    }
}

/// What a held `grant@~0` fire carries: role commit `commit`'s copy on `target`, fired on
/// `holder`'s inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Carried {
    pub commit: CommitId,
    pub holder: Tid,
    pub target: Tid,
}

/// `gf/` + fire commit ID: what a held `grant@~0` fire carries (`Carried`: commit, holder,
/// target), kept while the fire is held.
const CARRIED: &[u8] = b"gf/";

fn index_carried(core: &mut crate::engine::Core, fire: CommitId, c: Carried) {
    core.ix.fires_carrying.insert(c.target, fire);
    core.ix.grant_fires.insert(fire, c);
}

/// Loads what the held grant fires carry (an open or reload).
pub(crate) fn load_carried(tx: &mut Tx<'_>) -> Result<()> {
    let bad = || Error::Corrupt("grant fire row");
    let mut rows = Vec::new();
    tx.scan(CARRIED, |k, v| {
        let fire = CommitId(k.try_into().map_err(|_| bad())?);
        let (c, rest) = v.split_at_checked(32).ok_or_else(bad)?;
        let (h, t) = rest.split_at_checked(15).ok_or_else(bad)?;
        let tid = |b: &[u8]| -> Result<Tid> { Ok(Tid::from_bytes(b.try_into().map_err(|_| bad())?)) };
        rows.push((fire, Carried { commit: CommitId(c.try_into().map_err(|_| bad())?), holder: tid(h)?, target: tid(t)? }));
        Ok(())
    })?;
    for (fire, c) in rows {
        index_carried(tx.core, fire, c);
    }
    Ok(())
}

/// Held `grant@~0` fire `fire` carries `c`.
fn note_carried(tx: &mut Tx<'_>, fire: CommitId, c: Carried) -> Result<()> {
    if !tx.core.ix.commits.contains_key(&fire) || tx.core.ix.grant_fires.contains_key(&fire) {
        return Ok(());
    }
    index_carried(tx.core, fire, c);
    tx.txn.put_local(&[CARRIED, &fire.0[..]].concat(), &[&c.commit.0[..], c.holder.as_bytes(), c.target.as_bytes()].concat(), Shred::No)?;
    Ok(())
}

/// Commit `id` is forgotten: as a grant fire it carries nothing any more.
pub(crate) fn fire_gone(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let Some(c) = tx.core.ix.grant_fires.remove(id) else { return Ok(()) };
    tx.core.ix.fires_carrying.remove(&c.target, id);
    tx.core.note_lost(c.target);
    tx.txn.remove_local(&[CARRIED, &id.0[..]].concat(), Shred::No)?;
    Ok(())
}

/// Grant fire `id`'s body is dropped (past its keep, or invalid): its target lost what the offer
/// kept of it (`retention::needed::Need::Offered`).
pub(crate) fn fire_dropped(core: &mut crate::engine::Core, id: &CommitId) {
    if let Some(c) = core.ix.grant_fires.get(id).copied() {
        core.note_lost(c.target);
    }
}

/// The holders whose held valid `grant@~0` fires carry a commit on `target`, each with that
/// commit: the node holds what an offer carries while it holds the offer (spec/sync-inbox.md §5
/// Grant from outside).
pub(crate) fn granted_on<'a>(core: &'a crate::engine::Core, target: &Tid) -> impl Iterator<Item = (Tid, CommitId)> + 'a {
    core.ix.fires_carrying.get(target).into_iter().flatten().filter(|f| held_valid(core, f, GRANT_FIRE)).filter_map(|f| core.ix.grant_fires.get(f)).map(|c| (c.holder, c.commit))
}

/// Whether a valid fire of signal `ak` is taken for what it carries (`Engine::take_fire`): a
/// grant from outside, a stranded notice.
pub(crate) fn carries(ak: &str) -> bool {
    ak == GRANT_FIRE || ak == STRANDED_FIRE
}

/// The parts a `grant@~0` fire's copy holds: the role commit's role-class parts on its target
/// (spec/permissions.md §4 Copies), which give the holder its epochs and the target's `sync.0`.
const GRANT_PARTS: &[&str] = &["roles.0", "keys.0", "secrets.0", "sync.0"];

/// A sealed fire's ID: BLAKE3 of `[thing, ak, value]`, so the same fire is owed once.
pub type FireId = [u8; 32];

/// `node/fires/` + fire ID: a sealed fire owed (`OwedFire`).
pub(crate) const FIRES: &[u8] = b"node/fires/";

/// A fire of external signal `ak` on `thing` this node owes by sealed fire until a peer takes it
/// (spec/sync-inbox.md §2): offered to peers where `to` (an account holding a role on the thing)
/// is proven; its commit built once (`commit`, a `CommitBlob`'s bytes), sealed again whenever
/// the thing's read keyset moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedFire {
    pub thing: Tid,
    pub ak: Ak,
    pub what: Fire,
    pub to: BTreeSet<Tid>,
    pub commit: Option<Arc<Vec<u8>>>,
    /// The blobs `commit`'s delta links (its pages): they travel with the fire.
    pub pages: Arc<Vec<Vec<u8>>>,
}

/// What a fire carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fire {
    Value(Value),
    /// A value whose commit expires at wall ms `expires` (a stranded notice).
    Expiring(Value, u64),
    /// A grant from outside: role commit `commit`'s copy on `target` (`fire_copy`).
    Grant { commit: CommitId, target: Tid },
}

impl Fire {
    fn to_value(&self) -> Value {
        match self {
            Fire::Value(v) => Value::List(vec![Value::Int(0), v.clone()]),
            Fire::Expiring(v, t) => Value::List(vec![Value::Int(2), v.clone(), Value::Int(i64::try_from(*t).unwrap_or(i64::MAX))]),
            Fire::Grant { commit, target } => Value::List(vec![Value::Int(1), Value::Bytes(commit.0.to_vec()), Value::Bytes(target.as_bytes().to_vec())]),
        }
    }
    fn from_value(v: &Value) -> Option<Fire> {
        let Value::List(f) = v else { return None };
        match f.as_slice() {
            [Value::Int(0), v] => Some(Fire::Value(v.clone())),
            [Value::Int(2), v, Value::Int(t)] => Some(Fire::Expiring(v.clone(), u64::try_from(*t).ok()?)),
            [Value::Int(1), Value::Bytes(c), Value::Bytes(t)] => Some(Fire::Grant { commit: CommitId(c.as_slice().try_into().ok()?), target: Tid::from_bytes(t.as_slice().try_into().ok()?) }),
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
        let pages = Value::List(self.pages.iter().map(|b| Value::Bytes(b.clone())).collect());
        osis_base::encode(&Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), Value::Str(self.ak.as_str().into()), self.what.to_value(), Value::List(self.to.iter().map(|t| Value::Bytes(t.as_bytes().to_vec())).collect()), opt(self.commit.as_ref().map(|c| c.to_vec())), pages]))
    }
    fn decode(b: &[u8]) -> Result<OwedFire> {
        let bad = || Error::Corrupt("owed fire");
        let v = osis_base::decode(b, &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len())).map_err(|_| bad())?;
        let Value::List(f) = v else { return Err(bad()) };
        let [Value::Bytes(t), Value::Str(ak), what, Value::List(to), Value::List(c), Value::List(pages)] = f.as_slice() else { return Err(bad()) };
        let pages = pages.iter().map(|b| if let Value::Bytes(b) = b { Ok(b.clone()) } else { Err(bad()) }).collect::<Result<Vec<_>>>()?;
        let what = Fire::from_value(what).ok_or_else(bad)?;
        let tid = |b: &[u8]| -> Result<Tid> { Ok(Tid::from_bytes(b.try_into().map_err(|_| bad())?)) };
        let to = to.iter().map(|v| match v {
            Value::Bytes(b) => tid(b),
            _ => Err(bad()),
        }).collect::<Result<BTreeSet<Tid>>>()?;
        let commit = match c.as_slice() {
            [] => None,
            [Value::Bytes(b)] => Some(Arc::new(b.clone())),
            _ => return Err(bad()),
        };
        Ok(OwedFire { thing: tid(t)?, ak: Ak::new(ak.as_str()).map_err(|_| bad())?, what, to, commit, pages: Arc::new(pages) })
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
        tx.core.ix.fires_on.insert(o.thing, o.id());
        tx.core.ix.fires.insert(o.id(), Arc::new(o));
    }
    Ok(())
}

fn drop_fire(tx: &mut Tx<'_>, id: &FireId) -> Result<()> {
    if let Some(o) = tx.core.ix.fires.remove(id) {
        tx.core.ix.fires_on.remove(&o.thing, id);
        tx.txn.remove_local(&[FIRES, id].concat(), Shred::No)?;
    }
    Ok(())
}

/// Thing `t` is forgotten whole here (spec/commits.md §5 What a held thing needs): the fires owed
/// on it go, no keyset of it being left to seal them to (spec/sync-inbox.md §2).
pub(crate) fn drop_fires_on(tx: &mut Tx<'_>, t: &Tid) -> Result<()> {
    let ids: Vec<FireId> = tx.core.ix.fires_on.get(t).into_iter().flatten().copied().collect();
    for id in ids {
        drop_fire(tx, &id)?;
    }
    Ok(())
}

pub(crate) fn save(tx: &mut Tx<'_>, o: OwedFire) -> Result<()> {
    let id = o.id();
    tx.txn.put_local(&[FIRES, &id].concat(), &o.encode(), Shred::No)?;
    tx.core.ix.fires_on.insert(o.thing, id);
    tx.core.ix.fires.insert(id, Arc::new(o));
    Ok(())
}

/// Whether this node reads `t` as a fire goes (spec/sync-inbox.md §2): it holds a read secret of
/// `t`, of a current read epoch where one is established. A stranded node does not (spec/permissions.md
/// §4): its fires go sealed, to the keyset it cannot read.
fn reads_now(core: &crate::engine::Core, t: &Tid) -> bool {
    core.epochs(t).is_some_and(|e| {
        let r = e.role(Role::Read);
        let current = r.current();
        r.holds_any() && (current.is_empty() || current.iter().any(|x| r.secret(x).is_some()))
    })
}

/// Fires external signal `ak` on `thing` with `value` (spec/sync-inbox.md §2): a node holding and
/// reading the thing fires as it writes (a non-writer's commit is deposited as any); any other
/// owes a sealed fire, offered to peers where `to` is proven, kept until one takes it. A fire this
/// node would write that the thing's setting does not take is refused before anything is written,
/// naming the setting: `NotEnabled` where this node holds no write and the setting does not enable
/// the signal, else `Misuse(FIRE_IN_NO_HISTORY)` where it keeps no history for it (a fire is
/// history, spec/commits.md §5 Signals).
pub(crate) fn fire(tx: &mut Tx<'_>, thing: Tid, ak: &str, value: Value, to: BTreeSet<Tid>) -> Result<()> {
    let ak = super::ak(ak)?;
    if !tx.core.ix.closure.holds(&thing) || !reads_now(tx.core, &thing) {
        return save(tx, OwedFire { thing, ak, what: Fire::Value(value), to, commit: None, pages: Default::default() });
    }
    if !keeps_fire(tx.core, &thing, &ak) {
        let me = tx.core.me();
        let writes = tx.core.role_now(&me, &thing) >= Some(Role::Write);
        let enabled = crate::apply::validity::setting_now(tx.core, &thing).is_some_and(|s| s.enables(&ak));
        return Err(match writes || enabled {
            true => Error::Misuse(crate::engine::write::FIRE_IN_NO_HISTORY),
            false => Error::NotEnabled { tid: thing, ak: ak.to_string() },
        });
    }
    let mut m = Mutation::new();
    m.op(thing, &ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
    Engine::commit_tx(tx, m)?;
    Ok(())
}

/// Whether `thing`'s setting keeps a fire of `ak` written now (a fire is history, spec/commits.md
/// §5 Signals). An entry keeping an external signal also enables it, so such a fire is valid
/// whoever writes it.
fn keeps_fire(core: &crate::engine::Core, thing: &Tid, ak: &Ak) -> bool {
    let ts = core.hlc.peek();
    let wall = ts.wall_ms().0;
    crate::retention::history::of(core, thing, ak).leaves_at(Some(wall), ts) > wall
}

/// The blobs the deltas of `b`, a sealed fire's commit just built, link (their pages), taken out
/// of the blob store: they travel with the fire (spec/wire.md §9), held by its row.
fn built_pages(tx: &mut Tx<'_>, b: &osis_commit::CommitBlob) -> Result<Vec<Vec<u8>>> {
    let mut trees = crate::engine::large::Trees::default();
    for p in &b.parts {
        let Some(dedup) = b.header.aspects.get(p.ai).and_then(|a| tx.core.dedup(&a.tid)) else { continue };
        crate::engine::large::tree_blobs(tx, &dedup, &crate::engine::large::delta_roots(&p.delta), &mut trees)?;
    }
    let memory = tx.txn.is_memory();
    let mut out = Vec::new();
    for id in trees.blobs {
        out.push(tx.blobs.get(&id)?.ok_or(Error::Corrupt("a built fire's page"))?);
        tx.blobs.release(&id, memory)?;
    }
    Ok(out)
}

/// A sealed fire ready to go (`Engine::sealed_fire`): its Deposit item's sync ID and blob, the
/// thing whose deposit seed signs it, and the account to offer it where proven.
#[derive(Clone, Debug)]
pub struct SealedFireOut {
    pub sync_id: osis_base::SyncId,
    pub thing: Tid,
    pub to: BTreeSet<Tid>,
    pub blob: Vec<u8>,
}

impl Engine {
    /// The sealed fires owed (spec/sync-inbox.md §2), whole; `fires_feed` follows additions.
    pub fn fires_owed(&self) -> Vec<FireId> {
        self.core.ix.fires.keys().copied().collect()
    }

    /// Owed fire `id`'s commit once built (`sealed_fire`): its ID and the wall time it is
    /// stamped, which a receiver's clock must have reached but for `MAX_DRIFT`.
    pub fn fire_commit(&self, id: &FireId) -> Option<(CommitId, osis_base::WallMs)> {
        let b = osis_commit::CommitBlob::decode(self.core.ix.fires.get(id)?.commit.as_ref()?).ok()?;
        Some((b.id(), b.header.ts.wall_ms()))
    }

    /// A cursor over the sealed fires owed from now on.
    pub fn fires_feed(&self) -> osis_base::memo::Feed<FireId> {
        self.core.ix.fires.feed()
    }

    /// The read epoch fire `id` seals to now: its thing's read key in force held here
    /// (`fire_keys`); `None` while there is none (its delivery waits). Sealed again when this
    /// moves.
    pub fn fire_epoch(&mut self, id: &FireId) -> Result<Option<osis_crypto::Epoch>> {
        let Some(o) = self.core.ix.fires.get(id).cloned() else { return Ok(None) };
        Ok(self.fire_keys(&o.thing)?.map(|(e, _, _)| e))
    }

    /// What a fire on `t` from outside is sealed to and goes under (spec/sync-inbox.md §2): `t`'s
    /// read key in force (`sync_ids::read_key_in_force`, never a writer's keyset) and its sync
    /// ID, from the `keys.0` held here.
    pub(crate) fn fire_keys(&mut self, t: &Tid) -> Result<Option<(osis_crypto::Epoch, osis_crypto::KemPublicKey, osis_base::SyncId)>> {
        let t = *t;
        let Some((rk, s)) = self.read(|tx| Ok(super::sync_ids::read_key_in_force(tx, &t)?.zip(crate::engine::Core::keys_in(tx, &t)?.and_then(|k| k.sync_id))))? else { return Ok(None) };
        let ct::KemKey::X25519MlKem768(b) = &rk.kem_key;
        let (Ok(e), Ok(kem)) = (osis_keys::aspects::from_schema(&rk.epoch), osis_crypto::KemPublicKey::from_slice(b)) else { return Ok(None) };
        Ok(Some((e, kem, s)))
    }

    /// Fire `id` sealed now (spec/sync-inbox.md §2, spec/wire.md §9): its commit (built once, by
    /// this node's account, one delta: the fire) with its evidence (its signer's record and, an
    /// account's, its rotations to the epoch it signs at: spec/permissions.md §4), behind the
    /// commit's prefix, sealed to its thing's read key in force held (`fire_keys`). `None`: not
    /// owed, or no such key is held (the thing's public key record, or a step after its newest
    /// read keyset).
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
        let (blob, pages) = match &o.commit {
            Some(b) => (osis_commit::CommitBlob::decode(b)?, o.pages.clone()),
            None => {
                let (value, expires) = match &o.what {
                    Fire::Value(v) => (v.clone(), None),
                    Fire::Expiring(v, t) => (v.clone(), Some(osis_base::WallMs(*t))),
                    Fire::Grant { commit, target } => match self.grant_value(commit, target)? {
                        Some(v) => (v, None),
                        None => return Ok(None),
                    },
                };
                let o = (*o).clone();
                let made = self.run(|tx| {
                    let mut m = Mutation::new();
                    m.op(o.thing, &o.ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
                    if let Some(t) = expires {
                        m.expires(o.thing, &o.ak, t)?;
                    }
                    // a node holding and reading the thing now fires as it writes where the
                    // setting keeps the fire (spec/sync-inbox.md §2); else the fire it owes
                    // already goes sealed, its receivers judging it
                    if tx.core.ix.closure.holds(&o.thing) && reads_now(tx.core, &o.thing) && keeps_fire(tx.core, &o.thing, &o.ak) {
                        Engine::commit_tx(tx, m)?;
                        drop_fire(tx, &o.id())?;
                        return Ok(None);
                    }
                    m.commit_form();
                    let b = crate::engine::write::sealed_commit(tx, m)?;
                    let pages = Arc::new(built_pages(tx, &b)?);
                    save(tx, OwedFire { commit: Some(Arc::new(b.encode())), pages: pages.clone(), ..o })?;
                    Ok(Some((b, pages)))
                })?;
                match made {
                    Some(x) => x,
                    None => return Ok(None),
                }
            }
        };
        let h = &blob.header;
        let (evidence, records) = self.signer_evidence(&h.signer)?;
        let ais: Vec<usize> = (0..h.aspects.len()).collect();
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        let seed = self.run(|tx| Ok(osis_crypto::Secret32::random(&mut *tx.rng)))?;
        let mut rng = osis_crypto::SeededRng::from_seed(*seed.expose());
        let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &groups)?;
        let commit = osis_base::decode(&blob.encode(), &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB)).map_err(|_| Error::Corrupt("commit blob"))?;
        let fire = osis_blob::SealedFire { copy: false, commit, evidence, records, pages: (*pages).clone() };
        let sealed = osis_blob::seal_fire(&prefix, &o.thing, &epoch, &kem, &fire, &mut rng)?;
        Ok(Some(SealedFireOut { sync_id, thing: o.thing, to: o.to.clone(), blob: sealed }))
    }

    /// Whether `t`'s current setting here enables external signal `ak` (spec/sync-inbox.md §1:
    /// the default never; a node thing enables none), for tests: a fire of it from a party
    /// holding no write on `t` is invalid otherwise.
    #[doc(hidden)]
    pub fn enables(&self, t: &Tid, ak: &str) -> bool {
        osis_base::Ak::new(ak).is_ok_and(|a| crate::apply::validity::setting_now(&self.core, t).is_some_and(|s| s.enables(&a)))
    }

    /// Takes sealed fire `f` as a peer offers it (spec/sync-inbox.md §3 Sending): what a caller
    /// with no sync (a harness carrying fires by hand) does with one.
    pub fn offer_fire(&mut self, f: &SealedFireOut) -> Result<crate::sync::Opened> {
        self.open_entry(&f.sync_id, &osis_blob::blob_id(&f.blob), &[0; 57], &f.blob, u64::MAX)
    }

    /// Writes each fire owed on a thing this node holds and reads, where the thing's setting
    /// keeps it (`sealed_fire`: such a node fires as it writes, so a link's redeemer firing its
    /// grant on its own account holds the fire), and takes what they carry (`take_carried`).
    /// Sync's fire step does the same as it seals what is owed; a caller with no sync runs this.
    pub fn fire_own(&mut self) -> Result<()> {
        let own: Vec<FireId> = self.core.ix.fires.iter().filter(|(_, o)| o.commit.is_none() && self.core.ix.closure.holds(&o.thing) && reads_now(&self.core, &o.thing) && keeps_fire(&self.core, &o.thing, &o.ak)).map(|(id, _)| *id).collect();
        for id in &own {
            self.sealed_fire(id)?;
        }
        self.take_carried()?;
        Ok(())
    }

    /// A peer took fire `id` (answer 0, spec/sync-inbox.md §3): its delivery ends.
    pub fn fire_taken(&mut self, id: &FireId) -> Result<()> {
        let id = *id;
        self.run(|tx| drop_fire(tx, &id))
    }

    /// A fire's own evidence (spec/sync-inbox.md §4 A sealed fire): its signer's record, as
    /// commit values and creation records.
    fn signer_evidence(&mut self, signer: &Tid) -> Result<(Vec<Value>, Vec<osis_base::CreationRecord>)> {
        let mut certs = crate::sync_ids::Certs::default();
        certs.records.insert(*signer);
        self.certs_values(&certs)
    }

    /// The evidence of copy `copy` (spec/permissions.md §4 Evidence of a commit): the copies the
    /// derivation closes it over, with the records `close_records` brings, as commit values and
    /// creation records; the copy itself not among them.
    fn copy_evidence(&mut self, copy: &(CommitId, Tid)) -> Result<(Vec<Value>, Vec<osis_base::CreationRecord>)> {
        let ev = self.evidence_now()?;
        let mut certs = crate::sync_ids::Certs::default();
        if let Some(h) = self.header(&copy.0) {
            certs.records.extend([copy.1, h.signer]);
        }
        self.add_closure(&ev, &BTreeSet::from([*copy]), &mut certs);
        self.close_records(&ev, &mut certs);
        self.certs_values(&certs)
    }

    /// Role commit `c` as a `grant@~0` fire carries it (spec/sync-inbox.md §5): its certificate
    /// copy on `target` (its header and role-class parts there), the copies of its evidence, and
    /// their creation records. `None` while `c` is not applied here.
    fn grant_value(&mut self, c: &CommitId, target: &Tid) -> Result<Option<Value>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let parts: BTreeSet<usize> = full.header.aspects.iter().enumerate().filter(|(_, a)| a.tid == *target && GRANT_PARTS.contains(&a.ak.as_str())).map(|(i, _)| i).collect();
        let (chain, records) = self.copy_evidence(&(id, *target))?;
        let commit = osis_commit::rewrite(&full, |ai| !parts.contains(&ai));
        let blobs = |v: Vec<Value>| Value::List(v.iter().map(|x| Value::Bytes(osis_base::encode(x))).collect());
        let records = Value::List(records.iter().map(|r| Value::Bytes(osis_base::encode(&r.to_value()))).collect());
        Ok(Some(osis_schema::codec::rt::struct_value(vec![(0, Value::Bytes(commit.encode())), (1, blobs(chain)), (2, records)])))
    }
}

impl Engine {
    /// Opens entry `b` (`bytes`) of thing `t`'s sync ID as a sealed fire (spec/sync-inbox.md §4
    /// A sealed fire): with the read secret of each keyset of `t` held, newest first; takes the
    /// commit, which holds one delta: a fire of an external signal of `t` whose hash and prefix agree
    /// with its header, with the author's records and its chain's commits it carries as
    /// certificates, all or nothing: `Bad` unless the fire applies valid. `NotOpen` when no held
    /// key opens it.
    pub(crate) fn open_sealed_fire(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8]) -> Result<crate::sync::Opened> {
        self.bringing(|e| e.open_fire_in(t, b, bytes))
    }

    fn open_fire_in(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8]) -> Result<crate::sync::Opened> {
        use crate::sync::Opened;
        let mut found = None;
        for (e, secret) in self.read_epochs(t, &[]).into_iter().rev() {
            if let Ok(x) = osis_blob::open_fire(bytes, t, &e, &osis_crypto::role_kem(&secret)) {
                found = Some((e, x));
                break;
            }
        }
        let Some((under, (prefix, fire))) = found else { return Ok(Opened::NotOpen) };
        let Ok(commit) = osis_commit::CommitBlob::decode(&osis_base::encode(&fire.commit)) else { return Ok(Opened::Bad) };
        let h = &commit.header;
        let one = matches!(commit.parts.as_slice(), [p] if h.aspects.get(p.ai).is_some_and(|a| a.tid == *t && a.ak.external()));
        if !one || !h.is_resolved() {
            return Ok(Opened::Bad);
        }
        let ais: Vec<usize> = (0..h.aspects.len()).collect();
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        if !prefix.agrees(osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &h.blind, &groups, osis_blob::Class::of_marker(h.ephemeral)) {
            return Ok(Opened::Bad);
        }
        if let (Some(r), Some(p)) = (self.core.created(t), commit.parts.first())
            && h.aspects.get(p.ai).is_some_and(|a| osis_crypto::delta_hash(&osis_crypto::dedup_secret(r.nonce()), &p.delta) != a.hash)
        {
            return Ok(Opened::Bad);
        }
        // the evidence and records with the fire, kept only if the fire applies valid
        // (`ingest_sealed_fire`)
        let records: Vec<osis_base::CreationRecord> = fire.records.into_iter().filter(|r| self.core.created(&r.tid()).is_none()).collect();
        let evidence: Vec<Vec<u8>> = fire.evidence.iter().map(osis_base::encode).collect();
        let id = commit.id();
        let parts: Vec<usize> = commit.parts.iter().map(|p| p.ai).collect();
        // a grant from outside: its carried commit is taken with the fire by every node holding
        // it valid (spec/sync-inbox.md §5 Carried commits)
        let grant = commit.parts.first().is_some_and(|p| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == GRANT_FIRE));
        // a stranded notice: a writer of `t` acts on it as it takes it, whatever `t`'s history
        // setting (spec/sync-inbox.md §5 Stranded notice)
        let stranded = self.stranded_notice(t, &commit);
        // its delta came under the keyset it is sealed to: an opening under that epoch, as a
        // section's (spec/crypto.md §5 Passing on)
        self.note_opened(&commit.header, &[(*t, under, commit.parts.iter().collect())]);
        let Some(ingested) = self.ingest_sealed_fire(records, &evidence, commit, fire.pages)? else { return Ok(Opened::Bad) };
        // a fault of this node's is no judgment of the blob: kept to open again
        if matches!(ingested, crate::Ingested::Pending(_, crate::Reason::Fault)) {
            return Ok(Opened::NotOpen);
        }
        // one ahead of the clock waits (`ingest_sealed_fire`): what it carries is taken once it
        // applies valid (`take_carried`)
        let applied = !matches!(ingested, crate::Ingested::Pending(..));
        if applied && grant {
            self.take_fire(&id)?;
        }
        if applied && let Some((s, holder, keys)) = stranded {
            self.take_stranded_from(&s, &holder, &keys, crate::apply::carriers::Carrier::Fire(id))?;
        }
        if applied {
            self.run(|tx| {
                tx.core.ix.fires_due.remove(&id);
                Ok(())
            })?;
        }
        let row = crate::sync::BlobOf { commit: id, parts: parts.into_iter().collect(), sealed: Default::default(), copy: false, unchecked: false, salt: *prefix.salt(), ais: ais.into_iter().collect() };
        let b = *b;
        self.run(|tx| crate::sync::bodies::note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }

    /// The report stranded notice `fire` on `t` carries (`Engine::fire_stranded`): its sync ID,
    /// holder and holder keys. `None` for any other fire, or one that does not decode.
    fn stranded_notice(&self, t: &Tid, fire: &osis_commit::CommitBlob) -> Option<(osis_base::SyncId, Tid, osis_blob::HolderKeys)> {
        let h = &fire.header;
        let p = fire.parts.first().filter(|p| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == STRANDED_FIRE))?;
        let dedup = self.core.dedup(t)?;
        let mut interner = osis_crdt::Interner::new();
        notice_of(&osis_commit::verify_part(h, &fire.id(), p, &dedup, &mut interner, None).ok()?.into_fragment().read()?)
    }
}

/// The report a stranded notice's value `v` holds (`Engine::fire_stranded`): its sync ID, holder
/// and holder keys.
fn notice_of(v: &Value) -> Option<(osis_base::SyncId, Tid, osis_blob::HolderKeys)> {
    let Value::Map(m) = v else { return None };
    let (Some(Value::Bytes(s)), Some(Value::Weak(holder)), Some(Value::List(commits)), Some(Value::List(records))) = (m.get(&Value::Int(0)), m.get(&Value::Int(1)), m.get(&Value::Int(2)), m.get(&Value::Int(3))) else { return None };
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let decoded = |l: &[Value]| l.iter().map(|x| if let Value::Bytes(b) = x { osis_base::decode(b, &limits).ok() } else { None }).collect::<Option<Vec<Value>>>();
    let commits = Value::List(decoded(commits)?);
    let records = Value::List(decoded(records)?);
    let keys = osis_blob::HolderKeys::from_values(&commits, &records).ok()?;
    Some((osis_base::SyncId(s.as_slice().try_into().ok()?), *holder, keys))
}

/// Whether fire `c` holds its part on signal `ak` held and valid here: only such a fire is taken
/// (its carried commit, `take_fire`), whatever it carries (spec/permissions.md §5.2 External
/// fires, spec/sync-inbox.md §5). What was taken while it was valid stands.
fn held_valid(core: &crate::engine::Core, c: &CommitId, ak: &str) -> bool {
    core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().enumerate().any(|(ai, a)| a.ak.as_str() == ak && m.holds(ai) && m.valid_at(ai)))
}

/// The value fire commit `c` holds on external signal `ak`, as held here.
fn fire_value(tx: &mut Tx<'_>, c: &CommitId, ak: &str) -> Result<Option<Value>> {
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(None) };
    let Some(ai) = m.header.aspects.iter().position(|a| a.ak.as_str() == ak) else { return Ok(None) };
    // the part whole, its pages joined: a fire's value may page
    Ok(crate::apply::held_fragment(tx, c, ai)?.and_then(|f| f.read()))
}
