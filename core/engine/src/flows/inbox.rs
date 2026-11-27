//! External signals (spec/sync-inbox.md §1, §2, §5): fires of any external signal on any thing
//! that enables it (a stranded notice taken for what it carries), fired sealed by anyone holding the thing's keys (a card of a thing
//! whose inbox it is, or as a fellow holder), promoted by a writer.

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

/// Grant signals.
pub const GRANT_FIRE: &str = ct::INBOX_SIGNALS[0];
/// Stranded notices.
pub const STRANDED_FIRE: &str = ct::INBOX_SIGNALS[1];

/// `sg/` + fire commit: a held grant signal followed (`Engine::take_fire`): the thing it
/// names and that thing's sync ID.
const SIGNALS: &[u8] = b"sg/";

impl Engine {
    /// Takes what each due fire carries (`Indexes::fires_due`, `take_fire`) and what each card
    /// due a look does (`take_cards`): whether any was due.
    pub fn take_carried(&mut self) -> Result<bool> {
        let cards = self.take_cards()? | self.drop_signals()?;
        let due: Vec<CommitId> = self.core.ix.fires_due.iter().copied().collect();
        if due.is_empty() {
            return Ok(cards);
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
    /// stranded notice's report; a grant signal's thing, followed while the fire is held
    /// (`follow_signal`).
    pub(crate) fn take_fire(&mut self, fire: &CommitId) -> Result<()> {
        let id = *fire;
        if self.read(|tx| Ok(held_valid(tx.core, &id, GRANT_FIRE)))?
            && let Some(v) = self.read(|tx| fire_value(tx, &id, GRANT_FIRE))?
            && let Some((x, s, _)) = signal_of(&v)
        {
            self.run(|tx| tx.txn.put_local(&[SIGNALS, &id.0].concat(), &[x.as_bytes().as_slice(), &s.0].concat(), Shred::No).map_err(Into::into))?;
            self.core.followed_links.follow_signal(x, s, id);
        }
        // a stranded notice that applied after it was opened (one ahead of the clock): acted on
        // as one taken at its opening is
        if self.read(|tx| Ok(held_valid(tx.core, &id, STRANDED_FIRE)))?
            && let Some(v) = self.read(|tx| fire_value(tx, &id, STRANDED_FIRE))?
            && let Some((s, holder, keys)) = notice_of(&v)
        {
            self.take_stranded_from(&s, &holder, &keys, crate::apply::carriers::Carrier::Fire(id))?;
        }
        Ok(())
    }

    /// Tells `holder` of its role on `target` (spec/sync-inbox.md §5 Grant signal): owes a
    /// `grant@~0` fire on the holder's inbox (as its `keys.0` names it here, else the holder)
    /// whose value names `target`, its independent's sync ID and `peers`. Nothing where `target`'s
    /// independent owns no sync ID here, or the holder is the public or an own thing.
    pub fn signal_grant(&mut self, target: &Tid, holder: &Tid, peers: &[osis_blob::DialHint]) -> Result<()> {
        if holder.is_public() || self.core.is_own(holder) {
            return Ok(());
        }
        let Some(a) = self.core.secret_actor(target) else { return Ok(()) };
        let Some(s) = self.sync_id_of(&a)? else { return Ok(()) };
        let inbox = self.inbox_of(holder)?.unwrap_or(*holder);
        let dials = Value::List(peers.iter().map(|p| osis_schema::Codec::to_value(&ct::Dial { key: p.dialable.to_vec(), urls: p.urls.clone() })).collect());
        let v = osis_schema::codec::rt::struct_value(vec![(0, Value::Weak(a)), (1, Value::Bytes(s.0.to_vec())), (2, dials)]);
        let ak = super::ak(GRANT_FIRE)?;
        let to = BTreeSet::from([*holder]);
        self.run(|tx| save(tx, OwedFire { thing: inbox, ak, what: Fire::Value(v), to, commit: None, pages: Default::default() }))
    }

    /// Lets go each followed grant signal no longer held valid here (spec/sync-inbox.md §5: held
    /// while the inbox's setting keeps it): whether any went.
    fn drop_signals(&mut self) -> Result<bool> {
        if !self.core.followed_links.signals_loaded {
            let rows = self.read(load_signals)?;
            for (c, x, s) in rows {
                self.core.followed_links.follow_signal(x, s, c);
            }
            self.core.followed_links.signals_loaded = true;
        }
        let gone: Vec<(Tid, CommitId)> = self.core.followed_links.signals().iter().flat_map(|(x, (_, cs))| cs.iter().map(move |c| (*x, *c))).filter(|(_, c)| !held_valid(&self.core, c, GRANT_FIRE)).collect();
        if gone.is_empty() {
            return Ok(false);
        }
        self.run(|tx| {
            for (_, c) in &gone {
                tx.txn.remove_local(&[SIGNALS, &c.0].concat(), Shred::No)?;
            }
            Ok(())
        })?;
        for (x, c) in &gone {
            self.core.followed_links.unfollow_signal(x, c);
            self.core.lost_due.insert(*x);
        }
        Ok(true)
    }

    /// The peers the held grant signals name, as dial hints.
    pub fn signal_hints(&mut self) -> Result<Vec<osis_blob::DialHint>> {
        let cs: Vec<CommitId> = self.core.followed_links.signals().values().flat_map(|(_, cs)| cs.iter().copied()).collect();
        let mut out = Vec::new();
        for c in cs {
            if let Some(v) = self.read(|tx| fire_value(tx, &c, GRANT_FIRE))?
                && let Some((_, _, peers)) = signal_of(&v)
            {
                out.extend(peers);
            }
        }
        Ok(out)
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

/// Whether a valid fire of signal `ak` is taken for what it carries (`Engine::take_fire`): a
/// stranded notice, a grant signal.
pub(crate) fn carries(ak: &str) -> bool {
    ak == STRANDED_FIRE || ak == GRANT_FIRE
}

/// What grant signal value `v` names (`Engine::signal_grant`): the thing, its sync ID and the
/// peers to dial.
fn signal_of(v: &Value) -> Option<(Tid, osis_base::SyncId, Vec<osis_blob::DialHint>)> {
    let Value::Map(m) = v else { return None };
    let (Some(Value::Weak(x)), Some(Value::Bytes(s))) = (m.get(&Value::Int(0)), m.get(&Value::Int(1))) else { return None };
    let peers = match m.get(&Value::Int(2)) {
        Some(Value::List(l)) => l.iter().filter_map(|d| <ct::Dial as osis_schema::Codec>::from_value(d).ok()).filter_map(|d| Some(osis_blob::DialHint { dialable: d.key.as_slice().try_into().ok()?, urls: d.urls })).collect(),
        _ => Vec::new(),
    };
    Some((*x, osis_base::SyncId(s.as_slice().try_into().ok()?), peers))
}

/// The held grant signals followed (`SIGNALS` rows), read at this engine's first take.
fn load_signals(tx: &mut Tx<'_>) -> Result<Vec<(CommitId, Tid, osis_base::SyncId)>> {
    let bad = || Error::Corrupt("grant signal row");
    let rows = tx.scan_rows(SIGNALS, |k, v| {
        let c = CommitId(k.try_into().map_err(|_| bad())?);
        let (x, s) = v.split_at_checked(osis_base::format::TID_LEN).ok_or_else(bad)?;
        Ok((c, Tid::from_bytes(x.try_into().map_err(|_| bad())?), osis_base::SyncId(s.try_into().map_err(|_| bad())?)))
    })?;
    Ok(rows)
}

/// A sealed fire's ID: BLAKE3 of `[thing, ak, value]`, so the same fire is owed once.
pub type FireId = [u8; 32];

/// `node/fires/` + fire ID: a sealed fire owed (`OwedFire`).
pub(crate) const FIRES: &[u8] = b"node/fires/";

/// A fire of external signal `ak` on `thing` this node owes until a peer takes it (spec/sync-inbox.md §2): offered to peers
/// where `to` (an account holding a role on the thing) is proven; a fire's commit built once
/// (`commit`, a `CommitBlob`'s bytes), sealed again whenever the thing's read keyset moves.
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
}

impl Fire {
    fn to_value(&self) -> Value {
        match self {
            Fire::Value(v) => Value::List(vec![Value::Int(0), v.clone()]),
            Fire::Expiring(v, t) => Value::List(vec![Value::Int(2), v.clone(), Value::Int(i64::try_from(*t).unwrap_or(i64::MAX))]),
        }
    }
    fn from_value(v: &Value) -> Option<Fire> {
        let Value::List(f) = v else { return None };
        match f.as_slice() {
            [Value::Int(0), v] => Some(Fire::Value(v.clone())),
            [Value::Int(2), v, Value::Int(t)] => Some(Fire::Expiring(v.clone(), u64::try_from(*t).ok()?)),
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
        let [Value::Bytes(t), ak, what, Value::List(to), Value::List(c), Value::List(pages)] = f.as_slice() else { return Err(bad()) };
        let Value::Str(ak) = ak else { return Err(bad()) };
        let ak = Ak::new(ak.as_str()).map_err(|_| bad())?;
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
        Ok(OwedFire { thing: tid(t)?, ak, what, to, commit, pages: Arc::new(pages) })
    }
}

/// Loads the owed fires (an open).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let rows = tx.scan_rows(FIRES, |_, v| OwedFire::decode(&v))?;
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
        let me = tx.core.tid();
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

/// A fire's commit built, with the blobs its delta links.
type Built = (osis_commit::CommitBlob, Arc<Vec<Vec<u8>>>);

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

    /// Whether a sealed fire's delivery is pending here (spec/sync-inbox.md §2): one owed, but a
    /// stranded notice past its expiry (owed no more: no receiver would keep it). A wait on all
    /// waits for these (spec/sync-status.md §3). O(fires owed).
    pub fn delivering(&self) -> bool {
        let now = self.now().0;
        self.core.ix.fires.values().any(|o| !matches!(o.what, Fire::Expiring(_, t) if now >= t))
    }

    /// Owed fire `id`'s commit once built (`sealed_fire`): its ID and the wall time it is stamped, which a receiver's clock must have reached but for
    /// `MAX_DRIFT`.
    pub fn fire_commit(&self, id: &FireId) -> Option<(CommitId, osis_base::WallMs)> {
        let o = self.core.ix.fires.get(id)?;
        let b = osis_commit::CommitBlob::decode(o.commit.as_ref()?).ok()?;
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
        // none beside a KEM-less read keyset: nothing from outside is sealed to it
        let Some(ct::KemKey::X25519MlKem768(b)) = &rk.kem_key else { return Ok(None) };
        let (Ok(e), Ok(kem)) = (osis_keys::aspects::from_schema(&rk.epoch), osis_crypto::KemPublicKey::from_slice(b)) else { return Ok(None) };
        Ok(Some((e, kem, s)))
    }

    /// Fire `id` sealed now (spec/sync-inbox.md §2, spec/wire.md §9): its commit (built once, by
    /// this node's account, one delta: the fire) with its evidence (its signer's record and, an
    /// account's, its rotations to the epoch it signs at: spec/permissions.md §4), behind the
    /// commit's prefix, sealed to its thing's read key in force held (`fire_keys`). `None`: not
    /// owed, or no such key is held (the thing's public key record, or step keys whose read key
    /// is of its read keyset's epoch).
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
        let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
        let as_value = |b: &[u8]| osis_base::decode(b, &limits).map_err(|_| Error::Corrupt("commit blob"));
        let (blob, pages) = match &o.commit {
            Some(b) => (osis_commit::CommitBlob::decode(b)?, o.pages.clone()),
            None => match self.build_fire(&o)? {
                Some(x) => x,
                None => return Ok(None),
            },
        };
        let (evidence, records) = self.signer_evidence(&blob.header.signer)?;
        // the fire's own pages, then its evidence's
        let ev: Vec<Vec<u8>> = evidence.iter().map(osis_base::encode).collect();
        let ev_pages = self.run(|tx| held_pages(tx, &ev.iter().map(Vec::as_slice).collect::<Vec<_>>()))?;
        let pages = pages.iter().cloned().chain(ev_pages).collect();
        let fire = osis_blob::SealedFire { copy: false, commit: as_value(&blob.encode())?, evidence, records, pages };
        let ais = sealed_ais(&blob, fire.copy);
        let sealed = self.seal_payload(&blob.header, &ais, &o.thing, &epoch, &kem, &osis_blob::Sealed::Fire(fire))?;
        Ok(Some(SealedFireOut { sync_id, thing: o.thing, to: o.to.clone(), blob: sealed }))
    }

    /// Notice `n` sealed (`sync::notices`): its removal's certificate copy on its thing (the
    /// edge-class parts), with the copies of its evidence, their records and pages, under blob key
    /// `key`, that key sealed to `kem`, the read KEM key of the holder's keyset at the notice's
    /// epoch (spec/wire.md §9 Notice). `None` while the removal is not applied here.
    pub(crate) fn sealed_notice(&mut self, n: &crate::sync::notices::Notice, kem: &osis_crypto::KemPublicKey, key: &osis_crypto::Secret32) -> Result<Option<Vec<u8>>> {
        // a commit boxing the holder tells it its box; a removal, its edge-class parts
        let pieces = self.header(&n.commit).map(|h| h.aspect_parts(&n.thing, "secrets.0")).unwrap_or(0..0);
        let named = self.holders_named(&n.commit);
        let boxes = pieces.filter_map(|ai| named.get(&ai)).any(|hs| hs.contains(&n.holder));
        let cut = if boxes { crate::sync_ids::Cut::Told { holder: n.holder } } else { crate::sync_ids::Cut::Evidence { step: false } };
        let Some(p) = self.cert_copy(&n.commit, &n.thing, cut)? else { return Ok(None) };
        let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
        let as_value = |b: &[u8]| osis_base::decode(b, &limits).map_err(|_| Error::Corrupt("commit blob"));
        let copy = osis_commit::CommitBlob::decode(&p.copy)?;
        let evidence = p.evidence.iter().map(|c| as_value(c)).collect::<Result<Vec<_>>>()?;
        let fire = osis_blob::SealedFire { copy: true, commit: as_value(&p.copy)?, evidence, records: p.records, pages: p.pages };
        let ais = sealed_ais(&copy, true);
        let (prefix, _) = self.sealed_prefix(&copy.header, &ais)?;
        Ok(Some(osis_blob::seal_notice(&prefix, kem, key, &osis_blob::NoticeBody { holder: n.holder, epoch: n.epoch, copy: fire })?))
    }

    /// Seals `fire` to `thing`'s read KEM key `kem` at `epoch`, behind the prefix of header `h`'s
    /// encryption of parts `ais` (spec/wire.md §9).
    fn seal_payload(&mut self, h: &osis_commit::Header, ais: &[usize], thing: &Tid, epoch: &osis_crypto::Epoch, kem: &osis_crypto::KemPublicKey, fire: &osis_blob::Sealed) -> Result<Vec<u8>> {
        let (prefix, mut rng) = self.sealed_prefix(h, ais)?;
        Ok(osis_blob::seal_fire(&prefix, thing, epoch, kem, fire, &mut rng)?)
    }

    /// The prefix of header `h`'s encryption of parts `ais` (a fresh salt), and the randomness
    /// that drew it, for what is sealed behind it.
    fn sealed_prefix(&mut self, h: &osis_commit::Header, ais: &[usize]) -> Result<(osis_blob::Prefix, osis_crypto::SeededRng)> {
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        let seed = self.run(|tx| Ok(osis_crypto::Secret32::random(&mut *tx.rng)))?;
        let mut rng = osis_crypto::SeededRng::from_seed(*seed.expose());
        let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(h, ais).map(osis_base::WallMs), &groups)?;
        Ok((prefix, rng))
    }

    /// Builds owed fire `o`'s commit (by this node's account, one delta: the fire) and keeps it
    /// with the fire, or, where this node holds and reads the thing and its setting keeps the
    /// fire, writes it as any write and owes it no more (`None`).
    fn build_fire(&mut self, o: &OwedFire) -> Result<Option<Built>> {
        let ak = o.ak.clone();
        let (value, expires) = match &o.what {
            Fire::Value(v) => (v.clone(), None),
            Fire::Expiring(v, t) => (v.clone(), Some(osis_base::WallMs(*t))),
        };
        let o = o.clone();
        self.run(|tx| {
            let mut m = Mutation::new();
            m.op(o.thing, &ak, PathOp { path: Vec::new(), op: Op::Set(value) })?;
            if let Some(t) = expires {
                m.expires(o.thing, &ak, t)?;
            }
            // a node holding and reading the thing now fires as it writes where the setting
            // keeps the fire (spec/sync-inbox.md §2); else the fire it owes already goes sealed,
            // its receivers judging it
            if tx.core.ix.closure.holds(&o.thing) && reads_now(tx.core, &o.thing) && keeps_fire(tx.core, &o.thing, &ak) {
                Engine::commit_tx(tx, m)?;
                drop_fire(tx, &o.id())?;
                return Ok(None);
            }
            m.commit_form();
            let b = crate::engine::write::sealed_commit(tx, m)?;
            let pages = Arc::new(built_pages(tx, &b)?);
            save(tx, OwedFire { commit: Some(Arc::new(b.encode())), pages: pages.clone(), ..o })?;
            Ok(Some((b, pages)))
        })
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

    /// Commit `c`'s certificate copy on `target` (`CertCopy`: its header and `cut`'s parts there),
    /// the copies of its evidence, their creation records and the blobs their deltas link
    /// (`held_pages`). `None` while `c` is not applied here.
    pub(crate) fn cert_copy(&mut self, c: &CommitId, target: &Tid, cut: crate::sync_ids::Cut) -> Result<Option<CertCopy>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let parts = self.cut_parts(&id, target, cut);
        let (evidence, records) = self.copy_evidence(&(id, *target))?;
        let copy = osis_commit::rewrite(&full, |ai| !parts.contains(&ai));
        let (copy, evidence): (Vec<u8>, Vec<Vec<u8>>) = (copy.encode(), evidence.iter().map(osis_base::encode).collect());
        let all: Vec<&[u8]> = [copy.as_slice()].into_iter().chain(evidence.iter().map(Vec::as_slice)).collect();
        let pages = self.run(|tx| held_pages(tx, &all))?;
        Ok(Some(CertCopy { copy, evidence, records, pages }))
    }
}

/// A commit's certificate copy on a thing as it travels sealed (a notice's, spec/wire.md §9): the
/// copy, the copies of its evidence, their creation records and the blobs their deltas link. Held
/// only as the copy and its evidence judge it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertCopy {
    /// The copy, a `CommitBlobPlaintext`'s bytes.
    pub copy: Vec<u8>,
    pub evidence: Vec<Vec<u8>>,
    pub records: Vec<osis_base::CreationRecord>,
    pub pages: Vec<Vec<u8>>,
}

impl CertCopy {
    /// The thing copy `b` is on: every part a role-class part on that one thing (spec/permissions.md
    /// §4 Copies), at least one. `None` for any other commit.
    pub fn target(b: &osis_commit::CommitBlob) -> Option<Tid> {
        let mut on = b.parts.iter().map(|p| b.header.aspects.get(p.ai).filter(|a| ct::ROLE_CLASS.contains(&a.ak.as_str())).map(|a| a.tid));
        let first = on.next()??;
        on.all(|t| t == Some(first)).then_some(first)
    }
}

/// The aspects a sealed fire's or notice's prefix covers (spec/wire.md §9: its commit's
/// encryption's): a fire's every aspect, a notice copy's its parts.
fn sealed_ais(b: &osis_commit::CommitBlob, copy: bool) -> Vec<usize> {
    match copy {
        true => b.parts.iter().map(|p| p.ai).collect(),
        false => (0..b.header.aspects.len()).collect(),
    }
}

/// The blobs the deltas of `commits` (held commits or copies of them: a piece's copy and its
/// evidence, a fire's evidence, as `CommitBlobPlaintext` bytes) link, as held: what travels with
/// them (spec/wire.md §9), so a receiver holding none of the things they write applies each
/// (`apply::split_pages`).
pub(crate) fn held_pages(tx: &mut Tx<'_>, commits: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
    let mut trees = crate::engine::large::Trees::default();
    for c in commits {
        let b = osis_commit::CommitBlob::decode(c).map_err(|_| Error::Corrupt("a held commit's copy"))?;
        for p in &b.parts {
            let Some(dedup) = b.header.aspects.get(p.ai).and_then(|a| tx.core.dedup(&a.tid)) else { continue };
            crate::engine::large::tree_blobs(tx, &dedup, &crate::engine::large::delta_roots(&p.delta), &mut trees)?;
        }
    }
    trees.blobs.iter().map(|id| tx.blobs.get(id)?.ok_or(Error::Corrupt("a held commit's page"))).collect()
}

impl Engine {
    /// Opens entry `b` (`bytes`) of thing `t`'s sync ID as a sealed fire (spec/sync-inbox.md §4
    /// A sealed fire): with the read secret of each keyset of `t` held, newest first; takes the
    /// commit, which holds one delta: a fire of an external signal of `t` whose hash and prefix agree
    /// with its header, with the author's records and its chain's commits it carries as
    /// certificates, all or nothing: `Bad` unless the fire applies valid. `NotOpen` when no
    /// held key opens it.
    /// Invariant (security): anyone holding a keyset of `t`'s (its card, or old keys of a reader
    /// removed since) seals one; what it carries counts only as judged valid here
    /// (`ingest_sealed_fire`), so a forged copy gives no role, box or sync ID, and a replayed one
    /// is the old commit it was, held as any commit (spec/commits.md §5).
    pub(crate) fn open_sealed_fire(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8]) -> Result<crate::sync::Opened> {
        self.bringing(|e| e.open_fire_in(t, b, bytes))
    }

    fn open_fire_in(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8]) -> Result<crate::sync::Opened> {
        use crate::sync::Opened;
        let mut found = None;
        for (e, secret) in self.read_epochs(t, &[]).into_iter().rev() {
            if let Ok(x) = osis_blob::open_fire(bytes, t, &e, secret.kem()) {
                found = Some((e, x));
                break;
            }
        }
        let Some((under, (prefix, fire))) = found else { return Ok(Opened::NotOpen) };
        // only a fire is sealed to a thing's read key (a copy to a holder goes as a notice)
        let fire = match fire {
            osis_blob::Sealed::SyncCopy(_) => return Ok(Opened::Bad),
            osis_blob::Sealed::Fire(f) => f,
        };
        self.take_sealed(t, b, prefix, fire, Some(under), None)
    }

    /// Opens entry `b` (`bytes`) of thing `t`'s sync ID as a notice (spec/permissions.md §4
    /// Notices, spec/wire.md §9): by its blob key `key` where the entry's wrap opened here (its
    /// box checked against the holder it names, `osis_blob::open_notice`), else by the read KEM
    /// secrets this node holds of a holder of `t` (`notice_key_held`); takes the copy it carries,
    /// on `t` itself, as a sealed copy. `NotOpen` when nothing held opens it, or its box cannot be
    /// checked here.
    pub(crate) fn open_notice(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8], key: Option<osis_crypto::Secret32>) -> Result<crate::sync::Opened> {
        self.bringing(|e| e.open_notice_in(t, b, bytes, key))
    }

    fn open_notice_in(&mut self, t: &Tid, b: &osis_base::BlobId, bytes: &[u8], key: Option<osis_crypto::Secret32>) -> Result<crate::sync::Opened> {
        use crate::sync::Opened;
        // opened by its wrap: a reader of `t`, holding what it tells already or reaching it by
        // `t`'s own entries; it notes what the notice is and takes nothing of it
        let by_wrap = key.is_some();
        let key = match key {
            Some(k) => k,
            None => match self.notice_key_held(t, bytes)? {
                Some(k) => k,
                None => return Ok(Opened::NotOpen),
            },
        };
        let kem_of = |h: &Tid, e: &osis_crypto::Epoch| {
            let own = self.epochs(h).and_then(|x| x.read.secret(e).map(|s| s.kem().public().clone()));
            own.or_else(|| self.read(|tx| crate::apply::keys::keyset_kem(tx, h, Role::Read, e)).ok().flatten())
        };
        match osis_blob::open_notice(bytes, &key, kem_of) {
            Err(_) => Ok(Opened::Bad),
            Ok(None) => Ok(Opened::NotOpen),
            Ok(Some((_, body))) if by_wrap => {
                let Ok(copy) = osis_commit::CommitBlob::decode(&osis_base::encode(&body.copy.commit)) else { return Ok(Opened::Bad) };
                if CertCopy::target(&copy) != Some(*t) {
                    return Ok(Opened::Bad);
                }
                let n = crate::sync::notices::Notice { thing: *t, commit: copy.id(), holder: body.holder, epoch: body.epoch };
                let b = *b;
                self.run(|tx| crate::sync::notices::note(tx, &b, n))?;
                Ok(Opened::Notice(n.commit, crate::Ingested::Duplicate(n.commit)))
            }
            Ok(Some((prefix, body))) => self.take_sealed(t, b, prefix, body.copy, None, Some((body.holder, body.epoch))),
        }
    }

    /// The blob key of notice `bytes` under `t`'s sync ID that a read KEM secret held here of a
    /// holder of `t` for keys opens, or of a thing on this node's own chains (`own_chains`): a
    /// departed holder learns its removal so, holding no epoch of `t` its notice's wrap is under,
    /// and a holder that cannot open a commit boxing it (a grantee entering `t`, holding none of
    /// its roster yet) its box.
    /// Cost: tried on every entry under `t`'s sync ID no wrap opens here (anyone may put one there,
    /// within its bringer's budget: kept unopened, charged as any), one decapsulation per read
    /// epoch held of each such holder, beside `open_fire_in`'s one per epoch of `t`: of the same
    /// order, and nothing a bringer's bytes choose.
    fn notice_key_held(&mut self, t: &Tid, bytes: &[u8]) -> Result<Option<osis_crypto::Secret32>> {
        let mut holders: BTreeSet<Tid> = self.core.key_holders(t).into_iter().map(|(h, _)| h).collect();
        holders.extend(self.own_chains());
        holders.retain(|h| h != t && !h.is_public());
        for h in holders {
            for (e, s) in self.epochs(&h).map(|x| x.read.held().map(|(e, s)| (e, s.clone())).collect::<Vec<_>>()).unwrap_or_default().into_iter().rev() {
                if let Ok(k) = osis_blob::notice_key(bytes, &h, &e, s.kem()) {
                    return Ok(Some(k));
                }
            }
        }
        Ok(None)
    }

    /// The things on this node's own chains whose read epochs it holds: its own things, then each
    /// thing one of these holds a role on, transitively (what a notice to a holder this node
    /// reads through may be sealed to).
    fn own_chains(&self) -> BTreeSet<Tid> {
        let mut out = BTreeSet::new();
        let mut work: Vec<Tid> = std::iter::once(self.core.tid()).chain(self.core.link_keys.keys().copied()).collect();
        while let Some(h) = work.pop() {
            if !out.insert(h) {
                continue;
            }
            work.extend(self.core.ix.held.named_on(&h).copied().filter(|x| self.epochs(x).is_some_and(|e| e.read.held().next().is_some())));
        }
        out
    }

    /// Takes sealed fire or notice copy `fire` opened from entry `b` of `t`'s sync ID behind `prefix`
    /// (`open_fire_in`, under read epoch `under` of `t`; `open_notice_in`, a notice to `notice`'s
    /// holder and keyset): the commit, all or nothing: `Bad` unless it applies valid.
    fn take_sealed(&mut self, t: &Tid, b: &osis_base::BlobId, prefix: osis_blob::Prefix, fire: osis_blob::SealedFire, under: Option<osis_crypto::Epoch>, notice: Option<(Tid, osis_crypto::Epoch)>) -> Result<crate::sync::Opened> {
        use crate::sync::Opened;
        let Ok(commit) = osis_commit::CommitBlob::decode(&osis_base::encode(&fire.commit)) else { return Ok(Opened::Bad) };
        let h = &commit.header;
        // a sealed fire: one delta, a fire of an external signal of `t`; a notice: a certificate
        // copy on `t` itself (spec/permissions.md §4 Notices)
        let one = match (fire.copy, notice.is_some()) {
            (false, false) => matches!(commit.parts.as_slice(), [p] if h.aspects.get(p.ai).is_some_and(|a| a.tid == *t && a.ak.external())),
            (true, true) => CertCopy::target(&commit) == Some(*t),
            _ => false,
        };
        if !one || !h.is_resolved() {
            return Ok(Opened::Bad);
        }
        let ais = sealed_ais(&commit, fire.copy);
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        if !prefix.agrees(osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &h.blind, &groups, osis_blob::Class::of_marker(h.ephemeral)) {
            return Ok(Opened::Bad);
        }
        if !fire.copy
            && let (Some(r), Some(p)) = (self.core.created(t), commit.parts.first())
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
        // a stranded notice: a writer of `t` acts on it as it takes it, whatever `t`'s history
        // setting (spec/sync-inbox.md §5 Stranded notice)
        let stranded = self.stranded_notice(t, &commit);
        // a fire's delta came under the keyset it is sealed to: an opening under that epoch, as a
        // section's (spec/crypto.md §5 Passing on); a copy's role parts pass on by no opening
        if let (false, Some(under)) = (fire.copy, under) {
            self.note_opened(&commit.header, &[(*t, under, commit.parts.iter().collect())]);
        }
        let Some(ingested) = self.ingest_sealed_fire(records, &evidence, commit, &fire.pages)? else { return Ok(Opened::Bad) };
        // a fault of this node's is no judgment of the blob: kept to open again
        if matches!(ingested, crate::Ingested::Pending(_, crate::Reason::Fault)) {
            return Ok(Opened::NotOpen);
        }
        // one ahead of the clock waits (`ingest_sealed_fire`): what it carries is taken once it
        // applies valid (`take_carried`)
        let applied = !matches!(ingested, crate::Ingested::Pending(..));
        match stranded {
            Some((s, holder, keys)) if applied => drop(self.take_stranded_from(&s, &holder, &keys, crate::apply::carriers::Carrier::Fire(id))?),
            // a grant signal: followed while held
            None if applied && !fire.copy => self.take_fire(&id)?,
            _ => {}
        }
        if applied {
            self.run(|tx| {
                tx.core.ix.fires_due.remove(&id);
                // a copy taken: boxes kept out for want of what it carries open now
                if fire.copy {
                    crate::flows::retake(tx)?;
                }
                Ok(())
            })?;
        }
        let b = *b;
        // a notice is no blob of its commit: kept as what it is (`sync::notices`)
        if let Some((holder, epoch)) = notice {
            let n = crate::sync::notices::Notice { thing: *t, commit: id, holder, epoch };
            self.run(|tx| crate::sync::notices::note(tx, &b, n))?;
            return Ok(Opened::Notice(id, ingested));
        }
        let row = crate::sync::BlobOf { commit: id, parts: parts.into_iter().collect(), sealed: Default::default(), copy: fire.copy, unchecked: false, salt: *prefix.salt(), ais: ais.into_iter().collect(), seal: None };
        self.run(|tx| crate::sync::bodies::note_blob(tx, &b, row))?;
        Ok(Opened::Commit(id, ingested))
    }

    /// The report stranded notice `fire` on `t` carries (`Engine::fire_stranded`): its sync ID,
    /// holder and holder keys. `None` for any other fire, or one that does not decode.
    fn stranded_notice(&self, t: &Tid, fire: &osis_commit::CommitBlob) -> Option<(osis_base::SyncId, Tid, osis_blob::Certificates)> {
        let h = &fire.header;
        let p = fire.parts.first().filter(|p| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == STRANDED_FIRE))?;
        let dedup = self.core.dedup(t)?;
        let mut interner = osis_crdt::Interner::new();
        notice_of(&osis_commit::verify_part(h, &fire.id(), p, &dedup, &mut interner, None).ok()?.into_fragment().read()?)
    }
}

/// The report a stranded notice's value `v` holds (`Engine::fire_stranded`): its sync ID, holder
/// and holder keys.
fn notice_of(v: &Value) -> Option<(osis_base::SyncId, Tid, osis_blob::Certificates)> {
    let Value::Map(m) = v else { return None };
    let (Some(Value::Bytes(s)), Some(Value::Weak(holder)), Some(Value::List(commits)), Some(Value::List(records))) = (m.get(&Value::Int(0)), m.get(&Value::Int(1)), m.get(&Value::Int(2)), m.get(&Value::Int(3))) else { return None };
    let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
    let decoded = |l: &[Value]| l.iter().map(|x| if let Value::Bytes(b) = x { osis_base::decode(b, &limits).ok() } else { None }).collect::<Option<Vec<Value>>>();
    let commits = Value::List(decoded(commits)?);
    let records = Value::List(decoded(records)?);
    let keys = osis_blob::Certificates::from_values(&commits, &records, usize::MAX).ok()?;
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
