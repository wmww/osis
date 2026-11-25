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

/// Edge write commit `c` of `target` naming `holder` (a grant, a change, a removal), as the
/// holder's readers learn of it (spec/permissions.md §4 Delivering an edge piece): a holder this
/// node may write has it in its key part, logged under its own sync ID; any other is offered it
/// by a `grant@~0` fire (`fire_copy`; spec/sync-inbox.md §5 Grant from outside).
pub(crate) fn deliver_copy(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let me = tx.core.me();
    // an edge piece naming the public is delivered nowhere (spec/permissions.md §4): it has no
    // inbox, and every party reads its boxes where it reads the target
    if holder.is_public() || tx.core.role_now(&me, &holder) >= Some(Role::Write) {
        return Ok(());
    }
    fire_copy(tx, holder, c, target)
}

/// Rotation or re-seal commit `c` of `target` boxing `holder` where the holder holds no box at
/// the epoch it is wrapped under (spec/permissions.md §4 Delivering an edge piece): a holder this
/// node may write has it in its key part; any other is sent it as a sealed copy under its own
/// sync ID (spec/sync-inbox.md §2 Sealed copy), which its readers take as judged. One already
/// owed stays as it is.
pub(crate) fn deliver_sealed(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let me = tx.core.me();
    // the public, as in `deliver_copy`: no sync ID, its boxes read wherever the target is
    if holder.is_public() || tx.core.role_now(&me, &holder) >= Some(Role::Write) {
        return Ok(());
    }
    let to = fire_to(tx, &holder);
    let o = OwedFire { thing: holder, ak: None, what: Fire::Copy { commit: c, target }, to, commit: None, pages: Default::default() };
    if tx.core.ix.fires.contains_key(&o.id()) {
        return Ok(());
    }
    save(tx, o)
}

/// Fires `grant@~0` on `holder`'s inbox carrying role commit `c`'s piece on `target`: the fire's
/// value (`Engine::edge_piece`) is made when the fire is first sealed, `c` applied by then. One
/// already owed stays as it is. A holder with no inbox here (not independent here) is fired
/// nothing.
pub(crate) fn fire_copy(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let Some(inbox) = inbox_in(tx, &holder)? else { return Ok(()) };
    let to = fire_to(tx, &holder);
    let o = OwedFire { thing: inbox, ak: Some(super::ak(GRANT_FIRE)?), what: Fire::Grant { commit: c, target }, to, commit: None, pages: Default::default() };
    if tx.core.ix.fires.contains_key(&o.id()) {
        return Ok(());
    }
    save(tx, o)
}

/// The `grant@~0` fire owed on `holder`'s inbox for role commit `c` on `target` is owed no more:
/// its offer went another way (a pairing channel, spec/permissions.md §8 Pairing).
pub(crate) fn unowe_grant(tx: &mut Tx<'_>, holder: Tid, c: CommitId, target: Tid) -> Result<()> {
    let Some(inbox) = inbox_in(tx, &holder)? else { return Ok(()) };
    let ids: Vec<FireId> = tx.core.ix.fires_on.get(&inbox).into_iter().flatten().copied().filter(|id| tx.core.ix.fires.get(id).is_some_and(|o| o.what == Fire::Grant { commit: c, target })).collect();
    for id in ids {
        drop_fire(tx, &id)?;
    }
    Ok(())
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
        let Some(piece) = EdgePiece::from_value(&v) else { return Ok(()) };
        let Some(copy) = osis_commit::CommitBlob::decode(&piece.copy).ok() else { return Ok(()) };
        let Some(target) = EdgePiece::target(&copy) else { return Ok(()) };
        // what the offer carries is needed from before it is taken (`granted_on`)
        if let Some(holder) = self.fired_at(&id) {
            self.run(|tx| note_carried(tx, id, Carried { commit: copy.id(), holder, target }))?;
        }
        self.take_edge_piece(&piece, Some(crate::apply::carriers::Carrier::Fire(id)))?;
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

    /// Takes piece `p` (spec/sync-inbox.md §5 Carried commits; spec/permissions.md §8 Pairing):
    /// its records, then its evidence and its copy, each with the pages its deltas link
    /// (`split_pages`; nothing taken where a page is linked by none), each kept only where judged
    /// valid (`ingest_valid`), pending on what it lacks while `from` carries it, in rounds until
    /// none more applies (an evidence commit judged on one carried after it). The copy's (commit,
    /// target), or `None` with nothing taken where the copy is no certificate copy (`EdgePiece::target`)
    /// or a commit of it or a page is bad input.
    /// Invariant (security): a piece is anyone's to make (any party holding a card of the holder
    /// fires one); what it carries counts only as judged here, so it gives no box, role or sync
    /// ID that the commits it carries do not, valid, give.
    pub(crate) fn take_edge_piece(&mut self, p: &EdgePiece, from: Option<crate::apply::carriers::Carrier>) -> Result<Option<(CommitId, Tid)>> {
        let Ok(blob) = osis_commit::CommitBlob::decode(&p.copy) else { return Ok(None) };
        let Some(target) = EdgePiece::target(&blob) else { return Ok(None) };
        let records: Vec<osis_base::CreationRecord> = p.records.iter().filter(|r| self.core.created(&r.tid()).is_none()).cloned().collect();
        if !records.is_empty() {
            self.learn_records(records)?;
        }
        let copy = blob.id();
        // the evidence, then the copy, each with the pages its deltas link
        let mut blobs = Vec::new();
        for c in &p.evidence {
            match osis_commit::CommitBlob::decode(c) {
                Ok(b) => blobs.push(b),
                Err(_) => return Ok(None),
            }
        }
        blobs.push(blob);
        let refs: Vec<&osis_commit::CommitBlob> = blobs.iter().collect();
        let Some(split) = self.read(|tx| crate::apply::split_pages(tx, &refs, &p.pages))? else { return Ok(None) };
        let all: Vec<(&[u8], Vec<Vec<u8>>)> = p.evidence.iter().map(Vec::as_slice).chain([p.copy.as_slice()]).zip(split).collect();
        let mut left = all;
        loop {
            let before = left.len();
            let mut rest = Vec::new();
            for (c, pages) in std::mem::take(&mut left) {
                if self.ingest_valid_paged(c, &pages, from)?.is_none() {
                    rest.push((c, pages));
                }
            }
            if rest.is_empty() || rest.len() == before {
                return Ok(Some((copy, target)));
            }
            left = rest;
        }
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
        self.run(|tx| save(tx, OwedFire { thing: t, ak: Some(ak), what: Fire::Expiring(v, expires), to: BTreeSet::new(), commit: None, pages: Default::default() }))
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

/// A sealed fire's ID: BLAKE3 of `[thing, ak, value]`, so the same fire is owed once.
pub type FireId = [u8; 32];

/// `node/fires/` + fire ID: a sealed fire owed (`OwedFire`).
pub(crate) const FIRES: &[u8] = b"node/fires/";

/// A fire of external signal `ak` on `thing`, or with no `ak` a sealed copy to `thing`
/// (`Fire::Copy`), this node owes until a peer takes it (spec/sync-inbox.md §2): offered to peers
/// where `to` (an account holding a role on the thing) is proven; a fire's commit built once
/// (`commit`, a `CommitBlob`'s bytes), sealed again whenever the thing's read keyset moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedFire {
    pub thing: Tid,
    pub ak: Option<Ak>,
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
    /// A grant from outside: role commit `commit`'s piece on `target` (`fire_copy`).
    Grant { commit: CommitId, target: Tid },
    /// A sealed copy: role commit `commit`'s piece on `target` (`deliver_sealed`).
    Copy { commit: CommitId, target: Tid },
}

impl Fire {
    fn to_value(&self) -> Value {
        match self {
            Fire::Value(v) => Value::List(vec![Value::Int(0), v.clone()]),
            Fire::Expiring(v, t) => Value::List(vec![Value::Int(2), v.clone(), Value::Int(i64::try_from(*t).unwrap_or(i64::MAX))]),
            Fire::Grant { commit, target } => Value::List(vec![Value::Int(1), Value::Bytes(commit.0.to_vec()), Value::Bytes(target.as_bytes().to_vec())]),
            Fire::Copy { commit, target } => Value::List(vec![Value::Int(3), Value::Bytes(commit.0.to_vec()), Value::Bytes(target.as_bytes().to_vec())]),
        }
    }
    fn from_value(v: &Value) -> Option<Fire> {
        let Value::List(f) = v else { return None };
        match f.as_slice() {
            [Value::Int(0), v] => Some(Fire::Value(v.clone())),
            [Value::Int(2), v, Value::Int(t)] => Some(Fire::Expiring(v.clone(), u64::try_from(*t).ok()?)),
            [Value::Int(n @ (1 | 3)), Value::Bytes(c), Value::Bytes(t)] => {
                let (commit, target) = (CommitId(c.as_slice().try_into().ok()?), Tid::from_bytes(t.as_slice().try_into().ok()?));
                Some(if *n == 1 { Fire::Grant { commit, target } } else { Fire::Copy { commit, target } })
            }
            _ => None,
        }
    }
}

impl OwedFire {
    fn id(&self) -> FireId {
        let v = Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), ak_value(&self.ak), self.what.to_value()]);
        osis_base::hash::hash(&osis_base::encode(&v))
    }
    fn encode(&self) -> Vec<u8> {
        let opt = |b: Option<Vec<u8>>| Value::List(b.into_iter().map(Value::Bytes).collect());
        let pages = Value::List(self.pages.iter().map(|b| Value::Bytes(b.clone())).collect());
        osis_base::encode(&Value::List(vec![Value::Bytes(self.thing.as_bytes().to_vec()), ak_value(&self.ak), self.what.to_value(), Value::List(self.to.iter().map(|t| Value::Bytes(t.as_bytes().to_vec())).collect()), opt(self.commit.as_ref().map(|c| c.to_vec())), pages]))
    }
    fn decode(b: &[u8]) -> Result<OwedFire> {
        let bad = || Error::Corrupt("owed fire");
        let v = osis_base::decode(b, &osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, b.len())).map_err(|_| bad())?;
        let Value::List(f) = v else { return Err(bad()) };
        let [Value::Bytes(t), ak, what, Value::List(to), Value::List(c), Value::List(pages)] = f.as_slice() else { return Err(bad()) };
        let ak = match ak {
            Value::List(l) if l.is_empty() => None,
            Value::Str(a) => Some(Ak::new(a.as_str()).map_err(|_| bad())?),
            _ => return Err(bad()),
        };
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
        if ak.is_none() != matches!(what, Fire::Copy { .. }) {
            return Err(bad());
        }
        Ok(OwedFire { thing: tid(t)?, ak, what, to, commit, pages: Arc::new(pages) })
    }
}

fn ak_value(ak: &Option<Ak>) -> Value {
    ak.as_ref().map_or(Value::List(Vec::new()), |a| Value::Str(a.as_str().into()))
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
        return save(tx, OwedFire { thing, ak: Some(ak), what: Fire::Value(value), to, commit: None, pages: Default::default() });
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
        // a sealed copy: the piece, behind its copy's prefix (spec/sync-inbox.md §2 Sealed copy)
        let (blob, fire) = if let Fire::Copy { commit, target } = &o.what {
            let Some(p) = self.edge_piece(commit, target)? else { return Ok(None) };
            let copy = osis_commit::CommitBlob::decode(&p.copy)?;
            let evidence = p.evidence.iter().map(|c| as_value(c)).collect::<Result<Vec<_>>>()?;
            let fire = osis_blob::SealedFire { copy: true, commit: as_value(&p.copy)?, evidence, records: p.records, pages: p.pages };
            (copy, fire)
        } else {
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
            (blob, fire)
        };
        let h = &blob.header;
        let ais = sealed_ais(&blob, fire.copy);
        let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
        let seed = self.run(|tx| Ok(osis_crypto::Secret32::random(&mut *tx.rng)))?;
        let mut rng = osis_crypto::SeededRng::from_seed(*seed.expose());
        let prefix = osis_blob::Prefix::for_delete_keys(osis_blob::Prefix::random_salt(&mut rng), &h.blind, osis_commit::prefix_expiry(h, &ais).map(osis_base::WallMs), &groups)?;
        let sealed = osis_blob::seal_fire(&prefix, &o.thing, &epoch, &kem, &fire, &mut rng)?;
        Ok(Some(SealedFireOut { sync_id, thing: o.thing, to: o.to.clone(), blob: sealed }))
    }

    /// Builds owed fire `o`'s commit (by this node's account, one delta: the fire) and keeps it
    /// with the fire, or, where this node holds and reads the thing and its setting keeps the
    /// fire, writes it as any write and owes it no more (`None`).
    fn build_fire(&mut self, o: &OwedFire) -> Result<Option<Built>> {
        let ak = o.ak.clone().ok_or(Error::Misuse("a sealed copy builds no commit"))?;
        let (value, expires) = match &o.what {
            Fire::Value(v) => (v.clone(), None),
            Fire::Expiring(v, t) => (v.clone(), Some(osis_base::WallMs(*t))),
            Fire::Grant { commit, target } => match self.edge_piece(commit, target)? {
                Some(p) => (p.to_value(), None),
                None => return Ok(None),
            },
            Fire::Copy { .. } => return Err(Error::Misuse("a sealed copy builds no commit")),
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
        let own: Vec<FireId> = self.core.ix.fires.iter().filter(|(_, o)| o.commit.is_none() && o.ak.as_ref().is_some_and(|ak| self.core.ix.closure.holds(&o.thing) && reads_now(&self.core, &o.thing) && keeps_fire(&self.core, &o.thing, ak))).map(|(id, _)| *id).collect();
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

    /// Role commit `c`'s piece on `target` (`EdgePiece`): its certificate copy there (its header and
    /// role-class parts there), the copies of its evidence, their creation records and the blobs
    /// their deltas link (`held_pages`). `None` while `c` is not applied here.
    pub(crate) fn edge_piece(&mut self, c: &CommitId, target: &Tid) -> Result<Option<EdgePiece>> {
        let id = *c;
        let Some(full) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        let parts: BTreeSet<usize> = full.header.aspects.iter().enumerate().filter(|(_, a)| a.tid == *target && ct::ROLE_CLASS.contains(&a.ak.as_str())).map(|(i, _)| i).collect();
        let (evidence, records) = self.copy_evidence(&(id, *target))?;
        let copy = osis_commit::rewrite(&full, |ai| !parts.contains(&ai));
        let (copy, evidence): (Vec<u8>, Vec<Vec<u8>>) = (copy.encode(), evidence.iter().map(osis_base::encode).collect());
        let all: Vec<&[u8]> = [copy.as_slice()].into_iter().chain(evidence.iter().map(Vec::as_slice)).collect();
        let pages = self.run(|tx| held_pages(tx, &all))?;
        Ok(Some(EdgePiece { copy, evidence, records, pages }))
    }
}

/// Role commit `c`'s piece on a thing X, as it travels from outside a holder H of X
/// (spec/permissions.md §4 Delivering an edge piece): the commit's certificate copy on X, the
/// copies of its evidence, their creation records and the blobs their deltas link. One
/// value for each way it travels: a `grant@~0` fire's value (spec/data-model.md §9), a sealed
/// copy's payload (spec/wire.md §9), and a pairing channel's offer (spec/permissions.md §8).
/// It is the bootstrap of X at H's nodes (the thing, its sync ID, H's boxes), held only as the
/// copy and its evidence judge it: a box nothing judges gives no secret (spec/sync-inbox.md §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgePiece {
    /// The copy, a `CommitBlobPlaintext`'s bytes.
    pub copy: Vec<u8>,
    pub evidence: Vec<Vec<u8>>,
    pub records: Vec<osis_base::CreationRecord>,
    pub pages: Vec<Vec<u8>>,
}

impl EdgePiece {
    /// `struct { grant 0: blob, evidence 1: list<blob>, records 2: list<blob>, pages 3: list<blob> }`
    /// (spec/data-model.md §9).
    pub fn to_value(&self) -> Value {
        let blobs = |v: &[Vec<u8>]| Value::List(v.iter().map(|b| Value::Bytes(b.clone())).collect());
        let records: Vec<Vec<u8>> = self.records.iter().map(|r| osis_base::encode(&r.to_value())).collect();
        osis_schema::codec::rt::struct_value(vec![(0, Value::Bytes(self.copy.clone())), (1, blobs(&self.evidence)), (2, blobs(&records)), (3, blobs(&self.pages))])
    }

    /// `None` for a value not of that form.
    pub fn from_value(v: &Value) -> Option<EdgePiece> {
        let Value::Map(m) = v else { return None };
        let blobs = |k: i64| match m.get(&Value::Int(k)) {
            Some(Value::List(l)) => l.iter().map(|x| if let Value::Bytes(b) = x { Some(b.clone()) } else { None }).collect::<Option<Vec<_>>>(),
            _ => None,
        };
        let Some(Value::Bytes(copy)) = m.get(&Value::Int(0)) else { return None };
        let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
        let records = blobs(2)?.iter().map(|b| osis_base::decode(b, &limits).ok().and_then(|v| osis_base::CreationRecord::from_value(&v))).collect::<Option<Vec<_>>>()?;
        Some(EdgePiece { copy: copy.clone(), evidence: blobs(1)?, records, pages: blobs(3)? })
    }

    /// The thing copy `b` is on: every part a role-class part on that one thing (spec/permissions.md
    /// §4 Copies), at least one. `None` for any other commit.
    pub fn target(b: &osis_commit::CommitBlob) -> Option<Tid> {
        let mut on = b.parts.iter().map(|p| b.header.aspects.get(p.ai).filter(|a| ct::ROLE_CLASS.contains(&a.ak.as_str())).map(|a| a.tid));
        let first = on.next()??;
        on.all(|t| t == Some(first)).then_some(first)
    }
}

/// The aspects a sealed fire's or sealed copy's prefix covers (spec/wire.md §9: its commit's
/// encryption's): a fire's every aspect, a copy's its parts.
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
    /// certificates, all or nothing: `Bad` unless the fire applies valid. A sealed copy (form 1,
    /// §2) likewise, its commit a certificate copy on a thing other than `t`. `NotOpen` when no
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
            if let Ok(x) = osis_blob::open_fire(bytes, t, &e, &osis_crypto::role_kem(&secret)) {
                found = Some((e, x));
                break;
            }
        }
        let Some((under, (prefix, fire))) = found else { return Ok(Opened::NotOpen) };
        let Ok(commit) = osis_commit::CommitBlob::decode(&osis_base::encode(&fire.commit)) else { return Ok(Opened::Bad) };
        let h = &commit.header;
        // a sealed fire: one delta, a fire of an external signal of `t`; a sealed copy: a
        // certificate copy on another thing (spec/sync-inbox.md §2)
        let one = match fire.copy {
            false => matches!(commit.parts.as_slice(), [p] if h.aspects.get(p.ai).is_some_and(|a| a.tid == *t && a.ak.external())),
            true => EdgePiece::target(&commit).is_some_and(|x| x != *t),
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
        // a grant from outside: its carried commit is taken with the fire by every node holding
        // it valid (spec/sync-inbox.md §5 Carried commits)
        let grant = commit.parts.first().is_some_and(|p| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == GRANT_FIRE));
        // a stranded notice: a writer of `t` acts on it as it takes it, whatever `t`'s history
        // setting (spec/sync-inbox.md §5 Stranded notice)
        let stranded = self.stranded_notice(t, &commit);
        // a fire's delta came under the keyset it is sealed to: an opening under that epoch, as a
        // section's (spec/crypto.md §5 Passing on); a copy's role parts pass on by no opening
        if !fire.copy {
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
        if applied && grant {
            self.take_fire(&id)?;
        }
        if applied && let Some((s, holder, keys)) = stranded {
            self.take_stranded_from(&s, &holder, &keys, crate::apply::carriers::Carrier::Fire(id))?;
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
        let row = crate::sync::BlobOf { commit: id, parts: parts.into_iter().collect(), sealed: Default::default(), copy: fire.copy, unchecked: false, salt: *prefix.salt(), ais: ais.into_iter().collect() };
        let b = *b;
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
