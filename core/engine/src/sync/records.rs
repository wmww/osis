//! The account's sync records (spec/sync.md §3 Sync record): a node keeping a thing unread
//! trusts only its own account. Its sync IDs come from `kept^.0` on the account's D alone (an
//! accept or the account's own reading wrote them); a sync secret is recorded there only once a
//! step on this node's own path of such a sync ID bears its sync key. What a held boxes payload
//! offers (`Offer`) is held only while the blob is: its secrets open and show S, its sync IDs and
//! dial hint count only once kept.
//!
//! Indexes: `sync_kept` (D's `kept^.0`, by thing, derived from its state), `offers` and
//! `offered` (the boxes payloads held, persisted under `io/`), and the view sync reads,
//! `sync_records` with `record_ids`, refreshed per thing whenever either changes.

use super::{DialHint, SyncRecord};
use crate::engine::{Core, Engine, Tx};
use crate::error::{Error, Result};
use osis_base::{BlobId, Role, SyncId, Tid, Value, WallMs};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_crypto::{Epoch, Secret32};
use osis_schema::Codec;
use osis_schema::core_types as ct;
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// `io/` + blob ID: a boxes payload held (`Offer`).
pub(crate) const OFFERS: &[u8] = b"io/";

/// A boxes payload held (spec/sync-inbox.md §2): what it offers per thing, its verified granting
/// account (`None`: unsigned, or signed under no key held here), its prefix expiry and dial hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub expires: WallMs,
    pub from: Option<Tid>,
    pub things: Vec<OfferedThing>,
    pub dial: Option<DialHint>,
}

/// One thing a boxes payload boxes the recipient on: the sync ID it names, the highest role a box
/// of it opened to, and the sync secrets those boxes give (each naming its epoch of the thing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedThing {
    pub tid: Tid,
    pub sync_id: Option<SyncId>,
    pub role: Role,
    pub sync: Vec<(Epoch, Secret32)>,
}

fn offer_value(o: &Offer) -> Value {
    let things = o.things.iter().map(|t| {
        let sync = t.sync.iter().map(|(e, s)| Value::List(vec![e.to_wire(), Value::Bytes(s.expose().to_vec())])).collect();
        Value::List(vec![Value::Tid(t.tid), Value::opt(t.sync_id.map(|s| Value::Bytes(s.0.to_vec()))), Value::Int(i64::from(t.role.id())), Value::List(sync)])
    });
    let dial = o.dial.as_ref().map(|d| Value::List(vec![Value::Bytes(d.dialable.to_vec()), Value::List(d.urls.iter().cloned().map(Value::Str).collect())]));
    Value::List(vec![Value::Int(o.expires.0 as i64), Value::opt(o.from.map(Value::Tid)), Value::List(things.collect()), Value::opt(dial)])
}

fn offer_of(b: &[u8]) -> Result<Offer> {
    let bad = || Error::Corrupt("held boxes payload");
    let v = osis_base::decode(b, &osis_base::Limits { max_depth: 8, max_bytes: b.len() }).map_err(|_| bad())?;
    let Value::List(f) = v else { return Err(bad()) };
    let [Value::Int(e), from, Value::List(ts), dial] = f.as_slice() else { return Err(bad()) };
    let opt = |v: &Value| -> Result<Option<Value>> {
        match v {
            Value::List(x) => match x.as_slice() {
                [] => Ok(None),
                [v] => Ok(Some(v.clone())),
                _ => Err(bad()),
            },
            _ => Err(bad()),
        }
    };
    let from = match opt(from)? {
        None => None,
        Some(Value::Tid(t)) => Some(t),
        Some(_) => return Err(bad()),
    };
    let mut things = Vec::new();
    for t in ts {
        let Value::List(p) = t else { return Err(bad()) };
        let [Value::Tid(tid), s, Value::Int(r), Value::List(sync)] = p.as_slice() else { return Err(bad()) };
        let sync_id = match opt(s)? {
            None => None,
            Some(Value::Bytes(b)) => Some(SyncId(b.as_slice().try_into().map_err(|_| bad())?)),
            Some(_) => return Err(bad()),
        };
        let mut secrets = Vec::new();
        for x in sync {
            let Value::List(p) = x else { return Err(bad()) };
            let [e, Value::Bytes(k)] = p.as_slice() else { return Err(bad()) };
            secrets.push((Epoch::from_wire(e).map_err(|_| bad())?, Secret32::from_bytes(k.as_slice().try_into().map_err(|_| bad())?)));
        }
        let role = Role::from_id(u64::try_from(*r).map_err(|_| bad())?).ok_or_else(bad)?;
        things.push(OfferedThing { tid: *tid, sync_id, role, sync: secrets });
    }
    let dial = match opt(dial)? {
        None => None,
        Some(Value::List(p)) => {
            let [Value::Bytes(k), Value::List(urls)] = p.as_slice() else { return Err(bad()) };
            let urls = urls.iter().map(|u| if let Value::Str(u) = u { Ok(u.clone()) } else { Err(bad()) }).collect::<Result<_>>()?;
            Some(DialHint { dialable: k.as_slice().try_into().map_err(|_| bad())?, urls })
        }
        Some(_) => return Err(bad()),
    };
    Ok(Offer { expires: WallMs(u64::try_from(*e).map_err(|_| bad())?), from, things, dial })
}

/// Loads the held boxes payloads (an open or reload) and the views of what they offer; the
/// record itself is derived from D's state (`observe`).
pub(crate) fn load(tx: &mut Tx<'_>) -> Result<()> {
    let mut rows = Vec::new();
    tx.scan(OFFERS, |k, v| {
        rows.push((BlobId(k.try_into().map_err(|_| Error::Corrupt("held boxes payload"))?), offer_of(&v)?));
        Ok(())
    })?;
    let mut things = BTreeSet::new();
    for (b, o) in rows {
        for t in &o.things {
            tx.core.ix.offered.insert(t.tid, b);
            things.insert(t.tid);
        }
        tx.core.ix.offers.insert(b, Arc::new(o));
    }
    for t in things {
        refresh(tx.core, &t);
    }
    Ok(())
}

/// Holds boxes payload `blob` as `o` (`None`: drops it), refreshing the views of its things.
pub(crate) fn set_offer(tx: &mut Tx<'_>, blob: &BlobId, o: Option<Offer>) -> Result<()> {
    let before = tx.core.ix.offers.get(blob).cloned();
    if before.as_deref() == o.as_ref() {
        return Ok(());
    }
    let k = [OFFERS, &blob.0].concat();
    let mut things: BTreeSet<Tid> = before.iter().flat_map(|o| o.things.iter().map(|t| t.tid)).collect();
    for t in &things {
        tx.core.ix.offered.remove(t, blob);
    }
    match o {
        Some(o) => {
            tx.txn.put_local(&k, &osis_base::encode(&offer_value(&o)), Shred::Yes)?;
            for t in &o.things {
                tx.core.ix.offered.insert(t.tid, *blob);
                things.insert(t.tid);
            }
            tx.core.ix.offers.insert(*blob, Arc::new(o));
        }
        None => {
            tx.txn.remove_local(&k, Shred::Yes)?;
            tx.core.ix.offers.remove(blob);
        }
    }
    for t in things {
        refresh(tx.core, &t);
    }
    Ok(())
}

/// Drops the boxes payloads whose blob expired by `now` (`retention::tick`).
pub(crate) fn expire_offers(tx: &mut Tx<'_>, now: WallMs) -> Result<()> {
    let gone: Vec<BlobId> = tx.core.ix.offers.iter().filter(|(_, o)| o.expires <= now).map(|(b, _)| *b).collect();
    for b in gone {
        set_offer(tx, &b, None)?;
    }
    Ok(())
}

/// Keeps `sync_kept` at D's `kept^.0` state `f` (`Tx::derive`, a load), refreshing the views of
/// the things whose entry changed.
pub(crate) fn observe(core: &mut Core, f: Option<&osis_crdt::Fragment>) {
    use osis_schema::RawKey;
    let now: BTreeMap<Tid, ct::Kept> = f.and_then(osis_crdt::Fragment::read).and_then(|v| ct::KEPT.decode(&v).ok()).unwrap_or_default();
    let mut moved = Vec::new();
    let gone: Vec<Tid> = core.ix.sync_kept.keys().filter(|t| !now.contains_key(t)).copied().collect();
    for t in gone {
        core.ix.sync_kept.remove(&t);
        moved.push(t);
    }
    for (t, k) in now {
        if core.ix.sync_kept.get(&t).map(|x| &**x) != Some(&k) {
            core.ix.sync_kept.insert(t, Arc::new(k));
            moved.push(t);
        }
    }
    for t in moved {
        refresh(core, &t);
    }
}

/// `observe` at this node's account's D's `kept^.0` state: once the account is known (an open, a
/// pairing), after which `Tx::derive` follows its writes.
pub(crate) fn observe_own(tx: &mut Tx<'_>) -> Result<()> {
    let Some((_, d)) = tx.core.account_devices() else { return Ok(()) };
    let f = tx.state(&d, &osis_base::Ak::new("kept^.0").map_err(|_| Error::Corrupt("kept^.0"))?)?.cloned();
    observe(tx.core, f.as_ref());
    Ok(())
}

/// The view of `t`'s sync record (`SyncRecord`): its kept sync IDs and recorded secrets with the
/// secrets of the boxes payloads held offering it, and the dial hint of the one expiring last
/// whose sync IDs for `t` are all kept. None while no sync ID of `t` is kept.
fn refresh(core: &mut Core, t: &Tid) {
    let kept = core.ix.sync_kept.get(t).cloned();
    let view = kept.filter(|k| !k.ids.is_empty()).map(|k| {
        let mut r = SyncRecord { sync_ids: k.ids.iter().copied().collect(), ..SyncRecord::default() };
        for (e, s) in &k.secrets {
            if let Ok(e) = osis_keys::aspects::from_schema(e) {
                r.secrets.insert(e, Secret32::from_bytes(*s));
                r.recorded.insert(e);
            }
        }
        let mut dial: Option<(WallMs, DialHint)> = None;
        for b in core.ix.offered.get(t).into_iter().flatten() {
            let Some(o) = core.ix.offers.get(b) else { continue };
            let Some(x) = o.things.iter().find(|x| x.tid == *t) else { continue };
            for (e, s) in &x.sync {
                r.secrets.entry(*e).or_insert_with(|| s.clone());
            }
            if x.sync_id.is_none_or(|s| k.ids.contains(&s))
                && let Some(d) = &o.dial
                && dial.as_ref().is_none_or(|(at, _)| o.expires > *at)
            {
                dial = Some((o.expires, d.clone()));
            }
        }
        r.dial = dial.map(|(_, d)| d);
        r
    });
    let before: BTreeSet<SyncId> = core.ix.sync_records.get(t).map(|r| r.sync_ids.iter().copied().collect()).unwrap_or_default();
    let after: BTreeSet<SyncId> = view.as_ref().map(|r| r.sync_ids.iter().copied().collect()).unwrap_or_default();
    for s in before.difference(&after) {
        core.ix.record_ids.remove(s, t);
    }
    for s in after.difference(&before) {
        core.ix.record_ids.insert(*s, *t);
    }
    match view {
        Some(v) if core.ix.sync_records.get(t).map(|x| &**x) != Some(&v) => {
            core.ix.sync_records.insert(*t, Arc::new(v));
        }
        Some(_) => {}
        None => {
            core.ix.sync_records.remove(t);
        }
    }
}

/// Adds `ids` and the sync `secrets` of `t` (each checked to name its epoch of `t`'s sync role,
/// spec/crypto.md §4) to the account's sync record of `t` (`kept^.0` on D), in a commit of the
/// running transaction; nothing when they add nothing, or when no sync ID of `t` is kept after
/// (a record holds secrets only beside a kept sync ID). Returns whether it wrote.
pub(crate) fn keep_in(tx: &mut Tx<'_>, t: &Tid, ids: &[SyncId], secrets: impl IntoIterator<Item = (Epoch, Secret32)>) -> Result<bool> {
    let Some((_, d)) = tx.core.account_devices() else { return Ok(false) };
    let before = tx.core.ix.sync_kept.get(t).map(|k| (**k).clone()).unwrap_or_default();
    let mut k = before.clone();
    k.ids.extend(ids.iter().copied());
    for (e, s) in secrets {
        if e.names(t, Role::Sync, &s) {
            k.secrets.insert(osis_keys::aspects::to_schema(&e), *s.expose());
        }
    }
    if k == before || k.ids.is_empty() {
        return Ok(false);
    }
    let mut m = crate::Mutation::new();
    m.op(d, &ct::KEPT, PathOp { path: vec![PathSeg::Key(Value::Tid(*t))], op: Op::Set(k.to_value()) })?;
    crate::engine::write::commit_in(tx, m)?;
    Ok(true)
}

impl Engine {
    /// `thing`'s sync record view (spec/sync.md §3): reads only its key.
    pub(crate) fn sync_record_now(&self, thing: &Tid) -> Option<Arc<SyncRecord>> {
        self.core.ix.sync_records.get(thing).cloned()
    }

    /// Every sync record view, whole: for a start's listing (`sync_record_feed` follows additions).
    pub(crate) fn sync_records_now(&self) -> Arc<BTreeMap<Tid, SyncRecord>> {
        Arc::new(self.core.ix.sync_records.iter().map(|(t, r)| (*t, (**r).clone())).collect())
    }

    /// Records the held sync secrets of `thing` whose sync key one of `borne` is (the sync keys
    /// of the steps on this node's path of a kept sync ID of it, spec/sync.md §3 A recorded
    /// secret), those not recorded yet. Returns whether it wrote.
    pub(crate) fn record_borne_now(&mut self, thing: &Tid, borne: &BTreeSet<[u8; 32]>) -> Result<bool> {
        let Some(r) = self.core.ix.sync_records.get(thing).cloned() else { return Ok(false) };
        let new: Vec<(Epoch, Secret32)> = r
            .secrets
            .iter()
            .filter(|(e, s)| !r.recorded.contains(e) && borne.contains(&osis_crypto::label_role_key(osis_crypto::LabelRole::Sync, s).verifying_key().to_bytes()))
            .map(|(e, s)| (*e, s.clone()))
            .collect();
        if new.is_empty() {
            return Ok(false);
        }
        let t = *thing;
        self.run(|tx| keep_in(tx, &t, &[], new))
    }
}
