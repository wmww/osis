//! Secrets the engine holds (spec/crypto.md §3–§4): the node's own role secrets, derived secrets
//! of plain things, epochs of actors with secrets of their own opened from `/secrets` (the
//! `SecretStore`, kept in the store per actor), dedup secrets from creation records, and the
//! `Secrets` osis-commit asks for when building a commit.

use super::Core;
use crate::error::{Error, Result};
use osis_core::{CreationRecord, Role, Tid, Value};
use osis_crypto::{Epoch, Secret32, dedup_secret};
use osis_keys::{ActorEpochs, HistoryAlts, Opener, Provenance, ROLES, Unchecked};
use osis_schema::AspectKey;
use osis_schema::core_types::{Keys, Secrets};

/// Owner chains end at a key actor within `MAX_OWNER_DEPTH` links (spec/permissions.md §1).
const MAX_CHAIN: usize = osis_core::format::MAX_OWNER_DEPTH + 1;

impl Core {
    pub(crate) fn created(&self, tid: &Tid) -> Option<&CreationRecord> {
        self.held.created(tid)
    }

    pub(crate) fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.created(tid).map(|r| dedup_secret(r.nonce()))
    }

    /// The epochs this node holds for `tid`: its own, opened ones, or derived from the owner's
    /// for a plain thing without secrets of its own.
    pub(crate) fn epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let mut chain = Vec::new();
        let mut cur = *tid;
        for _ in 0..MAX_CHAIN {
            let held = (cur == self.id.tid()).then(|| self.id.epochs()).or_else(|| self.key_actors.get(&cur).map(|k| k.epochs()));
            if let Some(mut e) = held {
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if let Some(e) = self.secrets.get(&cur) {
                let mut e = e.clone();
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if self.own_keys.contains(&cur) {
                return None;
            }
            match self.created(&cur)? {
                CreationRecord::Thing { owner, .. } => {
                    chain.push(cur);
                    cur = *owner;
                }
                CreationRecord::KeyActor { .. } => return None,
            }
        }
        None
    }

    fn newest(&self, tid: &Tid, r: Role) -> Option<Secret32> {
        self.epochs(tid)?.role(r).newest_held().map(|(_, s)| s.clone())
    }

    /// Opens what `/secrets` of `actor` holds for this node or for actors it holds secrets of
    /// (spec/crypto.md §4). `unchecked`: `None` when `secrets` is the applied valid state; the
    /// source for the boxes of a pending commit, whose secrets are kept for reading only.
    /// Returns whether anything new was learned.
    /// `alts`: the live entries of history keys holding several (each tried). `published`: the
    /// actor's `/keys`, against which unchecked candidates are checked.
    pub(crate) fn ingest_secrets(&mut self, actor: &Tid, secrets: &Secrets, unchecked: Option<Unchecked>, alts: &HistoryAlts, published: Option<&Keys>) -> bool {
        let before = self.secrets.get(actor).cloned();
        // a bounded number of actors held through reading-only secrets alone
        let reading_only = |e: &ActorEpochs| ROLES.iter().all(|r| e.role(*r).held().next().is_none()) && ROLES.iter().any(|r| !e.role(*r).held_newest_first().is_empty());
        if unchecked.is_some() && before.as_ref().is_none_or(|e| ROLES.iter().all(|r| e.role(*r).held_newest_first().is_empty())) && self.secrets.iter().filter(|(t, e)| *t != actor && reading_only(e)).count() >= MAX_READING_ACTORS {
            return false;
        }
        let mut epochs = before.clone().unwrap_or_default();
        let seed = self.id.seed().clone();
        let me = self.id.tid();
        let mut openers: Vec<(Tid, ActorEpochs)> = self.secrets.iter().filter(|(t, _)| *t != actor).map(|(t, e)| (*t, e.clone())).collect();
        openers.sort_by_key(|x| x.0);
        let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { member: me, seed: &seed }, &mut epochs, unchecked);
        for (t, k) in &self.key_actors {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { member: *t, seed: k.seed() }, &mut epochs, unchecked);
        }
        for (m, e) in &openers {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::Actor { member: *m, epochs: e }, &mut epochs, unchecked);
        }
        if let Some(k) = published {
            osis_keys::prune_reading(&mut epochs, k);
        }
        self.adopt_derived(actor, &mut epochs);
        let held_any = ROLES.iter().any(|r| !epochs.role(*r).held_newest_first().is_empty());
        if held_any && Some(&epochs) != before.as_ref() {
            self.secrets.insert(*actor, epochs);
            self.membership_changed();
            return true;
        }
        false
    }

    /// `ingest_secrets` over the entries of `actor`'s `/secrets` state `st` that a change touched:
    /// the boxes keyed `boxes` and history boxes keyed `history` (key values), then the history
    /// box of every epoch with a secret held, repeatedly, as `open_histories` would reach them
    /// over the whole state. Boxes outside `boxes` were opened when they joined (an opener's new
    /// secrets reopen the boxes keyed to it, `flows::reopen_dependents`). O(touched entries +
    /// held epochs), not O(boxes). Returns whether anything new was learned.
    pub(crate) fn ingest_keyed(&mut self, actor: &Tid, st: &osis_crdt::Fragment, boxes: &[Value], history: &[Value]) -> bool {
        use osis_crdt::PathSeg;
        let mut s = Secrets::default();
        for k in boxes {
            let v = st.at(&[PathSeg::Field(0), PathSeg::Key(k.clone())]).filter(osis_crdt::Fragment::present).and_then(|f| f.read());
            if let (Some(bk), Some(b)) = (typed_as::<osis_schema::core_types::BoxKey>(k, "box_key"), v.and_then(|v| typed_as::<osis_schema::core_types::SecretBox>(&v, "box"))) {
                s.boxes.insert(bk, b);
            }
        }
        let mut alts = HistoryAlts::new();
        let mut tried: std::collections::BTreeSet<osis_schema::core_types::HistoryKey> = std::collections::BTreeSet::new();
        let mut add = |s: &mut Secrets, alts: &mut HistoryAlts, k: &Value| -> bool {
            let Some(hk) = typed_as::<osis_schema::core_types::HistoryKey>(k, "history_key") else { return false };
            if !tried.insert(hk.clone()) {
                return false;
            }
            let Some(m) = history_map(st) else { return false };
            let live: Vec<Vec<u8>> = m.live(k).into_iter().filter_map(|(_, f)| match f.read() {
                Some(Value::Bytes(b)) => Some(b),
                _ => None,
            }).collect();
            let Some(Value::Bytes(main)) = st.at(&[PathSeg::Field(1), PathSeg::Key(k.clone())]).filter(osis_crdt::Fragment::present).and_then(|f| f.read()) else { return false };
            if live.len() > 1 {
                alts.insert(hk.clone(), live);
            }
            s.history.insert(hk, main);
            true
        };
        for k in history {
            add(&mut s, &mut alts, k);
        }
        let mut learned = false;
        loop {
            learned |= self.ingest_secrets(actor, &s, None, &alts, None);
            let Some(e) = self.secrets.get(actor) else { break };
            let candidates: Vec<Value> = ROLES
                .iter()
                .flat_map(|r| e.role(*r).epochs().filter(|(ep, _)| !e.role(*r).reading_secrets(ep).is_empty()).map(|(ep, _)| osis_schema::Codec::to_value(&osis_keys::aspects::history_key(*r, ep))).collect::<Vec<_>>())
                .collect();
            let mut more = false;
            for k in &candidates {
                more |= add(&mut s, &mut alts, k);
            }
            if !more {
                break;
            }
        }
        learned
    }

    /// A thing that got secrets of its own keeps its earlier derived epochs (by history box):
    /// those derived from an established epoch of the owner are established (spec/crypto.md §4,
    /// "derived from an established epoch of the owner"), so the rotation from them establishes
    /// and labels registered under them can be stepped.
    pub(crate) fn adopt_derived(&self, actor: &Tid, epochs: &mut ActorEpochs) {
        let Some(CreationRecord::Thing { owner, .. }) = self.created(actor) else { return };
        let Some(o) = self.epochs(owner) else { return };
        let d = ActorEpochs::derived(&o, actor);
        let mut any = false;
        for r in ROLES {
            for (ep, info) in d.role(r).epochs() {
                if info.established.is_some() && epochs.role(r).get(ep).is_some() && !epochs.role(r).is_established(ep) {
                    epochs.role_mut(r).set_established(*ep, Provenance::Derived);
                    any = true;
                }
            }
        }
        if any {
            epochs.establish();
        }
    }

    /// Notes `/keys` of `actor`: keysets mean secrets of its own (spec/permissions.md §3).
    pub(crate) fn observe_keys(&mut self, actor: &Tid, keys: &Keys) {
        if keys.read.is_some() || keys.write.is_some() || keys.admin.is_some() {
            if self.own_keys.insert(*actor) {
                // reader actors of things below it change
                self.bodies.clear();
            }
            self.membership_changed();
            if let Some(e) = self.secrets.get_mut(actor) {
                let _ = osis_keys::observe_keys(keys, e);
            }
        }
    }
}

/// What a commit build asks for (osis-commit `Secrets`).
pub struct CommitSecrets<'c> {
    pub core: &'c Core,
    /// The actor the commit acts for.
    pub actor: Tid,
    /// Creation records of things the commit creates.
    pub created: &'c [CreationRecord],
}

impl osis_commit::Secrets for CommitSecrets<'_> {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.core.dedup(tid).or_else(|| self.created.iter().find(|r| r.tid() == *tid).map(|r| dedup_secret(r.nonce())))
    }
    fn admin(&self, tid: &Tid) -> Option<Secret32> {
        self.core.newest(tid, Role::Admin).or_else(|| self.derived_new(tid, Role::Admin))
    }
    fn chain_write(&self) -> Option<Secret32> {
        self.core.newest(&self.actor, Role::Write)
    }
    fn write(&self, tid: &Tid) -> Option<Secret32> {
        self.core.newest(tid, Role::Write).or_else(|| self.derived_new(tid, Role::Write))
    }
}

impl CommitSecrets<'_> {
    /// A thing created by this commit derives from its owner (through owners it creates too).
    fn derived_new(&self, tid: &Tid, r: Role) -> Option<Secret32> {
        let mut chain = vec![*tid];
        let mut e = loop {
            let cur = chain.last()?;
            let Some(CreationRecord::Thing { owner, .. }) = self.created.iter().find(|x| x.tid() == *cur) else { return None };
            if !self.created.iter().any(|x| x.tid() == *owner && matches!(x, CreationRecord::Thing { .. })) {
                break self.core.epochs(owner)?;
            }
            if chain.len() > self.created.len() {
                return None;
            }
            chain.push(*owner);
        };
        for t in chain.iter().rev() {
            e = ActorEpochs::derived(&e, t);
        }
        e.role(r).newest_held().map(|(_, s)| s.clone())
    }
}

// ---- local encoding of held epochs (the store's actor secrets unit)

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

fn provenance_code(p: Provenance) -> u64 {
    match p {
        Provenance::Own => 0,
        Provenance::Fixed => 1,
        Provenance::Derived => 2,
        Provenance::Chain => 3,
        Provenance::Snapshot => 4,
    }
}

fn provenance_of(c: i64) -> Option<Provenance> {
    [Provenance::Own, Provenance::Fixed, Provenance::Derived, Provenance::Chain, Provenance::Snapshot].get(usize::try_from(c).ok()?).copied()
}

/// Persisted as is: establishment is stored, never re-inferred on load (spec/crypto.md §4).
pub(crate) fn encode_epochs(a: &ActorEpochs) -> Vec<u8> {
    let roles = ROLES
        .iter()
        .map(|r| {
            Value::List(
                a.role(*r)
                    .epochs()
                    .map(|(e, i)| {
                        Value::List(vec![
                            e.to_wire(),
                            uint(i.suite),
                            Value::List(i.applied.iter().map(|a| Value::List(a.iter().map(Epoch::to_wire).collect())).collect()),
                            Value::Bool(i.snapshot),
                            Value::List(i.established.iter().map(|p| uint(provenance_code(*p))).collect()),
                            Value::List(i.supersedes.iter().map(Epoch::to_wire).collect()),
                            Value::List(i.secret.iter().map(|s| Value::Bytes(s.expose().to_vec())).collect()),
                            Value::List(i.reading.iter().map(|(s, u)| Value::List(vec![Value::Bytes(s.expose().to_vec()), Value::Bytes(u.author.as_bytes().to_vec()), Value::Bytes(u.commit.0.to_vec())])).collect()),
                        ])
                    })
                    .collect(),
            )
        })
        .collect();
    osis_core::encode(&Value::List(roles))
}

/// Most actors this node holds through reading-only secrets alone (local policy: pending
/// commits naming made-up actors cannot grow it without bound).
pub(crate) const MAX_READING_ACTORS: usize = 64;

/// The live entries of history keys holding several in a `/secrets` state (puts of one key by
/// different writers): readers try each, so a newer entry does not hide the genuine box.
pub(crate) fn history_alts(f: &osis_crdt::Fragment) -> HistoryAlts {
    use osis_crdt::{Encoding, Fragment, MemberRef};
    let mut out = HistoryAlts::new();
    let Some(MemberRef::Frag(Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return out };
    let Some(MemberRef::Frag(Fragment::Map(m))) = st.field(1).and_then(|x| x.slot(Encoding::Map)) else { return out };
    let mut by_key: std::collections::BTreeMap<Value, Vec<Vec<u8>>> = std::collections::BTreeMap::new();
    for (_, _, k, frag) in m.entries() {
        if let (Some(k), Some(Value::Bytes(b))) = (k, frag.and_then(osis_crdt::Fragment::read)) {
            by_key.entry(k.clone()).or_default().push(b);
        }
    }
    for (k, v) in by_key {
        if v.len() > 1
            && let Ok(k) = <osis_schema::core_types::HistoryKey as osis_schema::Codec>::from_value(&k)
        {
            out.insert(k, v);
        }
    }
    out
}

/// The history-box map of a `/secrets` state.
fn history_map(f: &osis_crdt::Fragment) -> Option<&osis_crdt::Map> {
    use osis_crdt::{Encoding, Fragment, MemberRef};
    let Some(MemberRef::Frag(Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return None };
    match st.field(1)?.slot(Encoding::Map)? {
        MemberRef::Frag(Fragment::Map(m)) => Some(m),
        _ => None,
    }
}

/// A core-schema value typed as the named type.
fn typed_as<T: osis_schema::Codec>(v: &Value, name: &str) -> Option<T> {
    let v = osis_schema::typed_read(osis_schema::core_schema(), v, &osis_schema::Type::Named(name.into(), Vec::new())).ok()?;
    T::from_value(&v).ok()
}

/// The keys of the box and history-box entries a `/secrets` delta (or snapshot) writes; `None`
/// when it writes the value, a field or a map whole (a reset): then every entry may change.
pub(crate) fn touched_keys(delta: &osis_crdt::Fragment) -> Option<(Vec<Value>, Vec<Value>)> {
    use osis_crdt::{Encoding, Fragment, MemberRef};
    if !delta.is_plain_struct() {
        return None;
    }
    let Some(MemberRef::Frag(Fragment::Struct(st))) = delta.slot(Encoding::Struct) else { return None };
    let mut out = (Vec::new(), Vec::new());
    for (id, keys) in [(0, &mut out.0), (1, &mut out.1)] {
        let Some(f) = st.field(id) else { continue };
        let Some(MemberRef::Frag(Fragment::Map(m))) = f.slot(Encoding::Map) else { return None };
        if f.has_reset() {
            return None;
        }
        keys.extend(m.entries().filter_map(|(_, _, k, _)| k.cloned()));
    }
    Some(out)
}

/// The source given a reading-only secret persisted before sources were kept.
const OLD_SOURCE: Unchecked = Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: osis_core::CommitId([0; 32]) };

pub(crate) fn decode_epochs(b: &[u8]) -> Result<ActorEpochs> {
    let bad = || Error::Corrupt("epochs");
    let lim = osis_core::Limits { max_depth: 16, max_bytes: b.len() };
    let Value::List(roles) = osis_core::decode(b, &lim).map_err(|_| bad())? else { return Err(bad()) };
    let mut a = ActorEpochs::default();
    for (r, items) in ROLES.iter().zip(roles) {
        let Value::List(items) = items else { return Err(bad()) };
        for it in items {
            let Value::List(f) = it else { return Err(bad()) };
            // older layouts: 7 fields, or an 8th `Bool` marking `sec` reading-only
            let empty = Vec::new();
            let (fields, reading, old_ro) = match f.as_slice() {
                [rest @ .., Value::List(r)] if rest.len() == 7 => (rest, r, false),
                [rest @ .., Value::Bool(ro)] if rest.len() == 7 => (rest, &empty, *ro),
                rest => (rest, &empty, false),
            };
            let [e, Value::Int(suite), Value::List(applied), Value::Bool(snapshot), Value::List(est), Value::List(sup), Value::List(sec)] = fields else { return Err(bad()) };
            let e = Epoch::from_wire(e).map_err(|_| bad())?;
            let info = a.role_mut(*r).observe(e);
            info.suite = u64::try_from(*suite).map_err(|_| bad())?;
            info.snapshot = *snapshot;
            if let [Value::List(ap)] = applied.as_slice() {
                info.applied = Some(ap.iter().map(Epoch::from_wire).collect::<std::result::Result<_, _>>().map_err(|_| bad())?);
            }
            if let [Value::Int(p)] = est.as_slice() {
                info.established = Some(provenance_of(*p).ok_or_else(bad)?);
            }
            for s in sup {
                info.supersedes.insert(Epoch::from_wire(s).map_err(|_| bad())?);
            }
            let secret = |v: &Value| match v {
                Value::Bytes(s) => Ok(Secret32::from_bytes(s.as_slice().try_into().map_err(|_| bad())?)),
                _ => Err(bad()),
            };
            if let [s] = sec.as_slice() {
                if old_ro {
                    // source unknown in that layout: kept until a checked secret replaces it
                    info.reading.push((secret(s)?, OLD_SOURCE));
                } else {
                    info.secret = Some(secret(s)?);
                }
            }
            for c in reading {
                let Value::List(c) = c else { return Err(bad()) };
                let [s, Value::Bytes(author), Value::Bytes(commit)] = c.as_slice() else { return Err(bad()) };
                let author = Tid::from_bytes(author.as_slice().try_into().map_err(|_| bad())?);
                let commit = osis_core::CommitId(commit.as_slice().try_into().map_err(|_| bad())?);
                info.reading.push((secret(s)?, Unchecked { author, commit }));
            }
        }
    }
    Ok(a)
}

/// The typed `/secrets` of a state value, if it reads as one. A map field never written (a
/// rotation that boxed nobody, a grant that carried no history box) reads as empty: the node
/// otherwise lost every box and history box of the actor.
pub(crate) fn secrets_value(v: &Value) -> Option<Secrets> {
    let mut v = v.clone();
    if let Value::Map(m) = &mut v {
        for f in [0, 1] {
            m.entry(Value::Int(f)).or_insert_with(|| Value::Map(Default::default()));
        }
    }
    osis_schema::core_types::SECRETS.decode(&v).ok()
}

pub(crate) fn keys_value(v: &Value) -> Option<Keys> {
    osis_schema::core_types::KEYS.decode(v).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/crypto.md §4: a secret learned only from a pending or invalid commit stays reading-only
    // across a restart (the mark is persisted with the epochs, never re-inferred).
    #[test]
    fn reading_only_mark_persists() {
        let mut a = ActorEpochs::default();
        let (e1, e2) = (Epoch::new(1, [1; 16]).unwrap(), Epoch::new(2, [2; 16]).unwrap());
        a.read.set_secret(e1, Secret32::from_bytes([1; 32]));
        a.read.set_established(e1, Provenance::Own);
        let from = |n: u8| Unchecked { author: Tid::from_bytes([n; 15]), commit: osis_core::CommitId([n; 32]) };
        a.read.set_reading_secret(e2, Secret32::from_bytes([2; 32]), from(1));
        a.read.set_reading_secret(e2, Secret32::from_bytes([3; 32]), from(2));
        a.read.set_established(e2, Provenance::Chain);
        let b = decode_epochs(&encode_epochs(&a)).unwrap();
        assert_eq!(b, a);
        assert!(b.read.is_reading_only(&e2) && b.read.secret(&e2).is_none());
        assert_eq!(b.read.newest_held().map(|x| x.0), Some(e1));
    }

    // spec/crypto.md §4: a store written before candidates kept their source (an 8th `Bool`
    // field marking the secret reading-only) still loads it as reading-only.
    #[test]
    fn old_reading_only_layout_decodes() {
        let e = Epoch::new(2, [2; 16]).unwrap();
        let item = |ro: bool| Value::List(vec![e.to_wire(), Value::Int(1), Value::List(vec![]), Value::Bool(false), Value::List(vec![]), Value::List(vec![]), Value::List(vec![Value::Bytes(vec![7; 32])]), Value::Bool(ro)]);
        for ro in [true, false] {
            let b = osis_core::encode(&Value::List(vec![Value::List(vec![item(ro)]), Value::List(vec![]), Value::List(vec![])]));
            let a = decode_epochs(&b).unwrap();
            assert_eq!(a.read.is_reading_only(&e), ro);
            assert_eq!(a.read.reading_secrets(&e), vec![&Secret32::from_bytes([7; 32])]);
            assert_eq!(a.read.secret(&e).is_some(), !ro);
            assert_eq!(decode_epochs(&encode_epochs(&a)).unwrap(), a);
        }
    }

    // spec/crypto.md §4: every live entry of a history key with several (puts by different
    // writers) is offered to readers, not only their merged read.
    #[test]
    fn history_alts_lists_live_entries() {
        use osis_crdt::{Batch, Op, PathOp, PathSeg, Source, Writer};
        use osis_schema::Codec;
        let schema = osis_schema::core_schema();
        let view = schema.view("/secrets").unwrap();
        let k = osis_schema::core_types::HistoryKey { role: Role::Read, epoch: osis_keys::aspects::to_schema(&Epoch::new(1, [1; 16]).unwrap()) };
        let mut st = osis_crdt::Fragment::default();
        for (n, b) in [(1u8, 0x11u8), (2, 0x22)] {
            let ts = osis_core::Ts::make(osis_core::WallMs(u64::from(n) * 1000), 0).unwrap();
            let mut batch = Batch::new(&st, Writer::new(ts, Source::node(Tid::from_bytes([n; 15])), 1));
            batch.apply(&PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Put(Value::Bytes(vec![b; 8])) }, &view).unwrap();
            st.join(batch.finish().unwrap().0);
        }
        let alts = history_alts(&st);
        let mut got = alts.get(&k).cloned().unwrap();
        got.sort();
        assert_eq!(got, vec![vec![0x11; 8], vec![0x22; 8]]);
    }
}
