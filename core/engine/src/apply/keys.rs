//! What establishment (spec/crypto.md §4) is computed from: a held valid role commit's
//! `secrets.0` write is recorded with its `keys.0` write (`SecretsWrite::rotated`); a held
//! `secrets.0` compaction snapshot keys its epochs (`snapshot_keyed`); a commit later found
//! invalid no longer counts, valid again is recorded again. `Core::own_epochs` establishes from
//! these and the held commits (the names).

use crate::engine::{Core, KeysetRec, SealedRec, Tx};
use crate::error::Result;
use osis_commit::{Decoded, Header, Kind};
use osis_base::{CommitId, Role, Tid, Value};
use osis_crdt::{Encoding, Fragment, SlotRef};
use osis_keys::{KeysWrite, ROLES, SecretsWrite};
use osis_schema::core_types::{self as ct, BoxKey, HistoryKey, SecretBox};
use osis_schema::{Codec, Type, typed_read};
use osis_store::Shred;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

fn field(f: &Fragment, id: u64) -> Option<&Fragment> {
    match f.slot(Encoding::Struct)? {
        SlotRef::Frag(Fragment::Struct(s)) => s.field(id),
        _ => None,
    }
}

fn map(f: Option<&Fragment>) -> Option<&osis_crdt::Map> {
    match f?.slot(Encoding::Map)? {
        SlotRef::Frag(Fragment::Map(m)) => Some(m),
        _ => None,
    }
}

/// Notes `boxes_to` for a `secrets.0` delta of any validity (the boxes keyed to each holder, for
/// `flows::reopen_dependents`; a load notes every held part alike).
pub(crate) fn note_boxes_to(core: &mut Core, actor: &Tid, delta: &Fragment) {
    for (bk, k) in written_boxes(delta) {
        core.ix.boxes_to.insert(bk.holder.0, (*actor, k.clone()));
    }
}

/// The keysets part `ai` of `h` writes in `bodies` (its `keys.0` deltas or snapshot): what it
/// noted (`note_keysets`), kept in its record when it drops (`Dropped::keysets`).
pub(crate) fn keysets_of(h: &Header, ai: usize, bodies: &[Fragment]) -> Vec<KeysetRec> {
    if !h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == "keys.0") {
        return Vec::new();
    }
    let mut out = std::collections::BTreeSet::new();
    for b in bodies {
        out.extend(KeysBody::of(b).recs);
    }
    out.into_iter().collect()
}

/// A `keys.0` body read: the keysets it writes, typed (whole keysets: a rotation replaces the
/// field), each as noted (`KeysetRec`: its role, epoch, listed epochs, KEM key (suite 1), names
/// digest, left-out keysets and carried demotions), and the box records it puts (`SealedRec`).
#[derive(Clone)]
pub(crate) struct KeysBody {
    pub write: KeysWrite,
    pub recs: Vec<KeysetRec>,
    pub sealed: Vec<SealedRec>,
}

impl KeysBody {
    pub(crate) fn of(body: &Fragment) -> KeysBody {
        let write = keys_write(body);
        let recs = write
            .keysets
            .iter()
            .filter_map(|(role, ks)| {
                let epoch = osis_keys::aspects::from_schema(&ks.epoch).ok()?;
                let lists = ks.supersedes.iter().filter_map(|x| osis_keys::aspects::from_schema(x).ok()).collect();
                let ct::KemKey::X25519MlKem768(b) = &ks.kem_key;
                let kem = (ks.suite == osis_keys::SUITE).then(|| osis_crypto::KemPublicKey::from_slice(b).ok()).flatten();
                let left_out = ks.left_out.iter().flat_map(|(m, xs)| xs.iter().filter_map(|x| Some((m.0, osis_keys::aspects::from_schema(x).ok()?)))).collect();
                let mut demotions: Vec<CommitId> = ks.demotions.iter().copied().collect();
                if ks.demotes {
                    // its rotation commit: the commit its write names (a role commit is commit
                    // form, spec/crdt.md §2.1), a snapshot's copy by its stamps
                    let f = field(body, osis_keys::aspects::keyset_field(*role));
                    demotions.extend(f.into_iter().flat_map(Fragment::live_writes).filter_map(|(d, _)| match d.src.kind() {
                        osis_crdt::SourceKind::Commit(c) => Some(*c),
                        _ => None,
                    }));
                    demotions.sort();
                    demotions.dedup();
                }
                Some(KeysetRec { role: *role, epoch, lists, kem, names: ks.names, left_out, demotions })
            })
            .collect();
        KeysBody { write, recs, sealed: sealed_recs(body) }
    }
}

/// The box records a `keys.0` body puts (a delta's puts, a snapshot's live entries;
/// spec/crypto.md §4, Stale), each naming the keysets its box names.
fn sealed_recs(body: &Fragment) -> Vec<SealedRec> {
    let Some(m) = map(field(body, crate::flows::SEALED)) else { return Vec::new() };
    let set = Type::Set(Box::new(Type::Named("epoch".into(), Vec::new())));
    let mut out: Vec<SealedRec> = m
        .entries()
        .filter_map(|(_, _, k, f)| {
            let k = BoxKey::from_value(&typed(k?, "box_key")?).ok()?;
            let v = typed_read(osis_schema::core_schema(), &f?.read()?, &set).ok()?;
            let ks = std::collections::BTreeSet::<ct::Epoch>::from_value(&v).ok()?;
            Some(SealedRec { role: k.role, epoch: osis_keys::aspects::from_schema(&k.epoch).ok()?, holder: k.holder.0, keysets: ks.iter().filter_map(|x| osis_keys::aspects::from_schema(x).ok()).collect() })
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The boxes a `secrets.0` delta writes (removals aside): typed key and key value.
fn written_boxes(delta: &Fragment) -> Vec<(BoxKey, &Value)> {
    let Some(m) = map(field(delta, 0)) else { return Vec::new() };
    m.entries().filter(|(_, _, _, f)| f.is_some()).filter_map(|(_, _, k, _)| Some((typed(k?, "box_key").and_then(|t| BoxKey::from_value(&t).ok())?, k?))).collect()
}

/// A role commit's `secrets.0` or any `keys.0` part dropped its body (`bodies`):
/// what was noted from them goes with them (spec/commits.md §5), re-derived from the bodies
/// still held: a `secrets.0` part's `boxes_to` entries of the boxes it wrote that no held body
/// writes; a `keys.0` part keeps its keysets (`Dropped::keysets`): the rotation and the keyset
/// epochs stay known.
pub(crate) fn forget_dropped(tx: &mut Tx<'_>, h: &Header, ai: usize, bodies: &[Fragment]) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    if a.ak.as_str() == "keys.0" {
        return rebuild_keysets(tx, &std::collections::BTreeSet::from([a.tid]));
    }
    if h.kind != Kind::Role || a.ak.as_str() != "secrets.0" {
        return Ok(());
    }
    let mut gone: std::collections::BTreeSet<(Tid, Value)> = bodies.iter().flat_map(written_boxes).map(|(bk, k)| (bk.holder.0, k.clone())).collect();
    let ids: Vec<CommitId> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let Some(xi) = m.aspect(&a.tid, &a.ak) else { continue };
        if m.header.kind != Kind::Role {
            continue;
        }
        if let Some(Decoded::Delta(d)) = super::held_part(tx, &id, xi)? {
            for (bk, k) in written_boxes(&d.fragment) {
                gone.remove(&(bk.holder.0, k.clone()));
            }
        }
    }
    for (m, k) in gone {
        tx.core.ix.boxes_to.remove(&m, &(a.tid, k));
    }
    Ok(())
}

/// Notes the keysets a valid `keys.0` body of `actor` writes (`KeysBody::recs`, or a dropped part's
/// record): each is a held valid keyset (`keysets`); a role
/// commit's also record the commit as the epoch's introduction if earliest: a rotation writes
/// the rotated roles' keysets, nothing else does, so the epoch's introducer
/// (`Core::epoch_intro`) is its rotation commit, or unknown while that `keys.0` part is not held
/// (synced after a compaction, or missing again after `retention::uncover`).
pub(crate) fn note_keysets(core: &mut Core, h: &Header, id: &CommitId, actor: &Tid, keysets: &[KeysetRec]) {
    if keysets.is_empty() {
        return;
    }
    let at = osis_perm::Point { ts: h.ts, node: h.signer, commit: *id };
    for k in keysets {
        if h.kind == Kind::Role {
            note_intro(core, h, id, actor, k.role, k.epoch);
        }
        let key = (*actor, k.role, k.epoch);
        let mut held = core.ix.keysets.get(&key).cloned().unwrap_or_default();
        let before = held.clone();
        held.lists.extend(k.lists.iter().copied());
        if k.kem.is_some() {
            held.kem_in = Some(held.kem_in.map_or(at, |x| x.min(at)));
        }
        held.since = Some(held.since.map_or(at, |x| x.min(at)));
        held.names.insert((k.names, h.signer));
        for (m, x) in &k.left_out {
            held.left_out.entry(*m).or_default().insert(*x);
        }
        held.demotions.extend(k.demotions.iter().copied());
        if held != before || !core.ix.keysets.contains_key(&key) {
            core.ix.keysets.insert(key, held);
            core.touch();
        }
    }
}

/// The KEM key of held keyset `e` of role `r` of actor `m` (spec/crypto.md §3), read from the
/// body `HeldKeyset::kem_in` names: its held part, or its record once the body dropped
/// (`Dropped::keysets`). Read only to seal to `m`.
pub(crate) fn keyset_kem(tx: &mut Tx<'_>, m: &Tid, r: Role, e: &osis_crypto::Epoch) -> Result<Option<osis_crypto::KemPublicKey>> {
    let Some(id) = tx.core.keyset(m, r, e).and_then(|k| k.kem_in).map(|p| p.commit) else { return Ok(None) };
    let Some(meta) = tx.core.ix.commits.get(&id) else { return Ok(None) };
    let Some(ai) = meta.view.aspect(m, "keys.0") else { return Ok(None) };
    let pick = |recs: &[KeysetRec]| recs.iter().find(|k| k.role == r && k.epoch == *e).and_then(|k| k.kem.clone());
    if let Some(k) = meta.dropped(ai).and_then(|d| pick(&d.keysets)) {
        return Ok(Some(k));
    }
    Ok(super::held_part(tx, &id, ai)?.and_then(|d| pick(&KeysBody::of(d.fragment()).recs)))
}

/// Notes the box records a valid `keys.0` body of `actor` (commit `id`) puts (`KeysBody::sealed`):
/// what Stale reads at the epochs they key, and the commit placed with those epochs' keysets.
pub(crate) fn note_sealed(core: &mut Core, id: &CommitId, actor: &Tid, recs: &[SealedRec]) {
    for x in recs {
        let key = (*actor, x.role, x.epoch);
        let mut at = core.ix.sealed.get(&key).cloned().unwrap_or_default();
        let before = at.clone();
        at.keysets.entry(x.holder).or_default().extend(x.keysets.iter().copied());
        at.by.insert(*id);
        if at != before {
            core.ix.sealed.insert(key, at);
            core.touch();
        }
    }
}

/// Re-derives `epoch_intro` and `keysets` of `actors` from their valid `keys.0` parts
/// (after validity flips, drops, and at load once validity is judged): an invalid write (a
/// removed admin's backdated rotation) never introduces an epoch nor makes one held.
pub(crate) fn rebuild_keysets(tx: &mut Tx<'_>, actors: &std::collections::BTreeSet<Tid>) -> Result<()> {
    if actors.is_empty() {
        return Ok(());
    }
    tx.core.touch();
    tx.core.ix.epoch_intro.retain(|(a, _, _), _| !actors.contains(a));
    for a in actors {
        let held: Vec<(Role, osis_crypto::Epoch)> = tx.core.keysets_noted(a).map(|x| (x.0, x.1)).collect();
        for (r, e) in held {
            tx.core.ix.keysets.remove(&(*a, r, e));
        }
        let sealed: Vec<(Role, osis_crypto::Epoch)> = tx.core.sealed_noted(a).map(|x| (x.0, x.1)).collect();
        for (r, e) in sealed {
            tx.core.ix.sealed.remove(&(*a, r, e));
        }
    }
    let ak = osis_base::Ak::new("keys.0").map_err(|_| crate::Error::Misuse("ak"))?;
    for a in actors {
        let ids: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*a, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        for id in ids {
            let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
            let Some(ai) = m.aspect(a, &ak) else { continue };
            if !m.valid_at(ai) {
                continue;
            }
            if let Some(d) = m.dropped(ai) {
                note_keysets(tx.core, &m.header, &id, a, &d.keysets);
            }
            if let Some(d) = super::held_part(tx, &id, ai)? {
                let body = KeysBody::of(d.fragment());
                note_keysets(tx.core, &m.header, &id, a, &body.recs);
                note_sealed(tx.core, &id, a, &body.sealed);
            }
        }
    }
    Ok(())
}

/// Notes the `keys.0` parts of role commit `h` whose bodies write a keyset, whatever their
/// validity (`records::OWN_SECRETS`: a fact of the body, kept once it drops or goes missing), then
/// re-derives `independent` of their things.
fn note_keyset_parts(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &super::PartsRead<'_>) -> Result<()> {
    if !h.kind.is_role() {
        return Ok(());
    }
    let id = *id;
    let mut things = std::collections::BTreeSet::new();
    for (i, (ai, _)) in parts.all().iter().enumerate() {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if parts.keys(i).is_none_or(|k| k.write.keysets.is_empty()) {
            continue;
        }
        if tx.core.ix.keyset_parts.insert(a.tid, id) {
            tx.core.touch();
            tx.txn.put_local(&crate::engine::records::own_secrets_key(&a.tid, &id), &[], Shred::No)?;
        }
        things.insert(a.tid);
    }
    refresh_independent(tx, &things, true)
}

/// Re-derives whether each of `things` is independent (spec/crypto.md §3): a held
/// commit's valid `keys.0` part wrote a keyset in its body (held, or dropped or missing since).
/// Called once a part is noted, after validity flips and at load (`!regain`). A thing that loses
/// it (that commit turned invalid) derives from its mint admin again; what it learned stays for
/// reading (`Core::epochs`). One that regains it starts its epochs again from those.
pub(crate) fn refresh_independent(tx: &mut Tx<'_>, things: &std::collections::BTreeSet<Tid>, regain: bool) -> Result<()> {
    for t in things {
        let ids: Vec<CommitId> = tx.core.ix.keyset_parts.get(t).into_iter().flatten().copied().collect();
        let mut own = false;
        for id in ids {
            let Some(m) = tx.core.ix.commits.get(&id) else {
                // forgotten
                tx.core.touch();
                tx.core.ix.keyset_parts.remove(t, &id);
                tx.txn.remove_local(&crate::engine::records::own_secrets_key(t, &id), Shred::No)?;
                continue;
            };
            own |= m.view.aspect(t, "keys.0").is_some_and(|ai| m.valid_at(ai));
        }
        if own == tx.core.ix.independent.contains(t) {
            continue;
        }
        tx.core.touch();
        if own {
            // epochs kept from a rotation found invalid earlier: start again from the derived
            // ones (`Core::epochs`), so a stale derived epoch stays current nowhere; only those
            // the kept epochs know (its history listed them), never one derived from a base epoch
            // its rotations never saw (a later rotation of the mint admin: no own epoch
            // supersedes it, so it would stay current, unboxed)
            let derived = |e: &osis_keys::ActorEpochs| {
                tx.core.base_derived(t).is_some_and(|d| ROLES.iter().any(|r| d.role(*r).epochs().any(|(ep, i)| i.established.is_some() && i.secret.is_some() && e.role(*r).get(ep).is_some())))
            };
            let restart = regain && tx.core.ix.secrets.get(t).is_some_and(derived) && tx.core.own_record(t).is_none();
            let base = restart.then(|| tx.core.epochs(t)).flatten().map(|view| {
                let kept = tx.core.ix.secrets.get(t);
                let mut out = osis_keys::ActorEpochs::default();
                for r in ROLES {
                    for (ep, info) in view.role(r).epochs() {
                        if kept.is_some_and(|k| k.role(r).get(ep).is_some()) {
                            *out.role_mut(r).observe(*ep) = info.clone();
                        }
                    }
                }
                out
            });
            tx.core.ix.independent.insert(*t);
            if let Some(b) = base {
                tx.core.ix.secrets.insert(*t, b.into_record());
                // what its history boxes say is the state's (the derived view's is its base's)
                super::atomic::observe_state(tx, t, &crate::flows::ak("secrets.0")?)?;
            }
        } else {
            tx.core.ix.independent.remove(t);
        }
    }
    Ok(())
}

pub(crate) fn note_intro(core: &mut Core, h: &Header, id: &CommitId, actor: &Tid, r: Role, e: osis_crypto::Epoch) {
    let v = (h.ts, *id);
    core.ix.epoch_intro.upsert((*actor, r, e), || v, |slot| *slot = (*slot).min(v));
}

/// The `secrets.0` write a delta makes: keyed entries put, keyed entries reset removed (a removal
/// record carries its entry's key, spec/crdt.md §5.6).
pub(crate) fn secrets_write(delta: &Fragment) -> SecretsWrite {
    let mut w = SecretsWrite::default();
    if let Some(m) = map(field(delta, 0)) {
        for (_, r, k, f) in m.entries() {
            let Some(k) = k.and_then(|k| typed(k, "box_key")).and_then(|k| BoxKey::from_value(&k).ok()) else { continue };
            match (r, f.and_then(Fragment::read)) {
                (_, Some(v)) => {
                    if let Some(b) = typed(&v, "box").and_then(|b| SecretBox::from_value(&b).ok()) {
                        w.boxes.insert(k, b);
                    }
                }
                (Some(_), None) => {
                    w.removed.insert(k);
                }
                (None, None) => {}
            }
        }
    }
    if let Some(m) = map(field(delta, 1)) {
        for (_, _, k, f) in m.entries() {
            if let (Some(k), Some(Value::Bytes(b))) = (k.and_then(|k| typed(k, "history_key")).and_then(|k| HistoryKey::from_value(&k).ok()), f.and_then(Fragment::read)) {
                w.history.insert(k, b);
            }
        }
    }
    w
}

/// The paths of the box and history keys `delta` writes: what `secrets_patch` reads of the
/// state, so every page holding an entry of one must be loaded first (`Tx::ensure_paths`).
pub(crate) fn secrets_paths(delta: &Fragment) -> Vec<Vec<osis_crdt::PathSeg>> {
    use osis_crdt::PathSeg;
    [0u64, 1].iter().flat_map(|i| map(field(delta, *i)).into_iter().flat_map(|m| m.entries()).filter_map(|(_, _, k, _)| Some(vec![PathSeg::Field(*i), PathSeg::Key(k?.clone())])).collect::<Vec<_>>()).collect()
}

/// Brings `read`, `secrets.0` as decoded before `delta` joined into `state`, up to date: the
/// delta's keys alone read again, O(log n) each. `state` holds every entry of those keys
/// (`secrets_paths`). False when it resets more than its entries, a key does not read as
/// one value, or a reset's key reads as gone: decode.
pub(crate) fn secrets_patch(read: &mut ct::Secrets, delta: &Fragment, state: &Fragment) -> bool {
    /// The value of key `k` in map `m`, if it has one; `None` when it does not read as one.
    fn one(m: Option<&osis_crdt::Map>, k: &Value) -> Option<Option<Value>> {
        match m.map(|m| m.live(k)).unwrap_or_default().as_slice() {
            [] => Some(None),
            [(_, f)] => f.read().map(Some),
            _ => None,
        }
    }
    let plain = matches!(delta, Fragment::Struct(_)) && [0, 1].iter().all(|i| field(delta, *i).is_none_or(|f| matches!(f, Fragment::Map(_)) && f.reset().is_none()));
    if delta.reset().is_some() || !plain {
        return false;
    }
    for (_, r, k, _) in map(field(delta, 0)).into_iter().flat_map(|m| m.entries()) {
        let Some(raw) = k else { return false };
        let Some(key) = typed(raw, "box_key").and_then(|k| BoxKey::from_value(&k).ok()) else { return false };
        match one(map(field(state, 0)), raw) {
            Some(None) => {
                if r.is_some() {
                    return false;
                }
                read.boxes.remove(&key);
            }
            Some(Some(v)) => {
                let Some(b) = typed(&v, "box").and_then(|b| SecretBox::from_value(&b).ok()) else { return false };
                read.boxes.insert(key, b);
            }
            None => return false,
        }
    }
    for (_, r, k, _) in map(field(delta, 1)).into_iter().flat_map(|m| m.entries()) {
        let Some(raw) = k else { return false };
        let Some(key) = typed(raw, "history_key").and_then(|k| HistoryKey::from_value(&k).ok()) else { return false };
        match one(map(field(state, 1)), raw) {
            Some(None) => {
                if r.is_some() {
                    return false;
                }
                read.history.remove(&key);
            }
            Some(Some(Value::Bytes(b))) => {
                read.history.insert(key, b);
            }
            _ => return false,
        }
    }
    true
}

/// The keysets a `keys.0` delta writes (whole keysets: a rotation replaces the field).
pub(crate) fn keys_write(delta: &Fragment) -> KeysWrite {
    let mut w = KeysWrite::default();
    for r in osis_keys::ROLES {
        if let Some(v) = field(delta, osis_keys::aspects::keyset_field(r)).and_then(Fragment::read)
            && let Some(ks) = keyset_of_value(&v)
        {
            w.keysets.insert(r, ks);
        }
    }
    w
}

fn keyset_of_value(v: &Value) -> Option<ct::Keyset> {
    // an `option<keyset>` field: `some(keyset)`
    let inner = match v {
        Value::Enum(1, Some(p)) => p.as_ref(),
        v => v,
    };
    ct::Keyset::from_value(&typed(inner, "keyset")?).ok()
}

/// Inputs gathered before a commit's deltas join: per actor, its `secrets.0` part and `keys.0`
/// write.
pub(crate) struct Pending {
    id: CommitId,
    ai: usize,
    actor: Tid,
    keys: KeysWrite,
}

pub(crate) fn before_join(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &super::PartsRead<'_>, valid: &[bool]) -> Result<Vec<Pending>> {
    note_keyset_parts(tx, h, id, parts)?;
    let mut out = Vec::new();
    for (i, (ai, _)) in parts.all().iter().enumerate() {
        if let Some(a) = h.aspects.get(*ai)
            && valid.get(*ai).copied().unwrap_or(false)
            && let Some(k) = parts.keys(i)
        {
            note_keysets(tx.core, h, id, &a.tid, &k.recs);
            note_sealed(tx.core, id, &a.tid, &k.sealed);
        }
    }
    if h.kind != Kind::Role {
        return Ok(out);
    }
    for (ai, d) in parts.all() {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "secrets.0" {
            continue;
        }
        let Decoded::Delta(d) = d else { continue };
        note_boxes_to(tx.core, &a.tid, &d.fragment);
        // an invalid commit's epochs count for nothing (spec/crypto.md §4)
        if !valid.get(*ai).copied().unwrap_or(false) {
            continue;
        }
        let keys = (parts.all().iter().enumerate())
            .find_map(|(i, (x, k))| match (h.aspects.get(*x), k) {
                (Some(b), Decoded::Delta(_)) if b.tid == a.tid => parts.keys(i).map(|k| k.write.clone()),
                _ => None,
            })
            .unwrap_or_default();
        out.push(Pending { id: *id, ai: *ai, actor: a.tid, keys });
    }
    Ok(out)
}

/// After the joins: the applied rotations, `secrets.0` compaction snapshots held, and the boxes
/// of invalid `secrets.0` deltas (`read_invalid`).
pub(crate) fn after_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)], valid: &[bool], pending: Vec<Pending>) -> Result<()> {
    tx.core.touch();
    if h.kind == Kind::Role {
        for (ai, d) in parts {
            if let (Some(a), Decoded::Delta(d)) = (h.aspects.get(*ai), d)
                && a.ak.as_str() == "secrets.0"
                && !valid.get(*ai).copied().unwrap_or(false)
            {
                read_invalid(tx, &h.id(), h.signer, a.tid, &d.fragment)?;
            }
        }
    }
    // per part, the write of all its held deltas at once
    let mut done = std::collections::BTreeSet::new();
    for p in pending {
        if !done.insert((p.id, p.ai)) {
            continue;
        }
        let mut w = SecretsWrite::default();
        if let Some(Decoded::Delta(d)) = super::held_part(tx, &p.id, p.ai)? {
            w.extend(secrets_write(&d.fragment));
        }
        let actor = p.actor;
        edit_epochs(tx, actor, |e| {
            let _ = w.rotated(e, p.id, &p.keys);
        });
    }
    if h.kind == Kind::RoleSnapshot {
        for (ai, d) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            if a.ak.as_str() != "secrets.0" || !valid.get(*ai).copied().unwrap_or(false) {
                continue;
            }
            let Decoded::Snapshot(s) = d else { continue };
            let Some(sv) = s.fragment.read().and_then(|v| crate::engine::secrets::secrets_value(&v)) else { continue };
            edit_epochs(tx, a.tid, |e| {
                let _ = osis_keys::snapshot_keyed(&sv, h.id(), e);
            });
        }
    }
    Ok(())
}

/// A held commit's `secrets.0` delta became invalid: its rotations, or a snapshot's keying, no
/// longer count (another valid commit of the same epoch keeps it); its boxes stay open for
/// reading (`read_invalid`).
pub(crate) fn invalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some((a, author)) = tx.core.ix.commits.get(c).and_then(|m| Some((m.header.aspects.get(ai)?.clone(), m.view.signer))) else { return Ok(()) };
    if a.ak.as_str() != "secrets.0" {
        return Ok(());
    }
    tx.core.touch();
    if let Some(e) = tx.core.ix.secrets.get_mut(&a.tid) {
        e.invalidate(c);
    }
    if let Some(Decoded::Delta(d)) = super::held_part(tx, c, ai)? {
        read_invalid(tx, c, author, a.tid, &d.fragment)?;
    }
    Ok(())
}

/// Opens, for reading only, the boxes and history boxes of held role commit `id`'s invalid
/// `secrets.0` delta on `actor` (spec/crypto.md §4 Reading-only secrets; custody follows holding:
/// a box opens whether or not its commit counts), then what that opens in turn
/// (`flows::reopen_dependents`: the history boxes of `actor`'s other invalid commits, the boxes
/// sealed to `actor`). What it gives is never encrypted under, and goes with the commit
/// (`unindex`) or once an applied valid box carries it.
pub(crate) fn read_invalid(tx: &mut Tx<'_>, id: &CommitId, author: Tid, actor: Tid, delta: &Fragment) -> Result<()> {
    if read_invalid_delta(tx, id, author, actor, delta)? {
        crate::flows::reopen_dependents(tx, actor)?;
    }
    Ok(())
}

/// `read_invalid` of one delta alone; whether it gave anything.
fn read_invalid_delta(tx: &mut Tx<'_>, id: &CommitId, author: Tid, actor: Tid, delta: &Fragment) -> Result<bool> {
    let w = secrets_write(delta);
    if w.boxes.is_empty() && w.history.is_empty() {
        return Ok(false);
    }
    let s = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() };
    Ok(read_for_reading(tx, &actor, &s, osis_keys::Unchecked { author, commit: *id }))
}

/// The invalid `secrets.0` deltas on `actor` held (`read_invalid`), opened again: an opener of
/// theirs came to be held, `actor` itself included (`flows::reopen_dependents`). O(the commits
/// invalid there). Whether anything was learned.
pub(crate) fn reread_invalid(tx: &mut Tx<'_>, actor: &Tid) -> Result<bool> {
    let ak = osis_base::Ak::new("secrets.0").map_err(|_| crate::Error::Misuse("ak"))?;
    let ids: Vec<(CommitId, usize, Tid)> = (tx.core.ix.invalid.get(&(*actor, ak.clone())).into_iter().flatten())
        .filter_map(|c| {
            let m = tx.core.ix.commits.get(c)?;
            let ai = m.aspect(actor, &ak)?;
            (m.header.kind == Kind::Role && !m.valid_at(ai) && m.holds(ai)).then_some((*c, ai, m.view.signer))
        })
        .collect();
    let mut learned = false;
    for (c, ai, author) in ids {
        if let Some(Decoded::Delta(d)) = super::held_part(tx, &c, ai)? {
            learned |= read_invalid_delta(tx, &c, author, *actor, &d.fragment)?;
        }
    }
    Ok(learned)
}

/// Ingests `s` of `actor` for reading only, sourced from `from` (`SecretsRead::Pending`);
/// whether it gave anything.
fn read_for_reading(tx: &mut Tx<'_>, actor: &Tid, s: &ct::Secrets, from: osis_keys::Unchecked) -> bool {
    tx.core.touch();
    if tx.core.ingest_secrets(actor, s, crate::engine::secrets::SecretsRead::Pending(from), &osis_keys::HistoryAlts::new()) {
        tx.core.waits.read_from(from.commit);
        return true;
    }
    if tx.core.reading_full(actor) {
        tx.core.waits.box_refused(from.commit);
    }
    false
}

/// What a `secrets.0` compaction snapshot carries (spec/crypto.md §4): `state` less every entry
/// at an epoch not established here, names aside (`osis_keys::unvouched`), so the snapshot bases
/// only what this node verified; the commits writing those stay beside it, uncovered. Those
/// commits, which the snapshot must not list in `Absorbed` (spec/crdt.md §8: else a node holding
/// the snapshot but not such a body judges it covered and never fetches what was left out).
/// A state that does not read as `secrets.0` is refused, never carried whole.
pub(crate) fn vouched_only(core: &Core, actor: &Tid, state: &mut Fragment) -> Result<std::collections::BTreeSet<CommitId>> {
    const UNREAD: crate::Error = crate::Error::Misuse("secrets.0 state does not read (spec/crypto.md §4)");
    let s = state.read().and_then(|v| crate::engine::secrets::secrets_value(&v)).ok_or(UNREAD)?;
    let e = core.epochs(actor).unwrap_or_default();
    let out = osis_keys::unvouched(&s, &e).map_err(|_| UNREAD)?;
    let mut dots = state.leave_out(0, &out.boxes.iter().map(|k| k.to_value()).collect::<Vec<_>>());
    dots.extend(state.leave_out(1, &out.history.iter().map(|k| k.to_value()).collect::<Vec<_>>()));
    Ok(dots
        .iter()
        .filter_map(|d| match osis_crdt::fact_source(&d.src).kind() {
            osis_crdt::SourceKind::Commit(c) => Some(*c),
            _ => None,
        })
        .collect())
}

/// A held commit's `secrets.0` delta became valid again (re-grant): applied as received.
pub(crate) fn revalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai).cloned() else { return Ok(()) };
    if a.ak.as_str() != "secrets.0" {
        return Ok(());
    }
    let mut secrets = SecretsWrite::default();
    match super::held_part(tx, c, ai)? {
        Some(Decoded::Delta(d)) => secrets.extend(secrets_write(&d.fragment)),
        Some(Decoded::Snapshot(s)) => {
            let Some(sv) = s.fragment.read().and_then(|v| crate::engine::secrets::secrets_value(&v)) else { return Ok(()) };
            tx.core.touch();
            edit_epochs(tx, a.tid, |e| {
                let _ = osis_keys::snapshot_keyed(&sv, *c, e);
            });
            return Ok(());
        }
        None => {}
    }
    let mut keys = KeysWrite::default();
    if let Some(ki) = h.aspect_index(&a.tid, "keys.0")
        && let Some(Decoded::Delta(d)) = super::held_part(tx, c, ki)?
    {
        keys = keys_write(&d.fragment);
    }
    tx.core.touch();
    edit_epochs(tx, a.tid, |e| {
        let _ = secrets.rotated(e, *c, &keys);
    });
    Ok(())
}

/// Edits `actor`'s epochs. An edit that learns nothing leaves no entry: the
/// index holds what is on disk.
fn edit_epochs(tx: &mut Tx<'_>, actor: Tid, f: impl FnOnce(&mut osis_keys::ActorEpochs)) {
    let before = tx.core.ix.secrets.get(&actor).cloned().unwrap_or_default();
    let mut e = before.clone();
    f(&mut e);
    if e != before {
        tx.core.ix.secrets.insert(actor, e);
    }
}

/// (pending commit, actor) whose boxes the lost-access forgetting kept (`rotation::boxes_kept`):
/// never read as candidates (they would keep the lost secrets for good), only applied.
pub(crate) const SEALED: &[u8] = b"b/";

pub(crate) fn sealed_key(c: &CommitId, a: &Tid) -> Vec<u8> {
    [SEALED, &c.0[..], a.as_bytes()].concat()
}

/// Opens, read-only, the boxes of a pending role commit addressed to this node or an actor
/// it holds (spec/crypto.md §4: such secrets are "kept for
/// reading"): the epochs are recorded unestablished, so a grantee whose grant waits for the
/// target's `created.0` and chain can open the target's sync ID and download them. Parts are
/// decoded unverified, so what they yield is reading-only: never encrypted under, and replaced
/// by an applied valid box (spec/crypto.md §4).
pub(crate) fn read_pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<()> {
    for (a, s, from) in pending_boxes(tx, blob, id)? {
        read_for_reading(tx, &a, &s, from);
    }
    Ok(())
}

/// What `read_pending_boxes` reads of pending commit `id`.
pub(crate) fn pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<Vec<(Tid, ct::Secrets, osis_keys::Unchecked)>> {
    let mut out = Vec::new();
    for (a, w) in pending_secrets_writes(blob, id) {
        if (w.boxes.is_empty() && w.history.is_empty()) || tx.txn.get_local(&sealed_key(id, &a))?.is_some() {
            continue;
        }
        // an author whose chain is not known here shares one budget with every such author (a
        // claimed grant earns nothing: its `roles.0` part is as unverified as the boxes)
        let author = if tx.core.created(&blob.header.signer).is_some() { blob.header.signer } else { osis_keys::UNKNOWN_AUTHOR };
        out.push((a, ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() }, osis_keys::Unchecked { author, commit: *id }));
    }
    Ok(out)
}

/// Drops the reading-only secrets commit `id` gave: it applied (its boxes are checked now), was
/// dropped or forgotten (spec/crypto.md §4). Those of an actor its held `secrets.0` part on is
/// invalid stay (`read_invalid`). An actor they were the only secrets of is left to the
/// lost-access trigger, which drops them with what they read.
pub(crate) fn forget_unchecked(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let prefix = [SEALED, &id.0[..]].concat();
    let mut sealed = Vec::new();
    tx.scan(&prefix, |k, _| {
        sealed.push([prefix.as_slice(), k].concat());
        Ok(())
    })?;
    for k in sealed {
        tx.txn.remove_local(&k, Shred::No)?;
    }
    let actors: Vec<Tid> = tx.core.ix.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.sources().any(|u| u.commit == *id)))).map(|(t, _)| *t).collect();
    let invalid_on = |core: &crate::engine::Core, a: &Tid| {
        core.ix.commits.get(id).is_some_and(|m| m.header.kind == Kind::Role && m.header.aspect_index(a, "secrets.0").is_some_and(|ai| !m.valid_at(ai) && m.holds(ai)))
    };
    let (kept, actors): (Vec<Tid>, Vec<Tid>) = actors.into_iter().partition(|a| invalid_on(tx.core, a));
    let mut lost = Vec::new();
    for a in actors {
        let Some(mut e) = tx.core.ix.secrets.get(&a).cloned() else { continue };
        e.drop_reading_from(id);
        // an actor left with no secret is the lost-access trigger's: it forgets what they read
        if !e.holds_any() {
            lost.push(a);
            continue;
        }
        tx.core.touch();
        tx.core.ix.secrets.insert(a, e);
    }
    if kept.is_empty() {
        tx.core.waits.forgot(id);
    }
    crate::rotation::touch_held(tx, lost);
    Ok(())
}

/// The `secrets.0` writes of a held, not applied role commit, per actor, decoded
/// unverified (what `read_pending_boxes` reads; the lost-access trigger's pending grants).
pub(crate) fn pending_secrets_writes(blob: &osis_commit::CommitBlob, id: &CommitId) -> Vec<(Tid, SecretsWrite)> {
    pending_deltas(blob, id, |a| a.ak.as_str() == "secrets.0").into_iter().map(|(t, d)| (t, secrets_write(&d))).collect()
}

/// The deltas of a held, not applied role commit's parts whose header entry `keep` takes, with
/// their things, decoded unverified; none while its header lists are not resolved.
fn pending_deltas(blob: &osis_commit::CommitBlob, id: &CommitId, keep: impl Fn(&osis_commit::AspectEntry) -> bool) -> Vec<(Tid, Fragment)> {
    let h = &blob.header;
    if !h.kind.is_role() || !h.is_resolved() {
        return Vec::new();
    }
    let mut interner = osis_crdt::Interner::new();
    let mut out = Vec::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai).filter(|a| keep(a)) else { continue };
        let Ok(cx) = osis_commit::delta_ctx(h, id, p.ai, &mut interner) else { continue };
        let Ok(d) = osis_crdt::decode_delta(&p.delta, &cx, &mut interner, None) else { continue };
        out.push((a.tid, d.fragment));
    }
    out
}

impl crate::engine::Engine {
    /// Records a read or sync secret learned from an entry box (a link key opening
    /// by static entry, spec/sync-ids.md §3) or a ticket (spec/sync-inbox.md §5) when it is the secret of epoch `e` of `g`'s role `r` (spec/crypto.md
    /// §4; anyone holding the head's step key, a removed admin among them, can write the box, so
    /// it establishes nothing). False when it is not, or when the node lost `g` (`rotation::may_learn`,
    /// spec/permissions.md §3).
    pub fn learn_secret(&mut self, g: &Tid, r: Role, e: osis_crypto::Epoch, secret: osis_crypto::Secret32) -> Result<bool> {
        let g = *g;
        self.run(|tx| learn_secret_in(tx, &g, r, e, secret))
    }
}

/// `Engine::learn_secret` in a transaction.
pub(crate) fn learn_secret_in(tx: &mut Tx<'_>, g: &Tid, r: Role, e: osis_crypto::Epoch, secret: osis_crypto::Secret32) -> Result<bool> {
    if !e.names(g, r, &secret) || !crate::rotation::may_learn(tx.core, g, r) {
        return Ok(false);
    }
    let g = *g;
    if tx.core.epochs(&g).is_some_and(|x| x.role(r).secret(&e).is_some()) {
        return Ok(false);
    }
    tx.core.touch();
    // a sync secret of a thing not read (a ticket's, spec/sync.md §3): held as its epoch's,
    // nothing of the thing opened by it
    if r == Role::Sync && !tx.core.epochs(&g).is_some_and(|x| x.role(Role::Read).holds_any()) {
        tx.core.ix.secrets.entry_or_default(g).role_mut(r).set_secret(e, secret);
        return Ok(true);
    }
    tx.core.ix.secrets.entry_or_default(g).role_mut(r).set_secret(e, secret);
    // what the secret opens: `g`'s own history boxes, then the boxes sealed to `g`
    let (s, alts) = (crate::flows::secrets_in(tx, &g)?, crate::flows::secrets_alts(tx, &g)?);
    tx.core.ingest_secrets(&g, &s, crate::engine::secrets::SecretsRead::State, &alts);
    crate::flows::reopen_dependents(tx, g)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use crate::flows::Demotion;

    /// A thing whose mint admin is `admin`, made by peer `i`, held by every peer.
    fn thing_of(lp: &mut LocalPeer, i: usize, admin: Tid) -> Tid {
        let e = &mut lp.peers[i].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, admin);
        m.set(t, &osis_base::Ak::new("x:reg.0").unwrap(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap().unwrap();
        lp.hold(t);
        t
    }

    fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
        for id in ids {
            let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
            lp.deliver(to, &pk).unwrap();
        }
    }

    use crate::engine::secrets::MAX_READING_ACTORS;
    use crate::local_peer::LocalPeer;
    use crate::Mutation;
    use osis_base::{CommitId, Role, Tid, Value, WallMs};
    use osis_crypto::{Epoch, Secret32};
    use osis_keys::{ActorEpochs, Unchecked};
    use osis_schema::Codec;
    use osis_schema::core_types as ct;

    fn reading_only(n: u8, commit: CommitId) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        a.read.set_reading_secret(Epoch::new(1, [n; 32]).unwrap(), Secret32::from_bytes([n; 32]), Unchecked { author: Tid::from_bytes([n; 15]), commit });
        a
    }

    // spec/crypto.md §4: boxes of pending commits are read, but the node holds a bounded number
    // of actors through reading-only secrets alone; past it a pending grant's boxes are not read.
    // A genuine grant past the cap reads its boxes once an applied one frees a place, or it waits
    // for good on the sync ID those secrets open.
    #[test]
    fn refused_boxes_read_when_a_grant_applies_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.dependents_admin();
        let b = lp.peers[1].engine.me();
        let thing = |lp: &mut LocalPeer| {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, me);
            m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
            let c = lp.peers[0].commit(m).unwrap().unwrap();
            lp.hold(t);
            lp.send_chain(0, 1, &t).unwrap();
            (t, c)
        };
        let ((t1, c1), (t2, _)) = (thing(&mut lp), thing(&mut lp));
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        let g1 = *lp.peers[0].engine.grant(&t1, &b, &edge).unwrap().commits.last().unwrap();
        let g2 = *lp.peers[0].engine.grant(&t2, &b, &edge).unwrap().commits.last().unwrap();
        let (p1, p2) = (lp.peers[0].engine.package(&g1).unwrap().unwrap(), lp.peers[0].engine.package(&g2).unwrap().unwrap());
        lp.peers[1].engine.index_poked = true;
        for n in 0..MAX_READING_ACTORS - 1 {
            let n = u8::try_from(n).unwrap();
            lp.peers[1].engine.core.ix.secrets.insert(Tid::from_bytes([n; 15]), reading_only(n, CommitId([n; 32])));
        }
        lp.deliver(1, &p1).unwrap();
        lp.deliver(1, &p2).unwrap();
        let held = |lp: &LocalPeer, t: &Tid| lp.peers[1].engine.core.ix.secrets.get(t).is_some_and(|e| e.read.holds_any());
        assert!(held(&lp, &t1));
        assert!(!held(&lp, &t2), "past the cap");
        // the first grant's thing arrives: it applies, its secret is checked, a place is free
        let created = lp.peers[0].engine.package(&c1).unwrap().unwrap();
        lp.deliver(1, &created).unwrap();
        lp.peers[1].reexamine().unwrap();
        assert!(!lp.peers[1].engine.pending().iter().any(|(c, _)| *c == g1), "applied");
        assert!(held(&lp, &t2), "read once a place is free");
    }

    // spec/crypto.md §4 (Reading-only secrets): pending boxes are read for reading only, apply::waits: what a pending
    // commit's boxes teach depends only on what its wait follows. Here the grant on `a` (mint
    // admin `u`, whose epochs the grantee holds) waits for `a`'s record; `u`'s establishment
    // changing (computed from applied commits and roles) wakes no wait, so reading the boxes again
    // must give nothing new: no derived establishment from `u`.
    #[test]
    fn pending_boxes_read_no_chain_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.me();
        let b = lp.peers[1].engine.me();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        let mut m = Mutation::new();
        let u = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(u, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(u);
        lp.peers[0].engine.grant(&u, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.core.epochs(&u).is_some_and(|e| !e.read.current().is_empty()), "the grantee holds u's established epochs");
        let mut m = Mutation::new();
        let a = lp.peers[0].engine.new_thing(&mut m, u);
        m.set(a, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(2)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(a);
        let g = *lp.peers[0].engine.grant(&a, &b, &edge).unwrap().commits.last().unwrap();
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        lp.deliver(1, &p).unwrap();
        assert!(!lp.peers[1].engine.commit_ids().contains(&g), "waits for a's record");
    }

    /// Peer 0 is mint admin of thing `t` (`x:a.0` = 1); peer 1 is the grantee, holding nothing of peer 0;
    /// peers 2.. are throwaway authors unknown to the grantee.
    fn grantee_world(n: usize) -> (LocalPeer, Tid) {
        LocalPeer::cached(&format!("apply::keys::grantee_world/{n}"), || grantee_build(n))
    }

    fn grantee_build(n: usize) -> (LocalPeer, Tid) {
        let mut lp = LocalPeer::fresh(n, WallMs(1_700_000_000_000));
        let me = lp.peers[0].engine.me();
        // the granter holds the grantee's keys
        lp.sync(1, 0).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.hold(t);
        (lp, t)
    }

    /// Floods the grantee (peer 1) with `per` bogus pending commits from each throwaway author
    /// (peers 2..): each boxes it a fresh read secret of `t` at a fresh epoch, built past the
    /// writer rules. Returns how many it delivered.
    fn flood(lp: &mut LocalPeer, t: Tid, per: usize) -> usize {
        let b = lp.peers[1].engine.me();
        let keys = lp.peers[1].engine.account_holder_keys(&b).unwrap();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let mut sent = 0;
        for x in 2..lp.peers.len() {
            for i in 0..per {
                let mut held = ActorEpochs::default();
                held.sync.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
                held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
                let rcpt = osis_keys::Recipient { holder: b, role: Role::Read, keys: keys.clone(), floor: 0 };
                let mut rng = osis_crypto::SeededRng::from_u64((x * 10_000 + i) as u64);
                let rot = osis_keys::rotate(&t, &[Role::Sync, Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut rng).unwrap();
                let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
                let bytes = forge_role_commit(lp, x, t, &rec, &v);
                assert!(matches!(lp.peers[1].receive(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(_, crate::Reason::MissingChain(_) | crate::Reason::UnknownCreated(_))), "a bogus commit cannot be judged at the grantee");
                sent += 1;
            }
        }
        sent
    }

    /// A role commit by peer `by` setting `t`'s `secrets.0` to `v`, signed past every writer rule
    /// (its author may hold no chain to `t`).
    fn forge_role_commit(lp: &mut LocalPeer, by: usize, t: Tid, rec: &osis_base::CreationRecord, v: &Value) -> Vec<u8> {
        use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
        use osis_crdt::{Delta, Source, Writer, create, encode_delta};
        struct Dedup(osis_base::CreationRecord);
        impl osis_commit::Secrets for Dedup {
            fn dedup(&self, _: &Tid) -> Option<Secret32> {
                Some(osis_crypto::dedup_secret(self.0.nonce()))
            }
            // made-up delete keys (peers' business)
            fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([3; 32])).verifying_key())
            }
            fn purge_author_key(&self) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([1; 32])).verifying_key())
            }
            fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([2; 32])).verifying_key())
            }
        }
        let ak = osis_base::Ak::new("secrets.0").unwrap();
        let author = lp.peers[by].engine.me();
        lp.peers[by].clock.advance(1);
        let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
        let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
        let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
        let f = create(&mut w, &view, v).unwrap();
        let r = w.range();
        let cx = writer_ctx(Form::Commit, Kind::Role, ts, author, r.lo, r.hi);
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
        let mut cb = CommitBuilder::new(Kind::Role, ts, author, osis_commit::Path::default(), Form::Commit);
        let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes.clone());
        aw.purge_by = osis_commit::retention::write_purge_by(ak.as_str(), None, None).unwrap();
        cb.aspects.push(aw);
        let forge_key = lp.peers[by].engine.sign_forged(&mut cb);
        cb.build(&forge_key, &Dedup(rec.clone()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap().commit.encode()
    }

    /// A pending commit by peer `by` boxing peer 1 a fresh read secret of `t`.
    fn forged_grant(lp: &mut LocalPeer, by: usize, t: Tid) {
        let b = lp.peers[1].engine.me();
        let keys = lp.peers[1].engine.account_holder_keys(&b).unwrap();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let mut held = ActorEpochs::default();
        held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
        let rcpt = osis_keys::Recipient { holder: b, role: Role::Read, keys, floor: 0 };
        let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(0)).unwrap();
        let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
        let bytes = forge_role_commit(lp, by, t, &rec, &v);
        assert!(matches!(lp.peers[1].receive(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(_, crate::Reason::MissingChain(_) | crate::Reason::UnknownCreated(_))));
    }

    /// Peer 1 reads `t` (checked secrets), then is removed by peer 0; the removal applied.
    fn removed_reader() -> (LocalPeer, Tid) {
        LocalPeer::cached("apply::keys::removed_reader", removed_build)
    }

    fn removed_build() -> (LocalPeer, Tid) {
        let (mut lp, t) = grantee_world(3);
        let b = lp.peers[1].engine.me();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), Some(Value::Int(1)));
        (lp, t)
    }

    // spec/crypto.md §4: what a node holds is a function of the secrets it holds, however it
    // learned them: a secret from an entry box opens the boxes sealed to its epoch at once, as a
    // rebuild of the store would. Node 1 reads g, which reads t; g's and t's next epochs box
    // node 1 nothing.
    #[test]
    fn a_learned_read_secret_opens_the_boxes_sealed_to_it_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(2, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let a = lp.peers[0].engine.me();
        let b = lp.peers[1].engine.me();
        let g = thing_of(&mut lp, 0, a);
        let t = thing_of(&mut lp, 0, a);
        let read = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &g, &read).unwrap();
        lp.peers[0].engine.grant(&g, &b, &read).unwrap();
        lp.peers[0].engine.rotate_boxing_only(&[g], &[Role::Read], &[a]).unwrap();
        lp.peers[0].engine.rotate_boxing_only(&[t], &[Role::Read], &[a, g]).unwrap();
        let e0 = lp.peers[0].engine.epochs(&g).unwrap();
        let eg = e0.read.newest().unwrap();
        let sg = e0.read.secret(&eg).cloned().unwrap();
        let et = lp.peers[0].engine.epochs(&t).unwrap().read.newest().unwrap();
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.epochs(&t).is_none_or(|e| e.read.secret(&et).is_none()), "nothing opens t yet");
        assert!(lp.peers[1].engine.learn_secret(&g, Role::Read, eg, sg).unwrap());
        assert!(lp.peers[1].engine.epochs(&t).unwrap().read.secret(&et).is_some(), "the box sealed to g's epoch opened");
        lp.peers[1].engine.check_index();
    }

    // spec/crypto.md §4, spec/sync-ids.md §3: a read secret from a sync ID's entry box (written by
    // whoever holds the head's step key: a removed admin before the remover re-registers) is
    // held only when it is the secret of the epoch it names; it establishes nothing, so the
    // node encrypts under it once the epoch's rotation commit applies.
    #[test]
    fn entry_box_secret_checked_spec_crypto_4() {
        let (mut lp, t) = removed_reader();
        let c = lp.peers[2].engine.me();
        lp.sync(2, 0).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &c, &edge).unwrap();
        let before = lp.peers[0].engine.epochs(&t).unwrap().read.newest().unwrap();
        lp.peers[0].engine.demote(&t, &Demotion { holder: c, new: None, retain: None }).unwrap();
        let e0 = lp.peers[0].engine.epochs(&t).unwrap();
        let e_new = e0.read.newest().unwrap();
        assert_ne!(e_new, before, "the removal rotated");
        let genuine = e0.read.secret(&e_new).cloned().unwrap();
        let planted = Secret32::from_bytes([0x66; 32]);
        assert!(!lp.peers[1].engine.learn_secret(&t, Role::Read, e_new, planted.clone()).unwrap(), "a secret of another epoch");
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert!(e1.read.reading_secret(&e_new).is_none());
        assert!(lp.peers[1].engine.learn_secret(&t, Role::Read, e_new, genuine.clone()).unwrap());
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert_eq!(e1.read.secret(&e_new), Some(&genuine));
        assert!(!e1.read.is_established(&e_new) && e1.read.newest_held().is_none_or(|x| x.0 != e_new));
        lp.sync(0, 1).unwrap();
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert_eq!(e1.read.newest_held(), Some((e_new, &genuine)));
        assert_eq!(lp.peers[1].engine.wrap_secret(&t, None).unwrap().as_ref(), Some(&genuine));
    }

    // spec/crypto.md §4 (`keys.0` vouches for no secret): a writer
    // re-publishing the current read epoch with another epoch's keys, applied at a late joiner
    // before or after the grant that boxes it that epoch, drops nothing: the joiner holds and
    // wraps under the genuine secret.
    #[test]
    fn bogus_keyset_drops_no_secret_spec_crypto_4() {
        use osis_crdt::{Op, PathOp, PathSeg};
        for junk_first in [true, false] {
            let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
            lp.sync_all().unwrap();
            let me = lp.peers[0].engine.me();
            let (w, d, m) = (lp.peers[1].engine.me(), lp.peers[2].engine.me(), lp.peers[3].engine.me());
            let mut mu = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut mu, me);
            mu.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
            lp.peers[0].commit(mu).unwrap();
            lp.hold(t);
            let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
            lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.demote(&t, &Demotion { holder: m, new: None, retain: None }).unwrap();
            let e0 = lp.peers[0].engine.epochs(&t).unwrap();
            let e = e0.read.newest().unwrap();
            let genuine = e0.read.secret(&e).cloned().unwrap();
            lp.sync(0, 1).unwrap();
            // the writer's `keys.0`: E's keyset with another secret's keys
            let junk = osis_keys::keyset(&e, &Secret32::from_bytes([0x66; 32]), &Default::default(), &Default::default());
            let mut mu = Mutation::new();
            mu.op(t, &ct::KEYS, PathOp { path: vec![PathSeg::Field(0)], op: Op::Set(Some(junk.clone()).to_value()) }).unwrap();
            mu.unchecked();
            lp.peers[1].engine.core.skip_writer_rules = true;
            lp.peers[1].commit(mu).unwrap().unwrap();
            lp.peers[1].engine.core.skip_writer_rules = false;
            if junk_first {
                lp.sync(1, 0).unwrap();
            }
            lp.peers[0].engine.grant(&t, &d, &edge(Role::Read)).unwrap();
            lp.sync(0, 2).unwrap();
            if !junk_first {
                lp.sync(1, 2).unwrap();
            }
            assert_eq!(lp.peers[2].engine.get_typed(&t, &ct::KEYS).unwrap().unwrap().read, Some(junk), "the writer's keyset applied");
            let ed = lp.peers[2].engine.epochs(&t).unwrap();
            assert_eq!(ed.read.newest_held(), Some((e, &genuine)), "junk first: {junk_first}");
            assert_eq!(lp.peers[2].engine.wrap_secret(&t, None).unwrap().as_ref(), Some(&genuine));
        }
    }

    fn remove(lp: &mut LocalPeer, t: Tid) {
        let b = lp.peers[1].engine.me();
        lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, retain: None }).unwrap();
        lp.sync(0, 1).unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), None);
    }

    // spec/permissions.md §3 (drop lost secrets),
    // spec/requirements.md Deletion: a pending commit boxing the removed node, by an author with
    // no right to grant on the thing, keeps nothing: it is held until it applies, so it would
    // keep the secrets for good.
    #[test]
    fn strangers_pending_box_keeps_no_lost_secrets_spec_perm_3() {
        let (mut lp, t) = removed_reader();
        forged_grant(&mut lp, 2, t);
        remove(&mut lp, t);
        assert!(lp.peers[1].engine.role_duties().unwrap().contains(&t));
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none());
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), None);
    }

    // spec/permissions.md §3 (unapplied `keys.0` write of the thing signed by a current admin): only one
    // signed by an admin of the actor counts; one whose author nobody can check (anyone can send
    // it) would hold the step back for good.
    #[test]
    fn keys_write_unapplied_needs_an_admin_spec_perm_3() {
        let (mut lp, t) = removed_reader();
        // a stranger's `keys.0` write on its own thing: its author's chain is unknown here
        let mut m = Mutation::new();
        let me2 = lp.peers[2].engine.me();
        let t2 = lp.peers[2].engine.new_thing(&mut m, me2);
        lp.peers[2].commit(m).unwrap();
        lp.hold(t2);
        let c = *lp.peers[2].engine.refresh_deposit_seed(&t2).unwrap().commits.last().unwrap();
        let pk = lp.peers[2].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(_, crate::Reason::MissingChain(_) | crate::Reason::UnknownCreated(_))));
        assert!(!lp.peers[1].engine.keys_write_unapplied(&t2).unwrap(), "unchecked author");
        // the admin's own, held back by drift
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let c = *lp.peers[0].engine.refresh_deposit_seed(&t).unwrap().commits.last().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(!lp.peers[1].engine.keys_write_unapplied(&t).unwrap());
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(_, crate::Reason::Drift)));
        assert!(lp.peers[1].engine.keys_write_unapplied(&t).unwrap(), "the admin's");
    }

    // spec/sync-ids.md §6 (a deposit-only step): waits for an unapplied `keys.0` write: a held commit
    // whose valid `keys.0` part is missing here is one (its body may give a newer seed, or secrets
    // of the thing's own); the body arriving lets the step go
    #[test]
    fn keys_write_unapplied_counts_a_missing_part_spec_sync_5() {
        let (mut lp, t) = removed_reader();
        let c = *lp.peers[0].engine.refresh_deposit_seed(&t).unwrap().commits.last().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        let b = osis_commit::CommitBlob::decode(&pk.bytes).unwrap();
        let cut = osis_commit::rewrite(&b, |ai| b.header.aspects.get(ai).is_some_and(|a| a.tid == t && a.ak.as_str() == "keys.0"));
        assert!(!lp.peers[1].engine.keys_write_unapplied(&t).unwrap());
        lp.peers[1].receive(&cut.encode(), pk.blobs.clone()).unwrap();
        assert!(lp.peers[1].engine.commit_ids().contains(&c), "held, its keys.0 part missing");
        assert!(lp.peers[1].engine.keys_write_unapplied(&t).unwrap(), "a missing part");
        lp.deliver(1, &pk).unwrap();
        assert!(!lp.peers[1].engine.keys_write_unapplied(&t).unwrap(), "joined");
    }

    /// Parts on `t`'s `secrets.0` of held commit `id` at peer 1.
    fn secrets_parts(lp: &mut LocalPeer, id: &CommitId, t: Tid) -> usize {
        let Some(bytes) = lp.peers[1].engine.commit_bytes(id).unwrap() else { return 0 };
        let blob = osis_commit::CommitBlob::decode(&bytes).unwrap();
        blob.parts.iter().filter(|p| blob.header.aspects.get(p.ai).is_some_and(|a| a.tid == t && a.ak.as_str() == "secrets.0")).count()
    }

    // spec/permissions.md §3: a re-grant held pending past the removal and outside the wait (here
    // ahead of the removed node's clock) keeps its boxes through the forgetting the removal
    // triggers, so once it applies the node holds the role and its secrets.
    #[test]
    fn late_regrant_keeps_its_boxes_spec_perm_3() {
        let (mut lp, t) = grantee_world(2);
        let b = lp.peers[1].engine.me();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        let removal = lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, retain: None }).unwrap();
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let regrant = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let pk = lp.peers[0].engine.package(&regrant).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(_, crate::Reason::Drift)));
        for id in &removal.commits {
            let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), None, "removed; the re-grant pending");
        lp.peers[1].engine.role_duties().unwrap();
        lp.peers[1].engine.drop_lost_secrets().unwrap();
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none(), "outside the wait: dropped, candidates too");
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), None, "content forgotten");
        assert_eq!(secrets_parts(&mut lp, &regrant, t), 1, "the boxes stay");
        lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].reexamine().unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), Some(Role::Read), "the re-grant applied");
        let checked = lp.peers[1].engine.core.ix.secrets.get(&t).is_some_and(|e| e.read.held().next().is_some());
        assert!(checked, "its boxes came with it");
    }

    /// The most reading candidates of one role (each role keeps its own budget).
    fn candidates(lp: &LocalPeer, t: &Tid) -> usize {
        lp.peers[1].engine.core.ix.secrets.get(t).map_or(0, |e| osis_keys::ROLES.iter().map(|r| e.role(*r).held_newest_first().len()).max().unwrap_or(0))
    }

    // spec/crypto.md §4 (Reading-only secrets): secrets from pending commits kept as reading candidates: a flood of
    // bogus pending commits from throwaway authors leaves at most the shared unknown-author
    // pool (`MAX_READING_PER_AUTHOR`), within the role's `MAX_READING`.
    #[test]
    fn bogus_flood_bounded_by_caps_spec_crypto_4() {
        let (mut lp, t) = grantee_world(5);
        let sent = flood(&mut lp, t, 30);
        assert!(sent > osis_keys::MAX_READING_PER_AUTHOR);
        let n = candidates(&lp, &t);
        assert_eq!(n, osis_keys::MAX_READING_PER_AUTHOR, "throwaway authors share one budget");
        assert!(n <= osis_keys::MAX_READING);
    }

    // spec/crypto.md §4, spec/permissions.md §2: with the unknown-author pool full, a genuine
    // pending grant adds no candidate (it claims a grant as cheaply as a bogus commit could); the
    // holder reads once the granter's chain arrives and the grant applies.
    #[test]
    fn genuine_grant_applies_after_flood_spec_crypto_4() {
        let (mut lp, t) = grantee_world(4);
        let b = lp.peers[1].engine.me();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, retain: false, floor: None };
        let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        flood(&mut lp, t, 40);
        let before = candidates(&lp, &t);
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &p).unwrap(), crate::Ingested::Pending(_, crate::Reason::MissingChain(_) | crate::Reason::UnknownCreated(_))), "the grant waits for the granter's chain");
        assert_eq!(candidates(&lp, &t), before, "the pool is full: the grant's candidate waits");
        lp.sync(0, 1).unwrap();
        assert!(!lp.peers[1].engine.core.ix.pending.contains_key(&g), "the grant applied");
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), Some(Value::Int(1)));
    }

    // spec/crypto.md §4, spec/permissions.md §3: a pending commit that applies or is dropped
    // takes its reading-only candidates; an actor they were the only secrets of is handed to
    // the lost-access trigger, which forgets it.
    #[test]
    fn applied_commit_hands_reading_only_actor_to_lost_trigger_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let (x, c) = (Tid::from_bytes([9; 15]), CommitId([9; 32]));
        lp.peers[0].engine.index_poked = true;
        lp.peers[0].engine.core.ix.secrets.insert(x, reading_only(9, c));
        lp.peers[0].engine.run(|tx| super::forget_unchecked(tx, &c)).unwrap();
        assert!(lp.peers[0].engine.lost_due(&x).unwrap());
        lp.peers[0].engine.role_duties().unwrap();
        assert!(lp.peers[0].engine.core.ix.secrets.get(&x).is_none_or(|e| !e.read.holds_any()));
    }

    // spec/crypto.md §4 (Reading-only secrets): a box opens whether or not its commit counts. Admin
    // A of T, demoted by T's mint admin O, rotates T's read role; writer W holds the rotation
    // before the demotion and writes under A's epoch. Reader R and O hold the demotion first, so
    // A's rotation is invalid on arrival there, yet W's write, sealed as a sync ID carries it,
    // opens and reads by value at both.
    #[test]
    fn a_write_under_an_invalid_rotations_epoch_reads_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let (o, a, w, r) = (0, 1, 2, 3);
        let tids: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.me()).collect();
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        let t = thing_of(&mut lp, o, tids[o]);
        lp.peers[o].engine.grant(&t, &tids[a], &edge(Role::Admin)).unwrap();
        lp.peers[o].engine.grant(&t, &tids[w], &edge(Role::Write)).unwrap();
        lp.peers[o].engine.grant(&t, &tids[r], &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.peers[o].engine.demote(&t, &Demotion { holder: tids[a], new: None, retain: None }).unwrap();
        lp.sync(o, r).unwrap();
        // A's clock runs ahead: its rotation is stamped after its demotion
        lp.peers[a].clock.advance(120_000);
        let rot = lp.peers[a].engine.rotate_leaving_out(&t, &[Role::Read], &[]).unwrap().unwrap();
        send(&mut lp, a, w, &[rot]);
        let ak = osis_base::Ak::new("x:a.0").unwrap();
        let mut m = Mutation::new();
        m.set(t, &ak, &Value::Int(7)).unwrap();
        let wc = lp.peers[w].engine.commit(m).unwrap().unwrap();
        let sealed = lp.sealed(w, &[wc]).unwrap();
        for i in [r, o] {
            send(&mut lp, a, i, &[rot]);
            assert!(lp.peers[i].engine.core.ix.commits.get(&rot).is_some_and(|m| !m.valid.iter().any(|v| *v)), "peer {i}: A's rotation is invalid");
            assert!(lp.deliver_sealed(i, &sealed).unwrap().is_empty(), "peer {i}: W's write opens");
            assert_eq!(lp.peers[i].engine.get(&t, &ak).unwrap(), Some(Value::Int(7)), "peer {i} reads W's write");
        }
    }

    // spec/crypto.md §3 (secrets of its own): a thing is independent while a valid `keys.0` part wrote a
    // keyset, §4 (Reading-only secrets): secrets of an invalid commit are kept for reading only: admin A of G grants
    // X on G's dependent thing T (T's first `keys.0`, a rotation from derived epochs) after G's mint
    // admin removed A. Once A's grant is invalid, every node derives T from G again (encrypting under
    // G's epoch rotated past A, not A's), delete base G, open = rebuild; peer 3 had A's commit
    // applied valid first (Y: a reader of G). The mint admin's own grant then gives T secrets of its own everywhere.
    #[test]
    fn keyset_of_invalid_rotation_leaves_thing_dependent_spec_crypto_3() {
        let mut lp = LocalPeer::fresh(4, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (me, a, x) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
        let y = tid(&mut lp, 3);
        lp.peers[0].engine.grant(&g, &y, &edge(Role::Read)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { holder: a, new: None, retain: None }).unwrap();
        // A's clock runs ahead: its grant is stamped after its removal
        lp.peers[1].clock.advance(120_000);
        lp.peers[1].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        let rot = lp.peers[1].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        assert!(lp.peers[1].engine.core.ix.independent.contains(&t));
        lp.sync(1, 3).unwrap();
        assert!(lp.peers[3].engine.core.ix.independent.contains(&t), "applied valid at peer 3");
        lp.sync_all().unwrap();
        let derived = |lp: &LocalPeer, i: usize| {
            let core = &lp.peers[i].engine.core;
            osis_keys::ActorEpochs::derived(&core.epochs(&g).unwrap(), &t).role(Role::Read).newest()
        };
        for i in 0..4 {
            let core = &lp.peers[i].engine.core;
            assert!(!core.ix.independent.contains(&t), "peer {i}: dependent again");
            assert!(!core.is_independent(&t), "peer {i}");
            let held = core.epochs(&t).unwrap_or_default();
            // X holds nothing of G
            if i != 2 {
                assert_eq!(held.role(Role::Read).newest(), derived(&lp, i), "peer {i}: derived from G");
                assert_ne!(held.role(Role::Read).newest(), Some(rot), "peer {i}");
            }
            assert!(!held.role(Role::Read).is_established(&rot), "peer {i}: A's epoch is for reading only");
            assert!(matches!(core.delete_base(&t), Some(crate::engine::secrets::DeleteBase::Actor(b, _)) if b == g), "peer {i}: delete base G");
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
        // the mint admin's grant: secrets of T's own, from G's derived epochs
        lp.peers[0].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let own = lp.peers[0].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        assert_ne!(own, rot);
        for i in 0..4 {
            let core = &lp.peers[i].engine.core;
            assert!(core.ix.independent.contains(&t), "peer {i}: independent");
            if i != 1 {
                assert_eq!(core.epochs(&t).unwrap().role(Role::Read).newest(), Some(own), "peer {i}");
            }
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
    }

    // spec/crypto.md §4 (Established: derived from an established epoch of the mint admin):
    // establishment is a function of the held commits, so reopen equals rebuild. B opens T's
    // epoch derived from G's e1 (T's first rotation's history box) while e1 is not established
    // (its rotation names C's self-removal, not held); once C's commit arrives, e1 and the
    // derived epoch are established, though nothing of T arrived again.
    #[test]
    fn derived_epoch_follows_base_establishment_spec_crypto_4() {
        let mut lp = LocalPeer::fresh(3, WallMs(1_700_000_000_000));
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.me();
        let (me, b, c) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let edge = |role| ct::Edge { role, until: None, invite: None, retain: false, floor: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &b, &edge(Role::Read)).unwrap();
        lp.peers[0].engine.grant(&g, &c, &edge(Role::Read)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        let before: std::collections::BTreeSet<CommitId> = lp.peers[2].engine.commit_ids().into_iter().collect();
        lp.peers[2].engine.demote(&g, &Demotion { holder: c, new: None, retain: None }).unwrap();
        let leave: Vec<CommitId> = lp.peers[2].engine.commit_ids().into_iter().filter(|x| !before.contains(x)).collect();
        send(&mut lp, 2, 0, &leave);
        lp.peers[0].engine.ensure_rotated(&g).unwrap();
        let e1 = lp.peers[0].engine.core.epochs(&g).unwrap().read.newest().unwrap();
        let d1 = osis_keys::ActorEpochs::derived(&lp.peers[0].engine.core.epochs(&g).unwrap(), &t).read.newest().unwrap();
        lp.peers[0].engine.grant(&t, &b, &edge(Role::Read)).unwrap();
        let rest: Vec<CommitId> = lp.peers[0].engine.commit_ids().into_iter().filter(|x| !leave.contains(x)).collect();
        send(&mut lp, 0, 1, &rest);
        let at_b = |lp: &LocalPeer| (lp.peers[1].engine.core.epochs(&g).unwrap(), lp.peers[1].engine.core.epochs(&t).unwrap());
        let (gb, tb) = at_b(&lp);
        assert!(gb.read.secret(&e1).is_some() && !gb.read.is_established(&e1), "e1 held, its names unmet");
        assert!(tb.read.secret(&d1).is_some() && !tb.read.is_established(&d1), "derived epoch held, not established");
        send(&mut lp, 2, 1, &leave);
        let (gb, tb) = at_b(&lp);
        assert!(gb.read.is_established(&e1));
        assert!(tb.read.is_established(&d1), "follows e1");
        lp.peers[1].engine.rebuild_index().unwrap();
        assert_eq!(at_b(&lp), (gb, tb), "rebuild = live");
    }

}
