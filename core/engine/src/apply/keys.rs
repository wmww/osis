//! What establishment (spec/crypto.md §4) is computed from: a held valid role commit's
//! `secrets.0` write is recorded with its `keys.0` write (`SecretsWrite::rotated`); a held
//! `secrets.0` compaction snapshot keys its epochs (`snapshot_keyed`); a commit later found
//! invalid no longer counts, valid again is recorded again. `Core::own_epochs` establishes from
//! these and the held commits (the names).

use crate::engine::{Core, KeysetRec, Tx};
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
        core.ix.boxes_to.insert(bk.holder, (*actor, k.clone()));
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
        out.extend(keyset_recs(b));
    }
    out.into_iter().collect()
}

/// Each keyset a `keys.0` body writes: its role, epoch, listed epochs, KEM key (suite 1),
/// possession key and names digest.
fn keyset_recs(body: &Fragment) -> Vec<KeysetRec> {
    keys_write(body)
        .keysets
        .into_iter()
        .filter_map(|(role, ks)| {
            let epoch = osis_keys::aspects::from_schema(&ks.epoch).ok()?;
            let lists = ks.supersedes.iter().filter_map(|x| osis_keys::aspects::from_schema(x).ok()).collect();
            let ct::KemKey::X25519MlKem768(b) = ks.kem_key;
            let kem = (ks.suite == osis_keys::SUITE && osis_crypto::KemPublicKey::from_slice(&b).is_ok()).then_some(b);
            let ct::SigningKey::Ed25519(p) = ks.possession_key;
            let possession = <[u8; 32]>::try_from(p.as_slice()).ok().filter(|p| osis_crypto::VerifyingKey::from_bytes(p).is_ok());
            Some(KeysetRec { role, epoch, lists, kem, possession, names: ks.names })
        })
        .collect()
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
    let mut gone: std::collections::BTreeSet<(Tid, Value)> = bodies.iter().flat_map(written_boxes).map(|(bk, k)| (bk.holder, k.clone())).collect();
    let ids: Vec<CommitId> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let Some(xi) = m.aspect(&a.tid, &a.ak) else { continue };
        if m.header.kind != Kind::Role {
            continue;
        }
        if let Some(Decoded::Delta(d)) = super::held_part(tx, &id, xi)? {
            for (bk, k) in written_boxes(&d.fragment) {
                gone.remove(&(bk.holder, k.clone()));
            }
        }
    }
    for (m, k) in gone {
        tx.core.ix.boxes_to.remove(&m, &(a.tid, k));
    }
    Ok(())
}

/// Notes the keysets a valid `keys.0` body of `actor` writes (`keyset_recs`, or a dropped part's
/// record): each is a held valid keyset (`keysets`); a role
/// commit's also record the commit as the epoch's introduction if earliest: a rotation writes
/// the rotated roles' keysets, nothing else does, so the epoch's introducer
/// (`Core::epoch_intro`) is its rotation commit, or unknown while that `keys.0` part is not held
/// (synced after a compaction, or missing again after `retention::uncover`).
pub(crate) fn note_keysets(core: &mut Core, h: &Header, actor: &Tid, keysets: &[KeysetRec]) {
    for k in keysets {
        if h.kind == Kind::Role {
            note_intro(core, h, actor, k.role, k.epoch);
        }
        let key = (*actor, k.role, k.epoch);
        let mut held = core.ix.keysets.get(&key).cloned().unwrap_or_default();
        let before = held.clone();
        held.lists.extend(k.lists.iter().copied());
        if held.kem.is_none() {
            held.kem = k.kem.clone();
        }
        held.possession.extend(k.possession);
        held.names.insert((k.names, h.author));
        if held != before || !core.ix.keysets.contains_key(&key) {
            core.ix.keysets.insert(key, held);
            core.touch();
            keyset_changed(core, actor);
        }
    }
}

/// A held valid keyset of `actor` changed: possession (`validity::possessed`) is judged again for
/// the `secrets.0` parts of what boxes it (`boxes_to`) and of what it holds a role on or is first admin of
/// (their commits only: a thing's other deltas do not depend on it).
fn keyset_changed(core: &mut Core, actor: &Tid) {
    let mut things: std::collections::BTreeSet<Tid> = core.ix.boxes_to.get(actor).into_iter().flatten().map(|x| x.0).collect();
    things.extend(core.ix.held.first_admin_of(actor).copied());
    if let Some(tl) = core.timelines.get(actor) {
        things.extend(tl.edges_at(None).targets(actor).copied());
    }
    let Ok(ak) = osis_base::Ak::new("secrets.0") else { return };
    for t in things {
        let ids: Vec<CommitId> = core.ix.by_aspect.get(&(t, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
        core.stale_commits.extend(ids);
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
        keyset_changed(tx.core, a);
        let held: Vec<(Role, osis_crypto::Epoch)> = tx.core.keysets_of(a).map(|x| (x.0, x.1)).collect();
        for (r, e) in held {
            tx.core.ix.keysets.remove(&(*a, r, e));
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
            if let Some(d) = m.dropped.get(&ai) {
                note_keysets(tx.core, &m.header, a, &d.keysets);
            }
            if let Some(d) = super::held_part(tx, &id, ai)? {
                note_keysets(tx.core, &m.header, a, &keyset_recs(d.fragment()));
            }
        }
    }
    tx.core.role_changed();
    Ok(())
}

/// Notes the `keys.0` parts of role commit `h` whose bodies write a keyset, whatever their
/// validity (`records::OWN_KEYS`: a fact of the body, kept once it drops or goes missing), then
/// re-derives `own_keys` of their things.
fn note_keyset_parts(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)]) -> Result<()> {
    if !h.kind.is_role() {
        return Ok(());
    }
    let id = h.id();
    let mut things = std::collections::BTreeSet::new();
    for (ai, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "keys.0" || keys_write(d.fragment()).keysets.is_empty() {
            continue;
        }
        if tx.core.ix.keyset_parts.insert(a.tid, id) {
            tx.core.touch();
            tx.txn.put_local(&crate::engine::records::own_keys_key(&a.tid, &id), &[], Shred::No)?;
        }
        things.insert(a.tid);
    }
    refresh_own_keys(tx, &things, true)
}

/// Re-derives whether each of `things` has secrets of its own (spec/crypto.md §3): a held
/// commit's valid `keys.0` part wrote a keyset in its body (held, or dropped or missing since).
/// Called once a part is noted, after validity flips and at load (`!regain`). A thing that loses
/// it (that commit turned invalid) derives from its base actor again; what it learned stays for
/// reading (`Core::epochs`). One that regains it starts its epochs again from those.
pub(crate) fn refresh_own_keys(tx: &mut Tx<'_>, things: &std::collections::BTreeSet<Tid>, regain: bool) -> Result<()> {
    for t in things {
        let ids: Vec<CommitId> = tx.core.ix.keyset_parts.get(t).into_iter().flatten().copied().collect();
        let mut own = false;
        for id in ids {
            let Some(m) = tx.core.ix.commits.get(&id) else {
                // forgotten
                tx.core.touch();
                tx.core.ix.keyset_parts.remove(t, &id);
                tx.txn.remove_local(&crate::engine::records::own_keys_key(t, &id), Shred::No)?;
                continue;
            };
            own |= m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid == *t && a.ak.as_str() == "keys.0" && m.valid_at(ai));
        }
        if own == tx.core.ix.own_keys.contains(t) {
            continue;
        }
        tx.core.touch();
        if own {
            // epochs kept from a rotation found invalid earlier: start again from the derived
            // ones (`Core::epochs`), so a stale derived epoch stays current nowhere
            let derived = |e: &osis_keys::ActorEpochs| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.established == Some(osis_keys::Provenance::Derived)));
            let restart = regain && tx.core.ix.secrets.get(t).is_some_and(derived) && tx.core.own_record(t).is_none();
            let base = restart.then(|| tx.core.epochs(t)).flatten();
            tx.core.ix.own_keys.insert(*t);
            if let Some(b) = base {
                tx.core.ix.secrets.insert(*t, b.into_record());
                save(tx, t)?;
            }
        } else {
            tx.core.ix.own_keys.remove(t);
        }
        // reader actors of things below it change
        tx.core.bodies.clear();
        tx.core.role_changed();
    }
    Ok(())
}

pub(crate) fn note_intro(core: &mut Core, h: &Header, actor: &Tid, r: Role, e: osis_crypto::Epoch) {
    let v = (h.ts, h.id());
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

/// Brings `read`, `secrets.0` as decoded before `delta` joined into `state`, up to date: the
/// delta's keys alone read again, O(log n) each. False when it resets more than its entries or
/// a key does not read as one value here: decode.
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
    for (_, _, k, _) in map(field(delta, 0)).into_iter().flat_map(|m| m.entries()) {
        let Some(raw) = k else { return false };
        let Some(key) = typed(raw, "box_key").and_then(|k| BoxKey::from_value(&k).ok()) else { return false };
        match one(map(field(state, 0)), raw) {
            Some(None) => {
                read.boxes.remove(&key);
            }
            Some(Some(v)) => {
                let Some(b) = typed(&v, "box").and_then(|b| SecretBox::from_value(&b).ok()) else { return false };
                read.boxes.insert(key, b);
            }
            None => return false,
        }
    }
    for (_, _, k, _) in map(field(delta, 1)).into_iter().flat_map(|m| m.entries()) {
        let Some(raw) = k else { return false };
        let Some(key) = typed(raw, "history_key").and_then(|k| HistoryKey::from_value(&k).ok()) else { return false };
        match one(map(field(state, 1)), raw) {
            Some(None) => {
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
    for (id, r) in [(0, Role::Read), (1, Role::Write), (2, Role::Admin)] {
        if let Some(v) = field(delta, id).and_then(Fragment::read)
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

pub(crate) fn before_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)], valid: &[bool]) -> Result<Vec<Pending>> {
    note_keyset_parts(tx, h, parts)?;
    let mut out = Vec::new();
    for (ai, d) in parts {
        if let Some(a) = h.aspects.get(*ai)
            && a.ak.as_str() == "keys.0"
            && valid.get(*ai).copied().unwrap_or(false)
        {
            note_keysets(tx.core, h, &a.tid, &keyset_recs(d.fragment()));
        }
    }
    if h.kind != Kind::Role {
        return Ok(out);
    }
    for (ai, d) in parts {
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
        let keys = parts
            .iter()
            .find_map(|(x, k)| match (h.aspects.get(*x), k) {
                (Some(b), Decoded::Delta(k)) if b.tid == a.tid && b.ak.as_str() == "keys.0" => Some(keys_write(&k.fragment)),
                _ => None,
            })
            .unwrap_or_default();
        out.push(Pending { id: h.id(), ai: *ai, actor: a.tid, keys });
    }
    Ok(out)
}

fn save(tx: &mut Tx<'_>, actor: &Tid) -> Result<()> {
    tx.core.role_changed();
    tx.core.waits.secrets_changed(actor);
    if let Some(e) = tx.core.ix.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
    }
    Ok(())
}

/// After the joins: the applied rotations, and `secrets.0` compaction snapshots held.
pub(crate) fn after_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, Decoded)], valid: &[bool], pending: Vec<Pending>) -> Result<()> {
    tx.core.touch();
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
        let e = tx.core.ix.secrets.entry_or_default(actor);
        let before = e.clone();
        let _ = w.rotated(e, p.id, &p.keys);
        if *e != before {
            save(tx, &actor)?;
        }
    }
    if h.kind == Kind::RoleSnapshot {
        for (ai, d) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            if a.ak.as_str() != "secrets.0" || !valid.get(*ai).copied().unwrap_or(false) {
                continue;
            }
            let Decoded::Snapshot(s) = d else { continue };
            let Some(sv) = s.fragment.read().and_then(|v| crate::engine::secrets::secrets_value(&v)) else { continue };
            let e = tx.core.ix.secrets.entry_or_default(a.tid);
            if osis_keys::snapshot_keyed(&sv, e).unwrap_or(false) {
                save(tx, &a.tid)?;
            }
        }
    }
    Ok(())
}

/// A held commit's `secrets.0` delta became invalid: its rotations no longer count (another valid
/// rotation commit of the same epoch keeps it).
pub(crate) fn invalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.header.aspects.get(ai)).cloned() else { return Ok(()) };
    if a.ak.as_str() != "secrets.0" {
        return Ok(());
    }
    tx.core.touch();
    if let Some(e) = tx.core.ix.secrets.get_mut(&a.tid) {
        e.invalidate(c);
    }
    save(tx, &a.tid)
}

/// The `secrets.0` compaction gate (spec/crypto.md §4).
pub(crate) fn may_compact(core: &Core, actor: &Tid, state: &Fragment) -> bool {
    let Some(s) = state.read().and_then(|v| crate::engine::secrets::secrets_value(&v)) else { return false };
    let e = core.epochs(actor).unwrap_or_default();
    osis_keys::may_compact_secrets(&s, &e).unwrap_or(false)
}

/// A held commit's `secrets.0` delta became valid again (re-grant): applied as received.
pub(crate) fn revalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai).cloned() else { return Ok(()) };
    let mut secrets = SecretsWrite::default();
    if let Some(Decoded::Delta(d)) = super::held_part(tx, c, ai)? {
        secrets.extend(secrets_write(&d.fragment));
    }
    let mut keys = KeysWrite::default();
    if let Some(ki) = h.aspects.iter().position(|x| x.tid == a.tid && x.ak.as_str() == "keys.0")
        && let Some(Decoded::Delta(d)) = super::held_part(tx, c, ki)?
    {
        keys = keys_write(&d.fragment);
    }
    tx.core.touch();
    let e = tx.core.ix.secrets.entry_or_default(a.tid);
    let before = e.clone();
    let _ = secrets.rotated(e, *c, &keys);
    if *e != before {
        save(tx, &a.tid)?;
    }
    Ok(())
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
/// target's `created.0` and chain can open the target's label and download them. Parts are
/// decoded unverified, so what they yield is reading-only: never encrypted under, and replaced
/// by an applied valid box (spec/crypto.md §4).
pub(crate) fn read_pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<()> {
    for (a, s, from) in pending_boxes(tx, blob, id)? {
        tx.core.touch();
        if tx.core.ingest_secrets(&a, &s, Some(from), &osis_keys::HistoryAlts::new()) {
            crate::flows::save_epochs(tx, &a)?;
        } else if tx.core.reading_full(&a) {
            tx.core.waits.box_refused(*id);
        }
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
        let author = if tx.core.created(&blob.header.author).is_some() { blob.header.author } else { osis_keys::UNKNOWN_AUTHOR };
        out.push((a, ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() }, osis_keys::Unchecked { author, commit: *id }));
    }
    Ok(out)
}

/// Drops the reading-only secrets pending commit `id` gave: it applied (its boxes are checked
/// now, or stripped as invalid) or was dropped (spec/crypto.md §4). An actor they were the only
/// secrets of is left to the lost-access trigger, which drops them with what they read.
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
    let actors: Vec<Tid> = tx.core.ix.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.reading.iter().any(|u| u.commit == *id)))).map(|(t, _)| *t).collect();
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
        crate::flows::save_epochs(tx, &a)?;
    }
    crate::rotation::mark_lost_due(tx, lost)
}

/// The holders a held, not applied role commit's `roles.0` parts on `on` put an edge
/// for, decoded unverified.
pub(crate) fn pending_grantees(blob: &osis_commit::CommitBlob, id: &CommitId, on: &Tid) -> Vec<Tid> {
    let h = &blob.header;
    let mut out = Vec::new();
    if !h.kind.is_role() || !h.is_resolved() {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in &blob.parts {
        if h.aspects.get(p.ai).is_none_or(|a| a.ak.as_str() != "roles.0" || a.tid != *on) {
            continue;
        }
        let Ok(cx) = osis_commit::delta_ctx(h, id, p.ai, &mut interner) else { continue };
        let Ok(d) = osis_crdt::decode_delta(&p.delta, &cx, &mut interner, None) else { continue };
        let Some(m) = map(Some(&d.fragment)) else { continue };
        for (_, _, k, f) in m.entries() {
            if let (Some(Value::Tid(t)), Some(_)) = (k, f.and_then(Fragment::read)) {
                out.push(*t);
            }
        }
    }
    out
}

/// The `secrets.0` writes of a held, not applied role commit, per actor, decoded
/// unverified (what `read_pending_boxes` reads; the lost-access trigger's pending grants).
pub(crate) fn pending_secrets_writes(blob: &osis_commit::CommitBlob, id: &CommitId) -> Vec<(Tid, SecretsWrite)> {
    let h = &blob.header;
    let mut out = Vec::new();
    if !h.kind.is_role() || !h.is_resolved() {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai) else { continue };
        if a.ak.as_str() != "secrets.0" {
            continue;
        }
        let Ok(cx) = osis_commit::delta_ctx(h, id, p.ai, &mut interner) else { continue };
        let Ok(d) = osis_crdt::decode_delta(&p.delta, &cx, &mut interner, None) else { continue };
        out.push((a.tid, secrets_write(&d.fragment)));
    }
    out
}

impl crate::engine::Engine {
    /// Records a read secret learned from a label's entry box (a recovery or link key opening
    /// by static entry, spec/sync.md §2) when it is the secret of epoch `e` of `g` (spec/crypto.md
    /// §4; anyone holding the head's step key, a removed admin among them, can write the box, so
    /// it establishes nothing). False when it is not.
    pub fn learn_read_secret(&mut self, g: &Tid, e: osis_crypto::Epoch, secret: osis_crypto::Secret32) -> Result<bool> {
        if !e.names(g, Role::Read, &secret) {
            return Ok(false);
        }
        let g = *g;
        self.run(|tx| {
            tx.core.touch();
            tx.core.ix.secrets.entry_or_default(g).role_mut(Role::Read).set_secret(e, secret);
            crate::flows::save_epochs(tx, &g)?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use crate::flows::{Delivery, Demotion, Done, PreSync};

    /// A thing whose first admin is `admin`, made by peer `i`.
    fn thing_of(lp: &mut LocalPeer, i: usize, admin: Tid) -> Tid {
        let e = &mut lp.peers[i].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, admin);
        m.set(t, &osis_base::Ak::new("x:reg.0").unwrap(), &Value::Str("new".into())).unwrap();
        e.commit(m).unwrap().unwrap();
        t
    }

    /// Every peer's commits to every other peer, twice.
    fn spread(lp: &mut LocalPeer) {
        let n = lp.peers.len();
        for _ in 0..2 {
            for a in 0..n {
                let ids = lp.peers[a].engine.commit_ids();
                for b in (0..n).filter(|b| *b != a) {
                    send(lp, a, b, &ids);
                }
            }
        }
    }

    fn send(lp: &mut LocalPeer, from: usize, to: usize, ids: &[CommitId]) {
        for id in ids {
            let pk = lp.peers[from].engine.package(id).unwrap().unwrap();
            lp.deliver(to, &pk).unwrap();
        }
    }

    /// A flow's direct sends and inbox blobs to the peers.
    fn carry(lp: &mut LocalPeer, from: usize, done: &Done) {
        for d in &done.deliveries {
            match d {
                Delivery::Direct { to, commits } => {
                    if let Some(i) = lp.peers.iter().position(|p| p.engine.tid() == *to) {
                        send(lp, from, i, commits);
                    }
                }
                Delivery::Inbox { blob, .. } => {
                    for i in (0..lp.peers.len()).filter(|i| *i != from) {
                        let _ = lp.peers[i].engine.accept_inbox(blob);
                    }
                }
                _ => {}
            }
        }
    }

    // spec/crypto.md §4 (opening `secrets.0`; reading-only secrets of unchecked boxes; history
    // keys with several live entries): random grants, demotions and rotations by several admins,
    // carried by inbox blobs (pending until their chain arrives) and partial deliveries. Every
    // per-entry ingestion of a `secrets.0` change is checked against ingesting the whole state
    // (the engine fails the operation where the whole state teaches more).
    #[test]
    fn per_entry_secrets_ingestion_equals_whole_state_spec_crypto_4() {
        let hosts = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        for seed in 0..4u64 {
            let mut lp = LocalPeer::new(4, 530 + seed, WallMs(1_700_000_000_000)).unwrap();
            let ps: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.create_person(&hosts).unwrap().0.person).collect();
            spread(&mut lp);
            for p in &mut lp.peers {
                p.engine.core.check_ingest = true;
            }
            let t = thing_of(&mut lp, 0, ps[0]);
            let mut rng = osis_crypto::SeededRng::from_u64(seed);
            let mut r = |n: u64| osis_crypto::RngCore::next_u64(&mut rng) % n;
            let roles = [Role::Read, Role::Write, Role::Admin];
            for _ in 0..14 {
                lp.advance(1000);
                let by = r(4) as usize;
                let holder = ps[1 + r(3) as usize];
                let done = match r(5) {
                    0 | 1 => lp.peers[by].engine.grant(&t, &holder, &edge(roles[r(3) as usize])),
                    2 => lp.peers[by].engine.demote(&t, &Demotion { holder, new: None, presync: PreSync::Synced, retain: None }),
                    3 => lp.peers[by].engine.demote(&t, &Demotion { holder, new: Some(edge(Role::Read)), presync: PreSync::Synced, retain: None }),
                    _ => lp.peers[by].engine.ensure_rotated(&t).map(|x| x.0),
                };
                match done {
                    Ok(d) => carry(&mut lp, by, &d),
                    Err(e) => assert!(!format!("{e}").contains("secrets.0 ingestion"), "seed {seed}: {e}"),
                }
                if r(3) == 0 {
                    spread(&mut lp);
                } else {
                    let (a, b) = (r(4) as usize, r(4) as usize);
                    if a != b {
                        let ids = lp.peers[a].engine.commit_ids();
                        send(&mut lp, a, b, &ids);
                    }
                }
            }
            spread(&mut lp);
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
    #[test]
    fn reading_only_actors_capped_spec_crypto_4() {
        let mut lp = LocalPeer::new(3, 907, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let (b, c) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid());
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let g1 = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let g2 = *lp.peers[0].engine.grant(&t, &c, &edge).unwrap().commits.last().unwrap();
        let (p1, p2) = (lp.peers[0].engine.package(&g1).unwrap().unwrap(), lp.peers[0].engine.package(&g2).unwrap().unwrap());
        for n in 0..MAX_READING_ACTORS {
            let n = u8::try_from(n).unwrap();
            lp.peers[1].engine.core.ix.secrets.insert(Tid::from_bytes([n; 15]), reading_only(n, CommitId([n; 32])));
        }
        // pending (the thing's `created.0` is not held): its boxes are read only under the cap
        lp.deliver(1, &p1).unwrap();
        lp.deliver(2, &p2).unwrap();
        assert!(!lp.peers[2].engine.pending().is_empty());
        let held = |lp: &LocalPeer, i: usize| lp.peers[i].engine.core.ix.secrets.get(&t).is_some_and(|e| e.read.holds_any());
        assert!(held(&lp, 2), "under the cap: read");
        assert!(!held(&lp, 1), "at the cap: not read");
    }

    // spec/crypto.md §4: a genuine grant past the cap reads its boxes once an applied one frees a
    // place, or it waits for good on the label those secrets open.
    #[test]
    fn refused_boxes_read_when_a_grant_applies_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 908, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let thing = |lp: &mut LocalPeer| {
            let mut m = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut m, me);
            m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
            let c = lp.peers[0].commit(m).unwrap().unwrap();
            (t, c)
        };
        let ((t1, c1), (t2, _)) = (thing(&mut lp), thing(&mut lp));
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let g1 = *lp.peers[0].engine.grant(&t1, &b, &edge).unwrap().commits.last().unwrap();
        let g2 = *lp.peers[0].engine.grant(&t2, &b, &edge).unwrap().commits.last().unwrap();
        let (p1, p2) = (lp.peers[0].engine.package(&g1).unwrap().unwrap(), lp.peers[0].engine.package(&g2).unwrap().unwrap());
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
        lp.peers[1].engine.reexamine().unwrap();
        assert!(!lp.peers[1].engine.pending().iter().any(|(c, _)| *c == g1), "applied");
        assert!(held(&lp, &t2), "read once a place is free");
    }

    // spec/crypto.md §4 (pending boxes are read for reading only), apply::waits: what a pending
    // commit's boxes teach depends only on what its wait follows. Here the grant on `a` (first
    // admin `u`, whose epochs the grantee holds) waits for `a`'s record; that record arriving as
    // memory class, or `u`'s establishment changing (computed from applied commits and roles), wakes
    // no wait, so reading the boxes again must give nothing new: no derived establishment from `u`.
    #[test]
    fn pending_boxes_read_no_chain_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 909, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let mut m = Mutation::new();
        let u = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(u, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        lp.peers[0].engine.grant(&u, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        assert!(lp.peers[1].engine.core.epochs(&u).is_some_and(|e| !e.read.current().is_empty()), "the grantee holds u's established epochs");
        let mut m = Mutation::new();
        let a = lp.peers[0].engine.new_thing(&mut m, u);
        m.set(a, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(2)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let g = *lp.peers[0].engine.grant(&a, &b, &edge).unwrap().commits.last().unwrap();
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        lp.deliver(1, &p).unwrap();
        assert!(lp.peers[1].engine.pending().iter().any(|(c, _)| *c == g), "waits for a's record");
        let rec = lp.peers[0].engine.core.created(&a).unwrap().clone();
        lp.peers[1].engine.core.ix.held.create_memory(rec);
        lp.peers[1].engine.check_unchanged(&[]);
    }

    /// Peer 0 is first admin of thing `t` (`x:a.0` = 1); peer 1 is the grantee, holding nothing of peer 0;
    /// peers 2.. are throwaway authors unknown to the grantee.
    fn grantee_world(seed: u64, n: usize) -> (LocalPeer, Tid) {
        let mut lp = LocalPeer::new(n, seed, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        // the granter holds the grantee's keys
        lp.sync(1, 0).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        (lp, t)
    }

    /// Floods the grantee (peer 1) with `per` bogus pending commits from each throwaway author
    /// (peers 2..): each boxes it a fresh read secret of `t` at a fresh epoch, built past the
    /// writer rules. Returns how many it delivered.
    fn flood(lp: &mut LocalPeer, t: Tid, per: usize) -> usize {
        let b = lp.peers[1].engine.tid();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let mut sent = 0;
        for x in 2..lp.peers.len() {
            for i in 0..per {
                let mut held = ActorEpochs::default();
                held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
                let rcpt = osis_keys::Recipient { holder: b, role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem: kem.clone(), seed: None } };
                let mut rng = osis_crypto::SeededRng::from_u64((x * 10_000 + i) as u64);
                let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut rng).unwrap();
                let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
                let bytes = forge_role_commit(lp, x, t, &rec, &v);
                assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)), "a bogus commit pends at the grantee");
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
            // made-up delete keys (hosts' business)
            fn admin_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([3; 32])).verifying_key())
            }
            fn chain_key(&self) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([1; 32])).verifying_key())
            }
            fn write_key(&self, _: &Tid) -> Option<osis_crypto::VerifyingKey> {
                Some(osis_crypto::DeleteSecret::derive(&Secret32::from_bytes([2; 32])).verifying_key())
            }
        }
        let ak = osis_base::Ak::new("secrets.0").unwrap();
        let author = lp.peers[by].engine.tid();
        lp.peers[by].clock.advance(1);
        let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
        let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
        let mut w = Writer::new(ts, Source::commit(CommitId([0; 32])), 1);
        let f = create(&mut w, &view, v).unwrap();
        let r = w.range();
        let cx = writer_ctx(Form::Commit, Kind::Role, ts, author, r.lo, r.hi);
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
        let mut cb = CommitBuilder::new(Kind::Role, ts, author, author, Form::Commit);
        let mut aw = AspectWrite::new(t, ak.clone(), r.lo, r.hi, bytes.clone());
        aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
        cb.aspects.push(aw);
        cb.build(&lp.peers[by].engine.identity().keys().signing, &Dedup(rec.clone()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
    }

    /// Puts peer `by`'s clock past the drift bound of peer 1's, so its next commit pends at peer 1
    /// (spec/commits.md §4): with its author and thing known nothing else keeps a role commit's
    /// only part pending, and `pending_for_good` keeps it there as the clock catches up.
    fn ahead_of_drift(lp: &mut LocalPeer, by: usize) {
        lp.peers[by].clock.advance(2 * osis_base::format::MAX_DRIFT_MS);
    }

    /// Peer 1's clock catches up with peer `by`'s and it stops examining what pends.
    fn pending_for_good(lp: &mut LocalPeer, by: usize) {
        let now = lp.peers[by].engine.now();
        lp.peers[1].clock.set(now);
        lp.peers[1].engine.freeze_pending();
    }

    /// A pending commit by peer `by` boxing peer 1 a fresh read secret of `t`.
    fn forged_grant(lp: &mut LocalPeer, by: usize, t: Tid, seed: u64) {
        let b = lp.peers[1].engine.tid();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let mut held = ActorEpochs::default();
        held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
        let rcpt = osis_keys::Recipient { holder: b, role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem, seed: None } };
        let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(seed)).unwrap();
        let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
        let bytes = forge_role_commit(lp, by, t, &rec, &v);
        assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)));
    }

    /// Peer 1 reads `t` (checked secrets), then is removed by peer 0; the removal applied.
    fn removed_reader(seed: u64) -> (LocalPeer, Tid) {
        let (mut lp, t) = grantee_world(seed, 3);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), Some(Value::Int(1)));
        (lp, t)
    }

    // spec/crypto.md §4, spec/sync.md §2: a read secret from a label's entry box (written by
    // whoever holds the head's step key: a removed admin before the remover re-registers) is
    // held only when it is the secret of the epoch it names; it establishes nothing, so the
    // node encrypts under it once the epoch's rotation commit applies.
    #[test]
    fn entry_box_secret_checked_spec_crypto_4() {
        let (mut lp, t) = removed_reader(931);
        let c = lp.peers[2].engine.tid();
        lp.sync(2, 0).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &c, &edge).unwrap();
        let before = lp.peers[0].engine.epochs(&t).unwrap().read.newest().unwrap();
        lp.peers[0].engine.demote(&t, &Demotion { holder: c, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        let e0 = lp.peers[0].engine.epochs(&t).unwrap();
        let e_new = e0.read.newest().unwrap();
        assert_ne!(e_new, before, "the removal rotated");
        let genuine = e0.read.secret(&e_new).cloned().unwrap();
        let planted = Secret32::from_bytes([0x66; 32]);
        assert!(!lp.peers[1].engine.learn_read_secret(&t, e_new, planted.clone()).unwrap(), "a secret of another epoch");
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert!(e1.read.reading_secret(&e_new).is_none());
        assert!(lp.peers[1].engine.learn_read_secret(&t, e_new, genuine.clone()).unwrap());
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
            let mut lp = LocalPeer::new(4, 941, WallMs(1_700_000_000_000)).unwrap();
            lp.sync_all().unwrap();
            let me = lp.peers[0].engine.tid();
            let (w, d, m) = (lp.peers[1].engine.tid(), lp.peers[2].engine.tid(), lp.peers[3].engine.tid());
            let mut mu = Mutation::new();
            let t = lp.peers[0].engine.new_thing(&mut mu, me);
            mu.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &Value::Int(1)).unwrap();
            lp.peers[0].commit(mu).unwrap();
            let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
            lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.demote(&t, &Demotion { holder: m, new: None, presync: PreSync::Synced, retain: None }).unwrap();
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
        let b = lp.peers[1].engine.tid();
        lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        lp.sync(0, 1).unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), None);
    }

    // spec/permissions.md §3 (a node that lost read access drops those secrets),
    // spec/requirements.md Deletion: a pending commit boxing the removed node, by an author with
    // no right to grant on the thing, keeps nothing: it is held until it applies, so it would
    // keep the secrets for good.
    #[test]
    fn strangers_pending_box_keeps_no_lost_secrets_spec_perm_3() {
        let (mut lp, t) = removed_reader(911);
        forged_grant(&mut lp, 2, t, 1);
        remove(&mut lp, t);
        assert!(lp.peers[1].engine.drop_lost_due().unwrap().contains(&t));
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none());
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), None);
    }

    // spec/permissions.md §3: a pending grant by an admin of the thing keeps the removed node's
    // secrets (it may yet read again), for a bounded time after its `ts` only.
    #[test]
    fn admins_pending_grant_keeps_lost_secrets_for_a_while_spec_perm_3() {
        let (mut lp, t) = removed_reader(912);
        remove(&mut lp, t);
        ahead_of_drift(&mut lp, 0);
        forged_grant(&mut lp, 0, t, 2);
        pending_for_good(&mut lp, 0);
        assert!(lp.peers[1].engine.drop_lost_due().unwrap().is_empty());
        assert!(lp.peers[1].engine.drop_lost_secrets().unwrap().is_empty());
        lp.peers[1].clock.advance(2 * crate::rotation::PENDING_GRANT_WAIT_MS);
        assert!(lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&t));
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none());
        // the grant itself keeps its boxes: it may still apply
        let (id, _) = lp.peers[1].engine.pending().into_iter().next().unwrap();
        assert_eq!(secrets_parts(&mut lp, &id, t), 1);
    }

    // spec/permissions.md §3: a pending grant from before the removal boxes only an epoch the
    // node held: applied, it would give no role, so forgetting shreds its boxes with the secrets
    // (kept, a device compromised later would open the lost secrets from them).
    #[test]
    fn stale_grant_loses_its_boxes_spec_perm_3() {
        let (mut lp, t) = removed_reader(915);
        let b = lp.peers[1].engine.tid();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let epochs = lp.peers[0].engine.epochs(&t).unwrap();
        let secrets = lp.peers[0].engine.get_typed(&t, &ct::SECRETS).unwrap().unwrap();
        let rcpt = osis_keys::Recipient { holder: b, role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem, seed: None } };
        let w = osis_keys::box_holder(&t, &epochs, &secrets, &rcpt, &[Role::Read].into(), &mut osis_crypto::SeededRng::from_u64(3)).unwrap().unwrap();
        let v = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() }.to_value();
        // boxes made before the removal: only the epoch held then
        remove(&mut lp, t);
        ahead_of_drift(&mut lp, 0);
        let bytes = forge_role_commit(&mut lp, 0, t, &rec, &v);
        assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)));
        pending_for_good(&mut lp, 0);
        lp.peers[1].clock.advance(2 * crate::rotation::PENDING_GRANT_WAIT_MS);
        assert!(lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&t));
        let id = osis_commit::CommitBlob::decode(&bytes).unwrap().id();
        assert_eq!(secrets_parts(&mut lp, &id, t), 0, "a held epoch's box goes");
    }

    // spec/permissions.md §3 (a deposit-only step waits for a pending `keys.0` write): only one
    // signed by an admin of the actor counts; one whose author nobody can check (anyone can send
    // it) would hold the step back for good.
    #[test]
    fn keys_write_pending_needs_an_admin_spec_perm_3() {
        let (mut lp, t) = removed_reader(916);
        // a stranger's `keys.0` write on its own thing: its author's chain is unknown here
        let mut m = Mutation::new();
        let me2 = lp.peers[2].engine.tid();
        let t2 = lp.peers[2].engine.new_thing(&mut m, me2);
        lp.peers[2].commit(m).unwrap();
        let c = *lp.peers[2].engine.refresh_deposit_seed(&t2).unwrap().commits.last().unwrap();
        let pk = lp.peers[2].engine.package(&c).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(..)));
        assert!(!lp.peers[1].engine.keys_write_pending(&t2).unwrap(), "unchecked author");
        // the admin's own, held back by drift
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let c = *lp.peers[0].engine.refresh_deposit_seed(&t).unwrap().commits.last().unwrap();
        let pk = lp.peers[0].engine.package(&c).unwrap().unwrap();
        assert!(!lp.peers[1].engine.keys_write_pending(&t).unwrap());
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(_, crate::Reason::Drift)));
        assert!(lp.peers[1].engine.keys_write_pending(&t).unwrap(), "the admin's");
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
        let (mut lp, t) = grantee_world(914, 2);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        let removal = lp.peers[0].engine.demote(&t, &Demotion { holder: b, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        lp.peers[0].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        let regrant = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let pk = lp.peers[0].engine.package(&regrant).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &pk).unwrap(), crate::Ingested::Pending(_, crate::Reason::Drift)));
        for id in &removal.commits {
            let pk = lp.peers[0].engine.package(id).unwrap().unwrap();
            lp.deliver(1, &pk).unwrap();
        }
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), None, "removed; the re-grant pending");
        lp.peers[1].engine.drop_lost_due().unwrap();
        lp.peers[1].engine.drop_lost_secrets().unwrap();
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none(), "outside the wait: dropped, candidates too");
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("x:a.0").unwrap()).unwrap(), None, "content forgotten");
        assert_eq!(secrets_parts(&mut lp, &regrant, t), 1, "the boxes stay");
        lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].engine.reexamine().unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), Some(Role::Read), "the re-grant applied");
        let checked = lp.peers[1].engine.core.ix.secrets.get(&t).is_some_and(|e| e.read.held().next().is_some());
        assert!(checked, "its boxes came with it");
    }

    // spec/permissions.md §3: a pending commit waiting on its author's chain is stored unchecked;
    // only a signature by the named admin over a header listing its `secrets.0` part makes it
    // a grant that keeps lost secrets (a stranger naming the admin as author keeps nothing).
    #[test]
    fn pending_grant_counts_only_signed_spec_perm_3() {
        let (mut lp, t) = removed_reader(913);
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let v = ct::Secrets::default().to_value();
        let genuine = osis_commit::CommitBlob::decode(&forge_role_commit(&mut lp, 0, t, &rec, &v)).unwrap();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rcpt = osis_keys::Recipient { holder: lp.peers[1].engine.tid(), role: Role::Read, keys: osis_keys::HolderKeys::KeyActor { kem, seed: None } };
        let mut held = ActorEpochs::default();
        held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Fixed);
        let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &osis_keys::Names::default(), &mut osis_crypto::SeededRng::from_u64(3)).unwrap();
        let boxed = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
        let mut forged = osis_commit::CommitBlob::decode(&forge_role_commit(&mut lp, 2, t, &rec, &boxed)).unwrap();
        forged.header.author = lp.peers[0].engine.tid();
        let core = &lp.peers[1].engine.core;
        assert!(crate::rotation::authentic(core, &genuine, &genuine.id(), &t));
        assert!(!crate::rotation::authentic(core, &forged, &forged.id(), &t), "signed by another");
        let mut swapped = genuine.clone();
        swapped.parts = forged.parts.clone();
        assert!(!crate::rotation::authentic(core, &swapped, &swapped.id(), &t), "a part its header does not list");
    }

    fn candidates(lp: &LocalPeer, t: &Tid) -> usize {
        lp.peers[1].engine.core.ix.secrets.get(t).map_or(0, |e| osis_keys::ROLES.iter().map(|r| e.role(*r).held_newest_first().len()).sum())
    }

    // spec/crypto.md §4 (secrets from pending commits kept as reading candidates): a flood of
    // bogus pending commits from throwaway authors leaves at most the shared unknown-author
    // pool (`MAX_READING_PER_AUTHOR`), within the role's `MAX_READING`.
    #[test]
    fn bogus_flood_bounded_by_caps_spec_crypto_4() {
        let (mut lp, t) = grantee_world(909, 5);
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
        let (mut lp, t) = grantee_world(910, 4);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, tied: None };
        let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        flood(&mut lp, t, 40);
        let before = candidates(&lp, &t);
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &p).unwrap(), crate::Ingested::Pending(..)), "the grant waits for the granter's chain");
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
        let mut lp = LocalPeer::new(1, 908, WallMs(1_700_000_000_000)).unwrap();
        let (x, c) = (Tid::from_bytes([9; 15]), CommitId([9; 32]));
        lp.peers[0].engine.core.ix.secrets.insert(x, reading_only(9, c));
        lp.peers[0].engine.run(|tx| super::forget_unchecked(tx, &c)).unwrap();
        assert!(lp.peers[0].engine.core.ix.lost_due.contains_key(&x));
        lp.peers[0].engine.drop_lost_due().unwrap();
        assert!(lp.peers[0].engine.core.ix.secrets.get(&x).is_none_or(|e| !e.read.holds_any()));
    }

    // spec/crypto.md §3 (a thing has secrets of its own while a valid `keys.0` part wrote a
    // keyset), §4 (secrets of an invalid commit are kept for reading only): admin A of G grants
    // X on G's plain thing T (T's first `keys.0`, a rotation from derived epochs) after G's first
    // admin removed A. Once A's grant is invalid, every node derives T from G again (encrypting under
    // G's epoch rotated past A, not A's), delete base G, open = rebuild; peer 3 had A's commit
    // applied valid first (Y: a reader of G). The first admin's own grant then gives T secrets of its own everywhere.
    #[test]
    fn keyset_of_invalid_rotation_leaves_thing_plain_spec_crypto_3() {
        let mut lp = LocalPeer::new(4, 941, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, a, x) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
        let y = tid(&mut lp, 3);
        lp.peers[0].engine.grant(&g, &y, &edge(Role::Read)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { holder: a, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        // A's clock runs ahead: its grant is stamped after its removal
        lp.peers[1].clock.advance(120_000);
        lp.peers[1].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        let rot = lp.peers[1].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        assert!(lp.peers[1].engine.core.ix.own_keys.contains(&t));
        lp.sync(1, 3).unwrap();
        assert!(lp.peers[3].engine.core.ix.own_keys.contains(&t), "applied valid at peer 3");
        lp.sync_all().unwrap();
        let derived = |lp: &LocalPeer, i: usize| {
            let core = &lp.peers[i].engine.core;
            osis_keys::ActorEpochs::derived(&core.epochs(&g).unwrap(), &t).role(Role::Read).newest()
        };
        for i in 0..4 {
            let core = &lp.peers[i].engine.core;
            assert!(!core.ix.own_keys.contains(&t), "peer {i}: plain again");
            assert!(!core.has_own_secrets(&t), "peer {i}");
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
        // the first admin's grant: secrets of T's own, from G's derived epochs
        lp.peers[0].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        let own = lp.peers[0].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        assert_ne!(own, rot);
        for i in 0..4 {
            let core = &lp.peers[i].engine.core;
            assert!(core.ix.own_keys.contains(&t), "peer {i}: own keys");
            if i != 1 {
                assert_eq!(core.epochs(&t).unwrap().role(Role::Read).newest(), Some(own), "peer {i}");
            }
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
    }

    // spec/crypto.md §3: B, an admin of G, grants Z on T while A's rotation (T's first keyset,
    // made after G's first admin removed A) still made T own-keyed at B, boxing under A's epochs. Once
    // A's commit is invalid, B's valid `secrets.0` part does not make T own-keyed again: its
    // opened epochs are derived from G's epochs from before A's removal (A knows those). T is
    // plain at every node: encrypted under G's epoch rotated past A, G's first admin can write.
    #[test]
    fn valid_grant_under_invalid_keyset_leaves_thing_plain_spec_crypto_3() {
        let mut lp = LocalPeer::new(5, 942, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, a, x, b, z) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3), tid(&mut lp, 4));
        let edge = |role| ct::Edge { role, until: None, invite: None, tied: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&g, &b, &edge(Role::Admin)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { holder: a, new: None, presync: PreSync::Synced, retain: None }).unwrap();
        lp.peers[1].clock.advance(120_000);
        lp.peers[1].engine.grant(&t, &x, &edge(Role::Read)).unwrap();
        lp.sync(1, 3).unwrap();
        assert!(lp.peers[3].engine.core.ix.own_keys.contains(&t));
        lp.peers[3].clock.advance(130_000);
        lp.peers[3].engine.grant(&t, &z, &edge(Role::Read)).unwrap();
        lp.sync_all().unwrap();
        lp.sync_all().unwrap();
        for i in [0usize, 3] {
            let core = &lp.peers[i].engine.core;
            assert!(!core.ix.own_keys.contains(&t) && core.own_epochs(&t).is_none(), "peer {i}: plain");
            let derived = osis_keys::ActorEpochs::derived(&core.epochs(&g).unwrap(), &t).role(Role::Read).newest();
            assert_eq!(core.epochs(&t).unwrap().role(Role::Read).newest_held().map(|x| x.0), derived, "peer {i}: under G's epoch past A");
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new("x:reg.0").unwrap(), &Value::Str(format!("w{i}"))).unwrap();
            lp.peers[i].engine.commit(m).unwrap().unwrap();
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
        // spec/permissions.md §3: at the end of a complete pass of G's labels, each admin (the
        // first admin's node, B) gives T secrets of its own again, boxing Z (concurrently: a fork at
        // one n); A (removed), X and Z (readers) do nothing; nothing more once T has them
        let runs: Vec<(usize, Vec<Delivery>)> = (0..5).map(|i| own_due_done(&mut lp, i, &g, &t)).collect();
        assert_eq!(runs.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 0, 0, 1, 0]);
        // each admin's rotation goes to Z directly (it holds no box at a current epoch of T),
        // never to T's first admin G (it reads the derived epochs), and first under T's labels; Z,
        // given only B's, holds T's new epochs
        for i in [0usize, 3] {
            let ds = &runs[i].1;
            let to: Vec<Tid> = ds.iter().filter_map(|d| if let Delivery::Direct { to, .. } = d { Some(*to) } else { None }).collect();
            assert_eq!(to, vec![z], "peer {i}: delivered to Z only");
            assert!(!ds.iter().any(|d| matches!(d, Delivery::Inbox { .. })), "peer {i}");
            assert!(ds.iter().any(|d| matches!(d, Delivery::First { under, .. } if under.contains(&t))), "peer {i}: first under T");
        }
        let Some(Delivery::Direct { commits, .. }) = runs[3].1.iter().find(|d| matches!(d, Delivery::Direct { .. })) else { unreachable!() };
        for c in commits.clone() {
            let pk = lp.peers[3].engine.package(&c).unwrap().unwrap();
            lp.deliver(4, &pk).unwrap();
        }
        let b_rot = lp.peers[3].engine.core.epochs(&t).unwrap().role(Role::Read).newest().unwrap();
        let zs = lp.peers[4].engine.core.epochs(&t).unwrap();
        assert!(lp.peers[4].engine.core.has_own_secrets(&t) && zs.role(Role::Read).is_current(&b_rot) && zs.role(Role::Read).secret(&b_rot).is_some(), "Z holds B's epoch");
        lp.sync_all().unwrap();
        lp.sync_all().unwrap();
        assert_eq!((0..5).map(|i| own_due(&mut lp, i, &g, &t)).sum::<usize>(), 0, "one rotation per admin");
        for i in [0usize, 3] {
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new(format!("x:new{i}.0")).unwrap(), &Value::Int(i as i64)).unwrap();
            lp.peers[i].engine.commit(m).unwrap().unwrap();
        }
        lp.sync_all().unwrap();
        lp.sync_all().unwrap();
        for i in 0..5 {
            let core = &lp.peers[i].engine.core;
            assert!(core.has_own_secrets(&t), "peer {i}: own keys");
            if i != 1 {
                for w in [0i64, 3] {
                    let v = lp.peers[i].engine.get(&t, &osis_base::Ak::new(format!("x:new{w}.0")).unwrap()).unwrap();
                    assert_eq!(v, Some(Value::Int(w)), "peer {i} reads peer {w}'s write");
                }
            }
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
    }

    /// Runs `own_secrets_due` on `actor` at peer `i` as after a complete pass; the commits made
    /// for `t` (each other thing makes none).
    fn own_due(lp: &mut LocalPeer, i: usize, actor: &Tid, t: &Tid) -> usize {
        own_due_done(lp, i, actor, t).0
    }

    /// `own_due` with the deliveries made.
    fn own_due_done(lp: &mut LocalPeer, i: usize, actor: &Tid, t: &Tid) -> (usize, Vec<Delivery>) {
        struct Passed;
        impl crate::flows::SyncState for Passed {
            fn complete_pass(&self, _: &Tid) -> bool {
                true
            }
        }
        let (mut n, mut ds) = (0, Vec::new());
        for (x, r) in lp.peers[i].engine.own_secrets_due(actor, &Passed).unwrap() {
            assert_eq!(x, *t, "peer {i}: only T");
            let done = r.unwrap();
            n += done.commits.len();
            ds.extend(done.deliveries);
        }
        (n, ds)
    }

    // spec/permissions.md §3: a plain thing with no holder other than its first admin gets no secrets of its own
    // from the trigger, nor does an own-keyed thing with holders.
    #[test]
    fn no_own_secrets_rotation_without_holders_spec_permissions_3() {
        let mut lp = LocalPeer::new(2, 943, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (me, y) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let edge = ct::Edge { role: Role::Admin, until: None, invite: None, tied: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &y, &edge).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        for i in 0..2 {
            let core = &lp.peers[i].engine.core;
            assert!(!core.has_own_secrets(&t) && core.has_own_secrets(&g), "peer {i}");
            for a in [me, g] {
                assert_eq!(own_due(&mut lp, i, &a, &t), 0, "peer {i}");
            }
        }
    }
}
