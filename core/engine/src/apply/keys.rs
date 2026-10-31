//! Established epochs (spec/crypto.md §4):
//! an applied valid commit's `/secrets` write is `SecretsWrite::applied` with its `/keys` write
//! and the keysets held before it; a held `/secrets` compaction snapshot keys its epochs
//! (`snapshot_keyed`); a commit later found invalid has its rotations unset. Establishment is
//! persisted with the epochs, never re-inferred from state.

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_commit::{Decoded, Header, Kind};
use osis_base::{CommitId, Role, Tid, Value};
use osis_crdt::{Encoding, Fragment, MemberRef};
use osis_keys::{KeysWrite, ROLES, SecretsWrite};
use osis_schema::core_types::{self as ct, BoxKey, HistoryKey, Keys, SecretBox};
use osis_schema::{AspectKey, Codec, Type, typed_read};
use osis_store::Shred;

fn typed(v: &Value, name: &str) -> Option<Value> {
    typed_read(osis_schema::core_schema(), v, &Type::Named(name.into(), Vec::new())).ok()
}

fn field(f: &Fragment, id: u64) -> Option<&Fragment> {
    match f.slot(Encoding::Struct)? {
        MemberRef::Frag(Fragment::Struct(s)) => s.field(id),
        _ => None,
    }
}

fn map(f: Option<&Fragment>) -> Option<&osis_crdt::Map> {
    match f?.slot(Encoding::Map)? {
        MemberRef::Frag(Fragment::Map(m)) => Some(m),
        _ => None,
    }
}

/// Records for each box a `/secrets` delta writes the commit's time: the earliest write of the
/// box. A box introduces no epoch (a grant or re-seal boxes an epoch it did not make;
/// `note_keysets`).
pub(crate) fn note_box_keys(core: &mut Core, h: &Header, actor: &Tid, delta: &Fragment) {
    for (bk, k) in written_boxes(delta) {
        core.ix.boxes_to.insert(bk.member, (*actor, k.clone()));
        core.ix.box_written.upsert((*actor, bk), || h.ts, |w| *w = (*w).min(h.ts));
    }
}

/// Notes `boxes_to` alone for a `/secrets` delta of any validity (the boxes keyed to each member,
/// for `flows::reopen_dependents`; a load notes every held part alike).
pub(crate) fn note_boxes_to(core: &mut Core, actor: &Tid, delta: &Fragment) {
    for (bk, k) in written_boxes(delta) {
        core.ix.boxes_to.insert(bk.member, (*actor, k.clone()));
    }
}

/// The epochs membership part `ai` of `h` keys in `bodies` (its `/keys` deltas): what it noted
/// in `epoch_intro`, kept in its record when it drops (`Dropped::intros`).
pub(crate) fn intro_epochs(h: &Header, ai: usize, bodies: &[Fragment]) -> Vec<(Role, osis_crypto::Epoch)> {
    let mut out = std::collections::BTreeSet::new();
    if h.kind == Kind::Membership && h.aspects.get(ai).is_some_and(|a| a.ak.as_str() == "/keys") {
        for (r, ks) in bodies.iter().flat_map(|b| keys_write(b).keysets) {
            if let Ok(e) = osis_keys::aspects::from_schema(&ks.epoch) {
                out.insert((r, e));
            }
        }
    }
    out.into_iter().collect()
}

/// The boxes a `/secrets` delta writes (removals aside): typed key and key value.
fn written_boxes(delta: &Fragment) -> Vec<(BoxKey, &Value)> {
    let Some(m) = map(field(delta, 0)) else { return Vec::new() };
    m.entries().filter(|(_, _, _, f)| f.is_some()).filter_map(|(_, _, k, _)| Some((typed(k?, "box_key").and_then(|t| BoxKey::from_value(&t).ok())?, k?))).collect()
}

/// A membership commit's `/secrets` or `/keys` part dropped its body (`bodies`, its deltas):
/// what was noted from them goes with them (spec/commits.md §5), re-derived from the bodies
/// still held: `box_written`, and the `boxes_to` entries of the boxes it wrote that no held body
/// writes (an unknown first write costs a rotation or a re-seal, never a leak). `epoch_intro`
/// keeps a `/keys` part's epochs (`Dropped::intros`): the rotation stays known.
pub(crate) fn forget_dropped(tx: &mut Tx<'_>, h: &Header, ai: usize, bodies: &[Fragment]) -> Result<()> {
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    if h.kind != Kind::Membership || !matches!(a.ak.as_str(), "/secrets" | "/keys") {
        return Ok(());
    }
    rebuild_intro(tx, &std::collections::BTreeSet::from([a.tid]))?;
    if a.ak.as_str() != "/secrets" {
        return Ok(());
    }
    let mut gone: std::collections::BTreeSet<(Tid, Value)> = bodies.iter().flat_map(written_boxes).map(|(bk, k)| (bk.member, k.clone())).collect();
    let ids: Vec<CommitId> = tx.core.ix.by_aspect.get(&(a.tid, a.ak.clone())).into_iter().flatten().map(|x| x.1).collect();
    for id in ids {
        let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
        let Some(xi) = m.header.aspects.iter().position(|x| x.tid == a.tid && x.ak == a.ak) else { continue };
        if m.header.kind != Kind::Membership {
            continue;
        }
        for d in super::held_parts(tx, &id, xi)? {
            if let Decoded::Delta(d) = d {
                for (bk, k) in written_boxes(&d.fragment) {
                    gone.remove(&(bk.member, k.clone()));
                }
            }
        }
    }
    for (m, k) in gone {
        tx.core.ix.boxes_to.remove(&m, &(a.tid, k));
    }
    Ok(())
}

/// Records for each keyset a `/keys` delta writes the commit's time as the epoch's introduction
/// if earliest: a rotation writes the rotated roles' keysets, nothing else does, so the epoch's
/// introducer (`Core::epoch_intro`) is its rotation commit, or unknown while that `/keys` part is
/// not held (synced after a compaction, or missing again after `retention::uncover`).
pub(crate) fn note_keysets(core: &mut Core, h: &Header, actor: &Tid, delta: &Fragment) {
    for (r, ks) in keys_write(delta).keysets {
        if let Ok(e) = osis_keys::aspects::from_schema(&ks.epoch) {
            note_intro(core, h, actor, r, e);
        }
    }
}

/// Re-derives `epoch_intro` and `box_written` of `actors` from their valid membership-kind
/// `/secrets` and `/keys` parts (after validity flips, and at load once validity is judged):
/// an invalid write (a removed admin's backdated rotation) never introduces an epoch.
pub(crate) fn rebuild_intro(tx: &mut Tx<'_>, actors: &std::collections::BTreeSet<Tid>) -> Result<()> {
    if actors.is_empty() {
        return Ok(());
    }
    tx.core.touch();
    tx.core.ix.epoch_intro.retain(|(a, _, _), _| !actors.contains(a));
    tx.core.ix.box_written.retain(|(a, _), _| !actors.contains(a));
    for a in actors {
        for ak in ["/secrets", "/keys"] {
            let ak = osis_base::Ak::new(ak).map_err(|_| crate::Error::Misuse("ak"))?;
            let ids: Vec<CommitId> = tx.core.ix.by_aspect.get(&(*a, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
            for id in ids {
                let Some(m) = tx.core.ix.commits.get(&id).cloned() else { continue };
                if m.header.kind != Kind::Membership {
                    continue;
                }
                let Some(ai) = m.header.aspects.iter().position(|x| x.tid == *a && x.ak == ak) else { continue };
                if !m.valid.get(ai).copied().unwrap_or(false) {
                    continue;
                }
                for (r, e) in m.dropped.get(&ai).map(|d| d.intros.clone()).unwrap_or_default() {
                    note_intro(tx.core, &m.header, a, r, e);
                }
                for d in super::held_parts(tx, &id, ai)? {
                    if let Decoded::Delta(d) = d {
                        if ak.as_str() == "/keys" {
                            note_keysets(tx.core, &m.header, a, &d.fragment);
                        } else {
                            note_box_keys(tx.core, &m.header, a, &d.fragment);
                        }
                    }
                }
            }
        }
    }
    tx.core.membership_changed();
    Ok(())
}

/// Notes the `/keys` parts of membership commit `h` whose bodies write a keyset, whatever their
/// validity (`records::OWN_KEYS`: a fact of the body, kept once it drops or goes missing), then
/// re-derives `own_keys` of their things.
fn note_keyset_parts(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)]) -> Result<()> {
    if !h.kind.is_membership() {
        return Ok(());
    }
    let id = h.id();
    let mut things = std::collections::BTreeSet::new();
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if a.ak.as_str() != "/keys" || keys_write(d.fragment()).keysets.is_empty() {
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
/// commit's valid `/keys` part wrote a keyset in its body (held, or dropped or missing since).
/// Called once a part is noted, after validity flips and at load (`!regain`). A thing that loses
/// it (that commit turned invalid) derives from its owner again; what it learned stays for
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
            own |= m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid == *t && a.ak.as_str() == "/keys" && m.valid.get(ai).copied().unwrap_or(false));
        }
        if own == tx.core.ix.own_keys.contains(t) {
            continue;
        }
        tx.core.touch();
        if own {
            // epochs kept from a rotation found invalid earlier: start again from the derived
            // ones (`Core::epochs`), so a stale derived epoch stays current nowhere
            let derived = |e: &osis_keys::ActorEpochs| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.established == Some(osis_keys::Provenance::Derived)));
            let restart = regain && tx.core.ix.secrets.get(t).is_some_and(derived) && tx.core.own_epochs(t).is_none();
            let base = restart.then(|| tx.core.epochs(t)).flatten();
            tx.core.ix.own_keys.insert(*t);
            if let Some(mut b) = base {
                b.establish();
                tx.core.ix.secrets.insert(*t, b);
                save(tx, t)?;
            }
        } else {
            tx.core.ix.own_keys.remove(t);
        }
        // reader actors of things below it change
        tx.core.bodies.clear();
        tx.core.membership_changed();
    }
    Ok(())
}

pub(crate) fn note_intro(core: &mut Core, h: &Header, actor: &Tid, r: Role, e: osis_crypto::Epoch) {
    let v = (h.ts, h.author, h.actor, h.id());
    core.ix.epoch_intro.upsert((*actor, r, e), || v, |slot| *slot = (*slot).min(v));
}

/// The `/secrets` write a delta makes: keyed entries put, keyed entries reset removed (a removal
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

/// The keysets a `/keys` delta writes (whole keysets: a rotation replaces the field).
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

/// Inputs gathered before a commit's deltas join: per actor, its `/secrets` write, `/keys`
/// write and the keysets held before.
pub(crate) struct Pending {
    id: CommitId,
    ai: usize,
    actor: Tid,
    keys: KeysWrite,
    before: Keys,
}

pub(crate) fn before_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)], valid: &[bool]) -> Result<Vec<Pending>> {
    note_keyset_parts(tx, h, parts)?;
    let mut out = Vec::new();
    if h.kind != Kind::Membership {
        return Ok(out);
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if let (Decoded::Delta(d), "/keys", true) = (d, a.ak.as_str(), valid.get(*ai).copied().unwrap_or(false)) {
            note_keysets(tx.core, h, &a.tid, &d.fragment);
        }
        if a.ak.as_str() != "/secrets" {
            continue;
        }
        let Decoded::Delta(d) = d else { continue };
        if !valid.get(*ai).copied().unwrap_or(false) {
            note_boxes_to(tx.core, &a.tid, &d.fragment);
            continue;
        }
        note_box_keys(tx.core, h, &a.tid, &d.fragment);
        let keys = parts
            .iter()
            .find_map(|(x, _, k)| match (h.aspects.get(*x), k) {
                (Some(b), Decoded::Delta(k)) if b.tid == a.tid && b.ak.as_str() == "/keys" => Some(keys_write(&k.fragment)),
                _ => None,
            })
            .unwrap_or_default();
        let keys_ak = osis_base::Ak::new("/keys").map_err(|_| crate::Error::Misuse("ak"))?;
        let before = tx.state(&a.tid, &keys_ak)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()).unwrap_or_default();
        out.push(Pending { id: h.id(), ai: *ai, actor: a.tid, keys, before });
    }
    Ok(out)
}

fn save(tx: &mut Tx<'_>, actor: &Tid) -> Result<()> {
    tx.core.membership_changed();
    if let Some(e) = tx.core.ix.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
    }
    Ok(())
}

/// After the joins: the applied rotations, and `/secrets` compaction snapshots held.
pub(crate) fn after_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)], valid: &[bool], pending: Vec<Pending>) -> Result<()> {
    tx.core.touch();
    // per part, the write of all its held deltas at once
    let mut done = std::collections::BTreeSet::new();
    for p in pending {
        if !done.insert((p.id, p.ai)) {
            continue;
        }
        let mut w = SecretsWrite::default();
        for d in super::held_parts(tx, &p.id, p.ai)? {
            if let Decoded::Delta(d) = d {
                w.extend(secrets_write(&d.fragment));
            }
        }
        let actor = p.actor;
        let e = tx.core.ix.secrets.entry_or_default(actor);
        // persisted whenever it changed: `applied` also records epochs and supersessions it
        // reports no change for
        let before = e.clone();
        let changed = w.applied(e, p.id, (&p.keys, &p.before)).unwrap_or(false);
        if changed || *e != before {
            save(tx, &actor)?;
        }
    }
    if h.kind == Kind::MembershipSnapshot {
        for (ai, _, d) in parts {
            let Some(a) = h.aspects.get(*ai) else { continue };
            if a.ak.as_str() != "/secrets" || !valid.get(*ai).copied().unwrap_or(false) {
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

/// A held commit's `/secrets` delta became invalid: the rotations it claimed are no longer
/// applied by it (another valid commit claiming the same epoch keeps it applied).
pub(crate) fn invalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(a) = tx.core.ix.commits.get(c).and_then(|m| m.header.aspects.get(ai)).cloned() else { return Ok(()) };
    if a.ak.as_str() != "/secrets" {
        return Ok(());
    }
    tx.core.touch();
    if let Some(e) = tx.core.ix.secrets.get_mut(&a.tid) {
        e.unset_applied(c);
        e.establish();
    }
    save(tx, &a.tid)
}

/// The `/secrets` compaction gate (spec/crypto.md §4).
pub(crate) fn may_compact(core: &Core, actor: &Tid, state: &Fragment) -> bool {
    let Some(s) = state.read().and_then(|v| crate::engine::secrets::secrets_value(&v)) else { return false };
    let e = core.epochs(actor).unwrap_or_default();
    osis_keys::may_compact_secrets(&s, &e).unwrap_or(false)
}

/// A held commit's `/secrets` delta became valid again (re-grant): applied as received, with
/// the current `/keys` as the keysets before it (an approximation: a keyset it replaced is no
/// longer known).
pub(crate) fn revalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai).cloned() else { return Ok(()) };
    let mut secrets = SecretsWrite::default();
    for d in super::held_parts(tx, c, ai)? {
        if let Decoded::Delta(d) = d {
            secrets.extend(secrets_write(&d.fragment));
        }
    }
    let mut keys = KeysWrite::default();
    if let Some(ki) = h.aspects.iter().position(|x| x.tid == a.tid && x.ak.as_str() == "/keys") {
        for d in super::held_parts(tx, c, ki)? {
            if let Decoded::Delta(d) = d {
                keys = keys_write(&d.fragment);
            }
        }
    }
    let keys_ak = osis_base::Ak::new("/keys").map_err(|_| crate::Error::Misuse("ak"))?;
    let before = tx.state(&a.tid, &keys_ak)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()).unwrap_or_default();
    tx.core.touch();
    let e = tx.core.ix.secrets.entry_or_default(a.tid);
    if secrets.applied(e, *c, (&keys, &before)).unwrap_or(false) {
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

/// Opens, read-only, the boxes of a pending membership commit addressed to this node or an actor
/// it holds (spec/crypto.md §4: such secrets are "kept for
/// reading"): the epochs are recorded unestablished, so a grantee whose grant waits for the
/// target's `/created` and chain can open the target's label and download them. Parts are
/// decoded unverified, so what they yield is reading-only: never encrypted under, and replaced
/// by an applied valid box (spec/crypto.md §4).
pub(crate) fn read_pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<()> {
    for (a, w) in pending_secrets_writes(blob, id) {
        if (w.boxes.is_empty() && w.history.is_empty()) || tx.txn.get_local(&sealed_key(id, &a))?.is_some() {
            continue;
        }
        let s = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() };
        tx.core.touch();
        // an author whose chain is not known here shares one budget with every such author (a
        // claimed grant earns nothing: its `/members` part is as unverified as the boxes)
        let author = if tx.core.created(&blob.header.author).is_some() { blob.header.author } else { osis_keys::UNKNOWN_AUTHOR };
        let from = osis_keys::Unchecked { author, commit: *id };
        if tx.core.ingest_secrets(&a, &s, Some(from), &osis_keys::HistoryAlts::new()) {
            crate::flows::save_epochs(tx, &a)?;
        }
    }
    Ok(())
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
        if ROLES.iter().all(|r| e.role(*r).held_newest_first().is_empty()) {
            lost.push(a);
            continue;
        }
        tx.core.touch();
        tx.core.ix.secrets.insert(a, e);
        crate::flows::save_epochs(tx, &a)?;
    }
    crate::rotation::mark_lost_due(tx, lost)
}

/// The members a held, not applied membership commit's `/members` parts on `on` put an edge
/// for, decoded unverified.
pub(crate) fn pending_grantees(blob: &osis_commit::CommitBlob, id: &CommitId, on: &Tid) -> Vec<Tid> {
    let h = &blob.header;
    let mut out = Vec::new();
    if !h.kind.is_membership() || !h.is_resolved() {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in &blob.parts {
        if h.aspects.get(p.ai).is_none_or(|a| a.ak.as_str() != "/members" || a.tid != *on) {
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

/// The `/secrets` writes of a held, not applied membership commit, per actor, decoded
/// unverified (what `read_pending_boxes` reads; the lost-access trigger's pending grants).
pub(crate) fn pending_secrets_writes(blob: &osis_commit::CommitBlob, id: &CommitId) -> Vec<(Tid, SecretsWrite)> {
    let h = &blob.header;
    let mut out = Vec::new();
    if !h.kind.is_membership() || !h.is_resolved() {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in &blob.parts {
        let Some(a) = h.aspects.get(p.ai) else { continue };
        if a.ak.as_str() != "/secrets" {
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

    /// A thing owned by `owner`, made by peer `i`.
    fn thing_of(lp: &mut LocalPeer, i: usize, owner: Tid) -> Tid {
        let e = &mut lp.peers[i].engine;
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, owner);
        m.set(t, &osis_base::Ak::new("/x/reg").unwrap(), &Value::Str("new".into())).unwrap();
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

    // spec/crypto.md §4 (opening `/secrets`; reading-only secrets of unchecked boxes; history
    // keys with several live entries): random grants, demotions and rotations by several admins,
    // carried by inbox blobs (pending until their chain arrives) and partial deliveries. Every
    // per-entry ingestion of a `/secrets` change is checked against ingesting the whole state
    // (the engine fails the operation where the whole state teaches more).
    #[test]
    fn per_entry_secrets_ingestion_equals_whole_state_spec_crypto_4() {
        let servers = vec![osis_label::Address { url: "quic://s1:1".into(), key: [7; 32] }];
        let edge = |role| ct::Edge { role, until: None, invite: None, since: None };
        for seed in 0..4u64 {
            let mut lp = LocalPeer::new(4, 530 + seed, WallMs(1_700_000_000_000)).unwrap();
            let ps: Vec<Tid> = (0..4).map(|i| lp.peers[i].engine.create_person(&servers).unwrap().0.person).collect();
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
                let member = ps[1 + r(3) as usize];
                let done = match r(5) {
                    0 | 1 => lp.peers[by].engine.grant(&t, &member, &edge(roles[r(3) as usize])),
                    2 => lp.peers[by].engine.demote(&t, &Demotion { member, new: None, presync: PreSync::Synced }),
                    3 => lp.peers[by].engine.demote(&t, &Demotion { member, new: Some(edge(Role::Read)), presync: PreSync::Synced }),
                    _ => lp.peers[by].engine.ensure_rotated(&t).map(|x| x.0),
                };
                match done {
                    Ok(d) => carry(&mut lp, by, &d),
                    Err(e) => assert!(!format!("{e}").contains("/secrets ingestion"), "seed {seed}: {e}"),
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
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let g1 = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let g2 = *lp.peers[0].engine.grant(&t, &c, &edge).unwrap().commits.last().unwrap();
        let (p1, p2) = (lp.peers[0].engine.package(&g1).unwrap().unwrap(), lp.peers[0].engine.package(&g2).unwrap().unwrap());
        for n in 0..MAX_READING_ACTORS {
            let n = u8::try_from(n).unwrap();
            lp.peers[1].engine.core.ix.secrets.insert(Tid::from_bytes([n; 15]), reading_only(n, CommitId([n; 32])));
        }
        // pending (the thing's `/created` is not held): its boxes are read only under the cap
        lp.deliver(1, &p1).unwrap();
        lp.deliver(2, &p2).unwrap();
        assert!(!lp.peers[2].engine.pending().is_empty());
        let held = |lp: &LocalPeer, i: usize| lp.peers[i].engine.core.ix.secrets.get(&t).is_some_and(|e| !e.read.held_newest_first().is_empty());
        assert!(held(&lp, 2), "under the cap: read");
        assert!(!held(&lp, 1), "at the cap: not read");
    }

    /// Peer 0 owns thing `t` (`/x/a` = 1); peer 1 is the grantee, holding nothing of peer 0;
    /// peers 2.. are throwaway authors unknown to the grantee.
    fn grantee_world(seed: u64, n: usize) -> (LocalPeer, Tid) {
        let mut lp = LocalPeer::new(n, seed, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        // the granter holds the grantee's keys
        lp.sync(1, 0).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
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
                held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Own);
                let rcpt = osis_keys::Recipient { member: b, role: Role::Read, keys: osis_keys::MemberKeys::KeyActor { kem: kem.clone(), seed: None } };
                let mut rng = osis_crypto::SeededRng::from_u64((x * 10_000 + i) as u64);
                let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &|_, _| true, &mut rng).unwrap();
                let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
                let bytes = forge_membership(lp, x, t, &rec, &v, None);
                assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)), "a bogus commit pends at the grantee");
                sent += 1;
            }
        }
        sent
    }

    /// A membership commit by peer `by` setting `t`'s `/secrets` to `v` (and `also`'s, a thing
    /// whose `/created` nobody holds, so the commit stays pending), signed past every writer
    /// rule (its author holds no chain to `t`).
    fn forge_membership(lp: &mut LocalPeer, by: usize, t: Tid, rec: &osis_base::CreationRecord, v: &Value, also: Option<Tid>) -> Vec<u8> {
        use osis_commit::{AspectWrite, CommitBuilder, Form, Kind, MemoryBlobs, writer_ctx};
        use osis_crdt::{Delta, Source, Writer, create, encode_delta};
        struct Dedup(osis_base::CreationRecord);
        impl osis_commit::Secrets for Dedup {
            fn dedup(&self, _: &Tid) -> Option<Secret32> {
                Some(osis_crypto::dedup_secret(self.0.nonce()))
            }
            // made-up delete keys (servers' business)
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
        let ak = osis_base::Ak::new("/secrets").unwrap();
        let author = lp.peers[by].engine.tid();
        lp.peers[by].clock.advance(1);
        let ts = osis_base::Ts::make(lp.peers[by].engine.now(), 0).unwrap();
        let view = osis_schema::core_schema().view(ak.as_str()).unwrap();
        let own = Source::commit(CommitId([0; 32]));
        let mut w = Writer::new(ts, own.clone(), 1);
        let f = create(&mut w, &view, v).unwrap();
        let r = w.range();
        let mut cx = writer_ctx(Kind::Membership, ts, author, r.lo, r.hi);
        cx.own = own;
        let bytes = encode_delta(&Delta { nonce: [7; 16], fragment: f }, &cx, None).unwrap();
        let mut cb = CommitBuilder::new(Kind::Membership, ts, author, author, Form::Commit);
        for tid in std::iter::once(t).chain(also) {
            let mut aw = AspectWrite::new(tid, ak.clone(), r.lo, r.hi, bytes.clone());
            aw.retention = osis_commit::retention::write_retention(ak.as_str(), None, None).unwrap();
            cb.aspects.push(aw);
        }
        cb.build(&lp.peers[by].engine.identity().keys().signing, &Dedup(rec.clone()), &mut MemoryBlobs::default(), &mut osis_crypto::SeededRng::from_u64(9)).unwrap().commit.encode()
    }

    /// A pending commit by peer `by` boxing peer 1 a fresh read secret of `t` (`also`: as in
    /// `forge_membership`).
    fn forged_grant(lp: &mut LocalPeer, by: usize, t: Tid, seed: u64, also: Option<Tid>) {
        let b = lp.peers[1].engine.tid();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let mut held = ActorEpochs::default();
        held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Own);
        let rcpt = osis_keys::Recipient { member: b, role: Role::Read, keys: osis_keys::MemberKeys::KeyActor { kem, seed: None } };
        let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &|_, _| true, &mut osis_crypto::SeededRng::from_u64(seed)).unwrap();
        let v = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
        let bytes = forge_membership(lp, by, t, &rec, &v, also);
        assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)));
    }

    /// Peer 1 reads `t` (checked secrets), then is removed by peer 0; the removal applied.
    fn removed_reader(seed: u64) -> (LocalPeer, Tid) {
        let (mut lp, t) = grantee_world(seed, 3);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("/x/a").unwrap()).unwrap(), Some(Value::Int(1)));
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
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &c, &edge).unwrap();
        let before = lp.peers[0].engine.epochs(&t).unwrap().read.newest().unwrap();
        lp.peers[0].engine.demote(&t, &Demotion { member: c, new: None, presync: PreSync::Synced }).unwrap();
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

    // spec/crypto.md §4 (`/keys` vouches for no secret): a writer
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
            mu.set(t, &osis_base::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
            lp.peers[0].commit(mu).unwrap();
            let edge = |role| ct::Edge { role, until: None, invite: None, since: None };
            lp.peers[0].engine.grant(&t, &w, &edge(Role::Write)).unwrap();
            lp.peers[0].engine.grant(&t, &m, &edge(Role::Read)).unwrap();
            lp.peers[0].engine.demote(&t, &Demotion { member: m, new: None, presync: PreSync::Synced }).unwrap();
            let e0 = lp.peers[0].engine.epochs(&t).unwrap();
            let e = e0.read.newest().unwrap();
            let genuine = e0.read.secret(&e).cloned().unwrap();
            lp.sync(0, 1).unwrap();
            // the writer's `/keys`: E's keyset with another secret's keys
            let junk = osis_keys::keyset(&e, &Secret32::from_bytes([0x66; 32]));
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
        lp.peers[0].engine.demote(&t, &Demotion { member: b, new: None, presync: PreSync::Synced }).unwrap();
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
        forged_grant(&mut lp, 2, t, 1, None);
        remove(&mut lp, t);
        assert!(lp.peers[1].engine.drop_lost_due().unwrap().contains(&t));
        assert!(lp.peers[1].engine.core.ix.secrets.get(&t).is_none());
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("/x/a").unwrap()).unwrap(), None);
    }

    // spec/permissions.md §3: a pending grant by an admin of the thing keeps the removed node's
    // secrets (it may yet read again), for a bounded time after its `ts` only.
    #[test]
    fn admins_pending_grant_keeps_lost_secrets_for_a_while_spec_perm_3() {
        let (mut lp, t) = removed_reader(912);
        remove(&mut lp, t);
        // pending for good: it also writes a thing nobody holds the `/created` of
        forged_grant(&mut lp, 0, t, 2, Some(Tid::from_bytes([0x5a; 15])));
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
        let rcpt = osis_keys::Recipient { member: b, role: Role::Read, keys: osis_keys::MemberKeys::KeyActor { kem, seed: None } };
        let w = osis_keys::reseal_member(&t, &epochs, &secrets, &rcpt, &[Role::Read].into(), &mut osis_crypto::SeededRng::from_u64(3)).unwrap().unwrap();
        let v = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() }.to_value();
        // signed before the removal; pending for good (a thing nobody holds the `/created` of)
        let bytes = forge_membership(&mut lp, 0, t, &rec, &v, Some(Tid::from_bytes([0x5b; 15])));
        remove(&mut lp, t);
        assert!(matches!(lp.peers[1].engine.ingest(&bytes, Vec::new()).unwrap(), crate::Ingested::Pending(..)));
        lp.peers[1].clock.advance(2 * crate::rotation::PENDING_GRANT_WAIT_MS);
        assert!(lp.peers[1].engine.drop_lost_secrets().unwrap().contains(&t));
        let (id, _) = lp.peers[1].engine.pending().into_iter().next().unwrap();
        assert_eq!(secrets_parts(&mut lp, &id, t), 0, "a held epoch's box goes");
    }

    // spec/permissions.md §3 (a deposit-only step waits for a pending `/keys` write): only one
    // signed by an admin of the actor counts; one whose author nobody can check (anyone can send
    // it) would hold the step back for good.
    #[test]
    fn keys_write_pending_needs_an_admin_spec_perm_3() {
        let (mut lp, t) = removed_reader(916);
        // a stranger's `/keys` write on its own thing: its author's chain is unknown here
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

    /// Parts on `t`'s `/secrets` of held commit `id` at peer 1.
    fn secrets_parts(lp: &mut LocalPeer, id: &CommitId, t: Tid) -> usize {
        let Some(bytes) = lp.peers[1].engine.commit_bytes(id).unwrap() else { return 0 };
        let blob = osis_commit::CommitBlob::decode(&bytes).unwrap();
        blob.parts.iter().filter(|p| blob.header.aspects.get(p.ai).is_some_and(|a| a.tid == t && a.ak.as_str() == "/secrets")).count()
    }

    // spec/permissions.md §3: a re-grant held pending past the removal and outside the wait (here
    // ahead of the removed node's clock) keeps its boxes through the forgetting the removal
    // triggers, so once it applies the node holds the role and its secrets.
    #[test]
    fn late_regrant_keeps_its_boxes_spec_perm_3() {
        let (mut lp, t) = grantee_world(914, 2);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        lp.peers[0].engine.grant(&t, &b, &edge).unwrap();
        lp.sync(0, 1).unwrap();
        let removal = lp.peers[0].engine.demote(&t, &Demotion { member: b, new: None, presync: PreSync::Synced }).unwrap();
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
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("/x/a").unwrap()).unwrap(), None, "content forgotten");
        assert_eq!(secrets_parts(&mut lp, &regrant, t), 1, "the boxes stay");
        lp.peers[1].clock.advance(3 * osis_base::format::MAX_DRIFT_MS);
        lp.peers[1].engine.reexamine().unwrap();
        assert_eq!(lp.peers[1].engine.core.role_now(&b, &t), Some(Role::Read), "the re-grant applied");
        let checked = lp.peers[1].engine.core.ix.secrets.get(&t).is_some_and(|e| e.read.held().next().is_some());
        assert!(checked, "its boxes came with it");
    }

    // spec/permissions.md §3: a pending commit waiting on its author's chain is stored unchecked;
    // only a signature by the named admin over a header listing its `/secrets` part makes it
    // a grant that keeps lost secrets (a stranger naming the admin as author keeps nothing).
    #[test]
    fn pending_grant_counts_only_signed_spec_perm_3() {
        let (mut lp, t) = removed_reader(913);
        let rec = lp.peers[0].engine.get_typed(&t, &ct::CREATED).unwrap().unwrap();
        let v = ct::Secrets::default().to_value();
        let genuine = osis_commit::CommitBlob::decode(&forge_membership(&mut lp, 0, t, &rec, &v, None)).unwrap();
        let kem = lp.peers[1].engine.identity().keys().kem.public().clone();
        let rcpt = osis_keys::Recipient { member: lp.peers[1].engine.tid(), role: Role::Read, keys: osis_keys::MemberKeys::KeyActor { kem, seed: None } };
        let mut held = ActorEpochs::default();
        held.read.set_established(Epoch::new(1, [0; 32]).unwrap(), osis_keys::Provenance::Own);
        let rot = osis_keys::rotate(&t, &[Role::Read].into(), &held, &ct::Secrets::default(), &[rcpt], &|_, _| true, &mut osis_crypto::SeededRng::from_u64(3)).unwrap();
        let boxed = ct::Secrets { boxes: rot.secrets.boxes, history: rot.secrets.history.into_iter().collect() }.to_value();
        let mut forged = osis_commit::CommitBlob::decode(&forge_membership(&mut lp, 2, t, &rec, &boxed, None)).unwrap();
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
    // member reads once the granter's chain arrives and the grant applies.
    #[test]
    fn genuine_grant_applies_after_flood_spec_crypto_4() {
        let (mut lp, t) = grantee_world(910, 4);
        let b = lp.peers[1].engine.tid();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        flood(&mut lp, t, 40);
        let before = candidates(&lp, &t);
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        assert!(matches!(lp.deliver(1, &p).unwrap(), crate::Ingested::Pending(..)), "the grant waits for the granter's chain");
        assert_eq!(candidates(&lp, &t), before, "the pool is full: the grant's candidate waits");
        lp.sync(0, 1).unwrap();
        assert!(!lp.peers[1].engine.core.ix.pending.contains_key(&g), "the grant applied");
        assert_eq!(lp.peers[1].engine.get(&t, &osis_base::Ak::new("/x/a").unwrap()).unwrap(), Some(Value::Int(1)));
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
        assert!(lp.peers[0].engine.core.ix.lost_due.contains(&x));
        lp.peers[0].engine.drop_lost_due().unwrap();
        assert!(lp.peers[0].engine.core.ix.secrets.get(&x).is_none_or(|e| e.read.held_newest_first().is_empty()));
    }

    // spec/crypto.md §3 (a thing has secrets of its own while a valid `/keys` part wrote a
    // keyset), §4 (secrets of an invalid commit are kept for reading only): admin A of G grants
    // X on G's plain thing T (T's first `/keys`, a rotation from derived epochs) after the owner
    // removed A. Once A's grant is invalid, every node derives T from G again (encrypting under
    // G's epoch rotated past A, not A's), delete base G, open = rebuild; peer 3 had A's commit
    // applied valid first (Y: a reader of G). The owner's own grant then gives T secrets of its own everywhere.
    #[test]
    fn keyset_of_invalid_rotation_leaves_thing_plain_spec_crypto_3() {
        let mut lp = LocalPeer::new(4, 941, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, a, x) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2));
        let edge = |role| ct::Edge { role, until: None, invite: None, since: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
        let y = tid(&mut lp, 3);
        lp.peers[0].engine.grant(&g, &y, &edge(Role::Read)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { member: a, new: None, presync: PreSync::Synced }).unwrap();
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
        // the owner's grant: secrets of T's own, from G's derived epochs
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
    // made after the owner removed A) still made T own-keyed at B, boxing under A's epochs. Once
    // A's commit is invalid, B's valid `/secrets` part does not make T own-keyed again: its
    // opened epochs are derived from G's epochs from before A's removal (A knows those). T is
    // plain at every node: encrypted under G's epoch rotated past A, the owner can write.
    #[test]
    fn valid_grant_under_invalid_keyset_leaves_thing_plain_spec_crypto_3() {
        let mut lp = LocalPeer::new(5, 942, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let tid = |lp: &mut LocalPeer, i: usize| lp.peers[i].engine.tid();
        let (me, a, x, b, z) = (tid(&mut lp, 0), tid(&mut lp, 1), tid(&mut lp, 2), tid(&mut lp, 3), tid(&mut lp, 4));
        let edge = |role| ct::Edge { role, until: None, invite: None, since: None };
        let g = thing_of(&mut lp, 0, me);
        lp.peers[0].engine.grant(&g, &a, &edge(Role::Admin)).unwrap();
        lp.peers[0].engine.grant(&g, &b, &edge(Role::Admin)).unwrap();
        let t = thing_of(&mut lp, 0, g);
        lp.sync_all().unwrap();
        lp.peers[0].engine.demote(&g, &Demotion { member: a, new: None, presync: PreSync::Synced }).unwrap();
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
            m.set(t, &osis_base::Ak::new("/x/reg").unwrap(), &Value::Str(format!("w{i}"))).unwrap();
            lp.peers[i].engine.commit(m).unwrap().unwrap();
            let d0 = lp.peers[i].engine.index_digest();
            lp.peers[i].engine.rebuild_index().unwrap();
            assert_eq!(d0.first_diff(&lp.peers[i].engine.index_digest()), None, "peer {i}: open = rebuild");
        }
        // spec/permissions.md §3: at the end of a complete pass of G's labels, each admin (the
        // owner's node, B) gives T secrets of its own again, boxing Z (concurrently: a fork at
        // one n); A (removed), X and Z (readers) do nothing; nothing more once T has them
        let ran: Vec<usize> = (0..5).map(|i| own_due(&mut lp, i, &g, &t)).collect();
        assert_eq!(ran, vec![1, 0, 0, 1, 0]);
        lp.sync_all().unwrap();
        lp.sync_all().unwrap();
        assert_eq!((0..5).map(|i| own_due(&mut lp, i, &g, &t)).sum::<usize>(), 0, "one rotation per admin");
        for i in [0usize, 3] {
            let mut m = Mutation::new();
            m.set(t, &osis_base::Ak::new(format!("/x/new{i}")).unwrap(), &Value::Int(i as i64)).unwrap();
            lp.peers[i].engine.commit(m).unwrap().unwrap();
        }
        lp.sync_all().unwrap();
        lp.sync_all().unwrap();
        for i in 0..5 {
            let core = &lp.peers[i].engine.core;
            assert!(core.has_own_secrets(&t), "peer {i}: own keys");
            if i != 1 {
                for w in [0i64, 3] {
                    let v = lp.peers[i].engine.get(&t, &osis_base::Ak::new(format!("/x/new{w}")).unwrap()).unwrap();
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
        struct Passed;
        impl crate::flows::SyncState for Passed {
            fn complete_pass(&self, _: &Tid) -> bool {
                true
            }
        }
        let mut n = 0;
        for (x, r) in lp.peers[i].engine.own_secrets_due(actor, &Passed).unwrap() {
            assert_eq!(x, *t, "peer {i}: only T");
            n += r.unwrap().commits.len();
        }
        n
    }

    // spec/permissions.md §3: a plain thing with no non-owner member gets no secrets of its own
    // from the trigger, nor does an own-keyed thing with members.
    #[test]
    fn no_own_secrets_rotation_without_members_spec_permissions_3() {
        let mut lp = LocalPeer::new(2, 943, WallMs(1_700_000_000_000)).unwrap();
        lp.sync_all().unwrap();
        let (me, y) = (lp.peers[0].engine.tid(), lp.peers[1].engine.tid());
        let edge = ct::Edge { role: Role::Admin, until: None, invite: None, since: None };
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
