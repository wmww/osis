//! Established epochs (spec/crypto.md §4):
//! an applied valid commit's `/secrets` write is `SecretsWrite::applied` with its `/keys` write
//! and the keysets held before it; a held `/secrets` compaction snapshot keys its epochs
//! (`snapshot_keyed`); a commit later found invalid has its rotations unset. Establishment is
//! persisted with the epochs, never re-inferred from state.

use crate::engine::{Core, Tx};
use crate::error::Result;
use osis_commit::{Decoded, Header, Kind};
use osis_core::{CommitId, Role, Tid, Value};
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

/// Records the box keys of keyed `/secrets` entries (a removal names only the entry's dot), and
/// for each box written the commit's time: the earliest write of the box, and the earliest of
/// its epoch (`Core::epoch_intro`).
pub(crate) fn note_box_keys(core: &mut Core, h: &Header, actor: &Tid, delta: &Fragment) {
    if let Some(m) = map(field(delta, 0)) {
        for (d, _, k, f) in m.entries() {
            let Some(k) = k else { continue };
            if !core.box_keys.contains_key(&(*actor, d.clone())) {
                core.box_keys.insert((*actor, d.clone()), k.clone());
            }
            if f.is_none() {
                continue;
            }
            let Some(bk) = typed(k, "box_key").and_then(|k| BoxKey::from_value(&k).ok()) else { continue };
            core.boxes_to.insert(bk.member, (*actor, k.clone()));
            if let Ok(e) = osis_keys::aspects::from_schema(&bk.epoch) {
                note_intro(core, h, actor, bk.role, e);
            }
            core.box_written.upsert((*actor, bk), || h.ts, |w| *w = (*w).min(h.ts));
        }
    }
}

/// Records for each keyset a `/keys` delta writes the commit's time as the epoch's introduction
/// if earliest (a rotation writes the rotated roles' keysets: an epoch boxed only to key actors,
/// keyed at a higher role, is found by it).
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
    tx.core.epoch_intro.retain(|(a, _, _), _| !actors.contains(a));
    tx.core.box_written.retain(|(a, _), _| !actors.contains(a));
    for a in actors {
        for ak in ["/secrets", "/keys"] {
            let ak = osis_core::Ak::new(ak).map_err(|_| crate::Error::Misuse("ak"))?;
            let ids: Vec<CommitId> = tx.core.by_aspect.get(&(*a, ak.clone())).into_iter().flatten().map(|x| x.1).collect();
            for id in ids {
                let Some(m) = tx.core.commits.get(&id).cloned() else { continue };
                if m.header.kind != Kind::Membership {
                    continue;
                }
                let Some(ai) = m.header.aspects.iter().position(|x| x.tid == *a && x.ak == ak) else { continue };
                if !m.valid.get(ai).copied().unwrap_or(false) {
                    continue;
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

fn note_intro(core: &mut Core, h: &Header, actor: &Tid, r: Role, e: osis_crypto::Epoch) {
    let v = (h.ts, h.author, h.actor, h.id());
    core.epoch_intro.upsert((*actor, r, e), || v, |slot| *slot = (*slot).min(v));
}

/// The `/secrets` write a delta makes: keyed entries put, resets of entries whose key is known
/// here removed. `false` while a removed entry's key is unknown (its creation not held yet).
pub(crate) fn secrets_write(core: &Core, actor: &Tid, delta: &Fragment) -> (SecretsWrite, bool) {
    let mut w = SecretsWrite::default();
    let mut complete = true;
    if let Some(m) = map(field(delta, 0)) {
        for (d, _, k, f) in m.entries() {
            match (k, f.and_then(Fragment::read)) {
                (Some(k), Some(v)) => {
                    if let (Some(k), Some(b)) = (typed(k, "box_key").and_then(|k| BoxKey::from_value(&k).ok()), typed(&v, "box").and_then(|b| SecretBox::from_value(&b).ok())) {
                        w.boxes.insert(k, b);
                    }
                }
                (None, None) => match core.box_keys.get(&(*actor, d.clone())).and_then(|k| typed(k, "box_key")).and_then(|k| BoxKey::from_value(&k).ok()) {
                    Some(k) => {
                        w.removed.insert(k);
                    }
                    None => complete = false,
                },
                _ => {}
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
    (w, complete)
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

/// A commit's `/secrets` write that waits for the keys of the boxes it removes.
#[derive(Clone, Debug)]
pub(crate) struct Unresolved {
    keys: KeysWrite,
    before: Keys,
}

pub(crate) fn before_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)], valid: &[bool]) -> Result<Vec<Pending>> {
    let mut out = Vec::new();
    if h.kind != Kind::Membership {
        return Ok(out);
    }
    for (ai, _, d) in parts {
        let Some(a) = h.aspects.get(*ai) else { continue };
        if let (Decoded::Delta(d), "/keys", true) = (d, a.ak.as_str(), valid.get(*ai).copied().unwrap_or(false)) {
            note_keysets(tx.core, h, &a.tid, &d.fragment);
        }
        if a.ak.as_str() != "/secrets" || !valid.get(*ai).copied().unwrap_or(false) {
            continue;
        }
        let Decoded::Delta(d) = d else { continue };
        note_box_keys(tx.core, h, &a.tid, &d.fragment);
        let keys = parts
            .iter()
            .find_map(|(x, _, k)| match (h.aspects.get(*x), k) {
                (Some(b), Decoded::Delta(k)) if b.tid == a.tid && b.ak.as_str() == "/keys" => Some(keys_write(&k.fragment)),
                _ => None,
            })
            .unwrap_or_default();
        let keys_ak = osis_core::Ak::new("/keys").map_err(|_| crate::Error::Misuse("ak"))?;
        let before = tx.state(&a.tid, &keys_ak)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()).unwrap_or_default();
        out.push(Pending { id: h.id(), ai: *ai, actor: a.tid, keys, before });
    }
    Ok(out)
}

fn save(tx: &mut Tx<'_>, actor: &Tid) -> Result<()> {
    tx.core.membership_changed();
    if let Some(e) = tx.core.secrets.get(actor) {
        let b = crate::engine::secrets::encode_epochs(e);
        tx.txn.put_local(&[b"k/".as_slice(), actor.as_bytes()].concat(), &b, Shred::Yes)?;
    }
    Ok(())
}

/// After the joins: the applied rotations, and `/secrets` compaction snapshots held.
pub(crate) fn after_join(tx: &mut Tx<'_>, h: &Header, parts: &[(usize, usize, Decoded)], valid: &[bool], pending: Vec<Pending>) -> Result<()> {
    tx.core.touch();
    let mut actors = std::collections::BTreeSet::new();
    for p in pending {
        let u = Unresolved { keys: p.keys, before: p.before };
        put_unresolved(tx, &p.id, p.ai, &u)?;
        tx.core.secrets_unresolved.insert((p.id, p.ai), u);
        actors.insert(p.actor);
    }
    // apply every waiting write of these actors whose removed keys are now known
    let waiting: Vec<(CommitId, usize, Unresolved)> = tx.core.secrets_unresolved.iter().map(|(k, v)| (k.0, k.1, v.clone())).collect();
    let mut progress = true;
    while progress {
        progress = false;
        for (c, ai, u) in &waiting {
            if !tx.core.secrets_unresolved.contains_key(&(*c, *ai)) {
                continue;
            }
            let Some(actor) = tx.core.commits.get(c).and_then(|m| m.header.aspects.get(*ai)).map(|a| a.tid) else { continue };
            if !actors.contains(&actor) {
                continue;
            }
            let mut w = SecretsWrite::default();
            let mut complete = true;
            for d in super::held_parts(tx, c, *ai)? {
                if let Decoded::Delta(d) = d {
                    let (x, ok) = secrets_write(tx.core, &actor, &d.fragment);
                    w.extend(x);
                    complete &= ok;
                }
            }
            if !complete {
                continue;
            }
            tx.core.secrets_unresolved.remove(&(*c, *ai));
            remove_unresolved(tx, c, *ai)?;
            progress = true;
            let e = tx.core.secrets.entry_or_default(actor);
            if w.applied(e, (&u.keys, &u.before)).unwrap_or(false) {
                save(tx, &actor)?;
            }
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
            let e = tx.core.secrets.entry_or_default(a.tid);
            if osis_keys::snapshot_keyed(&sv, e).unwrap_or(false) {
                save(tx, &a.tid)?;
            }
        }
    }
    Ok(())
}

/// A held commit's `/secrets` delta became invalid: its rotations are no longer applied.
pub(crate) fn invalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai) else { return Ok(()) };
    if a.ak.as_str() != "/secrets" {
        return Ok(());
    }
    // only the rotations this commit made (its `/keys` write sets the epoch's keyset): a grant
    // or re-seal re-writes history boxes of epochs another commit applied
    let mut keys = KeysWrite::default();
    if let Some(ki) = h.aspects.iter().position(|x| x.tid == a.tid && x.ak.as_str() == "/keys") {
        for d in super::held_parts(tx, c, ki)? {
            if let Decoded::Delta(d) = d {
                keys = keys_write(&d.fragment);
            }
        }
    }
    let mut eps = Vec::new();
    for d in super::held_parts(tx, c, ai)? {
        if let Decoded::Delta(d) = d {
            for k in secrets_write(tx.core, &a.tid, &d.fragment).0.history.keys() {
                if let Ok(e) = osis_keys::aspects::from_schema(&k.epoch)
                    && keys.keysets.get(&k.role).is_some_and(|ks| ks.epoch == k.epoch)
                {
                    eps.push((k.role, e));
                }
            }
        }
    }
    tx.core.touch();
    if let Some(e) = tx.core.secrets.get_mut(&a.tid) {
        for (r, ep) in eps {
            e.role_mut(r).unset_applied(&ep);
        }
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
    let Some(h) = tx.core.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
    let Some(a) = h.aspects.get(ai).cloned() else { return Ok(()) };
    let mut secrets = SecretsWrite::default();
    for d in super::held_parts(tx, c, ai)? {
        if let Decoded::Delta(d) = d {
            secrets.extend(secrets_write(tx.core, &a.tid, &d.fragment).0);
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
    let keys_ak = osis_core::Ak::new("/keys").map_err(|_| crate::Error::Misuse("ak"))?;
    let before = tx.state(&a.tid, &keys_ak)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()).unwrap_or_default();
    tx.core.touch();
    let e = tx.core.secrets.entry_or_default(a.tid);
    if secrets.applied(e, (&keys, &before)).unwrap_or(false) {
        save(tx, &a.tid)?;
    }
    Ok(())
}

pub(crate) const UNRESOLVED: &[u8] = b"w/";

fn unresolved_key(c: &CommitId, ai: usize) -> Vec<u8> {
    [UNRESOLVED, &c.0[..], &(ai as u32).to_be_bytes()].concat()
}

fn keys_of_write(w: &KeysWrite) -> Keys {
    let mut k = Keys::default();
    w.apply(&mut k);
    k
}

fn write_of_keys(k: &Keys) -> KeysWrite {
    let mut w = KeysWrite::default();
    for (r, ks) in [(Role::Read, &k.read), (Role::Write, &k.write), (Role::Admin, &k.admin)] {
        if let Some(ks) = ks {
            w.keysets.insert(r, ks.clone());
        }
    }
    w
}

fn put_unresolved(tx: &mut Tx<'_>, c: &CommitId, ai: usize, u: &Unresolved) -> Result<()> {
    let v = Value::List(vec![keys_of_write(&u.keys).to_value(), u.before.to_value()]);
    Ok(tx.txn.put_local(&unresolved_key(c, ai), &osis_core::encode(&v), Shred::No)?)
}

fn remove_unresolved(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    tx.txn.remove_local(&unresolved_key(c, ai), Shred::No)?;
    Ok(())
}

/// Loads the waiting `/secrets` writes.
pub(crate) fn load_unresolved(tx: &mut Tx<'_>) -> Result<()> {
    let mut out = Vec::new();
    tx.scan(UNRESOLVED, |k, v| {
        let mut r = crate::engine::records::Rd::new(k);
        let c = CommitId(r.arr()?);
        let ai = r.u32()? as usize;
        let lim = osis_core::Limits { max_depth: 32, max_bytes: v.len() };
        let bad = || crate::Error::Corrupt("unresolved secrets write");
        let Value::List(items) = osis_core::decode(&v, &lim).map_err(|_| bad())? else { return Err(bad()) };
        let [kw, kb] = items.as_slice() else { return Err(bad()) };
        let keys = write_of_keys(&Keys::from_value(kw).map_err(|_| bad())?);
        let before = Keys::from_value(kb).map_err(|_| bad())?;
        out.push((c, ai, Unresolved { keys, before }));
        Ok(())
    })?;
    for (c, ai, u) in out {
        tx.core.secrets_unresolved.insert((c, ai), u);
    }
    Ok(())
}

/// Opens, read-only, the boxes of a pending membership commit addressed to this node or an actor
/// it holds (spec/crypto.md §4: such secrets are "kept for
/// reading"): the epochs are recorded unestablished, so a grantee whose grant waits for the
/// target's `/created` and chain can open the target's label and download them. Parts are
/// decoded unverified, so what they yield is reading-only: never encrypted under, and replaced
/// by an applied valid box (spec/crypto.md §4).
pub(crate) fn read_pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<()> {
    // a commit whose `/members` part grants this node or an actor it holds outranks one that
    // only boxes it: its author gets a budget of its own even when its chain is unknown here
    let me = tx.core.id.tid();
    let grants = pending_grantees(blob, id).iter().any(|m| *m == me || tx.core.secrets.contains_key(m) || tx.core.key_actors.contains_key(m));
    for (a, w) in pending_secrets_writes(tx.core, blob, id) {
        if w.boxes.is_empty() && w.history.is_empty() {
            continue;
        }
        let s = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() };
        tx.core.touch();
        // an author whose chain is not known here shares one budget with every such author,
        // unless its commit grants this node (bogus commits that only box it fill no grant's)
        let author = if grants || tx.core.created(&blob.header.author).is_some() { blob.header.author } else { osis_keys::UNKNOWN_AUTHOR };
        let from = osis_keys::Unchecked { author, commit: *id };
        let published = Core::keys_in(tx, &a)?;
        if tx.core.ingest_secrets(&a, &s, Some(from), &osis_keys::HistoryAlts::new(), published.as_ref()) {
            crate::flows::save_epochs(tx, &a)?;
        }
    }
    Ok(())
}

/// Drops the reading-only secrets pending commit `id` gave: it applied (its boxes are checked
/// now, or stripped as invalid) or was dropped (spec/crypto.md §4). An actor they were the only
/// secrets of is left to the lost-access trigger, which drops them with what they read.
pub(crate) fn forget_unchecked(tx: &mut Tx<'_>, id: &CommitId) -> Result<()> {
    let actors: Vec<Tid> = tx.core.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.reading.iter().any(|(_, u)| u.commit == *id)))).map(|(t, _)| *t).collect();
    let mut lost = Vec::new();
    for a in actors {
        let Some(mut e) = tx.core.secrets.get(&a).cloned() else { continue };
        e.drop_reading_from(id);
        // an actor left with no secret is the lost-access trigger's: it forgets what they read
        if ROLES.iter().all(|r| e.role(*r).held_newest_first().is_empty()) {
            lost.push(a);
            continue;
        }
        tx.core.touch();
        tx.core.secrets.insert(a, e);
        crate::flows::save_epochs(tx, &a)?;
    }
    crate::rotation::mark_lost_due(tx, lost)
}

/// The members a held, not applied membership commit's `/members` parts put an edge for,
/// decoded unverified.
fn pending_grantees(blob: &osis_commit::CommitBlob, id: &CommitId) -> Vec<Tid> {
    let h = &blob.header;
    let mut out = Vec::new();
    if !h.kind.is_membership() || !h.is_resolved() {
        return out;
    }
    let mut interner = osis_crdt::Interner::new();
    for p in &blob.parts {
        if h.aspects.get(p.ai).is_none_or(|a| a.ak.as_str() != "/members") {
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
pub(crate) fn pending_secrets_writes(core: &Core, blob: &osis_commit::CommitBlob, id: &CommitId) -> Vec<(Tid, SecretsWrite)> {
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
        out.push((a.tid, secrets_write(core, &a.tid, &d.fragment).0));
    }
    out
}

impl crate::engine::Engine {
    /// Records a read secret learned from a label's entry box (a recovery or link key opening
    /// by static entry, spec/sync.md §2): kept for reading, unestablished.
    pub(crate) fn learn_read_secret(&mut self, g: &Tid, e: osis_crypto::Epoch, secret: osis_crypto::Secret32) -> Result<()> {
        let g = *g;
        self.run(|tx| {
            tx.core.touch();
            let ep = tx.core.secrets.entry_or_default(g);
            ep.role_mut(Role::Read).observe(e);
            ep.role_mut(Role::Read).set_secret(e, secret);
            crate::flows::save_epochs(tx, &g)
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
        m.set(t, &osis_core::Ak::new("/x/reg").unwrap(), &Value::Str("new".into())).unwrap();
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
    use osis_core::{CommitId, Role, Tid, Value, WallMs};
    use osis_crypto::{Epoch, Secret32};
    use osis_keys::{ActorEpochs, Unchecked};
    use osis_schema::core_types as ct;

    fn reading_only(n: u8, commit: CommitId) -> ActorEpochs {
        let mut a = ActorEpochs::default();
        a.read.set_reading_secret(Epoch::new(1, [n; 16]).unwrap(), Secret32::from_bytes([n; 32]), Unchecked { author: Tid::from_bytes([n; 15]), commit });
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
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let g1 = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let g2 = *lp.peers[0].engine.grant(&t, &c, &edge).unwrap().commits.last().unwrap();
        let (p1, p2) = (lp.peers[0].engine.package(&g1).unwrap().unwrap(), lp.peers[0].engine.package(&g2).unwrap().unwrap());
        for n in 0..MAX_READING_ACTORS {
            let n = u8::try_from(n).unwrap();
            lp.peers[1].engine.core.secrets.insert(Tid::from_bytes([n; 15]), reading_only(n, CommitId([n; 32])));
        }
        // pending (the thing's `/created` is not held): its boxes are read only under the cap
        lp.deliver(1, &p1).unwrap();
        lp.deliver(2, &p2).unwrap();
        assert!(!lp.peers[2].engine.pending().is_empty());
        let held = |lp: &LocalPeer, i: usize| lp.peers[i].engine.core.secrets.get(&t).is_some_and(|e| !e.read.held_newest_first().is_empty());
        assert!(held(&lp, 2), "under the cap: read");
        assert!(!held(&lp, 1), "at the cap: not read");
    }

    // spec/crypto.md §4: a grantee holding neither the target's `/keys` nor the granter's chain
    // reads the target from its pending grant even after 64 bogus pending commits from unknown
    // authors filled their shared budget: a commit granting the node outranks ones that only
    // box it.
    #[test]
    fn grant_outranks_unknown_authors_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 909, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        // the granter holds the grantee's keys; the grantee holds nothing of the granter
        lp.sync(1, 0).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        // 64 bogus candidates of unknown authors for the target, as pending commits leave them
        let mut bogus = ActorEpochs::default();
        for n in 0..osis_keys::MAX_READING_PER_AUTHOR {
            let n = u8::try_from(n).unwrap();
            bogus.read.set_reading_secret(Epoch::new(1, [n; 16]).unwrap(), Secret32::from_bytes([n; 32]), Unchecked { author: osis_keys::UNKNOWN_AUTHOR, commit: CommitId([n; 32]) });
        }
        lp.peers[1].engine.core.secrets.insert(t, bogus);
        lp.deliver(1, &p).unwrap();
        assert!(!lp.peers[1].engine.pending().is_empty(), "the grant waits for the granter's chain");
        let read = lp.peers[1].engine.core.secrets.get(&t).map(|e| e.read.held_newest_first().len()).unwrap_or(0);
        assert!(read > osis_keys::MAX_READING_PER_AUTHOR, "the grant's candidate is read: {read}");
    }

    // spec/crypto.md §4 (residue, issues/reading-candidates-unknown-authors.md): a bogus
    // pending commit can claim a grant as easily as a genuine one (its `/members` part is
    // unverified until its chain arrives), so such claims under throwaway authors each get a
    // budget of their own; only the role's total (`MAX_READING`) bounds them, and once they
    // fill it a genuine grant's candidate is refused until its grant applies.
    #[test]
    fn bogus_grant_claims_bounded_by_role_total_spec_crypto_4() {
        let mut lp = LocalPeer::new(2, 910, WallMs(1_700_000_000_000)).unwrap();
        let me = lp.peers[0].engine.tid();
        let b = lp.peers[1].engine.tid();
        lp.sync(1, 0).unwrap();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, me);
        m.set(t, &osis_core::Ak::new("/x/a").unwrap(), &Value::Int(1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        let edge = ct::Edge { role: Role::Read, until: None, invite: None, since: None };
        let g = *lp.peers[0].engine.grant(&t, &b, &edge).unwrap().commits.last().unwrap();
        let p = lp.peers[0].engine.package(&g).unwrap().unwrap();
        // what MAX_READING bogus grant claims under throwaway authors leave
        let mut bogus = ActorEpochs::default();
        for n in 0..osis_keys::MAX_READING {
            let x = u8::try_from(n % 256).unwrap();
            let y = u8::try_from(n / 256).unwrap();
            bogus.read.set_reading_secret(Epoch::new(1, [x; 16]).unwrap(), Secret32::from_bytes([x; 32]), Unchecked { author: Tid::from_bytes([x ^ 0x55, y, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), commit: CommitId([x; 32]) });
        }
        lp.peers[1].engine.core.secrets.insert(t, bogus);
        lp.deliver(1, &p).unwrap();
        let read = lp.peers[1].engine.core.secrets.get(&t).map(|e| e.read.held_newest_first().len()).unwrap_or(0);
        assert_eq!(read, osis_keys::MAX_READING, "bounded; the genuine grant's candidate waits for its grant to apply");
    }

    // spec/crypto.md §4, spec/permissions.md §3: a pending commit that applies or is dropped
    // takes its reading-only candidates; an actor they were the only secrets of is handed to
    // the lost-access trigger, which forgets it.
    #[test]
    fn applied_commit_hands_reading_only_actor_to_lost_trigger_spec_crypto_4() {
        let mut lp = LocalPeer::new(1, 908, WallMs(1_700_000_000_000)).unwrap();
        let (x, c) = (Tid::from_bytes([9; 15]), CommitId([9; 32]));
        lp.peers[0].engine.core.secrets.insert(x, reading_only(9, c));
        lp.peers[0].engine.run(|tx| super::forget_unchecked(tx, &c)).unwrap();
        assert!(lp.peers[0].engine.core.lost_due.contains(&x));
        lp.peers[0].engine.drop_lost_due().unwrap();
        assert!(lp.peers[0].engine.core.secrets.get(&x).is_none_or(|e| e.read.held_newest_first().is_empty()));
    }
}
