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
use osis_keys::{KeysWrite, SecretsWrite};
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

/// Records the box keys of keyed `/secrets` entries (a removal names only the entry's dot).
pub(crate) fn note_box_keys(core: &mut Core, actor: &Tid, delta: &Fragment) {
    if let Some(m) = map(field(delta, 0)) {
        for (d, _, k, _) in m.entries() {
            if let Some(k) = k {
                core.box_keys.entry((*actor, d.clone())).or_insert_with(|| k.clone());
            }
        }
    }
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
        if a.ak.as_str() != "/secrets" || !valid.get(*ai).copied().unwrap_or(false) {
            continue;
        }
        let Decoded::Delta(d) = d else { continue };
        note_box_keys(tx.core, &a.tid, &d.fragment);
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
            let e = tx.core.secrets.entry(actor).or_default();
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
            let e = tx.core.secrets.entry(a.tid).or_default();
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
    let mut eps = Vec::new();
    for d in super::held_parts(tx, c, ai)? {
        if let Decoded::Delta(d) = d {
            for k in secrets_write(tx.core, &a.tid, &d.fragment).0.history.keys() {
                if let Ok(e) = osis_keys::aspects::from_schema(&k.epoch) {
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
    let e = tx.core.secrets.entry(a.tid).or_default();
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
/// it holds (issues/pending-boxes.md, decided; spec/crypto.md §4: such secrets are "kept for
/// reading"): the epochs are recorded unestablished, so a grantee whose grant waits for the
/// target's `/created` and chain can open the target's label and download them. Parts are
/// decoded unverified, so what they yield is reading-only: never encrypted under, and replaced
/// by an applied valid box (spec/crypto.md §4).
pub(crate) fn read_pending_boxes(tx: &mut Tx<'_>, blob: &osis_commit::CommitBlob, id: &CommitId) -> Result<()> {
    for (a, w) in pending_secrets_writes(tx.core, blob, id) {
        if w.boxes.is_empty() && w.history.is_empty() {
            continue;
        }
        let s = ct::Secrets { boxes: w.boxes, history: w.history.into_iter().collect() };
        tx.core.touch();
        if tx.core.ingest_secrets(&a, &s, false) {
            crate::flows::save_epochs(tx, &a)?;
        }
    }
    Ok(())
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
            let ep = tx.core.secrets.entry(g).or_default();
            ep.role_mut(Role::Read).observe(e);
            ep.role_mut(Role::Read).set_secret(e, secret);
            crate::flows::save_epochs(tx, &g)
        })
    }
}
