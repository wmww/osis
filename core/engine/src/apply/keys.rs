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
/// box, and the earliest of its epoch (`Core::epoch_intro`).
pub(crate) fn note_box_keys(core: &mut Core, h: &Header, actor: &Tid, delta: &Fragment) {
    if let Some(m) = map(field(delta, 0)) {
        for (_, _, k, f) in m.entries() {
            let Some(k) = k else { continue };
            if f.is_none() {
                continue;
            }
            let Some(bk) = typed(k, "box_key").and_then(|k| BoxKey::from_value(&k).ok()) else { continue };
            core.ix.boxes_to.insert(bk.member, (*actor, k.clone()));
            if let Ok(e) = osis_keys::aspects::from_schema(&bk.epoch) {
                note_intro(core, h, actor, bk.role, e);
            }
            core.ix.box_written.upsert((*actor, bk), || h.ts, |w| *w = (*w).min(h.ts));
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
        let keys_ak = osis_base::Ak::new("/keys").map_err(|_| crate::Error::Misuse("ak"))?;
        let before = tx.state(&a.tid, &keys_ak)?.and_then(Fragment::read).and_then(|v| ct::KEYS.decode(&v).ok()).unwrap_or_default();
        out.push(Pending { id: h.id(), ai: *ai, actor: a.tid, keys, before });
    }
    Ok(out)
}

/// Secrets held that may be encrypted under, over the roles.
fn held_count(e: &osis_keys::ActorEpochs) -> usize {
    ROLES.iter().map(|r| e.role(*r).held().count()).sum()
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
        let held = held_count(e);
        let recorded = w.applied(e, (&p.keys, &p.before)).unwrap_or(false);
        if recorded {
            save(tx, &actor)?;
        }
        // a keyset it published refuted a held secret (the boxes may carry the genuine one),
        // or its keysets and history boxes may check candidates: reopen
        let reopen = |e: &osis_keys::ActorEpochs| held_count(e) < held || (recorded && ROLES.iter().any(|r| e.role(*r).epochs().any(|(x, _)| e.role(*r).is_reading_only(x))));
        if tx.core.ix.secrets.get(&actor).is_some_and(reopen) {
            super::atomic::observe_state(tx, &actor, &osis_base::Ak::new("/secrets").map_err(|_| crate::Error::Misuse("ak"))?)?;
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

/// A held commit's `/secrets` delta became invalid: its rotations are no longer applied.
pub(crate) fn invalidated(tx: &mut Tx<'_>, c: &CommitId, ai: usize) -> Result<()> {
    let Some(h) = tx.core.ix.commits.get(c).map(|m| m.header.clone()) else { return Ok(()) };
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
            for k in secrets_write(&d.fragment).history.keys() {
                if let Ok(e) = osis_keys::aspects::from_schema(&k.epoch)
                    && keys.keysets.get(&k.role).is_some_and(|ks| ks.epoch == k.epoch)
                {
                    eps.push((k.role, e));
                }
            }
        }
    }
    tx.core.touch();
    if let Some(e) = tx.core.ix.secrets.get_mut(&a.tid) {
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
    if secrets.applied(e, (&keys, &before)).unwrap_or(false) {
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
    let prefix = [SEALED, &id.0[..]].concat();
    let mut sealed = Vec::new();
    tx.scan(&prefix, |k, _| {
        sealed.push([prefix.as_slice(), k].concat());
        Ok(())
    })?;
    for k in sealed {
        tx.txn.remove_local(&k, Shred::No)?;
    }
    let actors: Vec<Tid> = tx.core.ix.secrets.iter().filter(|(_, e)| ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.reading.iter().any(|(_, u)| u.commit == *id)))).map(|(t, _)| *t).collect();
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
    /// by static entry, spec/sync.md §2): unestablished, and an unverified candidate kept for
    /// reading only (anyone holding the head's step key, a removed admin among them, can write
    /// the box) until it derives the epoch's published keyset or an applied valid box carries
    /// the secret (spec/crypto.md §4).
    pub fn learn_read_secret(&mut self, g: &Tid, e: osis_crypto::Epoch, secret: osis_crypto::Secret32) -> Result<()> {
        let g = *g;
        self.run(|tx| {
            tx.core.touch();
            let ep = tx.core.ix.secrets.entry_or_default(g);
            ep.role_mut(Role::Read).learn_unverified(e, secret);
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
                held.read.set_established(Epoch::new(1, [0; 16]).unwrap(), osis_keys::Provenance::Own);
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
        held.read.set_established(Epoch::new(1, [0; 16]).unwrap(), osis_keys::Provenance::Own);
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
    // reading-only: it names the next epoch before that epoch's rotation reaches the node, yet
    // the genuine box replaces it and the node encrypts under the genuine secret only.
    #[test]
    fn entry_box_secret_reading_only_until_box_spec_crypto_4() {
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
        lp.peers[1].engine.learn_read_secret(&t, e_new, planted.clone()).unwrap();
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert!(e1.read.secret(&e_new).is_none() && e1.read.reading_secrets(&e_new) == vec![&planted]);
        lp.sync(0, 1).unwrap();
        let e1 = lp.peers[1].engine.epochs(&t).unwrap();
        assert_eq!(e1.read.newest_held(), Some((e_new, &genuine)));
        assert_eq!(e1.read.reading_secrets(&e_new), vec![&genuine], "the planted one is gone");
        assert_eq!(lp.peers[1].engine.wrap_secret(&t, None).unwrap().as_ref(), Some(&genuine));
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
        held.read.set_established(Epoch::new(1, [0; 16]).unwrap(), osis_keys::Provenance::Own);
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
}
