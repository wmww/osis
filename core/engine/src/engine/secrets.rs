//! Secrets the engine holds (spec/crypto.md §3–§4): the node's own role secrets, derived secrets
//! of plain things, epochs of actors with secrets of their own opened from `/secrets` (kept
//! in the store per actor), dedup secrets from creation records, delete keys
//! (spec/crypto.md §7), and the `Secrets` osis-commit asks for when building a commit.

use super::Core;
use osis_base::CommitId;
use crate::error::{Error, Result};
use osis_base::{CreationRecord, Role, Tid, Value};
use osis_crypto::{DeleteSecret, Epoch, Secret32, VerifyingKey, dedup_secret};
use osis_keys::{ActorEpochs, HistoryAlts, Opener, Provenance, ROLES, Unchecked};
use osis_schema::AspectKey;
use osis_schema::core_types::{Keys, Secrets, SigningKey};
use std::collections::BTreeMap;

/// Owner chains end at a key actor within `MAX_OWNER_DEPTH` links (spec/permissions.md §1).
const MAX_CHAIN: usize = osis_base::format::MAX_OWNER_DEPTH + 1;

impl Core {
    pub fn created(&self, tid: &Tid) -> Option<&CreationRecord> {
        self.ix.held.created(tid)
    }

    pub(crate) fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.created(tid).map(|r| dedup_secret(r.nonce()))
    }

    /// The epochs this node holds for `tid`: its own, opened ones, or derived from the owner's
    /// for a plain thing without secrets of its own. A plain thing's epochs learned from a
    /// rotation since found invalid (`stale_epochs`) are added for reading only.
    pub(crate) fn epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let d = self.chain_epochs(tid);
        let Some(x) = self.stale_epochs(tid) else { return d };
        // no owner's epochs held: the leftovers alone, still reading-only (this node's own
        // invalid rotation's are `Own`)
        let mut d = d.unwrap_or_default();
        for r in ROLES {
            for (ep, info) in x.role(r).epochs() {
                if d.role(r).get(ep).is_none() {
                    let i = d.role_mut(r).observe(*ep);
                    *i = info.clone();
                    i.established = None;
                }
            }
        }
        Some(d)
    }

    fn chain_epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let mut chain = Vec::new();
        let mut cur = *tid;
        for _ in 0..MAX_CHAIN {
            let held = (cur == self.id.tid()).then(|| self.id.epochs()).or_else(|| self.key_actors.get(&cur).map(|k| k.epochs())).or_else(|| self.own_epochs(&cur).cloned());
            if let Some(mut e) = held {
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if self.ix.own_keys.contains(&cur) {
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

    /// The opened epochs of `tid` when they make it an actor with secrets of its own here: it is
    /// in `own_keys`, is no known thing, or, no keyset part of it held (`keyset_parts`), holds an epoch
    /// established by an applied valid rotation or a held snapshot, a valid `/secrets` part or an
    /// inbox hint of its delete keys. Not by this node's own rotation alone: that commit may have
    /// turned invalid.
    pub(crate) fn own_epochs(&self, tid: &Tid) -> Option<&ActorEpochs> {
        let e = self.ix.secrets.get(tid)?;
        let thing = matches!(self.created(tid), Some(CreationRecord::Thing { .. }));
        if self.ix.own_keys.contains(tid) || !thing {
            return Some(e);
        }
        // a held keyset part decides: all invalid, the thing is plain (a valid grant boxing under
        // that keyset's epochs counts for nothing; its derived epochs may predate a rotation of
        // the owner)
        if self.ix.keyset_parts.get(tid).is_some_and(|s| !s.is_empty()) {
            return None;
        }
        let rotated = || ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| matches!(i.established, Some(Provenance::Chain | Provenance::Snapshot))));
        (rotated() || self.ix.delete_hints.contains_key(tid) || self.valid_secrets_part(tid)).then_some(e)
    }

    /// Whether a held membership commit's `/secrets` part on `tid` is valid (only a thing with
    /// secrets of its own has boxes: a grant whose target's `/keys` is not held yet).
    fn valid_secrets_part(&self, tid: &Tid) -> bool {
        let Ok(ak) = osis_base::Ak::new("/secrets") else { return false };
        self.ix.by_aspect.get(&(*tid, ak)).into_iter().flatten().any(|(_, c)| {
            self.ix.commits.get(c).is_some_and(|m| m.view.kind.is_membership() && m.view.aspects.iter().enumerate().any(|(ai, a)| a.tid == *tid && a.ak.as_str() == "/secrets" && m.valid.get(ai).copied().unwrap_or(false)))
        })
    }

    /// The opened epochs of a plain thing `tid` that are not its own (`own_epochs`): what a
    /// rotation since found invalid gave it (spec/crypto.md §3, §4), kept for reading.
    fn stale_epochs(&self, tid: &Tid) -> Option<&ActorEpochs> {
        if self.own_epochs(tid).is_some() {
            return None;
        }
        self.ix.secrets.get(tid)
    }

    /// The delete base of `tid` (spec/crypto.md §7): the nearest actor in its owner chain,
    /// itself first, with secrets of its own (all three roles at once, spec/crypto.md §3), or the
    /// key actor the chain ends at.
    pub(crate) fn delete_base(&self, tid: &Tid) -> Option<DeleteBase> {
        let mut cur = *tid;
        for _ in 0..MAX_CHAIN {
            if cur == self.id.tid() {
                return Some(DeleteBase::KeyActor(self.id.keys().signing.verifying_key()));
            }
            if let Some(k) = self.key_actors.get(&cur) {
                return Some(DeleteBase::KeyActor(k.keys().signing.verifying_key()));
            }
            if let Some(e) = self.own_epochs(&cur) {
                return Some(DeleteBase::Actor(cur, Some(e.clone())));
            }
            if self.ix.own_keys.contains(&cur) {
                return Some(DeleteBase::Actor(cur, None));
            }
            match self.created(&cur)? {
                CreationRecord::Thing { owner, .. } => cur = *owner,
                CreationRecord::KeyActor { public_key, .. } => return VerifyingKey::from_slice(public_key).ok().map(DeleteBase::KeyActor),
            }
        }
        None
    }

    /// The delete secrets this node may hold along the owner chain of `tid`, itself first: a
    /// delete key a header lists for `tid` is one of them (a thing that got secrets of its own
    /// keeps content of its derived era under its former base's keys).
    pub(crate) fn delete_chain(&self, tid: &Tid) -> Vec<DeleteSource> {
        let mut out = Vec::new();
        let mut cur = *tid;
        for _ in 0..MAX_CHAIN {
            let seed = if cur == self.id.tid() { Some(self.id.seed().clone()) } else { self.key_actors.get(&cur).map(|k| k.seed().clone()) };
            if let Some(seed) = seed {
                out.push(DeleteSource::KeyActor(DeleteSecret::from_seed(osis_crypto::kdf::kdf(osis_crypto::kdf::SIGN, seed.expose(), b""))));
                break;
            }
            if let Some(e) = self.ix.secrets.get(&cur) {
                out.push(DeleteSource::Epochs(e.clone()));
            }
            match self.created(&cur) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => break,
            }
        }
        out
    }

    /// The delete secret of `level` matching a header's delete key `key` (spec/crypto.md §7),
    /// tried over every held epoch along the chains: `thing` the chain of the delta's thing,
    /// `author` that of the actor above its author node (empty for an import).
    pub(crate) fn delete_secret(level: u8, key: &[u8; 32], thing: &[DeleteSource], author: &[DeleteSource]) -> Option<DeleteSecret> {
        let chain = if level == osis_base::format::DELETE_AUTHOR { author } else { thing };
        for src in chain {
            match src {
                DeleteSource::KeyActor(d) if d.verifying_key().to_bytes() == *key => return Some(DeleteSecret::from_seed(d.seed().clone())),
                DeleteSource::KeyActor(_) => {}
                DeleteSource::Epochs(e) => {
                    let found = osis_keys::delete_candidates(level, e, Some(e)).into_iter().map(|(_, s)| DeleteSecret::derive(s)).find(|d| d.verifying_key().to_bytes() == *key);
                    if found.is_some() {
                        return found;
                    }
                }
            }
        }
        None
    }

    /// Opens what `/secrets` of `actor` holds for this node or for actors it holds secrets of
    /// (spec/crypto.md §4). `unchecked`: `None` when `secrets` is the applied valid state; the
    /// source for the boxes of a pending commit, whose secrets are kept for reading only.
    /// Returns whether anything new was learned.
    /// `alts`: the live entries of history keys holding several (each tried).
    pub(crate) fn ingest_secrets(&mut self, actor: &Tid, secrets: &Secrets, unchecked: Option<Unchecked>, alts: &HistoryAlts) -> bool {
        let before = self.ix.secrets.get(actor).cloned();
        // a bounded number of actors held through reading-only secrets alone
        let reading_only = |e: &ActorEpochs| ROLES.iter().all(|r| e.role(*r).held().next().is_none()) && e.holds_any();
        if unchecked.is_some() && before.as_ref().is_none_or(|e| !e.holds_any()) && self.ix.secrets.iter().filter(|(t, e)| *t != actor && reading_only(e)).count() >= MAX_READING_ACTORS {
            return false;
        }
        let mut epochs = before.clone().unwrap_or_default();
        let seed = self.id.seed().clone();
        let me = self.id.tid();
        let mut openers: Vec<(Tid, ActorEpochs)> = self.ix.secrets.iter().filter(|(t, _)| *t != actor).map(|(t, e)| (*t, e.clone())).collect();
        openers.sort_by_key(|x| x.0);
        let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { member: me, seed: &seed }, &mut epochs, unchecked);
        for (t, k) in &self.key_actors {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { member: *t, seed: k.seed() }, &mut epochs, unchecked);
        }
        for (m, e) in &openers {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::Actor { member: *m, epochs: e }, &mut epochs, unchecked);
        }
        self.adopt_derived(actor, &mut epochs);
        let held_any = epochs.holds_any();
        if held_any && Some(&epochs) != before.as_ref() {
            self.ix.secrets.insert(*actor, epochs);
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
            learned |= self.ingest_secrets(actor, &s, None, &alts);
            let Some(e) = self.ix.secrets.get(actor) else { break };
            let candidates: Vec<Value> = ROLES
                .iter()
                .flat_map(|r| e.role(*r).epochs().filter(|(_, i)| i.secret.is_some()).map(|(ep, _)| osis_schema::Codec::to_value(&osis_keys::aspects::history_key(*r, ep))).collect::<Vec<_>>())
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
    /// and labels registered under them can be stepped. A derived epoch's ID names its secret, so
    /// only an owner epoch whose secret is held matches.
    pub(crate) fn adopt_derived(&self, actor: &Tid, epochs: &mut ActorEpochs) {
        let Some(CreationRecord::Thing { owner, .. }) = self.created(actor) else { return };
        let Some(o) = self.epochs(owner) else { return };
        let d = ActorEpochs::derived(&o, actor);
        let mut any = false;
        for r in ROLES {
            for (ep, info) in d.role(r).epochs() {
                if info.established.is_some() && info.secret.is_some() && epochs.role(r).get(ep).is_some() && !epochs.role(r).is_established(ep) {
                    epochs.role_mut(r).set_established(*ep, Provenance::Derived);
                    any = true;
                }
            }
        }
        if any {
            epochs.establish();
        }
    }

    /// Notes the `/keys` state of `actor`: its published delete keys replace any inbox hint, and
    /// the keysets' epochs and suites are recorded with its epochs. Whether it has secrets of its
    /// own is the parts' (`apply::keys::refresh_own_keys`), not the state's.
    pub(crate) fn observe_keys(&mut self, actor: &Tid, keys: &Keys) {
        if keys.read.is_some() || keys.write.is_some() || keys.admin.is_some() {
            self.ix.delete_hints.remove(actor);
            self.membership_changed();
            if let Some(e) = self.ix.secrets.get_mut(actor) {
                let _ = osis_keys::observe_keys(keys, e);
            }
        }
    }
}

/// The delete base of a thing (spec/crypto.md §7).
pub(crate) enum DeleteBase {
    /// An actor with secrets of its own, with its epochs when held.
    Actor(Tid, Option<ActorEpochs>),
    /// A key actor: its signing key is its delete key at every level.
    KeyActor(VerifyingKey),
}

/// A held source of delete secrets along an owner chain.
pub(crate) enum DeleteSource {
    Epochs(ActorEpochs),
    /// A key actor's signing key.
    KeyActor(DeleteSecret),
}

/// What a commit build asks for (osis-commit `Secrets`).
pub struct CommitSecrets<'c> {
    pub core: &'c Core,
    /// The actor the commit acts for.
    pub actor: Tid,
    /// Creation records of things the commit creates.
    pub created: &'c crate::engine::write::Creates,
    /// Delete keys published in `/keys` of delete bases whose secret of that role is not held
    /// ([`published_keys`]).
    pub published: &'c BTreeMap<(Tid, Role), VerifyingKey>,
}

/// The delete base of `tid` ([`Core::delete_base`]); a thing `created` in this commit is plain,
/// so it uses its owner's.
fn base_of(core: &Core, created: &crate::engine::write::Creates, tid: &Tid) -> Option<DeleteBase> {
    let mut cur = *tid;
    for _ in 0..=created.len() {
        match created.get(&cur) {
            Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
            Some(CreationRecord::KeyActor { public_key, .. }) => return VerifyingKey::from_slice(public_key).ok().map(DeleteBase::KeyActor),
            None => return core.delete_base(&cur),
        }
    }
    None
}

/// The admin and write delete keys published in `/keys` (spec/crypto.md §3, §7) of the delete
/// bases of `tids` whose secret of that role this node does not hold: a writer that is no admin
/// lists the admin one.
pub(crate) fn published_keys(tx: &mut crate::engine::Tx<'_>, created: &crate::engine::write::Creates, tids: impl IntoIterator<Item = Tid>) -> Result<BTreeMap<(Tid, Role), VerifyingKey>> {
    let mut need = std::collections::BTreeSet::new();
    for t in tids {
        for r in [Role::Admin, Role::Write] {
            if let Some(DeleteBase::Actor(b, e)) = base_of(tx.core, created, &t)
                && e.is_none_or(|e| e.role(r).newest_held().is_none())
            {
                need.insert((b, r));
            }
        }
    }
    if !need.is_empty() {
        // the keys an inbox payload named stand in until `/keys` arrives
        tx.core.promote_hints();
    }
    let mut out = BTreeMap::new();
    for (b, r) in need {
        let keys = Core::keys_in(tx, &b)?;
        let ks = keys.and_then(|k| if r == Role::Admin { k.admin } else { k.write });
        let published = match ks.map(|ks| ks.delete_key) {
            Some(SigningKey::Ed25519(k)) => VerifyingKey::from_slice(&k).ok(),
            _ => None,
        };
        let hinted = || match tx.core.ix.delete_hints.get(&b) {
            Some(Value::List(x)) => x.get(usize::from(r != Role::Admin)).and_then(|v| if let Value::Bytes(k) = v { VerifyingKey::from_slice(k).ok() } else { None }),
            _ => None,
        };
        if let Some(vk) = published.or_else(hinted) {
            out.insert((b, r), vk);
        }
    }
    Ok(out)
}

/// The current admin and write delete keys of `t` when it is its own delete base (it has
/// secrets of its own): from held secrets, else published or hinted; for an inbox payload.
pub(crate) fn own_delete_keys(tx: &mut crate::engine::Tx<'_>, t: &Tid) -> Result<Option<(VerifyingKey, VerifyingKey)>> {
    let Some(DeleteBase::Actor(b, e)) = tx.core.delete_base(t) else { return Ok(None) };
    if b != *t {
        return Ok(None);
    }
    let published = published_keys(tx, &Default::default(), [*t])?;
    let key = |r: Role| e.as_ref().and_then(|e| newest_delete_key(e, r)).or_else(|| published.get(&(b, r)).copied());
    Ok(key(Role::Admin).zip(key(Role::Write)))
}

impl crate::Engine {
    /// [`own_delete_keys`] of `t`.
    pub fn own_delete_keys(&mut self, t: &Tid) -> Result<Option<(VerifyingKey, VerifyingKey)>> {
        let t = *t;
        self.run(|tx| own_delete_keys(tx, &t))
    }

    /// Notes the delete keys the inbox payload of commit `c` names (spec/wire.md §9) as
    /// candidates: kept only once `c` applies valid ([`Core::promote_hints`]).
    pub fn note_delete_hints(&mut self, c: CommitId, things: &[osis_label::InboxThing]) -> Result<()> {
        let hints: Vec<(Tid, Value)> = things.iter().filter_map(|t| t.delete_keys.map(|(a, w)| (t.tid, Value::List(vec![Value::Bytes(a.to_bytes().to_vec()), Value::Bytes(w.to_bytes().to_vec())])))).collect();
        if hints.is_empty() {
            return Ok(());
        }
        self.run(|tx| {
            let cands = &mut tx.core.ix.hint_candidates;
            if !cands.contains_key(&c) {
                if cands.len() >= MAX_HINT_COMMITS
                    && let Some(first) = cands.keys().next().copied()
                {
                    cands.remove(&first);
                }
                cands.insert(c, hints);
            }
            tx.core.promote_hints();
            Ok(())
        })
    }
}

/// Inbox commits whose hints wait for their commit to apply.
const MAX_HINT_COMMITS: usize = 64;

impl Core {
    /// Keeps the hints of candidate commits that applied: a thing's hint only from a commit
    /// touching it with valid deltas, by an author with admin on it at the commit's `ts`, and
    /// only while no hint and no `/keys` with keysets is held for it (the first stays).
    pub(crate) fn promote_hints(&mut self) {
        let applied: Vec<CommitId> = self.ix.hint_candidates.keys().filter(|c| self.ix.commits.contains_key(c)).copied().collect();
        for c in applied {
            let Some(hints) = self.ix.hint_candidates.remove(&c) else { continue };
            let Some(m) = self.ix.commits.get(&c) else { continue };
            let h = m.header.clone();
            let ok: Vec<(Tid, Value)> = hints
                .into_iter()
                .filter(|(t, _)| {
                    let mut touched = h.aspects.iter().enumerate().filter(|(_, a)| a.tid == *t).peekable();
                    touched.peek().is_some() && touched.all(|(i, _)| m.valid.get(i).copied().unwrap_or(false))
                })
                .filter(|(t, _)| crate::engine::write::role_of(self, &h.author, t, h.ts) == Some(Role::Admin))
                .collect();
            for (t, v) in ok {
                if !self.ix.delete_hints.contains_key(&t) && !self.ix.own_keys.contains(&t) {
                    self.ix.delete_hints.insert(t, v);
                }
            }
        }
    }
}

impl osis_commit::Secrets for CommitSecrets<'_> {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.core.dedup(tid).or_else(|| self.created.get(tid).map(|r| dedup_secret(r.nonce())))
    }
    fn admin_key(&self, tid: &Tid) -> Option<VerifyingKey> {
        self.key(tid, Role::Admin)
    }
    fn chain_key(&self) -> Option<VerifyingKey> {
        // the author's own actor: from a secret this node holds, never a published key (a node
        // cannot sign as an actor it does not act for)
        match self.core.delete_base(&self.actor)? {
            DeleteBase::KeyActor(k) => self.chain_holder().then_some(k),
            DeleteBase::Actor(_, e) => newest_delete_key(&e?, Role::Write),
        }
    }
    fn write_key(&self, tid: &Tid) -> Option<VerifyingKey> {
        self.key(tid, Role::Write)
    }
}

impl CommitSecrets<'_> {
    /// Whether this node holds the key actor at the end of the commit actor's owner chain.
    fn chain_holder(&self) -> bool {
        let mut cur = self.actor;
        for _ in 0..MAX_CHAIN {
            if cur == self.core.id.tid() || self.core.key_actors.contains_key(&cur) {
                return true;
            }
            match self.core.created(&cur) {
                Some(CreationRecord::Thing { owner, .. }) => cur = *owner,
                _ => return false,
            }
        }
        false
    }

    /// The delete key of role `r` of `tid`'s delete base: a key actor's signing key, else from
    /// the newest held secret of the role, else the published one.
    fn key(&self, tid: &Tid, r: Role) -> Option<VerifyingKey> {
        match base_of(self.core, self.created, tid)? {
            DeleteBase::KeyActor(k) => Some(k),
            DeleteBase::Actor(b, e) => e.and_then(|e| newest_delete_key(&e, r)).or_else(|| self.published.get(&(b, r)).copied()),
        }
    }
}

/// The delete key of the newest held secret of role `r` (spec/crypto.md §7).
fn newest_delete_key(e: &ActorEpochs, r: Role) -> Option<VerifyingKey> {
    e.role(r).newest_held().map(|(_, s)| DeleteSecret::derive(s).verifying_key())
}

// ---- local encoding of held epochs (the store's actor secrets unit)

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
                            Value::uint(i.suite),
                            Value::List(i.applied.iter().map(|(c, sup)| Value::List(vec![Value::Bytes(c.0.to_vec()), Value::List(sup.iter().map(Epoch::to_wire).collect())])).collect()),
                            Value::Bool(i.snapshot),
                            Value::List(i.established.iter().map(|p| Value::uint(provenance_code(*p))).collect()),
                            Value::List(i.supersedes.iter().map(Epoch::to_wire).collect()),
                            Value::List(i.secret.iter().map(|s| Value::Bytes(s.expose().to_vec())).collect()),
                            Value::List(i.reading.iter().map(|u| Value::List(vec![Value::Bytes(u.author.as_bytes().to_vec()), Value::Bytes(u.commit.0.to_vec())])).collect()),
                        ])
                    })
                    .collect(),
            )
        })
        .collect();
    osis_base::encode(&Value::List(roles))
}

/// Most actors this node holds through reading-only secrets alone (local policy: pending
/// commits naming made-up actors cannot grow it without bound).
pub(crate) const MAX_READING_ACTORS: usize = 64;

/// The live entries of history keys holding several in a `/secrets` state (puts of one key by
/// different writers): readers try each, so a newer entry does not hide the genuine box.
pub(crate) fn history_alts(f: &osis_crdt::Fragment) -> HistoryAlts {
    let mut out = HistoryAlts::new();
    let Some(m) = history_map(f) else { return out };
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

pub(crate) fn decode_epochs(b: &[u8]) -> Result<ActorEpochs> {
    let bad = || Error::Corrupt("epochs");
    let lim = osis_base::Limits { max_depth: 16, max_bytes: b.len() };
    let Value::List(roles) = osis_base::decode(b, &lim).map_err(|_| bad())? else { return Err(bad()) };
    let mut a = ActorEpochs::default();
    for (r, items) in ROLES.iter().zip(roles) {
        let Value::List(items) = items else { return Err(bad()) };
        for it in items {
            let Value::List(f) = it else { return Err(bad()) };
            let [e, Value::Int(suite), Value::List(applied), Value::Bool(snapshot), Value::List(est), Value::List(sup), Value::List(sec), Value::List(reading)] = f.as_slice() else { return Err(bad()) };
            let e = Epoch::from_wire(e).map_err(|_| bad())?;
            let info = a.role_mut(*r).observe(e);
            info.suite = u64::try_from(*suite).map_err(|_| bad())?;
            info.snapshot = *snapshot;
            for ap in applied {
                let Value::List(ap) = ap else { return Err(bad()) };
                let [Value::Bytes(c), Value::List(sup)] = ap.as_slice() else { return Err(bad()) };
                let c = CommitId(c.as_slice().try_into().map_err(|_| bad())?);
                info.applied.insert(c, sup.iter().map(Epoch::from_wire).collect::<std::result::Result<_, _>>().map_err(|_| bad())?);
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
                info.secret = Some(secret(s)?);
            }
            for c in reading {
                let Value::List(c) = c else { return Err(bad()) };
                let [Value::Bytes(author), Value::Bytes(commit)] = c.as_slice() else { return Err(bad()) };
                let author = Tid::from_bytes(author.as_slice().try_into().map_err(|_| bad())?);
                let commit = osis_base::CommitId(commit.as_slice().try_into().map_err(|_| bad())?);
                info.reading.insert(Unchecked { author, commit });
            }
            if !info.reading.is_empty() && info.secret.is_none() {
                return Err(bad());
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
        let (e1, e2) = (Epoch::new(1, [1; 32]).unwrap(), Epoch::new(2, [2; 32]).unwrap());
        a.read.set_secret(e1, Secret32::from_bytes([1; 32]));
        a.read.set_established(e1, Provenance::Own);
        let from = |n: u8| Unchecked { author: Tid::from_bytes([n; 15]), commit: osis_base::CommitId([n; 32]) };
        a.read.set_reading_secret(e2, Secret32::from_bytes([2; 32]), from(1));
        a.read.set_reading_secret(e2, Secret32::from_bytes([2; 32]), from(2));
        a.read.set_established(e2, Provenance::Chain);
        a.read.set_applied(e2, osis_base::CommitId([9; 32]), []);
        let b = decode_epochs(&encode_epochs(&a)).unwrap();
        assert_eq!(b, a);
        assert!(b.read.is_reading_only(&e2) && b.read.secret(&e2).is_none());
        assert_eq!(b.read.newest_held().map(|x| x.0), Some(e1));
    }

    // spec/crypto.md §4: every live entry of a history key with several (puts by different
    // writers) is offered to readers, not only their merged read.
    #[test]
    fn history_alts_lists_live_entries() {
        use osis_crdt::{Batch, Op, PathOp, PathSeg, Source, Writer};
        use osis_schema::Codec;
        let schema = osis_schema::core_schema();
        let view = schema.view("/secrets").unwrap();
        let k = osis_schema::core_types::HistoryKey { role: Role::Read, epoch: osis_keys::aspects::to_schema(&Epoch::new(1, [1; 32]).unwrap()) };
        let mut st = osis_crdt::Fragment::default();
        for (n, b) in [(1u8, 0x11u8), (2, 0x22)] {
            let ts = osis_base::Ts::make(osis_base::WallMs(u64::from(n) * 1000), 0).unwrap();
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
