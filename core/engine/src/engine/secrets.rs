//! Secrets the engine holds (spec/crypto.md §3–§4): the node's own role secrets, derived secrets
//! of plain things, epochs of actors with secrets of their own opened from `secrets.0` (kept
//! in the store per actor), dedup secrets from creation records, delete keys
//! (spec/crypto.md §7), and the `Secrets` osis-commit asks for when building a commit.

use super::Core;
use osis_base::CommitId;
use crate::error::{Error, Result};
use osis_base::{ChainStep, CreationRecord, Owner, OwnerChain, Role, Tid, Value};
use osis_crypto::{DeleteSecret, Epoch, Secret32, VerifyingKey, dedup_secret};
use osis_keys::{ActorEpochs, HistoryAlts, Name, Opener, Own, Provenance, ROLES, Unchecked};
use osis_schema::RawKey;
use osis_schema::core_types::{Keys, Secrets, SigningKey};
use std::collections::BTreeMap;

impl Core {
    /// The steps up `tid`'s record chain through the held records (`osis_base::owner_chain`).
    pub(crate) fn owner_chain(&self, tid: &Tid) -> OwnerChain<impl FnMut(&Tid) -> Option<Owner> + '_> {
        osis_base::owner_chain(*tid, |t| self.created(t).map(CreationRecord::owner_link))
    }

    /// The creation record of `tid`, durable or memory class (an ephemeral thing's).
    pub fn created(&self, tid: &Tid) -> Option<&CreationRecord> {
        self.ix.held.created(tid)
    }

    /// The record of `tid` if durable: what durable data may refer to (no durable row refers to
    /// a memory row, notes/local-store.md Memory overlay).
    pub fn durable_created(&self, tid: &Tid) -> Option<&CreationRecord> {
        self.created(tid).filter(|_| !self.ix.held.is_memory(tid))
    }

    /// The record of `tid` as a commit of class `memory` may use: a durable commit sees durable
    /// records only.
    pub fn created_for(&self, tid: &Tid, memory: bool) -> Option<&CreationRecord> {
        if memory { self.created(tid) } else { self.durable_created(tid) }
    }

    pub(crate) fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.created(tid).map(|r| dedup_secret(r.nonce()))
    }

    /// The epochs this node holds for `tid`: its own, opened ones, or derived from those of the
    /// next actor up its record chain (owner or first admin) for a plain thing. A plain thing's
    /// epochs learned from a rotation since found invalid (`stale_epochs`) are added for reading
    /// only.
    pub(crate) fn epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let d = self.chain_epochs(tid).or_else(|| self.unboxed_epochs(tid));
        let Some(x) = self.stale_epochs(tid) else { return d };
        // no owner's epochs held: the leftovers alone, still reading-only
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
        for step in self.owner_chain(tid) {
            let cur = step.thing()?;
            let held = (cur == self.id.tid()).then(|| self.id.epochs()).or_else(|| self.key_actors.get(&cur).map(|k| k.epochs())).or_else(|| self.own_epochs(&cur));
            if let Some(mut e) = held {
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if self.ix.own_keys.contains(&cur) {
                return None;
            }
            match step {
                ChainStep::Up { .. } | ChainStep::Ownerless { .. } => chain.push(cur),
                _ => return None,
            }
        }
        None
    }

    /// A thing whose keyset came under another label (spec/permissions.md §4) before any secret of
    /// it: the read epochs the next actor up its record chain derives, reading only. That actor's
    /// nodes open its label with them; the rotation boxing it is wrapped under them (spec/crypto.md
    /// §5).
    fn unboxed_epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        if !self.ix.own_keys.contains(tid) || self.ix.secrets.get(tid).is_some() {
            return None;
        }
        let up = self.created(tid)?.up()?;
        let derived = ActorEpochs::derived(&self.chain_epochs(&up)?, tid);
        let mut out = ActorEpochs::default();
        for (ep, info) in derived.role(Role::Read).epochs() {
            let i = out.role_mut(Role::Read).observe(*ep);
            *i = info.clone();
            i.established = None;
        }
        Some(out)
    }

    /// `own_record` established (spec/crypto.md §4): a function of what this node holds now (its
    /// applied commits, `NamesHeld`), so nothing about establishment is stored
    /// or invalidated.
    pub(crate) fn own_epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let mut e = self.own_record(tid)?.clone();
        e.establish(&self.names_held(tid));
        Some(e)
    }

    /// What this node holds for judging the names of `actor`'s epochs (spec/crypto.md §4).
    pub(crate) fn names_held(&self, actor: &Tid) -> NamesHeld<'_> {
        NamesHeld { core: self, actor: *actor }
    }

    /// The opened epochs of `tid` when they make it an actor with secrets of its own here: it is
    /// in `own_keys`, is no known thing, or, no keyset part of it held (`keyset_parts`), holds an epoch
    /// with a held valid rotation commit or snapshot, a valid `secrets.0` part or an inbox hint of
    /// its delete keys. Not by this node's own rotation alone: that commit may have turned
    /// invalid. Its `Rotated` establishment is not computed: `own_epochs` is the view.
    pub(crate) fn own_record(&self, tid: &Tid) -> Option<&ActorEpochs> {
        let e = self.ix.secrets.get(tid)?;
        let thing = matches!(self.created(tid), Some(CreationRecord::Thing { .. } | CreationRecord::Ownerless { .. }));
        if self.ix.own_keys.contains(tid) || !thing {
            return Some(e);
        }
        // a held keyset part decides: all invalid, the thing is plain (a valid grant boxing under
        // that keyset's epochs counts for nothing; its derived epochs may predate a rotation of
        // the owner)
        if self.ix.keyset_parts.get(tid).is_some_and(|s| !s.is_empty()) {
            return None;
        }
        let rotated = || ROLES.iter().any(|r| e.role(*r).epochs().any(|(_, i)| i.rotated()));
        (rotated() || self.ix.delete_hints.contains_key(tid) || self.valid_secrets_part(tid)).then_some(e)
    }

    /// Whether a held role commit's `secrets.0` part on `tid` is valid (only a thing with
    /// secrets of its own has boxes: a grant whose target's `keys.0` is not held yet).
    fn valid_secrets_part(&self, tid: &Tid) -> bool {
        let Ok(ak) = osis_base::Ak::new("secrets.0") else { return false };
        self.ix.by_aspect.get(&(*tid, ak.clone())).into_iter().flatten().any(|(_, c)| {
            self.ix.commits.get(c).is_some_and(|m| m.view.kind.is_role() && m.aspect(tid, &ak).is_some_and(|ai| m.valid_at(ai)))
        })
    }

    /// The opened epochs of a plain thing `tid` that are not its own (`own_epochs`): what a
    /// rotation since found invalid gave it (spec/crypto.md §3, §4), kept for reading.
    fn stale_epochs(&self, tid: &Tid) -> Option<&ActorEpochs> {
        if self.own_record(tid).is_some() {
            return None;
        }
        self.ix.secrets.get(tid)
    }

    /// The delete base of `tid` (spec/crypto.md §7): the nearest actor in its record chain,
    /// itself first, with secrets of its own (all three roles at once, spec/crypto.md §3), or the
    /// key actor the chain ends at.
    pub(crate) fn delete_base(&self, tid: &Tid) -> Option<DeleteBase> {
        for step in self.owner_chain(tid) {
            let cur = step.thing()?;
            if cur == self.id.tid() {
                return Some(DeleteBase::KeyActor(self.id.keys().signing.verifying_key()));
            }
            if let Some(k) = self.key_actors.get(&cur) {
                return Some(DeleteBase::KeyActor(k.keys().signing.verifying_key()));
            }
            if let Some(e) = self.own_epochs(&cur) {
                return Some(DeleteBase::Actor(cur, Some(e)));
            }
            if self.ix.own_keys.contains(&cur) {
                return Some(DeleteBase::Actor(cur, None));
            }
            if let CreationRecord::KeyActor { public_key, .. } = self.created(&cur)? {
                return VerifyingKey::from_slice(public_key).ok().map(DeleteBase::KeyActor);
            }
        }
        None
    }

    /// The delete secrets this node may hold along the record chain of `tid`, itself first: a
    /// delete key a header lists for `tid` is one of them (a thing that got secrets of its own
    /// keeps content of its derived era under its former base's keys).
    pub(crate) fn delete_chain(&self, tid: &Tid) -> Vec<DeleteSource> {
        let mut out = Vec::new();
        for step in self.owner_chain(tid) {
            let Some(cur) = step.thing() else { break };
            let seed = if cur == self.id.tid() { Some(self.id.seed().clone()) } else { self.key_actors.get(&cur).map(|k| k.seed().clone()) };
            if let Some(seed) = seed {
                out.push(DeleteSource::KeyActor(DeleteSecret::from_seed(osis_crypto::kdf::kdf(osis_crypto::kdf::SIGN, seed.expose(), b""))));
                break;
            }
            if let Some(e) = self.ix.secrets.get(&cur) {
                out.push(DeleteSource::Epochs(e.clone()));
            }
        }
        out
    }

    /// The delete secret of `level` matching a header's delete key `key` (spec/crypto.md §7),
    /// tried over every held epoch along the chains: `thing` the chain of the delta's thing,
    /// `author` that of the actor above its author node.
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

    /// Opens what `secrets.0` of `actor` holds for this node or for actors it holds secrets of
    /// (spec/crypto.md §4). `unchecked`: `None` when `secrets` is the applied valid state; the
    /// source for the boxes of a pending commit, whose secrets are kept for reading only.
    /// Returns whether anything new was learned.
    /// `alts`: the live entries of history keys holding several (each tried).
    pub(crate) fn ingest_secrets(&mut self, actor: &Tid, secrets: &Secrets, unchecked: Option<Unchecked>, alts: &HistoryAlts) -> bool {
        let Some(epochs) = self.ingest_view(actor, secrets, unchecked, alts) else { return false };
        self.ix.secrets.insert(*actor, epochs);
        self.role_changed();
        true
    }

    /// Whether the reading-only budget has no room for `actor`, which holds nothing yet.
    pub(crate) fn reading_full(&self, actor: &Tid) -> bool {
        self.ix.secrets.get(actor).is_none_or(|e| !e.holds_any()) && self.ix.secrets.iter().filter(|(t, e)| *t != actor && Self::reading_only(e)).count() >= MAX_READING_ACTORS
    }

    /// How many more actors the reading-only budget takes.
    pub(crate) fn reading_room(&self) -> usize {
        MAX_READING_ACTORS.saturating_sub(self.ix.secrets.values().filter(|e| Self::reading_only(e)).count())
    }

    fn reading_only(e: &ActorEpochs) -> bool {
        ROLES.iter().all(|r| e.role(*r).held().next().is_none()) && e.holds_any()
    }

    /// What `ingest_secrets` would make of `actor`'s epochs, when it changes them.
    pub(crate) fn ingest_view(&self, actor: &Tid, secrets: &Secrets, unchecked: Option<Unchecked>, alts: &HistoryAlts) -> Option<ActorEpochs> {
        let before = self.ix.secrets.get(actor).cloned();
        // a bounded number of actors held through reading-only secrets alone
        if unchecked.is_some() && self.reading_full(actor) {
            return None;
        }
        let mut epochs = before.clone().unwrap_or_default();
        let seed = self.id.seed().clone();
        let me = self.id.tid();
        // only a holder with a box here opens anything: not O(actors known) per ingest
        let holders: std::collections::BTreeSet<Tid> = secrets.boxes.keys().map(|k| k.holder).filter(|t| t != actor).collect();
        let openers: Vec<(Tid, &ActorEpochs)> = holders.iter().filter_map(|t| Some((*t, self.ix.secrets.get(t)?))).collect();
        let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { holder: me, seed: &seed }, &mut epochs, unchecked);
        for (t, k) in &self.key_actors {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::KeyActor { holder: *t, seed: k.seed() }, &mut epochs, unchecked);
        }
        for (m, e) in &openers {
            let _ = osis_keys::ingest_with(actor, secrets, alts, &Opener::Actor { holder: *m, epochs: e }, &mut epochs, unchecked);
        }
        self.adopt_derived(actor, &mut epochs);
        let held_any = epochs.holds_any();
        (held_any && Some(&epochs) != before.as_ref()).then_some(epochs)
    }

    /// `ingest_secrets` over the entries of `actor`'s `secrets.0` state `st` that a change touched:
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
    /// those derived from an established epoch of the next actor up its record chain are
    /// established (spec/crypto.md §4), so the rotation from them establishes
    /// and labels registered under them can be stepped. A derived epoch's ID names its secret, so
    /// only an owner epoch whose secret is held matches.
    pub(crate) fn adopt_derived(&self, actor: &Tid, epochs: &mut ActorEpochs) {
        let Some(up) = self.created(actor).and_then(CreationRecord::up) else { return };
        let Some(o) = self.epochs(&up) else { return };
        let d = ActorEpochs::derived(&o, actor);
        for r in ROLES {
            for (ep, info) in d.role(r).epochs() {
                let sticky = epochs.role(r).get(ep).is_some_and(|i| i.established.is_some_and(Provenance::sticky));
                if info.established.is_some() && info.secret.is_some() && epochs.role(r).get(ep).is_some() && !sticky {
                    epochs.role_mut(r).set_established(*ep, Provenance::Derived);
                }
            }
        }
    }

    /// Notes the `keys.0` state of `actor`: its published delete keys replace any inbox hint, and
    /// the keysets' epochs and suites are recorded with its epochs. Whether it has secrets of its
    /// own is the parts' (`apply::keys::refresh_own_keys`), not the state's.
    pub(crate) fn observe_keys(&mut self, actor: &Tid, keys: &Keys) {
        if keys.read.is_some() || keys.write.is_some() || keys.admin.is_some() {
            self.ix.delete_hints.remove(actor);
            self.role_changed();
            if let Some(e) = self.ix.secrets.get_mut(actor) {
                let _ = osis_keys::observe_keys(keys, e);
            }
        }
    }
}

/// The names a node holds (spec/crypto.md §4) for epochs of `actor`: applied commits (a departing
/// rotation commit by its `ts` and author among the held `roles.0` deltas of `actor`) and epoch
/// starts.
pub(crate) struct NamesHeld<'c> {
    core: &'c Core,
    actor: Tid,
}

impl NamesHeld<'_> {
    /// Commit `c` is applied here with what its edge writes end: no reset of it names an entry
    /// whose creation is not held (spec/permissions.md §2; such a commit applies none of its edge
    /// writes, `apply::validity`). Invariant: a met name is a departure this node holds whole,
    /// so it never boxes a holder an epoch's rotator saw depart into that epoch: a finalize held
    /// without the write it ends removes nobody here, yet its rotation would count.
    fn resolved(&self, c: &CommitId) -> bool {
        !self.core.ix.unresolved.contains(c)
    }
}

impl osis_keys::Held for NamesHeld<'_> {
    /// Applied: the commit held with its `roles.0` part on the name's thing, or, having none
    /// there, its `keys.0` part (a copy of some of it, a certificate copy or another label's parts,
    /// may lack the departure), and `resolved`.
    fn met(&self, n: &Name) -> bool {
        let applied = self.core.ix.commits.get(&n.key.commit).is_some_and(|m| {
            let part = |ak: &str| m.header.aspects.iter().position(|a| a.tid == n.thing && a.ak.as_str() == ak);
            part("roles.0").or_else(|| part("keys.0")).is_none_or(|ai| !m.missing.contains(&ai))
        });
        applied && self.resolved(&n.key.commit)
    }
    /// The commit by `own`'s `ts` and author among the held `roles.0` deltas of the actor, resolved,
    /// writing a keyset of the actor (a rotation commit), and making no self-removal on it.
    ///
    /// Invariant: a departs mark covers only departures its rotation commit makes by an
    /// explicit demotion or finalize, whose author stays a holder or was never the leaver. Any
    /// writer holding an epoch's secret may put an entry at its history key naming any mark, and
    /// a mark is predictable by its author: a leaver could name its own self-removal (in that
    /// commit, an earlier one, or a rotation of its own in it, whose secrets it made), and a
    /// leaver's guess at an admin's removal that carries no rotation (Seal waits) would name a
    /// commit with no keyset. A self-removal carries no rotation (spec/permissions.md §3), so an
    /// honest mark never names one.
    fn departed(&self, own: &Own) -> bool {
        let Ok(roles) = osis_base::Ak::new("roles.0") else { return false };
        let Some(set) = self.core.ix.by_aspect.get(&(self.actor, roles)) else { return false };
        let ts = osis_base::Ts::from_u64(own.ts).unwrap_or_default();
        let tl = self.core.timelines.get(&self.actor);
        set.range((ts, CommitId([0; 32]))..=(ts, CommitId([0xff; 32]))).any(|(_, c)| {
            let rotates = self.core.ix.commits.get(c).is_some_and(|m| m.view.author == own.node && m.header.aspects.iter().any(|a| a.tid == self.actor && a.ak.as_str() == "keys.0"));
            let leaves = tl.is_some_and(|tl| {
                tl.applied().range(osis_perm::WriteId(*c, 0)..=osis_perm::WriteId(*c, u32::MAX)).any(|(_, w)| w.target == self.actor && matches!(w.attr, osis_perm::Attr::SelfRemoval(..)))
            });
            rotates && !leaves && self.resolved(c)
        })
    }
}

/// The delete base of a thing (spec/crypto.md §7).
pub(crate) enum DeleteBase {
    /// An actor with secrets of its own, with its epochs when held.
    Actor(Tid, Option<ActorEpochs>),
    /// A key actor: its signing key is its delete key at every level.
    KeyActor(VerifyingKey),
}

/// A held source of delete secrets along a record chain.
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
    /// Delete keys published in `keys.0` of delete bases whose secret of that role is not held
    /// ([`published_keys`]).
    pub published: &'c BTreeMap<(Tid, Role), VerifyingKey>,
}

/// The delete base of `tid` ([`Core::delete_base`]); a thing `created` in this commit is plain,
/// so it uses that of the next actor up its record chain.
fn base_of(core: &Core, created: &crate::engine::write::Creates, tid: &Tid) -> Option<DeleteBase> {
    match osis_base::owner_chain(*tid, |t| created.get(t).map(CreationRecord::owner_link)).end() {
        ChainStep::Key(k) => match created.get(&k)? {
            CreationRecord::KeyActor { public_key, .. } => VerifyingKey::from_slice(public_key).ok().map(DeleteBase::KeyActor),
            _ => None,
        },
        ChainStep::Unknown(t) => core.delete_base(&t),
        ChainStep::Up { .. } | ChainStep::Ownerless { .. } | ChainStep::TooDeep => None,
    }
}

/// The admin and write delete keys published in `keys.0` (spec/crypto.md §3, §7) of the delete
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
        // the keys an inbox payload named stand in until `keys.0` arrives
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
    /// only while no hint and no `keys.0` with keysets is held for it (the first stays).
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
                    touched.peek().is_some() && touched.all(|(i, _)| m.valid_at(i))
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
    /// Whether this node holds the key actor at the end of the commit actor's record chain.
    fn chain_holder(&self) -> bool {
        self.core.owner_chain(&self.actor).filter_map(|s| s.thing()).any(|t| t == self.core.id.tid() || self.core.key_actors.contains_key(&t))
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

/// Persisted: what establishment is computed from (rotation commits, snapshot, names) and the
/// directly set `Fixed`/`Derived` provenances; `Rotated` is never stored (`Core::own_epochs`).
pub(crate) fn encode_epochs(a: &ActorEpochs) -> Vec<u8> {
    let roles = ROLES
        .iter()
        .map(|r| {
            Value::List(
                a.role(*r)
                    .epochs()
                    .map(|(e, i)| {
                        let sticky = i.established.filter(|p| p.sticky()).map(|p| Value::Bool(p == Provenance::Derived));
                        Value::List(vec![
                            e.to_wire(),
                            Value::uint(i.suite),
                            Value::List(i.rotations.iter().map(|(c, sup)| Value::List(vec![Value::Bytes(c.0.to_vec()), Value::List(sup.iter().map(Epoch::to_wire).collect())])).collect()),
                            Value::Bool(i.snapshot),
                            Value::List(i.names.iter().map(osis_keys::Names::to_value).collect()),
                            Value::List(sticky.into_iter().collect()),
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

/// The live entries of history keys holding several in a `secrets.0` state (puts of one key by
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

/// The history-box map of a `secrets.0` state.
fn history_map(f: &osis_crdt::Fragment) -> Option<&osis_crdt::Map> {
    use osis_crdt::{Encoding, Fragment, SlotRef};
    let Some(SlotRef::Frag(Fragment::Struct(st))) = f.slot(Encoding::Struct) else { return None };
    match st.field(1)?.slot(Encoding::Map)? {
        SlotRef::Frag(Fragment::Map(m)) => Some(m),
        _ => None,
    }
}

/// A core-schema value typed as the named type.
fn typed_as<T: osis_schema::Codec>(v: &Value, name: &str) -> Option<T> {
    let v = osis_schema::typed_read(osis_schema::core_schema(), v, &osis_schema::Type::Named(name.into(), Vec::new())).ok()?;
    T::from_value(&v).ok()
}

/// The keys of the box and history-box entries a `secrets.0` delta (or snapshot) writes; `None`
/// when it writes the value, a field or a map whole (a reset): then every entry may change.
pub(crate) fn touched_keys(delta: &osis_crdt::Fragment) -> Option<(Vec<Value>, Vec<Value>)> {
    use osis_crdt::{Encoding, Fragment, SlotRef};
    if !delta.is_plain_struct() {
        return None;
    }
    let Some(SlotRef::Frag(Fragment::Struct(st))) = delta.slot(Encoding::Struct) else { return None };
    let mut out = (Vec::new(), Vec::new());
    for (id, keys) in [(0, &mut out.0), (1, &mut out.1)] {
        let Some(f) = st.field(id) else { continue };
        let Some(SlotRef::Frag(Fragment::Map(m))) = f.slot(Encoding::Map) else { return None };
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
            let [e, Value::Int(suite), Value::List(rotations), Value::Bool(snapshot), Value::List(names), Value::List(est), Value::List(sup), Value::List(sec), Value::List(reading)] = f.as_slice() else { return Err(bad()) };
            let e = Epoch::from_wire(e).map_err(|_| bad())?;
            let info = a.role_mut(*r).observe(e);
            info.suite = u64::try_from(*suite).map_err(|_| bad())?;
            for x in rotations {
                let Value::List(x) = x else { return Err(bad()) };
                let [Value::Bytes(c), Value::List(list)] = x.as_slice() else { return Err(bad()) };
                let c = CommitId(c.as_slice().try_into().map_err(|_| bad())?);
                let list = list.iter().map(|s| Epoch::from_wire(s).map_err(|_| bad())).collect::<Result<_>>()?;
                info.rotations.insert(c, list);
            }
            info.snapshot = *snapshot;
            for n in names {
                info.names.insert(osis_keys::Names::from_value(n).ok_or_else(bad)?);
            }
            match est.as_slice() {
                [] => {}
                [Value::Bool(derived)] => info.established = Some(if *derived { Provenance::Derived } else { Provenance::Fixed }),
                _ => return Err(bad()),
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

/// The typed `secrets.0` of a state value, if it reads as one. A map field never written (a
/// rotation that boxed nobody, a grant that carried no history box) reads as empty: the node
/// otherwise lost every box and history box of the actor.
pub(crate) fn secrets_value(v: &Value) -> Option<Secrets> {
    let mut v = v.clone();
    if let Value::Map(m) = &mut v {
        for f in [0, 1] {
            if !m.contains_key(&Value::Int(f)) {
                m.insert(Value::Int(f), Value::Map(Default::default()));
            }
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
    // across a restart (the mark is persisted with the epochs, never re-inferred); what
    // establishment is computed from round-trips.
    #[test]
    fn reading_only_mark_persists() {
        let mut a = ActorEpochs::default();
        let (e1, e2) = (Epoch::new(1, [1; 32]).unwrap(), Epoch::new(2, [2; 32]).unwrap());
        a.read.set_secret(e1, Secret32::from_bytes([1; 32]));
        a.read.set_established(e1, Provenance::Fixed);
        let from = |n: u8| Unchecked { author: Tid::from_bytes([n; 15]), commit: osis_base::CommitId([n; 32]) };
        a.read.set_reading_secret(e2, Secret32::from_bytes([2; 32]), from(1));
        a.read.set_reading_secret(e2, Secret32::from_bytes([2; 32]), from(2));
        a.read.set_rotation(e2, osis_base::CommitId([9; 32]), [Epoch::new(1, [3; 32]).unwrap()].into());
        let k = |n: u8| osis_keys::Key { ts: u64::from(n), node: Tid::from_bytes([n; 15]), commit: osis_base::CommitId([n; 32]) };
        a.read.set_snapshot(e2);
        a.read.add_names(e2, osis_keys::Names { list: [Name { thing: Tid::from_bytes([6; 15]), key: k(5) }].into(), departs: Some(Own { ts: 7, node: Tid::from_bytes([7; 15]) }) });
        a.write.set_established(e1, Provenance::Derived);
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
        let view = schema.view("secrets.0").unwrap();
        let k = osis_schema::core_types::HistoryKey { role: Role::Read, epoch: osis_keys::aspects::to_schema(&Epoch::new(1, [1; 32]).unwrap()) };
        let mut st = osis_crdt::Fragment::default();
        for (n, b) in [(1u8, 0x11u8), (2, 0x22)] {
            let ts = osis_base::Ts::make(osis_base::WallMs(u64::from(n) * 1000), 0).unwrap();
            let mut batch = Batch::new(&st, Writer::new(ts, Source::session(osis_crdt::Session { node: Tid::from_bytes([n; 15]), nonce: [0; osis_crdt::SESSION_NONCE_LEN] }), 1));
            batch.apply(&PathOp { path: vec![PathSeg::Field(1), PathSeg::Key(k.to_value())], op: Op::Put(Value::Bytes(vec![b; 8])) }, &view).unwrap();
            st.join(batch.finish().unwrap().0);
        }
        let alts = history_alts(&st);
        let mut got = alts.get(&k).cloned().unwrap();
        got.sort();
        assert_eq!(got, vec![vec![0x11; 8], vec![0x22; 8]]);
    }
}
