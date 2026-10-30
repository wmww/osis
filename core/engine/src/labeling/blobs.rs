//! Bodies, encryption, wraps, stamps, deposits and delete keys (spec/sync.md §1-§3, §5;
//! spec/crypto.md §5, §7): what a commit becomes under a label, and the label keys a server's head calls for.

use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_commit::{CommitBlob, DeleteKey, Kind};
use osis_base::{BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_crypto::{CryptoRngCore, DeleteSecret, Epoch, LabelRole, Secret32, SigningSecret, deposit_key, label_role_key};
use osis_keys::{ActorEpochs, WrapEpoch};
use osis_label::Step;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// One projection of a held commit (spec/sync.md §3): the deltas of one (reader actor,
/// retention class), or a size split of one.
#[derive(Clone, Debug)]
pub struct Body {
    pub commit: CommitId,
    /// The reader actor of its deltas.
    pub reader: Tid,
    /// `(ai, di)`, sorted.
    pub parts: Vec<(usize, usize)>,
    pub expires: Option<u64>,
    pub keys: Vec<DeleteKey>,
    /// The header's blind (spec/crypto.md §7).
    pub blind: [u8; 16],
    pub plaintext: Vec<u8>,
    pub membership: bool,
}

/// A blob of a body: ID, bytes, key, prefix salt.
pub struct Sealed {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub key: Secret32,
    pub salt: [u8; 16],
}

/// Frames a body as a fresh blob: random salt and key, prefix from its class (spec/sync.md §1).
pub fn seal_body(b: &Body, rng: &mut dyn CryptoRngCore) -> Result<Sealed> {
    seal_body_as(b, osis_label::Class::Durable, rng)
}

/// `seal_body` with the prefix class of an ephemeral commit's body (spec/sync.md §1).
pub fn seal_body_as(b: &Body, class: osis_label::Class, rng: &mut dyn CryptoRngCore) -> Result<Sealed> {
    let salt = osis_label::Prefix::random_salt(rng);
    let prefix = osis_label::Prefix::for_delete_keys(salt, &b.blind, b.expires.map(WallMs), &b.keys)?.with_class(class);
    let (key, blob) = osis_label::frame(&prefix, &b.plaintext, rng)?;
    Ok(Sealed { id: osis_label::blob_id(&blob), blob, key, salt })
}

/// Opens a commit blob and checks its prefix against the header (spec/commits.md §4): the
/// plaintext and its parts.
pub fn open_commit(blob: &[u8], key: &Secret32) -> Result<(Vec<u8>, CommitBlob)> {
    let (prefix, pt) = osis_label::open(blob, key)?;
    let c = CommitBlob::decode(&pt)?;
    let parts: Vec<(usize, usize)> = c.parts.iter().map(|p| (p.ai, p.di)).collect();
    if !c.header.is_resolved() {
        // linked header lists: the agreement is checked once node-core resolved them (the
        // pass, `check_linked_prefixes`)
        return Ok((pt, c));
    }
    let (expiry, keys) = osis_commit::prefix_inputs(&c.header, &parts)?;
    if !parts.is_empty() && !prefix.agrees(expiry.map(WallMs), &c.header.blind, &keys, osis_label::Class::of_marker(c.header.ephemeral)) {
        return Err(Error::BadInput("blob prefix disagrees with its header"));
    }
    Ok((pt, c))
}

/// A group as `Engine::commit_bodies_under` sees it.
pub struct BodyCtx {
    pub closure: std::sync::Arc<std::collections::BTreeSet<Tid>>,
    pub actor: Tid,
    pub published: std::sync::Arc<std::collections::BTreeSet<Tid>>,
}

impl BodyCtx {
    /// Whether a commit (its `View`) may have bodies under the group's labels.
    pub(crate) fn touches(&self, v: &crate::engine::View) -> bool {
        v.aspects.iter().any(|a| self.closure.contains(&a.tid) || self.published.contains(&a.tid) && matches!(a.ak.as_str(), "/label" | "/created"))
    }
}

/// The label keys this node holds for a server's head (spec/sync.md §2, §5).
#[derive(Clone, Default)]
pub struct HeadKeys {
    /// Opens (any held secret, spec/crypto.md §4: opening is not encrypting under).
    pub sync: Option<SigningSecret>,
    /// The sync key's epoch is established: it may sign level-1 and level-2 deletes.
    pub sync_established: bool,
    /// Stamps and level-3 deletes (an established epoch).
    pub write: Option<SigningSecret>,
    /// Label-wide deletes and child steps (an established epoch).
    pub delete: Option<SigningSecret>,
    pub deposit: Option<SigningSecret>,
    /// The head's epoch per role (read, write, admin) where held.
    pub epochs: [Option<Epoch>; 3],
}

impl HeadKeys {
    pub fn is_writer(&self) -> bool {
        self.write.is_some()
    }
}

/// The held epoch of `role` whose label key at `index` is `pk`, with the secret deriving it
/// and whether that secret may be encrypted under (not reading-only, spec/crypto.md §4).
fn matching(e: &ActorEpochs, role: Role, index: u64, pk: &osis_crypto::VerifyingKey) -> Option<(Epoch, Secret32, bool)> {
    let re = e.role(role);
    let (ep, s) = osis_keys::registered_secret(re, role, index, pk)?;
    Some((ep, s.clone(), re.secret(&ep).is_some()))
}

impl Engine {
    /// The projections of a held commit's current blob (its held deltas), with their reader
    /// actors.
    pub fn bodies(&mut self, c: &CommitId) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let membership = blob.header.kind.is_membership();
        // linked header lists: classed by the applied (resolved) header
        let resolved = match self.core.ix.commits.get(&id) {
            Some(m) if !blob.header.is_resolved() => m.header.arc(),
            _ => std::sync::Arc::new(blob.header.clone()),
        };
        let readers: Vec<Tid> = resolved.aspects.iter().map(|a| self.core.reader_of(&a.tid)).collect();
        let ps = osis_commit::project_resolved(&blob, &resolved, |ai| readers.get(ai).copied())?;
        Ok(ps
            .into_iter()
            .filter_map(|p| {
                let reader = p.readers?;
                Some(Body { commit: id, reader, parts: p.parts, expires: p.expires, keys: p.keys, blind: blob.header.blind, plaintext: p.plaintext, membership })
            })
            .collect())
    }

    /// The bodies a group's label must hold from its closure (spec/sync.md §3): projections of
    /// held commits touching the closure whose deltas the group's actor may read. A home label
    /// (an actor synced as a group of itself) also carries the `/label` and `/created` writes of
    /// the labeled groups it is the nearest labeled owner-chain actor of (spec/sync.md §2).
    pub fn label_bodies(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let mut out = self.label_bodies_meta(g)?;
        for b in &mut out {
            b.plaintext = self.body_plaintext(b)?;
        }
        Ok(out)
    }

    /// The plaintext of a body (`label_bodies_meta` leaves it out): projected again from the
    /// held commit; empty when that body is not there any more.
    pub fn body_plaintext(&mut self, b: &Body) -> Result<Vec<u8>> {
        if !b.plaintext.is_empty() {
            return Ok(b.plaintext.clone());
        }
        Ok(self.bodies(&b.commit)?.into_iter().find(|x| x.parts == b.parts).map(|x| x.plaintext).unwrap_or_default())
    }

    /// `label_bodies` without plaintexts, from a per-commit cache (`Core::bodies`): a pass after a
    /// change projects only the commits it changed. The commits are found through `by_thing` and
    /// `by_aspect` (O(the closure's commits), no header decoded when the cache holds them), in ID
    /// order.
    pub fn label_bodies_meta(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let ctx = self.body_ctx(g);
        let core = &self.core;
        let mut ids: BTreeSet<CommitId> = ctx.closure.iter().flat_map(|t| core.ix.by_thing.get(t).into_iter().flatten().copied()).collect();
        for t in ctx.published.iter() {
            for ak in ["/label", "/created"] {
                let Ok(ak) = osis_base::Ak::new(ak) else { continue };
                ids.extend(core.ix.by_aspect.get(&(*t, ak)).into_iter().flatten().map(|x| x.1));
            }
        }
        #[cfg(debug_assertions)]
        debug_assert_eq!(ids, core.ix.commits.iter().filter(|(_, m)| ctx.touches(&m.view)).map(|(id, _)| *id).collect::<BTreeSet<_>>(), "label commits by index");
        let mut out = Vec::new();
        for id in ids {
            out.extend(self.commit_bodies_under(&ctx, &id)?);
        }
        Ok(out)
    }

    /// What `commit_bodies_under` needs of a group: its closure, actor and the things its home
    /// label publishes.
    pub fn body_ctx(&mut self, g: &Tid) -> BodyCtx {
        BodyCtx { closure: self.closure(g), actor: self.group_actor(g), published: self.published_under(g) }
    }

    /// The bodies of commit `id` a label of the group of `ctx` must hold (`label_bodies_meta`).
    pub fn commit_bodies_under(&mut self, ctx: &BodyCtx, id: &CommitId) -> Result<Vec<Body>> {
        let id = *id;
        // the view: the header is decoded only to project bodies the cache misses
        let Some(h) = self.core.ix.commits.get(&id).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
        if !ctx.touches(&h) {
            return Ok(Vec::new());
        }
        let touches = h.aspects.iter().any(|a| ctx.closure.contains(&a.tid));
        let bodies = match self.core.bodies.get(&id) {
            Some(b) => b.clone(),
            None => {
                let mut b = self.bodies(&id)?;
                for x in &mut b {
                    x.plaintext = Vec::new();
                }
                // kept only while every reader actor is resolved (a missing owner record
                // arriving later moves it)
                if h.aspects.iter().all(|a| self.core.secret_actor(&a.tid).is_some()) {
                    self.core.bodies.insert(id, b.clone());
                }
                b
            }
        };
        let mut out = Vec::new();
        for b in bodies {
            let inside = touches || b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| ctx.published.contains(&a.tid) && matches!(a.ak.as_str(), "/label" | "/created"));
            if inside && self.core.may_read(&ctx.actor, &b.reader) {
                out.push(b);
            }
        }
        Ok(out)
    }

    /// Labeled groups whose nearest labeled owner-chain actor is `g` (its home label publishes
    /// their `/label`, spec/sync.md §2). Empty unless `g` is an actor with secrets of its own.
    /// Taken for every actor at once, again only when a creation record, `own_keys` or the
    /// labeled things changed (`Core::published`): O(labeled things) per change, not per pass.
    pub fn published_under(&mut self, g: &Tid) -> std::sync::Arc<std::collections::BTreeSet<Tid>> {
        let core = &mut self.core;
        let at = (core.ix.held.generation(), core.ix.own_keys.changes(), core.ix.labeled.changes());
        if core.published.as_ref().is_none_or(|(k, _)| *k != at) {
            let map = published_by_actor(core, &core.ix.labeled);
            core.published = Some((at, map.into_iter().map(|(k, v)| (k, std::sync::Arc::new(v))).collect()));
        }
        let out = core.published.as_ref().and_then(|(_, m)| m.get(g).cloned()).unwrap_or_default();
        // the cache and the `/label` index against a scan of every held aspect
        #[cfg(debug_assertions)]
        {
            let scan: std::collections::BTreeSet<Tid> = core.ix.by_aspect.keys().filter(|(_, ak)| ak.as_str() == "/label").map(|(t, _)| *t).collect();
            assert!(scan == *core.ix.labeled, "labeled index {:?} vs held {scan:?}", *core.ix.labeled);
            assert_eq!(published_by_actor(core, &scan).remove(g).unwrap_or_default(), *out, "published_under({g}) cached");
        }
        out
    }

    /// The read secret a commit is wrapped under at a label of `g` (spec/crypto.md §5): the
    /// newest current read epoch held, except a rotation commit of the actor `g`'s secrets
    /// derive from, which goes under the newest epoch its rotation supersedes. `None`: no
    /// current secret held (only a stranded heartbeat may be placed).
    pub fn wrap_secret(&mut self, g: &Tid, c: Option<(&CommitId, &[(usize, usize)])>) -> Result<Option<Secret32>> {
        let Some(e) = self.epochs(g) else { return Ok(None) };
        if let Some((c, parts)) = c
            && self.carries_secrets(g, c, parts)
            && let Some(ep) = self.rotation_wrap_epoch(g, c)?
            && let Some(s) = e.read.secret(&ep)
        {
            return Ok(Some(s.clone()));
        }
        Ok(match osis_keys::wrap_epoch(&e.read) {
            WrapEpoch::Current(ep) => e.read.secret(&ep).cloned(),
            _ => None,
        })
    }

    /// Held read secrets of a group, newest first; then those derived from its owner's (a
    /// thing that got secrets of its own, or one owned by a key actor this node holds: the
    /// rotation that gave it its own is wrapped under the derived epoch, spec/crypto.md §5).
    pub fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        let mut v: Vec<Secret32> = self.epochs(g).map(|e| e.read.held_newest_first().into_iter().map(|(_, s)| s.clone()).collect()).unwrap_or_default();
        // the owner's epochs; a thing whose `/created` is not here yet (a recovery card's
        // person) may be owned by any key actor held
        let owners: Vec<osis_keys::ActorEpochs> = match self.core.created(g) {
            Some(osis_base::CreationRecord::Thing { owner, .. }) => self.epochs(owner).or_else(|| self.core.key_actors.get(owner).map(|id| osis_keys::ActorEpochs::key_actor(id.seed()))).into_iter().collect(),
            Some(osis_base::CreationRecord::KeyActor { .. }) => Vec::new(),
            None => self.core.key_actors.values().map(|id| osis_keys::ActorEpochs::key_actor(id.seed())).collect(),
        };
        for oe in owners {
            for (_, s) in osis_keys::ActorEpochs::derived(&oe, g).read.held_newest_first() {
                if !v.iter().any(|x| x.expose() == s.expose()) {
                    v.push(s.clone());
                }
            }
        }
        v
    }

    /// Whether these deltas of `c` hold the `/secrets` or `/keys` of the actor `g`'s secrets derive
    /// from (only a blob carrying the boxes takes the rotation's wrap exception).
    pub fn carries_secrets(&self, g: &Tid, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|x| x.tid == a && matches!(x.ak.as_str(), "/secrets" | "/keys"))
    }

    /// The newest established read secret held, current or not (a stranded heartbeat's wrap,
    /// spec/permissions.md §4).
    pub fn stranded_secret(&self, g: &Tid) -> Option<Secret32> {
        let e = self.epochs(g)?;
        match osis_keys::wrap_epoch(&e.read) {
            WrapEpoch::Current(ep) | WrapEpoch::Stranded(ep) => e.read.secret(&ep).cloned(),
            WrapEpoch::None => None,
        }
    }

    /// For a rotation commit of the read role of `g`'s secret actor (its `/keys` delta writes a
    /// read keyset): the newest held epoch the new read epoch supersedes.
    fn rotation_wrap_epoch(&mut self, g: &Tid, c: &CommitId) -> Result<Option<Epoch>> {
        let Some(a) = self.core.secret_actor(g) else { return Ok(None) };
        let Some(h) = self.header(c) else { return Ok(None) };
        let Some(ai) = h.aspects.iter().position(|x| x.tid == a && x.ak.as_str() == "/keys") else { return Ok(None) };
        if !h.aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "/secrets") {
            return Ok(None);
        }
        let id = *c;
        let parts = self.run(|tx| crate::apply::held_parts(tx, &id, ai))?;
        let Some(epochs) = self.epochs(&a) else { return Ok(None) };
        let mut best: Option<Epoch> = None;
        for d in parts {
            let f = d.into_fragment();
            let Some(ks) = crate::apply::keys::keys_write(&f).keysets.remove(&Role::Read) else { continue };
            let Ok(e) = osis_keys::aspects::from_schema(&ks.epoch) else { continue };
            let Some(info) = epochs.read.get(&e) else { continue };
            for s in &info.supersedes {
                if epochs.read.secret(s).is_some() && best.is_none_or(|b| osis_keys::is_newer(s, &b)) {
                    best = Some(*s);
                }
            }
        }
        Ok(best)
    }

    /// The deposit seed of `g`'s actor (its `/keys`).
    pub fn deposit_seed(&mut self, g: &Tid) -> Result<Option<Secret32>> {
        let x = self.group_actor(g);
        Ok(self.get_typed(&x, &ct::KEYS)?.and_then(|k| k.deposit_seed).map(Secret32::from_bytes))
    }

    /// The keys this node holds for `head` of label `index` of `g` (spec/sync.md §2, §5): any
    /// held secret opens; stamps and deletes need an established epoch (spec/crypto.md §4).
    pub fn head_keys(&mut self, g: &Tid, index: u64, head: &Step) -> Result<HeadKeys> {
        let mut k = HeadKeys::default();
        if let Some(e) = self.epochs(g) {
            if let Some((ep, s, _)) = matching(&e, Role::Read, index, &head.keys.sync) {
                k.sync = Some(label_role_key(LabelRole::Sync, &s, index));
                k.sync_established = self.established(g, &e, Role::Read, &ep);
                k.epochs[0] = Some(ep);
            }
            // stamps and deletes are encrypting under: never from a reading-only secret
            if let Some((ep, s, checked)) = matching(&e, Role::Write, index, &head.keys.write) {
                if checked && self.established(g, &e, Role::Write, &ep) {
                    k.write = Some(label_role_key(LabelRole::Write, &s, index));
                }
                k.epochs[1] = Some(ep);
            }
            if let Some((ep, s, checked)) = matching(&e, Role::Admin, index, &head.keys.delete) {
                if checked && self.established(g, &e, Role::Admin, &ep) {
                    k.delete = Some(label_role_key(LabelRole::Delete, &s, index));
                }
                k.epochs[2] = Some(ep);
            }
        }
        if let Some(seed) = self.deposit_seed(g)? {
            let d = deposit_key(&seed, &head.label);
            if d.verifying_key() == head.keys.deposit {
                k.deposit = Some(d);
            }
        }
        Ok(k)
    }

    /// Whether `ep` of role `r` is established for `g`: in its own epochs, or, for a thing that
    /// got secrets of its own, as the epoch derived from an established epoch of its owner it
    /// had before (spec/crypto.md §3-§4; the history box carries it without establishment).
    fn established(&self, g: &Tid, e: &ActorEpochs, r: Role, ep: &Epoch) -> bool {
        if e.role(r).is_established(ep) {
            return true;
        }
        let Some(osis_base::CreationRecord::Thing { owner, .. }) = self.core.created(g) else { return false };
        self.epochs(owner).is_some_and(|o| ActorEpochs::derived(&o, g).role(r).is_established(ep))
    }

    /// The delete secrets this node holds for the deltas `parts` of commit `c` (spec/crypto.md
    /// §7): per delete key the header lists for their class, with its level, matched over every
    /// held epoch along the owner chains. Needs no blob: a dropped body's copy may be gone.
    pub fn delete_secrets_of(&mut self, c: &CommitId, parts: &[(usize, usize)]) -> Vec<(u8, DeleteSecret)> {
        let Some(h) = self.header(c) else { return Vec::new() };
        let Some(a) = parts.first().and_then(|(ai, _)| h.aspects.get(*ai)) else { return Vec::new() };
        self.delete_secrets(&h, &a.tid, &a.keys)
    }

    /// The delete secrets for header `h`'s delete keys at indices `idx`, for a delta on `tid`.
    fn delete_secrets(&self, h: &osis_commit::Header, tid: &Tid, idx: &[usize]) -> Vec<(u8, DeleteSecret)> {
        let thing = self.core.delete_chain(tid);
        let author = if h.kind == Kind::Import { Vec::new() } else { self.core.delete_chain(&h.actor) };
        idx.iter().filter_map(|i| h.keys.get(*i)).filter_map(|k| crate::engine::Core::delete_secret(k.level, &k.key, &thing, &author).map(|d| (k.level, d))).collect()
    }
}

impl Engine {
    /// The delete secrets this node holds for chunk entry `ch` of commit `c` (spec/crypto.md
    /// §7: per delete key of the delta that created it), with their levels.
    pub fn chunk_delete_secrets(&mut self, c: &CommitId, ch: &osis_commit::ChunkEntry) -> Vec<(u8, DeleteSecret)> {
        let Some(h) = self.header(c) else { return Vec::new() };
        let Some(a) = h.aspects.iter().find(|a| a.keys == ch.keys) else { return Vec::new() };
        let tid = a.tid;
        self.delete_secrets(&h, &tid, &ch.keys)
    }
}

/// A delete item for an entry: by the label delete key when held, else by a level's delete key
/// (`dks`, for the blob's prefix salt and its header's blind) and the label key its level needs
/// (spec/sync.md §5), under established epochs only (spec/crypto.md §4).
pub fn delete_item(keys: &HeadKeys, label: &LabelId, blob: BlobId, at: Option<WallMs>, blinding: Option<(&[u8; 16], &[u8; 16])>, dks: &[(u8, DeleteSecret)]) -> Option<osis_label::DeleteItem> {
    if let Some(d) = &keys.delete {
        return osis_label::DeleteItem::sign(d, label, blob, at).ok();
    }
    let (salt, hb) = blinding?;
    for (level, dk) in dks {
        let key = match osis_label::key_for_level(*level).ok()? {
            LabelRole::Write => keys.write.as_ref(),
            _ => keys.sync.as_ref().filter(|_| keys.sync_established),
        };
        if let Some(k) = key {
            return osis_label::DeleteItem::sign_by(k, dk, *level, salt, hb, label, blob, at).ok();
        }
    }
    None
}

/// Labeled things by their nearest labeled owner-chain actor with secrets of its own
/// (`Engine::published_under`).
fn published_by_actor(core: &crate::engine::Core, labeled: &std::collections::BTreeSet<Tid>) -> std::collections::BTreeMap<Tid, std::collections::BTreeSet<Tid>> {
    let mut map: std::collections::BTreeMap<Tid, std::collections::BTreeSet<Tid>> = std::collections::BTreeMap::new();
    for h in labeled {
        let mut cur = *h;
        for _ in 0..64 {
            let Some(osis_base::CreationRecord::Thing { owner, .. }) = core.created(&cur) else { break };
            cur = *owner;
            if labeled.contains(&cur) && core.ix.own_keys.contains(&cur) {
                if cur != *h {
                    map.entry(cur).or_default().insert(*h);
                }
                break;
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // spec/sync.md §6 (convergence after each change; the pass's cost): a group's bodies are
    // projected per commit once and kept until that commit or the readers change, so one more
    // commit leaves every other commit's bodies cached.
    #[test]
    fn label_bodies_cached_per_commit_spec_sync_6() {
        use crate::Mutation;
        let mut lp = crate::local_peer::LocalPeer::new(1, 941, WallMs(1_700_000_000_000)).unwrap();
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        let ak = osis_base::Ak::new("/x/a").unwrap();
        let mut group = ct::Group::default();
        let add = |e: &mut Engine, group: &mut ct::Group| {
            let mut m = Mutation::new();
            let t = e.new_thing(&mut m, g);
            m.set(t, &ak, &osis_base::Value::Int(1)).unwrap();
            group.items.insert(t);
            m.set(g, &ct::GROUP, group).unwrap();
            e.commit(m).unwrap().unwrap()
        };
        for _ in 0..30 {
            add(e, &mut group);
        }
        let first = e.label_bodies_meta(&g).unwrap();
        assert!(first.len() >= 30 && first.iter().all(|b| b.plaintext.is_empty()));
        let cached: Vec<CommitId> = e.core.bodies.keys().copied().collect();
        assert!(cached.len() >= 30);
        let c = add(e, &mut group);
        assert!(cached.iter().all(|x| e.core.bodies.contains_key(x)), "a new commit leaves the others' bodies cached");
        let again = e.label_bodies_meta(&g).unwrap();
        assert!(again.iter().any(|b| b.commit == c) && e.core.bodies.contains_key(&c));
        let b = again.iter().find(|b| b.commit == c).unwrap();
        assert!(!e.body_plaintext(b).unwrap().is_empty(), "the plaintext is projected on demand");
    }

    // spec/crypto.md §4: a secret learned only from a pending or invalid commit is never
    // encrypted under; signing a stamp or delete is. A reading-only write or admin secret still
    // finds the head's epoch (opening, walking) but is not offered for signing.
    #[test]
    fn reading_only_head_secret_never_signs_spec_crypto_4() {
        let e = Epoch::new(2, [2; 16]).unwrap();
        let s = Secret32::from_bytes([5; 32]);
        let mut a = ActorEpochs::default();
        a.write.set_reading_secret(e, s.clone(), osis_keys::Unchecked { author: Tid::from_bytes([1; 15]), commit: CommitId([1; 32]) });
        a.write.set_established(e, osis_keys::Provenance::Chain);
        let pk = label_role_key(osis_keys::label_role(Role::Write), &s, 0).verifying_key();
        let (ep, got, checked) = matching(&a, Role::Write, 0, &pk).unwrap();
        assert_eq!((ep, &got, checked), (e, &s, false));
        a.write.set_secret(e, s.clone());
        assert!(matching(&a, Role::Write, 0, &pk).unwrap().2);
    }
}
