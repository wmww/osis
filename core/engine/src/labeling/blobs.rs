//! Bodies, sealing, wraps, stamps, deposits and delete keys (spec/sync-ids.md §1-§3, §5;
//! spec/crypto.md §5, §7): what a commit becomes under a label, and the label keys a host's head calls for.

use osis_base::memo::Memo;
use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_commit::{CommitBlob, Envelope, Section};
use osis_base::{BlobId, CommitId, Role, Tid, WallMs};
use osis_crypto::{CryptoRngCore, Epoch, LabelRole, Secret32, SigningSecret, deposit_key};
use osis_keys::ActorEpochs;
use osis_label::Step;
use osis_schema::RawKey;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;
use std::sync::Arc;

/// A held commit as one blob (spec/sync-judgement.md §1): every held part, each sealed to its thing's
/// reader actor (`Engine::seal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub commit: CommitId,
    /// Aspect indices, sorted: the parts a judgment reads. From `commit_bodies_under` those the
    /// label's actor may read; from `body` every held part; from `part_bodies` the copied ones.
    pub parts: Vec<usize>,
    pub expires: Option<u64>,
    /// The header's blind (spec/crypto.md §7).
    pub blind: [u8; 16],
    /// The opened form `[Header, signature, [Part*]]` of what the blob carries (every held part
    /// of the commit, or a copy's parts); empty from `label_bodies_meta` (`body_plaintext`).
    pub plaintext: Vec<u8>,
    pub role_commit: bool,
    /// Its wrap's fetch order (`fetch_order`).
    pub order: u64,
    /// A per-label copy: `parts` in one section under the blob key (`Engine::seal_to`), never
    /// shared with another label (spec/sync-judgement.md §1): a role commit with a part on a thing other
    /// than the actor (its boxes give the readers that thing's secrets), or a part whose thing's
    /// read secret derives from neither the actor nor an actor of its closure (a cross-published
    /// `created.0`, a thing added from another actor's tree, read by role).
    pub to_label: bool,
}

/// A wrap's fetch order (spec/crypto.md §5): 0 for a commit a judgment of other commits needs or a
/// purge request (what it names does not show first), else the commit's `ts`. Read only to order
/// this node's fetches.
pub fn fetch_order(h: &osis_commit::Header) -> u64 {
    let foundation = h.kind.is_role() || h.has_request() || h.aspects.iter().any(|a| matches!(a.ak.as_str(), "created.0" | "retention^.0" | "group.0") || osis_schema::core_types::is_role_class(a.ak.as_str()));
    if foundation { 0 } else { h.ts.to_u64().max(1) }
}

/// A blob of a body: ID, bytes, key, prefix salt, the aspects its sections list and the parts
/// sealed into them.
pub struct Sealed {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub key: Secret32,
    pub salt: [u8; 16],
    pub ais: Vec<usize>,
    pub parts: Vec<usize>,
    /// The digests of the sections holding none of `parts` (copied verbatim, not opened here).
    pub unopened: crate::sync::SealedSet,
}

/// A commit blob opened (`Engine::open_commit`): the opened form of the parts this node could
/// read, the commit, the aspects every section lists, and the sections left sealed (copied
/// verbatim into a fresh encryption).
pub struct OpenedBlob {
    pub plaintext: Vec<u8>,
    pub commit: CommitBlob,
    pub ais: Vec<usize>,
    pub sealed: Vec<Section>,
    /// Every section as it came, opened or not: what a fresh encryption of the commit copies
    /// verbatim (`Engine::seal`'s `extra`, spec/crypto.md §5 Passing on).
    pub sections: Vec<Section>,
    /// A section opened under the blob key: a copy (`seal_to`), never copied into another
    /// encryption.
    pub copy: bool,
}

impl OpenedBlob {
    /// The aspect indices of the opened parts.
    pub fn parts(&self) -> Vec<usize> {
        self.commit.parts.iter().map(|p| p.ai).collect()
    }
}

/// Frames the opened form of a commit as a copy: every part in one section under the blob key
/// (tests and tools: a node seals with `Engine::seal`, per reader actor, or `Engine::seal_to`).
pub fn seal_plain(plaintext: &[u8], class: osis_label::Class, rng: &mut dyn CryptoRngCore) -> Result<Sealed> {
    let c = CommitBlob::decode(plaintext)?;
    let key = osis_crypto::BlobKey::fresh(rng);
    let env = osis_commit::seal_commit(&c, |_| (), |_, _| Some((key.secret().clone(), Vec::new())), &[], rng)?;
    framed(key, &env, &c.header, class, rng, &c)
}

/// Frames an envelope: random salt and key, prefix from the header and the sections' aspects
/// (spec/sync-ids.md §1, spec/wire.md §5).
pub fn frame_envelope(env: &Envelope, resolved: &osis_commit::Header, class: osis_label::Class, rng: &mut dyn CryptoRngCore, from: &CommitBlob) -> Result<Sealed> {
    framed(osis_crypto::BlobKey::fresh(rng), env, resolved, class, rng, from)
}

/// `frame_envelope` under `key`.
fn framed(key: osis_crypto::BlobKey, env: &Envelope, resolved: &osis_commit::Header, class: osis_label::Class, rng: &mut dyn CryptoRngCore, from: &CommitBlob) -> Result<Sealed> {
    let ais = env.ais();
    let groups = osis_commit::prefix_groups(resolved, ais.iter().copied())?;
    let salt = osis_label::Prefix::random_salt(rng);
    let prefix = osis_label::Prefix::for_delete_keys(salt, &env.header.blind, osis_commit::prefix_expiry(resolved, &ais).map(WallMs), &groups)?.with_class(class);
    let (key, blob) = osis_label::frame_under(key, &prefix, &env.encode())?;
    let parts: Vec<usize> = from.parts.iter().filter(|p| ais.contains(&p.ai)).map(|p| p.ai).collect();
    let unopened = env.sections.iter().filter(|s| !s.ais.iter().any(|ai| parts.contains(ai))).map(|s| s.digest()).collect();
    Ok(Sealed { id: osis_label::blob_id(&blob), blob, key, salt, ais, parts, unopened })
}

/// A group as `Engine::commit_bodies_under` sees it.
pub struct BodyCtx {
    pub closure: crate::engine::groups::Closure,
    pub actor: Tid,
    pub published: super::published::PublishedView,
}

impl BodyCtx {
    /// Whether a commit (its `View`) may have bodies under the group's labels.
    pub(crate) fn touches(&self, v: &crate::engine::View) -> bool {
        v.aspects.iter().any(|a| self.closure.contains(&a.tid) || self.published.contains(&a.tid) && matches!(a.ak.as_str(), "sync.0" | "created.0"))
    }
}

/// The label keys this node holds for a host's head (spec/sync-ids.md §2, spec/sync-ids.md §6).
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
    /// The head's epoch per label role (`LabelRole::ALL`: sync, write, delete) where held.
    pub epochs: [Option<Epoch>; 3],
}

impl HeadKeys {
    /// What tells two apart: the public keys and the rest.
    fn public(&self) -> ([Option<osis_crypto::VerifyingKey>; 4], bool, [Option<Epoch>; 3]) {
        ([&self.sync, &self.write, &self.delete, &self.deposit].map(|k| k.as_ref().map(SigningSecret::verifying_key)), self.sync_established, self.epochs)
    }
}

impl PartialEq for HeadKeys {
    fn eq(&self, o: &HeadKeys) -> bool {
        self.public() == o.public()
    }
}

impl std::fmt::Debug for HeadKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.public().fmt(f)
    }
}

/// The held epoch of `l`'s group role whose label key is `pk`, with that key and
/// whether that secret may be encrypted under (not reading-only, spec/crypto.md §4).
fn matching(e: &ActorEpochs, l: LabelRole, pk: &osis_crypto::VerifyingKey) -> Option<(Epoch, SigningSecret, bool)> {
    let (ep, k) = osis_keys::registered_key(e, l, pk)?;
    Some((ep, k, e.role(l.role()).secret(&ep).is_some()))
}

impl Engine {
    /// The body of a held commit: its header, blind and expiry, every held part, the opened form
    /// as the plaintext. `None`: not held, or no part of it held (a lasting header is
    /// `commit_bodies_under`'s).
    pub fn body(&mut self, c: &CommitId) -> Result<Option<Body>> {
        self.body_with(c, true)
    }

    /// `body`, with the plaintext only if `plaintext` (a label pass projects it only to seal).
    pub(crate) fn body_with(&mut self, c: &CommitId, plaintext: bool) -> Result<Option<Body>> {
        let id = *c;
        let Some(blob) = self.read(|tx| tx.get_commit(&id))? else { return Ok(None) };
        if blob.parts.is_empty() {
            return Ok(None);
        }
        let resolved = self.resolved_header(&blob);
        Ok(Some(Body {
            commit: id,
            parts: blob.parts.iter().map(|p| p.ai).collect(),
            expires: osis_commit::blob_expiry(&resolved),
            blind: blob.header.blind,
            plaintext: if plaintext { blob.encode() } else { Vec::new() },
            role_commit: blob.header.kind.is_role(),
            order: fetch_order(&resolved),
            to_label: false,
        }))
    }

    /// The applied (resolved) header of a held commit whose stored header lists go by link,
    /// else the stored one.
    pub(crate) fn resolved_header(&self, blob: &CommitBlob) -> std::sync::Arc<osis_commit::Header> {
        match self.core.ix.commits.get(&blob.id()) {
            Some(m) if !blob.header.is_resolved() => m.header.arc(),
            _ => std::sync::Arc::new(blob.header.clone()),
        }
    }

    /// Seals a body's parts (`b.parts` alone) as a copy (spec/sync-judgement.md §1): a fresh blob of one
    /// section under its own blob key (spec/wire.md §4), so whoever opens a wrap of it reads it: a
    /// certificate copy, wrapped under every label needing exactly those parts, or a per-label
    /// copy (`Body::to_label`).
    pub fn seal_to(&mut self, b: &Body, class: osis_label::Class, rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        osis_base::costs::count("copy sealed", 1);
        let c = osis_commit::rewrite(&CommitBlob::decode_stored(&pt)?, |ai| !b.parts.contains(&ai));
        let resolved = self.resolved_header(&c);
        let key = osis_crypto::BlobKey::fresh(rng);
        let env = osis_commit::seal_commit(&c, |_| (), |_, _| Some((key.secret().clone(), Vec::new())), &[], rng)?;
        framed(key, &env, &resolved, class, rng, &c).map(Some)
    }

    /// The derivation chain a section lists for thing `t` (spec/wire.md §4): from its first admin
    /// up to and including the actor its read secret derives from; empty for a thing with
    /// secrets of its own or a key actor.
    fn section_chain(&self, t: &Tid) -> Vec<Tid> {
        let mut out = Vec::new();
        if self.core.ix.own_keys.contains(t) || Some(*t) == self.core.me() {
            return out;
        }
        for step in self.core.record_chain(t) {
            match step {
                osis_base::ChainStep::Up { admin: up, .. } => {
                    out.push(up);
                    if self.core.ix.own_keys.contains(&up) || Some(up) == self.core.me() {
                        return out;
                    }
                }
                // a key actor above `t` is the first admin the step before pushed: listed once
                _ => return out,
            }
        }
        out
    }

    /// The epochs of each member of a section's derivation chain (`chain`, nearest first, no tid
    /// twice: spec/wire.md §4) held here, each derived down the nearer part of the chain to the
    /// nearest member (a member given secrets of its own since the section was sealed holds the
    /// derived epoch in its history). `last`: the previous chain of this blob opening and its
    /// answer (a commit's sections in one group share a chain: derived once, memory bounded).
    pub(super) fn chain_epochs(&self, chain: &[Tid], last: &mut Option<(Vec<Tid>, Vec<Arc<ActorEpochs>>)>) -> Vec<Arc<ActorEpochs>> {
        if let Some((o, v)) = last.as_ref()
            && o == chain
        {
            return v.clone();
        }
        let mut out = Vec::new();
        for (i, o) in chain.iter().enumerate() {
            let Some(mut e) = self.epochs(o) else { continue };
            for x in chain.get(..i).into_iter().flatten().rev() {
                e = Arc::new(ActorEpochs::derived(&e, x));
            }
            out.push(e);
        }
        *last = Some((chain.to_vec(), out.clone()));
        out
    }

    /// The read secrets of thing `t` derived by tid from `chain_epochs` of its section's chain.
    fn derived_through(&self, t: &Tid, chain: &[Tid], last: &mut Option<(Vec<Tid>, Vec<Arc<ActorEpochs>>)>) -> Vec<Secret32> {
        let mut out: Vec<Secret32> = Vec::new();
        for e in self.chain_epochs(chain, last) {
            for s in ActorEpochs::derived(&e, t).read.opening_newest_first() {
                if !out.iter().any(|x| x.expose() == s.expose()) {
                    out.push(s);
                }
            }
        }
        out
    }

    /// Seals a body as a fresh blob (spec/sync-judgement.md §1, spec/wire.md §4; a fresh blob key,
    /// salt and blob ID): one section per thing (its role parts, `osis_keys::under_roles`, in one of their own under
    /// the epoch's roles secret, spec/crypto.md §4 Roles secrets) among the commit's held parts that may go under
    /// an epoch of this node's choosing (`opened::passes_on`, spec/crypto.md §5 Passing on), each
    /// under that thing's read secret (a plain thing's derives from its base actor's by tid,
    /// spec/crypto.md §3, so a thing given secrets of its own later opens its earlier sections by
    /// its history; `wrap_secret`: the newest current epoch, a rotation's under the epoch it
    /// supersedes); for the other parts the sections of `extra` (held sections of the commit,
    /// opened or not) copied verbatim where none of their parts is held stripped or dropped; the
    /// prefix commits to the delete-key groups of every section's aspects. A part neither covers
    /// is left out (one another wrote that this node read only under an epoch not established
    /// here; a key actor's own record or card, whose current secret it lacks, which travels as a
    /// certificate copy), unless the body needs it (`b.parts`): then `None`, nothing is sealed
    /// now. A plain thing's derived epoch sealed under is noted (`note_sealed`, spec/crypto.md
    /// §4 Current).
    pub fn seal(&mut self, b: &Body, class: osis_label::Class, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        let c = CommitBlob::decode_stored(&pt)?;
        let resolved = self.resolved_header(&c);
        let things: Vec<Tid> = resolved.aspects.iter().map(|a| a.tid).collect();
        let roles: Vec<bool> = resolved.aspects.iter().map(|a| osis_keys::under_roles(a.ak.as_str())).collect();
        let id = c.id();
        // a held section goes as it came only where it carries what this node holds of it: none
        // of its parts held stripped or dropped (a purge's or an expiry's leftover)
        let whole: Vec<Section> = {
            let m = self.core.ix.commits.get(&id);
            extra.iter().filter(|s| s.ais.iter().all(|ai| m.is_none_or(|m| matches!(m.hold.get(*ai), None | Some(crate::engine::Hold::Body { .. } | crate::engine::Hold::Missing(_)))))).cloned().collect()
        };
        // per thing, every part of it here: its sections' epoch is chosen from them all (a
        // rotation's roles.0 section goes under the epoch it supersedes too)
        let mut of_thing: std::collections::BTreeMap<Tid, Vec<usize>> = std::collections::BTreeMap::new();
        for p in &c.parts {
            if let Some(t) = things.get(p.ai) {
                of_thing.entry(*t).or_default().push(p.ai);
            }
        }
        let mut under = Vec::new();
        let env = osis_commit::seal_commit(
            &c,
            |ai| (things.get(ai).copied(), roles.get(ai).copied().unwrap_or(false)),
            |(t, is_roles), parts| {
                let t = (*t)?;
                let (e, s) = self.section_secret(&id, &resolved, &t, of_thing.get(&t)?, parts)?;
                under.push((t, e));
                // role parts in a section of their own under the epoch's roles secret
                // (spec/crypto.md §4, Roles secrets)
                let s = if *is_roles { osis_crypto::roles_secret(&s) } else { s };
                Some((s, self.section_chain(&t)))
            },
            &whole,
            rng,
        )?;
        let s = frame_envelope(&env, &resolved, class, rng, &c)?;
        if b.parts.iter().any(|p| !s.parts.contains(p)) {
            return Ok(None);
        }
        for (t, e) in &under {
            self.note_sealed(t, e)?;
        }
        Ok(Some(s))
    }

    /// The epoch and secret a fresh encryption's section of commit `id` (header `h`) holding
    /// `parts` on thing `t` goes under (`of_thing`: every held part of `id` on `t`, which choose
    /// the epoch, `wrap_under`). A write goes under this node's epoch only where
    /// `opened::passes_on` (its invariant and the floor clause, at that epoch's floor), else as a
    /// held section of it or not at all (`None`). `seal` and `may_log` alike.
    pub(crate) fn section_secret(&mut self, id: &CommitId, h: &osis_commit::Header, t: &Tid, of_thing: &[usize], parts: &[usize]) -> Option<(Epoch, Secret32)> {
        let (e, s) = self.wrap_under(t, Some((id, of_thing)), false).ok().flatten()?;
        if !self.passes_on_all(id, h, parts, self.core.read_floor(t, &e)).ok()? {
            return None;
        }
        Some((e, s))
    }

    /// Opens a commit blob (spec/wire.md §4): each section under the read secrets of its thing
    /// (own, or derived from its base actor's; `read_secrets`, newest first), those derived through
    /// the derivation chain the section lists (the thing's record may be inside the section) and
    /// the blob key (a copy's, `seal_to`), the rest left sealed; checks the prefix against the
    /// header and the sections' aspects (spec/commits.md §4).
    pub fn open_commit(&mut self, blob: &[u8], key: &Secret32) -> Result<OpenedBlob> {
        let (prefix, pt) = osis_label::open(blob, key)?;
        let env = Envelope::decode(&pt)?;
        let id = env.id();
        // linked header lists: resolved from held blobs when they are here, else the sections
        // stay sealed (no aspect names a thing yet) and the prefix's commitment groups, which
        // need the lists, go unchecked
        let header: Option<std::sync::Arc<osis_commit::Header>> = match self.core.ix.commits.get(&id) {
            Some(m) if !env.header.is_resolved() => m.header.decoded(),
            _ if env.header.is_resolved() => Some(std::sync::Arc::new(env.header.clone())),
            _ => {
                let mut h = env.header.clone();
                let ok = self
                    .run(|tx| {
                        let Some(dedup) = tx.core.dedup(&h.actor) else { return Err(Error::Misuse("not resolved")) };
                        Ok(h.resolve(&mut crate::engine::blobs::TxBlobs::new(&mut tx.blobs, tx.txn.is_memory()), &dedup)?)
                    })
                    .is_ok();
                ok.then(|| std::sync::Arc::new(h))
            }
        };
        let ais = env.ais();
        // its expiry is the commit's (spec/sync-ids.md §1), from the header's own fields, checked
        // whether or not its lists resolve here: a blob framed under another expiry is no
        // encryption of the commit (it would outlive the commit, or expire with a smaller blob
        // dropped beside it as a strict subset)
        if prefix.expiry() != osis_commit::prefix_expiry(&env.header, &ais).map(WallMs) {
            return Err(Error::BadInput("blob prefix expiry is not its commit's"));
        }
        if let Some(h) = &header {
            let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
            if !prefix.agrees(osis_commit::prefix_expiry(h, &ais).map(WallMs), &h.blind, &groups, osis_label::Class::of_marker(h.ephemeral)) {
                return Err(Error::BadInput("blob prefix disagrees with its header"));
            }
        }
        let thing_of = |sec: &Section| header.as_ref().and_then(|h| sec.ais.first().and_then(|ai| h.aspects.get(*ai)).map(|a| a.tid));
        let last = std::cell::RefCell::new(None);
        let own = |sec: &Section| -> Vec<Secret32> {
            let t = thing_of(sec);
            let mut v: Vec<Secret32> = t.map(|t| self.read_secrets(&t)).unwrap_or_default();
            if let Some(t) = t {
                v.extend(self.derived_through(&t, &sec.chain, &mut last.borrow_mut()));
            }
            v
        };
        let copy = env.sections.iter().any(|sec| osis_crypto::unwrap_section(key, &id, &sec.wrap).is_ok());
        let opened = env.open(|sec| {
            let mut v = own(sec);
            v.push(key.clone());
            v
        })?;
        // the epoch each section under a read secret opened under (`labeling::opened`)
        if let Some(h) = &header {
            let mut under = Vec::new();
            for sec in &env.sections {
                let Some(t) = thing_of(sec) else { continue };
                if opened.sealed.contains(sec) || osis_crypto::unwrap_section(key, &id, &sec.wrap).is_ok() {
                    continue;
                }
                let Some((e, _)) = self.read_epochs(&t, &sec.chain).into_iter().find(|(_, s)| osis_crypto::unwrap_section(s, &id, &sec.wrap).is_ok()) else { continue };
                under.push((e, opened.commit.parts.iter().filter(|p| sec.ais.contains(&p.ai)).collect::<Vec<_>>()));
            }
            self.note_opened(h, &under);
        }
        Ok(OpenedBlob { plaintext: opened.commit.encode(), commit: opened.commit, ais, sealed: opened.sealed, sections: env.sections, copy })
    }

    /// The plaintext of a body (`label_bodies_meta` leaves it out): the opened form of every
    /// held part of the commit; empty when the commit is not held any more.
    pub fn body_plaintext(&mut self, b: &Body) -> Result<Vec<u8>> {
        if !b.plaintext.is_empty() {
            return Ok(b.plaintext.clone());
        }
        let id = b.commit;
        let Some(c) = self.read(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        // a lasting header (`commit_bodies_under`) carries no part
        if b.parts.is_empty() {
            return Ok(osis_commit::rewrite(&c, |_| true).encode());
        }
        Ok(c.encode())
    }

    /// The bodies a group's label must hold from its closure (spec/sync-judgement.md §1): held commits
    /// touching the closure with a part the group's actor may read. A home label (an actor
    /// synced as a group of itself) also carries the `label.0` and `created.0` writes of the
    /// labeled groups it is the nearest labeled record-chain actor of (spec/sync-ids.md §2).
    /// Without plaintexts (`body_plaintext`), from a memo per commit (`Core::bodies`): a pass after a
    /// change looks at only the commits it changed. The commits are found through `on_thing` and
    /// `by_aspect` (O(the closure's commits), no header decoded when the memo holds them), in ID
    /// order.
    pub fn label_bodies_meta(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let ctx = self.body_ctx(g);
        let core = &self.core;
        let mut ids: BTreeSet<CommitId> = ctx.closure.iter().flat_map(|t| core.on_thing(t)).collect();
        for t in ctx.published.iter() {
            for ak in ["sync.0", "created.0"] {
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
        BodyCtx { closure: self.core.ix.groups.closure_of(g), actor: self.group_actor(g), published: self.published_view(g) }
    }

    /// The parts of commit `id` (its held parts, or `parts`) the actor of `ctx` may read
    /// (spec/sync-judgement.md §1): those on things whose reader actor it may read.
    pub fn readable_parts(&self, ctx: &BodyCtx, id: &CommitId, parts: &[usize]) -> Vec<usize> {
        let Some(m) = self.core.ix.commits.get(id) else { return Vec::new() };
        let h = &m.header;
        parts.iter().filter(|ai| h.aspects.get(**ai).is_some_and(|a| self.reads(ctx, &a.tid))).copied().collect()
    }

    /// The parts of copy `c`, opened under a sync ID of `g`, that the sync ID carries no more
    /// (spec/sync-judgement.md §1: a sync ID carries the parts its group's actor may read, and
    /// certificate copies of role-class parts on any thing): content (`is_content`) on a thing
    /// under an actor with secrets of its own that the group's actor may not read now, left by a
    /// revocation since the per-sync-ID copy was placed (spec/permissions.md §3). With any,
    /// `open_entry` takes none of the copy (`Opened::NotOpen`): those parts come from a body under
    /// their own thing's sync ID, which read fetches as missing once this node may hold it.
    /// Invariant: no part taken from a copy gives a node anything of an actor it cannot read now.
    /// Content is left out here; a role-class part is taken because each is judged as it is used:
    /// `secrets.0` boxes by `rotation::may_take` as they open, `label.0` entry boxes by
    /// `may_learn`, `account.0` seeds only under a devices epoch held for use
    /// (`signing::usable_seeds`); `roles.0`, `keys.0` and `listing.0` are certificate material.
    pub fn copy_stale(&self, g: &Tid, c: &CommitBlob) -> BTreeSet<usize> {
        let actor = self.group_actor(g);
        let h = &c.header;
        let stale = |a: &osis_commit::AspectEntry| osis_schema::core_types::is_content(a.ak.as_str()) && self.core.secret_actor(&a.tid).is_some_and(|x| self.core.ix.own_keys.contains(&x)) && !self.actor_reads(&actor, &a.tid);
        c.parts.iter().map(|p| p.ai).filter(|ai| h.aspects.get(*ai).is_some_and(stale)).collect()
    }


    /// Whether the actor of `ctx` may read `t` (spec/sync-judgement.md §1).
    pub(crate) fn reads(&self, ctx: &BodyCtx, t: &Tid) -> bool {
        self.actor_reads(&ctx.actor, t)
    }

    /// Whether the actor of group `g` may read `t` (`reads`).
    pub fn reads_in(&self, g: &Tid, t: &Tid) -> bool {
        let actor = self.group_actor(g);
        self.actor_reads(&actor, t)
    }

    fn actor_reads(&self, actor: &Tid, t: &Tid) -> bool {
        self.core.may_read(actor, &self.core.reader_of(t))
    }

    /// Whether the actor of group `g` reads `t` as every node judges it, for placing chain
    /// certificates alone (spec/sync-judgement.md §1: a devices actor reads as its account,
    /// whichever node judges it): any account's devices actor reads what its account reads, so
    /// the chains placed under a sync ID are the same at every node. Never an access, sealing,
    /// boxing or opening decision: there `reads_in`.
    pub(crate) fn cert_reads_in(&self, g: &Tid, t: &Tid) -> bool {
        let actor = self.group_actor(g);
        let reader = self.core.devices_of(&actor).unwrap_or(actor);
        self.core.may_read(&reader, &self.core.reader_of(t))
    }

    /// The parts of `h` a label of `ctx`'s group carries in its bodies (spec/sync-judgement.md §1): those on
    /// things of its closure its actor may read. A chain certificate's part on any other thing goes
    /// there as a certificate copy (spec/permissions.md §4).
    pub fn body_carried(&self, ctx: &BodyCtx, h: &osis_commit::Header) -> std::collections::BTreeSet<usize> {
        h.aspects.iter().enumerate().filter(|(_, a)| ctx.closure.contains(&a.tid) && self.reads(ctx, &a.tid)).map(|(i, _)| i).collect()
    }

    /// The body of commit `id` a label of the group of `ctx` must hold (`label_bodies_meta`):
    /// with the parts its actor may read among those inside the closure (or published there),
    /// when there are any; else, for a lasting commit, its header alone.
    pub fn commit_bodies_under(&mut self, ctx: &BodyCtx, id: &CommitId) -> Result<Vec<Body>> {
        self.bodies_under(ctx, id, false)
    }

    /// `commit_bodies_under`, with `unheld` the parts not held included: missing ones
    /// (spec/sync-judgement.md §3 Dropped bodies: a part counting as never received again is
    /// still the body's, to fetch again) and dropped ones (§2: a body dropped here is may-hold,
    /// its entries leaving by the carriers rule, not at once): what the sync judgement reads
    /// (`sync_bodies`). A body of such parts alone has no plaintext.
    pub(crate) fn bodies_under(&mut self, ctx: &BodyCtx, id: &CommitId, unheld: bool) -> Result<Vec<Body>> {
        drop(osis_base::costs::span("pass: bodies of a commit"));
        let id = *id;
        // the view: the header is decoded only for bodies the cache misses
        let Some(h) = self.core.ix.commits.get(&id).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
        if !ctx.touches(&h) {
            return Ok(Vec::new());
        }
        let touches = h.aspects.iter().any(|a| ctx.closure.contains(&a.tid));
        let mut body = Memo::get_in(self, |e| &e.core.bodies, &id, |e| e.body_with(&id, false))?;
        let gone: Vec<usize> = if unheld { self.core.ix.commits.get(&id).map(|m| m.missing_parts().chain(m.dropped_parts().map(|(ai, _)| ai)).collect()).unwrap_or_default() } else { Vec::new() };
        if !gone.is_empty() {
            body = match body {
                Some(mut b) => {
                    b.parts.extend(gone);
                    b.parts.sort_unstable();
                    b.parts.dedup();
                    Some(b)
                }
                None => self.header(&id).map(|full| Body { commit: id, parts: gone, expires: osis_commit::blob_expiry(&full), blind: full.blind, plaintext: Vec::new(), role_commit: full.kind.is_role(), order: fetch_order(&full), to_label: false }),
            };
        }
        let mut out = Vec::new();
        if let Some(mut b) = body {
            let published = |ai: usize| h.aspects.get(ai).is_some_and(|a| !ctx.closure.contains(&a.tid) && ctx.published.contains(&a.tid) && matches!(a.ak.as_str(), "sync.0" | "created.0"));
            let inside = |ai: usize| h.aspects.get(ai).is_some_and(|a| touches && ctx.closure.contains(&a.tid)) || published(ai);
            let parts: Vec<usize> = b.parts.iter().copied().filter(|ai| inside(*ai)).collect();
            let readable = self.readable_parts(ctx, &id, &parts);
            if !readable.is_empty() {
                // judged on what the actor reads; the blob carries every held part (`body_plaintext`),
                // unless the label's readers could not open a section of it: a per-label copy
                // (spec/sync-judgement.md §1, `Body::to_label`): a role commit on another thing (its
                // rotation, its grants, a cross-published `label.0`), whose boxes are what gives
                // the readers that thing's secrets, so its own section cannot be under them
                // (certificate blobs are copies for the same reason), or a part whose thing's
                // secret neither derives from the actor's nor comes through the closure (a destroyed
                // actor's boxes went with it: its secrets come through nothing)
                let derivable = |ai: usize| h.aspects.get(ai).is_some_and(|a| self.core.secret_actor(&a.tid).is_some_and(|x| x == ctx.actor || (ctx.closure.contains(&x) && !self.core.destroyed(&x))));
                // (a `created.0` part carries no boxes: a records-only role commit is shared)
                let role_elsewhere = h.kind.is_role() && readable.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid != ctx.actor && a.ak.as_str() != "created.0"));
                b.to_label = role_elsewhere || readable.iter().any(|ai| !derivable(*ai));
                b.parts = readable;
                out.push(b);
            }
        }
        // nothing of it here and a lasting header on the label's things: its header alone
        // (spec/commits.md §5, spec/sync-judgement.md §2)
        let now = self.now().0;
        let forever = |a: &crate::engine::AspectView| !h.memory && osis_commit::retention::fixed_retention(a.ak.as_str()).is_none() && crate::retention::history::of(&self.core, &a.tid, &a.ak).forever(now);
        if out.is_empty() && touches && (h.purges || h.aspects.iter().any(forever)) {
            let on = |core: &crate::engine::Core, t: &Tid| ctx.closure.contains(t) && core.may_read(&ctx.actor, &core.reader_of(t));
            if self.run(|tx| crate::retention::lasting(tx, &id, &on))?
                && let Some(blind) = self.core.ix.commits.get(&id).map(|m| m.header.blind)
            {
                out.push(Body { commit: id, parts: Vec::new(), expires: None, blind, plaintext: Vec::new(), role_commit: false, order: h.ts.to_u64().max(1), to_label: false });
            }
        }
        Ok(out)
    }

    /// The read secret a commit is wrapped under at a label of `g` (spec/crypto.md §5): the
    /// newest current read epoch held, except a rotation commit of the actor `g`'s secrets
    /// derive from, which goes under the newest epoch its rotation supersedes, never another.
    /// `None`: no current secret held (stranded: nothing is placed), no superseded secret of a
    /// rotation held (a holder of a floor above them), or a part of `c` it carries this node
    /// may not pass on under an epoch of its choosing (spec/crypto.md §5 Passing on).
    /// A blob carrying a role part of that actor (`osis_keys::under_roles`) goes under the epoch's
    /// roles secret (spec/crypto.md §4, Roles secrets): every holder of the actor opens it.
    pub fn wrap_secret(&mut self, g: &Tid, c: Option<(&CommitId, &[usize])>) -> Result<Option<Secret32>> {
        let roles = c.is_some_and(|(c, parts)| self.carries_roles(g, c, parts));
        Ok(self.wrap_under(g, c, true)?.map(|(_, s)| if roles { osis_crypto::roles_secret(&s) } else { s }))
    }

    /// Whether these deltas of `c` hold a role part (`osis_keys::under_roles`) of the actor `g`'s
    /// secrets derive from.
    fn carries_roles(&self, g: &Tid, c: &CommitId, parts: &[usize]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|ai| h.aspects.get(*ai)).any(|x| x.tid == a && osis_keys::under_roles(x.ak.as_str()))
    }

    /// `wrap_secret` with its epoch (`entry`: the blob's wrap, else a section's).
    fn wrap_under(&mut self, g: &Tid, c: Option<(&CommitId, &[usize])>, entry: bool) -> Result<Option<(Epoch, Secret32)>> {
        let Some(e) = self.epochs(g) else { return Ok(None) };
        let rotation = match c {
            Some((c, parts)) if self.carries_secrets(g, c, parts) => match self.rotation_wrap_epoch(g, c)? {
                RotationWrap::Plain => None,
                // a rotation goes under an epoch it supersedes or not at all (a holder of a floor
                // above them, or one lacking their secrets, may not choose another)
                RotationWrap::Lacking => return Ok(None),
                RotationWrap::Under(ep) => e.read.secret(&ep).map(|s| (ep, s.clone())),
            },
            Some((c, _)) if entry => self.account_rotation_wrap_epoch(g, c)?.and_then(|ep| e.read.secret(&ep).map(|s| (ep, s.clone()))),
            _ => None,
        };
        let own_wrap = rotation.is_some();
        let Some((ep, s)) = rotation.or_else(|| osis_keys::wrap_epoch(&e.read).and_then(|ep| e.read.secret(&ep).map(|s| (ep, s.clone())))) else { return Ok(None) };
        // spec/crypto.md §4 Encrypting under: wrapping is encrypting under the epoch, so none
        // under one blocked here (a rotation's own wrap excepted)
        if !own_wrap && self.wrap_blocked(&self.core.reader_of(g), c.map(|x| x.0))? {
            return Ok(None);
        }
        // the wrap gates the header, and a copy's whole content: under this node's epoch only
        // where every part it carries may go so and the commit's header may, at that epoch's
        // floor (`Engine::passes_on_parts`, spec/crypto.md §5 Passing on)
        if let Some((c, parts)) = c
            && !self.passes_on_parts(c, parts, &super::opened::Wrapping { thing: *g, actor: self.core.reader_of(g), floor: e.read.floor(&ep) })?
        {
            return Ok(None);
        }
        Ok(Some((ep, s)))
    }

    /// Whether read of `a` is blocked here for a wrap of commit `c` (spec/crypto.md §4 Encrypting
    /// under): a role commit, which goes as a certificate or as this node's own, by the placing
    /// walk (`Walk::Place`: through holder actors this node may rotate only, so a node that may
    /// not still logs what tells their rotators); anything else by the encrypting walk, and also
    /// while this node holds a grant on `a` it may finalize (spec/permissions.md §2 Finalize: the
    /// finalize goes before its next commit encrypting under `a`; the driver's role duties write
    /// it, `Engine::role_duty_due`). A key actor's epochs are its seed's: never blocked.
    /// Kept per (actor, walk) (`Core::wrap_blocks`, `memo::Cutoff`): every body judged under a
    /// sync ID asks it, and what it reads (the actor's component whole) moves far more often
    /// than its answer.
    fn wrap_blocked(&mut self, a: &Tid, c: Option<&CommitId>) -> Result<bool> {
        if self.core.is_key_actor(a) {
            return Ok(false);
        }
        let walk = match c.and_then(|c| self.header(c)) {
            Some(h) if !h.kind.is_role() => crate::rotation::Walk::Encrypt,
            _ => crate::rotation::Walk::Place,
        };
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.wrap_blocks, &(*a, walk), |e, (a, walk)| e.wrap_blocked_read(a, *walk))
    }

    /// `wrap_blocked` read anew.
    pub(crate) fn wrap_blocked_read(&mut self, a: &Tid, walk: crate::rotation::Walk) -> Result<bool> {
        let a = *a;
        // the roles at now it reads (`finalizable`, `may_rotate`) hold until the clock reaches
        // the next `until` or role commit in the components of `a` and this node's account
        self.core.time.until(self.core.horizon(std::iter::once(a).chain(self.core.writer().ok())));
        self.read(|tx| {
            // a node removed from its account wraps nothing as it (it may still hold the read
            // secrets through the pass its drop waits for)
            let Ok(who) = tx.core.writer() else { return Ok(true) };
            if matches!(walk, crate::rotation::Walk::Encrypt) && !crate::flows::edges::finalizable(tx.core, &who, &a).is_empty() {
                return Ok(true);
            }
            let deps = crate::rotation::departures(tx, &a)?;
            Ok(crate::rotation::blocked_roles_of(tx, &who, &a, &deps, walk)?.contains(&Role::Read))
        })
    }

    /// Held read secrets of a group, newest first; then those derived from its first admin's (a
    /// thing that got secrets of its own, or one under a key actor this node holds: the rotation
    /// that gave it its own is wrapped under the derived epoch, spec/crypto.md §5).
    /// Each epoch's roles secret follows its secret (spec/crypto.md §4, Roles secrets), and one
    /// held without its secret stands alone. None of a destroyed thing whose secrets are held for
    /// deletes alone (`retention::destroy::hold_secrets`): they open nothing new.
    pub fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        if self.core.ix.destroyed_secrets.contains(g) {
            return Vec::new();
        }
        let mut v: Vec<Secret32> = self.epochs(g).map(|e| e.read.opening_newest_first()).unwrap_or_default();
        // the first admin's epochs; a thing whose `created.0` is not here yet (a link's
        // person) may have any key actor held as first admin
        let firsts: Vec<Arc<osis_keys::ActorEpochs>> = match self.core.created(g).map(osis_base::CreationRecord::first_admin) {
            Some(Some(up)) => self.epochs(&up).or_else(|| self.core.key_actors.get(&up).map(|id| Arc::new(osis_keys::ActorEpochs::key_actor(id.seed())))).into_iter().collect(),
            Some(None) => Vec::new(),
            None => self.core.key_actors.values().map(|id| Arc::new(osis_keys::ActorEpochs::key_actor(id.seed()))).collect(),
        };
        for oe in firsts {
            for s in osis_keys::ActorEpochs::derived(&oe, g).read.opening_newest_first() {
                if !v.iter().any(|x| x.expose() == s.expose()) {
                    v.push(s);
                }
            }
        }
        v
    }

    /// Whether these deltas of `c` hold the `secrets.0` or `keys.0` of the actor `g`'s secrets derive
    /// from (only a blob carrying the boxes takes the rotation's wrap exception).
    pub fn carries_secrets(&self, g: &Tid, c: &CommitId, parts: &[usize]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|ai| h.aspects.get(*ai)).any(|x| x.tid == a && matches!(x.ak.as_str(), "secrets.0" | "keys.0"))
    }
    /// The secret a list blob of rotation `r` is wrapped under at `g` (spec/crypto.md §5 Who
    /// wraps under what: a rotation's thing lists are parts of it and wrap as it does): the roles
    /// secret (lists are role-class, spec/crypto.md §4 Roles secrets: a history-less holder holds
    /// it of every earlier epoch) of the newest established read epoch of `g`'s secret actor whose
    /// secret is held and that no rotation ordered at or after `r` minted (by (`ts`, author,
    /// commit ID), spec/permissions.md §5.1; `r`'s own epoch is not current when it is made), so
    /// a rotation of `g` that `r` caused takes nothing from whoever read `g` before it. Like a
    /// rotation's own wrap, it is not subject to `wrap_blocked`. An account's rotation at a sync
    /// ID of its devices actor: the roles secret of its entry's epoch
    /// (`account_rotation_wrap_epoch`), so its lists open wherever its entry does. `None`: `r` or
    /// no such epoch is held.
    pub(crate) fn list_wrap_secret(&mut self, g: &Tid, r: &CommitId) -> Result<Option<Secret32>> {
        if let Some(ep) = self.account_rotation_wrap_epoch(g, r)?
            && let Some(s) = self.epochs(g).and_then(|e| e.read.secret(&ep).cloned())
        {
            return Ok(Some(osis_crypto::roles_secret(&s)));
        }
        Ok(self.list_wrap_under(g, r))
    }

    /// `list_wrap_secret` for any rotation but an account's at its devices actor's sync IDs.
    fn list_wrap_under(&mut self, g: &Tid, r: &CommitId) -> Option<Secret32> {
        let a = self.core.secret_actor(g)?;
        let h = self.header(r)?;
        let at = (h.ts, h.author, *r);
        let e = self.epochs(&a)?;
        let (intro, commits) = (&self.core.ix.epoch_intro, &self.core.ix.commits);
        let before = |(ts, c): &(osis_base::Ts, CommitId)| commits.get(c).map_or(*ts < at.0, |m| (*ts, m.view.author, *c) < at);
        // role-class metadata: under that epoch's roles secret, which a history-less holder gets
        // of every earlier epoch (spec/crypto.md §4 Roles secrets)
        e.read.newest_held_where(|x| intro.get(&(a, Role::Read, *x)).is_none_or(before)).map(|(_, s)| osis_crypto::roles_secret(s))
    }

    /// For a rotation commit of the read role of `g`'s secret actor (its `keys.0` delta writes a
    /// read keyset): the newest held epoch the new read epoch supersedes (spec/crypto.md §5, Who
    /// wraps under what), `Lacking` where none is held (or the keyset is not held to tell).
    fn rotation_wrap_epoch(&mut self, g: &Tid, c: &CommitId) -> Result<RotationWrap> {
        let Some(a) = self.core.secret_actor(g) else { return Ok(RotationWrap::Plain) };
        let Some(h) = self.header(c) else { return Ok(RotationWrap::Plain) };
        let Some(ai) = h.aspect_index(&a, "keys.0") else { return Ok(RotationWrap::Plain) };
        if h.aspect_index(&a, "secrets.0").is_none() {
            return Ok(RotationWrap::Plain);
        }
        let id = *c;
        let Some(f) = self.read(|tx| crate::apply::held_fragment(tx, &id, ai))? else { return Ok(RotationWrap::Lacking) };
        let Some(ks) = crate::apply::keys::keys_write(&f).keysets.remove(&Role::Read) else { return Ok(RotationWrap::Plain) };
        let Ok(e) = osis_keys::aspects::from_schema(&ks.epoch) else { return Ok(RotationWrap::Lacking) };
        let Some(epochs) = self.epochs(&a) else { return Ok(RotationWrap::Lacking) };
        Ok(epochs.read.wrapped_under(&e).map_or(RotationWrap::Lacking, |(s, _)| RotationWrap::Under(s)))
    }

    /// For a rotation of an account (spec/crypto.md §9) at a sync ID whose read secrets are its
    /// devices actor D's: the newest held D read epoch that the epoch its seed sits under (its
    /// `account.0` entry's `under`) supersedes, the one D's own rotation made with it is wrapped
    /// under. Invariant: the rotation that makes a sibling's removal R from D count elsewhere (by
    /// naming it in its thing list for D, spec/permissions.md §5.5) opens without R's new D epoch,
    /// which is established there only once R counts; else R and its rotation wait on each other
    /// at every node that closed R's epoch before receiving R. Only the header goes so (a wrap
    /// gates the header, which readers outside the account hold anyway): the sections, the seed
    /// and the deposit seed with them, stay under the epoch chosen as for any commit.
    fn account_rotation_wrap_epoch(&mut self, g: &Tid, c: &CommitId) -> Result<Option<Epoch>> {
        let Some(d) = self.core.secret_actor(g) else { return Ok(None) };
        let Some(h) = self.header(c) else { return Ok(None) };
        let Some(rot) = h.rotation.as_ref() else { return Ok(None) };
        if self.core.devices_of(&d) != Some(h.author) {
            return Ok(None);
        }
        let Some(ai) = h.aspect_index(&d, "account.0") else { return Ok(None) };
        let key = rot.signing_key.to_bytes().to_vec();
        let id = *c;
        let Some(f) = self.read(|tx| crate::apply::held_fragment(tx, &id, ai))? else { return Ok(None) };
        let Some(acct) = f.read().and_then(|x| ct::ACCOUNT.decode(&x).ok()) else { return Ok(None) };
        let Some(under) = acct.seeds.get(&key).and_then(|s| osis_keys::aspects::from_schema(&s.under).ok()) else { return Ok(None) };
        let Some(epochs) = self.epochs(&d) else { return Ok(None) };
        Ok(epochs.read.wrapped_under(&under).map(|(s, _)| s))
    }

    /// The deposit seed of `g`'s actor (its `keys.0`; `flows::sync_ids::deposit_seed_of`).
    pub fn deposit_seed(&mut self, g: &Tid) -> Result<Option<Secret32>> {
        self.read(|tx| crate::flows::sync_ids::deposit_seed_of(tx, g))
    }

    /// The keys this node holds for `head` of a label of `g` (spec/sync-ids.md §2, spec/sync-ids.md §6): any
    /// held secret opens; stamps and deletes need an established epoch (spec/crypto.md §4), but for
    /// the delete key of a destroyed thing whose secrets are held for deletes alone
    /// (`retention::destroy::hold_secrets`): what established them went with it, and the step
    /// bearing the key vouches for the secret (spec/sync-judgement.md §5 Emptying). Its delete
    /// key alone: its epochs established nowhere, nothing is wrapped under them (`wrap_under`),
    /// and `read_secrets` gives none, so nothing new opens.
    pub fn head_keys(&mut self, g: &Tid, head: &Step) -> Result<HeadKeys> {
        Memo::get_in(self, |e| &e.core.head_keys, &(*g, head.id()), |e| e.head_keys_derived(g, head))
    }

    fn head_keys_derived(&mut self, g: &Tid, head: &Step) -> Result<HeadKeys> {
        let mut k = HeadKeys::default();
        if let Some(e) = self.epochs(g) {
            if let Some((ep, s, _)) = matching(&e, LabelRole::Sync, &head.keys.sync) {
                k.sync = Some(s);
                k.sync_established = self.established(g, &e, Role::Sync, &ep);
                k.epochs[0] = Some(ep);
            }
            // stamps and deletes are encrypting under: never from a reading-only secret
            if let Some((ep, s, checked)) = matching(&e, LabelRole::Write, &head.keys.write) {
                if checked && self.established(g, &e, Role::Write, &ep) {
                    k.write = Some(s);
                }
                k.epochs[1] = Some(ep);
            }
            if let Some((ep, s, checked)) = matching(&e, LabelRole::Delete, &head.keys.delete) {
                if checked && (self.established(g, &e, Role::Admin, &ep) || self.core.ix.destroyed_secrets.contains(g)) {
                    k.delete = Some(s);
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
    /// got secrets of its own, as the epoch derived from an established epoch of the base
    /// actor it had before (spec/crypto.md §3-§4; the history box carries it without establishment).
    fn established(&self, g: &Tid, e: &ActorEpochs, r: Role, ep: &Epoch) -> bool {
        if e.role(r).is_established(ep) {
            return true;
        }
        let Some(up) = self.core.created(g).and_then(osis_base::CreationRecord::first_admin) else { return false };
        self.epochs(&up).is_some_and(|o| ActorEpochs::derived(&o, g).role(r).is_established(ep))
    }
}

/// The label key of `keys` that signs `item` (the delete key, or the key its levels need).
pub fn delete_key<'a>(keys: &'a HeadKeys, item: &osis_label::DeleteItem) -> Option<&'a SigningSecret> {
    match osis_label::key_for_levels(&item.levels()) {
        Ok(LabelRole::Delete) => keys.delete.as_ref(),
        Ok(LabelRole::Write) => keys.write.as_ref(),
        Ok(_) => keys.sync.as_ref().filter(|_| keys.sync_established),
        Err(_) => None,
    }
}

/// The wrap a commit carrying `secrets.0` or `keys.0` of an actor takes (`rotation_wrap_epoch`).
enum RotationWrap {
    /// No read rotation: the plain rule.
    Plain,
    /// A read rotation, under this superseded epoch.
    Under(Epoch),
    /// A read rotation whose superseded epochs this node holds no secret of: not wrapped here.
    Lacking,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use osis_schema::core_types as ct;

    // spec/crypto.md §3, spec/wire.md §4: a record chain of two plain things under the node: O,
    // whose first admin is the node, derives from the node's epochs and T, whose first admin is
    // O, from O's; a section on T lists the chain up to the node, one on O the node.
    #[test]
    fn derives_through_a_first_admin_spec_crypto_3() {
        use crate::Mutation;
        let mut lp = crate::local_peer::LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let (o, _) = e.create_with_admin(&me).unwrap();
        let mut m = Mutation::new();
        let t = e.new_thing(&mut m, o);
        m.set(t, &osis_base::Ak::new("x:a.0").unwrap(), &osis_base::Value::Int(1)).unwrap();
        e.commit(m).unwrap().unwrap();
        let node = e.core.epochs(&me).unwrap();
        let of_o = ActorEpochs::derived(&node, &o);
        assert_eq!(*e.core.epochs(&o).unwrap(), of_o);
        assert_eq!(*e.core.epochs(&t).unwrap(), ActorEpochs::derived(&of_o, &t));
        assert_eq!(e.section_chain(&t), vec![o, me]);
        assert_eq!(e.section_chain(&o), vec![me]);
    }

    // spec/sync-judgement.md §3 (driven by events): convergence after each change; the pass's cost: a group's bodies are
    // projected per commit once and kept until what they read changes, so one more commit
    // leaves every other commit's bodies kept.
    #[test]
    fn label_bodies_cached_per_commit_spec_sync_6() {
        use crate::Mutation;
        let mut lp = crate::local_peer::LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.me();
        let mut m = Mutation::new();
        let g = e.new_thing(&mut m, me);
        e.commit(m).unwrap();
        let ak = osis_base::Ak::new("x:a.0").unwrap();
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
        let runs = || osis_base::costs::take().iter().filter(|x| x.0 == "label body").map(|x| x.2).sum::<u64>();
        osis_base::costs::take();
        let first = e.label_bodies_meta(&g).unwrap();
        assert!(first.len() >= 30 && first.iter().all(|b| b.plaintext.is_empty()));
        assert!(runs() >= 30);
        let c = add(e, &mut group);
        osis_base::costs::take();
        let again = e.label_bodies_meta(&g).unwrap();
        assert!(again.iter().any(|b| b.commit == c));
        assert_eq!(runs(), 1, "a new commit leaves the others' bodies kept");
        let b = again.iter().find(|b| b.commit == c).unwrap();
        assert!(!e.body_plaintext(b).unwrap().is_empty(), "the plaintext is projected on demand");
    }

    // spec/crypto.md §4: a secret learned only from a pending or invalid commit is never
    // encrypted under; signing a stamp or delete is. A reading-only write or admin secret still
    // finds the head's epoch (opening, walking) but is not offered for signing.
    #[test]
    fn reading_only_head_secret_never_signs_spec_crypto_4() {
        let e = Epoch::new(2, [2; 32]).unwrap();
        let s = Secret32::from_bytes([5; 32]);
        let mut a = ActorEpochs::default();
        a.write.set_reading_secret(e, s.clone(), osis_keys::Unchecked { author: Tid::from_bytes([1; 15]), commit: CommitId([1; 32]) });
        a.write.set_established(e, osis_keys::Provenance::Rotated);
        let pk = osis_crypto::label_role_key(LabelRole::Write, &s).verifying_key();
        let (ep, got, checked) = matching(&a, LabelRole::Write, &pk).unwrap();
        assert_eq!((ep, got.verifying_key(), checked), (e, pk, false));
        a.write.set_secret(e, s.clone());
        assert!(matching(&a, LabelRole::Write, &pk).unwrap().2);
    }
}
