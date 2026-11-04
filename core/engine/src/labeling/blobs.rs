//! Bodies, sealing, wraps, stamps, deposits and delete keys (spec/sync.md §1-§3, §5;
//! spec/crypto.md §5, §7): what a commit becomes under a label, and the label keys a host's head calls for.

use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_commit::{CommitBlob, Envelope, Section};
use osis_base::{BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_crypto::{CryptoRngCore, DeleteSecret, Epoch, LabelRole, Secret32, SigningSecret, deposit_key, label_role_key};
use osis_keys::{ActorEpochs, WrapEpoch};
use osis_label::Step;
use osis_schema::core_types as ct;
use std::collections::BTreeSet;

/// A held commit as one blob (spec/sync.md §3): every held part, each sealed to its thing's
/// reader actor (`Engine::seal`).
#[derive(Clone, Debug)]
pub struct Body {
    pub commit: CommitId,
    /// `(ai, di)`, sorted: the parts a judgment reads. From `commit_bodies_under` those the
    /// label's actor may read; from `body` every held part; from `part_bodies` the copied ones.
    pub parts: Vec<(usize, usize)>,
    pub expires: Option<u64>,
    /// The header's blind (spec/crypto.md §7).
    pub blind: [u8; 16],
    /// The opened form `[Header, signature, [Part*]]` of what the blob carries (every held part
    /// of the commit, or a copy's parts); empty from `label_bodies_meta` (`body_plaintext`).
    pub plaintext: Vec<u8>,
    pub role_commit: bool,
    /// Its wrap's fetch order (`fetch_order`).
    pub order: u64,
    /// Sealed per label in one section of `parts` under the label's actor (`Engine::seal_to`),
    /// never shared with another label (spec/sync.md §3): a role commit with a part on a thing
    /// other than the actor (its boxes give the readers that thing's secrets), or a part whose
    /// thing's read secret derives from neither the actor nor an actor of its closure (a
    /// cross-published `created.0`, a thing placed from another actor's tree, read by role).
    pub to_label: bool,
}

/// A wrap's fetch order (spec/crypto.md §5): 0 for a commit a judgment of other commits needs or a
/// purge request (what it names does not show first), else the commit's `ts`. Read only to order
/// this node's fetches.
pub fn fetch_order(h: &osis_commit::Header) -> u64 {
    let foundation = h.kind.is_role() || !h.purge.is_empty() || h.aspects.iter().any(|a| matches!(a.ak.as_str(), "created.0" | "required.0^" | "group.0") || osis_schema::core_types::is_role_class(a.ak.as_str()));
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
    pub parts: Vec<(usize, usize)>,
}

/// A commit blob opened (`Engine::open_commit`): the opened form of the parts this node could
/// read, the commit, the aspects every section lists, and the sections left sealed (copied
/// verbatim into a fresh encryption).
pub struct OpenedBlob {
    pub plaintext: Vec<u8>,
    pub commit: CommitBlob,
    pub ais: Vec<usize>,
    pub sealed: Vec<Section>,
    /// A section on a thing other than the label's group opened under the group's secret and
    /// none of the thing's: a per-label copy (`seal_to`), of use under no other label.
    pub copy: bool,
}

impl OpenedBlob {
    /// `(ai, di)` of the opened parts.
    pub fn parts(&self) -> Vec<(usize, usize)> {
        self.commit.parts.iter().map(|p| (p.ai, p.di)).collect()
    }
}

/// Frames the opened form of a commit as a blob whose every part is in one section under
/// `secret` (tests and tools: a node seals with `Engine::seal`, per reader actor).
pub fn seal_plain(plaintext: &[u8], secret: &Secret32, class: osis_label::Class, rng: &mut dyn CryptoRngCore) -> Result<Sealed> {
    let c = CommitBlob::decode(plaintext)?;
    let env = osis_commit::seal_commit(&c, |_| (), |_, _| Some((secret.clone(), Vec::new())), &[], rng)?;
    frame_envelope(&env, &c.header, class, rng, &c)
}

/// Frames an envelope: random salt and key, prefix from the header and the sections' aspects
/// (spec/sync.md §1, spec/wire.md §5).
pub fn frame_envelope(env: &Envelope, resolved: &osis_commit::Header, class: osis_label::Class, rng: &mut dyn CryptoRngCore, from: &CommitBlob) -> Result<Sealed> {
    let ais = env.ais();
    let groups = osis_commit::prefix_groups(resolved, ais.iter().copied())?;
    let salt = osis_label::Prefix::random_salt(rng);
    let prefix = osis_label::Prefix::for_delete_keys(salt, &env.header.blind, osis_commit::blob_expiry(resolved).map(WallMs), &groups)?.with_class(class);
    let (key, blob) = osis_label::frame(&prefix, &env.encode(), rng)?;
    let parts = from.parts.iter().filter(|p| ais.contains(&p.ai)).map(|p| (p.ai, p.di)).collect();
    Ok(Sealed { id: osis_label::blob_id(&blob), blob, key, salt, ais, parts })
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
        v.aspects.iter().any(|a| self.closure.contains(&a.tid) || self.published.contains(&a.tid) && matches!(a.ak.as_str(), "label.0" | "created.0"))
    }
}

/// The label keys this node holds for a host's head (spec/sync.md §2, §5).
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

    /// What tells two apart: the public keys and the rest.
    #[cfg(debug_assertions)]
    fn public(&self) -> ([Option<osis_crypto::VerifyingKey>; 4], bool, [Option<Epoch>; 3]) {
        ([&self.sync, &self.write, &self.delete, &self.deposit].map(|k| k.as_ref().map(SigningSecret::verifying_key)), self.sync_established, self.epochs)
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
    /// The body of a held commit: its header, blind and expiry, every held part, the opened form
    /// as the plaintext. `None`: not held, or no part of it held (a lasting header is
    /// `commit_bodies_under`'s).
    pub fn body(&mut self, c: &CommitId) -> Result<Option<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(None) };
        if blob.parts.is_empty() {
            return Ok(None);
        }
        let resolved = self.resolved_header(&blob);
        Ok(Some(Body {
            commit: id,
            parts: blob.parts.iter().map(|p| (p.ai, p.di)).collect(),
            expires: osis_commit::blob_expiry(&resolved),
            blind: blob.header.blind,
            plaintext: blob.encode(),
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

    /// `seal` of an opened form given as bytes (tests and tools: a copy, a forgery): a body
    /// built from it, with the commit's expiry and order from its header as held here.
    pub fn seal_plaintext(&mut self, plaintext: &[u8], class: osis_label::Class, rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let c = CommitBlob::decode(plaintext)?;
        let resolved = self.resolved_header(&c);
        let b = Body {
            commit: c.id(),
            parts: c.parts.iter().map(|p| (p.ai, p.di)).collect(),
            expires: osis_commit::blob_expiry(&resolved),
            blind: c.header.blind,
            plaintext: plaintext.to_vec(),
            role_commit: c.header.kind.is_role(),
            order: fetch_order(&resolved),
            to_label: false,
        };
        self.seal(&b, class, &[], rng)
    }

    /// Seals a body's parts (`b.parts` alone) as a fresh blob of one section under `secret`,
    /// the read secret the label's wrap goes under (spec/sync.md §3): a certificate copy, a
    /// heartbeat or a per-label copy (`Body::to_label`), readable by whoever opens the label.
    pub fn seal_to(&mut self, b: &Body, class: osis_label::Class, secret: &Secret32, rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        let c = osis_commit::rewrite(&CommitBlob::decode_stored(&pt)?, |ai, di| !b.parts.contains(&(ai, di)));
        let resolved = self.resolved_header(&c);
        let env = osis_commit::seal_commit(&c, |_| (), |_, _| Some((secret.clone(), Vec::new())), &[], rng)?;
        frame_envelope(&env, &resolved, class, rng, &c).map(Some)
    }

    /// The owner chain a section lists for thing `t` (spec/wire.md §4): from its owner up to
    /// and including the actor its read secret derives from; empty for a thing with secrets of
    /// its own, a key actor or an ownerless thing.
    fn section_owners(&self, t: &Tid) -> Vec<Tid> {
        let mut out = Vec::new();
        if self.core.ix.own_keys.contains(t) || *t == self.core.id.tid() {
            return out;
        }
        for step in self.core.owner_chain(t) {
            match step {
                osis_base::ChainStep::Up { owner, .. } => {
                    out.push(owner);
                    if self.core.ix.own_keys.contains(&owner) || owner == self.core.id.tid() {
                        return out;
                    }
                }
                osis_base::ChainStep::Key(k) => {
                    if k != *t {
                        out.push(k);
                    }
                    return out;
                }
                _ => return out,
            }
        }
        out
    }

    /// The epochs of each member of a section's owner chain (`owners`, nearest first, no tid
    /// twice: spec/wire.md §4) held here, each derived down the nearer part of the chain to the
    /// nearest owner (a member given secrets of its own since the section was sealed holds the
    /// derived epoch in its history). `last`: the previous chain of this blob opening and its
    /// answer (a commit's sections in one group share a chain: derived once, memory bounded).
    fn chain_epochs(&self, owners: &[Tid], last: &mut Option<(Vec<Tid>, Vec<ActorEpochs>)>) -> Vec<ActorEpochs> {
        if let Some((o, v)) = last.as_ref()
            && o == owners
        {
            return v.clone();
        }
        let mut out = Vec::new();
        for (i, o) in owners.iter().enumerate() {
            let Some(mut e) = self.epochs(o) else { continue };
            for x in owners.get(..i).into_iter().flatten().rev() {
                e = ActorEpochs::derived(&e, x);
            }
            out.push(e);
        }
        *last = Some((owners.to_vec(), out.clone()));
        out
    }

    /// The read secrets of thing `t` derived by tid from `chain_epochs` of its section's owners.
    fn derived_through(&self, t: &Tid, owners: &[Tid], last: &mut Option<(Vec<Tid>, Vec<ActorEpochs>)>) -> Vec<Secret32> {
        let mut out: Vec<Secret32> = Vec::new();
        for e in self.chain_epochs(owners, last) {
            for (_, s) in ActorEpochs::derived(&e, t).read.held_newest_first() {
                if !out.iter().any(|x| x.expose() == s.expose()) {
                    out.push(s.clone());
                }
            }
        }
        out
    }

    /// Seals a body as a fresh blob (spec/sync.md §3, spec/wire.md §4): one section per thing
    /// among the commit's held parts, each under that thing's read secret (a plain thing's
    /// derives from its owner's by tid, spec/crypto.md §3, so a thing given secrets of its own
    /// later opens its earlier sections by its history; `wrap_secret`: the newest current
    /// epoch, a rotation's under the epoch it supersedes), the sections of `extra` (those this
    /// node could not open, from a held blob of the commit) copied verbatim; the prefix commits
    /// to the delete-key groups of every section's aspects. A part whose thing's current secret
    /// this node does not hold is left out (a key actor's own record or card, which travels as a
    /// certificate copy), unless the body needs it (`b.parts`): then `None`, nothing is sealed
    /// now.
    pub fn seal(&mut self, b: &Body, class: osis_label::Class, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        let c = CommitBlob::decode_stored(&pt)?;
        let resolved = self.resolved_header(&c);
        let things: Vec<Tid> = resolved.aspects.iter().map(|a| a.tid).collect();
        let id = c.id();
        let env = osis_commit::seal_commit(&c, |ai| things.get(ai).copied(), |t, parts| t.and_then(|t| self.wrap_secret(&t, Some((&id, parts))).ok().flatten().map(|s| (s, self.section_owners(&t)))), extra, rng)?;
        let s = frame_envelope(&env, &resolved, class, rng, &c)?;
        if b.parts.iter().any(|p| !s.parts.contains(p)) {
            return Ok(None);
        }
        Ok(Some(s))
    }

    /// Opens a commit blob (spec/wire.md §4): each section under the read secrets of its thing
    /// (own, or derived from its owner's; `read_secrets`, newest first), those derived through
    /// the owner chain the section lists (the thing's record may be inside the section) and
    /// `label`'s group's own (a per-label copy's, `seal_to`), the rest left sealed; checks the
    /// prefix against the header and the sections' aspects (spec/commits.md §4).
    pub fn open_commit(&mut self, blob: &[u8], key: &Secret32, label: Option<&Tid>) -> Result<OpenedBlob> {
        let (prefix, pt) = osis_label::open(blob, key)?;
        let env = Envelope::decode(&pt)?;
        let id = env.id();
        // linked header lists: resolved from held blobs when they are here, else the sections
        // stay sealed (no aspect names a thing yet) and the prefix is checked once node-core
        // resolved them (the pass, `check_linked_prefixes`)
        let header: Option<std::sync::Arc<osis_commit::Header>> = match self.core.ix.commits.get(&id) {
            Some(m) if !env.header.is_resolved() => m.header.decoded(),
            _ if env.header.is_resolved() => Some(std::sync::Arc::new(env.header.clone())),
            _ => {
                let mut h = env.header.clone();
                let ok = self
                    .run(|tx| {
                        let Some(dedup) = tx.core.dedup(&h.actor) else { return Err(Error::Misuse("not resolved")) };
                        Ok(h.resolve(&mut crate::engine::blobs::TxBlobs::new(&mut tx.txn), &dedup)?)
                    })
                    .is_ok();
                ok.then(|| std::sync::Arc::new(h))
            }
        };
        let ais = env.ais();
        if let Some(h) = &header {
            let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
            if !prefix.agrees(osis_commit::blob_expiry(h).map(WallMs), &h.blind, &groups, osis_label::Class::of_marker(h.ephemeral)) {
                return Err(Error::BadInput("blob prefix disagrees with its header"));
            }
        }
        let of_label: Vec<Secret32> = label.map(|g| self.read_secrets(g)).unwrap_or_default();
        let thing_of = |sec: &Section| header.as_ref().and_then(|h| sec.ais.first().and_then(|ai| h.aspects.get(*ai)).map(|a| a.tid));
        let last = std::cell::RefCell::new(None);
        let own = |sec: &Section| -> Vec<Secret32> {
            let t = thing_of(sec);
            let mut v: Vec<Secret32> = t.map(|t| self.read_secrets(&t)).unwrap_or_default();
            if let Some(t) = t {
                v.extend(self.derived_through(&t, &sec.owners, &mut last.borrow_mut()));
            }
            v
        };
        let opened = env.open(|sec| {
            let mut v = own(sec);
            let more: Vec<Secret32> = of_label.iter().filter(|s| !v.iter().any(|x| x.expose() == s.expose())).cloned().collect();
            v.extend(more);
            v
        })?;
        let copy = env.sections.iter().filter(|sec| !opened.sealed.iter().any(|x| x.ais == sec.ais)).any(|sec| thing_of(sec).is_some_and(|t| label != Some(&t)) && !own(sec).iter().any(|s| osis_crypto::unwrap_section(s, &id, &sec.wrap).is_ok()));
        Ok(OpenedBlob { plaintext: opened.commit.encode(), commit: opened.commit, ais, sealed: opened.sealed, copy })
    }

    /// The bodies a group's label must hold from its closure (spec/sync.md §3): held commits
    /// touching the closure with a part the group's actor may read. A home label (an actor
    /// synced as a group of itself) also carries the `label.0` and `created.0` writes of the
    /// labeled groups it is the nearest labeled owner-chain actor of (spec/sync.md §2).
    pub fn label_bodies(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let mut out = self.label_bodies_meta(g)?;
        for b in &mut out {
            b.plaintext = self.body_plaintext(b)?;
        }
        Ok(out)
    }

    /// The plaintext of a body (`label_bodies_meta` leaves it out): the opened form of every
    /// held part of the commit; empty when the commit is not held any more.
    pub fn body_plaintext(&mut self, b: &Body) -> Result<Vec<u8>> {
        if !b.plaintext.is_empty() {
            return Ok(b.plaintext.clone());
        }
        let id = b.commit;
        let Some(c) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        // a lasting header (`commit_bodies_under`) carries no part
        if b.parts.is_empty() {
            return Ok(osis_commit::rewrite(&c, |_, _| true).encode());
        }
        Ok(c.encode())
    }

    /// `label_bodies` without plaintexts, from a per-commit cache (`Core::bodies`): a pass after a
    /// change looks at only the commits it changed. The commits are found through `on_thing` and
    /// `by_aspect` (O(the closure's commits), no header decoded when the cache holds them), in ID
    /// order.
    pub fn label_bodies_meta(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let ctx = self.body_ctx(g);
        let core = &self.core;
        let mut ids: BTreeSet<CommitId> = ctx.closure.iter().flat_map(|t| core.on_thing(t)).collect();
        for t in ctx.published.iter() {
            for ak in ["label.0", "created.0"] {
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

    /// The parts of commit `id` (its held parts, or `parts`) the actor of `ctx` may read
    /// (spec/sync.md §3): those on things whose reader actor it may read.
    pub fn readable_parts(&self, ctx: &BodyCtx, id: &CommitId, parts: &[(usize, usize)]) -> Vec<(usize, usize)> {
        let Some(m) = self.core.ix.commits.get(id) else { return Vec::new() };
        let h = &m.header;
        parts.iter().filter(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| self.core.may_read(&ctx.actor, &self.core.reader_of(&a.tid)))).copied().collect()
    }

    /// The body of commit `id` a label of the group of `ctx` must hold (`label_bodies_meta`):
    /// with the parts its actor may read among those inside the closure (or published there),
    /// when there are any; else, for a lasting commit, its header alone.
    pub fn commit_bodies_under(&mut self, ctx: &BodyCtx, id: &CommitId) -> Result<Vec<Body>> {
        drop(crate::costs::span("pass: bodies of a commit"));
        let id = *id;
        // the view: the header is decoded only for bodies the cache misses
        let Some(h) = self.core.ix.commits.get(&id).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
        if !ctx.touches(&h) {
            return Ok(Vec::new());
        }
        let touches = h.aspects.iter().any(|a| ctx.closure.contains(&a.tid));
        let body = match self.core.bodies.get(&id) {
            Some(b) => b.clone(),
            None => {
                let b = self.body(&id)?.map(|mut b| {
                    b.plaintext = Vec::new();
                    b
                });
                // kept only while every reader actor is resolved (a missing owner record
                // arriving later moves it)
                if h.aspects.iter().all(|a| self.core.secret_actor(&a.tid).is_some()) {
                    self.core.bodies.insert(id, b.clone());
                }
                b
            }
        };
        let mut out = Vec::new();
        if let Some(mut b) = body {
            let published = |ai: usize| h.aspects.get(ai).is_some_and(|a| !ctx.closure.contains(&a.tid) && ctx.published.contains(&a.tid) && matches!(a.ak.as_str(), "label.0" | "created.0"));
            let inside = |ai: usize| h.aspects.get(ai).is_some_and(|a| touches && ctx.closure.contains(&a.tid)) || published(ai);
            let parts: Vec<(usize, usize)> = b.parts.iter().filter(|(ai, _)| inside(*ai)).copied().collect();
            let readable = self.readable_parts(ctx, &id, &parts);
            if !readable.is_empty() {
                // judged on what the actor reads; the blob carries every held part (`body_plaintext`),
                // unless the label's readers could not open a section of it: a per-label copy
                // (spec/sync.md §3, `Body::to_label`): a role commit on another thing (its
                // rotation, its grants, a cross-published `label.0`), whose boxes are what gives
                // the readers that thing's secrets, so its own section cannot be under them
                // (certificate blobs are copies for the same reason), or a part whose thing's
                // secret neither derives from the actor's nor comes through the closure
                let derivable = |ai: usize| h.aspects.get(ai).is_some_and(|a| self.core.secret_actor(&a.tid).is_some_and(|x| x == ctx.actor || ctx.closure.contains(&x)));
                let role_elsewhere = h.kind.is_role() && readable.iter().any(|(ai, _)| h.aspects.get(*ai).is_some_and(|a| a.tid != ctx.actor));
                b.to_label = role_elsewhere || readable.iter().any(|(ai, _)| !derivable(*ai));
                b.parts = readable;
                out.push(b);
            }
        }
        // nothing of it here and a lasting header on the label's things: its header alone
        // (spec/commits.md §5, spec/sync.md §6)
        if out.is_empty() && touches && (h.purges || h.aspects.iter().any(|a| a.permanent)) {
            let on = |core: &crate::engine::Core, t: &Tid| ctx.closure.contains(t) && core.may_read(&ctx.actor, &core.reader_of(t));
            if self.run(|tx| crate::retention::lasting(tx, &id, &on))?
                && let Some(blind) = self.core.ix.commits.get(&id).map(|m| m.header.blind)
            {
                out.push(Body { commit: id, parts: Vec::new(), expires: None, blind, plaintext: Vec::new(), role_commit: false, order: h.ts.to_u64().max(1), to_label: false });
            }
        }
        Ok(out)
    }

    /// Labeled groups whose nearest labeled owner-chain actor is `g` (its home label publishes
    /// their `label.0`, spec/sync.md §2). Empty unless `g` is an actor with secrets of its own.
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
        // the cache and the `label.0` index against a scan of every held aspect
        #[cfg(debug_assertions)]
        {
            let scan: std::collections::BTreeSet<Tid> = core.ix.by_aspect.keys().filter(|(_, ak)| ak.as_str() == "label.0").map(|(t, _)| *t).collect();
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
        // the owner's epochs; a thing whose `created.0` is not here yet (a recovery card's
        // person) may be owned by any key actor held
        let owners: Vec<osis_keys::ActorEpochs> = match self.core.created(g) {
            Some(osis_base::CreationRecord::Thing { owner, .. }) => self.epochs(owner).or_else(|| self.core.key_actors.get(owner).map(|id| osis_keys::ActorEpochs::key_actor(id.seed()))).into_iter().collect(),
            Some(osis_base::CreationRecord::KeyActor { .. } | osis_base::CreationRecord::Ownerless { .. }) => Vec::new(),
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

    /// Whether these deltas of `c` hold the `secrets.0` or `keys.0` of the actor `g`'s secrets derive
    /// from (only a blob carrying the boxes takes the rotation's wrap exception).
    pub fn carries_secrets(&self, g: &Tid, c: &CommitId, parts: &[(usize, usize)]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|x| x.tid == a && matches!(x.ak.as_str(), "secrets.0" | "keys.0"))
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

    /// For a rotation commit of the read role of `g`'s secret actor (its `keys.0` delta writes a
    /// read keyset): the newest held epoch the new read epoch supersedes.
    fn rotation_wrap_epoch(&mut self, g: &Tid, c: &CommitId) -> Result<Option<Epoch>> {
        let Some(a) = self.core.secret_actor(g) else { return Ok(None) };
        let Some(h) = self.header(c) else { return Ok(None) };
        let Some(ai) = h.aspects.iter().position(|x| x.tid == a && x.ak.as_str() == "keys.0") else { return Ok(None) };
        if !h.aspects.iter().any(|x| x.tid == a && x.ak.as_str() == "secrets.0") {
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
            if let Some((s, _)) = epochs.read.wrapped_under(&e)
                && best.is_none_or(|b| osis_keys::is_newer(&s, &b))
            {
                best = Some(s);
            }
        }
        Ok(best)
    }

    /// The deposit seed of `g`'s actor (its `keys.0`).
    pub fn deposit_seed(&mut self, g: &Tid) -> Result<Option<Secret32>> {
        let x = self.group_actor(g);
        Ok(self.get_typed(&x, &ct::KEYS)?.and_then(|k| k.deposit_seed).map(Secret32::from_bytes))
    }

    /// The keys this node holds for `head` of label `index` of `g` (spec/sync.md §2, §5): any
    /// held secret opens; stamps and deletes need an established epoch (spec/crypto.md §4).
    pub fn head_keys(&mut self, g: &Tid, index: u64, head: &Step) -> Result<HeadKeys> {
        let key = (*g, index, head.id());
        if let Some(k) = self.core.head_keys.get(&key).cloned() {
            #[cfg(debug_assertions)]
            if self.recheck(format!("head_keys {g:?} {index} {:?}", head.id())) {
                assert_eq!(k.public(), self.head_keys_derived(g, index, head)?.public(), "head_keys of {g:?} went stale");
            }
            return Ok(k);
        }
        let _s = crate::costs::span("head keys: derive");
        let k = self.head_keys_derived(g, index, head)?;
        self.core.head_keys.insert(key, k.clone());
        Ok(k)
    }

    fn head_keys_derived(&mut self, g: &Tid, index: u64, head: &Step) -> Result<HeadKeys> {
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

    /// The delete secrets this node holds per commitment group of a blob of commit `c` whose
    /// sections list aspects `ais` (spec/crypto.md §7, spec/wire.md §5): one list per group in
    /// prefix order, each entry a level and its secret, matched over every held epoch along the
    /// owner chains. Needs no blob: a dropped body's copy may be gone.
    pub fn delete_secrets_of(&mut self, c: &CommitId, ais: &[usize]) -> Vec<Vec<(u8, DeleteSecret)>> {
        let Some(h) = self.header(c) else { return Vec::new() };
        self.delete_secrets_by_group(&h, ais)
    }

    /// `delete_secrets_of` for header `h`.
    pub(crate) fn delete_secrets_by_group(&self, h: &osis_commit::Header, ais: &[usize]) -> Vec<Vec<(u8, DeleteSecret)>> {
        let ais: BTreeSet<usize> = ais.iter().copied().collect();
        let mut sets: Vec<&Vec<usize>> = Vec::new();
        let mut out = Vec::new();
        for ai in ais {
            let Some(a) = h.aspects.get(ai) else { continue };
            if sets.contains(&&a.keys) {
                continue;
            }
            sets.push(&a.keys);
            out.push(self.delete_secrets(h, &a.tid, &a.keys));
        }
        out
    }

    /// The delete secrets for header `h`'s delete keys at indices `idx`, for a delta on `tid`.
    fn delete_secrets(&self, h: &osis_commit::Header, tid: &Tid, idx: &[usize]) -> Vec<(u8, DeleteSecret)> {
        let thing = self.core.delete_chain(tid);
        let author = self.core.delete_chain(&h.actor);
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

/// A delete item for an entry: by the label delete key when held, else by delete keys of
/// levels (`groups`: the secrets held per commitment group, for the blob's prefix salt and its
/// header's blind) and the label key those levels need (spec/sync.md §5), under established
/// epochs only (spec/crypto.md §4). `every`: one signature per group (a Delete); else one from
/// any group (a Replace).
pub fn delete_item(keys: &HeadKeys, label: &LabelId, blob: BlobId, at: Option<WallMs>, blinding: Option<(&[u8; 16], &[u8; 16])>, groups: &[Vec<(u8, DeleteSecret)>], every: bool) -> Option<osis_label::DeleteItem> {
    if let Some(d) = &keys.delete {
        return osis_label::DeleteItem::sign(d, label, blob, at).ok();
    }
    delete_item_by_level(keys, label, blob, at, blinding?, groups, every)
}

/// A delete item by delete keys: per group the first level whose label key `keys` hold (a
/// level-3 key needs the write key, which then signs for every level; without it, levels 1
/// and 2 under the sync key). Signs each distinct (level, key) once. `None`: a group (or, for
/// `every` false, every group) offers no level this node can sign for.
pub fn delete_item_by_level(keys: &HeadKeys, label: &LabelId, blob: BlobId, at: Option<WallMs>, blinding: (&[u8; 16], &[u8; 16]), groups: &[Vec<(u8, DeleteSecret)>], every: bool) -> Option<osis_label::DeleteItem> {
    let (salt, hb) = blinding;
    let sync = keys.sync.as_ref().filter(|_| keys.sync_established);
    let write = keys.write.as_ref();
    let usable = |level: u8| match osis_label::key_for_levels(&[level]).ok()? {
        LabelRole::Write => write.map(|_| ()),
        _ => sync.map(|_| ()),
    };
    let mut chosen: Vec<(u8, &DeleteSecret)> = Vec::new();
    for g in groups {
        // levels under the sync key first: the write key is asked for only when a group needs it
        let pick = g.iter().filter(|(l, _)| *l != osis_base::format::DELETE_WRITER && usable(*l).is_some()).chain(g.iter().filter(|(l, _)| *l == osis_base::format::DELETE_WRITER && usable(*l).is_some())).next();
        match pick {
            Some((l, dk)) => {
                if !chosen.iter().any(|(x, k)| x == l && k.seed().expose() == dk.seed().expose()) {
                    chosen.push((*l, dk));
                }
            }
            None if every => return None,
            None => {}
        }
    }
    if chosen.is_empty() {
        return None;
    }
    // one signature per level: two groups at one level with different keys cannot both be
    // signed in one item; the first wins and the other group goes unsigned
    chosen.sort_by_key(|(l, _)| *l);
    chosen.dedup_by_key(|(l, _)| *l);
    let levels: Vec<u8> = chosen.iter().map(|(l, _)| *l).collect();
    let key = match osis_label::key_for_levels(&levels).ok()? {
        LabelRole::Write => write?,
        _ => sync?,
    };
    let item = osis_label::DeleteItem::sign_by(key, &chosen, salt, hb, label, blob, at).ok()?;
    if every && groups.len() > chosen.len() {
        // a group was dropped by the level dedup: check each is still covered by a chosen key
        let covered = groups.iter().all(|g| g.iter().any(|(l, dk)| chosen.iter().any(|(x, k)| x == l && k.seed().expose() == dk.seed().expose())));
        if !covered {
            return None;
        }
    }
    Some(item)
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

/// Labeled things by their nearest labeled owner-chain actor with secrets of its own
/// (`Engine::published_under`).
fn published_by_actor(core: &crate::engine::Core, labeled: &std::collections::BTreeSet<Tid>) -> std::collections::BTreeMap<Tid, std::collections::BTreeSet<Tid>> {
    let mut map: std::collections::BTreeMap<Tid, std::collections::BTreeSet<Tid>> = std::collections::BTreeMap::new();
    for h in labeled {
        for step in core.owner_chain(h) {
            let osis_base::ChainStep::Up { owner, .. } = step else { break };
            if labeled.contains(&owner) && core.ix.own_keys.contains(&owner) {
                if owner != *h {
                    map.entry(owner).or_default().insert(*h);
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
        let e = Epoch::new(2, [2; 32]).unwrap();
        let s = Secret32::from_bytes([5; 32]);
        let mut a = ActorEpochs::default();
        a.write.set_reading_secret(e, s.clone(), osis_keys::Unchecked { author: Tid::from_bytes([1; 15]), commit: CommitId([1; 32]) });
        a.write.set_established(e, osis_keys::Provenance::Rotated);
        let pk = label_role_key(osis_keys::label_role(Role::Write), &s, 0).verifying_key();
        let (ep, got, checked) = matching(&a, Role::Write, 0, &pk).unwrap();
        assert_eq!((ep, &got, checked), (e, &s, false));
        a.write.set_secret(e, s.clone());
        assert!(matching(&a, Role::Write, 0, &pk).unwrap().2);
    }
}
