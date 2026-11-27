//! Bodies, sealing, wraps, stamps, deposits and delete keys (spec/sync-ids.md §1-§3, §5;
//! spec/crypto.md §5, §7): what a commit becomes under a sync ID, and the role keys a peer's head calls for.

use osis_base::memo::Memo;
use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_commit::{CommitBlob, Envelope, Section};
use osis_base::{BlobId, CommitId, Role, Tid, WallMs};
use osis_crypto::{CryptoRngCore, Epoch, RoleKey, Secret32, SigningSecret, deposit_key};
use osis_keys::ActorEpochs;
use osis_blob::Step;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// A held commit as one blob (spec/sync-judgement.md §1): every held part, each sealed to its thing's
/// independent (`Engine::seal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub commit: CommitId,
    /// Aspect indices, sorted: the parts a judgment reads. From `commit_bodies_under` those the
    /// sync ID's actor may read; from `body` every held part; from `part_body` the copied ones.
    pub parts: Vec<usize>,
    pub expires: Option<u64>,
    /// The header's blind (spec/crypto.md §7).
    pub blind: [u8; 16],
    /// The opened form `[Header, signature, [Part*]]` of what the blob carries (every held part
    /// of the commit, or a copy's parts); empty from `commit_bodies_under` (`body_plaintext`).
    pub plaintext: Vec<u8>,
    /// Its wrap's fetch order (`fetch_order`).
    pub order: u64,
    /// A per-sync-ID copy: `parts` in one section under the blob key (`Engine::seal_to`), never
    /// shared with another sync ID (spec/sync-judgement.md §1): a role commit with a part on a thing other
    /// than the actor (its boxes give the readers that thing's secrets), or a part whose thing's
    /// read secret derives from neither the actor nor an actor of its closure (a thing added from
    /// another actor's tree, read by role).
    pub to_sync_id: bool,
}

/// A wrap's fetch order (spec/crypto.md §5): 0 for a commit a judgment of other commits needs or a
/// purge request (what it names does not show first), else the commit's `ts`. Read only to order
/// this node's fetches.
pub fn fetch_order(h: &osis_commit::Header) -> u64 {
    let foundation = h.kind.is_role() || !h.purge.is_empty() || h.aspects.iter().any(|a| matches!(a.ak.as_str(), "created.0" | "retention^.0") || osis_schema::core_types::is_role_class(a.ak.as_str()));
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
    /// Its seal (`crate::sync::BlobSeal`): `None` for an envelope framed as given
    /// (`frame_envelope`), whose section keys are not known here.
    pub seal: Option<Arc<crate::sync::BlobSeal>>,
}

/// A commit blob opened (`Engine::open_commit`): the opened form of the parts this node could
/// read, the commit, the aspects every section lists, and the sections left sealed (copied
/// verbatim into a fresh encryption).
pub struct OpenedBlob {
    pub plaintext: Vec<u8>,
    pub commit: CommitBlob,
    pub ais: Vec<usize>,
    /// Its prefix salt.
    pub salt: [u8; 16],
    pub sealed: Vec<Section>,
    /// The creation records minted in sections left sealed for a thing this node does not hold
    /// and has no record of (`Engine::section_opens`): learned alone, the rest of those sections
    /// unread.
    pub records: Vec<osis_base::CreationRecord>,
    /// Every section as it came, opened or not: what a fresh encryption of the commit copies
    /// verbatim (`Engine::seal`'s `extra`, spec/crypto.md §5 Passing on).
    pub sections: Vec<Section>,
    /// A section opened under the blob key: a copy (`seal_to`), never copied into another
    /// encryption.
    pub copy: bool,
    /// Every section as a seal keeps it (`crate::sync::BlobSeal`).
    pub seals: Vec<osis_commit::SectionSeal>,
    /// Its prefix's entry blocks, as they came (`crate::sync::BlobSeal`).
    pub blocks: Vec<osis_blob::EntryBlock>,
}

/// How a section opens here (`Engine::section_opens`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SectionOpens {
    Whole,
    /// Only the creation record minted there is taken.
    Record,
    Sealed,
}

impl OpenedBlob {
    /// The part indices of the opened parts.
    pub fn parts(&self) -> Vec<usize> {
        self.commit.parts.iter().map(|p| p.ai).collect()
    }
}

/// Frames an envelope: random salt and key, prefix from the header and the sections' aspects
/// (spec/sync-ids.md §1, spec/wire.md §5).
pub fn frame_envelope(env: &Envelope, resolved: &osis_commit::Header, class: osis_blob::Class, rng: &mut dyn CryptoRngCore, from: &CommitBlob) -> Result<Sealed> {
    framed(osis_crypto::BlobKey::fresh(rng), env, None, resolved, class, rng, from, |_, _, _| Ok(Vec::new()))
}

/// `frame_envelope` under `key`, its sections as `seals` keeps them where known, carrying the
/// entry blocks `blocks` makes.
#[allow(clippy::too_many_arguments)]
fn framed(key: osis_crypto::BlobKey, env: &Envelope, seals: Option<Vec<osis_commit::SectionSeal>>, resolved: &osis_commit::Header, class: osis_blob::Class, rng: &mut dyn CryptoRngCore, from: &CommitBlob, blocks: impl FnOnce(&Secret32, &[u8; 16], &mut dyn CryptoRngCore) -> Result<Vec<osis_blob::EntryBlock>>) -> Result<Sealed> {
    let ais = env.ais();
    let groups = osis_commit::prefix_groups(resolved, ais.iter().copied())?;
    let salt = osis_blob::Prefix::random_salt(rng);
    let blocks = blocks(key.secret(), &salt, rng)?;
    let prefix = osis_blob::Prefix::for_delete_keys(salt, &env.header.blind, osis_commit::prefix_expiry(resolved, &ais).map(WallMs), &groups)?.with_class(class).with_blocks(blocks.clone())?;
    let (key, blob) = osis_blob::frame_under(key, &prefix, &env.encode())?;
    let parts: Vec<usize> = from.parts.iter().filter(|p| ais.contains(&p.ai)).map(|p| p.ai).collect();
    let unopened = env.sections.iter().filter(|s| !s.ais.iter().any(|ai| parts.contains(ai))).map(|s| s.digest()).collect();
    let seal = seals.map(|sections| Arc::new(crate::sync::BlobSeal { len: blob.len() as u64, key: key.clone(), sections, blocks }));
    Ok(Sealed { id: osis_blob::blob_id(&blob), blob, key, salt, ais, parts, unopened, seal })
}

/// A sync unit as `Engine::commit_bodies_under` sees it.
pub struct BodyCtx {
    /// The sync unit's thing: its members are asked one at a time (`holds`), so a judgement
    /// moves with the things it names, never with the unit's other members.
    pub unit: Tid,
    pub actor: Tid,
}

impl BodyCtx {
    /// Whether the sync unit holds `t`.
    pub(crate) fn holds(&self, core: &crate::engine::Core, t: &Tid) -> bool {
        core.ix.closure.unit_holds(&self.unit, t)
    }

    /// Whether a commit (its `View`) may have bodies under the sync IDs of this sync unit's thing.
    pub(crate) fn touches(&self, core: &crate::engine::Core, v: &crate::engine::View) -> bool {
        v.aspects.iter().any(|a| self.holds(core, &a.tid))
    }
}

/// The role keys this node holds for a peer's head (spec/sync-ids.md §2, spec/sync-ids.md §6).
#[derive(Clone, Default)]
pub struct HeadKeys {
    /// Opens (any held secret, spec/crypto.md §4: opening is not encrypting under).
    pub sync: Option<SigningSecret>,
    /// The sync key's epoch is established: it may sign level-1 and level-2 deletes.
    pub sync_established: bool,
    /// Stamps and level-3 deletes (an established epoch).
    pub write: Option<SigningSecret>,
    /// Sync-ID-wide deletes and child steps (an established epoch).
    pub delete: Option<SigningSecret>,
    pub deposit: Option<SigningSecret>,
    /// The head's epoch per role key (`RoleKey::ALL`: sync, write, delete) where held.
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

/// The held epoch of role key `l`'s role whose key is `pk` (`keys`: `key_epochs` of `e`), with
/// that key and whether that secret may be encrypted under (not reading-only, spec/crypto.md §4).
fn matching(keys: &BTreeMap<[u8; 32], Epoch>, e: &ActorEpochs, l: RoleKey, pk: &osis_crypto::VerifyingKey) -> Option<(Epoch, SigningSecret, bool)> {
    let ep = *keys.get(&pk.to_bytes())?;
    let r = e.role(l.role());
    Some((ep, osis_crypto::role_key(l, r.reading_secret(&ep)?), r.secret(&ep).is_some()))
}

/// The epoch of each secret of role key `l`'s role held in `e` (reading-only included) by the key
/// it derives, the newest where two derive one (`osis_keys::registered_key`, found by lookup).
pub(crate) fn key_epochs(e: &ActorEpochs, l: RoleKey) -> BTreeMap<[u8; 32], Epoch> {
    let mut out = BTreeMap::new();
    for (ep, s) in e.role(l.role()).held_newest_first() {
        out.entry(osis_crypto::role_key(l, s).verifying_key().to_bytes()).or_insert(ep);
    }
    out
}

/// `key_epochs` of a thing's epochs per role key.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct RoleKeyEpochs {
    sync: BTreeMap<[u8; 32], Epoch>,
    write: BTreeMap<[u8; 32], Epoch>,
    delete: BTreeMap<[u8; 32], Epoch>,
}

impl crate::engine::Core {
    /// `key_epochs` of `g`'s epochs per role key: a derivation per held secret once per change of
    /// `g`'s epochs (`memo`), not per head asked of it.
    pub(crate) fn role_key_epochs(&self, g: &Tid) -> Arc<RoleKeyEpochs> {
        self.role_key_epochs.get(g, || {
            let Some(e) = self.epochs(g) else { return Arc::default() };
            Arc::new(RoleKeyEpochs { sync: key_epochs(&e, RoleKey::Sync), write: key_epochs(&e, RoleKey::Write), delete: key_epochs(&e, RoleKey::Delete) })
        })
    }
}

impl Engine {
    /// The body of a held commit: its header, blind and expiry, every held part, the opened form
    /// as the plaintext. `None`: not held, or no part of it held (a lasting header is
    /// `commit_bodies_under`'s).
    pub fn body(&mut self, c: &CommitId) -> Result<Option<Body>> {
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
            plaintext: blob.encode(),
            order: fetch_order(&resolved),
            to_sync_id: false,
        }))
    }

    /// The applied (resolved) header of a held commit whose stored header lists go by link,
    /// else the stored one.
    pub(crate) fn resolved_header(&self, blob: &CommitBlob) -> std::sync::Arc<osis_commit::Header> {
        match self.core.ix.commits.get(&blob.id()) {
            Some(m) if !blob.header.is_resolved() => m.header.clone(),
            _ => std::sync::Arc::new(blob.header.clone()),
        }
    }

    /// Seals a body's parts (`b.parts` alone) as a copy (spec/sync-judgement.md §1): a fresh blob of one
    /// section under its own blob key (spec/wire.md §4; a header-only copy of a split commit
    /// destroying a thing: one section of no part carrying that thing's path key), so
    /// whoever opens a wrap of it reads it: a certificate copy, wrapped under every sync ID needing exactly those parts, or a per-sync-ID
    /// copy (`Body::to_sync_id`).
    pub fn seal_to(&mut self, b: &Body, class: osis_blob::Class, rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        osis_base::costs::count("copy sealed", 1);
        let c = osis_commit::rewrite(&CommitBlob::decode_stored(&pt)?, |ai| !b.parts.contains(&ai));
        let resolved = self.resolved_header(&c);
        let key = osis_crypto::BlobKey::fresh(rng);
        let (env, seals) = if c.parts.is_empty() {
            osis_commit::seal_header_only_keyed(&c, &resolved, key.secret(), rng)?
        } else {
            osis_commit::seal_commit_keyed(&c, &resolved, |_| (), |_, _| Some((key.secret().clone(), Vec::new())), &[], rng)?
        };
        framed(key, &env, Some(seals), &resolved, class, rng, &c, |_, _, _| Ok(Vec::new())).map(Some)
    }

    /// The derivation chain a section lists for thing `t` (spec/wire.md §4): from its mint admin
    /// up to and including the actor its read secret derives from; empty for an independent
    /// thing.
    fn section_chain(&self, t: &Tid) -> Vec<Tid> {
        let mut out = Vec::new();
        if self.core.ix.independent.contains(t) {
            return out;
        }
        for step in self.core.record_chain(t) {
            match step {
                osis_base::ChainStep::Up { admin: up, .. } => {
                    out.push(up);
                    if self.core.ix.independent.contains(&up) {
                        return out;
                    }
                }
                // a thing minted with a key above `t` is the mint admin the step before pushed: listed once
                _ => return out,
            }
        }
        out
    }

    /// The epochs of each member of a section's derivation chain (`chain`, nearest first, no tid
    /// twice: spec/wire.md §4) held here, each derived down the nearer part of the chain to the
    /// nearest member (a member made independent since the section was sealed holds the
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
    /// under that thing's read secret (a dependent thing's derives from its mint admin's by tid,
    /// spec/crypto.md §3, so a thing made independent later opens its earlier sections by
    /// its history; `wrap_secret`: the newest current epoch, a rotation's under the epoch it
    /// supersedes); for the other parts the sections of `extra` (held sections of the commit,
    /// opened or not) copied verbatim where none of their parts is held stripped or dropped; the
    /// prefix commits to the delete-key groups of every section's aspects. A part neither covers
    /// is left out (one another wrote that this node read only under an epoch not established
    /// here; a thing's own record or card, whose current secret it lacks, which travels as a
    /// certificate copy), unless the body needs it (`b.parts`): then `None`, nothing is sealed
    /// now. A dependent thing's derived epoch sealed under is noted (`note_sealed`, spec/crypto.md
    /// §4 Current).
    pub fn seal(&mut self, b: &Body, class: osis_blob::Class, extra: &[Section], rng: &mut dyn CryptoRngCore) -> Result<Option<Sealed>> {
        let pt = self.body_plaintext(b)?;
        if pt.is_empty() {
            return Ok(None);
        }
        let c = CommitBlob::decode_stored(&pt)?;
        let resolved = self.resolved_header(&c);
        let things: Vec<Tid> = resolved.aspects.iter().map(|a| a.tid).collect();
        let roles: Vec<bool> = resolved.aspects.iter().map(|a| osis_keys::under_roles(a.ak.as_str())).collect();
        let id = c.id();
        // a held section goes as it came only where none of its parts strips here (a purge's or
        // an expiry's leftover, one dropped as covered under purge on replace: `bodies::strips`)
        let whole: Vec<Section> = {
            let m = self.core.ix.commits.get(&id);
            extra.iter().filter(|s| s.ais.iter().all(|ai| m.is_none_or(|m| !crate::sync::bodies::strips(m, *ai)))).cloned().collect()
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
        let (env, seals) = osis_commit::seal_commit_keyed(
            &c,
            &resolved,
            |ai| (things.get(ai).copied(), roles.get(ai).copied().unwrap_or(false)),
            |(t, is_roles), parts| {
                let t = (*t)?;
                let (e, k) = self.section_secret(&id, &resolved, &t, of_thing.get(&t)?, parts)?;
                under.push((t, e));
                // role parts in a section of their own under the epoch's roles secret
                // (spec/crypto.md §4, Roles secrets)
                Some((k.of(*is_roles)?, self.section_chain(&t)))
            },
            &whole,
            rng,
        )?;
        // its entries (spec/sync-ids.md §3 Entry block): a fresh encryption of a body, never a copy
        let boxing = self.boxing(&c, &resolved, &seals)?;
        let s = framed(osis_crypto::BlobKey::fresh(rng), &env, Some(seals), &resolved, class, rng, &c, |k, salt, rng| self.entry_blocks(&boxing, k, salt, rng))?;
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
    /// the epoch, `epoch_under`). A write goes under this node's epoch only where
    /// `opened::passes_on` (its invariant and the floor clause, at that epoch's floor), else as a
    /// held section of it or not at all (`None`). A section carries no header, so the header's
    /// gate is the wrap's alone (`wrap_under`): a commit's sections cost its parts once each.
    /// `seal` and `may_log` alike.
    pub(crate) fn section_secret(&mut self, id: &CommitId, h: &osis_commit::Header, t: &Tid, of_thing: &[usize], parts: &[usize]) -> Option<(Epoch, WrapKey)> {
        let (e, k) = self.epoch_under(t, Some((id, of_thing))).ok().flatten()?;
        if !self.passes_on_all(id, h, parts, self.core.read_floor(t, &e)).ok()? {
            return None;
        }
        Some((e, k))
    }

    /// Opens a commit blob (spec/wire.md §4): each section under the read secrets of its thing
    /// (own, or derived from its mint admin's; `read_secrets`, newest first), those derived through
    /// the derivation chain the section lists (the thing's record may be inside the section) and
    /// the blob key (a copy's, `seal_to`), the rest left sealed; checks the prefix against the
    /// header and the sections' aspects (spec/commits.md §4).
    pub fn open_commit(&mut self, blob: &[u8], key: &Secret32) -> Result<OpenedBlob> {
        let (prefix, pt) = osis_blob::open(blob, key)?;
        let env = Envelope::decode(&pt)?;
        let id = env.id();
        // linked header lists: resolved from held blobs when they are here, else the sections
        // stay sealed (no aspect names a thing yet) and the prefix's commitment groups, which
        // need the lists, go unchecked
        let header: Option<std::sync::Arc<osis_commit::Header>> = match self.core.ix.commits.get(&id) {
            Some(m) if !env.header.is_resolved() => Some(m.header.clone()),
            _ if env.header.is_resolved() => Some(std::sync::Arc::new(env.header.clone())),
            _ => self.held_resolved(env.header.clone()).map(std::sync::Arc::new),
        };
        let ais = env.ais();
        // its expiry is the commit's (spec/sync-ids.md §1), from the header's own fields, checked
        // whether or not its lists resolve here: a blob framed under another expiry is no
        // encryption of the commit (it would outlive the commit, or expire with a smaller blob
        // dropped beside it as losing as needed)
        if prefix.expiry() != osis_commit::prefix_expiry(&env.header, &ais).map(WallMs) {
            return Err(Error::BadInput("blob prefix expiry is not its commit's"));
        }
        if let Some(h) = &header {
            let groups = osis_commit::prefix_groups(h, ais.iter().copied())?;
            if !prefix.agrees(osis_commit::prefix_expiry(h, &ais).map(WallMs), &h.blind, &groups, osis_blob::Class::of_marker(h.ephemeral)) {
                return Err(Error::BadInput("blob prefix disagrees with its header"));
            }
        }
        let thing_of = |sec: &Section| header.as_ref().and_then(|h| sec.ais.first().and_then(|ai| h.aspects.get(*ai)).map(|a| a.tid));
        let opens = |sec: &Section| header.as_ref().map_or(SectionOpens::Whole, |h| self.section_opens(h, sec));
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
        // a section of a thing not held here opens under the blob key alone (a copy's, whose
        // parts the sync ID's own readers judge); the record of one whose record is not held is
        // taken alone (spec/sync-judgement.md §1 Sealed sections)
        let mut records = Vec::new();
        let opened = env.open(|sec| {
            let mut v = match opens(sec) {
                SectionOpens::Whole => own(sec),
                SectionOpens::Record => {
                    if let Some(h) = &header
                        && let Ok(Some(c)) = sec.open(&id, h.is_split(), &own(sec))
                    {
                        // a record proves itself by its tid: its thing's path is not read
                        let parts = c.parts.into_iter().filter(|p| h.aspects.get(p.ai).is_some_and(|a| a.ak.as_str() == osis_commit::retention::CREATED)).collect();
                        let c = CommitBlob { header: (**h).clone(), sigs: env.sigs.clone(), parts, keys: Default::default() };
                        records.extend(crate::apply::carried_records(h, &c, &id).into_values());
                    }
                    Vec::new()
                }
                SectionOpens::Sealed => Vec::new(),
            };
            v.push(key.clone());
            v
        })?;
        // the epoch each section under a read secret opened under (`sync_ids::opened`)
        if let Some(h) = &header {
            let mut under = Vec::new();
            for sec in &env.sections {
                let Some(t) = thing_of(sec) else { continue };
                if opened.sealed.contains(sec) || osis_crypto::unwrap_section(key, &id, &sec.wrap).is_ok() {
                    continue;
                }
                let Some((e, _)) = self.read_epochs(&t, &sec.chain).into_iter().find(|(_, s)| osis_crypto::unwrap_section(s, &id, &sec.wrap).is_ok()) else { continue };
                under.push((t, e, opened.commit.parts.iter().filter(|p| sec.ais.contains(&p.ai)).collect::<Vec<_>>()));
            }
            self.note_opened(h, &under);
        }
        Ok(OpenedBlob { plaintext: opened.commit.encode(), commit: opened.commit, ais, salt: *prefix.salt(), sealed: opened.sealed, records, sections: env.sections, copy, seals: opened.seals, blocks: prefix.blocks().to_vec() })
    }

    /// How a section of a commit blob of header `h` opens here (spec/sync-judgement.md §1
    /// Sealed sections): a role section, or one of a thing this node holds (in its node closure) whole; one of
    /// a thing it does not hold stays sealed, but for the record minted there of a thing whose
    /// record it lacks (not destroyed here), which it needs to judge whether a held strong
    /// brings the thing in. Opening content only of held things keeps a purged part from being
    /// read from a sync ID its purge request never reaches; a held blob opens again as its
    /// thing enters (`section_keys`).
    pub(crate) fn section_opens(&self, h: &osis_commit::Header, sec: &Section) -> SectionOpens {
        let Some(a) = sec.ais.first().and_then(|ai| h.aspects.get(*ai)) else { return SectionOpens::Whole };
        if osis_keys::under_roles(a.ak.as_str()) || self.holds_sections(&a.tid) {
            return SectionOpens::Whole;
        }
        if self.core.created(&a.tid).is_none() && !self.core.destroyed(&a.tid) {
            return SectionOpens::Record;
        }
        SectionOpens::Sealed
    }

    /// Whether this node opens thing `t`'s sections whole (`section_opens`): `t` is in its node
    /// closure.
    fn holds_sections(&self, t: &Tid) -> bool {
        self.core.ix.closure.holds(t)
    }

    /// Whether this node holds thing `t` whole: its content applies here (spec/commits.md §4
    /// Outside the node closure).
    pub fn held_whole(&self, t: &Tid) -> bool {
        crate::retention::needed::whole(&self.core, t)
    }

    /// What a held blob's sealed section of thing `t` awaits to open again (store `Follow`):
    /// whether this node opens `t`'s sections whole (`section_opens`), and `t`'s read secrets
    /// while it opens them at all (whole, or for a record it lacks).
    pub fn section_keys(&self, t: &Tid) -> (bool, Vec<Secret32>) {
        let whole = self.holds_sections(t);
        let opens = whole || self.core.created(t).is_none() && !self.core.destroyed(t);
        (whole, if opens { self.read_secrets(t) } else { Vec::new() })
    }

    /// The plaintext of a body (`commit_bodies_under` leaves it out): the opened form of every
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

    /// What `commit_bodies_under` needs of a sync unit's root: the unit and its actor.
    pub fn body_ctx(&mut self, g: &Tid) -> BodyCtx {
        BodyCtx { unit: *g, actor: self.core.reader_of(g) }
    }

    /// The parts of commit `id` (its held parts, or `parts`) the actor of `ctx` may read
    /// (spec/sync-judgement.md §1): those on things whose independent it may read.
    pub fn readable_parts(&self, ctx: &BodyCtx, id: &CommitId, parts: &[usize]) -> Vec<usize> {
        let Some(m) = self.core.ix.commits.get(id) else { return Vec::new() };
        let h = &m.header;
        parts.iter().filter(|ai| h.aspects.get(**ai).is_some_and(|a| self.reads(ctx, &a.tid))).copied().collect()
    }

    /// The parts of copy `c`, opened under a sync ID of `g`, that the sync ID carries no more
    /// (spec/sync-judgement.md §1: a sync ID carries the parts its thing's independent may read,
    /// and certificate copies of role-class parts on any thing): content (`is_content`) on a thing
    /// under an independent thing that `g`'s independent may not read now, left by a
    /// revocation since the per-sync-ID copy was logged (spec/permissions.md §3). With any,
    /// `open_entry` takes none of the copy (`Opened::NotOpen`): those parts come from a body under
    /// their own thing's sync ID, which read fetches as missing once this node may hold it.
    /// Invariant: no part taken from a copy gives a node anything of an actor it cannot read now.
    /// Content is left out here; a role-class part is taken because each is judged as it is used:
    /// `secrets.0` boxes by `rotation::may_take` as they open; `sync.0`, `roles.0`, `keys.0`,
    /// `listing.0` and `account.0` are certificate material.
    pub fn copy_stale(&self, g: &Tid, c: &CommitBlob) -> BTreeSet<usize> {
        let actor = self.core.reader_of(g);
        let h = &c.header;
        let stale = |a: &osis_commit::AspectEntry| osis_schema::core_types::is_content(a.ak.as_str()) && self.core.secret_actor(&a.tid).is_some_and(|x| self.core.ix.independent.contains(&x)) && !self.actor_reads(&actor, &a.tid);
        c.parts.iter().map(|p| p.ai).filter(|ai| h.aspects.get(*ai).is_some_and(stale)).collect()
    }


    /// Whether the actor of `ctx` may read `t` (spec/sync-judgement.md §1): its keys open `t`.
    pub(crate) fn reads(&self, ctx: &BodyCtx, t: &Tid) -> bool {
        self.actor_reads(&ctx.actor, t)
    }

    /// Whether `actor`'s keys open `t` (`Core::keys_open`): what its sync IDs carry.
    fn actor_reads(&self, actor: &Tid, t: &Tid) -> bool {
        self.core.keys_open(actor, t)
    }

    /// The parts of `h` a sync ID of `ctx`'s sync unit carries in its bodies (spec/sync-judgement.md
    /// §1): those on things of the sync unit its independent may read. A part on any other thing that
    /// evidence needs goes there as a certificate copy (spec/permissions.md §4).
    pub fn body_carried(&self, ctx: &BodyCtx, h: &osis_commit::Header) -> std::collections::BTreeSet<usize> {
        h.aspects.iter().enumerate().filter(|(_, a)| ctx.holds(&self.core, &a.tid) && self.reads(ctx, &a.tid)).map(|(i, _)| i).collect()
    }

    /// The body of commit `id` a sync ID of `ctx`'s sync unit must hold (spec/sync-judgement.md §1):
    /// with the parts its independent may read among those inside the sync unit,
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
        let Some(h) = self.core.ix.commits.get(&id).map(|m| m.view.clone()) else { return Ok(Vec::new()) };
        if !ctx.touches(&self.core, &h) {
            return Ok(Vec::new());
        }
        let inside = |ai: usize| h.aspects.get(ai).is_some_and(|a| ctx.holds(&self.core, &a.tid));
        // the parts inside held as their bodies (what the record carries), with `unheld` the
        // missing and dropped ones: each part's hold read alone, so another part arriving or
        // dropping moves no body here
        let parts: Vec<usize> = match self.core.ix.commits.get(&id) {
            Some(m) => (0..m.parts()).filter(|ai| inside(*ai)).filter(|ai| match m.hold(*ai) {
                Some(crate::engine::Hold::Body { .. }) => true,
                Some(crate::engine::Hold::Missing(_) | crate::engine::Hold::Dropped(_)) => unheld,
                _ => false,
            }).collect(),
            None => Vec::new(),
        };
        let body = match parts.is_empty() {
            true => None,
            false => self.header(&id).map(|full| Body { commit: id, parts: Vec::new(), expires: osis_commit::blob_expiry(&full), blind: full.blind, plaintext: Vec::new(), order: fetch_order(&full), to_sync_id: false }),
        };
        let mut out = Vec::new();
        if let Some(mut b) = body {
            let readable = self.readable_parts(ctx, &id, &parts);
            if !readable.is_empty() {
                // judged on what the actor reads; the blob carries every held part (`body_plaintext`),
                // unless the sync ID's readers could not open a section of it: a per-sync-ID copy
                // (spec/sync-judgement.md §1, `Body::to_sync_id`): a role commit on another thing (its
                // rotation, its grants), whose boxes are what gives
                // the readers that thing's secrets, so its own section cannot be under them
                // (certificate blobs are copies for the same reason), or a part whose thing's
                // secret neither derives from the actor's nor comes through the closure (a destroyed
                // actor's boxes went with it: its secrets come through nothing)
                let derivable = |ai: usize| h.aspects.get(ai).is_some_and(|a| self.core.secret_actor(&a.tid).is_some_and(|x| x == ctx.actor || (ctx.holds(&self.core, &x) && !self.core.destroyed(&x))));
                // (a `created.0` part carries no boxes: a records-only role commit is shared)
                let role_elsewhere = h.kind.is_role() && readable.iter().any(|ai| h.aspects.get(*ai).is_some_and(|a| a.tid != ctx.actor && a.ak.as_str() != "created.0"));
                b.to_sync_id = role_elsewhere || readable.iter().any(|ai| !derivable(*ai));
                b.parts = readable;
                out.push(b);
            }
        }
        // nothing of it here and a lasting header on the sync ID's things: its header alone
        // (spec/commits.md §5, spec/sync-judgement.md §2)
        let forever = |a: &crate::engine::AspectView| !h.memory && osis_commit::retention::fixed_purge_by(a.ak.as_str()).is_none() && crate::retention::history::of(&self.core, &a.tid, &a.ak).forever(h.ts);
        if out.is_empty() && (h.purges || h.aspects.iter().any(forever)) {
            let on = |core: &crate::engine::Core, t: &Tid| ctx.holds(core, t) && core.keys_open(&ctx.actor, t);
            if self.run(|tx| crate::retention::lasting(tx, &id, &on))?
                && let Some(blind) = self.core.ix.commits.get(&id).map(|m| m.header.blind)
            {
                out.push(Body { commit: id, parts: Vec::new(), expires: None, blind, plaintext: Vec::new(), order: h.ts.to_u64().max(1), to_sync_id: false });
            }
        }
        Ok(out)
    }

    /// The read secret a commit is wrapped under at a sync ID of `g` (spec/crypto.md §5): the
    /// newest current read epoch held, except a commit giving read epochs of the actor `g`'s
    /// secrets derive from (a rotation, a grant, a re-seal), which goes under the newest epoch
    /// they supersede, never another (`giving_wrap_epoch`). `None`: no current secret held
    /// (stranded: nothing is logged), none of the superseded epochs held, or a part of `c` it
    /// carries this node may not pass on under an epoch of its choosing (spec/crypto.md §5
    /// Passing on). A blob carrying a role part of that actor (`osis_keys::under_roles`) goes
    /// under the epoch's roles secret (spec/crypto.md §4, Roles secrets): every holder of the
    /// actor opens it.
    pub fn wrap_secret(&mut self, g: &Tid, c: Option<(&CommitId, &[usize])>) -> Result<Option<Secret32>> {
        let roles = c.is_some_and(|(c, parts)| self.carries_roles(g, c, parts));
        Ok(self.wrap_under(g, c)?.and_then(|(_, k)| k.of(roles)))
    }

    /// Whether these deltas of `c` hold a role part (`osis_keys::under_roles`) of the actor `g`'s
    /// secrets derive from.
    fn carries_roles(&self, g: &Tid, c: &CommitId, parts: &[usize]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|ai| h.aspects.get(*ai)).any(|x| x.tid == a && osis_keys::under_roles(x.ak.as_str()))
    }

    /// `wrap_secret` with its epoch: `epoch_under`, where the commit's header may go under it.
    fn wrap_under(&mut self, g: &Tid, c: Option<(&CommitId, &[usize])>) -> Result<Option<(Epoch, WrapKey)>> {
        let Some((ep, k)) = self.epoch_under(g, c)? else { return Ok(None) };
        // the wrap gates the header, and a copy's whole content: under this node's epoch only
        // where the commit's header may go so, at that epoch's floor (`Engine::header_passes`,
        // spec/crypto.md §5 Passing on: every part it carries is content of the header)
        if let Some((c, _)) = c
            && let Some(e) = self.epochs(g)
            && !self.header_passes(c, &super::opened::Wrapping { thing: *g, actor: self.core.reader_of(g), floor: e.read.floor(&ep) })?
        {
            return Ok(None);
        }
        Ok(Some((ep, k)))
    }

    /// The epoch this node encrypts parts `c` names (all on `g`'s secret actor's things, for a
    /// section; the blob's, for a wrap) under at `g`: the newest current read epoch held, a
    /// commit giving read epochs under one they supersede (`giving_wrap_epoch`), none under an
    /// epoch blocked here (`wrap_blocked`).
    fn epoch_under(&mut self, g: &Tid, c: Option<(&CommitId, &[usize])>) -> Result<Option<(Epoch, WrapKey)>> {
        let Some(e) = self.epochs(g) else { return Ok(None) };
        let giving = match c {
            Some((c, parts)) if self.carries_secrets(g, c, parts) => match self.giving_wrap_epoch(g, c, parts)? {
                GivingWrap::Plain => None,
                // a commit giving read epochs goes under one they supersede or not at all (a
                // holder of a floor above them lacking their roles secrets too may not choose
                // another; a holder of one logs it)
                GivingWrap::Lacking => return Ok(None),
                GivingWrap::Under(ep, rotation) => match e.read.checked_roles(&ep) {
                    Some(roles) => Some((rotation, (ep, WrapKey { secret: e.read.secret(&ep).map(|s| s.secret().clone()), roles }))),
                    None => return Ok(None),
                },
            },
            _ => None,
        };
        let own_wrap = giving.as_ref().is_some_and(|(rotation, _)| *rotation);
        let giving = giving.map(|(_, x)| x);
        let plain = || osis_keys::wrap_epoch(&e.read).and_then(|ep| e.read.secret(&ep).map(|s| (ep, WrapKey { roles: osis_crypto::roles_secret(s), secret: Some(s.secret().clone()) })));
        let Some((ep, k)) = giving.or_else(plain) else { return Ok(None) };
        // spec/crypto.md §4 Encrypting under: wrapping is encrypting under the epoch, so none
        // under one blocked here (a rotation's own wrap excepted: it is what unblocks it)
        if !own_wrap && self.wrap_blocked(&self.core.reader_of(g), c.map(|x| x.0))? {
            return Ok(None);
        }
        Ok(Some((ep, k)))
    }

    /// Whether read of `a` is blocked here for a wrap of commit `c` (spec/crypto.md §4 Encrypting
    /// under): a role commit, which goes as a certificate or as this node's own, by the logging
    /// walk (`Walk::Log`: through holder actors this node may rotate only, so a node that may
    /// not still logs what tells their rotators); anything else by the encrypting walk, and also
    /// while this node holds a grant on `a` it may finalize (spec/permissions.md §2 Finalize: the
    /// finalize goes before its next commit encrypting under `a`; the driver's role duties write
    /// it, `Engine::role_duty_due`).
    /// Kept per (actor, walk) (`Core::wrap_blocks`, `memo::Cutoff`): every body judged under a
    /// sync ID asks it, and what it reads (the actor's component whole) moves far more often
    /// than its answer.
    fn wrap_blocked(&mut self, a: &Tid, c: Option<&CommitId>) -> Result<bool> {
        let walk = match c.and_then(|c| self.header(c)) {
            Some(h) if !h.kind.is_role() => crate::rotation::Walk::Encrypt,
            _ => crate::rotation::Walk::Log,
        };
        osis_base::memo::Cutoff::get_in(self, |e| &e.core.wrap_blocks, &(*a, walk), |e, (a, walk)| e.wrap_blocked_read(a, *walk))
    }

    /// Whether content written under `a` now waits for a rotation (`wrap_blocked`'s encrypting
    /// walk), for tests.
    #[doc(hidden)]
    pub fn encrypt_blocked(&mut self, a: &Tid) -> Result<bool> {
        self.wrap_blocked_read(a, crate::rotation::Walk::Encrypt)
    }

    /// `wrap_blocked` read anew.
    pub(crate) fn wrap_blocked_read(&mut self, a: &Tid, walk: crate::rotation::Walk) -> Result<bool> {
        let a = *a;
        let encrypt = matches!(walk, crate::rotation::Walk::Encrypt);
        self.read(|tx| {
            // the roles at now it reads (`finalizable`, `may_rotate`) hold until the clock
            // reaches the next `until` or role commit in the components of `a` and this
            // node's account
            let _horizon = tx.core.bound_to_horizon(std::iter::once(a).chain(Some(tx.core.tid())));
            // a node removed from its account wraps nothing as it (it may still hold the read
            // secrets through the pass its drop waits for)
            let who = tx.core.tid();
            if encrypt && !crate::flows::edges::finalizable(tx.core, &who, &a).is_empty() {
                return Ok(true);
            }
            Ok(crate::rotation::blocked_roles_of(tx, &who, &a, walk)?.contains(&Role::Read))
        })
    }

    /// Held read secrets of an independent thing, newest first; then those derived from its mint
    /// admin's (a thing made independent: the rotation that gave it its own is wrapped under the
    /// derived epoch, spec/crypto.md §5).
    /// Each epoch's roles secret follows its secret (spec/crypto.md §4, Roles secrets), and one
    /// held without its secret stands alone.
    pub fn read_secrets(&self, g: &Tid) -> Vec<Secret32> {
        let mut v: Vec<Secret32> = self.epochs(g).map(|e| e.read.opening_newest_first()).unwrap_or_default();
        // the mint admin's epochs
        let firsts: Vec<Arc<osis_keys::ActorEpochs>> = self.core.created(g).and_then(osis_base::CreationRecord::mint_admin).and_then(|up| self.epochs(&up)).into_iter().collect();
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
    /// from (only a blob carrying them takes the wrap of a commit giving read epochs, `giving_wrap_epoch`).
    pub fn carries_secrets(&self, g: &Tid, c: &CommitId, parts: &[usize]) -> bool {
        let Some(a) = self.core.secret_actor(g) else { return false };
        let Some(h) = self.header(c) else { return false };
        parts.iter().filter_map(|ai| h.aspects.get(*ai)).any(|x| x.tid == a && matches!(x.ak.as_str(), "secrets.0" | "keys.0"))
    }
    /// For a commit giving read epochs of `g`'s secret actor (its `secrets.0` delta boxes them, or
    /// its `keys.0` delta writes a read keyset: a rotation, a grant, a re-seal): the held epoch
    /// with the greatest n that they supersede (spec/crypto.md §5, Who wraps under what), never
    /// one they are, since a recipient may lack them; `Plain` where they are the actor's first
    /// epochs (superseding nothing: every other holder holds them, or nothing of it); `Lacking`
    /// where none is held (or the deltas, or what they supersede, are not held to tell).
    fn giving_wrap_epoch(&mut self, g: &Tid, c: &CommitId, parts: &[usize]) -> Result<GivingWrap> {
        let Some(a) = self.core.secret_actor(g) else { return Ok(GivingWrap::Plain) };
        let Some(h) = self.header(c) else { return Ok(GivingWrap::Plain) };
        let id = *c;
        let mut given = BTreeSet::new();
        let mut rotation = false;
        // each of `a`'s parts, held; of a `secrets.0` in pieces (spec/wire.md §4 Pieces), each
        // these deltas carry and any other held
        let mut reads = Vec::new();
        for ak in ["secrets.0", "keys.0"] {
            let pieces = h.aspect_parts(&a, ak);
            let one = pieces.len() == 1;
            for ai in pieces {
                match self.read(|tx| crate::apply::held_fragment(tx, &id, ai))? {
                    Some(f) => reads.push((ak, f)),
                    None if one || parts.contains(&ai) => return Ok(GivingWrap::Lacking),
                    None => {}
                }
            }
        }
        for (ak, f) in reads {
            let epochs: Vec<std::result::Result<Epoch, osis_keys::Error>> = if ak == "keys.0" {
                let ks = crate::apply::keys::keys_write(&f).keysets.remove(&Role::Read);
                rotation = ks.is_some();
                ks.map(|ks| osis_keys::aspects::from_schema(&ks.epoch)).into_iter().collect()
            } else {
                crate::apply::keys::secrets_write(&f).boxes.keys().filter(|k| k.role == Role::Read).map(|k| osis_keys::aspects::from_schema(&k.epoch)).collect()
            };
            for e in epochs {
                let Ok(e) = e else { return Ok(GivingWrap::Lacking) };
                given.insert(e);
            }
        }
        // the actor's first epochs (n 0) supersede nothing
        if given.iter().all(|e| e.n() == 0) {
            return Ok(GivingWrap::Plain);
        }
        let Some(epochs) = self.epochs(&a) else { return Ok(GivingWrap::Lacking) };
        // what it gives is established here first (spec/crypto.md §4 Established only): a grant or
        // re-seal goes on from a node holding the rotation that made the epochs it boxes
        if !given.iter().all(|e| epochs.read.is_established(e)) {
            return Ok(GivingWrap::Lacking);
        }
        // role parts go under the roles secret alone (spec/crypto.md §4 Roles secrets), which a
        // holder of a floor holds of every earlier epoch; any other part needs the secret
        let roles_only = parts.iter().filter_map(|ai| h.aspects.get(*ai)).all(|x| osis_keys::under_roles(x.ak.as_str()));
        let held = |s: &Epoch| if roles_only { epochs.read.checked_roles(s).is_some() } else { epochs.read.secret(s).is_some() };
        Ok(epochs.read.wrapped_under(&given, held).map_or(GivingWrap::Lacking, |e| GivingWrap::Under(e, rotation)))
    }

    /// The deposit seed of `g`'s actor (its `keys.0`; `flows::sync_ids::deposit_seed_of`).
    pub fn deposit_seed(&mut self, g: &Tid) -> Result<Option<Secret32>> {
        self.read(|tx| crate::flows::sync_ids::deposit_seed_of(tx, g))
    }

    /// The keys this node holds for `head` of a sync ID of `g` (spec/sync-ids.md §2, spec/sync-ids.md §6): any
    /// held secret opens; stamps and deletes need an established epoch (spec/crypto.md §4).
    pub fn head_keys(&mut self, g: &Tid, head: &Step) -> Result<HeadKeys> {
        Memo::get_in(self, |e| &e.core.head_keys, &(*g, head.id()), |e| e.head_keys_derived(g, head))
    }

    fn head_keys_derived(&mut self, g: &Tid, head: &Step) -> Result<HeadKeys> {
        let mut k = HeadKeys::default();
        if let Some(e) = self.epochs(g) {
            let keys = self.core.role_key_epochs(g);
            if let Some((ep, s, _)) = matching(&keys.sync, &e, RoleKey::Sync, &head.keys.sync) {
                k.sync = Some(s);
                k.sync_established = self.established(g, &e, Role::Sync, &ep);
                k.epochs[0] = Some(ep);
            }
            if let Some((ep, w)) = self.head_write(g, &e, head) {
                k.write = w;
                k.epochs[1] = Some(ep);
            }
            if let Some((ep, s, checked)) = matching(&keys.delete, &e, RoleKey::Delete, &head.keys.delete) {
                if checked && self.established(g, &e, Role::Admin, &ep) {
                    k.delete = Some(s);
                }
                k.epochs[2] = Some(ep);
            }
        }
        // kept unread: a sync secret held, the head bearing its key, is established
        // under S (spec/crypto.md §4 Established)
        if k.sync.is_none()
            && let Some((ep, s)) = self.core.unread(g).candidates.iter().find(|(_, s)| crate::sync_ids::unread::sync_key(s) == head.keys.sync.to_bytes())
        {
            k.sync = Some(osis_crypto::role_key(RoleKey::Sync, s));
            k.sync_established = true;
            k.epochs[0] = Some(*ep);
        }
        if let Some(seed) = self.deposit_seed(g)? {
            let d = deposit_key(&seed, &head.sync_id);
            if d.verifying_key() == head.keys.deposit {
                k.deposit = Some(d);
            }
        }
        Ok(k)
    }

    /// `head_keys`' write key alone (`Engine::step_write_key`): read by `g`'s epochs, never its
    /// deposit seed.
    pub(crate) fn head_write_key(&self, g: &Tid, head: &Step) -> Option<SigningSecret> {
        let e = self.epochs(g)?;
        self.head_write(g, &e, head)?.1
    }

    /// The epoch of `head`'s write key held of `g`'s epochs `e`, and the key where this node
    /// stamps under it: stamps and deletes are encrypting under, never from a reading-only
    /// secret, and only in an established epoch.
    fn head_write(&self, g: &Tid, e: &ActorEpochs, head: &Step) -> Option<(Epoch, Option<SigningSecret>)> {
        let (ep, s, checked) = matching(&self.core.role_key_epochs(g).write, e, RoleKey::Write, &head.keys.write)?;
        Some((ep, (checked && self.established(g, e, Role::Write, &ep)).then_some(s)))
    }

    /// Whether `ep` of role `r` is established for `g`: in its own epochs, or, for a thing made
    /// independent, as the epoch derived from an established epoch of the mint admin
    /// it derived from before (spec/crypto.md §3-§4; the history box carries it without establishment).
    fn established(&self, g: &Tid, e: &ActorEpochs, r: Role, ep: &Epoch) -> bool {
        if e.role(r).is_established(ep) {
            return true;
        }
        let Some(up) = self.core.created(g).and_then(osis_base::CreationRecord::mint_admin) else { return false };
        self.epochs(&up).is_some_and(|o| ActorEpochs::derived(&o, g).role(r).is_established(ep))
    }
}

/// The secrets of the epoch a commit's wrap or section goes under: its secret where held, and its
/// roles secret, the one role parts go under (spec/crypto.md §4 Roles secrets).
pub(crate) struct WrapKey {
    secret: Option<Secret32>,
    roles: Secret32,
}

impl WrapKey {
    /// The key for role parts (`roles`), else for the rest.
    fn of(self, roles: bool) -> Option<Secret32> {
        if roles { Some(self.roles) } else { self.secret }
    }
}

/// The wrap a commit carrying `secrets.0` or `keys.0` of an actor takes (`giving_wrap_epoch`).
enum GivingWrap {
    /// It gives no read epoch, or only epochs superseding none: the plain rule.
    Plain,
    /// Under this epoch the read epochs it gives supersede; whether it is a rotation of read
    /// (its own wrap is not held back by a blocked epoch, spec/crypto.md §4 Encrypting under).
    Under(Epoch, bool),
    /// It gives read epochs superseding ones this node holds no secret of: not wrapped here.
    Lacking,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    

    // spec/crypto.md §3, spec/wire.md §4: a record chain of two dependent things minted with the node as admin: O,
    // whose mint admin is the node, derives from the node's epochs and T, whose mint admin is
    // O, from O's; a section on T lists the chain up to the node, one on O the node.
    #[test]
    fn derives_through_a_mint_admin_spec_crypto_3() {
        use crate::Mutation;
        let mut lp = crate::local_peer::LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let e = &mut lp.peers[0].engine;
        let me = e.tid();
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
        let pk = osis_crypto::role_key(RoleKey::Write, &s).verifying_key();
        let (ep, got, checked) = matching(&key_epochs(&a, RoleKey::Write), &a, RoleKey::Write, &pk).unwrap();
        assert_eq!((ep, got.verifying_key(), checked), (e, pk, false));
        a.write.set_secret(e, s.clone());
        assert!(matching(&key_epochs(&a, RoleKey::Write), &a, RoleKey::Write, &pk).unwrap().2);
    }
}
