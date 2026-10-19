//! Bodies, encryption, wraps, stamps, deposits and tokens (spec/sync.md §1-§3, §5; spec/crypto.md
//! §5, §7): what a commit becomes under a label, and the label keys a server's head calls for.

use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_commit::{CommitBlob, Kind, Token};
use osis_core::{BlobId, CommitId, LabelId, Role, Tid, WallMs};
use osis_crypto::{CryptoRngCore, Epoch, LabelRole, Secret32, SigningSecret, deposit_key, label_role_key};
use osis_keys::{ActorEpochs, WrapEpoch};
use osis_label::Step;
use osis_schema::core_types as ct;

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
    pub tokens: Vec<Token>,
    pub plaintext: Vec<u8>,
    pub membership: bool,
}

/// A blob of a body: ID, bytes, key.
pub struct Sealed {
    pub id: BlobId,
    pub blob: Vec<u8>,
    pub key: Secret32,
}

/// Frames a body as a fresh blob: random salt and key, prefix from its class (spec/sync.md §1).
pub fn seal_body(b: &Body, rng: &mut dyn CryptoRngCore) -> Result<Sealed> {
    let salt = osis_label::Prefix::random_salt(rng);
    let p = osis_commit::Prefix::from_tokens(salt, b.expires, &b.tokens)?;
    let prefix = osis_label::Prefix::new(p.salt, p.expiry.map(WallMs), p.commitments)?;
    let (key, blob) = osis_label::frame(&prefix, &b.plaintext, rng)?;
    Ok(Sealed { id: osis_label::blob_id(&blob), blob, key })
}

/// Opens a commit blob and checks its prefix against the header (spec/commits.md §4): the
/// plaintext and its parts.
pub fn open_commit(blob: &[u8], key: &Secret32) -> Result<(Vec<u8>, CommitBlob)> {
    let (prefix, pt) = osis_label::open(blob, key)?;
    let c = CommitBlob::decode(&pt)?;
    let parts: Vec<(usize, usize)> = c.parts.iter().map(|p| (p.ai, p.di)).collect();
    if !c.header.is_resolved() {
        // linked header lists: the agreement is checked once node-core resolved them
        return Ok((pt, c));
    }
    let (expiry, tokens) = osis_commit::prefix_inputs(&c.header, &parts)?;
    let toks: Vec<(u8, [u8; 16])> = tokens.iter().map(|t| (t.level, t.hash)).collect();
    if !parts.is_empty() && !prefix.agrees(expiry.map(WallMs), &toks) {
        return Err(Error::BadInput("blob prefix disagrees with its header"));
    }
    Ok((pt, c))
}

/// The label keys this node holds for a server's head (spec/sync.md §2, §5).
#[derive(Clone, Default)]
pub struct HeadKeys {
    /// Opens (any held secret, spec/crypto.md §4: opening is not encrypting under).
    pub sync: Option<SigningSecret>,
    /// The sync key's epoch is established: it may sign token deletes.
    pub sync_established: bool,
    /// Stamps and level-3 token deletes (an established epoch).
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

/// The held epoch of `role` whose label key at `index` is `pk`, with its secret.
fn matching(e: &ActorEpochs, role: Role, index: u64, pk: &osis_crypto::VerifyingKey) -> Option<(Epoch, Secret32)> {
    let re = e.role(role);
    let ep = osis_keys::registered_epoch(re, role, index, pk)?;
    re.secret(&ep).map(|s| (ep, s.clone()))
}

impl Engine {
    /// The projections of a held commit's current blob (its held deltas), with their reader
    /// actors.
    pub fn bodies(&mut self, c: &CommitId) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let membership = blob.header.kind.is_membership();
        let readers: Vec<Tid> = blob.header.aspects.iter().map(|a| self.core.reader_of(&a.tid)).collect();
        let ps = osis_commit::project(&blob, |ai| readers.get(ai).copied())?;
        Ok(ps
            .into_iter()
            .filter_map(|p| {
                let reader = p.readers?;
                Some(Body { commit: id, reader, parts: p.parts, expires: p.expires, tokens: p.tokens, plaintext: p.plaintext, membership })
            })
            .collect())
    }

    /// The bodies a group's label must hold from its closure (spec/sync.md §3): projections of
    /// held commits touching the closure whose deltas the group's actor may read. A home label
    /// (an actor synced as a group of itself) also carries the `/label` and `/created` writes of
    /// the labeled groups it is the nearest labeled owner-chain actor of (spec/sync.md §2).
    pub fn label_bodies(&mut self, g: &Tid) -> Result<Vec<Body>> {
        let closure = self.closure(g);
        let x = self.group_actor(g);
        let published = self.published_under(g);
        let ids: Vec<CommitId> = self
            .core
            .commits
            .iter()
            .filter(|(_, m)| m.header.aspects.iter().any(|a| closure.contains(&a.tid) || published.contains(&a.tid) && matches!(a.ak.as_str(), "/label" | "/created")))
            .map(|(id, _)| *id)
            .collect();
        let mut out = Vec::new();
        for id in ids {
            let Some(h) = self.header(&id) else { continue };
            let touches = h.aspects.iter().any(|a| closure.contains(&a.tid));
            for b in self.bodies(&id)? {
                let inside = touches || b.parts.iter().filter_map(|(ai, _)| h.aspects.get(*ai)).any(|a| published.contains(&a.tid) && matches!(a.ak.as_str(), "/label" | "/created"));
                if inside && self.core.may_read(&x, &b.reader) {
                    out.push(b);
                }
            }
        }
        Ok(out)
    }

    /// Labeled groups whose nearest labeled owner-chain actor is `g` (its home label publishes
    /// their `/label`, spec/sync.md §2). Empty unless `g` is an actor with secrets of its own.
    fn published_under(&self, g: &Tid) -> std::collections::BTreeSet<Tid> {
        let mut out = std::collections::BTreeSet::new();
        if !self.core.own_keys.contains(g) {
            return out;
        }
        let labeled: std::collections::BTreeSet<Tid> = self.labeled_groups().into_iter().collect();
        for h in &labeled {
            if h == g {
                continue;
            }
            let mut cur = *h;
            for _ in 0..64 {
                let Some(osis_core::CreationRecord::Thing { owner, .. }) = self.core.created(&cur) else { break };
                cur = *owner;
                if labeled.contains(&cur) && self.core.own_keys.contains(&cur) {
                    if cur == *g {
                        out.insert(*h);
                    }
                    break;
                }
            }
        }
        out
    }

    /// The read secret a commit is wrapped under at a label of `g` (spec/crypto.md §5): the
    /// newest current read epoch held, except a rotation commit of the actor `g`'s secrets
    /// derive from, which goes under the newest epoch its rotation supersedes. `None`: no
    /// current secret held (only a stranded heartbeat may be placed).
    pub fn wrap_secret(&mut self, g: &Tid, c: Option<&CommitId>) -> Result<Option<Secret32>> {
        let Some(e) = self.epochs(g) else { return Ok(None) };
        if let Some(c) = c
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
            let f = match d {
                osis_commit::Decoded::Delta(x) => x.fragment,
                osis_commit::Decoded::Snapshot(x) => x.fragment,
            };
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
            if let Some((ep, s)) = matching(&e, Role::Read, index, &head.keys.sync) {
                k.sync = Some(label_role_key(LabelRole::Sync, &s, index));
                k.sync_established = self.established(g, &e, Role::Read, &ep);
                k.epochs[0] = Some(ep);
            }
            if let Some((ep, s)) = matching(&e, Role::Write, index, &head.keys.write) {
                if self.established(g, &e, Role::Write, &ep) {
                    k.write = Some(label_role_key(LabelRole::Write, &s, index));
                }
                k.epochs[1] = Some(ep);
            }
            if let Some((ep, s)) = matching(&e, Role::Admin, index, &head.keys.delete) {
                if self.established(g, &e, Role::Admin, &ep) {
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
        let Some(osis_core::CreationRecord::Thing { owner, .. }) = self.core.created(g) else { return false };
        self.epochs(owner).is_some_and(|o| ActorEpochs::derived(&o, g).role(r).is_established(ep))
    }

    /// The delete tokens this node can derive for the deltas `parts` of commit `c` (spec/crypto.md
    /// §7): per token the header lists for their class, with its level, tried over every held
    /// epoch of the level's secret. Needs no blob: a dropped body's copy may be gone.
    pub fn tokens_of(&mut self, c: &CommitId, parts: &[(usize, usize)]) -> Vec<(u8, Secret32)> {
        let Some(h) = self.header(c) else { return Vec::new() };
        let Some(a) = parts.first().and_then(|(ai, _)| h.aspects.get(*ai)) else { return Vec::new() };
        let Some(thing) = self.epochs(&a.tid) else { return Vec::new() };
        let author = if h.kind == Kind::Import { None } else { self.epochs(&h.actor) };
        let mut out = Vec::new();
        for t in a.tokens.iter().filter_map(|i| h.tokens.get(*i)) {
            for (_, s) in osis_keys::token_candidates(t.level, &thing, author.as_ref()) {
                let tok = osis_crypto::delete_token(s, &h.salt);
                if osis_crypto::token_hash(tok.expose()) == t.hash {
                    out.push((t.level, tok));
                    break;
                }
            }
        }
        out
    }
}

/// A delete item for an entry: by the delete key when held, else by a token and the key its
/// level needs (spec/sync.md §5), under established epochs only (spec/crypto.md §4).
pub fn delete_item(keys: &HeadKeys, label: &LabelId, blob: BlobId, at: Option<WallMs>, tokens: &[(u8, Secret32)]) -> Option<osis_label::DeleteItem> {
    if let Some(d) = &keys.delete {
        return osis_label::DeleteItem::sign(d, label, blob, at, None).ok();
    }
    for (level, tok) in tokens {
        let key = match osis_label::key_for_level(*level).ok()? {
            LabelRole::Write => keys.write.as_ref(),
            _ => keys.sync.as_ref().filter(|_| keys.sync_established),
        };
        if let Some(k) = key {
            return osis_label::DeleteItem::sign(k, label, blob, at, Some(tok)).ok();
        }
    }
    None
}
