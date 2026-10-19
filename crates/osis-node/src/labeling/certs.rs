//! Certificate blobs and steps (spec/permissions.md §4; spec/sync.md §2-§3): this node's chain
//! certificates for a group and its node card as (commit, aspects) to place; the readers a
//! registration step lists; new labels and child steps.

use super::blobs::Body;
use crate::engine::Engine;
use crate::error::{Error, Result};
use osis_core::{Ak, CommitId, CreationRecord, LabelId, Role, Tid};
use osis_crypto::{Epoch, KemPublicKey, LabelRole, Secret32, VerifyingKey, label_role_key};
use osis_crdt::{Op, PathOp, PathSeg};
use osis_label::{ClaimSet, EntryTo, Parent, Reader, Step, StepKeys};
use osis_perm::Point;
use osis_schema::Codec;
use osis_schema::core_types as ct;
use std::collections::{BTreeMap, BTreeSet};

/// Aspects a node card holds (each its own commit, spec/permissions.md §4).
const CARD: [&str; 3] = ["/keys", "/node", "/reach"];

/// A reader of a step, before its keys are borrowed.
enum Listed {
    Dh([u8; 32]),
    Static { signing: VerifyingKey, kem: KemPublicKey },
}

impl Engine {
    /// The newest held commit touching `(tid, ak)`.
    fn latest_on(&self, tid: &Tid, ak: &str) -> Option<CommitId> {
        let ak = Ak::new(ak).ok()?;
        self.core.by_aspect.get(&(*tid, ak)).and_then(|s| s.iter().next_back()).map(|(_, c)| *c)
    }

    /// Aspect indexes of commit `c` on `(tid, ak)` for any of `aks`.
    fn aspects_of(&self, c: &CommitId, tids: &BTreeSet<Tid>, aks: &[&str]) -> Vec<usize> {
        let Some(h) = self.header(c) else { return Vec::new() };
        h.aspects.iter().enumerate().filter(|(_, a)| tids.contains(&a.tid) && aks.contains(&a.ak.as_str())).map(|(i, _)| i).collect()
    }

    /// This node's chain certificates for `g` and its node card (spec/permissions.md §4), as
    /// commits with the aspect indexes to carry.
    pub fn certificates(&self, g: &Tid) -> BTreeMap<CommitId, BTreeSet<usize>> {
        let me = self.tid();
        let mut out: BTreeMap<CommitId, BTreeSet<usize>> = BTreeMap::new();
        let mut add = |c: CommitId, ais: Vec<usize>| {
            if !ais.is_empty() {
                out.entry(c).or_default().extend(ais);
            }
        };
        let mine = BTreeSet::from([me]);
        for ak in CARD.iter().chain(["/created"].iter()) {
            if let Some(c) = self.latest_on(&me, ak) {
                add(c, self.aspects_of(&c, &mine, &[ak]));
            }
        }
        let mut created: BTreeSet<Tid> = BTreeSet::new();
        let mut keys: BTreeSet<Tid> = BTreeSet::new();
        let mut cur = Some(*g);
        while let Some(t) = cur {
            if !created.insert(t) {
                break;
            }
            cur = match self.core.created(&t) {
                Some(CreationRecord::Thing { owner, .. }) => Some(*owner),
                _ => None,
            };
        }
        if let Some(tl) = self.core.timelines.get(g) {
            let ts = osis_core::Ts::make(self.now(), 0xffff).unwrap_or_default();
            let certs = tl.certificates(&me, g, Point { ts, node: me, commit: CommitId([0xff; 32]) });
            created.extend(certs.created.iter().copied());
            keys.extend(certs.keys.iter().copied());
            let all: BTreeSet<Tid> = certs.created.iter().copied().collect();
            for c in certs.commits.iter().chain(certs.snapshots.keys()) {
                add(*c, self.aspects_of(c, &all, &["/members", "/tenures"]));
            }
        }
        for t in &created {
            if let Some(c) = self.latest_on(t, "/created") {
                add(c, self.aspects_of(&c, &BTreeSet::from([*t]), &["/created"]));
            }
        }
        for t in &keys {
            if let Some(c) = self.latest_on(t, "/keys") {
                add(c, self.aspects_of(&c, &BTreeSet::from([*t]), &["/keys"]));
            }
        }
        out
    }

    /// The bodies of commit `c` restricted to aspects `ais` (one per retention class): a
    /// certificate copy.
    pub fn partial_bodies(&mut self, c: &CommitId, ais: &BTreeSet<usize>) -> Result<Vec<Body>> {
        let id = *c;
        let Some(blob) = self.run(|tx| tx.get_commit(&id))? else { return Ok(Vec::new()) };
        let cut = osis_commit::rewrite(&blob, |ai, _| !ais.contains(&ai));
        if cut.parts.is_empty() {
            return Ok(Vec::new());
        }
        let membership = cut.header.kind.is_membership();
        let ps = osis_commit::project(&cut, |_| ())?;
        Ok(ps.into_iter().map(|p| Body { commit: id, reader: self.tid(), parts: p.parts, expires: p.expires, tokens: p.tokens, plaintext: p.plaintext, membership }).collect())
    }

    /// Readers a step for read epoch `e` of actor `a` lists (spec/sync.md §2): holders of
    /// boxes in `/secrets` of `a` and its owner; nodes and actors by DH key, other key actors
    /// by static entry.
    fn listed(&mut self, a: &Tid) -> Result<Vec<Listed>> {
        let mut members: BTreeSet<Tid> = BTreeSet::new();
        match self.core.created(a).cloned() {
            Some(CreationRecord::KeyActor { .. }) => {
                members.insert(*a);
            }
            Some(CreationRecord::Thing { owner, .. }) => {
                members.insert(owner);
                if let Some(s) = self.get_typed(a, &ct::SECRETS)? {
                    members.extend(s.boxes.keys().map(|k| k.member));
                }
            }
            None => return Err(Error::UnknownThing(*a)),
        }
        let mut out = Vec::new();
        for m in members {
            let keys = self.get_typed(&m, &ct::KEYS)?;
            match self.core.created(&m).cloned() {
                Some(CreationRecord::KeyActor { public_key, .. }) => {
                    let kem = if m == self.tid() {
                        Some(self.identity().keys().kem.public().clone())
                    } else {
                        keys.as_ref().and_then(|k| k.key.as_ref()).and_then(|ct::KemKey::X25519MlKem768(b)| KemPublicKey::from_slice(b).ok())
                    };
                    let Some(kem) = kem else { continue };
                    let is_node = m == self.tid() || self.latest_on(&m, "/node").is_some();
                    if is_node {
                        out.push(Listed::Dh(kem.x25519()));
                    } else if let Ok(pk) = <[u8; 32]>::try_from(public_key.as_slice())
                        && let Ok(signing) = VerifyingKey::from_bytes(&pk)
                    {
                        out.push(Listed::Static { signing, kem });
                    }
                }
                Some(CreationRecord::Thing { .. }) => {
                    let Some(ks) = keys.and_then(|k| k.read) else { continue };
                    let ct::KemKey::X25519MlKem768(b) = &ks.kem_key;
                    if let Ok(kem) = KemPublicKey::from_slice(b) {
                        out.push(Listed::Dh(kem.x25519()));
                    }
                }
                None => {}
            }
        }
        Ok(out)
    }

    /// The step keys and read epoch a registration of label `index` of `g` uses now: the newest
    /// established epoch of each role (spec/permissions.md §3).
    fn step_keys(&mut self, g: &Tid, index: u64, label: Option<LabelId>) -> Result<(StepKeys, (Epoch, Secret32), Secret32, LabelId)> {
        let e = self.epochs(g).ok_or(Error::Misuse("no secrets of the group"))?;
        let [(re, rs), (_, ws), (_, a)] = osis_keys::registration_epochs(&e).ok_or(Error::Misuse("registration needs every role's newest secret"))?;
        let (rs, ws, a) = (rs.clone(), ws.clone(), a.clone());
        let label = label.unwrap_or_else(|| osis_label::genesis_label(&a, index));
        let seed = self.deposit_seed(g)?.ok_or(Error::Misuse("the group's actor has no deposit seed"))?;
        Ok((StepKeys::derive(&rs, &ws, &a, index, &seed, &label), (re, rs), a, label))
    }

    /// Registers a step: genesis (`parent` none) or a child of `parent` signed by `delete`.
    pub(crate) fn new_step(&mut self, g: &Tid, index: u64, parent: Option<(&Step, &osis_crypto::SigningSecret)>, rng: &mut dyn osis_crypto::CryptoRngCore) -> Result<(Step, ClaimSet)> {
        let (keys, (re, rs), admin, _) = self.step_keys(g, index, parent.map(|(p, _)| p.label))?;
        let a = self.core.secret_actor(g).unwrap_or(*g);
        let listed = self.listed(&a)?;
        let readers: Vec<Reader> = listed
            .iter()
            .map(|l| match l {
                Listed::Dh(k) => Reader::Dh(*k),
                Listed::Static { signing, kem } => Reader::Static { signing: *signing, entry: EntryTo::Sealed(kem) },
            })
            .collect();
        let genesis = label_role_key(LabelRole::Delete, &admin, index);
        let p = match parent {
            Some((step, delete)) => Parent::Child { step, delete },
            None => Parent::Genesis(&genesis),
        };
        Ok(osis_label::register(p, keys, &readers, (re, &rs), rng)?)
    }

    /// Creates a new label of `g` (index one above the highest recorded) with its genesis step,
    /// recorded in `/label` with `servers` (spec/sync.md §2). Only an admin of `g`.
    pub fn create_label(&mut self, g: &Tid, servers: Vec<osis_label::Address>, rng: &mut dyn osis_crypto::CryptoRngCore) -> Result<LabelId> {
        if self.role_on(g) < Some(Role::Admin) {
            return Err(Error::Permission { tid: *g });
        }
        let index = self.group_labels(g)?.iter().map(|l| l.index + 1).max().unwrap_or(0);
        let (step, set) = self.new_step(g, index, None, rng)?;
        let label = step.label;
        let rec = ct::Label { index, steps: BTreeMap::from([(step.id().0, osis_label::step_record(&step, Some(&set)))]), servers, replaced: false };
        let mut m = crate::Mutation::new();
        m.op(*g, &ct::LABEL, PathOp { path: vec![PathSeg::Key(label.to_value())], op: Op::Set(rec.to_value()) })?;
        self.commit(m)?;
        self.set_syncing(*g, true)?;
        Ok(label)
    }
}
