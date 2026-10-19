//! Secrets the engine holds (spec/crypto.md §3–§4): the node's own role secrets, derived secrets
//! of plain things, epochs of actors with secrets of their own opened from `/secrets` (the
//! `SecretStore`, kept in the store per actor), dedup secrets from creation records, and the
//! `Secrets` osis-commit asks for when building a commit.

use super::Core;
use crate::error::{Error, Result};
use osis_core::{CreationRecord, Role, Tid, Value};
use osis_crypto::{Epoch, Secret32, dedup_secret};
use osis_keys::{ActorEpochs, Opener, Provenance, ROLES};
use osis_schema::AspectKey;
use osis_schema::core_types::{Keys, Secrets};

/// Owner chains longer than this are refused (they end at a key actor long before).
const MAX_CHAIN: usize = 64;

impl Core {
    pub(crate) fn created(&self, tid: &Tid) -> Option<&CreationRecord> {
        self.held.created.get(tid)
    }

    pub(crate) fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.created(tid).map(|r| dedup_secret(r.nonce()))
    }

    /// The epochs this node holds for `tid`: its own, opened ones, or derived from the owner's
    /// for a plain thing without secrets of its own.
    pub(crate) fn epochs(&self, tid: &Tid) -> Option<ActorEpochs> {
        let mut chain = Vec::new();
        let mut cur = *tid;
        for _ in 0..MAX_CHAIN {
            let held = (cur == self.id.tid()).then(|| self.id.epochs()).or_else(|| self.key_actors.get(&cur).map(|k| k.epochs()));
            if let Some(mut e) = held {
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if let Some(e) = self.secrets.get(&cur) {
                let mut e = e.clone();
                for t in chain.iter().rev() {
                    e = ActorEpochs::derived(&e, t);
                }
                return Some(e);
            }
            if self.own_keys.contains(&cur) {
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

    fn newest(&self, tid: &Tid, r: Role) -> Option<Secret32> {
        self.epochs(tid)?.role(r).newest_held().map(|(_, s)| s.clone())
    }

    /// Opens what `/secrets` of `actor` holds for this node or for actors it holds secrets of
    /// (spec/crypto.md §4). Returns whether anything new was learned.
    pub(crate) fn ingest_secrets(&mut self, actor: &Tid, secrets: &Secrets) -> bool {
        let before = self.secrets.get(actor).cloned();
        let mut epochs = before.clone().unwrap_or_default();
        let seed = self.id.seed().clone();
        let me = self.id.tid();
        let mut openers: Vec<(Tid, ActorEpochs)> = self.secrets.iter().filter(|(t, _)| *t != actor).map(|(t, e)| (*t, e.clone())).collect();
        openers.sort_by_key(|x| x.0);
        let _ = osis_keys::ingest(actor, secrets, &Opener::KeyActor { member: me, seed: &seed }, &mut epochs);
        for (t, k) in &self.key_actors {
            let _ = osis_keys::ingest(actor, secrets, &Opener::KeyActor { member: *t, seed: k.seed() }, &mut epochs);
        }
        for (m, e) in &openers {
            let _ = osis_keys::ingest(actor, secrets, &Opener::Actor { member: *m, epochs: e }, &mut epochs);
        }
        self.adopt_derived(actor, &mut epochs);
        let held_any = ROLES.iter().any(|r| epochs.role(*r).held().next().is_some());
        if held_any && Some(&epochs) != before.as_ref() {
            self.secrets.insert(*actor, epochs);
            return true;
        }
        false
    }

    /// A thing that got secrets of its own keeps its earlier derived epochs (by history box):
    /// those derived from an established epoch of the owner are established (spec/crypto.md §4,
    /// "derived from an established epoch of the owner"), so the rotation from them establishes
    /// and labels registered under them can be stepped.
    pub(crate) fn adopt_derived(&self, actor: &Tid, epochs: &mut ActorEpochs) {
        let Some(CreationRecord::Thing { owner, .. }) = self.created(actor) else { return };
        let Some(o) = self.epochs(owner) else { return };
        let d = ActorEpochs::derived(&o, actor);
        let mut any = false;
        for r in ROLES {
            for (ep, info) in d.role(r).epochs() {
                if info.established.is_some() && epochs.role(r).get(ep).is_some() && !epochs.role(r).is_established(ep) {
                    epochs.role_mut(r).set_established(*ep, Provenance::Derived);
                    any = true;
                }
            }
        }
        if any {
            epochs.establish();
        }
    }

    /// Notes `/keys` of `actor`: keysets mean secrets of its own (spec/permissions.md §3).
    pub(crate) fn observe_keys(&mut self, actor: &Tid, keys: &Keys) {
        if keys.read.is_some() || keys.write.is_some() || keys.admin.is_some() {
            self.own_keys.insert(*actor);
            if let Some(e) = self.secrets.get_mut(actor) {
                let _ = osis_keys::observe_keys(keys, e);
            }
        }
    }
}

/// What a commit build asks for (osis-commit `Secrets`).
pub struct CommitSecrets<'c> {
    pub core: &'c Core,
    /// The actor the commit acts for.
    pub actor: Tid,
    /// Creation records of things the commit creates.
    pub created: &'c [CreationRecord],
}

impl osis_commit::Secrets for CommitSecrets<'_> {
    fn dedup(&self, tid: &Tid) -> Option<Secret32> {
        self.core.dedup(tid).or_else(|| self.created.iter().find(|r| r.tid() == *tid).map(|r| dedup_secret(r.nonce())))
    }
    fn admin(&self, tid: &Tid) -> Option<Secret32> {
        self.core.newest(tid, Role::Admin).or_else(|| self.derived_new(tid, Role::Admin))
    }
    fn chain_write(&self) -> Option<Secret32> {
        self.core.newest(&self.actor, Role::Write)
    }
    fn write(&self, tid: &Tid) -> Option<Secret32> {
        self.core.newest(tid, Role::Write).or_else(|| self.derived_new(tid, Role::Write))
    }
}

impl CommitSecrets<'_> {
    /// A thing created by this commit derives from its owner.
    fn derived_new(&self, tid: &Tid, r: Role) -> Option<Secret32> {
        let rec = self.created.iter().find(|x| x.tid() == *tid)?;
        let CreationRecord::Thing { owner, .. } = rec else { return None };
        let e = ActorEpochs::derived(&self.core.epochs(owner)?, tid);
        e.role(r).newest_held().map(|(_, s)| s.clone())
    }
}

// ---- local encoding of held epochs (the store's actor secrets unit)

fn uint(n: u64) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

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
                            uint(i.suite),
                            Value::List(i.applied.iter().map(|a| Value::List(a.iter().map(Epoch::to_wire).collect())).collect()),
                            Value::Bool(i.snapshot),
                            Value::List(i.established.iter().map(|p| uint(provenance_code(*p))).collect()),
                            Value::List(i.supersedes.iter().map(Epoch::to_wire).collect()),
                            Value::List(i.secret.iter().map(|s| Value::Bytes(s.expose().to_vec())).collect()),
                        ])
                    })
                    .collect(),
            )
        })
        .collect();
    osis_core::encode(&Value::List(roles))
}

pub(crate) fn decode_epochs(b: &[u8]) -> Result<ActorEpochs> {
    let bad = || Error::Corrupt("epochs");
    let lim = osis_core::Limits { max_depth: 16, max_bytes: b.len() };
    let Value::List(roles) = osis_core::decode(b, &lim).map_err(|_| bad())? else { return Err(bad()) };
    let mut a = ActorEpochs::default();
    for (r, items) in ROLES.iter().zip(roles) {
        let Value::List(items) = items else { return Err(bad()) };
        for it in items {
            let Value::List(f) = it else { return Err(bad()) };
            let [e, Value::Int(suite), Value::List(applied), Value::Bool(snapshot), Value::List(est), Value::List(sup), Value::List(sec)] = f.as_slice() else { return Err(bad()) };
            let e = Epoch::from_wire(e).map_err(|_| bad())?;
            let info = a.role_mut(*r).observe(e);
            info.suite = u64::try_from(*suite).map_err(|_| bad())?;
            info.snapshot = *snapshot;
            if let [Value::List(ap)] = applied.as_slice() {
                info.applied = Some(ap.iter().map(Epoch::from_wire).collect::<std::result::Result<_, _>>().map_err(|_| bad())?);
            }
            if let [Value::Int(p)] = est.as_slice() {
                info.established = Some(provenance_of(*p).ok_or_else(bad)?);
            }
            for s in sup {
                info.supersedes.insert(Epoch::from_wire(s).map_err(|_| bad())?);
            }
            if let [Value::Bytes(s)] = sec.as_slice() {
                info.secret = Some(Secret32::from_bytes(s.as_slice().try_into().map_err(|_| bad())?));
            }
        }
    }
    Ok(a)
}

/// The typed `/secrets` of a state value, if it reads as one.
pub(crate) fn secrets_value(v: &Value) -> Option<Secrets> {
    osis_schema::core_types::SECRETS.decode(v).ok()
}

pub(crate) fn keys_value(v: &Value) -> Option<Keys> {
    osis_schema::core_types::KEYS.decode(v).ok()
}
