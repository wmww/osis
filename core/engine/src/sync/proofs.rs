//! Connection proofs (spec/sync-opens.md §2): what this node proves (`Engine::proving`), how a
//! peer's proofs are judged (`Engine::proven`), and what the proven roles decide: J (§4), who a
//! peer may be (spec/sync-set.md §3 To be waited for), whom a Stranded message goes to
//! (spec/permissions.md §4), and whether some other node may hold a sync ID
//! (spec/sync-status.md §3).
//!
//! Who writes each input a verifier reads, and why it cannot lift a peer above what this node's
//! reading gives:
//! - the proof's signature: the peer, by a key; the key hop is judged here (the record's key, or a
//!   key grant this node's reading applies), never on the peer's word;
//! - the claimed path: the peer; each hop is an edge this node's reading (with the copies, below)
//!   applies, and a path proves at most the least of its hops;
//! - the copies: the peer chooses them (a removed node with old keys picks the commits that undo
//!   its removal; each side of a permanent fork picks its own side). They are taken in only as a
//!   trial (`Engine::trial`): verified and applied as any receipt, the sides that receipt records
//!   recorded (Held first), and all of it undone after. Invariant (the guard): a proof judged on
//!   a reading that undoes a lowering this node's own reading applies proves nothing, so no copy
//!   brings back a removed or demoted node, and no copy moves this node to another side of a
//!   fork. A node demoted concurrently proves at the role its path gives here.
//! - the role on S: this node's reading alone (no copy reaches it): a proven thing is trusted at
//!   most at the role its path gives (the proven role), never at the claimed thing's role alone.

use super::J;
use crate::Engine;
use crate::engine::Core;
use crate::error::Result;
use osis_base::{Holder, Role, SignKey, SyncId, Tid};
use osis_blob::Certificates;
use osis_commit::CommitBlob;
use osis_crypto::SigningSecret;
use osis_perm::{At, WriteId};
pub use osis_store::Claim;
use std::collections::BTreeSet;
use std::sync::Arc;

/// One proof this node makes: a key holding a grant on `record`'s thing, and the path claimed.
#[derive(Clone)]
pub struct Prover {
    pub key: SigningSecret,
    pub record: osis_base::CreationRecord,
    pub path: Vec<Tid>,
}

impl Prover {
    /// The claim this proof makes.
    pub fn claim(&self) -> Claim {
        Claim { thing: self.record.tid(), key: self.key.verifying_key().to_bytes(), path: self.path.clone() }
    }
}

/// What this node proves on a connection (spec/wire.md §11.2 Prove): its proofs in proof order,
/// and the copies backing them.
#[derive(Clone, Default)]
pub struct Proving {
    pub provers: Vec<Prover>,
    pub copies: Certificates,
}

/// A thing a peer's proof proved, with the role its path gives it here now (`None`: the path
/// once gave it a role and gives none now; a thing whose path never gave one is not listed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProvenThing {
    pub thing: Tid,
    pub role: Option<Role>,
}

/// A lowering this node's own reading applies: its write, its edge and the role it set.
type Lowering = (WriteId, Tid, Tid, Option<Role>);

impl Core {
    /// The things `c` proves on this node's reading at `now` (wall ms): the signed thing while
    /// the key hop gives a role, then each thing of the path while every hop up to it does
    /// (spec/sync-opens.md §2), each at the least of its hops so far. The signed thing first;
    /// the list stops at the first thing no hop up to ever gave a role. With the earliest
    /// `until` after `now` of a hop it read alive: the answer holds until then.
    fn claimed(&self, c: &Claim, now: u64) -> (Vec<ProvenThing>, Option<u64>) {
        let ts = crate::flows::ts_at(now);
        let tl = self.timelines();
        let key = SignKey(c.key);
        let mut until: Option<u64> = None;
        let mut alive = |e: &osis_perm::Edge| {
            if let Some(u) = e.until {
                until = Some(until.map_or(u.0, |x| x.min(u.0)));
            }
            e.role
        };
        let hop = tl.key_grant(&key, &c.thing).filter(|e| e.alive_at(Some(ts))).map(|e| alive(&e));
        if hop.is_none() && !tl.key_grants(&c.thing, None).contains_key(&key) {
            return (Vec::new(), until);
        }
        let mut out = vec![ProvenThing { thing: c.thing, role: hop }];
        let (mut role, mut prev) = (hop, c.thing);
        for x in &c.path {
            let edge = tl.on(x).and_then(|o| o.roster(At::now(ts)).get(&prev).map(&mut alive));
            if edge.is_none() && !tl.get(&prev).is_some_and(|t| t.roles_ever(&prev).contains_key(x)) {
                break;
            }
            role = role.min(edge);
            out.push(ProvenThing { thing: *x, role });
            prev = *x;
        }
        (out, until)
    }

    /// The lowerings this node's reading applies (spec/permissions.md §5.1): edge writes on a
    /// thing's grant giving below admin at their `ts`.
    fn applied_lowerings(&self) -> Vec<Lowering> {
        let tl = self.timelines();
        let mut out = Vec::new();
        for w in tl.applied_writes().into_keys() {
            let Some(rc) = tl.role_commit(&w.0) else { continue };
            let Some(op) = rc.ops.get(w.1 as usize) else { continue };
            let Holder::Thing(h) = op.holder else { continue };
            let set = op.edge.filter(|e| e.alive_at(Some(rc.ts))).map(|e| e.role);
            if set < Some(Role::Admin) {
                out.push((w, h, op.target, set));
            }
        }
        out
    }

    /// Whether this node's reading undoes one of `own`: it does not apply it, and its edge gives
    /// more than it set.
    fn undoes(&self, own: &[Lowering]) -> bool {
        let tl = self.timelines();
        let edges = tl.edges_at(None);
        own.iter().any(|(w, h, t, set)| !tl.is_applied(w) && edges.get(h, t).map(|e| e.role) > *set)
    }

    /// The role proven thing `p` is trusted at on `a` (spec/sync-opens.md §2 proven role): the
    /// least of what its path gives and its own role on `a` here.
    pub(crate) fn proven_role(&self, p: &ProvenThing, a: &Tid) -> Option<Role> {
        let on = if p.thing == *a { Some(Role::Admin) } else { self.role_now(&p.thing, a) };
        p.role.min(on)
    }

    /// Whether `t` is held only by this node: an own thing, or a thing without a key of its own
    /// whose holders are all held only by this node (spec/sync-status.md §3 held by no other node).
    fn held_here_only(&self, t: &Tid, seen: &mut BTreeSet<Tid>) -> bool {
        if self.is_own(t) {
            return true;
        }
        if !seen.insert(*t) || self.created(t).is_some_and(|r| r.key().is_some()) {
            return false;
        }
        let holders = self.key_holders(t);
        !holders.is_empty() && holders.iter().all(|(m, _)| self.held_here_only(m, seen))
    }
}

impl Engine {
    /// What this node proves on a connection, in proof order (spec/wire.md §11.2 Prove): its node
    /// thing claiming each thing it holds a grant on (its accounts), or nothing past itself where
    /// it holds none, then its held link keys by ascending tid; and as copies the edge writes on
    /// those claimed edges, with their evidence and records.
    pub fn proving(&mut self) -> Result<Proving> {
        let me = self.core.me();
        let targets: BTreeSet<Tid> = self.core.timelines().edges_at(None).targets(&me).copied().collect();
        let node = |path: Vec<Tid>| Prover { key: self.core.id.signing().clone(), record: self.core.id.record().clone(), path };
        let mut provers: Vec<Prover> = if targets.is_empty() { vec![node(Vec::new())] } else { targets.iter().map(|t| node(vec![*t])).collect() };
        provers.extend(self.core.link_keys.values().map(|k| Prover { key: k.signing().clone(), record: k.record().clone(), path: Vec::new() }));
        let copies = self.path_copies(&me, &targets)?;
        Ok(Proving { provers, copies })
    }

    /// Certificate copies of the edge writes on `holder`'s grants on `targets`, with their
    /// evidence and records (`copies_of`).
    fn path_copies(&mut self, holder: &Tid, targets: &BTreeSet<Tid>) -> Result<Certificates> {
        let mut seeds = Vec::new();
        for t in targets {
            if let Some(o) = self.core.timelines().on(t) {
                seeds.extend(o.held().filter(|(_, _, op)| op.holder == Holder::Thing(*holder)).map(|(w, _, _)| (w.0, *t)));
            }
        }
        self.copies_of(&seeds, &[*holder])
    }

    /// Certificate copies of held commits' `roles.0` parts on the things paired with them, with
    /// their evidence, and the records of those things, of `also` and of the evidence
    /// (spec/wire.md §11.2 Prove's copies).
    pub fn copies_of(&mut self, writes: &[(osis_base::CommitId, Tid)], also: &[Tid]) -> Result<Certificates> {
        let ev = self.evidence_now()?;
        let mut certs = crate::sync_ids::Certs::default();
        for (c, t) in writes {
            certs.records.insert(*t);
            let Some(h) = self.header(c) else { continue };
            let Some(ai) = h.aspect_index(t, "roles.0") else { continue };
            certs.commits.entry(*c).or_default().insert(ai);
            certs.records.insert(h.signer);
            self.add_closure(&ev, &BTreeSet::from([(*c, *t)]), &mut certs);
        }
        certs.records.extend(also.iter().copied());
        self.close_records(&ev, &mut certs);
        let (commits, records) = self.certs_values(&certs)?;
        Ok(Certificates { commits, records })
    }

    /// The things a peer's proofs prove here now (spec/sync-opens.md §2), each claim's in order:
    /// judged on what this node holds with `copies` taken in as a trial, the sides their receipt
    /// records, for this judgement alone; nothing where that reading undoes a lowering this
    /// node's own reading applies (the guard). With no copy this node lacks, its own reading. A
    /// memo per (claims, copies): it moves with what it read.
    pub fn proven(&mut self, claims: &[Claim], copies: &Certificates) -> Result<Arc<Vec<ProvenThing>>> {
        let mut h = osis_base::hash::Hasher::new();
        for c in claims {
            h.update(c.thing.as_bytes()).update(&c.key).update(&(c.path.len() as u64).to_be_bytes());
            for t in &c.path {
                h.update(t.as_bytes());
            }
        }
        let mut bytes = Vec::new();
        for v in &copies.commits {
            osis_base::cbor::encode_into(v, &mut bytes);
        }
        for r in &copies.records {
            osis_base::cbor::encode_into(&r.to_value(), &mut bytes);
        }
        let k = h.update(&bytes).finalize();
        osis_base::memo::Memo::get_in(self, |e| &e.core.proven, &k, |e| e.proven_now(claims, copies).map(Arc::new))
    }

    fn proven_now(&mut self, claims: &[Claim], copies: &Certificates) -> Result<Vec<ProvenThing>> {
        let blobs: Vec<CommitBlob> = copies.commits.iter().filter_map(|v| CommitBlob::decode(&osis_base::encode(v)).ok()).filter(|b| !self.core.ix.commits.contains_key(&b.id())).collect();
        let records: Vec<osis_base::CreationRecord> = copies.records.iter().filter(|r| self.core.created(&r.tid()).is_none()).cloned().collect();
        // each claim at the time, holding until the first `until` a hop read alive passes
        let judge = |core: &Core, now: u64| {
            let mut until: Option<u64> = None;
            let mut out = Vec::new();
            for c in claims {
                let (p, u) = core.claimed(c, now);
                out.extend(p);
                until = match (until, u) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
            }
            (out, until)
        };
        if blobs.is_empty() && records.is_empty() {
            return Ok(self.core.time.at(|now| judge(&self.core, now)));
        }
        // judged at the clock, holding until the first `until` a hop read alive passes; what the
        // trial itself reads of the clock (a copy's arrival) it reads as any reader does
        let now = self.core.time.until(None);
        let own = self.core.applied_lowerings();
        let (out, until) = self.trial(records, blobs, |core| if core.undoes(&own) { (Vec::new(), None) } else { judge(core, now) })?;
        self.core.time.until(until);
        Ok(out)
    }

    /// J of a peer whose proofs prove `proven` for `s` (spec/sync-opens.md §4): reader if a
    /// proven thing's proven role on one of `s`'s things is read or above, sync holder if one's
    /// is sync, departed if one once held a role there and none holds one now, else unknown.
    /// `Unknown` for a sync ID this node does not read.
    pub fn judge_peer(&mut self, s: &SyncId, proven: &[ProvenThing]) -> Result<J> {
        let mut out = J::Unknown;
        for t in self.sync_things_of(s)? {
            let a = self.core.reader_of(&t);
            let best = proven.iter().map(|p| self.core.proven_role(p, &a)).max().flatten();
            let j = match best {
                Some(r) if r >= Role::Read => J::Reader,
                Some(_) => J::SyncHolder,
                None if proven.iter().any(|p| p.thing == a || self.core.timelines().get(&p.thing).is_some_and(|tl| tl.roles_ever(&p.thing).contains_key(&a))) => J::Departed,
                None => J::Unknown,
            };
            if rank(j) > rank(out) {
                out = j;
            }
        }
        Ok(out)
    }

    /// The proven thing among `proven` whose proven role on read sync ID `s`'s thing is write or
    /// above (spec/permissions.md §4: whom a Stranded message goes to).
    pub fn writer_of(&mut self, s: &SyncId, proven: &[ProvenThing]) -> Result<Option<Tid>> {
        let Some((t, _)) = self.read_sync_id(s)? else { return Ok(None) };
        let a = self.core.reader_of(&t);
        Ok(proven.iter().find(|p| self.core.proven_role(p, &a) >= Some(Role::Write)).map(|p| p.thing))
    }

    /// Whether a peer whose proofs prove `proven` may hold `s` (spec/sync-set.md §3 To be waited
    /// for, who it may be): S kept unread, any peer; else a proven thing other than this node's
    /// own with a proven role on one of S's things.
    pub fn may_hold(&mut self, s: &SyncId, proven: &[ProvenThing]) -> Result<bool> {
        self.follow_read_things()?;
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(false) };
        if holding == super::Holding::Unread {
            return Ok(true);
        }
        Ok(things.iter().any(|t| {
            let a = self.core.reader_of(t);
            proven.iter().any(|p| !self.core.is_own(&p.thing) && self.core.proven_role(p, &a).is_some())
        }))
    }

    /// Whether some node other than this one may hold `s` by the rosters here (spec/sync-status.md
    /// §3): S kept unread, yes; read, unless no thing holds a role on its things but this node's
    /// own things and things only they hold roles on.
    pub fn others_may_hold(&mut self, s: &SyncId) -> Result<bool> {
        self.follow_read_things()?;
        let Some((things, holding)) = self.synced_things(s)? else { return Ok(false) };
        if holding == super::Holding::Unread {
            return Ok(true);
        }
        Ok(things.iter().any(|t| {
            let a = self.core.reader_of(t);
            !self.core.held_here_only(&a, &mut BTreeSet::new())
        }))
    }
}

fn rank(j: J) -> u8 {
    match j {
        J::Reader => 3,
        J::SyncHolder => 2,
        J::Departed => 1,
        J::Unknown => 0,
    }
}
