//! Pairing and removing a node of an account (spec/permissions.md §8): a library's arrangement of
//! ordinary things, read by no core rule. Pairing is the ordinary grant of the new node thing's
//! role on A, handed to the new node over a channel its users provide as an offer of A in place
//! of a `grant@~0` fire; removing is the ordinary removal with A's rotation.
//!
//! Invariants (security):
//! - Only an admin of A pairs or removes a node (`pair`, `remove_node` refuse otherwise; any other
//!   node's grant or removal is judged invalid wherever it lands, spec/permissions.md §2).
//! - What a pairer hands over gives the new node nothing it could not get by syncing A: the offer's
//!   copy holds role-class parts on A alone and is taken only where judged valid; its evidence and
//!   records only where they judge it (`take_parts`). Its trust records reach only lowerings on A
//!   it carries (`take_offer`). A pairer that is not an admin of A gives the new node no role.
//! - A removed node keeps nothing it reads by A once its loss is carried out: the removal rotates
//!   A (and what A reads, as its keysets go stale), says erase unless told otherwise, and drops
//!   the node's entries on A (`dial.0`, `caps^.0`) and on A's profile (`dial.0`).

use crate::engine::{Engine, Tx};
use crate::error::{Error, Result};
use crate::flows::{Demotion, Done};
use crate::Mutation;
use osis_base::{CommitId, CreationRecord, Holder, Role, Tid, Value, Weak};
use osis_blob::Certificates;
use osis_crdt::{Op, PathOp, PathSeg};
use osis_schema::core_types as ct;
use osis_schema::Codec;
use std::collections::BTreeSet;

/// What a pairer hands the new node over the pairing channel (spec/permissions.md §8 Pairing):
/// an offer of account `account` (the grant's certificate copy with its evidence and records, as
/// a `grant@~0` fire carries one: `Engine::grant_value`) and its trust records on A, each a
/// trusted lowering's write ID with its copy on A.
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub account: Tid,
    pub grant: Value,
    /// The copies of A's `sync.0` writes held (the rest of the new node thing's edge piece on A,
    /// spec/permissions.md §4 Key part): A's sync IDs, which the new node syncs A by.
    pub sync: Vec<Value>,
    pub trust: Vec<Trusted>,
}

/// A trust record on A (spec/permissions.md §5.1 Sides): edge write `op` of `commit`, lowering
/// `holder`, recorded as trusted, with its copy on A (`Engine::grant_value`).
#[derive(Clone, Debug, PartialEq)]
pub struct Trusted {
    pub commit: CommitId,
    pub op: u32,
    pub holder: Holder,
    pub copy: Value,
}

impl Offer {
    pub fn to_value(&self) -> Value {
        let trust = self.trust.iter().map(|t| Value::List(vec![Value::Bytes(t.commit.0.to_vec()), Value::Int(i64::from(t.op)), crate::engine::index::Rec::to(&t.holder), t.copy.clone()])).collect();
        Value::List(vec![Value::Bytes(self.account.as_bytes().to_vec()), self.grant.clone(), Value::List(self.sync.clone()), Value::List(trust)])
    }

    pub fn from_value(v: &Value) -> Option<Offer> {
        let Value::List(f) = v else { return None };
        let [Value::Bytes(a), grant, Value::List(sync), Value::List(trust)] = f.as_slice() else { return None };
        let trust = trust.iter().map(|t| {
            let Value::List(x) = t else { return None };
            let [Value::Bytes(c), Value::Int(op), holder, copy] = x.as_slice() else { return None };
            Some(Trusted { commit: CommitId(c.as_slice().try_into().ok()?), op: u32::try_from(*op).ok()?, holder: <Holder as crate::engine::index::Rec>::from(holder)?, copy: copy.clone() })
        }).collect::<Option<Vec<_>>>()?;
        Some(Offer { account: Tid::from_bytes(a.as_slice().try_into().ok()?), grant: grant.clone(), sync: sync.clone(), trust })
    }
}

impl Engine {
    /// What a new node shows the pairing node (spec/permissions.md §8 Pairing): its node thing's
    /// public key record (its record and current `keys.0` commits, spec/sync-inbox.md §1).
    pub fn node_keys(&mut self) -> Result<Certificates> {
        let me = self.core.me();
        self.holder_keys(&me)
    }

    /// Pairs node thing `node`, shown by `keys` (`node_keys`), into account `a` at `role` (admin
    /// for a node that may pair and remove, else write): this node, an admin of A, takes the
    /// public key record, writes the node's grant on A (boxing A's secrets to it, no `grant@~0`
    /// fire: the offer goes over the channel) and returns the offer to hand over.
    /// `Permission` unless this node holds admin on A; `BadInput` unless `keys` show a node thing.
    pub fn pair(&mut self, a: &Tid, node: &Tid, keys: &Certificates, role: Role) -> Result<(Offer, Done)> {
        let me = self.core.me();
        // only an admin of A pairs (spec/permissions.md §8): a grant by any other is invalid
        // wherever it lands, and would hand the new node an offer of nothing
        if self.core.role_now(&me, a) != Some(Role::Admin) {
            return Err(Error::Permission { tid: *a, needs: Role::Admin });
        }
        if role < Role::Write {
            return Err(Error::Misuse("a node holds write or admin on its account"));
        }
        self.take_holder_keys(node, keys, None)?;
        // a node thing: minted with a key, no link key (spec/sync-set.md §1)
        let is_node = self.core.created(node).is_some_and(|r| r.key().is_some() && r.link.is_none());
        if !is_node || self.current_keys(node).is_empty() {
            return Err(Error::BadInput("pairing: the keys shown are no node thing's public key record"));
        }
        let edge = ct::Edge { role, until: None, may_grant: false, retain: false, floor: None };
        let done = self.grant(a, node, &edge)?;
        let grant = *done.commits.last().ok_or(Error::Misuse("pairing wrote no grant"))?;
        // the offer goes over the channel in place of the fire the grant owes
        let (n, a2) = (*node, *a);
        self.run(|tx| crate::flows::inbox::unowe_grant(tx, n, grant, a2))?;
        let grant_v = self.grant_value(&grant, a)?.ok_or(Error::Misuse("pairing: the grant is not applied"))?;
        let ak = ct::SYNC.name();
        let syncs: Vec<CommitId> = self.core.on_thing(a).filter(|c| self.core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().enumerate().any(|(ai, x)| x.tid == *a && x.ak == ak && m.holds(ai)))).collect();
        let mut sync = Vec::new();
        for c in syncs.iter().filter(|c| **c != grant) {
            sync.extend(self.grant_value(c, a)?);
        }
        let mut trust = Vec::new();
        for (w, holder) in self.core.sides.trusted() {
            if self.core.timelines().edge_op(&w).is_none_or(|(_, _, t)| t != *a) {
                continue;
            }
            if let Some(copy) = self.grant_value(&w.0, a)? {
                trust.push(Trusted { commit: w.0, op: w.1, holder, copy });
            }
        }
        Ok((Offer { account: *a, grant: grant_v, sync, trust }, done))
    }

    /// Takes offer `o` handed over the pairing channel (spec/permissions.md §8 Pairing): records
    /// it as this node's own (the grant's copy, its evidence and records, each taken only where
    /// judged valid, `take_parts`; the copy is this node thing's edge piece on A, which carries A
    /// from then on, spec/sync-set.md §2 First entry), adopts its trust records on A, and writes a
    /// strong to A in the node root's `holds.0` and `settings^.0` naming A, so the node syncs A.
    /// `BadInput` (nothing written) unless the copy gives this node's node thing write or above
    /// on A.
    pub fn take_offer(&mut self, o: &Offer) -> Result<Done> {
        let (me, a) = (self.core.me(), o.account);
        self.take_parts(&o.grant, &a)?;
        for v in &o.sync {
            self.take_parts(v, &a)?;
        }
        if !self.core.key_holders(&a).iter().any(|(h, r)| *h == me && *r >= Role::Write) {
            return Err(Error::BadInput("pairing: the offer makes this node no node of its account"));
        }
        // trust records reach only lowerings on A (an edge write carrying a frontier the walk holds
        // there, the trust set's kind, spec/permissions.md §5.1): a pairer
        // may side for the new node in A's disputes, as it would by syncing A first, and nowhere
        // else
        let mut adopt = Vec::new();
        for t in &o.trust {
            self.take_parts(&t.copy, &a)?;
            let w = osis_perm::WriteId(t.commit, t.op);
            let lowering = self.core.timelines().role_commit(&w.0).is_some_and(|c| c.frontier.is_some());
            if lowering && self.core.timelines().edge_op(&w).is_some_and(|(_, h, on)| on == a && h == t.holder) {
                adopt.push((w, t.holder));
            }
        }
        if !adopt.is_empty() {
            self.adopt_trust(&adopt)?;
        }
        let root = self.core.node_root.ok_or(Error::Misuse("no node root"))?;
        let mut done = Done::default();
        done.add(self.run(|tx| {
            let mut m = Mutation::new();
            m.op(root, &ct::HOLDS, PathOp { path: Vec::new(), op: Op::Add(Value::Strong(a)) })?;
            m.set(root, &ct::SETTINGS, &Weak(a))?;
            let c = crate::engine::write::commit_in(tx, m)?;
            // the role the piece gives: boxes kept out for want of it open now
            crate::flows::retake(tx)?;
            Ok(c)
        })?);
        Ok(done)
    }

    /// Takes role commit copy `v` (`grant_value`) on `target`: its records, then its evidence and
    /// the copy, each kept only where judged valid (`ingest_valid`), in rounds until none more
    /// applies (an evidence commit judged on one carried after it). The copy's parts must all be
    /// role-class parts on `target`, else nothing is taken.
    fn take_parts(&mut self, v: &Value, target: &Tid) -> Result<()> {
        let Value::Map(m) = v else { return Err(Error::BadInput("pairing: a malformed copy")) };
        let bytes = |k: i64| match m.get(&Value::Int(k)) {
            Some(Value::Bytes(b)) => vec![b.clone()],
            Some(Value::List(l)) => l.iter().filter_map(|x| if let Value::Bytes(b) = x { Some(b.clone()) } else { None }).collect(),
            _ => Vec::new(),
        };
        let commit = bytes(0).into_iter().next().ok_or(Error::BadInput("pairing: a copy without its commit"))?;
        let blob = osis_commit::CommitBlob::decode(&commit).map_err(|_| Error::BadInput("pairing: a malformed copy"))?;
        if blob.parts.is_empty() || blob.parts.iter().any(|p| blob.header.aspects.get(p.ai).is_none_or(|x| x.tid != *target || !crate::flows::inbox::GRANT_PARTS.contains(&x.ak.as_str()))) {
            return Err(Error::BadInput("pairing: a copy of other than role-class parts on the account"));
        }
        let limits = osis_base::Limits::new(osis_base::format::MAX_OBJECT_DEPTH, osis_base::format::MAX_BLOB);
        let records: Vec<CreationRecord> = bytes(2).iter().filter_map(|b| osis_base::decode(b, &limits).ok()).filter_map(|v| CreationRecord::from_value(&v)).filter(|r| self.core.created(&r.tid()).is_none()).collect();
        if !records.is_empty() {
            self.learn_records(records)?;
        }
        let mut left: Vec<Vec<u8>> = bytes(1).into_iter().chain([commit]).collect();
        loop {
            let before = left.len();
            let mut rest = Vec::new();
            for c in std::mem::take(&mut left) {
                if self.ingest_valid(&c, None)?.is_none() {
                    rest.push(c);
                }
            }
            if rest.is_empty() || rest.len() == before {
                return Ok(());
            }
            left = rest;
        }
    }

    /// Removes node thing `node` from account `a` (spec/permissions.md §8 Removing): the explicit
    /// removal of its grant on A with A's rotation, saying erase unless `retain`; then the node's
    /// `dial.0` entries on A and on each of `also` (A's profile) and its `caps^.0` entry on A. Only
    /// an admin of A removes (`Permission`).
    pub fn remove_node(&mut self, a: &Tid, node: &Tid, retain: bool, also: &[Tid]) -> Result<Done> {
        let me = self.core.me();
        if self.core.role_now(&me, a) != Some(Role::Admin) {
            return Err(Error::Permission { tid: *a, needs: Role::Admin });
        }
        let mut done = self.demote(a, &Demotion { holder: *node, new: None, retain: Some(retain) })?;
        let mut m = Mutation::new();
        for t in std::iter::once(*a).chain(also.iter().copied()) {
            if self.role_on(&t) < Some(Role::Write) {
                continue;
            }
            let t2 = t;
            let n = *node;
            for k in self.read(|tx| dial_keys_by(tx, &t2, &n))? {
                m.op(t, &ct::DIAL, PathOp { path: Vec::new(), op: Op::Remove(Value::Bytes(k)) })?;
            }
        }
        let key = Codec::to_value(&Weak(*node));
        if self.get_at(a, &ct::CAPS.name(), &[PathSeg::Key(key.clone())])?.is_some() {
            m.op(*a, &ct::CAPS, PathOp { path: Vec::new(), op: Op::Remove(key) })?;
        }
        if !m.is_empty() {
            done.add(self.commit(m)?);
        }
        Ok(done)
    }
}

/// The keys of `t`'s `dial.0` entries now that commits signed as `node` put (each node keeps its
/// own entry, spec/sync-set.md §1: `publish_reach` writes it alone).
fn dial_keys_by(tx: &mut Tx<'_>, t: &Tid, node: &Tid) -> Result<BTreeSet<Vec<u8>>> {
    let ak = ct::DIAL.name();
    let mut out = BTreeSet::new();
    let ours: Vec<(CommitId, usize)> = tx.core.on_thing(t).filter_map(|c| {
        let m = tx.core.ix.commits.get(&c)?;
        (m.header.signer == *node).then_some(())?;
        let ai = m.header.aspects.iter().position(|x| x.tid == *t && x.ak == ak)?;
        m.holds(ai).then_some((c, ai))
    }).collect();
    for (c, ai) in ours {
        if let Some(Value::Map(m)) = crate::apply::held_fragment(tx, &c, ai)?.and_then(|f| f.read()) {
            out.extend(m.into_keys().filter_map(|k| if let Value::Bytes(b) = k { Some(b) } else { None }));
        }
    }
    let now = tx.state(t, &ak)?.and_then(osis_crdt::Fragment::read);
    let live: BTreeSet<Vec<u8>> = match now {
        Some(Value::Map(m)) => m.into_keys().filter_map(|k| if let Value::Bytes(b) = k { Some(b) } else { None }).collect(),
        _ => BTreeSet::new(),
    };
    Ok(out.intersection(&live).cloned().collect())
}
