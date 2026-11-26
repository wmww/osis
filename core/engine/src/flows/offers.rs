//! Grants and keys handed over by hand (spec/sync-inbox.md §5 Grant from outside: an offer
//! carried over a channel its users provide in place of a `grant@~0` fire; spec/permissions.md
//! §8 Pairing is one use): `Engine::offer` builds the offer of a holder's grant, `take_offer`
//! takes one; a holder's public key record shown by hand is `holder_keys`/`take_holder_keys`.
//!
//! Invariants (security):
//! - What an offer hands over gives its taker nothing it could not get by syncing the target:
//!   each of its edge pieces is a copy of role-class parts on the target alone, taken only where
//!   judged valid with its evidence and records (`Engine::take_edge_piece`). Its trust records
//!   reach only lowerings on the target it carries (`take_offer`). An offer of a grant its
//!   writer could not make gives no role.

use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::flows::inbox::EdgePiece;
use crate::flows::Done;
use crate::sync_ids::Cut;
use osis_base::{CommitId, Holder, Tid, Value};
use osis_schema::core_types as ct;

/// An offer of `target` handed over by hand (`Pieces`).
#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    pub target: Tid,
    pub pieces: Pieces,
}

/// What an offer carries: to a holder reading or above, the grant's edge piece, as a `grant@~0`
/// fire carries one (`EdgePiece`), the pieces of the target's `sync.0` writes held that its
/// evidence does not carry (the rest of the holder's edge piece on it, spec/permissions.md §4 Key
/// part: its sync IDs, which the taker syncs it by), and the offering node's trust records on the
/// target, each a trusted lowering's write ID with its piece on it; to a holder of sync alone,
/// the sync copies of the grant and of those `sync.0` writes (`SyncCopyPlaintext`, spec/wire.md
/// §4), no header, evidence or trust record.
#[derive(Clone, Debug, PartialEq)]
pub enum Pieces {
    Whole { grant: EdgePiece, sync: Vec<EdgePiece>, trust: Vec<Trusted> },
    SyncAlone(Vec<Vec<u8>>),
}

/// A trust record on the target (spec/permissions.md §5.1 Sides): edge write `op` of `commit`,
/// lowering `holder`, recorded as trusted, with its piece on the target (`Engine::edge_piece`).
#[derive(Clone, Debug, PartialEq)]
pub struct Trusted {
    pub commit: CommitId,
    pub op: u32,
    pub holder: Holder,
    pub copy: EdgePiece,
}

impl Offer {
    /// `[target, grant, [sync], [trust]]`, or `[target, [copy]]` for a holder of sync alone.
    pub fn to_value(&self) -> Value {
        let target = Value::Bytes(self.target.as_bytes().to_vec());
        match &self.pieces {
            Pieces::Whole { grant, sync, trust } => {
                let trust = trust.iter().map(|t| Value::List(vec![Value::Bytes(t.commit.0.to_vec()), Value::Int(i64::from(t.op)), crate::engine::index::Rec::to(&t.holder), t.copy.to_value()])).collect();
                Value::List(vec![target, grant.to_value(), Value::List(sync.iter().map(EdgePiece::to_value).collect()), Value::List(trust)])
            }
            Pieces::SyncAlone(copies) => Value::List(vec![target, Value::List(copies.iter().map(|c| Value::Bytes(c.clone())).collect())]),
        }
    }

    pub fn from_value(v: &Value) -> Option<Offer> {
        let Value::List(f) = v else { return None };
        if let [Value::Bytes(a), Value::List(copies)] = f.as_slice() {
            let copies = copies.iter().map(|c| if let Value::Bytes(b) = c { Some(b.clone()) } else { None }).collect::<Option<Vec<_>>>()?;
            return Some(Offer { target: Tid::from_bytes(a.as_slice().try_into().ok()?), pieces: Pieces::SyncAlone(copies) });
        }
        let [Value::Bytes(a), grant, Value::List(sync), Value::List(trust)] = f.as_slice() else { return None };
        let trust = trust.iter().map(|t| {
            let Value::List(x) = t else { return None };
            let [Value::Bytes(c), Value::Int(op), holder, copy] = x.as_slice() else { return None };
            Some(Trusted { commit: CommitId(c.as_slice().try_into().ok()?), op: u32::try_from(*op).ok()?, holder: <Holder as crate::engine::index::Rec>::from(holder)?, copy: EdgePiece::from_value(copy)? })
        }).collect::<Option<Vec<_>>>()?;
        let sync = sync.iter().map(EdgePiece::from_value).collect::<Option<Vec<_>>>()?;
        Some(Offer { target: Tid::from_bytes(a.as_slice().try_into().ok()?), pieces: Pieces::Whole { grant: EdgePiece::from_value(grant)?, sync, trust } })
    }
}

impl Engine {
    /// The offer of `holder`'s grant on `t` to hand over by hand (spec/sync-inbox.md §5): the
    /// piece of the newest edge write held naming it there, with `t`'s `sync.0` pieces and this
    /// node's trust records on `t`. The grant's `grant@~0` fire is owed no more: the offer goes in
    /// its place. `BadInput` while no edge write naming `holder` on `t` is held here.
    pub fn offer(&mut self, t: &Tid, holder: &Tid) -> Result<Offer> {
        let h = Holder::Thing(*holder);
        let tl = self.core.timelines();
        let grant = self.core.on_thing(t).filter_map(|c| tl.role_commit(&c)).filter(|rc| rc.ops.iter().any(|o| o.target == *t && o.holder == h && o.edge.is_some())).max_by_key(|rc| rc.ts).map(|rc| rc.id);
        let grant = grant.ok_or(Error::BadInput("no grant of the holder on the thing to offer"))?;
        let (n, t2) = (*holder, *t);
        self.run(|tx| crate::flows::inbox::unowe_grant(tx, n, grant, t2))?;
        let ak = ct::SYNC.name();
        let syncs: Vec<CommitId> = self.core.on_thing(t).filter(|c| self.core.ix.commits.get(c).is_some_and(|m| m.header.aspects.iter().enumerate().any(|(ai, x)| x.tid == *t && x.ak == ak && m.holds(ai)))).collect();
        // a holder of sync alone: sync copies alone, no header, evidence or trust record
        // (spec/wire.md §4 Sync copy)
        if self.core.sync_alone_on(holder, t) {
            let mut copies = Vec::new();
            for c in std::iter::once(grant).chain(syncs.into_iter().filter(|c| *c != grant)) {
                if let Some((copy, _)) = self.sync_copy(&c, t, holder)? {
                    copies.push(copy.encode());
                }
            }
            return Ok(Offer { target: *t, pieces: Pieces::SyncAlone(copies) });
        }
        let grant_v = self.edge_piece(&grant, t, Cut::EdgePiece(*holder))?.ok_or(Error::BadInput("no grant of the holder on the thing to offer"))?;
        // each copy once: a `sync.0` write the grant's evidence carries already (the target's
        // first, at least) is not handed over again
        let mut sync = Vec::new();
        for c in syncs.iter().filter(|c| **c != grant) {
            sync.extend(self.edge_piece(c, t, Cut::EdgePiece(*holder))?.filter(|p| !grant_v.evidence.contains(&p.copy)));
        }
        let mut trust = Vec::new();
        for (w, holder) in self.core.sides.trusted() {
            if self.core.timelines().edge_op(&w).is_none_or(|(_, _, on)| on != *t) {
                continue;
            }
            if let Some(copy) = self.edge_piece(&w.0, t, Cut::Evidence { step: false })? {
                trust.push(Trusted { commit: w.0, op: w.1, holder, copy });
            }
        }
        Ok(Offer { target: *t, pieces: Pieces::Whole { grant: grant_v, sync, trust } })
    }

    /// Takes offer `o` handed over by hand (spec/sync-inbox.md §5): the grant's copy, its
    /// evidence and records, each taken only where judged valid (`take_parts`; the copy is an own
    /// thing's edge piece on the target, which carries it from then on, spec/sync-set.md §2 First
    /// entry), and its trust records on the target; then a strong to the target in `holder`'s
    /// `holds.0` (a thing this node holds, or its node root), so this node holds it.
    /// `BadInput` unless it gives a role on the target to this node's node thing or a thing it
    /// may write; refused, what it brought goes unless something held needs it.
    pub fn take_offer(&mut self, o: &Offer, holder: &Tid) -> Result<Done> {
        let t = o.target;
        let me = self.core.tid();
        let mine = |e: &Engine, h: &Tid| *h == me || e.core.role_now(&me, h) >= Some(osis_base::Role::Write);
        let trust = match &o.pieces {
            Pieces::Whole { grant, sync, trust } => {
                // taken, then judged: refused, what it brought goes as a release's does
                // (`settle_due`: what nothing held needs), so a hander makes this node keep
                // nothing for an offer giving nothing
                let mut r = self.take_parts(grant, &t);
                for p in sync {
                    r = r.and_then(|()| self.take_parts(p, &t));
                }
                // the offer is to a node of its holder (spec/sync-inbox.md §5 By hand): the node
                // thing, or a thing it may write (an account), as `offered_to` reads a fire's
                let r = r.and_then(|()| if self.core.key_holders(&t).iter().any(|(h, _)| mine(self, h)) { Ok(()) } else { Err(Error::BadInput("the offer gives this node no role")) });
                if let Err(e) = r {
                    let brought = std::iter::once(grant).chain(sync).flat_map(EdgePiece::things).chain([t]).collect();
                    self.settle_due(&brought)?;
                    return Err(e);
                }
                trust.as_slice()
            }
            // sync copies of a holder of this node's, each taken under its holder (kept unread
            // here: a box counts only by a step bearing its secret, `sync_ids::unread`)
            Pieces::SyncAlone(copies) => {
                let Some((x, h)) = copies.iter().find_map(|c| crate::sync_ids::unread::holder_of(c)) else { return Err(Error::BadInput("an offer boxing no holder")) };
                if x != t || !mine(self, &h) {
                    return Err(Error::BadInput("an offer's sync copy of another thing or holder"));
                }
                // each copy's row under its content key; a refused offer's new rows go (a hander
                // makes this node keep nothing for an offer giving nothing)
                let mut new = Vec::new();
                let mut bad = None;
                let mut taken = Vec::new();
                for c in copies {
                    let b = osis_base::BlobId(crate::sync_ids::unread::content_key(c));
                    taken.push(b);
                    let fresh = !self.core.ix.sync_copy_on.contains_key(&b);
                    let ok = self.take_sync_copy(&h, &b, c, false)?;
                    if fresh && self.core.ix.sync_copy_on.contains_key(&b) {
                        new.push(b);
                    }
                    if !ok || self.core.ix.sync_copy_on.get(&b) != Some(&t) {
                        bad = Some(Error::BadInput("an offer's sync copy"));
                        break;
                    }
                }
                // a role is a counted box to the holder (`Unread::holders`): one of the offer's
                let un = self.core.unread(&t);
                let boxed = |b: &osis_base::BlobId| self.core.ix.sync_copies.get(&t).and_then(|m| m.get(b).cloned()).is_some_and(|c| !c.boxes.is_empty());
                if bad.is_none() && !taken.iter().any(|b| un.counted.contains(b) && boxed(b)) {
                    bad = Some(Error::BadInput("the offer gives this node no role"));
                }
                if let Some(e) = bad {
                    for b in &new {
                        self.unnamed_copy(b)?;
                    }
                    return Err(e);
                }
                &[]
            }
        };
        // trust records reach only lowerings on the target (an edge write carrying a frontier
        // the walk holds there, the trust set's kind, spec/permissions.md §5.1): an offering node
        // may side for the taker in the target's disputes, as it would by syncing it first, and
        // nowhere else
        let mut adopt = Vec::new();
        for x in trust {
            self.take_parts(&x.copy, &t)?;
            let w = osis_perm::WriteId(x.commit, x.op);
            let lowering = self.core.timelines().role_commit(&w.0).is_some_and(|c| c.frontier.is_some());
            if lowering && self.core.timelines().edge_op(&w).is_some_and(|(_, h, on)| on == t && h == x.holder) {
                adopt.push((w, x.holder));
            }
        }
        if !adopt.is_empty() {
            self.adopt_trust(&adopt)?;
        }
        let h = *holder;
        let mut done = Done::default();
        done.add(self.run(|tx| {
            let mut m = crate::Mutation::new();
            m.op(h, &ct::HOLDS, osis_crdt::PathOp { path: Vec::new(), op: osis_crdt::Op::Add(Value::Strong(t)) })?;
            let c = crate::engine::write::commit_in(tx, m)?;
            // the role the piece gives: boxes kept out for want of it open now
            crate::flows::retake(tx)?;
            Ok(c)
        })?);
        Ok(done)
    }

    /// Takes edge piece `p` on `target` (`take_edge_piece`), carried by nothing: `BadInput`
    /// (nothing taken) unless its copy is of role-class parts on `target` alone.
    fn take_parts(&mut self, p: &EdgePiece, target: &Tid) -> Result<()> {
        let on = osis_commit::CommitBlob::decode(&p.copy).ok().and_then(|b| EdgePiece::target(&b));
        if on != Some(*target) {
            return Err(Error::BadInput("an offer's copy of other than role-class parts on its thing"));
        }
        self.take_edge_piece(p, None)?;
        Ok(())
    }
}
