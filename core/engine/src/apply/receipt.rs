//! The receipt record (spec/permissions.md §5.1, notes/permissions.md Revocation): per aspect
//! and author node, the counter ranges received with their receipt time, plus commit-form
//! commits by ID. Adjacent ranges merge with the later time (a coarser record only shrinks a
//! frontier). Pending and parked commits are not received. Held snapshots' frontiers (`[1,
//! ctr]`) and `Absorbed` (spec/crdt.md §8) are not recorded: `received` adds those of the
//! snapshots valid now, at their receipt time, as far as held headers justify them, so a snapshot turning invalid takes them back
//! whatever the arrival order (spec/permissions.md §5.2); a snapshot dropped other than as
//! covered keeps them in its record (`Dropped::gives`, spec/commits.md §5). Demotions read it "as
//! of T" for their frontier.

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, CommitId, CreationRecord, Tid, Ts, WallMs};
use osis_commit::{CommitBlob, Decoded, Form, Header};
use osis_crypto::VerifyingKey;
use osis_crdt::Frontiers;
use osis_perm::DemotionScope;
use osis_schema::core_types::{Frontier, is_membership_class};
use osis_store::Shred;
use std::collections::{BTreeMap, BTreeSet};

/// Receipt-time granularity (local policy): adjacent ranges received within one bucket merge.
pub const GRANULARITY_MS: u64 = 60_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// node -> sorted disjoint `(lo, hi, received)`.
    pub nodes: BTreeMap<Tid, Vec<(u64, u64, u64)>>,
    /// commit-form commits: ID -> (author, received).
    pub commits: BTreeMap<CommitId, (Tid, u64)>,
}

impl Receipt {
    pub fn add(&mut self, node: Tid, lo: u64, hi: u64, t: u64) {
        if lo >= hi {
            return;
        }
        let v = self.nodes.entry(node).or_default();
        // counters already held keep their earlier receipt time
        let mut pieces = vec![(lo, hi)];
        for (a, b, _) in v.iter() {
            pieces = pieces.into_iter().flat_map(|(x, y)| [(x, y.min(*a)), (x.max(*b), y)]).filter(|(x, y)| x < y).collect();
        }
        v.extend(pieces.into_iter().map(|(x, y)| (x, y, t)));
        v.sort_unstable();
        let mut out: Vec<(u64, u64, u64)> = Vec::with_capacity(v.len());
        for (a, b, t) in v.drain(..) {
            match out.last_mut() {
                Some(l) if a == l.1 && l.2 / GRANULARITY_MS == t / GRANULARITY_MS => {
                    l.1 = b;
                    l.2 = l.2.max(t);
                }
                _ => out.push((a, b, t)),
            }
        }
        *v = out;
    }

    /// Last counter (inclusive) of `node` received contiguously from 1 by time `t`; 0 if none.
    pub fn contiguous(&self, node: &Tid, t: u64) -> u64 {
        let mut next = 1u64;
        for (lo, hi, at) in self.nodes.get(node).into_iter().flatten() {
            if *lo > next || *at > t {
                break;
            }
            next = next.max(*hi);
        }
        next - 1
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = Wr::new().u32(self.nodes.len() as u32);
        for (n, v) in &self.nodes {
            w = w.raw(n.as_bytes()).u32(v.len() as u32);
            for (a, b, t) in v {
                w = w.u64(*a).u64(*b).u64(*t);
            }
        }
        w = w.u32(self.commits.len() as u32);
        for (c, (a, t)) in &self.commits {
            w = w.raw(&c.0).raw(a.as_bytes()).u64(*t);
        }
        w.take()
    }

    fn decode(b: &[u8]) -> Result<Receipt> {
        let mut r = Rd::new(b);
        let mut out = Receipt::default();
        for _ in 0..r.u32()? {
            let n = r.tid()?;
            let mut v = Vec::new();
            for _ in 0..r.u32()? {
                v.push((r.u64()?, r.u64()?, r.u64()?));
            }
            out.nodes.insert(n, v);
        }
        for _ in 0..r.u32()? {
            let c = CommitId(r.arr()?);
            let a = r.tid()?;
            out.commits.insert(c, (a, r.u64()?));
        }
        r.end()?;
        Ok(out)
    }
}

pub(crate) fn get(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Receipt> {
    match tx.txn.get_local(&records::aspect_key(records::RECEIPT, tid, ak))? {
        Some(b) => Receipt::decode(&b),
        None => Ok(Receipt::default()),
    }
}

fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &Receipt) -> Result<()> {
    tx.core.waits.wake(tid, ak);
    Ok(tx.txn.put_local(&records::aspect_key(records::RECEIPT, tid, ak), &r.encode(), Shred::No)?)
}

/// The held snapshots of `(tid, ak)`, any validity (bodies held, or dropped with their frontiers
/// kept, `Dropped::gives`): ID, `ts`, frontiers, `Absorbed`.
fn held_snapshots<'a>(core: &'a crate::engine::Core, tid: &'a Tid, ak: &'a Ak) -> impl Iterator<Item = (CommitId, Ts, &'a Frontiers, &'a [(CommitId, Tid)])> + 'a {
    let k = (*tid, ak.clone());
    let held = core.ix.snapshots.get(&k).into_iter().flatten().map(|(ts, s, fr, abs)| (*s, *ts, fr, abs.as_slice()));
    let kept = core.ix.dropped_snapshots.get(&k).into_iter().flatten().filter_map(move |s| {
        let m = core.ix.commits.get(s)?;
        let ai = m.view.aspects.iter().position(|a| a.tid == *tid && a.ak == *ak)?;
        let (fr, abs) = m.dropped.get(&ai)?.gives.as_ref()?;
        Some((*s, m.view.ts, fr, abs.as_slice()))
    });
    held.chain(kept)
}

/// The held snapshots of `(tid, ak)` valid now.
fn valid_snapshots<'a>(core: &'a crate::engine::Core, tid: &'a Tid, ak: &'a Ak) -> impl Iterator<Item = (CommitId, Ts, &'a Frontiers, &'a [(CommitId, Tid)])> + 'a {
    held_snapshots(core, tid, ak).filter(move |s| super::validity::snapshot_valid(core, &s.0, tid, ak))
}

/// What this node had received of `(tid, ak)` by `as_of`: the record's entries received by
/// then, plus what the held snapshots valid now that it received by then justify (an invalid
/// one's count as not received, spec/permissions.md §5.2). A snapshot's frontier `[1, ctr]` for
/// node N counts only on the counters of N's node-form commits on the aspect whose header this
/// node holds, and its `Absorbed` only the listed commits with a delta of the aspect whose header
/// it holds, by that header's author (spec/crdt.md §8: a claim never covers a write that does
/// not exist yet), each from the later of the snapshot part's and the header's receipt. Cost:
/// the aspect's held and kept snapshots plus the claimed nodes' commits on it.
pub(crate) fn received(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, as_of: u64) -> Result<Receipt> {
    let mut r = get(tx, tid, ak)?;
    for v in r.nodes.values_mut() {
        v.retain(|x| x.2 <= as_of);
    }
    r.commits.retain(|_, x| x.1 <= as_of);
    let core = &*tx.core;
    // valid ones received by `as_of`, at their part's receipt time (`record`; a late part's,
    // not its header's)
    let mut claims: BTreeMap<Tid, Vec<(u64, u64)>> = BTreeMap::new();
    let mut absorbed: Vec<(CommitId, u64)> = Vec::new();
    for (s, _, fr, abs) in valid_snapshots(core, tid, ak) {
        let Some(at) = r.commits.get(&s).map(|c| c.1) else { continue };
        for (n, c) in &fr.nodes {
            claims.entry(*n).or_default().push((*c, at));
        }
        absorbed.extend(abs.iter().map(|(c, _)| (*c, at)));
    }
    for (c, at) in absorbed {
        let Some(m) = core.ix.commits.get(&c) else { continue };
        let t = at.max(m.received.0);
        if t <= as_of && m.view.aspects.iter().any(|a| a.tid == *tid && a.ak == *ak) {
            let e = r.commits.entry(c).or_insert((m.view.author, t));
            e.1 = e.1.min(t);
        }
    }
    // per node: each held range's counters at or below a claim, from the earliest claim
    // reaching them (suffix minimum of claim times by counter) or the header, the later
    let mut adds = Vec::new();
    for (n, mut cl) in claims {
        cl.sort_unstable();
        let mut m = u64::MAX;
        let mut first: Vec<u64> = cl.iter().rev().map(|x| { m = m.min(x.1); m }).collect();
        first.reverse();
        let top = cl.last().map_or(0, |x| x.0);
        let Some(rs) = core.ix.ranges.get(&(*tid, ak.clone(), n)) else { continue };
        for (lo, (hi, c)) in rs.range(..=top) {
            let Some(hr) = core.ix.commits.get(c).map(|m| m.received.0) else { continue };
            let mut x = *lo;
            while x < *hi {
                let i = cl.partition_point(|e| e.0 < x);
                let (Some((ctr, _)), Some(t0)) = (cl.get(i), first.get(i)) else { break };
                let end = (*hi).min(ctr.saturating_add(1));
                let t = (*t0).max(hr);
                if t <= as_of {
                    adds.push((n, x, end, t));
                }
                x = end;
            }
        }
    }
    for (n, lo, hi, t) in adds {
        r.add(n, lo, hi, t);
    }
    Ok(r)
}

/// Whether a held snapshot of `(tid, ak)`, any validity, stamped after commit `id` lists its
/// delta on the aspect as included: its frontier reaches a node-form commit's counters, or its
/// `Absorbed` names the commit (atomic apply: the missing delta counts as dropped,
/// spec/commits.md §4; a snapshot never absorbed a commit stamped after it, spec/crdt.md §2.2).
pub(crate) fn listed(core: &crate::engine::Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    let node_form = h.form == Form::Node && h.kind.has_own_writes();
    held_snapshots(core, &a.tid, &a.ak).any(|(_, ts, fr, abs)| {
        ts > h.ts && if node_form { fr.nodes.get(&h.author).is_some_and(|c| *c >= a.hi.saturating_sub(1)) } else { abs.iter().any(|x| x.0 == *id) }
    })
}

/// Records what an applied commit's held parts gave this node (a snapshot: its ID; what it
/// carries counts through `received`).
pub(crate) fn record(tx: &mut Tx<'_>, h: &Header, id: &CommitId, parts: &[(usize, usize, Decoded)], received: WallMs) -> Result<()> {
    let held: BTreeSet<usize> = parts.iter().map(|p| p.0).collect();
    for ai in held {
        let Some(a) = h.aspects.get(ai) else { continue };
        let mut r = get(tx, &a.tid, &a.ak)?;
        if h.kind.has_own_writes() {
            match h.form {
                Form::Node => r.add(h.author, a.lo, a.hi, received.0),
                Form::Commit => {
                    r.commits.insert(*id, (h.author, received.0));
                }
            }
        } else {
            // imports count by commit ID (spec/permissions.md §5.1 frontier coverage)
            r.commits.insert(*id, (h.author, received.0));
        }
        put(tx, &a.tid, &a.ak, &r)?;
    }
    Ok(())
}

impl Engine {
    /// Records what one commit's header shows this node received, keeping and applying nothing
    /// (a receipts-only read of a label this node does not hold, notes/sync.md Receipts-only
    /// reads): every aspect the header lists, received now (spec/permissions.md §5.1: received
    /// means its header decrypted and its signature verified). Those aspects join
    /// `Core::header_receipts`, which demotions' frontiers read. False, recording nothing, when
    /// the header cannot be verified here: lists by link (their pages are not fetched), an
    /// author whose creation record is not held, a bad signature or header, an ephemeral
    /// commit (a frontier lists none, spec/permissions.md §5.2), a `ts` past the drift bound
    /// (it would wait, spec/crdt.md §2.2).
    pub fn record_header(&mut self, c: &CommitBlob) -> Result<bool> {
        let h = &c.header;
        if !h.is_resolved() || h.ephemeral.is_some() {
            return Ok(false);
        }
        let Some(CreationRecord::KeyActor { public_key, .. }) = self.core.created(&h.author) else { return Ok(false) };
        let Ok(vk) = VerifyingKey::from_slice(public_key) else { return Ok(false) };
        let id = c.id();
        let now = self.now();
        if osis_commit::verify_signature(&id, &c.signature, &vk).is_err() || h.validate().is_err() || h.ts.wall_ms().0 > now.0.saturating_add(MAX_DRIFT_MS) {
            return Ok(false);
        }
        // by commit ID, never by counters: this node keeps none of it, so a commit its author
        // later signs on the same counters (overlap voids both, spec/commits.md §4) would meet
        // no holder of this one and be covered (spec/permissions.md §5.1)
        self.run(|tx| {
            for a in &h.aspects {
                let mut r = get(tx, &a.tid, &a.ak)?;
                r.commits.insert(id, (h.author, now.0));
                put(tx, &a.tid, &a.ak, &r)?;
            }
            Ok(())
        })?;
        self.core.header_receipts.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
        Ok(true)
    }

    /// What this node received of one aspect, held valid snapshots' frontiers included.
    pub fn receipt(&mut self, tid: &Tid, ak: &Ak) -> Result<Receipt> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| received(tx, &tid, &ak, u64::MAX))
    }

    /// The frontier a demotion stamped now must embed (spec/permissions.md §5.1): per aspect the
    /// scope puts in question and per demoted node, the last counter received contiguously as
    /// of `as_of`, plus that node's commit-form commits received by then. This node's own
    /// receipts only; `as_of` earlier than now gives a backdated revoke's frontier.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
        let mut aspects: Vec<(Tid, Tid, Ak)> = Vec::new();
        for (node, things) in &scope.membership {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)).filter(|((_, ak), _)| is_membership_class(ak.as_str())) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        for (node, things) in &scope.content {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        // aspects known only from headers (receipts-only reads): this node cannot tell which
        // the scope reaches, so each demoted node's commits on them are listed by ID; one
        // where its class did not fall is never consulted (spec/permissions.md §5.1)
        for (tid, ak) in &self.core.header_receipts {
            let membership = is_membership_class(ak.as_str());
            for node in scope.content.keys().chain(scope.membership.keys().filter(|_| membership)) {
                aspects.push((*node, *tid, ak.clone()));
            }
        }
        aspects.sort();
        aspects.dedup();
        self.run(|tx| {
            let mut f = Frontier::default();
            for (node, t, ak) in aspects {
                let r = received(tx, &t, &ak, as_of.0)?;
                let c = r.contiguous(&node, as_of.0);
                if c > 0 {
                    f.writes.entry(t).or_default().entry(ak.as_str().to_string()).or_default().insert(node, c);
                }
                for (id, (a, _)) in &r.commits {
                    if *a == node {
                        f.commits.insert(*id);
                    }
                }
            }
            Ok(f)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec/permissions.md §5.1: a frontier covers what was received contiguously as of T.
    // spec/permissions.md §5.1 (frontier received)
    #[test]
    fn contiguous_as_of_spec_5_1() {
        let n = Tid::from_bytes([1; 15]);
        let mut r = Receipt::default();
        r.add(n, 1, 3, 10);
        r.add(n, 5, 6, 11);
        assert_eq!(r.contiguous(&n, 100), 2);
        r.add(n, 3, 5, 200_000);
        assert_eq!(r.contiguous(&n, 300_000), 5);
        assert_eq!(r.contiguous(&n, 15), 2);
        // a repeat keeps the earlier time
        r.add(n, 1, 3, 400_000);
        assert_eq!(r.contiguous(&n, 15), 2);
        assert_eq!(Receipt::decode(&r.encode()).unwrap(), r);
    }
}
