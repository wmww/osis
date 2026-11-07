//! Receipts (spec/permissions.md §5.1, notes/permissions.md Revocation): what a demotion's
//! frontier lists, by commit ID only. A held commit counts as received at its meta's receipt
//! time; the receipt record (`r/` per aspect) keeps only the commits a receipts-only read
//! verified without keeping them (`Engine::record_header`). Pending and parked commits are not
//! received; snapshot frontiers and `Absorbed` are no receipts (spec/crdt.md §8).

use crate::engine::records::{self, Rd, Wr};
use crate::engine::{Engine, Tx};
use crate::error::Result;
use osis_base::format::MAX_DRIFT_MS;
use osis_base::{Ak, CommitId, CreationRecord, Tid, Ts, WallMs};
use osis_commit::{CommitBlob, Header};
use osis_crypto::VerifyingKey;
use osis_perm::DemotionScope;
use osis_schema::core_types::{Frontier, is_role_class};
use std::collections::BTreeMap;

/// The receipt record of one aspect: commits verified by header alone (receipts-only reads).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Receipt {
    /// ID -> (author, received).
    pub commits: BTreeMap<CommitId, (Tid, u64)>,
}

impl Receipt {
    fn encode(&self) -> Vec<u8> {
        let mut w = Wr::new().u32(self.commits.len() as u32);
        for (c, (a, t)) in &self.commits {
            w = w.raw(&c.0).raw(a.as_bytes()).u64(*t);
        }
        w.take()
    }

    fn decode(b: &[u8]) -> Result<Receipt> {
        let mut r = Rd::new(b);
        let mut out = Receipt::default();
        for _ in 0..r.u32()? {
            let c = CommitId(r.arr()?);
            let a = r.tid()?;
            out.commits.insert(c, (a, r.u64()?));
        }
        r.end()?;
        Ok(out)
    }
}

fn get(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak) -> Result<Receipt> {
    match tx.txn.get_local(&records::aspect_key(records::RECEIPT, tid, ak))? {
        Some(b) => Receipt::decode(&b),
        None => Ok(Receipt::default()),
    }
}

fn put(tx: &mut Tx<'_>, tid: &Tid, ak: &Ak, r: &Receipt) -> Result<()> {
    tx.put_aspect_local(records::RECEIPT, tid, ak, &r.encode())
}

/// The held snapshots of `(tid, ak)`, any validity (bodies held, or dropped and still standing in,
/// `Dropped::stands_in`): ID and `ts`.
fn held_snapshots<'a>(core: &'a crate::engine::Core, tid: &'a Tid, ak: &'a Ak) -> impl Iterator<Item = (CommitId, Ts)> + 'a {
    let k = (*tid, ak.clone());
    let held = core.ix.snapshots.get(&k).into_iter().flatten().map(|x| (x.1, x.0));
    let kept = core.ix.dropped_snapshots.get(&k).into_iter().flatten().filter_map(move |s| Some((*s, core.ix.commits.get(s)?.view.ts)));
    held.chain(kept)
}

/// Whether a held snapshot valid here is stamped after the delta's commit: a suspect flag about the
/// delta is settled while one is (spec/permissions.md §4; `retention::suspect`). Rule 5's "any
/// later snapshot": no frontier can say more, since one holding nothing of the delta's session
/// or commit is all a writer that held the delta may have left.
pub(crate) fn settled(core: &crate::engine::Core, h: &Header, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    held_snapshots(core, &a.tid, &a.ak).any(|(s, ts)| ts > h.ts && crate::apply::copies::snapshot_valid(core, &s, &a.tid, &a.ak))
}

impl Engine {
    /// Records what one commit's header shows this node received, keeping and applying nothing
    /// (a receipts-only read of a label this node does not hold, notes/node-sync.md Receipts-only
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
        // a request also counts where it names (any demotion there lists it, `frontier`): noted under
        // the thing's `roles.0`, which every demotion's scope reads
        let roles = Ak::new("roles.0").map_err(|_| crate::error::Error::Corrupt("roles.0"))?;
        let aspects: Vec<(Tid, Ak)> = h.aspects.iter().map(|a| (a.tid, a.ak.clone())).chain(h.purge.iter().map(|i| (*i.tid(), roles.clone()))).collect();
        self.run(|tx| {
            for (t, ak) in &aspects {
                let mut r = get(tx, t, ak)?;
                // a header read again keeps its first receipt time (`as_of` frontiers)
                r.commits.entry(id).or_insert((h.author, now.0));
                put(tx, t, ak, &r)?;
            }
            Ok(())
        })?;
        self.core.header_receipts.extend(aspects);
        Ok(true)
    }

    /// The receipt record of one aspect: commits verified by header alone.
    pub fn receipt(&mut self, tid: &Tid, ak: &Ak) -> Result<Receipt> {
        let (tid, ak) = (*tid, ak.clone());
        self.run(|tx| get(tx, &tid, &ak))
    }

    /// The frontier a demotion stamped now must embed (spec/permissions.md §5.1), by commit ID:
    /// per aspect the scope puts in question and per demoted node, that node's commits this
    /// node received by `as_of` (held ones at their meta's receipt time, those verified by
    /// header alone at the record's; bodies held, dropped or compacted alike), memory commits
    /// never; and, where it falls below write, its held commits acting for that thing; and every
    /// purge request whose right may rest on a role it puts in question
    /// (`retention::requests_resting_on`). This node's own receipts only. A demotion stamps it as
    /// of now; an earlier `as_of` gives the frontier as of then.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
        Ok(self.frontier_and_requests(scope, as_of)?.0)
    }

    /// `frontier_and_requests` fitted to the list bound (`fit`): what is left out of content the
    /// demoter's own addenda list instead.
    pub(crate) fn frontier_fitted(&mut self, scope: &DemotionScope, as_of: WallMs, keep: &std::collections::BTreeSet<CommitId>) -> Result<Frontier> {
        let (mut f, content, requests) = self.frontier_and_requests(scope, as_of)?;
        f.commits.extend(keep.iter().copied());
        let out: Vec<CommitId> = content.into_iter().chain(requests).filter(|c| !keep.contains(c)).collect();
        fit(&mut f, &out, self.core.list_bound);
        Ok(f)
    }

    /// `frontier`, the plain-content commits it lists (what addenda may list, received last
    /// first) and the requests it lists (received last first): what `fit` leaves out when it is
    /// over the list bound, in that order.
    pub(crate) fn frontier_and_requests(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<(Frontier, Vec<CommitId>, Vec<CommitId>)> {
        // the aspects a fall below admin puts in question: role-class and admin-only (`^`) ones
        let admin_class = |ak: &Ak| is_role_class(ak.as_str()) || ak.admin();
        let mut aspects: Vec<(Tid, Tid, Ak)> = Vec::new();
        for (node, things) in &scope.roles {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)).filter(|((_, ak), _)| admin_class(ak)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        for (node, things) in &scope.content {
            for ((t, ak), _) in things.iter().flat_map(|t| self.core.aspects_of(t)) {
                aspects.push((*node, *t, ak.clone()));
            }
        }
        // aspects known only from headers (receipts-only reads): this node cannot tell which
        // the scope reaches, so each demoted node's commits on them are listed; one where its
        // class did not fall is never consulted (spec/permissions.md §5.1)
        for (tid, ak) in &self.core.header_receipts {
            let admin = admin_class(ak);
            for node in scope.content.keys().chain(scope.roles.keys().filter(|_| admin)) {
                aspects.push((*node, *tid, ak.clone()));
            }
        }
        aspects.sort();
        aspects.dedup();
        self.run(|tx| {
            let mut f = Frontier::default();
            // (received, commit) of the plain-content commits: those addenda may list
            let mut content: Vec<(std::cmp::Reverse<u64>, CommitId)> = Vec::new();
            for (node, t, ak) in aspects.iter().cloned() {
                let plain = !admin_class(&ak);
                for (id, (a, at)) in get(tx, &t, &ak)?.commits {
                    if a == node && at <= as_of.0 {
                        f.commits.insert(id);
                        if plain {
                            content.push((std::cmp::Reverse(at), id));
                        }
                    }
                }
                for c in tx.core.durable_on(&(t, ak.clone())) {
                    let Some(m) = tx.core.ix.commits.get(&c) else { continue };
                    if m.view.author == node && m.received.0 <= as_of.0 {
                        f.commits.insert(c);
                        if plain && m.view.kind != osis_commit::Kind::Role && !m.view.purges {
                            content.push((std::cmp::Reverse(m.received.0), c));
                        }
                    }
                }
            }
            // a fall below write on M puts in question every delta of the node's commits acting
            // for M (`validity::acts_for`)
            for (node, things) in &scope.content {
                for t in things {
                    for c in tx.core.ix.by_actor.get(&(*t, *node)).into_iter().flatten() {
                        let Some(m) = tx.core.ix.commits.get(c) else { continue };
                        if !m.view.memory && m.received.0 <= as_of.0 {
                            f.commits.insert(*c);
                            if m.view.kind != osis_commit::Kind::Role && !m.view.purges {
                                content.push((std::cmp::Reverse(m.received.0), *c));
                            }
                        }
                    }
                }
            }
            // a request's right ends with the role unless the frontier lists it (spec/permissions.md
            // §6): one this node received stays rightful, whatever became of its body and on
            // whatever aspect its own delta lies
            let mut requests = Vec::new();
            for (node, things) in &scope.roles {
                for pc in crate::retention::requests_resting_on(tx.core, node, things) {
                    let Some(m) = tx.core.ix.commits.get(&pc) else { continue };
                    if m.received.0 <= as_of.0 {
                        f.commits.insert(pc);
                        requests.push((std::cmp::Reverse(m.received.0), pc));
                    }
                }
            }
            requests.sort();
            requests.dedup();
            content.sort();
            content.dedup();
            Ok((f, content.into_iter().map(|x| x.1).collect(), requests.into_iter().map(|x| x.1).collect()))
        })
    }
}

/// Leaves out of frontier `f` as many of `out` (in order) as it takes to fit `max` encoded bytes
/// (spec/permissions.md §5.1): first the plain-content commits received last, which the
/// demoter's own addenda list instead (`flows::addenda`), then the purge requests received last,
/// each losing its right, so that requests never make a role holder impossible to demote (a
/// hostile holder's flood is what it received last). What is over `max` without them stays over:
/// `build` refuses it.
pub(crate) fn fit(f: &mut Frontier, out: &[CommitId], max: usize) {
    let size = |f: &Frontier| osis_base::encode(&osis_schema::Codec::to_value(f)).len();
    let each = osis_base::encode(&osis_base::Value::bytes(&[0u8; 32])).len();
    let mut left = out.iter();
    let mut now = size(f);
    while now > max {
        for _ in 0..(now - max).div_ceil(each) {
            let Some(c) = left.next() else { return };
            f.commits.remove(c);
        }
        now = size(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // spec/permissions.md §5.1: over the bound the requests received last go first, never another
    // listed commit; with none left it stays over, for `build` to refuse.
    #[test]
    fn frontier_over_the_bound_leaves_out_requests_spec_perm_5_1() {
        let id = |i: u32| {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_be_bytes());
            CommitId(b)
        };
        let size = |f: &Frontier| osis_base::encode(&osis_schema::Codec::to_value(f)).len();
        let all = Frontier { commits: (0..2000).map(id).collect() };
        let requests: Vec<CommitId> = (1000..2000).rev().map(id).collect();
        let mut f = all.clone();
        fit(&mut f, &requests, size(&all));
        assert_eq!(f, all, "it fits");
        let max = size(&Frontier { commits: (0..1500).map(id).collect() });
        fit(&mut f, &requests, max);
        assert!(size(&f) <= max);
        assert_eq!(f.commits, (0..1500).map(id).collect::<BTreeSet<_>>(), "the oldest requests stay");
        fit(&mut f, &requests, 100);
        assert_eq!(f.commits, (0..1000).map(id).collect::<BTreeSet<_>>(), "only requests go");
    }
}
