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
use osis_crdt::Frontiers;
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

/// The held snapshots of `(tid, ak)`, any validity (bodies held, or dropped with their frontiers
/// kept, `Dropped::gives`): ID, `ts`, frontiers, `Absorbed`.
fn held_snapshots<'a>(core: &'a crate::engine::Core, tid: &'a Tid, ak: &'a Ak) -> impl Iterator<Item = (CommitId, Ts, &'a Frontiers, &'a [(CommitId, Tid)])> + 'a {
    let k = (*tid, ak.clone());
    let held = core.ix.snapshots.get(&k).into_iter().flatten().map(|(ts, s, fr, abs)| (*s, *ts, fr, abs.as_slice()));
    let kept = core.ix.dropped_snapshots.get(&k).into_iter().flatten().filter_map(move |s| {
        let m = core.ix.commits.get(s)?;
        let ai = m.aspect(tid, ak)?;
        let (fr, abs) = m.dropped.get(&ai)?.gives.as_ref()?;
        Some((*s, m.view.ts, fr, abs.as_slice()))
    });
    held.chain(kept)
}

/// Whether this node's compaction could drop part `(tid, ak)` of held commit `c` now, or
/// already dropped it as covered, under snapshots received by `as_of` (spec/permissions.md §5.1,
/// spec/commits.md §5): dropped as covered with every coverer received by then
/// (`retention::coverers`, coverers dropped in turn included), or held, droppable here now
/// (`retention::drop_from`: this node may purge it and its keep-at-least bound is `MAX_DRIFT`
/// past, as node-sync's `drop_covered` judges) and covered by a held valid snapshot stamped after
/// it, received by then, whose actor holds the right over it (of two covered-equal snapshots only the lower ID stays, as there).
/// A demoter leaves a commit out of its frontier only when each of its parts in question is
/// such: the covering snapshot vouches for its live writes (spec/permissions.md §5.2), and its
/// dead writes are what compaction erases anyway; a kept body's history stays valid. A coverer
/// received after `as_of` (a backdated revoke) would not be listed if the demoted node wrote
/// it, so it would vouch for nothing after the demotion.
fn droppable_here(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, as_of: WallMs) -> Result<bool> {
    let by_then = |core: &crate::engine::Core, s: &CommitId| core.ix.commits.get(s).is_some_and(|m| m.received.0 <= as_of.0);
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(false) };
    if let Some(d) = m.dropped.get(&ai) {
        return Ok(d.as_cover && crate::retention::coverers(tx.core, c, ai).iter().all(|s| by_then(tx.core, s)));
    }
    if m.missing.contains(&ai) {
        return Ok(false);
    }
    let (ts, snapshot) = (m.view.ts, m.view.kind.is_compaction());
    if !crate::retention::drop_from(tx, c, tid, ak)?.is_some_and(|due| due <= tx.now().0) {
        return Ok(false);
    }
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > ts && x.1 != *c && by_then(tx.core, &x.1)).map(|x| x.1).collect();
    for s in snaps {
        if crate::retention::snapshot_right(tx.core, &s, c, tid, ak) && crate::retention::covered(tx, &s, c, tid, ak)? == Some(true) && !(snapshot && *c < s && crate::retention::covered(tx, c, &s, tid, ak)? == Some(true)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether some delta of held commit `c` is missing here (neither held nor dropped: on a thing
/// this node does not hold, still to arrive, or dropped at its keep bounds and so counting as
/// never received): it cannot judge that delta droppable, so a frontier lists the commit.
fn part_missing(core: &crate::engine::Core, c: &CommitId) -> bool {
    core.ix.commits.get(c).is_none_or(|m| !m.missing.is_empty())
}

/// Whether a held snapshot of `(tid, ak)`, any validity, stamped after commit `id` lists its
/// delta on the aspect as included: its frontier reaches a node-form commit's counters, or its
/// `Absorbed` names the commit (atomic apply: the missing delta counts as dropped,
/// spec/commits.md §4; a snapshot never absorbed a commit stamped after it, spec/crdt.md §2.2).
pub(crate) fn listed(core: &crate::engine::Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    listed_where(core, h, id, ai, |_| true)
}

/// `listed` by a held snapshot valid here: it gave the delta's writes (spec/permissions.md
/// §5.2; a suspect flag's body, `retention::suspect`).
pub(crate) fn listed_by_valid(core: &crate::engine::Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    listed_where(core, h, id, ai, |s| crate::apply::validity::snapshot_valid(core, &s, &a.tid, &a.ak))
}

fn listed_where(core: &crate::engine::Core, h: &Header, id: &CommitId, ai: usize, by: impl Fn(CommitId) -> bool) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    let counted = (h.form.counted() && h.kind.has_own_writes()).then(|| h.form.own_source(h.author, *id));
    held_snapshots(core, &a.tid, &a.ak).any(|(s, ts, fr, abs)| {
        by(s)
            && ts > h.ts
            && match &counted {
                Some(src) => fr.of(src) > 0 && fr.of(src) >= a.hi.saturating_sub(1),
                None => abs.iter().any(|x| x.0 == *id),
            }
    })
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
    /// header alone at the record's), memory commits never, and held ones whose every delta is
    /// held or dropped here and whose part there is droppable here (`droppable_here`) left out;
    /// and, where it falls below write, its held commits acting for that thing, each left out
    /// under the same rule on every delta but `created.0`; and every purge request whose right
    /// may rest on a role it puts in question (`retention::requests_resting_on`). This node's own receipts only;
    /// `as_of` earlier than now gives a backdated revoke's frontier.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
        Ok(self.frontier_and_requests(scope, as_of)?.0)
    }

    /// `frontier`, and the commits it lists that are requests, those received last first
    /// (`fit_requests`).
    pub(crate) fn frontier_and_requests(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<(Frontier, Vec<CommitId>)> {
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
            // keep bounds read deaths
            if !tx.core.ix.deaths_due.is_empty() {
                crate::retention::settle_due(tx)?;
            }
            let mut f = Frontier::default();
            for (node, t, ak) in aspects.iter().cloned() {
                for (id, (a, at)) in get(tx, &t, &ak)?.commits {
                    if a == node && at <= as_of.0 {
                        f.commits.insert(id);
                    }
                }
                let held: Vec<CommitId> = tx.core.durable_on(&(t, ak.clone())).filter(|c| tx.core.ix.commits.get(c).is_some_and(|m| m.view.author == node && m.received.0 <= as_of.0)).collect();
                for c in held {
                    if f.commits.contains(&c) {
                        continue;
                    }
                    if part_missing(tx.core, &c) || !droppable_here(tx, &c, &t, &ak, as_of)? {
                        f.commits.insert(c);
                    }
                }
            }
            // a fall below write on M puts in question every delta of the node's commits acting
            // for M (`validity::acts_for`): one is listed unless each is droppable here, as above
            // (`created.0` is always valid, so never in question; an aspect walked above was
            // judged there, the commit not being listed)
            for (node, things) in &scope.content {
                for t in things {
                    let acting: Vec<CommitId> = tx.core.ix.by_actor.get(&(*t, *node)).into_iter().flatten().filter(|c| !f.commits.contains(*c)).copied().collect();
                    for c in acting {
                        let Some(m) = tx.core.ix.commits.get(&c) else { continue };
                        if m.view.memory || m.received.0 > as_of.0 {
                            continue;
                        }
                        if part_missing(tx.core, &c) {
                            f.commits.insert(c);
                            continue;
                        }
                        let parts: Vec<(Tid, Ak)> = m.view.aspects.iter().filter(|a| a.ak.as_str() != osis_commit::retention::CREATED).map(|a| (a.tid, a.ak.clone())).filter(|(pt, pak)| aspects.binary_search(&(*node, *pt, pak.clone())).is_err()).collect();
                        for (pt, pak) in parts {
                            if !droppable_here(tx, &c, &pt, &pak, as_of)? {
                                f.commits.insert(c);
                                break;
                            }
                        }
                    }
                }
            }
            // a request's right ends with the role unless the frontier lists it (spec/permissions.md
            // §8): one this node received stays rightful, whatever became of its body and on
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
            Ok((f, requests.into_iter().map(|x| x.1).collect()))
        })
    }
}

/// Leaves out of frontier `f` as many of `requests` (received last first) as it takes to fit `max`
/// encoded bytes, so that requests never make a role holder impossible to demote: each one left
/// out loses its right (spec/permissions.md §5.1). A hostile holder's flood is what it received
/// last. What is over `max` without them stays over: `build` refuses it.
pub(crate) fn fit_requests(f: &mut Frontier, requests: &[CommitId], max: usize) {
    let size = |f: &Frontier| osis_base::encode(&osis_schema::Codec::to_value(f)).len();
    let each = osis_base::encode(&osis_base::Value::bytes(&[0u8; 32])).len();
    let mut left = requests.iter();
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
        fit_requests(&mut f, &requests, size(&all));
        assert_eq!(f, all, "it fits");
        let max = size(&Frontier { commits: (0..1500).map(id).collect() });
        fit_requests(&mut f, &requests, max);
        assert!(size(&f) <= max);
        assert_eq!(f.commits, (0..1500).map(id).collect::<BTreeSet<_>>(), "the oldest requests stay");
        fit_requests(&mut f, &requests, 100);
        assert_eq!(f.commits, (0..1000).map(id).collect::<BTreeSet<_>>(), "only requests go");
    }
}
