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

/// Whether held commit `c`'s part on `(tid, ak)` is covered here by snapshots received by
/// `as_of`: dropped as covered with every coverer received by then (`retention::coverers`,
/// coverers dropped in turn included), or held and covered by a
/// held valid snapshot stamped after it and received by then (spec/commits.md §5). A demoter
/// leaves such a commit out of its frontier: the covering snapshot vouches for its live writes
/// (spec/permissions.md §5.2). A coverer received after `as_of` (a backdated revoke) would not
/// be listed if the demoted node wrote it, so it would vouch for nothing after the demotion.
fn covered_here(tx: &mut Tx<'_>, c: &CommitId, tid: &Tid, ak: &Ak, as_of: WallMs) -> Result<bool> {
    let by_then = |core: &crate::engine::Core, s: &CommitId| core.ix.commits.get(s).is_some_and(|m| m.received.0 <= as_of.0);
    let Some(m) = tx.core.ix.commits.get(c) else { return Ok(false) };
    let Some(ai) = m.aspect(tid, ak) else { return Ok(false) };
    if let Some(d) = m.dropped.get(&ai) {
        return Ok(d.as_cover && crate::retention::coverers(tx.core, c, ai).iter().all(|s| by_then(tx.core, s)));
    }
    if m.missing.contains(&ai) {
        return Ok(false);
    }
    let ts = m.view.ts;
    let snaps: Vec<CommitId> = tx.core.ix.snapshots.get(&(*tid, ak.clone())).into_iter().flatten().filter(|x| x.0 > ts && x.1 != *c && by_then(tx.core, &x.1)).map(|x| x.1).collect();
    for s in snaps {
        if crate::retention::covered(tx, &s, c, tid, ak)? == Some(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a held snapshot of `(tid, ak)`, any validity, stamped after commit `id` lists its
/// delta on the aspect as included: its frontier reaches a node-form commit's counters, or its
/// `Absorbed` names the commit (atomic apply: the missing delta counts as dropped,
/// spec/commits.md §4; a snapshot never absorbed a commit stamped after it, spec/crdt.md §2.2).
pub(crate) fn listed(core: &crate::engine::Core, h: &Header, id: &CommitId, ai: usize) -> bool {
    let Some(a) = h.aspects.get(ai) else { return false };
    let counted = (h.form.counted() && h.kind.has_own_writes()).then(|| h.form.own_source(h.author, *id));
    held_snapshots(core, &a.tid, &a.ak).any(|(_, ts, fr, abs)| {
        ts > h.ts
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
        self.run(|tx| {
            for a in &h.aspects {
                let mut r = get(tx, &a.tid, &a.ak)?;
                // a header read again keeps its first receipt time (`as_of` frontiers)
                r.commits.entry(id).or_insert((h.author, now.0));
                put(tx, &a.tid, &a.ak, &r)?;
            }
            Ok(())
        })?;
        self.core.header_receipts.extend(h.aspects.iter().map(|a| (a.tid, a.ak.clone())));
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
    /// header alone at the record's), memory commits never, and held ones whose part there is
    /// covered here (`covered_here`) left out. This node's own receipts only; `as_of` earlier
    /// than now gives a backdated revoke's frontier.
    pub fn frontier(&mut self, scope: &DemotionScope, as_of: WallMs) -> Result<Frontier> {
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
            for (node, t, ak) in aspects {
                for (id, (a, at)) in get(tx, &t, &ak)?.commits {
                    if a == node && at <= as_of.0 {
                        f.commits.insert(id);
                    }
                }
                let held: Vec<CommitId> = tx.core.durable_on(&(t, ak.clone())).filter(|c| tx.core.ix.commits.get(c).is_some_and(|m| m.view.author == node && m.received.0 <= as_of.0)).collect();
                for c in held {
                    if !covered_here(tx, &c, &t, &ak, as_of)? {
                        f.commits.insert(c);
                    }
                }
            }
            Ok(f)
        })
    }
}
