//! Credentials of a sync ID (issues/net-shared-set.md, Words): what this node holds, by class. A
//! beacon keys over the match value; the proof its Hit must show is the class's.

use super::{ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{LabelId, Tid};
use osis_crypto::Secret32;
use osis_label::{ClaimSet, Step};
use crate::engine::Core;
use std::collections::{BTreeMap, BTreeSet};

pub use osis_engine::labeling::Judgment;

/// A credential of L by class (issues/net-shared-set.md, Words).
#[derive(Clone, Debug)]
pub enum Credential {
    /// The read secret at a current epoch.
    ReadSecret(Secret32),
    /// A key actor's static entry on L (spec/wire.md §8).
    StaticEntry([u8; 32]),
    /// A served head's `sync_pk`.
    SyncKey([u8; 32]),
    /// A served head's `deposit_pk`.
    DepositKey([u8; 32]),
}

impl Credential {
    /// The 32 bytes a beacon keys over.
    pub fn match_value(&self) -> [u8; 32] {
        match self {
            Credential::ReadSecret(s) => *s.expose(),
            Credential::StaticEntry(b) | Credential::SyncKey(b) | Credential::DepositKey(b) => *b,
        }
    }
}

/// The credentials of a served head at a peer that cannot read it: its sync and deposit keys, and
/// its claim set. Every claim counts: static entries are not told from padding and claim keys
/// without a read secret, and a claim that is no static entry opens nothing (its Hit's key actor
/// must be proven).
pub fn head_credentials(head: &Step, claims: &ClaimSet) -> Vec<Credential> {
    let mut out = vec![Credential::SyncKey(head.keys.sync.to_bytes()), Credential::DepositKey(head.keys.deposit.to_bytes())];
    out.extend(claims.claims.iter().map(|c| Credential::StaticEntry(*c)));
    out
}

/// Local only: what a `changed_at` fingerprint is computed under.
const CHANGED_FP: &str = "changed fingerprint";

/// A fingerprint of `a`'s holders, through every roster held: who reaches it. A cycle is cut at
/// its first repeat; a fingerprint that moves for that reason is one spurious stamp, harmless.
fn holders_hash(core: &Core, a: &Tid, memo: &mut BTreeMap<Tid, [u8; 32]>, stack: &mut BTreeSet<Tid>) -> [u8; 32] {
    if let Some(h) = memo.get(a) {
        return *h;
    }
    if !stack.insert(*a) {
        return [0; 32];
    }
    let mut holders = core.key_holders(a);
    holders.sort_by_key(|(m, _)| *m);
    let mut bytes = Vec::with_capacity(holders.len() * 48);
    for (m, role) in holders {
        bytes.extend_from_slice(m.as_bytes());
        bytes.push(role as u8);
        bytes.extend_from_slice(&holders_hash(core, &m, memo, stack));
    }
    stack.remove(a);
    let h = *osis_crypto::kdf::kdf(CHANGED_FP, &bytes, b"holders").expose();
    memo.insert(*a, h);
    h
}

impl SyncEngine {
    /// `changed_at` of every held sync ID, stamped where its credentials or who reaches it moved
    /// (issues/net-reconnect.md, Changes). Runs when a role, roster or read secret moved, the set
    /// of sync IDs changed, or at a start: never per write. O(N) labels and O(edges) over the
    /// rosters, memoized per pass; a start or pass that finds nothing changed appends nothing.
    pub(super) fn stamp_changes(&mut self) -> Result<()> {
        self.labels();
        let generation = self.engine.core.role_generation;
        let hints = std::mem::take(&mut self.state.hints_moved);
        if !self.changed_due && !hints && generation == self.changed_gen {
            return Ok(());
        }
        let things = self.things();
        let labels: Vec<LabelId> = things.keys().copied().collect();
        let creds = self.credentials(&labels)?;
        let (mut memo, mut stack) = (BTreeMap::new(), BTreeSet::new());
        let mut fps = Vec::with_capacity(labels.len());
        for l in &labels {
            let actor = things.get(l).map(|t| self.engine.core.reader_of(t));
            let mut values: Vec<[u8; 32]> = creds.get(l).map(|c| c.iter().map(Credential::match_value).collect()).unwrap_or_default();
            values.sort_unstable();
            let reach = actor.map_or([0; 32], |a| holders_hash(&self.engine.core, &a, &mut memo, &mut stack));
            let bytes: Vec<u8> = values.iter().flatten().copied().chain(reach).collect();
            fps.push((*l, *osis_crypto::kdf::kdf(CHANGED_FP, &bytes, b"label").expose()));
        }
        let kept: BTreeSet<LabelId> = labels.into_iter().collect();
        self.engine.run(|tx| {
            for (l, fp) in &fps {
                tx.txn.changed_note(*l, fp)?;
            }
            for l in tx.txn.changed_labels()? {
                if !kept.contains(&l) {
                    tx.txn.changed_forget(&l)?;
                }
            }
            Ok(())
        })?;
        self.changed_due = false;
        self.changed_gen = generation;
        Ok(())
    }

    /// The thing each label is held under here: synced groups (`labels`, current for this
    /// generation), then hints.
    fn things(&mut self) -> BTreeMap<LabelId, Tid> {
        let mut out: BTreeMap<LabelId, Tid> = self.labels().into_iter().map(|(g, l)| (l.id, g)).collect();
        for (l, h) in &self.state.hints {
            out.entry(*l).or_insert(h.thing);
        }
        out
    }

    /// J of each of `labels` for `conn`'s proven key actors (issues/net-shared-set.md, Words);
    /// `None` for a connection this engine does not have. O(N) for the label table, one walk
    /// per proven actor, then a lookup per label.
    pub fn judgments(&mut self, conn: ConnId, labels: &[LabelId]) -> Option<BTreeMap<LabelId, Judgment>> {
        let proven = self.connection_proven(conn)?.clone();
        let things = self.things();
        let mut judge = self.engine.core.judge(proven.key_actors);
        Some(labels.iter().map(|l| (*l, things.get(l).map_or(Judgment::Unknown, |t| judge.of(t)))).collect())
    }

    /// This node's credentials of each of `labels`, as a reader or as the key actor its link or
    /// card names (issues/net-shared-set.md, Words): the read secret at each current epoch held,
    /// a static entry per key actor on the label's roster held, and the static entry of the key
    /// actor a hint names. A peer that cannot read a label has `head_credentials` instead (step 9).
    /// O(N) for the label table, then per label O(its roster).
    pub fn credentials(&mut self, labels: &[LabelId]) -> Result<BTreeMap<LabelId, Vec<Credential>>> {
        let readers: BTreeMap<LabelId, Tid> = self.labels().into_iter().map(|(g, l)| (l.id, g)).collect();
        let mut all = BTreeMap::new();
        for l in labels {
            let mut out = Vec::new();
            if let Some(g) = readers.get(l) {
                if let Some(e) = self.engine.epochs(g) {
                    out.extend(e.read.current().iter().filter_map(|ep| e.read.secret(ep)).map(|s| Credential::ReadSecret(s.clone())));
                }
                for pk in self.engine.static_listed(g)? {
                    out.push(Credential::StaticEntry(osis_crypto::static_entry(l, &pk)));
                }
            }
            let own = self.state.hints.get(l).and_then(|h| h.via).and_then(|a| self.engine.core.key_actors.get(&a).map(|k| k.keys().signing.verifying_key()));
            if let Some(pk) = own {
                let entry = osis_crypto::static_entry(l, &pk);
                if !out.iter().any(|c| matches!(c, Credential::StaticEntry(e) if *e == entry)) {
                    out.push(Credential::StaticEntry(entry));
                }
            }
            all.insert(*l, out);
        }
        Ok(all)
    }
}
