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

/// A fingerprint of `a`'s holders, through every roster held: who reaches it, as (hash, whole).
/// A cycle is cut at its first repeat: a hash below a cut names only part of its closure, so it
/// is not `whole` and is never reused for another root, where the cut would hide a holder.
fn holders_hash(core: &Core, a: &Tid, memo: &mut BTreeMap<Tid, [u8; 32]>, stack: &mut BTreeSet<Tid>) -> ([u8; 32], bool) {
    if let Some(h) = memo.get(a) {
        return (*h, true);
    }
    if !stack.insert(*a) {
        return ([0; 32], false);
    }
    let mut holders = core.key_holders(a);
    holders.sort_by_key(|(m, _)| *m);
    let mut bytes = Vec::with_capacity(holders.len() * 48);
    let mut whole = true;
    for (m, role) in holders {
        let (h, w) = holders_hash(core, &m, memo, stack);
        whole &= w;
        bytes.extend_from_slice(m.as_bytes());
        bytes.push(role as u8);
        bytes.extend_from_slice(&h);
    }
    stack.remove(a);
    let h = *osis_crypto::kdf::kdf(CHANGED_FP, &bytes, b"holders").expose();
    if whole {
        memo.insert(*a, h);
    }
    (h, whole)
}

impl SyncEngine {
    /// `changed_at` of every held sync ID, stamped where its credentials or who reaches it moved
    /// (issues/net-reconnect.md, Changes). Runs when a role, roster or read secret moved, the set
    /// of sync IDs changed, or at a start (`role_generation`, which also moves on every held-set
    /// change: issues/derived-state-recomputed.md). O(N) labels and O(edges) over the
    /// rosters, memoized per pass; a start or pass that finds nothing changed appends nothing.
    pub(super) fn stamp_changes(&mut self) -> Result<()> {
        self.labels();
        let generation = self.engine.core.role_generation;
        let hints = std::mem::take(&mut self.state.hints_moved);
        if !self.changed_due && !hints && generation == self.changed_gen {
            return Ok(());
        }
        self.shared_dirty = true;
        let things = self.things();
        // and the sync IDs kept unread: their head's credentials (step 9)
        let unread = self.unread_heads()?;
        let labels: Vec<LabelId> = things.keys().chain(unread.keys().filter(|l| !things.contains_key(l))).copied().collect();
        self.stats.changed_passes += 1;
        self.stats.changed_labels += labels.len() as u64;
        let creds = self.credentials(&labels)?;
        let (mut memo, mut stack) = (BTreeMap::new(), BTreeSet::new());
        let mut fps = Vec::with_capacity(labels.len());
        for l in &labels {
            let actor = things.get(l).map(|t| self.engine.core.reader_of(t));
            let mut values: Vec<[u8; 32]> = creds.get(l).map(|c| c.iter().map(Credential::match_value).collect()).unwrap_or_default();
            values.sort_unstable();
            let reach = actor.map_or([0; 32], |a| holders_hash(&self.engine.core, &a, &mut memo, &mut stack).0);
            let bytes: Vec<u8> = values.iter().flatten().copied().chain(reach).collect();
            fps.push((*l, *osis_crypto::kdf::kdf(CHANGED_FP, &bytes, b"label").expose()));
        }
        let kept: BTreeSet<LabelId> = labels.into_iter().collect();
        let moved = self.engine.run(|tx| {
            let mut moved = Vec::new();
            for (l, fp) in &fps {
                if tx.txn.changed_note(*l, fp)?.is_some() {
                    moved.push(*l);
                }
            }
            for l in tx.txn.changed_labels()? {
                if !kept.contains(&l) {
                    tx.txn.changed_forget(&l)?;
                }
            }
            Ok(moved)
        })?;
        // records not in use are judged for these (`shared_changed`, `records_end`)
        self.changed_moved.extend(moved);
        self.changed_due = false;
        self.changed_gen = generation;
        Ok(())
    }

    /// The thing each label is held under here: synced groups (`labels`, current for this
    /// generation), then hints.
    pub(super) fn things(&mut self) -> BTreeMap<LabelId, Tid> {
        let mut out: BTreeMap<LabelId, Tid> = self.labels().into_iter().map(|(g, l)| (l.id, g)).collect();
        for (l, h) in &self.state.hints {
            out.entry(*l).or_insert(h.thing);
        }
        out
    }

    /// J of each of `labels` for `conn`'s proven actors (issues/net-shared-set.md, Words);
    /// `None` for a connection this engine does not have. O(N) for the label table, one walk
    /// per proven actor, then a lookup per label.
    pub fn judgments(&mut self, conn: ConnId, labels: &[LabelId]) -> Option<BTreeMap<LabelId, Judgment>> {
        let proven = self.connection_proven(conn)?.clone();
        let things = self.things();
        let mut judge = self.engine.core.judge(proven.all());
        Some(labels.iter().map(|l| (*l, things.get(l).map_or(Judgment::Unknown, |t| judge.of(t)))).collect())
    }

    /// This node's credentials of each of `labels`, as a reader or as the key actor its link or
    /// card names (issues/net-shared-set.md, Words): the read secret at each current epoch held
    /// (of a synced group, or of a hint's thing a held box gave one of), a static entry per key actor on the label's roster held, and the static entry of the key
    /// actor a hint names; of a sync ID this node keeps and cannot read, its head's
    /// (`head_credentials`). O(N) for the label table, then per label O(its roster).
    pub fn credentials(&mut self, labels: &[LabelId]) -> Result<BTreeMap<LabelId, Vec<Credential>>> {
        let readers: BTreeMap<LabelId, Tid> = self.labels().into_iter().map(|(g, l)| (l.id, g)).collect();
        let unread = self.unread_heads()?;
        let mut all = BTreeMap::new();
        for l in labels {
            if let Some(h) = unread.get(l).filter(|_| !readers.contains_key(l) && !self.state.hints.contains_key(l)) {
                let none = ClaimSet { claims: Vec::new(), entries: BTreeMap::new() };
                all.insert(*l, head_credentials(&h.step, h.claims.as_deref().unwrap_or(&none)));
                continue;
            }
            let mut out = Vec::new();
            // a hint's thing too: a read secret a held box gave (an inbox grant), before the
            // label's own `label.0` comes by that label
            let read = readers.get(l).copied().or_else(|| self.state.hints.get(l).map(|h| h.thing));
            if let Some(g) = read
                && let Some(e) = self.engine.epochs(&g)
            {
                // current epochs, or (a newly granted reader, its epoch not established until
                // the group's commits arrive) the newest secret held: nothing else finds them
                let mut secrets: Vec<Secret32> = e.read.current().iter().filter_map(|ep| e.read.secret(ep)).cloned().collect();
                if secrets.is_empty() {
                    secrets.extend(e.read.held_newest_first().into_iter().take(1).map(|(_, s)| s.clone()));
                }
                out.extend(secrets.into_iter().map(Credential::ReadSecret));
            }
            if let Some(g) = readers.get(l) {
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
