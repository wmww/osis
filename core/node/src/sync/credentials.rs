//! Credentials of a sync ID (issues/net-shared-set.md, Words): what this node holds, by class. A
//! beacon keys over the match value; the proof its Hit must show is the class's.

use super::{ConnId, SyncEngine};
use crate::error::Result;
use osis_base::{LabelId, Tid};
use osis_crypto::Secret32;
use osis_label::{ClaimSet, Step};
use std::collections::BTreeMap;

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

impl SyncEngine {
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
