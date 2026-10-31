//! Roster snapshots (spec/permissions.md §6): by owner-chain authority, the roster with `since`
//! and the tenure ledger as perm's timeline computes them (`Timeline::roster_state`); policy:
//! due once the thing's held `/members` deltas pass `ROSTER_SNAPSHOT_AFTER`. The writer splits
//! the replace into one reset-plus-state delta per edge and per ledger entry (spec/commits.md
//! §2) and links frontiers above `CHUNK_THRESHOLD`; certificate copies carry the chain's deltas.

use super::{Done, ak};
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::Mutation;
use osis_base::{CommitId, Tid};
use osis_schema::Chunked;
use osis_schema::core_types::{self as ct, EdgeKey, Members, Tenures};

/// Held `/members` deltas of a thing after which a roster snapshot is due (local policy).
pub const ROSTER_SNAPSHOT_AFTER: usize = 64;

fn key(k: osis_perm::Point) -> EdgeKey {
    EdgeKey { ts: k.ts, node: k.node, commit: k.commit }
}

fn frontier(f: &osis_perm::Frontier) -> ct::Frontier {
    ct::Frontier { writes: f.writes.clone(), commits: f.commits.clone() }
}

impl Engine {
    /// Whether a roster snapshot of `thing` is due and this node (or held key actor `signer`)
    /// may write it.
    pub fn roster_snapshot_due(&self, thing: &Tid, signer: Option<&Tid>) -> bool {
        let who = signer.copied().unwrap_or(self.tid());
        let Ok(members) = ak("/members") else { return false };
        let n = self.core.ix.by_aspect.get(&(*thing, members)).map_or(0, |s| s.len());
        let ts = super::now_ts(&self.core);
        n > ROSTER_SNAPSHOT_AFTER && self.core.timelines.get(thing).is_some_and(|tl| tl.may_roster_snapshot(&who, thing, ts))
    }

    /// Writes a roster snapshot of `thing` (spec/permissions.md §6) as this node, or signed as
    /// held key actor `signer` (the recovery key of a person actor).
    pub fn roster_snapshot(&mut self, thing: &Tid, signer: Option<&Tid>) -> Result<Done> {
        let t = *thing;
        let who = signer.copied().unwrap_or(self.tid());
        let ts = super::now_ts(&self.core);
        if !self.core.timelines.get(&t).is_some_and(|tl| tl.may_roster_snapshot(&who, &t, ts)) {
            return Err(Error::Permission { tid: t });
        }
        // a ledger whose frontier is not known here would be written without it
        if self.core.ix.frontier_unknown.contains(&t) {
            return Err(Error::Misuse("a roster snapshot of the thing has a linked frontier not held here"));
        }
        // the snapshot compacts the edge history departures are read from: every one must be
        // covered first (rotated now where the author may; refused while any stays uncovered)
        let mut done = self.run(|tx| {
            let mut done = Done::default();
            let all = osis_keys::ROLES.into_iter().collect();
            crate::rotation::require_covered(tx, who, t, &all, &mut done)?;
            Ok(done)
        })?;
        let tl = self.core.timelines.get(&t).ok_or(Error::UnknownThing(t))?;
        let state = tl.roster_state(&t);
        let roster: Members = state
            .roster
            .iter()
            .map(|(m, e)| (*m, ct::Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(key), tied: e.tied.map(super::tied::tie_ct) }))
            .collect();
        let ledger = Tenures(
            state
                .ledger
                .iter()
                .map(|x| ct::Tenure { member: x.member, role: x.role, since: x.since.map(key), until: key(x.until), frontier: x.frontier.as_deref().map(|f| Chunked::Inline(frontier(f))) })
                .collect(),
        );
        // receivers refuse more linked frontier bytes than this (spec/permissions.md §6)
        let linked: std::collections::BTreeSet<Vec<u8>> = ledger
            .0
            .iter()
            .filter_map(|x| match &x.frontier {
                Some(Chunked::Inline(f)) => Some(osis_base::encode(&osis_schema::Codec::to_value(f))),
                _ => None,
            })
            .filter(|b| b.len() > osis_base::format::CHUNK_THRESHOLD)
            .collect();
        if linked.iter().map(Vec::len).sum::<usize>() > osis_base::format::MAX_LINKED_FRONTIERS {
            return Err(Error::Misuse("the ledger's frontiers exceed MAX_LINKED_FRONTIERS"));
        }
        let mut m = Mutation::new();
        m.replace(t, &ct::MEMBERS, &roster)?;
        m.replace(t, &ct::TENURES, &ledger)?;
        m.roster = true;
        if let Some(s) = signer {
            m.sign_as(*s);
        }
        let c: Option<CommitId> = self.commit(m)?;
        done.add(c);
        Ok(done)
    }
}
