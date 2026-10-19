//! Roster snapshots (spec/permissions.md §6): by owner-chain authority, the roster with `since`
//! and the tenure ledger as perm's timeline computes them (`Timeline::roster_state`); policy:
//! due once the thing's held `/members` deltas pass `ROSTER_SNAPSHOT_AFTER`.
//!
//! Reading (issues/roster-snapshot-deltas.md): one reset-plus-full-state delta per aspect, not
//! one per edge and ledger entry, so a certificate copy cannot yet be projected per edge.

use super::{Done, ak};
use crate::engine::Engine;
use crate::error::{Error, Result};
use crate::Mutation;
use osis_core::{CommitId, Tid};
use osis_perm::At;
use osis_schema::Chunked;
use osis_schema::core_types::{self as ct, EdgeKey, Members, Tenures};

/// Held `/members` deltas of a thing after which a roster snapshot is due (local policy).
pub const ROSTER_SNAPSHOT_AFTER: usize = 64;

fn key(k: osis_perm::EdgeKey) -> EdgeKey {
    EdgeKey { ts: k.ts, node: k.node }
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
        let n = self.core.by_aspect.get(&(*thing, members)).map_or(0, |s| s.len());
        let ts = super::now_ts(&self.core);
        n > ROSTER_SNAPSHOT_AFTER && self.core.timelines.get(thing).is_some_and(|tl| tl.may_roster_snapshot(&who, thing, ts))
    }

    /// Writes a roster snapshot of `thing` (spec/permissions.md §6) as this node, or signed as
    /// held key actor `signer` (the recovery key of a person actor).
    pub fn roster_snapshot(&mut self, thing: &Tid, signer: Option<&Tid>) -> Result<Done> {
        let t = *thing;
        let who = signer.copied().unwrap_or(self.tid());
        let ts = super::now_ts(&self.core);
        let tl = self.core.timelines.get(&t).ok_or(Error::UnknownThing(t))?;
        if !tl.may_roster_snapshot(&who, &t, ts) {
            return Err(Error::Permission { tid: t });
        }
        let state = tl.roster_state(&t);
        let _ = At::END;
        let roster: Members = state
            .roster
            .iter()
            .map(|(m, e)| (*m, ct::Edge { role: e.role, until: e.until, invite: e.invite, since: e.since.map(key) }))
            .collect();
        let ledger = Tenures(
            state
                .ledger
                .iter()
                .map(|x| ct::Tenure { member: x.member, role: x.role, since: x.since.map(key), until: key(x.until), frontier: x.frontier.as_deref().map(|f| Chunked::Inline(frontier(f))) })
                .collect(),
        );
        let mut m = Mutation::new();
        m.replace(t, &ct::MEMBERS, &roster)?;
        m.replace(t, &ct::TENURES, &ledger)?;
        m.roster = true;
        if let Some(s) = signer {
            m.sign_as(*s);
        }
        let c: Option<CommitId> = self.commit(m)?;
        let mut done = Done::default();
        done.add(c);
        Ok(done)
    }
}
