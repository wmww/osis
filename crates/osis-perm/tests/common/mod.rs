//! Test histories: nodes, things, commits with receipt times; frontiers derived from receipts
//! as the models do (a demoter at t covers what it received before t), commit-form dots.
#![allow(dead_code)]

use osis_core::{CommitId, CreationRecord, Role, Tid, Ts, WallMs};
use osis_perm::{Dots, Edge, EdgeKey, EdgeOp, Frontier, MembershipCommit, MemoryHeldSet, RosterSnapshot, Tenure, WriteId};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const LATE: u64 = 100_000;

pub fn ts(t: u64) -> Ts {
    Ts::make(WallMs(t), 0).unwrap()
}

pub fn cid(n: u32) -> CommitId {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_be_bytes());
    b[31] = 1;
    CommitId(b)
}

pub fn edge(role: Role) -> Option<Edge> {
    Some(Edge::new(role))
}

pub fn edge_inv(role: Role, invite: Option<Role>, until: Option<u64>) -> Option<Edge> {
    Some(Edge { role, until: until.map(WallMs), invite, since: None })
}

/// `n` key-actor records whose tids sort in index order (models order authors by index).
pub fn key_actors(n: usize, salt: u8) -> Vec<(Tid, CreationRecord)> {
    let mut v: Vec<(Tid, CreationRecord)> = (0..n)
        .map(|i| {
            let mut nonce = [salt; 32];
            nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let rec = CreationRecord::KeyActor { alg: 1, public_key: vec![i as u8; 32], nonce };
            (rec.tid(), rec)
        })
        .collect();
    v.sort_by_key(|(t, _)| *t);
    v
}

pub fn thing_record(owner: Tid, i: u64) -> (Tid, CreationRecord) {
    let mut nonce = [7u8; 32];
    nonce[..8].copy_from_slice(&i.to_be_bytes());
    let rec = CreationRecord::Thing { owner, nonce };
    (rec.tid(), rec)
}

#[derive(Clone, Debug)]
pub struct CSpec {
    pub id: CommitId,
    pub author: Tid,
    pub t: u64,
    pub ops: Vec<(Tid, Tid, Option<Edge>)>,
    pub recv: BTreeMap<Tid, u64>,
}

/// A ledger entry: (member, role, since, until, audited).
pub type LedgerSpec = (Tid, Role, Option<(u64, Tid)>, (u64, Tid), bool);

#[derive(Clone, Debug)]
pub struct SSpec {
    pub id: CommitId,
    pub author: Tid,
    pub t: u64,
    pub thing: Tid,
    pub roster: BTreeMap<Tid, Edge>,
    /// (member, role, since, until); the tenure's frontier is the until node's receipts before
    /// the until time; `audited: false` leaves it without one.
    pub ledger: Vec<LedgerSpec>,
    pub recv: BTreeMap<Tid, u64>,
}

/// A history under construction.
#[derive(Clone, Debug, Default)]
pub struct World {
    pub created: BTreeMap<Tid, CreationRecord>,
    pub commits: Vec<CSpec>,
    pub snaps: Vec<SSpec>,
    next: u32,
}

impl World {
    pub fn new() -> World {
        World { next: 1000, ..Default::default() }
    }
    /// `n` nodes (key actors), tids in index order.
    pub fn nodes(&mut self, n: usize) -> Vec<Tid> {
        key_actors(n, 1).into_iter().map(|(t, r)| {
            self.created.insert(t, r);
            t
        }).collect()
    }
    pub fn thing(&mut self, owner: Tid) -> Tid {
        let (t, r) = thing_record(owner, self.created.len() as u64);
        self.created.insert(t, r);
        t
    }
    pub fn fresh_id(&mut self) -> CommitId {
        self.next += 1;
        cid(self.next)
    }
    /// A commit; `recv`: receipt times by node (author: its own t; others LATE).
    pub fn commit(&mut self, author: Tid, t: u64, ops: &[(Tid, Tid, Option<Edge>)], recv: &[(Tid, u64)]) -> CommitId {
        let id = self.fresh_id();
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.commits.push(CSpec { id, author, t, ops: ops.to_vec(), recv: r });
        id
    }
    /// A commit with a chosen ID.
    pub fn commit_id(&mut self, id: CommitId, author: Tid, t: u64, ops: &[(Tid, Tid, Option<Edge>)], recv: &[(Tid, u64)]) {
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.commits.push(CSpec { id, author, t, ops: ops.to_vec(), recv: r });
    }
    /// One edge write: `member`'s edge on `target`.
    pub fn set(&mut self, author: Tid, target: Tid, member: Tid, e: Option<Edge>, t: u64, recv: &[(Tid, u64)]) -> CommitId {
        self.commit(author, t, &[(target, member, e)], recv)
    }
    pub fn snapshot(&mut self, author: Tid, thing: Tid, roster: &[(Tid, Edge)], t: u64, recv: &[(Tid, u64)]) -> CommitId {
        self.snapshot_l(author, thing, roster, &[], t, recv)
    }
    pub fn snapshot_l(
        &mut self,
        author: Tid,
        thing: Tid,
        roster: &[(Tid, Edge)],
        ledger: &[LedgerSpec],
        t: u64,
        recv: &[(Tid, u64)],
    ) -> CommitId {
        let id = self.fresh_id();
        let mut r: BTreeMap<Tid, u64> = recv.iter().copied().collect();
        r.insert(author, t);
        self.snaps.push(SSpec { id, author, t, thing, roster: roster.iter().copied().collect(), ledger: ledger.to_vec(), recv: r });
        id
    }

    fn recv_of(&self, id: &CommitId) -> Option<&BTreeMap<Tid, u64>> {
        self.commits.iter().find(|c| c.id == *id).map(|c| &c.recv).or_else(|| self.snaps.iter().find(|s| s.id == *id).map(|s| &s.recv))
    }

    /// Frontier of a demoter `node` at `t`: every commit it received before `t`.
    pub fn frontier(&self, node: Tid, t: u64) -> Frontier {
        let mut f = Frontier::default();
        for (id, r) in self.commits.iter().map(|c| (c.id, &c.recv)).chain(self.snaps.iter().map(|s| (s.id, &s.recv))) {
            if r.get(&node).copied().unwrap_or(LATE) < t {
                f.commits.insert(id);
            }
        }
        f
    }

    /// The held set, every commit carrying the frontier its receipts imply.
    pub fn held(&self) -> MemoryHeldSet {
        self.held_without(&BTreeSet::new())
    }

    pub fn held_without(&self, skip: &BTreeSet<CommitId>) -> MemoryHeldSet {
        let mut h = MemoryHeldSet::new();
        for (t, r) in &self.created {
            h.created.insert(*t, r.clone());
        }
        for c in self.commits.iter().filter(|c| !skip.contains(&c.id)) {
            h.add_commit(MembershipCommit {
                id: c.id,
                ts: ts(c.t),
                author: c.author,
                actor: c.author,
                frontier: Some(Arc::new(self.frontier(c.author, c.t))),
                ops: c.ops.iter().map(|&(target, member, edge)| EdgeOp { target, member, edge, dots: Dots::Commit }).collect(),
            });
        }
        for s in self.snaps.iter().filter(|s| !skip.contains(&s.id)) {
            let ledger = s
                .ledger
                .iter()
                .map(|&(member, role, since, until, audited)| Tenure {
                    member,
                    role,
                    since: since.map(|(t, node)| EdgeKey { ts: ts(t), node }),
                    until: EdgeKey { ts: ts(until.0), node: until.1 },
                    frontier: audited.then(|| Arc::new(self.frontier(until.1, until.0))),
                })
                .collect();
            h.add_snapshot(RosterSnapshot { id: s.id, ts: ts(s.t), author: s.author, actor: s.author, thing: s.thing, dots: Dots::Commit, roster: s.roster.clone(), ledger });
        }
        h
    }
}

/// The commit IDs of dropped writes.
pub fn dropped_commits(tl: &osis_perm::Timeline) -> BTreeSet<CommitId> {
    tl.dropped().keys().map(WriteId::commit).collect()
}
