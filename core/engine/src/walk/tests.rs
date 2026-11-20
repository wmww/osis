#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Count tests for the engine side of the walk along stated paths (notes/principles.md, Check
//! scaling): the work each piece does at n and 10n held commits.

use super::store::EngineStore;
use crate::local_peer::LocalPeer;
use crate::Mutation;
use osis_base::{Ak, CommitId, PurgeBy, Role, Tid, Ts, Value, WallMs};
use osis_perm::paths::{By, Commit, Content, Delta, DeltaClass, EdgeWrite, Part, PartKind, Paths, Store};
use osis_perm::{Edge, WriteId};
use std::collections::{BTreeMap, BTreeSet};

fn tid(i: u8) -> Tid {
    Tid::from_bytes([i; 15])
}

fn cid(i: u64) -> CommitId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&i.to_be_bytes());
    CommitId(b)
}

fn ts(ms: u64) -> Ts {
    Ts::make(WallMs(1_700_000_000_000 + ms), 0).unwrap()
}

const A: u8 = 1;
const X: u8 = 2;
const T: u8 = 3;
const U: u8 = 4;

/// T and U minted by A.
fn records() -> BTreeMap<Tid, Tid> {
    BTreeMap::from([(tid(T), tid(A)), (tid(U), tid(A))])
}

/// A grants `holder` `role` on `on` (the record edge: the empty path), with the `keys.0` box a
/// role commit carries (a role-class delta: its facts are the store's).
fn grant(i: u64, at: u64, on: u8, holder: Tid, role: Role) -> Commit {
    let value = Some(Edge { role, until: None, invite: None, retain: false, floor: None });
    let keys = Delta { aspect: Ak::new("keys.0").unwrap(), needs: Role::Admin, purge_author: 0, retention: PurgeBy::Admin, class: DeltaClass::RoleClass };
    let edge = Part { on: tid(on), path: vec![], direct: 0, kind: PartKind::Edge(EdgeWrite { holder, value, frontier: None, remains: None, adminless: false }) };
    Commit { id: cid(i), ts: ts(at), signer: tid(A), parts: vec![edge, Part { on: tid(on), path: vec![], direct: 0, kind: PartKind::Delta(keys) }] }
}

/// `by`'s content on `on` along `path`.
fn content(i: u64, at: u64, by: u8, on: u8, path: &[u8]) -> Commit {
    let d = Delta { aspect: Ak::new("x:a.0").unwrap(), needs: Role::Write, purge_author: 0, retention: PurgeBy::Admin, class: DeltaClass::Plain };
    Commit { id: cid(i), ts: ts(at), signer: tid(by), parts: vec![Part { on: tid(on), path: path.iter().map(|x| tid(*x)).collect(), direct: 0, kind: PartKind::Delta(d) }] }
}

/// X, granted write on T, writes n deltas there; other role commits grant n holders on U.
fn world(n: u64) -> Vec<Commit> {
    let mut c = vec![grant(1, 1, T, tid(X), Role::Write)];
    c.extend((0..10).map(|i| grant(10 + i, 2 + i, U, Tid::from_bytes([100 + i as u8; 15]), Role::Read)));
    c.extend((0..n).map(|i| content(1000 + i, 100 + i, X, T, &[])));
    c
}

// spec: none (a count test: notes/perm-paths.md, The delta-facts seam): the engine's store: judging a delta appended at the
// end reads the store a fixed number of times (its facts, the commit's held deltas), whatever is
// held: at n and 10n held deltas alike, each lookup a point or range read.
#[test]
fn a_judged_delta_reads_the_store_alike_at_n_and_10n() {
    let mut per = vec![];
    for n in [100u64, 1000] {
        let mut p = Paths::with_store(&records(), BTreeSet::new(), EngineStore::default());
        p.add(&world(n));
        let before = p.store().reads();
        p.add(&[content(9, 100 + n + 5, X, T, &[])]);
        assert_eq!(p.content(&WriteId(cid(9), 0)), Some(Content::Valid(By::Held)));
        per.push(p.store().reads() - before);
        // the path facts are shared per (commit, thing): one each here
        assert_eq!(p.store().sizes(), (n as usize + 12, n as usize + 12));
    }
    assert!(per[0] > 0 && per[0] == per[1], "store reads judging one delta at n and 10n: {per:?}");
}

/// The engine store holding what `commits` put, the role commits' own facts taken out: what a
/// persisted store holds at an open, whose walk is rebuilt from the role commits alone.
fn reopened(commits: &[Commit]) -> (EngineStore, Vec<Commit>) {
    let mut p = Paths::with_store(&records(), BTreeSet::new(), EngineStore::default());
    p.add(commits);
    let mut store = p.store().clone();
    let roles: Vec<Commit> = commits.iter().filter(|c| c.parts.iter().any(|x| matches!(x.kind, PartKind::Edge(_) | PartKind::Vouch { .. }) || matches!(&x.kind, PartKind::Delta(d) if matches!(d.class, DeltaClass::RoleClass)))).cloned().collect();
    for c in &roles {
        for id in store.of_commit(&c.id, None) {
            store.remove(&id);
        }
    }
    (store, roles)
}

// spec: none (a count test: notes/perm-paths.md, The switch, the load path): an open rebuilds the walk from the held role
// commits alone over the store as persisted (content facts stay in it, not added again): the same
// walk steps at n and 10n content commits, and every reading as the walk from scratch.
#[test]
fn an_open_rebuilds_the_walk_from_role_commits_alone() {
    let mut per = vec![];
    for n in [100u64, 1000] {
        let all = world(n);
        let (store, roles) = reopened(&all);
        let (puts, reads) = (store.puts(), store.reads());
        let mut p = Paths::with_store(&records(), BTreeSet::new(), store);
        p.add(&roles);
        let (puts, reads) = (p.store().puts() - puts, p.store().reads() - reads);
        let scratch = Paths::evaluate(&records(), BTreeSet::new(), &all);
        assert_eq!(p.statuses(), scratch.statuses());
        assert_eq!(p.contents(), scratch.contents());
        per.push((p.counts().steps, puts, reads, roles.len()));
    }
    assert!(per[0].0 > 0 && per[0] == per[1], "walk steps, facts put and store reads rebuilding at n and 10n content commits: {per:?}");
}

// spec: none (a count test: notes/perm-paths.md, Forget and update): forgetting a content commit walks nothing and reads
// the store along its own parts alone: alike at n and 10n held deltas.
#[test]
fn a_forgotten_content_commit_costs_its_own_parts() {
    let mut per = vec![];
    for n in [100u64, 1000] {
        let mut p = Paths::with_store(&records(), BTreeSet::new(), EngineStore::default());
        p.add(&world(n));
        let (steps, reads) = (p.counts().steps, p.store().reads());
        p.forget(&[cid(1000 + n / 2)]);
        per.push((p.counts().steps - steps, p.store().reads() - reads));
        assert_eq!(p.content(&WriteId(cid(1000 + n / 2), 0)), None);
    }
    assert!(per[0].0 == 0 && per[0] == per[1], "walk steps and store reads forgetting one content commit at n and 10n: {per:?}");
}

// spec: none (a count test: notes/perm-paths.md, The switch, the adapter): the shadow walk adapts only what a transaction
// moved: one write after n or 10n held content commits adapts the same commits.
#[test]
fn the_adapter_reads_what_a_transaction_moved() {
    let mut per = vec![];
    for n in [10u64, 100] {
        let mut lp = LocalPeer::fresh(1, WallMs(1_700_000_000_000));
        let a = lp.peers[0].engine.me();
        let mut m = Mutation::new();
        let t = lp.peers[0].engine.new_thing(&mut m, a);
        lp.peers[0].commit(m).unwrap();
        let reg = Ak::new("x:a.0").unwrap();
        for i in 0..n {
            let mut m = Mutation::new();
            m.set(t, &reg, &Value::Int(i as i64)).unwrap();
            lp.peers[0].commit(m).unwrap();
        }
        let before = lp.peers[0].engine.shadow.as_ref().unwrap().adapted;
        let mut m = Mutation::new();
        m.set(t, &reg, &Value::Int(-1)).unwrap();
        lp.peers[0].commit(m).unwrap();
        per.push(lp.peers[0].engine.shadow.as_ref().unwrap().adapted - before);
    }
    assert!(per[0] > 0 && per[0] == per[1], "commits adapted for one write at n and 10n: {per:?}");
}
